import base64
import hashlib
import hmac
import json
import os
import time
import uuid
import webbrowser
from datetime import datetime, date
from functools import wraps
from typing import Any, Dict, Optional, Tuple

from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

try:
    import requests  # type: ignore[import]
except ImportError:  # pragma: no cover - optional dependency
    requests = None  # type: ignore[assignment]

try:
    import stripe  # type: ignore[import]
except ImportError:  # pragma: no cover - optional dependency
    stripe = None  # type: ignore[assignment]

app = Flask(__name__)

# ==========
# 設定
# ==========

# SQLite DB
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///sales.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# セッション
app.config["SECRET_KEY"] = "change_this_secret_key"  # 適当に変えてOK

# 決済関連（環境変数から読み込み）
app.config["STRIPE_SECRET_KEY"] = os.getenv("STRIPE_SECRET_KEY", "")
app.config["STRIPE_WEBHOOK_SECRET"] = os.getenv("STRIPE_WEBHOOK_SECRET", "")
app.config["STRIPE_CURRENCY"] = os.getenv("STRIPE_CURRENCY", "jpy")
app.config["PAYPAY_API_KEY"] = os.getenv("PAYPAY_API_KEY", "")
app.config["PAYPAY_API_SECRET"] = os.getenv("PAYPAY_API_SECRET", "")
app.config["PAYPAY_MERCHANT_ID"] = os.getenv("PAYPAY_MERCHANT_ID", "")
app.config["PAYPAY_API_BASE"] = os.getenv(
    "PAYPAY_API_BASE", "https://stg-api.paypay.ne.jp"
)
app.config["PUBLIC_BASE_URL"] = os.getenv(
    "PUBLIC_BASE_URL", "http://127.0.0.1:8765"
)

db = SQLAlchemy(app)

# ここを追加（db = SQLAlchemy(app) の下あたりでOK）
@app.context_processor
def inject_datetime():
    """テンプレートから datetime.utcnow() を直接使えるようにする"""
    return {"datetime": datetime}

# ローカル保存（将来S3などに切り替えやすいように関数化）
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "photos")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def get_photo_url(filename: str) -> str:
    """
    画像URLを生成する関数。
    今はローカル(static/photos)だが、将来S3にする場合はここを書き換えるだけでOK。
    """
    return f"/static/photos/{filename}"


# ==========
# 決済ユーティリティ
# ==========


def stripe_available() -> bool:
    return bool(stripe and app.config.get("STRIPE_SECRET_KEY"))


def create_stripe_checkout_session(order: "Order") -> Tuple[Optional[str], Optional[str]]:
    if not stripe_available():
        return None, "Stripe の設定が完了していません。"

    stripe.api_key = app.config["STRIPE_SECRET_KEY"]
    success_url = url_for(
        "checkout_complete", order_id=order.id, status="success", _external=True
    )
    cancel_url = url_for(
        "checkout_complete", order_id=order.id, status="canceled", _external=True
    )
    currency = app.config.get("STRIPE_CURRENCY", "jpy")

    product_name = order.product.name if order.product else "LifeShot Order"

    try:
        session_obj = stripe.checkout.Session.create(
            mode="payment",
            success_url=success_url,
            cancel_url=cancel_url,
            client_reference_id=str(order.id),
            metadata={"order_id": str(order.id)},
            line_items=[
                {
                    "price_data": {
                        "currency": currency,
                        "product_data": {"name": product_name},
                        "unit_amount": order.unit_price * 100,
                    },
                    "quantity": order.quantity,
                }
            ],
        )
        order.payment_reference = session_obj.get("id")
        db.session.commit()
        return session_obj.get("url"), None
    except Exception as exc:  # pragma: no cover - depends on external service
        return None, f"Stripeセッションの作成に失敗しました: {exc}"


def _paypay_headers(method: str, path: str, body_str: str) -> Dict[str, str]:
    api_key = app.config.get("PAYPAY_API_KEY")
    api_secret = app.config.get("PAYPAY_API_SECRET")
    merchant_id = app.config.get("PAYPAY_MERCHANT_ID")
    timestamp = str(int(time.time()))
    nonce = uuid.uuid4().hex
    payload = method + path + timestamp + nonce + body_str
    signature = hmac.new(
        api_secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    signature_b64 = base64.b64encode(signature).decode()
    authorization = (
        f"HmacSHA256 signature={signature_b64},accessKey={api_key},"
        f"nonce={nonce},timestamp={timestamp}"
    )
    return {
        "Content-Type": "application/json",
        "Authorization": authorization,
        "X-ASSUME-MERCHANT": merchant_id,
    }


def create_paypay_code(order: "Order") -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    required = [
        app.config.get("PAYPAY_API_KEY"),
        app.config.get("PAYPAY_API_SECRET"),
        app.config.get("PAYPAY_MERCHANT_ID"),
    ]
    if not all(required):
        return None, "PayPay APIの資格情報が設定されていません。"
    if requests is None:
        return None, "requests ライブラリがインストールされていません。"

    path = "/v2/codes"
    base_url = app.config.get("PAYPAY_API_BASE", "https://stg-api.paypay.ne.jp")
    redirect_url = url_for(
        "checkout_complete", order_id=order.id, status="success", _external=True
    )
    body = {
        "merchantPaymentId": f"lifeshot-{order.id}-{uuid.uuid4().hex[:8]}",
        "amount": {"amount": order.total_amount, "currency": "JPY"},
        "codeType": "ORDER_QR",
        "orderDescription": f"{order.event_name or 'LifeShot'} / {order.photo_code}",
        "isAuthorization": False,
        "redirectUrl": redirect_url,
        "redirectType": "WEB_LINK",
    }
    body_str = json.dumps(body, ensure_ascii=False, separators=(",", ":"))

    try:
        headers = _paypay_headers("POST", path, body_str)
        response = requests.post(
            f"{base_url}{path}", data=body_str.encode("utf-8"), headers=headers, timeout=10
        )
        data = response.json()
    except Exception as exc:  # pragma: no cover - depends on external service
        return None, f"PayPay APIリクエストに失敗しました: {exc}"

    if data.get("resultInfo", {}).get("code") != "SUCCESS":
        message = data.get("resultInfo", {}).get("message", "不明なエラー")
        return None, f"PayPayコード生成に失敗しました: {message}"

    return data.get("data"), None


def verify_paypay_signature(raw_body: bytes, signature_header: str) -> bool:
    secret = app.config.get("PAYPAY_API_SECRET")
    if not secret or not signature_header:
        return False
    try:
        parts = dict(item.split("=", 1) for item in signature_header.split(","))
        signature_b64 = parts.get("signature")
        timestamp = parts.get("timestamp")
        nonce = parts.get("nonce")
        if not signature_b64 or not timestamp or not nonce:
            return False
        payload = "POST" + "/webhook/paypay" + timestamp + nonce + raw_body.decode()
        expected = hmac.new(
            secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
        ).digest()
        return base64.b64encode(expected).decode() == signature_b64
    except Exception:
        return False


# ==========
# モデル定義
# ==========


class AppSetting(db.Model):
    """アプリ全体の設定（管理者パスワードなど）"""

    id = db.Column(db.Integer, primary_key=True)
    admin_password = db.Column(db.String(100), nullable=False, default="itsuki0106")
    site_name = db.Column(db.String(100), nullable=False, default="JAN Photo Studio")


class Event(db.Model):
    """試合や撮影会などのイベント"""

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)  # 例: 2025-11-16 加古川ボウル
    date = db.Column(db.Date)
    gallery_password = db.Column(db.String(100), nullable=True)
    is_public = db.Column(db.Boolean, default=True)
    note = db.Column(db.Text)

    photos = db.relationship("Photo", backref="event", lazy=True)

    def __repr__(self) -> str:  # type: ignore[override]
        return f"<Event {self.name}>"


class Product(db.Model):
    """写真商品のマスタ（L判 / 2L / データ販売 など）"""

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    kind = db.Column(db.String(20), nullable=False)  # "print" or "data" など
    price = db.Column(db.Integer, nullable=False)
    is_active = db.Column(db.Boolean, default=True)

    def __repr__(self) -> str:  # type: ignore[override]
        return f"<Product {self.name}>"


class Order(db.Model):
    """注文情報"""

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # 顧客情報
    customer_name = db.Column(db.String(100), nullable=False)
    customer_contact = db.Column(db.String(200))
    price_category = db.Column(db.String(50))  # 一般 / チーム割 / 家族 など

    # イベント情報
    event_id = db.Column(db.Integer, db.ForeignKey("event.id"))
    event_name = db.Column(db.String(150))

    # 写真識別
    photo_id = db.Column(db.Integer, db.ForeignKey("photo.id"))
    photo_code = db.Column(db.String(100))

    # 商品
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    unit_price = db.Column(db.Integer, nullable=False)
    payment_status = db.Column(db.String(20), default="unpaid")  # unpaid / paid
    payment_method = db.Column(db.String(30))  # card / paypay / manual
    payment_reference = db.Column(db.String(120))

    note = db.Column(db.Text)

    product = db.relationship("Product")
    event = db.relationship("Event")
    photo = db.relationship("Photo")

    @property
    def total_amount(self) -> int:
        return self.unit_price * self.quantity

    def __repr__(self) -> str:  # type: ignore[override]
        return f"<Order {self.id} {self.customer_name}>"


class Photo(db.Model):
    """ギャラリー用の写真"""

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey("event.id"), nullable=False)
    photo_code = db.Column(db.String(100), nullable=False)
    image_url = db.Column(db.String(255), nullable=False)
    is_public = db.Column(db.Boolean, default=True)

    orders = db.relationship("Order", backref="photo_ref", lazy=True)

    def __repr__(self) -> str:  # type: ignore[override]
        return f"<Photo {self.photo_code}>"


class GalleryAccess(db.Model):
    """ギャラリーにアクセスした履歴（誰がどのイベントを見たか）"""

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey("event.id"))
    event_name = db.Column(db.String(150))
    customer_name = db.Column(db.String(100))
    contact = db.Column(db.String(200))
    accessed_at = db.Column(db.DateTime, default=datetime.utcnow)


class Job(db.Model):
    """撮影の求人（撮ってほしい人側のリクエスト）"""

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    sport_type = db.Column(db.String(100))
    shoot_date = db.Column(db.Date)
    location = db.Column(db.String(150))
    budget_min = db.Column(db.Integer)
    budget_max = db.Column(db.Integer)
    status = db.Column(db.String(20), nullable=False, default="open")  # open/matched/closed
    client_name = db.Column(db.String(100), nullable=False)
    client_contact = db.Column(db.String(200), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey("event.id"))
    internal_note = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    event = db.relationship("Event", backref="jobs")
    offers = db.relationship(
        "Offer", back_populates="job", cascade="all, delete-orphan", lazy=True
    )

    def __repr__(self) -> str:  # type: ignore[override]
        return f"<Job {self.title}>"


class Offer(db.Model):
    """撮りたいカメラマン側の応募"""

    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey("job.id"), nullable=False)
    photographer_name = db.Column(db.String(100), nullable=False)
    photographer_contact = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text)
    quote_amount = db.Column(db.Integer)
    available_from = db.Column(db.Date)
    status = db.Column(db.String(20), nullable=False, default="pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    job = db.relationship("Job", back_populates="offers")

    def __repr__(self) -> str:  # type: ignore[override]
        return f"<Offer {self.photographer_name} -> {self.job_id}>"


# ==========
# 認証系ユーティリティ
# ==========


def admin_login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            flash("管理者ログインが必要です", "warning")
            return redirect(url_for("admin_login"))
        return view_func(*args, **kwargs)

    return wrapper


def is_event_allowed(event_id: int) -> bool:
    if session.get("admin_logged_in"):
        return True
    allowed = session.get("allowed_events", [])
    return event_id in allowed


def allow_event(event_id: int):
    allowed = session.get("allowed_events", [])
    if event_id not in allowed:
        allowed.append(event_id)
        session["allowed_events"] = allowed


# ==========
# 公開側ルーティング（お客さん用）
# ==========


@app.route("/")
def welcome():
    """JAN Photo Studio トップページ（お客さん向け）"""
    setting = AppSetting.query.get(1)
    site_name = setting.site_name if setting else "JAN Photo Studio"
    events = Event.query.filter_by(is_public=True).order_by(
        Event.date.desc().nullslast(), Event.id.desc()
    ).all()
    return render_template("welcome.html", site_name=site_name, events=events)


@app.route("/lifeshot")
@app.route("/home")
def public_home():
    """LifeShot 事業紹介ページ"""
    setting = AppSetting.query.get(1)
    site_name = setting.site_name if setting else "LifeShot"
    events = (
        Event.query.filter_by(is_public=True)
        .order_by(Event.date.desc().nullslast(), Event.id.desc())
        .limit(3)
        .all()
    )
    return render_template("public_home.html", site_name=site_name, events=events)


@app.route("/gallery")
def gallery_events():
    """公開イベント一覧"""
    events = Event.query.filter_by(is_public=True).order_by(
        Event.date.desc().nullslast(), Event.id.desc()
    ).all()
    return render_template("gallery_events.html", events=events)


@app.route("/gallery/<int:event_id>/login", methods=["GET", "POST"])
def gallery_event_login(event_id: int):
    """イベントごとのパスワード & お客様情報入力"""
    event = Event.query.get_or_404(event_id)
    if request.method == "POST":
        password = request.form.get("password") or ""
        customer_name = request.form.get("customer_name") or ""
        contact = request.form.get("contact") or ""

        if not customer_name or not contact:
            flash("お名前と連絡先は必須です。", "danger")
            return redirect(url_for("gallery_event_login", event_id=event.id))

        if event.gallery_password and password != event.gallery_password:
            flash("パスワードが違います。", "danger")
            return redirect(url_for("gallery_event_login", event_id=event.id))

        # セッションに保存
        allow_event(event.id)
        session["customer_name"] = customer_name
        session["customer_contact"] = contact

        # アクセスログ
        acc = GalleryAccess(
            event_id=event.id,
            event_name=event.name,
            customer_name=customer_name,
            contact=contact,
        )
        db.session.add(acc)
        db.session.commit()

        return redirect(url_for("gallery_photos", event_id=event.id))

    return render_template("gallery_login.html", event=event)


@app.route("/gallery/<int:event_id>/photos")
def gallery_photos(event_id: int):
    """イベントごとのギャラリー"""
    event = Event.query.get_or_404(event_id)

    if not is_event_allowed(event_id):
        flash("このギャラリーを見るにはパスワードが必要です。", "warning")
        return redirect(url_for("gallery_event_login", event_id=event.id))

    photos = Photo.query.filter_by(event_id=event.id, is_public=True).order_by(
        Photo.id.asc()
    ).all()
    return render_template("gallery_photos.html", event=event, photos=photos)


@app.route("/gallery/order/<int:photo_id>", methods=["GET", "POST"])
def gallery_order(photo_id: int):
    """ギャラリーから直接注文"""
    photo = Photo.query.get_or_404(photo_id)
    event = photo.event

    if not is_event_allowed(event.id):
        flash("この写真を注文するには、先にギャラリーパスワードを入力してください。", "warning")
        return redirect(url_for("gallery_event_login", event_id=event.id))

    products = Product.query.filter_by(is_active=True).order_by(Product.id.asc()).all()

    if request.method == "POST":
        customer_name = (
            request.form.get("customer_name")
            or session.get("customer_name")
            or ""
        )
        contact = (
            request.form.get("contact")
            or session.get("customer_contact")
            or ""
        )
        product_id = request.form.get("product_id")
        quantity = request.form.get("quantity") or "1"
        payment_method = request.form.get("payment_method") or "manual"
        note = request.form.get("note") or ""

        if not customer_name or not contact or not product_id:
            flash("お名前・連絡先・商品は必須です。", "danger")
            return redirect(url_for("gallery_order", photo_id=photo.id))

        product = Product.query.get(int(product_id))
        if not product:
            flash("商品が見つかりません。", "danger")
            return redirect(url_for("gallery_order", photo_id=photo.id))

        q = int(quantity)
        order = Order(
            customer_name=customer_name,
            customer_contact=contact,
            price_category="web",
            event_id=event.id,
            event_name=event.name,
            photo_id=photo.id,
            photo_code=photo.photo_code,
            product_id=product.id,
            quantity=q,
            unit_price=product.price,
            payment_status="pending" if payment_method in {"card", "paypay"} else "unpaid",
            payment_method=payment_method,
            note=f"[ギャラリー注文]\n連絡先: {contact}\n{note}",
        )
        db.session.add(order)
        db.session.commit()
        if payment_method in {"card", "paypay"}:
            flash("決済ページへ移動します。", "info")
            return redirect(url_for("checkout_order", order_id=order.id))
        flash("ご注文を受け付けました。カメラマンからの連絡をお待ちください。", "success")
        return redirect(url_for("gallery_photos", event_id=event.id))

    # 初期値
    init_name = session.get("customer_name", "")
    init_contact = session.get("customer_contact", "")

    return render_template(
        "gallery_order.html",
        photo=photo,
        event=event,
        products=products,
        init_name=init_name,
        init_contact=init_contact,
    )


# ==========
# 決済ルーティング
# ==========


@app.route("/checkout/<int:order_id>")
def checkout_order(order_id: int):
    order = db.session.get(Order, order_id)
    if not order:
        abort(404)
    if order.payment_status == "paid":
        flash("この注文はすでに支払い済みです。", "info")
        return redirect(
            url_for("gallery_photos", event_id=order.event_id or order.photo.event_id)
        )

    if order.payment_method == "card":
        url, error = create_stripe_checkout_session(order)
        if url:
            return redirect(url, code=303)
        flash(error or "Stripe決済を開始できませんでした。", "danger")
        return redirect(url_for("gallery_order", photo_id=order.photo_id))

    if order.payment_method == "paypay":
        paypay_data, error = create_paypay_code(order)
        if error or not paypay_data:
            flash(error or "PayPayコードの生成に失敗しました。", "danger")
            return redirect(url_for("gallery_order", photo_id=order.photo_id))
        order.payment_reference = paypay_data.get("codeId")
        db.session.commit()
        return render_template(
            "checkout_paypay.html",
            order=order,
            paypay_data=paypay_data,
        )

    flash("この注文はオンライン決済対象ではありません。", "warning")
    return redirect(url_for("gallery_photos", event_id=order.event_id))


@app.route("/checkout/complete")
def checkout_complete():
    order_id = request.args.get("order_id", type=int)
    status = request.args.get("status", "success")
    if not order_id:
        abort(404)
    order = db.session.get(Order, order_id)
    if not order:
        abort(404)
    return render_template("checkout_complete.html", order=order, status=status)


@app.route("/webhook/stripe", methods=["POST"])
def stripe_webhook():
    if not stripe_available():
        return "", 204
    secret = app.config.get("STRIPE_WEBHOOK_SECRET")
    if not secret:
        abort(400)
    payload = request.get_data()
    sig_header = request.headers.get("Stripe-Signature")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, secret)
    except Exception:
        abort(400)

    if event.get("type") == "checkout.session.completed":
        session_obj = event["data"]["object"]
        order_id = (
            session_obj.get("metadata", {}).get("order_id")
            or session_obj.get("client_reference_id")
        )
        if order_id:
            order = db.session.get(Order, int(order_id))
            if order:
                order.payment_status = "paid"
                order.payment_reference = session_obj.get("payment_intent")
                db.session.commit()

    return jsonify({"received": True})


@app.route("/webhook/paypay", methods=["POST"])
def paypay_webhook():
    signature = request.headers.get("x-paypay-signature", "")
    raw_body = request.get_data()
    if not verify_paypay_signature(raw_body, signature):
        abort(400)
    data = request.get_json(force=True, silent=True) or {}
    event_type = data.get("eventType")
    code_id = data.get("data", {}).get("codeId") or data.get("codeId")

    if event_type in {"CODE_COMPLETED", "PAYMENT_COMPLETED"} and code_id:
        order = Order.query.filter_by(payment_reference=code_id).first()
        if order:
            order.payment_status = "paid"
            db.session.commit()

    return jsonify({"received": True})


# ==========
# LifeShot マッチングMVP
# ==========


@app.route("/matching")
def matching_home():
    """撮影マッチングのハブページ"""
    jobs = (
        Job.query.order_by(Job.created_at.desc())
        .filter(Job.status != "closed")
        .all()
    )
    phase_highlights = [
        "Phase 1：スポーツ撮影マッチングで需要と供給を可視化",
        "Phase 2：販売プラットフォームと決済を連携させ収益化",
        "Phase 3：人生アーカイブに撮影データを蓄積し、文化として定着",
    ]
    return render_template(
        "matching_home.html",
        jobs=jobs,
        phase_highlights=phase_highlights,
    )


@app.route("/matching/request", methods=["GET", "POST"])
def matching_request():
    """撮ってほしい側からのリクエスト受付"""
    if request.method == "POST":
        title = request.form.get("title") or ""
        client_name = request.form.get("client_name") or ""
        client_contact = request.form.get("client_contact") or ""
        sport_type = request.form.get("sport_type") or ""
        shoot_date_str = request.form.get("shoot_date") or ""
        location = request.form.get("location") or ""
        budget_min = request.form.get("budget_min") or ""
        budget_max = request.form.get("budget_max") or ""
        description = request.form.get("description") or ""

        if not title or not client_name or not client_contact:
            flash("案件名・依頼者名・連絡先は必須です。", "danger")
            return redirect(url_for("matching_request"))

        shoot_date = None
        if shoot_date_str:
            try:
                shoot_date = datetime.strptime(shoot_date_str, "%Y-%m-%d").date()
            except ValueError:
                flash("撮影日の形式が不正です（YYYY-MM-DD）。", "danger")
                return redirect(url_for("matching_request"))

        job = Job(
            title=title,
            client_name=client_name,
            client_contact=client_contact,
            sport_type=sport_type,
            shoot_date=shoot_date,
            location=location,
            budget_min=int(budget_min) if budget_min else None,
            budget_max=int(budget_max) if budget_max else None,
            description=description,
        )
        db.session.add(job)
        db.session.commit()
        flash("撮影リクエストを受け付けました。カメラマン募集を開始します。", "success")
        return redirect(url_for("matching_job_detail", job_id=job.id))

    return render_template("matching_request.html")


@app.route("/matching/jobs/<int:job_id>", methods=["GET", "POST"])
def matching_job_detail(job_id: int):
    """撮影リクエストの詳細とカメラマン応募フォーム"""
    job = Job.query.get_or_404(job_id)
    offers = (
        Offer.query.filter_by(job_id=job.id)
        .order_by(Offer.created_at.desc())
        .all()
    )

    if request.method == "POST":
        if job.status != "open":
            flash("この案件は募集を終了しています。", "warning")
            return redirect(url_for("matching_job_detail", job_id=job.id))

        photographer_name = request.form.get("photographer_name") or ""
        photographer_contact = request.form.get("photographer_contact") or ""
        message = request.form.get("message") or ""
        quote_amount = request.form.get("quote_amount") or ""
        available_from_str = request.form.get("available_from") or ""

        if not photographer_name or not photographer_contact:
            flash("氏名と連絡先は必須です。", "danger")
            return redirect(url_for("matching_job_detail", job_id=job.id))

        available_from = None
        if available_from_str:
            try:
                available_from = datetime.strptime(
                    available_from_str, "%Y-%m-%d"
                ).date()
            except ValueError:
                flash("参加可能日の形式が不正です（YYYY-MM-DD）。", "danger")
                return redirect(url_for("matching_job_detail", job_id=job.id))

        offer = Offer(
            job_id=job.id,
            photographer_name=photographer_name,
            photographer_contact=photographer_contact,
            message=message,
            quote_amount=int(quote_amount) if quote_amount else None,
            available_from=available_from,
        )
        db.session.add(offer)
        db.session.commit()
        flash("オファーを送信しました。案件オーナーからの連絡をお待ちください。", "success")
        return redirect(url_for("matching_job_detail", job_id=job.id))

    return render_template("matching_job_detail.html", job=job, offers=offers)


# ==========
# 管理者用ルーティング
# ==========


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        password = request.form.get("password") or ""
        setting = AppSetting.query.get(1)
        admin_pw = setting.admin_password if setting else "itsuki0106"
        if password == admin_pw:
            session["admin_logged_in"] = True
            flash("管理者としてログインしました。", "success")
            return redirect(url_for("admin_dashboard"))
        else:
            flash("パスワードが違います。", "danger")
    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    flash("ログアウトしました。", "info")
    return redirect(url_for("welcome"))


@app.route("/admin")
@admin_login_required
def admin_dashboard():
    """ダッシュボード（今日の売上、累計、未払いなど）"""
    today = date.today()
    today_start = datetime(today.year, today.month, today.day)

    today_orders = Order.query.filter(Order.created_at >= today_start).all()
    today_sales = sum(o.total_amount for o in today_orders)

    all_orders = Order.query.all()
    total_sales = sum(o.total_amount for o in all_orders)
    total_count = len(all_orders)
    unpaid_count = Order.query.filter_by(payment_status="unpaid").count()

    # 最近30日分の売上推移
    daily_stats = {}
    for o in all_orders:
        d = o.created_at.date()
        daily_stats.setdefault(d, 0)
        daily_stats[d] += o.total_amount

    # 日付順に並べて配列化（Chart.js用）
    sorted_days = sorted(daily_stats.keys())
    chart_labels = [d.strftime("%m/%d") for d in sorted_days]
    chart_values = [daily_stats[d] for d in sorted_days]

    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(10).all()
    recent_access = GalleryAccess.query.order_by(
        GalleryAccess.accessed_at.desc()
    ).limit(10).all()

    return render_template(
        "dashboard.html",
        today_sales=today_sales,
        total_sales=total_sales,
        total_count=total_count,
        unpaid_count=unpaid_count,
        chart_labels=chart_labels,
        chart_values=chart_values,
        recent_orders=recent_orders,
        recent_access=recent_access,
    )


# --- 設定（管理者パスワード変更など） ---


@app.route("/admin/settings", methods=["GET", "POST"])
@admin_login_required
def admin_settings():
    setting = AppSetting.query.get(1)
    if not setting:
        setting = AppSetting(
            id=1,
            admin_password="itsuki0106",
            site_name="JAN Photo Studio",
        )
        db.session.add(setting)
        db.session.commit()

    if request.method == "POST":
        site_name = request.form.get("site_name") or setting.site_name
        new_pw = request.form.get("admin_password") or ""
        setting.site_name = site_name
        if new_pw:
            setting.admin_password = new_pw
            flash("管理者パスワードを変更しました。", "success")
        else:
            flash("サイト名を更新しました。", "success")
        db.session.commit()
        return redirect(url_for("admin_settings"))

    return render_template("admin_settings.html", setting=setting)


# --- イベント管理 ---


@app.route("/admin/events")
@admin_login_required
def admin_events():
    events = Event.query.order_by(Event.date.desc().nullslast(), Event.id.desc()).all()
    return render_template("admin_events.html", events=events)


@app.route("/admin/events/new", methods=["GET", "POST"])
@admin_login_required
def admin_event_new():
    if request.method == "POST":
        name = request.form.get("name") or ""
        date_str = request.form.get("date") or ""
        gallery_password = request.form.get("gallery_password") or ""
        is_public = request.form.get("is_public") == "on"
        note = request.form.get("note") or ""

        if not name:
            flash("イベント名は必須です。", "danger")
            return redirect(url_for("admin_event_new"))

        d = None
        if date_str:
            try:
                d = datetime.strptime(date_str, "%Y-%m-%d").date()
            except ValueError:
                flash("日付の形式が不正です（YYYY-MM-DD）。", "danger")
                return redirect(url_for("admin_event_new"))

        ev = Event(
            name=name,
            date=d,
            gallery_password=gallery_password,
            is_public=is_public,
            note=note,
        )
        db.session.add(ev)
        db.session.commit()
        flash("イベントを作成しました。", "success")
        return redirect(url_for("admin_events"))

    return render_template("admin_event_form.html", event=None)


@app.route("/admin/events/<int:event_id>/edit", methods=["GET", "POST"])
@admin_login_required
def admin_event_edit(event_id: int):
    event = Event.query.get_or_404(event_id)
    if request.method == "POST":
        name = request.form.get("name") or ""
        date_str = request.form.get("date") or ""
        gallery_password = request.form.get("gallery_password") or ""
        is_public = request.form.get("is_public") == "on"
        note = request.form.get("note") or ""

        if not name:
            flash("イベント名は必須です。", "danger")
            return redirect(url_for("admin_event_edit", event_id=event.id))

        d = None
        if date_str:
            try:
                d = datetime.strptime(date_str, "%Y-%m-%d").date()
            except ValueError:
                flash("日付の形式が不正です（YYYY-MM-DD）。", "danger")
                return redirect(url_for("admin_event_edit", event_id=event.id))

        event.name = name
        event.date = d
        event.gallery_password = gallery_password
        event.is_public = is_public
        event.note = note
        db.session.commit()
        flash("イベントを更新しました。", "success")
        return redirect(url_for("admin_events"))

    return render_template("admin_event_form.html", event=event)


@app.route("/admin/events/<int:event_id>/toggle")
@admin_login_required
def admin_event_toggle(event_id: int):
    event = Event.query.get_or_404(event_id)
    event.is_public = not event.is_public
    db.session.commit()
    flash("公開ステータスを変更しました。", "info")
    return redirect(url_for("admin_events"))


# --- 商品管理 ---


@app.route("/admin/products")
@admin_login_required
def admin_products():
    products = Product.query.order_by(
        Product.is_active.desc(), Product.id.asc()
    ).all()
    return render_template("products.html", products=products)


@app.route("/admin/products/new", methods=["GET", "POST"])
@admin_login_required
def admin_product_new():
    if request.method == "POST":
        name = request.form.get("name") or ""
        kind = request.form.get("kind") or ""
        price = request.form.get("price") or ""

        if not name or not kind or not price:
            flash("商品名・種別・価格は必須です。", "danger")
            return redirect(url_for("admin_product_new"))

        product = Product(
            name=name,
            kind=kind,
            price=int(price),
            is_active=True,
        )
        db.session.add(product)
        db.session.commit()
        flash("商品を登録しました。", "success")
        return redirect(url_for("admin_products"))

    return render_template("product_form.html", product=None)


@app.route("/admin/products/<int:product_id>/edit", methods=["GET", "POST"])
@admin_login_required
def admin_product_edit(product_id: int):
    product = Product.query.get_or_404(product_id)
    if request.method == "POST":
        name = request.form.get("name") or ""
        kind = request.form.get("kind") or ""
        price = request.form.get("price") or ""

        if not name or not kind or not price:
            flash("商品名・種別・価格は必須です。", "danger")
            return redirect(
                url_for("admin_product_edit", product_id=product.id)
            )

        product.name = name
        product.kind = kind
        product.price = int(price)
        db.session.commit()
        flash("商品を更新しました。", "success")
        return redirect(url_for("admin_products"))

    return render_template("product_form.html", product=product)


@app.route("/admin/products/<int:product_id>/toggle")
@admin_login_required
def admin_product_toggle(product_id: int):
    product = Product.query.get_or_404(product_id)
    product.is_active = not product.is_active
    db.session.commit()
    flash("販売ステータスを変更しました。", "info")
    return redirect(url_for("admin_products"))


# --- 注文管理 ---


@app.route("/admin/orders")
@admin_login_required
def admin_orders():
    q_status = request.args.get("status")  # unpaid / paid / None
    q_event = request.args.get("event") or ""
    q_customer = request.args.get("customer") or ""

    query = Order.query

    if q_status in {"paid", "unpaid"}:
        query = query.filter_by(payment_status=q_status)

    if q_event:
        like = f"%{q_event}%"
        query = query.filter(Order.event_name.ilike(like))

    if q_customer:
        like = f"%{q_customer}%"
        query = query.filter(Order.customer_name.ilike(like))

    orders = query.order_by(Order.created_at.desc()).all()
    total_sales = sum(o.total_amount for o in orders)

    return render_template(
        "orders.html",
        orders=orders,
        total_sales=total_sales,
        q_status=q_status,
        q_event=q_event,
        q_customer=q_customer,
    )


@app.route("/admin/orders/<int:order_id>")
@admin_login_required
def admin_order_detail(order_id: int):
    order = Order.query.get_or_404(order_id)
    return render_template("order_detail.html", order=order)


@app.route("/admin/orders/<int:order_id>/pay")
@admin_login_required
def admin_order_mark_paid(order_id: int):
    order = Order.query.get_or_404(order_id)
    order.payment_status = "paid"
    db.session.commit()
    flash("支払済みに更新しました。", "success")
    return redirect(url_for("admin_order_detail", order_id=order_id))


@app.route("/admin/orders/new", methods=["GET", "POST"])
@admin_login_required
def admin_order_new():
    products = Product.query.filter_by(is_active=True).order_by(
        Product.id.asc()
    ).all()
    events = Event.query.order_by(Event.date.desc().nullslast(), Event.id.desc()).all()

    if request.method == "POST":
        customer_name = request.form.get("customer_name") or ""
        customer_contact = request.form.get("customer_contact") or ""
        price_category = request.form.get("price_category") or ""
        event_id = request.form.get("event_id")
        photo_code = request.form.get("photo_code") or ""
        product_id = request.form.get("product_id")
        quantity = request.form.get("quantity") or "1"
        payment_status = request.form.get("payment_status") or "unpaid"
        unit_price_str = request.form.get("unit_price") or ""
        note = request.form.get("note") or ""

        if not customer_name or not product_id:
            flash("お客様名と商品は必須です。", "danger")
            return redirect(url_for("admin_order_new"))

        product = Product.query.get(int(product_id))
        if not product:
            flash("商品が見つかりません。", "danger")
            return redirect(url_for("admin_order_new"))

        ev = None
        if event_id:
            ev = Event.query.get(int(event_id))

        unit_price = int(unit_price_str) if unit_price_str else product.price
        q = int(quantity)

        order = Order(
            customer_name=customer_name,
            customer_contact=customer_contact,
            price_category=price_category,
            event_id=ev.id if ev else None,
            event_name=ev.name if ev else None,
            photo_code=photo_code,
            product_id=product.id,
            quantity=q,
            unit_price=unit_price,
            payment_status=payment_status,
            note=note,
        )
        db.session.add(order)
        db.session.commit()
        flash("注文を登録しました。", "success")
        return redirect(url_for("admin_orders"))

    return render_template(
        "order_form.html",
        products=products,
        events=events,
    )


# --- 写真管理（管理者用） ---


@app.route("/admin/photos")
@admin_login_required
def admin_photos():
    q_event = request.args.get("event") or ""
    event_id = request.args.get("event_id")

    query = Photo.query
    if event_id:
        query = query.filter_by(event_id=int(event_id))
    elif q_event:
        like = f"%{q_event}%"
        query = query.join(Event).filter(Event.name.ilike(like))

    photos = query.order_by(Photo.id.asc()).all()
    events = Event.query.order_by(Event.date.desc().nullslast(), Event.id.desc()).all()
    return render_template(
        "admin_photos.html",
        photos=photos,
        events=events,
        selected_event_id=event_id,
    )


@app.route("/admin/photos/bulk", methods=["GET", "POST"])
@admin_login_required
def admin_photos_bulk():
    events = Event.query.order_by(Event.date.desc().nullslast(), Event.id.desc()).all()
    if not events:
        flash("先にイベントを作成してください。", "warning")
        return redirect(url_for("admin_event_new"))

    if request.method == "POST":
        event_id = request.form.get("event_id")
        is_public = request.form.get("is_public") == "on"
        files = request.files.getlist("photos")

        if not event_id:
            flash("イベントを選択してください。", "danger")
            return redirect(url_for("admin_photos_bulk"))
        if not files or all(f.filename == "" for f in files):
            flash("アップロードする写真を選択してください。", "danger")
            return redirect(url_for("admin_photos_bulk"))

        ev = Event.query.get(int(event_id))
        if not ev:
            flash("イベントが見つかりません。", "danger")
            return redirect(url_for("admin_photos_bulk"))

        saved_count = 0
        skipped_count = 0

        for file in files:
            if not file or file.filename == "":
                continue

            filename = secure_filename(file.filename)
            if not filename:
                continue

            photo_code = os.path.splitext(filename)[0]

            # 同じイベント + 写真番号が存在する場合はスキップ
            existing = Photo.query.filter_by(
                event_id=ev.id, photo_code=photo_code
            ).first()
            if existing:
                skipped_count += 1
                continue

            # ローカルに保存（将来クラウドにする場合はこの部分を差し替え）
            save_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(save_path)

            image_url = get_photo_url(filename)

            photo = Photo(
                event_id=ev.id,
                photo_code=photo_code,
                image_url=image_url,
                is_public=is_public,
            )
            db.session.add(photo)
            saved_count += 1

        db.session.commit()
        msg = f"{saved_count} 枚の写真を登録しました。"
        if skipped_count:
            msg += f"（重複写真番号 {skipped_count} 枚はスキップしました）"
        flash(msg, "success")
        return redirect(url_for("admin_photos"))

    return render_template("photo_bulk.html", events=events)


# --- マッチング管理 ---


@app.route("/admin/matching/jobs")
@admin_login_required
def admin_matching_jobs():
    status = request.args.get("status") or ""
    query = Job.query
    if status:
        query = query.filter_by(status=status)
    jobs = query.order_by(Job.created_at.desc()).all()
    events = Event.query.order_by(Event.date.desc().nullslast(), Event.id.desc()).all()
    job_status_options = [
        ("open", "募集中"),
        ("matched", "マッチング済"),
        ("closed", "クローズ"),
    ]
    offer_status_options = [
        ("pending", "検討中"),
        ("shortlist", "優先候補"),
        ("accepted", "採用"),
        ("declined", "不採用"),
    ]
    return render_template(
        "admin_matching_jobs.html",
        jobs=jobs,
        events=events,
        selected_status=status,
        job_status_options=job_status_options,
        offer_status_options=offer_status_options,
    )


@app.route("/admin/matching/jobs/<int:job_id>/update", methods=["POST"])
@admin_login_required
def admin_matching_job_update(job_id: int):
    job = Job.query.get_or_404(job_id)
    status = request.form.get("status")
    event_id = request.form.get("event_id")
    internal_note = request.form.get("internal_note") or ""

    if status:
        job.status = status

    if event_id:
        try:
            job.event_id = int(event_id)
        except ValueError:
            job.event_id = None
    else:
        job.event_id = None

    job.internal_note = internal_note
    db.session.commit()
    flash("マッチング案件を更新しました。", "success")
    return redirect(url_for("admin_matching_jobs"))


@app.route("/admin/matching/offers/<int:offer_id>/status", methods=["POST"])
@admin_login_required
def admin_matching_offer_status(offer_id: int):
    offer = Offer.query.get_or_404(offer_id)
    status = request.form.get("status")
    if status:
        offer.status = status
        db.session.commit()
        flash("オファーのステータスを更新しました。", "success")
    else:
        flash("ステータスを選択してください。", "warning")
    return redirect(url_for("admin_matching_jobs"))


# ==========
# 起動処理
# ==========


def init_db():
    with app.app_context():
        db.create_all()
        # 設定レコードがなければ作る
        setting = AppSetting.query.get(1)
        if not setting:
            setting = AppSetting(
                id=1,
                admin_password="itsuki0106",
                site_name="JAN Photo Studio",
            )
            db.session.add(setting)
            db.session.commit()

        # デモ用イベントが何もなければ1件作る（加古川ボウル）
        if Event.query.count() == 0:
            ev = Event(
                name="2025-11-16 加古川ボウル",
                date=date(2025, 11, 16),
                gallery_password="kakogawa2025",
                is_public=True,
                note="CLUB ISLANDS の公式戦。",
            )
            db.session.add(ev)
            db.session.commit()

        if Job.query.count() == 0:
            sample_job = Job(
                title="ライフショット初期案件：ジュニアボウル撮影",
                description="小学生フラッグフットボール大会の全試合を記録し、家族へ販売したい。",
                sport_type="アメリカンフットボール",
                shoot_date=date(2025, 12, 7),
                location="神戸市 王子スタジアム",
                budget_min=30000,
                budget_max=60000,
                client_name="LifeShot 運営",
                client_contact="lifeshot@example.com",
            )
            db.session.add(sample_job)
            db.session.commit()


if __name__ == "__main__":
    init_db()
    # 自動でブラウザを開く
    try:
        webbrowser.open("http://127.0.0.1:8765/")
    except Exception:
        pass

    app.run(debug=False, port=8765)