"""
NAGORI（名残） - 写真販売SaaSプラットフォーム
Phase 1 MVP

カメラマン向け写真販売機能を提供するSaaSプラットフォーム
「残された余韻を、永遠に。」
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
import webbrowser
from datetime import datetime, date, timedelta
from functools import wraps
from typing import Any, Dict, List, Optional, Tuple

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
    send_file,
    g,
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# レート制限（ログイン試行回数制限）
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    LIMITER_AVAILABLE = True
except ImportError:
    LIMITER_AVAILABLE = False

try:
    import requests  # type: ignore[import]
except ImportError:
    requests = None  # type: ignore[assignment]

try:
    import stripe  # type: ignore[import]
except ImportError:
    stripe = None  # type: ignore[assignment]

app = Flask(__name__)

# ==========
# 設定
# ==========

default_db_dir = (
    os.getenv("DATABASE_DIR")
    or ("/tmp" if os.getenv("RENDER") else app.root_path)
)
os.makedirs(default_db_dir, exist_ok=True)
default_db_path = os.path.join(default_db_dir, "sales.db")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL", f"sqlite:///{default_db_path}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "lifeshot_secret_key_change_in_production")

# 決済関連
app.config["STRIPE_SECRET_KEY"] = os.getenv("STRIPE_SECRET_KEY", "")
app.config["STRIPE_WEBHOOK_SECRET"] = os.getenv("STRIPE_WEBHOOK_SECRET", "")
app.config["STRIPE_CURRENCY"] = os.getenv("STRIPE_CURRENCY", "jpy")
app.config["PAYPAY_API_KEY"] = os.getenv("PAYPAY_API_KEY", "")
app.config["PAYPAY_API_SECRET"] = os.getenv("PAYPAY_API_SECRET", "")
app.config["PAYPAY_MERCHANT_ID"] = os.getenv("PAYPAY_MERCHANT_ID", "")
app.config["PAYPAY_API_BASE"] = os.getenv("PAYPAY_API_BASE", "https://stg-api.paypay.ne.jp")
app.config["PUBLIC_BASE_URL"] = os.getenv("PUBLIC_BASE_URL", "http://127.0.0.1:5000")

# プラットフォーム手数料（15%）
PLATFORM_FEE_RATE = 0.15

# ==========
# セキュリティ設定
# ==========

# CSRF保護
csrf = CSRFProtect(app)

# セッションのセキュリティ設定
app.config["SESSION_COOKIE_SECURE"] = os.getenv("RENDER") is not None  # 本番環境ではHTTPS必須
app.config["SESSION_COOKIE_HTTPONLY"] = True  # JavaScriptからのアクセス禁止
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # CSRF対策
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=24)  # セッション有効期限

# ファイルアップロード制限
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

# レート制限の設定（ログイン試行回数制限）
if LIMITER_AVAILABLE:
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://",
    )
else:
    limiter = None

# ログイン試行追跡用（メモリベース、本番ではRedis推奨）
login_attempts = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 300  # 5分間ロックアウト

# 二要素認証コード保存用
verification_codes = {}
VERIFICATION_CODE_EXPIRY = 300  # 5分間有効

# 不審なIPアドレス追跡用
suspicious_ips = {}
SUSPICIOUS_THRESHOLD = 20  # 1時間に20回以上のアクセスで制限
SUSPICIOUS_WINDOW = 3600  # 1時間

db = SQLAlchemy(app)

# ==========
# セキュリティ関数
# ==========

def is_account_locked(identifier: str) -> bool:
    """アカウントがロックされているかチェック"""
    if identifier not in login_attempts:
        return False
    attempts, last_attempt = login_attempts[identifier]
    if attempts >= MAX_LOGIN_ATTEMPTS:
        if time.time() - last_attempt < LOCKOUT_DURATION:
            return True
        # ロックアウト期間が過ぎたらリセット
        del login_attempts[identifier]
    return False

def record_failed_login(identifier: str) -> int:
    """ログイン失敗を記録し、残り試行回数を返す"""
    current_time = time.time()
    if identifier in login_attempts:
        attempts, _ = login_attempts[identifier]
        login_attempts[identifier] = (attempts + 1, current_time)
    else:
        login_attempts[identifier] = (1, current_time)
    attempts, _ = login_attempts[identifier]
    return MAX_LOGIN_ATTEMPTS - attempts

def reset_login_attempts(identifier: str):
    """ログイン成功時に試行回数をリセット"""
    if identifier in login_attempts:
        del login_attempts[identifier]

def allowed_file(filename: str) -> bool:
    """許可されたファイル拡張子かチェック"""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_email(email: str) -> bool:
    """メールアドレスの簡易バリデーション"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_password(password: str) -> Tuple[bool, str]:
    """パスワードの強度チェック"""
    if len(password) < 8:
        return False, "パスワードは8文字以上で設定してください"
    return True, ""

def sanitize_input(value: str, max_length: int = 500) -> str:
    """入力値のサニタイズ"""
    if not value:
        return ""
    # 長さ制限
    value = value[:max_length]
    # 制御文字を除去
    value = "".join(char for char in value if ord(char) >= 32 or char in "\n\r\t")
    return value.strip()

def generate_verification_code() -> str:
    """6桁の認証コードを生成"""
    import random
    return str(random.randint(100000, 999999))

def store_verification_code(email: str, code: str):
    """認証コードを保存"""
    verification_codes[email] = {
        "code": code,
        "created_at": time.time(),
        "attempts": 0
    }

def verify_code(email: str, code: str) -> Tuple[bool, str]:
    """認証コードを検証"""
    if email not in verification_codes:
        return False, "認証コードが見つかりません。再度ログインしてください"
    
    data = verification_codes[email]
    
    # 有効期限チェック
    if time.time() - data["created_at"] > VERIFICATION_CODE_EXPIRY:
        del verification_codes[email]
        return False, "認証コードの有効期限が切れました。再度ログインしてください"
    
    # 試行回数チェック
    if data["attempts"] >= 3:
        del verification_codes[email]
        return False, "認証コードの入力回数が上限に達しました。再度ログインしてください"
    
    # コード検証
    if data["code"] != code:
        verification_codes[email]["attempts"] += 1
        remaining = 3 - verification_codes[email]["attempts"]
        return False, f"認証コードが正しくありません（残り{remaining}回）"
    
    # 成功
    del verification_codes[email]
    return True, ""

def is_suspicious_ip(ip_address: str) -> bool:
    """不審なIPアドレスかチェック"""
    current_time = time.time()
    
    if ip_address not in suspicious_ips:
        suspicious_ips[ip_address] = []
    
    # 古いアクセス記録を削除
    suspicious_ips[ip_address] = [
        t for t in suspicious_ips[ip_address] 
        if current_time - t < SUSPICIOUS_WINDOW
    ]
    
    # アクセスを記録
    suspicious_ips[ip_address].append(current_time)
    
    # 閾値チェック
    return len(suspicious_ips[ip_address]) > SUSPICIOUS_THRESHOLD

def send_verification_email(email: str, code: str, name: str = "") -> bool:
    """認証コードをメールで送信（本番環境ではSendGrid等を使用）"""
    # 開発環境ではコンソールに出力
    if not os.getenv("RENDER"):
        print(f"[DEBUG] 認証コード送信: {email} -> {code}")
        return True
    
    # 本番環境ではSendGrid等のメール送信サービスを使用
    # TODO: SendGrid APIを実装
    sendgrid_api_key = os.getenv("SENDGRID_API_KEY")
    if not sendgrid_api_key:
        print(f"[WARN] SendGrid未設定。認証コード: {code}")
        return True  # 設定されていない場合はスキップ
    
    try:
        # SendGrid API呼び出し
        response = requests.post(
            "https://api.sendgrid.com/v3/mail/send",
            headers={
                "Authorization": f"Bearer {sendgrid_api_key}",
                "Content-Type": "application/json"
            },
            json={
                "personalizations": [{"to": [{"email": email}]}],
                "from": {"email": os.getenv("SENDGRID_FROM_EMAIL", "noreply@nagori.app")},
                "subject": f"【NAGORI】ログイン認証コード: {code}",
                "content": [{
                    "type": "text/plain",
                    "value": f"{name}様\n\nログイン認証コードは {code} です。\n\nこのコードは5分間有効です。\n\n心当たりがない場合は、このメールを無視してください。\n\n---\nNAGORI - 名残"
                }]
            }
        )
        return response.status_code == 202
    except Exception as e:
        print(f"[ERROR] メール送信失敗: {e}")
        return False

def send_login_notification(email: str, name: str, ip_address: str) -> bool:
    """ログイン通知をメールで送信"""
    if not os.getenv("RENDER"):
        print(f"[DEBUG] ログイン通知: {email} からのログイン (IP: {ip_address})")
        return True
    
    sendgrid_api_key = os.getenv("SENDGRID_API_KEY")
    if not sendgrid_api_key:
        return True
    
    try:
        login_time = datetime.now().strftime("%Y年%m月%d日 %H:%M")
        response = requests.post(
            "https://api.sendgrid.com/v3/mail/send",
            headers={
                "Authorization": f"Bearer {sendgrid_api_key}",
                "Content-Type": "application/json"
            },
            json={
                "personalizations": [{"to": [{"email": email}]}],
                "from": {"email": os.getenv("SENDGRID_FROM_EMAIL", "noreply@nagori.app")},
                "subject": "【NAGORI】ログインがありました",
                "content": [{
                    "type": "text/plain",
                    "value": f"{name}様\n\n{login_time}にログインがありました。\n\nIPアドレス: {ip_address}\n\n心当たりがない場合は、すぐにパスワードを変更してください。\n\n---\nNAGORI - 名残"
                }]
            }
        )
        return response.status_code == 202
    except Exception as e:
        print(f"[ERROR] ログイン通知送信失敗: {e}")
        return False

def require_password_confirmation(func):
    """パスワード確認が必要なエンドポイント用デコレータ"""
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if request.method == "POST":
            current_password = request.form.get("current_password", "")
            photographer = get_current_photographer()
            if photographer and not photographer.check_password(current_password):
                flash("現在のパスワードが正しくありません", "danger")
                return redirect(request.url)
        return func(*args, **kwargs)
    return decorated_function

# セキュリティヘッダーを追加
@app.after_request
def add_security_headers(response):
    """セキュリティヘッダーを追加"""
    # XSS対策
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    # HTTPSの強制（本番環境のみ）
    if os.getenv("RENDER"):
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # CSP（Content Security Policy）
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://js.stripe.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: blob: https:; "
        "frame-src https://js.stripe.com https://hooks.stripe.com; "
        "connect-src 'self' https://api.stripe.com;"
    )
    return response

@app.context_processor
def inject_globals():
    """テンプレートから使えるグローバル変数"""
    def _get_current_photographer():
        photographer_id = session.get("photographer_id")
        if photographer_id:
            return db.session.get(Photographer, photographer_id)
        return None
    
    return {
        "datetime": datetime,
        "now": datetime.utcnow(),
        "get_current_photographer": _get_current_photographer,
    }

# ==========
# ストレージ設定（R2 または ローカル）
# ==========
R2_ACCOUNT_ID = os.environ.get("R2_ACCOUNT_ID")
R2_ACCESS_KEY_ID = os.environ.get("R2_ACCESS_KEY_ID")
R2_SECRET_ACCESS_KEY = os.environ.get("R2_SECRET_ACCESS_KEY")
R2_BUCKET_NAME = os.environ.get("R2_BUCKET_NAME", "nagori-photos")
R2_PUBLIC_URL = os.environ.get("R2_PUBLIC_URL")  # 例: https://pub-xxx.r2.dev または カスタムドメイン

# R2が設定されているかチェック
USE_R2 = all([R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_PUBLIC_URL])

if USE_R2:
    import boto3
    from botocore.config import Config
    
    s3_client = boto3.client(
        "s3",
        endpoint_url=f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com",
        aws_access_key_id=R2_ACCESS_KEY_ID,
        aws_secret_access_key=R2_SECRET_ACCESS_KEY,
        config=Config(signature_version="s3v4"),
        region_name="auto",
    )
    print("✅ Cloudflare R2 ストレージを使用します")
else:
    s3_client = None
    print("⚠️ ローカルストレージを使用します（R2未設定）")

# ローカル保存用フォルダ（R2未使用時のフォールバック）
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "photos")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def upload_to_storage(file, filename: str) -> str:
    """ファイルをストレージにアップロードし、URLを返す"""
    if USE_R2 and s3_client:
        # R2にアップロード
        s3_client.upload_fileobj(
            file,
            R2_BUCKET_NAME,
            filename,
            ExtraArgs={"ContentType": file.content_type or "image/jpeg"}
        )
        return f"{R2_PUBLIC_URL}/{filename}"
    else:
        # ローカルに保存
        save_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(save_path)
        return f"/static/photos/{filename}"

def get_photo_url(filename: str) -> str:
    """写真のURLを取得"""
    if USE_R2:
        return f"{R2_PUBLIC_URL}/{filename}"
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
    success_url = url_for("checkout_complete", order_id=order.id, status="success", _external=True)
    cancel_url = url_for("checkout_complete", order_id=order.id, status="canceled", _external=True)
    currency = app.config.get("STRIPE_CURRENCY", "jpy")

    line_items = []
    for item in order.items:
        photo = item.photo
        line_items.append({
            "price_data": {
                "currency": currency,
                "product_data": {"name": f"写真: {photo.photo_code}"},
                "unit_amount": item.price,
            },
            "quantity": 1,
        })

    try:
        session_obj = stripe.checkout.Session.create(
            mode="payment",
            success_url=success_url,
            cancel_url=cancel_url,
            client_reference_id=str(order.id),
            metadata={"order_id": str(order.id)},
            line_items=line_items,
        )
        order.stripe_payment_id = session_obj.get("id")
        db.session.commit()
        return session_obj.get("url"), None
    except Exception as exc:
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
    redirect_url = url_for("checkout_complete", order_id=order.id, status="success", _external=True)
    
    event_name = order.event.title if order.event else "LifeShot"
    body = {
        "merchantPaymentId": f"lifeshot-{order.id}-{uuid.uuid4().hex[:8]}",
        "amount": {"amount": order.total_amount, "currency": "JPY"},
        "codeType": "ORDER_QR",
        "orderDescription": f"{event_name} - {len(order.items)}枚の写真",
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
    except Exception as exc:
        return None, f"PayPay APIリクエストに失敗しました: {exc}"

    if data.get("resultInfo", {}).get("code") != "SUCCESS":
        message = data.get("resultInfo", {}).get("message", "不明なエラー")
        return None, f"PayPayコード生成に失敗しました: {message}"

    return data.get("data"), None

# ==========
# モデル定義
# ==========

class AppSetting(db.Model):
    """アプリ全体の設定（運営管理者パスワードなど）"""
    id = db.Column(db.Integer, primary_key=True)
    admin_password = db.Column(db.String(200), nullable=False, default="admin123")
    site_name = db.Column(db.String(100), nullable=False, default="NAGORI")

class Photographer(db.Model):
    """カメラマン（サービス利用者）"""
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    profile_image = db.Column(db.String(500), nullable=True)
    bank_account_info = db.Column(db.Text, nullable=True)  # JSON形式
    status = db.Column(db.String(20), default="active")  # active / suspended
    two_factor_enabled = db.Column(db.Boolean, default=False)  # 二要素認証
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    events = db.relationship("Event", backref="photographer", lazy=True)
    products = db.relationship("Product", backref="photographer", lazy=True)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def total_sales(self) -> int:
        """累計売上（カメラマン取り分）"""
        total = 0
        for event in self.events:
            for order in event.orders:
                if order.status == "paid":
                    total += order.photographer_amount
        return total

    def __repr__(self) -> str:
        return f"<Photographer {self.email}>"

class Event(db.Model):
    """イベント（撮影会・試合など）"""
    id = db.Column(db.Integer, primary_key=True)
    photographer_id = db.Column(db.Integer, db.ForeignKey("photographer.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    event_date = db.Column(db.Date, nullable=True)
    event_code = db.Column(db.String(50), unique=True, nullable=False)  # URL用コード
    password = db.Column(db.String(100), nullable=True)  # ギャラリーパスワード
    status = db.Column(db.String(20), default="draft")  # draft / published / closed
    note = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    photos = db.relationship("Photo", backref="event", lazy=True, cascade="all, delete-orphan")
    orders = db.relationship("Order", backref="event", lazy=True)

    @staticmethod
    def generate_event_code() -> str:
        """ユニークなイベントコードを生成"""
        while True:
            code = secrets.token_urlsafe(6)[:8].lower()
            if not Event.query.filter_by(event_code=code).first():
                return code

    def __repr__(self) -> str:
        return f"<Event {self.title}>"

class Photo(db.Model):
    """写真"""
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey("event.id"), nullable=False)
    filename = db.Column(db.String(300), nullable=False)
    storage_url = db.Column(db.String(500), nullable=False)
    thumbnail_url = db.Column(db.String(500), nullable=True)
    photo_code = db.Column(db.String(100), nullable=False)
    width = db.Column(db.Integer, nullable=True)
    height = db.Column(db.Integer, nullable=True)
    file_size = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<Photo {self.photo_code}>"

class Product(db.Model):
    """商品設定（価格設定）"""
    id = db.Column(db.Integer, primary_key=True)
    photographer_id = db.Column(db.Integer, db.ForeignKey("photographer.id"), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    product_type = db.Column(db.String(20), nullable=False)  # data / print_l / print_2l
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<Product {self.name}>"

class Order(db.Model):
    """注文"""
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey("event.id"), nullable=False)
    buyer_email = db.Column(db.String(200), nullable=False)
    buyer_name = db.Column(db.String(100), nullable=False)
    total_amount = db.Column(db.Integer, nullable=False)  # 合計金額
    platform_fee = db.Column(db.Integer, nullable=False)  # 手数料（15%）
    photographer_amount = db.Column(db.Integer, nullable=False)  # カメラマン取り分（85%）
    status = db.Column(db.String(20), default="pending")  # pending / paid / downloaded / refunded
    payment_method = db.Column(db.String(30), nullable=True)  # card / paypay
    stripe_payment_id = db.Column(db.String(200), nullable=True)
    download_token = db.Column(db.String(100), nullable=True)
    download_expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    items = db.relationship("OrderItem", backref="order", lazy=True, cascade="all, delete-orphan")

    def generate_download_token(self):
        """ダウンロードトークンを生成（有効期限7日）"""
        self.download_token = secrets.token_urlsafe(32)
        self.download_expires_at = datetime.utcnow() + timedelta(days=7)

    def __repr__(self) -> str:
        return f"<Order {self.id}>"

class OrderItem(db.Model):
    """注文明細"""
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("order.id"), nullable=False)
    photo_id = db.Column(db.Integer, db.ForeignKey("photo.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    download_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    photo = db.relationship("Photo")
    product = db.relationship("Product")

    def __repr__(self) -> str:
        return f"<OrderItem {self.id}>"

class Cart(db.Model):
    """カート（セッションベース）"""
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(100), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey("event.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    items = db.relationship("CartItem", backref="cart", lazy=True, cascade="all, delete-orphan")
    event = db.relationship("Event")

    @property
    def total_amount(self) -> int:
        return sum(item.price for item in self.items)

    @property
    def item_count(self) -> int:
        return len(self.items)

class CartItem(db.Model):
    """カートアイテム"""
    id = db.Column(db.Integer, primary_key=True)
    cart_id = db.Column(db.Integer, db.ForeignKey("cart.id"), nullable=False)
    photo_id = db.Column(db.Integer, db.ForeignKey("photo.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    photo = db.relationship("Photo")
    product = db.relationship("Product")

class GalleryAccess(db.Model):
    """ギャラリーアクセス履歴"""
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey("event.id"))
    visitor_name = db.Column(db.String(100), nullable=True)
    visitor_email = db.Column(db.String(200), nullable=True)
    accessed_at = db.Column(db.DateTime, default=datetime.utcnow)

# ==========
# 認証ユーティリティ
# ==========

def get_current_photographer() -> Optional[Photographer]:
    """現在ログイン中のカメラマンを取得"""
    # デコレータでgに格納されている場合はそれを使用
    if hasattr(g, 'current_photographer') and g.current_photographer:
        return g.current_photographer
    photographer_id = session.get("photographer_id")
    if photographer_id:
        return db.session.get(Photographer, photographer_id)
    return None

def photographer_required(view_func):
    """カメラマンログインが必要なルート用デコレータ"""
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        photographer_id = session.get("photographer_id")
        if not photographer_id:
            flash("ログインが必要です", "warning")
            return redirect(url_for("photographer_login"))
        # DBにphotographerが存在するか確認
        photographer = db.session.get(Photographer, photographer_id)
        if not photographer:
            session.pop("photographer_id", None)
            flash("セッションが無効です。再度ログインしてください", "warning")
            return redirect(url_for("photographer_login"))
        # gオブジェクトにphotographerを格納（ビュー関数で再利用）
        g.current_photographer = photographer
        return view_func(*args, **kwargs)
    return wrapper

def admin_required(view_func):
    """運営管理者ログインが必要なルート用デコレータ"""
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            flash("管理者ログインが必要です", "warning")
            return redirect(url_for("admin_login"))
        return view_func(*args, **kwargs)
    return wrapper

def get_or_create_cart(event_id: int) -> Cart:
    """セッションに紐づくカートを取得または作成"""
    session_id = session.get("cart_session_id")
    if not session_id:
        session_id = secrets.token_urlsafe(16)
        session["cart_session_id"] = session_id

    cart = Cart.query.filter_by(session_id=session_id, event_id=event_id).first()
    if not cart:
        cart = Cart(session_id=session_id, event_id=event_id)
        db.session.add(cart)
        db.session.commit()
    return cart

def is_gallery_authorized(event_id: int) -> bool:
    """ギャラリーへのアクセス権限があるか"""
    authorized = session.get("authorized_events", [])
    return event_id in authorized

def authorize_gallery(event_id: int):
    """ギャラリーへのアクセスを許可"""
    authorized = session.get("authorized_events", [])
    if event_id not in authorized:
        authorized.append(event_id)
        session["authorized_events"] = authorized

# ==========
# 公開ページ（トップ・LP）
# ==========

@app.route("/")
def home():
    """LifeShot トップページ"""
    setting = AppSetting.query.get(1)
    site_name = setting.site_name if setting else "LifeShot"
    return render_template("public_home.html", site_name=site_name)

# ==========
# カメラマン認証
# ==========

@app.route("/signup", methods=["GET", "POST"])
def photographer_signup():
    """カメラマン新規登録"""
    if request.method == "POST":
        # 入力値のサニタイズ
        email = sanitize_input(request.form.get("email", ""), max_length=254).lower()
        password = request.form.get("password", "")
        name = sanitize_input(request.form.get("name", ""), max_length=100)

        if not email or not password or not name:
            flash("すべての項目を入力してください", "danger")
            return redirect(url_for("photographer_signup"))
        
        # メールアドレスのバリデーション
        if not validate_email(email):
            flash("有効なメールアドレスを入力してください", "danger")
            return redirect(url_for("photographer_signup"))
        
        # パスワードのバリデーション
        is_valid, error_msg = validate_password(password)
        if not is_valid:
            flash(error_msg, "danger")
            return redirect(url_for("photographer_signup"))
        
        # 名前の長さチェック
        if len(name) < 1 or len(name) > 50:
            flash("お名前は1〜50文字で入力してください", "danger")
            return redirect(url_for("photographer_signup"))

        if Photographer.query.filter_by(email=email).first():
            flash("このメールアドレスは既に登録されています", "danger")
            return redirect(url_for("photographer_signup"))

        photographer = Photographer(email=email, name=name)
        photographer.set_password(password)
        db.session.add(photographer)
        db.session.commit()

        # 自動ログイン
        session["photographer_id"] = photographer.id
        session.permanent = True
        flash(f"ようこそ {name} さん！アカウントが作成されました", "success")
        return redirect(url_for("photographer_dashboard"))

    return render_template("photographer_signup.html")

@app.route("/login", methods=["GET", "POST"])
def photographer_login():
    """カメラマンログイン"""
    # 不審なIPアドレスチェック
    client_ip = request.remote_addr
    if is_suspicious_ip(client_ip):
        flash("アクセスが制限されています。しばらく時間をおいて再度お試しください", "danger")
        return render_template("photographer_login.html")
    
    if request.method == "POST":
        email = sanitize_input(request.form.get("email", "")).lower()
        password = request.form.get("password", "")
        
        # アカウントロックチェック
        lock_key = f"photographer:{email}"
        if is_account_locked(lock_key):
            # セキュリティ：ロック時間を明示しない（汎用エラー）
            flash("認証に失敗しました。しばらく時間をおいて再度お試しください", "danger")
            return redirect(url_for("photographer_login"))

        photographer = Photographer.query.filter_by(email=email).first()
        if photographer and photographer.check_password(password):
            if photographer.status == "suspended":
                # セキュリティ：停止理由を明示しない
                flash("認証に失敗しました", "danger")
                return redirect(url_for("photographer_login"))
            
            # ログイン成功：試行回数リセット
            reset_login_attempts(lock_key)
            
            # 二要素認証が有効な場合
            if photographer.two_factor_enabled:
                code = generate_verification_code()
                store_verification_code(email, code)
                send_verification_email(email, code, photographer.name)
                session["pending_2fa_email"] = email
                flash("認証コードをメールで送信しました", "info")
                return redirect(url_for("verify_2fa"))
            
            # 通常ログイン
            session["photographer_id"] = photographer.id
            session.permanent = True
            
            # ログイン通知を送信
            send_login_notification(email, photographer.name, client_ip)
            
            flash(f"ようこそ {photographer.name} さん！", "success")
            return redirect(url_for("photographer_dashboard"))

        # ログイン失敗：試行回数を記録
        remaining = record_failed_login(lock_key)
        # セキュリティ：エラー内容を詳しく表示しない
        flash("メールアドレスまたはパスワードが正しくありません", "danger")

    return render_template("photographer_login.html")

@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    """二要素認証コード確認"""
    email = session.get("pending_2fa_email")
    if not email:
        return redirect(url_for("photographer_login"))
    
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        
        is_valid, error_msg = verify_code(email, code)
        if is_valid:
            photographer = Photographer.query.filter_by(email=email).first()
            if photographer:
                session.pop("pending_2fa_email", None)
                session["photographer_id"] = photographer.id
                session.permanent = True
                
                # ログイン通知を送信
                send_login_notification(email, photographer.name, request.remote_addr)
                
                flash(f"ようこそ {photographer.name} さん！", "success")
                return redirect(url_for("photographer_dashboard"))
        else:
            flash(error_msg, "danger")
    
    return render_template("verify_2fa.html", email=email)

@app.route("/logout")
def photographer_logout():
    """カメラマンログアウト"""
    session.pop("photographer_id", None)
    flash("ログアウトしました", "info")
    return redirect(url_for("home"))

# ==========
# カメラマンダッシュボード
# ==========

@app.route("/dashboard")
@photographer_required
def photographer_dashboard():
    """カメラマンダッシュボード"""
    photographer = get_current_photographer()
    
    # 統計情報
    events = Event.query.filter_by(photographer_id=photographer.id).all()
    total_photos = sum(len(e.photos) for e in events)
    
    # 売上情報
    paid_orders = []
    for event in events:
        for order in event.orders:
            if order.status == "paid":
                paid_orders.append(order)
    
    total_sales = sum(o.photographer_amount for o in paid_orders)
    total_orders = len(paid_orders)
    
    # 今月の売上
    today = date.today()
    month_start = datetime(today.year, today.month, 1)
    monthly_orders = [o for o in paid_orders if o.created_at >= month_start]
    monthly_sales = sum(o.photographer_amount for o in monthly_orders)
    
    # 最近の注文
    recent_orders = sorted(paid_orders, key=lambda x: x.created_at, reverse=True)[:5]
    
    return render_template(
        "photographer_dashboard.html",
        photographer=photographer,
        events=events,
        total_photos=total_photos,
        total_sales=total_sales,
        total_orders=total_orders,
        monthly_sales=monthly_sales,
        recent_orders=recent_orders,
    )

# ==========
# イベント管理（カメラマン）
# ==========

@app.route("/events")
@photographer_required
def photographer_events():
    """イベント一覧"""
    photographer = get_current_photographer()
    events = Event.query.filter_by(photographer_id=photographer.id).order_by(
        Event.event_date.desc().nullslast(), Event.id.desc()
    ).all()
    return render_template("photographer_events.html", events=events)

@app.route("/events/new", methods=["GET", "POST"])
@photographer_required
def photographer_event_new():
    """イベント作成"""
    photographer = get_current_photographer()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        event_date_str = request.form.get("event_date", "")
        password = request.form.get("password", "").strip()
        note = request.form.get("note", "").strip()

        if not title:
            flash("イベント名は必須です", "danger")
            return redirect(url_for("photographer_event_new"))

        event_date = None
        if event_date_str:
            try:
                event_date = datetime.strptime(event_date_str, "%Y-%m-%d").date()
            except ValueError:
                flash("日付の形式が不正です", "danger")
                return redirect(url_for("photographer_event_new"))

        event = Event(
            photographer_id=photographer.id,
            title=title,
            event_date=event_date,
            event_code=Event.generate_event_code(),
            password=password if password else None,
            status="draft",
            note=note,
        )
        db.session.add(event)
        db.session.commit()

        flash("イベントを作成しました", "success")
        return redirect(url_for("photographer_event_detail", event_id=event.id))

    return render_template("photographer_event_form.html", event=None)

@app.route("/events/<int:event_id>")
@photographer_required
def photographer_event_detail(event_id: int):
    """イベント詳細"""
    photographer = get_current_photographer()
    event = Event.query.filter_by(id=event_id, photographer_id=photographer.id).first_or_404()
    
    # 売上情報
    paid_orders = [o for o in event.orders if o.status == "paid"]
    total_sales = sum(o.photographer_amount for o in paid_orders)
    
    return render_template(
        "photographer_event_detail.html",
        event=event,
        paid_orders=paid_orders,
        total_sales=total_sales,
    )

@app.route("/events/<int:event_id>/edit", methods=["GET", "POST"])
@photographer_required
def photographer_event_edit(event_id: int):
    """イベント編集"""
    photographer = get_current_photographer()
    event = Event.query.filter_by(id=event_id, photographer_id=photographer.id).first_or_404()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        event_date_str = request.form.get("event_date", "")
        password = request.form.get("password", "").strip()
        status = request.form.get("status", "draft")
        note = request.form.get("note", "").strip()

        if not title:
            flash("イベント名は必須です", "danger")
            return redirect(url_for("photographer_event_edit", event_id=event.id))

        event_date = None
        if event_date_str:
            try:
                event_date = datetime.strptime(event_date_str, "%Y-%m-%d").date()
            except ValueError:
                flash("日付の形式が不正です", "danger")
                return redirect(url_for("photographer_event_edit", event_id=event.id))

        event.title = title
        event.event_date = event_date
        event.password = password if password else None
        event.status = status
        event.note = note
        db.session.commit()

        flash("イベントを更新しました", "success")
        return redirect(url_for("photographer_event_detail", event_id=event.id))

    return render_template("photographer_event_form.html", event=event)

@app.route("/events/<int:event_id>/delete", methods=["POST"])
@photographer_required
def photographer_event_delete(event_id: int):
    """イベント削除"""
    photographer = get_current_photographer()
    event = Event.query.filter_by(id=event_id, photographer_id=photographer.id).first_or_404()

    # 注文がある場合は削除不可
    if event.orders:
        flash("注文があるイベントは削除できません", "danger")
        return redirect(url_for("photographer_event_detail", event_id=event.id))

    db.session.delete(event)
    db.session.commit()
    flash("イベントを削除しました", "success")
    return redirect(url_for("photographer_events"))

# ==========
# 写真アップロード（カメラマン）
# ==========

@app.route("/events/<int:event_id>/upload", methods=["GET", "POST"])
@photographer_required
def photographer_photos_upload(event_id: int):
    """写真アップロード"""
    photographer = get_current_photographer()
    if not photographer:
        flash("ログインが必要です", "warning")
        return redirect(url_for("photographer_login"))
    event = Event.query.filter_by(id=event_id, photographer_id=photographer.id).first_or_404()

    if request.method == "POST":
        files = request.files.getlist("photos")
        
        # 非同期アップロード（Fetch API）の場合はJSONを返す
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or \
                  'application/json' in request.headers.get('Accept', '')
        
        if not files or all(f.filename == "" for f in files):
            if is_ajax:
                return jsonify({"success": False, "error": "ファイルがありません"}), 400
            flash("アップロードする写真を選択してください", "danger")
            return redirect(url_for("photographer_photos_upload", event_id=event.id))

        saved_count = 0
        skipped_count = 0
        rejected_count = 0

        for file in files:
            if not file or file.filename == "":
                continue

            filename = secure_filename(file.filename)
            if not filename:
                continue
            
            # セキュリティ：ファイル拡張子チェック
            if not allowed_file(filename):
                rejected_count += 1
                continue

            photo_code = os.path.splitext(filename)[0]

            # 重複チェック
            existing = Photo.query.filter_by(event_id=event.id, photo_code=photo_code).first()
            if existing:
                skipped_count += 1
                continue

            # ユニークなファイル名を生成
            unique_filename = f"{event.event_code}_{uuid.uuid4().hex[:8]}_{filename}"
            
            # ストレージにアップロード（R2またはローカル）
            storage_url = upload_to_storage(file, unique_filename)

            photo = Photo(
                event_id=event.id,
                filename=filename,
                storage_url=storage_url,
                thumbnail_url=storage_url,  # 同じURLを使用（将来的にサムネイル生成）
                photo_code=photo_code,
            )
            db.session.add(photo)
            saved_count += 1

        db.session.commit()
        
        # 非同期の場合はJSONを返す
        if is_ajax:
            return jsonify({
                "success": True,
                "saved": saved_count,
                "skipped": skipped_count,
                "rejected": rejected_count
            })

        msg = f"{saved_count}枚の写真をアップロードしました"
        if skipped_count:
            msg += f"（{skipped_count}枚は重複のためスキップ）"
        if rejected_count:
            msg += f"（{rejected_count}枚は非対応形式のため拒否）"
        flash(msg, "success" if saved_count > 0 else "warning")
        return redirect(url_for("photographer_event_detail", event_id=event.id))

    return render_template("photographer_photos_upload.html", event=event)

@app.route("/photos/<int:photo_id>/delete", methods=["POST"])
@photographer_required
def photographer_photo_delete(photo_id: int):
    """写真削除"""
    photographer = get_current_photographer()
    photo = Photo.query.get_or_404(photo_id)
    event = photo.event

    if event.photographer_id != photographer.id:
        abort(403)

    event_id = photo.event_id
    db.session.delete(photo)
    db.session.commit()
    flash("写真を削除しました", "success")
    return redirect(url_for("photographer_event_detail", event_id=event_id))

# ==========
# 商品設定（カメラマン）
# ==========

@app.route("/settings/products")
@photographer_required
def photographer_products():
    """商品設定"""
    photographer = get_current_photographer()
    products = Product.query.filter_by(photographer_id=photographer.id).order_by(Product.id.asc()).all()
    return render_template("photographer_products.html", products=products)

@app.route("/settings/products/new", methods=["GET", "POST"])
@photographer_required
def photographer_product_new():
    """商品追加"""
    photographer = get_current_photographer()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        price = request.form.get("price", "")
        product_type = request.form.get("product_type", "data")

        if not name or not price:
            flash("商品名と価格は必須です", "danger")
            return redirect(url_for("photographer_product_new"))

        try:
            price = int(price)
        except ValueError:
            flash("価格は数値で入力してください", "danger")
            return redirect(url_for("photographer_product_new"))

        product = Product(
            photographer_id=photographer.id,
            name=name,
            price=price,
            product_type=product_type,
        )
        db.session.add(product)
        db.session.commit()

        flash("商品を追加しました", "success")
        return redirect(url_for("photographer_products"))

    return render_template("photographer_product_form.html", product=None)

@app.route("/settings/products/<int:product_id>/edit", methods=["GET", "POST"])
@photographer_required
def photographer_product_edit(product_id: int):
    """商品編集"""
    photographer = get_current_photographer()
    product = Product.query.filter_by(id=product_id, photographer_id=photographer.id).first_or_404()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        price = request.form.get("price", "")
        product_type = request.form.get("product_type", "data")
        is_active = request.form.get("is_active") == "on"

        if not name or not price:
            flash("商品名と価格は必須です", "danger")
            return redirect(url_for("photographer_product_edit", product_id=product.id))

        try:
            price = int(price)
        except ValueError:
            flash("価格は数値で入力してください", "danger")
            return redirect(url_for("photographer_product_edit", product_id=product.id))

        product.name = name
        product.price = price
        product.product_type = product_type
        product.is_active = is_active
        db.session.commit()

        flash("商品を更新しました", "success")
        return redirect(url_for("photographer_products"))

    return render_template("photographer_product_form.html", product=product)

# ==========
# 売上確認（カメラマン）
# ==========

@app.route("/sales")
@photographer_required
def photographer_sales():
    """売上確認"""
    photographer = get_current_photographer()
    events = Event.query.filter_by(photographer_id=photographer.id).all()
    
    all_orders = []
    for event in events:
        for order in event.orders:
            if order.status == "paid":
                all_orders.append(order)
    
    # 日別集計
    daily_sales = {}
    for order in all_orders:
        d = order.created_at.date()
        if d not in daily_sales:
            daily_sales[d] = 0
        daily_sales[d] += order.photographer_amount
    
    sorted_days = sorted(daily_sales.keys(), reverse=True)[:30]
    chart_labels = [d.strftime("%m/%d") for d in reversed(sorted_days)]
    chart_values = [daily_sales[d] for d in reversed(sorted_days)]
    
    total_sales = sum(daily_sales.values())
    
    return render_template(
        "photographer_sales.html",
        orders=sorted(all_orders, key=lambda x: x.created_at, reverse=True),
        total_sales=total_sales,
        chart_labels=chart_labels,
        chart_values=chart_values,
    )

# ==========
# アカウント設定（カメラマン）
# ==========

@app.route("/settings")
@photographer_required
def photographer_settings():
    """アカウント設定"""
    photographer = get_current_photographer()
    return render_template("photographer_settings.html", photographer=photographer)

@app.route("/settings/update", methods=["POST"])
@photographer_required
def photographer_settings_update():
    """アカウント設定更新"""
    photographer = get_current_photographer()

    name = request.form.get("name", "").strip()
    bank_info = request.form.get("bank_account_info", "").strip()

    if name:
        photographer.name = name
    photographer.bank_account_info = bank_info
    db.session.commit()

    flash("設定を更新しました", "success")
    return redirect(url_for("photographer_settings"))

@app.route("/settings/password", methods=["POST"])
@photographer_required
def photographer_password_change():
    """パスワード変更"""
    photographer = get_current_photographer()

    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not photographer.check_password(current_password):
        flash("現在のパスワードが正しくありません", "danger")
        return redirect(url_for("photographer_settings"))

    if len(new_password) < 8:
        flash("新しいパスワードは8文字以上で設定してください", "danger")
        return redirect(url_for("photographer_settings"))

    if new_password != confirm_password:
        flash("新しいパスワードが一致しません", "danger")
        return redirect(url_for("photographer_settings"))

    photographer.set_password(new_password)
    db.session.commit()

    flash("パスワードを変更しました", "success")
    return redirect(url_for("photographer_settings"))

@app.route("/settings/2fa", methods=["POST"])
@photographer_required
def photographer_toggle_2fa():
    """二要素認証のオン/オフ切り替え"""
    photographer = get_current_photographer()
    current_password = request.form.get("current_password", "")
    
    # パスワード確認（属性変更時の再認証）
    if not photographer.check_password(current_password):
        flash("パスワードが正しくありません", "danger")
        return redirect(url_for("photographer_settings"))
    
    # トグル
    photographer.two_factor_enabled = not photographer.two_factor_enabled
    db.session.commit()
    
    if photographer.two_factor_enabled:
        flash("二要素認証を有効にしました。次回ログイン時から認証コードが必要になります", "success")
    else:
        flash("二要素認証を無効にしました", "info")
    
    return redirect(url_for("photographer_settings"))

# ==========
# ギャラリー（購入者向け）
# ==========

@app.route("/g/<event_code>")
def gallery_login(event_code: str):
    """ギャラリーログイン"""
    event = Event.query.filter_by(event_code=event_code).first_or_404()

    if event.status != "published":
        abort(404)

    # 認証済みならギャラリーへ
    if is_gallery_authorized(event.id) or not event.password:
        authorize_gallery(event.id)
        return redirect(url_for("gallery_photos", event_code=event_code))

    return render_template("gallery_login.html", event=event)

@app.route("/g/<event_code>/auth", methods=["POST"])
def gallery_auth(event_code: str):
    """ギャラリー認証"""
    event = Event.query.filter_by(event_code=event_code).first_or_404()

    password = request.form.get("password", "")
    visitor_name = request.form.get("visitor_name", "").strip()
    visitor_email = request.form.get("visitor_email", "").strip()

    if event.password and password != event.password:
        flash("パスワードが正しくありません", "danger")
        return redirect(url_for("gallery_login", event_code=event_code))

    # アクセス記録
    access = GalleryAccess(
        event_id=event.id,
        visitor_name=visitor_name,
        visitor_email=visitor_email,
    )
    db.session.add(access)
    db.session.commit()

    # セッションに保存
    authorize_gallery(event.id)
    session["visitor_name"] = visitor_name
    session["visitor_email"] = visitor_email

    return redirect(url_for("gallery_photos", event_code=event_code))

@app.route("/g/<event_code>/photos")
def gallery_photos(event_code: str):
    """ギャラリー写真一覧"""
    event = Event.query.filter_by(event_code=event_code).first_or_404()

    if event.status != "published":
        abort(404)

    if not is_gallery_authorized(event.id) and event.password:
        return redirect(url_for("gallery_login", event_code=event_code))

    photos = Photo.query.filter_by(event_id=event.id).order_by(Photo.id.asc()).all()
    products = Product.query.filter_by(
        photographer_id=event.photographer_id,
        is_active=True
    ).all()

    # カート情報
    cart = get_or_create_cart(event.id)
    cart_photo_ids = [item.photo_id for item in cart.items]

    return render_template(
        "gallery_photos.html",
        event=event,
        photos=photos,
        products=products,
        cart=cart,
        cart_photo_ids=cart_photo_ids,
    )

# ==========
# カート（購入者向け）
# ==========

@app.route("/g/<event_code>/cart/add", methods=["POST"])
def cart_add(event_code: str):
    """カートに追加"""
    event = Event.query.filter_by(event_code=event_code).first_or_404()

    if not is_gallery_authorized(event.id) and event.password:
        return jsonify({"error": "認証が必要です"}), 401

    photo_id = request.form.get("photo_id", type=int)
    product_id = request.form.get("product_id", type=int)

    photo = Photo.query.filter_by(id=photo_id, event_id=event.id).first()
    product = Product.query.filter_by(
        id=product_id,
        photographer_id=event.photographer_id,
        is_active=True
    ).first()

    if not photo or not product:
        flash("写真または商品が見つかりません", "danger")
        return redirect(url_for("gallery_photos", event_code=event_code))

    cart = get_or_create_cart(event.id)

    # 既にカートにあるかチェック
    existing = CartItem.query.filter_by(cart_id=cart.id, photo_id=photo_id).first()
    if existing:
        flash("この写真は既にカートに入っています", "info")
        return redirect(url_for("gallery_photos", event_code=event_code))

    cart_item = CartItem(
        cart_id=cart.id,
        photo_id=photo_id,
        product_id=product_id,
        price=product.price,
    )
    db.session.add(cart_item)
    db.session.commit()

    flash("カートに追加しました", "success")
    return redirect(url_for("gallery_photos", event_code=event_code))

@app.route("/g/<event_code>/cart/remove/<int:item_id>", methods=["POST"])
def cart_remove(event_code: str, item_id: int):
    """カートから削除"""
    event = Event.query.filter_by(event_code=event_code).first_or_404()
    cart = get_or_create_cart(event.id)

    item = CartItem.query.filter_by(id=item_id, cart_id=cart.id).first()
    if item:
        db.session.delete(item)
        db.session.commit()
        flash("カートから削除しました", "success")

    return redirect(url_for("gallery_cart", event_code=event_code))

@app.route("/g/<event_code>/cart")
def gallery_cart(event_code: str):
    """カート確認"""
    event = Event.query.filter_by(event_code=event_code).first_or_404()

    if not is_gallery_authorized(event.id) and event.password:
        return redirect(url_for("gallery_login", event_code=event_code))

    cart = get_or_create_cart(event.id)

    return render_template(
        "gallery_cart.html",
        event=event,
        cart=cart,
    )

# ==========
# チェックアウト（購入者向け）
# ==========

@app.route("/g/<event_code>/checkout", methods=["GET", "POST"])
def gallery_checkout(event_code: str):
    """チェックアウト"""
    event = Event.query.filter_by(event_code=event_code).first_or_404()

    if not is_gallery_authorized(event.id) and event.password:
        return redirect(url_for("gallery_login", event_code=event_code))

    cart = get_or_create_cart(event.id)

    if not cart.items:
        flash("カートが空です", "warning")
        return redirect(url_for("gallery_photos", event_code=event_code))

    if request.method == "POST":
        buyer_name = request.form.get("buyer_name", "").strip()
        buyer_email = request.form.get("buyer_email", "").strip()
        payment_method = request.form.get("payment_method", "card")

        if not buyer_name or not buyer_email:
            flash("お名前とメールアドレスは必須です", "danger")
            return redirect(url_for("gallery_checkout", event_code=event_code))

        # 注文作成
        total_amount = cart.total_amount
        platform_fee = int(total_amount * PLATFORM_FEE_RATE)
        photographer_amount = total_amount - platform_fee

        order = Order(
            event_id=event.id,
            buyer_name=buyer_name,
            buyer_email=buyer_email,
            total_amount=total_amount,
            platform_fee=platform_fee,
            photographer_amount=photographer_amount,
            status="pending",
            payment_method=payment_method,
        )
        db.session.add(order)
        db.session.flush()

        # 注文明細作成
        for item in cart.items:
            order_item = OrderItem(
                order_id=order.id,
                photo_id=item.photo_id,
                product_id=item.product_id,
                price=item.price,
            )
            db.session.add(order_item)

        # カートをクリア
        for item in cart.items:
            db.session.delete(item)

        db.session.commit()

        # 決済へ
        if payment_method == "card":
            url, error = create_stripe_checkout_session(order)
            if url:
                return redirect(url, code=303)
            flash(error or "決済を開始できませんでした", "danger")
            return redirect(url_for("gallery_checkout", event_code=event_code))
        elif payment_method == "paypay":
            paypay_data, error = create_paypay_code(order)
            if error or not paypay_data:
                flash(error or "PayPayコードの生成に失敗しました", "danger")
                return redirect(url_for("gallery_checkout", event_code=event_code))
            order.stripe_payment_id = paypay_data.get("codeId")
            db.session.commit()
            return render_template("checkout_paypay.html", order=order, paypay_data=paypay_data)

    return render_template(
        "gallery_checkout.html",
        event=event,
        cart=cart,
        visitor_name=session.get("visitor_name", ""),
        visitor_email=session.get("visitor_email", ""),
    )

@app.route("/checkout/complete")
def checkout_complete():
    """決済完了"""
    order_id = request.args.get("order_id", type=int)
    status = request.args.get("status", "success")

    if not order_id:
        abort(404)

    order = db.session.get(Order, order_id)
    if not order:
        abort(404)

    # Stripeの場合、成功時はWebhookで処理されるが、ここでも確認
    if status == "success" and order.status == "pending":
        order.status = "paid"
        order.generate_download_token()
        db.session.commit()

    return render_template("checkout_complete.html", order=order, status=status)

# ==========
# ダウンロード（購入者向け）
# ==========

@app.route("/download/<token>")
def download_page(token: str):
    """ダウンロードページ"""
    order = Order.query.filter_by(download_token=token).first_or_404()

    if order.status != "paid":
        flash("この注文はまだ支払いが完了していません", "warning")
        return redirect(url_for("home"))

    if order.download_expires_at and order.download_expires_at < datetime.utcnow():
        flash("ダウンロードリンクの有効期限が切れています", "warning")
        return redirect(url_for("home"))

    return render_template("download_page.html", order=order)

@app.route("/download/<token>/<int:item_id>")
def download_photo(token: str, item_id: int):
    """写真ダウンロード"""
    order = Order.query.filter_by(download_token=token).first_or_404()

    if order.status != "paid":
        abort(403)

    if order.download_expires_at and order.download_expires_at < datetime.utcnow():
        abort(403)

    item = OrderItem.query.filter_by(id=item_id, order_id=order.id).first_or_404()
    photo = item.photo

    # ダウンロードカウント更新
    item.download_count += 1
    db.session.commit()

    # ファイルパス
    filename = photo.storage_url.replace("/static/photos/", "")
    file_path = os.path.join(UPLOAD_FOLDER, filename)

    if not os.path.exists(file_path):
        abort(404)

    return send_file(
        file_path,
        as_attachment=True,
        download_name=photo.filename,
    )

# ==========
# Webhook
# ==========

@app.route("/webhook/stripe", methods=["POST"])
@csrf.exempt
def stripe_webhook():
    """Stripe Webhook（CSRF除外）"""
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
            if order and order.status == "pending":
                order.status = "paid"
                order.stripe_payment_id = session_obj.get("payment_intent")
                order.generate_download_token()
                db.session.commit()

    return jsonify({"received": True})

# ==========
# 運営管理画面
# ==========

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """運営管理者ログイン"""
    client_ip = request.remote_addr
    lock_key = f"admin:{client_ip}"
    
    # 不審なIPアドレスチェック
    if is_suspicious_ip(client_ip):
        flash("アクセスが制限されています", "danger")
        return render_template("admin_login.html")
    
    if request.method == "POST":
        password = request.form.get("password", "")
        
        # アカウントロックチェック
        if is_account_locked(lock_key):
            # セキュリティ：ロック時間を明示しない
            flash("認証に失敗しました。しばらく時間をおいて再度お試しください", "danger")
            return redirect(url_for("admin_login"))
        
        setting = AppSetting.query.get(1)
        admin_pw = setting.admin_password if setting else "admin123"

        if password == admin_pw:
            # ログイン成功：試行回数リセット
            reset_login_attempts(lock_key)
            session["admin_logged_in"] = True
            session.permanent = True
            flash("管理者としてログインしました", "success")
            return redirect(url_for("admin_dashboard"))
        else:
            # ログイン失敗：試行回数を記録
            record_failed_login(lock_key)
            # セキュリティ：エラー内容を詳しく表示しない
            flash("認証に失敗しました", "danger")

    return render_template("admin_login.html")

@app.route("/admin/logout")
def admin_logout():
    """運営管理者ログアウト"""
    session.pop("admin_logged_in", None)
    flash("ログアウトしました", "info")
    return redirect(url_for("home"))

@app.route("/admin")
@admin_required
def admin_dashboard():
    """運営ダッシュボード"""
    # 全体統計
    total_photographers = Photographer.query.count()
    active_photographers = Photographer.query.filter_by(status="active").count()
    total_events = Event.query.count()
    published_events = Event.query.filter_by(status="published").count()

    # 売上統計
    all_orders = Order.query.filter_by(status="paid").all()
    total_gmv = sum(o.total_amount for o in all_orders)
    total_platform_fee = sum(o.platform_fee for o in all_orders)

    # 今月の統計
    today = date.today()
    month_start = datetime(today.year, today.month, 1)
    monthly_orders = [o for o in all_orders if o.created_at >= month_start]
    monthly_gmv = sum(o.total_amount for o in monthly_orders)
    monthly_platform_fee = sum(o.platform_fee for o in monthly_orders)

    # 日別GMV（過去30日）
    daily_gmv = {}
    for order in all_orders:
        d = order.created_at.date()
        if d not in daily_gmv:
            daily_gmv[d] = 0
        daily_gmv[d] += order.total_amount

    sorted_days = sorted(daily_gmv.keys(), reverse=True)[:30]
    chart_labels = [d.strftime("%m/%d") for d in reversed(sorted_days)]
    chart_values = [daily_gmv.get(d, 0) for d in reversed(sorted_days)]

    # 最近の注文
    recent_orders = Order.query.filter_by(status="paid").order_by(
        Order.created_at.desc()
    ).limit(10).all()

    return render_template(
        "admin_dashboard.html",
        total_photographers=total_photographers,
        active_photographers=active_photographers,
        total_events=total_events,
        published_events=published_events,
        total_gmv=total_gmv,
        total_platform_fee=total_platform_fee,
        monthly_gmv=monthly_gmv,
        monthly_platform_fee=monthly_platform_fee,
        chart_labels=chart_labels,
        chart_values=chart_values,
        recent_orders=recent_orders,
    )

@app.route("/admin/photographers")
@admin_required
def admin_photographers():
    """カメラマン一覧"""
    photographers = Photographer.query.order_by(Photographer.created_at.desc()).all()
    return render_template("admin_photographers.html", photographers=photographers)

@app.route("/admin/photographers/<int:photographer_id>/toggle", methods=["POST"])
@admin_required
def admin_photographer_toggle(photographer_id: int):
    """カメラマンのステータス切り替え"""
    photographer = Photographer.query.get_or_404(photographer_id)
    photographer.status = "suspended" if photographer.status == "active" else "active"
    db.session.commit()
    flash(f"カメラマンのステータスを変更しました", "success")
    return redirect(url_for("admin_photographers"))

@app.route("/admin/sales")
@admin_required
def admin_sales():
    """全体売上管理"""
    orders = Order.query.filter_by(status="paid").order_by(Order.created_at.desc()).all()
    total_gmv = sum(o.total_amount for o in orders)
    total_platform_fee = sum(o.platform_fee for o in orders)

    return render_template(
        "admin_sales.html",
        orders=orders,
        total_gmv=total_gmv,
        total_platform_fee=total_platform_fee,
    )

@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    """運営設定"""
    setting = AppSetting.query.get(1)
    if not setting:
        setting = AppSetting(id=1, admin_password="admin123", site_name="LifeShot")
        db.session.add(setting)
        db.session.commit()

    if request.method == "POST":
        site_name = request.form.get("site_name", "").strip()
        new_password = request.form.get("admin_password", "").strip()

        if site_name:
            setting.site_name = site_name
        if new_password:
            setting.admin_password = new_password
            flash("管理者パスワードを変更しました", "success")
        else:
            flash("設定を更新しました", "success")

        db.session.commit()
        return redirect(url_for("admin_settings"))

    return render_template("admin_settings.html", setting=setting)

# ==========
# 初期化
# ==========

def init_db():
    """データベース初期化"""
    with app.app_context():
        db.create_all()

        # 設定レコード
        if not AppSetting.query.get(1):
            setting = AppSetting(id=1, admin_password="admin123", site_name="NAGORI")
            db.session.add(setting)
            db.session.commit()

# モジュール読み込み時にDB初期化
init_db()

if __name__ == "__main__":
    init_db()
    try:
        webbrowser.open("http://127.0.0.1:5000/")
    except Exception:
        pass
    app.run(debug=True, port=5000)
