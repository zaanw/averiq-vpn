#!/usr/bin/env python3
"""Averiq VPN WireGuard delivery API for Telegram Mini Apps.

Verifies Telegram WebApp initData, provisions one persistent WireGuard peer per
Telegram user, and sends the .conf file through the Telegram Bot API. Never logs
initData, bot tokens, or client private keys.
"""
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import sqlite3
import subprocess
import threading
import time
import base64
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

HOST = "127.0.0.1"
PORT = int(os.environ.get("API_PORT", "8765"))
BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()
WG_INTERFACE = os.environ.get("WG_INTERFACE", "wg0")
WG_ENDPOINT = os.environ.get("WG_ENDPOINT", "79.137.184.71").strip()
WG_PORT = int(os.environ.get("WG_PORT", "51820"))
YOOKASSA_SHOP_ID = os.environ.get("YOOKASSA_SHOP_ID", "").strip()
YOOKASSA_SECRET_KEY = os.environ.get("YOOKASSA_SECRET_KEY", "").strip()
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/")
MINI_APP_URL = os.environ.get("MINI_APP_URL", "").strip().rstrip("/")
SUBSCRIPTION_DAYS = 30
SUBSCRIPTION_PRICE = "499.00"
WG_CONFIG = Path(os.environ.get("WG_CONFIG", "/etc/wireguard/wg0.conf"))
DB_PATH = Path(os.environ.get("DB_PATH", "/var/lib/averiq-api/clients.sqlite3"))
MAX_INIT_AGE = int(os.environ.get("MAX_INIT_AGE", "86400"))
ALLOWED_ORIGINS = {item.strip().rstrip("/") for item in os.environ.get("ALLOWED_ORIGINS", "").split(",") if item.strip()}
ALLOWED_TELEGRAM_IDS_RAW = os.environ.get("ALLOWED_TELEGRAM_IDS", "").strip()
ALLOWED_TELEGRAM_IDS = None if ALLOWED_TELEGRAM_IDS_RAW == "*" else {
    int(item.strip()) for item in ALLOWED_TELEGRAM_IDS_RAW.split(",") if item.strip().isdigit()
}
LOCK = threading.RLock()
RECENT_REQUESTS = {}
RATE_LIMIT_SECONDS = 8


class ApiError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def checked_command(args, input_text=None):
    try:
        return subprocess.run(
            args, input=input_text, text=True, capture_output=True,
            check=True, timeout=15
        ).stdout.strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        raise ApiError("Не удалось выполнить операцию WireGuard на сервере.", 503) from None


def validate_init_data(raw):
    if not raw or len(raw) > 16000:
        raise ApiError("Открой Mini App из Telegram и попробуй снова.", 401)
    pairs = parse_qsl(raw, keep_blank_values=True, strict_parsing=True)
    fields = {}
    for key, value in pairs:
        if key in fields:
            raise ApiError("Данные Telegram некорректны. Перезапусти Mini App.", 401)
        fields[key] = value

    received_hash = fields.pop("hash", "")
    if not received_hash or not BOT_TOKEN:
        raise ApiError("Не удалось проверить Telegram. Попробуй открыть Mini App заново.", 401)

    check_string = "\n".join(f"{key}={value}" for key, value in sorted(fields.items()))
    secret_key = hmac.new(b"WebAppData", BOT_TOKEN.encode("utf-8"), hashlib.sha256).digest()
    calculated_hash = hmac.new(secret_key, check_string.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(calculated_hash, received_hash):
        raise ApiError("Проверка Telegram не пройдена. Открой Mini App через бота.", 401)

    try:
        auth_date = int(fields["auth_date"])
        user = json.loads(fields["user"])
        user_id = int(user["id"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise ApiError("В данных Telegram не найден пользователь.", 401) from None

    now = int(time.time())
    if auth_date > now + 60 or now - auth_date > MAX_INIT_AGE:
        raise ApiError("Данные входа устарели. Закрой и заново открой Mini App.", 401)
    if user_id <= 0:
        raise ApiError("Не удалось определить пользователя Telegram.", 401)
    return user_id, user


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(DB_PATH.parent, 0o700)
    old_umask = os.umask(0o077)
    try:
        with sqlite3.connect(DB_PATH) as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS clients (
                    telegram_user_id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL DEFAULT '',
                    private_key TEXT NOT NULL,
                    public_key TEXT NOT NULL UNIQUE,
                    client_ip TEXT NOT NULL UNIQUE,
                    created_at INTEGER NOT NULL
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS orders (
                    order_id TEXT PRIMARY KEY,
                    telegram_user_id INTEGER NOT NULL,
                    payment_id TEXT UNIQUE,
                    amount TEXT NOT NULL,
                    client_app TEXT NOT NULL DEFAULT 'karing',
                    status TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    paid_at INTEGER
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS subscriptions (
                    telegram_user_id INTEGER PRIMARY KEY,
                    expires_at INTEGER NOT NULL,
                    token_hash TEXT NOT NULL UNIQUE,
                    link_token TEXT NOT NULL,
                    client_app TEXT NOT NULL DEFAULT 'karing',
                    updated_at INTEGER NOT NULL
                )
            """)
            columns = {row[1] for row in db.execute("PRAGMA table_info(subscriptions)").fetchall()}
            if "link_token" not in columns:
                db.execute("ALTER TABLE subscriptions ADD COLUMN link_token TEXT NOT NULL DEFAULT ''")
            if "client_app" not in columns:
                db.execute("ALTER TABLE subscriptions ADD COLUMN client_app TEXT NOT NULL DEFAULT 'karing'")
            order_columns = {row[1] for row in db.execute("PRAGMA table_info(orders)").fetchall()}
            if "client_app" not in order_columns:
                db.execute("ALTER TABLE orders ADD COLUMN client_app TEXT NOT NULL DEFAULT 'karing'")
    finally:
        os.umask(old_umask)
    os.chmod(DB_PATH, 0o600)


def existing_live_ips():
    text = checked_command(["wg", "show", WG_INTERFACE, "allowed-ips"])
    used = set()
    for line in text.splitlines():
        columns = line.split()
        for value in columns[1:]:
            try:
                used.add(str(ipaddress.ip_interface(value).ip))
            except ValueError:
                continue
    return used


def choose_client_ip(db):
    used_db = {row[0] for row in db.execute("SELECT client_ip FROM clients").fetchall()}
    used_live = existing_live_ips()
    candidates = list(range(10, 255))
    secrets.SystemRandom().shuffle(candidates)
    for last_octet in candidates:
        candidate = f"10.66.66.{last_octet}"
        if candidate not in used_db and candidate not in used_live:
            return candidate
    raise ApiError("Свободные IP-адреса закончились. Обратись к администратору.", 503)


def replace_config(contents):
    temp = WG_CONFIG.with_name(WG_CONFIG.name + ".averiq-tmp")
    try:
        temp.write_text(contents.rstrip() + "\n", encoding="utf-8")
        os.chmod(temp, 0o600)
        os.replace(temp, WG_CONFIG)
        os.chmod(WG_CONFIG, 0o600)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def append_peer_to_config(public_key, client_ip, user_id):
    original = WG_CONFIG.read_text(encoding="utf-8")
    if public_key in original:
        return original, False
    block = (
        "\n\n# Averiq Telegram user " + str(user_id) + "\n"
        "[Peer]\n"
        "PublicKey = " + public_key + "\n"
        "AllowedIPs = " + client_ip + "/32\n"
    )
    replace_config(original.rstrip() + block)
    return original, True


def add_or_restore_live_peer(public_key, client_ip):
    live_peers = set(checked_command(["wg", "show", WG_INTERFACE, "peers"]).split())
    if public_key not in live_peers:
        checked_command(["wg", "set", WG_INTERFACE, "peer", public_key,
                         "allowed-ips", client_ip + "/32"])


def create_or_get_client(user_id, username):
    with LOCK:
        # Read the server public key before changing any client state.
        server_public = checked_command(["wg", "show", WG_INTERFACE, "public-key"])
        db = sqlite3.connect(DB_PATH, timeout=15)
        original_config = None
        config_changed = False
        live_peer_added = False
        public_key = None
        is_new_client = False
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT private_key, public_key, client_ip FROM clients WHERE telegram_user_id = ?",
                (user_id,)
            ).fetchone()

            if row:
                private_key, public_key, client_ip = row
                config_text = WG_CONFIG.read_text(encoding="utf-8")
                if public_key not in config_text:
                    original_config, config_changed = append_peer_to_config(public_key, client_ip, user_id)
                live_peers = set(checked_command(["wg", "show", WG_INTERFACE, "peers"]).split())
                if public_key not in live_peers:
                    checked_command(["wg", "set", WG_INTERFACE, "peer", public_key,
                                     "allowed-ips", client_ip + "/32"])
                    live_peer_added = True
            else:
                is_new_client = True
                private_key = checked_command(["wg", "genkey"])
                public_key = checked_command(["wg", "pubkey"], input_text=private_key + "\n")
                client_ip = choose_client_ip(db)
                checked_command(["wg", "set", WG_INTERFACE, "peer", public_key,
                                 "allowed-ips", client_ip + "/32"])
                live_peer_added = True
                original_config, config_changed = append_peer_to_config(public_key, client_ip, user_id)
                db.execute(
                    "INSERT INTO clients (telegram_user_id, username, private_key, public_key, client_ip, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (user_id, str(username or "")[:128], private_key, public_key, client_ip, int(time.time()))
                )

            db.commit()
        except Exception:
            db.rollback()
            if live_peer_added and public_key:
                try:
                    checked_command(["wg", "set", WG_INTERFACE, "peer", public_key, "remove"])
                except ApiError:
                    pass
            if config_changed and original_config is not None:
                replace_config(original_config)
            raise
        finally:
            db.close()

        return (
            "[Interface]\n"
            f"PrivateKey = {private_key}\n"
            f"Address = {client_ip}/32\n"
            "DNS = 1.1.1.1, 1.0.0.1\n\n"
            "[Peer]\n"
            f"PublicKey = {server_public}\n"
            f"Endpoint = {WG_ENDPOINT}:{WG_PORT}\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\n"
            "PersistentKeepalive = 25\n"
        )

def send_config_to_telegram(user_id, config_text):
    boundary = "----Averiq" + secrets.token_hex(16)
    chunks = [
        (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="chat_id"\r\n\r\n'
            f"{user_id}\r\n"
        ).encode("utf-8"),
        (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="caption"\r\n\r\n'
            "Твой персональный Averiq VPN. На iPhone открой файл и импортируй WireGuard-конфигурацию в Karing.\r\n"
        ).encode("utf-8"),
        (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="document"; filename="Averiq-Karing.conf"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode("utf-8"),
        config_text.encode("utf-8"),
        f"\r\n--{boundary}--\r\n".encode("utf-8"),
    ]
    request = Request(
        f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument",
        data=b"".join(chunks),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=25) as response:
            result = json.loads(response.read(1024 * 1024).decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError):
        raise ApiError("Конфиг создан, но Telegram не смог доставить файл. Открой чат бота и попробуй ещё раз.", 502) from None
    if not result.get("ok"):
        raise ApiError("Конфиг создан, но бот не смог отправить файл. Нажми Start в чате бота и повтори попытку.", 502)



def yookassa_request(method, path, body=None, idempotence_key=None):
    if not YOOKASSA_SHOP_ID or not YOOKASSA_SECRET_KEY:
        raise ApiError("Оплата пока не настроена администратором.", 503)
    raw = (YOOKASSA_SHOP_ID + ":" + YOOKASSA_SECRET_KEY).encode("utf-8")
    auth = "Basic " + base64.b64encode(raw).decode("ascii")
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Authorization": auth, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if idempotence_key:
        headers["Idempotence-Key"] = idempotence_key
    request = Request("https://api.yookassa.ru/v3" + path, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=20) as response:
            return json.loads(response.read(1024 * 1024).decode("utf-8"))
    except HTTPError as exc:
        try:
            detail = json.loads(exc.read(4096).decode("utf-8"))
        except Exception:
            detail = {}
        raise ApiError("Платёжный сервис отклонил запрос: " + str(detail.get("description", "ошибка API")), 502) from None
    except (URLError, TimeoutError, OSError, json.JSONDecodeError):
        raise ApiError("Не удалось связаться с платёжным сервисом. Попробуй ещё раз.", 502) from None


def create_payment(user_id, client_app):
    if client_app not in {"karing", "wireguard"}:
        raise ApiError("Выбери Karing или WireGuard.", 400)
    if not PUBLIC_BASE_URL.startswith("https://") or not MINI_APP_URL.startswith("https://"):
        raise ApiError("Оплата ещё не настроена: нужны публичные HTTPS-адреса API и Mini App.", 503)
    order_id = str(uuid.uuid4())
    payment = yookassa_request("POST", "/payments", {
        "amount": {"value": SUBSCRIPTION_PRICE, "currency": "RUB"},
        "payment_method_data": {"type": "sbp"},
        "confirmation": {"type": "redirect", "return_url": MINI_APP_URL + "/?payment=return"},
        "capture": True,
        "description": "Averiq VPN — подписка на 30 дней",
        "metadata": {"order_id": order_id, "telegram_user_id": str(user_id), "client_app": client_app}
    }, idempotence_key=order_id)
    confirmation_url = (payment.get("confirmation") or {}).get("confirmation_url")
    payment_id = payment.get("id")
    if not confirmation_url or not payment_id:
        raise ApiError("Платёжный сервис не вернул ссылку оплаты.", 502)
    with sqlite3.connect(DB_PATH, timeout=15) as db:
        db.execute(
            "INSERT INTO orders (order_id, telegram_user_id, payment_id, amount, client_app, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (order_id, user_id, payment_id, SUBSCRIPTION_PRICE, client_app, payment.get("status", "pending"), int(time.time()))
        )
    return {"ok": True, "order_id": order_id, "payment_url": confirmation_url}


def send_telegram_message(user_id, message):
    if not BOT_TOKEN:
        return
    body = json.dumps({"chat_id": user_id, "text": message, "disable_web_page_preview": True}).encode("utf-8")
    request = Request("https://api.telegram.org/bot" + BOT_TOKEN + "/sendMessage", data=body,
                      headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(request, timeout=15) as response:
            result = json.loads(response.read(1024 * 1024).decode("utf-8"))
        if not result.get("ok"):
            raise ApiError("Telegram не доставил ссылку. Открой чат бота и нажми Start.", 502)
    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError):
        raise ApiError("Оплата подтверждена, но Telegram не смог доставить ссылку. Обратись в поддержку.", 502) from None


def activate_subscription(order_id, payment):
    amount = payment.get("amount") or {}
    if payment.get("status") != "succeeded" or payment.get("paid") is not True:
        return False
    if amount.get("currency") != "RUB" or amount.get("value") != SUBSCRIPTION_PRICE:
        raise ApiError("Сумма или валюта платежа не совпадает с заказом.", 400)
    if (payment.get("payment_method") or {}).get("type") != "sbp":
        raise ApiError("Этот заказ должен быть оплачен через СБП.", 400)
    metadata = payment.get("metadata") or {}
    if metadata.get("order_id") != order_id:
        raise ApiError("Платёж не совпадает с заказом.", 400)
    now = int(time.time())
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    with sqlite3.connect(DB_PATH, timeout=15) as db:
        db.row_factory = sqlite3.Row
        row = db.execute("SELECT telegram_user_id, payment_id, status, amount, client_app FROM orders WHERE order_id = ?", (order_id,)).fetchone()
        if not row or row["payment_id"] != payment.get("id") or row["amount"] != SUBSCRIPTION_PRICE:
            raise ApiError("Заказ не найден или не совпадает с платежом.", 400)
        if row["status"] == "paid":
            existing = db.execute("SELECT link_token, client_app FROM subscriptions WHERE telegram_user_id = ?", (int(row["telegram_user_id"]),)).fetchone()
            if not existing:
                raise ApiError("Подписка оплачена, но ссылка не найдена. Обратись в поддержку.", 500)
            existing_link = PUBLIC_BASE_URL + "/s/" + str(existing["link_token"])
            app_name = "Karing" if existing["client_app"] == "karing" else "WireGuard"
            send_telegram_message(int(row["telegram_user_id"]), "Оплата Averiq VPN уже подтверждена. Открой персональную ссылку и импортируй конфигурацию в " + app_name + ":\n" + existing_link + "\n\nНе пересылай её другим людям.")
            return True
        user_id = int(row["telegram_user_id"])
        if str(metadata.get("telegram_user_id", "")) != str(user_id):
            raise ApiError("Платёж не совпадает с пользователем заказа.", 400)
        current = db.execute("SELECT expires_at FROM subscriptions WHERE telegram_user_id = ?", (user_id,)).fetchone()
        base = max(now, int(current["expires_at"])) if current else now
        expires_at = base + SUBSCRIPTION_DAYS * 86400
        db.execute("UPDATE orders SET status = 'paid', paid_at = ? WHERE order_id = ?", (now, order_id))
        db.execute(
            "INSERT INTO subscriptions (telegram_user_id, expires_at, token_hash, link_token, client_app, updated_at) VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(telegram_user_id) DO UPDATE SET expires_at=excluded.expires_at, token_hash=excluded.token_hash, link_token=excluded.link_token, client_app=excluded.client_app, updated_at=excluded.updated_at",
            (user_id, expires_at, token_hash, raw_token, row["client_app"], now)
        )
    link = PUBLIC_BASE_URL + "/s/" + raw_token
    app_name = "Karing" if row["client_app"] == "karing" else "WireGuard"
    send_telegram_message(user_id, "Оплата Averiq VPN подтверждена! Подписка активна 30 дней.\n\nОткрой персональную ссылку и импортируй конфигурацию в " + app_name + ":\n" + link + "\n\nНе пересылай эту ссылку другим людям.")
    return True


def process_yookassa_notification(payload):
    if payload.get("event") != "payment.succeeded":
        return
    obj = payload.get("object") or {}
    payment_id = str(obj.get("id", ""))
    if not payment_id:
        raise ApiError("В уведомлении отсутствует ID платежа.", 400)
    payment = yookassa_request("GET", "/payments/" + payment_id)
    metadata = payment.get("metadata") or {}
    order_id = str(metadata.get("order_id", ""))
    if not order_id:
        raise ApiError("В платеже отсутствует ID заказа.", 400)
    activate_subscription(order_id, payment)


def get_active_subscription_by_token(token):
    if not token or len(token) > 256:
        return None
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with sqlite3.connect(DB_PATH, timeout=15) as db:
        db.row_factory = sqlite3.Row
        row = db.execute("SELECT telegram_user_id, expires_at, client_app FROM subscriptions WHERE token_hash = ?", (token_hash,)).fetchone()
    if not row or int(row["expires_at"]) <= int(time.time()):
        return None
    return int(row["telegram_user_id"]), str(row["client_app"])


def has_active_subscription(user_id):
    with sqlite3.connect(DB_PATH, timeout=15) as db:
        row = db.execute("SELECT expires_at FROM subscriptions WHERE telegram_user_id = ?", (user_id,)).fetchone()
    return bool(row and int(row[0]) > int(time.time()))


def expire_subscriptions_loop():
    while True:
        try:
            now = int(time.time())
            with sqlite3.connect(DB_PATH, timeout=15) as db:
                rows = db.execute(
                    "SELECT c.telegram_user_id, c.public_key, c.client_ip FROM clients c "
                    "JOIN subscriptions s ON s.telegram_user_id = c.telegram_user_id "
                    "WHERE s.expires_at <= ?",
                    (now,)
                ).fetchall()
            for user_id, public_key, client_ip in rows:
                try:
                    checked_command(["wg", "set", WG_INTERFACE, "peer", public_key, "remove"])
                except ApiError:
                    pass
                try:
                    original = WG_CONFIG.read_text(encoding="utf-8")
                    block = ("\n\n# Averiq Telegram user " + str(user_id) + "\n"
                             "[Peer]\nPublicKey = " + public_key + "\nAllowedIPs = " + client_ip + "/32\n")
                    if block in original:
                        replace_config(original.replace(block, ""))
                except (OSError, ApiError):
                    pass
        except Exception:
            pass
        time.sleep(60)


class Handler(BaseHTTPRequestHandler):
    server_version = "AveriqAPI/1.0"

    def log_message(self, format_string, *args):
        # Standard access logs include path/status only. Request bodies are never logged.
        super().log_message(format_string, *args)

    def write_json(self, status, data, origin=None):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Vary", "Origin")
        if origin and origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        origin = self.headers.get("Origin", "").rstrip("/")
        if origin not in ALLOWED_ORIGINS:
            self.write_json(403, {"error": "Origin is not allowed."})
            return
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Vary", "Origin")
        self.end_headers()

    def do_GET(self):
        if self.path == "/health":
            self.write_json(200, {"ok": True}, self.headers.get("Origin", "").rstrip("/"))
            return
        if self.path.startswith("/s/"):
            token = self.path[3:].split("?", 1)[0]
            subscription = get_active_subscription_by_token(token)
            if subscription is None:
                self.send_error(410, "Ссылка недействительна или подписка закончилась.")
                return
            user_id, client_app = subscription
            try:
                config = create_or_get_client(user_id, "")
                body = config.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", 'attachment; filename="Averiq-Karing.conf"' if client_app == "karing" else 'attachment; filename="Averiq-WireGuard.conf"')
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)
            except ApiError as exc:
                self.send_error(exc.status, str(exc))
            return
        self.write_json(404, {"error": "Not found."})

    def do_POST(self):
        if self.path == "/api/webhooks/yookassa":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 65536:
                    raise ApiError("Некорректный размер уведомления.", 400)
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                process_yookassa_notification(payload)
                self.write_json(200, {"ok": True})
            except ApiError as exc:
                self.write_json(exc.status, {"error": str(exc)})
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
                self.write_json(400, {"error": "Некорректное уведомление."})
            except Exception:
                self.write_json(500, {"error": "Внутренняя ошибка обработки платежа."})
            return
        origin = self.headers.get("Origin", "").rstrip("/")
        if origin not in ALLOWED_ORIGINS:
            self.write_json(403, {"error": "Источник запроса не разрешён."})
            return
        if self.path not in {"/api/wireguard/iphone", "/api/payments/create"}:
            self.write_json(404, {"error": "Not found."}, origin)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 32768:
                raise ApiError("Некорректный размер запроса.", 400)
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            user_id, user = validate_init_data(str(payload.get("initData", "")))
            if self.path == "/api/payments/create":
                client_app = str(payload.get("clientApp", "karing")).strip().lower()
                result = create_payment(user_id, client_app)
                self.write_json(200, result, origin)
                return
            if ALLOWED_TELEGRAM_IDS is not None and user_id not in ALLOWED_TELEGRAM_IDS:
                raise ApiError(
                    f"Доступ пока не активирован. Твой Telegram ID: {user_id}. Передай его администратору.",
                    403
                )
            if not has_active_subscription(user_id):
                raise ApiError("Сначала оформи подписку на 30 дней за 499 ₽.", 402)
            now = time.time()
            with LOCK:
                previous = RECENT_REQUESTS.get(user_id, 0)
                if now - previous < RATE_LIMIT_SECONDS:
                    raise ApiError("Подожди несколько секунд и попробуй ещё раз.", 429)
                RECENT_REQUESTS[user_id] = now

            config = create_or_get_client(user_id, user.get("username", ""))
            send_config_to_telegram(user_id, config)
            self.write_json(200, {
                "ok": True,
                "message": "Готово! Персональный файл Averiq-Karing.conf отправлен в чат этого бота. Открой файл на iPhone и выбери WireGuard."
            }, origin)
        except ApiError as exc:
            self.write_json(exc.status, {"error": str(exc)}, origin)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            self.write_json(400, {"error": "Не удалось прочитать запрос. Перезапусти Mini App."}, origin)
        except Exception:
            self.write_json(500, {"error": "Внутренняя ошибка сервера. Попробуй позже."}, origin)

    def do_HEAD(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()


def main():
    if not BOT_TOKEN:
        raise SystemExit("BOT_TOKEN is missing from the environment.")
    if not ALLOWED_ORIGINS or "*" in ALLOWED_ORIGINS:
        raise SystemExit("Set ALLOWED_ORIGINS to one or more exact HTTPS origins.")
    if not WG_ENDPOINT or any(ch.isspace() for ch in WG_ENDPOINT):
        raise SystemExit("WG_ENDPOINT must be a hostname or IP address.")
    if not WG_CONFIG.is_file():
        raise SystemExit(f"WireGuard config not found: {WG_CONFIG}")
    if YOOKASSA_SHOP_ID and not YOOKASSA_SECRET_KEY:
        raise SystemExit("YOOKASSA_SECRET_KEY is missing.")
    if YOOKASSA_SECRET_KEY and not YOOKASSA_SHOP_ID:
        raise SystemExit("YOOKASSA_SHOP_ID is missing.")
    init_db()
    threading.Thread(target=expire_subscriptions_loop, daemon=True).start()
    print(f"Averiq API listening on {HOST}:{PORT}; interface={WG_INTERFACE}", flush=True)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
