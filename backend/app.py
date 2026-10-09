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
        db = sqlite3.connect(DB_PATH, timeout=15)
        original = None
        added_to_config = False
        public_key = None
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT private_key, public_key, client_ip FROM clients WHERE telegram_user_id = ?",
                (user_id,)
            ).fetchone()

            if row:
                private_key, public_key, client_ip = row
                if public_key not in WG_CONFIG.read_text(encoding="utf-8"):
                    original, added_to_config = append_peer_to_config(public_key, client_ip, user_id)
                add_or_restore_live_peer(public_key, client_ip)
                db.commit()
            else:
                private_key = checked_command(["wg", "genkey"])
                public_key = checked_command(["wg", "pubkey"], input_text=private_key + "\n")
                client_ip = choose_client_ip(db)
                checked_command(["wg", "set", WG_INTERFACE, "peer", public_key,
                                 "allowed-ips", client_ip + "/32"])
                original, added_to_config = append_peer_to_config(public_key, client_ip, user_id)
                db.execute(
                    "INSERT INTO clients (telegram_user_id, username, private_key, public_key, client_ip, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (user_id, str(username or "")[:128], private_key, public_key, client_ip, int(time.time()))
                )
                db.commit()

            server_public = checked_command(["wg", "show", WG_INTERFACE, "public-key"])
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
        except Exception:
            db.rollback()
            if public_key:
                try:
                    checked_command(["wg", "set", WG_INTERFACE, "peer", public_key, "remove"])
                except ApiError:
                    pass
            if added_to_config and original is not None:
                replace_config(original)
            raise
        finally:
            db.close()


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
            "Твой персональный Averiq VPN для WireGuard. На iPhone открой файл и импортируй его в WireGuard.\r\n"
        ).encode("utf-8"),
        (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="document"; filename="Averiq-iPhone.conf"\r\n'
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
        else:
            self.write_json(404, {"error": "Not found."})

    def do_POST(self):
        origin = self.headers.get("Origin", "").rstrip("/")
        if origin not in ALLOWED_ORIGINS:
            self.write_json(403, {"error": "Источник запроса не разрешён."})
            return
        if self.path != "/api/wireguard/iphone":
            self.write_json(404, {"error": "Not found."}, origin)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 32768:
                raise ApiError("Некорректный размер запроса.", 400)
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            user_id, user = validate_init_data(str(payload.get("initData", "")))
            if ALLOWED_TELEGRAM_IDS is not None and user_id not in ALLOWED_TELEGRAM_IDS:
                raise ApiError(
                    f"Доступ пока не активирован. Твой Telegram ID: {user_id}. Передай его администратору.",
                    403
                )
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
                "message": "Готово! Персональный файл Averiq-iPhone.conf отправлен в чат этого бота. Открой файл на iPhone и выбери WireGuard."
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
    init_db()
    print(f"Averiq API listening on {HOST}:{PORT}; interface={WG_INTERFACE}", flush=True)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
