#!/usr/bin/env python3
"""Averiq subscription admin CLI. Run only on the VPN server as root."""
import argparse
import hashlib
import os
import secrets
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

WG_INTERFACE = os.environ.get("WG_INTERFACE", "wg0")
WG_CONFIG = Path(os.environ.get("WG_CONFIG", "/etc/wireguard/wg0.conf"))
DB_PATH = Path(os.environ.get("DB_PATH", "/var/lib/averiq-api/clients.sqlite3"))
DEFAULT_DAYS = 30


def run(args, check=True):
    result = subprocess.run(args, text=True, capture_output=True, timeout=15)
    if check and result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "command failed"
        raise RuntimeError(detail)
    return result.stdout.strip()


def connect():
    if not DB_PATH.exists():
        raise RuntimeError(f"Database not found: {DB_PATH}")
    db = sqlite3.connect(DB_PATH, timeout=15)
    db.row_factory = sqlite3.Row
    return db


def schema_check(db):
    tables = {r["name"] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "clients" not in tables or "subscriptions" not in tables:
        raise RuntimeError(
            "This database has no subscription table. Deploy the Averiq subscription branch first."
        )


def peers_live():
    return set(run(["wg", "show", WG_INTERFACE, "peers"]).split())


def set_peer(public_key, client_ip):
    run(["wg", "set", WG_INTERFACE, "peer", public_key, "allowed-ips", client_ip + "/32"])


def remove_peer(public_key):
    run(["wg", "set", WG_INTERFACE, "peer", public_key, "remove"], check=False)


def edit_server_config(user_id, public_key, client_ip, remove=False):
    if not WG_CONFIG.exists():
        raise RuntimeError(f"WireGuard config not found: {WG_CONFIG}")
    text = WG_CONFIG.read_text(encoding="utf-8")
    lines = text.splitlines()
    output = []
    i = 0
    removed = False
    while i < len(lines):
        if lines[i].strip() == "[Peer]":
            start = i
            # Include an immediately preceding comment with this peer block.
            if output and output[-1].lstrip().startswith("# Averiq Telegram user "):
                output.pop()
                start = i - 1
            j = i + 1
            while j < len(lines) and lines[j].strip() != "[Peer]":
                j += 1
            block = lines[i:j]
            block_text = "\n".join(block)
            if f"PublicKey = {public_key}" in block_text:
                if remove:
                    removed = True
                    i = j
                    while i < len(lines) and not lines[i].strip():
                        i += 1
                    continue
                output.extend(block)
                i = j
                continue
            # Put back the comment if it belonged to a different peer.
            if start < i:
                output.append("# Averiq Telegram user " + str(user_id))
            output.extend(block)
            i = j
            continue
        output.append(lines[i])
        i += 1

    if not remove and public_key not in text:
        if output and output[-1].strip():
            output.append("")
        output.extend([
            "# Averiq Telegram user " + str(user_id),
            "[Peer]",
            "PublicKey = " + public_key,
            "AllowedIPs = " + client_ip + "/32",
        ])
    if remove and not removed:
        return
    new_text = "\n".join(output).rstrip() + "\n"
    temp = WG_CONFIG.with_name(WG_CONFIG.name + ".averiq-admin-tmp")
    temp.write_text(new_text, encoding="utf-8")
    os.chmod(temp, 0o600)
    os.replace(temp, WG_CONFIG)
    os.chmod(WG_CONFIG, 0o600)


def find_client(db, user_id):
    row = db.execute(
        "SELECT telegram_user_id, username, public_key, client_ip FROM clients WHERE telegram_user_id=?",
        (user_id,),
    ).fetchone()
    if not row:
        raise RuntimeError(f"No client for Telegram ID {user_id}.")
    return row


def list_clients():
    with connect() as db:
        schema_check(db)
        rows = db.execute("""
            SELECT c.telegram_user_id, c.username, c.client_ip, c.public_key,
                   s.expires_at, s.client_app
            FROM clients c
            LEFT JOIN subscriptions s ON s.telegram_user_id=c.telegram_user_id
            ORDER BY c.telegram_user_id
        """).fetchall()
        live = peers_live()
    if not rows:
        print("Пока нет созданных клиентов.")
        return
    now = int(time.time())
    print("ID Telegram | Имя | IP | Подписка | Действует до | WireGuard")
    for row in rows:
        expiry = int(row["expires_at"] or 0)
        status = "ОПЛАЧЕНО" if expiry > now else "НЕ ОПЛАЧЕНО/ИСТЕКЛА"
        date = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(expiry)) if expiry else "—"
        peer = "включён" if row["public_key"] in live else "отключён"
        print(f'{row["telegram_user_id"]} | {row["username"] or "—"} | {row["client_ip"]} | {status} | {date} | {peer}')


def show_status(user_id):
    with connect() as db:
        schema_check(db)
        client = db.execute(
            "SELECT telegram_user_id, username, client_ip, public_key FROM clients WHERE telegram_user_id=?",
            (user_id,),
        ).fetchone()
        sub = db.execute(
            "SELECT expires_at, client_app FROM subscriptions WHERE telegram_user_id=?",
            (user_id,),
        ).fetchone()
    if not client:
        print(f"Профиль для Telegram ID {user_id} ещё не создан.")
        return
    now = int(time.time())
    expiry = int(sub["expires_at"]) if sub else 0
    print(f'ID: {user_id}')
    print(f'Имя: {client["username"] or "—"}')
    print(f'IP: {client["client_ip"]}')
    print(f'Подписка: {"ОПЛАЧЕНО" if expiry > now else "НЕ ОПЛАЧЕНО/ИСТЕКЛА"}')
    print(f'Действует до: {time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(expiry)) if expiry else "—"}')
    print(f'WireGuard peer: {"включён" if client["public_key"] in peers_live() else "отключён"}')


def mark_paid(user_id, days):
    if days < 1 or days > 366:
        raise RuntimeError("Дни должны быть от 1 до 366.")
    now = int(time.time())
    with connect() as db:
        schema_check(db)
        current = db.execute(
            "SELECT expires_at, client_app FROM subscriptions WHERE telegram_user_id=?",
            (user_id,),
        ).fetchone()
        base = max(now, int(current["expires_at"])) if current else now
        expires = base + days * 86400
        client_app = str(current["client_app"]) if current else "wireguard"
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        db.execute("""
            INSERT INTO subscriptions
              (telegram_user_id, expires_at, token_hash, link_token, client_app, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(telegram_user_id) DO UPDATE SET
              expires_at=excluded.expires_at, token_hash=excluded.token_hash,
              link_token=excluded.link_token, client_app=excluded.client_app,
              updated_at=excluded.updated_at
        """, (user_id, expires, token_hash, token, client_app, now))
        client = db.execute(
            "SELECT public_key, client_ip FROM clients WHERE telegram_user_id=?",
            (user_id,),
        ).fetchone()
    if client:
        edit_server_config(user_id, client["public_key"], client["client_ip"], remove=False)
        set_peer(client["public_key"], client["client_ip"])
    print(f"Оплата подтверждена вручную для ID {user_id}.")
    print(f"Доступ до: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(expires))}")
    if not client:
        print("Профиль WireGuard будет создан при первом запросе конфигурации.")


def mark_unpaid(user_id):
    with connect() as db:
        schema_check(db)
        client = find_client(db, user_id)
        now = int(time.time())
        db.execute(
            "UPDATE subscriptions SET expires_at=?, updated_at=? WHERE telegram_user_id=?",
            (now, now, user_id),
        )
    remove_peer(client["public_key"])
    edit_server_config(user_id, client["public_key"], client["client_ip"], remove=True)
    print(f"ID {user_id} отключён: подписка помечена как неоплаченная.")


def main():
    parser = argparse.ArgumentParser(
        description="Управление доступом Averiq VPN по Telegram ID."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="Показать клиентов и статус оплаты")
    status = sub.add_parser("status", help="Показать одного клиента")
    status.add_argument("id", type=int, help="Telegram ID")
    paid = sub.add_parser("paid", help="Подтвердить оплату и продлить доступ")
    paid.add_argument("id", type=int, help="Telegram ID")
    paid.add_argument("--days", type=int, default=DEFAULT_DAYS, help="Срок доступа, по умолчанию 30 дней")
    unpaid = sub.add_parser("unpaid", help="Отключить клиента и пометить подписку неоплаченной")
    unpaid.add_argument("id", type=int, help="Telegram ID")
    args = parser.parse_args()
    try:
        if args.command == "list":
            list_clients()
        elif args.command == "status":
            show_status(args.id)
        elif args.command == "paid":
            mark_paid(args.id, args.days)
        elif args.command == "unpaid":
            mark_unpaid(args.id)
    except (RuntimeError, sqlite3.Error, OSError, subprocess.SubprocessError) as exc:
        print("Ошибка:", str(exc), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
