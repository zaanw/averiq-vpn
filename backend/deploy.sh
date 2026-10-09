#!/usr/bin/env bash
set -euo pipefail

if [[ "$EUID" -ne 0 ]]; then
  echo "Запусти от root: bash backend/deploy.sh"
  exit 1
fi
if ! command -v wg >/dev/null 2>&1 || ! wg show wg0 >/dev/null 2>&1; then
  echo "WireGuard wg0 должен быть установлен и запущен до установки API."
  exit 1
fi

apt-get update
apt-get install -y python3 ca-certificates
install -d -o root -g root -m 700 /opt/averiq-api /var/lib/averiq-api
install -m 700 backend/app.py /opt/averiq-api/app.py
install -m 644 backend/averiq-api.service /etc/systemd/system/averiq-api.service

echo
echo "Настройка Averiq API. Токен не будет отображён и не попадёт в GitHub."
read -r -s -p "Telegram Bot Token (из BotFather): " BOT_TOKEN
echo
if [[ -z "$BOT_TOKEN" || "$BOT_TOKEN" == *" "* ]]; then
  echo "Токен выглядит некорректно."
  exit 1
fi

read -r -p "HTTPS origin Mini App, например https://zaanw.github.io: " ALLOWED_ORIGINS
if [[ -z "$ALLOWED_ORIGINS" || "$ALLOWED_ORIGINS" == *" "* || "$ALLOWED_ORIGINS" == *"*"* ]]; then
  echo "Укажи точный origin без пути, например https://example.com (без завершающего /)."
  exit 1
fi
read -r -p "Telegram ID для тестового доступа (число или список через запятую): " ALLOWED_TELEGRAM_IDS
if [[ ! "$ALLOWED_TELEGRAM_IDS" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
  echo "Укажи один или несколько числовых Telegram ID через запятую."
  exit 1
fi
read -r -p "Публичный HTTPS URL API (например https://api.example.com): " PUBLIC_BASE_URL
if [[ "$PUBLIC_BASE_URL" != https://* || "$PUBLIC_BASE_URL" == *" "* ]]; then
  echo "Укажи HTTPS URL API без пробелов."
  exit 1
fi
read -r -p "HTTPS URL Mini App (например https://zaanw.github.io/averiq-vpn): " MINI_APP_URL
if [[ "$MINI_APP_URL" != https://* || "$MINI_APP_URL" == *" "* ]]; then
  echo "Укажи HTTPS URL Mini App без пробелов."
  exit 1
fi
read -r -p "ЮKassa Shop ID (оставь пустым, если пока нет): " YOOKASSA_SHOP_ID
read -r -s -p "ЮKassa Secret Key (оставь пустым, если пока нет): " YOOKASSA_SECRET_KEY
echo
if [[ -n "$YOOKASSA_SHOP_ID" && -z "$YOOKASSA_SECRET_KEY" ]] || [[ -z "$YOOKASSA_SHOP_ID" && -n "$YOOKASSA_SECRET_KEY" ]]; then
  echo "Нужно указать и Shop ID, и Secret Key, либо оставить оба поля пустыми."
  exit 1
fi
if [[ "$YOOKASSA_SHOP_ID" == *if [[ -z "$WG_ENDPOINT" ]]; then
  WG_ENDPOINT="79.137.184.71"
fi
if [[ ! "$WG_ENDPOINT" =~ ^[A-Za-z0-9.-]+$ ]]; then
  echo "Укажи только IP-адрес или домен, без https:// и порта."
  exit 1
fi

umask 077
cat > /etc/averiq-api.env <<EOF
BOT_TOKEN=$BOT_TOKEN
ALLOWED_ORIGINS=$ALLOWED_ORIGINS
ALLOWED_TELEGRAM_IDS=$ALLOWED_TELEGRAM_IDS
WG_ENDPOINT=$WG_ENDPOINT
PUBLIC_BASE_URL=$PUBLIC_BASE_URL
MINI_APP_URL=$MINI_APP_URL
YOOKASSA_SHOP_ID=$YOOKASSA_SHOP_ID
YOOKASSA_SECRET_KEY=$YOOKASSA_SECRET_KEY
WG_PORT=51820
WG_INTERFACE=wg0
WG_CONFIG=/etc/wireguard/wg0.conf
DB_PATH=/var/lib/averiq-api/clients.sqlite3
API_PORT=8765
EOF
chmod 600 /etc/averiq-api.env
unset BOT_TOKEN YOOKASSA_SECRET_KEY

systemctl daemon-reload
systemctl enable --now averiq-api
sleep 1
if systemctl is-active --quiet averiq-api; then
  echo
  echo "Averiq API запущен локально на 127.0.0.1:8765."
  echo "Проверка:"
  curl -fsS http://127.0.0.1:8765/health || true
  echo
  echo "Осталось настроить HTTPS reverse proxy для /api/* и задать API URL в index.html."
else
  systemctl --no-pager --full status averiq-api || true
  journalctl -u averiq-api -n 30 --no-pager || true
  exit 1
fi
\n'* || "$YOOKASSA_SECRET_KEY" == *if [[ -z "$WG_ENDPOINT" ]]; then
  WG_ENDPOINT="79.137.184.71"
fi
if [[ ! "$WG_ENDPOINT" =~ ^[A-Za-z0-9.-]+$ ]]; then
  echo "Укажи только IP-адрес или домен, без https:// и порта."
  exit 1
fi

umask 077
cat > /etc/averiq-api.env <<EOF
BOT_TOKEN=$BOT_TOKEN
ALLOWED_ORIGINS=$ALLOWED_ORIGINS
ALLOWED_TELEGRAM_IDS=$ALLOWED_TELEGRAM_IDS
WG_ENDPOINT=$WG_ENDPOINT
WG_PORT=51820
WG_INTERFACE=wg0
WG_CONFIG=/etc/wireguard/wg0.conf
DB_PATH=/var/lib/averiq-api/clients.sqlite3
API_PORT=8765
EOF
chmod 600 /etc/averiq-api.env
unset BOT_TOKEN

systemctl daemon-reload
systemctl enable --now averiq-api
sleep 1
if systemctl is-active --quiet averiq-api; then
  echo
  echo "Averiq API запущен локально на 127.0.0.1:8765."
  echo "Проверка:"
  curl -fsS http://127.0.0.1:8765/health || true
  echo
  echo "Осталось настроить HTTPS reverse proxy для /api/* и задать API URL в index.html."
else
  systemctl --no-pager --full status averiq-api || true
  journalctl -u averiq-api -n 30 --no-pager || true
  exit 1
fi
\n'* || "$YOOKASSA_SECRET_KEY" == *if [[ -z "$WG_ENDPOINT" ]]; then
  WG_ENDPOINT="79.137.184.71"
fi
if [[ ! "$WG_ENDPOINT" =~ ^[A-Za-z0-9.-]+$ ]]; then
  echo "Укажи только IP-адрес или домен, без https:// и порта."
  exit 1
fi

umask 077
cat > /etc/averiq-api.env <<EOF
BOT_TOKEN=$BOT_TOKEN
ALLOWED_ORIGINS=$ALLOWED_ORIGINS
ALLOWED_TELEGRAM_IDS=$ALLOWED_TELEGRAM_IDS
WG_ENDPOINT=$WG_ENDPOINT
WG_PORT=51820
WG_INTERFACE=wg0
WG_CONFIG=/etc/wireguard/wg0.conf
DB_PATH=/var/lib/averiq-api/clients.sqlite3
API_PORT=8765
EOF
chmod 600 /etc/averiq-api.env
unset BOT_TOKEN

systemctl daemon-reload
systemctl enable --now averiq-api
sleep 1
if systemctl is-active --quiet averiq-api; then
  echo
  echo "Averiq API запущен локально на 127.0.0.1:8765."
  echo "Проверка:"
  curl -fsS http://127.0.0.1:8765/health || true
  echo
  echo "Осталось настроить HTTPS reverse proxy для /api/* и задать API URL в index.html."
else
  systemctl --no-pager --full status averiq-api || true
  journalctl -u averiq-api -n 30 --no-pager || true
  exit 1
fi
\r'* ]]; then
  echo "Платёжные параметры содержат недопустимые символы."
  exit 1
fi

read -r -p "Публичный IP/домен WireGuard [79.137.184.71]: " WG_ENDPOINT
if [[ -z "$WG_ENDPOINT" ]]; then
  WG_ENDPOINT="79.137.184.71"
fi
if [[ ! "$WG_ENDPOINT" =~ ^[A-Za-z0-9.-]+$ ]]; then
  echo "Укажи только IP-адрес или домен, без https:// и порта."
  exit 1
fi

umask 077
cat > /etc/averiq-api.env <<EOF
BOT_TOKEN=$BOT_TOKEN
ALLOWED_ORIGINS=$ALLOWED_ORIGINS
ALLOWED_TELEGRAM_IDS=$ALLOWED_TELEGRAM_IDS
WG_ENDPOINT=$WG_ENDPOINT
WG_PORT=51820
WG_INTERFACE=wg0
WG_CONFIG=/etc/wireguard/wg0.conf
DB_PATH=/var/lib/averiq-api/clients.sqlite3
API_PORT=8765
EOF
chmod 600 /etc/averiq-api.env
unset BOT_TOKEN

systemctl daemon-reload
systemctl enable --now averiq-api
sleep 1
if systemctl is-active --quiet averiq-api; then
  echo
  echo "Averiq API запущен локально на 127.0.0.1:8765."
  echo "Проверка:"
  curl -fsS http://127.0.0.1:8765/health || true
  echo
  echo "Осталось настроить HTTPS reverse proxy для /api/* и задать API URL в index.html."
else
  systemctl --no-pager --full status averiq-api || true
  journalctl -u averiq-api -n 30 --no-pager || true
  exit 1
fi
