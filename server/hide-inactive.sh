#!/usr/bin/env bash
# hide-inactive.sh — Cron script to hide wallets inactive for 15+ days.
#
# Queries the login tracker's SQLite DB for addresses whose last_login
# is older than 15 days, then hides each one via monero-lws-admin.
#
# Crontab entry (run daily at 03:00 UTC):
#   0 3 * * * /opt/monero-web/hide-inactive.sh >> /var/log/monero-web/hide-inactive.log 2>&1

set -euo pipefail

DB_PATH="${LOGIN_DB_PATH:-/var/lib/monero-web/logins.db}"
LWS_ADMIN="/root/monero-lws/build/src/monero-lws-admin"
LWS_DB="/home/monero/.monero-lws"
INACTIVE_DAYS=15

if [ ! -f "$DB_PATH" ]; then
    echo "[$(date -u +%FT%TZ)] database not found at $DB_PATH — skipping"
    exit 0
fi

echo "[$(date -u +%FT%TZ)] checking for accounts inactive > ${INACTIVE_DAYS} days"

# Query addresses where last_login is older than INACTIVE_DAYS
ADDRESSES=$(sqlite3 "$DB_PATH" \
    "SELECT address FROM logins
     WHERE last_login < datetime('now', '-${INACTIVE_DAYS} days')")

if [ -z "$ADDRESSES" ]; then
    echo "[$(date -u +%FT%TZ)] no inactive accounts found"
    exit 0
fi

COUNT=0
while IFS= read -r addr; do
    echo "[$(date -u +%FT%TZ)] hiding inactive: ${addr:0:10}..."
    "$LWS_ADMIN" --db-path "$LWS_DB" modify_account_status hidden "$addr" 2>&1 || true
    COUNT=$((COUNT + 1))
done <<< "$ADDRESSES"

echo "[$(date -u +%FT%TZ)] done — hid $COUNT account(s)"
