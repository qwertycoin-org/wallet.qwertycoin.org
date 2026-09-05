# Login Tracker Setup (VPS)

## 1. Copy files to server

```bash
scp server/login-tracker.py    root@your-vps:/opt/monero-web/
scp server/hide-inactive.sh    root@your-vps:/opt/monero-web/
scp server/login-tracker.service root@your-vps:/etc/systemd/system/
```

## 2. Create data directory

```bash
mkdir -p /var/lib/monero-web
mkdir -p /var/log/monero-web
```

## 3. Start the service

```bash
systemctl daemon-reload
systemctl enable login-tracker
systemctl start login-tracker
```

## 4. Add nginx proxy rule

Add this inside the existing `server` block for node.monero-web.com:

```nginx
location /lws/admin/ping {
    proxy_pass http://127.0.0.1:8446/ping;
    proxy_set_header Content-Type application/json;
}
```

Then reload nginx:
```bash
nginx -t && systemctl reload nginx
```

## 5. Add cron job

```bash
crontab -e
# Add this line (runs daily at 03:00 UTC):
0 3 * * * /opt/monero-web/hide-inactive.sh >> /var/log/monero-web/hide-inactive.log 2>&1
```

## 6. Verify

```bash
# Check service is running
systemctl status login-tracker

# Test the endpoint
curl -X POST http://127.0.0.1:8446/ping \
  -H 'Content-Type: application/json' \
  -d '{"address": "4TEST..."}'

# Check the database
sqlite3 /var/lib/monero-web/logins.db "SELECT * FROM logins"
```
