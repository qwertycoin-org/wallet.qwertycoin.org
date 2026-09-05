#!/usr/bin/env python3
"""
login-tracker.py — Tiny HTTP server that records wallet login timestamps.

Listens on 127.0.0.1:8446 (nginx proxies /lws/admin/ping here).
Stores (address, last_login) in a SQLite database so a cron job can
hide wallets that haven't logged in for 15+ days.

Usage:
    python3 login-tracker.py          # foreground
    nohup python3 login-tracker.py &  # background

SystemD unit recommended for production — see login-tracker.service.
"""

import json
import sqlite3
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

DB_PATH = os.environ.get('LOGIN_DB_PATH', '/var/lib/monero-web/logins.db')
LISTEN_HOST = '127.0.0.1'
LISTEN_PORT = 8446


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS logins (
            address    TEXT PRIMARY KEY,
            last_login TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Quieter logs: just timestamp + first arg
        print(f'[login-tracker] {datetime.utcnow().isoformat()} {args[0] if args else ""}')

    def _respond(self, code, body):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def do_POST(self):
        if self.path != '/ping':
            self._respond(404, {'error': 'not found'})
            return

        length = int(self.headers.get('Content-Length', 0))
        if length == 0 or length > 4096:
            self._respond(400, {'error': 'bad request'})
            return

        try:
            data = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._respond(400, {'error': 'invalid json'})
            return

        address = data.get('address', '').strip()
        if not address or len(address) < 90:
            self._respond(400, {'error': 'invalid address'})
            return

        now = datetime.utcnow().isoformat()
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            'INSERT INTO logins (address, last_login) VALUES (?, ?) '
            'ON CONFLICT(address) DO UPDATE SET last_login = ?',
            (address, now, now)
        )
        conn.commit()
        conn.close()

        self._respond(200, {'status': 'ok', 'last_login': now})


if __name__ == '__main__':
    init_db()
    server = HTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    print(f'[login-tracker] listening on {LISTEN_HOST}:{LISTEN_PORT}')
    print(f'[login-tracker] database: {DB_PATH}')
    server.serve_forever()
