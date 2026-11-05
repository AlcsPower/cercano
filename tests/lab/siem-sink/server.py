# Copyright (C) 2026 Cercano Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""
Receptor SIEM simulado para pruebas de exportación (TC-F2-040).
Escucha en Syslog UDP (514) y HTTP POST (8088).
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import socket
import threading
import time

LOG_FILE = os.environ.get("SIEM_LOG_FILE", "/data/siem_events.log")
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8088"))
SYSLOG_PORT = int(os.environ.get("SYSLOG_PORT", "514"))

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


def log_event(proto, raw_data, sender):
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    entry = f"[{ts}] [{proto}] from {sender}: {raw_data.strip()}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry)
    print(entry, end="", flush=True)


class SiemHttpHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        log_event("HTTP", body, self.client_address[0])
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"received"}')

    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok","service":"siem-sink"}')
        elif self.path == "/events":
            content = ""
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, "r", encoding="utf-8") as f:
                    content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()


def syslog_udp_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", SYSLOG_PORT))
    print(f"SIEM Sink escuchando Syslog UDP en 0.0.0.0:{SYSLOG_PORT}", flush=True)
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            log_event("SYSLOG", data.decode("utf-8", errors="replace"), addr[0])
        except Exception as e:
            print(f"Error en syslog listener: {e}", flush=True)


def run():
    t = threading.Thread(target=syslog_udp_listener, daemon=True)
    t.start()
    httpd = HTTPServer(("0.0.0.0", HTTP_PORT), SiemHttpHandler)
    print(f"SIEM Sink escuchando HTTP en 0.0.0.0:{HTTP_PORT} (log: {LOG_FILE})", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    run()
