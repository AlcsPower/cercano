# Copyright (C) 2026 Cercano Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""
API Stub para el laboratorio de Cercano.
Emula endpoints del servidor de API (hbbs/control-plane) y registra peticiones
entrantes para análisis de tráfico (Spike S3) y pruebas de integración.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import sys
import time

PORT = int(os.environ.get("PORT", "21114"))
LOG_FILE = os.environ.get("LOG_FILE", "/data/requests.jsonl")

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


class StubHandler(BaseHTTPRequestHandler):
    def _log_request(self, method, path, headers, body_bytes):
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "client_ip": self.client_address[0],
            "method": method,
            "path": path,
            "headers": dict(headers),
            "body": body_bytes.decode("utf-8", errors="replace"),
        }
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        print(f"[{entry['ts']}] {method} {path} from {self.client_address[0]}", flush=True)

    def _send_json(self, status_code, data):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        self._log_request("GET", self.path, self.headers, body)

        if self.path == "/healthz":
            self._send_json(200, {"status": "ok", "service": "cercano-api-stub"})
        elif self.path == "/api/events":
            events = []
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                events.append(json.loads(line))
                            except Exception:
                                pass
            self._send_json(200, {"count": len(events), "events": events})
        else:
            self._send_json(200, {"status": "ok", "path": self.path})

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        self._log_request("POST", self.path, self.headers, body)

        # Rutas comunes esperadas del cliente RustDesk / Cercano
        if self.path in ("/api/heartbeat", "/api/sysinfo", "/api/audit", "/api/login-options"):
            self._send_json(200, {"status": "success", "recorded": True})
        else:
            self._send_json(200, {"status": "accepted", "path": self.path})


def run():
    server = HTTPServer(("0.0.0.0", PORT), StubHandler)
    print(f"cercano-api-stub escuchando en 0.0.0.0:{PORT} (log: {LOG_FILE})", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    run()
