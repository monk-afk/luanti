#!/usr/bin/env python3
"""
Very small local HTTP auth server for Luanti async auth testing.

Endpoint:
  GET /auth?name=<player>&ip=<ip>&delay=<seconds>

Response JSON:
  {
    "allow": true|false,
    "password": "<plain test password>",
    "privileges": ["interact", "shout"],
    "last_login": 0
  }

Usage:

  ./util/local_auth_test_server.py --host 127.0.0.1 --port 8085 --delay 1.5

"""

import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


USERS = {
    "alice": {
        "allow": True,
        "password": "alicepass",
        "privileges": ["interact", "shout"],
        "last_login": 0,
    },
    "admin": {
        "allow": True,
        "password": "adminpass",
        "privileges": ["interact", "shout", "server", "privs"],
        "last_login": 0,
    },
    "denied": {
        "allow": False,
    },
}


class Handler(BaseHTTPRequestHandler):
    default_delay = 1.5

    def log_message(self, fmt, *args):
        print("[%s] %s" % (self.address_string(), fmt % args))

    def _write_json(self, code: int, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/auth":
            self._write_json(404, {"error": "not_found"})
            return

        qs = parse_qs(parsed.query)
        name = (qs.get("name", [""])[0] or "").strip()
        ip = (qs.get("ip", [""])[0] or "").strip()

        delay_val = qs.get("delay", [None])[0]
        try:
            delay = float(delay_val) if delay_val is not None else self.default_delay
        except ValueError:
            delay = self.default_delay

        # Deterministic delay knobs for testing timeouts/concurrency.
        if name == "slow":
            delay = max(delay, 35.0)
        if delay > 0:
            time.sleep(delay)

        user = USERS.get(name)
        if user is None:
            # Unknown users default to denied.
            self._write_json(200, {"allow": False})
            return

        resp = dict(user)
        resp["name"] = name
        resp["ip"] = ip
        self._write_json(200, resp)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8085)
    parser.add_argument("--delay", type=float, default=1.5)
    args = parser.parse_args()

    Handler.default_delay = args.delay
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"local_http_auth_server listening on http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
