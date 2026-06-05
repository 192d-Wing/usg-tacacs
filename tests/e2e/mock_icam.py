#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Minimal mock ICAM server for e2e router tests.

Handles three request patterns:
  POST /auth/device                     → RFC 8628 device code response
  POST /token  grant_type=password      → fake JWT for valid static credentials
  POST /token  grant_type=device_code   → authorization_pending (no real browser auth)

This lets the e2e suite verify that:
  - Non-excluded users receive a GETDATA reply containing the mock URL.
  - Excluded users fall back to ROPC, which succeeds via the fake JWT.
"""
import base64
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

DEVICE_CODE = "mock-e2e-device-code"
USER_CODE   = "TEST-CODE"
BASE_URL    = "http://mock-icam:8090"

# Static credentials mirroring the usg-tacacs-device compose config.
VALID_CREDS = {"alice": "alice-secret", "bob": "bob-secret"}

# Pre-built fake JWT with groups claim (no signature — icam_decode_jwt_payload
# only base64-decodes the payload, it does not verify signatures).
def _make_jwt(username: str) -> str:
    header  = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({
        "sub": username,
        "groups": ["netops"],
        "exp": 9999999999,
    }).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}."


class MockIcamHandler(BaseHTTPRequestHandler):
    """Handle RFC 8628 device auth and token endpoint requests."""

    def _json(self, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_form(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode()
        return {k: v[0] for k, v in parse_qs(raw).items()}

    def do_POST(self) -> None:
        form = self._read_form()
        if self.path.endswith("/auth/device"):
            self._json({
                "device_code":              DEVICE_CODE,
                "user_code":                USER_CODE,
                "verification_uri":         f"{BASE_URL}/device",
                "verification_uri_complete": f"{BASE_URL}/device?user_code={USER_CODE}",
                "expires_in":               60,
                "interval":                 1,
            })
            return
        grant = form.get("grant_type", "")
        if grant == "password":
            username = form.get("username", "")
            password = form.get("password", "")
            if VALID_CREDS.get(username) == password:
                self._json({"access_token": _make_jwt(username), "token_type": "Bearer"})
            else:
                self._json({"error": "invalid_grant",
                            "error_description": "Invalid credentials"})
        else:
            # device_code grant or unknown — always pending in e2e
            self._json({"error": "authorization_pending"})

    def log_message(self, *_args) -> None:
        pass  # suppress per-request noise in compose logs


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8090), MockIcamHandler)
    print("mock-icam listening on :8090", flush=True)
    server.serve_forever()
