#!/usr/bin/env python3
"""
NIVRA receiver: a minimal authenticated HTTPS endpoint that accepts
normalized JSON telemetry events from the Android agent and appends them,
one JSON object per line, to a log file that the Wazuh Manager's own agent
(installed locally on this same host) monitors via a <localfile> stanza.

INGESTION MECHANISM (see WazuhTransport.kt for the full rationale): this
bridges plain HTTPS POSTs into Wazuh's supported "monitor a JSON Lines
file" ingestion path, since the native wazuh-agent daemon can't run on
Android without root.

Authentication: each enrolled device has a bearer token, stored (hashed)
in enrolled_devices.json next to this script. A request is rejected with
401 if the token is missing/invalid, and with 403 if the token is valid
but doesn't match the device_id in the payload (defends against a stolen
token from one device being replayed for a different device_id).

Deployment:
  1. Generate a token per device at enrollment time and add it to
     enrolled_devices.json (see enrolled_devices.example.json).
  2. Run this behind a real TLS terminator (nginx/Caddy) or supply your own
     cert via --cert/--key, on the same host as (or reachable by) the
     Wazuh Manager.
  3. Add to /var/ossec/etc/ossec.conf on the manager:

       <localfile>
         <log_format>json</log_format>
         <location>/var/log/nivra/nivra-events.json</location>
       </localfile>

  4. Restart the manager's log collector.
  5. Install nivra_decoder.xml and nivra_rules.xml (see sibling folders).
"""

import argparse
import hashlib
import json
import os
import ssl
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

LOG_DIR = "/var/log/nivra"
LOG_FILE = os.path.join(LOG_DIR, "nivra-events.json")
ENROLLED_DEVICES_FILE = os.path.join(os.path.dirname(__file__), "enrolled_devices.json")

REQUIRED_TOP_LEVEL = {"schema_version", "event_id", "timestamp", "device", "agent", "event", "data"}
MAX_BODY_BYTES = 256 * 1024  # generous ceiling for a single normalized event


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def load_enrolled_devices() -> dict:
    """Returns {device_id: hashed_token}. Missing file -> no devices enrolled (fail closed)."""
    if not os.path.exists(ENROLLED_DEVICES_FILE):
        return {}
    with open(ENROLLED_DEVICES_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


class NivraIngestHandler(BaseHTTPRequestHandler):
    server_version = "NivraReceiver/0.2"

    def do_POST(self):
        if self.path != "/nivra/ingest":
            self._reject(404, "not_found")
            return

        length = int(self.headers.get("Content-Length", 0))
        if length <= 0 or length > MAX_BODY_BYTES:
            self._reject(400, "invalid_content_length")
            return

        auth_header = self.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            self._reject(401, "missing_bearer_token")
            return
        token = auth_header[len("Bearer "):].strip()

        raw = self.rfile.read(length)
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            self._reject(400, "invalid_json")
            return

        if not REQUIRED_TOP_LEVEL.issubset(event.keys()):
            self._reject(422, "missing_required_fields")
            return

        device_id = event.get("device", {}).get("device_id", "")
        enrolled = load_enrolled_devices()
        expected_hash = enrolled.get(device_id)
        if expected_hash is None or hash_token(token) != expected_hash:
            self._reject(403, "token_device_mismatch")
            return

        event["_receiver_ingested_at"] = datetime.now(timezone.utc).isoformat()

        os.makedirs(LOG_DIR, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "accepted", "event_id": event["event_id"]}).encode())

    def _reject(self, code: int, reason: str):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"error": reason}).encode())

    def log_message(self, format, *args):
        # Route access logs through your own logging pipeline in production;
        # deliberately not printing to stdout here to avoid leaking tokens
        # via default http.server request-line logging.
        pass


def run(port: int, certfile: str, keyfile: str):
    server = HTTPServer(("0.0.0.0", port), NivraIngestHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print(f"NIVRA receiver listening on https://0.0.0.0:{port}/nivra/ingest")
    server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NIVRA HTTPS ingestion receiver")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cert", default="cert.pem")
    parser.add_argument("--key", default="key.pem")
    args = parser.parse_args()
    run(args.port, args.cert, args.key)
