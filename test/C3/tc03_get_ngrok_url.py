"""
Standalone helper for test_c3_real_world_beacon.bat -- polls ngrok's local
agent API (http://127.0.0.1:4040) for the public HTTPS tunnel URL currently
exposing the TC-03 mimicry server, so the demo .bat never needs a hardcoded
or manually copy-pasted tunnel address (ngrok's free tier assigns a new
random subdomain every launch).

Prints the public https URL to stdout and exits 0 once one appears; prints
a diagnostic to stderr and exits 1 if none appears within the timeout.
Not part of the WebSentinel/C3 backend -- never imported by it.
"""
from __future__ import annotations

import json
import sys
import time
from urllib import error, request

NGROK_API = "http://127.0.0.1:4040/api/tunnels"
TIMEOUT_S = 25


def _find_https_url() -> str | None:
    try:
        with request.urlopen(NGROK_API, timeout=2) as r:
            data = json.loads(r.read().decode())
    except (error.URLError, error.HTTPError, OSError, ValueError):
        return None
    for t in data.get("tunnels", []):
        if t.get("proto") == "https" and t.get("public_url"):
            return t["public_url"]
    return None


def main() -> int:
    deadline = time.time() + TIMEOUT_S
    while time.time() < deadline:
        url = _find_https_url()
        if url:
            print(url)
            return 0
        time.sleep(1)
    print(
        f"ngrok did not expose an https tunnel within {TIMEOUT_S}s "
        f"(is ngrok running and reachable at {NGROK_API}?)",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
