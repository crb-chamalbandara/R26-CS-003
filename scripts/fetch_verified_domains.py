"""
Build data/verified_domains.txt — the world-verified domain allowlist used by
C2's verified-domain trust gate (core/c2/verified_domains.py).

Source: the Tranco list (https://tranco-list.eu/) — a research-oriented ranking of the
most popular domains, designed for security research and citable via a permanent list ID.
We take the top-N registered domains (eTLD+1), one per line.

Usage:
    python scripts/fetch_verified_domains.py            # top 50,000 (default)
    python scripts/fetch_verified_domains.py 100000     # top 100,000

Reproducibility:
    By default this downloads the *latest* daily Tranco top-1M permalink. To pin an exact
    list for a paper, pass a Tranco list ID, e.g.:
        python scripts/fetch_verified_domains.py 50000 K2XLW
    which downloads https://tranco-list.eu/download/K2XLW/full

If the download fails (offline / blocked), a small curated fallback list is written so the
app still works out of the box. Re-run with network access to get full coverage.
"""
import csv
import io
import os
import sys
import zipfile
from urllib.request import urlopen, Request

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_OUT_PATH = os.path.join(_REPO_ROOT, "data", "verified_domains.txt")

_LATEST_URL = "https://tranco-list.eu/top-1m.csv.zip"


# Curated fallback — common legitimate domains, used only if the Tranco download fails.
_FALLBACK = """\
google.com microsoft.com apple.com amazon.com facebook.com instagram.com
youtube.com netflix.com dropbox.com linkedin.com twitter.com x.com
wellsfargo.com bankofamerica.com chase.com hsbc.com dhl.com fedex.com ups.com
paypal.com github.com gitlab.com stackoverflow.com wikipedia.org reddit.com
yahoo.com bing.com duckduckgo.com cloudflare.com mozilla.org office.com
live.com outlook.com gmail.com googleapis.com gstatic.com whatsapp.com
zoom.us slack.com adobe.com salesforce.com oracle.com ibm.com intel.com
spotify.com twitch.tv tiktok.com pinterest.com ebay.com walmart.com
target.com bestbuy.com cnn.com bbc.com nytimes.com theguardian.com
sliit.lk gov.uk irs.gov nih.gov harvard.edu mit.edu stanford.edu
""".split()


def _download_tranco(list_id: str = "") -> bytes:
    url = (f"https://tranco-list.eu/download/{list_id}/full"
           if list_id else _LATEST_URL)
    print(f"[fetch] downloading {url}")
    req = Request(url, headers={"User-Agent": "websentinel-c2/1.0"})
    with urlopen(req, timeout=60) as resp:
        return resp.read()


def _rows_from_payload(payload: bytes):
    """Tranco serves either a zip (permalink) or a raw CSV (list-id /full)."""
    if payload[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
            name = zf.namelist()[0]
            text = zf.read(name).decode("utf-8", "replace")
    else:
        text = payload.decode("utf-8", "replace")
    return csv.reader(io.StringIO(text))


def main() -> None:
    top_n = 50_000
    list_id = ""
    for arg in sys.argv[1:]:
        if arg.isdigit():
            top_n = int(arg)
        else:
            list_id = arg.strip()

    os.makedirs(os.path.dirname(_OUT_PATH), exist_ok=True)

    domains = []
    try:
        payload = _download_tranco(list_id)
        for row in _rows_from_payload(payload):
            # Tranco rows are: rank,domain
            if len(row) >= 2 and row[1]:
                domains.append(row[1].strip().lower())
            if len(domains) >= top_n:
                break
        print(f"[fetch] parsed {len(domains)} domains from Tranco")
    except Exception as exc:  # offline / blocked → curated fallback
        print(f"[fetch] download failed ({exc}); writing curated fallback list")
        domains = sorted(set(_FALLBACK))

    # De-dupe while preserving rank order.
    seen = set()
    uniq = []
    for d in domains:
        if d and d not in seen:
            seen.add(d)
            uniq.append(d)

    with open(_OUT_PATH, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(uniq) + "\n")
    print(f"[fetch] wrote {len(uniq)} domains -> {_OUT_PATH}")


if __name__ == "__main__":
    main()
