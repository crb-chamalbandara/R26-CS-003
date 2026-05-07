"""
scripts/generate_logo_hashes.py
───────────────────────────────
Downloads brand logos via Clearbit Logo API, computes perceptual hashes (pHash),
and saves results to data/logo_hashes.json for use by C2 Layer 3 (Visual Similarity).

Usage (from project root):
    python scripts/generate_logo_hashes.py

Requires:
    pip install imagehash Pillow httpx
"""
import json
import sys
from pathlib import Path
from io import BytesIO

try:
    import httpx
    import imagehash
    from PIL import Image
except ImportError as e:
    sys.exit(f"Missing dependency: {e}\nRun: pip install imagehash Pillow httpx")

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT    = REPO_ROOT / "data" / "logo_hashes.json"

# Brand name -> primary domain mapping
BRANDS = {
    "paypal":         "paypal.com",
    "microsoft":      "microsoft.com",
    "apple":          "apple.com",
    "amazon":         "amazon.com",
    "google":         "google.com",
    "facebook":       "facebook.com",
    "instagram":      "instagram.com",
    "netflix":        "netflix.com",
    "dropbox":        "dropbox.com",
    "linkedin":       "linkedin.com",
    "twitter":        "twitter.com",
    "wellsfargo":     "wellsfargo.com",
    "bankofamerica":  "bankofamerica.com",
    "chase":          "chase.com",
    "hsbc":           "hsbc.com",
    "dhl":            "dhl.com",
    "fedex":          "fedex.com",
    "ups":            "ups.com",
    "irs":            "irs.gov",
}

# Clearbit returns 128×128 PNG logos — good quality for pHash
CLEARBIT_URL  = "https://logo.clearbit.com/{domain}?size=128&format=png"
# Fallback: DuckDuckGo favicon (lower quality but widely available)
DUCKDUCKGO_URL = "https://icons.duckduckgo.com/ip3/{domain}.ico"


def _fetch_image(url: str, client: httpx.Client) -> Image.Image | None:
    """Fetch a URL and return a PIL Image, or None on failure."""
    try:
        r = client.get(url, timeout=10, follow_redirects=True)
        ct = r.headers.get("content-type", "")
        if r.status_code == 200 and ("image" in ct or r.content[:4] in (b"\x89PNG", b"\xff\xd8\xff", b"GIF8")):
            return Image.open(BytesIO(r.content)).convert("RGB")
    except Exception:
        pass
    return None


def fetch_logo_hash(brand: str, domain: str, client: httpx.Client) -> str | None:
    """Try Clearbit first, fall back to DuckDuckGo favicon."""
    # Primary: Clearbit Logo API
    img = _fetch_image(CLEARBIT_URL.format(domain=domain), client)

    # Fallback: DuckDuckGo
    if img is None:
        img = _fetch_image(DUCKDUCKGO_URL.format(domain=domain), client)

    if img is None:
        return None

    h = imagehash.phash(img)
    return str(h)


def main():
    print("=" * 50)
    print(" WebSentinel — Logo Hash Generator (L3)")
    print("=" * 50)
    print(f"Fetching logos for {len(BRANDS)} brands...\n")

    hashes = {}
    failed = []

    with httpx.Client(headers={"User-Agent": "WebSentinel/2.0 logo-indexer"}) as client:
        for brand, domain in BRANDS.items():
            print(f"  [{brand:15s}] {domain} ... ", end="", flush=True)
            h = fetch_logo_hash(brand, domain, client)
            if h:
                hashes[brand] = h
                print(f"OK  hash={h}")
            else:
                failed.append(brand)
                print("FAILED (no image returned)")

    print()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w") as f:
        json.dump(hashes, f, indent=2)

    print(f"Saved {len(hashes)}/{len(BRANDS)} logo hashes -> {OUTPUT}")
    if failed:
        print(f"Failed brands: {', '.join(failed)}")
        print("Tip: manually place <brand>.png files in data/logos/ and rerun, or add hashes manually.")
    print("\nRestart the FastAPI backend to load the updated logo_hashes.json.")


if __name__ == "__main__":
    main()
