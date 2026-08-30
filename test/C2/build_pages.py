"""
test/C2/build_pages.py
──────────────────────
Builds the self-contained realistic test pages in test/C2/pages/ from the real
mrd0x BITB attack templates in test/C2/bitb_samples/.

- Fills the XX-TITLE-XX / XX-DOMAIN-NAME-XX / XX-DOMAIN-PATH-XX / XX-PHISHING-LINK-XX
  placeholders with a realistic Microsoft-login masquerade.
- Inlines style.css and script.js so each page is a single self-contained HTML file
  (the dashboard test runner serves them via /dev/test-page/<name>).

Usage:
    python test/C2/build_pages.py
"""
import re
from pathlib import Path

HERE    = Path(__file__).resolve().parent
SAMPLES = HERE / "bitb_samples"
OUT     = HERE / "pages"

# Realistic masquerade: the fake window claims to be Microsoft's OAuth login
FILL = {
    "XX-TITLE-XX":       "Sign in to your Microsoft account",
    "XX-DOMAIN-NAME-XX": "login.microsoftonline.com",
    "XX-DOMAIN-PATH-XX": "/oauth2/v2.0/authorize",
    "XX-PHISHING-LINK-XX": "https://login-microsoftonline.evil-phish.xyz/oauth",
}

# template folder -> output filename
KITS = {
    "Windows-Chrome-DarkMode": "bitb_kit_windows.html",
    "MacOS-Chrome-DarkMode":   "bitb_kit_macos.html",
}


def inline_css(html: str, folder: Path) -> str:
    def rep(m):
        p = folder / m.group(1)
        return f"<style>\n{p.read_text(encoding='utf-8', errors='replace')}\n</style>" if p.exists() else m.group(0)
    return re.sub(r'<link[^>]+href=["\']([^"\']+\.css)["\'][^>]*>', rep, html, flags=re.IGNORECASE)


def inline_js(html: str, folder: Path) -> str:
    p = folder / "script.js"
    if p.exists():
        html = html.replace('<script src="script.js"></script>',
                            f"<script>\n{p.read_text(encoding='utf-8', errors='replace')}\n</script>")
    return html


def main() -> int:
    OUT.mkdir(exist_ok=True)
    for folder_name, out_name in KITS.items():
        folder = SAMPLES / folder_name
        src = folder / "index.html"
        if not src.exists():
            print(f"SKIP {folder_name} — index.html not found")
            continue
        html = src.read_text(encoding="utf-8", errors="replace")
        for k, v in FILL.items():
            html = html.replace(k, v)
        html = inline_css(html, folder)
        html = inline_js(html, folder)
        (OUT / out_name).write_text(html, encoding="utf-8")
        print(f"OK   {folder_name:28} -> pages/{out_name} ({len(html)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
