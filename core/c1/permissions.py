"""
C1 — permissions.py  |  Plain-language permission risk catalogue
------------------------------------------------------------------------
The verdict tells a user *that* an extension is dangerous. This module is
what tells them *why it can be*: the capabilities the extension asked the
browser for, ranked, in language a non-specialist can act on.

That is a different question from the flags in report.py. A flag says what
the extension DID (observed behaviour, or a pattern found in its code); a
permission says what it is ALLOWED to do (declared capability, granted at
install time whether or not it is ever used). An extension can score clean on
every behavioural signal and still be one update away from reading every
password field on every site, because the permission was granted up front.
Both halves belong in the report.

Severities are assigned by blast radius if the extension turns hostile, not by
how unusual the permission is: `storage` is ubiquitous and harmless, while
`nativeMessaging` is rare and lets the extension drive a desktop binary.

Descriptions deliberately say what the capability MEANS rather than restating
its name: "Read and change your data on every website you visit" rather than
"Grants all_urls host permission".
"""
from __future__ import annotations

from typing import Dict, List

from .features import _is_host_pattern

CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"

_SEV_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}


# ── Named API permissions ─────────────────────────────────────────────────────
# Keyed lowercase; lookup is case-insensitive.
_CATALOGUE: Dict[str, Dict[str, str]] = {
    # ── Critical: direct route to credentials, or to code outside the browser
    "nativemessaging": {
        "severity": CRITICAL,
        "desc": "Can send messages to a program installed on your computer, "
                "outside the browser's protection. This is how a browser "
                "extension reaches the rest of your machine.",
    },
    "debugger": {
        "severity": CRITICAL,
        "desc": "Can attach to browser tabs the way developer tools do, "
                "reading and modifying anything on any page, including "
                "passwords as you type them.",
    },
    "cookies": {
        "severity": CRITICAL,
        "desc": "Can read the login tokens that keep you signed in to websites. "
                "Stealing these lets someone enter your accounts without ever "
                "knowing your password.",
    },
    "proxy": {
        "severity": CRITICAL,
        "desc": "Can redirect all your browser traffic through another server, "
                "allowing it to be watched or altered in transit.",
    },
    "contentsettings": {
        "severity": HIGH,
        "desc": "Can change your browser's security settings per site, "
                "including re-enabling things you turned off for safety.",
    },

    # ── High: broad observation or modification of what you do
    "webrequest": {
        "severity": HIGH,
        "desc": "Can watch every network request the browser makes, including "
                "the contents of forms you submit.",
    },
    "webrequestblocking": {
        "severity": CRITICAL,
        "desc": "Can intercept and rewrite network requests before they are "
                "sent, including redirecting logins to a different server.",
    },
    "declarativenetrequest": {
        "severity": MEDIUM,
        "desc": "Can block or redirect network requests using preset rules. "
                "Standard for ad and content blockers.",
    },
    "declarativenetrequestwithhostaccess": {
        "severity": HIGH,
        "desc": "Can block or redirect network requests and see their full "
                "details on sites it has access to.",
    },
    "scripting": {
        "severity": HIGH,
        "desc": "Can inject its own code into web pages you visit, changing "
                "what they show or do.",
    },
    "history": {
        "severity": HIGH,
        "desc": "Can read your full browsing history, every page you have "
                "visited and when.",
    },
    "management": {
        "severity": HIGH,
        "desc": "Can see, disable, or uninstall your other extensions, "
                "including security extensions.",
    },
    "privacy": {
        "severity": HIGH,
        "desc": "Can change privacy-related browser settings, such as turning "
                "off protections that are on by default.",
    },
    "downloads": {
        "severity": HIGH,
        "desc": "Can download files to your computer and open them.",
    },
    "clipboardread": {
        "severity": HIGH,
        "desc": "Can read whatever you have copied, often passwords, wallet "
                "addresses, or personal details.",
    },
    "desktopcapture": {
        "severity": HIGH,
        "desc": "Can capture your screen contents.",
    },
    "tabcapture": {
        "severity": HIGH,
        "desc": "Can record the contents of browser tabs.",
    },
    "pagecapture": {
        "severity": HIGH,
        "desc": "Can save a complete copy of any page you visit, including "
                "pages only you can see when logged in.",
    },
    "geolocation": {
        "severity": HIGH,
        "desc": "Can read your physical location.",
    },
    "identity": {
        "severity": HIGH,
        "desc": "Can obtain sign-in tokens for your Google account.",
    },
    "vpnprovider": {
        "severity": HIGH,
        "desc": "Can route your network traffic as a VPN provider.",
    },

    # ── Medium: real reach, but ordinary for many legitimate extensions
    "tabs": {
        "severity": MEDIUM,
        "desc": "Can see the address and title of every tab you have open, "
                "building a picture of your browsing as it happens.",
    },
    "webnavigation": {
        "severity": MEDIUM,
        "desc": "Can watch you move between pages in real time.",
    },
    "activetab": {
        "severity": MEDIUM,
        "desc": "Can access the current tab, but only after you click the "
                "extension, a deliberately limited alternative to full "
                "site access.",
    },
    "clipboardwrite": {
        "severity": MEDIUM,
        "desc": "Can replace what you have copied before you paste it.",
    },
    "bookmarks": {
        "severity": MEDIUM,
        "desc": "Can read and change your saved bookmarks.",
    },
    "topsites": {
        "severity": MEDIUM,
        "desc": "Can see the sites you visit most often.",
    },
    "sessions": {
        "severity": MEDIUM,
        "desc": "Can read recently closed tabs and tabs open on your other "
                "signed-in devices.",
    },
    "notifications": {
        "severity": MEDIUM,
        "desc": "Can show system notifications, which can be used to imitate "
                "messages from the operating system or other apps.",
    },
    "background": {
        "severity": MEDIUM,
        "desc": "Can keep running in the background whenever the browser is "
                "open, even when you are not using it.",
    },
    "unlimitedstorage": {
        "severity": MEDIUM,
        "desc": "Can store an unlimited amount of data on your computer.",
    },
    "contextmenus": {
        "severity": LOW,
        "desc": "Can add its own entries to the right-click menu.",
    },
    "search": {
        "severity": MEDIUM,
        "desc": "Can run searches and change how search results reach you.",
    },
    "processes": {
        "severity": MEDIUM,
        "desc": "Can inspect the browser's internal processes.",
    },
    "system.storage": {
        "severity": MEDIUM,
        "desc": "Can read information about your computer's storage devices.",
    },

    # ── Low: routine, minimal reach on their own
    "storage": {
        "severity": LOW,
        "desc": "Can save its own settings and data in the browser. Needed by "
                "almost every extension.",
    },
    "alarms": {
        "severity": LOW,
        "desc": "Can schedule itself to run at set times, commonly used for "
                "periodic checks and updates.",
    },
    "idle": {
        "severity": LOW,
        "desc": "Can tell whether you are currently active at your computer.",
    },
    "power": {
        "severity": LOW,
        "desc": "Can keep your screen or system from going to sleep.",
    },
    "offscreen": {
        "severity": LOW,
        "desc": "Can run hidden pages to do work out of sight. Ordinary in "
                "modern extensions, which have no persistent page of their own.",
    },
    "scripttag": {
        "severity": LOW,
        "desc": "Can load additional scripts into its own pages.",
    },
    "favicon": {
        "severity": LOW,
        "desc": "Can read website icons.",
    },
    "sidepanel": {
        "severity": LOW,
        "desc": "Can show a panel alongside web pages.",
    },
    "tts": {
        "severity": LOW,
        "desc": "Can use the browser's text-to-speech engine.",
    },
    "fontsettings": {
        "severity": LOW,
        "desc": "Can change the browser's font settings.",
    },
    "printerprovider": {
        "severity": LOW,
        "desc": "Can offer itself as a printer to the browser.",
    },
}


def _host_entry(pattern: str) -> Dict[str, object]:
    """Classify one host match pattern.

    Blanket patterns are the single most consequential thing in a manifest —
    they are what turns "an extension" into "something running on your bank's
    login page", so they are rated separately from a named origin.
    """
    raw = pattern.strip()
    low = raw.lower()

    blanket = low in ("<all_urls>", "*://*/*", "*://*/", "http://*/*",
                      "https://*/*", "file:///*", "*://*")
    if blanket:
        return {
            "name": raw,
            "severity": CRITICAL,
            "description": "Can read and change your data on every website you "
                           "visit, including banking, email, and any page "
                           "where you enter a password.",
            "is_host": True,
        }

    # A wildcard across a whole domain still covers every page and subdomain
    # under it, which for a large provider is a very wide grant.
    return {
        "name": raw,
        "severity": MEDIUM,
        "description": f"Can read and change your data on {_host_label(raw)}.",
        "is_host": True,
    }


def _host_label(pattern: str) -> str:
    """Human-readable site name from a match pattern, for the description."""
    text = pattern
    for prefix in ("*://", "https://", "http://", "file://"):
        if text.lower().startswith(prefix):
            text = text[len(prefix):]
            break
    text = text.rstrip("/*").rstrip("/")
    if text.startswith("*."):
        return f"{text[2:]} and all of its subdomains"
    return text or pattern


def explain_permissions(manifest: dict) -> List[Dict[str, object]]:
    """Every capability the manifest declares, explained and severity-sorted.

    Reads both manifest versions. MV3 splits host access into its own
    `host_permissions` field; MV2 has no such field and mixes match patterns
    directly into `permissions`, the same split already handled for the
    classifier in features.py, reused here rather than re-derived.

    Unknown permissions are kept with a generic description rather than
    dropped: a permission this catalogue has not seen is exactly the one worth
    showing, and silently omitting it would understate what was granted.
    """
    if not isinstance(manifest, dict):
        return []

    raw_perms = manifest.get("permissions") or []
    raw_hosts = manifest.get("host_permissions") or []
    optional  = manifest.get("optional_permissions") or []

    entries: List[Dict[str, object]] = []
    seen: set = set()

    def add(entry: Dict[str, object]) -> None:
        key = str(entry["name"]).lower()
        if key in seen:
            return
        seen.add(key)
        entries.append(entry)

    for item in list(raw_hosts) + list(raw_perms) + list(optional):
        if not isinstance(item, (str, bytes)):
            continue
        name = str(item).strip()
        if not name:
            continue

        if _is_host_pattern(name):
            add(_host_entry(name))
            continue

        info = _CATALOGUE.get(name.lower())
        if info:
            add({
                "name": name,
                "severity": info["severity"],
                "description": info["desc"],
                "is_host": False,
            })
        else:
            add({
                "name": name,
                "severity": LOW,
                "description": f"Requests the {name} capability. This one is not "
                               f"in the risk catalogue, so it has not been rated.",
                "is_host": False,
            })

    entries.sort(key=lambda e: (_SEV_ORDER.get(str(e["severity"]), 99),
                                str(e["name"]).lower()))
    return entries


def permission_risk_counts(entries: List[Dict[str, object]]) -> Dict[str, int]:
    """Tally by severity, drives the 'N high-risk' subtitle on the stat card."""
    counts = {CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0}
    for entry in entries:
        sev = str(entry.get("severity", LOW))
        if sev in counts:
            counts[sev] += 1
    counts["total"]     = len(entries)
    counts["high_risk"] = counts[CRITICAL] + counts[HIGH]
    return counts
