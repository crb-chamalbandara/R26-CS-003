"""
C2 Layer 4 — Form destination analysis
Checks whether form POST actions submit to a different domain than the page.
"""
import re
from urllib.parse import urlparse


async def check_form(url: str, dom: str) -> dict:
    """
    Flags:
    - Password <input> fields on a page where form action points off-domain
    - Hidden <input> fields collecting data off-domain
    - Forms with no action (data goes to JS → harder to detect)
    """
    if not dom:
        return {"score": 0.0, "detail": "No DOM available",
                "evidence": {"reason": "no DOM supplied"}}

    try:
        page_host = (urlparse(url).hostname or "").lower()
    except Exception:
        return {"score": 0.0, "detail": "Could not parse URL",
                "evidence": {"reason": "URL did not parse"}}

    dom_lo = dom.lower()
    score  = 0.0
    flags  = []

    # Find all form actions
    form_actions = re.findall(r'<form[^>]+action=["\']([^"\']*)["\']', dom_lo)
    has_password  = bool(re.search(r'<input[^>]+type=["\']password["\']', dom_lo))

    # Hosts each form actually posts to. The score collapses this to a number and
    # the detail line truncates it, so the alert evidence keeps the full list —
    # "which host were the credentials going to" is the first question an analyst
    # asks, and it was not recoverable from a stored alert before.
    off_domain_hosts = []
    off_domain_seen = False
    for action in form_actions:
        if not action or action.startswith("#") or action.startswith("javascript"):
            continue
        try:
            action_host = (urlparse(action).hostname or "").lower()
        except Exception:
            continue
        if action_host and page_host and action_host != page_host:
            score += 0.50
            flags.append(f"form→{action_host}")
            off_domain_hosts.append(action_host)
            off_domain_seen = True

    # Apply the password-field penalty once per page, not once per form.
    if off_domain_seen and has_password:
        score += 0.35
        flags.append("password field on off-domain form")

    # Inline JS data exfiltration patterns
    async_exfil = bool(re.search(r'(fetch|XMLHttpRequest|axios)\s*\(.*https?://', dom_lo))
    if async_exfil:
        score += 0.10
        flags.append("async data exfil")

    score = min(1.0, score)
    detail = ", ".join(flags) if flags else "No form anomalies"
    evidence = {
        "page_host":                   page_host,
        "form_actions":                form_actions,
        "off_domain_hosts":            off_domain_hosts,
        "form_count":                  len(form_actions),
        "has_password_field":          has_password,
        "password_on_off_domain_form": bool(off_domain_seen and has_password),
        "async_exfil":                 async_exfil,
        "flags":                       list(flags),
    }
    return {"score": round(score, 4), "detail": detail, "evidence": evidence}
