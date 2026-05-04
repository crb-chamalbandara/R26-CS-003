"""
C2 Layer 1 — Browser-in-the-Browser (BitB) detection
Analyses raw DOM for iframe-based overlay attacks.
"""
import re


async def check_bitb(url: str, dom: str) -> dict:
    """
    Heuristic checks:
    - Iframe with position:fixed / z-index stacking over page
    - Drag-prevention JS patterns
    - Iframe dimensions matching viewport
    - Fake browser-chrome elements inside iframe
    """
    if not dom:
        return {"score": 0.0, "detail": "No DOM available"}

    score = 0.0
    flags = []

    dom_lo = dom.lower()

    # Fixed-position iframe
    if re.search(r'<iframe[^>]*style=["\'][^"\']*position\s*:\s*fixed', dom_lo):
        score += 0.4
        flags.append("fixed-pos iframe")

    # High z-index
    if re.search(r'z-index\s*:\s*(99[0-9]{2,}|[1-9]\d{4,})', dom_lo):
        score += 0.2
        flags.append("high z-index")

    # Iframe covering full viewport (100vw/100vh or 100%)
    if re.search(r'width\s*:\s*100(vw|%)', dom_lo) and re.search(r'height\s*:\s*100(vh|%)', dom_lo):
        score += 0.2
        flags.append("full-viewport coverage")

    # Drag-prevention JS (common in BitB kits)
    if re.search(r'(ondragstart|onselectstart|user-select\s*:\s*none)', dom_lo):
        score += 0.15
        flags.append("drag-prevention JS")

    # Fake browser address-bar elements
    if re.search(r'(fake.*address|address.*bar|browser.*bar)', dom_lo):
        score += 0.3
        flags.append("fake address-bar element")

    score = min(1.0, score)
    detail = ", ".join(flags) if flags else "No BitB indicators"
    return {"score": round(score, 4), "detail": detail}
