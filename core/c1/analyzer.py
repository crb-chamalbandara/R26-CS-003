"""
Component 1 — Malicious Browser Extension Analyzer
Entrypoint stub. Implement the functions below.
See ARCHITECTURE.md for the full specification.
"""


async def analyze_extension(manifest: str, source_code: str) -> dict:
    """
    Static + dynamic analysis of a browser extension.

    Args:
        manifest:    Raw JSON string of the extension's manifest.json
        source_code: Concatenated JS source of the extension's content scripts

    Returns:
        {"score": float 0-1, "verdict": str, "detail": str, "flags": list[str]}

    Expected verdicts: "SAFE" | "SUSPICIOUS" | "MALICIOUS"
    """
    raise NotImplementedError(
        "Component 1 — Extension Analyzer not yet implemented.\n"
        "See c1/ARCHITECTURE.md for implementation guide."
    )


async def sandbox_extension(extension_path: str) -> dict:
    """
    Deploy extension into Puppeteer headless sandbox and observe behaviour.

    Args:
        extension_path: Absolute path to unpacked extension directory

    Returns:
        {"network_requests": list, "dom_mutations": list,
         "cookie_access": list, "score": float, "detail": str}
    """
    raise NotImplementedError(
        "Component 1 — Sandbox analysis not yet implemented.\n"
        "See c1/ARCHITECTURE.md for implementation guide."
    )
