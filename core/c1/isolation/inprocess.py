"""
C1 — isolation/inprocess.py  |  Host-process backend (fallback)
------------------------------------------------------------------------
Runs the observation directly in the analysis process: a Chromium child of the
WebSentinel server, on the host OS, as the host user.

This is the original C1 behaviour and remains the fallback when no stronger
containment is available. It is fast (no guest boot) and needs nothing
installed, but it is NOT a sandbox in the containment sense, and its report
says so plainly:

  * the extension executes on the host kernel and filesystem
  * it reaches the network as the host, from the host's IP
  * `--no-sandbox` is passed to Chromium (a Playwright requirement for loading
    unpacked extensions in a persistent context), which also disables
    Chromium's own renderer sandbox

What it *does* guarantee is a fresh, throwaway browser profile per analysis,
so cookies, localStorage and extension storage never leak between runs.
"""
from __future__ import annotations

from typing import Any, Dict

from .base import (
    IsolationBackend, IsolationReport,
    LEVEL_BROWSER, NET_UNRESTRICTED,
)


class InProcessBackend(IsolationBackend):
    name = "inprocess"

    def __init__(self, network_policy: str = NET_UNRESTRICTED) -> None:
        # The host backend cannot enforce a network policy — Chromium is a
        # child process on the host stack. Requesting one is recorded as an
        # unmet request rather than silently accepted.
        self._requested_network = network_policy or NET_UNRESTRICTED

    @classmethod
    def is_available(cls) -> tuple[bool, str]:
        try:
            import playwright  # noqa: F401
        except ImportError:
            return False, "playwright is not installed"
        return True, "runs Chromium directly on the host"

    def describe(self) -> IsolationReport:
        warnings = [
            "Extension code executes on the host OS as the host user — this is "
            "not a virtual machine and not a container.",
            "Chromium's own renderer sandbox is disabled (--no-sandbox), which "
            "Playwright requires to load an unpacked extension here.",
            "Network egress is unrestricted and leaves from the host's own IP.",
        ]
        if self._requested_network != NET_UNRESTRICTED:
            warnings.append(
                f"Requested network policy {self._requested_network!r} could not "
                f"be enforced by this backend; the sandbox ran with unrestricted "
                f"network access."
            )
        return IsolationReport(
            backend=self.name,
            level=LEVEL_BROWSER,
            ephemeral=True,                      # the browser profile is
            fresh_per_analysis=True,             # created per run and
            discarded_after=True,                # deleted when the run ends
            shares_host_kernel=True,
            shares_host_filesystem=True,
            shares_host_network_identity=True,
            chromium_own_sandbox=False,
            network_policy=NET_UNRESTRICTED,
            detail=("Chromium child process on the host with a throwaway profile "
                    "directory. Browser state is isolated between analyses; the "
                    "operating system is not."),
            warnings=warnings,
        )

    async def run(self, extension_path: str, timeout_seconds: int) -> Dict[str, Any]:
        from ..sandbox import observe_extension
        result = await observe_extension(extension_path, timeout_seconds)
        result["isolation"] = self.describe().as_dict()
        return result
