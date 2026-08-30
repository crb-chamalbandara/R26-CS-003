"""
C1 — isolation/base.py  |  Sandbox isolation contract
------------------------------------------------------------------------
Purpose : Define what "isolated" means for a dynamic analysis run, and make
          every run state the isolation it actually had.

Why this exists
---------------
Before this layer, `run_sandbox()` launched Chromium directly on the host —
same kernel, same user account, same network — with `--no-sandbox`, which
also switches off Chromium's own renderer sandbox. The only thing that was
genuinely ephemeral was the browser profile directory. That is a real
isolation property, but a much weaker one than "the extension runs in a
disposable virtual machine", and nothing in the output distinguished the two.

So every backend now returns an `IsolationReport` alongside its findings, and
that report travels into the verdict. A result can then never imply
containment it did not have: if the analysis ran in-process, the report says
so in the same breath as the score.
"""
from __future__ import annotations

import abc
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional


# ── Isolation levels, weakest to strongest ────────────────────────────────────
LEVEL_NONE          = "none"              # no containment at all
LEVEL_BROWSER       = "browser_profile"   # fresh Chromium profile on the host
LEVEL_CONTAINER     = "container"         # OS-level container, shared kernel
LEVEL_EPHEMERAL_VM  = "ephemeral_vm"      # disposable VM, own kernel

_LEVEL_RANK = {
    LEVEL_NONE: 0, LEVEL_BROWSER: 1, LEVEL_CONTAINER: 2, LEVEL_EPHEMERAL_VM: 3,
}

# ── Network policies ──────────────────────────────────────────────────────────
NET_UNRESTRICTED = "unrestricted"   # extension reaches the real internet
NET_DISABLED     = "disabled"       # no network at all inside the sandbox


@dataclass
class IsolationReport:
    """What containment a single analysis actually ran under.

    Every field is a statement of fact about the run that produced it, not a
    configured intent — a backend that asked for a VM but fell back to the
    host must report the host.
    """
    backend: str                          # inprocess | windows_sandbox | ...
    level: str                            # one of the LEVEL_* constants
    ephemeral: bool                       # is the environment thrown away?
    fresh_per_analysis: bool              # built new for this run?
    discarded_after: bool                 # destroyed when the run finished?
    shares_host_kernel: bool
    shares_host_filesystem: bool
    shares_host_network_identity: bool
    chromium_own_sandbox: bool            # False when --no-sandbox is passed
    network_policy: str = NET_UNRESTRICTED
    detail: str = ""
    warnings: list = field(default_factory=list)

    @property
    def rank(self) -> int:
        return _LEVEL_RANK.get(self.level, 0)

    def as_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["rank"] = self.rank
        return data


class IsolationBackend(abc.ABC):
    """One way of running a dynamic analysis under some containment.

    A backend is responsible for producing the same observation payload the
    in-process runner produces (`executed`, `score`, `signals`,
    `network_requests`, `page_signals`, `detail`, `error`) plus an
    `IsolationReport` describing where that observation happened.
    """

    #: short stable identifier used in settings and in the result payload
    name: str = "base"

    @classmethod
    @abc.abstractmethod
    def is_available(cls) -> tuple[bool, str]:
        """(available, human-readable reason). Never raises."""

    @abc.abstractmethod
    def describe(self) -> IsolationReport:
        """The isolation this backend provides, before it runs."""

    @abc.abstractmethod
    async def run(self, extension_path: str, timeout_seconds: int) -> Dict[str, Any]:
        """Analyse the unpacked extension and return the observation payload."""


def unavailable_result(reason: str, report: Optional[IsolationReport] = None) -> Dict[str, Any]:
    """A well-formed 'did not run' payload, so callers never special-case None."""
    return {
        "executed": False,
        "score": 0,
        "signals": [],
        "network_requests": [],
        "page_signals": [],
        "detail": reason,
        "error": reason,
        "isolation": report.as_dict() if report else None,
    }
