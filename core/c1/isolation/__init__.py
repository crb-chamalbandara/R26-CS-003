"""
C1 — isolation  |  Sandbox containment backends
------------------------------------------------------------------------
Selects where a dynamic analysis actually executes, and makes every run
declare the containment it had.

Backends, strongest first:

    windows_sandbox   disposable Hyper-V VM, destroyed after each analysis
    inprocess         Chromium on the host with a throwaway browser profile

`select_backend()` picks the strongest available unless one is named
explicitly. When a named backend cannot run, it falls back and returns the
reason so the caller can surface it rather than silently downgrading the
isolation an analysis is reported to have had.

Adding a backend: implement `IsolationBackend` (see base.py) and register it
in `_REGISTRY` below. A Docker/Linux-container backend fits here directly —
it would report LEVEL_CONTAINER and could enforce network policy through
`--network`.
"""
from __future__ import annotations

from typing import Dict, List, Tuple, Type

from .base import (                                          # re-exported API
    IsolationBackend, IsolationReport, unavailable_result,
    LEVEL_NONE, LEVEL_BROWSER, LEVEL_CONTAINER, LEVEL_EPHEMERAL_VM,
    NET_UNRESTRICTED, NET_DISABLED,
)
from .inprocess import InProcessBackend
from .windows_sandbox import WindowsSandboxBackend

__all__ = [
    "IsolationBackend", "IsolationReport", "unavailable_result",
    "LEVEL_NONE", "LEVEL_BROWSER", "LEVEL_CONTAINER", "LEVEL_EPHEMERAL_VM",
    "NET_UNRESTRICTED", "NET_DISABLED",
    "InProcessBackend", "WindowsSandboxBackend",
    "select_backend", "available_backends", "backend_status",
]

# Strongest first — auto-selection walks this order.
_REGISTRY: List[Type[IsolationBackend]] = [
    WindowsSandboxBackend,
    InProcessBackend,
]

_BY_NAME: Dict[str, Type[IsolationBackend]] = {b.name: b for b in _REGISTRY}


def backend_status() -> List[Dict]:
    """Every known backend with its availability and the reason, for the UI."""
    status = []
    for cls in _REGISTRY:
        ok, reason = cls.is_available()
        status.append({
            "name": cls.name,
            "available": ok,
            "reason": reason,
            "level": cls().describe().level,
        })
    return status


def available_backends() -> List[str]:
    return [cls.name for cls in _REGISTRY if cls.is_available()[0]]


def select_backend(preferred: str = "",
                   network_policy: str = "") -> Tuple[IsolationBackend, str]:
    """Choose the backend for one analysis.

    Returns (backend, note). `note` is empty on a clean selection, and
    otherwise explains why the requested isolation was not used — the caller
    attaches it to the run's warnings so a downgrade is never silent.
    """
    policy = network_policy or NET_UNRESTRICTED
    preferred = (preferred or "").strip().lower()

    if preferred:
        cls = _BY_NAME.get(preferred)
        if cls is None:
            known = ", ".join(_BY_NAME)
            return (InProcessBackend(policy),
                    f"Unknown isolation backend {preferred!r} (known: {known}); "
                    f"fell back to in-process execution on the host.")
        ok, reason = cls.is_available()
        if ok:
            return cls(policy), ""
        return (InProcessBackend(policy),
                f"Requested isolation backend {preferred!r} is unavailable "
                f"({reason}); fell back to in-process execution on the host.")

    for cls in _REGISTRY:
        if cls.is_available()[0]:
            return cls(policy), ""

    # InProcessBackend is the last entry and needs only Playwright; if even
    # that is unavailable the run will report the failure itself.
    return InProcessBackend(policy), ""
