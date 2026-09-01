"""
C3 blocked-host persistence.

Why this file exists: C3Interceptor's block_host()/unblock_host() only ever
tracked blocked hosts in two in-memory dicts (_blocked_hosts/_blocked_routes),
tied to live Playwright route registrations on the current browser context.
That meant a block silently stopped working the moment the backend or the
Playwright session restarted -- which happens often during normal use -- with
no record left anywhere that a host had ever been blocked, and no time-based
expiry at all (a block lasted until manually undone or until a restart wiped
it, whichever happened first, entirely by accident either way).

This store gives each block a real, disk-persisted record with a 24-hour
expiry, so C3Interceptor can (a) reapply every still-active block when a new
session starts, and (b) automatically unblock a host once 24 hours have
passed -- both real, previously-missing pieces of behavior, not cosmetic.

Same SQLite-in-home-directory pattern as alert_store.py, deliberately kept in
its own database file (not a new table bolted onto alert_store.py) so this
addition cannot interact with or risk the existing alerts schema.
"""
from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

# How long a block lasts before it is automatically lifted. 24 hours, per the
# explicit requirement: a blocked host and this machine must not communicate
# for 24 hours, then it unblocks itself.
BLOCK_DURATION_HOURS = 24.0


class C3BlockStore:
    def __init__(self, db_path: str | Path | None = None) -> None:
        if db_path is not None:
            self._path = Path(db_path)
            self._path.parent.mkdir(parents=True, exist_ok=True)
        else:
            base = Path(os.path.expanduser("~")) / ".websentinel"
            base.mkdir(parents=True, exist_ok=True)
            self._path = base / "c3_blocks.db"
        self._init_db()

    @property
    def path(self) -> str:
        return str(self._path)

    def add_block(self, host: str, reason: str = "", score: float = 0.0) -> dict:
        """Persist a block, refreshing its 24h expiry from now. Upsert -- a
        host that is blocked again (e.g. a repeat manual click, or auto-block
        firing again on a still-active beacon) simply extends the window
        rather than erroring or duplicating rows."""
        host = self._clean_host(host)
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=BLOCK_DURATION_HOURS)
        row = {
            "host": host,
            "blocked_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "reason": reason,
            "score": float(score),
        }
        with sqlite3.connect(self._path) as conn:
            conn.execute(
                """
                INSERT INTO c3_blocked_hosts(host, blocked_at, expires_at, reason, score)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(host) DO UPDATE SET
                    blocked_at = excluded.blocked_at,
                    expires_at = excluded.expires_at,
                    reason = excluded.reason,
                    score = excluded.score
                """,
                (row["host"], row["blocked_at"], row["expires_at"], row["reason"], row["score"]),
            )
        return row

    def remove_block(self, host: str) -> None:
        host = self._clean_host(host)
        with sqlite3.connect(self._path) as conn:
            conn.execute("DELETE FROM c3_blocked_hosts WHERE host = ?", (host,))

    def is_blocked(self, host: str) -> bool:
        host = self._clean_host(host)
        now_iso = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self._path) as conn:
            row = conn.execute(
                "SELECT 1 FROM c3_blocked_hosts WHERE host = ? AND expires_at > ?",
                (host, now_iso),
            ).fetchone()
        return row is not None

    def list_active(self) -> list[dict]:
        """Blocks whose 24h window has not yet expired -- reapplied on startup."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self._path) as conn:
            rows = conn.execute(
                "SELECT host, blocked_at, expires_at, reason, score FROM c3_blocked_hosts "
                "WHERE expires_at > ? ORDER BY blocked_at DESC",
                (now_iso,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def list_expired(self) -> list[dict]:
        """Blocks whose 24h window has passed but the row has not been
        cleaned up yet -- polled by the analyzer loop to auto-unblock."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self._path) as conn:
            rows = conn.execute(
                "SELECT host, blocked_at, expires_at, reason, score FROM c3_blocked_hosts "
                "WHERE expires_at <= ?",
                (now_iso,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def _init_db(self) -> None:
        with sqlite3.connect(self._path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS c3_blocked_hosts (
                    host TEXT PRIMARY KEY,
                    blocked_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    reason TEXT NOT NULL DEFAULT '',
                    score REAL NOT NULL DEFAULT 0.0
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_c3_blocks_expires ON c3_blocked_hosts(expires_at)")

    @staticmethod
    def _row_to_dict(row) -> dict:
        return {"host": row[0], "blocked_at": row[1], "expires_at": row[2],
                "reason": row[3], "score": row[4]}

    @staticmethod
    def _clean_host(host: str) -> str:
        return str(host or "").lower().strip("[]")


c3_block_store = C3BlockStore()


# =============================================================================
# WHAT THIS FILE DOES — plain English summary
# =============================================================================
#
# This file remembers which hosts C3 has blocked, on disk, so the block
# survives an app restart -- and remembers WHEN each block should expire, so
# a blocked host is automatically un-blocked 24 hours after it was blocked
# rather than staying blocked forever or silently losing its block on the
# next restart (both of which were previously possible, since blocks used to
# live only in memory with no expiry at all).
#
# core/c3/interceptor.py calls add_block()/remove_block() whenever it blocks
# or unblocks a host, list_active() once at startup to reapply every block
# that has not yet expired, and list_expired() once per analyzer cycle to
# find hosts whose 24-hour window has passed so they can be automatically
# unblocked.
# =============================================================================
