"""
C2 alert persistence.

C2 alerts used to live only in the `alerts` list in core/main.py — capped at 500
and gone on restart, so there was no individual alert to open, cite or export
after the fact. This mirrors core/c3/alert_store.py so both detectors persist the
same way: SQLite under ~/.websentinel/, an in-memory cache of the most recent
records for instant dashboard load, and JSON columns for the nested structures.

What is stored per alert, beyond the verdict and score:
  - `layers`  — each layer's row *including* its `evidence` dict (the feature
                vectors, matched hosts and feed verdicts each layer measured).
  - `fusion`  — how the risk score was reached: meta-classifier vs weighted sum,
                the weights applied, and whether the L1 heuristic floor raised it.

Deliberately NOT stored: page HTML and screenshots. The feature vectors are the
evidence; the raw DOM of a credential-harvesting page is not something to keep on
disk, and it would take records from a few KB to hundreds.
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

# How many recent alerts to hold in memory for instant reads.
_CACHE_SIZE = 100


class C2AlertStore:
    def __init__(self, db_path: str | Path | None = None) -> None:
        # Store the database inside ~/.websentinel/ so it survives reboots.
        # db_path lets tests point at a temp file instead of the real one.
        if db_path is not None:
            self._path = Path(db_path)
            self._path.parent.mkdir(parents=True, exist_ok=True)
        else:
            base = Path(os.path.expanduser("~")) / ".websentinel"
            base.mkdir(parents=True, exist_ok=True)
            self._path = base / "c2_alerts.db"
        self._cache: list[dict] = []
        self._init_db()
        self._load_cache()

    @property
    def path(self) -> str:
        return str(self._path)

    # ── Write ────────────────────────────────────────────────────────────────
    def add_alert(self, alert: dict) -> dict:
        """Persist one C2 analysis. Returns the stored row (including its new id)."""
        timestamp = alert.get("timestamp") or datetime.now().isoformat()
        row = {
            "url":        str(alert.get("url") or ""),
            "verdict":    str(alert.get("verdict") or "SAFE"),
            "risk_score": float(alert.get("risk_score") or 0.0),
            "layers":     list(alert.get("layers") or []),
            "fusion":     dict(alert.get("fusion") or {}),
            "verified":   bool(alert.get("verified", False)),
            "timestamp":  timestamp,
        }
        with sqlite3.connect(self._path) as conn:
            cur = conn.execute(
                """
                INSERT INTO c2_alerts(url, verdict, risk_score, layers_json,
                                      fusion_json, verified, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["url"],
                    row["verdict"],
                    row["risk_score"],
                    json.dumps(row["layers"], sort_keys=True, default=str),
                    json.dumps(row["fusion"], sort_keys=True, default=str),
                    1 if row["verified"] else 0,
                    row["timestamp"],
                ),
            )
            row["id"] = cur.lastrowid

        self._cache.insert(0, row)
        del self._cache[_CACHE_SIZE:]
        return row

    # ── Read ─────────────────────────────────────────────────────────────────
    def list_alerts(self, limit: int = 50, verdict: str = "",
                    since: str = "") -> list[dict]:
        """Most recent first. Served from the cache only when no filter is applied
        and the window fits — a filtered query must see the whole table, not just
        the last 100 rows."""
        if not verdict and not since and limit <= len(self._cache):
            return self._cache[:limit]

        sql = ("SELECT id, url, verdict, risk_score, layers_json, fusion_json, "
               "verified, timestamp FROM c2_alerts")
        clauses, params = [], []
        if verdict:
            clauses.append("verdict = ?")
            params.append(verdict.upper())
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(int(limit))

        with sqlite3.connect(self._path) as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._to_dict(r) for r in rows]

    def get_alert(self, alert_id: int) -> Optional[dict]:
        """One full alert by id, or None. This is the individual-alert handle the
        dashboard's detail modal and the report endpoints resolve."""
        with sqlite3.connect(self._path) as conn:
            row = conn.execute(
                """
                SELECT id, url, verdict, risk_score, layers_json, fusion_json,
                       verified, timestamp
                FROM c2_alerts WHERE id = ?
                """,
                (int(alert_id),),
            ).fetchone()
        return self._to_dict(row) if row else None

    def count(self) -> int:
        with sqlite3.connect(self._path) as conn:
            return int(conn.execute("SELECT COUNT(*) FROM c2_alerts").fetchone()[0])

    # ── Maintenance ──────────────────────────────────────────────────────────
    def purge_older_than(self, days: int) -> int:
        """Delete alerts older than `days`; returns the number removed. Nothing
        calls this on a schedule yet — it exists so retention is available before
        the table becomes large enough to need it."""
        cutoff = (datetime.now() - timedelta(days=int(days))).isoformat()
        with sqlite3.connect(self._path) as conn:
            cur = conn.execute("DELETE FROM c2_alerts WHERE timestamp < ?", (cutoff,))
            removed = cur.rowcount or 0
        if removed:
            self._load_cache()
        return removed

    # ── Internals ────────────────────────────────────────────────────────────
    @staticmethod
    def _to_dict(row) -> dict:
        def _load(raw, fallback):
            try:
                return json.loads(raw) if raw else fallback
            except Exception:
                return fallback

        return {
            "id":         row[0],
            "url":        row[1],
            "verdict":    row[2],
            "risk_score": row[3],
            "layers":     _load(row[4], []),
            "fusion":     _load(row[5], {}),
            "verified":   bool(row[6]),
            "timestamp":  row[7],
        }

    def _init_db(self) -> None:
        with sqlite3.connect(self._path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS c2_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    layers_json TEXT NOT NULL DEFAULT '[]',
                    fusion_json TEXT NOT NULL DEFAULT '{}',
                    verified INTEGER NOT NULL DEFAULT 0,
                    timestamp TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_c2_alerts_ts ON c2_alerts(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_c2_alerts_url ON c2_alerts(url)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_c2_alerts_verdict ON c2_alerts(verdict)")
            # Migration guard: add columns if an older DB is being reused.
            columns = {r[1] for r in conn.execute("PRAGMA table_info(c2_alerts)").fetchall()}
            if "fusion_json" not in columns:
                conn.execute("ALTER TABLE c2_alerts ADD COLUMN fusion_json TEXT NOT NULL DEFAULT '{}' ")
            if "verified" not in columns:
                conn.execute("ALTER TABLE c2_alerts ADD COLUMN verified INTEGER NOT NULL DEFAULT 0 ")

    def _load_cache(self) -> None:
        with sqlite3.connect(self._path) as conn:
            rows = conn.execute(
                """
                SELECT id, url, verdict, risk_score, layers_json, fusion_json,
                       verified, timestamp
                FROM c2_alerts ORDER BY id DESC LIMIT ?
                """,
                (_CACHE_SIZE,),
            ).fetchall()
        self._cache = [self._to_dict(r) for r in rows]


# Module-level singleton, matching how core/main.py imports c3_alert_store.
c2_alert_store = C2AlertStore()
