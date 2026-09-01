"""
C3 alert persistence.
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path


class C3AlertStore:
    def __init__(self, db_path: str | Path | None = None) -> None:
        # Store the database inside ~/.websentinel/ so it survives reboots.
        # db_path lets tests point at a temp file instead of the real one.
        if db_path is not None:
            self._path = Path(db_path)
            self._path.parent.mkdir(parents=True, exist_ok=True)
        else:
            base = Path(os.path.expanduser("~")) / ".websentinel"
            base.mkdir(parents=True, exist_ok=True)
            self._path = base / "c3_alerts.db"
        # In-memory cache of the last 100 alerts so the dashboard loads instantly.
        self._cache: list[dict] = []
        self._init_db()     # create the table if this is the first run
        self._load_cache()  # pre-load the most recent alerts into memory

    @property
    def path(self) -> str:
        return str(self._path)

    def add_alert(self, alert: dict) -> dict:
        # Build a clean row from whatever the analyzer passed in.
        timestamp = alert.get("timestamp") or datetime.now().isoformat()
        row = {
            "host": str(alert.get("host") or ""),
            "score": float(alert.get("score") or 0.0),
            "verdict": str(alert.get("verdict") or "BEACON"),
            "detail": str(alert.get("detail") or ""),
            "features": dict(alert.get("features") or {}),
            "signal_breakdown": dict(alert.get("signal_breakdown") or {}),
            # Human-readable per-signal explanation (e.g. "RF prob=0.42
            # threshold=0.50 [human]") -- the analyzer always computes this
            # (see result["signal_detail"] in analyzer.py), but it was
            # previously dropped here, so every persisted alert permanently
            # lost it even though the dashboard's alert card renders it
            # (c3SignalBarsDetailed reads a.signal_detail).
            "signal_detail": dict(alert.get("signal_detail") or {}),
            "timestamp": timestamp,
        }
        # Write to SQLite — this survives a process restart.
        with sqlite3.connect(self._path) as conn:
            cur = conn.execute(
                """
                INSERT INTO c3_alerts(host, score, verdict, detail, features_json, signals_json, signal_detail_json, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["host"],
                    row["score"],
                    row["verdict"],
                    row["detail"],
                    json.dumps(row["features"], sort_keys=True),
                    json.dumps(row["signal_breakdown"], sort_keys=True),
                    json.dumps(row["signal_detail"], sort_keys=True),
                    row["timestamp"],
                ),
            )
            row["id"] = int(cur.lastrowid)
        # Also push to the front of the in-memory cache so reads are instant.
        self._cache.insert(0, row)
        # Keep the cache bounded to avoid unbounded memory growth.
        self._cache = self._cache[:100]
        return row

    def list_alerts(self, limit: int = 50) -> list[dict]:
        # Serve from in-memory cache — no disk read required on every poll.
        return self._cache[:limit]

    def count(self) -> int:
        with sqlite3.connect(self._path) as conn:
            return int(conn.execute("SELECT COUNT(*) FROM c3_alerts").fetchone()[0])

    def _init_db(self) -> None:
        with sqlite3.connect(self._path) as conn:
            # Create the alerts table if it does not exist yet.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS c3_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host TEXT NOT NULL,
                    score REAL NOT NULL,
                    verdict TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    features_json TEXT NOT NULL,
                    signals_json TEXT NOT NULL DEFAULT '{}',
                    signal_detail_json TEXT NOT NULL DEFAULT '{}',
                    timestamp TEXT NOT NULL
                )
                """
            )
            # Indexes make lookups by time or host much faster.
            conn.execute("CREATE INDEX IF NOT EXISTS idx_c3_alerts_ts ON c3_alerts(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_c3_alerts_host ON c3_alerts(host)")
            # Migration guard: add columns if an older DB is being reused.
            columns = {row[1] for row in conn.execute("PRAGMA table_info(c3_alerts)").fetchall()}
            if "signals_json" not in columns:
                conn.execute("ALTER TABLE c3_alerts ADD COLUMN signals_json TEXT NOT NULL DEFAULT '{}' ")
            if "signal_detail_json" not in columns:
                conn.execute("ALTER TABLE c3_alerts ADD COLUMN signal_detail_json TEXT NOT NULL DEFAULT '{}' ")

    def _load_cache(self) -> None:
        # Read the 100 most recent alerts from disk into memory at startup.
        with sqlite3.connect(self._path) as conn:
            rows = conn.execute(
                """
                SELECT id, host, score, verdict, detail, features_json, signals_json, signal_detail_json, timestamp
                FROM c3_alerts
                ORDER BY id DESC
                LIMIT 100
                """
            ).fetchall()
        self._cache = [
            {
                "id": row[0],
                "host": row[1],
                "score": row[2],
                "verdict": row[3],
                "detail": row[4],
                "features": json.loads(row[5] or "{}"),
                "signal_breakdown": json.loads(row[6] or "{}"),
                "signal_detail": json.loads(row[7] or "{}"),
                "timestamp": row[8],
            }
            for row in rows
        ]


c3_alert_store = C3AlertStore()


# =============================================================================
# WHAT THIS FILE DOES — plain English summary
# =============================================================================
#
# This file is the "memory" of C3.  Once a BEACON verdict is confirmed by the
# analyzer, this store makes sure the alert is never lost — even if the app
# is restarted, the browser is closed, or the computer reboots.
#
# How it works:
#
#   1. When the analyzer confirms a BEACON, it calls add_alert() with all the
#      details: which host, what score, which features triggered it, and a
#      human-readable explanation.
#
#   2. add_alert() writes a permanent record to a small SQLite database file
#      stored in your home folder (~/.websentinel/c3_alerts.db).  SQLite is a
#      lightweight database — it is a single file on disk, no server needed.
#
#   3. At the same time, the alert is placed at the front of an in-memory list
#      (the "cache").  The dashboard reads from this in-memory list so it can
#      show you the latest alerts instantly, without hitting the database on
#      every page refresh.
#
#   4. The cache holds at most 100 alerts at a time to keep memory usage small.
#      The database on disk holds every alert ever recorded.
#
# Why SQLite?
#   The detector may run for days or weeks.  Keeping every alert only in memory
#   would lose them all on the next restart.  SQLite gives persistent storage
#   with almost no setup complexity.
#
# The dashboard uses list_alerts() to show the Alerts tab, and count() to
# display the total alert count in the status panel.
# =============================================================================
