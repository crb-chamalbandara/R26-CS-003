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
    def __init__(self) -> None:
        base = Path(os.path.expanduser("~")) / ".websentinel"
        base.mkdir(parents=True, exist_ok=True)
        self._path = base / "c3_alerts.db"
        self._cache: list[dict] = []
        self._init_db()
        self._load_cache()

    @property
    def path(self) -> str:
        return str(self._path)

    def add_alert(self, alert: dict) -> dict:
        timestamp = alert.get("timestamp") or datetime.now().isoformat()
        row = {
            "host": str(alert.get("host") or ""),
            "score": float(alert.get("score") or 0.0),
            "verdict": str(alert.get("verdict") or "BEACON"),
            "detail": str(alert.get("detail") or ""),
            "features": dict(alert.get("features") or {}),
            "signal_breakdown": dict(alert.get("signal_breakdown") or {}),
            "timestamp": timestamp,
        }
        with sqlite3.connect(self._path) as conn:
            cur = conn.execute(
                """
                INSERT INTO c3_alerts(host, score, verdict, detail, features_json, signals_json, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["host"],
                    row["score"],
                    row["verdict"],
                    row["detail"],
                    json.dumps(row["features"], sort_keys=True),
                    json.dumps(row["signal_breakdown"], sort_keys=True),
                    row["timestamp"],
                ),
            )
            row["id"] = int(cur.lastrowid)
        self._cache.insert(0, row)
        self._cache = self._cache[:100]
        return row

    def list_alerts(self, limit: int = 50) -> list[dict]:
        return self._cache[:limit]

    def count(self) -> int:
        with sqlite3.connect(self._path) as conn:
            return int(conn.execute("SELECT COUNT(*) FROM c3_alerts").fetchone()[0])

    def _init_db(self) -> None:
        with sqlite3.connect(self._path) as conn:
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
                    timestamp TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_c3_alerts_ts ON c3_alerts(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_c3_alerts_host ON c3_alerts(host)")
            columns = {row[1] for row in conn.execute("PRAGMA table_info(c3_alerts)").fetchall()}
            if "signals_json" not in columns:
                conn.execute("ALTER TABLE c3_alerts ADD COLUMN signals_json TEXT NOT NULL DEFAULT '{}' ")

    def _load_cache(self) -> None:
        with sqlite3.connect(self._path) as conn:
            rows = conn.execute(
                """
                SELECT id, host, score, verdict, detail, features_json, signals_json, timestamp
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
                "timestamp": row[7],
            }
            for row in rows
        ]


c3_alert_store = C3AlertStore()
