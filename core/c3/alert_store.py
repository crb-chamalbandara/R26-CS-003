"""
C3 alert store.

Keeps confirmed BEACON alerts, and the analyst's verdict on them, in SQLite at
~/.websentinel/c3_alerts.db, with the most recent 100 mirrored in memory so the
dashboard can read them without touching disk. Written by analyzer.py at the end
of the pipeline; read by the dashboard's Alerts tab.

A plain-English walkthrough is at the bottom of this file.
"""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
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

    @contextmanager
    def _connect(self):
        # sqlite3's own "with conn:" commits (or rolls back) but does not close
        # the connection, so each call used to leave it open until garbage
        # collection (Python 3.13 reports that as a ResourceWarning). This
        # commits or rolls back exactly as before, then closes.
        conn = sqlite3.connect(self._path)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

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
            # Analyst feedback (Step 8). Starts empty on every new alert -- it
            # is set later, by a human, via set_feedback().
            "analyst_verdict": None,
            "analyst_note": "",
            "analyst_ts": None,
        }
        # Write to SQLite -- this survives a process restart.
        with self._connect() as conn:
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
        # Serve from in-memory cache -- no disk read required on every poll.
        return self._cache[:limit]

    # ------------------------------------------------------------------
    # Analyst feedback loop (the 2026-09-11 hardening pass, step 8)
    # ------------------------------------------------------------------
    # Section 3.7 identified that nothing anywhere records whether a verdict
    # was right. Without that, every false-positive measurement (Step 7) has to
    # be redone by hand, and post-deployment model drift is invisible.
    #
    # This is deliberately the smallest useful version: one label, one optional
    # note, one timestamp. No workflow, no review queue, no scoring effect --
    # the feedback is EVIDENCE, not an input to detection. Letting an analyst
    # label feed back into scoring automatically would be a retraining loop
    # with no held-out set, which is how a detector quietly learns its
    # operator's habits instead of the attacker's.
    VALID_FEEDBACK = ("correct", "false_positive")

    def set_feedback(self, alert_id: int, verdict: str, note: str = "") -> dict:
        """Record an analyst's judgement on one alert. Returns the updated row."""
        verdict = str(verdict or "").strip().lower()
        if verdict not in self.VALID_FEEDBACK:
            raise ValueError(
                f"analyst verdict must be one of {self.VALID_FEEDBACK}, got {verdict!r}"
            )
        alert_id = int(alert_id)
        stamped = datetime.now().isoformat()
        note = str(note or "")[:2000]
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE c3_alerts SET analyst_verdict=?, analyst_note=?, analyst_ts=? "
                "WHERE id=?",
                (verdict, note, stamped, alert_id),
            )
            if cur.rowcount == 0:
                raise KeyError(f"no alert with id {alert_id}")
        # Keep the hot cache in step so the dashboard reflects the click
        # immediately rather than after the next restart.
        for row in self._cache:
            if int(row.get("id") or -1) == alert_id:
                row["analyst_verdict"] = verdict
                row["analyst_note"] = note
                row["analyst_ts"] = stamped
                return row
        return {"id": alert_id, "analyst_verdict": verdict,
                "analyst_note": note, "analyst_ts": stamped}

    def feedback_stats(self) -> dict:
        """Counts an analyst can act on, plus the measured false-positive rate.

        The rate is over LABELLED alerts only. Unlabelled alerts are reported
        separately and never folded into the denominator -- an unreviewed alert
        is not evidence of correctness, and quietly treating it as one would
        flatter the number.
        """
        with self._connect() as conn:
            total = int(conn.execute("SELECT COUNT(*) FROM c3_alerts").fetchone()[0])
            rows = conn.execute(
                "SELECT analyst_verdict, COUNT(*) FROM c3_alerts "
                "WHERE analyst_verdict IS NOT NULL GROUP BY analyst_verdict"
            ).fetchall()
        counts = {verdict: int(n) for verdict, n in rows}
        correct = counts.get("correct", 0)
        false_positive = counts.get("false_positive", 0)
        labelled = correct + false_positive
        return {
            "total_alerts": total,
            "labelled": labelled,
            "unlabelled": total - labelled,
            "correct": correct,
            "false_positive": false_positive,
            "false_positive_rate": (round(false_positive / labelled, 4)
                                    if labelled else None),
            "note": ("false_positive_rate is over LABELLED alerts only; "
                     "unlabelled alerts are excluded, not assumed correct"),
        }

    def export_feedback(self) -> list[dict]:
        """Every labelled alert, for offline analysis or as training labels.

        This is the beginning of the "labelled fusion-outcome dataset" that
        risk_fusion.py's docstring says does not exist (Section 3.6).
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, host, score, verdict, detail, features_json, "
                "signals_json, timestamp, analyst_verdict, analyst_note, analyst_ts "
                "FROM c3_alerts WHERE analyst_verdict IS NOT NULL ORDER BY id"
            ).fetchall()
        return [{
            "id": r[0], "host": r[1], "score": r[2], "verdict": r[3],
            "detail": r[4], "features": json.loads(r[5] or "{}"),
            "signal_breakdown": json.loads(r[6] or "{}"), "timestamp": r[7],
            "analyst_verdict": r[8], "analyst_note": r[9], "analyst_ts": r[10],
        } for r in rows]

    def count(self) -> int:
        with self._connect() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM c3_alerts").fetchone()[0])

    def _init_db(self) -> None:
        with self._connect() as conn:
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
            # Analyst feedback (Step 8). Nullable on purpose: NULL means "nobody
            # has reviewed this alert", which is genuinely different from an
            # analyst having reviewed it and said it was correct. Defaulting to
            # a value would erase that distinction and inflate every accuracy
            # figure computed from this table.
            if "analyst_verdict" not in columns:
                conn.execute("ALTER TABLE c3_alerts ADD COLUMN analyst_verdict TEXT")
            if "analyst_note" not in columns:
                conn.execute("ALTER TABLE c3_alerts ADD COLUMN analyst_note TEXT NOT NULL DEFAULT '' ")
            if "analyst_ts" not in columns:
                conn.execute("ALTER TABLE c3_alerts ADD COLUMN analyst_ts TEXT")

    def _load_cache(self) -> None:
        # Read the 100 most recent alerts from disk into memory at startup.
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, host, score, verdict, detail, features_json, signals_json,
                       signal_detail_json, timestamp,
                       analyst_verdict, analyst_note, analyst_ts
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
                "analyst_verdict": row[9],
                "analyst_note": row[10] or "",
                "analyst_ts": row[11],
            }
            for row in rows
        ]


c3_alert_store = C3AlertStore()


# =============================================================================
# WHAT THIS FILE DOES -- plain English summary
# =============================================================================
#
# This file is the "memory" of C3.  Once a BEACON verdict is confirmed by the
# analyzer, this store makes sure the alert is never lost -- even if the app
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
#      lightweight database -- it is a single file on disk, no server needed.
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
