"""
C1 — SQLite persistence layer.
Database: ~/.websentinel/c1_analyses.db
All analysis results are saved here so history survives server restarts.
"""
from __future__ import annotations

import json
import os
import sqlite3
from typing import Dict, List

_DB_PATH = os.path.join(os.path.expanduser("~"), ".websentinel", "c1_analyses.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS c1_analyses (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    ext_id           TEXT    DEFAULT '',
    timestamp        TEXT    NOT NULL,
    source           TEXT    DEFAULT '',
    verdict          TEXT    NOT NULL,
    final_score      REAL    NOT NULL,
    static_score     REAL    DEFAULT 0,
    dynamic_score    REAL    DEFAULT 0,
    ml_prob          REAL    DEFAULT 0,
    hash_match       INTEGER DEFAULT 0,
    sandbox_executed INTEGER DEFAULT 0,
    flags            TEXT    DEFAULT '[]',
    detail           TEXT    DEFAULT '',
    report           TEXT    DEFAULT '{}',
    webstore_url     TEXT    DEFAULT '',
    filename         TEXT    DEFAULT ''
);
"""


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _init() -> None:
    with _connect() as conn:
        conn.execute(_SCHEMA)


def save_result(result: Dict) -> int:
    """Persist one C1 analysis result. Returns the new row id."""
    _init()
    s = result.get("static",  {})
    d = result.get("dynamic", {})
    with _connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO c1_analyses
              (ext_id, timestamp, source, verdict,
               final_score, static_score, dynamic_score,
               ml_prob, hash_match, sandbox_executed,
               flags, detail, report, webstore_url, filename)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                result.get("extension_id", ""),
                result.get("timestamp",    ""),
                result.get("source",       ""),
                result.get("verdict",      ""),
                round(result.get("score", 0) * 100, 2),
                round(s.get("score",    0) * 100, 2),
                round(d.get("score",    0) * 100, 2),
                round(s.get("ml_score", 0),       4),
                int(s.get("hash_match", False)),
                int(d.get("executed",   False)),
                json.dumps(result.get("flags",  [])),
                result.get("detail",       ""),
                json.dumps(result.get("report", {})),
                result.get("webstore_url", ""),
                result.get("filename",     ""),
            ),
        )
        return cur.lastrowid


def get_history(limit: int = 50) -> List[Dict]:
    """Return the most recent `limit` analyses, newest first."""
    _init()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM c1_analyses ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_to_dict(r) for r in rows]


def _to_dict(row: sqlite3.Row) -> Dict:
    d = dict(row)
    for key in ("flags", "report"):
        try:
            d[key] = json.loads(d[key] or ("[]" if key == "flags" else "{}"))
        except Exception:
            d[key] = [] if key == "flags" else {}
    # Normalise scores back to 0-1 range so dashboard JS works the same way
    d["score"]   = round(d["final_score"]   / 100, 4)
    d["static"]  = {
        "score":      round(d["static_score"]  / 100, 4),
        "ml_score":   d["ml_prob"],
        "hash_match": bool(d["hash_match"]),
    }
    d["dynamic"] = {
        "score":    round(d["dynamic_score"] / 100, 4),
        "executed": bool(d["sandbox_executed"]),
        "signals":  d["report"].get("flags", []) if isinstance(d.get("report"), dict) else [],
    }
    return d
