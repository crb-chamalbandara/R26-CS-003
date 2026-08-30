"""
C1 — db.py  |  The Persistence Layer
--------------------------------------
Purpose : Save every analysis result permanently to a SQLite database so
          history survives server restarts.
Database: ~/.websentinel/c1_analyses.db
Role    : Called by main.py after every analysis. The /extension/history
          API endpoint reads from here instead of memory.
"""
from __future__ import annotations

import json
import os
import sqlite3
from typing import Dict, List

# Full path to the SQLite database file — stored in the user's home directory
_DB_PATH = os.path.join(os.path.expanduser("~"), ".websentinel", "c1_analyses.db")

# SQL to create the table if it does not already exist — runs on every startup
_SCHEMA = """
CREATE TABLE IF NOT EXISTS c1_analyses (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,  -- auto-increment unique ID for each analysis
    ext_id           TEXT    DEFAULT '',     -- 32-char Chrome extension ID
    timestamp        TEXT    NOT NULL,       -- ISO datetime of when analysis ran
    source           TEXT    DEFAULT '',     -- how the extension was submitted: upload/webstore/live
    verdict          TEXT    NOT NULL,       -- SAFE, SUSPICIOUS, or MALICIOUS
    final_score      REAL    NOT NULL,       -- fused final score (0–100)
    static_score     REAL    DEFAULT 0,      -- XGBoost static analysis score (0–100)
    dynamic_score    REAL    DEFAULT 0,      -- sandbox dynamic score (0–100), 0 if not run
    ml_prob          REAL    DEFAULT 0,      -- raw XGBoost probability (0.0–1.0)
    hash_match       INTEGER DEFAULT 0,      -- 1 if ID was found in malicious blocklist
    sandbox_executed INTEGER DEFAULT 0,      -- 1 if dynamic sandbox actually ran
    flags            TEXT    DEFAULT '[]',   -- JSON array of detected flag codes
    detail           TEXT    DEFAULT '',     -- one-line human-readable score breakdown
    report           TEXT    DEFAULT '{}',   -- full structured report JSON (from report.py)
    webstore_url     TEXT    DEFAULT '',     -- Chrome Web Store URL if available
    filename         TEXT    DEFAULT ''      -- uploaded filename if submitted via file upload
);
"""


def _connect() -> sqlite3.Connection:
    """Open a connection to the SQLite database, creating the directory if needed."""
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)   # create ~/.websentinel/ if it doesn't exist
    conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row    # makes rows behave like dicts (access by column name)
    return conn


def _init() -> None:
    """Create the database table if it doesn't exist yet — called before every operation."""
    with _connect() as conn:
        conn.execute(_SCHEMA)


def save_result(result: Dict) -> int:
    """Persist one C1 analysis result to the database. Returns the new row's ID.
    Scores are stored as 0–100 (multiplied from the 0–1 scale used by analyzer.py)."""
    _init()
    s = result.get("static",  {})    # static analysis sub-dict
    d = result.get("dynamic", {})    # dynamic sandbox sub-dict
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
                round(result.get("score", 0) * 100, 2),    # convert 0–1 → 0–100 for readability
                round(s.get("score",    0) * 100, 2),
                round(d.get("score",    0) * 100, 2),
                round(s.get("ml_score", 0),       4),      # raw ML probability kept at full precision
                int(s.get("hash_match", False)),            # convert bool to 0/1 for SQLite
                int(d.get("executed",   False)),
                json.dumps(result.get("flags",  [])),       # list → JSON string for storage
                result.get("detail",       ""),
                json.dumps(result.get("report", {})),       # report dict → JSON string
                result.get("webstore_url", ""),
                result.get("filename",     ""),
            ),
        )
        return cur.lastrowid    # return the auto-assigned row ID


def get_history(limit: int = 50) -> List[Dict]:
    """Return the most recent `limit` analyses from the database, newest first.
    The dashboard calls this to populate the history list."""
    _init()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM c1_analyses ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_to_dict(r) for r in rows]    # convert each SQLite Row object to a plain Python dict


def _to_dict(row: sqlite3.Row) -> Dict:
    """Convert a raw database row back into the same dict format analyzer.py returns.
    JSON strings are parsed back to Python lists/dicts, and scores are converted back to 0–1."""
    d = dict(row)
    for key in ("flags", "report"):
        try:
            d[key] = json.loads(d[key] or ("[]" if key == "flags" else "{}"))  # parse stored JSON strings
        except Exception:
            d[key] = [] if key == "flags" else {}
    # Re-normalise scores to 0–1 range so the dashboard JavaScript reads them consistently
    report = d["report"] if isinstance(d.get("report"), dict) else {}
    d["score"]        = round(d["final_score"] / 100, 4)
    d["score_source"] = report.get("score_source", "")
    d["static"]  = {
        "score":      round(d["static_score"]  / 100, 4),
        "ml_score":   d["ml_prob"],
        "hash_match": bool(d["hash_match"]),
        # The report carries the blocklist evidence (name, reason, derivation
        # rationale, which fields were completed live). Restoring it here is
        # what lets the Blocklist Match panel render for a history entry the
        # same way it rendered when the analysis first ran.
        "blocklist_details": report.get("blocklist_details"),
    }
    # Only set when the models actually ran. Its absence is what tells the
    # dashboard a blocklist hit short-circuited, so it must not be defaulted.
    measured = (report.get("score_breakdown") or {}).get("measured_static")
    if measured is not None:
        d["static"]["measured_static_score"] = round(measured / 100, 4)
    d["dynamic"] = {
        "score":    round(d["dynamic_score"] / 100, 4),
        "executed": bool(d["sandbox_executed"]),
        # report["flags"] holds explained flag objects ({flag, severity,
        # description}), not the bare signal strings the dashboard renders —
        # take the names back out or every chip reads "[object Object]".
        "signals":  [f.get("flag", "") for f in report.get("flags", [])
                     if isinstance(f, dict)],
        # Without this a history entry shows a dynamic score with no record of
        # what contained the run, which is the thing the isolation layer exists
        # to prevent.
        "isolation": report.get("isolation"),
        # Per-host rollup the report's network view is drawn from. Same reason
        # as isolation above: the raw observation is long gone by the time a
        # history row is read, so the stored summary is the only copy.
        "observed":  report.get("observed") or {},
    }
    # Identity and declared permissions are properties of the extension, not of
    # the run, so a reopened analysis must show exactly what it showed live.
    d["identity"]    = report.get("identity") or {}
    d["permissions"] = report.get("permissions") or []
    return d
