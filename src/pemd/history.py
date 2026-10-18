"""Scan history for the monitoring dashboard (FR-12, NFR-05).

Every scan made through the dashboard or ``pemd scan --log`` is appended to a
small SQLite database (default ``data/scan_history.db``, git-ignored). Only
metadata is stored (name, SHA-256, score, route, timings), never file contents.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

DEFAULT_DB = Path("data") / "scan_history.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    file TEXT NOT NULL,
    sha256 TEXT,
    run TEXT,
    model TEXT,
    p_malware REAL,
    route TEXT,
    verdict TEXT,
    static_seconds REAL,
    dynamic_seconds REAL,
    source TEXT,
    error TEXT,
    details TEXT
)
"""


class ScanHistory:
    def __init__(self, db_path: str | Path = DEFAULT_DB):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as con:
            con.execute(_SCHEMA)

    @contextmanager
    def _connect(self):
        """Open, commit and always close (an open handle locks the file on Windows)."""
        con = sqlite3.connect(self.db_path)
        try:
            with con:
                yield con
        finally:
            con.close()

    def add(self, result: dict, run: str | Path | None = None, source: str = "dashboard") -> None:
        dyn = result.get("dynamic") or {}
        row = (
            datetime.now(timezone.utc).isoformat(timespec="seconds"), result.get("file", ""),
            result.get("sha256"), str(run) if run else None, result.get("model"),
            result.get("p_malware"), result.get("route", "rejected" if "error" in result else None),
            result.get("verdict", "rejected" if "error" in result else None),
            result.get("static_seconds"), dyn.get("seconds"), source, result.get("error"),
            json.dumps(result.get("influential_features", [])[:5]),
        )
        with self._connect() as con:
            con.execute(
                "INSERT INTO scans (ts, file, sha256, run, model, p_malware, route, verdict, "
                "static_seconds, dynamic_seconds, source, error, details) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", row)

    def dataframe(self, limit: int | None = None) -> pd.DataFrame:
        q = "SELECT * FROM scans ORDER BY id DESC"
        if limit:
            q += f" LIMIT {int(limit)}"
        with self._connect() as con:
            df = pd.read_sql_query(q, con)
        if not df.empty:
            df["ts"] = pd.to_datetime(df["ts"], utc=True)
        return df

    def stats(self) -> dict:
        df = self.dataframe()
        ok = df[df["error"].isna()] if not df.empty else df
        n = len(ok)
        routes = ok["route"].value_counts().to_dict() if n else {}
        esc = routes.get("escalate", 0)
        return {
            "n_scans": int(len(df)),
            "n_valid": int(n),
            "n_rejected": int(len(df) - n),
            "benign_cleared": int(routes.get("benign", 0)),
            "malware_reported": int(routes.get("malware", 0)),
            "escalated": int(esc),
            "static_resolution_rate": (1 - esc / n) if n else None,
            "mean_static_seconds": float(ok["static_seconds"].mean()) if n else None,
        }

    def clear(self) -> None:
        with self._connect() as con:
            con.execute("DELETE FROM scans")
