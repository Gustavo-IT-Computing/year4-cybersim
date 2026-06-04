import sqlite3  # sqlite database library
import json  # used to convert dictionaries into strings
from pathlib import Path  # helps manage file paths
from typing import Optional  # allows optional types
from sim.events import SimEvent

# this class handles opening/closing the database, creating tables, logging simulation events, storing threat intelligence results and retrieving recent threat history
class DB:

    # creates the DB object and stores file path
    def __init__(self, db_path: str = "cybersim.db") -> None:

        self.path = Path(db_path) # database path

        # connection starts as empty
        self.conn: Optional[sqlite3.Connection] = None

    # connect to SQLite database and prepare tables if they do not exists
    def connect(self) -> None:
        self.conn = sqlite3.connect(self.path.as_posix()) # open connection to db file

        # improves performance for writes
        self.conn.execute("PRAGMA journal_mode=WAL;")

        # create tables
        self._init_schema()

    # create tables and indexes and only run if the tables do not exist
    def _init_schema(self) -> None:
        assert self.conn is not None  # make sure connection exists

        # table for simulation events to store the simulation activity
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                tick INTEGER,
                event_type TEXT,
                source TEXT,
                target TEXT,
                severity INTEGER,
                details TEXT
            );
        """)

        # table for detected threats
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                node_id TEXT,
                indicator TEXT,
                verdict TEXT,
                source TEXT
            );
        """)

        # index to speed up queries by run_id
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id);")

        self.conn.commit()  # save changes

    # store a simulation event as infection spread, node quarantined
    def log_event(self, run_id: str, e: SimEvent) -> None:
        assert self.conn is not None

        # convert details dict into string so it can be stored
        details_str = json.dumps(e.details) if e.details else ""

        # insert events into a database
        self.conn.execute("""
            INSERT INTO events(run_id, tick, event_type, source, target, severity, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            run_id,
            e.tick,
            e.event_type.value,
            e.source,
            e.target,
            e.severity,
            details_str
        ))

    # save changes manually
    def commit(self) -> None:
        if self.conn:
            self.conn.commit()

    # close connection safely
    def close(self) -> None:
        if self.conn:
            self.conn.commit()  # make sure nothing is lost
            self.conn.close()

    # store a detected threat
    def log_threat(
            self,
            run_id: str,
            node_id: str,
            indicator: str,
            verdict: str,
            source: str
    ) -> None:
        assert self.conn is not None

        # remove old entry for same indicator (keep latest only)
        self.conn.execute("""
            DELETE FROM threats WHERE indicator = ?
        """, (indicator,))

        # insert new threat
        self.conn.execute("""
            INSERT INTO threats (run_id, node_id, indicator, verdict, source)
            VALUES (?, ?, ?, ?, ?)
        """, (run_id, node_id, indicator, verdict, source))

        self.conn.commit()

    # get latest threats for a run
    def get_recent_threats(self, run_id: str, limit: int = 6):
        assert self.conn is not None

        cursor = self.conn.execute("""
            SELECT node_id, verdict, source
            FROM threats
            WHERE run_id = ?
            ORDER BY id DESC
            LIMIT ?
        """, (run_id, limit))

        # convert rows into simple dictionaries
        return [
            {
                "node": row[0],
                "verdict": row[1],
                "source": row[2]
            }
            for row in cursor.fetchall()
        ]

    # get last verdict for a specific indicator
    def get_threat(self, indicator):
        assert self.conn is not None
        cursor = self.conn.execute("""
            SELECT verdict FROM threats WHERE indicator = ?
            ORDER BY id DESC LIMIT 1
        """, (indicator,))

        row = cursor.fetchone()

        # threat is found
        if row:
            return {"verdict": row[0]}

        return None