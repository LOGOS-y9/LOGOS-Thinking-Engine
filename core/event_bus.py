"""
core/event_bus.py

Law IV (Global Workspace) + Law VI (Vacuum Orchestrator): every engine talks
to every other engine ONLY by publishing/subscribing to events here. No
engine ever imports or calls another engine directly. If that rule holds,
there is literally only one road between components -- which is what makes
governance (enforcer.py) sit on that road meaningfully instead of being a
function someone could just not call.

Law XV (Deterministic Replay) fix, built in from the start: every event --
including stochastic ones, like an LLM output -- is written to an
append-only log the moment it's published, BEFORE being delivered to any
subscriber. "Replay" never re-runs the stochastic step. It re-plays the
logged value through the same deterministic subscriber code. That's what
actually makes replay reproducible: the unpredictable part is frozen as
data, the program logic around it stays ordinary deterministic code.
"""
import os
import sqlite3
import json
import time
import uuid
from collections import defaultdict
from typing import Callable, Dict, Any, List


class EventBus:
    def __init__(self, log_path: str):
        self.log_path = log_path
        self._subscribers: Dict[str, List[Callable]] = defaultdict(list)
        self._init_log()

    def _init_log(self):
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        with sqlite3.connect(self.log_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS event_log (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
            """)
            conn.commit()

    def subscribe(self, event_type: str, handler: Callable[[Dict[str, Any]], None]):
        self._subscribers[event_type].append(handler)

    def publish(self, event_type: str, payload: Dict[str, Any]) -> str:
        """Log first, deliver second. The log write is what makes this
        event replayable later -- delivery order to subscribers never
        affects what gets replayed, only the log does."""
        event_id = str(uuid.uuid4())
        record = {
            "event_id": event_id,
            "event_type": event_type,
            "payload_json": json.dumps(payload, sort_keys=True),
            "created_at": time.time(),
        }
        with sqlite3.connect(self.log_path) as conn:
            conn.execute(
                "INSERT INTO event_log (event_id, event_type, payload_json, created_at) VALUES (?,?,?,?)",
                (record["event_id"], record["event_type"], record["payload_json"], record["created_at"]),
            )
            conn.commit()

        for handler in self._subscribers.get(event_type, []):
            handler(payload)

        return event_id

    def read_log(self) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.log_path) as conn:
            rows = conn.execute(
                "SELECT event_id, event_type, payload_json, created_at FROM event_log ORDER BY seq ASC"
            ).fetchall()
        return [
            {"event_id": r[0], "event_type": r[1], "payload": json.loads(r[2]), "created_at": r[3]}
            for r in rows
        ]

    def replay(self, handlers_by_type: Dict[str, List[Callable]] = None) -> List[Dict[str, Any]]:
        """Re-deliver every logged event, in original order, to a FRESH set
        of handlers (or the currently subscribed ones). Nothing is
        recomputed -- every payload comes straight from the log, so a
        stochastic value recorded once replays identically forever."""
        handlers_by_type = handlers_by_type or self._subscribers
        delivered = []
        for event in self.read_log():
            for handler in handlers_by_type.get(event["event_type"], []):
                handler(event["payload"])
            delivered.append(event)
        return delivered
