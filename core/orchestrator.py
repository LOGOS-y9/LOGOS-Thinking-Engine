"""
core/orchestrator.py

Law VI / Law XXI (Vacuum Orchestrator): this file is only allowed to do
wiring -- create the event bus, create the governance client, register
engines as subscribers. It must never contain reasoning logic itself, and
it must never touch a protected file directly; any protected action goes
through self.governance, which is just a thin socket client (see
governance_client.py). This is the fix for the old bug where orchestrator.py
never even imported governance at all.
"""
import os
from core.event_bus import EventBus
from core.governance_client import GovernanceClient

LOGOS_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class Orchestrator:
    def __init__(self, event_log_path: str = None, socket_path: str = None):
        event_log_path = event_log_path or os.path.join(LOGOS_ROOT, "memory", "event_log.db")
        socket_path = socket_path or os.path.join(LOGOS_ROOT, "enforcer.sock")

        self.bus = EventBus(event_log_path)
        self.governance = GovernanceClient(socket_path)
        self._engines = {}

    def register_engine(self, name: str, engine) -> None:
        """An engine must expose .subscribe(bus) which wires its own
        handlers onto the bus. The orchestrator never calls engine methods
        directly outside of this registration step -- after this, all
        communication is event-only."""
        self._engines[name] = engine
        engine.subscribe(self.bus)

    def submit(self, event_type: str, payload: dict) -> str:
        """The only way anything enters the system: publish an event. The
        orchestrator does not interpret the payload itself -- that's an
        engine's job, triggered by its own subscription."""
        return self.bus.publish(event_type, payload)

    def request_protected_write(self, rel_path: str, content: str) -> dict:
        """The orchestrator itself has no file-write capability for
        protected paths -- it can only ask the enforcer, same as any
        engine would."""
        return self.governance.write_file(rel_path, content)
