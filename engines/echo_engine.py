"""
A minimal real engine, just to prove the pattern end-to-end before we build
the real reasoning engines on top of it. It talks to NOTHING except the bus
it's given in subscribe(). It has no reference to the orchestrator, no
reference to other engines, and no direct governance access of its own --
if it ever needs a protected write, it has to publish an event asking for
one, same as everything else.
"""


class EchoEngine:
    def __init__(self):
        self.received = []

    def subscribe(self, bus):
        bus.subscribe("ping", self._on_ping)

    def _on_ping(self, payload):
        self.received.append(payload)
