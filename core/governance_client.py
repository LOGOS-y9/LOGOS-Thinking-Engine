"""
core/governance_client.py

The ONLY interface engine code should ever use for a protected action. This
file deliberately contains no business logic and no actual file writes --
it just serializes a request, sends it to the enforcer process over a Unix
socket, and returns the enforcer's answer. If engine code imports this and
only this (never raw `open()` on a protected path), the enforcer is the
single choke point by construction.
"""
import socket
import json


class GovernanceClient:
    def __init__(self, socket_path: str, timeout: float = 5.0):
        self.socket_path = socket_path
        self.timeout = timeout

    def _request(self, req: dict) -> dict:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect(self.socket_path)
            s.sendall((json.dumps(req) + "\n").encode("utf-8"))
            buf = b""
            while b"\n" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            line, _, _ = buf.partition(b"\n")
            return json.loads(line.decode("utf-8"))
        except Exception as e:
            return {"allowed": False, "reason": f"ENFORCER_UNREACHABLE: {e}"}
        finally:
            s.close()

    def write_file(self, rel_path: str, content: str) -> dict:
        return self._request({"action": "write_file", "path": rel_path, "content": content})

    def check_resource_budget(self) -> dict:
        return self._request({"action": "check_resource_budget"})

    def check_integrity(self) -> dict:
        return self._request({"action": "check_integrity"})

    def emergency_stop(self, reason: str = "manual") -> dict:
        return self._request({"action": "emergency_stop", "reason": reason})

    def clear_emergency_stop(self) -> dict:
        return self._request({"action": "clear_emergency_stop"})
