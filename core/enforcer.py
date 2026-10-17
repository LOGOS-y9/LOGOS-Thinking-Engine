"""
core/enforcer.py

The Ring-0 fix for the bug found in the old codebase: validate_action() used
to just return yes/no, and the CALLER still performed the actual write --
which means a caller could always just skip the check and write directly,
since nothing stopped it.

This version is a GATEWAY, not a gate. Protected writes don't happen in the
caller's process at all -- they happen HERE, in a separate OS process, and
the only way in is this socket. The caller never gets a file handle to a
protected path; it can only ask this process to write one.

HONEST LIMIT (stated plainly, not buried): this stops *accidental* bypass
through the normal architecture -- forgetting a check, a bug, a prompt-
injected instruction trying to route an unsafe action through normal code.
It does NOT stop a determined attacker who already has arbitrary code
execution inside the same Termux user account, because Termux (without
root) doesn't give us separate OS users or containers -- any process
running as you can, in principle, open() a file directly if someone writes
code that does that instead of going through this client. True prevention
of THAT needs OS-level separation (root + separate Linux users, or a real
container/VM), which isn't available here. What this DOES add against that
case: an integrity check (Law XVI) that hashes every protected file and
raises an alarm if one changes outside this process's own writes -- so a
bypass gets caught, even though it can't always be physically prevented.
"""
import os
import sys
import socket
import json
import time
import hashlib
import resource
import threading
from dataclasses import dataclass, field

LOGOS_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

IMMUTABLE_FILES = {
    "core/enforcer.py",
    "core/orchestrator.py",
    "core/governance_client.py",
    "memory/sqlite_manager.py",
}


@dataclass
class ResourceLimits:
    max_ram_mb: float = 150.0
    max_cpu_sec: float = 20.0
    max_db_size_mb: float = 150.0


class Enforcer:
    def __init__(self, socket_path: str, limits: ResourceLimits = None):
        self.socket_path = socket_path
        self.limits = limits or ResourceLimits()
        self.e_stop_active = False
        self._file_hashes = {}
        self._snapshot_protected_files()

    # ---------- integrity (Law XVI) ----------

    def _hash_file(self, rel_path: str) -> str:
        full = os.path.join(LOGOS_ROOT, rel_path)
        if not os.path.exists(full):
            return ""
        with open(full, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    def _snapshot_protected_files(self):
        for rel_path in IMMUTABLE_FILES:
            self._file_hashes[rel_path] = self._hash_file(rel_path)

    def check_integrity(self) -> dict:
        tampered = []
        for rel_path, known_hash in self._file_hashes.items():
            current = self._hash_file(rel_path)
            if current != known_hash:
                tampered.append(rel_path)
        if tampered:
            self.trigger_emergency_stop(f"INTEGRITY_VIOLATION: {tampered}")
        return {"ok": len(tampered) == 0, "tampered_files": tampered}

    # ---------- resource budget ----------

    def _ram_usage_mb(self) -> float:
        try:
            return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
        except Exception:
            return 0.0

    def _cpu_usage_sec(self) -> float:
        try:
            return resource.getrusage(resource.RUSAGE_SELF).ru_utime
        except Exception:
            return 0.0

    def _db_size_mb(self) -> float:
        total = 0
        mem_dir = os.path.join(LOGOS_ROOT, "memory")
        if os.path.isdir(mem_dir):
            for f in os.listdir(mem_dir):
                if f.endswith(".db"):
                    total += os.path.getsize(os.path.join(mem_dir, f))
        return total / (1024.0 * 1024.0)

    def check_resource_budget(self) -> dict:
        ram = self._ram_usage_mb()
        cpu = self._cpu_usage_sec()
        db = self._db_size_mb()
        over = []
        if ram > self.limits.max_ram_mb:
            over.append(f"RAM {ram:.1f}MB > {self.limits.max_ram_mb}MB")
        if cpu > self.limits.max_cpu_sec:
            over.append(f"CPU {cpu:.1f}s > {self.limits.max_cpu_sec}s")
        if db > self.limits.max_db_size_mb:
            over.append(f"DB {db:.1f}MB > {self.limits.max_db_size_mb}MB")
        return {"within_budget": len(over) == 0, "violations": over,
                "ram_mb": round(ram, 2), "cpu_sec": round(cpu, 2), "db_mb": round(db, 2)}

    # ---------- emergency stop ----------

    def trigger_emergency_stop(self, reason: str):
        self.e_stop_active = True
        stop_path = os.path.join(LOGOS_ROOT, ".e_stop")
        with open(stop_path, "w") as f:
            f.write(f"{time.ctime()}: {reason}\n")

    def clear_emergency_stop(self):
        self.e_stop_active = False
        stop_path = os.path.join(LOGOS_ROOT, ".e_stop")
        if os.path.exists(stop_path):
            os.remove(stop_path)

    # ---------- the actual gateway ----------

    def handle_request(self, req: dict) -> dict:
        action = req.get("action")

        # Bug found by testing: these three MUST be handled before the
        # e_stop gate below, or an active emergency stop blocks the only
        # commands that could ever recover from it -- a self-lock with no
        # way out except killing the process and losing the stop reason.
        # Read-only diagnostics and the clear command are always reachable;
        # everything else (above all, write_file) is not.
        if action == "check_integrity":
            return self.check_integrity()
        if action == "check_resource_budget":
            return self.check_resource_budget()
        if action == "clear_emergency_stop":
            self.clear_emergency_stop()
            return {"allowed": True, "reason": "EMERGENCY_STOP_CLEARED"}

        if self.e_stop_active:
            return {"allowed": False, "reason": "EMERGENCY_STOP_ACTIVE"}

        if action == "emergency_stop":
            self.trigger_emergency_stop(req.get("reason", "manual"))
            return {"allowed": True, "reason": "EMERGENCY_STOP_TRIGGERED"}

        if action == "write_file":
            rel_path = req.get("path", "")
            content = req.get("content", "")
            return self._write_file(rel_path, content)

        return {"allowed": False, "reason": f"UNKNOWN_ACTION: {action}"}

    def _write_file(self, rel_path: str, content: str) -> dict:
        # Canonicalize BEFORE comparing -- this is the path-normalization
        # bug fix (Audit 03, Finding 1): resolve '..' and symlinks first,
        # then compare the real absolute path, not the raw string.
        full_path = os.path.realpath(os.path.join(LOGOS_ROOT, rel_path))
        root_real = os.path.realpath(LOGOS_ROOT)

        if not full_path.startswith(root_real + os.sep):
            return {"allowed": False, "reason": "PATH_ESCAPES_PROJECT_ROOT"}

        canonical_rel = os.path.relpath(full_path, root_real)
        if canonical_rel in IMMUTABLE_FILES:
            return {"allowed": False, "reason": f"IMMUTABLE_CORE_PROTECTION: '{canonical_rel}' is protected"}

        budget = self.check_resource_budget()
        if not budget["within_budget"]:
            return {"allowed": False, "reason": f"RESOURCE_BUDGET_EXCEEDED: {budget['violations']}"}

        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w") as f:
            f.write(content)

        return {"allowed": True, "reason": "WRITTEN", "path": canonical_rel}

    # ---------- socket server ----------

    def serve(self):
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.socket_path)
        server.listen(5)

        def handle_client(conn):
            with conn:
                buf = b""
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                    if b"\n" in buf:
                        line, _, buf = buf.partition(b"\n")
                        try:
                            req = json.loads(line.decode("utf-8"))
                            resp = self.handle_request(req)
                        except Exception as e:
                            resp = {"allowed": False, "reason": f"ENFORCER_ERROR: {e}"}
                        conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))

        while True:
            conn, _ = server.accept()
            threading.Thread(target=handle_client, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    sock_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(LOGOS_ROOT, "enforcer.sock")
    Enforcer(sock_path).serve()
