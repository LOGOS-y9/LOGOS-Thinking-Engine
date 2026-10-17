import os
import sys
import time
import shutil
import random
import subprocess
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.governance_client import GovernanceClient
from core.event_bus import EventBus
from core.orchestrator import Orchestrator
from engines.echo_engine import EchoEngine


def start_enforcer(workdir):
    sock_path = os.path.join(workdir, "enforcer.sock")
    enforcer_src = os.path.join(workdir, "core", "enforcer.py")
    proc = subprocess.Popen(
        [sys.executable, enforcer_src, sock_path],
        cwd=workdir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(50):
        if os.path.exists(sock_path):
            break
        time.sleep(0.1)
    else:
        proc.kill()
        raise RuntimeError("enforcer socket never appeared")
    time.sleep(0.1)
    return proc, sock_path


def setup_workdir():
    d = tempfile.mkdtemp(prefix="logos_zero_test_")
    for sub in ("core", "engines", "memory"):
        os.makedirs(os.path.join(d, sub), exist_ok=True)
    shutil.copy(os.path.join(ROOT, "core", "enforcer.py"), os.path.join(d, "core", "enforcer.py"))
    return d


results = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    results.append((name, cond, detail))
    print(f"{status}  {name}" + (f"  -- {detail}" if detail and not cond else ""))


print("=" * 70)
print("FOUNDATION TEST: enforcer runs as a REAL separate OS process")
print("=" * 70)
workdir = setup_workdir()
proc, sock_path = start_enforcer(workdir)
client = GovernanceClient(sock_path)

try:
    check("enforcer process has its own PID, distinct from this test process",
          proc.pid != os.getpid())

    print("\n--- normal write ---")
    r = client.write_file("engines/scratch.py", "# hello from enforcer\n")
    check("normal write to a non-protected path succeeds", r.get("allowed") is True, r)
    check("file was actually written by the enforcer, not by this process",
          os.path.exists(os.path.join(workdir, "engines", "scratch.py")))

    print("\n--- protected file, direct name ---")
    r = client.write_file("core/enforcer.py", "malicious overwrite attempt\n")
    check("writing core/enforcer.py directly is denied", r.get("allowed") is False, r)
    with open(os.path.join(workdir, "core", "enforcer.py")) as f:
        untouched = "malicious" not in f.read()
    check("protected file content is actually unchanged after the denied attempt", untouched)

    print("\n--- protected file, path-traversal attempt (the old canonicalization bug) ---")
    r = client.write_file("engines/../core/enforcer.py", "sneaky overwrite via ..\n")
    check("'../' path traversal to a protected file is also denied", r.get("allowed") is False, r)

    print("\n--- path trying to escape the project root entirely ---")
    r = client.write_file("../../etc/something_bad", "escape attempt\n")
    check("writing outside the project root is denied", r.get("allowed") is False, r)

    print("\n--- resource budget reporting ---")
    r = client.check_resource_budget()
    check("resource budget reports RAM, CPU, and DB size (the old version only checked RAM)",
          all(k in r for k in ("ram_mb", "cpu_sec", "db_mb")), r)

    print("\n--- integrity check ---")
    r = client.check_integrity()
    check("integrity check passes when nothing has actually been tampered with", r.get("ok") is True, r)

    print("\n--- emergency stop ---")
    client.emergency_stop("test")
    r = client.write_file("engines/should_not_write.py", "x")
    check("after emergency stop, even a normal write is blocked", r.get("allowed") is False, r)
    client.clear_emergency_stop()
    r = client.write_file("engines/after_clear.py", "ok again")
    check("clearing emergency stop restores normal operation", r.get("allowed") is True, r)

finally:
    proc.terminate()
    proc.wait(timeout=5)

print()
print("=" * 70)
print("EVENT BUS: deterministic replay of a genuinely non-deterministic value")
print("=" * 70)

log_path = os.path.join(workdir, "memory", "event_log.db")
bus = EventBus(log_path)

captured_first_run = []
bus.subscribe("llm_output", lambda p: captured_first_run.append(p["text"]))

random.seed()
for i in range(3):
    fake_llm_text = f"response-{random.randint(0, 10_000_000)}"
    bus.publish("llm_output", {"text": fake_llm_text})

print("Values actually produced (would differ if regenerated):", captured_first_run)

captured_replay = []
bus2 = EventBus(log_path)
bus2.subscribe("llm_output", lambda p: captured_replay.append(p["text"]))
bus2.replay()

check("replay reproduces the exact logged values, not newly-generated ones",
      captured_replay == captured_first_run,
      f"first={captured_first_run} replay={captured_replay}")

fresh_random = [f"response-{random.randint(0, 10_000_000)}" for _ in range(3)]
check("confirms randint is actually non-deterministic (sanity check on the test itself)",
      fresh_random != captured_first_run)

print()
print("=" * 70)
print("ORCHESTRATOR: bus-only wiring, no direct engine-to-engine calls")
print("=" * 70)

orch = Orchestrator(
    event_log_path=os.path.join(workdir, "memory", "event_log2.db"),
    socket_path=sock_path,
)
engine = EchoEngine()
orch.register_engine("echo", engine)
orch.submit("ping", {"n": 1})
orch.submit("ping", {"n": 2})

check("engine received events published through orchestrator.submit(), via the bus only",
      [p["n"] for p in engine.received] == [1, 2])

print()
total = len(results)
passed = sum(1 for _, ok, _ in results if ok)
print(f"{passed}/{total} checks passed")
sys.exit(0 if passed == total else 1)
