#!/usr/bin/env python3
"""Store and runner tests."""
import asyncio, os, sys, pathlib, tempfile, time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from bbhunter.store import Store
from bbhunter.runner import CommandRunner

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
    else:
        FAIL += 1
        print(f"  FAIL  {label}\n        got {got!r}, wanted {want!r}")


tmp = tempfile.mkdtemp()
store = Store(os.path.join(tmp, "engagement.db"))

print("== programmes ==")
prog = store.upsert_program("Acme", {"includes": ["*.acme.com"]},
                            {"per_host_rps": 5}, platform="hackerone",
                            handle="LukeDInfosec", scope_hash="abc123")
check("created", prog["name"], "Acme")
check("handle stored", prog["handle"], "LukeDInfosec")
store.upsert_program("Acme", {"includes": ["*.acme.com", "*.acme.io"]},
                     {"per_host_rps": 3}, handle="LukeDInfosec", scope_hash="def456")
prog = store.program_by_name("Acme")
check("updated in place, not duplicated", len(store.programs()), 1)
check("scope hash updated", prog["scope_hash"], "def456")
pid = prog["id"]

print("== assets: identity vs sighting ==")
run1 = store.create_run(pid, "standard", "def456", {})
new = store.upsert_assets(pid, run1, "subdomain", [
    {"key": "api.acme.com", "source": "subfinder"},
    {"key": "www.acme.com", "source": "crt.sh"},
    {"key": "old.acme.com", "source": "subfinder"},
])
check("three new on the first run", new, 3)
store.finish_run(run1, "completed")

run2 = store.create_run(pid, "standard", "def456", {})
new = store.upsert_assets(pid, run2, "subdomain", [
    {"key": "api.acme.com", "source": "subfinder"},
    {"key": "www.acme.com", "source": "subfinder"},
    {"key": "shop.acme.com", "source": "subfinder"},      # new
])
check("one new on the second run", new, 1)
check("still four assets in total", store.count_assets(pid, "subdomain"), 4)
store.finish_run(run2, "completed")

print("== enrichment merges rather than overwrites ==")
store.upsert_assets(pid, run2, "subdomain", [
    {"key": "api.acme.com", "data": {"status": 200, "title": "API"}},
])
store.upsert_assets(pid, run2, "subdomain", [
    {"key": "api.acme.com", "data": {"tech": ["nginx"]}},
])
asset = [a for a in store.assets(pid, "subdomain") if a["key"] == "api.acme.com"][0]
check("earlier field survives", asset["data"].get("title"), "API")
check("later field added", asset["data"].get("tech"), ["nginx"])

print("== diffing ==")
diff = store.diff(pid, run2, run1)
check("new asset listed", [a["key"] for a in diff["new_assets"]], ["shop.acme.com"])
check("disappeared asset listed", [a["key"] for a in diff["gone_assets"]],
      ["old.acme.com"])

print("== a failed stage must not produce 'disappeared' ==")
run3 = store.create_run(pid, "standard", "def456", {})
sid = store.add_stage(run3, "subdomains", "Subdomain enumeration", "subfinder")
store.update_stage(sid, status="failed", message="subfinder crashed")
store.upsert_assets(pid, run3, "subdomain", [{"key": "api.acme.com"}])
store.finish_run(run3, "partial")
diff = store.diff(pid, run3, run2)
check("caveat is raised", bool(diff["caveat"]), True)
check("failed stage named", "Subdomain enumeration" in diff["unreliable"], True)

print("== findings: fingerprints are stable, triage sticks ==")
fp1 = store.fingerprint("nuclei", "https://api.acme.com/x?t=1", "Exposed .env", "word")
fp2 = store.fingerprint("nuclei", "https://api.acme.com/x?t=99999", "Exposed .env", "word")
check("query string does not change the fingerprint", fp1, fp2)
fp3 = store.fingerprint("nuclei", "https://other.acme.com/x", "Exposed .env", "word")
check("a different host does", fp1 != fp3, True)

store.record_finding(pid, run2, {
    "severity": "high", "title": "Exposed .env", "tool": "nuclei",
    "target": "https://api.acme.com/.env", "detail": "returned 200",
})
found = store.findings(pid)
check("one finding", len(found), 1)
check("severity kept", found[0]["severity"], "high")
store.set_triage(found[0]["id"], "dismissed", "staging only, agreed with programme")

store.record_finding(pid, run3, {
    "severity": "high", "title": "Exposed .env", "tool": "nuclei",
    "target": "https://api.acme.com/.env", "detail": "returned 200 again",
})
found = store.findings(pid)
check("still one finding, not two", len(found), 1)
check("triage survived the rescan", found[0]["triage"], "dismissed")
check("instance count incremented", found[0]["instances"], 2)
check("dismissed findings leave the counts",
      store.finding_counts(pid)["high"], 0)

print("== the runner ==")


async def runner_tests():
    global PASS, FAIL
    lines = []
    runner = CommandRunner(on_line=lambda kind, text: lines.append((kind, text)))

    result = await runner.run(["/bin/echo", "hello world"])
    check("exit code", result.exit_code, 0)
    check("stdout captured", result.stdout_lines, ["hello world"])
    check("streamed live", ("out", "hello world") in lines, True)
    check("command recorded for audit", "echo" in result.command, True)

    result = await runner.run(["/bin/sh", "-c", "echo oops >&2; exit 3"])
    check("non-zero exit reported", result.exit_code, 3)
    check("stderr captured", result.stderr_lines, ["oops"])
    check("not ok", result.ok, False)

    result = await runner.run(["/nonexistent/tool"])
    check("missing tool is 127, not an exception", result.exit_code, 127)

    started = time.monotonic()
    result = await runner.run(["/bin/sleep", "30"], timeout=2, idle_timeout=0)
    check("hard timeout fired", result.timed_out, True)
    check("timeout was prompt", time.monotonic() - started < 10, True)

    started = time.monotonic()
    result = await runner.run(["/bin/sleep", "60"], timeout=300, idle_timeout=6)
    check("idle watchdog fired", result.idle_killed, True)
    check("idle kill was prompt", time.monotonic() - started < 20, True)
    check("idle kill is explained", "hung" in result.stderr_tail, True)

    # The one that matters: a killed stage must not leave children running.
    marker = os.path.join(tmp, "orphan.txt")
    script = (f"sh -c 'while true; do echo tick >> {marker}; sleep 1; done' & "
              f"echo started; sleep 60")
    runner2 = CommandRunner()
    task = asyncio.create_task(runner2.run(["/bin/sh", "-c", script],
                                           timeout=300, idle_timeout=0))
    await asyncio.sleep(2.5)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    await asyncio.sleep(0.5)
    size_after_kill = os.path.getsize(marker) if os.path.exists(marker) else 0
    await asyncio.sleep(3)
    size_later = os.path.getsize(marker) if os.path.exists(marker) else 0
    check("the grandchild was killed too, not orphaned",
          size_later, size_after_kill)

    # asyncio's default StreamReader limit is 64 KiB; httpx with screenshots
    # emits single JSON lines far larger than that.
    result = await runner.run(
        [sys.executable, "-c", "print('x' * 200000)"])
    check("a 200 KB line is not truncated",
          len(result.stdout_lines[0]) if result.stdout_lines else 0, 200_000)

    log = os.path.join(tmp, "stage.log")
    runner3 = CommandRunner(log_path=log)
    await runner3.run(["/bin/echo", "logged"])
    text = open(log).read()
    check("log records the command", "$ /bin/echo logged" in text, True)
    check("log records the output", "logged" in text, True)
    check("log records the exit", "[exit 0" in text, True)


asyncio.run(runner_tests())

store.close()
print()
print(f"{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
