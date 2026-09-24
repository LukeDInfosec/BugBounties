#!/usr/bin/env python3
"""Keeping the output readable.

Two failures, both of which drown the thing you were trying to read:

  * Resolving a few thousand names that do not exist printed a page of
    "Future exception was never retrieved" to the terminal, because a lookup
    that timed out left its exception on a future nobody awaited.
  * The headless browser checks for its own updates and asks Safe Browsing on
    every launch. The gate refuses all of it, correctly, and the log filled
    with hundreds of identical refusals for www.google.com.
"""

import asyncio
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bbhunter.engine import _RefusalLog                       # noqa: E402
from bbhunter.pipeline import ScreenshotStage, _resolve_one   # noqa: E402

PASS = FAIL = 0


def check(label, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  \033[32m✓\033[0m {label}")
    else:
        FAIL += 1
        print(f"  \033[31m✗\033[0m {label}  (got {got!r}, wanted {want!r})")


class Bus:
    def __init__(self):
        self.events = []

    def publish(self, kind, data):
        self.events.append((kind, data))

    def logs(self):
        return [d["text"] for k, d in self.events if k == "log"]


def main():
    print("\n\033[1mResolving names that do not exist\033[0m")
    # In a subprocess, because the warning is printed by asyncio's exception
    # handler to stderr and cannot be caught from inside the loop.
    script = textwrap.dedent(f"""
        import asyncio, sys
        sys.path.insert(0, {str(ROOT)!r})
        from bbhunter.pipeline import _resolve_one

        async def main():
            names = [f"no-such-host-{{i}}.invalid" for i in range(40)]
            out = await asyncio.gather(*[_resolve_one(n, timeout=0.05)
                                         for n in names])
            print("resolved:", sum(1 for o in out if o))

        asyncio.run(main())
    """)
    proc = subprocess.run([sys.executable, "-c", script],
                          capture_output=True, text=True, timeout=120)
    check("it exits cleanly", proc.returncode, 0)
    check("nothing resolved", "resolved: 0" in proc.stdout)
    check("no 'Future exception was never retrieved' on the terminal",
          "never retrieved" in proc.stderr, False)
    check("no traceback either", "Traceback" in proc.stderr, False)
    if proc.stderr.strip():
        print(f"      stderr was: {proc.stderr.strip()[:200]}")

    print("\n\033[1mA name that does resolve still resolves\033[0m")
    addresses = asyncio.run(_resolve_one("localhost", timeout=5))
    check("localhost comes back", bool(addresses))

    print("\n\033[1mRepeated refusals are counted, not repeated\033[0m")
    bus = Bus()
    refusals = _RefusalLog(bus)
    for _ in range(12):
        refusals.event("blocked", {"host": "www.google.com", "port": 443,
                                   "reason": "not in scope", "method": "CONNECT"})
    logs = bus.logs()
    check("the first one is reported in full",
          logs and "gate refused CONNECT www.google.com" in logs[0])
    check("the other eleven are not each logged", len(logs), 2)
    check("but the tenth says how many there have been",
          "refused 10 times" in logs[1])
    structured = [d for k, d in bus.events if k == "blocked"]
    check("every refusal is still published as an event", len(structured), 12)
    check("and the repeats are marked as muted",
          sum(1 for d in structured if d["muted"]), 11)

    print("\n\033[1mA different host is its own line\033[0m")
    refusals.event("blocked", {"host": "fonts.googleapis.com", "port": 443,
                               "reason": "not in scope", "method": "CONNECT"})
    check("it is reported", "fonts.googleapis.com" in bus.logs()[-1])
    total, ranked = refusals.summary()
    check("the total is exact", total, 13)
    check("the busiest host is first", ranked[0], ("www.google.com", 12))

    print("\n\033[1mAbandoned DNS failures do not reach the terminal\033[0m")
    # The one asyncio prints itself, from inside a connection attempt that was
    # already abandoned. The handler counts those and passes everything else
    # through untouched.
    from bbhunter.quiet import install as install_quiet
    import socket as _socket

    said, passed_through = [], []

    async def exercise():
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(lambda l, c: passed_through.append(c))
        install_quiet(loop, say=said.append)
        loop.call_exception_handler({
            "message": "Future exception was never retrieved",
            "exception": _socket.gaierror(-2, "Name or service not known")})
        loop.call_exception_handler({
            "message": "Future exception was never retrieved",
            "exception": _socket.gaierror(-2, "Name or service not known")})
        loop.call_exception_handler({
            "message": "Task exception was never retrieved",
            "exception": ValueError("a real bug")})

    asyncio.run(exercise())
    check("the name failures are counted once, not printed twice", len(said), 1)
    check("and the count is in the message", "1 name lookup(s) failed" in said[0])
    check("a real error still reaches the previous handler",
          len(passed_through), 1)
    check("and it is the real one",
          isinstance(passed_through[0]["exception"], ValueError))

    print("\n\033[1mThe browser is told not to phone home\033[0m")
    flags = ScreenshotStage.QUIET_CHROME
    for flag in ("--disable-background-networking", "--disable-component-update",
                 "--safebrowsing-disable-auto-update", "--no-pings"):
        check(f"{flag} is passed", flag in flags)

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
