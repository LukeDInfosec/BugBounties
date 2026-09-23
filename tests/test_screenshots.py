#!/usr/bin/env python3
"""Choosing a screenshot backend.

The failure this covers: httpx and gowitness both embed go-rod, which downloads
its own Chromium on first use. On a box that cannot reach Google's storage
bucket that download fails, httpx exits, and the stage used to report a cheerful
"0 screenshot(s) captured" as though nothing were wrong — because the backend
was chosen by which tool was installed and never reconsidered.
"""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bbhunter.pipeline import ScreenshotStage  # noqa: E402

PASS = FAIL = 0


def check(label, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  \033[32m✓\033[0m {label}")
    else:
        FAIL += 1
        print(f"  \033[31m✗\033[0m {label}  (got {got!r}, wanted {want!r})")


class Registry:
    def __init__(self, installed):
        self.installed = set(installed)

    def have(self, key):
        return key in self.installed

    def path(self, key):
        return f"/usr/bin/{key}"


class Ctx:
    """The least a stage needs, with the logs kept so they can be asserted on."""

    def __init__(self, workdir, installed=(), chrome_binary=""):
        self.workdir = workdir
        self.registry = Registry(installed)
        self.config = {"chrome_binary": chrome_binary, "screenshot_cap": 300}
        self.logs = []
        self.counters = {}
        self.proxy = None
        self.program_id = self.run_id = 1
        self.scope = self
        self.store = self

    # scope
    def filter_allowed(self, items):
        return list(items)

    # store
    def assets(self, *a, **k):
        return []

    def upsert_assets(self, *a, **k):
        pass

    # ctx
    def log(self, message, level="info"):
        self.logs.append((level, message))

    def counter(self, key, value):
        self.counters[key] = value

    def write_list(self, name, items):
        path = self.workdir / name
        path.write_text("\n".join(items))
        return path


def main():
    stage = ScreenshotStage()

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        (work / "distinct.txt").write_text("http://a.example\nhttp://b.example\n")

        print("\n\033[1mNo browser anywhere\033[0m")
        ctx = Ctx(work, installed=["httpx"], chrome_binary="/nope/chrome")
        ScreenshotStage._find_chrome = staticmethod(lambda configured="": "")
        out = asyncio.run(stage.run(ctx))
        check("nothing is captured", out["produced"], 0)
        check("it names the missing piece",
              "no browser is installed" in out.get("skipped", ""))
        check("it gives the install command",
              "apt install -y chromium" in out.get("skipped", ""))
        check("it mentions chrome_binary for an unusual location",
              "chrome_binary" in out.get("skipped", ""))
        check("no backend was even run", ctx.logs, [])

        print("\n\033[1mA backend that produces nothing falls through\033[0m")
        ScreenshotStage._find_chrome = staticmethod(
            lambda configured="": "/usr/bin/chromium")
        ctx = Ctx(work, installed=["httpx", "gowitness"])
        called = []

        async def dud(name):
            called.append(name)
            return f"{name} --ran"

        stage._httpx = lambda c, t, s, ch: dud("httpx")
        stage._gowitness = lambda c, t, s, ch: dud("gowitness")

        async def working(c, t, s, ch):
            called.append("chrome")
            (s / "0123456789abcdef.png").write_bytes(b"\x89PNG\r\n\x1a\n")
            for url in t:
                import hashlib
                (s / (hashlib.sha256(url.encode()).hexdigest()[:16] + ".png")
                 ).write_bytes(b"\x89PNG\r\n\x1a\n")
            return "chromium --headless"

        stage._chrome = working
        out = asyncio.run(stage.run(ctx))
        check("all three were tried in order", called,
              ["httpx", "gowitness", "chrome"])
        check("the images are counted", out["produced"], 2)
        check("the log says which backends came up empty",
              sum(1 for lvl, m in ctx.logs if "produced no images" in m), 2)
        check("the command records every attempt",
              out["command"].count(";"), 2)

        print("\n\033[1mThe first backend working stops the chain\033[0m")
        for f in (work / "screenshots").glob("*.png"):
            f.unlink()
        ctx = Ctx(work, installed=["httpx", "gowitness"])
        called.clear()
        stage._httpx = working
        out = asyncio.run(stage.run(ctx))
        check("gowitness and chrome are not run", called, ["chrome"])
        check("and it still reports the images", out["produced"], 2)

        print("\n\033[1mBackend order\033[0m")
        labels = [label for label, _ in
                  stage._backends(Ctx(work, installed=["httpx", "gowitness"]))]
        check("httpx first, then gowitness, then the browser", labels,
              ["httpx", "gowitness", "the browser directly"])
        labels = [label for label, _ in stage._backends(Ctx(work, installed=[]))]
        check("with no tools installed, the browser is still an option",
              labels, ["the browser directly"])

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
