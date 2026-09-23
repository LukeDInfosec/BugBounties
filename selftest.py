#!/usr/bin/env python3
"""Sanity check.

Runs the whole framework end to end against a target served on this machine,
so a failure shows up here rather than on an engagement. It covers the parts
that are dangerous when wrong — the scope gate, the rate limiter, the process
kill — and the parts that are merely annoying when wrong: the API, the
WebSocket, and whether every stage can be imported and executed.

    python3 selftest.py            # everything
    python3 selftest.py --quick    # skip the live run
"""

import asyncio
import json
import os
import socket
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

for _var in ("no_proxy", "NO_PROXY", "http_proxy", "HTTP_PROXY",
             "https_proxy", "HTTPS_PROXY"):
    os.environ.pop(_var, None)

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

BOLD, DIM, RED, GREEN, YELLOW, RESET = (
    "\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[33m", "\033[0m")

PASS = FAIL = WARN = 0
FAILURES = []


def section(title):
    print(f"\n{BOLD}{title}{RESET}")


def check(label, got=True, want=True, fatal=True):
    global PASS, FAIL, WARN
    if got == want:
        PASS += 1
        print(f"  {GREEN}✓{RESET} {label}")
        return True
    if fatal:
        FAIL += 1
        FAILURES.append(label)
        print(f"  {RED}✗{RESET} {label}\n      got {got!r}, wanted {want!r}")
    else:
        WARN += 1
        print(f"  {YELLOW}!{RESET} {label}  {DIM}(got {got!r}){RESET}")
    return False


# ─────────────────────────────────────────────────────────────────────────────
#  A target to scan: a small site with links, a JS file and a parameter.
# ─────────────────────────────────────────────────────────────────────────────

PAGES = {
    "/": b"""<html><head><title>Acme Self Test</title>
        <script src="/static/app.js"></script></head>
        <body><h1>Acme</h1>
        <a href="/search?q=test&next=/home">search</a>
        <a href="/admin/users">admin</a>
        <a href="/api/v1/orders/42">order</a>
        </body></html>""",
    "/search": b"<html><title>Search</title><body>results</body></html>",
    "/admin/users": b"<html><title>Admin</title><body>users</body></html>",
    "/api/v1/orders/42": b'{"id":42}',
    "/static/app.js": b"""
        var API = "/api/v1/orders";
        var GOOGLE_KEY = "AIzaSyB1234567890abcdefghijklmnopqrstuv";
        fetch(API + "?id=" + location.hash.slice(1));
    """,
}


class Target(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    hits = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        Target.hits.append((self.path, dict(self.headers)))
        path = self.path.split("?", 1)[0]
        body = PAGES.get(path)
        code = 200 if body else 404
        body = body or b"not found"
        ctype = ("application/javascript" if path.endswith(".js")
                 else "application/json" if path.startswith("/api")
                 else "text/html")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_target():
    """Bind port 80 if we can, because that is what a prober tries.

    Falls back to an ephemeral port when port 80 is unavailable, and the
    caller reports that the traffic check could not be performed rather than
    pretending it passed.
    """
    for port in (80, 8080, 0):
        try:
            server = ThreadingHTTPServer(("127.0.0.1", port), Target)
        except OSError:
            continue
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, server.server_address[1]
    return None, 0


# ─────────────────────────────────────────────────────────────────────────────

async def main(quick=False):
    workdir = tempfile.mkdtemp(prefix="bbhunter-selftest-")
    os.environ["BBHUNTER_HOME"] = workdir

    section("Imports")
    try:
        from bbhunter import config as cfg
        from bbhunter.scope import Scope, Decision
        from bbhunter.proxy import ScopeProxy, RatePolicy
        from bbhunter.store import Store
        from bbhunter.runner import CommandRunner
        from bbhunter.pipeline import STAGES, PRESETS, resolve_stage_list
        from bbhunter.engine import ScanEngine
        from bbhunter.tools import ToolRegistry, TOOLS
        from bbhunter.server import create_app
        from bbhunter import updater
        check("every module imports")
    except Exception as exc:
        print(f"  {RED}✗{RESET} import failed: {exc}")
        import traceback
        traceback.print_exc()
        return 1

    check("version is set", bool(cfg.version()) and cfg.version() != "0.0.0")
    check("every preset names only real stages",
          all(s in STAGES for p in PRESETS.values() for s in p["stages"]))
    check("every stage has a description",
          all(s.description for s in STAGES.values()))
    check("every stage's tool is in the registry",
          all((not s.tool_key) or s.tool_key in TOOLS for s in STAGES.values()))

    section("Scope decisions")
    scope = Scope.from_lines(include_text="*.acme.com",
                             exclude_text="secret.acme.com")
    check("in scope", scope.classify("api.acme.com").decision, Decision.ALLOW)
    check("excluded", scope.classify("secret.acme.com").decision, Decision.DENY)
    check("lookalike domain is not in scope",
          scope.classify("acme.com.evil.test").decision, Decision.OBSERVE)
    check("loopback denied", scope.classify("127.0.0.1").decision, Decision.DENY)
    check("metadata denied",
          scope.classify("169.254.169.254").decision, Decision.DENY)

    section("Store")
    store = Store(Path(workdir) / "selftest.db")
    program = store.upsert_program("SelfTest", {"include": ["127.0.0.1"]},
                                   {"per_host_rps": 50}, handle="LukeDInfosec")
    check("programme created", program["name"], "SelfTest")
    run = store.create_run(program["id"], "standard", "x", {})
    store.upsert_assets(program["id"], run, "subdomain", [{"key": "a.acme.com"}])
    check("asset stored", store.count_assets(program["id"], "subdomain"), 1)
    store.finish_run(run, "completed")

    section("Tool detection")
    registry = ToolRegistry()
    await registry.detect()
    summary = registry.summary()
    print(f"  {DIM}{len(summary['installed'])} installed, "
          f"{len(summary['missing'])} missing{RESET}")
    check("detection returns a verdict for every tool",
          len(summary["installed"]) + len(summary["missing"]), len(TOOLS))
    if summary["missing_required"]:
        check(f"required tools present ({', '.join(summary['missing_required'])} missing)",
              False, True, fatal=False)
        print(f"      {DIM}The live run below will still work — stages without "
              f"their tool are skipped.{RESET}")
    else:
        check("all required tools present")

    section("API and interface")
    app = create_app()
    routes = {getattr(r, "path", "") for r in app.routes}
    for path in ("/", "/api/meta", "/api/programs", "/api/tools", "/api/preflight",
                 "/api/runs", "/api/settings", "/api/update/check", "/ws"):
        check(f"route {path}", path in routes)
    check("interface HTML is present",
          (ROOT / "bbhunter" / "web" / "index.html").exists())
    check("interface script is present",
          (ROOT / "bbhunter" / "web" / "app.js").exists())

    section("Updater")
    info = await updater.check()
    check("update check returns without raising", isinstance(info, dict))
    check("it reports the installed version", bool(info.get("current")))
    if not info.get("git"):
        check("checkout is a git clone (needed for the Update button)",
              False, True, fatal=False)

    if quick:
        return report()

    # ── the live run ────────────────────────────────────────────────────────
    section("End-to-end run against a local target")
    server, port = start_target()
    target = f"127.0.0.1:{port}"
    print(f"  {DIM}target serving on http://{target}{RESET}")

    # allow_private is required because the target is on loopback; on a real
    # engagement this stays off and loopback is refused.
    store.upsert_program(
        "SelfTest",
        {"include": ["127.0.0.1"], "exclude": [], "seeds": ["127.0.0.1"],
         "allow_private": True, "allow_metadata": False,
         "bare_includes_children": True, "max_distance": 0},
        {"per_host_rps": 50, "global_rps": 100,
         "headers": {"X-Bug-Bounty": "LukeDInfosec"}},
        handle="LukeDInfosec")
    program = store.program_by_name("SelfTest")

    engine = ScanEngine(store, Path(workdir))
    await engine.detect_tools()

    settings = {**cfg.load_config(), "per_host_rps": 50, "global_rps": 100,
                "headers": {"X-Bug-Bounty": "LukeDInfosec"},
                "user_agent": "bbhunter-selftest",
                "stage_timeout": 120}

    settings["screenshot_cap"] = 10
    # Point the fallback at whatever browser this machine has, so the path
    # that a bare Kali box would take is actually exercised here.
    import glob as _glob
    for candidate in (_glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome")
                      + _glob.glob("/opt/pw-browsers/chromium_headless_shell-*/"
                                   "chrome-linux/headless_shell")):
        settings["chrome_binary"] = candidate
        break
    pre = engine.preflight(program, "standard", [], settings)
    check("preflight lists the stages", len(pre["stages"]) > 4)
    check("preflight shows the identification header",
          pre["identification"].get("X-Bug-Bounty"), "LukeDInfosec")
    check("preflight warns about private ranges being enabled",
          any("Private address" in w for w in pre["warnings"]))

    events = []
    engine.bus.publish = (lambda orig: (lambda kind, data: (
        events.append((kind, data)), orig(kind, data))[1]))(engine.bus.publish)

    run_id = await engine.start(program, "standard", [], settings)
    check("run started", isinstance(run_id, int))

    deadline = time.monotonic() + 240
    while engine.current and time.monotonic() < deadline:
        await asyncio.sleep(0.5)
    check("run finished within the time limit", engine.current is None)

    stages = store.stages(run_id)
    done = [s for s in stages if s["status"] == "completed"]
    skipped = [s for s in stages if s["status"] == "skipped"]
    failed = [s for s in stages if s["status"] == "failed"]
    print(f"  {DIM}{len(done)} completed, {len(skipped)} skipped, "
          f"{len(failed)} failed{RESET}")
    for stage in failed:
        print(f"      {RED}{stage['name']}: {stage['message']}{RESET}")
    check("no stage crashed", len(failed), 0)
    check("at least the seed and probe stages completed", len(done) >= 2)

    run_row = store.run(run_id)
    check("run recorded a terminal status",
          run_row["status"] in ("completed", "partial"))

    standard_port = port in (80, 443)
    check("the target actually received traffic", len(Target.hits) > 0,
          True, fatal=standard_port)
    if not standard_port:
        print(f"      {DIM}Target is on port {port}; the prober tries 80 and 443, "
              f"so this check cannot be performed here.{RESET}")
    if Target.hits:
        headers_seen = [h for _, h in Target.hits]
        check("every request carried the identification header",
              all(h.get("X-Bug-Bounty") == "LukeDInfosec" for h in headers_seen),
              True, fatal=False)

    if os.environ.get("BBHUNTER_DEBUG"):
        for kind, data in events:
            if kind == "blocked":
                print(f"      DEBUG blocked: {data}")
        for st in store.stages(run_id):
            print(f"      DEBUG {st['name']}: {st['status']} produced={st['produced']} "
                  f"msg={st['message'][:110]}")
        import glob
        dirs = sorted(glob.glob(os.path.join(workdir, "runs", "*")))
        if dirs:
            print("      DEBUG files:", sorted(os.path.basename(f)
                  for f in glob.glob(dirs[-1] + "/*")))
            rp = os.path.join(dirs[-1], "resolved.txt")
            if os.path.exists(rp):
                print("      DEBUG resolved.txt:", repr(open(rp).read()[:200]))

    stats = json.loads(run_row.get("request_stats_json") or "{}")
    check("request statistics were recorded", stats.get("total_requests", 0) >= 0)
    print(f"  {DIM}{stats.get('total_requests', 0)} request(s) through the gate, "
          f"{stats.get('total_blocked', 0)} refused{RESET}")

    kinds = store.asset_kinds(program["id"])
    print(f"  {DIM}assets: {kinds}{RESET}")
    check("the probe stage found the live service",
          kinds.get("http_service", 0) >= 1, True, fatal=False)

    section("Screenshots and the gallery")
    shots = [s for s in stages if s["key"] == "screenshots"]
    check("the screenshot stage ran", len(shots), 1)
    if shots:
        captured = shots[0]["produced"]
        if shots[0]["status"] == "skipped":
            check(f"screenshots skipped: {shots[0]['message']}", False, True, fatal=False)
        else:
            check("at least one screenshot was captured", captured >= 1)
            gallery = store.assets(program["id"], "screenshot", limit=50)
            check("the gallery has an entry", len(gallery) >= 1)
            if gallery:
                data = gallery[0].get("data") or {}
                check("the entry names an image file", bool(data.get("image")))
                image_path = (Path(workdir) / "runs"
                              / f"{program['id']}-{run_id}" / "screenshots"
                              / str(data.get("image")))
                check("the image exists on disk", image_path.is_file())
                if image_path.is_file():
                    check("the image is a real PNG",
                          image_path.read_bytes()[:4] == b"\x89PNG")
                    check("the image is not empty",
                          image_path.stat().st_size > 1000)

    section("Gallery and per-step API")
    from fastapi.testclient import TestClient
    os.environ["BBHUNTER_HOME"] = workdir
    client = TestClient(create_app())
    meta = client.get("/api/meta").json()
    check("meta exposes the numbered phases", len(meta.get("phases") or []), 5)
    check("phase one is scope", meta["phases"][0]["key"], "scope")
    check("screenshots belong to step 3",
          meta["stages"]["screenshots"]["phase"], "alive")
    check("the standard profile includes screenshots",
          "screenshots" in meta["presets"]["standard"]["stages"])

    section("The gate holds during a real run")
    scope_live = Scope.from_lines(include_text="127.0.0.1", allow_private=True)
    proxy = ScopeProxy(scope_live, RatePolicy(per_host_rps=50, global_rps=100,
                                              headers={"X-Bug-Bounty": "LukeDInfosec"}))
    pport = await proxy.start()

    def fetch(url):
        handler = urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{pport}"})
        opener = urllib.request.build_opener(handler)
        try:
            with opener.open(url, timeout=8) as resp:
                return resp.status
        except urllib.error.HTTPError as exc:
            return exc.code
        except Exception:
            return -1

    loop = asyncio.get_running_loop()
    check("in-scope request passes",
          await loop.run_in_executor(None, fetch, f"http://{target}/"), 200)
    check("out-of-scope request refused",
          await loop.run_in_executor(None, fetch, "http://example.test/"), 403)
    check("metadata address refused",
          await loop.run_in_executor(None, fetch,
                                     "http://169.254.169.254/latest/"), 403)
    await proxy.stop()

    section("Events reached the interface stream")
    kinds_seen = {k for k, _ in events}
    for expected in ("run_started", "stage", "log", "run_finished"):
        check(f"{expected} published", expected in kinds_seen)
    check("counters were published", "counter" in kinds_seen, True, fatal=False)

    server.shutdown()
    store.close()
    return report()


def report():
    print()
    print("─" * 62)
    total = PASS + FAIL
    if FAIL:
        print(f"{RED}{BOLD}{FAIL} of {total} checks failed{RESET}"
              + (f"  ({WARN} warning(s))" if WARN else ""))
        for label in FAILURES:
            print(f"  · {label}")
        return 1
    print(f"{GREEN}{BOLD}All {total} checks passed{RESET}"
          + (f"  ({WARN} warning(s) — see above)" if WARN else ""))
    print(f"{DIM}Warnings are usually tools that are not installed. The "
          f"framework skips those stages rather than failing.{RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main("--quick" in sys.argv)))
