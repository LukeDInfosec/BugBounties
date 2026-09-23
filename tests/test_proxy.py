#!/usr/bin/env python3
"""Proxy tests: does the egress gate actually hold?

These run a real HTTP server, a real proxy, and real clients. A test that
mocks the socket proves nothing about whether a packet can escape.
"""
import asyncio, os, sys, pathlib, time, threading, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# This environment sets NO_PROXY for loopback, which makes urllib bypass an
# explicit ProxyHandler. Clearing it is what forces the test client through
# the proxy under test rather than straight to the target.
for _var in ("no_proxy", "NO_PROXY", "http_proxy", "HTTP_PROXY",
             "https_proxy", "HTTPS_PROXY"):
    os.environ.pop(_var, None)

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from bbhunter.scope import Scope
from bbhunter.proxy import ScopeProxy, RatePolicy

PASS = FAIL = 0
SEEN_HEADERS = []


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
    else:
        FAIL += 1
        print(f"  FAIL  {label}\n        got {got!r}, wanted {want!r}")


class Target(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _reply(self, code=200, body=b"ok"):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        SEEN_HEADERS.append(dict(self.headers))
        if self.path == "/429":
            return self._reply(429, b"slow down")
        self._reply(200, b"hello from the target")

    def do_DELETE(self):
        self._reply(200, b"deleted")


server = ThreadingHTTPServer(("127.0.0.1", 0), Target)
TARGET_PORT = server.server_address[1]
threading.Thread(target=server.serve_forever, daemon=True).start()


async def main():
    global PASS, FAIL

    # The target runs on loopback, which the scope engine blocks by design.
    # allow_private is the switch an operator flips for internal testing, and
    # it is what makes this test possible at all.
    scope = Scope.from_lines(
        include_text="127.0.0.1\nallowed.test",
        exclude_text="blocked.test",
        allow_private=True,
    )
    events = []
    policy = RatePolicy(
        per_host_rps=50, global_rps=100,
        headers={"X-Bug-Bounty": "LukeDInfosec", "X-HackerOne": "LukeDInfosec"},
        user_agent="bbhunter/test (LukeDInfosec)",
    )
    proxy = ScopeProxy(scope, policy, on_event=lambda k, d: events.append((k, d)))
    port = await proxy.start()
    check("proxy bound a port", port > 0, True)

    def fetch(url, method="GET"):
        """Go through the proxy exactly as a tool would."""
        handler = urllib.request.ProxyHandler({
            "http": f"http://127.0.0.1:{port}",
            "https": f"http://127.0.0.1:{port}",
        })
        opener = urllib.request.build_opener(handler)
        req = urllib.request.Request(url, method=method)
        try:
            with opener.open(req, timeout=10) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()
        except Exception as exc:
            return -1, str(exc).encode()

    loop = asyncio.get_running_loop()

    print("== in-scope traffic passes ==")
    status, body = await loop.run_in_executor(
        None, fetch, f"http://127.0.0.1:{TARGET_PORT}/")
    check("200 through the proxy", status, 200)
    check("body arrived", b"hello from the target" in body, True)

    print("== the identification header is stamped on ==")
    check("X-Bug-Bounty present", SEEN_HEADERS[-1].get("X-Bug-Bounty"), "LukeDInfosec")
    check("second header present", SEEN_HEADERS[-1].get("X-HackerOne"), "LukeDInfosec")
    check("User-Agent set", "bbhunter" in (SEEN_HEADERS[-1].get("User-Agent") or ""), True)

    print("== out-of-scope traffic is refused at the gate ==")
    status, body = await loop.run_in_executor(
        None, fetch, "http://blocked.test/")
    check("excluded host refused", status, 403)
    check("refusal explains itself", b"excluded" in body.lower(), True)

    status, _ = await loop.run_in_executor(None, fetch, "http://unknown.test/")
    check("unknown host refused", status, 403)

    print("== a tool cannot reach cloud metadata through the proxy ==")
    status, body = await loop.run_in_executor(
        None, fetch, "http://169.254.169.254/latest/meta-data/")
    check("metadata refused", status, 403)
    check("reason names metadata", b"metadata" in body.lower(), True)

    print("== methods outside the policy are refused ==")
    status, _ = await loop.run_in_executor(
        None, fetch, f"http://127.0.0.1:{TARGET_PORT}/", "DELETE")
    check("DELETE refused by default policy", status, 403)

    print("== CONNECT is not subject to the method policy ==")
    # Refusing CONNECT blocks all HTTPS, which is almost all real traffic.
    ok, reason = proxy.check("127.0.0.1", 443, "CONNECT", "/")
    check("CONNECT to an in-scope host is permitted", ok, True)
    ok, reason = proxy.check("blocked.test", 443, "CONNECT", "/")
    check("CONNECT to an out-of-scope host is still refused", ok, False)

    print("== the safety path denylist holds ==")
    status, body = await loop.run_in_executor(
        None, fetch, f"http://127.0.0.1:{TARGET_PORT}/account/logout")
    check("/logout refused", status, 403)
    check("reason names the denylist", b"denylist" in body.lower(), True)

    print("== a 429 triggers backoff ==")
    before = proxy._bucket("127.0.0.1").rate
    await loop.run_in_executor(None, fetch, f"http://127.0.0.1:{TARGET_PORT}/429")
    await asyncio.sleep(0.2)
    after = proxy._bucket("127.0.0.1").rate
    check("rate was halved after 429", after < before, True)
    check("a throttle event was emitted",
          any(k == "throttled" for k, _ in events), True)
    check("host is now backed off",
          proxy.check("127.0.0.1", TARGET_PORT, "GET", "/")[0], False)

    print("== rate limiting actually limits ==")
    slow_scope = Scope.from_lines(include_text="127.0.0.1", allow_private=True)
    slow = ScopeProxy(slow_scope, RatePolicy(per_host_rps=4, global_rps=100))
    slow_port = await slow.start()

    def fetch_slow():
        handler = urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{slow_port}"})
        opener = urllib.request.build_opener(handler)
        try:
            with opener.open(f"http://127.0.0.1:{TARGET_PORT}/", timeout=20) as r:
                return r.status
        except Exception:
            return -1

    started = time.monotonic()
    results = await asyncio.gather(*[
        loop.run_in_executor(None, fetch_slow) for _ in range(12)])
    elapsed = time.monotonic() - started
    check("all 12 succeeded", results.count(200), 12)
    # 12 requests at 4/sec with a burst of 4 cannot finish in under ~2s.
    check(f"12 requests at 4 rps took >=1.5s (took {elapsed:.1f}s)", elapsed >= 1.5, True)
    await slow.stop()

    print("== statistics are recorded for the report ==")
    stats = proxy.stats()
    check("requests counted", stats["total_requests"] >= 2, True)
    check("blocks counted", stats["total_blocked"] >= 5, True)
    check("per-host breakdown present", "127.0.0.1" in stats["hosts"], True)

    await proxy.stop()
    print()
    print(f"{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


sys.exit(asyncio.run(main()))
