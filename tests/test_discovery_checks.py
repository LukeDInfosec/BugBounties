#!/usr/bin/env python3
"""The overhaul, proved against applications with and without the bugs.

The failure this is written against is specific and was measured: a run over
1,500 live hosts produced four parameters and zero findings. Both halves of
that are tested here, and the second half is the one that matters —

    every planted bug is found    …and the correctly-built twin stays quiet

A test suite that only proves the first half produces a scanner that reports
everything, which is exactly as useless as one that reports nothing. The safe
twin implements the same six features properly: escaped output, a
parameterised query, an allow-listed redirect, a basename-only file
parameter, a strict CSP, and — the one that caught a real bug in the
traversal check — a documentation page whose own text contains
``root:x:0:0``.
"""

import asyncio
import html as html_mod
import json
import re
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bbhunter import discovery, checks, xssrecon          # noqa: E402

PASS = FAIL = 0
GREEN, RED, DIM, BOLD, OFF = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"


def check(label, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  {GREEN}✓{OFF} {label}")
    else:
        FAIL += 1
        print(f"  {RED}✗{OFF} {label}  {DIM}(got {got!r}, wanted {want!r}){OFF}")


def section(title):
    print(f"\n{BOLD}{title}{OFF}")


# ─────────────────────────────────────────────────────────────────────────────
#  Two applications: one with the bugs, one without
# ─────────────────────────────────────────────────────────────────────────────

STRICT = {"Content-Security-Policy": "default-src 'self'",
          "Strict-Transport-Security": "max-age=63072000",
          "X-Content-Type-Options": "nosniff",
          "X-Frame-Options": "DENY"}


class _Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    secure = False

    def log_message(self, *args):
        pass

    def reply(self, code, body, headers=None, ctype="text/html"):
        raw = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        for key, value in {**(STRICT if self.secure else {}),
                           **(headers or {})}.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def parts(self):
        split = urllib.parse.urlsplit(self.path)
        return split.path, dict(urllib.parse.parse_qsl(split.query,
                                                       keep_blank_values=True))


HOME = """<html><head><title>Shop</title></head><body>
<form action="/search" method="GET">
  <input name="q" value=""><input name="category"><button>Go</button></form>
<form action="/login" method="POST">
  <input name="username"><input type="password" name="password"></form>
<a href="/item?id=1">Item</a> <a href="/download?file=notes.txt">Notes</a>
<a href="/logo.png">logo</a>
<script src="/static/app.js"></script>
<script>var t = location.hash; document.getElementById('x').innerHTML = t;
fetch('/api/v1/orders?order_id=3&include=all');</script>
</body></html>"""

APP_JS = """
const r = await fetch('/api/v1/profile?user_id=' + uid + '&fields=email');
axios.get('/api/v1/invoice?invoice_id=' + id);
const p = new URLSearchParams(location.search); p.get('debug'); p.get('ref');
$.ajax('/legacy/report?report_id=1&format=pdf');
window.addEventListener('message', function (e) { eval(e.data); });
"""

OPENAPI = json.dumps({"paths": {
    "/api/v1/users": {"get": {"parameters": [{"name": "page"},
                                             {"name": "per_page"}]}},
    "/api/v1/tokens": {"get": {"parameters": [{"name": "scope_filter"}]}}}})


class Vulnerable(_Base):
    secure = False

    def do_GET(self):
        path, q = self.parts()
        extra = {}
        origin = self.headers.get("Origin")
        if origin:
            extra["Access-Control-Allow-Origin"] = origin
            extra["Access-Control-Allow-Credentials"] = "true"
        host = self.headers.get("Host")
        if path == "/":
            return self.reply(200, HOME, extra)
        if path == "/static/app.js":
            return self.reply(200, APP_JS, ctype="application/javascript")
        if path == "/robots.txt":
            return self.reply(200, f"User-agent: *\nDisallow: /admin/panel\n"
                                   f"Sitemap: http://{host}/sitemap.xml\n",
                              ctype="text/plain")
        if path == "/sitemap.xml":
            return self.reply(200, f"<urlset><url><loc>http://{host}/news?"
                                   f"article=5</loc></url><url><loc>http://"
                                   f"{host}/go?next=/home</loc></url></urlset>",
                              ctype="application/xml")
        if path == "/openapi.json":
            return self.reply(200, OPENAPI, ctype="application/json")
        if path == "/.git/config":
            return self.reply(200, '[core]\n\trepositoryformatversion = 0\n'
                                   '[remote "origin"]\n\turl = x\n',
                              ctype="text/plain")
        if path == "/.env":
            return self.reply(200, "DB_PASSWORD=hunter2\nAPI_KEY=abc\n",
                              ctype="text/plain")
        if path == "/search":
            return self.reply(200, f"<html><body><h1>Results for "
                                   f"{q.get('q', '')}</h1></body></html>")
        if path == "/item":
            value = q.get("id", "")
            if "'" in value and "AND" not in value.upper():
                return self.reply(500, "<html><body>You have an error in your "
                                       "SQL syntax; check the manual that "
                                       "corresponds to your MySQL server "
                                       "version near ''' at line 1</body></html>")
            if "AND '1'='2" in value:
                return self.reply(200, "<html><body>No such item</body></html>")
            return self.reply(200, "<html><body><h2>Blue widget</h2>"
                                   "<p>In stock</p></body></html>")
        if path == "/go":
            return self.reply(302, "", {"Location": q.get("next", "/")})
        if path == "/download":
            name = q.get("file", "")
            if "etc/passwd" in urllib.parse.unquote(name):
                return self.reply(200, "root:x:0:0:root:/root:/bin/bash\n",
                                  ctype="text/plain")
            return self.reply(200, "<html><body>notes</body></html>")
        if path == "/news":
            return self.reply(200, f"<html><body>Article "
                                   f"{q.get('article', '')}</body></html>")
        if path == "/profile":
            if q.get("debug") == discovery._CANARY:
                return self.reply(200, "<html><body>DEBUG MODE ON — internal "
                                       "build 44, feature flags listed"
                                       "</body></html>")
            return self.reply(200, "<html><body>profile</body></html>")
        return self.reply(404, "<html><body>not found</body></html>")


class Safe(_Base):
    secure = True

    def do_GET(self):
        path, q = self.parts()
        if path == "/":
            return self.reply(200, "<html><head><title>Safe</title></head>"
                                   "<body><a href='/search?q=a'>s</a>"
                                   "</body></html>")
        if path == "/search":
            return self.reply(200, f"<html><body>Results for "
                                   f"{html_mod.escape(q.get('q', ''), quote=True)}"
                                   f"</body></html>")
        if path == "/item":
            return self.reply(200, "<html><body><h2>Blue widget</h2>"
                                   "<p>In stock</p></body></html>")
        if path == "/go":
            dest = q.get("next", "/")
            if (not dest.startswith("/") or dest.startswith("//")
                    or chr(92) in dest or ":" in dest):
                dest = "/"
            return self.reply(302, "", {"Location": dest})
        if path == "/download":
            return self.reply(200, "<html><body>notes</body></html>")
        if path == "/docs":
            # A page that legitimately quotes the traversal signature.
            return self.reply(200, "<html><body><pre>root:x:0:0:root:/root:"
                                   "/bin/bash</pre> example output</body></html>")
        if path == "/flaky":
            import random
            return self.reply(200, f"<html><body>{random.random()}"
                                   f"</body></html>")
        return self.reply(404, "<html><body>not found</body></html>")


def serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


# ─────────────────────────────────────────────────────────────────────────────

async def main():
    vuln_srv, vuln = serve(Vulnerable)
    safe_srv, safe = serve(Safe)
    try:
        await test_discovery(vuln)
        await test_brute(vuln, safe)
        await test_checks_find_the_bugs(vuln)
        await test_checks_stay_quiet(safe)
        await test_redirect_parsing()
        await test_reflection_context()
        await test_xssrecon(vuln, safe)
        test_no_third_party_imports()
    finally:
        vuln_srv.shutdown()
        safe_srv.shutdown()


async def test_discovery(base):
    section("Discovery finds what a query-string parser cannot")
    fetcher = discovery.Fetcher(concurrency=8, timeout=8)
    surface = discovery.Surface()
    await discovery.crawl_page(fetcher, base, surface)
    extra = await discovery.robots_and_sitemap(fetcher, base)
    surface.urls |= extra
    spec = await discovery.openapi_surface(fetcher, base)
    if spec:
        surface.endpoints |= spec["endpoints"]
        for name in spec["parameters"]:
            surface.add_param(name, "openapi")

    names = set(surface.parameters)
    check("form fields are parameters", {"q", "category"} <= names)
    check("so are fields in a POST form", {"username", "password"} <= names)
    check("parameters named in the bundle are found",
          {"user_id", "fields", "invoice_id", "report_id"} <= names)
    check("and in inline script", {"order_id", "include"} <= names)
    check("and in an OpenAPI document",
          {"page", "per_page", "scope_filter"} <= names)
    check("links carry parameters too", "id" in names)
    sources = {s for entry in surface.parameters.values()
               for s in entry["sources"]}
    check("every source is recorded on the parameter",
          {"form", "js", "inline-js", "openapi", "link"} <= sources)

    urls = {u.split(base)[-1] for u in surface.urls}
    check("robots.txt Disallow entries are followed up",
          any("/admin/panel" in u for u in urls))
    check("sitemap entries are collected",
          any("article=5" in u for u in urls))
    check("a GET form becomes a testable URL",
          any("/search?" in u and "q=" in u for u in urls))
    check("image links are not treated as endpoints",
          any(u.endswith("logo.png") for u in urls), False)
    check("the POST form is kept as a form, not invented as a GET URL",
          any(f.method == "POST" for f in surface.forms))
    check("scripts are recorded", len(surface.js_files), 1)

    # The count is the headline number from the bug report.
    check("a single page yields more than the four parameters a whole "
          "1,500-host run used to produce", len(names) > 10)


async def test_brute(vuln, safe):
    section("Hidden parameters, and knowing when not to guess")
    fetcher = discovery.Fetcher(concurrency=8, timeout=8)
    found = await discovery.brute_parameters(fetcher, vuln + "/profile")
    check("a hidden parameter is found by its effect on the response",
          [f["name"] for f in found], ["debug"])
    check("the URL recorded carries a benign value, not the canary",
          discovery._CANARY in (found[0]["url"] if found else ""), False)

    noisy = await discovery.brute_parameters(fetcher, safe + "/flaky")
    check("an endpoint that differs from itself is skipped rather than "
          "reported wholesale", noisy, [])


async def test_checks_find_the_bugs(base):
    section("Built-in checks find the planted bugs with nothing installed")
    fetcher = discovery.Fetcher(concurrency=8, timeout=8)
    urls = [base + p for p in (
        "/search?q=test&category=x", "/item?id=1", "/go?next=/home",
        "/download?file=notes.txt", "/news?article=5")]
    found = await checks.run_checks(fetcher, [base], urls,
                                    log=lambda t, level="info": None)
    titles = " | ".join(f["title"] for f in found)
    categories = {f["category"] for f in found}

    check("the .env file is reported", ".env" in
          " ".join(f["target"] for f in found))
    check("and at critical", any(f["severity"] == "critical" for f in found))
    check("the git directory is reported", "Git repository" in titles)
    check("CORS reflecting an arbitrary origin is reported",
          "CORS misconfiguration" in categories)
    check("the unencoded reflection is reported",
          "Cross-site scripting" in categories)
    check("the SQL error is reported", "SQL error triggered" in titles)
    check("so is the boolean difference", "Boolean-based" in titles)
    check("the open redirect is reported", "Open redirection" in categories)
    check("the traversal is reported", "Path traversal" in categories)
    check("missing headers are reported once, not once per header",
          len([f for f in found if f["category"] == "Security headers"]), 1)

    for row in found:
        if row["category"] in ("SQL injection", "Path traversal",
                               "Open redirection", "Cross-site scripting"):
            break
    check("every finding carries a raw HTTP request to replay",
          all(f["repro"].startswith(("GET ", "POST ", "Open "))
              or "HTTP/1.1" in f["repro"] for f in found))
    check("and names what was observed rather than only what it means",
          all(f.get("evidence") for f in found
              if f["category"] != "Reflection"))


async def test_checks_stay_quiet(base):
    section("…and the correctly-built twin stays quiet")
    fetcher = discovery.Fetcher(concurrency=8, timeout=8)
    urls = [base + p for p in (
        "/search?q=test", "/item?id=1", "/go?next=/home",
        "/download?file=notes.txt", "/docs?file=x", "/flaky?id=1")]
    found = await checks.run_checks(fetcher, [base], urls,
                                    log=lambda t, level="info": None)
    categories = [f["category"] for f in found]
    check("no SQL injection is claimed against a parameterised query",
          "SQL injection" in categories, False)
    check("the allow-listed redirect is not called an open redirect",
          "Open redirection" in categories, False)
    check("a page that quotes /etc/passwd is not called a traversal",
          "Path traversal" in categories, False)
    check("escaped output is not called cross-site scripting",
          "Cross-site scripting" in categories, False)
    check("no exposed files are invented",
          "Information disclosure" in categories, False)
    check("a strict CSP produces no header finding",
          "Security headers" in categories, False)
    check("the encoded reflection is still recorded, as information",
          any(f["category"] == "Reflection" and f["severity"] == "info"
              for f in found))
    check("and nothing else at all is reported",
          sorted({f["category"] for f in found}), ["Reflection"])


async def test_redirect_parsing():
    section("Where a browser will actually go")
    cases = [
        ("https://example.net/", "example.net"),
        ("//example.net/", "example.net"),
        ("/\\example.net/", "example.net"),
        ("https:/example.net/", "example.net"),
        ("/dashboard", ""),
        ("/?from=example.net", ""),
        ("", ""),
    ]
    for location, want in cases:
        host, _ = checks.redirect_destination(location)
        check(f"{location!r} → {want!r}", host, want)


async def test_reflection_context():
    section("Reflection context")
    token = "CANARY"
    cases = [
        (f"<p>{token}</p>", "html"),
        (f'<img src="x" alt="{token}">', "attribute_double"),
        (f"<img src='x' alt='{token}'>", "attribute_single"),
        (f"<script>var a = '{token}';</script>", "script"),
        (f"<!-- {token} -->", "comment"),
    ]
    for body, want in cases:
        check(f"{want} context is identified",
              checks.reflection_context(body, token), want)


async def test_xssrecon(vuln, safe):
    section("XSS Recon ranks the right way round")
    options = xssrecon.ReconOptions(profile="dom-based", scope_urls=[vuln],
                                    concurrency=6)
    run = xssrecon.ReconRun(options, emit=lambda k, p: None)
    await run.run()
    report = run.results[0]
    check("an application with sinks, sources and no CSP is worth testing",
          report.verdict, "worth testing")
    check("the sink is named", "innerHTML" in report.sinks)
    check("so is the source", "location.hash" in report.sources)
    check("an unguarded postMessage handler is counted",
          report.postmessage_unchecked >= 1)
    check("every signal that moved the score is recorded",
          len(report.signals) >= 4)
    check("and the signals explain the number, not just repeat it",
          any("sink" in s for s in report.signals))

    options = xssrecon.ReconOptions(profile="dom-based", scope_urls=[safe],
                                    concurrency=6)
    quiet = xssrecon.ReconRun(options, emit=lambda k, p: None)
    await quiet.run()
    check("a strict-CSP application with no custom JavaScript is not",
          quiet.results[0].verdict, "not a priority")
    check("and scores below the one that is",
          quiet.results[0].score < report.score)

    message = ""
    try:
        await xssrecon.hackerone_programs(discovery.Fetcher(), "no-colon-here")
    except ValueError as exc:
        message = str(exc)
    check("a key in the wrong format is explained, not just rejected",
          "identifier" in message and "hackerone.com/settings" in message)
    check("version comparison handles multi-digit parts",
          xssrecon._lt("3.10.0", "3.9.0"), False)
    check("and orders correctly", xssrecon._lt("3.4.1", "3.5.0"))
    check("a vendor bundle is not read as the application's own code",
          xssrecon.classify_script("/static/vendor.4f2a.js", "x")[0], False)
    check("an application bundle is",
          xssrecon.classify_script("/static/app.4f2a.js", "x")[0])


def test_no_third_party_imports():
    """The overhaul must stay installable on a box it must not disturb.

    The original target-finder script needed requests, selenium,
    webdriver-manager and wakepy. On Kali, installing those with
    --break-system-packages uninstalled the system `requests` to put a newer
    one in its place, which quietly breaks every other tool pinned below it.
    The fix was not a better install command, it was to need nothing: so this
    asserts that none of the three new modules imports anything outside the
    standard library, and fails the build if somebody adds one.
    """
    import ast
    section("Nothing to install, so nothing to break")
    stdlib = set(sys.stdlib_module_names)
    for name in ("discovery.py", "checks.py", "xssrecon.py"):
        path = ROOT / "bbhunter" / name
        tree = ast.parse(path.read_text())
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and not node.level:
                if node.module:
                    found.add(node.module.split(".")[0])
        outside = sorted(m for m in found
                         if m not in stdlib and m != "bbhunter")
        check(f"{name} imports only the standard library", outside, [])


if __name__ == "__main__":
    asyncio.run(main())
    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)
