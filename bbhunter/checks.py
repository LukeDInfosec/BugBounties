#!/usr/bin/env python3
"""Checks that find things with nothing installed.

The reason this file exists: a run against 1,500 live hosts reported zero
findings. Not "nothing serious" — zero rows. Every stage capable of producing
a finding was gated behind a Go binary (``nuclei``, ``dalfox``) and, below
that, behind a parameter list that was empty for the reasons set out in
``discovery.py``. With neither installed, the framework walked an entire
estate and reported nothing, which is indistinguishable from a clean result
and is far more dangerous than an error.

So the design rule here is: **the framework must find things on its own.** An
external scanner, when present, is an improvement on this, not a prerequisite
for it. Everything below is standard library and sends ordinary HTTP.

What each check will and will not claim is the other half of the design. A
reflection is not a cross-site scripting vulnerability, a `Location` header
pointing somewhere else is not always an open redirect, and a database error
in a response is not proof of SQL injection. Each check states what it
actually observed, carries the request that produced it, and marks itself
confirmed only when the observation cannot reasonably be anything else. Every
finding carries a raw HTTP request so it can be replayed by hand.
"""

from __future__ import annotations

import asyncio
import re
import urllib.parse

from .discovery import Fetcher, Response

# ─────────────────────────────────────────────────────────────────────────────
#  Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

CANARY = "bbh9z1q"


def raw_request(method, url, headers=None, body=""):
    """The request as raw HTTP/1.1, for pasting into Burp Repeater."""
    parts = urllib.parse.urlsplit(url)
    target = parts.path or "/"
    if parts.query:
        target += "?" + parts.query
    lines = [f"{method} {target} HTTP/1.1", f"Host: {parts.netloc}"]
    for name, value in (headers or {}).items():
        lines.append(f"{name}: {value}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
        lines.append("")
        lines.append(body)
    else:
        lines.append("")
        lines.append("")
    return "\r\n".join(lines)


def set_param(url, name, value):
    parts = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    replaced, out = False, []
    for key, existing in pairs:
        if key == name:
            out.append((key, value))
            replaced = True
        else:
            out.append((key, existing))
    if not replaced:
        out.append((name, value))
    return urllib.parse.urlunsplit(
        parts._replace(query=urllib.parse.urlencode(out)))


def param_names(url):
    try:
        return [k for k, _ in urllib.parse.parse_qsl(
            urllib.parse.urlsplit(url).query, keep_blank_values=True)]
    except Exception:
        return []


def finding(severity, title, category, target, **kwargs):
    row = {"severity": severity, "title": title, "category": category,
           "target": target, "tool": "bbhunter", "confidence": "tentative"}
    row.update(kwargs)
    return row


# ─────────────────────────────────────────────────────────────────────────────
#  Reflection and cross-site scripting
# ─────────────────────────────────────────────────────────────────────────────
#
# Three steps, and the third is the one that matters. Plenty of scanners stop
# at "the input came back in the response" and report an XSS; most of those
# are encoded, in a comment, or inside a JSON string, and a report full of
# them is why people stop reading scanner output. So: reflect, then work out
# *where* it landed, then send the characters that would be needed to break
# out of that specific place and check whether they survived.

_CONTEXTS = (
    ("script", re.compile(r"<script[^>]*>(?:(?!</script>).)*?%s", re.I | re.S)),
    ("attribute_unquoted", re.compile(r"<[^>]+=\s*[^\s\"'>]*%s", re.I)),
    ("attribute_single", re.compile(r"<[^>]+='[^']*%s", re.I)),
    ("attribute_double", re.compile(r'<[^>]+="[^"]*%s', re.I)),
    ("comment", re.compile(r"<!--(?:(?!-->).)*?%s", re.I | re.S)),
    ("html", re.compile(r"%s")),
)

#: What has to survive for the reflection to be exploitable in that context.
_BREAKOUT = {
    "html": "<>\"'",
    "attribute_double": "\"><",
    "attribute_single": "'><",
    "attribute_unquoted": " ><",
    "script": "'\";</",
    "comment": "-->",
}


def reflection_context(body, token):
    """Where in the document the token landed, most specific first."""
    escaped = re.escape(token)
    for name, pattern in _CONTEXTS:
        try:
            if re.search(pattern.pattern % escaped, body,
                         pattern.flags):
                return name
        except re.error:
            continue
    return ""


async def check_reflection(fetcher, url, scope_ok=None, log=None):
    """Reflected input, with the context and whether a break-out survives."""
    names = param_names(url)
    if not names:
        return []
    out = []
    for name in names[:12]:
        probe = set_param(url, name, CANARY)
        resp = await fetcher.get(probe)
        if resp is None or not resp.status or CANARY not in (resp.body or ""):
            continue
        context = reflection_context(resp.body, CANARY) or "html"
        needed = _BREAKOUT.get(context, "<>\"'")
        # Send the breakout characters wrapped around the canary so the exact
        # survivors can be measured, rather than guessing from an encoder's
        # reputation.
        marker = f"{CANARY}{needed}{CANARY}"
        confirm = await fetcher.get(set_param(url, name, marker))
        if confirm is None or not confirm.status:
            continue
        survived = ""
        for char in needed:
            if f"{CANARY}{char}" in (confirm.body or "") or \
                    (char in (confirm.body or "") and marker[:len(CANARY) + 1]
                     in (confirm.body or "")):
                survived += char
        raw_survivors = [c for c in needed
                         if c in _between(confirm.body or "", CANARY, CANARY)]
        survived = "".join(raw_survivors)

        if not survived:
            out.append(finding(
                "info",
                f"Input reflected but encoded: {name}",
                "Reflection",
                probe,
                matcher=name,
                detail=(f"The value of '{name}' is reflected into the response "
                        f"in a {context.replace('_', ' ')} context, but every "
                        f"character needed to break out of it "
                        f"({needed!r}) was encoded or stripped. Recorded "
                        f"because a later code change can remove the encoding, "
                        f"not because it is exploitable now."),
                evidence=f"context={context} survivors=none",
                confidence="confirmed",
                repro=raw_request("GET", probe),
            ))
            continue

        severity = "high" if context in ("html", "script",
                                         "attribute_unquoted") else "medium"
        out.append(finding(
            severity,
            f"Unencoded reflection in '{name}' ({context.replace('_', ' ')})",
            "Cross-site scripting",
            probe,
            matcher=name,
            detail=(f"The value of '{name}' is reflected into a "
                    f"{context.replace('_', ' ')} context and the characters "
                    f"{survived!r} survive unencoded. Those are the characters "
                    f"needed to break out of that context, so this is a "
                    f"candidate for cross-site scripting. It is NOT confirmed "
                    f"as XSS: that requires a payload executing in a browser, "
                    f"which this check does not do."),
            evidence=(f"context={context} needed={needed!r} "
                      f"survived={survived!r}"),
            confidence="tentative",
            repro=raw_request("GET", set_param(url, name, marker)),
            data={"parameter": name, "context": context,
                  "survivors": survived,
                  "next_step": ("Open the URL in a browser with a real payload "
                                "for this context and confirm "
                                "alert(document.domain) fires.")},
        ))
    return out


def _between(text, left, right):
    """The text between the first ``left`` and the next ``right`` after it."""
    start = text.find(left)
    if start < 0:
        return ""
    start += len(left)
    end = text.find(right, start)
    return text[start:end] if end > start else text[start:start + 40]


# ─────────────────────────────────────────────────────────────────────────────
#  Open redirect
# ─────────────────────────────────────────────────────────────────────────────

REDIRECT_PARAMS = {"redirect", "redirect_uri", "redirect_url", "redirecturl",
                   "url", "next", "return", "returnurl", "return_url",
                   "returnto", "return_to", "dest", "destination", "continue",
                   "go", "goto", "target", "forward", "back", "rurl",
                   "checkout_url", "callback", "to", "out", "view", "image_url",
                   "r", "u", "link"}

_PAYLOAD_HOST = "example.net"
_REDIRECT_PAYLOADS = (
    f"https://{_PAYLOAD_HOST}/",
    f"//{_PAYLOAD_HOST}/",
    f"https:/{_PAYLOAD_HOST}/",
    f"/\\{_PAYLOAD_HOST}/",
)


def redirect_destination(location):
    """``(host the browser will go to, how)`` for a Location value.

    The parsing matters more than it looks. A check that decides "the payload
    host appears somewhere in the Location string" calls ``/?from=evil.com``
    an open redirect, and a check that only accepts an absolute URL misses
    the three forms that actually get past a naive allow-list:

      ``//host/``   protocol-relative — the browser supplies the scheme;
      ``/\\host/``   a backslash in the authority position, which Chrome,
                    Firefox and Safari all normalise to ``//host/`` while a
                    server-side ``startswith('/')`` check reads it as a local
                    path. This is the single most common bypass of a
                    hand-written redirect allow-list;
      ``https:/host/`` a missing slash, normalised the same way.

    So the destination is worked out the way a browser works it out, and the
    sentence returned explains which case fired — a reviewer reading
    "redirects to example.net" with a Location of ``/\\example.net/`` would
    otherwise reasonably think the tool was wrong.
    """
    raw = (location or "").strip()
    if not raw:
        return "", ""
    normalised = raw.replace("\\", "/")
    how = ""
    if normalised.startswith("//"):
        if "\\" in raw:
            how = ("The Location is a path to the server, but the backslash "
                   "sits where the authority goes and every major browser "
                   "normalises it to '//', making this an external redirect.")
        else:
            how = ("The Location is protocol-relative, so the browser keeps "
                   "the current scheme and goes to the host given.")
        return urllib.parse.urlsplit("https:" + normalised).netloc, how
    if re.match(r"^[a-z][a-z0-9+.-]*:/(?!/)", normalised, re.I):
        how = ("The Location has a scheme with a single slash; browsers "
               "normalise this to a full URL.")
        scheme, _, rest = normalised.partition(":")
        return urllib.parse.urlsplit(f"{scheme}://{rest.lstrip('/')}").netloc, how
    if "://" in normalised:
        return urllib.parse.urlsplit(normalised).netloc, \
            "The Location is an absolute URL."
    if raw.startswith("(client-side)"):
        return raw.split()[-1], ("The redirect happens in JavaScript or a "
                                 "meta refresh rather than in a header.")
    return "", ""


async def check_open_redirect(fetcher, url, scope_ok=None, log=None):
    """A redirect parameter that will send a user to a host we chose.

    The verdict is taken from the Location header of an *unfollowed* response,
    because following it throws away the evidence — once urllib has chased the
    302 the status is 200 and the only thing left is somebody else's page.
    """
    names = [n for n in param_names(url) if n.lower() in REDIRECT_PARAMS]
    if not names:
        return []
    out = []
    for name in names[:6]:
        for payload in _REDIRECT_PAYLOADS:
            probe = set_param(url, name, payload)
            resp = await fetcher.get(probe, follow=False)
            if resp is None or not resp.status:
                continue
            location = resp.header("Location")
            if not location:
                # A meta refresh or a JavaScript assignment is the same bug.
                if resp.status == 200 and re.search(
                        r"(?:http-equiv=[\"']refresh[\"'][^>]*url=|"
                        r"location\.(?:href|replace|assign)\s*[=\(]\s*[\"'])"
                        r"[^\"'>]*" + re.escape(_PAYLOAD_HOST),
                        resp.body or "", re.I):
                    location = f"(client-side) {_PAYLOAD_HOST}"
                else:
                    continue
            host, how = redirect_destination(location)
            if host != _PAYLOAD_HOST:
                continue
            out.append(finding(
                "medium",
                f"Open redirect via '{name}'",
                "Open redirection",
                probe,
                matcher=name,
                detail=(f"Setting '{name}' to {payload!r} made the application "
                        f"redirect to a host supplied in the request "
                        f"({location[:200]}). {how} The destination is not "
                        f"checked against an allow-list, so this URL can be "
                        f"used to send a user to any site while the link they "
                        f"see belongs to the target."),
                evidence=f"HTTP {resp.status}  Location: {location[:300]}",
                confidence="confirmed",
                repro=raw_request("GET", probe),
                data={"parameter": name, "payload": payload},
            ))
            break
    return out


# ─────────────────────────────────────────────────────────────────────────────
#  SQL injection (error and boolean)
# ─────────────────────────────────────────────────────────────────────────────

SQL_ERRORS = (
    ("MySQL", re.compile(r"SQL syntax.*MySQL|Warning.*\bmysqli?_|"
                         r"MySqlException|check the manual that corresponds to "
                         r"your (?:MySQL|MariaDB) server version", re.I)),
    ("PostgreSQL", re.compile(r"PostgreSQL.*ERROR|Warning.*\bpg_|"
                              r"Npgsql\.|PG::SyntaxError|"
                              r"unterminated quoted string at or near", re.I)),
    ("MSSQL", re.compile(r"Microsoft SQL (?:Native Client|Server)|"
                         r"Unclosed quotation mark after the character string|"
                         r"System\.Data\.SqlClient\.SqlException", re.I)),
    ("Oracle", re.compile(r"\bORA-\d{5}|Oracle error|quoted string not properly "
                          r"terminated", re.I)),
    ("SQLite", re.compile(r"SQLite/JDBCDriver|sqlite3?\.OperationalError|"
                          r"SQLITE_ERROR|unrecognized token:", re.I)),
)


def database_error(body):
    for engine, pattern in SQL_ERRORS:
        match = pattern.search(body or "")
        if match:
            start = max(0, match.start() - 60)
            return engine, (body[start:match.end() + 140]).strip()
    return None


async def check_sqli(fetcher, url, scope_ok=None, log=None):
    """Error-based and boolean-based probing of each parameter.

    Boolean is the stronger of the two and is the reason this is here rather
    than relying on an error signature: a well-configured application does not
    print its database errors, but it will still evaluate ``1 AND 1=1``
    differently from ``1 AND 1=2`` if the value reaches a query.
    """
    names = param_names(url)
    if not names:
        return []
    out = []
    control = await fetcher.get(url)
    if control is None or not control.status:
        return []
    control2 = await fetcher.get(url)
    if control2 is None or _fingerprint(control) != _fingerprint(control2):
        return []                      # unstable endpoint: no verdict possible

    for name in names[:10]:
        original = dict(urllib.parse.parse_qsl(
            urllib.parse.urlsplit(url).query, keep_blank_values=True)).get(name, "")

        # 1. Error signature.
        for probe_value in (f"{original}'", f"{original}\"", f"{original}')"):
            probe = set_param(url, name, probe_value)
            resp = await fetcher.get(probe)
            if resp is None or not resp.status:
                continue
            if database_error(control.body) :
                break                   # the page always prints errors
            hit = database_error(resp.body)
            if hit:
                engine, excerpt = hit
                out.append(finding(
                    "high",
                    f"SQL error triggered by '{name}'",
                    "SQL injection",
                    probe,
                    matcher=name,
                    detail=(f"Appending {probe_value[len(original):]!r} to "
                            f"'{name}' made the application return a {engine} "
                            f"error that the unmodified request does not "
                            f"produce. The value is reaching a query without "
                            f"being parameterised."),
                    evidence=excerpt[:400],
                    confidence="firm",
                    repro=raw_request("GET", probe),
                    data={"parameter": name, "engine": engine},
                ))
                break

        # 2. Boolean differential.
        true_value = f"{original}' AND '1'='1"
        false_value = f"{original}' AND '1'='2"
        true_resp = await fetcher.get(set_param(url, name, true_value))
        false_resp = await fetcher.get(set_param(url, name, false_value))
        if not (true_resp and false_resp and true_resp.status and false_resp.status):
            continue
        same_as_control = _fingerprint(true_resp) == _fingerprint(control)
        differs = _fingerprint(true_resp) != _fingerprint(false_resp)
        if same_as_control and differs:
            # Confirm serially before claiming it. The first pass runs inside
            # a batch of sixty concurrent requests, and a server under that
            # much load from one client truncates, queues or drops responses —
            # which looks exactly like a page that changed. A safe test
            # application produced a confident "boolean-based SQL injection"
            # this way, and only under concurrency; run the same three
            # requests one at a time and the difference disappears. So the
            # concurrent pass is a filter, and this is the verdict.
            if not await self_confirm_boolean(fetcher, url, name,
                                              true_value, false_value):
                continue
            out.append(finding(
                "high",
                f"Boolean-based SQL injection in '{name}'",
                "SQL injection",
                set_param(url, name, true_value),
                matcher=name,
                detail=(f"A condition supplied in '{name}' was evaluated by "
                        f"the application: the TRUE form returned the original "
                        f"page and the FALSE form returned something different. "
                        f"That difference cannot be produced by an error "
                        f"handler, and it is the behaviour of a value being "
                        f"concatenated into a SQL query."),
                evidence=(f"TRUE  -> HTTP {true_resp.status}, "
                          f"{len(true_resp.body)} bytes\n"
                          f"FALSE -> HTTP {false_resp.status}, "
                          f"{len(false_resp.body)} bytes\n"
                          f"control -> HTTP {control.status}, "
                          f"{len(control.body)} bytes"),
                confidence="firm",
                repro=raw_request("GET", set_param(url, name, true_value)),
                data={"parameter": name,
                      "true_payload": true_value,
                      "false_payload": false_value},
            ))
    return out


async def self_confirm_boolean(fetcher, url, name, true_value, false_value,
                               rounds=2):
    """Re-run a boolean differential one request at a time.

    Every round must agree: control and TRUE identical, FALSE different. Two
    rounds rather than one because a single quiet repeat can still coincide
    with a cache filling or a connection being reused for the first time.
    """
    for _ in range(rounds):
        control = await fetcher.get(url)
        true_resp = await fetcher.get(set_param(url, name, true_value))
        false_resp = await fetcher.get(set_param(url, name, false_value))
        if not (control and true_resp and false_resp):
            return False
        if not (control.status and true_resp.status and false_resp.status):
            return False
        if _fingerprint(true_resp) != _fingerprint(control):
            return False
        if _fingerprint(true_resp) == _fingerprint(false_resp):
            return False
    return True


def _fingerprint(resp):
    """Exact, for the same reason as discovery._shape.

    The boolean test is only run after two identical control requests have
    agreed, so an endpoint that varies by itself never reaches this. Once
    that holds, rounding the length only loses real differences.
    """
    if resp is None:
        return (0, 0, 0)
    body = resp.body or ""
    return (resp.status, len(body), body.count("<"))


# ─────────────────────────────────────────────────────────────────────────────
#  Path traversal
# ─────────────────────────────────────────────────────────────────────────────

TRAVERSAL_PARAMS = {"file", "filename", "path", "doc", "document", "folder",
                    "dir", "download", "page", "template", "include", "src",
                    "load", "read", "view", "name", "report", "attachment",
                    "image", "img", "pdf", "log", "conf", "config"}

_TRAVERSAL = (
    ("../../../../../../etc/passwd", re.compile(r"root:[x*!]?:0:0:")),
    ("....//....//....//....//etc/passwd", re.compile(r"root:[x*!]?:0:0:")),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", re.compile(r"root:[x*!]?:0:0:")),
    ("/etc/passwd", re.compile(r"root:[x*!]?:0:0:")),
    ("..\\..\\..\\..\\windows\\win.ini", re.compile(r"\[fonts\]|for 16-bit app",
                                                   re.I)),
    ("../../../../windows/win.ini", re.compile(r"\[fonts\]|for 16-bit app",
                                               re.I)),
)


async def check_traversal(fetcher, url, scope_ok=None, log=None):
    names = [n for n in param_names(url) if n.lower() in TRAVERSAL_PARAMS]
    if not names:
        return []
    control = await fetcher.get(url)
    control_body = (control.body if control else "") or ""
    out = []
    for name in names[:6]:
        for payload, signature in _TRAVERSAL:
            if signature.search(control_body):
                break               # the page already contains the signature
            probe = set_param(url, name, payload)
            resp = await fetcher.get(probe)
            if resp is None or not resp.ok:
                continue
            match = signature.search(resp.body or "")
            if not match:
                continue
            out.append(finding(
                "high",
                f"Path traversal via '{name}'",
                "Path traversal",
                probe,
                matcher=name,
                detail=(f"Setting '{name}' to {payload!r} returned the "
                        f"contents of a file outside the web root. The "
                        f"parameter is used to build a file path without "
                        f"being constrained to a directory."),
                evidence=(resp.body or "")[max(0, match.start() - 40):
                                           match.end() + 200],
                confidence="confirmed",
                repro=raw_request("GET", probe),
                data={"parameter": name, "payload": payload},
            ))
            break
    return out


# ─────────────────────────────────────────────────────────────────────────────
#  CORS
# ─────────────────────────────────────────────────────────────────────────────

async def check_cors(fetcher, url, scope_ok=None, log=None):
    """An origin we chose, reflected into Access-Control-Allow-Origin.

    Only a finding when credentials are also allowed, or when the origin is
    reflected verbatim. ``*`` without credentials is the documented, intended
    configuration for a public API and reporting it is noise.
    """
    host = urllib.parse.urlsplit(url).netloc
    probes = [
        ("https://evil.example", "reflected arbitrary origin"),
        (f"https://{host}.evil.example", "suffix-matched origin"),
        (f"https://evil{host}", "prefix-matched origin"),
        ("null", "null origin"),
    ]
    out = []
    for origin, label in probes:
        resp = await fetcher.get(url, headers={"Origin": origin})
        if resp is None or not resp.status:
            continue
        allow = resp.header("Access-Control-Allow-Origin")
        creds = resp.header("Access-Control-Allow-Credentials").lower() == "true"
        if not allow:
            continue
        if allow.strip() == origin and (creds or origin != "null"):
            out.append(finding(
                "high" if creds else "medium",
                f"CORS accepts {label}",
                "CORS misconfiguration",
                url,
                matcher="Access-Control-Allow-Origin",
                detail=(f"The application echoed the Origin header "
                        f"({origin}) back in Access-Control-Allow-Origin"
                        + (" with Access-Control-Allow-Credentials: true, so a "
                           "page on that origin can read authenticated "
                           "responses from this endpoint."
                           if creds else
                           ", so any site can read responses from this "
                           "endpoint. Without credentials this is only "
                           "serious if the response contains anything "
                           "sensitive.")),
                evidence=(f"Origin: {origin}\n"
                          f"Access-Control-Allow-Origin: {allow}\n"
                          f"Access-Control-Allow-Credentials: {creds}"),
                confidence="confirmed",
                repro=raw_request("GET", url, {"Origin": origin}),
            ))
            break
    return out


# ─────────────────────────────────────────────────────────────────────────────
#  Exposed files
# ─────────────────────────────────────────────────────────────────────────────
#
# Each entry is a path, and a signature that must be present in the response.
# The signature is the whole point: a single-page application answers 200 with
# its index page for every path on the server, so a status code means nothing
# and a scanner that trusts one reports every path in its wordlist.

EXPOSED = (
    ("/.git/config", re.compile(r"\[core\]|\[remote\s"), "high",
     "Git repository exposed",
     "The .git directory is served. The full source history, including any "
     "credentials ever committed, can be reconstructed from it."),
    ("/.git/HEAD", re.compile(r"^ref:\s+refs/"), "high",
     "Git repository exposed", "The .git directory is served."),
    ("/.env", re.compile(r"(?m)^\s*[A-Z][A-Z0-9_]{2,}\s*="), "critical",
     "Environment file exposed",
     "A .env file is served. These hold database credentials, API keys and "
     "signing secrets."),
    ("/.svn/entries", re.compile(r"^\d+\s"), "medium",
     "Subversion metadata exposed", "The .svn directory is served."),
    ("/.DS_Store", re.compile(r"\x00\x00\x00\x01Bud1"), "low",
     "DS_Store exposed",
     "A .DS_Store file lists the names of every file in the directory, "
     "including ones not linked from anywhere."),
    ("/server-status", re.compile(r"Apache Server Status"), "medium",
     "Apache server-status exposed",
     "mod_status is public. It lists the URLs other users are requesting, "
     "including ones with tokens in the query string."),
    ("/.well-known/security.txt", re.compile(r"Contact:", re.I), "info",
     "security.txt published",
     "Not a vulnerability — recorded because it names where to report."),
    ("/phpinfo.php", re.compile(r"phpinfo\(\)|PHP Version"), "medium",
     "phpinfo exposed",
     "phpinfo() discloses the full configuration, paths and loaded modules."),
    ("/.aws/credentials", re.compile(r"aws_access_key_id", re.I), "critical",
     "AWS credentials exposed", "An AWS credentials file is served."),
    ("/config.json", re.compile(r"(?:password|secret|api_?key)\s*[\"']?\s*:",
                                re.I), "high",
     "Configuration file exposed",
     "A configuration document containing secret-looking keys is served."),
    ("/.npmrc", re.compile(r"_authToken", re.I), "high",
     "npm token exposed", "An .npmrc containing an auth token is served."),
    ("/docker-compose.yml", re.compile(r"(?m)^\s*(?:services|version)\s*:"),
     "medium", "docker-compose file exposed",
     "The compose file names internal services, images and often environment "
     "secrets."),
    ("/.git-credentials", re.compile(r"https?://[^:]+:[^@]+@"), "critical",
     "Git credentials exposed",
     "A .git-credentials file containing a username and password is served."),
    ("/backup.sql", re.compile(r"(?:CREATE TABLE|INSERT INTO)", re.I), "critical",
     "Database dump exposed", "A SQL dump is served."),
    ("/.htpasswd", re.compile(r"^[^:]+:\$[0-9a-z]"), "high",
     "htpasswd exposed", "A password file with hashes is served."),
)


async def check_exposed_files(fetcher, base, scope_ok=None, log=None):
    """Sensitive files served from the web root, confirmed by content."""
    # A control request for a path that cannot exist tells us whether this
    # host answers 200 for everything.
    control = await fetcher.get(
        urllib.parse.urljoin(base, "/bbhunter-does-not-exist-9z1q"))
    soft404 = bool(control and control.status == 200)
    control_body = (control.body if control else "") or ""

    paths = [urllib.parse.urljoin(base, path) for path, *_ in EXPOSED]
    responses = await fetcher.many(paths, limit=200_000)
    out = []
    for (path, signature, severity, title, detail), resp in zip(EXPOSED, responses):
        if resp is None or resp.status != 200 or not resp.body:
            continue
        if soft404 and resp.body[:500] == control_body[:500]:
            continue
        try:
            if not signature.search(resp.body):
                continue
        except Exception:
            continue
        out.append(finding(
            severity, title, "Information disclosure",
            urllib.parse.urljoin(base, path),
            matcher=path,
            detail=detail,
            evidence=(resp.body or "")[:400],
            confidence="confirmed",
            repro=raw_request("GET", urllib.parse.urljoin(base, path)),
        ))
    return out


# ─────────────────────────────────────────────────────────────────────────────
#  Headers and cookies
# ─────────────────────────────────────────────────────────────────────────────

async def check_headers(fetcher, base, scope_ok=None, log=None):
    """Transport and browser-policy headers, reported once per application.

    Deliberately low severity and deliberately one finding covering the lot.
    Six separate 'missing header' rows per host is how a findings list becomes
    something nobody opens.
    """
    resp = await fetcher.get(base)
    if resp is None or not resp.status:
        return []
    out = []
    missing = []
    headers = {k.lower(): v for k, v in (resp.headers or {}).items()}

    if "content-security-policy" not in headers:
        missing.append("Content-Security-Policy")
    else:
        csp = headers["content-security-policy"]
        weak = [d for d in ("'unsafe-inline'", "'unsafe-eval'") if d in csp]
        if weak:
            out.append(finding(
                "low", "Content-Security-Policy permits unsafe sources",
                "Security headers", base,
                matcher="Content-Security-Policy",
                detail=(f"The policy contains {', '.join(weak)}, which removes "
                        f"most of the protection a CSP gives against "
                        f"cross-site scripting."),
                evidence=csp[:400], confidence="confirmed",
                repro=raw_request("GET", base)))
    if "strict-transport-security" not in headers and base.startswith("https"):
        missing.append("Strict-Transport-Security")
    if "x-content-type-options" not in headers:
        missing.append("X-Content-Type-Options")
    if "x-frame-options" not in headers and \
            "frame-ancestors" not in headers.get("content-security-policy", ""):
        missing.append("X-Frame-Options or CSP frame-ancestors")

    if missing:
        out.append(finding(
            "info", f"{len(missing)} security header(s) not set",
            "Security headers", base,
            matcher=", ".join(missing),
            detail=("These headers are not set on the application's main "
                    "response: " + ", ".join(missing) + ". None of these is a "
                    "vulnerability on its own; they are defence in depth and "
                    "are listed here so they can be raised together rather "
                    "than as separate findings."),
            evidence="\n".join(f"{k}: {v}" for k, v in
                               sorted((resp.headers or {}).items()))[:600],
            confidence="confirmed",
            repro=raw_request("GET", base)))

    for cookie in _set_cookies(resp):
        name = cookie.split("=", 1)[0].strip()
        lowered = cookie.lower()
        issues = []
        if "httponly" not in lowered:
            issues.append("not HttpOnly")
        if base.startswith("https") and "secure" not in lowered:
            issues.append("not Secure")
        if "samesite" not in lowered:
            issues.append("no SameSite")
        looks_session = re.search(
            r"(sess|sid|auth|token|jwt|login|remember)", name, re.I)
        if issues and looks_session:
            out.append(finding(
                "low", f"Session cookie '{name}' missing flags",
                "Cookies", base, matcher=name,
                detail=(f"The cookie '{name}' looks like a session cookie and "
                        f"is {', '.join(issues)}."),
                evidence=cookie[:300], confidence="confirmed",
                repro=raw_request("GET", base)))
    return out


def _set_cookies(resp):
    out = []
    for key, value in (resp.headers or {}).items():
        if key.lower() == "set-cookie":
            out.append(value)
    return out


# ─────────────────────────────────────────────────────────────────────────────
#  The pass
# ─────────────────────────────────────────────────────────────────────────────

PER_HOST_CHECKS = (
    ("exposed", check_exposed_files),
    ("headers", check_headers),
    ("cors", check_cors),
)

PER_URL_CHECKS = (
    ("reflection", check_reflection),
    ("redirect", check_open_redirect),
    ("sqli", check_sqli),
    ("traversal", check_traversal),
)


async def run_checks(fetcher, hosts, urls, scope_ok=None, log=None,
                     enabled=None, host_cap=300, url_cap=800,
                     on_finding=None):
    """Every built-in check, across hosts and parameterised URLs.

    Returns the findings. A check that raises is logged and skipped — one
    malformed response on one host must not end a scan that has been running
    for an hour.
    """
    wanted = set(enabled or
                 [k for k, _ in PER_HOST_CHECKS] + [k for k, _ in PER_URL_CHECKS])
    findings = []

    async def guarded(name, func, target):
        try:
            return await func(fetcher, target, scope_ok=scope_ok, log=log)
        except Exception as exc:                                # noqa: BLE001
            if log:
                log(f"  {name} failed on {target[:80]}: "
                    f"{type(exc).__name__}", "warn")
            return []

    tasks = []
    for host in list(hosts)[:host_cap]:
        for name, func in PER_HOST_CHECKS:
            if name in wanted:
                tasks.append(guarded(name, func, host))
    for url in list(urls)[:url_cap]:
        for name, func in PER_URL_CHECKS:
            if name in wanted:
                tasks.append(guarded(name, func, url))

    for batch_start in range(0, len(tasks), 60):
        batch = tasks[batch_start:batch_start + 60]
        for result in await asyncio.gather(*batch):
            for row in result or []:
                findings.append(row)
                if on_finding:
                    on_finding(row)
    return findings
