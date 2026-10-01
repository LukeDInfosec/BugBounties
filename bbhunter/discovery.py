#!/usr/bin/env python3
"""Finding the attack surface, without needing six Go binaries on PATH.

This module exists because of a specific, measurable failure. A run against a
wildcard scope found 1,500 live hosts and **four parameters**, and every active
stage downstream reported nothing — not because the targets were clean, but
because nothing had been handed to them to test.

The cause was that parameter discovery was *passive in the worst sense*: it
parsed ``?a=b`` out of whatever URLs a link-following crawler had already
collected. That crawler visited 30 seed hosts to a depth of 2 with a 400-page
cap, ignored forms entirely, and never read a line of JavaScript. On a modern
application almost no parameters appear in anchor hrefs, so the input to every
injection check was a near-empty file, and an empty input produces an empty
report that looks exactly like a clean target.

So the fix is not a bigger cap. It is to go and get the parameters from the
places they actually live:

  **Archives.** Every URL the site has ever exposed, with its query strings,
  sitting in the Wayback CDX index, urlscan.io, AlienVault OTX and Common
  Crawl. This is the single largest source and it costs the target nothing —
  not one request is sent to them. ``gau`` does this; this does it over plain
  HTTP so it works with nothing installed.

  **Forms.** Every login, search, filter and checkout form on the site names
  its own parameters in ``name=`` attributes. A query-string parser cannot see
  any of them. This is where the bulk of a real application's input surface is.

  **JavaScript.** Single-page applications build their requests in code. The
  endpoint list and the parameter names are in the bundle, as fetch/axios/XHR
  calls, as query-string template literals, and as object keys passed to
  request builders.

  **robots.txt, sitemaps and OpenAPI documents.** Three files that frequently
  describe the entire application, including the paths somebody did not want
  indexed, which are usually the interesting ones.

  **Brute force, last.** Only once the passive sources are exhausted, and only
  against endpoints that look like they take input, using a reflection and
  response-shape oracle rather than a blind wordlist spray.

Everything here is standard library. That is deliberate: the install was
failing on compiled dependencies, and a recon tool that cannot be installed
discovers nothing at all.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


# ─────────────────────────────────────────────────────────────────────────────
#  Fetching
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Response:
    url: str
    status: int
    headers: dict
    body: str
    elapsed: float = 0.0
    error: str = ""

    @property
    def ok(self):
        return self.status and 200 <= self.status < 400

    def header(self, name, default=""):
        for key, value in (self.headers or {}).items():
            if key.lower() == name.lower():
                return value
        return default


class Fetcher:
    """A small concurrent HTTP client on top of urllib.

    urllib rather than aiohttp or httpx on purpose. The project ships with
    four pure-Python dependencies and installs in one command on a fresh Kali
    box; adding a compiled HTTP stack to shave milliseconds off a scan that is
    rate-limited anyway is a bad trade, and compiled dependencies are exactly
    what was breaking the install.
    """

    def __init__(self, concurrency=20, timeout=12, proxy=None, headers=None,
                 user_agent=DEFAULT_UA, verify=False):
        self.semaphore = asyncio.Semaphore(max(1, int(concurrency)))
        self.timeout = timeout
        self.proxy = proxy
        self.headers = dict(headers or {})
        self.user_agent = user_agent or DEFAULT_UA
        self.verify = verify
        self._opener = None

    def _build_opener(self):
        if self._opener is not None:
            return self._opener
        handlers = []
        if self.proxy:
            handlers.append(urllib.request.ProxyHandler(
                {"http": self.proxy, "https": self.proxy}))
        else:
            handlers.append(urllib.request.ProxyHandler({}))
        if not self.verify:
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=context))
        # Redirects are followed by default; the checks that care about a
        # redirect pass follow=False and inspect the Location themselves.
        self._opener = urllib.request.build_opener(*handlers)
        return self._opener

    def _blocking(self, method, url, body, extra_headers, follow, limit):
        headers = dict(self.headers)
        headers.setdefault("User-Agent", self.user_agent)
        headers.setdefault("Accept", "*/*")
        headers.update(extra_headers or {})
        opener = self._build_opener()
        if not follow:
            class _NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *args, **kwargs):
                    return None
            opener = urllib.request.build_opener(
                _NoRedirect, *[h for h in opener.handlers
                               if isinstance(h, (urllib.request.ProxyHandler,
                                                 urllib.request.HTTPSHandler))])
        data = body.encode("utf-8") if isinstance(body, str) else body
        request = urllib.request.Request(url, data=data, headers=headers,
                                         method=method)
        import time as _time
        started = _time.time()
        try:
            with opener.open(request, timeout=self.timeout) as resp:
                raw = resp.read(limit)
                if resp.headers.get("Content-Encoding", "") == "gzip":
                    try:
                        raw = gzip.decompress(raw)
                    except Exception:
                        pass
                return Response(resp.geturl() or url, resp.status,
                                dict(resp.headers),
                                raw.decode("utf-8", "replace"),
                                _time.time() - started)
        except urllib.error.HTTPError as exc:
            raw = b""
            try:
                raw = exc.read(limit)
            except Exception:
                pass
            return Response(url, exc.code, dict(exc.headers or {}),
                            raw.decode("utf-8", "replace"),
                            _time.time() - started)
        except Exception as exc:                                # noqa: BLE001
            return Response(url, 0, {}, "", _time.time() - started,
                            error=type(exc).__name__)

    async def get(self, url, headers=None, follow=True, limit=600_000,
                  method="GET", body=None):
        async with self.semaphore:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, self._blocking, method, url, body, headers, follow, limit)

    async def many(self, urls, headers=None, follow=True, limit=600_000):
        """Fetch a list concurrently, in order, never raising.

        A failed fetch comes back as a Response with status 0 rather than an
        exception, so a caller zipping the results against its input list
        never has to guess which one went missing.
        """
        tasks = [self.get(u, headers=headers, follow=follow, limit=limit)
                 for u in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r if isinstance(r, Response)
                else Response(u, 0, {}, "", 0.0, error=type(r).__name__)
                for u, r in zip(urls, results)]


# ─────────────────────────────────────────────────────────────────────────────
#  Archive sources
# ─────────────────────────────────────────────────────────────────────────────
#
# None of these touch the target. They are third-party indexes of what the
# target has published, which is why they belong in the passive preset and why
# they are the first thing to reach for: a domain that has existed for ten
# years has thousands of parameterised URLs in them, and an active crawl that
# runs for an hour will not find a fraction of it.

#: How much of one source's answer to read. A busy domain's Wayback index is
#: hundreds of megabytes; holding four of those in memory per domain, across
#: forty domains concurrently, is how a recon run turns into an OOM kill. The
#: cap is generous enough for tens of thousands of URLs and bounded enough to
#: run on a laptop.
ARCHIVE_READ_CAP = 12_000_000


async def wayback_urls(fetcher, domain, limit=20000):
    """Every distinct URL the Wayback Machine has indexed for a domain."""
    url = ("https://web.archive.org/cdx/search/cdx"
           f"?url=*.{urllib.parse.quote(domain)}/*&output=text&fl=original"
           f"&collapse=urlkey&limit={limit}")
    resp = await fetcher.get(url, limit=ARCHIVE_READ_CAP)
    if not resp.ok:
        return set()
    return {line.strip() for line in resp.body.splitlines()
            if line.strip().startswith("http")}


async def otx_urls(fetcher, domain, pages=10):
    """AlienVault OTX's passive URL list."""
    found = set()
    for page in range(1, pages + 1):
        url = (f"https://otx.alienvault.com/api/v1/indicators/domain/"
               f"{urllib.parse.quote(domain)}/url_list?limit=500&page={page}")
        resp = await fetcher.get(url, limit=ARCHIVE_READ_CAP)
        if not resp.ok:
            break
        try:
            data = json.loads(resp.body)
        except Exception:
            break
        rows = data.get("url_list") or []
        if not rows:
            break
        for row in rows:
            if row.get("url"):
                found.add(row["url"])
        if not data.get("has_next"):
            break
    return found


async def urlscan_urls(fetcher, domain):
    """urlscan.io's record of pages people have submitted for this domain."""
    url = ("https://urlscan.io/api/v1/search/?q=domain%3A"
           f"{urllib.parse.quote(domain)}&size=1000")
    resp = await fetcher.get(url, limit=ARCHIVE_READ_CAP)
    if not resp.ok:
        return set()
    try:
        data = json.loads(resp.body)
    except Exception:
        return set()
    found = set()
    for row in data.get("results") or []:
        page = (row.get("page") or {}).get("url")
        if page:
            found.add(page)
        task = (row.get("task") or {}).get("url")
        if task:
            found.add(task)
    return found


async def commoncrawl_urls(fetcher, domain, limit=10000):
    """The most recent Common Crawl index."""
    index_resp = await fetcher.get("https://index.commoncrawl.org/collinfo.json",
                                   limit=2_000_000)
    if not index_resp.ok:
        return set()
    try:
        indexes = json.loads(index_resp.body)
    except Exception:
        return set()
    if not indexes:
        return set()
    api = indexes[0].get("cdx-api")
    if not api:
        return set()
    resp = await fetcher.get(
        f"{api}?url=*.{urllib.parse.quote(domain)}&output=json&limit={limit}",
        limit=ARCHIVE_READ_CAP)
    if not resp.ok:
        return set()
    found = set()
    for line in resp.body.splitlines():
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if obj.get("url"):
            found.add(obj["url"])
    return found


ARCHIVE_SOURCES = (
    ("wayback", wayback_urls),
    ("urlscan", urlscan_urls),
    ("otx", otx_urls),
    ("commoncrawl", commoncrawl_urls),
)


async def archive_urls(fetcher, domains, log=None, sources=None):
    """Historical URLs for a set of registrable domains, from every source.

    Returns ``{url}``. Sources are queried concurrently and a source that is
    down, rate-limited or slow is skipped rather than failing the stage — the
    point is to get as much as is available, not to require all of it.
    """
    wanted = {name for name in (sources or [n for n, _ in ARCHIVE_SOURCES])}
    found = set()
    tasks = []
    labels = []
    for domain in domains:
        for name, func in ARCHIVE_SOURCES:
            if name in wanted:
                tasks.append(func(fetcher, domain))
                labels.append((name, domain))
    results = await asyncio.gather(*tasks, return_exceptions=True)
    per_source = {}
    for (name, domain), result in zip(labels, results):
        if isinstance(result, Exception) or not result:
            continue
        per_source[name] = per_source.get(name, 0) + len(result)
        found |= result
    if log:
        for name in sorted(per_source):
            log(f"  {name}: {per_source[name]} URL(s)")
    return found


# ─────────────────────────────────────────────────────────────────────────────
#  Forms
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Form:
    action: str
    method: str = "GET"
    params: dict = field(default_factory=dict)   # name -> default value
    enctype: str = ""
    source: str = ""

    def as_url(self):
        """The GET form expressed as a URL, so it can be fed to any scanner."""
        if self.method.upper() != "GET" or not self.params:
            return ""
        parts = urllib.parse.urlsplit(self.action)
        existing = dict(urllib.parse.parse_qsl(parts.query,
                                               keep_blank_values=True))
        existing.update({k: v or "test" for k, v in self.params.items()})
        return urllib.parse.urlunsplit(
            parts._replace(query=urllib.parse.urlencode(existing)))

    def as_dict(self):
        return {"action": self.action, "method": self.method,
                "params": sorted(self.params), "enctype": self.enctype,
                "source": self.source}


class _FormParser(HTMLParser):
    """Pulls forms and their named inputs out of a page.

    A regex cannot do this correctly — inputs belonging to one form routinely
    sit between another form's tags, and attribute order is arbitrary — and
    getting it wrong means missing the parameter list of the only form on the
    page that matters.
    """

    INPUT_TAGS = ("input", "select", "textarea", "button")
    SKIP_TYPES = ("submit", "button", "image", "reset", "file")

    def __init__(self, base_url):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.forms = []
        self._current = None
        self.orphan_inputs = {}

    def handle_starttag(self, tag, attrs):
        attributes = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            action = attributes.get("action", "")
            try:
                action = urllib.parse.urljoin(self.base_url, action) \
                    if action else self.base_url
            except Exception:
                action = self.base_url
            self._current = Form(action=action,
                                 method=(attributes.get("method") or "GET").upper(),
                                 enctype=attributes.get("enctype", ""),
                                 source="form")
            self.forms.append(self._current)
            return
        if tag in self.INPUT_TAGS:
            name = attributes.get("name") or attributes.get("id")
            if not name:
                return
            if tag == "input" and attributes.get("type", "").lower() in self.SKIP_TYPES:
                return
            value = attributes.get("value", "")
            if self._current is not None:
                self._current.params[name] = value
            else:
                # An input outside any form is still a named field the page's
                # JavaScript will read and send somewhere.
                self.orphan_inputs[name] = value

    def handle_endtag(self, tag):
        if tag == "form":
            self._current = None


def parse_forms(html, base_url):
    """``([Form], {orphan input name: value})`` for one page."""
    parser = _FormParser(base_url)
    try:
        parser.feed(html or "")
    except Exception:                                           # noqa: BLE001
        pass
    return [f for f in parser.forms if f.params], parser.orphan_inputs


# ─────────────────────────────────────────────────────────────────────────────
#  JavaScript
# ─────────────────────────────────────────────────────────────────────────────
#
# Single-page applications keep their whole API surface in the bundle. These
# patterns are deliberately broad: a false endpoint costs one request to find
# out, and a missed one is a whole feature nobody tests.

_JS_PATH = re.compile(
    r"""["'`](/(?!/)[A-Za-z0-9_\-./{}$]{2,180}?)["'`]""")
_JS_FULL_URL = re.compile(r"""["'`](https?://[^"'`\s]{6,400})["'`]""")
_JS_QUERY = re.compile(r"""[?&]([A-Za-z_][A-Za-z0-9_\-\[\]]{0,40})=""")
_JS_PARAM_CALL = re.compile(
    r"""(?:searchParams\.(?:get|set|append|has)|getParameter|params\.|query\.|"""
    r"""req\.query\.|\$_GET\[)\s*\(?\s*["'`]([A-Za-z_][A-Za-z0-9_\-]{0,40})["'`]""")
_JS_BODY_KEY = re.compile(
    r"""["'`]?([A-Za-z_][A-Za-z0-9_]{1,30})["'`]?\s*:\s*(?:encodeURIComponent|"""
    r"""[A-Za-z_$][A-Za-z0-9_$.]{0,40})""")
_JS_FETCH = re.compile(
    r"""(?:fetch|axios(?:\.(?:get|post|put|patch|delete))?|\.open|"""
    r"""\$\.(?:get|post|ajax)|XMLHttpRequest\(\)\.open)\s*\(\s*["'`]([^"'`]{2,400})["'`]""")

#: Paths that are assets, not endpoints. Keeping these out is what stops the
#: endpoint list being ten thousand sprite images.
_ASSET_SUFFIX = re.compile(
    r"\.(?:png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|otf|mp4|webm|mp3|wav|"
    r"css|map|pdf|zip|gz|tgz|rar|7z|dmg|exe|bin|wasm)(?:$|\?)", re.I)


def js_endpoints(js_text, base_url=""):
    """``(paths, parameter names)`` mined from one JavaScript file."""
    paths, params = set(), set()
    text = js_text or ""

    for match in _JS_FETCH.findall(text):
        candidate = match.strip()
        if candidate.startswith(("http://", "https://", "/")):
            paths.add(candidate)
    for match in _JS_PATH.findall(text):
        if _ASSET_SUFFIX.search(match):
            continue
        if match.count("/") > 8:
            continue
        paths.add(match)
    for match in _JS_FULL_URL.findall(text):
        if not _ASSET_SUFFIX.search(match):
            paths.add(match)

    params |= set(_JS_QUERY.findall(text))
    params |= set(_JS_PARAM_CALL.findall(text))

    absolute = set()
    for path in paths:
        if path.startswith("http"):
            absolute.add(path)
        elif base_url:
            try:
                absolute.add(urllib.parse.urljoin(base_url, path))
            except Exception:
                continue
        else:
            absolute.add(path)
    # Query strings written into the bundle carry their own parameter names.
    for path in absolute:
        query = urllib.parse.urlsplit(path).query
        if query:
            params |= {k for k, _ in urllib.parse.parse_qsl(query,
                                                            keep_blank_values=True)}
    return absolute, {p for p in params if 1 < len(p) <= 40}


_HREF = re.compile(r"""<a[^>]+href\s*=\s*["']([^"'<>]{1,500})["']""", re.I)
_SCRIPT_SRC = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.I)
_INLINE_SCRIPT = re.compile(r"<script(?![^>]*\bsrc\b)[^>]*>(.*?)</script>",
                            re.I | re.S)


def script_sources(html, base_url):
    out = []
    for src in _SCRIPT_SRC.findall(html or ""):
        try:
            out.append(urllib.parse.urljoin(base_url, src))
        except Exception:
            continue
    return out


def inline_scripts(html):
    return _INLINE_SCRIPT.findall(html or "")


# ─────────────────────────────────────────────────────────────────────────────
#  robots.txt, sitemaps, OpenAPI
# ─────────────────────────────────────────────────────────────────────────────

async def robots_and_sitemap(fetcher, base, cap=5000):
    """Paths from robots.txt and every sitemap it points at.

    robots.txt is where an application lists the directories it would rather
    nobody looked at, which makes it the highest-value single request in
    recon, and it is one GET.
    """
    found, sitemaps = set(), set()
    resp = await fetcher.get(urllib.parse.urljoin(base, "/robots.txt"),
                             limit=400_000)
    if resp.ok and "html" not in resp.header("Content-Type", "").lower():
        for line in resp.body.splitlines():
            line = line.strip()
            if line.lower().startswith(("allow:", "disallow:")):
                path = line.split(":", 1)[1].strip()
                if path and path != "/" and "*" not in path:
                    try:
                        found.add(urllib.parse.urljoin(base, path))
                    except Exception:
                        pass
            elif line.lower().startswith("sitemap:"):
                sitemaps.add(line.split(":", 1)[1].strip())
    sitemaps.add(urllib.parse.urljoin(base, "/sitemap.xml"))

    seen = set()
    queue = list(sitemaps)
    while queue and len(found) < cap:
        target = queue.pop(0)
        if target in seen or not target.startswith("http"):
            continue
        seen.add(target)
        resp = await fetcher.get(target, limit=8_000_000)
        if not resp.ok:
            continue
        locations = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", resp.body, re.I)
        for loc in locations:
            if loc.endswith((".xml", ".xml.gz")) and len(seen) < 25:
                queue.append(loc)
            else:
                found.add(loc)
    return found


OPENAPI_PATHS = ("/swagger.json", "/openapi.json", "/swagger/v1/swagger.json",
                 "/api/swagger.json", "/api/openapi.json", "/v1/openapi.json",
                 "/api-docs", "/api/v1/swagger.json", "/swagger/doc.json",
                 "/openapi.yaml", "/.well-known/openapi.json")


async def openapi_surface(fetcher, base):
    """Endpoints and parameters from an OpenAPI/Swagger document, if exposed.

    When one is present this is the complete, authoritative input surface of
    the API — every path, every parameter, every method. Nothing else in recon
    comes close, and a surprising number of applications serve it publicly.
    """
    for candidate in OPENAPI_PATHS:
        resp = await fetcher.get(urllib.parse.urljoin(base, candidate),
                                 limit=8_000_000)
        if not resp.ok or not resp.body.strip():
            continue
        try:
            doc = json.loads(resp.body)
        except Exception:
            continue
        if not isinstance(doc, dict) or "paths" not in doc:
            continue
        endpoints, params = set(), set()
        prefix = ""
        servers = doc.get("servers") or []
        if servers and isinstance(servers, list):
            prefix = (servers[0] or {}).get("url", "") or ""
        elif doc.get("basePath"):
            prefix = doc["basePath"]
        for path, methods in (doc.get("paths") or {}).items():
            try:
                full = urllib.parse.urljoin(base, (prefix or "") + path)
            except Exception:
                continue
            endpoints.add(full)
            if not isinstance(methods, dict):
                continue
            for method, spec in methods.items():
                if not isinstance(spec, dict):
                    continue
                for param in spec.get("parameters") or []:
                    if isinstance(param, dict) and param.get("name"):
                        params.add(param["name"])
        return {"document": resp.url, "endpoints": endpoints,
                "parameters": params}
    return None


# ─────────────────────────────────────────────────────────────────────────────
#  Parameter brute force
# ─────────────────────────────────────────────────────────────────────────────
#
# Last resort, and it earns its place only because it is the only way to find
# a parameter that is in no archive, no form and no bundle — a debug switch, a
# forgotten feature flag, an admin override. The oracle is what makes it
# usable: a parameter is only reported when adding it *changes the response in
# a way the control requests did not*, which is what separates a real hidden
# parameter from a page that renders differently every time.

COMMON_PARAMS = (
    "id", "page", "q", "query", "search", "s", "keyword", "key", "name",
    "user", "username", "uid", "user_id", "userid", "account", "account_id",
    "email", "token", "auth", "api_key", "apikey", "access_token", "session",
    "callback", "jsonp", "redirect", "redirect_uri", "redirect_url", "url",
    "uri", "next", "return", "returnurl", "return_url", "continue", "dest",
    "destination", "go", "target", "forward", "back", "ref", "referer",
    "file", "filename", "path", "dir", "folder", "doc", "document", "download",
    "template", "view", "page_id", "include", "lang", "language", "locale",
    "country", "region", "format", "type", "mode", "action", "cmd", "command",
    "exec", "func", "function", "method", "op", "operation", "debug", "test",
    "preview", "draft", "admin", "is_admin", "role", "permission", "sort",
    "order", "order_by", "orderby", "filter", "where", "limit", "offset",
    "count", "size", "start", "end", "from", "to", "date", "time", "status",
    "state", "category", "cat", "tag", "tags", "title", "content", "body",
    "message", "msg", "text", "comment", "description", "data", "json",
    "xml", "html", "src", "source", "host", "domain", "ip", "port", "proxy",
    "feed", "rss", "image", "img", "photo", "avatar", "upload", "attachment",
    "version", "v", "api_version", "env", "environment", "config", "setting",
    "settings", "option", "options", "flag", "feature", "enable", "disable",
    "show", "hide", "display", "render", "output", "print", "export",
    "import", "sync", "refresh", "reload", "reset", "clear", "delete",
    "remove", "update", "edit", "save", "submit", "confirm", "verify",
    "code", "otp", "pin", "password", "pass", "pwd", "secret", "hash",
    "signature", "sig", "nonce", "csrf", "csrf_token", "_token", "xsrf",
)

_CANARY = "bbh7q2x"


def _shape(resp):
    """A fingerprint to compare two responses by.

    Exact length, not a bucket. Bucketing was a mistake: the first version
    rounded to 64 bytes so that a page with a timestamp in it would not look
    different from itself, and the effect was that a hidden ``debug``
    parameter which turned a 33-byte response into a 59-byte one landed in
    the same bucket and was never reported. The jitter problem is real but
    this is the wrong place to solve it — the caller sends two identical
    control requests first and refuses to test an endpoint whose two controls
    disagree, which handles the varying page properly instead of blinding the
    comparison for every page.
    """
    if resp is None:
        return (0, 0, 0)
    body = resp.body or ""
    return (resp.status, len(body), body.count("<"))


def _with_value(url, name, value):
    parts = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    pairs.append((name, value))
    return urllib.parse.urlunsplit(
        parts._replace(query=urllib.parse.urlencode(pairs)))


async def brute_parameters(fetcher, url, wordlist=None, chunk=40,
                           max_rounds=3, log=None):
    """Hidden GET parameters on one endpoint, by reflection and by shape.

    Sends the wordlist in chunks and keeps a chunk only when it changes the
    response, then bisects to the individual names. A chunk that changes
    nothing is discarded whole, so the cost is roughly ``len(wordlist)/chunk``
    requests for an endpoint with no hidden parameters rather than one request
    per word.
    """
    words = [w for w in (wordlist or COMMON_PARAMS) if w]
    control = await fetcher.get(url)
    if control is None or not control.status:
        return []
    # Two controls: an endpoint that differs from itself cannot be tested this
    # way, and saying so is better than reporting every word in the list.
    control2 = await fetcher.get(url)
    if _shape(control) != _shape(control2):
        if log:
            log(f"  {url} varies between identical requests — skipping brute force")
        return []
    baseline = _shape(control)

    def with_params(names):
        parts = urllib.parse.urlsplit(url)
        existing = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        existing += [(n, _CANARY) for n in names]
        return urllib.parse.urlunsplit(
            parts._replace(query=urllib.parse.urlencode(existing)))

    async def interesting(names):
        resp = await fetcher.get(with_params(names))
        if resp is None or not resp.status:
            return None
        reflected = _CANARY in (resp.body or "")
        changed = _shape(resp) != baseline
        return (reflected or changed, resp)

    found = []
    chunks = [words[i:i + chunk] for i in range(0, len(words), chunk)]
    suspects = []
    results = await asyncio.gather(*[interesting(c) for c in chunks])
    for names, result in zip(chunks, results):
        if result and result[0]:
            suspects.append(names)

    rounds = 0
    while suspects and rounds < max_rounds + 6:
        rounds += 1
        group = suspects.pop(0)
        if len(group) == 1:
            result = await interesting(group)
            if result and result[0]:
                reflected = _CANARY in (result[1].body or "")
                found.append({"name": group[0],
                              "reflected": reflected,
                              "status": result[1].status,
                              # A benign value, not the canary. The caller
                              # feeds these URLs back into the testable list,
                              # and a list full of ?debug=bbh7q2x is both
                              # confusing to read and wrong to re-test — the
                              # discovery marker is not a value the
                              # application ever sees in normal use.
                              "url": _with_value(url, group[0], "1")})
            continue
        middle = len(group) // 2
        for half in (group[:middle], group[middle:]):
            if not half:
                continue
            result = await interesting(half)
            if result and result[0]:
                suspects.append(half)
    return found


# ─────────────────────────────────────────────────────────────────────────────
#  Putting it together
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Surface:
    """Everything discovered about one application's input surface."""
    urls: set = field(default_factory=set)
    forms: list = field(default_factory=list)
    parameters: dict = field(default_factory=dict)   # name -> {sources, count}
    endpoints: set = field(default_factory=set)
    js_files: set = field(default_factory=set)
    openapi: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    def add_param(self, name, source, example=""):
        if not name or len(name) > 60:
            return
        entry = self.parameters.setdefault(
            name, {"name": name, "sources": set(), "count": 0, "example": ""})
        entry["sources"].add(source)
        entry["count"] += 1
        if example and not entry["example"]:
            entry["example"] = example[:400]

    def merge_urls(self, urls, source):
        for url in urls:
            self.urls.add(url)
            try:
                query = urllib.parse.urlsplit(url).query
            except Exception:
                continue
            for name, _ in urllib.parse.parse_qsl(query, keep_blank_values=True):
                self.add_param(name, source, url)


async def crawl_page(fetcher, url, surface, scope_ok=None, fetch_js=True,
                     js_cap=12):
    """One page: its forms, its scripts, and the endpoints inside them."""
    resp = await fetcher.get(url)
    if resp is None or not resp.ok or not resp.body:
        return resp
    content_type = resp.header("Content-Type", "").lower()
    if "html" not in content_type and "<" not in resp.body[:400]:
        return resp

    # Links. Obvious, and omitting them was a real bug: a page whose only
    # parameterised URL was an ordinary <a href="/item?id=1"> handed the
    # parameter stage nothing, so the endpoint with the SQL injection in it
    # was never tested. Forms and bundles are where *most* of the surface is;
    # they are not where all of it is.
    for href in _HREF.findall(resp.body):
        if href.startswith(("mailto:", "tel:", "javascript:", "data:", "#")):
            continue
        try:
            absolute = urllib.parse.urljoin(resp.url, href)
        except Exception:
            continue
        if not absolute.startswith("http"):
            continue
        if _ASSET_SUFFIX.search(absolute):
            continue
        if scope_ok and not scope_ok(absolute):
            continue
        surface.urls.add(absolute)
        query = urllib.parse.urlsplit(absolute).query
        for name, _ in urllib.parse.parse_qsl(query, keep_blank_values=True):
            surface.add_param(name, "link", absolute)

    forms, orphans = parse_forms(resp.body, resp.url)
    for form in forms:
        if scope_ok and not scope_ok(form.action):
            continue
        surface.forms.append(form)
        surface.endpoints.add(form.action)
        for name, value in form.params.items():
            surface.add_param(name, "form", form.action)
        as_url = form.as_url()
        if as_url:
            surface.urls.add(as_url)
    for name in orphans:
        surface.add_param(name, "input", resp.url)

    scripts = script_sources(resp.body, resp.url)
    for src in scripts:
        if not scope_ok or scope_ok(src):
            surface.js_files.add(src)

    for block in inline_scripts(resp.body):
        endpoints, params = js_endpoints(block, resp.url)
        for endpoint in endpoints:
            if not scope_ok or scope_ok(endpoint):
                surface.endpoints.add(endpoint)
        for name in params:
            surface.add_param(name, "inline-js", resp.url)

    if fetch_js and scripts:
        targets = [s for s in scripts[:js_cap]
                   if not scope_ok or scope_ok(s)]
        responses = await asyncio.gather(*[fetcher.get(s) for s in targets])
        for src, js_resp in zip(targets, responses):
            if js_resp is None or not js_resp.ok:
                continue
            endpoints, params = js_endpoints(js_resp.body, src)
            for endpoint in endpoints:
                if not scope_ok or scope_ok(endpoint):
                    surface.endpoints.add(endpoint)
            for name in params:
                surface.add_param(name, "js", src)
    return resp
