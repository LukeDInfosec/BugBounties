#!/usr/bin/env python3
"""XSS Recon — pick the programmes worth spending a day on.

This is a rewrite of a standalone target-finder script. The idea it is built
on is a good one and is kept intact: before testing anything, go through the
scopes you are allowed to test and rank them by how likely they are to have
the *kind* of bug you are hunting, because an afternoon spent on an
application built entirely out of React with a strict CSP is an afternoon
gone.

Two profiles, as in the original:

  **Reflected and stored** wants applications that render on the server. A
  virtual-DOM framework escapes by default, so React, Vue, Angular and Svelte
  count against a target here rather than for it.

  **DOM-based** wants the opposite: a large bundle of the application's own
  JavaScript, with dangerous sinks, untrusted sources, prototype-pollution
  patterns and unguarded postMessage handlers in it.

What changed, and why:

**The dependencies are gone.** The original needed selenium,
webdriver-manager and wakepy, and it downloaded a matching ChromeDriver at
runtime. That is what was failing to install, and it bought one thing: a
check for whether ``__webpack_require__.m`` is exposed at runtime. That same
fact is visible in the bundle text, which is already being downloaded and
read, so the entire browser stack has been replaced by a regex over content
this module fetches anyway. Nothing here is outside the standard library.

**It finishes.** The original looped forever (``while True`` around a random
programme), tested one URL at a time, and slept two to five seconds between
each. Against a wildcard with fifty subdomains that is several minutes per
programme and it never stops on its own. This runs a bounded pass with a
budget, concurrently, and can be cancelled.

**The verdict carries its evidence.** "Score 72" on its own is not useful a
week later. Every result records which signals fired, so the list can be
re-read and argued with.

**Credentials are never written to disk by this module.** The key is passed
in, used, and not persisted or logged.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import urllib.parse
from dataclasses import dataclass, field

from .discovery import Fetcher, DEFAULT_UA, js_endpoints, script_sources, \
    inline_scripts

HACKERONE_KEY_URL = "https://hackerone.com/settings/api_token/edit"
BUGCROWD_KEY_URL = "https://bugcrowd.com/user/edit/api_keys"


# ─────────────────────────────────────────────────────────────────────────────
#  Platforms
# ─────────────────────────────────────────────────────────────────────────────

async def hackerone_programs(fetcher, api_key, limit_pages=10, log=None):
    """Public programmes and their structured scopes.

    ``api_key`` is ``identifier:token``. The identifier is the API token's
    *name*, not the username — getting that wrong is the usual cause of a 401
    here, so the error says so rather than just printing the status code.
    """
    if not api_key or ":" not in api_key:
        raise ValueError(
            "HackerOne API keys are 'identifier:token'. The identifier is the "
            "name you gave the token when you created it, not your username. "
            f"Create or check one at {HACKERONE_KEY_URL}")
    identifier, token = api_key.split(":", 1)
    auth = _basic(identifier, token)
    programs = []
    for page in range(1, limit_pages + 1):
        url = ("https://api.hackerone.com/v1/hackers/programs"
               f"?page%5Bnumber%5D={page}&page%5Bsize%5D=100")
        resp = await fetcher.get(url, headers={"Authorization": auth,
                                               "Accept": "application/json"})
        if resp.status in (401, 403):
            raise ValueError(
                f"HackerOne rejected the credentials (HTTP {resp.status}). "
                f"Check the identifier:token pair at {HACKERONE_KEY_URL}")
        if not resp.ok:
            if log:
                log(f"HackerOne returned HTTP {resp.status} on page {page}")
            break
        try:
            data = json.loads(resp.body)
        except Exception:
            break
        batch = data.get("data") or []
        if not batch:
            break
        for row in batch:
            attrs = row.get("attributes") or {}
            handle = attrs.get("handle")
            if not handle:
                continue
            programs.append({
                "platform": "hackerone",
                "handle": handle,
                "name": attrs.get("name") or handle,
                "url": f"https://hackerone.com/{handle}",
                "offers_bounties": bool(attrs.get("offers_bounties")),
                "submission_state": attrs.get("submission_state", ""),
            })
        if len(batch) < 100:
            break
    if log:
        log(f"HackerOne: {len(programs)} programme(s)")
    return programs


async def hackerone_scope(fetcher, api_key, handle):
    """The structured scope for one programme, as a list of assets."""
    identifier, token = api_key.split(":", 1)
    auth = _basic(identifier, token)
    assets, page = [], 1
    while page <= 5:
        url = (f"https://api.hackerone.com/v1/hackers/programs/{handle}"
               f"/structured_scopes?page%5Bnumber%5D={page}&page%5Bsize%5D=100")
        resp = await fetcher.get(url, headers={"Authorization": auth,
                                               "Accept": "application/json"})
        if not resp.ok:
            break
        try:
            data = json.loads(resp.body)
        except Exception:
            break
        rows = data.get("data") or []
        if not rows:
            break
        for row in rows:
            attrs = row.get("attributes") or {}
            if not attrs.get("eligible_for_submission", True):
                continue
            assets.append({
                "type": attrs.get("asset_type", ""),
                "identifier": attrs.get("asset_identifier", ""),
                "bounty": bool(attrs.get("eligible_for_bounty")),
            })
        if len(rows) < 100:
            break
        page += 1
    return assets


async def bugcrowd_programs(fetcher, api_key, log=None):
    if not api_key:
        return []
    resp = await fetcher.get(
        "https://api.bugcrowd.com/programs",
        headers={"Authorization": f"Token {api_key}",
                 "Accept": "application/vnd.bugcrowd.v4+json"})
    if resp.status in (401, 403):
        raise ValueError(
            f"Bugcrowd rejected the API key (HTTP {resp.status}). "
            f"Check it at {BUGCROWD_KEY_URL}")
    if not resp.ok:
        if log:
            log(f"Bugcrowd returned HTTP {resp.status}")
        return []
    try:
        data = json.loads(resp.body)
    except Exception:
        return []
    out = []
    for row in data.get("data") or data.get("programs") or []:
        attrs = row.get("attributes") or row
        code = attrs.get("code") or row.get("code")
        if not code:
            continue
        out.append({"platform": "bugcrowd", "handle": code,
                    "name": attrs.get("name") or code,
                    "url": f"https://bugcrowd.com/{code}"})
    if log:
        log(f"Bugcrowd: {len(out)} programme(s)")
    return out


def _basic(user, password):
    import base64
    raw = f"{user}:{password}".encode()
    return "Basic " + base64.b64encode(raw).decode()


# ─────────────────────────────────────────────────────────────────────────────
#  Scope to URLs
# ─────────────────────────────────────────────────────────────────────────────

async def crtsh_subdomains(fetcher, domain, cap=60):
    """Subdomains from certificate transparency, newest certificates first.

    The original took an arbitrary 50 from a Python set, which is the worst
    possible selection: set order is a hash artefact, so two runs against the
    same domain tested different hosts for no reason. Sorting by how recently
    a certificate was issued puts the hosts somebody is actively deploying at
    the top, which is where live applications are.
    """
    resp = await fetcher.get(
        f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json",
        limit=20_000_000)
    if not resp.ok:
        return []
    try:
        rows = json.loads(resp.body)
    except Exception:
        return []
    seen = {}
    for row in rows:
        when = row.get("not_before") or ""
        for name in (row.get("name_value") or "").split("\n"):
            name = name.strip().lower().lstrip("*.")
            if not name or "*" in name or not name.endswith(domain):
                continue
            if name not in seen or when > seen[name]:
                seen[name] = when
    ordered = sorted(seen, key=lambda n: seen[n], reverse=True)
    return ordered[:cap]


async def scope_to_urls(fetcher, assets, use_subdomains, per_wildcard=25,
                        log=None):
    """Testable URLs for one programme's scope."""
    urls, wildcards = [], []
    for asset in assets:
        kind = (asset.get("type") or "").upper()
        identifier = (asset.get("identifier") or "").strip()
        if not identifier:
            continue
        if kind in ("URL", "WILDCARD") or "." in identifier:
            if "*" in identifier:
                wildcards.append(identifier.replace("*.", "").lstrip("."))
            else:
                if not identifier.startswith(("http://", "https://")):
                    identifier = "https://" + identifier
                urls.append(identifier.split()[0])
    if use_subdomains:
        for domain in wildcards[:5]:
            names = await crtsh_subdomains(fetcher, domain, cap=per_wildcard)
            if log and names:
                log(f"  {domain}: {len(names)} subdomain(s) from crt.sh")
            urls += [f"https://{n}" for n in names]
    else:
        urls += [f"https://{d}" for d in wildcards]
    # Deduplicate while keeping order, and drop the double-scheme URLs the
    # original produced from scope entries that already carried one.
    out, seen = [], set()
    for url in urls:
        url = re.sub(r"^(https?://)(?:https?://)+", r"\1", url)
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out


# ─────────────────────────────────────────────────────────────────────────────
#  Analysis
# ─────────────────────────────────────────────────────────────────────────────

SINKS = {
    "innerHTML": r"\.innerHTML\s*[=+]",
    "outerHTML": r"\.outerHTML\s*[=+]",
    "insertAdjacentHTML": r"\.insertAdjacentHTML\s*\(",
    "document.write": r"document\.write(?:ln)?\s*\(",
    "eval": r"(?<![\w.])eval\s*\(",
    "Function()": r"new\s+Function\s*\(",
    "setTimeout(string)": r"setTimeout\s*\(\s*[\"'`]",
    "setInterval(string)": r"setInterval\s*\(\s*[\"'`]",
    "script injection": r"createElement\s*\(\s*[\"']script[\"']",
    "setAttribute(on*)": r"\.setAttribute\s*\(\s*[\"']on\w+",
    "srcdoc": r"\.srcdoc\s*=",
    "location assign": r"location\s*\.\s*(?:assign|replace|href)\s*[=(]",
    "jQuery html()": r"\$\([^)]*\)\s*\.\s*html\s*\(",
    "jQuery append": r"\.\s*(?:append|prepend|before|after|replaceWith)\s*\(",
    "Range.createContextualFragment": r"createContextualFragment\s*\(",
}

SOURCES = {
    "location.hash": r"location\s*\.\s*hash",
    "location.search": r"location\s*\.\s*search",
    "location.href": r"location\s*\.\s*href",
    "document.URL": r"document\s*\.\s*(?:URL|documentURI|baseURI)",
    "document.referrer": r"document\s*\.\s*referrer",
    "window.name": r"window\s*\.\s*name",
    "postMessage": r"addEventListener\s*\(\s*[\"']message[\"']",
    "URLSearchParams": r"new\s+URLSearchParams",
    "localStorage": r"localStorage\s*\.\s*getItem",
    "sessionStorage": r"sessionStorage\s*\.\s*getItem",
    "document.cookie": r"document\s*\.\s*cookie",
}

PROTOTYPE = {
    "__proto__": r"__proto__",
    "constructor[]": r"\[\s*[\"']constructor[\"']\s*\]",
    "prototype assign": r"\.prototype\s*[=\[]",
    "setPrototypeOf": r"Object\s*\.\s*setPrototypeOf",
}

MERGE = {
    "lodash merge": r"\b_\s*\.\s*(?:merge|defaultsDeep|set)\s*\(",
    "jQuery extend": r"\$\s*\.\s*extend\s*\(\s*(?:true|\{)",
    "deepmerge": r"\bdeepmerge\s*\(",
    "Object.assign": r"Object\s*\.\s*assign\s*\(",
    "custom merge": r"function\s+\w*(?:merge|extend|deep)\w*\s*\(",
}

FRAMEWORK_UNSAFE = {
    "dangerouslySetInnerHTML": r"dangerouslySetInnerHTML",
    "v-html": r"v-html",
    "ng-bind-html": r"ng-bind-html",
    "$sce.trustAsHtml": r"\$sce\s*\.\s*trustAsHtml",
    "bypassSecurityTrustHtml": r"bypassSecurityTrust\w+",
}

FRAMEWORKS = {
    "react": r"react(?:-dom)?(?:\.production|\.development)?\.min\.js|"
             r"__REACT_DEVTOOLS|createElement\(|_jsxRuntime",
    "vue": r"vue(?:\.runtime)?(?:\.global)?(?:\.prod)?\.js|__VUE__|"
           r"Vue\.createApp",
    "angular": r"angular(?:\.min)?\.js|ng-version=|platformBrowserDynamic",
    "svelte": r"svelte-[0-9a-z]{6}|__svelte",
    "ember": r"ember(?:\.min)?\.js|Ember\.Application",
}

#: Bundles whose names say they are somebody else's code. Analysing jQuery's
#: own source and reporting its sinks is how the original's score inflated on
#: targets with no custom JavaScript at all.
VENDOR_HINT = re.compile(
    r"(?:^|/)(?:vendor|vendors|runtime|polyfill|lib|libs|framework|common|"
    r"jquery|lodash|underscore|moment|bootstrap|react|vue|angular|ember|"
    r"swiper|gsap|three|chart|d3)[-.\w]*\.js", re.I)
CUSTOM_HINT = re.compile(
    r"(?:^|/)(?:app|main|index|bundle|site|custom|client|page|module|"
    r"chunk)[-.\w]*\.js", re.I)

VULNERABLE_LIBS = (
    ("jQuery", re.compile(r"jQuery\s+v?(\d+\.\d+\.\d+)", re.I),
     lambda v: _lt(v, "3.5.0"),
     "jQuery before 3.5.0 — htmlPrefilter allows XSS via crafted HTML "
     "(CVE-2020-11022/11023)"),
    ("lodash", re.compile(r"lodash[^\n]{0,40}?(\d+\.\d+\.\d+)", re.I),
     lambda v: _lt(v, "4.17.21"),
     "lodash before 4.17.21 — prototype pollution in merge/set "
     "(CVE-2020-8203, CVE-2021-23337)"),
    ("Underscore", re.compile(r"underscore[^\n]{0,40}?(\d+\.\d+\.\d+)", re.I),
     lambda v: _lt(v, "1.13.0"),
     "Underscore before 1.13.0 — arbitrary code execution in template "
     "(CVE-2021-23358)"),
    ("AngularJS", re.compile(r"angular[^\n]{0,20}?v?(1\.\d+\.\d+)", re.I),
     lambda v: _lt(v, "1.8.0"),
     "AngularJS before 1.8.0 — multiple sandbox escapes; any version of 1.x "
     "is end of life"),
    ("Moment.js", re.compile(r"moment[^\n]{0,30}?(\d+\.\d+\.\d+)", re.I),
     lambda v: _lt(v, "2.29.4"),
     "moment before 2.29.4 — path traversal in locale loading "
     "(CVE-2022-24785)"),
)


def _lt(version, floor):
    def parts(text):
        return [int(x) for x in re.findall(r"\d+", text)[:3]] or [0]
    a, b = parts(version), parts(floor)
    a += [0] * (3 - len(a))
    b += [0] * (3 - len(b))
    return a < b


def _count(text, table):
    out = {}
    for label, pattern in table.items():
        try:
            hits = len(re.findall(pattern, text, re.I))
        except re.error:
            continue
        if hits:
            out[label] = hits
    return out


def classify_script(url, body):
    """``(is_custom, why)`` for one script.

    Name first, because it is right far more often than content heuristics —
    ``vendor.4f2a.js`` is not the application's code whatever is inside it —
    and content only as a tie-break.
    """
    if VENDOR_HINT.search(url or ""):
        return False, "vendor bundle by name"
    if CUSTOM_HINT.search(url or ""):
        return True, "application bundle by name"
    head = (body or "")[:6000]
    vendor_signals = sum(bool(re.search(p, head, re.I)) for p in (
        r"\*\s*@license", r"node_modules", r"/\*!\s*\w+\.js v?\d",
        r"typeof exports\s*===?\s*[\"']object[\"']"))
    custom_signals = sum(bool(re.search(p, head)) for p in (
        r"__webpack_require__", r"\bfetch\s*\(\s*[\"'`]/",
        r"document\.querySelector", r"addEventListener\("))
    if vendor_signals > custom_signals:
        return False, f"vendor-like content ({vendor_signals} signal(s))"
    return True, f"application-like content ({custom_signals} signal(s))"


def analyse_webpack(text):
    """Whether the bundle leaves its module map reachable at runtime.

    The original started a headless Chrome to evaluate
    ``__webpack_require__.m``. The same conclusion is available from the
    bundle source — the runtime only exposes the map if the code that
    assigns it is in the file — and reading the file costs one request
    instead of a browser.
    """
    if re.search(r"__webpack_require__\s*\.\s*m\s*=", text):
        return True, "__webpack_require__.m is assigned in the bundle"
    if re.search(r"webpackJsonp|webpackChunk", text):
        return True, "webpack chunk registry is global"
    return False, ""


@dataclass
class TargetReport:
    url: str
    status: int = 0
    score: int = 0
    verdict: str = ""
    signals: list = field(default_factory=list)
    frameworks: list = field(default_factory=list)
    csp: str = ""
    waf: bool = False
    custom_scripts: int = 0
    vendor_scripts: int = 0
    vulnerable_libraries: list = field(default_factory=list)
    sinks: dict = field(default_factory=dict)
    sources: dict = field(default_factory=dict)
    prototype: dict = field(default_factory=dict)
    merges: dict = field(default_factory=dict)
    postmessage_unchecked: int = 0
    framework_unsafe: dict = field(default_factory=dict)
    webpack_exposed: bool = False
    source_maps: list = field(default_factory=list)
    program: str = ""
    program_url: str = ""
    error: str = ""

    def as_dict(self):
        row = dict(self.__dict__)
        return row


WAF_HINT = re.compile(
    r"cloudflare|akamai|incapsula|imperva|sucuri|barracuda|fortiweb|"
    r"awselb|aws-waf|f5-big|big-?ip|mod_security|wallarm|fastly", re.I)


async def analyse_target(fetcher, url, profile, program="", program_url="",
                         script_cap=10):
    """Fetch one target, read its JavaScript, and score it."""
    report = TargetReport(url=url, program=program, program_url=program_url)
    resp = await fetcher.get(url)
    if resp is None or not resp.status:
        report.error = resp.error if resp else "no response"
        report.verdict = f"no response ({report.error})"
        return report
    report.status = resp.status
    report.url = resp.url
    if not (200 <= resp.status < 400):
        report.verdict = f"HTTP {resp.status}"
        return report

    html = resp.body or ""
    headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
    report.csp = headers.get("content-security-policy", "")
    report.waf = bool(WAF_HINT.search(
        " ".join(f"{k}:{v}" for k, v in headers.items())))

    for name, pattern in FRAMEWORKS.items():
        if re.search(pattern, html, re.I):
            report.frameworks.append(name)

    scripts = script_sources(html, report.url)
    bodies = []
    inline = "\n".join(inline_scripts(html))
    if inline.strip():
        bodies.append(("inline", inline))

    fetched = await fetcher.many(scripts[:script_cap], limit=2_000_000)
    for src, script_resp in zip(scripts[:script_cap], fetched):
        if not script_resp.ok or not script_resp.body:
            continue
        is_custom, why = classify_script(src, script_resp.body)
        if is_custom:
            report.custom_scripts += 1
            bodies.append((src, script_resp.body))
        else:
            report.vendor_scripts += 1
            # Vendor code is still read, but only for its version number.
            _detect_libs(script_resp.body, src, report)
        if re.search(r"//[#@]\s*sourceMappingURL=", script_resp.body):
            report.source_maps.append(src)

    combined = "\n".join(body for _, body in bodies)
    _detect_libs(html + "\n" + combined[:200_000], report.url, report)

    report.sinks = _count(combined, SINKS)
    report.sources = _count(combined, SOURCES)
    report.prototype = _count(combined, PROTOTYPE)
    report.merges = _count(combined, MERGE)
    report.framework_unsafe = _count(html + "\n" + combined, FRAMEWORK_UNSAFE)
    report.webpack_exposed, webpack_why = analyse_webpack(combined)

    # postMessage handlers without an origin check.
    for handler in re.findall(
            r"addEventListener\s*\(\s*[\"']message[\"'][\s\S]{0,700}", combined):
        if not re.search(r"\.origin\s*[!=]==?|origin\s*===?\s*[\"']", handler):
            report.postmessage_unchecked += 1

    _score(report, profile, webpack_why)
    return report


def _detect_libs(text, where, report):
    for name, pattern, is_vulnerable, note in VULNERABLE_LIBS:
        match = pattern.search(text or "")
        if not match:
            continue
        version = match.group(1)
        if not is_vulnerable(version):
            continue
        entry = {"library": name, "version": version, "note": note,
                 "where": where}
        if entry not in report.vulnerable_libraries:
            report.vulnerable_libraries.append(entry)


def _score(report, profile, webpack_why=""):
    """Rank the target, and record every signal that moved the number.

    The signals list is the point. A bare score cannot be checked, argued
    with, or used to decide where to start — "72" tells you nothing, whereas
    "innerHTML with location.hash, no CSP, jQuery 3.4.1" tells you what to
    open first.
    """
    score, signals = 0, []

    def add(points, text):
        nonlocal score
        score += points
        signals.append(f"{'+' if points >= 0 else ''}{points}  {text}")

    if report.waf:
        add(-15, "WAF or CDN in front")
    if report.csp:
        unsafe = [d for d in ("'unsafe-inline'", "'unsafe-eval'")
                  if d in report.csp]
        if unsafe:
            add(-5, f"CSP present but allows {', '.join(unsafe)}")
        else:
            add(-25, "strict CSP")
    else:
        add(10, "no Content-Security-Policy")

    if profile == "reflected-stored":
        if report.frameworks:
            add(-30, f"virtual-DOM framework: {', '.join(report.frameworks)}")
        else:
            add(25, "no virtual-DOM framework — server-rendered")
        if report.custom_scripts <= 2:
            add(10, "little client-side code; output is built on the server")
        threshold = 20
    else:
        if report.custom_scripts == 0:
            add(-25, "no application JavaScript found")
        else:
            add(min(report.custom_scripts * 3, 12),
                f"{report.custom_scripts} application bundle(s)")
        if report.sinks:
            add(min(len(report.sinks) * 4, 20),
                "sinks: " + ", ".join(sorted(report.sinks)[:4]))
        if report.sources:
            add(min(len(report.sources) * 3, 15),
                "sources: " + ", ".join(sorted(report.sources)[:4]))
        # A sink and a source together is the thing that matters; either on
        # its own is background noise in any large bundle.
        if report.sinks and report.sources:
            add(12, "both a dangerous sink and an untrusted source present")
        if report.prototype:
            add(min(len(report.prototype) * 4, 12),
                "prototype pollution patterns: "
                + ", ".join(sorted(report.prototype)[:3]))
        if report.merges and report.prototype:
            add(10, "recursive merge beside prototype access")
        if report.postmessage_unchecked:
            add(min(report.postmessage_unchecked * 8, 20),
                f"{report.postmessage_unchecked} postMessage handler(s) with "
                f"no origin check")
        if report.framework_unsafe:
            add(min(len(report.framework_unsafe) * 8, 16),
                "unsafe framework bindings: "
                + ", ".join(sorted(report.framework_unsafe)))
        if report.webpack_exposed:
            add(6, webpack_why or "webpack internals reachable")
        if report.source_maps:
            add(5, f"{len(report.source_maps)} source map(s) published")
        threshold = 30

    for lib in report.vulnerable_libraries:
        add(14, f"{lib['library']} {lib['version']} — {lib['note'][:70]}")

    report.score = max(0, min(100, 50 + score))
    report.signals = signals
    report.verdict = ("worth testing" if score >= threshold
                      else "not a priority")
    return report


# ─────────────────────────────────────────────────────────────────────────────
#  The run
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ReconOptions:
    profile: str = "dom-based"           # dom-based | reflected-stored
    hackerone_key: str = ""
    bugcrowd_key: str = ""
    use_subdomains: bool = False
    program_limit: int = 25
    target_limit: int = 300
    per_wildcard: int = 25
    concurrency: int = 12
    timeout: int = 12
    only_bounty: bool = False
    scope_urls: list = field(default_factory=list)   # test these, no platform


class ReconRun:
    """One bounded pass. Cancellable, and it reports progress as it goes."""

    def __init__(self, options, emit=None, proxy=None, user_agent=DEFAULT_UA):
        self.options = options
        self.emit = emit or (lambda kind, payload: None)
        self.results = []
        self.cancelled = False
        self.started = time.time()
        self.fetcher = Fetcher(concurrency=options.concurrency,
                               timeout=options.timeout, proxy=proxy,
                               user_agent=user_agent)

    def log(self, text, level="info"):
        self.emit("log", {"text": text, "level": level})

    def cancel(self):
        self.cancelled = True

    async def gather_targets(self):
        options = self.options
        if options.scope_urls:
            self.log(f"testing {len(options.scope_urls)} URL(s) supplied "
                     f"directly — no platform API involved")
            return [(u, "", "") for u in options.scope_urls]

        programs = []
        if options.hackerone_key:
            programs += await hackerone_programs(
                self.fetcher, options.hackerone_key, log=self.log)
        if options.bugcrowd_key:
            try:
                programs += await bugcrowd_programs(
                    self.fetcher, options.bugcrowd_key, log=self.log)
            except ValueError as exc:
                self.log(str(exc), "warn")
        if options.only_bounty:
            before = len(programs)
            programs = [p for p in programs if p.get("offers_bounties", True)]
            self.log(f"{before - len(programs)} programme(s) without bounties "
                     f"skipped")
        if not programs:
            raise ValueError(
                "No programmes were returned. Check the API key, or paste "
                "URLs into the target list to test a scope directly.")

        programs = programs[:options.program_limit]
        targets = []
        for program in programs:
            if self.cancelled:
                break
            assets = []
            if program["platform"] == "hackerone":
                assets = await hackerone_scope(
                    self.fetcher, options.hackerone_key, program["handle"])
            if not assets:
                continue
            urls = await scope_to_urls(self.fetcher, assets,
                                       options.use_subdomains,
                                       per_wildcard=options.per_wildcard,
                                       log=self.log)
            self.log(f"{program['name']}: {len(urls)} URL(s) in scope")
            for url in urls:
                targets.append((url, program["name"], program["url"]))
            if len(targets) >= options.target_limit:
                break
        return targets[:options.target_limit]

    async def run(self):
        options = self.options
        self.log(f"XSS Recon starting — profile: {options.profile}")
        targets = await self.gather_targets()
        if not targets:
            self.log("no targets to test", "warn")
            return []
        total = len(targets)
        self.log(f"analysing {total} target(s)")
        done = 0

        async def one(url, program, program_url):
            nonlocal done
            if self.cancelled:
                return None
            try:
                report = await analyse_target(
                    self.fetcher, url, options.profile, program, program_url)
            except Exception as exc:                            # noqa: BLE001
                report = TargetReport(url=url, program=program,
                                      program_url=program_url,
                                      error=type(exc).__name__,
                                      verdict="error")
            done += 1
            self.emit("progress", {"done": done, "total": total,
                                   "current": url})
            if report.verdict == "worth testing":
                self.log(f"✓ {report.score:3d}  {report.url}  "
                         f"({'; '.join(report.signals[:3])})")
                self.emit("result", report.as_dict())
            return report

        batch = max(4, options.concurrency)
        for start in range(0, total, batch):
            if self.cancelled:
                self.log("cancelled", "warn")
                break
            chunk = targets[start:start + batch]
            for report in await asyncio.gather(
                    *[one(*t) for t in chunk]):
                if report is not None:
                    self.results.append(report)

        keep = [r for r in self.results if r.verdict == "worth testing"]
        keep.sort(key=lambda r: -r.score)
        self.log(f"done in {int(time.time() - self.started)}s — "
                 f"{len(keep)} of {total} target(s) worth testing")
        return keep

    def as_text(self):
        lines = [f"# XSS Recon — {self.options.profile}", ""]
        for report in sorted(self.results, key=lambda r: -r.score):
            if report.verdict != "worth testing":
                continue
            lines.append(f"{report.url}  --  {report.score}  --  "
                         f"{report.program_url}")
            for signal in report.signals:
                lines.append(f"      {signal}")
            lines.append("")
        return "\n".join(lines)
