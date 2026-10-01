#!/usr/bin/env python3
"""The chain: what runs, in what order, and what each step is allowed to touch.

The ordering is not arbitrary. It follows the principle that makes recon
tractable — start broad and passive, narrow progressively, and only send
anything intrusive at the very end, against a list that has already been
filtered down to things that are real.

Two steps in here exist specifically because skipping them is how recon runs
produce garbage:

**The wildcard verdict, before any bulk resolution.** If ``*.acme.com``
resolves, then every name you ever guess "exists", and a framework that does
not check first will hand you thousands of phantom hosts and then screenshot
all of them. The verdict is taken per zone, not once for the apex, because
zones routinely wildcard at ``*.dev.acme.com`` and not at the top.

**Response-body deduplication after probing.** Forty thousand hosts sharing one
body hash are one application, not forty thousand. Everything downstream — port
scanning, screenshots, crawling, scanning — runs against the deduplicated set,
which is the difference between a run that finishes and one that does not.

Every stage records the exact command it ran. If a result looks wrong, the
operator can see precisely what produced it and run it by hand. A framework
that hides its command lines cannot be debugged, and a tool you cannot debug
is one you stop trusting.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import random
import re
import socket
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit, parse_qsl, urlunsplit

from .runner import CommandRunner
from .scope import Decision, registrable_domain, normalise_host
from .tools import TOOLS


# ─────────────────────────────────────────────────────────────────────────────
#  Presets
# ─────────────────────────────────────────────────────────────────────────────
# A named profile beats two hundred checkboxes, and it makes a run
# reproducible: "standard, scope hash def456" is a complete description.

PRESETS = {
    "passive": {
        "label": "Passive",
        "blurb": ("Nothing is sent to the target at all. Public sources, "
                  "certificate transparency and archives only. Safe to run "
                  "against a programme before you have read its rules."),
        "stages": ["seeds", "subdomains", "wildcard", "resolve"],
        "active": False,
    },
    "standard": {
        "label": "Standard",
        "blurb": ("The full reconnaissance chain: enumerate, resolve, probe, "
                  "crawl, find parameters, read the JavaScript, check for "
                  "takeovers, and run nuclei at medium and above. No injection "
                  "payloads are sent."),
        "stages": ["seeds", "subdomains", "wildcard", "resolve", "probe",
                   "dedupe", "screenshots", "urls", "params", "js",
                   "takeover", "checks", "nuclei"],
        "active": False,
    },
    "deep": {
        "label": "Deep",
        "blurb": ("Everything in Standard, plus permutation brute-forcing, "
                  "port scanning, headless crawling and screenshots. Slower "
                  "and noisier; still sends no injection payloads."),
        "stages": ["seeds", "subdomains", "permute", "wildcard", "resolve",
                   "probe", "dedupe", "screenshots", "ports", "urls", "params",
                   "js", "takeover", "checks", "nuclei"],
        "active": False,
    },
    "monitor": {
        "label": "Monitor",
        "blurb": ("A fast pass designed to be run on a schedule: find what is "
                  "new since last time and check it. Skips the expensive "
                  "stages entirely."),
        "stages": ["seeds", "subdomains", "wildcard", "resolve", "probe",
                   "dedupe", "takeover", "checks", "nuclei"],
        "active": False,
    },
}

#: Active probe stages. Each one sends payloads, so each is opt-in on its own
#: and none of them is reachable without the run-level active acknowledgement.
ACTIVE_STAGES = {
    "inject": ("Built-in injection checks",
               "Reflection with context analysis, open redirect, error and "
               "boolean SQL injection, and path traversal — against every "
               "parameter found. Needs nothing installed."),
    "dast": ("Fuzzing templates (XSS, SQLi, SSTI, LFI, open redirect)",
             "Sends injection payloads to every parameter found. This is the "
             "stage most likely to trip a WAF."),
    "xss": ("Dedicated XSS discovery with dalfox",
            "Reflection analysis and payload testing on parameterised URLs."),
    "takeover_active": ("Active takeover confirmation",
                        "Requests the dangling host to read the provider's "
                        "error page."),
}


#: The chain, grouped into the phases a tester actually thinks in. The
#: interface presents these as numbered steps; the engine still runs stages.
#: Keeping the grouping here rather than in the front end means the two can
#: never disagree about what belongs where.
PHASES = [
    {
        "key": "scope", "number": 1, "label": "Scope",
        "blurb": "Fix the boundary before anything is sent.",
        "stages": ["seeds"],
    },
    {
        "key": "discover", "number": 2, "label": "Discover",
        "blurb": ("Find every name that belongs to the target, decide which "
                  "zones answer for anything, and resolve what is real."),
        "stages": ["subdomains", "permute", "wildcard", "resolve"],
    },
    {
        "key": "alive", "number": 3, "label": "See what is alive",
        "blurb": ("Probe for HTTP, collapse the hosts that serve the same "
                  "application, and photograph what is left."),
        "stages": ["probe", "dedupe", "screenshots", "ports"],
    },
    {
        "key": "explore", "number": 4, "label": "Explore the surface",
        "blurb": ("Crawl and mine archives for URLs, work out which "
                  "parameters matter, and read the JavaScript."),
        "stages": ["urls", "params", "js"],
    },
    {
        "key": "test", "number": 5, "label": "Test",
        "blurb": ("Takeover triage and template scanning. Injection testing "
                  "only if you have turned it on."),
        "stages": ["takeover", "checks", "nuclei", "inject", "dast", "xss"],
    },
]


def phase_for(stage_key: str) -> str:
    for phase in PHASES:
        if stage_key in phase["stages"]:
            return phase["key"]
    return "test"


@dataclass
class StageContext:
    """Everything a stage needs, and nothing it does not."""
    store: object
    scope: object
    proxy: object
    registry: object
    program_id: int
    run_id: int
    workdir: Path
    config: dict = field(default_factory=dict)
    emit: object = None
    findings: list = field(default_factory=list)

    def log(self, text, level="info"):
        if self.emit:
            self.emit("log", {"text": text, "level": level})

    def counter(self, name, value):
        if self.emit:
            self.emit("counter", {"name": name, "value": value})

    def runner(self, log_path=None, tool_key=""):
        """A runner wired to the proxy, so the tool cannot leave scope."""
        env = dict(self.proxy.env()) if self.proxy else {}
        return CommandRunner(env_extra=env,
                             on_line=lambda kind, line: self._tool_line(tool_key, kind, line),
                             log_path=str(log_path) if log_path else None)

    def _tool_line(self, tool_key, kind, line):
        if not line.strip():
            return
        if self.emit:
            self.emit("tool", {"tool": tool_key, "stream": kind, "text": line[:2000]})

    def identification(self, tool_key):
        """Header arguments that put the operator's handle on the request."""
        tool = TOOLS.get(tool_key)
        if not tool:
            return []
        headers = (self.config.get("headers") or {})
        return tool.header_args(headers, self.config.get("user_agent", ""))

    def rate_args(self, tool_key):
        """The rate flag for a tool, from the limit that actually applies to it.

        A programme's requests-per-second is a limit on what reaches *its*
        servers. A DNS resolver and a passive source are not its servers, and
        throttling those to 5/s only made DNS resolution take hours.
        """
        tool = TOOLS.get(tool_key)
        if not tool or not tool.rate_flag:
            return []
        if tool.rate_scope == "dns":
            rps = self.config.get("dns_rps", 300)
        elif tool.rate_scope == "source":
            rps = self.config.get("source_rps", 0)
        else:
            rps = self.config.get("per_host_rps", 5)
        try:
            rps = int(float(rps))
        except (TypeError, ValueError):
            rps = 0
        if rps <= 0:
            return []                       # unlimited: let the tool decide
        return [tool.rate_flag, str(rps)]

    def write_list(self, name, items):
        path = self.workdir / name
        path.write_text("\n".join(items) + ("\n" if items else ""), encoding="utf-8")
        return path

    def live_urls(self):
        """The live HTTP services, deduplicated if a dedupe has happened.

        Three sources, in order: this run's ``distinct.txt``, this run's
        ``live.txt``, and failing both, the stored http_service assets. The
        last one matters: a run gets its own directory, so a single step run
        on its own has neither file, and before this every later step reported
        "nothing live" against a database full of live hosts.
        """
        for name in ("distinct.txt", "live.txt"):
            path = self.workdir / name
            if path.is_file():
                items = [l.strip() for l in
                         path.read_text(errors="replace").splitlines() if l.strip()]
                if items:
                    return items
        return [a["key"] for a in
                self.store.assets(self.program_id, "http_service", limit=100000)]


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _jsonl(lines):
    for line in lines:
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            yield json.loads(line)
        except Exception:
            continue


def query_signature(url: str) -> str:
    """The shape of a URL with its values stripped.

    ``/p?id=1&ref=abc`` and ``/p?id=99&ref=xyz`` are the same endpoint and
    should be looked at once. Collapsing on this turns fifty thousand URLs
    into a few hundred things worth examining, which is the single most
    useful transform available on a URL corpus.
    """
    try:
        parts = urlsplit(url)
    except Exception:
        return url
    names = sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)})
    path = re.sub(r"/\d+(?=/|$)", "/{id}", parts.path or "/")
    path = re.sub(r"/[0-9a-f]{8,}(?=/|$)", "/{hash}", path, flags=re.I)
    return f"{parts.scheme}://{parts.netloc}{path}" + ("?" + "&".join(names) if names else "")


#: One pool for name lookups, sized so a wall of dead names cannot starve
#: everything else that wants a thread.
_DNS_POOL = None


def _dns_pool():
    global _DNS_POOL
    if _DNS_POOL is None:
        from concurrent.futures import ThreadPoolExecutor
        _DNS_POOL = ThreadPoolExecutor(max_workers=64,
                                       thread_name_prefix="bbhunter-dns")
    return _DNS_POOL


def _blocking_lookup(name):
    return sorted({info[4][0] for info in
                   socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)})


async def _resolve_one(name, timeout=3.0):
    """Resolve one name, or return [] — quietly, whatever goes wrong.

    The shield-and-drain dance is the point. `getaddrinfo` is a blocking call
    in a thread; cancelling the wait does not cancel the thread, so when the
    lookup of a name that does not exist finally fails, its exception lands on
    a future nobody is waiting for and asyncio prints "Future exception was
    never retrieved" to the terminal. Enumerate a few thousand permutations
    and the console fills with those instead of the scan. Retrieving the
    exception in a done-callback is what makes it stop.
    """
    loop = asyncio.get_running_loop()
    future = loop.run_in_executor(_dns_pool(), _blocking_lookup, name)
    try:
        return await asyncio.wait_for(asyncio.shield(future), timeout=timeout)
    except asyncio.TimeoutError:
        future.add_done_callback(lambda f: f.cancelled() or f.exception())
        return []
    except Exception:
        return []


async def http_probe(ctx, target, timeout=10):
    """Probe one host through the proxy, returning what httpx would report.

    This exists so the framework is useful the moment it is cloned, before
    anything is installed. httpx is faster and reports far more, and is used
    whenever it is present — but a recon tool that does nothing at all until
    six Go binaries are on PATH is a tool people give up on during setup.
    """
    def _get(url):
        handler = urllib.request.ProxyHandler(
            {"http": ctx.proxy.url, "https": ctx.proxy.url} if ctx.proxy else {})
        opener = urllib.request.build_opener(handler)
        headers = dict(ctx.config.get("headers") or {})
        if ctx.config.get("user_agent"):
            headers["User-Agent"] = ctx.config["user_agent"]
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read(300_000)
                return resp.status, dict(resp.headers), body, resp.geturl()
        except urllib.error.HTTPError as exc:
            body = b""
            try:
                body = exc.read(300_000)
            except Exception:
                pass
            return exc.code, dict(exc.headers or {}), body, url
        except Exception:
            return None

    loop = asyncio.get_running_loop()
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        result = await loop.run_in_executor(None, _get, url)
        if not result:
            continue
        status, headers, body, final = result
        text = body.decode("utf-8", "replace")
        title = ""
        match = re.search(r"<title[^>]*>(.*?)</title>", text,
                          re.I | re.S)
        if match:
            title = re.sub(r"\s+", " ", match.group(1)).strip()[:200]
        return {
            "url": final or url,
            "status_code": status,
            "title": title,
            "webserver": headers.get("Server", ""),
            "content_length": len(body),
            "location": headers.get("Location", ""),
            "hash": {"body_sha256": hashlib.sha256(body).hexdigest()},
            "body": text,
            "host": target,
        }
    return None


async def _fetch_json(url, timeout=25):
    """A small direct fetch for public data sources.

    These are lookups against crt.sh and similar — third-party services, not
    the target — so they do not go through the scope proxy. Nothing here ever
    contacts an asset under test.
    """
    def _get():
        req = urllib.request.Request(url, headers={
            "User-Agent": "bbhunter/recon",
            "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    return await asyncio.get_running_loop().run_in_executor(None, _get)


class _BuiltinCrawlMixin:
    """A deliberately small link crawler.

    It follows anchors and script sources to a shallow depth and nothing else
    — no JavaScript execution, no form submission. katana does this far
    better; this exists so a fresh clone produces something useful, and so the
    parameter and JavaScript stages have input to work with.
    """

    LINK_RE = re.compile(r"""(?:href|src)\s*=\s*["\']([^"\'<>]{1,400})["\']""",
                         re.I)

    async def _builtin_crawl(self, ctx, targets, depth=2, cap=400):
        seen = set()
        found = set()
        queue = [(t, 0) for t in targets[:30]]

        while queue and len(seen) < cap:
            url, level = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            if not ctx.scope.classify(url).allowed:
                continue
            probed = await http_probe(ctx, url.split("://", 1)[-1]
                                      if "://" in url else url)
            if not probed:
                continue
            found.add(probed["url"])
            if level >= depth:
                continue
            base = probed["url"]
            for href in self.LINK_RE.findall(probed.get("body") or ""):
                if href.startswith(("mailto:", "tel:", "javascript:", "data:", "#")):
                    continue
                try:
                    absolute = urllib.parse.urljoin(base, href)
                except Exception:
                    continue
                if not absolute.startswith("http"):
                    continue
                if ctx.scope.classify(absolute).allowed:
                    found.add(absolute)
                    if absolute not in seen:
                        queue.append((absolute, level + 1))
        return found



# ─────────────────────────────────────────────────────────────────────────────
#  Stages
# ─────────────────────────────────────────────────────────────────────────────

class Stage:
    key = "stage"
    name = "Stage"
    tool_key = ""
    description = ""

    async def run(self, ctx: StageContext) -> dict:
        raise NotImplementedError

    def stage_key(self, ctx: StageContext, inputs) -> str:
        """Content-addressed identity, for resume.

        Includes the tool version and the scope hash, so the stage
        re-runs when either changes rather than being wrongly skipped.
        """
        version = (ctx.registry.state.get(self.tool_key) or {}).get("version", "")
        payload = json.dumps({
            "stage": self.key, "tool": self.tool_key, "version": version,
            "scope": ctx.scope.fingerprint(),
            "inputs": sorted(inputs)[:5000],
            "config": {k: v for k, v in sorted(ctx.config.items())
                       if k in ("per_host_rps", "deep", "headers", "user_agent")},
        }, sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()[:24]


class SeedStage(Stage):
    key, name = "seeds", "Scope and seeds"
    description = "Turn the scope rules into the starting set of root domains."

    async def run(self, ctx):
        seeds = []
        for seed in ctx.scope.seeds:
            host = normalise_host(seed)
            if host:
                seeds.append(host)

        unusable = []
        for rule in ctx.scope.include:
            host = self._host_from_rule(rule)
            if host:
                if host not in seeds:
                    seeds.append(host)
            else:
                unusable.append(rule.value)
        if unusable:
            # An address range or an anchored regular expression is a perfectly
            # good boundary and a useless starting point: there is no name to
            # enumerate from. Saying so beats a run that quietly starts from
            # fewer roots than the scope appears to contain.
            ctx.log(f"{len(unusable)} scope rule(s) cannot seed enumeration "
                    f"(no domain to start from): "
                    + ", ".join(unusable[:5])
                    + ". They still admit anything discovered another way.",
                    "warn")

        allowed, observed, denied = ctx.scope.partition(seeds)
        if denied:
            ctx.log(f"{len(denied)} seed(s) refused by the scope engine: "
                    + ", ".join(f"{a} ({why})" for a, why in denied[:5]), "warn")
        ctx.store.upsert_assets(ctx.program_id, ctx.run_id, "root", [
            {"key": s, "source": "scope", "decision": "allow"} for s in allowed])
        ctx.counter("roots", len(allowed))
        ctx.log(f"{len(allowed)} root domain(s) in scope: {', '.join(allowed[:8])}"
                + (" …" if len(allowed) > 8 else ""))
        return {"roots": allowed, "produced": len(allowed)}

    @staticmethod
    def _host_from_rule(rule):
        """The name to start enumerating from, for each kind of scope rule.

        A bare domain gives itself. A URL gives its host — which is the case
        that used to be dropped: paste a programme's scope as a list of URLs
        and enumeration started from nothing at all. A glob gives the part of
        the name that is fixed, so `api-*.edge.acme.com` starts from
        `edge.acme.com`. A CIDR or a regular expression gives nothing, and the
        caller says so rather than pretending otherwise.
        """
        value = (rule.value or "").strip()
        kind = getattr(rule.kind, "name", str(rule.kind)).upper()
        if kind == "URL":
            host = urlsplit(value if "//" in value else "//" + value).hostname
            return normalise_host(host or "")
        if kind == "GLOB":
            labels = value.split(".")
            while labels and "*" in labels[0]:
                labels.pop(0)
            fixed = ".".join(labels)
            # One label left is a public suffix, not a target.
            return normalise_host(fixed) if fixed.count(".") >= 1 else ""
        if kind in ("CIDR", "REGEX", "IP"):
            return ""
        return normalise_host(value)


class SubdomainStage(Stage):
    key, name, tool_key = "subdomains", "Subdomain enumeration", "subfinder"
    description = ("Passive sources, certificate transparency and — where a "
                   "token is configured — public code search.")

    async def run(self, ctx):
        roots = ctx.store.asset_keys(ctx.program_id, "root")
        if not roots:
            return {"produced": 0, "skipped": "no in-scope root domains"}

        # The roots are assets in their own right. A scope that lists exact
        # hosts with no subdomains is completely normal, and a chain that only
        # carries forward what enumeration *discovered* would probe nothing at
        # all in that case.
        found = set(roots)
        sources = {"scope": len(roots)}

        # crt.sh needs no installation and is consistently one of the highest
        # yield sources, so it runs whatever else is available.
        for root in roots:
            try:
                ctx.log(f"certificate transparency: crt.sh for {root}")
                rows = await _fetch_json(
                    f"https://crt.sh/?q=%25.{root}&output=json", timeout=45)
                names = set()
                for row in rows or []:
                    for value in str(row.get("name_value", "")).split("\n"):
                        host = normalise_host(value.strip().lstrip("*."))
                        if host:
                            names.add(host)
                found |= names
                sources["crt.sh"] = sources.get("crt.sh", 0) + len(names)
                ctx.log(f"  crt.sh returned {len(names)} name(s) for {root}")
            except Exception as exc:
                ctx.log(f"  crt.sh failed for {root}: {exc}", "warn")

        roots_file = ctx.write_list("roots.txt", roots)

        if ctx.registry.have("subfinder"):
            log = ctx.workdir / "logs" / "subfinder.log"
            argv = [ctx.registry.path("subfinder"), "-dL", str(roots_file),
                    "-all", "-silent", "-oJ"] + ctx.rate_args("subfinder")
            result = await ctx.runner(log, "subfinder").run(
                argv, timeout=ctx.config.get("stage_timeout", 1800), idle_timeout=300)
            names = set()
            for obj in _jsonl(result.stdout_lines):
                host = normalise_host(obj.get("host") or obj.get("input") or "")
                if host:
                    names.add(host)
            found |= names
            sources["subfinder"] = len(names)
            ctx.log(f"subfinder returned {len(names)} name(s)")
            ctx.store.update_stage(ctx.config["_stage_id"], command=result.command)
        else:
            ctx.log("subfinder is not installed — running with crt.sh only", "warn")

        for key, args in (("assetfinder", ["--subs-only"]),
                          ("chaos", ["-silent"])):
            if not ctx.registry.have(key):
                continue
            names = set()
            for root in roots:
                log = ctx.workdir / "logs" / f"{key}.log"
                argv = ([ctx.registry.path(key)] + args + [root] if key == "assetfinder"
                        else [ctx.registry.path(key), "-d", root] + args)
                result = await ctx.runner(log, key).run(argv, timeout=600, idle_timeout=180)
                for line in result.stdout_lines:
                    host = normalise_host(line.strip())
                    if host:
                        names.add(host)
            found |= names
            sources[key] = len(names)
            ctx.log(f"{key} returned {len(names)} name(s)")

        # Only names that belong to the scope are kept; the rest are recorded
        # as observed so the operator can see what was found without anything
        # ever being sent to them.
        in_scope, observed, denied = ctx.scope.partition(sorted(found))
        ctx.store.upsert_assets(ctx.program_id, ctx.run_id, "subdomain", [
            {"key": h, "decision": "allow", "source": "enumeration"} for h in in_scope])
        if observed:
            ctx.store.upsert_assets(ctx.program_id, ctx.run_id, "out_of_scope_host", [
                {"key": h, "decision": "observe",
                 "reason": "discovered from an in-scope asset but not in scope"}
                for h in observed])

        ctx.counter("subdomains", len(in_scope))
        discovered = len(found) - len(roots)
        ctx.log(f"{discovered} name(s) discovered beyond the {len(roots)} root(s) — "
                f"{len(in_scope)} in scope, {len(observed)} recorded but out of "
                f"scope, {len(denied)} refused")
        return {"produced": len(in_scope), "sources": sources,
                "observed": len(observed)}


class PermuteStage(Stage):
    key, name, tool_key = "permute", "Permutation", "alterx"
    description = "Generate plausible new names from the ones already found."

    async def run(self, ctx):
        if not ctx.registry.have("alterx"):
            return {"produced": 0, "skipped": "alterx is not installed"}
        known = ctx.store.asset_keys(ctx.program_id, "subdomain")
        if not known:
            return {"produced": 0, "skipped": "nothing to permute"}

        source = ctx.write_list("known_subs.txt", known)
        limit = int(ctx.config.get("permutation_limit", 100000))
        argv = [ctx.registry.path("alterx"), "-list", str(source),
                "-enrich", "-limit", str(limit), "-silent"]
        result = await ctx.runner(ctx.workdir / "logs" / "alterx.log", "alterx").run(
            argv, timeout=900, idle_timeout=180)
        candidates = {normalise_host(l.strip()) for l in result.stdout_lines}
        candidates = {c for c in candidates if c and c not in set(known)}
        ctx.write_list("permutations.txt", sorted(candidates))
        ctx.log(f"alterx generated {len(candidates)} candidate name(s) to resolve")
        return {"produced": len(candidates), "command": result.command}


class WildcardStage(Stage):
    key, name = "wildcard", "Wildcard DNS verdict"
    description = ("Establish which zones answer for anything, before any bulk "
                   "resolution trusts a result.")

    async def run(self, ctx):
        roots = ctx.store.asset_keys(ctx.program_id, "root")
        known = ctx.store.asset_keys(ctx.program_id, "subdomain")

        # Test the apex and every intermediate zone, because wildcards are
        # routinely configured part-way down and a single apex test misses them.
        zones = set(roots)
        for host in known:
            labels = host.split(".")
            for depth in range(2, min(len(labels), 5)):
                zones.add(".".join(labels[-depth:]))
        zones = {z for z in zones if z}

        verdicts = {}
        for zone in sorted(zones):
            probes = [f"{random.randbytes(12).hex()}.{zone}" for _ in range(4)]
            answers = await asyncio.gather(
                *[_resolve_one(p) for p in probes], return_exceptions=True)
            answers = [a for a in answers if isinstance(a, list)]
            resolving = [a for a in answers if a]
            if len(resolving) >= 3:
                addresses = sorted({ip for a in resolving for ip in a})
                verdicts[zone] = addresses
                ctx.log(f"wildcard detected on *.{zone} → {', '.join(addresses[:4])}",
                        "warn")

        if verdicts:
            ctx.store.upsert_assets(ctx.program_id, ctx.run_id, "wildcard_zone", [
                {"key": zone, "data": {"addresses": ips}}
                for zone, ips in verdicts.items()])
            ctx.log(f"{len(verdicts)} wildcard zone(s). Names resolving only to "
                    f"these addresses will be treated as phantoms.", "warn")
        else:
            ctx.log("no wildcard DNS found — resolution results can be trusted "
                    "at face value")
        ctx.config["_wildcards"] = verdicts
        return {"produced": len(verdicts), "wildcards": verdicts}


class ResolveStage(Stage):
    key, name, tool_key = "resolve", "DNS resolution", "dnsx"
    description = "Resolve everything found, discarding wildcard phantoms."

    async def run(self, ctx):
        names = set(ctx.store.asset_keys(ctx.program_id, "subdomain"))
        perms = ctx.workdir / "permutations.txt"
        if perms.exists():
            names |= {l.strip() for l in perms.read_text().splitlines() if l.strip()}
        names = sorted(n for n in names if n)
        if not names:
            return {"produced": 0, "skipped": "nothing to resolve"}

        wildcards = ctx.config.get("_wildcards") or {}
        wildcard_ips = {ip for ips in wildcards.values() for ip in ips}
        live = {}

        if ctx.registry.have("dnsx"):
            source = ctx.write_list("to_resolve.txt", names)
            argv = [ctx.registry.path("dnsx"), "-l", str(source), "-a", "-cname",
                    "-resp", "-json", "-silent", "-t", "100"] + ctx.rate_args("dnsx")
            result = await ctx.runner(ctx.workdir / "logs" / "dnsx.log", "dnsx").run(
                argv, timeout=1800, idle_timeout=300)
            for obj in _jsonl(result.stdout_lines):
                host = normalise_host(obj.get("host", ""))
                if not host:
                    continue
                addresses = obj.get("a") or []
                live[host] = {"a": addresses, "cname": (obj.get("cname") or [None])[0]}
            command = result.command
        else:
            ctx.log("dnsx is not installed — resolving with the system resolver, "
                    "which is slower", "warn")
            semaphore = asyncio.Semaphore(64)

            async def one(name):
                async with semaphore:
                    addresses = await _resolve_one(name)
                    if addresses:
                        live[name] = {"a": addresses, "cname": None}

            await asyncio.gather(*[one(n) for n in names],
                                 return_exceptions=True)
            command = "(built-in resolver)"

        phantoms = []
        resolved = []
        for host, data in live.items():
            addresses = set(data.get("a") or [])
            if addresses and wildcard_ips and addresses.issubset(wildcard_ips):
                # Every address this name has is a wildcard address, so the
                # name does not exist as a distinct host.
                if host not in set(ctx.store.asset_keys(ctx.program_id, "subdomain")):
                    phantoms.append(host)
                    continue
            resolved.append({"key": host, "decision": "allow",
                             "data": {"a": sorted(addresses),
                                      "cname": data.get("cname")},
                             "source": "dns"})

        ctx.store.upsert_assets(ctx.program_id, ctx.run_id, "subdomain", resolved)
        ctx.counter("resolved", len(resolved))
        message = f"{len(resolved)} name(s) resolve"
        if phantoms:
            message += (f"; {len(phantoms)} discarded as wildcard phantoms — "
                        f"they resolve only to the wildcard address")
        ctx.log(message)
        ctx.write_list("resolved.txt", sorted(r["key"] for r in resolved))
        return {"produced": len(resolved), "phantoms": len(phantoms),
                "command": command}


class ProbeStage(Stage):
    key, name, tool_key = "probe", "HTTP probing", "httpx"
    description = ("Find which hosts actually serve HTTP, with status, title, "
                   "technology and a body hash.")

    async def run(self, ctx):
        resolved = ctx.workdir / "resolved.txt"
        names = ([l.strip() for l in resolved.read_text().splitlines() if l.strip()]
                 if resolved.exists() else ctx.store.asset_keys(ctx.program_id, "subdomain"))
        names = ctx.scope.filter_allowed(names)      # the input gate
        if not names:
            return {"produced": 0, "skipped": 'nothing resolved to probe. Run Step 2 (Discover) first, or add the hosts you already know as seeds on the Scope page.'}
        if not ctx.registry.have("httpx"):
            ctx.log("httpx is not installed — probing with the built-in prober. "
                    "Install httpx for technology detection, CDN identification "
                    "and far more speed.", "warn")
            return await self._builtin(ctx, names)

        source = ctx.write_list("probe_targets.txt", names)
        argv = [ctx.registry.path("httpx"), "-l", str(source),
                "-sc", "-title", "-td", "-server", "-cl", "-location", "-method",
                "-cdn", "-ip", "-hash", "sha256", "-json", "-silent",
                "-t", "40", "-timeout", "10", "-retries", "1"]
        argv += ctx.rate_args("httpx")
        argv += ctx.identification("httpx")
        tool = TOOLS["httpx"]
        if tool.proxy_flag and ctx.proxy:
            argv += [tool.proxy_flag, ctx.proxy.url]

        result = await ctx.runner(ctx.workdir / "logs" / "httpx.log", "httpx").run(
            argv, timeout=ctx.config.get("stage_timeout", 2400), idle_timeout=300)

        rows = []
        for obj in _jsonl(result.stdout_lines):
            url = obj.get("url") or ""
            if not url:
                continue
            if not ctx.scope.classify(url).allowed:
                continue                      # the output gate
            rows.append({
                "key": url, "decision": "allow", "source": "httpx",
                "data": {
                    "status": obj.get("status_code"),
                    "title": (obj.get("title") or "")[:200],
                    "tech": obj.get("tech") or [],
                    "server": obj.get("webserver") or "",
                    "length": obj.get("content_length"),
                    "cdn": obj.get("cdn_name") or "",
                    "host": obj.get("host") or "",
                    "body_hash": (obj.get("hash") or {}).get("body_sha256", ""),
                    "location": obj.get("location") or "",
                },
            })

        ctx.store.upsert_assets(ctx.program_id, ctx.run_id, "http_service", rows)
        ctx.counter("live_http", len(rows))
        ctx.log(f"{len(rows)} live HTTP service(s) from {len(names)} name(s)")
        ctx.write_list("live.txt", sorted(r["key"] for r in rows))
        return {"produced": len(rows), "command": result.command}

    @staticmethod
    async def _builtin(ctx, names):
        semaphore = asyncio.Semaphore(16)
        rows = []
        bodies = {}

        async def one(name):
            async with semaphore:
                probed = await http_probe(ctx, name)
                if not probed:
                    return
                if not ctx.scope.classify(probed["url"]).allowed:
                    return
                bodies[probed["url"]] = probed.pop("body", "")
                rows.append({
                    "key": probed["url"], "decision": "allow", "source": "built-in",
                    "data": {k: v for k, v in {
                        "status": probed["status_code"],
                        "title": probed["title"],
                        "server": probed["webserver"],
                        "length": probed["content_length"],
                        "location": probed["location"],
                        "host": probed["host"],
                        "body_hash": probed["hash"]["body_sha256"],
                    }.items() if v not in (None, "")},
                })

        await asyncio.gather(*[one(n) for n in names], return_exceptions=True)
        ctx.store.upsert_assets(ctx.program_id, ctx.run_id, "http_service", rows)
        ctx.counter("live_http", len(rows))
        ctx.write_list("live.txt", sorted(r["key"] for r in rows))
        (ctx.workdir / "bodies.json").write_text(json.dumps(bodies))
        ctx.log(f"{len(rows)} live HTTP service(s) from {len(names)} name(s)")
        return {"produced": len(rows), "command": "(built-in prober)"}


class DedupeStage(Stage):
    key, name = "dedupe", "Deduplicate by response"
    description = ("Collapse hosts that serve the same application, so later "
                   "stages run against distinct things rather than copies.")

    async def run(self, ctx):
        services = ctx.store.assets(ctx.program_id, "http_service", limit=100000)
        if not services:
            return {"produced": 0, "skipped": 'no live hosts to work from. Run Step 3 (See what is alive) first — on its own is fine, it starts from the previous run.'}

        clusters = {}
        for service in services:
            data = service.get("data") or {}
            signature = (data.get("body_hash") or "") + "|" + (data.get("title") or "")
            clusters.setdefault(signature, []).append(service["key"])

        representatives = []
        for signature, members in clusters.items():
            representatives.append(sorted(members)[0])

        wasted = len(services) - len(representatives)
        ctx.write_list("distinct.txt", sorted(representatives))
        ctx.counter("distinct_apps", len(representatives))
        if wasted > 0:
            ctx.log(f"{len(services)} services collapse to {len(representatives)} "
                    f"distinct application(s) — {wasted} are duplicates of another "
                    f"host and will not be crawled or screenshotted again")
        else:
            ctx.log(f"{len(representatives)} distinct application(s)")

        biggest = sorted(clusters.items(), key=lambda kv: -len(kv[1]))[:3]
        for signature, members in biggest:
            if len(members) > 3:
                ctx.log(f"  {len(members)} hosts share one response: "
                        f"{members[0]} and {len(members) - 1} others")
        return {"produced": len(representatives), "clusters": len(clusters)}


class PortStage(Stage):
    key, name, tool_key = "ports", "Port discovery", "naabu"
    description = "Top ports on non-CDN addresses, feeding anything new back into probing."

    async def run(self, ctx):
        if not ctx.registry.have("naabu"):
            return {"produced": 0, "skipped": "naabu is not installed"}
        names = ctx.scope.filter_allowed(
            ctx.store.asset_keys(ctx.program_id, "subdomain"))
        if not names:
            return {"produced": 0, "skipped": 'no live hosts to work from. Run Step 3 (See what is alive) first — on its own is fine, it starts from the previous run.'}

        source = ctx.write_list("port_targets.txt", names)
        argv = [ctx.registry.path("naabu"), "-list", str(source),
                "-top-ports", str(ctx.config.get("top_ports", 1000)),
                "-exclude-cdn", "-silent", "-json",
                "-c", "25", "-rate", str(int(ctx.config.get("port_rate", 500)))]
        result = await ctx.runner(ctx.workdir / "logs" / "naabu.log", "naabu").run(
            argv, timeout=2400, idle_timeout=420)

        rows = []
        for obj in _jsonl(result.stdout_lines):
            host = obj.get("host") or obj.get("ip") or ""
            port = obj.get("port")
            if not host or not port:
                continue
            if not ctx.scope.classify(host).allowed:
                continue
            rows.append({"key": f"{host}:{port}", "decision": "allow",
                         "source": "naabu",
                         "data": {"host": host, "port": port,
                                  "ip": obj.get("ip", "")}})
        ctx.store.upsert_assets(ctx.program_id, ctx.run_id, "port", rows)
        ctx.counter("open_ports", len(rows))
        ctx.log(f"{len(rows)} open port(s). CDN addresses were limited to 80 and 443, "
                f"which is the only sensible thing to scan on shared infrastructure.")
        return {"produced": len(rows), "command": result.command}


class UrlStage(_BuiltinCrawlMixin, Stage):
    key, name, tool_key = "urls", "URL discovery", "katana"
    description = "Archives and an active crawl, collapsed to distinct endpoint shapes."

    async def run(self, ctx):
        targets = ctx.live_urls()
        if not targets:
            return {"produced": 0, "skipped": 'no live hosts to work from. Run Step 3 (See what is alive) first — on its own is fine, it starts from the previous run.'}
        targets = ctx.scope.filter_allowed(targets)
        if not targets:
            return {"produced": 0, "skipped": "nothing in scope to crawl"}

        urls = set()
        commands = []
        target_file = ctx.write_list("crawl_targets.txt", targets)

        if ctx.registry.have("gau"):
            roots = ctx.store.asset_keys(ctx.program_id, "root")
            argv = [ctx.registry.path("gau"), "--subs", "--threads", "5"] + roots
            result = await ctx.runner(ctx.workdir / "logs" / "gau.log", "gau").run(
                argv, timeout=1200, idle_timeout=240)
            before = len(urls)
            urls |= {u.strip() for u in result.stdout_lines if u.strip().startswith("http")}
            commands.append(result.command)
            ctx.log(f"gau returned {len(urls) - before} archived URL(s)")

        if ctx.registry.have("katana"):
            argv = [ctx.registry.path("katana"), "-list", str(target_file),
                    "-jc", "-kf", "all", "-fs", "rdn", "-silent", "-jsonl",
                    "-d", str(ctx.config.get("crawl_depth", 3)),
                    "-c", "10", "-timeout", "10"]
            argv += ctx.rate_args("katana")
            argv += ctx.identification("katana")
            if ctx.proxy:
                argv += ["-proxy", ctx.proxy.url]
            result = await ctx.runner(ctx.workdir / "logs" / "katana.log", "katana").run(
                argv, timeout=ctx.config.get("stage_timeout", 2400), idle_timeout=300)
            before = len(urls)
            for obj in _jsonl(result.stdout_lines):
                endpoint = (obj.get("request") or {}).get("endpoint") or obj.get("url")
                if endpoint:
                    urls.add(endpoint)
            commands.append(result.command)
            ctx.log(f"katana crawled {len(urls) - before} URL(s)")

        # ── The built-in sources ─────────────────────────────────────────
        # These run whether or not katana and gau are installed, and they are
        # the reason a fresh clone finds a real attack surface rather than a
        # handful of anchor hrefs. The previous behaviour — fall back to a
        # link-only crawl of 30 hosts, but only when both tools were missing —
        # is what turned 1,500 live hosts into four parameters.
        from . import discovery

        fetcher = discovery.Fetcher(
            concurrency=int(ctx.config.get("http_concurrency", 20)),
            timeout=int(ctx.config.get("http_timeout", 12)),
            proxy=ctx.proxy.url if ctx.proxy else None,
            headers=dict(ctx.config.get("headers") or {}),
            user_agent=ctx.config.get("user_agent") or discovery.DEFAULT_UA)
        scope_ok = lambda u: ctx.scope.classify(u).allowed        # noqa: E731

        if ctx.config.get("use_archives", True):
            roots = ctx.store.asset_keys(ctx.program_id, "root")
            if roots:
                ctx.log(f"querying public archives for {len(roots)} root "
                        f"domain(s) — nothing is sent to the target")
                before = len(urls)
                archived = await discovery.archive_urls(
                    fetcher, roots[:40], log=lambda t: ctx.log(t))
                urls |= archived
                ctx.log(f"archives returned {len(urls) - before} URL(s)")

        surface = discovery.Surface()
        page_cap = int(ctx.config.get("crawl_page_cap", 600))
        host_cap = int(ctx.config.get("crawl_host_cap", 400))
        seeds = targets[:host_cap]
        ctx.log(f"crawling {len(seeds)} host(s) for forms, scripts and "
                f"endpoints")

        async def _one(base):
            try:
                await discovery.crawl_page(fetcher, base, surface,
                                           scope_ok=scope_ok)
                extra = await discovery.robots_and_sitemap(fetcher, base)
                for item in extra:
                    if scope_ok(item):
                        surface.urls.add(item)
                spec = await discovery.openapi_surface(fetcher, base)
                if spec:
                    surface.openapi.append(spec["document"])
                    surface.endpoints |= {e for e in spec["endpoints"]
                                          if scope_ok(e)}
                    for name in spec["parameters"]:
                        surface.add_param(name, "openapi", spec["document"])
                    ctx.log(f"  OpenAPI document at {spec['document']}: "
                            f"{len(spec['endpoints'])} endpoint(s), "
                            f"{len(spec['parameters'])} parameter(s)")
            except Exception as exc:                            # noqa: BLE001
                return

        for start in range(0, len(seeds), 25):
            if len(surface.urls) + len(urls) > page_cap * 60:
                break
            await asyncio.gather(*[_one(b) for b in seeds[start:start + 25]])

        urls |= surface.urls
        urls |= surface.endpoints
        ctx.log(f"crawl found {len(surface.forms)} form(s), "
                f"{len(surface.js_files)} script(s), "
                f"{len(surface.endpoints)} endpoint(s)")

        if not urls:
            ctx.log("no URLs from archives or the crawl — falling back to the "
                    "link-following crawler", "warn")
            urls |= await self._builtin_crawl(ctx, targets)

        # Hand the surface to the parameter stage rather than making it
        # re-derive everything from a flat URL list, which is what lost the
        # form and JavaScript parameters last time.
        ctx.write_list("forms.jsonl",
                       [json.dumps(f.as_dict()) for f in surface.forms])
        ctx.write_list("js_files.txt", sorted(surface.js_files))
        ctx.write_list("endpoints.txt", sorted(surface.endpoints))
        ctx.write_list("surface_params.jsonl", [
            json.dumps({"name": v["name"], "sources": sorted(v["sources"]),
                        "count": v["count"], "example": v["example"]})
            for v in surface.parameters.values()])

        in_scope = [u for u in sorted(urls) if ctx.scope.classify(u).allowed]

        # Collapse to endpoint shapes. This is what makes the result reviewable.
        shapes = {}
        for url in in_scope:
            shapes.setdefault(query_signature(url), []).append(url)

        ctx.store.upsert_assets(ctx.program_id, ctx.run_id, "url", [
            {"key": shape, "decision": "allow", "source": "crawl",
             "data": {"instances": len(members), "example": members[0]}}
            for shape, members in shapes.items()])

        ctx.write_list("urls.txt", in_scope)
        ctx.write_list("url_shapes.txt", sorted(shapes))
        ctx.counter("urls", len(in_scope))
        ctx.counter("endpoint_shapes", len(shapes))
        ctx.log(f"{len(in_scope)} in-scope URL(s) collapse to {len(shapes)} distinct "
                f"endpoint shape(s) — that is the list worth reading")
        return {"produced": len(shapes), "urls": len(in_scope),
                "command": "; ".join(commands)}


class ParamStage(Stage):
    key, name = "params", "Parameter discovery"
    description = "Parameters worth testing, and which bug class each suggests."

    #: Parameter names that map to a specific bug class. This is the same idea
    #: as the gf pattern set, kept inline so it works with nothing installed.
    INTERESTING = {
        "redirect": ("open redirect", ("redirect", "redirect_uri", "redirect_url",
                                       "url", "next", "returnurl", "return_url",
                                       "return", "dest", "destination", "continue",
                                       "go", "target", "rurl", "callback",
                                       "forward", "back", "checkout_url")),
        "ssrf": ("server-side request forgery", ("url", "uri", "path", "src",
                                                 "dest", "domain", "feed",
                                                 "host", "site", "page", "open",
                                                 "port", "to", "out", "view",
                                                 "webhook", "proxy", "fetch")),
        "lfi": ("file inclusion", ("file", "document", "folder", "root", "path",
                                   "pg", "style", "template", "php_path", "doc",
                                   "include", "page", "name", "download")),
        "sqli": ("SQL injection", ("id", "select", "report", "search", "category",
                                   "sort", "order", "filter", "where", "query",
                                   "user", "username", "number", "row", "results")),
        "xss": ("cross-site scripting", ("q", "s", "search", "query", "keyword",
                                         "lang", "id", "name", "message", "term",
                                         "text", "content", "title", "comment")),
        "idor": ("broken object level authorisation",
                 ("id", "user_id", "userid", "account", "account_id", "uid",
                  "order_id", "invoice", "doc_id", "file_id", "profile", "key")),
    }

    async def run(self, ctx):
        from . import discovery

        urls_file = ctx.workdir / "urls.txt"
        if not urls_file.exists():
            return {"produced": 0, "skipped": "no URLs discovered"}
        urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]

        params = {}

        def record(name, source, example=""):
            if not name or len(name) > 60:
                return
            entry = params.setdefault(name.lower(), {
                "name": name, "count": 0, "example": example or "",
                "classes": set(), "sources": set()})
            entry["count"] += 1
            entry["sources"].add(source)
            if example and not entry["example"]:
                entry["example"] = example

        # 1. Query strings, from the crawl and from the archives.
        for url in urls:
            try:
                parts = urlsplit(url)
            except Exception:
                continue
            for name, value in parse_qsl(parts.query, keep_blank_values=True):
                record(name, "query", url)

        # 2. Everything the crawl learned that a query-string parser cannot
        #    see: form fields, named inputs, parameters read in JavaScript and
        #    parameters declared in an OpenAPI document. This is where most of
        #    a modern application's input surface actually lives, and omitting
        #    it is what produced a four-parameter report from 1,500 hosts.
        surface_file = ctx.workdir / "surface_params.jsonl"
        if surface_file.exists():
            for line in surface_file.read_text().splitlines():
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                for source in row.get("sources") or ["crawl"]:
                    record(row["name"], source, row.get("example", ""))

        # 3. Forms become testable URLs in their own right. A GET form is a
        #    URL; a POST form is recorded so the operator can see it even
        #    though the automated checks here only drive GET.
        form_urls, post_forms = [], []
        forms_file = ctx.workdir / "forms.jsonl"
        if forms_file.exists():
            for line in forms_file.read_text().splitlines():
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                form = discovery.Form(
                    action=row.get("action", ""),
                    method=row.get("method", "GET"),
                    params={n: "" for n in row.get("params") or []})
                as_url = form.as_url()
                if as_url and ctx.scope.classify(as_url).allowed:
                    form_urls.append(as_url)
                elif form.method.upper() != "GET":
                    post_forms.append(row)
        if form_urls:
            urls = sorted(set(urls) | set(form_urls))
            ctx.log(f"{len(form_urls)} GET form(s) expressed as testable URLs")
        if post_forms:
            ctx.write_list("forms_post.jsonl",
                           [json.dumps(f) for f in post_forms])
            ctx.log(f"{len(post_forms)} POST form(s) recorded — drive these by "
                    f"hand or through the proxy; the built-in checks send GET")

        # 4. Brute force, last and only where it is worth it: endpoints that
        #    answered and that carry no parameters we already know about.
        if ctx.config.get("brute_parameters", True):
            fetcher = discovery.Fetcher(
                concurrency=int(ctx.config.get("http_concurrency", 20)),
                timeout=int(ctx.config.get("http_timeout", 12)),
                proxy=ctx.proxy.url if ctx.proxy else None,
                headers=dict(ctx.config.get("headers") or {}),
                user_agent=ctx.config.get("user_agent") or discovery.DEFAULT_UA)
            bare = [u for u in urls if "?" not in u]
            # One endpoint per shape: brute forcing /item/1 and /item/2 asks
            # the same question twice.
            by_shape = {}
            for url in bare:
                by_shape.setdefault(query_signature(url), url)
            candidates = list(by_shape.values())[
                :int(ctx.config.get("brute_endpoint_cap", 60))]
            if candidates:
                ctx.log(f"brute-forcing hidden parameters on "
                        f"{len(candidates)} distinct endpoint(s)")
                results = await asyncio.gather(*[
                    discovery.brute_parameters(
                        fetcher, url, log=lambda t: ctx.log(t))
                    for url in candidates], return_exceptions=True)
                hidden = 0
                for url, result in zip(candidates, results):
                    if isinstance(result, Exception) or not result:
                        continue
                    for row in result:
                        record(row["name"], "brute-force", row["url"])
                        urls.append(row["url"])
                        hidden += 1
                if hidden:
                    ctx.log(f"{hidden} hidden parameter(s) found by brute force")
        urls = sorted(set(urls))
        ctx.write_list("urls.txt", urls)

        for name, entry in params.items():
            for bug_class, (label, needles) in self.INTERESTING.items():
                if name in needles:
                    entry["classes"].add(bug_class)

        rows = []
        for name, entry in sorted(params.items(), key=lambda kv: -kv[1]["count"]):
            rows.append({
                "key": name, "decision": "allow",
                "source": ",".join(sorted(entry.get("sources") or {"urls"})),
                "data": {"occurrences": entry["count"],
                         "example": (entry["example"] or "")[:300],
                         "sources": sorted(entry.get("sources") or []),
                         "classes": sorted(entry["classes"])},
            })
        ctx.store.upsert_assets(ctx.program_id, ctx.run_id, "parameter", rows)

        # URLs carrying an interesting parameter are what the active stages
        # would be pointed at, so they are written out whether or not those
        # stages are enabled.
        candidates = {}
        for url in urls:
            try:
                names = {k.lower() for k, _ in parse_qsl(urlsplit(url).query,
                                                         keep_blank_values=True)}
            except Exception:
                continue
            for bug_class, (label, needles) in self.INTERESTING.items():
                if names & set(needles):
                    candidates.setdefault(bug_class, set()).add(url)

        for bug_class, found in candidates.items():
            ctx.write_list(f"candidates_{bug_class}.txt", sorted(found))

        # Every URL that takes input, not only the ones whose parameter name
        # happens to be on a list. The name-matching above is a good way to
        # *prioritise* — it says which bug class to look for first — and a
        # terrible way to decide what gets tested at all: a reflected XSS in
        # a parameter called "bannerId" is still a reflected XSS, and under
        # the old rule it was never sent to a single check.
        parameterised = sorted({
            u for u in urls
            if urlsplit(u).query and ctx.scope.classify(u).allowed})
        # Shape-collapsed, so a thousand instances of /news?id=N are tested
        # once rather than a thousand times.
        by_shape = {}
        for url in parameterised:
            by_shape.setdefault(query_signature(url), url)
        # One URL per shape on both halves. Without this a search page reached
        # as ?q=x&category=y and as ?category=y&q=x is tested twice for the
        # same bug, and on a real estate that doubling runs through the whole
        # list.
        prioritised = {}
        for url in parameterised:
            if any(url in found for found in candidates.values()):
                prioritised.setdefault(query_signature(url), url)
        testable = list(dict.fromkeys(
            list(prioritised.values()) + list(by_shape.values())))
        ctx.write_list("parameterised.txt", testable)
        ctx.write_list("parameterised_all.txt", parameterised)
        ctx.counter("parameterised_urls", len(testable))
        ctx.log(f"{len(parameterised)} parameterised URL(s) collapse to "
                f"{len(testable)} worth testing")

        ctx.counter("parameters", len(rows))
        ctx.log(f"{len(rows)} distinct parameter name(s) across {len(urls)} URL(s)")
        for bug_class, found in sorted(candidates.items(), key=lambda kv: -len(kv[1])):
            label = self.INTERESTING[bug_class][0]
            ctx.log(f"  {len(found)} URL(s) carry a parameter associated with {label}")
        return {"produced": len(rows), "candidates":
                {k: len(v) for k, v in candidates.items()}}


class JsStage(Stage):
    key, name = "js", "JavaScript analysis"
    description = ("Read the application's own JavaScript for endpoints, "
                   "secrets and exposed source maps.")

    async def run(self, ctx):
        live_targets = ctx.live_urls()
        if not live_targets:
            return {"produced": 0, "skipped": 'no live hosts to work from. Run Step 3 (See what is alive) first — on its own is fine, it starts from the previous run.'}

        urls_file = ctx.workdir / "urls.txt"
        js_urls = set()
        if urls_file.exists():
            for line in urls_file.read_text().splitlines():
                line = line.strip()
                if line.endswith(".js") or ".js?" in line:
                    js_urls.add(line)

        if ctx.registry.have("subjs"):
            targets = live_targets
            argv = [ctx.registry.path("subjs")]
            result = await ctx.runner(ctx.workdir / "logs" / "subjs.log", "subjs").run(
                argv, timeout=600, idle_timeout=180,
                stdin_data="\n".join(targets) + "\n")
            for line in result.stdout_lines:
                line = line.strip()
                if line.startswith("http"):
                    js_urls.add(line)

        js_urls = {u for u in js_urls if ctx.scope.classify(u).allowed}
        if not js_urls:
            return {"produced": 0, "skipped": "no JavaScript files found"}

        ctx.write_list("js_urls.txt", sorted(js_urls))
        ctx.store.upsert_assets(ctx.program_id, ctx.run_id, "javascript", [
            {"key": u, "decision": "allow", "source": "discovery"} for u in js_urls])
        ctx.log(f"{len(js_urls)} JavaScript file(s) identified")

        findings = 0
        if ctx.registry.have("jsluice"):
            jsdir = ctx.workdir / "js"
            jsdir.mkdir(exist_ok=True)
            ctx.log("downloading JavaScript through the proxy for analysis")
            downloaded = await self._download(ctx, sorted(js_urls)[:200], jsdir)
            if downloaded:
                for mode in ("secrets", "urls"):
                    argv = [ctx.registry.path("jsluice"), mode] + \
                           [str(p) for p in downloaded[:200]]
                    result = await ctx.runner(
                        ctx.workdir / "logs" / f"jsluice-{mode}.log", "jsluice").run(
                        argv, timeout=900, idle_timeout=180)
                    for obj in _jsonl(result.stdout_lines):
                        if mode == "secrets":
                            findings += 1
                            ctx.findings.append({
                                "severity": obj.get("severity", "medium"),
                                "title": f"Secret in JavaScript: {obj.get('kind', 'unknown')}",
                                "category": "Secret disclosure",
                                "tool": "jsluice",
                                "target": obj.get("filename", ""),
                                "detail": json.dumps(obj.get("data", {}))[:400],
                                "evidence": (obj.get("context") or "")[:400],
                                "repro": ("Fetch the file and search for the value. "
                                          "Then establish what it authenticates "
                                          "before reporting — a key that is meant "
                                          "to be public is not a finding."),
                            })
        else:
            ctx.log("jsluice is not installed — install it for JavaScript secret "
                    "and endpoint extraction", "warn")

        ctx.counter("js_files", len(js_urls))
        return {"produced": len(js_urls), "findings": findings}

    @staticmethod
    async def _download(ctx, urls, jsdir):
        """Fetch JavaScript through the proxy so scope and rate limits apply."""
        paths = []
        semaphore = asyncio.Semaphore(8)

        async def one(url):
            async with semaphore:
                ok, reason = (ctx.proxy.check(urlsplit(url).hostname or "", 443)
                              if ctx.proxy else (True, ""))
                if not ok:
                    return
                def _get():
                    handler = urllib.request.ProxyHandler(
                        {"http": ctx.proxy.url, "https": ctx.proxy.url}
                        if ctx.proxy else {})
                    opener = urllib.request.build_opener(handler)
                    headers = dict(ctx.config.get("headers") or {})
                    if ctx.config.get("user_agent"):
                        headers["User-Agent"] = ctx.config["user_agent"]
                    req = urllib.request.Request(url, headers=headers)
                    with opener.open(req, timeout=20) as resp:
                        return resp.read(3_000_000)
                try:
                    body = await asyncio.get_running_loop().run_in_executor(None, _get)
                except Exception:
                    return
                name = hashlib.sha256(url.encode()).hexdigest()[:16] + ".js"
                path = jsdir / name
                path.write_bytes(body)
                paths.append(path)

        await asyncio.gather(*[one(u) for u in urls], return_exceptions=True)
        return paths


class TakeoverStage(Stage):
    key, name = "takeover", "Subdomain takeover triage"
    description = "Find dangling CNAMEs pointing at services that can be claimed."

    #: Fingerprints kept inline so the check works with nothing installed.
    SIGNATURES = [
        ("GitHub Pages", ("github.io",), "There isn't a GitHub Pages site here"),
        ("Amazon S3", ("s3.amazonaws.com", "s3-website"), "NoSuchBucket"),
        ("Heroku", ("herokuapp.com", "herokudns.com"), "No such app"),
        ("Azure", ("azurewebsites.net", "cloudapp.azure.com", "trafficmanager.net"),
         "404 Web Site not found"),
        ("Shopify", ("myshopify.com",), "Sorry, this shop is currently unavailable"),
        ("Zendesk", ("zendesk.com",), "Help Center Closed"),
        ("Fastly", ("fastly.net",), "Fastly error: unknown domain"),
        ("Netlify", ("netlify.app", "netlify.com"), "Not Found"),
        ("Vercel", ("vercel.app", "vercel-dns.com"), "DEPLOYMENT_NOT_FOUND"),
        ("Surge", ("surge.sh",), "project not found"),
        ("Statuspage", ("statuspage.io",), "You are being redirected"),
        ("Readthedocs", ("readthedocs.io",), "unknown to Read the Docs"),
        ("Webflow", ("proxy-ssl.webflow.com",), "The page you are looking for"),
        ("Pantheon", ("pantheonsite.io",), "The gods are wise"),
        ("Bitbucket", ("bitbucket.io",), "Repository not found"),
    ]

    async def run(self, ctx):
        hosts = ctx.store.assets(ctx.program_id, "subdomain", limit=100000)
        candidates = []
        for host in hosts:
            cname = (host.get("data") or {}).get("cname") or ""
            if not cname:
                continue
            for provider, needles, evidence in self.SIGNATURES:
                if any(n in cname.lower() for n in needles):
                    candidates.append((host["key"], cname, provider, evidence))
                    break

        if not candidates:
            ctx.log("no CNAMEs pointing at a takeover-prone provider")
            return {"produced": 0}

        ctx.log(f"{len(candidates)} CNAME(s) point at a provider where dangling "
                f"records can be claimed — checking whether they resolve")

        confirmed = 0
        for host, cname, provider, evidence in candidates:
            addresses = await _resolve_one(host)
            dangling = not addresses
            severity = "high" if dangling else "info"
            title = (f"Possible subdomain takeover: {host} → {provider}"
                     if dangling else
                     f"{host} is hosted on {provider} (CNAME present and resolving)")
            ctx.findings.append({
                "severity": severity,
                "title": title,
                "category": "Subdomain takeover",
                "tool": "bbhunter",
                "target": host,
                "confidence": "tentative",
                "detail": (f"CNAME → {cname}. "
                           + ("The name does not resolve, which is the classic "
                              "dangling-record shape."
                              if dangling else
                              "It still resolves, so this is almost certainly "
                              "just a live site on that provider.")),
                "evidence": f"Provider error page to look for: {evidence!r}",
                "repro": ("Fetch the host over HTTP and compare the body against "
                          "the provider's unclaimed-resource page. Then confirm "
                          "the name is actually registerable on that provider "
                          "before reporting — a provider returning a generic 404 "
                          "for a claimed resource looks identical, and this is "
                          "the single most common false positive in bug bounty."),
            })
            if dangling:
                confirmed += 1

        ctx.counter("takeover_candidates", confirmed)
        return {"produced": len(candidates), "dangling": confirmed}


class _BuiltinChecksBase(Stage):
    """Shared plumbing for the two built-in check stages.

    They are two stages rather than one because the safety model here is
    worth keeping honest. Asking for /.git/config and reading the response
    headers is an ordinary GET of a path the server either serves or does
    not; sending a quote into a parameter to see whether the database
    complains is not. The first belongs in the default run, the second
    belongs behind the active acknowledgement, and merging them would mean
    either sending payloads by default or finding nothing by default. Both
    have been tried; neither is acceptable.
    """

    check_names = ()

    def _fetcher(self, ctx):
        from . import discovery
        return discovery.Fetcher(
            concurrency=int(ctx.config.get("http_concurrency", 20)),
            timeout=int(ctx.config.get("http_timeout", 12)),
            proxy=ctx.proxy.url if ctx.proxy else None,
            headers=dict(ctx.config.get("headers") or {}),
            user_agent=ctx.config.get("user_agent") or discovery.DEFAULT_UA)

    def _parameterised(self, ctx):
        source = ctx.workdir / "parameterised.txt"
        if not source.exists():
            return []
        return ctx.scope.filter_allowed(
            [l.strip() for l in source.read_text().splitlines() if l.strip()])

    async def _run_set(self, ctx, hosts, urls, host_cap, url_cap):
        from . import checks as builtin
        wanted = set(self.check_names)
        configured = ctx.config.get("builtin_checks")
        if configured:
            wanted &= set(configured)
        if not wanted:
            return {"produced": 0, "skipped": "every check in this stage is "
                                              "disabled in settings"}
        found = await builtin.run_checks(
            self._fetcher(ctx), hosts, urls,
            scope_ok=lambda u: ctx.scope.classify(u).allowed,
            log=lambda t, level="info": ctx.log(t, level),
            enabled=sorted(wanted), host_cap=host_cap, url_cap=url_cap)
        for row in found:
            ctx.findings.append(row)
        by_severity = {}
        for row in found:
            by_severity[row["severity"]] = by_severity.get(row["severity"], 0) + 1
        if found:
            ctx.log(f"{self.name}: " + ", ".join(
                f"{count} {sev}" for sev, count in sorted(by_severity.items())))
        else:
            ctx.log(f"{self.name}: nothing. That is a result — the surface "
                    f"above was tested and did not respond to any of these "
                    f"checks.")
        return {"produced": len(found), "by_severity": by_severity}


class SafeChecksStage(_BuiltinChecksBase):
    key, name = "checks", "Built-in checks (safe)"
    description = ("Exposed files, security headers and CORS, with nothing "
                   "installed. Ordinary GET requests; no payloads.")
    check_names = ("exposed", "headers", "cors")

    async def run(self, ctx):
        hosts = ctx.scope.filter_allowed(ctx.live_urls())
        if not hosts:
            return {"produced": 0,
                    "skipped": 'no live hosts to work from. Run Step 3 '
                               '(See what is alive) first.'}
        cap = int(ctx.config.get("checks_host_cap", 300))
        ctx.log(f"checking {min(len(hosts), cap)} host(s) for exposed files, "
                f"header policy and CORS")
        result = await self._run_set(ctx, hosts, [], cap, 0)
        ctx.counter("builtin_findings", result.get("produced", 0))
        return result


class InjectionChecksStage(_BuiltinChecksBase):
    key, name = "inject", "Built-in injection checks"
    description = ("Reflection, open redirect, SQL errors and traversal "
                   "against discovered parameters. Active: this sends "
                   "payloads.")
    check_names = ("reflection", "redirect", "sqli", "traversal")

    async def run(self, ctx):
        urls = self._parameterised(ctx)
        if not urls:
            return {"produced": 0,
                    "skipped": "no parameterised URLs. Run Step 4 (Explore "
                               "the surface) first — if it found none, the "
                               "run log for URL discovery says why."}
        cap = int(ctx.config.get("checks_url_cap", 800))
        ctx.log(f"testing {min(len(urls), cap)} parameterised URL(s) for "
                f"reflection, open redirect, SQL errors and traversal")
        result = await self._run_set(ctx, [], urls, 0, cap)
        ctx.counter("injection_findings", result.get("produced", 0))
        return result


class NucleiStage(Stage):
    key, name, tool_key = "nuclei", "Template scanning", "nuclei"
    description = "Run nuclei's template set against the distinct applications."

    async def run(self, ctx):
        if not ctx.registry.have("nuclei"):
            return {"produced": 0, "skipped": "nuclei is not installed"}
        live_targets = ctx.live_urls()
        if not live_targets:
            return {"produced": 0, "skipped": 'no live hosts to work from. Run Step 3 (See what is alive) first — on its own is fine, it starts from the previous run.'}

        targets = ctx.scope.filter_allowed(live_targets)
        if not targets:
            return {"produced": 0, "skipped": "nothing in scope"}
        target_file = ctx.write_list("nuclei_targets.txt", targets)

        severities = ctx.config.get("nuclei_severity", "critical,high,medium,low")
        argv = [ctx.registry.path("nuclei"), "-l", str(target_file),
                "-jsonl", "-silent", "-duc",
                "-severity", severities,
                "-bs", "25", "-c", "25", "-mhe", "5",
                "-timeout", "10", "-retries", "1"]
        argv += ctx.rate_args("nuclei")
        argv += ctx.identification("nuclei")
        if ctx.proxy:
            argv += ["-proxy", ctx.proxy.url]
        if ctx.config.get("exclude_intrusive", True):
            # dos and intrusive templates have no place in an automated pass.
            argv += ["-etags", "dos,intrusive,fuzz"]

        result = await ctx.runner(ctx.workdir / "logs" / "nuclei.log", "nuclei").run(
            argv, timeout=ctx.config.get("stage_timeout", 3600), idle_timeout=600)

        count = 0
        for obj in _jsonl(result.stdout_lines):
            info = obj.get("info") or {}
            target = obj.get("matched-at") or obj.get("host") or ""
            if target and not ctx.scope.classify(target).allowed:
                continue
            ctx.findings.append({
                "severity": (info.get("severity") or "info").lower(),
                "title": info.get("name") or obj.get("template-id") or "nuclei match",
                "category": "Template match",
                "tool": "nuclei",
                "target": target,
                "matcher": obj.get("matcher-name") or obj.get("template-id") or "",
                "detail": (info.get("description") or "")[:600],
                "evidence": (obj.get("extracted-results") and
                             json.dumps(obj["extracted-results"])[:400]) or
                            (obj.get("matched-line") or "")[:400],
                "repro": obj.get("curl-command") or "",
                "data": {"template": obj.get("template-id"),
                         "tags": info.get("tags") or []},
            })
            count += 1

        ctx.counter("nuclei_findings", count)
        ctx.log(f"nuclei produced {count} result(s) at {severities}")
        return {"produced": count, "command": result.command}


class DastStage(Stage):
    key, name, tool_key = "dast", "Fuzzing templates", "nuclei"
    description = ("Injection testing against discovered parameters. Active: "
                   "this sends payloads.")

    async def run(self, ctx):
        if not ctx.registry.have("nuclei"):
            return {"produced": 0, "skipped": "nuclei is not installed"}
        source = ctx.workdir / "parameterised.txt"
        if not source.exists():
            return {"produced": 0, "skipped": "no parameterised URLs found"}
        targets = ctx.scope.filter_allowed(
            [l.strip() for l in source.read_text().splitlines() if l.strip()])
        if not targets:
            return {"produced": 0, "skipped": "no in-scope parameterised URLs"}

        cap = int(ctx.config.get("dast_url_cap", 2000))
        if len(targets) > cap:
            ctx.log(f"limiting fuzzing to {cap} of {len(targets)} URLs — raise "
                    f"dast_url_cap if you want the rest", "warn")
            targets = targets[:cap]
        target_file = ctx.write_list("dast_targets.txt", targets)

        argv = [ctx.registry.path("nuclei"), "-l", str(target_file),
                "-dast", "-jsonl", "-silent", "-duc",
                "-c", "10", "-mhe", "5", "-timeout", "10"]
        argv += ctx.rate_args("nuclei")
        argv += ctx.identification("nuclei")
        if ctx.proxy:
            argv += ["-proxy", ctx.proxy.url]

        result = await ctx.runner(ctx.workdir / "logs" / "nuclei-dast.log", "nuclei").run(
            argv, timeout=ctx.config.get("stage_timeout", 3600), idle_timeout=600)

        count = 0
        for obj in _jsonl(result.stdout_lines):
            info = obj.get("info") or {}
            target = obj.get("matched-at") or ""
            if target and not ctx.scope.classify(target).allowed:
                continue
            ctx.findings.append({
                "severity": (info.get("severity") or "medium").lower(),
                "title": f"{info.get('name') or 'Injection'} (fuzzing)",
                "category": "Injection",
                "tool": "nuclei -dast",
                "target": target,
                "matcher": obj.get("template-id", ""),
                "detail": (info.get("description") or "")[:600],
                "evidence": (obj.get("matched-line") or "")[:400],
                "repro": obj.get("curl-command") or "",
                "confidence": "tentative",
            })
            count += 1
        ctx.counter("dast_findings", count)
        ctx.log(f"fuzzing produced {count} candidate(s) — every one needs manual "
                f"confirmation before it goes in a report")
        return {"produced": count, "command": result.command}


class XssStage(Stage):
    key, name, tool_key = "xss", "XSS testing", "dalfox"
    description = "Reflection analysis and payload testing. Active."

    async def run(self, ctx):
        if not ctx.registry.have("dalfox"):
            return {"produced": 0, "skipped": "dalfox is not installed"}
        source = ctx.workdir / "candidates_xss.txt"
        if not source.exists():
            source = ctx.workdir / "parameterised.txt"
        if not source.exists():
            return {"produced": 0, "skipped": "no candidate URLs"}
        targets = ctx.scope.filter_allowed(
            [l.strip() for l in source.read_text().splitlines() if l.strip()])
        if not targets:
            return {"produced": 0, "skipped": "no in-scope candidates"}
        targets = targets[:int(ctx.config.get("xss_url_cap", 500))]
        target_file = ctx.write_list("xss_targets.txt", targets)

        version = (ctx.registry.state.get("dalfox") or {}).get("version", "")
        subcommand = "scan" if version.startswith(("3", "v3")) else "file"
        argv = [ctx.registry.path("dalfox"), subcommand, str(target_file),
                "--format", "json", "--silence", "--no-spinner"]
        argv += ctx.identification("dalfox")
        if ctx.proxy:
            argv += ["--proxy", ctx.proxy.url]

        result = await ctx.runner(ctx.workdir / "logs" / "dalfox.log", "dalfox").run(
            argv, timeout=ctx.config.get("stage_timeout", 2400), idle_timeout=420)

        count = 0
        for obj in _jsonl(result.stdout_lines):
            target = obj.get("data") or obj.get("url") or ""
            if target and not ctx.scope.classify(target).allowed:
                continue
            ctx.findings.append({
                "severity": "high" if obj.get("type") == "V" else "medium",
                "title": f"XSS candidate: {obj.get('param', 'parameter')}",
                "category": "Cross-site scripting",
                "tool": "dalfox",
                "target": target,
                "matcher": obj.get("param", ""),
                "detail": f"{obj.get('message_str', '')} ({obj.get('method', 'GET')})"[:400],
                "evidence": (obj.get("payload") or "")[:300],
                "confidence": "tentative",
                "repro": ("Open the URL with the payload and confirm "
                          "alert(document.domain) fires in the browser. A "
                          "reflection is not an XSS until it executes."),
            })
            count += 1
        ctx.counter("xss_findings", count)
        ctx.log(f"dalfox reported {count} candidate(s)")
        return {"produced": count, "command": result.command}


class ScreenshotStage(Stage):
    key, name, tool_key = "screenshots", "Screenshots", "httpx"
    description = ("Capture what each distinct application actually looks like, "
                   "so you can pick the interesting ones by eye.")

    #: Three ways to get a picture, in order of preference. httpx is already
    #: in the pipeline; gowitness is what most people have; headless Chrome is
    #: the fallback that works on a bare Kali box with nothing else installed.
    CHROME_BINARIES = ("chromium", "chromium-browser", "google-chrome",
                       "google-chrome-stable", "chrome")

    NO_BROWSER = (
        "no browser is installed, so nothing can be photographed. Every "
        "backend drives a real one: httpx and gowitness both embed go-rod, "
        "which tries to download Chromium on first use and fails on a box "
        "that cannot reach Google's storage bucket.\n\n"
        "    sudo apt install -y chromium\n\n"
        "Then run this step again. If you already have a browser somewhere "
        "unusual — a snap, a flatpak, an unpacked tarball — set chrome_binary "
        "in Settings to its full path instead.")

    async def run(self, ctx):
        live_targets = ctx.live_urls()
        if not live_targets:
            return {"produced": 0, "skipped": 'no live hosts to work from. Run Step 3 (See what is alive) first — on its own is fine, it starts from the previous run.'}

        targets = ctx.scope.filter_allowed(live_targets)
        if not targets:
            return {"produced": 0, "skipped": "nothing in scope to capture"}

        cap = int(ctx.config.get("screenshot_cap", 300))
        if len(targets) > cap:
            ctx.log(f"capturing the first {cap} of {len(targets)} distinct "
                    f"applications — raise screenshot_cap for more", "warn")
            targets = targets[:cap]

        shots = ctx.workdir / "screenshots"
        shots.mkdir(exist_ok=True)

        # Every backend drives a real browser. httpx and gowitness both embed
        # go-rod, which downloads Chromium on first use — and that download is
        # the first thing to fail on a box with no egress to Google's storage
        # bucket, which is most bug bounty boxes. So find the browser first and
        # say plainly if there isn't one, rather than running a backend that
        # cannot possibly produce a file and then reporting "0 screenshots".
        chrome = self._find_chrome(ctx.config.get("chrome_binary", ""))
        if not chrome:
            return {"produced": 0, "skipped": self.NO_BROWSER}

        attempted, commands = [], []
        captured = []
        for label, backend in self._backends(ctx):
            attempted.append(label)
            commands.append(await backend(ctx, targets, shots, chrome))
            captured = self._index(ctx, targets, shots)
            if captured:
                break
            ctx.log(f"{label} produced no images — trying the next backend",
                    "warn")

        ctx.counter("screenshots", len(captured))
        if not captured:
            ctx.log(f"no screenshots: {', '.join(attempted)} all produced "
                    f"nothing. The browser found was {chrome}.", "error")
            return {"produced": 0,
                    "skipped": (f"tried {', '.join(attempted)}; none produced "
                                f"an image. See logs/screenshots.log."),
                    "command": "; ".join(c for c in commands if c)}

        ctx.log(f"{len(captured)} screenshot(s) captured with "
                f"{attempted[-1]}. Only the distinct applications were shot — "
                f"screenshotting every duplicate of a 404 page is the usual "
                f"way a run stops finishing.")
        return {"produced": len(captured),
                "command": "; ".join(c for c in commands if c)}

    def _backends(self, ctx):
        """The ways to get a picture, best first, as (label, coroutine).

        Ordered by speed, not by preference of author: httpx is already in the
        pipeline and shoots concurrently, gowitness is what most people have,
        and driving the browser directly is the one that cannot fail for want
        of a download."""
        order = []
        if ctx.registry.have("httpx"):
            order.append(("httpx", self._httpx))
        if ctx.registry.have("gowitness"):
            order.append(("gowitness", self._gowitness))
        order.append(("the browser directly", self._chrome))
        return order

    # ── backends ──────────────────────────────────────────────────────────

    @classmethod
    def _find_chrome(cls, configured=""):
        """Locate a browser. A configured path wins.

        Worth being explicit about: Kali usually has ``chromium``, but people
        run Chrome from a snap, a flatpak or an unpacked tarball, and hunting
        for it is not the operator's job when they can just say where it is.
        """
        import shutil as _shutil
        if configured:
            candidate = Path(configured).expanduser()
            if candidate.is_file():
                return str(candidate)
        for name in cls.CHROME_BINARIES:
            path = _shutil.which(name)
            if path:
                return path
        return ""

    async def _httpx(self, ctx, targets, shots, chrome):
        target_file = ctx.write_list("screenshot_targets.txt", targets)
        # -system-chrome stops go-rod trying to download its own Chromium,
        # which is the failure this whole stage used to die on.
        argv = [ctx.registry.path("httpx"), "-l", str(target_file),
                "-ss", "-system-chrome", "-esb", "-ehb", "-silent", "-json",
                "-srd", str(shots), "-t", "8", "-timeout", "20",
                "-screenshot-timeout", "25"]
        for flag in self.QUIET_CHROME:
            argv += ["-ho", flag]
        argv += ctx.identification("httpx")
        result = await ctx.runner(ctx.workdir / "logs" / "screenshots.log",
                                  "httpx").run(
            argv, timeout=ctx.config.get("stage_timeout", 2400), idle_timeout=420)
        return result.command

    async def _gowitness(self, ctx, targets, shots, chrome):
        target_file = ctx.write_list("screenshot_targets.txt", targets)
        # v3 restructured the CLI; the old `gowitness file -f` form is gone.
        # --chrome-path is the same defence as httpx's -system-chrome.
        argv = [ctx.registry.path("gowitness"), "scan", "file",
                "-f", str(target_file), "--screenshot-path", str(shots),
                "--chrome-path", chrome,
                "--write-jsonl", "--disable-db", "-t", "8"]
        result = await ctx.runner(ctx.workdir / "logs" / "screenshots.log",
                                  "gowitness").run(
            argv, timeout=ctx.config.get("stage_timeout", 2400), idle_timeout=420)
        return result.command

    #: Chrome talks to Google before it talks to the target: component and
    #: variations updates, Safe Browsing lists, the optimisation-hints service,
    #: a network-connectivity probe. Every one of those hits the scope gate and
    #: is correctly refused, which buries the run's real output under hundreds
    #: of identical refusals for www.google.com. None of it is needed to take a
    #: screenshot, so it is turned off at the browser rather than filtered from
    #: the log.
    QUIET_CHROME = (
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-client-side-phishing-detection",
        "--disable-sync",
        "--disable-domain-reliability",
        "--safebrowsing-disable-auto-update",
        "--disable-breakpad",
        "--metrics-recording-only",
        "--no-first-run",
        "--no-default-browser-check",
        "--no-pings",
        "--disable-default-apps",
        "--password-store=basic",
        "--use-mock-keychain",
        "--disable-features=Translate,OptimizationHints,MediaRouter,"
        "InterestFeedContentSuggestions,CalculateNativeWinOcclusion",
    )

    async def _chrome(self, ctx, targets, shots, chrome):
        """Headless Chrome, one page at a time, through the scope proxy.

        Slow, but it means a fresh clone with nothing installed still produces
        a gallery, and Chrome honours --proxy-server so the scope gate still
        applies to everything the page loads.
        """
        semaphore = asyncio.Semaphore(int(ctx.config.get("screenshot_workers", 4)))
        command = ""

        async def one(url):
            nonlocal command
            async with semaphore:
                out = shots / (hashlib.sha256(url.encode()).hexdigest()[:16] + ".png")
                argv = [chrome, "--headless=new", "--disable-gpu", "--no-sandbox",
                        "--hide-scrollbars", "--disable-dev-shm-usage",
                        "--virtual-time-budget=6000",
                        "--window-size=1280,800",
                        *self.QUIET_CHROME,
                        f"--screenshot={out}"]
                if ctx.proxy:
                    # Chrome has no per-request header flag, so identification
                    # headers reach the target from the gate on plain HTTP and
                    # not at all inside an HTTPS tunnel. Routing through the
                    # gate is what keeps the capture in scope either way.
                    argv.append(f"--proxy-server={ctx.proxy.url}")
                argv.append(url)
                result = await ctx.runner(None, "chromium").run(
                    argv, timeout=60, idle_timeout=45, capture_stdout=False)
                command = command or result.command

        await asyncio.gather(*[one(u) for u in targets], return_exceptions=True)
        return command

    # ── index ─────────────────────────────────────────────────────────────

    def _index(self, ctx, targets, shots):
        """Match each image to the URL it belongs to and record it.

        The backends name files differently — httpx uses a sanitised URL,
        gowitness uses its own scheme, the Chrome fallback uses a hash — so
        matching is done by trying each in turn rather than assuming one.
        """
        images = sorted(shots.rglob("*.png"))
        by_name = {p.stem: p for p in images}
        captured = []

        services = {a["key"]: a for a in
                    ctx.store.assets(ctx.program_id, "http_service", limit=100000)}

        for url in targets:
            path = by_name.get(hashlib.sha256(url.encode()).hexdigest()[:16])
            if path is None:
                stem = re.sub(r"[^A-Za-z0-9]+", "_", url).strip("_")
                path = by_name.get(stem)
            if path is None:
                # httpx sanitises differently across versions; fall back to a
                # containment match on the host.
                host = urlsplit(url).netloc.replace(":", "_")
                for name, candidate in by_name.items():
                    if host and host.replace(".", "_") in name:
                        path = candidate
                        break
            if path is None or not path.exists():
                continue

            data = (services.get(url, {}).get("data") or {})
            captured.append(url)
            ctx.store.upsert_assets(ctx.program_id, ctx.run_id, "screenshot", [{
                "key": url, "decision": "allow", "source": "screenshot",
                "data": {
                    "image": path.name,
                    "run_id": ctx.run_id,
                    "status": data.get("status"),
                    "title": data.get("title", ""),
                    "tech": data.get("tech", []),
                    "server": data.get("server", ""),
                    "bytes": path.stat().st_size,
                },
            }])
        return captured


STAGES = {s.key: s for s in [
    SeedStage(), SubdomainStage(), PermuteStage(), WildcardStage(), ResolveStage(),
    ProbeStage(), DedupeStage(), PortStage(), UrlStage(), ParamStage(), JsStage(),
    TakeoverStage(), SafeChecksStage(), InjectionChecksStage(),
    NucleiStage(), DastStage(), XssStage(), ScreenshotStage(),
]}


def resolve_stage_list(preset: str, active_stages=None):
    """The stage list for a run, with any opted-in active stages appended."""
    base = list(PRESETS.get(preset, PRESETS["standard"])["stages"])
    for key in (active_stages or []):
        if key in STAGES and key not in base:
            base.append(key)
    return base
