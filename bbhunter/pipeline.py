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
                   "dedupe", "urls", "params", "js", "takeover", "nuclei"],
        "active": False,
    },
    "deep": {
        "label": "Deep",
        "blurb": ("Everything in Standard, plus permutation brute-forcing, "
                  "port scanning, headless crawling and screenshots. Slower "
                  "and noisier; still sends no injection payloads."),
        "stages": ["seeds", "subdomains", "permute", "wildcard", "resolve",
                   "probe", "dedupe", "ports", "urls", "params", "js",
                   "takeover", "nuclei", "screenshots"],
        "active": False,
    },
    "monitor": {
        "label": "Monitor",
        "blurb": ("A fast pass designed to be run on a schedule: find what is "
                  "new since last time and check it. Skips the expensive "
                  "stages entirely."),
        "stages": ["seeds", "subdomains", "wildcard", "resolve", "probe",
                   "dedupe", "takeover", "nuclei"],
        "active": False,
    },
}

#: Active probe stages. Each one sends payloads, so each is opt-in on its own
#: and none of them is reachable without the run-level active acknowledgement.
ACTIVE_STAGES = {
    "dast": ("Fuzzing templates (XSS, SQLi, SSTI, LFI, open redirect)",
             "Sends injection payloads to every parameter found. This is the "
             "stage most likely to trip a WAF."),
    "xss": ("Dedicated XSS discovery with dalfox",
            "Reflection analysis and payload testing on parameterised URLs."),
    "takeover_active": ("Active takeover confirmation",
                        "Requests the dangling host to read the provider's "
                        "error page."),
}


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
        tool = TOOLS.get(tool_key)
        if not tool or not tool.rate_flag:
            return []
        rps = self.config.get("per_host_rps", 5)
        return [tool.rate_flag, str(max(1, int(rps)))]

    def write_list(self, name, items):
        path = self.workdir / name
        path.write_text("\n".join(items) + ("\n" if items else ""), encoding="utf-8")
        return path


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


async def _resolve_one(name, timeout=3.0):
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(name, None, proto=socket.IPPROTO_TCP), timeout=timeout)
        return sorted({info[4][0] for info in infos})
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
        for rule in ctx.scope.include:
            host = normalise_host(rule.value)
            if host and host not in seeds:
                seeds.append(host)

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
            answers = await asyncio.gather(*[_resolve_one(p) for p in probes])
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

            await asyncio.gather(*[one(n) for n in names])
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
            return {"produced": 0, "skipped": "nothing resolved to probe"}
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
            return {"produced": 0, "skipped": "nothing probed"}

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
            return {"produced": 0, "skipped": "nothing to scan"}

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
        distinct = ctx.workdir / "distinct.txt"
        live = ctx.workdir / "live.txt"
        source_file = distinct if distinct.exists() else live
        if not source_file.exists():
            return {"produced": 0, "skipped": "nothing live to crawl"}
        targets = [l.strip() for l in source_file.read_text().splitlines() if l.strip()]
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

        if not urls:
            ctx.log("neither katana nor gau is installed — crawling with the "
                    "built-in crawler, which follows links only", "warn")
            urls |= await self._builtin_crawl(ctx, targets)

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
        urls_file = ctx.workdir / "urls.txt"
        if not urls_file.exists():
            return {"produced": 0, "skipped": "no URLs discovered"}
        urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]

        params = {}
        for url in urls:
            try:
                parts = urlsplit(url)
            except Exception:
                continue
            for name, value in parse_qsl(parts.query, keep_blank_values=True):
                entry = params.setdefault(name.lower(), {
                    "name": name, "count": 0, "example": url, "classes": set()})
                entry["count"] += 1

        for name, entry in params.items():
            for bug_class, (label, needles) in self.INTERESTING.items():
                if name in needles:
                    entry["classes"].add(bug_class)

        rows = []
        for name, entry in sorted(params.items(), key=lambda kv: -kv[1]["count"]):
            rows.append({
                "key": name, "decision": "allow", "source": "urls",
                "data": {"occurrences": entry["count"],
                         "example": entry["example"][:300],
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
        parameterised = sorted({u for s in candidates.values() for u in s})
        ctx.write_list("parameterised.txt", parameterised)

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
        live_file = ctx.workdir / "distinct.txt"
        if not live_file.exists():
            live_file = ctx.workdir / "live.txt"
        if not live_file.exists():
            return {"produced": 0, "skipped": "nothing live"}

        urls_file = ctx.workdir / "urls.txt"
        js_urls = set()
        if urls_file.exists():
            for line in urls_file.read_text().splitlines():
                line = line.strip()
                if line.endswith(".js") or ".js?" in line:
                    js_urls.add(line)

        if ctx.registry.have("subjs"):
            targets = [l.strip() for l in live_file.read_text().splitlines() if l.strip()]
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


class NucleiStage(Stage):
    key, name, tool_key = "nuclei", "Template scanning", "nuclei"
    description = "Run nuclei's template set against the distinct applications."

    async def run(self, ctx):
        if not ctx.registry.have("nuclei"):
            return {"produced": 0, "skipped": "nuclei is not installed"}
        source_file = ctx.workdir / "distinct.txt"
        if not source_file.exists():
            source_file = ctx.workdir / "live.txt"
        if not source_file.exists():
            return {"produced": 0, "skipped": "nothing live to scan"}

        targets = ctx.scope.filter_allowed(
            [l.strip() for l in source_file.read_text().splitlines() if l.strip()])
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
    description = "Capture the distinct applications, not every duplicate of them."

    async def run(self, ctx):
        source = ctx.workdir / "distinct.txt"
        if not source.exists():
            return {"produced": 0, "skipped": "run deduplication first"}
        targets = ctx.scope.filter_allowed(
            [l.strip() for l in source.read_text().splitlines() if l.strip()])
        if not targets:
            return {"produced": 0, "skipped": "nothing to capture"}
        if not ctx.registry.have("httpx"):
            return {"produced": 0, "skipped": "httpx is not installed"}

        shots = ctx.workdir / "screenshots"
        shots.mkdir(exist_ok=True)
        target_file = ctx.write_list("screenshot_targets.txt", targets)
        argv = [ctx.registry.path("httpx"), "-l", str(target_file),
                "-ss", "-esb", "-ehb", "-silent", "-json",
                "-srd", str(shots), "-t", "10", "-timeout", "20"]
        argv += ctx.identification("httpx")
        result = await ctx.runner(ctx.workdir / "logs" / "screenshots.log", "httpx").run(
            argv, timeout=ctx.config.get("stage_timeout", 2400), idle_timeout=420)
        captured = len(list(shots.rglob("*.png")))
        ctx.counter("screenshots", captured)
        ctx.log(f"{captured} screenshot(s) — only the distinct applications were "
                f"captured, which is why this finished")
        return {"produced": captured, "command": result.command}


STAGES = {s.key: s for s in [
    SeedStage(), SubdomainStage(), PermuteStage(), WildcardStage(), ResolveStage(),
    ProbeStage(), DedupeStage(), PortStage(), UrlStage(), ParamStage(), JsStage(),
    TakeoverStage(), NucleiStage(), DastStage(), XssStage(), ScreenshotStage(),
]}


def resolve_stage_list(preset: str, active_stages=None):
    """The stage list for a run, with any opted-in active stages appended."""
    base = list(PRESETS.get(preset, PRESETS["standard"])["stages"])
    for key in (active_stages or []):
        if key in STAGES and key not in base:
            base.append(key)
    return base
