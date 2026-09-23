#!/usr/bin/env python3
"""Which tools exist on this machine, how to install them, and how to identify
yourself to the target through each one.

Two things this file is careful about.

**Kali's package names lag.** ``apt install httpx-toolkit`` gives you a binary
called ``httpx-toolkit``, not ``httpx``, because Kali's ``python3-httpx``
already owns ``/usr/bin/httpx`` — and it is several minor versions behind
upstream. Every entry here therefore lists the candidate binary names in
preference order and the framework uses whichever it finds, rather than
assuming one and failing confusingly later.

**Identification has to reach the target.** The proxy can stamp a header onto
plain HTTP, but a CONNECT tunnel is opaque, so for HTTPS the header has to come
from the tool itself. Each entry records the flag that tool uses for a custom
header, and ``header_args`` turns the operator's configured headers into the
right arguments. That is what puts your handle on the request whether it went
over HTTP or HTTPS.
"""

from __future__ import annotations

import asyncio
import os
import shutil
from dataclasses import dataclass, field


@dataclass
class Tool:
    key: str
    binaries: tuple                # candidate names, in preference order
    purpose: str
    install: str                   # the command that installs it
    install_kind: str = "go"       # go | apt | pipx | script
    version_args: tuple = ("-version",)
    header_flag: str = ""          # e.g. "-H"; empty when unsupported
    header_style: str = "name: value"
    rate_flag: str = ""            # e.g. "-rl"
    proxy_flag: str = ""           # e.g. "-proxy"
    optional: bool = True
    notes: str = ""
    #: A binary of the right *name* is not necessarily the right *tool*.
    #: When set, the version output must contain one of these, or the tool is
    #: reported as not installed with an explanation. This is what catches
    #: Python's httpx client sitting at /usr/bin/httpx on Kali and being
    #: mistaken for ProjectDiscovery's prober — a confusion that otherwise
    #: surfaces as a stage that "completes" having probed nothing.
    verify_any: tuple = ()
    wrong_tool_hint: str = ""

    def resolve(self):
        for name in self.binaries:
            path = shutil.which(name)
            if path:
                return path
        return ""

    def header_args(self, headers: dict, user_agent: str = ""):
        """Arguments that put the operator's identification on the request."""
        if not self.header_flag:
            return []
        args = []
        for name, value in (headers or {}).items():
            args += [self.header_flag, f"{name}: {value}"]
        if user_agent:
            args += [self.header_flag, f"User-Agent: {user_agent}"]
        return args


TOOLS = {
    # ── subdomain enumeration ─────────────────────────────────────────────
    "subfinder": Tool(
        "subfinder", ("subfinder",),
        "Passive subdomain enumeration across dozens of sources",
        "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        version_args=("-version",), rate_flag="-rl", optional=False,
        notes="API keys live in ~/.config/subfinder/provider-config.yaml"),
    "chaos": Tool(
        "chaos", ("chaos",),
        "ProjectDiscovery's dataset built from public bug bounty scopes",
        "go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest",
        notes="Needs PDCP_API_KEY. Rate limited to 60 requests a minute."),
    "assetfinder": Tool(
        "assetfinder", ("assetfinder",),
        "Extra passive sources; cheap to run alongside subfinder",
        "go install github.com/tomnomnom/assetfinder@latest",
        version_args=()),
    "github-subdomains": Tool(
        "github-subdomains", ("github-subdomains",),
        "Hostnames leaked in public GitHub code — finds internal names nothing else sees",
        "go install github.com/gwen001/github-subdomains@latest",
        version_args=(), notes="Supply several tokens; one gets rate limited fast."),
    "bbot": Tool(
        "bbot", ("bbot",),
        "Recursive enumeration with NLP mutations; the strongest single enumerator",
        "pipx install bbot", install_kind="pipx", version_args=("--version",)),

    # ── permutation and resolution ────────────────────────────────────────
    "alterx": Tool(
        "alterx", ("alterx",),
        "Generates permutations mined from the names you already found",
        "go install github.com/projectdiscovery/alterx/cmd/alterx@latest"),
    "dnsx": Tool(
        "dnsx", ("dnsx",),
        "DNS resolution, record enrichment and wildcard filtering",
        "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        rate_flag="-rl", optional=False),
    "puredns": Tool(
        "puredns", ("puredns",),
        "Mass resolution with wildcard detection and trusted re-validation",
        "go install github.com/d3mondev/puredns/v2@latest",
        version_args=("--help",),
        notes="Needs massdns on PATH. Its trusted re-validation pass is what "
              "keeps lying public resolvers out of your results."),
    "massdns": Tool(
        "massdns", ("massdns",), "Bulk DNS engine used by puredns",
        "sudo apt install -y massdns", install_kind="apt", version_args=()),

    # ── probing ───────────────────────────────────────────────────────────
    "httpx": Tool(
        "httpx", ("httpx-toolkit", "httpx"),
        "Finds which hosts actually serve HTTP, with title, tech and hashes",
        "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        header_flag="-H", rate_flag="-rl", proxy_flag="-http-proxy",
        optional=False,
        verify_any=("projectdiscovery", "httpx-toolkit"),
        wrong_tool_hint=("The binary found is the Python httpx HTTP client, "
                         "which shares the name. Install ProjectDiscovery's "
                         "httpx and it will be picked up — the launcher puts "
                         "$HOME/go/bin ahead on PATH."),
        notes="Kali's apt package installs as httpx-toolkit because "
              "python3-httpx owns /usr/bin/httpx. The framework checks which "
              "one it actually found."),
    "naabu": Tool(
        "naabu", ("naabu",), "Fast port discovery that chains into httpx",
        "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        rate_flag="-rate",
        notes="SYN scanning needs root; without it naabu falls back to connect "
              "scanning, which is much slower."),
    "tlsx": Tool(
        "tlsx", ("tlsx",),
        "Bulk certificate grabbing — the SANs are a free source of new names",
        "go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest"),
    "cdncheck": Tool(
        "cdncheck", ("cdncheck",),
        "Tells you which addresses are CDN, so you do not port scan Cloudflare",
        "go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"),

    # ── URLs and parameters ───────────────────────────────────────────────
    "katana": Tool(
        "katana", ("katana",),
        "Active crawler with JavaScript parsing",
        "go install github.com/projectdiscovery/katana/cmd/katana@latest",
        header_flag="-H", rate_flag="-rl", proxy_flag="-proxy",
        notes="-jsl uses jsluice for JS parsing, which beats regex extraction."),
    "gau": Tool(
        "gau", ("gau",),
        "Historical URLs from Wayback, Common Crawl, OTX and URLScan",
        "go install github.com/lc/gau/v2/cmd/gau@latest",
        version_args=("--version",), proxy_flag="--proxy"),
    "urlfinder": Tool(
        "urlfinder", ("urlfinder",),
        "ProjectDiscovery's passive URL source; overlaps gau but not entirely",
        "go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"),
    "waymore": Tool(
        "waymore", ("waymore",),
        "Archive mining that also fetches archived response bodies",
        "pipx install git+https://github.com/xnl-h4ck3r/waymore.git",
        install_kind="pipx", version_args=("-h",)),
    "uro": Tool(
        "uro", ("uro",),
        "Collapses a URL list to distinct endpoint shapes without sending requests",
        "pipx install uro", install_kind="pipx", version_args=()),
    "arjun": Tool(
        "arjun", ("arjun",),
        "Finds hidden parameters by binary-search probing",
        "pipx install arjun", install_kind="pipx", version_args=(),
        header_flag="--headers", header_style="raw"),
    "gf": Tool(
        "gf", ("gf",),
        "Saved grep patterns that slice a URL corpus into per-bug-class candidates",
        "go install github.com/tomnomnom/gf@latest", version_args=()),
    "anew": Tool(
        "anew", ("anew",), "Append-if-new; the right primitive for incremental recon",
        "go install github.com/tomnomnom/anew@latest", version_args=()),

    # ── vulnerabilities ───────────────────────────────────────────────────
    "nuclei": Tool(
        "nuclei", ("nuclei",),
        "Template-driven scanning, plus fuzzing templates under -dast",
        "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        header_flag="-H", rate_flag="-rl", proxy_flag="-proxy", optional=False,
        notes="Pass -duc in automation or it mutates its template directory "
              "mid-run."),
    "dalfox": Tool(
        "dalfox", ("dalfox",), "XSS discovery and verification",
        "go install github.com/hahwul/dalfox/v2@latest",
        version_args=("version",), header_flag="--header", proxy_flag="--proxy",
        notes="v3 is a Rust rewrite with a different CLI; the framework "
              "detects which is installed."),
    "subzy": Tool(
        "subzy", ("subzy",), "Subdomain takeover signatures",
        "go install -v github.com/PentestPad/subzy@latest", version_args=()),
    "interactsh-client": Tool(
        "interactsh-client", ("interactsh-client",),
        "Out-of-band callbacks — the only reliable way to find blind SSRF",
        "go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
        notes="Self-host it. Public oast.* domains are widely blocklisted by "
              "the targets worth testing."),
    "trufflehog": Tool(
        "trufflehog", ("trufflehog",),
        "Secret scanning that live-verifies what it finds",
        "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/"
        "main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin",
        install_kind="script", version_args=("--version",),
        notes="--results=verified is the whole point: a verified hit is a real "
              "working credential, not a regex match."),
    "jsluice": Tool(
        "jsluice", ("jsluice",),
        "Parses JavaScript with tree-sitter to extract URLs and secrets",
        "go install github.com/BishopFox/jsluice/cmd/jsluice@latest",
        version_args=()),
    "subjs": Tool(
        "subjs", ("subjs",), "Pulls JavaScript file URLs out of a page list",
        "go install github.com/lc/subjs@latest", version_args=()),

    # ── evidence ──────────────────────────────────────────────────────────
    "gowitness": Tool(
        "gowitness", ("gowitness",), "Screenshots, with a browsable report",
        "go install github.com/sensepost/gowitness@latest",
        version_args=("version",),
        notes="v3 restructured the CLI into `gowitness scan ...` subcommands."),

    # ── supporting ────────────────────────────────────────────────────────
    "nmap": Tool(
        "nmap", ("nmap",), "Service and version detection on the open ports",
        "sudo apt install -y nmap", install_kind="apt", version_args=("--version",)),
    "jq": Tool(
        "jq", ("jq",), "JSON handling in shell steps",
        "sudo apt install -y jq", install_kind="apt", version_args=("--version",)),
}

#: Stages refuse to run without these. Everything else degrades gracefully.
REQUIRED = [key for key, tool in TOOLS.items() if not tool.optional]


class ToolRegistry:
    """What is installed, at what version, and what is missing."""

    def __init__(self):
        self.state = {}

    async def detect(self, keys=None):
        """Probe every tool once. Cheap, and it is what the UI shows."""
        targets = list(keys or TOOLS.keys())
        results = await asyncio.gather(
            *[self._probe(TOOLS[k]) for k in targets if k in TOOLS],
            return_exceptions=True)
        for key, result in zip([k for k in targets if k in TOOLS], results):
            if isinstance(result, Exception):
                self.state[key] = {"key": key, "installed": False, "path": "",
                                   "version": "", "error": str(result)}
            else:
                self.state[key] = result
        return self.state

    @staticmethod
    async def _probe(tool: Tool):
        path = tool.resolve()
        info = {
            "key": tool.key, "installed": bool(path), "path": path, "version": "",
            "purpose": tool.purpose, "install": tool.install,
            "install_kind": tool.install_kind, "optional": tool.optional,
            "notes": tool.notes, "wrong_tool": False,
        }
        if not path or not tool.version_args:
            return info
        try:
            proc = await asyncio.create_subprocess_exec(
                path, *tool.version_args,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                stdin=asyncio.subprocess.DEVNULL, start_new_session=True)
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=12)
            text = (out or b"").decode("utf-8", "replace")

            if tool.verify_any and not any(
                    needle.lower() in text.lower() for needle in tool.verify_any):
                info["installed"] = False
                info["wrong_tool"] = True
                info["version"] = f"a different tool is at {path}"
                info["notes"] = tool.wrong_tool_hint or info["notes"]
                return info

            for line in text.splitlines():
                cleaned = line.strip()
                # Tool banners are noisy; take the first line that looks like
                # it carries a version rather than ASCII art.
                if cleaned and any(ch.isdigit() for ch in cleaned) and len(cleaned) < 120:
                    info["version"] = cleaned
                    break
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
        except Exception:
            pass
        return info

    def path(self, key) -> str:
        """Where the tool is — empty unless it passed identity verification.

        A binary that exists but is the wrong program must not be returned
        here, or a stage will happily execute it and report success having
        done nothing.
        """
        info = self.state.get(key) or {}
        return info.get("path", "") if info.get("installed") else ""

    def have(self, key) -> bool:
        return bool((self.state.get(key) or {}).get("installed"))

    def missing_required(self):
        return [k for k in REQUIRED if not self.have(k)]

    def summary(self):
        installed = [k for k, v in self.state.items() if v.get("installed")]
        missing = [k for k, v in self.state.items() if not v.get("installed")]
        return {
            "installed": sorted(installed),
            "missing": sorted(missing),
            "missing_required": self.missing_required(),
            "detail": self.state,
        }


def install_script(keys=None) -> str:
    """The exact commands to install a set of tools, for the UI to show."""
    lines = []
    for key in (keys or TOOLS.keys()):
        tool = TOOLS.get(key)
        if tool:
            lines.append(f"# {tool.key} — {tool.purpose}")
            lines.append(tool.install)
    return "\n".join(lines)
