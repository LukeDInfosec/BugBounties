#!/usr/bin/env python3
"""Scope: deciding what may be touched, and proving why.

This is the safety-critical module. Everything else in the framework asks it
one question — *may I send a packet to this?* — and it must never answer yes
when the answer is no. A bug here is not a crash, it is a tester scanning
something they were not authorised to scan, which costs a programme ban.

Three decisions, not two
────────────────────────
    ALLOW    active tools may send traffic here
    OBSERVE  record it, note where it came from, never send it a packet
    DENY     drop it entirely

Most frameworks have only in-scope and out-of-scope, which forces a bad
choice: either you throw away the knowledge that ``staging.acme-cdn.net`` is
reachable from the target, or you scan it. OBSERVE keeps the discovery without
the traffic.

Rules of the engine, in order and without exception
───────────────────────────────────────────────────
1. Private, loopback, link-local and cloud-metadata addresses are denied
   before anything else is considered, unless the operator has explicitly
   enabled internal testing.
2. An exclude rule vetoes everything. There is no include that overrides it.
3. An include rule allows.
4. Anything else is OBSERVE, carrying the distance from whatever in-scope
   asset led to it.
5. Anything unparseable, ambiguous or erroring is DENY. Failing closed is the
   whole point.

Matching is label-wise, never substring
───────────────────────────────────────
``host.endswith("acme.com")`` matches ``notacme.com`` and is how people end up
testing a stranger's site. Every host comparison here is done on DNS labels.
Names are IDNA-encoded before comparison so a Cyrillic homoglyph cannot smuggle
itself past an ASCII rule.

DNS scope and IP scope never silently bridge
────────────────────────────────────────────
``api.acme.com`` being in scope does not put its IP in scope, and certainly
does not put the other four hundred virtual hosts sharing that IP in scope. A
hostname resolving to an address is a distance-1 edge; an address only reaches
distance 0 by being named in a CIDR rule.
"""

from __future__ import annotations

import ipaddress
import json
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlsplit


class Decision(str, Enum):
    ALLOW = "allow"
    OBSERVE = "observe"
    DENY = "deny"


class RuleKind(str, Enum):
    DOMAIN = "domain"        # example.com and everything under it
    HOST = "host"            # exactly this name, no children
    GLOB = "glob"            # api-*.example.com
    CIDR = "cidr"            # 203.0.113.0/24, or a bare IP
    URL = "url"              # scheme://host[:port]/path-prefix
    REGEX = "regex"          # anchored, matched against the whole value


#: Suffixes under which a host's parent is a shared platform rather than the
#: same organisation. Used only to stop lineage inference walking upwards into
#: somebody else's namespace — never for enforcement, which is explicit rules
#: only. This is a deliberately small, hand-checked subset of the Public
#: Suffix List covering what actually shows up in bug bounty scopes.
_PUBLIC_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "net.za", "web.za",
    "com.br", "net.br", "org.br", "gov.br",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "co.in", "net.in", "org.in", "gov.in", "ac.in",
    "com.mx", "com.ar", "com.co", "com.sg", "com.hk", "com.tw", "com.tr",
    "com.pl", "com.ua", "com.my", "com.ph", "com.vn", "com.pk", "com.eg",
    "co.il", "co.kr", "co.id", "co.th", "or.kr", "ne.kr",
    # Shared hosting platforms — a sibling here is a different customer.
    "github.io", "gitlab.io", "herokuapp.com", "azurewebsites.net",
    "cloudfront.net", "amazonaws.com", "s3.amazonaws.com", "elb.amazonaws.com",
    "appspot.com", "web.app", "firebaseapp.com", "netlify.app", "vercel.app",
    "pages.dev", "workers.dev", "r2.dev", "surge.sh", "now.sh",
    "blob.core.windows.net", "trafficmanager.net", "cloudapp.azure.com",
    "readthedocs.io", "zendesk.com", "myshopify.com", "wpengine.com",
    "statuspage.io", "fastly.net", "akamaized.net", "cloudflare.net",
}

#: Address ranges that must never be scanned from a bug bounty run unless the
#: operator has deliberately turned internal testing on.
_METADATA_ADDRESSES = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("100.100.100.200"),   # Alibaba Cloud
    ipaddress.ip_address("192.0.0.192"),       # Oracle Cloud
    ipaddress.ip_address("fd00:ec2::254"),     # AWS IMDS over IPv6
}

#: Ranges that are not routable on the public internet but that Python's
#: ``is_private`` does not consistently flag across versions. Carrier-grade NAT
#: in particular is shared address space — a host there is somebody else's.
_EXTRA_BLOCKED_NETWORKS = [
    ipaddress.ip_network("100.64.0.0/10"),     # RFC 6598 CGNAT
    ipaddress.ip_network("192.0.0.0/24"),      # IETF protocol assignments
    ipaddress.ip_network("198.18.0.0/15"),     # benchmarking
    ipaddress.ip_network("64:ff9b::/96"),      # NAT64
    ipaddress.ip_network("fc00::/7"),          # unique local
]

_LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")


# ─────────────────────────────────────────────────────────────────────────────
#  Normalisation
# ─────────────────────────────────────────────────────────────────────────────

def normalise_host(value: str):
    """Canonical ASCII form of a hostname, or None if it is not one.

    Returning None is a DENY signal — callers must not fall back to the raw
    string. Unicode is normalised and IDNA-encoded so that a name using
    lookalike characters cannot compare equal to an ASCII rule by accident,
    nor slip past one.
    """
    if not value:
        return None
    text = value.strip().strip(".").lower()
    if not text or len(text) > 253:
        return None
    # Strip anything that is clearly not a bare hostname.
    if "/" in text or "@" in text or " " in text:
        return None
    if ":" in text and not text.count(":") > 1:   # host:port, not IPv6
        text = text.split(":", 1)[0]

    try:
        text = unicodedata.normalize("NFKC", text)
    except Exception:
        return None

    if any(ord(ch) > 127 for ch in text):
        try:
            text = text.encode("idna").decode("ascii").lower()
        except Exception:
            return None

    labels = text.split(".")
    if not labels or any(not _LABEL_RE.match(lbl) for lbl in labels):
        # A wildcard label is allowed in rules but never in an asset; callers
        # strip it before asking.
        return None
    return text


def normalise_ip(value: str):
    """Parse an address into a canonical object, or None.

    Goes through ``ipaddress`` rather than string comparison so that
    ``::ffff:127.0.0.1`` and ``127.0.0.1`` are recognised as the same host.
    """
    try:
        return ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None


def normalise_url(value: str):
    """Split a URL into (scheme, host, port, path), canonically.

    Userinfo is discarded deliberately: in ``https://api.acme.com@evil.test/``
    the host is ``evil.test``, and a scope check that reads the string left to
    right gets this catastrophically wrong.
    """
    if not value:
        return None
    text = value.strip()
    if "://" not in text:
        text = "https://" + text
    try:
        parts = urlsplit(text)
    except ValueError:
        return None

    scheme = (parts.scheme or "https").lower()
    if scheme not in ("http", "https"):
        return None

    host = parts.hostname            # urlsplit already drops userinfo
    if host is None:
        return None
    if normalise_ip(host) is None:
        host = normalise_host(host)
        if host is None:
            return None
    else:
        host = str(normalise_ip(host))

    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError:
        return None

    path = parts.path or "/"
    return scheme, host, port, path


def registrable_domain(host: str) -> str:
    """The organisational domain of a hostname.

    ``api.shop.acme.co.uk`` → ``acme.co.uk``; ``luke.github.io`` → itself,
    because a sibling under a shared platform belongs to somebody else.

    An IP address has no registrable domain and is returned unchanged. Without
    this, ``127.0.0.1`` would be "shortened" to ``0.1`` and every address in a
    /16 would share one rate-limit bucket — the limiter would be silently
    wrong in exactly the situation where it matters.
    """
    if normalise_ip(host) is not None:
        return host
    labels = (host or "").split(".")
    if len(labels) <= 2:
        return host or ""
    for depth in (3, 2):
        if len(labels) >= depth:
            candidate = ".".join(labels[-depth:])
            if candidate in _PUBLIC_SUFFIXES:
                return ".".join(labels[-(depth + 1):]) if len(labels) > depth else candidate
    return ".".join(labels[-2:])


def host_in_domain(host: str, apex: str, include_children: bool = True) -> bool:
    """Label-wise containment. The substring version of this is a security bug."""
    if not host or not apex:
        return False
    if host == apex:
        return True
    return include_children and host.endswith("." + apex)


# ─────────────────────────────────────────────────────────────────────────────
#  Rules
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Rule:
    kind: RuleKind
    value: str
    include_children: bool = True
    note: str = ""

    _net: object = field(default=None, repr=False, compare=False)
    _rx: object = field(default=None, repr=False, compare=False)
    _url: object = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        self.value = (self.value or "").strip()
        if self.kind == RuleKind.CIDR:
            try:
                self._net = ipaddress.ip_network(self.value, strict=False)
            except ValueError:
                self._net = None
        elif self.kind == RuleKind.REGEX:
            pattern = self.value
            if not pattern.startswith("^"):
                pattern = "^" + pattern
            if not pattern.endswith("$"):
                pattern = pattern + "$"
            try:
                self._rx = re.compile(pattern, re.IGNORECASE)
            except re.error:
                self._rx = None
        elif self.kind == RuleKind.URL:
            self._url = normalise_url(self.value)

    @property
    def valid(self) -> bool:
        if self.kind == RuleKind.CIDR:
            return self._net is not None
        if self.kind == RuleKind.REGEX:
            return self._rx is not None
        if self.kind == RuleKind.URL:
            return self._url is not None
        if self.kind in (RuleKind.DOMAIN, RuleKind.HOST):
            return normalise_host(self.value) is not None
        if self.kind == RuleKind.GLOB:
            return bool(self.value) and "*" in self.value
        return False

    def describe(self) -> str:
        if self.kind == RuleKind.DOMAIN:
            return f"*.{self.value}" if self.include_children else self.value
        return f"{self.kind.value}:{self.value}"

    # ── matching ──────────────────────────────────────────────────────────

    def matches_host(self, host: str) -> bool:
        if self.kind == RuleKind.DOMAIN:
            return host_in_domain(host, normalise_host(self.value) or "",
                                  self.include_children)
        if self.kind == RuleKind.HOST:
            return host == (normalise_host(self.value) or "\0")
        if self.kind == RuleKind.GLOB:
            return _glob_match(host, self.value.lower())
        if self.kind == RuleKind.REGEX:
            return bool(self._rx and self._rx.match(host))
        if self.kind == RuleKind.URL:
            return bool(self._url and self._url[1] == host)
        return False

    def matches_ip(self, addr) -> bool:
        if self.kind == RuleKind.CIDR:
            if self._net is None:
                return False
            if addr.version != self._net.version:
                return False
            return addr in self._net
        if self.kind in (RuleKind.HOST, RuleKind.REGEX):
            return self.matches_host(str(addr))
        return False

    def matches_url(self, parsed) -> bool:
        scheme, host, port, path = parsed
        if self.kind == RuleKind.URL:
            if not self._url:
                return False
            r_scheme, r_host, r_port, r_path = self._url
            if r_host != host or r_scheme != scheme or r_port != port:
                return False
            prefix = r_path.rstrip("/")
            return not prefix or path == prefix or path.startswith(prefix + "/")
        if self.kind == RuleKind.REGEX:
            full = f"{scheme}://{host}:{port}{path}"
            return bool(self._rx and (self._rx.match(full) or self._rx.match(host)))
        return self.matches_host(host)


def _glob_match(value: str, pattern: str) -> bool:
    """Glob that respects label boundaries: ``*`` never crosses a dot.

    ``api-*.acme.com`` matches ``api-eu.acme.com`` but not
    ``api-eu.internal.acme.com``, which a naive fnmatch would allow.
    """
    regex = "^" + re.escape(pattern).replace(r"\*", r"[^.]*") + "$"
    try:
        return bool(re.match(regex, value))
    except re.error:
        return False


# ─────────────────────────────────────────────────────────────────────────────
#  The engine
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Verdict:
    decision: Decision
    distance: int
    reason: str
    rule: str = ""

    @property
    def allowed(self) -> bool:
        return self.decision == Decision.ALLOW

    def as_dict(self):
        return {"decision": self.decision.value, "distance": self.distance,
                "reason": self.reason, "rule": self.rule}


class Scope:
    """An immutable-ish scope, hashed so findings can be tied to the rules
    that were in force when they were produced."""

    def __init__(self, seeds=None, include=None, exclude=None,
                 allow_private=False, max_distance=0, allow_metadata=False):
        self.seeds = list(seeds or [])
        self.include = [r for r in (include or [])]
        self.exclude = [r for r in (exclude or [])]
        self.allow_private = bool(allow_private)
        # Deliberately separate from allow_private. Someone testing an
        # internal range still does not want a scanner wandering into the
        # cloud metadata service by accident — that is how a recon run turns
        # into credential theft against the client's own infrastructure.
        self.allow_metadata = bool(allow_metadata)
        self.max_distance = int(max_distance)
        self._cache = {}

    # ── construction ──────────────────────────────────────────────────────

    @staticmethod
    def parse_rule(text: str, default_children: bool = True) -> Rule:
        """Turn one line of user input into a rule.

        Accepts what a bug bounty scope page actually contains:
        ``*.acme.com``, ``acme.com``, ``api.acme.com``, ``203.0.113.0/24``,
        ``https://acme.com/app/``, ``re:^api\\d+\\.acme\\.com$``.
        """
        raw = (text or "").strip()
        if not raw:
            raise ValueError("empty rule")

        if raw.lower().startswith("re:"):
            return Rule(RuleKind.REGEX, raw[3:].strip())
        if "://" in raw:
            return Rule(RuleKind.URL, raw)
        if raw.startswith("*."):
            return Rule(RuleKind.DOMAIN, raw[2:], include_children=True)
        if "*" in raw:
            return Rule(RuleKind.GLOB, raw)
        if "/" in raw:
            return Rule(RuleKind.CIDR, raw)
        if normalise_ip(raw) is not None:
            return Rule(RuleKind.CIDR, raw)
        # A bare domain. Whether children are included is the single most
        # consequential ambiguity in a scope page, so it is explicit.
        return Rule(RuleKind.DOMAIN, raw, include_children=default_children)

    @classmethod
    def from_lines(cls, include_text="", exclude_text="", seeds_text="",
                   allow_private=False, bare_domain_includes_children=True,
                   max_distance=0, allow_metadata=False):
        def parse_block(block):
            rules, errors = [], []
            for line in (block or "").splitlines():
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                try:
                    rule = cls.parse_rule(line, bare_domain_includes_children)
                except ValueError as exc:
                    errors.append((line, str(exc)))
                    continue
                if not rule.valid:
                    errors.append((line, "not a valid rule"))
                    continue
                rules.append(rule)
            return rules, errors

        include, inc_err = parse_block(include_text)
        exclude, exc_err = parse_block(exclude_text)
        seeds = [s.strip() for s in (seeds_text or "").splitlines() if s.strip()]
        if not seeds:
            seeds = [r.value for r in include if r.kind == RuleKind.DOMAIN]

        scope = cls(seeds=seeds, include=include, exclude=exclude,
                    allow_private=allow_private, max_distance=max_distance,
                    allow_metadata=allow_metadata)
        scope.errors = inc_err + exc_err
        return scope

    def fingerprint(self) -> str:
        """Stable hash of the rule set, stored on every run and asset."""
        import hashlib
        payload = json.dumps({
            "include": sorted(r.describe() for r in self.include),
            "exclude": sorted(r.describe() for r in self.exclude),
            "allow_private": self.allow_private,
            "allow_metadata": self.allow_metadata,
            "max_distance": self.max_distance,
        }, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    # ── the decision ──────────────────────────────────────────────────────

    def classify(self, asset: str, kind: str = "auto", parent_distance=None) -> Verdict:
        """Decide what may be done with one asset.

        ``kind`` is one of host / ip / url, or "auto" to work it out. A
        ``parent_distance`` is passed when the asset was discovered from
        another, so distance accumulates along the discovery chain.
        """
        key = (asset, kind, parent_distance)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        verdict = self._classify_uncached(asset, kind, parent_distance)
        if len(self._cache) < 200_000:
            self._cache[key] = verdict
        return verdict

    def _classify_uncached(self, asset, kind, parent_distance) -> Verdict:
        raw = (asset or "").strip()
        if not raw:
            return Verdict(Decision.DENY, 99, "empty value")

        if kind == "auto":
            if "://" in raw or raw.startswith("/"):
                kind = "url"
            elif normalise_ip(raw.split("/")[0]) is not None:
                kind = "ip"
            else:
                kind = "host"

        # ── parse, failing closed ──────────────────────────────────────────
        parsed_url = parsed_ip = parsed_host = None
        if kind == "url":
            parsed_url = normalise_url(raw)
            if parsed_url is None:
                return Verdict(Decision.DENY, 99, "unparseable URL")
            host_part = parsed_url[1]
            parsed_ip = normalise_ip(host_part)
            parsed_host = None if parsed_ip else host_part
        elif kind == "ip":
            parsed_ip = normalise_ip(raw)
            if parsed_ip is None:
                return Verdict(Decision.DENY, 99, "unparseable address")
        else:
            parsed_host = normalise_host(raw)
            if parsed_host is None:
                return Verdict(Decision.DENY, 99, "unparseable hostname")

        # ── 1. the hard safety net, before any rule is consulted ───────────
        if parsed_ip is not None:
            if parsed_ip in _METADATA_ADDRESSES and not self.allow_metadata:
                return Verdict(Decision.DENY, 99, "cloud metadata address")
            if not self.allow_private:
                blocked = self._dangerous_address(parsed_ip)
                if blocked:
                    return Verdict(Decision.DENY, 99, blocked)
        if parsed_host and not self.allow_private:
            if parsed_host == "localhost" or parsed_host.endswith(".localhost"):
                return Verdict(Decision.DENY, 99, "loopback name")

        # ── 2. exclude vetoes everything ───────────────────────────────────
        for rule in self.exclude:
            if self._rule_matches(rule, kind, parsed_url, parsed_ip, parsed_host):
                return Verdict(Decision.DENY, 99, "explicitly excluded",
                               rule.describe())

        # ── 3. include allows ──────────────────────────────────────────────
        for rule in self.include:
            if self._rule_matches(rule, kind, parsed_url, parsed_ip, parsed_host):
                return Verdict(Decision.ALLOW, 0, "matches an in-scope rule",
                               rule.describe())

        # ── 4. everything else is observed, never touched ──────────────────
        distance = 1 if parent_distance is None else int(parent_distance) + 1
        if distance <= self.max_distance:
            return Verdict(Decision.ALLOW, distance,
                           f"within max_distance {self.max_distance} of an in-scope asset")
        return Verdict(Decision.OBSERVE, distance,
                       "not in scope — recorded, but no traffic will be sent")

    @staticmethod
    def _dangerous_address(addr):
        # Checked first so the reason names it: "link-local" is true of
        # 169.254.169.254 but tells the operator far less than "cloud
        # metadata address", which is the thing they need to see.
        if addr in _METADATA_ADDRESSES:
            return "cloud metadata address"
        if addr.is_loopback:
            return "loopback address"
        if addr.is_link_local:
            return "link-local address"
        if addr.is_private:
            return "private address (RFC1918 or equivalent)"
        if addr.is_reserved or addr.is_multicast or addr.is_unspecified:
            return "reserved or multicast address"
        for net in _EXTRA_BLOCKED_NETWORKS:
            if addr.version == net.version and addr in net:
                return f"non-routable range {net}"
        return ""

    @staticmethod
    def _rule_matches(rule, kind, parsed_url, parsed_ip, parsed_host):
        if kind == "url":
            if rule.kind == RuleKind.CIDR:
                return parsed_ip is not None and rule.matches_ip(parsed_ip)
            return rule.matches_url(parsed_url)
        if kind == "ip":
            return rule.matches_ip(parsed_ip)
        return rule.matches_host(parsed_host)

    # ── operator-facing helpers ───────────────────────────────────────────

    def explain(self, asset: str) -> str:
        """A sentence a human can check. This is how trust gets built."""
        verdict = self.classify(asset)
        word = {Decision.ALLOW: "IN SCOPE", Decision.OBSERVE: "OBSERVE ONLY",
                Decision.DENY: "BLOCKED"}[verdict.decision]
        line = f"{asset} → {word} — {verdict.reason}"
        if verdict.rule:
            line += f" [{verdict.rule}]"
        if verdict.decision != Decision.ALLOW:
            line += "  (no packets will be sent)"
        return line

    def filter_allowed(self, assets, kind="auto", parent_distance=None):
        """The input gate. Tools are only ever handed the output of this."""
        out = []
        for asset in assets:
            if self.classify(asset, kind, parent_distance).allowed:
                out.append(asset)
        return out

    def partition(self, assets, kind="auto"):
        """Split a discovery list three ways, for reporting to the operator."""
        allowed, observed, denied = [], [], []
        for asset in assets:
            verdict = self.classify(asset, kind)
            if verdict.decision == Decision.ALLOW:
                allowed.append(asset)
            elif verdict.decision == Decision.OBSERVE:
                observed.append(asset)
            else:
                denied.append((asset, verdict.reason))
        return allowed, observed, denied

    def summary(self) -> dict:
        return {
            "includes": [r.describe() for r in self.include],
            "excludes": [r.describe() for r in self.exclude],
            "seeds": list(self.seeds),
            "allow_private": self.allow_private,
            "allow_metadata": self.allow_metadata,
            "max_distance": self.max_distance,
            "fingerprint": self.fingerprint(),
        }
