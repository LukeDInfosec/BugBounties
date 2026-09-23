#!/usr/bin/env python3
"""The egress gate: every tool's traffic goes through here or not at all.

Why this exists
───────────────
Filtering a tool's *input* list is necessary but not sufficient. A crawler
follows a redirect off-scope. A template has a hard-coded callback. A scanner
picks up an absolute URL from a page. An SSRF payload fires at the cloud
metadata address. A tool has a bug. In every one of those cases the input
filter was correct and the packet still left the machine.

So scope is enforced twice: once when the target list is built, and once here,
at the moment a connection is attempted. Tools are launched with
``HTTP_PROXY``/``HTTPS_PROXY`` pointing at this process and, where they support
it, an explicit ``-proxy`` flag. The proxy re-classifies the host of every
single connection and refuses the ones that are not in scope.

It also does two other jobs that have to be central to be correct:

**Rate limiting.** Five tools each politely set to 5 requests per second
against the same host is 25 requests per second. No individual tool can see
the aggregate; this process can. A token bucket per registrable domain, shared
across every tool, is the only place the real number is knowable.

**Identification.** Programmes ask you to identify yourself, and being
identifiable is what stops a blue team treating a scan as an intrusion. The
proxy stamps the configured header — typically your handle — onto every plain
HTTP request that passes through it.

What it cannot do, stated plainly
─────────────────────────────────
A CONNECT tunnel is opaque. For HTTPS this proxy validates and rate-limits the
host in the CONNECT line and then forwards bytes; it cannot add a header
inside someone else's TLS session without intercepting it with a forged
certificate, which would mean every tool has to be told to trust a local CA and
would break certificate-dependent checks. That trade is not worth it, so
headers for HTTPS are injected by each tool's own ``-H`` flag instead — see
``tools.py``, which does this for every tool that supports it. The enforcement
and the rate limiting apply to HTTP and HTTPS equally.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field

from .scope import Scope, Decision, registrable_domain, normalise_host, normalise_ip

#: Methods a recon run is ever allowed to make. Anything else is refused —
#: nothing here should be deleting or overwriting a customer's data.
SAFE_METHODS = {"GET", "HEAD", "POST", "OPTIONS", "PUT", "PATCH", "DELETE", "TRACE"}
DEFAULT_ALLOWED_METHODS = {"GET", "HEAD", "POST", "OPTIONS"}

#: Paths that are never requested automatically, whatever a crawler found.
#: Hitting these is how an automated run logs itself out mid-scan, or worse.
DEFAULT_PATH_DENYLIST = (
    "/logout", "/signout", "/sign-out", "/log-out",
    "/delete", "/destroy", "/remove", "/purge", "/reset",
    "/shutdown", "/restart", "/reboot",
)


@dataclass
class RatePolicy:
    """Per-host and aggregate limits. Deliberately conservative."""
    per_host_rps: float = 5.0
    per_host_concurrency: int = 10
    global_rps: float = 20.0
    allowed_methods: set = field(default_factory=lambda: set(DEFAULT_ALLOWED_METHODS))
    path_denylist: tuple = DEFAULT_PATH_DENYLIST
    headers: dict = field(default_factory=dict)
    user_agent: str = ""


class TokenBucket:
    """Classic token bucket, awaited rather than polled."""

    def __init__(self, rate: float, burst: float = None):
        self.rate = max(0.1, float(rate))
        self.capacity = float(burst if burst is not None else max(1.0, rate))
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def take(self, amount: float = 1.0):
        async with self._lock:
            while True:
                now = time.monotonic()
                self.tokens = min(self.capacity,
                                  self.tokens + (now - self.updated) * self.rate)
                self.updated = now
                if self.tokens >= amount:
                    self.tokens -= amount
                    return
                wait = (amount - self.tokens) / self.rate
                await asyncio.sleep(min(wait, 1.0))


@dataclass
class HostState:
    """What the proxy has learned about one host while running."""
    requests: int = 0
    blocked: int = 0
    errors: int = 0
    throttled: int = 0
    backoff_until: float = 0.0
    rate_multiplier: float = 1.0


class ScopeProxy:
    """An HTTP/HTTPS forward proxy that will not leave scope.

    Runs inside the framework's event loop; there is no separate process to
    supervise and no configuration file to get out of step with the scope the
    operator is actually looking at in the UI.
    """

    def __init__(self, scope: Scope, policy: RatePolicy = None, on_event=None):
        self.scope = scope
        self.policy = policy or RatePolicy()
        self.on_event = on_event or (lambda *_a, **_k: None)

        self._buckets = {}
        self._semaphores = {}
        self._global = TokenBucket(self.policy.global_rps,
                                   burst=max(5.0, self.policy.global_rps))
        self.hosts = defaultdict(HostState)
        self.total_requests = 0
        self.total_blocked = 0
        self._server = None
        self.port = 0

    # ── lifecycle ─────────────────────────────────────────────────────────

    async def start(self, host="127.0.0.1", port=0):
        self._server = await asyncio.start_server(self._handle, host, port)
        self.port = self._server.sockets[0].getsockname()[1]
        return self.port

    async def stop(self):
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
            self._server = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def env(self) -> dict:
        """Environment that forces an unconfigured tool through the proxy."""
        return {
            "HTTP_PROXY": self.url, "http_proxy": self.url,
            "HTTPS_PROXY": self.url, "https_proxy": self.url,
            "NO_PROXY": "", "no_proxy": "",
        }

    # ── gating ────────────────────────────────────────────────────────────

    def _bucket(self, key: str) -> TokenBucket:
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = TokenBucket(self.policy.per_host_rps,
                                 burst=max(2.0, self.policy.per_host_rps))
            self._buckets[key] = bucket
        return bucket

    def _semaphore(self, key: str) -> asyncio.Semaphore:
        sem = self._semaphores.get(key)
        if sem is None:
            sem = asyncio.Semaphore(self.policy.per_host_concurrency)
            self._semaphores[key] = sem
        return sem

    def check(self, host: str, port: int, method: str = "GET", path: str = "/"):
        """The decision, with a reason a human can read. No I/O."""
        # CONNECT is how a client asks for a tunnel; it is not a method being
        # applied to the target. The method policy governs what goes *inside*
        # the tunnel. Refusing CONNECT here would block every HTTPS request —
        # which is very nearly all bug bounty traffic.
        if method.upper() != "CONNECT" and \
                method.upper() not in self.policy.allowed_methods:
            return False, f"method {method} is not enabled for this run"

        canonical = host
        if normalise_ip(host) is None:
            canonical = normalise_host(host) or ""
            if not canonical:
                return False, "unparseable host"

        verdict = self.scope.classify(canonical, "auto")
        if verdict.decision != Decision.ALLOW:
            return False, f"{verdict.reason} ({verdict.decision.value})"

        lowered = (path or "/").split("?", 1)[0].lower().rstrip("/")
        for denied in self.policy.path_denylist:
            if lowered == denied or lowered.endswith(denied):
                return False, f"path {denied} is on the safety denylist"

        state = self.hosts[registrable_domain(canonical) or canonical]
        if state.backoff_until > time.monotonic():
            remaining = state.backoff_until - time.monotonic()
            return False, f"host is backed off for another {remaining:.0f}s"

        return True, ""

    async def _acquire(self, host: str):
        key = registrable_domain(host) or host
        await self._global.take()
        await self._bucket(key).take()
        return self._semaphore(key)

    def note_response(self, host: str, status: int):
        """Adaptive backoff. A 429 is the target asking you to slow down, and
        ignoring it is both rude and a good way to get false negatives."""
        key = registrable_domain(host) or host
        state = self.hosts[key]
        if status in (429, 503):
            state.throttled += 1
            state.rate_multiplier = max(0.1, state.rate_multiplier * 0.5)
            bucket = self._bucket(key)
            bucket.rate = max(0.2, self.policy.per_host_rps * state.rate_multiplier)
            state.backoff_until = time.monotonic() + min(60, 2 ** min(6, state.throttled))
            self.on_event("throttled", {
                "host": key, "status": status,
                "new_rate": round(bucket.rate, 2),
                "backoff_s": round(state.backoff_until - time.monotonic()),
            })

    # ── request handling ──────────────────────────────────────────────────

    async def _handle(self, reader, writer):
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=30)
            if not request_line:
                return
            parts = request_line.decode("latin-1", "replace").split()
            if len(parts) < 3:
                await self._refuse(writer, 400, "malformed request line",
                                   counts=False)
                return
            method, target, version = parts[0], parts[1], parts[2]

            headers = []
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=30)
                if not line or line in (b"\r\n", b"\n"):
                    break
                headers.append(line)
                if len(headers) > 200:
                    break

            if method.upper() == "CONNECT":
                await self._handle_connect(reader, writer, target)
            else:
                await self._handle_absolute(reader, writer, method, target,
                                            version, headers)
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as exc:
            try:
                await self._refuse(writer, 500, f"proxy error: {exc}",
                                   counts=False)
            except Exception:
                pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _refuse(self, writer, code: int, reason: str, counts=True):
        # Only a scope or policy refusal counts as "blocked". An upstream
        # connection failure is a 502 and must not inflate the number the
        # interface reports as "refused by the scope gate" — that number is
        # evidence about where traffic went, so it has to be honest.
        if counts:
            self.total_blocked += 1
        body = (f"bbhunter proxy refused this request\n\n{reason}\n").encode()
        writer.write(
            f"HTTP/1.1 {code} Blocked\r\n"
            f"Content-Type: text/plain\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"X-BBHunter-Block-Reason: {reason[:180]}\r\n"
            f"Connection: close\r\n\r\n".encode() + body)
        try:
            await writer.drain()
        except Exception:
            pass

    async def _handle_connect(self, reader, writer, target):
        host, _, port_text = target.rpartition(":")
        host = (host or target).strip("[]")
        try:
            port = int(port_text)
        except ValueError:
            port = 443

        ok, reason = self.check(host, port, "CONNECT", "/")
        if not ok:
            self.hosts[registrable_domain(host) or host].blocked += 1
            self.on_event("blocked", {"host": host, "port": port, "reason": reason,
                                      "method": "CONNECT"})
            await self._refuse(writer, 403, reason)
            return

        sem = await self._acquire(host)
        async with sem:
            state = self.hosts[registrable_domain(host) or host]
            state.requests += 1
            self.total_requests += 1
            try:
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=20)
            except Exception as exc:
                state.errors += 1
                await self._refuse(writer, 502, f"upstream connect failed: {exc}",
                                   counts=False)
                return

            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await self._pipe(reader, writer, remote_reader, remote_writer)

    async def _handle_absolute(self, reader, writer, method, target, version, headers):
        from urllib.parse import urlsplit

        if "://" not in target:
            await self._refuse(writer, 400,
                               "only absolute-form proxy requests are accepted",
                               counts=False)
            return
        parts = urlsplit(target)
        host = parts.hostname or ""
        port = parts.port or (443 if parts.scheme == "https" else 80)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query

        ok, reason = self.check(host, port, method, path)
        if not ok:
            self.hosts[registrable_domain(host) or host].blocked += 1
            self.on_event("blocked", {"host": host, "port": port, "reason": reason,
                                      "method": method, "path": path[:120]})
            await self._refuse(writer, 403, reason)
            return

        if parts.scheme == "https":
            # An absolute https:// URL through a plain proxy would mean this
            # process terminating TLS. Tools issue CONNECT for that; anything
            # that does not is refused rather than silently downgraded.
            await self._refuse(writer, 400, "use CONNECT for https targets",
                               counts=False)
            return

        sem = await self._acquire(host)
        async with sem:
            state = self.hosts[registrable_domain(host) or host]
            state.requests += 1
            self.total_requests += 1
            try:
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=20)
            except Exception as exc:
                state.errors += 1
                await self._refuse(writer, 502, f"upstream connect failed: {exc}",
                                   counts=False)
                return

            # The operator configured these deliberately, so they win over
            # whatever the tool set. Identification only works if it is
            # actually on the request, and a tool's own default User-Agent is
            # not what the programme asked to see.
            overrides = {k.lower(): (k, v)
                         for k, v in (self.policy.headers or {}).items()}
            if self.policy.user_agent:
                overrides["user-agent"] = ("User-Agent", self.policy.user_agent)

            rebuilt = [f"{method} {path} {version}\r\n".encode("latin-1")]
            for raw in headers:
                name = raw.split(b":", 1)[0].strip().lower().decode("latin-1", "replace")
                if name in ("proxy-connection", "proxy-authorization"):
                    continue
                if name in overrides:
                    continue          # replaced below
                rebuilt.append(raw)
            for name, value in overrides.values():
                rebuilt.append(f"{name}: {value}\r\n".encode("latin-1", "replace"))
            rebuilt.append(b"\r\n")

            remote_writer.write(b"".join(rebuilt))
            await remote_writer.drain()

            status = await self._relay_response(remote_reader, writer)
            if status:
                self.note_response(host, status)
            try:
                remote_writer.close()
            except Exception:
                pass

    async def _relay_response(self, remote_reader, writer):
        """Forward the response, reading the status code on the way past."""
        status = 0
        try:
            first = await asyncio.wait_for(remote_reader.readline(), timeout=30)
            if not first:
                return 0
            try:
                status = int(first.split()[1])
            except (IndexError, ValueError):
                status = 0
            writer.write(first)
            while True:
                chunk = await asyncio.wait_for(remote_reader.read(65536), timeout=60)
                if not chunk:
                    break
                writer.write(chunk)
                await writer.drain()
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception:
            pass
        return status

    @staticmethod
    async def _pipe(client_reader, client_writer, remote_reader, remote_writer):
        async def copy(src, dst):
            try:
                while True:
                    chunk = await src.read(65536)
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
            except Exception:
                pass
            finally:
                try:
                    dst.close()
                except Exception:
                    pass

        await asyncio.gather(
            copy(client_reader, remote_writer),
            copy(remote_reader, client_writer),
            return_exceptions=True,
        )

    # ── reporting ─────────────────────────────────────────────────────────

    def stats(self) -> dict:
        """What was actually sent, per host. A programme manager may ask."""
        return {
            "total_requests": self.total_requests,
            "total_blocked": self.total_blocked,
            "hosts": {
                name: {
                    "requests": st.requests, "blocked": st.blocked,
                    "errors": st.errors, "throttled": st.throttled,
                    "rate_multiplier": round(st.rate_multiplier, 2),
                }
                for name, st in sorted(self.hosts.items(),
                                       key=lambda kv: -kv[1].requests)
            },
        }
