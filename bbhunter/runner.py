#!/usr/bin/env python3
"""Running external tools without losing control of them.

Three things go wrong in every Python orchestrator that shells out to security
tools, and all three are handled here explicitly.

**Orphaned children.** Killing the process you spawned does not kill the
processes it spawned. Cancel a gowitness stage without this and Chrome keeps
running; cancel a naabu stage and nmap keeps scanning the target after the
operator pressed stop. Every tool is started in its own process group and
killed by group.

**Deadlock on a full pipe.** ``await proc.wait()`` before draining stdout hangs
the moment a tool fills the 64 KB pipe buffer, which nuclei does in under a
second. Both streams are pumped concurrently, always.

**Truncated JSON.** asyncio's default line limit is 64 KiB and httpx emits
single JSON lines far larger than that when screenshots are enabled. The limit
is raised and oversized lines are salvaged rather than dropped, because a
dropped line is a finding you never see.

There are two clocks on every stage. A hard timeout bounds the wall clock, and
an idle watchdog kills a tool that has stopped producing output — which is what
actually catches a hung scan, since a hard timeout alone either fires on
legitimate long runs or never fires at all.
"""

from __future__ import annotations

import asyncio
import os
import shlex
import signal
import time
from dataclasses import dataclass, field

#: 4 MiB. Large enough for an httpx line carrying a base64 screenshot.
STREAM_LIMIT = 4 * 1024 * 1024


@dataclass
class ToolResult:
    command: str
    exit_code: int
    stdout_lines: list = field(default_factory=list)
    stderr_lines: list = field(default_factory=list)
    duration: float = 0.0
    timed_out: bool = False
    idle_killed: bool = False
    cancelled: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not (self.timed_out or self.cancelled)

    @property
    def stderr_tail(self) -> str:
        return "\n".join(self.stderr_lines[-8:])


class CommandRunner:
    """Runs one external tool, streaming its output as it arrives."""

    def __init__(self, env_extra=None, on_line=None, log_path=None):
        self.env_extra = dict(env_extra or {})
        self.on_line = on_line or (lambda stream, line: None)
        self.log_path = log_path
        self._proc = None
        self._cancelled = False

    async def run(self, argv, timeout=3600, idle_timeout=300, cwd=None,
                  stdin_data=None, capture_stdout=True):
        """Execute ``argv``. Returns a ToolResult; never raises for tool failure."""
        env = os.environ.copy()
        env.update(self.env_extra)
        # A tool must never be able to prompt: a stage that blocks on stdin
        # looks identical to a hung scan and will sit there until the watchdog.
        env.setdefault("PYTHONUNBUFFERED", "1")

        command = " ".join(shlex.quote(str(a)) for a in argv)
        started = time.monotonic()
        result = ToolResult(command=command, exit_code=-1)

        log_file = None
        if self.log_path:
            try:
                os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
                log_file = open(self.log_path, "a", encoding="utf-8", errors="replace")
                log_file.write(f"\n$ {command}\n")
            except Exception:
                log_file = None

        try:
            self._proc = await asyncio.create_subprocess_exec(
                *[str(a) for a in argv],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=(asyncio.subprocess.PIPE if stdin_data is not None
                       else asyncio.subprocess.DEVNULL),
                limit=STREAM_LIMIT,
                start_new_session=True,      # own process group — see module docstring
                env=env,
                cwd=cwd,
            )
        except FileNotFoundError:
            result.exit_code = 127
            result.stderr_lines.append(f"{argv[0]}: not found on PATH")
            if log_file:
                log_file.close()
            return result
        except Exception as exc:
            result.exit_code = 126
            result.stderr_lines.append(f"could not start {argv[0]}: {exc}")
            if log_file:
                log_file.close()
            return result

        last_output = [time.monotonic()]

        async def pump(stream, kind):
            while True:
                try:
                    line = await stream.readline()
                except (ValueError, asyncio.LimitOverrunError):
                    # One enormous line. Salvage it rather than drop it.
                    try:
                        line = await stream.read(STREAM_LIMIT)
                    except Exception:
                        break
                except Exception:
                    break
                if not line:
                    break
                last_output[0] = time.monotonic()
                text = line.decode("utf-8", "replace").rstrip("\r\n")
                if kind == "out":
                    if capture_stdout:
                        result.stdout_lines.append(text)
                else:
                    result.stderr_lines.append(text)
                    if len(result.stderr_lines) > 2000:
                        del result.stderr_lines[:1000]
                if log_file:
                    try:
                        log_file.write(text + "\n")
                    except Exception:
                        pass
                try:
                    self.on_line(kind, text)
                except Exception:
                    pass

        async def watchdog():
            """Kill a tool that has gone quiet. This is the one that catches
            a genuinely hung scan."""
            while True:
                await asyncio.sleep(5)
                if self._proc is None or self._proc.returncode is not None:
                    return
                if idle_timeout and (time.monotonic() - last_output[0]) > idle_timeout:
                    result.idle_killed = True
                    await self.kill()
                    return

        if stdin_data is not None and self._proc.stdin is not None:
            try:
                self._proc.stdin.write(stdin_data.encode())
                await self._proc.stdin.drain()
                self._proc.stdin.close()
            except Exception:
                pass

        pumps = [asyncio.create_task(pump(self._proc.stdout, "out")),
                 asyncio.create_task(pump(self._proc.stderr, "err"))]
        guard = asyncio.create_task(watchdog())

        # Held so the cancellation exception is retrieved rather than left
        # for asyncio to complain about on garbage collection.
        gathered = asyncio.gather(*pumps, return_exceptions=True)
        try:
            await asyncio.wait_for(gathered, timeout=timeout)
            result.exit_code = await asyncio.wait_for(self._proc.wait(), timeout=30)
        except asyncio.TimeoutError:
            result.timed_out = True
            await self.kill()
            result.exit_code = -9
        except asyncio.CancelledError:
            result.cancelled = True
            self._cancelled = True
            await self.kill()
            result.exit_code = -15
            raise
        finally:
            guard.cancel()
            for task in pumps:
                task.cancel()
            if not gathered.done():
                gathered.cancel()
            try:
                await asyncio.gather(gathered, return_exceptions=True)
            except Exception:
                pass
            result.duration = time.monotonic() - started
            if log_file:
                try:
                    log_file.write(
                        f"[exit {result.exit_code} after {result.duration:.1f}s]\n")
                    log_file.close()
                except Exception:
                    pass
            self._proc = None

        if result.idle_killed:
            result.stderr_lines.append(
                f"[bbhunter] no output for {idle_timeout}s — treated as hung and stopped")
        return result

    async def kill(self):
        """Terminate the whole process group, politely then otherwise."""
        proc = self._proc
        if proc is None or proc.returncode is not None:
            return
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.terminate()
            except Exception:
                return
        try:
            await asyncio.wait_for(proc.wait(), timeout=10)
            return
        except (asyncio.TimeoutError, Exception):
            pass
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except Exception:
                pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except Exception:
            pass


class Semaphores:
    """A hierarchy of limits, because one global number is never right.

    Only one nmap at a time, but eight httpx; and a cap on the total number of
    processes so a big programme does not exhaust the machine.
    """

    def __init__(self, global_limit=8, per_tool=None):
        self.global_sem = asyncio.Semaphore(global_limit)
        self.per_tool_limits = dict(per_tool or {})
        self._tool_sems = {}

    def tool(self, name):
        sem = self._tool_sems.get(name)
        if sem is None:
            sem = asyncio.Semaphore(self.per_tool_limits.get(name, 4))
            self._tool_sems[name] = sem
        return sem
