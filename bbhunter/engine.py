#!/usr/bin/env python3
"""Running a scan: stage sequencing, live events, cancellation, resume."""

from __future__ import annotations

import asyncio
import json
import time
import traceback
from pathlib import Path

from .pipeline import (STAGES, PRESETS, PHASES, StageContext,
                       resolve_stage_list, phase_for)
from .proxy import ScopeProxy, RatePolicy
from .scope import Scope
from .tools import ToolRegistry


class EventBus:
    """Fans stage events out to connected browsers without letting a slow
    browser slow the scan down.

    Each subscriber gets its own bounded queue. When a queue fills — a tab left
    open on a laptop that went to sleep — the oldest events are dropped and a
    counter is incremented, which the UI shows. The alternative is
    backpressure reaching the scanner, which is how dashboards freeze scans.
    """

    def __init__(self, ring_size=2000):
        self.subscribers = []
        self.ring = []
        self.ring_size = ring_size
        self.seq = 0

    def publish(self, kind, data):
        self.seq += 1
        event = {"seq": self.seq, "kind": kind, "ts": time.time(), "data": data}
        self.ring.append(event)
        if len(self.ring) > self.ring_size:
            del self.ring[:len(self.ring) - self.ring_size]
        for queue, dropped in self.subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                try:
                    queue.get_nowait()
                    queue.put_nowait(event)
                    dropped[0] += 1
                except Exception:
                    pass
        return event

    def subscribe(self, maxsize=1000):
        queue = asyncio.Queue(maxsize=maxsize)
        dropped = [0]
        entry = (queue, dropped)
        self.subscribers.append(entry)
        return entry

    def unsubscribe(self, entry):
        try:
            self.subscribers.remove(entry)
        except ValueError:
            pass

    def replay(self, after_seq=0):
        return [e for e in self.ring if e["seq"] > after_seq]


class ScanEngine:
    """One scan at a time per programme. Owns the proxy for its lifetime."""

    def __init__(self, store, data_dir: Path):
        self.store = store
        self.data_dir = Path(data_dir)
        self.registry = ToolRegistry()
        self.bus = EventBus()
        self.current = None          # dict describing the in-flight run
        self._task = None
        self._proxy = None

    # ── introspection ─────────────────────────────────────────────────────

    def status(self):
        if not self.current:
            return {"running": False}
        out = dict(self.current)
        out["running"] = True
        if self._proxy:
            out["requests"] = self._proxy.total_requests
            out["blocked"] = self._proxy.total_blocked
        return out

    async def detect_tools(self):
        return await self.registry.detect()

    # ── preflight ─────────────────────────────────────────────────────────

    def preflight(self, program, preset, active_stages, config):
        """What is about to happen, in words, before anything is sent.

        This is the safety interlock and it doubles as the thing that makes a
        run reproducible: everything that determines the outcome is on one
        screen before the operator commits to it.
        """
        scope = _scope_from_program(program)
        stage_keys = resolve_stage_list(preset, active_stages)
        stages = [{"key": k, "name": STAGES[k].name,
                   "description": STAGES[k].description,
                   "tool": STAGES[k].tool_key,
                   "installed": (not STAGES[k].tool_key
                                 or self.registry.have(STAGES[k].tool_key)),
                   "active": k in ("dast", "xss")}
                  for k in stage_keys if k in STAGES]

        missing = sorted({s["tool"] for s in stages
                          if s["tool"] and not s["installed"]})
        headers = dict(config.get("headers") or {})

        return {
            "program": program["name"],
            "preset": preset,
            "preset_blurb": PRESETS.get(preset, {}).get("blurb", ""),
            "scope": scope.summary(),
            "seeds": scope.seeds,
            "stages": stages,
            "missing_tools": missing,
            "active": [s["key"] for s in stages if s["active"]],
            "rate": {
                "per_host_rps": config.get("per_host_rps", 5),
                "global_rps": config.get("global_rps", 20),
                "per_host_concurrency": config.get("per_host_concurrency", 10),
            },
            "identification": headers,
            "user_agent": config.get("user_agent", ""),
            "warnings": self._warnings(scope, stages, headers, config),
        }

    @staticmethod
    def _warnings(scope, stages, headers, config):
        warnings = []
        if not scope.include:
            warnings.append("No in-scope rules are set. Nothing will be scanned.")
        if scope.allow_private:
            warnings.append("Private address ranges are enabled. Only do this on "
                            "an engagement that covers internal infrastructure.")
        if scope.allow_metadata:
            warnings.append("Cloud metadata addresses are reachable. This is "
                            "almost never what you want.")
        if any(s["active"] for s in stages):
            warnings.append("Active testing is on: injection payloads will be "
                            "sent to parameters found on in-scope hosts.")
        if not headers:
            warnings.append("No identification header is configured. Most "
                            "programmes ask you to identify your traffic — set "
                            "one on the programme so a blue team can tell your "
                            "scan from an attack.")
        if float(config.get("per_host_rps", 5)) > 10:
            warnings.append(f"{config.get('per_host_rps')} requests per second "
                            f"per host is above what most programmes permit.")
        return warnings

    # ── running ───────────────────────────────────────────────────────────

    async def start(self, program, preset, active_stages, config, resume=True,
                    only_stages=None):
        """Run a preset, or — when ``only_stages`` is given — just those steps.

        Running one phase at a time is how the interface offers "re-run just
        this step". It matters because recon is iterative: you add three
        subdomains by hand and want probing redone, not the whole chain.
        """
        if self.current:
            raise RuntimeError("a scan is already running")

        scope = _scope_from_program(program)
        if only_stages:
            stage_keys = [k for k in only_stages if k in STAGES]
        else:
            stage_keys = [k for k in resolve_stage_list(preset, active_stages)
                          if k in STAGES]
        if not stage_keys:
            raise RuntimeError("no runnable stages were selected")

        run_id = self.store.create_run(program["id"], preset,
                                       scope.fingerprint(),
                                       {"stages": stage_keys, **config})
        workdir = self.data_dir / "runs" / f"{program['id']}-{run_id}"
        (workdir / "logs").mkdir(parents=True, exist_ok=True)

        self.current = {
            "run_id": run_id, "program_id": program["id"],
            "program": program["name"], "preset": preset,
            "stages": stage_keys, "started_at": time.time(),
            "stage_states": {k: "pending" for k in stage_keys},
            "stage_names": {k: STAGES[k].name for k in stage_keys},
            "phases": {k: phase_for(k) for k in stage_keys},
            "counters": {}, "current_stage": None,
            "partial": bool(only_stages),
        }
        self._task = asyncio.create_task(
            self._run(program, scope, stage_keys, config, run_id, workdir, resume))
        return run_id

    async def cancel(self):
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        return True

    async def _run(self, program, scope, stage_keys, config, run_id, workdir, resume):
        policy = RatePolicy(
            per_host_rps=float(config.get("per_host_rps", 5)),
            per_host_concurrency=int(config.get("per_host_concurrency", 10)),
            global_rps=float(config.get("global_rps", 20)),
            headers=dict(config.get("headers") or {}),
            user_agent=config.get("user_agent", ""),
        )
        if config.get("allow_methods"):
            policy.allowed_methods = set(config["allow_methods"])

        self._proxy = ScopeProxy(scope, policy,
                                 on_event=lambda k, d: self.bus.publish(k, d))
        await self._proxy.start()
        self.bus.publish("run_started", {
            "run_id": run_id, "program": program["name"],
            "stages": [{"key": k, "name": STAGES[k].name,
                        "phase": phase_for(k)} for k in stage_keys],
            "proxy_port": self._proxy.port,
        })
        self.bus.publish("log", {
            "text": (f"Scope gate active on 127.0.0.1:{self._proxy.port}. Every "
                     f"tool's traffic passes through it and anything outside "
                     f"scope is refused there, not just filtered from the "
                     f"input list."),
            "level": "info"})

        status = "completed"
        note = ""
        findings_total = 0

        try:
            await self.registry.detect()
            for key in stage_keys:
                stage = STAGES[key]
                stage_id = self.store.add_stage(run_id, key, stage.name, stage.tool_key)
                self.current["current_stage"] = key
                self.current["stage_states"][key] = "running"
                self.bus.publish("stage", {"key": key, "name": stage.name,
                                           "phase": phase_for(key),
                                           "status": "running"})
                self.store.update_stage(stage_id, status="running",
                                        started_at=time.time())

                ctx = StageContext(
                    store=self.store, scope=scope, proxy=self._proxy,
                    registry=self.registry, program_id=program["id"],
                    run_id=run_id, workdir=workdir,
                    config={**config, "_stage_id": stage_id,
                            "_wildcards": self.current.get("_wildcards", {})},
                    emit=lambda kind, data, _k=key: self._stage_event(_k, kind, data),
                )

                started = time.monotonic()
                try:
                    result = await stage.run(ctx)
                except asyncio.CancelledError:
                    self.store.update_stage(stage_id, status="cancelled",
                                            finished_at=time.time())
                    self.current["stage_states"][key] = "cancelled"
                    self.bus.publish("stage", {"key": key, "status": "cancelled"})
                    raise
                except Exception as exc:
                    detail = traceback.format_exc(limit=3)
                    self.store.update_stage(stage_id, status="failed",
                                            finished_at=time.time(),
                                            message=str(exc)[:400])
                    self.current["stage_states"][key] = "failed"
                    self.bus.publish("stage", {"key": key, "status": "failed",
                                               "message": str(exc)[:300]})
                    self.bus.publish("log", {"text": f"{stage.name} failed: {exc}",
                                             "level": "error"})
                    self.bus.publish("log", {"text": detail, "level": "debug"})
                    status = "partial"
                    continue

                # Findings the stage produced go in once, here, so a stage
                # cannot half-write the findings table.
                for finding in ctx.findings:
                    self.store.record_finding(program["id"], run_id, finding)
                    self.bus.publish("finding", {
                        "severity": finding.get("severity", "info"),
                        "title": finding.get("title", ""),
                        "target": finding.get("target", ""),
                        "tool": finding.get("tool", ""),
                    })
                findings_total += len(ctx.findings)

                if key == "wildcard":
                    self.current["_wildcards"] = result.get("wildcards", {})
                    config["_wildcards"] = result.get("wildcards", {})

                elapsed = time.monotonic() - started
                skipped = result.get("skipped")
                final = "skipped" if skipped else "completed"
                self.store.update_stage(
                    stage_id, status=final, finished_at=time.time(),
                    produced=int(result.get("produced", 0)),
                    command=result.get("command", ""),
                    message=skipped or "",
                    stage_key=stage.stage_key(ctx, []),
                    log_path=str(workdir / "logs"))
                self.current["stage_states"][key] = final
                self.bus.publish("stage", {
                    "key": key, "status": final,
                    "produced": result.get("produced", 0),
                    "elapsed": round(elapsed, 1),
                    "message": skipped or "",
                })
                if skipped:
                    self.bus.publish("log", {
                        "text": f"{stage.name} skipped — {skipped}", "level": "warn"})

        except asyncio.CancelledError:
            status = "cancelled"
            note = "cancelled by the operator"
            self.bus.publish("log", {"text": "Scan cancelled. Every tool process "
                                             "and its children were terminated.",
                                     "level": "warn"})
            raise
        except Exception as exc:
            status = "failed"
            note = str(exc)[:400]
            self.bus.publish("log", {"text": f"Run failed: {exc}", "level": "error"})
        finally:
            stats = self._proxy.stats() if self._proxy else {}
            self.store.finish_run(run_id, status, note, stats)
            if self._proxy:
                await self._proxy.stop()
                busiest = sorted(stats.get("hosts", {}).items(),
                                 key=lambda kv: -kv[1]["requests"])[:3]
                self.bus.publish("log", {
                    "text": (f"{stats.get('total_requests', 0)} request(s) sent, "
                             f"{stats.get('total_blocked', 0)} refused by the scope "
                             f"gate."
                             + ("  Busiest: " + ", ".join(
                                 f"{h} ({v['requests']})" for h, v in busiest)
                                if busiest else "")),
                    "level": "info"})
            self._proxy = None
            diff = self.store.diff(program["id"], run_id)
            self.bus.publish("run_finished", {
                "run_id": run_id, "status": status, "note": note,
                "findings": findings_total,
                "new_assets": len(diff.get("new_assets", [])),
                "request_stats": stats,
            })
            self.current = None
            self._task = None

    def _stage_event(self, stage_key, kind, data):
        if kind == "counter":
            self.current and self.current["counters"].update(
                {data["name"]: data["value"]})
            self.bus.publish("counter", data)
        elif kind == "log":
            self.bus.publish("log", {**data, "stage": stage_key})
        elif kind == "tool":
            self.bus.publish("tool", {**data, "stage": stage_key})
        else:
            self.bus.publish(kind, {**data, "stage": stage_key})


def _scope_from_program(program) -> Scope:
    raw = json.loads(program.get("scope_json") or "{}")
    return Scope.from_lines(
        include_text="\n".join(raw.get("include", [])),
        exclude_text="\n".join(raw.get("exclude", [])),
        seeds_text="\n".join(raw.get("seeds", [])),
        allow_private=bool(raw.get("allow_private")),
        allow_metadata=bool(raw.get("allow_metadata")),
        bare_domain_includes_children=bool(raw.get("bare_includes_children", True)),
        max_distance=int(raw.get("max_distance", 0)),
    )
