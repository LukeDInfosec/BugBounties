#!/usr/bin/env python3
"""The HTTP API and WebSocket stream behind the interface.

Bound to loopback only. This process holds API keys and can start scans, so it
is not something to expose on a network, and the framework will refuse to bind
anywhere else without an explicit override.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import config as cfg
from . import updater
from .engine import ScanEngine, _scope_from_program
from .pipeline import PRESETS, STAGES, ACTIVE_STAGES, PHASES, phase_for
from .scope import Scope
from .store import Store

WEB = Path(__file__).resolve().parent / "web"


class ProgramIn(BaseModel):
    name: str
    platform: str = ""
    handle: str = ""
    include: str = ""
    exclude: str = ""
    seeds: str = ""
    allow_private: bool = False
    allow_metadata: bool = False
    bare_includes_children: bool = True
    max_distance: int = 0
    headers: dict = {}
    per_host_rps: float = 5
    global_rps: float = 20


class RunIn(BaseModel):
    program_id: int
    preset: str = "standard"
    active_stages: list = []
    acknowledge_active: bool = False
    overrides: dict = {}
    #: When set, only these stages run. Used by "re-run just this step".
    only_stages: list = []


class TriageIn(BaseModel):
    finding_id: int
    triage: str
    note: str = ""


def create_app():
    store = Store(cfg.db_path())
    engine = ScanEngine(store, cfg.data_dir())
    app = FastAPI(title="bbhunter", version=cfg.version(),
                  docs_url=None, redoc_url=None)

    if WEB.exists():
        app.mount("/static", StaticFiles(directory=str(WEB)), name="static")

    # ── pages ─────────────────────────────────────────────────────────────

    @app.get("/", response_class=HTMLResponse)
    async def index():
        html = (WEB / "index.html")
        if not html.exists():
            return HTMLResponse("<h1>bbhunter</h1><p>Interface files are missing.</p>",
                                status_code=500)
        return HTMLResponse(html.read_text(encoding="utf-8"))

    # ── meta ──────────────────────────────────────────────────────────────

    @app.get("/api/meta")
    async def meta():
        settings = cfg.load_config()
        return {
            "version": cfg.version(),
            "presets": {k: {"label": v["label"], "blurb": v["blurb"],
                            "stages": v["stages"]} for k, v in PRESETS.items()},
            "active_stages": {k: {"label": v[0], "warning": v[1]}
                              for k, v in ACTIVE_STAGES.items()},
            "stages": {k: {"name": s.name, "description": s.description,
                           "tool": s.tool_key, "phase": phase_for(k)}
                       for k, s in STAGES.items()},
            "phases": PHASES,
            "settings": {k: v for k, v in settings.items() if k != "api_keys"},
            "data_dir": str(cfg.data_dir()),
        }

    @app.get("/api/tools")
    async def tools():
        await engine.detect_tools()
        return engine.registry.summary()

    @app.get("/api/settings")
    async def get_settings():
        settings = cfg.load_config()
        keys = settings.get("api_keys") or {}
        # Never send a key back to the browser; say only whether one is set.
        settings["api_keys"] = {k: bool(v) for k, v in keys.items()}
        return settings

    @app.post("/api/settings")
    async def set_settings(payload: dict):
        return cfg.save_config(payload)

    # ── programmes ────────────────────────────────────────────────────────

    @app.get("/api/programs")
    async def programs():
        out = []
        for program in store.programs():
            item = dict(program)
            item["scope"] = json.loads(item.pop("scope_json") or "{}")
            item["policy"] = json.loads(item.pop("policy_json") or "{}")
            item["stats"] = store.stats(program["id"])
            out.append(item)
        return out

    @app.post("/api/programs")
    async def save_program(payload: ProgramIn):
        scope = Scope.from_lines(
            include_text=payload.include, exclude_text=payload.exclude,
            seeds_text=payload.seeds, allow_private=payload.allow_private,
            allow_metadata=payload.allow_metadata,
            bare_domain_includes_children=payload.bare_includes_children,
            max_distance=payload.max_distance)
        errors = getattr(scope, "errors", [])
        scope_dict = {
            "include": [l.strip() for l in payload.include.splitlines() if l.strip()],
            "exclude": [l.strip() for l in payload.exclude.splitlines() if l.strip()],
            "seeds": [l.strip() for l in payload.seeds.splitlines() if l.strip()],
            "allow_private": payload.allow_private,
            "allow_metadata": payload.allow_metadata,
            "bare_includes_children": payload.bare_includes_children,
            "max_distance": payload.max_distance,
        }
        headers = cfg.identification_headers(payload.handle, payload.headers,
                                             payload.platform)
        policy = {"per_host_rps": payload.per_host_rps,
                  "global_rps": payload.global_rps,
                  "headers": headers}
        program = store.upsert_program(
            payload.name, scope_dict, policy, payload.platform,
            payload.handle, scope.fingerprint())
        return {"program": program, "scope": scope.summary(),
                "rule_errors": [{"line": l, "error": e} for l, e in errors],
                "headers": headers}

    @app.delete("/api/programs/{program_id}")
    async def delete_program(program_id: int):
        store.delete_program(program_id)
        return {"ok": True}

    @app.post("/api/scope/explain")
    async def explain(payload: dict):
        program = store.program(int(payload.get("program_id", 0)))
        if not program:
            raise HTTPException(404, "no such programme")
        scope = _scope_from_program(program)
        results = []
        for asset in (payload.get("assets") or "").splitlines():
            asset = asset.strip()
            if not asset:
                continue
            verdict = scope.classify(asset)
            results.append({"asset": asset, **verdict.as_dict(),
                            "text": scope.explain(asset)})
        return {"results": results}

    # ── runs ──────────────────────────────────────────────────────────────

    @app.post("/api/preflight")
    async def preflight(payload: RunIn):
        program = store.program(payload.program_id)
        if not program:
            raise HTTPException(404, "no such programme")
        await engine.detect_tools()
        settings = cfg.load_config()
        policy = json.loads(program.get("policy_json") or "{}")
        run_config = {**settings, **policy, **(payload.overrides or {})}
        return engine.preflight(program, payload.preset,
                                payload.active_stages, run_config)

    @app.post("/api/runs")
    async def start_run(payload: RunIn):
        program = store.program(payload.program_id)
        if not program:
            raise HTTPException(404, "no such programme")
        if engine.current:
            raise HTTPException(409, "a scan is already running")
        if payload.active_stages and not payload.acknowledge_active:
            raise HTTPException(
                400, "active testing must be acknowledged before it can run")

        settings = cfg.load_config()
        policy = json.loads(program.get("policy_json") or "{}")
        run_config = {**settings, **policy, **(payload.overrides or {})}
        run_id = await engine.start(program, payload.preset,
                                    payload.active_stages, run_config,
                                    only_stages=payload.only_stages or None)
        return {"run_id": run_id}

    @app.get("/api/runs/status")
    async def run_status():
        return engine.status()

    @app.post("/api/runs/cancel")
    async def cancel_run():
        await engine.cancel()
        return {"ok": True}

    @app.get("/api/programs/{program_id}/runs")
    async def list_runs(program_id: int):
        runs = store.runs(program_id)
        for run in runs:
            run["stages"] = store.stages(run["id"])
        return runs

    @app.get("/api/programs/{program_id}/diff")
    async def diff(program_id: int, run_id: int = 0, baseline: int = 0):
        if not run_id:
            runs = store.runs(program_id, limit=1)
            if not runs:
                return {"new_assets": [], "gone_assets": [], "new_findings": []}
            run_id = runs[0]["id"]
        return store.diff(program_id, run_id, baseline or None)

    # ── results ───────────────────────────────────────────────────────────

    @app.get("/api/programs/{program_id}/assets")
    async def assets(program_id: int, kind: str = "", decision: str = "",
                     search: str = "", new_in_run: int = 0,
                     limit: int = 300, offset: int = 0, order: str = "key"):
        return {
            "items": store.assets(program_id, kind or None, decision or None,
                                  search, new_in_run or None, limit, offset, order),
            "total": store.count_assets(program_id, kind or None,
                                        decision or None),
            "kinds": store.asset_kinds(program_id),
        }

    @app.get("/api/programs/{program_id}/findings")
    async def findings(program_id: int, severity: str = "", triage: str = "",
                       search: str = "", new_in_run: int = 0,
                       limit: int = 300, offset: int = 0):
        return {
            "items": store.findings(program_id, severity or None, triage or None,
                                    search, new_in_run or None, limit, offset),
            "counts": store.finding_counts(program_id),
        }

    @app.post("/api/findings/triage")
    async def triage(payload: TriageIn):
        store.set_triage(payload.finding_id, payload.triage, payload.note)
        return {"ok": True}

    @app.get("/api/programs/{program_id}/export")
    async def export(program_id: int, fmt: str = "json"):
        program = store.program(program_id)
        if not program:
            raise HTTPException(404, "no such programme")
        payload = {
            "program": program["name"],
            "exported_at": time.time(),
            "scope": json.loads(program.get("scope_json") or "{}"),
            "stats": store.stats(program_id),
            "findings": store.findings(program_id, limit=10000),
            "assets": {kind: store.asset_keys(program_id, kind)
                       for kind in store.asset_kinds(program_id)},
        }
        out = cfg.data_dir() / f"export-{program_id}.json"
        out.write_text(json.dumps(payload, indent=2, default=str))
        return FileResponse(str(out), filename=f"{program['name']}-export.json",
                            media_type="application/json")

    # ── screenshots ───────────────────────────────────────────────────────

    @app.get("/api/programs/{program_id}/gallery")
    async def gallery(program_id: int, search: str = "", limit: int = 400):
        """The captured applications, newest run first.

        Deduplicated on the way out: if the same URL was captured in several
        runs, only the most recent image is listed, because a gallery of the
        same page four times is not a gallery.
        """
        rows = store.assets(program_id, "screenshot", search=search,
                            limit=limit, order="recent")
        items = []
        for row in rows:
            data = row.get("data") or {}
            if not data.get("image"):
                continue
            items.append({
                "url": row["key"],
                "title": data.get("title") or "",
                "status": data.get("status"),
                "tech": data.get("tech") or [],
                "server": data.get("server") or "",
                "image": f"/api/programs/{program_id}/shot/"
                         f"{data.get('run_id')}/{data.get('image')}",
                "last_seen": row.get("last_seen_at"),
            })
        return {"items": items, "total": store.count_assets(program_id, "screenshot")}

    @app.get("/api/programs/{program_id}/shot/{run_id}/{name}")
    async def shot(program_id: int, run_id: int, name: str):
        # The name comes from our own index, but it still arrives over HTTP,
        # so it is resolved and confined to the run's screenshot directory
        # rather than trusted.
        base = (cfg.data_dir() / "runs" / f"{program_id}-{run_id}"
                / "screenshots").resolve()
        try:
            path = (base / name).resolve()
            path.relative_to(base)
        except (ValueError, OSError):
            raise HTTPException(400, "bad path")
        if not path.is_file():
            raise HTTPException(404, "no such screenshot")
        return FileResponse(str(path), media_type="image/png")

    # ── updates ───────────────────────────────────────────────────────────

    @app.get("/api/update/check")
    async def update_check():
        return await updater.check()

    @app.post("/api/update/apply")
    async def update_apply():
        return await updater.apply()

    # ── live stream ───────────────────────────────────────────────────────

    @app.websocket("/ws")
    async def websocket(ws: WebSocket):
        await ws.accept()
        entry = engine.bus.subscribe()
        queue, dropped = entry
        try:
            since = 0
            try:
                first = await asyncio.wait_for(ws.receive_text(), timeout=2)
                since = int(json.loads(first).get("since", 0))
            except Exception:
                since = 0

            replay = engine.bus.replay(since)
            if replay:
                await ws.send_text(json.dumps({"type": "batch", "events": replay[-500:]}))
            await ws.send_text(json.dumps({"type": "status",
                                           "status": engine.status()}))

            # Batched on a tick. One frame per line would kill the browser at
            # nuclei's output rate.
            while True:
                events = []
                try:
                    events.append(await asyncio.wait_for(queue.get(), timeout=0.4))
                except asyncio.TimeoutError:
                    pass
                while len(events) < 200:
                    try:
                        events.append(queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break
                if events:
                    await ws.send_text(json.dumps({
                        "type": "batch", "events": events,
                        "dropped": dropped[0]}))
                else:
                    await ws.send_text(json.dumps({"type": "ping"}))
        except (WebSocketDisconnect, asyncio.CancelledError):
            pass
        except Exception:
            pass
        finally:
            engine.bus.unsubscribe(entry)

    app.state.store = store
    app.state.engine = engine
    return app
