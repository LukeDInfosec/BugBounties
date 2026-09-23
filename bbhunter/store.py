#!/usr/bin/env python3
"""Storage: assets that live forever, sightings that belong to a run.

The one modelling decision that matters
───────────────────────────────────────
An **asset** is an identity — ``api.acme.com`` is the same thing this week as
it was last week. An **observation** is one run having seen it. Keeping those
apart is what makes every question a bounty hunter actually asks into a plain
SQL query:

    what is new since I last looked   →  asset.first_seen_run
    what has disappeared              →  no observation in the latest run
    what changed                      →  compare the volatile columns

Frameworks that store recon as text files can only diff strings, which is why
none of them can tell you that port 8080 stopped being nginx and started being
Tomcat. That is the finding, and they cannot see it.

Findings carry a fingerprint built from things that do not change between runs
— template, host, normalised path, matcher — and deliberately not from the
response body or a timestamp. That is what makes triage stick: dismiss two
hundred informational results today and they stay dismissed next week, which
is the single most requested and least implemented feature in this category of
tool.

SQLite, in WAL mode, with one writer. That is comfortably enough for millions
of rows and it means the whole engagement is one file you can copy, back up or
hand to someone else.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path

SCHEMA_VERSION = 1

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS program (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    platform TEXT DEFAULT '',
    handle TEXT DEFAULT '',
    scope_json TEXT NOT NULL DEFAULT '{}',
    policy_json TEXT NOT NULL DEFAULT '{}',
    scope_hash TEXT DEFAULT '',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS run (
    id INTEGER PRIMARY KEY,
    program_id INTEGER NOT NULL REFERENCES program(id) ON DELETE CASCADE,
    preset TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    started_at REAL,
    finished_at REAL,
    scope_hash TEXT DEFAULT '',
    config_json TEXT DEFAULT '{}',
    note TEXT DEFAULT '',
    request_stats_json TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_run_program ON run(program_id, id DESC);

CREATE TABLE IF NOT EXISTS stage (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    name TEXT NOT NULL,
    tool TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    started_at REAL,
    finished_at REAL,
    exit_code INTEGER,
    command TEXT DEFAULT '',
    stage_key TEXT DEFAULT '',
    produced INTEGER DEFAULT 0,
    message TEXT DEFAULT '',
    log_path TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_stage_run ON stage(run_id, id);
CREATE INDEX IF NOT EXISTS idx_stage_key ON stage(stage_key);

-- Identity. One row per thing, for the life of the programme.
CREATE TABLE IF NOT EXISTS asset (
    id INTEGER PRIMARY KEY,
    program_id INTEGER NOT NULL REFERENCES program(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    first_seen_run INTEGER,
    last_seen_run INTEGER,
    first_seen_at REAL,
    last_seen_at REAL,
    scope_decision TEXT DEFAULT 'observe',
    scope_distance INTEGER DEFAULT 0,
    scope_reason TEXT DEFAULT '',
    data_json TEXT NOT NULL DEFAULT '{}',
    source TEXT DEFAULT '',
    acknowledged_at REAL,
    UNIQUE(program_id, kind, key)
);
CREATE INDEX IF NOT EXISTS idx_asset_new ON asset(program_id, kind, first_seen_run);
CREATE INDEX IF NOT EXISTS idx_asset_last ON asset(program_id, kind, last_seen_run);
CREATE INDEX IF NOT EXISTS idx_asset_scope ON asset(program_id, scope_decision, kind);

-- Sightings. One row per (asset, run).
CREATE TABLE IF NOT EXISTS observation (
    asset_id INTEGER NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    run_id INTEGER NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    seen_at REAL NOT NULL,
    PRIMARY KEY (asset_id, run_id)
);
CREATE INDEX IF NOT EXISTS idx_obs_run ON observation(run_id, asset_id);

CREATE TABLE IF NOT EXISTS edge (
    src_id INTEGER NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    dst_id INTEGER NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    rel TEXT NOT NULL,
    run_id INTEGER,
    PRIMARY KEY (src_id, dst_id, rel)
);
CREATE INDEX IF NOT EXISTS idx_edge_src ON edge(src_id, rel);
CREATE INDEX IF NOT EXISTS idx_edge_dst ON edge(dst_id, rel);

CREATE TABLE IF NOT EXISTS finding (
    id INTEGER PRIMARY KEY,
    program_id INTEGER NOT NULL REFERENCES program(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    title TEXT NOT NULL,
    category TEXT DEFAULT '',
    tool TEXT DEFAULT '',
    target TEXT DEFAULT '',
    detail TEXT DEFAULT '',
    evidence TEXT DEFAULT '',
    repro TEXT DEFAULT '',
    confidence TEXT DEFAULT 'firm',
    triage TEXT NOT NULL DEFAULT 'new',
    triage_note TEXT DEFAULT '',
    instances INTEGER DEFAULT 1,
    first_seen_run INTEGER,
    last_seen_run INTEGER,
    first_seen_at REAL,
    last_seen_at REAL,
    data_json TEXT DEFAULT '{}',
    UNIQUE(program_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_finding_sev
    ON finding(program_id, severity, triage, first_seen_run);

CREATE TABLE IF NOT EXISTS mute (
    id INTEGER PRIMARY KEY,
    program_id INTEGER NOT NULL REFERENCES program(id) ON DELETE CASCADE,
    pattern TEXT NOT NULL,
    scope TEXT DEFAULT 'template',
    note TEXT DEFAULT '',
    created_at REAL NOT NULL
);
"""

#: Severity ordering used everywhere results are sorted.
SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3,
                 "low": 2, "info": 1, "unknown": 0}


class Store:
    """The engagement database. One instance, one writer, one file."""

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(self.path), check_same_thread=False,
                                  isolation_level=None, timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', ?)",
            (str(SCHEMA_VERSION),))

    def close(self):
        try:
            self.db.close()
        except Exception:
            pass

    # ── programmes ────────────────────────────────────────────────────────

    def upsert_program(self, name, scope_dict, policy_dict, platform="",
                       handle="", scope_hash=""):
        now = time.time()
        self.db.execute("""
            INSERT INTO program(name, platform, handle, scope_json, policy_json,
                                scope_hash, created_at, updated_at)
            VALUES(?,?,?,?,?,?,?,?)
            ON CONFLICT(name) DO UPDATE SET
                platform=excluded.platform,
                handle=excluded.handle,
                scope_json=excluded.scope_json,
                policy_json=excluded.policy_json,
                scope_hash=excluded.scope_hash,
                updated_at=excluded.updated_at
        """, (name, platform, handle, json.dumps(scope_dict),
              json.dumps(policy_dict), scope_hash, now, now))
        return self.program_by_name(name)

    def program_by_name(self, name):
        row = self.db.execute("SELECT * FROM program WHERE name=?", (name,)).fetchone()
        return dict(row) if row else None

    def program(self, program_id):
        row = self.db.execute("SELECT * FROM program WHERE id=?",
                              (program_id,)).fetchone()
        return dict(row) if row else None

    def programs(self):
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM program ORDER BY updated_at DESC")]

    def delete_program(self, program_id):
        self.db.execute("DELETE FROM program WHERE id=?", (program_id,))

    # ── runs and stages ───────────────────────────────────────────────────

    def create_run(self, program_id, preset, scope_hash, config):
        cur = self.db.execute("""
            INSERT INTO run(program_id, preset, status, started_at, scope_hash,
                            config_json)
            VALUES(?,?,'running',?,?,?)
        """, (program_id, preset, time.time(), scope_hash, json.dumps(config)))
        return cur.lastrowid

    def finish_run(self, run_id, status, note="", request_stats=None):
        self.db.execute("""
            UPDATE run SET status=?, finished_at=?, note=?, request_stats_json=?
            WHERE id=?
        """, (status, time.time(), note,
              json.dumps(request_stats or {}), run_id))

    def run(self, run_id):
        row = self.db.execute("SELECT * FROM run WHERE id=?", (run_id,)).fetchone()
        return dict(row) if row else None

    def runs(self, program_id, limit=50):
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM run WHERE program_id=? ORDER BY id DESC LIMIT ?",
            (program_id, limit))]

    def add_stage(self, run_id, key, name, tool=""):
        cur = self.db.execute("""
            INSERT INTO stage(run_id, key, name, tool, status)
            VALUES(?,?,?,?,'pending')
        """, (run_id, key, name, tool))
        return cur.lastrowid

    def update_stage(self, stage_id, **fields):
        if not fields:
            return
        allowed = {"status", "started_at", "finished_at", "exit_code", "command",
                   "stage_key", "produced", "message", "log_path"}
        sets, values = [], []
        for key, value in fields.items():
            if key in allowed:
                sets.append(f"{key}=?")
                values.append(value)
        if not sets:
            return
        values.append(stage_id)
        self.db.execute(f"UPDATE stage SET {', '.join(sets)} WHERE id=?", values)

    def stages(self, run_id):
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM stage WHERE run_id=? ORDER BY id", (run_id,))]

    def completed_stage_key(self, program_id, stage_key):
        """Has this exact work been done before, for resume?

        The key is content-addressed over tool, flags, inputs and scope, so it
        invalidates the moment any of those change. A marker file keyed only on
        the stage name — which is what most frameworks use — happily skips work
        whose inputs are completely different.
        """
        row = self.db.execute("""
            SELECT s.* FROM stage s JOIN run r ON r.id = s.run_id
            WHERE r.program_id=? AND s.stage_key=? AND s.status='completed'
            ORDER BY s.id DESC LIMIT 1
        """, (program_id, stage_key)).fetchone()
        return dict(row) if row else None

    # ── assets ────────────────────────────────────────────────────────────

    def upsert_assets(self, program_id, run_id, kind, items):
        """Record a batch of assets and their sighting in this run.

        ``items`` are dicts with at least ``key``; optional ``data``,
        ``decision``, ``distance``, ``reason``, ``source``. Returns how many
        were seen for the first time, which is the number the UI shows as
        "new".
        """
        now = time.time()
        new_count = 0
        rows = []
        for item in items:
            key = (item.get("key") or "").strip()
            if not key:
                continue
            rows.append((
                program_id, kind, key, run_id, run_id, now, now,
                item.get("decision", "allow"),
                int(item.get("distance", 0) or 0),
                item.get("reason", ""),
                json.dumps(item.get("data") or {}),
                item.get("source", ""),
            ))
        if not rows:
            return 0

        self.db.execute("BEGIN")
        try:
            for row in rows:
                cur = self.db.execute("""
                    INSERT INTO asset(program_id, kind, key, first_seen_run,
                                      last_seen_run, first_seen_at, last_seen_at,
                                      scope_decision, scope_distance, scope_reason,
                                      data_json, source)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(program_id, kind, key) DO UPDATE SET
                        last_seen_run=excluded.last_seen_run,
                        last_seen_at=excluded.last_seen_at,
                        scope_decision=excluded.scope_decision,
                        scope_distance=excluded.scope_distance,
                        scope_reason=excluded.scope_reason,
                        data_json=json_patch(asset.data_json, excluded.data_json),
                        source=CASE WHEN asset.source='' THEN excluded.source
                                    ELSE asset.source END
                """, row)
                if cur.rowcount and cur.lastrowid:
                    asset_row = self.db.execute(
                        "SELECT id, first_seen_run FROM asset "
                        "WHERE program_id=? AND kind=? AND key=?",
                        (program_id, kind, row[2])).fetchone()
                    if asset_row:
                        if asset_row["first_seen_run"] == run_id:
                            new_count += 1
                        self.db.execute(
                            "INSERT OR IGNORE INTO observation(asset_id, run_id, seen_at) "
                            "VALUES(?,?,?)", (asset_row["id"], run_id, now))
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise
        return new_count

    def assets(self, program_id, kind=None, decision=None, search="",
               new_in_run=None, limit=500, offset=0, order="key"):
        where = ["program_id=?"]
        params = [program_id]
        if kind:
            where.append("kind=?")
            params.append(kind)
        if decision:
            where.append("scope_decision=?")
            params.append(decision)
        if search:
            where.append("(key LIKE ? OR data_json LIKE ?)")
            params += [f"%{search}%", f"%{search}%"]
        if new_in_run:
            where.append("first_seen_run=?")
            params.append(new_in_run)
        order_sql = {"key": "key", "new": "first_seen_run DESC, key",
                     "recent": "last_seen_at DESC"}.get(order, "key")
        params += [limit, offset]
        rows = self.db.execute(
            f"SELECT * FROM asset WHERE {' AND '.join(where)} "
            f"ORDER BY {order_sql} LIMIT ? OFFSET ?", params)
        out = []
        for row in rows:
            item = dict(row)
            try:
                item["data"] = json.loads(item.pop("data_json") or "{}")
            except Exception:
                item["data"] = {}
            out.append(item)
        return out

    def count_assets(self, program_id, kind=None, decision=None):
        where = ["program_id=?"]
        params = [program_id]
        if kind:
            where.append("kind=?")
            params.append(kind)
        if decision:
            where.append("scope_decision=?")
            params.append(decision)
        row = self.db.execute(
            f"SELECT COUNT(*) c FROM asset WHERE {' AND '.join(where)}", params
        ).fetchone()
        return row["c"] if row else 0

    def asset_kinds(self, program_id):
        return {r["kind"]: r["c"] for r in self.db.execute(
            "SELECT kind, COUNT(*) c FROM asset WHERE program_id=? GROUP BY kind",
            (program_id,))}

    def asset_keys(self, program_id, kind, decision="allow"):
        """Just the keys, for feeding the next stage."""
        return [r["key"] for r in self.db.execute(
            "SELECT key FROM asset WHERE program_id=? AND kind=? AND scope_decision=? "
            "ORDER BY key", (program_id, kind, decision))]

    # ── findings ──────────────────────────────────────────────────────────

    @staticmethod
    def fingerprint(tool, target, title, matcher=""):
        """Stable across runs: no body, no timestamp, no generated id."""
        from urllib.parse import urlsplit
        host = target
        path = ""
        if "://" in (target or ""):
            parts = urlsplit(target)
            host = parts.hostname or target
            path = (parts.path or "/").rstrip("/")
        payload = "|".join([tool or "", host or "", path, title or "", matcher or ""])
        return hashlib.sha256(payload.encode()).hexdigest()[:32]

    def record_finding(self, program_id, run_id, finding: dict):
        """Insert or update one finding, preserving whatever triage state the
        operator already gave it."""
        now = time.time()
        fp = finding.get("fingerprint") or self.fingerprint(
            finding.get("tool", ""), finding.get("target", ""),
            finding.get("title", ""), finding.get("matcher", ""))
        self.db.execute("""
            INSERT INTO finding(program_id, fingerprint, severity, title, category,
                                tool, target, detail, evidence, repro, confidence,
                                instances, first_seen_run, last_seen_run,
                                first_seen_at, last_seen_at, data_json)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,1,?,?,?,?,?)
            ON CONFLICT(program_id, fingerprint) DO UPDATE SET
                last_seen_run=excluded.last_seen_run,
                last_seen_at=excluded.last_seen_at,
                instances=finding.instances + 1,
                severity=excluded.severity,
                detail=excluded.detail,
                evidence=excluded.evidence,
                repro=excluded.repro
        """, (program_id, fp, (finding.get("severity") or "info").lower(),
              finding.get("title", ""), finding.get("category", ""),
              finding.get("tool", ""), finding.get("target", ""),
              finding.get("detail", ""), finding.get("evidence", ""),
              finding.get("repro", ""), finding.get("confidence", "firm"),
              run_id, run_id, now, now,
              json.dumps(finding.get("data") or {})))
        return fp

    def findings(self, program_id, severity=None, triage=None, search="",
                 new_in_run=None, limit=500, offset=0):
        where = ["program_id=?"]
        params = [program_id]
        if severity:
            where.append("severity=?")
            params.append(severity)
        if triage:
            where.append("triage=?")
            params.append(triage)
        if search:
            where.append("(title LIKE ? OR target LIKE ? OR detail LIKE ?)")
            params += [f"%{search}%"] * 3
        if new_in_run:
            where.append("first_seen_run=?")
            params.append(new_in_run)
        params += [limit, offset]
        rows = self.db.execute(
            f"SELECT * FROM finding WHERE {' AND '.join(where)} "
            f"ORDER BY CASE severity "
            f"  WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
            f"  WHEN 'low' THEN 3 ELSE 4 END, last_seen_at DESC LIMIT ? OFFSET ?",
            params)
        out = []
        for row in rows:
            item = dict(row)
            try:
                item["data"] = json.loads(item.pop("data_json") or "{}")
            except Exception:
                item["data"] = {}
            out.append(item)
        return out

    def finding_counts(self, program_id):
        counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
        for row in self.db.execute(
                "SELECT severity, COUNT(*) c FROM finding "
                "WHERE program_id=? AND triage != 'dismissed' GROUP BY severity",
                (program_id,)):
            counts[row["severity"]] = row["c"]
        return counts

    def set_triage(self, finding_id, triage, note=""):
        self.db.execute("UPDATE finding SET triage=?, triage_note=? WHERE id=?",
                        (triage, note, finding_id))

    # ── diffing ───────────────────────────────────────────────────────────

    def diff(self, program_id, run_id, baseline_run_id=None):
        """What changed, with the guard rails that make it trustworthy.

        The rule that matters: a stage which failed cannot be allowed to
        produce "disappeared" results. A crashed subfinder must never report
        four thousand subdomains removed, and a framework that lets it do so
        trains its user to ignore the diff entirely.
        """
        if baseline_run_id is None:
            row = self.db.execute(
                "SELECT id FROM run WHERE program_id=? AND id < ? "
                "AND status IN ('completed','partial') ORDER BY id DESC LIMIT 1",
                (program_id, run_id)).fetchone()
            baseline_run_id = row["id"] if row else None

        new_rows = [dict(r) for r in self.db.execute(
            "SELECT kind, key, data_json, first_seen_at FROM asset "
            "WHERE program_id=? AND first_seen_run=? ORDER BY kind, key",
            (program_id, run_id))]

        gone_rows = []
        if baseline_run_id:
            failed = {r["name"] for r in self.db.execute(
                "SELECT name FROM stage WHERE run_id=? AND status!='completed'",
                (run_id,))}
            gone_rows = [dict(r) for r in self.db.execute("""
                SELECT a.kind, a.key, a.last_seen_at FROM asset a
                WHERE a.program_id=?
                  AND EXISTS (SELECT 1 FROM observation o
                               WHERE o.asset_id=a.id AND o.run_id=?)
                  AND NOT EXISTS (SELECT 1 FROM observation o
                               WHERE o.asset_id=a.id AND o.run_id=?)
                ORDER BY a.kind, a.key
            """, (program_id, baseline_run_id, run_id))]
        else:
            failed = set()

        new_findings = [dict(r) for r in self.db.execute(
            "SELECT id, severity, title, target FROM finding "
            "WHERE program_id=? AND first_seen_run=? "
            "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END",
            (program_id, run_id))]

        return {
            "run_id": run_id,
            "baseline_run_id": baseline_run_id,
            "new_assets": new_rows,
            "gone_assets": gone_rows,
            "new_findings": new_findings,
            "unreliable": sorted(failed),
            "caveat": ("Some stages did not complete in this run, so "
                       "'disappeared' is not trustworthy for the asset kinds "
                       "they produce." if failed else ""),
        }

    # ── misc ──────────────────────────────────────────────────────────────

    def stats(self, program_id):
        kinds = self.asset_kinds(program_id)
        return {
            "assets": kinds,
            "total_assets": sum(kinds.values()),
            "findings": self.finding_counts(program_id),
            "runs": self.db.execute(
                "SELECT COUNT(*) c FROM run WHERE program_id=?",
                (program_id,)).fetchone()["c"],
        }


def _json_patch(base, patch):
    """Shallow merge for the ON CONFLICT path, registered as a SQL function.

    A later stage adds fields to an asset (httpx adds a title and a status to
    a host subfinder found); it must not wipe what an earlier stage recorded.
    """
    try:
        merged = json.loads(base or "{}")
    except Exception:
        merged = {}
    try:
        incoming = json.loads(patch or "{}")
    except Exception:
        incoming = {}
    if isinstance(merged, dict) and isinstance(incoming, dict):
        merged.update({k: v for k, v in incoming.items() if v not in (None, "", [], {})})
        return json.dumps(merged)
    return patch or base or "{}"


_original_init = Store.__init__


def _init_with_functions(self, path):
    _original_init(self, path)
    self.db.create_function("json_patch", 2, _json_patch)


Store.__init__ = _init_with_functions
