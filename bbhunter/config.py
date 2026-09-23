#!/usr/bin/env python3
"""Paths, defaults and the settings that persist between sessions."""

from __future__ import annotations

import json
import os
from pathlib import Path

APP_NAME = "bbhunter"


def data_dir() -> Path:
    override = os.environ.get("BBHUNTER_HOME")
    if override:
        path = Path(override).expanduser()
    else:
        path = Path(os.environ.get("XDG_DATA_HOME",
                                   Path.home() / ".local" / "share")) / APP_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def config_path() -> Path:
    return data_dir() / "config.json"


def db_path() -> Path:
    return data_dir() / "engagement.db"


def version() -> str:
    for candidate in (Path(__file__).resolve().parent.parent / "VERSION",):
        try:
            return candidate.read_text().strip()
        except Exception:
            continue
    return "0.0.0"


#: Conservative by default. Every one of these can be raised in the UI, but a
#: framework whose defaults get its user banned is not a useful framework.
DEFAULTS = {
    "per_host_rps": 5,
    "global_rps": 20,
    "per_host_concurrency": 10,
    "user_agent": "",
    "headers": {},
    "handle": "",
    "nuclei_severity": "critical,high,medium,low",
    "exclude_intrusive": True,
    "crawl_depth": 3,
    "top_ports": 1000,
    "port_rate": 500,
    "stage_timeout": 3600,
    "dast_url_cap": 2000,
    "xss_url_cap": 500,
    "permutation_limit": 100000,
    "api_keys": {},
    "theme": "dark",
}


def load_config() -> dict:
    config = dict(DEFAULTS)
    try:
        stored = json.loads(config_path().read_text())
        if isinstance(stored, dict):
            config.update(stored)
    except Exception:
        pass
    return config


def save_config(config: dict):
    merged = load_config()
    merged.update(config or {})
    config_path().write_text(json.dumps(merged, indent=2))
    return merged


def identification_headers(handle: str, extra: dict = None) -> dict:
    """The headers that tell a target who is scanning them.

    Most programmes ask for this and several require it. It costs nothing and
    it is the difference between a blue team filing an incident and a blue
    team seeing a known researcher.
    """
    headers = {}
    handle = (handle or "").strip()
    if handle:
        headers["X-Bug-Bounty"] = handle
        headers["X-Bug-Bounty-Researcher"] = handle
    headers.update({k: v for k, v in (extra or {}).items() if k and v})
    return headers
