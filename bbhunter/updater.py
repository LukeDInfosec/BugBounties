#!/usr/bin/env python3
"""Self-update from the GitHub repository.

Deliberately conservative. An update is a `git pull` into the checkout the
framework is running from, and it refuses to run if there are local
modifications, because silently discarding somebody's edits to their own
tooling is unforgivable. The engagement database lives outside the checkout,
so an update never touches results.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import urllib.request
from pathlib import Path

REPO = "LukeDInfosec/BugBounties"
RAW_VERSION = f"https://raw.githubusercontent.com/{REPO}/main/VERSION"


def install_root() -> Path:
    return Path(__file__).resolve().parent.parent


def is_git_checkout() -> bool:
    return (install_root() / ".git").exists()


async def _git(*args, cwd=None):
    # core.fileMode=false for every call: the install instructions tell you to
    # `chmod +x bbf install.sh` (GitHub's web upload does not carry the
    # executable bit), and without this git reports those two files as locally
    # modified and the updater refuses to run. A permission bit is not an edit
    # worth protecting; a changed line is, and those are still caught.
    proc = await asyncio.create_subprocess_exec(
        "git", "-c", "core.fileMode=false", *args, cwd=str(cwd or install_root()),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        stdin=asyncio.subprocess.DEVNULL)
    out, _ = await proc.communicate()
    return proc.returncode, (out or b"").decode("utf-8", "replace").strip()


async def check() -> dict:
    """Is there a newer version? Never changes anything."""
    from .config import version as local_version

    current = local_version()
    info = {"current": current, "latest": "", "update_available": False,
            "git": is_git_checkout(), "dirty": False, "message": ""}

    if not shutil.which("git"):
        info["message"] = "git is not installed, so the Update button cannot work."
        return info
    if not info["git"]:
        info["message"] = (
            "This copy was not cloned from git (it looks like a downloaded "
            "zip), so it cannot update itself. You do not have to download it "
            "again — turn this folder into a checkout in place:\n\n"
            f"    cd {install_root()}\n"
            f"    git init\n"
            f"    git remote add origin https://github.com/{REPO}.git\n"
            f"    git fetch origin\n"
            f"    git reset --hard origin/main     # discards local edits\n"
            f"    git branch --set-upstream-to=origin/main main\n\n"
            "Your database, settings and results live outside the checkout, so "
            "none of that is touched. If the repository is private, clone over "
            "SSH or sign in with `gh auth login` first — GitHub no longer "
            "accepts a password over HTTPS.")
        return info

    code, out = await _git("status", "--porcelain")
    if code == 0 and out.strip():
        info["dirty"] = True
        info["message"] = ("You have local changes in the checkout. Updating "
                           "would overwrite them, so it is blocked. Commit or "
                           "stash them first.\n\n" + out[:600])

    try:
        def _fetch():
            req = urllib.request.Request(
                RAW_VERSION, headers={"User-Agent": "bbhunter-updater"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.read().decode().strip()
        info["latest"] = await asyncio.get_running_loop().run_in_executor(None, _fetch)
    except Exception as exc:
        info["message"] = info["message"] or f"Could not reach GitHub: {exc}"
        return info

    info["update_available"] = bool(
        info["latest"] and info["latest"] != current and not info["dirty"])
    if info["update_available"]:
        code, log = await _git("log", "--oneline", "-15", f"HEAD..origin/main")
        info["changes"] = log if code == 0 else ""
    return info


async def apply() -> dict:
    """Pull the latest code. Results and configuration are untouched."""
    result = {"ok": False, "output": "", "restart_required": True}
    if not is_git_checkout():
        result["output"] = "Not a git checkout — cannot update in place."
        return result

    code, status = await _git("status", "--porcelain")
    if code == 0 and status.strip():
        result["output"] = ("Refusing to update: the checkout has local "
                            "modifications that a pull would overwrite.\n" + status)
        return result

    code, fetch_out = await _git("fetch", "--all", "--tags")
    code2, pull_out = await _git("pull", "--ff-only", "origin", "main")
    result["output"] = (fetch_out + "\n" + pull_out).strip()
    result["ok"] = code2 == 0
    if not result["ok"]:
        result["output"] += ("\n\nA fast-forward pull failed. That usually means "
                             "the local branch has diverged; `git log --oneline "
                             "origin/main..HEAD` will show how.")
        return result

    requirements = install_root() / "requirements.txt"
    if requirements.exists():
        proc = await asyncio.create_subprocess_exec(
            "python3", "-m", "pip", "install", "-q", "--break-system-packages",
            "-r", str(requirements),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            stdin=asyncio.subprocess.DEVNULL)
        out, _ = await proc.communicate()
        result["output"] += "\n\n" + (out or b"").decode("utf-8", "replace")[-1500:]
    return result
