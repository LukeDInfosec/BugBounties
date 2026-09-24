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


async def _latest_from_git():
    """The published VERSION, read through the checkout's own remote.

    Returns (version, error). This is the path that works for a private
    repository: whatever credentials `git pull` uses, this uses."""
    code, out = await _git("fetch", "--quiet", "--tags", "origin", "main")
    if code != 0:
        return None, out or "git fetch failed"
    code, out = await _git("show", "origin/main:VERSION")
    if code == 0 and out.strip():
        return out.strip().splitlines()[0].strip(), ""
    return None, out or "origin/main has no VERSION file"


async def _latest_from_raw():
    """The published VERSION over anonymous HTTPS. Public repositories only."""
    def _fetch():
        req = urllib.request.Request(
            RAW_VERSION, headers={"User-Agent": "bbhunter-updater"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode().strip()
    try:
        return await asyncio.get_running_loop().run_in_executor(None, _fetch), ""
    except Exception as exc:
        return None, str(exc)


def _lookup_failed(git_err, http_err):
    """Say which of the two ways failed, and what to do about it."""
    private = "404" in (http_err or "")
    lines = ["Could not work out the published version."]
    if private:
        lines.append(
            f"github.com/{REPO} answers 404 to an anonymous request, which "
            f"normally means the repository is private — that is fine, but it "
            f"means the version can only be read through your own git remote.")
    lines.append(f"git said: {(git_err or 'nothing').strip()[:300]}")
    lines.append(f"https said: {(http_err or 'nothing').strip()[:200]}")
    lines.append(
        "Check that the remote works from a terminal:  git -C "
        f"{install_root()} fetch origin main   — if that asks for a password, "
        "set the remote to SSH or run `gh auth login`. `git pull` still "
        "updates you either way.")
    return "\n\n".join(lines)


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

    # Ask git first. It uses the checkout's own remote and credentials, so a
    # private repository over SSH works exactly as a public one does. The
    # anonymous raw.githubusercontent.com URL is only a fallback, and for a
    # private repository it answers 404 — which is what "Could not reach
    # GitHub: 404" used to mean, unhelpfully.
    latest, git_err = await _latest_from_git()
    if latest:
        info["latest"] = latest
    else:
        latest, http_err = await _latest_from_raw()
        if latest:
            info["latest"] = latest
        else:
            info["message"] = info["message"] or _lookup_failed(git_err, http_err)
            return info

    # The version number is a poor question to ask. A fortnight of fixes can
    # land without VERSION changing, and "you are on the latest version" while
    # sitting eight commits behind is worse than saying nothing. What matters
    # is whether the remote branch has commits this checkout does not.
    info["behind"] = await _commits_behind()
    info["update_available"] = bool(
        not info["dirty"]
        and (info["behind"] > 0
             or (info["latest"] and info["latest"] != current)))

    if info["update_available"]:
        code, log = await _git("log", "--oneline", "-15", "HEAD..origin/main")
        info["changes"] = log if code == 0 else ""
        if info["behind"] and info["latest"] == current:
            info["message"] = info["message"] or (
                f"{info['behind']} commit(s) behind, with the version number "
                f"unchanged at {current}. Fixes do not always come with a new "
                f"version; the commits below are what you are missing.")
    elif not info["dirty"] and info["behind"] == 0:
        info["message"] = info["message"] or "Up to date with origin/main."
    return info


async def _commits_behind() -> int:
    """How many commits origin/main has that this checkout does not.

    `_latest_from_git` has already fetched, so this reads what was just
    brought down rather than going to the network again. Returns 0 when the
    answer cannot be worked out — never a guess that invents an update.
    """
    code, out = await _git("rev-list", "--count", "HEAD..origin/main")
    if code != 0:
        return 0
    try:
        return int(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return 0


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
