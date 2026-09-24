#!/usr/bin/env python3
"""Does each tool actually work?

`bbhunter --doctor` answers a different question from the Tools page. That page
says whether a binary of the right name exists and prints its version. This
runs each one for real and checks that it produces the output the pipeline
expects, because the ways these tools fail are not the ways a version check
notices:

  * httpx is installed and prints a version, but its screenshot mode needs a
    browser it cannot download.
  * nuclei is installed with no templates, so every scan finds nothing.
  * subfinder is installed with no API keys, so it returns a handful of names
    where it should return thousands.
  * a binary of the right name is the wrong tool entirely.

Most checks run against a throwaway HTTP server this process starts on
127.0.0.1, so nothing is sent to anybody. The few that cannot be tested that
way — DNS resolution, passive sources — are marked, and the ones that need the
internet are only run when you pass --doctor-online.
"""

from __future__ import annotations

import asyncio
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

from .tools import TOOLS, ToolRegistry

OK, WARN, FAIL, SKIP = "ok", "warn", "fail", "skip"

PAGE = (b"<html><head><title>bbhunter doctor</title></head><body>"
        b"<h1>Local target</h1><a href='/admin?id=1&next=/x'>link</a>"
        b"<script src='/app.js'></script></body></html>")
SCRIPT = b"const API_BASE='/api/v1';fetch(API_BASE+'/users');\n"


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        body = SCRIPT if self.path.startswith("/app.js") else PAGE
        kind = "application/javascript" if self.path.startswith("/app.js") \
            else "text/html"
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "bbhunter-doctor")
        self.end_headers()
        self.wfile.write(body)

    do_HEAD = do_GET


async def _run(argv, timeout=60, stdin_data=None, cwd=None):
    """Run a command, returning (code, text). Never raises for a bad exit."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            stdin=asyncio.subprocess.PIPE if stdin_data else
            asyncio.subprocess.DEVNULL,
            cwd=str(cwd) if cwd else None, start_new_session=True)
    except (FileNotFoundError, PermissionError) as exc:
        return 127, str(exc)
    try:
        out, _ = await asyncio.wait_for(
            proc.communicate(stdin_data.encode() if stdin_data else None),
            timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return 124, f"timed out after {timeout}s"
    return proc.returncode, (out or b"").decode("utf-8", "replace")


class Doctor:
    """One check per tool, run against a local target where possible."""

    def __init__(self, registry, url, online=False, chrome=""):
        self.registry = registry
        self.url = url
        self.host = url.split("//", 1)[1]
        self.online = online
        self.chrome = chrome

    def path(self, key):
        return (self.registry.state.get(key) or {}).get("path", "")

    def installed(self, key):
        return bool((self.registry.state.get(key) or {}).get("installed"))

    # ── individual checks ────────────────────────────────────────────────
    # Each returns (status, detail). They are deliberately small: the point is
    # to prove the tool emits what the stage that uses it will try to parse.

    async def check_httpx(self, tmp):
        code, out = await _run([self.path("httpx"), "-u", self.url, "-silent",
                                "-json", "-sc", "-title", "-nc"], timeout=60)
        if '"status_code"' not in out:
            return FAIL, f"probing a local page produced no JSON (exit {code})"
        if "bbhunter doctor" not in out:
            return WARN, "probed, but did not report the page title"
        return OK, "probes and parses JSON"

    async def check_httpx_screenshot(self, tmp):
        shots = tmp / "shots"
        argv = [self.path("httpx"), "-u", self.url, "-ss", "-silent",
                "-esb", "-ehb", "-srd", str(shots), "-screenshot-timeout", "25"]
        if self.chrome:
            argv.insert(2, "-system-chrome")
        code, out = await _run(argv, timeout=120)
        images = list(shots.rglob("*.png")) if shots.exists() else []
        if images:
            return OK, f"captured {len(images)} image(s)"
        if "browser binary" in out or "chrome" in out.lower():
            return FAIL, ("no browser it can drive — sudo apt install -y "
                          "chromium")
        return FAIL, f"no image produced (exit {code})"

    async def check_dnsx(self, tmp):
        if not self.online:
            return SKIP, "needs DNS; run with --doctor-online"
        code, out = await _run([self.path("dnsx"), "-silent", "-a", "-resp",
                                "-json"], stdin_data="one.one.one.one\n",
                               timeout=45)
        if '"a"' in out or "1.1.1.1" in out:
            return OK, "resolves and emits JSON"
        return FAIL, f"resolved nothing (exit {code}) — check your resolvers"

    async def check_subfinder(self, tmp):
        code, out = await _run([self.path("subfinder"), "-ls"], timeout=45)
        sources = [l for l in out.splitlines() if l.strip()]
        if code != 0 or not sources:
            return FAIL, f"could not list its sources (exit {code})"
        config = Path.home() / ".config" / "subfinder" / "provider-config.yaml"
        keyed = config.is_file() and config.stat().st_size > 40
        if not keyed:
            return WARN, (f"{len(sources)} sources, but no API keys in "
                          f"{config} — free sources only, which finds a "
                          f"fraction of what keyed ones do")
        return OK, f"{len(sources)} sources, API keys present"

    async def check_nuclei(self, tmp):
        code, out = await _run([self.path("nuclei"), "-tl", "-silent"],
                               timeout=90)
        templates = [l for l in out.splitlines() if l.strip().endswith(".yaml")]
        if not templates:
            return FAIL, ("no templates installed — run `nuclei -update-"
                          "templates`; without them every scan finds nothing")
        code, out = await _run([self.path("nuclei"), "-u", self.url,
                                "-t", "http/miscellaneous/", "-silent",
                                "-jsonl", "-no-interactsh", "-duc"],
                               timeout=180)
        if code not in (0, 1):
            return WARN, f"{len(templates)} templates, but a scan exited {code}"
        return OK, f"{len(templates)} templates, scan ran"

    async def check_katana(self, tmp):
        code, out = await _run([self.path("katana"), "-u", self.url, "-silent",
                                "-d", "2", "-jc"], timeout=90)
        if self.host not in out:
            return FAIL, f"crawled nothing from a local page (exit {code})"
        if "app.js" not in out:
            return WARN, "crawled, but did not pick up the linked script"
        return OK, "crawls and follows script tags"

    async def check_naabu(self, tmp):
        port = self.host.rsplit(":", 1)[-1]
        code, out = await _run([self.path("naabu"), "-host", "127.0.0.1",
                                "-p", port, "-silent"], timeout=90)
        if port in out:
            return OK, "finds an open port"
        if "permission" in out.lower() or code == 1:
            return WARN, ("could not scan — naabu usually needs root or "
                          "CAP_NET_RAW (`sudo setcap cap_net_raw+eip $(which "
                          "naabu)`)")
        return FAIL, f"found nothing on a port that is open (exit {code})"

    async def check_gowitness(self, tmp):
        shots = tmp / "gw"
        shots.mkdir(exist_ok=True)
        argv = [self.path("gowitness"), "scan", "single", "-u", self.url,
                "--screenshot-path", str(shots), "--disable-db"]
        if self.chrome:
            argv += ["--chrome-path", self.chrome]
        code, out = await _run(argv, timeout=120)
        if list(shots.rglob("*.png")):
            return OK, "captured an image"
        return FAIL, f"no image produced (exit {code})"

    async def check_subjs(self, tmp):
        code, out = await _run([self.path("subjs")], stdin_data=self.url + "\n",
                               timeout=45)
        if "app.js" in out:
            return OK, "extracts script URLs"
        return WARN, f"found no script on a page that has one (exit {code})"

    async def check_ffuf(self, tmp):
        words = tmp / "words.txt"
        words.write_text("admin\nnope\n")
        code, out = await _run([self.path("ffuf"), "-u", self.url + "/FUZZ",
                                "-w", str(words), "-s", "-mc", "200"],
                               timeout=60)
        if code == 0:
            return OK, "fuzzes a local path list"
        return FAIL, f"exited {code}"

    async def check_dalfox(self, tmp):
        code, out = await _run([self.path("dalfox"), "url",
                                self.url + "/admin?id=1", "--silence",
                                "--no-color", "--skip-bav"], timeout=90)
        if code in (0, 1):
            return OK, "runs against a parameterised URL"
        return FAIL, f"exited {code}"

    async def check_chromium(self, tmp):
        out_file = tmp / "chrome.png"
        code, out = await _run([self.chrome or self.path("chromium"),
                                "--headless=new", "--disable-gpu", "--no-sandbox",
                                "--disable-dev-shm-usage",
                                "--virtual-time-budget=4000",
                                f"--screenshot={out_file}", self.url],
                               timeout=90)
        if out_file.is_file() and out_file.stat().st_size > 500:
            return OK, "captures a page headlessly"
        return FAIL, f"produced no image (exit {code})"

    async def check_generic_stdin(self, key, tmp):
        """Tools that read hosts on stdin and hit the internet to answer."""
        if not self.online:
            return SKIP, "needs the internet; run with --doctor-online"
        code, out = await _run([self.path(key)], stdin_data="example.com\n",
                               timeout=60)
        if code == 0:
            return OK, "ran and exited cleanly"
        return WARN, f"exited {code}"


CHECKS = {
    "httpx": "check_httpx",
    "dnsx": "check_dnsx",
    "subfinder": "check_subfinder",
    "nuclei": "check_nuclei",
    "katana": "check_katana",
    "naabu": "check_naabu",
    "gowitness": "check_gowitness",
    "subjs": "check_subjs",
    "ffuf": "check_ffuf",
    "dalfox": "check_dalfox",
    "chromium": "check_chromium",
}
#: Tools that only prove themselves against the internet.
ONLINE_STDIN = ("waybackurls", "gau", "assetfinder", "github-subdomains")


async def run_doctor(online=False, only=None):
    """Returns (rows, summary). Each row is a dict the CLI prints."""
    registry = ToolRegistry()
    await registry.detect()

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}"

    from .pipeline import ScreenshotStage
    chrome = ScreenshotStage._find_chrome()

    rows = []
    try:
        with TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            doctor = Doctor(registry, url, online=online, chrome=chrome)

            keys = list(only) if only else list(TOOLS.keys())
            for key in keys:
                tool = TOOLS.get(key)
                if not tool:
                    continue
                state = registry.state.get(key, {})
                row = {"key": key, "purpose": tool.purpose,
                       "optional": tool.optional,
                       "version": state.get("version", ""),
                       "path": state.get("path", "")}
                if state.get("wrong_tool"):
                    row.update(status=FAIL,
                               detail=f"a different tool is at {row['path']}. "
                                      f"{tool.wrong_tool_hint}")
                elif not state.get("installed"):
                    row.update(status=SKIP if tool.optional else FAIL,
                               detail=f"not installed — {tool.install}")
                else:
                    name = CHECKS.get(key)
                    try:
                        if name:
                            status, detail = await getattr(doctor, name)(tmp)
                        elif key in ONLINE_STDIN:
                            status, detail = await doctor.check_generic_stdin(
                                key, tmp)
                        else:
                            status, detail = WARN, "version only; not exercised"
                    except Exception as exc:                # noqa: BLE001
                        status, detail = FAIL, f"the check itself failed: {exc}"
                    row.update(status=status, detail=detail)
                rows.append(row)

                # The screenshot path is a separate question from probing.
                if key == "httpx" and state.get("installed"):
                    try:
                        status, detail = await doctor.check_httpx_screenshot(tmp)
                    except Exception as exc:                # noqa: BLE001
                        status, detail = FAIL, str(exc)
                    rows.append({"key": "httpx (screenshots)",
                                 "purpose": "Capturing pages for the gallery",
                                 "optional": True, "version": "", "path": "",
                                 "status": status, "detail": detail})
    finally:
        server.shutdown()

    summary = {s: sum(1 for r in rows if r["status"] == s)
               for s in (OK, WARN, FAIL, SKIP)}
    summary["chrome"] = chrome or ""
    return rows, summary


def print_report(rows, summary, online):
    bold, dim, reset = "\033[1m", "\033[2m", "\033[0m"
    colour = {OK: "\033[32m", WARN: "\033[33m", FAIL: "\033[31m",
              SKIP: "\033[2m"}
    mark = {OK: "✓", WARN: "!", FAIL: "✗", SKIP: "·"}

    print(f"\n{bold}Tool doctor{reset}")
    print(f"{dim}Each installed tool was run for real against a throwaway "
          f"server on 127.0.0.1.{reset}")
    if not online:
        print(f"{dim}Checks needing DNS or the internet were skipped; add "
              f"--doctor-online to include them.{reset}")
    print(f"{dim}Browser found: {summary.get('chrome') or 'none'}{reset}\n")

    for row in rows:
        status = row["status"]
        required = "" if row["optional"] else f" {dim}(required){reset}"
        print(f"  {colour[status]}{mark[status]}{reset} "
              f"{row['key']:<20}{required} {row['detail']}")

    print()
    print(f"  {colour[OK]}{summary[OK]} working{reset}   "
          f"{colour[WARN]}{summary[WARN]} with caveats{reset}   "
          f"{colour[FAIL]}{summary[FAIL]} broken{reset}   "
          f"{dim}{summary[SKIP]} not installed or not checked{reset}")
    return 1 if summary[FAIL] else 0
