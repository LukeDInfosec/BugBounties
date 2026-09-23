#!/usr/bin/env python3
"""The updater's idea of 'you have local changes'.

The install instructions tell you to `chmod +x bbf install.sh`, because a
repository populated through GitHub's web upload does not carry the executable
bit. If the updater counted that as a local modification it would refuse to
update a checkout that is, in fact, untouched — which is exactly what happened
before these tests existed.
"""

import asyncio
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bbhunter import updater  # noqa: E402

PASS = FAIL = 0


def check(label, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  \033[32m✓\033[0m {label}")
    else:
        FAIL += 1
        print(f"  \033[31m✗\033[0m {label}  (got {got!r}, wanted {want!r})")


def git(*args, cwd):
    return subprocess.run(
        ["git", *args], cwd=str(cwd), check=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
             "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"})


def build_checkout(root: Path) -> Path:
    """An origin and a clone of it, with bbf committed non-executable."""
    origin, work = root / "origin", root / "work"
    origin.mkdir()
    git("init", "--bare", "-b", "main", cwd=origin)
    seed = root / "seed"
    seed.mkdir()
    git("init", "-b", "main", cwd=seed)
    (seed / "bbf").write_text("#!/usr/bin/env bash\necho hi\n")
    (seed / "install.sh").write_text("#!/usr/bin/env bash\necho install\n")
    (seed / "VERSION").write_text("0.1.0\n")
    git("add", "-A", cwd=seed)
    git("-c", "core.fileMode=false", "commit", "-m", "seed", cwd=seed)
    git("remote", "add", "origin", str(origin), cwd=seed)
    git("push", "-u", "origin", "main", cwd=seed)
    git("clone", str(origin), str(work), cwd=root)
    return work


def main():
    if not subprocess.run(["git", "--version"], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0:
        print("git is not installed; skipping")
        return 0

    with tempfile.TemporaryDirectory() as tmp:
        work = build_checkout(Path(tmp))
        updater.install_root = lambda: work          # point the updater at it

        print("\n\033[1mA clean checkout\033[0m")
        info = asyncio.run(updater.check())
        check("is recognised as a git checkout", info["git"])
        check("is not dirty", info["dirty"], False)

        print("\n\033[1mAfter the chmod the install instructions ask for\033[0m")
        for name in ("bbf", "install.sh"):
            path = work / name
            path.chmod(path.stat().st_mode | 0o111)
        raw = subprocess.run(["git", "status", "--porcelain"], cwd=str(work),
                             stdout=subprocess.PIPE, text=True).stdout
        check("plain git does see the mode change", bool(raw.strip()))
        info = asyncio.run(updater.check())
        check("the updater does not call that a local change", info["dirty"], False)
        check("and says nothing about local changes",
              "local changes" in (info["message"] or ""), False)

        print("\n\033[1mA real edit is still protected\033[0m")
        (work / "bbf").write_text("#!/usr/bin/env bash\necho edited\n")
        info = asyncio.run(updater.check())
        check("an edited file makes it dirty", info["dirty"])
        check("and the message explains why",
              "local changes" in (info["message"] or ""))

        print("\n\033[1mReading the published version when GitHub is "
              "unreachable anonymously\033[0m")
        # A private repository answers 404 to raw.githubusercontent.com. Point
        # the HTTPS fallback at something that cannot work, so the only way to
        # learn the published version is through the checkout's own remote —
        # which is exactly the situation a private repo puts you in.
        updater.RAW_VERSION = "http://127.0.0.1:1/VERSION"
        git("checkout", "-q", "main", cwd=work)
        (work / "bbf").write_text("#!/usr/bin/env bash\necho hi\n")   # undo the edit
        seed = Path(tmp) / "seed"
        (seed / "VERSION").write_text("0.9.9\n")
        git("add", "-A", cwd=seed)
        git("-c", "core.fileMode=false", "commit", "-m", "bump", cwd=seed)
        git("push", "origin", "main", cwd=seed)

        info = asyncio.run(updater.check())
        check("the published version comes from git", info["latest"], "0.9.9")
        check("an update is offered", info["update_available"])
        check("no 'could not reach GitHub'",
              "Could not" in (info["message"] or ""), False)

        print("\n\033[1mWhen neither way works\033[0m")
        git("remote", "set-url", "origin", str(Path(tmp) / "gone"), cwd=work)
        info = asyncio.run(updater.check())
        check("it does not claim an update", info["update_available"], False)
        check("it names both ways it tried",
              "git said" in (info["message"] or "")
              and "https said" in (info["message"] or ""))
        check("and gives a command to test the remote",
              "git -C" in (info["message"] or ""))

        print("\n\033[1mA 404 over HTTPS is read as 'probably private'\033[0m")
        # This is the case Luke hit: the repo is private, so anonymous HTTPS
        # answers 404. That must not be reported as "could not reach GitHub".
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading

        class NotFound(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

        srv = ThreadingHTTPServer(("127.0.0.1", 0), NotFound)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        updater.RAW_VERSION = f"http://127.0.0.1:{srv.server_address[1]}/VERSION"
        info = asyncio.run(updater.check())
        srv.shutdown()
        check("it says the repository may be private",
              "private" in (info["message"] or "").lower())
        check("it does not say 'could not reach GitHub'",
              "Could not reach GitHub" in (info["message"] or ""), False)

        print("\n\033[1mA copy that is not a checkout at all\033[0m")
        plain = Path(tmp) / "zip"
        plain.mkdir()
        updater.install_root = lambda: plain
        info = asyncio.run(updater.check())
        check("is reported as not a git checkout", info["git"], False)
        check("and is told how to convert it in place",
              "git remote add origin" in (info["message"] or ""))
        check("without being told to download it again",
              "git clone" in (info["message"] or ""), False)

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
