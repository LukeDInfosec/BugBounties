#!/usr/bin/env python3
"""Entry point: start the server, open the interface, get out of the way."""

import argparse
import asyncio
import os
import socket
import sys
import threading
import webbrowser

from . import config as cfg


DEFAULT_PORT = 8777


def _port_free(host, port):
    """True if this process could bind there right now."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


def _next_free_port(host, start=DEFAULT_PORT, tries=20):
    """The first free port at or after `start`, else one the OS picks."""
    for port in range(start, start + tries):
        if _port_free(host, port):
            return port
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def _bbhunter_on(host, port, timeout=1.5):
    """Is the thing already holding this port another copy of bbhunter?

    Answering this is what turns 'address already in use' into a sentence the
    person can act on: their own interface is usually already open."""
    import json
    import urllib.request
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    shown = f"[{host}]" if ":" in host else host
    try:
        with opener.open(f"http://{shown}:{port}/api/meta", timeout=timeout) as r:
            return "version" in json.loads(r.read())
    except Exception:
        return False


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="bbhunter",
        description="Bug bounty reconnaissance with scope enforced at the socket.")
    parser.add_argument("--port", type=int, default=None,
                        help=f"Default {DEFAULT_PORT}. If that one is taken the "
                             f"next free port is used; an explicit --port is "
                             f"never silently moved.")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Only change this if you understand that this "
                             "process can start scans and holds your API keys.")
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--scope-check", nargs=2, metavar=("PROGRAMME", "ASSET"),
                        help="Print the scope decision for one asset and exit.")
    args = parser.parse_args(argv)

    if args.version:
        print(f"bbhunter {cfg.version()}")
        return 0

    if args.scope_check:
        return _scope_check(*args.scope_check)

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(f"[!] Binding to {args.host} exposes an interface that can start "
              f"scans and holds your API keys. Continue only if that host is "
              f"genuinely private.", file=sys.stderr)

    try:
        import uvicorn
    except ImportError:
        print("uvicorn is not installed. Run:  pip install -r requirements.txt "
              "--break-system-packages", file=sys.stderr)
        return 1

    from .server import create_app

    # Resolve the port BEFORE printing anything, so the banner never advertises
    # a URL that was never going to work.
    asked = args.port
    port = asked if asked is not None else DEFAULT_PORT
    if not _port_free(args.host, port):
        shown = f"[{args.host}]" if ":" in args.host else args.host
        busy = f"http://{shown}:{port}"
        if _bbhunter_on(args.host, port):
            print(f"\n  bbhunter is already running at {busy}\n\n"
                  f"  Open that, or stop the other copy first "
                  f"(pkill -f 'python3 -m bbhunter'). To run a second copy "
                  f"alongside it, pass a different --port.\n", file=sys.stderr)
            if not args.no_browser:
                webbrowser.open(busy)
            return 3
        if asked is not None:
            print(f"\n  Port {port} is already in use by something else, and "
                  f"you asked for it explicitly, so nothing was started.\n\n"
                  f"  See what holds it:  ss -ltnp | grep {port}\n"
                  f"  Or let bbhunter choose:  bbf\n", file=sys.stderr)
            return 3
        port = _next_free_port(args.host, DEFAULT_PORT)
        print(f"[i] Port {DEFAULT_PORT} is in use by something else; "
              f"using {port} instead.", file=sys.stderr)

    shown = f"[{args.host}]" if ":" in args.host else args.host
    url = f"http://{shown}:{port}"
    print(f"""
  bbhunter {cfg.version()}
  interface   {url}
  data        {cfg.data_dir()}

  Scope is enforced at the socket, not filtered from a list: every tool runs
  behind a local gate that re-checks the rules on each connection.
""")
    if not args.no_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()

    app = create_app()
    uvicorn.run(app, host=args.host, port=port, log_level="warning",
                access_log=False)
    return 0


def _scope_check(program_name, asset):
    """`bbhunter --scope-check Acme api.acme.com` — trust is built on this."""
    from .store import Store
    from .engine import _scope_from_program

    store = Store(cfg.db_path())
    program = store.program_by_name(program_name)
    if not program:
        names = ", ".join(p["name"] for p in store.programs()) or "none"
        print(f"No programme called {program_name!r}. Known: {names}", file=sys.stderr)
        return 2
    scope = _scope_from_program(program)
    print(scope.explain(asset))
    return 0 if scope.classify(asset).allowed else 1


if __name__ == "__main__":
    sys.exit(main())
