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


def _free_port(preferred=8777):
    for port in (preferred, 0):
        with socket.socket() as sock:
            try:
                sock.bind(("127.0.0.1", port))
                return sock.getsockname()[1]
            except OSError:
                continue
    return 8777


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="bbhunter",
        description="Bug bounty reconnaissance with scope enforced at the socket.")
    parser.add_argument("--port", type=int, default=8777)
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

    port = args.port if args.port else _free_port()
    url = f"http://{args.host}:{port}"
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
