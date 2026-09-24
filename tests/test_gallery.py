#!/usr/bin/env python3
"""Filtering the gallery.

A gallery of four hundred cards is a wall, not a triage tool. The point of the
filters is that "show me the 401s" and "hide the 404s" are one click, and that
the count on each chip is the truth about the whole programme rather than
about the page currently rendered.
"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PASS = FAIL = 0


def check(label, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  \033[32m✓\033[0m {label}")
    else:
        FAIL += 1
        print(f"  \033[31m✗\033[0m {label}  (got {got!r}, wanted {want!r})")


#: (url, status, title) — a plausible spread for one programme.
FIXTURES = (
    [(f"http://app{i}.example", 200, f"Portal {i}") for i in range(5)]
    + [("http://moved.example", 301, "Moved")]
    + [("http://secret.example", 401, "Sign in"),
       ("http://forbidden.example", 403, "Forbidden")]
    + [(f"http://gone{i}.example", 404, "Not found") for i in range(7)]
    + [("http://teapot.example", 418, "Teapot"),
       ("http://broken.example", 503, "Unavailable"),
       ("http://silent.example", None, "")]
)


def main():
    with tempfile.TemporaryDirectory() as home:
        os.environ["BBHUNTER_HOME"] = home
        import bbhunter.config as cfg
        from bbhunter.store import Store
        from bbhunter.server import create_app
        from fastapi.testclient import TestClient

        store = Store(cfg.db_path())
        program = store.upsert_program(
            "Acme", {"include": ["example"], "exclude": [], "seeds": []},
            {}, platform="hackerone", handle="envy93")
        pid = program["id"]
        run_id = store.create_run(pid, "standard", "fingerprint", {})

        shots = Path(home) / "runs" / f"{pid}-{run_id}" / "screenshots"
        shots.mkdir(parents=True, exist_ok=True)
        rows = []
        for index, (url, status, title) in enumerate(FIXTURES):
            name = f"{index:04d}.png"
            (shots / name).write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
            rows.append({"key": url, "decision": "allow", "source": "screenshot",
                         "data": {"image": name, "run_id": run_id,
                                  "status": status, "title": title,
                                  "tech": [], "server": "nginx"}})
        store.upsert_assets(pid, run_id, "screenshot", rows)

        client = TestClient(create_app())

        def gallery(**params):
            return client.get(f"/api/programs/{pid}/gallery", params=params).json()

        print("\n\033[1mThe counts describe the whole programme\033[0m")
        everything = gallery()
        check("every capture is counted", everything["captured"], len(FIXTURES))
        counts = {b["key"]: b["count"] for b in everything["buckets"]}
        check("200s are counted", counts["200"], 5)
        check("401 and 403 are one bucket", counts["auth"], 2)
        check("404s are counted", counts["404"], 7)
        check("other 4xx excludes 401, 403 and 404", counts["4xx"], 1)
        check("5xx are counted", counts["5xx"], 1)
        check("redirects are counted", counts["3xx"], 1)
        check("a capture with no status is counted", counts["none"], 1)
        check("the buckets add up to everything",
              sum(counts.values()), len(FIXTURES))

        print("\n\033[1mFiltering returns only that bucket\033[0m")
        only200 = gallery(status="200")
        check("only 200s come back", {i["status"] for i in only200["items"]},
              {200})
        check("and it says how many matched", only200["matching"], 5)
        check("while still reporting the total captured",
              only200["captured"], len(FIXTURES))
        auth = gallery(status="auth")
        check("the auth bucket is 401 and 403",
              sorted(i["status"] for i in auth["items"]), [401, 403])
        check("the counts do not change when a filter is applied",
              {b["key"]: b["count"] for b in auth["buckets"]}, counts)

        print("\n\033[1mThe limit is a limit, and says so\033[0m")
        page = gallery(limit=4)
        check("only that many are rendered", len(page["items"]), 4)
        check("shown reflects the page", page["shown"], 4)
        check("matching reflects everything", page["matching"], len(FIXTURES))
        check("an absurd limit is clamped rather than obeyed",
              len(gallery(limit=99999)["items"]), len(FIXTURES))

        print("\n\033[1mSorting\033[0m")
        by_status = [i["status"] for i in gallery(sort="status")["items"]]
        check("by status puts the lowest first", by_status[0], 200)
        check("and a missing status last", by_status[-1], None)
        by_url = [i["url"] for i in gallery(sort="url")["items"]]
        check("by URL is alphabetical", by_url, sorted(by_url))

        print("\n\033[1mSearch and filter compose\033[0m")
        searched = gallery(search="gone")
        check("the search narrows the captures", searched["matching"], 7)
        check("and the counts narrow with it",
              {b["key"]: b["count"] for b in searched["buckets"]}["404"], 7)
        check("a filter that matches nothing returns nothing, not everything",
              gallery(search="gone", status="200")["matching"], 0)

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
