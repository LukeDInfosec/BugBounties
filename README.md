# bbhunter

A bug bounty reconnaissance framework where scope is a boundary, not a filter.

You give it a programme's scope. It enumerates, resolves, probes, crawls, finds
parameters, reads the JavaScript, checks for takeovers and scans — and every
single connection any tool makes is re-checked against your scope rules at the
socket before it leaves the machine.

```
git clone https://github.com/LukeDInfosec/BugBounties.git
cd BugBounties
chmod +x bbf install.sh
./install.sh
./bbf
```

The interface opens at `http://127.0.0.1:8777`.

> The `chmod` is only needed the first time, and only if the repository was
> populated through the web interface rather than a push — GitHub's web upload
> does not carry the executable bit.

---

## Why this one

Most recon frameworks filter the target list and hope. That is necessary but
not sufficient: a crawler follows a redirect off-scope, a template has a
hard-coded callback, a scanner picks up an absolute URL from a page, an SSRF
payload fires at the cloud metadata address. In each case the input filter was
correct and the packet still left.

**bbhunter runs every tool behind a local gate it controls.** Tools are launched
with `HTTP_PROXY`/`HTTPS_PROXY` and an explicit `-proxy` flag pointing at it.
The gate re-classifies the host of every connection and refuses the ones that
are not in scope, so the enforcement holds even when a tool misbehaves.

The same gate is also the only place the real request rate is knowable. Five
tools each politely set to 5 requests per second against one host is 25
requests per second; no individual tool can see that, and this one can.

And it is where your identification goes. Set your handle once and every
request carries `X-Bug-Bounty: <handle>` — over HTTP from the gate, over HTTPS
from each tool's own header flag.

### Three decisions, not two

```
ALLOW    active tools may send traffic here
OBSERVE  record it, note where it came from, never send it a packet
DENY     drop it entirely
```

`OBSERVE` is the one most frameworks lack. Without it you either throw away the
knowledge that `staging.acme-cdn.net` is reachable from the target, or you scan
it. This keeps the discovery without the traffic.

### Things that are easy to get wrong, and are handled

| | |
|---|---|
| `host.endswith("acme.com")` matches `notacme.com` | Every comparison is label-wise |
| `https://api.acme.com@evil.test/` | Userinfo is stripped before the host is read |
| Cyrillic homoglyph domains | Names are IDNA-encoded before comparison |
| `api.acme.com` in scope ⇒ its IP in scope | DNS scope and IP scope never bridge silently |
| Wildcard DNS producing thousands of phantoms | Verdict taken per zone before any bulk resolution |
| 40,000 hosts that are one app | Deduplicated by response hash before anything expensive |
| `/usr/bin/httpx` being Python's httpx on Kali | Tool identity is verified, not assumed from the name |
| A crashed stage reporting "4,000 subdomains removed" | Diffs are gated on stage completion |
| Dismissing 400 findings and getting them back next week | Triage state is keyed to a fingerprint that survives rescans |

---

## Install

Kali, Ubuntu or Debian. Python 3.10+.

```bash
git clone https://github.com/LukeDInfosec/BugBounties.git
cd BugBounties
chmod +x bbf install.sh
./install.sh
```

`install.sh` is safe to re-run. It installs ~25 tools, skips anything already
present, never stops on a single failure, and prints a summary of what worked.
Anything needing root that it could not do is collected into one copy-paste
command at the end rather than prompting you six times.

If you would rather not run the installer, the framework works with nothing
installed at all — it falls back to built-in probing and crawling, and tells
you in the log which tool would have done it better. The Tools page lists every
tool, what it is for, and the exact command to install it.

**Required for full capability:** `subfinder`, `dnsx`, `httpx`, `nuclei`.
Everything else degrades gracefully.

### Running it

```bash
./bbf                      # interface on 127.0.0.1:8777
./bbf --port 9000
./bbf --no-browser
./bbf --scope-check Acme api.acme.com      # one decision, from the terminal
```

The launcher adds `$HOME/go/bin`, `$HOME/.pdtm/go/bin` and `$HOME/.local/bin`
to `PATH`, because a fresh Kali shell has none of them and `subfinder: not
found` immediately after a successful install is the usual first confusion.

---

## Using it

### 1. Scope

Paste the programme's scope. One rule per line.

```
*.acme.com                       the domain and everything under it
acme.com                         bare domain (children included unless you say otherwise)
api-*.edge.acme.com              glob — * never crosses a dot
45.33.32.0/24                    address range
https://portal.acme.com/app/     only URLs under that path
re:^api\d+\.acme\.com$           anchored regular expression
```

Out-of-scope rules always win. There is no include that overrides an exclude.

Set your **handle** here. It becomes the identification header on every request
the framework makes, which is what most programmes ask for and what stops a
blue team treating your testing as an intrusion.

Then use **Check a host against the scope** before you run anything. Paste in
the hosts you are unsure about; it shows exactly the decision the gate will
make, with the rule that decided it. This is the fastest way to catch a scope
you have typed wrong.

### 2. Run

Four profiles:

| Profile | What it does |
|---|---|
| **Passive** | Nothing is sent to the target. Public sources, certificate transparency, archives. |
| **Standard** | The full chain: enumerate, resolve, probe, crawl, parameters, JavaScript, takeovers, nuclei. No payloads. |
| **Deep** | Standard plus permutation brute-force, port scanning and screenshots. |
| **Monitor** | Fast pass for a schedule — find what is new and check it. |

**Active testing is off by default** and each class opts in separately. Before
anything starts you get a pre-flight screen: the exact scope, the stages that
will run, which tools are missing, the rate limits, the headers you will be
identified by, and the scope hash. Active stages require you to tick an
authorisation box.

While it runs you see a stage strip, live counters, findings appearing as they
are found, and the log. Every stage records the exact command it ran, so when a
result looks wrong you can see what produced it and reproduce it by hand.

### 3. Results

**Findings** group by a fingerprint built from the template, host, normalised
path and matcher — deliberately not the response body or a timestamp. Dismiss
something and it stays dismissed through every future run. Each finding carries
how to confirm it, and anything the framework is not confident about is marked
`needs confirming` rather than presented as fact.

**Assets** are filterable by kind and scope decision. URLs are collapsed to
endpoint shapes — `/p?id=1&ref=a` and `/p?id=99&ref=b` are one thing — which
turns 50,000 URLs into a few hundred worth reading.

**What's new** diffs against the last completed run. If a stage failed, the
"disappeared" list is suppressed and says so, because a crashed subfinder
reporting four thousand removed subdomains teaches you to ignore the screen.

---

## Updating

If the repository is **private**, the Update page cannot read the published
version number without credentials and will say so; `git pull` from the
terminal still works with your stored credentials. Making the repository public
enables the in-app version check.

The **Update** page checks GitHub and pulls. It refuses to run if you have
local modifications rather than discarding them, and your engagement database
and configuration live outside the checkout, so an update never touches your
results.

```bash
git -C BugBounties pull    # the same thing from the terminal
```

---

## Being a good citizen

Defaults are deliberately conservative: **5 requests per second per host, 20
combined, 10 concurrent connections**. Most programmes publish limits in that
range, and a framework whose defaults get its user banned is not useful.

Also on by default:

- Intrusive and denial-of-service nuclei templates are excluded.
- Only `GET`, `HEAD`, `POST` and `OPTIONS` are permitted.
- `/logout`, `/delete`, `/reset` and similar are on a path denylist, so a
  crawler cannot log your session out or trigger something destructive.
- A `429` or `503` halves the rate for that host and backs off exponentially,
  and says so in the log rather than silently producing false negatives.
- Private ranges, loopback, link-local and cloud metadata are refused before
  any rule is consulted. Each has its own switch, and metadata is separate from
  private, because someone testing an internal range still does not want a
  scanner wandering into the instance metadata service.

At the end of a run the framework reports how many requests went to each host.
If a programme manager ever asks, you have the number.

---

## What it does not do

Stated plainly, because a tool that overstates itself is worse than one that
does less.

- **It does not confirm findings for you.** Everything from a fuzzing stage is
  a candidate. The framework tells you how to confirm each one and marks its
  confidence; the confirmation is yours.
- **It cannot inject headers inside an HTTPS tunnel from the gate.** That would
  need a forged certificate and every tool told to trust it. Headers for HTTPS
  come from each tool's own flag instead. Scope enforcement and rate limiting
  apply to HTTP and HTTPS equally.
- **It does not do authenticated scanning.** No framework does this well and
  this one does not pretend to.
- **It runs one scan at a time.** Simpler to reason about, and correct.

---

## Layout

```
bbhunter/
  scope.py       the decision engine — the safety-critical part
  proxy.py       the egress gate, rate limiter and header injector
  store.py       SQLite: assets that persist, observations per run
  runner.py      subprocess supervision, process-group kill, watchdogs
  pipeline.py    the stages and what each is allowed to touch
  engine.py      run sequencing, live events, cancellation
  tools.py       tool registry, identity verification, install commands
  server.py      API and WebSocket
  web/           the interface — no build step
tests/           scope, proxy, store and runner tests
selftest.py      end-to-end check against a target on this machine
install.sh       Kali toolchain installer
```

Data lives in `~/.local/share/bbhunter/` — one SQLite file per installation
plus the per-run working directories. Copy it and you have the whole
engagement.

---

## Checking it still works

```bash
python3 selftest.py          # full: imports, scope, gate, a live run
python3 selftest.py --quick  # skip the live run
python3 tests/test_scope.py  # 70 scope cases
python3 tests/test_proxy.py  # the gate, under real sockets
```

`selftest.py` stands up a small site on this machine, runs the whole chain
against it, and checks the traffic arrived with your header on it. Run it after
an update.

---

## Authorisation

This is for programmes you are authorised to test. The scope engine is there to
help you stay inside that authorisation, not to substitute for having it.
Nothing here excuses testing something you have no permission to test.
