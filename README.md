# bbhunter

A bug bounty reconnaissance framework where scope is a boundary, not a filter.

You give it a programme's scope. It enumerates, resolves, probes, photographs
every distinct application it finds, crawls, finds parameters, reads the
JavaScript, checks for takeovers and scans — and every single connection any
tool makes is re-checked against your scope rules at the socket before it leaves
the machine.

The work is laid out as five numbered steps, from fixing the boundary to
testing, so it reads as a workflow rather than a wall of switches.

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

The port is resolved before anything is printed, so the banner never shows a
URL that was never going to work. If 8777 is already taken by another copy of
bbhunter you are told it is already running and given that URL; if something
else has it, the next free port is used and said so. An explicit `--port` is
never silently moved — if it is taken, nothing starts and you are shown how to
find out what holds it.

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
blue team treating your testing as an intrusion. With a handle of `envy93` on
HackerOne every request carries:

```
X-Bug-Bounty: envy93
X-Bug-Bounty-Researcher: envy93
X-HackerOne: envy93
```

The platform header follows the programme's platform (`X-HackerOne`,
`X-Bugcrowd`, `X-Intigriti`, `X-YesWeHack`), and you can add any further header
of your own — some programmes ask for a specific one. Headers are set per
programme and shown back to you on the pre-flight screen before anything is
sent.

Then use **Check a host against the scope** before you run anything. Paste in
the hosts you are unsure about; it shows exactly the decision the gate will
make, with the rule that decided it. This is the fastest way to catch a scope
you have typed wrong.

### 2. Run

The chain is presented as five numbered steps, each one feeding the next, so it
is always clear what has happened and what comes next:

| Step | What it does | Stages |
|---|---|---|
| **1 — Scope** | Fix the boundary before anything is sent. | scope and seeds |
| **2 — Discover** | Find every name that belongs to the target, decide which zones answer for anything, resolve what is real. | subdomains, permutations, wildcard verdict, DNS resolution |
| **3 — See what is alive** | Probe for HTTP, collapse hosts serving the same application, photograph what is left. | httpx probing, dedupe, screenshots, ports |
| **4 — Explore the surface** | Crawl and mine archives for URLs, work out which parameters matter, read the JavaScript. | URLs, parameters, JavaScript |
| **5 — Test** | Takeover triage and template scanning. Injection testing only if you turned it on. | takeovers, nuclei, fuzzing, XSS |

Each step shows its stages as chips with the count each produced, turns green
as it completes, and has its own **Run this step** button — so when you change
one thing you redo that part rather than the whole chain. A single step starts
from the previous run's results: each run has its own directory, so what one
stage leaves for the next is carried over, and the log names what was inherited
and from which run.

Four profiles decide which stages are in the chain to begin with:

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

### Themes

Fifteen palettes, in the picker at the top right of every page.

| Dark | Light |
|---|---|
| **Midnight** (default) — blue-slate on near-black | **Daylight** — cool white and blue |
| **Carbon** — neutral graphite, amber accent | **Paper** — warm off-white, ink text |
| **Abyss** — deep navy and cyan | **Slate** — cool grey with teal |
| **Nocturne** — near-black violet | **Sand** — warm beige, low glare |
| **Evergreen** — dark green, easy at length | **Mint** — white with a green accent |
| **Ember** — warm charcoal and orange | **Solar** — warm parchment |
| **Terminal** — true black and phosphor green | **High contrast** — black on white, heavy borders |
| **Nordic** — muted arctic blue-grey | |

Every theme sets CSS custom properties only, so nothing in the interface
hard-codes a colour and a new palette is about fifteen lines. All fifteen were
checked for contrast: body text is at least 12:1 on its background in every
one, secondary text at least 5.5:1, and the severity colours at least 4.7:1 —
so a screenshot taken in any theme is still readable in a report.

Your choice is remembered in that browser and applied before the page paints,
so a restart or an update never flashes the previous theme.

### Checking the tools actually work

Presence is not the same as working. httpx with no browser, nuclei with no
templates and subfinder with no API keys all pass a version check and then
quietly produce nothing.

**Tools → Check they actually work**, or from a terminal:

```bash
./bbf --doctor              # runs each installed tool against a local target
./bbf --doctor-online       # also the checks that need DNS or the internet
./bbf --doctor --doctor-tool httpx --doctor-tool nuclei
```

The doctor starts a throwaway HTTP server on `127.0.0.1` and runs each tool
against it for real — httpx must return parsed JSON with the page title, katana
must find the linked script, nuclei must have templates and complete a scan,
naabu must find a port that is open. Nothing is sent to any programme.

### 3. Results

**Gallery** is the fastest way to triage a large scope. Once httpx has confirmed
which hosts are alive and identical responses have been collapsed, every
distinct application is photographed and shown as a card with its URL, page
title, status code and server. Clicking a card opens that URL in a new tab. You
are looking at pictures of the estate rather than a list of four thousand
hostnames, so the login portal nobody remembers deploying stands out
immediately.

Across the top: a search box, a **status filter** with live counts —
`All 412 · 200 OK 96 · Redirects 31 · 401/403 8 · 404 240 · 5xx 3` — a sort
(newest, status, URL, title) and how many cards to render. The counts are
computed over everything the search matched, not over the page on screen, so
`401/403 8` means eight in the programme. One click hides two hundred 404s and
leaves the things worth looking at.

Capture needs **a browser on the machine** — `sudo apt install -y chromium`,
which `install.sh` now does for you. This is not optional: httpx and gowitness
both embed go-rod, which downloads its own Chromium on first use and fails on
any box without egress to Google's storage bucket. If no browser is found the
step says exactly that and how to fix it, rather than reporting nothing
captured.

Given a browser, capture tries `httpx -screenshot -system-chrome`, then
`gowitness --chrome-path`, then the browser directly — **moving on if one
produces no images**, not merely if one is missing. All three run through the
scope gate, so a redirect cannot walk the browser out of scope.
`screenshot_cap` (default 300) bounds how many are taken; `chrome_binary` in
Settings points at a browser in an unusual place (a snap, a flatpak, an
unpacked tarball).

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

The Update page reads the published version through **your own git remote**,
so a private repository works exactly as a public one does — whatever
credentials `git pull` uses, the version check uses. Anonymous HTTPS to
`raw.githubusercontent.com` is only a fallback for a checkout whose remote is
not reachable; a private repo answers 404 there, which is reported as "probably
private" rather than as a failure to reach GitHub.

The Update page compares **commits, not version numbers**: it reports how many
commits `origin/main` has that your checkout does not, and lists them. A
fortnight of fixes can land without `VERSION` changing, and "you are on the
latest version" while eight commits behind is worse than saying nothing.

The **Update** page checks GitHub and pulls. It refuses to run if you have
local modifications rather than discarding them, and your engagement database
and configuration live outside the checkout, so an update never touches your
results.

```bash
git -C BugBounties pull    # the same thing from the terminal
```

A permission bit is not a local modification: the install instructions tell you
to `chmod +x bbf install.sh`, so the updater runs git with
`core.fileMode=false` and those two files never block an update. A changed line
still does.

### If you downloaded a zip instead of cloning

The Update page will say so. You do not have to download anything again — turn
the folder you already have into a checkout in place:

```bash
cd /path/to/BugBounties
git init
git remote add origin https://github.com/LukeDInfosec/BugBounties.git
git fetch origin
git reset --hard origin/main            # discards local edits to tracked files
git branch --set-upstream-to=origin/main main
```

Your database, settings and results are in `~/.local/share/bbhunter/`, outside
the checkout, so none of that is touched. If the repository is private, GitHub
will not accept a password over HTTPS — clone over SSH, or run `gh auth login`
first.

---

## Being a good citizen

Defaults are deliberately conservative: **5 requests per second per host, 20
combined, 10 concurrent connections**. That limit governs what reaches the
programme's servers. DNS goes to a resolver and passive enumeration goes to
third-party APIs, so neither is throttled by it — `dns_rps` (default 300) and
`source_rps` (default 0, meaning the tool's own pacing) are separate. Applying
the per-host limit to DNS is not politeness, it is just a resolution stage that
takes hours. Most programmes publish limits in that
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

At the end of a run the framework reports how many requests went to each host,
and how many were refused and to where. If a programme manager ever asks, you
have the number.

Refusals are counted rather than repeated: the first one for a host is logged
in full, the rest are tallied, and the host is mentioned again at 10, 100 and
1000. The structured events are never dropped, so the totals stay exact. The
headless browser is also launched with its own background networking turned
off — component updates, Safe Browsing and the rest would otherwise generate
hundreds of correctly-refused requests to Google on every screenshot run.

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
  doctor.py      runs each tool for real and reports what works
  quiet.py       keeps abandoned DNS failures out of the terminal
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
plus the per-run working directories, screenshots included. Copy it and you have
the whole engagement.

---

## Checking it still works

```bash
python3 selftest.py          # full: imports, scope, gate, a live run
python3 selftest.py --quick  # skip the live run
python3 tests/test_scope.py  # 70 scope cases
python3 tests/test_proxy.py  # the gate, under real sockets
python3 tests/test_store_runner.py
python3 tests/test_updater.py  # what counts as a local change
python3 tests/test_screenshots.py
python3 tests/test_noise.py
python3 tests/test_gallery.py
```

The full selftest is **56 checks**, including one screenshot genuinely captured
through the gate and served back to the gallery.

`selftest.py` stands up a small site on this machine, runs the whole chain
against it, and checks the traffic arrived with your header on it. Run it after
an update.

---

## Authorisation

This is for programmes you are authorised to test. The scope engine is there to
help you stay inside that authorisation, not to substitute for having it.
Nothing here excuses testing something you have no permission to test.
