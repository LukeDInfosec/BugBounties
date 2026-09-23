#!/usr/bin/env bash
# bbhunter installer for Kali Linux.
#
# Written to be run more than once. Every step checks whether it is already
# done, nothing is reinstalled needlessly, and a failure in one tool never
# stops the rest — you end up with a report of what worked rather than a
# half-finished system and a stack trace.
#
# It never uses sudo without saying so, and it never silently writes outside
# $HOME except for the apt packages it names up front.

set -uo pipefail

BOLD=$'\e[1m'; DIM=$'\e[2m'; RED=$'\e[31m'; GREEN=$'\e[32m'
YELLOW=$'\e[33m'; BLUE=$'\e[34m'; RESET=$'\e[0m'

OK_LIST=(); FAILED_LIST=(); SKIPPED_LIST=(); DEFERRED_APT=()
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say()  { printf '%s\n' "$*"; }
head2(){ printf '\n%s%s%s\n' "$BOLD" "$*" "$RESET"; }
ok()   { printf '  %s✓%s %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '  %s!%s %s\n' "$YELLOW" "$RESET" "$*"; }
bad()  { printf '  %s✗%s %s\n' "$RED" "$RESET" "$*"; }
info() { printf '  %s%s%s\n' "$DIM" "$*" "$RESET"; }

# ── privilege ───────────────────────────────────────────────────────────────
# Asking for a password from a script that then runs for ten minutes is rude,
# so root operations are batched and anything that cannot be done without a
# password is deferred to a single command printed at the end.
run_root() {
    if [ "$(id -u)" -eq 0 ]; then "$@"; return $?; fi
    if sudo -n true 2>/dev/null; then sudo "$@"; return $?; fi
    return 1
}

apt_install() {
    local pkg="$1"
    if dpkg -s "$pkg" >/dev/null 2>&1; then
        SKIPPED_LIST+=("$pkg (already installed)")
        return 0
    fi
    if run_root apt-get install -y -qq "$pkg" >/dev/null 2>&1; then
        OK_LIST+=("$pkg")
        ok "$pkg"
    else
        DEFERRED_APT+=("$pkg")
        warn "$pkg needs root — deferred"
    fi
}

have() { command -v "$1" >/dev/null 2>&1; }

# ── Go tools ────────────────────────────────────────────────────────────────
# Kali's packaged versions of the ProjectDiscovery tools lag upstream by
# several minor releases, and httpx in particular is installed under a
# different binary name because python3-httpx already owns /usr/bin/httpx.
# Installing from source avoids both problems.
go_install() {
    local binary="$1" module="$2" purpose="$3"
    if have "$binary"; then
        SKIPPED_LIST+=("$binary (already installed)")
        info "$binary already present — $(command -v "$binary")"
        return 0
    fi
    if ! have go; then
        FAILED_LIST+=("$binary (Go is not installed)")
        bad "$binary — Go is not available"
        return 1
    fi
    printf '  %s… installing %s%s\r' "$DIM" "$binary" "$RESET"
    local log; log="$(mktemp)"
    if go install -v "$module" >"$log" 2>&1; then
        OK_LIST+=("$binary")
        ok "$binary — $purpose"
    else
        FAILED_LIST+=("$binary")
        bad "$binary — install failed"
        info "$(tail -n 3 "$log" | tr '\n' ' ')"
    fi
    rm -f "$log"
}

pipx_install() {
    local binary="$1" spec="$2" purpose="$3"
    if have "$binary"; then
        SKIPPED_LIST+=("$binary (already installed)")
        info "$binary already present"
        return 0
    fi
    if ! have pipx; then
        FAILED_LIST+=("$binary (pipx is not installed)")
        return 1
    fi
    if pipx install "$spec" >/dev/null 2>&1; then
        OK_LIST+=("$binary")
        ok "$binary — $purpose"
    else
        FAILED_LIST+=("$binary")
        bad "$binary — install failed"
    fi
}

# ── start ───────────────────────────────────────────────────────────────────
cat <<BANNER

${BOLD}bbhunter installer${RESET}
${DIM}Installs the reconnaissance toolchain and the framework's own
dependencies. Safe to re-run; anything already present is left alone.${RESET}

BANNER

if [ "$(id -u)" -eq 0 ]; then
    warn "Running as root. Go tools will install to /root/go/bin."
fi

head2 "1. System packages"
if run_root apt-get update -qq >/dev/null 2>&1; then
    ok "package lists updated"
else
    warn "could not update package lists without root — continuing"
fi
for pkg in git curl jq python3-pip pipx massdns nmap; do
    apt_install "$pkg"
done

head2 "2. Go"
if have go; then
    ok "go $(go version 2>/dev/null | awk '{print $3}')"
else
    apt_install golang-go
    if ! have go; then
        bad "Go is not installed. Most tools below need it."
        info "Install it with: sudo apt install -y golang-go"
    fi
fi
export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin"

head2 "3. Python dependencies for the framework itself"
if python3 -c "import fastapi, uvicorn" 2>/dev/null; then
    ok "fastapi and uvicorn already available"
else
    if python3 -m pip install -q --break-system-packages -r "$HERE/requirements.txt" 2>/dev/null \
       || python3 -m pip install -q -r "$HERE/requirements.txt" 2>/dev/null; then
        ok "installed from requirements.txt"
    else
        FAILED_LIST+=("python dependencies")
        bad "could not install Python dependencies"
        info "Try: python3 -m pip install --break-system-packages -r requirements.txt"
    fi
fi
have pipx || info "pipx missing — the Python-based tools below will be skipped"
pipx ensurepath >/dev/null 2>&1 || true

head2 "4. Discovery"
go_install subfinder  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"      "passive subdomain enumeration"
go_install assetfinder "github.com/tomnomnom/assetfinder@latest"                            "extra passive sources"
go_install chaos      "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"           "bug bounty scope dataset"
go_install github-subdomains "github.com/gwen001/github-subdomains@latest"                  "hostnames leaked in public code"
go_install alterx     "github.com/projectdiscovery/alterx/cmd/alterx@latest"                "permutation generation"

head2 "5. Resolution and probing"
go_install dnsx       "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"                    "DNS resolution and wildcard filtering"
go_install puredns    "github.com/d3mondev/puredns/v2@latest"                               "mass resolution with trusted re-validation"
go_install httpx      "github.com/projectdiscovery/httpx/cmd/httpx@latest"                  "HTTP probing"
go_install naabu      "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"               "port discovery"
go_install tlsx       "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"                    "certificate grabbing"
go_install cdncheck   "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"            "CDN detection"

head2 "6. URLs, parameters and JavaScript"
go_install katana     "github.com/projectdiscovery/katana/cmd/katana@latest"                "crawling"
go_install gau        "github.com/lc/gau/v2/cmd/gau@latest"                                 "archived URLs"
go_install urlfinder  "github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"          "passive URL sources"
go_install subjs      "github.com/lc/subjs@latest"                                          "JavaScript file discovery"
go_install jsluice    "github.com/BishopFox/jsluice/cmd/jsluice@latest"                     "JavaScript parsing"
go_install gf         "github.com/tomnomnom/gf@latest"                                      "pattern matching over URL sets"
go_install anew       "github.com/tomnomnom/anew@latest"                                    "append-if-new"
pipx_install uro      "uro"                                                                 "URL deduplication"
pipx_install arjun    "arjun"                                                               "hidden parameter discovery"

head2 "7. Vulnerability detection"
go_install nuclei     "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"             "template scanning and fuzzing"
go_install dalfox     "github.com/hahwul/dalfox/v2@latest"                                  "XSS testing"
go_install subzy      "github.com/PentestPad/subzy@latest"                                  "subdomain takeover signatures"
go_install interactsh-client "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest" "out-of-band callbacks"
go_install gowitness  "github.com/sensepost/gowitness@latest"                               "screenshots"

head2 "8. Secret scanning"
if have trufflehog; then
    SKIPPED_LIST+=("trufflehog (already installed)")
    info "trufflehog already present"
elif have curl; then
    if curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | run_root sh -s -- -b /usr/local/bin >/dev/null 2>&1; then
        OK_LIST+=("trufflehog"); ok "trufflehog — verifies the secrets it finds"
    else
        FAILED_LIST+=("trufflehog"); warn "trufflehog install needs root; see the summary"
    fi
fi

head2 "9. nuclei templates"
if have nuclei; then
    if nuclei -update-templates -silent >/dev/null 2>&1 || nuclei -ut -silent >/dev/null 2>&1; then
        ok "templates updated"
    else
        warn "could not update templates — run 'nuclei -ut' yourself"
    fi
fi

head2 "10. Resolver lists"
RESOLVER_DIR="$HOME/.config/bbhunter"
mkdir -p "$RESOLVER_DIR"
# A stale resolver list is the single most common cause of two runs against
# the same target disagreeing, so these are refreshed on install.
for pair in "resolvers.txt:resolvers.txt" "resolvers-trusted.txt:resolvers-trusted.txt"; do
    name="${pair%%:*}"; remote="${pair##*:}"
    if curl -sSfL --max-time 30 \
        "https://raw.githubusercontent.com/trickest/resolvers/main/$remote" \
        -o "$RESOLVER_DIR/$name" 2>/dev/null; then
        ok "$name ($(wc -l < "$RESOLVER_DIR/$name") resolvers)"
    else
        warn "could not fetch $name"
    fi
done

# ── summary ─────────────────────────────────────────────────────────────────
printf '\n%s%s%s\n' "$BOLD" "──────────────────────────────────────────────────────────" "$RESET"
head2 "Result"
say "  ${GREEN}${#OK_LIST[@]} installed${RESET}   ${DIM}${#SKIPPED_LIST[@]} already present${RESET}   ${RED}${#FAILED_LIST[@]} failed${RESET}"

if [ ${#FAILED_LIST[@]} -gt 0 ]; then
    printf '\n  %sThese did not install:%s\n' "$YELLOW" "$RESET"
    for item in "${FAILED_LIST[@]}"; do say "    · $item"; done
    say ""
    info "The framework runs without them — the stages that need them are"
    info "skipped and say so. Re-run this script to try again."
fi

if [ ${#DEFERRED_APT[@]} -gt 0 ]; then
    printf '\n  %sThese need root. One command:%s\n\n' "$YELLOW" "$RESET"
    say "    sudo apt-get install -y ${DEFERRED_APT[*]}"
fi

MISSING_PATH=0
case ":$PATH:" in *":$HOME/go/bin:"*) ;; *) MISSING_PATH=1 ;; esac
if [ "$MISSING_PATH" -eq 1 ] && [ -d "$HOME/go/bin" ]; then
    printf '\n  %s$HOME/go/bin is not on your PATH.%s Add it so the tools are found:\n\n' "$YELLOW" "$RESET"
    say "    echo 'export PATH=\$PATH:\$HOME/go/bin' >> ~/.zshrc && source ~/.zshrc"
    say ""
    info "The ./bbf launcher adds it automatically, so this only matters when"
    info "you run the tools by hand."
fi

cat <<DONE

${BOLD}Start it:${RESET}

    cd "$HERE"
    ./bbf

The interface opens at ${BLUE}http://127.0.0.1:8777${RESET}. Create a programme,
paste the scope, and check a few hostnames on the Scope page before you run
anything — that page shows exactly the decision the gate will make.

DONE
