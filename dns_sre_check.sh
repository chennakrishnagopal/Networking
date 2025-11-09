#!/usr/bin/env bash
# dns_sre_check.sh
# Usage: ./dns_sre_check.sh <domain>
# Example: ./dns_sre_check.sh onlinesbi.sbi.bank.in

if [ -z "$1" ]; then
  read -p "Enter domain name to check: " DOMAIN
else
  DOMAIN=$1
fi

# Colors
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
BOLD="\033[1m"
NC="\033[0m"

# Convenience: print section header
sec() {
  echo -e "\n${BOLD}${BLUE}==> $1${NC}"
}

warn() { echo -e "${YELLOW}⚠ $1${NC}"; }
ok()   { echo -e "${GREEN}✔ $1${NC}"; }
err()  { echo -e "${RED}✖ $1${NC}"; }

# Tool check
require() {
  command -v "$1" >/dev/null 2>&1 || {
    err "Missing required command: $1"
    echo "  Install on macOS (brew): brew install $2"
    echo "  Install on Debian/Ubuntu: sudo apt-get install $3"
    exit 2
  }
}

# Check a list of typical tools (adjust package names suggestions)
check_tools() {
  sec "Checking required tools"
  require dig bind9-dnsutils dnsutils    # dig (dnsutils / bind9-dnsutils)
  require nslookup bind9-dnsutils dnsutils
  require curl curl curl
  require whois whois whois
  require traceroute traceroute traceroute
  require ping iputils-ping iputils-ping
  ok "All necessary CLI tools found"
}

# Try to map package name suggestions above more nicely:
# Note: require called with (cmd, brew-pkg, apt-pkg) but we reused placeholders
# We'll still check the binaries exist.

# Helper to run a command and show it
run_and_print() {
  echo -e "${BOLD}\$ $*${NC}"
  eval "$@" 2>&1
}

# Start report
echo -e "${BOLD}DNS & Network Quick SRE Check — domain: ${DOMAIN}${NC}"
echo "Timestamp: $(date -u +"%Y-%m-%d %H:%M:%SZ")"

# Ensure tools (but don't try to auto-install)
missing_tools=()
for t in dig nslookup curl whois traceroute ping; do
  if ! command -v "$t" >/dev/null 2>&1; then
    missing_tools+=("$t")
  fi
done

if [ ${#missing_tools[@]} -ne 0 ]; then
  echo -e "${YELLOW}Some commands are missing: ${missing_tools[*]}${NC}"
  echo "Install suggestions:"
  echo " macOS (Homebrew):"
  echo "   brew install bind whois curl traceroute"
  echo " Debian/Ubuntu:"
  echo "   sudo apt update && sudo apt install dnsutils whois curl traceroute -y"
  echo "Continuing with available tools..."
fi

# 1) Basic dig A/AAAA/CNAME
sec "1) Basic record lookups (A / AAAA / CNAME / MX / TXT)"
if command -v dig >/dev/null 2>&1; then
  echo -e "${BOLD}A record:${NC}"
  run_and_print "dig +noall +answer A ${DOMAIN}"
  echo -e "${BOLD}AAAA record:${NC}"
  run_and_print "dig +noall +answer AAAA ${DOMAIN}"
  echo -e "${BOLD}CNAME record:${NC}"
  run_and_print "dig +noall +answer CNAME ${DOMAIN}"
  echo -e "${BOLD}MX record:${NC}"
  run_and_print "dig +noall +answer MX ${DOMAIN}"
  echo -e "${BOLD}TXT record(s):${NC}"
  run_and_print "dig +noall +answer TXT ${DOMAIN}"
else
  warn "dig not available; skipping these checks"
fi

# 2) dig +trace (full resolution path)
sec "2) Full resolution path (dig +trace)"
if command -v dig >/dev/null 2>&1; then
  run_and_print "dig +trace ${DOMAIN}"
else
  warn "dig not available; skip trace"
fi

# 3) DNSSEC check (if any)
sec "3) DNSSEC (DNS Security) quick check"
if command -v dig >/dev/null 2>&1; then
  # Query DNSKEY and check RRSIG presence
  run_and_print "dig +short DNSKEY ${DOMAIN}"
  echo -e "\nCheck if zone has DS at parent (requires parent lookup):"
  run_and_print "dig +short DS ${DOMAIN}"
  echo -e "(If output non-empty, DNSSEC likely configured; use dnsviz.net for detailed view)"
else
  warn "dig not available; skip DNSSEC checks"
fi

# 4) whois lookup
sec "4) WHOIS (registration / nameserver / expiry)"
if command -v whois >/dev/null 2>&1; then
  run_and_print "whois ${DOMAIN}" | sed -n '1,120p'
  echo -e "${YELLOW}... truncated whois output shown above ...${NC}"
else
  warn "whois not available; skip"
fi

# 5) nslookup (resolver used) — shows which resolver you're using and the answer
sec "5) nslookup (resolver + non-authoritative/authoritative reply)"
if command -v nslookup >/dev/null 2>&1; then
  run_and_print "nslookup ${DOMAIN}"
else
  warn "nslookup not available; skip"
fi

# 6) HTTP(S) HEAD check — verify TLS & app reachability
sec "6) HTTP(S) HEAD (curl -I) — checks TLS + HTTP response"
if command -v curl >/dev/null 2>&1; then
  # try https then http
  echo -e "${BOLD}HTTPS HEAD:${NC}"
  run_and_print "curl -I --max-time 10 --location --silent --show-error https://${DOMAIN}" || true
  echo -e "${BOLD}HTTP HEAD (fallback):${NC}"
  run_and_print "curl -I --max-time 10 --location --silent --show-error http://${DOMAIN}" || true
else
  warn "curl not available; skip HTTP checks"
fi

# 7) Ping (ICMP) quick check (warn when blocked)
sec "7) Ping (ICMP) — may be blocked by firewall"
if command -v ping >/dev/null 2>&1; then
  # On macOS ping default count is until ctrl-c; use -c 4
  if [[ "$(uname)" == "Darwin" ]]; then
    run_and_print "ping -c 4 ${DOMAIN}"
  else
    run_and_print "ping -c 4 ${DOMAIN}"
  fi
  echo -e "${YELLOW}Note: 100% loss is common for CDNs/banks that block ICMP.${NC}"
else
  warn "ping not available; skip"
fi

# 8) traceroute — different flags on macOS vs Linux
sec "8) Traceroute (path analysis)"
if command -v traceroute >/dev/null 2>&1; then
  if [[ "$(uname)" == "Darwin" ]]; then
    # macOS traceroute uses -m for max hops and -q for queries
    run_and_print "traceroute -m 30 -q 1 ${DOMAIN}"
  else
    # Linux traceroute (usually from inetutils / traceroute)
    run_and_print "traceroute -n -m 30 ${DOMAIN}"
  fi
else
  warn "traceroute not available; try 'mtr' or 'traceroute' package"
fi

# 9) Optional: reverse DNS for each returned A record
sec "9) Reverse DNS (PTR) for A records found"
AIPS=$(dig +short A "${DOMAIN}" 2>/dev/null | tr '\n' ' ')
if [ -z "$AIPS" ]; then
  warn "No A records found to reverse lookup"
else
  for ip in $AIPS; do
    echo -e "${BOLD}PTR for ${ip}:${NC}"
    if command -v dig >/dev/null 2>&1; then
      run_and_print "dig -x ${ip} +short"
    else
      run_and_print "nslookup ${ip}"
    fi
  done
fi

# 10) Quick guidance summary
sec "10) Quick interpretation hints"
echo "- If DNS answers exist (A/MX) but curl -I fails -> check TLS/certs and WAF/CDN."
echo "- If dig +trace shows correct authoritative NS but end-users can't reach -> verify firewall/WAF/CDN rules."
echo "- If DNSSEC lookups produce SERVFAIL -> DNSSEC misconfiguration possible (check DS and DNSKEY)."
echo "- If ping/traceroute stops at CDN -> likely intentional (ICMP blocked or origin hidden)."

echo -e "\n${BOLD}Done. Save output if you want to attach to incidents.${NC}"
