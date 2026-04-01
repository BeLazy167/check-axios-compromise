#!/usr/bin/env bash
# check-axios-compromise.sh
# Detects malicious axios supply chain attack (versions 1.14.1 / 0.30.4)
# Works on macOS, Linux, and Windows (Git Bash / WSL)

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

compromised=0
warnings=0

banner() { printf "\n${BOLD}── %s ──${NC}\n" "$1"; }
ok()     { printf "  ${GREEN}✓${NC} %s\n" "$1"; }
warn()   { printf "  ${YELLOW}⚠${NC} %s\n" "$1"; warnings=$((warnings + 1)); }
fail()   { printf "  ${RED}✗ %s${NC}\n" "$1"; compromised=$((compromised + 1)); }

printf "${BOLD}Axios Supply Chain Attack Scanner${NC}\n"
printf "Checks for malicious axios 1.14.1 / 0.30.4 and related artifacts\n"

# ── Step 1: RAT artifacts ──
banner "RAT Artifacts"

case "$(uname -s)" in
  Darwin*)
    if [ -e "/Library/Caches/com.apple.act.mond" ]; then
      fail "macOS RAT found: /Library/Caches/com.apple.act.mond"
    else
      ok "No macOS RAT artifact"
    fi
    ;;
  Linux*)
    if [ -e "/tmp/ld.py" ]; then
      fail "Linux RAT found: /tmp/ld.py"
    else
      ok "No Linux RAT artifact"
    fi
    ;;
  MINGW*|MSYS*|CYGWIN*)
    if [ -e "${PROGRAMDATA:-C:\\ProgramData}/wt.exe" ]; then
      fail "Windows RAT found: %PROGRAMDATA%\\wt.exe"
    else
      ok "No Windows RAT artifact"
    fi
    ;;
  *)
    warn "Unknown OS — check manually for RAT artifacts"
    ;;
esac

# ── Step 2: Current project ──
banner "Current Project ($(pwd))"

if [ -f "package-lock.json" ]; then
  if grep -qE '"axios"' package-lock.json 2>/dev/null; then
    if grep -A1 '"axios"' package-lock.json | grep -qE '1\.14\.1|0\.30\.4'; then
      fail "Malicious axios version in package-lock.json"
    else
      ok "axios in lockfile — safe version"
    fi
  else
    ok "No axios in package-lock.json"
  fi
elif [ -f "yarn.lock" ]; then
  if grep -qE 'axios@' yarn.lock 2>/dev/null; then
    if grep -A1 'axios@' yarn.lock | grep -qE '1\.14\.1|0\.30\.4'; then
      fail "Malicious axios version in yarn.lock"
    else
      ok "axios in yarn.lock — safe version"
    fi
  else
    ok "No axios in yarn.lock"
  fi
elif [ -f "pnpm-lock.yaml" ]; then
  if grep -qE 'axios' pnpm-lock.yaml 2>/dev/null; then
    if grep -E 'axios' pnpm-lock.yaml | grep -qE '1\.14\.1|0\.30\.4'; then
      fail "Malicious axios version in pnpm-lock.yaml"
    else
      ok "axios in pnpm-lock.yaml — safe version"
    fi
  else
    ok "No axios in pnpm-lock.yaml"
  fi
else
  ok "No lockfile in current directory"
fi

if [ -d "node_modules/plain-crypto-js" ]; then
  fail "Dropper package found: node_modules/plain-crypto-js"
else
  ok "No plain-crypto-js dropper"
fi

# ── Step 3: Scan project directories ──
banner "Scanning Projects"

search_dirs=()
for d in "$HOME/Projects" "$HOME/projects" "$HOME/code" "$HOME/Code" \
         "$HOME/dev" "$HOME/Dev" "$HOME/src" "$HOME/work" "$HOME/repos" \
         "$HOME/workspace" "$HOME/Workspace" "$HOME/sites" "$HOME/Sites" \
         "$HOME/Desktop" "$HOME/Documents"; do
  [ -d "$d" ] && search_dirs+=("$d")
done

if [ ${#search_dirs[@]} -eq 0 ]; then
  warn "No common project directories found — run from your project root instead"
else
  lockfiles_checked=0
  for dir in "${search_dirs[@]}"; do
    while IFS= read -r lockfile; do
      lockfiles_checked=$((lockfiles_checked + 1))
      project_dir="$(dirname "$lockfile")"

      # Check lockfile for malicious versions
      if grep -A1 '"axios"' "$lockfile" 2>/dev/null | grep -qE '1\.14\.1|0\.30\.4'; then
        fail "Malicious axios in $lockfile"
      fi

      # Check for dropper
      if [ -d "$project_dir/node_modules/plain-crypto-js" ]; then
        fail "Dropper found in $project_dir/node_modules/plain-crypto-js"
      fi
    done < <(find "$dir" -maxdepth 5 -name "package-lock.json" -not -path "*/node_modules/*" 2>/dev/null)

    # Also check yarn.lock
    while IFS= read -r lockfile; do
      lockfiles_checked=$((lockfiles_checked + 1))
      if grep -A1 'axios@' "$lockfile" 2>/dev/null | grep -qE '1\.14\.1|0\.30\.4'; then
        fail "Malicious axios in $lockfile"
      fi
    done < <(find "$dir" -maxdepth 5 -name "yarn.lock" -not -path "*/node_modules/*" 2>/dev/null)

    # Also check pnpm-lock.yaml
    while IFS= read -r lockfile; do
      lockfiles_checked=$((lockfiles_checked + 1))
      if grep -E 'axios' "$lockfile" 2>/dev/null | grep -qE '1\.14\.1|0\.30\.4'; then
        fail "Malicious axios in $lockfile"
      fi
    done < <(find "$dir" -maxdepth 5 -name "pnpm-lock.yaml" -not -path "*/node_modules/*" 2>/dev/null)
  done

  if [ "$lockfiles_checked" -eq 0 ]; then
    ok "No lockfiles found in project directories"
  else
    ok "Scanned $lockfiles_checked lockfiles"
  fi
fi

# ── Step 4: Global npm cache ──
banner "Global npm Cache"

npm_cache="$(npm config get cache 2>/dev/null || echo "")"
if [ -n "$npm_cache" ] && [ -d "$npm_cache" ]; then
  if find "$npm_cache" -path "*/axios/-/axios-1.14.1.tgz" -o -path "*/axios/-/axios-0.30.4.tgz" 2>/dev/null | grep -q .; then
    warn "Malicious axios tarball in npm cache — run: npm cache clean --force"
  else
    ok "No malicious axios in npm cache"
  fi
else
  ok "npm cache not found or npm not installed"
fi

# ── Results ──
banner "Results"

if [ "$compromised" -gt 0 ]; then
  printf "\n${RED}${BOLD}  COMPROMISED — %d issue(s) found${NC}\n" "$compromised"
  printf "\n  Recommended actions:\n"
  printf "  1. Disconnect affected machines from the network\n"
  printf "  2. Rotate all secrets, tokens, and credentials\n"
  printf "  3. Audit CI/CD pipelines for npm installs of axios@1.14.1 or axios@0.30.4\n"
  printf "  4. Remove malicious packages: npm uninstall axios && npm install axios@1.7.9\n"
  printf "  5. Check for unauthorized access in logs\n"
  exit 1
elif [ "$warnings" -gt 0 ]; then
  printf "\n${YELLOW}${BOLD}  WARNINGS — %d warning(s), review manually${NC}\n" "$warnings"
  exit 0
else
  printf "\n${GREEN}${BOLD}  CLEAN — no indicators of compromise found${NC}\n"
  exit 0
fi
