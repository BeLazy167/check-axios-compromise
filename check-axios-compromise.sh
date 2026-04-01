#!/usr/bin/env bash
# check-axios-compromise.sh
# Detects malicious axios supply chain attack (versions 1.14.1 / 0.30.4)
# Works on macOS, Linux, and Windows (Git Bash / WSL)

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

compromised=0
warnings=0

MALICIOUS_VER='1\.14\.1([^0-9]|$)|0\.30\.4([^0-9]|$)'

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
    found_rat=0
    for rat_path in "/Library/Caches/com.apple.act.mond" "$HOME/Library/Caches/com.apple.act.mond"; do
      if [ -e "$rat_path" ]; then
        fail "macOS RAT found: $rat_path"
        found_rat=1
      fi
    done
    [ "$found_rat" -eq 0 ] && ok "No macOS RAT artifact"
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

found_lockfile=0

if [ -f "package-lock.json" ]; then
  found_lockfile=1
  if grep -qE '"axios"' package-lock.json 2>/dev/null; then
    if grep -A5 '"axios"' package-lock.json | grep -qE "$MALICIOUS_VER"; then
      fail "Malicious axios version in package-lock.json"
    else
      ok "axios in package-lock.json — safe version"
    fi
  else
    ok "No axios in package-lock.json"
  fi
fi

if [ -f "yarn.lock" ]; then
  found_lockfile=1
  if grep -qE 'axios@' yarn.lock 2>/dev/null; then
    if grep -A5 'axios@' yarn.lock | grep -qE "$MALICIOUS_VER"; then
      fail "Malicious axios version in yarn.lock"
    else
      ok "axios in yarn.lock — safe version"
    fi
  else
    ok "No axios in yarn.lock"
  fi
fi

if [ -f "pnpm-lock.yaml" ]; then
  found_lockfile=1
  if grep -qE 'axios' pnpm-lock.yaml 2>/dev/null; then
    if grep -A5 'axios' pnpm-lock.yaml | grep -qE "$MALICIOUS_VER"; then
      fail "Malicious axios version in pnpm-lock.yaml"
    else
      ok "axios in pnpm-lock.yaml — safe version"
    fi
  else
    ok "No axios in pnpm-lock.yaml"
  fi
fi

if [ "$found_lockfile" -eq 0 ]; then
  warn "No lockfile in current directory — cd to your project root"
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
    # Check all lockfile types
    for lockfile_name in "package-lock.json" "yarn.lock" "pnpm-lock.yaml"; do
      while IFS= read -r lockfile; do
        lockfiles_checked=$((lockfiles_checked + 1))
        project_dir="$(dirname "$lockfile")"

        # Check lockfile for malicious versions
        if grep -A5 -Ei 'axios' "$lockfile" 2>/dev/null | grep -qE "$MALICIOUS_VER"; then
          fail "Malicious axios in $lockfile"
        fi

        # Check for dropper
        if [ -d "$project_dir/node_modules/plain-crypto-js" ]; then
          fail "Dropper found in $project_dir/node_modules/plain-crypto-js"
        fi
      done < <(find "$dir" -maxdepth 5 -name "$lockfile_name" -not -path "*/node_modules/*" 2>/dev/null || true)
    done
  done

  if [ "$lockfiles_checked" -eq 0 ]; then
    ok "No lockfiles found in project directories"
  else
    ok "Scanned $lockfiles_checked lockfiles"
  fi
fi

# ── Step 4: Global npm cache ──
banner "Global npm Cache"

if ! command -v npm &>/dev/null; then
  ok "npm not installed — skipping cache check"
else
  npm_cache="$(npm config get cache 2>/dev/null || echo "")"
  if [ -n "$npm_cache" ] && [ -d "$npm_cache" ]; then
    malicious_tarballs="$(find "$npm_cache" \( -path "*/axios/-/axios-1.14.1.tgz" -o -path "*/axios/-/axios-0.30.4.tgz" \) 2>/dev/null || true)"
    if [ -n "$malicious_tarballs" ]; then
      warn "Malicious axios tarball in npm cache — run: npm cache clean --force"
    else
      ok "No malicious axios in npm cache"
    fi
  else
    warn "npm installed but cache location not found"
  fi
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
