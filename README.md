# check-axios-compromise

Detect the malicious axios supply chain attack (versions `1.14.1` / `0.30.4`) that installs a Remote Access Trojan via the [`plain-crypto-js`](https://www.npmjs.com/package/plain-crypto-js) dropper package.

Based on the [StepSecurity advisory](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan).

## Usage

```bash
curl -fsSL https://raw.githubusercontent.com/BeLazy167/check-axios-compromise/main/check-axios-compromise.sh | bash
```

Or clone and run:

```bash
git clone https://github.com/BeLazy167/check-axios-compromise.git
cd check-axios-compromise
./check-axios-compromise.sh
```

## What it checks

| # | Check | Details |
|---|-------|---------|
| 1 | **RAT artifacts** | OS-specific payloads (see table below) |
| 2 | **Network IOCs** | Active connections to C2 `sfrclak.com` / `142.11.206.73` |
| 3 | **Lockfiles** | All lockfile types (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`) checked independently |
| 4 | **Dropper package** | `node_modules/plain-crypto-js` in current project and all scanned projects |
| 5 | **Project scan** | Recursively scans common project directories (depth 5) for all lockfile types |
| 6 | **npm cache** | Cached malicious tarballs |

Version matching uses anchored regex to avoid false positives (e.g. `1.14.10` won't match `1.14.1`).

## RAT artifacts by OS

| OS | Path | Type |
|----|------|------|
| macOS | `/Library/Caches/com.apple.act.mond` | Primary payload |
| macOS | `~/Library/Caches/com.apple.act.mond` | Primary payload (user-level) |
| macOS | `/tmp/6202033` | AppleScript dropper (self-deleting) |
| Windows | `%PROGRAMDATA%\wt.exe` | Persistent PowerShell copy |
| Windows | `%TEMP%\6202033.ps1` | Stage-2 payload (self-deleting) |
| Windows | `%TEMP%\6202033.vbs` | VBScript wrapper (self-deleting) |
| Linux | `/tmp/ld.py` | Python RAT (self-deleting) |

## Attack details

- **Malicious versions:** `axios@1.14.1`, `axios@0.30.4`
- **Dropper:** `plain-crypto-js@4.2.1` — injected as dependency, runs `postinstall` hook (`setup.js`)
- **C2 server:** `sfrclak.com:8000` (`142.11.206.73`)
- **Campaign endpoint:** `http://sfrclak.com:8000/6202033`
- **Compromised account:** `jasonsaayman` (axios maintainer, email changed to `ifstap@proton.me`)
- **Anti-forensics:** dropper self-destructs and replaces `package.json` with clean stub, spoofing version to `4.2.0`
- **Obfuscation:** Two-layer XOR cipher (key `OrDeR_7077`) + Base64

### Timeline (2026-03-30/31 UTC)

| Time | Event |
|------|-------|
| 05:57 | Clean `plain-crypto-js@4.2.0` published |
| 23:59 | Malicious `plain-crypto-js@4.2.1` published |
| 00:21 | `axios@1.14.1` published |
| 01:00 | `axios@0.30.4` published |
| ~03:15 | npm unpublished both axios versions |
| 03:25 | npm security hold on `plain-crypto-js` |
| 04:26 | npm published security stub |

## Platform support

- macOS
- Linux
- Windows (Git Bash / WSL / MSYS2)

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean or warnings only |
| `1` | Compromised — indicators found |

## If compromised

1. Disconnect affected machines from the network
2. Rotate all secrets, tokens, and credentials
3. Audit CI/CD pipelines for `axios@1.14.1` or `axios@0.30.4`
4. Remove malicious packages: `npm uninstall axios && npm install axios@1.7.9`
5. Check for unauthorized access in logs
6. Check for connections to `sfrclak.com` / `142.11.206.73` in network logs

## License

MIT
