# check-axios-compromise

Detect the malicious axios supply chain attack (versions `1.14.1` / `0.30.4`) that installs a Remote Access Trojan via the `plain-crypto-js` dropper package.

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
| 1 | **RAT artifacts** | OS-specific payloads (macOS, Linux, Windows) |
| 2 | **Lockfiles** | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` for axios `1.14.1` / `0.30.4` |
| 3 | **Dropper package** | `node_modules/plain-crypto-js` directory |
| 4 | **Project scan** | Recursively scans common project directories |
| 5 | **npm cache** | Cached malicious tarballs |

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

## License

MIT
