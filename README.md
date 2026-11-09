# Windows 11 CVE Security Audit

A portable read-only security audit tool and report for Windows 11 systems.

## What this audit checks

1. **Local software inventory** — Installed applications from registry and winget
2. **Microsoft CVE coverage** — CISA KEV catalog cross-reference vs your Windows build
3. **Third-party CVEs** — WinSCP, VLC, Git, VS Code, WireGuard, Chrome, etc.
4. **Available updates** — winget upgrades, pending Windows Updates, driver updates

## Usage

Run on any Windows 11 machine:

```powershell
# Download and run directly
powershell.exe -ExecutionPolicy Bypass -File win11-cve-audit.ps1
```

The script:
- Queries nothing without explicit user confirmation
- Only reads registry, winget, and public APIs
- Produces a markdown report at `security-audit-report.md`

## Output files

| File | Purpose |
|------|---------|
| `win11-cve-audit.ps1` | Main audit script (portable) |
| `security-audit-report.md` | Generated audit report |
| `README.md` | Documentation |

## Data sources (all public APIs)

- CISA KEV Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Microsoft Security Update Guide API: https://api.msrc.microsoft.com/sug/v2.0/
- Microsoft CVRF feeds: https://api.msrc.microsoft.com/cvrf/v3.0/
- NVD API: https://services.nvd.nist.gov/rest/json/cves/2.0
- Vendor sites: winscp.net, videolan.org, code.visualstudio.com, etc.

## Requirements

- PowerShell 5.1+ (Windows default)
- Internet access
- No admin rights required (read-only)

## License

MIT — Free to use, modify, and distribute.