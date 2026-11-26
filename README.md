# Windows 11 CVE Security Audit

[![Security Policy](https://img.shields.io/badge/Security-Policy-blue)](SECURITY.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)](https://learn.microsoft.com/powershell)

A portable, read-only security audit tool and report generator for Windows 11 systems.

## What this audit checks

1. **Executive Summary** — High-level counts: passed/failed/unknown checks, vulnerable KEV entries, pending updates
2. **System Information** — OS version, build, UBR, architecture, edition, install/boot dates
3. **Security Features** — Evidence-based assessment of:
   - BitLocker (system volume encryption state)
   - Secure Boot (UEFI state)
   - TPM 2.0 (present, ready, enabled, activated, spec version)
   - Windows Defender (AV enabled, real-time protection, signature freshness)
   - Windows Firewall (active profiles, default actions)
   - Administrator privilege detection (explicit REQUIRES ELEVATION status)
4. **Installed Applications** — Multi-source inventory:
   - Registry (HKLM x64/x86, HKCU)
   - winget repository
   - MSIX/AppX (current user)
   - Deduplication by (Id, Scope, Architecture) — not display name
   - Coverage metadata (source counts)
5. **CISA KEV Coverage** — Every Microsoft Windows KEV entry from the lookback window (default 12 months), with per-CVE verdict:
   - PATCHED / PATCHED (inherited) / VULNERABLE / VULNERABLE (inherited) / NOT AFFECTED / UNKNOWN
   - Confidence scoring: High (direct MSRC fix metadata), Medium (servicing family inheritance), Low (limited metadata)
   - Fixed build, KB article, ransomware flag, CVSS, severity
6. **Available Updates (winget)** — Structured outcome: UpdatesAvailable / NoUpdates / Unavailable / ExecutionFailed / SourceError / ParseError / Unknown
7. **Pending Windows Updates** — Windows Update Agent COM scan (read-only):
   - Applicable updates with Title, KB, Category, Severity, Download Size
   - Pending reboot detection (SystemInfo COM + registry)
   - Outcome: AFFECTED / NOT AFFECTED / ERROR
8. **Assessment Coverage and Limitations** — Explicit table of what is/isn't covered
9. **Data Sources and Timestamps** — Provenance for every data source
10. **Recommended Actions** — Priority remediation guidance for failed checks, vulnerable KEV entries, pending Windows Updates, winget updates

## Usage

### Quick Run
```powershell
# Run directly with PowerShell
powershell.exe -ExecutionPolicy Bypass -File win11-cve-audit.ps1
```

### With Options
```powershell
# Custom output path and KEV lookback window
powershell.exe -ExecutionPolicy Bypass -File win11-cve-audit.ps1 -OutputPath ".\my-report.md" -LookbackMonths 6
```

### Import as Module
```powershell
# Import the module for granular function calls
Import-Module win11-cve-audit

# Get specific info
Get-WindowsBuildInfo
Get-LocalSoftwareInventory
Test-SecurityFeature
Get-PendingWindowsUpdate
Get-WingetUpdate
Get-KevVulnerabilityStatus -BuildNumber 26200 -UBR 9974

# Full audit report
$report = New-AuditReport -OutputPath ".\security-audit-report.md"
```

## Output

The audit generates a `security-audit-report.md` containing all sections above. Key features:
- **Evidence-based verdicts** — UNKNOWN/ERROR/NOT ASSESSED/REQUIRES ELEVATION are never presented as clean results
- **Confidence scoring** — High/Medium/Low with reasoning
- **Executive summary table** — Counts by outcome for quick triage
- **Remediation guidance** — Concrete next steps for each finding

## Project Structure

```
Windows-Security-Audit/
├── win11-cve-audit.ps1      # Main entry point script
├── win11-cve-audit.psm1     # PowerShell module manifest
├── win11-cve-audit.psd1     # Module definition file
├── functions/               # Modular PowerShell functions
│   ├── 0.Invoke-AuditRestMethod.ps1
│   ├── 1.Get-WindowsBuildInfo.ps1
│   ├── 2.Get-LocalSoftwareInventory.ps1
│   ├── 3.Get-KevVulnerabilityStatus.ps1
│   ├── 4.Compare-Version.ps1
│   ├── 5.Get-AppCveStatus.ps1
│   ├── 6.Get-WingetUpdate.ps1
│   ├── 7.Test-SecurityFeature.ps1
│   ├── 8.New-AuditReport.ps1
│   └── 9.Get-PendingWindowsUpdate.ps1
├── tests/                   # Pester regression tests (gitignored)
│   ├── Verify-P01.ps1
│   ├── Verify-Winget.ps1
│   └── fixtures/
├── .github/workflows/       # CI/CD validation
├── SECURITY.md
└── README.md
```

## Data Sources (All Public APIs)

| Source | Purpose | Auth Required |
|--------|---------|---------------|
| CISA KEV JSON | Known Exploited Vulnerabilities | No |
| MSRC SUG API v2.0 | Vulnerability details, affected products, fixed builds | No |
| Windows Update Agent (COM) | Pending Windows Updates | No |
| winget | Windows package updates | No |
| Local WMI/CIM | System info, security features | No |
| Registry | Installed applications | No |

## Requirements

- PowerShell 5.1+ (built into Windows 11)
- Internet access for KEV/MSRC/winget queries
- **No admin rights required** for most checks (read-only)
- **Administrator privileges required** for TPM and Secure Boot queries (explicitly reported as REQUIRES ELEVATION)
- Pester 6+ (optional, for regression tests: `Install-Module -Name Pester -Force -Scope CurrentUser`)

## Installation

1. Clone or download the repository:
   ```powershell
   git clone https://github.com/amirhedayatikia/Windows-Security-Audit.git
   cd Windows-Security-Audit
   ```

2. Run the audit:
   ```powershell
   powershell.exe -ExecutionPolicy Bypass -File win11-cve-audit.ps1 [-Verbose] [-OutputPath ".\report.md"] [-LookbackMonths 12]
   ```

3. Or import as a module:
   ```powershell
   Import-Module .\win11-cve-audit.psm1
   New-AuditReport
   ```

## Security Considerations

This script is **read-only** and performs no system modifications:
- Only reads local registry and system information
- Only queries public, unauthenticated APIs
- No data is collected or transmitted beyond the audit report
- TLS 1.2+ enforced for all HTTPS connections (via Invoke-AuditRestMethod)
- No telemetry or persistence

See [SECURITY.md](SECURITY.md) for security best practices and vulnerability reporting.

## Contributing

We welcome contributions! Please read our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT — Free to use, modify, and distribute.