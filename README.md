# Windows 11 CVE Security Audit

[![Security Policy](https://img.shields.io/badge/Security-Policy-blue)](SECURITY.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)](https://learn.microsoft.com/powershell)

A portable, read-only security audit tool and report generator for Windows 11 systems.

## What this audit checks

1. **Local software inventory** — Installed applications from registry and winget
2. **Microsoft CVE coverage** — CISA KEV catalog cross-reference vs your Windows build
3. **Microsoft Security Updates** — Patch status for known exploited vulnerabilities
4. **Available updates** — winget upgrades, pending Windows Updates

## Usage

### Quick Run
```powershell
# Run directly with PowerShell
powershell.exe -ExecutionPolicy Bypass -File win11-cve-audit.ps1
```

### Import as Module
```powershell
# Import the module for granular function calls
Import-Module win11-cve-audit

# Get specific info
Get-WindowsBuildInfo
Get-LocalSoftwareInventory
Test-SecurityFeatures

# Full audit report
$report = New-AuditReport -OutputPath ".\security-audit-report.md"
```

### Claude Code Integration

After installing the skill to `C:\Users\amir_\.claude\skills\`, use:

```
/skill:system-cve-audit
```

Which provides access to:
- `Get-WindowsBuildInfo` — OS build and version details
- `Get-LocalSoftwareInventory` — Installed software list
- `Get-KevVulnerabilityStatus` — KEV vulnerability check
- `Get-AppCveStatus` — Application CVE lookup
- `Get-WingetUpdates` — Available package updates
- `Test-SecurityFeatures` — BitLocker, TPM, Defender status
- `New-AuditReport` — Generate full markdown report

## Output

The audit generates a `security-audit-report.md` containing:
- System Information (OS version, build, UBR)
- Security Features Status (BitLocker, TPM, Defender, Firewall)
- CISA KEV Vulnerability Coverage
- Available winget Updates

## Project Structure

```
Windows-Security-Audit/
├── win11-cve-audit.ps1      # Main entry point script
├── win11-cve-audit.psm1     # PowerShell module manifest
├── win11-cve-audit.psd1     # Module definition file
├── functions/               # Modular PowerShell functions
│   ├── 1.Get-WindowsBuildInfo.ps1
│   ├── 2.Get-LocalSoftwareInventory.ps1
│   ├── 3.Get-KevVulnerabilityStatus.ps1
│   ├── 4.Compare-Version.ps1
│   ├── 5.Get-AppCveStatus.ps1
│   ├── 6.Get-WingetUpdates.ps1
│   ├── 7.Test-SecurityFeatures.ps1
│   └── 8.New-AuditReport.ps1
├── .github/workflows/       # CI/CD validation
├── SECURITY.md
└── README.md
```

## Data Sources (All Public APIs)

| Source | Purpose | Auth Required |
|--------|---------|---------------|
| CISA KEV JSON | Known Exploited Vulnerabilities | No |
| MSRC CVRF | Microsoft Security Updates | No |
| MSRC SUG API | Security Update Guide | No |
| NVD API | General CVE database | No |
| winget | Windows package updates | No |

## Requirements

- PowerShell 5.1+ (built into Windows 11)
- Internet access
- No admin rights required (read-only)

## Installation

1. Clone or download the repository:
   ```powershell
   git clone https://github.com/amirhedayatikia/Windows-Security-Audit.git
   cd Windows-Security-Audit
   ```

2. Run the audit:
   ```powershell
   powershell.exe -ExecutionPolicy Bypass -File win11-cve-audit.ps1 [-Verbose]
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
- TLS 1.2+ enforced for all HTTPS connections
- No telemetry or persistence

See [SECURITY.md](SECURITY.md) for security best practices and vulnerability reporting.

## Contributing

We welcome contributions! Please read our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT — Free to use, modify, and distribute.