# Generates deterministic Pester test fixtures for CI when the tests/ directory
# is absent (it is gitignored per repo policy). Run this step before Invoke-Pester.
#
# Outputs:
#   tests/fixtures/kev-sample.json     - Sample CISA KEV catalog subset
#   tests/fixtures/winget-updates.txt  - Sample winget upgrade output with updates
#   tests/fixtures/winget-none.txt     - Sample winget upgrade output, no updates
#   tests/fixtures/winget-source-err.txt - Sample winget source/network error output

$ErrorActionPreference = 'Stop'
# Create tests/ at repository root (one level up from scripts/)
$repoRoot = Split-Path $PSScriptRoot -Parent
$fixtureDir = Join-Path $repoRoot 'tests\fixtures'
if (-not (Test-Path $fixtureDir)) {
    New-Item -ItemType Directory -Path $fixtureDir -Force | Out-Null
}

# --- KEV sample fixture: Microsoft Windows entries in lookback window ---
$kevSample = @{
    vulnerabilities = @(
        @{
            cveID             = 'CVE-2026-1001'
            vendorProject     = 'Microsoft'
            product           = 'Windows'
            dateAdded         = '2026-06-15'
            shortDescription  = 'Windows kernel elevation of privilege vulnerability'
            knownRansomwareCampaignUse = 'Known'
        }
        @{
            cveID             = 'CVE-2026-1002'
            vendorProject     = 'Microsoft'
            product           = 'Windows'
            dateAdded         = '2026-07-20'
            shortDescription  = 'Windows Print Spooler remote code execution vulnerability'
            knownRansomwareCampaignUse = 'No'
        }
        @{
            cveID             = 'CVE-2026-1003'
            vendorProject     = 'Microsoft'
            product           = 'Windows'
            dateAdded         = '2026-08-10'
            shortDescription  = 'Windows DNS server information disclosure vulnerability'
            knownRansomwareCampaignUse = 'Unknown'
        }
    )
}
$kevSample | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $fixtureDir 'kev-sample.json') -Encoding UTF8

# --- winget upgrade output with updates available ---
$wingetUpdates = @'
Name             Id                           Version Available Source
---------------------------------------------------------------
Example Package  Example.Package              1.0.0   2.0.0   winget
Microsoft Edge   Microsoft.Edge               120.0   121.0   winget
'@
$wingetUpdates | Set-Content -Path (Join-Path $fixtureDir 'winget-updates.txt') -Encoding UTF8

# --- winget upgrade output, no updates available ---
$wingetNone = @'
Name             Id                           Version Available Source
---------------------------------------------------------------
No installed package found matching input criteria.
'@
$wingetNone | Set-Content -Path (Join-Path $fixtureDir 'winget-none.txt') -Encoding UTF8

# --- winget source/network error output ---
$wingetSourceErr = @'
Error: Package source is unavailable.
Please check your network connection and try again.
'@
$wingetSourceErr | Set-Content -Path (Join-Path $fixtureDir 'winget-source-err.txt') -Encoding UTF8

Write-Host "Generated test fixtures in $fixtureDir"
Get-ChildItem $fixtureDir | ForEach-Object { Write-Host ("  " + $_.Name) }
