# Generates deterministic Pester test fixtures AND test files for CI when the tests/ directory
# is absent (it is gitignored per repo policy). Run this step before Invoke-Pester.

$ErrorActionPreference = 'Stop'
# Create tests/ at repository root (one level up from scripts/)
$repoRoot = Split-Path $PSScriptRoot -Parent
$fixtureDir = Join-Path $repoRoot 'tests\fixtures'
$testDir = Join-Path $repoRoot 'tests'
if (-not (Test-Path $fixtureDir)) {
    New-Item -ItemType Directory -Path $fixtureDir -Force | Out-Null
}
if (-not (Test-Path $testDir)) {
    New-Item -ItemType Directory -Path $testDir -Force | Out-Null
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

# Use module import + dot-source internal functions for tests
# Calculate repo root once at generation time and embed absolute path
$repoRoot = $PWD.ProviderPath
$moduleImport = @"
`$repoRoot = '$repoRoot'
Import-Module (Join-Path `$repoRoot "win11-cve-audit.psd1") -Force -ErrorAction Stop
# Dot-source internal functions needed by tests
. (Join-Path `$repoRoot "functions\6.Get-WingetUpdate.ps1")
. (Join-Path `$repoRoot "functions\3.Get-KevVulnerabilityStatus.ps1")

"@

# --- Generate Verify-P01.Tests.ps1 test file ---
$verifyP01 = $moduleImport + @'
Describe "ConvertFrom-WingetUpgradeOutput" {
    It "Distinguishes a successful zero-update scan" {
        $output = @(
            "Name             Id               Version Available Source",
            "-----------------------------------------------------------",
            "No installed package found matching input criteria."
        )
        $result = ConvertFrom-WingetUpgradeOutput -Output $output -Stderr $null -ExitCode 0
        $result.Status | Should Be "NoUpdates"
        $result.Items.Count | Should Be 0
        $result.Reason | Should Be "No winget packages have available updates"
    }

    It "Returns available updates from valid output" {
        $output = @(
            "Name             Id               Version Available Source",
            "-----------------------------------------------------------",
            "Example Package  Example.Package  1.0     2.0       winget"
        )
        $result = ConvertFrom-WingetUpgradeOutput -Output $output -Stderr $null -ExitCode 0
        $result.Status | Should Be "UpdatesAvailable"
        $result.Items.Count | Should Be 1
        $result.Items[0].Name | Should Be "Example Package"
        $result.Items[0].Id | Should Be "Example.Package"
        $result.Items[0].InstalledVersion | Should Be "1.0"
        $result.Items[0].AvailableVersion | Should Be "2.0"
    }

    It "Returns ParseError for empty output" {
        $result = ConvertFrom-WingetUpgradeOutput -Output @() -Stderr $null -ExitCode 0
        $result.Status | Should Not Be "NoUpdates"
        $result.Status | Should Be "ParseError"
    }

    It "Multi-word package names parse correctly" {
        $output = @(
            "Name             Id               Version Available Source",
            "-----------------------------------------------------------",
            "Microsoft Edge   Microsoft.Edge   1.0     2.0       winget",
            "Visual Studio Code  Microsoft.VisualStudio.Code   1.1    1.2    winget"
        )
        $result = ConvertFrom-WingetUpgradeOutput -Output $output -Stderr $null -ExitCode 0
        $result.Status | Should Be "UpdatesAvailable"
        $result.Items.Count | Should Be 2
        $result.Items[0].Name | Should Be "Microsoft Edge"
        $result.Items[1].Name | Should Be "Visual Studio Code"
    }

    It "Returns SourceError when output indicates source failure" {
        $output = @(
            "Error: Package source is unavailable",
            "Please check your network connection."
        )
        $result = ConvertFrom-WingetUpgradeOutput -Output $output -Stderr $null -ExitCode 0
        $result.Status | Should Be "SourceError"
        $result.Items.Count | Should Be 0
    }

    It "Returns ParseError for unrecognized successful output" {
        $output = @(
            "Some unexpected successful output",
            "Without known headers"
        )
        $result = ConvertFrom-WingetUpgradeOutput -Output $output -Stderr $null -ExitCode 0
        $result.Status | Should Be "ParseError"
        $result.Items.Count | Should Be 0
    }
}
'@
$verifyP01 | Set-Content -Path (Join-Path $testDir 'Verify-P01.Tests.ps1') -Encoding UTF8

# --- Generate Verify-Winget.Tests.ps1 test file (simple assertions only) ---
$verifyWinget = $moduleImport + @'
Describe "ConvertFrom-WingetUpgradeOutput" {
    It "Distinguishes a successful zero-update scan" {
        $output = @(
            "Name             Id               Version Available Source",
            "-----------------------------------------------------------",
            "No installed package found matching input criteria."
        )
        $result = ConvertFrom-WingetUpgradeOutput -Output $output -Stderr $null -ExitCode 0
        $result.Status | Should Be "NoUpdates"
        $result.Items.Count | Should Be 0
        $result.Reason | Should Be "No winget packages have available updates"
    }

    It "Returns available updates from valid output" {
        $output = @(
            "Name             Id               Version Available Source",
            "-----------------------------------------------------------",
            "Example Package  Example.Package  1.0     2.0       winget"
        )
        $result = ConvertFrom-WingetUpgradeOutput -Output $output -Stderr $null -ExitCode 0
        $result.Status | Should Be "UpdatesAvailable"
        $result.Items.Count | Should Be 1
        $result.Items[0].Name | Should Be "Example Package"
        $result.Items[0].Id | Should Be "Example.Package"
        $result.Items[0].InstalledVersion | Should Be "1.0"
        $result.Items[0].AvailableVersion | Should Be "2.0"
    }

    It "Returns ParseError for empty output" {
        $result = ConvertFrom-WingetUpgradeOutput -Output @() -Stderr $null -ExitCode 0
        $result.Status | Should Not Be "NoUpdates"
        $result.Status | Should Be "ParseError"
    }

    It "Multi-word package names parse correctly" {
        $output = @(
            "Name             Id               Version Available Source",
            "-----------------------------------------------------------",
            "Microsoft Edge   Microsoft.Edge   1.0     2.0       winget",
            "Visual Studio Code  Microsoft.VisualStudio.Code   1.1    1.2    winget"
        )
        $result = ConvertFrom-WingetUpgradeOutput -Output $output -Stderr $null -ExitCode 0
        $result.Status | Should Be "UpdatesAvailable"
        $result.Items.Count | Should Be 2
        $result.Items[0].Name | Should Be "Microsoft Edge"
        $result.Items[1].Name | Should Be "Visual Studio Code"
    }

    It "Returns SourceError when output indicates source failure" {
        $output = @(
            "Error: Package source is unavailable",
            "Please check your network connection."
        )
        $result = ConvertFrom-WingetUpgradeOutput -Output $output -Stderr $null -ExitCode 0
        $result.Status | Should Be "SourceError"
        $result.Items.Count | Should Be 0
    }

    It "Returns ParseError for unrecognized successful output" {
        $output = @(
            "Some unexpected successful output",
            "Without known headers"
        )
        $result = ConvertFrom-WingetUpgradeOutput -Output $output -Stderr $null -ExitCode 0
        $result.Status | Should Be "ParseError"
        $result.Items.Count | Should Be 0
    }
}
'@
$verifyWinget | Set-Content -Path (Join-Path $testDir 'Verify-Winget.Tests.ps1') -Encoding UTF8

Write-Host "Generated test fixtures in $fixtureDir"
Get-ChildItem $fixtureDir | ForEach-Object { Write-Host ("  " + $_.Name) }
Write-Host "Generated test files in $testDir"
Get-ChildItem $testDir -Filter "*.Tests.ps1" | ForEach-Object { Write-Host ("  " + $_.Name) }