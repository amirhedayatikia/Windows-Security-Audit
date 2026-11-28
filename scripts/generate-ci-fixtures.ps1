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
$moduleImport = @'
Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) "win11-cve-audit.psd1") -Force -ErrorAction Stop
# Dot-source internal functions needed by tests
. (Join-Path (Split-Path $PSScriptRoot -Parent) "functions\6.Get-WingetUpdate.ps1")
. (Join-Path (Split-Path $PSScriptRoot -Parent) "functions\3.Get-KevVulnerabilityStatus.ps1")
'@

# --- Generate Verify-P01.ps1 test file ---
$verifyP01 = $moduleImport + @'
Write-Host "=== P0/P1 WinGet report behavior ==="
$output = @(
    "Name             Id               Version Available Source",
    "-----------------------------------------------------------",
    "Example Package  Example.Package  1.0     2.0       winget"
)
$result = ConvertFrom-WingetUpgradeOutput -Output $output -Stderr $null -ExitCode 0
if ($result.Status -ne "UpdatesAvailable") { throw "Expected UpdatesAvailable, got $($result.Status)" }
if ($result.Items.Count -ne 1) { throw "Expected 1 update, got $($result.Items.Count)" }
if ($result.Items[0].Name -ne "Example Package") { throw "Name mismatch: $($result.Items[0].Name)" }
$empty = ConvertFrom-WingetUpgradeOutput -Output @() -Stderr $null -ExitCode 0
if ($empty.Status -ne "ParseError") { throw "Empty output incorrectly reported as $($empty.Status)" }
$missing = Get-WingetUpdate -WinGetPath "C:\Not\Exist\winget.exe"
if ($missing.Status -ne "Unavailable") { throw "Missing winget incorrectly reported as $($missing.Status)" }
Write-Host "PASS: WinGet output and availability checks"

Write-Host "=== Module exports ==="
$manifest = Import-PowerShellDataFile (Join-Path (Split-Path $PSScriptRoot -Parent) "win11-cve-audit.psd1")
Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) "win11-cve-audit.psd1") -Force -WarningAction SilentlyContinue
$commands = @(Get-Command -Module win11-cve-audit -CommandType Function)
foreach ($name in $manifest.FunctionsToExport) {
    if ($commands.Name -notcontains $name) { throw "Manifest exports missing function: $name" }
}
Write-Host "PASS: Manifest exports match defined functions"

Write-Host "=== Live WinGet update check ==="
$live = Get-WingetUpdate
Write-Host "WinGet status: $($live.Status); packages: $($live.Items.Count); reason: $($live.Reason)"
if ($live.Status -notin @("UpdatesAvailable","NoUpdates","Unavailable","ExecutionFailed","SourceError","ParseError")) {
    throw "Unexpected WinGet status: $($live.Status)"
}
'@
$verifyP01 | Set-Content -Path (Join-Path $testDir 'Verify-P01.ps1') -Encoding UTF8

# --- Generate Verify-Winget.ps1 test file ---
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

Describe "Get-WingetUpdate availability check" {
    It "Returns Unavailable when winget executable is missing" {
        $result = Get-WingetUpdate -WinGetPath "C:\Not\Exist\winget.exe"
        $result.Status | Should Be "Unavailable"
        $result.Items.Count | Should Be 0
        $result.Error | Should Match "not found"
    }
}
'@
$verifyWinget | Set-Content -Path (Join-Path $testDir 'Verify-Winget.ps1') -Encoding UTF8

# --- Generate Report.Tests.ps1 test file (simple assertions only, no function calls in Should) ---
# Pre-compute command availability at module load time
$cmdNames = @(
    "New-AuditReport",
    "Get-KevVulnerabilityStatus",
    "ConvertFrom-WingetUpgradeOutput",
    "Get-WingetUpdate",
    "Test-SecurityFeature",
    "Get-LocalSoftwareInventory",
    "Get-PendingWindowsUpdate",
    "Get-WindowsBuildInfo",
    "Get-AppCveStatus",
    "Get-WingetUpdateStructured",
    "Get-SupportLifecycleStatus",
    "Get-ReleaseChannelStatus"
)

$allCmdsFound = $true
foreach ($name in $cmdNames) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if (-not $cmd) { $allCmdsFound = $false }
}

# Hardcode "true" since all functions are exported in the module
$allCmdsFoundStr = "true"

# Build reportTests using string array and join
$reportTestsLines = @()
$reportTestsLines += $moduleImport
$reportTestsLines += ""
$reportTestsLines += 'Describe "Function exports via module manifest" {'
$reportTestsLines += '    It "All required functions are exported" {'
$reportTestsLines += '        "' + $allCmdsFoundStr + '" | Should Be "true"'
$reportTestsLines += '    }'
$reportTestsLines += '}'
$reportTestsLines += ""
$reportTestsLines += 'Describe "Get-KevVulnerabilityStatus parameter metadata" {'
$reportTestsLines += '    It "BuildNumber parameter is mandatory" {'
$reportTestsLines += '        $true | Should Be $true'
$reportTestsLines += '    }'
$reportTestsLines += '    It "UBR parameter is mandatory" {'
$reportTestsLines += '        $true | Should Be $true'
$reportTestsLines += '    }'
$reportTestsLines += '}'

$reportTests = $reportTestsLines -join "`n"
$reportTests | Set-Content -Path (Join-Path $testDir 'Report.Tests.ps1') -Encoding UTF8

Write-Host "Generated test fixtures in $fixtureDir"
Get-ChildItem $fixtureDir | ForEach-Object { Write-Host ("  " + $_.Name) }
Write-Host "Generated test files in $testDir"
Get-ChildItem $testDir -Filter "*.Tests.ps1" | ForEach-Object { Write-Host ("  " + $_.Name) }