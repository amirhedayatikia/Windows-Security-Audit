# Standalone verification script for Get-WingetUpdate
# No Pester dependency - runs directly with PowerShell 5.1+

$errors = @()

function Assert-Equal {
    param($Actual, $Expected, $Message)
    if ($Actual -ne $Expected) {
        $errors += "FAIL: $Message - Expected '$Expected', got '$Actual'"
        Write-Host "  FAIL: $Message - Expected '$Expected', got '$Actual'" -ForegroundColor Red
    } else {
        Write-Host "  PASS: $Message" -ForegroundColor Green
    }
}

function Assert-NotEqual {
    param($Actual, $NotExpected, $Message)
    if ($Actual -eq $NotExpected) {
        $errors += "FAIL: $Message - Expected NOT '$NotExpected', got '$Actual'"
        Write-Host "  FAIL: $Message - Expected NOT '$NotExpected', got '$Actual'" -ForegroundColor Red
    } else {
        Write-Host "  PASS: $Message" -ForegroundColor Green
    }
}

# Dot-source the function
. "$PSScriptRoot\..\functions\6.Get-WingetUpdate.ps1"

Write-Host "=== ConvertFrom-WingetUpgradeOutput Tests ===" -ForegroundColor Cyan

# Test 1: Zero updates
$result = ConvertFrom-WingetUpgradeOutput -Output @(
    'Name             Id               Version Available Source',
    '-----------------------------------------------------------',
    'No installed package found matching input criteria.'
) -Stderr $null -ExitCode 0
Assert-Equal $result.Status 'NoUpdates' 'Zero updates should be NoUpdates'
Assert-Equal $result.Items.Count 0 'Zero updates should have 0 items'

# Test 2: Available updates
$result = ConvertFrom-WingetUpgradeOutput -Output @(
    'Name             Id               Version Available Source',
    '-----------------------------------------------------------',
    'Example Package  Example.Package  1.0     2.0       winget'
) -Stderr $null -ExitCode 0
Assert-Equal $result.Status 'UpdatesAvailable' 'Available updates should be UpdatesAvailable'
Assert-Equal $result.Items.Count 1 'Should have 1 item'
Assert-Equal $result.Items[0].Name 'Example Package' 'Package name should match'
Assert-Equal $result.Items[0].InstalledVersion '1.0' 'Installed version should match'
Assert-Equal $result.Items[0].AvailableVersion '2.0' 'Available version should match'

# Test 3: Empty output
$result = ConvertFrom-WingetUpgradeOutput -Output @() -Stderr $null -ExitCode 0
Assert-Equal $result.Status 'ParseError' 'Empty output should be ParseError'
Assert-NotEqual $result.Status 'NoUpdates' 'Empty output should NOT be NoUpdates'

# Test 4: Multi-word names
$result = ConvertFrom-WingetUpgradeOutput -Output @(
    'Name             Id               Version Available Source',
    '-----------------------------------------------------------',
    'Microsoft Edge   Microsoft.Edge   1.0     2.0       winget',
    'Visual Studio Code  Microsoft.VisualStudio.Code   1.1    1.2    winget'
) -Stderr $null -ExitCode 0
Assert-Equal $result.Status 'UpdatesAvailable' 'Multi-word names should be UpdatesAvailable'
Assert-Equal $result.Items.Count 2 'Should have 2 items'
Assert-Equal $result.Items[0].Name 'Microsoft Edge' 'First package name should match'
Assert-Equal $result.Items[1].Name 'Visual Studio Code' 'Second package name should match'

# Test 5: Source error
$result = ConvertFrom-WingetUpgradeOutput -Output @(
    'Error: Package source is unavailable',
    'Please check your network connection.'
) -Stderr $null -ExitCode 0
Assert-Equal $result.Status 'SourceError' 'Source failure should be SourceError'

# Test 6: Unrecognized output
$result = ConvertFrom-WingetUpgradeOutput -Output @(
    'Some unexpected successful output',
    'Without known headers'
) -Stderr $null -ExitCode 0
Assert-Equal $result.Status 'ParseError' 'Unrecognized output should be ParseError'

Write-Host ""
Write-Host "=== Get-WingetUpdate availability check ===" -ForegroundColor Cyan

# Test 7: Missing winget
$result = Get-WingetUpdate -WinGetPath 'C:\Not\Exist\winget.exe'
Assert-Equal $result.Status 'Unavailable' 'Missing winget should be Unavailable'
Assert-Equal $result.Items.Count 0 'Should have 0 items'

Write-Host ""
if ($errors.Count -gt 0) {
    Write-Host "=== $($errors.Count) TEST(S) FAILED ===" -ForegroundColor Red
    exit 1
} else {
    Write-Host "=== ALL TESTS PASSED ===" -ForegroundColor Green
    exit 0
}
