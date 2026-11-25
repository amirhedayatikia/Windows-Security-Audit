. "G:\My Drive\My-Projects\Windows-Security-Audit\functions\6.Get-WingetUpdate.ps1"

Write-Host "=== Debug: Source error detection ===" -ForegroundColor Cyan
$output = @(
    'Error: Package source is unavailable',
    'Please check your network connection.'
)
$result = ConvertFrom-WingetUpgradeOutput -Output $output -Stderr $null -ExitCode 0
Write-Host "Result status: $($result.Status)"

Write-Host ""
Write-Host "=== Debug: Multi-word names ===" -ForegroundColor Cyan
$output2 = @(
    'Name             Id               Version Available Source',
    '-----------------------------------------------------------',
    'Microsoft Edge   Microsoft.Edge   1.0     2.0       winget',
    'Visual Studio Code  Microsoft.VisualStudio.Code 1.1  1.2 winget'
)
$result2 = ConvertFrom-WingetUpgradeOutput -Output $output2 -Stderr $null -ExitCode 0
Write-Host "Result status: $($result2.Status)"
Write-Host "Result count: $($result2.Items.Count)"
$result2.Items | ForEach-Object { Write-Host "  Name: '$($_.Name)', Id: '$($_.Id)'" }
