. "G:\My Drive\My-Projects\Windows-Security-Audit\functions\6.Get-WingetUpdate.ps1"
$output = @('Name Id Version Available Source','-----------------------------------------------------------','No installed package found matching input criteria.')
$combined = ''
if ($output -is [array]) {
    $dataRows = $output | Where-Object { $_ -notmatch '^\s*Name\s+Id\s+Version\s+Available' -and $_ -notmatch '^[-\s]*$' }
    if ($dataRows) { $combined = $dataRows -join "`n" }
}
Write-Output ('combined=' + $combined)
Write-Output ('match=' + ($combined -match 'source|network|unavailable|error'))
$result = ConvertFrom-WingetUpgradeOutput -Output $output -Stderr $null -ExitCode 0
Write-Output ('status=' + $result.Status)
