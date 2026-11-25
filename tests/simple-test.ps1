. "$PSScriptRoot\..\functions\6.Get-WingetUpdate.ps1"

Describe 'simple test' {
    It 'test ConvertFrom-WingetUpgradeOutput' {
        $output = @('Name Id Version Available Source','-----------------------------------------------------------','No installed package found matching input criteria.')
        $result = ConvertFrom-WingetUpgradeOutput -Output $output -Stderr $null -ExitCode 0
        $result.Status | Should Be 'NoUpdates'
    }
}
