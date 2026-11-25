Describe 'ConvertFrom-WingetUpgradeOutput' {
    BeforeAll {
        Import-Module "G:\My Drive\My-Projects\Windows-Security-Audit\functions\6.Get-WingetUpdate.ps1" -Force -ErrorAction Stop
    }

    It 'Distinguishes a successful zero-update scan' {
        $output = @(
            'Name             Id               Version Available Source',
            '-----------------------------------------------------------',
            'No installed package found matching input criteria.'
        )
        $result = ConvertFrom-WingetUpgradeOutput -Output $output -Stderr $null -ExitCode 0
        $result.Status | Should Be 'NoUpdates'
        $result.Items.Count | Should Be 0
        $result.Reason | Should Be 'No winget packages have available updates'
    }

    It 'Returns available updates from valid output' {
        $output = @(
            'Name             Id               Version Available Source',
            '-----------------------------------------------------------',
            'Example Package  Example.Package  1.0     2.0       winget'
        )
        $result = ConvertFrom-WingetUpgradeOutput -Output $output -Stderr $null -ExitCode 0
        $result.Status | Should Be 'UpdatesAvailable'
        $result.Items.Count | Should Be 1
        $result.Items[0].Name | Should Be 'Example Package'
        $result.Items[0].Id | Should Be 'Example.Package'
        $result.Items[0].InstalledVersion | Should Be '1.0'
        $result.Items[0].AvailableVersion | Should Be '2.0'
    }

    It 'Returns ParseError for empty output' {
        $result = ConvertFrom-WingetUpgradeOutput -Output @() -Stderr $null -ExitCode 0
        $result.Status | Should Not Be 'NoUpdates'
        $result.Status | Should Be 'ParseError'
    }

    It 'Multi-word package names parse correctly' {
        $output = @(
            'Name             Id               Version Available Source',
            '-----------------------------------------------------------',
            'Microsoft Edge   Microsoft.Edge   1.0     2.0       winget',
            'Visual Studio Code  Microsoft.VisualStudio.Code 1.1  1.2 winget'
        )
        $result = ConvertFrom-WingetUpgradeOutput -Output $output -Stderr $null -ExitCode 0
        $result.Status | Should Be 'UpdatesAvailable'
        $result.Items.Count | Should Be 2
        $result.Items[0].Name | Should Be 'Microsoft Edge'
        $result.Items[1].Name | Should Be 'Visual Studio Code'
    }

    It 'Returns SourceError when output indicates source failure' {
        $output = @(
            'Error: Package source is unavailable',
            'Please check your network connection.'
        )
        $result = ConvertFrom-WingetUpgradeOutput -Output $output -Stderr $null -ExitCode 0
        $result.Status | Should Be 'SourceError'
        $result.Items.Count | Should Be 0
    }

    It 'Returns ParseError for unrecognized successful output' {
        $output = @(
            'Some unexpected successful output',
            'Without known headers'
        )
        $result = ConvertFrom-WingetUpgradeOutput -Output $output -Stderr $null -ExitCode 0
        $result.Status | Should Be 'ParseError'
        $result.Items.Count | Should Be 0
    }
}

Describe 'Get-WingetUpdate availability check' {
    BeforeAll {
        Import-Module "G:\My Drive\My-Projects\Windows-Security-Audit\functions\6.Get-WingetUpdate.ps1" -Force -ErrorAction Stop
    }

    It 'Returns Unavailable when winget executable is missing' {
        $result = Get-WingetUpdate -WinGetPath 'C:\Not\Exist\winget.exe'
        $result.Status | Should Be 'Unavailable'
        $result.Items.Count | Should Be 0
        $result.Error | Should Match 'not found'
    }
}
