[CmdletBinding()]
param(
    [string]$PesterModulePath
)

$ErrorActionPreference = 'Stop'

if ($PesterModulePath) {
    Import-Module $PesterModulePath -Force
} elseif (-not (Get-Module -ListAvailable -Name Pester | Where-Object { $_.Version.Major -ge 5 })) {
    throw 'Pester 5 or later is required. Install with: Install-Module -Name Pester -Force -Scope CurrentUser'
}

Import-Module Pester -MinimumVersion 5.0 -Force

$config = New-PesterConfiguration
$config.Run.Path = Join-Path $PSScriptRoot 'WinGet.Tests.ps1'
$config.Output.Verbosity = 'Detailed'

$result = Invoke-Pester -Configuration $config

if ($result.FailedCount -gt 0) {
    Write-Error "$($result.FailedCount) test(s) failed"
    exit 1
}
Write-Host "All Pester regression tests passed"
