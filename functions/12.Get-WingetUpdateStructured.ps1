function Get-WingetUpdateStructured {
    <#
    .SYNOPSIS
        Gets available winget package updates using the Microsoft.WinGet.Client module when available.

    .DESCRIPTION
        Attempts to use the Microsoft.WinGet.Client PowerShell module for structured
        package update queries. Falls back to console winget output parsing if the
        module is not available. Read-only: never modifies packages or sources.

    .OUTPUTS
        PSCustomObject with Status, Items, Reason, Error, Timestamp, Confidence, Source
        Status values:
          UpdatesAvailable  - structured API reported upgrades
          NoUpdates         - structured API reported no upgrades
          Unavailable       - neither module nor console winget available
          ExecutionFailed   - API call failed
          SourceError       - source/network error
          ParseError        - output could not be parsed
    #>
    [CmdletBinding()]
    param()

    $now  = Get-Date
    $source = 'winget'

    # Try the structured Microsoft.WinGet.Client API first
    try {
        $module = Get-Module -ListAvailable -Name 'Microsoft.WinGet.Client' -ErrorAction Stop
        if ($module) {
            Import-Module 'Microsoft.WinGet.Client' -Force -ErrorAction Stop -ErrorAction SilentlyContinue
            $cmd = Get-Command -Module 'Microsoft.WinGet.Client' -Name 'Get-WinGetPackage' -ErrorAction SilentlyContinue
            if ($cmd) {
                $packages = & $cmd -ErrorAction SilentlyContinue
                if ($packages) {
                    $updates = @()
                    foreach ($pkg in $packages) {
                        $installed = if ($pkg.InstalledVersion) { $pkg.InstalledVersion.ToString() } else { 'N/A' }
                        $available = if ($pkg.AvailableVersion) { $pkg.AvailableVersion.ToString() } else { 'N/A' }
                        if ($available -ne 'N/A' -and $available -ne $installed) {
                            $updates += [PSCustomObject]@{
                                Name             = if ($pkg.Name) { $pkg.Name.ToString() } else { 'N/A' }
                                Id               = if ($pkg.PackageId) { $pkg.PackageId.ToString() } else { 'N/A' }
                                InstalledVersion = $installed
                                AvailableVersion = $available
                                Source           = 'winget'
                            }
                        }
                    }
                    if ($updates.Count -gt 0) {
                        return [PSCustomObject]@{
                            Status         = 'UpdatesAvailable'
                            Items          = @($updates)
                            Reason         = "$($updates.Count) winget package(s) with updates available (structured API)"
                            Error          = $null
                            Timestamp      = $now
                            Confidence     = 'High'
                            Source         = $source
                        }
                    }
                    return [PSCustomObject]@{
                        Status         = 'NoUpdates'
                        Items          = @()
                        Reason         = 'No winget packages have available updates (structured API)'
                        Error          = $null
                        Timestamp      = $now
                        Confidence     = 'High'
                        Source         = $source
                    }
                }
            }
        }
    } catch {
        # Fall through to console winget
        Write-Verbose "Structured WinGet API unavailable, falling back to console: $($_.Exception.Message)"
    }

    # Fall back to console winget upgrade
    $wingetPath = 'winget'
    if (-not (Get-Command $wingetPath -ErrorAction SilentlyContinue)) {
        return [PSCustomObject]@{
            Status         = 'Unavailable'
            Items          = @()
            Reason         = 'winget executable not found'
            Error          = "The 'winget' executable is not available on this machine."
            Timestamp      = $now
            Confidence     = 'High'
            Source         = $source
        }
    }

    return $null  # Signals caller to use console parsing fallback
}
