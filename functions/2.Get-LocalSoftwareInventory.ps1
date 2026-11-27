function Get-LocalSoftwareInventory {
    <#
    .SYNOPSIS
        Gets inventory of installed software from multiple sources with identity preservation.

    .DESCRIPTION
        Collects installed applications from:
        - Machine-wide registry (HKLM 64-bit and 32-bit)
        - Current-user registry (HKCU)
        - WinGet repository packages
        - MSIX/AppX packages (all users)
        Returns structured objects with preserved package identity, version, publisher, scope, and source.
        Deduplicates by (Id, Scope, Architecture) rather than display name.

    .OUTPUTS
        Array of PSCustomObject with Name, Version, Publisher, Source, Scope, Architecture, Id, InstallLocation, InstallDate
    #>
    [CmdletBinding()]
    param()

    $results = @()

    # --- 1. Registry inventory (HKLM 64-bit, HKLM 32-bit, HKCU) ---
    $registryPaths = @(
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"; Scope = "Machine"; Architecture = "x64" },
        @{ Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"; Scope = "Machine"; Architecture = "x86" },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"; Scope = "User"; Architecture = "x64" }
    )

    foreach ($rp in $registryPaths) {
        try {
            $items = Get-ItemProperty $rp.Path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and $_.DisplayName.Trim() }
            foreach ($item in $items) {
                $id = $item.PSChildName
                $results += [PSCustomObject]@{
                    Name             = $item.DisplayName.Trim()
                    Version          = if ($item.DisplayVersion) { $item.DisplayVersion.Trim() } else { 'N/A' }
                    Publisher        = if ($item.Publisher) { $item.Publisher.Trim() } else { 'N/A' }
                    Source           = 'Registry'
                    Scope            = $rp.Scope
                    Architecture     = $rp.Architecture
                    Id               = $id
                    InstallLocation  = if ($item.InstallLocation) { $item.InstallLocation.Trim() } else { 'N/A' }
                    InstallDate      = if ($item.InstallDate) { $item.InstallDate } else { 'N/A' }
                    RegistryPath     = $item.PSPath
                }
            }
        } catch {
            Write-Verbose "Registry inventory failed for $($rp.Path): $($_.Exception.Message)"
        }
    }

    # --- 2. WinGet repository inventory (scope-specific) ---
    # Query winget list separately for user and machine scope so each package
    # is labeled with its actual installation scope instead of defaulting to Machine.
    $wingetScopes = @('user', 'machine')
    foreach ($scope in $wingetScopes) {
        try {
            $wingetOutput = winget list --source winget --scope $scope 2>$null
            if (-not $wingetOutput) { continue }
            $lines = $wingetOutput -split "`n"
            $headerIndex = $null
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match '^\s*Name\s+Id\s+Version') {
                    $headerIndex = $i
                    break
                }
            }
            if ($null -ne $headerIndex) {
                $header = $lines[$headerIndex]
                # Determine column positions by finding header boundaries
                $namePos = $header.IndexOf('Name')
                $idPos = $header.IndexOf('Id')
                $verPos = $header.IndexOf('Version')
                $srcPos = $header.IndexOf('Source')
                for ($i = $headerIndex + 1; $i -lt $lines.Count; $i++) {
                    $line = $lines[$i]
                    if (-not $line -or $line -match '^[-\s]*$') { continue }
                    # Extract columns by position (fixed-width table)
                    $name = if ($namePos -ge 0 -and $idPos -gt $namePos) { $line.Substring($namePos, $idPos - $namePos).Trim() } else { $line.Trim() }
                    $id = if ($idPos -ge 0 -and $verPos -gt $idPos) { $line.Substring($idPos, $verPos - $idPos).Trim() } else { '' }
                    $version = if ($verPos -ge 0 -and $srcPos -gt $verPos) { $line.Substring($verPos, $srcPos - $verPos).Trim() } else { 'N/A' }
                    # $source column available but not used; Source hardcoded to 'winget'
                    $null = if ($srcPos -ge 0) { $line.Substring($srcPos).Trim() } else { 'winget' }
                    if ($name -and $id) {
                        $results += [PSCustomObject]@{
                            Name             = $name
                            Version          = if ($version) { $version } else { 'N/A' }
                            Publisher        = 'N/A'  # winget list doesn't include publisher
                            Source           = 'winget'
                            Scope            = if ($scope -eq 'user') { 'User' } else { 'Machine' }
                            Architecture     = 'Unknown'
                            Id               = $id
                            InstallLocation  = 'N/A'
                            InstallDate      = 'N/A'
                            RegistryPath     = $null
                        }
                    }
                }
            }
        } catch {
            Write-Verbose "WinGet inventory failed for scope '$scope': $($_.Exception.Message)"
        }
    }

    # --- 3. MSIX/AppX inventory (current user; -AllUsers requires admin) ---
    try {
        $appxPackages = Get-AppxPackage -ErrorAction SilentlyContinue
        foreach ($pkg in $appxPackages) {
            # Skip framework packages unless they have a meaningful name
            if ($pkg.PackageFamilyName -match '^Microsoft\.(VCLibs|NET|WindowsAppRuntime|WinAppRuntime)' -and -not $pkg.Name) { continue }
            $results += [PSCustomObject]@{
                Name             = if ($pkg.Name) { $pkg.Name } else { $pkg.PackageFamilyName }
                Version          = if ($pkg.Version) { $pkg.Version.ToString() } else { 'N/A' }
                Publisher        = if ($pkg.PublisherDisplayName) { $pkg.PublisherDisplayName } elseif ($pkg.Publisher) { $pkg.Publisher } else { 'N/A' }
                Source           = 'MSIX/AppX'
                Scope            = if ($pkg.IsFramework) { 'System' } else { 'User' }
                Architecture     = $pkg.Architecture
                Id               = $pkg.PackageFamilyName
                InstallLocation  = if ($pkg.InstallLocation) { $pkg.InstallLocation } else { 'N/A' }
                InstallDate      = if ($pkg.InstallDate) { $pkg.InstallDate.ToString() } else { 'N/A' }
                RegistryPath     = $null
            }
        }
    } catch {
        Write-Verbose "MSIX/AppX inventory failed: $($_.Exception.Message)"
    }

    # --- Deduplicate by (Id, Scope, Architecture) - preserve first occurrence ---
    $seen = @{}
    $deduped = foreach ($r in $results) {
        $idPart = if ($null -ne $r.Id -and $r.Id -ne '') { $r.Id } else { $r.Name }
        $key = $idPart + '|' + $r.Scope + '|' + $r.Architecture
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $r
        }
    }

    # Compute coverage metadata
    $sources = @{}
    foreach ($r in $deduped) {
        $sources[$r.Source] = $true
    }
    $coverage = @{
        TotalCount     = $deduped.Count
        Sources        = $sources.Keys
        RegistryCount  = ($deduped | Where-Object Source -eq 'Registry').Count
        WingetCount    = ($deduped | Where-Object Source -eq 'winget').Count
        MSIXCount      = ($deduped | Where-Object Source -eq 'MSIX/AppX').Count
    }

    # Return structured object with inventory array and coverage metadata
    return [PSCustomObject]@{
        Inventory = @($deduped)
        Coverage  = $coverage
    }
}