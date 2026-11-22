function Get-WingetUpdate {
    <#
    .SYNOPSIS
        Gets available winget updates.

    .OUTPUTS
        Array of PSCustomObject with Name, Id, InstalledVersion, AvailableVersion, Source
    #>
    try {
        $output = winget upgrade --disable-interactivity 2>$null
        if (-not $output) { return @() }

        # winget pads columns to fixed offsets; locate them from the header line
        $header = $output | Where-Object { $_ -match '^\s*Name\s+Id\s+Version\s+Available' } | Select-Object -First 1
        if (-not $header) { return @() }

        $nameCol  = $header.IndexOf('Name')
        $idCol    = $header.IndexOf('Id')
        $verCol   = $header.IndexOf('Version')
        $availCol = $header.IndexOf('Available')
        $srcCol   = $header.IndexOf('Source')

        $results = foreach ($line in $output) {
            if (-not $line -or $line -eq $header) { continue }
            if ($line -match '^[-\s]*$') { continue }    # separator / blank
            if ($line.Length -lt $srcCol) { continue }   # summary lines ("N upgrades available.")

            $name  = $line.Substring($nameCol,  [Math]::Min($idCol  - $nameCol,  $line.Length - $nameCol)).Trim()
            $id    = $line.Substring($idCol,    [Math]::Min($verCol - $idCol,    $line.Length - $idCol)).Trim()
            $inst  = $line.Substring($verCol,   [Math]::Min($availCol - $verCol, $line.Length - $verCol)).Trim()
            if ($srcCol -gt $availCol) {
                $avail = $line.Substring($availCol, [Math]::Min($srcCol - $availCol, $line.Length - $availCol)).Trim()
            } else {
                $avail = $line.Substring($availCol).Trim()
            }

            if (-not $id -or -not $inst -or -not $avail) { continue }

            [PSCustomObject]@{
                Name             = $name
                Id               = $id
                InstalledVersion = $inst
                AvailableVersion = $avail
                Source           = 'winget'
            }
        }

        return @($results | Where-Object { $_ -ne $null })
    } catch {
        Write-Error "Failed to get winget updates: $_"
        return @()
    }
}
