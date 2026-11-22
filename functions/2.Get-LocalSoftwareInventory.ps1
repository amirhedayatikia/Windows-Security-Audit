function Get-LocalSoftwareInventory {
    <#
    .SYNOPSIS
        Gets inventory of installed software on the system.

    .OUTPUTS
        Array of PSCustomObject with Name, Version, Publisher, Source
    #>
    $apps = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    ) | Get-ItemProperty -ErrorAction SilentlyContinue | Where-Object DisplayName |
      Select-Object @{n='Name';e={$_.DisplayName}}, @{n='Version';e={$_.DisplayVersion}}, @{n='Publisher';e={$_.Publisher}}, @{n='Source';e={'Registry'}}

    # Add winget packages
    try {
        $winget = winget list --source winget 2>$null
        $wingetApps = $winget | Select-Object -Skip 2 | Where-Object { $_ -match '\S' }
        foreach ($app in $wingetApps) {
            $parts = $app -split '\s+', 4
            if ($parts.Count -ge 2) {
                $name = $parts[0]
                $version = if ($parts.Count -ge 3) { $parts[2] } else { 'N/A' }
                $apps += [PSCustomObject]@{Name=$name; Version=$version; Publisher='Unknown'; Source='winget'}
            }
        }
    } catch { }

    $apps | Sort-Object Name -Unique
}