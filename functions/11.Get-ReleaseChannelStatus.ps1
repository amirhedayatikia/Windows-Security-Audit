function Get-ReleaseChannelStatus {
    <#
    .SYNOPSIS
        Detects Windows release channel (Insider/Release/Preview) from registry.

    .DESCRIPTION
        Queries registry keys that indicate the Windows release channel:
        - Windows Insider Program channel (Dev, Beta, Release Preview)
        - Release channel (standard retail/Volume Licensing)

    .OUTPUTS
        PSCustomObject with Channel, IsInsider, InsiderRing, Evidence, Source, Timestamp, Confidence
    #>
    [CmdletBinding()]
    param()

    $now     = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
    $source  = "Registry"

    # Insider channel registry locations
    $insiderPaths = @(
        @{ Path = "HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\UI\State"; ValueName = "Ring" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\UX\Settings"; ValueName = "Channel" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State\"; ValueName = "ImageState" }
    )

    $channel = "Release"
    $isInsider = $false
    $insiderRing = $null
    $evidence = @()

    foreach ($p in $insiderPaths) {
        try {
            $prop = Get-ItemProperty -Path $p.Path -Name $p.ValueName -ErrorAction Stop
            $val = $prop.$($p.ValueName)
            if ($null -ne $val -and $val -ne '') {
                $evidence += "$($p.Path)\$($p.ValueName) = $val"
                if ($val -match '(?i)dev|beta|release.?preview|insider') {
                    $channel = $val
                    $isInsider = $true
                    $insiderRing = $val
                }
            }
        } catch {
            # Key not found - try next path
        }
    }

    # Check for Insider-specific policy keys
    try {
        $insiderPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\UI\State" -ErrorAction SilentlyContinue
        if ($insiderPolicy -and $insiderPolicy.Ring) {
            $evidence += "Insider ring detected: $($insiderPolicy.Ring)"
            $channel = $insiderPolicy.Ring
            $isInsider = $true
            $insiderRing = $insiderPolicy.Ring
        }
    } catch {
        # Ignore
    }

    if ($isInsider) {
        $summary = "Windows Insider channel: $channel"
    } else {
        $summary = "Standard release channel"
    }

    return [PSCustomObject]@{
        CheckId      = "REL-CH-001"
        Name         = "Release Channel"
        Channel      = $channel
        IsInsider    = $isInsider
        InsiderRing  = $insiderRing
        Summary      = $summary
        Reason       = "Release channel detected from registry: $channel"
        Evidence     = $evidence
        Source       = $source
        Timestamp    = $now
        Confidence   = "High"
        Items        = @()
        Error        = $null
    }
}
