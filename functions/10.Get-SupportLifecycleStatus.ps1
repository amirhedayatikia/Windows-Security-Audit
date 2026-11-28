function Get-SupportLifecycleStatus {
    <#
    .SYNOPSIS
        Gets Windows support lifecycle status from endoflife.date API.

    .DESCRIPTION
        Queries the endoflife.date public API for Windows 11 support lifecycle
        information, including release date, end of life date, and whether the
        current release is still supported. Read-only: queries a public API only.

    .PARAMETER Product
        Product name to query (default: windows). endoflife.date uses 'windows' for Windows.

    .PARAMETER Version
        Specific Windows version to check (e.g., '24h2', '23h2'). If omitted, the
        latest Windows release is returned.

    .OUTPUTS
        PSCustomObject with Product, Version, ReleaseDate, EndOfLifeDate, IsSupported,
        Status, Reason, Evidence, Source, Timestamp, Confidence, Error
    #>
    [CmdletBinding()]
    param(
        [string]$Product = 'windows',
        [string]$Version = ''
    )

    $checkId = "SUPPORT-LC-001"
    $source  = "endoflife.date API"
    $now     = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
    $url     = "https://endoflife.date/api/$Product.json"

    try {
        $data = Invoke-AuditRestMethod -Uri $url -TimeoutSec 30
        if (-not $data) {
            return [PSCustomObject]@{
                CheckId    = $checkId
                Name       = "Support Lifecycle"
                Status     = "ERROR"
                Severity   = "Medium"
                Summary    = "Unable to determine support lifecycle status"
                Reason     = "endoflife.date API returned no data for product '$Product'"
                Evidence   = @("API response: empty")
                Source     = $source
                Timestamp  = $now
                Confidence = "N/A"
                Items      = @()
                Error      = "Empty API response"
            }
        }

        $releases = @($data)
        $selected = $null

        if ([string]::IsNullOrWhiteSpace($Version)) {
            $selected = $releases[0]
        } else {
            $selected = $releases | Where-Object { $_.cycle -eq $Version } | Select-Object -First 1
            if (-not $selected) {
                return [PSCustomObject]@{
                    CheckId    = $checkId
                    Name       = "Support Lifecycle"
                    Status     = "UNKNOWN"
                    Severity   = "Medium"
                    Summary    = "Windows version '$Version' not found in endoflife.date data"
                    Reason     = "Requested version not available in lifecycle data; $($releases.Count) release(s) known"
                    Evidence   = @("Available versions: $($releases.cycle -join ', ')")
                    Source     = $source
                    Timestamp  = $now
                    Confidence = "High"
                    Items      = @($releases | ForEach-Object { [PSCustomObject]@{ Version = $_.cycle; ReleaseDate = $_.releaseDate; EndOfLife = $_.eol } })
                    Error      = $null
                }
            }
        }

        $eolDate = if ($selected.eol) { [datetime]$selected.eol } else { $null }
        $today       = Get-Date

        $isSupported = $false
        if ($eolDate -and $today -lt $eolDate) { $isSupported = $true }

        $status = if ($isSupported) { "PASS" } else { "FAIL" }
        $summary = if ($isSupported) {
            "Windows $($selected.cycle) is supported (EOL: $($selected.eol))"
        } else {
            "Windows $($selected.cycle) is past end of life (EOL: $($selected.eol))"
        }

        $items = @([PSCustomObject]@{
            Version        = if ($selected.cycle) { $selected.cycle } else { 'N/A' }
            ReleaseDate    = if ($selected.releaseDate) { $selected.releaseDate } else { 'N/A' }
            EndOfLifeDate  = if ($selected.eol) { $selected.eol } else { 'N/A' }
            IsSupported    = $isSupported
            Latest         = if ($selected.latest) { $selected.latest } else { 'N/A' }
        })

        return [PSCustomObject]@{
            CheckId    = $checkId
            Name       = "Support Lifecycle"
            Status     = $status
            Severity   = if ($isSupported) { "Informational" } else { "High" }
            Summary    = $summary
            Reason     = "endoflife.date reports Windows $($selected.cycle) EOL date: $($selected.eol); current date: $(Get-Date -Format 'yyyy-MM-dd')"
            Evidence   = @(
                "Version: $($selected.cycle)",
                "Release date: $($selected.releaseDate)",
                "End of life: $($selected.eol)",
                "Is supported: $isSupported"
            )
            Source     = $source
            Timestamp  = $now
            Confidence = "High"
            Items      = $items
            Error      = $null
        }
    } catch {
        return [PSCustomObject]@{
            CheckId    = $checkId
            Name       = "Support Lifecycle"
            Status     = "ERROR"
            Severity   = "Medium"
            Summary    = "Unable to determine support lifecycle status"
            Reason     = "endoflife.date API query failed: $($_.Exception.Message)"
            Evidence   = @($_.Exception.Message)
            Source     = $source
            Timestamp  = $now
            Confidence = "N/A"
            Items      = @()
            Error      = $_.Exception.Message
        }
    }
}
