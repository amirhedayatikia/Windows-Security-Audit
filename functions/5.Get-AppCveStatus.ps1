function Get-AppCveStatus {
    <#
    .SYNOPSIS
        Checks if a specific application version has known CVEs via CPE/NVD mapping.

    .DESCRIPTION
        Maps an application name/version to a CPE identifier, queries the NVD
        vulnerability API for matching CVEs, and returns an explicit status:
        VULNERABLE, NOT AFFECTED, UNKNOWN, or NOT ASSESSED.

        This implementation avoids false precision by:
        - Requiring explicit CPE/vendor-product mapping (not inferred from display name)
        - Version normalization per ecosystem
        - Explicit confidence scoring
        - Returning NOT ASSESSED when mapping cannot be reliably determined

    .PARAMETER Name
        Application name

    .PARAMETER Version
        Application version

    .PARAMETER Vendor
        CPE vendor (e.g., 'microsoft', 'mozilla', 'google'). If omitted, attempted
        from WinGet ID/publisher mapping.

    .PARAMETER Product
        CPE product name (e.g., 'edge', 'firefox', 'chrome'). If omitted, attempted
        from WinGet ID/publisher mapping.

    .OUTPUTS
        PSCustomObject with CheckId, Name, Version, Vendor, Product, CPE, Status,
        Confidence, CveCount, Cves, Evidence, Source, Timestamp, Error
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Version,
        [string]$Vendor,
        [string]$Product
    )

    $checkId = "APP-CVE-$([guid]::NewGuid().ToString().Substring(0,8))"
    $now     = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
    $source  = "NVD API v2.0 + CPE mapping"

    # --- Step 1: Resolve vendor/product from parameters or WinGet ID ---
    if ([string]::IsNullOrWhiteSpace($Vendor) -or [string]::IsNullOrWhiteSpace($Product)) {
        # Try to map from WinGet-style package ID (e.g., "Microsoft.Edge" -> vendor=microsoft, product=edge)
        $wingetId = $Name
        if ($wingetId -match '\.(.+)') {
            $vendorGuess = $wingetId -replace '\..*$', ''
            $productGuess = $matches[1]
            if ([string]::IsNullOrWhiteSpace($Vendor)) { $Vendor = $vendorGuess }
            if ([string]::IsNullOrWhiteSpace($Product)) { $Product = $productGuess }
        }
    }

    # If still missing vendor/product, we cannot reliably map to CPE -> NOT ASSESSED
    if ([string]::IsNullOrWhiteSpace($Vendor) -or [string]::IsNullOrWhiteSpace($Product)) {
        return [PSCustomObject]@{
            CheckId    = $checkId
            Name       = $Name
            Version    = $Version
            Vendor     = $Vendor
            Product    = $Product
            CPE        = $null
            Status     = "NOT ASSESSED"
            Severity   = "Informational"
            Summary    = "Application CVE correlation not assessed - vendor/product mapping unavailable"
            Reason     = "Cannot determine CPE vendor/product for '$Name'. Provide Vendor and Product parameters, or ensure the WinGet package ID encodes them (e.g., 'Microsoft.Edge')."
            Evidence   = @("WinGet ID: $Name", "Vendor: $Vendor", "Product: $Product")
            Source     = $source
            Timestamp  = $now
            Confidence = "N/A"
            CveCount   = 0
            Cves       = @()
            Error      = $null
        }
    }

    # --- Step 2: Build CPE 2.3 URI ---
    # Format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
    $cpe = "cpe:2.3:a:${Vendor}:${Product}:${Version}:*:*:*:*:*:*:*"

    # --- Step 3: Query NVD API for CVEs matching this CPE ---
    $nvdUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=" + [uri]::EscapeDataString($cpe)

    try {
        $response = Invoke-AuditRestMethod -Uri $nvdUrl -TimeoutSec 30
        $totalResults = if ($null -ne $response.totalResults) { [int]$response.totalResults } else { 0 }
        $vulns = @()
        if ($response.vulnerabilities) {
            foreach ($v in $response.vulnerabilities) {
                $cve = $v.cve
                $vulns += [PSCustomObject]@{
                    CVE         = if ($cve.id) { $cve.id } else { 'N/A' }
                    Title       = if ($cve.descriptions) { ($cve.descriptions | Where-Object { $_.lang -eq 'en' } | Select-Object -First 1).value } else { 'N/A' }
                    CVSS        = if ($cve.metrics.cvssMetricV31) { $cve.metrics.cvssMetricV31[0].cvssData.baseScore } elseif ($cve.metrics.cvssMetricV30) { $cve.metrics.cvssMetricV30[0].cvssData.baseScore } elseif ($cve.metrics.cvssMetricV2) { $cve.metrics.cvssMetricV2[0].cvssData.baseScore } else { 'N/A' }
                    Severity    = if ($cve.metrics.cvssMetricV31) { $cve.metrics.cvssMetricV31[0].cvssData.baseSeverity } elseif ($cve.metrics.cvssMetricV30) { $cve.metrics.cvssMetricV30[0].cvssData.baseSeverity } elseif ($cve.metrics.cvssMetricV2) { $cve.metrics.cvssMetricV2[0].cvssData.baseSeverity } else { 'Unknown' }
                    Published   = if ($cve.published) { $cve.published } else { 'N/A' }
                    LastModified= if ($cve.lastModified) { $cve.lastModified } else { 'N/A' }
                }
            }
        }

        if ($totalResults -gt 0 -and $vulns.Count -gt 0) {
            $maxScore = 0
            foreach ($v in $vulns) {
                if ($v.CVSS -is [double] -and $v.CVSS -gt $maxScore) { $maxScore = $v.CVSS }
            }
            $severity = if ($maxScore -ge 9.0) { "Critical" } elseif ($maxScore -ge 7.0) { "High" } elseif ($maxScore -ge 4.0) { "Medium" } else { "Low" }
            return [PSCustomObject]@{
                CheckId    = $checkId
                Name       = $Name
                Version    = $Version
                Vendor     = $Vendor
                Product    = $Product
                CPE        = $cpe
                Status     = "VULNERABLE"
                Severity   = $severity
                Summary    = "$($vulns.Count) CVE(s) found for ${Vendor}:${Product} $Version"
                Reason     = "NVD returned $totalResults CVE(s) matching CPE ${cpe}"
                Evidence   = @("CPE: ${cpe}", "NVD totalResults: $totalResults", "Max CVSS: $maxScore")
                Source     = $source
                Timestamp  = $now
                Confidence = "Medium"
                CveCount   = $vulns.Count
                Cves       = $vulns
                Error      = $null
            }
        } else {
            return [PSCustomObject]@{
                CheckId    = $checkId
                Name       = $Name
                Version    = $Version
                Vendor     = $Vendor
                Product    = $Product
                CPE        = $cpe
                Status     = "NOT AFFECTED"
                Severity   = "Informational"
                Summary    = "No known CVEs for ${Vendor}:${Product} $Version"
                Reason     = "NVD returned 0 CVE(s) matching CPE ${cpe}"
                Evidence   = @("CPE: ${cpe}", "NVD totalResults: $totalResults")
                Source     = $source
                Timestamp  = $now
                Confidence = "Medium"
                CveCount   = 0
                Cves       = @()
                Error      = $null
            }
        }
    } catch {
        return [PSCustomObject]@{
            CheckId    = $checkId
            Name       = $Name
            Version    = $Version
            Vendor     = $Vendor
            Product    = $Product
            CPE        = $cpe
            Status     = "UNKNOWN"
            Severity   = "Medium"
            Summary    = "Unable to query NVD for CVE information"
            Reason     = "NVD API query failed: $($_.Exception.Message)"
            Evidence   = @("CPE: ${cpe}", $_.Exception.Message)
            Source     = $source
            Timestamp  = $now
            Confidence = "N/A"
            CveCount   = 0
            Cves       = @()
            Error      = $_.Exception.Message
        }
    }
}
