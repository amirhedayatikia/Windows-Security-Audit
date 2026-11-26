function Invoke-AuditRestMethod {
    <#
    .SYNOPSIS
        Internal helper: HTTP GET with TLS 1.2, direct connection first.

    .DESCRIPTION
        The .NET default web proxy (system/IE proxy with auto-detect) can add
        20+ seconds of latency per request on machines with WPAD enabled. This
        helper attempts a direct connection first and falls back to the system
        default proxy on failure. HTTP 404 is rethrown immediately (definitive
        answer) without proxy fallback.

    .PARAMETER Uri
        Request URI.

    .PARAMETER TimeoutSec
        Per-attempt timeout in seconds.

    .OUTPUTS
        Whatever Invoke-RestMethod returns (JSON deserialized).
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Uri,

        [int]$TimeoutSec = 30
    )

    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $oldProxy = [System.Net.WebRequest]::DefaultWebProxy

    # Attempt 1: direct (no proxy)
    [System.Net.WebRequest]::DefaultWebProxy = $null
    try {
        return Invoke-RestMethod -Uri $Uri -TimeoutSec $TimeoutSec -UserAgent "win11-cve-audit/1.0"
    } catch {
        # 404 means the resource does not exist; no point retrying via proxy
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq [System.Net.HttpStatusCode]::NotFound) {
            throw
        }
        # Fall through to system proxy fallback
        Write-Error "Direct connection failed: $($_.Exception.Message)"
    } finally {
        [System.Net.WebRequest]::DefaultWebProxy = $oldProxy
    }

    # Attempt 2: system default proxy
    try {
        return Invoke-RestMethod -Uri $Uri -TimeoutSec $TimeoutSec -UserAgent "win11-cve-audit/1.0"
    } catch {
        # Surface the direct error - it is usually the more meaningful one
        throw $_
    }
}