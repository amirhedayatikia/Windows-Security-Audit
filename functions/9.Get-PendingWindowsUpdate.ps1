function Get-PendingWindowsUpdate {
    <#
    .SYNOPSIS
        Gets pending Windows Updates using Windows Update Agent COM interfaces (read-only).

    .DESCRIPTION
        Uses Microsoft.Update.Session and IUpdateSearcher to scan for applicable updates
        without installing or modifying system state. Returns structured assessment with
        update titles, KB identifiers, categories, severity, and scan status.

    .PARAMETER IncludeHidden
        Include updates marked as hidden/suppressed.

    .OUTPUTS
        PSCustomObject with CheckId, Status, Summary, Reason, Evidence, Items, Source, Timestamp, Confidence, Error
        Items: Array of PSCustomObject with Title, KB, Category, Severity, Size, IsHidden, UpdateIdentity
    #>
    [CmdletBinding()]
    param(
        [switch]$IncludeHidden
    )

    $checkId = "SEC-WU-001"
    $source  = "Windows Update Agent (IUpdateSearcher)"
    $now     = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")

    try {
        # Create Windows Update Session
        $session = New-Object -ComObject "Microsoft.Update.Session" -ErrorAction Stop
        $searcher = $session.CreateUpdateSearcher()

        # Configure search: only non-installed, non-hidden (unless requested)
        $criteria = "IsInstalled=0"
        if (-not $IncludeHidden) { $criteria += " AND IsHidden=0" }

        # Perform search (this may take 10-60 seconds)
        $searchResult = $searcher.Search($criteria)

        $updates = @()
        $kbPattern = '(?:KB|kb)\d{6,7}'

        foreach ($update in $searchResult.Updates) {
            $kb = $null
            foreach ($id in $update.KBArticleIDs) {
                if ($id -match $kbPattern) { $kb = $id; break }
            }
            # Also check title for KB pattern
            if (-not $kb -and $update.Title -match $kbPattern) {
                $kb = $matches[0]
            }

            # Get categories
            $categories = @()
            try {
                foreach ($cat in $update.Categories) { $categories += $cat.Name }
            } catch {
                Write-Verbose "Failed to get update categories: $($_.Exception.Message)"
            }

            # Get severity
            $severity = 'Unknown'
            try {
                if ($update.MsrcSeverity) { $severity = $update.MsrcSeverity }
            } catch {
                Write-Verbose "Failed to get update severity: $($_.Exception.Message)"
            }

            # Update identity for tracking
            $identity = $null
            try {
                if ($update.Identity) { $identity = $update.Identity.UpdateID }
            } catch {
                Write-Verbose "Failed to get update identity: $($_.Exception.Message)"
            }

            $updates += [PSCustomObject]@{
                Title          = $update.Title
                KB             = if ($kb) { $kb } else { 'N/A' }
                Category       = if ($categories.Count -gt 0) { $categories -join '; ' } else { 'N/A' }
                Severity       = $severity
                Size           = if ($update.MaxDownloadSize -gt 0) { [math]::Round($update.MaxDownloadSize / 1MB, 2) } else { 0 }
                SizeMB         = if ($update.MaxDownloadSize -gt 0) { [math]::Round($update.MaxDownloadSize / 1MB, 2) } else { 0 }
                IsHidden       = $update.IsHidden
                IsMandatory    = $update.IsMandatory
                IsUninstallable= $update.IsUninstallable
                UpdateID       = if ($identity) { $identity } else { 'N/A' }
                LastDeploymentChangeTime = if ($update.LastDeploymentChangeTime) { $update.LastDeploymentChangeTime.ToString() } else { 'N/A' }
            }
        }

        # Check for pending reboot
        $pendingReboot = $false
        $pendingRebootReason = ''
        try {
            $sysInfo = New-Object -ComObject "Microsoft.Update.SystemInfo" -ErrorAction SilentlyContinue
            if ($sysInfo -and $sysInfo.RebootRequired) {
                $pendingReboot = $true
                $pendingRebootReason = 'Windows Update Agent reports reboot required'
            }
        } catch {
            Write-Verbose "Failed to query SystemInfo for reboot status: $($_.Exception.Message)"
        }

        # Also check registry for pending reboot
        try {
            $regPaths = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting'
            )
            foreach ($path in $regPaths) {
                if (Test-Path $path -ErrorAction SilentlyContinue) { $pendingReboot = $true; break }
            }
        } catch {
            Write-Verbose "Failed to check registry for pending reboot: $($_.Exception.Message)"
        }

        if ($updates.Count -gt 0) {
            $status = 'AFFECTED'
            $severity = 'Medium'
            $summary = "$($updates.Count) applicable Windows Update(s) pending installation"
            $reason = "IUpdateSearcher found $($updates.Count) update(s) matching criteria: $criteria"
        } else {
            $status = 'NOT AFFECTED'
            $severity = 'Informational'
            $summary = 'No applicable Windows Updates pending installation'
            $reason = "IUpdateSearcher found 0 updates matching criteria: $criteria"
        }

        $evidence = @(
            "Search criteria: $criteria",
            "Updates found: $($updates.Count)",
            "Search completed: $($searchResult.ResultCode)",
            "Pending reboot: $pendingReboot"
        )
        if ($pendingReboot) { $evidence += "Reboot reason: $pendingRebootReason" }

        return [PSCustomObject]@{
            CheckId    = $checkId
            Name       = "Pending Windows Updates"
            Status     = $status
            Severity   = $severity
            Summary    = $summary
            Reason     = $reason
            Evidence   = $evidence
            Source     = $source
            Timestamp  = $now
            Confidence = 'High'
            Items      = $updates
            Error      = $null
            PendingReboot = $pendingReboot
            SearchCriteria = $criteria
            SearchResultCode = $searchResult.ResultCode
        }
    } catch {
        $errMsg = $_.Exception.Message
        $status = if ($errMsg -match "access denied|privilege|unauthorized|elevated") { 'ERROR' } else { 'ERROR' }
        return [PSCustomObject]@{
            CheckId    = $checkId
            Name       = "Pending Windows Updates"
            Status     = $status
            Severity   = 'Medium'
            Summary    = 'Unable to scan for pending Windows Updates'
            Reason     = "Windows Update Agent search failed: $errMsg"
            Evidence   = @($errMsg)
            Source     = $source
            Timestamp  = $now
            Confidence = 'N/A'
            Items      = @()
            Error      = $errMsg
            PendingReboot = $false
        }
    }
}