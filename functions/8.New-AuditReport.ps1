function New-AuditReport {
    <#
    .SYNOPSIS
        Generates a comprehensive security audit report.

    .PARAMETER OutputPath
        Path to save the markdown report (default: security-audit-report.md in current directory)

    .PARAMETER LookbackMonths
        KEV lookback window in months, anchored at the audit start date (default: 12).

    .OUTPUTS
        String containing the markdown report
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [string]$OutputPath = (Join-Path $PWD "security-audit-report.md"),
        [int]$LookbackMonths = 12
    )

    $auditDate = Get-Date
    $windowStart = $auditDate.AddMonths(-1 * [Math]::Abs($LookbackMonths))

    $report = New-Object System.Text.StringBuilder

    function AddSection($h) { $null = $report.AppendLine("## $h") }
    function AddLine($l) { $null = $report.AppendLine($l) }
    function AddBlank { $null = $report.AppendLine("") }
    function AddTable($hdrs,$rows) {
        $null = $report.AppendLine("| " + ($hdrs -join " | ") + " |")
        $null = $report.AppendLine("| " + (($hdrs | ForEach-Object { "---" }) -join " | ") + " |")
        $rows | ForEach-Object { $null = $report.AppendLine("| " + ($_ -join " | ") + " |") }
    }
    function Clean($s) { ([string]$s) -replace '\|', ' ' -replace '\r?\n', ' ' }

    # --- Collect all assessment data first ---
    $build = Get-WindowsBuildInfo -ErrorAction SilentlyContinue
    $features = Test-SecurityFeature -ErrorAction SilentlyContinue
    $inv = Get-LocalSoftwareInventory -ErrorAction SilentlyContinue
    $apps = if ($inv) { $inv.Inventory | Sort-Object Name } else { @() }
    $coverage = if ($inv) { $inv.Coverage } else { $null }
    $wu = Get-PendingWindowsUpdate -ErrorAction SilentlyContinue
    $kevStatus = @()
    if ($build -and -not [string]::IsNullOrWhiteSpace([string]$build.BuildNumber) -and $null -ne $build.UBR) {
        try {
            $kevStatus = Get-KevVulnerabilityStatus -BuildNumber $build.BuildNumber -UBR $build.UBR `
                -AuditDate $auditDate -LookbackMonths $LookbackMonths `
                -IsServer:([bool]($build.OSCaption -match 'Server')) -ErrorAction Stop
            $kevStatus = @($kevStatus)
        } catch { $kevStatus = @() }
    }
    $updates = Get-WingetUpdate -ErrorAction SilentlyContinue

    # --- Count outcomes for executive summary ---
    $counts = @{
        PASS            = 0
        FAIL            = 0
        ERROR           = 0
        UNKNOWN         = 0
        'NOT APPLICABLE'= 0
        'REQUIRES ELEVATION' = 0
        'NOT ASSESSED'  = 0
        AFFECTED        = 0
        VULNERABLE      = 0
        PATCHED         = 0
        'NOT AFFECTED'  = 0
    }

    if ($features) {
        foreach ($f in $features) {
            if ($counts.ContainsKey($f.Status)) { $counts[$f.Status]++ }
        }
    }
    if ($kevStatus) {
        foreach ($k in $kevStatus) {
            if ($k.Status -like 'PATCHED*') { $counts.PATCHED++ }
            elseif ($k.Status -like 'VULNERABLE*') { $counts.VULNERABLE++ }
            elseif ($k.Status -eq 'NOT AFFECTED') { $counts['NOT AFFECTED']++ }
            elseif ($k.Status -eq 'UNKNOWN') { $counts.UNKNOWN++ }
        }
    }
    if ($wu) {
        if ($wu.Status -eq 'AFFECTED') { $counts.AFFECTED++ }
        elseif ($wu.Status -eq 'ERROR') { $counts.ERROR++ }
        elseif ($wu.Status -eq 'NOT AFFECTED') { $counts['NOT AFFECTED']++ }
    }
    if ($updates) {
        if ($updates.Status -eq 'UpdatesAvailable') { $counts.AFFECTED++ }
        elseif ($updates.Status -in @('ExecutionFailed','SourceError','ParseError','Unavailable','Unknown')) { $counts.ERROR++ }
    }

    # --- Title ---
    AddSection "Windows 11 CVE Security Audit"
    AddLine "*Audit date: $($auditDate.ToString('yyyy-MM-dd HH:mm')) (all KEV windows and patch comparisons are relative to this date)*"
    AddBlank

    # --- Executive Summary ---
    AddSection "Executive Summary"
    AddLine "| Metric | Count |"
    AddLine "| ------ | ----- |"
    AddLine "| Checks Passed | $($counts.PASS) |"
    AddLine "| Checks Failed | $($counts.FAIL) |"
    AddLine "| Errors | $($counts.ERROR) |"
    AddLine "| Unknown / Incomplete | $($counts.UNKNOWN) |"
    AddLine "| Not Applicable | $($counts['NOT APPLICABLE']) |"
    AddLine "| Requires Elevation | $($counts['REQUIRES ELEVATION']) |"
    AddLine "| Not Assessed | $($counts['NOT ASSESSED']) |"
    AddLine "| KEV Vulnerabilities (Patched) | $($counts.PATCHED) |"
    AddLine "| KEV Vulnerabilities (Vulnerable) | $($counts.VULNERABLE) |"
    AddLine "| KEV Vulnerabilities (Not Affected) | $($counts['NOT AFFECTED']) |"
    AddLine "| Pending Windows Updates | $($counts.AFFECTED) |"
    AddLine "| Available Winget Updates | $($counts.AFFECTED) |"
    AddBlank

    # High-level assessment
    $criticalIssues = $counts.FAIL + $counts.VULNERABLE + $counts.AFFECTED
    if ($criticalIssues -gt 0) {
        AddLine "**Overall: $criticalIssues critical finding(s) require attention** (Failed checks, vulnerable KEV entries, or pending updates)"
    } else {
        AddLine "**Overall: No critical findings** (All checks passed, no vulnerable KEV entries, no pending Windows Updates)"
    }
    AddBlank

    # --- 1. System Information ---
    AddSection "1. System Information"
    if ($build) {
        $installDate = try { (Get-Date $build.InstallDate -Format 'yyyy-MM-dd HH:mm') } catch { "N/A" }
        $lastBoot = try { (Get-Date $build.LastBoot -Format 'yyyy-MM-dd HH:mm') } catch { "N/A" }
        AddLine "| Property | Value |"
        AddLine "| -------- | ----- |"
        AddLine "| OS | $(Clean $build.OSCaption) |"
        AddLine "| Build | $($build.BuildNumber) |"
        AddLine "| UBR | $($build.UBR) |"
        AddLine "| Full Version | $($build.FullVersion) |"
        AddLine "| Install Date | $installDate |"
        AddLine "| Last Boot | $lastBoot |"
        AddLine "| Architecture | $($build.Architecture) |"
        AddLine "| Edition | $($build.Edition) |"
    } else {
        AddLine "*Unable to retrieve system information*"
    }
    AddBlank

    # --- 2. Security Features ---
    AddSection "2. Security Features"
    if ($features -and $features.Count -gt 0) {
        $pass   = @($features | Where-Object Status -eq 'PASS').Count
        $fail   = @($features | Where-Object Status -eq 'FAIL').Count
        $errCnt = @($features | Where-Object Status -eq 'ERROR').Count
        $unknown= @($features | Where-Object Status -eq 'UNKNOWN').Count
        $na     = @($features | Where-Object Status -eq 'NOT APPLICABLE').Count
        $relev  = @($features | Where-Object Status -eq 'REQUIRES ELEVATION').Count
        AddLine "*Security checks: $pass PASS / $fail FAIL / $errCnt ERROR / $unknown UNKNOWN / $na NOT APPLICABLE / $relev REQUIRES ELEVATION*"
        AddBlank
        $featureRows = foreach ($f in $features) {
            $statusCell = if ($f.Status -eq 'FAIL') { "**$($f.Status)**" } elseif ($f.Status -eq 'ERROR') { "**$($f.Status)**" } elseif ($f.Status -eq 'UNKNOWN') { "**$($f.Status)**" } else { $f.Status }
            ,@((Clean $f.Name), $statusCell, (Clean $f.Summary), (Clean $f.Reason))
        }
        AddTable @("Check","Status","Summary","Reason") $featureRows
        AddBlank
        AddLine "**Evidence details:**"
        foreach ($f in $features) {
            AddLine "- **$($f.Name)** [$($f.Status)]: $($f.Reason)"
            if ($f.Evidence -and $f.Evidence.Count -gt 0) {
                foreach ($e in $f.Evidence) { AddLine "  - $e" }
            }
            if ($f.Error) { AddLine "  - *Error: $($f.Error)*" }
        }
    } else {
        AddLine "*Unable to retrieve security features information*"
    }
    AddBlank

    # --- 3. Installed Applications ---
    AddSection "3. Installed Applications"
    if ($apps -and @($apps).Count -gt 0) {
        AddLine "*Inventory coverage: $($coverage.TotalCount) applications from $($coverage.Sources -join ', ') (Registry: $($coverage.RegistryCount), winget: $($coverage.WingetCount), MSIX/AppX: $($coverage.MSIXCount))*"
        AddLine "*Note: Current-user registry (HKCU) and current-user MSIX/AppX only; other user profiles not assessed. Deduplication by (Id, Scope, Architecture).*"
        AddBlank
        $appRows = foreach ($a in $apps) {
            ,@((Clean $a.Name), ($(if ([string]::IsNullOrWhiteSpace([string]$a.Version)) { "N/A" } else { Clean $a.Version })), (Clean $a.Publisher), (Clean $a.Source), (Clean $a.Scope), (Clean $a.Architecture))
        }
        AddTable @("Application","Installed Version","Publisher","Source","Scope","Architecture") $appRows
    } else {
        AddLine "*Unable to retrieve installed application inventory*"
    }
    AddBlank

    # --- 4. CISA KEV Coverage ---
    AddSection "4. CISA KEV Coverage"
    if ($build -and -not [string]::IsNullOrWhiteSpace([string]$build.BuildNumber) -and $null -ne $build.UBR) {
        if ($kevStatus.Count -gt 0) {
            AddLine "*KEV window: $($windowStart.ToString('yyyy-MM-dd')) to $($auditDate.ToString('yyyy-MM-dd')) (Microsoft Windows entries added in the $($LookbackMonths) months before the audit date)*"
            $patched   = @($kevStatus | Where-Object Status -like 'PATCHED*').Count
            $vulnerable= @($kevStatus | Where-Object Status -like 'VULNERABLE*').Count
            $notAffect = @($kevStatus | Where-Object Status -eq 'NOT AFFECTED').Count
            $unknown   = @($kevStatus | Where-Object Status -eq 'UNKNOWN').Count
            AddLine "*Found $($kevStatus.Count) KEV entries: $patched PATCHED / $vulnerable VULNERABLE / $notAffect NOT AFFECTED / $unknown UNKNOWN*"
            AddBlank

            $kevRows = foreach ($k in $kevStatus) {
                $statusCell = if ($k.Status -like 'VULNERABLE*') { "**$($k.Status)**" } else { $k.Status }
                $confCell = if ($k.Status -like 'VULNERABLE*' -or $k.Status -like 'UNKNOWN*') { "**$($k.Confidence)**" } else { $k.Confidence }
                ,@(
                    (Clean $k.CVE),
                    (Clean $k.Title),
                    (Clean $k.DateAdded),
                    (Clean $k.CVSS),
                    (Clean $k.Severity),
                    (Clean $k.Ransomware),
                    $statusCell,
                    $confCell,
                    (Clean $k.FixedBuild),
                    (Clean $k.KB)
                )
            }
            AddTable @("CVE","Title","Date Added","CVSS","Severity","Ransomware","Status","Confidence","Fixed Build","KB") $kevRows
            AddBlank
            AddLine "**Status legend:**"
            AddLine "- PATCHED - a fix exists for this build line and the installed UBR is greater than or equal to the fixed build."
            AddLine "- PATCHED (inherited) - MSRC no longer lists this build line (it shipped after the fix), but the sibling build on the same servicing branch was fixed at an earlier UBR, which the installed cumulative update covers."
            AddLine "- VULNERABLE / VULNERABLE (inherited) - the installed UBR is below the fixed build; install the listed KB (cumulative updates include earlier fixes)."
            AddLine "- NOT AFFECTED - MSRC lists affected products for this CVE, but none on this system's build line."
            AddLine "- UNKNOWN - evidence insufficient to determine patch status (legacy CVE absent from MSRC, or no fix build metadata available)."
            AddLine "- Confidence: High = direct MSRC fix metadata; Medium = inherited from sibling servicing family; Low = limited or no MSRC metadata."
        } else {
            AddLine "No Microsoft Windows KEV entries were added in the lookback window."
        }
    } else {
        AddLine "*Unable to check KEV coverage: valid Windows build number and UBR were not retrieved.*"
    }
    AddBlank

    # --- 5. Available Updates (winget) ---
    AddSection "5. Available Updates (winget)"
    try {
        if ($updates.Status -eq 'UpdatesAvailable') {
            $updateCount = $updates.Items.Count
            AddLine "*Packages with available updates: $updateCount*"
            AddBlank
            $updateRows = foreach ($u in $updates.Items) {
                ,@((Clean $u.Name), (Clean $u.InstalledVersion), (Clean $u.AvailableVersion))
            }
            AddTable @("Package","Installed","Available") $updateRows
        } elseif ($updates.Status -eq 'NoUpdates') {
            AddLine "*WinGet completed successfully; all packages are up to date.*"
        } else {
            AddLine "*WinGet assessment incomplete: $(Clean $updates.Status). $(Clean $updates.Reason)*"
            if ($updates.Error) { AddLine "*Details: $(Clean $updates.Error)*" }
        }
    } catch {
        AddLine "*Could not check for winget updates: $(Clean $_.Exception.Message)*"
    }
    AddBlank

    # --- 6. Pending Windows Updates ---
    AddSection "6. Pending Windows Updates"
    try {
        if ($wu.Status -eq 'AFFECTED') {
            AddLine "*$($wu.Items.Count) applicable update(s) pending installation*"
            AddBlank
            $wuRows = foreach ($u in $wu.Items) {
                $kb = if ($u.KB -and $u.KB -ne 'N/A') { $u.KB } else { 'N/A' }
                $size = if ($u.SizeMB -and $u.SizeMB -gt 0) { "$($u.SizeMB) MB" } else { 'N/A' }
                ,@((Clean $u.Title), $kb, (Clean $u.Category), (Clean $u.Severity), $size)
            }
            AddTable @("Title","KB","Category","Severity","Download Size") $wuRows
            AddBlank
        } elseif ($wu.Status -eq 'NOT AFFECTED') {
            AddLine "*No applicable Windows Updates pending installation*"
            AddBlank
        } else {
            AddLine "*Windows Update assessment incomplete: $($wu.Status). $($wu.Reason)*"
            if ($wu.Error) { AddLine "*Details: $(Clean $wu.Error)*" }
            AddBlank
        }
        if ($wu.PendingReboot) {
            AddLine "**Pending reboot required** - Windows Update Agent reports a reboot is needed to complete installation."
            AddBlank
        }
    } catch {
        AddLine "*Could not check for pending Windows Updates: $(Clean $_.Exception.Message)*"
    }
    AddBlank

    # --- Coverage and Limitations ---
    AddSection "Assessment Coverage and Limitations"
    AddLine "| Area | Coverage | Limitations |"
    AddLine "| ---- | -------- | ----------- |"
    AddLine ("| CISA KEV | Microsoft Windows entries from last {0} months | Prioritization window, not comprehensive vulnerability assessment. Legacy CVEs (pre-2009) often absent from MSRC catalog. |" -f $LookbackMonths)
    AddLine "| Windows Updates | Applicable updates via Windows Update Agent (read-only scan) | Does not install updates. Requires admin for complete results on some systems. Policy-restricted sources may limit visibility. |"
    AddLine "| winget Updates | winget repository source only | Does not include Microsoft Store, third-party sources, or non-winget package managers. |"
    AddLine "| Application Inventory | Registry (HKLM x64/x86, HKCU), winget, MSIX/AppX (current user) | Other user profiles not assessed. Framework packages filtered. Deduplication by (Id, Scope, Architecture). |"
    AddLine "| Security Features | BitLocker, Secure Boot, TPM, Defender, Firewall | BitLocker requires Pro/Enterprise. TPM/Secure Boot require admin for accurate query. Firewall shows profile state, not per-connection effective policy. |"
    AddLine "| Application CVEs | NOT ASSESSED | Requires CPE mapping, version normalization, authoritative feeds (NVD, vendor advisories). Not implemented to avoid false precision. |"
    AddBlank

    # --- Data Sources and Timestamps ---
    AddSection "Data Sources and Timestamps"
    AddLine "| Source | Purpose | Retrieved |"
    AddLine "| ------ | ------- | --------- |"
    AddLine ("| CISA KEV Catalog | Known Exploited Vulnerabilities | {0} |" -f $auditDate.ToString('yyyy-MM-dd HH:mm'))
    AddLine ("| MSRC SUG API v2.0 | Vulnerability details, affected products, fixed builds | {0} |" -f $auditDate.ToString('yyyy-MM-dd HH:mm'))
    $wuTime = if ($wu -and $wu.Timestamp -and $wu.Timestamp -ne '') { $wu.Timestamp } else { $auditDate.ToString('yyyy-MM-dd HH:mm') }
    $upTime = if ($updates -and $updates.Timestamp -and $updates.Timestamp -ne '') { $updates.Timestamp } else { $auditDate.ToString('yyyy-MM-dd HH:mm') }
    AddLine ("| Windows Update Agent (COM) | Pending Windows Updates | {0} |" -f $wuTime)
    AddLine ("| winget | Package updates | {0} |" -f $upTime)
    AddLine ("| Local WMI/CIM | System info, security features | {0} |" -f $auditDate.ToString('yyyy-MM-dd HH:mm'))
    AddLine ("| Registry | Installed applications | {0} |" -f $auditDate.ToString('yyyy-MM-dd HH:mm'))
    AddBlank

    # --- Remediation Guidance ---
    AddSection "Recommended Actions"
    $hasActions = $false
    if ($features) {
        foreach ($f in $features) {
            if ($f.Status -eq 'FAIL') {
                if (-not $hasActions) { $hasActions = $true; AddLine "**Priority actions from failed security checks:**"; AddBlank }
                AddLine "- **$($f.Name)**: $($f.Reason) - Review evidence and remediate per Microsoft guidance."
            }
        }
    }
    if ($kevStatus) {
        foreach ($k in $kevStatus) {
            if ($k.Status -like 'VULNERABLE*') {
                if (-not $hasActions) { $hasActions = $true; AddLine "**Priority actions from vulnerable KEV entries:**"; AddBlank }
                AddLine "- **$($k.CVE)**: Install KB $($k.KB) (fixed build $($k.FixedBuild)) - Cumulative updates include this fix."
            }
        }
    }
    if ($wu -and $wu.Status -eq 'AFFECTED') {
        if (-not $hasActions) { $hasActions = $true; AddLine "**Priority actions from pending Windows Updates:**"; AddBlank }
        AddLine "- Install pending Windows Updates via Settings > Windows Update or 'Install-Module PSWindowsUpdate; Get-WindowsUpdate -Install -AcceptAll -AutoReboot' (requires admin)."
    }
    if ($updates -and $updates.Status -eq 'UpdatesAvailable') {
        if (-not $hasActions) { $hasActions = $true; AddLine "**Priority actions from winget updates:**"; AddBlank }
        foreach ($u in $updates.Items) {
            AddLine "- **$($u.Name)**: Update from $($u.InstalledVersion) to $($u.AvailableVersion) via 'winget upgrade $($u.Id)'"
        }
    }
    if ($wu -and $wu.PendingReboot) {
        AddLine "- **Reboot required** to complete Windows Update installation."
    }
    if (-not $hasActions) {
        AddLine "*No critical remediation actions identified.*"
    }
    AddBlank

    # --- Footer ---
    AddLine "---"
    AddLine "*Report generated by win11-cve-audit PowerShell module v1.1.0. Read-only audit; no system changes were made.*"
    AddLine "*All assessments are evidence-based. UNKNOWN/ERROR/NOT ASSESSED results are never presented as clean verdicts.*"

    $reportText = $report.ToString()
    $reportText | Out-File -FilePath $OutputPath -Encoding UTF8
    return $reportText
}