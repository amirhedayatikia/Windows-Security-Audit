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

    AddSection "Windows 11 CVE Security Audit"
    AddLine "*Audit date: $($auditDate.ToString('yyyy-MM-dd HH:mm')) (all KEV windows and patch comparisons are relative to this date)*"
    AddBlank

    # 1. System Information
    AddSection "1. System Information"
    $build = Get-WindowsBuildInfo -ErrorAction SilentlyContinue
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
    } else {
        AddLine "*Unable to retrieve system information*"
    }
    AddBlank

    # 2. Security Features
    AddSection "2. Security Features"
    $features = Test-SecurityFeature -ErrorAction SilentlyContinue
    if ($features -and $features.Count -gt 0) {
        $pass   = @($features | Where-Object Status -eq 'PASS').Count
        $fail   = @($features | Where-Object Status -eq 'FAIL').Count
        $errCnt = @($features | Where-Object Status -eq 'ERROR').Count
        $unknown= @($features | Where-Object Status -eq 'UNKNOWN').Count
        $na     = @($features | Where-Object Status -eq 'NOT APPLICABLE').Count
        AddLine "*Security checks: $pass PASS / $fail FAIL / $errCnt ERROR / $unknown UNKNOWN / $na NOT APPLICABLE*"
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

    # 3. Installed Applications (multi-source inventory)
    AddSection "3. Installed Applications"
    $apps = $null
    try {
        $inv = Get-LocalSoftwareInventory -ErrorAction Stop
        $apps = $inv.Inventory | Sort-Object Name
        $coverage = $inv.Coverage
    } catch { $apps = $null; $coverage = $null }
    if ($apps -and @($apps).Count -gt 0) {
        AddLine "*Inventory coverage: $($coverage.TotalCount) applications from $($coverage.Sources -join ', ') (Registry: $($coverage.RegistryCount), winget: $($coverage.WingetCount), MSIX/AppX: $($coverage.MSIXCount))*"
        AddBlank
        $appRows = foreach ($a in $apps) {
            ,@((Clean $a.Name), ($(if ([string]::IsNullOrWhiteSpace([string]$a.Version)) { "N/A" } else { Clean $a.Version })), (Clean $a.Publisher), (Clean $a.Source), (Clean $a.Scope), (Clean $a.Architecture))
        }
        AddTable @("Application","Installed Version","Publisher","Source","Scope","Architecture") $appRows
    } else {
        AddLine "*Unable to retrieve installed application inventory*"
    }
    AddBlank

    # 4. CISA KEV Coverage
    AddSection "4. CISA KEV Coverage"
    if ($build -and -not [string]::IsNullOrWhiteSpace([string]$build.BuildNumber) -and $null -ne $build.UBR) {
        try {
            $kevStatus = Get-KevVulnerabilityStatus -BuildNumber $build.BuildNumber -UBR $build.UBR `
                -AuditDate $auditDate -LookbackMonths $LookbackMonths `
                -IsServer:([bool]($build.OSCaption -match 'Server')) -ErrorAction Stop
            $kevStatus = @($kevStatus)
            $count = $kevStatus.Count

            AddLine "*KEV window: $($windowStart.ToString('yyyy-MM-dd')) to $($auditDate.ToString('yyyy-MM-dd')) (Microsoft Windows entries added in the $($LookbackMonths) months before the audit date)*"
            $patched   = @($kevStatus | Where-Object Status -like 'PATCHED*').Count
            $vulnerable= @($kevStatus | Where-Object Status -like 'VULNERABLE*').Count
            $notAffect = @($kevStatus | Where-Object Status -eq 'NOT AFFECTED').Count
            $unknown   = @($kevStatus | Where-Object Status -eq 'UNKNOWN').Count
            AddLine "*Found $count KEV entries: $patched PATCHED / $vulnerable VULNERABLE / $notAffect NOT AFFECTED / $unknown UNKNOWN*"
            AddBlank

            if ($count -gt 0) {
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
            } else {
                AddLine "No Microsoft Windows KEV entries were added in the lookback window."
            }
            AddBlank
            AddLine "**Status legend:**"
            AddLine "- PATCHED - a fix exists for this build line and the installed UBR is greater than or equal to the fixed build."
            AddLine "- PATCHED (inherited) - MSRC no longer lists this build line (it shipped after the fix), but the sibling build on the same servicing branch was fixed at an earlier UBR, which the installed cumulative update covers."
            AddLine "- VULNERABLE / VULNERABLE (inherited) - the installed UBR is below the fixed build; install the listed KB (cumulative updates include earlier fixes)."
            AddLine "- NOT AFFECTED - MSRC lists affected products for this CVE, but none on this system's build line."
            AddLine "- UNKNOWN - evidence insufficient to determine patch status (legacy CVE absent from MSRC, or no fix build metadata available)."
            AddLine "- Confidence: High = direct MSRC fix metadata; Medium = inherited from sibling servicing family; Low = limited or no MSRC metadata."
        } catch {
            AddLine "*Error checking KEV vulnerabilities: $(Clean $_.Exception.Message)*"
        }
    } else {
        AddLine "*Unable to check KEV coverage: valid Windows build number and UBR were not retrieved.*"
    }
    AddBlank

    # 5. Application Updates (winget)
    AddSection "5. Available Updates (winget)"
    try {
        $updates = Get-WingetUpdate -ErrorAction SilentlyContinue
        if ($updates.Status -eq 'UpdatesAvailable') {
            $updateCount = $updates.Items.Count
            AddLine "*Packages with available updates: $updateCount*"
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

    # 6. Pending Windows Updates
    AddSection "6. Pending Windows Updates"
    try {
        $wu = Get-PendingWindowsUpdate -ErrorAction SilentlyContinue
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

    AddLine "---"
    AddLine "*Report generated by win11-cve-audit PowerShell module. Read-only audit; no system changes were made.*"

    $reportText = $report.ToString()
    $reportText | Out-File -FilePath $OutputPath -Encoding UTF8
    return $reportText
}
