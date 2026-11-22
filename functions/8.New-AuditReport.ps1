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
        $featureRows = foreach ($f in $features) {
            ,@((Clean $f.Feature), (Clean $f.Status), (Clean $f.Details))
        }
        AddTable @("Feature","Status","Details") $featureRows
    } else {
        AddLine "*Unable to retrieve security features information*"
    }
    AddBlank

    # 3. Installed Applications (registry inventory)
    AddSection "3. Installed Applications"
    $apps = $null
    try {
        $apps = Get-LocalSoftwareInventory -ErrorAction Stop |
            Where-Object { $_.Source -eq 'Registry' } |
            Sort-Object Name
    } catch { $apps = $null }
    if ($apps -and @($apps).Count -gt 0) {
        $appRows = foreach ($a in $apps) {
            ,@((Clean $a.Name), ($(if ([string]::IsNullOrWhiteSpace([string]$a.Version)) { "N/A" } else { Clean $a.Version })), (Clean $a.Publisher))
        }
        AddTable @("Application","Installed Version","Publisher") $appRows
    } else {
        AddLine "*Unable to retrieve installed application inventory*"
    }
    AddBlank

    # 4. CISA KEV Coverage
    AddSection "4. CISA KEV Coverage"
    if ($build) {
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
                    ,@(
                        (Clean $k.CVE),
                        (Clean $k.Title),
                        (Clean $k.DateAdded),
                        (Clean $k.CVSS),
                        (Clean $k.Severity),
                        (Clean $k.Ransomware),
                        $statusCell,
                        (Clean $k.FixedBuild),
                        (Clean $k.KB)
                    )
                }
                AddTable @("CVE","Title","Date Added","CVSS","Severity","Ransomware","Status","Fixed Build","KB") $kevRows
            } else {
                AddLine "No Microsoft Windows KEV entries were added in the lookback window."
            }
            AddBlank
            AddLine "**Status legend:**"
            AddLine "- PATCHED - a fix exists for this build line and the installed UBR is greater than or equal to the fixed build."
            AddLine "- PATCHED (inherited) - MSRC no longer lists this build line (it shipped after the fix), but the sibling build on the same servicing branch was fixed at an earlier UBR, which the installed cumulative update covers."
            AddLine "- VULNERABLE / VULNERABLE (inherited) - the installed UBR is below the fixed build; install the listed KB (cumulative updates include earlier fixes)."
            AddLine "- NOT AFFECTED - MSRC lists affected products for this CVE, but none on this system's build line."
            AddLine "- UNKNOWN - the CVE is not in the MSRC catalog (typically legacy CVEs); verify patch status manually."
        } catch {
            AddLine "*Error checking KEV vulnerabilities: $(Clean $_.Exception.Message)*"
        }
    } else {
        AddLine "*Unable to check KEV coverage (no build info)*"
    }
    AddBlank

    # 5. Application Updates (winget)
    AddSection "5. Available Updates (winget)"
    try {
        $updates = Get-WingetUpdate -ErrorAction SilentlyContinue
        if ($updates -and $updates.Count -gt 0) {
            $updateCount = $updates.Count
            AddLine "*Packages with available updates: $updateCount*"
            $updateRows = foreach ($u in $updates) {
                ,@((Clean $u.Name), (Clean $u.InstalledVersion), (Clean $u.AvailableVersion))
            }
            AddTable @("Package","Installed","Available") $updateRows
        } else {
            AddLine "*All winget packages are up to date.*"
        }
    } catch {
        AddLine "*Could not check for winget updates: $(Clean $_.Exception.Message)*"
    }
    AddBlank

    AddLine "---"
    AddLine "*Report generated by win11-cve-audit PowerShell module. Read-only audit; no system changes were made.*"

    $report.ToString() | Out-File -FilePath $OutputPath -Encoding UTF8
    return $report.ToString()
}
