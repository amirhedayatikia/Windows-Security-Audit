function Test-SecurityFeature {
    <#
    .SYNOPSIS
        Checks Windows security feature status with evidence-based verdicts.

    .DESCRIPTION
        Assesses BitLocker, Secure Boot, TPM, Windows Defender, and Windows Firewall.
        Returns structured assessment objects with explicit statuses:
        PASS, FAIL, AFFECTED, NOT AFFECTED, UNKNOWN, ERROR, NOT APPLICABLE, NOT ASSESSED,
        REQUIRES ELEVATION.

    .OUTPUTS
        Array of PSCustomObject with CheckId, Name, Status, Severity, Summary, Reason,
        Evidence, Source, Timestamp, Confidence, Items, Error
    #>
    [CmdletBinding()]
    param()

    $results = @()

    # --- 0. Elevation check ---
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        $results += [PSCustomObject]@{
            CheckId    = "SEC-ELEV-001"
            Name       = "Administrator Privileges"
            Status     = "REQUIRES ELEVATION"
            Severity   = "Informational"
            Summary    = "Audit is not running with administrator privileges"
            Reason     = "TPM and Secure Boot assessments require elevated rights. Run PowerShell as Administrator for complete results."
            Evidence   = @("Current user is not in Administrators group")
            Source     = "WindowsPrincipal.IsInRole"
            Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
            Confidence = "High"
            Items      = @()
            Error      = $null
        }
    } else {
        $results += [PSCustomObject]@{
            CheckId    = "SEC-ELEV-001"
            Name       = "Administrator Privileges"
            Status     = "PASS"
            Severity   = "Informational"
            Summary    = "Audit is running with administrator privileges"
            Reason     = "Elevated context detected; all security checks can query full system state"
            Evidence   = @("Current user is in Administrators group")
            Source     = "WindowsPrincipal.IsInRole"
            Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
            Confidence = "High"
            Items      = @()
            Error      = $null
        }
    }

    # --- 1. BitLocker ---
    try {
        $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        if ($bl.ProtectionStatus -eq "On") {
            $results += [PSCustomObject]@{
                CheckId    = "SEC-BL-001"
                Name       = "BitLocker System Volume"
                Status     = "PASS"
                Severity   = "Informational"
                Summary    = "System volume is encrypted and protected"
                Reason     = "BitLocker ProtectionStatus is On for the system volume"
                Evidence   = @("ProtectionStatus: On", "EncryptionMethod: $($bl.EncryptionMethod)", "VolumeType: $($bl.VolumeType)")
                Source     = "Get-BitLockerVolume"
                Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
                Confidence = "High"
                Items      = @([PSCustomObject]@{ Volume = $env:SystemDrive; ProtectionStatus = $bl.ProtectionStatus; EncryptionMethod = $bl.EncryptionMethod; KeyProtector = $bl.KeyProtector })
                Error      = $null
            }
        } else {
            $results += [PSCustomObject]@{
                CheckId    = "SEC-BL-001"
                Name       = "BitLocker System Volume"
                Status     = "FAIL"
                Severity   = "High"
                Summary    = "System volume is not protected by BitLocker"
                Reason     = "BitLocker ProtectionStatus is $($bl.ProtectionStatus) for the system volume"
                Evidence   = @("ProtectionStatus: $($bl.ProtectionStatus)", "EncryptionMethod: $($bl.EncryptionMethod)")
                Source     = "Get-BitLockerVolume"
                Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
                Confidence = "High"
                Items      = @([PSCustomObject]@{ Volume = $env:SystemDrive; ProtectionStatus = $bl.ProtectionStatus; EncryptionMethod = $bl.EncryptionMethod })
                Error      = $null
            }
        }
    } catch {
        # Determine if BitLocker is unavailable (Home edition) or query failed
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        $isHome = $os -and $os.Caption -like "*Home*"
        if ($isHome) {
            $results += [PSCustomObject]@{
                CheckId    = "SEC-BL-001"
                Name       = "BitLocker System Volume"
                Status     = "NOT APPLICABLE"
                Severity   = "Informational"
                Summary    = "BitLocker not available on Windows Home edition"
                Reason     = "Windows Home edition does not include BitLocker Drive Encryption"
                Evidence   = @("OSCaption: $($os.Caption)")
                Source     = "Win32_OperatingSystem"
                Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
                Confidence = "High"
                Items      = @()
                Error      = $null
            }
        } else {
            $results += [PSCustomObject]@{
                CheckId    = "SEC-BL-001"
                Name       = "BitLocker System Volume"
                Status     = "ERROR"
                Severity   = "Medium"
                Summary    = "Unable to query BitLocker status"
                Reason     = "Get-BitLockerVolume failed: $($_.Exception.Message)"
                Evidence   = @($_.Exception.Message)
                Source     = "Get-BitLockerVolume"
                Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
                Confidence = "N/A"
                Items      = @()
                Error      = $_.Exception.Message
            }
        }
    }

    # --- 2. Secure Boot ---
    if (-not $isAdmin) {
        $results += [PSCustomObject]@{
            CheckId    = "SEC-SB-001"
            Name       = "Secure Boot"
            Status     = "REQUIRES ELEVATION"
            Severity   = "Informational"
            Summary    = "Secure Boot assessment requires administrator privileges"
            Reason     = "Confirm-SecureBootUEFI requires elevated rights to query UEFI Secure Boot state"
            Evidence   = @("Audit not running as Administrator")
            Source     = "Confirm-SecureBootUEFI (skipped)"
            Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
            Confidence = "High"
            Items      = @()
            Error      = $null
        }
    } else {
        try {
            $sb = Confirm-SecureBootUEFI -ErrorAction Stop
            if ($sb) {
                $results += [PSCustomObject]@{
                    CheckId    = "SEC-SB-001"
                    Name       = "Secure Boot"
                    Status     = "PASS"
                    Severity   = "Informational"
                    Summary    = "UEFI Secure Boot is enabled"
                    Reason     = "Confirm-SecureBootUEFI returned True"
                    Evidence   = @("SecureBoot: True")
                    Source     = "Confirm-SecureBootUEFI"
                    Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
                    Confidence = "High"
                    Items      = @([PSCustomObject]@{ SecureBoot = $true })
                    Error      = $null
                }
            } else {
                $results += [PSCustomObject]@{
                    CheckId    = "SEC-SB-001"
                    Name       = "Secure Boot"
                    Status     = "FAIL"
                    Severity   = "High"
                    Summary    = "UEFI Secure Boot is disabled"
                    Reason     = "Confirm-SecureBootUEFI returned False"
                    Evidence   = @("SecureBoot: False")
                    Source     = "Confirm-SecureBootUEFI"
                    Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
                    Confidence = "High"
                    Items      = @([PSCustomObject]@{ SecureBoot = $false })
                    Error      = $null
                }
            }
        } catch {
            $ex = $_.Exception
            $errMsg = $ex.Message
            # Typed exception classification instead of English error message matching
            if ($ex -is [System.UnauthorizedAccessException] -or $errMsg -match "access denied|privilege|unauthorized|elevated") {
                $status = "REQUIRES ELEVATION"
                $severity = "Informational"
                $summary = "Secure Boot assessment requires administrator privileges"
                $reason = "Confirm-SecureBootUEFI access denied: $errMsg"
                $confidence = "High"
                $errorOut = $null
            } elseif ($ex -is [System.Management.Automation.CmdletInvocationException] -and $ex.TargetObject -is [System.Management.Automation.ErrorRecord]) {
                # Underlying .NET exception from the cmdlet
                $inner = $ex.TargetObject.Exception
                if ($inner -is [System.UnauthorizedAccessException]) {
                    $status = "REQUIRES ELEVATION"
                    $severity = "Informational"
                    $summary = "Secure Boot assessment requires administrator privileges"
                    $reason = "Confirm-SecureBootUEFI access denied (inner): $($inner.Message)"
                    $confidence = "High"
                    $errorOut = $null
                } else {
                    $status = "NOT APPLICABLE"
                    $severity = "Informational"
                    $summary = "Secure Boot not supported on this firmware"
                    $reason = "Confirm-SecureBootUEFI failed: $errMsg"
                    $confidence = "High"
                    $errorOut = if ($status -eq "ERROR") { $errMsg } else { $null }
                }
            } else {
                $status = "NOT APPLICABLE"
                $severity = "Informational"
                $summary = "Secure Boot not supported on this firmware"
                $reason = "Confirm-SecureBootUEFI failed: $errMsg"
                $confidence = "High"
                $errorOut = $null
            }
            $results += [PSCustomObject]@{
                CheckId    = "SEC-SB-001"
                Name       = "Secure Boot"
                Status     = $status
                Severity   = $severity
                Summary    = $summary
                Reason     = $reason
                Evidence   = @($errMsg)
                Source     = "Confirm-SecureBootUEFI"
                Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
                Confidence = $confidence
                Items      = @()
                Error      = $errorOut
            }
        }
    }

    # --- 3. TPM ---
    if (-not $isAdmin) {
        $results += [PSCustomObject]@{
            CheckId    = "SEC-TPM-001"
            Name       = "TPM 2.0"
            Status     = "REQUIRES ELEVATION"
            Severity   = "Informational"
            Summary    = "TPM assessment requires administrator privileges"
            Reason     = "Get-Tpm requires elevated rights to query TPM hardware state"
            Evidence   = @("Audit not running as Administrator")
            Source     = "Get-Tpm (skipped)"
            Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
            Confidence = "High"
            Items      = @()
            Error      = $null
        }
    } else {
        try {
            $tpm = Get-Tpm -ErrorAction Stop
            # Get TPM spec version from Win32_Tpm CIM class (more authoritative than
            # ManufacturerVersionFull20 which is the manufacturer-specific version)
            $specVersion = $null
            $tpmSpecSource = 'ManufacturerVersionFull20'
            try {
                $cimTpm = Get-CimInstance Win32_Tpm -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($cimTpm -and $null -ne $cimTpm.SpecVersion) {
                    $specVersion = [string]$cimTpm.SpecVersion
                    $tpmSpecSource = 'Win32_Tpm.SpecVersion'
                } else {
                    $specVersion = if ($null -ne $tpm.ManufacturerVersionFull20) { [string]$tpm.ManufacturerVersionFull20 } else { 'Unknown' }
                }
            } catch {
                $specVersion = if ($null -ne $tpm.ManufacturerVersionFull20) { [string]$tpm.ManufacturerVersionFull20 } else { 'Unknown' }
            }

            $items = @([PSCustomObject]@{
                TpmPresent       = $tpm.TpmPresent
                TpmReady         = $tpm.TpmReady
                TpmEnabled       = $tpm.TpmEnabled
                TpmActivated     = $tpm.TpmActivated
                TpmOwned         = $tpm.TpmOwned
                SpecVersion      = $specVersion
                TpmSpecSource    = $tpmSpecSource
                ManufacturerId   = $tpm.ManufacturerIdTxt
                ManufacturerVer  = $tpm.ManufacturerVersion
            })
            if ($tpm.TpmPresent -and $tpm.TpmReady -and $tpm.TpmEnabled -and $tpm.TpmActivated) {
                $results += [PSCustomObject]@{
                    CheckId    = "SEC-TPM-001"
                    Name       = "TPM 2.0"
                    Status     = "PASS"
                    Severity   = "Informational"
                    Summary    = "TPM 2.0 is present, ready, enabled, and activated"
                    Reason     = "All TPM readiness flags are true"
                    Evidence   = @("Present: $($tpm.TpmPresent)", "Ready: $($tpm.TpmReady)", "Enabled: $($tpm.TpmEnabled)", "Activated: $($tpm.TpmActivated)", "SpecVersion: $specVersion")
                    Source     = "Get-Tpm"
                    Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
                    Confidence = "High"
                    Items      = $items
                    Error      = $null
                }
            } elseif ($tpm.TpmPresent -and $tpm.TpmReady) {
                $results += [PSCustomObject]@{
                    CheckId    = "SEC-TPM-001"
                    Name       = "TPM 2.0"
                    Status     = "FAIL"
                    Severity   = "Medium"
                    Summary    = "TPM present but not fully enabled/activated"
                    Reason     = "TPM is present and ready but Enabled=$($tpm.TpmEnabled) or Activated=$($tpm.TpmActivated)"
                    Evidence   = @("Present: $($tpm.TpmPresent)", "Ready: $($tpm.TpmReady)", "Enabled: $($tpm.TpmEnabled)", "Activated: $($tpm.TpmActivated)", "SpecVersion: $specVersion")
                    Source     = "Get-Tpm"
                    Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
                    Confidence = "High"
                    Items      = $items
                    Error      = $null
                }
            } else {
                $results += [PSCustomObject]@{
                    CheckId    = "SEC-TPM-001"
                    Name       = "TPM 2.0"
                    Status     = "FAIL"
                    Severity   = "High"
                    Summary    = "TPM not present or not ready"
                    Reason     = "Present=$($tpm.TpmPresent), Ready=$($tpm.TpmReady)"
                    Evidence   = @("Present: $($tpm.TpmPresent)", "Ready: $($tpm.TpmReady)", "Enabled: $($tpm.TpmEnabled)", "Activated: $($tpm.TpmActivated)")
                    Source     = "Get-Tpm"
                    Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
                    Confidence = "High"
                    Items      = $items
                    Error      = $null
                }
            }
        } catch {
            $results += [PSCustomObject]@{
                CheckId    = "SEC-TPM-001"
                Name       = "TPM 2.0"
                Status     = "ERROR"
                Severity   = "Medium"
                Summary    = "Unable to query TPM status"
                Reason     = "Get-Tpm failed: $($_.Exception.Message)"
                Evidence   = @($_.Exception.Message)
                Source     = "Get-Tpm"
                Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
                Confidence = "N/A"
                Items      = @()
                Error      = $_.Exception.Message
            }
        }
    }

    # --- 4. Windows Defender ---
    try {
        $defender = Get-MpComputerStatus -ErrorAction Stop
        $items = @([PSCustomObject]@{
            AntivirusEnabled         = $defender.AntivirusEnabled
            RealTimeProtectionEnabled= $defender.RealTimeProtectionEnabled
            AntispywareEnabled       = $defender.AntispywareEnabled
            BehaviorMonitorEnabled   = $defender.BehaviorMonitorEnabled
            IoavProtectionEnabled    = $defender.IoavProtectionEnabled
            OnAccessProtectionEnabled= $defender.OnAccessProtectionEnabled
            LastQuickScanTime        = if ($defender.LastQuickScanSource) { $defender.LastQuickScanSource } else { 'N/A' }
            LastFullScanTime         = if ($defender.LastFullScanSource) { $defender.LastFullScanSource } else { 'N/A' }
            AntivirusSignatureVersion= $defender.AntivirusSignatureVersion
            AntivirusSignatureLastUpdated = $defender.AntivirusSignatureLastUpdated
            AntispywareSignatureVersion = $defender.AntispywareSignatureVersion
            AntispywareSignatureLastUpdated = $defender.AntispywareSignatureLastUpdated
        })
        if ($defender.AntivirusEnabled -and $defender.RealTimeProtectionEnabled) {
            $results += [PSCustomObject]@{
                CheckId    = "SEC-WD-001"
                Name       = "Windows Defender"
                Status     = "PASS"
                Severity   = "Informational"
                Summary    = "Windows Defender Antivirus is enabled with real-time protection"
                Reason     = "AntivirusEnabled=True and RealTimeProtectionEnabled=True"
                Evidence   = @("AntivirusEnabled: $($defender.AntivirusEnabled)", "RealTimeProtection: $($defender.RealTimeProtectionEnabled)", "SignatureVersion: $($defender.AntivirusSignatureVersion)", "SignatureUpdated: $($defender.AntivirusSignatureLastUpdated)")
                Source     = "Get-MpComputerStatus"
                Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
                Confidence = "High"
                Items      = $items
                Error      = $null
            }
        } elseif ($defender.AntivirusEnabled) {
            $results += [PSCustomObject]@{
                CheckId    = "SEC-WD-001"
                Name       = "Windows Defender"
                Status     = "FAIL"
                Severity   = "Medium"
                Summary    = "Windows Defender enabled but real-time protection is off"
                Reason     = "AntivirusEnabled=True but RealTimeProtectionEnabled=$($defender.RealTimeProtectionEnabled)"
                Evidence   = @("AntivirusEnabled: $($defender.AntivirusEnabled)", "RealTimeProtection: $($defender.RealTimeProtectionEnabled)")
                Source     = "Get-MpComputerStatus"
                Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
                Confidence = "High"
                Items      = $items
                Error      = $null
            }
        } else {
            $results += [PSCustomObject]@{
                CheckId    = "SEC-WD-001"
                Name       = "Windows Defender"
                Status     = "FAIL"
                Severity   = "High"
                Summary    = "Windows Defender Antivirus is disabled"
                Reason     = "AntivirusEnabled=False"
                Evidence   = @("AntivirusEnabled: $($defender.AntivirusEnabled)")
                Source     = "Get-MpComputerStatus"
                Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
                Confidence = "High"
                Items      = $items
                Error      = $null
            }
        }
    } catch {
        $results += [PSCustomObject]@{
            CheckId    = "SEC-WD-001"
            Name       = "Windows Defender"
            Status     = "ERROR"
            Severity   = "Medium"
            Summary    = "Unable to query Windows Defender status"
            Reason     = "Get-MpComputerStatus failed: $($_.Exception.Message)"
            Evidence   = @($_.Exception.Message)
            Source     = "Get-MpComputerStatus"
            Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
            Confidence = "N/A"
            Items      = @()
            Error      = $_.Exception.Message
        }
    }

    # --- 5. Windows Firewall ---
    try {
        # Get effective (active store) firewall profiles - reflects the policy actually in force
        $fwProfiles = Get-NetFirewallProfile -PolicyStoreSource ActiveStore -ErrorAction Stop

        # Get active network connections to determine which firewall profile applies
        $netProfiles = @()
        try {
            $netProfiles = Get-NetConnectionProfile -ErrorAction SilentlyContinue
        } catch {
            Write-Verbose "Failed to get network connection profiles: $($_.Exception.Message)"
        }

        # Build profile details from ActiveStore
        $profileDetails = @()
        foreach ($p in $fwProfiles) {
            $profileDetails += [PSCustomObject]@{
                Name                 = $p.Name
                Enabled              = $p.Enabled
                DefaultInboundAction = $p.DefaultInboundAction
                DefaultOutboundAction= $p.DefaultOutboundAction
                NotifyOnListen       = $p.NotifyOnListen
                PolicyStoreSource    = if ($p.PolicyStoreSource) { $p.PolicyStoreSource } else { 'Unknown' }
            }
        }

        # Determine active network categories and map to firewall profile names
        $activeCategories = @()
        if ($netProfiles -and $netProfiles.Count -gt 0) {
            foreach ($np in $netProfiles) {
                $cat = if ($np.NetworkCategory) { [string]$np.NetworkCategory } else { 'Unknown' }
                if ($activeCategories -notcontains $cat) {
                    $activeCategories += $cat
                }
            }
        }

        # Map network category to firewall profile name
        $categoryToProfile = @{
            'DomainAuthenticated' = 'Domain'
            'Domain'              = 'Domain'
            'Private'             = 'Private'
            'Public'              = 'Public'
        }

        # Check each active network's corresponding firewall profile
        $activeProfileStates = @()
        $allActiveEnabled = $true
        $anyActiveFound = $false
        foreach ($cat in $activeCategories) {
            $profileName = if ($categoryToProfile.ContainsKey($cat)) { $categoryToProfile[$cat] } else { $cat }
            $fwProfile = $fwProfiles | Where-Object { $_.Name -eq $profileName } | Select-Object -First 1
            if ($fwProfile) {
                $anyActiveFound = $true
                $isEnabled = [bool]$fwProfile.Enabled
                $activeProfileStates += @("$(${profileName}): Enabled=$isEnabled")
                if (-not $isEnabled) {
                    $allActiveEnabled = $false
                }
            }
        }

        if ($anyActiveFound -and $allActiveEnabled) {
            $results += [PSCustomObject]@{
                CheckId    = "SEC-FW-001"
                Name       = "Windows Firewall"
                Status     = "PASS"
                Severity   = "Informational"
                Summary    = "Windows Firewall is enabled on all active network profile(s): $($activeProfileStates -join '; ')"
                Reason     = "ActiveStore firewall policy is enabled for active network categories: $($activeCategories -join ', ')"
                Evidence   = $profileDetails | ForEach-Object { "$($_.Name): Enabled=$($_.Enabled), Inbound=$($_.DefaultInboundAction), Outbound=$($_.DefaultOutboundAction)" }
                Source     = "Get-NetFirewallProfile -PolicyStoreSource ActiveStore + Get-NetConnectionProfile"
                Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
                Confidence = "High"
                Items      = $profileDetails
                Error      = $null
            }
        } elseif ($anyActiveFound -and -not $allActiveEnabled) {
            $results += [PSCustomObject]@{
                CheckId    = "SEC-FW-001"
                Name       = "Windows Firewall"
                Status     = "FAIL"
                Severity   = "High"
                Summary    = "Windows Firewall is disabled on active network profile(s)"
                Reason     = "ActiveStore firewall policy is disabled for one or more active network categories: $($activeCategories -join ', ')"
                Evidence   = $profileDetails | ForEach-Object { "$($_.Name): Enabled=$($_.Enabled)" }
                Source     = "Get-NetFirewallProfile -PolicyStoreSource ActiveStore + Get-NetConnectionProfile"
                Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
                Confidence = "High"
                Items      = $profileDetails
                Error      = $null
            }
        } else {
            # No active network connections found; fall back to reporting all profiles
            $enabledCount = @($fwProfiles | Where-Object { $_.Enabled }).Count
            if ($enabledCount -gt 0) {
                $enabledNames = @($fwProfiles | Where-Object { $_.Enabled} | ForEach-Object { $_.Name }) -join ', '
                $results += [PSCustomObject]@{
                    CheckId    = "SEC-FW-001"
                    Name       = "Windows Firewall"
                    Status     = "PASS"
                    Severity   = "Informational"
                    Summary    = "Windows Firewall is enabled on $enabledCount profile(s): $enabledNames (no active network connection detected)"
                    Reason     = "No active network connection detected; reporting all ActiveStore firewall profile states"
                    Evidence   = $profileDetails | ForEach-Object { "$($_.Name): Enabled=$($_.Enabled), Inbound=$($_.DefaultInboundAction), Outbound=$($_.DefaultOutboundAction)" }
                    Source     = "Get-NetFirewallProfile -PolicyStoreSource ActiveStore"
                    Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
                    Confidence = "High"
                    Items      = $profileDetails
                    Error      = $null
                }
            } else {
                $results += [PSCustomObject]@{
                    CheckId    = "SEC-FW-001"
                    Name       = "Windows Firewall"
                    Status     = "FAIL"
                    Severity   = "High"
                    Summary    = "Windows Firewall is disabled on all profiles (no active network connection detected)"
                    Reason     = "No enabled profiles found in ActiveStore firewall policy and no active network connection detected"
                    Evidence   = $profileDetails | ForEach-Object { "$($_.Name): Enabled=$($_.Enabled)" }
                    Source     = "Get-NetFirewallProfile -PolicyStoreSource ActiveStore"
                    Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
                    Confidence = "High"
                    Items      = $profileDetails
                    Error      = $null
                }
            }
        }
    } catch {
        $results += [PSCustomObject]@{
            CheckId    = "SEC-FW-001"
            Name       = "Windows Firewall"
            Status     = "ERROR"
            Severity   = "Medium"
            Summary    = "Unable to query Windows Firewall status"
            Reason     = "Get-NetFirewallProfile failed: $($_.Exception.Message)"
            Evidence   = @($_.Exception.Message)
            Source     = "Get-NetFirewallProfile -PolicyStoreSource ActiveStore"
            Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
            Confidence = "N/A"
            Items      = @()
            Error      = $_.Exception.Message
        }
    }

    return $results
}