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
            $errMsg = $_.Exception.Message
            $status = if ($errMsg -match "not supported|not available|firmware") { "NOT APPLICABLE" } else { "ERROR" }
            $severity = if ($status -eq "NOT APPLICABLE") { "Informational" } else { "Medium" }
            $results += [PSCustomObject]@{
                CheckId    = "SEC-SB-001"
                Name       = "Secure Boot"
                Status     = $status
                Severity   = $severity
                Summary    = if ($status -eq "NOT APPLICABLE") { "Secure Boot not supported on this firmware" } else { "Unable to determine Secure Boot state" }
                Reason     = if ($status -eq "NOT APPLICABLE") { "Firmware does not support UEFI Secure Boot or platform lacks Secure Boot capability" } else { "Confirm-SecureBootUEFI failed: $errMsg" }
                Evidence   = @($errMsg)
                Source     = "Confirm-SecureBootUEFI"
                Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
                Confidence = if ($status -eq "NOT APPLICABLE") { "High" } else { "N/A" }
                Items      = @()
                Error      = if ($status -eq "ERROR") { $errMsg } else { $null }
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
            $items = @([PSCustomObject]@{
                TpmPresent       = $tpm.TpmPresent
                TpmReady         = $tpm.TpmReady
                TpmEnabled       = $tpm.TpmEnabled
                TpmActivated     = $tpm.TpmActivated
                TpmOwned         = $tpm.TpmOwned
                SpecVersion      = $tpm.ManufacturerVersionFull20
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
                    Evidence   = @("Present: $($tpm.TpmPresent)", "Ready: $($tpm.TpmReady)", "Enabled: $($tpm.TpmEnabled)", "Activated: $($tpm.TpmActivated)", "SpecVersion: $($tpm.ManufacturerVersionFull20)")
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
                    Evidence   = @("Present: $($tpm.TpmPresent)", "Ready: $($tpm.TpmReady)", "Enabled: $($tpm.TpmEnabled)", "Activated: $($tpm.TpmActivated)", "SpecVersion: $($tpm.ManufacturerVersionFull20)")
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
        $fw = Get-NetFirewallProfile -ErrorAction Stop
        $profileDetails = @()
        $activeProfiles = @()
        foreach ($p in $fw) {
            $profileDetails += [PSCustomObject]@{
                Name     = $p.Name
                Enabled  = $p.Enabled
                DefaultInboundAction   = $p.DefaultInboundAction
                DefaultOutboundAction  = $p.DefaultOutboundAction
                NotifyOnListen         = $p.NotifyOnListen
            }
            if ($p.Enabled) { $activeProfiles += $p.Name }
        }
        if ($activeProfiles.Count -gt 0) {
            $results += [PSCustomObject]@{
                CheckId    = "SEC-FW-001"
                Name       = "Windows Firewall"
                Status     = "PASS"
                Severity   = "Informational"
                Summary    = "Windows Firewall is enabled on $($activeProfiles.Count) profile(s): $($activeProfiles -join ', ')"
                Reason     = "Get-NetFirewallProfile shows enabled profiles: $($activeProfiles -join ', ')"
                Evidence   = $profileDetails | ForEach-Object { "$($_.Name): Enabled=$($_.Enabled), Inbound=$($_.DefaultInboundAction), Outbound=$($_.DefaultOutboundAction)" }
                Source     = "Get-NetFirewallProfile"
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
                Summary    = "Windows Firewall is disabled on all profiles"
                Reason     = "No enabled profiles found in Get-NetFirewallProfile"
                Evidence   = $profileDetails | ForEach-Object { "$($_.Name): Enabled=$($_.Enabled)" }
                Source     = "Get-NetFirewallProfile"
                Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
                Confidence = "High"
                Items      = $profileDetails
                Error      = $null
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
            Source     = "Get-NetFirewallProfile"
            Timestamp  = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
            Confidence = "N/A"
            Items      = @()
            Error      = $_.Exception.Message
        }
    }

    return $results
}