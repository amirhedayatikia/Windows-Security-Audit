function Test-SecurityFeature {
    <#
    .SYNOPSIS
        Checks Windows security feature status (BitLocker, Secure Boot, TPM, Windows Defender, Firewall).

    .OUTPUTS
        Array of PSCustomObject with Feature, Status, Details
    #>
    $features = @()

    # BitLocker - check if available/encrypted
    try {
        $bl = Get-BitLockerVolume -MountPoint C: -ErrorAction Stop
        $features += [PSCustomObject]@{
            Feature = "BitLocker"
            Status  = if ($bl.ProtectionStatus -eq "On") { "Enabled" } else { "Disabled" }
            Details = "Encryption: $($bl.EncryptionMethod)"
        }
    } catch {
        # Check if BitLocker is available (Home edition doesn't have it)
        try {
            $os = Get-CimInstance Win32_OperatingSystem
            if ($os.Name -like "*Home*") {
                $features += [PSCustomObject]@{
                    Feature = "BitLocker"
                    Status  = "Not Available"
                    Details = "Windows 11 Home edition (requires Pro/Enterprise)"
                }
            } else {
                # Try to check service status
                $blService = Get-Service BDESVC -ErrorAction SilentlyContinue
                if ($blService) {
                    $features += [PSCustomObject]@{
                        Feature = "BitLocker"
                        Status  = "Disabled"
                        Details = "Service: $($blService.Status)"
                    }
                } else {
                    $features += [PSCustomObject]@{
                        Feature = "BitLocker"
                        Status  = "Not Available"
                        Details = "BitLocker cmdlet error"
                    }
                }
            }
        } catch {
            $features += [PSCustomObject]@{
                Feature = "BitLocker"
                Status  = "Not Available"
                Details = "Windows 11 Home edition"
            }
        }
    }

    # Secure Boot
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($sb) {
            $features += [PSCustomObject]@{
                Feature = "Secure Boot"
                Status  = "Enabled"
                Details = "UEFI Secure Boot active"
            }
        } else {
            $features += [PSCustomObject]@{
                Feature = "Secure Boot"
                Status  = "Disabled"
                Details = "Secure Boot not enabled"
            }
        }
    } catch {
        $features += [PSCustomObject]@{
            Feature = "Secure Boot"
            Status  = "Check BIOS"
            Details = "Use 'Confirm-SecureBootUEFI' or check UEFI settings"
        }
    }

    # TPM - check availability and status
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        if ($tpm.TpmPresent -and $tpm.TpmReady) {
            if ($tpm.TpmEnabled -and $tpm.TpmActivated) {
                $features += [PSCustomObject]@{
                    Feature = "TPM"
                    Status  = "Enabled"
                    Details = "Spec: $($tpm.TpmSpecVersion)"
                }
            } else {
                $features += [PSCustomObject]@{
                    Feature = "TPM"
                    Status  = "Present"
                    Details = "Not ready - check BIOS settings"
                }
            }
        } else {
            $features += [PSCustomObject]@{
                Feature = "TPM"
                Status  = "Not Present"
                Details = "Enable TPM 2.0 in BIOS/UEFI"
            }
        }
    } catch {
        $features += [PSCustomObject]@{
            Feature = "TPM"
            Status  = "Not Present"
            Details = "TPM 2.0 not detected or disabled in BIOS"
        }
    }

    # Windows Defender
    try {
        $defender = Get-MpComputerStatus -ErrorAction Stop
        $features += [PSCustomObject]@{
            Feature = "Windows Defender"
            Status  = if ($defender.AntivirusEnabled) { "Enabled" } else { "Disabled" }
            Details = "Real-time: $($defender.RealTimeProtectionEnabled)"
        }
    } catch {
        $features += [PSCustomObject]@{
            Feature = "Windows Defender"
            Status  = "Unknown"
            Details = $_.Exception.Message
        }
    }

    # Firewall
    try {
        $fw = Get-NetFirewallProfile -ErrorAction Stop
        $enabledProfiles = $fw | Where-Object { $_.Enabled } | ForEach-Object { $_.Name }
        $profileCount = if ($enabledProfiles) { $enabledProfiles.Count } else { 0 }
        $profiles = ($enabledProfiles -join ", ")
        if ($profiles) {
            $features += [PSCustomObject]@{
                Feature = "Windows Firewall"
                Status  = "Enabled ($profileCount profiles)"
                Details = "Active: $profiles"
            }
        } else {
            $features += [PSCustomObject]@{
                Feature = "Windows Firewall"
                Status  = "Disabled"
                Details = "No profiles enabled"
            }
        }
    } catch {
        $features += [PSCustomObject]@{
            Feature = "Windows Firewall"
            Status  = "Unknown"
            Details = $_.Exception.Message
        }
    }

    return $features
}