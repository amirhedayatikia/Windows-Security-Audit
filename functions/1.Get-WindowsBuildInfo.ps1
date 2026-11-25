function Get-WindowsBuildInfo {
    <#
    .SYNOPSIS
        Gets Windows 11 build version and patch level information.

    .OUTPUTS
        PSCustomObject with BuildNumber, UBR, FullVersion, Channel, InstallDate, LastBoot, OSCaption, Version, Edition, Architecture
    #>
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $ubrRaw = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).UBR

        # Validate UBR - must be a valid integer
        $ubr = $null
        if ($null -ne $ubrRaw -and $ubrRaw -ne '') {
            $ubr = [int]$ubrRaw
        }

        # Get edition
        $edition = $null
        try {
            $osEdition = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
            $edition = $osEdition.OSProductSuite
        } catch {
            # Best effort - edition not critical
        }

        # Get architecture
        $architecture = $null
        try {
            $procArch = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1 Architecture
            $architecture = switch ($procArch.Architecture) {
                0 { "x86" }
                1 { "MIPS" }
                2 { "Alpha" }
                3 { "PowerPC" }
                6 { "IA64" }
                9 { "x64" }
                default { "Unknown ($($procArch.Architecture))" }
            }
        } catch {
            # Best effort
        }

        [PSCustomObject]@{
            BuildNumber   = $os.BuildNumber
            UBR           = $ubr
            FullVersion   = "10.0.$($os.BuildNumber).$ubrRaw"
            Channel       = "Release"  # Would need more detection for Dev/Insider
            InstallDate   = $os.InstallDate
            LastBoot      = $os.LastBootUpTime
            OSCaption     = $os.Caption
            Version       = $os.Version
            Edition       = $edition
            Architecture  = $architecture
        }
    } catch {
        Write-Error "Failed to get Windows build info: $_"
        $null
    }
}