function Get-WindowsBuildInfo {
    <#
    .SYNOPSIS
        Gets Windows 11 build version and patch level information.

    .OUTPUTS
        PSCustomObject with BuildNumber, UBR, Channel, InstallDate, LastBoot
    #>
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).UBR

        [PSCustomObject]@{
            BuildNumber = $os.BuildNumber
            UBR         = $ubr
            FullVersion = "10.0.$($os.BuildNumber).$ubr"
            Channel     = "Release"  # Would need more detection for Dev/Insider
            InstallDate = $os.InstallDate
            LastBoot    = $os.LastBootUpTime
            OSCaption   = $os.Caption
            Version     = $os.Version
        }
    } catch {
        Write-Error "Failed to get Windows build info: $_"
        $null
    }
}