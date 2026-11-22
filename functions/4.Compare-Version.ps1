function Compare-Version {
    <#
    .SYNOPSIS
        Compares two version strings.

    .PARAMETER Version1
        First version string

    .PARAMETER Version2
        Second version string

    .OUTPUTS
        -1 if Version1 < Version2, 0 if equal, 1 if Version1 > Version2
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Version1,
        [Parameter(Mandatory=$true)][string]$Version2
    )

    $v1 = [version]($Version1 -replace '^v', '')
    $v2 = [version]($Version2 -replace '^v', '')

    return $v1.CompareTo($v2)
}