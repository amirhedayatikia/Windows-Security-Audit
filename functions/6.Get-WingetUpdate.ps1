function Invoke-WingetProcess {
    <#
    .SYNOPSIS
        Runs winget upgrade --disable-interactivity --quiet and captures output.

    .DESCRIPTION
        Internal helper used by Get-WingetUpdate. Separated so tests can inject
        output without launching winget. Read-only: never modifies packages or sources.

    .PARAMETER WinGetPath
        Path to the winget executable. Defaults to 'winget' on PATH.

    .OUTPUTS
        PSCustomObject with ExitCode, StandardOutput, StandardError
    #>
    [CmdletBinding()]
    param(
        [string]$WinGetPath = 'winget'
    )

    $outputFile = Join-Path $env:TEMP "win11-cve-audit-winget-out-$([guid]::NewGuid()).txt"
    $errorFile  = Join-Path $env:TEMP "win11-cve-audit-winget-err-$([guid]::NewGuid()).txt"

    try {
        $process = Start-Process -FilePath $WinGetPath `
            -ArgumentList @('upgrade','--disable-interactivity') `
            -NoNewWindow -PassThru -Wait `
            -RedirectStandardOutput $outputFile `
            -RedirectStandardError $errorFile 2>$null
        $exitCode = $process.ExitCode
        $output   = Get-Content $outputFile -Raw -ErrorAction SilentlyContinue
        $stderr   = Get-Content $errorFile -Raw -ErrorAction SilentlyContinue
        Remove-Item $outputFile -ErrorAction SilentlyContinue
        Remove-Item $errorFile  -ErrorAction SilentlyContinue
    } catch {
        $caughtError = $_
        # Surface the error and return failure result
        Write-Warning "winget process failed: $($caughtError.Exception.Message)"
        return [PSCustomObject]@{
            ExitCode        = $null
            StandardOutput  = $null
            StandardError   = $caughtError.Exception.Message
            ProcessFailed   = $true
        }
    }

    return [PSCustomObject]@{
        ExitCode         = $exitCode
        StandardOutput   = $output
        StandardError    = $stderr
        ProcessFailed    = $false
    }
}

function ConvertFrom-WingetUpgradeOutput {
    <#
    .SYNOPSIS
        Parses winget upgrade console output into structured results.

    .DESCRIPTION
        Pure parsing logic used by Get-WingetUpdate. Accepts raw console text
        and returns status plus items without launching winget.

    .PARAMETER Output
        Raw winget upgrade console output text.

    .PARAMETER Stderr
        Raw winget upgrade stderr text.

    .PARAMETER ExitCode
        winget exit code.

    .OUTPUTS
        PSCustomObject with Status, Items, Reason, Error, Confidence
    #>
    [CmdletBinding()]
    param(
        [object]$Output,
        [string]$Stderr,
        [int]$ExitCode
    )

    # ExitCode is reserved for future use when distinguishing exit-code-based
    # failures from source/parse failures
    $null = $ExitCode

    $now = Get-Date

    # Normalize array output from tests to a single string.
    if ($Output -is [array]) {
        $Output = $Output -join "`n"
    }

    # Never equate missing output with a clean scan.
    if (-not $Output -or $Output -match '^\s*$') {
        return [PSCustomObject]@{
            Status         = 'ParseError'
            Items          = @()
            Reason         = 'winget produced no usable output'
            Error          = $Stderr
            Timestamp      = $now
            Confidence     = 'Medium'
            Source         = 'winget'
        }
    }

    # winget outputs "No installed package found matching input criteria." when
    # there are no upgradeable packages in the current scope/source. Treat this
    # as a successful zero-update scan, not a parse error.
    if ($Output -match 'No installed package found matching input criteria') {
        return [PSCustomObject]@{
            Status         = 'NoUpdates'
            Items          = @()
            Reason         = 'No winget packages have available upgrades'
            Error          = $null
            Timestamp      = $now
            Confidence     = 'High'
            Source         = 'winget'
        }
    }

    # Source/network errors appear on stderr; treat them as incomplete checks,
    # not as a successful zero-update scan. Do not scan stdout data rows for
    # error keywords, since column names such as "Source" are not failures.
    if ($Stderr -and $Stderr -match 'source|network|unavailable|error') {
        return [PSCustomObject]@{
            Status         = 'SourceError'
            Items          = @()
            Reason         = 'winget source or network unavailable'
            Error          = $Stderr
            Timestamp      = $now
            Confidence     = 'Medium'
            Source         = 'winget'
        }
    }

    # Check data rows for explicit source failure messages (exclude header and separator).
    # $Output may be a string (from Get-Content -Raw) or an array (from tests).
    if ($Output -is [array]) {
        $outputLines = $Output
    } elseif ($Output) {
        $outputLines = $Output -split "`n"
    } else {
        $outputLines = @()
    }
    $dataRows = $outputLines | Where-Object { $_ -notmatch '^\s*Name\s+Id\s+Version\s+Available' -and $_ -notmatch '^[-\s]*$' }
    if ($dataRows -and ($dataRows -match 'source|network|unavailable|error')) {
        return [PSCustomObject]@{
            Status         = 'SourceError'
            Items          = @()
            Reason         = 'winget source or network unavailable'
            Error          = $Stderr
            Timestamp      = $now
            Confidence     = 'Medium'
            Source         = 'winget'
        }
    }

    # Header row: "Name  Id  Version Available Source"
    $headerIndex = $null
    for ($i = 0; $i -lt $outputLines.Count; $i++) {
        if ($outputLines[$i] -match '^\s*Name\s+Id\s+Version\s+Available') {
            $headerIndex = $i
            break
        }
    }

    if ($null -eq $headerIndex) {
        return [PSCustomObject]@{
            Status         = 'ParseError'
            Items          = @()
            Reason         = 'winget output header not recognized'
            Error          = $Stderr
            Timestamp      = $now
            Confidence     = 'Medium'
            Source         = 'winget'
        }
    }

    $header = $outputLines[$headerIndex]
    # Verify expected header columns exist before parsing data rows
    if ($header -notmatch 'Name' -or $header -notmatch 'Id' -or $header -notmatch 'Version' -or $header -notmatch 'Available') {
        return [PSCustomObject]@{
            Status         = 'ParseError'
            Items          = @()
            Reason         = 'winget output header missing required columns'
            Error          = $Stderr
            Timestamp      = $now
            Confidence     = 'Medium'
            Source         = 'winget'
        }
    }

    $results = @()
    for ($i = $headerIndex + 1; $i -lt $outputLines.Count; $i++) {
        $line = $outputLines[$i]
        if (-not $line -or $line -match '^[-\s]*$') { continue }

        # winget pads columns with spaces. Column names contain no spaces, but
        # package names (the first column) can contain spaces. Split on runs of
        # two or more spaces, then take the last four tokens as Id, Version,
        # Available, Source. Everything before them is the package name.
        $tokens = $line -split '\s{2,}'
        $tokens = $tokens | Where-Object { $_ -ne '' }

        if ($tokens.Count -lt 4) { continue }

        $available = $tokens[-2]
        $version   = $tokens[-3]
        $id        = $tokens[-4]
        $name      = $tokens[0..($tokens.Count - 5)] -join ' '
        # $source not used; Source column is hardcoded to 'winget'

        if (-not $id -or -not $version -or -not $available) { continue }

        $results += [PSCustomObject]@{
            Name             = $name.Trim()
            Id               = $id.Trim()
            InstalledVersion = $version.Trim()
            AvailableVersion = $available.Trim()
            Source           = 'winget'
        }
    }

    if ($results.Count -gt 0) {
        return [PSCustomObject]@{
            Status         = 'UpdatesAvailable'
            Items          = @($results)
            Reason         = "$($results.Count) winget package(s) with updates available"
            Error          = $null
            Timestamp      = $now
            Confidence     = 'High'
            Source         = 'winget'
        }
    }

    return [PSCustomObject]@{
        Status         = 'NoUpdates'
        Items          = @()
        Reason         = 'No winget packages have available updates'
        Error          = $null
        Timestamp      = $now
        Confidence     = 'High'
        Source         = 'winget'
    }
}

function Get-WingetUpdate {
    <#
    .SYNOPSIS
        Gets available winget package updates with structured outcome status.

    .DESCRIPTION
        Runs winget upgrade --disable-interactivity --quiet and parses the result
        without relying on English-language console text for outcome decisions.
        Returns a structured object describing update availability, errors, and
        available upgrades. Read-only: never modifies packages or sources.

    .PARAMETER WinGetPath
        Path to the winget executable. Defaults to 'winget' on PATH.

    .OUTPUTS
        PSCustomObject with Status, Items, Reason, Error, Timestamp, Confidence, Source
        Status values:
          UpdatesAvailable      - winget ran successfully and reported upgrades
          NoUpdates             - winget ran successfully and reported no upgrades
          Unavailable           - winget executable not found
          ExecutionFailed       - winget returned nonzero exit code
          SourceError           - output indicates a source/network error
          ParseError            - output ran but could not be parsed
          Unknown               - outcome could not be determined

    .EXAMPLE
        Get-WingetUpdate

    .EXAMPLE
        Get-WingetUpdate -WinGetPath 'C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller\winget.exe'
    #>
    [CmdletBinding()]
    param(
        [string]$WinGetPath = 'winget'
    )

    $now = Get-Date

    # Try structured Microsoft.WinGet.Client API first; fall back to console parsing
    $structured = Get-WingetUpdateStructured -ErrorAction SilentlyContinue
    if ($structured -and $structured.Status -ne $null) {
        return $structured
    }

    # Never equate missing output with a clean scan.
    if (-not (Get-Command $WinGetPath -ErrorAction SilentlyContinue)) {
        return [PSCustomObject]@{
            Status         = 'Unavailable'
            Items          = @()
            Reason         = 'winget executable not found'
            Error          = "The 'winget' executable ($WinGetPath) is not available on this machine."
            Timestamp      = $now
            Confidence     = 'High'
            Source         = 'winget'
        }
    }

    $process = Invoke-WingetProcess -WinGetPath $WinGetPath

    if ($process.ProcessFailed) {
        return [PSCustomObject]@{
            Status         = 'ExecutionFailed'
            Items          = @()
            Reason         = 'winget execution failed'
            Error          = $process.StandardError
            Timestamp      = $now
            Confidence     = 'Medium'
            Source         = 'winget'
        }
    }

    if ($process.ExitCode -ne 0) {
        return [PSCustomObject]@{
            Status         = 'ExecutionFailed'
            Items          = @()
            Reason         = "winget exited with code $($process.ExitCode)"
            Error          = $process.StandardError
            Timestamp      = $now
            Confidence     = 'Medium'
            Source         = 'winget'
        }
    }

    return ConvertFrom-WingetUpgradeOutput -Output $process.StandardOutput -Stderr $process.StandardError -ExitCode $process.ExitCode
}
