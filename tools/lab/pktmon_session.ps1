$script:PktmonSessionExe = Join-Path $env:SystemRoot 'System32\pktmon.exe'
$script:PktmonStoppedPattern = '(?i)not running|is stopped|not started|не запущен|не выполняется|остановлен|сбор не ведется|сбор не ведётся'

function Get-PktmonSessionStatus {
    $text = (& $script:PktmonSessionExe status 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read Pktmon status; refusing to alter any capture.' }
    return $text
}

function Get-PktmonSessionEtlPath([string]$StatusText) {
    $match = [regex]::Match($StatusText, '(?im)^\s*(?:log\s+file|file\s+name|файл\s+журнала|имя\s+файла)\s*:\s*(.+?\.etl)\s*$')
    if (-not $match.Success) {
        $match = [regex]::Match($StatusText, '(?i)([a-z]:\\[^\r\n]*?\.etl)')
    }
    if (-not $match.Success) { return $null }
    return [IO.Path]::GetFullPath($match.Groups[1].Value.Trim().Trim('"'))
}

function Assert-PktmonStopped {
    $status = Get-PktmonSessionStatus
    if ($status -notmatch $script:PktmonStoppedPattern) {
        $path = Get-PktmonSessionEtlPath $status
        $detail = if ($path) { ": $path" } else { "" }
        throw "Pktmon is already active$detail; lab capture refused without stopping it."
    }
}

function Assert-PktmonOwned([string]$EtlPath) {
    $status = Get-PktmonSessionStatus
    $expected = [IO.Path]::GetFullPath($EtlPath)
    $active = Get-PktmonSessionEtlPath $status
    if ($status -match $script:PktmonStoppedPattern -or -not $active -or
        -not [string]::Equals($active, $expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Pktmon did not start the expected lab capture ($expected); no stop will be issued."
    }
}

function Stop-PktmonOwned([string]$EtlPath) {
    Assert-PktmonOwned $EtlPath
    $output = (& $script:PktmonSessionExe stop 2>&1 | Out-String)
    $stopCode = $LASTEXITCODE
    $status = Get-PktmonSessionStatus
    if ($stopCode -ne 0 -or $status -notmatch $script:PktmonStoppedPattern) {
        throw "Could not verify a clean stop for the owned Pktmon capture ($EtlPath)."
    }
    return $output
}
