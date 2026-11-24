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

function Test-PktmonOwnedByLiveIntegrityGuard([string]$EtlPath) {
    # Waiting is safe only when the ETL is in our unique temp layout and the
    # owner marker matches a live project process and its creation time. Never
    # use the path prefix alone as authority to stop or adopt a Pktmon session.
    try {
        $fullPath = [IO.Path]::GetFullPath($EtlPath)
        $parent = [IO.Path]::GetDirectoryName($fullPath)
        $parentName = [IO.Path]::GetFileName($parent)
        $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
        if ([IO.Path]::GetFileName($fullPath) -ne 'segment.etl' -or
            -not $parentName.StartsWith('integrityguard-pktmon-', [StringComparison]::OrdinalIgnoreCase) -or
            -not [string]::Equals([IO.Path]::GetDirectoryName($parent).TrimEnd('\'), $tempRoot,
                                  [StringComparison]::OrdinalIgnoreCase)) { return $false }

        $ownerPath = Join-Path $parent 'owner.json'
        if (-not (Test-Path -LiteralPath $ownerPath -PathType Leaf)) { return $false }
        $owner = Get-Content -LiteralPath $ownerPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $ownerPid = [int]$owner.pid
        $ownerCreated = [double]$owner.process_create_time
        $process = Get-Process -Id $ownerPid -ErrorAction Stop
        if ($process.ProcessName -notin @('IntegrityGuard', 'pythonw')) { return $false }
        $exePath = $process.Path
        if (-not $exePath) { return $false }
        $projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..')).TrimEnd('\') + '\'
        $fullExePath = [IO.Path]::GetFullPath($exePath)
        if (-not $fullExePath.StartsWith($projectRoot, [StringComparison]::OrdinalIgnoreCase)) { return $false }
        $epoch = [DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
        $processCreated = ($process.StartTime.ToUniversalTime() - $epoch).TotalSeconds
        return ([Math]::Abs($processCreated - $ownerCreated) -lt 2.0)
    } catch {
        return $false
    }
}

function Assert-PktmonStopped([int]$WaitForOwnedAppCaptureSeconds = 45) {
    # An active unknown/foreign session is never stopped. When the app itself
    # owns the live temporary capture, wait briefly for its normal bounded stop.
    $deadline = [DateTime]::UtcNow.AddSeconds([Math]::Max(0, $WaitForOwnedAppCaptureSeconds))
    $reportedWait = $false
    while ($true) {
        $status = Get-PktmonSessionStatus
        $path = Get-PktmonSessionEtlPath $status
        if (-not $path) { return }
        if (-not (Test-PktmonOwnedByLiveIntegrityGuard $path)) {
            # The app may have stopped and removed its temp directory between
            # status and owner inspection. Re-read status before refusing.
            $confirmedPath = Get-PktmonSessionEtlPath (Get-PktmonSessionStatus)
            if (-not $confirmedPath) { return }
            if (-not [string]::Equals($confirmedPath, $path, [StringComparison]::OrdinalIgnoreCase)) { continue }
            throw "Pktmon is already active: $path; owner is not verified, so the lab capture will not stop or replace it."
        }
        if ([DateTime]::UtcNow -ge $deadline) {
            throw "IntegrityGuard's own Pktmon capture is still active after $WaitForOwnedAppCaptureSeconds seconds ($path); retry after it finishes."
        }
        if (-not $reportedWait) {
            Write-Host "IntegrityGuard owns the active Pktmon segment; waiting for its normal stop ($path)."
            $reportedWait = $true
        }
        Start-Sleep -Seconds 2
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
    # After a stop there is no capture path in the status (see Assert-PktmonStopped).
    if ($stopCode -ne 0 -or (Get-PktmonSessionEtlPath $status)) {
        throw "Could not verify a clean stop for the owned Pktmon capture ($EtlPath)."
    }
    return $output
}
