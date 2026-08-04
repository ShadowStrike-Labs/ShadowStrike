<#
    Measure-PhantomStall.ps1

    Purpose
    -------
    Proves, from inside the guest, whether file operations are being delayed and
    by how much. Everything diagnosed so far has been inferred from the service's
    own log, which cannot show how long OTHER processes wait - and that is exactly
    what the reported "3-4 seconds frozen, 5 seconds normal" pattern is.

    This does two independent measurements once per 250 ms:

      1. File create latency. Creates, writes, closes and deletes a small file in
         a temporary directory. This is the operation that passes through
         PreCreate and can block waiting for a user-mode verdict.

      2. Wall-clock scheduling delay. Measures how much longer than 250 ms the
         loop actually took. If the machine stalls for reasons unrelated to our
         filter, this rises while file latency stays flat, which distinguishes
         "our filter is slow" from "the whole machine is stalled".

    Run for a couple of minutes while the lag is happening, then send the CSV and
    the summary.

    Usage
    -----
      powershell -ExecutionPolicy Bypass -File Measure-PhantomStall.ps1
      powershell -ExecutionPolicy Bypass -File Measure-PhantomStall.ps1 -Seconds 180

    No elevation required. Writes only into its own temp folder.
#>

[CmdletBinding()]
param(
    [int]    $Seconds     = 120,
    [int]    $IntervalMs  = 250,
    [string] $OutCsv      = "$PSScriptRoot\phantom-stall.csv",
    [double] $StallMs     = 250
)

$ErrorActionPreference = 'Stop'

$probeDir = Join-Path $env:TEMP ('PhantomStallProbe_' + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Force -Path $probeDir | Out-Null

Write-Host ''
Write-Host '  Measuring file-operation latency and scheduling delay.'
Write-Host ("  Duration {0}s, sample every {1}ms, flagging anything over {2}ms." -f $Seconds, $IntervalMs, $StallMs)
Write-Host ("  Probe directory: {0}" -f $probeDir)
Write-Host ''

$samples = New-Object System.Collections.Generic.List[object]
$sw      = [System.Diagnostics.Stopwatch]::StartNew()
$opSw    = [System.Diagnostics.Stopwatch]::new()
$deadline = (Get-Date).AddSeconds($Seconds)
$lastTick = $sw.Elapsed.TotalMilliseconds
$i = 0

while ((Get-Date) -lt $deadline) {
    $i++
    $path = Join-Path $probeDir ("p{0}.tmp" -f ($i % 32))

    # --- 1. file create + write + close + delete -------------------------
    $opSw.Restart()
    try {
        $fs = [System.IO.File]::Create($path)
        $b  = [byte[]]@(1,2,3,4,5,6,7,8)
        $fs.Write($b, 0, $b.Length)
        $fs.Close()
        [System.IO.File]::Delete($path)
        $err = ''
    } catch {
        $err = $_.Exception.GetType().Name
    }
    $opSw.Stop()
    $fileMs = $opSw.Elapsed.TotalMilliseconds

    # --- 2. scheduling delay --------------------------------------------
    $now      = $sw.Elapsed.TotalMilliseconds
    $loopMs   = $now - $lastTick
    $lastTick = $now
    $schedMs  = [Math]::Max(0.0, $loopMs - $IntervalMs)

    $stamp = (Get-Date).ToString('HH:mm:ss.fff')
    $samples.Add([pscustomobject]@{
        Time          = $stamp
        FileOpMs      = [Math]::Round($fileMs, 2)
        SchedDelayMs  = [Math]::Round($schedMs, 2)
        Error         = $err
    })

    if ($fileMs -ge $StallMs -or $schedMs -ge $StallMs) {
        Write-Host ("  {0}  file {1,8:N1} ms   sched delay {2,8:N1} ms  {3}" -f `
            $stamp, $fileMs, $schedMs, $(if($err){"[$err]"}else{''})) -ForegroundColor Yellow
    }

    Start-Sleep -Milliseconds $IntervalMs
}

$sw.Stop()
Remove-Item $probeDir -Recurse -Force -ErrorAction SilentlyContinue
$samples | Export-Csv -NoTypeInformation -Path $OutCsv -Encoding UTF8

# ------------------------------- summary -------------------------------
function Pct([double[]]$v, [double]$p) {
    if (-not $v -or $v.Count -eq 0) { return 0 }
    $s = $v | Sort-Object
    $idx = [int][Math]::Floor(($s.Count - 1) * $p)
    return $s[$idx]
}

$fileVals  = @($samples.FileOpMs)
$schedVals = @($samples.SchedDelayMs)
$stalls    = @($samples | Where-Object { $_.FileOpMs -ge $StallMs -or $_.SchedDelayMs -ge $StallMs })

Write-Host ''
Write-Host '  ---------------------------------------------------------------'
Write-Host ('  samples                : {0}' -f $samples.Count)
Write-Host ('  file op  median / p95  : {0:N1} ms / {1:N1} ms   max {2:N1} ms' -f (Pct $fileVals 0.50), (Pct $fileVals 0.95), (($fileVals | Measure-Object -Maximum).Maximum)
)
Write-Host ('  sched    median / p95  : {0:N1} ms / {1:N1} ms   max {2:N1} ms' -f (Pct $schedVals 0.50), (Pct $schedVals 0.95), (($schedVals | Measure-Object -Maximum).Maximum)
)
Write-Host ('  samples over {0} ms    : {1}  ({2:N1}% of run)' -f $StallMs, $stalls.Count, (100.0 * $stalls.Count / [Math]::Max(1,$samples.Count)))

if ($stalls.Count -ge 2) {
    $gaps = @()
    for ($k = 1; $k -lt $stalls.Count; $k++) {
        $t1 = [datetime]::ParseExact($stalls[$k-1].Time, 'HH:mm:ss.fff', $null)
        $t2 = [datetime]::ParseExact($stalls[$k].Time,   'HH:mm:ss.fff', $null)
        $d  = ($t2 - $t1).TotalSeconds
        if ($d -gt 0.4) { $gaps += $d }
    }
    if ($gaps.Count -gt 0) {
        Write-Host ('  stall period median   : {0:N2} s   (min {1:N2} s, max {2:N2} s)' -f `
            (Pct $gaps 0.50), (($gaps | Measure-Object -Minimum).Minimum), (($gaps | Measure-Object -Maximum).Maximum))
    }
}

Write-Host ''
Write-Host '  How to read this:'
Write-Host '    file op high, sched low   -> file operations are being delayed; our filter is implicated.'
Write-Host '    file op low,  sched high  -> the whole machine is stalling for another reason.'
Write-Host '    both high                 -> a system-wide stall that also blocks file I/O.'
Write-Host ''
Write-Host ('  CSV written: {0}' -f $OutCsv)
Write-Host '  ---------------------------------------------------------------'
Write-Host ''
