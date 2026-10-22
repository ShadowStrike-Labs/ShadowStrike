<#
.SYNOPSIS
    Restart PRODUCT_TESTS and sample the service's private commit and working set
    every second from the moment its process appears. Task 227.

.DESCRIPTION
    Run with the product installed and the VM running. Writes a CSV beside the
    run logs and prints the peak with its time, so the peak can be matched to the
    service log line that was being written at that second.
#>
param(
    [string]$VmxPath = 'C:\Users\RTX40\Documents\Virtual Machines\PRODUCT_TESTS\PRODUCT_TESTS.vmx',
    [int]$Seconds = 420,
    [string]$OutCsv,
    [switch]$NoRestart
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'PhantomVm.psm1') -Force
Initialize-PhantomVm -VmxPath $VmxPath
Wait-PhantomVmGuest -TimeoutSec 120
if (-not $NoRestart) { Restart-PhantomGuest -TimeoutSec 900 }

$r = Invoke-PhantomGuestScript -TimeoutSec ($Seconds + 400) -AllowFailure -Script @"
`$deadline = (Get-Date).AddSeconds(300)
while (-not (Get-Process ShadowStrikePhantomService -EA 0) -and (Get-Date) -lt `$deadline) { Start-Sleep -Milliseconds 500 }
`$rows = [System.Collections.Generic.List[string]]::new()
`$rows.Add('utc,private_mb,ws_mb,threads,handles')
`$end = (Get-Date).AddSeconds($Seconds)
while ((Get-Date) -lt `$end) {
    `$p = Get-Process ShadowStrikePhantomService -EA 0
    if (`$p) { `$rows.Add(('{0},{1},{2},{3},{4}' -f (Get-Date).ToUniversalTime().ToString('HH:mm:ss'), [int](`$p.PrivateMemorySize64/1MB), [int](`$p.WorkingSet64/1MB), `$p.Threads.Count, `$p.HandleCount)) }
    Start-Sleep -Seconds 1
}
`$rows -join "``n"
"@
$csv = $r.Output.Trim()
if ($OutCsv) { $csv | Out-File -Encoding ascii $OutCsv }
$data = $csv -split "`r?`n" | Select-Object -Skip 1 | ForEach-Object { $f = $_ -split ','; [pscustomobject]@{ T=$f[0]; Priv=[int]$f[1]; WS=[int]$f[2] } }
$peak = $data | Sort-Object Priv -Descending | Select-Object -First 1
Write-VmLog ("samples={0} first={1} peakPrivate={2} MB at {3} UTC  final={4} MB" -f @($data).Count, $data[0].T, $peak.Priv, $peak.T, $data[-1].Priv)
