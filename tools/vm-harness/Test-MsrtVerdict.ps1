<#
.SYNOPSIS
    Ask Microsoft's Malicious Software Removal Tool, inside PRODUCT_TESTS, whether
    it would remove the given binaries. Detect-only: nothing is deleted.

.DESCRIPTION
    MSRT removed ShadowStrikePhantomService as Ransom:Win32/Locky.A during an
    automated run (task 331). Its quick scan found it through the service
    registration (service://ShadowStrikePhantomService), so each candidate is
    registered as a demand-start service that is NEVER started, then MRT runs
    with /Q /N (quiet, detect only) and its log is parsed per candidate.

    Nothing from the candidates executes; MRT.exe is Microsoft-signed and is
    copied from the host's System32 into the guest.

.EXAMPLE
    .\tools\vm-harness\Test-MsrtVerdict.ps1 -Candidate bin\Release\ShadowStrikePhantomService.exe
#>
param(
    [Parameter(Mandatory)][string[]]$Candidate,
    [string]$VmxPath  = 'C:\Users\RTX40\Documents\Virtual Machines\PRODUCT_TESTS\PRODUCT_TESTS.vmx',
    [string]$Snapshot = 'Test1234',
    [string]$MrtPath  = 'C:\Windows\System32\MRT.exe',
    [int]$ScanTimeoutSec = 1800,
    [switch]$KeepRunning
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'PhantomVm.psm1') -Force

$RepoRoot  = $PSScriptRoot | Split-Path | Split-Path
$StageRel  = 'msrt-probe'
$StageHost = Join-Path $RepoRoot "vm_shrd\$StageRel"
$StageGuest = "\\vmware-host\Shared Folders\vm_shrd\$StageRel"

if (-not (Test-Path $MrtPath)) { throw "MRT not found: $MrtPath" }
$sig = Get-AuthenticodeSignature $MrtPath
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
    throw "Refusing to use $MrtPath - not a valid Microsoft signature ($($sig.Status))"
}

# Stage MRT and the candidates on the shared folder (faster than vmrun copies).
Remove-Item -Recurse -Force $StageHost -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $StageHost | Out-Null
Copy-Item $MrtPath (Join-Path $StageHost 'MRT.exe')
$map = @()
for ($i = 0; $i -lt $Candidate.Count; $i++) {
    $src = (Resolve-Path $Candidate[$i]).Path
    $d = Join-Path $StageHost "c$i"
    New-Item -ItemType Directory -Force $d | Out-Null
    Copy-Item $src (Join-Path $d (Split-Path $src -Leaf))
    $map += [pscustomobject]@{ Index = $i; Source = $src; Leaf = (Split-Path $src -Leaf);
                               Sha256 = (Get-FileHash $src -Algorithm SHA256).Hash }
}
$mrtVer = (Get-Item $MrtPath).VersionInfo.FileVersion
Write-VmLog "MRT $mrtVer, $($map.Count) candidate(s) staged"

Initialize-PhantomVm -VmxPath $VmxPath
if (Test-PhantomVmRunning) { Stop-PhantomVm -Hard }
Restore-PhantomVmSnapshot -Name $Snapshot
Start-PhantomVm
Wait-PhantomVmGuest -TimeoutSec 600

$names = ($map | ForEach-Object { "'" + $_.Leaf + "'" }) -join ','
$setup = Invoke-PhantomGuestScript -TimeoutSec 600 -Script @"
# Windows Update must not run a different MRT build in the middle of this.
foreach (`$s in 'wuauserv','UsoSvc') { sc.exe config `$s start= disabled | Out-Null; sc.exe stop `$s | Out-Null }
`$root = 'C:\SsMsrtProbe'
New-Item -ItemType Directory -Force `$root | Out-Null
Copy-Item '$StageGuest\MRT.exe' "`$root\MRT.exe" -Force
`$leaves = @($names)
for (`$i = 0; `$i -lt `$leaves.Count; `$i++) {
    `$d = "`$root\c`$i"; New-Item -ItemType Directory -Force `$d | Out-Null
    Copy-Item "$StageGuest\c`$i\`$(`$leaves[`$i])" "`$d\`$(`$leaves[`$i])" -Force
    # Registered, never started.
    sc.exe create "SsMsrtProbe`$i" binPath= "`"`$d\`$(`$leaves[`$i])`"" start= demand | Out-Null
}
Remove-Item C:\Windows\debug\mrt.log -Force -ErrorAction SilentlyContinue
"probes: " + (Get-Service SsMsrtProbe* | Measure-Object).Count
"@
Write-VmLog $setup.Output.Trim()

Write-VmLog 'Running MRT quick scan, detect-only (several minutes)'
$sw = [Diagnostics.Stopwatch]::StartNew()
$scan = Invoke-PhantomGuestScript -TimeoutSec $ScanTimeoutSec -AllowFailure -Script @'
$p = Start-Process C:\SsMsrtProbe\MRT.exe -ArgumentList '/Q','/N' -Wait -PassThru
"mrt exit: " + $p.ExitCode
'@
Write-VmLog ("{0} after {1}s" -f $scan.Output.Trim(), [int]$sw.Elapsed.TotalSeconds)

$log = (Invoke-PhantomGuestScript -TimeoutSec 120 -AllowFailure -Script 'Get-Content C:\Windows\debug\mrt.log -Raw').Output
$logHost = Join-Path $StageHost 'mrt.log'
$log | Out-File -Encoding utf8 $logHost

# Per-candidate verdict: a candidate is detected when a Threat block lists its
# probe service or its path.
$blocks = [regex]::Split($log, '(?m)^Threat Detected:')
foreach ($c in $map) {
    $hit = $blocks | Select-Object -Skip 1 | Where-Object {
        $_ -match "SsMsrtProbe$($c.Index)\b" -or $_ -match [regex]::Escape("C:\SsMsrtProbe\c$($c.Index)\")
    } | Select-Object -First 1
    $verdict = if ($hit) { 'DETECTED ' + (($hit -split "`r?`n")[0].Trim()) } else { 'clean' }
    "{0,-9} c{1} {2}  ({3})" -f ($(if ($hit) {'FLAGGED'} else {'OK'})), $c.Index, $verdict, $c.Source
}
Write-VmLog "Full log: $logHost"

if (-not $KeepRunning) { Stop-PhantomVm -Hard; Restore-PhantomVmSnapshot -Name $Snapshot }
Remove-Item -Recurse -Force (Join-Path $StageHost 'MRT.exe') -ErrorAction SilentlyContinue
