<#
.SYNOPSIS
  Bounded, detached batch VM run for the package in vm_shrd\PhantomHome: install, soak,
  second reboot, an administrator stop probe, collect, power off.

.DESCRIPTION
  Progress goes to vm_shrd\PhantomHome\batch-<version>.progress.log and evidence to
  batch-<version>.txt, where <version> is the bundle's ProductVersion.

  Every phase has a hard deadline, and the VM is always powered off in the finally block.

  Memory (owner directive 2026-10-22): the run refuses to start unless host headroom
  covers the VM's memsize plus a 2 GB floor, and it starts Watch-VmMemory.ps1, which
  hard-stops the VM if headroom stays below 2 GB. A single low reading during the soak
  does not abort the run; with other work on the host, 3-5 GB is the normal steady state.

    Phase 1  install + first boot     Invoke-VmTestRun.ps1 in a child process, own diag dir
    Phase 2  soak to SoakUptimeMin    kernel capacity line + frame-failure counts every 5 min
    Phase 3  second reboot            threat-intel store reopen, scan channel
    Phase 4  Stop-Service probe       administrator stop behaviour
    Phase 5  collect + power off      Invoke-VmTestRun.ps1 -CollectOnly -PowerOff

  Phase 1 runs as a child so its own `exit` cannot end this runner and so it can be killed
  on its deadline. After the second reboot the service starts delayed-auto, so Phases 3 and
  4 first wait (bounded) for service and driver to run; without that wait both phases
  measured a stopped service on the 1.0.127 run.

.EXAMPLE
  # Launch detached so a cancelled tool call cannot kill it, then poll the progress log:
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
      CommandLine = 'pwsh.exe -NoProfile -ExecutionPolicy Bypass -File "<repo>\tools\vm-harness\Invoke-VmBatchRun.ps1"' }
#>
param(
    [string]$VmxPath = 'C:\Users\RTX40\Documents\Virtual Machines\PRODUCT_TESTS\PRODUCT_TESTS.vmx',
    [int]$SoakUptimeMin = 25,
    [int]$OverallDeadlineMin = 75,
    [int]$ServiceWaitSec = 600
)
$ErrorActionPreference = 'Continue'
$here = $PSScriptRoot
$root = $here | Split-Path | Split-Path
$pkg  = Join-Path $root 'vm_shrd\PhantomHome'
$bundle = Join-Path $pkg 'ShadowStrikePhantom-Home-Setup.exe'
if (-not (Test-Path $bundle)) { throw "No package to test: $bundle" }
$version = (Get-Item $bundle).VersionInfo.ProductVersion
$prog = Join-Path $pkg "batch-$version.progress.log"
$evid = Join-Path $pkg "batch-$version.txt"
$runScript = Join-Path $here 'Invoke-VmTestRun.ps1'
$overallEnd = (Get-Date).AddMinutes($OverallDeadlineMin)

function P([string]$m) { "$(Get-Date -Format 'HH:mm:ss') $m" | Out-File $prog -Append -Encoding ascii }
function E([string]$m) { $m | Out-File $evid -Append -Encoding ascii }
function HeadGB {
    $m = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory
    [math]::Round([math]::Min($m.AvailableMBytes / 1KB, ([double]$m.CommitLimit - [double]$m.CommittedBytes) / 1GB), 1)
}
# All vmrun traffic MUST go through PhantomVm.psm1: the VM is vTPM-encrypted and a
# raw `vmrun` call blocks on a password prompt. Initialize-PhantomVm injects the
# stored credential, so Stop-PhantomVm works where a bare `vmrun stop` would hang.
Import-Module (Join-Path $here 'PhantomVm.psm1') -Force
try { Initialize-PhantomVm -VmxPath $VmxPath } catch { P "WARN: Initialize-PhantomVm failed: $($_.Exception.Message)" }
function KillVm { try { if (Test-PhantomVmRunning) { Stop-PhantomVm -Hard } } catch { P "KillVm: $($_.Exception.Message)" } }

Remove-Item $prog, $evid -ErrorAction SilentlyContinue
$commit = (& git -C $root rev-parse --short HEAD 2>$null)
P "batch $version start; headroom $(HeadGB) GB; soak target ${SoakUptimeMin}m; deadline ${OverallDeadlineMin}m"
E "=== BATCH $version VM RUN  (tree at $commit)"
E "=== started $(Get-Date -Format s)"

function RunChild([string[]]$a, [int]$sec, [string]$label) {
    P "START $label (deadline ${sec}s)"
    $out = "$prog.$label.out"; $err = "$prog.$label.err"
    $p = Start-Process pwsh.exe -PassThru -NoNewWindow `
        -ArgumentList (@('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$runScript`"") + $a) `
        -RedirectStandardOutput $out -RedirectStandardError $err
    $null = $p.Handle
    if (-not $p.WaitForExit($sec * 1000)) { & taskkill.exe /T /F /PID $p.Id 2>$null | Out-Null; P "KILLED $label after ${sec}s"; return $false }
    P "END $label exit=$($p.ExitCode)"
    return ($p.ExitCode -eq 0)
}

# Bounded wait for the product after a reboot: service and driver running, and the service
# up long enough to have initialized. Returns the last state line; never throws.
function Wait-ServiceUp([int]$TimeoutSec, [int]$MinUptimeSec = 90) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec); $last = ''
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-PhantomGuestScript -TimeoutSec 120 -AllowFailure -Script @'
$p = Get-Process ShadowStrikePhantomService -EA 0
$up = if ($p) { [int]((Get-Date) - $p.StartTime).TotalSeconds } else { -1 }
"service=" + (Get-Service ShadowStrikePhantomService -EA 0).Status + " driver=" + (Get-Service PhantomSensor -EA 0).Status + " uptimeSec=$up"
'@
            $last = $r.Output.Trim()
            $m = [regex]::Match($last, 'service=Running driver=Running uptimeSec=(\d+)')
            if ($m.Success -and [int]$m.Groups[1].Value -ge $MinUptimeSec) { return "UP $last" }
        } catch { $last = "guest not ready: $($_.Exception.Message)" }
        Start-Sleep -Seconds 15
    }
    return "TIMEOUT after ${TimeoutSec}s (last: $last)"
}

$readCap = @'
$f='C:\ProgramData\ShadowStrike\Logs\PhantomHome.Service.log'
$p=Get-Process ShadowStrikePhantomService -EA 0
$up= if($p){[int]((Get-Date)-$p.StartTime).TotalMinutes}else{-1}
"uptime=$up"
Select-String -Path $f -Pattern 'kernelPreCreate: total=' | Select-Object -Last 1 | ForEach-Object { $i=$_.Line.IndexOf('kernelDeniedAllCallbacks'); if($i -ge 0){$_.Line.Substring($i)}else{$_.Line} }
foreach($s in 'frame failed integrity or decryption','HMAC verification FAILED','Invalid kernel encryption header','Invalid message magic','consecutive unusable receives','RegistryNotify valueName exceeds buffer'){ "{0} = {1}" -f $s, @(Select-String -Path $f -SimpleMatch $s).Count }
'@

$preReboot = @'
$f='C:\ProgramData\ShadowStrike\Logs\PhantomHome.Service.log'
'--- feed / store state before the second reboot'
Select-String -Path $f -Pattern 'StartFeedUpdates|feed.*(sync|update|success|fail|entries|indicators)|ThreatIntelStore.*(entries|initialized)|IOC entries|UpdateTimestamp' | Select-Object -Last 20 | ForEach-Object { $_.Line }
'--- Data directory'
Get-ChildItem 'C:\ProgramData\ShadowStrike\Data' -EA 0 | Select-Object Name,Length,LastWriteTime | Format-Table -Auto | Out-String
'@

$postReboot = @'
$f='C:\ProgramData\ShadowStrike\Logs\PhantomHome.Service.log'
$b='C:\ProgramData\ShadowStrike\Logs\PhantomHome.Service.boot.log'
'svc=' + (Get-Service ShadowStrikePhantomService -EA 0).Status + ' drv=' + (Get-Service PhantomSensor -EA 0).Status
'--- threatintel store reopen / degraded'
Select-String -Path $f,$b -Pattern 'was unreadable|unusable content|ThreatIntelStore unavailable|initialized successfully with|OpenExisting|could not be moved aside' -EA 0 | Select-Object -Last 25 | ForEach-Object { $_.Line }
'--- *.unreadable sidecars'
Get-ChildItem 'C:\ProgramData\ShadowStrike\Data' -Filter *.unreadable -EA 0 | ForEach-Object { $_.FullName }
'--- scan channel / attestation'
Select-String -Path $f,$b -Pattern 'scanner connection FAILED|scan channel|Driver attestation|kernelPreCreate: total=' -EA 0 | Select-Object -Last 8 | ForEach-Object { $_.Line }
'@

$stopProbe = @'
$svc='ShadowStrikePhantomService'
$r=[System.Collections.Generic.List[string]]::new()
$r.Add('before: ' + (Get-Service $svc -EA 0).Status)
try { Stop-Service $svc -Force -ErrorAction Stop; $r.Add('Stop-Service -Force: returned ok') } catch { $r.Add('Stop-Service -Force: ' + $_.Exception.Message) }
Start-Sleep 5; $r.Add('after 5s: ' + (Get-Service $svc -EA 0).Status)
$r.Add((sc.exe query $svc | Out-String))
Start-Sleep 55; $r.Add('after 60s: ' + (Get-Service $svc -EA 0).Status)
$f='C:\ProgramData\ShadowStrike\Logs\PhantomHome.Service.log'
$r.Add(((Select-String -Path $f -Pattern 'attempting restart|shutdown complete|Shutdown complete|Service stopped' -EA 0 | Select-Object -Last 8 | ForEach-Object { $_.Line }) -join "`n"))
$r -join "`n"
'@

$installOk = $false
try {
    # The VM commits its whole memsize, so headroom must cover it plus the kill-switch floor.
    $memMB = 0
    $mm = [regex]::Match((Get-Content -LiteralPath $VmxPath -Raw), 'memsize\s*=\s*"(\d+)"')
    if ($mm.Success) { $memMB = [int]$mm.Groups[1].Value }
    $needGB = if ($memMB -gt 0) { [math]::Ceiling($memMB / 1024) + 2 } else { 18 }
    if ((HeadGB) -lt $needGB) { P "ABORT: headroom $(HeadGB) GB < $needGB GB (VM memsize $memMB MB + 2 GB floor)"; return }

    $ks = Join-Path $here 'Watch-VmMemory.ps1'
    $kc = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
        CommandLine      = "pwsh.exe -NoProfile -ExecutionPolicy Bypass -File `"$ks`" -MaxMin $($OverallDeadlineMin + 10)"
        CurrentDirectory = $here }
    P "kill switch started rc=$($kc.ReturnValue) pid=$($kc.ProcessId)"

    # -- Phase 1: install + first boot (proven script, own diag dir, leaves VM running) --
    $installOk = RunChild @('-ProductWaitSec', '600') 1500 'install'

    Import-Module (Join-Path $here 'PhantomVm.psm1') -Force
    Initialize-PhantomVm -VmxPath $VmxPath

    if (-not $installOk) {
        P 'install phase failed or timed out; collecting what exists, then power off'
    }
    else {
        # -- Phase 2: soak, sampling the kernel capacity line and the frame-failure counts --
        E "`n=== PHASE 2  soak capacity samples"
        while ((Get-Date) -lt $overallEnd) {
            if (-not (Test-PhantomVmRunning)) { P 'VM gone mid-soak (kill-switch may have fired); ending soak early'; break }
            $r = Invoke-PhantomGuestScript -TimeoutSec 180 -AllowFailure -Script $readCap
            $up = [regex]::Match($r.Output, 'uptime=(-?\d+)').Groups[1].Value
            P "soak uptime=${up}m headroom=$(HeadGB)GB"
            E "--- sample $(Get-Date -Format HH:mm:ss) headroom=$(HeadGB)GB"; E $r.Output
            if ([int]('0' + $up) -ge $SoakUptimeMin) { break }
            Start-Sleep -Seconds 300
        }

        # -- Phase 3: second reboot - feed sync, service stop, reboot, store reopen --
        E "`n=== PHASE 3  second reboot"
        $pre = Invoke-PhantomGuestScript -TimeoutSec 180 -AllowFailure -Script $preReboot
        E $pre.Output
        if (-not (Test-PhantomVmRunning)) { P 'VM gone before reboot (kill-switch may have fired); skipping to finally'; return }
        P 'second reboot'
        try { Restart-PhantomGuest -TimeoutSec 900 } catch { P "reboot fallback: $($_.Exception.Message)" }
        $state = Wait-ServiceUp -TimeoutSec $ServiceWaitSec
        P "after second reboot: $state"
        E "--- product after second reboot: $state"
        $post = Invoke-PhantomGuestScript -TimeoutSec 180 -AllowFailure -Script $postReboot
        E $post.Output

        # -- Phase 4: Stop-Service probe; only meaningful against a running service --
        E "`n=== PHASE 4  Stop-Service -Force as administrator"
        if ($state.StartsWith('UP ')) {
            $stop = Invoke-PhantomGuestScript -TimeoutSec 180 -AllowFailure -Script $stopProbe
            E $stop.Output
        } else {
            E "NOT MEASURED: the service was not up ($state)"
        }
    }

    # -- Phase 5: final collect + power off (second-boot logs land in a fresh diag dir) --
    [void](RunChild @('-CollectOnly', '-PowerOff') 900 'collect')
}
catch { P "FATAL: $($_.Exception.Message)" }
finally {
    try {
        Import-Module (Join-Path $here 'PhantomVm.psm1') -Force
        Initialize-PhantomVm -VmxPath $VmxPath
        if (Test-PhantomVmRunning) { Stop-PhantomVm -Hard }
    } catch { KillVm }
    P "batch $version done; headroom $(HeadGB) GB"
    E "`n=== finished $(Get-Date -Format s)"
}
