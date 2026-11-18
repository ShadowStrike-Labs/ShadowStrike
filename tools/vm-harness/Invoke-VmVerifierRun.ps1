<#
.SYNOPSIS
    Install the staged package and exercise the kernel driver under Driver
    Verifier (/standard) to validate a kernel change is BSOD-safe.

.DESCRIPTION
    Mirrors Invoke-VmTestRun's proven install sequence, but enables Driver
    Verifier on PhantomSensor.sys in the FIRST-BOOT window (where guest exec is
    reliable; task 390 only degrades it ~2 min AFTER a reboot). The subsequent
    reboot loads the driver under Verifier. Every remote-thread creation then
    drives the new ShadowStrikeSendThreadNotification path under Special Pool /
    IRQL / pool-tracking checks, so a buffer or IRQL fault bugchecks the guest.

    Success = the guest boots, the service runs, and the service log shows healthy
    post-reboot operation (the send path ran many times, no bugcheck). A boot-time
    bugcheck shows up as a Restart timeout; a run-time bugcheck as an unresponsive
    guest / boot loop / a minidump.

    Collection uses Copy-FromPhantomGuest, which survives task 390.
#>
param(
    [string]$VmxPath  = 'C:\Users\RTX40\Documents\Virtual Machines\PRODUCT_TESTS\PRODUCT_TESTS.vmx',
    [string]$Snapshot = 'Test1234_8g',
    [int]$ProductWaitSec = 240,
    [string]$VerifierSpec = '/standard',
    [string]$OutHost = (Join-Path $env:TEMP 'vm-verifier')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'PhantomVm.psm1') -Force

$RepoRoot   = $PSScriptRoot | Split-Path | Split-Path
$PkgDir     = Join-Path $RepoRoot 'vm_shrd\PhantomHome'
$Bundle     = Join-Path $PkgDir 'ShadowStrikePhantom-Home-Setup.exe'
$GuestShare = '\\vmware-host\Shared Folders\vm_shrd\PhantomHome'
$GuestWork  = 'C:\ProgramData\ss-vm'
New-Item -ItemType Directory -Force $OutHost | Out-Null
$Log = Join-Path $OutHost 'verifier-run.log'

function Step([string]$m) {
    $line = "[{0:HH:mm:ss}] {1}" -f (Get-Date), $m
    $line | Tee-Object -FilePath $Log -Append
}
trap {
    Step "FATAL: $($_.Exception.Message)"
    Step $_.ScriptStackTrace
    # A boot-time bugcheck typically surfaces here as a Restart/guest-ready timeout.
    exit 1
}

if (-not (Test-Path $Bundle)) { throw "No package: $Bundle" }
$version  = (Get-Item $Bundle).VersionInfo.ProductVersion
$hostHash = (Get-FileHash $Bundle -Algorithm SHA256).Hash
Step "Package $version ($($hostHash.Substring(0,16))...)"

Initialize-PhantomVm -VmxPath $VmxPath

if (Test-PhantomVmRunning) { Stop-PhantomVm -Hard }
Restore-PhantomVmSnapshot -Name $Snapshot
Start-PhantomVm
Wait-PhantomVmGuest -TimeoutSec 600
Step "Guest ready ($Snapshot)"

# Keep Windows Update / MSRT out of the run (MSRT deletes the service as Locky, task 331).
Invoke-PhantomGuestScript -TimeoutSec 120 -AllowFailure -Script @'
foreach ($s in 'wuauserv','UsoSvc') { sc.exe config $s start= disabled | Out-Null; sc.exe stop $s | Out-Null }
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MRT' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MRT' -Name DontOfferThroughWUAU -Type DWord -Value 1
powercfg.exe /change standby-timeout-ac 0 | Out-Null
powercfg.exe /hibernate off | Out-Null
'@ | Out-Null
Step "WU/MSRT paused"

# Copy + verify the installer.
$copy = Invoke-PhantomGuestScript -TimeoutSec 300 -Script @"
New-Item -ItemType Directory -Force '$GuestWork' | Out-Null
Copy-Item -LiteralPath '$GuestShare\ShadowStrikePhantom-Home-Setup.exe' -Destination '$GuestWork\Setup.exe' -Force
(Get-FileHash '$GuestWork\Setup.exe' -Algorithm SHA256).Hash
"@
if ($copy.Output.Trim() -ne $hostHash) { throw "installer hash mismatch in guest" }
Step "Installer copied + SHA-256 verified"

# Silent install.
$inst = Invoke-PhantomGuestScript -TimeoutSec 900 -AllowFailure -Script @"
`$p = Start-Process -FilePath '$GuestWork\Setup.exe' -ArgumentList '/quiet','/norestart','/log','$GuestWork\install.log' -Wait -PassThru
"installer exit code: " + `$p.ExitCode
exit `$p.ExitCode
"@
Step $inst.Output.Trim()
if ($inst.ExitCode -notin 0, 3010) { throw "install failed: exit $($inst.ExitCode)" }

# ---- Enable Driver Verifier on the sensor (first-boot window: guest exec works) ----
$vfScript = @'
# Verifier spec (__VSPEC__) is applied to PhantomSensor.sys on next boot. A lighter
# /flags set omits Special Pool (0x1), whose per-allocation guard pages exhaust pool
# on this large driver at 8 GB and boot-loop the guest; Force-IRQL (0x2), pool
# tracking (0x8), I/O verification (0x10) and deadlock detection (0x20) still catch
# most BSOD-class faults (IRQL violations, pool mismatches, bad IRPs, lock cycles).
verifier.exe __VSPEC__ /driver PhantomSensor.sys | Out-Null
$vq = (verifier.exe /query | Select-String 'PhantomSensor' | Out-String).Trim()
# A bugcheck should write a minidump and auto-reboot so a loop is distinguishable.
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Force | Out-Null
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name CrashDumpEnabled -Type DWord -Value 3 -Force
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name AutoReboot -Type DWord -Value 1 -Force
# Clear any stale dumps so a new one is unambiguous.
Remove-Item 'C:\Windows\Minidump\*.dmp' -Force -ErrorAction SilentlyContinue
"verifier-set: " + ($vq -replace '\s+',' ')
'@ -replace '__VSPEC__', $VerifierSpec
$vf = Invoke-PhantomGuestScript -TimeoutSec 120 -AllowFailure -Script $vfScript
Step "Driver Verifier ($VerifierSpec): $($vf.Output.Trim())"

# Reboot -> driver loads under Verifier. A boot-time bugcheck makes this time out.
Restart-PhantomGuest -TimeoutSec 900
Step "Guest rebooted - PhantomSensor.sys now under Driver Verifier"

# Confirm Verifier is actively instrumenting the driver, in the FIRST-BOOT window -
# runProgramInGuest is reliable here; task 390 only degrades it ~2 min after a reboot,
# which is why the later post-soak probe cannot capture this.
$vq0 = Invoke-PhantomGuestScript -TimeoutSec 90 -AllowFailure -Script @'
(verifier.exe /query 2>&1 | Out-String)
'@
($vq0.Output) | Set-Content -Path (Join-Path $OutHost 'verifier-query.txt')
Step ("Verifier active on PhantomSensor: {0} (full /query in verifier-query.txt)" -f [bool]($vq0.Output -match 'PhantomSensor'))

# Give the service time to start and process many thread-create events under
# Verifier. A run-time bugcheck during this window auto-reboots the guest.
Start-Sleep -Seconds $ProductWaitSec
Step "Waited ${ProductWaitSec}s under Verifier"

# Collect the service log (survives task 390). If this fails, the guest may be
# bugchecked / mid-boot-loop.
$svcLogLocal = Join-Path $OutHost 'PhantomHome.Service.log'
try {
    Copy-FromPhantomGuest -GuestPath 'C:\ProgramData\ShadowStrike\Logs\PhantomHome.Service.log' -HostPath $svcLogLocal -TimeoutSec 180
    Step "Service log collected: $((Get-Item $svcLogLocal).Length) bytes"
} catch {
    Step "SERVICE LOG COPY FAILED (possible bugcheck / unresponsive guest): $($_.Exception.Message)"
}

# Best-effort guest probe: minidump count + verifier status + driver state.
# May fail under task 390 this late; informational only.
$probe = Invoke-PhantomGuestScript -TimeoutSec 60 -AllowFailure -Script @'
$md = @(Get-ChildItem 'C:\Windows\Minidump' -Filter *.dmp -ErrorAction SilentlyContinue)
$drv = (Get-Service PhantomSensor -ErrorAction SilentlyContinue).Status
$svc = (Get-Service ShadowStrikePhantomService -ErrorAction SilentlyContinue).Status
$vq = (verifier.exe /query | Select-String 'PhantomSensor' | Out-String).Trim()
"minidumps=$($md.Count) driver=$drv service=$svc verifierActive=$([bool]$vq)"
'@
Step "Post-reboot probe: $($probe.Output.Trim())"

# If a minidump exists, pull the newest for host-side analysis.
if ($probe.Output -match 'minidumps=([1-9])') {
    try {
        $dmpName = (Invoke-PhantomGuestScript -TimeoutSec 60 -AllowFailure -Script @'
(Get-ChildItem 'C:\Windows\Minidump' -Filter *.dmp | Sort-Object LastWriteTime -Descending | Select-Object -First 1).Name
'@).Output.Trim()
        if ($dmpName) {
            Copy-FromPhantomGuest -GuestPath "C:\Windows\Minidump\$dmpName" -HostPath (Join-Path $OutHost $dmpName) -TimeoutSec 180
            Step "BUGCHECK MINIDUMP collected: $dmpName"
        }
    } catch { Step "minidump copy failed: $($_.Exception.Message)" }
}

Step "Done. VM left running."
