<#
.SYNOPSIS
    Install the current vm_shrd package into PRODUCT_TESTS, restart it, wait for
    the product to come up, and collect every log back to the host.

.DESCRIPTION
    All product code runs inside the guest. The host only drives VMware.

      1. Revert to an existing snapshot (never creates or deletes one) and start
      2. Copy the bundle from the shared folder into the guest, verify its SHA-256
      3. Silent install:  Setup.exe /quiet /norestart /log
      4. Restart the guest and wait for the real reboot
      5. Wait for: driver Stage 2 complete, PhantomSensor running, service running,
         and the service log reporting driver attestation
      6. Collect logs + a state report into vm_shrd\PhantomHome\diag-auto\<stamp>
      7. Leave the VM running for manual UI testing (unless -PowerOff)

    The guest is left at the logon screen after the restart. The UI and tray start
    only when someone signs in, so this run covers the service, driver and
    installer; sign in afterwards to test the UI.

.EXAMPLE
    .\tools\vm-harness\Invoke-VmTestRun.ps1
    .\tools\vm-harness\Invoke-VmTestRun.ps1 -Snapshot Test1234 -ProductWaitSec 600
#>
param(
    [string]$VmxPath  = 'C:\Users\RTX40\Documents\Virtual Machines\PRODUCT_TESTS\PRODUCT_TESTS.vmx',
    [string]$Snapshot = 'Test1234',
    [int]$ProductWaitSec = 480,
    [switch]$PowerOff,
    # Skip install and restart; only collect logs from the running VM, for
    # example after testing the UI by hand.
    [switch]$CollectOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'PhantomVm.psm1') -Force

$RepoRoot   = $PSScriptRoot | Split-Path | Split-Path
$PkgDir     = Join-Path $RepoRoot 'vm_shrd\PhantomHome'
$Bundle     = Join-Path $PkgDir 'ShadowStrikePhantom-Home-Setup.exe'
$GuestShare = '\\vmware-host\Shared Folders\vm_shrd\PhantomHome'
$GuestWork  = 'C:\ProgramData\ss-vm'
$Stamp      = Get-Date -Format 'yyyyMMdd-HHmmss'

if (-not (Test-Path $Bundle)) { throw "No package to test: $Bundle" }
$version  = (Get-Item $Bundle).VersionInfo.ProductVersion
$hostHash = (Get-FileHash $Bundle -Algorithm SHA256).Hash
$OutRel   = "diag-auto\$version-$Stamp"
$OutHost  = Join-Path $PkgDir $OutRel
New-Item -ItemType Directory -Force $OutHost | Out-Null
Start-Transcript -Path (Join-Path $OutHost 'host-run.log') -Force | Out-Null
trap {
    Write-VmLog "FATAL: $($_.Exception.Message)"
    Write-VmLog $_.ScriptStackTrace
    Stop-Transcript | Out-Null
    exit 1
}
$sw = [Diagnostics.Stopwatch]::StartNew()
function Step([string]$m) { Write-VmLog ("[{0,4}s] {1}" -f [int]$sw.Elapsed.TotalSeconds, $m) }

Initialize-PhantomVm -VmxPath $VmxPath
$inst = $null
if (-not $CollectOnly) {

# -- 1. Clean state ------------------------------------------------------------
if (Test-PhantomVmRunning) { Stop-PhantomVm -Hard }
Restore-PhantomVmSnapshot -Name $Snapshot
Start-PhantomVm
Wait-PhantomVmGuest -TimeoutSec 600
Step "Guest ready (snapshot '$Snapshot')"

# -- 1b. Keep Windows Update out of the run -------------------------------------
# TEST ENVIRONMENT ONLY, undone by the next snapshot revert. During the first
# automated run Windows Update executed the Malicious Software Removal Tool
# (KB890830) at shutdown, and it removed the service as Ransom:Win32/Locky.A
# because the binary embeds Locky indicator strings in plain text. That is a
# real product defect (task 331) and is NOT hidden by this: it is reported in
# every run's vm-state.txt. Stopping updates here only keeps an unrelated
# monthly update from deciding whether this run tests anything at all.
#
# sc.exe, not Stop-Service: a busy wuauserv makes Stop-Service block for minutes.
$wu = Invoke-PhantomGuestScript -TimeoutSec 120 -AllowFailure -Script @'
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MRT' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MRT' -Name DontOfferThroughWUAU -Type DWord -Value 1
foreach ($s in 'wuauserv','UsoSvc') {
    sc.exe config $s start= disabled | Out-Null
    sc.exe stop $s | Out-Null
}
Get-Process mrt -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
# An idle guest at the logon screen requests ACPI sleep and VMware suspends the
# VM in the middle of a run. Test environment only; undone by the next revert.
powercfg.exe /change standby-timeout-ac 0 | Out-Null
powercfg.exe /change hibernate-timeout-ac 0 | Out-Null
powercfg.exe /hibernate off | Out-Null
"wuauserv=" + (Get-Service wuauserv).StartType + " UsoSvc=" + (Get-Service UsoSvc).StartType + " MRT-offer=off"
'@
Step "Windows Update paused for this run: $($wu.Output.Trim())"

# -- 2. Installer into the guest ------------------------------------------------
$copy = Invoke-PhantomGuestScript -TimeoutSec 300 -Script @"
New-Item -ItemType Directory -Force '$GuestWork' | Out-Null
Copy-Item -LiteralPath '$GuestShare\ShadowStrikePhantom-Home-Setup.exe' -Destination '$GuestWork\Setup.exe' -Force
(Get-FileHash '$GuestWork\Setup.exe' -Algorithm SHA256).Hash
"@
if ($copy.Output.Trim() -ne $hostHash) { throw "Installer hash mismatch in guest: '$($copy.Output.Trim())' vs host $hostHash" }
Step "Installer $version copied, SHA-256 verified"

# -- 3. Silent install -----------------------------------------------------------
$inst = Invoke-PhantomGuestScript -TimeoutSec 900 -AllowFailure -Script @"
`$p = Start-Process -FilePath '$GuestWork\Setup.exe' -ArgumentList '/quiet','/norestart','/log','$GuestWork\install.log' -Wait -PassThru
"installer exit code: " + `$p.ExitCode
exit `$p.ExitCode
"@
Step $inst.Output
$postInstall = (Invoke-PhantomGuestScript -TimeoutSec 60 -AllowFailure -Script @'
"exe=" + (Test-Path 'C:\Program Files\ShadowStrike\Phantom\ShadowStrikePhantomService.exe') +
" serviceKey=" + (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\ShadowStrikePhantomService') +
" pendingRenames=" + @((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -EA 0).PendingFileRenameOperations | Where-Object { $_ -match 'ShadowStrike' }).Count
'@).Output.Trim()
Step "After install: $postInstall"
if ($inst.ExitCode -notin 0, 3010) {
    Write-VmLog 'Install failed - collecting what exists'
}

# -- 4. Restart -------------------------------------------------------------------
if ($inst.ExitCode -in 0, 3010) {
    Restart-PhantomGuest -TimeoutSec 900
    Step 'Guest restarted'
    $postBoot = (Invoke-PhantomGuestScript -TimeoutSec 60 -AllowFailure -Script @'
"exe=" + (Test-Path 'C:\Program Files\ShadowStrike\Phantom\ShadowStrikePhantomService.exe') +
" serviceKey=" + (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\ShadowStrikePhantomService')
'@).Output.Trim()
    Step "After reboot: $postBoot"

    # -- 5. Wait for the product ---------------------------------------------------
    $deadline = [DateTime]::UtcNow.AddSeconds($ProductWaitSec)
    $state = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        $state = (Invoke-PhantomGuestScript -TimeoutSec 120 -AllowFailure -Script @'
$logs = 'C:\ProgramData\ShadowStrike\Logs'
$stage2 = [bool](Get-ChildItem $logs -Filter 'DriverResume.*.log' -ErrorAction SilentlyContinue |
          Select-String -SimpleMatch '=== Stage 2 complete. ===' -List)
$drv = (Get-Service PhantomSensor -ErrorAction SilentlyContinue).Status
$svc = (Get-Service ShadowStrikePhantomService -ErrorAction SilentlyContinue).Status
$att = [bool](Get-ChildItem $logs -Filter 'PhantomHome.Service*.log' -ErrorAction SilentlyContinue |
       Select-String -SimpleMatch 'Driver attestation passed' -List)
"stage2=$stage2 driver=$drv service=$svc attestation=$att"
'@).Output.Trim()
        if ($state -match 'stage2=True driver=Running service=Running attestation=True') { break }
        Start-Sleep -Seconds 10
    }
    Step "Product state: $state"
}

}  # end of install/restart/wait (skipped with -CollectOnly)

# -- 6. Collect ---------------------------------------------------------------------
$collect = Invoke-PhantomGuestScript -TimeoutSec 600 -AllowFailure -Script @"
`$dst = '$GuestShare\$OutRel'
New-Item -ItemType Directory -Force `$dst | Out-Null
Copy-Item 'C:\ProgramData\ShadowStrike\Logs\*' `$dst -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item '$GuestWork\install*.log' `$dst -Force -ErrorAction SilentlyContinue
Get-ChildItem `$env:TEMP -Filter '*ShadowStrike*.log' -ErrorAction SilentlyContinue | Copy-Item -Destination `$dst -Force
foreach (`$u in Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue) {
    `$l = Join-Path `$u.FullName 'AppData\Local\ShadowStrike\Logs'
    if (Test-Path `$l) { Get-ChildItem `$l -File | ForEach-Object { Copy-Item `$_.FullName (Join-Path `$dst ("client-" + `$u.Name + "-" + `$_.Name)) -Force } }
}
`$r = [System.Collections.Generic.List[string]]::new()
`$r.Add("=== collected " + (Get-Date).ToString('o'))
`$r.Add("=== services"); `$r.Add((Get-Service ShadowStrikePhantomService,PhantomSensor -ErrorAction SilentlyContinue | Format-Table -Auto Name,Status,StartType | Out-String))
`$r.Add("=== sc query PhantomSensor"); `$r.Add((sc.exe query PhantomSensor | Out-String))
`$r.Add("=== fltmc"); `$r.Add((fltmc.exe filters | Out-String))
`$r.Add("=== processes"); `$r.Add((Get-Process -ErrorAction SilentlyContinue | Where-Object ProcessName -like 'ShadowStrike*' | Format-Table -Auto Id,ProcessName,@{n='WS_MB';e={[int](`$_.WorkingSet64/1MB)}},@{n='PeakWS_MB';e={[int](`$_.PeakWorkingSet64/1MB)}},@{n='CPU_s';e={[int]`$_.CPU}} | Out-String))
`$r.Add("=== certificates"); `$r.Add((Get-ChildItem Cert:\LocalMachine\Root,Cert:\LocalMachine\TrustedPublisher | Where-Object Subject -like '*ShadowStrike*' | Format-Table -Auto PSParentPath,Subject,Thumbprint | Out-String))
`$r.Add("=== defender"); `$r.Add((Get-MpComputerStatus -ErrorAction SilentlyContinue | Format-List RealTimeProtectionEnabled,IsTamperProtected | Out-String))
`$r.Add("=== defender detections"); `$r.Add((Get-MpThreatDetection -ErrorAction SilentlyContinue | Format-List InitialDetectionTime,ThreatID,Resources | Out-String))
`$r.Add("=== MSRT (C:\Windows\debug\mrt.log, last run)"); if (Test-Path C:\Windows\debug\mrt.log) { `$t = Get-Content C:\Windows\debug\mrt.log; `$i = [Math]::Max(0, @(`$t | Select-String -SimpleMatch 'Started On').Count); `$r.Add(((`$t | Select-Object -Last 30) -join "``n")) }
`$r.Add("=== application errors (last 2h)"); `$r.Add((Get-WinEvent -FilterHashtable @{LogName='Application';Level=1,2;StartTime=(Get-Date).AddHours(-2)} -MaxEvents 40 -ErrorAction SilentlyContinue | Format-Table -Auto -Wrap TimeCreated,ProviderName,Id,Message | Out-String -Width 300))
`$r.Add("=== system errors (last 2h)"); `$r.Add((Get-WinEvent -FilterHashtable @{LogName='System';Level=1,2;StartTime=(Get-Date).AddHours(-2)} -MaxEvents 40 -ErrorAction SilentlyContinue | Format-Table -Auto -Wrap TimeCreated,ProviderName,Id,Message | Out-String -Width 300))
`$r | Out-File -Encoding utf8 -Width 300 (Join-Path `$dst 'vm-state.txt')
(Get-ChildItem `$dst -File | Measure-Object).Count
"@
Step "Collected $($collect.Output.Trim()) file(s) into vm_shrd\PhantomHome\$OutRel"

if ($CollectOnly) { Wait-PhantomVmGuest -TimeoutSec 60 }
if ($PowerOff) { Stop-PhantomVm } else { Step 'VM left running - sign in to test the UI' }
Write-VmLog "Done in $([int]$sw.Elapsed.TotalSeconds) s. Logs: $OutHost"
Stop-Transcript | Out-Null
