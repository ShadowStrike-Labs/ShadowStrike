<#
.SYNOPSIS
    Task 334 probe: does SCM apply a service's failure (recovery) actions when the
    service misses the 30 s connect window (events 7009/7000)? Uses a throw-away service
    whose binary never calls StartServiceCtrlDispatcher. Clean snapshot; bounded.
#>
param([string]$Out = (Join-Path ($PSScriptRoot | Split-Path | Split-Path) 'vm_shrd\PhantomHome\recovery-probe.txt'))
$ErrorActionPreference = 'Continue'
Import-Module (Join-Path $PSScriptRoot 'PhantomVm.psm1') -Force
Initialize-PhantomVm -VmxPath 'C:\Users\RTX40\Documents\Virtual Machines\PRODUCT_TESTS\PRODUCT_TESTS.vmx'
Stop-PhantomVm -Hard; Restore-PhantomVmSnapshot -Name 'Test1234'; Start-PhantomVm; Wait-PhantomVmGuest -TimeoutSec 300
$s = @'
$name = 'SsProbeNoConnect'
sc.exe delete $name 2>$null | Out-Null
sc.exe create $name binPath= "C:\Windows\System32\cmd.exe /c ping -n 400 127.0.0.1" start= demand | Out-Null
sc.exe failure $name reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
sc.exe failureflag $name 1 | Out-Null
$t0 = Get-Date
sc.exe start $name | Out-Null
Start-Sleep -Seconds 110
"SCM events for the probe (7009=connect timeout, 7000=start failed, 7031/7034=crash, 7036=state):"
Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Service Control Manager';StartTime=$t0} -EA 0 |
    Where-Object { $_.Message -match $name } | Sort-Object TimeCreated |
    ForEach-Object { "{0:HH:mm:ss} {1}" -f $_.TimeCreated, $_.Id }
"cmd.exe ping processes started since t0: " + @(Get-CimInstance Win32_Process -Filter "CommandLine like '%ping -n 400%'").Count
"state: " + (Get-Service $name).Status
Get-CimInstance Win32_Process -Filter "CommandLine like '%ping -n 400%'" | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA 0 }
sc.exe delete $name | Out-Null
'@
try { (Invoke-PhantomGuestScript -TimeoutSec 240 -AllowFailure -Script $s).Output | Out-File -Encoding ascii $Out }
catch { 'probe failed: ' + $_.Exception.Message | Out-File -Encoding ascii $Out }
Stop-PhantomVm -Hard; Restore-PhantomVmSnapshot -Name 'Test1234'
