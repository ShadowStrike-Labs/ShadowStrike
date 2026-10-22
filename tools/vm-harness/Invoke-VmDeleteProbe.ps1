<#
.SYNOPSIS
    Probe the kernel's mass-delete (data destruction) rule inside PRODUCT_TESTS
    against an installed, running product. Task 329.

.DESCRIPTION
    Three cases, each measured by what the deleting process experienced
    (failed deletes) and by what the service logged (KERNEL DENIED lines whose
    path is under the case's directory):

      own        One process creates N files and deletes them. Nothing that
                 existed before it ran is destroyed. MUST NOT be blocked.
      foreign    Process A creates N files, a different process B deletes them.
                 This is what a wiper does to existing data. MUST still be
                 blocked - the detection being kept.
      appx       Removes a Store package for all users, which makes the AppX
                 deployment service (svchost, Windows-signed) delete the
                 package files under WindowsApps\Deleted - the field false
                 positive. MUST NOT be blocked.

    Run after Invoke-VmTestRun.ps1 has left the VM running with the product up.
#>
param(
    [string]$VmxPath = 'C:\Users\RTX40\Documents\Virtual Machines\PRODUCT_TESTS\PRODUCT_TESTS.vmx',
    [int]$FileCount = 1500,
    [string]$OutFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'PhantomVm.psm1') -Force
Initialize-PhantomVm -VmxPath $VmxPath
Wait-PhantomVmGuest -TimeoutSec 120

function Get-DeniedCount([string]$Needle) {
    $s = "@(Select-String -Path 'C:\ProgramData\ShadowStrike\Logs\PhantomHome.Service*.log' -SimpleMatch 'KERNEL DENIED' -ErrorAction SilentlyContinue | Where-Object { `$_.Line -like '*$Needle*' }).Count"
    [int](Invoke-PhantomGuestScript -TimeoutSec 120 -Script $s).Output.Trim()
}

$results = [System.Collections.Generic.List[string]]::new()
function Report([string]$line) { Write-VmLog $line; $results.Add($line) }

# -- own ----------------------------------------------------------------------
$before = Get-DeniedCount 'SsDelProbe\own'
$own = Invoke-PhantomGuestScript -TimeoutSec 600 -AllowFailure -Script @"
`$d = 'C:\SsDelProbe\own'; New-Item -ItemType Directory -Force `$d | Out-Null
1..$FileCount | ForEach-Object { [IO.File]::WriteAllText("`$d\f`$_.txt", 'probe') }
`$fail = 0
Get-ChildItem `$d -File | ForEach-Object { try { [IO.File]::Delete(`$_.FullName) } catch { `$fail++ } }
"created=$FileCount failedDeletes=`$fail remaining=" + @(Get-ChildItem `$d -File).Count
"@
Start-Sleep -Seconds 3
Report ("own     : {0}  kernelDenied={1}" -f $own.Output.Trim(), ((Get-DeniedCount 'SsDelProbe\own') - $before))

# -- foreign --------------------------------------------------------------------
$before = Get-DeniedCount 'SsDelProbe\foreign'
[void](Invoke-PhantomGuestScript -TimeoutSec 600 -Script @"
`$d = 'C:\SsDelProbe\foreign'; New-Item -ItemType Directory -Force `$d | Out-Null
1..$FileCount | ForEach-Object { [IO.File]::WriteAllText("`$d\f`$_.txt", 'probe') }
"@)
# A separate Invoke = a separate powershell.exe process that did not create them.
$foreign = Invoke-PhantomGuestScript -TimeoutSec 600 -AllowFailure -Script @"
`$d = 'C:\SsDelProbe\foreign'; `$fail = 0
Get-ChildItem `$d -File | ForEach-Object { try { [IO.File]::Delete(`$_.FullName) } catch { `$fail++ } }
"deleter pid=`$PID failedDeletes=`$fail remaining=" + @(Get-ChildItem `$d -File).Count
"@
Start-Sleep -Seconds 3
Report ("foreign : {0}  kernelDenied={1}" -f $foreign.Output.Trim(), ((Get-DeniedCount 'SsDelProbe\foreign') - $before))

# -- appx -----------------------------------------------------------------------
# The removal runs as LocalSystem through a one-shot service. The vmrun login has
# no loaded user profile, and AppX refuses a removal requested from such a
# session with 0x80073CFA ("Failed to determine the type of current user's
# profile"), which would make this case measure nothing.
$before = Get-DeniedCount 'WindowsApps'
$appx = Invoke-PhantomGuestScript -TimeoutSec 900 -AllowFailure -Script @'
$names = 'Microsoft.BingWeather','Microsoft.BingNews','Microsoft.MicrosoftSolitaireCollection','Microsoft.ZuneMusic','Clipchamp.Clipchamp'
$pk = @(Get-AppxPackage -AllUsers -EA 0 | Where-Object { $names -contains $_.Name })
$files = 0; foreach ($p in $pk) { $files += @(Get-ChildItem $p.InstallLocation -Recurse -File -Force -EA 0).Count }
$id  = [guid]::NewGuid().ToString('N')
$ps1 = "C:\ProgramData\ss-vm\appx-$id.ps1"
$out = "C:\ProgramData\ss-vm\appx-$id.txt"
$body = @"
`$names = '$($names -join "','")'
Get-AppxPackage -AllUsers | Where-Object { `$names -contains `$_.Name } | Remove-AppxPackage -AllUsers *> '$out'
'DONE' >> '$out'
"@
[IO.File]::WriteAllText($ps1, $body)
sc.exe create SsAppxProbe binPath= "cmd.exe /c powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ps1" type= own start= demand | Out-Null
sc.exe start SsAppxProbe | Out-Null
$t0 = Get-Date
do { Start-Sleep 10 } while (-not ((Get-Content $out -EA 0) -contains 'DONE') -and ((Get-Date) - $t0).TotalSeconds -lt 600)
sc.exe delete SsAppxProbe | Out-Null
Start-Sleep -Seconds 60
$left = @(Get-AppxPackage -AllUsers -EA 0 | Where-Object { $names -contains $_.Name }).Count
$err  = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-AppXDeploymentServer/Operational'; Level=2; StartTime=$t0} -EA 0).Count
"packages=$($pk.Count) files=$files stillInstalled=$left appxErrors=$err"
'@
Report ("appx    : {0}  kernelDenied(WindowsApps)={1}" -f $appx.Output.Trim(), ((Get-DeniedCount 'WindowsApps') - $before))

if ($OutFile) { $results | Out-File -Encoding utf8 $OutFile }
