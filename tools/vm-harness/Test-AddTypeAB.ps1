<#
.SYNOPSIS
    Does PowerShell Add-Type (csc compiling into %TEMP%) work with the product
    installed? Task 332. Installs the current package, then runs the probe.
#>
param([string]$Out = (Join-Path ($PSScriptRoot | Split-Path | Split-Path) 'vm_shrd\addtype-ab.txt'))
$ErrorActionPreference = 'Continue'
Import-Module (Join-Path $PSScriptRoot 'PhantomVm.psm1') -Force
& (Join-Path $PSScriptRoot 'Invoke-VmTestRun.ps1')
Initialize-PhantomVm -VmxPath 'C:\Users\RTX40\Documents\Virtual Machines\PRODUCT_TESTS\PRODUCT_TESTS.vmx'
$probe = @'
$ok=0; $fail=@()
1..3 | ForEach-Object { try { Add-Type -TypeDefinition ("public static class SsProbe" + (Get-Random) + " { public static int V() { return 1; } }") -ErrorAction Stop; $ok++ } catch { $fail += $_.Exception.Message.Substring(0,[Math]::Min(160,$_.Exception.Message.Length)) } }
"Add-Type ok=$ok of 3"; $fail | Select-Object -First 2
$L = Get-Content 'C:\ProgramData\ShadowStrike\Logs\PhantomHome.Service.log'
"KERNEL DENIED in Temp: " + @($L | Select-String -SimpleMatch 'KERNEL DENIED' | Where-Object { $_.Line -match '\\Temp\\' }).Count
$L | Select-String -SimpleMatch 'KERNEL DENIED' | Where-Object { $_.Line -match '\\Temp\\' } | Select-Object -Last 3 | ForEach-Object { $_.Line.Substring(24,[Math]::Min(260,$_.Line.Length-24)) }
$c = ($L | Select-String 'kernelPreCreate:' | Select-Object -Last 1).Line
[regex]::Match($c,'kernelPreCreate:.*').Value
'@
try { $r = Invoke-PhantomGuestScript -TimeoutSec 180 -AllowFailure -Script $probe; "installed: " + $r.Output | Out-File -Encoding utf8 $Out }
catch { "installed probe ERR: " + $_.Exception.Message | Out-File -Encoding utf8 $Out }
