<#
.SYNOPSIS
    First-boot start reliability (task 334): N fresh installs from the clean snapshot,
    each recording whether the service reached Running and how long the loader took
    before the first static initialiser ran. Bounded: Invoke-VmTestRun has its own
    deadlines and this script adds none of its own waits.
#>
param([int]$Runs = 3, [string]$Out = (Join-Path ($PSScriptRoot | Split-Path | Split-Path) 'vm_shrd\PhantomHome\firstboot-summary.txt'))
$ErrorActionPreference = 'Continue'
$root = $PSScriptRoot | Split-Path | Split-Path
$lines = [System.Collections.Generic.List[string]]::new()
for ($i = 1; $i -le $Runs; $i++) {
    $before = @(Get-ChildItem (Join-Path $root 'vm_shrd\PhantomHome\diag-auto') -Directory -EA 0 | ForEach-Object Name)
    $log = & (Join-Path $PSScriptRoot 'Invoke-VmTestRun.ps1') *>&1 | Out-String
    $state = ([regex]::Match($log, 'Product state: [^\r\n]*')).Value
    $dir = Get-ChildItem (Join-Path $root 'vm_shrd\PhantomHome\diag-auto') -Directory -EA 0 |
           Where-Object { $before -notcontains $_.Name } | Sort-Object LastWriteTime | Select-Object -Last 1
    $boot = if ($dir) { Get-ChildItem $dir.FullName -Recurse -Filter '*boot.log' -EA 0 | Select-Object -First 1 }
    $pre = if ($boot) { (Select-String -Path $boot.FullName -Pattern 'pre-wmain-static-initializer[^\r\n]*' | Select-Object -First 1).Matches.Value } else { 'NO boot.log' }
    $disp = if ($boot) { (Select-String -Path $boot.FullName -Pattern '\S+Z \[BOOT\][^\r\n]*pre-StartServiceCtrlDispatcherW' | Select-Object -First 1).Line } else { '' }
    $scm = if ($dir) { (Select-String -Path (Join-Path $dir.FullName 'vm-state.txt') -Pattern 'Service Control Manager\s+70(00|09|11|31)' -EA 0 | ForEach-Object { $_.Line.Trim() }) -join ' | ' } else { '' }
    $lines.Add("run $i  dir=$($dir.Name)")
    $lines.Add("  $state")
    $lines.Add("  $pre")
    $lines.Add("  dispatcher: $disp")
    $lines.Add("  scm: $scm")
}
$lines | Out-File -Encoding ascii $Out
