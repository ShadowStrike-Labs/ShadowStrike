param([string]$Spec)
# Each mutation: file | old | new | gtest filter. Reverts after each run.
$ErrorActionPreference = 'Continue'
Set-Location (Split-Path $PSScriptRoot -Parent)
$muts = Get-Content $Spec -Raw | ConvertFrom-Json
foreach ($m in $muts) {
    $p = (Resolve-Path $m.file).Path
    $orig = [IO.File]::ReadAllBytes($p)
    $text = [IO.File]::ReadAllText($p)
    if ($text -notmatch "`r`n") { $m.old = $m.old.Replace("`r`n", "`n"); $m.new = $m.new.Replace("`r`n", "`n") }
    $n = ([regex]::Matches($text, [regex]::Escape($m.old))).Count
    if ($n -ne 1) { "ANCHOR($n) $($m.name)"; continue }
    [IO.File]::WriteAllText($p, $text.Replace($m.old, $m.new), [Text.UTF8Encoding]::new($orig[0] -eq 0xEF))
    try {
        $out = & .\tools\Invoke-HostGate.ps1 -Filter $m.filter
        $failed = @($out | Where-Object { $_ -match '^\[  FAILED  \] \w+\.\w+ \(' } | ForEach-Object { [regex]::Match($_, '\] (\S+) \(').Groups[1].Value } | Sort-Object -Unique)
        $build = ($out | Where-Object { $_ -match '^build:' }) -join ''
        "{0,-42} {1} -> {2}" -f $m.name, $build, $(if ($failed) { $failed -join ', ' } else { 'NOTHING FAILED' })
    } finally { [IO.File]::WriteAllBytes($p, $orig) }
}
