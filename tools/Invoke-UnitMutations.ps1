param([string]$Spec)
# Each mutation: file | old | new | gtest filter. Reverts after each run.
$ErrorActionPreference = 'Continue'
Set-Location (Split-Path $PSScriptRoot -Parent)
$muts = Get-Content $Spec -Raw | ConvertFrom-Json
foreach ($m in $muts) {
    $p = (Resolve-Path $m.file).Path
    $orig = [IO.File]::ReadAllBytes($p)
    $text = [IO.File]::ReadAllText($p)
    # Anchors are written with either line ending; match the file's.
    $old = $m.old.Replace("`r`n", "`n"); $new = $m.new.Replace("`r`n", "`n")
    if ($text -match "`r`n") { $old = $old.Replace("`n", "`r`n"); $new = $new.Replace("`n", "`r`n") }
    $m.old = $old; $m.new = $new
    $n = ([regex]::Matches($text, [regex]::Escape($m.old))).Count
    if ($n -ne 1) { "ANCHOR($n) $($m.name)"; continue }
    [IO.File]::WriteAllText($p, $text.Replace($m.old, $m.new), [Text.UTF8Encoding]::new($orig[0] -eq 0xEF))
    try {
        $out = & .\tools\Invoke-HostGate.ps1 -Filter $m.filter
        # A fatal assertion in SetUpTestSuite SKIPS the suite rather than failing a case, and
        # the run still exits non-zero; both count as the mutation being caught.
        $failed = @($out | Where-Object { $_ -match '^\[\s+(FAILED|SKIPPED)\s+\] \w+\.\w+ \(' } | ForEach-Object { $k = $Matches[1]; $n = [regex]::Match($_, '\] (\S+) \(').Groups[1].Value; if ($k -eq 'SKIPPED') { "$n(skipped)" } else { $n } } | Sort-Object -Unique)
        $build = ($out | Where-Object { $_ -match '^build:' }) -join ''
        $texit = ($out | Where-Object { $_ -match '^tests: exit=' }) -join ''
        $verdict = if ($failed) { $failed -join ', ' } elseif ($texit -and $texit -ne 'tests: exit=0') { "NO CASE NAMED, but $texit" } else { 'NOTHING FAILED' }
        "{0,-42} {1} -> {2}" -f $m.name, $build, $verdict
    } finally { [IO.File]::WriteAllBytes($p, $orig) }
}
