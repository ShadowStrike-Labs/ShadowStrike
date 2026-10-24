param([Parameter(Mandatory)][string[]]$Files, [Parameter(Mandatory)][string]$MessageFile)
# Commit exactly $Files with the message in $MessageFile, after the house gates:
# ASCII only, no first-person narration, staged set equals the intended set.
$ErrorActionPreference = 'Continue'
Set-Location (Split-Path $PSScriptRoot -Parent)
$m = [IO.File]::ReadAllText((Resolve-Path $MessageFile).Path)
if ((([char[]]$m) | Where-Object { [int]$_ -gt 127 }).Count -ne 0) { 'REFUSING: not ASCII'; exit 1 }
$fp = @(); foreach ($rx in '\bI\b', '(?i)\bmy\b', '(?i)\bme\b', '(?i)\bmine\b') { if ([regex]::IsMatch($m, $rx)) { $fp += $rx } }
if ($fp.Count) { 'REFUSING: first-person ' + ($fp -join ','); exit 1 }
$subject = ($m -split "`r?`n")[0]
if ($subject.Length -ge 70) { "REFUSING: subject is $($subject.Length) chars"; exit 1 }
git reset -q
git add -A -- $Files
$staged = @(git diff --cached --name-only | Sort-Object -Unique)
$want = @($Files | ForEach-Object { $_.Replace('\', '/') } | Sort-Object -Unique)
if (($staged -join '|') -ne ($want -join '|')) { 'REFUSING staged: ' + ($staged -join ','); git reset -q; exit 1 }
git commit -q -F $MessageFile
Remove-Item $MessageFile
git log --oneline -1
