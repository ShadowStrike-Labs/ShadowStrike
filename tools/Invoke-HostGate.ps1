<#
.SYNOPSIS
    Bounded host gate: build phantom-tests (Release x64) and optionally run tests.
    Every step has a hard deadline; on expiry the process tree is killed.
.EXAMPLE
    .\tools\Invoke-HostGate.ps1 -Filter 'MetamorphicDetector*'
    .\tools\Invoke-HostGate.ps1 -Full        # build + whole suite + contract tests
#>
param(
    [string]$Filter,
    [switch]$Full,
    [switch]$NoBuild,
    [int]$BuildTimeoutSec = 2400,
    [int]$SuiteTimeoutSec = 1500
)
$ErrorActionPreference = 'Continue'
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
$msbuild = 'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64\MSBuild.exe'
$log = Join-Path $root 'build-tests.log'

function Wait-Bounded([System.Diagnostics.Process]$p, [int]$sec, [string]$what) {
    if (-not $p.WaitForExit($sec * 1000)) {
        & taskkill.exe /T /F /PID $p.Id | Out-Null
        "TIMEOUT: $what exceeded $sec s and was killed"
        return $false
    }
    return $true
}

if (-not $NoBuild) {
    Remove-Item $log -ErrorAction SilentlyContinue
    $args = "`"$root\PhantomTests.vcxproj`" /p:Configuration=Release /p:Platform=x64 /p:SolutionDir=$root\ /m /v:m /nologo"
    $p = Start-Process $msbuild -ArgumentList $args -NoNewWindow -PassThru -RedirectStandardOutput $log
    if (-not (Wait-Bounded $p $BuildTimeoutSec 'build')) { exit 1 }
    $errs = @(Select-String -Path $log -Pattern ': error ')
    "build: exit=$($p.ExitCode) errors=$($errs.Count)"
    $errs | Select-Object -First 8 | ForEach-Object { $_.Line.Trim().Substring(0, [Math]::Min(260, $_.Line.Trim().Length)) }
    if ($errs.Count -gt 0 -or $p.ExitCode -ne 0) { exit 1 }
}

$exe = Join-Path $root 'bin\Release\phantom-tests.exe'
$out = Join-Path $root 't1.txt'
if ($Filter -or $Full) {
    $targs = @(); if ($Filter -and -not $Full) { $targs += "--gtest_filter=$Filter" }
    $p = Start-Process $exe -ArgumentList $targs -NoNewWindow -PassThru -RedirectStandardOutput $out
    if (-not (Wait-Bounded $p $SuiteTimeoutSec 'test run')) { exit 1 }
    "tests: exit=$($p.ExitCode)"
    Select-String -Path $out -Pattern '^\[==========\] \d+ tests|^\[  PASSED|^\[  FAILED  \] \S|^\[  SKIPPED' |
        ForEach-Object { $_.Line } | Select-Object -Unique -First 20
}
if ($Full) {
    $err = Join-Path $root 't2.txt'
    $p = Start-Process py -ArgumentList '-m', 'unittest', 'discover', '-s', 'tests\kernel_contracts', '-q' -NoNewWindow -PassThru -RedirectStandardError $err
    if (-not (Wait-Bounded $p 600 'contract tests')) { exit 1 }
    Get-Content $err | Select-String -Pattern '^Ran |^OK|^FAILED' | ForEach-Object { "contract: " + $_.Line }
}
