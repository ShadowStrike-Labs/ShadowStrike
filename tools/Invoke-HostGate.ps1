<#
.SYNOPSIS
    Bounded host gate: build phantom-tests (Release x64) and optionally run tests.
    Every step has a hard deadline AND a memory bound; on either the process tree is killed.
.DESCRIPTION
    Memory safety (2026-10-25, after a host lock-up under a parallel build with a VM running):
      - refuses to start unless -MinFreeGB of physical memory is available and no VMware VM runs
      - the build is limited to -BuildNodes projects x 2 compilers, without node reuse
      - the build tree and the test process each run in a Windows job object with a hard
        committed-memory cap (-BuildMemoryGB, -TestMemoryGB); the kernel refuses allocations
        above it, so a runaway build or test fails instead of exhausting the machine
      - while a step runs, available memory is polled; below -AbortBelowGB the step is killed
.EXAMPLE
    .\tools\Invoke-HostGate.ps1 -Filter 'MetamorphicDetector*'
    .\tools\Invoke-HostGate.ps1 -Full        # build + whole suite + contract tests
#>
param(
    [string]$Filter,
    [switch]$Full,
    [switch]$NoBuild,
    [int]$BuildTimeoutSec = 2400,
    [int]$SuiteTimeoutSec = 1500,
    [int]$MinFreeGB = 12,
    [int]$AbortBelowGB = 3,
    [int]$BuildNodes = 4,
    [int]$BuildMemoryGB = 14,
    [int]$TestMemoryGB = 6
)
$ErrorActionPreference = 'Continue'
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
$msbuild = 'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64\MSBuild.exe'
$log = Join-Path $root 'build-tests.log'

if (-not ('HostGate.Job' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace HostGate {
public static class Job {
    [StructLayout(LayoutKind.Sequential)] struct BASIC { public long a, b; public uint LimitFlags; public UIntPtr c, d; public uint e; public UIntPtr f; public uint g, h; }
    [StructLayout(LayoutKind.Sequential)] struct IO { public ulong a, b, c, d, e, f; }
    [StructLayout(LayoutKind.Sequential)] struct EXT { public BASIC Basic; public IO Io; public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcess, PeakJob; }
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr CreateJobObjectW(IntPtr a, string n);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetInformationJobObject(IntPtr j, int c, ref EXT i, int l);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool QueryInformationJobObject(IntPtr j, int c, ref EXT i, int l, IntPtr r);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool AssignProcessToJobObject(IntPtr j, IntPtr p);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool TerminateJobObject(IntPtr j, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool CloseHandle(IntPtr h);
    const uint JOB_MEMORY = 0x200, KILL_ON_CLOSE = 0x2000;
    // A job whose processes together may commit at most limitBytes; closing it kills them.
    public static IntPtr Create(long limitBytes) {
        IntPtr j = CreateJobObjectW(IntPtr.Zero, null);
        if (j == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
        EXT e = new EXT(); e.Basic.LimitFlags = JOB_MEMORY | KILL_ON_CLOSE; e.JobMemoryLimit = new UIntPtr((ulong)limitBytes);
        if (!SetInformationJobObject(j, 9, ref e, Marshal.SizeOf(typeof(EXT)))) throw new System.ComponentModel.Win32Exception();
        return j;
    }
    public static bool Assign(IntPtr j, IntPtr process) { return AssignProcessToJobObject(j, process); }
    public static ulong PeakBytes(IntPtr j) { EXT e = new EXT(); QueryInformationJobObject(j, 9, ref e, Marshal.SizeOf(typeof(EXT)), IntPtr.Zero); return e.PeakJob.ToUInt64(); }
}}
'@
}

# Headroom = the smaller of available physical memory (free + standby cache, which Windows
# reclaims on demand) and free commit (what the lock-up exhausted: RAM plus page file).
function Get-FreeGB {
    $m = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory
    $available = $m.AvailableMBytes / 1KB
    $commitFree = ([double]$m.CommitLimit - [double]$m.CommittedBytes) / 1GB
    [math]::Round([math]::Min($available, $commitFree), 1)
}

# Preflight: enough free memory, no VM competing for it.
$vm = @(Get-Process vmware-vmx -ErrorAction SilentlyContinue)
if ($vm.Count -gt 0) { "REFUSED: a VMware VM is running ($($vm.Count) vmware-vmx); stop it before a host build"; exit 2 }
$free = Get-FreeGB
if ($free -lt $MinFreeGB) { "REFUSED: $free GB memory headroom (available and free commit), $MinFreeGB GB required"; exit 2 }

# Starts a process suspended-free inside a memory-capped job, waits with deadline and memory watch.
# The process is assigned right after start; anything it spawns afterwards inherits the job.
function Invoke-Guarded([string]$file, [string[]]$argList, [string]$stdout, [string]$stderr,
                        [int]$sec, [int]$capGB, [string]$what) {
    $job = [HostGate.Job]::Create([long]$capGB * 1GB)
    $sp = @{ FilePath = $file; NoNewWindow = $true; PassThru = $true }
    # Start-Process rejects an empty -ArgumentList; the whole suite runs with no arguments.
    if ($argList.Count -gt 0) { $sp.ArgumentList = $argList }
    if ($stdout) { $sp.RedirectStandardOutput = $stdout }
    if ($stderr) { $sp.RedirectStandardError = $stderr }
    $p = Start-Process @sp
    $null = $p.Handle   # keeps the handle so ExitCode is readable after exit
    if (-not [HostGate.Job]::Assign($job, $p.Handle)) { "WARN: $what could not be placed in a memory-capped job" }
    $deadline = (Get-Date).AddSeconds($sec); $minFree = 999.0; $reason = $null
    while (-not $p.WaitForExit(2000)) {
        $f = Get-FreeGB; if ($f -lt $minFree) { $minFree = $f }
        if ($f -lt $AbortBelowGB) { $reason = "free memory fell to $f GB (abort below $AbortBelowGB GB)"; break }
        if ((Get-Date) -gt $deadline) { $reason = "exceeded $sec s"; break }
    }
    $peak = [math]::Round([HostGate.Job]::PeakBytes($job) / 1GB, 1)
    if ($reason) {
        [void][HostGate.Job]::TerminateJobObject($job, 1)
        & taskkill.exe /T /F /PID $p.Id 2>$null | Out-Null
        [void][HostGate.Job]::CloseHandle($job)
        "KILLED: $what $reason; peak $peak GB"
        return $null
    }
    [void][HostGate.Job]::CloseHandle($job)
    "memory: $what peak $peak GB of $capGB GB cap, lowest free $minFree GB"
    return $p.ExitCode
}

if (-not $NoBuild) {
    Remove-Item $log -ErrorAction SilentlyContinue
    $bargs = @("`"$root\PhantomTests.vcxproj`"", '/p:Configuration=Release', '/p:Platform=x64', "/p:SolutionDir=$root\",
               "/m:$BuildNodes", '/p:CL_MPCount=2', '/nr:false', '/v:m', '/nologo')
    $r = Invoke-Guarded $msbuild $bargs $log $null $BuildTimeoutSec $BuildMemoryGB 'build'
    $r | Where-Object { $_ -is [string] }
    $code = $r | Where-Object { $_ -isnot [string] } | Select-Object -Last 1
    if ($null -eq $code) { exit 1 }
    $errs = @(Select-String -Path $log -Pattern ': error ')
    "build: exit=$code errors=$($errs.Count)"
    $errs | Select-Object -First 8 | ForEach-Object { $_.Line.Trim().Substring(0, [Math]::Min(260, $_.Line.Trim().Length)) }
    if ($errs.Count -gt 0 -or $code -ne 0) { exit 1 }
}

$exe = Join-Path $root 'bin\Release\phantom-tests.exe'
$out = Join-Path $root 't1.txt'
if ($Filter -or $Full) {
    $targs = @(); if ($Filter -and -not $Full) { $targs += "--gtest_filter=$Filter" }
    $r = Invoke-Guarded $exe $targs $out $null $SuiteTimeoutSec $TestMemoryGB 'test run'
    $r | Where-Object { $_ -is [string] }
    $code = $r | Where-Object { $_ -isnot [string] } | Select-Object -Last 1
    if ($null -eq $code) { exit 1 }
    "tests: exit=$code"
    Select-String -Path $out -Pattern '^\[==========\] \d+ tests|^\[  PASSED|^\[  FAILED  \] \S|^\[  SKIPPED' |
        ForEach-Object { $_.Line } | Select-Object -Unique -First 20
}
if ($Full) {
    $err = Join-Path $root 't2.txt'
    $r = Invoke-Guarded 'py' @('-m', 'unittest', 'discover', '-s', 'tests\kernel_contracts', '-q') $null $err 600 4 'contract tests'
    $r | Where-Object { $_ -is [string] }
    if ($null -eq ($r | Where-Object { $_ -isnot [string] } | Select-Object -Last 1)) { exit 1 }
    Get-Content $err | Select-String -Pattern '^Ran |^OK|^FAILED' | ForEach-Object { "contract: " + $_.Line }
}
