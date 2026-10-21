<#
.SYNOPSIS
    Host-side control of the PRODUCT_TESTS VMware Workstation VM through vmrun.

.DESCRIPTION
    Every product binary runs INSIDE the guest. The host only drives VMware:
    power, snapshot revert, guest command execution and file copies.

    Secrets
      * VM encryption password: read at run time from the Windows Credential
        Manager entry that VMware Workstation itself created when it was told to
        remember the password (target name = the .vmx encryptedVM.guid). It is
        never written to disk by this module.
      * Guest login: a PSCredential exported with Export-Clixml, so it is DPAPI
        protected for the current Windows user on this machine only.

    vmrun takes both passwords as command-line arguments; there is no other
    interface. They are therefore visible to other processes of this user for
    the lifetime of each vmrun call, and are masked in everything this module
    logs.
#>

Set-StrictMode -Version Latest

$script:Vmrun = 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
$script:Ctx   = $null

if (-not ('SsVmCred' -as [type])) {
    Add-Type @"
using System; using System.Runtime.InteropServices;
public static class SsVmCred {
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  struct CREDENTIAL { public int Flags; public int Type; public IntPtr TargetName; public IntPtr Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten; public int CredentialBlobSize;
    public IntPtr CredentialBlob; public int Persist; public int AttributeCount; public IntPtr Attributes;
    public IntPtr TargetAlias; public IntPtr UserName; }
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern bool CredReadW(string target, int type, int flags, out IntPtr cred);
  [DllImport("advapi32.dll")] static extern void CredFree(IntPtr cred);
  public static string Read(string target) {
    IntPtr p; if (!CredReadW(target, 1, 0, out p)) return null;
    try { var c = (CREDENTIAL)Marshal.PtrToStructure(p, typeof(CREDENTIAL));
          return Marshal.PtrToStringUTF8(c.CredentialBlob, c.CredentialBlobSize); }
    finally { CredFree(p); }
  }
}
"@
}

function Write-VmLog { param([string]$Msg) Write-Host "[$(Get-Date -Format 'HH:mm:ss')] [vm] $Msg" }

function Initialize-PhantomVm {
    <# Resolves the VM, its encryption password and the guest login. Call once. #>
    param(
        [Parameter(Mandatory)][string]$VmxPath,
        [string]$GuestCredentialPath = (Join-Path $env:USERPROFILE '.shadowstrike-vm\vm-guest.xml')
    )
    if (-not (Test-Path $script:Vmrun)) { throw "vmrun.exe not found at $script:Vmrun" }
    if (-not (Test-Path $VmxPath))      { throw "VM not found: $VmxPath" }
    if (-not (Test-Path $GuestCredentialPath)) { throw "Guest login not saved: $GuestCredentialPath" }

    $vmxText = Get-Content -LiteralPath $VmxPath -Raw
    $vp = $null
    $m = [regex]::Match($vmxText, 'encryptedVM\.guid\s*=\s*"([^"]+)"')
    if ($m.Success) {
        $vp = [SsVmCred]::Read($m.Groups[1].Value)
        if (-not $vp) {
            throw "The VM is encrypted and VMware has no remembered password for it in Credential Manager. Open it once in Workstation and tick 'Remember the password'."
        }
    }
    $script:Ctx = [pscustomobject]@{
        Vmx   = $VmxPath
        Vp    = $vp
        Guest = (Import-Clixml -LiteralPath $GuestCredentialPath).GetNetworkCredential()
    }
}

function Invoke-Vmrun {
    <# Runs one vmrun command with a hard timeout. Returns ExitCode and Output. #>
    param(
        [Parameter(Mandatory)][string]$Command,
        [string[]]$Arguments = @(),
        [switch]$Guest,
        [int]$TimeoutSec = 120
    )
    if (-not $script:Ctx) { throw 'Initialize-PhantomVm has not been called.' }
    $argv = [System.Collections.Generic.List[string]]::new()
    $argv.AddRange([string[]]@('-T', 'ws'))
    if ($script:Ctx.Vp) { $argv.AddRange([string[]]@('-vp', $script:Ctx.Vp)) }
    if ($Guest) { $argv.AddRange([string[]]@('-gu', $script:Ctx.Guest.UserName, '-gp', $script:Ctx.Guest.Password)) }
    $argv.Add($Command)
    if ($Command -notin @('list')) { $argv.Add($script:Ctx.Vmx) }
    foreach ($a in $Arguments) { $argv.Add($a) }

    $psi = [System.Diagnostics.ProcessStartInfo]::new($script:Vmrun)
    foreach ($a in $argv) { $psi.ArgumentList.Add($a) }
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill($true) } catch { }
        throw "vmrun $Command timed out after $TimeoutSec s"
    }
    # Do NOT call the parameterless WaitForExit() here. 'vmrun start' spawns the
    # VMware UI/VMX processes, which inherit the redirected stdout/stderr handles
    # and keep them open for the life of the VM; waiting for end-of-stream then
    # never returns. vmrun itself has exited, so give the readers a short grace
    # period and take whatever arrived.
    [void][System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($outTask, $errTask), 5000)
    $stdout = if ($outTask.IsCompleted) { $outTask.Result } else { '' }
    $stderr = if ($errTask.IsCompleted) { $errTask.Result } else { '' }
    $text = ($stdout + $stderr).Trim()
    foreach ($secret in @($script:Ctx.Vp, $script:Ctx.Guest.Password)) {
        if ($secret) { $text = $text.Replace($secret, '***') }
    }
    [pscustomobject]@{ ExitCode = $p.ExitCode; Output = $text }
}

function Assert-Vmrun {
    param([Parameter(Mandatory)]$Result, [Parameter(Mandatory)][string]$What)
    if ($Result.ExitCode -ne 0) { throw "$What failed (vmrun exit $($Result.ExitCode)): $($Result.Output)" }
}

function Test-PhantomVmRunning {
    $r = Invoke-Vmrun -Command list
    return @($r.Output -split "`r?`n" | Where-Object { $_.Trim() -ieq $script:Ctx.Vmx }).Count -gt 0
}

function Restore-PhantomVmSnapshot {
    <# Reverts to an EXISTING snapshot. Never creates or deletes one. #>
    param([Parameter(Mandatory)][string]$Name)
    $list = Invoke-Vmrun -Command listSnapshots
    Assert-Vmrun $list 'listSnapshots'
    $names = @($list.Output -split "`r?`n" | Select-Object -Skip 1 | ForEach-Object { $_.Trim() })
    if ($names -notcontains $Name) { throw "Snapshot '$Name' does not exist. Present: $($names -join ', ')" }
    Write-VmLog "Reverting to snapshot '$Name'"
    Assert-Vmrun (Invoke-Vmrun -Command revertToSnapshot -Arguments @($Name) -TimeoutSec 300) 'revertToSnapshot'
}

function Start-PhantomVm {
    if (Test-PhantomVmRunning) { Write-VmLog 'VM already running'; return }
    Write-VmLog 'Starting VM (window visible)'
    Assert-Vmrun (Invoke-Vmrun -Command start -Arguments @('gui') -TimeoutSec 300) 'start'
}

function Stop-PhantomVm {
    param([switch]$Hard)
    if (-not (Test-PhantomVmRunning)) { return }
    $mode = if ($Hard) { 'hard' } else { 'soft' }
    Write-VmLog "Stopping VM ($mode)"
    Assert-Vmrun (Invoke-Vmrun -Command stop -Arguments @($mode) -TimeoutSec 300) 'stop'
}

function Wait-PhantomVmGuest {
    <# Waits until VMware Tools is running AND the guest login can execute a program. #>
    param([int]$TimeoutSec = 600)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSec)
    $last = ''
    while ([DateTime]::UtcNow -lt $deadline) {
        $t = Invoke-Vmrun -Command checkToolsState -TimeoutSec 60
        if ($t.Output -match 'running') {
            $probe = Invoke-Vmrun -Command fileExistsInGuest -Arguments @('C:\Windows\System32\cmd.exe') -Guest -TimeoutSec 60
            if ($probe.ExitCode -eq 0) { return }
            $last = $probe.Output
            if ($last -match 'Invalid user name or password') { throw "Guest login refused: $last" }
        } else { $last = $t.Output }
        Start-Sleep -Seconds 5
    }
    throw "Guest not ready after $TimeoutSec s (last: $last)"
}

function Invoke-PhantomGuestScript {
    <#
        Runs a PowerShell script inside the guest as the saved login and returns
        its combined output and exit code. The script travels Base64-encoded, so
        no quoting survives into cmd.exe; the output comes back as a file.
    #>
    param(
        [Parameter(Mandatory)][string]$Script,
        [int]$TimeoutSec = 300,
        [switch]$AllowFailure
    )
    $id  = [guid]::NewGuid().ToString('N')
    $dir = 'C:\ProgramData\ss-vm'
    $out = "$dir\out-$id.txt"
    # cmd.exe owns the redirection: a direct powershell.exe launch through
    # runProgramInGuest returns 1 with no output on this guest, while the same
    # command under cmd /c works. The script's own exit code is preserved.
    $wrapped = @"
`$ErrorActionPreference = 'Continue'
`$ProgressPreference = 'SilentlyContinue'
`$global:LASTEXITCODE = 0
try { & { $Script } } catch { `$_ | Out-String | Write-Output; exit 1 }
exit [int]`$global:LASTEXITCODE
"@
    # The script travels as a FILE. An -EncodedCommand line is UTF-16 Base64,
    # roughly 2.7x the script size, and cmd.exe truncates command lines at 8191
    # characters - a 3 KB collection script silently never ran.
    $hostPs1  = Join-Path $env:TEMP "ss-vm-$id.ps1"
    $guestPs1 = "$dir\run-$id.ps1"
    [IO.File]::WriteAllText($hostPs1, $wrapped, [Text.UTF8Encoding]::new($true))
    try {
        [void](Invoke-Vmrun -Command createDirectoryInGuest -Guest -Arguments @($dir) -TimeoutSec 60)
        Assert-Vmrun (Invoke-Vmrun -Command CopyFileFromHostToGuest -Guest -Arguments @($hostPs1, $guestPs1) -TimeoutSec 120) 'copy script to guest'
    } finally { Remove-Item -LiteralPath $hostPs1 -Force -ErrorAction SilentlyContinue }
    $cmdLine = "/c C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $guestPs1 > $out 2>&1"
    $r = Invoke-Vmrun -Command runProgramInGuest -Guest -TimeoutSec $TimeoutSec -Arguments @(
        'C:\Windows\System32\cmd.exe', $cmdLine)
    [void](Invoke-Vmrun -Command deleteFileInGuest -Guest -Arguments @($guestPs1) -TimeoutSec 60)
    $rc = 0
    if ($r.ExitCode -ne 0) {
        $m = [regex]::Match($r.Output, 'exit code:\s*(-?\d+)')
        if ($m.Success) { $rc = [int]$m.Groups[1].Value } else { throw "runProgramInGuest failed: $($r.Output)" }
    }
    $local = Join-Path $env:TEMP "ss-vm-out-$id.txt"
    $text = ''
    $c = $null
    foreach ($attempt in 1..3) {
        $c = Invoke-Vmrun -Command CopyFileFromGuestToHost -Guest -Arguments @($out, $local) -TimeoutSec 120
        if ($c.ExitCode -eq 0 -and (Test-Path $local)) { break }
        Start-Sleep -Seconds 2
    }
    if ($c.ExitCode -eq 0 -and (Test-Path $local)) {
        $text = (Get-Content -LiteralPath $local -Raw -Encoding utf8)
        Remove-Item -LiteralPath $local -Force
        [void](Invoke-Vmrun -Command deleteFileInGuest -Guest -Arguments @($out) -TimeoutSec 60)
    }
    if ($null -eq $text) { $text = '' }
    if ($rc -ne 0 -and -not $AllowFailure) { throw "Guest script exited $rc`n$text" }
    [pscustomobject]@{ ExitCode = $rc; Output = $text.TrimEnd() }
}

function Copy-ToPhantomGuest {
    param([Parameter(Mandatory)][string]$HostPath, [Parameter(Mandatory)][string]$GuestPath, [int]$TimeoutSec = 600)
    Assert-Vmrun (Invoke-Vmrun -Command CopyFileFromHostToGuest -Guest -Arguments @($HostPath, $GuestPath) -TimeoutSec $TimeoutSec) "copy to guest $GuestPath"
}

function Copy-FromPhantomGuest {
    param([Parameter(Mandatory)][string]$GuestPath, [Parameter(Mandatory)][string]$HostPath, [int]$TimeoutSec = 600)
    Assert-Vmrun (Invoke-Vmrun -Command CopyFileFromGuestToHost -Guest -Arguments @($GuestPath, $HostPath) -TimeoutSec $TimeoutSec) "copy from guest $GuestPath"
}

function Get-PhantomGuestBootTime {
    $r = Invoke-PhantomGuestScript -Script '(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString("o")'
    return [DateTime]::Parse($r.Output.Trim()).ToUniversalTime()
}

function Restart-PhantomGuest {
    <# Restarts Windows inside the guest and waits until it has really rebooted. #>
    param([int]$TimeoutSec = 900)
    $before = Get-PhantomGuestBootTime
    Write-VmLog "Restarting guest Windows (booted $($before.ToString('HH:mm:ss')) UTC)"
    # Primary: shutdown.exe started through the cmd-wrapped guest script path,
    # which is the launch path proven to work on this guest. Fallbacks only if
    # the guest is still on the same boot after two minutes.
    [void](Invoke-PhantomGuestScript -TimeoutSec 60 -AllowFailure -Script 'shutdown.exe /r /t 3 /f /d p:4:1')
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSec)
    $fallbacks = [System.Collections.Generic.Queue[string]]::new([string[]]@('soft', 'hard'))
    $nextFallback = [DateTime]::UtcNow.AddSeconds(120)
    Start-Sleep -Seconds 20
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            Wait-PhantomVmGuest -TimeoutSec 60
            $now = Get-PhantomGuestBootTime
            if ($now -gt $before.AddSeconds(5)) { Write-VmLog "Guest back up (booted $($now.ToString('HH:mm:ss')) UTC)"; return }
        } catch { }
        if ([DateTime]::UtcNow -gt $nextFallback -and $fallbacks.Count -gt 0) {
            $mode = $fallbacks.Dequeue()
            Write-VmLog "Guest has not restarted yet - vmrun reset $mode"
            [void](Invoke-Vmrun -Command reset -Arguments @($mode) -TimeoutSec 300)
            $nextFallback = [DateTime]::UtcNow.AddSeconds(120)
        }
        Start-Sleep -Seconds 5
    }
    throw "Guest did not come back from restart within $TimeoutSec s"
}

Export-ModuleMember -Function Initialize-PhantomVm, Invoke-Vmrun, Test-PhantomVmRunning, Restore-PhantomVmSnapshot,
    Start-PhantomVm, Stop-PhantomVm, Wait-PhantomVmGuest, Invoke-PhantomGuestScript, Copy-ToPhantomGuest,
    Copy-FromPhantomGuest, Get-PhantomGuestBootTime, Restart-PhantomGuest, Write-VmLog
