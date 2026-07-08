<#
.SYNOPSIS
    TEST-ONLY: Neutralize Microsoft Defender real-time protection inside a
    ShadowStrike test VM so it stops competing with PhantomSensor / PhantomCore
    during evaluation.

.DESCRIPTION
    Part of the developer VM harness. It is NOT shipped with the product. In
    production the supported way to make Windows Defender stand down is to
    register ShadowStrike as an antivirus provider with the Windows Security
    Center (WSC) -- which requires Microsoft Virus Initiative (MVI) membership,
    an ELAM driver, and an allowlisted signing certificate. Once registered,
    Windows disables Defender's real-time protection automatically. This script
    is only a stopgap for isolating Defender while testing dev builds.

    WHY DEFENDER "TURNS BACK ON AFTER RESTART":
    Windows "Tamper Protection" reverts every Defender disable (UI, PowerShell,
    registry, policy) -- especially across reboot. It is ON by default and cannot
    be toggled from a script (Microsoft blocks that on purpose, because malware
    tried exactly this). So this script REFUSES to proceed while Tamper
    Protection is on, instead of pretending. Turn it off once, by hand:
        Windows Security > Virus & threat protection > Manage settings >
        Tamper Protection > Off
    then re-run. With Tamper Protection OFF, the changes below DO persist across
    reboot -- that is the whole point.

    AFTER A SUCCESSFUL RUN: reboot, run with -Verify, then SNAPSHOT the VM and
    always revert to that snapshot for testing. Stable and repeatable.

    Deliberately does NOT touch the boot-critical Defender ELAM / filter drivers
    (WdBoot, WdFilter): disabling those can break boot, and we do not trade one
    reinstall cycle for another.

.PARAMETER Revert
    Re-enable Defender (undo policy/service changes, turn real-time protection
    back on). Use before returning a VM to a clean baseline.

.PARAMETER Verify
    Only print current Defender status (no changes).

.NOTES
    Requires an elevated (Administrator) PowerShell. Test VMs only.
#>
[CmdletBinding()]
param(
    [switch]$Revert,
    [switch]$Verify
)

$ErrorActionPreference = 'Continue'

function Write-Step($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Write-Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn2($m){ Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-Err2($m) { Write-Host "[x] $m" -ForegroundColor Red }

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-DefenderStatusSafe {
    try { return Get-MpComputerStatus -ErrorAction Stop } catch { return $null }
}

function Show-Status {
    $s = Get-DefenderStatusSafe
    if (-not $s) {
        Write-Warn2 "Get-MpComputerStatus unavailable (Defender module absent or removed)."
        return
    }
    Write-Host ""
    Write-Host "  Defender status:" -ForegroundColor White
    Write-Host ("    RealTimeProtectionEnabled : {0}" -f $s.RealTimeProtectionEnabled)
    Write-Host ("    AntivirusEnabled          : {0}" -f $s.AntivirusEnabled)
    Write-Host ("    BehaviorMonitorEnabled    : {0}" -f $s.BehaviorMonitorEnabled)
    Write-Host ("    OnAccessProtectionEnabled : {0}" -f $s.OnAccessProtectionEnabled)
    Write-Host ("    IsTamperProtected         : {0}" -f $s.IsTamperProtected)
    Write-Host ("    AMRunningMode             : {0}" -f $s.AMRunningMode)
    Write-Host ""
}

# --- policy / service targets --------------------------------------------------
$PolicyRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
$PolicyRtp  = "$PolicyRoot\Real-Time Protection"
# User-mode services only. WdBoot (ELAM) and WdFilter (minifilter) are boot-start
# and are intentionally left alone to avoid boot failures.
$Services   = @('WinDefend','WdNisSvc','Sense')

if (-not (Test-Admin)) {
    Write-Err2 "Run this in an ELEVATED (Administrator) PowerShell."
    exit 1
}

Write-Host "== ShadowStrike test-VM Defender helper (TEST ONLY) ==" -ForegroundColor Magenta

if ($Verify) { Show-Status; exit 0 }

# ------------------------------------------------------------------ REVERT ------
if ($Revert) {
    Write-Step "Reverting: re-enabling Windows Defender..."
    foreach ($svc in $Services) {
        try {
            Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -Name Start -Value 2 -ErrorAction Stop
            Write-Ok "Service $svc set to auto-start (2)."
        } catch { Write-Warn2 "Could not reset service $svc start type: $($_.Exception.Message)" }
    }
    try { Remove-Item $PolicyRoot -Recurse -Force -ErrorAction Stop; Write-Ok "Removed Defender disable policies." }
    catch { Write-Warn2 "No policy keys to remove (or blocked): $($_.Exception.Message)" }
    try {
        Get-ScheduledTask -TaskPath '\Microsoft\Windows\Windows Defender\' -ErrorAction Stop |
            Enable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
        Write-Ok "Re-enabled Defender scheduled tasks."
    } catch { }
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false `
            -DisableScriptScanning $false -DisableIOAVProtection $false -ErrorAction Stop
        Write-Ok "Set-MpPreference: real-time protection re-enabled."
    } catch { Write-Warn2 "Set-MpPreference revert failed (Tamper Protection?): $($_.Exception.Message)" }
    Write-Warn2 "Reboot to fully restore Defender."
    Show-Status
    exit 0
}

# ------------------------------------------------------------------ DISABLE -----
# Gate on Tamper Protection: while it is ON everything below is reverted, so do
# not pretend. Fail loudly with instructions.
$status = Get-DefenderStatusSafe
if ($status -and $status.IsTamperProtected) {
    Write-Err2 "Tamper Protection is ON -- Defender reverts every change (this is why it comes back after reboot)."
    Write-Host ""
    Write-Host "  Turn it off MANUALLY (cannot be scripted), then re-run this:" -ForegroundColor Yellow
    Write-Host "    Windows Security > Virus & threat protection > Manage settings >" -ForegroundColor Yellow
    Write-Host "    Tamper Protection > Off" -ForegroundColor Yellow
    Write-Host ""
    exit 2
}
if (-not $status) {
    Write-Warn2 "Defender cmdlets unavailable; applying policy/service changes only."
}

Write-Step "Disabling Defender real-time protection via Set-MpPreference..."
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true `
        -DisableBlockAtFirstSeen $true -DisableIOAVProtection $true `
        -DisableScriptScanning $true -DisableArchiveScanning $true `
        -MAPSReporting Disabled -SubmitSamplesConsent NeverSend -ErrorAction Stop
    Write-Ok "Set-MpPreference applied."
} catch { Write-Warn2 "Set-MpPreference failed: $($_.Exception.Message)" }

Write-Step "Applying disable policies (persist across reboot while Tamper Protection is off)..."
try {
    New-Item -Path $PolicyRoot -Force | Out-Null
    New-Item -Path $PolicyRtp  -Force | Out-Null
    New-ItemProperty -Path $PolicyRoot -Name 'DisableAntiSpyware'          -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $PolicyRtp  -Name 'DisableRealtimeMonitoring'   -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $PolicyRtp  -Name 'DisableBehaviorMonitoring'   -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $PolicyRtp  -Name 'DisableOnAccessProtection'   -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $PolicyRtp  -Name 'DisableScanOnRealtimeEnable' -Value 1 -PropertyType DWord -Force | Out-Null
    Write-Ok "Policy keys written."
} catch { Write-Warn2 "Policy write failed: $($_.Exception.Message)" }

Write-Step "Disabling Defender scheduled tasks..."
try {
    Get-ScheduledTask -TaskPath '\Microsoft\Windows\Windows Defender\' -ErrorAction Stop |
        Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
    Write-Ok "Scheduled tasks disabled."
} catch { Write-Warn2 "Could not enumerate/disable Defender tasks: $($_.Exception.Message)" }

Write-Step "Disabling Defender user-mode services (boot drivers left intact)..."
foreach ($svc in $Services) {
    try {
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -Name Start -Value 4 -ErrorAction Stop
        Write-Ok "Service $svc set to disabled (4)."
    } catch { Write-Warn2 "Could not disable service $svc (protected?): $($_.Exception.Message)" }
}

Write-Host ""
Write-Ok "Done. Now: 1) REBOOT, 2) run '.\Disable-DefenderForTest.ps1 -Verify', 3) SNAPSHOT the VM."
Write-Warn2 "If RealTimeProtectionEnabled is still True after reboot, Tamper Protection was not fully off."
Show-Status
