<#
.SYNOPSIS
    One-time setup: registers PhantomVMAgent.ps1 as a Task Scheduler task on the VM.

.DESCRIPTION
    Run this script ONCE on the VM (as Administrator) from the shared folder.
    After that the agent starts automatically on every boot and you never need
    to touch the VM again for build/test cycles.

    Usage (on the VM, PowerShell as Administrator):
        Set-ExecutionPolicy -Scope Process Bypass
        \\vmware-host\Shared Folders\ShadowStrike\tools\vm-harness\Setup-VMAgent.ps1 `
            -SharedRoot '\\vmware-host\Shared Folders\ShadowStrike'

    For a drive-letter mapped share (e.g. Z:):
        .\Setup-VMAgent.ps1 -SharedRoot 'Z:'
#>

#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory)]
    [string]$SharedRoot,

    [string]$TaskName = 'PhantomVMAgent'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Write-Host "[Setup] SharedRoot: $SharedRoot"

$agentScript = Join-Path $SharedRoot 'tools\vm-harness\PhantomVMAgent.ps1'
if (-not (Test-Path $agentScript)) {
    Write-Error "Agent script not found: $agentScript"
    exit 1
}

# Remove existing task if present
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "[Setup] Removed previous task (if any)."

$action = New-ScheduledTaskAction `
    -Execute 'powershell.exe' `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command `"& '$agentScript'`"" `
    -WorkingDirectory 'C:\'

$envAction = New-ScheduledTaskAction `
    -Execute 'powershell.exe' `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command `"[System.Environment]::SetEnvironmentVariable('PHANTOM_SHARED_ROOT','$SharedRoot','Machine')`""

# Run at system startup (before logon) as SYSTEM with highest privileges
$trigger  = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Hours 0) `
    -RestartCount 5 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable

$principal = New-ScheduledTaskPrincipal `
    -UserId 'NT AUTHORITY\SYSTEM' `
    -LogonType ServiceAccount `
    -RunLevel Highest

Register-ScheduledTask `
    -TaskName  $TaskName `
    -Action    $action `
    -Trigger   $trigger `
    -Settings  $settings `
    -Principal $principal `
    -Force | Out-Null

# Persist SharedRoot as machine-wide env var so the agent finds it after reboot
[System.Environment]::SetEnvironmentVariable('PHANTOM_SHARED_ROOT', $SharedRoot, 'Machine')
Write-Host "[Setup] Set PHANTOM_SHARED_ROOT machine env var: $SharedRoot"

Write-Host "[Setup] Task '$TaskName' registered. Starting now..."
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 2

$info = Get-ScheduledTask -TaskName $TaskName
Write-Host "[Setup] Task state: $($info.State)"
Write-Host ""
Write-Host "=========================================================="
Write-Host "  Setup complete. PhantomVMAgent is now running."
Write-Host "  It will start automatically on every boot."
Write-Host "  You never need to log into this VM again for testing."
Write-Host "=========================================================="
