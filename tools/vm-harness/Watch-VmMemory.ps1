<#
.SYNOPSIS
  Independent kill switch for a running PRODUCT_TESTS VM (owner directive
  2026-10-22). Polls host headroom; if it stays below -FloorGB for -Consec
  consecutive samples the VM is hard-stopped through PhantomVm.psm1 (never raw
  vmrun - the VM is vTPM-encrypted). Uses Get-Process for VM liveness and perf
  counters for memory, so it never issues a vmrun command except the final stop,
  and so it cannot collide with the batch runner's own vmrun traffic.

  Covers EVERY phase of the run, unlike the runner's soak-only 4 GB guard, and
  unlike Watch-HostMemory.ps1 which only kills build/test trees. Exits when the
  VM is gone or after -MaxMin.
#>
param(
    [string]$VmxPath = 'C:\Users\RTX40\Documents\Virtual Machines\PRODUCT_TESTS\PRODUCT_TESTS.vmx',
    [double]$FloorGB = 2.0,
    [int]$Consec = 3,
    [int]$MaxMin = 80,
    [string]$Log = 'C:\ShadowStrike\ShadowStrike\vm_shrd\PhantomHome\vm-killswitch.log'
)
$ErrorActionPreference = 'Continue'
function L([string]$m) { "$(Get-Date -Format s) $m" | Out-File $Log -Append -Encoding ascii }
Import-Module (Join-Path $PSScriptRoot 'PhantomVm.psm1') -Force
try { Initialize-PhantomVm -VmxPath $VmxPath } catch { L "Initialize failed: $($_.Exception.Message)"; return }
L "killswitch start pid=$PID floor=${FloorGB}GB consec=$Consec maxMin=$MaxMin"
$end = (Get-Date).AddMinutes($MaxMin)
$low = 0; $tick = 0
# Wait for the VM to come up (the runner reverts and starts it); up to 10 min, because
# the runner starts this switch before the snapshot revert, which can take minutes.
# Not finding it immediately must NOT be read as "VM gone" - that would make the
# switch exit before monitoring ever began if it launched before the VM started.
$appeared = $false
for ($w = 0; $w -lt 120; $w++) { if (Get-Process vmware-vmx -ErrorAction SilentlyContinue) { $appeared = $true; break }; Start-Sleep 5 }
if (-not $appeared) { L 'VM never appeared within 10 min; killswitch exiting'; return }
L 'VM up; monitoring begins'
# Let the start transient settle; it legitimately dips low.
Start-Sleep -Seconds 20
while ((Get-Date) -lt $end) {
    if (-not (Get-Process vmware-vmx -ErrorAction SilentlyContinue)) {
        # A snapshot revert stops and restarts the VM process; let it come back first.
        $back = $false
        for ($g = 0; $g -lt 12; $g++) { Start-Sleep -Seconds 5; if (Get-Process vmware-vmx -ErrorAction SilentlyContinue) { $back = $true; break } }
        if (-not $back) { L 'VM no longer running; killswitch exiting'; break }
        L 'VM process restarted; monitoring continues'
    }
    $m = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory
    $head = [math]::Round([math]::Min($m.AvailableMBytes / 1KB, ([double]$m.CommitLimit - [double]$m.CommittedBytes) / 1GB), 1)
    if ($head -lt $FloorGB) { $low++ } else { $low = 0 }
    if (($tick % 12) -eq 0 -or $low -gt 0) { L "head=${head}GB low=$low" }
    if ($low -ge $Consec) {
        L "KILL: headroom ${head}GB < ${FloorGB}GB for $Consec samples; hard-stopping VM"
        try { Stop-PhantomVm -Hard; L 'VM stopped' } catch { L "stop failed: $($_.Exception.Message)" }
        New-Item -ItemType File -Force -Path (Join-Path (Split-Path $Log) 'vm-killswitch.fired') | Out-Null
        break
    }
    $tick++
    Start-Sleep -Seconds 10
}
L 'killswitch stop'
