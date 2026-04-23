# VM Test Automation Harness

Zero-manual-step build → deploy → test → log collection pipeline for ShadowStrike PhantomHome.

## Architecture

```
HOST MACHINE                          VM (always-on agent)
────────────────────────────────      ────────────────────────────────────────
tools\vm-harness\                     PhantomVMAgent.ps1 (scheduled task, SYSTEM)
  Invoke-PhantomDeploy.ps1            │
    │                                 │  polls every 5s
    ├─ MSBuild (service + UI)         │
    ├─ wix build (MSI + Bundle)       │
    ├─ Sign                           │
    ├─ Copy → vm_shrd\PhantomHome\    │
    ├─ Write job → vm_shrd\auto\jobs\ ←──── agent picks up job
    └─ Poll vm_shrd\auto\results\     ────→ agent writes results + logs
         │                            │     (status.json + logs/ + commands/)
         └─ Print all logs to stdout  │
              (AI reads them here)    │
```

The shared folder (`vm_shrd`) is the only communication channel. No network, no SSH, no RDP.

## One-Time VM Setup

Run **once** on the VM (PowerShell as Administrator):

```powershell
Set-ExecutionPolicy -Scope Process Bypass

# Replace with your actual shared folder path as seen from inside the VM.
# VMware Workstation: \\vmware-host\Shared Folders\ShadowStrike
# Hyper-V with drive letter: Z:  (adjust accordingly)

$shared = '\\vmware-host\Shared Folders\ShadowStrike'
& "$shared\tools\vm-harness\Setup-VMAgent.ps1" -SharedRoot $shared
```

That's it. The agent starts immediately and on every subsequent boot. You never need to touch the VM again.

**To verify the agent is running** (from the VM or host after first job):

```powershell
# On VM:
Get-ScheduledTask -TaskName PhantomVMAgent | Select State
# Should be: Running

# On host — check agent heartbeat log:
Get-Content vm_shrd\auto\agent.log -Tail 5
```

## Daily Workflow (host only)

```powershell
# Full rebuild (after C++ changes):
.\tools\vm-harness\Invoke-PhantomDeploy.ps1 -RebuildLib

# Quick iteration (only service changed):
.\tools\vm-harness\Invoke-PhantomDeploy.ps1

# Skip sign step (fastest, dev cert already on VM):
.\tools\vm-harness\Invoke-PhantomDeploy.ps1 -SkipSign

# Custom wait + extra command:
.\tools\vm-harness\Invoke-PhantomDeploy.ps1 -WaitSeconds 90 `
    -ExtraCommands '[{"label":"driver-check","script":"Get-Service ShadowStrikePhantomDriver -ErrorAction SilentlyContinue | Select Status | ConvertTo-Json"}]'
```

All collected logs (Service.log, DriverResume.*.log, etc.) are printed directly to the host terminal so the AI agent can analyze them without any manual file copying.

## Files

| File | Location | Purpose |
|------|----------|---------|
| `PhantomVMAgent.ps1` | `tools\vm-harness\` | VM-side polling agent |
| `Setup-VMAgent.ps1`  | `tools\vm-harness\` | One-time VM Task Scheduler registration |
| `Invoke-PhantomDeploy.ps1` | `tools\vm-harness\` | Host-side build+deploy+test orchestrator |

## Job Protocol

**Job manifest** (`vm_shrd\auto\jobs\<jobId>.json`):
```json
{
  "jobId": "job-20260423-174000",
  "status": "pending",
  "installerPath": "PhantomHome\\ShadowStrikePhantom-Home-Setup.exe",
  "installerHash": "ABC123...",
  "waitSeconds": 45,
  "collectPaths": ["%ProgramData%\\ShadowStrike\\Logs"],
  "extraCommands": [
    { "label": "service-status", "script": "Get-Service ... | ConvertTo-Json" }
  ]
}
```

**Result structure** (`vm_shrd\auto\results\<jobId>\`):
```
status.json        — { "status": "done|failed", "completedAt": "...", "error": null }
logs\              — all collected log files (Service.log, DriverResume.*.log, ...)
commands\          — output of extra diagnostic PowerShell commands
agent.log          — snapshot of VM agent log at time of job completion
```

## Troubleshooting

**Agent not responding:**
- Check `vm_shrd\auto\agent.log` — if empty, the agent isn't running
- On the VM: `Get-ScheduledTask -TaskName PhantomVMAgent`
- Re-run `Setup-VMAgent.ps1` if needed

**Installer path mismatch:**
- The `installerPath` in the job is relative to `$SharedRoot` on the VM
- Verify `$env:PHANTOM_SHARED_ROOT` is set correctly on the VM

**Hash mismatch:**
- Signing step modifies the bundle — `Invoke-PhantomDeploy.ps1` hashes AFTER signing
- Never modify the file after the hash is computed
