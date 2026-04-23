<#
.SYNOPSIS
    ShadowStrike PhantomHome VM Test Automation Agent.
    Runs permanently on the VM as a SYSTEM scheduled task.

.DESCRIPTION
    Polls the shared-folder job queue for deploy+test jobs submitted by the
    host-side Invoke-PhantomDeploy.ps1. For each job:
      1. Stops running UI and tray processes
      2. Stops the PhantomHome service
      3. Uninstalls the previous build (if present) via its bundle EXE
      4. Installs the new bundle silently
      5. Waits for the service to initialize
      6. Collects all requested log paths
      7. Runs any extra diagnostic commands specified in the job
      8. Writes results + logs to the results directory
      9. Marks the job done

.NOTES
    One-time VM setup: run Setup-VMAgent.ps1 from the shared folder (as admin).
    After that this agent runs automatically on every boot and requires no
    further manual intervention.

    $SharedRoot MUST point to the vm_shrd directory as seen from inside the VM.
    For VMware Workstation shared folders this is typically:
        \\vmware-host\Shared Folders\ShadowStrike  (if the share is named ShadowStrike)
    For Hyper-V with a VHD drive letter it would be the drive root.
    Edit the variable below to match your hypervisor mapping.
#>

#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── CONFIGURATION ────────────────────────────────────────────────────────────
# Adjust to match how the shared folder appears inside the VM.
$SharedRoot  = $env:PHANTOM_SHARED_ROOT
if (-not $SharedRoot) { $SharedRoot = '\\vmware-host\Shared Folders\ShadowStrike' }

$AutoDir     = Join-Path $SharedRoot 'auto'
$JobsDir     = Join-Path $AutoDir    'jobs'
$ResultsDir  = Join-Path $AutoDir    'results'
$AgentLog    = Join-Path $AutoDir    'agent.log'
$PollInterval= 5   # seconds

$SvcName     = 'ShadowStrikePhantomService'
$TrayExe     = 'ShadowStrikePhantomTray.exe'
$UIExe       = 'ShadowStrikePhantomUI.exe'

# ── LOGGING ──────────────────────────────────────────────────────────────────
function Write-AgentLog {
    param([string]$Level, [string]$Message)
    $ts   = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss.fffZ')
    $line = "[$ts] [$Level] $Message"
    $line | Out-File -FilePath $AgentLog -Append -Encoding utf8 -ErrorAction SilentlyContinue
    Write-Host $line
}
function Log-Info  { param($m) Write-AgentLog 'INFO ' $m }
function Log-Warn  { param($m) Write-AgentLog 'WARN ' $m }
function Log-Error { param($m) Write-AgentLog 'ERROR' $m }

# ── HELPERS ──────────────────────────────────────────────────────────────────

function Stop-PhantomProcesses {
    foreach ($exe in @($UIExe, $TrayExe)) {
        $procs = Get-Process -Name ([System.IO.Path]::GetFileNameWithoutExtension($exe)) `
                             -ErrorAction SilentlyContinue
        foreach ($p in $procs) {
            Log-Info "Stopping process: $($p.Name) (PID $($p.Id))"
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Seconds 2
}

function Stop-PhantomService {
    $svc = Get-Service -Name $SvcName -ErrorAction SilentlyContinue
    if (-not $svc) { Log-Info "Service '$SvcName' not found (first install)."; return }
    if ($svc.Status -ne 'Stopped') {
        Log-Info "Stopping service '$SvcName'..."
        Stop-Service -Name $SvcName -Force -ErrorAction SilentlyContinue
        $timeout = [DateTime]::UtcNow.AddSeconds(30)
        while ($svc.Status -ne 'Stopped' -and [DateTime]::UtcNow -lt $timeout) {
            Start-Sleep -Milliseconds 500
            $svc.Refresh()
        }
        if ($svc.Status -ne 'Stopped') {
            Log-Warn "Service did not stop cleanly; force-killing..."
            $procs = Get-Process -Name ([System.IO.Path]::GetFileNameWithoutExtension($SvcName)) `
                                 -ErrorAction SilentlyContinue
            foreach ($p in $procs) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
        }
        Log-Info "Service stopped."
    }
}

function Get-InstalledBundleUninstallCmd {
    # Search both HKLM and HKCU uninstall hive for ShadowStrike bundle
    $hives = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($hive in $hives) {
        if (-not (Test-Path $hive)) { continue }
        $keys = Get-ChildItem $hive -ErrorAction SilentlyContinue
        foreach ($key in $keys) {
            $props = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
            if ($props.DisplayName -like '*ShadowStrike*Phantom*' -or
                $props.DisplayName -like '*PhantomHome*') {
                $qr = $props.QuietUninstallString
                if ($qr) { return $qr }
                $ur = $props.UninstallString
                if ($ur) { return "$ur /quiet /norestart" }
            }
        }
    }
    return $null
}

function Uninstall-Previous {
    Log-Info "Checking for existing installation..."
    $cmd = Get-InstalledBundleUninstallCmd
    if (-not $cmd) {
        Log-Info "No previous installation found."
        return
    }
    Log-Info "Uninstalling: $cmd"
    try {
        # cmd may contain "path\to\setup.exe" /uninstall syntax
        if ($cmd -match '^"([^"]+)"\s*(.*)$') {
            $exe  = $Matches[1]
            $args = $Matches[2]
        } elseif ($cmd -match '^(\S+)\s*(.*)$') {
            $exe  = $Matches[1]
            $args = $Matches[2]
        } else {
            $exe  = $cmd; $args = ''
        }
        if (Test-Path $exe) {
            $proc = Start-Process -FilePath $exe -ArgumentList "$args /quiet /norestart" `
                                  -Wait -PassThru -ErrorAction Stop
            Log-Info "Uninstall exited with code $($proc.ExitCode)"
        } else {
            Log-Warn "Uninstall EXE not found at '$exe' — skipping uninstall."
        }
    } catch {
        Log-Warn "Uninstall failed: $_"
    }
    Start-Sleep -Seconds 3
}

function Install-Bundle {
    param([string]$BundleExe, [string]$ExpectedHash)

    if (-not (Test-Path $BundleExe)) {
        throw "Bundle EXE not found: $BundleExe"
    }

    # Verify SHA-256 hash if provided
    if ($ExpectedHash) {
        $actual = (Get-FileHash $BundleExe -Algorithm SHA256).Hash
        if ($actual -ne $ExpectedHash.ToUpper()) {
            throw "Hash mismatch! Expected=$ExpectedHash Actual=$actual"
        }
        Log-Info "Hash verified: $actual"
    }

    Log-Info "Installing: $BundleExe"
    $proc = Start-Process -FilePath $BundleExe `
                          -ArgumentList '/install /quiet /norestart' `
                          -Wait -PassThru -ErrorAction Stop
    $code = $proc.ExitCode
    Log-Info "Installer exited: $code"

    # 0 = success, 3010 = success+reboot pending
    if ($code -ne 0 -and $code -ne 3010) {
        throw "Installer failed with exit code $code"
    }
}

function Wait-ForService {
    param([int]$MaxSeconds)
    Log-Info "Waiting up to ${MaxSeconds}s for service '$SvcName'..."
    $deadline = [DateTime]::UtcNow.AddSeconds($MaxSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $svc = Get-Service -Name $SvcName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            Log-Info "Service is Running."
            return $true
        }
        Start-Sleep -Seconds 2
    }
    Log-Warn "Service did not reach Running state within ${MaxSeconds}s."
    return $false
}

function Collect-Logs {
    param([string[]]$Sources, [string]$ResultDir)

    $logDest = Join-Path $ResultDir 'logs'
    New-Item -ItemType Directory -Force -Path $logDest | Out-Null

    foreach ($src in $Sources) {
        # Expand environment variables
        $expanded = [System.Environment]::ExpandEnvironmentVariables($src)
        if (Test-Path $expanded -PathType Container) {
            # Directory: copy all files (non-recursive to avoid huge trees)
            $files = Get-ChildItem $expanded -File -ErrorAction SilentlyContinue
            foreach ($f in $files) {
                $dest = Join-Path $logDest $f.Name
                Copy-Item $f.FullName $dest -Force -ErrorAction SilentlyContinue
                Log-Info "Collected: $($f.Name) ($([Math]::Round($f.Length/1KB,1)) KB)"
            }
        } elseif (Test-Path $expanded -PathType Leaf) {
            $dest = Join-Path $logDest (Split-Path $expanded -Leaf)
            Copy-Item $expanded $dest -Force -ErrorAction SilentlyContinue
            $sz = (Get-Item $expanded).Length
            Log-Info "Collected: $(Split-Path $expanded -Leaf) ($([Math]::Round($sz/1KB,1)) KB)"
        } else {
            Log-Warn "Log source not found: $expanded"
        }
    }
}

function Run-ExtraCommands {
    param([object[]]$Commands, [string]$ResultDir)
    if (-not $Commands -or $Commands.Count -eq 0) { return }

    $cmdDest = Join-Path $ResultDir 'commands'
    New-Item -ItemType Directory -Force -Path $cmdDest | Out-Null

    $i = 0
    foreach ($cmd in $Commands) {
        $i++
        $label  = if ($cmd.label) { $cmd.label } else { "cmd$i" }
        $script = $cmd.script
        Log-Info "Running extra command [$label]: $script"
        $out    = & powershell.exe -NoProfile -NonInteractive -Command $script 2>&1
        $outStr = $out -join "`n"
        $outFile= Join-Path $cmdDest "$label.txt"
        $outStr | Out-File -FilePath $outFile -Encoding utf8 -Force
        Log-Info "Command [$label] output saved ($($outStr.Length) chars)"
    }
}

function Process-Job {
    param([string]$JobFile)

    # Atomically claim job
    $inprog = $JobFile -replace '\.json$', '.inprogress'
    try {
        Move-Item $JobFile $inprog -Force -ErrorAction Stop
    } catch {
        Log-Warn "Could not claim job (another agent may have taken it): $_"
        return
    }

    $job = Get-Content $inprog -Raw | ConvertFrom-Json
    $jobId     = $job.jobId
    $ResultDir = Join-Path $ResultsDir $jobId

    Log-Info "=== Processing job: $jobId ==="
    New-Item -ItemType Directory -Force -Path $ResultDir | Out-Null

    # Write initial status
    @{ status='running'; startedAt=(Get-Date -Format 'o'); jobId=$jobId } |
        ConvertTo-Json | Out-File (Join-Path $ResultDir 'status.json') -Encoding utf8 -Force

    $exitError = $null
    try {
        # Resolve bundle path relative to shared root
        $bundlePath = $job.installerPath
        if (-not [System.IO.Path]::IsPathRooted($bundlePath)) {
            $bundlePath = Join-Path $SharedRoot $bundlePath
        }

        Stop-PhantomProcesses
        Stop-PhantomService
        Uninstall-Previous
        Install-Bundle -BundleExe $bundlePath -ExpectedHash $job.installerHash

        # Wait for service to come up
        $waitSec = if ($job.waitSeconds) { [int]$job.waitSeconds } else { 45 }
        Wait-ForService -MaxSeconds $waitSec

        # Let service init settle
        Log-Info "Letting service settle for additional 10s..."
        Start-Sleep -Seconds 10

        # Collect logs
        $sources = if ($job.collectPaths) { $job.collectPaths } else {
            @('%ProgramData%\ShadowStrike\Logs')
        }
        Collect-Logs -Sources $sources -ResultDir $ResultDir

        # Run extra diagnostic commands
        if ($job.extraCommands) {
            Run-ExtraCommands -Commands $job.extraCommands -ResultDir $ResultDir
        }

        Log-Info "Job $jobId completed successfully."
        @{
            status      = 'done'
            jobId       = $jobId
            completedAt = (Get-Date -Format 'o')
            error       = $null
        } | ConvertTo-Json | Out-File (Join-Path $ResultDir 'status.json') -Encoding utf8 -Force

    } catch {
        $exitError = $_.ToString()
        Log-Error "Job $jobId FAILED: $exitError"
        @{
            status      = 'failed'
            jobId       = $jobId
            completedAt = (Get-Date -Format 'o')
            error       = $exitError
        } | ConvertTo-Json | Out-File (Join-Path $ResultDir 'status.json') -Encoding utf8 -Force
    } finally {
        # Copy agent log snapshot into results
        try {
            Copy-Item $AgentLog (Join-Path $ResultDir 'agent.log') -Force -ErrorAction SilentlyContinue
        } catch {}
        # Remove in-progress marker
        Remove-Item $inprog -Force -ErrorAction SilentlyContinue
    }
}

# ── MAIN LOOP ─────────────────────────────────────────────────────────────────

Log-Info "PhantomVMAgent starting. SharedRoot=$SharedRoot PollInterval=${PollInterval}s"

while ($true) {
    try {
        if (-not (Test-Path $JobsDir)) {
            New-Item -ItemType Directory -Force -Path $JobsDir  | Out-Null
            New-Item -ItemType Directory -Force -Path $ResultsDir | Out-Null
        }

        $pending = Get-ChildItem $JobsDir -Filter '*.json' -File -ErrorAction SilentlyContinue |
                   Sort-Object CreationTime

        foreach ($jf in $pending) {
            Process-Job -JobFile $jf.FullName
        }
    } catch {
        Log-Error "Agent loop error: $_"
    }

    Start-Sleep -Seconds $PollInterval
}
