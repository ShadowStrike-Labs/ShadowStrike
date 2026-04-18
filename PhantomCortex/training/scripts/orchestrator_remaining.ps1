<#
.SYNOPSIS
    Comprehensive GPU Training Orchestrator for ALL PhantomCortex Models
    Chains: wait-for-Network -> Emulation -> Behavioral v3 -> Memory v2

.DESCRIPTION
    Runs unattended for 6+ hours. Chains all GPU-dependent trainings sequentially.
    Static (LightGBM/CPU) runs independently on the other process.
    
    Models trained:
    1. Cortex-Network (ALREADY RUNNING - wait for completion)
    2. Cortex-Static  (ALREADY RUNNING on CPU - independent)
    3. Cortex-Emulation (GPU - after Network finishes)
    4. Cortex-Behavioral v3 (GPU - with class-aware oversampling)
    5. Cortex-Memory v2 (GPU - with class-aware oversampling)

.NOTES
    Date: 2026-04-18
    Author: PhantomCortex AI/ML Pipeline
#>

param(
    [int]$NetworkPID = 23364,
    [string]$RepoRoot = "C:\ShadowStrike\ShadowStrike",
    [string]$PythonExe = "C:\ShadowStrike\ShadowStrike\PhantomCortex\.venv_local\Scripts\python.exe",
    [string]$LogFile = "C:\ShadowStrike\ShadowStrike\PhantomCortex\training\data\models\orchestrator_log.txt"
)

$ErrorActionPreference = "Continue"
$env:PYTHONPATH = $RepoRoot

$modelsDir = Join-Path $RepoRoot "PhantomCortex\training\data\models"
New-Item -ItemType Directory -Path $modelsDir -Force | Out-Null

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
}

function Run-Training {
    param(
        [string]$Name,
        [string]$OutputDir,
        [string[]]$TrainArgs
    )
    $start = Get-Date
    Write-Log "Starting $Name training..."
    Write-Log "  Output: $OutputDir"
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

    $stdOut = Join-Path $OutputDir "stdout.log"
    $stdErr = Join-Path $OutputDir "stderr.log"

    try {
        $proc = Start-Process -FilePath $PythonExe -ArgumentList $TrainArgs `
            -WorkingDirectory $RepoRoot -NoNewWindow -PassThru -Wait `
            -RedirectStandardOutput $stdOut `
            -RedirectStandardError $stdErr
        
        $duration = (Get-Date) - $start
        $durMin = [math]::Round($duration.TotalMinutes, 1)

        if ($proc.ExitCode -eq 0) {
            Write-Log "SUCCESS: $Name completed in ${durMin}m (exit 0)"
            # Report model artifacts
            $onnxFiles = Get-ChildItem -Path $OutputDir -Filter "*.onnx" -ErrorAction SilentlyContinue
            foreach ($f in $onnxFiles) {
                $sizeMB = [math]::Round($f.Length / 1MB, 2)
                Write-Log "  ONNX: $($f.Name) (${sizeMB} MB)"
            }
            $metricsFiles = Get-ChildItem -Path $OutputDir -Filter "*metrics*.json" -ErrorAction SilentlyContinue
            if (-not $metricsFiles) {
                $metricsFiles = Get-ChildItem -Path $OutputDir -Filter "*report*.json" -ErrorAction SilentlyContinue
            }
            foreach ($f in $metricsFiles) {
                try {
                    $m = Get-Content $f.FullName -Raw | ConvertFrom-Json
                    if ($m.accuracy) { Write-Log "  Accuracy: $($m.accuracy)" }
                    if ($m.macro_f1) { Write-Log "  Macro F1: $($m.macro_f1)" }
                    if ($m.metrics -and $m.metrics.accuracy) { Write-Log "  Accuracy: $($m.metrics.accuracy)" }
                    if ($m.metrics -and $m.metrics.macro_f1) { Write-Log "  Macro F1: $($m.metrics.macro_f1)" }
                } catch {}
            }
            return $true
        } else {
            Write-Log "FAILED: $Name exited with code $($proc.ExitCode)" "ERROR"
            Write-Log "  Check: $stdErr" "ERROR"
            # Print last 10 lines of stderr for diagnostics
            if (Test-Path $stdErr) {
                $errLines = Get-Content $stdErr -Tail 10
                foreach ($line in $errLines) { Write-Log "  stderr: $line" "ERROR" }
            }
            return $false
        }
    } catch {
        Write-Log "EXCEPTION in ${Name}: $_" "ERROR"
        return $false
    }
}

# ============================================================================
Write-Log "================================================================"
Write-Log "=== PhantomCortex Comprehensive Training Orchestrator ==="
Write-Log "================================================================"
Write-Log "Start time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Log "Models to train: Emulation, Behavioral v3, Memory v2"
Write-Log "Already running: Network (PID $NetworkPID, GPU), Static (CPU)"
Write-Log ""

# ============================================================================
# STEP 0: Wait for Network training
# ============================================================================
Write-Log "[STEP 0/3] Waiting for Cortex-Network (PID $NetworkPID) to finish..."

$networkProcess = $null
try { $networkProcess = Get-Process -Id $NetworkPID -ErrorAction SilentlyContinue } catch {}

if ($null -eq $networkProcess) {
    Write-Log "Network PID not found, may have already finished." "WARN"
} else {
    $memMB = [math]::Round($networkProcess.WorkingSet64 / 1MB)
    Write-Log "  Network running (${memMB} MB). Waiting..."
    $networkProcess.WaitForExit()
    Write-Log "  Network exited with code: $($networkProcess.ExitCode)"
}

Write-Log "GPU cooldown (15s)..."
Start-Sleep -Seconds 15

# ============================================================================
# STEP 1: Cortex-Emulation (Quo Vadis Speakeasy real data)
# ============================================================================
Write-Log ""
Write-Log "[STEP 1/3] Cortex-Emulation Training"
Write-Log "  Data: Quo Vadis Speakeasy 93K real emulation traces"
Write-Log "  Mode: real (all real data)"

$emulDir = Join-Path $modelsDir "cortex_emulation_v2"
$emulArgs = @(
    "-m", "PhantomCortex.training.scripts.train_emulation",
    "--dataset-mode", "real",
    "--quovadis-dir", (Join-Path $RepoRoot "PhantomCortex\training\data\raw\quovadis_speakeasy"),
    "--epochs", "120",
    "--batch-size", "64",
    "--hidden-dim", "256",
    "--num-layers", "3",
    "--learning-rate", "0.0003",
    "--weight-decay", "0.0001",
    "--grad-clip", "1.0",
    "--device", "cuda",
    "--num-workers", "0",
    "--checkpoint-every", "10",
    "--seq-length", "1024",
    "--output-dir", $emulDir
)
$emulOk = Run-Training -Name "Cortex-Emulation" -OutputDir $emulDir -Args $emulArgs

Write-Log "GPU cooldown (10s)..."
Start-Sleep -Seconds 10

# ============================================================================
# STEP 2: Cortex-Behavioral v3 (class-aware oversampling + tuned hyperparams)
# ============================================================================
Write-Log ""
Write-Log "[STEP 2/3] Cortex-Behavioral v3 Training"
Write-Log "  Data: Quo Vadis (93K) + External (6.3K) + synthetic backfill"
Write-Log "  Improvements: class-aware oversampling (min 3000/class)"
Write-Log "  LR=0.0003, WD=0.001, real-fraction=0.85, epochs=200"

$behDir = Join-Path $modelsDir "cortex_behavioral_v3"
$behArgs = @(
    "-m", "PhantomCortex.training.scripts.train_behavioral",
    "--dataset-mode", "hybrid_real_first",
    "--quovadis-dir", (Join-Path $RepoRoot "PhantomCortex\training\data\raw\quovadis_speakeasy"),
    "--data-dir", (Join-Path $RepoRoot "PhantomCortex\training\data\raw\behavioral_external"),
    "--real-data-fraction", "0.85",
    "--min-class-samples", "3000",
    "--epochs", "200",
    "--batch-size", "128",
    "--learning-rate", "0.0003",
    "--weight-decay", "0.001",
    "--embed-dim", "128",
    "--sequence-length", "512",
    "--samples-per-class", "5000",
    "--device", "cuda",
    "--num-workers", "0",
    "--checkpoints",
    "--checkpoint-every", "10",
    "--tensorboard",
    "--output-dir", $behDir
)
$behOk = Run-Training -Name "Cortex-Behavioral-v3" -OutputDir $behDir -Args $behArgs

Write-Log "GPU cooldown (10s)..."
Start-Sleep -Seconds 10

# ============================================================================
# STEP 3: Cortex-Memory v2 (class-aware oversampling + real data)
# ============================================================================
Write-Log ""
Write-Log "[STEP 3/3] Cortex-Memory v2 Training"
Write-Log "  Data: CIC-MalMem-2022 + MemMal-D2024 benign augmentation"
Write-Log "  Improvements: oversampling weak classes to 5000 minimum"
Write-Log "  LR=0.0005, WD=0.0005, epochs=150"

$memDir = Join-Path $modelsDir "cortex_memory_v3"
$memArgs = @(
    "-m", "PhantomCortex.training.scripts.train_memory",
    "--dataset-mode", "real",
    "--min-class-samples", "5000",
    "--samples-per-class", "50000",
    "--epochs", "150",
    "--batch-size", "256",
    "--learning-rate", "0.0005",
    "--weight-decay", "0.0005",
    "--grad-clip", "1.0",
    "--gpu",
    "--checkpoint-every", "10",
    "--output-dir", $memDir
)
$memOk = Run-Training -Name "Cortex-Memory-v2" -OutputDir $memDir -Args $memArgs

# ============================================================================
# FINAL SUMMARY
# ============================================================================
Write-Log ""
Write-Log "================================================================"
Write-Log "=== ALL TRAININGS COMPLETE ==="
Write-Log "================================================================"
Write-Log ""
Write-Log "Results summary:"
Write-Log "  [$(if ($emulOk) {'PASS'} else {'FAIL'})] Cortex-Emulation  -> $emulDir"
Write-Log "  [$(if ($behOk) {'PASS'} else {'FAIL'})] Cortex-Behavioral  -> $behDir"
Write-Log "  [$(if ($memOk) {'PASS'} else {'FAIL'})] Cortex-Memory      -> $memDir"
Write-Log "  [INDEPENDENT]  Cortex-Network    -> $(Join-Path $modelsDir 'cortex_network_v2')"
Write-Log "  [INDEPENDENT]  Cortex-Static     -> $(Join-Path $modelsDir 'cortex_static_v2')"
Write-Log ""
Write-Log "Each model directory contains:"
Write-Log "  *.onnx              Production model for C++ inference"
Write-Log "  *metrics*.json      Evaluation metrics (F1, accuracy, etc.)"
Write-Log "  stdout.log          Full training output"
Write-Log "  stderr.log          Errors (if any)"
Write-Log "  checkpoints/        Epoch checkpoints"
Write-Log ""
Write-Log "Orchestrator finished at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
