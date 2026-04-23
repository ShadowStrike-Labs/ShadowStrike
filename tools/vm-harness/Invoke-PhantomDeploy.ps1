<#
.SYNOPSIS
    Host-side: build PhantomHome, deploy to vm_shrd, submit test job, wait for
    results, and print all collected logs to stdout so the AI agent can read them.

.DESCRIPTION
    Full automated pipeline:
      1. MSBuild: PhantomCoreLib (if -RebuildLib) + service + UI
      2. Package: MSI → Bundle (wix build)
      3. Sign: packaging\signing\Sign-PhantomHome.ps1
      4. Stage: copy installers to vm_shrd\PhantomHome\
      5. Submit job manifest to vm_shrd\auto\jobs\
      6. Poll vm_shrd\auto\results\<jobId>\status.json
      7. Print all collected log files to stdout
      8. Return exit code 0 (success) or 1 (VM job failed)

    Run from the repository root:
        .\tools\vm-harness\Invoke-PhantomDeploy.ps1

    Optional flags:
        -RebuildLib      Also rebuild PhantomCoreLib.lib before service build
        -SkipBuild       Skip build step (reuse last bin\Release artifacts)
        -SkipSign        Skip code-signing step (for faster iteration)
        -WaitSeconds 60  Override default post-install service wait (seconds)
        -JobTimeout 300  Max seconds to wait for VM agent to finish (default 300)
        -ExtraCommands   JSON array string of {label,script} objects
        -Verbose         Extra diagnostic output

.EXAMPLE
    # Full rebuild + deploy + test
    .\tools\vm-harness\Invoke-PhantomDeploy.ps1 -RebuildLib

    # Quick: skip lib rebuild, sign step; just rebuild service+UI and test
    .\tools\vm-harness\Invoke-PhantomDeploy.ps1 -SkipSign -WaitSeconds 60
#>

param(
    [switch]$RebuildLib,
    [switch]$SkipBuild,
    [switch]$SkipSign,
    [int]$WaitSeconds  = 45,
    [int]$JobTimeout   = 300,
    [string]$ExtraCommands = '',
    [switch]$VerboseOutput
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── PATHS ────────────────────────────────────────────────────────────────────
$RepoRoot    = $PSScriptRoot | Split-Path | Split-Path  # tools\vm-harness -> tools -> root
$BinDir      = Join-Path $RepoRoot 'bin\Release'
$StagingDir  = Join-Path $RepoRoot 'build\installer\staging'
$BuildDir    = Join-Path $RepoRoot 'build\installer'
$PackageDir  = Join-Path $RepoRoot 'packaging\installer'
$VmShared    = Join-Path $RepoRoot 'vm_shrd\PhantomHome'
$AutoDir     = Join-Path $RepoRoot 'vm_shrd\auto'
$JobsDir     = Join-Path $AutoDir  'jobs'
$ResultsDir  = Join-Path $AutoDir  'results'

$MSBuild     = 'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe'
$MsiOut      = Join-Path $BuildDir 'ShadowStrikePhantom-Home-Setup.msi'
$BundleOut   = Join-Path $BuildDir 'ShadowStrikePhantom-Home-Setup.exe'

New-Item -ItemType Directory -Force -Path $JobsDir    | Out-Null
New-Item -ItemType Directory -Force -Path $ResultsDir | Out-Null

# ── LOGGING ──────────────────────────────────────────────────────────────────
function Log { param($Msg) Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Msg" }
function Die { param($Msg) Write-Error $Msg; exit 1 }

# ── BUILD ────────────────────────────────────────────────────────────────────
if (-not $SkipBuild) {
    if ($RebuildLib) {
        Log "Building PhantomCoreLib..."
        & $MSBuild (Join-Path $RepoRoot 'PhantomCoreLib.vcxproj') `
            /p:Configuration=Release /p:Platform=x64 /m /nologo /v:minimal
        if ($LASTEXITCODE -ne 0) { Die "PhantomCoreLib build failed" }
    }

    Log "Building PhantomHome Service..."
    & $MSBuild (Join-Path $RepoRoot 'ShadowStrikePhantomService.vcxproj') `
        /p:Configuration=Release /p:Platform=x64 /m /nologo /v:minimal
    if ($LASTEXITCODE -ne 0) { Die "Service build failed" }

    Log "Building PhantomHome UI..."
    & $MSBuild (Join-Path $RepoRoot 'ShadowStrikePhantomUI.vcxproj') `
        /p:Configuration=Release /p:Platform=x64 /m /nologo /v:minimal
    if ($LASTEXITCODE -ne 0) { Die "UI build failed" }

    # Update staging
    Copy-Item (Join-Path $BinDir 'ShadowStrikePhantomService.exe') $StagingDir -Force
    Log "Staged service EXE."
}

# ── PACKAGE ──────────────────────────────────────────────────────────────────
Log "Building MSI..."
wix build -arch x64 `
    -d ProductVersion=1.0.0.0 `
    -d BinDir=$BinDir `
    -d StagingDir=$StagingDir `
    -d InstallerDir=$PackageDir `
    -ext WixToolset.Util.wixext `
    -ext WixToolset.UI.wixext `
    (Join-Path $PackageDir 'Product.wxs') `
    (Join-Path $PackageDir 'Components.wxs') `
    (Join-Path $PackageDir 'DriverComponent.wxs') `
    (Join-Path $PackageDir 'DriverInstallCA.wxs') `
    (Join-Path $BuildDir   'QtHarvest.wxs') `
    -o $MsiOut 2>&1 | Tee-Object -Variable wixOut
if ($LASTEXITCODE -ne 0) { Die "MSI build failed" }

Log "Building Bundle..."
wix build -arch x64 `
    -d ProductVersion=1.0.0.0 `
    -d BinDir=$BinDir `
    -d InstallerDir=$PackageDir `
    -d MsiPath=$MsiOut `
    -ext WixToolset.Util.wixext `
    -ext WixToolset.BootstrapperApplications.wixext `
    (Join-Path $PackageDir 'Bundle.wxs') `
    -o $BundleOut 2>&1 | Tee-Object -Variable bundleOut
if ($LASTEXITCODE -ne 0) { Die "Bundle build failed" }

# ── SIGN ─────────────────────────────────────────────────────────────────────
if (-not $SkipSign) {
    Log "Signing..."
    $signScript = Join-Path $RepoRoot 'packaging\signing\Sign-PhantomHome.ps1'
    pwsh -File $signScript
    if ($LASTEXITCODE -ne 0) { Die "Signing failed" }
}

# ── DEPLOY TO vm_shrd ────────────────────────────────────────────────────────
New-Item -ItemType Directory -Force -Path $VmShared | Out-Null
Copy-Item $BundleOut $VmShared -Force
Copy-Item $MsiOut    $VmShared -Force

$bundleHash = (Get-FileHash $BundleOut -Algorithm SHA256).Hash
$msiHash    = (Get-FileHash $MsiOut    -Algorithm SHA256).Hash
@("$bundleHash *ShadowStrikePhantom-Home-Setup.exe",
  "$msiHash *ShadowStrikePhantom-Home-Setup.msi") |
    Out-File (Join-Path $VmShared 'SHA256SUMS.txt') -Encoding ascii -Force

Log "Deployed — EXE: $bundleHash"
Log "           MSI: $msiHash"

# ── SUBMIT JOB ───────────────────────────────────────────────────────────────
$jobId = "job-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$jobFile = Join-Path $JobsDir "$jobId.json"

$extraCmds = if ($ExtraCommands) { $ExtraCommands | ConvertFrom-Json } else { @() }

$job = [ordered]@{
    jobId          = $jobId
    status         = 'pending'
    # Path relative to SharedRoot as seen from host (VM agent resolves it)
    installerPath  = 'PhantomHome\ShadowStrikePhantom-Home-Setup.exe'
    installerHash  = $bundleHash
    waitSeconds    = $WaitSeconds
    collectPaths   = @(
        '%ProgramData%\ShadowStrike\Logs'
    )
    extraCommands  = @(
        @{ label='service-status';    script='Get-Service ShadowStrikePhantomService -ErrorAction SilentlyContinue | Select Status,DisplayName | ConvertTo-Json' }
        @{ label='event-log-errors';  script='Get-WinEvent -LogName Application -MaxEvents 50 -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -like "*Shadow*" -or $_.ProviderName -like "*Phantom*" } | Select TimeCreated,LevelDisplayName,Message | ConvertTo-Json' }
        @{ label='pipe-exists';       script='[bool](Get-ChildItem \\.\pipe\ -ErrorAction SilentlyContinue | Where-Object Name -like "*ShadowStrike*") | ConvertTo-Json' }
    ) + $extraCmds
    submittedAt    = (Get-Date -Format 'o')
    submittedBy    = $env:COMPUTERNAME
}

$job | ConvertTo-Json -Depth 5 | Out-File $jobFile -Encoding utf8 -Force
Log "Job submitted: $jobId"

# ── POLL FOR RESULTS ─────────────────────────────────────────────────────────
Log "Waiting for VM agent to complete job (timeout=${JobTimeout}s)..."
$deadline   = [DateTime]::UtcNow.AddSeconds($JobTimeout)
$statusFile = Join-Path $ResultsDir "$jobId\status.json"
$lastStatus = ''

while ([DateTime]::UtcNow -lt $deadline) {
    Start-Sleep -Seconds 3
    if (Test-Path $statusFile) {
        try {
            $statusObj = Get-Content $statusFile -Raw | ConvertFrom-Json
            $st = $statusObj.status
            if ($st -ne $lastStatus) {
                Log "Job status: $st"
                $lastStatus = $st
            }
            if ($st -eq 'done' -or $st -eq 'failed') { break }
        } catch {}
    }
}

# ── PRINT RESULTS ────────────────────────────────────────────────────────────
$resultDir  = Join-Path $ResultsDir $jobId
$statusObj  = $null
if (Test-Path $statusFile) {
    $statusObj = Get-Content $statusFile -Raw | ConvertFrom-Json
}

if (-not $statusObj) {
    Die "Timeout: VM agent did not respond within ${JobTimeout}s. Is PhantomVMAgent running on the VM?"
}

Log ""
Log "================================================================"
Log "  JOB RESULT: $($statusObj.status.ToUpper())"
if ($statusObj.error) { Log "  ERROR: $($statusObj.error)" }
Log "================================================================"
Log ""

# Print all collected log files
$logsDir = Join-Path $resultDir 'logs'
if (Test-Path $logsDir) {
    $logFiles = Get-ChildItem $logsDir -File | Sort-Object Name
    foreach ($lf in $logFiles) {
        Log ""
        Log "════════════════════════════════════════════════"
        Log "  LOG: $($lf.Name) ($([Math]::Round($lf.Length/1KB,1)) KB)"
        Log "════════════════════════════════════════════════"
        Get-Content $lf.FullName | Write-Host
    }
}

# Print extra command outputs
$cmdDir = Join-Path $resultDir 'commands'
if (Test-Path $cmdDir) {
    $cmdFiles = Get-ChildItem $cmdDir -File | Sort-Object Name
    foreach ($cf in $cmdFiles) {
        Log ""
        Log "────────────────────────────────────────────────"
        Log "  CMD: $($cf.Name)"
        Log "────────────────────────────────────────────────"
        Get-Content $cf.FullName | Write-Host
    }
}

# Copy diagnostics snapshot to vm_shrd\PhantomHome\diagnostics\ for manual inspection
$snapDir = Join-Path $VmShared 'diagnostics'
New-Item -ItemType Directory -Force -Path $snapDir | Out-Null
if (Test-Path $logsDir) {
    Copy-Item (Join-Path $logsDir '*') $snapDir -Force -ErrorAction SilentlyContinue
}
Log ""
Log "Diagnostics snapshot: $snapDir"

if ($statusObj.status -eq 'failed') { exit 1 }
exit 0
