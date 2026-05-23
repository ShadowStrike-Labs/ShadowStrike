<#
.SYNOPSIS
    Host-side: build PhantomHome, deploy to vm_shrd, submit test job, wait for
    results, and print all collected logs to stdout so the AI agent can read them.

.DESCRIPTION
    Full automated pipeline:
      1. MSBuild: PhantomCoreLib (if -RebuildLib) + service + UI + tray
      2. Package: MSI → Bundle (wix build)
      3. Sign: packaging\signing\Sign-PhantomHome.ps1
      4. Stage: copy installers and build artifacts to vm_shrd\PhantomHome\
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
$MsiObjDir   = Join-Path $BuildDir 'obj\msi'
$BundleObjDir = Join-Path $BuildDir 'obj\bundle'
$PackageDir  = Join-Path $RepoRoot 'packaging\installer'
$VmShared    = Join-Path $RepoRoot 'vm_shrd\PhantomHome'
$AutoDir     = Join-Path $RepoRoot 'vm_shrd\auto'
$JobsDir     = Join-Path $AutoDir  'jobs'
$ResultsDir  = Join-Path $AutoDir  'results'

$MSBuild     = 'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe'
$MsiOut      = Join-Path $BuildDir 'ShadowStrikePhantom-Home-Setup.msi'
$BundleOut   = Join-Path $BuildDir 'ShadowStrikePhantom-Home-Setup.exe'
$ProductVersion = '1.0.1.0'

New-Item -ItemType Directory -Force -Path $JobsDir    | Out-Null
New-Item -ItemType Directory -Force -Path $ResultsDir | Out-Null

# ── LOGGING ──────────────────────────────────────────────────────────────────
function Log { param($Msg) Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Msg" }
function Die { param($Msg) Write-Error $Msg; exit 1 }

function Require-File {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Label)
    if (-not (Test-Path $Path -PathType Leaf)) {
        Die "$Label not found: $Path"
    }
}

function Sync-QtRuntimeStaging {
    $qtRoot = if ($env:Qt6_ROOT) { $env:Qt6_ROOT } else { 'C:\Qt\6.7.3\msvc2019_64' }
    $qtBin  = Join-Path $qtRoot 'bin'
    $deploy = Join-Path $qtBin  'windeployqt.exe'
    Require-File -Path $deploy -Label 'windeployqt'

    $uiExe = Join-Path $BinDir 'ShadowStrikePhantomUI.exe'
    Require-File -Path $uiExe -Label 'PhantomHome UI executable'

    New-Item -ItemType Directory -Force -Path $StagingDir | Out-Null
    Log "Refreshing Qt runtime staging with windeployqt..."
    & $deploy `
        --qmldir (Join-Path $RepoRoot 'src\Products\Community\PhantomHome\UI\Client\qml') `
        --dir $StagingDir `
        --no-system-d3d-compiler `
        --no-opengl-sw `
        $uiExe
    if ($LASTEXITCODE -ne 0) { Die "windeployqt staging failed" }
}

function Assert-QtHarvestSources {
    $harvest = Join-Path $BuildDir 'QtHarvest.wxs'
    Require-File -Path $harvest -Label 'QtHarvest.wxs'

    $content = Get-Content $harvest -Raw
    $matches = [regex]::Matches($content, 'Source="\$\(var\.StagingDir\)\\([^"]+)"')
    $missing = New-Object System.Collections.Generic.List[string]

    foreach ($m in $matches) {
        $relative = $m.Groups[1].Value
        $source = Join-Path $StagingDir $relative
        if (-not (Test-Path $source -PathType Leaf)) {
            $missing.Add($relative)
            if ($missing.Count -ge 20) { break }
        }
    }

    if ($missing.Count -gt 0) {
        Die ("QtHarvest references missing staged runtime files: " + ($missing -join ', '))
    }

    Log "QtHarvest source validation passed ($($matches.Count) staged files)."
}

function Copy-ProductExecutablesToStaging {
    foreach ($name in @('ShadowStrikePhantomService.exe',
                       'ShadowStrikePhantomUI.exe',
                       'ShadowStrikePhantomTray.exe',
                       'ShadowStrikeDriverResume.exe')) {
        $src = Join-Path $BinDir $name
        Require-File -Path $src -Label $name
        Copy-Item $src $StagingDir -Force
    }
    Log "Staged service, UI, and tray executables."
}

function Assert-MsiAuthoring {
    param([Parameter(Mandatory)][string]$Path)

    Require-File -Path $Path -Label 'PhantomHome MSI'

    $assertDir = Join-Path ([IO.Path]::GetTempPath()) ("ss-msi-assert-{0}" -f ([Guid]::NewGuid()))
    New-Item -ItemType Directory -Force -Path $assertDir | Out-Null
    $decompiled = Join-Path $assertDir 'decompiled.wxs'

    try {
        wix msi decompile $Path -o $decompiled | Out-Null
        if ($LASTEXITCODE -ne 0) { Die "MSI decompile failed during authoring assertion" }

        $content = Get-Content $decompiled -Raw
        $failures = New-Object System.Collections.Generic.List[string]

        if ($content -notmatch ('<Package\b[\s\S]*?\bVersion="' + [regex]::Escape($ProductVersion) + '"')) {
            $failures.Add("MSI package version is not $ProductVersion")
        }
        if ($content -notmatch '<ServiceInstall\b[\s\S]*?\bName="ShadowStrikePhantomService"') {
            $failures.Add('ServiceInstall for ShadowStrikePhantomService is missing')
        }
        if ($content -notmatch '<ServiceDependency\b[^>]*\bId="Winmgmt"') {
            $failures.Add('Winmgmt service dependency is missing')
        }
        if ($content -notmatch '<ServiceDependency\b[^>]*\bId="FltMgr"') {
            $failures.Add('FltMgr service dependency is missing')
        }
        if ($content -match '<ServiceControl\b[^>]*\bName="ShadowStrikePhantomService"[^>]*\bStart="install"') {
            $failures.Add('ServiceControl still starts ShadowStrikePhantomService during MSI install')
        }
        if ($content -notmatch '<CustomAction\b[^>]*\bId="ExecDriverInstallStg1"') {
            $failures.Add('ExecDriverInstallStg1 custom action is missing')
        }
        if ($content -notmatch '--stage1-msi') {
            $failures.Add('DriverResume MSI-safe stage1 command is missing')
        }
        if ($content -notmatch '<Component\b[^>]*\bId="CmpInstallAnchor"') {
            $failures.Add('CmpInstallAnchor registry component is missing')
        }

        if ($failures.Count -gt 0) {
            Die ("MSI authoring assertion failed: " + ($failures -join '; '))
        }

        Log "MSI authoring assertion passed."
    } finally {
        Remove-Item $assertDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

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

    Log "Building PhantomHome Tray..."
    & $MSBuild (Join-Path $RepoRoot 'ShadowStrikePhantomTray.vcxproj') `
        /p:Configuration=Release /p:Platform=x64 /m /nologo /v:minimal
    if ($LASTEXITCODE -ne 0) { Die "Tray build failed" }

    Sync-QtRuntimeStaging
    Copy-ProductExecutablesToStaging
    Assert-QtHarvestSources
} else {
    Assert-QtHarvestSources
}

# ── PACKAGE ──────────────────────────────────────────────────────────────────
Log "Building MSI..."
New-Item -ItemType Directory -Force -Path $MsiObjDir | Out-Null
wix build -arch x64 `
    -intermediatefolder $MsiObjDir `
    -d ProductVersion=$ProductVersion `
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
Assert-MsiAuthoring -Path $MsiOut

Log "Building Bundle..."
New-Item -ItemType Directory -Force -Path $BundleObjDir | Out-Null
wix build -arch x64 `
    -intermediatefolder $BundleObjDir `
    -d ProductVersion=$ProductVersion `
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
Remove-Item (Join-Path $VmShared '*.exe') -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $VmShared '*.msi') -Force -ErrorAction SilentlyContinue
Copy-Item $BundleOut $VmShared -Force
Copy-Item $MsiOut    $VmShared -Force

$VmArtifacts = Join-Path $VmShared 'artifacts'
New-Item -ItemType Directory -Force -Path $VmArtifacts | Out-Null
foreach ($name in @('ShadowStrikePhantomService.exe',
                   'ShadowStrikePhantomUI.exe',
                   'ShadowStrikePhantomTray.exe',
                   'ShadowStrikeDriverResume.exe')) {
    $src = Join-Path $BinDir $name
    if (Test-Path $src -PathType Leaf) {
        Copy-Item $src $VmArtifacts -Force
    }
}

$bundleHash = (Get-FileHash $BundleOut -Algorithm SHA256).Hash
$msiHash    = (Get-FileHash $MsiOut    -Algorithm SHA256).Hash
$hashLines = @("$bundleHash *ShadowStrikePhantom-Home-Setup.exe",
               "$msiHash *ShadowStrikePhantom-Home-Setup.msi")
foreach ($artifact in Get-ChildItem $VmArtifacts -File -ErrorAction SilentlyContinue | Sort-Object Name) {
    $hash = (Get-FileHash $artifact.FullName -Algorithm SHA256).Hash
    $hashLines += "$hash *artifacts\$($artifact.Name)"
}
$hashLines | Out-File (Join-Path $VmShared 'SHA256SUMS.txt') -Encoding ascii -Force

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
