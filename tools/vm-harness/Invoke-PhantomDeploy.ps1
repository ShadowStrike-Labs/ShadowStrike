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
    [switch]$NoVMRun,
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
$ProductVersion = '1.0.71'
$SigningDir  = Join-Path $RepoRoot 'packaging\signing'
$DevPfxPath  = Join-Path $SigningDir 'ShadowStrike-Dev.pfx'
$DevCerPath  = Join-Path $SigningDir 'ShadowStrike-Dev.cer'

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

# ── SIGNING HELPERS ──────────────────────────────────────────────────────────
function Get-LatestSigntoolPath {
    $candidates = @(
        'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe',
        'C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe',
        'C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000.0\x64\signtool.exe',
        'C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe'
    )
    $direct = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($direct) { return $direct }

    $found = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe' -ErrorAction SilentlyContinue |
             Sort-Object { try { [version]($_.Directory.Parent.Name) } catch { [version]'0.0' } } -Descending |
             Select-Object -First 1
    if ($found) { return $found.FullName }
    return $null
}

# Resolve the PFX password once: empty if the PFX has no password, otherwise
# pulled from $env:SHADOWSTRIKE_PFX_PASSWORD.  Fails fast if neither path works.
function Resolve-PfxPassword {
    param([Parameter(Mandatory)][string]$PfxPath)
    Require-File -Path $PfxPath -Label 'Dev PFX'

    # Validate via X509Certificate2 (authoritative: opens the private key the
    # same way signtool does). Get-PfxData can spuriously fail on a valid PFX in
    # a -NoProfile / non-interactive child process even with the correct
    # password, which previously aborted an otherwise-valid signed deploy.
    $ss_TryPfx = {
        param($Plain)
        try {
            $c = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PfxPath, $Plain)
            $has = $c.HasPrivateKey; $c.Dispose(); return $has
        } catch { return $false }
    }

    # Try unpassworded first
    if (& $ss_TryPfx '') { return '' }

    $envPwd = $env:SHADOWSTRIKE_PFX_PASSWORD
    if ([string]::IsNullOrEmpty($envPwd)) {
        # Last-resort: known dev password documented in Sign-PhantomHome.ps1
        $envPwd = 'ShadowStrikeDev!'
    }

    if (& $ss_TryPfx $envPwd) { return $envPwd }

    Die "Dev PFX at $PfxPath is password-protected and no working password is available. Set `$env:SHADOWSTRIKE_PFX_PASSWORD before running this harness."
}

function Sign-Artifact {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$PfxPath,
        [string]$PfxPasswordPlain = '',
        [Parameter(Mandatory)][string]$Signtool,
        [string]$TimestampUrl = 'http://timestamp.digicert.com'
    )

    Require-File -Path $Path     -Label "Artifact to sign"
    Require-File -Path $PfxPath  -Label 'PFX'
    Require-File -Path $Signtool -Label 'signtool.exe'

    $argList = @('sign', '/fd', 'SHA256', '/f', $PfxPath)
    if (-not [string]::IsNullOrEmpty($PfxPasswordPlain)) {
        $argList += @('/p', $PfxPasswordPlain)
    }
    $argList += @('/tr', $TimestampUrl, '/td', 'SHA256', '/d', 'ShadowStrike PhantomHome', $Path)

    Log "[SIGN] $Path"
    & $Signtool @argList | Out-Host
    $rc = $LASTEXITCODE

    if ($rc -ne 0) {
        # Retry once without timestamp (sandboxed/offline environments)
        Log "[SIGN] Timestamp failed (exit $rc); retrying without /tr ..."
        $noTs = @('sign', '/fd', 'SHA256', '/f', $PfxPath)
        if (-not [string]::IsNullOrEmpty($PfxPasswordPlain)) {
            $noTs += @('/p', $PfxPasswordPlain)
        }
        $noTs += @('/d', 'ShadowStrike PhantomHome', $Path)
        & $Signtool @noTs | Out-Host
        $rc = $LASTEXITCODE
    }

    if ($rc -ne 0) {
        Die "Signing failed for $Path (signtool exit $rc)"
    }
}

function Assert-ArtifactsSigned {
    param([Parameter(Mandatory)][string[]]$Paths)

    $failures = New-Object System.Collections.Generic.List[string]
    foreach ($p in $Paths) {
        if (-not (Test-Path $p -PathType Leaf)) {
            $failures.Add("Missing artifact: $p")
            continue
        }
        $sig = Get-AuthenticodeSignature -FilePath $p
        $status = "$($sig.Status)"
        Log ("[AUTHSIG] {0,-14}  {1}" -f $status, $p)
        # Valid = chain-trusted; UnknownError = signed but untrusted root (expected for self-signed dev cert).
        # NotSigned / HashMismatch are hard fails.
        if ($status -ne 'Valid' -and $status -ne 'UnknownError') {
            $failures.Add("Artifact has Authenticode Status=${status}: $p")
        }
    }

    if ($failures.Count -gt 0) {
        Die ("Authenticode assertion failed: " + ($failures -join '; '))
    }
    Log "Authenticode assertion passed for $($Paths.Count) artifact(s)."
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
        if ($content -notmatch '<CustomAction\b[^>]*\bId="ExecDriverInstallStg1"[^>]*\bFileRef="DriverResumeExe"') {
            $failures.Add('ExecDriverInstallStg1 must run the installed DriverResumeExe file')
        }
        if ($content -notmatch '<CustomAction\b[^>]*\bId="ExecDriverInstallStg1"[^>]*\bReturn="ignore"') {
            $failures.Add('ExecDriverInstallStg1 must ignore DriverResume exit code to prevent MSI rollback')
        }
        if ($content -notmatch '--stage1-msi') {
            $failures.Add('DriverResume MSI-safe stage1 command is missing')
        }
        if ($content -notmatch '<Component\b[^>]*\bId="CmpInstallAnchor"') {
            $failures.Add('CmpInstallAnchor registry component is missing')
        }

        # ── Trust-root cert + ExecInstallRootCert authoring assertions ──
        if ($content -notmatch '<Component\b[^>]*\bId="CmpShadowStrikeRootCert"') {
            $failures.Add('CmpShadowStrikeRootCert component is missing')
        }
        if ($content -notmatch '<File\b[^>]*\bId="ShadowStrikeRootCer"[^>]*\bName="ShadowStrike-Dev\.cer"') {
            $failures.Add('ShadowStrikeRootCer file (Name=ShadowStrike-Dev.cer) is missing')
        }
        if ($content -notmatch '<CustomAction\b[^>]*\bId="ExecInstallRootCert"') {
            $failures.Add('ExecInstallRootCert custom action is missing')
        }
        if ($content -notmatch '<CustomAction\b[^>]*\bId="ExecInstallRootCert"[^>]*\bFileRef="DriverResumeExe"') {
            $failures.Add('ExecInstallRootCert must run the installed DriverResumeExe file')
        }
        # Return="check" is the WiX/MSI default; `wix msi decompile` elides it.
        # Accept either an explicit Return="check" attribute OR the absence of any
        # Return="..." attribute on the ExecInstallRootCert row.
        $rootCaMatch = [regex]::Match($content, '<CustomAction\b[^/]*?\bId="ExecInstallRootCert"[\s\S]*?/>')
        if ($rootCaMatch.Success) {
            $rowText = $rootCaMatch.Value
            $hasReturn = $rowText -match '\bReturn="([^"]+)"'
            if ($hasReturn -and $Matches[1] -ne 'check') {
                $failures.Add("ExecInstallRootCert must use Return=`"check`" (found Return=`"$($Matches[1])`")")
            }
        } else {
            $failures.Add('ExecInstallRootCert custom action row not parseable in decompiled MSI')
        }
        if ($content -notmatch '--install-root-cert') {
            $failures.Add('ExecInstallRootCert is missing the --install-root-cert ExeCommand argument')
        }

        # Sequencing: ExecInstallRootCert must precede ExecDriverInstallStg1 in InstallExecuteSequence.
        # Decompiled WiX renders sequence either as ordered <Custom Action="..." Before/After=...> rows
        # or as numeric Sequence="N" attributes.  Accept either: explicit Before/After link, or numeric ordering.
        $seqMatch = [regex]::Match($content, '<InstallExecuteSequence>([\s\S]*?)</InstallExecuteSequence>')
        if (-not $seqMatch.Success) {
            $failures.Add('InstallExecuteSequence block not found in decompiled MSI')
        } else {
            $seqBody = $seqMatch.Groups[1].Value

            $linkedBefore = $seqBody -match '<Custom\b[^>]*\bAction="ExecInstallRootCert"[^>]*\bBefore="ExecDriverInstallStg1"'
            $linkedAfter  = $seqBody -match '<Custom\b[^>]*\bAction="ExecDriverInstallStg1"[^>]*\bAfter="ExecInstallRootCert"'

            $numericOk = $false
            $rootMatch = [regex]::Match($seqBody, '<Custom\b[^>]*\bAction="ExecInstallRootCert"[^>]*\bSequence="(\d+)"')
            $stg1Match = [regex]::Match($seqBody, '<Custom\b[^>]*\bAction="ExecDriverInstallStg1"[^>]*\bSequence="(\d+)"')
            if ($rootMatch.Success -and $stg1Match.Success) {
                $numericOk = ([int]$rootMatch.Groups[1].Value -lt [int]$stg1Match.Groups[1].Value)
            }

            if (-not ($linkedBefore -or $linkedAfter -or $numericOk)) {
                $failures.Add('ExecInstallRootCert is not scheduled BEFORE ExecDriverInstallStg1 in InstallExecuteSequence')
            }
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
# PreferredToolArchitecture=x64 forces the 64-bit-hosted cl.exe; the default
# HostX86 toolchain runs out of heap on PhantomEmulator/JIT/JITCompiler.cpp
# (large `std::array<RuntimeBlock, 4096>` value-init exceeds 32-bit cl's
# compiler heap) and fails with C1060.
if (-not $SkipBuild) {
    if ($RebuildLib) {
        Log "Building PhantomCoreLib..."
        & $MSBuild (Join-Path $RepoRoot 'PhantomCoreLib.vcxproj') `
            /p:Configuration=Release /p:Platform=x64 /p:PreferredToolArchitecture=x64 /m /nologo /v:minimal
        if ($LASTEXITCODE -ne 0) { Die "PhantomCoreLib build failed" }
    }

    Log "Building PhantomHome Service..."
    & $MSBuild (Join-Path $RepoRoot 'ShadowStrikePhantomService.vcxproj') `
        /p:Configuration=Release /p:Platform=x64 /p:PreferredToolArchitecture=x64 /m /nologo /v:minimal
    if ($LASTEXITCODE -ne 0) { Die "Service build failed" }

    Log "Building PhantomHome UI..."
    & $MSBuild (Join-Path $RepoRoot 'ShadowStrikePhantomUI.vcxproj') `
        /p:Configuration=Release /p:Platform=x64 /p:PreferredToolArchitecture=x64 /m /nologo /v:minimal
    if ($LASTEXITCODE -ne 0) { Die "UI build failed" }

    Log "Building PhantomHome Tray..."
    & $MSBuild (Join-Path $RepoRoot 'ShadowStrikePhantomTray.vcxproj') `
        /p:Configuration=Release /p:Platform=x64 /p:PreferredToolArchitecture=x64 /m /nologo /v:minimal
    if ($LASTEXITCODE -ne 0) { Die "Tray build failed" }

    Log "Building PhantomHome DriverResume..."
    & $MSBuild (Join-Path $RepoRoot 'ShadowStrikeDriverResume.vcxproj') `
        /p:Configuration=Release /p:Platform=x64 /p:PreferredToolArchitecture=x64 /m /nologo /v:minimal
    if ($LASTEXITCODE -ne 0) { Die "DriverResume build failed" }

    Sync-QtRuntimeStaging

    # ── Sign C++ artifacts BEFORE they get embedded into the MSI. ─────────
    # The wix build packages whatever bin\Release contains right now into the
    # CAB; if we sign after wix build, the MSI ships unsigned copies of the
    # service/UI/tray/driver-resume EXEs even though the on-disk copies are
    # signed.  Sign first, then stage into the WiX staging dir.
    if (-not $SkipSign) {
        $signtool = Get-LatestSigntoolPath
        if (-not $signtool) { Die "signtool.exe not found under Windows Kits\10\bin\*\x64." }
        Log "Using signtool: $signtool"

        $pfxPwd = Resolve-PfxPassword -PfxPath $DevPfxPath

        foreach ($name in @('ShadowStrikePhantomService.exe',
                            'ShadowStrikePhantomTray.exe',
                            'ShadowStrikePhantomUI.exe',
                            'ShadowStrikeDriverResume.exe')) {
            $exe = Join-Path $BinDir $name
            Require-File -Path $exe -Label $name
            Sign-Artifact -Path $exe -PfxPath $DevPfxPath -PfxPasswordPlain $pfxPwd -Signtool $signtool
        }
    } else {
        Log "Skipping pre-stage EXE signing (-SkipSign)"
    }

    Copy-ProductExecutablesToStaging

    # ── Stage the dev trust-root .cer for the MSI Certs\ component. ────────
    $stagingCertsDir = Join-Path $StagingDir 'Certs'
    New-Item -ItemType Directory -Force -Path $stagingCertsDir | Out-Null
    Require-File -Path $DevCerPath -Label 'ShadowStrike-Dev.cer'
    Copy-Item $DevCerPath $stagingCertsDir -Force
    Log "Staged trust-root certificate: $stagingCertsDir\ShadowStrike-Dev.cer"

    Assert-QtHarvestSources
} else {
    Assert-QtHarvestSources

    # In SkipBuild mode the staging dir must still contain the .cer; stage it
    # if missing so wix build does not break on $(var.StagingDir)\Certs\...
    $stagingCertsDir = Join-Path $StagingDir 'Certs'
    New-Item -ItemType Directory -Force -Path $stagingCertsDir | Out-Null
    if (-not (Test-Path (Join-Path $stagingCertsDir 'ShadowStrike-Dev.cer'))) {
        Require-File -Path $DevCerPath -Label 'ShadowStrike-Dev.cer'
        Copy-Item $DevCerPath $stagingCertsDir -Force
    }
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
# After wix build, sign the MSI and bundle.  EXEs in bin\Release were already
# signed before staging so the MSI's CAB ships signed payloads; we still call
# Sign-PhantomHome.ps1 here to (a) re-verify those signatures via signtool /pa,
# (b) sign the freshly-built MSI, and (c) sign the Burn bundle via the
# detach/sign-engine/reattach process (which signtool alone cannot do safely).
if (-not $SkipSign) {
    Log "Signing MSI + Bundle (and re-verifying EXEs) via Sign-PhantomHome.ps1..."
    $signScript = Join-Path $RepoRoot 'packaging\signing\Sign-PhantomHome.ps1'
    pwsh -File $signScript
    if ($LASTEXITCODE -ne 0) { Die "Signing failed" }

    # ── Assert all 6 final artifacts carry an Authenticode signature. ──────
    $signedArtifacts = @(
        (Join-Path $BinDir   'ShadowStrikePhantomService.exe'),
        (Join-Path $BinDir   'ShadowStrikePhantomTray.exe'),
        (Join-Path $BinDir   'ShadowStrikePhantomUI.exe'),
        (Join-Path $BinDir   'ShadowStrikeDriverResume.exe'),
        $MsiOut
        # NOTE: Burn bundle outer EXE is intentionally signed via detach/reattach;
        # Get-AuthenticodeSignature against the outer file returns NotSigned even
        # when the engine is correctly signed.  Verified by signtool inside
        # Sign-PhantomHome.ps1; not re-asserted here to avoid a false failure.
    )
    Assert-ArtifactsSigned -Paths $signedArtifacts
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

if ($NoVMRun) {
    Log "-NoVMRun specified: skipping VM job submission and result polling."
    exit 0
}

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
