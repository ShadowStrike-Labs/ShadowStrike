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
# Product version, read from src\VersionInfo.h rather than repeated here.
#
# It used to be the literal '1.0.91' on this line, while the only resource script
# in the tree said 1.0.0.0 and the WiX sources carried their own default. Three
# copies, no agreement, and nothing that would notice. The header is now the one
# place the version is written down and every binary's VERSIONINFO comes from it,
# so this script must read it rather than assert it.
#
# A parse failure is fatal on purpose. Falling back to a literal is precisely how
# the previous mismatch survived: the deploy would keep working while stamping the
# wrong number onto the MSI.
$VersionHeader = Join-Path $RepoRoot 'src\VersionInfo.h'
if (-not (Test-Path $VersionHeader)) {
    throw "Cannot determine the product version: $VersionHeader is missing."
}
$verText = Get-Content $VersionHeader -Raw
$verParts = @{}
foreach ($field in @('MAJOR','MINOR','PATCH','BUILD')) {
    $m = [regex]::Match($verText, ('#define\s+SS_VERSION_' + $field + '\s+(\d+)'))
    if (-not $m.Success) {
        throw "Cannot parse SS_VERSION_$field from $VersionHeader."
    }
    $verParts[$field] = $m.Groups[1].Value
}
# MSI ProductVersion is major.minor.build with at most three fields honoured by
# Windows Installer for upgrade comparisons, so the fourth number is deliberately
# not included here even though the binaries carry it.
$ProductVersion = '{0}.{1}.{2}' -f $verParts['MAJOR'], $verParts['MINOR'], $verParts['PATCH']
$FileVersionFull = '{0}.{1}.{2}.{3}' -f $verParts['MAJOR'], $verParts['MINOR'], $verParts['PATCH'], $verParts['BUILD']
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

# Inf2Cat lives under x86 only - there is no x64 build of it in the WDK.
function Get-LatestInf2CatPath {
    $found = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin\*\x86\Inf2Cat.exe' -ErrorAction SilentlyContinue |
             Sort-Object { try { [version]($_.Directory.Parent.Name) } catch { [version]'0.0' } } -Descending |
             Select-Object -First 1
    if ($found) { return $found.FullName }
    $legacy = 'C:\Program Files (x86)\Windows Kits\10\bin\x86\Inf2Cat.exe'
    if (Test-Path $legacy) { return $legacy }
    return $null
}

# ── CERTIFICATE IDENTITY ─────────────────────────────────────────────────────
# Both helpers return the SHA-256 of the certificate's SUBJECT PUBLIC KEY, as
# uppercase hex.
#
# WHY THE PUBLIC KEY AND NOT THE THUMBPRINT: a thumbprint hashes the whole
# certificate, so it changes when the certificate is reissued or its validity
# window is extended even though the key - the thing that actually establishes
# identity - is unchanged. Pinning the key survives a legitimate reissue and
# still rejects a different signer, which is the property we want. It is also
# what the eventual production EV/WHQL certificate will need, so the mechanism
# does not have to be replaced when the certificate is.
function Get-CertificateSpkiSha256 {
    param([Parameter(Mandatory)][string]$CertPath)
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 `
                ((Resolve-Path -LiteralPath $CertPath).Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hash = $sha.ComputeHash($cert.PublicKey.EncodedKeyValue.RawData)
    return (($hash | ForEach-Object { $_.ToString('X2') }) -join '')
}

# Returns $null when the file carries no Authenticode signer certificate.
#
# NOTE: this deliberately does NOT require the signature to be TRUSTED.
# Get-AuthenticodeSignature reports Status=UnknownError for our dev certificate
# because this build host does not have the dev root installed, yet it still
# hands back SignerCertificate. Asking "who signed this" is a different question
# from "does this machine trust that signer", and conflating the two is what the
# runtime attestation defect did.
function Get-SignerSpkiSha256 {
    param([Parameter(Mandatory)][string]$FilePath)
    $sig = Get-AuthenticodeSignature -LiteralPath $FilePath
    if (-not $sig -or -not $sig.SignerCertificate) { return $null }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hash = $sha.ComputeHash($sig.SignerCertificate.PublicKey.EncodedKeyValue.RawData)
    return (($hash | ForEach-Object { $_.ToString('X2') }) -join '')
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
        [string]$TimestampUrl = 'http://timestamp.digicert.com',
        # Emit page hashes (/ph). Kernel-mode images only: Code Integrity can then
        # validate each page as it is paged in rather than only hashing the whole
        # file at load. Meaningless for a catalog, which has no image pages, and
        # for user-mode EXEs it only inflates the signature.
        [switch]$PageHashes
    )

    Require-File -Path $Path     -Label "Artifact to sign"
    Require-File -Path $PfxPath  -Label 'PFX'
    Require-File -Path $Signtool -Label 'signtool.exe'

    $argList = @('sign', '/fd', 'SHA256', '/f', $PfxPath)
    if (-not [string]::IsNullOrEmpty($PfxPasswordPlain)) {
        $argList += @('/p', $PfxPasswordPlain)
    }
    if ($PageHashes) { $argList += '/ph' }
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
        if ($PageHashes) { $noTs += '/ph' }
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

        # ── PhantomCortex model-store pointer ──
        # CortexConfigManager::LoadFromRegistry reads
        # HKLM\SOFTWARE\ShadowStrike\PhantomCortex\ModelDirectory (CortexConfig.cpp:65).
        # That reader existed for a long time with NO writer in any shipped installer -
        # the only authoring that wrote it was packaging\wix\ShadowStrikePhantomHome.wxs,
        # a duplicate installer definition that was never wired into this build and has
        # since been deleted. The value is asserted here rather than trusted because a
        # missing pointer does not fail anything visibly: the service silently falls back
        # to a hardcoded C:\ProgramData path and ML stays quiet either way.
        if ($content -notmatch '<Component\b[^>]*\bId="CmpCortexModelStore"') {
            $failures.Add('CmpCortexModelStore component is missing')
        }
        if ($content -notmatch '<RegistryValue\b[^>]*\bKey="SOFTWARE\\ShadowStrike\\PhantomCortex"[^>]*\bName="ModelDirectory"') {
            $failures.Add('PhantomCortex ModelDirectory registry pointer is missing')
        }
        if ($content -notmatch '<Directory\b[^>]*\bId="ProgramDataModels"[^>]*\bName="Models"') {
            $failures.Add('ProgramData\ShadowStrike\Models directory is missing')
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

# ── DETECTION CONTENT ────────────────────────────────────────────────────────
# Stage signatures.sdb and its attribution manifest for CmpDetectionContent.
#
# This runs for both the build and -SkipBuild paths, because the MSI needs the
# payload either way, and it DIES rather than continuing when the database is
# unavailable. That is deliberate: an MSI that packages fine while shipping no
# signatures, no patterns and no YARA rules produces an installation that starts,
# logs healthily and detects nothing. Every hard-won defect in this project has
# been of that shape, so the build refuses to produce one.
#
# The database is rebuilt only when it is missing or older than the newest rule
# source, so a normal deploy pays nothing and a content change is never missed.
function Sync-DetectionContentStaging {
    $stagingContentDir = Join-Path $StagingDir 'Content'
    New-Item -ItemType Directory -Force -Path $stagingContentDir | Out-Null

    $contentSrcDir = Join-Path $RepoRoot 'content'
    $sigBuild      = Join-Path $BinDir 'phantom-sigbuild.exe'
    $prebuiltDb    = Join-Path $PSScriptRoot 'signatures.sdb'
    $prebuiltDoc   = Join-Path $PSScriptRoot 'THIRD-PARTY-RULES.md'

    # Newest rule/hash/pattern source, if any content is checked out at all.
    $newestInput = $null
    if (Test-Path $contentSrcDir) {
        $newestInput = Get-ChildItem $contentSrcDir -Recurse -File -ErrorAction SilentlyContinue |
                       Sort-Object LastWriteTimeUtc -Descending |
                       Select-Object -First 1
    }

    $needsBuild = $false
    if ((Test-Path $sigBuild) -and $newestInput) {
        if (-not (Test-Path $prebuiltDb)) {
            $needsBuild = $true
            Log "Detection content: no prebuilt database, building from $contentSrcDir"
        } elseif ((Get-Item $prebuiltDb).LastWriteTimeUtc -lt $newestInput.LastWriteTimeUtc) {
            $needsBuild = $true
            Log "Detection content: $($newestInput.Name) is newer than signatures.sdb, rebuilding"
        }
    }

    if ($needsBuild) {
        & $sigBuild --out $prebuiltDb --content $contentSrcDir --overwrite 2>&1 |
            ForEach-Object { Log "  sigbuild: $_" }
        if ($LASTEXITCODE -ne 0) {
            Die "phantom-sigbuild failed with exit code $LASTEXITCODE - refusing to ship an MSI with stale or absent detection content."
        }
    }

    if (-not (Test-Path $prebuiltDb)) {
        Die @"
No detection database available, so the MSI would ship with zero signatures.

Build one before deploying:
  bin\Release\phantom-sigbuild.exe --out tools\vm-harness\signatures.sdb --content content --overwrite

The YARA rule pack is gitignored because roughly 640 of its rules carry no
redistribution grant; fetch it from https://github.com/YARAHQ/yara-forge/releases
into content\yara\ first. See content\README.md.
"@
    }

    Copy-Item $prebuiltDb (Join-Path $stagingContentDir 'signatures.sdb') -Force

    # Attribution is a redistribution CONDITION of DRL 1.1 and CC BY-SA 4.0, so a
    # database without its manifest is not shippable. phantom-sigbuild writes the
    # manifest beside its output; if it is not there the database was produced by
    # something other than the licence-filtering path and must not be shipped.
    if (-not (Test-Path $prebuiltDoc)) {
        Die @"
signatures.sdb is present but THIRD-PARTY-RULES.md is not, next to:
  $prebuiltDb

Attribution is a condition of the licences the bundled rules are distributed
under, not a courtesy, so shipping the database without it would breach them.
Rebuild with phantom-sigbuild, which generates the manifest alongside the output.
"@
    }
    Copy-Item $prebuiltDoc (Join-Path $stagingContentDir 'THIRD-PARTY-RULES.md') -Force

    # Report what is actually going into the MSI, decoded from the database header
    # rather than taken on trust: magic 'SSSD' at 0, rule/hash counts at 144/128.
    $bytes = New-Object byte[] 160
    $fs = [IO.File]::OpenRead((Join-Path $stagingContentDir 'signatures.sdb'))
    try { $null = $fs.Read($bytes, 0, 160) } finally { $fs.Close() }
    $magic = [BitConverter]::ToUInt32($bytes, 0)
    if ($magic -ne 0x53535344) {
        Die ("Staged signatures.sdb has magic 0x{0:X8}, expected 0x53535344 ('SSSD') - the file is not a signature database." -f $magic)
    }
    Log ("Staged detection content: {0:N0} bytes, {1:N0} hash(es), format {2}.{3}" -f `
        (Get-Item (Join-Path $stagingContentDir 'signatures.sdb')).Length, `
        [BitConverter]::ToUInt64($bytes, 128), `
        [BitConverter]::ToUInt16($bytes, 4), `
        [BitConverter]::ToUInt16($bytes, 6))
}

# Stage PhantomSensor.sys / .inf / .cat for CmpPhantomSensorDriver.
#
# WHY THIS EXISTS: DriverComponent.wxs sources all three files from
# $(var.StagingDir)\drivers, and NOTHING in this script ever wrote to that
# directory. The files got there by hand, once, and then stopped tracking the
# driver build - so 1.0.91 shipped a PhantomSensor.sys with NO VERSIONINFO
# resource at all, after that resource had been added AND verified. It was
# verified on the BUILD OUTPUT while the MSI packages the STAGED copy, and the
# two had silently diverged. A driver rebuild that never reaches the installer is
# the same silent staleness this project keeps paying for, so the copy is now part
# of the deploy rather than a step someone has to remember.
#
# THE CATALOG AND THE BINARY MUST MOVE TOGETHER. PhantomSensor.cat contains the
# hash of PhantomSensor.sys, so a catalog that does not cover the .sys beside it
# makes the driver fail signature verification and refuse to load. Copying one
# without the other is not a partial update, it is a broken install.
#
# ============================================================================
# AND THE DRIVER MUST BE SIGNED BY THE CERTIFICATE THE INSTALLER TRUSTS.
# ============================================================================
# The first version of this function copied the driver straight out of the WDK
# build output and staged it unsigned-by-us. That shipped 1.0.92 with a driver
# signed by "CN=WDKTestCert RTX40,134178001707380803" - the certificate the WDK
# generates by itself when a driver project has no explicit SignMode, which is
# the case here: <DriverSign> in PhantomSensor.vcxproj sets only
# FileDigestAlgorithm, so TestSign with an auto-generated cert is the default.
#
# DriverResume installs packaging\signing\ShadowStrike-Dev.cer into Root and
# TrustedPublisher. That is a DIFFERENT certificate. The WDK test cert is
# self-signed and is never installed anywhere, so the driver's chain could not
# terminate in a trusted root no matter how many times the installer succeeded:
#
#   DriverResume 15:42:37.092  cert installed into 'Root' store
#   DriverResume 15:42:37.092  cert installed into 'TrustedPublisher' store
#   DriverResume 15:42:37.273  WARN dev-cert signature (root not in CA store)
#                              HRESULT=0x800B0109        <- 180ms after installing
#
# and at runtime the consequence was total:
#
#   CryptoManager.cpp:5047  Authenticode verification FAILED (result=0x800B0109)
#   FilterConnection        KEX: Driver attestation FAILED
#   IPCManager              Primary encrypted scanner connection FAILED -
#                           kernel scan requests cannot be served
#
# ON-ACCESS SCANNING DID NOT RUN AT ALL on that build. The machine looked
# healthy - no freeze, no crash, UI served to the last line - precisely because
# no scan request ever reached user mode. A packaging defect presented as a
# clean run, which is the most expensive way for this to fail.
#
# WHY IT WAS INVISIBLE: Sign-PhantomHome.ps1 runs AFTER wix build and signs the
# staged driver too, so by the time anyone inspected build\installer\staging the
# .sys was correctly signed and 6,096 bytes larger. The MSI had already been
# built from the test-signed copy one second earlier. The staging directory and
# the shipped package disagreed, and staging is the one a human looks at.
#
# ORDER IS LOAD-BEARING, and the script already says so 200 lines above for the
# EXEs: sign BEFORE the artifact is packaged, because wix packages whatever is
# on disk at that moment. Within the driver package the order is tighter still:
#   1. sign the .sys          - changes the file, therefore changes its hash
#   2. run Inf2Cat            - hashes the .sys AS SIGNED into a new catalog
#   3. sign the .cat
# Signing the .sys after the catalog was generated leaves a catalog covering
# bytes that no longer exist. Inf2Cat must run after step 1 or not at all.
#
# The driver loads via CreateServiceW + FilterLoad (DriverInstaller.cpp:511,
# :631), not an INF/PnP install, so Code Integrity checks the .sys EMBEDDED
# signature at load and the catalog is not consulted on that path. The catalog
# is still regenerated rather than left stale: an artifact that opens fine and
# describes the wrong file is the exact failure mode this whole function exists
# to prevent, and this function's own catalog-freshness check would be asserting
# something false.
function Sync-DriverStaging {
    $driverOutDir  = Join-Path $RepoRoot 'PhantomSensor\x64\Release\PhantomSensor'
    $stagingDrvDir = Join-Path $StagingDir 'drivers'
    New-Item -ItemType Directory -Force -Path $stagingDrvDir | Out-Null

    $sysSrc = Join-Path $driverOutDir 'PhantomSensor.sys'
    $infSrc = Join-Path $driverOutDir 'PhantomSensor.inf'
    $catSrc = Join-Path $driverOutDir 'phantomsensor.cat'

    foreach ($need in @(@{ P = $sysSrc; L = 'driver binary' },
                        @{ P = $infSrc; L = 'driver INF' },
                        @{ P = $catSrc; L = 'driver catalog' })) {
        if (-not (Test-Path $need.P)) {
            Die @"
The $($need.L) is missing:
  $($need.P)

Build the driver before deploying, and build it with /t:Rebuild - an incremental
driver build fails inf2cat with an error that names nothing useful:
  MSBuild PhantomSensor\PhantomSensor.vcxproj /p:Configuration=Release /p:Platform=x64 /t:Rebuild
"@
        }
    }

    $sysItem = Get-Item $sysSrc

    # Validate the build output BEFORE signing it. Signing does not touch
    # VERSIONINFO, so this could run either side - it runs first so a driver from
    # the wrong build is rejected before we spend a signature on it.
    $drvVersion = $sysItem.VersionInfo.FileVersion
    if ([string]::IsNullOrWhiteSpace($drvVersion)) {
        Die "PhantomSensor.sys carries no VERSIONINFO resource, so the shipped driver would be unidentifiable in msinfo32, Autoruns and every driver-enumeration tool - on the one component that runs in ring 0. Rebuild the driver."
    }
    if ($drvVersion.Trim() -ne $FileVersionFull) {
        Die ("PhantomSensor.sys reports version '{0}' but this deploy is {1}, so the driver was not rebuilt after the version bump and the MSI would ship a driver from a different build than every other binary. Rebuild it with /t:Rebuild." -f `
            $drvVersion.Trim(), $FileVersionFull)
    }

    # ── Expected signer: the certificate the MSI ships and DriverResume trusts ──
    # Pinned to the SUBJECT PUBLIC KEY (SPKI SHA-256), not the thumbprint,
    # so reissuing the certificate with the same key does not break the check
    # while a different key does.
    $expectedCer = Join-Path $RepoRoot 'packaging\signing\ShadowStrike-Dev.cer'
    Require-File -Path $expectedCer -Label 'ShadowStrike-Dev.cer (driver trust anchor)'
    $expectedSpki = Get-CertificateSpkiSha256 -CertPath $expectedCer

    if ($SkipSign) {
        Log "WARNING: -SkipSign is set, so PhantomSensor.sys keeps the signature its build gave it."
        Log "WARNING: the WDK signs with an auto-generated test certificate that NOTHING installs,"
        Log "WARNING: so runtime driver attestation will fail with 0x800B0109, the encrypted kernel"
        Log "WARNING: channel will NOT establish, and ON-ACCESS SCANNING WILL NOT RUN on this build."
    }
    else {
        $signtool = Get-LatestSigntoolPath
        if (-not $signtool) { Die "signtool.exe not found under Windows Kits\10\bin\*\x64." }
        $pfxPwd = Resolve-PfxPassword -PfxPath $DevPfxPath

        # 1. Sign the .sys. This REPLACES the WDK test signature (signtool sign
        #    without /as replaces the primary signature rather than appending).
        #    /ph emits page hashes, which is what a kernel-mode image wants: Code
        #    Integrity can then validate pages as they are paged in. The previous
        #    owner of this step (Sign-PhantomHome.ps1) used /ph for the driver, so
        #    signing it here without page hashes would have quietly dropped that.
        Log "Signing PhantomSensor.sys with the deploy certificate..."
        Sign-Artifact -Path $sysSrc -PfxPath $DevPfxPath -PfxPasswordPlain $pfxPwd -Signtool $signtool -PageHashes

        # 2. Regenerate the catalog over the driver AS SIGNED. Must follow step 1:
        #    the catalog stores the hash of the .sys, and signing changed it.
        $inf2cat = Get-LatestInf2CatPath
        if (-not $inf2cat) {
            Die "Inf2Cat.exe not found under Windows Kits\10\bin\*\x86. The catalog cannot be regenerated over the signed driver, and shipping the pre-signing catalog would describe bytes that no longer exist."
        }
        Log "Regenerating driver catalog over the signed binary..."
        & $inf2cat /driver:"$driverOutDir" /os:10_X64 2>&1 | Out-Host
        if ($LASTEXITCODE -ne 0) {
            Die ("Inf2Cat failed (exit {0}) for {1}. The catalog no longer covers the signed driver, so this package must not ship. An incremental driver build is the usual cause - rebuild with /t:Rebuild." -f `
                $LASTEXITCODE, $driverOutDir)
        }
        if (-not (Test-Path $catSrc)) {
            Die ("Inf2Cat reported success but {0} is absent. Check the CatalogFile directive in PhantomSensor.inf matches this filename." -f $catSrc)
        }

        # 3. Sign the regenerated catalog.
        Log "Signing regenerated driver catalog..."
        Sign-Artifact -Path $catSrc -PfxPath $DevPfxPath -PfxPasswordPlain $pfxPwd -Signtool $signtool
    }

    # Re-stat: both files changed on disk if we signed them.
    $sysItem = Get-Item $sysSrc
    $catItem = Get-Item $catSrc

    Copy-Item $sysSrc (Join-Path $stagingDrvDir 'PhantomSensor.sys') -Force
    Copy-Item $infSrc (Join-Path $stagingDrvDir 'PhantomSensor.inf') -Force
    Copy-Item $catSrc (Join-Path $stagingDrvDir 'PhantomSensor.cat') -Force

    # ── Assert on the STAGED copies, because those are what wix packages. ──────
    # Verifying the build output is what let the last defect ship: the build tree
    # and the staged tree disagreed and only the staged one reaches the MSI.
    $stagedSys = Join-Path $stagingDrvDir 'PhantomSensor.sys'
    $stagedCat = Join-Path $stagingDrvDir 'PhantomSensor.cat'

    $stagedSysItem = Get-Item $stagedSys
    $stagedCatItem = Get-Item $stagedCat
    if ($stagedCatItem.LastWriteTimeUtc -lt $stagedSysItem.LastWriteTimeUtc) {
        Die ("PhantomSensor.cat ({0:u}) is older than PhantomSensor.sys ({1:u}), so the catalog cannot cover this driver. The catalog must be regenerated AFTER the driver is signed." -f `
            $stagedCatItem.LastWriteTimeUtc, $stagedSysItem.LastWriteTimeUtc)
    }

    if (-not $SkipSign) {
        # THE CHECK THAT MAKES THE 1.0.92 DEFECT UNSHIPPABLE.
        # A version check and a catalog check both passed while the driver was
        # signed by a certificate nothing trusts, because neither of them asked
        # WHO signed it. This one does, against the anchor the installer actually
        # installs, so the two can no longer disagree silently.
        $actualSpki = Get-SignerSpkiSha256 -FilePath $stagedSys
        if (-not $actualSpki) {
            Die ("The staged PhantomSensor.sys carries no Authenticode signer certificate. An unsigned kernel driver cannot pass runtime attestation and will not load under Code Integrity. Path: {0}" -f $stagedSys)
        }
        if ($actualSpki -ne $expectedSpki) {
            $actualSubject = (Get-AuthenticodeSignature -LiteralPath $stagedSys).SignerCertificate.Subject
            Die @"
The staged kernel driver is signed by the WRONG CERTIFICATE.

  staged driver signer : $actualSubject
       its public key  : $actualSpki
  installer trusts     : CN=ShadowStrike-Labs Dev Code Signing
       its public key  : $expectedSpki

DriverResume installs packaging\signing\ShadowStrike-Dev.cer into the Root and
TrustedPublisher stores. A driver signed by any other certificate cannot chain to
a trusted root on the target machine, so runtime driver attestation fails with
0x800B0109, the encrypted kernel channel is refused, and ON-ACCESS SCANNING NEVER
RUNS - while the service otherwise looks completely healthy.

This is exactly what shipped in 1.0.92. Do not work around this check.
"@
        }
        Log ("Driver signer verified: public key matches the installer's trust anchor ({0}...)" -f $actualSpki.Substring(0, 16))
    }

    Log ("Staged driver: PhantomSensor.sys {0:N0} bytes ver={1}, catalog {2:N0} bytes" -f `
        $stagedSysItem.Length, $drvVersion.Trim(), $stagedCatItem.Length)
}

Sync-DriverStaging
Sync-DetectionContentStaging

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
    (Join-Path $PackageDir 'ContentComponent.wxs') `
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

# THE LOOSE COPIES UNDER vm_shrd WENT STALE BECAUSE NOTHING REFRESHED THEM.
#
# Only the four executables above were ever re-copied, so artifacts\drivers and
# data\signatures.sdb kept whatever they held the last time somebody put them
# there by hand. On the 1.0.94 deploy that meant artifacts\drivers\PhantomSensor.sys
# was 11 days old and carried NO version resource at all, sitting next to an MSI
# whose driver was freshly built and stamped 1.0.94.0. Anyone loading the driver
# by hand on the VM - which is the only reason these loose copies exist - would
# have installed a different binary from the one under test and drawn conclusions
# about it.
#
# This is the defect Sync-DriverStaging already documents for build\installer\staging
# ("The staging directory and the shipped package disagreed, and staging is the one
# a human looks at"). vm_shrd is looked at more often than staging is, so it earns
# the same treatment.
#
# Copied from $StagingDir rather than rebuilt or re-signed, because $StagingDir
# holds the exact bytes the MSI's CAB was built from. Deriving them any other way
# reintroduces the possibility of disagreement that this block exists to remove.
$VmDrivers = Join-Path $VmArtifacts 'drivers'
New-Item -ItemType Directory -Force -Path $VmDrivers | Out-Null
foreach ($name in @('PhantomSensor.sys', 'PhantomSensor.inf', 'PhantomSensor.cat')) {
    $src = Join-Path (Join-Path $StagingDir 'drivers') $name
    if (Test-Path $src -PathType Leaf) {
        Copy-Item $src $VmDrivers -Force
    } else {
        Die "Driver artifact missing from staging: $src. The MSI was built from this directory, so a loose copy under vm_shrd cannot be made to agree with the installer."
    }
}

$VmData = Join-Path $VmShared 'data'
New-Item -ItemType Directory -Force -Path $VmData | Out-Null
foreach ($name in @('signatures.sdb', 'THIRD-PARTY-RULES.md')) {
    $src = Join-Path (Join-Path $StagingDir 'Content') $name
    if (Test-Path $src -PathType Leaf) {
        Copy-Item $src (Join-Path $VmData $name) -Force
    }
}

$bundleHash = (Get-FileHash $BundleOut -Algorithm SHA256).Hash
$msiHash    = (Get-FileHash $MsiOut    -Algorithm SHA256).Hash
$hashLines = @("$bundleHash *ShadowStrikePhantom-Home-Setup.exe",
               "$msiHash *ShadowStrikePhantom-Home-Setup.msi")
# RECURSIVE, and relative to $VmShared. The old enumeration was non-recursive over
# artifacts\ alone, so the manifest silently described six files while the share
# held the driver and the 64 MB detection database as well - the two payloads whose
# integrity matters most, and the two a reader would most want to check a hash for.
foreach ($artifact in Get-ChildItem $VmShared -File -Recurse -ErrorAction SilentlyContinue |
                          Where-Object { $_.Name -ne 'SHA256SUMS.txt' -and $_.FullName -notmatch '\\diag' } |
                          Sort-Object FullName) {
    $rel = $artifact.FullName.Substring($VmShared.Length).TrimStart('\')
    if ($rel -eq 'ShadowStrikePhantom-Home-Setup.exe' -or $rel -eq 'ShadowStrikePhantom-Home-Setup.msi') { continue }
    $hash = (Get-FileHash $artifact.FullName -Algorithm SHA256).Hash
    $hashLines += "$hash *$rel"
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
        # THE CLIENT LOGS LIVE SOMEWHERE ELSE, and not collecting them is why the
        # 1.0.93 run could not answer "why did the UI never connect?".
        #
        # The UI and tray run as the interactive user and the install directory is
        # read-only to that user, so both resolve their log directory to
        # %LOCALAPPDATA%\ShadowStrike\Logs (UI/Client/main.cpp InitLogger and
        # Tray/main.cpp InitTrayLogger). Only %ProgramData% was collected, so the
        # service's account of events was the only account available, and it
        # cannot see a client that fails before it sends anything.
        #
        # PhantomHomeUI*.log and PhantomHomeTray*.log land here.
        '%LOCALAPPDATA%\ShadowStrike\Logs'
    )
    extraCommands  = @(
        @{ label='service-status';    script='Get-Service ShadowStrikePhantomService -ErrorAction SilentlyContinue | Select Status,DisplayName | ConvertTo-Json' }
        @{ label='event-log-errors';  script='Get-WinEvent -LogName Application -MaxEvents 50 -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -like "*Shadow*" -or $_.ProviderName -like "*Phantom*" } | Select TimeCreated,LevelDisplayName,Message | ConvertTo-Json' }
        # Names, not a boolean. The previous probe answered only "does some pipe
        # matching *ShadowStrike* exist", which is true whenever ANY of our
        # servers is up and therefore cannot distinguish the UI channel being
        # absent from the control channel being present. Task 94 needed exactly
        # that distinction: there are two servers on two names one word apart.
        @{ label='pipe-names';        script='Get-ChildItem \\.\pipe\ -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*ShadowStrike*" -or $_.Name -like "*Phantom*" } | Select-Object -ExpandProperty Name | ConvertTo-Json' }
        # Did the client processes even start? A UI that never launched and a UI
        # that launched and could not authenticate look identical in a service log.
        @{ label='client-processes';  script='Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like "*ShadowStrikePhantom*" } | Select ProcessName,Id,StartTime | ConvertTo-Json' }
        # Does the per-session auth token the UI must read actually exist? An
        # empty read is the tray's own reported reason for failing to authenticate.
        @{ label='ui-auth-token';     script='$p = Join-Path $env:LOCALAPPDATA "ShadowStrike\ui.token"; $e = Test-Path $p; $len = 0; if ($e) { $len = (Get-Item $p).Length }; [ordered]@{ path=$p; exists=$e; length=$len } | ConvertTo-Json' }
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
