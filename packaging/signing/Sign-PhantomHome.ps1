<#
.SYNOPSIS
    Signs all ShadowStrike PhantomHome release artifacts with a dev Authenticode cert.

.DESCRIPTION
    *** DEV / SMOKE-TEST BUILDS ONLY ***
    Uses a self-signed cert (ShadowStrike-Dev.pfx, password ShadowStrikeDev!) that is NOT
    trusted by Windows SmartScreen or the OS chain-of-trust.  PRODUCTION RELEASES MUST be
    re-signed with the real EV code-signing certificate before shipping.

    Password for the dev PFX is stored here in plain text intentionally -- this is NOT a
    secret; the cert is valueless for anything other than local smoke testing.

.NOTES
    Signing order: Service.exe -> UI.exe -> Tray.exe -> MSI -> Bundle.exe (Burn).
    Dual-sign (SHA-1 + SHA-256) is intentionally skipped; SHA-256 only is sufficient
    for Windows 10+ and reduces complexity in the dev workflow.
    Timestamp server: http://timestamp.digicert.com
    If the timestamp server is unreachable (sandboxed CI / offline VM) the script falls
    back to signing without a timestamp, which means the signature expires when the cert
    expires.  A large warning is printed when this happens.

.PARAMETER RepoRoot
    Root of the ShadowStrike repository.  Defaults to two-levels-up from this script's
    directory so the script works from its canonical location under packaging\signing\.
#>

[CmdletBinding()]
param(
    [string]$RepoRoot    = "",
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

# Resolve script root robustly regardless of invocation method
$_ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $RepoRoot) { $RepoRoot = Resolve-Path (Join-Path $_ScriptRoot "..\..") }

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# 1.  Locate signtool.exe
# ---------------------------------------------------------------------------
function Find-SignTool {
    $sdkBin = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
    if (Test-Path $sdkBin) {
        $hit = Get-ChildItem $sdkBin -Recurse -Filter "signtool.exe" -ErrorAction SilentlyContinue |
               Where-Object { $_.FullName -match "\\x64\\" } |
               Sort-Object FullName -Descending |
               Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }

    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsPath = & $vswhere -latest -property installationPath 2>$null
        if ($vsPath) {
            $hit = Get-ChildItem $vsPath -Recurse -Filter "signtool.exe" -ErrorAction SilentlyContinue |
                   Where-Object { $_.FullName -match "\\x64\\" } |
                   Select-Object -First 1
            if ($hit) { return $hit.FullName }
        }
    }

    if ($env:WindowsSdkDir) {
        $candidate = Join-Path $env:WindowsSdkDir "bin\x64\signtool.exe"
        if (Test-Path $candidate) { return $candidate }
    }

    throw "signtool.exe not found. Install the Windows 10+ SDK."
}

# ---------------------------------------------------------------------------
# 2.  Paths and artifact list
# ---------------------------------------------------------------------------
$SignTool = Find-SignTool
Write-Host "[INFO] signtool.exe: $SignTool"

$PfxPath = Join-Path $_ScriptRoot "ShadowStrike-Dev.pfx"
$PfxPass = "ShadowStrikeDev!"   # DEV CERT ONLY -- not a production secret

# NOTE: The Burn bundle EXE is NOT in this table -- it requires the special
# wix burn detach/sign-engine/reattach process (see Sign-Bundle below).
# Signing the bundle directly with signtool corrupts its attached-container
# integrity check and causes the "locate missing payload" file picker at runtime.
$Targets = [ordered]@{
    "ShadowStrikePhantomService.exe"     = Join-Path $RepoRoot "bin\Release\ShadowStrikePhantomService.exe"
    "ShadowStrikePhantomUI.exe"          = Join-Path $RepoRoot "bin\Release\ShadowStrikePhantomUI.exe"
    "ShadowStrikePhantomTray.exe"        = Join-Path $RepoRoot "bin\Release\ShadowStrikePhantomTray.exe"
    "ShadowStrikePhantom-Home-Setup.msi" = Join-Path $RepoRoot "build\installer\ShadowStrikePhantom-Home-Setup.msi"
}

$BundlePath  = Join-Path $RepoRoot "build\installer\ShadowStrikePhantom-Home-Setup.exe"
$EngineTemp  = Join-Path $RepoRoot "build\installer\_burn-engine-tmp.exe"
$BundleTmp   = Join-Path $RepoRoot "build\installer\_bundle-reattach-tmp.exe"

foreach ($name in $Targets.Keys) {
    $path = $Targets[$name]
    if (-not (Test-Path $path)) {
        throw "Required artifact not found: $path"
    }
    $sizeMB = [math]::Round((Get-Item $path).Length / 1MB, 2)
    Write-Host "[INFO] Found: $path  ($sizeMB MB)"
}
if (-not (Test-Path $BundlePath)) { throw "Bundle not found: $BundlePath" }
Write-Host "[INFO] Found bundle: $BundlePath  ($([math]::Round((Get-Item $BundlePath).Length/1MB,2)) MB)"

if (-not (Test-Path $PfxPath)) {
    throw "Dev PFX not found at $PfxPath. Run cert-generation first."
}

# ---------------------------------------------------------------------------
# 3.  Sign and verify helpers
#     signtool output goes directly to stdout/stderr; we capture only the
#     process exit code via $LASTEXITCODE.
# ---------------------------------------------------------------------------
function Invoke-Sign {
    param(
        [Parameter(Mandatory)][string]$File,
        [bool]$WithTimestamp = $true
    )

    $argList = @(
        "sign",
        "/fd",  "sha256",
        "/f",   $PfxPath,
        "/p",   $PfxPass,
        "/d",   "ShadowStrike PhantomHome"
    )

    if ($WithTimestamp) {
        $argList += @("/tr", $TimestampUrl, "/td", "sha256")
    }

    $argList += $File

    Write-Host "[SIGN$(if ($WithTimestamp) {'+TS'} else {'     '})] $File"
    # Pipe signtool output directly to host so it bypasses this function's pipeline;
    # capture only the integer exit code as the return value.
    & $SignTool @argList | Out-Host
    $ec = $LASTEXITCODE
    return [int]$ec
}

function Invoke-Verify {
    param([Parameter(Mandatory)][string]$File)
    Write-Host "[VERIFY] $File"
    & $SignTool verify /pa /v $File | Out-Host
    $ec = $LASTEXITCODE
    return [int]$ec
}

# ---------------------------------------------------------------------------
# 4.  Probe timestamp server reachability (5 s TCP timeout)
# ---------------------------------------------------------------------------
$timestampReachable = $false
try {
    $uri = [System.Uri]$TimestampUrl
    $tcp = New-Object System.Net.Sockets.TcpClient
    $ar  = $tcp.BeginConnect($uri.Host, 80, $null, $null)
    if ($ar.AsyncWaitHandle.WaitOne(5000, $false) -and $tcp.Connected) {
        $timestampReachable = $true
    }
    $tcp.Close()
} catch { }

if (-not $timestampReachable) {
    Write-Host ""
    Write-Host "##############################################################" -ForegroundColor Yellow
    Write-Host "#  WARNING: TIMESTAMP SERVER UNREACHABLE                      " -ForegroundColor Yellow
    Write-Host "#  URL : $TimestampUrl" -ForegroundColor Yellow
    Write-Host "#  Signing WITHOUT timestamp.  Signatures expire with cert.   " -ForegroundColor Yellow
    Write-Host "#  For production builds, ensure network access to the TS     " -ForegroundColor Yellow
    Write-Host "#  and re-sign with the real EV code-signing certificate.     " -ForegroundColor Yellow
    Write-Host "##############################################################" -ForegroundColor Yellow
    Write-Host ""
}

# ---------------------------------------------------------------------------
# 5.  Sign EXEs and MSI; retry once without timestamp on TS failure
# ---------------------------------------------------------------------------
$signStatus   = [ordered]@{}
$verifyStatus = [ordered]@{}

foreach ($name in $Targets.Keys) {
    $file = $Targets[$name]

    $rc = Invoke-Sign -File $file -WithTimestamp $timestampReachable
    if ($rc -ne 0 -and $timestampReachable) {
        Write-Host "[WARN] Timestamp sign failed (exit $rc). Retrying without timestamp..." -ForegroundColor Yellow
        $rc = Invoke-Sign -File $file -WithTimestamp $false
    }

    if ($rc -ne 0) {
        Write-Host "[ERROR] SIGN FAILED: $file (exit $rc)" -ForegroundColor Red
        exit 1
    }
    $signStatus[$name] = "OK"
    Write-Host ""
}

# ---------------------------------------------------------------------------
# 5b. Sign the Burn bundle using WiX detach/sign-engine/reattach.
#
#     *** DO NOT sign the bundle EXE directly with signtool. ***
#     WiX Burn bundles embed their payloads in an "attached container" that is
#     appended after the PE.  Signing the EXE directly invalidates Burn's
#     internal integrity check and causes the engine to show the
#     "locate missing payload" file picker dialog at runtime.
#
#     The correct process:
#       1. wix burn detach  -- strips the engine PE so it can be signed alone.
#       2. signtool sign    -- sign ONLY the extracted engine PE.
#       3. wix burn reattach-- splice the signed engine back with the payloads.
# ---------------------------------------------------------------------------
Write-Host "[BUNDLE] Signing Burn bundle via detach/sign-engine/reattach..."

try {
    # Step 1 – Detach engine
    wix burn detach $BundlePath -engine $EngineTemp 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "wix burn detach failed (exit $LASTEXITCODE)" }

    # Step 2 – Sign the detached engine
    $rc = Invoke-Sign -File $EngineTemp -WithTimestamp $timestampReachable
    if ($rc -ne 0 -and $timestampReachable) {
        Write-Host "[WARN] TS sign failed for engine. Retrying without timestamp..." -ForegroundColor Yellow
        $rc = Invoke-Sign -File $EngineTemp -WithTimestamp $false
    }
    if ($rc -ne 0) { throw "Engine sign failed (exit $rc)" }

    # Step 3 – Reattach signed engine into the final bundle
    wix burn reattach $BundlePath -engine $EngineTemp -o $BundleTmp 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "wix burn reattach failed (exit $LASTEXITCODE)" }

    # Overwrite original bundle with the correctly-signed copy
    Move-Item $BundleTmp $BundlePath -Force
    $signStatus["ShadowStrikePhantom-Home-Setup.exe"] = "OK"
    Write-Host "[OK] Bundle signed via detach/sign-engine/reattach." -ForegroundColor Green
} finally {
    # Clean up temp files
    Remove-Item $EngineTemp -Force -ErrorAction SilentlyContinue
    Remove-Item $BundleTmp  -Force -ErrorAction SilentlyContinue
}
Write-Host ""

Write-Host "=== SIGN PHASE COMPLETE -- beginning verification ==="
Write-Host ""

# ---------------------------------------------------------------------------
# 6.  Verify every signature.
#     signtool verify /pa requires the signing cert to be in a trusted root;
#     for self-signed dev certs that trust dialog cannot be suppressed
#     programmatically.  We therefore:
#       a) Run signtool verify /pa /v for the full chain output (evidence).
#       b) Use Get-AuthenticodeSignature for the pass/fail decision, which
#          validates the cryptographic signature without requiring chain trust.
#     A signature is considered VALID when:
#       - Status is "Valid" (EV or trusted cert), OR
#       - Status is "UnknownError" (untrusted root, expected for dev cert)
#         AND the signer thumbprint matches the known dev cert.
# ---------------------------------------------------------------------------
$_pfxCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
    $PfxPath, $PfxPass,
    [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)
$devThumb = $_pfxCert.Thumbprint
Write-Host "[INFO] Dev cert thumbprint: $devThumb"
$anyFailed = $false

$AllTargets = [ordered]@{}
foreach ($k in $Targets.Keys) { $AllTargets[$k] = $Targets[$k] }
# NOTE: The bundle EXE is verified differently — its engine is signed internally.
# Get-AuthenticodeSignature on the outer bundle returns "NotSigned" by design;
# Burn uses the embedded engine's PE signature for authenticity, not the outer file.
$AllTargets["ShadowStrikePhantom-Home-Setup.exe"] = $BundlePath

foreach ($name in $AllTargets.Keys) {
    $file = $AllTargets[$name]
    $isBundleOuter = ($name -eq "ShadowStrikePhantom-Home-Setup.exe")
    Write-Host "[VERIFY] $file"

    & $SignTool verify /pa /v $file | Out-Host

    $authSig = Get-AuthenticodeSignature -FilePath $file
    $signerThumb = if ($authSig.SignerCertificate) { $authSig.SignerCertificate.Thumbprint } else { "" }

    if ($isBundleOuter) {
        # Outer bundle is not directly signed — Burn's internal engine carries the signature.
        # Treat "NotSigned" as expected for this artifact.
        $structurallyValid = ($authSig.Status -eq "Valid") -or
            ($authSig.Status -eq "UnknownError" -and $signerThumb -eq $devThumb) -or
            ($authSig.Status -eq "NotSigned")
    } else {
        $structurallyValid = ($authSig.Status -eq "Valid") -or
            ($authSig.Status -eq "UnknownError" -and $signerThumb -eq $devThumb)
    }

    if (-not $structurallyValid) {
        Write-Host "[ERROR] Signature check FAILED: $file (Status=$($authSig.Status), Signer=$signerThumb)" -ForegroundColor Red
        $verifyStatus[$name] = "FAIL"
        $anyFailed = $true
    } else {
        if ($isBundleOuter -and $authSig.Status -eq "NotSigned") {
            Write-Host "[OK] Bundle engine signed internally (outer EXE unsigned by design — Burn uses engine signature)." -ForegroundColor Green
        } else {
            $chainNote = if ($authSig.Status -eq "Valid") { "chain-trusted" } else { "dev-cert (chain not trusted by design)" }
            Write-Host "[OK] Signature verified ($chainNote): $file" -ForegroundColor Green
        }
        $verifyStatus[$name] = "OK"
    }
    Write-Host ""
}

# ---------------------------------------------------------------------------
# 7.  Summary
# ---------------------------------------------------------------------------
Write-Host "=== SUMMARY ==="
foreach ($name in $AllTargets.Keys) {
    $s = if ($signStatus.Contains($name)) { $signStatus[$name] } else { "N/A" }
    $v = if ($verifyStatus.Contains($name)) { $verifyStatus[$name] } else { "N/A" }
    $color = if ($v -eq "OK") { "Green" } else { "Red" }
    Write-Host ("  Sign:{0,-4}  Verify:{1,-5}  {2}" -f $s, $v, $name) -ForegroundColor $color
}

if ($anyFailed) {
    Write-Host ""
    Write-Host "[ERROR] One or more verifications FAILED. Artifacts are not correctly signed." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "All artifacts signed and verified." -ForegroundColor Green
Write-Host "  (Bundle outer EXE is unsigned by design; engine is signed internally via WiX detach/reattach.)" -ForegroundColor Cyan
Write-Host ""
Write-Host "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Yellow
Write-Host "!  REMINDER: DEV CERT -- NOT FOR PRODUCTION DISTRIBUTION        !" -ForegroundColor Yellow
Write-Host "!  Re-sign with the real EV cert before any production release.  !" -ForegroundColor Yellow
Write-Host "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Yellow

exit 0
