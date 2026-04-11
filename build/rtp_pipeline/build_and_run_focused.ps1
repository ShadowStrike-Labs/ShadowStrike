Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $repoRoot
Set-Location $repoRoot

function Get-VcVarsPath {
    $vsWhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vsWhere) {
        $installationPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($installationPath)) {
            $candidate = Join-Path $installationPath 'VC\Auxiliary\Build\vcvars64.bat'
            if (Test-Path $candidate) {
                return $candidate
            }
        }
    }

    $candidates = @(
        'C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat',
        'C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat',
        'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat',
        'C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
    )

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    throw 'Unable to locate vcvars64.bat.'
}

function Invoke-VcCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Command,
        [Parameter(Mandatory = $true)]
        [string] $LogPath
    )

    $vcVars = Get-VcVarsPath
    $quotedLogPath = '"' + $LogPath + '"'
    $cmdLine = 'call "' + $vcVars + '" && ' + $Command + ' > ' + $quotedLogPath + ' 2>&1'
    & cmd.exe /d /s /c $cmdLine
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE. See $LogPath"
    }
}

$compilePchLog = Join-Path $PSScriptRoot 'compile_pch.log'
$compileFocusedLog = Join-Path $PSScriptRoot 'compile_focused.log'
$linkFocusedLog = Join-Path $PSScriptRoot 'link_focused_min.log'
$runLog = Join-Path $PSScriptRoot 'RTPPipeline_focused_run.log'

Invoke-VcCommand -LogPath $compilePchLog -Command (@(
    'cl',
    '/nologo',
    '/c',
    '/std:c++latest',
    '/EHsc',
    '/MDd',
    '/Yc"pch.h"',
    '/Fpbuild\rtp_pipeline\focused_pch.pch',
    '/Fobuild\rtp_pipeline\pch.obj',
    '/I.',
    '/Isrc',
    '/Iinclude',
    '/Iinclude\YARA',
    '/Ivendor',
    '/Ivendor\gtest_framework\include',
    'src\pch.cpp'
) -join ' ')

Invoke-VcCommand -LogPath $compileFocusedLog -Command 'cl @build\rtp_pipeline\compile_focused.rsp'
Invoke-VcCommand -LogPath $linkFocusedLog -Command 'link @build\rtp_pipeline\link_focused_min.rsp'

$env:PATH = (Join-Path $repoRoot 'build') + ';' + $env:PATH
& .\build\rtp_pipeline\RTPPipeline_focused.exe *> $runLog
exit $LASTEXITCODE
