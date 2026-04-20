# ShadowStrike Phantom Home - WiX Packaging

This directory contains the [WiX Toolset v4](https://wixtoolset.org/) authoring
that turns the three built executables into an MSI.

## Prerequisites

* WiX 4.x as a .NET global tool:
  ```
  dotnet tool install --global wix --version 4.*
  wix extension add WixToolset.Util.wixext/4.0.5
  ```
* All three executables built in `Release|x64`:
  - `bin\Release\ShadowStrikePhantomService.exe`
  - `bin\Release\ShadowStrikePhantomTray.exe`
  - `bin\Release\ShadowStrikePhantomUI.exe`

## Build

From the repository root:

```
wix build ^
  -arch x64 ^
  -d ProductVersion=1.0.0 ^
  -d BinDir=bin\Release ^
  -ext WixToolset.Util.wixext ^
  packaging\wix\ShadowStrikePhantomHome.wxs ^
  -o bin\Release\ShadowStrikePhantomHome.msi
```

`ProductVersion` is injected by the caller (CI pipeline or release script);
it must be a `major.minor.build` string. `BinDir` points at the directory
containing the three executables.

## What the MSI does

1. Copies the service, tray, and UI exes into
   `%ProgramFiles%\ShadowStrike\Phantom\`.
2. Registers `ShadowStrikePhantomService` with the SCM as a LocalSystem
   auto-start service via MSI's native `ServiceInstall` element. Failure
   actions match the programmatic installer (two restarts at 60 s).
3. Starts the service on install and stops it on uninstall via
   `ServiceControl`.
4. Writes
   `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\ShadowStrikePhantomTray`
   so the tray launches for every interactive user on logon.
5. Populates Add/Remove Programs metadata and blocks downgrades via
   `MajorUpgrade`.

## What the MSI does NOT do

* It does not ship the dashboard-cloud or Pro/Enterprise components - those
  are packaged separately by the commercial tier.
* It does not sign the output. Signing is a downstream CI step:
  ```
  signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 ^
                /f <cert.pfx> /p <pw> bin\Release\ShadowStrikePhantomHome.msi
  ```

## Upgrade contract

`UpgradeCode="D8A6D9E2-4E2F-4A8B-9D3E-7F6B0E2C1A11"` is the permanent
identity of the product. It must never change. Changing it breaks upgrade
paths for every existing customer - they would end up with two copies
installed side-by-side.
