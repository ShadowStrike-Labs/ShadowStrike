# PhantomHome VM Smoke-Test Checklist

> **Audience:** QA engineers running a manual acceptance pass before each dev-signed build is
> handed off for broader testing.  
> **Build type:** Dev-cert signed (self-signed Authenticode).  See [Known Limitations](#known-limitations).  
> **Target OS:** Windows 11 22H2 x64 (also validated on Windows 10 22H2 x64).  
> **Estimated time:** 45–60 minutes per clean VM.

---

## Pre-flight requirements (VM)

Before you do anything else on the target VM, the following gates must be cleared.
Skipping any of them will cause the MSI to roll back at stage1 (driver work) and
leave the VM in a dirty state.

### 1. Disable Secure Boot in VM firmware

The dev build is signed with a self-signed certificate.  Secure Boot will refuse
to load the PhantomSensor minifilter against this cert, and the
`ExecDriverInstallStg1` custom action will fail mid-install.

| Hypervisor | How to disable |
|------------|----------------|
| Hyper-V    | VM Settings → Security → **uncheck** *Enable Secure Boot* |
| VirtualBox | Machine → Settings → System → **disable** *Enable EFI (special OSes only)* (or keep EFI but ensure no Secure Boot variables are persisted) |
| VMware Workstation / Fusion | VM → Settings → Options → Advanced → Boot Options → **uncheck** *Enable secure boot* |

Take a snapshot AFTER disabling Secure Boot so subsequent QA passes start from
a known-good firmware state.

### 2. Run `Pre-Install-Check.ps1` as Administrator

Copy `Pre-Install-Check.ps1` from the VM share (`vm_shrd\PhantomHome\`) into the VM
and run it from an elevated PowerShell prompt:

```powershell
# Run as Administrator
powershell.exe -ExecutionPolicy Bypass -File "C:\Users\Public\Desktop\Pre-Install-Check.ps1"
```

The script is **read-only** — it inspects the system but modifies nothing.

**PASS criterion:** Script exits with code `0` and prints `All checks passed`.
**FAIL criterion:** Exit code `1`.  Resolve any reported FAIL (typically: enable
Administrator context, disable SecureBoot, free disk space) before continuing.

`WARN` lines are advisory and do not block install (e.g., Defender real-time
protection still on, prior install folder present from a previous run).

### 3. Acceptable verification commands after install

These commands are the canonical post-install smoke checks.  Each should return
the indicated value within 60 seconds of the bundle EXE exiting.

```powershell
# Run as Administrator inside the VM

# (a) Service is registered, Automatic, and Running.
Get-Service ShadowStrikePhantomService | Select-Object Status, StartType

# (b) Install anchor is set.
Get-ItemProperty 'HKLM:\SOFTWARE\ShadowStrike\PhantomHome' -ErrorAction SilentlyContinue

# (c) Trust-root cert was installed by ExecInstallRootCert.
Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -match 'ShadowStrike' } |
    Select-Object Subject, Thumbprint, NotAfter

# (d) Driver staging files exist.
Test-Path 'C:\Program Files\ShadowStrike\Phantom\Drivers\PhantomSensor.sys'
Test-Path 'C:\Program Files\ShadowStrike\Phantom\Certs\ShadowStrike-Dev.cer'

# (e) Driver stage1 state file (consumed by the bootstrapper to decide reboot).
Get-Content 'C:\ProgramData\ShadowStrike\State\driver-stage1.json' -ErrorAction SilentlyContinue

# (f) Tray + UI processes (after first logon).
Get-Process ShadowStrikePhantomTray, ShadowStrikePhantomUI -ErrorAction SilentlyContinue |
    Select-Object Name, Id, StartTime

# (g) Named pipe is accepting connections.
[bool](Get-ChildItem \\.\pipe\ -ErrorAction SilentlyContinue | Where-Object Name -like '*ShadowStrike*')

# (h) No MSI rollback was recorded in the Application event log in the last hour.
Get-WinEvent -FilterHashtable @{ LogName='Application'; ProviderName='MsiInstaller'; StartTime=(Get-Date).AddHours(-1) } -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'rollback|1602|1603' } |
    Select-Object TimeCreated, Id, Message
```

---

## Prerequisites

| Item | Value |
|------|-------|
| VM snapshot name | `CLEAN-PRE-INSTALL` |
| VM RAM | ≥ 4 GB |
| VM Disk | ≥ 40 GB free |
| Network | NAT or bridged (needed for service IPC; internet not required) |
| Windows edition | Windows 11 22H2 Pro or Enterprise, x64 |

---

## 1. VM Preparation

### 1.1 Start from a known-good snapshot

```
Action: Revert VM to the "CLEAN-PRE-INSTALL" snapshot before every run.
Expected: Desktop is clean, no prior ShadowStrike installation present.
```

Verify no prior installation exists:

```powershell
# In the VM — run as Administrator
Get-Service ShadowStrikePhantomService -ErrorAction SilentlyContinue
# Expected output: nothing (service does not exist)

Get-ChildItem "C:\Program Files\ShadowStrike" -ErrorAction SilentlyContinue
# Expected output: nothing
```

**PASS criterion:** Both commands return no output.  
**FAIL criterion:** Either command returns data — revert snapshot and try again.

---

### 1.2 Disable Defender real-time protection & tamper protection

> Required so Defender does not quarantine the dev-cert binary before installation.

1. Open **Windows Security → Virus & threat protection → Manage settings**.
2. Set **Real-time protection** → **Off**.
3. Set **Tamper Protection** → **Off** (requires slider, not PowerShell).
4. Confirm: notification area shield shows "Action needed".

**PASS criterion:** Both toggles are Off and remain Off after 30 seconds.

---

### 1.3 Trust the dev root certificate

Copy `ShadowStrike-Dev.cer` from the VM shared folder into the VM, then:

```cmd
:: Run as Administrator in cmd.exe
certutil -addstore root "C:\Users\Public\Desktop\ShadowStrike-Dev.cer"
```

**Expected output:**

```
Root "Trusted Root Certification Authorities"
Signature matches Public Key
Certificate "ShadowStrike-Labs Dev Code Signing" added to store.
CertUtil: -addstore command completed successfully.
```

**PASS criterion:** Command exits 0 and the certificate appears in  
`certmgr.msc → Trusted Root Certification Authorities → Certificates`  
as `ShadowStrike-Labs Dev Code Signing`.  
**FAIL criterion:** `ERROR_CANCELLED` or cert not present in store — re-run as Administrator.

---

### 1.4 Copy installers to desktop

From the VM shared folder (`vm_shrd\PhantomHome\`), copy these two files to `C:\Users\Public\Desktop\`:

- `ShadowStrikePhantom-Home-Setup.exe`
- `ShadowStrikePhantom-Home-Setup.msi`

Verify SHA256 hashes match `SHA256SUMS.txt`:

```cmd
certutil -hashfile "C:\Users\Public\Desktop\ShadowStrikePhantom-Home-Setup.exe" SHA256
certutil -hashfile "C:\Users\Public\Desktop\ShadowStrikePhantom-Home-Setup.msi" SHA256
```

**PASS criterion:** Hashes match `SHA256SUMS.txt` exactly.  
**FAIL criterion:** Any hash mismatch — do not proceed; re-copy the files.

---

### 1.5 Take a pre-install snapshot

```
Action: In the hypervisor, take snapshot named "PRE-INSTALL-<YYYYMMDD>-<build_hash>".
```

---

## 2. Installation

### 2.1 Run the bundle

```
Action: Double-click ShadowStrikePhantom-Home-Setup.exe on the desktop.
```

**Expected sequence:**

| Step | What you see | Pass / Fail |
|------|-------------|-------------|
| SmartScreen warning | "Windows protected your PC" dialog appears (expected for dev cert) | Click **More info → Run anyway** |
| UAC prompt | "Do you want to allow this app to make changes?" | Click **Yes** |
| Prerequisite | VC++ 2022 x64 Redistributable installs silently (≈ 5–15 s) | No error dialog |
| ShadowStrike MSI | Progress bar labeled "ShadowStrike PhantomHome" advances to 100 % | No error dialog |
| Finish | Installer exits; no error dialog | — |

**PASS criterion:** Installer exits without an error dialog.  
**FAIL criterion:** Any error dialog, rollback, or MSI error code.  If the installer rolls back, capture the log:

```cmd
msiexec /i "C:\Users\Public\Desktop\ShadowStrikePhantom-Home-Setup.msi" /l*v "%USERPROFILE%\Desktop\install.log" /qb
```

---

### 2.2 Verify service auto-start

Immediately after the installer exits:

```powershell
# Run as Administrator
Get-Service ShadowStrikePhantomService | Select-Object Status, StartType
```

**Expected output:**

```
Status  StartType
------  ---------
Running Automatic
```

**PASS criterion:** Status = `Running`, StartType = `Automatic`.  
**FAIL criterion:** Status is `Stopped` or service does not exist.

---

### 2.3 Verify tray icon

**Expected:** Within 5 seconds of logon (or immediately post-install), the ShadowStrike shield
icon appears in the Windows notification area (system tray, bottom-right).

**PASS criterion:** Icon is visible; hovering it shows a tooltip such as "ShadowStrike –
Protected".  
**FAIL criterion:** Icon absent after 15 seconds. Check:

```powershell
Get-Process ShadowStrikePhantomTray -ErrorAction SilentlyContinue
# Should return one process entry
```

---

### 2.4 Verify install paths

```powershell
Test-Path "C:\Program Files\ShadowStrike\ShadowStrikePhantomService.exe"  # must be True
Test-Path "C:\Program Files\ShadowStrike\ShadowStrikePhantomUI.exe"       # must be True
Test-Path "C:\Program Files\ShadowStrike\ShadowStrikePhantomTray.exe"     # must be True
Test-Path "C:\ProgramData\ShadowStrike"                                    # must be True
```

**PASS criterion:** All four return `True`.

---

## 3. First-Launch UI Checks

### 3.1 Launch the dashboard

```
Action: Open Start Menu → search "ShadowStrike" → click "ShadowStrike Dashboard".
```

**Expected:** Main window opens within 3 seconds. Title bar reads **"ShadowStrike PhantomHome"**.

---

### 3.2 Sidebar navigation

The sidebar on the left must contain exactly these 4 top-level items (icons and labels):

| # | Label | Expected when clicked |
|---|-------|-----------------------|
| 1 | Home / Dashboard | Headline ticker showing device protection status |
| 2 | Scan | Scan page (Idle state, Start Fast Scan button visible) |
| 3 | Modules | Module list with ≥ 40 modules across ≥ 3 categories |
| 4 | Settings | Settings pane with sub-items |

**PASS criterion:** All 4 items present; all 4 open their respective pages without error overlay.  
**FAIL criterion:** Fewer items, blank page, or crash.

---

### 3.3 Home — headline ticker

```
Action: Click "Home" in sidebar.
```

**Expected:** Banner/ticker at the top displays one of:
- "Your device is protected"
- "Protection active"

Text updates within 2 seconds of the page loading; no spinner or "Loading..." persists beyond 5 s.

**PASS criterion:** Non-empty status text displayed.  
**FAIL criterion:** "Unknown", blank, or unhandled exception overlay.

---

### 3.4 Scan page

```
Action: Click "Scan" in sidebar.
```

| Check | Expected | Pass / Fail |
|-------|----------|-------------|
| Initial state label | "Idle" or equivalent | — |
| "Start Fast Scan" button | Visible and enabled | — |
| No scan in progress | Progress bar absent or at 0 % | — |

---

### 3.5 Modules page

```
Action: Click "Modules" in sidebar.
```

**Expected:**
- Module list renders within 3 seconds.
- At least 40 module entries are visible or reachable by scrolling.
- Modules are grouped into named categories (e.g., Behavioral, Network, File System).
- Each module shows: name, status indicator (Enabled/Disabled), toggle control.

**PASS criterion:** ≥ 40 modules present, categories labeled, no render errors.  
**FAIL criterion:** Fewer than 40 modules, missing categories, or error overlay.

---

### 3.6 Settings sub-pages

```
Action: Click "Settings" → cycle through each sub-item.
```

| Sub-page | PASS criterion |
|----------|----------------|
| General / Privacy | Page renders, no error |
| Zero-Trust | Page renders, at least one policy toggle visible |
| Performance | Page renders, at least one slider or threshold visible |

---

## 4. IPC Round-Trips

All actions below communicate from the UI process to the service via named pipe / IPC.
Each must complete without the UI freezing (> 5 s) or showing an error.

---

### 4.1 Pause Protection

```
Action: Click "Pause Protection" in the UI (look for a shield icon with a pause overlay,
         or a "Pause" button on the Home page).
```

**Expected:** Headline ticker updates to "Protection paused" or "Paused" within 2 seconds.  
Tray icon changes to indicate paused state.

```powershell
# Confirm service is still running (pause is a soft state, not a stop)
Get-Service ShadowStrikePhantomService | Select-Object Status
# Expected: Running
```

**PASS criterion:** Ticker shows "paused" state; service still Running.

```
Action: Click "Resume Protection".
Expected: Ticker reverts to "Protected" state within 2 seconds.
```

---

### 4.2 Fast Scan

```
Action: Navigate to Scan page → click "Start Fast Scan".
```

**Expected sequence:**

| Checkpoint | Expected | Acceptable wait |
|-----------|----------|-----------------|
| Scan starts | Progress bar appears and advances | ≤ 3 s |
| Scan runs | Progress bar advances monotonically | — |
| Scan completes | Progress bar reaches 100 %; result summary displayed | ≤ 5 min |
| Result summary | Shows files scanned count (> 0) and threat count | — |

**PASS criterion:** Scan completes with a result summary; no crash or freeze.  
**FAIL criterion:** Progress bar stalls for > 60 s, UI freezes, or unhandled exception.

---

### 4.3 Quarantine list

```
Action: Navigate to Quarantine (may be under Home, Scan result, or a dedicated menu item).
```

**Expected:** Quarantine list page opens; it may be empty (acceptable for a clean VM).  
No error overlay or blank screen.

**PASS criterion:** Page renders with either an empty-state message or a list of items.

---

### 4.4 Reports list

```
Action: Navigate to Reports (may be under Settings or a top-level menu).
```

**Expected:** Reports page opens; at minimum the just-completed Fast Scan report should appear.

**PASS criterion:** At least one report entry visible.  
**FAIL criterion:** Empty page with no explanation, or error overlay.

---

### 4.5 Module toggle persistence

```
Action:
  1. Open Modules page.
  2. Locate any enabled module (e.g., the first one in the list).
  3. Toggle it OFF.
  4. Confirm toggle indicator updates immediately.
  5. Close and relaunch the UI:
       a. File → Exit  (or right-click tray → Exit Dashboard)
       b. Relaunch from Start Menu.
  6. Navigate back to Modules page.
```

**PASS criterion:** The previously toggled module is still shown as **Off** after the UI restarts.  
**FAIL criterion:** Module reverted to Enabled.

---

## 5. Tray Interactions

### 5.1 Right-click tray menu

```
Action: Right-click the ShadowStrike tray icon.
```

**Expected menu items (minimum):**

| Item | Action when clicked |
|------|---------------------|
| Open Dashboard | UI window opens / comes to foreground |
| Pause Protection | Protection state toggles (see §4.1) |
| Exit | Tray process exits; icon disappears |

**PASS criterion:** All three items present and functional.

---

### 5.2 Single-instance enforcement

```
Action: Launch the Dashboard from Start Menu.
         While it is open, launch it again from Start Menu (or double-click the shortcut).
```

**Expected:** The second launch does NOT open a second window.  
Instead, the existing window comes to the foreground (focus steal or flash).

**PASS criterion:** Only one Dashboard window exists; second launch activates the existing window.  
**FAIL criterion:** Two separate Dashboard windows open.

---

## 6. Service Lifecycle

### 6.1 Stop service — UI response

```powershell
# Run as Administrator
sc stop ShadowStrikePhantomService
# Or:
Stop-Service ShadowStrikePhantomService
```

**Expected in UI:** Within 5 seconds, the Dashboard displays a "Service stopped" banner or
disables its controls with a "Cannot connect to service" message.

**PASS criterion:** UI shows the disconnected/stopped state within 5 s.  
**FAIL criterion:** UI remains in "Protected" state after 10 s with service stopped.

---

### 6.2 Start service — UI reconnects

```powershell
sc start ShadowStrikePhantomService
# Or:
Start-Service ShadowStrikePhantomService
```

**Expected:** UI reconnects and resumes showing live status within 5 seconds.

**PASS criterion:** UI transitions back to "Protected" state ≤ 5 s after service starts.  
**FAIL criterion:** UI requires a manual restart to show the connected state.

---

## 7. Uninstall

### 7.1 Uninstall via msiexec

Find the ProductCode from the registry:

```powershell
# Run as Administrator
$pkg = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*ShadowStrike*" }
Write-Host "ProductCode: $($pkg.IdentifyingNumber)"
```

Uninstall:

```cmd
msiexec /x {PRODUCT-CODE-FROM-ABOVE} /qb /l*v "%USERPROFILE%\Desktop\uninstall.log"
```

Replace `{PRODUCT-CODE-FROM-ABOVE}` with the GUID returned by the PowerShell query,
e.g.: `msiexec /x {1A2B3C4D-...} /qb`

---

### 7.2 Verify service removed

```powershell
Get-Service ShadowStrikePhantomService -ErrorAction SilentlyContinue
# Expected: no output (service does not exist)
```

**PASS criterion:** Command returns nothing.

---

### 7.3 Verify binary files removed

```powershell
Test-Path "C:\Program Files\ShadowStrike\ShadowStrikePhantomService.exe"  # must be False
Test-Path "C:\Program Files\ShadowStrike\ShadowStrikePhantomUI.exe"       # must be False
Test-Path "C:\Program Files\ShadowStrike\ShadowStrikePhantomTray.exe"     # must be False
```

**PASS criterion:** All three return `False`.

---

### 7.4 Verify ProgramData quarantine preserved

Per product spec, quarantine data is intentionally NOT removed by the uninstaller.

```powershell
Test-Path "C:\ProgramData\ShadowStrike\Quarantine"
# Expected: True (directory exists, even if empty)
```

**PASS criterion:** Directory exists after uninstall.  
**FAIL criterion:** Directory was removed by uninstaller (data-loss regression).

---

## 8. Reboot Persistence

### 8.1 Reinstall and reboot

If you ran the uninstall check above, reinstall first:

```cmd
ShadowStrikePhantom-Home-Setup.exe /quiet
```

Then reboot the VM:

```powershell
Restart-Computer -Force
```

---

### 8.2 Post-reboot checks

After the VM restarts and the desktop loads (allow up to 60 s for services):

```powershell
# Run in a new Administrator PowerShell
Get-Service ShadowStrikePhantomService | Select-Object Status, StartType
```

**Expected:**

```
Status  StartType
------  ---------
Running Automatic
```

**PASS criterion:** Service auto-started without manual intervention.

```
Action: Observe notification area within 30 seconds of desktop appearance.
Expected: ShadowStrike tray icon appears automatically.
```

**PASS criterion:** Tray icon present within 30 s of logon.  
**FAIL criterion:** Service is Stopped, or tray icon requires manual launch.

---

## Test Result Sheet

Copy this table into your test report and fill in each row.

| # | Test | Build | Environment | Result | Notes |
|---|------|-------|-------------|--------|-------|
| 1.1 | Clean VM state | | Win11 22H2 | PASS / FAIL | |
| 1.2 | Defender disabled | | | PASS / FAIL | |
| 1.3 | Dev cert trusted | | | PASS / FAIL | |
| 1.4 | Hash verification | | | PASS / FAIL | |
| 2.1 | Bundle install | | | PASS / FAIL | |
| 2.2 | Service auto-start | | | PASS / FAIL | |
| 2.3 | Tray icon | | | PASS / FAIL | |
| 2.4 | Install paths | | | PASS / FAIL | |
| 3.2 | Sidebar 4 items | | | PASS / FAIL | |
| 3.3 | Headline ticker | | | PASS / FAIL | |
| 3.4 | Scan page idle | | | PASS / FAIL | |
| 3.5 | Modules ≥ 40 | | | PASS / FAIL | |
| 3.6 | Settings sub-pages | | | PASS / FAIL | |
| 4.1 | Pause / Resume | | | PASS / FAIL | |
| 4.2 | Fast Scan | | | PASS / FAIL | |
| 4.3 | Quarantine list | | | PASS / FAIL | |
| 4.4 | Reports list | | | PASS / FAIL | |
| 4.5 | Module toggle persist | | | PASS / FAIL | |
| 5.1 | Tray menu | | | PASS / FAIL | |
| 5.2 | Single-instance | | | PASS / FAIL | |
| 6.1 | Service stop → UI | | | PASS / FAIL | |
| 6.2 | Service start → reconnect | | | PASS / FAIL | |
| 7.1–7.3 | Uninstall | | | PASS / FAIL | |
| 7.4 | Quarantine preserved | | | PASS / FAIL | |
| 8.1–8.2 | Reboot persistence | | | PASS / FAIL | |

---

## Known Limitations

### Dev-cert SmartScreen warning

Builds signed with `CN=ShadowStrike-Labs Dev Code Signing` (self-signed) will trigger a
**Windows SmartScreen "Windows protected your PC"** warning on every run.  The engineer must
click **More info → Run anyway** to proceed.

This is expected and documented behavior for dev-cert builds.

> **PRODUCTION REQUIREMENT:** Before any external or field distribution, ALL release artifacts
> (`ShadowStrikePhantomService.exe`, `ShadowStrikePhantomUI.exe`, `ShadowStrikePhantomTray.exe`,
> `ShadowStrikePhantom-Home-Setup.msi`, `ShadowStrikePhantom-Home-Setup.exe`) **MUST** be
> re-signed using the real Extended Validation (EV) code-signing certificate.  EV signatures
> satisfy SmartScreen reputation requirements and eliminate this warning.  
> Re-run `packaging\signing\Sign-PhantomHome.ps1` with the production PFX substituted for
> `ShadowStrike-Dev.pfx`.

### No kernel driver in PhantomHome edition

The PhantomHome build does not load a kernel minifilter driver; protection is usermode-only.
Kernel-mode hooks are present only in the PhantomEnterprise SKU.  Do not attempt to verify
KMCS (kernel-mode code signing) behavior against this build.

### VC++ Redistributable version dependency

The bundle installs **VC++ 2022 x64 Redistributable (14.x)**.  If a newer minor version is
already installed the bundle skips the prereq silently (expected).  If a conflicting older
locked version is installed the prereq may fail — note the installer log for triage.
