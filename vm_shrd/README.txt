================================================================================
ShadowStrike Phantom Home - VM test procedure
================================================================================

All scripts below copy themselves (and, for 02, the full payload) to
%LOCALAPPDATA%\ShadowStrike-Install and re-launch from there, then self-elevate
via UAC. This is the only reliable way to run admin scripts out of a VMware /
VirtualBox shared folder on Z:\, because UAC does not inherit the mapped drive.

Double-click from Z:\vm_shrd\ - the first window stages, the second is the real
console you interact with.

--------------------------------------------------------------------------------
ONE-TIME VM PREP (in this order)
--------------------------------------------------------------------------------
[A] Windows Security -> Virus & threat protection -> Manage settings:
       Tamper Protection:        OFF
       Real-time protection:     OFF
       Cloud-delivered prot.:    OFF
       Automatic sample submit:  OFF
    (Microsoft blocks programmatic disable while Tamper Protection is ON.)

[B] Double-click  00_disable_defender.bat
    Registers install-path exclusions (critical - this is why the service
    EXE kept being quarantined in earlier attempts), sets all group-policy
    keys, disables Defender services, kills live Defender processes.
    -> REBOOT VM.

[C] Double-click  01_prepare_vm.bat
    Relaxes UAC prompt level and reports current boot flags. User-mode
    only; does NOT touch test-signing.

--------------------------------------------------------------------------------
DISPLAY / RESOLUTION ISSUES
--------------------------------------------------------------------------------
If your VM screen is stuck at 1024x768 and Settings -> Display will not let
you change it, the cause is kernel test-signing being ON - Windows 11 falls
back to the Microsoft Basic Display adapter in that state. Fix:

    00a_fix_resolution.bat   -> turns test-signing OFF -> REBOOT.

--------------------------------------------------------------------------------
INSTALL / UNINSTALL / DIAGNOSE (repeatable)
--------------------------------------------------------------------------------
  02_install.bat               Install service + tray + UI.
  03_uninstall.bat             Full teardown (force-kills stuck service).
  04_collect_diagnostics.bat   Dumps state to Z:\vm_shrd\diagnostics\.

--------------------------------------------------------------------------------
OPTIONAL - kernel minifilter driver
--------------------------------------------------------------------------------
The PhantomSensor minifilter is OFF by default in Home installs. The
user-mode product is fully functional without it. Loading the unsigned
test build requires kernel test-signing, which on Windows 11 locks the
display into generic 1024x768 mode.

If you specifically want to test the kernel sensor:
  1) Take a VM snapshot (you may need to roll back).
  2) Run  05_enable_driver_dev.bat   -> enables test-signing -> REBOOT.
  3) Run  02_install.bat              -> installer will now load the driver.
  4) When done, run  00a_fix_resolution.bat to restore the real display.

--------------------------------------------------------------------------------
What gets installed
--------------------------------------------------------------------------------
  %ProgramFiles%\ShadowStrike\Phantom\
        ShadowStrikePhantomService.exe   Service (LocalSystem, auto-start)
        ShadowStrikePhantomTray.exe      Tray icon (per-session autostart)
        ShadowStrikePhantomUI.exe        Dashboard
        assets\ShadowStrike_Logo.png     Brand icon
        Qt6*.dll, qml\, platforms\, ... (Qt runtime for the UI)
        Drivers\PhantomSensor.{sys,inf,cat,cer}   (loaded only in dev mode)

  Windows service :  ShadowStrikePhantomService
  Autostart       :  HKLM\...\Run\ShadowStrikePhantomTray
  Shortcut        :  Start Menu -> ShadowStrike Phantom

--------------------------------------------------------------------------------
Troubleshooting
--------------------------------------------------------------------------------
* Tray says "service offline" / Open Dashboard does nothing:
     sc queryex ShadowStrikePhantomService
  - STATE=RUNNING: tray should now connect within 1-2s.
  - STATE=START_PENDING CHECKPOINT=1: service is wedged in Initialize().
       Run 03_uninstall.bat (it will force-kill the stuck process), then
       reboot and re-run 02_install.bat.

* Defender quarantines files mid-install ("robocopy errors"):
     Tamper Protection is still ON, or 00_disable_defender.bat was not run.
     Fix the order: Tamper Protection OFF in UI -> 00_disable_defender.bat
     -> reboot -> 02_install.bat.

* Screen stuck at 1024x768 after running the scripts:
     Kernel test-signing is ON. Run 00a_fix_resolution.bat and reboot.

* 02_install.bat flashes and closes / "system cannot find the drive":
     VMware shared-folder drive letter is not inherited by UAC. Our
     staging step handles this; if it still happens, wipe
     %LOCALAPPDATA%\ShadowStrike-Install and try again.
