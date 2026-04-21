================================================================================
ShadowStrike Phantom Home - VM test procedure
================================================================================

The scripts below all use the same scheme to survive VMware/VirtualBox shared
folders:

  1. On first invocation they copy themselves (and for 02, the full payload
     tree) to  %LOCALAPPDATA%\ShadowStrike-Install
  2. They re-launch a fresh cmd window from that LOCAL path.
  3. The local copy self-elevates via UAC. Elevation works correctly when the
     script lives on C:\, which is NOT the case for Z:\vm_shrd\ inside the VM.

So you can double-click them from the shared folder - the first run stages,
the second window is the real one you interact with.

--------------------------------------------------------------------------------
ONE-TIME VM PREP (in this order)
--------------------------------------------------------------------------------
[A] Windows Security -> Virus & threat protection -> Manage settings:
       Tamper Protection:        OFF
       Real-time protection:     OFF
       Cloud-delivered prot.:    OFF
       Automatic sample submit:  OFF
    (Microsoft blocks programmatic disable while Tamper Protection is ON.)

[B] Double-click  01_prepare_vm.bat     -> enables TESTSIGNING -> REBOOT VM.
    After reboot the desktop shows "Test Mode" in the bottom-right corner.

[C] Double-click  00_disable_defender.bat  -> registry + SCM teardown -> REBOOT.

--------------------------------------------------------------------------------
INSTALL / UNINSTALL / DIAGNOSE (any order, repeatable)
--------------------------------------------------------------------------------
  02_install.bat               Install service + tray + driver.
  03_uninstall.bat             Full teardown.
  04_collect_diagnostics.bat   Dumps state to
                               %LOCALAPPDATA%\ShadowStrike-Install\diagnostics\

--------------------------------------------------------------------------------
What gets installed
--------------------------------------------------------------------------------
  %ProgramFiles%\ShadowStrike\Phantom\
        ShadowStrikePhantomService.exe   Service (LocalSystem, auto-start)
        ShadowStrikePhantomTray.exe      Tray icon (per-session autostart)
        ShadowStrikePhantomUI.exe        Dashboard
        assets\ShadowStrike_Logo.png     Brand icon
        Qt6*.dll, qml\, platforms\, ... (Qt runtime for the UI)
        Drivers\PhantomSensor.sys|inf|cat|cer   Minifilter driver

  Windows service :  ShadowStrikePhantomService
  Minifilter      :  ShadowStrikePhantomSensor
  Autostart       :  HKLM\...\Run\ShadowStrikePhantomTray
  Shortcut        :  Start Menu -> ShadowStrike Phantom

--------------------------------------------------------------------------------
Troubleshooting
--------------------------------------------------------------------------------
* Tray icon says "service offline":
     sc query ShadowStrikePhantomService
  If the service is STOPPED, check  %OUT%\events_application.txt from the
  diagnostics bundle. Common cause: driver refused to load -> TESTSIGNING off
  -> re-run 01_prepare_vm.bat and reboot.

* 02_install.bat window flashes and closes:
     Means the STAGE copy was never created. Check that
     %LOCALAPPDATA%\ShadowStrike-Install exists and contains payload\app\.
     Run the script from an interactive cmd.exe window to see the error:
        cmd /k "Z:\vm_shrd\02_install.bat"

* "The system cannot find the drive specified." :
     VMware/VirtualBox shared-folder drive letter is not inherited by UAC.
     Solved by our staging step. If you still see it, your stage dir is
     pointing at Z: for some reason - check %LOCALAPPDATA% in the new window.
