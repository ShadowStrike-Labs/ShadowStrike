# PhantomHome Tray

This directory owns the `ShadowStrikePhantomTray.exe` entry point.

## Design

The tray is an **IPC-only client**. It does not link, load, initialize, or
otherwise duplicate any part of the PhantomCore scan engine, real-time
protection, AI models, or signature database. All protection logic lives
inside `ShadowStrikePhantomService.exe` (LocalSystem) and is reached
exclusively over the authenticated named pipe.

Rationale:

1. The tray runs as the interactive user at medium integrity. Loading the
   engine there would put the scan pipeline, signature database, and AI
   models inside a process the user can freely debug, dump, and patch.
2. It would also duplicate hundreds of MB of runtime state per logged-on
   user and race the LocalSystem service for on-disk resources
   (signature DB, quarantine, telemetry).
3. Keeping the tray thin also makes it trivially cheap to restart - e.g.
   after an explorer.exe crash - because there is no engine startup cost.

## Surface

`TrayMain.cpp` owns:

- Per-session single-instance gate via `Local\ShadowStrike.PhantomHome.Tray.SingleInstance`.
- A hidden message-only window that receives `Shell_NotifyIconW` callbacks.
- Tray icon install/modify/remove and TaskbarCreated re-registration.
- `PipeClient` with `Start()` / state + push callbacks; all callbacks
  marshal onto the GUI thread via `PostMessageW` so no Shell / GDI API is
  ever called off-thread.
- Polling `GetState` every 5s and reacting to `EventStateChanged` push
  frames for instant updates.
- Context menu dispatch: Open Dashboard, Quick Scan, Full Scan, Pause
  15 min / 1 hour, Resume, Exit.
- Launching the dashboard via the **sibling** `ShadowStrikePhantomUI.exe`
  (absolute path derived from `GetModuleFileNameW`) so `PATH` hijacking
  cannot redirect us to an attacker binary.

## Build

Compiled by `ShadowStrikePhantomTray.vcxproj` at the repository root.
`/t:ClCompile Configuration=Debug Platform=x64` is clean; the full link
stage is blocked on the pending PhantomCore / Utils static library
carve-out, same as `ShadowStrikePhantomService.vcxproj` and
`ShadowStrikePhantomUI.vcxproj`.

## What lives elsewhere

`../SystemTray.hpp` / `../SystemTray.cpp` are retained as a legacy
in-process tray facade that other modules may still reference. The real
tray executable is this TU; any future UI should build on `TrayMain.cpp`.
