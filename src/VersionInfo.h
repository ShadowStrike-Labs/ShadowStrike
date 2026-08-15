/*
 * VersionInfo.h - the single place the shipped product version is written down.
 *
 * WHY THIS FILE EXISTS
 *
 * Before it, the version lived in three unrelated places and agreed with none of
 * them: tools/vm-harness/Invoke-PhantomDeploy.ps1 said 1.0.91, the only resource
 * script in the tree (the UI's app.rc) said 1.0.0.0, and the WiX sources carry
 * their own -d ProductVersion. Five of the six shipped native binaries carried no
 * version resource at all, so Explorer, Task Manager, Add/Remove Programs, crash
 * reports and any support conversation had nothing to go on.
 *
 * Duplicating the number into five new resource scripts would have made six
 * places to update and guaranteed drift. This codebase has already paid for that
 * exact mistake once: DRIVER_SERVICE_NAME was written out by hand in four modules
 * and none of them matched the name the SCM actually registers, which silently
 * disabled driver-presence detection, driver recovery, and registry protection for
 * the driver's own service key. One definition, included everywhere, is the fix
 * for that class of defect rather than for one instance of it.
 *
 * HOW TO BUMP THE VERSION
 *
 * Change the four numbers below and nothing else. Invoke-PhantomDeploy.ps1 reads
 * them out of this header, so the MSI, the bootstrapper and every binary follow
 * automatically. The deploy script fails loudly if it cannot parse them rather
 * than falling back to a literal, because a silent fallback is how the previous
 * mismatch survived.
 *
 * DELIBERATELY NOT UNIFIED: PhantomSensor/Shared/SharedDefs.h defines
 * SHADOWSTRIKE_VERSION_MAJOR/MINOR/BUILD as 3.0.0. That is NOT this version - it
 * is reported to user mode as the driver's own version in the driver-status
 * message (CommPort.c:3089, MessageHandler.c:1749) and logged at DriverEntry, so
 * it is part of a kernel/user contract. Renumbering it to match the product would
 * change a value that crosses the kernel boundary, and nothing in this change has
 * established what user mode does with it. Left alone on purpose.
 */

#ifndef SHADOWSTRIKE_VERSIONINFO_H
#define SHADOWSTRIKE_VERSIONINFO_H

// ---------------------------------------------------------------------------
// THE VERSION. Change these four numbers and nothing else.
// ---------------------------------------------------------------------------
#define SS_VERSION_MAJOR      1
#define SS_VERSION_MINOR      0
#define SS_VERSION_PATCH      94
#define SS_VERSION_BUILD      0

// String form, built from the numbers above so the two cannot disagree.
// The extra indirection is required: the preprocessor stringises the macro NAME
// rather than its expansion unless it goes through a second macro.
#define SS_STRINGISE_(x)      #x
#define SS_STRINGISE(x)       SS_STRINGISE_(x)

#define SS_VERSION_STRING     SS_STRINGISE(SS_VERSION_MAJOR) "." \
                              SS_STRINGISE(SS_VERSION_MINOR) "." \
                              SS_STRINGISE(SS_VERSION_PATCH) "." \
                              SS_STRINGISE(SS_VERSION_BUILD)

// ---------------------------------------------------------------------------
// Fields that are identical on every binary.
//
// LegalCopyright and CompanyName are not decoration: an unsigned binary with no
// publisher information is treated as more suspicious by other security products
// and by SmartScreen, and this product ships a kernel driver, so looking like
// anonymous software is a practical problem rather than a cosmetic one.
// ---------------------------------------------------------------------------
#define SS_COMPANY_NAME       "ShadowStrike-Labs"
#define SS_PRODUCT_NAME       "ShadowStrike Phantom"
#define SS_LEGAL_COPYRIGHT    "Copyright (C) 2026 ShadowStrike-Labs"

// AGPL-3.0 is the licence the whole tree ships under, and stating it in the
// binary means a user inspecting a file on their machine can find that out
// without the repository.
#define SS_LEGAL_TRADEMARKS   "Licensed under AGPL-3.0"

#endif // SHADOWSTRIKE_VERSIONINFO_H
