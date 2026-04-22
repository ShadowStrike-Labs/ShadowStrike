#pragma once
/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Resource IDs for system-tray icons.
 *
 * The matching .ico files are produced by the packaging pipeline from the
 * brand logo and embedded via the tray's .rc file (tray.rc).
 * This header is included by both C++ translation units and the RC compiler.
 *
 * TODO(packaging): Generate tray.rc and the five .ico files as part of the
 *                  brand-asset packaging step before release builds.
 */

#define IDI_TRAY_HEALTHY   101
#define IDI_TRAY_ATRISK    102
#define IDI_TRAY_CRITICAL  103
#define IDI_TRAY_PAUSED    104
#define IDI_TRAY_OFFLINE   105
