/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * ============================================================================
 * ShadowStrike NGAV - WPP TRACING
 * ============================================================================
 *
 * @file Trace.h
 * @brief WPP tracing definitions and GUIDs.
 *
 * Defines the control GUID and tracing flags for Windows Software Trace
 * Preprocessor (WPP).
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma once

//
// Define the tracing flags
//
// Tracing GUID: {D7A3F6C2-9E4B-4D1A-8F3E-2B1C0D9E8F7A}
//

#define WPP_CONTROL_GUIDS \
    WPP_DEFINE_CONTROL_GUID( \
        ShadowStrikeTraceGuid, \
        (D7A3F6C2,9E4B,4D1A,8F3E,2B1C0D9E8F7A), \
        WPP_DEFINE_BIT(TRACE_FLAG_GENERAL)      /* 0x00000001 */ \
        WPP_DEFINE_BIT(TRACE_FLAG_FILTER)       /* 0x00000002 */ \
        WPP_DEFINE_BIT(TRACE_FLAG_SCAN)         /* 0x00000004 */ \
        WPP_DEFINE_BIT(TRACE_FLAG_COMM)         /* 0x00000008 */ \
        WPP_DEFINE_BIT(TRACE_FLAG_PROCESS)      /* 0x00000010 */ \
        WPP_DEFINE_BIT(TRACE_FLAG_REGISTRY)     /* 0x00000020 */ \
        WPP_DEFINE_BIT(TRACE_FLAG_NETWORK)      /* 0x00000040 */ \
        WPP_DEFINE_BIT(TRACE_FLAG_SELFPROT)     /* 0x00000080 */ \
        WPP_DEFINE_BIT(TRACE_FLAG_CACHE)        /* 0x00000100 */ \
    )

#define WPP_LEVEL_FLAGS_LOGGER(level,flags) \
    WPP_LEVEL_LOGGER(flags)

#define WPP_LEVEL_FLAGS_ENABLED(level, flags) \
    (WPP_LEVEL_ENABLED(flags) && WPP_CONTROL(WPP_BIT_ ## flags).Level >= level)

//
// Configuration to print function name
//
// FUNC TraceEvents(LEVEL, FLAGS, MSG, ...);
//
// USAGE:
// TraceEvents(TRACE_LEVEL_ERROR, TRACE_FLAG_GENERAL, "Error: %!STATUS!", status);
//
