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
