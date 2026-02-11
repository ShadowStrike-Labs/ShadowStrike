/**
 * ============================================================================
 * ShadowStrike NGAV - WPP TRACING RUNTIME CONFIGURATION
 * ============================================================================
 *
 * @file WppConfig.h
 * @brief Runtime configuration types, constants, and API for WPP tracing.
 *
 * This header provides:
 * - Trace level and flag constants
 * - Runtime configuration structures (WPP_TRACE_CONFIG, WPP_TRACE_CONTEXT)
 * - Component identifiers
 * - Initialization / shutdown API
 * - Runtime configuration API (levels, flags, rate limiting)
 * - Correlation ID and trace context API
 * - Statistics API
 * - Convenience macros for common trace patterns
 *
 * WPP preprocessor directives (control GUIDs, WPP_DEFINE_BIT,
 * FUNC definitions, CUSTOM_TYPE) belong in Trace.h — not here.
 *
 * Implementation is in Trace.c (sole implementation file).
 *
 * @author ShadowStrike Security Team
 * @version 2.1.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma once

#ifndef _SHADOWSTRIKE_WPP_CONFIG_H_
#define _SHADOWSTRIKE_WPP_CONFIG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

// ============================================================================
// TRACE LEVELS — Extended beyond standard WPP levels
// ============================================================================

#ifndef TRACE_LEVEL_NONE
#define TRACE_LEVEL_NONE        0   ///< Tracing disabled
#endif
#ifndef TRACE_LEVEL_CRITICAL
#define TRACE_LEVEL_CRITICAL    1   ///< Critical errors causing shutdown
#endif
#ifndef TRACE_LEVEL_ERROR
#define TRACE_LEVEL_ERROR       2   ///< Errors requiring attention
#endif
#ifndef TRACE_LEVEL_WARNING
#define TRACE_LEVEL_WARNING     3   ///< Warnings
#endif
#ifndef TRACE_LEVEL_INFORMATION
#define TRACE_LEVEL_INFORMATION 4   ///< General informational messages
#endif
#ifndef TRACE_LEVEL_VERBOSE
#define TRACE_LEVEL_VERBOSE     5   ///< Detailed diagnostic information
#endif

/// Extended levels (6–10) for security/EDR use.
#define TRACE_LEVEL_SECURITY    6   ///< Security-relevant events
#define TRACE_LEVEL_AUDIT       7   ///< Audit trail events
#define TRACE_LEVEL_DEBUG       8   ///< Debug-only messages
#define TRACE_LEVEL_PERF        9   ///< Performance measurements
#define TRACE_LEVEL_RESERVED    10  ///< Maximum valid level

// ============================================================================
// TRACE FLAGS — Component-specific filtering
// ============================================================================

/// Core component flags (bits 0–8 match Trace.h WPP_DEFINE_BIT order).
#define TRACE_FLAG_GENERAL      0x00000001
#define TRACE_FLAG_FILTER       0x00000002
#define TRACE_FLAG_SCAN         0x00000004
#define TRACE_FLAG_COMM         0x00000008
#define TRACE_FLAG_PROCESS      0x00000010
#define TRACE_FLAG_REGISTRY     0x00000020
#define TRACE_FLAG_NETWORK      0x00000040
#define TRACE_FLAG_SELFPROT     0x00000080
#define TRACE_FLAG_CACHE        0x00000100

/// Extended flags (bits 9–19).
#define TRACE_FLAG_MEMORY       0x00000200
#define TRACE_FLAG_THREAD       0x00000400
#define TRACE_FLAG_IMAGE        0x00000800
#define TRACE_FLAG_BEHAVIOR     0x00001000
#define TRACE_FLAG_ETW          0x00002000
#define TRACE_FLAG_CRYPTO       0x00004000
#define TRACE_FLAG_SYNC         0x00008000
#define TRACE_FLAG_PERF         0x00010000
#define TRACE_FLAG_INIT         0x00020000
#define TRACE_FLAG_IOCTL        0x00040000
#define TRACE_FLAG_THREAT       0x00080000

/// Composite masks.
#define TRACE_FLAG_ALL          0xFFFFFFFF
#define TRACE_FLAG_SECURITY_ALL (TRACE_FLAG_SELFPROT | TRACE_FLAG_BEHAVIOR | TRACE_FLAG_THREAT)
#define TRACE_FLAG_MONITOR_ALL  (TRACE_FLAG_PROCESS | TRACE_FLAG_REGISTRY | TRACE_FLAG_NETWORK | \
                                 TRACE_FLAG_THREAD | TRACE_FLAG_IMAGE)

// ============================================================================
// POOL TAGS
// ============================================================================

#define WPP_POOL_TAG_TRACE      'rTsS'  ///< SsTr — Trace buffer
#define WPP_POOL_TAG_FORMAT     'fTsS'  ///< SsTf — Format string
#define WPP_POOL_TAG_CONTEXT    'cTsS'  ///< SsTc — Trace context

// ============================================================================
// RUNTIME CONFIGURATION STRUCTURES
// ============================================================================

/**
 * @brief Runtime trace configuration.
 *
 * All volatile fields are updated via InterlockedXxx.
 * Non-volatile scalar fields (MinimumLevel, MaximumLevel, BOOLEAN enables)
 * are naturally atomic on x86/x64 for aligned reads/writes; concurrent
 * updates use InterlockedOr/InterlockedAnd for flag bitmasks.
 */
typedef struct _WPP_TRACE_CONFIG {
    BOOLEAN TracingEnabled;
    BOOLEAN DebugTracingEnabled;
    BOOLEAN PerfTracingEnabled;
    BOOLEAN SecurityTracingEnabled;

    UCHAR   MinimumLevel;
    UCHAR   MaximumLevel;
    UCHAR   Reserved[2];

    ULONG   EnabledFlags;           ///< Updated via InterlockedOr/And
    ULONG   DisabledFlags;          ///< Updated via InterlockedOr/And

    ULONG   MaxTracesPerSecond;     ///< 0 = unlimited
    volatile LONG CurrentSecondTraces;
    volatile LONG64 CurrentSecondStart; ///< In 100ns units (atomically swapped)

    volatile LONG64 TotalTraces;
    volatile LONG64 DroppedTraces;
    volatile LONG64 ErrorCount;

    GUID    SessionGuid;
    volatile LONG64 SequenceNumber;
} WPP_TRACE_CONFIG, *PWPP_TRACE_CONFIG;

/**
 * @brief Trace context for structured logging.
 *
 * Stack-allocated by the caller; filled by WppCreateTraceContext,
 * completed by WppCompleteTraceContext.
 */
typedef struct _WPP_TRACE_CONTEXT {
    UINT64 CorrelationId;
    UINT64 ParentCorrelationId;

    UINT32 ProcessId;
    UINT32 ThreadId;

    UINT32 ComponentId;
    UINT32 SubComponentId;

    UINT64 StartTimestamp;          ///< 100ns system time
    UINT64 EndTimestamp;            ///< 100ns system time (0 until completed)

    PVOID  CustomData;
    ULONG  CustomDataSize;
} WPP_TRACE_CONTEXT, *PWPP_TRACE_CONTEXT;

/**
 * @brief Component identifiers for tracing.
 *
 * Array index into the component name table returned by WppGetComponentName.
 */
typedef enum _WPP_COMPONENT_ID {
    WppComponent_Unknown = 0,
    WppComponent_Core,
    WppComponent_Filter,
    WppComponent_Scan,
    WppComponent_Communication,
    WppComponent_Process,
    WppComponent_Registry,
    WppComponent_Network,
    WppComponent_SelfProtection,
    WppComponent_Cache,
    WppComponent_Memory,
    WppComponent_Thread,
    WppComponent_Image,
    WppComponent_Behavior,
    WppComponent_ETW,
    WppComponent_Crypto,
    WppComponent_Sync,
    WppComponent_Max
} WPP_COMPONENT_ID;

// ============================================================================
// LEVEL NAME COUNT — compile-time sync guard
// ============================================================================

#define WPP_LEVEL_NAME_COUNT    10  ///< Must match LevelNames[] in Trace.c

// ============================================================================
// INITIALIZATION / SHUTDOWN API
// ============================================================================

/**
 * @brief Initialize WPP tracing subsystem.
 *
 * Calls WPP_INIT_TRACING internally. Must be called during DriverEntry
 * before any trace macros are invoked.
 *
 * NOTE: Placed in INIT section — do NOT call after DriverEntry returns.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WppTraceInitialize(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

/**
 * @brief Shutdown WPP tracing subsystem.
 *
 * Calls WPP_CLEANUP internally. Must be called during DriverUnload.
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
WppTraceShutdown(
    _In_ PDRIVER_OBJECT DriverObject
    );

/**
 * @brief Check if tracing is initialized and enabled.
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WppTraceIsEnabled(
    VOID
    );

// ============================================================================
// RUNTIME CONFIGURATION API
// ============================================================================

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WppSetMinimumLevel(
    _In_ UCHAR Level
    );

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
UCHAR
WppGetMinimumLevel(
    VOID
    );

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WppSetTraceFlags(
    _In_ ULONG Flags,
    _In_ BOOLEAN Enable
    );

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
WppGetTraceFlags(
    VOID
    );

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WppSetRateLimit(
    _In_ ULONG MaxTracesPerSecond
    );

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WppSetDebugTracing(
    _In_ BOOLEAN Enable
    );

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WppSetPerfTracing(
    _In_ BOOLEAN Enable
    );

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WppSetSecurityTracing(
    _In_ BOOLEAN Enable
    );

// ============================================================================
// CORRELATION API
// ============================================================================

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
UINT64
WppGenerateCorrelationId(
    VOID
    );

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
WppCreateTraceContext(
    _Out_ PWPP_TRACE_CONTEXT Context,
    _In_ WPP_COMPONENT_ID ComponentId,
    _In_ UINT64 ParentCorrelationId
    );

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WppCompleteTraceContext(
    _Inout_ PWPP_TRACE_CONTEXT Context
    );

// ============================================================================
// STATISTICS API
// ============================================================================

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
WppGetStatistics(
    _Out_opt_ PUINT64 TotalTraces,
    _Out_opt_ PUINT64 DroppedTraces,
    _Out_opt_ PUINT64 ErrorCount
    );

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WppResetStatistics(
    VOID
    );

// ============================================================================
// EXTENDED API (previously in WppConfig.c, now in Trace.c)
// ============================================================================

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
WppGetConfiguration(
    _Out_ PWPP_TRACE_CONFIG Config
    );

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
UINT64
WppGetElapsedMicroseconds(
    _In_ PWPP_TRACE_CONTEXT Context
    );

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
WppFormatCorrelationId(
    _In_ UINT64 CorrelationId,
    _Out_writes_(BufferSize) PWCHAR Buffer,
    _In_ SIZE_T BufferSize
    );

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WppShouldTrace(
    _In_ UCHAR Level,
    _In_ ULONG Flags
    );

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WppRecordError(
    VOID
    );

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WppRecordTrace(
    VOID
    );

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
UINT64
WppGetSequenceNumber(
    VOID
    );

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
WppGetSessionGuid(
    _Out_ PGUID SessionGuid
    );

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WppIsDebugTracingEnabled(
    VOID
    );

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WppIsPerfTracingEnabled(
    VOID
    );

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
WppIsSecurityTracingEnabled(
    VOID
    );

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WppDumpConfiguration(
    VOID
    );

// ============================================================================
// FORMATTING HELPERS
// ============================================================================

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
WppFormatStatus(
    _In_ NTSTATUS Status,
    _Out_writes_(BufferSize) PCHAR Buffer,
    _In_ ULONG BufferSize
    );

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
WppFormatGuid(
    _In_ PGUID Guid,
    _Out_writes_(BufferSize) PCHAR Buffer,
    _In_ ULONG BufferSize
    );

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
WppFormatHexDump(
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_writes_(BufferSize) PCHAR Buffer,
    _In_ ULONG BufferSize
    );

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
WppFormatTimestamp(
    _In_ UINT64 Timestamp,
    _Out_writes_(BufferSize) PCHAR Buffer,
    _In_ ULONG BufferSize
    );

// ============================================================================
// NAME LOOKUP (regular functions — avoid inline static array duplication)
// ============================================================================

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
PCSTR
WppGetComponentName(
    _In_ WPP_COMPONENT_ID ComponentId
    );

/** @irql <= DISPATCH_LEVEL */
_IRQL_requires_max_(DISPATCH_LEVEL)
PCSTR
WppGetLevelName(
    _In_ UCHAR Level
    );

// ============================================================================
// CONVENIENCE MACROS
// ============================================================================

/** Trace function entry. */
#define WPP_TRACE_ENTRY(flags) \
    do { TraceEnter(flags, "-->"); } while (0)

/** Trace function exit. */
#define WPP_TRACE_EXIT(flags) \
    do { TraceExit(flags, "<--"); } while (0)

/** Trace function exit with NTSTATUS. */
#define WPP_TRACE_EXIT_STATUS(flags, status) \
    do { TraceExit(flags, "<-- Status=%!STATUS!", status); } while (0)

/** Trace NTSTATUS error if not success. */
#define WPP_TRACE_STATUS(flags, status) \
    do { \
        if (!NT_SUCCESS(status)) { \
            TraceError(flags, "Status=%!STATUS!", status); \
        } \
    } while (0)

/** Trace with correlation ID. */
#define WPP_TRACE_CORRELATED(level, flags, correlationId, msg, ...) \
    do { \
        TraceEvents(level, flags, "[CID:%I64u] " msg, correlationId, __VA_ARGS__); \
    } while (0)

/** Trace security event. */
#define WPP_TRACE_SECURITY_EVENT(flags, eventType, processId, msg, ...) \
    do { \
        TraceSecurity(flags, "[%s] PID:%u " msg, eventType, processId, __VA_ARGS__); \
    } while (0)

/**
 * @brief Performance measurement macros.
 *
 * Usage:
 *   LARGE_INTEGER perfStart;
 *   WPP_TRACE_PERF_START(&perfStart);
 *   ... work ...
 *   WPP_TRACE_PERF_END(TRACE_FLAG_PERF, &perfStart, "MyOperation");
 *
 * The context parameter must point to a LARGE_INTEGER (not WPP_TRACE_CONTEXT).
 */
#define WPP_TRACE_PERF_START(pLargeInt) \
    do { *(pLargeInt) = KeQueryPerformanceCounter(NULL); } while (0)

#define WPP_TRACE_PERF_END(flags, pLargeInt, operation) \
    do { \
        LARGE_INTEGER _wppEndTime, _wppFreq; \
        UINT64 _wppElapsedUs; \
        _wppEndTime = KeQueryPerformanceCounter(&_wppFreq); \
        _wppElapsedUs = (((UINT64)(_wppEndTime.QuadPart - (pLargeInt)->QuadPart)) * 1000000) \
                        / (UINT64)_wppFreq.QuadPart; \
        TracePerf(flags, "%s completed in %I64u us", operation, _wppElapsedUs); \
    } while (0)

/** Conditional trace based on runtime config. */
#define WPP_TRACE_IF_ENABLED(level, flags, msg, ...) \
    do { \
        if (WppShouldTrace((UCHAR)(level), (flags))) { \
            TraceEvents(level, flags, msg, __VA_ARGS__); \
        } \
    } while (0)

// ============================================================================
// DEBUG BUILD ONLY MACROS
// ============================================================================

#if DBG

#define WPP_TRACE_DEBUG(flags, msg, ...) \
    TraceVerbose(flags, "[DEBUG] " msg, __VA_ARGS__)

#define WPP_ASSERT_TRACE(condition, flags, msg, ...) \
    do { \
        if (!(condition)) { \
            TraceFatal(flags, "ASSERTION FAILED: " #condition " - " msg, __VA_ARGS__); \
            NT_ASSERT(condition); \
        } \
    } while (0)

#else

#define WPP_TRACE_DEBUG(flags, msg, ...)            ((void)0)
#define WPP_ASSERT_TRACE(condition, flags, msg, ...) ((void)0)

#endif /* DBG */

#ifdef __cplusplus
}
#endif

#endif /* _SHADOWSTRIKE_WPP_CONFIG_H_ */
