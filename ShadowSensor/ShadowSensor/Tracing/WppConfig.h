/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE WPP TRACING CONFIGURATION
 * ============================================================================
 *
 * @file WppConfig.h
 * @brief Enterprise-grade WPP (Windows Software Trace Preprocessor) configuration.
 *
 * Provides CrowdStrike Falcon-level tracing infrastructure with:
 * - Custom WPP type definitions for security-specific data types
 * - Extended trace levels for granular logging control
 * - Custom trace formatters for IP addresses, GUIDs, hashes, etc.
 * - Conditional compilation for debug/release builds
 * - Performance-optimized trace macros
 * - IRQL-safe tracing primitives
 * - Structured logging with correlation IDs
 * - Runtime trace level management
 *
 * WPP Integration:
 * - Control GUID: {D7A3F6C2-9E4B-4D1A-8F3E-2B1C0D9E8F7A}
 * - Use tracelog.exe or traceview.exe to capture traces
 * - PDB files required for trace message formatting
 *
 * MITRE ATT&CK Coverage:
 * - T1070: Indicator Removal (audit trail for forensics)
 * - T1562: Impair Defenses (tamper detection logging)
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma once

#ifndef _SHADOWSTRIKE_WPP_CONFIG_H_
#define _SHADOWSTRIKE_WPP_CONFIG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <evntrace.h>

// ============================================================================
// WPP CONTROL AND COMPATIBILITY
// ============================================================================

/**
 * @brief Enable WPP compatibility mode for mixed environments
 */
#ifndef WPP_COMPATIBILITY_MODE
#define WPP_COMPATIBILITY_MODE
#endif

/**
 * @brief Check for NULL strings in trace arguments
 */
#define WPP_CHECK_FOR_NULL_STRING

/**
 * @brief Enable kernel mode WPP
 */
#define WPP_KERNEL_MODE

// ============================================================================
// TRACE LEVELS - Extended beyond standard WPP levels
// ============================================================================

/**
 * @brief Standard WPP trace levels
 */
#define TRACE_LEVEL_NONE        0   // Tracing disabled
#define TRACE_LEVEL_CRITICAL    1   // Critical errors causing shutdown
#define TRACE_LEVEL_ERROR       2   // Errors requiring attention
#define TRACE_LEVEL_WARNING     3   // Warnings that may indicate problems
#define TRACE_LEVEL_INFORMATION 4   // General informational messages
#define TRACE_LEVEL_VERBOSE     5   // Detailed diagnostic information

/**
 * @brief Extended trace levels for security operations
 */
#define TRACE_LEVEL_SECURITY    6   // Security-relevant events
#define TRACE_LEVEL_AUDIT       7   // Audit trail events
#define TRACE_LEVEL_DEBUG       8   // Debug-only messages
#define TRACE_LEVEL_PERF        9   // Performance measurements
#define TRACE_LEVEL_RESERVED    10  // Reserved for future use

// ============================================================================
// TRACE FLAGS - Component-specific filtering
// ============================================================================

/**
 * @brief Trace flag definitions (must match Trace.h WPP_DEFINE_BIT order)
 */
#define TRACE_FLAG_GENERAL      0x00000001  // General driver operations
#define TRACE_FLAG_FILTER       0x00000002  // Minifilter operations
#define TRACE_FLAG_SCAN         0x00000004  // File scanning
#define TRACE_FLAG_COMM         0x00000008  // User-mode communication
#define TRACE_FLAG_PROCESS      0x00000010  // Process monitoring
#define TRACE_FLAG_REGISTRY     0x00000020  // Registry monitoring
#define TRACE_FLAG_NETWORK      0x00000040  // Network monitoring
#define TRACE_FLAG_SELFPROT     0x00000080  // Self-protection
#define TRACE_FLAG_CACHE        0x00000100  // Cache operations

/**
 * @brief Extended trace flags
 */
#define TRACE_FLAG_MEMORY       0x00000200  // Memory operations
#define TRACE_FLAG_THREAD       0x00000400  // Thread operations
#define TRACE_FLAG_IMAGE        0x00000800  // Image load operations
#define TRACE_FLAG_BEHAVIOR     0x00001000  // Behavioral analysis
#define TRACE_FLAG_ETW          0x00002000  // ETW provider
#define TRACE_FLAG_CRYPTO       0x00004000  // Cryptographic operations
#define TRACE_FLAG_SYNC         0x00008000  // Synchronization primitives
#define TRACE_FLAG_PERF         0x00010000  // Performance tracing
#define TRACE_FLAG_INIT         0x00020000  // Initialization/shutdown
#define TRACE_FLAG_IOCTL        0x00040000  // IOCTL handling
#define TRACE_FLAG_THREAT       0x00080000  // Threat detection events

/**
 * @brief Composite trace flags
 */
#define TRACE_FLAG_ALL          0xFFFFFFFF  // All flags enabled
#define TRACE_FLAG_SECURITY_ALL (TRACE_FLAG_SELFPROT | TRACE_FLAG_BEHAVIOR | TRACE_FLAG_THREAT)
#define TRACE_FLAG_MONITOR_ALL  (TRACE_FLAG_PROCESS | TRACE_FLAG_REGISTRY | TRACE_FLAG_NETWORK | TRACE_FLAG_THREAD | TRACE_FLAG_IMAGE)

// ============================================================================
// POOL TAGS
// ============================================================================

#define WPP_POOL_TAG_TRACE      'rTsS'  // SsTr - Trace buffer
#define WPP_POOL_TAG_FORMAT     'fTsS'  // SsTf - Format string
#define WPP_POOL_TAG_CONTEXT    'cTsS'  // SsTc - Trace context

// ============================================================================
// CUSTOM TYPE DEFINITIONS FOR WPP
// ============================================================================

/**
 * @brief Custom WPP types for security-specific data
 *
 * These extend WPP's built-in types with security-focused formatters.
 * Use these in trace format strings: %!IPADDR!, %!HASH!, etc.
 */

//
// begin_wpp config
//
// CUSTOM_TYPE(IPADDR, ItemIPAddr);
// CUSTOM_TYPE(IPV6ADDR, ItemIPV6Addr);
// CUSTOM_TYPE(MACADDR, ItemMACAddr);
// CUSTOM_TYPE(GUID, ItemGUID);
// CUSTOM_TYPE(HASH, ItemHexDump);
// CUSTOM_TYPE(NTSTATUS, ItemNTSTATUS);
// CUSTOM_TYPE(HRESULT, ItemHRESULT);
// CUSTOM_TYPE(IRQL, ItemIRQL);
// CUSTOM_TYPE(BOOLEAN, ItemBoolean);
// CUSTOM_TYPE(POINTER, ItemPointer);
// CUSTOM_TYPE(USTR, ItemWString);
// CUSTOM_TYPE(ASTR, ItemString);
// CUSTOM_TYPE(HEXDUMP, ItemHexDump);
// CUSTOM_TYPE(FILETIME, ItemFileTime);
// CUSTOM_TYPE(TIMESTAMP, ItemTimestamp);
// CUSTOM_TYPE(SID, ItemSID);
// CUSTOM_TYPE(PID, ItemULong);
// CUSTOM_TYPE(TID, ItemULong);
//
// end_wpp
//

// ============================================================================
// WPP FUNCTION DEFINITIONS
// ============================================================================

//
// begin_wpp config
//
// FUNC TraceEvents(LEVEL, FLAGS, MSG, ...);
// FUNC TraceError{LEVEL=TRACE_LEVEL_ERROR}(FLAGS, MSG, ...);
// FUNC TraceWarning{LEVEL=TRACE_LEVEL_WARNING}(FLAGS, MSG, ...);
// FUNC TraceInfo{LEVEL=TRACE_LEVEL_INFORMATION}(FLAGS, MSG, ...);
// FUNC TraceVerbose{LEVEL=TRACE_LEVEL_VERBOSE}(FLAGS, MSG, ...);
// FUNC TraceSecurity{LEVEL=TRACE_LEVEL_SECURITY}(FLAGS, MSG, ...);
// FUNC TracePerf{LEVEL=TRACE_LEVEL_PERF}(FLAGS, MSG, ...);
//
// FUNC TraceEnter{LEVEL=TRACE_LEVEL_VERBOSE}(FLAGS, MSG, ...);
// FUNC TraceExit{LEVEL=TRACE_LEVEL_VERBOSE}(FLAGS, MSG, ...);
//
// FUNC TraceFatal{LEVEL=TRACE_LEVEL_CRITICAL}(FLAGS, MSG, ...);
//
// USEPREFIX(TraceEvents, "%!STDPREFIX! [%!FUNC!] ");
// USEPREFIX(TraceError, "%!STDPREFIX! [%!FUNC!] ERROR: ");
// USEPREFIX(TraceWarning, "%!STDPREFIX! [%!FUNC!] WARNING: ");
// USEPREFIX(TraceInfo, "%!STDPREFIX! [%!FUNC!] INFO: ");
// USEPREFIX(TraceVerbose, "%!STDPREFIX! [%!FUNC!] VERBOSE: ");
// USEPREFIX(TraceSecurity, "%!STDPREFIX! [%!FUNC!] SECURITY: ");
// USEPREFIX(TracePerf, "%!STDPREFIX! [%!FUNC!] PERF: ");
// USEPREFIX(TraceEnter, "%!STDPREFIX! [%!FUNC!] ENTER: ");
// USEPREFIX(TraceExit, "%!STDPREFIX! [%!FUNC!] EXIT: ");
// USEPREFIX(TraceFatal, "%!STDPREFIX! [%!FUNC!] FATAL: ");
//
// end_wpp
//

// ============================================================================
// WPP CONDITIONAL MACROS
// ============================================================================

/**
 * @brief Level and flags condition macro
 */
#define WPP_LEVEL_FLAGS_LOGGER(level, flags) \
    WPP_LEVEL_LOGGER(flags)

#define WPP_LEVEL_FLAGS_ENABLED(level, flags) \
    (WPP_LEVEL_ENABLED(flags) && WPP_CONTROL(WPP_BIT_ ## flags).Level >= level)

// ============================================================================
// RUNTIME TRACE CONFIGURATION
// ============================================================================

/**
 * @brief Runtime trace configuration structure
 */
typedef struct _WPP_TRACE_CONFIG {
    //
    // Enable flags
    //
    BOOLEAN TracingEnabled;
    BOOLEAN DebugTracingEnabled;
    BOOLEAN PerfTracingEnabled;
    BOOLEAN SecurityTracingEnabled;

    //
    // Level configuration
    //
    UCHAR MinimumLevel;
    UCHAR MaximumLevel;
    UCHAR Reserved[2];

    //
    // Flag configuration
    //
    ULONG EnabledFlags;
    ULONG DisabledFlags;

    //
    // Rate limiting
    //
    ULONG MaxTracesPerSecond;
    ULONG CurrentSecondTraces;
    LARGE_INTEGER CurrentSecondStart;

    //
    // Statistics
    //
    volatile LONG64 TotalTraces;
    volatile LONG64 DroppedTraces;
    volatile LONG64 ErrorCount;

    //
    // Correlation
    //
    GUID SessionGuid;
    volatile LONG64 SequenceNumber;

} WPP_TRACE_CONFIG, *PWPP_TRACE_CONFIG;

/**
 * @brief Trace context for structured logging
 */
typedef struct _WPP_TRACE_CONTEXT {
    //
    // Correlation ID for request tracking
    //
    UINT64 CorrelationId;
    UINT64 ParentCorrelationId;

    //
    // Process/thread context
    //
    UINT32 ProcessId;
    UINT32 ThreadId;

    //
    // Component identification
    //
    UINT32 ComponentId;
    UINT32 SubComponentId;

    //
    // Timing
    //
    UINT64 StartTimestamp;
    UINT64 EndTimestamp;

    //
    // Optional custom data
    //
    PVOID CustomData;
    ULONG CustomDataSize;

} WPP_TRACE_CONTEXT, *PWPP_TRACE_CONTEXT;

/**
 * @brief Component IDs for tracing
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
// INITIALIZATION API
// ============================================================================

/**
 * @brief Initialize WPP tracing subsystem.
 *
 * Must be called during DriverEntry before any trace calls.
 *
 * @param DriverObject Driver object pointer.
 * @param RegistryPath Registry path for driver.
 *
 * @return STATUS_SUCCESS on success.
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
 * Must be called during driver unload.
 *
 * @param DriverObject Driver object pointer.
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
 *
 * @return TRUE if tracing is ready.
 *
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

/**
 * @brief Set minimum trace level.
 *
 * @param Level Minimum level to trace.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WppSetMinimumLevel(
    _In_ UCHAR Level
    );

/**
 * @brief Get current minimum trace level.
 *
 * @return Current minimum level.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
UCHAR
WppGetMinimumLevel(
    VOID
    );

/**
 * @brief Enable/disable specific trace flags.
 *
 * @param Flags Flags to modify.
 * @param Enable TRUE to enable, FALSE to disable.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WppSetTraceFlags(
    _In_ ULONG Flags,
    _In_ BOOLEAN Enable
    );

/**
 * @brief Get currently enabled trace flags.
 *
 * @return Current enabled flags.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
WppGetTraceFlags(
    VOID
    );

/**
 * @brief Set trace rate limit.
 *
 * @param MaxTracesPerSecond Maximum traces per second (0 = unlimited).
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WppSetRateLimit(
    _In_ ULONG MaxTracesPerSecond
    );

// ============================================================================
// CORRELATION API
// ============================================================================

/**
 * @brief Generate a new correlation ID.
 *
 * @return New unique correlation ID.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
UINT64
WppGenerateCorrelationId(
    VOID
    );

/**
 * @brief Create a trace context.
 *
 * @param Context Receives initialized context.
 * @param ComponentId Source component.
 * @param ParentCorrelationId Parent correlation ID (0 for root).
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
WppCreateTraceContext(
    _Out_ PWPP_TRACE_CONTEXT Context,
    _In_ WPP_COMPONENT_ID ComponentId,
    _In_ UINT64 ParentCorrelationId
    );

/**
 * @brief Complete a trace context (record end time).
 *
 * @param Context Context to complete.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WppCompleteTraceContext(
    _Inout_ PWPP_TRACE_CONTEXT Context
    );

// ============================================================================
// STATISTICS API
// ============================================================================

/**
 * @brief Get trace statistics.
 *
 * @param TotalTraces Receives total trace count.
 * @param DroppedTraces Receives dropped trace count.
 * @param ErrorCount Receives error count.
 *
 * @return STATUS_SUCCESS on success.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
WppGetStatistics(
    _Out_opt_ PUINT64 TotalTraces,
    _Out_opt_ PUINT64 DroppedTraces,
    _Out_opt_ PUINT64 ErrorCount
    );

/**
 * @brief Reset trace statistics.
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
WppResetStatistics(
    VOID
    );

// ============================================================================
// HELPER MACROS
// ============================================================================

/**
 * @brief Trace function entry with timing
 */
#define WPP_TRACE_ENTRY(flags) \
    do { \
        TraceEnter(flags, "-->"); \
    } while (0)

/**
 * @brief Trace function exit with timing
 */
#define WPP_TRACE_EXIT(flags) \
    do { \
        TraceExit(flags, "<--"); \
    } while (0)

/**
 * @brief Trace function exit with status
 */
#define WPP_TRACE_EXIT_STATUS(flags, status) \
    do { \
        TraceExit(flags, "<-- Status=%!STATUS!", status); \
    } while (0)

/**
 * @brief Trace NTSTATUS error if not success
 */
#define WPP_TRACE_STATUS(flags, status) \
    do { \
        if (!NT_SUCCESS(status)) { \
            TraceError(flags, "Status=%!STATUS!", status); \
        } \
    } while (0)

/**
 * @brief Trace with correlation ID
 */
#define WPP_TRACE_CORRELATED(level, flags, correlationId, msg, ...) \
    do { \
        TraceEvents(level, flags, "[CID:%I64u] " msg, correlationId, __VA_ARGS__); \
    } while (0)

/**
 * @brief Trace security-relevant event
 */
#define WPP_TRACE_SECURITY_EVENT(flags, eventType, processId, msg, ...) \
    do { \
        TraceSecurity(flags, "[%s] PID:%u " msg, eventType, processId, __VA_ARGS__); \
    } while (0)

/**
 * @brief Trace performance measurement
 */
#define WPP_TRACE_PERF_START(context) \
    do { \
        KeQueryPerformanceCounter(&(context)->StartTime); \
    } while (0)

#define WPP_TRACE_PERF_END(flags, context, operation) \
    do { \
        LARGE_INTEGER endTime, freq; \
        endTime = KeQueryPerformanceCounter(&freq); \
        UINT64 elapsedUs = ((endTime.QuadPart - (context)->StartTime.QuadPart) * 1000000) / freq.QuadPart; \
        TracePerf(flags, "%s completed in %I64u us", operation, elapsedUs); \
    } while (0)

/**
 * @brief Conditional trace based on runtime config
 */
#define WPP_TRACE_IF_ENABLED(level, flags, msg, ...) \
    do { \
        if (WppTraceIsEnabled() && WppGetMinimumLevel() <= (level)) { \
            TraceEvents(level, flags, msg, __VA_ARGS__); \
        } \
    } while (0)

// ============================================================================
// DEBUG BUILD ONLY MACROS
// ============================================================================

#if DBG

/**
 * @brief Debug-only trace
 */
#define WPP_TRACE_DEBUG(flags, msg, ...) \
    TraceVerbose(flags, "[DEBUG] " msg, __VA_ARGS__)

/**
 * @brief Assert with trace
 */
#define WPP_ASSERT_TRACE(condition, flags, msg, ...) \
    do { \
        if (!(condition)) { \
            TraceFatal(flags, "ASSERTION FAILED: " #condition " - " msg, __VA_ARGS__); \
            NT_ASSERT(condition); \
        } \
    } while (0)

#else

#define WPP_TRACE_DEBUG(flags, msg, ...) ((void)0)
#define WPP_ASSERT_TRACE(condition, flags, msg, ...) ((void)0)

#endif // DBG

// ============================================================================
// INLINE UTILITIES
// ============================================================================

/**
 * @brief Get component name string for tracing.
 */
FORCEINLINE
PCSTR
WppGetComponentName(
    _In_ WPP_COMPONENT_ID ComponentId
    )
{
    static const PCSTR ComponentNames[] = {
        "Unknown",
        "Core",
        "Filter",
        "Scan",
        "Communication",
        "Process",
        "Registry",
        "Network",
        "SelfProtection",
        "Cache",
        "Memory",
        "Thread",
        "Image",
        "Behavior",
        "ETW",
        "Crypto",
        "Sync"
    };

    if (ComponentId >= WppComponent_Max) {
        return "Invalid";
    }

    return ComponentNames[ComponentId];
}

/**
 * @brief Get trace level name string.
 */
FORCEINLINE
PCSTR
WppGetLevelName(
    _In_ UCHAR Level
    )
{
    static const PCSTR LevelNames[] = {
        "NONE",
        "CRITICAL",
        "ERROR",
        "WARNING",
        "INFO",
        "VERBOSE",
        "SECURITY",
        "AUDIT",
        "DEBUG",
        "PERF"
    };

    if (Level >= ARRAYSIZE(LevelNames)) {
        return "UNKNOWN";
    }

    return LevelNames[Level];
}

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_WPP_CONFIG_H_
