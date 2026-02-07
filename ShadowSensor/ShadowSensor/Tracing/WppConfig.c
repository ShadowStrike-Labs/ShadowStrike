/*++
    ShadowStrike Next-Generation Antivirus
    Module: WppConfig.c

    Purpose: Enterprise-grade WPP (Windows Software Trace Preprocessor) runtime
             configuration and management for kernel-mode tracing.

    Architecture:
    - Runtime trace level and flag management
    - Correlation ID generation for distributed tracing
    - Trace context management for structured logging
    - Rate limiting to prevent trace flooding
    - Statistics collection for monitoring
    - Thread-safe configuration updates

    Integration:
    - Works with standard WPP infrastructure
    - Compatible with tracelog.exe and traceview.exe
    - Supports ETW consumers and SIEM integration

    MITRE ATT&CK Coverage:
    - T1070: Indicator Removal (comprehensive audit trail)
    - T1562: Impair Defenses (tamper-resistant logging)

    Copyright (c) ShadowStrike Team
--*/

#include "WppConfig.h"
#include "Trace.h"
#include "../Utilities/MemoryUtils.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, WppTraceInitialize)
#pragma alloc_text(PAGE, WppTraceShutdown)
#endif

//=============================================================================
// Internal Constants
//=============================================================================

#define WPP_CONFIG_SIGNATURE            'GFCW'  // 'WCFG' reversed
#define WPP_DEFAULT_MAX_TRACES_PER_SEC  100000
#define WPP_RATE_LIMIT_WINDOW_MS        1000
#define WPP_CORRELATION_EPOCH           0x0001000000000000ULL

//=============================================================================
// Global State
//=============================================================================

static WPP_TRACE_CONFIG g_WppConfig = { 0 };
static BOOLEAN g_WppInitialized = FALSE;
static KSPIN_LOCK g_WppConfigLock;

//=============================================================================
// Forward Declarations
//=============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
WpppCheckRateLimit(
    VOID
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
WpppIncrementTraceCount(
    VOID
    );

//=============================================================================
// Initialization / Shutdown
//=============================================================================

_Use_decl_annotations_
NTSTATUS
WppTraceInitialize(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    Initializes the WPP tracing subsystem with runtime configuration.
    This supplements the standard WPP_INIT_TRACING macro.

Arguments:

    DriverObject - Driver object pointer.
    RegistryPath - Registry path for driver configuration.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER perfCounter;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    if (g_WppInitialized) {
        return STATUS_ALREADY_INITIALIZED;
    }

    //
    // Initialize configuration structure
    //
    RtlZeroMemory(&g_WppConfig, sizeof(WPP_TRACE_CONFIG));

    //
    // Initialize spinlock for configuration access
    //
    KeInitializeSpinLock(&g_WppConfigLock);

    //
    // Set default configuration
    //
    g_WppConfig.TracingEnabled = TRUE;
    g_WppConfig.DebugTracingEnabled = FALSE;
    g_WppConfig.PerfTracingEnabled = FALSE;
    g_WppConfig.SecurityTracingEnabled = TRUE;

    //
    // Set default levels
    //
#if DBG
    g_WppConfig.MinimumLevel = TRACE_LEVEL_VERBOSE;
#else
    g_WppConfig.MinimumLevel = TRACE_LEVEL_WARNING;
#endif
    g_WppConfig.MaximumLevel = TRACE_LEVEL_RESERVED;

    //
    // Set default flags - enable core components
    //
    g_WppConfig.EnabledFlags = TRACE_FLAG_GENERAL |
                               TRACE_FLAG_FILTER |
                               TRACE_FLAG_SCAN |
                               TRACE_FLAG_COMM |
                               TRACE_FLAG_PROCESS |
                               TRACE_FLAG_SELFPROT |
                               TRACE_FLAG_INIT |
                               TRACE_FLAG_THREAT;
    g_WppConfig.DisabledFlags = 0;

    //
    // Initialize rate limiting
    //
    g_WppConfig.MaxTracesPerSecond = WPP_DEFAULT_MAX_TRACES_PER_SEC;
    g_WppConfig.CurrentSecondTraces = 0;
    KeQuerySystemTimePrecise(&g_WppConfig.CurrentSecondStart);

    //
    // Initialize statistics
    //
    g_WppConfig.TotalTraces = 0;
    g_WppConfig.DroppedTraces = 0;
    g_WppConfig.ErrorCount = 0;

    //
    // Generate session GUID for correlation
    //
    status = ExUuidCreate(&g_WppConfig.SessionGuid);
    if (!NT_SUCCESS(status)) {
        //
        // Fall back to pseudo-random GUID if ExUuidCreate fails
        //
        KeQuerySystemTimePrecise(&currentTime);
        perfCounter = KeQueryPerformanceCounter(NULL);

        RtlZeroMemory(&g_WppConfig.SessionGuid, sizeof(GUID));
        g_WppConfig.SessionGuid.Data1 = (ULONG)currentTime.LowPart;
        g_WppConfig.SessionGuid.Data2 = (USHORT)(perfCounter.LowPart & 0xFFFF);
        g_WppConfig.SessionGuid.Data3 = (USHORT)((perfCounter.LowPart >> 16) & 0xFFFF);

        status = STATUS_SUCCESS;
    }

    //
    // Initialize sequence number with epoch to ensure uniqueness
    //
    KeQuerySystemTimePrecise(&currentTime);
    g_WppConfig.SequenceNumber = WPP_CORRELATION_EPOCH |
                                 ((currentTime.QuadPart >> 8) & 0x0000FFFFFFFFFFFFULL);

    g_WppInitialized = TRUE;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
WppTraceShutdown(
    _In_ PDRIVER_OBJECT DriverObject
    )
/*++

Routine Description:

    Shuts down the WPP tracing subsystem.
    This supplements the standard WPP_CLEANUP macro.

Arguments:

    DriverObject - Driver object pointer.

--*/
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);

    if (!g_WppInitialized) {
        return;
    }

    //
    // Disable tracing first
    //
    g_WppConfig.TracingEnabled = FALSE;

    //
    // Memory barrier to ensure visibility
    //
    KeMemoryBarrier();

    //
    // Clear configuration
    //
    RtlZeroMemory(&g_WppConfig, sizeof(WPP_TRACE_CONFIG));

    g_WppInitialized = FALSE;
}


_Use_decl_annotations_
BOOLEAN
WppTraceIsEnabled(
    VOID
    )
/*++

Routine Description:

    Checks if WPP tracing is initialized and enabled.

Return Value:

    TRUE if tracing is ready, FALSE otherwise.

--*/
{
    return (g_WppInitialized && g_WppConfig.TracingEnabled);
}


//=============================================================================
// Runtime Configuration API
//=============================================================================

_Use_decl_annotations_
VOID
WppSetMinimumLevel(
    _In_ UCHAR Level
    )
/*++

Routine Description:

    Sets the minimum trace level. Traces below this level are filtered.

Arguments:

    Level - New minimum level (TRACE_LEVEL_*).

--*/
{
    KIRQL oldIrql;

    if (!g_WppInitialized) {
        return;
    }

    if (Level > TRACE_LEVEL_RESERVED) {
        Level = TRACE_LEVEL_RESERVED;
    }

    KeAcquireSpinLock(&g_WppConfigLock, &oldIrql);
    g_WppConfig.MinimumLevel = Level;
    KeReleaseSpinLock(&g_WppConfigLock, oldIrql);
}


_Use_decl_annotations_
UCHAR
WppGetMinimumLevel(
    VOID
    )
/*++

Routine Description:

    Gets the current minimum trace level.

Return Value:

    Current minimum level.

--*/
{
    if (!g_WppInitialized) {
        return TRACE_LEVEL_NONE;
    }

    return g_WppConfig.MinimumLevel;
}


_Use_decl_annotations_
VOID
WppSetTraceFlags(
    _In_ ULONG Flags,
    _In_ BOOLEAN Enable
    )
/*++

Routine Description:

    Enables or disables specific trace flags.

Arguments:

    Flags - Flags to modify (TRACE_FLAG_*).
    Enable - TRUE to enable, FALSE to disable.

--*/
{
    KIRQL oldIrql;

    if (!g_WppInitialized) {
        return;
    }

    KeAcquireSpinLock(&g_WppConfigLock, &oldIrql);

    if (Enable) {
        g_WppConfig.EnabledFlags |= Flags;
        g_WppConfig.DisabledFlags &= ~Flags;
    } else {
        g_WppConfig.EnabledFlags &= ~Flags;
        g_WppConfig.DisabledFlags |= Flags;
    }

    KeReleaseSpinLock(&g_WppConfigLock, oldIrql);
}


_Use_decl_annotations_
ULONG
WppGetTraceFlags(
    VOID
    )
/*++

Routine Description:

    Gets the currently enabled trace flags.

Return Value:

    Current enabled flags bitmask.

--*/
{
    if (!g_WppInitialized) {
        return 0;
    }

    return g_WppConfig.EnabledFlags;
}


_Use_decl_annotations_
VOID
WppSetRateLimit(
    _In_ ULONG MaxTracesPerSecond
    )
/*++

Routine Description:

    Sets the trace rate limit.

Arguments:

    MaxTracesPerSecond - Maximum traces per second (0 = unlimited).

--*/
{
    KIRQL oldIrql;

    if (!g_WppInitialized) {
        return;
    }

    KeAcquireSpinLock(&g_WppConfigLock, &oldIrql);
    g_WppConfig.MaxTracesPerSecond = MaxTracesPerSecond;
    KeReleaseSpinLock(&g_WppConfigLock, oldIrql);
}


//=============================================================================
// Correlation API
//=============================================================================

_Use_decl_annotations_
UINT64
WppGenerateCorrelationId(
    VOID
    )
/*++

Routine Description:

    Generates a unique correlation ID for distributed tracing.
    The ID combines session info with a monotonic sequence number.

Return Value:

    New unique correlation ID.

--*/
{
    LONG64 sequence;

    if (!g_WppInitialized) {
        //
        // Return timestamp-based ID if not initialized
        //
        LARGE_INTEGER timestamp;
        KeQuerySystemTimePrecise(&timestamp);
        return (UINT64)timestamp.QuadPart;
    }

    //
    // Generate monotonically increasing correlation ID
    //
    sequence = InterlockedIncrement64(&g_WppConfig.SequenceNumber);

    return (UINT64)sequence;
}


_Use_decl_annotations_
NTSTATUS
WppCreateTraceContext(
    _Out_ PWPP_TRACE_CONTEXT Context,
    _In_ WPP_COMPONENT_ID ComponentId,
    _In_ UINT64 ParentCorrelationId
    )
/*++

Routine Description:

    Creates and initializes a trace context for structured logging.

Arguments:

    Context - Receives initialized context.
    ComponentId - Source component identifier.
    ParentCorrelationId - Parent correlation ID (0 for root context).

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    LARGE_INTEGER timestamp;

    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Context, sizeof(WPP_TRACE_CONTEXT));

    //
    // Generate new correlation ID
    //
    Context->CorrelationId = WppGenerateCorrelationId();
    Context->ParentCorrelationId = ParentCorrelationId;

    //
    // Capture process/thread context
    //
    Context->ProcessId = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    Context->ThreadId = (UINT32)(ULONG_PTR)PsGetCurrentThreadId();

    //
    // Set component info
    //
    Context->ComponentId = (UINT32)ComponentId;
    Context->SubComponentId = 0;

    //
    // Record start time
    //
    KeQuerySystemTimePrecise(&timestamp);
    Context->StartTimestamp = (UINT64)timestamp.QuadPart;
    Context->EndTimestamp = 0;

    //
    // No custom data initially
    //
    Context->CustomData = NULL;
    Context->CustomDataSize = 0;

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
WppCompleteTraceContext(
    _Inout_ PWPP_TRACE_CONTEXT Context
    )
/*++

Routine Description:

    Completes a trace context by recording the end time.

Arguments:

    Context - Context to complete.

--*/
{
    LARGE_INTEGER timestamp;

    if (Context == NULL) {
        return;
    }

    KeQuerySystemTimePrecise(&timestamp);
    Context->EndTimestamp = (UINT64)timestamp.QuadPart;
}


//=============================================================================
// Statistics API
//=============================================================================

_Use_decl_annotations_
NTSTATUS
WppGetStatistics(
    _Out_opt_ PUINT64 TotalTraces,
    _Out_opt_ PUINT64 DroppedTraces,
    _Out_opt_ PUINT64 ErrorCount
    )
/*++

Routine Description:

    Retrieves trace statistics.

Arguments:

    TotalTraces - Receives total trace count.
    DroppedTraces - Receives dropped trace count.
    ErrorCount - Receives error count.

Return Value:

    STATUS_SUCCESS on success.

--*/
{
    if (!g_WppInitialized) {
        if (TotalTraces != NULL) *TotalTraces = 0;
        if (DroppedTraces != NULL) *DroppedTraces = 0;
        if (ErrorCount != NULL) *ErrorCount = 0;
        return STATUS_NOT_FOUND;
    }

    if (TotalTraces != NULL) {
        *TotalTraces = (UINT64)g_WppConfig.TotalTraces;
    }

    if (DroppedTraces != NULL) {
        *DroppedTraces = (UINT64)g_WppConfig.DroppedTraces;
    }

    if (ErrorCount != NULL) {
        *ErrorCount = (UINT64)g_WppConfig.ErrorCount;
    }

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
WppResetStatistics(
    VOID
    )
/*++

Routine Description:

    Resets all trace statistics to zero.

--*/
{
    if (!g_WppInitialized) {
        return;
    }

    InterlockedExchange64(&g_WppConfig.TotalTraces, 0);
    InterlockedExchange64(&g_WppConfig.DroppedTraces, 0);
    InterlockedExchange64(&g_WppConfig.ErrorCount, 0);
}


//=============================================================================
// Internal Functions
//=============================================================================

static
_Use_decl_annotations_
BOOLEAN
WpppCheckRateLimit(
    VOID
    )
/*++

Routine Description:

    Checks if we're within the trace rate limit.
    Resets counter each second.

Return Value:

    TRUE if under rate limit, FALSE if limit exceeded.

--*/
{
    LARGE_INTEGER currentTime;
    LONGLONG elapsedMs;
    ULONG maxTraces;
    ULONG currentCount;

    if (!g_WppInitialized) {
        return FALSE;
    }

    maxTraces = g_WppConfig.MaxTracesPerSecond;

    //
    // If rate limiting is disabled, always allow
    //
    if (maxTraces == 0) {
        return TRUE;
    }

    KeQuerySystemTimePrecise(&currentTime);

    //
    // Calculate elapsed time in milliseconds
    //
    elapsedMs = (currentTime.QuadPart - g_WppConfig.CurrentSecondStart.QuadPart) / 10000;

    if (elapsedMs >= WPP_RATE_LIMIT_WINDOW_MS) {
        //
        // New window - reset counter
        //
        g_WppConfig.CurrentSecondStart = currentTime;
        g_WppConfig.CurrentSecondTraces = 1;
        return TRUE;
    }

    //
    // Increment and check
    //
    currentCount = (ULONG)InterlockedIncrement((LONG*)&g_WppConfig.CurrentSecondTraces);

    if (currentCount > maxTraces) {
        InterlockedIncrement64(&g_WppConfig.DroppedTraces);
        return FALSE;
    }

    return TRUE;
}


static
_Use_decl_annotations_
VOID
WpppIncrementTraceCount(
    VOID
    )
/*++

Routine Description:

    Increments the total trace counter.

--*/
{
    if (g_WppInitialized) {
        InterlockedIncrement64(&g_WppConfig.TotalTraces);
    }
}


//=============================================================================
// Extended Trace Helpers
//=============================================================================

/**
 * @brief Log a trace with rate limiting and statistics.
 *
 * This function is called by the WPP macros to perform pre-trace
 * checks and statistics updates.
 *
 * @param Level Trace level.
 * @param Flags Trace flags.
 *
 * @return TRUE if trace should proceed, FALSE to skip.
 */
BOOLEAN
WppShouldTrace(
    _In_ UCHAR Level,
    _In_ ULONG Flags
    )
{
    if (!g_WppInitialized || !g_WppConfig.TracingEnabled) {
        return FALSE;
    }

    //
    // Check level
    //
    if (Level < g_WppConfig.MinimumLevel) {
        return FALSE;
    }

    //
    // Check flags
    //
    if ((Flags & g_WppConfig.EnabledFlags) == 0) {
        return FALSE;
    }

    if ((Flags & g_WppConfig.DisabledFlags) != 0) {
        return FALSE;
    }

    //
    // Check rate limit
    //
    if (!WpppCheckRateLimit()) {
        return FALSE;
    }

    //
    // Update statistics
    //
    WpppIncrementTraceCount();

    return TRUE;
}


/**
 * @brief Record a trace error.
 *
 * Called when a trace operation fails.
 */
VOID
WppRecordError(
    VOID
    )
{
    if (g_WppInitialized) {
        InterlockedIncrement64(&g_WppConfig.ErrorCount);
    }
}


/**
 * @brief Get the session GUID for this tracing session.
 *
 * @param SessionGuid Receives the session GUID.
 *
 * @return STATUS_SUCCESS if available.
 */
NTSTATUS
WppGetSessionGuid(
    _Out_ PGUID SessionGuid
    )
{
    if (SessionGuid == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_WppInitialized) {
        RtlZeroMemory(SessionGuid, sizeof(GUID));
        return STATUS_NOT_FOUND;
    }

    RtlCopyMemory(SessionGuid, &g_WppConfig.SessionGuid, sizeof(GUID));

    return STATUS_SUCCESS;
}


/**
 * @brief Enable or disable debug tracing.
 *
 * @param Enable TRUE to enable, FALSE to disable.
 */
VOID
WppSetDebugTracing(
    _In_ BOOLEAN Enable
    )
{
    if (!g_WppInitialized) {
        return;
    }

    g_WppConfig.DebugTracingEnabled = Enable;

    if (Enable) {
        g_WppConfig.MinimumLevel = TRACE_LEVEL_VERBOSE;
    }
}


/**
 * @brief Enable or disable performance tracing.
 *
 * @param Enable TRUE to enable, FALSE to disable.
 */
VOID
WppSetPerfTracing(
    _In_ BOOLEAN Enable
    )
{
    if (!g_WppInitialized) {
        return;
    }

    g_WppConfig.PerfTracingEnabled = Enable;

    if (Enable) {
        g_WppConfig.EnabledFlags |= TRACE_FLAG_PERF;
    } else {
        g_WppConfig.EnabledFlags &= ~TRACE_FLAG_PERF;
    }
}


/**
 * @brief Enable or disable security tracing.
 *
 * @param Enable TRUE to enable, FALSE to disable.
 */
VOID
WppSetSecurityTracing(
    _In_ BOOLEAN Enable
    )
{
    if (!g_WppInitialized) {
        return;
    }

    g_WppConfig.SecurityTracingEnabled = Enable;

    if (Enable) {
        g_WppConfig.EnabledFlags |= TRACE_FLAG_SECURITY_ALL;
    } else {
        g_WppConfig.EnabledFlags &= ~TRACE_FLAG_SECURITY_ALL;
    }
}


/**
 * @brief Get current trace configuration summary.
 *
 * @param Config Receives configuration copy.
 *
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
WppGetConfiguration(
    _Out_ PWPP_TRACE_CONFIG Config
    )
{
    KIRQL oldIrql;

    if (Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_WppInitialized) {
        RtlZeroMemory(Config, sizeof(WPP_TRACE_CONFIG));
        return STATUS_NOT_FOUND;
    }

    KeAcquireSpinLock(&g_WppConfigLock, &oldIrql);
    RtlCopyMemory(Config, &g_WppConfig, sizeof(WPP_TRACE_CONFIG));
    KeReleaseSpinLock(&g_WppConfigLock, oldIrql);

    return STATUS_SUCCESS;
}


/**
 * @brief Calculate elapsed time from trace context.
 *
 * @param Context Completed trace context.
 *
 * @return Elapsed time in microseconds.
 */
UINT64
WppGetElapsedMicroseconds(
    _In_ PWPP_TRACE_CONTEXT Context
    )
{
    UINT64 elapsed;

    if (Context == NULL) {
        return 0;
    }

    if (Context->EndTimestamp == 0 || Context->StartTimestamp == 0) {
        return 0;
    }

    if (Context->EndTimestamp < Context->StartTimestamp) {
        return 0;
    }

    //
    // Convert 100ns units to microseconds
    //
    elapsed = (Context->EndTimestamp - Context->StartTimestamp) / 10;

    return elapsed;
}


/**
 * @brief Format correlation ID as string.
 *
 * @param CorrelationId Correlation ID to format.
 * @param Buffer Output buffer.
 * @param BufferSize Size of buffer in characters.
 *
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
WppFormatCorrelationId(
    _In_ UINT64 CorrelationId,
    _Out_writes_(BufferSize) PWCHAR Buffer,
    _In_ SIZE_T BufferSize
    )
{
    NTSTATUS status;

    if (Buffer == NULL || BufferSize < 20) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = RtlStringCchPrintfW(
        Buffer,
        BufferSize,
        L"%016I64X",
        CorrelationId
        );

    return status;
}

