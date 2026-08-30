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
 * ShadowStrike NGAV - DRIVER ENTRY POINT
 * ============================================================================
 *
 * @file DriverEntry.c
 * @brief Main driver entry point and initialization.
 *
 * This file contains DriverEntry, the main entry point called when the driver
 * is loaded. It initializes all subsystems in the correct order and handles
 * cleanup on failure.
 *
 * ENTERPRISE-GRADE IMPLEMENTATION:
 * - Uses EX_RUNDOWN_REF for safe unload synchronization (no race conditions)
 * - All security callbacks are fully implemented (no stubs)
 * - Memory barriers for all shared state access
 * - Proper IRQL handling throughout
 * - Version checking for API compatibility
 * - Registry-based configuration loading
 * - Precise cleanup based on initialization flags
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "../Callbacks/FileSystem/PostCreate.h"
#include "DriverEntry.h"
#include "FilterRegistration.h"
#include "../Communication/CommPort.h"
#include "../Cache/ScanCache.h"
#include "../Exclusions/ExclusionManager.h"
#include "../SelfProtection/SelfProtect.h"
#include "../Callbacks/Registry/RegistryCallback.h"
#include "../Utilities/HashUtils.h"
#include "../Utilities/FileUtils.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/ProcessUtils.h"
#include "../Shared/SharedDefs.h"
#include "../Shared/PortName.h"
#include "../Callbacks/FileSystem/NamedPipeMonitor.h"
#include "../Callbacks/Process/AmsiBypassDetector.h"
#include "../Callbacks/FileSystem/FileBackupEngine.h"
#include "../Callbacks/FileSystem/USBDeviceControl.h"
#include "../Callbacks/FileSystem/FileSystemCallbacks.h"

// Forward declarations for PostWrite subsystem (no separate header)
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ShadowStrikePostWriteInitialize(VOID);

_IRQL_requires_(PASSIVE_LEVEL)
VOID ShadowStrikePostWriteShutdown(VOID);

// Forward declarations for PreCreate subsystem
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS PcInitialize(VOID);

_IRQL_requires_(PASSIVE_LEVEL)
VOID PcShutdown(VOID);

// Forward declarations for PreSetInfo subsystem
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ShadowStrikeInitializePreSetInfo(VOID);

_IRQL_requires_(PASSIVE_LEVEL)
VOID ShadowStrikeCleanupPreSetInfo(VOID);

// Forward declarations for PreWrite subsystem
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ShadowStrikeInitializePreWrite(VOID);

_IRQL_requires_(PASSIVE_LEVEL)
VOID ShadowStrikeCleanupPreWrite(VOID);

#include "../Callbacks/Process/WSLMonitor.h"
#include "../Callbacks/Process/AppControl.h"
#include "../SelfProtection/FirmwareIntegrity.h"
#include "../Callbacks/Process/ClipboardMonitor.h"
#include "../Callbacks/Object/ObjectCallback.h"
#include "../Callbacks/Process/ProcessNotify.h"
#include "../Callbacks/Process/ImageNotify.h"
#include "../Callbacks/Process/ThreadNotify.h"

// Phase 1A: Sync infrastructure
#include "../Sync/WorkQueue.h"
#include "../Sync/ThreadPool.h"
#include "../Sync/AsyncWorkQueue.h"
#include "../Sync/TimerManager.h"
#include "../Sync/DeferredProcedure.h"

// Phase 1B: Performance infrastructure
#include "../Performance/PerformanceMonitor.h"
#include "../Performance/ResourceThrottling.h"
#include "../Performance/BatchProcessing.h"
#include "../Performance/CacheOptimization.h"
#include "../Performance/LookasideLists.h"

// Phase 1C: Power management
#include "../Power/PowerCallback.h"

// Phase 1D: Telemetry pipeline
#include "../ETW/ETWProvider.h"
#include "../ETW/ETWConsumer.h"
#include "../ETW/TelemetryEvents.h"
#include "../ETW/EventSchema.h"
#include "../ETW/ManifestGenerator.h"
#include "../Communication/TelemetryBuffer.h"
#include "../Communication/Compression.h"
#include "../Communication/Encryption.h"

// Phase 2: Detection subsystems
#include "../Behavioral/BehaviorEngine.h"
#include "../Memory/MemoryMonitor.h"
#include "../Memory/MemoryScanner.h"
#include "../Syscall/SyscallMonitor.h"
#include "../Network/NetworkFilter.h"

// Phase 3: Enrichment & communication
#include "../Callbacks/Process/ProcessAnalyzer.h"
#include "../Communication/MessageHandler.h"
#include "../Communication/ScanBridge.h"

// Phase 4: Self-protection hardening
#include "../SelfProtection/CallbackProtection.h"
#include "../SelfProtection/HandleProtection.h"
#include "../SelfProtection/IntegrityMonitor.h"
#include "../SelfProtection/AntiDebug.h"
#include "../SelfProtection/AntiUnload.h"
#include "../SelfProtection/FileProtection.h"
#include "../../PhantomSensorELAM/ELAMDriver.h"

// Phase 5: Specialized subsystems
#include "../ALPC/AlpcPortMonitor.h"
#include "../Transactions/KtmMonitor.h"
#include "../Objects/ObjectNamespace.h"

// Phase 6: Scoring orchestration
#include "../Behavioral/ThreatScoring.h"

// Tracing infrastructure
#include "../Tracing/WppConfig.h"

// Infrastructure: lock subsystem and message queue
#include "../Sync/SpinLock.h"
#include "../Communication/MessageQueue.h"

// Forward declaration for INIT-section breadcrumb function
static VOID ShadowStrikeLogBootStep(
    _In_ PUNICODE_STRING RegistryPath,
    _In_ ULONG StepNumber
);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(INIT, ShadowStrikeCheckVersionCompatibility)
#pragma alloc_text(INIT, ShadowStrikeLoadConfiguration)
#pragma alloc_text(INIT, ShadowStrikeLogBootStep)
#pragma alloc_text(PAGE, ShadowStrikeUnload)
#pragma alloc_text(PAGE, ShadowStrikeInitializeLookasideLists)
#pragma alloc_text(PAGE, ShadowStrikeCleanupLookasideLists)
#pragma alloc_text(PAGE, ShadowStrikeRegisterProcessCallbacks)
#pragma alloc_text(PAGE, ShadowStrikeUnregisterProcessCallbacks)

#pragma alloc_text(PAGE, ShadowStrikeCleanupByFlags)
#pragma alloc_text(PAGE, ShadowStrikeWaitForRundownComplete)
#endif

// ============================================================================
// GLOBAL DRIVER DATA
// ============================================================================

/**
 * @brief Global driver data instance.
 *
 * Single instance of driver state, initialized in DriverEntry.
 */
SHADOWSTRIKE_DRIVER_DATA g_DriverData = {0};

/**
 * @brief Initialization flags tracking successful subsystem init.
 */
static ULONG g_InitFlags = InitFlag_None;

/**
 * @brief Callback registration flags for process/thread/image.
 */
static ULONG g_CallbackFlags = 0;

/**
 * @brief Subsystem initialization flags for infrastructure and detection modules.
 */
static ULONG g_SubsystemFlags = SubsysFlag_None;

/**
 * @brief PreSetInfo subsystem initialized flag.
 *
 * All 32 bits in both g_InitFlags and g_SubsystemFlags are exhausted.
 * PreSetInfo uses its own init guard rather than consuming a flag bit.
 */
static BOOLEAN g_PreSetInfoInitialized = FALSE;
static BOOLEAN g_PreWriteInitialized = FALSE;
static BOOLEAN g_FileUtilsInitialized = FALSE;
static BOOLEAN g_ProcessUtilsInitialized = FALSE;

// ============================================================================
// SUBSYSTEM HANDLE STORAGE
// ============================================================================

/// @brief Thread pool handle (Phase 1A)
static PTP_THREAD_POOL g_ThreadPool = NULL;

/// @brief Async work queue handle (Phase 1A)
static HAWQ_MANAGER g_AsyncWorkQueue = NULL;

/// @brief Timer manager handle (Phase 1A)
static PTM_MANAGER g_TimerManager = NULL;
static PDEVICE_OBJECT g_TimerControlDevice = NULL;  // Control device for TimerManager work items

/// @brief DPC manager handle (Phase 1A)
static PDPC_MANAGER g_DpcManager = NULL;

/// @brief Performance monitor handle (Phase 1B)
static PSSPM_MONITOR g_PerformanceMonitor = NULL;

/// @brief Resource throttler handle (Phase 1B)
static PRT_THROTTLER g_ResourceThrottler = NULL;

//
// Accounting for the ETW -> user-mode behavioural alert forward. These exist
// because two different reasons for NOT forwarding an event must be told
// apart: one is structural and permanent (the subject is our own service), the
// other is load shedding and is the signal that the per-process budget below
// needs tuning. A single "dropped" number could not distinguish them, and a
// suppression path with no counter is indistinguishable from a path that never
// runs. Reported on the unload path beside the other final statistics.
//
static volatile LONG64 g_EtwAlertsForwarded = 0;
static volatile LONG64 g_EtwAlertsSuppressedSelf = 0;
static volatile LONG64 g_EtwAlertsSuppressedBudget = 0;

/// @brief Batch processor handle (Phase 1B)
static PBP_PROCESSOR g_BatchProcessor = NULL;

/// @brief Cache optimizer handle (Phase 1B)
static PCO_MANAGER g_CacheOptimizer = NULL;

/// @brief Telemetry buffer manager handle (Phase 1D)
static PTB_MANAGER g_TelemetryBuffer = NULL;

/// @brief Process analyzer handle (Phase 3A)
static PPA_ANALYZER g_ProcessAnalyzer = NULL;

/// @brief Callback protection handle (Phase 4A)
static PCP_PROTECTOR g_CallbackProtector = NULL;

/// @brief Handle protection engine (Phase 4B)
static PHP_PROTECTION_ENGINE g_HandleProtection = NULL;

/// @brief Integrity monitor handle (Phase 4B)
static PIM_MONITOR g_IntegrityMonitor = NULL;

/// @brief Anti-debug protector handle (Phase 4C)
static PADB_PROTECTOR g_AntiDebugProtector = NULL;

/// @brief Anti-unload protector handle (Phase 4C)
static PAU_PROTECTOR g_AntiUnloadProtector = NULL;

/// @brief File protection engine handle (Phase 4C)
static PFP_ENGINE g_FileProtectionEngine = NULL;

/// @brief Threat scoring engine (Phase 6A)
static PTS_SCORING_ENGINE g_ThreatScoring = NULL;

/// @brief Event schema handle (Phase 1D)
static PES_SCHEMA g_EventSchema = NULL;

/// @brief Manifest generator handle (Phase 1D)
static PMG_GENERATOR g_ManifestGenerator = NULL;

/// @brief Memory scanner handle (Phase 2B)
static PMS_SCANNER g_MemoryScanner = NULL;

/// @brief Power-to-BehaviorEngine bridge callback handle
static PVOID g_PowerBehaviorBridgeHandle = NULL;

/// @brief ETW Consumer event pipeline (centralized event broker)
static PEC_CONSUMER g_EtwConsumer = NULL;

/// @brief Centralized lookaside list manager (memory pool management)
static PLL_MANAGER g_LookasideManager = NULL;

/// @brief Compression manager (telemetry bandwidth optimization)
static COMP_MANAGER g_CompressionManager = {0};

/// @brief Encryption manager (secure kernel-to-user communication)
static ENC_MANAGER g_EncryptionManager = {0};

/**
 * @brief Power callback bridge â€” forwards sleep/resume events to BehaviorEngine.
 *
 * Detects T1497.003 (Time Based Evasion) by making power transitions visible
 * in the behavioral event stream. Attack chain tracker correlates sleep/resume
 * with process activity to detect sandbox evasion and timing attacks.
 */
static VOID
ShadowStrikePowerBehaviorBridge(
    _In_ SHADOW_POWER_EVENT_TYPE EventType,
    _In_ PSHADOW_POWER_EVENT_INFO Event,
    _In_opt_ PVOID Context
    )
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Event);

    if (!(g_SubsystemFlags & SubsysFlag_BehaviorEngine)) {
        return;
    }

    //
    // Map power events to behavioral event types.
    // Sleep/resume transitions are Defense Evasion indicators (T1497.003)
    // because attackers use NtDelayExecution + sleep-based sandbox evasion.
    //
    UINT32 threatScore;

    switch (EventType) {
    case ShadowPowerEvent_EnteringSleep:
    case ShadowPowerEvent_EnteringHibernate:
        threatScore = 0;  // Entering sleep is benign
        break;

    case ShadowPowerEvent_ResumingFromSleep:
    case ShadowPowerEvent_ResumingFromHibernate:
        threatScore = 5;  // Mild baseline â€” chain tracker evaluates context
        break;

    case ShadowPowerEvent_BatteryCritical:
        threatScore = 0;
        break;

    default:
        return;
    }

    BeEngineSubmitEvent(
        BehaviorEvent_SandboxEvasion,
        BehaviorCategory_DefenseEvasion,
        0,          // System-level event, no specific process
        NULL, 0,
        threatScore,
        FALSE,
        NULL
        );
}

// ============================================================================
// BATCH PROCESSING CALLBACK
// ============================================================================

//
// ShadowStrikeBatchFlushCallback
//
// Invoked by BatchProcessing worker thread at PASSIVE_LEVEL when a batch
// of telemetry events is ready.  Forwards each event to the user-mode
// agent via CommPort.
//
static
VOID
ShadowStrikeBatchFlushCallback(
    _In_reads_(EventCount) PBP_EVENT* Events,
    _In_ ULONG EventCount,
    _In_opt_ PVOID Context
    )
{
    UNREFERENCED_PARAMETER(Context);

    for (ULONG i = 0; i < EventCount; i++) {
        PBP_EVENT evt = Events[i];
        ULONG totalSize;

        if (evt == NULL || evt->DataSize > BP_MAX_EVENT_DATA_SIZE) {
            continue;
        }

        totalSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + (ULONG)evt->DataSize;
        if (totalSize < sizeof(SHADOWSTRIKE_MESSAGE_HEADER)) {
            continue;  // overflow guard
        }

        PSHADOWSTRIKE_MESSAGE_HEADER msg =
            (PSHADOWSTRIKE_MESSAGE_HEADER)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, totalSize, 'btCP');
        if (msg == NULL) {
            continue;
        }

        RtlZeroMemory(msg, sizeof(SHADOWSTRIKE_MESSAGE_HEADER));
        msg->Magic = SHADOWSTRIKE_MESSAGE_MAGIC;
        msg->Version = SHADOWSTRIKE_PROTOCOL_VERSION;
        msg->MessageType = (UINT16)evt->Type;
        msg->TotalSize = totalSize;
        msg->DataSize = (UINT32)evt->DataSize;
        KeQuerySystemTime((PLARGE_INTEGER)&msg->Timestamp);

        RtlCopyMemory(
            (PUCHAR)msg + sizeof(SHADOWSTRIKE_MESSAGE_HEADER),
            evt->Data,
            evt->DataSize
        );

        ShadowStrikeSendNotification(msg, totalSize);

        ExFreePoolWithTag(msg, 'btCP');
    }
}

// ============================================================================
// ETW CONSUMER EVENT CALLBACK
// ============================================================================

/**
 * @brief Unified event callback for all ETWConsumer subscriptions.
 *
 * This callback runs on ETWConsumer processing threads (system threads at
 * PASSIVE_LEVEL). It receives events from all kernel callbacks that emit
 * into the pipeline via EcEmitKernelEvent, providing:
 *   - Centralized telemetry streaming to user-mode via CommPort
 *   - Unified event rate limiting and priority ordering
 *   - Cross-source event correlation via AttackChainTracker
 *
 * @irql PASSIVE_LEVEL (processing threads)
 */
static
EC_PROCESS_RESULT
NTAPI
ShadowStrikeEtwEventCallback(
    _In_ PEC_EVENT_RECORD Record,
    _In_opt_ PVOID Context
    )
{
    UNREFERENCED_PARAMETER(Context);

    if (Record == NULL) {
        return EcResult_Continue;
    }

    //
    // Stream processed events to TelemetryEvents ETW provider.
    // NOTE: We do NOT log every individual event â€” that would flood the
    // telemetry channel at thousands of events/second. Instead, stats
    // are aggregated and logged periodically in the health check timer.
    // Individual event forwarding to CommPort (below) handles real-time
    // delivery of high-priority events to the user-mode agent.
    //

    //
    // Forward high-priority events to CommPort for real-time user-mode delivery.
    // Low/Background priority events are only streamed via ETW telemetry
    // to avoid flooding the communication channel.
    //
    if (Record->Priority <= EcPriority_Normal) {
        //
        // Build a real payload. This used to hand-assemble a bare
        // SHADOWSTRIKE_MESSAGE_HEADER with DataSize = 0, TotalSize = sizeof(hdr)
        // and the ProcessId stuffed into MessageId, then call
        // ShadowStrikeSendNotification directly. Three things were wrong with it.
        //
        // 1. IT CONVEYED NOTHING AND REACHED NOBODY. The user-mode consumer,
        //    RealTimeProtection's FilterMessageType_BehavioralAlert case, is gated
        //    on `if (data && size > 0)` before it calls
        //    BehaviorBlocker::OnKernelBehavioralAlert - which parses a process id
        //    and parent process id and can go on to BLOCK a process. With
        //    DataSize == 0 that call never happened. This is the only producer of
        //    this message type in the driver (RegpSendBehavioralAlert is misnamed
        //    and actually sends FilterMessageType_RegistryNotify), so the kernel
        //    behavioural path into BehaviorBlocker has never carried one event.
        //    The alert also could not say WHICH behaviour fired.
        //
        // 2. IT WENT OUT IN CLEARTEXT. ShadowStrikeSendNotification gates its
        //    encryption block on `sendSize > sizeof(SHADOWSTRIKE_MESSAGE_HEADER)`,
        //    so a header-only frame skipped encryption entirely and was sent
        //    unauthenticated - directly contradicting that function's own
        //    "never send plaintext" policy.
        //
        // 3. IT USED THE UNBATCHED PATH. This callback's own comments describe a
        //    channel carrying thousands of events per second. Sixty lines above
        //    this one, the same file defines ShadowStrikeBatchFlushCallback, and
        //    ShadowStrikeBatchSendNotification exists precisely to route
        //    high-throughput events through BpQueueEvent. That funnel builds the
        //    header itself, keeps the payload, delivers via
        //    ShadowStrikeSendNotification from the flush thread (so it is
        //    encrypted), and drops rather than faulting above APC_LEVEL.
        //
        SHADOWSTRIKE_BEHAVIORAL_ALERT alert;
        HANDLE subjectPid = (HANDLE)(ULONG_PTR)Record->Header.ProcessId;

        //
        // DO NOT REPORT THE SCANNER'S OWN ACTIVITY BACK TO THE SCANNER.
        //
        // Every alert forwarded from here costs the user-mode service three
        // WARN log writes (RealTimeProtection's BehavioralAlert case,
        // BehaviorBlocker's chain escalation, and BufferOverflowProtection),
        // and a log write is file I/O that re-enters our own minifilter, which
        // produces further ETW events for this same callback. Forwarding our
        // own events therefore closes a positive feedback loop that sustains
        // itself once started, and it runs on the two user-mode threads that
        // owe the kernel a scan verdict - so the machine stops answering file
        // operations. The 1.0.97 field run measured 51,437 alerts in 4m02s, of
        // which 19,825 named the service's own pid, with 27.7 MB of log written
        // in the same window.
        //
        // This is the exact recursion ShadowStrikeIsScannerProcess was written
        // for: its own contract in CommPort.h describes exempting the scanner's
        // file I/O because it "would otherwise recurse into PreCreate ->
        // SbSendScanRequest and exhaust the scanner worker pool". PreCreate has
        // consulted it since the beginning; this producer never did.
        //
        // NO DETECTION IS LOST, and the reasoning matters because suppressing a
        // detection feed is normally forbidden. What is suppressed is only the
        // BEHAVIOURAL correlation feed for our own process, whose sole possible
        // product is a decision about ourselves - and BehaviorBlocker acts on
        // that by terminating the process tree, which is what took the 1.0.95
        // logon session down. Attacks AGAINST this service keep their dedicated
        // coverage: handle-based self-protection (ObjectCallback, ObRegisterCallbacks
        // over PsProcessType/PsThreadType), HandleProtection, AntiDebug,
        // AntiUnload, CallbackProtection, IntegrityMonitor and FileProtection in
        // the kernel, plus SelfDefense / TamperProtection / ProcessProtection in
        // user mode. None of those route through this callback. The event also
        // still reaches the ETW telemetry stream; only the synchronous forward
        // to the reply-blocking threads is withheld.
        //
        if (ShadowStrikeIsScannerProcess(subjectPid)) {
            InterlockedIncrement64(&g_EtwAlertsSuppressedSelf);
            return EcResult_Continue;
        }

        //
        // BOUND THE PER-PROCESS RATE.
        //
        // Independently of the loop above, an unbounded forward is a denial of
        // service: a process that generates ETW events in a tight loop starves
        // the threads that answer kernel scan requests, which blinds the
        // scanner without needing an exploit. The throttler exists for exactly
        // this - DriverEntry's own configuration comment calls it "enterprise
        // DoS mitigation" - and five hot callbacks already REPORT usage into
        // it. Until now nothing anywhere in the driver ever asked it whether to
        // proceed, so it measured everything and gated nothing.
        //
        // RtResourceEventQueue is used rather than RtResourceCallbackRate
        // because ImageNotify.c already reports image-load volume into the
        // latter; sharing one budget would let either producer exhaust the
        // other's headroom.
        //
        // FAILS OPEN BY DESIGN: if the throttler is absent or the query fails
        // the event is forwarded. A fault in a load-shedding mechanism must
        // never be able to silence a detection feed.
        //
        {
            PRT_THROTTLER throttler = ShadowStrikeGetResourceThrottler();

            if (throttler != NULL) {
                RT_THROTTLE_ACTION action = RtActionNone;
                NTSTATUS throttleStatus;

                (VOID)RtReportProcessUsage(
                    throttler, subjectPid, RtResourceEventQueue, 1);

                //
                // Any action other than RtActionNone means the budget is
                // exceeded. They are treated alike here deliberately: this path
                // has exactly one sane response to being over budget, and
                // honouring RtActionDelay literally would mean stalling an ETW
                // callback that can run at DISPATCH_LEVEL.
                //
                throttleStatus = RtCheckProcessThrottle(
                    throttler, subjectPid, RtResourceEventQueue, &action);

                if (NT_SUCCESS(throttleStatus) && action != RtActionNone) {
                    InterlockedIncrement64(&g_EtwAlertsSuppressedBudget);
                    return EcResult_Continue;
                }
            }
        }

        RtlZeroMemory(&alert, sizeof(alert));

        alert.ProcessId       = Record->Header.ProcessId;
        alert.ParentProcessId = 0;  // Not resolved here - see the wire struct's comment
        alert.ThreadId        = Record->Header.ThreadId;
        alert.SequenceNumber  = Record->SequenceNumber;
        alert.Timestamp       = Record->Header.Timestamp.QuadPart;
        alert.Keywords        = Record->Header.Keywords;
        alert.CorrelationId   = Record->IsCorrelated ? Record->CorrelationId : 0ULL;
        alert.EventId         = Record->Header.EventId;
        alert.Task            = Record->Header.Task;
        alert.Level           = Record->Header.Level;
        alert.Opcode          = Record->Header.Opcode;

        //
        // Priority and Source are C enumerations in EC_EVENT_RECORD, so their
        // width is the compiler's choice. Narrowed explicitly rather than assigned
        // through, because an enum on a wire structure is how field offsets drift
        // between producer and consumer without any diagnostic.
        //
        alert.Priority        = (UINT8)Record->Priority;
        alert.Source          = (UINT8)Record->Source;
        alert.UserDataBytes   = Record->UserDataLength;

        (VOID)ShadowStrikeBatchSendNotification(
            (UINT16)FilterMessageType_BehavioralAlert,
            &alert,
            sizeof(alert)
        );

        InterlockedIncrement64(&g_EtwAlertsForwarded);
    }

    return EcResult_Continue;
}

// ============================================================================
// EVENT SCHEMA POPULATION
// ============================================================================

/**
 * @brief Populate the event schema with all ETW event definitions.
 *
 * Called once during DriverEntry after EsInitialize succeeds. Registers all
 * ETW event types, keywords, tasks, and channels so that the schema engine
 * is fully populated for manifest generation, event validation, and
 * serialization.
 *
 * @param Schema  Initialized event schema to populate.
 * @return STATUS_SUCCESS on success, or the first failure status.
 * @irql PASSIVE_LEVEL
 */
static NTSTATUS
ShadowStrikePopulateEventSchema(
    _In_ PES_SCHEMA Schema
    )
{
    NTSTATUS status;
    ES_FIELD_DEFINITION fields[16];
    ULONG registered = 0;
    ULONG failed = 0;

#define ES_REG_KEYWORD(name, mask, desc) \
    do { \
        status = EsRegisterKeyword(Schema, (name), (mask), (desc)); \
        if (!NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_COLLISION) { \
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, \
                "[ShadowStrike] EventSchema: keyword '%s' reg failed: 0x%08X\n", (name), status); \
            failed++; \
        } \
    } while (0)

#define ES_REG_TASK(name, val, desc) \
    do { \
        status = EsRegisterTask(Schema, (name), (val), (desc)); \
        if (!NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_COLLISION) { \
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, \
                "[ShadowStrike] EventSchema: task '%s' reg failed: 0x%08X\n", (name), status); \
            failed++; \
        } \
    } while (0)

#define ES_REG_CHANNEL(name, type, val, enabled, desc) \
    do { \
        status = EsRegisterChannel(Schema, (name), (type), (val), (enabled), (desc)); \
        if (!NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_COLLISION) { \
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, \
                "[ShadowStrike] EventSchema: channel '%s' reg failed: 0x%08X\n", (name), status); \
            failed++; \
        } \
    } while (0)

    //
    // Register keywords
    //
    ES_REG_KEYWORD("Process",    ETW_KEYWORD_PROCESS,    "Process lifecycle events");
    ES_REG_KEYWORD("Thread",     ETW_KEYWORD_THREAD,     "Thread lifecycle events");
    ES_REG_KEYWORD("Image",      ETW_KEYWORD_IMAGE,      "Image/module load events");
    ES_REG_KEYWORD("File",       ETW_KEYWORD_FILE,       "File system events");
    ES_REG_KEYWORD("Registry",   ETW_KEYWORD_REGISTRY,   "Registry events");
    ES_REG_KEYWORD("Memory",     ETW_KEYWORD_MEMORY,     "Memory and injection events");
    ES_REG_KEYWORD("Network",    ETW_KEYWORD_NETWORK,    "Network events");
    ES_REG_KEYWORD("Behavior",   ETW_KEYWORD_BEHAVIOR,   "Behavioral analysis events");
    ES_REG_KEYWORD("Security",   ETW_KEYWORD_SECURITY,   "Security alert events");
    ES_REG_KEYWORD("Diagnostic", ETW_KEYWORD_DIAGNOSTIC, "Diagnostic and health events");
    ES_REG_KEYWORD("Threat",     ETW_KEYWORD_THREAT,     "Threat detection events");
    ES_REG_KEYWORD("Telemetry",  ETW_KEYWORD_TELEMETRY,  "Telemetry events");

    //
    // Register tasks
    //
    ES_REG_TASK("ProcessLifecycle",  1,  "Process create/terminate");
    ES_REG_TASK("ThreadLifecycle",   2,  "Thread create/terminate");
    ES_REG_TASK("ImageLoad",         3,  "Image/module load");
    ES_REG_TASK("FileOperation",     4,  "File I/O operations");
    ES_REG_TASK("RegistryOperation", 5,  "Registry operations");
    ES_REG_TASK("MemoryProtection",  6,  "Memory and injection detection");
    ES_REG_TASK("NetworkActivity",   7,  "Network connections and DNS");
    ES_REG_TASK("BehavioralAnalysis",8,  "Behavioral analysis and attack chains");
    ES_REG_TASK("DriverDiagnostic",  9,  "Driver health and diagnostics");

    //
    // Register channels
    //
    ES_REG_CHANNEL("Operational", EsChannel_Operational, 1, TRUE,
                   "Primary operational event channel");
    ES_REG_CHANNEL("Analytic",    EsChannel_Analytic,    2, FALSE,
                   "High-volume analytic event channel");
    ES_REG_CHANNEL("Security",    EsChannel_Admin,       3, TRUE,
                   "Security alerts and threat detections");

    //
    // â”€â”€ Process Events â”€â”€
    //

    // EtwEventId_ProcessCreate (1)
    RtlZeroMemory(fields, sizeof(fields));
    EsInitField(&fields[0],  "Timestamp",      EsType_UINT64,        0,  8, EsFieldFlag_None);
    EsInitField(&fields[1],  "ProcessId",      EsType_UINT32,        8,  4, EsFieldFlag_None);
    EsInitField(&fields[2],  "ThreadId",       EsType_UINT32,       12,  4, EsFieldFlag_None);
    EsInitField(&fields[3],  "SessionId",      EsType_UINT32,       16,  4, EsFieldFlag_None);
    EsInitField(&fields[4],  "ParentProcessId",EsType_UINT32,       24,  4, EsFieldFlag_None);
    EsInitField(&fields[5],  "Flags",          EsType_HEXINT32,     28,  4, EsFieldFlag_None);
    EsInitField(&fields[6],  "ThreatScore",    EsType_UINT32,       36,  4, EsFieldFlag_None);
    EsInitField(&fields[7],  "ImagePath",      EsType_UNICODESTRING, 0,  0, EsFieldFlag_VariableLength);
    EsInitField(&fields[8],  "CommandLine",    EsType_UNICODESTRING, 0,  0, EsFieldFlag_VariableLength);
    status = EsRegisterEventEx(Schema, EtwEventId_ProcessCreate, "ProcessCreate",
                               ETW_LEVEL_INFORMATIONAL, ETW_KEYWORD_PROCESS, 9, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_ProcessTerminate (2)
    RtlZeroMemory(fields, sizeof(fields));
    EsInitField(&fields[0],  "Timestamp",      EsType_UINT64,  0,  8, EsFieldFlag_None);
    EsInitField(&fields[1],  "ProcessId",      EsType_UINT32,  8,  4, EsFieldFlag_None);
    EsInitField(&fields[2],  "ExitCode",       EsType_UINT32, 32,  4, EsFieldFlag_None);
    status = EsRegisterEventEx(Schema, EtwEventId_ProcessTerminate, "ProcessTerminate",
                               ETW_LEVEL_INFORMATIONAL, ETW_KEYWORD_PROCESS, 3, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_ProcessSuspicious (3)
    RtlZeroMemory(fields, sizeof(fields));
    EsInitField(&fields[0],  "Timestamp",   EsType_UINT64,  0, 8, EsFieldFlag_None);
    EsInitField(&fields[1],  "ProcessId",   EsType_UINT32,  8, 4, EsFieldFlag_None);
    EsInitField(&fields[2],  "ThreatScore", EsType_UINT32, 36, 4, EsFieldFlag_None);
    EsInitField(&fields[3],  "ImagePath",   EsType_UNICODESTRING, 0, 0, EsFieldFlag_VariableLength);
    status = EsRegisterEventEx(Schema, EtwEventId_ProcessSuspicious, "ProcessSuspicious",
                               ETW_LEVEL_WARNING, ETW_KEYWORD_PROCESS | ETW_KEYWORD_THREAT, 4, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_ProcessBlocked (4)
    RtlZeroMemory(fields, sizeof(fields));
    EsInitField(&fields[0],  "Timestamp",   EsType_UINT64,  0, 8, EsFieldFlag_None);
    EsInitField(&fields[1],  "ProcessId",   EsType_UINT32,  8, 4, EsFieldFlag_None);
    EsInitField(&fields[2],  "ThreatScore", EsType_UINT32, 36, 4, EsFieldFlag_None);
    EsInitField(&fields[3],  "ImagePath",   EsType_UNICODESTRING, 0, 0, EsFieldFlag_VariableLength);
    status = EsRegisterEventEx(Schema, EtwEventId_ProcessBlocked, "ProcessBlocked",
                               ETW_LEVEL_WARNING, ETW_KEYWORD_PROCESS | ETW_KEYWORD_SECURITY, 4, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    //
    // â”€â”€ Thread Events â”€â”€
    //

    // EtwEventId_ThreadCreate (100)
    RtlZeroMemory(fields, sizeof(fields));
    EsInitField(&fields[0],  "Timestamp",       EsType_UINT64,  0,  8, EsFieldFlag_None);
    EsInitField(&fields[1],  "ProcessId",       EsType_UINT32,  8,  4, EsFieldFlag_None);
    EsInitField(&fields[2],  "ThreadId",        EsType_UINT32, 12,  4, EsFieldFlag_None);
    EsInitField(&fields[3],  "TargetProcessId", EsType_UINT32, 24,  4, EsFieldFlag_None);
    EsInitField(&fields[4],  "TargetThreadId",  EsType_UINT32, 28,  4, EsFieldFlag_None);
    EsInitField(&fields[5],  "StartAddress",    EsType_HEXINT64,32,  8, EsFieldFlag_None);
    status = EsRegisterEventEx(Schema, EtwEventId_ThreadCreate, "ThreadCreate",
                               ETW_LEVEL_VERBOSE, ETW_KEYWORD_THREAD, 6, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_RemoteThreadCreate (101)
    RtlZeroMemory(fields, sizeof(fields));
    EsInitField(&fields[0],  "Timestamp",       EsType_UINT64,  0,  8, EsFieldFlag_None);
    EsInitField(&fields[1],  "ProcessId",       EsType_UINT32,  8,  4, EsFieldFlag_None);
    EsInitField(&fields[2],  "TargetProcessId", EsType_UINT32, 24,  4, EsFieldFlag_None);
    EsInitField(&fields[3],  "StartAddress",    EsType_HEXINT64,32,  8, EsFieldFlag_None);
    EsInitField(&fields[4],  "ThreatScore",     EsType_UINT32, 40,  4, EsFieldFlag_None);
    status = EsRegisterEventEx(Schema, EtwEventId_RemoteThreadCreate, "RemoteThreadCreate",
                               ETW_LEVEL_WARNING, ETW_KEYWORD_THREAD | ETW_KEYWORD_THREAT, 5, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_ThreadSuspicious (102)
    RtlZeroMemory(fields, sizeof(fields));
    EsInitField(&fields[0],  "Timestamp",   EsType_UINT64,  0, 8, EsFieldFlag_None);
    EsInitField(&fields[1],  "ProcessId",   EsType_UINT32,  8, 4, EsFieldFlag_None);
    EsInitField(&fields[2],  "ThreatScore", EsType_UINT32, 40, 4, EsFieldFlag_None);
    EsInitField(&fields[3],  "ProcessPath", EsType_UNICODESTRING, 0, 0, EsFieldFlag_VariableLength);
    status = EsRegisterEventEx(Schema, EtwEventId_ThreadSuspicious, "ThreadSuspicious",
                               ETW_LEVEL_WARNING, ETW_KEYWORD_THREAD | ETW_KEYWORD_THREAT, 4, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    //
    // â”€â”€ Image Events â”€â”€
    //

    // EtwEventId_ImageLoad (200)
    RtlZeroMemory(fields, sizeof(fields));
    EsInitField(&fields[0],  "Timestamp",   EsType_UINT64,  0,  8, EsFieldFlag_None);
    EsInitField(&fields[1],  "ProcessId",   EsType_UINT32,  8,  4, EsFieldFlag_None);
    EsInitField(&fields[2],  "ImageBase",   EsType_HEXINT64,24,  8, EsFieldFlag_None);
    EsInitField(&fields[3],  "ImageSize",   EsType_UINT64,  32,  8, EsFieldFlag_None);
    EsInitField(&fields[4],  "ThreatScore", EsType_UINT32,  40,  4, EsFieldFlag_None);
    EsInitField(&fields[5],  "Flags",       EsType_HEXINT32,44,  4, EsFieldFlag_None);
    EsInitField(&fields[6],  "ImagePath",   EsType_UNICODESTRING, 0, 0, EsFieldFlag_VariableLength);
    status = EsRegisterEventEx(Schema, EtwEventId_ImageLoad, "ImageLoad",
                               ETW_LEVEL_VERBOSE, ETW_KEYWORD_IMAGE, 7, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_ImageSuspicious (201)
    RtlZeroMemory(fields, sizeof(fields));
    EsInitField(&fields[0],  "Timestamp",   EsType_UINT64,  0, 8, EsFieldFlag_None);
    EsInitField(&fields[1],  "ProcessId",   EsType_UINT32,  8, 4, EsFieldFlag_None);
    EsInitField(&fields[2],  "ThreatScore", EsType_UINT32, 40, 4, EsFieldFlag_None);
    EsInitField(&fields[3],  "ImagePath",   EsType_UNICODESTRING, 0, 0, EsFieldFlag_VariableLength);
    status = EsRegisterEventEx(Schema, EtwEventId_ImageSuspicious, "ImageSuspicious",
                               ETW_LEVEL_WARNING, ETW_KEYWORD_IMAGE | ETW_KEYWORD_THREAT, 4, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_ImageBlocked (202)
    RtlZeroMemory(fields, sizeof(fields));
    EsInitField(&fields[0],  "Timestamp",   EsType_UINT64,  0, 8, EsFieldFlag_None);
    EsInitField(&fields[1],  "ProcessId",   EsType_UINT32,  8, 4, EsFieldFlag_None);
    EsInitField(&fields[2],  "ThreatScore", EsType_UINT32, 40, 4, EsFieldFlag_None);
    EsInitField(&fields[3],  "ImagePath",   EsType_UNICODESTRING, 0, 0, EsFieldFlag_VariableLength);
    status = EsRegisterEventEx(Schema, EtwEventId_ImageBlocked, "ImageBlocked",
                               ETW_LEVEL_WARNING, ETW_KEYWORD_IMAGE | ETW_KEYWORD_SECURITY, 4, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    //
    // â”€â”€ File Events â”€â”€
    //

    // EtwEventId_FileCreate (300)
    RtlZeroMemory(fields, sizeof(fields));
    EsInitField(&fields[0],  "Timestamp",   EsType_UINT64,  0, 8, EsFieldFlag_None);
    EsInitField(&fields[1],  "ProcessId",   EsType_UINT32,  8, 4, EsFieldFlag_None);
    EsInitField(&fields[2],  "Operation",   EsType_UINT32, 24, 4, EsFieldFlag_None);
    EsInitField(&fields[3],  "Disposition",  EsType_UINT32, 28, 4, EsFieldFlag_None);
    EsInitField(&fields[4],  "FileSize",    EsType_UINT64, 32, 8, EsFieldFlag_None);
    EsInitField(&fields[5],  "ThreatScore", EsType_UINT32, 40, 4, EsFieldFlag_None);
    EsInitField(&fields[6],  "Verdict",     EsType_UINT32, 44, 4, EsFieldFlag_None);
    EsInitField(&fields[7],  "FilePath",    EsType_UNICODESTRING, 0, 0, EsFieldFlag_VariableLength);
    status = EsRegisterEventEx(Schema, EtwEventId_FileCreate, "FileCreate",
                               ETW_LEVEL_INFORMATIONAL, ETW_KEYWORD_FILE, 8, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_FileWrite (301) â€” same struct as FileCreate
    status = EsRegisterEventEx(Schema, EtwEventId_FileWrite, "FileWrite",
                               ETW_LEVEL_INFORMATIONAL, ETW_KEYWORD_FILE, 8, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_FileScanResult (302)
    status = EsRegisterEventEx(Schema, EtwEventId_FileScanResult, "FileScanResult",
                               ETW_LEVEL_INFORMATIONAL, ETW_KEYWORD_FILE | ETW_KEYWORD_THREAT, 8, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_FileBlocked (303)
    status = EsRegisterEventEx(Schema, EtwEventId_FileBlocked, "FileBlocked",
                               ETW_LEVEL_WARNING, ETW_KEYWORD_FILE | ETW_KEYWORD_SECURITY, 8, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_FileQuarantined (304)
    status = EsRegisterEventEx(Schema, EtwEventId_FileQuarantined, "FileQuarantined",
                               ETW_LEVEL_WARNING, ETW_KEYWORD_FILE | ETW_KEYWORD_SECURITY, 8, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    //
    // â”€â”€ Registry Events â”€â”€
    //

    // EtwEventId_RegistrySetValue (400)
    RtlZeroMemory(fields, sizeof(fields));
    EsInitField(&fields[0],  "Timestamp",   EsType_UINT64,  0, 8, EsFieldFlag_None);
    EsInitField(&fields[1],  "ProcessId",   EsType_UINT32,  8, 4, EsFieldFlag_None);
    EsInitField(&fields[2],  "Operation",   EsType_UINT32, 24, 4, EsFieldFlag_None);
    EsInitField(&fields[3],  "ThreatScore", EsType_UINT32, 28, 4, EsFieldFlag_None);
    EsInitField(&fields[4],  "KeyPath",     EsType_UNICODESTRING, 0, 0, EsFieldFlag_VariableLength);
    EsInitField(&fields[5],  "ValueName",   EsType_UNICODESTRING, 0, 0, EsFieldFlag_VariableLength);
    status = EsRegisterEventEx(Schema, EtwEventId_RegistrySetValue, "RegistrySetValue",
                               ETW_LEVEL_INFORMATIONAL, ETW_KEYWORD_REGISTRY, 6, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_RegistryDeleteValue (401)
    status = EsRegisterEventEx(Schema, EtwEventId_RegistryDeleteValue, "RegistryDeleteValue",
                               ETW_LEVEL_INFORMATIONAL, ETW_KEYWORD_REGISTRY, 6, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_RegistrySuspicious (402)
    status = EsRegisterEventEx(Schema, EtwEventId_RegistrySuspicious, "RegistrySuspicious",
                               ETW_LEVEL_WARNING, ETW_KEYWORD_REGISTRY | ETW_KEYWORD_THREAT, 6, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_RegistryBlocked (403)
    status = EsRegisterEventEx(Schema, EtwEventId_RegistryBlocked, "RegistryBlocked",
                               ETW_LEVEL_WARNING, ETW_KEYWORD_REGISTRY | ETW_KEYWORD_SECURITY, 6, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    //
    // â”€â”€ Memory Events â”€â”€
    //

    // EtwEventId_MemoryAllocation (500)
    RtlZeroMemory(fields, sizeof(fields));
    EsInitField(&fields[0],  "Timestamp",       EsType_UINT64,   0,  8, EsFieldFlag_None);
    EsInitField(&fields[1],  "ProcessId",       EsType_UINT32,   8,  4, EsFieldFlag_None);
    EsInitField(&fields[2],  "TargetProcessId", EsType_UINT32,  24,  4, EsFieldFlag_None);
    EsInitField(&fields[3],  "AlertType",       EsType_UINT32,  28,  4, EsFieldFlag_None);
    EsInitField(&fields[4],  "BaseAddress",     EsType_HEXINT64,32,  8, EsFieldFlag_None);
    EsInitField(&fields[5],  "RegionSize",      EsType_UINT64,  40,  8, EsFieldFlag_None);
    EsInitField(&fields[6],  "Protection",      EsType_HEXINT32,48,  4, EsFieldFlag_None);
    EsInitField(&fields[7],  "ThreatScore",     EsType_UINT32,  52,  4, EsFieldFlag_None);
    EsInitField(&fields[8],  "ProcessPath",     EsType_UNICODESTRING, 0, 0, EsFieldFlag_VariableLength);
    status = EsRegisterEventEx(Schema, EtwEventId_MemoryAllocation, "MemoryAllocation",
                               ETW_LEVEL_VERBOSE, ETW_KEYWORD_MEMORY, 9, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_MemoryProtectionChange (501)
    status = EsRegisterEventEx(Schema, EtwEventId_MemoryProtectionChange, "MemoryProtectionChange",
                               ETW_LEVEL_INFORMATIONAL, ETW_KEYWORD_MEMORY, 9, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_ShellcodeDetected (502)
    status = EsRegisterEventEx(Schema, EtwEventId_ShellcodeDetected, "ShellcodeDetected",
                               ETW_LEVEL_WARNING, ETW_KEYWORD_MEMORY | ETW_KEYWORD_THREAT, 9, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_InjectionDetected (503)
    status = EsRegisterEventEx(Schema, EtwEventId_InjectionDetected, "InjectionDetected",
                               ETW_LEVEL_WARNING, ETW_KEYWORD_MEMORY | ETW_KEYWORD_THREAT, 9, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_HollowingDetected (504)
    status = EsRegisterEventEx(Schema, EtwEventId_HollowingDetected, "HollowingDetected",
                               ETW_LEVEL_WARNING, ETW_KEYWORD_MEMORY | ETW_KEYWORD_THREAT, 9, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    //
    // â”€â”€ Network Events â”€â”€
    //

    // EtwEventId_NetworkConnect (600)
    RtlZeroMemory(fields, sizeof(fields));
    EsInitField(&fields[0],  "Timestamp",      EsType_UINT64,   0,   8, EsFieldFlag_None);
    EsInitField(&fields[1],  "ProcessId",      EsType_UINT32,   8,   4, EsFieldFlag_None);
    EsInitField(&fields[2],  "Protocol",       EsType_UINT32,  24,   4, EsFieldFlag_None);
    EsInitField(&fields[3],  "Direction",      EsType_UINT32,  28,   4, EsFieldFlag_None);
    EsInitField(&fields[4],  "LocalPort",      EsType_UINT16,  32,   2, EsFieldFlag_None);
    EsInitField(&fields[5],  "RemotePort",     EsType_UINT16,  34,   2, EsFieldFlag_None);
    EsInitField(&fields[6],  "LocalIpV4",      EsType_IPV4,    36,   4, EsFieldFlag_None);
    EsInitField(&fields[7],  "RemoteIpV4",     EsType_IPV4,    40,   4, EsFieldFlag_None);
    EsInitField(&fields[8],  "LocalIpV6",      EsType_IPV6,    44,  16, EsFieldFlag_FixedCount);
    EsInitField(&fields[9],  "RemoteIpV6",     EsType_IPV6,    60,  16, EsFieldFlag_FixedCount);
    EsInitField(&fields[10], "BytesSent",      EsType_UINT64,  76,   8, EsFieldFlag_None);
    EsInitField(&fields[11], "BytesReceived",  EsType_UINT64,  84,   8, EsFieldFlag_None);
    EsInitField(&fields[12], "ThreatScore",    EsType_UINT32,  92,   4, EsFieldFlag_None);
    EsInitField(&fields[13], "ThreatType",     EsType_UINT32,  96,   4, EsFieldFlag_None);
    EsInitField(&fields[14], "RemoteHostname", EsType_UNICODESTRING, 0, 0, EsFieldFlag_VariableLength);
    status = EsRegisterEventEx(Schema, EtwEventId_NetworkConnect, "NetworkConnect",
                               ETW_LEVEL_INFORMATIONAL, ETW_KEYWORD_NETWORK, 15, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_NetworkListen (601) â€” same layout
    status = EsRegisterEventEx(Schema, EtwEventId_NetworkListen, "NetworkListen",
                               ETW_LEVEL_INFORMATIONAL, ETW_KEYWORD_NETWORK, 15, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_DnsQuery (602)
    RtlZeroMemory(fields, sizeof(fields));
    EsInitField(&fields[0],  "Timestamp",    EsType_UINT64,  0, 8, EsFieldFlag_None);
    EsInitField(&fields[1],  "ProcessId",    EsType_UINT32,  8, 4, EsFieldFlag_None);
    EsInitField(&fields[2],  "RemoteIpV4",   EsType_IPV4,   40, 4, EsFieldFlag_None);
    EsInitField(&fields[3],  "ThreatScore",  EsType_UINT32, 92, 4, EsFieldFlag_None);
    EsInitField(&fields[4],  "Hostname",     EsType_UNICODESTRING, 0, 0, EsFieldFlag_VariableLength);
    status = EsRegisterEventEx(Schema, EtwEventId_DnsQuery, "DnsQuery",
                               ETW_LEVEL_INFORMATIONAL, ETW_KEYWORD_NETWORK, 5, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_C2Detected (603) â€” uses full NetworkConnect layout (15 fields)
    RtlZeroMemory(fields, sizeof(fields));
    EsInitField(&fields[0],  "Timestamp",      EsType_UINT64,   0,   8, EsFieldFlag_None);
    EsInitField(&fields[1],  "ProcessId",      EsType_UINT32,   8,   4, EsFieldFlag_None);
    EsInitField(&fields[2],  "Protocol",       EsType_UINT32,  24,   4, EsFieldFlag_None);
    EsInitField(&fields[3],  "Direction",      EsType_UINT32,  28,   4, EsFieldFlag_None);
    EsInitField(&fields[4],  "LocalPort",      EsType_UINT16,  32,   2, EsFieldFlag_None);
    EsInitField(&fields[5],  "RemotePort",     EsType_UINT16,  34,   2, EsFieldFlag_None);
    EsInitField(&fields[6],  "LocalIpV4",      EsType_IPV4,    36,   4, EsFieldFlag_None);
    EsInitField(&fields[7],  "RemoteIpV4",     EsType_IPV4,    40,   4, EsFieldFlag_None);
    EsInitField(&fields[8],  "LocalIpV6",      EsType_IPV6,    44,  16, EsFieldFlag_FixedCount);
    EsInitField(&fields[9],  "RemoteIpV6",     EsType_IPV6,    60,  16, EsFieldFlag_FixedCount);
    EsInitField(&fields[10], "BytesSent",      EsType_UINT64,  76,   8, EsFieldFlag_None);
    EsInitField(&fields[11], "BytesReceived",  EsType_UINT64,  84,   8, EsFieldFlag_None);
    EsInitField(&fields[12], "ThreatScore",    EsType_UINT32,  92,   4, EsFieldFlag_None);
    EsInitField(&fields[13], "ThreatType",     EsType_UINT32,  96,   4, EsFieldFlag_None);
    EsInitField(&fields[14], "RemoteHostname", EsType_UNICODESTRING, 0, 0, EsFieldFlag_VariableLength);
    status = EsRegisterEventEx(Schema, EtwEventId_C2Detected, "C2Detected",
                               ETW_LEVEL_WARNING, ETW_KEYWORD_NETWORK | ETW_KEYWORD_THREAT, 15, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_ExfiltrationDetected (604)
    status = EsRegisterEventEx(Schema, EtwEventId_ExfiltrationDetected, "ExfiltrationDetected",
                               ETW_LEVEL_WARNING, ETW_KEYWORD_NETWORK | ETW_KEYWORD_THREAT, 15, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_NetworkBlocked (605)
    status = EsRegisterEventEx(Schema, EtwEventId_NetworkBlocked, "NetworkBlocked",
                               ETW_LEVEL_WARNING, ETW_KEYWORD_NETWORK | ETW_KEYWORD_SECURITY, 15, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    //
    // â”€â”€ Behavior Events â”€â”€
    //

    // EtwEventId_BehaviorAlert (700)
    RtlZeroMemory(fields, sizeof(fields));
    EsInitField(&fields[0],  "Timestamp",       EsType_UINT64,  0,  8, EsFieldFlag_None);
    EsInitField(&fields[1],  "ProcessId",       EsType_UINT32,  8,  4, EsFieldFlag_None);
    EsInitField(&fields[2],  "BehaviorType",    EsType_UINT32, 24,  4, EsFieldFlag_None);
    EsInitField(&fields[3],  "Category",        EsType_UINT32, 28,  4, EsFieldFlag_None);
    EsInitField(&fields[4],  "ThreatScore",     EsType_UINT32, 32,  4, EsFieldFlag_None);
    EsInitField(&fields[5],  "Confidence",      EsType_UINT32, 36,  4, EsFieldFlag_None);
    EsInitField(&fields[6],  "ChainId",         EsType_UINT64, 40,  8, EsFieldFlag_None);
    EsInitField(&fields[7],  "MitreTechnique",  EsType_UINT32, 48,  4, EsFieldFlag_None);
    EsInitField(&fields[8],  "MitreTactic",     EsType_UINT32, 52,  4, EsFieldFlag_None);
    EsInitField(&fields[9],  "ProcessPath",     EsType_UNICODESTRING, 0, 0, EsFieldFlag_VariableLength);
    EsInitField(&fields[10], "Description",     EsType_UNICODESTRING, 0, 0, EsFieldFlag_VariableLength);
    status = EsRegisterEventEx(Schema, EtwEventId_BehaviorAlert, "BehaviorAlert",
                               ETW_LEVEL_WARNING, ETW_KEYWORD_BEHAVIOR, 11, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_AttackChainStarted (701)
    status = EsRegisterEventEx(Schema, EtwEventId_AttackChainStarted, "AttackChainStarted",
                               ETW_LEVEL_WARNING, ETW_KEYWORD_BEHAVIOR | ETW_KEYWORD_THREAT, 11, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_AttackChainUpdated (702)
    status = EsRegisterEventEx(Schema, EtwEventId_AttackChainUpdated, "AttackChainUpdated",
                               ETW_LEVEL_WARNING, ETW_KEYWORD_BEHAVIOR | ETW_KEYWORD_THREAT, 11, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_AttackChainCompleted (703)
    status = EsRegisterEventEx(Schema, EtwEventId_AttackChainCompleted, "AttackChainCompleted",
                               ETW_LEVEL_WARNING, ETW_KEYWORD_BEHAVIOR | ETW_KEYWORD_THREAT, 11, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_MitreDetection (704)
    status = EsRegisterEventEx(Schema, EtwEventId_MitreDetection, "MitreDetection",
                               ETW_LEVEL_WARNING, ETW_KEYWORD_BEHAVIOR | ETW_KEYWORD_THREAT, 11, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    //
    // â”€â”€ Security Alert Events â”€â”€
    //

    // EtwEventId_TamperAttempt (800)
    RtlZeroMemory(fields, sizeof(fields));
    EsInitField(&fields[0],  "Timestamp",        EsType_UINT64,  0,  8, EsFieldFlag_None);
    EsInitField(&fields[1],  "ProcessId",        EsType_UINT32,  8,  4, EsFieldFlag_None);
    EsInitField(&fields[2],  "AlertType",        EsType_UINT32, 24,  4, EsFieldFlag_None);
    EsInitField(&fields[3],  "Severity",         EsType_UINT32, 28,  4, EsFieldFlag_None);
    EsInitField(&fields[4],  "ThreatScore",      EsType_UINT32, 32,  4, EsFieldFlag_None);
    EsInitField(&fields[5],  "ResponseAction",   EsType_UINT32, 36,  4, EsFieldFlag_None);
    EsInitField(&fields[6],  "ChainId",          EsType_UINT64, 40,  8, EsFieldFlag_None);
    EsInitField(&fields[7],  "AlertTitle",       EsType_UNICODESTRING, 0, 0, EsFieldFlag_VariableLength);
    EsInitField(&fields[8],  "AlertDescription", EsType_UNICODESTRING, 0, 0, EsFieldFlag_VariableLength);
    EsInitField(&fields[9],  "ProcessPath",      EsType_UNICODESTRING, 0, 0, EsFieldFlag_VariableLength);
    EsInitField(&fields[10], "TargetPath",       EsType_UNICODESTRING, 0, 0, EsFieldFlag_VariableLength);
    status = EsRegisterEventEx(Schema, EtwEventId_TamperAttempt, "TamperAttempt",
                               ETW_LEVEL_CRITICAL, ETW_KEYWORD_SECURITY, 11, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_EvasionAttempt (801)
    status = EsRegisterEventEx(Schema, EtwEventId_EvasionAttempt, "EvasionAttempt",
                               ETW_LEVEL_WARNING, ETW_KEYWORD_SECURITY | ETW_KEYWORD_THREAT, 11, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_DirectSyscall (802)
    status = EsRegisterEventEx(Schema, EtwEventId_DirectSyscall, "DirectSyscall",
                               ETW_LEVEL_WARNING, ETW_KEYWORD_SECURITY | ETW_KEYWORD_THREAT, 11, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_PrivilegeEscalation (803)
    status = EsRegisterEventEx(Schema, EtwEventId_PrivilegeEscalation, "PrivilegeEscalation",
                               ETW_LEVEL_CRITICAL, ETW_KEYWORD_SECURITY | ETW_KEYWORD_THREAT, 11, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_CredentialAccess (804)
    status = EsRegisterEventEx(Schema, EtwEventId_CredentialAccess, "CredentialAccess",
                               ETW_LEVEL_CRITICAL, ETW_KEYWORD_SECURITY | ETW_KEYWORD_THREAT, 11, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    //
    // â”€â”€ Diagnostic Events â”€â”€
    //

    // EtwEventId_DriverStarted (900)
    RtlZeroMemory(fields, sizeof(fields));
    EsInitField(&fields[0],  "Timestamp",   EsType_UINT64,  0, 8, EsFieldFlag_None);
    EsInitField(&fields[1],  "ComponentId", EsType_UINT32, 24, 4, EsFieldFlag_None);
    EsInitField(&fields[2],  "ErrorCode",   EsType_HEXINT32,28, 4, EsFieldFlag_None);
    EsInitField(&fields[3],  "Message",     EsType_UNICODESTRING, 0, 0, EsFieldFlag_VariableLength | EsFieldFlag_Optional);
    status = EsRegisterEventEx(Schema, EtwEventId_DriverStarted, "DriverStarted",
                               ETW_LEVEL_INFORMATIONAL, ETW_KEYWORD_DIAGNOSTIC, 4, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_DriverStopping (901)
    status = EsRegisterEventEx(Schema, EtwEventId_DriverStopping, "DriverStopping",
                               ETW_LEVEL_INFORMATIONAL, ETW_KEYWORD_DIAGNOSTIC, 4, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_Heartbeat (902)
    status = EsRegisterEventEx(Schema, EtwEventId_Heartbeat, "Heartbeat",
                               ETW_LEVEL_VERBOSE, ETW_KEYWORD_DIAGNOSTIC | ETW_KEYWORD_TELEMETRY, 4, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_PerformanceStats (903)
    status = EsRegisterEventEx(Schema, EtwEventId_PerformanceStats, "PerformanceStats",
                               ETW_LEVEL_VERBOSE, ETW_KEYWORD_DIAGNOSTIC | ETW_KEYWORD_TELEMETRY, 4, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_ComponentHealth (904)
    status = EsRegisterEventEx(Schema, EtwEventId_ComponentHealth, "ComponentHealth",
                               ETW_LEVEL_WARNING, ETW_KEYWORD_DIAGNOSTIC, 4, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

    // EtwEventId_Error (905)
    status = EsRegisterEventEx(Schema, EtwEventId_Error, "Error",
                               ETW_LEVEL_ERROR, ETW_KEYWORD_DIAGNOSTIC, 4, fields);
    if (NT_SUCCESS(status)) registered++; else failed++;

#undef ES_REG_KEYWORD
#undef ES_REG_TASK
#undef ES_REG_CHANNEL

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] EventSchema: Registered %lu events, %lu failures\n",
               registered, failed);

    return (registered > 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

// ============================================================================
// BOOT-STEP BREADCRUMB LOGGING
// ============================================================================

/**
 * @brief Write current initialization step to the registry.
 *
 * Persists the step number as DWORD "LastInitStep" under the driver's
 * Parameters key. Because registry writes survive BSODs, the last
 * written value pinpoints exactly which init step the crash occurred
 * AFTER. Read with:
 *   reg query "HKLM\SYSTEM\CurrentControlSet\Services\PhantomSensor\Parameters" /v LastInitStep
 *
 * @param RegistryPath  Service key path supplied by the I/O manager.
 * @param Step          Monotonic step number (see comments in DriverEntry).
 */
static VOID
ShadowStrikeLogBootStep(
    _In_ PUNICODE_STRING RegistryPath,
    _In_ ULONG Step
    )
{
    HANDLE serviceKey = NULL;
    HANDLE paramsKey = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING subKeyName = RTL_CONSTANT_STRING(L"Parameters");
    UNICODE_STRING valueName = RTL_CONSTANT_STRING(L"LastInitStep");
    NTSTATUS st;

    InitializeObjectAttributes(
        &oa, RegistryPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL, NULL);

    st = ZwOpenKey(&serviceKey, KEY_CREATE_SUB_KEY, &oa);
    if (!NT_SUCCESS(st)) {
        return;
    }

    InitializeObjectAttributes(
        &oa, &subKeyName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        serviceKey, NULL);

    st = ZwCreateKey(
        &paramsKey, KEY_SET_VALUE, &oa,
        0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (!NT_SUCCESS(st)) {
        ZwClose(serviceKey);
        return;
    }

    ZwSetValueKey(paramsKey, &valueName, 0, REG_DWORD, &Step, sizeof(Step));
    ZwFlushKey(paramsKey);

    ZwClose(paramsKey);
    ZwClose(serviceKey);
}

// ============================================================================
// POST-INIT WORK QUEUE (v1.0.13.0 — winlogon grey-screen fix)
// ============================================================================

/**
 * @brief Internal post-init queue entry.
 */
typedef struct _SHADOWSTRIKE_POST_INIT_ITEM {
    LIST_ENTRY                  ListEntry;
    PFN_SHADOWSTRIKE_POST_INIT  Callback;
    PVOID                       Context;
} SHADOWSTRIKE_POST_INIT_ITEM, *PSHADOWSTRIKE_POST_INIT_ITEM;

#define SHADOWSTRIKE_POST_INIT_TAG  'IPSS'  // "SSPI"

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeQueuePostInitWork(
    _In_ PFN_SHADOWSTRIKE_POST_INIT Callback,
    _In_opt_ PVOID Context
    )
{
    PSHADOWSTRIKE_POST_INIT_ITEM item;
    KIRQL oldIrql;
    BOOLEAN runInline = FALSE;

    if (Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Fast path: if the queue is already drained, the driver is operational
    // and we can simply invoke the callback inline. This is also the path
    // taken by any post-boot caller (e.g., late-loaded sub-modules).
    //
    // NOTE: PostInitDrained is set to 1 by ShadowStrikeDrainPostInitWork()
    // strictly AFTER the queue has been emptied under the spinlock, so an
    // observed value of 1 here implies no pending drain can touch our item.
    //
    if (InterlockedCompareExchange(&g_DriverData.PostInitDrained, 0, 0) != 0) {
        //
        // Drain already happened. Must be PASSIVE_LEVEL for inline invoke.
        // Callers at DISPATCH_LEVEL should not normally reach this — but
        // if they do, route through a fresh allocation so we don't violate
        // the IRQL contract of the callback.
        //
        if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
            Callback(Context);
            return STATUS_SUCCESS;
        }
        //
        // Fall through to enqueue path even though drained — the next drain
        // (or an explicit one) will pick it up. In practice this branch is
        // exceptional; we still want a deterministic enqueue to avoid loss.
        //
    }

    item = (PSHADOWSTRIKE_POST_INIT_ITEM)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(SHADOWSTRIKE_POST_INIT_ITEM),
        SHADOWSTRIKE_POST_INIT_TAG);

    if (item == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] PostInitWork: allocation failed\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    item->Callback = Callback;
    item->Context  = Context;

    KeAcquireSpinLock(&g_DriverData.PostInitWorkLock, &oldIrql);

    if (InterlockedCompareExchange(&g_DriverData.PostInitDrained, 0, 0) != 0) {
        //
        // Race: drain completed between our outer check and the lock acquire.
        // Run inline at PASSIVE_LEVEL only.
        //
        runInline = (KeGetCurrentIrql() == PASSIVE_LEVEL);
    }

    if (!runInline) {
        InsertTailList(&g_DriverData.PostInitWorkList, &item->ListEntry);
    }

    KeReleaseSpinLock(&g_DriverData.PostInitWorkLock, oldIrql);

    if (runInline) {
        Callback(Context);
        ExFreePoolWithTag(item, SHADOWSTRIKE_POST_INIT_TAG);
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShadowStrikeDrainPostInitWork(VOID)
{
    LIST_ENTRY localList;
    KIRQL oldIrql;
    ULONG drained = 0;

    PAGED_CODE();

    InitializeListHead(&localList);

    //
    // Detach the queue under the spinlock so concurrent producers either
    // see the empty post-drain queue (and follow the inline path) or
    // append to a queue that we will drain on the next pass. We loop
    // until we observe an empty queue while holding the lock.
    //
    for (;;) {
        BOOLEAN gotItems = FALSE;

        KeAcquireSpinLock(&g_DriverData.PostInitWorkLock, &oldIrql);

        if (!IsListEmpty(&g_DriverData.PostInitWorkList)) {
            PLIST_ENTRY head = g_DriverData.PostInitWorkList.Flink;
            PLIST_ENTRY tail = g_DriverData.PostInitWorkList.Blink;

            //
            // Splice the entire list into our local list, then re-init
            // the global list. This is the standard kernel idiom for
            // an atomic list-steal under a spinlock.
            //
            head->Blink = &localList;
            tail->Flink = &localList;
            localList.Flink = head;
            localList.Blink = tail;

            InitializeListHead(&g_DriverData.PostInitWorkList);
            gotItems = TRUE;
        } else {
            //
            // No more items. Mark drained while still holding the lock
            // so concurrent producers see the transition atomically.
            //
            InterlockedExchange(&g_DriverData.PostInitDrained, 1);
        }

        KeReleaseSpinLock(&g_DriverData.PostInitWorkLock, oldIrql);

        if (!gotItems) {
            break;
        }

        while (!IsListEmpty(&localList)) {
            PLIST_ENTRY entry = RemoveHeadList(&localList);
            PSHADOWSTRIKE_POST_INIT_ITEM item =
                CONTAINING_RECORD(entry, SHADOWSTRIKE_POST_INIT_ITEM, ListEntry);

            __try {
                item->Callback(item->Context);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[ShadowStrike] PostInitWork: callback %p faulted "
                           "(code 0x%08X) — continuing drain\n",
                           item->Callback, GetExceptionCode());
            }

            ExFreePoolWithTag(item, SHADOWSTRIKE_POST_INIT_TAG);
            drained++;
        }
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] PostInitWork: drained %lu deferred item(s)\n",
               drained);
}

// ============================================================================
// DRIVER ENTRY
// ============================================================================

/**
 * @brief Main driver entry point.
 *
 * Initialization order is critical for correctness and safety.
 * On any CRITICAL failure, cleanup is performed precisely based on
 * what was actually initialized.
 */
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG buildNumber = 0;

    //
    // Diagnostic: validate ThreadPool->ThreadList integrity after each init step.
    // Set to 0 to disable once root cause found. Tag identifies the step.
    //
#define TP_VALIDATE_AFTER_STEP(stepTag) \
    do { \
        if (g_ThreadPool != NULL) { \
            if (!TpValidateThreadList(g_ThreadPool, stepTag)) { \
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
                    "[ShadowStrike] *** THREAD LIST CORRUPTION DETECTED AFTER %s ***\n", stepTag); \
            } \
        } \
    } while (0)

    //
    // Boot-step breadcrumb: Step 0 = DriverEntry entered.
    // After a BSOD, read the registry to find the last completed step:
    //   reg query "HKLM\SYSTEM\CurrentControlSet\Services\PhantomSensor\Parameters" /v LastInitStep
    //
    // Step Map:
    //   0  = DriverEntry entered
    //   1  = Version check passed
    //   2  = Global state zeroed
    //   3  = WPP + Lock subsystem
    //   5  = Lookaside lists
    //   6  = Sync infrastructure (WorkQueue..DPC)
    //   7  = Perf + Throttling + Batch
    //   8  = Power + ETW + Telemetry
    //   9  = Compression
    //  10  = FltRegisterFilter
    //  11  = CommPort
    //  12  = Telemetry Events + Schema + Manifest
    //  13  = ScanCache + Exclusions + Hash/File Utils
    //  14  = BehaviorEngine + Memory + Syscall
    //  15  = NetworkFilter
    //  16  = Process/Thread/Image callbacks
    //  17  = Registry + Object callbacks
    //  18  = Self-protection suite
    //  19  = ELAM + Handle/Integrity/AntiDebug
    //  20  = FileProtection + Callback + ALPC + KTM
    //  21  = ThreatScoring + Perf + Power bridge
    //  22  = FSC + PostCreate + PostWrite init
    //  23  = PreAcquire + PreCreate + PreSetInfo + PreWrite init
    //  24  = FltStartFiltering
    //  25  = Init complete (driver READY)
    //  26  = FullyOperational gate set (post-init periodic workers running)
    //
    ShadowStrikeLogBootStep(RegistryPath, 0);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] DriverEntry: Starting initialization (v%u.%u.%u)\n",
               SHADOWSTRIKE_VERSION_MAJOR,
               SHADOWSTRIKE_VERSION_MINOR,
               SHADOWSTRIKE_VERSION_BUILD);

    //
    // Step 1: Check Windows version compatibility
    //
    status = ShadowStrikeCheckVersionCompatibility(&buildNumber);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Windows version check failed. Build %lu required, current build incompatible.\n",
                   (ULONG)SHADOWSTRIKE_MIN_BUILD_NUMBER);
        return status;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Windows build %lu detected, compatibility verified.\n",
               buildNumber);

    ShadowStrikeLogBootStep(RegistryPath, 1); // Version check passed

    //
    // Step 2: Initialize global state
    //
    RtlZeroMemory(&g_DriverData, sizeof(SHADOWSTRIKE_DRIVER_DATA));
    g_DriverData.DriverObject = DriverObject;
    g_InitFlags = InitFlag_None;
    g_CallbackFlags = 0;

    KeInitializeEvent(&g_DriverData.UnloadEvent, NotificationEvent, FALSE);
    ExInitializePushLock(&g_DriverData.ClientPortLock);
    ExInitializePushLock(&g_DriverData.ConfigLock);
    ExInitializePushLock(&g_DriverData.ProtectedProcessLock);

    InitializeListHead(&g_DriverData.ProtectedProcessList);

    //
    // Step 2.1: Boot-phase tracking initialization (v1.0.13.0).
    //
    // Capture the performance-counter tick at the start of DriverEntry and
    // compute the 90-second boot-grace deadline. All callback modules use
    // ShadowStrikeInBootGrace() to skip expensive scanning during early boot,
    // and ShadowStrikeIsFullyOperational() to skip ALL work until the driver
    // has transitioned to fully operational.
    //
    // FullyOperational is set to 0 here and flipped to 1 strictly AFTER
    // FltStartFiltering returns success AND the CommPort is created.
    //
    InterlockedExchange(&g_DriverData.FullyOperational, 0);
    InterlockedExchange(&g_DriverData.PostInitDrained, 0);
    KeInitializeSpinLock(&g_DriverData.PostInitWorkLock);
    InitializeListHead(&g_DriverData.PostInitWorkList);

    g_DriverData.BootPhaseStartTick = KeQueryPerformanceCounter(&g_DriverData.PerfFrequency);
    {
        //
        // BootGraceUntilTick = now + 90 seconds. Use cached frequency.
        // PerfFrequency.QuadPart is guaranteed non-zero on Windows >= XP.
        //
        LONGLONG ticksPerSecond = g_DriverData.PerfFrequency.QuadPart;
        if (ticksPerSecond <= 0) {
            //
            // Defensive: paranoia path. Should not happen on supported builds.
            // Use a conservative fallback of 10 MHz so the grace window
            // still exists rather than collapsing to zero.
            //
            ticksPerSecond = 10000000LL;
        }
        g_DriverData.BootGraceUntilTick.QuadPart =
            g_DriverData.BootPhaseStartTick.QuadPart + (ticksPerSecond * 90LL);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Boot-phase tracking armed: StartTick=0x%llX "
               "GraceUntil=0x%llX Freq=%lld Hz (90s grace window)\n",
               g_DriverData.BootPhaseStartTick.QuadPart,
               g_DriverData.BootGraceUntilTick.QuadPart,
               g_DriverData.PerfFrequency.QuadPart);

    //
    // Step 2.4: Initialize WPP tracing (earliest possible, before any trace calls)
    //
    status = WppTraceInitialize(DriverObject, RegistryPath);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: WPP tracing init failed: 0x%08X (continuing without tracing)\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_InitFlags |= InitFlag_WppTracing;
    }

    //
    // Step 2.5: Initialize lock subsystem (must be before any module using enhanced locks)
    //
    status = ShadowStrikeLockSubsystemInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Lock subsystem init failed: 0x%08X (continuing with native locks)\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_SubsystemFlags |= SubsysFlag_SpinLockSubsystem;
    }

    //
    // Step 3: Initialize rundown protection (CRITICAL for safe unload)
    //
    ExInitializeRundownProtection(&g_DriverData.RundownProtection);
    g_InitFlags |= InitFlag_RundownInitialized;

    //
    // Step 4: Load configuration from registry (with defaults fallback)
    //
    status = ShadowStrikeLoadConfiguration(RegistryPath, &g_DriverData.Config);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Failed to load registry config: 0x%08X, using defaults.\n",
                   status);
        ShadowStrikeInitDefaultConfig(&g_DriverData.Config);
        status = STATUS_SUCCESS;
    }

    // Record start time
    KeQuerySystemTime(&g_DriverData.Stats.StartTime);

    //
    // Step 4.5: Initialize memory utilities (foundational â€” must precede all allocations)
    //
    status = ShadowStrikeInitializeMemoryUtils();
    if (!NT_SUCCESS(status) && status != STATUS_ALREADY_INITIALIZED) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] CRITICAL: Failed to initialize memory utilities: 0x%08X\n",
                   status);
        goto Cleanup;
    }
    status = STATUS_SUCCESS;

    //
    // Step 4.6: Initialize process utilities (creating context table, function
    // pointer resolution). Must precede ProcessNotify registration so the
    // context hash table is ready to receive Store calls at process creation.
    //
    status = ShadowProcessUtilsInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize process utilities: 0x%08X\n",
                   status);
        // Non-fatal: lazy init will retry on first use. Continue.
        status = STATUS_SUCCESS;
    } else {
        g_ProcessUtilsInitialized = TRUE;
    }

    //
    // Step 5: Initialize lookaside lists for memory allocation
    //
    status = ShadowStrikeInitializeLookasideLists();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] CRITICAL: Failed to initialize lookaside lists: 0x%08X\n",
                   status);
        goto Cleanup;
    }
    g_InitFlags |= InitFlag_LookasideLists;
    g_DriverData.LookasideInitialized = TRUE;
    ShadowStrikeLogInitStatus("Lookaside Lists", status);

    ShadowStrikeLogBootStep(RegistryPath, 5); // Lookaside lists ready

    // =========================================================================
    // PHASE 1A: Synchronization Infrastructure
    // =========================================================================

    //
    // Step 5.1: Initialize work queue (singleton â€” provides work item dispatch)
    //
    status = ShadowStrikeWorkQueueInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize work queue: 0x%08X (continuing)\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_SubsystemFlags |= SubsysFlag_WorkQueue;
        ShadowStrikeLogInitStatus("Work Queue", STATUS_SUCCESS);
    }

    //
    // Step 5.2: Initialize thread pool (managed worker threads)
    //
    status = TpCreateDefault(
        &g_ThreadPool,
        2,      // MinThreads: 2 workers minimum
        8,      // MaxThreads: 8 workers maximum (scales with load)
        NULL    // DeviceObject: not required for WDM driver
    );
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize thread pool: 0x%08X (continuing)\n",
                   status);
        g_ThreadPool = NULL;
        status = STATUS_SUCCESS;
    } else {
        g_SubsystemFlags |= SubsysFlag_ThreadPool;
        ShadowStrikeLogInitStatus("Thread Pool", STATUS_SUCCESS);
    }
    TP_VALIDATE_AFTER_STEP("5.2-ThreadPool");

    //
    // Step 5.3: Initialize async work queue (deferred async processing)
    //
    status = AwqInitialize(
        &g_AsyncWorkQueue,
        1,      // MinThreads: 1 worker
        4,      // MaxThreads: 4 workers
        4096    // MaxQueueSize: cap to prevent unbounded growth
    );
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize async work queue: 0x%08X (continuing)\n",
                   status);
        g_AsyncWorkQueue = NULL;
        status = STATUS_SUCCESS;
    } else {
        g_SubsystemFlags |= SubsysFlag_AsyncWorkQueue;
        ShadowStrikeLogInitStatus("Async Work Queue", STATUS_SUCCESS);
    }
    TP_VALIDATE_AFTER_STEP("5.3-AsyncWorkQueue");

    //
    // Step 5.4: Create control device for TimerManager work items.
    // IoAllocateWorkItem (used by TmFlag_WorkItemCallback) requires a valid
    // DEVICE_OBJECT. FltRegisterFilter hasn't happened yet, so we create a
    // lightweight control device here. This must happen BEFORE TmInitialize
    // so all subsequent TmCreatePeriodic calls in Phase 5.x work correctly.
    //
    {
        PDEVICE_OBJECT controlDevice = NULL;
        NTSTATUS devStatus = IoCreateDevice(
            DriverObject,
            0,                          // No device extension
            NULL,                       // No device name (internal use only)
            FILE_DEVICE_UNKNOWN,
            FILE_DEVICE_SECURE_OPEN,
            FALSE,                      // Not exclusive
            &controlDevice
        );
        if (NT_SUCCESS(devStatus)) {
            g_TimerControlDevice = controlDevice;
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] WARNING: Failed to create timer control device: 0x%08X\n"
                       "    TimerManager work-item callbacks will be unavailable.\n",
                       devStatus);
            g_TimerControlDevice = NULL;
        }
    }

    //
    // Step 5.5: Initialize timer manager (centralized timer management)
    //
    status = TmInitialize(g_TimerControlDevice, &g_TimerManager);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize timer manager: 0x%08X (continuing)\n",
                   status);
        g_TimerManager = NULL;
        status = STATUS_SUCCESS;
    } else {
        g_SubsystemFlags |= SubsysFlag_TimerManager;
        ShadowStrikeLogInitStatus("Timer Manager", STATUS_SUCCESS);
    }
    TP_VALIDATE_AFTER_STEP("5.5-TimerManager");

    //
    // Step 5.5: Initialize DPC manager (deferred procedure call management)
    //
    status = DpcInitialize(&g_DpcManager, 64);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize DPC manager: 0x%08X (continuing)\n",
                   status);
        g_DpcManager = NULL;
        status = STATUS_SUCCESS;
    } else {
        g_SubsystemFlags |= SubsysFlag_DeferredProcedure;
        ShadowStrikeLogInitStatus("DPC Manager", STATUS_SUCCESS);
    }
    TP_VALIDATE_AFTER_STEP("5.5-DPC");

    // =========================================================================
    // PHASE 1B: Performance Infrastructure
    // =========================================================================

    //
    // Step 5.6: Initialize performance monitor (health metrics)
    //
    status = SsPmInitialize(&g_PerformanceMonitor);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize performance monitor: 0x%08X (continuing)\n",
                   status);
        g_PerformanceMonitor = NULL;
        status = STATUS_SUCCESS;
    } else {
        g_SubsystemFlags |= SubsysFlag_PerformanceMonitor;
        ShadowStrikeLogInitStatus("Performance Monitor", STATUS_SUCCESS);
    }

    //
    // Step 5.7: Initialize resource throttling (DoS prevention)
    //
    status = RtInitialize(&g_ResourceThrottler);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize resource throttler: 0x%08X (continuing)\n",
                   status);
        g_ResourceThrottler = NULL;
        status = STATUS_SUCCESS;
    } else {
        g_SubsystemFlags |= SubsysFlag_ResourceThrottling;

        //
        // Configure resource limits for enterprise DoS mitigation.
        // Limits are absolute usage thresholds per monitor interval (10s).
        // BurstCapacity controls per-check token bucket rate limiting.
        //
        // Process creation: moderate rate, strict limits
        RtSetLimits(g_ResourceThrottler, RtResourceProcessCreation,
                    500, 1000, 2000);
        RtSetRateConfig(g_ResourceThrottler, RtResourceProcessCreation,
                        1000, 500);
        RtEnableResource(g_ResourceThrottler, RtResourceProcessCreation, TRUE);

        // Registry operations: high-volume callback
        RtSetLimits(g_ResourceThrottler, RtResourceRegOps,
                    50000, 100000, 200000);
        RtSetRateConfig(g_ResourceThrottler, RtResourceRegOps,
                        1000, 50000);
        RtEnableResource(g_ResourceThrottler, RtResourceRegOps, TRUE);

        // Filesystem operations: highest volume
        RtSetLimits(g_ResourceThrottler, RtResourceFsOps,
                    100000, 200000, 500000);
        RtSetRateConfig(g_ResourceThrottler, RtResourceFsOps,
                        1000, 100000);
        RtEnableResource(g_ResourceThrottler, RtResourceFsOps, TRUE);

        // Callback rate (image load notifications)
        RtSetLimits(g_ResourceThrottler, RtResourceCallbackRate,
                    50000, 100000, 200000);
        RtSetRateConfig(g_ResourceThrottler, RtResourceCallbackRate,
                        1000, 50000);
        RtEnableResource(g_ResourceThrottler, RtResourceCallbackRate, TRUE);

        // Handle operations (object callback rate)
        RtSetLimits(g_ResourceThrottler, RtResourceHandleOps,
                    50000, 100000, 200000);
        RtSetRateConfig(g_ResourceThrottler, RtResourceHandleOps,
                        1000, 50000);
        RtEnableResource(g_ResourceThrottler, RtResourceHandleOps, TRUE);

        //
        // ETW -> user-mode behavioural alert forward, consulted by
        // ShadowStrikeEtwEventCallback. This is the only resource in this block
        // whose check is actually wired; the others are reported into and never
        // queried.
        //
        // THESE NUMBERS ARE CHOSEN, NOT MEASURED, and the counters exist so the
        // choice can be corrected with evidence rather than argued about. The
        // soft limit is 600 per 10s monitoring interval, i.e. 60 events/second
        // from any ONE process. Rationale: BehaviorBlocker escalates a chain
        // from a handful of events, so 60/s is already far beyond what
        // behavioural correlation can use, while remaining above the volume any
        // single process was observed producing in the field once the feedback
        // loop is removed (the busiest non-self process measured 57/s). The
        // intent is to bound a runaway producer, not to discard traffic the
        // product has actually been seen to handle. If
        // g_EtwAlertsSuppressedBudget climbs on a healthy endpoint, this is the
        // number to revisit - upward - after checking what is producing it.
        //
        RtSetLimits(g_ResourceThrottler, RtResourceEventQueue,
                    600, 1200, 2400);
        RtSetRateConfig(g_ResourceThrottler, RtResourceEventQueue,
                        1000, 60);
        RtEnableResource(g_ResourceThrottler, RtResourceEventQueue, TRUE);

        ShadowStrikeLogInitStatus("Resource Throttling", STATUS_SUCCESS);
    }

    //
    // Step 5.8: Batch processing â€” telemetry event aggregator
    //
    status = BpInitialize(&g_BatchProcessor);
    if (NT_SUCCESS(status)) {
        status = BpRegisterCallback(
            g_BatchProcessor,
            ShadowStrikeBatchFlushCallback,
            NULL
        );
        if (NT_SUCCESS(status)) {
            status = BpStart(g_BatchProcessor);
        }
        if (NT_SUCCESS(status)) {
            g_SubsystemFlags |= SubsysFlag_BatchProcessing;
            ShadowStrikeLogInitStatus("Batch Processing", STATUS_SUCCESS);
        } else {
            BpShutdown(g_BatchProcessor);
            g_BatchProcessor = NULL;
            ShadowStrikeLogInitStatus("Batch Processing", status);
        }
    } else {
        ShadowStrikeLogInitStatus("Batch Processing (init)", status);
    }

    //
    // Step 5.9: Cache optimization manager
    // Init cost: sizeof(CO_MANAGER) + timer â€” memory limit is a ceiling, not a reservation.
    //
    {
        status = CoInitialize(&g_CacheOptimizer, 16 * 1024 * 1024);  /* 16 MB ceiling */
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] WARNING: Failed to initialize cache optimization: 0x%08X (continuing)\n",
                       status);
            g_CacheOptimizer = NULL;
            status = STATUS_SUCCESS;
        } else {
            g_SubsystemFlags |= SubsysFlag_CacheOptimization;
            ShadowStrikeLogInitStatus("Cache Optimization", STATUS_SUCCESS);
        }
    }

    //
    // Step 5.10: Centralized lookaside list manager (memory pressure awareness)
    //
    {
        status = LlInitialize(&g_LookasideManager);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] WARNING: Failed to initialize centralized lookaside manager: 0x%08X (continuing)\n",
                       status);
            g_LookasideManager = NULL;
            status = STATUS_SUCCESS;
        } else {
            //
            // Set 32MB memory ceiling and enable periodic maintenance (30s).
            // Maintenance checks memory pressure and invokes callbacks.
            //
            LlSetMemoryLimit(g_LookasideManager, 32 * 1024 * 1024);
            LlEnableMaintenance(g_LookasideManager, 30000);
            ShadowStrikeLogInitStatus("Centralized Lookaside Manager", STATUS_SUCCESS);
        }
    }

    // =========================================================================
    // PHASE 1C: Power Management
    // =========================================================================

    //
    // Step 5.10: Register power state callbacks
    //
    status = ShadowRegisterPowerCallbacks(NULL);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to register power callbacks: 0x%08X (continuing)\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_SubsystemFlags |= SubsysFlag_PowerCallback;
        ShadowStrikeLogInitStatus("Power Callbacks", STATUS_SUCCESS);
    }

    // =========================================================================
    // PHASE 1D: Telemetry Pipeline
    // =========================================================================

    //
    // Step 5.11: Initialize ETW provider (event emission)
    //
    status = EtwProviderInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize ETW provider: 0x%08X (continuing)\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_SubsystemFlags |= SubsysFlag_ETWProvider;
        ShadowStrikeLogInitStatus("ETW Provider", STATUS_SUCCESS);
    }

    //
    // Step 5.12: Initialize telemetry buffer (buffered event delivery)
    //
    status = TbInitialize(
        &g_TelemetryBuffer,
        32 * 1024,   // 32KB per-CPU buffer
        256,         // Batch size: 256 events per flush
        5000         // Batch timeout: 5 seconds
    );
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize telemetry buffer: 0x%08X (continuing)\n",
                   status);
        g_TelemetryBuffer = NULL;
        status = STATUS_SUCCESS;
    } else {
        g_SubsystemFlags |= SubsysFlag_TelemetryBuffer;
        ShadowStrikeLogInitStatus("Telemetry Buffer", STATUS_SUCCESS);

        //
        // Start telemetry buffering â€” transitions state to Active,
        // creates flush thread, enables TbEnqueue from detection modules.
        //
        status = TbStart(g_TelemetryBuffer);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] WARNING: Failed to start telemetry buffer: 0x%08X (continuing)\n",
                       status);
        } else {
            ShadowStrikeLogInitStatus("Telemetry Buffer Start", STATUS_SUCCESS);
        }
    }

    //
    // Step 5.13: Initialize ETW consumer event pipeline (centralized event broker)
    //
    status = EcInitialize(NULL, &g_EtwConsumer);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize ETW consumer: 0x%08X (continuing)\n",
                   status);
        g_EtwConsumer = NULL;
        status = STATUS_SUCCESS;
    } else {
        //
        // Start the consumer (spawns processing threads, health timer)
        //
        NTSTATUS ecStatus = EcStart(g_EtwConsumer);
        if (!NT_SUCCESS(ecStatus)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] WARNING: Failed to start ETW consumer: 0x%08X (continuing)\n",
                       ecStatus);
        } else {
            //
            // Register subscriptions for all kernel event domains.
            // Each subscription uses the unified event callback that
            // streams events to telemetry and CommPort.
            //
            PEC_SUBSCRIPTION subTemp = NULL;

            EcSubscribeKernelProcess(g_EtwConsumer, ShadowStrikeEtwEventCallback, NULL, &subTemp);
            subTemp = NULL;
            EcSubscribeKernelFile(g_EtwConsumer, ShadowStrikeEtwEventCallback, NULL, &subTemp);
            subTemp = NULL;
            EcSubscribeKernelNetwork(g_EtwConsumer, ShadowStrikeEtwEventCallback, NULL, &subTemp);
            subTemp = NULL;
            EcSubscribeKernelRegistry(g_EtwConsumer, ShadowStrikeEtwEventCallback, NULL, &subTemp);
            subTemp = NULL;
            EcSubscribeSecurityAuditing(g_EtwConsumer, ShadowStrikeEtwEventCallback, NULL, &subTemp);
            subTemp = NULL;
            EcSubscribeThreatIntelligence(g_EtwConsumer, ShadowStrikeEtwEventCallback, NULL, &subTemp);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike] ETW consumer started with %ld subscriptions\n",
                       InterlockedCompareExchange(&g_EtwConsumer->SubscriptionCount, 0, 0));
        }

        ShadowStrikeLogInitStatus("ETW Consumer", STATUS_SUCCESS);
    }

    //
    // Step 5.14: Initialize compression engine (telemetry bandwidth optimization)
    //
    status = CompInitialize(&g_CompressionManager);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize compression engine: 0x%08X (continuing)\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        ShadowStrikeLogInitStatus("Compression Engine", STATUS_SUCCESS);
    }

    ShadowStrikeLogBootStep(RegistryPath, 9); // Pre-FltRegisterFilter

    //
    // Step 6: Register the minifilter
    //
    status = FltRegisterFilter(
        DriverObject,
        ShadowStrikeGetFilterRegistration(),
        &g_DriverData.FilterHandle
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] CRITICAL: FltRegisterFilter failed: 0x%08X\n",
                   status);
        goto Cleanup;
    }
    g_InitFlags |= InitFlag_FilterRegistered;
    ShadowStrikeLogInitStatus("FltRegisterFilter", status);

    ShadowStrikeLogBootStep(RegistryPath, 10); // FltRegisterFilter succeeded
    TP_VALIDATE_AFTER_STEP("6-FltRegisterFilter");

    //
    // Step 6.1: Wire WorkQueue with FilterHandle + DeviceObject now available.
    // WorkQueue was initialized at Step 5.1 with NULL handles; it becomes
    // fully functional only after receiving at least one dispatch target.
    //
    {
        PDEVICE_OBJECT wqDeviceObject = g_DriverData.DriverObject->DeviceObject;
        if (wqDeviceObject != NULL) {
            ShadowStrikeWorkQueueSetDeviceObject(wqDeviceObject);
        }
        ShadowStrikeWorkQueueSetFilterHandle(g_DriverData.FilterHandle);
    }

    // Step 6.1a: DeviceObject for TimerManager is provided via g_TimerControlDevice
    // (created at Step 5.4, before any module initialization).

    //
    // Step 6.5: Initialize encryption engine (AES-256-GCM for secure CommPort + HMAC auth)
    //
    {
        status = EncInitialize(&g_EncryptionManager);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] WARNING: Failed to initialize encryption engine: 0x%08X (continuing)\n",
                       status);
            status = STATUS_SUCCESS;
        } else {
            ShadowStrikeLogInitStatus("Encryption Engine (AES-256-GCM)", STATUS_SUCCESS);
        }
    }

    //
    // Step 7: Create communication port
    //
    status = ShadowStrikeCreateCommunicationPort(g_DriverData.FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] CRITICAL: Failed to create communication port: 0x%08X\n",
                   status);
        goto Cleanup;
    }
    g_InitFlags |= InitFlag_CommPortCreated;
    ShadowStrikeLogInitStatus("Communication Port", status);

    ShadowStrikeLogBootStep(RegistryPath, 11); // CommPort created
    TP_VALIDATE_AFTER_STEP("7-CommPort");

    //
    // Step 7.5: Initialize telemetry events (requires DeviceObject from FltRegisterFilter)
    //
    {
        PDEVICE_OBJECT deviceObject = g_DriverData.DriverObject->DeviceObject;
        if (deviceObject != NULL) {
            status = TeInitialize(deviceObject, NULL);
            if (!NT_SUCCESS(status)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike] WARNING: Failed to initialize telemetry events: 0x%08X (continuing)\n",
                           status);
                status = STATUS_SUCCESS;
            } else {
                g_SubsystemFlags |= SubsysFlag_TelemetryEvents;
                ShadowStrikeLogInitStatus("Telemetry Events", STATUS_SUCCESS);
            }
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] WARNING: No DeviceObject available â€” telemetry events skipped\n");
        }
    }

    //
    // Step 7.6: Initialize event schema (requires ETW provider context)
    //
    {
        static const GUID ShadowStrikeProviderId = 
            { 0xA3B5C7D9, 0xE1F2, 0x4A6B, { 0x8C, 0x0D, 0x2E, 0x4F, 0x6A, 0x8B, 0xCD, 0xEF } };

        status = EsInitialize(&g_EventSchema, &ShadowStrikeProviderId, "ShadowStrike.PhantomSensor");
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] WARNING: Failed to initialize event schema: 0x%08X (continuing)\n",
                       status);
            g_EventSchema = NULL;
            status = STATUS_SUCCESS;
        } else {
            g_SubsystemFlags |= SubsysFlag_EventSchema;
            ShadowStrikeLogInitStatus("Event Schema", STATUS_SUCCESS);

            //
            // Step 7.6a: Populate event schema with all ETW event definitions
            //
            status = ShadowStrikePopulateEventSchema(g_EventSchema);
            if (!NT_SUCCESS(status)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike] WARNING: Failed to populate event schema: 0x%08X (continuing)\n",
                           status);
            } else {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                           "[ShadowStrike] Event schema populated with %lu events\n",
                           (ULONG)EsGetEventCount(g_EventSchema));
            }
            status = STATUS_SUCCESS;

            //
            // Step 7.7: Initialize manifest generator (depends on EventSchema)
            //
            status = MgInitialize(g_EventSchema, &g_ManifestGenerator);
            if (!NT_SUCCESS(status)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike] WARNING: Failed to initialize manifest generator: 0x%08X (continuing)\n",
                           status);
                g_ManifestGenerator = NULL;
                status = STATUS_SUCCESS;
            } else {
                //
                // Step 7.7a: Populate manifest generator with default channels, keywords, and tasks
                //
                NTSTATUS mgStatus;

                mgStatus = MgRegisterDefaultChannels(g_ManifestGenerator);
                if (!NT_SUCCESS(mgStatus)) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                               "[ShadowStrike] WARNING: MgRegisterDefaultChannels failed: 0x%08X\n", mgStatus);
                }

                mgStatus = MgRegisterDefaultKeywords(g_ManifestGenerator);
                if (!NT_SUCCESS(mgStatus)) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                               "[ShadowStrike] WARNING: MgRegisterDefaultKeywords failed: 0x%08X\n", mgStatus);
                }

                mgStatus = MgRegisterDefaultTasks(g_ManifestGenerator);
                if (!NT_SUCCESS(mgStatus)) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                               "[ShadowStrike] WARNING: MgRegisterDefaultTasks failed: 0x%08X\n", mgStatus);
                }

                //
                // Step 7.7b: Validate schema integrity at init time
                // Protected with SEH — validation is non-critical for driver operation.
                //
                {
                    ULONG validationErrors = 0;
                    __try {
                        mgStatus = MgValidateSchema(g_ManifestGenerator, &validationErrors, NULL, NULL);
                        if (validationErrors > 0) {
                            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                                       "[ShadowStrike] ManifestGenerator schema validation: %lu error(s)\n",
                                       validationErrors);
                        }
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                                   "[ShadowStrike] WARNING: MgValidateSchema faulted (code 0x%08X) — skipping validation\n",
                                   GetExceptionCode());
                    }
                }

                ShadowStrikeLogInitStatus("Manifest Generator", STATUS_SUCCESS);
            }
        }
    }

    //
    // Step 8: Initialize scan cache (non-critical - continue on failure)
    //
    status = ShadowStrikeCacheInitialize(NULL, g_DriverData.Config.CacheTTLSeconds);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize scan cache: 0x%08X (continuing without cache)\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_InitFlags |= InitFlag_ScanCacheInitialized;
        ShadowStrikeLogInitStatus("Scan Cache", STATUS_SUCCESS);
    }

    //
    // Step 9: Initialize exclusion manager (non-critical)
    //
    status = ShadowStrikeExclusionInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize exclusion manager: 0x%08X\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_InitFlags |= InitFlag_ExclusionsInitialized;
        ShadowStrikeLogInitStatus("Exclusion Manager", STATUS_SUCCESS);
    }

    //
    // Step 9.1: Initialize process exclusion engine (trusted PID bitmap + hash)
    // Depends on ExclusionManager for path/process name matching.
    //
    if (g_InitFlags & InitFlag_ExclusionsInitialized) {
        status = ShadowStrikeProcessExclusionInitialize();
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] WARNING: Failed to initialize process exclusion engine: 0x%08X\n",
                       status);
            status = STATUS_SUCCESS;
        } else {
            ShadowStrikeLogInitStatus("Process Exclusion Engine", STATUS_SUCCESS);
        }
    }

    //
    // Step 10: Initialize hash utilities (non-critical)
    //
    status = ShadowStrikeInitializeHashUtils();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize hash utilities: 0x%08X\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_InitFlags |= InitFlag_HashUtilsInitialized;
        ShadowStrikeLogInitStatus("Hash Utilities", STATUS_SUCCESS);
    }

    //
    // Step 10.5: Initialize file utilities (non-critical)
    // Provides file type detection, ADS detection, volume info, PE parsing,
    // Zone.Identifier extraction, and secure file reading infrastructure.
    // Requires FilterHandle from FltRegisterFilter (Step 6).
    //
    status = ShadowStrikeInitializeFileUtils(g_DriverData.FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize file utilities: 0x%08X\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_FileUtilsInitialized = TRUE;
        ShadowStrikeLogInitStatus("File Utilities", STATUS_SUCCESS);
    }

    // =========================================================================
    // PHASE 2: Detection Subsystems
    // =========================================================================

    ShadowStrikeLogBootStep(RegistryPath, 13); // Pre-detection subsystems

    //
    // Step 10.1: Initialize behavioral engine (multi-stage attack detection)
    // Children: AttackChainTracker, PatternMatcher, RuleEngine, IOCMatcher, MITREMapper
    //
    status = BeEngineInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize behavioral engine: 0x%08X (continuing)\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_SubsystemFlags |= SubsysFlag_BehaviorEngine;
        ShadowStrikeLogInitStatus("Behavioral Engine", STATUS_SUCCESS);
    }
    TP_VALIDATE_AFTER_STEP("10.1-BehaviorEngine");

    //
    // Step 10.2: Initialize memory monitoring subsystem
    // Children: HollowingDetector, InjectionDetector, HeapSpray, ShellcodeDetector,
    //           ROPDetector, VadTracker, SectionTracker, ETWConsumer
    //
    status = MmMonitorInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize memory monitor: 0x%08X (continuing)\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_SubsystemFlags |= SubsysFlag_MemoryMonitor;
        ShadowStrikeLogInitStatus("Memory Monitor", STATUS_SUCCESS);
    }

    //
    // Step 10.2b: Initialize memory scanner (full-scan engine, requires DeviceObject)
    //
    {
        PDEVICE_OBJECT deviceObject = g_DriverData.DriverObject->DeviceObject;
        if (deviceObject != NULL) {
            status = MsInitialize(deviceObject, &g_MemoryScanner);
            if (!NT_SUCCESS(status)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike] WARNING: Failed to initialize memory scanner: 0x%08X (continuing)\n",
                           status);
                g_MemoryScanner = NULL;
                status = STATUS_SUCCESS;
            } else {
                g_SubsystemFlags |= SubsysFlag_MemoryScanner;
                ShadowStrikeLogInitStatus("Memory Scanner", STATUS_SUCCESS);
            }
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] WARNING: No DeviceObject â€” memory scanner skipped\n");
        }
    }

    //
    // Step 10.3: Initialize syscall monitoring subsystem
    // Children: SyscallTable, SyscallHooks, NtdllIntegrity, DirectSyscallDetector,
    //           HeavensGateDetector, CallstackAnalyzer
    //
    status = ScMonitorInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize syscall monitor: 0x%08X (continuing)\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_SubsystemFlags |= SubsysFlag_SyscallMonitor;
        ShadowStrikeLogInitStatus("Syscall Monitor", STATUS_SUCCESS);
    }

    ShadowStrikeLogBootStep(RegistryPath, 15); // Pre-NetworkFilter

    //
    // Step 10.4: Initialize network filter (WFP-based network detection)
    // Children: DnsMonitor, C2Detection, DataExfiltration, ConnectionTracker,
    //           ProtocolParser, PortScanner, NetworkReputation, SSLInspection
    // Note: Requires a device object for WFP callout registration
    //
    status = NfFilterInitialize(g_DriverData.DriverObject->DeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize network filter: 0x%08X (continuing)\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_SubsystemFlags |= SubsysFlag_NetworkFilter;
        ShadowStrikeLogInitStatus("Network Filter", STATUS_SUCCESS);
    }
    TP_VALIDATE_AFTER_STEP("10.4-NetworkFilter");

    ShadowStrikeLogBootStep(RegistryPath, 16); // Pre-process callbacks

    //
    // Step 11: Register process/thread notification callbacks
    // Process callback is CRITICAL for security product
    //
    status = ShadowStrikeRegisterProcessCallbacks(&g_CallbackFlags);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] CRITICAL: Failed to register process callbacks: 0x%08X\n",
                   status);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] A security product CANNOT function without process monitoring.\n");
        goto Cleanup;
    }
    // Flags are set inside the function based on what succeeded

    //
    // Step 12: Initialize registry monitoring subsystem, then register callback
    //
    status = ShadowStrikeInitializeRegistryMonitoring();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize registry monitoring: 0x%08X\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_InitFlags |= InitFlag_RegistryMonitorInit;

        status = ShadowStrikeRegisterRegistryCallback(DriverObject);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] WARNING: Failed to register registry callback: 0x%08X\n",
                       status);
            status = STATUS_SUCCESS;
        } else {
            g_InitFlags |= InitFlag_RegistryCallbackReg;
        }
    }

    //
    // Step 13: Register object callbacks for self-protection
    // This is CRITICAL - without it, malware can terminate us
    //
    status = ShadowStrikeRegisterObjectCallbacks();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] CRITICAL: Failed to register object callbacks: 0x%08X\n",
                   status);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Self-protection DISABLED - driver vulnerable to termination.\n");
        // This is critical but we continue in degraded mode with a warning
        // A real enterprise product might fail here depending on policy
    } else {
        g_InitFlags |= InitFlag_ObjectCallbackReg;
    }

    //
    // Step 14: Initialize self-protection subsystem
    //
    status = ShadowStrikeInitializeSelfProtection();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize self-protection: 0x%08X\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_InitFlags |= InitFlag_SelfProtectInitialized;
        ShadowStrikeLogInitStatus("Self-Protection", STATUS_SUCCESS);
    }

    //
    // Step 14.5: Initialize named pipe monitoring
    //
    status = NpMonInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize named pipe monitor: 0x%08X\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_InitFlags |= InitFlag_NamedPipeMonInitialized;
        ShadowStrikeLogInitStatus("Named Pipe Monitor", STATUS_SUCCESS);
    }

    //
    // Step 14.6: Initialize AMSI bypass detector
    //
    status = AbdInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize AMSI bypass detector: 0x%08X\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_InitFlags |= InitFlag_AmsiBypassDetInitialized;
        ShadowStrikeLogInitStatus("AMSI Bypass Detector", STATUS_SUCCESS);
    }

    //
    // Step 14.7: Initialize file backup engine (ransomware rollback)
    //
    status = FbeInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize file backup engine: 0x%08X\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_InitFlags |= InitFlag_FileBackupEngineInitialized;
        ShadowStrikeLogInitStatus("File Backup Engine", STATUS_SUCCESS);
    }

    //
    // Step 14.8: Initialize USB device control
    //
    status = UdcInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize USB device control: 0x%08X\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_InitFlags |= InitFlag_USBDeviceControlInitialized;
        ShadowStrikeLogInitStatus("USB Device Control", STATUS_SUCCESS);
    }

    //
    // Step 14.9: Initialize WSL/Container monitor
    //
    status = WslMonInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize WSL monitor: 0x%08X\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_InitFlags |= InitFlag_WslMonitorInitialized;
        ShadowStrikeLogInitStatus("WSL/Container Monitor", STATUS_SUCCESS);
    }

    //
    // Step 14.10: Initialize application control
    //
    status = AcInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize application control: 0x%08X\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_InitFlags |= InitFlag_AppControlInitialized;
        ShadowStrikeLogInitStatus("Application Control", STATUS_SUCCESS);
    }

    //
    // Step 14.11: Initialize firmware integrity monitor
    //
    status = FiInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize firmware integrity: 0x%08X\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_InitFlags |= InitFlag_FirmwareIntegrityInitialized;
        ShadowStrikeLogInitStatus("Firmware Integrity", STATUS_SUCCESS);
    }

    //
    // Step 14.12: Initialize Clipboard Monitor (heuristic clipboard abuse detection)
    //
    status = CbMonInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize clipboard monitor: 0x%08X\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_InitFlags |= InitFlag_ClipboardMonitorInitialized;
        ShadowStrikeLogInitStatus("Clipboard Monitor", STATUS_SUCCESS);
    }

    // =========================================================================
    // PHASE 3A: Process Analysis Pipeline
    // =========================================================================

    //
    // Step 14.13: Initialize process analyzer
    //
    status = PaInitialize(&g_ProcessAnalyzer, NULL);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize process analyzer: 0x%08X (continuing)\n",
                   status);
        g_ProcessAnalyzer = NULL;
        status = STATUS_SUCCESS;
    } else {
        g_SubsystemFlags |= SubsysFlag_ProcessAnalyzer;
        ShadowStrikeLogInitStatus("Process Analyzer", STATUS_SUCCESS);
    }

    // =========================================================================
    // PHASE 3B: Communication Pipeline
    // =========================================================================

    //
    // Step 14.14: Initialize message handler
    //
    status = MhInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize message handler: 0x%08X (continuing)\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_SubsystemFlags |= SubsysFlag_MessageHandler;
        ShadowStrikeLogInitStatus("Message Handler", STATUS_SUCCESS);
    }

    //
    // Step 14.15: Initialize scan bridge
    //
    status = ShadowStrikeScanBridgeInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize scan bridge: 0x%08X (continuing)\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_SubsystemFlags |= SubsysFlag_ScanBridge;
        ShadowStrikeLogInitStatus("Scan Bridge", STATUS_SUCCESS);
    }

    //
    // Step 14.15b: Initialize message queue
    //
    status = MqInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize message queue: 0x%08X (continuing)\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_SubsystemFlags |= SubsysFlag_MessageQueue;
        ShadowStrikeLogInitStatus("Message Queue", STATUS_SUCCESS);
    }

    // =========================================================================
    // PHASE 4A: Boot-Time Protection (ELAM Alternative)
    // Initialize early-launch driver classification before self-protection
    // so boot drivers are monitored as soon as possible.

    ShadowStrikeLogBootStep(RegistryPath, 19); // Pre-ELAM + self-protection
    // =========================================================================

    //
    // Step 14.15a: Initialize ELAM driver subsystem
    //
    status = ElamDriverInitialize(DriverObject, RegistryPath);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize ELAM driver: 0x%08X (continuing)\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_InitFlags |= InitFlag_ElamInitialized;
        ShadowStrikeLogInitStatus("ELAM Driver", STATUS_SUCCESS);

        //
        // Step 14.15b: Register ELAM image load + registry callbacks
        //
        status = ElamRegisterCallback();
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] WARNING: Failed to register ELAM callbacks: 0x%08X (continuing)\n",
                       status);
            status = STATUS_SUCCESS;
        } else {
            ShadowStrikeLogInitStatus("ELAM Callbacks", STATUS_SUCCESS);
        }
    }

    // =========================================================================
    // PHASE 4: Self-Protection Hardening
    // Must be AFTER all callbacks are registered to protect them
    // =========================================================================

    //
    // Step 14.16: Initialize handle protection
    //
    status = HpInitialize(&g_HandleProtection);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize handle protection: 0x%08X (continuing)\n",
                   status);
        g_HandleProtection = NULL;
        status = STATUS_SUCCESS;
    } else {
        g_SubsystemFlags |= SubsysFlag_HandleProtection;
        ShadowStrikeLogInitStatus("Handle Protection", STATUS_SUCCESS);
    }

    //
    // Step 14.17: Initialize integrity monitor
    //
    {
        PVOID driverBase = g_DriverData.DriverObject->DriverStart;
        SIZE_T driverSize = (SIZE_T)g_DriverData.DriverObject->DriverSize;

        status = ImInitialize(&g_IntegrityMonitor, driverBase, driverSize);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] WARNING: Failed to initialize integrity monitor: 0x%08X (continuing)\n",
                       status);
            g_IntegrityMonitor = NULL;
            status = STATUS_SUCCESS;
        } else {
            g_SubsystemFlags |= SubsysFlag_IntegrityMonitor;
            ShadowStrikeLogInitStatus("Integrity Monitor", STATUS_SUCCESS);

            //
            // NOTE (v1.0.13.0 — winlogon grey-screen fix):
            // ImEnablePeriodicCheck() spawns a periodic worker that, on
            // its first tick, may issue file IO to re-hash the driver
            // image. If armed BEFORE FltStartFiltering, that IO can race
            // with winlogon's boot IO. Periodic checks are now deferred
            // to the post-FltStartFiltering block — see "POST-INIT
            // PERIODIC WORKERS" near the end of DriverEntry.
            //
        }
    }

    //
    // Step 14.18a: Initialize anti-debug protector
    // Detects kernel debugger attachment and debug port abuse (T1622)
    //
    status = AdbInitialize(&g_AntiDebugProtector);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize anti-debug protector: 0x%08X (continuing)\n",
                   status);
        g_AntiDebugProtector = NULL;
        status = STATUS_SUCCESS;
    } else {
        g_InitFlags |= InitFlag_AntiDebugInitialized;
        ShadowStrikeLogInitStatus("Anti-Debug Protector", STATUS_SUCCESS);
    }

    //
    // Step 14.18b: Initialize anti-unload protector
    // Prevents malicious driver unload via OB callbacks and DriverUnload nullification
    //
    status = AuInitialize(g_DriverData.DriverObject, &g_AntiUnloadProtector);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize anti-unload protector: 0x%08X (continuing)\n",
                   status);
        g_AntiUnloadProtector = NULL;
        status = STATUS_SUCCESS;
    } else {
        g_InitFlags |= InitFlag_AntiUnloadInitialized;
        ShadowStrikeLogInitStatus("Anti-Unload Protector", STATUS_SUCCESS);

        //
        // Upgrade to Full protection â€” registers OB callbacks for handle
        // stripping on protected PIDs. Basic only nulls DriverUnload.
        //
        {
            NTSTATUS levelStatus = AuSetLevel(g_AntiUnloadProtector, AuLevel_Full);
            if (!NT_SUCCESS(levelStatus)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                           "[ShadowStrike] WARNING: AuSetLevel(Full) failed: 0x%08X "
                           "(continuing at Basic)\n", levelStatus);
            }
        }
    }

    //
    // Step 14.18c: Initialize file protection engine
    // Protects driver files on disk from deletion/modification (T1562.001)
    //
    status = FpInitialize(&g_FileProtectionEngine);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize file protection: 0x%08X (continuing)\n",
                   status);
        g_FileProtectionEngine = NULL;
        status = STATUS_SUCCESS;
    } else {
        g_InitFlags |= InitFlag_FileProtectionInitialized;
        ShadowStrikeLogInitStatus("File Protection Engine", STATUS_SUCCESS);
    }

    //
    // Step 14.19: Initialize callback protection (LAST protection init â€” protects all registered callbacks)
    //
    status = CpInitialize(&g_CallbackProtector);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize callback protection: 0x%08X (continuing)\n",
                   status);
        g_CallbackProtector = NULL;
        status = STATUS_SUCCESS;
    } else {
        g_SubsystemFlags |= SubsysFlag_CallbackProtection;
        ShadowStrikeLogInitStatus("Callback Protection", STATUS_SUCCESS);

        //
        // Wire all registered callbacks into callback protection for tamper detection.
        // CpProtectCallback computes SHA-256 of callback code and backs up original bytes
        // so periodic verification can detect and restore tampered callback routines.
        //

        // Protect minifilter callback (if registered)
        if (g_InitFlags & InitFlag_FilterRegistered) {
            (VOID)CpProtectCallback(
                g_CallbackProtector,
                CpCallback_Minifilter,
                (PVOID)g_DriverData.FilterHandle,
                (PVOID)(ULONG_PTR)ShadowStrikeGetFilterRegistration
            );
        }

        // Protect process creation callback
        if (g_DriverData.ProcessNotifyRegistered) {
            (VOID)CpProtectCallback(
                g_CallbackProtector,
                CpCallback_Process,
                (PVOID)ShadowStrikeProcessNotifyCallback,
                (PVOID)ShadowStrikeProcessNotifyCallback
            );
        }

        // Protect thread creation callback
        if (g_DriverData.ThreadNotifyRegistered) {
            PVOID threadCbPtr = TnGetNotifyCallbackPointer();
            if (threadCbPtr != NULL) {
                (VOID)CpProtectCallback(
                    g_CallbackProtector,
                    CpCallback_Thread,
                    threadCbPtr,
                    threadCbPtr
                );
            }
        }

        // Protect image load callback
        if (g_DriverData.ImageNotifyRegistered) {
            (VOID)CpProtectCallback(
                g_CallbackProtector,
                CpCallback_Image,
                (PVOID)ImageLoadNotifyRoutine,
                (PVOID)ImageLoadNotifyRoutine
            );
        }

        // Protect registry callback
        if (g_InitFlags & InitFlag_RegistryCallbackReg) {
            (VOID)CpProtectCallback(
                g_CallbackProtector,
                CpCallback_Registry,
                (PVOID)(ULONG_PTR)g_DriverData.RegistryCallbackCookie.QuadPart,
                (PVOID)ShadowStrikeRegistryCallbackRoutine
            );
        }

        // Protect object callbacks (process + thread handle protection)
        if (g_InitFlags & InitFlag_ObjectCallbackReg) {
            (VOID)CpProtectCallback(
                g_CallbackProtector,
                CpCallback_Object,
                g_DriverData.ObjectCallbackHandle,
                (PVOID)ShadowStrikeProcessPreCallback
            );
        }

        //
        // NOTE (v1.0.13.0 — winlogon grey-screen fix):
        // CpEnablePeriodicVerify() arms a 5-second timer whose first tick
        // hashes registered callback code. This must NOT race with the
        // boot-phase IO storm from winlogon/csrss/smss, so it is deferred
        // to the post-FltStartFiltering block — see "POST-INIT PERIODIC
        // WORKERS" near the end of DriverEntry.
        //

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] Callback protection wired: %u callbacks protected with 5s verification\n",
                   (g_DriverData.ProcessNotifyRegistered ? 1u : 0u) +
                   (g_DriverData.ThreadNotifyRegistered ? 1u : 0u) +
                   (g_DriverData.ImageNotifyRegistered ? 1u : 0u) +
                   ((g_InitFlags & InitFlag_RegistryCallbackReg) ? 1u : 0u) +
                   ((g_InitFlags & InitFlag_ObjectCallbackReg) ? 1u : 0u) +
                   ((g_InitFlags & InitFlag_FilterRegistered) ? 1u : 0u));
    }

    // =========================================================================
    // PHASE 5: Specialized Subsystems
    // =========================================================================

    //
    // Step 14.19: Initialize ALPC port monitor
    //
    status = ShadowAlpcInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize ALPC monitor: 0x%08X (continuing)\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_SubsystemFlags |= SubsysFlag_AlpcPortMonitor;
        ShadowStrikeLogInitStatus("ALPC Monitor", STATUS_SUCCESS);
    }

    //
    // Step 14.20: Initialize KTM transaction monitor
    //
    status = ShadowInitializeKtmMonitor(g_DriverData.FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize KTM monitor: 0x%08X (continuing)\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_SubsystemFlags |= SubsysFlag_KtmMonitor;
        ShadowStrikeLogInitStatus("KTM Monitor", STATUS_SUCCESS);
    }

    //
    // Step 14.21: Create private object namespace
    //
    status = ShadowCreatePrivateNamespace();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to create private namespace: 0x%08X (continuing)\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_SubsystemFlags |= SubsysFlag_ObjectNamespace;
        ShadowStrikeLogInitStatus("Object Namespace", STATUS_SUCCESS);
    }

    // =========================================================================
    // PHASE 6A: Scoring Orchestration
    // =========================================================================

    //
    // Step 14.22: Initialize threat scoring engine (driver-wide)
    //
    status = TsInitialize(&g_ThreatScoring);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize threat scoring: 0x%08X (continuing)\n",
                   status);
        g_ThreatScoring = NULL;
        status = STATUS_SUCCESS;
    } else {
        g_SubsystemFlags |= SubsysFlag_ThreatScoring;
        ShadowStrikeLogInitStatus("Threat Scoring", STATUS_SUCCESS);
    }

    //
    // Step 14.23: Performance monitoring collection — DEFERRED (v1.0.13.0).
    // Periodic collection worker is started in the post-FltStartFiltering
    // block to keep the boot path quiescent. See "POST-INIT PERIODIC WORKERS".
    //

    //
    // Step 14.24: Resource throttling monitoring — DEFERRED (v1.0.13.0).
    // Started in the post-FltStartFiltering block. See "POST-INIT PERIODIC
    // WORKERS" near the end of DriverEntry.
    //

    //
    // Step 14.25: Register power-to-behavior bridge callback
    // Forwards sleep/resume events to BehaviorEngine for time-based evasion detection
    //
    if ((g_SubsystemFlags & SubsysFlag_PowerCallback) &&
        (g_SubsystemFlags & SubsysFlag_BehaviorEngine))
    {
        ULONGLONG powerEventMask =
            (1ULL << ShadowPowerEvent_EnteringSleep) |
            (1ULL << ShadowPowerEvent_ResumingFromSleep) |
            (1ULL << ShadowPowerEvent_EnteringHibernate) |
            (1ULL << ShadowPowerEvent_ResumingFromHibernate) |
            (1ULL << ShadowPowerEvent_BatteryCritical);

        status = ShadowPowerRegisterCallback(
            ShadowStrikePowerBehaviorBridge,
            NULL,
            ShadowPowerPriority_Normal,
            powerEventMask,
            &g_PowerBehaviorBridgeHandle
            );
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] WARNING: Failed to register power-behavior bridge: 0x%08X (continuing)\n",
                       status);
            g_PowerBehaviorBridgeHandle = NULL;
        } else {
            ShadowStrikeLogInitStatus("Power-Behavior Bridge", STATUS_SUCCESS);
        }
        status = STATUS_SUCCESS;
    }

    //
    // Step 14.26: Initialize filesystem callback subsystem (MUST be before FltStartFiltering)
    // InstanceSetup is called during FltStartFiltering and accesses FSC global state
    // (VolumeList, ProcessContextList, lookaside lists). Without this init, BSOD occurs.
    //

    ShadowStrikeLogBootStep(RegistryPath, 22); // Pre-FSC + callback subsystem init
    status = ShadowStrikeInitializeFileSystemCallbacks();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] CRITICAL: Failed to initialize filesystem callbacks: 0x%08X\n"
                   "    Cannot start filtering - InstanceSetup requires FSC state.\n",
                   status);
        goto Cleanup;
    }
    g_InitFlags |= InitFlag_FscInitialized;
    ShadowStrikeLogInitStatus("Filesystem Callbacks", STATUS_SUCCESS);

    //
    // Step 14.27: Initialize PostCreate subsystem (stream context management,
    // file classification, ransomware monitoring baselines, handle contexts)
    // MUST be before FltStartFiltering â€” PostCreate callback needs lookaside lists
    //
    status = PocInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize PostCreate subsystem: 0x%08X\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_InitFlags |= InitFlag_PocInitialized;
        ShadowStrikeLogInitStatus("PostCreate Subsystem", STATUS_SUCCESS);
    }

    //
    // Step 14.28: Initialize PostWrite subsystem (process notify callback for
    // cleanup on process termination, prevents stale PID entries and PID reuse issues)
    // MUST be before FltStartFiltering â€” PostWrite callback needs process tracking
    //
    status = ShadowStrikePostWriteInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize PostWrite subsystem: 0x%08X\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_InitFlags |= InitFlag_PwInitialized;
        ShadowStrikeLogInitStatus("PostWrite Subsystem", STATUS_SUCCESS);
    }

    //
    // Step 14.29: Initialize PreAcquireSection subsystem (behavioral detection for
    // process hollowing, DLL injection, reflective loading via section mapping patterns)
    //
    status = ShadowStrikePreAcquireSectionInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize PreAcquireSection subsystem: 0x%08X\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_InitFlags |= InitFlag_PasInitialized;
        ShadowStrikeLogInitStatus("PreAcquireSection Subsystem", STATUS_SUCCESS);
    }

    //
    // Step 14.30: Initialize PreCreate subsystem (on-access scanning, ADS detection,
    // double-extension detection, honeypot detection, ransomware correlation, USB autorun blocking)
    // Uses SubsysFlag_PreCreate because all LONG InitFlag bits are exhausted.
    //
    status = PcInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize PreCreate subsystem: 0x%08X\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_SubsystemFlags |= SubsysFlag_PreCreate;
        ShadowStrikeLogInitStatus("PreCreate Subsystem", STATUS_SUCCESS);
    }

    //
    // Step 14.31: Initialize PreSetInfo subsystem (ransomware behavioral detection,
    // data destruction prevention, credential access monitoring, self-protection
    // for delete/rename/hardlink operations)
    //
    status = ShadowStrikeInitializePreSetInfo();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize PreSetInfo subsystem: 0x%08X\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_PreSetInfoInitialized = TRUE;
        ShadowStrikeLogInitStatus("PreSetInfo Subsystem", STATUS_SUCCESS);
    }

    //
    // Step 14.32: Initialize PreWrite subsystem (ransomware detection via
    // entropy analysis, canary file protection, shadow copy/credential file
    // write monitoring, self-protection for write operations)
    //
    status = ShadowStrikeInitializePreWrite();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize PreWrite subsystem: 0x%08X\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_PreWriteInitialized = TRUE;
        ShadowStrikeLogInitStatus("PreWrite Subsystem", STATUS_SUCCESS);
    }

    //
    // Step 15: Start filtering
    //

    ShadowStrikeLogBootStep(RegistryPath, 24); // Pre-FltStartFiltering
    TP_VALIDATE_AFTER_STEP("PRE-FltStartFiltering");

    status = FltStartFiltering(g_DriverData.FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] CRITICAL: FltStartFiltering failed: 0x%08X\n",
                   status);
        goto Cleanup;
    }
    g_InitFlags |= InitFlag_FilteringStarted;
    WriteBooleanRelease(&g_DriverData.FilteringStarted, TRUE);
    ShadowStrikeLogInitStatus("FltStartFiltering", status);
    TP_VALIDATE_AFTER_STEP("POST-FltStartFiltering");

    //
    // Mark driver as initialized with proper memory barrier
    //
    MemoryBarrier();
    WriteBooleanRelease(&g_DriverData.Initialized, TRUE);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Driver initialized successfully (InitFlags=0x%08X)\n",
               g_InitFlags);

    ShadowStrikeLogBootStep(RegistryPath, 25); // Init complete — driver READY

    //
    // =========================================================================
    // POST-INIT PERIODIC WORKERS (v1.0.13.0 — winlogon grey-screen fix)
    // =========================================================================
    //
    // These periodic workers are launched ONLY AFTER FltStartFiltering has
    // returned and the core driver state booleans (FilteringStarted,
    // Initialized) are set. Launching them earlier produced a boot-time
    // race where their first tick performed file IO that contended with
    // winlogon/csrss/smss boot IO, producing a permanent grey "Welcome"
    // screen on low-RAM VMs.
    //
    // Each call is best-effort and non-fatal; failures are logged but do
    // not block the post-init transition.
    //

    if (g_SubsystemFlags & SubsysFlag_IntegrityMonitor) {
        ImEnablePeriodicCheck(g_IntegrityMonitor, 30000);
        ShadowStrikeLogInitStatus("Integrity Monitor periodic check (post-init)",
                                  STATUS_SUCCESS);
    }

    if (g_SubsystemFlags & SubsysFlag_CallbackProtection) {
        (VOID)CpEnablePeriodicVerify(g_CallbackProtector, 5000);
        ShadowStrikeLogInitStatus("Callback Protection periodic verify (post-init)",
                                  STATUS_SUCCESS);
    }

    if (g_SubsystemFlags & SubsysFlag_PerformanceMonitor) {
        NTSTATUS pmStatus = SsPmEnableCollection(g_PerformanceMonitor, 5000);
        if (!NT_SUCCESS(pmStatus)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] WARNING: Post-init SsPmEnableCollection "
                       "failed: 0x%08X (continuing)\n", pmStatus);
        } else {
            ShadowStrikeLogInitStatus("Performance Collection (post-init)",
                                      STATUS_SUCCESS);
        }
    }

    if (g_SubsystemFlags & SubsysFlag_ResourceThrottling) {
        NTSTATUS rtStatus = RtStartMonitoring(g_ResourceThrottler, 10000);
        if (!NT_SUCCESS(rtStatus)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] WARNING: Post-init RtStartMonitoring "
                       "failed: 0x%08X (continuing)\n", rtStatus);
        } else {
            ShadowStrikeLogInitStatus("Resource Throttling Monitor (post-init)",
                                      STATUS_SUCCESS);
        }
    }

    //
    // Drain any work items queued by foreign agents during their own init
    // phase. Each callback is invoked at PASSIVE_LEVEL; after this point
    // ShadowStrikeQueuePostInitWork() invokes callbacks inline.
    //
    ShadowStrikeDrainPostInitWork();

    //
    // FINAL TRANSITION: mark driver fully operational.
    // This is the gate that callbacks in foreign modules consult via
    // ShadowStrikeIsFullyOperational(). It is set AFTER:
    //   * FltStartFiltering returned success
    //   * CommPort exists (InitFlag_CommPortCreated set above)
    //   * Driver Initialized/FilteringStarted booleans are set
    //   * All deferred periodic workers and post-init items have run
    //
    NT_ASSERT(g_InitFlags & InitFlag_CommPortCreated);
    NT_ASSERT(g_InitFlags & InitFlag_FilteringStarted);

    MemoryBarrier();
    InterlockedExchange(&g_DriverData.FullyOperational, 1);

    //
    // Cross-scope bridge: drop the FS callback boot-phase latch in lockstep
    // with FullyOperational so that PreCreate/PreWrite/PreSetInfo/etc. can
    // transition out of their fast-bail path at the same instant the rest
    // of the driver is declared healthy. WriteRelease pairs with the
    // ReadAcquire inside ShadowFsIsBootPhase().
    //
    {
        extern volatile LONG g_ShadowFsBootPhaseActive;
        InterlockedExchange(&g_ShadowFsBootPhaseActive, 0);
    }

    ShadowStrikeLogBootStep(RegistryPath, 26); // FullyOperational = TRUE

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Driver FULLY OPERATIONAL — boot-grace window "
               "active for 90s from tick 0x%llX\n",
               g_DriverData.BootPhaseStartTick.QuadPart);

    //
    // Emit ETW diagnostic event: driver started successfully
    //
    EtwWriteDiagnosticEvent(
        EtwEventId_DriverStarted,
        TRACE_LEVEL_INFORMATION,
        0,  // ComponentId: 0 = core driver
        L"Driver initialized successfully",
        STATUS_SUCCESS);

    //
    // Log security status
    //
    if ((g_InitFlags & InitFlag_ObjectCallbackReg) == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Running in DEGRADED MODE - self-protection disabled\n");
    }

    return STATUS_SUCCESS;

Cleanup:
#undef TP_VALIDATE_AFTER_STEP
    //
    // Cleanup precisely based on what was initialized
    //
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[ShadowStrike] DriverEntry failed (status=0x%08X), cleaning up (InitFlags=0x%08X)...\n",
               status, g_InitFlags);

    ShadowStrikeCleanupByFlags(g_InitFlags);
    g_InitFlags = InitFlag_None;

    return status;
}

// ============================================================================
// DRIVER UNLOAD
// ============================================================================

/**
 * @brief Driver unload callback.
 *
 * Uses EX_RUNDOWN_REF for proper synchronization - waits for ALL
 * outstanding callbacks to complete before freeing any resources.
 */
NTSTATUS
ShadowStrikeUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    BOOLEAN mandatoryUnload;

    PAGED_CODE();

    mandatoryUnload = (Flags & FLTFL_FILTER_UNLOAD_MANDATORY) != 0;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Unload: Starting (InitFlags=0x%08X, "
               "Flags=0x%08X, Mandatory=%s)\n",
               g_InitFlags, (ULONG)Flags,
               mandatoryUnload ? "TRUE" : "FALSE");

    //
    // Emit ETW diagnostic event: driver shutting down (Unload path)
    //
    EtwWriteDiagnosticEvent(
        EtwEventId_DriverStopping,
        TRACE_LEVEL_WARNING,
        0,
        mandatoryUnload
            ? L"Driver unloading (mandatory)"
            : L"Driver unloading (voluntary)",
        STATUS_SUCCESS);

    //
    // Step 1: Signal shutdown - stop accepting new work.
    // Use memory barrier to ensure visibility. Callbacks that have not
    // yet acquired rundown will bail at the SHADOWSTRIKE_IS_READY() gate;
    // callbacks already past the gate continue to hold the global rundown
    // until they unwind.
    //
    // Also clear FullyOperational so that callbacks consulting the v1.0.13.0
    // ShadowStrikeIsFullyOperational() gate observe the unload immediately,
    // without having to re-read three separate booleans.
    //
    InterlockedExchange(&g_DriverData.FullyOperational, 0);
    WriteBooleanRelease(&g_DriverData.ShuttingDown, TRUE);
    MemoryBarrier();

    //
    // Step 2: Drain worker-thread / ERESOURCE-owning subsystems BEFORE
    // waiting on the global rundown. Each of these subsystems is gated
    // by its OWN local rundown / stopping flag and will refuse new public
    // API calls once shut down, which lets callbacks that still hold the
    // global rundown unwind through DEVICE_NOT_READY (etc.) and release
    // it - breaking the hold-and-wait deadlock cycle around BehaviorEngine
    // and ScanBridge ERESOURCEs that previously hung the OS shutdown
    // watchdog (Event 41 / 6008).
    //
    // Audit reference: bounded-wait subsystem reorder list. Each call
    // site below mirrors the original later-in-function ordering in
    // EXACT reverse-init order; the in-place duplicate later in this
    // function becomes a no-op via the cleared flag.
    //
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Unload step 2: draining self-gated "
               "subsystems (pre-rundown-wait).\n");

    //
    // Unregister power-to-behavior bridge BEFORE shutting down
    // BehaviorEngine - the power callback can submit events to BE.
    //
    if (g_PowerBehaviorBridgeHandle != NULL) {
        ShadowPowerUnregisterCallback(g_PowerBehaviorBridgeHandle);
        g_PowerBehaviorBridgeHandle = NULL;
    }

    //
    // BehaviorEngine: PRIMARY deadlock site. Must shut down FIRST so its
    // worker thread releases ChainLock/ProcessLock and any in-flight
    // PreAcquireSection callback can unwind off those ERESOURCEs.
    //
    if (g_SubsystemFlags & SubsysFlag_BehaviorEngine) {
        BeEngineShutdown();
        g_SubsystemFlags &= ~SubsysFlag_BehaviorEngine;
    }

    //
    // Detection subsystems - their workers contend on BehaviorEngine
    // state and on each other; bring them down in reverse-init order.
    //
    if (g_SubsystemFlags & SubsysFlag_MemoryMonitor) {
        MmMonitorShutdown();
        g_SubsystemFlags &= ~SubsysFlag_MemoryMonitor;
    }
    if (g_SubsystemFlags & SubsysFlag_MemoryScanner) {
        MsShutdown(g_MemoryScanner);
        g_MemoryScanner = NULL;
        g_SubsystemFlags &= ~SubsysFlag_MemoryScanner;
    }
    if (g_SubsystemFlags & SubsysFlag_SyscallMonitor) {
        ScMonitorShutdown();
        g_SubsystemFlags &= ~SubsysFlag_SyscallMonitor;
    }
    if (g_SubsystemFlags & SubsysFlag_NetworkFilter) {
        NfFilterShutdown();
        g_SubsystemFlags &= ~SubsysFlag_NetworkFilter;
    }

    //
    // Communication subsystems - process analyzer + message routing.
    // Their senders may be blocked in FltSendMessage, but ScanBridge
    // Shutdown internally aborts those waiters.
    //
    if (g_SubsystemFlags & SubsysFlag_ProcessAnalyzer) {
        PaShutdown(&g_ProcessAnalyzer);
        g_ProcessAnalyzer = NULL;
        g_SubsystemFlags &= ~SubsysFlag_ProcessAnalyzer;
    }
    if (g_SubsystemFlags & SubsysFlag_MessageHandler) {
        MhShutdown();
        g_SubsystemFlags &= ~SubsysFlag_MessageHandler;
    }
    if (g_SubsystemFlags & SubsysFlag_ScanBridge) {
        ShadowStrikeScanBridgeShutdown();
        g_SubsystemFlags &= ~SubsysFlag_ScanBridge;
    }
    if (g_SubsystemFlags & SubsysFlag_MessageQueue) {
        MqShutdown();
        g_SubsystemFlags &= ~SubsysFlag_MessageQueue;
    }

    //
    // ThreatScoring publishes to BehaviorEngine - safe to drop once BE
    // is down.
    //
    if (g_SubsystemFlags & SubsysFlag_ThreatScoring) {
        TsShutdown(g_ThreatScoring);
        g_ThreatScoring = NULL;
        g_SubsystemFlags &= ~SubsysFlag_ThreatScoring;
    }

    //
    // ETW consumer (worker thread for batched event emit).
    //
    if (g_EtwConsumer != NULL) {
        EcShutdown(&g_EtwConsumer);
        g_EtwConsumer = NULL;
    }

    //
    // Batch processor (owns its own worker thread).
    //
    if (g_SubsystemFlags & SubsysFlag_BatchProcessing) {
        BpStop(g_BatchProcessor);
        BpShutdown(g_BatchProcessor);
        g_BatchProcessor = NULL;
        g_SubsystemFlags &= ~SubsysFlag_BatchProcessing;
    }

    //
    // Resource throttler (owns worker thread).
    //
    if (g_SubsystemFlags & SubsysFlag_ResourceThrottling) {
        RtShutdown(&g_ResourceThrottler);
        g_ResourceThrottler = NULL;
        g_SubsystemFlags &= ~SubsysFlag_ResourceThrottling;
    }

    //
    // Generic work infrastructure - callbacks queue work here; must
    // drain before they can finish releasing rundown.
    //
    if (g_SubsystemFlags & SubsysFlag_AsyncWorkQueue) {
        AwqShutdown(g_AsyncWorkQueue);
        g_AsyncWorkQueue = NULL;
        g_SubsystemFlags &= ~SubsysFlag_AsyncWorkQueue;
    }
    if (g_SubsystemFlags & SubsysFlag_ThreadPool) {
        TpDestroy(&g_ThreadPool, TRUE);
        g_ThreadPool = NULL;
        g_SubsystemFlags &= ~SubsysFlag_ThreadPool;
    }
    if (g_SubsystemFlags & SubsysFlag_WorkQueue) {
        ShadowStrikeWorkQueueShutdown(TRUE);
        g_SubsystemFlags &= ~SubsysFlag_WorkQueue;
    }

    //
    // DPC infrastructure - flush queued DPCs first so any DPC-bound
    // callback state is consumed, then tear down the DPC manager.
    //
    KeFlushQueuedDpcs();
    if (g_SubsystemFlags & SubsysFlag_DeferredProcedure) {
        DpcShutdown(&g_DpcManager);
        g_DpcManager = NULL;
        g_SubsystemFlags &= ~SubsysFlag_DeferredProcedure;
    }

    //
    // Step 3: Bounded wait for the global rundown to drain. The pre-drain
    // above should have eliminated the hold-and-wait cycle; if anything
    // is still stuck we will know it within the bounded budget instead
    // of hanging the OS shutdown watchdog indefinitely.
    //
    // Budgets:
    //   Mandatory unload (OS forcing us out): 10 s; proceed past timeout
    //     - the alternative is hanging shutdown.
    //   Voluntary unload (admin requested): 5 s; REFUSE unload on
    //     timeout via STATUS_FLT_DO_NOT_DETACH. The driver is left
    //     half-quiesced and a reboot is required to restore service;
    //     proceeding past a stuck callback would UAF.
    //
    {
        ULONGLONG timeoutMs = mandatoryUnload ? 10000ULL : 5000ULL;
        NTSTATUS  waitStatus;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] Unload: InFlight(P=%ld T=%ld PAS=%ld) - "
                   "bounded rundown wait %llums\n",
                   ReadAcquire(&g_DriverData.InFlightProcess),
                   ReadAcquire(&g_DriverData.InFlightThread),
                   ReadAcquire(&g_DriverData.InFlightPreAcquireSection),
                   timeoutMs);

        waitStatus = ShadowStrikeWaitForRundownCompleteBounded(timeoutMs);

        if (waitStatus == STATUS_TIMEOUT) {
            LONG procIn = ReadAcquire(&g_DriverData.InFlightProcess);
            LONG thrIn  = ReadAcquire(&g_DriverData.InFlightThread);
            LONG pasIn  = ReadAcquire(&g_DriverData.InFlightPreAcquireSection);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike] RUNDOWN DRAIN TIMEOUT (%llums). "
                       "Flags=0x%08X Mandatory=%s "
                       "InFlight: Process=%ld Thread=%ld "
                       "PreAcquireSection=%ld\n",
                       timeoutMs, (ULONG)Flags,
                       mandatoryUnload ? "TRUE" : "FALSE",
                       procIn, thrIn, pasIn);

            EtwWriteDiagnosticEvent(
                EtwEventId_DriverStopping,
                TRACE_LEVEL_ERROR,
                0,
                mandatoryUnload
                    ? L"Rundown drain timeout (mandatory unload - proceeding)"
                    : L"Rundown drain timeout (voluntary unload - refused)",
                (UINT32)STATUS_TIMEOUT);

            if (!mandatoryUnload) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                           "[ShadowStrike] Voluntary unload TIMEOUT - "
                           "returning STATUS_FLT_DO_NOT_DETACH. Reboot "
                           "required to restore service.\n");
                return STATUS_FLT_DO_NOT_DETACH;
            }

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] Mandatory unload TIMEOUT - "
                       "proceeding past stuck callback (OS shutdown "
                       "context).\n");
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike] Rundown drained (status=0x%08X), "
                       "proceeding with cleanup.\n",
                       waitStatus);
        }
    }

    //
    // Step 3: Unprotect callbacks from tamper detection before unregistering
    //
    if (g_SubsystemFlags & SubsysFlag_CallbackProtection) {
        CpDisablePeriodicVerify(g_CallbackProtector);

        if (g_DriverData.ProcessNotifyRegistered) {
            CpUnprotectCallback(g_CallbackProtector, (PVOID)ShadowStrikeProcessNotifyCallback);
        }
        if (g_DriverData.ThreadNotifyRegistered) {
            PVOID threadCbPtr = TnGetNotifyCallbackPointer();
            if (threadCbPtr != NULL) {
                CpUnprotectCallback(g_CallbackProtector, threadCbPtr);
            }
        }
        if (g_DriverData.ImageNotifyRegistered) {
            CpUnprotectCallback(g_CallbackProtector, (PVOID)ImageLoadNotifyRoutine);
        }
        if (g_InitFlags & InitFlag_RegistryCallbackReg) {
            CpUnprotectCallback(g_CallbackProtector, (PVOID)(ULONG_PTR)g_DriverData.RegistryCallbackCookie.QuadPart);
        }
        if (g_InitFlags & InitFlag_ObjectCallbackReg) {
            CpUnprotectCallback(g_CallbackProtector, g_DriverData.ObjectCallbackHandle);
        }
        if (g_InitFlags & InitFlag_FilterRegistered) {
            CpUnprotectCallback(g_CallbackProtector, (PVOID)g_DriverData.FilterHandle);
        }
    }

    //
    // Step 4: Unregister callbacks in reverse order of registration
    //
    if (g_InitFlags & InitFlag_ObjectCallbackReg) {
        ShadowStrikeUnregisterObjectCallbacks();
    }

    if (g_InitFlags & InitFlag_RegistryCallbackReg) {
        ShadowStrikeUnregisterRegistryCallback();
    }

    if (g_InitFlags & InitFlag_RegistryMonitorInit) {
        ShadowStrikeCleanupRegistryMonitoring();
    }

    ShadowStrikeUnregisterProcessCallbacks(g_CallbackFlags);

    //
    // Step 4: Shutdown self-protection subsystem
    //
    if (g_InitFlags & InitFlag_SelfProtectInitialized) {
        ShadowStrikeShutdownSelfProtection();
    }

    //
    // Step 4.5: Shutdown named pipe monitoring
    //
    if (g_InitFlags & InitFlag_NamedPipeMonInitialized) {
        NpMonShutdown();
    }

    //
    // Step 4.6: Shutdown AMSI bypass detector
    //
    if (g_InitFlags & InitFlag_AmsiBypassDetInitialized) {
        AbdShutdown();
    }

    //
    // Step 4.7: Shutdown file backup engine
    //
    if (g_InitFlags & InitFlag_FileBackupEngineInitialized) {
        FbeShutdown();
    }

    //
    // Step 4.8: Shutdown USB device control
    //
    if (g_InitFlags & InitFlag_USBDeviceControlInitialized) {
        UdcShutdown();
    }

    //
    // Step 4.9: Shutdown WSL monitor
    //
    if (g_InitFlags & InitFlag_WslMonitorInitialized) {
        WslMonShutdown();
    }

    //
    // Step 4.10: Shutdown application control
    //
    if (g_InitFlags & InitFlag_AppControlInitialized) {
        AcShutdown();
    }

    //
    // Step 4.11: Shutdown firmware integrity
    //
    if (g_InitFlags & InitFlag_FirmwareIntegrityInitialized) {
        FiShutdown();
    }

    //
    // Step 4.12: Shutdown clipboard monitor
    //
    if (g_InitFlags & InitFlag_ClipboardMonitorInitialized) {
        CbMonShutdown();
    }

    //
    // Step 5: Shutdown process exclusion engine (BEFORE ExclusionManager)
    // ProcessExclusion depends on ExclusionManager â€” shut down dependent first.
    //
    ShadowStrikeProcessExclusionShutdown();

    //
    // Step 5.1: Shutdown exclusion manager
    //
    if (g_InitFlags & InitFlag_ExclusionsInitialized) {
        ShadowStrikeExclusionShutdown();
    }

    //
    // Step 6: Cleanup hash utilities
    //
    if (g_InitFlags & InitFlag_HashUtilsInitialized) {
        ShadowStrikeCleanupHashUtils();
    }

    //
    // Step 7: Shutdown scan cache (CRITICAL - was missing before)
    //
    if (g_InitFlags & InitFlag_ScanCacheInitialized) {
        ShadowStrikeCacheShutdown();
    }

    //
    // Step 8: Close communication port
    //
    if (g_InitFlags & InitFlag_CommPortCreated) {
        ShadowStrikeCloseCommunicationPort();
    }

    //
    // Step 8.4: Shutdown PostWrite subsystem (BEFORE PostCreate â€”
    // PostWrite has its own PsSetCreateProcessNotifyRoutineEx that must
    // be unregistered before filter teardown)
    //
    if (g_InitFlags & InitFlag_PwInitialized) {
        ShadowStrikePostWriteShutdown();
    }

    //
    // Step 8.4a: Shutdown PreAcquireSection subsystem (cancel cleanup timer,
    // drain process contexts and mapping records)
    //
    if (g_InitFlags & InitFlag_PasInitialized) {
        ShadowStrikePreAcquireSectionShutdown();
    }

    //
    // Step 8.4b: Shutdown PreCreate subsystem (rundown protection drain,
    // honeypot pattern cleanup, lookaside list deletion)
    //
    if (g_PreSetInfoInitialized) {
        ShadowStrikeCleanupPreSetInfo();
        g_PreSetInfoInitialized = FALSE;
    }

    if (g_PreWriteInitialized) {
        ShadowStrikeCleanupPreWrite();
        g_PreWriteInitialized = FALSE;
    }

    if (g_SubsystemFlags & SubsysFlag_PreCreate) {
        PcShutdown();
        g_SubsystemFlags &= ~SubsysFlag_PreCreate;
    }

    //
    // Step 8.5: Shutdown PostCreate subsystem (BEFORE FltUnregisterFilter â€”
    // marks ShutdownRequested so in-flight post-creates drain cleanly)
    //
    if (g_InitFlags & InitFlag_PocInitialized) {
        PocShutdown();
    }

    //
    // Step 9: Unregister filter
    //
    if (g_InitFlags & InitFlag_FilterRegistered) {
        if (g_DriverData.FilterHandle != NULL) {
            FltUnregisterFilter(g_DriverData.FilterHandle);
            g_DriverData.FilterHandle = NULL;
        }
    }

    //
    // Step 9.5: Cleanup filesystem callbacks (AFTER FltUnregisterFilter â€” 
    // InstanceTeardownComplete accesses FSC state during filter teardown)
    //
    if (g_InitFlags & InitFlag_FscInitialized) {
        ShadowStrikeCleanupFileSystemCallbacks();
    }

    //
    // Step 9.6: Cleanup file utilities (AFTER FltUnregisterFilter â€”
    // filter callbacks may call FileUtils functions; must drain first)
    //
    if (g_FileUtilsInitialized) {
        ShadowStrikeCleanupFileUtils();
        g_FileUtilsInitialized = FALSE;
    }

    // =========================================================================
    // PHASE 6A SHUTDOWN: Scoring Orchestration
    // =========================================================================

    if (g_SubsystemFlags & SubsysFlag_ThreatScoring) {
        TsShutdown(g_ThreatScoring);
        g_ThreatScoring = NULL;
    }

    // =========================================================================
    // PHASE 5 SHUTDOWN: Specialized Subsystems (reverse init order)
    // =========================================================================

    if (g_SubsystemFlags & SubsysFlag_ObjectNamespace) {
        ShadowDestroyPrivateNamespace();
    }

    if (g_SubsystemFlags & SubsysFlag_KtmMonitor) {
        ShadowCleanupKtmMonitor();
    }

    if (g_SubsystemFlags & SubsysFlag_AlpcPortMonitor) {
        ShadowAlpcCleanup();
    }

    // =========================================================================
    // PHASE 4 SHUTDOWN: Self-Protection Hardening (reverse init order)
    // =========================================================================

    //
    // IntegrityMonitor depends on CallbackProtection (calls CpVerifyAll),
    // so it MUST be shut down first to prevent UAF during unload.
    //
    if (g_SubsystemFlags & SubsysFlag_IntegrityMonitor) {
        ImShutdown(&g_IntegrityMonitor);
        g_IntegrityMonitor = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_CallbackProtection) {
        CpShutdown(g_CallbackProtector);
        g_CallbackProtector = NULL;
    }

    if (g_InitFlags & InitFlag_FileProtectionInitialized) {
        FpShutdown(g_FileProtectionEngine);
        g_FileProtectionEngine = NULL;
    }

    if (g_InitFlags & InitFlag_AntiUnloadInitialized) {
        AuShutdown(g_AntiUnloadProtector);
        g_AntiUnloadProtector = NULL;
    }

    if (g_InitFlags & InitFlag_AntiDebugInitialized) {
        AdbShutdown(g_AntiDebugProtector);
        g_AntiDebugProtector = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_HandleProtection) {
        HpShutdown(g_HandleProtection);
        g_HandleProtection = NULL;
    }

    //
    // Phase 4A shutdown: ELAM boot-time protection
    //
    if (g_InitFlags & InitFlag_ElamInitialized) {
        ElamUnregisterCallback();
        ElamDriverShutdown();
    }

    // =========================================================================
    // PHASE 3 SHUTDOWN: Enrichment & Communication (reverse init order)
    // =========================================================================

    if (g_SubsystemFlags & SubsysFlag_MessageQueue) {
        MqShutdown();
    }

    if (g_SubsystemFlags & SubsysFlag_ScanBridge) {
        ShadowStrikeScanBridgeShutdown();
    }

    if (g_SubsystemFlags & SubsysFlag_MessageHandler) {
        MhShutdown();
    }

    if (g_SubsystemFlags & SubsysFlag_ProcessAnalyzer) {
        PaShutdown(&g_ProcessAnalyzer);
        g_ProcessAnalyzer = NULL;
    }

    // =========================================================================
    // PHASE 2 SHUTDOWN: Detection Subsystems (reverse init order)
    // =========================================================================

    if (g_SubsystemFlags & SubsysFlag_NetworkFilter) {
        NfFilterShutdown();
    }

    if (g_SubsystemFlags & SubsysFlag_SyscallMonitor) {
        ScMonitorShutdown();
    }

    if (g_SubsystemFlags & SubsysFlag_MemoryScanner) {
        MsShutdown(g_MemoryScanner);
        g_MemoryScanner = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_MemoryMonitor) {
        MmMonitorShutdown();
    }

    //
    // Unregister power-to-behavior bridge BEFORE shutting down BehaviorEngine.
    // Prevents ShadowStrikePowerBehaviorBridge from calling BeEngineSubmitEvent
    // on a destroyed engine during power transitions.
    //
    if (g_PowerBehaviorBridgeHandle != NULL) {
        ShadowPowerUnregisterCallback(g_PowerBehaviorBridgeHandle);
        g_PowerBehaviorBridgeHandle = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_BehaviorEngine) {
        BeEngineShutdown();
    }

    // =========================================================================
    // PHASE 1D SHUTDOWN: Telemetry Pipeline (reverse init order)
    // =========================================================================

    if (g_ManifestGenerator != NULL) {
        MgShutdown(g_ManifestGenerator);
        g_ManifestGenerator = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_EventSchema) {
        EsShutdown(&g_EventSchema);
        g_EventSchema = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_TelemetryEvents) {
        TeShutdown();
    }

    if (g_SubsystemFlags & SubsysFlag_TelemetryBuffer) {
        TbStop(g_TelemetryBuffer, TRUE);
        TbShutdown(g_TelemetryBuffer);
        g_TelemetryBuffer = NULL;
    }

    //
    // Shutdown compression engine
    //
    CompShutdown(&g_CompressionManager);

    //
    // Shutdown ETW consumer event pipeline
    //
    if (g_EtwConsumer != NULL) {
        EcShutdown(&g_EtwConsumer);
        g_EtwConsumer = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_ETWProvider) {
        EtwProviderShutdown();
    }

    //
    // Shutdown encryption engine
    //
    EncShutdown(&g_EncryptionManager);

    // =========================================================================
    // PHASE 1C SHUTDOWN: Power Management
    // =========================================================================

    if (g_SubsystemFlags & SubsysFlag_PowerCallback) {
        // Power behavior bridge already unregistered above (before BehaviorEngine shutdown)
        ShadowUnregisterPowerCallbacks();
    }

    // =========================================================================
    // PHASE 1B SHUTDOWN: Performance Infrastructure (reverse init order)
    // =========================================================================

    if (g_SubsystemFlags & SubsysFlag_CacheOptimization) {
        CoShutdown(g_CacheOptimizer);
        g_CacheOptimizer = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_BatchProcessing) {
        BpStop(g_BatchProcessor);
        BpShutdown(g_BatchProcessor);
        g_BatchProcessor = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_ResourceThrottling) {
        RtShutdown(&g_ResourceThrottler);
        g_ResourceThrottler = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_PerformanceMonitor) {
        SsPmShutdown(g_PerformanceMonitor);
        g_PerformanceMonitor = NULL;
    }

    //
    // Shutdown centralized lookaside manager
    //
    if (g_LookasideManager != NULL) {
        LlShutdown(&g_LookasideManager);
        g_LookasideManager = NULL;
    }

    // =========================================================================
    // PHASE 1A SHUTDOWN: Synchronization Infrastructure (reverse init order)
    // =========================================================================

    if (g_SubsystemFlags & SubsysFlag_DeferredProcedure) {
        DpcShutdown(&g_DpcManager);
        g_DpcManager = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_TimerManager) {
        TmShutdown(g_TimerManager);
        g_TimerManager = NULL;
    }

    // Delete control device created for TimerManager work items
    if (g_TimerControlDevice != NULL) {
        IoDeleteDevice(g_TimerControlDevice);
        g_TimerControlDevice = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_AsyncWorkQueue) {
        AwqShutdown(g_AsyncWorkQueue);
        g_AsyncWorkQueue = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_ThreadPool) {
        TpDestroy(&g_ThreadPool, TRUE);
        g_ThreadPool = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_WorkQueue) {
        ShadowStrikeWorkQueueShutdown(TRUE);
    }

    if (g_SubsystemFlags & SubsysFlag_SpinLockSubsystem) {
        ShadowStrikeLockSubsystemCleanup();
    }

    g_SubsystemFlags = SubsysFlag_None;

    //
    // Step 10: Cleanup lookaside lists
    //
    if (g_InitFlags & InitFlag_LookasideLists) {
        ShadowStrikeCleanupLookasideLists();
        g_DriverData.LookasideInitialized = FALSE;
    }

    //
    // Step 11: Cleanup protected process list
    //
    ShadowStrikeCleanupProtectedProcessList();

    //
    // Log final statistics
    //
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Final stats: Scanned=%lld, Blocked=%lld, CacheHits=%lld, TotalOps=%lld\n",
               g_DriverData.Stats.TotalFilesScanned,
               g_DriverData.Stats.FilesBlocked,
               g_DriverData.Stats.CacheHits,
               g_DriverData.TotalOperationsProcessed);

    //
    // Behavioural alert forward accounting. Emitted as its own line rather than
    // appended to the statement above so the existing format string and its
    // argument list stay paired.
    //
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Final stats: BehavioralAlerts forwarded=%lld, "
               "suppressed(self)=%lld, suppressed(budget)=%lld\n",
               g_EtwAlertsForwarded,
               g_EtwAlertsSuppressedSelf,
               g_EtwAlertsSuppressedBudget);

    WriteBooleanRelease(&g_DriverData.Initialized, FALSE);
    g_InitFlags = InitFlag_None;

    //
    // Step 11.5: Cleanup process utilities (creating context table drain).
    // Must happen before MemoryUtils cleanup since it frees pool memory.
    //
    if (g_ProcessUtilsInitialized) {
        ShadowProcessUtilsCleanup();
        g_ProcessUtilsInitialized = FALSE;
    }

    //
    // Step 12: Cleanup memory utilities (foundational â€” must be after all other
    // module cleanups that may free memory; logs leak stats in debug builds)
    //
    ShadowStrikeCleanupMemoryUtils();

    //
    // FINAL: Shutdown WPP tracing (must be last â€” after all trace-emitting code)
    //
    WppTraceShutdown(g_DriverData.DriverObject);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Driver unloaded successfully\n");

    return STATUS_SUCCESS;
}

// ============================================================================
// SUBSYSTEM ACCESSORS
// ============================================================================

PVOID
ShadowStrikeGetThreatScoringEngine(VOID)
{
    return (PVOID)g_ThreatScoring;
}

_Use_decl_annotations_
PVOID
ShadowStrikeGetBehaviorEngine(VOID)
{
    return (g_SubsystemFlags & SubsysFlag_BehaviorEngine) ?
           BeEngineGetInstance() : NULL;
}

PBP_PROCESSOR
ShadowStrikeGetBatchProcessor(VOID)
{
    return g_BatchProcessor;
}

PCO_MANAGER
ShadowStrikeGetCacheManager(VOID)
{
    return g_CacheOptimizer;
}

PLL_MANAGER
ShadowStrikeGetLookasideManager(VOID)
{
    return g_LookasideManager;
}

_Use_decl_annotations_
NTSTATUS
ShadowStrikeBatchSendNotification(
    _In_ UINT16 MessageType,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize
    )
{
    PBP_PROCESSOR proc = g_BatchProcessor;

    //
    // Try batch path first â€” routes through BpQueueEvent, which is safe up
    // to DISPATCH_LEVEL. The batch processing thread will deliver via CommPort.
    //
    if (proc != NULL) {
        NTSTATUS status = BpQueueEvent(proc, (ULONG)MessageType, Data, (SIZE_T)DataSize);
        if (NT_SUCCESS(status)) {
            return status;
        }
        //
        // Batch enqueue failed (shutting down, full, or OOM).
        // Fall through to direct send.
        //
    }

    //
    // Fallback: build a full message header and send directly via CommPort.
    // IRQL SAFETY: ShadowStrikeSendNotification uses FltSendMessage which
    // requires IRQL <= APC_LEVEL. If we're above APC_LEVEL (e.g. called from
    // a DPC or spinlock-holding context after batch processor teardown),
    // we must drop the event rather than BSOD.
    //
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_UNSUCCESSFUL;
    }

    {
        ULONG totalSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + DataSize;
        PSHADOWSTRIKE_MESSAGE_HEADER msg;
        NTSTATUS sendStatus;

        if (totalSize < sizeof(SHADOWSTRIKE_MESSAGE_HEADER) ||
            DataSize > BP_MAX_EVENT_DATA_SIZE) {
            return STATUS_INVALID_PARAMETER;
        }

        msg = (PSHADOWSTRIKE_MESSAGE_HEADER)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, totalSize, 'btCP');
        if (msg == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(msg, sizeof(SHADOWSTRIKE_MESSAGE_HEADER));
        msg->Magic = SHADOWSTRIKE_MESSAGE_MAGIC;
        msg->Version = SHADOWSTRIKE_PROTOCOL_VERSION;
        msg->MessageType = MessageType;
        msg->TotalSize = totalSize;
        msg->DataSize = DataSize;
        KeQuerySystemTime((PLARGE_INTEGER)&msg->Timestamp);

        if (DataSize > 0 && Data != NULL) {
            RtlCopyMemory(
                (PUCHAR)msg + sizeof(SHADOWSTRIKE_MESSAGE_HEADER),
                Data,
                DataSize
            );
        }

        sendStatus = ShadowStrikeSendNotification(msg, totalSize);
        ExFreePoolWithTag(msg, 'btCP');

        return sendStatus;
    }
}

PTM_MANAGER
ShadowStrikeGetTimerManager(VOID)
{
    return g_TimerManager;
}

PENC_MANAGER
ShadowStrikeGetEncryptionManager(VOID)
{
    if (!g_EncryptionManager.Initialized) {
        return NULL;
    }
    return &g_EncryptionManager;
}

PCOMP_MANAGER
ShadowStrikeGetCompressionManager(VOID)
{
    if (!g_CompressionManager.Initialized) {
        return NULL;
    }
    return &g_CompressionManager;
}

PPA_ANALYZER
ShadowStrikeGetProcessAnalyzer(VOID)
{
    return g_ProcessAnalyzer;
}

PTB_MANAGER
ShadowStrikeGetTelemetryBuffer(VOID)
{
    return g_TelemetryBuffer;
}

PEC_CONSUMER
ShadowStrikeGetETWConsumer(VOID)
{
    return g_EtwConsumer;
}

PES_SCHEMA
ShadowStrikeGetEventSchema(VOID)
{
    return g_EventSchema;
}

PMG_GENERATOR
ShadowStrikeGetManifestGenerator(VOID)
{
    return g_ManifestGenerator;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
PSSPM_MONITOR
ShadowStrikeGetPerformanceMonitor(VOID)
{
    return g_PerformanceMonitor;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
PRT_THROTTLER
ShadowStrikeGetResourceThrottler(VOID)
{
    return g_ResourceThrottler;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
PMS_SCANNER
ShadowStrikeGetMemoryScanner(VOID)
{
    return g_MemoryScanner;
}

_IRQL_requires_max_(APC_LEVEL)
PADB_PROTECTOR
ShadowStrikeGetAntiDebugProtector(VOID)
{
    return g_AntiDebugProtector;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
PAU_PROTECTOR
ShadowStrikeGetAntiUnloadProtector(VOID)
{
    return g_AntiUnloadProtector;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
PCP_PROTECTOR
ShadowStrikeGetCallbackProtector(VOID)
{
    return g_CallbackProtector;
}

_IRQL_requires_max_(APC_LEVEL)
PFP_ENGINE
ShadowStrikeGetFileProtectionEngine(VOID)
{
    return g_FileProtectionEngine;
}

_IRQL_requires_max_(APC_LEVEL)
PHP_PROTECTION_ENGINE
ShadowStrikeGetHandleProtection(VOID)
{
    return g_HandleProtection;
}

_IRQL_requires_max_(APC_LEVEL)
PIM_MONITOR
ShadowStrikeGetIntegrityMonitor(VOID)
{
    return g_IntegrityMonitor;
}

_IRQL_requires_max_(APC_LEVEL)
HAWQ_MANAGER
ShadowStrikeGetAsyncWorkQueue(VOID)
{
    return g_AsyncWorkQueue;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
PDPC_MANAGER
ShadowStrikeGetDpcManager(VOID)
{
    return g_DpcManager;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
PTP_THREAD_POOL
ShadowStrikeGetThreadPool(VOID)
{
    return g_ThreadPool;
}

// ============================================================================
// VERSION COMPATIBILITY CHECK
// ============================================================================

NTSTATUS
ShadowStrikeCheckVersionCompatibility(
    _Out_opt_ PULONG OutBuildNumber
    )
{
    RTL_OSVERSIONINFOW versionInfo;
    NTSTATUS status;

    RtlZeroMemory(&versionInfo, sizeof(versionInfo));
    versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);

    status = RtlGetVersion(&versionInfo);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] RtlGetVersion failed: 0x%08X\n", status);
        return status;
    }

    if (OutBuildNumber != NULL) {
        *OutBuildNumber = versionInfo.dwBuildNumber;
    }

    //
    // Check minimum build number
    //
    if (versionInfo.dwBuildNumber < SHADOWSTRIKE_MIN_BUILD_NUMBER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Unsupported Windows version: Build %lu < %lu required\n",
                   versionInfo.dwBuildNumber,
                   (ULONG)SHADOWSTRIKE_MIN_BUILD_NUMBER);
        return STATUS_NOT_SUPPORTED;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// CONFIGURATION LOADING
// ============================================================================

NTSTATUS
ShadowStrikeLoadConfiguration(
    _In_ PUNICODE_STRING RegistryPath,
    _Out_ PSHADOWSTRIKE_CONFIG Config
    )
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE keyHandle = NULL;
    ULONG resultLength;
    UCHAR valueBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION valueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)valueBuffer;
    UNICODE_STRING valueName;

    //
    // Start with defaults
    //
    ShadowStrikeInitDefaultConfig(Config);

    if (RegistryPath == NULL || RegistryPath->Buffer == NULL) {
        return STATUS_SUCCESS;
    }

    //
    // Open the driver's registry key
    //
    InitializeObjectAttributes(
        &objAttr,
        RegistryPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    status = ZwOpenKey(&keyHandle, KEY_READ, &objAttr);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Cannot open registry key: 0x%08X\n", status);
        return STATUS_SUCCESS; // Use defaults
    }

    //
    // Read ScanTimeoutMs
    //
    RtlInitUnicodeString(&valueName, L"ScanTimeoutMs");
    status = ZwQueryValueKey(
        keyHandle,
        &valueName,
        KeyValuePartialInformation,
        valueInfo,
        sizeof(valueBuffer),
        &resultLength
    );
    if (NT_SUCCESS(status) && valueInfo->Type == REG_DWORD && valueInfo->DataLength == sizeof(ULONG)) {
        ULONG timeout = *(PULONG)valueInfo->Data;
        if (timeout >= SHADOWSTRIKE_MIN_SCAN_TIMEOUT_MS &&
            timeout <= SHADOWSTRIKE_MAX_SCAN_TIMEOUT_MS) {
            Config->ScanTimeoutMs = timeout;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike] Config: ScanTimeoutMs = %lu\n", timeout);
        }
    }

    //
    // Read CacheTTLSeconds
    //
    RtlInitUnicodeString(&valueName, L"CacheTTLSeconds");
    status = ZwQueryValueKey(
        keyHandle,
        &valueName,
        KeyValuePartialInformation,
        valueInfo,
        sizeof(valueBuffer),
        &resultLength
    );
    if (NT_SUCCESS(status) && valueInfo->Type == REG_DWORD && valueInfo->DataLength == sizeof(ULONG)) {
        ULONG ttl = *(PULONG)valueInfo->Data;
        if (ttl > 0 && ttl <= SHADOWSTRIKE_CACHE_MAX_TTL) {
            Config->CacheTTLSeconds = ttl;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                       "[ShadowStrike] Config: CacheTTLSeconds = %lu\n", ttl);
        }
    }

    //
    // Read SelfProtectionEnabled
    //
    RtlInitUnicodeString(&valueName, L"SelfProtectionEnabled");
    status = ZwQueryValueKey(
        keyHandle,
        &valueName,
        KeyValuePartialInformation,
        valueInfo,
        sizeof(valueBuffer),
        &resultLength
    );
    if (NT_SUCCESS(status) && valueInfo->Type == REG_DWORD && valueInfo->DataLength == sizeof(ULONG)) {
        Config->SelfProtectionEnabled = (*(PULONG)valueInfo->Data) != 0;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] Config: SelfProtectionEnabled = %u\n",
                   Config->SelfProtectionEnabled);
    }

    ZwClose(keyHandle);
    return STATUS_SUCCESS;
}

// ============================================================================
// LOOKASIDE LIST MANAGEMENT
// ============================================================================

NTSTATUS
ShadowStrikeInitializeLookasideLists(
    VOID
    )
{
    PAGED_CODE();

    //
    // Message lookaside - for kernel<->user messages
    //
    ExInitializeNPagedLookasideList(
        &g_DriverData.MessageLookaside,
        NULL,                           // Allocate function (use default)
        NULL,                           // Free function (use default)
        POOL_NX_ALLOCATION,             // Non-executable pool
        SHADOWSTRIKE_MAX_MESSAGE_SIZE,  // Entry size
        SHADOWSTRIKE_POOL_TAG,          // Pool tag
        0                               // Depth (0 = system default)
    );

    //
    // Stream context lookaside - for per-file tracking
    //
    ExInitializeNPagedLookasideList(
        &g_DriverData.StreamContextLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(SHADOWSTRIKE_STREAM_CONTEXT),
        SHADOWSTRIKE_POOL_TAG,
        0
    );

    return STATUS_SUCCESS;
}

VOID
ShadowStrikeCleanupLookasideLists(
    VOID
    )
{
    PAGED_CODE();

    ExDeleteNPagedLookasideList(&g_DriverData.MessageLookaside);
    ExDeleteNPagedLookasideList(&g_DriverData.StreamContextLookaside);
}

// ============================================================================
// PROCESS CALLBACK REGISTRATION
// ============================================================================

NTSTATUS
ShadowStrikeRegisterProcessCallbacks(
    _Out_ PULONG OutFlags
    )
{
    NTSTATUS status;

    PAGED_CODE();

    *OutFlags = 0;

    //
    // Register process creation/termination callback (MANDATORY)
    //
    status = PsSetCreateProcessNotifyRoutineEx(
        ShadowStrikeProcessNotifyCallback,
        FALSE   // Register (not remove)
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] CRITICAL: PsSetCreateProcessNotifyRoutineEx failed: 0x%08X\n",
                   status);
        return status;
    }

    g_DriverData.ProcessNotifyRegistered = TRUE;
    *OutFlags |= InitFlag_ProcessCallbackReg;
    g_InitFlags |= InitFlag_ProcessCallbackReg;
    ShadowStrikeLogInitStatus("Process Notify", status);

    //
    // Register thread creation callback via ThreadNotify module
    // (injection detection, shellcode analysis, cross-process monitoring, BehaviorEngine)
    //
    status = RegisterThreadNotify();
    if (NT_SUCCESS(status)) {
        // RegisterThreadNotify already sets g_DriverData.ThreadNotifyRegistered = TRUE
        *OutFlags |= InitFlag_ThreadCallbackReg;
        g_InitFlags |= InitFlag_ThreadCallbackReg;
        ShadowStrikeLogInitStatus("Thread Notify", status);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: RegisterThreadNotify failed: 0x%08X\n",
                   status);
    }

    //
    // Register image load callback via ImageNotify module
    // (PE analysis, hash computation, BYOVD, module tracking, BehaviorEngine)
    //
    status = ImageNotifyInitialize(NULL);
    if (NT_SUCCESS(status)) {
        NTSTATUS regStatus = RegisterImageNotify();
        if (NT_SUCCESS(regStatus)) {
            g_DriverData.ImageNotifyRegistered = TRUE;
            *OutFlags |= InitFlag_ImageCallbackReg;
            g_InitFlags |= InitFlag_ImageCallbackReg;
            ShadowStrikeLogInitStatus("Image Notify", regStatus);
        } else {
            //
            // Registration failed AFTER successful Initialize() — must tear
            // down the subsystem to avoid a permanent leak of internal state
            // (lookasides, locks, hash tables) that ImageNotifyInitialize
            // allocated. Without this, ImageNotifyShutdown is never reached
            // because g_DriverData.ImageNotifyRegistered stays FALSE and the
            // unload path skips it.
            //
            ImageNotifyShutdown();
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] WARNING: RegisterImageNotify failed after init: 0x%08X — subsystem torn down\n",
                       regStatus);
        }
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: ImageNotifyInitialize failed: 0x%08X\n",
                   status);
    }

    return STATUS_SUCCESS;
}

VOID
ShadowStrikeUnregisterProcessCallbacks(
    _In_ ULONG Flags
    )
{
    PAGED_CODE();

    if (Flags & InitFlag_ImageCallbackReg) {
        if (g_DriverData.ImageNotifyRegistered) {
            ImageNotifyShutdown();
            g_DriverData.ImageNotifyRegistered = FALSE;
        }
    }

    if (Flags & InitFlag_ThreadCallbackReg) {
        if (g_DriverData.ThreadNotifyRegistered) {
            UnregisterThreadNotify();
            // UnregisterThreadNotify already sets g_DriverData.ThreadNotifyRegistered = FALSE
        }
    }

    if (Flags & InitFlag_ProcessCallbackReg) {
        if (g_DriverData.ProcessNotifyRegistered) {
            PsSetCreateProcessNotifyRoutineEx(
                ShadowStrikeProcessNotifyCallback,
                TRUE    // Remove
            );
            g_DriverData.ProcessNotifyRegistered = FALSE;
        }
    }
}



// ============================================================================
// PROTECTED PROCESS LIST MANAGEMENT
// ============================================================================

VOID
ShadowStrikeInitializeProtectedProcessList(
    VOID
    )
{
    // Already initialized in DriverEntry
}

VOID
ShadowStrikeCleanupProtectedProcessList(
    VOID
    )
{
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    PSHADOWSTRIKE_PROTECTED_PROCESS_ENTRY processEntry;

    //
    // Free all entries in the protected process list
    // CRITICAL FIX: Use proper CONTAINING_RECORD macro to get the full structure
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_DriverData.ProtectedProcessLock);

    for (entry = g_DriverData.ProtectedProcessList.Flink;
         entry != &g_DriverData.ProtectedProcessList;
         entry = nextEntry) {

        nextEntry = entry->Flink;

        //
        // Get the containing structure
        //
        processEntry = CONTAINING_RECORD(entry, SHADOWSTRIKE_PROTECTED_PROCESS_ENTRY, ListEntry);

        //
        // Dereference the EPROCESS if we have a reference
        //
        if (processEntry->Process != NULL) {
            ObDereferenceObject(processEntry->Process);
            processEntry->Process = NULL;
        }

        RemoveEntryList(entry);
        ExFreePoolWithTag(processEntry, SHADOWSTRIKE_POOL_TAG);
    }

    g_DriverData.ProtectedProcessCount = 0;

    ExReleasePushLockExclusive(&g_DriverData.ProtectedProcessLock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

VOID
ShadowStrikeWaitForRundownComplete(
    VOID
    )
{
    PAGED_CODE();

    //
    // Wait for rundown protection to drain
    // This blocks until all SHADOWSTRIKE_ACQUIRE_RUNDOWN() holders release
    //
    ExWaitForRundownProtectionRelease(&g_DriverData.RundownProtection);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Rundown protection released, all callbacks complete.\n");
}

//
// Context block for the bounded-wait worker. Heap-allocated because the
// worker thread can outlive the calling stack frame when the wait times
// out - we let the worker complete on its own rather than join it (joining
// would re-introduce the unbounded wait this primitive exists to avoid).
//
// Lifetime ownership:
//   - Success path: caller waits for Done, then references and joins the
//     worker for clean object teardown, then frees the context.
//   - Timeout path: caller drops its reference to the worker and returns;
//     the worker frees the context itself right before
//     PsTerminateSystemThread.
//
typedef struct _SHADOWSTRIKE_RUNDOWN_WAIT_CTX {
    PEX_RUNDOWN_REF Rundown;
    KEVENT          Done;
    volatile LONG   OwnerDone;  // 1 once caller path completed successfully
} SHADOWSTRIKE_RUNDOWN_WAIT_CTX, *PSHADOWSTRIKE_RUNDOWN_WAIT_CTX;

static VOID
ShadowStrikeRundownWaitWorker(
    _In_ PVOID StartContext
    )
{
    PSHADOWSTRIKE_RUNDOWN_WAIT_CTX ctx =
        (PSHADOWSTRIKE_RUNDOWN_WAIT_CTX)StartContext;

    PAGED_CODE();

    //
    // Same infinite wait the legacy code did, but now isolated on a
    // dedicated worker thread so the unload thread can apply a timeout.
    //
    ExWaitForRundownProtectionRelease(ctx->Rundown);

    KeSetEvent(&ctx->Done, IO_NO_INCREMENT, FALSE);

    //
    // If the caller has already completed (success path), it owns the
    // context and will free it after joining us. Otherwise (timeout
    // path), we own the context and must free it here before exit, since
    // the caller has abandoned it.
    //
    if (InterlockedCompareExchange(&ctx->OwnerDone, 0, 0) == 0) {
        ExFreePoolWithTag(ctx, SHADOWSTRIKE_POOL_TAG);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShadowStrikeWaitForRundownCompleteBounded(
    _In_ ULONGLONG TimeoutMs
    )
{
    PSHADOWSTRIKE_RUNDOWN_WAIT_CTX ctx = NULL;
    HANDLE                         threadHandle = NULL;
    PETHREAD                       workerThread = NULL;
    OBJECT_ATTRIBUTES              oa;
    LARGE_INTEGER                  timeout;
    NTSTATUS                       status;

    PAGED_CODE();

    ctx = (PSHADOWSTRIKE_RUNDOWN_WAIT_CTX)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(*ctx),
        SHADOWSTRIKE_POOL_TAG);
    if (ctx == NULL) {
        //
        // Allocation failure - degrade to the legacy unbounded wait
        // inline. This preserves correctness (callbacks still drain)
        // at the cost of losing the timeout, which is strictly no worse
        // than pre-patch behavior on the rare ENOMEM path.
        //
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Bounded-wait context alloc failed - "
                   "falling back to unbounded wait.\n");
        ExWaitForRundownProtectionRelease(&g_DriverData.RundownProtection);
        return STATUS_SUCCESS;
    }

    ctx->Rundown = &g_DriverData.RundownProtection;
    ctx->OwnerDone = 0;
    KeInitializeEvent(&ctx->Done, NotificationEvent, FALSE);

    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        &oa,
        NULL,
        NULL,
        ShadowStrikeRundownWaitWorker,
        ctx);

    if (!NT_SUCCESS(status)) {
        //
        // Could not spawn worker - degrade to the unbounded wait inline.
        //
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Bounded-wait worker spawn failed "
                   "(0x%08X) - falling back to unbounded wait.\n",
                   status);
        ExFreePoolWithTag(ctx, SHADOWSTRIKE_POOL_TAG);
        ExWaitForRundownProtectionRelease(&g_DriverData.RundownProtection);
        return STATUS_SUCCESS;
    }

    //
    // Resolve handle -> object reference so we can wait on the worker
    // thread after closing the handle. If this fails we still wait on
    // Done; the worker self-terminates regardless via
    // PsTerminateSystemThread.
    //
    (VOID)ObReferenceObjectByHandle(
        threadHandle,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        (PVOID*)&workerThread,
        NULL);
    ZwClose(threadHandle);
    threadHandle = NULL;

    //
    // Negative LARGE_INTEGER = relative wait in 100ns units.
    //
    timeout.QuadPart = -((LONGLONG)TimeoutMs * 10000LL);

    status = KeWaitForSingleObject(
        &ctx->Done,
        Executive,
        KernelMode,
        FALSE,
        &timeout);

    if (status == STATUS_TIMEOUT) {
        //
        // The worker is still parked inside ExWaitForRundownProtectionRelease.
        // We MUST NOT join it - joining is exactly the unbounded wait this
        // primitive exists to escape. Hand ownership of the context to the
        // worker (it will free it after the rundown eventually drains and
        // before calling PsTerminateSystemThread), drop our thread reference,
        // and return.
        //
        // The OwnerDone CAS protects against a race where the worker is just
        // about to wake up: if it observes OwnerDone == 0, it frees the
        // context; if (in the success-path code below) the caller wins the
        // CAS, the worker leaves the context alone and the caller frees it.
        //
        if (workerThread != NULL) {
            ObDereferenceObject(workerThread);
            workerThread = NULL;
        }
        // Context is now owned by the worker - do NOT free here.
        return STATUS_TIMEOUT;
    }

    //
    // Success path: worker has signaled Done and is exiting. Claim ownership
    // of the context so the worker won't free it, briefly wait for the
    // worker to actually finish so we can dereference cleanly, then free.
    //
    (VOID)InterlockedExchange(&ctx->OwnerDone, 1);

    if (workerThread != NULL) {
        KeWaitForSingleObject(
            workerThread,
            Executive,
            KernelMode,
            FALSE,
            NULL);
        ObDereferenceObject(workerThread);
        workerThread = NULL;
    }

    ExFreePoolWithTag(ctx, SHADOWSTRIKE_POOL_TAG);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Bounded rundown wait complete, all "
               "callbacks drained within %llums budget.\n", TimeoutMs);

    return STATUS_SUCCESS;
}

VOID
ShadowStrikeLogInitStatus(
    _In_ PCSTR Component,
    _In_ NTSTATUS Status
    )
{
    if (NT_SUCCESS(Status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "[ShadowStrike] %s: OK\n", Component);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] %s: FAILED (0x%08X)\n", Component, Status);
    }
}

VOID
ShadowStrikeCleanupByFlags(
    _In_ ULONG InitFlags
    )
{
    PAGED_CODE();

    //
    // Signal shutdown first â€” stop all callbacks from processing new events.
    // Mirror Steps 1-2 of ShadowStrikeUnload to prevent UAF during teardown.
    //
    WriteBooleanRelease(&g_DriverData.ShuttingDown, TRUE);
    MemoryBarrier();

    //
    // Drain rundown protection - wait for in-flight callback operations
    // that hold rundown refs (work items, DPCs, async operations).
    // Use the bounded variant with a 5-second budget so a stuck callback
    // on the partial-init failure path cannot hang the load thread (and
    // hence the OS service-control timeout). On timeout we proceed with
    // cleanup regardless - the failure path MUST always complete.
    //
    {
        NTSTATUS waitStatus =
            ShadowStrikeWaitForRundownCompleteBounded(5000ULL);
        if (waitStatus == STATUS_TIMEOUT) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike] CleanupByFlags: rundown drain "
                       "TIMEOUT - InFlight(P=%ld T=%ld PAS=%ld). "
                       "Proceeding with cleanup (failure path).\n",
                       ReadAcquire(&g_DriverData.InFlightProcess),
                       ReadAcquire(&g_DriverData.InFlightThread),
                       ReadAcquire(&g_DriverData.InFlightPreAcquireSection));
            EtwWriteDiagnosticEvent(
                EtwEventId_DriverStopping,
                TRACE_LEVEL_ERROR,
                0,
                L"CleanupByFlags rundown drain timeout - proceeding",
                (UINT32)STATUS_TIMEOUT);
        }
    }

    //
    // Emit ETW diagnostic event: driver cleanup starting (failure path)
    //
    EtwWriteDiagnosticEvent(
        EtwEventId_DriverStopping,
        TRACE_LEVEL_WARNING,
        0,
        L"Driver cleanup by flags",
        (UINT32)STATUS_UNSUCCESSFUL);

    //
    // Cleanup in reverse order based on what was actually initialized
    //

    // Unprotect callbacks from tamper detection before OS unregistration
    if (g_SubsystemFlags & SubsysFlag_CallbackProtection) {
        CpDisablePeriodicVerify(g_CallbackProtector);

        if (g_DriverData.ProcessNotifyRegistered) {
            CpUnprotectCallback(g_CallbackProtector, (PVOID)ShadowStrikeProcessNotifyCallback);
        }
        if (g_DriverData.ThreadNotifyRegistered) {
            PVOID threadCbPtr = TnGetNotifyCallbackPointer();
            if (threadCbPtr != NULL) {
                CpUnprotectCallback(g_CallbackProtector, threadCbPtr);
            }
        }
        if (g_DriverData.ImageNotifyRegistered) {
            CpUnprotectCallback(g_CallbackProtector, (PVOID)ImageLoadNotifyRoutine);
        }
        if (InitFlags & InitFlag_RegistryCallbackReg) {
            CpUnprotectCallback(g_CallbackProtector, (PVOID)(ULONG_PTR)g_DriverData.RegistryCallbackCookie.QuadPart);
        }
        if (InitFlags & InitFlag_ObjectCallbackReg) {
            CpUnprotectCallback(g_CallbackProtector, g_DriverData.ObjectCallbackHandle);
        }
        if (InitFlags & InitFlag_FilterRegistered) {
            CpUnprotectCallback(g_CallbackProtector, (PVOID)g_DriverData.FilterHandle);
        }

        //
        // ImShutdown BEFORE CpShutdown: IM worker thread calls CpVerifyAll.
        //
        if (g_SubsystemFlags & SubsysFlag_IntegrityMonitor) {
            ImShutdown(&g_IntegrityMonitor);
            g_IntegrityMonitor = NULL;
            g_SubsystemFlags &= ~SubsysFlag_IntegrityMonitor;
        }

        CpShutdown(g_CallbackProtector);
        g_CallbackProtector = NULL;
        g_SubsystemFlags &= ~SubsysFlag_CallbackProtection;
    }

    if (InitFlags & InitFlag_ObjectCallbackReg) {
        ShadowStrikeUnregisterObjectCallbacks();
    }

    if (InitFlags & InitFlag_RegistryCallbackReg) {
        ShadowStrikeUnregisterRegistryCallback();
    }

    if (InitFlags & InitFlag_RegistryMonitorInit) {
        ShadowStrikeCleanupRegistryMonitoring();
    }

    ShadowStrikeUnregisterProcessCallbacks(g_CallbackFlags);

    if (InitFlags & InitFlag_SelfProtectInitialized) {
        ShadowStrikeShutdownSelfProtection();
    }

    if (InitFlags & InitFlag_NamedPipeMonInitialized) {
        NpMonShutdown();
    }

    if (InitFlags & InitFlag_AmsiBypassDetInitialized) {
        AbdShutdown();
    }

    if (InitFlags & InitFlag_FileBackupEngineInitialized) {
        FbeShutdown();
    }

    if (InitFlags & InitFlag_USBDeviceControlInitialized) {
        UdcShutdown();
    }

    if (InitFlags & InitFlag_WslMonitorInitialized) {
        WslMonShutdown();
    }

    if (InitFlags & InitFlag_AppControlInitialized) {
        AcShutdown();
    }

    if (InitFlags & InitFlag_FirmwareIntegrityInitialized) {
        FiShutdown();
    }

    if (InitFlags & InitFlag_ClipboardMonitorInitialized) {
        CbMonShutdown();
    }

    if (InitFlags & InitFlag_HashUtilsInitialized) {
        ShadowStrikeCleanupHashUtils();
    }

    if (InitFlags & InitFlag_ExclusionsInitialized) {
        ShadowStrikeProcessExclusionShutdown();
        ShadowStrikeExclusionShutdown();
    }

    if (InitFlags & InitFlag_ScanCacheInitialized) {
        ShadowStrikeCacheShutdown();
    }

    if (InitFlags & InitFlag_CommPortCreated) {
        ShadowStrikeCloseCommunicationPort();
    }

    if (InitFlags & InitFlag_PwInitialized) {
        ShadowStrikePostWriteShutdown();
    }

    if (InitFlags & InitFlag_PasInitialized) {
        ShadowStrikePreAcquireSectionShutdown();
    }

    if (g_PreSetInfoInitialized) {
        ShadowStrikeCleanupPreSetInfo();
        g_PreSetInfoInitialized = FALSE;
    }

    if (g_PreWriteInitialized) {
        ShadowStrikeCleanupPreWrite();
        g_PreWriteInitialized = FALSE;
    }

    if (g_SubsystemFlags & SubsysFlag_PreCreate) {
        PcShutdown();
        g_SubsystemFlags &= ~SubsysFlag_PreCreate;
    }

    if (InitFlags & InitFlag_PocInitialized) {
        PocShutdown();
    }

    if (InitFlags & InitFlag_FilterRegistered) {
        if (g_DriverData.FilterHandle != NULL) {
            FltUnregisterFilter(g_DriverData.FilterHandle);
            g_DriverData.FilterHandle = NULL;
        }
    }

    if (InitFlags & InitFlag_FscInitialized) {
        ShadowStrikeCleanupFileSystemCallbacks();
    }

    //
    // Cleanup file utilities AFTER FltUnregisterFilter â€”
    // filter callbacks may call FileUtils functions; must drain first
    //
    if (g_FileUtilsInitialized) {
        ShadowStrikeCleanupFileUtils();
        g_FileUtilsInitialized = FALSE;
    }

    //
    // Phase 6A: Shutdown scoring orchestration
    //
    if (g_SubsystemFlags & SubsysFlag_ThreatScoring) {
        TsShutdown(g_ThreatScoring);
        g_ThreatScoring = NULL;
    }

    //
    // Phase 5: Shutdown specialized subsystems (reverse init order)
    //
    if (g_SubsystemFlags & SubsysFlag_ObjectNamespace) {
        ShadowDestroyPrivateNamespace();
    }

    if (g_SubsystemFlags & SubsysFlag_KtmMonitor) {
        ShadowCleanupKtmMonitor();
    }

    if (g_SubsystemFlags & SubsysFlag_AlpcPortMonitor) {
        ShadowAlpcCleanup();
    }

    //
    // Phase 4: Shutdown self-protection (reverse init order)
    // NOTE: CallbackProtection already shut down + flag cleared above (lines 3854-3881).
    //

    if (g_SubsystemFlags & SubsysFlag_IntegrityMonitor) {
        ImShutdown(&g_IntegrityMonitor);
        g_IntegrityMonitor = NULL;
    }

    if (InitFlags & InitFlag_FileProtectionInitialized) {
        FpShutdown(g_FileProtectionEngine);
        g_FileProtectionEngine = NULL;
    }

    if (InitFlags & InitFlag_AntiUnloadInitialized) {
        AuShutdown(g_AntiUnloadProtector);
        g_AntiUnloadProtector = NULL;
    }

    if (InitFlags & InitFlag_AntiDebugInitialized) {
        AdbShutdown(g_AntiDebugProtector);
        g_AntiDebugProtector = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_HandleProtection) {
        HpShutdown(g_HandleProtection);
        g_HandleProtection = NULL;
    }

    //
    // Phase 4A: ELAM shutdown
    //
    if (InitFlags & InitFlag_ElamInitialized) {
        ElamUnregisterCallback();
        ElamDriverShutdown();
    }

    //
    // Phase 3: Shutdown enrichment & communication (reverse init order)
    //
    if (g_SubsystemFlags & SubsysFlag_MessageQueue) {
        MqShutdown();
    }

    if (g_SubsystemFlags & SubsysFlag_ScanBridge) {
        ShadowStrikeScanBridgeShutdown();
    }

    if (g_SubsystemFlags & SubsysFlag_MessageHandler) {
        MhShutdown();
    }

    if (g_SubsystemFlags & SubsysFlag_ProcessAnalyzer) {
        PaShutdown(&g_ProcessAnalyzer);
        g_ProcessAnalyzer = NULL;
    }

    //
    // Phase 2: Shutdown detection subsystems (reverse init order)
    //
    if (g_SubsystemFlags & SubsysFlag_NetworkFilter) {
        NfFilterShutdown();
    }

    if (g_SubsystemFlags & SubsysFlag_SyscallMonitor) {
        ScMonitorShutdown();
    }

    if (g_SubsystemFlags & SubsysFlag_MemoryScanner) {
        MsShutdown(g_MemoryScanner);
        g_MemoryScanner = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_MemoryMonitor) {
        MmMonitorShutdown();
    }

    //
    // Unregister power-to-behavior bridge BEFORE shutting down BehaviorEngine.
    //
    if (g_PowerBehaviorBridgeHandle != NULL) {
        ShadowPowerUnregisterCallback(g_PowerBehaviorBridgeHandle);
        g_PowerBehaviorBridgeHandle = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_BehaviorEngine) {
        BeEngineShutdown();
    }

    //
    // Phase 1D: Shutdown telemetry pipeline (reverse init order)
    //
    if (g_ManifestGenerator != NULL) {
        MgShutdown(g_ManifestGenerator);
        g_ManifestGenerator = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_EventSchema) {
        EsShutdown(&g_EventSchema);
        g_EventSchema = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_TelemetryEvents) {
        TeShutdown();
    }

    if (g_SubsystemFlags & SubsysFlag_TelemetryBuffer) {
        TbStop(g_TelemetryBuffer, TRUE);
        TbShutdown(g_TelemetryBuffer);
        g_TelemetryBuffer = NULL;
    }

    //
    // Shutdown compression engine
    //
    CompShutdown(&g_CompressionManager);

    //
    // Shutdown ETW consumer event pipeline
    //
    if (g_EtwConsumer != NULL) {
        EcShutdown(&g_EtwConsumer);
        g_EtwConsumer = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_ETWProvider) {
        EtwProviderShutdown();
    }

    //
    // Shutdown encryption engine
    //
    EncShutdown(&g_EncryptionManager);

    //
    // Phase 1C: Shutdown power management
    //
    if (g_SubsystemFlags & SubsysFlag_PowerCallback) {
        // Power behavior bridge already unregistered above (before BehaviorEngine shutdown)
        ShadowUnregisterPowerCallbacks();
    }

    //
    // Phase 1B: Shutdown performance infrastructure (reverse init order)
    //
    if (g_SubsystemFlags & SubsysFlag_CacheOptimization) {
        CoShutdown(g_CacheOptimizer);
        g_CacheOptimizer = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_BatchProcessing) {
        BpStop(g_BatchProcessor);
        BpShutdown(g_BatchProcessor);
        g_BatchProcessor = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_ResourceThrottling) {
        RtShutdown(&g_ResourceThrottler);
        g_ResourceThrottler = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_PerformanceMonitor) {
        SsPmShutdown(g_PerformanceMonitor);
        g_PerformanceMonitor = NULL;
    }

    //
    // Shutdown centralized lookaside manager
    //
    if (g_LookasideManager != NULL) {
        LlShutdown(&g_LookasideManager);
        g_LookasideManager = NULL;
    }

    //
    // Phase 1A: Shutdown sync infrastructure (reverse init order)
    //
    if (g_SubsystemFlags & SubsysFlag_DeferredProcedure) {
        DpcShutdown(&g_DpcManager);
        g_DpcManager = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_TimerManager) {
        TmShutdown(g_TimerManager);
        g_TimerManager = NULL;
    }

    // Delete control device created for TimerManager work items
    if (g_TimerControlDevice != NULL) {
        IoDeleteDevice(g_TimerControlDevice);
        g_TimerControlDevice = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_AsyncWorkQueue) {
        AwqShutdown(g_AsyncWorkQueue);
        g_AsyncWorkQueue = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_ThreadPool) {
        TpDestroy(&g_ThreadPool, TRUE);
        g_ThreadPool = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_WorkQueue) {
        ShadowStrikeWorkQueueShutdown(TRUE);
    }

    if (g_SubsystemFlags & SubsysFlag_SpinLockSubsystem) {
        ShadowStrikeLockSubsystemCleanup();
    }

    g_SubsystemFlags = SubsysFlag_None;

    if (InitFlags & InitFlag_LookasideLists) {
        ShadowStrikeCleanupLookasideLists();
        g_DriverData.LookasideInitialized = FALSE;
    }

    ShadowStrikeCleanupProtectedProcessList();

    //
    // Cleanup process utilities (creating context table drain)
    //
    if (g_ProcessUtilsInitialized) {
        ShadowProcessUtilsCleanup();
        g_ProcessUtilsInitialized = FALSE;
    }

    //
    // Cleanup memory utilities (foundational â€” after all module cleanups)
    //
    ShadowStrikeCleanupMemoryUtils();

    //
    // Shutdown WPP tracing last (after all trace-emitting modules)
    //
    if (InitFlags & InitFlag_WppTracing) {
        WppTraceShutdown(g_DriverData.DriverObject);
    }
}

// ============================================================================
// CALLBACK IMPLEMENTATIONS
// ============================================================================

//
// ShadowStrikeThreadNotifyCallback â€” REMOVED.
// Thread notification is now handled by the ThreadNotify module via
// RegisterThreadNotify()/UnregisterThreadNotify() which registers
// TnpThreadNotifyCallback with full injection detection, shellcode
// analysis, cross-process monitoring, and BehaviorEngine integration.
//



/**
 * @brief Object pre-operation callback for handle protection.
 *
 * This is the CORE of our self-protection. Strips dangerous access rights
 * from handles opened to protected processes.
 *
 * NOTE: This callback is registered in SelfProtect.c but declared here
 * for completeness. The actual implementation is in SelfProtect.c.
 */
// ShadowStrikeObjectPreCallback is implemented in SelfProtection/SelfProtect.c
// and is referenced by g_ObjectOperations above.
