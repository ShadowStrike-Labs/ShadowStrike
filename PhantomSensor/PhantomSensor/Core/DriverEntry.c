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

#include "DriverEntry.h"
#include "FilterRegistration.h"
#include "../Communication/CommPort.h"
#include "../Cache/ScanCache.h"
#include "../Exclusions/ExclusionManager.h"
#include "../SelfProtection/SelfProtect.h"
#include "../Callbacks/Registry/RegistryCallback.h"
#include "../Utilities/HashUtils.h"
#include "../Shared/SharedDefs.h"
#include "../Shared/PortName.h"
#include "../Callbacks/FileSystem/NamedPipeMonitor.h"
#include "../Callbacks/Process/AmsiBypassDetector.h"
#include "../Callbacks/FileSystem/FileBackupEngine.h"
#include "../Callbacks/FileSystem/USBDeviceControl.h"
#include "../Callbacks/FileSystem/FileSystemCallbacks.h"

//
// Forward declarations for PostCreate subsystem (PostCreate.h redefines
// SHADOWSTRIKE_STREAM_CONTEXT — cannot include alongside SharedDefs.h)
//
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS PocInitialize(VOID);

_IRQL_requires_(PASSIVE_LEVEL)
VOID PocShutdown(VOID);

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

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(INIT, ShadowStrikeCheckVersionCompatibility)
#pragma alloc_text(INIT, ShadowStrikeLoadConfiguration)
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
 * @brief Power callback bridge — forwards sleep/resume events to BehaviorEngine.
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
        threatScore = 5;  // Mild baseline — chain tracker evaluates context
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
        ULONG totalSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + (ULONG)evt->DataSize;

        if (totalSize < sizeof(SHADOWSTRIKE_MESSAGE_HEADER) || evt->DataSize > 65536) {
            continue;
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

    // =========================================================================
    // PHASE 1A: Synchronization Infrastructure
    // =========================================================================

    //
    // Step 5.1: Initialize work queue (singleton — provides work item dispatch)
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
        ShadowStrikeLogInitStatus("Resource Throttling", STATUS_SUCCESS);
    }

    //
    // Step 5.8: Batch processing — telemetry event aggregator
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
    // Step 5.9: Cache optimization — DEFERRED
    // CoInitialize reserves 64MB. ScanCache already handles verdict caching
    // independently. Enable when additional cache types are integrated.
    //

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

    // Step 6.1: DeviceObject for TimerManager is provided via g_TimerControlDevice
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
                       "[ShadowStrike] WARNING: No DeviceObject available — telemetry events skipped\n");
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

    // =========================================================================
    // PHASE 2: Detection Subsystems
    // =========================================================================

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
                       "[ShadowStrike] WARNING: No DeviceObject — memory scanner skipped\n");
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
    // Step 14.19: Initialize callback protection (LAST protection init — protects all registered callbacks)
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
        // Enable periodic integrity verification (every 5 seconds)
        // This detects callback code patching by rootkits
        //
        (VOID)CpEnablePeriodicVerify(g_CallbackProtector, 5000);

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
    // Step 14.23: Enable performance monitoring collection
    //
    if (g_SubsystemFlags & SubsysFlag_PerformanceMonitor) {
        status = SsPmEnableCollection(g_PerformanceMonitor, 5000);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] WARNING: Failed to enable performance collection: 0x%08X (continuing)\n",
                       status);
        } else {
            ShadowStrikeLogInitStatus("Performance Collection", STATUS_SUCCESS);
        }
        status = STATUS_SUCCESS;
    }

    //
    // Step 14.24: Start resource throttling monitoring
    //
    if (g_SubsystemFlags & SubsysFlag_ResourceThrottling) {
        status = RtStartMonitoring(g_ResourceThrottler, 10000);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] WARNING: Failed to start resource throttling: 0x%08X (continuing)\n",
                       status);
        } else {
            ShadowStrikeLogInitStatus("Resource Throttling Monitor", STATUS_SUCCESS);
        }
        status = STATUS_SUCCESS;
    }

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
    status = ShadowStrikeInitializeFileSystemCallbacks();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Failed to initialize filesystem callbacks: 0x%08X\n",
                   status);
        status = STATUS_SUCCESS;
    } else {
        g_InitFlags |= InitFlag_FscInitialized;
        ShadowStrikeLogInitStatus("Filesystem Callbacks", STATUS_SUCCESS);
    }

    //
    // Step 14.27: Initialize PostCreate subsystem (stream context management,
    // file classification, ransomware monitoring baselines, handle contexts)
    // MUST be before FltStartFiltering — PostCreate callback needs lookaside lists
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
    // MUST be before FltStartFiltering — PostWrite callback needs process tracking
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

    //
    // Mark driver as initialized with proper memory barrier
    //
    MemoryBarrier();
    WriteBooleanRelease(&g_DriverData.Initialized, TRUE);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Driver initialized successfully (InitFlags=0x%08X)\n",
               g_InitFlags);

    //
    // Log security status
    //
    if ((g_InitFlags & InitFlag_ObjectCallbackReg) == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: Running in DEGRADED MODE - self-protection disabled\n");
    }

    return STATUS_SUCCESS;

Cleanup:
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
    PAGED_CODE();

    UNREFERENCED_PARAMETER(Flags);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Unload: Starting driver unload (InitFlags=0x%08X)\n",
               g_InitFlags);

    //
    // Step 1: Signal shutdown - stop accepting new work
    // Use memory barrier to ensure visibility
    //
    WriteBooleanRelease(&g_DriverData.ShuttingDown, TRUE);
    MemoryBarrier();

    //
    // Step 2: Wait for rundown protection to drain
    // This ensures ALL callbacks complete before we free anything
    //
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Waiting for rundown protection to drain...\n");

    ShadowStrikeWaitForRundownComplete();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Rundown complete, proceeding with cleanup.\n");

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
    // Step 5: Shutdown exclusion manager
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
    // Step 8.4: Shutdown PostWrite subsystem (BEFORE PostCreate —
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
    // Step 8.5: Shutdown PostCreate subsystem (BEFORE FltUnregisterFilter —
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
    // Step 9.5: Cleanup filesystem callbacks (AFTER FltUnregisterFilter — 
    // InstanceTeardownComplete accesses FSC state during filter teardown)
    //
    if (g_InitFlags & InitFlag_FscInitialized) {
        ShadowStrikeCleanupFileSystemCallbacks();
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

    if (g_SubsystemFlags & SubsysFlag_CallbackProtection) {
        CpShutdown(g_CallbackProtector);
        g_CallbackProtector = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_IntegrityMonitor) {
        ImShutdown(&g_IntegrityMonitor);
        g_IntegrityMonitor = NULL;
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
        if (g_PowerBehaviorBridgeHandle != NULL) {
            ShadowPowerUnregisterCallback(g_PowerBehaviorBridgeHandle);
            g_PowerBehaviorBridgeHandle = NULL;
        }
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

    WriteBooleanRelease(&g_DriverData.Initialized, FALSE);
    g_InitFlags = InitFlag_None;

    //
    // FINAL: Shutdown WPP tracing (must be last — after all trace-emitting code)
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

PBP_PROCESSOR
ShadowStrikeGetBatchProcessor(VOID)
{
    return g_BatchProcessor;
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
        sizeof(SHADOW_STREAM_CONTEXT),
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
        status = RegisterImageNotify();
    }
    if (NT_SUCCESS(status)) {
        g_DriverData.ImageNotifyRegistered = TRUE;
        *OutFlags |= InitFlag_ImageCallbackReg;
        g_InitFlags |= InitFlag_ImageCallbackReg;
        ShadowStrikeLogInitStatus("Image Notify", status);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] WARNING: ImageNotify initialization failed: 0x%08X\n",
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
    //
    if (g_SubsystemFlags & SubsysFlag_CallbackProtection) {
        CpShutdown(g_CallbackProtector);
        g_CallbackProtector = NULL;
    }

    if (g_SubsystemFlags & SubsysFlag_IntegrityMonitor) {
        ImShutdown(&g_IntegrityMonitor);
        g_IntegrityMonitor = NULL;
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
    // Phase 4A: ELAM shutdown
    //
    if (g_InitFlags & InitFlag_ElamInitialized) {
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
        if (g_PowerBehaviorBridgeHandle != NULL) {
            ShadowPowerUnregisterCallback(g_PowerBehaviorBridgeHandle);
            g_PowerBehaviorBridgeHandle = NULL;
        }
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
// ShadowStrikeThreadNotifyCallback — REMOVED.
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
