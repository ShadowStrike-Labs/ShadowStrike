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
 * ShadowStrike NGAV - DRIVER ENTRY HEADER
 * ============================================================================
 *
 * @file DriverEntry.h
 * @brief Driver entry point and unload function declarations.
 *
 * Contains the main driver lifecycle function prototypes and initialization
 * helper declarations. This is the primary entry point for the enterprise
 * kernel sensor.
 *
 * CRITICAL DESIGN DECISIONS:
 * 1. Uses EX_RUNDOWN_REF for safe callback synchronization during unload
 * 2. All security callbacks are MANDATORY - failure to register is FATAL
 * 3. Memory barriers used for all shared state access
 * 4. IRQL-correct implementations throughout
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_DRIVER_ENTRY_H
#define SHADOWSTRIKE_DRIVER_ENTRY_H

#ifdef __cplusplus
extern "C" {
#endif

#pragma warning(push)
#pragma warning(disable:4324)
#include <fltKernel.h>
#pragma warning(pop)
#include <ntddk.h>
#include <wdm.h>
#include "Globals.h"

// ============================================================================
// VERSION REQUIREMENTS
// ============================================================================

/**
 * @brief Minimum Windows version required.
 * Windows 10 RS1 (1607) = 14393 for PsSetCreateProcessNotifyRoutineEx2
 */
#define SHADOWSTRIKE_MIN_BUILD_NUMBER   14393

/**
 * @brief Windows version for enhanced features.
 * Windows 10 RS3 (1709) = 16299 for additional APIs
 */
#define SHADOWSTRIKE_ENHANCED_BUILD     16299

// ============================================================================
// INITIALIZATION STATE FLAGS
// ============================================================================

/**
 * @brief Bit flags tracking which subsystems were successfully initialized.
 * Used for precise cleanup on failure and for degraded mode detection.
 */
typedef enum _SHADOWSTRIKE_INIT_FLAGS {
    InitFlag_None                   = 0x00000000,
    InitFlag_LookasideLists         = 0x00000001,
    InitFlag_FilterRegistered       = 0x00000002,
    InitFlag_CommPortCreated        = 0x00000004,
    InitFlag_ScanCacheInitialized   = 0x00000008,
    InitFlag_ExclusionsInitialized  = 0x00000010,
    InitFlag_HashUtilsInitialized   = 0x00000020,
    InitFlag_ProcessCallbackReg     = 0x00000040,
    InitFlag_ThreadCallbackReg      = 0x00000080,
    InitFlag_ImageCallbackReg       = 0x00000100,
    InitFlag_RegistryCallbackReg    = 0x00000200,
    InitFlag_ObjectCallbackReg      = 0x00000400,
    InitFlag_FilteringStarted       = 0x00000800,
    InitFlag_RundownInitialized     = 0x00001000,
    InitFlag_SelfProtectInitialized = 0x00002000,
    InitFlag_NamedPipeMonInitialized = 0x00004000,
    InitFlag_AmsiBypassDetInitialized = 0x00008000,
    InitFlag_FileBackupEngineInitialized = 0x00010000,
    InitFlag_USBDeviceControlInitialized = 0x00020000,
    InitFlag_WslMonitorInitialized     = 0x00040000,
    InitFlag_AppControlInitialized     = 0x00080000,
    InitFlag_FirmwareIntegrityInitialized = 0x00100000,
    InitFlag_ClipboardMonitorInitialized  = 0x00200000,
    InitFlag_AntiDebugInitialized         = 0x00400000,
    InitFlag_AntiUnloadInitialized        = 0x00800000,
    InitFlag_FileProtectionInitialized    = 0x01000000,
    InitFlag_WppTracing                   = 0x02000000,
    InitFlag_ElamInitialized              = 0x04000000,
    InitFlag_RegistryMonitorInit          = 0x08000000,
    InitFlag_FscInitialized               = 0x10000000,
    InitFlag_PocInitialized               = 0x20000000,
    InitFlag_PwInitialized                = 0x40000000,
    InitFlag_PasInitialized               = (LONG)0x80000000,

    // Combined flags for critical security components
    InitFlag_AllSecurityCallbacks   = (InitFlag_ProcessCallbackReg |
                                       InitFlag_ObjectCallbackReg),
    InitFlag_AllCritical            = (InitFlag_LookasideLists |
                                       InitFlag_FilterRegistered |
                                       InitFlag_CommPortCreated |
                                       InitFlag_RundownInitialized)
} SHADOWSTRIKE_INIT_FLAGS;

/**
 * @brief Subsystem initialization flags for infrastructure and detection modules.
 *
 * These flags track initialization of subsystem modules that were added
 * during the integration phase. Separate from InitFlags to avoid ULONG overflow.
 * Used by g_SubsystemFlags in DriverEntry.c.
 */
typedef enum _SHADOWSTRIKE_SUBSYSTEM_FLAGS {
    SubsysFlag_None                 = 0x00000000,

    // Phase 1A: Synchronization infrastructure
    SubsysFlag_WorkQueue            = 0x00000001,
    SubsysFlag_ThreadPool           = 0x00000002,
    SubsysFlag_AsyncWorkQueue       = 0x00000004,
    SubsysFlag_TimerManager         = 0x00000008,
    SubsysFlag_DeferredProcedure    = 0x00000010,

    // Phase 1B: Performance infrastructure
    SubsysFlag_PerformanceMonitor   = 0x00000020,
    SubsysFlag_ResourceThrottling   = 0x00000040,
    SubsysFlag_BatchProcessing      = 0x00000080,
    SubsysFlag_CacheOptimization    = 0x00000100,

    // Phase 1C: Power management
    SubsysFlag_PowerCallback        = 0x00000200,

    // Phase 1D: Telemetry pipeline
    SubsysFlag_ETWProvider          = 0x00000400,
    SubsysFlag_TelemetryEvents      = 0x00000800,
    SubsysFlag_TelemetryBuffer      = 0x00001000,

    // Phase 2: Detection subsystems
    SubsysFlag_BehaviorEngine       = 0x00002000,
    SubsysFlag_MemoryMonitor        = 0x00004000,
    SubsysFlag_SyscallMonitor       = 0x00008000,
    SubsysFlag_NetworkFilter        = 0x00010000,

    // Phase 3: Enrichment & communication
    SubsysFlag_ProcessAnalyzer      = 0x00020000,
    SubsysFlag_MessageHandler       = 0x00040000,
    SubsysFlag_ScanBridge           = 0x00080000,

    // Phase 4: Self-protection hardening
    SubsysFlag_CallbackProtection   = 0x00100000,
    SubsysFlag_HandleProtection     = 0x00200000,
    SubsysFlag_IntegrityMonitor     = 0x00400000,

    // Phase 5: Specialized subsystems
    SubsysFlag_AlpcPortMonitor      = 0x00800000,
    SubsysFlag_KtmMonitor           = 0x01000000,
    SubsysFlag_ObjectNamespace      = 0x02000000,

    // Phase 6: Scoring orchestration
    SubsysFlag_ThreatScoring        = 0x04000000,

    // Infrastructure: lock subsystem and message queue
    SubsysFlag_SpinLockSubsystem    = 0x08000000,
    SubsysFlag_MessageQueue         = 0x10000000,

    // Phase 7: Filesystem callback subsystems (InitFlags exhausted)
    SubsysFlag_PreCreate            = 0x20000000,

    // DeviceObject-dependent modules
    SubsysFlag_EventSchema          = 0x40000000,
    SubsysFlag_MemoryScanner        = 0x80000000,
} SHADOWSTRIKE_SUBSYSTEM_FLAGS;

//
// Forward declarations for opaque types exposed by accessor functions
//
typedef struct _BP_PROCESSOR BP_PROCESSOR, *PBP_PROCESSOR;
typedef struct _TM_MANAGER TM_MANAGER, *PTM_MANAGER;
typedef struct _ENC_MANAGER ENC_MANAGER, *PENC_MANAGER;
typedef struct _COMP_MANAGER COMP_MANAGER, *PCOMP_MANAGER;
typedef struct _PA_ANALYZER *PPA_ANALYZER;
typedef struct _TB_MANAGER TB_MANAGER, *PTB_MANAGER;
typedef struct _CO_MANAGER CO_MANAGER, *PCO_MANAGER;
typedef struct _EC_CONSUMER EC_CONSUMER, *PEC_CONSUMER;
typedef struct _ES_SCHEMA ES_SCHEMA, *PES_SCHEMA;
typedef struct _LL_MANAGER LL_MANAGER, *PLL_MANAGER;
typedef struct _SSPM_MONITOR SSPM_MONITOR, *PSSPM_MONITOR;
typedef struct _RT_THROTTLER RT_THROTTLER, *PRT_THROTTLER;

// ============================================================================
// DRIVER LIFECYCLE FUNCTIONS
// ============================================================================

/**
 * @brief Main driver entry point.
 *
 * Called by the system when the driver is loaded. Performs all initialization
 * including filter registration, callback setup, and communication port creation.
 *
 * INITIALIZATION ORDER (critical for correctness):
 * 1. Version check
 * 2. Initialize global state and rundown protection
 * 3. Create lookaside lists
 * 4. Register minifilter
 * 5. Create communication port
 * 6. Initialize scan cache
 * 7. Initialize exclusion manager
 * 8. Initialize hash utilities
 * 9. Register process/thread/image callbacks
 * 10. Register registry callback
 * 11. Register object callbacks (self-protection)
 * 12. Start filtering
 *
 * On any CRITICAL failure, cleanup is performed in reverse order.
 *
 * @param DriverObject  Pointer to the driver object.
 * @param RegistryPath  Path to the driver's registry key.
 * @return STATUS_SUCCESS on success, appropriate error code otherwise.
 */
DRIVER_INITIALIZE DriverEntry;

/**
 * @brief Driver unload callback.
 *
 * Called by the Filter Manager when the driver is being unloaded.
 * Performs cleanup of all resources in reverse order of allocation.
 *
 * CRITICAL: Uses EX_RUNDOWN_REF to wait for all outstanding callbacks
 * to complete before freeing any resources. This prevents BSOD.
 *
 * @param Flags  Flags indicating the reason for unload.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ShadowStrikeUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

// ============================================================================
// INITIALIZATION FUNCTIONS
// ============================================================================

/**
 * @brief Check Windows version compatibility.
 *
 * Verifies the running Windows version meets minimum requirements
 * for all APIs used by this driver.
 *
 * @param OutBuildNumber  Optional pointer to receive actual build number.
 * @return STATUS_SUCCESS if compatible, STATUS_NOT_SUPPORTED otherwise.
 */
NTSTATUS
ShadowStrikeCheckVersionCompatibility(
    _Out_opt_ PULONG OutBuildNumber
    );

/**
 * @brief Load configuration from registry.
 *
 * Reads driver configuration from the registry path provided in DriverEntry.
 * Falls back to defaults if registry values are missing or invalid.
 *
 * @param RegistryPath  Registry path from DriverEntry.
 * @param Config        Configuration structure to populate.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ShadowStrikeLoadConfiguration(
    _In_ PUNICODE_STRING RegistryPath,
    _Out_ PSHADOWSTRIKE_CONFIG Config
    );

/**
 * @brief Initialize all lookaside lists.
 *
 * Creates non-paged lookaside lists for common allocations to prevent
 * pool fragmentation and improve performance.
 *
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ShadowStrikeInitializeLookasideLists(
    VOID
    );

/**
 * @brief Cleanup all lookaside lists.
 */
VOID
ShadowStrikeCleanupLookasideLists(
    VOID
    );

/**
 * @brief Get the global lookaside list manager.
 *
 * Returns NULL if LlInitialize has not been called or failed.
 * Callers should use this to create managed lookaside lists via
 * LlCreateLookaside/LlAllocate/LlFree instead of raw ExInitialize*LookasideList.
 *
 * @return PLL_MANAGER or NULL
 *
 * @irql Any (no lock acquisition, returns a stable pointer)
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PLL_MANAGER
ShadowStrikeGetLookasideManager(
    VOID
    );

/**
 * @brief Register process and thread notification callbacks.
 *
 * Registers:
 * - PsSetCreateProcessNotifyRoutineEx (process creation/termination)
 * - PsSetCreateThreadNotifyRoutine (thread creation/termination)
 * - PsSetLoadImageNotifyRoutine (image/DLL loading)
 *
 * IMPORTANT: Process callback registration is MANDATORY for security.
 * Thread and image callbacks are optional enhancements.
 *
 * @param OutFlags  Receives flags indicating which callbacks registered.
 * @return STATUS_SUCCESS if process callback registered successfully.
 */
NTSTATUS
ShadowStrikeRegisterProcessCallbacks(
    _Out_ PULONG OutFlags
    );

/**
 * @brief Unregister process and thread notification callbacks.
 *
 * @param Flags  Flags from registration indicating which to unregister.
 */
VOID
ShadowStrikeUnregisterProcessCallbacks(
    _In_ ULONG Flags
    );

/**
 * @brief Register registry callback.
 *
 * Uses CmRegisterCallbackEx for registry operation monitoring.
 *
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ShadowStrikeRegisterRegistryCallback(
    _In_ PDRIVER_OBJECT DriverObject
    );

/**
 * @brief Unregister registry callback.
 */
VOID
ShadowStrikeUnregisterRegistryCallback(
    VOID
    );

/**
 * @brief Register object callbacks for self-protection.
 *
 * Uses ObRegisterCallbacks to protect AV processes from termination
 * and handle manipulation. This is CRITICAL for self-protection.
 *
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ShadowStrikeRegisterObjectCallbacks(
    VOID
    );

/**
 * @brief Unregister object callbacks.
 */
VOID
ShadowStrikeUnregisterObjectCallbacks(
    VOID
    );

/**
 * @brief Initialize protected process list.
 */
VOID
ShadowStrikeInitializeProtectedProcessList(
    VOID
    );

/**
 * @brief Cleanup protected process list.
 *
 * Properly frees all entries, dereferencing EPROCESS objects.
 */
VOID
ShadowStrikeCleanupProtectedProcessList(
    VOID
    );

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Wait for rundown protection to drain.
 *
 * Called during unload to ensure no callbacks are in progress
 * before freeing resources. Uses EX_RUNDOWN_REF.
 */
VOID
ShadowStrikeWaitForRundownComplete(
    VOID
    );

/**
 * @brief Log driver initialization status.
 *
 * @param Component  Name of the component being initialized.
 * @param Status     Initialization status.
 */
VOID
ShadowStrikeLogInitStatus(
    _In_ PCSTR Component,
    _In_ NTSTATUS Status
    );

/**
 * @brief Perform cleanup based on initialization flags.
 *
 * @param InitFlags  Flags indicating which components to clean up.
 */
VOID
ShadowStrikeCleanupByFlags(
    _In_ ULONG InitFlags
    );

// ============================================================================
// CALLBACK DECLARATIONS
// ============================================================================

/**
 * @brief Process creation/termination notification callback.
 *
 * Called by the kernel for every process creation and termination.
 * Implements threat detection, logging, and optional blocking.
 */
VOID
ShadowStrikeProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    );

/**
 * @brief Thread creation/termination notification callback.
 *
 * Called by the kernel for every thread creation and termination.
 * Used for detecting suspicious thread injection patterns.
 */
VOID
ShadowStrikeThreadNotifyCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
    );

/**
 * @brief Registry operation callback.
 *
 * Called by the configuration manager for registry operations.
 * Used for detecting registry-based persistence and tampering.
 */
NTSTATUS
ShadowStrikeRegistryCallbackRoutine(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    );

/**
 * @brief Returns the driver-owned ThreatScoring engine instance.
 *
 * @return PTS_SCORING_ENGINE, or NULL if ThreatScoring is not initialized.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
PVOID
ShadowStrikeGetThreatScoringEngine(VOID);

/**
 * @brief Get the batch processing engine for telemetry event aggregation.
 * @return PBP_PROCESSOR or NULL if not initialized.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PBP_PROCESSOR
ShadowStrikeGetBatchProcessor(VOID);

/**
 * @brief Get the global cache optimization manager.
 * @return PCO_MANAGER or NULL if not initialized.
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PCO_MANAGER
ShadowStrikeGetCacheManager(VOID);

/**
 * @brief Send a notification to user-mode via batch processing.
 *
 * Routes through the batch processor (BpQueueEvent) for high-throughput
 * delivery. Falls back to direct ShadowStrikeSendNotification if the
 * batch processor is not available or not running.
 *
 * Callers pass only the payload data (without SHADOWSTRIKE_MESSAGE_HEADER).
 * The batch flush callback builds the header and sends via CommPort.
 *
 * @param[in] MessageType  SHADOWSTRIKE_MESSAGE_TYPE value (e.g. SHADOWSTRIKE_MSG_PROCESS_HANDLE_ALERT)
 * @param[in] Data         Payload data to include after the header
 * @param[in] DataSize     Size in bytes of the payload data (max BP_MAX_EVENT_DATA_SIZE)
 * @return STATUS_SUCCESS, STATUS_INSUFFICIENT_RESOURCES, or STATUS_DELETE_PENDING
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
ShadowStrikeBatchSendNotification(
    _In_ UINT16 MessageType,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ ULONG DataSize
    );

/**
 * @brief Get the global performance monitor for metric recording.
 * @return PSSPM_MONITOR or NULL if not initialized.
 * @note Callers use SsPmRecordSample/SsPmRecordLatency at <= DISPATCH_LEVEL.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PSSPM_MONITOR
ShadowStrikeGetPerformanceMonitor(VOID);

/**
 * @brief Get the global resource throttler for DoS mitigation.
 * @return PRT_THROTTLER or NULL if not initialized.
 * @note Consumers call RtReportUsage/RtShouldProceed at <= DISPATCH_LEVEL.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PRT_THROTTLER
ShadowStrikeGetResourceThrottler(VOID);

/**
 * @brief Get the centralized timer manager for periodic/one-shot timers.
 * @return PTM_MANAGER or NULL if not initialized.
 * @note DeviceObject is set after FltRegisterFilter; TmFlag_WorkItemCallback
 *       requires DeviceObject, so only use after Phase 2 completes.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PTM_MANAGER
ShadowStrikeGetTimerManager(VOID);

/**
 * @brief Returns the global encryption manager for fast-path crypto operations.
 * @return PENC_MANAGER or NULL if not initialized.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PENC_MANAGER
ShadowStrikeGetEncryptionManager(VOID);

/**
 * @brief Returns the global CompressionManager for transport stats/verification.
 * @return PCOMP_MANAGER or NULL if not initialized.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PCOMP_MANAGER
ShadowStrikeGetCompressionManager(VOID);

/**
 * @brief Returns the global ProcessAnalyzer instance for deep process analysis.
 * @return PPA_ANALYZER or NULL if not initialized.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PPA_ANALYZER
ShadowStrikeGetProcessAnalyzer(VOID);

/**
 * @brief Get the global telemetry buffer manager.
 * @return PTB_MANAGER or NULL if not initialized/started.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PTB_MANAGER
ShadowStrikeGetTelemetryBuffer(VOID);

/**
 * @brief Get the global ETW consumer event pipeline.
 * @return PEC_CONSUMER or NULL if not initialized.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PEC_CONSUMER
ShadowStrikeGetETWConsumer(VOID);

/**
 * @brief Get the global event schema instance.
 * @return PES_SCHEMA or NULL if not initialized.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PES_SCHEMA
ShadowStrikeGetEventSchema(VOID);

typedef struct _MG_GENERATOR MG_GENERATOR, *PMG_GENERATOR;

/**
 * @brief Get the global manifest generator instance.
 * @return PMG_GENERATOR or NULL if not initialized.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PMG_GENERATOR
ShadowStrikeGetManifestGenerator(VOID);

typedef struct _MS_SCANNER MS_SCANNER, *PMS_SCANNER;

/**
 * @brief Get the global memory scanner instance for pattern-based memory scanning.
 * @return PMS_SCANNER or NULL if not initialized.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
PMS_SCANNER
ShadowStrikeGetMemoryScanner(VOID);

typedef struct _ADB_PROTECTOR ADB_PROTECTOR, *PADB_PROTECTOR;

/**
 * @brief Get the global anti-debug protector instance.
 * @return PADB_PROTECTOR or NULL if not initialized.
 * @note Callers use AdbCheckForDebugger/AdbCheckForHypervisor/AdbGetStatistics.
 */
_IRQL_requires_max_(APC_LEVEL)
PADB_PROTECTOR
ShadowStrikeGetAntiDebugProtector(VOID);

/**
 * @brief Get the global anti-unload protector instance.
 * @return PAU_PROTECTOR or NULL if not initialized.
 * @note Used by ProcessNotify for cleanup on process termination.
 */
typedef struct _AU_PROTECTOR AU_PROTECTOR, *PAU_PROTECTOR;

_IRQL_requires_max_(DISPATCH_LEVEL)
PAU_PROTECTOR
ShadowStrikeGetAntiUnloadProtector(VOID);

/**
 * @brief Get the global callback protection instance.
 * @return PCP_PROTECTOR or NULL if not initialized.
 * @note Used by PerformanceMonitor for stats collection.
 *       All CP public APIs require PASSIVE_LEVEL.
 */
typedef struct _CP_PROTECTOR CP_PROTECTOR, *PCP_PROTECTOR;

_IRQL_requires_max_(PASSIVE_LEVEL)
PCP_PROTECTOR
ShadowStrikeGetCallbackProtector(VOID);

/**
 * @brief Get the global file protection engine instance.
 * @return PFP_ENGINE or NULL if not initialized.
 * @note All Fp* public APIs require <= APC_LEVEL.
 *       Used by minifilter callbacks (PreCreate) for file access control.
 */
typedef struct _FP_ENGINE FP_ENGINE, *PFP_ENGINE;

_IRQL_requires_max_(APC_LEVEL)
PFP_ENGINE
ShadowStrikeGetFileProtectionEngine(VOID);

/**
 * @brief Get handle protection engine instance.
 *        Used by ObjectCallback for deep handle abuse analysis,
 *        and ProcessNotify for per-process context cleanup.
 */
typedef struct _HP_PROTECTION_ENGINE HP_PROTECTION_ENGINE, *PHP_PROTECTION_ENGINE;

_IRQL_requires_max_(APC_LEVEL)
PHP_PROTECTION_ENGINE
ShadowStrikeGetHandleProtection(VOID);

/**
 * @brief Get integrity monitor instance.
 *        Used by other modules to register tamper callbacks
 *        or trigger on-demand integrity checks.
 */
typedef struct _IM_MONITOR IM_MONITOR, *PIM_MONITOR;

_IRQL_requires_max_(APC_LEVEL)
PIM_MONITOR
ShadowStrikeGetIntegrityMonitor(VOID);

/**
 * @brief Get async work queue handle for deferred task submission.
 *        Modules that need non-blocking work dispatch (deferred scans,
 *        async telemetry, background analysis) submit via this handle.
 * @return HAWQ_MANAGER or NULL if not initialized.
 */
struct HAWQ_MANAGER__;
typedef struct HAWQ_MANAGER__ *HAWQ_MANAGER;

_IRQL_requires_max_(APC_LEVEL)
HAWQ_MANAGER
ShadowStrikeGetAsyncWorkQueue(VOID);

/**
 * @brief Get DPC manager for deferred procedure call dispatch.
 *        Modules needing fire-and-forget DPC work at <= DISPATCH_LEVEL
 *        use this pooled DPC infrastructure instead of raw KeInitializeDpc.
 * @return PDPC_MANAGER or NULL if not initialized.
 */
struct _DPC_MANAGER;

_IRQL_requires_max_(DISPATCH_LEVEL)
struct _DPC_MANAGER*
ShadowStrikeGetDpcManager(VOID);

/**
 * @brief Get the global thread pool handle.
 *
 * @details
 *        Returns the driver-wide managed thread pool for background work.
 *        Modules needing dedicated worker threads with scaling, priority,
 *        and affinity control use this pool instead of raw PsCreateSystemThread.
 * @return PTP_THREAD_POOL or NULL if not initialized.
 */
struct _TP_THREAD_POOL;

_IRQL_requires_max_(DISPATCH_LEVEL)
struct _TP_THREAD_POOL*
ShadowStrikeGetThreadPool(VOID);

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_DRIVER_ENTRY_H
