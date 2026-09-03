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
 * ShadowStrike NGAV - SHARED DEFINITIONS
 * ============================================================================
 *
 * @file SharedDefs.h
 * @brief Shared definitions between kernel driver and user-mode service.
 *
 * This file contains constants, limits, and macros used by both
 * the ShadowStrikeFlt minifilter driver and the user-mode service.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_SHARED_DEFS_H
#define SHADOWSTRIKE_SHARED_DEFS_H

#ifdef _KERNEL_MODE
    #include <fltKernel.h>
#else
    #include <windows.h>
#endif

// ============================================================================
// VERSION INFORMATION
// ============================================================================

#define SHADOWSTRIKE_VERSION_MAJOR      3
#define SHADOWSTRIKE_VERSION_MINOR      0
#define SHADOWSTRIKE_VERSION_BUILD      0

#define SHADOWSTRIKE_DRIVER_NAME        L"ShadowStrikeFlt"
#define SHADOWSTRIKE_DRIVER_VERSION     L"3.0.0"
#define SHADOWSTRIKE_SERVICE_NAME       L"ShadowStrikeService"

/**
 * @brief Expected service executable filename for client verification.
 *
 * The kernel driver verifies connecting user-mode processes against this
 * expected filename. Full-path matching is used when the install path
 * is known from registry; otherwise filename-only matching is used
 * with additional code-signing checks.
 */
#define SHADOWSTRIKE_SERVICE_EXECUTABLE L"ShadowStrikePhantomService.exe"

// ============================================================================
// FILTER ALTITUDE
// ============================================================================

/**
 * @brief Minifilter altitude.
 *
 * Altitude 385210 is in the "Anti-Virus" range (320000-389999).
 * This must be registered with Microsoft for production use.
 */
#define SHADOWSTRIKE_ALTITUDE           "385210"
#define SHADOWSTRIKE_ALTITUDE_W         L"385210"

// ============================================================================
// COMMUNICATION PORT
// ============================================================================

/**
 * @brief Communication port name.
 *
 * User-mode connects to this port for communication with the driver.
 */
#define SHADOWSTRIKE_PORT_NAME          L"\\ShadowStrikePort"
#define SHADOWSTRIKE_PORT_NAME_A        "\\ShadowStrikePort"

/**
 * @brief Maximum simultaneous client connections.
 */
//
// Maximum simultaneous user-mode clients on the communication port.
//
// The service opens more channels than the original limit of 4 allowed:
// IPCManager, the primary scanner connection, the push connection, the
// file-system filter, the network traffic filter, and a one-shot availability
// probe from the file lock manager. With a limit of 4 the later arrivals were
// simply refused with ERROR_CONNECTION_COUNT_LIMIT (0x800704D6) - and because
// nothing retried, NetworkTrafficFilter ran permanently with NO kernel channel,
// silently losing its share of detection while appearing to start normally.
//
// 8 covers the six real channels with headroom for a reconnect overlapping a
// connection that has not been reaped yet. It is deliberately not larger: every
// slot costs non-paged pool for its reference and session key, and the port is
// reachable only by SYSTEM/administrators, so a small bounded table also limits
// what a compromised privileged process could occupy.
//
// Sharing one channel across subsystems would be better still and remains the
// preferred architecture, but that is a wider refactor than this limit fix.
//
#define SHADOWSTRIKE_MAX_CONNECTIONS    8
#define SHADOWSTRIKE_PORT_MAX_CONNECTIONS SHADOWSTRIKE_MAX_CONNECTIONS

// ============================================================================
// MEMORY AND BUFFER LIMITS
// ============================================================================

/**
 * @brief Pool tag for driver allocations: 'SsFt' = ShadowStrike Filter
 */
#define SHADOWSTRIKE_POOL_TAG           'tFsS'

/**
 * @brief Pool tag for context allocations
 */
#define SHADOWSTRIKE_CONTEXT_POOL_TAG   'xCsS'

/**
 * @brief Maximum message size for kernel<->user communication.
 */
#define SHADOWSTRIKE_MAX_MESSAGE_SIZE   (64 * 1024)  // 64 KB

/**
 * @brief Maximum file path length in characters.
 */
#define MAX_FILE_PATH_LENGTH            1024

/**
 * @brief Maximum process name length in characters.
 */
#define MAX_PROCESS_NAME_LENGTH         260

/**
 * @brief Maximum command line length in characters.
 */
#define MAX_COMMAND_LINE_LENGTH         8192

/**
 * @brief Maximum threat name length in characters.
 */
#define MAX_THREAT_NAME_LENGTH          256

/**
 * @brief Maximum registry key path length.
 */
#define MAX_REGISTRY_KEY_LENGTH         512

/**
 * @brief Maximum registry value name length.
 */
#define MAX_REGISTRY_VALUE_LENGTH       256

/**
 * @brief Maximum registry data to capture.
 */
#define MAX_REGISTRY_DATA_SIZE          1024

// ============================================================================
// STREAM CONTEXT
// ============================================================================

//
// Guard against redefinition.
// PostCreate.h defines a full-featured version of this struct.
// When both headers are included, the first definition wins.
//
#ifndef _SHADOWSTRIKE_STREAM_CONTEXT_DEFINED_
#define _SHADOWSTRIKE_STREAM_CONTEXT_DEFINED_

/**
 * @brief Stream context structure for per-file tracking.
 */
typedef struct _SHADOWSTRIKE_STREAM_CONTEXT {
    /// @brief File has been scanned
    BOOLEAN Scanned;

    /// @brief Last scan verdict
    UINT8 LastVerdict;

    /// @brief File is being written to (dirty)
    BOOLEAN Dirty;

    /// @brief Reserved for alignment
    UINT8 Reserved;

    /// @brief Last write time when scanned
    LARGE_INTEGER ScanTime;

    /// @brief File size when scanned
    UINT64 ScanFileSize;

    /// @brief File ID for cache correlation
    UINT64 FileId;

    /// @brief Volume serial for cache correlation
    ULONG VolumeSerial;

    /// @brief Reserved
    ULONG Reserved2;

} SHADOWSTRIKE_STREAM_CONTEXT, *PSHADOWSTRIKE_STREAM_CONTEXT;

#endif // _SHADOWSTRIKE_STREAM_CONTEXT_DEFINED_

// ============================================================================
// TIMEOUTS AND LIMITS
// ============================================================================

/**
 * @brief Default scan timeout in milliseconds.
 */
#define SHADOWSTRIKE_DEFAULT_SCAN_TIMEOUT_MS    30000

/**
 * @brief Minimum scan timeout in milliseconds.
 */
#define SHADOWSTRIKE_MIN_SCAN_TIMEOUT_MS        1000

/**
 * @brief Maximum scan timeout in milliseconds.
 */
#define SHADOWSTRIKE_MAX_SCAN_TIMEOUT_MS        300000

/**
 * @brief Default cache TTL in seconds.
 */
#define SHADOWSTRIKE_DEFAULT_CACHE_TTL_SEC      300

/**
 * @brief Default maximum pending requests.
 */
#define SHADOWSTRIKE_DEFAULT_MAX_PENDING        10000

/**
 * @brief Maximum file size to scan (0 = unlimited).
 */
#define SHADOWSTRIKE_DEFAULT_MAX_FILE_SIZE      0

// ============================================================================
// MESSAGE PROTOCOL CONSTANTS
// ============================================================================

/**
 * @brief Message magic number: "SSFS" (ShadowStrike Filter Service)
 */
#define SHADOWSTRIKE_MESSAGE_MAGIC      0x53534653

/**
 * @brief Current protocol version.
 */
#define SHADOWSTRIKE_PROTOCOL_VERSION   2

// ============================================================================
// FILE ACCESS TYPES (for scan requests)
// ============================================================================

typedef enum _SHADOWSTRIKE_FILE_ACCESS_TYPE {
    ShadowStrikeAccessNone = 0,
    ShadowStrikeAccessRead,
    ShadowStrikeAccessWrite,
    ShadowStrikeAccessExecute,
    ShadowStrikeAccessCreate,
    ShadowStrikeAccessRename,
    ShadowStrikeAccessDelete,
    ShadowStrikeAccessSetInfo,
    ShadowStrikeAccessMax
} SHADOWSTRIKE_FILE_ACCESS_TYPE;

typedef SHADOWSTRIKE_FILE_ACCESS_TYPE SHADOWSTRIKE_ACCESS_TYPE;

// ============================================================================
// PRIORITY LEVELS
// ============================================================================

typedef enum _SHADOWSTRIKE_PRIORITY {
    ShadowStrikePriorityLow = 0,
    ShadowStrikePriorityNormal,
    ShadowStrikePriorityHigh,
    ShadowStrikePriorityCritical
} SHADOWSTRIKE_PRIORITY;

// ============================================================================
// DRIVER STATUS STRUCTURE
// ============================================================================

#pragma pack(push, 1)

typedef struct _SHADOWSTRIKE_DRIVER_STATUS {
    UINT16 VersionMajor;
    UINT16 VersionMinor;
    UINT16 VersionBuild;
    UINT16 Reserved1;

    BOOLEAN FilteringActive;
    BOOLEAN ScanOnOpenEnabled;
    BOOLEAN ScanOnExecuteEnabled;
    BOOLEAN ScanOnWriteEnabled;
    BOOLEAN NotificationsEnabled;
    UINT8 Reserved2[3];

    UINT64 TotalFilesScanned;
    UINT64 FilesBlocked;
    UINT64 CacheHits;
    UINT64 CacheMisses;

    LONG PendingRequests;
    LONG PeakPendingRequests;
    LONG ConnectedClients;
    LONG Reserved3;

    //
    // Compression transport statistics (v2 extension)
    //
    UINT64 CompressedMessages;
    UINT64 CompressionBytesSaved;
    ULONG  CompressionAvgRatio;          // 0-100 percentage (35 = compressed to 35% of original)
    ULONG  CompressionErrors;

    //
    // Message queue health statistics (v3 extension)
    //
    UINT64 MqTotalEnqueued;
    UINT64 MqTotalDequeued;
    UINT64 MqTotalDropped;
    ULONG  MqCurrentDepth;
    ULONG  MqPeakDepth;
    BOOLEAN MqFlowControlActive;
    UINT8  MqReserved[3];

    // ScanBridge health
    LONG64 SbTotalScans;
    LONG64 SbSuccessfulScans;
    LONG64 SbFailedScans;
    LONG64 SbTimeoutScans;
    LONG64 SbCircuitBreakerTrips;
    ULONG  SbAvgLatencyMs;
    ULONG  SbCircuitState;      // 0=Closed, 1=Open, 2=HalfOpen

    //
    // TelemetryBuffer health
    //
    LONG64 TbTotalEnqueued;
    LONG64 TbTotalDequeued;
    LONG64 TbTotalDropped;
    LONG64 TbTotalBytes;
    LONG64 TbBatchesSent;
    ULONG  TbUtilizationPercent;
    ULONG  TbActiveCpuCount;
    ULONG  TbBufferState;       // TB_BUFFER_STATE enum

    //
    // Per-instance aggregate stats (summed across all volumes)
    //
    LONG64 IcTotalCreateOps;
    LONG64 IcTotalScans;
    LONG64 IcTotalBlocks;
    LONG64 IcTotalWrites;
    LONG64 IcCleanVerdicts;
    LONG64 IcMalwareVerdicts;
    LONG64 IcScanErrors;
    LONG64 IcCacheHits;
    ULONG  IcActiveInstances;
    ULONG  IcReserved;

    //
    // ETW Provider statistics
    //
    UINT64 EtwEventsWritten;
    UINT64 EtwEventsDropped;
    UINT64 EtwBytesWritten;

    // Event schema registered event count
    UINT32 EventSchemaEventCount;

    // ManifestGenerator channel/keyword/task counts
    UINT32 ManifestChannelCount;
    UINT32 ManifestKeywordCount;
    UINT32 ManifestTaskCount;
    UINT32 ManifestValidationErrors;

    //
    // TelemetryEvents engine statistics
    //
    LONG64 TeEventsGenerated;
    LONG64 TeEventsThrottled;
    LONG64 TeAllocationFailures;
    LONG  TePeakEventsPerSecond;
    LONG  TeThrottleAction;         // Current throttle level (TeThrottle_*)
    LONG64 TeThrottleActivations;

    //
    // ExclusionManager statistics
    //
    LONG64 ExclTotalChecks;
    LONG64 ExclPathMatches;
    LONG64 ExclExtensionMatches;
    LONG64 ExclProcessMatches;
    LONG64 ExclPidMatches;
    LONG64 ExclTotalBypassed;
    LONG  ExclPathCount;
    LONG  ExclExtensionCount;
    LONG  ExclProcessCount;
    LONG  ExclPidCount;

    //
    // Process Exclusion Engine stats (ProcessExclusion.c)
    //
    LONG64 ProcExclTotalLookups;
    LONG64 ProcExclBitmapHits;
    LONG64 ProcExclHashHits;
    LONG64 ProcExclMisses;
    LONG64 ProcExclProcessesExcluded;
    LONG64 ProcExclInheritedExclusions;
    LONG   ProcExclCurrentBitmapCount;
    LONG   ProcExclCurrentHashCount;

    //
    // Hollowing Detector stats (HollowingDetector.c)
    //
    LONG64 HollowProcessesAnalyzed;
    LONG64 HollowDetections;
    LONG64 HollowDoppelgangingDetected;
    LONG64 HollowGhostingDetected;

    //
    // Injection Detector stats (InjectionDetector.c)
    //
    LONG64 InjTotalOperations;
    LONG64 InjDetectedInjections;
    LONG64 InjBlockedInjections;
    LONG64 InjActiveChains;

    //
    // Memory Monitor aggregate stats (MemoryMonitor.c)
    //
    LONG64 MemMonEventsProcessed;
    LONG64 MemMonShellcodeDetections;
    LONG64 MemMonHeapSprayDetections;
    LONG64 MemMonROPDetections;
    LONG64 MemMonSectionAnomalies;
    LONG64 MemMonEventsDropped;
    LONG   MemMonProcessContexts;
    BOOLEAN MemMonEnabled;
    UCHAR  MemMonReserved[3];

    //
    // Memory Scanner stats (MemoryScanner.c)
    //
    LONG64 MsScannerTotalScans;
    LONG64 MsScannerTotalMatches;
    LONG64 MsScannerBytesScanned;
    LONG64 MsScannerTimeouts;
    ULONG  MsScannerPatternCount;
    ULONG  MsScannerActiveScans;
    ULONG  MsScannerAvgScanTimeMs;
    ULONG  MsScannerReserved;

    //
    // PreCreate callback statistics (v4 extension)
    //
    // IRP_MJ_CREATE is the highest-volume callback this driver owns and it was
    // the ONLY subsystem with no block here, so its counters could be read only
    // with a kernel debugger. Every field below already exists in PC_STATISTICS
    // (PreCreate.h) and is maintained by the callback; this block is a
    // projection, not a second set of counters, so the two cannot disagree
    // about a number.
    //
    // The Pc prefix matches the Ic/Excl/Sb/Tb/Mq/Te convention already used
    // above: one prefix per owning module, so a reader can attribute any field
    // to the code that maintains it without consulting a map.
    //
    LONG64 PcTotalOperations;           // Total PreCreate invocations
    LONG64 PcOperationsScanned;         // Routed to the user-mode scanner
    LONG64 PcOperationsBlocked;         // Completed with STATUS_ACCESS_DENIED
    LONG64 PcOperationsExcluded;        // Matched a configured exclusion
    LONG64 PcOperationsCached;          // Answered from the kernel scan cache
    LONG64 PcScanTimeouts;              // Scanner did not answer in time
    LONG64 PcScanErrors;                // Scan request failed outright
    LONG64 PcSelfProtectBlocks;         // Denied to protect our own files
    LONG64 PcCatalogStoreExemptions;    // Catalog-store creates not routed
    LONG64 PcAdsDetections;             // Alternate data stream abuse
    LONG64 PcDoubleExtDetections;       // Double/hidden extension
    LONG64 PcHoneypotDetections;        // Decoy file touched
    LONG64 PcSuspiciousPathDetections;  // Temp/recycle/public path
    LONG64 PcRansomwareCorrelations;    // Correlated with ransomware activity
    LONG64 PcExecutablesScanned;        // By file class
    LONG64 PcScriptsScanned;
    LONG64 PcDocumentsScanned;
    LONG64 PcArchivesScanned;
    LONG64 PcTotalScanTimeMs;           // Sum, for deriving an average
    LONG64 PcMaxScanTimeMs;             // Worst single scan observed

    //
    // In-callback cost of ShadowStrikePreCreate itself, in MICROSECONDS.
    //
    // Distinct from PcTotalScanTimeMs/PcMaxScanTimeMs above, which time the
    // user-mode scan round trip only. The field run measured that round trip
    // fast and idle while the machine still stalled, so what was missing is the
    // in-kernel work performed on every create before a scan is considered.
    //
    // Microseconds because a create is expected to cost microseconds; a
    // millisecond field would round nearly every sample to zero and report the
    // callback as free.
    //
    LONG64 PcCallbackSamples;
    LONG64 PcTotalCallbackTimeUs;
    LONG64 PcMaxCallbackTimeUs;

    //
    // Creates the scanner was never asked about, because its circuit breaker
    // was open. NOT a scan error, which is what these used to be counted as:
    // an error means a scan was attempted and failed, while this means the
    // attempt was deliberately skipped and the file was allowed unscanned.
    // Field run 1.0.107 reported errors=27961 against scanned=40392, and the
    // overwhelming majority of that 69 percent was this, mislabelled.
    //
    LONG64 PcScanCircuitOpen;

    //
    // SCAN-PATH TRANSPORT LATENCY, measured around the raw FltSendMessage wait
    // and nothing else. See the block on SHADOWSTRIKE_STATISTICS in Globals.h
    // for why the create-path counters cannot answer this on their own.
    //
    LONG64 TxScanSendSamples;
    LONG64 TxScanSendTotalUs;
    LONG64 TxScanSendMaxUs;
    LONG64 TxScanSendDeadlineOverruns;

} SHADOWSTRIKE_DRIVER_STATUS, *PSHADOWSTRIKE_DRIVER_STATUS;

//
// Layout assertions for the PreCreate block.
//
// This structure crosses the kernel/user boundary and carried NO size or
// offset assertion of any kind before this block was added. That is exactly how
// ProcessNotificationData, RegistryNotificationData and DriverStatisticsData
// drifted away from the layouts the driver actually emits, so the block is
// pinned on arrival rather than after the first misparse.
//
// The BASE offset of the block is deliberately NOT asserted as an absolute: it
// moves whenever an earlier extension block is added, and pinning it would turn
// every future extension into a false failure. What is pinned is that the block
// is APPENDED with no padding, that its internal layout is contiguous, and that
// nothing follows it - which is what a reader of these fields depends on.
//
// Note this structure is under #pragma pack(push, 1) (see the top of this
// region), so the LONG64 fields are byte-packed and are NOT 8-byte aligned.
// That is deliberate and correct for a wire structure - the layout must not
// depend on a compiler's alignment choices - and it is why the assertion below
// is about packing rather than alignment. An earlier version of this block
// asserted 8-byte alignment and was simply wrong about its own format.
//
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcTotalOperations) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, MsScannerReserved) + sizeof(ULONG));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcOperationsScanned) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcTotalOperations) + sizeof(LONG64));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcOperationsBlocked) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcOperationsScanned) + sizeof(LONG64));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcOperationsExcluded) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcOperationsBlocked) + sizeof(LONG64));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcOperationsCached) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcOperationsExcluded) + sizeof(LONG64));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcScanTimeouts) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcOperationsCached) + sizeof(LONG64));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcScanErrors) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcScanTimeouts) + sizeof(LONG64));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcSelfProtectBlocks) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcScanErrors) + sizeof(LONG64));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcCatalogStoreExemptions) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcSelfProtectBlocks) + sizeof(LONG64));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcAdsDetections) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcCatalogStoreExemptions) + sizeof(LONG64));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcDoubleExtDetections) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcAdsDetections) + sizeof(LONG64));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcHoneypotDetections) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcDoubleExtDetections) + sizeof(LONG64));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcSuspiciousPathDetections) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcHoneypotDetections) + sizeof(LONG64));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcRansomwareCorrelations) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcSuspiciousPathDetections) + sizeof(LONG64));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcExecutablesScanned) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcRansomwareCorrelations) + sizeof(LONG64));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcScriptsScanned) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcExecutablesScanned) + sizeof(LONG64));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcDocumentsScanned) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcScriptsScanned) + sizeof(LONG64));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcArchivesScanned) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcDocumentsScanned) + sizeof(LONG64));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcTotalScanTimeMs) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcArchivesScanned) + sizeof(LONG64));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcMaxScanTimeMs) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcTotalScanTimeMs) + sizeof(LONG64));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcCallbackSamples) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcMaxScanTimeMs) + sizeof(LONG64));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcTotalCallbackTimeUs) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcCallbackSamples) + sizeof(LONG64));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcMaxCallbackTimeUs) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcTotalCallbackTimeUs) + sizeof(LONG64));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcScanCircuitOpen) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcMaxCallbackTimeUs) + sizeof(LONG64));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, TxScanSendSamples) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, PcScanCircuitOpen) + sizeof(LONG64));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, TxScanSendTotalUs) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, TxScanSendSamples) + sizeof(LONG64));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, TxScanSendMaxUs) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, TxScanSendTotalUs) + sizeof(LONG64));
C_ASSERT(FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, TxScanSendDeadlineOverruns) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, TxScanSendMaxUs) + sizeof(LONG64));
C_ASSERT(sizeof(SHADOWSTRIKE_DRIVER_STATUS) ==
         FIELD_OFFSET(SHADOWSTRIKE_DRIVER_STATUS, TxScanSendDeadlineOverruns) + sizeof(LONG64));

// ============================================================================
// POLICY UPDATE STRUCTURE
// ============================================================================

typedef struct _SHADOWSTRIKE_POLICY_UPDATE {
    BOOLEAN ScanOnOpen;
    BOOLEAN ScanOnExecute;
    BOOLEAN ScanOnWrite;
    BOOLEAN EnableNotifications;
    BOOLEAN BlockOnTimeout;
    BOOLEAN BlockOnError;
    BOOLEAN ScanNetworkFiles;
    BOOLEAN ScanRemovableMedia;

    UINT64 MaxScanFileSize;
    ULONG ScanTimeoutMs;
    ULONG CacheTTLSeconds;
    ULONG MaxPendingRequests;

    //
    // Message queue tuning (v3 extension).
    // Set to 0 to leave current values unchanged.
    //
    ULONG MqMaxQueueDepth;
    ULONG MqMaxMessageSize;
    ULONG MqBatchSize;
    ULONG MqBatchTimeoutMs;

} SHADOWSTRIKE_POLICY_UPDATE, *PSHADOWSTRIKE_POLICY_UPDATE;

// ============================================================================
// PROTECTED PROCESS REGISTRATION
// ============================================================================

typedef struct _SHADOWSTRIKE_PROTECTED_PROCESS {
    UINT32 ProcessId;
    UINT32 ProtectionFlags;
    WCHAR ProcessName[MAX_PROCESS_NAME_LENGTH];
} SHADOWSTRIKE_PROTECTED_PROCESS, *PSHADOWSTRIKE_PROTECTED_PROCESS;

// ============================================================================
// GENERIC REPLY STRUCTURE
// ============================================================================

typedef struct _SHADOWSTRIKE_GENERIC_REPLY {
    UINT64 MessageId;
    UINT32 Status;
    UINT32 Reserved;
} SHADOWSTRIKE_GENERIC_REPLY, *PSHADOWSTRIKE_GENERIC_REPLY;

// ============================================================================
// PROCESS VERDICT REPLY
// ============================================================================

typedef struct _SHADOWSTRIKE_PROCESS_VERDICT_REPLY {
    UINT64 MessageId;
    UINT8 Verdict;          // Allow/Block
    UINT8 ThreatScore;
    UINT8 Reserved[2];
    UINT32 Flags;
} SHADOWSTRIKE_PROCESS_VERDICT_REPLY, *PSHADOWSTRIKE_PROCESS_VERDICT_REPLY;

// ============================================================================
// FILE SCAN REQUEST (compatible with CommPort.c)
// ============================================================================

typedef struct _SHADOWSTRIKE_FILE_SCAN_REQUEST {
    UINT64 MessageId;
    UINT8  AccessType;
    UINT8  Disposition;
    UINT8  Priority;
    UINT8  RequiresReply;
    UINT32 ProcessId;
    UINT32 ThreadId;
    UINT32 ParentProcessId;
    UINT32 SessionId;
    UINT64 FileSize;
    UINT32 FileAttributes;
    UINT32 DesiredAccess;
    UINT32 ShareAccess;
    UINT32 CreateOptions;
    UINT32 VolumeSerial;
    UINT64 FileId;
    UINT8  IsDirectory;
    UINT8  IsNetworkFile;
    UINT8  IsRemovableMedia;
    UINT8  HasADS;
    UINT16 PathLength;
    UINT16 ProcessNameLength;
    //
    // BYTE COUNTS. See the FILE_SCAN_REQUEST declaration in MessageProtocol.h
    // for why, and for the history of the three builders that disagreed.
    //
    // THIS STRUCTURE IS A SECOND NAME FOR THAT ONE. It is byte-for-byte
    // identical to FILE_SCAN_REQUEST (MessageProtocol.h), which makes the two
    // mutually castable while nothing enforces the pairing - so a change to
    // either declaration alone silently produces two different wire formats
    // under two names. That is the mechanism that let three fabricated
    // user-mode structs drift out of existence-in-the-driver undetected.
    // MessageProtocol.h is the authority; this one exists because CommPort.c
    // was written against it. Do not edit one without the other, and note that
    // tests/kernel_contracts asserts they stay identical.
    //
    // Followed by variable data:
    // WCHAR FilePath[PathLength / sizeof(WCHAR)]
    // WCHAR ProcessName[ProcessNameLength / sizeof(WCHAR)]
} SHADOWSTRIKE_FILE_SCAN_REQUEST, *PSHADOWSTRIKE_FILE_SCAN_REQUEST;

#pragma pack(pop)

// ============================================================================
// HELPER MACROS
// ============================================================================

/**
 * @brief Calculate file scan request size including variable data.
 *
 * BOTH ARGUMENTS ARE BYTE COUNTS, matching PathLength / ProcessNameLength on
 * the wire. This macro used to multiply each argument by sizeof(WCHAR), which
 * is what made it the third statement of the character-count contract; its one
 * caller compensated by dividing a byte count it already held. Passing the
 * field values straight through means the frame size and the declared lengths
 * can no longer disagree by a factor of two.
 */
#define SHADOWSTRIKE_FILE_SCAN_REQUEST_SIZE(pathBytes, procNameBytes) \
    (sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + \
     sizeof(SHADOWSTRIKE_FILE_SCAN_REQUEST) + \
     (pathBytes) + \
     (procNameBytes))

/**
 * @brief Validate message header magic and version.
 */
#define SHADOWSTRIKE_VALID_MESSAGE_HEADER(hdr) \
    ((hdr) != NULL && \
     (hdr)->Magic == SHADOWSTRIKE_MESSAGE_MAGIC && \
     (hdr)->Version == SHADOWSTRIKE_PROTOCOL_VERSION)

/**
 * @brief Check if verdict indicates threat.
 */
#define SHADOWSTRIKE_IS_THREAT_VERDICT(v) \
    ((v) == ShadowStrikeVerdictMalware || \
     (v) == ShadowStrikeVerdictSuspicious || \
     (v) == ShadowStrikeVerdictPUA)

/**
 * @brief Check if verdict should block access.
 */
#define SHADOWSTRIKE_SHOULD_BLOCK_VERDICT(v) \
    ((v) == ShadowStrikeVerdictMalware || \
     (v) == ShadowStrikeVerdictBlock)

// ============================================================================
// FORWARD DECLARATIONS (from MessageProtocol.h)
// ============================================================================

// These are defined in MessageProtocol.h but declared here for convenience
#ifndef SHADOWSTRIKE_MESSAGE_HEADER_DEFINED
#define SHADOWSTRIKE_MESSAGE_HEADER_DEFINED
struct _SHADOWSTRIKE_MESSAGE_HEADER;
#endif

#endif // SHADOWSTRIKE_SHARED_DEFS_H
