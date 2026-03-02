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
#define SHADOWSTRIKE_SERVICE_EXECUTABLE L"ShadowStrikeService.exe"

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
#define SHADOWSTRIKE_MAX_CONNECTIONS    4
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

} SHADOWSTRIKE_DRIVER_STATUS, *PSHADOWSTRIKE_DRIVER_STATUS;

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
    ULONG Reserved;

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
    // Followed by variable data:
    // WCHAR FilePath[PathLength]
    // WCHAR ProcessName[ProcessNameLength]
} SHADOWSTRIKE_FILE_SCAN_REQUEST, *PSHADOWSTRIKE_FILE_SCAN_REQUEST;

#pragma pack(pop)

// ============================================================================
// HELPER MACROS
// ============================================================================

/**
 * @brief Calculate file scan request size including variable data.
 */
#define SHADOWSTRIKE_FILE_SCAN_REQUEST_SIZE(pathLen, procNameLen) \
    (sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + \
     sizeof(SHADOWSTRIKE_FILE_SCAN_REQUEST) + \
     ((pathLen) * sizeof(WCHAR)) + \
     ((procNameLen) * sizeof(WCHAR)))

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
