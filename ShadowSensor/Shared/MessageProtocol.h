#pragma once

#include "SharedDefs.h"
#include "MessageTypes.h"
#include "VerdictTypes.h"

// Magic value: "SSFS" (ShadowStrike Filter Service)
#define SHADOWSTRIKE_MESSAGE_MAGIC 0x53534653
#define SHADOWSTRIKE_PROTOCOL_VERSION 2

// Ensure structure packing is consistent
#pragma pack(push, 1)

//
// Common Message Header
//
typedef struct _SHADOWSTRIKE_MESSAGE_HEADER {
    UINT32 Magic;           // SHADOWSTRIKE_MESSAGE_MAGIC
    UINT16 Version;         // SHADOWSTRIKE_PROTOCOL_VERSION
    UINT16 MessageType;     // SHADOWSTRIKE_MESSAGE_TYPE
    UINT64 MessageId;       // Correlation ID
    UINT32 TotalSize;       // Size of Header + Data
    UINT32 DataSize;        // Size of Data only
    UINT64 Timestamp;       // Kernel timestamp
    UINT32 Flags;           // Message flags
    UINT32 Reserved;        // Padding/Reserved
} SHADOWSTRIKE_MESSAGE_HEADER, *PSHADOWSTRIKE_MESSAGE_HEADER;

//
// Backward compatibility aliases for code that references FILTER_MESSAGE_HEADER.
// In kernel mode, WDK defines its own FILTER_MESSAGE_HEADER (fltUserStructures.h)
// with a completely different layout, so we must NOT redefine it there.
// Instead, redirect all our references to SHADOWSTRIKE_MESSAGE_HEADER.
//
#ifdef __FLT_USER_STRUCTURES_H__
// Kernel mode: WDK owns FILTER_MESSAGE_HEADER. Our code must use SHADOWSTRIKE_MESSAGE_HEADER.
// MessageHandler code uses SS_MESSAGE_HEADER as the portable alias.
#define SS_MESSAGE_HEADER   SHADOWSTRIKE_MESSAGE_HEADER
#define PSS_MESSAGE_HEADER  PSHADOWSTRIKE_MESSAGE_HEADER
#else
// User mode: no WDK conflict, provide direct aliases.
typedef SHADOWSTRIKE_MESSAGE_HEADER  FILTER_MESSAGE_HEADER;
typedef PSHADOWSTRIKE_MESSAGE_HEADER PFILTER_MESSAGE_HEADER;
#define SS_MESSAGE_HEADER   SHADOWSTRIKE_MESSAGE_HEADER
#define PSS_MESSAGE_HEADER  PSHADOWSTRIKE_MESSAGE_HEADER
#endif

//
// 1. File Scan Request (FilterMessageType_ScanRequest)
//
typedef struct _FILE_SCAN_REQUEST {
    UINT64 MessageId;
    UINT8  AccessType;      // Read, Write, Execute...
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
    // Followed by:
    // WCHAR FilePath[PathLength]
    // WCHAR ProcessName[ProcessNameLength]
} FILE_SCAN_REQUEST, *PFILE_SCAN_REQUEST;

//
// 2. Scan Verdict Reply (FilterMessageType_ScanVerdict)
//
typedef struct _SHADOWSTRIKE_SCAN_VERDICT_REPLY {
    UINT64 MessageId;
    UINT8  Verdict;         // SHADOWSTRIKE_SCAN_VERDICT
    UINT32 ResultCode;
    UINT8  ThreatDetected;
    UINT8  ThreatScore;
    UINT8  CacheResult;
    UINT32 CacheTTL;
    UINT32 Reserved;
    UINT16 ThreatNameLength;
    // Followed by:
    // WCHAR ThreatName[ThreatNameLength]
} SHADOWSTRIKE_SCAN_VERDICT_REPLY, *PSHADOWSTRIKE_SCAN_VERDICT_REPLY;

//
// 3. Process Notification (FilterMessageType_ProcessNotify)
//
typedef struct _SHADOWSTRIKE_PROCESS_NOTIFICATION {
    SS_MESSAGE_HEADER Header; // Header included for convenience in some contexts, or payload starts here?
                                  // Standard convention: Payload struct follows header.
                                  // BUT ScanBridge.c casts Header+1 to specific type.
                                  // So this struct should contain ONLY payload.

    UINT32 ProcessId;
    UINT32 ParentProcessId;
    UINT32 CreatingProcessId; // For explicit creator tracking
    UINT32 CreatingThreadId;
    BOOLEAN Create;
    UINT16 ImagePathLength;
    UINT16 CommandLineLength;
    // Followed by:
    // WCHAR ImagePath[ImagePathLength]
    // WCHAR CommandLine[CommandLineLength]
} SHADOWSTRIKE_PROCESS_NOTIFICATION, *PSHADOWSTRIKE_PROCESS_NOTIFICATION;

//
// 4. Thread Notification (FilterMessageType_ThreadNotify)
//
typedef struct _SHADOWSTRIKE_THREAD_NOTIFICATION {
    UINT32 ProcessId;        // Target Process
    UINT32 ThreadId;         // New Thread
    UINT32 CreatorProcessId; // Source Process (Current)
    UINT32 CreatorThreadId;  // Source Thread (Current)
    BOOLEAN IsRemote;        // TRUE if Creator != Target
    // Additional Context could go here
} SHADOWSTRIKE_THREAD_NOTIFICATION, *PSHADOWSTRIKE_THREAD_NOTIFICATION;

//
// 5. Image Load Notification (FilterMessageType_ImageLoad)
//
typedef struct _SHADOWSTRIKE_IMAGE_NOTIFICATION {
    UINT32 ProcessId;
    UINT64 ImageBase;
    UINT64 ImageSize;
    UINT8  SignatureLevel;
    UINT8  SignatureType;
    BOOLEAN IsSystemImage;
    UINT16 ImageNameLength;
    // Followed by:
    // WCHAR ImageName[ImageNameLength]
} SHADOWSTRIKE_IMAGE_NOTIFICATION, *PSHADOWSTRIKE_IMAGE_NOTIFICATION;

//
// 6. Registry Notification (FilterMessageType_RegistryNotify)
//
typedef struct _SHADOWSTRIKE_REGISTRY_NOTIFICATION {
    UINT32 ProcessId;
    UINT32 ThreadId;
    UINT8  Operation; // Create, Set, Delete
    UINT16 KeyPathLength;
    UINT16 ValueNameLength;
    UINT32 DataSize;
    UINT32 DataType;
    // Followed by:
    // WCHAR KeyPath[KeyPathLength]
    // WCHAR ValueName[ValueNameLength]
    // BYTE Data[DataSize]
} SHADOWSTRIKE_REGISTRY_NOTIFICATION, *PSHADOWSTRIKE_REGISTRY_NOTIFICATION;

#pragma pack(pop)
