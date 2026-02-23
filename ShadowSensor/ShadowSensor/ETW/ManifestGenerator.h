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
/*++
===============================================================================
ShadowStrike NGAV - ETW MANIFEST GENERATOR
===============================================================================

@file ManifestGenerator.h
@brief Enterprise-grade ETW manifest and header generation for ShadowSensor.

Provides Enterprise-Grade-class ETW instrumentation manifest generation:
- Full Windows Event Log manifest XML generation (RFC 4122 GUID compliant)
- C/C++ header file generation for compile-time event definitions
- Message table resource generation for localized event messages
- Provider, channel, level, task, opcode, and keyword definitions
- Event template generation with typed parameters
- Internationalization support (resource DLL paths)
- Schema versioning and compatibility validation
- WEVTUTIL-compatible manifest output

Architecture:
- Integrates with EventSchema.h for runtime schema definitions
- Generates manifests consumable by Windows Event Viewer
- Produces headers for type-safe event logging
- Supports incremental generation for CI/CD pipelines

Security Considerations:
- All string operations are bounds-checked
- No user-controlled data in manifest paths
- GUID generation uses cryptographically secure randomness
- XML output is properly escaped to prevent injection

Performance:
- Lazy generation with caching
- Streaming output for large manifests
- Minimal memory allocation during generation

MITRE ATT&CK Coverage:
- T1562.002: Disable Windows Event Logging (manifest enables robust logging)
- T1070.001: Clear Windows Event Logs (structured events for forensics)

@author ShadowStrike Security Team
@version 2.0.0 (Enterprise Edition)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#pragma once

#ifndef _SHADOWSTRIKE_MANIFEST_GENERATOR_H_
#define _SHADOWSTRIKE_MANIFEST_GENERATOR_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include "EventSchema.h"

// ============================================================================
// POOL TAGS
// ============================================================================

/**
 * @brief Pool tag for manifest generator allocations: 'MGen'
 */
#define MG_POOL_TAG                     'neGM'

/**
 * @brief Pool tag for XML buffer allocations
 */
#define MG_XML_POOL_TAG                 'lmXM'

/**
 * @brief Pool tag for header buffer allocations
 */
#define MG_HDR_POOL_TAG                 'rdHM'

/**
 * @brief Pool tag for string builder allocations
 */
#define MG_STR_POOL_TAG                 'rtSM'

/**
 * @brief Pool tag for channel definition allocations
 */
#define MG_CHN_POOL_TAG                 'nhCM'

/**
 * @brief Pool tag for level definition allocations
 */
#define MG_LVL_POOL_TAG                 'lvLM'

/**
 * @brief Pool tag for task definition allocations
 */
#define MG_TSK_POOL_TAG                 'ksTE'

/**
 * @brief Pool tag for opcode definition allocations
 */
#define MG_OPC_POOL_TAG                 'cpOM'

/**
 * @brief Pool tag for keyword definition allocations
 */
#define MG_KWD_POOL_TAG                 'dwKM'

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * @brief Maximum provider symbol name length
 */
#define MG_MAX_PROVIDER_SYMBOL          64

/**
 * @brief Maximum resource file path length
 */
#define MG_MAX_RESOURCE_PATH            260

/**
 * @brief Maximum message file path length
 */
#define MG_MAX_MESSAGE_PATH             260

/**
 * @brief Maximum channel name length
 */
#define MG_MAX_CHANNEL_NAME             64

/**
 * @brief Maximum task name length
 */
#define MG_MAX_TASK_NAME                64

/**
 * @brief Maximum opcode name length
 */
#define MG_MAX_OPCODE_NAME              64

/**
 * @brief Maximum keyword name length
 */
#define MG_MAX_KEYWORD_NAME             64

/**
 * @brief Maximum event message length
 */
#define MG_MAX_EVENT_MESSAGE            1024

/**
 * @brief Initial XML buffer size (64 KB)
 */
#define MG_INITIAL_XML_BUFFER_SIZE      (64 * 1024)

/**
 * @brief Maximum XML buffer size (4 MB)
 */
#define MG_MAX_XML_BUFFER_SIZE          (4 * 1024 * 1024)

/**
 * @brief Initial header buffer size (32 KB)
 */
#define MG_INITIAL_HDR_BUFFER_SIZE      (32 * 1024)

/**
 * @brief Maximum header buffer size (2 MB)
 */
#define MG_MAX_HDR_BUFFER_SIZE          (2 * 1024 * 1024)

/**
 * @brief XML indentation string (4 spaces)
 */
#define MG_XML_INDENT                   "    "

/**
 * @brief Manifest schema namespace
 */
#define MG_MANIFEST_NAMESPACE           "http://schemas.microsoft.com/win/2004/08/events"

/**
 * @brief Manifest schema location
 */
#define MG_MANIFEST_SCHEMA              "http://schemas.microsoft.com/win/2004/08/events eventman.xsd"

/**
 * @brief Default provider message resource ID base
 */
#define MG_DEFAULT_MESSAGE_ID_BASE      0x10000000

/**
 * @brief Event message ID offset from event ID
 */
#define MG_EVENT_MESSAGE_ID_OFFSET      0x10000000

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Manifest generation flags
 *
 * Only flags with active implementations are defined.
 */
typedef enum _MG_GENERATION_FLAGS {
    /// No special flags
    MgFlagNone                  = 0x00000000,

    /// Include verbose comments in output (currently active)
    MgFlagIncludeComments       = 0x00000001,

} MG_GENERATION_FLAGS;

/**
 * @brief Channel types (Windows Event Log channels)
 */
typedef enum _MG_CHANNEL_TYPE {
    /// Admin channel (for IT administrators)
    MgChannelAdmin              = 0,

    /// Operational channel (for diagnostics)
    MgChannelOperational        = 1,

    /// Analytic channel (for debugging, high volume)
    MgChannelAnalytic           = 2,

    /// Debug channel (for developers)
    MgChannelDebug              = 3

} MG_CHANNEL_TYPE;

/**
 * @brief Channel isolation types
 */
typedef enum _MG_CHANNEL_ISOLATION {
    /// Application isolation (default)
    MgIsolationApplication      = 0,

    /// System isolation (requires admin)
    MgIsolationSystem           = 1,

    /// Custom isolation
    MgIsolationCustom           = 2

} MG_CHANNEL_ISOLATION;

/**
 * @brief Generation result status
 */
typedef enum _MG_GENERATION_STATUS {
    /// Generation successful
    MgStatusSuccess             = 0,

    /// Schema is empty or invalid
    MgStatusEmptySchema         = 1,

    /// Buffer allocation failed
    MgStatusAllocationFailed    = 2,

    /// Buffer overflow (content too large)
    MgStatusBufferOverflow      = 3,

    /// Invalid parameter
    MgStatusInvalidParameter    = 4,

    /// Schema validation failed
    MgStatusValidationFailed    = 5,

    /// Internal error
    MgStatusInternalError       = 6

} MG_GENERATION_STATUS;

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Maximum valid channel type value
 */
#define MG_MAX_CHANNEL_TYPE_VALUE       MgChannelDebug

/**
 * @brief Maximum valid isolation type value
 */
#define MG_MAX_ISOLATION_TYPE_VALUE     MgIsolationCustom

/**
 * @brief Channel definition for manifest
 */
typedef struct _MG_CHANNEL_DEFINITION {
    /// Channel name (e.g., "ShadowStrike-Security/Operational")
    CHAR Name[MG_MAX_CHANNEL_NAME];

    /// Channel symbol for header generation
    CHAR Symbol[MG_MAX_CHANNEL_NAME];

    /// Channel type
    MG_CHANNEL_TYPE Type;

    /// Channel isolation type
    MG_CHANNEL_ISOLATION Isolation;

    /// Is channel enabled by default
    BOOLEAN EnabledByDefault;

    /// Channel value (unique identifier)
    UCHAR Value;

    /// Reserved for alignment
    UCHAR Reserved[2];

    /// Message ID for channel name
    ULONG MessageId;

    /// Linked list entry
    LIST_ENTRY ListEntry;

} MG_CHANNEL_DEFINITION, *PMG_CHANNEL_DEFINITION;

/**
 * @brief Level definition for manifest
 */
typedef struct _MG_LEVEL_DEFINITION {
    /// Level name
    CHAR Name[32];

    /// Level symbol for header
    CHAR Symbol[32];

    /// Level value (1=Critical, 2=Error, 3=Warning, 4=Info, 5=Verbose)
    UCHAR Value;

    /// Reserved
    UCHAR Reserved[3];

    /// Message ID for level name
    ULONG MessageId;

    /// Linked list entry
    LIST_ENTRY ListEntry;

} MG_LEVEL_DEFINITION, *PMG_LEVEL_DEFINITION;

/**
 * @brief Task definition for manifest
 */
typedef struct _MG_TASK_DEFINITION {
    /// Task name
    CHAR Name[MG_MAX_TASK_NAME];

    /// Task symbol for header
    CHAR Symbol[MG_MAX_TASK_NAME];

    /// Task value (unique within provider)
    USHORT Value;

    /// Reserved
    UCHAR Reserved[2];

    /// Message ID for task name
    ULONG MessageId;

    /// Linked list entry
    LIST_ENTRY ListEntry;

} MG_TASK_DEFINITION, *PMG_TASK_DEFINITION;

/**
 * @brief Opcode definition for manifest
 */
typedef struct _MG_OPCODE_DEFINITION {
    /// Opcode name
    CHAR Name[MG_MAX_OPCODE_NAME];

    /// Opcode symbol for header
    CHAR Symbol[MG_MAX_OPCODE_NAME];

    /// Opcode value
    UCHAR Value;

    /// Reserved
    UCHAR Reserved[3];

    /// Message ID for opcode name
    ULONG MessageId;

    /// Parent task (NULL for global opcodes)
    PMG_TASK_DEFINITION ParentTask;

    /// Linked list entry
    LIST_ENTRY ListEntry;

} MG_OPCODE_DEFINITION, *PMG_OPCODE_DEFINITION;

/**
 * @brief Keyword definition for manifest
 */
typedef struct _MG_KEYWORD_DEFINITION {
    /// Keyword name
    CHAR Name[MG_MAX_KEYWORD_NAME];

    /// Keyword symbol for header
    CHAR Symbol[MG_MAX_KEYWORD_NAME];

    /// Keyword mask (bit position)
    ULONG64 Mask;

    /// Message ID for keyword name
    ULONG MessageId;

    /// Linked list entry
    LIST_ENTRY ListEntry;

} MG_KEYWORD_DEFINITION, *PMG_KEYWORD_DEFINITION;

/**
 * @brief String builder for efficient concatenation
 */
typedef struct _MG_STRING_BUILDER {
    /// Buffer pointer
    PCHAR Buffer;

    /// Current length (excluding null terminator)
    SIZE_T Length;

    /// Buffer capacity
    SIZE_T Capacity;

    /// Maximum allowed capacity (prevents unbounded growth)
    SIZE_T MaxCapacity;

    /// Pool tag for allocations
    ULONG PoolTag;

    /// Has overflow occurred
    BOOLEAN Overflow;

    /// Reserved
    UCHAR Reserved[3];

} MG_STRING_BUILDER, *PMG_STRING_BUILDER;

/**
 * @brief Generation statistics
 */
typedef struct _MG_GENERATION_STATS {
    /// Total events generated
    ULONG EventCount;

    /// Total channels generated
    ULONG ChannelCount;

    /// Total tasks generated
    ULONG TaskCount;

    /// Total keywords generated
    ULONG KeywordCount;

    /// Total opcodes generated
    ULONG OpcodeCount;

    /// Total templates generated
    ULONG TemplateCount;

    /// Output size in bytes (manifest)
    SIZE_T ManifestSize;

    /// Output size in bytes (header)
    SIZE_T HeaderSize;

    /// Generation time in microseconds
    ULONG64 GenerationTimeUs;

    /// Validation errors encountered
    ULONG ValidationErrors;

} MG_GENERATION_STATS, *PMG_GENERATION_STATS;

/**
 * @brief Manifest generator context
 */
typedef struct _MG_GENERATOR {
    /// Initialization flag
    BOOLEAN Initialized;

    /// Shutdown in progress - prevents new operations
    volatile BOOLEAN ShuttingDown;

    /// Reserved for alignment
    UCHAR Reserved1[2];

    /// Reference count for safe concurrent access.
    /// Starts at 1 on init. Each public API call increments on entry,
    /// decrements on exit. Shutdown waits for count to reach 0.
    volatile LONG ReferenceCount;

    /// Generation flags
    ULONG Flags;

    /// Source schema (reference counted via EsAcquireReference/EsReleaseReference)
    PES_SCHEMA Schema;

    /// Provider symbol name (for C header)
    CHAR ProviderSymbol[MG_MAX_PROVIDER_SYMBOL];

    /// Resource file path (for manifest resourceFileName)
    CHAR ResourceFile[MG_MAX_RESOURCE_PATH];

    /// Message file path (for manifest messageFileName)
    CHAR MessageFile[MG_MAX_MESSAGE_PATH];

    /// Provider name override (if different from schema)
    CHAR ProviderNameOverride[64];

    /// Provider GUID override
    GUID ProviderGuidOverride;

    /// Use GUID override flag
    BOOLEAN UseGuidOverride;

    /// Reserved
    UCHAR Reserved2[7];

    /// Channel definitions list
    LIST_ENTRY ChannelList;
    EX_PUSH_LOCK ChannelLock;
    ULONG ChannelCount;

    /// Level definitions list
    LIST_ENTRY LevelList;
    EX_PUSH_LOCK LevelLock;
    ULONG LevelCount;

    /// Task definitions list
    LIST_ENTRY TaskList;
    EX_PUSH_LOCK TaskLock;
    ULONG TaskCount;

    /// Opcode definitions list
    LIST_ENTRY OpcodeList;
    EX_PUSH_LOCK OpcodeLock;
    ULONG OpcodeCount;

    /// Keyword definitions list
    LIST_ENTRY KeywordList;
    EX_PUSH_LOCK KeywordLock;
    ULONG KeywordCount;

    /// Message ID counter for auto-assignment
    volatile LONG NextMessageId;

    /// Generation statistics
    MG_GENERATION_STATS Stats;

    /// Cached manifest content (protected by CacheLock)
    PCHAR CachedManifest;
    SIZE_T CachedManifestSize;
    BOOLEAN ManifestCacheValid;

    /// Cached header content (protected by CacheLock)
    PCHAR CachedHeader;
    SIZE_T CachedHeaderSize;
    BOOLEAN HeaderCacheValid;

    /// Reserved
    UCHAR Reserved3[5];

    /// Lock for cache operations
    EX_PUSH_LOCK CacheLock;

    /// Shutdown completion event — signaled when ReferenceCount reaches 0
    KEVENT ShutdownEvent;

} MG_GENERATOR, *PMG_GENERATOR;

// ============================================================================
// INITIALIZATION AND SHUTDOWN
// ============================================================================

/**
 * @brief Initialize manifest generator with schema.
 *
 * Creates a new manifest generator instance bound to the provided schema.
 * The generator can produce both XML manifests and C headers.
 *
 * @param Schema        Event schema containing event definitions
 * @param Generator     Receives pointer to new generator instance
 *
 * @return STATUS_SUCCESS on success
 * @return STATUS_INVALID_PARAMETER if Schema or Generator is NULL
 * @return STATUS_INSUFFICIENT_RESOURCES if allocation fails
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MgInitialize(
    _In_ PES_SCHEMA Schema,
    _Outptr_ PMG_GENERATOR* Generator
    );

/**
 * @brief Shutdown and free manifest generator.
 *
 * Releases all resources associated with the generator.
 * Any cached content is freed.
 *
 * @param Generator     Generator instance to shutdown
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
MgShutdown(
    _Inout_ _Post_ptr_invalid_ PMG_GENERATOR Generator
    );

// ============================================================================
// CONFIGURATION
// ============================================================================

/**
 * @brief Set output paths for resource and message files.
 *
 * These paths are embedded in the manifest and used by Windows
 * Event Viewer to locate provider resources.
 *
 * @param Generator     Generator instance
 * @param ResourceFile  Path to resource DLL (e.g., "%SystemRoot%\\System32\\ShadowStrike.dll")
 * @param MessageFile   Path to message DLL (usually same as ResourceFile)
 *
 * @return STATUS_SUCCESS on success
 * @return STATUS_INVALID_PARAMETER if parameters are invalid
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MgSetOutputPaths(
    _In_ PMG_GENERATOR Generator,
    _In_opt_z_ PCSTR ResourceFile,
    _In_opt_z_ PCSTR MessageFile
    );

/**
 * @brief Set provider symbol name for header generation.
 *
 * The symbol name is used as prefix for generated constants and macros.
 *
 * @param Generator         Generator instance
 * @param ProviderSymbol    Symbol name (e.g., "SHADOWSTRIKE")
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MgSetProviderSymbol(
    _In_ PMG_GENERATOR Generator,
    _In_z_ PCSTR ProviderSymbol
    );

/**
 * @brief Override provider GUID.
 *
 * By default, the generator uses the GUID from the schema.
 * This allows overriding for testing or multi-provider scenarios.
 *
 * @param Generator     Generator instance
 * @param ProviderGuid  GUID to use (NULL to clear override)
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MgSetProviderGuid(
    _In_ PMG_GENERATOR Generator,
    _In_opt_ PCGUID ProviderGuid
    );

/**
 * @brief Set generation flags.
 *
 * @param Generator     Generator instance
 * @param Flags         Combination of MG_GENERATION_FLAGS
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MgSetFlags(
    _In_ PMG_GENERATOR Generator,
    _In_ ULONG Flags
    );

// ============================================================================
// CHANNEL/TASK/KEYWORD REGISTRATION
// ============================================================================

/**
 * @brief Register an event channel.
 *
 * Channels organize events in Windows Event Viewer.
 *
 * @param Generator     Generator instance
 * @param Channel       Channel definition
 *
 * @return STATUS_SUCCESS on success
 * @return STATUS_DUPLICATE_NAME if channel already exists
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MgRegisterChannel(
    _In_ PMG_GENERATOR Generator,
    _In_ PMG_CHANNEL_DEFINITION Channel
    );

/**
 * @brief Register an event task.
 *
 * Tasks group related events (e.g., "FileOperations", "ProcessEvents").
 *
 * @param Generator     Generator instance
 * @param Task          Task definition
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MgRegisterTask(
    _In_ PMG_GENERATOR Generator,
    _In_ PMG_TASK_DEFINITION Task
    );

/**
 * @brief Register an event keyword.
 *
 * Keywords enable filtering of events by category.
 *
 * @param Generator     Generator instance
 * @param Keyword       Keyword definition
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MgRegisterKeyword(
    _In_ PMG_GENERATOR Generator,
    _In_ PMG_KEYWORD_DEFINITION Keyword
    );

/**
 * @brief Register an event opcode.
 *
 * Opcodes indicate the operation type (start, stop, info, etc.).
 *
 * @param Generator     Generator instance
 * @param Opcode        Opcode definition
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MgRegisterOpcode(
    _In_ PMG_GENERATOR Generator,
    _In_ PMG_OPCODE_DEFINITION Opcode
    );

// ============================================================================
// MANIFEST GENERATION
// ============================================================================

/**
 * @brief Generate ETW manifest XML.
 *
 * Produces a complete Windows Event Log manifest file suitable for
 * installation with WEVTUTIL. The manifest includes:
 * - Provider definition with GUID
 * - Channel definitions
 * - Level, task, opcode, and keyword definitions
 * - Event definitions with templates
 * - Localization string tables
 *
 * @param Generator         Generator instance
 * @param ManifestContent   Receives pointer to manifest XML (caller must free)
 * @param ContentSize       Receives size of manifest in bytes
 *
 * @return STATUS_SUCCESS on success
 * @return STATUS_INSUFFICIENT_RESOURCES if allocation fails
 *
 * @note Caller must free ManifestContent with ExFreePoolWithTag using MG_XML_POOL_TAG
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MgGenerateManifest(
    _In_ PMG_GENERATOR Generator,
    _Outptr_result_buffer_(*ContentSize) PCHAR* ManifestContent,
    _Out_ PSIZE_T ContentSize
    );

/**
 * @brief Generate C header file with event definitions.
 *
 * Produces a C/C++ header file with:
 * - Provider GUID definition
 * - Event ID enumerations
 * - Keyword mask constants
 * - Level constants
 * - Task/opcode constants
 * - Event logging macros
 *
 * @param Generator         Generator instance
 * @param HeaderContent     Receives pointer to header content (caller must free)
 * @param ContentSize       Receives size of header in bytes
 *
 * @return STATUS_SUCCESS on success
 * @return STATUS_INSUFFICIENT_RESOURCES if allocation fails
 *
 * @note Caller must free HeaderContent with ExFreePoolWithTag using MG_HDR_POOL_TAG
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MgGenerateHeader(
    _In_ PMG_GENERATOR Generator,
    _Outptr_result_buffer_(*ContentSize) PCHAR* HeaderContent,
    _Out_ PSIZE_T ContentSize
    );

/**
 * @brief Generate message table resource script.
 *
 * Produces an .mc file for message compiler input.
 *
 * @param Generator         Generator instance
 * @param MessageContent    Receives pointer to message content (caller must free)
 * @param ContentSize       Receives size in bytes
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MgGenerateMessageTable(
    _In_ PMG_GENERATOR Generator,
    _Outptr_result_buffer_(*ContentSize) PCHAR* MessageContent,
    _Out_ PSIZE_T ContentSize
    );

// ============================================================================
// VALIDATION
// ============================================================================

/**
 * @brief Validate manifest schema consistency.
 *
 * Checks for:
 * - Duplicate event IDs
 * - Missing task/opcode/keyword references
 * - Invalid level values
 * - Schema version compatibility
 *
 * @param Generator         Generator instance
 * @param ErrorCount        Receives number of validation errors
 * @param ErrorMessages     Optional: receives error message buffer (caller frees)
 * @param ErrorBufferSize   Receives size of error buffer
 *
 * @return STATUS_SUCCESS if validation passes
 * @return STATUS_INVALID_PARAMETER if validation fails
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MgValidateSchema(
    _In_ PMG_GENERATOR Generator,
    _Out_ PULONG ErrorCount,
    _Outptr_opt_result_buffer_(*ErrorBufferSize) PCHAR* ErrorMessages,
    _Out_opt_ PSIZE_T ErrorBufferSize
    );

// ============================================================================
// STATISTICS AND CACHE MANAGEMENT
// ============================================================================

/**
 * @brief Get generation statistics.
 *
 * @param Generator     Generator instance
 * @param Stats         Receives statistics
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MgGetStatistics(
    _In_ PMG_GENERATOR Generator,
    _Out_ PMG_GENERATION_STATS Stats
    );

/**
 * @brief Invalidate cached content.
 *
 * Forces regeneration on next manifest/header request.
 * Call after schema changes. Acquires CacheLock exclusive internally.
 *
 * @param Generator     Generator instance
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
MgInvalidateCache(
    _In_ PMG_GENERATOR Generator
    );

// ============================================================================
// DEFAULT DEFINITIONS REGISTRATION
// ============================================================================

/**
 * @brief Register ShadowStrike default channels.
 *
 * Registers the standard ShadowStrike event channels:
 * - ShadowStrike-Security/Operational
 * - ShadowStrike-Security/Analytic
 * - ShadowStrike-Security/Debug
 *
 * @param Generator     Generator instance
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MgRegisterDefaultChannels(
    _In_ PMG_GENERATOR Generator
    );

/**
 * @brief Register ShadowStrike default keywords.
 *
 * Registers standard filtering keywords from ETWProvider.h.
 *
 * @param Generator     Generator instance
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MgRegisterDefaultKeywords(
    _In_ PMG_GENERATOR Generator
    );

/**
 * @brief Register ShadowStrike default tasks.
 *
 * Registers tasks for each event category.
 *
 * @param Generator     Generator instance
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MgRegisterDefaultTasks(
    _In_ PMG_GENERATOR Generator
    );

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_MANIFEST_GENERATOR_H_
