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
 * ShadowStrike NGAV - ENTERPRISE ETW EVENT SCHEMA ENGINE
 * ============================================================================
 *
 * @file EventSchema.h
 * @brief Enterprise-grade ETW event schema definition and validation engine.
 *
 * Implements CrowdStrike Falcon-class event schema management with:
 * - Dynamic event schema registration and lookup
 * - Field-level type validation and serialization
 * - Schema versioning with backward compatibility
 * - Manifest generation for Event Viewer integration
 * - Binary and XML schema serialization
 * - Template-based event construction
 * - Schema inheritance and composition
 * - Runtime schema validation
 * - Memory-efficient field pooling
 * - Thread-safe schema operations
 *
 * Security Hardened v2.2.0:
 * - All input parameters validated before use
 * - Integer overflow protection on size calculations
 * - Safe string handling with length limits
 * - Reference counting with underflow protection
 * - Proper cleanup on all error paths
 * - Lock ordering enforced to prevent deadlocks
 * - Serialization sanitized to prevent kernel pointer leaks
 * - XML entity escaping in manifest generation
 * - Bounded spin-waits with timeout
 * - Duplicate metadata detection
 * - Atomic statistics read/write
 *
 * Lock Ordering (MANDATORY - acquire in this order, never reverse):
 *   Level 0: ManifestLock   (lowest, acquired last)
 *   Level 1: ValueMapLock
 *   Level 2: ChannelLock
 *   Level 3: OpcodeLock
 *   Level 4: TaskLock
 *   Level 5: KeywordLock
 *   Level 6: EventLock      (highest, acquired first)
 *
 *   Per-object locks (ES_VALUE_MAP.Lock) are subordinate to ValueMapLock
 *   and must only be acquired while ValueMapLock is already held.
 *
 * Performance Optimizations:
 * - Hash-based event ID lookup O(1)
 * - Lookaside lists for frequent allocations
 * - Zero-copy field access where possible
 * - IRQL-aware operation selection
 * - Cached schema validation results
 * - Geometric buffer growth for XML generation
 *
 * MITRE ATT&CK Coverage:
 * - T1562.002: Disable Windows Event Logging (schema integrity)
 * - T1070.001: Clear Windows Event Logs (event validation)
 * - T1036: Masquerading (event field validation)
 *
 * @author ShadowStrike Security Team
 * @version 2.2.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_EVENT_SCHEMA_H_
#define _SHADOWSTRIKE_EVENT_SCHEMA_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>
#include <ntddk.h>
#include <evntrace.h>
#include <ntstrsafe.h>

//
// PCGUID is not defined in WDK kernel headers (it comes from ObjBase.h
// in user-mode). Define it here for kernel-mode usage.
//
#ifndef PCGUID_DEFINED
#define PCGUID_DEFINED
typedef const GUID* PCGUID;
#endif

// ============================================================================
// POOL TAGS
// ============================================================================

/**
 * @brief Pool tag for event schema allocations: 'ESCH'
 */
#define ES_POOL_TAG                     'HCSE'

/**
 * @brief Pool tag for field definitions: 'EFLD'
 */
#define ES_FIELD_TAG                    'DLFE'

/**
 * @brief Pool tag for event definitions: 'EEVT'
 */
#define ES_EVENT_TAG                    'TVEE'

/**
 * @brief Pool tag for manifest generation: 'EMAN'
 */
#define ES_MANIFEST_TAG                 'NAME'

/**
 * @brief Pool tag for template allocations: 'ETPL'
 */
#define ES_TEMPLATE_TAG                 'LPTE'

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * @brief Magic value for schema validation
 */
#define ES_SCHEMA_MAGIC                 0x45534348  // 'ESCH'

/**
 * @brief Magic value for event definition validation
 */
#define ES_EVENT_MAGIC                  0x45455654  // 'EEVT'

/**
 * @brief Maximum field name length
 */
#define ES_MAX_FIELD_NAME               64

/**
 * @brief Maximum event name length
 */
#define ES_MAX_EVENT_NAME               64

/**
 * @brief Maximum description length
 */
#define ES_MAX_DESCRIPTION              256

/**
 * @brief Maximum fields per event
 */
#define ES_MAX_FIELDS_PER_EVENT         64

/**
 * @brief Maximum events per schema
 */
#define ES_MAX_EVENTS_PER_SCHEMA        1024

/**
 * @brief Maximum provider name length
 */
#define ES_MAX_PROVIDER_NAME            128

/**
 * @brief Maximum channel name length
 */
#define ES_MAX_CHANNEL_NAME             64

/**
 * @brief Maximum task name length
 */
#define ES_MAX_TASK_NAME                64

/**
 * @brief Maximum opcode name length
 */
#define ES_MAX_OPCODE_NAME              64

/**
 * @brief Maximum keyword name length
 */
#define ES_MAX_KEYWORD_NAME             64

/**
 * @brief Event definition hash bucket count
 */
#define ES_EVENT_HASH_BUCKETS           128

/**
 * @brief Default lookaside list depth
 */
#define ES_LOOKASIDE_DEPTH              64

/**
 * @brief Maximum manifest XML size (1 MB)
 */
#define ES_MAX_MANIFEST_SIZE            (1024 * 1024)

/**
 * @brief Maximum binary schema size (256 KB)
 */
#define ES_MAX_BINARY_SCHEMA_SIZE       (256 * 1024)

/**
 * @brief Schema version for serialization
 */
#define ES_SCHEMA_VERSION_MAJOR         2
#define ES_SCHEMA_VERSION_MINOR         2

/**
 * @brief Maximum metadata entries per category (keywords, tasks, etc.)
 */
#define ES_MAX_KEYWORDS                 256
#define ES_MAX_TASKS                    256
#define ES_MAX_OPCODES                  256
#define ES_MAX_CHANNELS                 32
#define ES_MAX_VALUE_MAPS               128
#define ES_MAX_VALUE_MAP_ENTRIES        1024

/**
 * @brief Maximum iterations for reference drain spin-wait.
 *
 * At 1ms per iteration, this gives a 10-second maximum wait
 * before declaring a leaked reference and proceeding.
 */
#define ES_MAX_DRAIN_ITERATIONS         10000

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief ETW field data types
 */
typedef enum _ES_FIELD_TYPE {
    EsType_NULL = 0,            ///< Null/empty type
    EsType_UINT8,               ///< Unsigned 8-bit integer
    EsType_UINT16,              ///< Unsigned 16-bit integer
    EsType_UINT32,              ///< Unsigned 32-bit integer
    EsType_UINT64,              ///< Unsigned 64-bit integer
    EsType_INT8,                ///< Signed 8-bit integer
    EsType_INT16,               ///< Signed 16-bit integer
    EsType_INT32,               ///< Signed 32-bit integer
    EsType_INT64,               ///< Signed 64-bit integer
    EsType_FLOAT,               ///< 32-bit floating point
    EsType_DOUBLE,              ///< 64-bit floating point
    EsType_BOOL,                ///< Boolean (stored as UINT8)
    EsType_BINARY,              ///< Binary blob (variable length)
    EsType_ANSISTRING,          ///< ANSI string (null-terminated)
    EsType_UNICODESTRING,       ///< Unicode string (null-terminated)
    EsType_GUID,                ///< 128-bit GUID
    EsType_POINTER,             ///< Pointer-sized value
    EsType_FILETIME,            ///< Windows FILETIME
    EsType_SYSTEMTIME,          ///< Windows SYSTEMTIME
    EsType_SID,                 ///< Windows Security Identifier
    EsType_HEXINT32,            ///< 32-bit hex display
    EsType_HEXINT64,            ///< 64-bit hex display
    EsType_COUNTEDSTRING,       ///< Length-prefixed string
    EsType_COUNTEDANSISTRING,   ///< Length-prefixed ANSI string
    EsType_STRUCT,              ///< Nested structure
    EsType_ARRAY,               ///< Array of elements
    EsType_WBEMSID,             ///< WBEM-style SID
    EsType_XMLSTRING,           ///< XML string
    EsType_JSONSTRING,          ///< JSON string
    EsType_IPV4,                ///< IPv4 address (UINT32)
    EsType_IPV6,                ///< IPv6 address (16 bytes)
    EsType_SOCKETADDRESS,       ///< Socket address structure
    EsType_CIMDATETIME,         ///< CIM datetime
    EsType_ETWTIME,             ///< ETW timestamp
    EsType_MAX
} ES_FIELD_TYPE;

/**
 * @brief Field attribute flags
 *
 * Stored as ULONG in ES_FIELD_DEFINITION.Flags to accommodate all values.
 */
typedef enum _ES_FIELD_FLAGS {
    EsFieldFlag_None            = 0x00000000,
    EsFieldFlag_Optional        = 0x00000001,   ///< Field may be omitted
    EsFieldFlag_VariableLength  = 0x00000002,   ///< Variable length field
    EsFieldFlag_Array           = 0x00000004,   ///< Array of values
    EsFieldFlag_CountedArray    = 0x00000008,   ///< Array with count prefix
    EsFieldFlag_FixedCount      = 0x00000010,   ///< Fixed number of elements
    EsFieldFlag_NullTerminated  = 0x00000020,   ///< Null-terminated string
    EsFieldFlag_Indexed         = 0x00000040,   ///< Field is indexed
    EsFieldFlag_Extension       = 0x00000080,   ///< Extension field
    EsFieldFlag_Sensitive       = 0x00000100,   ///< Contains sensitive data
    EsFieldFlag_HexFormat       = 0x00000200,   ///< Display in hex
    EsFieldFlag_Signed          = 0x00000400,   ///< Signed integer
    EsFieldFlag_Pointer         = 0x00000800,   ///< Pointer reference
} ES_FIELD_FLAGS;

/**
 * @brief Event definition flags
 */
typedef enum _ES_EVENT_FLAGS {
    EsEventFlag_None            = 0x00000000,
    EsEventFlag_Critical        = 0x00000001,   ///< Critical event
    EsEventFlag_Security        = 0x00000002,   ///< Security-related
    EsEventFlag_Diagnostic      = 0x00000004,   ///< Diagnostic event
    EsEventFlag_Performance     = 0x00000008,   ///< Performance event
    EsEventFlag_Deprecated      = 0x00000010,   ///< Deprecated event
    EsEventFlag_Internal        = 0x00000020,   ///< Internal use only
    EsEventFlag_HighVolume      = 0x00000040,   ///< High volume event
    EsEventFlag_LowPriority     = 0x00000080,   ///< Low priority
    EsEventFlag_RequiresReply   = 0x00000100,   ///< Requires response
} ES_EVENT_FLAGS;

/**
 * @brief Event channel types
 */
typedef enum _ES_CHANNEL_TYPE {
    EsChannel_Admin = 0,        ///< Admin channel
    EsChannel_Operational,      ///< Operational channel
    EsChannel_Analytic,         ///< Analytic channel
    EsChannel_Debug,            ///< Debug channel
    EsChannel_Max
} ES_CHANNEL_TYPE;

/**
 * @brief Validation result codes
 */
typedef enum _ES_VALIDATION_RESULT {
    EsValidation_Success = 0,
    EsValidation_InvalidSchema,
    EsValidation_InvalidEvent,
    EsValidation_InvalidField,
    EsValidation_SizeMismatch,
    EsValidation_TypeMismatch,
    EsValidation_MissingRequired,
    EsValidation_BufferTooSmall,
    EsValidation_Overflow,
    EsValidation_InvalidPointer,
    EsValidation_StringTooLong,
    EsValidation_InvalidAlignment,
    EsValidation_Max
} ES_VALIDATION_RESULT;

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Field definition structure
 *
 * Note: Flags field is ULONG to match ES_FIELD_FLAGS enum width.
 */
typedef struct _ES_FIELD_DEFINITION {
    /// Field name (ANSI for ETW compatibility)
    CHAR FieldName[ES_MAX_FIELD_NAME];

    /// Field data type
    ES_FIELD_TYPE Type;

    /// Byte offset within event data
    USHORT Offset;

    /// Fixed size (0 for variable-length)
    USHORT Size;

    /// Array element count (0 for non-array)
    USHORT ArrayCount;

    /// Reserved for alignment
    USHORT Reserved1;

    /// Field flags (ULONG to match ES_FIELD_FLAGS enum)
    ULONG Flags;

    /// For array types, the element type
    ES_FIELD_TYPE ElementType;

    /// Field ordinal (position in event)
    UCHAR Ordinal;

    /// Alignment requirement (must be power of 2)
    UCHAR Alignment;

    /// Reserved
    UCHAR Reserved[2];

    /// Field description
    CHAR Description[ES_MAX_DESCRIPTION];

    /// OutType for manifest (display hint)
    CHAR OutType[32];

    /// Map name for value maps
    CHAR MapName[64];

} ES_FIELD_DEFINITION, *PES_FIELD_DEFINITION;

typedef const ES_FIELD_DEFINITION *PCES_FIELD_DEFINITION;

/**
 * @brief Event keyword definition
 */
typedef struct _ES_KEYWORD_DEFINITION {
    LIST_ENTRY ListEntry;
    CHAR Name[ES_MAX_KEYWORD_NAME];
    ULONGLONG Mask;
    CHAR Description[ES_MAX_DESCRIPTION];
} ES_KEYWORD_DEFINITION, *PES_KEYWORD_DEFINITION;

/**
 * @brief Event task definition
 */
typedef struct _ES_TASK_DEFINITION {
    LIST_ENTRY ListEntry;
    CHAR Name[ES_MAX_TASK_NAME];
    USHORT Value;
    USHORT Reserved;
    CHAR Description[ES_MAX_DESCRIPTION];
} ES_TASK_DEFINITION, *PES_TASK_DEFINITION;

/**
 * @brief Event opcode definition
 */
typedef struct _ES_OPCODE_DEFINITION {
    LIST_ENTRY ListEntry;
    CHAR Name[ES_MAX_OPCODE_NAME];
    UCHAR Value;
    UCHAR TaskValue;        ///< Associated task (0 for global)
    USHORT Reserved;
    CHAR Description[ES_MAX_DESCRIPTION];
} ES_OPCODE_DEFINITION, *PES_OPCODE_DEFINITION;

/**
 * @brief Event channel definition
 */
typedef struct _ES_CHANNEL_DEFINITION {
    LIST_ENTRY ListEntry;
    CHAR Name[ES_MAX_CHANNEL_NAME];
    ES_CHANNEL_TYPE Type;
    UCHAR Value;
    BOOLEAN Enabled;
    UCHAR Reserved;
    CHAR Description[ES_MAX_DESCRIPTION];
} ES_CHANNEL_DEFINITION, *PES_CHANNEL_DEFINITION;

/**
 * @brief Event definition structure
 *
 * Internal runtime structure. Contains LIST_ENTRY fields for hash/ordered
 * linkage that must NOT be serialized (see ES_SERIALIZED_EVENT_DEFINITION
 * for the wire format).
 */
typedef struct _ES_EVENT_DEFINITION {
    /// List entry for hash bucket (INTERNAL - never serialize)
    LIST_ENTRY ListEntry;

    /// List entry for ordered enumeration (INTERNAL - never serialize)
    LIST_ENTRY OrderedEntry;

    /// Magic value for validation (INTERNAL)
    ULONG Magic;

    /// Reference count (INTERNAL)
    volatile LONG ReferenceCount;

    /// TRUE if allocated from pool (not lookaside). INTERNAL - never serialize.
    BOOLEAN AllocatedFromPool;

    /// Reserved padding
    UCHAR InternalReserved[3];

    /// Event ID
    USHORT EventId;

    /// Event version
    UCHAR Version;

    /// Event channel
    UCHAR Channel;

    /// Event level (TRACE_LEVEL_*)
    UCHAR Level;

    /// Event opcode
    UCHAR Opcode;

    /// Reserved padding
    UCHAR Reserved[2];

    /// Event task
    USHORT Task;

    /// Event flags
    USHORT Flags;

    /// Event keywords (bitmask)
    ULONGLONG Keywords;

    /// Event name
    CHAR EventName[ES_MAX_EVENT_NAME];

    /// Event description
    CHAR Description[ES_MAX_DESCRIPTION];

    /// Channel name for manifest
    CHAR ChannelName[ES_MAX_CHANNEL_NAME];

    /// Task name for manifest
    CHAR TaskName[ES_MAX_TASK_NAME];

    /// Opcode name for manifest
    CHAR OpcodeName[ES_MAX_OPCODE_NAME];

    /// Template name for manifest
    CHAR TemplateName[ES_MAX_EVENT_NAME];

    /// Message string for Event Viewer
    CHAR Message[ES_MAX_DESCRIPTION];

    /// Field definitions
    ES_FIELD_DEFINITION Fields[ES_MAX_FIELDS_PER_EVENT];

    /// Number of fields
    ULONG FieldCount;

    /// Minimum event data size (fixed fields only)
    ULONG MinDataSize;

    /// Maximum event data size (0 = unlimited)
    ULONG MaxDataSize;

    /// Computed hash for quick lookup
    ULONG NameHash;

} ES_EVENT_DEFINITION, *PES_EVENT_DEFINITION;

typedef const ES_EVENT_DEFINITION *PCES_EVENT_DEFINITION;

/**
 * @brief Serialized event definition - wire format WITHOUT internal fields.
 *
 * This structure is used for binary serialization/deserialization.
 * It excludes LIST_ENTRY, Magic, ReferenceCount, AllocatedFromPool
 * to prevent kernel pointer leakage (KASLR bypass) and stale state.
 */
typedef struct _ES_SERIALIZED_EVENT_DEFINITION {
    USHORT EventId;
    UCHAR Version;
    UCHAR Channel;
    UCHAR Level;
    UCHAR Opcode;
    UCHAR Reserved[2];
    USHORT Task;
    USHORT Flags;
    ULONGLONG Keywords;
    CHAR EventName[ES_MAX_EVENT_NAME];
    CHAR Description[ES_MAX_DESCRIPTION];
    CHAR ChannelName[ES_MAX_CHANNEL_NAME];
    CHAR TaskName[ES_MAX_TASK_NAME];
    CHAR OpcodeName[ES_MAX_OPCODE_NAME];
    CHAR TemplateName[ES_MAX_EVENT_NAME];
    CHAR Message[ES_MAX_DESCRIPTION];
    ES_FIELD_DEFINITION Fields[ES_MAX_FIELDS_PER_EVENT];
    ULONG FieldCount;
    ULONG MinDataSize;
    ULONG MaxDataSize;
    ULONG NameHash;
} ES_SERIALIZED_EVENT_DEFINITION, *PES_SERIALIZED_EVENT_DEFINITION;

/**
 * @brief Serialized keyword definition - wire format WITHOUT LIST_ENTRY.
 */
typedef struct _ES_SERIALIZED_KEYWORD_DEFINITION {
    CHAR Name[ES_MAX_KEYWORD_NAME];
    ULONGLONG Mask;
    CHAR Description[ES_MAX_DESCRIPTION];
} ES_SERIALIZED_KEYWORD_DEFINITION, *PES_SERIALIZED_KEYWORD_DEFINITION;

/**
 * @brief Serialized task definition - wire format WITHOUT LIST_ENTRY.
 */
typedef struct _ES_SERIALIZED_TASK_DEFINITION {
    CHAR Name[ES_MAX_TASK_NAME];
    USHORT Value;
    USHORT Reserved;
    CHAR Description[ES_MAX_DESCRIPTION];
} ES_SERIALIZED_TASK_DEFINITION, *PES_SERIALIZED_TASK_DEFINITION;

/**
 * @brief Serialized opcode definition - wire format WITHOUT LIST_ENTRY.
 */
typedef struct _ES_SERIALIZED_OPCODE_DEFINITION {
    CHAR Name[ES_MAX_OPCODE_NAME];
    UCHAR Value;
    UCHAR TaskValue;
    USHORT Reserved;
    CHAR Description[ES_MAX_DESCRIPTION];
} ES_SERIALIZED_OPCODE_DEFINITION, *PES_SERIALIZED_OPCODE_DEFINITION;

/**
 * @brief Serialized channel definition - wire format WITHOUT LIST_ENTRY.
 */
typedef struct _ES_SERIALIZED_CHANNEL_DEFINITION {
    CHAR Name[ES_MAX_CHANNEL_NAME];
    ES_CHANNEL_TYPE Type;
    UCHAR Value;
    BOOLEAN Enabled;
    UCHAR Reserved;
    CHAR Description[ES_MAX_DESCRIPTION];
} ES_SERIALIZED_CHANNEL_DEFINITION, *PES_SERIALIZED_CHANNEL_DEFINITION;

/**
 * @brief Value map entry (for enumeration display)
 */
typedef struct _ES_VALUE_MAP_ENTRY {
    LIST_ENTRY ListEntry;
    ULONG Value;
    CHAR DisplayName[ES_MAX_FIELD_NAME];
} ES_VALUE_MAP_ENTRY, *PES_VALUE_MAP_ENTRY;

/**
 * @brief Value map definition
 */
typedef struct _ES_VALUE_MAP {
    LIST_ENTRY ListEntry;
    CHAR Name[ES_MAX_FIELD_NAME];
    LIST_ENTRY Entries;
    ULONG EntryCount;
    EX_PUSH_LOCK Lock;
} ES_VALUE_MAP, *PES_VALUE_MAP;

/**
 * @brief Schema statistics
 */
typedef struct _ES_STATISTICS {
    volatile LONG64 EventsRegistered;
    volatile LONG64 EventsUnregistered;
    volatile LONG64 LookupCount;
    volatile LONG64 LookupHits;
    volatile LONG64 LookupMisses;
    volatile LONG64 ValidationCount;
    volatile LONG64 ValidationFailures;
    volatile LONG64 ManifestGenerations;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER LastModifiedTime;
} ES_STATISTICS, *PES_STATISTICS;

/**
 * @brief Event schema structure
 */
typedef struct _ES_SCHEMA {
    /// Magic value for validation
    ULONG Magic;

    /// Initialization flag
    BOOLEAN Initialized;

    /// Shutdown in progress
    BOOLEAN ShuttingDown;

    /// Reserved padding
    UCHAR Reserved[2];

    /// Reference count
    volatile LONG ReferenceCount;

    /// Provider GUID
    GUID ProviderId;

    /// Provider name
    CHAR ProviderName[ES_MAX_PROVIDER_NAME];

    /// Provider symbol (for code generation)
    CHAR ProviderSymbol[ES_MAX_PROVIDER_NAME];

    /// Schema version
    UCHAR MajorVersion;
    UCHAR MinorVersion;
    USHORT Revision;

    /// Event hash buckets
    LIST_ENTRY EventHashBuckets[ES_EVENT_HASH_BUCKETS];

    /// Ordered event list (for enumeration)
    LIST_ENTRY EventList;

    /// Event list lock (Lock Level 6 - highest)
    EX_PUSH_LOCK EventLock;

    /// Number of registered events
    volatile LONG EventCount;

    /// Keyword definitions
    LIST_ENTRY Keywords;
    ULONG KeywordCount;
    EX_PUSH_LOCK KeywordLock;       ///< Lock Level 5

    /// Task definitions
    LIST_ENTRY Tasks;
    ULONG TaskCount;
    EX_PUSH_LOCK TaskLock;          ///< Lock Level 4

    /// Opcode definitions
    LIST_ENTRY Opcodes;
    ULONG OpcodeCount;
    EX_PUSH_LOCK OpcodeLock;        ///< Lock Level 3

    /// Channel definitions
    LIST_ENTRY Channels;
    ULONG ChannelCount;
    EX_PUSH_LOCK ChannelLock;       ///< Lock Level 2

    /// Value maps
    LIST_ENTRY ValueMaps;
    ULONG ValueMapCount;
    EX_PUSH_LOCK ValueMapLock;      ///< Lock Level 1

    /// Lookaside list for event definitions
    NPAGED_LOOKASIDE_LIST EventLookaside;
    BOOLEAN LookasideInitialized;

    /// Statistics
    ES_STATISTICS Stats;

    /// Cached manifest (if generated)
    PCHAR CachedManifest;
    SIZE_T CachedManifestSize;
    BOOLEAN ManifestDirty;
    EX_PUSH_LOCK ManifestLock;      ///< Lock Level 0 - lowest

} ES_SCHEMA, *PES_SCHEMA;

typedef const ES_SCHEMA *PCES_SCHEMA;

/**
 * @brief Event data descriptor for validation
 */
typedef struct _ES_EVENT_DATA_DESC {
    PVOID Data;
    SIZE_T Size;
    ES_FIELD_TYPE ExpectedType;
    ULONG Flags;
} ES_EVENT_DATA_DESC, *PES_EVENT_DATA_DESC;

/**
 * @brief Validation context
 */
typedef struct _ES_VALIDATION_CONTEXT {
    PCES_SCHEMA Schema;
    PCES_EVENT_DEFINITION Event;
    PVOID EventData;
    SIZE_T DataSize;
    ES_VALIDATION_RESULT Result;
    ULONG ErrorFieldIndex;
    CHAR ErrorMessage[256];
} ES_VALIDATION_CONTEXT, *PES_VALIDATION_CONTEXT;

/**
 * @brief Manifest generation options
 */
typedef struct _ES_MANIFEST_OPTIONS {
    BOOLEAN IncludeTemplates;
    BOOLEAN IncludeMessages;
    BOOLEAN IncludeValueMaps;
    BOOLEAN IncludeStringTable;
    BOOLEAN GenerateHeader;
    PCSTR ResourceFileName;
    PCSTR MessageFileName;
    ULONG Culture;          ///< LCID for localization
} ES_MANIFEST_OPTIONS, *PES_MANIFEST_OPTIONS;

// ============================================================================
// INITIALIZATION AND CLEANUP
// ============================================================================

/**
 * @brief Initialize an event schema.
 *
 * Creates a new event schema with the specified provider information.
 *
 * @param Schema        Receives pointer to initialized schema
 * @param ProviderId    Provider GUID (NULL to use ExUuidCreate)
 * @param ProviderName  Provider name (required)
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EsInitialize(
    _Outptr_ PES_SCHEMA* Schema,
    _In_opt_ PCGUID ProviderId,
    _In_ PCSTR ProviderName
    );

/**
 * @brief Initialize schema with default provider name.
 *
 * @param Schema    Receives pointer to initialized schema
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EsInitializeDefault(
    _Outptr_ PES_SCHEMA* Schema
    );

/**
 * @brief Shutdown and free an event schema.
 *
 * Sets *Schema to NULL after freeing to prevent use-after-free.
 * Waits up to ES_MAX_DRAIN_ITERATIONS for references to drain.
 *
 * @param Schema    Pointer to schema pointer (set to NULL on return)
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
EsShutdown(
    _Inout_ PES_SCHEMA* Schema
    );

/**
 * @brief Acquire reference to schema.
 *
 * @param Schema    Schema to reference
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EsAcquireReference(
    _In_ PES_SCHEMA Schema
    );

/**
 * @brief Release reference to schema.
 *
 * @param Schema    Schema to dereference
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EsReleaseReference(
    _In_ PES_SCHEMA Schema
    );

// ============================================================================
// EVENT REGISTRATION
// ============================================================================

/**
 * @brief Register an event definition.
 *
 * Thread-safe: duplicate check and insertion are performed atomically
 * under the event lock.
 *
 * @param Schema    Schema to register event with
 * @param Event     Event definition (copied internally)
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
EsRegisterEvent(
    _In_ PES_SCHEMA Schema,
    _In_ PCES_EVENT_DEFINITION Event
    );

/**
 * @brief Register event with inline definition.
 *
 * @param Schema        Schema to register event with
 * @param EventId       Event ID
 * @param EventName     Event name
 * @param Level         Event level
 * @param Keywords      Event keywords
 * @param FieldCount    Number of fields
 * @param Fields        Array of field definitions
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
EsRegisterEventEx(
    _In_ PES_SCHEMA Schema,
    _In_ USHORT EventId,
    _In_ PCSTR EventName,
    _In_ UCHAR Level,
    _In_ ULONGLONG Keywords,
    _In_ ULONG FieldCount,
    _In_reads_(FieldCount) PCES_FIELD_DEFINITION Fields
    );

/**
 * @brief Unregister an event definition.
 *
 * @param Schema    Schema containing event
 * @param EventId   Event ID to unregister
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
EsUnregisterEvent(
    _In_ PES_SCHEMA Schema,
    _In_ USHORT EventId
    );

// ============================================================================
// EVENT LOOKUP
// ============================================================================

/**
 * @brief Get event definition by ID.
 *
 * Push locks require <= APC_LEVEL. Do NOT call at DISPATCH_LEVEL.
 *
 * @param Schema    Schema to search
 * @param EventId   Event ID to find
 * @param Event     Receives pointer to event definition
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= APC_LEVEL
 *
 * @note Caller must release reference with EsReleaseEventReference
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
EsGetEventDefinition(
    _In_ PES_SCHEMA Schema,
    _In_ USHORT EventId,
    _Outptr_ PES_EVENT_DEFINITION* Event
    );

/**
 * @brief Get event definition by name.
 *
 * Uses case-insensitive comparison.
 *
 * @param Schema    Schema to search
 * @param EventName Event name to find
 * @param Event     Receives pointer to event definition
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
EsGetEventByName(
    _In_ PES_SCHEMA Schema,
    _In_ PCSTR EventName,
    _Outptr_ PES_EVENT_DEFINITION* Event
    );

/**
 * @brief Release event definition reference.
 *
 * @param Event     Event definition to release
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EsReleaseEventReference(
    _In_ PES_EVENT_DEFINITION Event
    );

/**
 * @brief Check if event ID is registered.
 *
 * @param Schema    Schema to check
 * @param EventId   Event ID
 *
 * @return TRUE if registered
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
EsIsEventRegistered(
    _In_ PES_SCHEMA Schema,
    _In_ USHORT EventId
    );

/**
 * @brief Enumerate all registered events.
 *
 * @param Schema        Schema to enumerate
 * @param Callback      Callback for each event
 * @param Context       User context for callback
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= APC_LEVEL
 */
typedef BOOLEAN
(*PES_ENUMERATE_CALLBACK)(
    _In_ PCES_EVENT_DEFINITION Event,
    _In_opt_ PVOID Context
    );

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
EsEnumerateEvents(
    _In_ PES_SCHEMA Schema,
    _In_ PES_ENUMERATE_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

// ============================================================================
// EVENT VALIDATION
// ============================================================================

/**
 * @brief Validate event data against schema.
 *
 * @param Schema        Schema containing event definition
 * @param EventId       Event ID to validate against
 * @param EventData     Event data buffer
 * @param DataSize      Size of event data
 *
 * @return STATUS_SUCCESS if valid
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
EsValidateEvent(
    _In_ PES_SCHEMA Schema,
    _In_ USHORT EventId,
    _In_reads_bytes_(DataSize) PVOID EventData,
    _In_ SIZE_T DataSize
    );

/**
 * @brief Validate event data with detailed results.
 *
 * @param Schema        Schema containing event definition
 * @param EventId       Event ID to validate against
 * @param EventData     Event data buffer
 * @param DataSize      Size of event data
 * @param Context       Validation context (receives details)
 *
 * @return STATUS_SUCCESS if valid
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
EsValidateEventEx(
    _In_ PES_SCHEMA Schema,
    _In_ USHORT EventId,
    _In_reads_bytes_(DataSize) PVOID EventData,
    _In_ SIZE_T DataSize,
    _Out_ PES_VALIDATION_CONTEXT Context
    );

/**
 * @brief Get minimum data size for event.
 *
 * @param Schema    Schema containing event
 * @param EventId   Event ID
 * @param MinSize   Receives minimum data size
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
EsGetEventMinSize(
    _In_ PES_SCHEMA Schema,
    _In_ USHORT EventId,
    _Out_ PULONG MinSize
    );

// ============================================================================
// METADATA MANAGEMENT
// ============================================================================

/**
 * @brief Register a keyword definition.
 *
 * @param Schema        Schema to add keyword to
 * @param Name          Keyword name
 * @param Mask          Keyword bit mask
 * @param Description   Keyword description
 *
 * @return STATUS_SUCCESS on success
 *         STATUS_OBJECT_NAME_COLLISION if duplicate name
 *         STATUS_QUOTA_EXCEEDED if limit reached
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
EsRegisterKeyword(
    _In_ PES_SCHEMA Schema,
    _In_ PCSTR Name,
    _In_ ULONGLONG Mask,
    _In_opt_ PCSTR Description
    );

/**
 * @brief Register a task definition.
 *
 * @param Schema        Schema to add task to
 * @param Name          Task name
 * @param Value         Task value
 * @param Description   Task description
 *
 * @return STATUS_SUCCESS on success
 *         STATUS_OBJECT_NAME_COLLISION if duplicate name
 *         STATUS_QUOTA_EXCEEDED if limit reached
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
EsRegisterTask(
    _In_ PES_SCHEMA Schema,
    _In_ PCSTR Name,
    _In_ USHORT Value,
    _In_opt_ PCSTR Description
    );

/**
 * @brief Register an opcode definition.
 *
 * @param Schema        Schema to add opcode to
 * @param Name          Opcode name
 * @param Value         Opcode value
 * @param TaskValue     Associated task (0 for global)
 * @param Description   Opcode description
 *
 * @return STATUS_SUCCESS on success
 *         STATUS_OBJECT_NAME_COLLISION if duplicate name
 *         STATUS_QUOTA_EXCEEDED if limit reached
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
EsRegisterOpcode(
    _In_ PES_SCHEMA Schema,
    _In_ PCSTR Name,
    _In_ UCHAR Value,
    _In_ UCHAR TaskValue,
    _In_opt_ PCSTR Description
    );

/**
 * @brief Register a channel definition.
 *
 * @param Schema        Schema to add channel to
 * @param Name          Channel name
 * @param Type          Channel type
 * @param Value         Channel value
 * @param Enabled       Channel enabled by default
 * @param Description   Channel description
 *
 * @return STATUS_SUCCESS on success
 *         STATUS_OBJECT_NAME_COLLISION if duplicate name
 *         STATUS_QUOTA_EXCEEDED if limit reached
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
EsRegisterChannel(
    _In_ PES_SCHEMA Schema,
    _In_ PCSTR Name,
    _In_ ES_CHANNEL_TYPE Type,
    _In_ UCHAR Value,
    _In_ BOOLEAN Enabled,
    _In_opt_ PCSTR Description
    );

/**
 * @brief Register a value map for display.
 *
 * @param Schema    Schema to add map to
 * @param MapName   Map name
 *
 * @return STATUS_SUCCESS on success
 *         STATUS_OBJECT_NAME_COLLISION if duplicate name
 *         STATUS_QUOTA_EXCEEDED if limit reached
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
EsRegisterValueMap(
    _In_ PES_SCHEMA Schema,
    _In_ PCSTR MapName
    );

/**
 * @brief Add entry to value map.
 *
 * @param Schema        Schema containing map
 * @param MapName       Map name
 * @param Value         Numeric value
 * @param DisplayName   Display name for value
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
EsAddValueMapEntry(
    _In_ PES_SCHEMA Schema,
    _In_ PCSTR MapName,
    _In_ ULONG Value,
    _In_ PCSTR DisplayName
    );

// ============================================================================
// MANIFEST GENERATION
// ============================================================================

/**
 * @brief Generate ETW manifest XML.
 *
 * @param Schema        Schema to generate manifest for
 * @param ManifestXml   Receives allocated manifest XML
 * @param XmlSize       Receives manifest size
 *
 * @return STATUS_SUCCESS on success
 *
 * @note Caller must free ManifestXml with EsFreeManifest
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EsGenerateManifestXml(
    _In_ PES_SCHEMA Schema,
    _Outptr_ PCHAR* ManifestXml,
    _Out_ PSIZE_T XmlSize
    );

/**
 * @brief Generate ETW manifest with options.
 *
 * @param Schema        Schema to generate manifest for
 * @param Options       Generation options
 * @param ManifestXml   Receives allocated manifest XML
 * @param XmlSize       Receives manifest size
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EsGenerateManifestXmlEx(
    _In_ PES_SCHEMA Schema,
    _In_ PES_MANIFEST_OPTIONS Options,
    _Outptr_ PCHAR* ManifestXml,
    _Out_ PSIZE_T XmlSize
    );

/**
 * @brief Free manifest XML.
 *
 * @param ManifestXml   Manifest to free
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EsFreeManifest(
    _In_ PCHAR ManifestXml
    );

/**
 * @brief Get cached manifest if available.
 *
 * Returns a COPY of the cached manifest. Caller must free with EsFreeManifest.
 *
 * @param Schema        Schema to get manifest for
 * @param ManifestXml   Receives allocated copy of cached manifest
 * @param XmlSize       Receives manifest size
 *
 * @return STATUS_SUCCESS if cached manifest available
 *
 * @irql <= APC_LEVEL
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
EsGetCachedManifest(
    _In_ PES_SCHEMA Schema,
    _Outptr_ PCHAR* ManifestXml,
    _Out_ PSIZE_T XmlSize
    );

// ============================================================================
// SCHEMA SERIALIZATION
// ============================================================================

/**
 * @brief Serialize schema to binary format.
 *
 * Uses sanitized wire-format structures that exclude kernel pointers
 * and internal state.
 *
 * @param Schema        Schema to serialize
 * @param Buffer        Receives allocated buffer
 * @param BufferSize    Receives buffer size
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EsSerializeSchema(
    _In_ PES_SCHEMA Schema,
    _Outptr_ PVOID* Buffer,
    _Out_ PSIZE_T BufferSize
    );

/**
 * @brief Deserialize schema from binary format.
 *
 * Validates all string fields for null-termination and cross-validates
 * header counts against buffer size before processing.
 *
 * @param Buffer        Serialized schema buffer
 * @param BufferSize    Buffer size
 * @param Schema        Receives initialized schema
 *
 * @return STATUS_SUCCESS on success
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EsDeserializeSchema(
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Outptr_ PES_SCHEMA* Schema
    );

// ============================================================================
// STATISTICS AND DIAGNOSTICS
// ============================================================================

/**
 * @brief Get schema statistics.
 *
 * Reads each counter atomically to prevent torn reads.
 *
 * @param Schema    Schema to get stats for
 * @param Stats     Receives statistics
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EsGetStatistics(
    _In_ PES_SCHEMA Schema,
    _Out_ PES_STATISTICS Stats
    );

/**
 * @brief Reset schema statistics.
 *
 * @param Schema    Schema to reset stats for
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EsResetStatistics(
    _In_ PES_SCHEMA Schema
    );

/**
 * @brief Get event count in schema.
 *
 * @param Schema    Schema to query
 *
 * @return Number of registered events
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
EsGetEventCount(
    _In_ PES_SCHEMA Schema
    );

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Check if schema is valid.
 *
 * WARNING: This function checks magic/initialized fields on the provided
 * pointer. It provides NO protection against use-after-free - if Schema
 * points to freed memory, the read itself is undefined behavior. Callers
 * are responsible for ensuring the schema pointer is valid (i.e., the
 * schema has not been shut down via EsShutdown).
 *
 * @param Schema    Schema to validate
 *
 * @return TRUE if valid
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
EsIsValidSchema(
    _In_opt_ PES_SCHEMA Schema
    );

/**
 * @brief Get field type name.
 *
 * @param Type  Field type
 *
 * @return Static string name
 *
 * @irql Any
 */
PCSTR
EsGetFieldTypeName(
    _In_ ES_FIELD_TYPE Type
    );

/**
 * @brief Get field type size.
 *
 * @param Type  Field type
 *
 * @return Size in bytes (0 for variable)
 *
 * @irql Any
 */
ULONG
EsGetFieldTypeSize(
    _In_ ES_FIELD_TYPE Type
    );

/**
 * @brief Get validation result name.
 *
 * @param Result    Validation result
 *
 * @return Static string name
 *
 * @irql Any
 */
PCSTR
EsGetValidationResultName(
    _In_ ES_VALIDATION_RESULT Result
    );

/**
 * @brief Calculate field offset for alignment.
 *
 * @param CurrentOffset Current offset
 * @param Alignment     Required alignment (MUST be power of 2)
 *
 * @return Aligned offset, or CurrentOffset if alignment is invalid
 *
 * @irql Any
 */
FORCEINLINE
USHORT
EsAlignOffset(
    _In_ USHORT CurrentOffset,
    _In_ UCHAR Alignment
    )
{
    ULONG aligned;

    if (Alignment == 0 || Alignment == 1) {
        return CurrentOffset;
    }

    //
    // Validate alignment is a power of 2
    //
    if ((Alignment & (Alignment - 1)) != 0) {
        return CurrentOffset;
    }

    //
    // Compute in ULONG to detect overflow, then clamp to USHORT max
    //
    aligned = ((ULONG)CurrentOffset + Alignment - 1) & ~((ULONG)Alignment - 1);
    if (aligned > 0xFFFF) {
        return 0xFFFF;
    }

    return (USHORT)aligned;
}

/**
 * @brief Initialize field definition helper.
 *
 * @param Field         Field to initialize
 * @param Name          Field name
 * @param Type          Field type
 * @param Offset        Byte offset
 * @param Size          Size (0 for variable)
 * @param Flags         Field flags
 */
FORCEINLINE
VOID
EsInitField(
    _Out_ PES_FIELD_DEFINITION Field,
    _In_ PCSTR Name,
    _In_ ES_FIELD_TYPE Type,
    _In_ USHORT Offset,
    _In_ USHORT Size,
    _In_ ULONG Flags
    )
{
    RtlZeroMemory(Field, sizeof(ES_FIELD_DEFINITION));
    RtlStringCchCopyA(Field->FieldName, ES_MAX_FIELD_NAME, Name);
    Field->Type = Type;
    Field->Offset = Offset;
    Field->Size = Size;
    Field->Flags = Flags;
    Field->Alignment = 1;
}

#ifdef __cplusplus
}
#endif

#endif // _SHADOWSTRIKE_EVENT_SCHEMA_H_
