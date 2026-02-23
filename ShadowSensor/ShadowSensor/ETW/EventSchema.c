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
 * ShadowStrike NGAV - ENTERPRISE ETW EVENT SCHEMA ENGINE IMPLEMENTATION
 * ============================================================================
 *
 * @file EventSchema.c
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
 * Security Hardened v2.0.0:
 * - All input parameters validated before use
 * - Integer overflow protection on size calculations
 * - Safe string handling with length limits
 * - Reference counting for thread safety
 * - Proper cleanup on all error paths
 * - Lock ordering to prevent deadlocks
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "EventSchema.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/StringUtils.h"
#include <ntstrsafe.h>

//
// FLOAT, DOUBLE, FILETIME, SYSTEMTIME are not declared in WDK kernel
// headers. Define their sizes explicitly for the ETW type-size table.
// va_copy may not be available in MSVC C mode; define a fallback.
//
#define ES_SIZEOF_FLOAT         4   // IEEE 754 single-precision
#define ES_SIZEOF_DOUBLE        8   // IEEE 754 double-precision
#define ES_SIZEOF_FILETIME      8   // Two ULONG (dwLowDateTime + dwHighDateTime)
#define ES_SIZEOF_SYSTEMTIME   16   // Eight WORD fields

#ifndef va_copy
#define va_copy(dest, src) ((dest) = (src))
#endif

//
// Maximum length of a value map name (matches ES_VALUE_MAP.Name[] size).
//
#define ES_MAX_VALUE_MAP_NAME  ES_MAX_FIELD_NAME

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

/**
 * @brief Binary schema header magic
 */
#define ES_BINARY_HEADER_MAGIC          0x45534248  // 'ESBH'

/**
 * @brief Maximum XML element depth for manifest
 */
#define ES_MAX_XML_DEPTH                16

/**
 * @brief XML buffer growth increment
 */
#define ES_XML_BUFFER_INCREMENT         4096

/**
 * @brief Default string table size
 */
#define ES_DEFAULT_STRING_TABLE_SIZE    256

/**
 * @brief Hash seed for name hashing
 */
#define ES_HASH_SEED                    0x5A5A5A5A

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

/**
 * @brief Binary schema header for serialization
 */
typedef struct _ES_BINARY_HEADER {
    ULONG Magic;
    UCHAR MajorVersion;
    UCHAR MinorVersion;
    USHORT Flags;
    ULONG EventCount;
    ULONG KeywordCount;
    ULONG TaskCount;
    ULONG OpcodeCount;
    ULONG ChannelCount;
    ULONG ValueMapCount;
    ULONG TotalSize;
    GUID ProviderId;
    CHAR ProviderName[ES_MAX_PROVIDER_NAME];
} ES_BINARY_HEADER, *PES_BINARY_HEADER;

/**
 * @brief XML builder context
 */
typedef struct _ES_XML_CONTEXT {
    PCHAR Buffer;
    SIZE_T BufferSize;
    SIZE_T CurrentPos;
    ULONG IndentLevel;
    BOOLEAN Error;
    NTSTATUS ErrorStatus;
} ES_XML_CONTEXT, *PES_XML_CONTEXT;

// ============================================================================
// STATIC STRING TABLES
// ============================================================================

/**
 * @brief Field type names for manifest generation
 */
static PCSTR g_FieldTypeNames[] = {
    "win:Null",             // EsType_NULL
    "win:UInt8",            // EsType_UINT8
    "win:UInt16",           // EsType_UINT16
    "win:UInt32",           // EsType_UINT32
    "win:UInt64",           // EsType_UINT64
    "win:Int8",             // EsType_INT8
    "win:Int16",            // EsType_INT16
    "win:Int32",            // EsType_INT32
    "win:Int64",            // EsType_INT64
    "win:Float",            // EsType_FLOAT
    "win:Double",           // EsType_DOUBLE
    "win:Boolean",          // EsType_BOOL
    "win:Binary",           // EsType_BINARY
    "win:AnsiString",       // EsType_ANSISTRING
    "win:UnicodeString",    // EsType_UNICODESTRING
    "win:GUID",             // EsType_GUID
    "win:Pointer",          // EsType_POINTER
    "win:FILETIME",         // EsType_FILETIME
    "win:SYSTEMTIME",       // EsType_SYSTEMTIME
    "win:SID",              // EsType_SID
    "win:HexInt32",         // EsType_HEXINT32
    "win:HexInt64",         // EsType_HEXINT64
    "win:CountedString",    // EsType_COUNTEDSTRING
    "win:CountedAnsiString",// EsType_COUNTEDANSISTRING
    "win:Struct",           // EsType_STRUCT
    "win:Binary",           // EsType_ARRAY (uses Binary for manifest)
    "trace:WBEMSid",        // EsType_WBEMSID
    "win:UnicodeString",    // EsType_XMLSTRING
    "win:UnicodeString",    // EsType_JSONSTRING
    "win:UInt32",           // EsType_IPV4
    "win:Binary",           // EsType_IPV6
    "win:Binary",           // EsType_SOCKETADDRESS
    "win:UnicodeString",    // EsType_CIMDATETIME
    "win:UInt64"            // EsType_ETWTIME
};

/**
 * @brief Field type sizes (0 = variable length)
 */
static ULONG g_FieldTypeSizes[] = {
    0,                      // EsType_NULL
    sizeof(UINT8),          // EsType_UINT8
    sizeof(UINT16),         // EsType_UINT16
    sizeof(UINT32),         // EsType_UINT32
    sizeof(UINT64),         // EsType_UINT64
    sizeof(INT8),           // EsType_INT8
    sizeof(INT16),          // EsType_INT16
    sizeof(INT32),          // EsType_INT32
    sizeof(INT64),          // EsType_INT64
    ES_SIZEOF_FLOAT,        // EsType_FLOAT
    ES_SIZEOF_DOUBLE,       // EsType_DOUBLE
    sizeof(UINT8),          // EsType_BOOL
    0,                      // EsType_BINARY (variable)
    0,                      // EsType_ANSISTRING (variable)
    0,                      // EsType_UNICODESTRING (variable)
    sizeof(GUID),           // EsType_GUID
    sizeof(PVOID),          // EsType_POINTER
    ES_SIZEOF_FILETIME,     // EsType_FILETIME
    ES_SIZEOF_SYSTEMTIME,   // EsType_SYSTEMTIME
    0,                      // EsType_SID (variable)
    sizeof(UINT32),         // EsType_HEXINT32
    sizeof(UINT64),         // EsType_HEXINT64
    0,                      // EsType_COUNTEDSTRING (variable)
    0,                      // EsType_COUNTEDANSISTRING (variable)
    0,                      // EsType_STRUCT (variable)
    0,                      // EsType_ARRAY (variable)
    0,                      // EsType_WBEMSID (variable)
    0,                      // EsType_XMLSTRING (variable)
    0,                      // EsType_JSONSTRING (variable)
    sizeof(UINT32),         // EsType_IPV4
    16,                     // EsType_IPV6
    0,                      // EsType_SOCKETADDRESS (variable)
    0,                      // EsType_CIMDATETIME (variable)
    sizeof(UINT64)          // EsType_ETWTIME
};

/**
 * @brief Validation result names
 */
static PCSTR g_ValidationResultNames[] = {
    "Success",
    "InvalidSchema",
    "InvalidEvent",
    "InvalidField",
    "SizeMismatch",
    "TypeMismatch",
    "MissingRequired",
    "BufferTooSmall",
    "Overflow",
    "InvalidPointer",
    "StringTooLong",
    "InvalidAlignment"
};

/**
 * @brief Channel type names for manifest
 */
static PCSTR g_ChannelTypeNames[] = {
    "Admin",
    "Operational",
    "Analytic",
    "Debug"
};

// ============================================================================
// PRIVATE FUNCTION PROTOTYPES
// ============================================================================

static ULONG
EspHashEventId(
    _In_ USHORT EventId
);

static ULONG
EspHashEventName(
    _In_ PCSTR EventName
);

static PES_EVENT_DEFINITION
EspAllocateEventDefinition(
    _In_ PES_SCHEMA Schema
);

static VOID
EspFreeEventDefinition(
    _In_ PES_SCHEMA Schema,
    _In_ PES_EVENT_DEFINITION Event
);

static VOID
EspInsertEventIntoHash(
    _In_ PES_SCHEMA Schema,
    _In_ PES_EVENT_DEFINITION Event
);

static VOID
EspRemoveEventFromHash(
    _In_ PES_SCHEMA Schema,
    _In_ PES_EVENT_DEFINITION Event
);

static NTSTATUS
EspValidateFieldData(
    _In_ PCES_FIELD_DEFINITION Field,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ SIZE_T DataSize,
    _Inout_ PES_VALIDATION_CONTEXT Context
);

static NTSTATUS
EspXmlInitContext(
    _Out_ PES_XML_CONTEXT Context,
    _In_ SIZE_T InitialSize
);

static VOID
EspXmlFreeContext(
    _Inout_ PES_XML_CONTEXT Context
);

static NTSTATUS
EspXmlAppend(
    _Inout_ PES_XML_CONTEXT Context,
    _In_ PCSTR Format,
    ...
);

static NTSTATUS
EspXmlAppendIndent(
    _Inout_ PES_XML_CONTEXT Context
);

static SIZE_T
EspXmlEscapeString(
    _Out_writes_opt_(DestSize) PCHAR Dest,
    _In_ SIZE_T DestSize,
    _In_ PCSTR Src
);

static NTSTATUS
EspXmlAppendEscaped(
    _Inout_ PES_XML_CONTEXT Context,
    _In_ PCSTR Str
);

static NTSTATUS
EspGenerateEventsElement(
    _In_ PES_SCHEMA Schema,
    _Inout_ PES_XML_CONTEXT Context,
    _In_ PES_MANIFEST_OPTIONS Options
);

static NTSTATUS
EspGenerateTemplatesElement(
    _In_ PES_SCHEMA Schema,
    _Inout_ PES_XML_CONTEXT Context
);

static NTSTATUS
EspGenerateKeywordsElement(
    _In_ PES_SCHEMA Schema,
    _Inout_ PES_XML_CONTEXT Context
);

static NTSTATUS
EspGenerateTasksElement(
    _In_ PES_SCHEMA Schema,
    _Inout_ PES_XML_CONTEXT Context
);

static NTSTATUS
EspGenerateChannelsElement(
    _In_ PES_SCHEMA Schema,
    _Inout_ PES_XML_CONTEXT Context
);

static NTSTATUS
EspGenerateMapsElement(
    _In_ PES_SCHEMA Schema,
    _Inout_ PES_XML_CONTEXT Context
);

static VOID
EspGuidToString(
    _In_ PCGUID Guid,
    _Out_writes_(37) PCHAR Buffer
);

static VOID
EspInvalidateCachedManifest(
    _Inout_ PES_SCHEMA Schema
);

// ============================================================================
// PAGE ALLOCATION
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, EsInitialize)
#pragma alloc_text(INIT, EsInitializeDefault)
#pragma alloc_text(PAGE, EsShutdown)
#pragma alloc_text(PAGE, EsRegisterEvent)
#pragma alloc_text(PAGE, EsRegisterEventEx)
#pragma alloc_text(PAGE, EsUnregisterEvent)
#pragma alloc_text(PAGE, EsEnumerateEvents)
#pragma alloc_text(PAGE, EsRegisterKeyword)
#pragma alloc_text(PAGE, EsRegisterTask)
#pragma alloc_text(PAGE, EsRegisterOpcode)
#pragma alloc_text(PAGE, EsRegisterChannel)
#pragma alloc_text(PAGE, EsRegisterValueMap)
#pragma alloc_text(PAGE, EsAddValueMapEntry)
#pragma alloc_text(PAGE, EsGenerateManifestXml)
#pragma alloc_text(PAGE, EsGenerateManifestXmlEx)
#pragma alloc_text(PAGE, EsSerializeSchema)
#pragma alloc_text(PAGE, EsDeserializeSchema)
#endif

// ============================================================================
// INITIALIZATION AND CLEANUP
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EsInitialize(
    _Outptr_ PES_SCHEMA* Schema,
    _In_opt_ PCGUID ProviderId,
    _In_ PCSTR ProviderName
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PES_SCHEMA schema = NULL;
    ULONG i;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Schema == NULL) {
        return STATUS_INVALID_PARAMETER_1;
    }

    *Schema = NULL;

    if (ProviderName == NULL) {
        return STATUS_INVALID_PARAMETER_3;
    }

    //
    // Validate provider name length
    //
    SIZE_T nameLen = 0;
    status = RtlStringCchLengthA(ProviderName, ES_MAX_PROVIDER_NAME, &nameLen);
    if (!NT_SUCCESS(status) || nameLen == 0) {
        return STATUS_INVALID_PARAMETER_3;
    }

    //
    // Allocate schema structure
    //
    schema = (PES_SCHEMA)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(ES_SCHEMA),
        ES_POOL_TAG
    );

    if (schema == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(schema, sizeof(ES_SCHEMA));

    //
    // Set magic value
    //
    schema->Magic = ES_SCHEMA_MAGIC;

    //
    // Set provider ID
    //
    if (ProviderId != NULL) {
        RtlCopyMemory(&schema->ProviderId, ProviderId, sizeof(GUID));
    } else {
        //
        // Generate a GUID based on provider name hash
        //
        ULONG hash = EspHashEventName(ProviderName);
        schema->ProviderId.Data1 = hash;
        schema->ProviderId.Data2 = (USHORT)(hash >> 16);
        schema->ProviderId.Data3 = (USHORT)(hash & 0xFFFF);
        RtlFillMemory(schema->ProviderId.Data4, 8, (UCHAR)(hash >> 24));
    }

    //
    // Copy provider name
    //
    status = RtlStringCchCopyA(
        schema->ProviderName,
        ES_MAX_PROVIDER_NAME,
        ProviderName
    );

    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(schema, ES_POOL_TAG);
        return status;
    }

    //
    // Generate provider symbol (remove spaces and special chars)
    //
    PCHAR symbolPtr = schema->ProviderSymbol;
    PCSTR namePtr = ProviderName;
    SIZE_T symbolLen = 0;

    while (*namePtr != '\0' && symbolLen < ES_MAX_PROVIDER_NAME - 1) {
        CHAR c = *namePtr++;
        if ((c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '_') {
            *symbolPtr++ = c;
            symbolLen++;
        } else if (c == ' ' || c == '-') {
            *symbolPtr++ = '_';
            symbolLen++;
        }
    }
    *symbolPtr = '\0';

    //
    // Set version
    //
    schema->MajorVersion = ES_SCHEMA_VERSION_MAJOR;
    schema->MinorVersion = ES_SCHEMA_VERSION_MINOR;
    schema->Revision = 0;

    //
    // Initialize hash buckets
    //
    for (i = 0; i < ES_EVENT_HASH_BUCKETS; i++) {
        InitializeListHead(&schema->EventHashBuckets[i]);
    }

    //
    // Initialize ordered event list
    //
    InitializeListHead(&schema->EventList);

    //
    // Initialize push locks
    //
    ExInitializePushLock(&schema->EventLock);
    ExInitializePushLock(&schema->KeywordLock);
    ExInitializePushLock(&schema->TaskLock);
    ExInitializePushLock(&schema->OpcodeLock);
    ExInitializePushLock(&schema->ChannelLock);
    ExInitializePushLock(&schema->ValueMapLock);
    ExInitializePushLock(&schema->ManifestLock);

    //
    // Initialize metadata lists
    //
    InitializeListHead(&schema->Keywords);
    InitializeListHead(&schema->Tasks);
    InitializeListHead(&schema->Opcodes);
    InitializeListHead(&schema->Channels);
    InitializeListHead(&schema->ValueMaps);

    //
    // Initialize lookaside list for event definitions
    //
    ExInitializeNPagedLookasideList(
        &schema->EventLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(ES_EVENT_DEFINITION),
        ES_EVENT_TAG,
        ES_LOOKASIDE_DEPTH
    );
    schema->LookasideInitialized = TRUE;

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&schema->Stats.CreateTime);
    schema->Stats.LastModifiedTime = schema->Stats.CreateTime;

    //
    // Set initial reference count
    //
    schema->ReferenceCount = 1;

    //
    // Mark as initialized
    //
    schema->Initialized = TRUE;

    *Schema = schema;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EsInitializeDefault(
    _Outptr_ PES_SCHEMA* Schema
)
{
    PAGED_CODE();

    return EsInitialize(Schema, NULL, "ShadowStrike-NGAV");
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
EsShutdown(
    _Inout_ PES_SCHEMA* SchemaPtr
)
{
    PES_SCHEMA Schema;
    PLIST_ENTRY entry;
    PES_EVENT_DEFINITION event;
    PES_KEYWORD_DEFINITION keyword;
    PES_TASK_DEFINITION task;
    PES_OPCODE_DEFINITION opcode;
    PES_CHANNEL_DEFINITION channel;
    PES_VALUE_MAP valueMap;
    PES_VALUE_MAP_ENTRY mapEntry;
    ULONG i;
    ULONG drainIterations;

    PAGED_CODE();

    if (SchemaPtr == NULL) {
        return;
    }

    Schema = *SchemaPtr;

    if (Schema == NULL || Schema->Magic != ES_SCHEMA_MAGIC) {
        return;
    }

    //
    // Signal shutdown
    //
    Schema->ShuttingDown = TRUE;

    //
    // Wait for references to drain (bounded)
    //
    drainIterations = 0;
    while (Schema->ReferenceCount > 1) {
        LARGE_INTEGER delay;
        delay.QuadPart = -10000; // 1ms
        KeDelayExecutionThread(KernelMode, FALSE, &delay);

        if (++drainIterations >= ES_MAX_DRAIN_ITERATIONS) {
            break;
        }
    }

    //
    // Free all events (remove from both hash and ordered list)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Schema->EventLock);

    for (i = 0; i < ES_EVENT_HASH_BUCKETS; i++) {
        while (!IsListEmpty(&Schema->EventHashBuckets[i])) {
            entry = RemoveHeadList(&Schema->EventHashBuckets[i]);
            event = CONTAINING_RECORD(entry, ES_EVENT_DEFINITION, ListEntry);
            RemoveEntryList(&event->OrderedEntry);
            EspFreeEventDefinition(Schema, event);
        }
    }

    ExReleasePushLockExclusive(&Schema->EventLock);
    KeLeaveCriticalRegion();

    //
    // Free keywords
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Schema->KeywordLock);

    while (!IsListEmpty(&Schema->Keywords)) {
        entry = RemoveHeadList(&Schema->Keywords);
        keyword = CONTAINING_RECORD(entry, ES_KEYWORD_DEFINITION, ListEntry);
        ShadowStrikeFreePoolWithTag(keyword, ES_POOL_TAG);
    }

    ExReleasePushLockExclusive(&Schema->KeywordLock);
    KeLeaveCriticalRegion();

    //
    // Free tasks
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Schema->TaskLock);

    while (!IsListEmpty(&Schema->Tasks)) {
        entry = RemoveHeadList(&Schema->Tasks);
        task = CONTAINING_RECORD(entry, ES_TASK_DEFINITION, ListEntry);
        ShadowStrikeFreePoolWithTag(task, ES_POOL_TAG);
    }

    ExReleasePushLockExclusive(&Schema->TaskLock);
    KeLeaveCriticalRegion();

    //
    // Free opcodes
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Schema->OpcodeLock);

    while (!IsListEmpty(&Schema->Opcodes)) {
        entry = RemoveHeadList(&Schema->Opcodes);
        opcode = CONTAINING_RECORD(entry, ES_OPCODE_DEFINITION, ListEntry);
        ShadowStrikeFreePoolWithTag(opcode, ES_POOL_TAG);
    }

    ExReleasePushLockExclusive(&Schema->OpcodeLock);
    KeLeaveCriticalRegion();

    //
    // Free channels
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Schema->ChannelLock);

    while (!IsListEmpty(&Schema->Channels)) {
        entry = RemoveHeadList(&Schema->Channels);
        channel = CONTAINING_RECORD(entry, ES_CHANNEL_DEFINITION, ListEntry);
        ShadowStrikeFreePoolWithTag(channel, ES_POOL_TAG);
    }

    ExReleasePushLockExclusive(&Schema->ChannelLock);
    KeLeaveCriticalRegion();

    //
    // Free value maps and their entries
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Schema->ValueMapLock);

    while (!IsListEmpty(&Schema->ValueMaps)) {
        entry = RemoveHeadList(&Schema->ValueMaps);
        valueMap = CONTAINING_RECORD(entry, ES_VALUE_MAP, ListEntry);

        //
        // Free all entries in this map
        //
        while (!IsListEmpty(&valueMap->Entries)) {
            PLIST_ENTRY entryEntry = RemoveHeadList(&valueMap->Entries);
            mapEntry = CONTAINING_RECORD(entryEntry, ES_VALUE_MAP_ENTRY, ListEntry);
            ShadowStrikeFreePoolWithTag(mapEntry, ES_POOL_TAG);
        }

        ShadowStrikeFreePoolWithTag(valueMap, ES_POOL_TAG);
    }

    ExReleasePushLockExclusive(&Schema->ValueMapLock);
    KeLeaveCriticalRegion();

    //
    // Free cached manifest
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Schema->ManifestLock);

    if (Schema->CachedManifest != NULL) {
        ShadowStrikeFreePoolWithTag(Schema->CachedManifest, ES_MANIFEST_TAG);
        Schema->CachedManifest = NULL;
        Schema->CachedManifestSize = 0;
    }

    ExReleasePushLockExclusive(&Schema->ManifestLock);
    KeLeaveCriticalRegion();

    //
    // Delete lookaside list
    //
    if (Schema->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&Schema->EventLookaside);
        Schema->LookasideInitialized = FALSE;
    }

    //
    // Clear magic and free
    //
    Schema->Magic = 0;
    Schema->Initialized = FALSE;

    ShadowStrikeFreePoolWithTag(Schema, ES_POOL_TAG);

    //
    // NULL out caller's pointer to prevent use-after-free
    //
    *SchemaPtr = NULL;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EsAcquireReference(
    _In_ PES_SCHEMA Schema
)
{
    if (Schema != NULL && Schema->Magic == ES_SCHEMA_MAGIC &&
        !Schema->ShuttingDown) {
        InterlockedIncrement(&Schema->ReferenceCount);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EsReleaseReference(
    _In_ PES_SCHEMA Schema
)
{
    if (Schema != NULL && Schema->Magic == ES_SCHEMA_MAGIC) {
        LONG newVal = InterlockedDecrement(&Schema->ReferenceCount);
        if (newVal < 0) {
            //
            // Underflow detected — restore and do not go negative
            //
            InterlockedIncrement(&Schema->ReferenceCount);
        }
    }
}

// ============================================================================
// EVENT REGISTRATION
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
EsRegisterEvent(
    _In_ PES_SCHEMA Schema,
    _In_ PCES_EVENT_DEFINITION Event
)
{
    PES_EVENT_DEFINITION newEvent = NULL;
    BOOLEAN duplicateFound = FALSE;
    ULONG bucket;
    PLIST_ENTRY entry;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (!EsIsValidSchema(Schema)) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (Event == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Schema->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Validate field count
    //
    if (Event->FieldCount > ES_MAX_FIELDS_PER_EVENT) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Allocate new event definition
    //
    newEvent = EspAllocateEventDefinition(Schema);
    if (newEvent == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Copy only public/data fields — never copy internal fields
    // (ListEntry, OrderedEntry, Magic, ReferenceCount, AllocatedFromPool)
    //
    newEvent->EventId = Event->EventId;
    newEvent->Version = Event->Version;
    newEvent->Channel = Event->Channel;
    newEvent->Level = Event->Level;
    newEvent->Opcode = Event->Opcode;
    newEvent->Task = Event->Task;
    newEvent->Flags = Event->Flags;
    newEvent->Keywords = Event->Keywords;
    newEvent->FieldCount = Event->FieldCount;
    newEvent->MaxDataSize = Event->MaxDataSize;

    RtlCopyMemory(newEvent->EventName, Event->EventName, sizeof(newEvent->EventName));
    RtlCopyMemory(newEvent->Description, Event->Description, sizeof(newEvent->Description));
    RtlCopyMemory(newEvent->ChannelName, Event->ChannelName, sizeof(newEvent->ChannelName));
    RtlCopyMemory(newEvent->TaskName, Event->TaskName, sizeof(newEvent->TaskName));
    RtlCopyMemory(newEvent->OpcodeName, Event->OpcodeName, sizeof(newEvent->OpcodeName));
    RtlCopyMemory(newEvent->TemplateName, Event->TemplateName, sizeof(newEvent->TemplateName));
    RtlCopyMemory(newEvent->Message, Event->Message, sizeof(newEvent->Message));

    if (Event->FieldCount > 0) {
        RtlCopyMemory(newEvent->Fields, Event->Fields,
            Event->FieldCount * sizeof(ES_FIELD_DEFINITION));
    }

    //
    // Initialize internal fields
    //
    InitializeListHead(&newEvent->ListEntry);
    InitializeListHead(&newEvent->OrderedEntry);
    newEvent->Magic = ES_EVENT_MAGIC;
    newEvent->ReferenceCount = 1;

    //
    // Compute name hash
    //
    newEvent->NameHash = EspHashEventName(newEvent->EventName);

    //
    // Calculate minimum data size from fixed fields (with overflow check)
    //
    newEvent->MinDataSize = 0;
    for (ULONG i = 0; i < newEvent->FieldCount; i++) {
        PCES_FIELD_DEFINITION field = &newEvent->Fields[i];
        if (!(field->Flags & EsFieldFlag_Optional)) {
            if (field->Size > 0) {
                ULONG newSize = newEvent->MinDataSize + field->Size;
                if (newSize < newEvent->MinDataSize) {
                    EspFreeEventDefinition(Schema, newEvent);
                    return STATUS_INTEGER_OVERFLOW;
                }
                newEvent->MinDataSize = newSize;
            }
        }
    }

    //
    // Atomically check for duplicate and insert under exclusive lock
    // (eliminates TOCTOU race between check and insert)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Schema->EventLock);

    //
    // Check event count limit under lock
    //
    if ((ULONG)Schema->EventCount >= ES_MAX_EVENTS_PER_SCHEMA) {
        ExReleasePushLockExclusive(&Schema->EventLock);
        KeLeaveCriticalRegion();
        EspFreeEventDefinition(Schema, newEvent);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Check for duplicate event ID under lock
    //
    bucket = EspHashEventId(Event->EventId);
    for (entry = Schema->EventHashBuckets[bucket].Flink;
         entry != &Schema->EventHashBuckets[bucket];
         entry = entry->Flink) {

        PES_EVENT_DEFINITION candidate = CONTAINING_RECORD(
            entry, ES_EVENT_DEFINITION, ListEntry
        );

        if (candidate->EventId == Event->EventId) {
            duplicateFound = TRUE;
            break;
        }
    }

    if (duplicateFound) {
        ExReleasePushLockExclusive(&Schema->EventLock);
        KeLeaveCriticalRegion();
        EspFreeEventDefinition(Schema, newEvent);
        return STATUS_OBJECT_NAME_COLLISION;
    }

    EspInsertEventIntoHash(Schema, newEvent);
    InsertTailList(&Schema->EventList, &newEvent->OrderedEntry);
    InterlockedIncrement(&Schema->EventCount);

    ExReleasePushLockExclusive(&Schema->EventLock);
    KeLeaveCriticalRegion();

    //
    // Update statistics
    //
    InterlockedIncrement64(&Schema->Stats.EventsRegistered);
    KeQuerySystemTime(&Schema->Stats.LastModifiedTime);

    //
    // Invalidate cached manifest
    //
    EspInvalidateCachedManifest(Schema);

    return STATUS_SUCCESS;
}

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
)
{
    PES_EVENT_DEFINITION eventDef;
    NTSTATUS status;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (EventName == NULL) {
        return STATUS_INVALID_PARAMETER_3;
    }

    if (FieldCount > 0 && Fields == NULL) {
        return STATUS_INVALID_PARAMETER_6;
    }

    if (FieldCount > ES_MAX_FIELDS_PER_EVENT) {
        return STATUS_INVALID_PARAMETER_5;
    }

    //
    // Allocate from pool — ES_EVENT_DEFINITION is ~30KB, too large for kernel stack
    //
    eventDef = (PES_EVENT_DEFINITION)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(ES_EVENT_DEFINITION),
        ES_EVENT_TAG
    );

    if (eventDef == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize event definition
    //
    RtlZeroMemory(eventDef, sizeof(ES_EVENT_DEFINITION));

    eventDef->EventId = EventId;
    eventDef->Level = Level;
    eventDef->Keywords = Keywords;
    eventDef->FieldCount = FieldCount;

    //
    // Copy event name
    //
    status = RtlStringCchCopyA(
        eventDef->EventName,
        ES_MAX_EVENT_NAME,
        EventName
    );

    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(eventDef, ES_EVENT_TAG);
        return status;
    }

    //
    // Copy fields
    //
    if (FieldCount > 0) {
        RtlCopyMemory(
            eventDef->Fields,
            Fields,
            FieldCount * sizeof(ES_FIELD_DEFINITION)
        );
    }

    status = EsRegisterEvent(Schema, eventDef);

    ShadowStrikeFreePoolWithTag(eventDef, ES_EVENT_TAG);

    return status;
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
EsUnregisterEvent(
    _In_ PES_SCHEMA Schema,
    _In_ USHORT EventId
)
{
    PES_EVENT_DEFINITION event = NULL;

    PAGED_CODE();

    if (!EsIsValidSchema(Schema)) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (Schema->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Find and remove event
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Schema->EventLock);

    ULONG bucket = EspHashEventId(EventId);
    PLIST_ENTRY entry;

    for (entry = Schema->EventHashBuckets[bucket].Flink;
         entry != &Schema->EventHashBuckets[bucket];
         entry = entry->Flink) {

        PES_EVENT_DEFINITION candidate = CONTAINING_RECORD(
            entry, ES_EVENT_DEFINITION, ListEntry
        );

        if (candidate->EventId == EventId) {
            event = candidate;
            RemoveEntryList(&event->ListEntry);
            RemoveEntryList(&event->OrderedEntry);
            InterlockedDecrement(&Schema->EventCount);
            break;
        }
    }

    ExReleasePushLockExclusive(&Schema->EventLock);
    KeLeaveCriticalRegion();

    if (event == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Wait for references to drain (bounded)
    //
    {
        ULONG drainIterations = 0;
        while (event->ReferenceCount > 0) {
            LARGE_INTEGER delay;
            delay.QuadPart = -10000; // 1ms
            KeDelayExecutionThread(KernelMode, FALSE, &delay);

            if (++drainIterations >= ES_MAX_DRAIN_ITERATIONS) {
                break;
            }
        }
    }

    //
    // Free event
    //
    EspFreeEventDefinition(Schema, event);

    //
    // Update statistics
    //
    InterlockedIncrement64(&Schema->Stats.EventsUnregistered);
    KeQuerySystemTime(&Schema->Stats.LastModifiedTime);

    //
    // Invalidate cached manifest
    //
    EspInvalidateCachedManifest(Schema);

    return STATUS_SUCCESS;
}

// ============================================================================
// EVENT LOOKUP
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
EsGetEventDefinition(
    _In_ PES_SCHEMA Schema,
    _In_ USHORT EventId,
    _Outptr_ PES_EVENT_DEFINITION* Event
)
{
    PES_EVENT_DEFINITION event = NULL;
    ULONG bucket;
    PLIST_ENTRY entry;

    if (Event == NULL) {
        return STATUS_INVALID_PARAMETER_3;
    }

    *Event = NULL;

    if (!EsIsValidSchema(Schema)) {
        return STATUS_INVALID_PARAMETER_1;
    }

    //
    // Update lookup statistics
    //
    InterlockedIncrement64(&Schema->Stats.LookupCount);

    //
    // Hash lookup
    //
    bucket = EspHashEventId(EventId);

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Schema->EventLock);

    for (entry = Schema->EventHashBuckets[bucket].Flink;
         entry != &Schema->EventHashBuckets[bucket];
         entry = entry->Flink) {

        PES_EVENT_DEFINITION candidate = CONTAINING_RECORD(
            entry, ES_EVENT_DEFINITION, ListEntry
        );

        if (candidate->EventId == EventId &&
            candidate->Magic == ES_EVENT_MAGIC) {
            event = candidate;
            InterlockedIncrement(&event->ReferenceCount);
            break;
        }
    }

    ExReleasePushLockShared(&Schema->EventLock);
    KeLeaveCriticalRegion();

    if (event == NULL) {
        InterlockedIncrement64(&Schema->Stats.LookupMisses);
        return STATUS_NOT_FOUND;
    }

    InterlockedIncrement64(&Schema->Stats.LookupHits);
    *Event = event;

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
EsGetEventByName(
    _In_ PES_SCHEMA Schema,
    _In_ PCSTR EventName,
    _Outptr_ PES_EVENT_DEFINITION* Event
)
{
    PES_EVENT_DEFINITION event = NULL;
    ULONG nameHash;
    ULONG i;
    PLIST_ENTRY entry;

    if (Event == NULL) {
        return STATUS_INVALID_PARAMETER_3;
    }

    *Event = NULL;

    if (!EsIsValidSchema(Schema)) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (EventName == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    //
    // Compute name hash for quick comparison
    //
    nameHash = EspHashEventName(EventName);

    //
    // Search all buckets (name lookup is O(n) but uses hash for quick reject)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Schema->EventLock);

    for (i = 0; i < ES_EVENT_HASH_BUCKETS && event == NULL; i++) {
        for (entry = Schema->EventHashBuckets[i].Flink;
             entry != &Schema->EventHashBuckets[i];
             entry = entry->Flink) {

            PES_EVENT_DEFINITION candidate = CONTAINING_RECORD(
                entry, ES_EVENT_DEFINITION, ListEntry
            );

            //
            // Quick hash comparison
            //
            if (candidate->NameHash == nameHash &&
                candidate->Magic == ES_EVENT_MAGIC) {
                //
                // Verify with string compare
                //
                if (_stricmp(candidate->EventName, EventName) == 0) {
                    event = candidate;
                    InterlockedIncrement(&event->ReferenceCount);
                    break;
                }
            }
        }
    }

    ExReleasePushLockShared(&Schema->EventLock);
    KeLeaveCriticalRegion();

    if (event == NULL) {
        return STATUS_NOT_FOUND;
    }

    *Event = event;

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EsReleaseEventReference(
    _In_ PES_EVENT_DEFINITION Event
)
{
    if (Event != NULL && Event->Magic == ES_EVENT_MAGIC) {
        LONG newVal = InterlockedDecrement(&Event->ReferenceCount);
        if (newVal < 0) {
            InterlockedIncrement(&Event->ReferenceCount);
        }
    }
}

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
EsIsEventRegistered(
    _In_ PES_SCHEMA Schema,
    _In_ USHORT EventId
)
{
    BOOLEAN found = FALSE;
    ULONG bucket;
    PLIST_ENTRY entry;

    if (!EsIsValidSchema(Schema)) {
        return FALSE;
    }

    bucket = EspHashEventId(EventId);

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Schema->EventLock);

    for (entry = Schema->EventHashBuckets[bucket].Flink;
         entry != &Schema->EventHashBuckets[bucket];
         entry = entry->Flink) {

        PES_EVENT_DEFINITION event = CONTAINING_RECORD(
            entry, ES_EVENT_DEFINITION, ListEntry
        );

        if (event->EventId == EventId) {
            found = TRUE;
            break;
        }
    }

    ExReleasePushLockShared(&Schema->EventLock);
    KeLeaveCriticalRegion();

    return found;
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
EsEnumerateEvents(
    _In_ PES_SCHEMA Schema,
    _In_ PES_ENUMERATE_CALLBACK Callback,
    _In_opt_ PVOID Context
)
{
    PLIST_ENTRY entry;
    BOOLEAN continueEnum = TRUE;

    PAGED_CODE();

    if (!EsIsValidSchema(Schema)) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (Callback == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Schema->EventLock);

    for (entry = Schema->EventList.Flink;
         entry != &Schema->EventList && continueEnum;
         entry = entry->Flink) {

        PES_EVENT_DEFINITION event = CONTAINING_RECORD(
            entry, ES_EVENT_DEFINITION, OrderedEntry
        );

        if (event->Magic == ES_EVENT_MAGIC) {
            continueEnum = Callback(event, Context);
        }
    }

    ExReleasePushLockShared(&Schema->EventLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

// ============================================================================
// EVENT VALIDATION
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
EsValidateEvent(
    _In_ PES_SCHEMA Schema,
    _In_ USHORT EventId,
    _In_reads_bytes_(DataSize) PVOID EventData,
    _In_ SIZE_T DataSize
)
{
    ES_VALIDATION_CONTEXT context;
    return EsValidateEventEx(Schema, EventId, EventData, DataSize, &context);
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
EsValidateEventEx(
    _In_ PES_SCHEMA Schema,
    _In_ USHORT EventId,
    _In_reads_bytes_(DataSize) PVOID EventData,
    _In_ SIZE_T DataSize,
    _Out_ PES_VALIDATION_CONTEXT Context
)
{
    NTSTATUS status;
    PES_EVENT_DEFINITION event = NULL;
    SIZE_T offset = 0;
    ULONG fieldIndex;

    if (Context == NULL) {
        return STATUS_INVALID_PARAMETER_5;
    }

    RtlZeroMemory(Context, sizeof(ES_VALIDATION_CONTEXT));
    Context->Schema = Schema;
    Context->EventData = EventData;
    Context->DataSize = DataSize;
    Context->Result = EsValidation_Success;

    //
    // Validate schema
    //
    if (!EsIsValidSchema(Schema)) {
        Context->Result = EsValidation_InvalidSchema;
        RtlStringCchCopyA(Context->ErrorMessage, sizeof(Context->ErrorMessage),
            "Invalid or uninitialized schema");
        return STATUS_INVALID_PARAMETER_1;
    }

    //
    // Update validation statistics
    //
    InterlockedIncrement64(&Schema->Stats.ValidationCount);

    //
    // Get event definition
    //
    status = EsGetEventDefinition(Schema, EventId, &event);
    if (!NT_SUCCESS(status)) {
        Context->Result = EsValidation_InvalidEvent;
        RtlStringCchPrintfA(Context->ErrorMessage, sizeof(Context->ErrorMessage),
            "Event ID %u not registered", EventId);
        InterlockedIncrement64(&Schema->Stats.ValidationFailures);
        return status;
    }

    Context->Event = event;

    //
    // Validate minimum size
    //
    if (DataSize < event->MinDataSize) {
        Context->Result = EsValidation_BufferTooSmall;
        RtlStringCchPrintfA(Context->ErrorMessage, sizeof(Context->ErrorMessage),
            "Data size %zu less than minimum %u", DataSize, event->MinDataSize);
        EsReleaseEventReference(event);
        InterlockedIncrement64(&Schema->Stats.ValidationFailures);
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Validate maximum size if specified
    //
    if (event->MaxDataSize > 0 && DataSize > event->MaxDataSize) {
        Context->Result = EsValidation_SizeMismatch;
        RtlStringCchPrintfA(Context->ErrorMessage, sizeof(Context->ErrorMessage),
            "Data size %zu exceeds maximum %u", DataSize, event->MaxDataSize);
        EsReleaseEventReference(event);
        InterlockedIncrement64(&Schema->Stats.ValidationFailures);
        return STATUS_BUFFER_OVERFLOW;
    }

    //
    // Validate each field
    //
    for (fieldIndex = 0; fieldIndex < event->FieldCount; fieldIndex++) {
        PCES_FIELD_DEFINITION field = &event->Fields[fieldIndex];
        SIZE_T fieldSize;
        PVOID fieldData;

        //
        // Calculate field location
        //
        if (field->Offset > 0) {
            //
            // Explicit offset
            //
            if (field->Offset >= DataSize) {
                if (field->Flags & EsFieldFlag_Optional) {
                    continue;  // Optional field not present
                }
                Context->Result = EsValidation_MissingRequired;
                Context->ErrorFieldIndex = fieldIndex;
                RtlStringCchPrintfA(Context->ErrorMessage, sizeof(Context->ErrorMessage),
                    "Required field '%s' offset %u exceeds data size",
                    field->FieldName, field->Offset);
                EsReleaseEventReference(event);
                InterlockedIncrement64(&Schema->Stats.ValidationFailures);
                return STATUS_INVALID_PARAMETER;
            }
            fieldData = (PUCHAR)EventData + field->Offset;
            offset = field->Offset;
        } else {
            //
            // Sequential offset
            //
            fieldData = (PUCHAR)EventData + offset;
        }

        //
        // Get field size
        //
        if (field->Size > 0) {
            fieldSize = field->Size;
        } else {
            fieldSize = EsGetFieldTypeSize(field->Type);
        }

        //
        // Check if field data fits
        //
        if (fieldSize > 0 && offset + fieldSize > DataSize) {
            if (field->Flags & EsFieldFlag_Optional) {
                continue;
            }
            Context->Result = EsValidation_BufferTooSmall;
            Context->ErrorFieldIndex = fieldIndex;
            RtlStringCchPrintfA(Context->ErrorMessage, sizeof(Context->ErrorMessage),
                "Field '%s' at offset %zu with size %zu exceeds data boundary",
                field->FieldName, offset, fieldSize);
            EsReleaseEventReference(event);
            InterlockedIncrement64(&Schema->Stats.ValidationFailures);
            return STATUS_BUFFER_TOO_SMALL;
        }

        //
        // Validate field data
        //
        status = EspValidateFieldData(field, fieldData, DataSize - offset, Context);
        if (!NT_SUCCESS(status)) {
            Context->ErrorFieldIndex = fieldIndex;
            EsReleaseEventReference(event);
            InterlockedIncrement64(&Schema->Stats.ValidationFailures);
            return status;
        }

        //
        // Advance offset for sequential fields
        //
        if (field->Offset == 0 && fieldSize > 0) {
            offset += fieldSize;
        }
    }

    EsReleaseEventReference(event);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
EsGetEventMinSize(
    _In_ PES_SCHEMA Schema,
    _In_ USHORT EventId,
    _Out_ PULONG MinSize
)
{
    PES_EVENT_DEFINITION event;
    NTSTATUS status;

    if (MinSize == NULL) {
        return STATUS_INVALID_PARAMETER_3;
    }

    *MinSize = 0;

    status = EsGetEventDefinition(Schema, EventId, &event);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *MinSize = event->MinDataSize;

    EsReleaseEventReference(event);

    return STATUS_SUCCESS;
}

// ============================================================================
// METADATA MANAGEMENT
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
EsRegisterKeyword(
    _In_ PES_SCHEMA Schema,
    _In_ PCSTR Name,
    _In_ ULONGLONG Mask,
    _In_opt_ PCSTR Description
)
{
    PES_KEYWORD_DEFINITION keyword;
    NTSTATUS status;

    PAGED_CODE();

    if (!EsIsValidSchema(Schema)) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (Name == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Mask == 0) {
        return STATUS_INVALID_PARAMETER_3;
    }

    //
    // Allocate keyword definition
    //
    keyword = (PES_KEYWORD_DEFINITION)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(ES_KEYWORD_DEFINITION),
        ES_POOL_TAG
    );

    if (keyword == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(keyword, sizeof(ES_KEYWORD_DEFINITION));

    //
    // Copy name
    //
    status = RtlStringCchCopyA(keyword->Name, ES_MAX_KEYWORD_NAME, Name);
    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(keyword, ES_POOL_TAG);
        return status;
    }

    keyword->Mask = Mask;

    //
    // Copy description if provided
    //
    if (Description != NULL) {
        RtlStringCchCopyA(keyword->Description, ES_MAX_DESCRIPTION, Description);
    }

    //
    // Add to list (with duplicate and quota check under lock)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Schema->KeywordLock);

    //
    // Check quota
    //
    if (Schema->KeywordCount >= ES_MAX_KEYWORDS) {
        ExReleasePushLockExclusive(&Schema->KeywordLock);
        KeLeaveCriticalRegion();
        ShadowStrikeFreePoolWithTag(keyword, ES_POOL_TAG);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Check for duplicate name
    //
    {
        PLIST_ENTRY dup;
        for (dup = Schema->Keywords.Flink;
             dup != &Schema->Keywords;
             dup = dup->Flink) {

            PES_KEYWORD_DEFINITION existing = CONTAINING_RECORD(
                dup, ES_KEYWORD_DEFINITION, ListEntry
            );

            if (_stricmp(existing->Name, keyword->Name) == 0) {
                ExReleasePushLockExclusive(&Schema->KeywordLock);
                KeLeaveCriticalRegion();
                ShadowStrikeFreePoolWithTag(keyword, ES_POOL_TAG);
                return STATUS_OBJECT_NAME_COLLISION;
            }
        }
    }

    InsertTailList(&Schema->Keywords, &keyword->ListEntry);
    Schema->KeywordCount++;

    ExReleasePushLockExclusive(&Schema->KeywordLock);
    KeLeaveCriticalRegion();

    EspInvalidateCachedManifest(Schema);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
EsRegisterTask(
    _In_ PES_SCHEMA Schema,
    _In_ PCSTR Name,
    _In_ USHORT Value,
    _In_opt_ PCSTR Description
)
{
    PES_TASK_DEFINITION task;
    NTSTATUS status;

    PAGED_CODE();

    if (!EsIsValidSchema(Schema)) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (Name == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    //
    // Allocate task definition
    //
    task = (PES_TASK_DEFINITION)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(ES_TASK_DEFINITION),
        ES_POOL_TAG
    );

    if (task == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(task, sizeof(ES_TASK_DEFINITION));

    //
    // Copy name
    //
    status = RtlStringCchCopyA(task->Name, ES_MAX_TASK_NAME, Name);
    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(task, ES_POOL_TAG);
        return status;
    }

    task->Value = Value;

    if (Description != NULL) {
        RtlStringCchCopyA(task->Description, ES_MAX_DESCRIPTION, Description);
    }

    //
    // Add to list (with duplicate and quota check under lock)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Schema->TaskLock);

    if (Schema->TaskCount >= ES_MAX_TASKS) {
        ExReleasePushLockExclusive(&Schema->TaskLock);
        KeLeaveCriticalRegion();
        ShadowStrikeFreePoolWithTag(task, ES_POOL_TAG);
        return STATUS_QUOTA_EXCEEDED;
    }

    {
        PLIST_ENTRY dup;
        for (dup = Schema->Tasks.Flink;
             dup != &Schema->Tasks;
             dup = dup->Flink) {

            PES_TASK_DEFINITION existing = CONTAINING_RECORD(
                dup, ES_TASK_DEFINITION, ListEntry
            );

            if (_stricmp(existing->Name, task->Name) == 0) {
                ExReleasePushLockExclusive(&Schema->TaskLock);
                KeLeaveCriticalRegion();
                ShadowStrikeFreePoolWithTag(task, ES_POOL_TAG);
                return STATUS_OBJECT_NAME_COLLISION;
            }
        }
    }

    InsertTailList(&Schema->Tasks, &task->ListEntry);
    Schema->TaskCount++;

    ExReleasePushLockExclusive(&Schema->TaskLock);
    KeLeaveCriticalRegion();

    EspInvalidateCachedManifest(Schema);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
EsRegisterOpcode(
    _In_ PES_SCHEMA Schema,
    _In_ PCSTR Name,
    _In_ UCHAR Value,
    _In_ UCHAR TaskValue,
    _In_opt_ PCSTR Description
)
{
    PES_OPCODE_DEFINITION opcode;
    NTSTATUS status;

    PAGED_CODE();

    if (!EsIsValidSchema(Schema)) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (Name == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    //
    // Allocate opcode definition
    //
    opcode = (PES_OPCODE_DEFINITION)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(ES_OPCODE_DEFINITION),
        ES_POOL_TAG
    );

    if (opcode == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(opcode, sizeof(ES_OPCODE_DEFINITION));

    //
    // Copy name
    //
    status = RtlStringCchCopyA(opcode->Name, ES_MAX_OPCODE_NAME, Name);
    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(opcode, ES_POOL_TAG);
        return status;
    }

    opcode->Value = Value;
    opcode->TaskValue = TaskValue;

    if (Description != NULL) {
        RtlStringCchCopyA(opcode->Description, ES_MAX_DESCRIPTION, Description);
    }

    //
    // Add to list (with duplicate and quota check under lock)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Schema->OpcodeLock);

    if (Schema->OpcodeCount >= ES_MAX_OPCODES) {
        ExReleasePushLockExclusive(&Schema->OpcodeLock);
        KeLeaveCriticalRegion();
        ShadowStrikeFreePoolWithTag(opcode, ES_POOL_TAG);
        return STATUS_QUOTA_EXCEEDED;
    }

    {
        PLIST_ENTRY dup;
        for (dup = Schema->Opcodes.Flink;
             dup != &Schema->Opcodes;
             dup = dup->Flink) {

            PES_OPCODE_DEFINITION existing = CONTAINING_RECORD(
                dup, ES_OPCODE_DEFINITION, ListEntry
            );

            if (_stricmp(existing->Name, opcode->Name) == 0) {
                ExReleasePushLockExclusive(&Schema->OpcodeLock);
                KeLeaveCriticalRegion();
                ShadowStrikeFreePoolWithTag(opcode, ES_POOL_TAG);
                return STATUS_OBJECT_NAME_COLLISION;
            }
        }
    }

    InsertTailList(&Schema->Opcodes, &opcode->ListEntry);
    Schema->OpcodeCount++;

    ExReleasePushLockExclusive(&Schema->OpcodeLock);
    KeLeaveCriticalRegion();

    EspInvalidateCachedManifest(Schema);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
EsRegisterChannel(
    _In_ PES_SCHEMA Schema,
    _In_ PCSTR Name,
    _In_ ES_CHANNEL_TYPE Type,
    _In_ UCHAR Value,
    _In_ BOOLEAN Enabled,
    _In_opt_ PCSTR Description
)
{
    PES_CHANNEL_DEFINITION channel;
    NTSTATUS status;

    PAGED_CODE();

    if (!EsIsValidSchema(Schema)) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (Name == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (Type >= EsChannel_Max) {
        return STATUS_INVALID_PARAMETER_3;
    }

    //
    // Allocate channel definition
    //
    channel = (PES_CHANNEL_DEFINITION)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(ES_CHANNEL_DEFINITION),
        ES_POOL_TAG
    );

    if (channel == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(channel, sizeof(ES_CHANNEL_DEFINITION));

    //
    // Copy name
    //
    status = RtlStringCchCopyA(channel->Name, ES_MAX_CHANNEL_NAME, Name);
    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(channel, ES_POOL_TAG);
        return status;
    }

    channel->Type = Type;
    channel->Value = Value;
    channel->Enabled = Enabled;

    if (Description != NULL) {
        RtlStringCchCopyA(channel->Description, ES_MAX_DESCRIPTION, Description);
    }

    //
    // Add to list (with duplicate and quota check under lock)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Schema->ChannelLock);

    if (Schema->ChannelCount >= ES_MAX_CHANNELS) {
        ExReleasePushLockExclusive(&Schema->ChannelLock);
        KeLeaveCriticalRegion();
        ShadowStrikeFreePoolWithTag(channel, ES_POOL_TAG);
        return STATUS_QUOTA_EXCEEDED;
    }

    {
        PLIST_ENTRY dup;
        for (dup = Schema->Channels.Flink;
             dup != &Schema->Channels;
             dup = dup->Flink) {

            PES_CHANNEL_DEFINITION existing = CONTAINING_RECORD(
                dup, ES_CHANNEL_DEFINITION, ListEntry
            );

            if (_stricmp(existing->Name, channel->Name) == 0) {
                ExReleasePushLockExclusive(&Schema->ChannelLock);
                KeLeaveCriticalRegion();
                ShadowStrikeFreePoolWithTag(channel, ES_POOL_TAG);
                return STATUS_OBJECT_NAME_COLLISION;
            }
        }
    }

    InsertTailList(&Schema->Channels, &channel->ListEntry);
    Schema->ChannelCount++;

    ExReleasePushLockExclusive(&Schema->ChannelLock);
    KeLeaveCriticalRegion();

    EspInvalidateCachedManifest(Schema);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
EsRegisterValueMap(
    _In_ PES_SCHEMA Schema,
    _In_ PCSTR MapName
)
{
    PES_VALUE_MAP valueMap;
    NTSTATUS status;

    PAGED_CODE();

    if (!EsIsValidSchema(Schema)) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (MapName == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    //
    // Allocate value map
    //
    valueMap = (PES_VALUE_MAP)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(ES_VALUE_MAP),
        ES_POOL_TAG
    );

    if (valueMap == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(valueMap, sizeof(ES_VALUE_MAP));

    //
    // Copy name
    //
    status = RtlStringCchCopyA(valueMap->Name, ES_MAX_FIELD_NAME, MapName);
    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(valueMap, ES_POOL_TAG);
        return status;
    }

    InitializeListHead(&valueMap->Entries);
    ExInitializePushLock(&valueMap->Lock);

    //
    // Add to list (with duplicate and quota check under lock)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Schema->ValueMapLock);

    if (Schema->ValueMapCount >= ES_MAX_VALUE_MAPS) {
        ExReleasePushLockExclusive(&Schema->ValueMapLock);
        KeLeaveCriticalRegion();
        ShadowStrikeFreePoolWithTag(valueMap, ES_POOL_TAG);
        return STATUS_QUOTA_EXCEEDED;
    }

    {
        PLIST_ENTRY dup;
        for (dup = Schema->ValueMaps.Flink;
             dup != &Schema->ValueMaps;
             dup = dup->Flink) {

            PES_VALUE_MAP existing = CONTAINING_RECORD(
                dup, ES_VALUE_MAP, ListEntry
            );

            if (_stricmp(existing->Name, valueMap->Name) == 0) {
                ExReleasePushLockExclusive(&Schema->ValueMapLock);
                KeLeaveCriticalRegion();
                ShadowStrikeFreePoolWithTag(valueMap, ES_POOL_TAG);
                return STATUS_OBJECT_NAME_COLLISION;
            }
        }
    }

    InsertTailList(&Schema->ValueMaps, &valueMap->ListEntry);
    Schema->ValueMapCount++;

    ExReleasePushLockExclusive(&Schema->ValueMapLock);
    KeLeaveCriticalRegion();

    EspInvalidateCachedManifest(Schema);

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
EsAddValueMapEntry(
    _In_ PES_SCHEMA Schema,
    _In_ PCSTR MapName,
    _In_ ULONG Value,
    _In_ PCSTR DisplayName
)
{
    PES_VALUE_MAP valueMap = NULL;
    PES_VALUE_MAP_ENTRY entry;
    PLIST_ENTRY listEntry;
    NTSTATUS status;

    PAGED_CODE();

    if (!EsIsValidSchema(Schema)) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (MapName == NULL || DisplayName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Pre-allocate entry before taking locks
    //
    entry = (PES_VALUE_MAP_ENTRY)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(ES_VALUE_MAP_ENTRY),
        ES_POOL_TAG
    );

    if (entry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(entry, sizeof(ES_VALUE_MAP_ENTRY));

    entry->Value = Value;

    status = RtlStringCchCopyA(entry->DisplayName, ES_MAX_FIELD_NAME, DisplayName);
    if (!NT_SUCCESS(status)) {
        ShadowStrikeFreePoolWithTag(entry, ES_POOL_TAG);
        return status;
    }

    //
    // Hold ValueMapLock while accessing the per-map lock (correct lock ordering:
    // ValueMapLock level 1 → per-object Lock subordinate)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Schema->ValueMapLock);

    for (listEntry = Schema->ValueMaps.Flink;
         listEntry != &Schema->ValueMaps;
         listEntry = listEntry->Flink) {

        PES_VALUE_MAP candidate = CONTAINING_RECORD(
            listEntry, ES_VALUE_MAP, ListEntry
        );

        if (_stricmp(candidate->Name, MapName) == 0) {
            valueMap = candidate;
            break;
        }
    }

    if (valueMap == NULL) {
        ExReleasePushLockShared(&Schema->ValueMapLock);
        KeLeaveCriticalRegion();
        ShadowStrikeFreePoolWithTag(entry, ES_POOL_TAG);
        return STATUS_NOT_FOUND;
    }

    //
    // Check entry count limit
    //
    if (valueMap->EntryCount >= ES_MAX_VALUE_MAP_ENTRIES) {
        ExReleasePushLockShared(&Schema->ValueMapLock);
        KeLeaveCriticalRegion();
        ShadowStrikeFreePoolWithTag(entry, ES_POOL_TAG);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Acquire per-map lock while ValueMapLock is still held
    //
    ExAcquirePushLockExclusive(&valueMap->Lock);

    InsertTailList(&valueMap->Entries, &entry->ListEntry);
    valueMap->EntryCount++;

    ExReleasePushLockExclusive(&valueMap->Lock);
    ExReleasePushLockShared(&Schema->ValueMapLock);
    KeLeaveCriticalRegion();

    EspInvalidateCachedManifest(Schema);

    return STATUS_SUCCESS;
}

// ============================================================================
// MANIFEST GENERATION
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EsGenerateManifestXml(
    _In_ PES_SCHEMA Schema,
    _Outptr_ PCHAR* ManifestXml,
    _Out_ PSIZE_T XmlSize
)
{
    ES_MANIFEST_OPTIONS options;

    PAGED_CODE();

    RtlZeroMemory(&options, sizeof(options));
    options.IncludeTemplates = TRUE;
    options.IncludeMessages = TRUE;
    options.IncludeValueMaps = TRUE;
    options.IncludeStringTable = FALSE;
    options.GenerateHeader = FALSE;
    options.ResourceFileName = NULL;
    options.MessageFileName = NULL;
    options.Culture = 0x0409;  // en-US

    return EsGenerateManifestXmlEx(Schema, &options, ManifestXml, XmlSize);
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EsGenerateManifestXmlEx(
    _In_ PES_SCHEMA Schema,
    _In_ PES_MANIFEST_OPTIONS Options,
    _Outptr_ PCHAR* ManifestXml,
    _Out_ PSIZE_T XmlSize
)
{
    NTSTATUS status = STATUS_SUCCESS;
    ES_XML_CONTEXT xmlContext;
    CHAR guidString[40];

    PAGED_CODE();

    if (ManifestXml == NULL || XmlSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ManifestXml = NULL;
    *XmlSize = 0;

    if (!EsIsValidSchema(Schema)) {
        return STATUS_INVALID_PARAMETER_1;
    }

    if (Options == NULL) {
        return STATUS_INVALID_PARAMETER_2;
    }

    //
    // Check for cached manifest
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Schema->ManifestLock);

    if (Schema->CachedManifest != NULL && !Schema->ManifestDirty) {
        //
        // Return cached copy
        //
        PCHAR cachedCopy = (PCHAR)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            Schema->CachedManifestSize + 1,
            ES_MANIFEST_TAG
        );

        if (cachedCopy != NULL) {
            RtlCopyMemory(cachedCopy, Schema->CachedManifest, Schema->CachedManifestSize);
            cachedCopy[Schema->CachedManifestSize] = '\0';
            *ManifestXml = cachedCopy;
            *XmlSize = Schema->CachedManifestSize;

            ExReleasePushLockShared(&Schema->ManifestLock);
            KeLeaveCriticalRegion();

            return STATUS_SUCCESS;
        }
    }

    ExReleasePushLockShared(&Schema->ManifestLock);
    KeLeaveCriticalRegion();

    //
    // Initialize XML context
    //
    status = EspXmlInitContext(&xmlContext, ES_XML_BUFFER_INCREMENT * 4);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Generate XML header
    //
    EspXmlAppend(&xmlContext, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n");

    //
    // Open instrumentation manifest
    //
    EspXmlAppend(&xmlContext,
        "<instrumentationManifest\r\n"
        "    xmlns=\"http://schemas.microsoft.com/win/2004/08/events\"\r\n"
        "    xmlns:win=\"http://manifests.microsoft.com/win/2004/08/windows/events\"\r\n"
        "    xmlns:xs=\"http://www.w3.org/2001/XMLSchema\">\r\n"
    );

    xmlContext.IndentLevel = 1;

    //
    // Open instrumentation
    //
    EspXmlAppendIndent(&xmlContext);
    EspXmlAppend(&xmlContext, "<instrumentation>\r\n");
    xmlContext.IndentLevel++;

    //
    // Open events
    //
    EspXmlAppendIndent(&xmlContext);
    EspXmlAppend(&xmlContext, "<events>\r\n");
    xmlContext.IndentLevel++;

    //
    // Generate provider element
    //
    EspGuidToString(&Schema->ProviderId, guidString);

    {
        CHAR escapedProvName[ES_MAX_PROVIDER_NAME * 6];
        CHAR escapedProvSymbol[ES_MAX_PROVIDER_NAME * 6];
        EspXmlEscapeString(escapedProvName, sizeof(escapedProvName), Schema->ProviderName);
        EspXmlEscapeString(escapedProvSymbol, sizeof(escapedProvSymbol), Schema->ProviderSymbol);

        EspXmlAppendIndent(&xmlContext);
        EspXmlAppend(&xmlContext,
            "<provider name=\"%s\"\r\n",
            escapedProvName
        );

        xmlContext.IndentLevel += 2;
        EspXmlAppendIndent(&xmlContext);
        EspXmlAppend(&xmlContext,
            "guid=\"{%s}\"\r\n",
            guidString
        );
        EspXmlAppendIndent(&xmlContext);
        EspXmlAppend(&xmlContext,
            "symbol=\"%s\"\r\n",
            escapedProvSymbol
        );
    }
    EspXmlAppendIndent(&xmlContext);

    if (Options->ResourceFileName != NULL) {
        EspXmlAppend(&xmlContext,
            "resourceFileName=\"%s\"\r\n",
            Options->ResourceFileName
        );
        EspXmlAppendIndent(&xmlContext);
    }

    if (Options->MessageFileName != NULL) {
        EspXmlAppend(&xmlContext,
            "messageFileName=\"%s\"\r\n",
            Options->MessageFileName
        );
        EspXmlAppendIndent(&xmlContext);
    }

    EspXmlAppend(&xmlContext, ">\r\n");
    xmlContext.IndentLevel--;

    //
    // Generate channels
    //
    status = EspGenerateChannelsElement(Schema, &xmlContext);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Generate keywords
    //
    status = EspGenerateKeywordsElement(Schema, &xmlContext);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Generate tasks
    //
    status = EspGenerateTasksElement(Schema, &xmlContext);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Generate value maps if requested
    //
    if (Options->IncludeValueMaps) {
        status = EspGenerateMapsElement(Schema, &xmlContext);
        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }
    }

    //
    // Generate templates if requested
    //
    if (Options->IncludeTemplates) {
        status = EspGenerateTemplatesElement(Schema, &xmlContext);
        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }
    }

    //
    // Generate events
    //
    status = EspGenerateEventsElement(Schema, &xmlContext, Options);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    //
    // Close provider
    //
    xmlContext.IndentLevel--;
    EspXmlAppendIndent(&xmlContext);
    EspXmlAppend(&xmlContext, "</provider>\r\n");

    //
    // Close events
    //
    xmlContext.IndentLevel--;
    EspXmlAppendIndent(&xmlContext);
    EspXmlAppend(&xmlContext, "</events>\r\n");

    //
    // Close instrumentation
    //
    xmlContext.IndentLevel--;
    EspXmlAppendIndent(&xmlContext);
    EspXmlAppend(&xmlContext, "</instrumentation>\r\n");

    //
    // Close manifest
    //
    EspXmlAppend(&xmlContext, "</instrumentationManifest>\r\n");

    //
    // Check for errors during generation
    //
    if (xmlContext.Error) {
        status = xmlContext.ErrorStatus;
        goto Cleanup;
    }

    //
    // Allocate output buffer
    //
    *ManifestXml = (PCHAR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        xmlContext.CurrentPos + 1,
        ES_MANIFEST_TAG
    );

    if (*ManifestXml == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlCopyMemory(*ManifestXml, xmlContext.Buffer, xmlContext.CurrentPos);
    (*ManifestXml)[xmlContext.CurrentPos] = '\0';
    *XmlSize = xmlContext.CurrentPos;

    //
    // Cache the manifest
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Schema->ManifestLock);

    if (Schema->CachedManifest != NULL) {
        ShadowStrikeFreePoolWithTag(Schema->CachedManifest, ES_MANIFEST_TAG);
    }

    Schema->CachedManifest = (PCHAR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        xmlContext.CurrentPos + 1,
        ES_MANIFEST_TAG
    );

    if (Schema->CachedManifest != NULL) {
        RtlCopyMemory(Schema->CachedManifest, xmlContext.Buffer, xmlContext.CurrentPos);
        Schema->CachedManifest[xmlContext.CurrentPos] = '\0';
        Schema->CachedManifestSize = xmlContext.CurrentPos;
        Schema->ManifestDirty = FALSE;
    }

    ExReleasePushLockExclusive(&Schema->ManifestLock);
    KeLeaveCriticalRegion();

    //
    // Update statistics
    //
    InterlockedIncrement64(&Schema->Stats.ManifestGenerations);

Cleanup:
    EspXmlFreeContext(&xmlContext);

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EsFreeManifest(
    _In_ PCHAR ManifestXml
)
{
    if (ManifestXml != NULL) {
        ShadowStrikeFreePoolWithTag(ManifestXml, ES_MANIFEST_TAG);
    }
}

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
EsGetCachedManifest(
    _In_ PES_SCHEMA Schema,
    _Outptr_ PCHAR* ManifestXml,
    _Out_ PSIZE_T XmlSize
)
{
    PCHAR cachedCopy;

    if (ManifestXml == NULL || XmlSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ManifestXml = NULL;
    *XmlSize = 0;

    if (!EsIsValidSchema(Schema)) {
        return STATUS_INVALID_PARAMETER_1;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Schema->ManifestLock);

    if (Schema->CachedManifest == NULL || Schema->ManifestDirty) {
        ExReleasePushLockShared(&Schema->ManifestLock);
        KeLeaveCriticalRegion();
        return STATUS_NOT_FOUND;
    }

    //
    // Return a COPY so the caller does not hold a pointer to internal state
    //
    cachedCopy = (PCHAR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        Schema->CachedManifestSize + 1,
        ES_MANIFEST_TAG
    );

    if (cachedCopy == NULL) {
        ExReleasePushLockShared(&Schema->ManifestLock);
        KeLeaveCriticalRegion();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(cachedCopy, Schema->CachedManifest, Schema->CachedManifestSize);
    cachedCopy[Schema->CachedManifestSize] = '\0';
    *ManifestXml = cachedCopy;
    *XmlSize = Schema->CachedManifestSize;

    ExReleasePushLockShared(&Schema->ManifestLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

// ============================================================================
// SCHEMA SERIALIZATION
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EsSerializeSchema(
    _In_ PES_SCHEMA Schema,
    _Outptr_ PVOID* Buffer,
    _Out_ PSIZE_T BufferSize
)
{
    SIZE_T totalSize;
    PUCHAR buffer = NULL;
    PUCHAR currentPos;
    PES_BINARY_HEADER header;
    PLIST_ENTRY entry;

    PAGED_CODE();

    if (Buffer == NULL || BufferSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Buffer = NULL;
    *BufferSize = 0;

    if (!EsIsValidSchema(Schema)) {
        return STATUS_INVALID_PARAMETER_1;
    }

    //
    // Calculate total size using SERIALIZED (wire-format) structures only —
    // these exclude LIST_ENTRY, Magic, ReferenceCount, AllocatedFromPool
    // to prevent kernel pointer leakage.
    //
    totalSize = sizeof(ES_BINARY_HEADER);
    totalSize += Schema->EventCount * sizeof(ES_SERIALIZED_EVENT_DEFINITION);
    totalSize += Schema->KeywordCount * sizeof(ES_SERIALIZED_KEYWORD_DEFINITION);
    totalSize += Schema->TaskCount * sizeof(ES_SERIALIZED_TASK_DEFINITION);
    totalSize += Schema->OpcodeCount * sizeof(ES_SERIALIZED_OPCODE_DEFINITION);
    totalSize += Schema->ChannelCount * sizeof(ES_SERIALIZED_CHANNEL_DEFINITION);

    //
    // Check size limit
    //
    if (totalSize > ES_MAX_BINARY_SCHEMA_SIZE) {
        return STATUS_BUFFER_OVERFLOW;
    }

    //
    // Allocate buffer
    //
    buffer = (PUCHAR)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        totalSize,
        ES_POOL_TAG
    );

    if (buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(buffer, totalSize);
    currentPos = buffer;

    //
    // Write header
    //
    header = (PES_BINARY_HEADER)currentPos;
    header->Magic = ES_BINARY_HEADER_MAGIC;
    header->MajorVersion = Schema->MajorVersion;
    header->MinorVersion = Schema->MinorVersion;
    header->EventCount = Schema->EventCount;
    header->KeywordCount = Schema->KeywordCount;
    header->TaskCount = Schema->TaskCount;
    header->OpcodeCount = Schema->OpcodeCount;
    header->ChannelCount = Schema->ChannelCount;

    //
    // NOTE: ValueMapCount is stored in the header for informational purposes only.
    // Value map data is NOT serialized — value maps contain runtime-only structures
    // (LIST_ENTRY, EX_PUSH_LOCK) and must be rebuilt by the caller after deserialization.
    //
    header->ValueMapCount = Schema->ValueMapCount;
    header->TotalSize = (ULONG)totalSize;
    RtlCopyMemory(&header->ProviderId, &Schema->ProviderId, sizeof(GUID));
    RtlStringCchCopyA(header->ProviderName, ES_MAX_PROVIDER_NAME, Schema->ProviderName);

    currentPos += sizeof(ES_BINARY_HEADER);

    //
    // Serialize events — copy only public fields via ES_SERIALIZED_EVENT_DEFINITION
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Schema->EventLock);

    for (entry = Schema->EventList.Flink;
         entry != &Schema->EventList;
         entry = entry->Flink) {

        PES_EVENT_DEFINITION event = CONTAINING_RECORD(
            entry, ES_EVENT_DEFINITION, OrderedEntry
        );

        if (currentPos + sizeof(ES_SERIALIZED_EVENT_DEFINITION) <= buffer + totalSize) {
            PES_SERIALIZED_EVENT_DEFINITION ser = (PES_SERIALIZED_EVENT_DEFINITION)currentPos;

            ser->EventId = event->EventId;
            ser->Version = event->Version;
            ser->Channel = event->Channel;
            ser->Level = event->Level;
            ser->Opcode = event->Opcode;
            RtlZeroMemory(ser->Reserved, sizeof(ser->Reserved));
            ser->Task = event->Task;
            ser->Flags = event->Flags;
            ser->Keywords = event->Keywords;
            RtlCopyMemory(ser->EventName, event->EventName, sizeof(ser->EventName));
            RtlCopyMemory(ser->Description, event->Description, sizeof(ser->Description));
            RtlCopyMemory(ser->ChannelName, event->ChannelName, sizeof(ser->ChannelName));
            RtlCopyMemory(ser->TaskName, event->TaskName, sizeof(ser->TaskName));
            RtlCopyMemory(ser->OpcodeName, event->OpcodeName, sizeof(ser->OpcodeName));
            RtlCopyMemory(ser->TemplateName, event->TemplateName, sizeof(ser->TemplateName));
            RtlCopyMemory(ser->Message, event->Message, sizeof(ser->Message));
            RtlCopyMemory(ser->Fields, event->Fields,
                event->FieldCount * sizeof(ES_FIELD_DEFINITION));
            ser->FieldCount = event->FieldCount;
            ser->MinDataSize = event->MinDataSize;
            ser->MaxDataSize = event->MaxDataSize;
            ser->NameHash = event->NameHash;

            currentPos += sizeof(ES_SERIALIZED_EVENT_DEFINITION);
        }
    }

    ExReleasePushLockShared(&Schema->EventLock);
    KeLeaveCriticalRegion();

    //
    // Serialize keywords — exclude LIST_ENTRY
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Schema->KeywordLock);

    for (entry = Schema->Keywords.Flink;
         entry != &Schema->Keywords;
         entry = entry->Flink) {

        PES_KEYWORD_DEFINITION keyword = CONTAINING_RECORD(
            entry, ES_KEYWORD_DEFINITION, ListEntry
        );

        if (currentPos + sizeof(ES_SERIALIZED_KEYWORD_DEFINITION) <= buffer + totalSize) {
            PES_SERIALIZED_KEYWORD_DEFINITION ser = (PES_SERIALIZED_KEYWORD_DEFINITION)currentPos;
            RtlCopyMemory(ser->Name, keyword->Name, sizeof(ser->Name));
            ser->Mask = keyword->Mask;
            RtlCopyMemory(ser->Description, keyword->Description, sizeof(ser->Description));
            currentPos += sizeof(ES_SERIALIZED_KEYWORD_DEFINITION);
        }
    }

    ExReleasePushLockShared(&Schema->KeywordLock);
    KeLeaveCriticalRegion();

    //
    // Serialize tasks — exclude LIST_ENTRY
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Schema->TaskLock);

    for (entry = Schema->Tasks.Flink;
         entry != &Schema->Tasks;
         entry = entry->Flink) {

        PES_TASK_DEFINITION task = CONTAINING_RECORD(
            entry, ES_TASK_DEFINITION, ListEntry
        );

        if (currentPos + sizeof(ES_SERIALIZED_TASK_DEFINITION) <= buffer + totalSize) {
            PES_SERIALIZED_TASK_DEFINITION ser = (PES_SERIALIZED_TASK_DEFINITION)currentPos;
            RtlCopyMemory(ser->Name, task->Name, sizeof(ser->Name));
            ser->Value = task->Value;
            ser->Reserved = 0;
            RtlCopyMemory(ser->Description, task->Description, sizeof(ser->Description));
            currentPos += sizeof(ES_SERIALIZED_TASK_DEFINITION);
        }
    }

    ExReleasePushLockShared(&Schema->TaskLock);
    KeLeaveCriticalRegion();

    //
    // Serialize opcodes — exclude LIST_ENTRY
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Schema->OpcodeLock);

    for (entry = Schema->Opcodes.Flink;
         entry != &Schema->Opcodes;
         entry = entry->Flink) {

        PES_OPCODE_DEFINITION opcode = CONTAINING_RECORD(
            entry, ES_OPCODE_DEFINITION, ListEntry
        );

        if (currentPos + sizeof(ES_SERIALIZED_OPCODE_DEFINITION) <= buffer + totalSize) {
            PES_SERIALIZED_OPCODE_DEFINITION ser = (PES_SERIALIZED_OPCODE_DEFINITION)currentPos;
            RtlCopyMemory(ser->Name, opcode->Name, sizeof(ser->Name));
            ser->Value = opcode->Value;
            ser->TaskValue = opcode->TaskValue;
            ser->Reserved = 0;
            RtlCopyMemory(ser->Description, opcode->Description, sizeof(ser->Description));
            currentPos += sizeof(ES_SERIALIZED_OPCODE_DEFINITION);
        }
    }

    ExReleasePushLockShared(&Schema->OpcodeLock);
    KeLeaveCriticalRegion();

    //
    // Serialize channels — exclude LIST_ENTRY
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Schema->ChannelLock);

    for (entry = Schema->Channels.Flink;
         entry != &Schema->Channels;
         entry = entry->Flink) {

        PES_CHANNEL_DEFINITION channel = CONTAINING_RECORD(
            entry, ES_CHANNEL_DEFINITION, ListEntry
        );

        if (currentPos + sizeof(ES_SERIALIZED_CHANNEL_DEFINITION) <= buffer + totalSize) {
            PES_SERIALIZED_CHANNEL_DEFINITION ser = (PES_SERIALIZED_CHANNEL_DEFINITION)currentPos;
            RtlCopyMemory(ser->Name, channel->Name, sizeof(ser->Name));
            ser->Type = channel->Type;
            ser->Value = channel->Value;
            ser->Enabled = channel->Enabled;
            ser->Reserved = 0;
            RtlCopyMemory(ser->Description, channel->Description, sizeof(ser->Description));
            currentPos += sizeof(ES_SERIALIZED_CHANNEL_DEFINITION);
        }
    }

    ExReleasePushLockShared(&Schema->ChannelLock);
    KeLeaveCriticalRegion();

    *Buffer = buffer;
    *BufferSize = totalSize;

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
EsDeserializeSchema(
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Outptr_ PES_SCHEMA* Schema
)
{
    NTSTATUS status;
    PES_BINARY_HEADER header;
    PUCHAR currentPos;
    PES_SCHEMA schema = NULL;
    ULONG i;
    SIZE_T expectedSize;
    ULONG errorCount = 0;

    PAGED_CODE();

    if (Buffer == NULL || Schema == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Schema = NULL;

    //
    // Validate minimum size
    //
    if (BufferSize < sizeof(ES_BINARY_HEADER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Validate header
    //
    header = (PES_BINARY_HEADER)Buffer;

    if (header->Magic != ES_BINARY_HEADER_MAGIC) {
        return STATUS_INVALID_SIGNATURE;
    }

    if (header->TotalSize > BufferSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Cross-validate header counts against buffer size
    //
    expectedSize = sizeof(ES_BINARY_HEADER);
    expectedSize += (SIZE_T)header->EventCount * sizeof(ES_SERIALIZED_EVENT_DEFINITION);
    expectedSize += (SIZE_T)header->KeywordCount * sizeof(ES_SERIALIZED_KEYWORD_DEFINITION);
    expectedSize += (SIZE_T)header->TaskCount * sizeof(ES_SERIALIZED_TASK_DEFINITION);
    expectedSize += (SIZE_T)header->OpcodeCount * sizeof(ES_SERIALIZED_OPCODE_DEFINITION);
    expectedSize += (SIZE_T)header->ChannelCount * sizeof(ES_SERIALIZED_CHANNEL_DEFINITION);

    if (expectedSize > BufferSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Force null-termination on provider name before use
    //
    header->ProviderName[ES_MAX_PROVIDER_NAME - 1] = '\0';

    //
    // Initialize schema
    //
    status = EsInitialize(&schema, &header->ProviderId, header->ProviderName);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    schema->MajorVersion = header->MajorVersion;
    schema->MinorVersion = header->MinorVersion;

    currentPos = (PUCHAR)Buffer + sizeof(ES_BINARY_HEADER);

    //
    // Deserialize events from wire-format structs
    // NOTE: ES_EVENT_DEFINITION is ~30KB — must be pool-allocated, not stack.
    //
    if (header->EventCount > 0) {
        PES_EVENT_DEFINITION eventDef = (PES_EVENT_DEFINITION)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(ES_EVENT_DEFINITION),
            ES_EVENT_TAG
        );

        if (eventDef == NULL) {
            EsShutdown(&schema);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        for (i = 0; i < header->EventCount; i++) {
            PES_SERIALIZED_EVENT_DEFINITION ser;

            if (currentPos + sizeof(ES_SERIALIZED_EVENT_DEFINITION) > (PUCHAR)Buffer + BufferSize) {
                break;
            }

            ser = (PES_SERIALIZED_EVENT_DEFINITION)currentPos;

            //
            // Force null-termination on all string fields
            //
            ser->EventName[ES_MAX_EVENT_NAME - 1] = '\0';
            ser->Description[ES_MAX_DESCRIPTION - 1] = '\0';
            ser->ChannelName[ES_MAX_CHANNEL_NAME - 1] = '\0';
            ser->TaskName[ES_MAX_TASK_NAME - 1] = '\0';
            ser->OpcodeName[ES_MAX_OPCODE_NAME - 1] = '\0';
            ser->TemplateName[ES_MAX_EVENT_NAME - 1] = '\0';
            ser->Message[ES_MAX_DESCRIPTION - 1] = '\0';

            //
            // Validate field count
            //
            if (ser->FieldCount > ES_MAX_FIELDS_PER_EVENT) {
                errorCount++;
                currentPos += sizeof(ES_SERIALIZED_EVENT_DEFINITION);
                continue;
            }

            //
            // Build runtime struct from wire-format (never cast directly)
            //
            RtlZeroMemory(eventDef, sizeof(*eventDef));
            eventDef->EventId = ser->EventId;
            eventDef->Version = ser->Version;
            eventDef->Channel = ser->Channel;
            eventDef->Level = ser->Level;
            eventDef->Opcode = ser->Opcode;
            eventDef->Task = ser->Task;
            eventDef->Flags = ser->Flags;
            eventDef->Keywords = ser->Keywords;
            eventDef->FieldCount = ser->FieldCount;
            eventDef->MaxDataSize = ser->MaxDataSize;

            RtlCopyMemory(eventDef->EventName, ser->EventName, sizeof(eventDef->EventName));
            RtlCopyMemory(eventDef->Description, ser->Description, sizeof(eventDef->Description));
            RtlCopyMemory(eventDef->ChannelName, ser->ChannelName, sizeof(eventDef->ChannelName));
            RtlCopyMemory(eventDef->TaskName, ser->TaskName, sizeof(eventDef->TaskName));
            RtlCopyMemory(eventDef->OpcodeName, ser->OpcodeName, sizeof(eventDef->OpcodeName));
            RtlCopyMemory(eventDef->TemplateName, ser->TemplateName, sizeof(eventDef->TemplateName));
            RtlCopyMemory(eventDef->Message, ser->Message, sizeof(eventDef->Message));

            if (ser->FieldCount > 0) {
                RtlCopyMemory(eventDef->Fields, ser->Fields,
                    ser->FieldCount * sizeof(ES_FIELD_DEFINITION));

                for (ULONG f = 0; f < ser->FieldCount; f++) {
                    eventDef->Fields[f].FieldName[ES_MAX_FIELD_NAME - 1] = '\0';
                    eventDef->Fields[f].Description[ES_MAX_DESCRIPTION - 1] = '\0';
                }
            }

            status = EsRegisterEvent(schema, eventDef);
            if (!NT_SUCCESS(status)) {
                errorCount++;
            }

            currentPos += sizeof(ES_SERIALIZED_EVENT_DEFINITION);
        }

        ShadowStrikeFreePoolWithTag(eventDef, ES_EVENT_TAG);
    }

    //
    // Deserialize keywords from wire-format
    //
    for (i = 0; i < header->KeywordCount; i++) {
        PES_SERIALIZED_KEYWORD_DEFINITION ser;

        if (currentPos + sizeof(ES_SERIALIZED_KEYWORD_DEFINITION) > (PUCHAR)Buffer + BufferSize) {
            break;
        }

        ser = (PES_SERIALIZED_KEYWORD_DEFINITION)currentPos;
        ser->Name[ES_MAX_KEYWORD_NAME - 1] = '\0';
        ser->Description[ES_MAX_DESCRIPTION - 1] = '\0';

        status = EsRegisterKeyword(schema, ser->Name, ser->Mask, ser->Description);
        if (!NT_SUCCESS(status)) {
            errorCount++;
        }

        currentPos += sizeof(ES_SERIALIZED_KEYWORD_DEFINITION);
    }

    //
    // Deserialize tasks from wire-format
    //
    for (i = 0; i < header->TaskCount; i++) {
        PES_SERIALIZED_TASK_DEFINITION ser;

        if (currentPos + sizeof(ES_SERIALIZED_TASK_DEFINITION) > (PUCHAR)Buffer + BufferSize) {
            break;
        }

        ser = (PES_SERIALIZED_TASK_DEFINITION)currentPos;
        ser->Name[ES_MAX_TASK_NAME - 1] = '\0';
        ser->Description[ES_MAX_DESCRIPTION - 1] = '\0';

        status = EsRegisterTask(schema, ser->Name, ser->Value, ser->Description);
        if (!NT_SUCCESS(status)) {
            errorCount++;
        }

        currentPos += sizeof(ES_SERIALIZED_TASK_DEFINITION);
    }

    //
    // Deserialize opcodes from wire-format
    //
    for (i = 0; i < header->OpcodeCount; i++) {
        PES_SERIALIZED_OPCODE_DEFINITION ser;

        if (currentPos + sizeof(ES_SERIALIZED_OPCODE_DEFINITION) > (PUCHAR)Buffer + BufferSize) {
            break;
        }

        ser = (PES_SERIALIZED_OPCODE_DEFINITION)currentPos;
        ser->Name[ES_MAX_OPCODE_NAME - 1] = '\0';
        ser->Description[ES_MAX_DESCRIPTION - 1] = '\0';

        status = EsRegisterOpcode(schema, ser->Name, ser->Value,
            ser->TaskValue, ser->Description);
        if (!NT_SUCCESS(status)) {
            errorCount++;
        }

        currentPos += sizeof(ES_SERIALIZED_OPCODE_DEFINITION);
    }

    //
    // Deserialize channels from wire-format
    //
    for (i = 0; i < header->ChannelCount; i++) {
        PES_SERIALIZED_CHANNEL_DEFINITION ser;

        if (currentPos + sizeof(ES_SERIALIZED_CHANNEL_DEFINITION) > (PUCHAR)Buffer + BufferSize) {
            break;
        }

        ser = (PES_SERIALIZED_CHANNEL_DEFINITION)currentPos;
        ser->Name[ES_MAX_CHANNEL_NAME - 1] = '\0';
        ser->Description[ES_MAX_DESCRIPTION - 1] = '\0';

        if (ser->Type >= EsChannel_Max) {
            errorCount++;
            currentPos += sizeof(ES_SERIALIZED_CHANNEL_DEFINITION);
            continue;
        }

        status = EsRegisterChannel(schema, ser->Name, ser->Type,
            ser->Value, ser->Enabled, ser->Description);
        if (!NT_SUCCESS(status)) {
            errorCount++;
        }

        currentPos += sizeof(ES_SERIALIZED_CHANNEL_DEFINITION);
    }

    if (errorCount > 0 && schema->EventCount == 0) {
        EsShutdown(&schema);
        return STATUS_INVALID_PARAMETER;
    }

    *Schema = schema;

    return STATUS_SUCCESS;
}

// ============================================================================
// STATISTICS AND DIAGNOSTICS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EsGetStatistics(
    _In_ PES_SCHEMA Schema,
    _Out_ PES_STATISTICS Stats
)
{
    if (Stats == NULL) {
        return;
    }

    RtlZeroMemory(Stats, sizeof(ES_STATISTICS));

    if (!EsIsValidSchema(Schema)) {
        return;
    }

    //
    // Read each volatile counter atomically to prevent torn reads
    //
    Stats->EventsRegistered = InterlockedCompareExchange64(&Schema->Stats.EventsRegistered, 0, 0);
    Stats->EventsUnregistered = InterlockedCompareExchange64(&Schema->Stats.EventsUnregistered, 0, 0);
    Stats->LookupCount = InterlockedCompareExchange64(&Schema->Stats.LookupCount, 0, 0);
    Stats->LookupHits = InterlockedCompareExchange64(&Schema->Stats.LookupHits, 0, 0);
    Stats->LookupMisses = InterlockedCompareExchange64(&Schema->Stats.LookupMisses, 0, 0);
    Stats->ValidationCount = InterlockedCompareExchange64(&Schema->Stats.ValidationCount, 0, 0);
    Stats->ValidationFailures = InterlockedCompareExchange64(&Schema->Stats.ValidationFailures, 0, 0);
    Stats->ManifestGenerations = InterlockedCompareExchange64(&Schema->Stats.ManifestGenerations, 0, 0);
    Stats->CreateTime = Schema->Stats.CreateTime;
    Stats->LastModifiedTime = Schema->Stats.LastModifiedTime;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EsResetStatistics(
    _In_ PES_SCHEMA Schema
)
{
    if (!EsIsValidSchema(Schema)) {
        return;
    }

    InterlockedExchange64(&Schema->Stats.EventsRegistered, 0);
    InterlockedExchange64(&Schema->Stats.EventsUnregistered, 0);
    InterlockedExchange64(&Schema->Stats.LookupCount, 0);
    InterlockedExchange64(&Schema->Stats.LookupHits, 0);
    InterlockedExchange64(&Schema->Stats.LookupMisses, 0);
    InterlockedExchange64(&Schema->Stats.ValidationCount, 0);
    InterlockedExchange64(&Schema->Stats.ValidationFailures, 0);
    InterlockedExchange64(&Schema->Stats.ManifestGenerations, 0);

    KeQuerySystemTime(&Schema->Stats.LastModifiedTime);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG
EsGetEventCount(
    _In_ PES_SCHEMA Schema
)
{
    if (!EsIsValidSchema(Schema)) {
        return 0;
    }

    return (ULONG)Schema->EventCount;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
EsIsValidSchema(
    _In_opt_ PES_SCHEMA Schema
)
{
    if (Schema == NULL) {
        return FALSE;
    }

    if (Schema->Magic != ES_SCHEMA_MAGIC) {
        return FALSE;
    }

    if (!Schema->Initialized) {
        return FALSE;
    }

    return TRUE;
}

PCSTR
EsGetFieldTypeName(
    _In_ ES_FIELD_TYPE Type
)
{
    if (Type >= EsType_MAX) {
        return "Unknown";
    }

    return g_FieldTypeNames[Type];
}

ULONG
EsGetFieldTypeSize(
    _In_ ES_FIELD_TYPE Type
)
{
    if (Type >= EsType_MAX) {
        return 0;
    }

    return g_FieldTypeSizes[Type];
}

PCSTR
EsGetValidationResultName(
    _In_ ES_VALIDATION_RESULT Result
)
{
    if (Result >= EsValidation_Max) {
        return "Unknown";
    }

    return g_ValidationResultNames[Result];
}

// ============================================================================
// PRIVATE IMPLEMENTATION - HASH FUNCTIONS
// ============================================================================

static ULONG
EspHashEventId(
    _In_ USHORT EventId
)
{
    //
    // Simple hash for event ID distribution
    //
    ULONG hash = (ULONG)EventId;
    hash = hash ^ (hash >> 8);
    hash = hash * 0x9E3779B1;
    return hash % ES_EVENT_HASH_BUCKETS;
}

static ULONG
EspHashEventName(
    _In_ PCSTR EventName
)
{
    //
    // Case-insensitive DJB2 hash — normalize to lowercase to match
    // the case-insensitive _stricmp comparison in EsGetEventByName
    //
    ULONG hash = ES_HASH_SEED;

    if (EventName == NULL) {
        return hash;
    }

    while (*EventName != '\0') {
        UCHAR c = (UCHAR)*EventName;
        if (c >= 'A' && c <= 'Z') {
            c = c + ('a' - 'A');
        }
        hash = ((hash << 5) + hash) + c;
        EventName++;
    }

    return hash;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - EVENT ALLOCATION
// ============================================================================

static PES_EVENT_DEFINITION
EspAllocateEventDefinition(
    _In_ PES_SCHEMA Schema
)
{
    PES_EVENT_DEFINITION event = NULL;

    if (Schema->LookasideInitialized) {
        event = (PES_EVENT_DEFINITION)ExAllocateFromNPagedLookasideList(
            &Schema->EventLookaside
        );
    }

    if (event == NULL) {
        event = (PES_EVENT_DEFINITION)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(ES_EVENT_DEFINITION),
            ES_EVENT_TAG
        );

        if (event != NULL) {
            RtlZeroMemory(event, sizeof(ES_EVENT_DEFINITION));
            event->AllocatedFromPool = TRUE;
        }
    } else {
        RtlZeroMemory(event, sizeof(ES_EVENT_DEFINITION));
        event->AllocatedFromPool = FALSE;
    }

    return event;
}

static VOID
EspFreeEventDefinition(
    _In_ PES_SCHEMA Schema,
    _In_ PES_EVENT_DEFINITION Event
)
{
    if (Event == NULL) {
        return;
    }

    Event->Magic = 0;

    if (!Event->AllocatedFromPool && Schema->LookasideInitialized) {
        ExFreeToNPagedLookasideList(&Schema->EventLookaside, Event);
    } else {
        ShadowStrikeFreePoolWithTag(Event, ES_EVENT_TAG);
    }
}

static VOID
EspInsertEventIntoHash(
    _In_ PES_SCHEMA Schema,
    _In_ PES_EVENT_DEFINITION Event
)
{
    ULONG bucket = EspHashEventId(Event->EventId);
    InsertTailList(&Schema->EventHashBuckets[bucket], &Event->ListEntry);
}

static VOID
EspRemoveEventFromHash(
    _In_ PES_SCHEMA Schema,
    _In_ PES_EVENT_DEFINITION Event
)
{
    UNREFERENCED_PARAMETER(Schema);
    RemoveEntryList(&Event->ListEntry);
}

// ============================================================================
// PRIVATE IMPLEMENTATION - FIELD VALIDATION
// ============================================================================

static NTSTATUS
EspValidateFieldData(
    _In_ PCES_FIELD_DEFINITION Field,
    _In_reads_bytes_(DataSize) PVOID Data,
    _In_ SIZE_T DataSize,
    _Inout_ PES_VALIDATION_CONTEXT Context
)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (Data == NULL && !(Field->Flags & EsFieldFlag_Optional)) {
        Context->Result = EsValidation_InvalidPointer;
        RtlStringCchPrintfA(Context->ErrorMessage, sizeof(Context->ErrorMessage),
            "Required field '%s' has NULL data pointer", Field->FieldName);
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Type-specific validation
    //
    switch (Field->Type) {
        case EsType_ANSISTRING:
        case EsType_COUNTEDANSISTRING:
            //
            // Verify null termination within bounds
            //
            if (Data != NULL) {
                SIZE_T i;
                BOOLEAN terminated = FALSE;
                PCSTR str = (PCSTR)Data;

                for (i = 0; i < DataSize; i++) {
                    if (str[i] == '\0') {
                        terminated = TRUE;
                        break;
                    }
                }

                if (!terminated && !(Field->Flags & EsFieldFlag_VariableLength)) {
                    Context->Result = EsValidation_StringTooLong;
                    RtlStringCchPrintfA(Context->ErrorMessage, sizeof(Context->ErrorMessage),
                        "Field '%s' string not null-terminated", Field->FieldName);
                    return STATUS_INVALID_PARAMETER;
                }
            }
            break;

        case EsType_UNICODESTRING:
        case EsType_COUNTEDSTRING:
            //
            // Verify null termination within bounds
            //
            if (Data != NULL) {
                SIZE_T i;
                BOOLEAN terminated = FALSE;
                PCWSTR str = (PCWSTR)Data;
                SIZE_T charCount = DataSize / sizeof(WCHAR);

                for (i = 0; i < charCount; i++) {
                    if (str[i] == L'\0') {
                        terminated = TRUE;
                        break;
                    }
                }

                if (!terminated && !(Field->Flags & EsFieldFlag_VariableLength)) {
                    Context->Result = EsValidation_StringTooLong;
                    RtlStringCchPrintfA(Context->ErrorMessage, sizeof(Context->ErrorMessage),
                        "Field '%s' unicode string not null-terminated", Field->FieldName);
                    return STATUS_INVALID_PARAMETER;
                }
            }
            break;

        case EsType_POINTER:
            //
            // On 64-bit, verify alignment
            //
#ifdef _WIN64
            if (Data != NULL && ((ULONG_PTR)Data & (sizeof(PVOID) - 1)) != 0) {
                Context->Result = EsValidation_InvalidAlignment;
                RtlStringCchPrintfA(Context->ErrorMessage, sizeof(Context->ErrorMessage),
                    "Field '%s' pointer not properly aligned", Field->FieldName);
                return STATUS_DATATYPE_MISALIGNMENT;
            }
#endif
            break;

        case EsType_GUID:
            if (Field->Size > 0 && Field->Size != sizeof(GUID)) {
                Context->Result = EsValidation_SizeMismatch;
                RtlStringCchPrintfA(Context->ErrorMessage, sizeof(Context->ErrorMessage),
                    "Field '%s' GUID size mismatch (expected %zu, got %u)",
                    Field->FieldName, sizeof(GUID), Field->Size);
                return STATUS_INVALID_PARAMETER;
            }
            break;

        default:
            //
            // For fixed-size types, validate size matches
            //
            if (Field->Size > 0) {
                ULONG expectedSize = EsGetFieldTypeSize(Field->Type);
                if (expectedSize > 0 && Field->Size != expectedSize) {
                    Context->Result = EsValidation_SizeMismatch;
                    RtlStringCchPrintfA(Context->ErrorMessage, sizeof(Context->ErrorMessage),
                        "Field '%s' size mismatch (expected %u, got %u)",
                        Field->FieldName, expectedSize, Field->Size);
                    return STATUS_INVALID_PARAMETER;
                }
            }
            break;
    }

    return status;
}

// ============================================================================
// PRIVATE IMPLEMENTATION - XML BUILDER
// ============================================================================

static NTSTATUS
EspXmlInitContext(
    _Out_ PES_XML_CONTEXT Context,
    _In_ SIZE_T InitialSize
)
{
    RtlZeroMemory(Context, sizeof(ES_XML_CONTEXT));

    Context->Buffer = (PCHAR)ShadowStrikeAllocatePoolWithTag(
        PagedPool,
        InitialSize,
        ES_MANIFEST_TAG
    );

    if (Context->Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Context->BufferSize = InitialSize;
    Context->CurrentPos = 0;
    Context->IndentLevel = 0;
    Context->Error = FALSE;

    return STATUS_SUCCESS;
}

static VOID
EspXmlFreeContext(
    _Inout_ PES_XML_CONTEXT Context
)
{
    if (Context->Buffer != NULL) {
        ShadowStrikeFreePoolWithTag(Context->Buffer, ES_MANIFEST_TAG);
        Context->Buffer = NULL;
    }
    Context->BufferSize = 0;
    Context->CurrentPos = 0;
}

//
// EspXmlEscapeString - Escape XML special characters in a string
// Returns: number of characters written (excluding null terminator)
// If DestSize is 0, returns the required size (excluding null terminator)
//
static SIZE_T
EspXmlEscapeString(
    _Out_writes_opt_(DestSize) PCHAR Dest,
    _In_ SIZE_T DestSize,
    _In_ PCSTR Src
)
{
    SIZE_T needed = 0;
    SIZE_T pos = 0;

    if (Src == NULL) {
        if (Dest != NULL && DestSize > 0) {
            Dest[0] = '\0';
        }
        return 0;
    }

    while (*Src != '\0') {
        PCSTR replacement = NULL;
        SIZE_T repLen = 0;

        switch (*Src) {
        case '&':
            replacement = "&amp;";
            repLen = 5;
            break;
        case '<':
            replacement = "&lt;";
            repLen = 4;
            break;
        case '>':
            replacement = "&gt;";
            repLen = 4;
            break;
        case '"':
            replacement = "&quot;";
            repLen = 6;
            break;
        case '\'':
            replacement = "&apos;";
            repLen = 6;
            break;
        default:
            replacement = NULL;
            repLen = 1;
            break;
        }

        if (Dest != NULL && DestSize > 0) {
            if (pos + repLen < DestSize) {
                if (replacement != NULL) {
                    RtlCopyMemory(Dest + pos, replacement, repLen);
                } else {
                    Dest[pos] = *Src;
                }
            }
        }

        needed += repLen;
        pos += repLen;
        Src++;
    }

    if (Dest != NULL && DestSize > 0) {
        SIZE_T termPos = (pos < DestSize) ? pos : DestSize - 1;
        Dest[termPos] = '\0';
    }

    return needed;
}

//
// EspXmlAppendEscaped - Append XML-escaped string to context
//
static NTSTATUS
EspXmlAppendEscaped(
    _Inout_ PES_XML_CONTEXT Context,
    _In_ PCSTR Str
)
{
    CHAR escaped[1024];

    if (Str == NULL || *Str == '\0') {
        return STATUS_SUCCESS;
    }

    EspXmlEscapeString(escaped, sizeof(escaped), Str);
    return EspXmlAppend(Context, "%s", escaped);
}

static NTSTATUS
EspXmlAppend(
    _Inout_ PES_XML_CONTEXT Context,
    _In_ PCSTR Format,
    ...
)
{
    va_list args;
    va_list argsCopy;
    NTSTATUS status;
    SIZE_T remaining;
    SIZE_T written;

    if (Context->Error) {
        return Context->ErrorStatus;
    }

    va_start(args, Format);
    va_copy(argsCopy, args);

    //
    // Try to format into remaining buffer
    //
    remaining = Context->BufferSize - Context->CurrentPos;

    status = RtlStringCchVPrintfA(
        Context->Buffer + Context->CurrentPos,
        remaining,
        Format,
        args
    );

    if (status == STATUS_BUFFER_OVERFLOW) {
        //
        // Geometric growth: double the buffer size
        //
        SIZE_T newSize = Context->BufferSize * 2;
        PCHAR newBuffer;

        if (newSize < Context->BufferSize + ES_XML_BUFFER_INCREMENT) {
            newSize = Context->BufferSize + ES_XML_BUFFER_INCREMENT;
        }

        if (newSize > ES_MAX_MANIFEST_SIZE) {
            Context->Error = TRUE;
            Context->ErrorStatus = STATUS_BUFFER_OVERFLOW;
            va_end(argsCopy);
            va_end(args);
            return STATUS_BUFFER_OVERFLOW;
        }

        newBuffer = (PCHAR)ShadowStrikeAllocatePoolWithTag(
            PagedPool,
            newSize,
            ES_MANIFEST_TAG
        );

        if (newBuffer == NULL) {
            Context->Error = TRUE;
            Context->ErrorStatus = STATUS_INSUFFICIENT_RESOURCES;
            va_end(argsCopy);
            va_end(args);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(newBuffer, Context->Buffer, Context->CurrentPos);
        ShadowStrikeFreePoolWithTag(Context->Buffer, ES_MANIFEST_TAG);
        Context->Buffer = newBuffer;
        Context->BufferSize = newSize;

        //
        // Retry format with the saved va_list copy (original is consumed)
        //
        remaining = Context->BufferSize - Context->CurrentPos;
        status = RtlStringCchVPrintfA(
            Context->Buffer + Context->CurrentPos,
            remaining,
            Format,
            argsCopy
        );
    }

    va_end(argsCopy);
    va_end(args);

    if (!NT_SUCCESS(status)) {
        Context->Error = TRUE;
        Context->ErrorStatus = status;
        return status;
    }

    //
    // Update position
    //
    RtlStringCchLengthA(
        Context->Buffer + Context->CurrentPos,
        remaining,
        &written
    );
    Context->CurrentPos += written;

    return STATUS_SUCCESS;
}

static NTSTATUS
EspXmlAppendIndent(
    _Inout_ PES_XML_CONTEXT Context
)
{
    ULONG i;

    for (i = 0; i < Context->IndentLevel; i++) {
        NTSTATUS status = EspXmlAppend(Context, "    ");
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    return STATUS_SUCCESS;
}

static VOID
EspGuidToString(
    _In_ PCGUID Guid,
    _Out_writes_(37) PCHAR Buffer
)
{
    RtlStringCchPrintfA(
        Buffer,
        40,
        "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        Guid->Data1,
        Guid->Data2,
        Guid->Data3,
        Guid->Data4[0], Guid->Data4[1],
        Guid->Data4[2], Guid->Data4[3],
        Guid->Data4[4], Guid->Data4[5],
        Guid->Data4[6], Guid->Data4[7]
    );
}

static VOID
EspInvalidateCachedManifest(
    _Inout_ PES_SCHEMA Schema
)
{
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Schema->ManifestLock);

    Schema->ManifestDirty = TRUE;

    ExReleasePushLockExclusive(&Schema->ManifestLock);
    KeLeaveCriticalRegion();

    KeQuerySystemTime(&Schema->Stats.LastModifiedTime);
}

// ============================================================================
// PRIVATE IMPLEMENTATION - MANIFEST ELEMENT GENERATORS
// ============================================================================

static NTSTATUS
EspGenerateChannelsElement(
    _In_ PES_SCHEMA Schema,
    _Inout_ PES_XML_CONTEXT Context
)
{
    PLIST_ENTRY entry;
    NTSTATUS status = STATUS_SUCCESS;

    if (Schema->ChannelCount == 0) {
        return STATUS_SUCCESS;
    }

    EspXmlAppendIndent(Context);
    EspXmlAppend(Context, "<channels>\r\n");
    Context->IndentLevel++;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Schema->ChannelLock);

    for (entry = Schema->Channels.Flink;
         entry != &Schema->Channels;
         entry = entry->Flink) {

        PES_CHANNEL_DEFINITION channel = CONTAINING_RECORD(
            entry, ES_CHANNEL_DEFINITION, ListEntry
        );

        {
            CHAR escapedProvName[ES_MAX_PROVIDER_NAME * 6];
            CHAR escapedChanName[ES_MAX_CHANNEL_NAME * 6];
            EspXmlEscapeString(escapedProvName, sizeof(escapedProvName), Schema->ProviderName);
            EspXmlEscapeString(escapedChanName, sizeof(escapedChanName), channel->Name);

            EspXmlAppendIndent(Context);
            EspXmlAppend(Context,
                "<channel name=\"%s/%s\" chid=\"%s\" type=\"%s\" enabled=\"%s\" />\r\n",
                escapedProvName,
                escapedChanName,
                escapedChanName,
                (channel->Type < EsChannel_Max) ? g_ChannelTypeNames[channel->Type] : "Admin",
                channel->Enabled ? "true" : "false"
            );
        }
    }

    ExReleasePushLockShared(&Schema->ChannelLock);
    KeLeaveCriticalRegion();

    Context->IndentLevel--;
    EspXmlAppendIndent(Context);
    EspXmlAppend(Context, "</channels>\r\n");

    if (Context->Error) {
        return Context->ErrorStatus;
    }

    return status;
}

static NTSTATUS
EspGenerateKeywordsElement(
    _In_ PES_SCHEMA Schema,
    _Inout_ PES_XML_CONTEXT Context
)
{
    PLIST_ENTRY entry;
    NTSTATUS status = STATUS_SUCCESS;

    if (Schema->KeywordCount == 0) {
        return STATUS_SUCCESS;
    }

    EspXmlAppendIndent(Context);
    EspXmlAppend(Context, "<keywords>\r\n");
    Context->IndentLevel++;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Schema->KeywordLock);

    for (entry = Schema->Keywords.Flink;
         entry != &Schema->Keywords;
         entry = entry->Flink) {

        PES_KEYWORD_DEFINITION keyword = CONTAINING_RECORD(
            entry, ES_KEYWORD_DEFINITION, ListEntry
        );

        {
            CHAR escapedName[ES_MAX_KEYWORD_NAME * 6];
            EspXmlEscapeString(escapedName, sizeof(escapedName), keyword->Name);

            EspXmlAppendIndent(Context);
            EspXmlAppend(Context,
                "<keyword name=\"%s\" mask=\"0x%I64X\" />\r\n",
                escapedName,
                keyword->Mask
            );
        }
    }

    ExReleasePushLockShared(&Schema->KeywordLock);
    KeLeaveCriticalRegion();

    Context->IndentLevel--;
    EspXmlAppendIndent(Context);
    EspXmlAppend(Context, "</keywords>\r\n");

    if (Context->Error) {
        return Context->ErrorStatus;
    }

    return status;
}

static NTSTATUS
EspGenerateTasksElement(
    _In_ PES_SCHEMA Schema,
    _Inout_ PES_XML_CONTEXT Context
)
{
    PLIST_ENTRY entry;
    NTSTATUS status = STATUS_SUCCESS;

    if (Schema->TaskCount == 0) {
        return STATUS_SUCCESS;
    }

    EspXmlAppendIndent(Context);
    EspXmlAppend(Context, "<tasks>\r\n");
    Context->IndentLevel++;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Schema->TaskLock);

    for (entry = Schema->Tasks.Flink;
         entry != &Schema->Tasks;
         entry = entry->Flink) {

        PES_TASK_DEFINITION task = CONTAINING_RECORD(
            entry, ES_TASK_DEFINITION, ListEntry
        );

        {
            CHAR escapedName[ES_MAX_TASK_NAME * 6];
            EspXmlEscapeString(escapedName, sizeof(escapedName), task->Name);

            EspXmlAppendIndent(Context);
            EspXmlAppend(Context,
                "<task name=\"%s\" value=\"%u\" />\r\n",
                escapedName,
                task->Value
            );
        }
    }

    ExReleasePushLockShared(&Schema->TaskLock);
    KeLeaveCriticalRegion();

    Context->IndentLevel--;
    EspXmlAppendIndent(Context);
    EspXmlAppend(Context, "</tasks>\r\n");

    if (Context->Error) {
        return Context->ErrorStatus;
    }

    return status;
}

static NTSTATUS
EspGenerateMapsElement(
    _In_ PES_SCHEMA Schema,
    _Inout_ PES_XML_CONTEXT Context
)
{
    PLIST_ENTRY entry;
    PLIST_ENTRY entryEntry;
    NTSTATUS status = STATUS_SUCCESS;

    if (Schema->ValueMapCount == 0) {
        return STATUS_SUCCESS;
    }

    EspXmlAppendIndent(Context);
    EspXmlAppend(Context, "<maps>\r\n");
    Context->IndentLevel++;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Schema->ValueMapLock);

    for (entry = Schema->ValueMaps.Flink;
         entry != &Schema->ValueMaps;
         entry = entry->Flink) {

        PES_VALUE_MAP valueMap = CONTAINING_RECORD(
            entry, ES_VALUE_MAP, ListEntry
        );

        {
            CHAR escapedMapName[ES_MAX_VALUE_MAP_NAME * 6];
            EspXmlEscapeString(escapedMapName, sizeof(escapedMapName), valueMap->Name);

            EspXmlAppendIndent(Context);
            EspXmlAppend(Context, "<valueMap name=\"%s\">\r\n", escapedMapName);
            Context->IndentLevel++;

            //
            // Already in critical region from outer ValueMapLock acquisition.
            // Acquire per-map lock without redundant KeEnterCriticalRegion.
            //
            ExAcquirePushLockShared(&valueMap->Lock);

            for (entryEntry = valueMap->Entries.Flink;
                 entryEntry != &valueMap->Entries;
                 entryEntry = entryEntry->Flink) {

                PES_VALUE_MAP_ENTRY mapEntry = CONTAINING_RECORD(
                    entryEntry, ES_VALUE_MAP_ENTRY, ListEntry
                );

                EspXmlAppendIndent(Context);
                EspXmlAppend(Context,
                    "<map value=\"%u\" message=\"$(string.%s.%s.%u)\" />\r\n",
                    mapEntry->Value,
                    Schema->ProviderSymbol,
                    escapedMapName,
                    mapEntry->Value
                );
            }

            ExReleasePushLockShared(&valueMap->Lock);

            Context->IndentLevel--;
            EspXmlAppendIndent(Context);
            EspXmlAppend(Context, "</valueMap>\r\n");
        }
    }

    ExReleasePushLockShared(&Schema->ValueMapLock);
    KeLeaveCriticalRegion();

    Context->IndentLevel--;
    EspXmlAppendIndent(Context);
    EspXmlAppend(Context, "</maps>\r\n");

    if (Context->Error) {
        return Context->ErrorStatus;
    }

    return status;
}

static NTSTATUS
EspGenerateTemplatesElement(
    _In_ PES_SCHEMA Schema,
    _Inout_ PES_XML_CONTEXT Context
)
{
    PLIST_ENTRY entry;
    NTSTATUS status = STATUS_SUCCESS;

    if (Schema->EventCount == 0) {
        return STATUS_SUCCESS;
    }

    EspXmlAppendIndent(Context);
    EspXmlAppend(Context, "<templates>\r\n");
    Context->IndentLevel++;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Schema->EventLock);

    for (entry = Schema->EventList.Flink;
         entry != &Schema->EventList;
         entry = entry->Flink) {

        PES_EVENT_DEFINITION event = CONTAINING_RECORD(
            entry, ES_EVENT_DEFINITION, OrderedEntry
        );

        if (event->FieldCount == 0) {
            continue;
        }

        {
            CHAR escapedEvtName[ES_MAX_EVENT_NAME * 6];
            CHAR escapedTplName[ES_MAX_EVENT_NAME * 6];
            EspXmlEscapeString(escapedEvtName, sizeof(escapedEvtName), event->EventName);

            //
            // Generate template
            //
            EspXmlAppendIndent(Context);
            if (event->TemplateName[0] != '\0') {
                EspXmlEscapeString(escapedTplName, sizeof(escapedTplName), event->TemplateName);
                EspXmlAppend(Context, "<template tid=\"%s\">\r\n", escapedTplName);
            } else {
                EspXmlAppend(Context, "<template tid=\"%s_Template\">\r\n", escapedEvtName);
            }
            Context->IndentLevel++;

            //
            // Generate fields
            //
            for (ULONG i = 0; i < event->FieldCount; i++) {
                PCES_FIELD_DEFINITION field = &event->Fields[i];
                PCSTR typeName = EsGetFieldTypeName(field->Type);
                CHAR escapedFieldName[ES_MAX_FIELD_NAME * 6];
                EspXmlEscapeString(escapedFieldName, sizeof(escapedFieldName), field->FieldName);

                EspXmlAppendIndent(Context);
                EspXmlAppend(Context, "<data name=\"%s\" inType=\"%s\"",
                    escapedFieldName, typeName);

                if (field->OutType[0] != '\0') {
                    CHAR escapedOutType[64 * 6];
                    EspXmlEscapeString(escapedOutType, sizeof(escapedOutType), field->OutType);
                    EspXmlAppend(Context, " outType=\"%s\"", escapedOutType);
                }

                if (field->MapName[0] != '\0') {
                    CHAR escapedMapRef[ES_MAX_VALUE_MAP_NAME * 6];
                    EspXmlEscapeString(escapedMapRef, sizeof(escapedMapRef), field->MapName);
                    EspXmlAppend(Context, " map=\"%s\"", escapedMapRef);
                }

                if (field->ArrayCount > 0) {
                    EspXmlAppend(Context, " count=\"%u\"", field->ArrayCount);
                }

                EspXmlAppend(Context, " />\r\n");
            }

            Context->IndentLevel--;
            EspXmlAppendIndent(Context);
            EspXmlAppend(Context, "</template>\r\n");
        }
    }

    ExReleasePushLockShared(&Schema->EventLock);
    KeLeaveCriticalRegion();

    Context->IndentLevel--;
    EspXmlAppendIndent(Context);
    EspXmlAppend(Context, "</templates>\r\n");

    if (Context->Error) {
        return Context->ErrorStatus;
    }

    return status;
}

static NTSTATUS
EspGenerateEventsElement(
    _In_ PES_SCHEMA Schema,
    _Inout_ PES_XML_CONTEXT Context,
    _In_ PES_MANIFEST_OPTIONS Options
)
{
    PLIST_ENTRY entry;
    NTSTATUS status = STATUS_SUCCESS;
    static PCSTR LevelNames[] = {
        "win:LogAlways",
        "win:Critical",
        "win:Error",
        "win:Warning",
        "win:Informational",
        "win:Verbose"
    };

    if (Schema->EventCount == 0) {
        return STATUS_SUCCESS;
    }

    EspXmlAppendIndent(Context);
    EspXmlAppend(Context, "<events>\r\n");
    Context->IndentLevel++;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Schema->EventLock);

    for (entry = Schema->EventList.Flink;
         entry != &Schema->EventList;
         entry = entry->Flink) {

        PES_EVENT_DEFINITION event = CONTAINING_RECORD(
            entry, ES_EVENT_DEFINITION, OrderedEntry
        );

        PCSTR levelName = "win:LogAlways";
        if (event->Level <= 5) {
            levelName = LevelNames[event->Level];
        }

        {
            CHAR escapedEvtName[ES_MAX_EVENT_NAME * 6];
            EspXmlEscapeString(escapedEvtName, sizeof(escapedEvtName), event->EventName);

            EspXmlAppendIndent(Context);
            EspXmlAppend(Context,
                "<event value=\"%u\" symbol=\"%s\" version=\"%u\" level=\"%s\"",
                event->EventId,
                escapedEvtName,
                event->Version,
                levelName
            );

            if (event->Keywords != 0) {
                EspXmlAppend(Context, " keywords=\"0x%I64X\"", event->Keywords);
            }

            if (event->Task != 0) {
                EspXmlAppend(Context, " task=\"%u\"", event->Task);
            }

            if (event->Opcode != 0) {
                EspXmlAppend(Context, " opcode=\"%u\"", event->Opcode);
            }

            if (event->ChannelName[0] != '\0') {
                CHAR escapedChan[ES_MAX_CHANNEL_NAME * 6];
                EspXmlEscapeString(escapedChan, sizeof(escapedChan), event->ChannelName);
                EspXmlAppend(Context, " channel=\"%s\"", escapedChan);
            }

            if (event->FieldCount > 0) {
                if (event->TemplateName[0] != '\0') {
                    CHAR escapedTpl[ES_MAX_EVENT_NAME * 6];
                    EspXmlEscapeString(escapedTpl, sizeof(escapedTpl), event->TemplateName);
                    EspXmlAppend(Context, " template=\"%s\"", escapedTpl);
                } else {
                    EspXmlAppend(Context, " template=\"%s_Template\"", escapedEvtName);
                }
            }

            if (Options->IncludeMessages && event->Message[0] != '\0') {
                EspXmlAppend(Context,
                    " message=\"$(string.%s.%s.Message)\"",
                    Schema->ProviderSymbol,
                    escapedEvtName
                );
            }

            EspXmlAppend(Context, " />\r\n");
        }
    }

    ExReleasePushLockShared(&Schema->EventLock);
    KeLeaveCriticalRegion();

    Context->IndentLevel--;
    EspXmlAppendIndent(Context);
    EspXmlAppend(Context, "</events>\r\n");

    if (Context->Error) {
        return Context->ErrorStatus;
    }

    return status;
}
