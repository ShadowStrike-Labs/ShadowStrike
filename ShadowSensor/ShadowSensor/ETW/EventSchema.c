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
    sizeof(FLOAT),          // EsType_FLOAT
    sizeof(DOUBLE),         // EsType_DOUBLE
    sizeof(UINT8),          // EsType_BOOL
    0,                      // EsType_BINARY (variable)
    0,                      // EsType_ANSISTRING (variable)
    0,                      // EsType_UNICODESTRING (variable)
    sizeof(GUID),           // EsType_GUID
    sizeof(PVOID),          // EsType_POINTER
    sizeof(FILETIME),       // EsType_FILETIME
    sizeof(SYSTEMTIME),     // EsType_SYSTEMTIME
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

static NTSTATUS
EspXmlOpenElement(
    _Inout_ PES_XML_CONTEXT Context,
    _In_ PCSTR ElementName
);

static NTSTATUS
EspXmlCloseElement(
    _Inout_ PES_XML_CONTEXT Context,
    _In_ PCSTR ElementName
);

static NTSTATUS
EspXmlAddAttribute(
    _Inout_ PES_XML_CONTEXT Context,
    _In_ PCSTR Name,
    _In_ PCSTR Value
);

static NTSTATUS
EspGenerateProviderElement(
    _In_ PES_SCHEMA Schema,
    _Inout_ PES_XML_CONTEXT Context,
    _In_ PES_MANIFEST_OPTIONS Options
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
    _Inout_ PES_SCHEMA Schema
)
{
    PLIST_ENTRY entry;
    PES_EVENT_DEFINITION event;
    PES_KEYWORD_DEFINITION keyword;
    PES_TASK_DEFINITION task;
    PES_OPCODE_DEFINITION opcode;
    PES_CHANNEL_DEFINITION channel;
    PES_VALUE_MAP valueMap;
    PES_VALUE_MAP_ENTRY mapEntry;
    ULONG i;

    PAGED_CODE();

    if (Schema == NULL || Schema->Magic != ES_SCHEMA_MAGIC) {
        return;
    }

    //
    // Signal shutdown
    //
    Schema->ShuttingDown = TRUE;

    //
    // Wait for references to drain
    //
    while (Schema->ReferenceCount > 1) {
        LARGE_INTEGER delay;
        delay.QuadPart = -10000; // 1ms
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    //
    // Free all events
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Schema->EventLock);

    for (i = 0; i < ES_EVENT_HASH_BUCKETS; i++) {
        while (!IsListEmpty(&Schema->EventHashBuckets[i])) {
            entry = RemoveHeadList(&Schema->EventHashBuckets[i]);
            event = CONTAINING_RECORD(entry, ES_EVENT_DEFINITION, ListEntry);
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
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
EsAcquireReference(
    _In_ PES_SCHEMA Schema
)
{
    if (Schema != NULL && Schema->Magic == ES_SCHEMA_MAGIC) {
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
        InterlockedDecrement(&Schema->ReferenceCount);
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
    NTSTATUS status = STATUS_SUCCESS;
    PES_EVENT_DEFINITION newEvent = NULL;

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
    // Check if event ID already exists
    //
    if (EsIsEventRegistered(Schema, Event->EventId)) {
        return STATUS_OBJECT_NAME_COLLISION;
    }

    //
    // Check event count limit
    //
    if ((ULONG)Schema->EventCount >= ES_MAX_EVENTS_PER_SCHEMA) {
        return STATUS_QUOTA_EXCEEDED;
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
    // Copy event definition
    //
    RtlCopyMemory(newEvent, Event, sizeof(ES_EVENT_DEFINITION));

    //
    // Initialize list entries
    //
    InitializeListHead(&newEvent->ListEntry);
    InitializeListHead(&newEvent->OrderedEntry);

    //
    // Set magic and reference count
    //
    newEvent->Magic = ES_EVENT_MAGIC;
    newEvent->ReferenceCount = 1;

    //
    // Compute name hash
    //
    newEvent->NameHash = EspHashEventName(newEvent->EventName);

    //
    // Calculate minimum data size from fixed fields
    //
    newEvent->MinDataSize = 0;
    for (ULONG i = 0; i < newEvent->FieldCount; i++) {
        PCES_FIELD_DEFINITION field = &newEvent->Fields[i];
        if (!(field->Flags & EsFieldFlag_Optional)) {
            if (field->Size > 0) {
                newEvent->MinDataSize += field->Size;
            }
        }
    }

    //
    // Insert into hash table and ordered list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Schema->EventLock);

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
    ES_EVENT_DEFINITION eventDef;
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
    // Initialize event definition
    //
    RtlZeroMemory(&eventDef, sizeof(eventDef));

    eventDef.EventId = EventId;
    eventDef.Level = Level;
    eventDef.Keywords = Keywords;
    eventDef.FieldCount = FieldCount;

    //
    // Copy event name
    //
    status = RtlStringCchCopyA(
        eventDef.EventName,
        ES_MAX_EVENT_NAME,
        EventName
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Copy fields
    //
    if (FieldCount > 0) {
        RtlCopyMemory(
            eventDef.Fields,
            Fields,
            FieldCount * sizeof(ES_FIELD_DEFINITION)
        );
    }

    return EsRegisterEvent(Schema, &eventDef);
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
EsUnregisterEvent(
    _In_ PES_SCHEMA Schema,
    _In_ USHORT EventId
)
{
    PES_EVENT_DEFINITION event = NULL;
    NTSTATUS status;

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
    // Wait for references to drain
    //
    while (event->ReferenceCount > 0) {
        LARGE_INTEGER delay;
        delay.QuadPart = -10000; // 1ms
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
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

_IRQL_requires_max_(DISPATCH_LEVEL)
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

_IRQL_requires_max_(DISPATCH_LEVEL)
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
        InterlockedDecrement(&Event->ReferenceCount);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
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

_IRQL_requires_max_(DISPATCH_LEVEL)
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

_IRQL_requires_max_(DISPATCH_LEVEL)
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

_IRQL_requires_max_(DISPATCH_LEVEL)
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
    // Add to list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Schema->KeywordLock);

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
    // Add to list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Schema->TaskLock);

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
    // Add to list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Schema->OpcodeLock);

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
    // Add to list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Schema->ChannelLock);

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
    // Add to list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Schema->ValueMapLock);

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
    // Find value map
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

    ExReleasePushLockShared(&Schema->ValueMapLock);
    KeLeaveCriticalRegion();

    if (valueMap == NULL) {
        return STATUS_NOT_FOUND;
    }

    //
    // Allocate entry
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
    // Add to map
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&valueMap->Lock);

    InsertTailList(&valueMap->Entries, &entry->ListEntry);
    valueMap->EntryCount++;

    ExReleasePushLockExclusive(&valueMap->Lock);
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

    EspXmlAppendIndent(&xmlContext);
    EspXmlAppend(&xmlContext,
        "<provider name=\"%s\"\r\n",
        Schema->ProviderName
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
        Schema->ProviderSymbol
    );
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

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
EsGetCachedManifest(
    _In_ PES_SCHEMA Schema,
    _Outptr_ PCHAR* ManifestXml,
    _Out_ PSIZE_T XmlSize
)
{
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

    *ManifestXml = Schema->CachedManifest;
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
    NTSTATUS status = STATUS_SUCCESS;
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
    // Calculate total size needed
    //
    totalSize = sizeof(ES_BINARY_HEADER);
    totalSize += Schema->EventCount * sizeof(ES_EVENT_DEFINITION);
    totalSize += Schema->KeywordCount * sizeof(ES_KEYWORD_DEFINITION);
    totalSize += Schema->TaskCount * sizeof(ES_TASK_DEFINITION);
    totalSize += Schema->OpcodeCount * sizeof(ES_OPCODE_DEFINITION);
    totalSize += Schema->ChannelCount * sizeof(ES_CHANNEL_DEFINITION);

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
    header->ValueMapCount = Schema->ValueMapCount;
    header->TotalSize = (ULONG)totalSize;
    RtlCopyMemory(&header->ProviderId, &Schema->ProviderId, sizeof(GUID));
    RtlStringCchCopyA(header->ProviderName, ES_MAX_PROVIDER_NAME, Schema->ProviderName);

    currentPos += sizeof(ES_BINARY_HEADER);

    //
    // Serialize events
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Schema->EventLock);

    for (entry = Schema->EventList.Flink;
         entry != &Schema->EventList;
         entry = entry->Flink) {

        PES_EVENT_DEFINITION event = CONTAINING_RECORD(
            entry, ES_EVENT_DEFINITION, OrderedEntry
        );

        if (currentPos + sizeof(ES_EVENT_DEFINITION) <= buffer + totalSize) {
            RtlCopyMemory(currentPos, event, sizeof(ES_EVENT_DEFINITION));
            currentPos += sizeof(ES_EVENT_DEFINITION);
        }
    }

    ExReleasePushLockShared(&Schema->EventLock);
    KeLeaveCriticalRegion();

    //
    // Serialize keywords
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Schema->KeywordLock);

    for (entry = Schema->Keywords.Flink;
         entry != &Schema->Keywords;
         entry = entry->Flink) {

        PES_KEYWORD_DEFINITION keyword = CONTAINING_RECORD(
            entry, ES_KEYWORD_DEFINITION, ListEntry
        );

        if (currentPos + sizeof(ES_KEYWORD_DEFINITION) <= buffer + totalSize) {
            RtlCopyMemory(currentPos, keyword, sizeof(ES_KEYWORD_DEFINITION));
            currentPos += sizeof(ES_KEYWORD_DEFINITION);
        }
    }

    ExReleasePushLockShared(&Schema->KeywordLock);
    KeLeaveCriticalRegion();

    //
    // Serialize tasks
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Schema->TaskLock);

    for (entry = Schema->Tasks.Flink;
         entry != &Schema->Tasks;
         entry = entry->Flink) {

        PES_TASK_DEFINITION task = CONTAINING_RECORD(
            entry, ES_TASK_DEFINITION, ListEntry
        );

        if (currentPos + sizeof(ES_TASK_DEFINITION) <= buffer + totalSize) {
            RtlCopyMemory(currentPos, task, sizeof(ES_TASK_DEFINITION));
            currentPos += sizeof(ES_TASK_DEFINITION);
        }
    }

    ExReleasePushLockShared(&Schema->TaskLock);
    KeLeaveCriticalRegion();

    //
    // Serialize opcodes
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Schema->OpcodeLock);

    for (entry = Schema->Opcodes.Flink;
         entry != &Schema->Opcodes;
         entry = entry->Flink) {

        PES_OPCODE_DEFINITION opcode = CONTAINING_RECORD(
            entry, ES_OPCODE_DEFINITION, ListEntry
        );

        if (currentPos + sizeof(ES_OPCODE_DEFINITION) <= buffer + totalSize) {
            RtlCopyMemory(currentPos, opcode, sizeof(ES_OPCODE_DEFINITION));
            currentPos += sizeof(ES_OPCODE_DEFINITION);
        }
    }

    ExReleasePushLockShared(&Schema->OpcodeLock);
    KeLeaveCriticalRegion();

    //
    // Serialize channels
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Schema->ChannelLock);

    for (entry = Schema->Channels.Flink;
         entry != &Schema->Channels;
         entry = entry->Flink) {

        PES_CHANNEL_DEFINITION channel = CONTAINING_RECORD(
            entry, ES_CHANNEL_DEFINITION, ListEntry
        );

        if (currentPos + sizeof(ES_CHANNEL_DEFINITION) <= buffer + totalSize) {
            RtlCopyMemory(currentPos, channel, sizeof(ES_CHANNEL_DEFINITION));
            currentPos += sizeof(ES_CHANNEL_DEFINITION);
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
    // Deserialize events
    //
    for (i = 0; i < header->EventCount; i++) {
        if (currentPos + sizeof(ES_EVENT_DEFINITION) > (PUCHAR)Buffer + BufferSize) {
            break;
        }

        PES_EVENT_DEFINITION eventDef = (PES_EVENT_DEFINITION)currentPos;
        status = EsRegisterEvent(schema, eventDef);
        if (!NT_SUCCESS(status)) {
            // Continue on non-fatal errors
        }

        currentPos += sizeof(ES_EVENT_DEFINITION);
    }

    //
    // Deserialize keywords
    //
    for (i = 0; i < header->KeywordCount; i++) {
        if (currentPos + sizeof(ES_KEYWORD_DEFINITION) > (PUCHAR)Buffer + BufferSize) {
            break;
        }

        PES_KEYWORD_DEFINITION keywordDef = (PES_KEYWORD_DEFINITION)currentPos;
        EsRegisterKeyword(schema, keywordDef->Name, keywordDef->Mask, keywordDef->Description);

        currentPos += sizeof(ES_KEYWORD_DEFINITION);
    }

    //
    // Deserialize tasks
    //
    for (i = 0; i < header->TaskCount; i++) {
        if (currentPos + sizeof(ES_TASK_DEFINITION) > (PUCHAR)Buffer + BufferSize) {
            break;
        }

        PES_TASK_DEFINITION taskDef = (PES_TASK_DEFINITION)currentPos;
        EsRegisterTask(schema, taskDef->Name, taskDef->Value, taskDef->Description);

        currentPos += sizeof(ES_TASK_DEFINITION);
    }

    //
    // Deserialize opcodes
    //
    for (i = 0; i < header->OpcodeCount; i++) {
        if (currentPos + sizeof(ES_OPCODE_DEFINITION) > (PUCHAR)Buffer + BufferSize) {
            break;
        }

        PES_OPCODE_DEFINITION opcodeDef = (PES_OPCODE_DEFINITION)currentPos;
        EsRegisterOpcode(schema, opcodeDef->Name, opcodeDef->Value,
            opcodeDef->TaskValue, opcodeDef->Description);

        currentPos += sizeof(ES_OPCODE_DEFINITION);
    }

    //
    // Deserialize channels
    //
    for (i = 0; i < header->ChannelCount; i++) {
        if (currentPos + sizeof(ES_CHANNEL_DEFINITION) > (PUCHAR)Buffer + BufferSize) {
            break;
        }

        PES_CHANNEL_DEFINITION channelDef = (PES_CHANNEL_DEFINITION)currentPos;
        EsRegisterChannel(schema, channelDef->Name, channelDef->Type,
            channelDef->Value, channelDef->Enabled, channelDef->Description);

        currentPos += sizeof(ES_CHANNEL_DEFINITION);
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

    RtlCopyMemory(Stats, &Schema->Stats, sizeof(ES_STATISTICS));
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
    // DJB2 hash algorithm
    //
    ULONG hash = ES_HASH_SEED;

    if (EventName == NULL) {
        return hash;
    }

    while (*EventName != '\0') {
        hash = ((hash << 5) + hash) + (UCHAR)*EventName;
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
    }

    if (event != NULL) {
        RtlZeroMemory(event, sizeof(ES_EVENT_DEFINITION));
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

    if (Schema->LookasideInitialized) {
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

static NTSTATUS
EspXmlAppend(
    _Inout_ PES_XML_CONTEXT Context,
    _In_ PCSTR Format,
    ...
)
{
    va_list args;
    NTSTATUS status;
    SIZE_T remaining;
    SIZE_T written;

    if (Context->Error) {
        return Context->ErrorStatus;
    }

    va_start(args, Format);

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
        // Grow buffer
        //
        SIZE_T newSize = Context->BufferSize + ES_XML_BUFFER_INCREMENT;
        PCHAR newBuffer;

        if (newSize > ES_MAX_MANIFEST_SIZE) {
            Context->Error = TRUE;
            Context->ErrorStatus = STATUS_BUFFER_OVERFLOW;
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
            va_end(args);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(newBuffer, Context->Buffer, Context->CurrentPos);
        ShadowStrikeFreePoolWithTag(Context->Buffer, ES_MANIFEST_TAG);
        Context->Buffer = newBuffer;
        Context->BufferSize = newSize;

        //
        // Retry format
        //
        remaining = Context->BufferSize - Context->CurrentPos;
        status = RtlStringCchVPrintfA(
            Context->Buffer + Context->CurrentPos,
            remaining,
            Format,
            args
        );
    }

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

        EspXmlAppendIndent(Context);
        EspXmlAppend(Context,
            "<channel name=\"%s/%s\" chid=\"%s\" type=\"%s\" enabled=\"%s\" />\r\n",
            Schema->ProviderName,
            channel->Name,
            channel->Name,
            g_ChannelTypeNames[channel->Type],
            channel->Enabled ? "true" : "false"
        );
    }

    ExReleasePushLockShared(&Schema->ChannelLock);
    KeLeaveCriticalRegion();

    Context->IndentLevel--;
    EspXmlAppendIndent(Context);
    EspXmlAppend(Context, "</channels>\r\n");

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

        EspXmlAppendIndent(Context);
        EspXmlAppend(Context,
            "<keyword name=\"%s\" mask=\"0x%I64X\" />\r\n",
            keyword->Name,
            keyword->Mask
        );
    }

    ExReleasePushLockShared(&Schema->KeywordLock);
    KeLeaveCriticalRegion();

    Context->IndentLevel--;
    EspXmlAppendIndent(Context);
    EspXmlAppend(Context, "</keywords>\r\n");

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

        EspXmlAppendIndent(Context);
        EspXmlAppend(Context,
            "<task name=\"%s\" value=\"%u\" />\r\n",
            task->Name,
            task->Value
        );
    }

    ExReleasePushLockShared(&Schema->TaskLock);
    KeLeaveCriticalRegion();

    Context->IndentLevel--;
    EspXmlAppendIndent(Context);
    EspXmlAppend(Context, "</tasks>\r\n");

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

        EspXmlAppendIndent(Context);
        EspXmlAppend(Context, "<valueMap name=\"%s\">\r\n", valueMap->Name);
        Context->IndentLevel++;

        KeEnterCriticalRegion();
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
                valueMap->Name,
                mapEntry->Value
            );
        }

        ExReleasePushLockShared(&valueMap->Lock);
        KeLeaveCriticalRegion();

        Context->IndentLevel--;
        EspXmlAppendIndent(Context);
        EspXmlAppend(Context, "</valueMap>\r\n");
    }

    ExReleasePushLockShared(&Schema->ValueMapLock);
    KeLeaveCriticalRegion();

    Context->IndentLevel--;
    EspXmlAppendIndent(Context);
    EspXmlAppend(Context, "</maps>\r\n");

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

        //
        // Generate template
        //
        EspXmlAppendIndent(Context);
        if (event->TemplateName[0] != '\0') {
            EspXmlAppend(Context, "<template tid=\"%s\">\r\n", event->TemplateName);
        } else {
            EspXmlAppend(Context, "<template tid=\"%s_Template\">\r\n", event->EventName);
        }
        Context->IndentLevel++;

        //
        // Generate fields
        //
        for (ULONG i = 0; i < event->FieldCount; i++) {
            PCES_FIELD_DEFINITION field = &event->Fields[i];
            PCSTR typeName = EsGetFieldTypeName(field->Type);

            EspXmlAppendIndent(Context);
            EspXmlAppend(Context, "<data name=\"%s\" inType=\"%s\"",
                field->FieldName, typeName);

            if (field->OutType[0] != '\0') {
                EspXmlAppend(Context, " outType=\"%s\"", field->OutType);
            }

            if (field->MapName[0] != '\0') {
                EspXmlAppend(Context, " map=\"%s\"", field->MapName);
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

    ExReleasePushLockShared(&Schema->EventLock);
    KeLeaveCriticalRegion();

    Context->IndentLevel--;
    EspXmlAppendIndent(Context);
    EspXmlAppend(Context, "</templates>\r\n");

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

        EspXmlAppendIndent(Context);
        EspXmlAppend(Context,
            "<event value=\"%u\" symbol=\"%s\" version=\"%u\" level=\"%s\"",
            event->EventId,
            event->EventName,
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
            EspXmlAppend(Context, " channel=\"%s\"", event->ChannelName);
        }

        if (event->FieldCount > 0) {
            if (event->TemplateName[0] != '\0') {
                EspXmlAppend(Context, " template=\"%s\"", event->TemplateName);
            } else {
                EspXmlAppend(Context, " template=\"%s_Template\"", event->EventName);
            }
        }

        if (Options->IncludeMessages && event->Message[0] != '\0') {
            EspXmlAppend(Context,
                " message=\"$(string.%s.%s.Message)\"",
                Schema->ProviderSymbol,
                event->EventName
            );
        }

        EspXmlAppend(Context, " />\r\n");
    }

    ExReleasePushLockShared(&Schema->EventLock);
    KeLeaveCriticalRegion();

    Context->IndentLevel--;
    EspXmlAppendIndent(Context);
    EspXmlAppend(Context, "</events>\r\n");

    return status;
}
