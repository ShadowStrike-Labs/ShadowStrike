/*++
    ShadowStrike Next-Generation Antivirus
    Module: EventSchema.h - ETW event schema definitions
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define ES_POOL_TAG 'HCSE'

// Field types
typedef enum _ES_FIELD_TYPE {
    EsType_NULL = 0,
    EsType_UINT8,
    EsType_UINT16,
    EsType_UINT32,
    EsType_UINT64,
    EsType_INT8,
    EsType_INT16,
    EsType_INT32,
    EsType_INT64,
    EsType_FLOAT,
    EsType_DOUBLE,
    EsType_BOOL,
    EsType_BINARY,
    EsType_ANSISTRING,
    EsType_UNICODESTRING,
    EsType_GUID,
    EsType_POINTER,
    EsType_FILETIME,
    EsType_SYSTEMTIME,
    EsType_SID,
    EsType_HEXINT32,
    EsType_HEXINT64,
} ES_FIELD_TYPE;

typedef struct _ES_FIELD_DEFINITION {
    CHAR FieldName[64];
    ES_FIELD_TYPE Type;
    USHORT Offset;
    USHORT Size;                        // 0 for variable
    CHAR Description[128];
} ES_FIELD_DEFINITION, *PES_FIELD_DEFINITION;

typedef struct _ES_EVENT_DEFINITION {
    USHORT EventId;
    CHAR EventName[64];
    CHAR Description[256];
    
    // Fields
    ES_FIELD_DEFINITION Fields[32];
    ULONG FieldCount;
    
    // Metadata
    UCHAR Level;
    ULONG64 Keywords;
    CHAR Channel[32];
    CHAR Task[32];
    CHAR Opcode[32];
    
    LIST_ENTRY ListEntry;
} ES_EVENT_DEFINITION, *PES_EVENT_DEFINITION;

typedef struct _ES_SCHEMA {
    BOOLEAN Initialized;
    
    GUID ProviderId;
    CHAR ProviderName[64];
    
    LIST_ENTRY EventList;
    EX_PUSH_LOCK EventLock;
    ULONG EventCount;
    
    // Version
    UCHAR MajorVersion;
    UCHAR MinorVersion;
    USHORT Revision;
    
} ES_SCHEMA, *PES_SCHEMA;

NTSTATUS EsInitialize(_Out_ PES_SCHEMA* Schema);
VOID EsShutdown(_Inout_ PES_SCHEMA Schema);
NTSTATUS EsRegisterEvent(_In_ PES_SCHEMA Schema, _In_ PES_EVENT_DEFINITION Event);
NTSTATUS EsGetEventDefinition(_In_ PES_SCHEMA Schema, _In_ USHORT EventId, _Out_ PES_EVENT_DEFINITION* Event);
NTSTATUS EsValidateEvent(_In_ PES_SCHEMA Schema, _In_ USHORT EventId, _In_ PVOID EventData, _In_ SIZE_T DataSize);
NTSTATUS EsGenerateManifestXml(_In_ PES_SCHEMA Schema, _Out_ PCHAR* ManifestXml, _Out_ PSIZE_T XmlSize);

#ifdef __cplusplus
}
#endif
