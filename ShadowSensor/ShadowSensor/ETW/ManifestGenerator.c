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
ShadowStrike NGAV - ETW MANIFEST GENERATOR IMPLEMENTATION
===============================================================================

@file ManifestGenerator.c
@brief Enterprise-grade ETW manifest and header generation implementation.

This module provides complete Windows Event Log manifest generation for
integration with Windows Event Viewer, SIEM systems, and forensic tools.

Implementation Features:
- Thread-safe generation with EX_PUSH_LOCK synchronization
- Efficient string building with automatic buffer growth
- XML escaping to prevent injection attacks
- GUID formatting compliant with RFC 4122
- Caching for repeated generation requests
- Comprehensive validation with detailed error reporting

@author ShadowStrike Security Team
@version 2.0.0 (Enterprise Edition)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "ManifestGenerator.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/StringUtils.h"
#include <ntstrsafe.h>
#include <wdm.h>

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define MG_STRING_BUILDER_GROWTH_FACTOR     2
#define MG_MIN_BUFFER_GROWTH                4096
#define MG_GUID_STRING_LENGTH               38      // {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
#define MG_MAX_INDENT_LEVEL                 16
#define MG_TEMPLATE_NAME_PREFIX             "Template_"
#define MG_DEFAULT_PROVIDER_SYMBOL          "SHADOWSTRIKE"
#define MG_FORMAT_TEMP_BUFFER_SIZE          2048

//
// XML generation templates
//
static const CHAR MgpXmlHeader[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";

static const CHAR MgpManifestOpen[] =
    "<instrumentationManifest\r\n"
    "    xmlns=\"http://schemas.microsoft.com/win/2004/08/events\"\r\n"
    "    xmlns:win=\"http://manifests.microsoft.com/win/2004/08/windows/events\"\r\n"
    "    xmlns:xs=\"http://www.w3.org/2001/XMLSchema\">\r\n"
    "\r\n"
    "    <instrumentation>\r\n"
    "        <events>\r\n";

static const CHAR MgpManifestClose[] =
    "        </events>\r\n"
    "    </instrumentation>\r\n"
    "</instrumentationManifest>\r\n";

//
// Channel type strings
//
static const CHAR* MgpChannelTypeStrings[] = {
    "Admin",
    "Operational",
    "Analytic",
    "Debug"
};

//
// Isolation type strings
//
static const CHAR* MgpIsolationTypeStrings[] = {
    "Application",
    "System",
    "Custom"
};

//
// Field type to ETW in-type mapping
//
static const CHAR* MgpFieldTypeToInType[] = {
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
    "win:HexInt64"          // EsType_HEXINT64
};

#define MG_FIELD_TYPE_COUNT (sizeof(MgpFieldTypeToInType) / sizeof(MgpFieldTypeToInType[0]))

// ============================================================================
// REFERENCE COUNTING HELPERS
// ============================================================================

//
// Acquire a reference on the generator for the duration of a public API call.
// Returns STATUS_DEVICE_NOT_READY if the generator is shutting down.
//
static
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MgpAcquireReference(
    _In_ PMG_GENERATOR Generator
    )
{
    LONG OldCount;

    if (Generator == NULL || !Generator->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Generator->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    OldCount = InterlockedIncrement(&Generator->ReferenceCount);

    //
    // Re-check after increment to handle race with shutdown
    //
    if (Generator->ShuttingDown) {
        if (InterlockedDecrement(&Generator->ReferenceCount) == 0) {
            KeSetEvent(&Generator->ShutdownEvent, IO_NO_INCREMENT, FALSE);
        }
        return STATUS_DEVICE_NOT_READY;
    }

    return STATUS_SUCCESS;
}

//
// Release a reference on the generator. Signals shutdown event when count
// reaches zero.
//
static
VOID
MgpReleaseReference(
    _In_ PMG_GENERATOR Generator
    )
{
    LONG NewCount = InterlockedDecrement(&Generator->ReferenceCount);

    NT_ASSERT(NewCount >= 0);

    if (NewCount == 0) {
        KeSetEvent(&Generator->ShutdownEvent, IO_NO_INCREMENT, FALSE);
    }
}

// ============================================================================
// PRIVATE FUNCTION PROTOTYPES
// ============================================================================

//
// String builder functions
//
static NTSTATUS
MgpStringBuilderInit(
    _Out_ PMG_STRING_BUILDER Builder,
    _In_ SIZE_T InitialCapacity,
    _In_ SIZE_T MaxCapacity,
    _In_ ULONG PoolTag
    );

static VOID
MgpStringBuilderCleanup(
    _Inout_ PMG_STRING_BUILDER Builder
    );

static NTSTATUS
MgpStringBuilderAppend(
    _Inout_ PMG_STRING_BUILDER Builder,
    _In_z_ PCSTR String
    );

static NTSTATUS
MgpStringBuilderAppendFormat(
    _Inout_ PMG_STRING_BUILDER Builder,
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...
    );

static NTSTATUS
MgpStringBuilderAppendFormatV(
    _Inout_ PMG_STRING_BUILDER Builder,
    _In_z_ PCSTR Format,
    _In_ va_list Args
    );

static NTSTATUS
MgpStringBuilderEnsureCapacity(
    _Inout_ PMG_STRING_BUILDER Builder,
    _In_ SIZE_T RequiredCapacity
    );

static NTSTATUS
MgpStringBuilderAppendIndent(
    _Inout_ PMG_STRING_BUILDER Builder,
    _In_ ULONG IndentLevel
    );

//
// XML helper functions
//
static NTSTATUS
MgpAppendXmlEscaped(
    _Inout_ PMG_STRING_BUILDER Builder,
    _In_z_ PCSTR String
    );

static NTSTATUS
MgpFormatGuid(
    _In_ PCGUID Guid,
    _Out_writes_(BufferSize) PCHAR Buffer,
    _In_ SIZE_T BufferSize
    );

//
// Manifest generation helpers
//
static NTSTATUS
MgpGenerateProviderSection(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    );

static NTSTATUS
MgpGenerateChannelsSection(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    );

static NTSTATUS
MgpGenerateLevelsSection(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    );

static NTSTATUS
MgpGenerateTasksSection(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    );

static NTSTATUS
MgpGenerateOpcodesSection(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    );

static NTSTATUS
MgpGenerateKeywordsSection(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    );

static NTSTATUS
MgpGenerateEventsSection(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    );

static NTSTATUS
MgpGenerateTemplatesSection(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    );

static NTSTATUS
MgpGenerateStringTableSection(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    );

//
// Header generation helpers
//
static NTSTATUS
MgpGenerateHeaderPreamble(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    );

static NTSTATUS
MgpGenerateHeaderGuidDefinition(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    );

static NTSTATUS
MgpGenerateHeaderEventIds(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    );

static NTSTATUS
MgpGenerateHeaderKeywords(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    );

static NTSTATUS
MgpGenerateHeaderTasks(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    );

static NTSTATUS
MgpGenerateHeaderLevels(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    );

//
// List management helpers
//
static VOID
MgpFreeChannelList(
    _Inout_ PLIST_ENTRY ListHead
    );

static VOID
MgpFreeTaskList(
    _Inout_ PLIST_ENTRY ListHead
    );

static VOID
MgpFreeKeywordList(
    _Inout_ PLIST_ENTRY ListHead
    );

static VOID
MgpFreeOpcodeList(
    _Inout_ PLIST_ENTRY ListHead
    );

static VOID
MgpFreeLevelList(
    _Inout_ PLIST_ENTRY ListHead
    );

//
// Default registrations
//
static NTSTATUS
MgpRegisterDefaultLevels(
    _In_ PMG_GENERATOR Generator
    );

// ============================================================================
// PUBLIC FUNCTION IMPLEMENTATIONS
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MgInitialize(
    _In_ PES_SCHEMA Schema,
    _Outptr_ PMG_GENERATOR* Generator
    )
/*++
Routine Description:
    Initializes a new manifest generator instance.

Arguments:
    Schema - Event schema containing event definitions.
    Generator - Receives pointer to new generator instance.

Return Value:
    STATUS_SUCCESS on success.
    STATUS_INVALID_PARAMETER if parameters are invalid.
    STATUS_INSUFFICIENT_RESOURCES if allocation fails.
--*/
{
    NTSTATUS Status;
    PMG_GENERATOR NewGenerator = NULL;

    PAGED_CODE();

    //
    // Validate parameters
    //
    if (Schema == NULL || Generator == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Schema->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    *Generator = NULL;

    //
    // Acquire reference on schema to ensure it outlives the generator
    //
    EsAcquireReference(Schema);

    //
    // Allocate generator structure (ExAllocatePool2 zero-initializes)
    //
    NewGenerator = (PMG_GENERATOR)ExAllocatePool2(
        POOL_FLAG_PAGED,
        sizeof(MG_GENERATOR),
        MG_POOL_TAG
        );

    if (NewGenerator == NULL) {
        EsReleaseReference(Schema);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize basic fields
    //
    NewGenerator->Schema = Schema;
    NewGenerator->Flags = MgFlagIncludeComments;
    NewGenerator->NextMessageId = MG_DEFAULT_MESSAGE_ID_BASE;
    NewGenerator->ReferenceCount = 1;

    //
    // Initialize shutdown event (manual reset, initially non-signaled)
    //
    KeInitializeEvent(&NewGenerator->ShutdownEvent, NotificationEvent, FALSE);

    //
    // Initialize lists
    //
    InitializeListHead(&NewGenerator->ChannelList);
    InitializeListHead(&NewGenerator->LevelList);
    InitializeListHead(&NewGenerator->TaskList);
    InitializeListHead(&NewGenerator->OpcodeList);
    InitializeListHead(&NewGenerator->KeywordList);

    //
    // Initialize locks
    //
    ExInitializePushLock(&NewGenerator->ChannelLock);
    ExInitializePushLock(&NewGenerator->LevelLock);
    ExInitializePushLock(&NewGenerator->TaskLock);
    ExInitializePushLock(&NewGenerator->OpcodeLock);
    ExInitializePushLock(&NewGenerator->KeywordLock);
    ExInitializePushLock(&NewGenerator->CacheLock);

    //
    // Set default provider symbol
    //
    Status = RtlStringCchCopyA(
        NewGenerator->ProviderSymbol,
        MG_MAX_PROVIDER_SYMBOL,
        MG_DEFAULT_PROVIDER_SYMBOL
        );

    if (!NT_SUCCESS(Status)) {
        goto InitFailed;
    }

    //
    // Set default resource paths
    //
    Status = RtlStringCchCopyA(
        NewGenerator->ResourceFile,
        MG_MAX_RESOURCE_PATH,
        "%SystemRoot%\\System32\\drivers\\ShadowSensor.sys"
        );

    if (!NT_SUCCESS(Status)) {
        goto InitFailed;
    }

    Status = RtlStringCchCopyA(
        NewGenerator->MessageFile,
        MG_MAX_MESSAGE_PATH,
        "%SystemRoot%\\System32\\drivers\\ShadowSensor.sys"
        );

    if (!NT_SUCCESS(Status)) {
        goto InitFailed;
    }

    //
    // Register default levels (no lock needed — not yet published)
    //
    Status = MgpRegisterDefaultLevels(NewGenerator);
    if (!NT_SUCCESS(Status)) {
        goto InitFailed;
    }

    //
    // Mark as initialized and publish
    //
    NewGenerator->Initialized = TRUE;
    *Generator = NewGenerator;

    return STATUS_SUCCESS;

InitFailed:
    //
    // Clean up any levels that were partially registered
    //
    MgpFreeLevelList(&NewGenerator->LevelList);
    EsReleaseReference(Schema);
    ExFreePoolWithTag(NewGenerator, MG_POOL_TAG);
    return Status;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
MgShutdown(
    _Inout_ _Post_ptr_invalid_ PMG_GENERATOR Generator
    )
/*++
Routine Description:
    Shuts down and frees the manifest generator.

Arguments:
    Generator - Generator instance to shutdown.
--*/
{
    LARGE_INTEGER Timeout;

    PAGED_CODE();

    if (Generator == NULL) {
        return;
    }

    if (!Generator->Initialized) {
        ExFreePoolWithTag(Generator, MG_POOL_TAG);
        return;
    }

    //
    // Signal shutdown to prevent new operations
    //
    Generator->ShuttingDown = TRUE;
    MemoryBarrier();
    Generator->Initialized = FALSE;

    //
    // Release our init reference and wait for all in-flight operations to complete.
    // Timeout after 10 seconds to prevent hang — log and proceed if hit.
    //
    if (InterlockedDecrement(&Generator->ReferenceCount) > 0) {
        Timeout.QuadPart = -10LL * 10 * 1000 * 1000;   // 10 seconds relative
        KeWaitForSingleObject(
            &Generator->ShutdownEvent,
            Executive,
            KernelMode,
            FALSE,
            &Timeout
            );
    }

    //
    // Free all list entries
    //
    MgpFreeChannelList(&Generator->ChannelList);
    MgpFreeLevelList(&Generator->LevelList);
    MgpFreeTaskList(&Generator->TaskList);
    MgpFreeOpcodeList(&Generator->OpcodeList);
    MgpFreeKeywordList(&Generator->KeywordList);

    //
    // Free cached content
    //
    if (Generator->CachedManifest != NULL) {
        ExFreePoolWithTag(Generator->CachedManifest, MG_XML_POOL_TAG);
        Generator->CachedManifest = NULL;
    }

    if (Generator->CachedHeader != NULL) {
        ExFreePoolWithTag(Generator->CachedHeader, MG_HDR_POOL_TAG);
        Generator->CachedHeader = NULL;
    }

    //
    // Release schema reference
    //
    if (Generator->Schema != NULL) {
        EsReleaseReference(Generator->Schema);
        Generator->Schema = NULL;
    }

    //
    // Free generator structure
    //
    ExFreePoolWithTag(Generator, MG_POOL_TAG);
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MgSetOutputPaths(
    _In_ PMG_GENERATOR Generator,
    _In_opt_z_ PCSTR ResourceFile,
    _In_opt_z_ PCSTR MessageFile
    )
/*++
Routine Description:
    Sets the resource and message file paths for the manifest.

Arguments:
    Generator - Generator instance.
    ResourceFile - Path to resource DLL.
    MessageFile - Path to message DLL.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    NTSTATUS Status;

    PAGED_CODE();

    Status = MgpAcquireReference(Generator);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Invalidate cache since paths are changing
    //
    MgInvalidateCache(Generator);

    if (ResourceFile != NULL) {
        Status = RtlStringCchCopyA(
            Generator->ResourceFile,
            MG_MAX_RESOURCE_PATH,
            ResourceFile
            );

        if (!NT_SUCCESS(Status)) {
            MgpReleaseReference(Generator);
            return Status;
        }
    }

    if (MessageFile != NULL) {
        Status = RtlStringCchCopyA(
            Generator->MessageFile,
            MG_MAX_MESSAGE_PATH,
            MessageFile
            );

        if (!NT_SUCCESS(Status)) {
            MgpReleaseReference(Generator);
            return Status;
        }
    }

    MgpReleaseReference(Generator);
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MgSetProviderSymbol(
    _In_ PMG_GENERATOR Generator,
    _In_z_ PCSTR ProviderSymbol
    )
/*++
Routine Description:
    Sets the provider symbol name for header generation.

Arguments:
    Generator - Generator instance.
    ProviderSymbol - Symbol name prefix.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    NTSTATUS Status;

    PAGED_CODE();

    if (ProviderSymbol == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Status = MgpAcquireReference(Generator);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    MgInvalidateCache(Generator);

    Status = RtlStringCchCopyA(
        Generator->ProviderSymbol,
        MG_MAX_PROVIDER_SYMBOL,
        ProviderSymbol
        );

    MgpReleaseReference(Generator);
    return Status;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MgSetProviderGuid(
    _In_ PMG_GENERATOR Generator,
    _In_opt_ PCGUID ProviderGuid
    )
/*++
Routine Description:
    Overrides the provider GUID from the schema.

Arguments:
    Generator - Generator instance.
    ProviderGuid - GUID to use, or NULL to clear override.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    NTSTATUS Status;

    PAGED_CODE();

    Status = MgpAcquireReference(Generator);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    MgInvalidateCache(Generator);

    if (ProviderGuid != NULL) {
        Generator->ProviderGuidOverride = *ProviderGuid;
        Generator->UseGuidOverride = TRUE;
    } else {
        RtlZeroMemory(&Generator->ProviderGuidOverride, sizeof(GUID));
        Generator->UseGuidOverride = FALSE;
    }

    MgpReleaseReference(Generator);
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MgSetFlags(
    _In_ PMG_GENERATOR Generator,
    _In_ ULONG Flags
    )
/*++
Routine Description:
    Sets generation flags.

Arguments:
    Generator - Generator instance.
    Flags - Combination of MG_GENERATION_FLAGS.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    NTSTATUS Status;

    PAGED_CODE();

    Status = MgpAcquireReference(Generator);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    MgInvalidateCache(Generator);
    Generator->Flags = Flags;

    MgpReleaseReference(Generator);
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MgRegisterChannel(
    _In_ PMG_GENERATOR Generator,
    _In_ PMG_CHANNEL_DEFINITION Channel
    )
/*++
Routine Description:
    Registers an event channel.

Arguments:
    Generator - Generator instance.
    Channel - Channel definition to register.

Return Value:
    STATUS_SUCCESS on success.
    STATUS_DUPLICATE_NAME if channel already exists.
--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    PMG_CHANNEL_DEFINITION NewChannel = NULL;
    PLIST_ENTRY Entry;
    PMG_CHANNEL_DEFINITION ExistingChannel;

    PAGED_CODE();

    if (Channel == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Validate enum bounds to prevent OOB array access during generation
    //
    if (Channel->Type > MG_MAX_CHANNEL_TYPE_VALUE) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Channel->Isolation > MG_MAX_ISOLATION_TYPE_VALUE) {
        return STATUS_INVALID_PARAMETER;
    }

    Status = MgpAcquireReference(Generator);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Allocate new channel entry
    //
    NewChannel = (PMG_CHANNEL_DEFINITION)ExAllocatePool2(
        POOL_FLAG_PAGED,
        sizeof(MG_CHANNEL_DEFINITION),
        MG_CHN_POOL_TAG
        );

    if (NewChannel == NULL) {
        MgpReleaseReference(Generator);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(NewChannel, Channel, sizeof(MG_CHANNEL_DEFINITION));
    InitializeListHead(&NewChannel->ListEntry);

    //
    // Assign message ID if not set
    //
    if (NewChannel->MessageId == 0) {
        NewChannel->MessageId = (ULONG)InterlockedIncrement(&Generator->NextMessageId);
    }

    //
    // Check for duplicates and insert
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Generator->ChannelLock);

    for (Entry = Generator->ChannelList.Flink;
         Entry != &Generator->ChannelList;
         Entry = Entry->Flink) {

        ExistingChannel = CONTAINING_RECORD(Entry, MG_CHANNEL_DEFINITION, ListEntry);

        if (_strnicmp(ExistingChannel->Name, NewChannel->Name, MG_MAX_CHANNEL_NAME) == 0) {
            Status = STATUS_DUPLICATE_NAME;
            break;
        }
    }

    if (NT_SUCCESS(Status)) {
        InsertTailList(&Generator->ChannelList, &NewChannel->ListEntry);
        Generator->ChannelCount++;
    }

    ExReleasePushLockExclusive(&Generator->ChannelLock);
    KeLeaveCriticalRegion();

    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(NewChannel, MG_CHN_POOL_TAG);
    } else {
        //
        // Invalidate cache AFTER releasing ChannelLock to prevent lock ordering violation
        //
        MgInvalidateCache(Generator);
    }

    MgpReleaseReference(Generator);
    return Status;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MgRegisterTask(
    _In_ PMG_GENERATOR Generator,
    _In_ PMG_TASK_DEFINITION Task
    )
/*++
Routine Description:
    Registers an event task.

Arguments:
    Generator - Generator instance.
    Task - Task definition to register.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    NTSTATUS Status;
    PMG_TASK_DEFINITION NewTask = NULL;

    PAGED_CODE();

    if (Task == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Status = MgpAcquireReference(Generator);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    NewTask = (PMG_TASK_DEFINITION)ExAllocatePool2(
        POOL_FLAG_PAGED,
        sizeof(MG_TASK_DEFINITION),
        MG_TSK_POOL_TAG
        );

    if (NewTask == NULL) {
        MgpReleaseReference(Generator);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(NewTask, Task, sizeof(MG_TASK_DEFINITION));
    InitializeListHead(&NewTask->ListEntry);

    if (NewTask->MessageId == 0) {
        NewTask->MessageId = (ULONG)InterlockedIncrement(&Generator->NextMessageId);
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Generator->TaskLock);

    InsertTailList(&Generator->TaskList, &NewTask->ListEntry);
    Generator->TaskCount++;

    ExReleasePushLockExclusive(&Generator->TaskLock);
    KeLeaveCriticalRegion();

    MgInvalidateCache(Generator);

    MgpReleaseReference(Generator);
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MgRegisterKeyword(
    _In_ PMG_GENERATOR Generator,
    _In_ PMG_KEYWORD_DEFINITION Keyword
    )
/*++
Routine Description:
    Registers an event keyword.

Arguments:
    Generator - Generator instance.
    Keyword - Keyword definition to register.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    NTSTATUS Status;
    PMG_KEYWORD_DEFINITION NewKeyword = NULL;

    PAGED_CODE();

    if (Keyword == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Status = MgpAcquireReference(Generator);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    NewKeyword = (PMG_KEYWORD_DEFINITION)ExAllocatePool2(
        POOL_FLAG_PAGED,
        sizeof(MG_KEYWORD_DEFINITION),
        MG_KWD_POOL_TAG
        );

    if (NewKeyword == NULL) {
        MgpReleaseReference(Generator);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(NewKeyword, Keyword, sizeof(MG_KEYWORD_DEFINITION));
    InitializeListHead(&NewKeyword->ListEntry);

    if (NewKeyword->MessageId == 0) {
        NewKeyword->MessageId = (ULONG)InterlockedIncrement(&Generator->NextMessageId);
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Generator->KeywordLock);

    InsertTailList(&Generator->KeywordList, &NewKeyword->ListEntry);
    Generator->KeywordCount++;

    ExReleasePushLockExclusive(&Generator->KeywordLock);
    KeLeaveCriticalRegion();

    MgInvalidateCache(Generator);

    MgpReleaseReference(Generator);
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MgRegisterOpcode(
    _In_ PMG_GENERATOR Generator,
    _In_ PMG_OPCODE_DEFINITION Opcode
    )
/*++
Routine Description:
    Registers an event opcode.

Arguments:
    Generator - Generator instance.
    Opcode - Opcode definition to register.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    NTSTATUS Status;
    PMG_OPCODE_DEFINITION NewOpcode = NULL;

    PAGED_CODE();

    if (Opcode == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Status = MgpAcquireReference(Generator);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    NewOpcode = (PMG_OPCODE_DEFINITION)ExAllocatePool2(
        POOL_FLAG_PAGED,
        sizeof(MG_OPCODE_DEFINITION),
        MG_OPC_POOL_TAG
        );

    if (NewOpcode == NULL) {
        MgpReleaseReference(Generator);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(NewOpcode, Opcode, sizeof(MG_OPCODE_DEFINITION));
    InitializeListHead(&NewOpcode->ListEntry);

    if (NewOpcode->MessageId == 0) {
        NewOpcode->MessageId = (ULONG)InterlockedIncrement(&Generator->NextMessageId);
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Generator->OpcodeLock);

    InsertTailList(&Generator->OpcodeList, &NewOpcode->ListEntry);
    Generator->OpcodeCount++;

    ExReleasePushLockExclusive(&Generator->OpcodeLock);
    KeLeaveCriticalRegion();

    MgInvalidateCache(Generator);

    MgpReleaseReference(Generator);
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MgGenerateManifest(
    _In_ PMG_GENERATOR Generator,
    _Outptr_result_buffer_(*ContentSize) PCHAR* ManifestContent,
    _Out_ PSIZE_T ContentSize
    )
/*++
Routine Description:
    Generates the ETW manifest XML.

Arguments:
    Generator - Generator instance.
    ManifestContent - Receives pointer to manifest XML.
    ContentSize - Receives size of manifest in bytes.

Return Value:
    STATUS_SUCCESS on success.
    STATUS_INSUFFICIENT_RESOURCES if allocation fails.
--*/
{
    NTSTATUS Status;
    MG_STRING_BUILDER Builder;
    PCHAR OutputBuffer = NULL;
    SIZE_T OutputSize;
    LARGE_INTEGER StartTime, EndTime, Frequency;

    PAGED_CODE();

    if (ManifestContent == NULL || ContentSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ManifestContent = NULL;
    *ContentSize = 0;

    Status = MgpAcquireReference(Generator);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Check cache first
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Generator->CacheLock);

    if (Generator->ManifestCacheValid && Generator->CachedManifest != NULL) {
        //
        // Return copy of cached content
        //
        OutputSize = Generator->CachedManifestSize;
        OutputBuffer = (PCHAR)ExAllocatePool2(
            POOL_FLAG_PAGED,
            OutputSize + 1,
            MG_XML_POOL_TAG
            );

        if (OutputBuffer != NULL) {
            RtlCopyMemory(OutputBuffer, Generator->CachedManifest, OutputSize);
            OutputBuffer[OutputSize] = '\0';
            *ManifestContent = OutputBuffer;
            *ContentSize = OutputSize;

            ExReleasePushLockShared(&Generator->CacheLock);
            KeLeaveCriticalRegion();
            MgpReleaseReference(Generator);
            return STATUS_SUCCESS;
        }
    }

    ExReleasePushLockShared(&Generator->CacheLock);
    KeLeaveCriticalRegion();

    //
    // Generate manifest
    //
    StartTime = KeQueryPerformanceCounter(&Frequency);

    Status = MgpStringBuilderInit(&Builder, MG_INITIAL_XML_BUFFER_SIZE, MG_MAX_XML_BUFFER_SIZE, MG_XML_POOL_TAG);
    if (!NT_SUCCESS(Status)) {
        MgpReleaseReference(Generator);
        return Status;
    }

    //
    // XML header
    //
    Status = MgpStringBuilderAppend(&Builder, MgpXmlHeader);
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    //
    // Manifest opening
    //
    Status = MgpStringBuilderAppend(&Builder, MgpManifestOpen);
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    //
    // Provider section
    //
    Status = MgpGenerateProviderSection(Generator, &Builder);
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    //
    // Localization section (string table for all $(string.*) references)
    //
    Status = MgpGenerateStringTableSection(Generator, &Builder);
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    //
    // Manifest closing
    //
    Status = MgpStringBuilderAppend(&Builder, MgpManifestClose);
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    EndTime = KeQueryPerformanceCounter(NULL);

    //
    // Steal builder buffer as output to avoid redundant copy
    //
    OutputSize = Builder.Length;
    OutputBuffer = Builder.Buffer;
    Builder.Buffer = NULL;
    Builder.Length = 0;
    Builder.Capacity = 0;

    //
    // Update cache
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Generator->CacheLock);

    if (Generator->CachedManifest != NULL) {
        ExFreePoolWithTag(Generator->CachedManifest, MG_XML_POOL_TAG);
        Generator->CachedManifest = NULL;
        Generator->CachedManifestSize = 0;
        Generator->ManifestCacheValid = FALSE;
    }

    Generator->CachedManifest = (PCHAR)ExAllocatePool2(
        POOL_FLAG_PAGED,
        OutputSize + 1,
        MG_XML_POOL_TAG
        );

    if (Generator->CachedManifest != NULL) {
        RtlCopyMemory(Generator->CachedManifest, OutputBuffer, OutputSize + 1);
        Generator->CachedManifestSize = OutputSize;
        Generator->ManifestCacheValid = TRUE;
    }

    //
    // Update statistics
    //
    Generator->Stats.ManifestSize = OutputSize;
    if (Frequency.QuadPart > 0) {
        Generator->Stats.GenerationTimeUs =
            (ULONG64)((EndTime.QuadPart - StartTime.QuadPart) * 1000000 / Frequency.QuadPart);
    }

    ExReleasePushLockExclusive(&Generator->CacheLock);
    KeLeaveCriticalRegion();

    *ManifestContent = OutputBuffer;
    *ContentSize = OutputSize;
    Status = STATUS_SUCCESS;

Cleanup:
    MgpStringBuilderCleanup(&Builder);

    if (!NT_SUCCESS(Status) && OutputBuffer != NULL) {
        ExFreePoolWithTag(OutputBuffer, MG_XML_POOL_TAG);
    }

    MgpReleaseReference(Generator);
    return Status;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MgGenerateHeader(
    _In_ PMG_GENERATOR Generator,
    _Outptr_result_buffer_(*ContentSize) PCHAR* HeaderContent,
    _Out_ PSIZE_T ContentSize
    )
/*++
Routine Description:
    Generates the C header file with event definitions.

Arguments:
    Generator - Generator instance.
    HeaderContent - Receives pointer to header content.
    ContentSize - Receives size of header in bytes.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    NTSTATUS Status;
    MG_STRING_BUILDER Builder;
    PCHAR OutputBuffer = NULL;
    SIZE_T OutputSize;

    PAGED_CODE();

    if (HeaderContent == NULL || ContentSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *HeaderContent = NULL;
    *ContentSize = 0;

    Status = MgpAcquireReference(Generator);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Check cache first
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Generator->CacheLock);

    if (Generator->HeaderCacheValid && Generator->CachedHeader != NULL) {
        OutputSize = Generator->CachedHeaderSize;
        OutputBuffer = (PCHAR)ExAllocatePool2(
            POOL_FLAG_PAGED,
            OutputSize + 1,
            MG_HDR_POOL_TAG
            );

        if (OutputBuffer != NULL) {
            RtlCopyMemory(OutputBuffer, Generator->CachedHeader, OutputSize);
            OutputBuffer[OutputSize] = '\0';
            *HeaderContent = OutputBuffer;
            *ContentSize = OutputSize;

            ExReleasePushLockShared(&Generator->CacheLock);
            KeLeaveCriticalRegion();
            MgpReleaseReference(Generator);
            return STATUS_SUCCESS;
        }
    }

    ExReleasePushLockShared(&Generator->CacheLock);
    KeLeaveCriticalRegion();

    //
    // Generate header
    //
    Status = MgpStringBuilderInit(&Builder, MG_INITIAL_HDR_BUFFER_SIZE, MG_MAX_HDR_BUFFER_SIZE, MG_HDR_POOL_TAG);
    if (!NT_SUCCESS(Status)) {
        MgpReleaseReference(Generator);
        return Status;
    }

    //
    // Header preamble
    //
    Status = MgpGenerateHeaderPreamble(Generator, &Builder);
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    //
    // GUID definition
    //
    Status = MgpGenerateHeaderGuidDefinition(Generator, &Builder);
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    //
    // Event IDs
    //
    Status = MgpGenerateHeaderEventIds(Generator, &Builder);
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    //
    // Keywords
    //
    Status = MgpGenerateHeaderKeywords(Generator, &Builder);
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    //
    // Levels
    //
    Status = MgpGenerateHeaderLevels(Generator, &Builder);
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    //
    // Tasks
    //
    Status = MgpGenerateHeaderTasks(Generator, &Builder);
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    //
    // Footer
    //
    Status = MgpStringBuilderAppendFormat(&Builder,
        "\r\n#ifdef __cplusplus\r\n"
        "}\r\n"
        "#endif\r\n"
        "\r\n"
        "#endif // _%s_ETW_EVENTS_H_\r\n",
        Generator->ProviderSymbol
        );

    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    //
    // Steal builder buffer as output
    //
    OutputSize = Builder.Length;
    OutputBuffer = Builder.Buffer;
    Builder.Buffer = NULL;
    Builder.Length = 0;
    Builder.Capacity = 0;

    //
    // Update cache
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Generator->CacheLock);

    if (Generator->CachedHeader != NULL) {
        ExFreePoolWithTag(Generator->CachedHeader, MG_HDR_POOL_TAG);
        Generator->CachedHeader = NULL;
        Generator->CachedHeaderSize = 0;
        Generator->HeaderCacheValid = FALSE;
    }

    Generator->CachedHeader = (PCHAR)ExAllocatePool2(
        POOL_FLAG_PAGED,
        OutputSize + 1,
        MG_HDR_POOL_TAG
        );

    if (Generator->CachedHeader != NULL) {
        RtlCopyMemory(Generator->CachedHeader, OutputBuffer, OutputSize + 1);
        Generator->CachedHeaderSize = OutputSize;
        Generator->HeaderCacheValid = TRUE;
    }

    Generator->Stats.HeaderSize = OutputSize;

    ExReleasePushLockExclusive(&Generator->CacheLock);
    KeLeaveCriticalRegion();

    *HeaderContent = OutputBuffer;
    *ContentSize = OutputSize;
    Status = STATUS_SUCCESS;

Cleanup:
    MgpStringBuilderCleanup(&Builder);

    if (!NT_SUCCESS(Status) && OutputBuffer != NULL) {
        ExFreePoolWithTag(OutputBuffer, MG_HDR_POOL_TAG);
    }

    MgpReleaseReference(Generator);
    return Status;
}

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
MgGenerateMessageTable(
    _In_ PMG_GENERATOR Generator,
    _Outptr_result_buffer_(*ContentSize) PCHAR* MessageContent,
    _Out_ PSIZE_T ContentSize
    )
/*++
Routine Description:
    Generates message table resource script (.mc file).

Arguments:
    Generator - Generator instance.
    MessageContent - Receives pointer to message content.
    ContentSize - Receives size in bytes.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    NTSTATUS Status;
    MG_STRING_BUILDER Builder;
    PCHAR OutputBuffer = NULL;
    SIZE_T OutputSize;
    PLIST_ENTRY Entry;
    PMG_CHANNEL_DEFINITION Channel;
    PMG_KEYWORD_DEFINITION Keyword;
    PMG_TASK_DEFINITION Task;

    PAGED_CODE();

    if (MessageContent == NULL || ContentSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *MessageContent = NULL;
    *ContentSize = 0;

    Status = MgpAcquireReference(Generator);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = MgpStringBuilderInit(&Builder, MG_INITIAL_HDR_BUFFER_SIZE, MG_MAX_HDR_BUFFER_SIZE, MG_STR_POOL_TAG);
    if (!NT_SUCCESS(Status)) {
        MgpReleaseReference(Generator);
        return Status;
    }

    //
    // MC file header
    //
    Status = MgpStringBuilderAppendFormat(&Builder,
        ";// =============================================================================\r\n"
        ";// ShadowStrike NGAV - Message Table Resource\r\n"
        ";// =============================================================================\r\n"
        ";// Auto-generated by ManifestGenerator\r\n"
        ";// =============================================================================\r\n"
        "\r\n"
        "MessageIdTypedef=DWORD\r\n"
        "\r\n"
        "SeverityNames=(\r\n"
        "    Success=0x0:STATUS_SEVERITY_SUCCESS\r\n"
        "    Informational=0x1:STATUS_SEVERITY_INFORMATIONAL\r\n"
        "    Warning=0x2:STATUS_SEVERITY_WARNING\r\n"
        "    Error=0x3:STATUS_SEVERITY_ERROR\r\n"
        ")\r\n"
        "\r\n"
        "FacilityNames=(\r\n"
        "    System=0x0:FACILITY_SYSTEM\r\n"
        "    ShadowStrike=0x100:FACILITY_SHADOWSTRIKE\r\n"
        ")\r\n"
        "\r\n"
        "LanguageNames=(English=0x409:MSG00409)\r\n"
        "\r\n"
        );

    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    //
    // Channel messages
    //
    Status = MgpStringBuilderAppend(&Builder,
        ";// =============================================================================\r\n"
        ";// Channel Names\r\n"
        ";// =============================================================================\r\n"
        "\r\n"
        );

    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Generator->ChannelLock);

    for (Entry = Generator->ChannelList.Flink;
         Entry != &Generator->ChannelList;
         Entry = Entry->Flink) {

        Channel = CONTAINING_RECORD(Entry, MG_CHANNEL_DEFINITION, ListEntry);

        Status = MgpStringBuilderAppendFormat(&Builder,
            "MessageId=0x%08X\r\n"
            "Severity=Informational\r\n"
            "Facility=ShadowStrike\r\n"
            "SymbolicName=%s_CHANNEL_NAME\r\n"
            "Language=English\r\n"
            "%s\r\n"
            ".\r\n"
            "\r\n",
            Channel->MessageId,
            Channel->Symbol,
            Channel->Name
            );

        if (!NT_SUCCESS(Status)) {
            ExReleasePushLockShared(&Generator->ChannelLock);
            KeLeaveCriticalRegion();
            goto Cleanup;
        }
    }

    ExReleasePushLockShared(&Generator->ChannelLock);
    KeLeaveCriticalRegion();

    //
    // Keyword messages
    //
    Status = MgpStringBuilderAppend(&Builder,
        ";// =============================================================================\r\n"
        ";// Keyword Names\r\n"
        ";// =============================================================================\r\n"
        "\r\n"
        );

    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Generator->KeywordLock);

    for (Entry = Generator->KeywordList.Flink;
         Entry != &Generator->KeywordList;
         Entry = Entry->Flink) {

        Keyword = CONTAINING_RECORD(Entry, MG_KEYWORD_DEFINITION, ListEntry);

        Status = MgpStringBuilderAppendFormat(&Builder,
            "MessageId=0x%08X\r\n"
            "Severity=Informational\r\n"
            "Facility=ShadowStrike\r\n"
            "SymbolicName=%s_KEYWORD_NAME\r\n"
            "Language=English\r\n"
            "%s\r\n"
            ".\r\n"
            "\r\n",
            Keyword->MessageId,
            Keyword->Symbol,
            Keyword->Name
            );

        if (!NT_SUCCESS(Status)) {
            ExReleasePushLockShared(&Generator->KeywordLock);
            KeLeaveCriticalRegion();
            goto Cleanup;
        }
    }

    ExReleasePushLockShared(&Generator->KeywordLock);
    KeLeaveCriticalRegion();

    //
    // Task messages
    //
    Status = MgpStringBuilderAppend(&Builder,
        ";// =============================================================================\r\n"
        ";// Task Names\r\n"
        ";// =============================================================================\r\n"
        "\r\n"
        );

    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Generator->TaskLock);

    for (Entry = Generator->TaskList.Flink;
         Entry != &Generator->TaskList;
         Entry = Entry->Flink) {

        Task = CONTAINING_RECORD(Entry, MG_TASK_DEFINITION, ListEntry);

        Status = MgpStringBuilderAppendFormat(&Builder,
            "MessageId=0x%08X\r\n"
            "Severity=Informational\r\n"
            "Facility=ShadowStrike\r\n"
            "SymbolicName=%s_TASK_NAME\r\n"
            "Language=English\r\n"
            "%s\r\n"
            ".\r\n"
            "\r\n",
            Task->MessageId,
            Task->Symbol,
            Task->Name
            );

        if (!NT_SUCCESS(Status)) {
            ExReleasePushLockShared(&Generator->TaskLock);
            KeLeaveCriticalRegion();
            goto Cleanup;
        }
    }

    ExReleasePushLockShared(&Generator->TaskLock);
    KeLeaveCriticalRegion();

    //
    // Event messages from schema
    //
    Status = MgpStringBuilderAppend(&Builder,
        ";// =============================================================================\r\n"
        ";// Event Messages\r\n"
        ";// =============================================================================\r\n"
        "\r\n"
        );

    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    if (Generator->Schema != NULL) {
        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&Generator->Schema->EventLock);

        for (Entry = Generator->Schema->EventList.Flink;
             Entry != &Generator->Schema->EventList;
             Entry = Entry->Flink) {

            PES_EVENT_DEFINITION Event = CONTAINING_RECORD(Entry, ES_EVENT_DEFINITION, ListEntry);

            Status = MgpStringBuilderAppendFormat(&Builder,
                "MessageId=0x%08X\r\n"
                "Severity=Informational\r\n"
                "Facility=ShadowStrike\r\n"
                "SymbolicName=%s_EVENT_%s_MESSAGE\r\n"
                "Language=English\r\n"
                "%s\r\n"
                ".\r\n"
                "\r\n",
                MG_EVENT_MESSAGE_ID_OFFSET + Event->EventId,
                Generator->ProviderSymbol,
                Event->EventName,
                Event->Description[0] != '\0' ? Event->Description : Event->EventName
                );

            if (!NT_SUCCESS(Status)) {
                ExReleasePushLockShared(&Generator->Schema->EventLock);
                KeLeaveCriticalRegion();
                goto Cleanup;
            }
        }

        ExReleasePushLockShared(&Generator->Schema->EventLock);
        KeLeaveCriticalRegion();
    }

    //
    // Steal builder buffer as output
    //
    OutputSize = Builder.Length;
    OutputBuffer = Builder.Buffer;
    Builder.Buffer = NULL;
    Builder.Length = 0;
    Builder.Capacity = 0;

    *MessageContent = OutputBuffer;
    *ContentSize = OutputSize;
    Status = STATUS_SUCCESS;

Cleanup:
    MgpStringBuilderCleanup(&Builder);

    if (!NT_SUCCESS(Status) && OutputBuffer != NULL) {
        ExFreePoolWithTag(OutputBuffer, MG_STR_POOL_TAG);
    }

    MgpReleaseReference(Generator);
    return Status;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MgValidateSchema(
    _In_ PMG_GENERATOR Generator,
    _Out_ PULONG ErrorCount,
    _Outptr_opt_result_buffer_(*ErrorBufferSize) PCHAR* ErrorMessages,
    _Out_opt_ PSIZE_T ErrorBufferSize
    )
/*++
Routine Description:
    Validates the manifest schema consistency.

Arguments:
    Generator - Generator instance.
    ErrorCount - Receives number of validation errors.
    ErrorMessages - Optional: receives error message buffer.
    ErrorBufferSize - Receives size of error buffer.

Return Value:
    STATUS_SUCCESS if validation passes.
--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    MG_STRING_BUILDER ErrorBuilder = { 0 };
    ULONG Errors = 0;
    PLIST_ENTRY Entry, Entry2;
    PES_EVENT_DEFINITION Event, Event2;
    BOOLEAN BuilderInitialized = FALSE;

    PAGED_CODE();

    if (ErrorCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ErrorCount = 0;

    if (ErrorMessages != NULL) {
        *ErrorMessages = NULL;
    }

    if (ErrorBufferSize != NULL) {
        *ErrorBufferSize = 0;
    }

    Status = MgpAcquireReference(Generator);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Initialize error builder if needed
    //
    if (ErrorMessages != NULL) {
        Status = MgpStringBuilderInit(&ErrorBuilder, 4096, MG_MAX_HDR_BUFFER_SIZE, MG_STR_POOL_TAG);
        if (NT_SUCCESS(Status)) {
            BuilderInitialized = TRUE;
        }
    }

    //
    // Check for empty schema
    //
    if (Generator->Schema == NULL || Generator->Schema->EventCount == 0) {
        Errors++;
        if (BuilderInitialized) {
            MgpStringBuilderAppend(&ErrorBuilder, "ERROR: Schema is empty or NULL\r\n");
        }
    }

    //
    // Check for duplicate event IDs
    //
    if (Generator->Schema != NULL) {
        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&Generator->Schema->EventLock);

        for (Entry = Generator->Schema->EventList.Flink;
             Entry != &Generator->Schema->EventList;
             Entry = Entry->Flink) {

            Event = CONTAINING_RECORD(Entry, ES_EVENT_DEFINITION, ListEntry);

            for (Entry2 = Entry->Flink;
                 Entry2 != &Generator->Schema->EventList;
                 Entry2 = Entry2->Flink) {

                Event2 = CONTAINING_RECORD(Entry2, ES_EVENT_DEFINITION, ListEntry);

                if (Event->EventId == Event2->EventId) {
                    Errors++;
                    if (BuilderInitialized) {
                        MgpStringBuilderAppendFormat(&ErrorBuilder,
                            "ERROR: Duplicate event ID %u: '%s' and '%s'\r\n",
                            Event->EventId,
                            Event->EventName,
                            Event2->EventName
                            );
                    }
                }
            }

            //
            // Validate level
            //
            if (Event->Level > 5) {
                Errors++;
                if (BuilderInitialized) {
                    MgpStringBuilderAppendFormat(&ErrorBuilder,
                        "ERROR: Invalid level %u for event '%s' (must be 1-5)\r\n",
                        Event->Level,
                        Event->EventName
                        );
                }
            }
        }

        ExReleasePushLockShared(&Generator->Schema->EventLock);
        KeLeaveCriticalRegion();
    }

    //
    // Check for missing provider info
    //
    if (Generator->Schema != NULL && Generator->Schema->ProviderName[0] == '\0') {
        Errors++;
        if (BuilderInitialized) {
            MgpStringBuilderAppend(&ErrorBuilder, "WARNING: Provider name is empty\r\n");
        }
    }

    *ErrorCount = Errors;
    Generator->Stats.ValidationErrors = Errors;

    //
    // Return error messages if requested
    //
    if (BuilderInitialized && ErrorMessages != NULL && ErrorBufferSize != NULL) {
        if (ErrorBuilder.Length > 0) {
            PCHAR OutputBuffer = (PCHAR)ExAllocatePool2(
                POOL_FLAG_PAGED,
                ErrorBuilder.Length + 1,
                MG_STR_POOL_TAG
                );

            if (OutputBuffer != NULL) {
                RtlCopyMemory(OutputBuffer, ErrorBuilder.Buffer, ErrorBuilder.Length);
                OutputBuffer[ErrorBuilder.Length] = '\0';
                *ErrorMessages = OutputBuffer;
                *ErrorBufferSize = ErrorBuilder.Length;
            }
        }

        MgpStringBuilderCleanup(&ErrorBuilder);
    }

    MgpReleaseReference(Generator);
    return (Errors > 0) ? STATUS_INVALID_PARAMETER : STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MgGetStatistics(
    _In_ PMG_GENERATOR Generator,
    _Out_ PMG_GENERATION_STATS Stats
    )
/*++
Routine Description:
    Gets generation statistics.

Arguments:
    Generator - Generator instance.
    Stats - Receives statistics.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    NTSTATUS Status;

    PAGED_CODE();

    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Status = MgpAcquireReference(Generator);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    RtlCopyMemory(Stats, &Generator->Stats, sizeof(MG_GENERATION_STATS));

    Stats->ChannelCount = Generator->ChannelCount;
    Stats->TaskCount = Generator->TaskCount;
    Stats->KeywordCount = Generator->KeywordCount;
    Stats->OpcodeCount = Generator->OpcodeCount;

    if (Generator->Schema != NULL) {
        Stats->EventCount = Generator->Schema->EventCount;
    }

    MgpReleaseReference(Generator);
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID
MgInvalidateCache(
    _In_ PMG_GENERATOR Generator
    )
/*++
Routine Description:
    Invalidates cached content and frees stale buffers.
    Acquires CacheLock exclusive to prevent races with generation.

Arguments:
    Generator - Generator instance.
--*/
{
    PAGED_CODE();

    if (Generator == NULL) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Generator->CacheLock);

    Generator->ManifestCacheValid = FALSE;
    Generator->HeaderCacheValid = FALSE;

    if (Generator->CachedManifest != NULL) {
        ExFreePoolWithTag(Generator->CachedManifest, MG_XML_POOL_TAG);
        Generator->CachedManifest = NULL;
        Generator->CachedManifestSize = 0;
    }

    if (Generator->CachedHeader != NULL) {
        ExFreePoolWithTag(Generator->CachedHeader, MG_HDR_POOL_TAG);
        Generator->CachedHeader = NULL;
        Generator->CachedHeaderSize = 0;
    }

    ExReleasePushLockExclusive(&Generator->CacheLock);
    KeLeaveCriticalRegion();
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MgRegisterDefaultChannels(
    _In_ PMG_GENERATOR Generator
    )
/*++
Routine Description:
    Registers the default ShadowStrike event channels.

Arguments:
    Generator - Generator instance.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    NTSTATUS Status;
    MG_CHANNEL_DEFINITION Channel;

    PAGED_CODE();

    //
    // No explicit MgpAcquireReference needed — MgRegisterChannel handles ref counting.
    // Just validate the generator pointer.
    //
    if (Generator == NULL || !Generator->Initialized || Generator->ShuttingDown) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Operational channel
    //
    RtlZeroMemory(&Channel, sizeof(Channel));
    RtlStringCchCopyA(Channel.Name, MG_MAX_CHANNEL_NAME, "ShadowStrike-Security/Operational");
    RtlStringCchCopyA(Channel.Symbol, MG_MAX_CHANNEL_NAME, "CHANNEL_OPERATIONAL");
    Channel.Type = MgChannelOperational;
    Channel.Isolation = MgIsolationApplication;
    Channel.EnabledByDefault = TRUE;
    Channel.Value = 1;

    Status = MgRegisterChannel(Generator, &Channel);
    if (!NT_SUCCESS(Status) && Status != STATUS_DUPLICATE_NAME) {
        return Status;
    }

    //
    // Analytic channel
    //
    RtlZeroMemory(&Channel, sizeof(Channel));
    RtlStringCchCopyA(Channel.Name, MG_MAX_CHANNEL_NAME, "ShadowStrike-Security/Analytic");
    RtlStringCchCopyA(Channel.Symbol, MG_MAX_CHANNEL_NAME, "CHANNEL_ANALYTIC");
    Channel.Type = MgChannelAnalytic;
    Channel.Isolation = MgIsolationApplication;
    Channel.EnabledByDefault = FALSE;
    Channel.Value = 2;

    Status = MgRegisterChannel(Generator, &Channel);
    if (!NT_SUCCESS(Status) && Status != STATUS_DUPLICATE_NAME) {
        return Status;
    }

    //
    // Debug channel
    //
    RtlZeroMemory(&Channel, sizeof(Channel));
    RtlStringCchCopyA(Channel.Name, MG_MAX_CHANNEL_NAME, "ShadowStrike-Security/Debug");
    RtlStringCchCopyA(Channel.Symbol, MG_MAX_CHANNEL_NAME, "CHANNEL_DEBUG");
    Channel.Type = MgChannelDebug;
    Channel.Isolation = MgIsolationApplication;
    Channel.EnabledByDefault = FALSE;
    Channel.Value = 3;

    Status = MgRegisterChannel(Generator, &Channel);
    if (!NT_SUCCESS(Status) && Status != STATUS_DUPLICATE_NAME) {
        return Status;
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MgRegisterDefaultKeywords(
    _In_ PMG_GENERATOR Generator
    )
/*++
Routine Description:
    Registers the default ShadowStrike keywords.

Arguments:
    Generator - Generator instance.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    NTSTATUS Status;
    MG_KEYWORD_DEFINITION Keyword;

    PAGED_CODE();

    if (Generator == NULL || !Generator->Initialized || Generator->ShuttingDown) {
        return STATUS_INVALID_PARAMETER;
    }
    struct {
        PCSTR Name;
        PCSTR Symbol;
        ULONG64 Mask;
    } Keywords[] = {
        { "Process",        "KEYWORD_PROCESS",      0x0000000000000001ULL },
        { "Thread",         "KEYWORD_THREAD",       0x0000000000000002ULL },
        { "Image",          "KEYWORD_IMAGE",        0x0000000000000004ULL },
        { "File",           "KEYWORD_FILE",         0x0000000000000008ULL },
        { "Registry",       "KEYWORD_REGISTRY",     0x0000000000000010ULL },
        { "Memory",         "KEYWORD_MEMORY",       0x0000000000000020ULL },
        { "Network",        "KEYWORD_NETWORK",      0x0000000000000040ULL },
        { "Behavior",       "KEYWORD_BEHAVIOR",     0x0000000000000080ULL },
        { "Security",       "KEYWORD_SECURITY",     0x0000000000000100ULL },
        { "Diagnostic",     "KEYWORD_DIAGNOSTIC",   0x0000000000000200ULL },
        { "Threat",         "KEYWORD_THREAT",       0x0000000000000400ULL },
        { "Telemetry",      "KEYWORD_TELEMETRY",    0x0000000000000800ULL },
    };

    for (ULONG i = 0; i < ARRAYSIZE(Keywords); i++) {
        RtlZeroMemory(&Keyword, sizeof(Keyword));
        RtlStringCchCopyA(Keyword.Name, MG_MAX_KEYWORD_NAME, Keywords[i].Name);
        RtlStringCchCopyA(Keyword.Symbol, MG_MAX_KEYWORD_NAME, Keywords[i].Symbol);
        Keyword.Mask = Keywords[i].Mask;

        Status = MgRegisterKeyword(Generator, &Keyword);
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MgRegisterDefaultTasks(
    _In_ PMG_GENERATOR Generator
    )
/*++
Routine Description:
    Registers the default ShadowStrike tasks.

Arguments:
    Generator - Generator instance.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    NTSTATUS Status;
    MG_TASK_DEFINITION Task;

    PAGED_CODE();

    if (Generator == NULL || !Generator->Initialized || Generator->ShuttingDown) {
        return STATUS_INVALID_PARAMETER;
    }
    struct {
        PCSTR Name;
        PCSTR Symbol;
        USHORT Value;
    } Tasks[] = {
        { "ProcessEvents",      "TASK_PROCESS",     1 },
        { "ThreadEvents",       "TASK_THREAD",      2 },
        { "ImageEvents",        "TASK_IMAGE",       3 },
        { "FileEvents",         "TASK_FILE",        4 },
        { "RegistryEvents",     "TASK_REGISTRY",    5 },
        { "MemoryEvents",       "TASK_MEMORY",      6 },
        { "NetworkEvents",      "TASK_NETWORK",     7 },
        { "BehaviorEvents",     "TASK_BEHAVIOR",    8 },
        { "SecurityEvents",     "TASK_SECURITY",    9 },
        { "DiagnosticEvents",   "TASK_DIAGNOSTIC",  10 },
    };

    for (ULONG i = 0; i < ARRAYSIZE(Tasks); i++) {
        RtlZeroMemory(&Task, sizeof(Task));
        RtlStringCchCopyA(Task.Name, MG_MAX_TASK_NAME, Tasks[i].Name);
        RtlStringCchCopyA(Task.Symbol, MG_MAX_TASK_NAME, Tasks[i].Symbol);
        Task.Value = Tasks[i].Value;

        Status = MgRegisterTask(Generator, &Task);
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE FUNCTION IMPLEMENTATIONS
// ============================================================================

static NTSTATUS
MgpStringBuilderInit(
    _Out_ PMG_STRING_BUILDER Builder,
    _In_ SIZE_T InitialCapacity,
    _In_ SIZE_T MaxCapacity,
    _In_ ULONG PoolTag
    )
/*++
Routine Description:
    Initializes a string builder with bounded growth.
--*/
{
    RtlZeroMemory(Builder, sizeof(MG_STRING_BUILDER));

    Builder->Buffer = (PCHAR)ExAllocatePool2(
        POOL_FLAG_PAGED,
        InitialCapacity,
        PoolTag
        );

    if (Builder->Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Builder->Buffer[0] = '\0';
    Builder->Capacity = InitialCapacity;
    Builder->MaxCapacity = MaxCapacity;
    Builder->Length = 0;
    Builder->PoolTag = PoolTag;
    Builder->Overflow = FALSE;

    return STATUS_SUCCESS;
}

static VOID
MgpStringBuilderCleanup(
    _Inout_ PMG_STRING_BUILDER Builder
    )
/*++
Routine Description:
    Cleans up a string builder.
--*/
{
    if (Builder->Buffer != NULL) {
        ExFreePoolWithTag(Builder->Buffer, Builder->PoolTag);
        Builder->Buffer = NULL;
    }

    Builder->Length = 0;
    Builder->Capacity = 0;
}

static NTSTATUS
MgpStringBuilderEnsureCapacity(
    _Inout_ PMG_STRING_BUILDER Builder,
    _In_ SIZE_T RequiredCapacity
    )
/*++
Routine Description:
    Ensures the builder has enough capacity.
--*/
{
    SIZE_T NewCapacity;
    PCHAR NewBuffer;

    if (RequiredCapacity <= Builder->Capacity) {
        return STATUS_SUCCESS;
    }

    //
    // Calculate new capacity with growth factor
    //
    NewCapacity = Builder->Capacity * MG_STRING_BUILDER_GROWTH_FACTOR;
    if (NewCapacity < RequiredCapacity) {
        NewCapacity = RequiredCapacity + MG_MIN_BUFFER_GROWTH;
    }

    //
    // Check maximum size using per-builder limit
    //
    if (NewCapacity > Builder->MaxCapacity) {
        if (RequiredCapacity > Builder->MaxCapacity) {
            Builder->Overflow = TRUE;
            return STATUS_BUFFER_OVERFLOW;
        }
        NewCapacity = Builder->MaxCapacity;
    }

    //
    // Allocate new buffer
    //
    NewBuffer = (PCHAR)ExAllocatePool2(
        POOL_FLAG_PAGED,
        NewCapacity,
        Builder->PoolTag
        );

    if (NewBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Copy existing content
    //
    if (Builder->Length > 0) {
        RtlCopyMemory(NewBuffer, Builder->Buffer, Builder->Length + 1);
    } else {
        NewBuffer[0] = '\0';
    }

    //
    // Free old buffer and update
    //
    ExFreePoolWithTag(Builder->Buffer, Builder->PoolTag);
    Builder->Buffer = NewBuffer;
    Builder->Capacity = NewCapacity;

    return STATUS_SUCCESS;
}

static NTSTATUS
MgpStringBuilderAppend(
    _Inout_ PMG_STRING_BUILDER Builder,
    _In_z_ PCSTR String
    )
/*++
Routine Description:
    Appends a string to the builder.
--*/
{
    NTSTATUS Status;
    SIZE_T StringLength;
    SIZE_T RequiredCapacity;

    if (Builder->Overflow) {
        return STATUS_BUFFER_OVERFLOW;
    }

    StringLength = strlen(String);
    RequiredCapacity = Builder->Length + StringLength + 1;

    Status = MgpStringBuilderEnsureCapacity(Builder, RequiredCapacity);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    RtlCopyMemory(Builder->Buffer + Builder->Length, String, StringLength + 1);
    Builder->Length += StringLength;

    return STATUS_SUCCESS;
}

static NTSTATUS
MgpStringBuilderAppendFormat(
    _Inout_ PMG_STRING_BUILDER Builder,
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...
    )
/*++
Routine Description:
    Appends a formatted string to the builder.
--*/
{
    NTSTATUS Status;
    va_list Args;

    va_start(Args, Format);
    Status = MgpStringBuilderAppendFormatV(Builder, Format, Args);
    va_end(Args);

    return Status;
}

static NTSTATUS
MgpStringBuilderAppendFormatV(
    _Inout_ PMG_STRING_BUILDER Builder,
    _In_z_ PCSTR Format,
    _In_ va_list Args
    )
/*++
Routine Description:
    Appends a formatted string using va_list.
    Uses pool-allocated temp buffer to avoid consuming kernel stack.
--*/
{
    NTSTATUS Status;
    PCHAR TempBuffer;

    if (Builder->Overflow) {
        return STATUS_BUFFER_OVERFLOW;
    }

    TempBuffer = (PCHAR)ExAllocatePool2(
        POOL_FLAG_PAGED,
        MG_FORMAT_TEMP_BUFFER_SIZE,
        Builder->PoolTag
        );

    if (TempBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = RtlStringCchVPrintfA(
        TempBuffer,
        MG_FORMAT_TEMP_BUFFER_SIZE,
        Format,
        Args
        );

    if (NT_SUCCESS(Status)) {
        Status = MgpStringBuilderAppend(Builder, TempBuffer);
    }

    ExFreePoolWithTag(TempBuffer, Builder->PoolTag);
    return Status;
}

static NTSTATUS
MgpStringBuilderAppendIndent(
    _Inout_ PMG_STRING_BUILDER Builder,
    _In_ ULONG IndentLevel
    )
/*++
Routine Description:
    Appends indentation to the builder.
--*/
{
    NTSTATUS Status = STATUS_SUCCESS;

    if (IndentLevel > MG_MAX_INDENT_LEVEL) {
        IndentLevel = MG_MAX_INDENT_LEVEL;
    }

    for (ULONG i = 0; i < IndentLevel && NT_SUCCESS(Status); i++) {
        Status = MgpStringBuilderAppend(Builder, MG_XML_INDENT);
    }

    return Status;
}

static NTSTATUS
MgpAppendXmlEscaped(
    _Inout_ PMG_STRING_BUILDER Builder,
    _In_z_ PCSTR String
    )
/*++
Routine Description:
    Appends a string with XML escaping.
--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    PCSTR p;

    for (p = String; *p != '\0' && NT_SUCCESS(Status); p++) {
        switch (*p) {
        case '<':
            Status = MgpStringBuilderAppend(Builder, "&lt;");
            break;
        case '>':
            Status = MgpStringBuilderAppend(Builder, "&gt;");
            break;
        case '&':
            Status = MgpStringBuilderAppend(Builder, "&amp;");
            break;
        case '"':
            Status = MgpStringBuilderAppend(Builder, "&quot;");
            break;
        case '\'':
            Status = MgpStringBuilderAppend(Builder, "&apos;");
            break;
        default:
            {
                CHAR c[2] = { *p, '\0' };
                Status = MgpStringBuilderAppend(Builder, c);
            }
            break;
        }
    }

    return Status;
}

static NTSTATUS
MgpFormatGuid(
    _In_ PCGUID Guid,
    _Out_writes_(BufferSize) PCHAR Buffer,
    _In_ SIZE_T BufferSize
    )
/*++
Routine Description:
    Formats a GUID as a string.
--*/
{
    if (BufferSize < MG_GUID_STRING_LENGTH + 1) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return RtlStringCchPrintfA(
        Buffer,
        BufferSize,
        "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        Guid->Data1,
        Guid->Data2,
        Guid->Data3,
        Guid->Data4[0], Guid->Data4[1],
        Guid->Data4[2], Guid->Data4[3],
        Guid->Data4[4], Guid->Data4[5],
        Guid->Data4[6], Guid->Data4[7]
        );
}

static NTSTATUS
MgpGenerateProviderSection(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    )
/*++
Routine Description:
    Generates the provider section of the manifest.
--*/
{
    NTSTATUS Status;
    CHAR GuidString[MG_GUID_STRING_LENGTH + 1];
    PCGUID ProviderGuid;
    PCSTR ProviderName;

    //
    // Determine provider GUID and name
    //
    if (Generator->UseGuidOverride) {
        ProviderGuid = &Generator->ProviderGuidOverride;
    } else {
        ProviderGuid = &Generator->Schema->ProviderId;
    }

    if (Generator->ProviderNameOverride[0] != '\0') {
        ProviderName = Generator->ProviderNameOverride;
    } else {
        ProviderName = Generator->Schema->ProviderName;
    }

    //
    // Format GUID
    //
    Status = MgpFormatGuid(ProviderGuid, GuidString, sizeof(GuidString));
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Provider opening — escape all string attributes to prevent XML injection
    //
    Status = MgpStringBuilderAppend(Builder, "            <provider\r\n                name=\"");
    if (!NT_SUCCESS(Status)) return Status;

    Status = MgpAppendXmlEscaped(Builder, ProviderName);
    if (!NT_SUCCESS(Status)) return Status;

    Status = MgpStringBuilderAppendFormat(Builder,
        "\"\r\n"
        "                guid=\"%s\"\r\n"
        "                symbol=\"%s_PROVIDER\"\r\n"
        "                resourceFileName=\"",
        GuidString,
        Generator->ProviderSymbol
        );
    if (!NT_SUCCESS(Status)) return Status;

    Status = MgpAppendXmlEscaped(Builder, Generator->ResourceFile);
    if (!NT_SUCCESS(Status)) return Status;

    Status = MgpStringBuilderAppend(Builder, "\"\r\n                messageFileName=\"");
    if (!NT_SUCCESS(Status)) return Status;

    Status = MgpAppendXmlEscaped(Builder, Generator->MessageFile);
    if (!NT_SUCCESS(Status)) return Status;

    Status = MgpStringBuilderAppend(Builder, "\">\r\n\r\n");
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Generate sub-sections
    //
    Status = MgpGenerateChannelsSection(Generator, Builder);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = MgpGenerateLevelsSection(Generator, Builder);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = MgpGenerateTasksSection(Generator, Builder);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = MgpGenerateOpcodesSection(Generator, Builder);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = MgpGenerateKeywordsSection(Generator, Builder);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = MgpGenerateTemplatesSection(Generator, Builder);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = MgpGenerateEventsSection(Generator, Builder);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Provider closing
    //
    Status = MgpStringBuilderAppend(Builder,
        "            </provider>\r\n"
        );

    return Status;
}

static NTSTATUS
MgpGenerateChannelsSection(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    )
/*++
Routine Description:
    Generates the channels section of the manifest.
--*/
{
    NTSTATUS Status;
    PLIST_ENTRY Entry;
    PMG_CHANNEL_DEFINITION Channel;

    if (IsListEmpty(&Generator->ChannelList)) {
        return STATUS_SUCCESS;
    }

    Status = MgpStringBuilderAppend(Builder,
        "                <channels>\r\n"
        );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Generator->ChannelLock);

    for (Entry = Generator->ChannelList.Flink;
         Entry != &Generator->ChannelList;
         Entry = Entry->Flink) {

        Channel = CONTAINING_RECORD(Entry, MG_CHANNEL_DEFINITION, ListEntry);

        //
        // Defense-in-depth: bounds check enum values to prevent OOB read
        //
        if (Channel->Type > MG_MAX_CHANNEL_TYPE_VALUE ||
            Channel->Isolation > MG_MAX_ISOLATION_TYPE_VALUE) {
            Status = STATUS_INTERNAL_ERROR;
            break;
        }

        //
        // Build channel element with XML-escaped name attribute
        //
        Status = MgpStringBuilderAppend(Builder,
            "                    <channel\r\n"
            "                        name=\""
            );

        if (NT_SUCCESS(Status)) {
            Status = MgpAppendXmlEscaped(Builder, Channel->Name);
        }

        if (NT_SUCCESS(Status)) {
            Status = MgpStringBuilderAppendFormat(Builder,
                "\"\r\n"
                "                        chid=\"%s\"\r\n"
                "                        symbol=\"%s_%s\"\r\n"
                "                        type=\"%s\"\r\n"
                "                        isolation=\"%s\"\r\n"
                "                        enabled=\"%s\"\r\n"
                "                        message=\"$(string.Channel.%s)\"/>\r\n",
                Channel->Symbol,
                Generator->ProviderSymbol,
                Channel->Symbol,
                MgpChannelTypeStrings[Channel->Type],
                MgpIsolationTypeStrings[Channel->Isolation],
                Channel->EnabledByDefault ? "true" : "false",
                Channel->Symbol
                );
        }

        if (!NT_SUCCESS(Status)) {
            break;
        }
    }

    ExReleasePushLockShared(&Generator->ChannelLock);
    KeLeaveCriticalRegion();

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    return MgpStringBuilderAppend(Builder,
        "                </channels>\r\n"
        "\r\n"
        );
}

static NTSTATUS
MgpGenerateLevelsSection(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    )
/*++
Routine Description:
    Generates the levels section of the manifest.
--*/
{
    NTSTATUS Status;
    PLIST_ENTRY Entry;
    PMG_LEVEL_DEFINITION Level;

    if (IsListEmpty(&Generator->LevelList)) {
        return STATUS_SUCCESS;
    }

    Status = MgpStringBuilderAppend(Builder,
        "                <levels>\r\n"
        );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Generator->LevelLock);

    for (Entry = Generator->LevelList.Flink;
         Entry != &Generator->LevelList;
         Entry = Entry->Flink) {

        Level = CONTAINING_RECORD(Entry, MG_LEVEL_DEFINITION, ListEntry);

        Status = MgpStringBuilderAppendFormat(Builder,
            "                    <level\r\n"
            "                        name=\"%s\"\r\n"
            "                        symbol=\"%s_%s\"\r\n"
            "                        value=\"%u\"\r\n"
            "                        message=\"$(string.Level.%s)\"/>\r\n",
            Level->Name,
            Generator->ProviderSymbol,
            Level->Symbol,
            Level->Value,
            Level->Symbol
            );

        if (!NT_SUCCESS(Status)) {
            break;
        }
    }

    ExReleasePushLockShared(&Generator->LevelLock);
    KeLeaveCriticalRegion();

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    return MgpStringBuilderAppend(Builder,
        "                </levels>\r\n"
        "\r\n"
        );
}

static NTSTATUS
MgpGenerateTasksSection(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    )
/*++
Routine Description:
    Generates the tasks section of the manifest.
--*/
{
    NTSTATUS Status;
    PLIST_ENTRY Entry;
    PMG_TASK_DEFINITION Task;

    if (IsListEmpty(&Generator->TaskList)) {
        return STATUS_SUCCESS;
    }

    Status = MgpStringBuilderAppend(Builder,
        "                <tasks>\r\n"
        );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Generator->TaskLock);

    for (Entry = Generator->TaskList.Flink;
         Entry != &Generator->TaskList;
         Entry = Entry->Flink) {

        Task = CONTAINING_RECORD(Entry, MG_TASK_DEFINITION, ListEntry);

        Status = MgpStringBuilderAppendFormat(Builder,
            "                    <task\r\n"
            "                        name=\"%s\"\r\n"
            "                        symbol=\"%s_%s\"\r\n"
            "                        value=\"%u\"\r\n"
            "                        message=\"$(string.Task.%s)\"/>\r\n",
            Task->Name,
            Generator->ProviderSymbol,
            Task->Symbol,
            Task->Value,
            Task->Symbol
            );

        if (!NT_SUCCESS(Status)) {
            break;
        }
    }

    ExReleasePushLockShared(&Generator->TaskLock);
    KeLeaveCriticalRegion();

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    return MgpStringBuilderAppend(Builder,
        "                </tasks>\r\n"
        "\r\n"
        );
}

static NTSTATUS
MgpGenerateOpcodesSection(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    )
/*++
Routine Description:
    Generates the opcodes section of the manifest.
--*/
{
    NTSTATUS Status;
    PLIST_ENTRY Entry;
    PMG_OPCODE_DEFINITION Opcode;

    if (IsListEmpty(&Generator->OpcodeList)) {
        return STATUS_SUCCESS;
    }

    Status = MgpStringBuilderAppend(Builder,
        "                <opcodes>\r\n"
        );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Generator->OpcodeLock);

    for (Entry = Generator->OpcodeList.Flink;
         Entry != &Generator->OpcodeList;
         Entry = Entry->Flink) {

        Opcode = CONTAINING_RECORD(Entry, MG_OPCODE_DEFINITION, ListEntry);

        Status = MgpStringBuilderAppendFormat(Builder,
            "                    <opcode\r\n"
            "                        name=\"%s\"\r\n"
            "                        symbol=\"%s_%s\"\r\n"
            "                        value=\"%u\"\r\n"
            "                        message=\"$(string.Opcode.%s)\"/>\r\n",
            Opcode->Name,
            Generator->ProviderSymbol,
            Opcode->Symbol,
            Opcode->Value,
            Opcode->Symbol
            );

        if (!NT_SUCCESS(Status)) {
            break;
        }
    }

    ExReleasePushLockShared(&Generator->OpcodeLock);
    KeLeaveCriticalRegion();

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    return MgpStringBuilderAppend(Builder,
        "                </opcodes>\r\n"
        "\r\n"
        );
}

static NTSTATUS
MgpGenerateKeywordsSection(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    )
/*++
Routine Description:
    Generates the keywords section of the manifest.
--*/
{
    NTSTATUS Status;
    PLIST_ENTRY Entry;
    PMG_KEYWORD_DEFINITION Keyword;

    if (IsListEmpty(&Generator->KeywordList)) {
        return STATUS_SUCCESS;
    }

    Status = MgpStringBuilderAppend(Builder,
        "                <keywords>\r\n"
        );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Generator->KeywordLock);

    for (Entry = Generator->KeywordList.Flink;
         Entry != &Generator->KeywordList;
         Entry = Entry->Flink) {

        Keyword = CONTAINING_RECORD(Entry, MG_KEYWORD_DEFINITION, ListEntry);

        Status = MgpStringBuilderAppendFormat(Builder,
            "                    <keyword\r\n"
            "                        name=\"%s\"\r\n"
            "                        symbol=\"%s_%s\"\r\n"
            "                        mask=\"0x%016llX\"\r\n"
            "                        message=\"$(string.Keyword.%s)\"/>\r\n",
            Keyword->Name,
            Generator->ProviderSymbol,
            Keyword->Symbol,
            Keyword->Mask,
            Keyword->Symbol
            );

        if (!NT_SUCCESS(Status)) {
            break;
        }
    }

    ExReleasePushLockShared(&Generator->KeywordLock);
    KeLeaveCriticalRegion();

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    return MgpStringBuilderAppend(Builder,
        "                </keywords>\r\n"
        "\r\n"
        );
}

static NTSTATUS
MgpGenerateTemplatesSection(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    )
/*++
Routine Description:
    Generates the templates section of the manifest.
--*/
{
    NTSTATUS Status;
    PLIST_ENTRY Entry;
    PES_EVENT_DEFINITION Event;
    ULONG TemplateCount = 0;

    if (Generator->Schema == NULL || Generator->Schema->EventCount == 0) {
        return STATUS_SUCCESS;
    }

    Status = MgpStringBuilderAppend(Builder,
        "                <templates>\r\n"
        );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Generator->Schema->EventLock);

    for (Entry = Generator->Schema->EventList.Flink;
         Entry != &Generator->Schema->EventList;
         Entry = Entry->Flink) {

        Event = CONTAINING_RECORD(Entry, ES_EVENT_DEFINITION, ListEntry);

        if (Event->FieldCount == 0) {
            continue;
        }

        Status = MgpStringBuilderAppendFormat(Builder,
            "                    <template tid=\"%s%s\">\r\n",
            MG_TEMPLATE_NAME_PREFIX,
            Event->EventName
            );

        if (!NT_SUCCESS(Status)) {
            break;
        }

        //
        // Generate fields
        //
        for (ULONG i = 0; i < Event->FieldCount; i++) {
            PES_FIELD_DEFINITION Field = &Event->Fields[i];
            PCSTR InType = "win:UnicodeString";

            if (Field->Type < MG_FIELD_TYPE_COUNT) {
                InType = MgpFieldTypeToInType[Field->Type];
            }

            Status = MgpStringBuilderAppend(Builder,
                "                        <data name=\""
                );

            if (NT_SUCCESS(Status)) {
                Status = MgpAppendXmlEscaped(Builder, Field->FieldName);
            }

            if (NT_SUCCESS(Status)) {
                Status = MgpStringBuilderAppendFormat(Builder,
                    "\" inType=\"%s\"/>\r\n",
                    InType
                    );
            }

            if (!NT_SUCCESS(Status)) {
                break;
            }
        }

        if (!NT_SUCCESS(Status)) {
            break;
        }

        Status = MgpStringBuilderAppend(Builder,
            "                    </template>\r\n"
            );

        if (!NT_SUCCESS(Status)) {
            break;
        }

        TemplateCount++;
    }

    ExReleasePushLockShared(&Generator->Schema->EventLock);
    KeLeaveCriticalRegion();

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Generator->Stats.TemplateCount = TemplateCount;

    return MgpStringBuilderAppend(Builder,
        "                </templates>\r\n"
        "\r\n"
        );
}

static NTSTATUS
MgpGenerateEventsSection(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    )
/*++
Routine Description:
    Generates the events section of the manifest.
--*/
{
    NTSTATUS Status;
    PLIST_ENTRY Entry;
    PES_EVENT_DEFINITION Event;
    ULONG EventCount = 0;

    if (Generator->Schema == NULL || Generator->Schema->EventCount == 0) {
        return STATUS_SUCCESS;
    }

    Status = MgpStringBuilderAppend(Builder,
        "                <events>\r\n"
        );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Generator->Schema->EventLock);

    for (Entry = Generator->Schema->EventList.Flink;
         Entry != &Generator->Schema->EventList;
         Entry = Entry->Flink) {

        Event = CONTAINING_RECORD(Entry, ES_EVENT_DEFINITION, ListEntry);

        Status = MgpStringBuilderAppendFormat(Builder,
            "                    <event\r\n"
            "                        value=\"%u\"\r\n"
            "                        symbol=\"%s_EVENT_%s\"\r\n"
            "                        level=\"win:Level%u\"\r\n"
            "                        keywords=\"0x%016llX\"\r\n",
            Event->EventId,
            Generator->ProviderSymbol,
            Event->EventName,
            Event->Level,
            Event->Keywords
            );

        if (!NT_SUCCESS(Status)) {
            break;
        }

        //
        // Add template reference if event has fields
        //
        if (Event->FieldCount > 0) {
            Status = MgpStringBuilderAppendFormat(Builder,
                "                        template=\"%s%s\"\r\n",
                MG_TEMPLATE_NAME_PREFIX,
                Event->EventName
                );

            if (!NT_SUCCESS(Status)) {
                break;
            }
        }

        //
        // Add channel reference if specified
        //
        if (Event->ChannelName[0] != '\0') {
            Status = MgpStringBuilderAppend(Builder,
                "                        channel=\""
                );

            if (NT_SUCCESS(Status)) {
                Status = MgpAppendXmlEscaped(Builder, Event->ChannelName);
            }

            if (NT_SUCCESS(Status)) {
                Status = MgpStringBuilderAppend(Builder, "\"\r\n");
            }

            if (!NT_SUCCESS(Status)) {
                break;
            }
        }

        Status = MgpStringBuilderAppendFormat(Builder,
            "                        message=\"$(string.Event.%s)\"/>\r\n",
            Event->EventName
            );

        if (!NT_SUCCESS(Status)) {
            break;
        }

        EventCount++;
    }

    ExReleasePushLockShared(&Generator->Schema->EventLock);
    KeLeaveCriticalRegion();

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Generator->Stats.EventCount = EventCount;

    return MgpStringBuilderAppend(Builder,
        "                </events>\r\n"
        "\r\n"
        );
}

static NTSTATUS
MgpGenerateStringTableSection(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    )
/*++
Routine Description:
    Generates the localization/stringTable section of the manifest.
    This section is REQUIRED for all $(string.*) references used in
    channels, levels, tasks, opcodes, keywords, and events.
--*/
{
    NTSTATUS Status;
    PLIST_ENTRY Entry;
    PMG_CHANNEL_DEFINITION Channel;
    PMG_LEVEL_DEFINITION Level;
    PMG_TASK_DEFINITION Task;
    PMG_OPCODE_DEFINITION Opcode;
    PMG_KEYWORD_DEFINITION Keyword;
    PES_EVENT_DEFINITION Event;

    //
    // Close provider and events, then open localization section
    //
    Status = MgpStringBuilderAppend(Builder,
        "\r\n"
        "    <localization>\r\n"
        "        <resources culture=\"en-US\">\r\n"
        "            <stringTable>\r\n"
        );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Channel strings
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Generator->ChannelLock);

    for (Entry = Generator->ChannelList.Flink;
         Entry != &Generator->ChannelList;
         Entry = Entry->Flink) {

        Channel = CONTAINING_RECORD(Entry, MG_CHANNEL_DEFINITION, ListEntry);

        Status = MgpStringBuilderAppendFormat(Builder,
            "                <string id=\"Channel.%s\" value=\"",
            Channel->Symbol
            );

        if (NT_SUCCESS(Status)) {
            Status = MgpAppendXmlEscaped(Builder, Channel->Name);
        }

        if (NT_SUCCESS(Status)) {
            Status = MgpStringBuilderAppend(Builder, "\"/>\r\n");
        }

        if (!NT_SUCCESS(Status)) {
            break;
        }
    }

    ExReleasePushLockShared(&Generator->ChannelLock);
    KeLeaveCriticalRegion();

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Level strings
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Generator->LevelLock);

    for (Entry = Generator->LevelList.Flink;
         Entry != &Generator->LevelList;
         Entry = Entry->Flink) {

        Level = CONTAINING_RECORD(Entry, MG_LEVEL_DEFINITION, ListEntry);

        Status = MgpStringBuilderAppendFormat(Builder,
            "                <string id=\"Level.%s\" value=\"",
            Level->Symbol
            );

        if (NT_SUCCESS(Status)) {
            Status = MgpAppendXmlEscaped(Builder, Level->Name);
        }

        if (NT_SUCCESS(Status)) {
            Status = MgpStringBuilderAppend(Builder, "\"/>\r\n");
        }

        if (!NT_SUCCESS(Status)) {
            break;
        }
    }

    ExReleasePushLockShared(&Generator->LevelLock);
    KeLeaveCriticalRegion();

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Task strings
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Generator->TaskLock);

    for (Entry = Generator->TaskList.Flink;
         Entry != &Generator->TaskList;
         Entry = Entry->Flink) {

        Task = CONTAINING_RECORD(Entry, MG_TASK_DEFINITION, ListEntry);

        Status = MgpStringBuilderAppendFormat(Builder,
            "                <string id=\"Task.%s\" value=\"",
            Task->Symbol
            );

        if (NT_SUCCESS(Status)) {
            Status = MgpAppendXmlEscaped(Builder, Task->Name);
        }

        if (NT_SUCCESS(Status)) {
            Status = MgpStringBuilderAppend(Builder, "\"/>\r\n");
        }

        if (!NT_SUCCESS(Status)) {
            break;
        }
    }

    ExReleasePushLockShared(&Generator->TaskLock);
    KeLeaveCriticalRegion();

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Opcode strings
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Generator->OpcodeLock);

    for (Entry = Generator->OpcodeList.Flink;
         Entry != &Generator->OpcodeList;
         Entry = Entry->Flink) {

        Opcode = CONTAINING_RECORD(Entry, MG_OPCODE_DEFINITION, ListEntry);

        Status = MgpStringBuilderAppendFormat(Builder,
            "                <string id=\"Opcode.%s\" value=\"",
            Opcode->Symbol
            );

        if (NT_SUCCESS(Status)) {
            Status = MgpAppendXmlEscaped(Builder, Opcode->Name);
        }

        if (NT_SUCCESS(Status)) {
            Status = MgpStringBuilderAppend(Builder, "\"/>\r\n");
        }

        if (!NT_SUCCESS(Status)) {
            break;
        }
    }

    ExReleasePushLockShared(&Generator->OpcodeLock);
    KeLeaveCriticalRegion();

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Keyword strings
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Generator->KeywordLock);

    for (Entry = Generator->KeywordList.Flink;
         Entry != &Generator->KeywordList;
         Entry = Entry->Flink) {

        Keyword = CONTAINING_RECORD(Entry, MG_KEYWORD_DEFINITION, ListEntry);

        Status = MgpStringBuilderAppendFormat(Builder,
            "                <string id=\"Keyword.%s\" value=\"",
            Keyword->Symbol
            );

        if (NT_SUCCESS(Status)) {
            Status = MgpAppendXmlEscaped(Builder, Keyword->Name);
        }

        if (NT_SUCCESS(Status)) {
            Status = MgpStringBuilderAppend(Builder, "\"/>\r\n");
        }

        if (!NT_SUCCESS(Status)) {
            break;
        }
    }

    ExReleasePushLockShared(&Generator->KeywordLock);
    KeLeaveCriticalRegion();

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Event strings from schema
    //
    if (Generator->Schema != NULL && Generator->Schema->EventCount > 0) {
        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&Generator->Schema->EventLock);

        for (Entry = Generator->Schema->EventList.Flink;
             Entry != &Generator->Schema->EventList;
             Entry = Entry->Flink) {

            Event = CONTAINING_RECORD(Entry, ES_EVENT_DEFINITION, ListEntry);

            Status = MgpStringBuilderAppendFormat(Builder,
                "                <string id=\"Event.%s\" value=\"",
                Event->EventName
                );

            if (NT_SUCCESS(Status)) {
                PCSTR Desc = (Event->Description[0] != '\0') ? Event->Description : Event->EventName;
                Status = MgpAppendXmlEscaped(Builder, Desc);
            }

            if (NT_SUCCESS(Status)) {
                Status = MgpStringBuilderAppend(Builder, "\"/>\r\n");
            }

            if (!NT_SUCCESS(Status)) {
                break;
            }
        }

        ExReleasePushLockShared(&Generator->Schema->EventLock);
        KeLeaveCriticalRegion();

        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }

    //
    // Close localization section
    //
    Status = MgpStringBuilderAppend(Builder,
        "            </stringTable>\r\n"
        "        </resources>\r\n"
        "    </localization>\r\n"
        );

    return Status;
}

static NTSTATUS
MgpGenerateHeaderPreamble(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    )
/*++
Routine Description:
    Generates the header file preamble.
--*/
{
    return MgpStringBuilderAppendFormat(Builder,
        "/*++\r\n"
        "===============================================================================\r\n"
        "ShadowStrike NGAV - ETW Event Definitions\r\n"
        "===============================================================================\r\n"
        "\r\n"
        "Auto-generated by ManifestGenerator\r\n"
        "DO NOT EDIT MANUALLY\r\n"
        "\r\n"
        "@copyright (c) 2026 ShadowStrike Security. All rights reserved.\r\n"
        "===============================================================================\r\n"
        "--*/\r\n"
        "\r\n"
        "#ifndef _%s_ETW_EVENTS_H_\r\n"
        "#define _%s_ETW_EVENTS_H_\r\n"
        "\r\n"
        "#ifdef __cplusplus\r\n"
        "extern \"C\" {\r\n"
        "#endif\r\n"
        "\r\n"
        "#include <evntprov.h>\r\n"
        "\r\n",
        Generator->ProviderSymbol,
        Generator->ProviderSymbol
        );
}

static NTSTATUS
MgpGenerateHeaderGuidDefinition(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    )
/*++
Routine Description:
    Generates the GUID definition in the header.
--*/
{
    PCGUID ProviderGuid;

    if (Generator->UseGuidOverride) {
        ProviderGuid = &Generator->ProviderGuidOverride;
    } else {
        ProviderGuid = &Generator->Schema->ProviderId;
    }

    return MgpStringBuilderAppendFormat(Builder,
        "// =============================================================================\r\n"
        "// Provider GUID\r\n"
        "// =============================================================================\r\n"
        "\r\n"
        "// {%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}\r\n"
        "DEFINE_GUID(%s_PROVIDER_GUID,\r\n"
        "    0x%08X, 0x%04X, 0x%04X,\r\n"
        "    0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X);\r\n"
        "\r\n",
        ProviderGuid->Data1, ProviderGuid->Data2, ProviderGuid->Data3,
        ProviderGuid->Data4[0], ProviderGuid->Data4[1],
        ProviderGuid->Data4[2], ProviderGuid->Data4[3],
        ProviderGuid->Data4[4], ProviderGuid->Data4[5],
        ProviderGuid->Data4[6], ProviderGuid->Data4[7],
        Generator->ProviderSymbol,
        ProviderGuid->Data1, ProviderGuid->Data2, ProviderGuid->Data3,
        ProviderGuid->Data4[0], ProviderGuid->Data4[1],
        ProviderGuid->Data4[2], ProviderGuid->Data4[3],
        ProviderGuid->Data4[4], ProviderGuid->Data4[5],
        ProviderGuid->Data4[6], ProviderGuid->Data4[7]
        );
}

static NTSTATUS
MgpGenerateHeaderEventIds(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    )
/*++
Routine Description:
    Generates event ID enumeration in the header.
--*/
{
    NTSTATUS Status;
    PLIST_ENTRY Entry;
    PES_EVENT_DEFINITION Event;

    Status = MgpStringBuilderAppend(Builder,
        "// =============================================================================\r\n"
        "// Event IDs\r\n"
        "// =============================================================================\r\n"
        "\r\n"
        );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    if (Generator->Schema == NULL || Generator->Schema->EventCount == 0) {
        return STATUS_SUCCESS;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Generator->Schema->EventLock);

    for (Entry = Generator->Schema->EventList.Flink;
         Entry != &Generator->Schema->EventList;
         Entry = Entry->Flink) {

        Event = CONTAINING_RECORD(Entry, ES_EVENT_DEFINITION, ListEntry);

        Status = MgpStringBuilderAppendFormat(Builder,
            "#define %s_EVENT_%s    %u\r\n",
            Generator->ProviderSymbol,
            Event->EventName,
            Event->EventId
            );

        if (!NT_SUCCESS(Status)) {
            break;
        }
    }

    ExReleasePushLockShared(&Generator->Schema->EventLock);
    KeLeaveCriticalRegion();

    if (NT_SUCCESS(Status)) {
        Status = MgpStringBuilderAppend(Builder, "\r\n");
    }

    return Status;
}

static NTSTATUS
MgpGenerateHeaderKeywords(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    )
/*++
Routine Description:
    Generates keyword definitions in the header.
--*/
{
    NTSTATUS Status;
    PLIST_ENTRY Entry;
    PMG_KEYWORD_DEFINITION Keyword;

    Status = MgpStringBuilderAppend(Builder,
        "// =============================================================================\r\n"
        "// Keywords\r\n"
        "// =============================================================================\r\n"
        "\r\n"
        );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    if (IsListEmpty(&Generator->KeywordList)) {
        return STATUS_SUCCESS;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Generator->KeywordLock);

    for (Entry = Generator->KeywordList.Flink;
         Entry != &Generator->KeywordList;
         Entry = Entry->Flink) {

        Keyword = CONTAINING_RECORD(Entry, MG_KEYWORD_DEFINITION, ListEntry);

        Status = MgpStringBuilderAppendFormat(Builder,
            "#define %s_%s    0x%016llXULL\r\n",
            Generator->ProviderSymbol,
            Keyword->Symbol,
            Keyword->Mask
            );

        if (!NT_SUCCESS(Status)) {
            break;
        }
    }

    ExReleasePushLockShared(&Generator->KeywordLock);
    KeLeaveCriticalRegion();

    if (NT_SUCCESS(Status)) {
        Status = MgpStringBuilderAppend(Builder, "\r\n");
    }

    return Status;
}

static NTSTATUS
MgpGenerateHeaderLevels(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    )
/*++
Routine Description:
    Generates level definitions in the header.
--*/
{
    NTSTATUS Status;
    PLIST_ENTRY Entry;
    PMG_LEVEL_DEFINITION Level;

    Status = MgpStringBuilderAppend(Builder,
        "// =============================================================================\r\n"
        "// Levels\r\n"
        "// =============================================================================\r\n"
        "\r\n"
        );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    if (IsListEmpty(&Generator->LevelList)) {
        return STATUS_SUCCESS;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Generator->LevelLock);

    for (Entry = Generator->LevelList.Flink;
         Entry != &Generator->LevelList;
         Entry = Entry->Flink) {

        Level = CONTAINING_RECORD(Entry, MG_LEVEL_DEFINITION, ListEntry);

        Status = MgpStringBuilderAppendFormat(Builder,
            "#define %s_%s    %u\r\n",
            Generator->ProviderSymbol,
            Level->Symbol,
            Level->Value
            );

        if (!NT_SUCCESS(Status)) {
            break;
        }
    }

    ExReleasePushLockShared(&Generator->LevelLock);
    KeLeaveCriticalRegion();

    if (NT_SUCCESS(Status)) {
        Status = MgpStringBuilderAppend(Builder, "\r\n");
    }

    return Status;
}

static NTSTATUS
MgpGenerateHeaderTasks(
    _In_ PMG_GENERATOR Generator,
    _Inout_ PMG_STRING_BUILDER Builder
    )
/*++
Routine Description:
    Generates task definitions in the header.
--*/
{
    NTSTATUS Status;
    PLIST_ENTRY Entry;
    PMG_TASK_DEFINITION Task;

    Status = MgpStringBuilderAppend(Builder,
        "// =============================================================================\r\n"
        "// Tasks\r\n"
        "// =============================================================================\r\n"
        "\r\n"
        );

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    if (IsListEmpty(&Generator->TaskList)) {
        return STATUS_SUCCESS;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Generator->TaskLock);

    for (Entry = Generator->TaskList.Flink;
         Entry != &Generator->TaskList;
         Entry = Entry->Flink) {

        Task = CONTAINING_RECORD(Entry, MG_TASK_DEFINITION, ListEntry);

        Status = MgpStringBuilderAppendFormat(Builder,
            "#define %s_%s    %u\r\n",
            Generator->ProviderSymbol,
            Task->Symbol,
            Task->Value
            );

        if (!NT_SUCCESS(Status)) {
            break;
        }
    }

    ExReleasePushLockShared(&Generator->TaskLock);
    KeLeaveCriticalRegion();

    if (NT_SUCCESS(Status)) {
        Status = MgpStringBuilderAppend(Builder, "\r\n");
    }

    return Status;
}

static NTSTATUS
MgpRegisterDefaultLevels(
    _In_ PMG_GENERATOR Generator
    )
/*++
Routine Description:
    Registers the default ETW levels.
    Called ONLY from MgInitialize before the generator is published,
    so no lock acquisition is needed (single-threaded context).
--*/
{
    PMG_LEVEL_DEFINITION Level;

    struct {
        PCSTR Name;
        PCSTR Symbol;
        UCHAR Value;
    } Levels[] = {
        { "Critical",       "LEVEL_CRITICAL",       1 },
        { "Error",          "LEVEL_ERROR",          2 },
        { "Warning",        "LEVEL_WARNING",        3 },
        { "Informational",  "LEVEL_INFO",           4 },
        { "Verbose",        "LEVEL_VERBOSE",        5 },
    };

    for (ULONG i = 0; i < ARRAYSIZE(Levels); i++) {
        Level = (PMG_LEVEL_DEFINITION)ExAllocatePool2(
            POOL_FLAG_PAGED,
            sizeof(MG_LEVEL_DEFINITION),
            MG_LVL_POOL_TAG
            );

        if (Level == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlStringCchCopyA(Level->Name, sizeof(Level->Name), Levels[i].Name);
        RtlStringCchCopyA(Level->Symbol, sizeof(Level->Symbol), Levels[i].Symbol);
        Level->Value = Levels[i].Value;
        Level->MessageId = (ULONG)InterlockedIncrement(&Generator->NextMessageId);

        InitializeListHead(&Level->ListEntry);
        InsertTailList(&Generator->LevelList, &Level->ListEntry);
        Generator->LevelCount++;
    }

    return STATUS_SUCCESS;
}

static VOID
MgpFreeChannelList(
    _Inout_ PLIST_ENTRY ListHead
    )
{
    PLIST_ENTRY Entry;
    PMG_CHANNEL_DEFINITION Channel;

    while (!IsListEmpty(ListHead)) {
        Entry = RemoveHeadList(ListHead);
        Channel = CONTAINING_RECORD(Entry, MG_CHANNEL_DEFINITION, ListEntry);
        ExFreePoolWithTag(Channel, MG_CHN_POOL_TAG);
    }
}

static VOID
MgpFreeTaskList(
    _Inout_ PLIST_ENTRY ListHead
    )
{
    PLIST_ENTRY Entry;
    PMG_TASK_DEFINITION Task;

    while (!IsListEmpty(ListHead)) {
        Entry = RemoveHeadList(ListHead);
        Task = CONTAINING_RECORD(Entry, MG_TASK_DEFINITION, ListEntry);
        ExFreePoolWithTag(Task, MG_TSK_POOL_TAG);
    }
}

static VOID
MgpFreeKeywordList(
    _Inout_ PLIST_ENTRY ListHead
    )
{
    PLIST_ENTRY Entry;
    PMG_KEYWORD_DEFINITION Keyword;

    while (!IsListEmpty(ListHead)) {
        Entry = RemoveHeadList(ListHead);
        Keyword = CONTAINING_RECORD(Entry, MG_KEYWORD_DEFINITION, ListEntry);
        ExFreePoolWithTag(Keyword, MG_KWD_POOL_TAG);
    }
}

static VOID
MgpFreeOpcodeList(
    _Inout_ PLIST_ENTRY ListHead
    )
{
    PLIST_ENTRY Entry;
    PMG_OPCODE_DEFINITION Opcode;

    while (!IsListEmpty(ListHead)) {
        Entry = RemoveHeadList(ListHead);
        Opcode = CONTAINING_RECORD(Entry, MG_OPCODE_DEFINITION, ListEntry);
        ExFreePoolWithTag(Opcode, MG_OPC_POOL_TAG);
    }
}

static VOID
MgpFreeLevelList(
    _Inout_ PLIST_ENTRY ListHead
    )
{
    PLIST_ENTRY Entry;
    PMG_LEVEL_DEFINITION Level;

    while (!IsListEmpty(ListHead)) {
        Entry = RemoveHeadList(ListHead);
        Level = CONTAINING_RECORD(Entry, MG_LEVEL_DEFINITION, ListEntry);
        ExFreePoolWithTag(Level, MG_LVL_POOL_TAG);
    }
}
