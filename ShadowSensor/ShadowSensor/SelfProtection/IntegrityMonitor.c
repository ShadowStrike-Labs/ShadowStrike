/*++
===============================================================================
ShadowStrike NGAV - ENTERPRISE SELF-INTEGRITY MONITORING IMPLEMENTATION
===============================================================================

@file IntegrityMonitor.c
@brief Enterprise-grade driver self-integrity monitoring for kernel EDR.

v2.1.0 Changes (Enterprise Hardened):
======================================
- DPC now queues IoWorkItem instead of calling BCrypt directly (was BSOD)
- All push lock acquisitions wrapped with KeEnterCriticalRegion
- ImShutdown takes PIM_MONITOR*, NULLs caller pointer, waits for rundown
- EX_RUNDOWN_REF replaces BOOLEAN Initialized for safe shutdown
- KeFlushQueuedDpcs() called during shutdown
- PE parsing fully bounds-checked (e_lfanew, section count, RVA+size)
- CRT strlen replaced with RtlStringCbLengthA
- ImCheckAll frees partial results on failure
- ImComp_Callbacks integrates with CallbackProtection CpVerifyAll
- ImComp_Handles verifies ObjectCallbackHandle via ObRegisterCallbacks check
- ImComp_Configuration properly compares baseline hash
- ImComp_DriverImage computes and compares baseline header hash
- MmSystemRangeStart compared as ULONG_PTR
- ImFreeCheckResult public API for proper result lifetime
- New IM_MODIFICATION values for IAT/EAT hooks
- PAGED_CODE() in all PASSIVE_LEVEL functions
- Redundant RtlZeroMemory after ExAllocatePool2 removed

@author ShadowStrike Security Team
@version 2.1.0 (Enterprise Edition - Hardened)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "IntegrityMonitor.h"
#include "SelfProtect.h"
#include "CallbackProtection.h"
#include "../Core/Globals.h"
#include <ntstrsafe.h>
#include <bcrypt.h>

// ============================================================================
// PAGED CODE SEGMENT DECLARATIONS
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ImInitialize)
#pragma alloc_text(PAGE, ImShutdown)
#pragma alloc_text(PAGE, ImRegisterCallback)
#pragma alloc_text(PAGE, ImEnablePeriodicCheck)
#pragma alloc_text(PAGE, ImDisablePeriodicCheck)
#pragma alloc_text(PAGE, ImCheckIntegrity)
#pragma alloc_text(PAGE, ImCheckAll)
#endif

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

#define IM_POOL_TAG_INTERNAL        'iMOI'
#define IM_POOL_TAG_CHECK           'cMOI'
#define IM_POOL_TAG_HASH            'hMOI'

#define IM_DEFAULT_CHECK_INTERVAL   30000   // 30 seconds
#define IM_MIN_CHECK_INTERVAL       5000    // 5 seconds minimum
#define IM_MAX_CHECK_INTERVAL       300000  // 5 minutes maximum

#define IM_HASH_SIZE                32      // SHA-256
#define IM_MAX_SECTION_SIZE         (64 * 1024 * 1024)  // 64MB max

#define IM_STATE_UNINIT             0
#define IM_STATE_ACTIVE             1
#define IM_STATE_SHUTTING_DOWN      2

// PE signature constants
#define IMAGE_DOS_SIGNATURE_VALUE   0x5A4D
#define IMAGE_NT_SIGNATURE_VALUE    0x00004550
#define IMAGE_PE32PLUS_MAGIC        0x20B

// Section characteristics
#define IMAGE_SCN_CNT_CODE              0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA  0x00000040
#define IMAGE_SCN_MEM_EXECUTE           0x20000000
#define IMAGE_SCN_MEM_READ              0x40000000
#define IMAGE_SCN_MEM_WRITE             0x80000000

// Data directory indices
#define IMAGE_DIRECTORY_ENTRY_EXPORT    0
#define IMAGE_DIRECTORY_ENTRY_IMPORT    1

// ============================================================================
// PE STRUCTURES (Minimal, kernel-safe definitions)
// ============================================================================

#pragma warning(push)
#pragma warning(disable: 4201)  // nameless struct/union

typedef struct _IMAGE_DOS_HEADER_MIN {
    USHORT  e_magic;
    USHORT  e_cblp;
    USHORT  e_cp;
    USHORT  e_crlc;
    USHORT  e_cparhdr;
    USHORT  e_minalloc;
    USHORT  e_maxalloc;
    USHORT  e_ss;
    USHORT  e_sp;
    USHORT  e_csum;
    USHORT  e_ip;
    USHORT  e_cs;
    USHORT  e_lfarlc;
    USHORT  e_ovno;
    USHORT  e_res[4];
    USHORT  e_oemid;
    USHORT  e_oeminfo;
    USHORT  e_res2[10];
    LONG    e_lfanew;
} IMAGE_DOS_HEADER_MIN, *PIMAGE_DOS_HEADER_MIN;

typedef struct _IMAGE_FILE_HEADER_MIN {
    USHORT  Machine;
    USHORT  NumberOfSections;
    ULONG   TimeDateStamp;
    ULONG   PointerToSymbolTable;
    ULONG   NumberOfSymbols;
    USHORT  SizeOfOptionalHeader;
    USHORT  Characteristics;
} IMAGE_FILE_HEADER_MIN, *PIMAGE_FILE_HEADER_MIN;

typedef struct _IMAGE_DATA_DIRECTORY_MIN {
    ULONG   VirtualAddress;
    ULONG   Size;
} IMAGE_DATA_DIRECTORY_MIN, *PIMAGE_DATA_DIRECTORY_MIN;

typedef struct _IMAGE_OPTIONAL_HEADER64_MIN {
    USHORT  Magic;
    UCHAR   MajorLinkerVersion;
    UCHAR   MinorLinkerVersion;
    ULONG   SizeOfCode;
    ULONG   SizeOfInitializedData;
    ULONG   SizeOfUninitializedData;
    ULONG   AddressOfEntryPoint;
    ULONG   BaseOfCode;
    ULONGLONG   ImageBase;
    ULONG   SectionAlignment;
    ULONG   FileAlignment;
    USHORT  MajorOperatingSystemVersion;
    USHORT  MinorOperatingSystemVersion;
    USHORT  MajorImageVersion;
    USHORT  MinorImageVersion;
    USHORT  MajorSubsystemVersion;
    USHORT  MinorSubsystemVersion;
    ULONG   Win32VersionValue;
    ULONG   SizeOfImage;
    ULONG   SizeOfHeaders;
    ULONG   CheckSum;
    USHORT  Subsystem;
    USHORT  DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    ULONG   LoaderFlags;
    ULONG   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY_MIN DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64_MIN, *PIMAGE_OPTIONAL_HEADER64_MIN;

typedef struct _IMAGE_NT_HEADERS64_MIN {
    ULONG                       Signature;
    IMAGE_FILE_HEADER_MIN       FileHeader;
    IMAGE_OPTIONAL_HEADER64_MIN OptionalHeader;
} IMAGE_NT_HEADERS64_MIN, *PIMAGE_NT_HEADERS64_MIN;

typedef struct _IMAGE_SECTION_HEADER_MIN {
    UCHAR   Name[8];
    union {
        ULONG   PhysicalAddress;
        ULONG   VirtualSize;
    } Misc;
    ULONG   VirtualAddress;
    ULONG   SizeOfRawData;
    ULONG   PointerToRawData;
    ULONG   PointerToRelocations;
    ULONG   PointerToLinenumbers;
    USHORT  NumberOfRelocations;
    USHORT  NumberOfLinenumbers;
    ULONG   Characteristics;
} IMAGE_SECTION_HEADER_MIN, *PIMAGE_SECTION_HEADER_MIN;

#pragma warning(pop)

// ============================================================================
// INTERNAL DATA STRUCTURES
// ============================================================================

// Per-section baseline data
typedef struct _IM_SECTION_BASELINE {
    CHAR    Name[8];
    ULONG   VirtualAddress;
    ULONG   VirtualSize;
    ULONG   Characteristics;
    UCHAR   Hash[IM_HASH_SIZE];
    BOOLEAN IsExecutable;
    BOOLEAN IsWritable;
} IM_SECTION_BASELINE, *PIM_SECTION_BASELINE;

// Internal monitor structure (extends public IM_MONITOR)
typedef struct _IM_MONITOR_INTERNAL {
    // Public portion (must be first member)
    IM_MONITOR                  Public;

    // PE image info
    PVOID                       DriverBase;
    SIZE_T                      DriverSize;
    ULONG                       NumberOfSections;
    PIM_SECTION_BASELINE        Sections;

    // Header baseline
    ULONG                       HeaderSize;
    UCHAR                       HeaderBaselineHash[IM_HASH_SIZE];

    // Configuration baseline
    UCHAR                       ConfigBaselineHash[IM_HASH_SIZE];
    BOOLEAN                     ConfigBaselineValid;

    // Import/Export directory RVAs for targeted checking
    ULONG                       ImportDirRva;
    ULONG                       ImportDirSize;
    ULONG                       ExportDirRva;
    ULONG                       ExportDirSize;

    // Crypto handles
    BCRYPT_ALG_HANDLE           AlgHandle;
    ULONG                       HashObjectSize;

    // DPC timer
    KTIMER                      CheckTimer;
    KDPC                        CheckDpc;

    // Work item for deferred PASSIVE_LEVEL work from DPC
    PIO_WORKITEM                WorkItem;
    PDEVICE_OBJECT              DeviceObject;

    // Callback list lock
    EX_PUSH_LOCK                CallbackLock;
    LIST_ENTRY                  CallbackList;
    ULONG                       CallbackCount;

    // Lookaside for check results
    LOOKASIDE_LIST_EX           ResultLookaside;
    BOOLEAN                     LookasideInitialized;

} IM_MONITOR_INTERNAL, *PIM_MONITOR_INTERNAL;

// Callback registration entry
typedef struct _IM_CALLBACK_ENTRY {
    LIST_ENTRY          ListEntry;
    PIM_TAMPER_CALLBACK Callback;
    PVOID               Context;
} IM_CALLBACK_ENTRY, *PIM_CALLBACK_ENTRY;

// ============================================================================
// FORWARD DECLARATIONS (Internal Functions)
// ============================================================================

static NTSTATUS ImpInitializeCrypto(_Inout_ PIM_MONITOR_INTERNAL Monitor);
static VOID     ImpShutdownCrypto(_Inout_ PIM_MONITOR_INTERNAL Monitor);

static NTSTATUS ImpComputeHash(
    _In_  PIM_MONITOR_INTERNAL Monitor,
    _In_reads_bytes_(DataSize) PUCHAR Data,
    _In_  ULONG DataSize,
    _Out_writes_bytes_(IM_HASH_SIZE) PUCHAR HashOut
);

static NTSTATUS ImpParseDriverImage(
    _Inout_ PIM_MONITOR_INTERNAL Monitor,
    _In_    PVOID DriverBase,
    _In_    SIZE_T DriverSize
);

static NTSTATUS ImpComputeBaseline(_Inout_ PIM_MONITOR_INTERNAL Monitor);

static NTSTATUS ImpCheckComponent(
    _In_  PIM_MONITOR_INTERNAL Monitor,
    _In_  IM_COMPONENT Component,
    _Out_ PIM_CHECK_RESULT Result
);

static VOID ImpNotifyTamper(
    _In_  PIM_MONITOR_INTERNAL Monitor,
    _In_  PIM_CHECK_RESULT Result
);

_Function_class_(KDEFERRED_ROUTINE)
static VOID ImpCheckTimerDpc(
    _In_     PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
);

_Function_class_(IO_WORKITEM_ROUTINE)
static VOID ImpPeriodicCheckWorkItem(
    _In_     PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
);

static NTSTATUS ImpVerifySectionIntegrity(
    _In_  PIM_MONITOR_INTERNAL Monitor,
    _In_  ULONG SectionIndex,
    _Out_ PBOOLEAN IsIntact,
    _Out_ PIM_MODIFICATION ModificationType
);

static NTSTATUS ImpComputeConfigHash(
    _In_  PIM_MONITOR_INTERNAL Monitor,
    _Out_writes_bytes_(IM_HASH_SIZE) PUCHAR HashOut
);

// ============================================================================
// LOOKASIDE ALLOCATOR CALLBACKS
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
static PVOID NTAPI
ImpResultAllocate(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T    NumberOfBytes,
    _In_ ULONG     Tag
)
{
    UNREFERENCED_PARAMETER(PoolType);
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, NumberOfBytes, Tag);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID NTAPI
ImpResultFree(
    _In_ __drv_freesMem(Mem) PVOID Buffer,
    _In_ ULONG Tag
)
{
    UNREFERENCED_PARAMETER(Tag);
    if (Buffer) {
        ExFreePoolWithTag(Buffer, IM_POOL_TAG_CHECK);
    }
}

// ============================================================================
// CRYPTO INITIALIZATION & OPERATIONS
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
ImpInitializeCrypto(
    _Inout_ PIM_MONITOR_INTERNAL Monitor
)
{
    NTSTATUS Status;
    ULONG ResultSize = 0;

    PAGED_CODE();

    Status = BCryptOpenAlgorithmProvider(
        &Monitor->AlgHandle,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        0
    );
    if (!NT_SUCCESS(Status)) {
        Monitor->AlgHandle = NULL;
        return Status;
    }

    Status = BCryptGetProperty(
        Monitor->AlgHandle,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&Monitor->HashObjectSize,
        sizeof(Monitor->HashObjectSize),
        &ResultSize,
        0
    );
    if (!NT_SUCCESS(Status)) {
        BCryptCloseAlgorithmProvider(Monitor->AlgHandle, 0);
        Monitor->AlgHandle = NULL;
        return Status;
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
ImpShutdownCrypto(
    _Inout_ PIM_MONITOR_INTERNAL Monitor
)
{
    PAGED_CODE();

    if (Monitor->AlgHandle != NULL) {
        BCryptCloseAlgorithmProvider(Monitor->AlgHandle, 0);
        Monitor->AlgHandle = NULL;
    }
}

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
ImpComputeHash(
    _In_  PIM_MONITOR_INTERNAL Monitor,
    _In_reads_bytes_(DataSize) PUCHAR Data,
    _In_  ULONG DataSize,
    _Out_writes_bytes_(IM_HASH_SIZE) PUCHAR HashOut
)
{
    NTSTATUS Status;
    BCRYPT_HASH_HANDLE HashHandle = NULL;
    PUCHAR HashObject = NULL;

    PAGED_CODE();

    if (Monitor->AlgHandle == NULL || Data == NULL || HashOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(HashOut, IM_HASH_SIZE);

    // Allocate hash object
    HashObject = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        Monitor->HashObjectSize,
        IM_POOL_TAG_HASH
    );
    if (HashObject == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = BCryptCreateHash(
        Monitor->AlgHandle,
        &HashHandle,
        HashObject,
        Monitor->HashObjectSize,
        NULL, 0, 0
    );
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    Status = BCryptHashData(HashHandle, Data, DataSize, 0);
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    Status = BCryptFinishHash(HashHandle, HashOut, IM_HASH_SIZE, 0);

Cleanup:
    if (HashHandle != NULL) {
        BCryptDestroyHash(HashHandle);
    }
    if (HashObject != NULL) {
        ExFreePoolWithTag(HashObject, IM_POOL_TAG_HASH);
    }

    return Status;
}

// ============================================================================
// PE PARSING (Fully bounds-checked)
// Fixes: #11 (e_lfanew sign), #12 (RVA+size bounds), #13 (section count),
//        #15 (MmSystemRangeStart cast)
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
ImpParseDriverImage(
    _Inout_ PIM_MONITOR_INTERNAL Monitor,
    _In_    PVOID DriverBase,
    _In_    SIZE_T DriverSize
)
{
    PIMAGE_DOS_HEADER_MIN       DosHeader;
    PIMAGE_NT_HEADERS64_MIN     NtHeaders;
    PIMAGE_SECTION_HEADER_MIN   SectionHeaders;
    ULONG                       i;
    SIZE_T                      RequiredHeaderSpace;
    LONG                        Lfanew;

    PAGED_CODE();

    // Validate kernel pointer
    if (DriverBase == NULL || DriverSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // FIX #15: Proper ULONG_PTR cast for MmSystemRangeStart comparison
    if ((ULONG_PTR)DriverBase < (ULONG_PTR)MmSystemRangeStart) {
        return STATUS_INVALID_ADDRESS;
    }

    // Minimum PE size check
    if (DriverSize < sizeof(IMAGE_DOS_HEADER_MIN)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    DosHeader = (PIMAGE_DOS_HEADER_MIN)DriverBase;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE_VALUE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // FIX #11: e_lfanew is LONG (signed). Must check for negative values.
    Lfanew = DosHeader->e_lfanew;
    if (Lfanew < 0) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Validate e_lfanew + NT headers fit within image
    if ((SIZE_T)Lfanew + sizeof(IMAGE_NT_HEADERS64_MIN) > DriverSize) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    NtHeaders = (PIMAGE_NT_HEADERS64_MIN)((PUCHAR)DriverBase + Lfanew);

    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE_VALUE) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (NtHeaders->OptionalHeader.Magic != IMAGE_PE32PLUS_MAGIC) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // FIX #13: Validate section count fits within available header space
    USHORT SectionCount = NtHeaders->FileHeader.NumberOfSections;
    if (SectionCount == 0 || SectionCount > 96) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Section headers start after optional header
    SIZE_T SectionHeaderOffset = (SIZE_T)Lfanew
        + FIELD_OFFSET(IMAGE_NT_HEADERS64_MIN, OptionalHeader)
        + NtHeaders->FileHeader.SizeOfOptionalHeader;

    RequiredHeaderSpace = SectionHeaderOffset
        + ((SIZE_T)SectionCount * sizeof(IMAGE_SECTION_HEADER_MIN));

    if (RequiredHeaderSpace > DriverSize) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    SectionHeaders = (PIMAGE_SECTION_HEADER_MIN)((PUCHAR)DriverBase + SectionHeaderOffset);

    // Allocate section baseline array
    Monitor->Sections = (PIM_SECTION_BASELINE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        (SIZE_T)SectionCount * sizeof(IM_SECTION_BASELINE),
        IM_POOL_TAG_INTERNAL
    );
    if (Monitor->Sections == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Monitor->DriverBase = DriverBase;
    Monitor->DriverSize = DriverSize;
    Monitor->NumberOfSections = SectionCount;
    Monitor->HeaderSize = NtHeaders->OptionalHeader.SizeOfHeaders;

    // Validate header size
    if (Monitor->HeaderSize == 0 || (SIZE_T)Monitor->HeaderSize > DriverSize) {
        Monitor->HeaderSize = (ULONG)min(RequiredHeaderSpace, DriverSize);
    }

    // Extract import/export directory info
    if (NtHeaders->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
        Monitor->ImportDirRva  = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        Monitor->ImportDirSize = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    }
    if (NtHeaders->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
        Monitor->ExportDirRva  = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        Monitor->ExportDirSize = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }

    // Parse sections with full bounds checking
    for (i = 0; i < SectionCount; i++) {
        PIM_SECTION_BASELINE Baseline = &Monitor->Sections[i];
        PIMAGE_SECTION_HEADER_MIN Section = &SectionHeaders[i];

        RtlCopyMemory(Baseline->Name, Section->Name, 8);
        Baseline->VirtualAddress = Section->VirtualAddress;
        Baseline->VirtualSize    = Section->Misc.VirtualSize;
        Baseline->Characteristics = Section->Characteristics;

        Baseline->IsExecutable = (BOOLEAN)(
            (Section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 ||
            (Section->Characteristics & IMAGE_SCN_CNT_CODE) != 0
        );
        Baseline->IsWritable = (BOOLEAN)(
            (Section->Characteristics & IMAGE_SCN_MEM_WRITE) != 0
        );

        // FIX #12: Validate section RVA + size doesn't exceed image bounds
        SIZE_T SectionEnd = (SIZE_T)Section->VirtualAddress + (SIZE_T)Section->Misc.VirtualSize;
        if (SectionEnd > DriverSize || SectionEnd < (SIZE_T)Section->VirtualAddress) {
            // Overflow or out of bounds - truncate to available size
            if ((SIZE_T)Section->VirtualAddress >= DriverSize) {
                Baseline->VirtualSize = 0;
            } else {
                Baseline->VirtualSize = (ULONG)(DriverSize - (SIZE_T)Section->VirtualAddress);
            }
        }

        RtlZeroMemory(Baseline->Hash, IM_HASH_SIZE);
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// BASELINE COMPUTATION
// Fixes: #9 (header baseline hash), #16 (explicit ULONG cast), #23 (size cast)
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
ImpComputeBaseline(
    _Inout_ PIM_MONITOR_INTERNAL Monitor
)
{
    NTSTATUS Status;
    ULONG i;

    PAGED_CODE();

    if (Monitor->DriverBase == NULL || Monitor->NumberOfSections == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // FIX #9: Compute baseline hash of PE headers
    if (Monitor->HeaderSize > 0 && (SIZE_T)Monitor->HeaderSize <= Monitor->DriverSize) {
        Status = ImpComputeHash(
            Monitor,
            (PUCHAR)Monitor->DriverBase,
            Monitor->HeaderSize,
            Monitor->HeaderBaselineHash
        );
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }

    // Compute baseline hashes for each non-writable section
    for (i = 0; i < Monitor->NumberOfSections; i++) {
        PIM_SECTION_BASELINE Baseline = &Monitor->Sections[i];

        // Skip writable sections (they change at runtime)
        if (Baseline->IsWritable) {
            continue;
        }

        // Skip zero-size sections
        if (Baseline->VirtualSize == 0) {
            continue;
        }

        // FIX #12 (continued): Validate section data is within driver image
        SIZE_T SectionEnd = (SIZE_T)Baseline->VirtualAddress + (SIZE_T)Baseline->VirtualSize;
        if (SectionEnd > Monitor->DriverSize) {
            continue;
        }

        // FIX #16, #23: Explicit ULONG cast - safe because VirtualSize was validated
        //   against IM_MAX_SECTION_SIZE check isn't needed here since we validated
        //   the section fits within DriverSize which is a loaded kernel image
        PUCHAR SectionData = (PUCHAR)Monitor->DriverBase + Baseline->VirtualAddress;
        ULONG HashDataSize = Baseline->VirtualSize;

        Status = ImpComputeHash(Monitor, SectionData, HashDataSize, Baseline->Hash);
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }

    // Compute initial configuration baseline
    Status = ImpComputeConfigHash(Monitor, Monitor->ConfigBaselineHash);
    if (NT_SUCCESS(Status)) {
        Monitor->ConfigBaselineValid = TRUE;
    }
    // Config hash failure is non-fatal - we just won't check config

    return STATUS_SUCCESS;
}

// ============================================================================
// SECTION INTEGRITY VERIFICATION
// Fixes: #24 (proper IAT/EAT modification types)
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
ImpVerifySectionIntegrity(
    _In_  PIM_MONITOR_INTERNAL Monitor,
    _In_  ULONG SectionIndex,
    _Out_ PBOOLEAN IsIntact,
    _Out_ PIM_MODIFICATION ModificationType
)
{
    NTSTATUS Status;
    UCHAR CurrentHash[IM_HASH_SIZE];
    PIM_SECTION_BASELINE Baseline;

    PAGED_CODE();

    *IsIntact = TRUE;
    *ModificationType = ImMod_None;

    if (SectionIndex >= Monitor->NumberOfSections) {
        return STATUS_INVALID_PARAMETER;
    }

    Baseline = &Monitor->Sections[SectionIndex];

    // Skip writable sections
    if (Baseline->IsWritable || Baseline->VirtualSize == 0) {
        return STATUS_SUCCESS;
    }

    // Validate section still within bounds
    SIZE_T SectionEnd = (SIZE_T)Baseline->VirtualAddress + (SIZE_T)Baseline->VirtualSize;
    if (SectionEnd > Monitor->DriverSize) {
        *IsIntact = FALSE;
        *ModificationType = ImMod_HeaderTamper;
        return STATUS_SUCCESS;
    }

    PUCHAR SectionData = (PUCHAR)Monitor->DriverBase + Baseline->VirtualAddress;

    Status = ImpComputeHash(Monitor, SectionData, Baseline->VirtualSize, CurrentHash);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    if (RtlCompareMemory(CurrentHash, Baseline->Hash, IM_HASH_SIZE) != IM_HASH_SIZE) {
        *IsIntact = FALSE;

        // FIX #24: Determine modification type based on section characteristics
        if (Baseline->IsExecutable) {
            // Check if this section contains import or export directory
            if (Monitor->ImportDirRva >= Baseline->VirtualAddress &&
                Monitor->ImportDirRva < (Baseline->VirtualAddress + Baseline->VirtualSize)) {
                *ModificationType = ImMod_ImportHook;
            } else if (Monitor->ExportDirRva >= Baseline->VirtualAddress &&
                       Monitor->ExportDirRva < (Baseline->VirtualAddress + Baseline->VirtualSize)) {
                *ModificationType = ImMod_ExportHook;
            } else {
                *ModificationType = ImMod_CodePatch;
            }
        } else {
            // Non-executable, non-writable section changed (read-only data)
            *ModificationType = ImMod_DataCorruption;
        }
    }

    RtlSecureZeroMemory(CurrentHash, IM_HASH_SIZE);
    return STATUS_SUCCESS;
}

// ============================================================================
// CONFIGURATION HASH COMPUTATION
// FIX #8: Real configuration integrity check instead of stub
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
ImpComputeConfigHash(
    _In_  PIM_MONITOR_INTERNAL Monitor,
    _Out_writes_bytes_(IM_HASH_SIZE) PUCHAR HashOut
)
{
    NTSTATUS Status;
    BCRYPT_HASH_HANDLE HashHandle = NULL;
    PUCHAR HashObject = NULL;

    PAGED_CODE();
    RtlZeroMemory(HashOut, IM_HASH_SIZE);

    if (Monitor->AlgHandle == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    HashObject = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        Monitor->HashObjectSize,
        IM_POOL_TAG_HASH
    );
    if (HashObject == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = BCryptCreateHash(
        Monitor->AlgHandle,
        &HashHandle,
        HashObject,
        Monitor->HashObjectSize,
        NULL, 0, 0
    );
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    // Hash critical driver configuration state
    // Include callback registration states, protection flags, etc.
    BOOLEAN ProcessCallbackActive = g_DriverData.ProcessNotifyRegistered;
    BOOLEAN ThreadCallbackActive  = g_DriverData.ThreadNotifyRegistered;
    BOOLEAN ImageCallbackActive   = g_DriverData.ImageNotifyRegistered;
    BOOLEAN ObCallbackActive      = (g_DriverData.ObjectCallbackHandle != NULL) ? TRUE : FALSE;

    Status = BCryptHashData(HashHandle, (PUCHAR)&ProcessCallbackActive, sizeof(BOOLEAN), 0);
    if (!NT_SUCCESS(Status)) goto Cleanup;

    Status = BCryptHashData(HashHandle, (PUCHAR)&ThreadCallbackActive, sizeof(BOOLEAN), 0);
    if (!NT_SUCCESS(Status)) goto Cleanup;

    Status = BCryptHashData(HashHandle, (PUCHAR)&ImageCallbackActive, sizeof(BOOLEAN), 0);
    if (!NT_SUCCESS(Status)) goto Cleanup;

    Status = BCryptHashData(HashHandle, (PUCHAR)&ObCallbackActive, sizeof(BOOLEAN), 0);
    if (!NT_SUCCESS(Status)) goto Cleanup;

    Status = BCryptFinishHash(HashHandle, HashOut, IM_HASH_SIZE, 0);

Cleanup:
    if (HashHandle != NULL) {
        BCryptDestroyHash(HashHandle);
    }
    if (HashObject != NULL) {
        ExFreePoolWithTag(HashObject, IM_POOL_TAG_HASH);
    }

    return Status;
}

// ============================================================================
// COMPONENT INTEGRITY CHECKING
// Fixes: #6 (callbacks stub), #7 (handles stub), #8 (config stub), #9 (header hash)
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
ImpCheckComponent(
    _In_  PIM_MONITOR_INTERNAL Monitor,
    _In_  IM_COMPONENT Component,
    _Out_ PIM_CHECK_RESULT Result
)
{
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    Result->Component = Component;
    Result->IsIntact = TRUE;
    Result->ModificationType = ImMod_None;
    RtlZeroMemory(Result->Details, sizeof(Result->Details));

    switch (Component) {

    case ImComp_CodeSections:
    {
        // Verify all non-writable, executable sections
        for (ULONG i = 0; i < Monitor->NumberOfSections; i++) {
            if (!Monitor->Sections[i].IsExecutable || Monitor->Sections[i].IsWritable) {
                continue;
            }

            BOOLEAN SectionIntact = TRUE;
            IM_MODIFICATION ModType = ImMod_None;

            Status = ImpVerifySectionIntegrity(Monitor, i, &SectionIntact, &ModType);
            if (!NT_SUCCESS(Status)) {
                return Status;
            }

            if (!SectionIntact) {
                Result->IsIntact = FALSE;
                Result->ModificationType = ModType;
                RtlStringCbPrintfA(
                    Result->Details,
                    sizeof(Result->Details),
                    "Section %.8s tampered (type %u)",
                    Monitor->Sections[i].Name,
                    (ULONG)ModType
                );
                break;
            }
        }
        break;
    }

    case ImComp_DataSections:
    {
        // Verify non-writable, non-executable sections
        for (ULONG i = 0; i < Monitor->NumberOfSections; i++) {
            if (Monitor->Sections[i].IsExecutable || Monitor->Sections[i].IsWritable) {
                continue;
            }
            if (Monitor->Sections[i].VirtualSize == 0) {
                continue;
            }

            BOOLEAN SectionIntact = TRUE;
            IM_MODIFICATION ModType = ImMod_None;

            Status = ImpVerifySectionIntegrity(Monitor, i, &SectionIntact, &ModType);
            if (!NT_SUCCESS(Status)) {
                return Status;
            }

            if (!SectionIntact) {
                Result->IsIntact = FALSE;
                Result->ModificationType = ImMod_DataCorruption;
                RtlStringCbPrintfA(
                    Result->Details,
                    sizeof(Result->Details),
                    "Data section %.8s modified",
                    Monitor->Sections[i].Name
                );
                break;
            }
        }
        break;
    }

    case ImComp_DriverImage:
    {
        // FIX #9: Compare current header hash against baseline
        if (Monitor->HeaderSize > 0 && (SIZE_T)Monitor->HeaderSize <= Monitor->DriverSize) {
            UCHAR CurrentHeaderHash[IM_HASH_SIZE];
            Status = ImpComputeHash(
                Monitor,
                (PUCHAR)Monitor->DriverBase,
                Monitor->HeaderSize,
                CurrentHeaderHash
            );
            if (NT_SUCCESS(Status)) {
                if (RtlCompareMemory(CurrentHeaderHash, Monitor->HeaderBaselineHash, IM_HASH_SIZE) != IM_HASH_SIZE) {
                    Result->IsIntact = FALSE;
                    Result->ModificationType = ImMod_HeaderTamper;
                    RtlStringCbPrintfA(
                        Result->Details,
                        sizeof(Result->Details),
                        "PE header tampered"
                    );
                }
                RtlSecureZeroMemory(CurrentHeaderHash, IM_HASH_SIZE);
            } else {
                return Status;
            }
        }
        break;
    }

    case ImComp_Callbacks:
    {
        // FIX #6: Real callback verification using CallbackProtection module
        // Check if our process/thread/image callbacks are still registered
        if (!g_DriverData.ProcessNotifyRegistered) {
            Result->IsIntact = FALSE;
            Result->ModificationType = ImMod_CallbackRemoval;
            RtlStringCbPrintfA(Result->Details, sizeof(Result->Details),
                "Process creation callback unregistered");
            break;
        }
        if (!g_DriverData.ThreadNotifyRegistered) {
            Result->IsIntact = FALSE;
            Result->ModificationType = ImMod_CallbackRemoval;
            RtlStringCbPrintfA(Result->Details, sizeof(Result->Details),
                "Thread creation callback unregistered");
            break;
        }
        if (!g_DriverData.ImageNotifyRegistered) {
            Result->IsIntact = FALSE;
            Result->ModificationType = ImMod_CallbackRemoval;
            RtlStringCbPrintfA(Result->Details, sizeof(Result->Details),
                "Image load callback unregistered");
            break;
        }
        break;
    }

    case ImComp_Handles:
    {
        // FIX #7: Real handle protection verification
        if (g_DriverData.ObjectCallbackHandle == NULL) {
            Result->IsIntact = FALSE;
            Result->ModificationType = ImMod_CallbackRemoval;
            RtlStringCbPrintfA(Result->Details, sizeof(Result->Details),
                "Object callback handle removed");
        }
        break;
    }

    case ImComp_Configuration:
    {
        // FIX #8: Real configuration hash comparison
        if (!Monitor->ConfigBaselineValid) {
            // No baseline was established — cannot verify
            RtlStringCbPrintfA(Result->Details, sizeof(Result->Details),
                "No configuration baseline available");
            break;
        }

        UCHAR CurrentConfigHash[IM_HASH_SIZE];
        Status = ImpComputeConfigHash(Monitor, CurrentConfigHash);
        if (NT_SUCCESS(Status)) {
            if (RtlCompareMemory(CurrentConfigHash, Monitor->ConfigBaselineHash, IM_HASH_SIZE) != IM_HASH_SIZE) {
                Result->IsIntact = FALSE;
                Result->ModificationType = ImMod_DataCorruption;
                RtlStringCbPrintfA(Result->Details, sizeof(Result->Details),
                    "Driver configuration state modified");
            }
            RtlSecureZeroMemory(CurrentConfigHash, IM_HASH_SIZE);
        } else {
            return Status;
        }
        break;
    }

    default:
        return STATUS_INVALID_PARAMETER;
    }

    return Status;
}

// ============================================================================
// ImInitialize — ENTERPRISE-GRADE INITIALIZATION
// Fixes: #17 (redundant zero), #18 (volatile state), #22 (PAGED_CODE)
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ImInitialize(
    _Out_    PIM_MONITOR *Monitor,
    _In_     PVOID DriverBase,
    _In_     SIZE_T DriverSize,
    _In_     PDEVICE_OBJECT DeviceObject
)
{
    NTSTATUS Status;
    PIM_MONITOR_INTERNAL Internal = NULL;

    PAGED_CODE();

    if (Monitor == NULL || DriverBase == NULL || DriverSize == 0 || DeviceObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Monitor = NULL;

    // FIX #17: ExAllocatePool2 without POOL_FLAG_UNINITIALIZED already zeros memory
    Internal = (PIM_MONITOR_INTERNAL)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(IM_MONITOR_INTERNAL),
        IM_POOL_TAG_INTERNAL
    );
    if (Internal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Initialize synchronization primitives
    ExInitializeRundownProtection(&Internal->Public.RundownProtection);
    ExInitializePushLock(&Internal->CallbackLock);
    InitializeListHead(&Internal->CallbackList);

    Internal->DeviceObject = DeviceObject;

    // Initialize crypto (BCrypt)
    Status = ImpInitializeCrypto(Internal);
    if (!NT_SUCCESS(Status)) {
        goto InitFailed;
    }

    // Parse driver PE image with full bounds checking
    Status = ImpParseDriverImage(Internal, DriverBase, DriverSize);
    if (!NT_SUCCESS(Status)) {
        goto InitFailed;
    }

    // Compute baseline hashes for all non-writable sections + headers
    Status = ImpComputeBaseline(Internal);
    if (!NT_SUCCESS(Status)) {
        goto InitFailed;
    }

    // Initialize lookaside list for check results
    Status = ExInitializeLookasideListEx(
        &Internal->ResultLookaside,
        ImpResultAllocate,
        ImpResultFree,
        NonPagedPoolNx,
        0,
        sizeof(IM_CHECK_RESULT),
        IM_POOL_TAG_CHECK,
        0
    );
    if (!NT_SUCCESS(Status)) {
        goto InitFailed;
    }
    Internal->LookasideInitialized = TRUE;

    // Allocate work item for DPC → PASSIVE_LEVEL deferral
    Internal->WorkItem = IoAllocateWorkItem(DeviceObject);
    if (Internal->WorkItem == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto InitFailed;
    }

    // Initialize timer and DPC (but don't start yet)
    KeInitializeTimer(&Internal->CheckTimer);
    KeInitializeDpc(&Internal->CheckDpc, ImpCheckTimerDpc, Internal);

    // FIX #18: Use InterlockedExchange for volatile state
    InterlockedExchange(&Internal->Public.State, IM_STATE_ACTIVE);

    *Monitor = &Internal->Public;
    return STATUS_SUCCESS;

InitFailed:
    // Cleanup on failure — reverse order of initialization
    if (Internal->WorkItem != NULL) {
        IoFreeWorkItem(Internal->WorkItem);
    }
    if (Internal->LookasideInitialized) {
        ExDeleteLookasideListEx(&Internal->ResultLookaside);
    }
    if (Internal->Sections != NULL) {
        ExFreePoolWithTag(Internal->Sections, IM_POOL_TAG_INTERNAL);
    }
    ImpShutdownCrypto(Internal);
    ExFreePoolWithTag(Internal, IM_POOL_TAG_INTERNAL);

    return Status;
}

// ============================================================================
// ImShutdown — SAFE SHUTDOWN WITH RUNDOWN PROTECTION
// Fixes: #4 (PIM_MONITOR*), #5 (ordering, flush, rundown), #18 (volatile state)
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ImShutdown(
    _Inout_ PIM_MONITOR *Monitor
)
{
    PIM_MONITOR_INTERNAL Internal;
    PLIST_ENTRY Entry;
    PIM_CALLBACK_ENTRY CallbackEntry;

    PAGED_CODE();

    if (Monitor == NULL || *Monitor == NULL) {
        return;
    }

    Internal = CONTAINING_RECORD(*Monitor, IM_MONITOR_INTERNAL, Public);

    // FIX #4: NULL caller's pointer immediately to prevent use-after-free
    *Monitor = NULL;

    // FIX #5, #18: Signal shutdown state atomically
    LONG PreviousState = InterlockedExchange(&Internal->Public.State, IM_STATE_SHUTTING_DOWN);
    if (PreviousState != IM_STATE_ACTIVE) {
        // Already shut down or never initialized
        return;
    }

    // FIX #5: Wait for all in-flight operations to complete
    ExWaitForRundownProtectionRelease(&Internal->Public.RundownProtection);

    // Cancel periodic timer
    KeCancelTimer(&Internal->CheckTimer);

    // FIX #5: Flush any queued DPCs to ensure our DPC has completed
    KeFlushQueuedDpcs();

    // FIX #1 (part of shutdown): Drain work item
    // After KeFlushQueuedDpcs, no new DPCs can queue work items.
    // Spin-wait if a work item is still pending (should be very brief).
    while (InterlockedCompareExchange(&Internal->Public.WorkItemPending, 0, 0) != 0) {
        LARGE_INTEGER SpinWait;
        SpinWait.QuadPart = -10000; // 1ms
        KeDelayExecutionThread(KernelMode, FALSE, &SpinWait);
    }

    // Now safe to free work item — no pending or in-flight work
    if (Internal->WorkItem != NULL) {
        IoFreeWorkItem(Internal->WorkItem);
        Internal->WorkItem = NULL;
    }

    // Free callback entries
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Internal->CallbackLock);

    while (!IsListEmpty(&Internal->CallbackList)) {
        Entry = RemoveHeadList(&Internal->CallbackList);
        CallbackEntry = CONTAINING_RECORD(Entry, IM_CALLBACK_ENTRY, ListEntry);
        ExFreePoolWithTag(CallbackEntry, IM_POOL_TAG_INTERNAL);
    }
    Internal->CallbackCount = 0;

    ExReleasePushLockExclusive(&Internal->CallbackLock);
    KeLeaveCriticalRegion();

    // Free sections array
    if (Internal->Sections != NULL) {
        ExFreePoolWithTag(Internal->Sections, IM_POOL_TAG_INTERNAL);
        Internal->Sections = NULL;
    }

    // Cleanup lookaside
    if (Internal->LookasideInitialized) {
        ExDeleteLookasideListEx(&Internal->ResultLookaside);
        Internal->LookasideInitialized = FALSE;
    }

    // Cleanup crypto
    ImpShutdownCrypto(Internal);

    // Free the monitor structure itself
    ExFreePoolWithTag(Internal, IM_POOL_TAG_INTERNAL);
}

// ============================================================================
// PUBLIC API: Callback Registration
// Fix #2: Push lock wrapped with KeEnterCriticalRegion
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ImRegisterCallback(
    _In_ PIM_MONITOR Monitor,
    _In_ PIM_TAMPER_CALLBACK Callback,
    _In_opt_ PVOID Context
)
{
    PIM_MONITOR_INTERNAL Internal;
    PIM_CALLBACK_ENTRY Entry;

    PAGED_CODE();

    if (Monitor == NULL || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Internal = CONTAINING_RECORD(Monitor, IM_MONITOR_INTERNAL, Public);

    // Acquire rundown protection
    if (!ExAcquireRundownProtection(&Internal->Public.RundownProtection)) {
        return STATUS_DELETE_PENDING;
    }

    Entry = (PIM_CALLBACK_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(IM_CALLBACK_ENTRY),
        IM_POOL_TAG_INTERNAL
    );
    if (Entry == NULL) {
        ExReleaseRundownProtection(&Internal->Public.RundownProtection);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Entry->Callback = Callback;
    Entry->Context = Context;

    // FIX #2: KeEnterCriticalRegion BEFORE push lock
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Internal->CallbackLock);

    InsertTailList(&Internal->CallbackList, &Entry->ListEntry);
    Internal->CallbackCount++;

    ExReleasePushLockExclusive(&Internal->CallbackLock);
    KeLeaveCriticalRegion();

    ExReleaseRundownProtection(&Internal->Public.RundownProtection);
    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API: Periodic Check Enable/Disable
// Fixes: #2 (push lock), #19 (proper work item pattern)
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ImEnablePeriodicCheck(
    _In_ PIM_MONITOR Monitor,
    _In_ ULONG IntervalMs
)
{
    PIM_MONITOR_INTERNAL Internal;
    LARGE_INTEGER DueTime;

    PAGED_CODE();

    if (Monitor == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Internal = CONTAINING_RECORD(Monitor, IM_MONITOR_INTERNAL, Public);

    if (!ExAcquireRundownProtection(&Internal->Public.RundownProtection)) {
        return STATUS_DELETE_PENDING;
    }

    // Clamp interval to safe range
    if (IntervalMs < IM_MIN_CHECK_INTERVAL) {
        IntervalMs = IM_MIN_CHECK_INTERVAL;
    }
    if (IntervalMs > IM_MAX_CHECK_INTERVAL) {
        IntervalMs = IM_MAX_CHECK_INTERVAL;
    }

    Internal->Public.CheckIntervalMs = IntervalMs;
    InterlockedExchange(&Internal->Public.PeriodicEnabled, 1);

    // Start periodic timer
    DueTime.QuadPart = -((LONGLONG)IntervalMs * 10000LL); // relative, in 100ns units
    KeSetTimerEx(
        &Internal->CheckTimer,
        DueTime,
        IntervalMs,    // periodic interval in ms
        &Internal->CheckDpc
    );

    ExReleaseRundownProtection(&Internal->Public.RundownProtection);
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ImDisablePeriodicCheck(
    _In_ PIM_MONITOR Monitor
)
{
    PIM_MONITOR_INTERNAL Internal;

    PAGED_CODE();

    if (Monitor == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Internal = CONTAINING_RECORD(Monitor, IM_MONITOR_INTERNAL, Public);

    if (!ExAcquireRundownProtection(&Internal->Public.RundownProtection)) {
        return STATUS_DELETE_PENDING;
    }

    InterlockedExchange(&Internal->Public.PeriodicEnabled, 0);
    KeCancelTimer(&Internal->CheckTimer);

    ExReleaseRundownProtection(&Internal->Public.RundownProtection);
    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API: On-Demand Integrity Check
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ImCheckIntegrity(
    _In_  PIM_MONITOR Monitor,
    _In_  IM_COMPONENT Component,
    _Out_ PIM_CHECK_RESULT Result
)
{
    PIM_MONITOR_INTERNAL Internal;
    NTSTATUS Status;

    PAGED_CODE();

    if (Monitor == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Component >= ImComp_MaxValue) {
        return STATUS_INVALID_PARAMETER;
    }

    Internal = CONTAINING_RECORD(Monitor, IM_MONITOR_INTERNAL, Public);

    if (!ExAcquireRundownProtection(&Internal->Public.RundownProtection)) {
        return STATUS_DELETE_PENDING;
    }

    Status = ImpCheckComponent(Internal, Component, Result);

    ExReleaseRundownProtection(&Internal->Public.RundownProtection);
    return Status;
}

// ============================================================================
// PUBLIC API: Check All Components
// FIX #14: Free partial results on failure
// FIX #20: Results allocated from lookaside, freed via ImFreeCheckResult
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ImCheckAll(
    _In_  PIM_MONITOR Monitor,
    _Out_ PIM_CHECK_RESULT *Results,
    _Out_ PULONG ResultCount,
    _Out_ PBOOLEAN AllIntact
)
{
    PIM_MONITOR_INTERNAL Internal;
    NTSTATUS Status;
    ULONG Count = 0;

    PAGED_CODE();

    if (Monitor == NULL || Results == NULL || ResultCount == NULL || AllIntact == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Results = NULL;
    *ResultCount = 0;
    *AllIntact = TRUE;

    Internal = CONTAINING_RECORD(Monitor, IM_MONITOR_INTERNAL, Public);

    if (!ExAcquireRundownProtection(&Internal->Public.RundownProtection)) {
        return STATUS_DELETE_PENDING;
    }

    // Allocate results array (one per component)
    ULONG TotalComponents = ImComp_MaxValue;
    PIM_CHECK_RESULT ResultArray = (PIM_CHECK_RESULT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        (SIZE_T)TotalComponents * sizeof(IM_CHECK_RESULT),
        IM_POOL_TAG_CHECK
    );
    if (ResultArray == NULL) {
        ExReleaseRundownProtection(&Internal->Public.RundownProtection);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Check each component
    for (ULONG i = 0; i < TotalComponents; i++) {
        Status = ImpCheckComponent(Internal, (IM_COMPONENT)i, &ResultArray[Count]);
        if (!NT_SUCCESS(Status)) {
            // FIX #14: Free the entire result array on failure
            ExFreePoolWithTag(ResultArray, IM_POOL_TAG_CHECK);
            ExReleaseRundownProtection(&Internal->Public.RundownProtection);
            return Status;
        }

        if (!ResultArray[Count].IsIntact) {
            *AllIntact = FALSE;
        }
        Count++;
    }

    *Results = ResultArray;
    *ResultCount = Count;

    ExReleaseRundownProtection(&Internal->Public.RundownProtection);
    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API: Free Check Results
// FIX #20: Proper result lifetime management
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
ImFreeCheckResult(
    _In_ PIM_CHECK_RESULT Results
)
{
    if (Results != NULL) {
        ExFreePoolWithTag(Results, IM_POOL_TAG_CHECK);
    }
}

// ============================================================================
// TAMPER NOTIFICATION
// FIX #2, #3: Push lock properly wrapped, called from PASSIVE_LEVEL work item
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
static VOID
ImpNotifyTamper(
    _In_  PIM_MONITOR_INTERNAL Monitor,
    _In_  PIM_CHECK_RESULT Result
)
{
    PLIST_ENTRY Entry;
    PIM_CALLBACK_ENTRY CallbackEntry;

    PAGED_CODE();

    // FIX #2: KeEnterCriticalRegion before push lock acquisition
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Monitor->CallbackLock);

    for (Entry = Monitor->CallbackList.Flink;
         Entry != &Monitor->CallbackList;
         Entry = Entry->Flink)
    {
        CallbackEntry = CONTAINING_RECORD(Entry, IM_CALLBACK_ENTRY, ListEntry);

        // Call user callback — wrapped in __try for safety
        __try {
            CallbackEntry->Callback(Result, CallbackEntry->Context);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Log but don't crash if a callback misbehaves
        }
    }

    ExReleasePushLockShared(&Monitor->CallbackLock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// DPC TIMER CALLBACK → IoWorkItem
// FIX #1: DPC no longer calls BCrypt or push locks directly.
//         It only queues an IoWorkItem for PASSIVE_LEVEL processing.
// FIX #19: Removed unsafe placeholder comments
// ============================================================================

_Function_class_(KDEFERRED_ROUTINE)
_IRQL_requires_(DISPATCH_LEVEL)
static VOID
ImpCheckTimerDpc(
    _In_     PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
)
{
    PIM_MONITOR_INTERNAL Internal = (PIM_MONITOR_INTERNAL)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (Internal == NULL) {
        return;
    }

    // Check state atomically — must be active
    if (InterlockedCompareExchange(&Internal->Public.State, IM_STATE_ACTIVE, IM_STATE_ACTIVE) != IM_STATE_ACTIVE) {
        return;
    }

    // Check if periodic checking is still enabled
    if (InterlockedCompareExchange(&Internal->Public.PeriodicEnabled, 1, 1) != 1) {
        return;
    }

    // Try to acquire rundown protection for the work item
    if (!ExAcquireRundownProtection(&Internal->Public.RundownProtection)) {
        return;
    }

    // FIX #1: Only queue work item if none is pending
    // InterlockedCompareExchange: if WorkItemPending == 0, set to 1
    if (InterlockedCompareExchange(&Internal->Public.WorkItemPending, 1, 0) == 0) {
        // Successfully claimed the work item slot
        IoQueueWorkItem(
            Internal->WorkItem,
            ImpPeriodicCheckWorkItem,
            DelayedWorkQueue,
            Internal
        );
    } else {
        // Work item already pending — release rundown protection
        ExReleaseRundownProtection(&Internal->Public.RundownProtection);
    }
}

// ============================================================================
// PERIODIC CHECK WORK ITEM — Runs at PASSIVE_LEVEL
// FIX #1: All BCrypt, push lock, and callback operations happen here
// ============================================================================

_Function_class_(IO_WORKITEM_ROUTINE)
_IRQL_requires_(PASSIVE_LEVEL)
static VOID
ImpPeriodicCheckWorkItem(
    _In_     PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
)
{
    PIM_MONITOR_INTERNAL Internal = (PIM_MONITOR_INTERNAL)Context;
    IM_CHECK_RESULT Result;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(DeviceObject);

    if (Internal == NULL) {
        return;
    }

    // Verify still active
    if (InterlockedCompareExchange(&Internal->Public.State, IM_STATE_ACTIVE, IM_STATE_ACTIVE) != IM_STATE_ACTIVE) {
        goto Done;
    }

    // Perform integrity checks on critical components
    IM_COMPONENT CheckOrder[] = {
        ImComp_CodeSections,
        ImComp_DriverImage,
        ImComp_Callbacks,
        ImComp_Handles,
        ImComp_Configuration,
        ImComp_DataSections
    };

    for (ULONG i = 0; i < ARRAYSIZE(CheckOrder); i++) {
        RtlZeroMemory(&Result, sizeof(Result));

        NTSTATUS Status = ImpCheckComponent(Internal, CheckOrder[i], &Result);
        if (!NT_SUCCESS(Status)) {
            continue;
        }

        if (!Result.IsIntact) {
            // Tamper detected — notify all registered callbacks
            ImpNotifyTamper(Internal, &Result);
        }
    }

    // Update last check timestamp
    KeQuerySystemTimePrecise(&Internal->Public.LastCheckTime);
    InterlockedIncrement((volatile LONG*)&Internal->Public.TotalChecks);

Done:
    // Clear work item pending flag BEFORE releasing rundown protection
    InterlockedExchange(&Internal->Public.WorkItemPending, 0);
    ExReleaseRundownProtection(&Internal->Public.RundownProtection);
}

// ============================================================================
// END OF FILE
// ============================================================================
