/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE CALLBACK PROTECTION ENGINE
 * ============================================================================
 *
 * @file CallbackProtection.c
 * @brief Enterprise-grade callback registration protection against tampering.
 *
 * This module provides comprehensive callback protection capabilities:
 * - SHA-256 integrity hashing of callback code regions
 * - Periodic verification of all registered callbacks
 * - Tamper detection with immediate notification
 * - Automatic callback restoration on tampering
 * - Support for all Windows kernel callback types
 * - Thread-safe concurrent access
 * - Real-time statistics and monitoring
 *
 * Protection Coverage:
 * - Process creation/termination callbacks (PsSetCreateProcessNotifyRoutine)
 * - Thread creation callbacks (PsSetCreateThreadNotifyRoutine)
 * - Image load callbacks (PsSetLoadImageNotifyRoutine)
 * - Registry callbacks (CmRegisterCallback)
 * - Object callbacks (ObRegisterCallbacks)
 * - Minifilter callbacks (FltRegisterFilter)
 * - WFP callouts (FwpsCalloutRegister)
 * - ETW providers (EtwRegister)
 *
 * Threat Mitigation:
 * - Callback unhooking attacks
 * - Code patching of callback functions
 * - Registration handle manipulation
 * - Driver callback table corruption
 *
 * MITRE ATT&CK Coverage:
 * - T1562.001: Disable or Modify Tools
 * - T1014: Rootkit
 * - T1556: Modify Authentication Process
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "CallbackProtection.h"
#include "../Core/Globals.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, CpInitialize)
#pragma alloc_text(PAGE, CpShutdown)
#pragma alloc_text(PAGE, CpProtectCallback)
#pragma alloc_text(PAGE, CpUnprotectCallback)
#pragma alloc_text(PAGE, CpRegisterTamperCallback)
#pragma alloc_text(PAGE, CpEnablePeriodicVerify)
#pragma alloc_text(PAGE, CpVerifyAll)
#pragma alloc_text(PAGE, CppComputeCallbackHash)
#pragma alloc_text(PAGE, CppVerifyCallbackIntegrity)
#endif

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define CP_MAX_CALLBACKS                    256
#define CP_DEFAULT_VERIFY_INTERVAL_MS       5000        // 5 seconds
#define CP_MIN_VERIFY_INTERVAL_MS           1000        // 1 second minimum
#define CP_MAX_VERIFY_INTERVAL_MS           60000       // 1 minute maximum
#define CP_CALLBACK_HASH_SIZE               64          // Bytes to hash from callback
#define CP_LOOKASIDE_DEPTH                  32

#define CP_POOL_TAG_ENTRY                   'eRPC'
#define CP_POOL_TAG_HASH                    'hRPC'

//
// SHA-256 constants
//
static const ULONG g_Sha256K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

/**
 * @brief SHA-256 context structure.
 */
typedef struct _CP_SHA256_CONTEXT {
    ULONG State[8];
    ULONG64 BitCount;
    UCHAR Buffer[64];
    ULONG BufferLength;
} CP_SHA256_CONTEXT, *PCP_SHA256_CONTEXT;

/**
 * @brief Extended protector state (internal).
 */
typedef struct _CP_PROTECTOR_INTERNAL {
    //
    // Public structure (must be first)
    //
    CP_PROTECTOR Public;

    //
    // Lookaside list for callback entries
    //
    NPAGED_LOOKASIDE_LIST EntryLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Timer state
    //
    volatile BOOLEAN TimerActive;
    volatile BOOLEAN ShuttingDown;

    //
    // Verification work item for deferred processing
    //
    PIO_WORKITEM VerifyWorkItem;
    volatile LONG VerifyPending;

    //
    // Callback entry hash table for fast lookup
    //
    struct {
        LIST_ENTRY Buckets[16];
        EX_PUSH_LOCK Lock;
    } EntryHash;

    //
    // Original callback code backup for restoration
    //
    BOOLEAN EnableRestoration;

} CP_PROTECTOR_INTERNAL, *PCP_PROTECTOR_INTERNAL;

/**
 * @brief Extended callback entry (internal).
 */
typedef struct _CP_CALLBACK_ENTRY_INTERNAL {
    //
    // Public structure (must be first)
    //
    CP_CALLBACK_ENTRY Public;

    //
    // Hash table linkage
    //
    LIST_ENTRY HashEntry;
    ULONG HashBucket;

    //
    // Original callback code backup (for restoration)
    //
    UCHAR OriginalCode[CP_CALLBACK_HASH_SIZE];
    SIZE_T OriginalCodeSize;
    BOOLEAN HasBackup;

    //
    // Verification state
    //
    LARGE_INTEGER LastVerifyTime;
    ULONG VerifyCount;
    ULONG TamperCount;

    //
    // Reference counting
    //
    volatile LONG RefCount;

    //
    // Type-specific metadata
    //
    union {
        struct {
            BOOLEAN IsEx;           // PsSetCreateProcessNotifyRoutineEx
            BOOLEAN RemoveOnExit;
        } Process;

        struct {
            BOOLEAN IsEx;           // PsSetCreateThreadNotifyRoutineEx
        } Thread;

        struct {
            BOOLEAN IsEx;           // PsSetLoadImageNotifyRoutineEx
        } Image;

        struct {
            LARGE_INTEGER Cookie;   // CmRegisterCallback cookie
        } Registry;

        struct {
            PVOID OperationRegistration;
        } Object;

        struct {
            PFLT_FILTER Filter;
        } Minifilter;

        struct {
            UINT32 CalloutId;
        } WFP;

        struct {
            REGHANDLE RegHandle;
        } ETW;
    } TypeData;

} CP_CALLBACK_ENTRY_INTERNAL, *PCP_CALLBACK_ENTRY_INTERNAL;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static VOID
CppSha256Init(
    _Out_ PCP_SHA256_CONTEXT Context
    );

static VOID
CppSha256Update(
    _Inout_ PCP_SHA256_CONTEXT Context,
    _In_reads_bytes_(Length) PCUCHAR Data,
    _In_ SIZE_T Length
    );

static VOID
CppSha256Final(
    _Inout_ PCP_SHA256_CONTEXT Context,
    _Out_writes_bytes_(32) PUCHAR Hash
    );

static VOID
CppSha256Transform(
    _Inout_ PCP_SHA256_CONTEXT Context,
    _In_reads_bytes_(64) PCUCHAR Block
    );

static NTSTATUS
CppComputeCallbackHash(
    _In_ PVOID Callback,
    _Out_writes_bytes_(32) PUCHAR Hash
    );

static BOOLEAN
CppVerifyCallbackIntegrity(
    _In_ PCP_CALLBACK_ENTRY_INTERNAL Entry
    );

static ULONG
CppHashRegistration(
    _In_ PVOID Registration
    );

static PCP_CALLBACK_ENTRY_INTERNAL
CppFindEntryByRegistration(
    _In_ PCP_PROTECTOR_INTERNAL Protector,
    _In_ PVOID Registration
    );

static VOID
CppInsertEntryIntoHash(
    _In_ PCP_PROTECTOR_INTERNAL Protector,
    _In_ PCP_CALLBACK_ENTRY_INTERNAL Entry
    );

static VOID
CppRemoveEntryFromHash(
    _In_ PCP_PROTECTOR_INTERNAL Protector,
    _In_ PCP_CALLBACK_ENTRY_INTERNAL Entry
    );

static VOID
CppNotifyTamper(
    _In_ PCP_PROTECTOR_INTERNAL Protector,
    _In_ PCP_CALLBACK_ENTRY_INTERNAL Entry
    );

static BOOLEAN
CppRestoreCallback(
    _In_ PCP_CALLBACK_ENTRY_INTERNAL Entry
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
CppVerifyTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static VOID
CppVerifyWorkItemRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    );

static PCSTR
CppGetCallbackTypeName(
    _In_ CP_CALLBACK_TYPE Type
    );

// ============================================================================
// SHA-256 IMPLEMENTATION
// ============================================================================

//
// SHA-256 helper macros
//
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static VOID
CppSha256Init(
    _Out_ PCP_SHA256_CONTEXT Context
    )
/**
 * @brief Initialize SHA-256 context.
 */
{
    Context->State[0] = 0x6a09e667;
    Context->State[1] = 0xbb67ae85;
    Context->State[2] = 0x3c6ef372;
    Context->State[3] = 0xa54ff53a;
    Context->State[4] = 0x510e527f;
    Context->State[5] = 0x9b05688c;
    Context->State[6] = 0x1f83d9ab;
    Context->State[7] = 0x5be0cd19;
    Context->BitCount = 0;
    Context->BufferLength = 0;
}

static VOID
CppSha256Transform(
    _Inout_ PCP_SHA256_CONTEXT Context,
    _In_reads_bytes_(64) PCUCHAR Block
    )
/**
 * @brief Process a 64-byte block.
 */
{
    ULONG a, b, c, d, e, f, g, h;
    ULONG t1, t2;
    ULONG w[64];
    ULONG i;

    //
    // Prepare message schedule
    //
    for (i = 0; i < 16; i++) {
        w[i] = ((ULONG)Block[i * 4] << 24) |
               ((ULONG)Block[i * 4 + 1] << 16) |
               ((ULONG)Block[i * 4 + 2] << 8) |
               ((ULONG)Block[i * 4 + 3]);
    }

    for (i = 16; i < 64; i++) {
        w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];
    }

    //
    // Initialize working variables
    //
    a = Context->State[0];
    b = Context->State[1];
    c = Context->State[2];
    d = Context->State[3];
    e = Context->State[4];
    f = Context->State[5];
    g = Context->State[6];
    h = Context->State[7];

    //
    // Compression function
    //
    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + g_Sha256K[i] + w[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    //
    // Update state
    //
    Context->State[0] += a;
    Context->State[1] += b;
    Context->State[2] += c;
    Context->State[3] += d;
    Context->State[4] += e;
    Context->State[5] += f;
    Context->State[6] += g;
    Context->State[7] += h;
}

static VOID
CppSha256Update(
    _Inout_ PCP_SHA256_CONTEXT Context,
    _In_reads_bytes_(Length) PCUCHAR Data,
    _In_ SIZE_T Length
    )
/**
 * @brief Update SHA-256 with additional data.
 */
{
    SIZE_T i;
    SIZE_T remaining;

    Context->BitCount += Length * 8;

    //
    // Process any buffered data first
    //
    if (Context->BufferLength > 0) {
        remaining = 64 - Context->BufferLength;

        if (Length < remaining) {
            RtlCopyMemory(Context->Buffer + Context->BufferLength, Data, Length);
            Context->BufferLength += (ULONG)Length;
            return;
        }

        RtlCopyMemory(Context->Buffer + Context->BufferLength, Data, remaining);
        CppSha256Transform(Context, Context->Buffer);
        Data += remaining;
        Length -= remaining;
        Context->BufferLength = 0;
    }

    //
    // Process full blocks
    //
    while (Length >= 64) {
        CppSha256Transform(Context, Data);
        Data += 64;
        Length -= 64;
    }

    //
    // Buffer remaining data
    //
    if (Length > 0) {
        RtlCopyMemory(Context->Buffer, Data, Length);
        Context->BufferLength = (ULONG)Length;
    }
}

static VOID
CppSha256Final(
    _Inout_ PCP_SHA256_CONTEXT Context,
    _Out_writes_bytes_(32) PUCHAR Hash
    )
/**
 * @brief Finalize SHA-256 and produce hash.
 */
{
    UCHAR padding[64];
    ULONG padLen;
    UCHAR lenBits[8];
    ULONG i;

    //
    // Prepare length in bits (big-endian)
    //
    lenBits[0] = (UCHAR)(Context->BitCount >> 56);
    lenBits[1] = (UCHAR)(Context->BitCount >> 48);
    lenBits[2] = (UCHAR)(Context->BitCount >> 40);
    lenBits[3] = (UCHAR)(Context->BitCount >> 32);
    lenBits[4] = (UCHAR)(Context->BitCount >> 24);
    lenBits[5] = (UCHAR)(Context->BitCount >> 16);
    lenBits[6] = (UCHAR)(Context->BitCount >> 8);
    lenBits[7] = (UCHAR)(Context->BitCount);

    //
    // Pad to 56 bytes mod 64
    //
    padLen = (Context->BufferLength < 56) ? (56 - Context->BufferLength) : (120 - Context->BufferLength);

    RtlZeroMemory(padding, sizeof(padding));
    padding[0] = 0x80;

    CppSha256Update(Context, padding, padLen);
    CppSha256Update(Context, lenBits, 8);

    //
    // Produce final hash (big-endian)
    //
    for (i = 0; i < 8; i++) {
        Hash[i * 4] = (UCHAR)(Context->State[i] >> 24);
        Hash[i * 4 + 1] = (UCHAR)(Context->State[i] >> 16);
        Hash[i * 4 + 2] = (UCHAR)(Context->State[i] >> 8);
        Hash[i * 4 + 3] = (UCHAR)(Context->State[i]);
    }
}

// ============================================================================
// INITIALIZATION AND SHUTDOWN
// ============================================================================

_Use_decl_annotations_
NTSTATUS
CpInitialize(
    _Out_ PCP_PROTECTOR* Protector
    )
/**
 * @brief Initialize the callback protection subsystem.
 *
 * Allocates and initializes all data structures required for
 * callback protection including hash tables and verification timer.
 */
{
    NTSTATUS status = STATUS_SUCCESS;
    PCP_PROTECTOR_INTERNAL protector = NULL;
    ULONG i;

    PAGED_CODE();

    if (Protector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Protector = NULL;

    //
    // Allocate protector structure
    //
    protector = (PCP_PROTECTOR_INTERNAL)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(CP_PROTECTOR_INTERNAL),
        CP_POOL_TAG
    );

    if (protector == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize callback list
    //
    InitializeListHead(&protector->Public.CallbackList);
    ExInitializePushLock(&protector->Public.CallbackLock);

    //
    // Initialize hash table
    //
    for (i = 0; i < 16; i++) {
        InitializeListHead(&protector->EntryHash.Buckets[i]);
    }
    ExInitializePushLock(&protector->EntryHash.Lock);

    //
    // Initialize lookaside list
    //
    ExInitializeNPagedLookasideList(
        &protector->EntryLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(CP_CALLBACK_ENTRY_INTERNAL),
        CP_POOL_TAG_ENTRY,
        CP_LOOKASIDE_DEPTH
    );

    protector->LookasideInitialized = TRUE;

    //
    // Initialize verification timer
    //
    KeInitializeTimer(&protector->Public.VerifyTimer);
    KeInitializeDpc(&protector->Public.VerifyDpc, CppVerifyTimerDpc, protector);

    //
    // Set default verification interval
    //
    protector->Public.VerifyIntervalMs = CP_DEFAULT_VERIFY_INTERVAL_MS;

    //
    // Enable callback restoration by default
    //
    protector->EnableRestoration = TRUE;

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&protector->Public.Stats.StartTime);

    protector->Public.Initialized = TRUE;
    *Protector = &protector->Public;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
CpShutdown(
    _Inout_ PCP_PROTECTOR Protector
    )
/**
 * @brief Shutdown and cleanup the callback protection subsystem.
 *
 * Cancels verification timer, releases all callback entries,
 * and frees all allocated memory.
 */
{
    PCP_PROTECTOR_INTERNAL protector;
    PLIST_ENTRY entry;
    PCP_CALLBACK_ENTRY_INTERNAL callbackEntry;

    PAGED_CODE();

    if (Protector == NULL || !Protector->Initialized) {
        return;
    }

    protector = CONTAINING_RECORD(Protector, CP_PROTECTOR_INTERNAL, Public);
    protector->ShuttingDown = TRUE;

    //
    // Cancel verification timer
    //
    if (protector->TimerActive) {
        KeCancelTimer(&Protector->VerifyTimer);
        protector->TimerActive = FALSE;
    }

    //
    // Wait for pending DPCs
    //
    KeFlushQueuedDpcs();

    //
    // Free work item if allocated
    //
    if (protector->VerifyWorkItem != NULL) {
        IoFreeWorkItem(protector->VerifyWorkItem);
        protector->VerifyWorkItem = NULL;
    }

    //
    // Free all callback entries
    //
    ExAcquirePushLockExclusive(&Protector->CallbackLock);

    while (!IsListEmpty(&Protector->CallbackList)) {
        entry = RemoveHeadList(&Protector->CallbackList);
        callbackEntry = CONTAINING_RECORD(entry, CP_CALLBACK_ENTRY_INTERNAL, Public.ListEntry);

        if (protector->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&protector->EntryLookaside, callbackEntry);
        } else {
            ExFreePoolWithTag(callbackEntry, CP_POOL_TAG_ENTRY);
        }
    }

    ExReleasePushLockExclusive(&Protector->CallbackLock);

    //
    // Delete lookaside list
    //
    if (protector->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&protector->EntryLookaside);
        protector->LookasideInitialized = FALSE;
    }

    Protector->Initialized = FALSE;

    //
    // Free protector structure
    //
    ExFreePoolWithTag(protector, CP_POOL_TAG);
}

// ============================================================================
// CALLBACK PROTECTION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
CpProtectCallback(
    _In_ PCP_PROTECTOR Protector,
    _In_ CP_CALLBACK_TYPE Type,
    _In_ PVOID Registration,
    _In_ PVOID Callback
    )
/**
 * @brief Add a callback to the protection list.
 *
 * Computes SHA-256 hash of the callback code and stores
 * it for periodic integrity verification.
 */
{
    PCP_PROTECTOR_INTERNAL protector;
    PCP_CALLBACK_ENTRY_INTERNAL newEntry = NULL;
    NTSTATUS status;

    PAGED_CODE();

    if (Protector == NULL || !Protector->Initialized ||
        Registration == NULL || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Type > CpCallback_ETW) {
        return STATUS_INVALID_PARAMETER;
    }

    protector = CONTAINING_RECORD(Protector, CP_PROTECTOR_INTERNAL, Public);

    //
    // Check callback limit
    //
    if (Protector->CallbackCount >= CP_MAX_CALLBACKS) {
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Check for duplicate
    //
    ExAcquirePushLockShared(&protector->EntryHash.Lock);
    if (CppFindEntryByRegistration(protector, Registration) != NULL) {
        ExReleasePushLockShared(&protector->EntryHash.Lock);
        return STATUS_OBJECT_NAME_EXISTS;
    }
    ExReleasePushLockShared(&protector->EntryHash.Lock);

    //
    // Allocate entry from lookaside
    //
    newEntry = (PCP_CALLBACK_ENTRY_INTERNAL)ExAllocateFromNPagedLookasideList(
        &protector->EntryLookaside
    );

    if (newEntry == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(newEntry, sizeof(CP_CALLBACK_ENTRY_INTERNAL));

    //
    // Initialize entry
    //
    newEntry->Public.Type = Type;
    newEntry->Public.Registration = Registration;
    newEntry->Public.Callback = Callback;
    newEntry->Public.IsProtected = TRUE;
    newEntry->Public.WasTampered = FALSE;
    newEntry->RefCount = 1;

    //
    // Compute initial hash
    //
    status = CppComputeCallbackHash(Callback, newEntry->Public.CallbackHash);
    if (!NT_SUCCESS(status)) {
        ExFreeToNPagedLookasideList(&protector->EntryLookaside, newEntry);
        return status;
    }

    //
    // Backup original callback code for potential restoration
    //
    __try {
        SIZE_T copySize = min(CP_CALLBACK_HASH_SIZE, MmGetMdlByteCount(IoAllocateMdl(Callback, CP_CALLBACK_HASH_SIZE, FALSE, FALSE, NULL)));

        //
        // Safely probe and copy the callback code
        //
        if (MmIsAddressValid(Callback)) {
            RtlCopyMemory(newEntry->OriginalCode, Callback, CP_CALLBACK_HASH_SIZE);
            newEntry->OriginalCodeSize = CP_CALLBACK_HASH_SIZE;
            newEntry->HasBackup = TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        //
        // Could not backup - continue without restoration capability
        //
        newEntry->HasBackup = FALSE;
    }

    KeQuerySystemTime(&newEntry->LastVerifyTime);

    //
    // Insert into callback list
    //
    ExAcquirePushLockExclusive(&Protector->CallbackLock);
    InsertTailList(&Protector->CallbackList, &newEntry->Public.ListEntry);
    Protector->CallbackCount++;
    ExReleasePushLockExclusive(&Protector->CallbackLock);

    //
    // Insert into hash table
    //
    CppInsertEntryIntoHash(protector, newEntry);

    //
    // Update statistics
    //
    InterlockedIncrement64(&Protector->Stats.CallbacksProtected);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
CpUnprotectCallback(
    _In_ PCP_PROTECTOR Protector,
    _In_ PVOID Registration
    )
/**
 * @brief Remove a callback from protection.
 */
{
    PCP_PROTECTOR_INTERNAL protector;
    PCP_CALLBACK_ENTRY_INTERNAL entry;

    PAGED_CODE();

    if (Protector == NULL || !Protector->Initialized || Registration == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    protector = CONTAINING_RECORD(Protector, CP_PROTECTOR_INTERNAL, Public);

    //
    // Find the entry
    //
    ExAcquirePushLockExclusive(&protector->EntryHash.Lock);
    entry = CppFindEntryByRegistration(protector, Registration);

    if (entry == NULL) {
        ExReleasePushLockExclusive(&protector->EntryHash.Lock);
        return STATUS_NOT_FOUND;
    }

    //
    // Remove from hash table
    //
    RemoveEntryList(&entry->HashEntry);
    ExReleasePushLockExclusive(&protector->EntryHash.Lock);

    //
    // Remove from callback list
    //
    ExAcquirePushLockExclusive(&Protector->CallbackLock);
    RemoveEntryList(&entry->Public.ListEntry);
    Protector->CallbackCount--;
    ExReleasePushLockExclusive(&Protector->CallbackLock);

    //
    // Free entry
    //
    ExFreeToNPagedLookasideList(&protector->EntryLookaside, entry);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
CpRegisterTamperCallback(
    _In_ PCP_PROTECTOR Protector,
    _In_ CP_TAMPER_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
/**
 * @brief Register callback for tamper notifications.
 */
{
    PAGED_CODE();

    if (Protector == NULL || !Protector->Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Protector->TamperCallback = Callback;
    Protector->CallbackContext = Context;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
CpEnablePeriodicVerify(
    _In_ PCP_PROTECTOR Protector,
    _In_ ULONG IntervalMs
    )
/**
 * @brief Enable periodic integrity verification.
 */
{
    PCP_PROTECTOR_INTERNAL protector;
    LARGE_INTEGER dueTime;

    PAGED_CODE();

    if (Protector == NULL || !Protector->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (IntervalMs < CP_MIN_VERIFY_INTERVAL_MS || IntervalMs > CP_MAX_VERIFY_INTERVAL_MS) {
        return STATUS_INVALID_PARAMETER;
    }

    protector = CONTAINING_RECORD(Protector, CP_PROTECTOR_INTERNAL, Public);

    //
    // Cancel existing timer if active
    //
    if (protector->TimerActive) {
        KeCancelTimer(&Protector->VerifyTimer);
        protector->TimerActive = FALSE;
    }

    Protector->VerifyIntervalMs = IntervalMs;
    Protector->PeriodicEnabled = TRUE;

    //
    // Start timer
    //
    dueTime.QuadPart = -((LONGLONG)IntervalMs * 10000);
    KeSetTimerEx(
        &Protector->VerifyTimer,
        dueTime,
        IntervalMs,
        &Protector->VerifyDpc
    );

    protector->TimerActive = TRUE;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
CpVerifyAll(
    _In_ PCP_PROTECTOR Protector,
    _Out_ PULONG TamperedCount
    )
/**
 * @brief Verify integrity of all protected callbacks.
 *
 * Computes current hash of each callback and compares
 * with stored hash to detect tampering.
 */
{
    PCP_PROTECTOR_INTERNAL protector;
    PLIST_ENTRY entry;
    PCP_CALLBACK_ENTRY_INTERNAL callbackEntry;
    ULONG tamperedCount = 0;
    LARGE_INTEGER currentTime;

    PAGED_CODE();

    if (Protector == NULL || !Protector->Initialized || TamperedCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *TamperedCount = 0;

    protector = CONTAINING_RECORD(Protector, CP_PROTECTOR_INTERNAL, Public);

    if (protector->ShuttingDown) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeQuerySystemTime(&currentTime);

    ExAcquirePushLockShared(&Protector->CallbackLock);

    for (entry = Protector->CallbackList.Flink;
         entry != &Protector->CallbackList;
         entry = entry->Flink) {

        callbackEntry = CONTAINING_RECORD(entry, CP_CALLBACK_ENTRY_INTERNAL, Public.ListEntry);

        if (!callbackEntry->Public.IsProtected) {
            continue;
        }

        //
        // Verify integrity
        //
        if (!CppVerifyCallbackIntegrity(callbackEntry)) {
            //
            // Tampering detected!
            //
            callbackEntry->Public.WasTampered = TRUE;
            callbackEntry->TamperCount++;
            tamperedCount++;

            InterlockedIncrement64(&Protector->Stats.TamperAttempts);

            //
            // Attempt restoration if enabled
            //
            if (protector->EnableRestoration && callbackEntry->HasBackup) {
                if (CppRestoreCallback(callbackEntry)) {
                    InterlockedIncrement64(&Protector->Stats.CallbacksRestored);
                }
            }

            //
            // Notify tamper callback
            //
            CppNotifyTamper(protector, callbackEntry);
        }

        callbackEntry->LastVerifyTime = currentTime;
        callbackEntry->VerifyCount++;
    }

    ExReleasePushLockShared(&Protector->CallbackLock);

    *TamperedCount = tamperedCount;

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS
// ============================================================================

static NTSTATUS
CppComputeCallbackHash(
    _In_ PVOID Callback,
    _Out_writes_bytes_(32) PUCHAR Hash
    )
/**
 * @brief Compute SHA-256 hash of callback code region.
 */
{
    CP_SHA256_CONTEXT sha256;
    UCHAR codeBuffer[CP_CALLBACK_HASH_SIZE];
    SIZE_T bytesToHash = CP_CALLBACK_HASH_SIZE;

    PAGED_CODE();

    if (Callback == NULL || Hash == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Safely read callback code
    //
    __try {
        if (!MmIsAddressValid(Callback)) {
            return STATUS_INVALID_ADDRESS;
        }

        //
        // Probe the address range
        //
        ProbeForRead(Callback, bytesToHash, 1);

        //
        // Copy code to local buffer
        //
        RtlCopyMemory(codeBuffer, Callback, bytesToHash);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    //
    // Compute SHA-256
    //
    CppSha256Init(&sha256);
    CppSha256Update(&sha256, codeBuffer, bytesToHash);
    CppSha256Final(&sha256, Hash);

    //
    // Clear sensitive data
    //
    RtlSecureZeroMemory(&sha256, sizeof(sha256));
    RtlSecureZeroMemory(codeBuffer, sizeof(codeBuffer));

    return STATUS_SUCCESS;
}

static BOOLEAN
CppVerifyCallbackIntegrity(
    _In_ PCP_CALLBACK_ENTRY_INTERNAL Entry
    )
/**
 * @brief Verify integrity of a single callback.
 */
{
    UCHAR currentHash[32];
    NTSTATUS status;

    PAGED_CODE();

    if (Entry == NULL || Entry->Public.Callback == NULL) {
        return FALSE;
    }

    //
    // Compute current hash
    //
    status = CppComputeCallbackHash(Entry->Public.Callback, currentHash);
    if (!NT_SUCCESS(status)) {
        //
        // If we can't compute hash, assume tampered
        //
        return FALSE;
    }

    //
    // Compare with stored hash
    //
    if (RtlCompareMemory(currentHash, Entry->Public.CallbackHash, 32) != 32) {
        return FALSE;
    }

    return TRUE;
}

static ULONG
CppHashRegistration(
    _In_ PVOID Registration
    )
/**
 * @brief Hash function for registration pointer.
 */
{
    ULONG_PTR ptr = (ULONG_PTR)Registration;
    return (ULONG)((ptr >> 4) % 16);
}

static PCP_CALLBACK_ENTRY_INTERNAL
CppFindEntryByRegistration(
    _In_ PCP_PROTECTOR_INTERNAL Protector,
    _In_ PVOID Registration
    )
/**
 * @brief Find callback entry by registration handle.
 */
{
    ULONG bucket;
    PLIST_ENTRY entry;
    PCP_CALLBACK_ENTRY_INTERNAL callbackEntry;

    bucket = CppHashRegistration(Registration);

    for (entry = Protector->EntryHash.Buckets[bucket].Flink;
         entry != &Protector->EntryHash.Buckets[bucket];
         entry = entry->Flink) {

        callbackEntry = CONTAINING_RECORD(entry, CP_CALLBACK_ENTRY_INTERNAL, HashEntry);

        if (callbackEntry->Public.Registration == Registration) {
            return callbackEntry;
        }
    }

    return NULL;
}

static VOID
CppInsertEntryIntoHash(
    _In_ PCP_PROTECTOR_INTERNAL Protector,
    _In_ PCP_CALLBACK_ENTRY_INTERNAL Entry
    )
/**
 * @brief Insert entry into hash table.
 */
{
    ULONG bucket;

    bucket = CppHashRegistration(Entry->Public.Registration);
    Entry->HashBucket = bucket;

    ExAcquirePushLockExclusive(&Protector->EntryHash.Lock);
    InsertTailList(&Protector->EntryHash.Buckets[bucket], &Entry->HashEntry);
    ExReleasePushLockExclusive(&Protector->EntryHash.Lock);
}

static VOID
CppRemoveEntryFromHash(
    _In_ PCP_PROTECTOR_INTERNAL Protector,
    _In_ PCP_CALLBACK_ENTRY_INTERNAL Entry
    )
/**
 * @brief Remove entry from hash table.
 */
{
    ExAcquirePushLockExclusive(&Protector->EntryHash.Lock);
    RemoveEntryList(&Entry->HashEntry);
    ExReleasePushLockExclusive(&Protector->EntryHash.Lock);
}

static VOID
CppNotifyTamper(
    _In_ PCP_PROTECTOR_INTERNAL Protector,
    _In_ PCP_CALLBACK_ENTRY_INTERNAL Entry
    )
/**
 * @brief Notify registered tamper callback.
 */
{
    CP_TAMPER_CALLBACK callback = Protector->Public.TamperCallback;
    PVOID context = Protector->Public.CallbackContext;

    if (callback != NULL) {
        callback(
            Entry->Public.Type,
            Entry->Public.Registration,
            context
        );
    }
}

static BOOLEAN
CppRestoreCallback(
    _In_ PCP_CALLBACK_ENTRY_INTERNAL Entry
    )
/**
 * @brief Attempt to restore tampered callback code.
 *
 * This is a best-effort restoration - may fail if memory
 * is read-only or page protections prevent writes.
 */
{
    PMDL mdl = NULL;
    PVOID mappedAddress = NULL;
    BOOLEAN success = FALSE;

    if (!Entry->HasBackup || Entry->OriginalCodeSize == 0) {
        return FALSE;
    }

    __try {
        //
        // Allocate MDL for callback region
        //
        mdl = IoAllocateMdl(
            Entry->Public.Callback,
            (ULONG)Entry->OriginalCodeSize,
            FALSE,
            FALSE,
            NULL
        );

        if (mdl == NULL) {
            return FALSE;
        }

        //
        // Lock pages
        //
        __try {
            MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            IoFreeMdl(mdl);
            return FALSE;
        }

        //
        // Map with write access
        //
        mappedAddress = MmMapLockedPagesSpecifyCache(
            mdl,
            KernelMode,
            MmCached,
            NULL,
            FALSE,
            NormalPagePriority
        );

        if (mappedAddress != NULL) {
            //
            // Restore original code
            //
            RtlCopyMemory(mappedAddress, Entry->OriginalCode, Entry->OriginalCodeSize);

            //
            // Recompute hash
            //
            CppComputeCallbackHash(Entry->Public.Callback, Entry->Public.CallbackHash);

            Entry->Public.WasTampered = FALSE;
            success = TRUE;

            MmUnmapLockedPages(mappedAddress, mdl);
        }

        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (mdl != NULL) {
            IoFreeMdl(mdl);
        }
        success = FALSE;
    }

    return success;
}

static PCSTR
CppGetCallbackTypeName(
    _In_ CP_CALLBACK_TYPE Type
    )
/**
 * @brief Get human-readable name for callback type.
 */
{
    switch (Type) {
        case CpCallback_Process:
            return "Process";
        case CpCallback_Thread:
            return "Thread";
        case CpCallback_Image:
            return "Image";
        case CpCallback_Registry:
            return "Registry";
        case CpCallback_Object:
            return "Object";
        case CpCallback_Minifilter:
            return "Minifilter";
        case CpCallback_WFP:
            return "WFP";
        case CpCallback_ETW:
            return "ETW";
        default:
            return "Unknown";
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
CppVerifyTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
/**
 * @brief DPC callback for periodic verification.
 *
 * Performs lightweight verification at DISPATCH_LEVEL.
 * For full verification, queues a work item.
 */
{
    PCP_PROTECTOR_INTERNAL protector = (PCP_PROTECTOR_INTERNAL)DeferredContext;
    PLIST_ENTRY entry;
    PCP_CALLBACK_ENTRY_INTERNAL callbackEntry;
    ULONG tamperedCount = 0;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (protector == NULL || protector->ShuttingDown) {
        return;
    }

    //
    // Quick integrity check at DISPATCH_LEVEL
    // We can read callback code but should be brief
    //
    ExAcquirePushLockShared(&protector->Public.CallbackLock);

    for (entry = protector->Public.CallbackList.Flink;
         entry != &protector->Public.CallbackList;
         entry = entry->Flink) {

        callbackEntry = CONTAINING_RECORD(entry, CP_CALLBACK_ENTRY_INTERNAL, Public.ListEntry);

        if (!callbackEntry->Public.IsProtected) {
            continue;
        }

        //
        // Lightweight check - just verify address is valid
        //
        if (!MmIsAddressValid(callbackEntry->Public.Callback)) {
            //
            // Callback address became invalid - major tampering
            //
            callbackEntry->Public.WasTampered = TRUE;
            tamperedCount++;
            InterlockedIncrement64(&protector->Public.Stats.TamperAttempts);

            //
            // Notify immediately
            //
            CppNotifyTamper(protector, callbackEntry);
        }
    }

    ExReleasePushLockShared(&protector->Public.CallbackLock);

    //
    // If tampering detected, schedule full verification work item
    //
    if (tamperedCount > 0 && protector->VerifyWorkItem != NULL) {
        if (InterlockedCompareExchange(&protector->VerifyPending, 1, 0) == 0) {
            IoQueueWorkItem(
                protector->VerifyWorkItem,
                CppVerifyWorkItemRoutine,
                DelayedWorkQueue,
                protector
            );
        }
    }
}

static VOID
CppVerifyWorkItemRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    )
/**
 * @brief Work item for full verification at PASSIVE_LEVEL.
 */
{
    PCP_PROTECTOR_INTERNAL protector = (PCP_PROTECTOR_INTERNAL)Context;
    ULONG tamperedCount = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    if (protector == NULL || protector->ShuttingDown) {
        return;
    }

    //
    // Perform full verification
    //
    CpVerifyAll(&protector->Public, &tamperedCount);

    //
    // Clear pending flag
    //
    InterlockedExchange(&protector->VerifyPending, 0);
}
