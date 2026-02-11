/*++
    ShadowStrike Next-Generation Antivirus
    Module: CallbackProtection.c - Callback registration protection engine

    Purpose: Protects kernel callback registrations against tampering by
             hashing the callback code region (SHA-256 of first 256 bytes)
             and periodically verifying integrity. On tamper detection,
             notifies a registered callback and optionally restores the
             original code via MDL-mapped write.

    Synchronization Strategy:
    - Single EX_PUSH_LOCK (CallbackLock) protects the callback list AND
      hash table. Always bracketed with KeEnterCriticalRegion /
      KeLeaveCriticalRegion (MANDATORY for push locks to prevent APC
      deadlock).
    - EX_RUNDOWN_REF on all public APIs. CpShutdown waits for rundown
      completion before tearing down.
    - Timer DPC does ZERO lock acquisition — it only queues a work item.
      All verification runs at PASSIVE_LEVEL on the work item thread.
    - Tamper notification callback invoked only at PASSIVE_LEVEL.

    Safety Guarantees:
    - No ProbeForRead on kernel addresses (ProbeForRead is user-mode only).
    - No MmIsAddressValid (point-in-time, unreliable).
    - Kernel code reads use __try/__except with direct RtlCopyMemory.
    - CpProtectCallback duplicate check + insert is atomic under
      exclusive lock (no TOCTOU).
    - CpUnprotectCallback removes from both list and hash table under
      single exclusive lock acquisition.
    - Reference counting on entries: +1 list, verification bumps refcount
      while iterating. Free only at refcount==0.
    - Work item allocated in CpInitialize, waited on during CpShutdown
      via VerifyComplete event.

    Copyright (c) ShadowStrike Team
--*/

#include "CallbackProtection.h"
#include "../Core/Globals.h"

// ============================================================================
// PAGE SECTION
// ============================================================================

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, CpInitialize)
#pragma alloc_text(PAGE, CpShutdown)
#pragma alloc_text(PAGE, CpProtectCallback)
#pragma alloc_text(PAGE, CpUnprotectCallback)
#pragma alloc_text(PAGE, CpRegisterTamperCallback)
#pragma alloc_text(PAGE, CpEnablePeriodicVerify)
#pragma alloc_text(PAGE, CpDisablePeriodicVerify)
#pragma alloc_text(PAGE, CpVerifyAll)
#pragma alloc_text(PAGE, CpGetStatistics)
#endif

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define CP_DEFAULT_VERIFY_INTERVAL_MS   5000
#define CP_MIN_VERIFY_INTERVAL_MS       1000
#define CP_MAX_VERIFY_INTERVAL_MS       60000
#define CP_LOOKASIDE_DEPTH              16
#define CP_HASH_BUCKETS                 16

// ============================================================================
// SHA-256 CONSTANTS
// ============================================================================

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
// SHA-256 MACROS
// ============================================================================

#define ROTR(x, n)    (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)   (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)         (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x)         (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x)        (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x)        (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

typedef struct _CP_SHA256_CTX {
    ULONG State[8];
    ULONG64 BitCount;
    UCHAR Buffer[64];
    ULONG BufferLen;
} CP_SHA256_CTX;

typedef struct _CP_CALLBACK_ENTRY_INTERNAL {
    //
    // List linkage — main ordered list
    //
    LIST_ENTRY ListEntry;

    //
    // Hash table linkage — fast lookup by Registration pointer
    //
    LIST_ENTRY HashEntry;
    ULONG HashBucket;

    //
    // Core identity
    //
    CP_CALLBACK_TYPE Type;
    PVOID Registration;
    PVOID Callback;

    //
    // SHA-256 of first CP_CALLBACK_HASH_BYTES bytes of callback code
    //
    UCHAR CodeHash[32];

    //
    // Original code backup for restoration
    //
    UCHAR OriginalCode[CP_CALLBACK_HASH_BYTES];
    SIZE_T OriginalCodeSize;
    BOOLEAN HasBackup;

    //
    // Protection state
    //
    BOOLEAN IsProtected;
    BOOLEAN WasTampered;

    //
    // Verification stats per entry
    //
    LARGE_INTEGER LastVerifyTime;
    ULONG VerifyCount;
    ULONG TamperCount;

    //
    // Reference counting: 1 for list ownership, +1 during iteration
    //
    volatile LONG RefCount;

} CP_CALLBACK_ENTRY_INTERNAL, *PCP_CALLBACK_ENTRY_INTERNAL;

//
// Full internal protector state. Opaque to consumers.
//
struct _CP_PROTECTOR {
    //
    // Lifecycle
    //
    volatile LONG Initialized;
    EX_RUNDOWN_REF RundownRef;

    //
    // Single lock for callback list + hash table.
    // ALWAYS use CppAcquire*/CppRelease* wrappers.
    //
    EX_PUSH_LOCK CallbackLock;
    LIST_ENTRY CallbackList;
    ULONG CallbackCount;

    //
    // Hash table for O(1) lookup by Registration pointer
    //
    LIST_ENTRY HashBuckets[CP_HASH_BUCKETS];

    //
    // Lookaside for entry allocations
    //
    NPAGED_LOOKASIDE_LIST EntryLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Tamper notification
    //
    CP_TAMPER_CALLBACK TamperCallback;
    PVOID TamperContext;

    //
    // Periodic verification via timer → DPC → work item
    //
    KTIMER VerifyTimer;
    KDPC VerifyDpc;
    ULONG VerifyIntervalMs;
    volatile LONG TimerActive;
    volatile LONG PeriodicEnabled;

    //
    // Work item for PASSIVE_LEVEL verification
    //
    PIO_WORKITEM VerifyWorkItem;
    volatile LONG VerifyPending;
    KEVENT VerifyComplete;

    //
    // Enable automatic code restoration on tamper
    //
    BOOLEAN EnableRestoration;

    //
    // Statistics
    //
    struct {
        volatile LONG64 CallbacksProtected;
        volatile LONG64 TamperAttempts;
        volatile LONG64 CallbacksRestored;
        volatile LONG64 VerificationsRun;
        LARGE_INTEGER StartTime;
    } Stats;
};

// ============================================================================
// PUSH LOCK WRAPPERS — Mandatory KeEnterCriticalRegion bracketing
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
static __forceinline VOID
CppAcquireLockShared(
    _Inout_ PEX_PUSH_LOCK Lock
    )
{
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(Lock);
}

_IRQL_requires_max_(APC_LEVEL)
static __forceinline VOID
CppReleaseLockShared(
    _Inout_ PEX_PUSH_LOCK Lock
    )
{
    ExReleasePushLockShared(Lock);
    KeLeaveCriticalRegion();
}

_IRQL_requires_max_(APC_LEVEL)
static __forceinline VOID
CppAcquireLockExclusive(
    _Inout_ PEX_PUSH_LOCK Lock
    )
{
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(Lock);
}

_IRQL_requires_max_(APC_LEVEL)
static __forceinline VOID
CppReleaseLockExclusive(
    _Inout_ PEX_PUSH_LOCK Lock
    )
{
    ExReleasePushLockExclusive(Lock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static VOID
CppSha256Init(
    _Out_ CP_SHA256_CTX* Ctx
    );

static VOID
CppSha256Update(
    _Inout_ CP_SHA256_CTX* Ctx,
    _In_reads_bytes_(Len) const UCHAR* Data,
    _In_ SIZE_T Len
    );

static VOID
CppSha256Final(
    _Inout_ CP_SHA256_CTX* Ctx,
    _Out_writes_bytes_(32) UCHAR* Hash
    );

static VOID
CppSha256Transform(
    _Inout_ CP_SHA256_CTX* Ctx,
    _In_reads_bytes_(64) const UCHAR* Block
    );

static NTSTATUS
CppComputeCodeHash(
    _In_ PVOID CodeAddress,
    _In_ SIZE_T BytesToHash,
    _Out_writes_bytes_(32) UCHAR* Hash
    );

static NTSTATUS
CppReadKernelCode(
    _In_ PVOID Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
    );

static ULONG
CppHashPointer(
    _In_ PVOID Ptr
    );

static PCP_CALLBACK_ENTRY_INTERNAL
CppFindByRegistration(
    _In_ PCP_PROTECTOR Protector,
    _In_ PVOID Registration
    );

static VOID
CppReferenceEntry(
    _Inout_ PCP_CALLBACK_ENTRY_INTERNAL Entry
    );

static VOID
CppDereferenceEntry(
    _In_ PCP_PROTECTOR Protector,
    _Inout_ PCP_CALLBACK_ENTRY_INTERNAL Entry
    );

static BOOLEAN
CppVerifySingleEntry(
    _In_ PCP_CALLBACK_ENTRY_INTERNAL Entry
    );

static BOOLEAN
CppRestoreCallback(
    _In_ PCP_CALLBACK_ENTRY_INTERNAL Entry
    );

static VOID
CppNotifyTamper(
    _In_ PCP_PROTECTOR Protector,
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

static VOID
CppArmTimer(
    _In_ PCP_PROTECTOR Protector
    );

// ============================================================================
// SHA-256 IMPLEMENTATION
// ============================================================================

static VOID
CppSha256Init(
    _Out_ CP_SHA256_CTX* Ctx
    )
{
    Ctx->State[0] = 0x6a09e667;
    Ctx->State[1] = 0xbb67ae85;
    Ctx->State[2] = 0x3c6ef372;
    Ctx->State[3] = 0xa54ff53a;
    Ctx->State[4] = 0x510e527f;
    Ctx->State[5] = 0x9b05688c;
    Ctx->State[6] = 0x1f83d9ab;
    Ctx->State[7] = 0x5be0cd19;
    Ctx->BitCount = 0;
    Ctx->BufferLen = 0;
}

static VOID
CppSha256Transform(
    _Inout_ CP_SHA256_CTX* Ctx,
    _In_reads_bytes_(64) const UCHAR* Block
    )
{
    ULONG a, b, c, d, e, f, g, h;
    ULONG t1, t2;
    ULONG w[64];
    ULONG i;

    for (i = 0; i < 16; i++) {
        w[i] = ((ULONG)Block[i * 4] << 24) |
               ((ULONG)Block[i * 4 + 1] << 16) |
               ((ULONG)Block[i * 4 + 2] << 8) |
               ((ULONG)Block[i * 4 + 3]);
    }

    for (i = 16; i < 64; i++) {
        w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];
    }

    a = Ctx->State[0]; b = Ctx->State[1];
    c = Ctx->State[2]; d = Ctx->State[3];
    e = Ctx->State[4]; f = Ctx->State[5];
    g = Ctx->State[6]; h = Ctx->State[7];

    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + g_Sha256K[i] + w[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    Ctx->State[0] += a; Ctx->State[1] += b;
    Ctx->State[2] += c; Ctx->State[3] += d;
    Ctx->State[4] += e; Ctx->State[5] += f;
    Ctx->State[6] += g; Ctx->State[7] += h;
}

static VOID
CppSha256Update(
    _Inout_ CP_SHA256_CTX* Ctx,
    _In_reads_bytes_(Len) const UCHAR* Data,
    _In_ SIZE_T Len
    )
{
    SIZE_T remaining;

    Ctx->BitCount += Len * 8;

    if (Ctx->BufferLen > 0) {
        remaining = 64 - Ctx->BufferLen;
        if (Len < remaining) {
            RtlCopyMemory(Ctx->Buffer + Ctx->BufferLen, Data, Len);
            Ctx->BufferLen += (ULONG)Len;
            return;
        }
        RtlCopyMemory(Ctx->Buffer + Ctx->BufferLen, Data, remaining);
        CppSha256Transform(Ctx, Ctx->Buffer);
        Data += remaining;
        Len -= remaining;
        Ctx->BufferLen = 0;
    }

    while (Len >= 64) {
        CppSha256Transform(Ctx, Data);
        Data += 64;
        Len -= 64;
    }

    if (Len > 0) {
        RtlCopyMemory(Ctx->Buffer, Data, Len);
        Ctx->BufferLen = (ULONG)Len;
    }
}

static VOID
CppSha256Final(
    _Inout_ CP_SHA256_CTX* Ctx,
    _Out_writes_bytes_(32) UCHAR* Hash
    )
{
    UCHAR padding[64];
    ULONG padLen;
    UCHAR lenBits[8];
    ULONG i;

    lenBits[0] = (UCHAR)(Ctx->BitCount >> 56);
    lenBits[1] = (UCHAR)(Ctx->BitCount >> 48);
    lenBits[2] = (UCHAR)(Ctx->BitCount >> 40);
    lenBits[3] = (UCHAR)(Ctx->BitCount >> 32);
    lenBits[4] = (UCHAR)(Ctx->BitCount >> 24);
    lenBits[5] = (UCHAR)(Ctx->BitCount >> 16);
    lenBits[6] = (UCHAR)(Ctx->BitCount >> 8);
    lenBits[7] = (UCHAR)(Ctx->BitCount);

    padLen = (Ctx->BufferLen < 56) ?
             (56 - Ctx->BufferLen) :
             (120 - Ctx->BufferLen);

    RtlZeroMemory(padding, sizeof(padding));
    padding[0] = 0x80;

    CppSha256Update(Ctx, padding, padLen);
    CppSha256Update(Ctx, lenBits, 8);

    for (i = 0; i < 8; i++) {
        Hash[i * 4]     = (UCHAR)(Ctx->State[i] >> 24);
        Hash[i * 4 + 1] = (UCHAR)(Ctx->State[i] >> 16);
        Hash[i * 4 + 2] = (UCHAR)(Ctx->State[i] >> 8);
        Hash[i * 4 + 3] = (UCHAR)(Ctx->State[i]);
    }
}

// ============================================================================
// KERNEL CODE READ HELPER
// ============================================================================

/**
 * Safely read kernel code bytes. No ProbeForRead (kernel addresses only).
 * No MmIsAddressValid (unreliable). Uses __try/__except for fault handling.
 */
static NTSTATUS
CppReadKernelCode(
    _In_ PVOID Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
    )
{
    if (Address == NULL || Buffer == NULL || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Kernel addresses must be above MmUserProbeAddress.
    // Reject anything in user space.
    //
    if ((ULONG_PTR)Address < (ULONG_PTR)MmUserProbeAddress) {
        return STATUS_INVALID_ADDRESS;
    }

    __try {
        RtlCopyMemory(Buffer, Address, Size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// HASH COMPUTATION
// ============================================================================

/**
 * Compute SHA-256 of BytesToHash bytes starting at CodeAddress.
 * Reads kernel code safely, then hashes the local copy.
 */
static NTSTATUS
CppComputeCodeHash(
    _In_ PVOID CodeAddress,
    _In_ SIZE_T BytesToHash,
    _Out_writes_bytes_(32) UCHAR* Hash
    )
{
    CP_SHA256_CTX sha;
    UCHAR localBuf[CP_CALLBACK_HASH_BYTES];
    NTSTATUS status;

    if (BytesToHash > sizeof(localBuf)) {
        BytesToHash = sizeof(localBuf);
    }

    status = CppReadKernelCode(CodeAddress, localBuf, BytesToHash);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    CppSha256Init(&sha);
    CppSha256Update(&sha, localBuf, BytesToHash);
    CppSha256Final(&sha, Hash);

    RtlSecureZeroMemory(&sha, sizeof(sha));
    RtlSecureZeroMemory(localBuf, sizeof(localBuf));

    return STATUS_SUCCESS;
}

// ============================================================================
// HASH TABLE HELPERS
// ============================================================================

static ULONG
CppHashPointer(
    _In_ PVOID Ptr
    )
{
    ULONG_PTR val = (ULONG_PTR)Ptr;
    //
    // FNV-1a-style mix for pointer → bucket index.
    // Shift right 4 to discard alignment bits.
    //
    val = val >> 4;
    val ^= val >> 16;
    return (ULONG)(val % CP_HASH_BUCKETS);
}

/**
 * Find entry by Registration pointer in hash table.
 * Caller MUST hold CallbackLock (shared or exclusive).
 */
static PCP_CALLBACK_ENTRY_INTERNAL
CppFindByRegistration(
    _In_ PCP_PROTECTOR Protector,
    _In_ PVOID Registration
    )
{
    ULONG bucket;
    PLIST_ENTRY entry;
    PCP_CALLBACK_ENTRY_INTERNAL cbEntry;

    bucket = CppHashPointer(Registration);

    for (entry = Protector->HashBuckets[bucket].Flink;
         entry != &Protector->HashBuckets[bucket];
         entry = entry->Flink) {

        cbEntry = CONTAINING_RECORD(entry, CP_CALLBACK_ENTRY_INTERNAL, HashEntry);
        if (cbEntry->Registration == Registration) {
            return cbEntry;
        }
    }

    return NULL;
}

// ============================================================================
// REFERENCE COUNTING
// ============================================================================

static __forceinline VOID
CppReferenceEntry(
    _Inout_ PCP_CALLBACK_ENTRY_INTERNAL Entry
    )
{
    InterlockedIncrement(&Entry->RefCount);
}

/**
 * Decrement refcount. When it reaches 0, free to lookaside.
 * Caller must NOT hold CallbackLock when refcount could reach 0.
 */
static VOID
CppDereferenceEntry(
    _In_ PCP_PROTECTOR Protector,
    _Inout_ PCP_CALLBACK_ENTRY_INTERNAL Entry
    )
{
    LONG newRef = InterlockedDecrement(&Entry->RefCount);
    NT_ASSERT(newRef >= 0);

    if (newRef == 0) {
        if (Protector->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&Protector->EntryLookaside, Entry);
        } else {
            ExFreePoolWithTag(Entry, CP_POOL_TAG_ENTRY);
        }
    }
}

// ============================================================================
// INITIALIZATION / SHUTDOWN
// ============================================================================

_Use_decl_annotations_
NTSTATUS
CpInitialize(
    _Out_ PCP_PROTECTOR* Protector
    )
{
    PCP_PROTECTOR prot = NULL;
    ULONG i;

    PAGED_CODE();

    if (Protector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Protector = NULL;

    prot = (PCP_PROTECTOR)ExAllocatePoolZero(
        NonPagedPoolNx,
        sizeof(CP_PROTECTOR),
        CP_POOL_TAG
    );

    if (prot == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ExInitializeRundownProtection(&prot->RundownRef);
    ExInitializePushLock(&prot->CallbackLock);
    InitializeListHead(&prot->CallbackList);

    for (i = 0; i < CP_HASH_BUCKETS; i++) {
        InitializeListHead(&prot->HashBuckets[i]);
    }

    ExInitializeNPagedLookasideList(
        &prot->EntryLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(CP_CALLBACK_ENTRY_INTERNAL),
        CP_POOL_TAG_ENTRY,
        CP_LOOKASIDE_DEPTH
    );
    prot->LookasideInitialized = TRUE;

    KeInitializeTimer(&prot->VerifyTimer);
    KeInitializeDpc(&prot->VerifyDpc, CppVerifyTimerDpc, prot);
    KeInitializeEvent(&prot->VerifyComplete, NotificationEvent, TRUE);

    prot->VerifyIntervalMs = CP_DEFAULT_VERIFY_INTERVAL_MS;
    prot->EnableRestoration = TRUE;

    //
    // Allocate work item. Requires g_DriverData.DriverObject from Globals.
    // If DriverObject is not available yet, the work item is NULL and
    // periodic verification will be unavailable (CpEnablePeriodicVerify
    // will return STATUS_DEVICE_NOT_READY).
    //
    if (g_DriverData.DriverObject != NULL) {
        //
        // IoAllocateWorkItem needs a device object. Use the unnamed
        // control device from the driver object if available.
        //
        PDEVICE_OBJECT devObj = g_DriverData.DriverObject->DeviceObject;
        if (devObj != NULL) {
            prot->VerifyWorkItem = IoAllocateWorkItem(devObj);
        }
    }

    KeQuerySystemTime(&prot->Stats.StartTime);
    InterlockedExchange(&prot->Initialized, TRUE);
    *Protector = prot;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
CpShutdown(
    _Inout_ PCP_PROTECTOR Protector
    )
{
    PLIST_ENTRY entry;
    PCP_CALLBACK_ENTRY_INTERNAL cbEntry;

    PAGED_CODE();

    if (Protector == NULL || !Protector->Initialized) {
        return;
    }

    //
    // Prevent new API calls from entering.
    //
    InterlockedExchange(&Protector->Initialized, FALSE);

    //
    // Cancel timer. After KeCancelTimer, no new DPCs fire.
    //
    if (InterlockedExchange(&Protector->TimerActive, FALSE)) {
        KeCancelTimer(&Protector->VerifyTimer);
    }

    //
    // Flush all queued DPCs so CppVerifyTimerDpc has fully returned.
    //
    KeFlushQueuedDpcs();

    //
    // Wait for any in-flight work item to complete.
    // The work item sets VerifyComplete when it finishes.
    //
    KeWaitForSingleObject(
        &Protector->VerifyComplete,
        Executive,
        KernelMode,
        FALSE,
        NULL
    );

    //
    // Wait for all in-flight public API calls to drain.
    //
    ExWaitForRundownProtectionRelease(&Protector->RundownRef);

    //
    // Free work item (safe now — no work item is in flight).
    //
    if (Protector->VerifyWorkItem != NULL) {
        IoFreeWorkItem(Protector->VerifyWorkItem);
        Protector->VerifyWorkItem = NULL;
    }

    //
    // Free all callback entries. Nobody is iterating now.
    //
    CppAcquireLockExclusive(&Protector->CallbackLock);

    while (!IsListEmpty(&Protector->CallbackList)) {
        entry = RemoveHeadList(&Protector->CallbackList);
        cbEntry = CONTAINING_RECORD(entry, CP_CALLBACK_ENTRY_INTERNAL, ListEntry);

        //
        // Remove from hash table too.
        //
        RemoveEntryList(&cbEntry->HashEntry);

        //
        // Drop the list reference. If refcount reaches 0 it frees.
        // Since we waited for rundown, no other thread holds a ref.
        //
        cbEntry->RefCount = 0; // Force-free since we own everything
        if (Protector->LookasideInitialized) {
            ExFreeToNPagedLookasideList(&Protector->EntryLookaside, cbEntry);
        } else {
            ExFreePoolWithTag(cbEntry, CP_POOL_TAG_ENTRY);
        }
    }

    CppReleaseLockExclusive(&Protector->CallbackLock);

    //
    // Delete lookaside.
    //
    if (Protector->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&Protector->EntryLookaside);
        Protector->LookasideInitialized = FALSE;
    }

    ExFreePoolWithTag(Protector, CP_POOL_TAG);
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
{
    PCP_CALLBACK_ENTRY_INTERNAL newEntry = NULL;
    NTSTATUS status;
    ULONG bucket;

    PAGED_CODE();

    if (Protector == NULL || !Protector->Initialized ||
        Registration == NULL || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if ((ULONG)Type >= (ULONG)CpCallback_MaxType) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Protector->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    //
    // Pre-allocate entry BEFORE acquiring lock.
    //
    newEntry = (PCP_CALLBACK_ENTRY_INTERNAL)ExAllocateFromNPagedLookasideList(
        &Protector->EntryLookaside
    );

    if (newEntry == NULL) {
        ExReleaseRundownProtection(&Protector->RundownRef);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(newEntry, sizeof(CP_CALLBACK_ENTRY_INTERNAL));
    InitializeListHead(&newEntry->ListEntry);
    InitializeListHead(&newEntry->HashEntry);

    newEntry->Type = Type;
    newEntry->Registration = Registration;
    newEntry->Callback = Callback;
    newEntry->IsProtected = TRUE;
    newEntry->RefCount = 1; // Owned by the list

    //
    // Compute hash of callback code.
    //
    status = CppComputeCodeHash(Callback, CP_CALLBACK_HASH_BYTES, newEntry->CodeHash);
    if (!NT_SUCCESS(status)) {
        ExFreeToNPagedLookasideList(&Protector->EntryLookaside, newEntry);
        ExReleaseRundownProtection(&Protector->RundownRef);
        return status;
    }

    //
    // Backup original code for potential restoration.
    //
    status = CppReadKernelCode(Callback, newEntry->OriginalCode, CP_CALLBACK_HASH_BYTES);
    if (NT_SUCCESS(status)) {
        newEntry->OriginalCodeSize = CP_CALLBACK_HASH_BYTES;
        newEntry->HasBackup = TRUE;
    } else {
        newEntry->HasBackup = FALSE;
    }

    KeQuerySystemTime(&newEntry->LastVerifyTime);

    //
    // ATOMIC: check duplicate + insert under single exclusive lock.
    // This eliminates the TOCTOU race.
    //
    CppAcquireLockExclusive(&Protector->CallbackLock);

    if (Protector->CallbackCount >= CP_MAX_CALLBACKS) {
        CppReleaseLockExclusive(&Protector->CallbackLock);
        ExFreeToNPagedLookasideList(&Protector->EntryLookaside, newEntry);
        ExReleaseRundownProtection(&Protector->RundownRef);
        return STATUS_QUOTA_EXCEEDED;
    }

    if (CppFindByRegistration(Protector, Registration) != NULL) {
        CppReleaseLockExclusive(&Protector->CallbackLock);
        ExFreeToNPagedLookasideList(&Protector->EntryLookaside, newEntry);
        ExReleaseRundownProtection(&Protector->RundownRef);
        return STATUS_OBJECT_NAME_EXISTS;
    }

    //
    // Insert into main list.
    //
    InsertTailList(&Protector->CallbackList, &newEntry->ListEntry);

    //
    // Insert into hash table.
    //
    bucket = CppHashPointer(Registration);
    newEntry->HashBucket = bucket;
    InsertTailList(&Protector->HashBuckets[bucket], &newEntry->HashEntry);

    Protector->CallbackCount++;

    CppReleaseLockExclusive(&Protector->CallbackLock);

    InterlockedIncrement64(&Protector->Stats.CallbacksProtected);
    ExReleaseRundownProtection(&Protector->RundownRef);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
CpUnprotectCallback(
    _In_ PCP_PROTECTOR Protector,
    _In_ PVOID Registration
    )
{
    PCP_CALLBACK_ENTRY_INTERNAL entry;

    PAGED_CODE();

    if (Protector == NULL || !Protector->Initialized || Registration == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Protector->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    //
    // ATOMIC: find, remove from both hash table and list under single lock.
    // No window for use-after-free.
    //
    CppAcquireLockExclusive(&Protector->CallbackLock);

    entry = CppFindByRegistration(Protector, Registration);
    if (entry == NULL) {
        CppReleaseLockExclusive(&Protector->CallbackLock);
        ExReleaseRundownProtection(&Protector->RundownRef);
        return STATUS_NOT_FOUND;
    }

    RemoveEntryList(&entry->ListEntry);
    RemoveEntryList(&entry->HashEntry);
    Protector->CallbackCount--;

    CppReleaseLockExclusive(&Protector->CallbackLock);

    //
    // Drop list reference. If no one else has a ref, this frees the entry.
    //
    CppDereferenceEntry(Protector, entry);

    ExReleaseRundownProtection(&Protector->RundownRef);
    return STATUS_SUCCESS;
}

// ============================================================================
// TAMPER CALLBACK REGISTRATION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
CpRegisterTamperCallback(
    _In_ PCP_PROTECTOR Protector,
    _In_ CP_TAMPER_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    PAGED_CODE();

    if (Protector == NULL || !Protector->Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Protector->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    //
    // Write callback + context under exclusive lock so
    // CppNotifyTamper (reading under shared) sees consistent state.
    //
    CppAcquireLockExclusive(&Protector->CallbackLock);
    Protector->TamperCallback = Callback;
    Protector->TamperContext = Context;
    CppReleaseLockExclusive(&Protector->CallbackLock);

    ExReleaseRundownProtection(&Protector->RundownRef);
    return STATUS_SUCCESS;
}

// ============================================================================
// PERIODIC VERIFICATION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
CpEnablePeriodicVerify(
    _In_ PCP_PROTECTOR Protector,
    _In_ ULONG IntervalMs
    )
{
    PAGED_CODE();

    if (Protector == NULL || !Protector->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (IntervalMs < CP_MIN_VERIFY_INTERVAL_MS ||
        IntervalMs > CP_MAX_VERIFY_INTERVAL_MS) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Protector->VerifyWorkItem == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (!ExAcquireRundownProtection(&Protector->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    //
    // Cancel existing timer if active.
    //
    if (InterlockedExchange(&Protector->TimerActive, FALSE)) {
        KeCancelTimer(&Protector->VerifyTimer);
    }

    Protector->VerifyIntervalMs = IntervalMs;
    InterlockedExchange(&Protector->PeriodicEnabled, TRUE);

    CppArmTimer(Protector);

    ExReleaseRundownProtection(&Protector->RundownRef);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
CpDisablePeriodicVerify(
    _In_ PCP_PROTECTOR Protector
    )
{
    PAGED_CODE();

    if (Protector == NULL || !Protector->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!ExAcquireRundownProtection(&Protector->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    InterlockedExchange(&Protector->PeriodicEnabled, FALSE);

    if (InterlockedExchange(&Protector->TimerActive, FALSE)) {
        KeCancelTimer(&Protector->VerifyTimer);
    }

    ExReleaseRundownProtection(&Protector->RundownRef);
    return STATUS_SUCCESS;
}

// ============================================================================
// FULL VERIFICATION
// ============================================================================

_Use_decl_annotations_
NTSTATUS
CpVerifyAll(
    _In_ PCP_PROTECTOR Protector,
    _Out_ PULONG TamperedCount
    )
{
    PLIST_ENTRY listEntry;
    PCP_CALLBACK_ENTRY_INTERNAL cbEntry;
    ULONG tampered = 0;
    LARGE_INTEGER now;
    ULONG i;

    //
    // Fixed-size snapshot array on stack: 256 pointers = 2KB on x64.
    // Safe for kernel stack (12-24KB typical).
    //
    PCP_CALLBACK_ENTRY_INTERNAL snapshot[CP_MAX_CALLBACKS];
    ULONG snapshotCount = 0;

    PAGED_CODE();

    if (Protector == NULL || !Protector->Initialized || TamperedCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *TamperedCount = 0;

    if (!ExAcquireRundownProtection(&Protector->RundownRef)) {
        return STATUS_DELETE_PENDING;
    }

    KeQuerySystemTime(&now);

    //
    // Phase 1: Snapshot under shared lock
    //
    CppAcquireLockShared(&Protector->CallbackLock);

    for (listEntry = Protector->CallbackList.Flink;
         listEntry != &Protector->CallbackList;
         listEntry = listEntry->Flink) {

        cbEntry = CONTAINING_RECORD(listEntry, CP_CALLBACK_ENTRY_INTERNAL, ListEntry);

        if (!cbEntry->IsProtected) {
            continue;
        }

        if (snapshotCount >= CP_MAX_CALLBACKS) {
            break;
        }

        CppReferenceEntry(cbEntry);
        snapshot[snapshotCount++] = cbEntry;
    }

    CppReleaseLockShared(&Protector->CallbackLock);

    //
    // Phase 2: Verify each entry outside the lock at PASSIVE_LEVEL.
    // No data race — we hold a ref on each entry so it won't be freed.
    // Verification-specific fields (WasTampered, TamperCount, etc.) are
    // written exclusively by the verification path, which is single-threaded
    // (VerifyPending gate ensures only one work item at a time).
    //
    for (i = 0; i < snapshotCount; i++) {
        cbEntry = snapshot[i];

        if (!CppVerifySingleEntry(cbEntry)) {
            cbEntry->WasTampered = TRUE;
            cbEntry->TamperCount++;
            tampered++;

            InterlockedIncrement64(&Protector->Stats.TamperAttempts);

            if (Protector->EnableRestoration && cbEntry->HasBackup) {
                if (CppRestoreCallback(cbEntry)) {
                    InterlockedIncrement64(&Protector->Stats.CallbacksRestored);
                }
            }

            CppNotifyTamper(Protector, cbEntry);
        }

        cbEntry->LastVerifyTime = now;
        cbEntry->VerifyCount++;

        CppDereferenceEntry(Protector, cbEntry);
    }

    InterlockedIncrement64(&Protector->Stats.VerificationsRun);
    *TamperedCount = tampered;

    ExReleaseRundownProtection(&Protector->RundownRef);
    return STATUS_SUCCESS;
}

// ============================================================================
// STATISTICS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
CpGetStatistics(
    _In_ PCP_PROTECTOR Protector,
    _Out_ PCP_STATISTICS Stats
    )
{
    LARGE_INTEGER now;

    PAGED_CODE();

    if (Protector == NULL || !Protector->Initialized || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(CP_STATISTICS));

    Stats->CallbacksProtected = Protector->Stats.CallbacksProtected;
    Stats->TamperAttempts = Protector->Stats.TamperAttempts;
    Stats->CallbacksRestored = Protector->Stats.CallbacksRestored;
    Stats->VerificationsRun = Protector->Stats.VerificationsRun;
    Stats->CallbackCount = Protector->CallbackCount;

    KeQuerySystemTime(&now);
    Stats->UpTime.QuadPart = now.QuadPart - Protector->Stats.StartTime.QuadPart;

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE — SINGLE ENTRY VERIFICATION
// ============================================================================

/**
 * Verify integrity of one callback entry by recomputing its code hash.
 * Returns TRUE if intact, FALSE if tampered or unreadable.
 */
static BOOLEAN
CppVerifySingleEntry(
    _In_ PCP_CALLBACK_ENTRY_INTERNAL Entry
    )
{
    UCHAR currentHash[32];
    NTSTATUS status;

    if (Entry == NULL || Entry->Callback == NULL) {
        return FALSE;
    }

    status = CppComputeCodeHash(Entry->Callback, CP_CALLBACK_HASH_BYTES, currentHash);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    return (RtlCompareMemory(currentHash, Entry->CodeHash, 32) == 32);
}

// ============================================================================
// PRIVATE — CALLBACK RESTORATION
// ============================================================================

/**
 * Restore tampered callback code from backup via MDL-mapped write.
 * Handles all MDL lifecycle correctly in all error paths.
 */
static BOOLEAN
CppRestoreCallback(
    _In_ PCP_CALLBACK_ENTRY_INTERNAL Entry
    )
{
    PMDL mdl = NULL;
    PVOID mapped = NULL;
    BOOLEAN success = FALSE;
    BOOLEAN locked = FALSE;

    if (!Entry->HasBackup || Entry->OriginalCodeSize == 0) {
        return FALSE;
    }

    //
    // Validate callback address is in kernel space.
    //
    if ((ULONG_PTR)Entry->Callback < (ULONG_PTR)MmUserProbeAddress) {
        return FALSE;
    }

    __try {
        mdl = IoAllocateMdl(
            Entry->Callback,
            (ULONG)Entry->OriginalCodeSize,
            FALSE,
            FALSE,
            NULL
        );

        if (mdl == NULL) {
            return FALSE;
        }

        __try {
            MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
            locked = TRUE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            IoFreeMdl(mdl);
            return FALSE;
        }

        mapped = MmMapLockedPagesSpecifyCache(
            mdl,
            KernelMode,
            MmCached,
            NULL,
            FALSE,
            NormalPagePriority
        );

        if (mapped != NULL) {
            RtlCopyMemory(mapped, Entry->OriginalCode, Entry->OriginalCodeSize);
            MmUnmapLockedPages(mapped, mdl);
            mapped = NULL;

            //
            // Recompute hash from the actual callback address so
            // future verifications use the restored code's hash.
            //
            CppComputeCodeHash(
                Entry->Callback,
                CP_CALLBACK_HASH_BYTES,
                Entry->CodeHash
            );

            Entry->WasTampered = FALSE;
            success = TRUE;
        }

        if (locked) {
            MmUnlockPages(mdl);
        }
        IoFreeMdl(mdl);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        //
        // Clean up MDL state on exception.
        // mapped was set to NULL after unmap, so no double-unmap.
        //
        if (mapped != NULL && mdl != NULL) {
            MmUnmapLockedPages(mapped, mdl);
        }
        if (locked && mdl != NULL) {
            MmUnlockPages(mdl);
        }
        if (mdl != NULL) {
            IoFreeMdl(mdl);
        }
        success = FALSE;
    }

    return success;
}

// ============================================================================
// PRIVATE — TAMPER NOTIFICATION
// ============================================================================

/**
 * Invoke the registered tamper callback. Always at PASSIVE_LEVEL.
 * Reads callback pointer under shared lock for consistency.
 */
static VOID
CppNotifyTamper(
    _In_ PCP_PROTECTOR Protector,
    _In_ PCP_CALLBACK_ENTRY_INTERNAL Entry
    )
{
    CP_TAMPER_CALLBACK callback;
    PVOID context;

    //
    // Read callback + context under shared lock to get a consistent
    // snapshot (CpRegisterTamperCallback writes under exclusive).
    //
    CppAcquireLockShared(&Protector->CallbackLock);
    callback = Protector->TamperCallback;
    context = Protector->TamperContext;
    CppReleaseLockShared(&Protector->CallbackLock);

    if (callback != NULL) {
        callback(Entry->Type, Entry->Registration, context);
    }
}

// ============================================================================
// PRIVATE — TIMER / DPC / WORK ITEM
// ============================================================================

static VOID
CppArmTimer(
    _In_ PCP_PROTECTOR Protector
    )
{
    LARGE_INTEGER dueTime;

    if (Protector->VerifyIntervalMs == 0) {
        return;
    }

    dueTime.QuadPart = -((LONGLONG)Protector->VerifyIntervalMs * 10000);

    KeSetTimerEx(
        &Protector->VerifyTimer,
        dueTime,
        Protector->VerifyIntervalMs,
        &Protector->VerifyDpc
    );

    InterlockedExchange(&Protector->TimerActive, TRUE);
}

/**
 * Timer DPC — runs at DISPATCH_LEVEL.
 * Does ZERO lock acquisition. Only queues a work item for PASSIVE_LEVEL
 * verification. InterlockedCompareExchange prevents stacking.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
CppVerifyTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PCP_PROTECTOR prot = (PCP_PROTECTOR)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (prot == NULL || !prot->Initialized || !prot->PeriodicEnabled) {
        return;
    }

    if (prot->VerifyWorkItem == NULL) {
        return;
    }

    //
    // Gate: only one work item in flight at a time.
    //
    if (InterlockedCompareExchange(&prot->VerifyPending, 1, 0) == 0) {
        //
        // Clear the completion event so CpShutdown can wait on it.
        //
        KeClearEvent(&prot->VerifyComplete);

        IoQueueWorkItem(
            prot->VerifyWorkItem,
            CppVerifyWorkItemRoutine,
            DelayedWorkQueue,
            prot
        );
    }
}

/**
 * Work item — runs at PASSIVE_LEVEL. Performs full SHA-256 verification.
 */
static VOID
CppVerifyWorkItemRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    )
{
    PCP_PROTECTOR prot = (PCP_PROTECTOR)Context;
    ULONG tamperedCount = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (prot == NULL || !prot->Initialized) {
        goto Done;
    }

    CpVerifyAll(prot, &tamperedCount);

Done:
    //
    // Clear pending flag and signal completion event.
    // Order matters: clear pending BEFORE signaling so that
    // CpShutdown sees both cleared.
    //
    InterlockedExchange(&prot->VerifyPending, 0);
    KeSetEvent(&prot->VerifyComplete, IO_NO_INCREMENT, FALSE);
}
