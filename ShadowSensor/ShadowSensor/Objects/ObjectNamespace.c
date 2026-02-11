/**
 * ============================================================================
 * ShadowStrike NGAV - OBJECT NAMESPACE IMPLEMENTATION
 * ============================================================================
 *
 * @file ObjectNamespace.c
 * @brief Enterprise-grade secure object directory management.
 *
 * Architecture:
 * - Creates \\ShadowStrike directory object with restrictive DACL
 * - High Integrity Level mandatory label in merged SACL
 * - Self-relative SD: single allocation, single free, no double-free
 * - EX_RUNDOWN_REF for correct reference lifetime (no manual refcount)
 * - Anti-squatting: verifies SD owner on STATUS_OBJECT_NAME_COLLISION
 * - ZwMakeTemporaryObject on cleanup to clear OBJ_PERMANENT
 * - NonPagedPoolNx for security descriptor (safe at any IRQL)
 * - ExInitializePushLock (not FsRtl variant) for non-filesystem driver
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition - Rundown-Protected)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "ObjectNamespace.h"
#include <ntstrsafe.h>

// ============================================================================
// GLOBAL STATE (file-scoped — NOT exported in header)
// ============================================================================

static SHADOW_NAMESPACE_STATE g_NamespaceState = { 0 };

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static NTSTATUS
ShadowpBuildSecurityDescriptor(
    _Outptr_ PSECURITY_DESCRIPTOR* SecurityDescriptor,
    _Out_ PULONG DescriptorSize
    );

static VOID
ShadowpCleanupState(
    _Inout_ PSHADOW_NAMESPACE_STATE State
    );

static NTSTATUS
ShadowpVerifyDirectoryOwner(
    _In_ HANDLE DirectoryHandle
    );

// ============================================================================
// PUBLIC FUNCTIONS
// ============================================================================

/**
 * @brief Create and secure the \\ShadowStrike object directory.
 */
NTSTATUS
ShadowCreatePrivateNamespace(
    VOID
    )
{
    NTSTATUS status;
    UNICODE_STRING directoryName;
    OBJECT_ATTRIBUTES objectAttributes;
    PSHADOW_NAMESPACE_STATE state = &g_NamespaceState;
    LONG previousState;
    BOOLEAN created = FALSE;

    PAGED_CODE();

    //
    // Atomic one-shot initialization via CAS.
    //
    previousState = InterlockedCompareExchange(
        &state->InitializationState,
        NAMESPACE_STATE_INITIALIZING,
        NAMESPACE_STATE_UNINITIALIZED
    );

    if (previousState == NAMESPACE_STATE_INITIALIZED) {
        return STATUS_ALREADY_INITIALIZED;
    }

    if (previousState == NAMESPACE_STATE_INITIALIZING) {
        //
        // Another thread is initializing. Spin-wait and detect BOTH
        // success (INITIALIZED) and failure (UNINITIALIZED).
        //
        LARGE_INTEGER sleepInterval;
        sleepInterval.QuadPart = -((LONGLONG)50 * 10000LL); // 50ms

        for (ULONG i = 0; i < 100; i++) {
            KeDelayExecutionThread(KernelMode, FALSE, &sleepInterval);

            LONG current = InterlockedCompareExchange(
                &state->InitializationState, 0, 0);

            if (current == NAMESPACE_STATE_INITIALIZED) {
                return STATUS_SUCCESS;
            }
            if (current == NAMESPACE_STATE_UNINITIALIZED) {
                //
                // First thread failed initialization.
                //
                return STATUS_UNSUCCESSFUL;
            }
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Namespace initialization timeout\n");
        return STATUS_TIMEOUT;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Creating namespace: %ws\n", SHADOW_NAMESPACE_ROOT);

    //
    // STEP 1: Initialize push lock (Ex variant, not FsRtl).
    //
    ExInitializePushLock(&state->Lock);
    state->LockInitialized = TRUE;

    //
    // STEP 2: Initialize rundown protection.
    //
    ExInitializeRundownProtection(&state->RundownRef);
    state->RundownInitialized = TRUE;

    //
    // STEP 3: Build self-relative security descriptor (NonPagedPoolNx).
    //
    status = ShadowpBuildSecurityDescriptor(
        &state->DirectorySecurityDescriptor,
        &state->SecurityDescriptorSize
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Failed to build SD: 0x%X\n", status);
        goto cleanup;
    }

    state->SecurityDescriptorAllocated = TRUE;

    //
    // STEP 4: Create the \\ShadowStrike directory object.
    //
    RtlInitUnicodeString(&directoryName, SHADOW_NAMESPACE_ROOT);

    InitializeObjectAttributes(
        &objectAttributes,
        &directoryName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE | OBJ_PERMANENT,
        NULL,
        state->DirectorySecurityDescriptor
    );

    status = ZwCreateDirectoryObject(
        &state->DirectoryHandle,
        DIRECTORY_ALL_ACCESS,
        &objectAttributes
    );

    if (NT_SUCCESS(status)) {
        created = TRUE;
    } else if (status == STATUS_OBJECT_NAME_COLLISION) {
        //
        // Directory already exists. Open it, then verify ownership
        // to prevent namespace squatting attacks.
        //
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Directory already exists — verifying owner\n");

        //
        // Remove OBJ_PERMANENT for the open (we didn't create it).
        //
        InitializeObjectAttributes(
            &objectAttributes,
            &directoryName,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL,
            NULL
        );

        status = ZwOpenDirectoryObject(
            &state->DirectoryHandle,
            DIRECTORY_ALL_ACCESS | READ_CONTROL,
            &objectAttributes
        );

        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike] Failed to open existing directory: 0x%X\n", status);
            goto cleanup;
        }

        //
        // Anti-squatting: verify the directory owner is SYSTEM.
        //
        status = ShadowpVerifyDirectoryOwner(state->DirectoryHandle);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike] SECURITY: Directory owner verification failed "
                       "(possible squatting attack): 0x%X\n", status);
            ZwClose(state->DirectoryHandle);
            state->DirectoryHandle = NULL;
            status = STATUS_ACCESS_DENIED;
            goto cleanup;
        }
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Failed to create directory: 0x%X\n", status);
        goto cleanup;
    }

    //
    // STEP 5: Reference the directory object.
    // We pass NULL for ObjectType because ObDirectoryObjectType is not
    // publicly exported. The handle was obtained via ZwCreateDirectoryObject
    // or ZwOpenDirectoryObject in KernelMode, so the type is guaranteed.
    //
    status = ObReferenceObjectByHandle(
        state->DirectoryHandle,
        DIRECTORY_ALL_ACCESS,
        NULL,
        KernelMode,
        &state->DirectoryObject,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Failed to reference directory: 0x%X\n", status);
        goto cleanup;
    }

    state->DirectoryObjectReferenced = TRUE;

    //
    // STEP 6: Mark namespace as initialized.
    //
    KeQuerySystemTime(&state->CreationTime);
    state->Initialized = TRUE;
    state->Destroying = FALSE;

    InterlockedExchange(&state->InitializationState, NAMESPACE_STATE_INITIALIZED);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Namespace created successfully (v3.0 rundown-protected)\n");

    return STATUS_SUCCESS;

cleanup:
    InterlockedExchange(&state->InitializationState, NAMESPACE_STATE_UNINITIALIZED);
    ShadowpCleanupState(state);
    return status;
}

/**
 * @brief Destroy the namespace and free all resources.
 */
VOID
ShadowDestroyPrivateNamespace(
    VOID
    )
{
    PSHADOW_NAMESPACE_STATE state = &g_NamespaceState;

    PAGED_CODE();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Destroying namespace\n");

    //
    // STEP 1: Set Destroying flag under lock to prevent new operations.
    //
    if (state->LockInitialized) {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&state->Lock);
        state->Destroying = TRUE;
        InterlockedExchange(&state->InitializationState, NAMESPACE_STATE_UNINITIALIZED);
        ExReleasePushLockExclusive(&state->Lock);
        KeLeaveCriticalRegion();
    } else {
        state->Destroying = TRUE;
        InterlockedExchange(&state->InitializationState, NAMESPACE_STATE_UNINITIALIZED);
    }

    //
    // STEP 2: Wait for all outstanding rundown references to drain.
    // ExWaitForRundownProtectionRelease blocks until all
    // ExAcquireRundownProtection holders call ExReleaseRundownProtection.
    // After this returns, ExAcquireRundownProtection will return FALSE
    // for all future callers — no new work can begin.
    //
    if (state->RundownInitialized) {
        ExWaitForRundownProtectionRelease(&state->RundownRef);
    }

    //
    // STEP 3: Perform cleanup (all refs are drained, safe to proceed).
    //
    ShadowpCleanupState(state);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[ShadowStrike] Namespace destroyed\n");
}

/**
 * @brief Create a named object within \\ShadowStrike.
 */
NTSTATUS
ShadowCreateNamespaceObject(
    _In_ PCWSTR ObjectName,
    _In_ POBJECT_TYPE ObjectType,
    _In_ SIZE_T SectionSize,
    _Out_ PHANDLE ObjectHandle,
    _Outptr_opt_ PVOID* ObjectPointer
    )
{
    NTSTATUS status;
    WCHAR fullPath[SHADOW_MAX_NAMESPACE_PATH];
    UNICODE_STRING objectNameStr;
    OBJECT_ATTRIBUTES objectAttributes;
    PSHADOW_NAMESPACE_STATE state = &g_NamespaceState;
    PVOID objectPtr = NULL;
    size_t nameLen = 0;

    PAGED_CODE();

    if (ObjectHandle == NULL || ObjectName == NULL || ObjectType == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ObjectHandle = NULL;
    if (ObjectPointer != NULL) {
        *ObjectPointer = NULL;
    }

    //
    // Validate ObjectName length before any work.
    //
    status = RtlStringCchLengthW(ObjectName, SHADOW_MAX_OBJECT_NAME, &nameLen);
    if (!NT_SUCCESS(status) || nameLen == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Acquire rundown protection (returns FALSE if shutting down).
    //
    if (!ShadowReferenceNamespace()) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Build full path: \\ShadowStrike\\<ObjectName>
    //
    status = RtlStringCbPrintfW(
        fullPath,
        sizeof(fullPath),
        L"%ws\\%ws",
        SHADOW_NAMESPACE_ROOT,
        ObjectName
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Path construction failed: 0x%X\n", status);
        ShadowDereferenceNamespace();
        return status;
    }

    RtlInitUnicodeString(&objectNameStr, fullPath);

    InitializeObjectAttributes(
        &objectAttributes,
        &objectNameStr,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        state->DirectorySecurityDescriptor
    );

    //
    // Type-specific object creation.
    //
    if (ObjectType == *ExEventObjectType) {
        status = ZwCreateEvent(
            ObjectHandle,
            EVENT_ALL_ACCESS,
            &objectAttributes,
            NotificationEvent,
            FALSE
        );
    }
    else if (ObjectType == *ExSemaphoreObjectType) {
        status = ZwCreateSemaphore(
            ObjectHandle,
            SEMAPHORE_ALL_ACCESS,
            &objectAttributes,
            0,
            MAXLONG
        );
    }
    else if (ObjectType == *ExMutantObjectType) {
        status = ZwCreateMutant(
            ObjectHandle,
            MUTANT_ALL_ACCESS,
            &objectAttributes,
            FALSE
        );
    }
    else if (ObjectType == *ExTimerObjectType) {
        status = ZwCreateTimer(
            ObjectHandle,
            TIMER_ALL_ACCESS,
            &objectAttributes,
            NotificationTimer
        );
    }
    else if (ObjectType == *MmSectionObjectType) {
        LARGE_INTEGER maxSize;
        maxSize.QuadPart = (SectionSize > 0)
            ? (LONGLONG)SectionSize
            : (LONGLONG)SHADOW_DEFAULT_SECTION_SIZE;

        status = ZwCreateSection(
            ObjectHandle,
            SECTION_ALL_ACCESS,
            &objectAttributes,
            &maxSize,
            PAGE_READWRITE,
            SEC_COMMIT,
            NULL
        );
    }
    else if (ObjectType == *IoFileObjectType ||
             ObjectType == *PsProcessType ||
             ObjectType == *PsThreadType ||
             ObjectType == *SeTokenObjectType) {
        //
        // Dangerous or invalid object types — deny creation.
        //
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Denied creation of restricted object type: %p\n",
                   ObjectType);
        status = STATUS_ACCESS_DENIED;
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] Unsupported object type: %p\n", ObjectType);
        status = STATUS_OBJECT_TYPE_MISMATCH;
    }

    //
    // Get object pointer if requested and creation succeeded.
    //
    if (NT_SUCCESS(status) && ObjectPointer != NULL && *ObjectHandle != NULL) {
        NTSTATUS refStatus = ObReferenceObjectByHandle(
            *ObjectHandle,
            0,
            ObjectType,
            KernelMode,
            &objectPtr,
            NULL
        );

        if (NT_SUCCESS(refStatus)) {
            *ObjectPointer = objectPtr;
        } else {
            //
            // Reference failed — close the handle to avoid leak.
            //
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[ShadowStrike] ObReferenceObjectByHandle failed: 0x%X "
                       "(closing handle)\n", refStatus);
            ZwClose(*ObjectHandle);
            *ObjectHandle = NULL;
            status = refStatus;
        }
    }

#if DBG
    if (NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                   "[ShadowStrike] Created object: %wZ\n", &objectNameStr);
    }
#endif

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Object creation failed: 0x%X\n", status);
    }

    ShadowDereferenceNamespace();
    return status;
}

/**
 * @brief Check if the namespace is initialized and not shutting down.
 */
BOOLEAN
ShadowIsNamespaceInitialized(
    VOID
    )
{
    PSHADOW_NAMESPACE_STATE state = &g_NamespaceState;
    BOOLEAN initialized = FALSE;

    if (state->LockInitialized) {
        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&state->Lock);
        initialized = state->Initialized && !state->Destroying;
        ExReleasePushLockShared(&state->Lock);
        KeLeaveCriticalRegion();
    }

    return initialized;
}

/**
 * @brief Acquire rundown protection on the namespace.
 *
 * Uses EX_RUNDOWN_REF — no TOCTOU races, no manual refcount.
 * Returns FALSE after ExWaitForRundownProtectionRelease has been called.
 */
BOOLEAN
ShadowReferenceNamespace(
    VOID
    )
{
    PSHADOW_NAMESPACE_STATE state = &g_NamespaceState;

    if (!state->RundownInitialized) {
        return FALSE;
    }

    //
    // ExAcquireRundownProtection returns FALSE if rundown is active
    // (i.e., ShadowDestroyPrivateNamespace called ExWaitForRundownProtectionRelease).
    //
    return ExAcquireRundownProtection(&state->RundownRef);
}

/**
 * @brief Release rundown protection on the namespace.
 *
 * Must be paired with a successful ShadowReferenceNamespace call.
 * If ShadowDestroyPrivateNamespace is blocked in
 * ExWaitForRundownProtectionRelease, the last release unblocks it.
 */
VOID
ShadowDereferenceNamespace(
    VOID
    )
{
    PSHADOW_NAMESPACE_STATE state = &g_NamespaceState;

    if (!state->RundownInitialized) {
        NT_ASSERT(FALSE);
        return;
    }

    ExReleaseRundownProtection(&state->RundownRef);
}

// ============================================================================
// PRIVATE HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Build self-relative security descriptor with DACL + merged SACL.
 *
 * Creates a self-relative SD containing:
 * - DACL: SYSTEM + Administrators (GENERIC_ALL)
 * - SACL: High Integrity Level mandatory label + Everyone audit
 *
 * All ACLs are embedded in the self-relative SD. Single alloc = single free.
 * Uses NonPagedPoolNx for the final SD so it's safe at any IRQL.
 * Temporary DACL/SACL during construction use PagedPool (freed before return).
 */
static NTSTATUS
ShadowpBuildSecurityDescriptor(
    _Outptr_ PSECURITY_DESCRIPTOR* SecurityDescriptor,
    _Out_ PULONG DescriptorSize
    )
{
    NTSTATUS status;
    SECURITY_DESCRIPTOR absoluteSD;
    PSECURITY_DESCRIPTOR selfRelativeSD = NULL;
    PACL dacl = NULL;
    PACL sacl = NULL;
    ULONG daclSize;
    ULONG saclSize;
    ULONG selfRelativeSize = 0;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY worldAuthority = SECURITY_WORLD_SID_AUTHORITY;
    PSID systemSid = NULL;
    PSID adminSid = NULL;
    PSID highILSid = NULL;
    PSID everyoneSid = NULL;

    PAGED_CODE();

    *SecurityDescriptor = NULL;
    *DescriptorSize = 0;

    //
    // STEP 1: Create all required SIDs.
    //
    status = RtlAllocateAndInitializeSid(
        &ntAuthority, 1,
        SECURITY_LOCAL_SYSTEM_RID,
        0, 0, 0, 0, 0, 0, 0,
        &systemSid
    );
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] SYSTEM SID alloc failed: 0x%X\n", status);
        goto cleanup;
    }

    status = RtlAllocateAndInitializeSid(
        &ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &adminSid
    );
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Admin SID alloc failed: 0x%X\n", status);
        goto cleanup;
    }

    status = RtlAllocateAndInitializeSid(
        &ntAuthority, 1,
        SECURITY_MANDATORY_HIGH_RID,
        0, 0, 0, 0, 0, 0, 0,
        &highILSid
    );
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] High IL SID alloc failed: 0x%X\n", status);
        goto cleanup;
    }

    status = RtlAllocateAndInitializeSid(
        &worldAuthority, 1,
        SECURITY_WORLD_RID,
        0, 0, 0, 0, 0, 0, 0,
        &everyoneSid
    );
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Everyone SID alloc failed: 0x%X\n", status);
        goto cleanup;
    }

    //
    // STEP 2: Calculate DACL size with overflow protection.
    //
    {
        ULONG systemSidLen = RtlLengthSid(systemSid);
        ULONG adminSidLen = RtlLengthSid(adminSid);

        //
        // Each ACCESS_ALLOWED_ACE contains a ULONG SidStart field.
        // The actual SID replaces SidStart, so net addition = sizeof(ACE) + SidLen - sizeof(ULONG).
        //
        daclSize = sizeof(ACL)
                 + sizeof(ACCESS_ALLOWED_ACE) + systemSidLen - sizeof(ULONG)
                 + sizeof(ACCESS_ALLOWED_ACE) + adminSidLen  - sizeof(ULONG);

        // Align to ULONG boundary.
        daclSize = (daclSize + sizeof(ULONG) - 1) & ~(sizeof(ULONG) - 1);
    }

    //
    // STEP 3: Calculate SACL size (mandatory label + audit ACE).
    //
    {
        ULONG highILLen = RtlLengthSid(highILSid);
        ULONG everyoneLen = RtlLengthSid(everyoneSid);

        saclSize = sizeof(ACL)
                 + sizeof(SYSTEM_MANDATORY_LABEL_ACE) + highILLen    - sizeof(ULONG)
                 + sizeof(SYSTEM_AUDIT_ACE)           + everyoneLen  - sizeof(ULONG);

        saclSize = (saclSize + sizeof(ULONG) - 1) & ~(sizeof(ULONG) - 1);
    }

    //
    // STEP 4: Allocate and initialize DACL (temporary, PagedPool, zeroed).
    //
    dacl = (PACL)ExAllocatePoolZero(PagedPool, daclSize, SHADOW_NAMESPACE_ACL_TAG);
    if (dacl == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    status = RtlCreateAcl(dacl, daclSize, ACL_REVISION);
    if (!NT_SUCCESS(status)) goto cleanup;

    status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, GENERIC_ALL, systemSid);
    if (!NT_SUCCESS(status)) goto cleanup;

    status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, GENERIC_ALL, adminSid);
    if (!NT_SUCCESS(status)) goto cleanup;

    //
    // STEP 5: Allocate and initialize SACL (temporary, PagedPool, zeroed).
    //
    sacl = (PACL)ExAllocatePoolZero(PagedPool, saclSize, SHADOW_NAMESPACE_ACL_TAG);
    if (sacl == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    status = RtlCreateAcl(sacl, saclSize, ACL_REVISION);
    if (!NT_SUCCESS(status)) goto cleanup;

    //
    // Mandatory label ACE — CRITICAL for security. Failure is fatal.
    //
    status = RtlAddMandatoryAce(
        sacl,
        ACL_REVISION,
        0,
        SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_READ_UP,
        0,
        highILSid
    );
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Mandatory label ACE failed: 0x%X (FATAL)\n", status);
        goto cleanup;
    }

    //
    // Audit ACE — non-fatal (nice to have).
    //
    {
        NTSTATUS auditStatus = RtlAddAuditAccessAce(
            sacl, ACL_REVISION, GENERIC_ALL, everyoneSid, TRUE, TRUE);
        if (!NT_SUCCESS(auditStatus)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                       "[ShadowStrike] Audit ACE failed: 0x%X (non-fatal)\n", auditStatus);
        }
    }

    //
    // STEP 6: Create absolute security descriptor.
    //
    status = RtlCreateSecurityDescriptor(&absoluteSD, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) goto cleanup;

    status = RtlSetDaclSecurityDescriptor(&absoluteSD, TRUE, dacl, FALSE);
    if (!NT_SUCCESS(status)) goto cleanup;

    status = RtlSetSaclSecurityDescriptor(&absoluteSD, TRUE, sacl, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                   "[ShadowStrike] SetSacl failed: 0x%X (non-fatal)\n", status);
        // DACL alone is sufficient; continue.
    }

    //
    // STEP 7: Convert to self-relative format (NonPagedPoolNx, zeroed).
    //
    status = RtlAbsoluteToSelfRelativeSD(&absoluteSD, NULL, &selfRelativeSize);
    if (status != STATUS_BUFFER_TOO_SMALL) {
        if (NT_SUCCESS(status)) status = STATUS_INTERNAL_ERROR;
        goto cleanup;
    }

    selfRelativeSD = (PSECURITY_DESCRIPTOR)ExAllocatePoolZero(
        NonPagedPoolNx, selfRelativeSize, SHADOW_NAMESPACE_SD_TAG);
    if (selfRelativeSD == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    status = RtlAbsoluteToSelfRelativeSD(&absoluteSD, selfRelativeSD, &selfRelativeSize);
    if (!NT_SUCCESS(status)) goto cleanup;

    //
    // SUCCESS — transfer ownership.
    //
    *SecurityDescriptor = selfRelativeSD;
    *DescriptorSize = selfRelativeSize;
    selfRelativeSD = NULL;
    status = STATUS_SUCCESS;

#if DBG
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] Self-relative SD built (size=%lu)\n", *DescriptorSize);
#endif

cleanup:
    if (dacl)          ExFreePoolWithTag(dacl, SHADOW_NAMESPACE_ACL_TAG);
    if (sacl)          ExFreePoolWithTag(sacl, SHADOW_NAMESPACE_ACL_TAG);
    if (selfRelativeSD) ExFreePoolWithTag(selfRelativeSD, SHADOW_NAMESPACE_SD_TAG);
    if (systemSid)     RtlFreeSid(systemSid);
    if (adminSid)      RtlFreeSid(adminSid);
    if (highILSid)     RtlFreeSid(highILSid);
    if (everyoneSid)   RtlFreeSid(everyoneSid);

    return status;
}

/**
 * @brief Verify that an existing directory object is owned by SYSTEM.
 *
 * Anti-squatting defense: if \\ShadowStrike already exists, we must
 * verify its owner before trusting it. An attacker who pre-creates the
 * directory with permissive ACLs could hijack all namespace objects.
 *
 * @param DirectoryHandle  Handle to the existing directory (READ_CONTROL).
 * @return STATUS_SUCCESS if owner is SYSTEM, STATUS_ACCESS_DENIED otherwise.
 */
static NTSTATUS
ShadowpVerifyDirectoryOwner(
    _In_ HANDLE DirectoryHandle
    )
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;
    ULONG sdSize = 0;
    PSID ownerSid = NULL;
    BOOLEAN ownerDefaulted = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID systemSid = NULL;

    PAGED_CODE();

    //
    // Query the security descriptor (owner info) for the directory.
    // First call gets required size.
    //
    status = ZwQuerySecurityObject(
        DirectoryHandle,
        OWNER_SECURITY_INFORMATION,
        NULL,
        0,
        &sdSize
    );

    if (status != STATUS_BUFFER_TOO_SMALL || sdSize == 0) {
        return STATUS_ACCESS_DENIED;
    }

    sd = (PSECURITY_DESCRIPTOR)ExAllocatePoolZero(
        PagedPool, sdSize, SHADOW_NAMESPACE_TAG);
    if (sd == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQuerySecurityObject(
        DirectoryHandle,
        OWNER_SECURITY_INFORMATION,
        sd,
        sdSize,
        &sdSize
    );

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(sd, SHADOW_NAMESPACE_TAG);
        return status;
    }

    //
    // Extract owner SID from the queried SD.
    //
    status = RtlGetOwnerSecurityDescriptor(sd, &ownerSid, &ownerDefaulted);
    if (!NT_SUCCESS(status) || ownerSid == NULL) {
        ExFreePoolWithTag(sd, SHADOW_NAMESPACE_TAG);
        return STATUS_ACCESS_DENIED;
    }

    //
    // Build SYSTEM SID for comparison.
    //
    status = RtlAllocateAndInitializeSid(
        &ntAuthority, 1,
        SECURITY_LOCAL_SYSTEM_RID,
        0, 0, 0, 0, 0, 0, 0,
        &systemSid
    );

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(sd, SHADOW_NAMESPACE_TAG);
        return status;
    }

    //
    // Compare owner to SYSTEM.
    //
    if (!RtlEqualSid(ownerSid, systemSid)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[ShadowStrike] Directory owner is NOT SYSTEM — rejecting\n");
        status = STATUS_ACCESS_DENIED;
    } else {
        status = STATUS_SUCCESS;
    }

    RtlFreeSid(systemSid);
    ExFreePoolWithTag(sd, SHADOW_NAMESPACE_TAG);

    return status;
}

/**
 * @brief Cleanup namespace state during shutdown.
 *
 * Handles partial initialization gracefully. Each resource is checked
 * before cleanup. Order matters:
 * 1. ObDereferenceObject (releases kernel reference)
 * 2. ZwMakeTemporaryObject (clears OBJ_PERMANENT so object can be deleted)
 * 3. ZwClose (closes handle)
 * 4. Free SD
 * 5. Clear state
 */
static VOID
ShadowpCleanupState(
    _Inout_ PSHADOW_NAMESPACE_STATE State
    )
{
    PAGED_CODE();

    if (State == NULL) {
        return;
    }

    //
    // Dereference directory object (kernel pointer ref).
    //
    if (State->DirectoryObjectReferenced && State->DirectoryObject != NULL) {
        ObDereferenceObject(State->DirectoryObject);
        State->DirectoryObjectReferenced = FALSE;
        State->DirectoryObject = NULL;
    }

    //
    // Clear OBJ_PERMANENT and close handle.
    // ZwMakeTemporaryObject removes the permanent flag so the object
    // manager can delete the directory when no more references exist.
    //
    if (State->DirectoryHandle != NULL) {
        ZwMakeTemporaryObject(State->DirectoryHandle);
        ZwClose(State->DirectoryHandle);
        State->DirectoryHandle = NULL;
    }

    //
    // Free self-relative security descriptor (single alloc contains
    // embedded DACL + SACL — no other ACL allocations to free).
    //
    if (State->SecurityDescriptorAllocated && State->DirectorySecurityDescriptor != NULL) {
        ExFreePoolWithTag(State->DirectorySecurityDescriptor, SHADOW_NAMESPACE_SD_TAG);
        State->DirectorySecurityDescriptor = NULL;
        State->SecurityDescriptorAllocated = FALSE;
        State->SecurityDescriptorSize = 0;
    }

    //
    // Push lock has no delete function for Ex variant (it's a no-op).
    // Just mark as uninitialized.
    //
    State->LockInitialized = FALSE;

    //
    // Clear all state.
    //
    State->Initialized = FALSE;
    State->Destroying = FALSE;
    State->RundownInitialized = FALSE;
    InterlockedExchange(&State->InitializationState, NAMESPACE_STATE_UNINITIALIZED);

#if DBG
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
               "[ShadowStrike] Namespace state cleaned up\n");
#endif
}
