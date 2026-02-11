/**
 * ============================================================================
 * ShadowStrike NGAV - OBJECT NAMESPACE MANAGEMENT
 * ============================================================================
 *
 * @file ObjectNamespace.h
 * @brief Secure object directory management for driver object isolation.
 *
 * Provides enterprise-grade object directory creation, management, and
 * security enforcement. Protects critical driver objects from tampering,
 * unauthorized access, and injection attacks.
 *
 * Architecture:
 * - Creates \ShadowStrike directory object in the NT object namespace
 * - Enforces strict DACL (SYSTEM + Administrators only)
 * - High Integrity Level mandatory label prevents lower IL access
 * - Audit SACL for security monitoring
 * - Prevents object name squatting attacks via SD verification
 * - Supports secure communication channel establishment
 *
 * Security Guarantees:
 * - Directory accessible only to SYSTEM and Administrators
 * - All child objects created with restrictive DACL
 * - Mandatory integrity label (High) blocks lower-integrity access
 * - Pre-existing directory SD verified to prevent hijacking
 * - Self-relative SD format: single allocation, no double-free
 *
 * Thread Safety:
 * - EX_PUSH_LOCK protects state transitions
 * - EX_RUNDOWN_REF provides correct reference lifetime management
 * - Atomic initialization flag prevents concurrent init races
 * - ExWaitForRundownProtectionRelease blocks until all refs drained
 *
 * Memory Management:
 * - Self-relative security descriptors (single alloc, single free)
 * - NonPagedPoolNx for security descriptor (safe at any IRQL ≤ DISPATCH)
 * - All ACLs embedded in self-relative SD
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition - Rundown-Protected)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_OBJECT_NAMESPACE_H
#define SHADOWSTRIKE_OBJECT_NAMESPACE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>

// ============================================================================
// POOL TAGS
// ============================================================================

/** @brief Pool tag for namespace allocations: 'nSSx' */
#define SHADOW_NAMESPACE_TAG        'nSSx'

/** @brief Pool tag for namespace string buffers */
#define SHADOW_NAMESPACE_STRING_TAG 'sSSn'

/** @brief Pool tag for security descriptor allocations (NonPagedPoolNx) */
#define SHADOW_NAMESPACE_SD_TAG     'dSSn'

/** @brief Pool tag for temporary ACL allocations during SD build */
#define SHADOW_NAMESPACE_ACL_TAG    'aSSn'

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================

/** @brief Root namespace directory name */
#define SHADOW_NAMESPACE_ROOT           L"\\ShadowStrike"

/** @brief Communication port object name */
#define SHADOW_NAMESPACE_PORT           L"\\ShadowStrike\\ScanPort"

/** @brief Event object for driver ready notification */
#define SHADOW_NAMESPACE_READY_EVENT    L"\\ShadowStrike\\DriverReady"

/** @brief Shared section for telemetry */
#define SHADOW_NAMESPACE_TELEMETRY_SECTION L"\\ShadowStrike\\Telemetry"

/**
 * @brief Maximum full path length in WCHARs (includes \\ShadowStrike\\ prefix).
 *
 * The object name parameter is the relative name. The full path is
 * \\ShadowStrike\\<ObjectName>. This constant limits the total buffer.
 */
#define SHADOW_MAX_NAMESPACE_PATH   256

/**
 * @brief Maximum relative object name length in WCHARs.
 *
 * Accounts for the \\ShadowStrike\\ prefix (15 chars) plus null terminator.
 */
#define SHADOW_MAX_OBJECT_NAME      (SHADOW_MAX_NAMESPACE_PATH - 16)

/**
 * @brief Default section size for shared memory objects (bytes).
 *
 * Callers can override this via ShadowCreateNamespaceObject parameter.
 */
#define SHADOW_DEFAULT_SECTION_SIZE (64 * 1024)

// ============================================================================
// INITIALIZATION STATE VALUES
// ============================================================================

#define NAMESPACE_STATE_UNINITIALIZED 0
#define NAMESPACE_STATE_INITIALIZING  1
#define NAMESPACE_STATE_INITIALIZED   2

// ============================================================================
// NAMESPACE STATE STRUCTURE
// ============================================================================

/**
 * @brief Namespace state tracking structure.
 *
 * Maintains handles, security descriptors, and synchronization state for
 * the \ShadowStrike object directory.
 *
 * Lifetime:
 *   Created in ShadowCreatePrivateNamespace (DriverEntry).
 *   Destroyed in ShadowDestroyPrivateNamespace (DriverUnload).
 *
 * Thread Safety:
 *   - Lock (EX_PUSH_LOCK): Protects state fields (Initialized, Destroying).
 *   - RundownRef (EX_RUNDOWN_REF): Protects object lifetime during operations.
 *     Callers acquire rundown protection before touching namespace objects.
 *     Shutdown waits for all rundown refs to drain before cleanup.
 *   - InitializationState: Atomic CAS for one-shot init.
 *
 * Memory Management:
 *   - DirectorySecurityDescriptor is self-relative, allocated from NonPagedPoolNx.
 *   - Single ExFreePoolWithTag frees SD + embedded DACL + SACL.
 */
typedef struct _SHADOW_NAMESPACE_STATE {

    //
    // Synchronization
    //

    /** @brief Push lock protecting state transitions. */
    EX_PUSH_LOCK Lock;

    /** @brief TRUE after ExInitializePushLock has been called. */
    BOOLEAN LockInitialized;

    /**
     * @brief Rundown protection for safe reference lifetime.
     *
     * Replaces the manual LONG ReferenceCount. Provides:
     * - ExAcquireRundownProtection: returns FALSE during rundown (no new refs)
     * - ExReleaseRundownProtection: releases a held ref
     * - ExWaitForRundownProtectionRelease: blocks until all refs drained
     * No TOCTOU races, no self-inflicted BSODs.
     */
    EX_RUNDOWN_REF RundownRef;

    /** @brief TRUE after ExInitializeRundownProtection has been called. */
    BOOLEAN RundownInitialized;

    /** @brief Atomic initialization flag (NAMESPACE_STATE_*). */
    volatile LONG InitializationState;

    //
    // Namespace Objects
    //

    /** @brief Kernel handle to \\ShadowStrike directory object. */
    HANDLE DirectoryHandle;

    /** @brief Pointer to directory object (referenced). */
    PVOID DirectoryObject;

    /** @brief TRUE if ObReferenceObjectByHandle was called for DirectoryObject. */
    BOOLEAN DirectoryObjectReferenced;

    //
    // Security Descriptors
    //
    // Self-relative SD allocated from NonPagedPoolNx.
    // Contains embedded DACL and SACL — single free cleans everything.
    //

    /** @brief Self-relative security descriptor (NonPagedPoolNx). */
    PSECURITY_DESCRIPTOR DirectorySecurityDescriptor;

    /** @brief Size of the self-relative SD in bytes. */
    ULONG SecurityDescriptorSize;

    /** @brief TRUE if DirectorySecurityDescriptor was allocated. */
    BOOLEAN SecurityDescriptorAllocated;

    //
    // State Tracking
    //

    /** @brief TRUE after namespace is fully initialized. */
    BOOLEAN Initialized;

    /** @brief TRUE when ShadowDestroyPrivateNamespace is executing. */
    BOOLEAN Destroying;

    /** @brief Timestamp when namespace was created. */
    LARGE_INTEGER CreationTime;

} SHADOW_NAMESPACE_STATE, *PSHADOW_NAMESPACE_STATE;

// ============================================================================
// PUBLIC FUNCTION PROTOTYPES
// ============================================================================

/**
 * @brief Create and secure the \ShadowStrike object directory.
 *
 * Creates the directory with a restrictive DACL (SYSTEM + Administrators),
 * High Integrity Level mandatory label, and audit SACL.
 *
 * If the directory already exists (STATUS_OBJECT_NAME_COLLISION), verifies
 * the existing directory's security descriptor before using it. Refuses
 * to use a pre-existing directory with unexpected ownership (anti-squatting).
 *
 * Uses atomic CAS on InitializationState to prevent concurrent initialization.
 * Second callers spin-wait and detect both success and failure of the first.
 *
 * @return STATUS_SUCCESS on success
 *         STATUS_ALREADY_INITIALIZED if already initialized
 *         STATUS_INSUFFICIENT_RESOURCES if allocation fails
 *         STATUS_ACCESS_DENIED if SD verification fails on existing directory
 *         STATUS_TIMEOUT if concurrent init takes too long
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowCreatePrivateNamespace(
    VOID
    );

/**
 * @brief Destroy the namespace and free all resources.
 *
 * Steps:
 * 1. Set Destroying = TRUE under lock to prevent new refs.
 * 2. ExWaitForRundownProtectionRelease — blocks until all refs drained.
 * 3. ZwMakeTemporaryObject to clear OBJ_PERMANENT.
 * 4. ObDereferenceObject + ZwClose.
 * 5. Free self-relative SD.
 * 6. Zero all state.
 *
 * Safe to call if init never happened or partially failed.
 *
 * @irql PASSIVE_LEVEL
 */
VOID
ShadowDestroyPrivateNamespace(
    VOID
    );

/**
 * @brief Create a named object within \\ShadowStrike.
 *
 * Creates an event, semaphore, mutant, timer, or section object
 * under the namespace directory with the namespace's security descriptor.
 *
 * For section objects, the SectionSize parameter controls the committed size.
 * Pass 0 to use SHADOW_DEFAULT_SECTION_SIZE.
 *
 * Acquires rundown protection for the duration of the call.
 *
 * @param ObjectName    Relative name (e.g., L"DriverReady"). Max SHADOW_MAX_OBJECT_NAME chars.
 * @param ObjectType    Kernel object type pointer (*ExEventObjectType, etc.)
 * @param SectionSize   For section objects: committed size in bytes (0 = default 64KB).
 *                      Ignored for non-section object types.
 * @param ObjectHandle  [out] Receives kernel handle to created object.
 * @param ObjectPointer [out, optional] Receives referenced pointer to object.
 *
 * @return STATUS_SUCCESS on success
 *         STATUS_INVALID_PARAMETER if params invalid or name too long
 *         STATUS_INVALID_DEVICE_STATE if namespace not initialized
 *         STATUS_DEVICE_NOT_READY if namespace is shutting down
 *         STATUS_OBJECT_TYPE_MISMATCH if unsupported object type
 *
 * @note Caller must close ObjectHandle with ZwClose.
 * @note Caller must dereference ObjectPointer with ObDereferenceObject if non-NULL.
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowCreateNamespaceObject(
    _In_ PCWSTR ObjectName,
    _In_ POBJECT_TYPE ObjectType,
    _In_ SIZE_T SectionSize,
    _Out_ PHANDLE ObjectHandle,
    _Outptr_opt_ PVOID* ObjectPointer
    );

/**
 * @brief Check if the namespace is initialized and not shutting down.
 *
 * @return TRUE if namespace is ready for operations.
 *
 * @irql <= APC_LEVEL (acquires push lock shared)
 */
BOOLEAN
ShadowIsNamespaceInitialized(
    VOID
    );

/**
 * @brief Acquire rundown protection on the namespace.
 *
 * Must be paired with ShadowDereferenceNamespace. Returns FALSE if the
 * namespace is shutting down (rundown active).
 *
 * @return TRUE if protection acquired, FALSE if namespace is shutting down.
 *
 * @irql <= DISPATCH_LEVEL
 */
BOOLEAN
ShadowReferenceNamespace(
    VOID
    );

/**
 * @brief Release rundown protection on the namespace.
 *
 * @irql <= DISPATCH_LEVEL
 */
VOID
ShadowDereferenceNamespace(
    VOID
    );

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_OBJECT_NAMESPACE_H
