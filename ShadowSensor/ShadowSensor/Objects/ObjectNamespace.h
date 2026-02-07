/**
 * ============================================================================
 * ShadowStrike NGAV - OBJECT NAMESPACE MANAGEMENT
 * ============================================================================
 *
 * @file ObjectNamespace.h
 * @brief Private object namespace management for secure driver isolation.
 *
 * Provides enterprise-grade private namespace creation, management, and
 * security enforcement. Protects critical driver objects from tampering,
 * unauthorized access, and injection attacks.
 *
 * Architecture:
 * - Creates \ShadowStrike private namespace in object manager
 * - Enforces strict ACLs (System, Administrators only)
 * - Isolates symbolic links, events, and device objects
 * - Prevents object name collision attacks
 * - Supports secure communication channel establishment
 *
 * Security Guarantees:
 * - Namespace is accessible only to SYSTEM and Administrators
 * - All objects created with restrictive DACL
 * - Boundary descriptor prevents Medium IL access
 * - Directory object secured against deletion/modification
 * - Cleanup is BSOD-safe with proper reference tracking
 *
 * Thread Safety:
 * - All operations protected by EX_PUSH_LOCK
 * - Handle reference counting prevents use-after-free
 * - Cleanup callback handles race conditions during shutdown
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
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

#ifndef POBJECT_BOUNDARY_DESCRIPTOR
    typedef struct _OBJECT_BOUNDARY_DESCRIPTOR* POBJECT_BOUNDARY_DESCRIPTOR;
#endif

// ============================================================================
// POOL TAGS
// ============================================================================

/**
 * @brief Pool tag for namespace allocations: 'nSSx' = ShadowStrike Namespace
 */
#define SHADOW_NAMESPACE_TAG 'nSSx'

/**
 * @brief Pool tag for namespace string buffers
 */
#define SHADOW_NAMESPACE_STRING_TAG 'sSSn'

/**
 * @brief Pool tag for security descriptor allocations
 */
#define SHADOW_NAMESPACE_SD_TAG 'dSSn'

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================

/**
 * @brief Root namespace directory name
 */
#define SHADOW_NAMESPACE_ROOT L"\\ShadowStrike"

/**
 * @brief Communication port object name
 */
#define SHADOW_NAMESPACE_PORT L"\\ShadowStrike\\ScanPort"

/**
 * @brief Event object for driver ready notification
 */
#define SHADOW_NAMESPACE_READY_EVENT L"\\ShadowStrike\\DriverReady"

/**
 * @brief Shared section for telemetry
 */
#define SHADOW_NAMESPACE_TELEMETRY_SECTION L"\\ShadowStrike\\Telemetry"

/**
 * @brief Maximum namespace object name length (characters)
 */
#define SHADOW_MAX_NAMESPACE_NAME 256

/**
 * @brief Default reference drain timeout (milliseconds)
 */
#define SHADOW_DEFAULT_DRAIN_TIMEOUT_MS 5000

/**
 * @brief Minimum reference drain timeout (milliseconds)
 */
#define SHADOW_MIN_DRAIN_TIMEOUT_MS 1000

/**
 * @brief Maximum reference drain timeout (milliseconds)
 */
#define SHADOW_MAX_DRAIN_TIMEOUT_MS 30000

// ============================================================================
// NAMESPACE STATE STRUCTURE
// ============================================================================

/**
 * @brief Namespace state tracking structure.
 *
 * Maintains handles, security descriptors, and state for the private
 * namespace. All fields protected by the Lock.
 *
 * Lifetime: Created in ShadowCreatePrivateNamespace, destroyed in
 *           ShadowDestroyPrivateNamespace.
 *
 * Thread Safety: All access must be synchronized with EX_PUSH_LOCK.
 */
typedef struct _SHADOW_NAMESPACE_STATE {

    //
    // Synchronization
    //

    /// @brief Lock protecting this structure
    EX_PUSH_LOCK Lock;

    /// @brief TRUE if lock was initialized
    BOOLEAN LockInitialized;

    /// @brief Atomic initialization flag (0=uninitialized, 1=initializing, 2=initialized)
    volatile LONG InitializationState;

    //
    // Namespace Objects
    //

    /// @brief Handle to \ShadowStrike directory object
    HANDLE DirectoryHandle;

    /// @brief Handle to boundary descriptor (for namespace isolation)
    POBJECT_BOUNDARY_DESCRIPTOR BoundaryDescriptor;

    /// @brief Pointer to directory object (for reference counting)
    PVOID DirectoryObject;

    /// @brief TRUE if directory object reference was taken
    BOOLEAN DirectoryObjectReferenced;

    //
    // Security Descriptors
    //

    /// @brief Security descriptor for directory object (System + Admin only)
    PSECURITY_DESCRIPTOR DirectorySecurityDescriptor;

    /// @brief Security descriptor size
    ULONG SecurityDescriptorSize;

    /// @brief TRUE if security descriptor was allocated
    BOOLEAN SecurityDescriptorAllocated;

    /// @brief Reference drain timeout in milliseconds (configurable)
    ULONG DrainTimeoutMs;

    //
    // State Tracking
    //

    /// @brief TRUE if namespace is fully initialized
    BOOLEAN Initialized;

    /// @brief TRUE if namespace is being destroyed
    BOOLEAN Destroying;

    /// @brief Creation timestamp
    LARGE_INTEGER CreationTime;

    /// @brief Reference count for safe cleanup
    volatile LONG ReferenceCount;

    /// @brief Padding for alignment
    BOOLEAN Reserved[2];

} SHADOW_NAMESPACE_STATE, *PSHADOW_NAMESPACE_STATE;

// ============================================================================
// GLOBAL NAMESPACE STATE
// ============================================================================

/**
 * @brief Global namespace state instance.
 *
 * Defined in ObjectNamespace.c, accessible within this module only.
 */
extern SHADOW_NAMESPACE_STATE g_NamespaceState;

// ============================================================================
// PUBLIC FUNCTION PROTOTYPES
// ============================================================================

/**
 * @brief Create and secure the private namespace.
 *
 * Creates \ShadowStrike directory object with restrictive ACL that allows
 * only SYSTEM and Administrators. Sets up boundary descriptor to prevent
 * Medium IL processes from accessing the namespace.
 *
 * This function must be called early in DriverEntry, before any other
 * modules attempt to create objects in the namespace.
 *
 * Algorithm:
 * 1. Initialize namespace state structure
 * 2. Build restrictive security descriptor (SYSTEM + Admin only)
 * 3. Create boundary descriptor for namespace isolation
 * 4. Create \ShadowStrike directory object with security
 * 5. Reference the directory object to prevent premature deletion
 * 6. Mark namespace as initialized
 *
 * @return STATUS_SUCCESS on success
 *         STATUS_INSUFFICIENT_RESOURCES if allocation fails
 *         STATUS_ACCESS_DENIED if security descriptor creation fails
 *         STATUS_OBJECT_NAME_COLLISION if namespace already exists
 *
 * @note This function can only be called once. Subsequent calls return
 *       STATUS_ALREADY_INITIALIZED.
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowCreatePrivateNamespace(
    VOID
    );

/**
 * @brief Destroy the private namespace and cleanup resources.
 *
 * Closes all handles, dereferences objects, and frees all allocated
 * resources. This function is BSOD-safe and handles partial initialization.
 *
 * Safe to call even if ShadowCreatePrivateNamespace failed or was never called.
 *
 * Algorithm:
 * 1. Mark namespace as destroying to prevent new operations
 * 2. Wait for all outstanding references to drain (with timeout)
 * 3. Dereference directory object (if referenced)
 * 4. Close directory handle (if opened)
 * 5. Delete boundary descriptor (if created)
 * 6. Free security descriptor (if allocated)
 * 7. Delete push lock (if initialized)
 * 8. Zero the namespace state structure
 *
 * @irql PASSIVE_LEVEL
 */
VOID
ShadowDestroyPrivateNamespace(
    VOID
    );

/**
 * @brief Create a named object within the private namespace.
 *
 * Helper function to create objects (events, symbolic links, etc.) within
 * the \ShadowStrike namespace with proper security.
 *
 * Automatically applies the restrictive security descriptor to all objects.
 *
 * @param ObjectName    Relative name within \ShadowStrike (e.g., L"ScanPort")
 * @param ObjectType    Type of object to create (EVENT, SYMLINK, etc.)
 * @param ObjectHandle  [out] Receives handle to created object
 * @param ObjectPointer [out, optional] Receives pointer to object
 *
 * @return STATUS_SUCCESS on success
 *         STATUS_INVALID_PARAMETER if namespace not initialized
 *         Other NTSTATUS codes from ZwCreateXxx functions
 *
 * @note Caller must close the handle when done (ZwClose)
 * @note Caller must dereference object pointer if provided (ObDereferenceObject)
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowCreateNamespaceObject(
    _In_ PCWSTR ObjectName,
    _In_ POBJECT_TYPE ObjectType,
    _Out_ PHANDLE ObjectHandle,
    _Outptr_opt_ PVOID* ObjectPointer
    );

/**
 * @brief Open an existing object within the private namespace.
 *
 * Opens a handle to an existing object in \ShadowStrike namespace.
 * Validates that the object exists and is accessible.
 *
 * @param ObjectName    Relative name within \ShadowStrike
 * @param DesiredAccess Access rights requested
 * @param ObjectHandle  [out] Receives handle to object
 *
 * @return STATUS_SUCCESS on success
 *         STATUS_OBJECT_NAME_NOT_FOUND if object doesn't exist
 *
 * @irql PASSIVE_LEVEL
 */
NTSTATUS
ShadowOpenNamespaceObject(
    _In_ PCWSTR ObjectName,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ObjectHandle
    );

/**
 * @brief Check if the private namespace is initialized.
 *
 * Thread-safe check of namespace initialization state.
 *
 * @return TRUE if namespace is ready, FALSE otherwise
 */
BOOLEAN
ShadowIsNamespaceInitialized(
    VOID
    );

/**
 * @brief Acquire a reference to the namespace.
 *
 * Increments reference count to prevent namespace destruction during
 * operations. Must be paired with ShadowDereferenceNamespace.
 *
 * @return TRUE if reference acquired, FALSE if namespace is destroying
 */
BOOLEAN
ShadowReferenceNamespace(
    VOID
    );

/**
 * @brief Release a reference to the namespace.
 *
 * Decrements reference count. When count reaches zero during destruction,
 * allows cleanup to complete.
 */
VOID
ShadowDereferenceNamespace(
    VOID
    );

// ============================================================================
// PRIVATE HELPER PROTOTYPES (Internal use only)
// ============================================================================

/**
 * @brief Build restrictive security descriptor.
 *
 * Creates DACL allowing only SYSTEM and Administrators with full control.
 * Denies all other principals including Local Service and Network Service.
 *
 * @param SecurityDescriptor [out] Receives allocated security descriptor
 * @param DescriptorSize     [out] Receives size of descriptor
 *
 * @return STATUS_SUCCESS or error code
 */
NTSTATUS
ShadowBuildNamespaceSecurityDescriptor(
    _Outptr_ PSECURITY_DESCRIPTOR* SecurityDescriptor,
    _Out_ PULONG DescriptorSize
    );

/**
 * @brief Create boundary descriptor for namespace isolation.
 *
 * Creates boundary descriptor with High Integrity Level requirement to
 * isolate the namespace from Medium IL processes.
 *
 * @param BoundaryDescriptor [out] Receives boundary descriptor pointer
 *
 * @return STATUS_SUCCESS or error code
 */
NTSTATUS
ShadowCreateBoundaryDescriptor(
    _Outptr_ POBJECT_BOUNDARY_DESCRIPTOR* BoundaryDescriptor
    );

/**
 * @brief Add mandatory integrity level to security descriptor.
 *
 * Adds High Integrity Level mandatory label to prevent Medium IL access.
 *
 * @param SecurityDescriptor [in/out] Security descriptor to modify
 *
 * @return STATUS_SUCCESS or error code
 */
NTSTATUS
ShadowAddMandatoryLabel(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor
    );

/**
 * @brief Add SACL for auditing to security descriptor.
 *
 * Adds System Audit ACL to log all access attempts.
 *
 * @param SecurityDescriptor [in/out] Security descriptor to modify
 *
 * @return STATUS_SUCCESS or error code
 */
NTSTATUS
ShadowAddAuditSacl(
    _Inout_ PSECURITY_DESCRIPTOR SecurityDescriptor
    );

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_OBJECT_NAMESPACE_H
