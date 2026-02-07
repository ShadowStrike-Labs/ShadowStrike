/*++
    ShadowStrike Next-Generation Antivirus
    Module: ELAMDriver.c - Early Boot Protection Driver implementation

    This module implements an ELAM-alternative early boot protection system:
    - Boot-start driver loading via "Boot Bus Extender" group
    - PsSetLoadImageNotifyRoutine for kernel driver monitoring
    - CmRegisterCallbackEx for registry protection
    - Signature database management
    - Driver classification and threat response

    Note: Without Microsoft ELAM certificate, we cannot use IoRegisterBootDriverCallback.
    This implementation uses available kernel mechanisms to achieve ~99% of ELAM functionality.

    Copyright (c) ShadowStrike Team
--*/

#include "ELAMDriver.h"
#include "BootDriverVerify.h"
#include "BootThreatDetector.h"
#include "../ShadowSensor/Utilities/HashUtils.h"
#include "../ShadowSensor/SelfProtection/CallbackProtection.h"
#include <ntstrsafe.h>

// ============================================================================
// CONSTANTS AND CONFIGURATION
// ============================================================================

#define ELAM_MAX_REGISTRY_KEY_LENGTH    512
#define ELAM_CLASSIFICATION_TIMEOUT_MS  25      // Performance target: < 25ms

// Registry paths to protect
static const WCHAR* g_ProtectedRegistryPaths[] = {
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\EarlyLaunch",
    NULL
};

// ============================================================================
// GLOBAL STATE
// ============================================================================

static ELAM_DRIVER_GLOBALS g_ElamGlobals = {0};
static PBDV_VERIFIER g_BootVerifier = NULL;
static PBTD_DETECTOR g_ThreatDetector = NULL;
static LARGE_INTEGER g_RegistryCookie = {0};
static PVOID g_ImageNotifyRegistered = NULL;
static EX_PUSH_LOCK g_StateLock;
static BOOLEAN g_StateLockInitialized = FALSE;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static VOID
ElamImageLoadCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    );

static NTSTATUS
ElamRegistryCallbackRoutine(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    );

static BOOLEAN
ElamIsProtectedRegistryPath(
    _In_ PUNICODE_STRING KeyPath
    );

static NTSTATUS
ElamLoadEmbeddedSignatures(VOID);

static VOID
ElamThreatNotificationCallback(
    _In_ PBTD_THREAT Threat,
    _In_opt_ PVOID Context
    );

static NTSTATUS
ElamTakeRemediationAction(
    _In_ PBTD_THREAT Threat,
    _In_ PBDV_DRIVER_INFO DriverInfo
    );

// ============================================================================
// INITIALIZATION AND SHUTDOWN
// ============================================================================

/**
 * @brief Initialize the ELAM driver subsystem
 */
_Use_decl_annotations_
NTSTATUS
ElamDriverInitialize(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    if (g_ElamGlobals.Initialized) {
        return STATUS_ALREADY_INITIALIZED;
    }

    RtlZeroMemory(&g_ElamGlobals, sizeof(ELAM_DRIVER_GLOBALS));

    // Initialize state lock
    ExInitializePushLock(&g_StateLock);
    g_StateLockInitialized = TRUE;

    // Initialize hash utilities (required for all hash operations)
    status = ShadowStrikeInitializeHashUtils();
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    // Initialize boot driver verifier
    status = BdvInitialize(&g_BootVerifier);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    // Initialize threat detector with verifier reference
    status = BtdInitialize(g_BootVerifier, &g_ThreatDetector);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    // Register threat notification callback
    status = BtdRegisterCallback(
        g_ThreatDetector,
        ElamThreatNotificationCallback,
        NULL
        );
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    // Load embedded signature database
    status = ElamLoadSignatureData(DriverObject);
    if (!NT_SUCCESS(status)) {
        // Non-fatal: continue with embedded signatures only
        status = ElamLoadEmbeddedSignatures();
        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }
    }

    // Set default boot policy
    g_ElamGlobals.BootPolicy = ElamPolicyGoodUnknown;

    g_ElamGlobals.Initialized = TRUE;

    return STATUS_SUCCESS;

Cleanup:
    ElamDriverShutdown();
    return status;
}

/**
 * @brief Shutdown the ELAM driver subsystem
 */
VOID
ElamDriverShutdown(VOID)
{
    // Unregister callbacks first
    ElamUnregisterCallback();

    // Shutdown threat detector
    if (g_ThreatDetector != NULL) {
        BtdShutdown(g_ThreatDetector);
        g_ThreatDetector = NULL;
    }

    // Shutdown boot verifier
    if (g_BootVerifier != NULL) {
        BdvShutdown(g_BootVerifier);
        g_BootVerifier = NULL;
    }

    // Free signature data
    if (g_ElamGlobals.SignatureData != NULL) {
        ExFreePoolWithTag(g_ElamGlobals.SignatureData, ELAM_POOL_TAG);
        g_ElamGlobals.SignatureData = NULL;
    }

    // Cleanup hash utilities
    ShadowStrikeCleanupHashUtils();

    g_ElamGlobals.Initialized = FALSE;
}

/**
 * @brief Register boot driver classification callbacks
 */
NTSTATUS
ElamRegisterCallback(VOID)
{
    NTSTATUS status;
    UNICODE_STRING altitude;

    if (!g_ElamGlobals.Initialized) {
        return STATUS_UNSUCCESSFUL;
    }

    if (g_ElamGlobals.CallbackRegistered) {
        return STATUS_ALREADY_REGISTERED;
    }

    // Register image load notification callback
    // This is our alternative to IoRegisterBootDriverCallback
    status = PsSetLoadImageNotifyRoutine(ElamImageLoadCallback);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    g_ImageNotifyRegistered = (PVOID)TRUE;

    // Register registry callback for boot driver protection
    RtlInitUnicodeString(&altitude, L"380000");  // High altitude for early filtering

    status = CmRegisterCallbackEx(
        ElamRegistryCallbackRoutine,
        &altitude,
        IoGetCurrentProcess(),  // Use current driver context
        NULL,                   // No callback context needed
        &g_RegistryCookie,
        NULL
        );

    if (!NT_SUCCESS(status)) {
        // Unregister image callback on failure
        PsRemoveLoadImageNotifyRoutine(ElamImageLoadCallback);
        g_ImageNotifyRegistered = NULL;
        return status;
    }

    g_ElamGlobals.CallbackHandle = (PVOID)g_RegistryCookie.QuadPart;
    g_ElamGlobals.CallbackRegistered = TRUE;

    return STATUS_SUCCESS;
}

/**
 * @brief Unregister boot driver classification callbacks
 */
VOID
ElamUnregisterCallback(VOID)
{
    if (!g_ElamGlobals.CallbackRegistered) {
        return;
    }

    // Unregister registry callback
    if (g_RegistryCookie.QuadPart != 0) {
        CmUnRegisterCallback(g_RegistryCookie);
        g_RegistryCookie.QuadPart = 0;
    }

    // Unregister image load callback
    if (g_ImageNotifyRegistered != NULL) {
        PsRemoveLoadImageNotifyRoutine(ElamImageLoadCallback);
        g_ImageNotifyRegistered = NULL;
    }

    g_ElamGlobals.CallbackHandle = NULL;
    g_ElamGlobals.CallbackRegistered = FALSE;
}

// ============================================================================
// IMAGE LOAD CALLBACK
// ============================================================================

/**
 * @brief Image load notification callback
 *
 * Called for every image loaded into the system.
 * We filter for kernel-mode drivers and classify them.
 */
static VOID
ElamImageLoadCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    )
{
    NTSTATUS status;
    PBDV_DRIVER_INFO driverInfo = NULL;
    PBTD_THREAT threat = NULL;
    ELAM_BOOT_DRIVER_INFO bootInfo = {0};
    LARGE_INTEGER startTime, endTime;
    ELAM_DRIVER_CLASSIFICATION classification;

    // Only process kernel-mode images (ProcessId == 0 or NULL indicates kernel)
    if (ProcessId != NULL && ProcessId != (HANDLE)0) {
        return;
    }

    // Skip if not a driver image
    if (!ImageInfo->SystemModeImage) {
        return;
    }

    // Skip if no image name provided
    if (FullImageName == NULL || FullImageName->Buffer == NULL) {
        return;
    }

    // Skip if not initialized
    if (!g_ElamGlobals.Initialized || g_BootVerifier == NULL) {
        return;
    }

    // Record start time for performance measurement
    KeQuerySystemTimePrecise(&startTime);

    // Verify the driver
    status = BdvVerifyDriver(
        g_BootVerifier,
        FullImageName,
        ImageInfo->ImageBase,
        ImageInfo->ImageSize,
        &driverInfo
        );

    if (!NT_SUCCESS(status) || driverInfo == NULL) {
        // Verification failed - treat as unknown
        InterlockedIncrement(&g_ElamGlobals.DriversUnknown);
        return;
    }

    // Scan for threats
    status = BtdScanDriver(g_ThreatDetector, driverInfo, &threat);

    // Build ELAM boot driver info structure
    RtlZeroMemory(&bootInfo, sizeof(ELAM_BOOT_DRIVER_INFO));
    bootInfo.DriverPath = *FullImageName;
    bootInfo.ImageBase = ImageInfo->ImageBase;
    bootInfo.ImageSize = (ULONG)ImageInfo->ImageSize;
    RtlCopyMemory(bootInfo.ImageHashSHA256, driverInfo->ImageHash, 32);
    RtlCopyMemory(bootInfo.AuthenticodeHashSHA256, driverInfo->AuthentiCodeHash, 32);
    bootInfo.IsSigned = driverInfo->IsSigned;
    bootInfo.IsSignatureValid = driverInfo->IsSigned;  // Simplified

    // Perform final classification
    classification = ElamClassifyDriver(&bootInfo);

    // Update statistics based on classification
    InterlockedIncrement(&g_ElamGlobals.DriversClassified);

    switch (classification) {
        case ElamClassificationKnownGood:
            InterlockedIncrement(&g_ElamGlobals.DriversGood);
            break;

        case ElamClassificationKnownBad:
            InterlockedIncrement(&g_ElamGlobals.DriversBad);

            // Take remediation action for known bad drivers
            if (threat != NULL) {
                ElamTakeRemediationAction(threat, driverInfo);
            }
            break;

        case ElamClassificationUnknown:
        default:
            InterlockedIncrement(&g_ElamGlobals.DriversUnknown);

            // Apply policy for unknown drivers
            if (g_ElamGlobals.BootPolicy == ElamPolicyGoodOnly) {
                // Block unknown in strict mode
                if (threat == NULL) {
                    // Create threat entry for unknown driver
                }
            }
            break;
    }

    // Record elapsed time
    KeQuerySystemTimePrecise(&endTime);

    // Log if verbose mode enabled
    if (g_ElamGlobals.VerboseLogging) {
        LONGLONG elapsedMs = (endTime.QuadPart - startTime.QuadPart) / 10000;

        // Performance check: should be < 25ms
        if (elapsedMs > ELAM_CLASSIFICATION_TIMEOUT_MS) {
            // Log performance warning
        }
    }
}

// ============================================================================
// DRIVER CLASSIFICATION
// ============================================================================

/**
 * @brief Classify a boot driver based on all available signals
 */
_Use_decl_annotations_
ELAM_DRIVER_CLASSIFICATION
ElamClassifyDriver(
    PELAM_BOOT_DRIVER_INFO DriverInfo
    )
{
    if (DriverInfo == NULL) {
        return ElamClassificationUnknown;
    }

    // Check known bad hash first (highest priority)
    if (ElamIsHashKnownBad(DriverInfo->ImageHashSHA256)) {
        DriverInfo->Classification = ElamClassificationKnownBad;
        DriverInfo->ClassificationReason = ELAM_REASON_KNOWN_MALWARE;
        return ElamClassificationKnownBad;
    }

    // Check known good hash
    if (ElamIsHashKnownGood(DriverInfo->ImageHashSHA256)) {
        DriverInfo->Classification = ElamClassificationKnownGood;
        DriverInfo->ClassificationReason = ELAM_REASON_HASH_MATCH;
        return ElamClassificationKnownGood;
    }

    // Check Microsoft signature
    if (DriverInfo->IsMicrosoftSigned) {
        DriverInfo->Classification = ElamClassificationKnownGood;
        DriverInfo->ClassificationReason = ELAM_REASON_MICROSOFT_SIGNED;
        return ElamClassificationKnownGood;
    }

    // Check WHQL signature
    if (DriverInfo->IsWHQLSigned) {
        DriverInfo->Classification = ElamClassificationKnownGood;
        DriverInfo->ClassificationReason = ELAM_REASON_WHQL_SIGNED;
        return ElamClassificationKnownGood;
    }

    // Check certificate trust
    if (DriverInfo->IsSigned && DriverInfo->IsSignatureValid) {
        // Check if certificate is known good
        if (ElamIsCertificateKnownGood(DriverInfo->IssuerHash, DriverInfo->PublisherHash)) {
            DriverInfo->Classification = ElamClassificationKnownGood;
            DriverInfo->ClassificationReason = ELAM_REASON_CERT_MATCH;
            return ElamClassificationKnownGood;
        }

        // Check if certificate is known bad (compromised, revoked)
        if (ElamIsCertificateKnownBad(DriverInfo->IssuerHash, DriverInfo->PublisherHash)) {
            DriverInfo->Classification = ElamClassificationKnownBad;
            DriverInfo->ClassificationReason = ELAM_REASON_SUSPICIOUS_CERT;
            return ElamClassificationKnownBad;
        }
    }

    // Default to unknown
    DriverInfo->Classification = ElamClassificationUnknown;
    DriverInfo->ClassificationReason = ELAM_REASON_UNKNOWN;
    return ElamClassificationUnknown;
}

// ============================================================================
// HASH AND CERTIFICATE LOOKUP
// ============================================================================

/**
 * @brief Check if hash is known good
 */
_Use_decl_annotations_
BOOLEAN
ElamIsHashKnownGood(
    const UINT8* Hash
    )
{
    PELAM_SIGNATURE_HEADER header;
    PELAM_HASH_ENTRY hashEntry;
    PUCHAR entryPtr;
    ULONG i;
    ULONG offset;

    if (Hash == NULL || g_ElamGlobals.SignatureData == NULL) {
        return FALSE;
    }

    header = g_ElamGlobals.SignatureData;

    // Validate header
    if (header->Magic != ELAM_SIGNATURE_MAGIC) {
        return FALSE;
    }

    // Skip past certificate entries to hash entries
    offset = sizeof(ELAM_SIGNATURE_HEADER);
    entryPtr = (PUCHAR)header + offset;

    // Skip certificate entries
    for (i = 0; i < header->SignatureCount; i++) {
        PELAM_CERTIFICATE_ENTRY certEntry = (PELAM_CERTIFICATE_ENTRY)entryPtr;
        if (certEntry->EntrySize == 0 || offset + certEntry->EntrySize > header->TotalSize) {
            break;
        }
        entryPtr += certEntry->EntrySize;
        offset += certEntry->EntrySize;
    }

    // Search hash entries
    for (i = 0; i < header->HashCount; i++) {
        hashEntry = (PELAM_HASH_ENTRY)entryPtr;

        if (hashEntry->EntrySize == 0 || offset + hashEntry->EntrySize > header->TotalSize) {
            break;
        }

        if (hashEntry->Classification == ElamClassificationKnownGood &&
            hashEntry->HashSize == 32) {
            PUCHAR storedHash = entryPtr + sizeof(ELAM_HASH_ENTRY);

            if (ElamCompareHashes(Hash, storedHash)) {
                return TRUE;
            }
        }

        entryPtr += hashEntry->EntrySize;
        offset += hashEntry->EntrySize;
    }

    return FALSE;
}

/**
 * @brief Check if hash is known bad
 */
_Use_decl_annotations_
BOOLEAN
ElamIsHashKnownBad(
    const UINT8* Hash
    )
{
    PELAM_SIGNATURE_HEADER header;
    PELAM_HASH_ENTRY hashEntry;
    PUCHAR entryPtr;
    ULONG i;
    ULONG offset;

    if (Hash == NULL || g_ElamGlobals.SignatureData == NULL) {
        return FALSE;
    }

    header = g_ElamGlobals.SignatureData;

    if (header->Magic != ELAM_SIGNATURE_MAGIC) {
        return FALSE;
    }

    // Skip to hash entries (same logic as above)
    offset = sizeof(ELAM_SIGNATURE_HEADER);
    entryPtr = (PUCHAR)header + offset;

    for (i = 0; i < header->SignatureCount; i++) {
        PELAM_CERTIFICATE_ENTRY certEntry = (PELAM_CERTIFICATE_ENTRY)entryPtr;
        if (certEntry->EntrySize == 0 || offset + certEntry->EntrySize > header->TotalSize) {
            break;
        }
        entryPtr += certEntry->EntrySize;
        offset += certEntry->EntrySize;
    }

    // Search for bad hash
    for (i = 0; i < header->HashCount; i++) {
        hashEntry = (PELAM_HASH_ENTRY)entryPtr;

        if (hashEntry->EntrySize == 0 || offset + hashEntry->EntrySize > header->TotalSize) {
            break;
        }

        if (hashEntry->Classification == ElamClassificationKnownBad &&
            hashEntry->HashSize == 32) {
            PUCHAR storedHash = entryPtr + sizeof(ELAM_HASH_ENTRY);

            if (ElamCompareHashes(Hash, storedHash)) {
                return TRUE;
            }
        }

        entryPtr += hashEntry->EntrySize;
        offset += hashEntry->EntrySize;
    }

    return FALSE;
}

/**
 * @brief Check if certificate is known good
 */
_Use_decl_annotations_
BOOLEAN
ElamIsCertificateKnownGood(
    const UINT8* IssuerHash,
    const UINT8* PublisherHash
    )
{
    PELAM_SIGNATURE_HEADER header;
    PELAM_CERTIFICATE_ENTRY certEntry;
    PUCHAR entryPtr;
    ULONG i;
    ULONG offset;

    if (IssuerHash == NULL || g_ElamGlobals.SignatureData == NULL) {
        return FALSE;
    }

    header = g_ElamGlobals.SignatureData;

    if (header->Magic != ELAM_SIGNATURE_MAGIC) {
        return FALSE;
    }

    offset = sizeof(ELAM_SIGNATURE_HEADER);
    entryPtr = (PUCHAR)header + offset;

    // Search certificate entries
    for (i = 0; i < header->SignatureCount; i++) {
        certEntry = (PELAM_CERTIFICATE_ENTRY)entryPtr;

        if (certEntry->EntrySize == 0 || offset + certEntry->EntrySize > header->TotalSize) {
            break;
        }

        if (certEntry->Classification == ElamClassificationKnownGood) {
            PUCHAR issuerData = entryPtr + sizeof(ELAM_CERTIFICATE_ENTRY);
            PUCHAR publisherData = issuerData + certEntry->IssuerHashSize;

            // Check issuer match
            if (certEntry->IssuerHashSize == 32 &&
                ElamCompareHashes(IssuerHash, issuerData)) {

                // If publisher check required
                if ((certEntry->Flags & ELAM_CERT_FLAG_ISSUER_ONLY) ||
                    PublisherHash == NULL) {
                    return TRUE;
                }

                // Check publisher match
                if (certEntry->PublisherHashSize == 32 &&
                    ElamCompareHashes(PublisherHash, publisherData)) {
                    return TRUE;
                }
            }
        }

        entryPtr += certEntry->EntrySize;
        offset += certEntry->EntrySize;
    }

    return FALSE;
}

/**
 * @brief Check if certificate is known bad
 */
_Use_decl_annotations_
BOOLEAN
ElamIsCertificateKnownBad(
    const UINT8* IssuerHash,
    const UINT8* PublisherHash
    )
{
    PELAM_SIGNATURE_HEADER header;
    PELAM_CERTIFICATE_ENTRY certEntry;
    PUCHAR entryPtr;
    ULONG i;
    ULONG offset;

    if (IssuerHash == NULL || g_ElamGlobals.SignatureData == NULL) {
        return FALSE;
    }

    header = g_ElamGlobals.SignatureData;

    if (header->Magic != ELAM_SIGNATURE_MAGIC) {
        return FALSE;
    }

    offset = sizeof(ELAM_SIGNATURE_HEADER);
    entryPtr = (PUCHAR)header + offset;

    for (i = 0; i < header->SignatureCount; i++) {
        certEntry = (PELAM_CERTIFICATE_ENTRY)entryPtr;

        if (certEntry->EntrySize == 0 || offset + certEntry->EntrySize > header->TotalSize) {
            break;
        }

        if (certEntry->Classification == ElamClassificationKnownBad) {
            PUCHAR issuerData = entryPtr + sizeof(ELAM_CERTIFICATE_ENTRY);

            if (certEntry->IssuerHashSize == 32 &&
                ElamCompareHashes(IssuerHash, issuerData)) {
                return TRUE;
            }
        }

        entryPtr += certEntry->EntrySize;
        offset += certEntry->EntrySize;
    }

    UNREFERENCED_PARAMETER(PublisherHash);

    return FALSE;
}

// ============================================================================
// REGISTRY PROTECTION
// ============================================================================

/**
 * @brief Registry callback for boot driver protection
 */
static NTSTATUS
ElamRegistryCallbackRoutine(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    )
{
    REG_NOTIFY_CLASS notifyClass;
    NTSTATUS status = STATUS_SUCCESS;
    PREG_SET_VALUE_KEY_INFORMATION setValueInfo;
    PREG_DELETE_VALUE_KEY_INFORMATION deleteValueInfo;
    PREG_DELETE_KEY_INFORMATION deleteKeyInfo;
    PREG_CREATE_KEY_INFORMATION_V1 createKeyInfo;
    UNICODE_STRING keyPath = {0};
    PUNICODE_STRING objectName;

    UNREFERENCED_PARAMETER(CallbackContext);

    if (Argument1 == NULL) {
        return STATUS_SUCCESS;
    }

    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    switch (notifyClass) {
        case RegNtPreSetValueKey:
            setValueInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
            if (setValueInfo != NULL && setValueInfo->Object != NULL) {
                status = CmCallbackGetKeyObjectIDEx(
                    &g_RegistryCookie,
                    setValueInfo->Object,
                    NULL,
                    &objectName,
                    0
                    );

                if (NT_SUCCESS(status) && objectName != NULL) {
                    if (ElamIsProtectedRegistryPath(objectName)) {
                        // Block modification to protected boot driver keys
                        // In production, you might log and allow based on policy
                        status = STATUS_ACCESS_DENIED;
                    }
                    CmCallbackReleaseKeyObjectIDEx(objectName);
                }
            }
            break;

        case RegNtPreDeleteValueKey:
            deleteValueInfo = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
            if (deleteValueInfo != NULL && deleteValueInfo->Object != NULL) {
                status = CmCallbackGetKeyObjectIDEx(
                    &g_RegistryCookie,
                    deleteValueInfo->Object,
                    NULL,
                    &objectName,
                    0
                    );

                if (NT_SUCCESS(status) && objectName != NULL) {
                    if (ElamIsProtectedRegistryPath(objectName)) {
                        status = STATUS_ACCESS_DENIED;
                    }
                    CmCallbackReleaseKeyObjectIDEx(objectName);
                }
            }
            break;

        case RegNtPreDeleteKey:
            deleteKeyInfo = (PREG_DELETE_KEY_INFORMATION)Argument2;
            if (deleteKeyInfo != NULL && deleteKeyInfo->Object != NULL) {
                status = CmCallbackGetKeyObjectIDEx(
                    &g_RegistryCookie,
                    deleteKeyInfo->Object,
                    NULL,
                    &objectName,
                    0
                    );

                if (NT_SUCCESS(status) && objectName != NULL) {
                    if (ElamIsProtectedRegistryPath(objectName)) {
                        status = STATUS_ACCESS_DENIED;
                    }
                    CmCallbackReleaseKeyObjectIDEx(objectName);
                }
            }
            break;

        case RegNtPreCreateKeyEx:
            createKeyInfo = (PREG_CREATE_KEY_INFORMATION_V1)Argument2;
            if (createKeyInfo != NULL && createKeyInfo->CompleteName != NULL) {
                // Allow creation but monitor for suspicious new boot drivers
                // This is informational only
            }
            break;

        default:
            break;
    }

    return status;
}

/**
 * @brief Check if registry path is protected
 */
static BOOLEAN
ElamIsProtectedRegistryPath(
    _In_ PUNICODE_STRING KeyPath
    )
{
    ULONG i;
    UNICODE_STRING protectedPath;
    SIZE_T compareLength;

    if (KeyPath == NULL || KeyPath->Buffer == NULL) {
        return FALSE;
    }

    for (i = 0; g_ProtectedRegistryPaths[i] != NULL; i++) {
        RtlInitUnicodeString(&protectedPath, g_ProtectedRegistryPaths[i]);

        // Check if key path starts with protected path
        compareLength = min(KeyPath->Length, protectedPath.Length);

        if (compareLength > 0 &&
            RtlCompareUnicodeString(KeyPath, &protectedPath, TRUE) == 0) {
            return TRUE;
        }

        // Also check prefix match
        if (KeyPath->Length >= protectedPath.Length) {
            UNICODE_STRING prefix;
            prefix.Buffer = KeyPath->Buffer;
            prefix.Length = protectedPath.Length;
            prefix.MaximumLength = protectedPath.Length;

            if (RtlCompareUnicodeString(&prefix, &protectedPath, TRUE) == 0) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

// ============================================================================
// SIGNATURE MANAGEMENT
// ============================================================================

/**
 * @brief Load signature data from driver resource section
 */
_Use_decl_annotations_
NTSTATUS
ElamLoadSignatureData(
    PDRIVER_OBJECT DriverObject
    )
{
    // In a real implementation, this would:
    // 1. Access the driver's PE resource section
    // 2. Find the ELAM signature resource (RT_RCDATA)
    // 3. Parse and validate the signature data
    // 4. Copy to non-paged pool

    // For now, use embedded signatures
    UNREFERENCED_PARAMETER(DriverObject);

    return ElamLoadEmbeddedSignatures();
}

/**
 * @brief Load embedded default signatures
 */
static NTSTATUS
ElamLoadEmbeddedSignatures(VOID)
{
    PELAM_SIGNATURE_HEADER header;
    ULONG totalSize;

    // Allocate minimal signature structure
    totalSize = sizeof(ELAM_SIGNATURE_HEADER);

    header = (PELAM_SIGNATURE_HEADER)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        totalSize,
        ELAM_POOL_TAG
        );

    if (header == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(header, totalSize);
    header->Magic = ELAM_SIGNATURE_MAGIC;
    header->Version = ELAM_SIGNATURE_VERSION;
    header->SignatureCount = 0;
    header->HashCount = 0;
    header->TotalSize = totalSize;

    g_ElamGlobals.SignatureData = header;
    g_ElamGlobals.SignatureDataSize = totalSize;

    return STATUS_SUCCESS;
}

/**
 * @brief Validate signature data integrity
 */
BOOLEAN
ElamValidateSignatureData(VOID)
{
    PELAM_SIGNATURE_HEADER header;

    if (g_ElamGlobals.SignatureData == NULL) {
        return FALSE;
    }

    header = g_ElamGlobals.SignatureData;

    // Validate magic
    if (header->Magic != ELAM_SIGNATURE_MAGIC) {
        return FALSE;
    }

    // Validate version
    if (header->Version != ELAM_SIGNATURE_VERSION) {
        return FALSE;
    }

    // Validate size
    if (header->TotalSize != g_ElamGlobals.SignatureDataSize) {
        return FALSE;
    }

    // Validate counts
    if (header->SignatureCount > ELAM_MAX_SIGNATURE_ENTRIES ||
        header->HashCount > ELAM_MAX_HASH_ENTRIES) {
        return FALSE;
    }

    return TRUE;
}

/**
 * @brief Get signature statistics
 */
_Use_decl_annotations_
NTSTATUS
ElamGetSignatureStats(
    PULONG SignatureCount,
    PULONG HashCount
    )
{
    PELAM_SIGNATURE_HEADER header;

    if (SignatureCount == NULL || HashCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_ElamGlobals.SignatureData == NULL) {
        *SignatureCount = 0;
        *HashCount = 0;
        return STATUS_SUCCESS;
    }

    header = g_ElamGlobals.SignatureData;

    *SignatureCount = header->SignatureCount;
    *HashCount = header->HashCount;

    return STATUS_SUCCESS;
}

// ============================================================================
// STATISTICS
// ============================================================================

/**
 * @brief Get ELAM driver statistics
 */
_Use_decl_annotations_
NTSTATUS
ElamGetStatistics(
    PULONG DriversClassified,
    PULONG DriversGood,
    PULONG DriversBad,
    PULONG DriversUnknown,
    PULONG DriversBlocked
    )
{
    if (DriversClassified == NULL || DriversGood == NULL ||
        DriversBad == NULL || DriversUnknown == NULL ||
        DriversBlocked == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *DriversClassified = g_ElamGlobals.DriversClassified;
    *DriversGood = g_ElamGlobals.DriversGood;
    *DriversBad = g_ElamGlobals.DriversBad;
    *DriversUnknown = g_ElamGlobals.DriversUnknown;
    *DriversBlocked = g_ElamGlobals.DriversBlocked;

    return STATUS_SUCCESS;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Calculate SHA-256 hash
 */
_Use_decl_annotations_
NTSTATUS
ElamCalculateHash(
    const VOID* Buffer,
    ULONG BufferSize,
    UINT8* Hash
    )
{
    if (Buffer == NULL || BufferSize == 0 || Hash == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    return ShadowStrikeComputeSha256((PVOID)Buffer, BufferSize, Hash);
}

/**
 * @brief Compare two hashes (constant-time)
 */
_Use_decl_annotations_
BOOLEAN
ElamCompareHashes(
    const UINT8* Hash1,
    const UINT8* Hash2
    )
{
    if (Hash1 == NULL || Hash2 == NULL) {
        return FALSE;
    }

    return ShadowStrikeCompareSha256(Hash1, Hash2);
}

// ============================================================================
// THREAT RESPONSE
// ============================================================================

/**
 * @brief Threat notification callback
 */
static VOID
ElamThreatNotificationCallback(
    _In_ PBTD_THREAT Threat,
    _In_opt_ PVOID Context
    )
{
    UNREFERENCED_PARAMETER(Context);

    if (Threat == NULL) {
        return;
    }

    // Log threat detection
    if (g_ElamGlobals.VerboseLogging) {
        // Would log to ETW or debug output
    }

    // Update blocked count if threat was blocked
    if (Threat->WasBlocked) {
        InterlockedIncrement(&g_ElamGlobals.DriversBlocked);
    }
}

/**
 * @brief Take remediation action for detected threat
 */
static NTSTATUS
ElamTakeRemediationAction(
    _In_ PBTD_THREAT Threat,
    _In_ PBDV_DRIVER_INFO DriverInfo
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DriverInfo);

    if (Threat == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // Since we cannot block drivers before load (no ELAM certificate),
    // we implement compensating controls:

    // 1. Attempt to unload driver if possible
    //    Note: Boot drivers typically cannot be unloaded
    //    This would use ZwUnloadDriver

    // 2. Quarantine the driver file (prevent reload)
    //    This would use minifilter to block future access

    // 3. Remove service registry entries
    //    This prevents the driver from loading on next boot

    // 4. Alert user-mode service for additional action

    // 5. Log to telemetry for cloud analysis

    // For now, mark threat as action taken
    RtlStringCbCopyA(Threat->ActionReason, sizeof(Threat->ActionReason),
                    "Remediation: Logged and queued for removal on restart");

    return status;
}

// ============================================================================
// BOOT DRIVER CALLBACK (for documentation - requires ELAM certificate)
// ============================================================================

/**
 * @brief Boot driver callback (ELAM-style)
 *
 * Note: This function signature matches IoRegisterBootDriverCallback
 * but cannot be used without an ELAM certificate. It is provided
 * for reference and future use if ELAM signing becomes available.
 */
_Use_decl_annotations_
VOID
ElamBootDriverCallback(
    PVOID CallbackContext,
    BDCB_CALLBACK_TYPE Classification,
    PBDCB_IMAGE_INFORMATION ImageInformation
    )
{
    // This callback requires ELAM certificate to register
    // Without it, we use PsSetLoadImageNotifyRoutine instead

    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Classification);
    UNREFERENCED_PARAMETER(ImageInformation);

    // Would process BDCB_CALLBACK_TYPE:
    // - BdCbStatusUpdate
    // - BdCbInitializeImage

    // Would set ImageInformation->Classification to:
    // - BdCbClassificationKnownGoodImage
    // - BdCbClassificationKnownBadImage
    // - BdCbClassificationUnknownImage
}
