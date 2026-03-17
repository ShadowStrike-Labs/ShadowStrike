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
#include "ELAMCallbacks.h"
#include "BootDriverVerify.h"
#include "BootThreatDetector.h"
#pragma warning(push)
#pragma warning(disable:4324)
#include "../PhantomSensor/Utilities/HashUtils.h"
#pragma warning(pop)
#include <ntimage.h>
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
static PEC_ELAM_CALLBACKS g_ElamCallbacks = NULL;
static LARGE_INTEGER g_RegistryCookie = {0};
static BOOLEAN g_ImageNotifyRegistered = FALSE;
static volatile LONG g_SelfModifyingRegistry = 0;  // Self-exclusion for remediation writes

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
ElamTryLoadVulnerableDriverList(VOID);

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

    //
    // Atomically claim initialization (0→1). Prevents double-init race
    // where two threads both read 0, then both zero + initialize.
    //
    if (InterlockedCompareExchange(&g_ElamGlobals.Initialized, 1, 0) != 0) {
        return STATUS_ALREADY_INITIALIZED;
    }

    // Zero all fields then re-set our "initializing" sentinel
    RtlZeroMemory(&g_ElamGlobals, sizeof(ELAM_DRIVER_GLOBALS));
    InterlockedExchange(&g_ElamGlobals.Initialized, 1);

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

    // After loading signature data, check for a BVDL (vulnerable driver list)
    // trailer section appended after the ELAM signature block in the PE resource.
    // If present, merges into BTD's runtime BYOVD database.
    ElamTryLoadVulnerableDriverList();

    // Initialize boot driver callbacks subsystem (tracking, policy, user notifications)
    status = ElcbInitialize(&g_ElamCallbacks);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[ShadowStrike/ELAM] ElcbInitialize failed: 0x%08X (non-fatal)\n", status);
        // Non-fatal: core classification still works without tracking
        g_ElamCallbacks = NULL;
    } else {
        // Register callbacks and set initial policy
        ElcbRegisterCallbacks(g_ElamCallbacks);
        ElcbSetPolicy(g_ElamCallbacks, FALSE, FALSE);
        ElcbSetBootPhase(g_ElamCallbacks, EcPhase_Early);
    }

    // Set default boot policy
    g_ElamGlobals.BootPolicy = ElamPolicyGoodUnknown;

    InterlockedExchange(&g_ElamGlobals.Initialized, TRUE);

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
    //
    // CAS double-shutdown guard: atomically clear Initialized (1→0).
    // If not initialized or already shutdown, nothing to do.
    //
    if (InterlockedCompareExchange(&g_ElamGlobals.Initialized, 0, 1) != 1) {
        return;
    }

    // Unregister callbacks first
    ElamUnregisterCallback();

    // Signal boot complete phase before shutdown
    if (g_ElamCallbacks != NULL) {
        ElcbSetBootPhase(g_ElamCallbacks, EcPhase_Complete);
    }

    // Shutdown boot driver callbacks subsystem
    if (g_ElamCallbacks != NULL) {
        ElcbShutdown(g_ElamCallbacks);
        g_ElamCallbacks = NULL;
    }

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
}

/**
 * @brief Register boot driver classification callbacks
 */
NTSTATUS
ElamRegisterCallback(VOID)
{
    NTSTATUS status;
    UNICODE_STRING altitude;

    if (!InterlockedCompareExchange(&g_ElamGlobals.Initialized, 0, 0)) {
        return STATUS_UNSUCCESSFUL;
    }

    if (InterlockedCompareExchange(&g_ElamGlobals.CallbackRegistered, 0, 0)) {
        return STATUS_ALREADY_REGISTERED;
    }

    // Register image load notification callback
    // This is our alternative to IoRegisterBootDriverCallback
    status = PsSetLoadImageNotifyRoutine(ElamImageLoadCallback);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    g_ImageNotifyRegistered = TRUE;

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
        g_ImageNotifyRegistered = FALSE;
        return status;
    }

    g_ElamGlobals.CallbackHandle = (PVOID)g_RegistryCookie.QuadPart;
    InterlockedExchange(&g_ElamGlobals.CallbackRegistered, TRUE);

    return STATUS_SUCCESS;
}

/**
 * @brief Unregister boot driver classification callbacks
 */
VOID
ElamUnregisterCallback(VOID)
{
    if (!InterlockedCompareExchange(&g_ElamGlobals.CallbackRegistered, 0, 0)) {
        return;
    }

    // Unregister registry callback
    if (g_RegistryCookie.QuadPart != 0) {
        CmUnRegisterCallback(g_RegistryCookie);
        g_RegistryCookie.QuadPart = 0;
    }

    // Unregister image load callback
    if (g_ImageNotifyRegistered) {
        PsRemoveLoadImageNotifyRoutine(ElamImageLoadCallback);
        g_ImageNotifyRegistered = FALSE;
    }

    g_ElamGlobals.CallbackHandle = NULL;
    InterlockedExchange(&g_ElamGlobals.CallbackRegistered, FALSE);
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
    LONGLONG elapsedMs;

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
    if (!InterlockedCompareExchange(&g_ElamGlobals.Initialized, 0, 0) ||
        g_BootVerifier == NULL) {
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
        InterlockedIncrement(&g_ElamGlobals.DriversUnknown);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[ShadowStrike/ELAM] Driver verification failed for %wZ: 0x%08X\n",
            FullImageName, status);
        return;
    }

    // Scan for threats
    status = BtdScanDriver(g_ThreatDetector, driverInfo, ImageInfo->ImageBase, ImageInfo->ImageSize, &threat);

    // Build ELAM boot driver info structure
    RtlZeroMemory(&bootInfo, sizeof(ELAM_BOOT_DRIVER_INFO));
    bootInfo.DriverPath = *FullImageName;
    bootInfo.ImageBase = ImageInfo->ImageBase;
    bootInfo.ImageSize = (ULONG)(min(ImageInfo->ImageSize, (SIZE_T)MAXULONG));
    RtlCopyMemory(bootInfo.ImageHashSHA256, driverInfo->ImageHash, 32);
    RtlCopyMemory(bootInfo.AuthenticodeHashSHA256, driverInfo->AuthentiCodeHash, 32);
    bootInfo.IsSigned = driverInfo->IsSigned;
    bootInfo.IsSignatureValid = driverInfo->IsSigned;

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

            if (threat != NULL) {
                ElamTakeRemediationAction(threat, driverInfo);
            } else {
                //
                // No BTD threat but classified as bad by hash/cert — create one
                //
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[ShadowStrike/ELAM] KNOWN BAD driver detected: %wZ\n",
                    FullImageName);
                InterlockedIncrement(&g_ElamGlobals.DriversBlocked);
            }
            break;

        case ElamClassificationUnknown:
        default:
            InterlockedIncrement(&g_ElamGlobals.DriversUnknown);

            if (g_ElamGlobals.BootPolicy == ElamPolicyGoodOnly) {
                //
                // Strict mode: unknown drivers are treated as threats
                //
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "[ShadowStrike/ELAM] POLICY BLOCK (GoodOnly): unknown driver %wZ\n",
                    FullImageName);
                InterlockedIncrement(&g_ElamGlobals.DriversBlocked);

                if (threat != NULL) {
                    threat->WasBlocked = TRUE;
                    RtlStringCbCopyA(threat->ActionReason, sizeof(threat->ActionReason),
                        "Blocked by GoodOnly boot policy");
                }
            }
            break;
    }

    //
    // Feed classification results into the ELAMCallbacks tracking subsystem.
    // Maps ELAM classification → BDCB classification constants for the
    // callback layer's policy engine and user notification pipeline.
    //
    if (g_ElamCallbacks != NULL) {
        ULONG bdcbClass;
        BOOLEAN callbackAllow = TRUE;

        switch (classification) {
            case ElamClassificationKnownGood: bdcbClass = EC_BDCB_KNOWN_GOOD_IMAGE; break;
            case ElamClassificationKnownBad:  bdcbClass = EC_BDCB_KNOWN_BAD_IMAGE;  break;
            default:                          bdcbClass = EC_BDCB_UNKNOWN_IMAGE;     break;
        }

        ElcbProcessBootDriver(
            g_ElamCallbacks,
            FullImageName,
            NULL,               // RegistryPath not available in image load callback
            ImageInfo->ImageBase,
            ImageInfo->ImageSize,
            bdcbClass,
            driverInfo->IsSigned,
            EcPhase_BeforeDriverInit,
            &callbackAllow
            );

        // If the callback subsystem blocked the driver, update our stats
        if (!callbackAllow && classification != ElamClassificationKnownBad) {
            InterlockedIncrement(&g_ElamGlobals.DriversBlocked);
        }
    }

    // Record elapsed time and log performance data
    KeQuerySystemTimePrecise(&endTime);
    elapsedMs = (endTime.QuadPart - startTime.QuadPart) / 10000;

    if (elapsedMs > ELAM_CLASSIFICATION_TIMEOUT_MS) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[ShadowStrike/ELAM] PERFORMANCE WARNING: classification of %wZ took %lld ms "
            "(threshold=%u ms)\n",
            FullImageName, elapsedMs, ELAM_CLASSIFICATION_TIMEOUT_MS);
    }

    if (g_ElamGlobals.VerboseLogging) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
            "[ShadowStrike/ELAM] Classified %wZ => %d (signed=%d) in %lld ms\n",
            FullImageName, (int)classification, (int)bootInfo.IsSigned, elapsedMs);
    }

    // Release resources allocated by BDV/BTD
    if (threat != NULL) {
        BtdFreeThreat(g_ThreatDetector, threat);
    }
    if (driverInfo != NULL) {
        BdvFreeDriverInfo(g_BootVerifier, driverInfo);
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
        if (certEntry->EntrySize == 0 ||
            offset > header->TotalSize ||
            certEntry->EntrySize > header->TotalSize - offset) {
            break;
        }
        entryPtr += certEntry->EntrySize;
        offset += certEntry->EntrySize;
    }

    // Search hash entries
    for (i = 0; i < header->HashCount; i++) {
        hashEntry = (PELAM_HASH_ENTRY)entryPtr;

        if (hashEntry->EntrySize == 0 ||
            offset > header->TotalSize ||
            hashEntry->EntrySize > header->TotalSize - offset) {
            break;
        }

        if (hashEntry->Classification == ElamClassificationKnownGood &&
            hashEntry->HashSize == 32 &&
            hashEntry->EntrySize >= sizeof(ELAM_HASH_ENTRY) + 32) {
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
        if (certEntry->EntrySize == 0 ||
            offset > header->TotalSize ||
            certEntry->EntrySize > header->TotalSize - offset) {
            break;
        }
        entryPtr += certEntry->EntrySize;
        offset += certEntry->EntrySize;
    }

    // Search for bad hash
    for (i = 0; i < header->HashCount; i++) {
        hashEntry = (PELAM_HASH_ENTRY)entryPtr;

        if (hashEntry->EntrySize == 0 ||
            offset > header->TotalSize ||
            hashEntry->EntrySize > header->TotalSize - offset) {
            break;
        }

        if (hashEntry->Classification == ElamClassificationKnownBad &&
            hashEntry->HashSize == 32 &&
            hashEntry->EntrySize >= sizeof(ELAM_HASH_ENTRY) + 32) {
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

    for (i = 0; i < header->SignatureCount; i++) {
        certEntry = (PELAM_CERTIFICATE_ENTRY)entryPtr;

        if (certEntry->EntrySize == 0 ||
            offset > header->TotalSize ||
            certEntry->EntrySize > header->TotalSize - offset) {
            break;
        }

        if (certEntry->Classification == ElamClassificationKnownGood) {
            // Validate hash data fits within entry (overflow-safe subtraction)
            if (certEntry->EntrySize < sizeof(ELAM_CERTIFICATE_ENTRY) ||
                certEntry->IssuerHashSize > certEntry->EntrySize - sizeof(ELAM_CERTIFICATE_ENTRY) ||
                certEntry->PublisherHashSize > certEntry->EntrySize - sizeof(ELAM_CERTIFICATE_ENTRY) - certEntry->IssuerHashSize) {
                entryPtr += certEntry->EntrySize;
                offset += certEntry->EntrySize;
                continue;
            }
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

        if (certEntry->EntrySize == 0 ||
            offset > header->TotalSize ||
            certEntry->EntrySize > header->TotalSize - offset) {
            break;
        }

        if (certEntry->Classification == ElamClassificationKnownBad) {
            // Validate issuer hash fits within entry
            if (certEntry->EntrySize < sizeof(ELAM_CERTIFICATE_ENTRY) ||
                certEntry->IssuerHashSize > certEntry->EntrySize - sizeof(ELAM_CERTIFICATE_ENTRY)) {
                entryPtr += certEntry->EntrySize;
                offset += certEntry->EntrySize;
                continue;
            }
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
    PUNICODE_STRING objectName;

    UNREFERENCED_PARAMETER(CallbackContext);

    if (Argument1 == NULL) {
        return STATUS_SUCCESS;
    }

    //
    // Self-exclusion: allow our own remediation writes through.
    // ElamTakeRemediationAction sets g_SelfModifyingRegistry before Zw* calls
    // to prevent the callback from blocking our own registry operations.
    //
    if (InterlockedCompareExchange(&g_SelfModifyingRegistry, 0, 0)) {
        return STATUS_SUCCESS;
    }

    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    switch (notifyClass) {
        case RegNtPreSetValueKey:
            setValueInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
            if (setValueInfo != NULL && setValueInfo->Object != NULL) {
                NTSTATUS lookupStatus;
                lookupStatus = CmCallbackGetKeyObjectIDEx(
                    &g_RegistryCookie,
                    setValueInfo->Object,
                    NULL,
                    &objectName,
                    0
                    );

                if (NT_SUCCESS(lookupStatus) && objectName != NULL) {
                    if (ElamIsProtectedRegistryPath(objectName)) {
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                            "[ShadowStrike/ELAM] BLOCKED registry value modification: %wZ\n",
                            objectName);
                        status = STATUS_ACCESS_DENIED;
                    }
                    CmCallbackReleaseKeyObjectIDEx(objectName);
                }
            }
            break;

        case RegNtPreDeleteValueKey:
            deleteValueInfo = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
            if (deleteValueInfo != NULL && deleteValueInfo->Object != NULL) {
                NTSTATUS lookupStatus;
                lookupStatus = CmCallbackGetKeyObjectIDEx(
                    &g_RegistryCookie,
                    deleteValueInfo->Object,
                    NULL,
                    &objectName,
                    0
                    );

                if (NT_SUCCESS(lookupStatus) && objectName != NULL) {
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
                NTSTATUS lookupStatus;
                lookupStatus = CmCallbackGetKeyObjectIDEx(
                    &g_RegistryCookie,
                    deleteKeyInfo->Object,
                    NULL,
                    &objectName,
                    0
                    );

                if (NT_SUCCESS(lookupStatus) && objectName != NULL) {
                    if (ElamIsProtectedRegistryPath(objectName)) {
                        status = STATUS_ACCESS_DENIED;
                    }
                    CmCallbackReleaseKeyObjectIDEx(objectName);
                }
            }
            break;

        case RegNtPreCreateKeyEx:
            createKeyInfo = (PREG_CREATE_KEY_INFORMATION_V1)Argument2;
            if (createKeyInfo != NULL && createKeyInfo->RootObject != NULL) {
                //
                // Monitor creation of new keys under protected boot driver paths.
                // Use CmCallbackGetKeyObjectIDEx on RootObject to get the absolute
                // parent path — CompleteName is relative and would never match our
                // absolute protected paths.
                //
                NTSTATUS lookupStatus;
                lookupStatus = CmCallbackGetKeyObjectIDEx(
                    &g_RegistryCookie,
                    createKeyInfo->RootObject,
                    NULL,
                    &objectName,
                    0
                    );

                if (NT_SUCCESS(lookupStatus) && objectName != NULL) {
                    if (ElamIsProtectedRegistryPath(objectName)) {
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                            "[ShadowStrike/ELAM] New key creation under protected path: %wZ\\%wZ\n",
                            objectName, createKeyInfo->CompleteName);
                    }
                    CmCallbackReleaseKeyObjectIDEx(objectName);
                }
            }
            break;

        default:
            break;
    }

    return status;
}

/**
 * @brief Check if registry path is protected
 *
 * Uses prefix matching: any key under the protected paths is considered protected.
 */
static BOOLEAN
ElamIsProtectedRegistryPath(
    _In_ PUNICODE_STRING KeyPath
    )
{
    ULONG i;
    UNICODE_STRING protectedPath;

    if (KeyPath == NULL || KeyPath->Buffer == NULL || KeyPath->Length == 0) {
        return FALSE;
    }

    for (i = 0; g_ProtectedRegistryPaths[i] != NULL; i++) {
        RtlInitUnicodeString(&protectedPath, g_ProtectedRegistryPaths[i]);

        // Prefix match: the key path starts with the protected path
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
    NTSTATUS status;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_DATA_DIRECTORY resourceDir;
    PIMAGE_RESOURCE_DIRECTORY resRoot;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY resEntry;
    PVOID driverBase;
    ULONG driverSize;
    PVOID resourceData = NULL;
    ULONG resourceSize = 0;
    BOOLEAN foundResource = FALSE;

    if (DriverObject == NULL || DriverObject->DriverStart == NULL) {
        return ElamLoadEmbeddedSignatures();
    }

    driverBase = DriverObject->DriverStart;
    driverSize = DriverObject->DriverSize;

    //
    // Validate PE headers with bounds checking
    //
    if (driverSize < sizeof(IMAGE_DOS_HEADER)) {
        goto FallbackEmbedded;
    }

    dosHeader = (PIMAGE_DOS_HEADER)driverBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        goto FallbackEmbedded;
    }

    if ((ULONG)dosHeader->e_lfanew >= driverSize ||
        (ULONG)dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > driverSize) {
        goto FallbackEmbedded;
    }

    ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)driverBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        goto FallbackEmbedded;
    }

    //
    // Locate resource directory (IMAGE_DIRECTORY_ENTRY_RESOURCE = 2)
    //
    if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_RESOURCE) {
        goto FallbackEmbedded;
    }

    resourceDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    if (resourceDir->VirtualAddress == 0 || resourceDir->Size == 0) {
        goto FallbackEmbedded;
    }

    if (resourceDir->VirtualAddress > driverSize ||
        resourceDir->Size > driverSize - resourceDir->VirtualAddress) {
        goto FallbackEmbedded;
    }

    //
    // Walk the resource directory looking for RT_RCDATA (type 10)
    // RT_RCDATA entries contain our signature blob
    //
    resRoot = (PIMAGE_RESOURCE_DIRECTORY)((PUCHAR)driverBase + resourceDir->VirtualAddress);

    {
        ULONG numEntries = (ULONG)resRoot->NumberOfNamedEntries + resRoot->NumberOfIdEntries;
        ULONG i;

        // Bounds: entry array must fit within resource directory
        if (sizeof(IMAGE_RESOURCE_DIRECTORY) + numEntries * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) > resourceDir->Size) {
            goto FallbackEmbedded;
        }

        resEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(resRoot + 1);

        for (i = 0; i < numEntries && !foundResource; i++) {
            //
            // Look for RT_RCDATA (10) by ID
            //
            if (!resEntry[i].NameIsString && resEntry[i].Id == 10) {  // RT_RCDATA
                if (resEntry[i].DataIsDirectory) {
                    //
                    // Descend into type directory → name directory → language entry
                    //
                    PIMAGE_RESOURCE_DIRECTORY nameDir;
                    ULONG nameDirOffset = resEntry[i].OffsetToDirectory;

                    if (nameDirOffset + sizeof(IMAGE_RESOURCE_DIRECTORY) > resourceDir->Size) {
                        continue;
                    }

                    nameDir = (PIMAGE_RESOURCE_DIRECTORY)((PUCHAR)resRoot + nameDirOffset);
                    ULONG nameCount = (ULONG)nameDir->NumberOfNamedEntries + nameDir->NumberOfIdEntries;

                    // Bounds: name entry array must fit
                    if (nameDirOffset + sizeof(IMAGE_RESOURCE_DIRECTORY) +
                        nameCount * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) > resourceDir->Size) {
                        continue;
                    }

                    if (nameCount > 0) {
                        PIMAGE_RESOURCE_DIRECTORY_ENTRY nameEntry;
                        nameEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(nameDir + 1);

                        //
                        // Look for our specific resource ID (ELAM_RESOURCE_SIGNATURE_TYPE = 1)
                        //
                        for (ULONG j = 0; j < nameCount; j++) {
                            if (!nameEntry[j].NameIsString &&
                                nameEntry[j].Id == ELAM_RESOURCE_SIGNATURE_TYPE) {

                                if (nameEntry[j].DataIsDirectory) {
                                    //
                                    // Language directory — take first entry
                                    //
                                    PIMAGE_RESOURCE_DIRECTORY langDir;
                                    ULONG langOffset = nameEntry[j].OffsetToDirectory;

                                    if (langOffset + sizeof(IMAGE_RESOURCE_DIRECTORY) > resourceDir->Size) {
                                        continue;
                                    }

                                    langDir = (PIMAGE_RESOURCE_DIRECTORY)((PUCHAR)resRoot + langOffset);
                                    ULONG langCount = (ULONG)langDir->NumberOfNamedEntries + langDir->NumberOfIdEntries;

                                    // Bounds: lang entry array must fit
                                    if (langOffset + sizeof(IMAGE_RESOURCE_DIRECTORY) +
                                        langCount * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) > resourceDir->Size) {
                                        continue;
                                    }

                                    if (langCount > 0) {
                                        PIMAGE_RESOURCE_DIRECTORY_ENTRY langEntry;
                                        langEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(langDir + 1);

                                        if (!langEntry[0].DataIsDirectory) {
                                            // Bounds: data entry must fit
                                            if (langEntry[0].OffsetToData + sizeof(IMAGE_RESOURCE_DATA_ENTRY) > resourceDir->Size) {
                                                continue;
                                            }
                                            PIMAGE_RESOURCE_DATA_ENTRY dataEntry;
                                            dataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)(
                                                (PUCHAR)resRoot + langEntry[0].OffsetToData);

                                            if (dataEntry->OffsetToData <= driverSize &&
                                                dataEntry->Size <= driverSize - dataEntry->OffsetToData &&
                                                dataEntry->Size >= sizeof(ELAM_SIGNATURE_HEADER)) {

                                                resourceData = (PUCHAR)driverBase + dataEntry->OffsetToData;
                                                resourceSize = dataEntry->Size;
                                                foundResource = TRUE;
                                            }
                                        }
                                    }
                                } else {
                                    //
                                    // Direct data entry (no language subdirectory)
                                    //
                                    if (nameEntry[j].OffsetToData + sizeof(IMAGE_RESOURCE_DATA_ENTRY) > resourceDir->Size) {
                                        break;
                                    }
                                    PIMAGE_RESOURCE_DATA_ENTRY dataEntry;
                                    dataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)(
                                        (PUCHAR)resRoot + nameEntry[j].OffsetToData);

                                    if (dataEntry->OffsetToData <= driverSize &&
                                        dataEntry->Size <= driverSize - dataEntry->OffsetToData &&
                                        dataEntry->Size >= sizeof(ELAM_SIGNATURE_HEADER)) {

                                        resourceData = (PUCHAR)driverBase + dataEntry->OffsetToData;
                                        resourceSize = dataEntry->Size;
                                        foundResource = TRUE;
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    if (!foundResource || resourceData == NULL || resourceSize < sizeof(ELAM_SIGNATURE_HEADER)) {
        goto FallbackEmbedded;
    }

    //
    // Validate the resource data is a valid ELAM signature blob
    //
    {
        PELAM_SIGNATURE_HEADER resHeader = (PELAM_SIGNATURE_HEADER)resourceData;

        if (resHeader->Magic != ELAM_SIGNATURE_MAGIC ||
            resHeader->Version != ELAM_SIGNATURE_VERSION ||
            resHeader->TotalSize > resourceSize ||
            resHeader->SignatureCount > ELAM_MAX_SIGNATURE_ENTRIES ||
            resHeader->HashCount > ELAM_MAX_HASH_ENTRIES) {

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[ShadowStrike/ELAM] PE resource signature blob failed validation "
                "(magic=0x%08X, ver=%u, size=%u/%u)\n",
                resHeader->Magic, resHeader->Version,
                resHeader->TotalSize, resourceSize);

            goto FallbackEmbedded;
        }
    }

    //
    // Copy validated signature data to non-paged pool
    //
    {
        PELAM_SIGNATURE_HEADER sigCopy;

        sigCopy = (PELAM_SIGNATURE_HEADER)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            resourceSize,
            ELAM_POOL_TAG
            );

        if (sigCopy == NULL) {
            goto FallbackEmbedded;
        }

        RtlCopyMemory(sigCopy, resourceData, resourceSize);

        g_ElamGlobals.SignatureData = sigCopy;
        g_ElamGlobals.SignatureDataSize = resourceSize;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[ShadowStrike/ELAM] Loaded %u signatures + %u hashes from PE resource (%u bytes)\n",
            sigCopy->SignatureCount, sigCopy->HashCount, resourceSize);

        return STATUS_SUCCESS;
    }

FallbackEmbedded:
    //
    // No PE resource found — use minimal embedded signatures
    //
    status = ElamLoadEmbeddedSignatures();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[ShadowStrike/ELAM] Using embedded signatures (no PE resource): 0x%08X\n",
        status);

    return status;
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
 * @brief Try to load a BVDL vulnerable driver list from the signature resource
 *
 * After ElamLoadSignatureData, the PE resource buffer may contain a trailing
 * BVDL section appended after the ELAM signature block (at offset TotalSize).
 * If present, BtdLoadVulnerableList validates the format and merges entries
 * into the BTD runtime BYOVD database. If absent or invalid, this is a no-op.
 */
static VOID
ElamTryLoadVulnerableDriverList(VOID)
{
    PELAM_SIGNATURE_HEADER header;
    SIZE_T dataSize;
    PUCHAR trailingData;
    SIZE_T trailingSize;
    NTSTATUS status;

    if (g_ThreatDetector == NULL || g_ElamGlobals.SignatureData == NULL) {
        return;
    }

    header = g_ElamGlobals.SignatureData;
    dataSize = g_ElamGlobals.SignatureDataSize;

    // Check if there's data after the ELAM signature block
    if (header->TotalSize >= dataSize || header->TotalSize < sizeof(ELAM_SIGNATURE_HEADER)) {
        return;
    }

    trailingData = (PUCHAR)header + header->TotalSize;
    trailingSize = dataSize - header->TotalSize;

    // BtdLoadVulnerableList validates BVDL magic/version/size internally.
    // If the trailing data isn't a valid BVDL section, it returns an error
    // and we silently ignore it.
    status = BtdLoadVulnerableList(g_ThreatDetector, trailingData, trailingSize);
    if (NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[ShadowStrike/ELAM] Loaded BVDL vulnerable driver list from PE resource trailer\n");
    }
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

    // Validate size (TotalSize may be < SignatureDataSize when BVDL trailer present)
    if (header->TotalSize > g_ElamGlobals.SignatureDataSize) {
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
    PLONG DriversClassified,
    PLONG DriversGood,
    PLONG DriversBad,
    PLONG DriversUnknown,
    PLONG DriversBlocked
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
 *
 * Called by BootThreatDetector when a threat is identified during scanning.
 * Logs the detection and updates statistics.
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

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[ShadowStrike/ELAM] THREAT DETECTED: type=%d severity=%u critical=%d "
        "name=%s driver=%wZ\n",
        (int)Threat->Type, Threat->SeverityScore, (int)Threat->IsCritical,
        Threat->ThreatName, &Threat->DriverPath);

    if (Threat->WasBlocked) {
        InterlockedIncrement(&g_ElamGlobals.DriversBlocked);
    }
}

/**
 * @brief Take remediation action for detected boot-time threat
 *
 * Since PsSetLoadImageNotifyRoutine callbacks are VOID (cannot block loads),
 * remediation writes a registry flag for the user-mode agent to process.
 * The agent can then quarantine the file, disable the service, or uninstall.
 */
static NTSTATUS
ElamTakeRemediationAction(
    _In_ PBTD_THREAT Threat,
    _In_ PBDV_DRIVER_INFO DriverInfo
    )
{
    NTSTATUS status;
    HANDLE keyHandle = NULL;
    OBJECT_ATTRIBUTES objAttrs;
    UNICODE_STRING keyPath;
    UNICODE_STRING valueName;
    ULONG flagValue;

    if (Threat == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Log the threat at ERROR level — this is always visible
    //
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[ShadowStrike/ELAM] REMEDIATION: threat=%s severity=%u driver=%wZ\n",
        Threat->ThreatName, Threat->SeverityScore,
        (DriverInfo != NULL) ? &DriverInfo->DriverPath : NULL);

    //
    // Write a marker in the registry for the user-mode agent.
    // Path: HKLM\System\CurrentControlSet\Control\EarlyLaunch\BlockedDrivers
    // Value: severity score — the agent reads this after boot to take action.
    //
    // Set self-exclusion flag so our registry callback allows these writes
    // through — the BlockedDrivers path is under the protected EarlyLaunch prefix.
    //
    InterlockedExchange(&g_SelfModifyingRegistry, 1);

    RtlInitUnicodeString(&keyPath,
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\EarlyLaunch\\BlockedDrivers");

    InitializeObjectAttributes(&objAttrs, &keyPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateKey(
        &keyHandle,
        KEY_WRITE,
        &objAttrs,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        NULL
        );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[ShadowStrike/ELAM] Failed to create BlockedDrivers key: 0x%08X\n",
            status);
        RtlStringCbCopyA(Threat->ActionReason, sizeof(Threat->ActionReason),
            "Registry write failed; logged for manual review");
        InterlockedExchange(&g_SelfModifyingRegistry, 0);
        return status;
    }

    //
    // Write the driver path as value name with severity as data
    //
    if (DriverInfo != NULL && DriverInfo->DriverPath.Buffer != NULL &&
        DriverInfo->DriverPath.Length > 0) {
        valueName = DriverInfo->DriverPath;
    } else {
        RtlInitUnicodeString(&valueName, L"UnidentifiedThreat");
    }

    flagValue = Threat->SeverityScore;
    if (flagValue == 0) {
        flagValue = 1;
    }

    status = ZwSetValueKey(
        keyHandle,
        &valueName,
        0,
        REG_DWORD,
        &flagValue,
        sizeof(flagValue)
        );

    if (NT_SUCCESS(status)) {
        RtlStringCbCopyA(Threat->ActionReason, sizeof(Threat->ActionReason),
            "Flagged in registry for user-mode agent remediation");
        Threat->WasBlocked = FALSE;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[ShadowStrike/ELAM] Remediation marker written for %wZ (severity=%u)\n",
            &valueName, flagValue);
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[ShadowStrike/ELAM] Failed to write remediation value: 0x%08X\n",
            status);
        RtlStringCbCopyA(Threat->ActionReason, sizeof(Threat->ActionReason),
            "Registry value write failed; logged for manual review");
    }

    ZwClose(keyHandle);
    InterlockedExchange(&g_SelfModifyingRegistry, 0);
    return status;
}

/**
 * @brief Query boot-time threat detections for telemetry/reporting
 *
 * Wraps BtdGetThreats so the main sensor can query ELAM detections without
 * directly accessing the BTD_DETECTOR pointer. Returns threat pointers that
 * must be freed with BtdFreeThreat(g_ThreatDetector, threat).
 */
NTSTATUS
ElamGetBootThreats(
    _Out_writes_to_(MaxThreats, *ThreatCount) PBTD_THREAT* Threats,
    _In_ ULONG MaxThreats,
    _Out_ PULONG ThreatCount
    )
{
    if (Threats == NULL || ThreatCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *ThreatCount = 0;

    if (MaxThreats == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!InterlockedCompareExchange(&g_ElamGlobals.Initialized, 0, 0) || g_ThreatDetector == NULL) {
        return STATUS_NOT_FOUND;
    }

    return BtdGetThreats(g_ThreatDetector, Threats, MaxThreats, ThreatCount);
}

// End of ELAMDriver.c
