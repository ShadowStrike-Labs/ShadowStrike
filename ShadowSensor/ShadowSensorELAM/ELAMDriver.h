/**
 * ============================================================================
 * ShadowStrike NGAV - ELAM DRIVER
 * ============================================================================
 *
 * @file ELAMDriver.h
 * @brief Early Launch Anti-Malware (ELAM) driver header.
 *
 * The ELAM driver starts early in the boot process (before other 
 * third-party drivers) to classify boot-start drivers as:
 * - Good (known safe)
 * - Bad (known malicious)
 * - Unknown
 *
 * This provides boot-time protection against bootkits and rootkits.
 *
 * Requirements:
 * - Must be signed with a Microsoft ELAM certificate
 * - Must have a resource section with known-good/bad signature data
 * - Must be registered in the system's ELAM configuration
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma once

#include <ntddk.h>
#include <wdm.h>

// ============================================================================
// ELAM CONFIGURATION
// ============================================================================

/**
 * @brief ELAM driver pool tag.
 */
#define ELAM_POOL_TAG                   'malE'

/**
 * @brief ELAM registry configuration path.
 */
#define ELAM_REGISTRY_PATH              L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\EarlyLaunch"
#define ELAM_MEASURED_BOOT_PATH         L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\MeasuredBoot"

/**
 * @brief ELAM signature resource IDs.
 */
#define ELAM_HASH_ALGORITHM_SHA256      0x800C  // ALG_ID for SHA-256
#define ELAM_RESOURCE_SIGNATURE_TYPE    1       // Custom signature resource
#define ELAM_RESOURCE_HASH_TYPE         2       // Hash resource

/**
 * @brief Maximum signature entries.
 */
#define ELAM_MAX_SIGNATURE_ENTRIES      10000
#define ELAM_MAX_HASH_ENTRIES           100000

// ============================================================================
// ELAM CLASSIFICATION
// ============================================================================

/**
 * @brief ELAM driver classification.
 * These values are defined by Windows and must match exactly.
 */
typedef enum _ELAM_DRIVER_CLASSIFICATION {
    ElamClassificationUnknown = 0,        // Driver is unknown
    ElamClassificationKnownGood = 1,      // Driver is known to be good
    ElamClassificationKnownBad = 2,       // Driver is known to be malicious
    ElamClassificationMax
} ELAM_DRIVER_CLASSIFICATION;

/**
 * @brief ELAM measured boot policy.
 */
typedef enum _ELAM_BOOT_POLICY {
    ElamPolicyDefault = 0,                // Follow system policy
    ElamPolicyGoodOnly = 1,               // Allow only known good
    ElamPolicyGoodUnknown = 2,            // Allow good and unknown
    ElamPolicyAll = 3                     // Allow all (logging only)
} ELAM_BOOT_POLICY;

// ============================================================================
// ELAM SIGNATURE STRUCTURES
// ============================================================================

#pragma pack(push, 1)

/**
 * @brief ELAM signature header.
 */
typedef struct _ELAM_SIGNATURE_HEADER {
    UINT32 Magic;                         // 'ELAM'
    UINT32 Version;
    UINT32 SignatureCount;
    UINT32 HashCount;
    UINT32 TotalSize;
    UINT32 Reserved;
    // Variable: Signatures follow
    // Variable: Hashes follow
} ELAM_SIGNATURE_HEADER, *PELAM_SIGNATURE_HEADER;

#define ELAM_SIGNATURE_MAGIC            0x4D414C45  // 'ELAM'
#define ELAM_SIGNATURE_VERSION          1

/**
 * @brief ELAM certificate signature entry.
 */
typedef struct _ELAM_CERTIFICATE_ENTRY {
    UINT32 EntrySize;                     // Total entry size
    UINT32 Flags;
    ELAM_DRIVER_CLASSIFICATION Classification;
    UINT32 IssuerHashSize;                // Size of issuer hash
    UINT32 PublisherHashSize;             // Size of publisher hash
    // UINT8 IssuerHash[IssuerHashSize]
    // UINT8 PublisherHash[PublisherHashSize]
} ELAM_CERTIFICATE_ENTRY, *PELAM_CERTIFICATE_ENTRY;

// Certificate entry flags
#define ELAM_CERT_FLAG_EXACT_MATCH        0x00000001
#define ELAM_CERT_FLAG_ISSUER_ONLY        0x00000002
#define ELAM_CERT_FLAG_PUBLISHER_ONLY     0x00000004
#define ELAM_CERT_FLAG_KNOWN_ROOT         0x00000008

/**
 * @brief ELAM file hash entry.
 */
typedef struct _ELAM_HASH_ENTRY {
    UINT32 EntrySize;                     // Total entry size
    UINT32 Flags;
    ELAM_DRIVER_CLASSIFICATION Classification;
    UINT32 HashAlgorithm;                 // ELAM_HASH_ALGORITHM_*
    UINT32 HashSize;                      // 32 for SHA-256
    // UINT8 FileHash[HashSize]
} ELAM_HASH_ENTRY, *PELAM_HASH_ENTRY;

// Hash entry flags
#define ELAM_HASH_FLAG_AUTHENTICODE       0x00000001  // Authenticode hash
#define ELAM_HASH_FLAG_FLAT_FILE          0x00000002  // Flat file hash
#define ELAM_HASH_FLAG_PAGE_HASH          0x00000004  // Page hash

#pragma pack(pop)

// ============================================================================
// ELAM CALLBACK STRUCTURES
// ============================================================================

/**
 * @brief Information about a boot driver being classified.
 */
typedef struct _ELAM_BOOT_DRIVER_INFO {
    // Driver identification
    UNICODE_STRING DriverPath;
    UNICODE_STRING DriverRegistryPath;
    UNICODE_STRING DriverServiceName;
    
    // Image information
    PVOID ImageBase;
    ULONG ImageSize;
    UINT8 ImageHashSHA256[32];
    UINT8 AuthenticodeHashSHA256[32];
    
    // Certificate information
    BOOLEAN IsSigned;
    BOOLEAN IsSignatureValid;
    BOOLEAN IsMicrosoftSigned;
    BOOLEAN IsWHQLSigned;
    UINT8 IssuerHash[32];
    UINT8 PublisherHash[32];
    
    // Classification result
    ELAM_DRIVER_CLASSIFICATION Classification;
    UINT32 ClassificationReason;
    
    // Flags
    UINT32 Flags;
} ELAM_BOOT_DRIVER_INFO, *PELAM_BOOT_DRIVER_INFO;

// Classification reasons
#define ELAM_REASON_UNKNOWN               0
#define ELAM_REASON_HASH_MATCH            1
#define ELAM_REASON_CERT_MATCH            2
#define ELAM_REASON_MICROSOFT_SIGNED      3
#define ELAM_REASON_WHQL_SIGNED           4
#define ELAM_REASON_KNOWN_MALWARE         5
#define ELAM_REASON_SUSPICIOUS_CERT       6

// ============================================================================
// ELAM GLOBAL STATE
// ============================================================================

/**
 * @brief ELAM driver global state.
 */
typedef struct _ELAM_DRIVER_GLOBALS {
    // Initialization state
    BOOLEAN Initialized;
    BOOLEAN CallbackRegistered;
    UINT16 Reserved1;
    
    // Configuration
    ELAM_BOOT_POLICY BootPolicy;
    UINT32 Reserved2;
    
    // Signature data
    PELAM_SIGNATURE_HEADER SignatureData;
    ULONG SignatureDataSize;
    
    // Callback handle
    PVOID CallbackHandle;
    
    // Statistics
    ULONG DriversClassified;
    ULONG DriversGood;
    ULONG DriversBad;
    ULONG DriversUnknown;
    ULONG DriversBlocked;
    
    // Logging
    BOOLEAN VerboseLogging;
    UINT8 Reserved3[3];
} ELAM_DRIVER_GLOBALS, *PELAM_DRIVER_GLOBALS;

// ============================================================================
// PUBLIC API - INITIALIZATION
// ============================================================================

/**
 * @brief Initialize the ELAM driver.
 * @param DriverObject Driver object.
 * @param RegistryPath Registry path.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ElamDriverInitialize(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

/**
 * @brief Shutdown the ELAM driver.
 */
VOID
ElamDriverShutdown(VOID);

/**
 * @brief Register the boot driver classification callback.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ElamRegisterCallback(VOID);

/**
 * @brief Unregister the boot driver classification callback.
 */
VOID
ElamUnregisterCallback(VOID);

// ============================================================================
// PUBLIC API - CLASSIFICATION
// ============================================================================

/**
 * @brief Classify a boot driver.
 * @param DriverInfo Driver information.
 * @return Classification result.
 */
ELAM_DRIVER_CLASSIFICATION
ElamClassifyDriver(
    _Inout_ PELAM_BOOT_DRIVER_INFO DriverInfo
    );

/**
 * @brief Check if driver hash is known good.
 * @param Hash SHA-256 hash of driver.
 * @return TRUE if known good.
 */
BOOLEAN
ElamIsHashKnownGood(
    _In_reads_(32) const UINT8* Hash
    );

/**
 * @brief Check if driver hash is known bad.
 * @param Hash SHA-256 hash of driver.
 * @return TRUE if known bad.
 */
BOOLEAN
ElamIsHashKnownBad(
    _In_reads_(32) const UINT8* Hash
    );

/**
 * @brief Check if certificate is known good.
 * @param IssuerHash Issuer certificate hash.
 * @param PublisherHash Publisher certificate hash.
 * @return TRUE if known good.
 */
BOOLEAN
ElamIsCertificateKnownGood(
    _In_reads_(32) const UINT8* IssuerHash,
    _In_reads_opt_(32) const UINT8* PublisherHash
    );

/**
 * @brief Check if certificate is known bad.
 * @param IssuerHash Issuer certificate hash.
 * @param PublisherHash Publisher certificate hash.
 * @return TRUE if known bad (compromised, revoked, etc.).
 */
BOOLEAN
ElamIsCertificateKnownBad(
    _In_reads_(32) const UINT8* IssuerHash,
    _In_reads_opt_(32) const UINT8* PublisherHash
    );

// ============================================================================
// PUBLIC API - SIGNATURE MANAGEMENT
// ============================================================================

/**
 * @brief Load signature data from resource.
 * @param DriverObject Driver object.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ElamLoadSignatureData(
    _In_ PDRIVER_OBJECT DriverObject
    );

/**
 * @brief Validate signature data integrity.
 * @return TRUE if signature data is valid.
 */
BOOLEAN
ElamValidateSignatureData(VOID);

/**
 * @brief Get signature statistics.
 * @param SignatureCount Output signature count.
 * @param HashCount Output hash count.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ElamGetSignatureStats(
    _Out_ PULONG SignatureCount,
    _Out_ PULONG HashCount
    );

// ============================================================================
// PUBLIC API - STATISTICS
// ============================================================================

/**
 * @brief Get ELAM driver statistics.
 * @param DriversClassified Output drivers classified.
 * @param DriversGood Output good drivers.
 * @param DriversBad Output bad drivers.
 * @param DriversUnknown Output unknown drivers.
 * @param DriversBlocked Output blocked drivers.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ElamGetStatistics(
    _Out_ PULONG DriversClassified,
    _Out_ PULONG DriversGood,
    _Out_ PULONG DriversBad,
    _Out_ PULONG DriversUnknown,
    _Out_ PULONG DriversBlocked
    );

// ============================================================================
// BOOT DRIVER CALLBACK (Internal)
// ============================================================================

/**
 * @brief Boot driver callback function.
 * Called by the system for each boot-start driver.
 */
VOID
ElamBootDriverCallback(
    _In_ PVOID CallbackContext,
    _In_ BDCB_CALLBACK_TYPE Classification,
    _Inout_ PBDCB_IMAGE_INFORMATION ImageInformation
    );

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Calculate SHA-256 hash of buffer.
 * @param Buffer Input buffer.
 * @param BufferSize Buffer size.
 * @param Hash Output 32-byte hash.
 * @return STATUS_SUCCESS on success.
 */
NTSTATUS
ElamCalculateHash(
    _In_reads_bytes_(BufferSize) const VOID* Buffer,
    _In_ ULONG BufferSize,
    _Out_writes_(32) UINT8* Hash
    );

/**
 * @brief Compare two hashes.
 * @param Hash1 First hash.
 * @param Hash2 Second hash.
 * @return TRUE if equal.
 */
BOOLEAN
ElamCompareHashes(
    _In_reads_(32) const UINT8* Hash1,
    _In_reads_(32) const UINT8* Hash2
    );

#endif // SHADOWSTRIKE_ELAM_DRIVER_H
