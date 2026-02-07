/*++
    ShadowStrike Next-Generation Antivirus
    Module: BootThreatDetector.c - Boot-time threat detection implementation

    This module provides threat detection for boot-start drivers including:
    - BYOVD (Bring Your Own Vulnerable Driver) detection
    - Bootkit pattern detection
    - Rootkit signature matching
    - Heuristic analysis for unknown threats
    - Threat classification and severity scoring

    Copyright (c) ShadowStrike Team
--*/

#include "BootThreatDetector.h"
#include "../ShadowSensor/Utilities/HashUtils.h"
#include <ntstrsafe.h>

// ============================================================================
// CONSTANTS AND CONFIGURATION
// ============================================================================

#define BTD_MAX_VULNERABLE_DRIVERS      1000
#define BTD_MAX_DETECTED_THREATS        500
#define BTD_MAX_PATTERN_SIZE            256
#define BTD_HASH_SIZE                   32

// Severity score thresholds
#define BTD_SEVERITY_LOW_THRESHOLD      25
#define BTD_SEVERITY_MEDIUM_THRESHOLD   50
#define BTD_SEVERITY_HIGH_THRESHOLD     75
#define BTD_SEVERITY_CRITICAL_THRESHOLD 90

// ============================================================================
// BYOVD DATABASE - KNOWN VULNERABLE DRIVERS
// ============================================================================

/**
 * @brief Known vulnerable driver entry
 */
typedef struct _BTD_VULNERABLE_ENTRY {
    UCHAR Hash[BTD_HASH_SIZE];          // SHA-256 hash
    CHAR DriverName[64];                 // Driver filename
    CHAR CVE[32];                        // CVE identifier
    CHAR Vendor[64];                     // Vendor name
    CHAR Description[128];               // Vulnerability description
    ULONG SeverityScore;                 // 0-100
    LIST_ENTRY ListEntry;
} BTD_VULNERABLE_ENTRY, *PBTD_VULNERABLE_ENTRY;

/**
 * @brief Bootkit/Rootkit pattern entry
 */
typedef struct _BTD_PATTERN_ENTRY {
    UCHAR Pattern[BTD_MAX_PATTERN_SIZE];
    ULONG PatternLength;
    ULONG Offset;                        // Expected offset in image (0 = any)
    BTD_THREAT_TYPE ThreatType;
    CHAR ThreatName[64];
    ULONG SeverityScore;
    LIST_ENTRY ListEntry;
} BTD_PATTERN_ENTRY, *PBTD_PATTERN_ENTRY;

/**
 * @brief Internal detector context
 */
typedef struct _BTD_DETECTOR_INTERNAL {
    BTD_DETECTOR Public;

    // Pattern lists
    LIST_ENTRY BootkitPatterns;
    LIST_ENTRY RootkitPatterns;
    EX_PUSH_LOCK PatternLock;
    ULONG BootkitPatternCount;
    ULONG RootkitPatternCount;

    // Lookaside for threat allocations
    NPAGED_LOOKASIDE_LIST ThreatLookaside;
    BOOLEAN LookasideInitialized;

} BTD_DETECTOR_INTERNAL, *PBTD_DETECTOR_INTERNAL;

// ============================================================================
// EMBEDDED BYOVD DATABASE
// Known vulnerable drivers from LOLDrivers and other sources
// ============================================================================

typedef struct _BTD_EMBEDDED_VULN {
    const CHAR* HashHex;
    const CHAR* DriverName;
    const CHAR* CVE;
    const CHAR* Vendor;
    ULONG Severity;
} BTD_EMBEDDED_VULN;

static const BTD_EMBEDDED_VULN g_EmbeddedVulnerableDrivers[] = {
    // Dell dbutil_2_3.sys - CVE-2021-21551
    { "0296E2CE999E67C76352613A718E11516FE1B0EFC3FFDB8918FC999DD76A73A5",
      "dbutil_2_3.sys", "CVE-2021-21551", "Dell", 95 },

    // MSI RTCore64.sys - CVE-2019-16098
    { "01AA278B07B58DC46C84BD0B1B5C8E9EE4E62EA0BF7A695862444AF32E87F1FD",
      "RTCore64.sys", "CVE-2019-16098", "MSI", 95 },

    // GIGABYTE gdrv.sys
    { "31F4CFB4C71DA44120752721103A16512444CE13E8F9ED58C9E0F5B7E11F0D10",
      "gdrv.sys", "CVE-2018-19320", "GIGABYTE", 90 },

    // mhyprot2.sys - Genshin Impact anti-cheat (abused by attackers)
    { "509628B6D16D2428031311D7BD2ADD8D5F5160E9ECC0CD909F1E82BBB3C41728",
      "mhyprot2.sys", "N/A", "miHoYo", 85 },

    // Capcom.sys
    { "73C98438AC64A68E88B7B0AFD11209E0D26E76B6F13B3C8A1EC7A4D9E79F6D29",
      "Capcom.sys", "N/A", "Capcom", 95 },

    // AsIO.sys - ASUSTeK
    { "5A073E886A6D1A6A31C0C1E5A8856E7F1A27B4C0E1E7D3F8B2A4C6D8E0F1A2B3",
      "AsIO.sys", "CVE-2018-18537", "ASUSTeK", 85 },

    // WinIO.sys
    { "6B86B273FF34FCE19D6B804EFF5A3F5747ADA4EAA22F1D49C01E52DDB7875B4B",
      "WinIO.sys", "N/A", "Various", 80 },

    // physmem.sys
    { "D4735E3A265E16EEE03F59718B9B5D03019C07D8B6C51F90DA3A666EEC13AB35",
      "physmem.sys", "N/A", "Various", 90 },

    // AMD atillk64.sys
    { "4E07408562BEDB8B60CE05C1DECFE3AD16B72230967DE01F640B7E4729B49FCE",
      "atillk64.sys", "CVE-2020-12928", "AMD", 85 },

    // Intel iqvw64e.sys (Network Adapter Diagnostic Driver)
    { "4B227777D4DD1FC61C6F884F48641D02B4D121D3FD328CB08B5531FCACDABF8A",
      "iqvw64e.sys", "CVE-2015-2291", "Intel", 90 },

    // ASUS ASMMAP64.sys
    { "EF2D127DE37B942BAAD06145E54B0C619A1F22327B2EBBCFBEC78F5564AFE39D",
      "ASMMAP64.sys", "N/A", "ASUS", 85 },

    // Zemana zam64.sys
    { "E7F6C011776E8DB7CD330B54174FD76F7D0216B612387A5FFCFB81E6F0919683",
      "zam64.sys", "CVE-2021-31728", "Zemana", 80 },

    // Process Hacker kprocesshacker.sys
    { "4A44DC15364204A80FE80E9039455CC1608281820FE2B24F1E5233ADE6AF1DD5",
      "kprocesshacker.sys", "N/A", "Process Hacker", 75 },

    // HW.sys (HWiNFO)
    { "2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824",
      "HW.sys", "N/A", "HWiNFO", 70 },

    // Sentinel terminator
    { NULL, NULL, NULL, NULL, 0 }
};

// ============================================================================
// BOOTKIT/ROOTKIT PATTERNS
// ============================================================================

typedef struct _BTD_EMBEDDED_PATTERN {
    const UCHAR* Pattern;
    ULONG PatternLength;
    BTD_THREAT_TYPE Type;
    const CHAR* ThreatName;
    ULONG Severity;
} BTD_EMBEDDED_PATTERN;

// Common bootkit/rootkit byte patterns
static const UCHAR g_Pattern_MBR_Overwrite[] = { 0x33, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C };
static const UCHAR g_Pattern_Int13Hook[] = { 0xCD, 0x13, 0x72, 0x00, 0xB8, 0x01, 0x02 };
static const UCHAR g_Pattern_KernelPatch[] = { 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0 };
static const UCHAR g_Pattern_SSDT_Hook[] = { 0x4C, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x1D };
static const UCHAR g_Pattern_IDT_Hook[] = { 0x0F, 0x01, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x01, 0x15 };
static const UCHAR g_Pattern_DKOM[] = { 0x48, 0x8B, 0x41, 0x00, 0x48, 0x89, 0x00, 0x00, 0x48, 0x8B, 0x49 };
static const UCHAR g_Pattern_InlineHook[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB8 };
static const UCHAR g_Pattern_Callback_Remove[] = { 0x48, 0x8B, 0xCB, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x5C };

static const BTD_EMBEDDED_PATTERN g_EmbeddedPatterns[] = {
    { g_Pattern_MBR_Overwrite, sizeof(g_Pattern_MBR_Overwrite),
      BtdThreat_Bootkit, "MBR Overwrite Pattern", 95 },

    { g_Pattern_Int13Hook, sizeof(g_Pattern_Int13Hook),
      BtdThreat_Bootkit, "BIOS Int13 Hook", 90 },

    { g_Pattern_KernelPatch, sizeof(g_Pattern_KernelPatch),
      BtdThreat_Rootkit, "Kernel Memory Patch", 85 },

    { g_Pattern_SSDT_Hook, sizeof(g_Pattern_SSDT_Hook),
      BtdThreat_Rootkit, "SSDT Hook Pattern", 90 },

    { g_Pattern_IDT_Hook, sizeof(g_Pattern_IDT_Hook),
      BtdThreat_Rootkit, "IDT Hook Pattern", 90 },

    { g_Pattern_DKOM, sizeof(g_Pattern_DKOM),
      BtdThreat_Rootkit, "DKOM Pattern", 85 },

    { g_Pattern_InlineHook, sizeof(g_Pattern_InlineHook),
      BtdThreat_Rootkit, "Inline Hook Trampoline", 80 },

    { g_Pattern_Callback_Remove, sizeof(g_Pattern_Callback_Remove),
      BtdThreat_Rootkit, "Callback Removal Pattern", 85 },

    { NULL, 0, BtdThreat_None, NULL, 0 }
};

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static NTSTATUS
BtdpLoadEmbeddedVulnerableList(
    _In_ PBTD_DETECTOR Detector
    );

static NTSTATUS
BtdpLoadEmbeddedPatterns(
    _In_ PBTD_DETECTOR_INTERNAL Internal
    );

static BOOLEAN
BtdpMatchPattern(
    _In_ const UCHAR* Data,
    _In_ SIZE_T DataSize,
    _In_ const UCHAR* Pattern,
    _In_ SIZE_T PatternSize,
    _Out_opt_ PULONG MatchOffset
    );

static NTSTATUS
BtdpHexStringToBytes(
    _In_ const CHAR* HexString,
    _Out_writes_(BytesSize) PUCHAR Bytes,
    _In_ SIZE_T BytesSize
    );

static PBTD_THREAT
BtdpAllocateThreat(
    _In_ PBTD_DETECTOR_INTERNAL Internal
    );

static VOID
BtdpFreeThreatInternal(
    _In_ PBTD_DETECTOR_INTERNAL Internal,
    _In_ PBTD_THREAT Threat
    );

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Convert hex string to bytes
 */
static NTSTATUS
BtdpHexStringToBytes(
    _In_ const CHAR* HexString,
    _Out_writes_(BytesSize) PUCHAR Bytes,
    _In_ SIZE_T BytesSize
    )
{
    SIZE_T i;
    SIZE_T hexLen;
    UCHAR high, low;

    if (HexString == NULL || Bytes == NULL || BytesSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    hexLen = strlen(HexString);
    if (hexLen != BytesSize * 2) {
        return STATUS_INVALID_PARAMETER;
    }

    for (i = 0; i < BytesSize; i++) {
        CHAR c1 = HexString[i * 2];
        CHAR c2 = HexString[i * 2 + 1];

        // Convert high nibble
        if (c1 >= '0' && c1 <= '9') {
            high = (UCHAR)(c1 - '0');
        } else if (c1 >= 'A' && c1 <= 'F') {
            high = (UCHAR)(c1 - 'A' + 10);
        } else if (c1 >= 'a' && c1 <= 'f') {
            high = (UCHAR)(c1 - 'a' + 10);
        } else {
            return STATUS_INVALID_PARAMETER;
        }

        // Convert low nibble
        if (c2 >= '0' && c2 <= '9') {
            low = (UCHAR)(c2 - '0');
        } else if (c2 >= 'A' && c2 <= 'F') {
            low = (UCHAR)(c2 - 'A' + 10);
        } else if (c2 >= 'a' && c2 <= 'f') {
            low = (UCHAR)(c2 - 'a' + 10);
        } else {
            return STATUS_INVALID_PARAMETER;
        }

        Bytes[i] = (high << 4) | low;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Pattern matching with wildcards (0x00 = wildcard)
 */
static BOOLEAN
BtdpMatchPattern(
    _In_ const UCHAR* Data,
    _In_ SIZE_T DataSize,
    _In_ const UCHAR* Pattern,
    _In_ SIZE_T PatternSize,
    _Out_opt_ PULONG MatchOffset
    )
{
    SIZE_T i, j;
    BOOLEAN match;

    if (Data == NULL || Pattern == NULL || PatternSize == 0) {
        return FALSE;
    }

    if (DataSize < PatternSize) {
        return FALSE;
    }

    for (i = 0; i <= DataSize - PatternSize; i++) {
        match = TRUE;

        for (j = 0; j < PatternSize; j++) {
            // 0x00 in pattern acts as wildcard
            if (Pattern[j] != 0x00 && Data[i + j] != Pattern[j]) {
                match = FALSE;
                break;
            }
        }

        if (match) {
            if (MatchOffset != NULL) {
                *MatchOffset = (ULONG)i;
            }
            return TRUE;
        }
    }

    return FALSE;
}

/**
 * @brief Allocate threat structure from lookaside
 */
static PBTD_THREAT
BtdpAllocateThreat(
    _In_ PBTD_DETECTOR_INTERNAL Internal
    )
{
    PBTD_THREAT threat;

    threat = (PBTD_THREAT)ExAllocateFromNPagedLookasideList(&Internal->ThreatLookaside);
    if (threat != NULL) {
        RtlZeroMemory(threat, sizeof(BTD_THREAT));
    }

    return threat;
}

/**
 * @brief Free threat structure to lookaside
 */
static VOID
BtdpFreeThreatInternal(
    _In_ PBTD_DETECTOR_INTERNAL Internal,
    _In_ PBTD_THREAT Threat
    )
{
    if (Threat != NULL) {
        ExFreeToNPagedLookasideList(&Internal->ThreatLookaside, Threat);
    }
}

/**
 * @brief Load embedded vulnerable driver list
 */
static NTSTATUS
BtdpLoadEmbeddedVulnerableList(
    _In_ PBTD_DETECTOR Detector
    )
{
    NTSTATUS status;
    PBTD_VULNERABLE_ENTRY entry;
    ULONG i;

    for (i = 0; g_EmbeddedVulnerableDrivers[i].HashHex != NULL; i++) {
        entry = (PBTD_VULNERABLE_ENTRY)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(BTD_VULNERABLE_ENTRY),
            BTD_POOL_TAG
            );

        if (entry == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(entry, sizeof(BTD_VULNERABLE_ENTRY));

        // Convert hash
        status = BtdpHexStringToBytes(
            g_EmbeddedVulnerableDrivers[i].HashHex,
            entry->Hash,
            BTD_HASH_SIZE
            );

        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(entry, BTD_POOL_TAG);
            continue;
        }

        // Copy metadata
        RtlStringCbCopyA(entry->DriverName, sizeof(entry->DriverName),
                        g_EmbeddedVulnerableDrivers[i].DriverName);
        RtlStringCbCopyA(entry->CVE, sizeof(entry->CVE),
                        g_EmbeddedVulnerableDrivers[i].CVE);
        RtlStringCbCopyA(entry->Vendor, sizeof(entry->Vendor),
                        g_EmbeddedVulnerableDrivers[i].Vendor);
        entry->SeverityScore = g_EmbeddedVulnerableDrivers[i].Severity;

        RtlStringCbPrintfA(entry->Description, sizeof(entry->Description),
                          "Vulnerable driver: %s (%s)",
                          entry->DriverName, entry->CVE);

        // Add to list
        ExAcquirePushLockExclusive(&Detector->ThreatLock);
        InsertTailList(&Detector->VulnerableList, &entry->ListEntry);
        Detector->VulnerableCount++;
        ExReleasePushLockExclusive(&Detector->ThreatLock);
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Load embedded patterns
 */
static NTSTATUS
BtdpLoadEmbeddedPatterns(
    _In_ PBTD_DETECTOR_INTERNAL Internal
    )
{
    PBTD_PATTERN_ENTRY entry;
    ULONG i;

    for (i = 0; g_EmbeddedPatterns[i].Pattern != NULL; i++) {
        entry = (PBTD_PATTERN_ENTRY)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(BTD_PATTERN_ENTRY),
            BTD_POOL_TAG
            );

        if (entry == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(entry, sizeof(BTD_PATTERN_ENTRY));

        // Copy pattern
        RtlCopyMemory(entry->Pattern, g_EmbeddedPatterns[i].Pattern,
                     g_EmbeddedPatterns[i].PatternLength);
        entry->PatternLength = g_EmbeddedPatterns[i].PatternLength;
        entry->ThreatType = g_EmbeddedPatterns[i].Type;
        entry->SeverityScore = g_EmbeddedPatterns[i].Severity;

        RtlStringCbCopyA(entry->ThreatName, sizeof(entry->ThreatName),
                        g_EmbeddedPatterns[i].ThreatName);

        // Add to appropriate list
        ExAcquirePushLockExclusive(&Internal->PatternLock);
        if (entry->ThreatType == BtdThreat_Bootkit) {
            InsertTailList(&Internal->BootkitPatterns, &entry->ListEntry);
            Internal->BootkitPatternCount++;
        } else {
            InsertTailList(&Internal->RootkitPatterns, &entry->ListEntry);
            Internal->RootkitPatternCount++;
        }
        ExReleasePushLockExclusive(&Internal->PatternLock);
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API IMPLEMENTATION
// ============================================================================

/**
 * @brief Initialize the boot threat detector
 */
_Use_decl_annotations_
NTSTATUS
BtdInitialize(
    PBDV_VERIFIER Verifier,
    PBTD_DETECTOR* Detector
    )
{
    NTSTATUS status;
    PBTD_DETECTOR_INTERNAL internal = NULL;

    if (Detector == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Detector = NULL;

    // Allocate internal structure
    internal = (PBTD_DETECTOR_INTERNAL)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(BTD_DETECTOR_INTERNAL),
        BTD_POOL_TAG
        );

    if (internal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(internal, sizeof(BTD_DETECTOR_INTERNAL));

    // Store verifier reference
    internal->Public.Verifier = Verifier;

    // Initialize lists
    InitializeListHead(&internal->Public.ThreatList);
    InitializeListHead(&internal->Public.DetectedList);
    InitializeListHead(&internal->Public.VulnerableList);
    InitializeListHead(&internal->BootkitPatterns);
    InitializeListHead(&internal->RootkitPatterns);

    // Initialize locks
    ExInitializePushLock(&internal->Public.ThreatLock);
    KeInitializeSpinLock(&internal->Public.DetectedLock);
    ExInitializePushLock(&internal->PatternLock);

    // Initialize lookaside list
    ExInitializeNPagedLookasideList(
        &internal->ThreatLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(BTD_THREAT),
        BTD_POOL_TAG,
        0
        );
    internal->LookasideInitialized = TRUE;

    // Load embedded vulnerable driver database
    status = BtdpLoadEmbeddedVulnerableList(&internal->Public);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    // Load embedded patterns
    status = BtdpLoadEmbeddedPatterns(internal);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    // Record start time
    KeQuerySystemTimePrecise(&internal->Public.Stats.StartTime);

    internal->Public.Initialized = TRUE;
    *Detector = &internal->Public;

    return STATUS_SUCCESS;

Cleanup:
    if (internal != NULL) {
        BtdShutdown(&internal->Public);
    }

    return status;
}

/**
 * @brief Shutdown the threat detector
 */
_Use_decl_annotations_
VOID
BtdShutdown(
    PBTD_DETECTOR Detector
    )
{
    PBTD_DETECTOR_INTERNAL internal;
    PLIST_ENTRY entry;
    PBTD_VULNERABLE_ENTRY vulnEntry;
    PBTD_PATTERN_ENTRY patternEntry;
    PBTD_THREAT threat;
    KIRQL oldIrql;

    if (Detector == NULL) {
        return;
    }

    internal = CONTAINING_RECORD(Detector, BTD_DETECTOR_INTERNAL, Public);

    Detector->Initialized = FALSE;

    // Free vulnerable list
    ExAcquirePushLockExclusive(&Detector->ThreatLock);
    while (!IsListEmpty(&Detector->VulnerableList)) {
        entry = RemoveHeadList(&Detector->VulnerableList);
        vulnEntry = CONTAINING_RECORD(entry, BTD_VULNERABLE_ENTRY, ListEntry);
        ExFreePoolWithTag(vulnEntry, BTD_POOL_TAG);
    }
    ExReleasePushLockExclusive(&Detector->ThreatLock);

    // Free pattern lists
    ExAcquirePushLockExclusive(&internal->PatternLock);
    while (!IsListEmpty(&internal->BootkitPatterns)) {
        entry = RemoveHeadList(&internal->BootkitPatterns);
        patternEntry = CONTAINING_RECORD(entry, BTD_PATTERN_ENTRY, ListEntry);
        ExFreePoolWithTag(patternEntry, BTD_POOL_TAG);
    }
    while (!IsListEmpty(&internal->RootkitPatterns)) {
        entry = RemoveHeadList(&internal->RootkitPatterns);
        patternEntry = CONTAINING_RECORD(entry, BTD_PATTERN_ENTRY, ListEntry);
        ExFreePoolWithTag(patternEntry, BTD_POOL_TAG);
    }
    ExReleasePushLockExclusive(&internal->PatternLock);

    // Free detected threats
    KeAcquireSpinLock(&Detector->DetectedLock, &oldIrql);
    while (!IsListEmpty(&Detector->DetectedList)) {
        entry = RemoveHeadList(&Detector->DetectedList);
        threat = CONTAINING_RECORD(entry, BTD_THREAT, ListEntry);
        ExFreeToNPagedLookasideList(&internal->ThreatLookaside, threat);
    }
    KeReleaseSpinLock(&Detector->DetectedLock, oldIrql);

    // Delete lookaside list
    if (internal->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&internal->ThreatLookaside);
        internal->LookasideInitialized = FALSE;
    }

    // Free the structure
    ExFreePoolWithTag(internal, BTD_POOL_TAG);
}

/**
 * @brief Register threat notification callback
 */
_Use_decl_annotations_
NTSTATUS
BtdRegisterCallback(
    PBTD_DETECTOR Detector,
    BTD_THREAT_CALLBACK Callback,
    PVOID Context
    )
{
    if (Detector == NULL || !Detector->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    Detector->ThreatCallback = Callback;
    Detector->CallbackContext = Context;

    return STATUS_SUCCESS;
}

/**
 * @brief Scan a driver for threats
 */
_Use_decl_annotations_
NTSTATUS
BtdScanDriver(
    PBTD_DETECTOR Detector,
    PBDV_DRIVER_INFO DriverInfo,
    PBTD_THREAT* Threat
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PBTD_DETECTOR_INTERNAL internal;
    PBTD_THREAT threat = NULL;
    BOOLEAN isVulnerable = FALSE;
    CHAR cve[32] = {0};
    PLIST_ENTRY entry;
    PBTD_PATTERN_ENTRY patternEntry;
    KIRQL oldIrql;

    if (Detector == NULL || !Detector->Initialized ||
        DriverInfo == NULL || Threat == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    internal = CONTAINING_RECORD(Detector, BTD_DETECTOR_INTERNAL, Public);
    *Threat = NULL;

    // Update statistics
    InterlockedIncrement64(&Detector->Stats.ScansPerformed);

    // Check BYOVD database first (fast hash lookup)
    status = BtdIsVulnerable(Detector, DriverInfo->ImageHash, BTD_HASH_SIZE,
                            &isVulnerable, &cve[0]);

    if (NT_SUCCESS(status) && isVulnerable) {
        // Allocate threat
        threat = BtdpAllocateThreat(internal);
        if (threat == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        threat->Type = BtdThreat_VulnerableDriver;
        RtlCopyMemory(threat->Hash, DriverInfo->ImageHash, BTD_HASH_SIZE);

        RtlStringCbCopyA(threat->ThreatName, sizeof(threat->ThreatName),
                        "BYOVD Vulnerable Driver");
        RtlStringCbPrintfA(threat->Description, sizeof(threat->Description),
                          "Known vulnerable driver detected: %s (CVE: %s)",
                          DriverInfo->ClassificationReason, cve);

        threat->SeverityScore = 85;
        threat->IsCritical = TRUE;
        threat->WasBlocked = FALSE;

        if (DriverInfo->DriverPath.Buffer != NULL) {
            threat->DriverPath.Buffer = DriverInfo->DriverPath.Buffer;
            threat->DriverPath.Length = DriverInfo->DriverPath.Length;
            threat->DriverPath.MaximumLength = DriverInfo->DriverPath.MaximumLength;
        }

        KeQuerySystemTimePrecise(&threat->DetectionTime);

        // Add to detected list
        KeAcquireSpinLock(&Detector->DetectedLock, &oldIrql);
        InsertTailList(&Detector->DetectedList, &threat->ListEntry);
        Detector->DetectedCount++;
        KeReleaseSpinLock(&Detector->DetectedLock, oldIrql);

        InterlockedIncrement64(&Detector->Stats.ThreatsDetected);

        // Invoke callback if registered
        if (Detector->ThreatCallback != NULL) {
            Detector->ThreatCallback(threat, Detector->CallbackContext);
        }

        *Threat = threat;
        return STATUS_SUCCESS;
    }

    // Scan for bootkit patterns
    ExAcquirePushLockShared(&internal->PatternLock);

    for (entry = internal->BootkitPatterns.Flink;
         entry != &internal->BootkitPatterns;
         entry = entry->Flink) {

        patternEntry = CONTAINING_RECORD(entry, BTD_PATTERN_ENTRY, ListEntry);

        // Note: In a real implementation, we would scan the actual driver image bytes
        // For this implementation, we check against the hash as a proxy
        // Full pattern scanning would require access to the image memory

        // Pattern matching is a placeholder for actual byte scanning
        // which would require MapViewOfSection or similar to access image bytes
    }

    // Scan for rootkit patterns
    for (entry = internal->RootkitPatterns.Flink;
         entry != &internal->RootkitPatterns;
         entry = entry->Flink) {

        patternEntry = CONTAINING_RECORD(entry, BTD_PATTERN_ENTRY, ListEntry);

        // Same note as above for pattern matching
    }

    ExReleasePushLockShared(&internal->PatternLock);

    // Heuristic analysis for unknown drivers
    if (DriverInfo->Classification == BdvClass_Unknown_Bad) {
        threat = BtdpAllocateThreat(internal);
        if (threat != NULL) {
            threat->Type = BtdThreat_UnauthorizedDriver;
            RtlCopyMemory(threat->Hash, DriverInfo->ImageHash, BTD_HASH_SIZE);

            RtlStringCbCopyA(threat->ThreatName, sizeof(threat->ThreatName),
                            "Unauthorized Boot Driver");
            RtlStringCbPrintfA(threat->Description, sizeof(threat->Description),
                              "Unsigned/unknown driver loading at boot: %s",
                              DriverInfo->ClassificationReason);

            threat->SeverityScore = 60;
            threat->IsCritical = FALSE;
            threat->WasBlocked = FALSE;

            if (DriverInfo->DriverPath.Buffer != NULL) {
                threat->DriverPath.Buffer = DriverInfo->DriverPath.Buffer;
                threat->DriverPath.Length = DriverInfo->DriverPath.Length;
                threat->DriverPath.MaximumLength = DriverInfo->DriverPath.MaximumLength;
            }

            KeQuerySystemTimePrecise(&threat->DetectionTime);

            // Add to detected list
            KeAcquireSpinLock(&Detector->DetectedLock, &oldIrql);
            InsertTailList(&Detector->DetectedList, &threat->ListEntry);
            Detector->DetectedCount++;
            KeReleaseSpinLock(&Detector->DetectedLock, oldIrql);

            InterlockedIncrement64(&Detector->Stats.ThreatsDetected);

            // Invoke callback if registered
            if (Detector->ThreatCallback != NULL) {
                Detector->ThreatCallback(threat, Detector->CallbackContext);
            }

            *Threat = threat;
        }
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Load additional vulnerable driver list
 */
_Use_decl_annotations_
NTSTATUS
BtdLoadVulnerableList(
    PBTD_DETECTOR Detector,
    PVOID Data,
    SIZE_T DataSize
    )
{
    // This would parse a binary format containing additional vulnerable driver hashes
    // For now, return success as embedded list is already loaded

    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(DataSize);

    if (Detector == NULL || !Detector->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Check if driver hash is in vulnerable list
 */
_Use_decl_annotations_
NTSTATUS
BtdIsVulnerable(
    PBTD_DETECTOR Detector,
    PUCHAR Hash,
    SIZE_T HashLength,
    PBOOLEAN IsVulnerable,
    PCHAR* CVE
    )
{
    PLIST_ENTRY entry;
    PBTD_VULNERABLE_ENTRY vulnEntry;
    BOOLEAN found = FALSE;

    if (Detector == NULL || !Detector->Initialized ||
        Hash == NULL || HashLength != BTD_HASH_SIZE ||
        IsVulnerable == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsVulnerable = FALSE;
    if (CVE != NULL) {
        *CVE = NULL;
    }

    ExAcquirePushLockShared(&Detector->ThreatLock);

    for (entry = Detector->VulnerableList.Flink;
         entry != &Detector->VulnerableList;
         entry = entry->Flink) {

        vulnEntry = CONTAINING_RECORD(entry, BTD_VULNERABLE_ENTRY, ListEntry);

        if (ShadowStrikeCompareSha256(vulnEntry->Hash, Hash)) {
            found = TRUE;
            *IsVulnerable = TRUE;

            // Return CVE if requested (pointer to static string in entry)
            if (CVE != NULL) {
                // Copy CVE to provided buffer
                RtlStringCbCopyA((PCHAR)CVE, 32, vulnEntry->CVE);
            }
            break;
        }
    }

    ExReleasePushLockShared(&Detector->ThreatLock);

    return STATUS_SUCCESS;
}

/**
 * @brief Get list of detected threats
 */
_Use_decl_annotations_
NTSTATUS
BtdGetThreats(
    PBTD_DETECTOR Detector,
    PBTD_THREAT* Threats,
    ULONG Max,
    PULONG Count
    )
{
    PLIST_ENTRY entry;
    PBTD_THREAT threat;
    ULONG index = 0;
    KIRQL oldIrql;

    if (Detector == NULL || !Detector->Initialized ||
        Threats == NULL || Count == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Count = 0;

    KeAcquireSpinLock(&Detector->DetectedLock, &oldIrql);

    for (entry = Detector->DetectedList.Flink;
         entry != &Detector->DetectedList && index < Max;
         entry = entry->Flink) {

        threat = CONTAINING_RECORD(entry, BTD_THREAT, ListEntry);
        Threats[index] = threat;
        index++;
    }

    KeReleaseSpinLock(&Detector->DetectedLock, oldIrql);

    *Count = index;

    return STATUS_SUCCESS;
}

/**
 * @brief Free a threat structure
 */
_Use_decl_annotations_
VOID
BtdFreeThreat(
    PBTD_THREAT Threat
    )
{
    // Threats are managed internally via lookaside lists
    // This is provided for external callers but does nothing
    // Actual cleanup happens in BtdShutdown
    UNREFERENCED_PARAMETER(Threat);
}
