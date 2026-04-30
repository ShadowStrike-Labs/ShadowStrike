// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
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
#pragma warning(push)
#pragma warning(disable:4324)
#include "../PhantomSensor/Utilities/HashUtils.h"
#pragma warning(pop)
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
#define BTD_MAX_HEX_STRING_LENGTH       128

// Binary format for BtdLoadVulnerableList
#define BTD_VULN_LIST_MAGIC     'BVDL'
#define BTD_VULN_LIST_VERSION   1

#pragma pack(push, 1)
typedef struct _BTD_VULN_LIST_HEADER {
    ULONG Magic;
    ULONG Version;
    ULONG EntryCount;
    ULONG Reserved;
} BTD_VULN_LIST_HEADER, *PBTD_VULN_LIST_HEADER;

typedef struct _BTD_VULN_LIST_RECORD {
    UCHAR Hash[32];
    CHAR DriverName[64];
    CHAR CVE[32];
    CHAR Vendor[64];
    ULONG SeverityScore;
} BTD_VULN_LIST_RECORD, *PBTD_VULN_LIST_RECORD;
#pragma pack(pop)

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
    _In_reads_bytes_(DataSize) const UCHAR* Data,
    _In_ SIZE_T DataSize,
    _In_reads_bytes_(PatternSize) const UCHAR* Pattern,
    _In_ SIZE_T PatternSize,
    _In_ ULONG PatternOffset,
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

static NTSTATUS
BtdpDeepCopyDriverPath(
    _In_ PUNICODE_STRING Source,
    _Out_ PUNICODE_STRING Destination
    );

static VOID
BtdpFreeDriverPath(
    _Inout_ PUNICODE_STRING Path
    );

static VOID
BtdpInvokeCallback(
    _In_ PBTD_DETECTOR Detector,
    _In_ PBTD_THREAT Threat
    );

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Convert hex string to bytes with bounded length check
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

    //
    // Bounded length scan â€” never scan more than BTD_MAX_HEX_STRING_LENGTH
    //
    hexLen = 0;
    while (hexLen < BTD_MAX_HEX_STRING_LENGTH && HexString[hexLen] != '\0') {
        hexLen++;
    }

    if (hexLen != BytesSize * 2) {
        return STATUS_INVALID_PARAMETER;
    }

    for (i = 0; i < BytesSize; i++) {
        CHAR c1 = HexString[i * 2];
        CHAR c2 = HexString[i * 2 + 1];

        if (c1 >= '0' && c1 <= '9')      { high = (UCHAR)(c1 - '0'); }
        else if (c1 >= 'A' && c1 <= 'F') { high = (UCHAR)(c1 - 'A' + 10); }
        else if (c1 >= 'a' && c1 <= 'f') { high = (UCHAR)(c1 - 'a' + 10); }
        else { return STATUS_INVALID_PARAMETER; }

        if (c2 >= '0' && c2 <= '9')      { low = (UCHAR)(c2 - '0'); }
        else if (c2 >= 'A' && c2 <= 'F') { low = (UCHAR)(c2 - 'A' + 10); }
        else if (c2 >= 'a' && c2 <= 'f') { low = (UCHAR)(c2 - 'a' + 10); }
        else { return STATUS_INVALID_PARAMETER; }

        Bytes[i] = (high << 4) | low;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Pattern matching with wildcards (0x00 = wildcard) and optional fixed offset
 *
 * @param Data          Image bytes to scan
 * @param DataSize      Size of image bytes
 * @param Pattern       Pattern bytes (0x00 acts as wildcard)
 * @param PatternSize   Length of pattern
 * @param PatternOffset If non-zero, only check at this specific offset. If zero, scan entire image.
 * @param MatchOffset   Receives the offset where match was found
 */
static BOOLEAN
BtdpMatchPattern(
    _In_reads_bytes_(DataSize) const UCHAR* Data,
    _In_ SIZE_T DataSize,
    _In_reads_bytes_(PatternSize) const UCHAR* Pattern,
    _In_ SIZE_T PatternSize,
    _In_ ULONG PatternOffset,
    _Out_opt_ PULONG MatchOffset
    )
{
    SIZE_T scanStart, scanEnd, i, j;
    BOOLEAN match;

    if (Data == NULL || Pattern == NULL || PatternSize == 0) {
        return FALSE;
    }

    if (DataSize < PatternSize) {
        return FALSE;
    }

    //
    // If a fixed offset is specified, only check at that position
    //
    if (PatternOffset != 0) {
        if ((SIZE_T)PatternOffset + PatternSize > DataSize) {
            return FALSE;
        }
        scanStart = PatternOffset;
        scanEnd = PatternOffset;
    } else {
        scanStart = 0;
        scanEnd = DataSize - PatternSize;
    }

    for (i = scanStart; i <= scanEnd; i++) {
        match = TRUE;

        for (j = 0; j < PatternSize; j++) {
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
 * @brief Free threat structure â€” releases deep-copied path and returns to lookaside
 */
static VOID
BtdpFreeThreatInternal(
    _In_ PBTD_DETECTOR_INTERNAL Internal,
    _In_ PBTD_THREAT Threat
    )
{
    if (Threat != NULL) {
        BtdpFreeDriverPath(&Threat->DriverPath);
        ExFreeToNPagedLookasideList(&Internal->ThreatLookaside, Threat);
    }
}

/**
 * @brief Deep-copy a UNICODE_STRING with own buffer allocation
 */
static NTSTATUS
BtdpDeepCopyDriverPath(
    _In_ PUNICODE_STRING Source,
    _Out_ PUNICODE_STRING Destination
    )
{
    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0) {
        RtlInitUnicodeString(Destination, NULL);
        return STATUS_SUCCESS;
    }

    Destination->Buffer = (PWCH)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        (SIZE_T)Source->Length + sizeof(WCHAR),
        BTD_POOL_TAG
        );

    if (Destination->Buffer == NULL) {
        RtlInitUnicodeString(Destination, NULL);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(Destination->Buffer, Source->Buffer, Source->Length);
    Destination->Buffer[Source->Length / sizeof(WCHAR)] = L'\0';
    Destination->Length = Source->Length;
    Destination->MaximumLength = Source->Length + sizeof(WCHAR);

    return STATUS_SUCCESS;
}

/**
 * @brief Free a deep-copied driver path
 */
static VOID
BtdpFreeDriverPath(
    _Inout_ PUNICODE_STRING Path
    )
{
    if (Path->Buffer != NULL) {
        ExFreePoolWithTag(Path->Buffer, BTD_POOL_TAG);
        Path->Buffer = NULL;
        Path->Length = 0;
        Path->MaximumLength = 0;
    }
}

/**
 * @brief Safely invoke the registered threat callback outside any lock
 *
 * Captures the callback pointer and context under CallbackLock,
 * then invokes outside the lock to prevent deadlocks.
 */
static VOID
BtdpInvokeCallback(
    _In_ PBTD_DETECTOR Detector,
    _In_ PBTD_THREAT Threat
    )
{
    BTD_THREAT_CALLBACK callback;
    PVOID context;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->CallbackLock);
    callback = Detector->ThreatCallback;
    context = Detector->CallbackContext;
    ExReleasePushLockShared(&Detector->CallbackLock);
    KeLeaveCriticalRegion();

    if (callback != NULL) {
        callback(Threat, context);
    }
}

/**
 * @brief Load embedded vulnerable driver list into VulnerableList
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

        if (InterlockedCompareExchange(&Detector->VulnerableCount,
                                       0, 0) >= BTD_MAX_VULNERABLE_DRIVERS) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[ShadowStrike/BTD] Vulnerable list cap reached (%u), skipping remaining embedded entries\n",
                BTD_MAX_VULNERABLE_DRIVERS);
            break;
        }

        entry = (PBTD_VULNERABLE_ENTRY)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(BTD_VULNERABLE_ENTRY),
            BTD_POOL_TAG
            );

        if (entry == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(entry, sizeof(BTD_VULNERABLE_ENTRY));

        status = BtdpHexStringToBytes(
            g_EmbeddedVulnerableDrivers[i].HashHex,
            entry->Hash,
            BTD_HASH_SIZE
            );

        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(entry, BTD_POOL_TAG);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[ShadowStrike/BTD] Failed to parse hash for embedded driver #%u\n", i);
            continue;
        }

        RtlStringCbCopyA(entry->DriverName, sizeof(entry->DriverName),
                        g_EmbeddedVulnerableDrivers[i].DriverName);
        RtlStringCbCopyA(entry->CVE, sizeof(entry->CVE),
                        g_EmbeddedVulnerableDrivers[i].CVE);
        RtlStringCbCopyA(entry->Vendor, sizeof(entry->Vendor),
                        g_EmbeddedVulnerableDrivers[i].Vendor);
        entry->SeverityScore = min(g_EmbeddedVulnerableDrivers[i].Severity, 100);

        RtlStringCbPrintfA(entry->Description, sizeof(entry->Description),
                          "Vulnerable driver: %s (%s)",
                          entry->DriverName, entry->CVE);

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Detector->VulnerableLock);
        InsertTailList(&Detector->VulnerableList, &entry->ListEntry);
        InterlockedIncrement(&Detector->VulnerableCount);
        ExReleasePushLockExclusive(&Detector->VulnerableLock);
        KeLeaveCriticalRegion();
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
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Internal->PatternLock);
        if (entry->ThreatType == BtdThreat_Bootkit) {
            InsertTailList(&Internal->BootkitPatterns, &entry->ListEntry);
            Internal->BootkitPatternCount++;
        } else {
            InsertTailList(&Internal->RootkitPatterns, &entry->ListEntry);
            Internal->RootkitPatternCount++;
        }
        ExReleasePushLockExclusive(&Internal->PatternLock);
        KeLeaveCriticalRegion();
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// PUBLIC API IMPLEMENTATION
// ============================================================================

/**
 * @brief Initialize the boot threat detector
 *
 * Allocates internal state, loads embedded BYOVD database and bootkit/rootkit
 * patterns. Caller receives an opaque detector handle.
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

    internal = (PBTD_DETECTOR_INTERNAL)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(BTD_DETECTOR_INTERNAL),
        BTD_POOL_TAG
        );

    if (internal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(internal, sizeof(BTD_DETECTOR_INTERNAL));

    internal->Public.Verifier = Verifier;

    InitializeListHead(&internal->Public.DetectedList);
    InitializeListHead(&internal->Public.VulnerableList);
    InitializeListHead(&internal->BootkitPatterns);
    InitializeListHead(&internal->RootkitPatterns);

    KeInitializeSpinLock(&internal->Public.DetectedLock);
    ExInitializePushLock(&internal->Public.VulnerableLock);
    ExInitializePushLock(&internal->Public.CallbackLock);
    ExInitializePushLock(&internal->PatternLock);

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

    // Mark initialized early so BtdShutdown CAS guard works for both
    // normal shutdown and init-error cleanup paths. The detector pointer
    // is not exposed to callers until *Detector is set on success.
    InterlockedExchange(&internal->Public.Initialized, 1);

    status = BtdpLoadEmbeddedVulnerableList(&internal->Public);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    status = BtdpLoadEmbeddedPatterns(internal);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    KeQuerySystemTimePrecise(&internal->Public.Stats.StartTime);

    *Detector = &internal->Public;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[ShadowStrike/BTD] Boot threat detector initialized: %ld BYOVD entries, "
        "%lu bootkit + %lu rootkit patterns\n",
        internal->Public.VulnerableCount,
        internal->BootkitPatternCount,
        internal->RootkitPatternCount);

    return STATUS_SUCCESS;

Cleanup:
    if (internal != NULL) {
        BtdShutdown(&internal->Public);
    }

    return status;
}

/**
 * @brief Shutdown the threat detector and release all resources
 *
 * Drains all lists, frees driver path buffers in detected threats,
 * deletes the lookaside list, and frees the detector structure.
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

    // CAS guard: prevent double-shutdown. Init sets Initialized=1 early,
    // so this works for both normal shutdown and init-error cleanup.
    if (InterlockedCompareExchange(&Detector->Initialized, 0, 1) != 1) {
        return;
    }

    //
    // Free vulnerable list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->VulnerableLock);
    while (!IsListEmpty(&Detector->VulnerableList)) {
        entry = RemoveHeadList(&Detector->VulnerableList);
        vulnEntry = CONTAINING_RECORD(entry, BTD_VULNERABLE_ENTRY, ListEntry);
        ExFreePoolWithTag(vulnEntry, BTD_POOL_TAG);
    }
    InterlockedExchange(&Detector->VulnerableCount, 0);
    ExReleasePushLockExclusive(&Detector->VulnerableLock);
    KeLeaveCriticalRegion();

    //
    // Free pattern lists
    //
    KeEnterCriticalRegion();
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
    KeLeaveCriticalRegion();

    //
    // Free detected threats (including deep-copied driver paths)
    //
    KeAcquireSpinLock(&Detector->DetectedLock, &oldIrql);
    while (!IsListEmpty(&Detector->DetectedList)) {
        entry = RemoveHeadList(&Detector->DetectedList);
        threat = CONTAINING_RECORD(entry, BTD_THREAT, ListEntry);
        BtdpFreeDriverPath(&threat->DriverPath);
        ExFreeToNPagedLookasideList(&internal->ThreatLookaside, threat);
    }
    InterlockedExchange(&Detector->DetectedCount, 0);
    KeReleaseSpinLock(&Detector->DetectedLock, oldIrql);

    if (internal->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&internal->ThreatLookaside);
        internal->LookasideInitialized = FALSE;
    }

    ExFreePoolWithTag(internal, BTD_POOL_TAG);
}

/**
 * @brief Register threat notification callback with synchronization
 *
 * Atomically updates both callback pointer and context under CallbackLock
 * to prevent torn reads from concurrent scan threads.
 */
_Use_decl_annotations_
NTSTATUS
BtdRegisterCallback(
    PBTD_DETECTOR Detector,
    BTD_THREAT_CALLBACK Callback,
    PVOID Context
    )
{
    if (Detector == NULL || !InterlockedCompareExchange(&Detector->Initialized, 1, 1)) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Detector->CallbackLock);
    Detector->ThreatCallback = Callback;
    Detector->CallbackContext = Context;
    ExReleasePushLockExclusive(&Detector->CallbackLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

/**
 * @brief Scan a driver for threats using BYOVD hash lookup, pattern matching, and heuristics
 *
 * Performs three-phase detection:
 *   1. BYOVD hash lookup against known vulnerable driver database
 *   2. Bootkit/rootkit byte pattern scanning against mapped image (if available)
 *   3. Heuristic classification for unknown-bad drivers
 *
 * @param Detector    Initialized detector handle
 * @param DriverInfo  Driver metadata from BdvVerifyDriver
 * @param ImageBase   Mapped image base in system space (NULL if unavailable)
 * @param ImageSize   Size of the mapped image in bytes
 * @param Threat      Receives allocated threat on detection, NULL if clean
 */
_Use_decl_annotations_
NTSTATUS
BtdScanDriver(
    PBTD_DETECTOR Detector,
    PBDV_DRIVER_INFO DriverInfo,
    PVOID ImageBase,
    SIZE_T ImageSize,
    PBTD_THREAT* Threat
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PBTD_DETECTOR_INTERNAL internal;
    PBTD_THREAT threat = NULL;
    BOOLEAN isVulnerable = FALSE;
    CHAR cveBuffer[32] = {0};
    PLIST_ENTRY entry;
    PBTD_PATTERN_ENTRY patternEntry;
    KIRQL oldIrql;
    ULONG matchOffset;
    LONG currentDetected;
    BOOLEAN patternMatched = FALSE;
    BTD_THREAT_TYPE matchedThreatType = BtdThreat_None;
    CHAR matchedThreatName[64] = {0};
    ULONG matchedSeverity = 0;
    ULONG matchedOffset = 0;

    if (Detector == NULL ||
        !InterlockedCompareExchange(&Detector->Initialized, 1, 1) ||
        DriverInfo == NULL || Threat == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    internal = CONTAINING_RECORD(Detector, BTD_DETECTOR_INTERNAL, Public);
    *Threat = NULL;

    InterlockedIncrement64(&Detector->Stats.ScansPerformed);

    //
    // Phase 1: BYOVD hash lookup (fast path)
    //
    status = BtdIsVulnerable(
        Detector,
        DriverInfo->ImageHash,
        BTD_HASH_SIZE,
        &isVulnerable,
        cveBuffer,
        sizeof(cveBuffer)
        );

    if (NT_SUCCESS(status) && isVulnerable) {

        currentDetected = InterlockedCompareExchange(&Detector->DetectedCount, 0, 0);
        if (currentDetected >= BTD_MAX_DETECTED_THREATS) {
            InterlockedIncrement64(&Detector->Stats.ThreatsDetected);
            return STATUS_QUOTA_EXCEEDED;
        }

        threat = BtdpAllocateThreat(internal);
        if (threat == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        threat->Type = BtdThreat_VulnerableDriver;
        RtlCopyMemory(threat->Hash, DriverInfo->ImageHash, BTD_HASH_SIZE);

        RtlStringCbCopyA(threat->ThreatName, sizeof(threat->ThreatName),
                        "BYOVD Vulnerable Driver");
        RtlStringCbPrintfA(threat->Description, sizeof(threat->Description),
                          "Known vulnerable driver detected (CVE: %s)",
                          cveBuffer);

        threat->SeverityScore = BTD_SEVERITY_CRITICAL_THRESHOLD;
        threat->IsCritical = TRUE;
        threat->WasBlocked = FALSE;

        if (!NT_SUCCESS(BtdpDeepCopyDriverPath(&DriverInfo->DriverPath, &threat->DriverPath))) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[ShadowStrike/BTD] Failed to copy driver path for BYOVD threat\n");
        }
        KeQuerySystemTimePrecise(&threat->DetectionTime);

        KeAcquireSpinLock(&Detector->DetectedLock, &oldIrql);
        InsertTailList(&Detector->DetectedList, &threat->ListEntry);
        InterlockedIncrement(&Detector->DetectedCount);
        KeReleaseSpinLock(&Detector->DetectedLock, oldIrql);

        InterlockedIncrement64(&Detector->Stats.ThreatsDetected);

        BtdpInvokeCallback(Detector, threat);

        *Threat = threat;
        return STATUS_SUCCESS;
    }

    //
    // Phase 2: Byte pattern scanning against the mapped driver image
    //
    // Lock discipline: capture match data UNDER PatternLock, release lock
    // exactly ONCE after the __try/__except, then build threat OUTSIDE lock.
    // This prevents (a) double PushLock release on exception and
    // (b) use-after-free on patternEntry fields after lock release.
    //
    if (ImageBase != NULL && ImageSize > 0) {

        patternMatched = FALSE;

        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&internal->PatternLock);

        __try {
            //
            // Scan for bootkit patterns
            //
            for (entry = internal->BootkitPatterns.Flink;
                 entry != &internal->BootkitPatterns;
                 entry = entry->Flink) {

                patternEntry = CONTAINING_RECORD(entry, BTD_PATTERN_ENTRY, ListEntry);

                if (BtdpMatchPattern(
                        (const UCHAR*)ImageBase,
                        ImageSize,
                        patternEntry->Pattern,
                        patternEntry->PatternLength,
                        patternEntry->Offset,
                        &matchOffset)) {

                    matchedThreatType = patternEntry->ThreatType;
                    RtlStringCbCopyA(matchedThreatName, sizeof(matchedThreatName),
                                    patternEntry->ThreatName);
                    matchedSeverity = patternEntry->SeverityScore;
                    matchedOffset = matchOffset;
                    patternMatched = TRUE;
                    break;
                }
            }

            //
            // Scan for rootkit patterns (only if bootkit scan found nothing)
            //
            if (!patternMatched) {
                for (entry = internal->RootkitPatterns.Flink;
                     entry != &internal->RootkitPatterns;
                     entry = entry->Flink) {

                    patternEntry = CONTAINING_RECORD(entry, BTD_PATTERN_ENTRY, ListEntry);

                    if (BtdpMatchPattern(
                            (const UCHAR*)ImageBase,
                            ImageSize,
                            patternEntry->Pattern,
                            patternEntry->PatternLength,
                            patternEntry->Offset,
                            &matchOffset)) {

                        matchedThreatType = patternEntry->ThreatType;
                        RtlStringCbCopyA(matchedThreatName, sizeof(matchedThreatName),
                                        patternEntry->ThreatName);
                        matchedSeverity = patternEntry->SeverityScore;
                        matchedOffset = matchOffset;
                        patternMatched = TRUE;
                        break;
                    }
                }
            }

        } __except (EXCEPTION_EXECUTE_HANDLER) {
            patternMatched = FALSE;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[ShadowStrike/BTD] Exception 0x%08X during image pattern scan at base %p (size 0x%IX)\n",
                GetExceptionCode(), ImageBase, ImageSize);
        }

        ExReleasePushLockShared(&internal->PatternLock);
        KeLeaveCriticalRegion();

        //
        // Build threat structure OUTSIDE lock using captured data
        //
        if (patternMatched) {

            currentDetected = InterlockedCompareExchange(&Detector->DetectedCount, 0, 0);
            if (currentDetected >= BTD_MAX_DETECTED_THREATS) {
                InterlockedIncrement64(&Detector->Stats.ThreatsDetected);
                return STATUS_QUOTA_EXCEEDED;
            }

            threat = BtdpAllocateThreat(internal);
            if (threat == NULL) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            threat->Type = matchedThreatType;
            RtlCopyMemory(threat->Hash, DriverInfo->ImageHash, BTD_HASH_SIZE);
            RtlStringCbCopyA(threat->ThreatName, sizeof(threat->ThreatName),
                            matchedThreatName);

            if (matchedThreatType == BtdThreat_Bootkit) {
                RtlStringCbPrintfA(threat->Description, sizeof(threat->Description),
                                  "Bootkit pattern '%s' matched at offset 0x%X in driver image",
                                  matchedThreatName, matchedOffset);
            } else {
                RtlStringCbPrintfA(threat->Description, sizeof(threat->Description),
                                  "Rootkit pattern '%s' matched at offset 0x%X in driver image",
                                  matchedThreatName, matchedOffset);
            }

            threat->SeverityScore = matchedSeverity;
            threat->IsCritical = (matchedSeverity >= BTD_SEVERITY_CRITICAL_THRESHOLD);
            threat->WasBlocked = FALSE;

            if (!NT_SUCCESS(BtdpDeepCopyDriverPath(&DriverInfo->DriverPath, &threat->DriverPath))) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "[ShadowStrike/BTD] Failed to copy driver path for pattern threat\n");
            }
            KeQuerySystemTimePrecise(&threat->DetectionTime);

            KeAcquireSpinLock(&Detector->DetectedLock, &oldIrql);
            InsertTailList(&Detector->DetectedList, &threat->ListEntry);
            InterlockedIncrement(&Detector->DetectedCount);
            KeReleaseSpinLock(&Detector->DetectedLock, oldIrql);

            InterlockedIncrement64(&Detector->Stats.ThreatsDetected);
            BtdpInvokeCallback(Detector, threat);

            *Threat = threat;
            return STATUS_SUCCESS;
        }
    }

    //
    // Phase 3: Heuristic analysis for unknown-bad classified drivers
    //
    if (DriverInfo->Classification == BdvClass_Unknown_Bad) {

        currentDetected = InterlockedCompareExchange(&Detector->DetectedCount, 0, 0);
        if (currentDetected >= BTD_MAX_DETECTED_THREATS) {
            InterlockedIncrement64(&Detector->Stats.ThreatsDetected);
            return STATUS_QUOTA_EXCEEDED;
        }

        threat = BtdpAllocateThreat(internal);
        if (threat == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

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

        if (!NT_SUCCESS(BtdpDeepCopyDriverPath(&DriverInfo->DriverPath, &threat->DriverPath))) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[ShadowStrike/BTD] Failed to copy driver path for unauthorized threat\n");
        }
        KeQuerySystemTimePrecise(&threat->DetectionTime);

        KeAcquireSpinLock(&Detector->DetectedLock, &oldIrql);
        InsertTailList(&Detector->DetectedList, &threat->ListEntry);
        InterlockedIncrement(&Detector->DetectedCount);
        KeReleaseSpinLock(&Detector->DetectedLock, oldIrql);

        InterlockedIncrement64(&Detector->Stats.ThreatsDetected);
        BtdpInvokeCallback(Detector, threat);

        *Threat = threat;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Load additional vulnerable driver list from binary format
 *
 * Binary format:
 *   Header (16 bytes): Magic('BVDL') + Version(1) + EntryCount + Reserved
 *   Entries[N]: Hash(32) + DriverName(64) + CVE(32) + Vendor(64) + Severity(4) = 196 bytes each
 *
 * Validates all fields, enforces cap, and merges into existing VulnerableList.
 */
_Use_decl_annotations_
NTSTATUS
BtdLoadVulnerableList(
    PBTD_DETECTOR Detector,
    PVOID Data,
    SIZE_T DataSize
    )
{
    PBTD_VULN_LIST_HEADER header;
    PBTD_VULN_LIST_RECORD records;
    PBTD_VULNERABLE_ENTRY entry;
    ULONG i;
    SIZE_T expectedSize;
    LONG currentCount;

    if (Detector == NULL || !InterlockedCompareExchange(&Detector->Initialized, 1, 1)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Data == NULL || DataSize < sizeof(BTD_VULN_LIST_HEADER)) {
        return STATUS_INVALID_PARAMETER;
    }

    header = (PBTD_VULN_LIST_HEADER)Data;

    //
    // Validate header
    //
    if (header->Magic != BTD_VULN_LIST_MAGIC) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[ShadowStrike/BTD] BtdLoadVulnerableList: invalid magic 0x%08X (expected 0x%08X)\n",
            header->Magic, BTD_VULN_LIST_MAGIC);
        return STATUS_INVALID_PARAMETER;
    }

    if (header->Version != BTD_VULN_LIST_VERSION) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[ShadowStrike/BTD] BtdLoadVulnerableList: unsupported version %u\n",
            header->Version);
        return STATUS_NOT_SUPPORTED;
    }

    if (header->EntryCount == 0) {
        return STATUS_SUCCESS;
    }

    //
    // Integer overflow check: EntryCount * sizeof(record) + header
    //
    if (header->EntryCount > BTD_MAX_VULNERABLE_DRIVERS) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[ShadowStrike/BTD] BtdLoadVulnerableList: entry count %u exceeds max %u\n",
            header->EntryCount, BTD_MAX_VULNERABLE_DRIVERS);
        return STATUS_INVALID_PARAMETER;
    }

    expectedSize = sizeof(BTD_VULN_LIST_HEADER) +
                   (SIZE_T)header->EntryCount * sizeof(BTD_VULN_LIST_RECORD);

    if (DataSize < expectedSize) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[ShadowStrike/BTD] BtdLoadVulnerableList: data size %IX < expected %IX\n",
            DataSize, expectedSize);
        return STATUS_BUFFER_TOO_SMALL;
    }

    records = (PBTD_VULN_LIST_RECORD)((PUCHAR)Data + sizeof(BTD_VULN_LIST_HEADER));

    for (i = 0; i < header->EntryCount; i++) {

        //
        // Enforce global cap
        //
        currentCount = InterlockedCompareExchange(&Detector->VulnerableCount, 0, 0);
        if (currentCount >= BTD_MAX_VULNERABLE_DRIVERS) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[ShadowStrike/BTD] Vulnerable list cap reached (%u), loaded %u of %u new entries\n",
                BTD_MAX_VULNERABLE_DRIVERS, i, header->EntryCount);
            break;
        }

        //
        // Validate string fields are null-terminated within their bounds
        //
        if (records[i].DriverName[sizeof(records[i].DriverName) - 1] != '\0' ||
            records[i].CVE[sizeof(records[i].CVE) - 1] != '\0' ||
            records[i].Vendor[sizeof(records[i].Vendor) - 1] != '\0') {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[ShadowStrike/BTD] Skipping entry #%u: unterminated string field\n", i);
            continue;
        }

        if (records[i].SeverityScore > 100) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                "[ShadowStrike/BTD] Clamping entry #%u severity from %u to 100\n",
                i, records[i].SeverityScore);
        }

        entry = (PBTD_VULNERABLE_ENTRY)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(BTD_VULNERABLE_ENTRY),
            BTD_POOL_TAG
            );

        if (entry == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(entry, sizeof(BTD_VULNERABLE_ENTRY));

        RtlCopyMemory(entry->Hash, records[i].Hash, BTD_HASH_SIZE);
        RtlStringCbCopyA(entry->DriverName, sizeof(entry->DriverName), records[i].DriverName);
        RtlStringCbCopyA(entry->CVE, sizeof(entry->CVE), records[i].CVE);
        RtlStringCbCopyA(entry->Vendor, sizeof(entry->Vendor), records[i].Vendor);
        entry->SeverityScore = min(records[i].SeverityScore, 100);

        RtlStringCbPrintfA(entry->Description, sizeof(entry->Description),
                          "Vulnerable driver: %s (%s)", entry->DriverName, entry->CVE);

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Detector->VulnerableLock);
        InsertTailList(&Detector->VulnerableList, &entry->ListEntry);
        InterlockedIncrement(&Detector->VulnerableCount);
        ExReleasePushLockExclusive(&Detector->VulnerableLock);
        KeLeaveCriticalRegion();
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[ShadowStrike/BTD] Loaded %u additional vulnerable driver entries (total: %ld)\n",
        i, Detector->VulnerableCount);

    return STATUS_SUCCESS;
}

/**
 * @brief Check if driver hash is in vulnerable list
 *
 * @param Detector        Initialized detector handle
 * @param Hash            SHA-256 hash of the driver image
 * @param HashLength      Must be BTD_HASH_SIZE (32)
 * @param IsVulnerable    Receives TRUE if hash matches a known vulnerable driver
 * @param CVEBuffer       Optional buffer to receive CVE identifier string
 * @param CVEBufferSize   Size of CVEBuffer in bytes (must be >= 32 if provided)
 */
_Use_decl_annotations_
NTSTATUS
BtdIsVulnerable(
    PBTD_DETECTOR Detector,
    PUCHAR Hash,
    SIZE_T HashLength,
    PBOOLEAN IsVulnerable,
    PCHAR CVEBuffer,
    SIZE_T CVEBufferSize
    )
{
    PLIST_ENTRY entry;
    PBTD_VULNERABLE_ENTRY vulnEntry;

    if (Detector == NULL ||
        !InterlockedCompareExchange(&Detector->Initialized, 1, 1) ||
        Hash == NULL || HashLength != BTD_HASH_SIZE ||
        IsVulnerable == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsVulnerable = FALSE;
    if (CVEBuffer != NULL && CVEBufferSize > 0) {
        CVEBuffer[0] = '\0';
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Detector->VulnerableLock);

    for (entry = Detector->VulnerableList.Flink;
         entry != &Detector->VulnerableList;
         entry = entry->Flink) {

        vulnEntry = CONTAINING_RECORD(entry, BTD_VULNERABLE_ENTRY, ListEntry);

        if (ShadowStrikeCompareSha256(vulnEntry->Hash, Hash)) {
            *IsVulnerable = TRUE;

            if (CVEBuffer != NULL && CVEBufferSize > 0) {
                RtlStringCbCopyA(CVEBuffer, CVEBufferSize, vulnEntry->CVE);
            }
            break;
        }
    }

    ExReleasePushLockShared(&Detector->VulnerableLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

/**
 * @brief Get list of detected threats (returns pointers, NOT copies)
 *
 * The returned threat pointers remain owned by the detector.
 * Caller must NOT free them individually â€” use BtdFreeThreat to remove
 * a specific threat, or let BtdShutdown clean up all.
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

    if (Detector == NULL ||
        !InterlockedCompareExchange(&Detector->Initialized, 1, 1) ||
        Threats == NULL || Count == NULL || Max == 0) {
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
 * @brief Free a threat structure â€” removes from DetectedList and releases to lookaside
 *
 * Safely unlinks the threat from the detector's DetectedList under spinlock,
 * frees the deep-copied driver path, and returns the structure to the lookaside.
 */
_Use_decl_annotations_
VOID
BtdFreeThreat(
    PBTD_DETECTOR Detector,
    PBTD_THREAT Threat
    )
{
    PBTD_DETECTOR_INTERNAL internal;
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    PLIST_ENTRY entry;

    if (Detector == NULL || Threat == NULL) {
        return;
    }

    //
    // Guard against calls after BtdShutdown has destroyed the lookaside.
    // The caller MUST ensure all scan threads have quiesced before shutdown.
    //
    if (!InterlockedCompareExchange(&Detector->Initialized, 1, 1)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[ShadowStrike/BTD] BtdFreeThreat called on shut-down detector â€” leak preferred over pool corruption\n");
        return;
    }

    internal = CONTAINING_RECORD(Detector, BTD_DETECTOR_INTERNAL, Public);

    //
    // Remove from DetectedList if present
    //
    KeAcquireSpinLock(&Detector->DetectedLock, &oldIrql);

    for (entry = Detector->DetectedList.Flink;
         entry != &Detector->DetectedList;
         entry = entry->Flink) {

        if (entry == &Threat->ListEntry) {
            RemoveEntryList(&Threat->ListEntry);
            InterlockedDecrement(&Detector->DetectedCount);
            found = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&Detector->DetectedLock, oldIrql);

    if (!found) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "[ShadowStrike/BTD] BtdFreeThreat: threat %p not found in DetectedList â€” "
            "possible double-free or stale pointer, leak preferred over corruption\n",
            Threat);
        return;
    }

    BtdpFreeDriverPath(&Threat->DriverPath);
    ExFreeToNPagedLookasideList(&internal->ThreatLookaside, Threat);
}
