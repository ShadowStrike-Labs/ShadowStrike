/*++
    ShadowStrike Next-Generation Antivirus
    Module: BootDriverVerify.h - ELAM boot driver verification
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define BDV_POOL_TAG 'VDBE'

typedef enum _BDV_CLASSIFICATION {
    BdvClass_Unknown = 0,
    BdvClass_KnownGood,
    BdvClass_KnownBad,
    BdvClass_Unknown_Good,              // Unknown but passes heuristics
    BdvClass_Unknown_Bad,               // Unknown but fails heuristics
} BDV_CLASSIFICATION;

typedef struct _BDV_DRIVER_INFO {
    UNICODE_STRING DriverPath;
    UNICODE_STRING DriverName;
    
    // Signature
    BOOLEAN IsSigned;
    BOOLEAN IsWhqlSigned;
    UNICODE_STRING SignerName;
    UCHAR ThumbPrint[20];               // SHA-1 of signing cert
    
    // Hashes
    UCHAR ImageHash[32];                // SHA-256
    UCHAR AuthentiCodeHash[32];
    
    // Classification
    BDV_CLASSIFICATION Classification;
    CHAR ClassificationReason[128];
    
    // PE info
    LARGE_INTEGER FileSize;
    LARGE_INTEGER TimeDateStamp;
    ULONG Characteristics;
    
    LIST_ENTRY ListEntry;
} BDV_DRIVER_INFO, *PBDV_DRIVER_INFO;

typedef struct _BDV_VERIFIER {
    BOOLEAN Initialized;
    
    // Known good/bad lists
    LIST_ENTRY KnownGoodList;
    LIST_ENTRY KnownBadList;
    EX_PUSH_LOCK ListLock;
    
    // Verified drivers
    LIST_ENTRY VerifiedList;
    KSPIN_LOCK VerifiedLock;
    ULONG VerifiedCount;
    
    // ELAM config
    PVOID ELAMConfig;
    SIZE_T ELAMConfigSize;
    
    struct {
        volatile LONG64 DriversVerified;
        volatile LONG64 KnownGood;
        volatile LONG64 KnownBad;
        volatile LONG64 UnknownAllowed;
        volatile LONG64 UnknownBlocked;
        LARGE_INTEGER StartTime;
    } Stats;
} BDV_VERIFIER, *PBDV_VERIFIER;

NTSTATUS BdvInitialize(_Out_ PBDV_VERIFIER* Verifier);
VOID BdvShutdown(_Inout_ PBDV_VERIFIER Verifier);
NTSTATUS BdvLoadConfiguration(_In_ PBDV_VERIFIER Verifier, _In_ PVOID ConfigData, _In_ SIZE_T ConfigSize);
NTSTATUS BdvVerifyDriver(_In_ PBDV_VERIFIER Verifier, _In_ PUNICODE_STRING DriverPath, _In_ PVOID ImageBase, _In_ SIZE_T ImageSize, _Out_ PBDV_DRIVER_INFO* Info);
NTSTATUS BdvClassifyDriver(_In_ PBDV_VERIFIER Verifier, _In_ PBDV_DRIVER_INFO Info, _Out_ PBDV_CLASSIFICATION Classification);
NTSTATUS BdvAddKnownHash(_In_ PBDV_VERIFIER Verifier, _In_ PUCHAR Hash, _In_ SIZE_T HashLength, _In_ BOOLEAN IsGood);
VOID BdvFreeDriverInfo(_In_ PBDV_DRIVER_INFO Info);

#ifdef __cplusplus
}
#endif
