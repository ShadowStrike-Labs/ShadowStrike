/*++
    ShadowStrike Next-Generation Antivirus
    Module: ManifestGenerator.h - ETW manifest generation
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include "EventSchema.h"

#define MG_POOL_TAG 'GMGM'

typedef struct _MG_GENERATOR {
    BOOLEAN Initialized;
    
    PES_SCHEMA Schema;
    
    // Output settings
    CHAR ProviderSymbol[64];
    CHAR ResourceFile[260];
    CHAR MessageFile[260];
    
} MG_GENERATOR, *PMG_GENERATOR;

NTSTATUS MgInitialize(_In_ PES_SCHEMA Schema, _Out_ PMG_GENERATOR* Generator);
VOID MgShutdown(_Inout_ PMG_GENERATOR Generator);
NTSTATUS MgGenerateManifest(_In_ PMG_GENERATOR Generator, _Out_ PCHAR* ManifestContent, _Out_ PSIZE_T ContentSize);
NTSTATUS MgGenerateHeader(_In_ PMG_GENERATOR Generator, _Out_ PCHAR* HeaderContent, _Out_ PSIZE_T ContentSize);
NTSTATUS MgSetOutputPaths(_In_ PMG_GENERATOR Generator, _In_ PCSTR ResourceFile, _In_ PCSTR MessageFile);

#ifdef __cplusplus
}
#endif
