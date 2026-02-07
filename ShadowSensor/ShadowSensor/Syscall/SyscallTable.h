/*++
    ShadowStrike Next-Generation Antivirus
    Module: SyscallTable.h - Syscall number management
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define SST_POOL_TAG 'TSSS'
#define SST_MAX_SYSCALLS 512

typedef struct _SST_SYSCALL_INFO {
    ULONG Number;                       // Syscall number (OS version specific)
    CHAR Name[64];                      // NtXxx name
    PVOID NtdllAddress;                 // Address in ntdll
    PVOID KernelAddress;                // SSDT target
    ULONG ArgumentCount;
    BOOLEAN IsHooked;
    BOOLEAN IsMonitored;
    LIST_ENTRY ListEntry;
} SST_SYSCALL_INFO, *PSST_SYSCALL_INFO;

typedef struct _SST_OS_VERSION {
    ULONG MajorVersion;                 // 10 for Win10/11
    ULONG MinorVersion;
    ULONG BuildNumber;
    ULONG ServicePack;
} SST_OS_VERSION;

typedef struct _SST_TABLE {
    BOOLEAN Initialized;
    SST_OS_VERSION OsVersion;
    
    // Syscall entries
    SST_SYSCALL_INFO Syscalls[SST_MAX_SYSCALLS];
    ULONG SyscallCount;
    
    // Hash map for fast lookup by number
    struct {
        LIST_ENTRY* Buckets;
        ULONG BucketCount;
    } NumberHash;
    
    // Hash map for fast lookup by name
    struct {
        LIST_ENTRY* Buckets;
        ULONG BucketCount;
    } NameHash;
    
    // SSDT pointer (read-only reference)
    PVOID SSDTBase;
    ULONG SSDTCount;
    
    struct {
        volatile LONG64 Lookups;
        LARGE_INTEGER StartTime;
    } Stats;
} SST_TABLE, *PSST_TABLE;

NTSTATUS SstInitialize(_Out_ PSST_TABLE* Table);
VOID SstShutdown(_Inout_ PSST_TABLE Table);
NTSTATUS SstPopulateFromNtdll(_In_ PSST_TABLE Table);
NTSTATUS SstLookupByNumber(_In_ PSST_TABLE Table, _In_ ULONG Number, _Out_ PSST_SYSCALL_INFO* Info);
NTSTATUS SstLookupByName(_In_ PSST_TABLE Table, _In_ PCSTR Name, _Out_ PSST_SYSCALL_INFO* Info);
NTSTATUS SstGetKernelAddress(_In_ PSST_TABLE Table, _In_ ULONG Number, _Out_ PVOID* Address);
BOOLEAN SstIsKnownSyscall(_In_ PSST_TABLE Table, _In_ ULONG Number);

#ifdef __cplusplus
}
#endif
