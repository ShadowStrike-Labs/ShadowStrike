/*++
    ShadowStrike Next-Generation Antivirus
    Module: CacheOptimization.h - Memory cache optimization
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define CO_POOL_TAG 'HCOC'

typedef enum _CO_CACHE_TYPE {
    CoCache_ProcessInfo = 0,
    CoCache_FileHash,
    CoCache_ModuleInfo,
    CoCache_Verdict,
    CoCache_IOC,
    CoCache_NetworkConnection,
    CoCache_Custom,
} CO_CACHE_TYPE;

typedef struct _CO_CACHE_ENTRY {
    ULONG64 Key;
    PVOID Data;
    SIZE_T DataSize;
    
    volatile LONG RefCount;
    LARGE_INTEGER LastAccess;
    LARGE_INTEGER CreateTime;
    ULONG TTLSeconds;
    
    LIST_ENTRY ListEntry;
    LIST_ENTRY LRUEntry;
    LIST_ENTRY HashEntry;
} CO_CACHE_ENTRY, *PCO_CACHE_ENTRY;

typedef struct _CO_CACHE {
    CO_CACHE_TYPE Type;
    CHAR CacheName[32];
    
    // Storage
    LIST_ENTRY EntryList;
    ULONG EntryCount;
    ULONG MaxEntries;
    
    // Hash table
    struct {
        LIST_ENTRY* Buckets;
        ULONG BucketCount;
    } HashTable;
    
    // LRU list
    LIST_ENTRY LRUList;
    
    // Locking
    EX_PUSH_LOCK Lock;
    
    // Stats
    struct {
        volatile LONG64 Hits;
        volatile LONG64 Misses;
        volatile LONG64 Evictions;
        volatile LONG64 Expirations;
    } Stats;
    
    LIST_ENTRY CacheListEntry;
} CO_CACHE, *PCO_CACHE;

typedef struct _CO_MANAGER {
    BOOLEAN Initialized;
    
    // All caches
    LIST_ENTRY CacheList;
    EX_PUSH_LOCK CacheListLock;
    ULONG CacheCount;
    
    // Global memory limit
    SIZE_T MaxTotalMemory;
    volatile SIZE_T CurrentMemory;
    
    // Maintenance
    KTIMER MaintenanceTimer;
    KDPC MaintenanceDpc;
    ULONG MaintenanceIntervalMs;
    
} CO_MANAGER, *PCO_MANAGER;

NTSTATUS CoInitialize(_Out_ PCO_MANAGER* Manager);
VOID CoShutdown(_Inout_ PCO_MANAGER Manager);
NTSTATUS CoCreateCache(_In_ PCO_MANAGER Manager, _In_ CO_CACHE_TYPE Type, _In_ PCSTR Name, _In_ ULONG MaxEntries, _Out_ PCO_CACHE* Cache);
NTSTATUS CoDestroyCache(_In_ PCO_MANAGER Manager, _In_ PCO_CACHE Cache);
NTSTATUS CoPut(_In_ PCO_CACHE Cache, _In_ ULONG64 Key, _In_ PVOID Data, _In_ SIZE_T DataSize, _In_ ULONG TTLSeconds);
NTSTATUS CoGet(_In_ PCO_CACHE Cache, _In_ ULONG64 Key, _Out_ PVOID* Data, _Out_ PSIZE_T DataSize);
NTSTATUS CoInvalidate(_In_ PCO_CACHE Cache, _In_ ULONG64 Key);
NTSTATUS CoFlush(_In_ PCO_CACHE Cache);
NTSTATUS CoSetMemoryLimit(_In_ PCO_MANAGER Manager, _In_ SIZE_T MaxBytes);

#ifdef __cplusplus
}
#endif
