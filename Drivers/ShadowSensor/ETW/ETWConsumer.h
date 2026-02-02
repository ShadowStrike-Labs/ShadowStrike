/*++
    ShadowStrike Next-Generation Antivirus
    Module: ETWConsumer.h - ETW event consumption
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define EC_POOL_TAG 'NOCE'

typedef struct _EC_EVENT_RECORD {
    GUID ProviderId;
    USHORT EventId;
    UCHAR Level;
    ULONG64 Keywords;
    
    LARGE_INTEGER Timestamp;
    ULONG ProcessId;
    ULONG ThreadId;
    
    PVOID UserData;
    ULONG UserDataLength;
    
    LIST_ENTRY ListEntry;
} EC_EVENT_RECORD, *PEC_EVENT_RECORD;

typedef VOID (*EC_EVENT_CALLBACK)(
    _In_ PEC_EVENT_RECORD Record,
    _In_opt_ PVOID Context
);

typedef struct _EC_SUBSCRIPTION {
    GUID ProviderId;
    ULONG64 KeywordMask;
    UCHAR MaxLevel;
    EC_EVENT_CALLBACK Callback;
    PVOID CallbackContext;
    LIST_ENTRY ListEntry;
} EC_SUBSCRIPTION, *PEC_SUBSCRIPTION;

typedef struct _EC_CONSUMER {
    BOOLEAN Initialized;
    
    // Subscriptions
    LIST_ENTRY SubscriptionList;
    EX_PUSH_LOCK SubscriptionLock;
    ULONG SubscriptionCount;
    
    // Event buffer
    LIST_ENTRY EventBuffer;
    KSPIN_LOCK BufferLock;
    volatile LONG BufferedEvents;
    ULONG MaxBufferedEvents;
    
    // Processing thread
    HANDLE ProcessingThread;
    KEVENT StopEvent;
    BOOLEAN StopRequested;
    
    struct {
        volatile LONG64 EventsReceived;
        volatile LONG64 EventsProcessed;
        volatile LONG64 EventsDropped;
        LARGE_INTEGER StartTime;
    } Stats;
} EC_CONSUMER, *PEC_CONSUMER;

NTSTATUS EcInitialize(_Out_ PEC_CONSUMER* Consumer);
VOID EcShutdown(_Inout_ PEC_CONSUMER Consumer);
NTSTATUS EcSubscribe(_In_ PEC_CONSUMER Consumer, _In_ PGUID ProviderId, _In_ ULONG64 Keywords, _In_ UCHAR Level, _In_ EC_EVENT_CALLBACK Callback, _In_opt_ PVOID Context, _Out_ PEC_SUBSCRIPTION* Subscription);
NTSTATUS EcUnsubscribe(_In_ PEC_CONSUMER Consumer, _In_ PEC_SUBSCRIPTION Subscription);
NTSTATUS EcStart(_In_ PEC_CONSUMER Consumer);
NTSTATUS EcStop(_In_ PEC_CONSUMER Consumer);
VOID EcFreeEventRecord(_In_ PEC_EVENT_RECORD Record);

#ifdef __cplusplus
}
#endif
