/*++
    ShadowStrike Next-Generation Antivirus
    Module: SyscallHooks.h - Syscall interception framework
    Copyright (c) ShadowStrike Team
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

#define SH_POOL_TAG 'KHSS'
#define SH_MAX_HOOKS 64

typedef enum _SH_HOOK_RESULT {
    ShResult_Allow = 0,
    ShResult_Block,
    ShResult_Redirect,
    ShResult_Modify,
} SH_HOOK_RESULT;

typedef struct _SH_SYSCALL_CONTEXT {
    HANDLE ProcessId;
    HANDLE ThreadId;
    ULONG SyscallNumber;
    ULONG64 Arguments[16];
    ULONG ArgumentCount;
    PVOID ReturnAddress;
    NTSTATUS* ReturnValue;              // For post-call
    BOOLEAN IsPreCall;
} SH_SYSCALL_CONTEXT, *PSH_SYSCALL_CONTEXT;

typedef SH_HOOK_RESULT (*SH_HOOK_CALLBACK)(
    _In_ PSH_SYSCALL_CONTEXT Context,
    _In_opt_ PVOID CallbackContext
);

typedef struct _SH_HOOK {
    ULONG SyscallNumber;
    CHAR SyscallName[64];
    SH_HOOK_CALLBACK PreCallback;
    SH_HOOK_CALLBACK PostCallback;
    PVOID CallbackContext;
    BOOLEAN Enabled;
    volatile LONG64 HitCount;
    LIST_ENTRY ListEntry;
} SH_HOOK, *PSH_HOOK;

typedef struct _SH_FRAMEWORK {
    BOOLEAN Initialized;
    
    // Hooks
    LIST_ENTRY HookList;
    EX_PUSH_LOCK HookLock;
    volatile LONG HookCount;
    
    // Fast lookup by syscall number
    PSH_HOOK HookTable[SH_MAX_HOOKS];
    
    // Original handlers
    PVOID OriginalHandlers[SH_MAX_HOOKS];
    
    struct {
        volatile LONG64 TotalCalls;
        volatile LONG64 Blocked;
        volatile LONG64 Modified;
        LARGE_INTEGER StartTime;
    } Stats;
} SH_FRAMEWORK, *PSH_FRAMEWORK;

NTSTATUS ShInitialize(_Out_ PSH_FRAMEWORK* Framework);
VOID ShShutdown(_Inout_ PSH_FRAMEWORK Framework);
NTSTATUS ShInstallHook(_In_ PSH_FRAMEWORK Framework, _In_ ULONG SyscallNumber, _In_opt_ SH_HOOK_CALLBACK PreCallback, _In_opt_ SH_HOOK_CALLBACK PostCallback, _In_opt_ PVOID Context, _Out_ PSH_HOOK* Hook);
NTSTATUS ShRemoveHook(_In_ PSH_FRAMEWORK Framework, _In_ PSH_HOOK Hook);
NTSTATUS ShEnableHook(_In_ PSH_FRAMEWORK Framework, _In_ PSH_HOOK Hook);
NTSTATUS ShDisableHook(_In_ PSH_FRAMEWORK Framework, _In_ PSH_HOOK Hook);
NTSTATUS ShInvokeCallbacks(_In_ PSH_FRAMEWORK Framework, _In_ PSH_SYSCALL_CONTEXT Context, _Out_ PSH_HOOK_RESULT Result);

#ifdef __cplusplus
}
#endif
