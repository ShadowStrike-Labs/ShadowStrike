/**
 * ============================================================================
 * ShadowStrike NGAV - SYNC UTILITIES
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_SPINLOCK_H_
#define _SHADOWSTRIKE_SPINLOCK_H_

#include <fltKernel.h>

//
// Simple wrapper for KSPIN_LOCK
//
typedef struct _SHADOWSTRIKE_LOCK {
    KSPIN_LOCK Lock;
    KIRQL OldIrql;
} SHADOWSTRIKE_LOCK, *PSHADOWSTRIKE_LOCK;

FORCEINLINE
VOID
ShadowStrikeInitializeLock(
    _Out_ PSHADOWSTRIKE_LOCK Lock
    )
{
    KeInitializeSpinLock(&Lock->Lock);
}

FORCEINLINE
VOID
ShadowStrikeAcquireLock(
    _Inout_ PSHADOWSTRIKE_LOCK Lock
    )
{
    KeAcquireSpinLock(&Lock->Lock, &Lock->OldIrql);
}

FORCEINLINE
VOID
ShadowStrikeReleaseLock(
    _Inout_ PSHADOWSTRIKE_LOCK Lock
    )
{
    KeReleaseSpinLock(&Lock->Lock, Lock->OldIrql);
}

#endif // _SHADOWSTRIKE_SPINLOCK_H_
