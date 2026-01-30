/**
 * ============================================================================
 * ShadowStrike NGAV - WORK QUEUE
 * ============================================================================
 */

#ifndef _SHADOWSTRIKE_WORK_QUEUE_H_
#define _SHADOWSTRIKE_WORK_QUEUE_H_

#include <fltKernel.h>

typedef VOID (*PFN_SHADOWSTRIKE_WORK_ROUTINE)(_In_ PVOID Context);

NTSTATUS
ShadowStrikeQueueWorkItem(
    _In_ PFN_SHADOWSTRIKE_WORK_ROUTINE Routine,
    _In_ PVOID Context
    );

#endif // _SHADOWSTRIKE_WORK_QUEUE_H_
