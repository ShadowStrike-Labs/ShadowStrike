/**
 * ============================================================================
 * ShadowStrike NGAV - KERNEL TRANSACTION MONITOR HEADER
 * ============================================================================
 * @brief Monitoring of NTFS Transactions (TxF) to detect Process Doppelganging.
 */
#ifndef SHADOWSTRIKE_KTM_MONITOR_H
#define SHADOWSTRIKE_KTM_MONITOR_H

#include <fltKernel.h>

NTSTATUS ShadowKtmNotificationCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_CONTEXT TransactionContext,
    _In_ ULONG NotificationMask
);

#endif
