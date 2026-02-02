/**
 * ============================================================================
 * ShadowStrike NGAV - KERNEL TRANSACTION MONITOR IMPLEMENTATION
 * ============================================================================
 */
#include "KtmMonitor.h"

NTSTATUS ShadowKtmNotificationCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_CONTEXT TransactionContext,
    _In_ ULONG NotificationMask
) {
    // Stub implementation for Transaction Notifications
    return STATUS_SUCCESS;
}
