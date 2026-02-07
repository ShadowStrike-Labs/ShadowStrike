/**
 * ============================================================================
 * ShadowStrike NGAV - PROCESS NOTIFICATION IMPLEMENTATION
 * ============================================================================
 *
 * @file ProcessNotify.c
 * @brief Implementation of process creation/termination interception.
 *
 * Implements the PsSetCreateProcessNotifyRoutineEx callback.
 *
 * Key responsibilities:
 * 1. Capture process details (PID, Parent PID, Command Line, Image Path)
 * 2. Send synchronization message to user-mode service
 * 3. Enforce blocking verdicts (STATUS_ACCESS_DENIED)
 * 4. Handle process termination events
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "ProcessNotify.h"
#include "../../Core/Globals.h"
#include "../../Communication/CommPort.h"

// ============================================================================
// IMPLEMENTATION
// ============================================================================

VOID
ShadowStrikeProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    NTSTATUS status;
    PSHADOWSTRIKE_PROCESS_NOTIFICATION notification = NULL;
    ULONG notificationSize = 0;
    PSHADOWSTRIKE_PROCESS_VERDICT_REPLY reply = NULL;
    ULONG replySize = sizeof(SHADOWSTRIKE_PROCESS_VERDICT_REPLY);
    BOOLEAN isCreation = (CreateInfo != NULL);
    BOOLEAN requireReply = FALSE;

    //
    // 1. Validation and State Checks
    //
    UNREFERENCED_PARAMETER(Process);

    // Always increment stats regardless of driver state
    if (isCreation) {
        SHADOWSTRIKE_INC_STAT(TotalProcessCreations);
    }

    // Check if we should process this event
    if (!SHADOWSTRIKE_IS_READY() ||
        !g_DriverData.Config.ProcessMonitorEnabled) {
        return;
    }

    // Ensure we don't block the driver unload
    SHADOWSTRIKE_ENTER_OPERATION();

    //
    // 2. Prepare Data
    //

    // Calculate sizes for variable data
    USHORT imagePathLen = 0;
    USHORT cmdLineLen = 0;

    if (isCreation) {
        if (CreateInfo->ImageFileName) {
            imagePathLen = CreateInfo->ImageFileName->Length;
        }

        if (CreateInfo->CommandLine) {
            cmdLineLen = CreateInfo->CommandLine->Length;
        }

        // Determine if we need to block/wait for verdict
        // We only wait if user mode is connected AND configured to block
        // (If not blocking on error/timeout, we can still send async)
        if (SHADOWSTRIKE_USER_MODE_CONNECTED()) {
            requireReply = TRUE;
        }
    }

    //
    // 3. Allocate Message Buffer
    //

    // Calculate total size
    notificationSize = sizeof(SHADOWSTRIKE_PROCESS_NOTIFICATION) +
                       imagePathLen +
                       cmdLineLen;

    // Use lookaside list for performance
    // Note: If size > SHADOWSTRIKE_MAX_MESSAGE_SIZE, AllocateMessageBuffer handles it
    // by falling back to pool allocation.
    // We cap size to 64KB - overhead to be safe
    if (notificationSize > SHADOWSTRIKE_MAX_MESSAGE_SIZE) {
        ULONG maxData = SHADOWSTRIKE_MAX_MESSAGE_SIZE - sizeof(SHADOWSTRIKE_PROCESS_NOTIFICATION);

        if (imagePathLen > maxData) {
            imagePathLen = (USHORT)maxData;
            cmdLineLen = 0;
        } else if ((ULONG)imagePathLen + cmdLineLen > maxData) {
            cmdLineLen = (USHORT)(maxData - imagePathLen);
        }
        notificationSize = SHADOWSTRIKE_MAX_MESSAGE_SIZE;
    }

    notification = (PSHADOWSTRIKE_PROCESS_NOTIFICATION)ShadowStrikeAllocateMessageBuffer(notificationSize);
    if (!notification) {
        SHADOWSTRIKE_INC_STAT(MessagesDropped);
        goto Cleanup;
    }

    RtlZeroMemory(notification, notificationSize);

    //
    // 4. Populate Notification Structure
    //

    notification->MessageId = SHADOWSTRIKE_NEXT_MESSAGE_ID();
    notification->IsCreation = isCreation ? 1 : 0;
    notification->RequiresVerdict = requireReply ? 1 : 0;
    notification->ProcessId = HandleToULong(ProcessId);
    notification->ParentProcessId = HandleToULong(PsGetCurrentProcessId());
    notification->CreatingThreadId = HandleToULong(PsGetCurrentThreadId());
    notification->SessionId = 0; // SeQuerySessionIdToken is not always available at passive/dispatch level easily without token

    if (isCreation) {
        notification->CreatingProcessId = HandleToULong(CreateInfo->CreatingThreadId.UniqueProcess);

        // Copy variable length data
        notification->ImagePathLength = imagePathLen;
        notification->CommandLineLength = cmdLineLen;

        PUCHAR bufferPtr = (PUCHAR)(notification + 1);

        // Safe string copy with truncation
        if (imagePathLen > 0 && CreateInfo->ImageFileName) {
            // Check remaining space carefully
            if ((ULONG_PTR)bufferPtr + imagePathLen <= (ULONG_PTR)notification + notificationSize) {
                RtlCopyMemory(bufferPtr, CreateInfo->ImageFileName->Buffer, imagePathLen);
                bufferPtr += imagePathLen;
            }
        }

        if (cmdLineLen > 0 && CreateInfo->CommandLine) {
            // Check remaining space carefully
            if ((ULONG_PTR)bufferPtr + cmdLineLen <= (ULONG_PTR)notification + notificationSize) {
                RtlCopyMemory(bufferPtr, CreateInfo->CommandLine->Buffer, cmdLineLen);
            }
        }
    } else {
        // Termination: we can capture exit code if needed, but PsSetCreateProcessNotifyRoutineEx
        // doesn't provide it directly in arguments.
        notification->ExitCode = 0;
    }

    //
    // 5. Send to User Mode
    //

    if (requireReply) {
        reply = (PSHADOWSTRIKE_PROCESS_VERDICT_REPLY)ShadowStrikeAllocateMessageBuffer(sizeof(SHADOWSTRIKE_PROCESS_VERDICT_REPLY));
        if (!reply) {
            // Memory pressure - fail open (allow execution)
            goto Cleanup;
        }
    }

    status = ShadowStrikeSendProcessNotification(
        notification,
        notificationSize,
        requireReply,
        reply,
        requireReply ? &replySize : NULL
    );

    //
    // 6. Handle Verdict (Creation Only)
    //

    if (isCreation && requireReply) {
        if (NT_SUCCESS(status)) {
            if (reply->Verdict == SHADOWSTRIKE_VERDICT_BLOCK) {
                // User mode requested block
                CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
                SHADOWSTRIKE_INC_STAT(ProcessesBlocked);

                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "[ShadowStrike] Blocked process creation: PID %lu\n",
                    notification->ProcessId);
            }
        } else {
            // Communication failed or timeout
            if (status == STATUS_TIMEOUT) {
                SHADOWSTRIKE_INC_STAT(ScanTimeouts);
                if (g_DriverData.Config.BlockOnTimeout) {
                    CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
                    SHADOWSTRIKE_INC_STAT(ProcessesBlocked);
                }
            } else {
                SHADOWSTRIKE_INC_STAT(ScanErrors);
                if (g_DriverData.Config.BlockOnError) {
                    CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
                    SHADOWSTRIKE_INC_STAT(ProcessesBlocked);
                }
            }
        }
    }

Cleanup:
    if (notification) {
        ShadowStrikeFreeMessageBuffer(notification);
    }
    if (reply) {
        ShadowStrikeFreeMessageBuffer(reply);
    }

    SHADOWSTRIKE_LEAVE_OPERATION();
}

NTSTATUS
ShadowStrikeInitializeProcessMonitoring(
    VOID
    )
{
    return STATUS_SUCCESS;
}

VOID
ShadowStrikeCleanupProcessMonitoring(
    VOID
    )
{
    // No specific cleanup needed beyond unregistering callback (handled in DriverEntry)
}
