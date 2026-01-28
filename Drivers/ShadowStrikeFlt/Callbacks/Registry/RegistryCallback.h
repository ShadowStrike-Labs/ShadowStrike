/**
 * ============================================================================
 * ShadowStrike NGAV - REGISTRY CALLBACKS
 * ============================================================================
 *
 * @file RegistryCallback.h
 * @brief Registry filtering and monitoring.
 *
 * Handles CmRegisterCallbackEx callbacks to detect:
 * - Persistence mechanisms (Run keys, Services)
 * - Self-protection (Tampering with AV keys)
 * - Malicious configuration changes
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_REGISTRY_CALLBACK_H
#define SHADOWSTRIKE_REGISTRY_CALLBACK_H

#include <ntddk.h>

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * @brief Maximum registry path length to track.
 */
#define SHADOWSTRIKE_MAX_REG_PATH_LENGTH    512

/**
 * @brief Service registry path prefix.
 */
#define SHADOWSTRIKE_REG_SERVICES_PATH      L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services"

/**
 * @brief Run key path.
 */
#define SHADOWSTRIKE_REG_RUN_KEY            L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

/**
 * @brief RunOnce key path.
 */
#define SHADOWSTRIKE_REG_RUNONCE_KEY        L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"

/**
 * @brief ShadowStrike service name.
 */
#define SHADOWSTRIKE_SERVICE_NAME           L"ShadowStrikeFlt"

// ============================================================================
// FUNCTION PROTOTYPES
// ============================================================================

/**
 * @brief Main registry callback routine.
 *
 * @param CallbackContext Context provided at registration.
 * @param Argument1       Operation type (REG_NOTIFY_CLASS).
 * @param Argument2       Operation specific data.
 * @return STATUS_SUCCESS or error status.
 */
NTSTATUS
ShadowStrikeRegistryCallbackRoutine(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    );

/**
 * @brief Check if registry operation should be blocked for self-protection.
 *
 * @param RegistryPath  Full path of the key.
 * @param ProcessId     Requesting process ID.
 * @return TRUE if access should be denied.
 */
BOOLEAN
ShadowStrikeCheckRegistrySelfProtection(
    _In_ PUNICODE_STRING RegistryPath,
    _In_ HANDLE ProcessId
    );

/**
 * @brief Analyze registry write for persistence mechanisms.
 *
 * @param RegistryPath  Full path of the key.
 * @param ValueName     Name of the value being written.
 * @param Data          Data being written.
 * @param DataSize      Size of data.
 * @param DataType      Type of data (REG_SZ, etc.).
 */
VOID
ShadowStrikeAnalyzeRegistryPersistence(
    _In_ PUNICODE_STRING RegistryPath,
    _In_ PUNICODE_STRING ValueName,
    _In_ PVOID Data,
    _In_ ULONG DataSize,
    _In_ ULONG DataType
    );

#endif // SHADOWSTRIKE_REGISTRY_CALLBACK_H
