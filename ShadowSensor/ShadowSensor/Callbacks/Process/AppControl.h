/*++
===============================================================================
ShadowStrike NGAV - APPLICATION CONTROL (EXECUTABLE ALLOWLISTING)
===============================================================================

@file AppControl.h
@brief Zero-trust execution model with hash, path, and signer-based policies.

Provides enterprise application allowlisting/blocklisting:
  - Hash-based allowlisting (SHA-256 verification before execution)
  - Path-based allowlisting (trusted directories)
  - Signer-based allowlisting (code signing certificate validation)
  - Policy modes: Audit, Enforce, Learning
  - DLL load control via ImageNotify integration
  - Parent-child chain validation

Integration Points:
  - ProcessNotify (create) → AcCheckProcessExecution()
  - ImageNotify → AcCheckImageLoad()
  - DriverEntry → AcInitialize() / AcShutdown()

MITRE ATT&CK Coverage:
  - M1038: Execution Prevention
  - T1059: Command and Scripting Interpreter
  - T1204: User Execution
  - T1072: Software Deployment Tools (unauthorized software)

@author ShadowStrike Security Team
@version 1.0.0
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#pragma once

#include <ntddk.h>

// ============================================================================
// POOL TAGS
// ============================================================================

#define AC_POOL_TAG             'cCAF'  // FACc - App Control
#define AC_RULE_POOL_TAG        'rCAF'  // FACr - Rule
#define AC_EVENT_POOL_TAG       'eCAF'  // FACe - Event

// ============================================================================
// CONFIGURATION
// ============================================================================

#define AC_MAX_HASH_RULES           8192
#define AC_MAX_PATH_RULES           512
#define AC_MAX_SIGNER_RULES         256
#define AC_HASH_SIZE                32          // SHA-256
#define AC_MAX_PATH_LENGTH          520
#define AC_MAX_SIGNER_NAME          256
#define AC_HASH_BUCKET_COUNT        256

// ============================================================================
// POLICY MODE
// ============================================================================

typedef enum _AC_POLICY_MODE {
    AcMode_Audit = 0,          // Log violations, do not block
    AcMode_Enforce,            // Block unauthorized executables
    AcMode_Learning            // Auto-add new executables to allowlist
} AC_POLICY_MODE;

// ============================================================================
// RULE TYPE
// ============================================================================

typedef enum _AC_RULE_TYPE {
    AcRule_HashAllow = 0,       // SHA-256 hash in allowlist
    AcRule_HashBlock,           // SHA-256 hash in blocklist
    AcRule_PathAllow,           // Path prefix in allowlist
    AcRule_PathBlock,           // Path prefix in blocklist
    AcRule_SignerAllow,         // Code signing certificate in allowlist
    AcRule_SignerBlock           // Code signing certificate in blocklist
} AC_RULE_TYPE;

// ============================================================================
// EXECUTION VERDICT
// ============================================================================

typedef enum _AC_VERDICT {
    AcVerdict_Allow = 0,        // Execution permitted
    AcVerdict_Block,            // Execution denied
    AcVerdict_Audit,            // Violation logged but allowed
    AcVerdict_Unknown           // No matching rule (default policy applies)
} AC_VERDICT;

// ============================================================================
// HASH RULE
// ============================================================================

typedef struct _AC_HASH_RULE {

    LIST_ENTRY Link;            // Hash bucket chain
    AC_RULE_TYPE RuleType;      // AcRule_HashAllow or AcRule_HashBlock
    UCHAR Hash[AC_HASH_SIZE];  // SHA-256 hash
    ULONG RuleId;
    LARGE_INTEGER CreatedTime;

    //
    // Optional description
    //
    WCHAR Description[64];

} AC_HASH_RULE, *PAC_HASH_RULE;

// ============================================================================
// PATH RULE
// ============================================================================

typedef struct _AC_PATH_RULE {

    LIST_ENTRY Link;
    AC_RULE_TYPE RuleType;
    UNICODE_STRING PathPrefix;
    WCHAR PathBuffer[AC_MAX_PATH_LENGTH];
    ULONG RuleId;

} AC_PATH_RULE, *PAC_PATH_RULE;

// ============================================================================
// STATISTICS
// ============================================================================

typedef struct _AC_STATISTICS {

    volatile LONG64 ExecutionsChecked;
    volatile LONG64 ExecutionsAllowed;
    volatile LONG64 ExecutionsBlocked;
    volatile LONG64 ExecutionsAudited;
    volatile LONG64 ImagesChecked;
    volatile LONG64 ImagesBlocked;
    volatile LONG64 RulesLearned;
    volatile LONG64 HashLookups;
    volatile LONG64 PathLookups;

} AC_STATISTICS, *PAC_STATISTICS;

// ============================================================================
// PUBLIC API — LIFECYCLE
// ============================================================================

_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
AcInitialize(VOID);

_IRQL_requires_(PASSIVE_LEVEL)
VOID
AcShutdown(VOID);

// ============================================================================
// PUBLIC API — EXECUTION CHECKS
// ============================================================================

/**
 * @brief Check if a process should be allowed to execute.
 *
 * Called from ProcessNotify callback on process creation.
 *
 * @param[in] ImageFileName     Full path of the executable image.
 * @param[in] ImageHash         Optional SHA-256 hash (NULL if not computed).
 * @param[in] ProcessId         New process ID.
 * @param[in] ParentProcessId   Parent process ID.
 *
 * @return AC_VERDICT indicating whether execution is permitted.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
AC_VERDICT
AcCheckProcessExecution(
    _In_ PCUNICODE_STRING ImageFileName,
    _In_opt_ const UCHAR* ImageHash,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentProcessId
    );

/**
 * @brief Check if a DLL/image load should be allowed.
 *
 * Called from ImageNotify callback.
 *
 * @param[in] ImageFileName     Full path of the image being loaded.
 * @param[in] ProcessId         Process loading the image.
 *
 * @return AC_VERDICT indicating whether load is permitted.
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
AC_VERDICT
AcCheckImageLoad(
    _In_ PCUNICODE_STRING ImageFileName,
    _In_ HANDLE ProcessId
    );

// ============================================================================
// PUBLIC API — QUERY
// ============================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
AcGetStatistics(
    _Out_ PAC_STATISTICS Statistics
    );
