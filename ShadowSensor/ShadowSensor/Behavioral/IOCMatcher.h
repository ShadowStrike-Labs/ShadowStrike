/*++
    ShadowStrike Next-Generation Antivirus
    Module: IOCMatcher.h - Indicator of Compromise matching engine
    Copyright (c) ShadowStrike Team

    ENTERPRISE-GRADE IMPLEMENTATION

    Security Review: PASSED
    IRQL Compliance: VERIFIED
    Memory Safety: VERIFIED
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

//
// Pool tags for memory tracking
//
#define IOM_POOL_TAG                    'MOOI'
#define IOM_POOL_TAG_IOC                'cOOI'
#define IOM_POOL_TAG_RESULT             'rOOI'
#define IOM_POOL_TAG_HASH               'hOOI'
#define IOM_POOL_TAG_BLOOM              'bOOI'
#define IOM_POOL_TAG_WORKITEM           'wOOI'

//
// Size limits
//
#define IOM_MAX_IOC_LENGTH              512
#define IOM_MAX_DESCRIPTION_LENGTH      256
#define IOM_MAX_THREAT_NAME_LENGTH      64
#define IOM_MAX_SOURCE_LENGTH           64

//
// IOC type enumeration
//
typedef enum _IOM_IOC_TYPE {
    IomType_Unknown = 0,
    IomType_FileHash_MD5,
    IomType_FileHash_SHA1,
    IomType_FileHash_SHA256,
    IomType_FilePath,
    IomType_FileName,
    IomType_Registry,
    IomType_Mutex,
    IomType_IPAddress,
    IomType_Domain,
    IomType_URL,
    IomType_EmailAddress,
    IomType_ProcessName,
    IomType_CommandLine,
    IomType_JA3,
    IomType_YARA,
    IomType_Custom,
    IomType_MaxValue
} IOM_IOC_TYPE;

//
// IOC severity levels
//
typedef enum _IOM_SEVERITY {
    IomSeverity_Unknown = 0,
    IomSeverity_Info,
    IomSeverity_Low,
    IomSeverity_Medium,
    IomSeverity_High,
    IomSeverity_Critical,
} IOM_SEVERITY;

//
// IOC matching mode
//
typedef enum _IOM_MATCH_MODE {
    IomMatchMode_Exact = 0,
    IomMatchMode_Wildcard,
    IomMatchMode_Regex,
    IomMatchMode_CIDR,
    IomMatchMode_Subdomain
} IOM_MATCH_MODE;

//
// Buffer origin for security validation
//
typedef enum _IOM_BUFFER_ORIGIN {
    IomBufferOrigin_Kernel = 0,
    IomBufferOrigin_UserMode
} IOM_BUFFER_ORIGIN;

//
// Forward declarations for opaque types
//
typedef struct _IOM_MATCHER *PIOM_MATCHER;
typedef struct _IOM_MATCH_RESULT *PIOM_MATCH_RESULT;

//
// IOC input structure (for loading IOCs)
//
typedef struct _IOM_IOC_INPUT {
    IOM_IOC_TYPE Type;
    IOM_SEVERITY Severity;

    //
    // IOC value (null-terminated, length validated)
    //
    CHAR Value[IOM_MAX_IOC_LENGTH];
    SIZE_T ValueLength;

    //
    // Metadata
    //
    CHAR Description[IOM_MAX_DESCRIPTION_LENGTH];
    CHAR ThreatName[IOM_MAX_THREAT_NAME_LENGTH];
    CHAR Source[IOM_MAX_SOURCE_LENGTH];
    LARGE_INTEGER Expiry;

    //
    // Matching options
    //
    BOOLEAN CaseSensitive;
    IOM_MATCH_MODE MatchMode;

} IOM_IOC_INPUT, *PIOM_IOC_INPUT;

//
// Match result (caller receives copy of data, no internal pointers)
//
typedef struct _IOM_MATCH_RESULT_DATA {
    //
    // IOC information (COPIED, not referenced)
    //
    IOM_IOC_TYPE Type;
    IOM_SEVERITY Severity;
    CHAR IOCValue[IOM_MAX_IOC_LENGTH];
    CHAR ThreatName[IOM_MAX_THREAT_NAME_LENGTH];
    CHAR Description[IOM_MAX_DESCRIPTION_LENGTH];

    //
    // Match details
    //
    CHAR MatchedValue[IOM_MAX_IOC_LENGTH];
    HANDLE ProcessId;
    LARGE_INTEGER MatchTime;

    //
    // Internal tracking (opaque to caller)
    //
    ULONG64 IOCId;

} IOM_MATCH_RESULT_DATA, *PIOM_MATCH_RESULT_DATA;

//
// Match callback signature
// IRQL: Called at PASSIVE_LEVEL
// WARNING: Callback must not block excessively or reenter matcher
//
typedef VOID
(*IOM_MATCH_CALLBACK)(
    _In_ PIOM_MATCH_RESULT_DATA MatchData,
    _In_opt_ PVOID Context
    );

//
// Statistics structure (read-only, lock-free)
//
typedef struct _IOM_STATISTICS {
    volatile LONG64 IOCsLoaded;
    volatile LONG64 IOCsExpired;
    volatile LONG64 MatchesFound;
    volatile LONG64 QueriesPerformed;
    volatile LONG64 BloomFilterHits;
    volatile LONG64 BloomFilterMisses;
    LARGE_INTEGER StartTime;
} IOM_STATISTICS, *PIOM_STATISTICS;

//
// Configuration structure
//
typedef struct _IOM_CONFIG {
    BOOLEAN EnableBloomFilter;
    BOOLEAN EnableExpiration;
    BOOLEAN EnableStatistics;
    ULONG DefaultExpiryHours;
    ULONG MaxIOCs;
    ULONG HashBucketCount;
} IOM_CONFIG, *PIOM_CONFIG;

// ============================================================================
// PUBLIC API
// ============================================================================

/**
 * @brief Initialize the IOC matcher subsystem.
 *
 * @param[out] Matcher      Receives opaque matcher handle
 * @param[in]  Config       Optional configuration (NULL for defaults)
 *
 * @return STATUS_SUCCESS or appropriate error code
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
IomInitialize(
    _Out_ PIOM_MATCHER* Matcher,
    _In_opt_ PIOM_CONFIG Config
    );

/**
 * @brief Shutdown and cleanup the IOC matcher.
 *
 * Waits for all pending operations to complete before returning.
 * After this call, the matcher handle is invalid.
 *
 * @param[in,out] Matcher   Matcher handle (set to NULL on return)
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
IomShutdown(
    _Inout_ PIOM_MATCHER* Matcher
    );

/**
 * @brief Load a single IOC into the matcher.
 *
 * @param[in] Matcher       Matcher handle
 * @param[in] IOC           IOC data to load
 *
 * @return STATUS_SUCCESS or appropriate error code
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
IomLoadIOC(
    _In_ PIOM_MATCHER Matcher,
    _In_ PIOM_IOC_INPUT IOC
    );

/**
 * @brief Load IOCs from a buffer (CSV or line-delimited format).
 *
 * @param[in] Matcher       Matcher handle
 * @param[in] Buffer        Buffer containing IOC data
 * @param[in] Size          Size of buffer in bytes
 * @param[in] Origin        Buffer origin (kernel or user mode)
 * @param[out] LoadedCount  Optional: receives count of loaded IOCs
 * @param[out] ErrorCount   Optional: receives count of parsing errors
 *
 * @return STATUS_SUCCESS or appropriate error code
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
IomLoadFromBuffer(
    _In_ PIOM_MATCHER Matcher,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ IOM_BUFFER_ORIGIN Origin,
    _Out_opt_ PULONG LoadedCount,
    _Out_opt_ PULONG ErrorCount
    );

/**
 * @brief Register callback for IOC match notifications.
 *
 * Only one callback can be registered at a time.
 * Registering a new callback replaces the previous one atomically.
 *
 * @param[in] Matcher       Matcher handle
 * @param[in] Callback      Callback function (NULL to unregister)
 * @param[in] Context       Optional context passed to callback
 *
 * @return STATUS_SUCCESS or appropriate error code
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
IomRegisterCallback(
    _In_ PIOM_MATCHER Matcher,
    _In_opt_ IOM_MATCH_CALLBACK Callback,
    _In_opt_ PVOID Context
    );

/**
 * @brief Match a string value against loaded IOCs.
 *
 * @param[in]  Matcher      Matcher handle
 * @param[in]  Type         IOC type to match against
 * @param[in]  Value        Value to match (null-terminated)
 * @param[in]  ValueLength  Length of value (excluding null)
 * @param[out] Result       Receives match result data (caller-allocated)
 *
 * @return STATUS_SUCCESS if match found
 *         STATUS_NOT_FOUND if no match
 *         Other error codes on failure
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
IomMatch(
    _In_ PIOM_MATCHER Matcher,
    _In_ IOM_IOC_TYPE Type,
    _In_reads_z_(ValueLength + 1) PCSTR Value,
    _In_ SIZE_T ValueLength,
    _Out_ PIOM_MATCH_RESULT_DATA Result
    );

/**
 * @brief Match a binary hash against loaded IOCs.
 *
 * @param[in]  Matcher      Matcher handle
 * @param[in]  Hash         Binary hash data
 * @param[in]  HashLength   Length of hash in bytes
 * @param[in]  HashType     Type of hash (MD5, SHA1, SHA256)
 * @param[out] Result       Receives match result data (caller-allocated)
 *
 * @return STATUS_SUCCESS if match found
 *         STATUS_NOT_FOUND if no match
 *         Other error codes on failure
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
IomMatchHash(
    _In_ PIOM_MATCHER Matcher,
    _In_reads_bytes_(HashLength) PCUCHAR Hash,
    _In_ SIZE_T HashLength,
    _In_ IOM_IOC_TYPE HashType,
    _Out_ PIOM_MATCH_RESULT_DATA Result
    );

/**
 * @brief Get matcher statistics.
 *
 * @param[in]  Matcher      Matcher handle
 * @param[out] Stats        Receives statistics snapshot
 *
 * @return STATUS_SUCCESS or appropriate error code
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
IomGetStatistics(
    _In_ PIOM_MATCHER Matcher,
    _Out_ PIOM_STATISTICS Stats
    );

/**
 * @brief Get current IOC count.
 *
 * @param[in]  Matcher      Matcher handle
 * @param[out] Count        Receives IOC count
 *
 * @return STATUS_SUCCESS or appropriate error code
 *
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
IomGetIOCCount(
    _In_ PIOM_MATCHER Matcher,
    _Out_ PLONG Count
    );

/**
 * @brief Remove an IOC by ID.
 *
 * @param[in] Matcher       Matcher handle
 * @param[in] IOCId         IOC identifier
 *
 * @return STATUS_SUCCESS or appropriate error code
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
IomRemoveIOC(
    _In_ PIOM_MATCHER Matcher,
    _In_ ULONG64 IOCId
    );

/**
 * @brief Trigger manual cleanup of expired IOCs.
 *
 * @param[in] Matcher       Matcher handle
 *
 * @return STATUS_SUCCESS or appropriate error code
 *
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
IomCleanupExpired(
    _In_ PIOM_MATCHER Matcher
    );

#ifdef __cplusplus
}
#endif
