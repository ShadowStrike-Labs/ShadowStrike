/**
 * ============================================================================
 * ShadowStrike Real-Time - ACCESS CONTROL MANAGER (The Bouncer)
 * ============================================================================
 *
 * @file AccessControlManager.hpp
 * @brief Enterprise-grade access control and privilege management system.
 *
 * This module implements comprehensive access control for ShadowStrike,
 * including Role-Based Access Control (RBAC), privilege hardening, token
 * manipulation, integrity level management, and process sandboxing.
 *
 * Key Capabilities:
 * =================
 * 1. ROLE-BASED ACCESS CONTROL (RBAC)
 *    - Hierarchical role system (SuperAdmin → Admin → Analyst → User → Guest)
 *    - Granular permission model (100+ discrete permissions)
 *    - Dynamic role assignment based on AD group membership
 *    - Multi-tenant support for MSP deployments
 *    - Session-based temporary privilege elevation
 *
 * 2. PRIVILEGE HARDENING
 *    - Dangerous privilege stripping (SeDebugPrivilege, SeTcbPrivilege, etc.)
 *    - Token integrity level enforcement
 *    - Restricted token creation for sandboxing
 *    - ACL manipulation for process isolation
 *    - Job object enforcement for resource limits
 *
 * 3. PROCESS PROTECTION
 *    - Anti-tampering for ShadowStrike processes
 *    - PPL (Protected Process Light) integration
 *    - Handle protection against external access
 *    - Thread creation blocking for protected processes
 *    - Memory protection via integrity levels
 *
 * 4. USER SESSION MANAGEMENT
 *    - Session isolation and tracking
 *    - Credential caching with secure storage
 *    - Multi-factor authentication integration
 *    - Session timeout and renewal
 *    - Audit trail for all access decisions
 *
 * 5. SECURITY BOUNDARY ENFORCEMENT
 *    - AppContainer compatibility
 *    - LPAC (Less Privileged AppContainer) support
 *    - Capability SID management
 *    - Mandatory Integrity Control (MIC)
 *    - Process attribute enforcement
 *
 * Windows Security Concepts Used:
 * ===============================
 * - Security Identifiers (SIDs): User/group identification
 * - Access Tokens: Security context for processes/threads
 * - Security Descriptors: Object access control
 * - Privileges: Special rights beyond normal access
 * - Integrity Levels: Mandatory access control
 * - Restricted Tokens: Reduced capability tokens
 * - Job Objects: Process grouping and limits
 * - Protected Processes: Kernel-enforced protection
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1134: Access Token Manipulation (Defense)
 * - T1548: Abuse Elevation Control Mechanism (Prevention)
 * - T1078: Valid Accounts (Monitoring)
 * - T1098: Account Manipulation (Detection)
 * - T1484: Domain Policy Modification (Auditing)
 * - T1562.001: Impair Defenses - Disable Tools (Protection)
 *
 * Architecture:
 * =============
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                    AccessControlManager                             │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │ RoleManager  │  │PermissionDB │  │  PrivilegeHardener       │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Roles      │  │ - Grants     │  │ - TokenManipulation      │  │
 *   │  │ - Hierarchy  │  │ - Denies     │  │ - IntegrityLevels        │  │
 *   │  │ - Mappings   │  │ - Audit      │  │ - JobObjects             │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │SessionManager│  │ AuditLogger  │  │  ProcessProtector        │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Sessions   │  │ - Events     │  │ - HandleProtection       │  │
 *   │  │ - MFA        │  │ - Compliance │  │ - PPLIntegration         │  │
 *   │  │ - Timeouts   │  │ - Alerts     │  │ - AntiTampering          │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * Thread Safety:
 * ==============
 * - All public methods are thread-safe
 * - Uses std::shared_mutex for read-heavy workloads
 * - Atomic operations for statistics
 * - Lock-free fast paths where possible
 *
 * Performance Considerations:
 * ===========================
 * - Permission checks cached per-session
 * - SID resolution cached with TTL
 * - Lazy evaluation of group memberships
 * - Background refresh of stale caches
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see Utils/SecurityUtils.hpp for low-level Windows security helpers
 * @see ThreatIntel/ThreatIntelManager.hpp for reputation-based decisions
 * @see Whitelist/WhitelistManager.hpp for trusted process lists
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../Utils/ProcessUtils.hpp"          // Process context
#include "../Utils/SystemUtils.hpp"           // System security settings
#include "../Whitelist/WhiteListStore.hpp"    // Trusted processes

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <set>
#include <optional>
#include <variant>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <shared_mutex>
#include <bitset>
#include <span>

// ============================================================================
// WINDOWS INCLUDES (Forward declarations to minimize header pollution)
// ============================================================================
// Note: Implementation file will include full Windows headers
struct _SID;
struct _TOKEN_PRIVILEGES;
struct _SECURITY_DESCRIPTOR;

namespace ShadowStrike {
namespace RealTime {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class AccessControlManagerImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace AccessControlConstants {

    // Version information
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Permission system limits
    constexpr size_t MAX_PERMISSIONS = 256;
    constexpr size_t MAX_ROLES = 64;
    constexpr size_t MAX_SESSIONS_PER_USER = 16;
    constexpr size_t MAX_GROUP_MEMBERSHIPS = 256;
    constexpr size_t MAX_PRIVILEGE_COUNT = 36;  // Windows privilege count
    constexpr size_t MAX_CAPABILITY_SIDS = 64;

    // Cache settings
    constexpr size_t SID_CACHE_SIZE = 10000;
    constexpr size_t PERMISSION_CACHE_SIZE = 50000;
    constexpr size_t GROUP_CACHE_SIZE = 5000;

    // Timeouts (milliseconds)
    constexpr uint32_t DEFAULT_SESSION_TIMEOUT_MS = 3600000;     // 1 hour
    constexpr uint32_t ELEVATED_SESSION_TIMEOUT_MS = 900000;     // 15 minutes
    constexpr uint32_t MFA_CHALLENGE_TIMEOUT_MS = 300000;        // 5 minutes
    constexpr uint32_t CACHE_TTL_MS = 60000;                     // 1 minute
    constexpr uint32_t AD_SYNC_INTERVAL_MS = 300000;             // 5 minutes

    // Integrity levels (Windows standard values)
    constexpr uint32_t INTEGRITY_UNTRUSTED = 0x0000;
    constexpr uint32_t INTEGRITY_LOW = 0x1000;
    constexpr uint32_t INTEGRITY_MEDIUM = 0x2000;
    constexpr uint32_t INTEGRITY_MEDIUM_PLUS = 0x2100;
    constexpr uint32_t INTEGRITY_HIGH = 0x3000;
    constexpr uint32_t INTEGRITY_SYSTEM = 0x4000;
    constexpr uint32_t INTEGRITY_PROTECTED_PROCESS = 0x5000;

    // Job object limits
    constexpr uint64_t DEFAULT_MEMORY_LIMIT_BYTES = 512ULL * 1024 * 1024;  // 512 MB
    constexpr uint32_t DEFAULT_PROCESS_LIMIT = 10;
    constexpr uint32_t DEFAULT_CPU_RATE_LIMIT = 50;  // 50% CPU

    // Well-known SIDs (string format for readability)
    constexpr std::wstring_view SID_EVERYONE = L"S-1-1-0";
    constexpr std::wstring_view SID_LOCAL_SYSTEM = L"S-1-5-18";
    constexpr std::wstring_view SID_LOCAL_SERVICE = L"S-1-5-19";
    constexpr std::wstring_view SID_NETWORK_SERVICE = L"S-1-5-20";
    constexpr std::wstring_view SID_ADMINISTRATORS = L"S-1-5-32-544";
    constexpr std::wstring_view SID_USERS = L"S-1-5-32-545";
    constexpr std::wstring_view SID_GUESTS = L"S-1-5-32-546";
    constexpr std::wstring_view SID_TRUSTED_INSTALLER = L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

}  // namespace AccessControlConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum RoleType
 * @brief Predefined roles in the RBAC hierarchy.
 * 
 * Roles form a strict hierarchy where higher roles inherit all permissions
 * from lower roles. Custom roles can be created between predefined levels.
 */
enum class RoleType : uint8_t {
    // System roles (cannot be modified)
    SYSTEM = 0,              ///< Internal system operations (highest)
    KERNEL = 1,              ///< Kernel driver context

    // Administrative roles
    SUPER_ADMIN = 10,        ///< Full control, can modify RBAC itself
    TENANT_ADMIN = 15,       ///< MSP: Full control within tenant
    SECURITY_ADMIN = 20,     ///< Security policy management
    IT_ADMIN = 25,           ///< General IT administration

    // Operational roles
    SOC_ANALYST_L3 = 30,     ///< Senior SOC analyst
    SOC_ANALYST_L2 = 35,     ///< SOC analyst
    SOC_ANALYST_L1 = 40,     ///< Junior SOC analyst
    INCIDENT_RESPONDER = 45, ///< Incident response specialist

    // Standard roles
    POWER_USER = 50,         ///< Advanced end user
    STANDARD_USER = 60,      ///< Normal authenticated user
    GUEST = 70,              ///< Limited guest access
    RESTRICTED = 80,         ///< Heavily restricted access

    // Special roles
    SERVICE_ACCOUNT = 90,    ///< Automated service identity
    API_CLIENT = 91,         ///< External API consumer
    AUDITOR = 92,            ///< Read-only audit access

    // Custom role range
    CUSTOM_START = 100,      ///< Start of custom role IDs
    CUSTOM_END = 199,        ///< End of custom role IDs

    INVALID = 255            ///< Invalid/unassigned role
};

/**
 * @enum Permission
 * @brief Granular permissions for RBAC enforcement.
 * 
 * Permissions are organized by category for clarity.
 * Each permission is a single capability that can be granted or denied.
 */
enum class Permission : uint16_t {
    // ========================================================================
    // SCAN PERMISSIONS (0-19)
    // ========================================================================
    SCAN_ON_DEMAND = 0,              ///< Run manual scans
    SCAN_QUICK = 1,                  ///< Run quick scans
    SCAN_FULL = 2,                   ///< Run full system scans
    SCAN_CUSTOM = 3,                 ///< Run custom path scans
    SCAN_MEMORY = 4,                 ///< Scan process memory
    SCAN_BOOT_SECTOR = 5,            ///< Scan boot sectors
    SCAN_SCHEDULED_CREATE = 6,       ///< Create scheduled scans
    SCAN_SCHEDULED_MODIFY = 7,       ///< Modify scheduled scans
    SCAN_SCHEDULED_DELETE = 8,       ///< Delete scheduled scans
    SCAN_CANCEL = 9,                 ///< Cancel running scans
    SCAN_VIEW_HISTORY = 10,          ///< View scan history

    // ========================================================================
    // QUARANTINE PERMISSIONS (20-39)
    // ========================================================================
    QUARANTINE_VIEW = 20,            ///< View quarantined items
    QUARANTINE_RESTORE = 21,         ///< Restore quarantined items
    QUARANTINE_DELETE = 22,          ///< Permanently delete quarantined items
    QUARANTINE_DOWNLOAD = 23,        ///< Download quarantined samples
    QUARANTINE_SUBMIT = 24,          ///< Submit samples for analysis
    QUARANTINE_EXCLUDE = 25,         ///< Add quarantine exclusions

    // ========================================================================
    // CONFIGURATION PERMISSIONS (40-69)
    // ========================================================================
    CONFIG_VIEW = 40,                ///< View configuration
    CONFIG_REALTIME_MODIFY = 41,     ///< Modify real-time protection settings
    CONFIG_SCAN_MODIFY = 42,         ///< Modify scan settings
    CONFIG_EXCLUSION_VIEW = 43,      ///< View exclusions
    CONFIG_EXCLUSION_ADD = 44,       ///< Add exclusions
    CONFIG_EXCLUSION_REMOVE = 45,    ///< Remove exclusions
    CONFIG_NETWORK_MODIFY = 46,      ///< Modify network settings
    CONFIG_BEHAVIOR_MODIFY = 47,     ///< Modify behavior analysis settings
    CONFIG_HEURISTIC_MODIFY = 48,    ///< Modify heuristic settings
    CONFIG_UPDATE_MODIFY = 49,       ///< Modify update settings
    CONFIG_CLOUD_MODIFY = 50,        ///< Modify cloud connectivity settings
    CONFIG_EXPORT = 51,              ///< Export configuration
    CONFIG_IMPORT = 52,              ///< Import configuration
    CONFIG_RESET = 53,               ///< Reset to defaults

    // ========================================================================
    // PROTECTION CONTROL PERMISSIONS (70-89)
    // ========================================================================
    PROTECTION_ENABLE = 70,          ///< Enable protection components
    PROTECTION_DISABLE = 71,         ///< Disable protection components
    PROTECTION_PAUSE = 72,           ///< Temporarily pause protection
    PROTECTION_TAMPER_MODIFY = 73,   ///< Modify tamper protection settings
    PROTECTION_SELF_DEFENSE = 74,    ///< Access self-defense features

    // ========================================================================
    // UPDATE PERMISSIONS (90-99)
    // ========================================================================
    UPDATE_CHECK = 90,               ///< Check for updates
    UPDATE_DOWNLOAD = 91,            ///< Download updates
    UPDATE_INSTALL = 92,             ///< Install updates
    UPDATE_ROLLBACK = 93,            ///< Rollback updates
    UPDATE_SCHEDULE = 94,            ///< Schedule update times

    // ========================================================================
    // LOG AND AUDIT PERMISSIONS (100-119)
    // ========================================================================
    LOG_VIEW_DETECTIONS = 100,       ///< View detection logs
    LOG_VIEW_EVENTS = 101,           ///< View event logs
    LOG_VIEW_AUDIT = 102,            ///< View audit logs
    LOG_EXPORT = 103,                ///< Export logs
    LOG_CLEAR = 104,                 ///< Clear logs
    LOG_CONFIGURE = 105,             ///< Configure logging settings

    // ========================================================================
    // THREAT INTELLIGENCE PERMISSIONS (120-139)
    // ========================================================================
    THREATINTEL_VIEW = 120,          ///< View threat intelligence data
    THREATINTEL_QUERY = 121,         ///< Query threat intelligence
    THREATINTEL_ADD_IOC = 122,       ///< Add custom IOCs
    THREATINTEL_REMOVE_IOC = 123,    ///< Remove custom IOCs
    THREATINTEL_IMPORT = 124,        ///< Import threat feeds
    THREATINTEL_EXPORT = 125,        ///< Export threat data

    // ========================================================================
    // WHITELIST PERMISSIONS (140-159)
    // ========================================================================
    WHITELIST_VIEW = 140,            ///< View whitelists
    WHITELIST_ADD = 141,             ///< Add to whitelist
    WHITELIST_REMOVE = 142,          ///< Remove from whitelist
    WHITELIST_IMPORT = 143,          ///< Import whitelist
    WHITELIST_EXPORT = 144,          ///< Export whitelist

    // ========================================================================
    // RESPONSE PERMISSIONS (160-179)
    // ========================================================================
    RESPONSE_TERMINATE_PROCESS = 160, ///< Terminate suspicious processes
    RESPONSE_ISOLATE_NETWORK = 161,   ///< Isolate endpoint from network
    RESPONSE_BLOCK_FILE = 162,        ///< Block file execution
    RESPONSE_REMEDIATE_AUTO = 163,    ///< Enable auto-remediation
    RESPONSE_COLLECT_FORENSICS = 164, ///< Collect forensic data
    RESPONSE_EXECUTE_SCRIPT = 165,    ///< Execute response scripts

    // ========================================================================
    // ADMINISTRATION PERMISSIONS (180-199)
    // ========================================================================
    ADMIN_USER_VIEW = 180,           ///< View user accounts
    ADMIN_USER_CREATE = 181,         ///< Create user accounts
    ADMIN_USER_MODIFY = 182,         ///< Modify user accounts
    ADMIN_USER_DELETE = 183,         ///< Delete user accounts
    ADMIN_ROLE_VIEW = 184,           ///< View roles
    ADMIN_ROLE_CREATE = 185,         ///< Create custom roles
    ADMIN_ROLE_MODIFY = 186,         ///< Modify roles
    ADMIN_ROLE_DELETE = 187,         ///< Delete custom roles
    ADMIN_TENANT_VIEW = 188,         ///< View tenant configuration
    ADMIN_TENANT_MODIFY = 189,       ///< Modify tenant configuration
    ADMIN_LICENSE_VIEW = 190,        ///< View license information
    ADMIN_LICENSE_MODIFY = 191,      ///< Modify license settings

    // ========================================================================
    // SYSTEM PERMISSIONS (200-219)
    // ========================================================================
    SYSTEM_SERVICE_CONTROL = 200,    ///< Control ShadowStrike service
    SYSTEM_DRIVER_CONTROL = 201,     ///< Control kernel driver
    SYSTEM_DEBUG = 202,              ///< Access debug features
    SYSTEM_DIAGNOSTIC = 203,         ///< Run diagnostics
    SYSTEM_UNINSTALL = 204,          ///< Uninstall ShadowStrike

    // ========================================================================
    // API PERMISSIONS (220-239)
    // ========================================================================
    API_READ = 220,                  ///< Read API access
    API_WRITE = 221,                 ///< Write API access
    API_ADMIN = 222,                 ///< Administrative API access
    API_WEBHOOK_CONFIGURE = 223,     ///< Configure webhooks
    API_KEY_MANAGE = 224,            ///< Manage API keys

    // Special
    PERMISSION_COUNT = 240,          ///< Total permission count
    INVALID_PERMISSION = 255         ///< Invalid permission marker
};

/**
 * @enum PrivilegeAction
 * @brief Actions that can be taken on Windows privileges.
 */
enum class PrivilegeAction : uint8_t {
    QUERY = 0,          ///< Query privilege status
    ENABLE = 1,         ///< Enable privilege
    DISABLE = 2,        ///< Disable privilege
    REMOVE = 3          ///< Permanently remove from token
};

/**
 * @enum WindowsPrivilege
 * @brief Windows security privileges that can be managed.
 */
enum class WindowsPrivilege : uint8_t {
    SE_CREATE_TOKEN = 0,
    SE_ASSIGN_PRIMARY_TOKEN = 1,
    SE_LOCK_MEMORY = 2,
    SE_INCREASE_QUOTA = 3,
    SE_MACHINE_ACCOUNT = 4,
    SE_TCB = 5,
    SE_SECURITY = 6,
    SE_TAKE_OWNERSHIP = 7,
    SE_LOAD_DRIVER = 8,
    SE_SYSTEM_PROFILE = 9,
    SE_SYSTEMTIME = 10,
    SE_PROF_SINGLE_PROCESS = 11,
    SE_INC_BASE_PRIORITY = 12,
    SE_CREATE_PAGEFILE = 13,
    SE_CREATE_PERMANENT = 14,
    SE_BACKUP = 15,
    SE_RESTORE = 16,
    SE_SHUTDOWN = 17,
    SE_DEBUG = 18,                   ///< Critical: Debug any process
    SE_AUDIT = 19,
    SE_SYSTEM_ENVIRONMENT = 20,
    SE_CHANGE_NOTIFY = 21,
    SE_REMOTE_SHUTDOWN = 22,
    SE_UNDOCK = 23,
    SE_SYNC_AGENT = 24,
    SE_ENABLE_DELEGATION = 25,
    SE_MANAGE_VOLUME = 26,
    SE_IMPERSONATE = 27,             ///< Critical: Impersonate tokens
    SE_CREATE_GLOBAL = 28,
    SE_TRUSTED_CREDMAN_ACCESS = 29,
    SE_RELABEL = 30,
    SE_INC_WORKING_SET = 31,
    SE_TIME_ZONE = 32,
    SE_CREATE_SYMBOLIC_LINK = 33,
    SE_DELEGATE_SESSION_USER_IMPERSONATE = 34,

    PRIVILEGE_COUNT = 35,
    INVALID_PRIVILEGE = 255
};

/**
 * @enum IntegrityLevel
 * @brief Windows Mandatory Integrity Control levels.
 */
enum class IntegrityLevel : uint8_t {
    UNTRUSTED = 0,       ///< Untrusted code (sandboxed)
    LOW = 1,             ///< Low integrity (browser tabs)
    MEDIUM = 2,          ///< Standard user processes
    MEDIUM_PLUS = 3,     ///< Elevated from medium
    HIGH = 4,            ///< Administrative processes
    SYSTEM = 5,          ///< System services
    PROTECTED = 6,       ///< Protected process (PPL)
    INVALID = 255
};

/**
 * @enum TokenType
 * @brief Types of access tokens that can be created.
 */
enum class TokenType : uint8_t {
    PRIMARY = 0,         ///< Primary token for process creation
    IMPERSONATION = 1,   ///< Impersonation token for thread
    RESTRICTED = 2,      ///< Restricted token with reduced rights
    FILTERED = 3,        ///< UAC filtered admin token
    LOWBOX = 4,          ///< AppContainer token
    LPAC = 5             ///< Less Privileged AppContainer
};

/**
 * @enum RestrictionType
 * @brief Types of restrictions that can be applied to processes.
 */
enum class RestrictionType : uint8_t {
    NONE = 0,
    PRIVILEGE_STRIP = 1,         ///< Remove dangerous privileges
    SID_RESTRICT = 2,            ///< Restrict SID access
    INTEGRITY_LOWER = 3,         ///< Lower integrity level
    JOB_OBJECT = 4,              ///< Apply job object limits
    DESKTOP_RESTRICT = 5,        ///< Restrict to separate desktop
    FULL_SANDBOX = 6,            ///< Full AppContainer sandbox
    CUSTOM = 7
};

/**
 * @enum SessionState
 * @brief States of a user authentication session.
 */
enum class SessionState : uint8_t {
    INACTIVE = 0,
    PENDING_MFA = 1,
    ACTIVE = 2,
    ELEVATED = 3,
    LOCKED = 4,
    EXPIRED = 5,
    REVOKED = 6
};

/**
 * @enum AuditEventType
 * @brief Types of audit events for access control.
 */
enum class AuditEventType : uint8_t {
    PERMISSION_GRANTED = 0,
    PERMISSION_DENIED = 1,
    ROLE_ASSIGNED = 2,
    ROLE_REVOKED = 3,
    SESSION_CREATED = 4,
    SESSION_EXPIRED = 5,
    SESSION_ELEVATED = 6,
    PRIVILEGE_MODIFIED = 7,
    PROCESS_RESTRICTED = 8,
    PROCESS_PROTECTED = 9,
    TAMPERING_BLOCKED = 10,
    MFA_SUCCESS = 11,
    MFA_FAILURE = 12,
    CONFIG_CHANGED = 13,
    INTEGRITY_LOWERED = 14
};

/**
 * @enum ProcessProtectionLevel
 * @brief Protection levels for ShadowStrike processes.
 */
enum class ProcessProtectionLevel : uint8_t {
    NONE = 0,
    STANDARD = 1,            ///< Basic handle protection
    ELEVATED = 2,            ///< + Thread creation blocking
    MAXIMUM = 3,             ///< + Memory protection
    PPL_ANTIMALWARE = 4,     ///< Windows PPL AM level
    PPL_WINDOWS = 5          ///< Windows PPL highest level
};

/**
 * @enum AccessDecision
 * @brief Result of an access control check.
 */
enum class AccessDecision : uint8_t {
    ALLOW = 0,
    DENY = 1,
    ALLOW_WITH_AUDIT = 2,
    DENY_WITH_ALERT = 3,
    REQUIRE_MFA = 4,
    REQUIRE_ELEVATION = 5,
    DELEGATE = 6             ///< Delegate to another authority
};

/**
 * @enum MFAMethod
 * @brief Supported multi-factor authentication methods.
 */
enum class MFAMethod : uint8_t {
    NONE = 0,
    TOTP = 1,                ///< Time-based OTP (Google Authenticator)
    PUSH = 2,                ///< Push notification
    SMS = 3,                 ///< SMS code
    EMAIL = 4,               ///< Email code
    HARDWARE_TOKEN = 5,      ///< Hardware security key (FIDO2)
    WINDOWS_HELLO = 6,       ///< Windows Hello
    SMARTCARD = 7            ///< Smart card/PIV
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct SecurityIdentifier
 * @brief Wrapper for Windows SID with utility methods.
 */
struct alignas(8) SecurityIdentifier {
    std::vector<uint8_t> binarySid;     ///< Raw SID bytes
    std::wstring stringSid;             ///< String representation (S-1-...)
    std::wstring accountName;           ///< Resolved account name
    std::wstring domainName;            ///< Domain if applicable
    bool isWellKnown{ false };          ///< Is this a well-known SID?
    bool isGroup{ false };              ///< Is this a group SID?
    bool isValid{ false };              ///< Successfully parsed?

    // Comparison operators for use in containers
    bool operator==(const SecurityIdentifier& other) const noexcept {
        return binarySid == other.binarySid;
    }

    bool operator<(const SecurityIdentifier& other) const noexcept {
        return binarySid < other.binarySid;
    }

    // Hash function for unordered containers
    struct Hash {
        size_t operator()(const SecurityIdentifier& sid) const noexcept;
    };
};

/**
 * @struct RoleDefinition
 * @brief Complete definition of a role in the RBAC system.
 */
struct alignas(64) RoleDefinition {
    // Identity
    uint32_t roleId{ 0 };
    RoleType type{ RoleType::INVALID };
    std::wstring name;
    std::wstring description;

    // Hierarchy
    uint32_t parentRoleId{ 0 };         ///< Inherits from this role
    uint8_t hierarchyLevel{ 0 };        ///< Position in hierarchy (0 = highest)

    // Permissions
    std::bitset<AccessControlConstants::MAX_PERMISSIONS> grantedPermissions;
    std::bitset<AccessControlConstants::MAX_PERMISSIONS> deniedPermissions;  ///< Explicit denies

    // Constraints
    bool requiresMFA{ false };
    bool allowsElevation{ false };
    uint32_t maxSessionDurationMs{ AccessControlConstants::DEFAULT_SESSION_TIMEOUT_MS };
    std::vector<std::wstring> allowedIPRanges;    ///< IP-based restrictions
    std::vector<std::wstring> allowedTimeRanges;  ///< Time-based restrictions

    // Multi-tenant
    uint32_t tenantId{ 0 };             ///< 0 = global role

    // Metadata
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point modifiedAt;
    std::wstring createdBy;
    bool isBuiltIn{ false };            ///< Cannot be deleted
    bool isEnabled{ true };
};

/**
 * @struct UserPrincipal
 * @brief Represents a user identity in the access control system.
 */
struct alignas(64) UserPrincipal {
    // Identity
    SecurityIdentifier sid;
    std::wstring username;
    std::wstring upn;                   ///< User Principal Name (email format)
    std::wstring displayName;

    // Role assignments
    std::vector<uint32_t> roleIds;
    RoleType effectiveRole{ RoleType::INVALID };  ///< Highest effective role

    // Group memberships (resolved)
    std::vector<SecurityIdentifier> groupMemberships;

    // Multi-tenant
    uint32_t primaryTenantId{ 0 };
    std::vector<uint32_t> accessibleTenants;

    // MFA configuration
    bool mfaEnabled{ false };
    std::vector<MFAMethod> configuredMFAMethods;

    // Account state
    bool isEnabled{ true };
    bool isLocked{ false };
    bool passwordExpired{ false };
    std::chrono::system_clock::time_point lastLogin;
    std::chrono::system_clock::time_point lastPasswordChange;
    uint32_t failedLoginAttempts{ 0 };

    // Caching
    std::chrono::steady_clock::time_point cacheTime;
    bool isCacheValid{ false };
};

/**
 * @struct AuthenticationSession
 * @brief Tracks an authenticated user session.
 */
struct alignas(64) AuthenticationSession {
    // Session identity
    uint64_t sessionId{ 0 };
    std::wstring sessionToken;          ///< Secure random token

    // User reference
    SecurityIdentifier userSid;
    std::wstring username;

    // Session state
    SessionState state{ SessionState::INACTIVE };
    RoleType currentRole{ RoleType::INVALID };
    bool isElevated{ false };

    // Timing
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point lastActivityAt;
    std::chrono::system_clock::time_point expiresAt;
    std::chrono::system_clock::time_point elevatedUntil;

    // Context
    std::wstring sourceIP;
    std::wstring machineName;
    uint32_t windowsSessionId{ 0 };     ///< Terminal Services session ID
    uint32_t sourceProcessId{ 0 };

    // MFA state
    bool mfaCompleted{ false };
    MFAMethod mfaMethodUsed{ MFAMethod::NONE };
    std::chrono::system_clock::time_point mfaCompletedAt;

    // Effective permissions (cached)
    std::bitset<AccessControlConstants::MAX_PERMISSIONS> effectivePermissions;
    std::chrono::steady_clock::time_point permissionsCacheTime;
};

/**
 * @struct PrivilegeInfo
 * @brief Information about a Windows privilege.
 */
struct alignas(8) PrivilegeInfo {
    WindowsPrivilege privilege{ WindowsPrivilege::INVALID_PRIVILEGE };
    std::wstring name;
    std::wstring displayName;
    bool isEnabled{ false };
    bool isEnabledByDefault{ false };
    bool isRemoved{ false };
    bool isDangerous{ false };          ///< Flagged as security-sensitive
};

/**
 * @struct TokenInfo
 * @brief Comprehensive information about an access token.
 */
struct alignas(64) TokenInfo {
    // Token identity
    uint64_t tokenHandle{ 0 };
    TokenType type{ TokenType::PRIMARY };

    // User
    SecurityIdentifier userSid;
    std::wstring username;

    // Groups
    std::vector<SecurityIdentifier> groups;
    std::vector<SecurityIdentifier> restrictedSids;
    std::vector<SecurityIdentifier> capabilitySids;

    // Privileges
    std::vector<PrivilegeInfo> privileges;

    // Integrity
    IntegrityLevel integrityLevel{ IntegrityLevel::MEDIUM };
    uint32_t integrityRid{ AccessControlConstants::INTEGRITY_MEDIUM };

    // Session
    uint32_t sessionId{ 0 };
    uint64_t logonId{ 0 };

    // Flags
    bool isElevated{ false };
    bool isFiltered{ false };
    bool isRestricted{ false };
    bool isAppContainer{ false };
    bool isLPAC{ false };
    bool hasUIAccess{ false };
    bool isVirtualized{ false };

    // AppContainer specific
    std::wstring appContainerName;
    SecurityIdentifier appContainerSid;
};

/**
 * @struct ProcessRestrictionConfig
 * @brief Configuration for restricting a process.
 */
struct alignas(64) ProcessRestrictionConfig {
    // Target
    uint32_t targetPid{ 0 };
    uint64_t targetProcessUniqueId{ 0 };

    // Restriction types to apply
    RestrictionType primaryRestriction{ RestrictionType::NONE };
    std::vector<RestrictionType> additionalRestrictions;

    // Privilege stripping
    bool stripAllPrivileges{ false };
    std::vector<WindowsPrivilege> privilegesToRemove;
    std::vector<WindowsPrivilege> privilegesToDisable;

    // Integrity modification
    IntegrityLevel targetIntegrity{ IntegrityLevel::MEDIUM };
    bool forceIntegrity{ false };

    // SID restrictions
    std::vector<SecurityIdentifier> restrictingGroups;
    bool disableMaxPrivilege{ false };

    // Job object limits
    bool applyJobObject{ false };
    uint64_t memoryLimitBytes{ AccessControlConstants::DEFAULT_MEMORY_LIMIT_BYTES };
    uint32_t processLimit{ AccessControlConstants::DEFAULT_PROCESS_LIMIT };
    uint32_t cpuRateLimit{ AccessControlConstants::DEFAULT_CPU_RATE_LIMIT };
    bool breakawayOk{ false };

    // Network restrictions
    bool blockNetwork{ false };
    std::vector<std::wstring> allowedHosts;

    // File system restrictions
    std::vector<std::wstring> allowedPaths;
    std::vector<std::wstring> deniedPaths;

    // Factory methods
    static ProcessRestrictionConfig CreateMinimal() noexcept;
    static ProcessRestrictionConfig CreateModerate() noexcept;
    static ProcessRestrictionConfig CreateStrict() noexcept;
    static ProcessRestrictionConfig CreateSandbox() noexcept;
};

/**
 * @struct ProcessProtectionConfig
 * @brief Configuration for protecting ShadowStrike processes.
 */
struct alignas(64) ProcessProtectionConfig {
    // Target
    uint32_t targetPid{ 0 };
    std::wstring processName;

    // Protection level
    ProcessProtectionLevel level{ ProcessProtectionLevel::STANDARD };

    // Handle protection
    bool protectHandles{ true };
    uint32_t allowedAccessMask{ 0x1000 };  ///< PROCESS_QUERY_LIMITED_INFORMATION

    // Thread protection
    bool blockThreadCreation{ false };
    bool blockThreadHijacking{ true };
    std::vector<uint32_t> allowedThreadCreatorPids;

    // Memory protection
    bool blockMemoryRead{ false };
    bool blockMemoryWrite{ true };
    bool blockMemoryExecute{ true };

    // Additional protections
    bool preventSuspend{ true };
    bool preventTerminate{ true };
    bool protectDLLs{ true };

    // Exceptions
    std::vector<std::wstring> trustedProcesses;     ///< Can access despite protection
    std::vector<SecurityIdentifier> trustedUsers;   ///< SIDs that can access

    // Factory methods
    static ProcessProtectionConfig CreateDefault() noexcept;
    static ProcessProtectionConfig CreateMaximum() noexcept;
    static ProcessProtectionConfig CreateForService() noexcept;
    static ProcessProtectionConfig CreateForDriver() noexcept;
};

/**
 * @struct AccessControlAuditEvent
 * @brief Audit event for access control decisions.
 */
struct alignas(64) AccessControlAuditEvent {
    // Event identity
    uint64_t eventId{ 0 };
    AuditEventType type{ AuditEventType::PERMISSION_GRANTED };
    std::chrono::system_clock::time_point timestamp;

    // Subject (who)
    SecurityIdentifier subjectSid;
    std::wstring subjectUsername;
    uint64_t sessionId{ 0 };
    uint32_t processId{ 0 };

    // Object (what)
    Permission permission{ Permission::INVALID_PERMISSION };
    std::wstring resourcePath;
    std::wstring resourceType;

    // Decision
    AccessDecision decision{ AccessDecision::ALLOW };
    std::wstring reason;

    // Context
    std::wstring sourceIP;
    std::wstring machineName;
    std::wstring additionalInfo;

    // Severity
    uint8_t severity{ 0 };              ///< 0=info, 1=warning, 2=critical
    bool requiresAlert{ false };
};

/**
 * @struct RestrictionResult
 * @brief Result of a process restriction operation.
 */
struct alignas(64) RestrictionResult {
    bool success{ false };
    uint32_t errorCode{ 0 };
    std::wstring errorMessage;

    // What was applied
    std::vector<RestrictionType> appliedRestrictions;
    std::vector<WindowsPrivilege> strippedPrivileges;
    IntegrityLevel newIntegrityLevel{ IntegrityLevel::INVALID };
    bool jobObjectApplied{ false };

    // New token info (if token was modified)
    std::optional<TokenInfo> newTokenInfo;

    // Timing
    std::chrono::microseconds duration{ 0 };
};

/**
 * @struct ProtectionResult
 * @brief Result of a process protection operation.
 */
struct alignas(64) ProtectionResult {
    bool success{ false };
    uint32_t errorCode{ 0 };
    std::wstring errorMessage;

    // What was applied
    ProcessProtectionLevel achievedLevel{ ProcessProtectionLevel::NONE };
    bool handlesProtected{ false };
    bool threadsProtected{ false };
    bool memoryProtected{ false };

    // Timing
    std::chrono::microseconds duration{ 0 };
};

/**
 * @struct MFAChallengeResult
 * @brief Result of an MFA challenge.
 */
struct alignas(64) MFAChallengeResult {
    bool success{ false };
    MFAMethod methodUsed{ MFAMethod::NONE };
    std::wstring errorMessage;

    // Challenge details
    std::wstring challengeId;
    std::chrono::system_clock::time_point challengeExpiry;

    // For push notifications
    bool isPending{ false };
    std::wstring approvalUrl;
};

/**
 * @struct AccessControlManagerConfig
 * @brief Configuration for the AccessControlManager.
 */
struct alignas(64) AccessControlManagerConfig {
    // RBAC settings
    bool enableRBAC{ true };
    bool inheritPermissions{ true };
    bool explicitDenyOverrides{ true };     ///< Deny always wins

    // Session settings
    uint32_t defaultSessionTimeoutMs{ AccessControlConstants::DEFAULT_SESSION_TIMEOUT_MS };
    uint32_t maxSessionsPerUser{ AccessControlConstants::MAX_SESSIONS_PER_USER };
    bool singleSessionOnly{ false };        ///< Allow only one session per user

    // MFA settings
    bool requireMFAForAdmin{ true };
    bool requireMFAForElevation{ true };
    uint32_t mfaChallengeTimeoutMs{ AccessControlConstants::MFA_CHALLENGE_TIMEOUT_MS };
    std::vector<MFAMethod> allowedMFAMethods;

    // Privilege hardening
    bool autoStripDangerousPrivileges{ true };
    std::vector<WindowsPrivilege> privilegesToAlwaysStrip;

    // Process protection
    bool autoProtectShadowStrikeProcesses{ true };
    ProcessProtectionLevel defaultProtectionLevel{ ProcessProtectionLevel::ELEVATED };

    // Auditing
    bool auditAllAccessDecisions{ false };
    bool auditDeniedOnly{ true };
    bool alertOnPrivilegeEscalation{ true };

    // Active Directory integration
    bool enableADIntegration{ false };
    std::wstring adDomainController;
    uint32_t adSyncIntervalMs{ AccessControlConstants::AD_SYNC_INTERVAL_MS };

    // Multi-tenant
    bool enableMultiTenant{ false };
    uint32_t defaultTenantId{ 0 };

    // Cache settings
    uint32_t cacheTTLMs{ AccessControlConstants::CACHE_TTL_MS };
    size_t maxCacheEntries{ AccessControlConstants::PERMISSION_CACHE_SIZE };

    // Factory methods
    static AccessControlManagerConfig CreateDefault() noexcept;
    static AccessControlManagerConfig CreateEnterprise() noexcept;
    static AccessControlManagerConfig CreateMSP() noexcept;
    static AccessControlManagerConfig CreateStandalone() noexcept;
};

/**
 * @struct AccessControlStatistics
 * @brief Runtime statistics for access control operations.
 */
struct alignas(64) AccessControlStatistics {
    // Permission checks
    std::atomic<uint64_t> totalPermissionChecks{ 0 };
    std::atomic<uint64_t> permissionsGranted{ 0 };
    std::atomic<uint64_t> permissionsDenied{ 0 };
    std::atomic<uint64_t> permissionsCached{ 0 };

    // Sessions
    std::atomic<uint64_t> sessionsCreated{ 0 };
    std::atomic<uint64_t> sessionsExpired{ 0 };
    std::atomic<uint64_t> sessionsRevoked{ 0 };
    std::atomic<uint32_t> activeSessions{ 0 };

    // MFA
    std::atomic<uint64_t> mfaChallenges{ 0 };
    std::atomic<uint64_t> mfaSuccesses{ 0 };
    std::atomic<uint64_t> mfaFailures{ 0 };

    // Privilege operations
    std::atomic<uint64_t> privilegeStrips{ 0 };
    std::atomic<uint64_t> integrityLowerings{ 0 };
    std::atomic<uint64_t> processRestrictions{ 0 };
    std::atomic<uint64_t> processProtections{ 0 };

    // Tampering
    std::atomic<uint64_t> tamperAttempts{ 0 };
    std::atomic<uint64_t> tamperBlocked{ 0 };

    // Errors
    std::atomic<uint64_t> errorCount{ 0 };
    std::atomic<uint64_t> cacheHits{ 0 };
    std::atomic<uint64_t> cacheMisses{ 0 };

    // Performance
    std::atomic<uint64_t> totalCheckTimeUs{ 0 };
    std::atomic<uint64_t> maxCheckTimeUs{ 0 };

    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Callback for permission check results.
 * @param decision The access decision
 * @param permission The permission that was checked
 * @param userSid The user's SID
 * @param reason Explanation for the decision
 */
using PermissionCheckCallback = std::function<void(
    AccessDecision decision,
    Permission permission,
    const SecurityIdentifier& userSid,
    std::wstring_view reason
)>;

/**
 * @brief Callback for session events.
 * @param sessionId The session identifier
 * @param oldState Previous session state
 * @param newState New session state
 * @param userSid The user's SID
 */
using SessionEventCallback = std::function<void(
    uint64_t sessionId,
    SessionState oldState,
    SessionState newState,
    const SecurityIdentifier& userSid
)>;

/**
 * @brief Callback for tampering attempts.
 * @param targetPid The protected process that was targeted
 * @param attackerPid The process that attempted tampering
 * @param attackType Description of the tampering attempt
 */
using TamperAttemptCallback = std::function<void(
    uint32_t targetPid,
    uint32_t attackerPid,
    std::wstring_view attackType
)>;

/**
 * @brief Callback for audit events.
 * @param event The audit event details
 */
using AuditEventCallback = std::function<void(
    const AccessControlAuditEvent& event
)>;

/**
 * @brief Callback for privilege modification events.
 * @param pid The affected process
 * @param privilege The modified privilege
 * @param action The action taken
 * @param success Whether the operation succeeded
 */
using PrivilegeModificationCallback = std::function<void(
    uint32_t pid,
    WindowsPrivilege privilege,
    PrivilegeAction action,
    bool success
)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class AccessControlManager
 * @brief Enterprise-grade access control and privilege management system.
 *
 * This class provides comprehensive access control functionality including:
 * - Role-Based Access Control (RBAC) with hierarchical roles
 * - Granular permission management
 * - Windows privilege hardening
 * - Process protection against tampering
 * - Multi-factor authentication integration
 * - Session management with timeout and elevation
 * - Comprehensive auditing
 *
 * Thread Safety:
 * All public methods are thread-safe and can be called concurrently.
 *
 * Usage Example:
 * @code
 * auto& acm = AccessControlManager::Instance();
 * 
 * // Initialize with enterprise config
 * auto config = AccessControlManagerConfig::CreateEnterprise();
 * acm.Initialize(config);
 * 
 * // Check permission
 * auto decision = acm.CheckPermission(userSid, Permission::QUARANTINE_RESTORE);
 * if (decision == AccessDecision::ALLOW) {
 *     // Proceed with operation
 * }
 * 
 * // Restrict a suspicious process
 * auto restrictConfig = ProcessRestrictionConfig::CreateStrict();
 * restrictConfig.targetPid = suspiciousPid;
 * auto result = acm.RestrictProcess(restrictConfig);
 * @endcode
 */
class AccessControlManager {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    /**
     * @brief Gets the singleton instance of the AccessControlManager.
     * @return Reference to the singleton instance.
     * @note Thread-safe. Uses Meyers' singleton pattern.
     */
    static AccessControlManager& Instance();

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initializes the access control system with specified configuration.
     * @param config Configuration settings.
     * @return True if initialization succeeded.
     * @note Must be called before any other operations.
     */
    bool Initialize(const AccessControlManagerConfig& config);

    /**
     * @brief Shuts down the access control system gracefully.
     * @note Revokes all active sessions and releases resources.
     */
    void Shutdown() noexcept;

    /**
     * @brief Checks if the system is initialized and operational.
     * @return True if initialized and ready.
     */
    [[nodiscard]] bool IsInitialized() const noexcept;

    /**
     * @brief Gets the current configuration.
     * @return Current configuration (copy for thread safety).
     */
    [[nodiscard]] AccessControlManagerConfig GetConfig() const;

    /**
     * @brief Updates configuration at runtime.
     * @param config New configuration settings.
     * @return True if configuration was updated successfully.
     */
    bool UpdateConfig(const AccessControlManagerConfig& config);

    // ========================================================================
    // PERMISSION MANAGEMENT
    // ========================================================================

    /**
     * @brief Checks if a user has a specific permission.
     * @param userSid The user's security identifier.
     * @param permission The permission to check.
     * @param resourcePath Optional resource path for context-based checks.
     * @return Access decision.
     * @note Thread-safe. Uses cached permissions when available.
     */
    [[nodiscard]] AccessDecision CheckPermission(
        const SecurityIdentifier& userSid,
        Permission permission,
        std::wstring_view resourcePath = L""
    ) const;

    /**
     * @brief Checks if a session has a specific permission.
     * @param sessionId The session identifier.
     * @param permission The permission to check.
     * @param resourcePath Optional resource path.
     * @return Access decision.
     */
    [[nodiscard]] AccessDecision CheckSessionPermission(
        uint64_t sessionId,
        Permission permission,
        std::wstring_view resourcePath = L""
    ) const;

    /**
     * @brief Batch checks multiple permissions at once.
     * @param userSid The user's security identifier.
     * @param permissions Vector of permissions to check.
     * @return Map of permission to access decision.
     * @note More efficient than individual checks for multiple permissions.
     */
    [[nodiscard]] std::unordered_map<Permission, AccessDecision> CheckPermissions(
        const SecurityIdentifier& userSid,
        const std::vector<Permission>& permissions
    ) const;

    /**
     * @brief Gets all effective permissions for a user.
     * @param userSid The user's security identifier.
     * @return Bitset of all granted permissions.
     */
    [[nodiscard]] std::bitset<AccessControlConstants::MAX_PERMISSIONS> GetEffectivePermissions(
        const SecurityIdentifier& userSid
    ) const;

    // ========================================================================
    // ROLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Gets the effective role for a user.
     * @param userSid The user's security identifier.
     * @return The user's highest effective role type.
     */
    [[nodiscard]] RoleType GetEffectiveRole(const SecurityIdentifier& userSid) const;

    /**
     * @brief Assigns a role to a user.
     * @param userSid The user's security identifier.
     * @param roleId The role ID to assign.
     * @param assignedBy SID of the administrator making the assignment.
     * @return True if assignment succeeded.
     */
    bool AssignRole(
        const SecurityIdentifier& userSid,
        uint32_t roleId,
        const SecurityIdentifier& assignedBy
    );

    /**
     * @brief Revokes a role from a user.
     * @param userSid The user's security identifier.
     * @param roleId The role ID to revoke.
     * @param revokedBy SID of the administrator making the revocation.
     * @return True if revocation succeeded.
     */
    bool RevokeRole(
        const SecurityIdentifier& userSid,
        uint32_t roleId,
        const SecurityIdentifier& revokedBy
    );

    /**
     * @brief Creates a new custom role.
     * @param definition The role definition.
     * @param createdBy SID of the administrator creating the role.
     * @return The new role ID, or 0 on failure.
     */
    [[nodiscard]] uint32_t CreateRole(
        const RoleDefinition& definition,
        const SecurityIdentifier& createdBy
    );

    /**
     * @brief Modifies an existing role.
     * @param roleId The role ID to modify.
     * @param definition Updated role definition.
     * @param modifiedBy SID of the administrator modifying the role.
     * @return True if modification succeeded.
     */
    bool ModifyRole(
        uint32_t roleId,
        const RoleDefinition& definition,
        const SecurityIdentifier& modifiedBy
    );

    /**
     * @brief Deletes a custom role.
     * @param roleId The role ID to delete.
     * @param deletedBy SID of the administrator deleting the role.
     * @return True if deletion succeeded.
     * @note Built-in roles cannot be deleted.
     */
    bool DeleteRole(
        uint32_t roleId,
        const SecurityIdentifier& deletedBy
    );

    /**
     * @brief Gets a role definition by ID.
     * @param roleId The role ID.
     * @return Role definition, or nullopt if not found.
     */
    [[nodiscard]] std::optional<RoleDefinition> GetRole(uint32_t roleId) const;

    /**
     * @brief Gets all roles assigned to a user.
     * @param userSid The user's security identifier.
     * @return Vector of role IDs.
     */
    [[nodiscard]] std::vector<uint32_t> GetUserRoles(const SecurityIdentifier& userSid) const;

    /**
     * @brief Lists all defined roles.
     * @param includeBuiltIn Include built-in roles.
     * @param tenantId Filter by tenant (0 for all).
     * @return Vector of role definitions.
     */
    [[nodiscard]] std::vector<RoleDefinition> ListRoles(
        bool includeBuiltIn = true,
        uint32_t tenantId = 0
    ) const;

    // ========================================================================
    // SESSION MANAGEMENT
    // ========================================================================

    /**
     * @brief Creates a new authentication session.
     * @param userSid The user's security identifier.
     * @param sourceIP Source IP address.
     * @param machineName Source machine name.
     * @return Session information, or nullopt on failure.
     */
    [[nodiscard]] std::optional<AuthenticationSession> CreateSession(
        const SecurityIdentifier& userSid,
        std::wstring_view sourceIP = L"",
        std::wstring_view machineName = L""
    );

    /**
     * @brief Validates and retrieves a session by token.
     * @param sessionToken The session token.
     * @return Session information, or nullopt if invalid/expired.
     */
    [[nodiscard]] std::optional<AuthenticationSession> ValidateSession(
        std::wstring_view sessionToken
    ) const;

    /**
     * @brief Validates and retrieves a session by ID.
     * @param sessionId The session ID.
     * @return Session information, or nullopt if invalid/expired.
     */
    [[nodiscard]] std::optional<AuthenticationSession> GetSession(
        uint64_t sessionId
    ) const;

    /**
     * @brief Refreshes a session's expiration time.
     * @param sessionId The session ID.
     * @return True if refresh succeeded.
     */
    bool RefreshSession(uint64_t sessionId);

    /**
     * @brief Elevates a session to higher privileges.
     * @param sessionId The session ID.
     * @param targetRole Target role for elevation.
     * @param durationMs Duration of elevation in milliseconds.
     * @return True if elevation succeeded (may require MFA).
     */
    bool ElevateSession(
        uint64_t sessionId,
        RoleType targetRole,
        uint32_t durationMs = AccessControlConstants::ELEVATED_SESSION_TIMEOUT_MS
    );

    /**
     * @brief Revokes a session immediately.
     * @param sessionId The session ID.
     * @param reason Reason for revocation.
     * @return True if revocation succeeded.
     */
    bool RevokeSession(
        uint64_t sessionId,
        std::wstring_view reason = L""
    );

    /**
     * @brief Revokes all sessions for a user.
     * @param userSid The user's security identifier.
     * @param reason Reason for revocation.
     * @return Number of sessions revoked.
     */
    uint32_t RevokeAllUserSessions(
        const SecurityIdentifier& userSid,
        std::wstring_view reason = L""
    );

    /**
     * @brief Lists all active sessions.
     * @param userSid Filter by user (empty for all).
     * @return Vector of active sessions.
     */
    [[nodiscard]] std::vector<AuthenticationSession> ListActiveSessions(
        const SecurityIdentifier& userSid = SecurityIdentifier{}
    ) const;

    // ========================================================================
    // MULTI-FACTOR AUTHENTICATION
    // ========================================================================

    /**
     * @brief Initiates an MFA challenge for a session.
     * @param sessionId The session ID.
     * @param method Preferred MFA method.
     * @return Challenge result with challenge ID or error.
     */
    [[nodiscard]] MFAChallengeResult InitiateMFAChallenge(
        uint64_t sessionId,
        MFAMethod method = MFAMethod::NONE
    );

    /**
     * @brief Verifies an MFA response.
     * @param sessionId The session ID.
     * @param challengeId The challenge ID.
     * @param response The user's response (OTP code, etc.).
     * @return True if verification succeeded.
     */
    bool VerifyMFAResponse(
        uint64_t sessionId,
        std::wstring_view challengeId,
        std::wstring_view response
    );

    /**
     * @brief Checks if a session requires MFA.
     * @param sessionId The session ID.
     * @param forOperation Optional operation to check MFA requirement for.
     * @return True if MFA is required.
     */
    [[nodiscard]] bool RequiresMFA(
        uint64_t sessionId,
        Permission forOperation = Permission::INVALID_PERMISSION
    ) const;

    // ========================================================================
    // USER IDENTITY OPERATIONS
    // ========================================================================

    /**
     * @brief Verifies if a user is in the administrators group.
     * @param userSid The user's string SID.
     * @return True if the user is an administrator.
     */
    [[nodiscard]] bool IsAdmin(const std::wstring& userSid) const;

    /**
     * @brief Resolves a SID to a UserPrincipal with full information.
     * @param sid The security identifier.
     * @param useCache Whether to use cached data.
     * @return User principal information.
     */
    [[nodiscard]] std::optional<UserPrincipal> ResolveUser(
        const SecurityIdentifier& sid,
        bool useCache = true
    ) const;

    /**
     * @brief Looks up a user by username.
     * @param username The username or UPN.
     * @param domain Domain name (optional).
     * @return Security identifier, or nullopt if not found.
     */
    [[nodiscard]] std::optional<SecurityIdentifier> LookupUser(
        std::wstring_view username,
        std::wstring_view domain = L""
    ) const;

    /**
     * @brief Gets group memberships for a user.
     * @param userSid The user's security identifier.
     * @param includeNested Include nested group memberships.
     * @return Vector of group SIDs.
     */
    [[nodiscard]] std::vector<SecurityIdentifier> GetGroupMemberships(
        const SecurityIdentifier& userSid,
        bool includeNested = true
    ) const;

    /**
     * @brief Checks if a user is a member of a group.
     * @param userSid The user's security identifier.
     * @param groupSid The group's security identifier.
     * @param checkNested Check nested memberships.
     * @return True if the user is a member.
     */
    [[nodiscard]] bool IsMemberOf(
        const SecurityIdentifier& userSid,
        const SecurityIdentifier& groupSid,
        bool checkNested = true
    ) const;

    // ========================================================================
    // PRIVILEGE HARDENING
    // ========================================================================

    /**
     * @brief Restricts a process by stripping privileges and applying limits.
     * @param config Restriction configuration.
     * @return Result of the restriction operation.
     */
    [[nodiscard]] RestrictionResult RestrictProcess(
        const ProcessRestrictionConfig& config
    );

    /**
     * @brief Convenience overload to restrict by PID with default settings.
     * @param pid Process ID to restrict.
     */
    void RestrictProcess(uint32_t pid);

    /**
     * @brief Gets the current token information for a process.
     * @param pid Process ID.
     * @return Token information, or nullopt on failure.
     */
    [[nodiscard]] std::optional<TokenInfo> GetProcessToken(uint32_t pid) const;

    /**
     * @brief Gets the current token information for a thread.
     * @param tid Thread ID.
     * @return Token information, or nullopt on failure.
     */
    [[nodiscard]] std::optional<TokenInfo> GetThreadToken(uint32_t tid) const;

    /**
     * @brief Modifies a privilege in a process's token.
     * @param pid Process ID.
     * @param privilege The privilege to modify.
     * @param action Action to take (enable/disable/remove).
     * @return True if modification succeeded.
     */
    bool ModifyProcessPrivilege(
        uint32_t pid,
        WindowsPrivilege privilege,
        PrivilegeAction action
    );

    /**
     * @brief Strips all dangerous privileges from a process.
     * @param pid Process ID.
     * @return Number of privileges stripped.
     */
    uint32_t StripDangerousPrivileges(uint32_t pid);

    /**
     * @brief Lowers the integrity level of a process.
     * @param pid Process ID.
     * @param targetLevel Target integrity level.
     * @return True if operation succeeded.
     */
    bool LowerIntegrity(
        uint32_t pid,
        IntegrityLevel targetLevel = IntegrityLevel::LOW
    );

    /**
     * @brief Creates a restricted token from an existing token.
     * @param sourceToken Handle to source token.
     * @param disabledSids SIDs to disable (deny-only).
     * @param removedPrivileges Privileges to remove.
     * @param restrictedSids SIDs to add as restricting.
     * @return Handle to new restricted token, or 0 on failure.
     */
    [[nodiscard]] uint64_t CreateRestrictedToken(
        uint64_t sourceToken,
        const std::vector<SecurityIdentifier>& disabledSids,
        const std::vector<WindowsPrivilege>& removedPrivileges,
        const std::vector<SecurityIdentifier>& restrictedSids
    );

    // ========================================================================
    // PROCESS PROTECTION
    // ========================================================================

    /**
     * @brief Applies protection to a process against tampering.
     * @param config Protection configuration.
     * @return Result of the protection operation.
     */
    [[nodiscard]] ProtectionResult ProtectProcess(
        const ProcessProtectionConfig& config
    );

    /**
     * @brief Removes protection from a process.
     * @param pid Process ID.
     * @return True if protection was removed.
     */
    bool UnprotectProcess(uint32_t pid);

    /**
     * @brief Checks if a process is protected.
     * @param pid Process ID.
     * @return Protection level, or NONE if not protected.
     */
    [[nodiscard]] ProcessProtectionLevel GetProcessProtectionLevel(uint32_t pid) const;

    /**
     * @brief Protects all ShadowStrike processes.
     * @param level Protection level to apply.
     * @return Number of processes protected.
     */
    uint32_t ProtectShadowStrikeProcesses(
        ProcessProtectionLevel level = ProcessProtectionLevel::ELEVATED
    );

    /**
     * @brief Checks if an access attempt to a protected process is allowed.
     * @param protectedPid The protected process ID.
     * @param accessorPid The process attempting access.
     * @param desiredAccess The requested access rights.
     * @return True if access should be allowed.
     */
    [[nodiscard]] bool IsAccessAllowed(
        uint32_t protectedPid,
        uint32_t accessorPid,
        uint32_t desiredAccess
    ) const;

    // ========================================================================
    // JOB OBJECT MANAGEMENT
    // ========================================================================

    /**
     * @brief Creates a job object with specified limits.
     * @param jobName Name for the job object.
     * @param memoryLimit Memory limit in bytes (0 = unlimited).
     * @param processLimit Maximum processes in job (0 = unlimited).
     * @param cpuRateLimit CPU rate limit percentage (0 = unlimited).
     * @return Job object handle, or 0 on failure.
     */
    [[nodiscard]] uint64_t CreateJobObject(
        std::wstring_view jobName,
        uint64_t memoryLimit = 0,
        uint32_t processLimit = 0,
        uint32_t cpuRateLimit = 0
    );

    /**
     * @brief Assigns a process to a job object.
     * @param jobHandle Job object handle.
     * @param pid Process ID.
     * @return True if assignment succeeded.
     */
    bool AssignProcessToJob(uint64_t jobHandle, uint32_t pid);

    /**
     * @brief Terminates all processes in a job object.
     * @param jobHandle Job object handle.
     * @return True if termination succeeded.
     */
    bool TerminateJobObject(uint64_t jobHandle);

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    /**
     * @brief Registers a callback for permission check events.
     * @param callback The callback function.
     * @return Callback ID for unregistration.
     */
    [[nodiscard]] uint64_t RegisterPermissionCheckCallback(
        PermissionCheckCallback callback
    );

    /**
     * @brief Registers a callback for session events.
     * @param callback The callback function.
     * @return Callback ID for unregistration.
     */
    [[nodiscard]] uint64_t RegisterSessionEventCallback(
        SessionEventCallback callback
    );

    /**
     * @brief Registers a callback for tampering attempts.
     * @param callback The callback function.
     * @return Callback ID for unregistration.
     */
    [[nodiscard]] uint64_t RegisterTamperAttemptCallback(
        TamperAttemptCallback callback
    );

    /**
     * @brief Registers a callback for audit events.
     * @param callback The callback function.
     * @return Callback ID for unregistration.
     */
    [[nodiscard]] uint64_t RegisterAuditEventCallback(
        AuditEventCallback callback
    );

    /**
     * @brief Registers a callback for privilege modifications.
     * @param callback The callback function.
     * @return Callback ID for unregistration.
     */
    [[nodiscard]] uint64_t RegisterPrivilegeModificationCallback(
        PrivilegeModificationCallback callback
    );

    /**
     * @brief Unregisters a previously registered callback.
     * @param callbackId The callback ID returned during registration.
     * @return True if unregistration succeeded.
     */
    bool UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // AUDITING
    // ========================================================================

    /**
     * @brief Gets recent audit events.
     * @param maxEvents Maximum events to return.
     * @param eventType Filter by event type (nullopt for all).
     * @param userSid Filter by user (empty for all).
     * @return Vector of audit events.
     */
    [[nodiscard]] std::vector<AccessControlAuditEvent> GetAuditEvents(
        size_t maxEvents = 100,
        std::optional<AuditEventType> eventType = std::nullopt,
        const SecurityIdentifier& userSid = SecurityIdentifier{}
    ) const;

    /**
     * @brief Exports audit events to a file.
     * @param filePath Output file path.
     * @param startTime Start of time range.
     * @param endTime End of time range.
     * @param format Output format ("json", "csv", "xml").
     * @return True if export succeeded.
     */
    bool ExportAuditLog(
        const std::wstring& filePath,
        std::chrono::system_clock::time_point startTime,
        std::chrono::system_clock::time_point endTime,
        std::wstring_view format = L"json"
    ) const;

    // ========================================================================
    // STATISTICS AND DIAGNOSTICS
    // ========================================================================

    /**
     * @brief Gets current runtime statistics.
     * @return Reference to statistics structure.
     */
    [[nodiscard]] const AccessControlStatistics& GetStatistics() const noexcept;

    /**
     * @brief Resets all statistics counters.
     */
    void ResetStatistics() noexcept;

    /**
     * @brief Performs a self-diagnostic check.
     * @return True if all systems are operational.
     */
    [[nodiscard]] bool PerformDiagnostics() const;

    /**
     * @brief Invalidates all cached data.
     * @note Forces refresh from authoritative sources.
     */
    void InvalidateCache() noexcept;

    // ========================================================================
    // UTILITY METHODS
    // ========================================================================

    /**
     * @brief Converts a string SID to a SecurityIdentifier structure.
     * @param stringSid SID in string format (S-1-...).
     * @return SecurityIdentifier, or invalid if parsing failed.
     */
    [[nodiscard]] static SecurityIdentifier ParseSid(std::wstring_view stringSid);

    /**
     * @brief Converts a binary SID to string format.
     * @param binarySid Raw SID bytes.
     * @return String SID (S-1-...), or empty on failure.
     */
    [[nodiscard]] static std::wstring SidToString(std::span<const uint8_t> binarySid);

    /**
     * @brief Gets the name of a permission.
     * @param permission The permission.
     * @return Permission name string.
     */
    [[nodiscard]] static std::wstring_view GetPermissionName(Permission permission) noexcept;

    /**
     * @brief Gets the name of a role type.
     * @param role The role type.
     * @return Role name string.
     */
    [[nodiscard]] static std::wstring_view GetRoleName(RoleType role) noexcept;

    /**
     * @brief Gets the name of a Windows privilege.
     * @param privilege The privilege.
     * @return Privilege name string.
     */
    [[nodiscard]] static std::wstring_view GetPrivilegeName(WindowsPrivilege privilege) noexcept;

    /**
     * @brief Checks if a privilege is considered dangerous.
     * @param privilege The privilege.
     * @return True if the privilege is security-sensitive.
     */
    [[nodiscard]] static bool IsDangerousPrivilege(WindowsPrivilege privilege) noexcept;

    /**
     * @brief Gets the current process's integrity level.
     * @return Current integrity level.
     */
    [[nodiscard]] static IntegrityLevel GetCurrentIntegrityLevel() noexcept;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR (Singleton)
    // ========================================================================
    AccessControlManager();
    ~AccessControlManager();

    // Non-copyable, non-movable
    AccessControlManager(const AccessControlManager&) = delete;
    AccessControlManager& operator=(const AccessControlManager&) = delete;
    AccessControlManager(AccessControlManager&&) = delete;
    AccessControlManager& operator=(AccessControlManager&&) = delete;

    // ========================================================================
    // PIMPL IMPLEMENTATION
    // ========================================================================
    std::unique_ptr<AccessControlManagerImpl> m_impl;
};

}  // namespace RealTime
}  // namespace ShadowStrike
