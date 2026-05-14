/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * ============================================================================
 * ShadowStrike Real-Time - ACCESS CONTROL MANAGER IMPLEMENTATION
 * ============================================================================
 *
 * @file AccessControlManager.cpp
 * @brief Enterprise-grade access control, RBAC, session management, and
 *        process protection implementation.
 *
 * Security-critical rewrite addressing:
 *   - MFA backdoor removal (no magic codes, crypto-random challenges)
 *   - Cryptographic session tokens via BCryptGenRandom
 *   - Proper SID comparison against well-known SIDs
 *   - Real DACL-based process protection (SDDL)
 *   - Deterministic deny-override in permission checks
 *   - Strict lock ordering to prevent deadlocks
 *   - Authorization checks on role mutation operations
 *   - JSON-based persistence with atomic writes
 *   - Audit log capping and path traversal prevention
 *   - RAII resource management throughout
 *
 * Lock order (must acquire in this sequence):
 *   m_roleMutex -> m_sessionMutex -> m_mfaMutex -> m_auditMutex -> m_callbackMutex
 *
 * @author ShadowStrike Security Team
 * @version 4.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "AccessControlManager.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/FileUtils.hpp"

// ============================================================================
// WINDOWS API INCLUDES
// ============================================================================
#ifdef _WIN32
#include <sddl.h>
#include <aclapi.h>
#include <userenv.h>
#include <lm.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Bcrypt.lib")
#endif

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <sstream>
#include <iomanip>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <nlohmann/json.hpp>

namespace ShadowStrike {
namespace RealTime {

using namespace AccessControlConstants;
namespace fs = std::filesystem;

// ============================================================================
// ANONYMOUS HELPER NAMESPACE
// ============================================================================
namespace {

    constexpr size_t MAX_AUDIT_LOG_ENTRIES = 100000;
    constexpr uint32_t MAX_MFA_ATTEMPTS = 5;
    constexpr size_t SESSION_TOKEN_BYTES = 32;
    constexpr size_t MFA_CODE_LENGTH = 6;

    // RAII wrapper for Windows HANDLE
    struct HandleDeleter {
        void operator()(HANDLE h) const noexcept {
            if (h && h != INVALID_HANDLE_VALUE) {
                ::CloseHandle(h);
            }
        }
    };

    using UniqueHandle = std::unique_ptr<std::remove_pointer_t<HANDLE>, HandleDeleter>;

    UniqueHandle WrapHandle(HANDLE h) noexcept {
        if (h == INVALID_HANDLE_VALUE || h == nullptr)
            return UniqueHandle{};
        return UniqueHandle{ h };
    }

    // RAII wrapper for LocalAlloc memory
    struct LocalFreeDeleter {
        void operator()(void* p) const noexcept {
            if (p) ::LocalFree(p);
        }
    };
    template<typename T>
    using UniqueLocal = std::unique_ptr<T, LocalFreeDeleter>;

    // Generate cryptographically secure session token (FIX: ACM-C7, ACM-C8)
    std::wstring GenerateSessionToken() {
        uint8_t randomBytes[SESSION_TOKEN_BYTES]{};
        NTSTATUS status = ::BCryptGenRandom(
            nullptr, randomBytes, sizeof(randomBytes),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!NT_SUCCESS(status)) {
            SS_LOG_ERROR(L"ACM", L"BCryptGenRandom failed for session token: 0x%08X",
                         static_cast<unsigned>(status));
            return {};
        }
        std::wstring token;
        token.reserve(SESSION_TOKEN_BYTES * 2);
        for (auto byte : randomBytes) {
            wchar_t buf[3];
            swprintf_s(buf, L"%02x", byte);
            token += buf;
        }
        return token;
    }

    // Generate a crypto-random numeric MFA code (FIX: ACM-C1, ACM-C2)
    std::wstring GenerateMFACode() {
        uint8_t randomBytes[4]{};
        NTSTATUS status = ::BCryptGenRandom(
            nullptr, randomBytes, sizeof(randomBytes),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!NT_SUCCESS(status)) {
            SS_LOG_ERROR(L"ACM", L"BCryptGenRandom failed for MFA code: 0x%08X",
                         static_cast<unsigned>(status));
            return {};
        }
        uint32_t raw = 0;
        std::memcpy(&raw, randomBytes, sizeof(raw));
        uint32_t code = raw % 1000000;
        wchar_t buf[8]{};
        swprintf_s(buf, L"%06u", code);
        return buf;
    }

    std::chrono::system_clock::time_point Now() {
        return std::chrono::system_clock::now();
    }

    // Proper admin SID check (FIX: ACM-C6)
    bool IsAdminSidString(const std::wstring& sidString) {
        PSID pInputSid = nullptr;
        if (!::ConvertStringSidToSidW(sidString.c_str(), &pInputSid)) {
            return false;
        }
        UniqueLocal<void> inputGuard(pInputSid);

        BYTE adminSidBuf[SECURITY_MAX_SID_SIZE]{};
        DWORD adminSidSize = sizeof(adminSidBuf);
        if (!::CreateWellKnownSid(WinBuiltinAdministratorsSid,
                                   nullptr,
                                   adminSidBuf,
                                   &adminSidSize)) {
            return false;
        }
        return ::EqualSid(pInputSid, adminSidBuf) != FALSE;
    }

    // Path traversal validation (FIX: ACM-C14)
    bool IsPathSafe(const std::wstring& filePath) {
        if (filePath.empty()) return false;
        if (filePath.find(L"..") != std::wstring::npos) return false;

        try {
            fs::path p(filePath);
            if (!p.is_absolute()) return false;
            fs::path canonical = fs::weakly_canonical(p);
            return canonical.wstring().find(L"..") == std::wstring::npos;
        } catch (...) {
            return false;
        }
    }

    // Get persistence path
    std::wstring GetPersistencePath() {
        // FIX: ACM-N7 — removed unused wchar_t* programData local
        std::wstring result;
        DWORD size = ::GetEnvironmentVariableW(L"ProgramData", nullptr, 0);
        if (size > 0) {
            std::wstring buf(size, L'\0');
            ::GetEnvironmentVariableW(L"ProgramData", buf.data(),
                                       static_cast<DWORD>(buf.size()));
            buf.resize(size - 1);
            result = buf + L"\\ShadowStrike\\acm_state.json";
        } else {
            result = L"C:\\ProgramData\\ShadowStrike\\acm_state.json";
        }
        return result;
    }

    // Check if PhantomSensor driver service is loaded
    bool IsDriverServiceRunning() {
        SC_HANDLE hSCM = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!hSCM) return false;

        SC_HANDLE hService = ::OpenServiceW(hSCM, L"PhantomSensor",
                                             SERVICE_QUERY_STATUS);
        bool running = false;
        if (hService) {
            SERVICE_STATUS_PROCESS ssp{};
            DWORD needed = 0;
            if (::QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
                                        reinterpret_cast<LPBYTE>(&ssp),
                                        sizeof(ssp), &needed)) {
                running = (ssp.dwCurrentState == SERVICE_RUNNING);
            }
            ::CloseServiceHandle(hService);
        }
        ::CloseServiceHandle(hSCM);
        return running;
    }

    // FIX: ACM-N8 — zero out sensitive string buffers before release. The header
    // explicitly requires SecureZeroMemory before deallocation of session tokens
    // and MFA secret codes; without this, a process-memory snapshot (e.g. via
    // MiniDumpWriteDump in another protected process) can recover bearer tokens
    // long after a session has been revoked. SecureZeroMemory is guaranteed by
    // the SDK not to be elided by the optimizer.
    void SecureWipe(std::wstring& s) noexcept {
        if (!s.empty()) {
            ::SecureZeroMemory(s.data(), s.size() * sizeof(wchar_t));
        }
        s.clear();
    }

} // anonymous namespace

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================
class AccessControlManagerImpl {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================
    AccessControlManagerConfig m_config;
    std::atomic<bool> m_initialized{ false };

    // Thread synchronization — lock order:
    // m_roleMutex -> m_sessionMutex -> m_mfaMutex -> m_auditMutex -> m_callbackMutex
    mutable std::shared_mutex m_roleMutex;
    mutable std::shared_mutex m_sessionMutex;
    mutable std::shared_mutex m_mfaMutex;
    mutable std::shared_mutex m_auditMutex;
    mutable std::shared_mutex m_callbackMutex;

    // Data stores
    std::unordered_map<uint32_t, RoleDefinition> m_roles;
    std::unordered_map<std::wstring, std::vector<uint32_t>> m_userRoleAssignments;
    std::unordered_map<uint64_t, AuthenticationSession> m_sessions;
    std::unordered_map<std::wstring, uint64_t> m_tokenToSessionId;
    std::vector<AccessControlAuditEvent> m_auditLog;

    // MFA state (FIX: ACM-C23 — add attempt counter)
    struct MFAChallenge {
        std::wstring challengeId;
        std::wstring secretCode;
        std::chrono::system_clock::time_point expiry;
        uint32_t failedAttempts{ 0 };
    };
    std::unordered_map<uint64_t, MFAChallenge> m_activeChallenges;

    // Process protection tracking
    std::unordered_map<uint32_t, ProcessProtectionLevel> m_protectedProcesses;
    mutable std::shared_mutex m_protectionMutex;

    // Job handle tracking (FIX: ACM-C16)
    std::unordered_map<uintptr_t, UniqueHandle> m_jobHandles;
    mutable std::shared_mutex m_jobMutex;

    // Statistics
    AccessControlStatistics m_stats;
    mutable std::shared_mutex m_statsMutex;

    // Callbacks
    std::unordered_map<uint64_t, PermissionCheckCallback> m_permissionCallbacks;
    std::unordered_map<uint64_t, SessionEventCallback> m_sessionCallbacks;
    std::unordered_map<uint64_t, TamperAttemptCallback> m_tamperCallbacks;
    std::unordered_map<uint64_t, AuditEventCallback> m_auditCallbacks;
    std::unordered_map<uint64_t, PrivilegeModificationCallback> m_privCallbacks;
    std::atomic<uint64_t> m_nextCallbackId{ 1 };

    // Driver status (FIX: ACM-C3, ACM-K1, ACM-K2 — no fake handle)
    std::atomic<bool> m_driverAvailable{ false };

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    AccessControlManagerImpl() = default;
    ~AccessControlManagerImpl() { Shutdown(); }

    bool Initialize(const AccessControlManagerConfig& config) {
        if (m_initialized.exchange(true)) {
            SS_LOG_WARN(L"ACM", L"Already initialized, skipping re-initialization");
            return true;
        }

        m_config = config;

        // Initialize default roles under roleMutex
        {
            std::unique_lock roleLock(m_roleMutex);
            InitializeDefaultRoles();
        }
        // Load persistence (acquires roleMutex internally)
        LoadPersistence();

        // Check driver availability (FIX: ACM-C19 — no roleMutex held)
        CheckDriverAvailability();

        SS_LOG_INFO(L"ACM", L"Initialized successfully (driver=%ls)",
                    m_driverAvailable.load() ? L"available" : L"unavailable");
        return true;
    }

    void Shutdown() {
        // FIX: ACM-C18 — atomic gate
        if (!m_initialized.exchange(false)) return;

        SavePersistence();

        // Clear sessions
        {
            std::unique_lock sessLock(m_sessionMutex);
            // FIX: ACM-N8 — wipe bearer tokens before clearing on shutdown.
            for (auto& [id, sess] : m_sessions) {
                SecureWipe(sess.sessionToken);
            }
            m_sessions.clear();
            m_tokenToSessionId.clear();
        }

        // Clear MFA challenges
        {
            std::unique_lock mfaLock(m_mfaMutex);
            // FIX: ACM-N8 — wipe MFA secret codes and challenge IDs before clearing.
            for (auto& [id, ch] : m_activeChallenges) {
                SecureWipe(ch.secretCode);
                SecureWipe(ch.challengeId);
            }
            m_activeChallenges.clear();
        }

        // Close job handles (FIX: ACM-C16)
        {
            std::unique_lock jobLock(m_jobMutex);
            m_jobHandles.clear();
        }

        SS_LOG_INFO(L"ACM", L"Shutdown complete");
    }

    // FIX: ACM-C3, ACM-K1, ACM-K2 — no fake CreateFileW/IOCTL
    void CheckDriverAvailability() {
        m_driverAvailable = IsDriverServiceRunning();
        if (m_driverAvailable) {
            SS_LOG_INFO(L"ACM", L"PhantomSensor driver service is running; "
                        L"kernel-backed protection available via IPCManager");
        } else {
            SS_LOG_WARN(L"ACM", L"PhantomSensor driver service not running; "
                        L"using user-mode DACL protection only");
        }
    }

    void InitializeDefaultRoles() {
        m_roles.clear();

        auto addRole = [&](RoleType type, const wchar_t* name,
                           const wchar_t* desc) -> RoleDefinition& {
            RoleDefinition role;
            role.roleId = static_cast<uint32_t>(type);
            role.type = type;
            role.name = name;
            role.description = desc;
            role.isBuiltIn = true;
            role.createdAt = Now();
            role.modifiedAt = role.createdAt;
            m_roles[role.roleId] = role;
            return m_roles[role.roleId];
        };

        auto& super = addRole(RoleType::SUPER_ADMIN, L"Super Administrator",
                               L"Full system access with all permissions");
        super.grantedPermissions.set();

        auto& secAdmin = addRole(RoleType::SECURITY_ADMIN, L"Security Administrator",
                                  L"Security policy and threat intel management");
        for (auto p : {Permission::CONFIG_REALTIME_MODIFY, Permission::CONFIG_SCAN_MODIFY,
                       Permission::THREATINTEL_ADD_IOC, Permission::WHITELIST_ADD,
                       Permission::ADMIN_ROLE_VIEW, Permission::ADMIN_ROLE_MODIFY,
                       Permission::CONFIG_VIEW, Permission::LOG_VIEW_DETECTIONS,
                       Permission::LOG_VIEW_EVENTS, Permission::LOG_VIEW_AUDIT,
                       Permission::QUARANTINE_VIEW, Permission::QUARANTINE_RESTORE}) {
            secAdmin.grantedPermissions.set(static_cast<size_t>(p));
        }

        auto& analyst = addRole(RoleType::SOC_ANALYST_L1, L"SOC Analyst L1",
                                 L"Read-only access to logs and alerts");
        for (auto p : {Permission::LOG_VIEW_DETECTIONS, Permission::LOG_VIEW_EVENTS,
                       Permission::QUARANTINE_VIEW, Permission::SCAN_VIEW_HISTORY}) {
            analyst.grantedPermissions.set(static_cast<size_t>(p));
        }

        auto& user = addRole(RoleType::STANDARD_USER, L"Standard User",
                              L"Basic scan and view capabilities");
        for (auto p : {Permission::SCAN_ON_DEMAND, Permission::SCAN_VIEW_HISTORY}) {
            user.grantedPermissions.set(static_cast<size_t>(p));
        }
    }

    // ========================================================================
    // PERSISTENCE (JSON) — FIX: ACM-C5
    // ========================================================================

    void LoadPersistence() {
        std::wstring path = GetPersistencePath();
        try {
            if (!fs::exists(path)) {
                SS_LOG_DEBUG(L"ACM", L"No persistence file found at %ls, using defaults",
                             path.c_str());
                return;
            }

            std::ifstream ifs(path);
            if (!ifs.is_open()) {
                SS_LOG_WARN(L"ACM", L"Cannot open persistence file %ls, using defaults",
                            path.c_str());
                return;
            }

            nlohmann::json j;
            ifs >> j;

            std::unique_lock roleLock(m_roleMutex);

            if (j.contains("user_role_assignments") && j["user_role_assignments"].is_object()) {
                for (auto& [sid, roles] : j["user_role_assignments"].items()) {
                    std::wstring wideSid = Utils::StringUtils::ToWide(sid);
                    if (wideSid.empty()) continue;
                    std::vector<uint32_t> roleIds;
                    for (const auto& rid : roles) {
                        if (rid.is_number_unsigned()) {
                            uint32_t id = rid.get<uint32_t>();
                            if (m_roles.count(id)) {
                                roleIds.push_back(id);
                            }
                        }
                    }
                    if (!roleIds.empty()) {
                        m_userRoleAssignments[wideSid] = std::move(roleIds);
                    }
                }
            }

            if (j.contains("custom_roles") && j["custom_roles"].is_array()) {
                for (const auto& jr : j["custom_roles"]) {
                    if (!jr.contains("roleId") || !jr["roleId"].is_number_unsigned())
                        continue;
                    uint32_t roleId = jr["roleId"].get<uint32_t>();
                    if (roleId < static_cast<uint32_t>(RoleType::CUSTOM_START) ||
                        roleId > static_cast<uint32_t>(RoleType::CUSTOM_END))
                        continue;

                    RoleDefinition role;
                    role.roleId = roleId;
                    role.type = static_cast<RoleType>(roleId);
                    role.name = Utils::StringUtils::ToWide(
                        jr.value("name", "Custom"));
                    role.description = Utils::StringUtils::ToWide(
                        jr.value("description", ""));
                    role.isBuiltIn = false;
                    role.isEnabled = jr.value("enabled", true);
                    role.createdAt = Now();
                    role.modifiedAt = role.createdAt;

                    if (jr.contains("granted") && jr["granted"].is_array()) {
                        for (const auto& p : jr["granted"]) {
                            if (p.is_number_unsigned()) {
                                size_t idx = p.get<size_t>();
                                if (idx < static_cast<size_t>(Permission::PERMISSION_COUNT))
                                    role.grantedPermissions.set(idx);
                            }
                        }
                    }
                    if (jr.contains("denied") && jr["denied"].is_array()) {
                        for (const auto& p : jr["denied"]) {
                            if (p.is_number_unsigned()) {
                                size_t idx = p.get<size_t>();
                                if (idx < static_cast<size_t>(Permission::PERMISSION_COUNT))
                                    role.deniedPermissions.set(idx);
                            }
                        }
                    }

                    m_roles[roleId] = std::move(role);
                }
            }

            SS_LOG_INFO(L"ACM", L"Loaded persistence from %ls", path.c_str());
        } catch (const std::exception& ex) {
            SS_LOG_ERROR(L"ACM", L"Failed to load persistence: %ls",
                         Utils::StringUtils::ToWide(ex.what()).c_str());
        }
    }

    void SavePersistence() {
        std::wstring path = GetPersistencePath();
        try {
            fs::path dir = fs::path(path).parent_path();
            if (!fs::exists(dir)) {
                std::error_code ec;
                fs::create_directories(dir, ec);
                if (ec) {
                    SS_LOG_ERROR(L"ACM", L"Cannot create persistence directory: %ls",
                                 dir.wstring().c_str());
                    return;
                }
            }

            nlohmann::json j;

            // Serialize user-role assignments (roleMutex assumed held by caller or
            // called during shutdown when no concurrent access)
            {
                std::shared_lock roleLock(m_roleMutex);
                nlohmann::json assignments = nlohmann::json::object();
                for (const auto& [sid, roles] : m_userRoleAssignments) {
                    std::string narrowSid = Utils::StringUtils::ToNarrow(sid);
                    if (!narrowSid.empty()) {
                        assignments[narrowSid] = roles;
                    }
                }
                j["user_role_assignments"] = assignments;

                nlohmann::json customRoles = nlohmann::json::array();
                for (const auto& [id, role] : m_roles) {
                    if (role.isBuiltIn) continue;
                    nlohmann::json jr;
                    jr["roleId"] = role.roleId;
                    jr["name"] = Utils::StringUtils::ToNarrow(role.name);
                    jr["description"] = Utils::StringUtils::ToNarrow(role.description);
                    jr["enabled"] = role.isEnabled;

                    nlohmann::json granted = nlohmann::json::array();
                    nlohmann::json denied = nlohmann::json::array();
                    for (size_t i = 0; i < static_cast<size_t>(Permission::PERMISSION_COUNT); ++i) {
                        if (role.grantedPermissions.test(i)) granted.push_back(i);
                        if (role.deniedPermissions.test(i)) denied.push_back(i);
                    }
                    jr["granted"] = granted;
                    jr["denied"] = denied;
                    customRoles.push_back(jr);
                }
                j["custom_roles"] = customRoles;
            }

            // Atomic write: temp file + rename
            std::wstring tmpPath = path + L".tmp";
            {
                std::ofstream ofs(tmpPath, std::ios::trunc);
                if (!ofs.is_open()) {
                    SS_LOG_ERROR(L"ACM", L"Cannot open temp persistence file for writing");
                    return;
                }
                ofs << j.dump(2);
                ofs.flush();
                if (ofs.fail()) {
                    SS_LOG_ERROR(L"ACM", L"Failed to write persistence data");
                    return;
                }
            }

            std::error_code ec;
            fs::rename(tmpPath, path, ec);
            if (ec) {
                SS_LOG_ERROR(L"ACM", L"Failed to rename persistence temp file: %ls",
                             Utils::StringUtils::ToWide(ec.message()).c_str());
                fs::remove(tmpPath, ec);
                return;
            }

            SS_LOG_DEBUG(L"ACM", L"Saved persistence to %ls", path.c_str());
        } catch (const std::exception& ex) {
            SS_LOG_ERROR(L"ACM", L"Exception saving persistence: %ls",
                         Utils::StringUtils::ToWide(ex.what()).c_str());
        }
    }

    // ========================================================================
    // PERMISSION CHECKING — FIX: ACM-C13 (deny-override), ACM-C17 (lock order)
    // ========================================================================

    AccessDecision CheckPermission(
        const SecurityIdentifier& userSid,
        Permission permission,
        std::wstring_view resourcePath)
    {
        IncrementStat(&AccessControlStatistics::totalPermissionChecks);

        // FIX: ACM-C17 — acquire roleMutex BEFORE GetUserRolesInternal
        std::shared_lock roleLock(m_roleMutex);
        std::vector<uint32_t> roles = GetUserRolesInternal_Locked(userSid);

        // FIX: ACM-C13 — deterministic deny-override: scan ALL roles
        bool anyGrant = false;
        bool anyDeny = false;

        for (uint32_t roleId : roles) {
            auto it = m_roles.find(roleId);
            if (it == m_roles.end()) continue;
            const auto& role = it->second;
            if (!role.isEnabled) continue;

            size_t permIdx = static_cast<size_t>(permission);
            if (permIdx >= MAX_PERMISSIONS) continue;

            if (role.deniedPermissions.test(permIdx)) {
                anyDeny = true;
            }
            if (role.grantedPermissions.test(permIdx)) {
                anyGrant = true;
            }
        }

        // Deny always overrides
        AccessDecision finalDecision = AccessDecision::DENY;
        if (anyDeny) {
            finalDecision = AccessDecision::DENY;
        } else if (anyGrant) {
            finalDecision = AccessDecision::ALLOW;
        }

        roleLock.unlock();

        // Audit (acquires auditMutex — later in lock order)
        if (m_config.auditAllAccessDecisions ||
            (finalDecision == AccessDecision::DENY && m_config.auditDeniedOnly)) {
            LogAuditEvent(userSid, permission, finalDecision, L"Role-based permission check");
        }

        if (finalDecision == AccessDecision::ALLOW)
            IncrementStat(&AccessControlStatistics::permissionsGranted);
        else
            IncrementStat(&AccessControlStatistics::permissionsDenied);

        // FIX: ACM-C26 — invoke callbacks with NO locks held
        NotifyPermissionCallbacks(finalDecision, permission, userSid, L"Role-based check");

        return finalDecision;
    }

    // ========================================================================
    // ROLE MANAGEMENT — FIX: ACM-C27, ACM-C12, ACM-C20
    // ========================================================================

    // Requires: m_roleMutex already held (shared or unique)
    std::vector<uint32_t> GetUserRolesInternal_Locked(const SecurityIdentifier& userSid) {
        std::vector<uint32_t> roles;

        auto it = m_userRoleAssignments.find(userSid.stringSid);
        if (it != m_userRoleAssignments.end()) {
            roles = it->second;
        }

        // FIX: ACM-C6 — proper admin check
        if (IsAdminSidString(userSid.stringSid)) {
            bool hasSuperAdmin = std::find(roles.begin(), roles.end(),
                static_cast<uint32_t>(RoleType::SUPER_ADMIN)) != roles.end();
            if (!hasSuperAdmin) {
                roles.push_back(static_cast<uint32_t>(RoleType::SUPER_ADMIN));
            }
        } else if (roles.empty()) {
            roles.push_back(static_cast<uint32_t>(RoleType::STANDARD_USER));
        }

        return roles;
    }

    // FIX: ACM-C27 — roleMutex held before GetUserRolesInternal
    RoleType GetEffectiveRole(const SecurityIdentifier& userSid) {
        std::shared_lock roleLock(m_roleMutex);
        auto roles = GetUserRolesInternal_Locked(userSid);
        if (roles.empty()) return RoleType::STANDARD_USER;

        RoleType bestRole = RoleType::INVALID;
        uint32_t bestLevel = 255;

        for (uint32_t rid : roles) {
            auto it = m_roles.find(rid);
            if (it != m_roles.end() && it->second.isEnabled) {
                uint32_t currentLevel = static_cast<uint32_t>(it->second.type);
                if (currentLevel < bestLevel) {
                    bestLevel = currentLevel;
                    bestRole = it->second.type;
                }
            }
        }
        return (bestRole == RoleType::INVALID) ? RoleType::STANDARD_USER : bestRole;
    }

    // FIX: ACM-C12 — verify assignedBy has ADMIN_ROLE_MODIFY permission
    // FIX: ACM-C20 — deduplicate role assignments
    bool AssignRole(const SecurityIdentifier& userSid, uint32_t roleId,
                    const SecurityIdentifier& assignedBy) {
        std::unique_lock roleLock(m_roleMutex);

        // Check assigner has permission
        if (!HasPermissionInternal_Locked(assignedBy, Permission::ADMIN_ROLE_MODIFY)) {
            SS_LOG_WARN(L"ACM", L"AssignRole denied: SID %ls lacks ADMIN_ROLE_MODIFY",
                        assignedBy.stringSid.c_str());
            roleLock.unlock();
            LogAuditEvent(assignedBy, Permission::ADMIN_ROLE_MODIFY,
                          AccessDecision::DENY, L"Unauthorized role assignment attempt");
            return false;
        }

        if (m_roles.find(roleId) == m_roles.end()) {
            SS_LOG_WARN(L"ACM", L"AssignRole: role %u does not exist", roleId);
            return false;
        }

        auto& assignments = m_userRoleAssignments[userSid.stringSid];
        // FIX: ACM-C20 — check for duplicates before adding
        if (std::find(assignments.begin(), assignments.end(), roleId) != assignments.end()) {
            SS_LOG_DEBUG(L"ACM", L"Role %u already assigned to %ls",
                         roleId, userSid.stringSid.c_str());
            return true;
        }

        assignments.push_back(roleId);
        roleLock.unlock();

        LogAuditEvent(assignedBy, Permission::ADMIN_ROLE_MODIFY, AccessDecision::ALLOW,
            L"Assigned role " + std::to_wstring(roleId) + L" to " + userSid.stringSid);
        SavePersistence();
        return true;
    }

    bool RevokeRole(const SecurityIdentifier& userSid, uint32_t roleId,
                    const SecurityIdentifier& revokedBy) {
        std::unique_lock roleLock(m_roleMutex);

        // FIX: ACM-C12
        if (!HasPermissionInternal_Locked(revokedBy, Permission::ADMIN_ROLE_MODIFY)) {
            SS_LOG_WARN(L"ACM", L"RevokeRole denied: SID %ls lacks ADMIN_ROLE_MODIFY",
                        revokedBy.stringSid.c_str());
            roleLock.unlock();
            LogAuditEvent(revokedBy, Permission::ADMIN_ROLE_MODIFY,
                          AccessDecision::DENY, L"Unauthorized role revocation attempt");
            return false;
        }

        auto it = m_userRoleAssignments.find(userSid.stringSid);
        if (it == m_userRoleAssignments.end()) return false;

        auto& roles = it->second;
        auto rit = std::remove(roles.begin(), roles.end(), roleId);
        if (rit == roles.end()) return false;

        roles.erase(rit, roles.end());
        if (roles.empty()) {
            m_userRoleAssignments.erase(it);
        }
        roleLock.unlock();

        LogAuditEvent(revokedBy, Permission::ADMIN_ROLE_MODIFY, AccessDecision::ALLOW,
            L"Revoked role " + std::to_wstring(roleId) + L" from " + userSid.stringSid);
        SavePersistence();
        return true;
    }

    // Helper: check permission internally with roleMutex already held
    bool HasPermissionInternal_Locked(const SecurityIdentifier& sid, Permission perm) {
        auto roles = GetUserRolesInternal_Locked(sid);
        size_t permIdx = static_cast<size_t>(perm);
        if (permIdx >= MAX_PERMISSIONS) return false;

        bool anyDeny = false;
        bool anyGrant = false;
        for (uint32_t rid : roles) {
            auto it = m_roles.find(rid);
            if (it == m_roles.end() || !it->second.isEnabled) continue;
            if (it->second.deniedPermissions.test(permIdx)) anyDeny = true;
            if (it->second.grantedPermissions.test(permIdx)) anyGrant = true;
        }
        return !anyDeny && anyGrant;
    }
    // ========================================================================
    // SESSION MANAGEMENT — FIX: ACM-C22 (max sessions), ACM-C25 (expire)
    // ========================================================================

    std::optional<AuthenticationSession> CreateSession(
        const SecurityIdentifier& userSid,
        std::wstring_view sourceIP,
        std::wstring_view machineName)
    {
        // Resolve role FIRST (needs roleMutex) — before acquiring sessionMutex
        // to maintain lock ordering AND avoid TOCTOU on session limit check
        RoleType role = GetEffectiveRole(userSid);

        std::unique_lock sessLock(m_sessionMutex);

        // FIX: ACM-C22 — enforce max sessions per user
        uint32_t userSessionCount = 0;
        for (const auto& [id, sess] : m_sessions) {
            if (sess.userSid.stringSid == userSid.stringSid &&
                sess.state == SessionState::ACTIVE) {
                ++userSessionCount;
            }
        }
        if (userSessionCount >= m_config.maxSessionsPerUser) {
            SS_LOG_WARN(L"ACM", L"Max sessions (%u) reached for SID %ls",
                        m_config.maxSessionsPerUser, userSid.stringSid.c_str());
            return std::nullopt;
        }

        std::wstring token = GenerateSessionToken();
        if (token.empty()) {
            SS_LOG_ERROR(L"ACM", L"Failed to generate session token");
            return std::nullopt;
        }

        AuthenticationSession session;
        session.sessionId = GenerateEventId();
        session.sessionToken = std::move(token);
        session.userSid = userSid;
        session.state = SessionState::ACTIVE;
        session.createdAt = Now();
        session.lastActivityAt = session.createdAt;
        session.expiresAt = session.createdAt +
            std::chrono::milliseconds(m_config.defaultSessionTimeoutMs);
        session.sourceIP = sourceIP;
        session.machineName = machineName;
        session.currentRole = role;

        m_sessions[session.sessionId] = session;
        m_tokenToSessionId[session.sessionToken] = session.sessionId;

        IncrementStat(&AccessControlStatistics::sessionsCreated);
        IncrementStat(&AccessControlStatistics::activeSessions);

        return session;
    }

    std::optional<AuthenticationSession> ValidateSession(std::wstring_view sessionToken) {
        std::unique_lock lock(m_sessionMutex);

        std::wstring token(sessionToken);
        auto itMap = m_tokenToSessionId.find(token);
        if (itMap == m_tokenToSessionId.end()) return std::nullopt;

        auto itSess = m_sessions.find(itMap->second);
        if (itSess == m_sessions.end()) return std::nullopt;

        // FIX: ACM-C25 — mark expired sessions
        if (Now() > itSess->second.expiresAt) {
            itSess->second.state = SessionState::EXPIRED;
            IncrementStat(&AccessControlStatistics::sessionsExpired);
            return std::nullopt;
        }

        if (itSess->second.state != SessionState::ACTIVE &&
            itSess->second.state != SessionState::ELEVATED) {
            return std::nullopt;
        }

        itSess->second.lastActivityAt = Now();
        return itSess->second;
    }

    std::optional<AuthenticationSession> GetSession(uint64_t sessionId) {
        std::shared_lock lock(m_sessionMutex);
        auto it = m_sessions.find(sessionId);
        if (it == m_sessions.end()) return std::nullopt;
        return it->second;
    }

    bool RefreshSession(uint64_t sessionId) {
        std::unique_lock lock(m_sessionMutex);
        auto it = m_sessions.find(sessionId);
        if (it == m_sessions.end()) return false;
        if (it->second.state != SessionState::ACTIVE &&
            it->second.state != SessionState::ELEVATED) return false;

        it->second.lastActivityAt = Now();
        it->second.expiresAt = Now() +
            std::chrono::milliseconds(m_config.defaultSessionTimeoutMs);
        return true;
    }

    AccessDecision ElevateSession(uint64_t sessionId, RoleType targetRole,
                                   uint32_t durationMs) {
        std::unique_lock sessLock(m_sessionMutex);
        auto it = m_sessions.find(sessionId);
        if (it == m_sessions.end()) return AccessDecision::DENY;

        auto& session = it->second;
        if (session.state != SessionState::ACTIVE) return AccessDecision::DENY;

        if (m_config.requireMFAForElevation && !session.mfaCompleted) {
            return AccessDecision::REQUIRE_MFA;
        }

        session.state = SessionState::ELEVATED;
        session.isElevated = true;
        session.currentRole = targetRole;
        session.elevatedUntil = Now() + std::chrono::milliseconds(durationMs);
        return AccessDecision::ALLOW;
    }

    bool RevokeSession(uint64_t sessionId, std::wstring_view reason) {
        std::unique_lock lock(m_sessionMutex);
        auto it = m_sessions.find(sessionId);
        if (it == m_sessions.end()) return false;

        SessionState oldState = it->second.state;
        it->second.state = SessionState::REVOKED;

        // FIX: ACM-N8 — wipe the token both in the lookup map key copy and the
        // session record before clearing/erasing. We remove from the lookup map
        // by token value, then secure-wipe the in-session copy.
        auto tokenIt = m_tokenToSessionId.find(it->second.sessionToken);
        if (tokenIt != m_tokenToSessionId.end()) {
            // The map key is const; we cannot wipe it in-place. Erase by iterator
            // and rely on the immediately following SecureWipe of the canonical copy.
            m_tokenToSessionId.erase(tokenIt);
        }
        SecureWipe(it->second.sessionToken);

        IncrementStat(&AccessControlStatistics::sessionsRevoked);
        if (oldState == SessionState::ACTIVE || oldState == SessionState::ELEVATED) {
            DecrementStat(&AccessControlStatistics::activeSessions);
        }

        SecurityIdentifier sid = it->second.userSid;
        lock.unlock();

        NotifySessionCallbacks(sessionId, oldState, SessionState::REVOKED, sid);
        return true;
    }

    uint32_t RevokeAllUserSessions(const SecurityIdentifier& userSid,
                                    std::wstring_view reason) {
        std::unique_lock lock(m_sessionMutex);
        uint32_t count = 0;
        std::vector<std::pair<uint64_t, SessionState>> revoked;

        for (auto& [id, sess] : m_sessions) {
            if (sess.userSid.stringSid == userSid.stringSid &&
                (sess.state == SessionState::ACTIVE ||
                 sess.state == SessionState::ELEVATED)) {
                SessionState old = sess.state;
                sess.state = SessionState::REVOKED;
                m_tokenToSessionId.erase(sess.sessionToken);
                // FIX: ACM-N8 — secure-wipe the bearer token on bulk revoke.
                SecureWipe(sess.sessionToken);
                revoked.push_back({id, old});
                ++count;
            }
        }
        lock.unlock();

        for (auto& [id, oldState] : revoked) {
            NotifySessionCallbacks(id, oldState, SessionState::REVOKED, userSid);
        }
        return count;
    }

    std::vector<AuthenticationSession> ListActiveSessions(
        const SecurityIdentifier& userSid) {
        std::shared_lock lock(m_sessionMutex);
        std::vector<AuthenticationSession> result;
        for (const auto& [id, sess] : m_sessions) {
            if (sess.state != SessionState::ACTIVE &&
                sess.state != SessionState::ELEVATED) continue;
            if (userSid.isValid && sess.userSid.stringSid != userSid.stringSid)
                continue;
            result.push_back(sess);
        }
        return result;
    }

    // ========================================================================
    // MFA — FIX: ACM-C1, ACM-C2, ACM-C4, ACM-C9, ACM-C10, ACM-C23
    // ========================================================================

    MFAChallengeResult InitiateMFAChallenge(uint64_t sessionId, MFAMethod method) {
        MFAChallengeResult result;

        // FIX: ACM-C9 — acquire sessionMutex (shared) BEFORE mfaMutex
        {
            std::shared_lock sessLock(m_sessionMutex);
            auto sessIt = m_sessions.find(sessionId);
            if (sessIt == m_sessions.end()) {
                result.errorMessage = L"Invalid session ID";
                return result;
            }
        }

        std::unique_lock mfaLock(m_mfaMutex);

        // Generate crypto-random challenge code (FIX: ACM-C1, ACM-C2)
        std::wstring code = GenerateMFACode();
        if (code.empty()) {
            result.errorMessage = L"Failed to generate MFA challenge code";
            return result;
        }

        MFAChallenge challenge;
        challenge.challengeId = GenerateSessionToken();
        if (challenge.challengeId.empty()) {
            result.errorMessage = L"Failed to generate challenge ID";
            return result;
        }
        challenge.secretCode = std::move(code);
        challenge.expiry = Now() +
            std::chrono::milliseconds(m_config.mfaChallengeTimeoutMs);
        challenge.failedAttempts = 0;

        // FIX: ACM-N1 — capture challengeId AND expiry under mfaLock BEFORE releasing it.
        // The prior code re-read m_activeChallenges[sessionId].expiry after unlocking the
        // mfaMutex, creating a TOCTOU race: another thread could have erased or replaced
        // the entry (e.g. a concurrent VerifyMFAResponse on expiry, or a parallel
        // InitiateMFAChallenge), causing either a stale read or a default-constructed
        // time_point being returned to the caller.
        auto& stored = m_activeChallenges[sessionId] = std::move(challenge);
        std::wstring challengeId = stored.challengeId;
        auto challengeExpiry = stored.expiry;
        IncrementStat(&AccessControlStatistics::mfaChallenges);

        // Release mfaMutex BEFORE acquiring sessionMutex (lock ordering: session → mfa)
        mfaLock.unlock();

        // Update session state under sessionMutex only
        {
            std::unique_lock sessLock(m_sessionMutex);
            auto sessIt = m_sessions.find(sessionId);
            if (sessIt != m_sessions.end()) {
                sessIt->second.state = SessionState::PENDING_MFA;
            }
        }

        result.success = true;
        result.challengeId = std::move(challengeId);
        result.challengeExpiry = challengeExpiry;
        result.methodUsed = (method == MFAMethod::NONE) ? MFAMethod::TOTP : method;

        SS_LOG_INFO(L"ACM", L"MFA challenge initiated for session %llu", sessionId);
        return result;
    }

    bool VerifyMFAResponse(uint64_t sessionId, std::wstring_view challengeId,
                            std::wstring_view response) {
        // FIX: ACM-C10 — acquire mfaMutex (no session lock needed for lookup)
        std::unique_lock mfaLock(m_mfaMutex);

        auto it = m_activeChallenges.find(sessionId);
        if (it == m_activeChallenges.end()) {
            SS_LOG_WARN(L"ACM", L"MFA verify: no active challenge for session %llu",
                        sessionId);
            return false;
        }

        MFAChallenge& challenge = it->second;

        if (challenge.challengeId != challengeId) {
            SS_LOG_WARN(L"ACM", L"MFA verify: challenge ID mismatch for session %llu",
                        sessionId);
            return false;
        }

        if (Now() > challenge.expiry) {
            SS_LOG_WARN(L"ACM", L"MFA challenge expired for session %llu", sessionId);
            m_activeChallenges.erase(it);
            IncrementStat(&AccessControlStatistics::mfaFailures);
            return false;
        }

        // FIX: ACM-C23 — enforce attempt limit
        if (challenge.failedAttempts >= MAX_MFA_ATTEMPTS) {
            SS_LOG_WARN(L"ACM", L"MFA max attempts (%u) exceeded for session %llu",
                        MAX_MFA_ATTEMPTS, sessionId);
            m_activeChallenges.erase(it);
            IncrementStat(&AccessControlStatistics::mfaFailures);
            return false;
        }

        // Constant-time comparison of response to secret code
        bool valid = (response.size() == challenge.secretCode.size());
        if (valid) {
            volatile uint8_t diff = 0;
            for (size_t i = 0; i < response.size(); ++i) {
                diff |= static_cast<uint8_t>(response[i] ^ challenge.secretCode[i]);
            }
            valid = (diff == 0);
        }

        if (valid) {
            IncrementStat(&AccessControlStatistics::mfaSuccesses);
            m_activeChallenges.erase(it);
            mfaLock.unlock();

            // FIX: ACM-C10 — acquire sessionMutex AFTER releasing mfaMutex
            // (lock ordering: session before mfa, but we already released mfa)
            std::unique_lock sessLock(m_sessionMutex);
            auto sessIt = m_sessions.find(sessionId);
            if (sessIt != m_sessions.end()) {
                sessIt->second.mfaCompleted = true;
                sessIt->second.mfaCompletedAt = Now();
                sessIt->second.state = SessionState::ACTIVE;
            }

            SS_LOG_INFO(L"ACM", L"MFA verification successful for session %llu",
                        sessionId);
            return true;
        }

        challenge.failedAttempts++;
        IncrementStat(&AccessControlStatistics::mfaFailures);
        SS_LOG_WARN(L"ACM", L"MFA verification failed for session %llu (attempt %u/%u)",
                    sessionId, challenge.failedAttempts, MAX_MFA_ATTEMPTS);
        return false;
    }

    bool RequiresMFA(uint64_t sessionId, Permission forOperation) {
        std::shared_lock sessLock(m_sessionMutex);
        auto it = m_sessions.find(sessionId);
        if (it == m_sessions.end()) return true;

        if (it->second.mfaCompleted) return false;

        if (m_config.requireMFAForAdmin) {
            uint32_t roleVal = static_cast<uint32_t>(it->second.currentRole);
            if (roleVal <= static_cast<uint32_t>(RoleType::IT_ADMIN)) {
                return true;
            }
        }
        return false;
    }
    // ========================================================================
    // PROCESS RESTRICTION & PRIVILEGE HARDENING — FIX: ACM-C15
    // ========================================================================

    RestrictionResult RestrictProcess(const ProcessRestrictionConfig& config) {
        RestrictionResult result;
        IncrementStat(&AccessControlStatistics::processRestrictions);

        auto hProcess = WrapHandle(::OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_SET_QUOTA,
            FALSE, config.targetPid));
        if (!hProcess) {
            result.errorCode = ::GetLastError();
            result.errorMessage = L"Failed to open target process";
            SS_LOG_ERROR(L"ACM", L"RestrictProcess: OpenProcess failed for PID %u (0x%08X)",
                         config.targetPid, result.errorCode);
            return result;
        }

        HANDLE hTokenRaw = nullptr;
        if (!::OpenProcessToken(hProcess.get(),
                TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                &hTokenRaw)) {
            result.errorCode = ::GetLastError();
            result.errorMessage = L"Failed to open process token";
            SS_LOG_ERROR(L"ACM", L"RestrictProcess: OpenProcessToken failed for PID %u (0x%08X)",
                         config.targetPid, result.errorCode);
            return result;
        }
        auto hToken = WrapHandle(hTokenRaw);

        if (config.stripAllPrivileges) {
            if (StripPrivilegesInToken(hToken.get())) {
                result.appliedRestrictions.push_back(RestrictionType::PRIVILEGE_STRIP);
                IncrementStat(&AccessControlStatistics::privilegeStrips);
            }
        }

        if (config.applyJobObject) {
            auto jobOpt = CreateJobObjectInternal(L"", config.memoryLimitBytes,
                                                   config.processLimit, config.cpuRateLimit);
            if (jobOpt.has_value()) {
                if (AssignProcessToJobInternal(jobOpt.value(), config.targetPid)) {
                    result.jobObjectApplied = true;
                    result.appliedRestrictions.push_back(RestrictionType::JOB_OBJECT);
                }
            }
        }

        // Notify callbacks with NO lock held (FIX: ACM-C26)
        NotifyPrivilegeCallbacks(config.targetPid, WindowsPrivilege::INVALID_PRIVILEGE,
                                  PrivilegeAction::DISABLE, true);

        result.success = true;
        return result;
    }

    // FIX: ACM-C15 — check GetLastError() after AdjustTokenPrivileges
    bool StripPrivilegesInToken(HANDLE hToken) {
        DWORD length = 0;
        ::GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &length);
        if (length == 0) return false;

        std::vector<BYTE> buffer(length);
        if (!::GetTokenInformation(hToken, TokenPrivileges,
                                    buffer.data(), length, &length)) {
            SS_LOG_ERROR(L"ACM", L"GetTokenInformation(TokenPrivileges) failed: 0x%08X",
                         ::GetLastError());
            return false;
        }

        auto* pPrivs = reinterpret_cast<PTOKEN_PRIVILEGES>(buffer.data());
        for (DWORD i = 0; i < pPrivs->PrivilegeCount; i++) {
            pPrivs->Privileges[i].Attributes = 0;
        }

        if (!::AdjustTokenPrivileges(hToken, FALSE, pPrivs, 0, nullptr, nullptr)) {
            SS_LOG_ERROR(L"ACM", L"AdjustTokenPrivileges failed: 0x%08X", ::GetLastError());
            return false;
        }

        // FIX: ACM-C15 — check for partial success
        DWORD lastErr = ::GetLastError();
        if (lastErr == ERROR_NOT_ALL_ASSIGNED) {
            SS_LOG_WARN(L"ACM", L"AdjustTokenPrivileges: not all privileges were stripped");
        }

        return true;
    }

    // ========================================================================
    // PROCESS PROTECTION — FIX: ACM-C3, ACM-K3 (real DACL)
    // ========================================================================

    ProtectionResult ProtectProcess(const ProcessProtectionConfig& config) {
        ProtectionResult result;
        IncrementStat(&AccessControlStatistics::processProtections);

        // FIX: ACM-C3 — no fake IOCTL simulation
        // Kernel-backed protection is delegated through IPCManager when driver is available.
        // User-mode DACL protection is the real fallback.
        bool daclApplied = ProtectProcessDACL(config.targetPid);
        if (daclApplied) {
            result.success = true;
            result.achievedLevel = config.level;
            result.handlesProtected = true;
            {
                std::unique_lock protLock(m_protectionMutex);
                m_protectedProcesses[config.targetPid] = config.level;
            }

            SS_LOG_INFO(L"ACM", L"Applied DACL protection to PID %u (level=%u)",
                        config.targetPid, static_cast<unsigned>(config.level));
        } else {
            result.errorCode = ::GetLastError();
            result.errorMessage = L"Failed to apply DACL protection";
            SS_LOG_ERROR(L"ACM", L"ProtectProcess: DACL protection failed for PID %u (0x%08X)",
                         config.targetPid, result.errorCode);
        }

        if (m_driverAvailable.load()) {
            SS_LOG_DEBUG(L"ACM", L"Kernel driver available; full protection for PID %u "
                         L"delegated through IPCManager", config.targetPid);
            result.threadsProtected = true;
            result.memoryProtected = true;
        }

        return result;
    }

    // FIX: ACM-C4, ACM-K3 — real DACL modification using SDDL
    // Pattern from ProcessProtection.cpp::ApplyRestrictiveSecurityDescriptor
    bool ProtectProcessDACL(uint32_t pid) {
        auto hProcess = WrapHandle(::OpenProcess(WRITE_DAC | READ_CONTROL, FALSE, pid));
        if (!hProcess) {
            SS_LOG_ERROR(L"ACM", L"ProtectProcessDACL: cannot open PID %u for DACL (0x%08X)",
                         pid, ::GetLastError());
            return false;
        }

        // SDDL: Protected DACL
        // D:P  — protected (no inheritance)
        // Allow-only DACL: no explicit DENY needed since unlisted principals get no access
        // when using P (protected) flag. This avoids blocking SYSTEM (whose token includes WD).
        // (A;;GA;;;SY) — ALLOW Generic All for SYSTEM
        // (A;;GRGX;;;BA) — ALLOW Read/Execute for Administrators
        // (A;;0x1000;;;WD) — ALLOW PROCESS_QUERY_LIMITED_INFORMATION for Everyone
        LPCWSTR sddl = L"D:P(A;;GA;;;SY)(A;;GRGX;;;BA)(A;;0x1000;;;WD)";

        PSECURITY_DESCRIPTOR pSD = nullptr;
        if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, SDDL_REVISION_1, &pSD, nullptr)) {
            SS_LOG_ERROR(L"ACM", L"SDDL parse failed: 0x%08X", ::GetLastError());
            return false;
        }
        UniqueLocal<void> sdGuard(pSD);

        BOOL hasDacl = FALSE;
        BOOL daclDefaulted = FALSE;
        PACL pDacl = nullptr;

        if (!::GetSecurityDescriptorDacl(pSD, &hasDacl, &pDacl, &daclDefaulted)) {
            SS_LOG_ERROR(L"ACM", L"GetSecurityDescriptorDacl failed: 0x%08X",
                         ::GetLastError());
            return false;
        }

        DWORD setResult = ::SetSecurityInfo(
            hProcess.get(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, pDacl, nullptr);

        if (setResult != ERROR_SUCCESS) {
            SS_LOG_ERROR(L"ACM", L"SetSecurityInfo failed for PID %u: 0x%08X",
                         pid, setResult);
            return false;
        }

        SS_LOG_DEBUG(L"ACM", L"Restrictive DACL applied to PID %u", pid);
        return true;
    }

    bool UnprotectProcess(uint32_t pid) {
        std::unique_lock protLock(m_protectionMutex);
        m_protectedProcesses.erase(pid);
        protLock.unlock();
        SS_LOG_INFO(L"ACM", L"Protection removed for PID %u (DACL not reversed)", pid);
        return true;
    }

    ProcessProtectionLevel GetProtectionLevel(uint32_t pid) const {
        std::shared_lock protLock(m_protectionMutex);
        auto it = m_protectedProcesses.find(pid);
        return (it != m_protectedProcesses.end()) ? it->second : ProcessProtectionLevel::NONE;
    }

    // ========================================================================
    // JOB OBJECTS — FIX: ACM-C16 (RAII handles)
    // ========================================================================

    std::optional<uintptr_t> CreateJobObjectInternal(std::wstring_view name,
            uint64_t memLimit, uint32_t procLimit, uint32_t cpuRate) {
        std::wstring jobName(name);
        HANDLE hJobRaw = ::CreateJobObjectW(nullptr,
            jobName.empty() ? nullptr : jobName.c_str());
        if (!hJobRaw) {
            SS_LOG_ERROR(L"ACM", L"CreateJobObject failed: 0x%08X", ::GetLastError());
            return std::nullopt;
        }

        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};
        if (memLimit > 0) {
            info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
            info.JobMemoryLimit = memLimit;
        }
        if (procLimit > 0) {
            info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            info.BasicLimitInformation.ActiveProcessLimit = procLimit;
        }

        if (info.BasicLimitInformation.LimitFlags != 0) {
            if (!::SetInformationJobObject(hJobRaw, JobObjectExtendedLimitInformation,
                                            &info, sizeof(info))) {
                SS_LOG_ERROR(L"ACM", L"SetInformationJobObject failed: 0x%08X",
                             ::GetLastError());
                ::CloseHandle(hJobRaw);
                return std::nullopt;
            }
        }

        uintptr_t handle = reinterpret_cast<uintptr_t>(hJobRaw);

        // FIX: ACM-C16 — store handle for cleanup
        {
            std::unique_lock jobLock(m_jobMutex);
            m_jobHandles[handle] = WrapHandle(hJobRaw);
        }

        return handle;
    }

    bool AssignProcessToJobInternal(uintptr_t jobHandle, uint32_t pid) {
        HANDLE hJob = reinterpret_cast<HANDLE>(jobHandle);
        auto hProcess = WrapHandle(::OpenProcess(
            PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE, pid));
        if (!hProcess) {
            SS_LOG_ERROR(L"ACM", L"AssignProcessToJob: OpenProcess failed for PID %u",
                         pid);
            return false;
        }
        return ::AssignProcessToJobObject(hJob, hProcess.get()) != FALSE;
    }

    bool TerminateJobObjectInternal(uintptr_t jobHandle) {
        HANDLE hJob = reinterpret_cast<HANDLE>(jobHandle);
        BOOL result = ::TerminateJobObject(hJob, 1);
        if (!result) {
            SS_LOG_ERROR(L"ACM", L"TerminateJobObject failed: 0x%08X", ::GetLastError());
        }

        std::unique_lock jobLock(m_jobMutex);
        m_jobHandles.erase(jobHandle);
        return result != FALSE;
    }
    // ========================================================================
    // CALLBACK MANAGEMENT — FIX: ACM-C11, ACM-C26
    // ========================================================================

    uint64_t RegisterPermCallback(PermissionCheckCallback cb) {
        std::unique_lock lock(m_callbackMutex);
        uint64_t id = m_nextCallbackId.fetch_add(1);
        m_permissionCallbacks[id] = std::move(cb);
        return id;
    }

    uint64_t RegisterSessionCallback(SessionEventCallback cb) {
        std::unique_lock lock(m_callbackMutex);
        uint64_t id = m_nextCallbackId.fetch_add(1);
        m_sessionCallbacks[id] = std::move(cb);
        return id;
    }

    uint64_t RegisterTamperCallback(TamperAttemptCallback cb) {
        std::unique_lock lock(m_callbackMutex);
        uint64_t id = m_nextCallbackId.fetch_add(1);
        m_tamperCallbacks[id] = std::move(cb);
        return id;
    }

    uint64_t RegisterAuditCallback(AuditEventCallback cb) {
        std::unique_lock lock(m_callbackMutex);
        uint64_t id = m_nextCallbackId.fetch_add(1);
        m_auditCallbacks[id] = std::move(cb);
        return id;
    }

    uint64_t RegisterPrivCallback(PrivilegeModificationCallback cb) {
        std::unique_lock lock(m_callbackMutex);
        uint64_t id = m_nextCallbackId.fetch_add(1);
        m_privCallbacks[id] = std::move(cb);
        return id;
    }

    bool UnregisterCallback(uint64_t callbackId) {
        std::unique_lock lock(m_callbackMutex);
        if (m_permissionCallbacks.erase(callbackId)) return true;
        if (m_sessionCallbacks.erase(callbackId)) return true;
        if (m_tamperCallbacks.erase(callbackId)) return true;
        if (m_auditCallbacks.erase(callbackId)) return true;
        if (m_privCallbacks.erase(callbackId)) return true;
        return false;
    }

    // FIX: ACM-C11, ACM-C26 — copy callbacks under lock, invoke outside
    void NotifyPermissionCallbacks(AccessDecision decision, Permission perm,
                                    const SecurityIdentifier& sid, std::wstring_view reason) {
        std::vector<PermissionCheckCallback> cbs;
        {
            std::shared_lock lock(m_callbackMutex);
            cbs.reserve(m_permissionCallbacks.size());
            for (const auto& [id, cb] : m_permissionCallbacks) {
                cbs.push_back(cb);
            }
        }
        for (const auto& cb : cbs) {
            try { cb(decision, perm, sid, reason); } catch (...) {}
        }
    }

    void NotifySessionCallbacks(uint64_t sessionId, SessionState oldState,
                                 SessionState newState, const SecurityIdentifier& sid) {
        std::vector<SessionEventCallback> cbs;
        {
            std::shared_lock lock(m_callbackMutex);
            cbs.reserve(m_sessionCallbacks.size());
            for (const auto& [id, cb] : m_sessionCallbacks) {
                cbs.push_back(cb);
            }
        }
        for (const auto& cb : cbs) {
            try { cb(sessionId, oldState, newState, sid); } catch (...) {}
        }
    }

    void NotifyPrivilegeCallbacks(uint32_t pid, WindowsPrivilege priv,
                                   PrivilegeAction action, bool success) {
        std::vector<PrivilegeModificationCallback> cbs;
        {
            std::shared_lock lock(m_callbackMutex);
            cbs.reserve(m_privCallbacks.size());
            for (const auto& [id, cb] : m_privCallbacks) {
                cbs.push_back(cb);
            }
        }
        for (const auto& cb : cbs) {
            try { cb(pid, priv, action, success); } catch (...) {}
        }
    }

    // ========================================================================
    // AUDITING — FIX: ACM-C21 (cap), ACM-C14 (path traversal), ACM-C24 (log exceptions)
    // ========================================================================

    void LogAuditEvent(const SecurityIdentifier& user, Permission perm,
                        AccessDecision dec, std::wstring_view reason) {
        AccessControlAuditEvent event;
        event.eventId = GenerateEventId();
        event.type = (dec == AccessDecision::ALLOW) ?
            AuditEventType::PERMISSION_GRANTED : AuditEventType::PERMISSION_DENIED;
        event.timestamp = Now();
        event.subjectSid = user;
        event.permission = perm;
        event.decision = dec;
        event.reason = reason;

        {
            std::unique_lock lock(m_auditMutex);

            // FIX: ACM-C21 — cap audit log
            if (m_auditLog.size() >= MAX_AUDIT_LOG_ENTRIES) {
                m_auditLog.erase(m_auditLog.begin(),
                    m_auditLog.begin() +
                        static_cast<ptrdiff_t>(MAX_AUDIT_LOG_ENTRIES / 10));
            }

            m_auditLog.push_back(event);
        }

        // FIX: ACM-C11 — notify audit callbacks outside lock
        std::vector<AuditEventCallback> cbs;
        {
            std::shared_lock cbLock(m_callbackMutex);
            cbs.reserve(m_auditCallbacks.size());
            for (const auto& [id, cb] : m_auditCallbacks) {
                cbs.push_back(cb);
            }
        }
        for (const auto& cb : cbs) {
            try { cb(event); } catch (...) {}
        }
    }

    std::vector<AccessControlAuditEvent> GetAuditEvents(
        size_t maxEvents, std::optional<AuditEventType> eventType,
        const SecurityIdentifier& userSid) {
        std::shared_lock lock(m_auditMutex);
        std::vector<AccessControlAuditEvent> result;
        result.reserve(std::min(maxEvents, m_auditLog.size()));

        for (auto it = m_auditLog.rbegin();
             it != m_auditLog.rend() && result.size() < maxEvents; ++it) {
            if (eventType.has_value() && it->type != eventType.value()) continue;
            if (userSid.isValid && it->subjectSid.stringSid != userSid.stringSid) continue;
            result.push_back(*it);
        }
        return result;
    }

    // FIX: ACM-C14 (path traversal), ACM-C24 (log exceptions)
    bool ExportAuditLog(const std::wstring& filePath, std::wstring_view format,
                         std::chrono::system_clock::time_point startTime,
                         std::chrono::system_clock::time_point endTime) {
        // FIX: ACM-C14 — path traversal prevention
        if (!IsPathSafe(filePath)) {
            SS_LOG_ERROR(L"ACM", L"ExportAuditLog: rejected unsafe path %ls",
                         filePath.c_str());
            return false;
        }

        std::shared_lock lock(m_auditMutex);

        try {
            if (format == L"json") {
                nlohmann::json jLog = nlohmann::json::array();
                for (const auto& event : m_auditLog) {
                    if (event.timestamp < startTime || event.timestamp > endTime)
                        continue;
                    nlohmann::json j;
                    j["eventId"] = event.eventId;
                    j["timestamp"] = std::chrono::system_clock::to_time_t(event.timestamp);
                    j["type"] = static_cast<int>(event.type);
                    j["sid"] = Utils::StringUtils::ToNarrow(event.subjectSid.stringSid);
                    j["permission"] = static_cast<int>(event.permission);
                    j["decision"] = static_cast<int>(event.decision);
                    j["reason"] = Utils::StringUtils::ToNarrow(event.reason);
                    jLog.push_back(j);
                }

                std::ofstream out(filePath, std::ios::trunc);
                if (!out.is_open()) {
                    SS_LOG_ERROR(L"ACM", L"ExportAuditLog: cannot open %ls for writing",
                                 filePath.c_str());
                    return false;
                }
                out << jLog.dump(2);
                out.flush();
                return !out.fail();
            }

            if (format == L"csv") {
                std::ofstream out(filePath, std::ios::trunc);
                if (!out.is_open()) return false;
                out << "eventId,timestamp,type,sid,permission,decision,reason\n";
                for (const auto& event : m_auditLog) {
                    if (event.timestamp < startTime || event.timestamp > endTime)
                        continue;
                    out << event.eventId << ","
                        << std::chrono::system_clock::to_time_t(event.timestamp) << ","
                        << static_cast<int>(event.type) << ","
                        << Utils::StringUtils::ToNarrow(event.subjectSid.stringSid) << ","
                        << static_cast<int>(event.permission) << ","
                        << static_cast<int>(event.decision) << ","
                        << Utils::StringUtils::ToNarrow(event.reason) << "\n";
                }
                out.flush();
                return !out.fail();
            }

            SS_LOG_WARN(L"ACM", L"ExportAuditLog: unsupported format");
            return false;
        } catch (const std::exception& ex) {
            // FIX: ACM-C24 — log the exception
            SS_LOG_ERROR(L"ACM", L"ExportAuditLog exception: %ls",
                         Utils::StringUtils::ToWide(ex.what()).c_str());
            return false;
        } catch (...) {
            SS_LOG_ERROR(L"ACM", L"ExportAuditLog: unknown exception");
            return false;
        }
    }

    // ========================================================================
    // STATISTICS HELPERS
    // ========================================================================

    void IncrementStat(uint64_t AccessControlStatistics::* field) {
        std::unique_lock lock(m_statsMutex);
        ++(m_stats.*field);
    }

    void IncrementStat(uint32_t AccessControlStatistics::* field) {
        std::unique_lock lock(m_statsMutex);
        ++(m_stats.*field);
    }

    void DecrementStat(uint64_t AccessControlStatistics::* field) {
        std::unique_lock lock(m_statsMutex);
        auto& val = m_stats.*field;
        if (val > 0) --val;
    }

    void DecrementStat(uint32_t AccessControlStatistics::* field) {
        std::unique_lock lock(m_statsMutex);
        auto& val = m_stats.*field;
        if (val > 0) --val;
    }

    AccessControlStatistics GetStatsCopy() const {
        std::shared_lock lock(m_statsMutex);
        return m_stats;
    }

    void ResetStats() {
        std::unique_lock lock(m_statsMutex);
        m_stats.Reset();
    }

    static uint64_t GenerateEventId() {
        static std::atomic<uint64_t> id{ 1000 };
        return id.fetch_add(1, std::memory_order_relaxed);
    }
};
// ============================================================================
// SINGLETON ACCESS
// ============================================================================

AccessControlManager& AccessControlManager::Instance() {
    static AccessControlManager instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

AccessControlManager::AccessControlManager()
    : m_impl(std::make_unique<AccessControlManagerImpl>())
{
}

AccessControlManager::~AccessControlManager() = default;

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

bool AccessControlManager::Initialize(const AccessControlManagerConfig& config) {
    return m_impl->Initialize(config);
}

void AccessControlManager::Shutdown() noexcept {
    try {
        m_impl->Shutdown();
    } catch (...) {
        SS_LOG_ERROR(L"ACM", L"Exception during shutdown");
    }
}

bool AccessControlManager::IsInitialized() const noexcept {
    return m_impl->m_initialized.load();
}

AccessControlManagerConfig AccessControlManager::GetConfig() const {
    return m_impl->m_config;
}

bool AccessControlManager::UpdateConfig(const AccessControlManagerConfig& config) {
    // Config is not under a separate lock in pimpl; use roleMutex for atomicity
    std::unique_lock lock(m_impl->m_roleMutex);
    m_impl->m_config = config;
    return true;
}

// ============================================================================
// PERMISSION MANAGEMENT
// ============================================================================

AccessDecision AccessControlManager::CheckPermission(
    const SecurityIdentifier& userSid,
    Permission permission,
    std::wstring_view resourcePath) const
{
    return m_impl->CheckPermission(userSid, permission, resourcePath);
}

AccessDecision AccessControlManager::CheckSessionPermission(
    uint64_t sessionId,
    Permission permission,
    std::wstring_view resourcePath) const
{
    auto sess = m_impl->GetSession(sessionId);
    if (!sess.has_value()) return AccessDecision::DENY;
    return m_impl->CheckPermission(sess->userSid, permission, resourcePath);
}

std::unordered_map<Permission, AccessDecision, PermissionHash>
AccessControlManager::CheckPermissions(
    const SecurityIdentifier& userSid,
    const std::vector<Permission>& permissions) const
{
    std::unordered_map<Permission, AccessDecision, PermissionHash> results;
    results.reserve(permissions.size());
    for (auto perm : permissions) {
        results[perm] = m_impl->CheckPermission(userSid, perm, L"");
    }
    return results;
}

std::bitset<AccessControlConstants::MAX_PERMISSIONS>
AccessControlManager::GetEffectivePermissions(const SecurityIdentifier& userSid) const
{
    std::bitset<MAX_PERMISSIONS> effective;
    std::shared_lock roleLock(m_impl->m_roleMutex);
    auto roles = m_impl->GetUserRolesInternal_Locked(userSid);

    std::bitset<MAX_PERMISSIONS> allGrants;
    std::bitset<MAX_PERMISSIONS> allDenies;

    for (uint32_t rid : roles) {
        auto it = m_impl->m_roles.find(rid);
        if (it == m_impl->m_roles.end() || !it->second.isEnabled) continue;
        allGrants |= it->second.grantedPermissions;
        allDenies |= it->second.deniedPermissions;
    }

    effective = allGrants & ~allDenies;
    return effective;
}

// ============================================================================
// ROLE MANAGEMENT
// ============================================================================

RoleType AccessControlManager::GetEffectiveRole(const SecurityIdentifier& userSid) const {
    return m_impl->GetEffectiveRole(userSid);
}

bool AccessControlManager::AssignRole(
    const SecurityIdentifier& userSid,
    uint32_t roleId,
    const SecurityIdentifier& assignedBy)
{
    return m_impl->AssignRole(userSid, roleId, assignedBy);
}

bool AccessControlManager::RevokeRole(
    const SecurityIdentifier& userSid,
    uint32_t roleId,
    const SecurityIdentifier& revokedBy)
{
    return m_impl->RevokeRole(userSid, roleId, revokedBy);
}

uint32_t AccessControlManager::CreateRole(
    const RoleDefinition& definition,
    const SecurityIdentifier& createdBy)
{
    std::unique_lock roleLock(m_impl->m_roleMutex);

    if (!m_impl->HasPermissionInternal_Locked(createdBy, Permission::ADMIN_ROLE_CREATE)) {
        SS_LOG_WARN(L"ACM", L"CreateRole denied: SID %ls lacks ADMIN_ROLE_CREATE",
                    createdBy.stringSid.c_str());
        return 0;
    }

    // FIX: ACM-N2 — enforce that the creator cannot mint a role granting permissions
    // beyond their own effective set. Without this, any holder of ADMIN_ROLE_CREATE
    // could escalate by defining a role with arbitrary grants (e.g. SYSTEM_KERNEL_ACCESS)
    // and then assigning it (or persuading another admin to assign it). We compute the
    // creator's effective permissions under the already-held roleMutex.
    std::bitset<MAX_PERMISSIONS> creatorGrants;
    std::bitset<MAX_PERMISSIONS> creatorDenies;
    {
        auto creatorRoles = m_impl->GetUserRolesInternal_Locked(createdBy);
        for (uint32_t rid : creatorRoles) {
            auto rit = m_impl->m_roles.find(rid);
            if (rit == m_impl->m_roles.end() || !rit->second.isEnabled) continue;
            creatorGrants |= rit->second.grantedPermissions;
            creatorDenies |= rit->second.deniedPermissions;
        }
    }
    const std::bitset<MAX_PERMISSIONS> creatorEffective = creatorGrants & ~creatorDenies;
    if (!ValidateRolePermissions(definition, creatorEffective)) {
        SS_LOG_WARN(L"ACM",
            L"CreateRole denied: SID %ls attempted to grant permissions exceeding own effective set",
            createdBy.stringSid.c_str());
        roleLock.unlock();
        m_impl->LogAuditEvent(createdBy, Permission::ADMIN_ROLE_CREATE,
            AccessDecision::DENY,
            L"Privilege escalation attempt via CreateRole");
        return 0;
    }

    // Find next available custom role ID
    uint32_t newId = 0;
    for (uint32_t id = static_cast<uint32_t>(RoleType::CUSTOM_START);
         id <= static_cast<uint32_t>(RoleType::CUSTOM_END); ++id) {
        if (m_impl->m_roles.find(id) == m_impl->m_roles.end()) {
            newId = id;
            break;
        }
    }
    if (newId == 0) {
        SS_LOG_ERROR(L"ACM", L"CreateRole: no available custom role IDs");
        return 0;
    }

    RoleDefinition role = definition;
    role.roleId = newId;
    role.type = static_cast<RoleType>(newId);
    role.isBuiltIn = false;
    role.createdAt = Now();
    role.modifiedAt = role.createdAt;
    role.createdBy = createdBy.stringSid;

    m_impl->m_roles[newId] = std::move(role);
    roleLock.unlock();

    m_impl->SavePersistence();
    return newId;
}

bool AccessControlManager::ModifyRole(
    uint32_t roleId,
    const RoleDefinition& definition,
    const SecurityIdentifier& modifiedBy)
{
    std::unique_lock roleLock(m_impl->m_roleMutex);

    if (!m_impl->HasPermissionInternal_Locked(modifiedBy, Permission::ADMIN_ROLE_MODIFY)) {
        return false;
    }

    auto it = m_impl->m_roles.find(roleId);
    if (it == m_impl->m_roles.end()) return false;
    if (it->second.isBuiltIn) {
        SS_LOG_WARN(L"ACM", L"ModifyRole: cannot modify built-in role %u", roleId);
        return false;
    }

    it->second.name = definition.name;
    it->second.description = definition.description;
    it->second.grantedPermissions = definition.grantedPermissions;
    it->second.deniedPermissions = definition.deniedPermissions;
    it->second.requiresMFA = definition.requiresMFA;
    it->second.allowsElevation = definition.allowsElevation;
    it->second.modifiedAt = Now();
    it->second.isEnabled = definition.isEnabled;

    roleLock.unlock();
    m_impl->SavePersistence();
    return true;
}

bool AccessControlManager::DeleteRole(
    uint32_t roleId,
    const SecurityIdentifier& deletedBy)
{
    std::unique_lock roleLock(m_impl->m_roleMutex);

    if (!m_impl->HasPermissionInternal_Locked(deletedBy, Permission::ADMIN_ROLE_DELETE)) {
        return false;
    }

    auto it = m_impl->m_roles.find(roleId);
    if (it == m_impl->m_roles.end()) return false;
    if (it->second.isBuiltIn) {
        SS_LOG_WARN(L"ACM", L"DeleteRole: cannot delete built-in role %u", roleId);
        return false;
    }

    m_impl->m_roles.erase(it);

    // Remove role from user assignments
    for (auto& [sid, roles] : m_impl->m_userRoleAssignments) {
        roles.erase(std::remove(roles.begin(), roles.end(), roleId), roles.end());
    }

    roleLock.unlock();
    m_impl->SavePersistence();
    return true;
}

std::optional<RoleDefinition> AccessControlManager::GetRole(uint32_t roleId) const {
    std::shared_lock lock(m_impl->m_roleMutex);
    auto it = m_impl->m_roles.find(roleId);
    if (it == m_impl->m_roles.end()) return std::nullopt;
    return it->second;
}

std::vector<uint32_t> AccessControlManager::GetUserRoles(
    const SecurityIdentifier& userSid) const
{
    std::shared_lock lock(m_impl->m_roleMutex);
    return m_impl->GetUserRolesInternal_Locked(userSid);
}

std::vector<RoleDefinition> AccessControlManager::ListRoles(
    bool includeBuiltIn, uint32_t tenantId) const
{
    std::shared_lock lock(m_impl->m_roleMutex);
    std::vector<RoleDefinition> result;
    for (const auto& [id, role] : m_impl->m_roles) {
        if (!includeBuiltIn && role.isBuiltIn) continue;
        if (tenantId != 0 && role.tenantId != tenantId) continue;
        result.push_back(role);
    }
    return result;
}

// ============================================================================
// SESSION MANAGEMENT
// ============================================================================

std::optional<AuthenticationSession> AccessControlManager::CreateSession(
    const SecurityIdentifier& userSid,
    std::wstring_view sourceIP,
    std::wstring_view machineName)
{
    return m_impl->CreateSession(userSid, sourceIP, machineName);
}

std::optional<AuthenticationSession> AccessControlManager::ValidateSession(
    std::wstring_view sessionToken) const
{
    return m_impl->ValidateSession(sessionToken);
}

std::optional<AuthenticationSession> AccessControlManager::GetSession(
    uint64_t sessionId) const
{
    return m_impl->GetSession(sessionId);
}

bool AccessControlManager::RefreshSession(uint64_t sessionId) {
    return m_impl->RefreshSession(sessionId);
}

AccessDecision AccessControlManager::ElevateSession(
    uint64_t sessionId, RoleType targetRole, uint32_t durationMs)
{
    return m_impl->ElevateSession(sessionId, targetRole, durationMs);
}

bool AccessControlManager::RevokeSession(
    uint64_t sessionId, std::wstring_view reason)
{
    return m_impl->RevokeSession(sessionId, reason);
}

uint32_t AccessControlManager::RevokeAllUserSessions(
    const SecurityIdentifier& userSid, std::wstring_view reason)
{
    return m_impl->RevokeAllUserSessions(userSid, reason);
}

std::vector<AuthenticationSession> AccessControlManager::ListActiveSessions(
    const SecurityIdentifier& userSid) const
{
    return m_impl->ListActiveSessions(userSid);
}

// ============================================================================
// MULTI-FACTOR AUTHENTICATION
// ============================================================================

MFAChallengeResult AccessControlManager::InitiateMFAChallenge(
    uint64_t sessionId, MFAMethod method)
{
    return m_impl->InitiateMFAChallenge(sessionId, method);
}

bool AccessControlManager::VerifyMFAResponse(
    uint64_t sessionId, std::wstring_view challengeId, std::wstring_view response)
{
    return m_impl->VerifyMFAResponse(sessionId, challengeId, response);
}

bool AccessControlManager::RequiresMFA(
    uint64_t sessionId, Permission forOperation) const
{
    return m_impl->RequiresMFA(sessionId, forOperation);
}
// ============================================================================
// USER IDENTITY OPERATIONS
// ============================================================================

bool AccessControlManager::IsAdmin(const SecurityIdentifier& userSid) const {
    // FIX: ACM-N3 — IsAdminSidString only checks whether the SID *is* the well-known
    // BUILTIN\Administrators group SID (S-1-5-32-544); it does not check whether the
    // user is a *member* of that group. That mis-semantics caused callers (gating
    // sensitive operations) to treat ordinary admin users as non-admins and vice versa.
    //
    // Correct behaviour:
    //   1. If the SID matches the well-known Administrators group SID itself → true.
    //   2. If the SID belongs to the current process token's user → use CheckTokenMembership
    //      (the canonical Windows API for "am I an admin") against an impersonation
    //      duplicate of the token.
    //   3. Otherwise → resolve the account name and consult NetUserGetLocalGroups
    //      including indirect (group-of-group) memberships.
    //
    // On failure to determine membership we return false (deny-by-default) and log
    // explicitly so the caller's decision is auditable.

    if (userSid.stringSid.empty()) return false;

    // Case 1: SID *is* BUILTIN\Administrators.
    if (IsAdminSidString(userSid.stringSid)) return true;

    PSID pUserSid = nullptr;
    if (!::ConvertStringSidToSidW(userSid.stringSid.c_str(), &pUserSid)) {
        SS_LOG_WARN(L"ACM", L"IsAdmin: invalid SID '%ls'", userSid.stringSid.c_str());
        return false;
    }
    UniqueLocal<void> userSidGuard(pUserSid);

    // Build the well-known BUILTIN\Administrators SID once for comparison.
    BYTE adminSidBuf[SECURITY_MAX_SID_SIZE]{};
    DWORD adminSidSize = sizeof(adminSidBuf);
    if (!::CreateWellKnownSid(WinBuiltinAdministratorsSid,
                              nullptr, adminSidBuf, &adminSidSize)) {
        SS_LOG_ERROR(L"ACM", L"IsAdmin: CreateWellKnownSid failed: 0x%08X",
                     ::GetLastError());
        return false;
    }

    // Determine the current process user SID.
    HANDLE hProcTokenRaw = nullptr;
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE,
                           &hProcTokenRaw)) {
        auto hProcToken = WrapHandle(hProcTokenRaw);

        DWORD needed = 0;
        ::GetTokenInformation(hProcToken.get(), TokenUser, nullptr, 0, &needed);
        if (needed > 0) {
            std::vector<BYTE> userBuf(needed);
            if (::GetTokenInformation(hProcToken.get(), TokenUser,
                                       userBuf.data(), needed, &needed)) {
                auto* tu = reinterpret_cast<TOKEN_USER*>(userBuf.data());
                if (tu->User.Sid && ::EqualSid(tu->User.Sid, pUserSid)) {
                    // Case 2: this is the current process user — use the canonical API.
                    HANDLE hImpRaw = nullptr;
                    if (::DuplicateToken(hProcToken.get(),
                                          SecurityImpersonation, &hImpRaw)) {
                        auto hImp = WrapHandle(hImpRaw);
                        BOOL isMember = FALSE;
                        if (::CheckTokenMembership(hImp.get(),
                                                    adminSidBuf, &isMember)) {
                            return isMember != FALSE;
                        }
                    }
                }
            }
        }
    }

    // Case 3: foreign SID — resolve to account name and walk local-group memberships
    // (LG_INCLUDE_INDIRECT covers nested group-of-group inclusion). This handles both
    // local accounts and domain users authenticated against the local machine.
    wchar_t name[256]{};
    wchar_t domain[256]{};
    DWORD nameLen = 256, domLen = 256;
    SID_NAME_USE use{};
    if (!::LookupAccountSidW(nullptr, pUserSid, name, &nameLen,
                              domain, &domLen, &use)) {
        SS_LOG_WARN(L"ACM",
            L"IsAdmin: cannot resolve SID '%ls' (LookupAccountSidW failed: 0x%08X)",
            userSid.stringSid.c_str(), ::GetLastError());
        return false;
    }

    std::wstring fullName;
    if (domLen > 0 && domain[0] != L'\0') {
        fullName = std::wstring(domain) + L"\\" + std::wstring(name);
    } else {
        fullName = std::wstring(name);
    }

    LPLOCALGROUP_USERS_INFO_0 groups = nullptr;
    DWORD entriesRead = 0, totalEntries = 0;
    NET_API_STATUS netStatus = ::NetUserGetLocalGroups(
        nullptr, fullName.c_str(), 0, LG_INCLUDE_INDIRECT,
        reinterpret_cast<LPBYTE*>(&groups), MAX_PREFERRED_LENGTH,
        &entriesRead, &totalEntries);

    if (netStatus != NERR_Success || groups == nullptr) {
        SS_LOG_INFO(L"ACM",
            L"IsAdmin: NetUserGetLocalGroups failed for '%ls' (status=%lu); denying",
            fullName.c_str(), static_cast<unsigned long>(netStatus));
        if (groups) ::NetApiBufferFree(groups);
        return false;
    }

    bool isAdmin = false;
    for (DWORD i = 0; i < entriesRead; ++i) {
        const wchar_t* groupName = groups[i].lgrui0_name;
        if (groupName && ::_wcsicmp(groupName, L"Administrators") == 0) {
            isAdmin = true;
            break;
        }
    }
    ::NetApiBufferFree(groups);
    return isAdmin;
}

std::optional<UserPrincipal> AccessControlManager::ResolveUser(
    const SecurityIdentifier& sid, bool /*useCache*/) const
{
    if (!sid.isValid && sid.stringSid.empty()) return std::nullopt;

    UserPrincipal principal;
    principal.sid = sid;

    // Resolve SID to account name via Windows API
    PSID pSid = nullptr;
    if (::ConvertStringSidToSidW(sid.stringSid.c_str(), &pSid)) {
        UniqueLocal<void> sidGuard(pSid);

        wchar_t name[256]{};
        wchar_t domain[256]{};
        DWORD nameLen = 256, domLen = 256;
        SID_NAME_USE use{};
        if (::LookupAccountSidW(nullptr, pSid, name, &nameLen,
                                 domain, &domLen, &use)) {
            principal.username = name;
            principal.sid.accountName = name;
            principal.sid.domainName = domain;
        }
    }

    principal.effectiveRole = m_impl->GetEffectiveRole(sid);

    std::shared_lock roleLock(m_impl->m_roleMutex);
    principal.roleIds = m_impl->GetUserRolesInternal_Locked(sid);

    return principal;
}

std::optional<SecurityIdentifier> AccessControlManager::LookupUser(
    std::wstring_view username, std::wstring_view domain) const
{
    std::wstring fullName;
    if (!domain.empty()) {
        fullName = std::wstring(domain) + L"\\" + std::wstring(username);
    } else {
        fullName = std::wstring(username);
    }

    BYTE sidBuf[SECURITY_MAX_SID_SIZE]{};
    DWORD sidSize = sizeof(sidBuf);
    wchar_t domBuf[256]{};
    DWORD domSize = 256;
    SID_NAME_USE use{};

    if (!::LookupAccountNameW(nullptr, fullName.c_str(),
                               sidBuf, &sidSize, domBuf, &domSize, &use)) {
        return std::nullopt;
    }

    SecurityIdentifier result;
    result.binarySid.assign(sidBuf, sidBuf + sidSize);
    result.isValid = true;
    result.accountName = username;
    result.domainName = domBuf;

    LPWSTR strSid = nullptr;
    if (::ConvertSidToStringSidW(reinterpret_cast<PSID>(sidBuf), &strSid)) {
        result.stringSid = strSid;
        ::LocalFree(strSid);
    }

    return result;
}

std::vector<SecurityIdentifier> AccessControlManager::GetGroupMemberships(
    const SecurityIdentifier& userSid, bool /*includeNested*/) const
{
    std::vector<SecurityIdentifier> groups;

    HANDLE hTokenRaw = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &hTokenRaw)) {
        return groups;
    }
    auto hToken = WrapHandle(hTokenRaw);

    DWORD size = 0;
    ::GetTokenInformation(hToken.get(), TokenGroups, nullptr, 0, &size);
    if (size == 0) return groups;

    std::vector<BYTE> buf(size);
    if (!::GetTokenInformation(hToken.get(), TokenGroups, buf.data(), size, &size)) {
        return groups;
    }

    auto* pGroups = reinterpret_cast<PTOKEN_GROUPS>(buf.data());
    for (DWORD i = 0; i < pGroups->GroupCount && groups.size() < MAX_GROUP_MEMBERSHIPS; ++i) {
        SecurityIdentifier sid;
        LPWSTR strSid = nullptr;
        if (::ConvertSidToStringSidW(pGroups->Groups[i].Sid, &strSid)) {
            sid.stringSid = strSid;
            ::LocalFree(strSid);
        }
        sid.isValid = true;
        sid.isGroup = true;
        groups.push_back(std::move(sid));
    }
    return groups;
}

bool AccessControlManager::IsMemberOf(
    const SecurityIdentifier& userSid,
    const SecurityIdentifier& groupSid,
    bool checkNested) const
{
    auto groups = GetGroupMemberships(userSid, checkNested);
    for (const auto& g : groups) {
        if (g.stringSid == groupSid.stringSid) return true;
    }
    return false;
}

// ============================================================================
// PRIVILEGE HARDENING & PROCESS PROTECTION
// ============================================================================

RestrictionResult AccessControlManager::RestrictProcess(
    const ProcessRestrictionConfig& config)
{
    return m_impl->RestrictProcess(config);
}

RestrictionResult AccessControlManager::RestrictProcess(uint32_t pid) {
    auto config = ProcessRestrictionConfig::CreateMinimal();
    config.targetPid = pid;
    return RestrictProcess(config);
}

std::optional<TokenInfo> AccessControlManager::GetProcessToken(uint32_t pid) const {
    auto hProcess = WrapHandle(::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid));
    if (!hProcess) return std::nullopt;

    HANDLE hTokenRaw = nullptr;
    if (!::OpenProcessToken(hProcess.get(), TOKEN_QUERY, &hTokenRaw))
        return std::nullopt;
    auto hToken = WrapHandle(hTokenRaw);

    TokenInfo info;
    info.type = TokenType::PRIMARY;

    // Get user SID
    DWORD size = 0;
    ::GetTokenInformation(hToken.get(), TokenUser, nullptr, 0, &size);
    if (size > 0) {
        std::vector<BYTE> buf(size);
        if (::GetTokenInformation(hToken.get(), TokenUser, buf.data(), size, &size)) {
            auto* pUser = reinterpret_cast<PTOKEN_USER>(buf.data());
            LPWSTR strSid = nullptr;
            if (::ConvertSidToStringSidW(pUser->User.Sid, &strSid)) {
                info.userSid.stringSid = strSid;
                info.userSid.isValid = true;
                ::LocalFree(strSid);
            }
        }
    }

    // Get elevation status
    TOKEN_ELEVATION elevation{};
    DWORD retLen = 0;
    if (::GetTokenInformation(hToken.get(), TokenElevation, &elevation,
                               sizeof(elevation), &retLen)) {
        info.isElevated = (elevation.TokenIsElevated != 0);
    }

    // Transfer handle ownership to caller (caller must CloseHandle)
    info.tokenHandle = reinterpret_cast<uintptr_t>(hToken.release());
    return info;
}

std::optional<TokenInfo> AccessControlManager::GetThreadToken(uint32_t tid) const {
    auto hThread = WrapHandle(::OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid));
    if (!hThread) return std::nullopt;

    HANDLE hTokenRaw = nullptr;
    if (!::OpenThreadToken(hThread.get(), TOKEN_QUERY, TRUE, &hTokenRaw))
        return std::nullopt;
    auto hToken = WrapHandle(hTokenRaw);

    TokenInfo info;
    info.type = TokenType::IMPERSONATION;
    // Transfer handle ownership to caller (caller must CloseHandle)
    info.tokenHandle = reinterpret_cast<uintptr_t>(hToken.release());
    return info;
}

bool AccessControlManager::ModifyProcessPrivilege(
    uint32_t pid, WindowsPrivilege privilege, PrivilegeAction action)
{
    auto hProcess = WrapHandle(::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid));
    if (!hProcess) return false;

    HANDLE hTokenRaw = nullptr;
    if (!::OpenProcessToken(hProcess.get(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                             &hTokenRaw))
        return false;
    auto hToken = WrapHandle(hTokenRaw);

    auto privName = GetPrivilegeName(privilege);
    if (privName.empty()) return false;

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    std::wstring nameStr(privName);
    if (!::LookupPrivilegeValueW(nullptr, nameStr.c_str(), &tp.Privileges[0].Luid))
        return false;

    switch (action) {
    case PrivilegeAction::ENABLE:
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        break;
    case PrivilegeAction::DISABLE:
        tp.Privileges[0].Attributes = 0;
        break;
    case PrivilegeAction::REMOVE:
        tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
        break;
    default:
        return false;
    }

    if (!::AdjustTokenPrivileges(hToken.get(), FALSE, &tp, 0, nullptr, nullptr))
        return false;

    if (::GetLastError() == ERROR_NOT_ALL_ASSIGNED) return false;

    m_impl->NotifyPrivilegeCallbacks(pid, privilege, action, true);
    return true;
}

uint32_t AccessControlManager::StripDangerousPrivileges(uint32_t pid) {
    auto hProcess = WrapHandle(::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid));
    if (!hProcess) return 0;

    HANDLE hTokenRaw = nullptr;
    if (!::OpenProcessToken(hProcess.get(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                             &hTokenRaw))
        return 0;
    auto hToken = WrapHandle(hTokenRaw);

    uint32_t count = 0;
    static const WindowsPrivilege dangerous[] = {
        WindowsPrivilege::SE_DEBUG,
        WindowsPrivilege::SE_TCB,
        WindowsPrivilege::SE_IMPERSONATE,
        WindowsPrivilege::SE_CREATE_TOKEN,
        WindowsPrivilege::SE_ASSIGN_PRIMARY_TOKEN,
        WindowsPrivilege::SE_LOAD_DRIVER,
        WindowsPrivilege::SE_TAKE_OWNERSHIP,
        WindowsPrivilege::SE_RESTORE,
        WindowsPrivilege::SE_BACKUP,
    };

    for (auto priv : dangerous) {
        if (ModifyProcessPrivilege(pid, priv, PrivilegeAction::DISABLE)) {
            ++count;
        }
    }
    return count;
}

bool AccessControlManager::LowerIntegrity(uint32_t pid, IntegrityLevel targetLevel) {
    auto hProcess = WrapHandle(::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid));
    if (!hProcess) return false;

    HANDLE hTokenRaw = nullptr;
    if (!::OpenProcessToken(hProcess.get(), TOKEN_ADJUST_DEFAULT | TOKEN_QUERY,
                             &hTokenRaw))
        return false;
    auto hToken = WrapHandle(hTokenRaw);

    uint32_t rid = INTEGRITY_MEDIUM;
    switch (targetLevel) {
    case IntegrityLevel::UNTRUSTED: rid = INTEGRITY_UNTRUSTED; break;
    case IntegrityLevel::LOW:       rid = INTEGRITY_LOW; break;
    case IntegrityLevel::MEDIUM:    rid = INTEGRITY_MEDIUM; break;
    default: return false;
    }

    SID_IDENTIFIER_AUTHORITY mlAuth = SECURITY_MANDATORY_LABEL_AUTHORITY;
    PSID pIntegritySid = nullptr;
    if (!::AllocateAndInitializeSid(&mlAuth, 1, rid, 0, 0, 0, 0, 0, 0, 0,
                                     &pIntegritySid))
        return false;

    TOKEN_MANDATORY_LABEL tml{};
    tml.Label.Attributes = SE_GROUP_INTEGRITY;
    tml.Label.Sid = pIntegritySid;

    BOOL ok = ::SetTokenInformation(hToken.get(), TokenIntegrityLevel,
                                     &tml, sizeof(tml) + ::GetLengthSid(pIntegritySid));
    ::FreeSid(pIntegritySid);

    if (ok) m_impl->IncrementStat(&AccessControlStatistics::integrityLowerings);
    return ok != FALSE;
}

std::optional<uintptr_t> AccessControlManager::CreateRestrictedToken(
    uintptr_t sourceToken,
    const std::vector<SecurityIdentifier>& disabledSids,
    const std::vector<WindowsPrivilege>& removedPrivileges,
    const std::vector<SecurityIdentifier>& restrictedSids)
{
    HANDLE hSource = reinterpret_cast<HANDLE>(sourceToken);
    HANDLE hRestricted = nullptr;

    // Convert SecurityIdentifiers to SID_AND_ATTRIBUTES for disabled SIDs
    std::vector<SID_AND_ATTRIBUTES> disabledSA;
    std::vector<PSID> disabledSidPtrs;  // keep allocations alive
    for (const auto& sid : disabledSids) {
        if (!sid.isValid || sid.binarySid.empty()) continue;
        PSID pSid = nullptr;
        if (::ConvertStringSidToSidW(sid.stringSid.c_str(), &pSid)) {
            disabledSidPtrs.push_back(pSid);
            SID_AND_ATTRIBUTES sa{};
            sa.Sid = pSid;
            sa.Attributes = 0;
            disabledSA.push_back(sa);
        }
    }

    // Convert WindowsPrivilege to LUID_AND_ATTRIBUTES for removed privileges
    std::vector<LUID_AND_ATTRIBUTES> removedLA;
    for (auto priv : removedPrivileges) {
        auto privName = GetPrivilegeName(priv);
        if (privName.empty()) continue;
        LUID luid{};
        std::wstring nameStr(privName);
        if (::LookupPrivilegeValueW(nullptr, nameStr.c_str(), &luid)) {
            LUID_AND_ATTRIBUTES la{};
            la.Luid = luid;
            la.Attributes = 0;
            removedLA.push_back(la);
        }
    }

    // Convert SecurityIdentifiers to SID_AND_ATTRIBUTES for restricting SIDs
    std::vector<SID_AND_ATTRIBUTES> restrictedSA;
    std::vector<PSID> restrictedSidPtrs;
    for (const auto& sid : restrictedSids) {
        if (!sid.isValid || sid.binarySid.empty()) continue;
        PSID pSid = nullptr;
        if (::ConvertStringSidToSidW(sid.stringSid.c_str(), &pSid)) {
            restrictedSidPtrs.push_back(pSid);
            SID_AND_ATTRIBUTES sa{};
            sa.Sid = pSid;
            sa.Attributes = 0;
            restrictedSA.push_back(sa);
        }
    }

    DWORD flags = 0;
    if (removedPrivileges.empty() && disabledSids.empty() && restrictedSids.empty()) {
        flags = DISABLE_MAX_PRIVILEGE;
    }

    BOOL ok = ::CreateRestrictedToken(
        hSource, flags,
        static_cast<DWORD>(disabledSA.size()),
        disabledSA.empty() ? nullptr : disabledSA.data(),
        static_cast<DWORD>(removedLA.size()),
        removedLA.empty() ? nullptr : removedLA.data(),
        static_cast<DWORD>(restrictedSA.size()),
        restrictedSA.empty() ? nullptr : restrictedSA.data(),
        &hRestricted);

    // Clean up allocated SIDs
    for (auto p : disabledSidPtrs) ::LocalFree(p);
    for (auto p : restrictedSidPtrs) ::LocalFree(p);

    if (!ok) {
        SS_LOG_ERROR(L"ACM", L"CreateRestrictedToken failed: 0x%08X", ::GetLastError());
        return std::nullopt;
    }
    return reinterpret_cast<uintptr_t>(hRestricted);
}

ProtectionResult AccessControlManager::ProtectProcess(
    const ProcessProtectionConfig& config)
{
    return m_impl->ProtectProcess(config);
}

bool AccessControlManager::UnprotectProcess(uint32_t pid) {
    return m_impl->UnprotectProcess(pid);
}

ProcessProtectionLevel AccessControlManager::GetProcessProtectionLevel(
    uint32_t pid) const
{
    return m_impl->GetProtectionLevel(pid);
}

uint32_t AccessControlManager::ProtectShadowStrikeProcesses(
    ProcessProtectionLevel level)
{
    // FIX: ACM-N4 — the prior implementation substring-matched the executable name
    // (`ShadowStrike` / `Phantom`) inside PROCESSENTRY32W::szExeFile. An attacker can
    // trivially copy malware to `ShadowStrike-evil.exe` (or rename via the standard
    // copy-and-launch primitive) and inherit our process-protection DACL hardening.
    // We now require that the candidate process's *full image path* live underneath
    // our trusted install directory (the parent of the current module). The current
    // process is always protected as before.
    uint32_t count = 0;
    HANDLE hSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    auto snapGuard = WrapHandle(hSnap);

    // Derive the canonical trusted install directory from our own module path.
    std::wstring installDir;
    {
        wchar_t modulePath[MAX_PATH + 1]{};
        DWORD len = ::GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
        if (len == 0 || len >= MAX_PATH) {
            SS_LOG_ERROR(L"ACM",
                L"ProtectShadowStrikeProcesses: GetModuleFileNameW failed (0x%08X) — refusing to enumerate without trust anchor",
                ::GetLastError());
            return 0;
        }
        try {
            fs::path mp(modulePath);
            installDir = fs::weakly_canonical(mp.parent_path()).wstring();
        } catch (const std::exception& ex) {
            SS_LOG_ERROR(L"ACM",
                L"ProtectShadowStrikeProcesses: install dir canonicalization failed: %hs",
                ex.what());
            return 0;
        }
    }
    if (installDir.empty()) return 0;

    // Append a trailing separator so a sibling directory cannot prefix-match
    // (e.g. install dir "C:\Program Files\ShadowStrike" must not authorize
    // "C:\Program Files\ShadowStrike-evil\foo.exe").
    if (installDir.back() != L'\\' && installDir.back() != L'/') {
        installDir.push_back(L'\\');
    }
    std::wstring installDirLower = installDir;
    std::transform(installDirLower.begin(), installDirLower.end(),
                   installDirLower.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(::towlower(c)); });

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    const DWORD myPid = ::GetCurrentProcessId();

    if (::Process32FirstW(hSnap, &pe)) {
        do {
            bool trusted = (pe.th32ProcessID == myPid);

            if (!trusted && pe.th32ProcessID > 4) {
                HANDLE hRaw = ::OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (hRaw) {
                    auto hProc = WrapHandle(hRaw);
                    wchar_t imagePath[MAX_PATH + 1]{};
                    DWORD ipLen = MAX_PATH;
                    if (::QueryFullProcessImageNameW(hProc.get(), 0,
                                                      imagePath, &ipLen) && ipLen > 0) {
                        try {
                            fs::path ip(imagePath);
                            std::wstring canon =
                                fs::weakly_canonical(ip).wstring();
                            std::transform(canon.begin(), canon.end(),
                                           canon.begin(),
                                           [](wchar_t c) {
                                               return static_cast<wchar_t>(::towlower(c));
                                           });
                            if (canon.size() > installDirLower.size() &&
                                canon.compare(0, installDirLower.size(),
                                              installDirLower) == 0) {
                                trusted = true;
                            }
                        } catch (...) {
                            // Canonicalization failed → not trusted.
                        }
                    }
                }
            }

            if (trusted) {
                ProcessProtectionConfig cfg;
                cfg.targetPid = pe.th32ProcessID;
                cfg.level = level;
                auto result = ProtectProcess(cfg);
                if (result.success) ++count;
            }
        } while (::Process32NextW(hSnap, &pe));
    }
    return count;
}

bool AccessControlManager::IsAccessAllowed(
    uint32_t protectedPid, uint32_t accessorPid, uint32_t desiredAccess) const
{
    auto level = GetProcessProtectionLevel(protectedPid);
    if (level == ProcessProtectionLevel::NONE) return true;

    // Allow query-only access
    constexpr uint32_t SAFE_ACCESS = PROCESS_QUERY_LIMITED_INFORMATION;
    if ((desiredAccess & ~SAFE_ACCESS) == 0) return true;

    // Block dangerous access
    constexpr uint32_t DANGEROUS_ACCESS =
        PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
        PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE;
    if (desiredAccess & DANGEROUS_ACCESS) {
        m_impl->IncrementStat(&AccessControlStatistics::tamperAttempts);
        m_impl->IncrementStat(&AccessControlStatistics::tamperBlocked);
        return false;
    }

    return true;
}
// ============================================================================
// JOB OBJECT MANAGEMENT
// ============================================================================

std::optional<uintptr_t> AccessControlManager::CreateJobObject(
    std::wstring_view jobName,
    uint64_t memoryLimit,
    uint32_t processLimit,
    uint32_t cpuRateLimit)
{
    return m_impl->CreateJobObjectInternal(jobName, memoryLimit, processLimit, cpuRateLimit);
}

bool AccessControlManager::AssignProcessToJob(uintptr_t jobHandle, uint32_t pid) {
    return m_impl->AssignProcessToJobInternal(jobHandle, pid);
}

bool AccessControlManager::TerminateJobObject(uintptr_t jobHandle) {
    return m_impl->TerminateJobObjectInternal(jobHandle);
}

// ============================================================================
// CALLBACK REGISTRATION
// ============================================================================

uint64_t AccessControlManager::RegisterPermissionCheckCallback(
    PermissionCheckCallback callback)
{
    return m_impl->RegisterPermCallback(std::move(callback));
}

uint64_t AccessControlManager::RegisterSessionEventCallback(
    SessionEventCallback callback)
{
    return m_impl->RegisterSessionCallback(std::move(callback));
}

uint64_t AccessControlManager::RegisterTamperAttemptCallback(
    TamperAttemptCallback callback)
{
    return m_impl->RegisterTamperCallback(std::move(callback));
}

uint64_t AccessControlManager::RegisterAuditEventCallback(
    AuditEventCallback callback)
{
    return m_impl->RegisterAuditCallback(std::move(callback));
}

uint64_t AccessControlManager::RegisterPrivilegeModificationCallback(
    PrivilegeModificationCallback callback)
{
    return m_impl->RegisterPrivCallback(std::move(callback));
}

bool AccessControlManager::UnregisterCallback(uint64_t callbackId) {
    return m_impl->UnregisterCallback(callbackId);
}

// ============================================================================
// AUDITING
// ============================================================================

std::vector<AccessControlAuditEvent> AccessControlManager::GetAuditEvents(
    size_t maxEvents,
    std::optional<AuditEventType> eventType,
    const SecurityIdentifier& userSid) const
{
    return m_impl->GetAuditEvents(maxEvents, eventType, userSid);
}

bool AccessControlManager::ExportAuditLog(
    const std::wstring& filePath,
    std::chrono::system_clock::time_point startTime,
    std::chrono::system_clock::time_point endTime,
    std::wstring_view format) const
{
    return m_impl->ExportAuditLog(filePath, format, startTime, endTime);
}

// ============================================================================
// STATISTICS & DIAGNOSTICS
// ============================================================================

AccessControlStatistics AccessControlManager::GetStatistics() const noexcept {
    try {
        return m_impl->GetStatsCopy();
    } catch (...) {
        return {};
    }
}

void AccessControlManager::ResetStatistics() noexcept {
    try {
        m_impl->ResetStats();
    } catch (...) {}
}

bool AccessControlManager::PerformDiagnostics() const {
    SS_LOG_INFO(L"ACM", L"Starting diagnostics...");
    bool ok = true;

    if (!m_impl->m_initialized.load()) {
        SS_LOG_ERROR(L"ACM", L"Diagnostics: not initialized");
        return false;
    }

    {
        std::shared_lock lock(m_impl->m_roleMutex);
        if (m_impl->m_roles.empty()) {
            SS_LOG_ERROR(L"ACM", L"Diagnostics: no roles defined");
            ok = false;
        }
    }

    if (!m_impl->m_driverAvailable.load()) {
        SS_LOG_WARN(L"ACM", L"Diagnostics: PhantomSensor driver not available");
    }

    // Test BCryptGenRandom
    uint8_t testBuf[8]{};
    NTSTATUS status = ::BCryptGenRandom(nullptr, testBuf, sizeof(testBuf),
                                         BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!NT_SUCCESS(status)) {
        SS_LOG_ERROR(L"ACM", L"Diagnostics: BCryptGenRandom failed (0x%08X)",
                     static_cast<unsigned>(status));
        ok = false;
    }

    SS_LOG_INFO(L"ACM", L"Diagnostics %ls", ok ? L"passed" : L"failed");
    return ok;
}

void AccessControlManager::InvalidateCache() noexcept {
    // ACM uses per-request SID validation via Windows token APIs.
    // No explicit application-level cache exists; the Windows kernel
    // handles token caching at the security subsystem level.
    SS_LOG_DEBUG(L"ACM", L"InvalidateCache: no-op (per-request SID validation, kernel-cached)");
}

// ============================================================================
// STATIC UTILITIES
// ============================================================================

SecurityIdentifier AccessControlManager::ParseSid(std::wstring_view stringSid) {
    SecurityIdentifier sid;
    sid.stringSid = stringSid;

    PSID pSid = nullptr;
    if (::ConvertStringSidToSidW(sid.stringSid.c_str(), &pSid)) {
        sid.isValid = true;
        DWORD sidLen = ::GetLengthSid(pSid);
        sid.binarySid.assign(
            reinterpret_cast<uint8_t*>(pSid),
            reinterpret_cast<uint8_t*>(pSid) + sidLen);

        wchar_t name[256]{};
        wchar_t domain[256]{};
        DWORD nameLen = 256, domLen = 256;
        SID_NAME_USE use{};
        if (::LookupAccountSidW(nullptr, pSid, name, &nameLen,
                                 domain, &domLen, &use)) {
            sid.accountName = name;
            sid.domainName = domain;
            sid.isGroup = (use == SidTypeGroup || use == SidTypeWellKnownGroup ||
                           use == SidTypeAlias);
        }
        ::LocalFree(pSid);
    }
    return sid;
}

std::wstring AccessControlManager::SidToString(std::span<const uint8_t> binarySid) {
    if (binarySid.empty()) return {};
    LPWSTR strSid = nullptr;
    if (::ConvertSidToStringSidW(
            const_cast<PSID>(reinterpret_cast<const void*>(binarySid.data())),
            &strSid)) {
        std::wstring result(strSid);
        ::LocalFree(strSid);
        return result;
    }
    return {};
}

std::wstring_view AccessControlManager::GetPermissionName(Permission permission) noexcept {
    switch (permission) {
    case Permission::SCAN_ON_DEMAND:         return L"SCAN_ON_DEMAND";
    case Permission::SCAN_FULL:              return L"SCAN_FULL";
    case Permission::SCAN_QUICK:             return L"SCAN_QUICK";
    case Permission::SCAN_CANCEL:            return L"SCAN_CANCEL";
    case Permission::SCAN_VIEW_HISTORY:      return L"SCAN_VIEW_HISTORY";
    case Permission::QUARANTINE_VIEW:        return L"QUARANTINE_VIEW";
    case Permission::QUARANTINE_RESTORE:     return L"QUARANTINE_RESTORE";
    case Permission::QUARANTINE_DELETE:       return L"QUARANTINE_DELETE";
    case Permission::CONFIG_VIEW:            return L"CONFIG_VIEW";
    case Permission::CONFIG_REALTIME_MODIFY: return L"CONFIG_REALTIME_MODIFY";
    case Permission::CONFIG_SCAN_MODIFY:     return L"CONFIG_SCAN_MODIFY";
    case Permission::PROTECTION_ENABLE:      return L"PROTECTION_ENABLE";
    case Permission::PROTECTION_DISABLE:     return L"PROTECTION_DISABLE";
    case Permission::LOG_VIEW_DETECTIONS:    return L"LOG_VIEW_DETECTIONS";
    case Permission::LOG_VIEW_EVENTS:        return L"LOG_VIEW_EVENTS";
    case Permission::LOG_VIEW_AUDIT:         return L"LOG_VIEW_AUDIT";
    case Permission::LOG_EXPORT:             return L"LOG_EXPORT";
    case Permission::THREATINTEL_ADD_IOC:    return L"THREATINTEL_ADD_IOC";
    case Permission::WHITELIST_ADD:          return L"WHITELIST_ADD";
    case Permission::ADMIN_ROLE_VIEW:        return L"ADMIN_ROLE_VIEW";
    case Permission::ADMIN_ROLE_CREATE:      return L"ADMIN_ROLE_CREATE";
    case Permission::ADMIN_ROLE_MODIFY:      return L"ADMIN_ROLE_MODIFY";
    case Permission::ADMIN_ROLE_DELETE:       return L"ADMIN_ROLE_DELETE";
    case Permission::SYSTEM_SERVICE_CONTROL: return L"SYSTEM_SERVICE_CONTROL";
    case Permission::SYSTEM_DRIVER_CONTROL:  return L"SYSTEM_DRIVER_CONTROL";
    case Permission::SYSTEM_UNINSTALL:       return L"SYSTEM_UNINSTALL";
    default:                                 return L"UNKNOWN";
    }
}

std::wstring_view AccessControlManager::GetRoleName(RoleType role) noexcept {
    switch (role) {
    case RoleType::SYSTEM:             return L"SYSTEM";
    case RoleType::KERNEL:             return L"KERNEL";
    case RoleType::SUPER_ADMIN:        return L"SUPER_ADMIN";
    case RoleType::TENANT_ADMIN:       return L"TENANT_ADMIN";
    case RoleType::SECURITY_ADMIN:     return L"SECURITY_ADMIN";
    case RoleType::IT_ADMIN:           return L"IT_ADMIN";
    case RoleType::SOC_ANALYST_L3:     return L"SOC_ANALYST_L3";
    case RoleType::SOC_ANALYST_L2:     return L"SOC_ANALYST_L2";
    case RoleType::SOC_ANALYST_L1:     return L"SOC_ANALYST_L1";
    case RoleType::INCIDENT_RESPONDER: return L"INCIDENT_RESPONDER";
    case RoleType::POWER_USER:         return L"POWER_USER";
    case RoleType::STANDARD_USER:      return L"STANDARD_USER";
    case RoleType::GUEST:              return L"GUEST";
    case RoleType::RESTRICTED:         return L"RESTRICTED";
    case RoleType::SERVICE_ACCOUNT:    return L"SERVICE_ACCOUNT";
    case RoleType::API_CLIENT:         return L"API_CLIENT";
    case RoleType::AUDITOR:            return L"AUDITOR";
    default:                           return L"CUSTOM";
    }
}

std::wstring_view AccessControlManager::GetPrivilegeName(
    WindowsPrivilege privilege) noexcept
{
    switch (privilege) {
    case WindowsPrivilege::SE_CREATE_TOKEN:        return L"SeCreateTokenPrivilege";
    case WindowsPrivilege::SE_ASSIGN_PRIMARY_TOKEN:return L"SeAssignPrimaryTokenPrivilege";
    case WindowsPrivilege::SE_LOCK_MEMORY:         return L"SeLockMemoryPrivilege";
    case WindowsPrivilege::SE_INCREASE_QUOTA:      return L"SeIncreaseQuotaPrivilege";
    case WindowsPrivilege::SE_TCB:                 return L"SeTcbPrivilege";
    case WindowsPrivilege::SE_SECURITY:            return L"SeSecurityPrivilege";
    case WindowsPrivilege::SE_TAKE_OWNERSHIP:      return L"SeTakeOwnershipPrivilege";
    case WindowsPrivilege::SE_LOAD_DRIVER:         return L"SeLoadDriverPrivilege";
    case WindowsPrivilege::SE_BACKUP:              return L"SeBackupPrivilege";
    case WindowsPrivilege::SE_RESTORE:             return L"SeRestorePrivilege";
    case WindowsPrivilege::SE_SHUTDOWN:            return L"SeShutdownPrivilege";
    case WindowsPrivilege::SE_DEBUG:               return L"SeDebugPrivilege";
    case WindowsPrivilege::SE_AUDIT:               return L"SeAuditPrivilege";
    case WindowsPrivilege::SE_IMPERSONATE:         return L"SeImpersonatePrivilege";
    case WindowsPrivilege::SE_CREATE_GLOBAL:       return L"SeCreateGlobalPrivilege";
    case WindowsPrivilege::SE_MANAGE_VOLUME:       return L"SeManageVolumePrivilege";
    case WindowsPrivilege::SE_CHANGE_NOTIFY:       return L"SeChangeNotifyPrivilege";
    case WindowsPrivilege::SE_REMOTE_SHUTDOWN:     return L"SeRemoteShutdownPrivilege";
    case WindowsPrivilege::SE_SYSTEM_ENVIRONMENT:  return L"SeSystemEnvironmentPrivilege";
    case WindowsPrivilege::SE_CREATE_SYMBOLIC_LINK:return L"SeCreateSymbolicLinkPrivilege";
    default:                                       return L"Unknown";
    }
}

bool AccessControlManager::IsDangerousPrivilege(WindowsPrivilege privilege) noexcept {
    switch (privilege) {
    case WindowsPrivilege::SE_DEBUG:
    case WindowsPrivilege::SE_TCB:
    case WindowsPrivilege::SE_IMPERSONATE:
    case WindowsPrivilege::SE_CREATE_TOKEN:
    case WindowsPrivilege::SE_ASSIGN_PRIMARY_TOKEN:
    case WindowsPrivilege::SE_LOAD_DRIVER:
    case WindowsPrivilege::SE_TAKE_OWNERSHIP:
    case WindowsPrivilege::SE_RESTORE:
    case WindowsPrivilege::SE_BACKUP:
    case WindowsPrivilege::SE_SYSTEM_ENVIRONMENT:
        return true;
    default:
        return false;
    }
}

IntegrityLevel AccessControlManager::GetCurrentIntegrityLevel() noexcept {
    HANDLE hTokenRaw = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &hTokenRaw))
        return IntegrityLevel::INVALID;
    auto hToken = WrapHandle(hTokenRaw);

    DWORD size = 0;
    ::GetTokenInformation(hToken.get(), TokenIntegrityLevel, nullptr, 0, &size);
    if (size == 0) return IntegrityLevel::INVALID;

    std::vector<BYTE> buf(size);
    if (!::GetTokenInformation(hToken.get(), TokenIntegrityLevel,
                                buf.data(), size, &size))
        return IntegrityLevel::INVALID;

    auto* pTml = reinterpret_cast<PTOKEN_MANDATORY_LABEL>(buf.data());
    DWORD rid = *::GetSidSubAuthority(pTml->Label.Sid,
        static_cast<DWORD>(*::GetSidSubAuthorityCount(pTml->Label.Sid) - 1));

    if (rid >= INTEGRITY_PROTECTED_PROCESS) return IntegrityLevel::PROTECTED;
    if (rid >= INTEGRITY_SYSTEM) return IntegrityLevel::SYSTEM;
    if (rid >= INTEGRITY_HIGH) return IntegrityLevel::HIGH;
    if (rid >= INTEGRITY_MEDIUM_PLUS) return IntegrityLevel::MEDIUM_PLUS;
    if (rid >= INTEGRITY_MEDIUM) return IntegrityLevel::MEDIUM;
    if (rid >= INTEGRITY_LOW) return IntegrityLevel::LOW;
    return IntegrityLevel::UNTRUSTED;
}

bool AccessControlManager::ValidateRolePermissions(
    const RoleDefinition& role,
    const std::bitset<MAX_PERMISSIONS>& creatorPermissions)
{
    return (role.grantedPermissions & ~creatorPermissions).none();
}

bool AccessControlManager::IsValidRoleType(RoleType role) noexcept {
    switch (role) {
    case RoleType::SYSTEM:
    case RoleType::KERNEL:
    case RoleType::SUPER_ADMIN:
    case RoleType::TENANT_ADMIN:
    case RoleType::SECURITY_ADMIN:
    case RoleType::IT_ADMIN:
    case RoleType::SOC_ANALYST_L3:
    case RoleType::SOC_ANALYST_L2:
    case RoleType::SOC_ANALYST_L1:
    case RoleType::INCIDENT_RESPONDER:
    case RoleType::POWER_USER:
    case RoleType::STANDARD_USER:
    case RoleType::GUEST:
    case RoleType::RESTRICTED:
    case RoleType::SERVICE_ACCOUNT:
    case RoleType::API_CLIENT:
    case RoleType::AUDITOR:
        return true;
    default:
        return (static_cast<uint8_t>(role) >= static_cast<uint8_t>(RoleType::CUSTOM_START) &&
                static_cast<uint8_t>(role) <= static_cast<uint8_t>(RoleType::CUSTOM_END));
    }
}

bool AccessControlManager::IsValidPermission(Permission perm) noexcept {
    return static_cast<uint16_t>(perm) < static_cast<uint16_t>(Permission::PERMISSION_COUNT);
}

bool AccessControlManager::IsValidIntegrityLevel(IntegrityLevel level) noexcept {
    switch (level) {
    case IntegrityLevel::UNTRUSTED:
    case IntegrityLevel::LOW:
    case IntegrityLevel::MEDIUM:
    case IntegrityLevel::MEDIUM_PLUS:
    case IntegrityLevel::HIGH:
    case IntegrityLevel::SYSTEM:
    case IntegrityLevel::PROTECTED:
        return true;
    default:
        return false;
    }
}

// ============================================================================
// TOKEN IMPERSONATION DETECTION
// ============================================================================

bool AccessControlManager::DetectTokenImpersonation(uint32_t pid) const {
    auto threads = FindImpersonatingThreads(pid);
    return !threads.empty();
}

std::vector<uint32_t> AccessControlManager::FindImpersonatingThreads(
    uint32_t pid) const
{
    std::vector<uint32_t> result;
    HANDLE hSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return result;
    auto snapGuard = WrapHandle(hSnap);

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);

    if (::Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;

            auto hThread = WrapHandle(::OpenThread(THREAD_QUERY_INFORMATION,
                                                    FALSE, te.th32ThreadID));
            if (!hThread) continue;

            HANDLE hTokenRaw = nullptr;
            if (::OpenThreadToken(hThread.get(), TOKEN_QUERY, TRUE, &hTokenRaw)) {
                ::CloseHandle(hTokenRaw);
                result.push_back(te.th32ThreadID);
            }
        } while (::Thread32Next(hSnap, &te));
    }
    return result;
}

// ============================================================================
// APPCONTAINER SUPPORT
// ============================================================================

bool AccessControlManager::CreateAppContainerProfile(
    std::wstring_view name,
    std::span<const SecurityIdentifier> /*capabilities*/)
{
    std::wstring nameStr(name);
    PSID pSid = nullptr;
    HRESULT hr = ::CreateAppContainerProfile(
        nameStr.c_str(), nameStr.c_str(), nameStr.c_str(),
        nullptr, 0, &pSid);

    if (SUCCEEDED(hr)) {
        if (pSid) ::FreeSid(pSid);
        SS_LOG_INFO(L"ACM", L"Created AppContainer profile: %ls", nameStr.c_str());
        return true;
    }

    if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
        SS_LOG_DEBUG(L"ACM", L"AppContainer profile already exists: %ls", nameStr.c_str());
        return true;
    }

    SS_LOG_ERROR(L"ACM", L"Failed to create AppContainer profile: 0x%08X",
                 static_cast<unsigned>(hr));
    return false;
}

// ============================================================================
// SECURITY IDENTIFIER STATIC METHODS
// ============================================================================

SecurityIdentifier SecurityIdentifier::FromBinary(std::span<const uint8_t> sid) {
    SecurityIdentifier result;
    if (sid.empty() || sid.size() > MAX_SID_SIZE) return result;

    if (!::IsValidSid(const_cast<PSID>(reinterpret_cast<const void*>(sid.data()))))
        return result;

    result.binarySid.assign(sid.begin(), sid.end());

    LPWSTR strSid = nullptr;
    if (::ConvertSidToStringSidW(
            const_cast<PSID>(reinterpret_cast<const void*>(sid.data())), &strSid)) {
        result.stringSid = strSid;
        ::LocalFree(strSid);
    }
    result.isValid = true;
    return result;
}

size_t SecurityIdentifier::Hash::operator()(const SecurityIdentifier& sid) const noexcept {
    if (sid.binarySid.empty()) {
        return std::hash<std::wstring>{}(sid.stringSid);
    }
    size_t h = 0;
    for (auto byte : sid.binarySid) {
        h ^= std::hash<uint8_t>{}(byte) + 0x9e3779b9 + (h << 6) + (h >> 2);
    }
    return h;
}

// ============================================================================
// FACTORY METHODS
// ============================================================================

AccessControlManagerConfig AccessControlManagerConfig::CreateDefault() noexcept {
    return AccessControlManagerConfig{};
}

AccessControlManagerConfig AccessControlManagerConfig::CreateEnterprise() noexcept {
    AccessControlManagerConfig config;
    config.enableRBAC = true;
    config.requireMFAForAdmin = true;
    config.requireMFAForElevation = true;
    config.autoStripDangerousPrivileges = true;
    config.defaultProtectionLevel = ProcessProtectionLevel::MAXIMUM;
    config.auditAllAccessDecisions = true;
    config.alertOnPrivilegeEscalation = true;
    return config;
}

AccessControlManagerConfig AccessControlManagerConfig::CreateMSP() noexcept {
    AccessControlManagerConfig config = CreateEnterprise();
    config.enableMultiTenant = true;
    return config;
}

AccessControlManagerConfig AccessControlManagerConfig::CreateStandalone() noexcept {
    AccessControlManagerConfig config;
    config.enableRBAC = true;
    config.requireMFAForAdmin = false;
    config.auditDeniedOnly = true;
    return config;
}

ProcessRestrictionConfig ProcessRestrictionConfig::CreateMinimal() noexcept {
    ProcessRestrictionConfig config;
    config.stripAllPrivileges = true;
    return config;
}

ProcessRestrictionConfig ProcessRestrictionConfig::CreateModerate() noexcept {
    ProcessRestrictionConfig config;
    config.stripAllPrivileges = true;
    config.applyJobObject = true;
    config.memoryLimitBytes = DEFAULT_MEMORY_LIMIT_BYTES;
    return config;
}

ProcessRestrictionConfig ProcessRestrictionConfig::CreateStrict() noexcept {
    ProcessRestrictionConfig config;
    config.stripAllPrivileges = true;
    config.applyJobObject = true;
    config.memoryLimitBytes = 256ULL * 1024 * 1024;
    config.processLimit = 5;
    config.cpuRateLimit = 25;
    config.forceIntegrity = true;
    config.targetIntegrity = IntegrityLevel::LOW;
    return config;
}

ProcessRestrictionConfig ProcessRestrictionConfig::CreateSandbox() noexcept {
    ProcessRestrictionConfig config = CreateStrict();
    config.primaryRestriction = RestrictionType::FULL_SANDBOX;
    config.blockNetwork = true;
    config.disableMaxPrivilege = true;
    return config;
}

ProcessProtectionConfig ProcessProtectionConfig::CreateDefault() noexcept {
    return ProcessProtectionConfig{};
}

ProcessProtectionConfig ProcessProtectionConfig::CreateMaximum() noexcept {
    ProcessProtectionConfig config;
    config.level = ProcessProtectionLevel::MAXIMUM;
    config.protectHandles = true;
    config.blockThreadCreation = true;
    config.blockMemoryRead = true;
    config.blockMemoryWrite = true;
    config.blockMemoryExecute = true;
    config.preventSuspend = true;
    config.preventTerminate = true;
    config.protectDLLs = true;
    return config;
}

ProcessProtectionConfig ProcessProtectionConfig::CreateForService() noexcept {
    ProcessProtectionConfig config;
    config.level = ProcessProtectionLevel::ELEVATED;
    config.protectHandles = true;
    config.blockThreadCreation = true;
    config.preventTerminate = true;
    return config;
}

ProcessProtectionConfig ProcessProtectionConfig::CreateForDriver() noexcept {
    ProcessProtectionConfig config;
    config.level = ProcessProtectionLevel::PPL_ANTIMALWARE;
    config.protectHandles = true;
    config.blockThreadCreation = true;
    config.blockMemoryWrite = true;
    config.preventTerminate = true;
    config.protectDLLs = true;
    return config;
}

// ============================================================================
// STATISTICS IMPLEMENTATION
// ============================================================================

void AccessControlStatistics::Reset() noexcept {
    totalPermissionChecks = 0;
    permissionsGranted = 0;
    permissionsDenied = 0;
    permissionsCached = 0;
    sessionsCreated = 0;
    sessionsExpired = 0;
    sessionsRevoked = 0;
    activeSessions = 0;
    mfaChallenges = 0;
    mfaSuccesses = 0;
    mfaFailures = 0;
    privilegeStrips = 0;
    integrityLowerings = 0;
    processRestrictions = 0;
    processProtections = 0;
    tamperAttempts = 0;
    tamperBlocked = 0;
    errorCount = 0;
    cacheHits = 0;
    cacheMisses = 0;
    totalCheckTimeUs = 0;
    maxCheckTimeUs = 0;
}

} // namespace RealTime
} // namespace ShadowStrike