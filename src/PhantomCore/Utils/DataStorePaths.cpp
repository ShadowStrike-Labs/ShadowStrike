/**
 * @file DataStorePaths.cpp
 * @brief Implementation of canonical detection-store locations and hardening.
 *
 * @copyright ShadowStrike Labs. Licensed under AGPL-3.0.
 */

#include "pch.h"
#include "DataStorePaths.hpp"

#include "Logger.hpp"

#include <Windows.h>
#include <aclapi.h>   // SetEntriesInAclW, SetNamedSecurityInfoW
#include <sddl.h>

#include <mutex>

namespace ShadowStrike::Utils::DataStorePaths {

namespace {

constexpr const wchar_t* kLogCat = L"DataStorePaths";

/// RAII wrapper for SIDs from AllocateAndInitializeSid.
class ScopedSid {
public:
    explicit ScopedSid(PSID sid = nullptr) noexcept : m_sid(sid) {}
    ~ScopedSid() { if (m_sid) ::FreeSid(m_sid); }
    ScopedSid(const ScopedSid&) = delete;
    ScopedSid& operator=(const ScopedSid&) = delete;
    [[nodiscard]] PSID Get() const noexcept { return m_sid; }
    [[nodiscard]] bool Valid() const noexcept { return m_sid != nullptr; }
private:
    PSID m_sid;
};

/// RAII wrapper for LocalAlloc'd ACLs.
class LocalAllocGuard {
public:
    explicit LocalAllocGuard(HLOCAL h) noexcept : m_h(h) {}
    ~LocalAllocGuard() { if (m_h) ::LocalFree(m_h); }
    LocalAllocGuard(const LocalAllocGuard&) = delete;
    LocalAllocGuard& operator=(const LocalAllocGuard&) = delete;
private:
    HLOCAL m_h;
};

/// @brief Resolve %ProgramData%, falling back to the documented default.
[[nodiscard]] std::wstring ProgramDataRoot() {
    wchar_t buffer[MAX_PATH]{};
    const DWORD len = ::GetEnvironmentVariableW(L"ProgramData", buffer, MAX_PATH);
    if (len > 0 && len < MAX_PATH) {
        return std::wstring(buffer, len);
    }
    // A service always has this variable; the fallback exists so a stripped or
    // hijacked environment cannot redirect our stores somewhere writable.
    return L"C:\\ProgramData";
}

std::once_flag        g_ensureOnce;
bool                  g_hardened = false;

/// @brief Apply a protected DACL: SYSTEM + Administrators write, Users read.
///
/// PROTECTED_DACL_SECURITY_INFORMATION is the important part - it stops
/// permissive ACEs inherited from %ProgramData% (which grants ordinary users
/// create-file rights) from reaching our store files.
[[nodiscard]] bool ApplyRestrictiveAcl(const std::wstring& directory) noexcept {
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;

    PSID rawSystem = nullptr;
    if (!::AllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID,
                                    0, 0, 0, 0, 0, 0, 0, &rawSystem)) {
        SS_LOG_ERROR(kLogCat, L"AllocateAndInitializeSid(LocalSystem) failed: %lu",
                     static_cast<unsigned long>(::GetLastError()));
        return false;
    }
    ScopedSid systemSid(rawSystem);

    PSID rawAdmins = nullptr;
    if (!::AllocateAndInitializeSid(&ntAuth, 2,
                                    SECURITY_BUILTIN_DOMAIN_RID,
                                    DOMAIN_ALIAS_RID_ADMINS,
                                    0, 0, 0, 0, 0, 0, &rawAdmins)) {
        SS_LOG_ERROR(kLogCat, L"AllocateAndInitializeSid(Administrators) failed: %lu",
                     static_cast<unsigned long>(::GetLastError()));
        return false;
    }
    ScopedSid adminSid(rawAdmins);

    PSID rawUsers = nullptr;
    if (!::AllocateAndInitializeSid(&ntAuth, 2,
                                    SECURITY_BUILTIN_DOMAIN_RID,
                                    DOMAIN_ALIAS_RID_USERS,
                                    0, 0, 0, 0, 0, 0, &rawUsers)) {
        SS_LOG_ERROR(kLogCat, L"AllocateAndInitializeSid(Users) failed: %lu",
                     static_cast<unsigned long>(::GetLastError()));
        return false;
    }
    ScopedSid usersSid(rawUsers);

    constexpr DWORD kInherit = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    EXPLICIT_ACCESS_W ea[3] = {};

    // LocalSystem - the service identity that maintains the stores.
    ea[0].grfAccessPermissions = FILE_ALL_ACCESS;
    ea[0].grfAccessMode        = SET_ACCESS;
    ea[0].grfInheritance       = kInherit;
    ea[0].Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName    = reinterpret_cast<LPWSTR>(systemSid.Get());

    // Administrators - so an operator can service the databases.
    ea[1].grfAccessPermissions = FILE_ALL_ACCESS;
    ea[1].grfAccessMode        = SET_ACCESS;
    ea[1].grfInheritance       = kInherit;
    ea[1].Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[1].Trustee.ptstrName    = reinterpret_cast<LPWSTR>(adminSid.Get());

    // Users - READ ONLY. Deliberately no write: a user-writable whitelist is a
    // detection bypass, since malware could trust itself by adding its own hash.
    ea[2].grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
    ea[2].grfAccessMode        = SET_ACCESS;
    ea[2].grfInheritance       = kInherit;
    ea[2].Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea[2].Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[2].Trustee.ptstrName    = reinterpret_cast<LPWSTR>(usersSid.Get());

    PACL rawDacl = nullptr;
    const DWORD rc = ::SetEntriesInAclW(3, ea, nullptr, &rawDacl);
    if (rc != ERROR_SUCCESS || rawDacl == nullptr) {
        SS_LOG_ERROR(kLogCat, L"SetEntriesInAclW failed: %lu",
                     static_cast<unsigned long>(rc));
        return false;
    }
    LocalAllocGuard daclGuard(static_cast<HLOCAL>(rawDacl));

    std::wstring mutablePath = directory;
    const DWORD setRc = ::SetNamedSecurityInfoW(
        mutablePath.data(), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr, nullptr, rawDacl, nullptr);
    if (setRc != ERROR_SUCCESS) {
        SS_LOG_ERROR(kLogCat,
            L"SetNamedSecurityInfoW failed for '%ls': %lu - the detection stores "
            L"would be writable by unprivileged callers",
            directory.c_str(), static_cast<unsigned long>(setRc));
        return false;
    }

    return true;
}

/// @brief Create a single directory level, tolerating an existing one.
[[nodiscard]] bool CreateLevel(const std::wstring& path) noexcept {
    if (::CreateDirectoryW(path.c_str(), nullptr)) {
        return true;
    }
    const DWORD err = ::GetLastError();
    if (err == ERROR_ALREADY_EXISTS) {
        return true;
    }
    SS_LOG_ERROR(kLogCat, L"CreateDirectoryW('%ls') failed: %lu",
                 path.c_str(), static_cast<unsigned long>(err));
    return false;
}

}  // namespace

std::wstring GetDataDirectory() {
    return ProgramDataRoot() + L"\\ShadowStrike\\Data";
}

bool EnsureDataDirectory() noexcept {
    std::call_once(g_ensureOnce, []() noexcept {
        const std::wstring root = ProgramDataRoot() + L"\\ShadowStrike";
        const std::wstring data = root + L"\\Data";

        // The parent is shared with Logs/Quarantine, so it is created but its
        // ACL is left alone; only our own subtree is hardened.
        if (!CreateLevel(root) || !CreateLevel(data)) {
            g_hardened = false;
            return;
        }

        g_hardened = ApplyRestrictiveAcl(data);
        if (g_hardened) {
            SS_LOG_INFO(kLogCat,
                L"Detection store directory ready and hardened: %ls", data.c_str());
        } else {
            SS_LOG_WARN(kLogCat,
                L"Detection store directory '%ls' exists but could NOT be hardened. "
                L"Allow-listing will be treated as untrusted so a writable store "
                L"cannot be used to bypass detection.",
                data.c_str());
        }
    });

    const std::wstring data = GetDataDirectory();
    const DWORD attrs = ::GetFileAttributesW(data.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES &&
           (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

bool IsDataDirectoryHardened() noexcept {
    return g_hardened;
}

std::wstring SignatureDatabase()      { return GetDataDirectory() + L"\\signatures.sdb"; }
std::wstring WhitelistDatabase()      { return GetDataDirectory() + L"\\whitelist.wdb"; }
std::wstring ThreatIntelDatabase()    { return GetDataDirectory() + L"\\threatintel.tidb"; }
std::wstring HashReputationDatabase() { return GetDataDirectory() + L"\\hashes.hdb"; }

}  // namespace ShadowStrike::Utils::DataStorePaths
