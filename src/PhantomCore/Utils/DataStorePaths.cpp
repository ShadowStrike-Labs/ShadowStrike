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

#include <cstdint>
#include <cstring>
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

namespace {

// Signature database header, as written by phantom-sigbuild. Only the two fields
// needed to decide whether a copy is worthwhile are named here; the full layout
// belongs to SignatureStore and is deliberately not duplicated.
constexpr std::uint32_t kSignatureDbMagic       = 0x53535344u;  // 'SSSD'
constexpr std::size_t   kOffsetMagic            = 0;
constexpr std::size_t   kOffsetLastUpdateTime   = 32;           // Unix milliseconds
constexpr std::size_t   kHeaderProbeBytes       = 48;

struct DbStamp {
    bool          valid = false;
    std::uint64_t lastUpdateTime = 0;
};

// Reads and validates just enough of a candidate database to compare versions.
// A file that fails this is treated as absent rather than as empty or as zero,
// so a truncated download or a half-written copy can never be judged "older" and
// silently overwrite something good, nor be judged "newer" and replace it.
[[nodiscard]] DbStamp ReadDbStamp(const std::wstring& path) noexcept {
    DbStamp stamp;

    const HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE,
                                     nullptr, OPEN_EXISTING,
                                     FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return stamp;
    }

    unsigned char header[kHeaderProbeBytes]{};
    DWORD read = 0;
    const BOOL ok = ::ReadFile(file, header, static_cast<DWORD>(sizeof(header)), &read, nullptr);
    ::CloseHandle(file);

    if (!ok || read != sizeof(header)) {
        return stamp;
    }

    std::uint32_t magic = 0;
    std::memcpy(&magic, header + kOffsetMagic, sizeof(magic));
    if (magic != kSignatureDbMagic) {
        return stamp;
    }

    std::memcpy(&stamp.lastUpdateTime, header + kOffsetLastUpdateTime, sizeof(stamp.lastUpdateTime));
    stamp.valid = true;
    return stamp;
}

[[nodiscard]] std::wstring ModuleDirectory() noexcept {
    // GetModuleFileNameW(nullptr) is the executable, which for the service is
    // <install dir>\ShadowStrikePhantomService.exe. Resolving relative to the
    // module rather than the working directory matters because a service starts
    // with the working directory set to System32.
    std::wstring buffer(MAX_PATH, L'\0');
    for (;;) {
        const DWORD len = ::GetModuleFileNameW(nullptr, buffer.data(),
                                              static_cast<DWORD>(buffer.size()));
        if (len == 0) {
            return {};
        }
        if (len < buffer.size()) {
            buffer.resize(len);
            break;
        }
        if (buffer.size() >= 32768) {   // NT path ceiling; give up rather than spin
            return {};
        }
        buffer.resize(buffer.size() * 2);
    }

    const std::size_t slash = buffer.find_last_of(L'\\');
    return (slash == std::wstring::npos) ? std::wstring{} : buffer.substr(0, slash);
}

}  // namespace

std::wstring GetShippedContentDirectory() {
    const std::wstring dir = ModuleDirectory();
    return dir.empty() ? std::wstring{} : (dir + L"\\content");
}

bool SeedSignatureDatabaseFromBaseline() noexcept {
    const std::wstring working = SignatureDatabase();
    const std::wstring contentDir = GetShippedContentDirectory();

    const DbStamp workingStamp = ReadDbStamp(working);

    if (contentDir.empty()) {
        SS_LOG_WARN(kLogCat,
            L"Could not resolve this module's directory, so the shipped detection "
            L"content could not be located. Working database %ls",
            workingStamp.valid ? L"is present and will be used as-is."
                               : L"is ALSO absent - the engine will start with no signatures.");
        return workingStamp.valid;
    }

    const std::wstring baseline = contentDir + L"\\signatures.sdb";
    const DbStamp baselineStamp = ReadDbStamp(baseline);

    if (!baselineStamp.valid) {
        // Distinguish "not shipped" from "shipped but unusable": the first is a
        // packaging gap, the second is corruption, and they need different fixes.
        const DWORD attrs = ::GetFileAttributesW(baseline.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            SS_LOG_WARN(kLogCat,
                L"No shipped detection content at '%ls'. This installation cannot "
                L"seed a signature database, so unless one is already present the "
                L"engine will run with no signatures, no patterns and no YARA rules.",
                baseline.c_str());
        } else {
            SS_LOG_ERROR(kLogCat,
                L"Shipped detection content at '%ls' is present but is not a valid "
                L"signature database (bad magic or truncated). Refusing to use it; "
                L"any existing working database is left untouched.",
                baseline.c_str());
        }
        return workingStamp.valid;
    }

    if (workingStamp.valid && workingStamp.lastUpdateTime >= baselineStamp.lastUpdateTime) {
        // Never roll back content that runtime updates have moved forward.
        return true;
    }

    if (!EnsureDataDirectory()) {
        SS_LOG_ERROR(kLogCat,
            L"Cannot prepare the data directory, so the shipped signature database "
            L"could not be installed. The engine will start with no signatures.");
        return false;
    }

    // Copy to a sibling temporary first, then swap. A direct CopyFileW onto the
    // live path would leave a half-written database behind if the machine lost
    // power or the copy failed, and that file would then look like a real
    // database to the next start - the failure mode this whole function exists to
    // avoid. MOVEFILE_REPLACE_EXISTING on the same volume is atomic.
    const std::wstring staging = working + L".incoming";
    ::DeleteFileW(staging.c_str());

    if (!::CopyFileW(baseline.c_str(), staging.c_str(), FALSE)) {
        SS_LOG_ERROR(kLogCat,
            L"Copying the shipped signature database to '%ls' failed (win32=%lu). "
            L"Existing content, if any, is unchanged.",
            staging.c_str(), ::GetLastError());
        ::DeleteFileW(staging.c_str());
        return workingStamp.valid;
    }

    // Re-validate the copy rather than the source. A short read or a full disk
    // produces a file that passes CopyFileW's return but is not a database.
    if (!ReadDbStamp(staging).valid) {
        SS_LOG_ERROR(kLogCat,
            L"The copied signature database at '%ls' did not validate, so it was "
            L"discarded. Existing content, if any, is unchanged.", staging.c_str());
        ::DeleteFileW(staging.c_str());
        return workingStamp.valid;
    }

    if (!::MoveFileExW(staging.c_str(), working.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        SS_LOG_ERROR(kLogCat,
            L"Could not swap the new signature database into place at '%ls' "
            L"(win32=%lu). Existing content, if any, is unchanged.",
            working.c_str(), ::GetLastError());
        ::DeleteFileW(staging.c_str());
        return workingStamp.valid;
    }

    if (workingStamp.valid) {
        SS_LOG_INFO(kLogCat,
            L"Refreshed the signature database from shipped content: "
            L"stamp %llu -> %llu (%ls)",
            static_cast<unsigned long long>(workingStamp.lastUpdateTime),
            static_cast<unsigned long long>(baselineStamp.lastUpdateTime),
            working.c_str());
    } else {
        SS_LOG_INFO(kLogCat,
            L"Installed the shipped signature database (stamp %llu) to '%ls'",
            static_cast<unsigned long long>(baselineStamp.lastUpdateTime),
            working.c_str());
    }
    return true;
}

}  // namespace ShadowStrike::Utils::DataStorePaths
