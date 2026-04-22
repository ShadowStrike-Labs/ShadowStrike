#include "pch.h"
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
 * ShadowStrike NGAV - SESSION-SCOPED IPC AUTH TOKEN IMPLEMENTATION
 * ============================================================================
 *
 * @file IpcAuthToken.cpp
 * @see  IpcAuthToken.hpp for the full API documentation.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#include "IpcAuthToken.hpp"

// Windows SDK — explicit inclusions after PCH
#include <shlobj.h>         // SHGetKnownFolderPath, FOLDERID_LocalAppData
#include <userenv.h>        // GetUserProfileDirectoryW
#include <wtsapi32.h>       // WTSQueryUserToken
#include <aclapi.h>         // SetEntriesInAclW, SetNamedSecurityInfoW
#include <sddl.h>           // ConvertSidToStringSidW (diagnostic only)
#include <bcrypt.h>         // BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG

// STL
#include <array>
#include <shared_mutex>
#include <unordered_map>

// ShadowStrike infrastructure
#include "../Utils/Logger.hpp"
#include "../Utils/Base64Utils.hpp"

// Link required import libraries from within the TU so the consuming project
// need not enumerate them explicitly in its .vcxproj linker settings.
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

namespace ShadowStrike::Service {

// =============================================================================
// INTERNAL IMPLEMENTATION
// =============================================================================

namespace {

constexpr std::size_t   kNonceBytes   = 32;
constexpr DWORD         kMaxTokenRead = 256;  // Base64(32 bytes) = 44 chars; cap at 256.
constexpr const wchar_t* kLogCat      = L"IpcAuthToken";
constexpr const wchar_t* kTokenSubdir = L"ShadowStrike";
constexpr const wchar_t* kTokenFile   = L"ui.token";

// ─────────────────────────────────────────────────────────────────────────────
// RAII helpers
// ─────────────────────────────────────────────────────────────────────────────

/// RAII wrapper around a Win32 HANDLE.
class ScopedHandle final {
public:
    explicit ScopedHandle(HANDLE h = INVALID_HANDLE_VALUE) noexcept : m_h(h) {}
    ~ScopedHandle() noexcept { Reset(); }

    ScopedHandle(const ScopedHandle&)            = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    ScopedHandle(ScopedHandle&& o) noexcept : m_h(o.m_h) {
        o.m_h = INVALID_HANDLE_VALUE;
    }
    ScopedHandle& operator=(ScopedHandle&& o) noexcept {
        if (this != &o) { Reset(); m_h = o.m_h; o.m_h = INVALID_HANDLE_VALUE; }
        return *this;
    }

    [[nodiscard]] bool   Valid()  const noexcept { return m_h != INVALID_HANDLE_VALUE && m_h != nullptr; }
    [[nodiscard]] HANDLE Get()    const noexcept { return m_h; }
    void                 Reset()  noexcept {
        if (Valid()) { CloseHandle(m_h); m_h = INVALID_HANDLE_VALUE; }
    }

private:
    HANDLE m_h;
};

/// RAII wrapper for CoTaskMem-allocated wide strings (SHGetKnownFolderPath).
class CoTaskWStr final {
public:
    CoTaskWStr()  noexcept : m_ptr(nullptr) {}
    ~CoTaskWStr() noexcept { if (m_ptr) CoTaskMemFree(m_ptr); }

    CoTaskWStr(const CoTaskWStr&)            = delete;
    CoTaskWStr& operator=(const CoTaskWStr&) = delete;

    [[nodiscard]] PWSTR* AddressOf() noexcept { return &m_ptr; }
    [[nodiscard]] PCWSTR Get()       const noexcept { return m_ptr; }
    [[nodiscard]] bool   Valid()     const noexcept { return m_ptr != nullptr; }

private:
    PWSTR m_ptr;
};

/// RAII wrapper for a PSID allocated by AllocateAndInitializeSid.
class ScopedSid final {
public:
    explicit ScopedSid(PSID s = nullptr) noexcept : m_sid(s) {}
    ~ScopedSid() noexcept { if (m_sid) FreeSid(m_sid); }

    ScopedSid(const ScopedSid&)            = delete;
    ScopedSid& operator=(const ScopedSid&) = delete;

    [[nodiscard]] PSID Get()  const noexcept { return m_sid; }
    [[nodiscard]] bool Valid()const noexcept { return m_sid != nullptr; }

private:
    PSID m_sid;
};

/// RAII wrapper for LocalAlloc-allocated memory (SetEntriesInAcl output).
class LocalAllocGuard final {
public:
    explicit LocalAllocGuard(HLOCAL p = nullptr) noexcept : m_p(p) {}
    ~LocalAllocGuard() noexcept { if (m_p) LocalFree(m_p); }

    LocalAllocGuard(const LocalAllocGuard&)            = delete;
    LocalAllocGuard& operator=(const LocalAllocGuard&) = delete;

    [[nodiscard]] void* Get() const noexcept { return m_p; }

private:
    HLOCAL m_p;
};

// ─────────────────────────────────────────────────────────────────────────────
// Token cache (Meyers singleton)
// ─────────────────────────────────────────────────────────────────────────────

class TokenCache final {
public:
    [[nodiscard]] static TokenCache& Instance() noexcept {
        static TokenCache s_inst;
        return s_inst;
    }

    void Store(std::uint32_t sessionId, std::string&& token) {
        std::unique_lock lock(m_mtx);
        m_map[sessionId] = std::move(token);
    }

    [[nodiscard]] std::string Get(std::uint32_t sessionId) const {
        std::shared_lock lock(m_mtx);
        auto it = m_map.find(sessionId);
        return (it != m_map.end()) ? it->second : std::string{};
    }

    [[nodiscard]] bool Contains(std::uint32_t sessionId) const noexcept {
        std::shared_lock lock(m_mtx);
        return m_map.count(sessionId) != 0;
    }

private:
    mutable std::shared_mutex                       m_mtx;
    std::unordered_map<std::uint32_t, std::string>  m_map;

    TokenCache()  = default;
    ~TokenCache() = default;

    TokenCache(const TokenCache&)            = delete;
    TokenCache& operator=(const TokenCache&) = delete;
};

// ─────────────────────────────────────────────────────────────────────────────
// Constant-time comparison (resist timing attacks)
// ─────────────────────────────────────────────────────────────────────────────

/// Compare two string_views in constant time.  Length differences short-circuit
/// (length is NOT secret — the expected token length is fixed at 44 chars for
/// base64 of 32 bytes, and the attacker can observe that without timing).
[[nodiscard]] bool ConstantTimeEqual(std::string_view a, std::string_view b) noexcept
{
    if (a.size() != b.size()) return false;

    volatile unsigned char acc = 0;
    const auto* pa = reinterpret_cast<const unsigned char*>(a.data());
    const auto* pb = reinterpret_cast<const unsigned char*>(b.data());

    for (std::size_t i = 0; i < a.size(); ++i) {
        acc |= pa[i] ^ pb[i];   // Bitwise OR accumulates any difference.
    }

    return acc == 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Nonce generation
// ─────────────────────────────────────────────────────────────────────────────

[[nodiscard]] bool GenerateNonce(std::array<std::uint8_t, kNonceBytes>& out) noexcept
{
    NTSTATUS status = BCryptGenRandom(
        /*hAlgorithm=*/nullptr,
        out.data(),
        static_cast<ULONG>(out.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    if (!BCRYPT_SUCCESS(status)) {
        SS_LOG_ERROR(kLogCat,
            L"BCryptGenRandom failed: NTSTATUS=0x%08X",
            static_cast<unsigned int>(status));
        return false;
    }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Path resolution (service-side: given the interactive user token)
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the full path to the token file for the user owning hUserToken,
/// and ensures the parent directory exists.  Returns empty on any failure.
[[nodiscard]] std::wstring ResolveTokenPathForSession(HANDLE hUserToken)
{
    // GetUserProfileDirectoryW — size query (first call with null buffer).
    DWORD needed = 0;
    ::GetUserProfileDirectoryW(hUserToken, nullptr, &needed);
    if (needed < 2) {
        SS_LOG_LAST_ERROR(kLogCat,
            L"GetUserProfileDirectoryW size-query failed (returned %lu)", needed);
        return {};
    }

    std::wstring profileDir(static_cast<std::size_t>(needed), L'\0');
    if (!::GetUserProfileDirectoryW(hUserToken, profileDir.data(), &needed)) {
        SS_LOG_LAST_ERROR(kLogCat, L"GetUserProfileDirectoryW failed");
        return {};
    }
    // needed now contains the character count including the null terminator.
    while (!profileDir.empty() && profileDir.back() == L'\0')
        profileDir.pop_back();

    if (profileDir.empty()) {
        SS_LOG_ERROR(kLogCat, L"GetUserProfileDirectoryW returned empty path");
        return {};
    }

    // Construct: <profile>\AppData\Local\ShadowStrike
    std::wstring tokenDir;
    tokenDir.reserve(profileDir.size() + 64);
    tokenDir  = profileDir;
    tokenDir += L"\\AppData\\Local\\";
    tokenDir += kTokenSubdir;

    // Create the directory; tolerate ERROR_ALREADY_EXISTS.
    if (!::CreateDirectoryW(tokenDir.c_str(), nullptr)) {
        DWORD err = ::GetLastError();
        if (err != ERROR_ALREADY_EXISTS) {
            SS_LOG_ERROR(kLogCat,
                L"CreateDirectoryW('%ls') failed: error=%lu",
                tokenDir.c_str(), static_cast<unsigned long>(err));
            return {};
        }
    }

    std::wstring path = tokenDir + L"\\" + kTokenFile;
    return path;
}

// ─────────────────────────────────────────────────────────────────────────────
// Token SID extraction
// ─────────────────────────────────────────────────────────────────────────────

/// Populate tokenBuf with the TOKEN_USER structure from hToken and return a
/// pointer to the embedded SID (valid as long as tokenBuf is alive).
/// Returns nullptr on failure.
[[nodiscard]] PSID ExtractUserSid(HANDLE hToken, std::vector<BYTE>& tokenBuf)
{
    DWORD needed = 0;
    ::GetTokenInformation(hToken, TokenUser, nullptr, 0, &needed);
    if (needed == 0) {
        SS_LOG_LAST_ERROR(kLogCat, L"GetTokenInformation(TokenUser) size-query failed");
        return nullptr;
    }

    tokenBuf.resize(static_cast<std::size_t>(needed));
    if (!::GetTokenInformation(hToken, TokenUser, tokenBuf.data(), needed, &needed)) {
        SS_LOG_LAST_ERROR(kLogCat, L"GetTokenInformation(TokenUser) failed");
        tokenBuf.clear();
        return nullptr;
    }

    auto* tu = reinterpret_cast<TOKEN_USER*>(tokenBuf.data());
    return tu->User.Sid;
}

// ─────────────────────────────────────────────────────────────────────────────
// File ACL setup
// ─────────────────────────────────────────────────────────────────────────────

/// Apply a restrictive DACL to filePath:
///   • userSid       → FILE_GENERIC_READ | FILE_GENERIC_WRITE
///   • LocalSystem   → FILE_GENERIC_READ | FILE_GENERIC_WRITE
///   • (everyone else: implicit deny — PROTECTED_DACL disables inheritance)
[[nodiscard]] bool SetTokenFileAcl(const std::wstring& filePath, PSID userSid) noexcept
{
    // Build the LocalSystem well-known SID.
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID rawSystemSid = nullptr;
    if (!::AllocateAndInitializeSid(
            &ntAuth, 1,
            SECURITY_LOCAL_SYSTEM_RID,
            0, 0, 0, 0, 0, 0, 0,
            &rawSystemSid)) {
        SS_LOG_LAST_ERROR(kLogCat, L"AllocateAndInitializeSid(LocalSystem) failed");
        return false;
    }
    ScopedSid systemSid(rawSystemSid);

    // Two explicit-access entries.
    EXPLICIT_ACCESS_W ea[2] = {};

    // ACE 0: session user.
    ea[0].grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
    ea[0].grfAccessMode        = SET_ACCESS;
    ea[0].grfInheritance       = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType  = TRUSTEE_IS_USER;
    ea[0].Trustee.ptstrName    = reinterpret_cast<LPWSTR>(userSid);

    // ACE 1: LocalSystem.
    ea[1].grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
    ea[1].grfAccessMode        = SET_ACCESS;
    ea[1].grfInheritance       = NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[1].Trustee.ptstrName    = reinterpret_cast<LPWSTR>(systemSid.Get());

    PACL rawDacl = nullptr;
    DWORD rc = ::SetEntriesInAclW(2, ea, /*OldDacl=*/nullptr, &rawDacl);
    if (rc != ERROR_SUCCESS || rawDacl == nullptr) {
        SS_LOG_ERROR(kLogCat,
            L"SetEntriesInAclW failed: error=%lu", static_cast<unsigned long>(rc));
        return false;
    }
    LocalAllocGuard daclGuard(static_cast<HLOCAL>(rawDacl));

    // DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION:
    //   - PROTECTED_DACL prevents inheriting permissive ACEs from AppData.
    rc = ::SetNamedSecurityInfoW(
        const_cast<LPWSTR>(filePath.c_str()),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        /*psidOwner=*/nullptr,
        /*psidGroup=*/nullptr,
        rawDacl,
        /*pSacl=*/nullptr
    );
    if (rc != ERROR_SUCCESS) {
        SS_LOG_ERROR(kLogCat,
            L"SetNamedSecurityInfoW('%ls') failed: error=%lu",
            filePath.c_str(), static_cast<unsigned long>(rc));
        return false;
    }

    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Token file write
// ─────────────────────────────────────────────────────────────────────────────

[[nodiscard]] bool WriteTokenFile(const std::wstring& path,
                                   const std::string&  tokenB64,
                                   PSID                userSid) noexcept
{
    // Create/overwrite the file.  No sharing during write.
    ScopedHandle hf{::CreateFileW(
        path.c_str(),
        GENERIC_WRITE,
        /*dwShareMode=*/0,
        /*lpSecurityAttributes=*/nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        /*hTemplateFile=*/nullptr
    )};
    if (!hf.Valid()) {
        SS_LOG_LAST_ERROR(kLogCat, L"CreateFileW failed creating token file '%ls'",
            path.c_str());
        return false;
    }

    DWORD written = 0;
    const DWORD toWrite = static_cast<DWORD>(tokenB64.size());
    if (!::WriteFile(hf.Get(), tokenB64.c_str(), toWrite, &written, nullptr) ||
        written != toWrite) {
        SS_LOG_LAST_ERROR(kLogCat, L"WriteFile to token file '%ls' failed", path.c_str());
        return false;
    }

    // Close before applying the ACL (some implementations require the handle
    // to be closed before SetNamedSecurityInfoW can succeed on the same path).
    hf.Reset();

    if (!SetTokenFileAcl(path, userSid)) {
        SS_LOG_ERROR(kLogCat,
            L"SetTokenFileAcl failed; removing insecure token file '%ls'", path.c_str());
        ::DeleteFileW(path.c_str());
        return false;
    }

    return true;
}

} // anonymous namespace

// =============================================================================
// IpcAuthToken PUBLIC API
// =============================================================================

// ─────────────────────────────────────────────────────────────────────────────
// EnsureForSession  (service-side)
// ─────────────────────────────────────────────────────────────────────────────

std::string IpcAuthToken::EnsureForSession(std::uint32_t sessionId)
{
    TokenCache& cache = TokenCache::Instance();

    // Fast path: token already cached for this session.
    {
        std::string cached = cache.Get(sessionId);
        if (!cached.empty()) {
            return cached;
        }
    }

    // ── Generate nonce ────────────────────────────────────────────────────────
    std::array<std::uint8_t, kNonceBytes> nonce{};
    if (!GenerateNonce(nonce)) {
        SS_LOG_ERROR(kLogCat,
            L"EnsureForSession: nonce generation failed for session %u", sessionId);
        return {};
    }

    // ── Base64-encode nonce ───────────────────────────────────────────────────
    std::string tokenB64;
    if (!ShadowStrike::Utils::Base64Encode(nonce.data(), nonce.size(), tokenB64)) {
        SS_LOG_ERROR(kLogCat,
            L"EnsureForSession: Base64Encode failed for session %u", sessionId);
        RtlSecureZeroMemory(nonce.data(), nonce.size());
        return {};
    }
    // Clear the raw nonce from the stack immediately.
    RtlSecureZeroMemory(nonce.data(), nonce.size());

    // ── Obtain the interactive user's primary token ───────────────────────────
    HANDLE rawUserToken = nullptr;
    if (!::WTSQueryUserToken(sessionId, &rawUserToken)) {
        DWORD err = ::GetLastError();
        SS_LOG_ERROR(kLogCat,
            L"WTSQueryUserToken failed for session %u: error=%lu",
            sessionId, static_cast<unsigned long>(err));
        return {};
    }
    ScopedHandle hUserToken(rawUserToken);

    // ── Resolve the token file path ───────────────────────────────────────────
    std::wstring tokenPath = ResolveTokenPathForSession(hUserToken.Get());
    if (tokenPath.empty()) {
        SS_LOG_ERROR(kLogCat,
            L"EnsureForSession: failed to resolve token path for session %u", sessionId);
        return {};
    }

    // ── Extract user SID for ACL ──────────────────────────────────────────────
    std::vector<BYTE> tokenUserBuf;
    PSID userSid = ExtractUserSid(hUserToken.Get(), tokenUserBuf);
    if (userSid == nullptr) {
        SS_LOG_ERROR(kLogCat,
            L"EnsureForSession: failed to extract user SID for session %u", sessionId);
        return {};
    }

    // ── Write the token file with restrictive ACL ─────────────────────────────
    if (!WriteTokenFile(tokenPath, tokenB64, userSid)) {
        SS_LOG_ERROR(kLogCat,
            L"EnsureForSession: WriteTokenFile failed for session %u", sessionId);
        return {};
    }

    // ── Cache and return ──────────────────────────────────────────────────────
    cache.Store(sessionId, std::string(tokenB64));

    SS_LOG_INFO(kLogCat,
        L"IPC auth token issued for session %u at '%ls'",
        sessionId, tokenPath.c_str());

    return tokenB64;
}

// ─────────────────────────────────────────────────────────────────────────────
// Verify  (service-side)
// ─────────────────────────────────────────────────────────────────────────────

bool IpcAuthToken::Verify(std::uint32_t   sessionId,
                           std::string_view tokenBase64) noexcept
{
    if (tokenBase64.empty()) {
        SS_LOG_WARN(kLogCat,
            L"Verify: empty token presented for session %u", sessionId);
        return false;
    }

    const std::string expected = TokenCache::Instance().Get(sessionId);
    if (expected.empty()) {
        SS_LOG_WARN(kLogCat,
            L"Verify: no cached token for session %u — "
            L"EnsureForSession must be called first", sessionId);
        return false;
    }

    const bool match = ConstantTimeEqual(expected, tokenBase64);

    // Audit failure; do not log the token values to avoid leaking secrets.
    if (!match) {
        SS_LOG_WARN(kLogCat,
            L"Verify: auth token mismatch for session %u", sessionId);
    }

    return match;
}

// ─────────────────────────────────────────────────────────────────────────────
// ReadForCurrentSession  (client-side)
// ─────────────────────────────────────────────────────────────────────────────

std::string IpcAuthToken::ReadForCurrentSession()
{
    // Resolve LOCALAPPDATA for the current user (nullptr hToken → current process).
    CoTaskWStr localAppData;
    HRESULT hr = ::SHGetKnownFolderPath(
        FOLDERID_LocalAppData,
        KF_FLAG_DEFAULT,
        /*hToken=*/nullptr,
        localAppData.AddressOf()
    );
    if (FAILED(hr)) {
        SS_LOG_ERROR(kLogCat,
            L"ReadForCurrentSession: SHGetKnownFolderPath failed: hr=0x%08X",
            static_cast<unsigned int>(hr));
        return {};
    }

    std::wstring tokenPath;
    tokenPath.reserve(260);
    tokenPath  = localAppData.Get();
    tokenPath += L'\\';
    tokenPath += kTokenSubdir;
    tokenPath += L'\\';
    tokenPath += kTokenFile;

    ScopedHandle hf{::CreateFileW(
        tokenPath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    )};
    if (!hf.Valid()) {
        DWORD err = ::GetLastError();
        // Missing file is expected if the service hasn't run yet.
        if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND) {
            SS_LOG_ERROR(kLogCat,
                L"ReadForCurrentSession: CreateFileW failed for '%ls': error=%lu",
                tokenPath.c_str(), static_cast<unsigned long>(err));
        }
        return {};
    }

    // Read at most kMaxTokenRead bytes into a stack buffer to avoid heap
    // allocations that might leave copies of the token in free-store memory.
    char buf[kMaxTokenRead + 1] = {};
    DWORD bytesRead = 0;
    if (!::ReadFile(hf.Get(), buf, kMaxTokenRead, &bytesRead, nullptr)) {
        SS_LOG_LAST_ERROR(kLogCat,
            L"ReadForCurrentSession: ReadFile on token file failed");
        RtlSecureZeroMemory(buf, sizeof(buf));
        return {};
    }

    // Null-terminate and strip trailing whitespace (CR/LF from text editors).
    buf[bytesRead] = '\0';
    std::string_view sv{buf, static_cast<std::size_t>(bytesRead)};
    while (!sv.empty() && (sv.back() == '\r' || sv.back() == '\n' || sv.back() == ' '))
        sv.remove_suffix(1u);

    std::string result(sv);

    // Scrub the sensitive stack buffer before returning.
    RtlSecureZeroMemory(buf, sizeof(buf));

    return result;
}

} // namespace ShadowStrike::Service
