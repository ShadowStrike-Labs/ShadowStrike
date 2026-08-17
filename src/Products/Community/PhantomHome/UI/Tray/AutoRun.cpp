/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AutoRun.cpp — HKCU\Run self-healing registration for the Phantom tray.
 *
 * Security notes:
 *   - Paths are stored as REG_SZ (never REG_EXPAND_SZ) to prevent
 *     environment-variable injection.
 *   - Executable paths containing control characters are rejected.
 *   - The path is quoted and the "--autorun" flag is appended so the tray
 *     can detect it was launched at login (future use).
 */

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>

#include <string>

#include "AutoRun.hpp"
#include "PhantomCore/Utils/Logger.hpp"

namespace ShadowStrike::PhantomHome::Tray {

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------

static constexpr wchar_t kRunSubKey[]    =
    L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
static constexpr wchar_t kAutoRunFlag[]  = L" --autorun";
static constexpr wchar_t kLogCategory[]  = L"AutoRun";

// ---------------------------------------------------------------------------
// HKeyGuard — RAII wrapper for HKEY; calls RegCloseKey on destruction.
// ---------------------------------------------------------------------------

class HKeyGuard final {
public:
    HKeyGuard() noexcept = default;
    explicit HKeyGuard(HKEY k) noexcept : k_(k) {}
    ~HKeyGuard() noexcept { reset(); }

    HKeyGuard(const HKeyGuard&)            = delete;
    HKeyGuard& operator=(const HKeyGuard&) = delete;
    HKeyGuard(HKeyGuard&&)                 = delete;
    HKeyGuard& operator=(HKeyGuard&&)      = delete;

    [[nodiscard]] HKEY get()   const noexcept { return k_; }
    [[nodiscard]] bool valid() const noexcept { return k_ != nullptr; }
    explicit operator bool()   const noexcept { return valid(); }

    void reset(HKEY k = nullptr) noexcept {
        if (k_) { RegCloseKey(k_); }
        k_ = k;
    }

private:
    HKEY k_{nullptr};
};

// ---------------------------------------------------------------------------
// BuildAutoRunValue
//   Returns: "<quoted-exe-path> --autorun"
//   Grows the buffer to 32 768 chars if MAX_PATH is insufficient.
//   Rejects paths containing control characters.
//   Returns empty string on any failure.
// ---------------------------------------------------------------------------

[[nodiscard]] static std::wstring BuildAutoRunValue() noexcept {
    std::wstring buf(MAX_PATH + 1, L'\0');

    while (true) {
        const DWORD written = GetModuleFileNameW(
            nullptr, buf.data(), static_cast<DWORD>(buf.size()));

        if (written == 0) {
            SS_LOG_LAST_ERROR(kLogCategory,
                L"GetModuleFileNameW failed; cannot resolve executable path");
            return {};
        }

        if (written < static_cast<DWORD>(buf.size())) {
            buf.resize(written);
            break;
        }

        // Buffer was too small; grow and retry (up to 32 768 chars).
        if (buf.size() >= 32768) {
            SS_LOG_ERROR(kLogCategory,
                L"Executable path exceeds 32768 characters; rejecting autorun registration");
            return {};
        }
        buf.assign(32768, L'\0');
    }

    // Security: reject any path containing control characters (U+0001–U+001F).
    for (const wchar_t c : buf) {
        if (c >= L'\x01' && c <= L'\x1F') {
            SS_LOG_ERROR(kLogCategory,
                L"Executable path contains control characters; rejecting autorun registration");
            return {};
        }
    }

    // Build: "<path>" --autorun
    std::wstring result;
    result.reserve(buf.size() + 13);   // quotes + flag
    result += L'"';
    result += buf;
    result += L'"';
    result += kAutoRunFlag;
    return result;
}

// ---------------------------------------------------------------------------
// EnsureAutoRun
// ---------------------------------------------------------------------------

bool EnsureAutoRun() {
    const std::wstring desired = BuildAutoRunValue();
    if (desired.empty()) {
        return false;
    }

    HKEY raw{nullptr};
    const LSTATUS openStatus = RegOpenKeyExW(
        HKEY_CURRENT_USER, kRunSubKey, 0, KEY_READ | KEY_WRITE, &raw);

    if (openStatus != ERROR_SUCCESS) {
        SS_LOG_ERROR(kLogCategory,
            L"RegOpenKeyExW(HKCU\\%ls, KEY_READ|KEY_WRITE) failed (status=%ld)",
            kRunSubKey, openStatus);
        return false;
    }
    HKeyGuard key(raw);

    // Read the existing value (if any) to decide whether a write is needed.
    DWORD type{0};
    DWORD cbData{0};
    LSTATUS ls = RegQueryValueExW(
        key.get(), kAutoRunValueName, nullptr, &type, nullptr, &cbData);

    if (ls == ERROR_SUCCESS && type == REG_SZ && cbData >= sizeof(wchar_t)) {
        std::wstring existing(cbData / sizeof(wchar_t), L'\0');
        ls = RegQueryValueExW(
            key.get(), kAutoRunValueName, nullptr, &type,
            reinterpret_cast<LPBYTE>(existing.data()), &cbData);

        if (ls == ERROR_SUCCESS) {
            // Strip null terminator(s) that RegQueryValueExW may include.
            while (!existing.empty() && existing.back() == L'\0')
                existing.pop_back();

            if (existing == desired) {
                SS_LOG_DEBUG(kLogCategory,
                    L"Autorun value already correct; no write needed");
                return true;
            }

            SS_LOG_INFO(kLogCategory,
                L"Autorun value mismatch; updating."
                L" Before=[%ls] After=[%ls]",
                existing.c_str(), desired.c_str());
        }
        // Fall through to write the corrected value.

    } else if (ls == ERROR_FILE_NOT_FOUND) {
        SS_LOG_INFO(kLogCategory,
            L"Autorun value absent; registering: [%ls]", desired.c_str());

    } else if (ls != ERROR_SUCCESS) {
        SS_LOG_ERROR(kLogCategory,
            L"RegQueryValueExW('%ls') failed (status=%ld)",
            kAutoRunValueName, ls);
        return false;
    }

    // Write as REG_SZ — never REG_EXPAND_SZ — to prevent env-var expansion.
    const DWORD cbWrite =
        static_cast<DWORD>((desired.size() + 1) * sizeof(wchar_t));

    ls = RegSetValueExW(
        key.get(), kAutoRunValueName, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(desired.c_str()), cbWrite);

    if (ls != ERROR_SUCCESS) {
        SS_LOG_ERROR(kLogCategory,
            L"RegSetValueExW('%ls') failed (status=%ld)",
            kAutoRunValueName, ls);
        return false;
    }

    SS_LOG_INFO(kLogCategory,
        L"Autorun value registered successfully: [%ls]", desired.c_str());
    return true;
}

// ---------------------------------------------------------------------------
// RemoveAutoRun
// ---------------------------------------------------------------------------

bool RemoveAutoRun() {
    HKEY raw{nullptr};
    LSTATUS ls = RegOpenKeyExW(
        HKEY_CURRENT_USER, kRunSubKey, 0, KEY_WRITE, &raw);

    if (ls != ERROR_SUCCESS) {
        SS_LOG_ERROR(kLogCategory,
            L"RegOpenKeyExW(HKCU\\%ls, KEY_WRITE) for removal failed (status=%ld)",
            kRunSubKey, ls);
        return false;
    }
    HKeyGuard key(raw);

    ls = RegDeleteValueW(key.get(), kAutoRunValueName);

    if (ls == ERROR_FILE_NOT_FOUND) {
        SS_LOG_DEBUG(kLogCategory,
            L"Autorun value already absent; nothing to remove");
        return true;
    }

    if (ls != ERROR_SUCCESS) {
        SS_LOG_ERROR(kLogCategory,
            L"RegDeleteValueW('%ls') failed (status=%ld)",
            kAutoRunValueName, ls);
        return false;
    }

    SS_LOG_INFO(kLogCategory, L"Autorun value removed successfully");
    return true;
}

// ---------------------------------------------------------------------------
// CurrentAutoRunValue
// ---------------------------------------------------------------------------

std::wstring CurrentAutoRunValue() {
    HKEY raw{nullptr};
    LSTATUS ls = RegOpenKeyExW(
        HKEY_CURRENT_USER, kRunSubKey, 0, KEY_READ, &raw);

    if (ls != ERROR_SUCCESS) {
        SS_LOG_WARN(kLogCategory,
            L"RegOpenKeyExW(HKCU\\%ls, KEY_READ) failed (status=%ld)",
            kRunSubKey, ls);
        return {};
    }
    HKeyGuard key(raw);

    DWORD type{0};
    DWORD cbData{0};
    ls = RegQueryValueExW(
        key.get(), kAutoRunValueName, nullptr, &type, nullptr, &cbData);

    if (ls == ERROR_FILE_NOT_FOUND) return {};

    if (ls != ERROR_SUCCESS || type != REG_SZ || cbData < sizeof(wchar_t)) {
        SS_LOG_WARN(kLogCategory,
            L"RegQueryValueExW('%ls') failed or unexpected type "
            L"(status=%ld, type=%lu, cbData=%lu)",
            kAutoRunValueName, ls, type, cbData);
        return {};
    }

    std::wstring value(cbData / sizeof(wchar_t), L'\0');
    ls = RegQueryValueExW(
        key.get(), kAutoRunValueName, nullptr, &type,
        reinterpret_cast<LPBYTE>(value.data()), &cbData);

    if (ls != ERROR_SUCCESS) {
        SS_LOG_WARN(kLogCategory,
            L"RegQueryValueExW('%ls') data read failed (status=%ld)",
            kAutoRunValueName, ls);
        return {};
    }

    while (!value.empty() && value.back() == L'\0')
        value.pop_back();

    return value;
}

} // namespace ShadowStrike::PhantomHome::Tray
