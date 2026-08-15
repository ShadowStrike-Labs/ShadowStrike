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
 * @file RegistryAnalyzer.cpp
 * @brief Enterprise implementation of deep registry forensic analysis engine.
 *
 * The Deep Inspector of ShadowStrike NGAV - performs comprehensive forensic analysis
 * of Windows Registry to detect hidden keys, rootkit artifacts, malformed structures,
 * and advanced persistence mechanisms that evade standard API enumeration.
 *
 * @author ShadowStrike Security Team
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#include "pch.h"
#include "RegistryAnalyzer.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../Utils/RegistryUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../PatternStore/PatternStore.hpp"
#include "../../ThreatIntel/ThreatIntelManager.hpp"
#include "../Process/ProcessMonitor.hpp"
#include "RegistryMonitor.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <chrono>
#include <format>
#include <fstream>
#include <filesystem>
#include <cmath>
#include <numeric>
#include <sstream>
#include <deque>
#include <unordered_set>
#include <regex>
#include <thread>

// ============================================================================
// WINDOWS INCLUDES
// ============================================================================
#ifdef _WIN32
#  include <Windows.h>
#  include <winternl.h>
#  include <sddl.h>
#  pragma comment(lib, "ntdll.lib")
#  pragma comment(lib, "advapi32.lib")

// Native API definitions not in winternl.h
typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation,
    KeyNodeInformation,
    KeyFullInformation,
    KeyNameInformation,
    KeyCachedInformation,
    KeyFlagsInformation,
    KeyVirtualizationInformation,
    KeyHandleTagsInformation,
    KeyAccountInformation,
    MaxKeyInfoClass
} KEY_INFORMATION_CLASS;

typedef struct _KEY_BASIC_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

extern "C" NTSTATUS NTAPI NtOpenKey(
    OUT PHANDLE KeyHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS NTAPI NtEnumerateKey(
    IN HANDLE KeyHandle,
    IN ULONG Index,
    IN KEY_INFORMATION_CLASS KeyInformationClass,
    OUT PVOID KeyInformation,
    IN ULONG Length,
    OUT PULONG ResultLength
);

extern "C" VOID NTAPI RtlInitUnicodeString(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
);
#endif

namespace ShadowStrike {
namespace Core {
namespace Registry {

using namespace std::chrono;
using namespace Utils;
namespace fs = std::filesystem;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

/**
 * @brief Resolve the current interactive user's SID as a wide string.
 * Falls back to "S-1-5-21-0-0-0-0" if token introspection fails.
 */
[[nodiscard]] std::wstring ResolveCurrentUserSid() noexcept {
    std::wstring sidStr;
    HANDLE hToken = nullptr;

    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return L".DEFAULT";
    }

    DWORD tokenUserLen = 0;
    ::GetTokenInformation(hToken, TokenUser, nullptr, 0, &tokenUserLen);

    if (tokenUserLen == 0 || tokenUserLen > 4096) {
        ::CloseHandle(hToken);
        return L".DEFAULT";
    }

    auto buf = std::make_unique<uint8_t[]>(tokenUserLen);
    if (::GetTokenInformation(hToken, TokenUser, buf.get(), tokenUserLen, &tokenUserLen)) {
        auto* pTokenUser = reinterpret_cast<TOKEN_USER*>(buf.get());
        LPWSTR pSidStr = nullptr;
        if (::ConvertSidToStringSidW(pTokenUser->User.Sid, &pSidStr)) {
            sidStr = pSidStr;
            ::LocalFree(pSidStr);
        }
    }

    ::CloseHandle(hToken);
    return sidStr.empty() ? L".DEFAULT" : sidStr;
}

/**
 * @brief Reject paths containing embedded NULL bytes or traversal sequences.
 *
 * Used to validate caller-supplied registry paths before they are converted to
 * Native form. Defends against attacker-influenced path manipulation that
 * could redirect privileged lookups (e.g., `\..\\Machine\\SAM`).
 */
[[nodiscard]] bool IsSafeRegistryPath(const std::wstring& path) noexcept {
    if (path.size() > RegistryAnalyzerConstants::MAX_KEY_PATH_LENGTH) return false;
    if (path.find(L'\0') != std::wstring::npos) return false;
    // Reject "..\\" segments which are not meaningful for registry but are
    // common in path-traversal attacks against converters that share logic
    // with filesystem code.
    if (path.find(L"\\..\\") != std::wstring::npos) return false;
    if (path.starts_with(L"..\\") || path.ends_with(L"\\..")) return false;
    return true;
}

/**
 * @brief Convert Win32 path to Native path, resolving user SID.
 *
 * The current-user SID is resolved on every call so that the function
 * behaves correctly when invoked under impersonation tokens or in service
 * contexts where the calling thread's effective user is not the same as the
 * one captured at first use. Returns an empty string if the input fails
 * structural validation.
 */
[[nodiscard]] std::wstring Win32ToNativePath(const std::wstring& path) {
    if (!IsSafeRegistryPath(path)) {
        return {};
    }
    std::wstring native = path;
    if (native.starts_with(L"HKEY_LOCAL_MACHINE") || native.starts_with(L"HKLM")) {
        size_t pos = native.find(L'\\');
        native = L"\\Registry\\Machine" + (pos != std::wstring::npos ? native.substr(pos) : L"");
    } else if (native.starts_with(L"HKEY_CURRENT_USER") || native.starts_with(L"HKCU")) {
        size_t pos = native.find(L'\\');
        // Resolve per-call so impersonated threads map to the correct hive.
        const std::wstring currentSid = ResolveCurrentUserSid();
        native = L"\\Registry\\User\\" + currentSid + (pos != std::wstring::npos ? native.substr(pos) : L"");
    } else if (native.starts_with(L"HKEY_USERS") || native.starts_with(L"HKU")) {
        size_t pos = native.find(L'\\');
        native = L"\\Registry\\User" + (pos != std::wstring::npos ? native.substr(pos) : L"");
    } else if (native.starts_with(L"HKEY_CLASSES_ROOT") || native.starts_with(L"HKCR")) {
        size_t pos = native.find(L'\\');
        native = L"\\Registry\\Machine\\SOFTWARE\\Classes" + (pos != std::wstring::npos ? native.substr(pos) : L"");
    } else if (native.starts_with(L"HKEY_CURRENT_CONFIG") || native.starts_with(L"HKCC")) {
        size_t pos = native.find(L'\\');
        native = L"\\Registry\\Machine\\System\\CurrentControlSet\\Hardware Profiles\\Current"
              + (pos != std::wstring::npos ? native.substr(pos) : L"");
    }
    return native;
}

/**
 * @brief Map an HKEY root to its short hive label (HKLM/HKCU/HKCR/HKU/HKCC).
 */
[[nodiscard]] std::wstring HKeyToHiveLabel(HKEY root) noexcept {
    if (root == HKEY_LOCAL_MACHINE)     return L"HKLM";
    if (root == HKEY_CURRENT_USER)      return L"HKCU";
    if (root == HKEY_CLASSES_ROOT)      return L"HKCR";
    if (root == HKEY_USERS)             return L"HKU";
    if (root == HKEY_CURRENT_CONFIG)    return L"HKCC";
    return L"UNKNOWN";
}

/**
 * @brief Return the hive label for the leading root of a Win32 registry path.
 */
[[nodiscard]] std::wstring PathToHiveLabel(const std::wstring& keyPath) noexcept {
    if (keyPath.starts_with(L"HKEY_LOCAL_MACHINE") || keyPath.starts_with(L"HKLM"))    return L"HKLM";
    if (keyPath.starts_with(L"HKEY_CURRENT_USER")  || keyPath.starts_with(L"HKCU"))    return L"HKCU";
    if (keyPath.starts_with(L"HKEY_CLASSES_ROOT")  || keyPath.starts_with(L"HKCR"))    return L"HKCR";
    if (keyPath.starts_with(L"HKEY_USERS")         || keyPath.starts_with(L"HKU"))     return L"HKU";
    if (keyPath.starts_with(L"HKEY_CURRENT_CONFIG")|| keyPath.starts_with(L"HKCC"))    return L"HKCC";
    return L"UNKNOWN";
}

/**
 * @brief Returns true if the given path already carries an explicit hive prefix.
 */
[[nodiscard]] bool PathHasExplicitHive(const std::wstring& keyPath) noexcept {
    return PathToHiveLabel(keyPath) != L"UNKNOWN";
}

/**
 * @brief Calculate Shannon entropy.
 */
[[nodiscard]] double CalculateEntropy(std::span<const uint8_t> data) noexcept {
    if (data.empty()) return 0.0;

    std::array<uint64_t, 256> frequencies{};
    for (uint8_t byte : data) {
        frequencies[byte]++;
    }

    double entropy = 0.0;
    const double dataSize = static_cast<double>(data.size());

    for (uint64_t freq : frequencies) {
        if (freq > 0) {
            double probability = static_cast<double>(freq) / dataSize;
            entropy -= probability * std::log2(probability);
        }
    }

    return entropy;
}

/**
 * @brief Check if data contains NULL bytes.
 */
[[nodiscard]] bool ContainsNullBytes(std::span<const uint8_t> data) noexcept {
    return std::find(data.begin(), data.end(), 0x00) != data.end();
}

/**
 * @brief Check if string has control characters.
 */
[[nodiscard]] bool HasControlCharacters(const std::wstring& str) noexcept {
    for (wchar_t ch : str) {
        if (ch < 0x20 && ch != 0x09 && ch != 0x0A && ch != 0x0D) {
            return true;  // Control character (except tab, LF, CR)
        }
    }
    return false;
}

/**
 * @brief Check if data looks like executable content.
 * Detects PE files, ELF, scripts (.NET, PowerShell, VBScript, JScript), and shellcode patterns.
 */
[[nodiscard]] bool LooksLikeExecutable(std::span<const uint8_t> data) noexcept {
    if (data.size() < 4) return false;

    // PE signature (MZ header)
    if (data[0] == 'M' && data[1] == 'Z') {
        return true;
    }

    // ELF signature
    if (data.size() >= 4 && data[0] == 0x7F && data[1] == 'E' &&
        data[2] == 'L' && data[3] == 'F') {
        return true;
    }

    // .NET assembly / MSIL (check for CLI header marker after MZ)
    // BSJB (.NET metadata) signature
    if (data.size() >= 64) {
        for (size_t i = 0; i + 4 <= data.size() && i < 512; ++i) {
            if (data[i] == 'B' && data[i+1] == 'S' &&
                data[i+2] == 'J' && data[i+3] == 'B') {
                return true;
            }
        }
    }

    // Common x86/x64 shellcode stubs
    // NOP sled (>= 16 consecutive NOPs). Raised from 8 to reduce false
    // positives against benign binary blobs that legitimately contain short
    // 0x90 runs (font padding, structured padding, etc.).
    if (data.size() >= 16) {
        size_t nopCount = 0;
        for (size_t i = 0; i < std::min(data.size(), size_t(256)); ++i) {
            if (data[i] == 0x90) {
                if (++nopCount >= 16) return true;
            } else {
                nopCount = 0;
            }
        }
    }

    // Shellcode prologue patterns require *corroborating* context to fire,
    // because the raw byte sequences are extremely common inside ordinary
    // binary data (image rows, compressed blobs, REG_BINARY structures).
    // We therefore require both a recognizable opcode prefix AND a
    // plausible immediate operand, AND a minimum payload size.
    if (data.size() >= 32) {
        // x86 GetPC via `call $+5` followed by `pop reg` (58-5F).
        if (data[0] == 0xE8 && data[1] == 0x00 && data[2] == 0x00 &&
            data[3] == 0x00 && data[4] == 0x00 &&
            data[5] >= 0x58 && data[5] <= 0x5F) {
            return true;
        }
        // x64 `sub rsp, imm8` must use an aligned, reasonable stack delta
        // (multiple of 8, less than 0x80), and be followed by another
        // typical prologue byte. Otherwise this is almost certainly noise.
        if (data[0] == 0x48 && data[1] == 0x83 && data[2] == 0xEC) {
            const uint8_t delta = data[3];
            const uint8_t next  = data[4];
            const bool sanePrologue = (delta != 0) && ((delta & 0x07) == 0) && (delta < 0x80);
            // Common follow-ups: another REX-prefixed instruction, push reg,
            // mov reg/reg, lea, or xor reg,reg.
            const bool plausibleFollow =
                next == 0x48 || next == 0x4C || next == 0x49 ||
                (next >= 0x50 && next <= 0x57) ||
                next == 0x33 || next == 0x8B || next == 0x89;
            if (sanePrologue && plausibleFollow) return true;
        }
    }

    // Script detection - check as narrow string for script markers
    auto asStr = std::string_view(reinterpret_cast<const char*>(data.data()),
                                   std::min(data.size(), size_t(512)));

    // PowerShell markers
    static constexpr std::string_view psMarkers[] = {
        "powershell", "Invoke-Expression", "IEX(", "New-Object",
        "[System.Convert]::", "[System.Reflection.Assembly]::",
        "-EncodedCommand", "FromBase64String"
    };
    for (auto marker : psMarkers) {
        if (asStr.find(marker) != std::string_view::npos) return true;
    }

    // VBScript/JScript markers
    static constexpr std::string_view scriptMarkers[] = {
        "WScript.Shell", "CreateObject(", "Scripting.FileSystemObject",
        "ADODB.Stream", "eval(", "ActiveXObject"
    };
    for (auto marker : scriptMarkers) {
        if (asStr.find(marker) != std::string_view::npos) return true;
    }

    return false;
}

/**
 * @brief Sanitize a registry path for safe logging.
 * Replaces NULL bytes and control characters with escape sequences.
 */
[[nodiscard]] std::wstring SanitizePathForLogging(const std::wstring& path) noexcept {
    std::wstring sanitized;
    sanitized.reserve(path.size());
    for (wchar_t ch : path) {
        if (ch == L'\0') {
            sanitized += L"\\x00";
        } else if (ch < 0x20) {
            sanitized += std::format(L"\\x{:02X}", static_cast<unsigned>(ch));
        } else {
            sanitized += ch;
        }
    }
    return sanitized;
}

/**
 * @brief Escape a string field for CSV output (RFC 4180 compliant).
 */
[[nodiscard]] std::string EscapeCsvField(const std::string& field) noexcept {
    if (field.find_first_of(",\"\r\n") == std::string::npos &&
        !field.starts_with('=') && !field.starts_with('+') &&
        !field.starts_with('-') && !field.starts_with('@')) {
        return field;
    }
    std::string escaped = "\"";
    for (char ch : field) {
        if (ch == '"') escaped += "\"\"";
        else escaped += ch;
    }
    escaped += '"';
    return escaped;
}

/**
 * @brief Resolve HKEY root + subkey from a full path like "HKLM\\SOFTWARE\\..."
 */
[[nodiscard]] std::pair<HKEY, std::wstring> ResolveRootKey(const std::wstring& keyPath) noexcept {
    // Helper that safely returns the subkey portion or the empty string
    // when the path consists of just a root prefix (no backslash).
    auto subAfterFirstSep = [&](const std::wstring& p) -> std::wstring {
        const size_t pos = p.find(L'\\');
        return (pos == std::wstring::npos) ? std::wstring{} : p.substr(pos + 1);
    };

    if (keyPath == L"HKEY_LOCAL_MACHINE" || keyPath == L"HKLM" ||
        keyPath.starts_with(L"HKEY_LOCAL_MACHINE\\") || keyPath.starts_with(L"HKLM\\")) {
        return { HKEY_LOCAL_MACHINE, subAfterFirstSep(keyPath) };
    }
    if (keyPath == L"HKEY_CURRENT_USER" || keyPath == L"HKCU" ||
        keyPath.starts_with(L"HKEY_CURRENT_USER\\") || keyPath.starts_with(L"HKCU\\")) {
        return { HKEY_CURRENT_USER, subAfterFirstSep(keyPath) };
    }
    if (keyPath == L"HKEY_CLASSES_ROOT" || keyPath == L"HKCR" ||
        keyPath.starts_with(L"HKEY_CLASSES_ROOT\\") || keyPath.starts_with(L"HKCR\\")) {
        return { HKEY_CLASSES_ROOT, subAfterFirstSep(keyPath) };
    }
    if (keyPath == L"HKEY_USERS" || keyPath == L"HKU" ||
        keyPath.starts_with(L"HKEY_USERS\\") || keyPath.starts_with(L"HKU\\")) {
        return { HKEY_USERS, subAfterFirstSep(keyPath) };
    }
    if (keyPath == L"HKEY_CURRENT_CONFIG" || keyPath == L"HKCC" ||
        keyPath.starts_with(L"HKEY_CURRENT_CONFIG\\") || keyPath.starts_with(L"HKCC\\")) {
        return { HKEY_CURRENT_CONFIG, subAfterFirstSep(keyPath) };
    }
    // No recognized hive prefix; treat as a relative path under HKLM.
    return { HKEY_LOCAL_MACHINE, keyPath };
}

/**
 * @brief Detect if data is Base64 encoded with reduced false-positive rate.
 * Checks alphabet match, length divisibility, padding, and whitespace ratio.
 */
[[nodiscard]] bool IsBase64Encoded(std::span<const uint8_t> data) noexcept {
    if (data.size() < 16) return false;

    // Determine effective length (strip trailing whitespace/newlines)
    size_t effectiveLen = data.size();
    while (effectiveLen > 0 && (data[effectiveLen - 1] == '\r' || data[effectiveLen - 1] == '\n' ||
                                 data[effectiveLen - 1] == ' ')) {
        effectiveLen--;
    }
    if (effectiveLen < 16) return false;

    size_t validB64Count = 0;
    size_t whitespaceCount = 0;
    size_t paddingCount = 0;
    bool lastWasPadding = false;

    for (size_t i = 0; i < effectiveLen; ++i) {
        uint8_t ch = data[i];
        if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
            (ch >= '0' && ch <= '9') || ch == '+' || ch == '/') {
            if (lastWasPadding) return false;  // data after padding = not base64
            validB64Count++;
        } else if (ch == '=') {
            paddingCount++;
            lastWasPadding = true;
            if (paddingCount > 2) return false;
        } else if (ch == '\r' || ch == '\n' || ch == ' ') {
            whitespaceCount++;
        } else {
            return false;  // Invalid character for base64
        }
    }

    size_t contentLen = validB64Count + paddingCount;
    if (contentLen < 16) return false;

    // Base64 content length must be divisible by 4
    if (contentLen % 4 != 0) return false;

    // High ratio of valid chars (>95% excluding whitespace)
    size_t nonWhitespace = effectiveLen - whitespaceCount;
    if (nonWhitespace == 0) return false;
    return (validB64Count + paddingCount) > (nonWhitespace * 95 / 100);
}

/**
 * @brief Extract hive name from hive type.
 */
[[nodiscard]] std::wstring HiveTypeToString(HiveType type) noexcept {
    switch (type) {
        case HiveType::SAM: return L"SAM";
        case HiveType::SECURITY: return L"SECURITY";
        case HiveType::SOFTWARE: return L"SOFTWARE";
        case HiveType::SYSTEM: return L"SYSTEM";
        case HiveType::DEFAULT: return L"DEFAULT";
        case HiveType::NTUSER: return L"NTUSER.DAT";
        case HiveType::USRCLASS: return L"UsrClass.dat";
        case HiveType::AMCACHE: return L"Amcache.hve";
        case HiveType::BCD: return L"BCD";
        case HiveType::COMPONENTS: return L"COMPONENTS";
        default: return L"Unknown";
    }
}

/**
 * @brief Get MITRE technique for anomaly type.
 *
 * Mappings reflect MITRE ATT&CK v14 sub-techniques most precisely
 * applicable to the anomaly class. SuspiciousAutorun and KnownMalwareKey
 * map to T1547 (Boot/Logon Autostart) alongside T1112 (Modify Registry).
 */
[[nodiscard]] std::string GetMITRETechnique(AnomalyType type) noexcept {
    switch (type) {
        case AnomalyType::NullByteInjection:
        case AnomalyType::UnicodeControlChar:
        case AnomalyType::APIHiddenKey:
        case AnomalyType::APIHiddenValue:
            return "T1564.001";  // Hidden Files and Directories

        case AnomalyType::DKOMEvidence:
        case AnomalyType::HookedFunction:
        case AnomalyType::ModifiedCallback:
            return "T1014";  // Rootkit

        case AnomalyType::KnownMalwareKey:
        case AnomalyType::KnownMalwareValue:
            return "T1112/T1547";  // Modify Registry + Autostart

        case AnomalyType::SuspiciousAutorun:
            return "T1547.001";  // Run keys

        default:
            return "T1112";  // Modify Registry
    }
}

/**
 * @brief Decode a REG_SZ/REG_EXPAND_SZ/REG_MULTI_SZ buffer into one or more
 *        wide strings, performing strict bounds validation.
 *
 * - The buffer must be an even number of bytes (UTF-16 LE).
 * - Each individual string is bounded by the buffer extent and never
 *   reads past the terminator.
 * - REG_MULTI_SZ stops at the first empty string (the documented
 *   double-NULL terminator) and rejects oversized component counts to
 *   defend against forced allocation amplification.
 */
[[nodiscard]] std::vector<std::wstring> DecodeRegistryStrings(
    DWORD valueType,
    std::span<const uint8_t> data
) noexcept {
    std::vector<std::wstring> out;
    if (data.empty() || (data.size() % sizeof(wchar_t)) != 0) {
        return out;
    }
    const auto* base = reinterpret_cast<const wchar_t*>(data.data());
    const size_t count = data.size() / sizeof(wchar_t);

    if (valueType == REG_SZ || valueType == REG_EXPAND_SZ) {
        // Stop at the first NULL terminator (may be absent on malformed
        // values; clamp to buffer end).
        size_t end = 0;
        while (end < count && base[end] != L'\0') ++end;
        if (end > 0) out.emplace_back(base, end);
        return out;
    }

    if (valueType == REG_MULTI_SZ) {
        constexpr size_t MAX_MULTI_SZ_COMPONENTS = 4096;
        size_t pos = 0;
        while (pos < count && out.size() < MAX_MULTI_SZ_COMPONENTS) {
            size_t end = pos;
            while (end < count && base[end] != L'\0') ++end;
            const size_t len = end - pos;
            if (len == 0) break;  // double-NULL terminator
            out.emplace_back(base + pos, len);
            pos = end + 1;  // skip the embedded NULL
        }
    }
    return out;
}

/**
 * @brief Safely expand %VAR% references in a REG_EXPAND_SZ payload.
 *
 * Caps the expansion buffer at 64 KB so a hostile registry value of the
 * form `%X%%X%%X%...` (recursive amplification) cannot exhaust memory.
 */
[[nodiscard]] std::wstring ExpandEnvironmentStringsSafe(const std::wstring& src) noexcept {
    if (src.empty()) return {};
    if (src.find(L'%') == std::wstring::npos) return src;
    constexpr DWORD CAP = 64 * 1024 / sizeof(wchar_t);
    std::wstring out(CAP, L'\0');
    const DWORD needed = ::ExpandEnvironmentStringsW(src.c_str(), out.data(), CAP);
    if (needed == 0 || needed > CAP) {
        return src;  // Failure or overflow: return the raw form unchanged.
    }
    // ExpandEnvironmentStringsW returns size including terminator.
    out.resize(needed > 0 ? needed - 1 : 0);
    return out;
}

/**
 * @brief Lower-case a wide string (ASCII-only fold) for substring matching.
 */
[[nodiscard]] std::wstring ToLowerAscii(std::wstring s) noexcept {
    for (auto& ch : s) {
        if (ch >= L'A' && ch <= L'Z') ch = static_cast<wchar_t>(ch + (L'a' - L'A'));
    }
    return s;
}

} // anonymous namespace

// ============================================================================
// RegistryAnalyzerConfig FACTORY METHODS
// ============================================================================

RegistryAnalyzerConfig RegistryAnalyzerConfig::CreateDefault() noexcept {
    return RegistryAnalyzerConfig{};
}

RegistryAnalyzerConfig RegistryAnalyzerConfig::CreateForensic() noexcept {
    RegistryAnalyzerConfig config;
    config.defaultMode = AnalysisMode::Forensic;
    config.detectHiddenKeys = true;
    config.detectHiddenValues = true;
    config.analyzeEntropy = true;
    config.detectEmbeddedExecutables = true;

    config.enableCrossView = true;
    config.detectDKOM = true;

    config.recoverDeleted = true;
    config.analyzeSlackSpace = true;
    config.buildTimeline = true;

    config.matchPatterns = true;
    config.matchIOCs = true;

    config.maxAnomalies = RegistryAnalyzerConstants::MAX_ANOMALIES;
    config.threadCount = 8;

    return config;
}

RegistryAnalyzerConfig RegistryAnalyzerConfig::CreateRootkitHunting() noexcept {
    RegistryAnalyzerConfig config;
    config.defaultMode = AnalysisMode::RootkitHunting;
    config.detectHiddenKeys = true;
    config.detectHiddenValues = true;
    config.analyzeEntropy = true;
    config.detectEmbeddedExecutables = false;

    config.enableCrossView = true;
    config.detectDKOM = true;

    config.recoverDeleted = false;
    config.analyzeSlackSpace = false;
    config.buildTimeline = false;

    config.matchPatterns = true;
    config.matchIOCs = true;

    config.maxAnomalies = 10000;
    config.threadCount = 4;

    return config;
}

RegistryAnalyzerConfig RegistryAnalyzerConfig::CreateQuick() noexcept {
    RegistryAnalyzerConfig config;
    config.defaultMode = AnalysisMode::Quick;
    config.detectHiddenKeys = true;
    config.detectHiddenValues = false;
    config.analyzeEntropy = false;
    config.detectEmbeddedExecutables = false;

    config.enableCrossView = false;
    config.detectDKOM = false;

    config.recoverDeleted = false;
    config.analyzeSlackSpace = false;
    config.buildTimeline = false;

    config.matchPatterns = false;
    config.matchIOCs = false;

    config.maxAnomalies = 1000;
    config.threadCount = 2;

    return config;
}

// ============================================================================
// RegistryAnalyzerStatistics METHODS
// ============================================================================

void RegistryAnalyzerStatistics::Reset() noexcept {
    totalScans.store(0, std::memory_order_relaxed);
    keysAnalyzed.store(0, std::memory_order_relaxed);
    valuesAnalyzed.store(0, std::memory_order_relaxed);
    bytesAnalyzed.store(0, std::memory_order_relaxed);

    anomaliesDetected.store(0, std::memory_order_relaxed);
    hiddenKeysFound.store(0, std::memory_order_relaxed);
    hiddenValuesFound.store(0, std::memory_order_relaxed);
    rootkitIndicators.store(0, std::memory_order_relaxed);
    maliciousEntries.store(0, std::memory_order_relaxed);

    deletedRecovered.store(0, std::memory_order_relaxed);
    patternsMatched.store(0, std::memory_order_relaxed);
    iocsMatched.store(0, std::memory_order_relaxed);
}

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

/**
 * @brief Private implementation class for RegistryAnalyzer.
 */
class RegistryAnalyzer::Impl {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================

    // Thread safety
    mutable std::shared_mutex m_configMutex;
    mutable std::shared_mutex m_anomalyMutex;
    mutable std::shared_mutex m_hiddenMutex;
    mutable std::shared_mutex m_timelineMutex;
    mutable std::shared_mutex m_callbackMutex;
    mutable std::shared_mutex m_indicatorMutex;

    // State
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_analyzing{false};
    std::atomic<bool> m_abortRequested{false};
    std::atomic<uint64_t> m_nextAnomalyId{1};

    // Configuration
    RegistryAnalyzerConfig m_config{};

    // Statistics
    RegistryAnalyzerStatistics m_stats{};

    // Detected anomalies
    std::deque<RegistryAnomaly> m_anomalies;
    std::unordered_map<uint64_t, RegistryAnomaly> m_anomalyMap;

    // Hidden entries
    std::unordered_set<std::wstring> m_hiddenKeys;
    std::unordered_map<std::wstring, std::vector<std::wstring>> m_hiddenValues;

    // Forensic timeline
    std::deque<ForensicTimeline> m_timeline;

    // Deleted entries
    std::vector<DeletedEntry> m_deletedEntries;

    // Threat indicators
    std::vector<ThreatIndicator> m_indicators;

    // Callbacks
    std::atomic<uint64_t> m_nextCallbackId{1};
    std::unordered_map<uint64_t, AnomalyCallback> m_anomalyCallbacks;
    std::unordered_map<uint64_t, ScanProgressCallback> m_progressCallbacks;
    std::unordered_map<uint64_t, HiddenEntryCallback> m_hiddenCallbacks;

    // ========================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // ========================================================================

    Impl() = default;
    ~Impl() = default;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    [[nodiscard]] bool Initialize(const RegistryAnalyzerConfig& config) {
        std::unique_lock lock(m_configMutex);

        if (m_initialized.load(std::memory_order_acquire)) {
            SS_LOG_WARN(L"Registry", L"RegistryAnalyzer::Impl already initialized");
            return true;
        }

        try {
            SS_LOG_INFO(L"Registry", L"RegistryAnalyzer::Impl: Initializing");

            // Store configuration
            m_config = config;

            // Reset statistics
            m_stats.Reset();

            // Load threat indicators if path specified
            if (!m_config.iocDatabasePath.empty()) {
                LoadThreatIndicatorsImpl(m_config.iocDatabasePath);
            }

            m_initialized.store(true, std::memory_order_release);
            SS_LOG_INFO(L"Registry", L"RegistryAnalyzer::Impl: Initialization complete");

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer::Impl: Initialization exception: %hs", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_configMutex);

        if (!m_initialized.load(std::memory_order_acquire)) {
            return;
        }

        SS_LOG_INFO(L"Registry", L"RegistryAnalyzer::Impl: Shutting down");

        // Signal any in-flight scan to abort and drain it before
        // dismantling the data structures it may still be touching.
        m_abortRequested.store(true, std::memory_order_release);
        {
            using namespace std::chrono;
            const auto deadline = steady_clock::now() + seconds(5);
            while (m_analyzing.load(std::memory_order_acquire) &&
                   steady_clock::now() < deadline) {
                std::this_thread::sleep_for(milliseconds(10));
            }
            if (m_analyzing.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"Registry",
                    L"RegistryAnalyzer::Impl: Shutdown proceeding while analyzer thread still active "
                    L"(drain timeout) - data structures will be cleared regardless");
            }
        }

        // Clear data structures
        {
            std::unique_lock anomalyLock(m_anomalyMutex);
            m_anomalies.clear();
            m_anomalyMap.clear();
        }

        {
            std::unique_lock hiddenLock(m_hiddenMutex);
            m_hiddenKeys.clear();
            m_hiddenValues.clear();
        }

        {
            std::unique_lock timelineLock(m_timelineMutex);
            m_timeline.clear();
        }

        {
            std::unique_lock cbLock(m_callbackMutex);
            m_anomalyCallbacks.clear();
            m_progressCallbacks.clear();
            m_hiddenCallbacks.clear();
        }

        m_initialized.store(false, std::memory_order_release);
        SS_LOG_INFO(L"Registry", L"RegistryAnalyzer::Impl: Shutdown complete");
    }

    // ========================================================================
    // ANALYSIS OPERATIONS
    // ========================================================================

    [[nodiscard]] AnalysisResult AnalyzeImpl(const AnalysisScope& scope, AnalysisMode mode) {
        AnalysisResult result{};
        result.mode = mode;
        result.startTime = system_clock::now();

        const auto analysisStart = steady_clock::now();

        try {
            m_analyzing.store(true, std::memory_order_release);
            m_abortRequested.store(false, std::memory_order_release);

            SS_LOG_INFO(L"Registry", L"RegistryAnalyzer: Starting analysis - Mode: %d", static_cast<int>(mode));

            // Analyze based on mode
            switch (mode) {
                case AnalysisMode::Quick:
                    result = PerformQuickAnalysis(scope);
                    break;

                case AnalysisMode::Standard:
                    result = PerformStandardAnalysis(scope);
                    break;

                case AnalysisMode::Deep:
                    result = PerformDeepAnalysis(scope);
                    break;

                case AnalysisMode::Forensic:
                    result = PerformForensicAnalysis(scope);
                    break;

                case AnalysisMode::RootkitHunting:
                    result = PerformRootkitHunting(scope);
                    break;
            }

            result.endTime = system_clock::now();
            result.duration = duration_cast<milliseconds>(steady_clock::now() - analysisStart);
            result.completed = true;

            m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);

            SS_LOG_INFO(L"Registry", L"RegistryAnalyzer: Analysis complete - %llu anomalies, %llu hidden keys, %lld ms",
                result.anomaliesFound, result.hiddenKeysFound, result.duration.count());

            m_analyzing.store(false, std::memory_order_release);
            return result;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Analysis exception: %hs", e.what());
            result.hadErrors = true;
            result.errors.push_back(e.what());
            m_analyzing.store(false, std::memory_order_release);
            return result;
        }
    }

    [[nodiscard]] AnalysisResult PerformQuickAnalysis(const AnalysisScope& scope) {
        AnalysisResult result{};
        result.mode = AnalysisMode::Quick;

        // Quick scan for NULL byte hidden keys
        if (m_config.detectHiddenKeys) {
            for (const auto& path : scope.specificPaths) {
                auto hidden = DetectNullByteKeysImpl(path);
                result.hiddenKeysFound += static_cast<uint32_t>(hidden.size());
            }
        }

        return result;
    }

    [[nodiscard]] AnalysisResult PerformStandardAnalysis(const AnalysisScope& scope) {
        AnalysisResult result{};
        result.mode = AnalysisMode::Standard;

        // Detect hidden keys
        if (m_config.detectHiddenKeys) {
            for (const auto& path : scope.specificPaths) {
                auto hidden = DetectNullByteKeysImpl(path);
                result.hiddenKeysFound += static_cast<uint32_t>(hidden.size());

                // Analyze each hidden key
                for (const auto& hiddenPath : hidden) {
                    auto anomalies = AnalyzeKeyImpl(hiddenPath, false);
                    result.anomaliesFound += static_cast<uint32_t>(anomalies.size());
                }
            }
        }

        // Cross-view detection for rootkits
        if (m_config.enableCrossView) {
            for (const auto& path : scope.specificPaths) {
                auto crossView = PerformCrossViewDetectionImpl(path);
                if (crossView.hasDiscrepancy) {
                    result.hiddenKeysFound += static_cast<uint32_t>(crossView.hiddenSubKeys.size());
                    result.hiddenValuesFound += static_cast<uint32_t>(crossView.hiddenValues.size());
                    m_stats.rootkitIndicators.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }

        return result;
    }

    [[nodiscard]] AnalysisResult PerformDeepAnalysis(const AnalysisScope& scope) {
        AnalysisResult result = PerformStandardAnalysis(scope);
        result.mode = AnalysisMode::Deep;

        // Analyze all values for entropy, executables, etc.
        if (m_config.analyzeEntropy || m_config.detectEmbeddedExecutables) {
            for (const auto& path : scope.specificPaths) {
                auto anomalies = AnalyzeKeyImpl(path, scope.maxDepth > 1);
                result.anomaliesFound += static_cast<uint32_t>(anomalies.size());
            }
        }

        // Pattern matching
        if (m_config.matchPatterns && !m_indicators.empty()) {
            auto iocAnomalies = SearchIOCsImpl({});
            result.anomaliesFound += static_cast<uint32_t>(iocAnomalies.size());
        }

        return result;
    }

    [[nodiscard]] AnalysisResult PerformForensicAnalysis(const AnalysisScope& scope) {
        AnalysisResult result = PerformDeepAnalysis(scope);
        result.mode = AnalysisMode::Forensic;

        // Recover deleted entries if configured
        if (m_config.recoverDeleted) {
            // Recover from system hives where we have access
            const std::wstring sysRoot = L"C:\\Windows\\System32\\config\\";
            struct HiveEntry { HiveType type; std::wstring path; };
            const HiveEntry hives[] = {
                { HiveType::SOFTWARE, sysRoot + L"SOFTWARE" },
                { HiveType::SYSTEM,   sysRoot + L"SYSTEM" },
                { HiveType::SAM,      sysRoot + L"SAM" },
                { HiveType::SECURITY, sysRoot + L"SECURITY" },
            };

            for (const auto& [hiveType, hivePath] : hives) {
                if (m_abortRequested.load(std::memory_order_acquire)) break;
                try {
                    auto recovered = RecoverDeletedEntriesImpl(hivePath);
                    result.deletedRecovered += recovered.size();
                    for (auto& entry : recovered) {
                        std::unique_lock lock(m_anomalyMutex);
                        m_deletedEntries.push_back(std::move(entry));
                    }
                } catch (const std::exception& e) {
                    SS_LOG_WARN(L"Registry", L"RegistryAnalyzer: Recovery from %ls failed: %hs",
                        hivePath.c_str(), e.what());
                }
            }
        }

        // Build forensic timeline from key timestamps
        if (m_config.buildTimeline) {
            BuildTimelineFromKeys(scope);
        }

        return result;
    }

    /**
     * @brief Build forensic timeline by enumerating keys and recording their last-write times.
     */
    void BuildTimelineFromKeys(const AnalysisScope& scope) {
        for (const auto& path : scope.specificPaths) {
            if (m_abortRequested.load(std::memory_order_acquire)) break;
            try {
                auto [rootKey, subKey] = ResolveRootKey(path);

                RegistryUtils::RegistryKey regKey;
                RegistryUtils::OpenOptions opts;
                opts.access = KEY_READ;
                opts.wow64_64 = true;

                if (!regKey.Open(rootKey, subKey, opts)) continue;

                RegistryUtils::KeyInfo info;
                if (regKey.QueryInfo(info)) {
                    ULARGE_INTEGER uli;
                    uli.LowPart = info.lastWriteTime.dwLowDateTime;
                    uli.HighPart = info.lastWriteTime.dwHighDateTime;

                    if (uli.QuadPart > 0) {
                        constexpr int64_t FILETIME_EPOCH_OFFSET_SEC = 11644473600LL;
                        auto windowsDuration = std::chrono::duration<int64_t, std::ratio<1, 10000000>>(
                            static_cast<int64_t>(uli.QuadPart));
                        auto unixDuration = windowsDuration - std::chrono::seconds(FILETIME_EPOCH_OFFSET_SEC);

                        ForensicTimeline entry;
                        entry.timestamp = std::chrono::system_clock::time_point(
                            std::chrono::duration_cast<std::chrono::system_clock::duration>(unixDuration));
                        entry.action = "Modified";
                        entry.keyPath = path;
                        entry.description = "Key last write time";

                        std::unique_lock lock(m_timelineMutex);
                        m_timeline.push_back(std::move(entry));
                    }
                }
            } catch (const std::exception& e) {
                SS_LOG_DEBUG(L"Registry", L"RegistryAnalyzer: Timeline build exception for %ls: %hs",
                    SanitizePathForLogging(path).c_str(), e.what());
            }
        }
    }

    [[nodiscard]] AnalysisResult PerformRootkitHunting(const AnalysisScope& scope) {
        AnalysisResult result{};
        result.mode = AnalysisMode::RootkitHunting;

        // Focus on cross-view detection
        if (m_config.enableCrossView) {
            for (const auto& path : scope.specificPaths) {
                auto crossView = PerformCrossViewDetectionImpl(path);
                if (crossView.hasDiscrepancy) {
                    result.hiddenKeysFound += static_cast<uint32_t>(crossView.hiddenSubKeys.size());
                    result.hiddenValuesFound += static_cast<uint32_t>(crossView.hiddenValues.size());

                    m_stats.rootkitIndicators.fetch_add(1, std::memory_order_relaxed);

                    // Create anomaly for rootkit indicator
                    for (const auto& hiddenKey : crossView.hiddenSubKeys) {
                        RecordAnomaly(AnomalyType::APIHiddenKey, AnomalySeverity::Critical,
                            path, hiddenKey, L"", {},
                            "Hidden key detected via cross-view analysis (rootkit indicator)");
                    }
                }
            }
        }

        // DKOM detection — queries kernel registry integrity
        if (m_config.detectDKOM) {
            if (DetectDKOMImpl()) {
                result.maliciousEntries++;
            }
        }

        return result;
    }

    [[nodiscard]] std::vector<RegistryAnomaly> AnalyzeKeyImpl(
        const std::wstring& keyPath,
        bool recursive,
        uint32_t currentDepth = 0,
        uint32_t maxDepth = RegistryAnalyzerConstants::MAX_SCAN_DEPTH
    ) {
        std::vector<RegistryAnomaly> anomalies;

        if (m_abortRequested.load(std::memory_order_acquire)) {
            return anomalies;
        }

        const uint32_t effectiveMaxDepth = std::min<uint32_t>(
            maxDepth, RegistryAnalyzerConstants::MAX_SCAN_DEPTH);
        if (currentDepth >= effectiveMaxDepth) {
            SS_LOG_WARN(L"Registry", L"RegistryAnalyzer: Max scan depth %u reached at %ls",
                effectiveMaxDepth, SanitizePathForLogging(keyPath).c_str());
            return anomalies;
        }

        // Reject paths with embedded NULLs / traversal sequences before
        // touching any registry API.
        if (!IsSafeRegistryPath(keyPath)) {
            SS_LOG_WARN(L"Registry", L"RegistryAnalyzer: Rejected unsafe key path: %ls",
                SanitizePathForLogging(keyPath).c_str());
            return anomalies;
        }

        try {
            // Resolve the root key from path prefix.
            auto [rootHKey, subKeyPath] = ResolveRootKey(keyPath);
            const bool pathIsBare = !PathHasExplicitHive(keyPath);
            std::wstring hiveLabel = HKeyToHiveLabel(rootHKey);

            // Use RAII registry key wrapper. Scan both views (64-bit and
            // 32-bit) on the same path so attackers cannot hide under
            // WOW6432Node when the analyzer was compiled 64-bit.
            struct ViewSpec { bool wow64_64; bool wow64_32; const wchar_t* tag; };
            const ViewSpec views[] = {
                { true,  false, L"64" },
                { false, true,  L"32" },
            };

            for (const auto& view : views) {
                if (m_abortRequested.load(std::memory_order_acquire)) break;

                RegistryUtils::RegistryKey regKey;
                RegistryUtils::OpenOptions opts;
                opts.access   = KEY_READ;
                opts.wow64_64 = view.wow64_64;
                opts.wow64_32 = view.wow64_32;

                RegistryUtils::Error regErr;
                if (!regKey.Open(rootHKey, subKeyPath, opts, &regErr)) {
                    // Only fall back to HKCU when the caller supplied a BARE
                    // (no hive prefix) path AND the default HKLM open failed.
                    // Explicit fallback for explicit paths would silently
                    // misattribute and is therefore refused.
                    if (pathIsBare && rootHKey == HKEY_LOCAL_MACHINE && view.wow64_64) {
                        if (regKey.Open(HKEY_CURRENT_USER, subKeyPath, opts)) {
                            hiveLabel = L"HKCU";
                        } else {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }

                // Enumerate values using RAII key
                DWORD index = 0;
                DWORD valueNameSize;
                DWORD valueType;
                DWORD valueDataSize;

                // Heap-allocated name buffer (not stack). 32767 is the
                // registry's documented hard maximum for a value name
                // including terminator.
                constexpr DWORD VALUE_NAME_CAP = 32768;
                auto valueNameBuf = std::make_unique<wchar_t[]>(VALUE_NAME_CAP);

                while (!m_abortRequested.load(std::memory_order_acquire)) {
                    valueNameSize = VALUE_NAME_CAP;
                    // First call with NULL data to get required size
                    valueDataSize = 0;

                    LONG result = ::RegEnumValueW(regKey.Handle(), index, valueNameBuf.get(),
                                                  &valueNameSize, nullptr, &valueType,
                                                  nullptr, &valueDataSize);

                    if (result == ERROR_NO_MORE_ITEMS) {
                        break;
                    }

                    if (result != ERROR_SUCCESS && result != ERROR_MORE_DATA) {
                        index++;
                        continue;
                    }

                    // Snapshot the discovered name immediately so that even
                    // if a parallel writer changes the value between calls
                    // we can still attribute oversized-value anomalies.
                    std::wstring discoveredName(valueNameBuf.get(), valueNameSize);

                    // Cap value data to prevent DoS from oversized values
                    const DWORD cappedDataSize = std::min(
                        valueDataSize,
                        static_cast<DWORD>(RegistryAnalyzerConstants::MAX_VALUE_SIZE));

                    // Allocate exact-size buffer for the actual data
                    std::vector<uint8_t> valueData(cappedDataSize);
                    DWORD actualDataSize = cappedDataSize;
                    valueNameSize = VALUE_NAME_CAP;  // Reset for second call

                    result = ::RegEnumValueW(regKey.Handle(), index, valueNameBuf.get(),
                                             &valueNameSize, nullptr, &valueType,
                                             valueData.data(), &actualDataSize);

                    if (result != ERROR_SUCCESS) {
                        // If still overflows our cap, record oversized anomaly
                        if (result == ERROR_MORE_DATA && valueDataSize > RegistryAnalyzerConstants::MAX_VALUE_SIZE) {
                            anomalies.push_back(RecordAnomaly(
                                AnomalyType::OversizedValue,
                                AnomalySeverity::Medium,
                                hiveLabel,
                                keyPath,
                                discoveredName,
                                {},
                                std::format("Oversized value: {} bytes (capped at {})",
                                            valueDataSize, RegistryAnalyzerConstants::MAX_VALUE_SIZE)
                            ));
                        }
                        index++;
                        continue;
                    }

                    // Trim vector to actual size
                    valueData.resize(actualDataSize);
                    std::wstring valName(valueNameBuf.get(), valueNameSize);
                    std::span<const uint8_t> dataSpan(valueData);

                    // --- Value Analysis ---

                    // High entropy check
                    if (m_config.analyzeEntropy && actualDataSize >= RegistryAnalyzerConstants::MIN_BLOB_SIZE_FOR_ANALYSIS) {
                        double entropy = ::ShadowStrike::Core::Registry::CalculateEntropy(dataSpan);
                        if (entropy >= RegistryAnalyzerConstants::HIGH_ENTROPY_THRESHOLD) {
                            anomalies.push_back(RecordAnomaly(
                                AnomalyType::HighEntropy,
                                AnomalySeverity::Medium,
                                hiveLabel,
                                keyPath,
                                valName,
                                valueData,
                                std::format("High entropy value: {:.2f} ({} bytes)", entropy, actualDataSize)
                            ));
                        }
                    }

                    // Embedded executable check
                    if (m_config.detectEmbeddedExecutables && LooksLikeExecutable(dataSpan)) {
                        anomalies.push_back(RecordAnomaly(
                            AnomalyType::EmbeddedExecutable,
                            AnomalySeverity::High,
                            hiveLabel,
                            keyPath,
                            valName,
                            valueData,
                            std::format("Embedded executable detected in registry value ({} bytes)", actualDataSize)
                        ));
                        m_stats.maliciousEntries.fetch_add(1, std::memory_order_relaxed);
                    }

                    // Base64 encoding check — limited to types where a
                    // textual payload makes sense (string-like or generic
                    // BINARY blobs). REG_DWORD/QWORD/LINK never legitimately
                    // contain base64.
                    if ((valueType == REG_SZ || valueType == REG_EXPAND_SZ ||
                         valueType == REG_MULTI_SZ || valueType == REG_BINARY) &&
                        IsBase64Encoded(dataSpan)) {
                        anomalies.push_back(RecordAnomaly(
                            AnomalyType::EncodedData,
                            AnomalySeverity::Medium,
                            hiveLabel,
                            keyPath,
                            valName,
                            valueData,
                            std::format("Base64-encoded data detected ({} bytes)", actualDataSize)
                        ));
                    }

                    // String-typed value canonicalization (REG_SZ / REG_EXPAND_SZ
                    // / REG_MULTI_SZ). Decode safely and feed each component
                    // through the autorun heuristics so attackers cannot
                    // hide behind environment-variable indirection or
                    // multi-string padding.
                    if (valueType == REG_SZ || valueType == REG_EXPAND_SZ ||
                        valueType == REG_MULTI_SZ) {
                        const auto strings = DecodeRegistryStrings(valueType, dataSpan);
                        for (const auto& raw : strings) {
                            std::wstring canonical = (valueType == REG_EXPAND_SZ)
                                ? ExpandEnvironmentStringsSafe(raw) : raw;
                            if (canonical.empty()) continue;
                            AnalyzeAutorunCandidate(hiveLabel, keyPath, valName,
                                                    raw, canonical, anomalies);
                        }
                    }

                    // ThreatIntel hash reputation check
                    if (actualDataSize >= RegistryAnalyzerConstants::MIN_BLOB_SIZE_FOR_ANALYSIS) {
                        CheckValueAgainstThreatIntel(hiveLabel, keyPath, valName, valueData, anomalies);
                    }

                    m_stats.valuesAnalyzed.fetch_add(1, std::memory_order_relaxed);
                    m_stats.bytesAnalyzed.fetch_add(actualDataSize, std::memory_order_relaxed);

                    index++;
                }

                m_stats.keysAnalyzed.fetch_add(1, std::memory_order_relaxed);

                // Recursive enumeration of subkeys
                if (recursive && !m_abortRequested.load(std::memory_order_acquire)) {
                    std::vector<std::wstring> subkeyNames;
                    RegistryUtils::Error enumErr;
                    if (regKey.EnumKeys(subkeyNames, &enumErr)) {
                        for (const auto& subkeyName : subkeyNames) {
                            if (m_abortRequested.load(std::memory_order_acquire)) break;
                            // Defensively reject subkey names with embedded NULL
                            // bytes — they will be flagged separately by the
                            // cross-view path and must never be silently
                            // re-concatenated into recursion targets.
                            if (subkeyName.find(L'\0') != std::wstring::npos) continue;
                            std::wstring subkeyPath = keyPath + L"\\" + subkeyName;
                            auto subkeyAnomalies = AnalyzeKeyImpl(
                                subkeyPath, true, currentDepth + 1, effectiveMaxDepth);
                            anomalies.insert(anomalies.end(),
                                std::make_move_iterator(subkeyAnomalies.begin()),
                                std::make_move_iterator(subkeyAnomalies.end()));
                        }
                    }
                }

                // regKey closes automatically via RAII.
                // For HKCR/HKCU/HKU/HKCC there is no separate WOW64 view;
                // only scan once. The WOW64 redirection map only exists
                // under HKLM\Software and HKCU\Software.
                if (rootHKey != HKEY_LOCAL_MACHINE && rootHKey != HKEY_CURRENT_USER) {
                    break;
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: AnalyzeKey exception at %ls: %hs",
                SanitizePathForLogging(keyPath).c_str(), e.what());
        }

        return anomalies;
    }

    // ========================================================================
    // HIDDEN KEY DETECTION
    // ========================================================================

    [[nodiscard]] std::vector<std::wstring> DetectNullByteKeysImpl(const std::wstring& rootKey) {
        std::vector<std::wstring> hiddenKeys;
        std::vector<std::wstring> pendingCallbacks;  // Invoked outside m_hiddenMutex.

        try {
            SS_LOG_DEBUG(L"Registry", L"RegistryAnalyzer: Deep scanning for hidden keys in %ls",
                SanitizePathForLogging(rootKey).c_str());

            // Validate input path before conversion to defend against
            // injection through Native-form lookups.
            const std::wstring nativePath = Win32ToNativePath(rootKey);
            if (nativePath.empty()) {
                SS_LOG_WARN(L"Registry", L"RegistryAnalyzer: Rejected unsafe registry path: %ls",
                    SanitizePathForLogging(rootKey).c_str());
                return hiddenKeys;
            }
            const std::wstring hiveLabel = PathToHiveLabel(rootKey);

            UNICODE_STRING usPath;
            RtlInitUnicodeString(&usPath, nativePath.c_str());

            OBJECT_ATTRIBUTES objAttr;
            InitializeObjectAttributes(&objAttr, &usPath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

            HANDLE hKey = nullptr;
            NTSTATUS status = NtOpenKey(&hKey, KEY_READ, &objAttr);
            if (status != 0 /* STATUS_SUCCESS */) {
                return hiddenKeys;
            }

            // RAII guard for native handle
            auto handleGuard = std::unique_ptr<void, decltype(&::CloseHandle)>(hKey, &::CloseHandle);

            ULONG index = 0;
            std::vector<uint8_t> buffer(4096);
            ULONG resultLength = 0;

            while (!m_abortRequested.load(std::memory_order_acquire)) {
                status = NtEnumerateKey(hKey, index, KeyBasicInformation, buffer.data(),
                                        static_cast<ULONG>(buffer.size()), &resultLength);

                if (status == 0x80000005 /* STATUS_BUFFER_OVERFLOW */ ||
                    status == 0xC0000023 /* STATUS_BUFFER_TOO_SMALL */) {
                    // Cap buffer resize to prevent DoS
                    if (resultLength > RegistryAnalyzerConstants::MAX_NTAPI_BUFFER_SIZE) {
                        SS_LOG_WARN(L"Registry", L"RegistryAnalyzer: NtEnumerateKey requested %lu bytes, exceeds cap; skipping index %lu",
                            resultLength, index);
                        index++;
                        continue;
                    }
                    // Resize and retry at the SAME index. Do not advance: the
                    // entry we want still lives at the current index.
                    buffer.resize(resultLength);
                    continue;
                }

                if (status != 0 /* STATUS_SUCCESS */) {
                    break;
                }

                auto* pInfo = reinterpret_cast<PKEY_BASIC_INFORMATION>(buffer.data());

                // Validate NameLength to prevent out-of-bounds read.
                // NameLength is in BYTES; the flex array starts at offsetof(Name).
                const size_t maxName = buffer.size() - offsetof(KEY_BASIC_INFORMATION, Name);
                if (pInfo->NameLength > maxName || (pInfo->NameLength % sizeof(WCHAR)) != 0) {
                    SS_LOG_WARN(L"Registry", L"RegistryAnalyzer: Malformed NameLength %lu at index %lu",
                        pInfo->NameLength, index);
                    index++;
                    continue;
                }

                std::wstring keyName(pInfo->Name, pInfo->NameLength / sizeof(WCHAR));

                // Detect NULL-byte injection (RegHider technique). Any embedded
                // NULL prior to the final character is a strong rootkit
                // indicator because the Win32 ANSI/Unicode APIs terminate on
                // the first NULL while the kernel preserves the full name.
                bool isHidden = false;
                if (!keyName.empty()) {
                    for (size_t i = 0; i + 1 < keyName.length(); ++i) {
                        if (keyName[i] == L'\0') { isHidden = true; break; }
                    }
                }

                if (isHidden || HasControlCharacters(keyName)) {
                    std::wstring fullPath = rootKey + L"\\" + keyName;
                    hiddenKeys.push_back(fullPath);

                    {
                        std::unique_lock lock(m_hiddenMutex);
                        m_hiddenKeys.insert(fullPath);
                    }
                    m_stats.hiddenKeysFound.fetch_add(1, std::memory_order_relaxed);

                    SS_LOG_FATAL(L"Registry", L"RegistryAnalyzer: HIDDEN KEY DETECTED: %ls",
                        SanitizePathForLogging(fullPath).c_str());

                    RecordAnomaly(AnomalyType::APIHiddenKey, AnomalySeverity::Critical,
                        hiveLabel, rootKey, SanitizePathForLogging(keyName), {},
                        "Registry key hidden using NULL-byte or control character injection");

                    // Defer external callbacks until after the loop so that
                    // a callback re-entering the analyzer cannot deadlock
                    // against m_hiddenMutex held above.
                    pendingCallbacks.push_back(std::move(fullPath));
                }

                index++;
            }

            // handleGuard automatically closes hKey

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: DetectNullByteKeys exception: %hs", e.what());
        }

        // Fire hidden-entry callbacks while holding no internal locks.
        for (const auto& path : pendingCallbacks) {
            InvokeHiddenCallbacks(path, true);
        }

        return hiddenKeys;
    }

    [[nodiscard]] CrossViewResult PerformCrossViewDetectionImpl(const std::wstring& keyPath) {
        CrossViewResult result{};
        result.keyPath = keyPath;

        try {
            SS_LOG_DEBUG(L"Registry", L"RegistryAnalyzer: Performing Cross-View Analysis for %ls",
                SanitizePathForLogging(keyPath).c_str());

            // Honor the hive root encoded in the caller's path (HKLM, HKCU,
            // HKU, HKCR, HKCC). The previous implementation hardcoded HKLM
            // and silently mis-attributed every cross-view comparison
            // against the wrong hive when invoked for HKCU/HKU.
            auto [rootHKey, subKey] = ResolveRootKey(keyPath);
            const std::wstring hiveLabel = HKeyToHiveLabel(rootHKey);

            // 1. Get keys via Win32 API (View A) — uses RAII wrapper
            {
                RegistryUtils::RegistryKey apiKey;
                RegistryUtils::OpenOptions opts;
                opts.access = KEY_READ;
                opts.wow64_64 = true;

                if (apiKey.Open(rootHKey, subKey, opts)) {
                    result.foundViaAPI = true;
                    std::vector<std::wstring> subkeys;
                    if (apiKey.EnumKeys(subkeys)) {
                        result.apiSubKeys = std::move(subkeys);
                    }
                }
            }

            // 2. Get keys via Native API (View B)
            const std::wstring nativePath = Win32ToNativePath(keyPath);
            if (nativePath.empty()) {
                SS_LOG_WARN(L"Registry", L"RegistryAnalyzer: Cross-view rejected unsafe path %ls",
                    SanitizePathForLogging(keyPath).c_str());
                return result;
            }
            UNICODE_STRING usPath;
            RtlInitUnicodeString(&usPath, nativePath.c_str());
            OBJECT_ATTRIBUTES objAttr;
            InitializeObjectAttributes(&objAttr, &usPath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

            HANDLE hNativeKey = nullptr;
            if (NtOpenKey(&hNativeKey, KEY_READ, &objAttr) == 0 /* STATUS_SUCCESS */) {
                auto handleGuard = std::unique_ptr<void, decltype(&::CloseHandle)>(hNativeKey, &::CloseHandle);

                result.foundViaRaw = true;
                ULONG index = 0;
                std::vector<uint8_t> buffer(4096);
                ULONG resLen = 0;

                while (!m_abortRequested.load(std::memory_order_acquire)) {
                    NTSTATUS status = NtEnumerateKey(hNativeKey, index, KeyBasicInformation,
                                                   buffer.data(), static_cast<ULONG>(buffer.size()), &resLen);
                    if (status == 0x80000005 || status == 0xC0000023 /* BUFFER_TOO_SMALL */) {
                        if (resLen > RegistryAnalyzerConstants::MAX_NTAPI_BUFFER_SIZE) {
                            // Pathologically large entry: skip and continue.
                            index++;
                            continue;
                        }
                        // Resize and retry at the same index (do NOT advance).
                        buffer.resize(resLen);
                        continue;
                    }
                    if (status != 0) break;

                    auto* pInfo = reinterpret_cast<PKEY_BASIC_INFORMATION>(buffer.data());
                    const size_t maxName = buffer.size() - offsetof(KEY_BASIC_INFORMATION, Name);
                    if (pInfo->NameLength <= maxName && (pInfo->NameLength % sizeof(WCHAR)) == 0) {
                        result.rawSubKeys.emplace_back(pInfo->Name, pInfo->NameLength / sizeof(WCHAR));
                    }
                    index++;
                }
                // handleGuard closes automatically
            }

            // 3. Compare View A and View B — case-insensitive (registry is case-insensitive)
            std::unordered_set<std::wstring> apiSetLower;
            apiSetLower.reserve(result.apiSubKeys.size());
            for (const auto& key : result.apiSubKeys) {
                std::wstring lower = key;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
                apiSetLower.insert(std::move(lower));
            }

            for (const auto& rawKey : result.rawSubKeys) {
                std::wstring lowerRaw = rawKey;
                std::transform(lowerRaw.begin(), lowerRaw.end(), lowerRaw.begin(), ::towlower);
                if (apiSetLower.find(lowerRaw) == apiSetLower.end()) {
                    result.hiddenSubKeys.push_back(rawKey);
                    result.hasDiscrepancy = true;
                }
            }

            if (result.hasDiscrepancy) {
                m_stats.rootkitIndicators.fetch_add(1, std::memory_order_relaxed);
                SS_LOG_FATAL(L"Registry", L"RegistryAnalyzer: ROOTKIT DISCREPANCY detected in %ls - %zu hidden keys",
                    SanitizePathForLogging(keyPath).c_str(), result.hiddenSubKeys.size());

                for (const auto& hidden : result.hiddenSubKeys) {
                    RecordAnomaly(AnomalyType::APIHiddenKey, AnomalySeverity::Critical,
                        hiveLabel, keyPath, SanitizePathForLogging(hidden), {},
                        "Key found via NTAPI but hidden from Win32 API (Rootkit indicator)");
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Cross-view detection exception: %hs", e.what());
        }

        return result;
    }

    // ========================================================================
    // HIVE PARSING
    // ========================================================================

    [[nodiscard]] HiveHeader ParseHiveHeaderImpl(const std::wstring& hivePath) {
        HiveHeader header{};

        try {
            std::error_code ec;
            const auto fileSize = fs::file_size(fs::path(hivePath), ec);
            if (ec || fileSize < 0x1000) {
                SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Hive file missing or too small: %ls",
                    SanitizePathForLogging(hivePath).c_str());
                return header;
            }

            std::ifstream file(hivePath, std::ios::binary);
            if (!file) {
                SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Failed to open hive file: %ls",
                    SanitizePathForLogging(hivePath).c_str());
                return header;
            }

            auto readField = [&](void* dst, std::streamsize n) -> bool {
                file.read(static_cast<char*>(dst), n);
                return file.gcount() == n;
            };

            // Read signature
            if (!readField(&header.signature, sizeof(header.signature))) return header;

            // Validate signature
            if (header.signature != RegistryAnalyzerConstants::HIVE_SIGNATURE) {
                SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Invalid hive signature: 0x%08X", header.signature);
                header.isCorrupted = true;
                return header;
            }

            // Read sequence numbers
            if (!readField(&header.sequence1, sizeof(header.sequence1))) return header;
            if (!readField(&header.sequence2, sizeof(header.sequence2))) return header;

            if (header.sequence1 != header.sequence2) {
                SS_LOG_WARN(L"Registry", L"RegistryAnalyzer: Sequence mismatch - hive may be dirty");
                header.isDirty = true;
            }

            // Read timestamp (offset 0x0C)
            file.seekg(0x0C);
            uint64_t timestamp = 0;
            if (!readField(&timestamp, sizeof(timestamp))) return header;

            constexpr int64_t FILETIME_EPOCH_OFFSET_SEC = 11644473600LL;
            if (timestamp > 0) {
                auto windowsDuration = std::chrono::duration<int64_t, std::ratio<1, 10000000>>(
                    static_cast<int64_t>(timestamp));
                auto unixDuration = windowsDuration - std::chrono::seconds(FILETIME_EPOCH_OFFSET_SEC);
                header.lastWritten = std::chrono::system_clock::time_point(
                    std::chrono::duration_cast<std::chrono::system_clock::duration>(unixDuration));
            }

            // Read version (offset 0x14)
            file.seekg(0x14);
            if (!readField(&header.majorVersion, sizeof(header.majorVersion))) return header;
            if (!readField(&header.minorVersion, sizeof(header.minorVersion))) return header;
            if (!readField(&header.hiveType,     sizeof(header.hiveType)))     return header;

            // Read root cell offset (offset 0x24) and data length (offset 0x28)
            file.seekg(0x24);
            if (!readField(&header.rootCellOffset, sizeof(header.rootCellOffset))) return header;
            if (!readField(&header.dataLength,     sizeof(header.dataLength)))     return header;

            // Defensive: dataLength must not promise more bytes than the
            // file actually contains. A hostile hive could specify a huge
            // dataLength to coerce downstream loops into reading past EOF.
            if (static_cast<uint64_t>(header.dataLength) + 0x1000ULL > fileSize) {
                SS_LOG_WARN(L"Registry", L"RegistryAnalyzer: Hive dataLength %u exceeds file size; clamping",
                    header.dataLength);
                header.dataLength = static_cast<uint32_t>(fileSize - 0x1000);
                header.isDirty = true;
            }

            header.isValid = true;

            SS_LOG_INFO(L"Registry", L"RegistryAnalyzer: Hive header parsed - Version: %u.%u, Root: 0x%08X",
                header.majorVersion, header.minorVersion, header.rootCellOffset);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Hive header parse exception: %hs", e.what());
            header.isCorrupted = true;
        }

        return header;
    }

    [[nodiscard]] bool ValidateHiveStructureImpl(const std::wstring& hivePath) {
        try {
            auto header = ParseHiveHeaderImpl(hivePath);

            if (!header.isValid) {
                SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Invalid hive header");
                return false;
            }

            if (header.isCorrupted) {
                SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Corrupted hive structure");
                return false;
            }

            // Additional validation would check hbin structures, offsets, etc.

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Hive validation exception: %hs", e.what());
            return false;
        }
    }

    // ========================================================================
    // THREAT HUNTING
    // ========================================================================

    size_t LoadThreatIndicatorsImpl(const std::wstring& indicatorsPath) {
        try {
            std::unique_lock lock(m_indicatorMutex);

            // Reject pathologically large indicator files outright. A
            // multi-gigabyte file would otherwise force an O(n^2) load
            // against the in-process indicator vector and exhaust memory.
            std::error_code ec;
            const auto fileSize = fs::file_size(fs::path(indicatorsPath), ec);
            if (!ec && fileSize > RegistryAnalyzerConstants::MAX_INDICATOR_FILE_SIZE) {
                SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Indicator file too large (%llu bytes) - refusing to load",
                    static_cast<unsigned long long>(fileSize));
                return 0;
            }

            std::ifstream file(indicatorsPath);
            if (!file) {
                SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Failed to open indicators file: %ls",
                    SanitizePathForLogging(indicatorsPath).c_str());
                return 0;
            }

            // Parse line-delimited indicator file.
            // Format: keyPattern|valuePattern|threatName|malwareFamily|mitreId
            size_t loaded = 0;
            std::string line;
            while (std::getline(file, line)) {
                if (line.empty() || line[0] == '#') continue;  // Skip comments/empty
                if (line.size() > 4096) {
                    SS_LOG_WARN(L"Registry", L"RegistryAnalyzer: Skipping oversized indicator line (%zu bytes)",
                        line.size());
                    continue;
                }

                std::istringstream iss(line);
                std::string keyPat, valPat, threat, family, mitre;
                if (!std::getline(iss, keyPat, '|')) continue;
                std::getline(iss, valPat, '|');
                std::getline(iss, threat, '|');
                std::getline(iss, family, '|');
                std::getline(iss, mitre, '|');

                ThreatIndicator indicator;
                indicator.keyPattern = StringUtils::ToWide(keyPat);
                indicator.valuePattern = StringUtils::ToWide(valPat);
                indicator.threatName = threat;
                indicator.malwareFamily = family;
                indicator.mitreId = mitre.empty() ? "T1112" : mitre;

                // Heuristic regex detection: the literal characters that
                // signal regex metacharacters in our format. Backslash is
                // INTENTIONALLY excluded because registry paths contain
                // backslashes natively and would otherwise force every
                // indicator to be compiled as a regex.
                indicator.isRegex = (keyPat.find_first_of(".*+?[](){}^$") != std::string::npos);

                // Pre-validate (compile-and-discard) regex patterns at
                // load time so malformed indicators are surfaced eagerly
                // instead of silently dropped on every search invocation.
                if (indicator.isRegex) {
                    try {
                        std::wregex test(indicator.keyPattern,
                            std::regex_constants::icase |
                            std::regex_constants::nosubs |
                            std::regex_constants::optimize);
                        (void)test;
                    } catch (const std::regex_error& re) {
                        SS_LOG_WARN(L"Registry",
                            L"RegistryAnalyzer: Dropping malformed regex indicator '%hs' (%hs)",
                            keyPat.c_str(), re.what());
                        continue;
                    }
                }

                m_indicators.push_back(std::move(indicator));
                loaded++;

                constexpr size_t MAX_INDICATORS = 50000;
                if (loaded >= MAX_INDICATORS) {
                    SS_LOG_WARN(L"Registry", L"RegistryAnalyzer: Indicator cap reached (%zu)", MAX_INDICATORS);
                    break;
                }
            }

            SS_LOG_INFO(L"Registry", L"RegistryAnalyzer: Loaded %zu threat indicators from %ls",
                loaded, SanitizePathForLogging(indicatorsPath).c_str());

            return m_indicators.size();

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Load indicators exception: %hs", e.what());
            return 0;
        }
    }

    [[nodiscard]] std::vector<RegistryAnomaly> SearchIOCsImpl(const std::vector<std::wstring>& iocs) {
        std::vector<RegistryAnomaly> matches;

        try {
            std::shared_lock lock(m_indicatorMutex);
            std::shared_lock anomalyLock(m_anomalyMutex);

            // Build a case-insensitive set of literal IOC substrings provided
            // by the caller. This is folded into the match alongside the
            // persistent indicator list.
            std::vector<std::wstring> iocLower;
            iocLower.reserve(iocs.size());
            for (const auto& ioc : iocs) {
                if (!ioc.empty()) iocLower.push_back(ToLowerAscii(ioc));
            }

            for (const auto& anomaly : m_anomalies) {
                const std::wstring keyLower  = ToLowerAscii(anomaly.keyPath);
                const std::wstring nameLower = ToLowerAscii(anomaly.valueName);

                bool matched = false;

                // Caller-supplied IOC literals.
                for (const auto& needle : iocLower) {
                    if (keyLower.find(needle) != std::wstring::npos ||
                        nameLower.find(needle) != std::wstring::npos) {
                        matched = true;
                        break;
                    }
                }

                // Persistent indicator list.
                if (!matched) {
                    for (const auto& indicator : m_indicators) {
                        if (MatchesIndicator(anomaly, indicator)) {
                            matched = true;
                            break;
                        }
                    }
                }

                if (matched) {
                    matches.push_back(anomaly);
                    m_stats.iocsMatched.fetch_add(1, std::memory_order_relaxed);
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: IOC search exception: %hs", e.what());
        }

        return matches;
    }

    [[nodiscard]] bool MatchesIndicator(
        const RegistryAnomaly& anomaly,
        const ThreatIndicator& indicator
    ) const noexcept {
        try {
            if (!indicator.keyPattern.empty()) {
                if (indicator.isRegex) {
                    std::wregex rx(indicator.keyPattern,
                        std::regex_constants::icase |
                        std::regex_constants::nosubs |
                        std::regex_constants::optimize);
                    if (!std::regex_search(anomaly.keyPath, rx)) {
                        return false;
                    }
                } else {
                    // Case-insensitive substring match
                    std::wstring lowerPath = ToLowerAscii(anomaly.keyPath);
                    std::wstring lowerPat  = ToLowerAscii(indicator.keyPattern);
                    if (lowerPath.find(lowerPat) == std::wstring::npos) {
                        return false;
                    }
                }
            }

            if (!indicator.valuePattern.empty()) {
                std::wstring lowerVal = ToLowerAscii(anomaly.valueName);
                std::wstring lowerPat = ToLowerAscii(indicator.valuePattern);
                if (lowerVal.find(lowerPat) == std::wstring::npos) {
                    return false;
                }
            }

            // Binary data pattern match
            if (!indicator.dataPattern.empty() && !anomaly.rawData.empty()) {
                auto it = std::search(anomaly.rawData.begin(), anomaly.rawData.end(),
                                      indicator.dataPattern.begin(), indicator.dataPattern.end());
                if (it == anomaly.rawData.end()) {
                    return false;
                }
            }

            return true;
        } catch (const std::regex_error&) {
            // Malformed regex in indicator — treat as no match
            return false;
        } catch (...) {
            return false;
        }
    }

    // ========================================================================
    // ANOMALY RECORDING
    // ========================================================================

    /**
     * @brief Direct Kernel Object Manipulation detection.
     *
     * Queries the RegistryMonitor for kernel-side integrity data.
     * If RegistryMonitor reports CmCallback list tampering or handle table
     * mismatches, we flag DKOM evidence.
     */
    [[nodiscard]] bool DetectDKOMImpl() {
        try {
            auto& regMon = ShadowStrike::Core::Registry::RegistryMonitor::Instance();
            if (!regMon.IsKernelConnected()) {
                // Not an error condition: the registry feed is simply not up.
                // Demoted from WARN because it would otherwise be printed on
                // every rootkit scan for a state that is normal before start.
                SS_LOG_DEBUG(L"Registry",
                    L"RegistryAnalyzer: DKOM detection needs the kernel registry feed, not connected yet");
                return false;
            }

            auto recentEvents = regMon.GetRecentEvents(50);
            if (recentEvents.empty()) {
                return false;
            }

            // ================================================================
            // CORROBORATED AGAINST THE OS, NOT AGAINST OUR OWN CACHE
            // ================================================================
            // This detector used to conclude DKOM from one fact: the PID that
            // performed a registry operation was absent from ProcessMonitor.
            // That is unsound, and one direction of it was about to become
            // catastrophic.
            //
            // ProcessMonitor IS NOT INITIALIZED IN PRODUCTION - nothing outside
            // tests calls ProcessMonitor::Initialize (tracked as task 130). Its
            // table is therefore empty and GetProcessInfo returns nullopt for
            // EVERY pid. Registry events arrive in real time, so the five-second
            // recency filter below is satisfied by essentially every event. The
            // moment the registry feed went live, this function would have raised
            // a CRITICAL DKOM anomaly for the first registry write performed by
            // any ordinary process on the machine.
            //
            // AN EMPTY CACHE IS SILENCE, NOT EVIDENCE. Absence of a record in a
            // store that was never populated carries no information, and reading
            // it as an indicator is how a detector becomes a random number
            // generator.
            //
            // The replacement is an actual DKOM signature rather than a proxy
            // for one. A process hidden by direct kernel object manipulation is
            // unlinked from the ActiveProcessLinks list that process enumeration
            // walks, but its PspCidTable entry survives, so the kernel still
            // resolves the PID directly. The discrepancy between "absent from
            // enumeration" and "still resolvable" IS the tell, and it needs no
            // help from our own bookkeeping.
            std::vector<ProcessUtils::ProcessId> livePids;
            if (!ProcessUtils::EnumerateProcesses(livePids)) {
                // Cannot corroborate, so do not guess. A detector that reports
                // on evidence it could not gather is worse than one that stays
                // quiet and says why.
                SS_LOG_WARN(L"Registry",
                    L"RegistryAnalyzer: DKOM check skipped, process enumeration failed");
                return false;
            }
            const std::unordered_set<ProcessUtils::ProcessId> enumerated(
                livePids.begin(), livePids.end());

            auto& procMon = ShadowStrike::Core::Process::ProcessMonitor::Instance();
            const bool procMonUsable = procMon.IsInitialized();

            for (const auto& event : recentEvents) {
                if (event.processId == 0 || event.processId == 4) continue;  // Idle / System

                // Cheap acquittal: our own tracker recognises the process. Only
                // consulted when it is actually initialized, precisely so an
                // empty tracker cannot contribute a signal.
                if (procMonUsable &&
                    procMon.GetProcessInfo(event.processId).has_value()) {
                    continue;
                }

                // AGE BOUND, WITH ITS REAL JUSTIFICATION. Windows recycles PIDs,
                // so an old event's PID may already belong to a different
                // process and every check below would be evaluating the wrong
                // one. The bound keeps the correlation SOUND. It is not a
                // false-positive suppressor - that is what the corroboration
                // below is for, and conflating the two is what hid the defect.
                const auto now = std::chrono::system_clock::now();
                const auto age = std::chrono::duration_cast<std::chrono::seconds>(
                    now - event.timestamp);
                if (age.count() < 0 || age.count() > 5) continue;

                // Listed by the OS: an ordinary process, nothing hidden.
                if (enumerated.contains(event.processId)) continue;

                // Not listed. Either it exited between the event and this check,
                // or it is unlinked from the list while still alive.
                if (!ProcessUtils::IsProcessRunning(event.processId)) {
                    continue;  // exited - the benign short-lived case
                }

                // Absent from enumeration, still resolvable by the kernel, and
                // it performed a registry operation seconds ago. Hidden process.
                RecordAnomaly(AnomalyType::DKOMEvidence, AnomalySeverity::Critical,
                    L"KERNEL", event.keyPath, event.valueName, {},
                    std::format("Registry operation from PID {} that is absent from process "
                                "enumeration but still resolvable by the kernel (age {}s) - "
                                "hidden process, possible DKOM",
                                event.processId, age.count()));
                m_stats.rootkitIndicators.fetch_add(1, std::memory_order_relaxed);
                return true;
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: DKOM detection exception: %hs", e.what());
        }
        return false;
    }

    /**
     * @brief Inspect a string-typed registry value for autorun / ASEP abuse.
     *
     * Recognized patterns include:
     *  - Image File Execution Options "Debugger" / "GlobalFlag" hijack
     *    (MITRE T1546.012).
     *  - AppInit_DLLs / AppCertDlls injection (MITRE T1546.010 / T1546.009).
     *  - Winlogon Notify, Userinit, Shell, TaskMan hijack (T1547.004).
     *  - LSA Notification packages / Security packages (T1556.002).
     *  - PendingFileRenameOperations boot-time replacement.
     *  - Run / RunOnce / Services / ServicesActive autoruns with
     *    suspicious payload paths (UNC, ProgramData, Public, Temp, AppData
     *    roots, or unsigned PowerShell one-liners).
     *
     * The function emits AnomalySeverity::High by default, and
     * AnomalySeverity::Critical for IFEO debugger and LSA package
     * substitution which are reliable signals of post-compromise activity.
     */
    void AnalyzeAutorunCandidate(
        const std::wstring& hiveLabel,
        const std::wstring& keyPath,
        const std::wstring& valueName,
        const std::wstring& rawValue,
        const std::wstring& canonicalValue,
        std::vector<RegistryAnomaly>& anomalies
    ) {
        if (canonicalValue.empty()) return;

        const std::wstring keyLower   = ToLowerAscii(keyPath);
        const std::wstring nameLower  = ToLowerAscii(valueName);
        const std::wstring valueLower = ToLowerAscii(canonicalValue);

        auto contains = [](const std::wstring& hay, std::wstring_view needle) noexcept {
            return hay.find(needle) != std::wstring::npos;
        };

        auto record = [&](AnomalySeverity sev, const std::string& desc) {
            // Store the canonical form so analysts see the resolved path,
            // but keep raw bytes (capped) as evidence.
            std::vector<uint8_t> evidence(reinterpret_cast<const uint8_t*>(rawValue.data()),
                                          reinterpret_cast<const uint8_t*>(rawValue.data())
                                              + std::min<size_t>(rawValue.size() * sizeof(wchar_t),
                                                                 RegistryAnalyzerConstants::MAX_ANOMALY_RAW_DATA_BYTES));
            anomalies.push_back(RecordAnomaly(
                AnomalyType::SuspiciousAutorun, sev, hiveLabel, keyPath, valueName,
                std::move(evidence), desc));
        };

        // 1. IFEO Debugger / GlobalFlag hijack.
        if (contains(keyLower, L"\\image file execution options\\")) {
            if (nameLower == L"debugger") {
                record(AnomalySeverity::Critical,
                    "IFEO Debugger value present (MITRE T1546.012). Subkey name is the image being hijacked.");
                return;
            }
            if (nameLower == L"globalflag" || nameLower == L"reportingmode" ||
                nameLower == L"monitorprocess") {
                record(AnomalySeverity::High,
                    "IFEO Silent Process Exit / GlobalFlag instrumentation (MITRE T1546.012).");
                return;
            }
        }

        // 2. AppInit_DLLs / AppCertDlls.
        if (nameLower == L"appinit_dlls" && !canonicalValue.empty()) {
            record(AnomalySeverity::Critical,
                "AppInit_DLLs entry present (MITRE T1546.010). Loads into every user32-linked process.");
            return;
        }
        if (contains(keyLower, L"\\session manager\\appcertdlls")) {
            record(AnomalySeverity::Critical,
                "AppCertDlls entry present (MITRE T1546.009). Loads into every process that calls Create*Process.");
            return;
        }

        // 3. Winlogon hijack values.
        if (contains(keyLower, L"\\winlogon")) {
            if (nameLower == L"userinit" || nameLower == L"shell" || nameLower == L"taskman") {
                // Userinit is normally userinit.exe; Shell is normally explorer.exe.
                const bool userinitOk = (nameLower == L"userinit") &&
                                        contains(valueLower, L"userinit.exe");
                const bool shellOk = (nameLower == L"shell") &&
                                     (valueLower == L"explorer.exe" || contains(valueLower, L"\\explorer.exe"));
                if (!userinitOk && !shellOk) {
                    record(AnomalySeverity::Critical,
                        "Winlogon hijack candidate (MITRE T1547.004): non-default value for system shell/userinit/taskman.");
                    return;
                }
            }
            if (contains(keyLower, L"\\notify\\")) {
                record(AnomalySeverity::High,
                    "Winlogon Notify package detected (deprecated mechanism, persistence indicator).");
                return;
            }
        }

        // 4. LSA notification / security packages.
        if (contains(keyLower, L"\\control\\lsa")) {
            if (nameLower == L"notification packages" || nameLower == L"security packages" ||
                nameLower == L"authentication packages") {
                record(AnomalySeverity::Critical,
                    "LSA package list modification (MITRE T1556.002 / T1547.002). Inspect for non-Microsoft DLLs.");
                return;
            }
        }

        // 5. PendingFileRenameOperations — boot-time file replacement.
        if (nameLower == L"pendingfilerenameoperations") {
            record(AnomalySeverity::High,
                "PendingFileRenameOperations entry (boot-time file replacement; abused for tamper).");
            return;
        }

        // 6. Run / RunOnce / Services payload heuristics.
        const bool isRunKey = contains(keyLower, L"\\currentversion\\run") ||
                              contains(keyLower, L"\\currentversion\\runonce") ||
                              contains(keyLower, L"\\currentversion\\runservices") ||
                              contains(keyLower, L"\\currentversion\\runservicesonce");
        const bool isServiceKey = contains(keyLower, L"\\services\\");

        if (isRunKey || isServiceKey) {
            // Payload location heuristics.
            const bool fromTempLike =
                contains(valueLower, L"\\appdata\\local\\temp\\") ||
                contains(valueLower, L"\\windows\\temp\\") ||
                contains(valueLower, L"\\users\\public\\") ||
                contains(valueLower, L"\\programdata\\") ||
                contains(valueLower, L"\\$recycle.bin\\");
            const bool isUnc = valueLower.starts_with(L"\\\\");
            const bool encodedPs =
                (contains(valueLower, L"powershell") &&
                 (contains(valueLower, L"-enc") || contains(valueLower, L"-encodedcommand") ||
                  contains(valueLower, L"frombase64string") || contains(valueLower, L"hidden")));
            const bool wmicAbuse = contains(valueLower, L"wmic ") && contains(valueLower, L"process call create");
            const bool regsvr32Squiblydoo = contains(valueLower, L"regsvr32") &&
                                            (contains(valueLower, L"http://") || contains(valueLower, L"https://"));
            const bool mshtaWeb = contains(valueLower, L"mshta") &&
                                  (contains(valueLower, L"http://") || contains(valueLower, L"https://") ||
                                   contains(valueLower, L"javascript:"));
            const bool rundll32JsVbs = contains(valueLower, L"rundll32") &&
                                       (contains(valueLower, L"javascript:") || contains(valueLower, L"vbscript:"));
            const bool fromUserHive = (hiveLabel == L"HKCU" || hiveLabel == L"HKU");
            const bool runFromUser  = isRunKey && fromUserHive;

            if (fromTempLike || isUnc || encodedPs || wmicAbuse ||
                regsvr32Squiblydoo || mshtaWeb || rundll32JsVbs) {
                record(AnomalySeverity::High,
                    std::format("Autorun/service entry with suspicious payload (MITRE {})",
                                isServiceKey ? "T1543.003" : "T1547.001"));
                return;
            }
            if (runFromUser && contains(valueLower, L".exe")) {
                // Lower-confidence: per-user Run key pointing at an exe.
                // Down-rate to Medium so SOC noise stays manageable.
                std::vector<uint8_t> evidence(reinterpret_cast<const uint8_t*>(rawValue.data()),
                                              reinterpret_cast<const uint8_t*>(rawValue.data())
                                                  + std::min<size_t>(rawValue.size() * sizeof(wchar_t),
                                                                     RegistryAnalyzerConstants::MAX_ANOMALY_RAW_DATA_BYTES));
                anomalies.push_back(RecordAnomaly(
                    AnomalyType::SuspiciousAutorun, AnomalySeverity::Medium,
                    hiveLabel, keyPath, valueName, std::move(evidence),
                    "Per-user Run-key autostart entry (MITRE T1547.001) - triage payload provenance"));
                return;
            }
        }

        // 7. ServiceDll / ImagePath hijacking under \\Services.
        if (isServiceKey &&
            (nameLower == L"servicedll" || nameLower == L"imagepath")) {
            if (contains(valueLower, L"\\appdata\\") ||
                contains(valueLower, L"\\users\\public\\") ||
                contains(valueLower, L"\\programdata\\") ||
                valueLower.starts_with(L"\\\\")) {
                record(AnomalySeverity::Critical,
                    "Service ImagePath/ServiceDll resolves into a user-writable location (MITRE T1543.003).");
                return;
            }
        }
    }

    /**
     * @brief Check a registry value's hash against ThreatIntelManager.
     */
    void CheckValueAgainstThreatIntel(
        const std::wstring& hiveLabel,
        const std::wstring& keyPath,
        const std::wstring& valueName,
        const std::vector<uint8_t>& data,
        std::vector<RegistryAnomaly>& anomalies
    ) {
        try {
            auto& threatIntel = ShadowStrike::ThreatIntel::ThreatIntelManager::Instance();
            if (!threatIntel.IsInitialized()) return;

            // Hash the value data
            std::vector<uint8_t> hashResult;
            if (!HashUtils::Compute(HashUtils::Algorithm::SHA256,
                                     data.data(), data.size(), hashResult)) {
                return;
            }

            std::string hexHash = HashUtils::ToHexLower(hashResult);

            double riskScore = 0.0;
            std::string threatName;
            if (threatIntel.IsKnownMalicious(hexHash, riskScore, threatName)) {
                anomalies.push_back(RecordAnomaly(
                    AnomalyType::KnownMalwareValue,
                    AnomalySeverity::Critical,
                    hiveLabel,
                    keyPath,
                    valueName,
                    data,
                    std::format("Known malicious value - SHA256: {} (score: {:.0f})",
                                hexHash.substr(0, 16) + "...", riskScore)
                ));
                m_stats.maliciousEntries.fetch_add(1, std::memory_order_relaxed);
                // Note: iocsMatched is intentionally NOT incremented here.
                // That counter tracks indicator-list matches; the
                // ThreatIntelManager path is a separate signal accounted
                // for by maliciousEntries.
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: ThreatIntel check exception: %hs", e.what());
        }
    }

    /**
     * @brief Parse a raw cell from the hive.
     */
    template<typename T>
    [[nodiscard]] std::optional<T> ParseCell(std::ifstream& file, uint32_t offset) {
        if (offset == 0xFFFFFFFF) return std::nullopt;

        // Offsets in registry hives are relative to the first hbin (0x1000)
        // and are always 4-byte aligned.
        uint64_t absoluteOffset = static_cast<uint64_t>(offset) + 0x1000;

        file.seekg(absoluteOffset);
        int32_t cellSize;
        file.read(reinterpret_cast<char*>(&cellSize), sizeof(cellSize));

        if (file.gcount() != sizeof(cellSize)) return std::nullopt;

        // Cell size is negative if allocated, positive if free
        // The size includes the 4-byte size header itself
        uint32_t actualSize = std::abs(cellSize);
        if (actualSize < sizeof(T) + 4) return std::nullopt;

        T cellData;
        file.read(reinterpret_cast<char*>(&cellData), sizeof(T));
        if (file.gcount() != sizeof(T)) return std::nullopt;

        return cellData;
    }

    /**
     * @brief Recover deleted entries by scanning hbin slack space.
     */
    [[nodiscard]] std::vector<DeletedEntry> RecoverDeletedEntriesImpl(const std::wstring& hivePath) {
        std::vector<DeletedEntry> recovered;

        try {
            std::error_code ec;
            const auto fileSize = fs::file_size(fs::path(hivePath), ec);
            if (ec || fileSize < 0x2000) return recovered;

            std::ifstream file(hivePath, std::ios::binary);
            if (!file) return recovered;

            auto header = ParseHiveHeaderImpl(hivePath);
            if (!header.isValid) return recovered;

            // Cap recovery iteration so a malformed hive cannot turn this
            // into an unbounded loop. Real hives have well under 100k hbins.
            constexpr uint32_t MAX_HBINS = 65536;
            uint32_t hbinCount = 0;

            // Cap total recovered entries so per-hive memory growth is bounded.
            constexpr size_t MAX_RECOVERED_ENTRIES = 100000;

            // Scan all hbin segments
            uint32_t currentOffset = 0;
            while (currentOffset < header.dataLength && hbinCount++ < MAX_HBINS &&
                   recovered.size() < MAX_RECOVERED_ENTRIES) {
                if (static_cast<uint64_t>(currentOffset) + 0x1000ULL >= fileSize) break;
                file.seekg(0x1000 + currentOffset);

                uint32_t signature = 0;
                file.read(reinterpret_cast<char*>(&signature), sizeof(signature));
                if (file.gcount() != sizeof(signature)) break;
                if (signature != RegistryAnalyzerConstants::HBIN_SIGNATURE) break;

                uint32_t hbinSize = 0;
                file.seekg(0x1000 + currentOffset + 0x08);
                file.read(reinterpret_cast<char*>(&hbinSize), sizeof(hbinSize));
                if (file.gcount() != sizeof(hbinSize)) break;
                // An hbin is always at least 0x1000 bytes and aligned to 0x1000.
                if (hbinSize < 0x1000 || (hbinSize & 0xFFF) != 0) break;
                if (static_cast<uint64_t>(currentOffset) + hbinSize > header.dataLength) break;

                // Scan cells within this hbin
                uint32_t cellOffset = 0x20; // Skip hbin header
                while (cellOffset + sizeof(int32_t) <= hbinSize) {
                    if (m_abortRequested.load(std::memory_order_acquire)) return recovered;

                    file.seekg(0x1000 + currentOffset + cellOffset);
                    int32_t cellSize = 0;
                    file.read(reinterpret_cast<char*>(&cellSize), sizeof(cellSize));
                    if (file.gcount() != sizeof(cellSize)) break;

                    // Guard against INT32_MIN abuse and pathological sizes.
                    const int64_t signedAbs = (cellSize == std::numeric_limits<int32_t>::min())
                        ? static_cast<int64_t>(std::numeric_limits<int32_t>::max())
                        : std::abs(static_cast<int64_t>(cellSize));
                    if (signedAbs < 8 || (signedAbs & 0x7) != 0) break;
                    const uint32_t absCellSize = static_cast<uint32_t>(signedAbs);
                    if (cellOffset + absCellSize > hbinSize) break;

                    // If cell is free (positive size), it's slack space
                    if (cellSize > 0 && absCellSize >= 8) {
                        // Check for 'nk' signature in deleted cells. Reading
                        // the 2-byte signature is safe because absCellSize
                        // is at least 8 and we've validated cellOffset.
                        uint16_t sig = 0;
                        file.read(reinterpret_cast<char*>(&sig), sizeof(sig));

                        if (sig == 0x6B6E) { // 'nk' - Key node
                            // Minimum nk cell layout requires the name length
                            // field at offset 0x4C (relative to size header)
                            // and the name immediately after at 0x50.
                            constexpr uint32_t NK_NAME_LEN_OFFSET = 0x4C;
                            constexpr uint32_t NK_NAME_OFFSET     = 0x50;
                            if (absCellSize <= NK_NAME_OFFSET) {
                                cellOffset += absCellSize;
                                continue;
                            }

                            DeletedEntry entry;
                            entry.isKey = true;
                            entry.cellOffset = currentOffset + cellOffset;

                            uint16_t nameLen = 0;
                            file.seekg(0x1000 + currentOffset + cellOffset + NK_NAME_LEN_OFFSET);
                            file.read(reinterpret_cast<char*>(&nameLen), sizeof(nameLen));
                            if (file.gcount() == sizeof(nameLen) && nameLen > 0) {
                                // The name region must fit inside the cell.
                                const uint32_t maxName = absCellSize - NK_NAME_OFFSET;
                                const uint32_t safeLen = std::min<uint32_t>(nameLen, maxName);
                                // Hard cap at 1024 chars; real key names are <=255.
                                const uint32_t cappedLen = std::min<uint32_t>(safeLen, 1024);
                                if (cappedLen > 0) {
                                    std::vector<char> nameBuf(cappedLen);
                                    file.seekg(0x1000 + currentOffset + cellOffset + NK_NAME_OFFSET);
                                    file.read(nameBuf.data(), cappedLen);
                                    const std::streamsize got = file.gcount();
                                    if (got > 0) {
                                        entry.name = StringUtils::ToWide(
                                            std::string_view(nameBuf.data(), static_cast<size_t>(got)));
                                    }
                                }
                            }

                            entry.isRecoverable = !entry.name.empty();
                            recovered.push_back(std::move(entry));
                            if (recovered.size() >= MAX_RECOVERED_ENTRIES) break;
                        }
                    }

                    cellOffset += absCellSize;
                }

                currentOffset += hbinSize;
            }

            m_stats.deletedRecovered.fetch_add(recovered.size(), std::memory_order_relaxed);
            SS_LOG_INFO(L"Registry", L"RegistryAnalyzer: Recovered %zu deleted entries from %ls",
                recovered.size(), SanitizePathForLogging(hivePath).c_str());

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Recovery exception: %hs", e.what());
        }

        return recovered;
    }

    RegistryAnomaly RecordAnomaly(
        AnomalyType type,
        AnomalySeverity severity,
        const std::wstring& hivePath,
        const std::wstring& keyPath,
        const std::wstring& valueName,
        const std::vector<uint8_t>& rawData,
        const std::string& description
    ) {
        RegistryAnomaly anomaly{};
        anomaly.anomalyId = m_nextAnomalyId.fetch_add(1, std::memory_order_relaxed);
        anomaly.detectedTime = system_clock::now();

        anomaly.hivePath = hivePath;
        anomaly.keyPath = keyPath;
        anomaly.valueName = valueName;

        anomaly.type = type;
        anomaly.severity = severity;
        anomaly.description = description;
        anomaly.technique = GetMITRETechnique(type);

        if (!rawData.empty()) {
            // Always hash the FULL data so SHA-256 reputation lookups
            // remain correct.
            anomaly.entropy = ::ShadowStrike::Core::Registry::CalculateEntropy(rawData);

            std::vector<uint8_t> hashResult;
            if (HashUtils::Compute(HashUtils::Algorithm::SHA256,
                                    rawData.data(), rawData.size(), hashResult)) {
                const size_t copyLen = std::min(hashResult.size(), anomaly.sha256.size());
                std::copy_n(hashResult.begin(), copyLen, anomaly.sha256.begin());
                anomaly.sha256Hex = HashUtils::ToHexLower(hashResult);
            }

            // Store only a bounded prefix of the raw data inside the
            // in-memory ring buffer to prevent a long-running analyzer
            // from accumulating hundreds of megabytes of attacker-supplied
            // blobs. The originalSize field preserves the true length so
            // exporters can flag truncation.
            const size_t cap = RegistryAnalyzerConstants::MAX_ANOMALY_RAW_DATA_BYTES;
            if (rawData.size() <= cap) {
                anomaly.rawData = rawData;
            } else {
                anomaly.rawData.assign(rawData.begin(), rawData.begin() + cap);
                anomaly.rawDataTruncated = true;
                anomaly.originalSize = rawData.size();
            }
        }

        // Determine if hidden/deleted/malicious based on type
        switch (type) {
            case AnomalyType::NullByteInjection:
            case AnomalyType::UnicodeControlChar:
            case AnomalyType::APIHiddenKey:
            case AnomalyType::APIHiddenValue:
                anomaly.isHidden = true;
                break;

            case AnomalyType::DeletedNotCleared:
            case AnomalyType::OrphanedCell:
                anomaly.isDeleted = true;
                break;

            case AnomalyType::KnownMalwareKey:
            case AnomalyType::KnownMalwareValue:
            case AnomalyType::EmbeddedExecutable:
                anomaly.isMalicious = true;
                break;

            default:
                break;
        }

        // Store anomaly. The deque retains the authoritative copy; the
        // map references the SAME object via a back-pointer to avoid
        // doubling memory cost for large payloads.
        {
            std::unique_lock lock(m_anomalyMutex);

            if (m_anomalies.size() >= m_config.maxAnomalies) {
                // Evict oldest — also remove from map to prevent unbounded growth
                const uint64_t evictedId = m_anomalies.front().anomalyId;
                m_anomalyMap.erase(evictedId);
                m_anomalies.pop_front();
            }

            m_anomalies.push_back(anomaly);
            m_anomalyMap[anomaly.anomalyId] = anomaly;
        }

        m_stats.anomaliesDetected.fetch_add(1, std::memory_order_relaxed);

        // Invoke callbacks (no internal locks held here).
        InvokeAnomalyCallbacks(anomaly);

        SS_LOG_DEBUG(L"Registry", L"RegistryAnalyzer: Anomaly recorded - ID: %llu, Type: %d, Severity: %d",
            anomaly.anomalyId, static_cast<int>(type), static_cast<int>(severity));

        return anomaly;
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void InvokeAnomalyCallbacks(const RegistryAnomaly& anomaly) const {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_anomalyCallbacks) {
            try {
                callback(anomaly);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Anomaly callback exception: %hs", e.what());
            }
        }
    }

    void InvokeProgressCallbacks(const std::wstring& currentPath, uint32_t progressPercent) const {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_progressCallbacks) {
            try {
                callback(currentPath, progressPercent);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Progress callback exception: %hs", e.what());
            }
        }
    }

    void InvokeHiddenCallbacks(const std::wstring& path, bool isKey) const {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_hiddenCallbacks) {
            try {
                callback(path, isKey);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Hidden entry callback exception: %hs", e.what());
            }
        }
    }
};

// ============================================================================
// SINGLETON INSTANCE
// ============================================================================

RegistryAnalyzer& RegistryAnalyzer::Instance() {
    static RegistryAnalyzer instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

RegistryAnalyzer::RegistryAnalyzer()
    : m_impl(std::make_unique<Impl>())
{
    SS_LOG_INFO(L"Registry", L"RegistryAnalyzer: Constructor called");
}

RegistryAnalyzer::~RegistryAnalyzer() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    SS_LOG_INFO(L"Registry", L"RegistryAnalyzer: Destructor called");
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

bool RegistryAnalyzer::Initialize(const RegistryAnalyzerConfig& config) {
    if (!m_impl) {
        SS_LOG_FATAL(L"Registry", L"RegistryAnalyzer: Implementation is null");
        return false;
    }

    return m_impl->Initialize(config);
}

void RegistryAnalyzer::Shutdown() noexcept {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

// ============================================================================
// ANALYSIS OPERATIONS
// ============================================================================

[[nodiscard]] AnalysisResult RegistryAnalyzer::Analyze(
    const AnalysisScope& scope,
    AnalysisMode mode
) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Not initialized");
        return AnalysisResult{};
    }

    return m_impl->AnalyzeImpl(scope, mode);
}

[[nodiscard]] std::vector<RegistryAnomaly> RegistryAnalyzer::AnalyzeKey(
    const std::wstring& keyPath,
    bool recursive
) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Not initialized");
        return {};
    }

    return m_impl->AnalyzeKeyImpl(keyPath, recursive);
}

[[nodiscard]] AnalysisResult RegistryAnalyzer::AnalyzeHiveFile(const std::wstring& hivePath) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Not initialized");
        return AnalysisResult{};
    }

    AnalysisResult result{};
    result.mode = AnalysisMode::Forensic;
    result.startTime = system_clock::now();

    try {
        // Parse hive header
        auto header = m_impl->ParseHiveHeaderImpl(hivePath);

        if (!header.isValid) {
            result.hadErrors = true;
            result.errors.push_back("Invalid hive file");
            return result;
        }

        result.hivesAnalyzed = 1;
        result.completed = true;
        result.endTime = system_clock::now();

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Hive analysis exception: %hs", e.what());
        result.hadErrors = true;
        result.errors.push_back(e.what());
    }

    return result;
}

void RegistryAnalyzer::AbortAnalysis() noexcept {
    if (m_impl) {
        m_impl->m_abortRequested.store(true, std::memory_order_release);
    }
}

[[nodiscard]] bool RegistryAnalyzer::IsAnalysisRunning() const noexcept {
    return m_impl && m_impl->m_analyzing.load(std::memory_order_acquire);
}

// ============================================================================
// HIDDEN ENTRY DETECTION
// ============================================================================

[[nodiscard]] std::vector<std::wstring> RegistryAnalyzer::DetectNullByteKeys(
    const std::wstring& rootKey
) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Not initialized");
        return {};
    }

    return m_impl->DetectNullByteKeysImpl(rootKey);
}

[[nodiscard]] CrossViewResult RegistryAnalyzer::PerformCrossViewDetection(
    const std::wstring& keyPath
) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Not initialized");
        return CrossViewResult{};
    }

    return m_impl->PerformCrossViewDetectionImpl(keyPath);
}

[[nodiscard]] std::vector<std::wstring> RegistryAnalyzer::GetHiddenKeys() const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    std::shared_lock lock(m_impl->m_hiddenMutex);
    return std::vector<std::wstring>(m_impl->m_hiddenKeys.begin(), m_impl->m_hiddenKeys.end());
}

[[nodiscard]] std::unordered_map<std::wstring, std::vector<std::wstring>>
RegistryAnalyzer::GetHiddenValues() const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    std::shared_lock lock(m_impl->m_hiddenMutex);
    return m_impl->m_hiddenValues;
}

// ============================================================================
// ANOMALY ACCESS
// ============================================================================

[[nodiscard]] std::vector<RegistryAnomaly> RegistryAnalyzer::GetAnomalies() const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    std::shared_lock lock(m_impl->m_anomalyMutex);
    return std::vector<RegistryAnomaly>(m_impl->m_anomalies.begin(), m_impl->m_anomalies.end());
}

[[nodiscard]] std::vector<RegistryAnomaly> RegistryAnalyzer::GetAnomaliesByType(
    AnomalyType type
) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    std::vector<RegistryAnomaly> filtered;
    std::shared_lock lock(m_impl->m_anomalyMutex);

    for (const auto& anomaly : m_impl->m_anomalies) {
        if (anomaly.type == type) {
            filtered.push_back(anomaly);
        }
    }

    return filtered;
}

[[nodiscard]] std::vector<RegistryAnomaly> RegistryAnalyzer::GetAnomaliesBySeverity(
    AnomalySeverity minSeverity
) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    std::vector<RegistryAnomaly> filtered;
    std::shared_lock lock(m_impl->m_anomalyMutex);

    for (const auto& anomaly : m_impl->m_anomalies) {
        if (anomaly.severity >= minSeverity) {
            filtered.push_back(anomaly);
        }
    }

    return filtered;
}

[[nodiscard]] std::optional<RegistryAnomaly> RegistryAnalyzer::GetAnomalyById(
    uint64_t anomalyId
) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return std::nullopt;
    }

    std::shared_lock lock(m_impl->m_anomalyMutex);

    auto it = m_impl->m_anomalyMap.find(anomalyId);
    if (it != m_impl->m_anomalyMap.end()) {
        return it->second;
    }

    return std::nullopt;
}

void RegistryAnalyzer::ClearAnomalies() noexcept {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_anomalyMutex);
    m_impl->m_anomalies.clear();
    m_impl->m_anomalyMap.clear();
}

// ============================================================================
// DELETED ENTRY RECOVERY
// ============================================================================

[[nodiscard]] std::vector<DeletedEntry> RegistryAnalyzer::RecoverDeletedEntries(HiveType hive) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Not initialized");
        return {};
    }

    // Map hive type to system hive file path
    std::wstring hivePath;
    const std::wstring sysRoot = L"C:\\Windows\\System32\\config\\";

    switch (hive) {
        case HiveType::SAM:       hivePath = sysRoot + L"SAM"; break;
        case HiveType::SECURITY:  hivePath = sysRoot + L"SECURITY"; break;
        case HiveType::SOFTWARE:  hivePath = sysRoot + L"SOFTWARE"; break;
        case HiveType::SYSTEM:    hivePath = sysRoot + L"SYSTEM"; break;
        case HiveType::DEFAULT:   hivePath = sysRoot + L"DEFAULT"; break;
        case HiveType::AMCACHE:   hivePath = L"C:\\Windows\\AppCompat\\Programs\\Amcache.hve"; break;
        case HiveType::BCD:       hivePath = L"C:\\Boot\\BCD"; break;
        default:
            SS_LOG_WARN(L"Registry", L"RegistryAnalyzer: Unsupported hive type for recovery: %d",
                static_cast<int>(hive));
            return {};
    }

    SS_LOG_INFO(L"Registry", L"RegistryAnalyzer: Attempting deleted entry recovery from %ls",
        hivePath.c_str());

    return m_impl->RecoverDeletedEntriesImpl(hivePath);
}

[[nodiscard]] std::vector<DeletedEntry> RegistryAnalyzer::RecoverFromHiveFile(
    const std::wstring& hivePath
) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Not initialized");
        return {};
    }

    // Validate the hive file path
    if (hivePath.empty()) {
        SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Empty hive path for recovery");
        return {};
    }

    if (!fs::exists(hivePath)) {
        SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Hive file does not exist: %ls", hivePath.c_str());
        return {};
    }

    // Validate hive structure before attempting recovery
    auto header = m_impl->ParseHiveHeaderImpl(hivePath);
    if (!header.isValid) {
        SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Invalid hive file for recovery: %ls", hivePath.c_str());
        return {};
    }

    return m_impl->RecoverDeletedEntriesImpl(hivePath);
}

// ============================================================================
// HIVE PARSING
// ============================================================================

[[nodiscard]] HiveHeader RegistryAnalyzer::ParseHiveHeader(const std::wstring& hivePath) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Not initialized");
        return HiveHeader{};
    }

    return m_impl->ParseHiveHeaderImpl(hivePath);
}

[[nodiscard]] bool RegistryAnalyzer::ValidateHiveStructure(const std::wstring& hivePath) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Not initialized");
        return false;
    }

    return m_impl->ValidateHiveStructureImpl(hivePath);
}

[[nodiscard]] std::optional<KeyCell> RegistryAnalyzer::GetKeyCell(
    const std::wstring& hivePath,
    uint32_t offset
) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return std::nullopt;
    }

    try {
        std::ifstream file(hivePath, std::ios::binary);
        if (!file) {
            SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: GetKeyCell: Cannot open hive: %ls", hivePath.c_str());
            return std::nullopt;
        }

        if (offset == 0xFFFFFFFF) return std::nullopt;

        // Offsets are relative to first hbin (0x1000) and 4-byte aligned
        uint64_t absoluteOffset = static_cast<uint64_t>(offset) + 0x1000;
        file.seekg(absoluteOffset);

        int32_t cellSize;
        file.read(reinterpret_cast<char*>(&cellSize), sizeof(cellSize));
        if (file.gcount() != sizeof(cellSize)) return std::nullopt;

        uint32_t absCellSize = static_cast<uint32_t>(std::abs(cellSize));
        if (absCellSize < 6) return std::nullopt;  // Minimum: size(4) + sig(2)

        // Read signature
        uint16_t sig;
        file.read(reinterpret_cast<char*>(&sig), sizeof(sig));
        if (file.gcount() != sizeof(sig) || sig != 0x6B6E /* 'nk' */) {
            return std::nullopt;
        }

        KeyCell cell;
        cell.offset = offset;
        cell.cellSize = cellSize;
        cell.isAllocated = (cellSize < 0);
        cell.isDeleted = (cellSize > 0);

        // Read flags (2 bytes at nk+0x02)
        uint16_t flags;
        file.read(reinterpret_cast<char*>(&flags), sizeof(flags));

        // Read timestamp (8 bytes at nk+0x04)
        uint64_t timestamp;
        file.read(reinterpret_cast<char*>(&timestamp), sizeof(timestamp));
        constexpr int64_t FILETIME_EPOCH_OFFSET_SEC = 11644473600LL;
        if (timestamp > 0) {
            auto windowsDuration = std::chrono::duration<int64_t, std::ratio<1, 10000000>>(
                static_cast<int64_t>(timestamp));
            auto unixDuration = windowsDuration - std::chrono::seconds(FILETIME_EPOCH_OFFSET_SEC);
            cell.lastWritten = std::chrono::system_clock::time_point(
                std::chrono::duration_cast<std::chrono::system_clock::duration>(unixDuration));
        }

        // Skip to parent offset (nk+0x10)
        file.seekg(absoluteOffset + 4 + 0x10);  // +4 for cellSize
        file.read(reinterpret_cast<char*>(&cell.parentOffset), sizeof(cell.parentOffset));

        // Subkey count (nk+0x14)
        file.read(reinterpret_cast<char*>(&cell.subKeyCount), sizeof(cell.subKeyCount));

        // Skip volatile subkeys (nk+0x18), subkeys list offset (nk+0x1C), volatile list (nk+0x20)
        file.seekg(absoluteOffset + 4 + 0x24);
        file.read(reinterpret_cast<char*>(&cell.valueCount), sizeof(cell.valueCount));

        // Security offset (nk+0x2C)
        file.seekg(absoluteOffset + 4 + 0x2C);
        file.read(reinterpret_cast<char*>(&cell.securityOffset), sizeof(cell.securityOffset));

        // Class name offset (nk+0x30)
        file.read(reinterpret_cast<char*>(&cell.classNameOffset), sizeof(cell.classNameOffset));

        // Key name length (nk+0x48)
        file.seekg(absoluteOffset + 4 + 0x48);
        uint16_t nameLen;
        file.read(reinterpret_cast<char*>(&nameLen), sizeof(nameLen));

        // Cap name length
        nameLen = std::min(nameLen, static_cast<uint16_t>(1024));

        // Key name starts at nk+0x4C
        file.seekg(absoluteOffset + 4 + 0x4C);
        std::vector<char> nameBuf(nameLen);
        file.read(nameBuf.data(), nameLen);
        if (file.gcount() == nameLen) {
            cell.keyName = StringUtils::ToWide(std::string_view(nameBuf.data(), nameLen));
            cell.keyNameRaw = cell.keyName;

            // Check for hidden characters
            cell.hasNullByte = std::any_of(nameBuf.begin(), nameBuf.end(),
                                            [](char c) { return c == '\0'; });
            cell.hasHiddenChars = HasControlCharacters(cell.keyName);
        }

        return cell;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: GetKeyCell exception: %hs", e.what());
        return std::nullopt;
    }
}

// ============================================================================
// THREAT HUNTING
// ============================================================================

size_t RegistryAnalyzer::LoadThreatIndicators(const std::wstring& indicatorsPath) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Not initialized");
        return 0;
    }

    return m_impl->LoadThreatIndicatorsImpl(indicatorsPath);
}

void RegistryAnalyzer::AddThreatIndicator(const ThreatIndicator& indicator) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_indicatorMutex);
    m_impl->m_indicators.push_back(indicator);
}

[[nodiscard]] std::vector<RegistryAnomaly> RegistryAnalyzer::SearchIOCs(
    const std::vector<std::wstring>& iocs
) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Not initialized");
        return {};
    }

    return m_impl->SearchIOCsImpl(iocs);
}

// ============================================================================
// FORENSIC TIMELINE
// ============================================================================

[[nodiscard]] std::vector<ForensicTimeline> RegistryAnalyzer::GetTimeline(
    system_clock::time_point startTime,
    system_clock::time_point endTime
) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    std::vector<ForensicTimeline> filtered;
    std::shared_lock lock(m_impl->m_timelineMutex);

    for (const auto& entry : m_impl->m_timeline) {
        if (entry.timestamp >= startTime && entry.timestamp <= endTime) {
            filtered.push_back(entry);
        }
    }

    return filtered;
}

bool RegistryAnalyzer::ExportTimeline(const std::wstring& outputPath) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    try {
        std::ofstream file(outputPath);
        if (!file) {
            SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Failed to open output file: %ls",
                outputPath.c_str());
            return false;
        }

        // Write CSV header
        file << "Timestamp,Action,Hive,KeyPath,ValueName,Description,IsAnomaly\n";

        std::shared_lock lock(m_impl->m_timelineMutex);
        for (const auto& entry : m_impl->m_timeline) {
            file << std::chrono::system_clock::to_time_t(entry.timestamp) << ","
                 << EscapeCsvField(entry.action) << ","
                 << EscapeCsvField(StringUtils::ToNarrow(HiveTypeToString(entry.hive))) << ","
                 << EscapeCsvField(StringUtils::ToNarrow(entry.keyPath)) << ","
                 << EscapeCsvField(StringUtils::ToNarrow(entry.valueName)) << ","
                 << EscapeCsvField(entry.description) << ","
                 << (entry.isAnomaly ? "true" : "false") << "\n";
        }

        SS_LOG_INFO(L"Registry", L"RegistryAnalyzer: Timeline exported to %ls",
            outputPath.c_str());
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Timeline export exception: %hs", e.what());
        return false;
    }
}

// ============================================================================
// ENTROPY ANALYSIS
// ============================================================================

[[nodiscard]] double RegistryAnalyzer::CalculateEntropy(std::span<const uint8_t> data) const noexcept {
    return ::ShadowStrike::Core::Registry::CalculateEntropy(data);
}

[[nodiscard]] std::vector<RegistryAnomaly> RegistryAnalyzer::GetHighEntropyValues(
    double minEntropy
) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    std::vector<RegistryAnomaly> filtered;
    std::shared_lock lock(m_impl->m_anomalyMutex);

    for (const auto& anomaly : m_impl->m_anomalies) {
        if (anomaly.entropy >= minEntropy) {
            filtered.push_back(anomaly);
        }
    }

    return filtered;
}

// ============================================================================
// CALLBACK REGISTRATION
// ============================================================================

uint64_t RegistryAnalyzer::RegisterAnomalyCallback(AnomalyCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_anomalyCallbacks[id] = std::move(callback);

    SS_LOG_DEBUG(L"Registry", L"RegistryAnalyzer: Registered anomaly callback %llu", id);
    return id;
}

uint64_t RegistryAnalyzer::RegisterProgressCallback(ScanProgressCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_progressCallbacks[id] = std::move(callback);

    SS_LOG_DEBUG(L"Registry", L"RegistryAnalyzer: Registered progress callback %llu", id);
    return id;
}

uint64_t RegistryAnalyzer::RegisterHiddenEntryCallback(HiddenEntryCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_hiddenCallbacks[id] = std::move(callback);

    SS_LOG_DEBUG(L"Registry", L"RegistryAnalyzer: Registered hidden entry callback %llu", id);
    return id;
}

bool RegistryAnalyzer::UnregisterCallback(uint64_t callbackId) {
    if (!m_impl) return false;

    std::unique_lock lock(m_impl->m_callbackMutex);

    bool removed = false;
    removed |= m_impl->m_anomalyCallbacks.erase(callbackId) > 0;
    removed |= m_impl->m_progressCallbacks.erase(callbackId) > 0;
    removed |= m_impl->m_hiddenCallbacks.erase(callbackId) > 0;

    if (removed) {
        SS_LOG_DEBUG(L"Registry", L"RegistryAnalyzer: Unregistered callback %llu", callbackId);
    }

    return removed;
}

// ============================================================================
// STATISTICS
// ============================================================================

[[nodiscard]] const RegistryAnalyzerStatistics& RegistryAnalyzer::GetStatistics() const noexcept {
    static RegistryAnalyzerStatistics emptyStats{};
    return m_impl ? m_impl->m_stats : emptyStats;
}

void RegistryAnalyzer::ResetStatistics() noexcept {
    if (m_impl) {
        m_impl->m_stats.Reset();
        SS_LOG_INFO(L"Registry", L"RegistryAnalyzer: Statistics reset");
    }
}

// ============================================================================
// EXPORT
// ============================================================================

bool RegistryAnalyzer::ExportReport(const std::wstring& outputPath) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    try {
        std::ofstream file(outputPath);
        if (!file) {
            return false;
        }

        file << "=== ShadowStrike Registry Analysis Report ===\n\n";

        // Statistics
        file << "Total Scans: " << m_impl->m_stats.totalScans.load() << "\n";
        file << "Keys Analyzed: " << m_impl->m_stats.keysAnalyzed.load() << "\n";
        file << "Values Analyzed: " << m_impl->m_stats.valuesAnalyzed.load() << "\n";
        file << "Anomalies Detected: " << m_impl->m_stats.anomaliesDetected.load() << "\n";
        file << "Hidden Keys Found: " << m_impl->m_stats.hiddenKeysFound.load() << "\n";
        file << "Rootkit Indicators: " << m_impl->m_stats.rootkitIndicators.load() << "\n\n";

        // Anomalies
        std::shared_lock lock(m_impl->m_anomalyMutex);
        file << "=== Anomalies ===\n";
        for (const auto& anomaly : m_impl->m_anomalies) {
            file << "ID: " << anomaly.anomalyId << "\n";
            file << "Type: " << static_cast<int>(anomaly.type) << "\n";
            file << "Severity: " << static_cast<int>(anomaly.severity) << "\n";
            file << "Path: " << StringUtils::ToNarrow(anomaly.keyPath) << "\n";
            file << "Description: " << anomaly.description << "\n\n";
        }

        SS_LOG_INFO(L"Registry", L"RegistryAnalyzer: Report exported to %ls",
            outputPath.c_str());
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Report export exception: %hs", e.what());
        return false;
    }
}

bool RegistryAnalyzer::ExportAnomalies(const std::wstring& outputPath) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    try {
        std::ofstream file(outputPath);
        if (!file) {
            return false;
        }

        // CSV header
        file << "AnomalyID,Type,Severity,HivePath,KeyPath,ValueName,Description,SHA256\n";

        std::shared_lock lock(m_impl->m_anomalyMutex);
        for (const auto& anomaly : m_impl->m_anomalies) {
            file << anomaly.anomalyId << ","
                 << static_cast<int>(anomaly.type) << ","
                 << static_cast<int>(anomaly.severity) << ","
                 << EscapeCsvField(StringUtils::ToNarrow(anomaly.hivePath)) << ","
                 << EscapeCsvField(StringUtils::ToNarrow(anomaly.keyPath)) << ","
                 << EscapeCsvField(StringUtils::ToNarrow(anomaly.valueName)) << ","
                 << EscapeCsvField(anomaly.description) << ","
                 << anomaly.sha256Hex << "\n";
        }

        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Anomalies export exception: %hs", e.what());
        return false;
    }
}

bool RegistryAnalyzer::ExportHiddenEntries(const std::wstring& outputPath) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    try {
        std::ofstream file(outputPath);
        if (!file) {
            return false;
        }

        file << "=== Hidden Registry Keys ===\n\n";

        std::shared_lock lock(m_impl->m_hiddenMutex);
        for (const auto& hiddenKey : m_impl->m_hiddenKeys) {
            file << StringUtils::ToNarrow(hiddenKey) << "\n";
        }

        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Registry", L"RegistryAnalyzer: Hidden entries export exception: %hs", e.what());
        return false;
    }
}

} // namespace Registry
} // namespace Core
} // namespace ShadowStrike
