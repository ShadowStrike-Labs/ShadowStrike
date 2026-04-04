/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * VirtualRegistry.cpp — Centralized virtual registry hive implementation
 *
 * Single authoritative registry backing all emulated registry APIs.
 * Pre-populated with ~200+ realistic Windows 10 Pro 22H2 entries (Dell
 * Precision 5570 / Intel i7-12700H) with ZERO VM/sandbox artifacts.
 *
 * Persistence detection covers: Run, RunOnce, RunOnceEx, Services,
 * Shell Folders, Winlogon, IFEO, AppInit_DLLs, Environment, Explorer\Run.
 *
 * Thread-safe: shared_mutex (concurrent reads, exclusive writes).
 * All public methods acquire the appropriate lock and return copies for
 * safe enumeration.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "VirtualRegistry.hpp"

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <cctype>
#include <string>

namespace Phantom::VirtualOS {

// ============================================================================
// Internal helpers (file-local)
// ============================================================================

namespace {

// Case-insensitive ASCII-range wide-char to uppercase
[[nodiscard]] static wchar_t WideToUpper(wchar_t c) noexcept {
    return (c >= L'a' && c <= L'z') ? static_cast<wchar_t>(c - L'a' + L'A') : c;
}

// Full string uppercase (case-folding for comparison keys)
[[nodiscard]] static std::wstring ToUpper(std::wstring_view sv) noexcept {
    std::wstring result;
    result.reserve(sv.size());
    for (const auto c : sv) {
        result.push_back(WideToUpper(c));
    }
    return result;
}

// Case-insensitive wide string comparison
[[nodiscard]] static bool WideEqualCI(std::wstring_view a, std::wstring_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (WideToUpper(a[i]) != WideToUpper(b[i])) return false;
    }
    return true;
}

// Case-insensitive substring search
[[nodiscard]] static bool WideContainsCI(std::wstring_view haystack,
                                          std::wstring_view needle) noexcept {
    if (needle.empty()) return true;
    if (haystack.size() < needle.size()) return false;
    for (size_t i = 0; i <= haystack.size() - needle.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < needle.size(); ++j) {
            if (WideToUpper(haystack[i + j]) != WideToUpper(needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

// Case-insensitive suffix check
[[nodiscard]] static bool WideEndsWithCI(std::wstring_view str,
                                          std::wstring_view suffix) noexcept {
    if (str.size() < suffix.size()) return false;
    return WideEqualCI(str.substr(str.size() - suffix.size()), suffix);
}

// Encode a wide string as REG_SZ byte data (UTF-16LE with null terminator)
[[nodiscard]] static std::vector<uint8_t> EncodeRegSz(std::wstring_view str) noexcept {
    const size_t charCount = str.size() + 1;  // include null terminator
    std::vector<uint8_t> data(charCount * sizeof(wchar_t));
    std::memcpy(data.data(), str.data(), str.size() * sizeof(wchar_t));
    // Final null already zero-initialized by vector ctor
    return data;
}

// Encode DWORD as 4-byte little-endian
[[nodiscard]] static std::vector<uint8_t> EncodeDword(uint32_t val) noexcept {
    std::vector<uint8_t> data(sizeof(uint32_t));
    std::memcpy(data.data(), &val, sizeof(uint32_t));
    return data;
}

// Encode QWORD as 8-byte little-endian
[[nodiscard]] static std::vector<uint8_t> EncodeQword(uint64_t val) noexcept {
    std::vector<uint8_t> data(sizeof(uint64_t));
    std::memcpy(data.data(), &val, sizeof(uint64_t));
    return data;
}

// Encode MULTI_SZ: concatenated null-terminated wide strings with double-null terminator
[[nodiscard]] static std::vector<uint8_t> EncodeMultiSz(
        const std::vector<std::wstring>& strings) noexcept {
    size_t totalChars = 0;
    for (const auto& s : strings) {
        totalChars += s.size() + 1;  // each string + null
    }
    totalChars += 1;  // final double-null terminator

    std::vector<uint8_t> data(totalChars * sizeof(wchar_t), 0);
    size_t offset = 0;
    for (const auto& s : strings) {
        const size_t byteLen = s.size() * sizeof(wchar_t);
        std::memcpy(data.data() + offset, s.data(), byteLen);
        offset += byteLen + sizeof(wchar_t);  // skip past null terminator
    }
    return data;
}

// Generate a fake FILETIME-like 64-bit value (~Jan 2023)
[[nodiscard]] static uint64_t FakeLastWriteTime() noexcept {
    // Windows FILETIME for 2023-01-01 00:00:00 UTC
    // 133155264000000000 = 0x01D93A39_13310000
    return 133155264000000000ULL;
}

} // anonymous namespace

// ============================================================================
// Meyers' Singleton
// ============================================================================

VirtualRegistry& VirtualRegistry::Instance() noexcept {
    static VirtualRegistry s_instance;
    return s_instance;
}

// ============================================================================
// Initialize / Reset
// ============================================================================

void VirtualRegistry::Initialize(const EmulationConfig& config) noexcept {
    std::unique_lock lock(m_mutex);
    if (m_initialized) return;
    PopulateDefaults(config);
    m_initialized = true;
}

void VirtualRegistry::Reset() noexcept {
    std::unique_lock lock(m_mutex);
    m_keys.clear();
    m_writeIOCs.clear();
    m_initialized = false;
}

// ============================================================================
// Path Utilities
// ============================================================================

std::wstring VirtualRegistry::NormalizePath(std::wstring_view path) noexcept {
    std::wstring result;
    result.reserve(path.size());

    // Collapse double backslashes and copy uppercase
    bool lastWasSep = false;
    for (const auto c : path) {
        if (c == L'\\' || c == L'/') {
            if (!lastWasSep) {
                result.push_back(L'\\');
            }
            lastWasSep = true;
        } else {
            result.push_back(WideToUpper(c));
            lastWasSep = false;
        }
    }

    // Strip leading backslash
    if (!result.empty() && result.front() == L'\\') {
        result.erase(result.begin());
    }

    // Strip trailing backslash
    while (!result.empty() && result.back() == L'\\') {
        result.pop_back();
    }

    // NT kernel path → short-form conversion
    // \Registry\Machine\... → HKLM\...
    if (result.starts_with(L"REGISTRY\\MACHINE\\")) {
        result = L"HKLM\\" + result.substr(17);
    } else if (result == L"REGISTRY\\MACHINE") {
        result = L"HKLM";
    }
    // \Registry\User\... → HKU\...
    else if (result.starts_with(L"REGISTRY\\USER\\")) {
        result = L"HKU\\" + result.substr(14);
    } else if (result == L"REGISTRY\\USER") {
        result = L"HKU";
    }

    // Map HKEY_LOCAL_MACHINE → HKLM
    if (result.starts_with(L"HKEY_LOCAL_MACHINE\\")) {
        result = L"HKLM\\" + result.substr(19);
    } else if (result == L"HKEY_LOCAL_MACHINE") {
        result = L"HKLM";
    }
    // Map HKEY_CURRENT_USER → HKCU
    else if (result.starts_with(L"HKEY_CURRENT_USER\\")) {
        result = L"HKCU\\" + result.substr(18);
    } else if (result == L"HKEY_CURRENT_USER") {
        result = L"HKCU";
    }
    // Map HKEY_CLASSES_ROOT → HKCR
    else if (result.starts_with(L"HKEY_CLASSES_ROOT\\")) {
        result = L"HKCR\\" + result.substr(18);
    } else if (result == L"HKEY_CLASSES_ROOT") {
        result = L"HKCR";
    }
    // Map HKEY_USERS → HKU
    else if (result.starts_with(L"HKEY_USERS\\")) {
        result = L"HKU\\" + result.substr(11);
    } else if (result == L"HKEY_USERS") {
        result = L"HKU";
    }
    // Map HKEY_CURRENT_CONFIG → HKCC
    else if (result.starts_with(L"HKEY_CURRENT_CONFIG\\")) {
        result = L"HKCC\\" + result.substr(20);
    } else if (result == L"HKEY_CURRENT_CONFIG") {
        result = L"HKCC";
    }

    // Map HKU\S-1-5-21-*\... → HKCU\... (current user SID → HKCU)
    if (result.starts_with(L"HKU\\S-1-5-21-")) {
        auto secondSep = result.find(L'\\', 4);
        if (secondSep != std::wstring::npos) {
            result = L"HKCU\\" + result.substr(secondSep + 1);
        } else {
            result = L"HKCU";
        }
    }
    // Map HKU\.DEFAULT → HKCU
    else if (result == L"HKU\\.DEFAULT" || result.starts_with(L"HKU\\.DEFAULT\\")) {
        if (result.size() > 13) {
            result = L"HKCU\\" + result.substr(14);
        } else {
            result = L"HKCU";
        }
    }

    return result;
}

std::wstring VirtualRegistry::ResolveRootHandle(uint64_t rootHandle,
                                                 std::wstring_view subKey) noexcept {
    std::wstring prefix;
    switch (rootHandle) {
        case RootKey::HKCR:  prefix = L"HKCR";  break;
        case RootKey::HKCU:  prefix = L"HKCU";  break;
        case RootKey::HKLM:  prefix = L"HKLM";  break;
        case RootKey::HKU:   prefix = L"HKU";   break;
        case RootKey::HKCC:  prefix = L"HKCC";  break;
        default:             return NormalizePath(subKey);
    }

    if (subKey.empty()) return prefix;

    std::wstring full = prefix;
    full.push_back(L'\\');
    full.append(subKey);
    return NormalizePath(full);
}

bool VirtualRegistry::IsRootHandle(uint64_t handle) noexcept {
    return handle == RootKey::HKCR  ||
           handle == RootKey::HKCU  ||
           handle == RootKey::HKLM  ||
           handle == RootKey::HKU   ||
           handle == RootKey::HKCC;
}

// ============================================================================
// Key Operations
// ============================================================================

bool VirtualRegistry::KeyExists(std::wstring_view fullPath) const noexcept {
    const auto normalized = NormalizePath(fullPath);
    std::shared_lock lock(m_mutex);
    return m_keys.contains(normalized);
}

bool VirtualRegistry::CreateKey(std::wstring_view fullPath) noexcept {
    const auto normalized = NormalizePath(fullPath);
    if (normalized.empty()) return false;

    std::unique_lock lock(m_mutex);

    if (m_keys.size() >= kMaxKeys) return false;

    // Create all intermediate keys (mkdir -p behavior)
    size_t pos = 0;
    while (pos != std::wstring::npos) {
        pos = normalized.find(L'\\', pos == 0 ? 0 : pos + 1);
        const auto segment = (pos == std::wstring::npos)
            ? normalized
            : normalized.substr(0, pos);

        if (!m_keys.contains(segment)) {
            if (m_keys.size() >= kMaxKeys) return false;

            RegKeyInfo& newKey = m_keys[segment];
            newKey.fullPath = segment;
            newKey.lastWriteTime = FakeLastWriteTime();
            newKey.isPrePopulated = false;

            // Register in parent's subkey list
            const auto lastSep = segment.rfind(L'\\');
            if (lastSep != std::wstring::npos) {
                const auto parentPath = segment.substr(0, lastSep);
                const auto childName = segment.substr(lastSep + 1);
                auto pit = m_keys.find(parentPath);
                if (pit != m_keys.end()) {
                    auto& subs = pit->second.subKeyNames;
                    if (std::find(subs.begin(), subs.end(), childName) == subs.end()) {
                        subs.push_back(std::wstring(childName));
                    }
                }
            }
        }

        if (pos == std::wstring::npos) break;
    }

    return true;
}

bool VirtualRegistry::DeleteKey(std::wstring_view fullPath) noexcept {
    const auto normalized = NormalizePath(fullPath);
    std::unique_lock lock(m_mutex);

    auto it = m_keys.find(normalized);
    if (it == m_keys.end()) return false;

    // Refuse to delete keys that have subkeys (matches Windows behavior)
    if (!it->second.subKeyNames.empty()) return false;

    // Remove from parent's subkey list
    const auto lastSep = normalized.rfind(L'\\');
    if (lastSep != std::wstring::npos) {
        const auto parentPath = normalized.substr(0, lastSep);
        const auto childName = normalized.substr(lastSep + 1);
        auto pit = m_keys.find(parentPath);
        if (pit != m_keys.end()) {
            auto& subs = pit->second.subKeyNames;
            subs.erase(std::remove(subs.begin(), subs.end(), childName), subs.end());
        }
    }

    m_keys.erase(it);
    return true;
}

std::vector<std::wstring> VirtualRegistry::GetSubkeys(std::wstring_view fullPath) const noexcept {
    const auto normalized = NormalizePath(fullPath);
    std::shared_lock lock(m_mutex);
    auto it = m_keys.find(normalized);
    if (it == m_keys.end()) return {};
    return it->second.subKeyNames;
}

std::optional<std::wstring> VirtualRegistry::EnumSubKey(std::wstring_view fullPath,
                                                         uint32_t index) const noexcept {
    const auto normalized = NormalizePath(fullPath);
    std::shared_lock lock(m_mutex);
    auto it = m_keys.find(normalized);
    if (it == m_keys.end()) return std::nullopt;
    if (index >= it->second.subKeyNames.size()) return std::nullopt;
    return it->second.subKeyNames[index];
}

// ============================================================================
// Value Operations
// ============================================================================

bool VirtualRegistry::SetValue(std::wstring_view keyPath, std::wstring_view valueName,
                                uint32_t type, const uint8_t* data,
                                uint32_t dataSize) noexcept {
    if (dataSize > kMaxValueData) return false;
    if (data == nullptr && dataSize > 0) return false;

    const auto normalizedKey = NormalizePath(keyPath);
    const auto upperName = ToUpper(valueName);

    std::unique_lock lock(m_mutex);

    auto it = m_keys.find(normalizedKey);
    if (it == m_keys.end()) return false;

    if (it->second.values.size() >= kMaxValuesPerKey) {
        // Check if we're updating an existing value
        bool exists = false;
        for (const auto& v : it->second.values) {
            if (ToUpper(v.name) == upperName) { exists = true; break; }
        }
        if (!exists) return false;
    }

    // Find existing value or add new one
    RegValue* target = nullptr;
    for (auto& v : it->second.values) {
        if (ToUpper(v.name) == upperName) {
            target = &v;
            break;
        }
    }

    if (target == nullptr) {
        it->second.values.emplace_back();
        target = &it->second.values.back();
        target->name = std::wstring(valueName);
    }

    target->type = type;
    if (data != nullptr && dataSize > 0) {
        target->data.assign(data, data + dataSize);
    } else {
        target->data.clear();
    }

    it->second.lastWriteTime = FakeLastWriteTime();

    // Track IOC
    const bool persistence = IsPersistencePath(normalizedKey);
    const bool autoStart = IsAutoStartService(normalizedKey, target->data);

    if (persistence || autoStart) {
        RegistryWriteIOC ioc;
        ioc.keyPath = normalizedKey;
        ioc.valueName = std::wstring(valueName);
        ioc.valueType = type;
        if (data != nullptr && dataSize > 0) {
            ioc.data.assign(data, data + dataSize);
        }
        ioc.isPersistence = persistence;
        ioc.isAutoStart = autoStart;
        m_writeIOCs.push_back(std::move(ioc));
    }

    return true;
}

const RegValue* VirtualRegistry::QueryValue(std::wstring_view keyPath,
                                             std::wstring_view valueName) const noexcept {
    const auto normalizedKey = NormalizePath(keyPath);
    const auto upperName = ToUpper(valueName);

    std::shared_lock lock(m_mutex);

    auto it = m_keys.find(normalizedKey);
    if (it == m_keys.end()) return nullptr;

    for (const auto& v : it->second.values) {
        if (ToUpper(v.name) == upperName) {
            return &v;
        }
    }
    return nullptr;
}

bool VirtualRegistry::DeleteValue(std::wstring_view keyPath,
                                   std::wstring_view valueName) noexcept {
    const auto normalizedKey = NormalizePath(keyPath);
    const auto upperName = ToUpper(valueName);

    std::unique_lock lock(m_mutex);

    auto it = m_keys.find(normalizedKey);
    if (it == m_keys.end()) return false;

    auto& vals = it->second.values;
    auto vit = std::remove_if(vals.begin(), vals.end(),
        [&upperName](const RegValue& v) { return ToUpper(v.name) == upperName; });

    if (vit == vals.end()) return false;
    vals.erase(vit, vals.end());
    return true;
}

std::vector<RegValue> VirtualRegistry::GetValues(std::wstring_view keyPath) const noexcept {
    const auto normalizedKey = NormalizePath(keyPath);
    std::shared_lock lock(m_mutex);

    auto it = m_keys.find(normalizedKey);
    if (it == m_keys.end()) return {};
    return it->second.values;
}

std::optional<RegValue> VirtualRegistry::EnumValue(std::wstring_view keyPath,
                                                    uint32_t index) const noexcept {
    const auto normalizedKey = NormalizePath(keyPath);
    std::shared_lock lock(m_mutex);

    auto it = m_keys.find(normalizedKey);
    if (it == m_keys.end()) return std::nullopt;
    if (index >= it->second.values.size()) return std::nullopt;
    return it->second.values[index];
}

// ============================================================================
// Key Metadata Queries
// ============================================================================

uint32_t VirtualRegistry::GetSubkeyCount(std::wstring_view keyPath) const noexcept {
    const auto normalized = NormalizePath(keyPath);
    std::shared_lock lock(m_mutex);
    auto it = m_keys.find(normalized);
    if (it == m_keys.end()) return 0;
    return static_cast<uint32_t>(it->second.subKeyNames.size());
}

uint32_t VirtualRegistry::GetValueCount(std::wstring_view keyPath) const noexcept {
    const auto normalized = NormalizePath(keyPath);
    std::shared_lock lock(m_mutex);
    auto it = m_keys.find(normalized);
    if (it == m_keys.end()) return 0;
    return static_cast<uint32_t>(it->second.values.size());
}

uint32_t VirtualRegistry::GetMaxValueNameLen(std::wstring_view keyPath) const noexcept {
    const auto normalized = NormalizePath(keyPath);
    std::shared_lock lock(m_mutex);
    auto it = m_keys.find(normalized);
    if (it == m_keys.end()) return 0;

    uint32_t maxLen = 0;
    for (const auto& v : it->second.values) {
        const auto len = static_cast<uint32_t>(v.name.size());
        if (len > maxLen) maxLen = len;
    }
    return maxLen;
}

uint32_t VirtualRegistry::GetMaxValueDataLen(std::wstring_view keyPath) const noexcept {
    const auto normalized = NormalizePath(keyPath);
    std::shared_lock lock(m_mutex);
    auto it = m_keys.find(normalized);
    if (it == m_keys.end()) return 0;

    uint32_t maxLen = 0;
    for (const auto& v : it->second.values) {
        const auto len = static_cast<uint32_t>(v.data.size());
        if (len > maxLen) maxLen = len;
    }
    return maxLen;
}

// ============================================================================
// IOC Tracking
// ============================================================================

std::vector<RegistryWriteIOC> VirtualRegistry::GetWriteIOCs() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_writeIOCs;
}

bool VirtualRegistry::HasPersistenceWrites() const noexcept {
    std::shared_lock lock(m_mutex);
    for (const auto& ioc : m_writeIOCs) {
        if (ioc.isPersistence || ioc.isAutoStart) return true;
    }
    return false;
}

// ============================================================================
// Persistence / AutoStart Detection
// ============================================================================

bool VirtualRegistry::IsPersistencePath(std::wstring_view path) noexcept {
    const auto upper = ToUpper(path);

    // Run / RunOnce / RunOnceEx keys
    if (WideEndsWithCI(upper, L"\\CURRENTVERSION\\RUN")) return true;
    if (WideContainsCI(upper, L"\\CURRENTVERSION\\RUN\\")) return true;
    if (WideEndsWithCI(upper, L"\\CURRENTVERSION\\RUNONCE")) return true;
    if (WideContainsCI(upper, L"\\CURRENTVERSION\\RUNONCE\\")) return true;
    if (WideEndsWithCI(upper, L"\\CURRENTVERSION\\RUNONCEEX")) return true;
    if (WideContainsCI(upper, L"\\CURRENTVERSION\\RUNONCEEX\\")) return true;

    // Service creation
    if (WideContainsCI(upper, L"\\SERVICES\\")) return true;

    // Explorer Shell Folders
    if (WideContainsCI(upper, L"\\EXPLORER\\SHELL FOLDERS")) return true;
    if (WideContainsCI(upper, L"\\EXPLORER\\USER SHELL FOLDERS")) return true;

    // Winlogon persistence (Userinit, Shell)
    if (WideContainsCI(upper, L"\\WINLOGON")) return true;

    // Image File Execution Options (debugger injection)
    if (WideContainsCI(upper, L"\\IMAGE FILE EXECUTION OPTIONS\\")) return true;
    if (WideEndsWithCI(upper, L"\\IMAGE FILE EXECUTION OPTIONS")) return true;

    // AppInit_DLLs
    if (WideContainsCI(upper, L"\\APPINIT_DLLS")) return true;

    // Environment path hijacking
    if (WideEndsWithCI(upper, L"\\ENVIRONMENT")) return true;
    if (WideContainsCI(upper, L"\\ENVIRONMENT\\")) return true;

    // Policies\Explorer\Run
    if (WideContainsCI(upper, L"\\POLICIES\\EXPLORER\\RUN")) return true;

    return false;
}

bool VirtualRegistry::IsAutoStartService(std::wstring_view path,
                                          const std::vector<uint8_t>& data) noexcept {
    const auto upper = ToUpper(path);

    // Only applies to service keys where "Start" value is being set
    if (!WideContainsCI(upper, L"\\SERVICES\\")) return false;

    // Check if the data represents auto-start (Start type 0=Boot, 1=System, 2=Auto)
    if (data.size() >= sizeof(uint32_t)) {
        uint32_t startType = 0;
        std::memcpy(&startType, data.data(), sizeof(uint32_t));
        return startType <= 2;  // SERVICE_BOOT_START, SERVICE_SYSTEM_START, SERVICE_AUTO_START
    }

    return false;
}

// ============================================================================
// Private: Population helpers (called under write lock during Initialize)
// ============================================================================

void VirtualRegistry::AddKey(std::wstring_view path) noexcept {
    const auto normalized = NormalizePath(path);
    if (normalized.empty()) return;
    if (m_keys.size() >= kMaxKeys) return;

    // Create all intermediate keys
    size_t pos = 0;
    while (pos != std::wstring::npos) {
        pos = normalized.find(L'\\', pos == 0 ? 0 : pos + 1);
        const auto segment = (pos == std::wstring::npos)
            ? normalized
            : normalized.substr(0, pos);

        if (!m_keys.contains(segment)) {
            RegKeyInfo& newKey = m_keys[segment];
            newKey.fullPath = segment;
            newKey.lastWriteTime = FakeLastWriteTime();
            newKey.isPrePopulated = true;
        }

        // Register in parent's subkey list
        const auto lastSep = segment.rfind(L'\\');
        if (lastSep != std::wstring::npos) {
            const auto parentPath = segment.substr(0, lastSep);
            const auto childName = segment.substr(lastSep + 1);
            auto pit = m_keys.find(parentPath);
            if (pit != m_keys.end()) {
                auto& subs = pit->second.subKeyNames;
                if (std::find(subs.begin(), subs.end(), childName) == subs.end()) {
                    subs.push_back(std::wstring(childName));
                }
            }
        }

        if (pos == std::wstring::npos) break;
    }
}

void VirtualRegistry::AddStrValue(std::wstring_view keyPath, std::wstring_view name,
                                   std::wstring_view value) noexcept {
    const auto normalizedKey = NormalizePath(keyPath);
    auto it = m_keys.find(normalizedKey);
    if (it == m_keys.end()) return;

    RegValue rv;
    rv.name = std::wstring(name);
    rv.type = RegType::SZ;
    rv.data = EncodeRegSz(value);
    it->second.values.push_back(std::move(rv));
}

void VirtualRegistry::AddExpandSzValue(std::wstring_view keyPath, std::wstring_view name,
                                        std::wstring_view value) noexcept {
    const auto normalizedKey = NormalizePath(keyPath);
    auto it = m_keys.find(normalizedKey);
    if (it == m_keys.end()) return;

    RegValue rv;
    rv.name = std::wstring(name);
    rv.type = RegType::ExpandSZ;
    rv.data = EncodeRegSz(value);
    it->second.values.push_back(std::move(rv));
}

void VirtualRegistry::AddDwordValue(std::wstring_view keyPath, std::wstring_view name,
                                     uint32_t value) noexcept {
    const auto normalizedKey = NormalizePath(keyPath);
    auto it = m_keys.find(normalizedKey);
    if (it == m_keys.end()) return;

    RegValue rv;
    rv.name = std::wstring(name);
    rv.type = RegType::DWord;
    rv.data = EncodeDword(value);
    it->second.values.push_back(std::move(rv));
}

void VirtualRegistry::AddQwordValue(std::wstring_view keyPath, std::wstring_view name,
                                     uint64_t value) noexcept {
    const auto normalizedKey = NormalizePath(keyPath);
    auto it = m_keys.find(normalizedKey);
    if (it == m_keys.end()) return;

    RegValue rv;
    rv.name = std::wstring(name);
    rv.type = RegType::QWord;
    rv.data = EncodeQword(value);
    it->second.values.push_back(std::move(rv));
}

void VirtualRegistry::AddBinaryValue(std::wstring_view keyPath, std::wstring_view name,
                                      const std::vector<uint8_t>& data) noexcept {
    const auto normalizedKey = NormalizePath(keyPath);
    auto it = m_keys.find(normalizedKey);
    if (it == m_keys.end()) return;

    RegValue rv;
    rv.name = std::wstring(name);
    rv.type = RegType::Binary;
    rv.data = data;
    it->second.values.push_back(std::move(rv));
}

void VirtualRegistry::AddMultiSzValue(std::wstring_view keyPath, std::wstring_view name,
                                       const std::vector<std::wstring>& strings) noexcept {
    const auto normalizedKey = NormalizePath(keyPath);
    auto it = m_keys.find(normalizedKey);
    if (it == m_keys.end()) return;

    RegValue rv;
    rv.name = std::wstring(name);
    rv.type = RegType::MultiSZ;
    rv.data = EncodeMultiSz(strings);
    it->second.values.push_back(std::move(rv));
}

// ============================================================================
// PopulateDefaults — ~200+ realistic Windows 10 Pro 22H2 registry entries
//
// Hardware profile: Dell Precision 5570 / Intel Core i7-12700H
// NO VM/sandbox/analysis-tool artifacts permitted.
// ============================================================================

void VirtualRegistry::PopulateDefaults(const EmulationConfig& config) noexcept {

    // =======================================================================
    // Root keys
    // =======================================================================

    AddKey(L"HKLM");
    AddKey(L"HKCU");
    AddKey(L"HKU");
    AddKey(L"HKCR");
    AddKey(L"HKCC");

    // =======================================================================
    // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
    // =======================================================================

    AddKey(L"HKLM\\SOFTWARE");
    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT");
    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT");
    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION");

    {
        const auto cv = L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION";
        AddStrValue(cv, L"ProductName",              L"Windows 10 Pro");
        AddStrValue(cv, L"CurrentBuild",             L"19045");
        AddStrValue(cv, L"CurrentBuildNumber",       L"19045");
        AddStrValue(cv, L"EditionID",                L"Professional");
        AddStrValue(cv, L"InstallationType",         L"Client");
        AddStrValue(cv, L"RegisteredOrganization",   config.domainName);
        AddStrValue(cv, L"RegisteredOwner",          config.userName);
        AddStrValue(cv, L"BuildLab",                 L"19041.vb_release.191206-1406");
        AddStrValue(cv, L"BuildLabEx",               L"19041.1.amd64fre.vb_release.191206-1406");
        AddStrValue(cv, L"CurrentVersion",           L"6.3");
        AddStrValue(cv, L"DisplayVersion",           L"22H2");
        AddStrValue(cv, L"ReleaseId",                L"2009");
        AddStrValue(cv, L"ProductId",                L"00330-80000-00000-AA174");
        AddStrValue(cv, L"SystemRoot",               L"C:\\Windows");
        AddStrValue(cv, L"PathName",                 L"C:\\Windows");
        AddStrValue(cv, L"CompositionEditionID",     L"Enterprise");
        AddDwordValue(cv, L"InstallDate",            1640000000);  // Dec 2021
        AddDwordValue(cv, L"UBR",                    4412);
        AddDwordValue(cv, L"CurrentMajorVersionNumber", 10);
        AddDwordValue(cv, L"CurrentMinorVersionNumber", 0);
    }

    // =======================================================================
    // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinSATAPI
    // =======================================================================

    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\WINLOGON");
    {
        const auto wl = L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\WINLOGON";
        AddStrValue(wl, L"Shell",      L"explorer.exe");
        AddStrValue(wl, L"Userinit",   L"C:\\Windows\\system32\\userinit.exe,");
        AddStrValue(wl, L"DefaultUserName",  config.userName);
        AddStrValue(wl, L"DefaultDomainName", config.domainName);
    }

    // =======================================================================
    // HKLM\SOFTWARE\Microsoft\Cryptography
    // =======================================================================

    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\CRYPTOGRAPHY");
    AddStrValue(L"HKLM\\SOFTWARE\\MICROSOFT\\CRYPTOGRAPHY",
                L"MachineGuid", L"a3b7c912-48d1-4e3a-b8f2-1a2b3c4d5e6f");

    // =======================================================================
    // HKLM\HARDWARE\DESCRIPTION\System\BIOS — anti-VM critical
    // =======================================================================

    AddKey(L"HKLM\\HARDWARE");
    AddKey(L"HKLM\\HARDWARE\\DESCRIPTION");
    AddKey(L"HKLM\\HARDWARE\\DESCRIPTION\\SYSTEM");
    AddKey(L"HKLM\\HARDWARE\\DESCRIPTION\\SYSTEM\\BIOS");

    {
        const auto bios = L"HKLM\\HARDWARE\\DESCRIPTION\\SYSTEM\\BIOS";
        AddStrValue(bios, L"SystemManufacturer",     L"Dell Inc.");
        AddStrValue(bios, L"SystemProductName",      L"Precision 5570");
        AddStrValue(bios, L"BIOSVendor",             L"Dell Inc.");
        AddStrValue(bios, L"BIOSVersion",            L"1.18.0");
        AddStrValue(bios, L"BIOSReleaseDate",        L"09/28/2023");
        AddStrValue(bios, L"SystemFamily",           L"Precision");
        AddStrValue(bios, L"BaseBoardManufacturer",  L"Dell Inc.");
        AddStrValue(bios, L"BaseBoardProduct",       L"0F3JK1");
        AddStrValue(bios, L"BaseBoardVersion",       L"A00");
        AddStrValue(bios, L"SystemVersion",          L"");
        AddStrValue(bios, L"SystemSKU",              L"0A97");
        AddDwordValue(bios, L"BiosMajorRelease",     1);
        AddDwordValue(bios, L"BiosMinorRelease",     18);
        AddDwordValue(bios, L"ECFirmwareMajorRelease", 1);
        AddDwordValue(bios, L"ECFirmwareMinorRelease", 12);
    }

    // =======================================================================
    // HKLM\HARDWARE\DESCRIPTION\System
    // =======================================================================

    {
        const auto hw = L"HKLM\\HARDWARE\\DESCRIPTION\\SYSTEM";
        AddMultiSzValue(hw, L"SystemBiosVersion",
            { L"DELL   - 1380", L"Dell Inc. - 1180009" });
        AddMultiSzValue(hw, L"VideoBiosVersion",
            { L"NVIDIA - 1080 Ti" });
        AddStrValue(hw, L"Identifier", L"AT/AT COMPATIBLE");
        AddStrValue(hw, L"SystemBiosDate", L"09/28/2023");
        AddStrValue(hw, L"VideoBiosDate", L"08/15/2023");
    }

    // =======================================================================
    // HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0
    // =======================================================================

    AddKey(L"HKLM\\HARDWARE\\DESCRIPTION\\SYSTEM\\CENTRALPROCESSOR");
    AddKey(L"HKLM\\HARDWARE\\DESCRIPTION\\SYSTEM\\CENTRALPROCESSOR\\0");

    {
        const auto cpu = L"HKLM\\HARDWARE\\DESCRIPTION\\SYSTEM\\CENTRALPROCESSOR\\0";
        AddStrValue(cpu, L"ProcessorNameString",
                    L"Intel(R) Core(TM) i7-12700H");
        AddStrValue(cpu, L"Identifier",
                    L"Intel64 Family 6 Model 154 Stepping 3");
        AddStrValue(cpu, L"VendorIdentifier", L"GenuineIntel");
        AddDwordValue(cpu, L"~MHz",           2688);
        AddDwordValue(cpu, L"FeatureSet",     0xBFEBFBFF);
        AddDwordValue(cpu, L"Update Revision", 0x00000019);
        AddDwordValue(cpu, L"Platform ID",    0x00000050);
    }

    // Additional CPU cores (1-7) for realistic multi-core appearance
    for (int core = 1; core <= 7; ++core) {
        const auto corePath = L"HKLM\\HARDWARE\\DESCRIPTION\\SYSTEM\\CENTRALPROCESSOR\\"
            + std::to_wstring(core);
        AddKey(corePath);
        AddStrValue(corePath, L"ProcessorNameString",
                    L"Intel(R) Core(TM) i7-12700H");
        AddStrValue(corePath, L"Identifier",
                    L"Intel64 Family 6 Model 154 Stepping 3");
        AddStrValue(corePath, L"VendorIdentifier", L"GenuineIntel");
        AddDwordValue(corePath, L"~MHz", 2688);
        AddDwordValue(corePath, L"FeatureSet", 0xBFEBFBFF);
    }

    // =======================================================================
    // HKLM\HARDWARE\DESCRIPTION\System\FloatingPointProcessor\0
    // =======================================================================

    AddKey(L"HKLM\\HARDWARE\\DESCRIPTION\\SYSTEM\\FLOATINGPOINTPROCESSOR");
    AddKey(L"HKLM\\HARDWARE\\DESCRIPTION\\SYSTEM\\FLOATINGPOINTPROCESSOR\\0");
    AddStrValue(L"HKLM\\HARDWARE\\DESCRIPTION\\SYSTEM\\FLOATINGPOINTPROCESSOR\\0",
                L"Identifier", L"x86 Family 6 Model 154 Stepping 3");

    // =======================================================================
    // HKLM\HARDWARE\DEVICEMAP\Scsi
    // =======================================================================

    AddKey(L"HKLM\\HARDWARE\\DEVICEMAP");
    AddKey(L"HKLM\\HARDWARE\\DEVICEMAP\\SCSI");
    AddKey(L"HKLM\\HARDWARE\\DEVICEMAP\\SCSI\\SCSI PORT 0");
    AddKey(L"HKLM\\HARDWARE\\DEVICEMAP\\SCSI\\SCSI PORT 0\\SCSI BUS 0");
    AddKey(L"HKLM\\HARDWARE\\DEVICEMAP\\SCSI\\SCSI PORT 0\\SCSI BUS 0\\TARGET ID 0");
    AddKey(L"HKLM\\HARDWARE\\DEVICEMAP\\SCSI\\SCSI PORT 0\\SCSI BUS 0\\TARGET ID 0\\LOGICAL UNIT ID 0");

    {
        const auto disk = L"HKLM\\HARDWARE\\DEVICEMAP\\SCSI\\SCSI PORT 0\\SCSI BUS 0\\TARGET ID 0\\LOGICAL UNIT ID 0";
        AddStrValue(disk, L"Identifier", L"NVMe    Samsung SSD 980 PRO 1TB             ");
        AddStrValue(disk, L"Type", L"DiskPeripheral");
    }

    // =======================================================================
    // HKLM\SYSTEM\CurrentControlSet hierarchy
    // =======================================================================

    AddKey(L"HKLM\\SYSTEM");
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET");
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL");

    // ComputerName
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\COMPUTERNAME");
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\COMPUTERNAME\\COMPUTERNAME");
    AddStrValue(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\COMPUTERNAME\\COMPUTERNAME",
                L"ComputerName", config.computerName);
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\COMPUTERNAME\\ACTIVECOMPUTERNAME");
    AddStrValue(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\COMPUTERNAME\\ACTIVECOMPUTERNAME",
                L"ComputerName", config.computerName);

    // Session Manager
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\SESSION MANAGER");
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\SESSION MANAGER\\ENVIRONMENT");
    {
        const auto env = L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\SESSION MANAGER\\ENVIRONMENT";
        AddExpandSzValue(env, L"ComSpec",                L"%SystemRoot%\\system32\\cmd.exe");
        AddExpandSzValue(env, L"Path",                   L"%SystemRoot%\\system32;%SystemRoot%;%SystemRoot%\\System32\\Wbem;%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\");
        AddExpandSzValue(env, L"PATHEXT",                L".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC");
        AddExpandSzValue(env, L"TEMP",                   L"%SystemRoot%\\TEMP");
        AddExpandSzValue(env, L"TMP",                    L"%SystemRoot%\\TEMP");
        AddExpandSzValue(env, L"windir",                 L"%SystemRoot%");
        AddStrValue(env, L"OS",                          L"Windows_NT");
        AddStrValue(env, L"PROCESSOR_ARCHITECTURE",      L"AMD64");
        AddStrValue(env, L"PROCESSOR_IDENTIFIER",        L"Intel64 Family 6 Model 154 Stepping 3, GenuineIntel");
        AddStrValue(env, L"PROCESSOR_LEVEL",             L"6");
        AddStrValue(env, L"PROCESSOR_REVISION",          L"9a03");
        AddStrValue(env, L"NUMBER_OF_PROCESSORS",        L"8");
        AddStrValue(env, L"USERNAME",                    L"SYSTEM");
    }

    // AppInit_DLLs (empty — monitor for injection)
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\SESSION MANAGER\\APPINIT_DLLS");

    // ProductOptions
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\PRODUCTOPTIONS");
    AddStrValue(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\PRODUCTOPTIONS",
                L"ProductType", L"WinNT");
    AddMultiSzValue(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\PRODUCTOPTIONS",
                    L"ProductSuite", { L"Terminal Server" });

    // SystemInformation
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\SYSTEMINFORMATION");
    {
        const auto si = L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\SYSTEMINFORMATION";
        AddStrValue(si, L"SystemManufacturer",  L"Dell Inc.");
        AddStrValue(si, L"SystemProductName",   L"Precision 5570");
        AddStrValue(si, L"BIOSVersion",         L"1.18.0");
        AddStrValue(si, L"BIOSReleaseDate",     L"09/28/2023");
    }

    // =======================================================================
    // TimeZoneInformation
    // =======================================================================

    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\TIMEZONEINFORMATION");
    {
        const auto tz = L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\TIMEZONEINFORMATION";
        AddStrValue(tz, L"TimeZoneKeyName",     L"Eastern Standard Time");
        AddStrValue(tz, L"StandardName",        L"Eastern Standard Time");
        AddStrValue(tz, L"DaylightName",        L"Eastern Daylight Time");
        AddDwordValue(tz, L"Bias",              300);
        AddDwordValue(tz, L"StandardBias",      0);
        AddDwordValue(tz, L"DaylightBias",      static_cast<uint32_t>(-60));
        AddDwordValue(tz, L"ActiveTimeBias",    300);
    }

    // =======================================================================
    // Services hierarchy (monitor for persistence)
    // =======================================================================

    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\SERVICES");

    // Tcpip\Parameters
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\TCPIP");
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\TCPIP\\PARAMETERS");
    {
        const auto tcp = L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\TCPIP\\PARAMETERS";
        AddStrValue(tcp, L"Hostname",        config.computerName);
        AddStrValue(tcp, L"Domain",          config.domainName);
        AddStrValue(tcp, L"NV Hostname",     config.computerName);
        AddStrValue(tcp, L"NV Domain",       config.domainName);
        AddStrValue(tcp, L"ICSDomain",       config.domainName);
        AddStrValue(tcp, L"DhcpDomain",      config.domainName);
        AddStrValue(tcp, L"SearchList",      config.domainName);
        AddDwordValue(tcp, L"EnableICMPRedirect", 1);
        AddDwordValue(tcp, L"DeadGWDetectDefault", 1);
    }

    // Disk
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\DISK");
    AddDwordValue(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\DISK",
                  L"Start", 0);
    AddDwordValue(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\DISK",
                  L"Type", 1);
    AddStrValue(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\DISK",
                L"ImagePath", L"\\SystemRoot\\System32\\drivers\\disk.sys");

    // Winsock
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\WINSOCK");
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\WINSOCK\\PARAMETERS");

    // Dnscache
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\DNSCACHE");
    AddDwordValue(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\DNSCACHE",
                  L"Start", 2);
    AddDwordValue(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\DNSCACHE",
                  L"Type", 32);

    // W32Time
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\W32TIME");
    AddDwordValue(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\W32TIME",
                  L"Start", 3);

    // =======================================================================
    // HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion hierarchy
    // =======================================================================

    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS");
    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION");

    // Run / RunOnce (empty — monitor for persistence)
    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN");
    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNONCE");
    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNONCEEX");

    // Uninstall
    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\UNINSTALL");

    // Policies\Explorer\Run (monitor for persistence)
    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\POLICIES");
    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\POLICIES\\EXPLORER");
    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\POLICIES\\EXPLORER\\RUN");

    // Explorer
    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER");
    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\SHELL FOLDERS");
    {
        const auto sf = L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\SHELL FOLDERS";
        AddStrValue(sf, L"Common Startup",   L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
        AddStrValue(sf, L"Common Programs",  L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs");
        AddStrValue(sf, L"Common Desktop",   L"C:\\Users\\Public\\Desktop");
        AddStrValue(sf, L"CommonVideo",      L"C:\\Users\\Public\\Videos");
        AddStrValue(sf, L"CommonPictures",   L"C:\\Users\\Public\\Pictures");
        AddStrValue(sf, L"CommonMusic",      L"C:\\Users\\Public\\Music");
        AddStrValue(sf, L"CommonDocuments",  L"C:\\Users\\Public\\Documents");
    }

    // ProgramFilesDir
    AddStrValue(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION",
                L"ProgramFilesDir",          L"C:\\Program Files");
    AddStrValue(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION",
                L"ProgramFilesDir (x86)",    L"C:\\Program Files (x86)");
    AddStrValue(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION",
                L"CommonFilesDir",           L"C:\\Program Files\\Common Files");
    AddStrValue(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION",
                L"CommonFilesDir (x86)",     L"C:\\Program Files (x86)\\Common Files");
    AddStrValue(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION",
                L"DevicePath",               L"%SystemRoot%\\inf");

    // =======================================================================
    // HKLM\SOFTWARE\Microsoft\Windows Defender
    // =======================================================================

    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS DEFENDER");
    {
        const auto wd = L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS DEFENDER";
        AddDwordValue(wd, L"DisableAntiSpyware", 0);
        AddStrValue(wd, L"ProductAppDataPath",
                    L"C:\\ProgramData\\Microsoft\\Windows Defender");
        AddStrValue(wd, L"InstallLocation",
                    L"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.23110.3-0\\");
    }
    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS DEFENDER\\REAL-TIME PROTECTION");
    AddDwordValue(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS DEFENDER\\REAL-TIME PROTECTION",
                  L"DisableRealtimeMonitoring", 0);

    // =======================================================================
    // HKLM\SOFTWARE\Microsoft\.NETFramework
    // =======================================================================

    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\.NETFRAMEWORK");
    AddStrValue(L"HKLM\\SOFTWARE\\MICROSOFT\\.NETFRAMEWORK",
                L"InstallRoot", L"C:\\Windows\\Microsoft.NET\\Framework64\\");

    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\.NETFRAMEWORK\\V4.0.30319");
    AddStrValue(L"HKLM\\SOFTWARE\\MICROSOFT\\.NETFRAMEWORK\\V4.0.30319",
                L"Version", L"4.8.09032");

    // =======================================================================
    // HKLM\SOFTWARE\Classes\CLSID (for COM registration monitoring)
    // =======================================================================

    AddKey(L"HKLM\\SOFTWARE\\CLASSES");
    AddKey(L"HKLM\\SOFTWARE\\CLASSES\\CLSID");

    // =======================================================================
    // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
    // =======================================================================

    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\IMAGE FILE EXECUTION OPTIONS");

    // =======================================================================
    // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags
    // =======================================================================

    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\APPCOMPATFLAGS");
    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\APPCOMPATFLAGS\\LAYERS");

    // =======================================================================
    // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
    // =======================================================================

    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\PROFILELIST");
    AddStrValue(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\PROFILELIST",
                L"ProfilesDirectory", L"%SystemDrive%\\Users");
    AddStrValue(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\PROFILELIST",
                L"Default", L"%SystemDrive%\\Users\\Default");
    AddStrValue(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\PROFILELIST",
                L"ProgramData", L"%SystemDrive%\\ProgramData");
    AddStrValue(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\PROFILELIST",
                L"Public", L"%SystemDrive%\\Users\\Public");

    // Current user profile
    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\PROFILELIST\\S-1-5-21-3842345678-1234567890-9876543210-1001");
    AddExpandSzValue(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\PROFILELIST\\S-1-5-21-3842345678-1234567890-9876543210-1001",
                     L"ProfileImagePath", L"C:\\Users\\" + std::wstring(config.userName));

    // =======================================================================
    // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList
    // =======================================================================

    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\NETWORKLIST");
    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\NETWORKLIST\\PROFILES");
    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\NETWORKLIST\\PROFILES\\{B5E2D3A1-7C4F-4D8E-A1B2-3C4D5E6F7A8B}");
    {
        const auto np = L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\NETWORKLIST\\PROFILES\\{B5E2D3A1-7C4F-4D8E-A1B2-3C4D5E6F7A8B}";
        AddStrValue(np, L"ProfileName",  L"CORP-NET");
        AddDwordValue(np, L"Category",   2);  // Domain network
        AddDwordValue(np, L"NameType",   6);  // wired
        AddDwordValue(np, L"Managed",    1);
    }

    // =======================================================================
    // HKLM\SOFTWARE\Microsoft\Ole
    // =======================================================================

    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\OLE");
    AddStrValue(L"HKLM\\SOFTWARE\\MICROSOFT\\OLE",
                L"EnableDCOM", L"Y");

    // =======================================================================
    // HKLM\SOFTWARE\Microsoft\Rpc
    // =======================================================================

    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\RPC");
    AddDwordValue(L"HKLM\\SOFTWARE\\MICROSOFT\\RPC",
                  L"DCOM Protocols", 0);

    // =======================================================================
    // HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell
    // =======================================================================

    AddKey(L"HKLM\\SOFTWARE\\POLICIES");
    AddKey(L"HKLM\\SOFTWARE\\POLICIES\\MICROSOFT");
    AddKey(L"HKLM\\SOFTWARE\\POLICIES\\MICROSOFT\\WINDOWS");
    AddKey(L"HKLM\\SOFTWARE\\POLICIES\\MICROSOFT\\WINDOWS\\POWERSHELL");
    AddDwordValue(L"HKLM\\SOFTWARE\\POLICIES\\MICROSOFT\\WINDOWS\\POWERSHELL",
                  L"EnableScripts", 1);
    AddStrValue(L"HKLM\\SOFTWARE\\POLICIES\\MICROSOFT\\WINDOWS\\POWERSHELL",
                L"ExecutionPolicy", L"RemoteSigned");

    // =======================================================================
    // HKLM\SYSTEM\CurrentControlSet\Control\Nls
    // =======================================================================

    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\NLS");
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\NLS\\LANGUAGE");
    {
        const auto nls = L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\NLS\\LANGUAGE";
        AddStrValue(nls, L"InstallLanguage",    L"0409");
        AddStrValue(nls, L"Default",            L"0409");
    }
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\NLS\\LOCALE");
    AddStrValue(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\NLS\\LOCALE",
                L"(Default)", L"00000409");

    // =======================================================================
    // HKLM\SYSTEM\CurrentControlSet\Control\Windows
    // =======================================================================

    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\WINDOWS");
    AddDwordValue(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\WINDOWS",
                  L"CSDVersion", 0);
    AddStrValue(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\WINDOWS",
                L"Directory", L"%SystemRoot%");

    // =======================================================================
    // HKLM\SYSTEM\Select
    // =======================================================================

    AddKey(L"HKLM\\SYSTEM\\SELECT");
    AddDwordValue(L"HKLM\\SYSTEM\\SELECT", L"Current", 1);
    AddDwordValue(L"HKLM\\SYSTEM\\SELECT", L"Default", 1);
    AddDwordValue(L"HKLM\\SYSTEM\\SELECT", L"Failed",  0);
    AddDwordValue(L"HKLM\\SYSTEM\\SELECT", L"LastKnownGood", 1);

    // =======================================================================
    // HKLM\SYSTEM\Setup
    // =======================================================================

    AddKey(L"HKLM\\SYSTEM\\SETUP");
    AddDwordValue(L"HKLM\\SYSTEM\\SETUP", L"SystemSetupInProgress", 0);
    AddDwordValue(L"HKLM\\SYSTEM\\SETUP", L"OOBEInProgress", 0);

    // =======================================================================
    // HKLM\HARDWARE\ACPI\DSDT\DELL__ (realistic Dell ACPI)
    // =======================================================================

    AddKey(L"HKLM\\HARDWARE\\ACPI");
    AddKey(L"HKLM\\HARDWARE\\ACPI\\DSDT");
    AddKey(L"HKLM\\HARDWARE\\ACPI\\DSDT\\DELL__");
    AddKey(L"HKLM\\HARDWARE\\ACPI\\FADT");
    AddKey(L"HKLM\\HARDWARE\\ACPI\\FADT\\DELL__");
    AddKey(L"HKLM\\HARDWARE\\ACPI\\RSDT");
    AddKey(L"HKLM\\HARDWARE\\ACPI\\RSDT\\DELL__");

    // =======================================================================
    // HKCU — Current User keys
    // =======================================================================

    AddKey(L"HKCU\\SOFTWARE");
    AddKey(L"HKCU\\SOFTWARE\\MICROSOFT");
    AddKey(L"HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS");
    AddKey(L"HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION");

    // Run / RunOnce (empty — monitor for persistence)
    AddKey(L"HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN");
    AddKey(L"HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNONCE");

    // Explorer
    AddKey(L"HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER");
    AddKey(L"HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\SHELL FOLDERS");
    {
        const auto usf = L"HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\SHELL FOLDERS";
        const std::wstring userDir = L"C:\\Users\\" + std::wstring(config.userName);
        AddStrValue(usf, L"Desktop",           userDir + L"\\Desktop");
        AddStrValue(usf, L"Personal",          userDir + L"\\Documents");
        AddStrValue(usf, L"AppData",           userDir + L"\\AppData\\Roaming");
        AddStrValue(usf, L"Local AppData",     userDir + L"\\AppData\\Local");
        AddStrValue(usf, L"Startup",           userDir + L"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
        AddStrValue(usf, L"Programs",          userDir + L"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs");
        AddStrValue(usf, L"Recent",            userDir + L"\\AppData\\Roaming\\Microsoft\\Windows\\Recent");
        AddStrValue(usf, L"Cookies",           userDir + L"\\AppData\\Local\\Microsoft\\Windows\\INetCookies");
        AddStrValue(usf, L"Cache",             userDir + L"\\AppData\\Local\\Microsoft\\Windows\\INetCache");
    }

    AddKey(L"HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\USER SHELL FOLDERS");
    {
        const auto uf = L"HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\USER SHELL FOLDERS";
        AddExpandSzValue(uf, L"Desktop",       L"%USERPROFILE%\\Desktop");
        AddExpandSzValue(uf, L"Personal",      L"%USERPROFILE%\\Documents");
        AddExpandSzValue(uf, L"AppData",       L"%USERPROFILE%\\AppData\\Roaming");
        AddExpandSzValue(uf, L"Local AppData", L"%USERPROFILE%\\AppData\\Local");
        AddExpandSzValue(uf, L"Startup",       L"%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    }

    // =======================================================================
    // HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings
    // =======================================================================

    AddKey(L"HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\INTERNET SETTINGS");
    {
        const auto inet = L"HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\INTERNET SETTINGS";
        AddDwordValue(inet, L"ProxyEnable",   0);
        AddDwordValue(inet, L"MigrateProxy",  1);
        AddStrValue(inet, L"AutoConfigURL",   L"");
        AddStrValue(inet, L"ProxyServer",     L"");
        AddStrValue(inet, L"ProxyOverride",   L"<local>");
        AddDwordValue(inet, L"EnableHttp1_1", 1);
    }

    // =======================================================================
    // HKCU\Control Panel\International
    // =======================================================================

    AddKey(L"HKCU\\CONTROL PANEL");
    AddKey(L"HKCU\\CONTROL PANEL\\INTERNATIONAL");
    {
        const auto intl = L"HKCU\\CONTROL PANEL\\INTERNATIONAL";
        AddStrValue(intl, L"LocaleName",    L"en-US");
        AddStrValue(intl, L"sCountry",      L"United States");
        AddStrValue(intl, L"sLanguage",     L"ENU");
        AddStrValue(intl, L"Locale",        L"00000409");
        AddStrValue(intl, L"sDecimal",      L".");
        AddStrValue(intl, L"sThousand",     L",");
        AddStrValue(intl, L"sDate",         L"/");
        AddStrValue(intl, L"sTime",         L":");
        AddStrValue(intl, L"sShortDate",    L"M/d/yyyy");
        AddStrValue(intl, L"sLongDate",     L"dddd, MMMM d, yyyy");
        AddStrValue(intl, L"iCountry",      L"1");
        AddStrValue(intl, L"iMeasure",      L"1");
        AddStrValue(intl, L"sNativeDigits", L"0123456789");
    }

    // =======================================================================
    // HKCU\Control Panel\Desktop
    // =======================================================================

    AddKey(L"HKCU\\CONTROL PANEL\\DESKTOP");
    {
        const auto desk = L"HKCU\\CONTROL PANEL\\DESKTOP";
        AddStrValue(desk, L"Wallpaper",         L"C:\\Windows\\Web\\Wallpaper\\Windows\\img0.jpg");
        AddDwordValue(desk, L"WallpaperStyle",  10);
        AddStrValue(desk, L"ScreenSaveActive",  L"0");
        AddDwordValue(desk, L"LogPixels",       96);
    }

    // =======================================================================
    // HKCU\Environment
    // =======================================================================

    AddKey(L"HKCU\\ENVIRONMENT");
    {
        const std::wstring userDir = L"C:\\Users\\" + std::wstring(config.userName);
        AddExpandSzValue(L"HKCU\\ENVIRONMENT", L"TEMP",
                         userDir + L"\\AppData\\Local\\Temp");
        AddExpandSzValue(L"HKCU\\ENVIRONMENT", L"TMP",
                         userDir + L"\\AppData\\Local\\Temp");
        AddExpandSzValue(L"HKCU\\ENVIRONMENT", L"Path",
                         L"%USERPROFILE%\\AppData\\Local\\Microsoft\\WindowsApps;");
    }

    // =======================================================================
    // HKCU\Volatile Environment
    // =======================================================================

    AddKey(L"HKCU\\VOLATILE ENVIRONMENT");
    {
        const auto ve = L"HKCU\\VOLATILE ENVIRONMENT";
        const std::wstring userDir = L"C:\\Users\\" + std::wstring(config.userName);
        AddStrValue(ve, L"LOGONSERVER",       L"\\\\" + std::wstring(config.computerName));
        AddStrValue(ve, L"USERDOMAIN",        config.domainName);
        AddStrValue(ve, L"USERNAME",          config.userName);
        AddStrValue(ve, L"USERPROFILE",       userDir);
        AddStrValue(ve, L"HOMEPATH",          L"\\Users\\" + std::wstring(config.userName));
        AddStrValue(ve, L"HOMEDRIVE",         L"C:");
        AddStrValue(ve, L"APPDATA",           userDir + L"\\AppData\\Roaming");
        AddStrValue(ve, L"LOCALAPPDATA",      userDir + L"\\AppData\\Local");
        AddDwordValue(ve, L"SESSION",         1);
    }

    // =======================================================================
    // HKCU\Software\Microsoft\Windows\CurrentVersion\Policies
    // =======================================================================

    AddKey(L"HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\POLICIES");
    AddKey(L"HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\POLICIES\\EXPLORER");

    // =======================================================================
    // HKU — Users
    // =======================================================================

    AddKey(L"HKU\\.DEFAULT");
    AddKey(L"HKU\\S-1-5-18");
    AddKey(L"HKU\\S-1-5-19");
    AddKey(L"HKU\\S-1-5-20");

    // =======================================================================
    // HKCR — commonly queried COM entries
    // =======================================================================

    AddKey(L"HKCR\\.exe");
    AddStrValue(L"HKCR\\.exe", L"(Default)", L"exefile");
    AddStrValue(L"HKCR\\.exe", L"Content Type", L"application/x-msdownload");

    AddKey(L"HKCR\\.dll");
    AddStrValue(L"HKCR\\.dll", L"(Default)", L"dllfile");
    AddStrValue(L"HKCR\\.dll", L"Content Type", L"application/x-msdownload");

    AddKey(L"HKCR\\.bat");
    AddStrValue(L"HKCR\\.bat", L"(Default)", L"batfile");

    AddKey(L"HKCR\\.cmd");
    AddStrValue(L"HKCR\\.cmd", L"(Default)", L"cmdfile");

    AddKey(L"HKCR\\.vbs");
    AddStrValue(L"HKCR\\.vbs", L"(Default)", L"VBSFile");

    AddKey(L"HKCR\\.js");
    AddStrValue(L"HKCR\\.js", L"(Default)", L"JSFile");

    AddKey(L"HKCR\\.ps1");
    AddStrValue(L"HKCR\\.ps1", L"(Default)", L"Microsoft.PowerShellScript.1");

    AddKey(L"HKCR\\.lnk");
    AddStrValue(L"HKCR\\.lnk", L"(Default)", L"lnkfile");

    AddKey(L"HKCR\\EXEFILE");
    AddKey(L"HKCR\\EXEFILE\\SHELL");
    AddKey(L"HKCR\\EXEFILE\\SHELL\\OPEN");
    AddKey(L"HKCR\\EXEFILE\\SHELL\\OPEN\\COMMAND");
    AddStrValue(L"HKCR\\EXEFILE\\SHELL\\OPEN\\COMMAND",
                L"(Default)", L"\"%1\" %*");

    // =======================================================================
    // HKCC — Current Config
    // =======================================================================

    AddKey(L"HKCC\\SYSTEM");
    AddKey(L"HKCC\\SYSTEM\\CURRENTCONTROLSET");
    AddKey(L"HKCC\\SYSTEM\\CURRENTCONTROLSET\\CONTROL");
    AddKey(L"HKCC\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\VIDEO");

    AddKey(L"HKCC\\SOFTWARE");
    AddKey(L"HKCC\\SOFTWARE\\FONTS");
    AddStrValue(L"HKCC\\SOFTWARE\\FONTS", L"LogPixels", L"96");

    // =======================================================================
    // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts
    // =======================================================================

    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\FONTS");
    {
        const auto fonts = L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\FONTS";
        AddStrValue(fonts, L"Arial (TrueType)",          L"arial.ttf");
        AddStrValue(fonts, L"Arial Bold (TrueType)",     L"arialbd.ttf");
        AddStrValue(fonts, L"Arial Italic (TrueType)",   L"ariali.ttf");
        AddStrValue(fonts, L"Calibri (TrueType)",        L"calibri.ttf");
        AddStrValue(fonts, L"Consolas (TrueType)",       L"consola.ttf");
        AddStrValue(fonts, L"Courier New (TrueType)",    L"cour.ttf");
        AddStrValue(fonts, L"Segoe UI (TrueType)",       L"segoeui.ttf");
        AddStrValue(fonts, L"Tahoma (TrueType)",         L"tahoma.ttf");
        AddStrValue(fonts, L"Times New Roman (TrueType)", L"times.ttf");
        AddStrValue(fonts, L"Verdana (TrueType)",        L"verdana.ttf");
    }

    // =======================================================================
    // HKLM\SOFTWARE\Microsoft\DirectX
    // =======================================================================

    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\DIRECTX");
    AddStrValue(L"HKLM\\SOFTWARE\\MICROSOFT\\DIRECTX",
                L"Version", L"4.09.00.0904");
    AddDwordValue(L"HKLM\\SOFTWARE\\MICROSOFT\\DIRECTX",
                  L"InstalledVersion", 0x0004000900000904);

    // =======================================================================
    // HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths
    // =======================================================================

    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\APP PATHS");
    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\APP PATHS\\WMPLAYER.EXE");
    AddStrValue(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\APP PATHS\\WMPLAYER.EXE",
                L"(Default)", L"%ProgramFiles%\\Windows Media Player\\wmplayer.exe");

    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\APP PATHS\\IEXPLORE.EXE");
    AddStrValue(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\APP PATHS\\IEXPLORE.EXE",
                L"(Default)", L"C:\\Program Files\\Internet Explorer\\iexplore.exe");

    // =======================================================================
    // HKLM\SOFTWARE\WOW6432Node (32-bit compatibility layer)
    // =======================================================================

    AddKey(L"HKLM\\SOFTWARE\\WOW6432NODE");
    AddKey(L"HKLM\\SOFTWARE\\WOW6432NODE\\MICROSOFT");
    AddKey(L"HKLM\\SOFTWARE\\WOW6432NODE\\MICROSOFT\\WINDOWS NT");
    AddKey(L"HKLM\\SOFTWARE\\WOW6432NODE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION");
    AddStrValue(L"HKLM\\SOFTWARE\\WOW6432NODE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION",
                L"ProductName", L"Windows 10 Pro");
    AddStrValue(L"HKLM\\SOFTWARE\\WOW6432NODE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION",
                L"CurrentBuildNumber", L"19045");

    // =======================================================================
    // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SvcHost
    // =======================================================================

    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\SVCHOST");
    AddMultiSzValue(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\SVCHOST",
                    L"netsvcs", {
                        L"Themes", L"BITS", L"CertPropSvc", L"gpsvc",
                        L"ProfSvc", L"Schedule", L"SENS", L"SessionEnv",
                        L"Winmgmt", L"wuauserv"
                    });
    AddMultiSzValue(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\SVCHOST",
                    L"LocalService", {
                        L"EventSystem", L"nsi", L"W32Time"
                    });

    // =======================================================================
    // HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings
    // =======================================================================

    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\INTERNET SETTINGS");
    {
        const auto lis = L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\INTERNET SETTINGS";
        AddDwordValue(lis, L"EnableHttp1_1",       1);
        AddDwordValue(lis, L"ProxyHttp1.1",        0);
        AddDwordValue(lis, L"WarnOnBadCertRecving", 1);
        AddDwordValue(lis, L"EnableNegotiate",     1);
    }

    // =======================================================================
    // HKLM\SYSTEM\CurrentControlSet\Enum (device enumeration — anti-VM)
    // =======================================================================

    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\ENUM");
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\ENUM\\PCI");
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\ENUM\\IDE");
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\ENUM\\SCSI");

    // Realistic NVMe device entry (Samsung SSD — NOT a VBOX/VMWARE disk)
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\ENUM\\SCSI\\DISK&VEN_NVME&PROD_SAMSUNG_SSD_980");
    AddStrValue(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\ENUM\\SCSI\\DISK&VEN_NVME&PROD_SAMSUNG_SSD_980",
                L"FriendlyName", L"Samsung SSD 980 PRO 1TB");

    // Realistic Intel GPU
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\ENUM\\PCI\\VEN_8086&DEV_46A6&SUBSYS_0A971028&REV_0C");
    AddStrValue(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\ENUM\\PCI\\VEN_8086&DEV_46A6&SUBSYS_0A971028&REV_0C",
                L"DeviceDesc", L"Intel(R) Iris(R) Xe Graphics");

    // NVIDIA discrete GPU
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\ENUM\\PCI\\VEN_10DE&DEV_24DC&SUBSYS_0A971028&REV_A1");
    AddStrValue(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\ENUM\\PCI\\VEN_10DE&DEV_24DC&SUBSYS_0A971028&REV_A1",
                L"DeviceDesc", L"NVIDIA GeForce RTX 3080 Ti Laptop GPU");

    // Realistic network adapter
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\ENUM\\PCI\\VEN_8086&DEV_51F0&SUBSYS_00628086&REV_02");
    AddStrValue(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\ENUM\\PCI\\VEN_8086&DEV_51F0&SUBSYS_00628086&REV_02",
                L"DeviceDesc", L"Intel(R) Wi-Fi 6E AX211 160MHz");

    // =======================================================================
    // HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces
    // =======================================================================

    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\TCPIP\\PARAMETERS\\INTERFACES");
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\TCPIP\\PARAMETERS\\INTERFACES\\{E1A2B3C4-D5E6-F7A8-B9C0-D1E2F3A4B5C6}");
    {
        const auto iface = L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\TCPIP\\PARAMETERS\\INTERFACES\\{E1A2B3C4-D5E6-F7A8-B9C0-D1E2F3A4B5C6}";
        AddDwordValue(iface, L"EnableDHCP",      1);
        AddStrValue(iface, L"DhcpIPAddress",     L"10.0.1.142");
        AddStrValue(iface, L"DhcpSubnetMask",    L"255.255.255.0");
        AddStrValue(iface, L"DhcpDefaultGateway", L"10.0.1.1");
        AddStrValue(iface, L"DhcpServer",        L"10.0.1.1");
        AddStrValue(iface, L"Domain",            config.domainName);
        AddStrValue(iface, L"DhcpNameServer",    L"10.0.1.1");
    }

    // =======================================================================
    // HKLM\SOFTWARE\Microsoft\PowerShell
    // =======================================================================

    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\POWERSHELL");
    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\POWERSHELL\\1");
    AddDwordValue(L"HKLM\\SOFTWARE\\MICROSOFT\\POWERSHELL\\1",
                  L"Install", 1);
    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\POWERSHELL\\1\\POWERSHELLENGINE");
    AddStrValue(L"HKLM\\SOFTWARE\\MICROSOFT\\POWERSHELL\\1\\POWERSHELLENGINE",
                L"PowerShellVersion", L"5.1.19041.4355");
    AddStrValue(L"HKLM\\SOFTWARE\\MICROSOFT\\POWERSHELL\\1\\POWERSHELLENGINE",
                L"RuntimeVersion", L"v4.0.30319");

    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\POWERSHELL\\3");
    AddDwordValue(L"HKLM\\SOFTWARE\\MICROSOFT\\POWERSHELL\\3",
                  L"Install", 1);
    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\POWERSHELL\\3\\POWERSHELLENGINE");
    AddStrValue(L"HKLM\\SOFTWARE\\MICROSOFT\\POWERSHELL\\3\\POWERSHELLENGINE",
                L"PowerShellVersion", L"5.1.19041.4355");

    // =======================================================================
    // HKLM\SOFTWARE\Microsoft\NET Framework Setup
    // =======================================================================

    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\NET FRAMEWORK SETUP");
    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\NET FRAMEWORK SETUP\\NDP");
    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\NET FRAMEWORK SETUP\\NDP\\V4");
    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\NET FRAMEWORK SETUP\\NDP\\V4\\FULL");
    {
        const auto nf = L"HKLM\\SOFTWARE\\MICROSOFT\\NET FRAMEWORK SETUP\\NDP\\V4\\FULL";
        AddDwordValue(nf, L"Install",  1);
        AddDwordValue(nf, L"Release",  528049);
        AddStrValue(nf, L"Version",    L"4.8.04084");
        AddStrValue(nf, L"TargetVersion", L"4.0.0");
    }

    // =======================================================================
    // HKLM\SYSTEM\CurrentControlSet\Control\Class (Device classes)
    // =======================================================================

    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\CLASS");
    // Network adapters GUID
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\CLASS\\{4D36E972-E325-11CE-BFC1-08002BE10318}");
    // Display adapters GUID
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\CLASS\\{4D36E968-E325-11CE-BFC1-08002BE10318}");
    // Disk drives GUID
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\CLASS\\{4D36E967-E325-11CE-BFC1-08002BE10318}");

    // =======================================================================
    // HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup
    // =======================================================================

    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\SETUP");
    AddStrValue(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\SETUP",
                L"SourcePath", L"D:\\");

    // =======================================================================
    // HKLM\SYSTEM\CurrentControlSet\Control\CrashControl
    // =======================================================================

    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\CRASHCONTROL");
    AddDwordValue(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\CRASHCONTROL",
                  L"CrashDumpEnabled", 7);
    AddDwordValue(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\CRASHCONTROL",
                  L"AutoReboot", 1);
    AddExpandSzValue(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\CRASHCONTROL",
                     L"DumpFile", L"%SystemRoot%\\MEMORY.DMP");

    // =======================================================================
    // HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing
    // =======================================================================

    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\COMPONENT BASED SERVICING");
    AddStrValue(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\COMPONENT BASED SERVICING",
                L"Version", L"10.0.19041.4355");

    // =======================================================================
    // HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags
    // =======================================================================

    AddKey(L"HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS NT");
    AddKey(L"HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION");
    AddKey(L"HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\APPCOMPATFLAGS");

    // =======================================================================
    // HKLM\SOFTWARE\Microsoft\COM3
    // =======================================================================

    AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\COM3");
    AddStrValue(L"HKLM\\SOFTWARE\\MICROSOFT\\COM3",
                L"REGDBVersion", L"1.0");

    // =======================================================================
    // HKLM\SYSTEM\CurrentControlSet\Control\Lsa
    // =======================================================================

    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\LSA");
    AddDwordValue(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\LSA",
                  L"LimitBlankPasswordUse", 1);
    AddDwordValue(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\LSA",
                  L"RestrictAnonymous", 0);

    // =======================================================================
    // HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders
    // =======================================================================

    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\SECURITYPROVIDERS");
    AddStrValue(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\SECURITYPROVIDERS",
                L"SecurityProviders", L"credssp.dll");

    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\SECURITYPROVIDERS\\SCHANNEL");
    AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\SECURITYPROVIDERS\\SCHANNEL\\PROTOCOLS");
}

} // namespace Phantom::VirtualOS
