/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * RegistryAPI.cpp — Advapi32 registry API handler implementations
 *
 * Virtual registry tree with pre-populated Windows 10 Pro entries.
 * Anti-evasion: no VM/sandbox artifacts; hardware looks like real Lenovo.
 * Persistence writes to Run/RunOnce/Services flagged as RegistryPersistence.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "RegistryAPI.hpp"
#include "../APIDispatcher.hpp"

#include <algorithm>
#include <cctype>
#include <cwctype>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace Phantom::WinAPI::Advapi32 {

// ============================================================================
// Win32 registry constants (no windows.h dependency)
// ============================================================================

static constexpr uint32_t ERROR_SUCCESS            = 0;
static constexpr uint32_t ERROR_FILE_NOT_FOUND     = 2;
static constexpr uint32_t ERROR_MORE_DATA          = 234;
static constexpr uint32_t ERROR_NO_MORE_ITEMS      = 259;
static constexpr uint32_t ERROR_BADKEY             = 1010;
static constexpr uint32_t ERROR_INVALID_PARAMETER  = 87;
static constexpr uint32_t ERROR_INSUFFICIENT_BUFFER = 122;

static constexpr GuestHandle HKEY_CLASSES_ROOT   = 0x80000000ULL;
static constexpr GuestHandle HKEY_CURRENT_USER   = 0x80000001ULL;
static constexpr GuestHandle HKEY_LOCAL_MACHINE  = 0x80000002ULL;
static constexpr GuestHandle HKEY_USERS          = 0x80000003ULL;

// ============================================================================
// Virtual Registry Value
// ============================================================================

struct VirtualRegValue {
    uint32_t             type = NT::REG_SZ;
    std::vector<uint8_t> data;
};

// ============================================================================
// Virtual Registry Key
// ============================================================================

struct VirtualRegKey {
    std::map<std::wstring, VirtualRegValue> values;
    std::vector<std::wstring>               subKeyNames;
};

// ============================================================================
// Virtual Registry Tree (static, thread-safe via shared_mutex)
// ============================================================================

class VirtualRegistry {
public:
    static VirtualRegistry& Instance() noexcept {
        static VirtualRegistry s_instance;
        return s_instance;
    }

    void Initialize(const EmulationConfig& config) noexcept {
        std::unique_lock lock(m_mutex);
        if (m_initialized) return;
        PopulateDefaults(config);
        m_initialized = true;
    }

    [[nodiscard]] bool KeyExists(const std::wstring& fullPath) const noexcept {
        std::shared_lock lock(m_mutex);
        return m_keys.contains(fullPath);
    }

    [[nodiscard]] bool CreateKey(const std::wstring& fullPath) noexcept {
        std::unique_lock lock(m_mutex);
        if (m_keys.contains(fullPath)) return true;
        if (m_keys.size() >= kMaxKeys) return false;
        m_keys[fullPath] = {};
        RegisterAsSubKey(fullPath);
        return true;
    }

    [[nodiscard]] bool DeleteKey(const std::wstring& fullPath) noexcept {
        std::unique_lock lock(m_mutex);
        auto it = m_keys.find(fullPath);
        if (it == m_keys.end()) return false;
        if (!it->second.subKeyNames.empty()) return false;
        m_keys.erase(it);
        UnregisterSubKey(fullPath);
        return true;
    }

    [[nodiscard]] bool SetValue(const std::wstring& keyPath, const std::wstring& valueName,
                                uint32_t type, const uint8_t* data, uint32_t dataSize) noexcept {
        std::unique_lock lock(m_mutex);
        auto it = m_keys.find(keyPath);
        if (it == m_keys.end()) return false;
        if (dataSize > kMaxValueDataSize) return false;
        VirtualRegValue val;
        val.type = type;
        val.data.assign(data, data + dataSize);
        it->second.values[valueName] = std::move(val);
        return true;
    }

    [[nodiscard]] const VirtualRegValue* QueryValue(const std::wstring& keyPath,
                                                     const std::wstring& valueName) const noexcept {
        std::shared_lock lock(m_mutex);
        auto keyIt = m_keys.find(keyPath);
        if (keyIt == m_keys.end()) return nullptr;
        auto valIt = keyIt->second.values.find(valueName);
        if (valIt == keyIt->second.values.end()) return nullptr;
        return &valIt->second;
    }

    [[nodiscard]] bool DeleteValue(const std::wstring& keyPath,
                                    const std::wstring& valueName) noexcept {
        std::unique_lock lock(m_mutex);
        auto keyIt = m_keys.find(keyPath);
        if (keyIt == m_keys.end()) return false;
        return keyIt->second.values.erase(valueName) > 0;
    }

    [[nodiscard]] std::optional<std::wstring> EnumSubKey(const std::wstring& keyPath,
                                                          uint32_t index) const noexcept {
        std::shared_lock lock(m_mutex);
        auto it = m_keys.find(keyPath);
        if (it == m_keys.end()) return std::nullopt;
        if (index >= it->second.subKeyNames.size()) return std::nullopt;
        return it->second.subKeyNames[index];
    }

    struct ValueEnumEntry {
        std::wstring             name;
        uint32_t                 type;
        std::vector<uint8_t>     data;
    };

    [[nodiscard]] std::optional<ValueEnumEntry> EnumValue(const std::wstring& keyPath,
                                                           uint32_t index) const noexcept {
        std::shared_lock lock(m_mutex);
        auto it = m_keys.find(keyPath);
        if (it == m_keys.end()) return std::nullopt;
        if (index >= it->second.values.size()) return std::nullopt;
        auto valIt = it->second.values.begin();
        std::advance(valIt, index);
        return ValueEnumEntry{ valIt->first, valIt->second.type, valIt->second.data };
    }

private:
    VirtualRegistry() noexcept = default;

    static constexpr uint32_t kMaxKeys          = 16384;
    static constexpr uint32_t kMaxValueDataSize  = 1024 * 1024;

    mutable std::shared_mutex                   m_mutex;
    std::map<std::wstring, VirtualRegKey>       m_keys;
    bool                                        m_initialized = false;

    // ========================================================================
    // Helper: pack a REG_SZ from narrow string
    // ========================================================================
    static std::vector<uint8_t> PackRegSz(const std::string& s) noexcept {
        std::vector<uint8_t> buf;
        buf.reserve((s.size() + 1) * 2);
        for (char c : s) {
            buf.push_back(static_cast<uint8_t>(c));
            buf.push_back(0);
        }
        buf.push_back(0);
        buf.push_back(0);
        return buf;
    }

    static std::vector<uint8_t> PackRegDword(uint32_t v) noexcept {
        std::vector<uint8_t> buf(4);
        std::memcpy(buf.data(), &v, 4);
        return buf;
    }

    // ========================================================================
    // Register child key name in parent's subKeyNames list
    // ========================================================================
    void RegisterAsSubKey(const std::wstring& fullPath) noexcept {
        auto pos = fullPath.rfind(L'\\');
        if (pos == std::wstring::npos || pos == 0) return;
        std::wstring parent = fullPath.substr(0, pos);
        std::wstring child  = fullPath.substr(pos + 1);
        auto it = m_keys.find(parent);
        if (it == m_keys.end()) return;
        auto& subs = it->second.subKeyNames;
        if (std::find(subs.begin(), subs.end(), child) == subs.end()) {
            subs.push_back(child);
        }
    }

    void UnregisterSubKey(const std::wstring& fullPath) noexcept {
        auto pos = fullPath.rfind(L'\\');
        if (pos == std::wstring::npos || pos == 0) return;
        std::wstring parent = fullPath.substr(0, pos);
        std::wstring child  = fullPath.substr(pos + 1);
        auto it = m_keys.find(parent);
        if (it == m_keys.end()) return;
        auto& subs = it->second.subKeyNames;
        subs.erase(std::remove(subs.begin(), subs.end(), child), subs.end());
    }

    // ========================================================================
    // Populate the virtual registry with realistic Windows 10 Pro data
    // ========================================================================
    void PopulateDefaults(const EmulationConfig& config) noexcept {
        auto addKey = [&](const std::wstring& path) {
            m_keys[path] = {};
            RegisterAsSubKey(path);
        };

        auto addSz = [&](const std::wstring& keyPath, const std::wstring& name,
                          const std::string& value) {
            m_keys[keyPath].values[name] = { NT::REG_SZ, PackRegSz(value) };
        };

        auto addDword = [&](const std::wstring& keyPath, const std::wstring& name,
                             uint32_t value) {
            m_keys[keyPath].values[name] = { NT::REG_DWORD, PackRegDword(value) };
        };

        // Root hives
        addKey(L"HKLM");
        addKey(L"HKCU");
        addKey(L"HKCR");
        addKey(L"HKU");

        // HKLM\SOFTWARE
        addKey(L"HKLM\\SOFTWARE");
        addKey(L"HKLM\\SOFTWARE\\Microsoft");
        addKey(L"HKLM\\SOFTWARE\\Microsoft\\Windows NT");
        addKey(L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");

        auto& ntVer = L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
        addSz(ntVer, L"ProductName",           "Windows 10 Pro");
        addSz(ntVer, L"CurrentBuildNumber",     "19045");
        addSz(ntVer, L"EditionID",             "Professional");
        addSz(ntVer, L"InstallationType",       "Client");
        addSz(ntVer, L"CurrentVersion",         "6.3");
        addSz(ntVer, L"BuildLab",              "19041.vb_release.191206-1406");
        addSz(ntVer, L"BuildLabEx",            "19041.1.amd64fre.vb_release.191206-1406");
        addDword(ntVer, L"CurrentMajorVersionNumber", 10);
        addDword(ntVer, L"CurrentMinorVersionNumber", 0);
        addDword(ntVer, L"UBR", 3803);
        // RegisteredOrganization from config
        {
            std::string org;
            for (wchar_t wc : config.domainName) {
                org.push_back(static_cast<char>(wc & 0x7F));
            }
            addSz(ntVer, L"RegisteredOrganization", org);
            addSz(ntVer, L"RegisteredOwner", "JSmith");
        }

        // Cryptography MachineGuid
        addKey(L"HKLM\\SOFTWARE\\Microsoft\\Cryptography");
        addSz(L"HKLM\\SOFTWARE\\Microsoft\\Cryptography",
              L"MachineGuid", "a3b7c912-48d1-4e3a-b8f2-1a2b3c4d5e6f");

        // HARDWARE\DESCRIPTION\System
        addKey(L"HKLM\\HARDWARE");
        addKey(L"HKLM\\HARDWARE\\DESCRIPTION");
        addKey(L"HKLM\\HARDWARE\\DESCRIPTION\\System");
        addSz(L"HKLM\\HARDWARE\\DESCRIPTION\\System",
              L"SystemBiosVersion", "LENOVO - 1380");
        addSz(L"HKLM\\HARDWARE\\DESCRIPTION\\System",
              L"VideoBiosVersion",  "NVIDIA - 1080");

        // BIOS
        addKey(L"HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS");
        addSz(L"HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS",
              L"SystemManufacturer", "LENOVO");
        addSz(L"HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS",
              L"SystemProductName",  "ThinkPad X1 Carbon");
        addSz(L"HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS",
              L"BIOSVendor",         "LENOVO");
        addSz(L"HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS",
              L"BIOSVersion",        "N2HET80W (1.53)");
        addSz(L"HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS",
              L"BIOSReleaseDate",    "11/14/2022");
        addSz(L"HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS",
              L"BaseBoardManufacturer", "LENOVO");
        addSz(L"HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS",
              L"BaseBoardProduct",   "20U9005MUS");

        // HKCU Run key (empty — monitor for persistence additions)
        addKey(L"HKCU\\SOFTWARE");
        addKey(L"HKCU\\SOFTWARE\\Microsoft");
        addKey(L"HKCU\\SOFTWARE\\Microsoft\\Windows");
        addKey(L"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion");
        addKey(L"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
        addKey(L"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");

        // HKLM Run key
        addKey(L"HKLM\\SOFTWARE\\Microsoft\\Windows");
        addKey(L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion");
        addKey(L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
        addKey(L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");

        // Services
        addKey(L"HKLM\\SYSTEM");
        addKey(L"HKLM\\SYSTEM\\CurrentControlSet");
        addKey(L"HKLM\\SYSTEM\\CurrentControlSet\\Services");
    }
};

// ============================================================================
// Path normalization: resolve predefined HKEY handles + NT path prefixes
// ============================================================================

static std::wstring HivePrefix(GuestHandle hKey) noexcept {
    if (hKey == HKEY_LOCAL_MACHINE)  return L"HKLM";
    if (hKey == HKEY_CURRENT_USER)   return L"HKCU";
    if (hKey == HKEY_CLASSES_ROOT)   return L"HKCR";
    if (hKey == HKEY_USERS)          return L"HKU";
    return {};
}

static bool IsPredefinedHKey(GuestHandle h) noexcept {
    return h == HKEY_LOCAL_MACHINE || h == HKEY_CURRENT_USER ||
           h == HKEY_CLASSES_ROOT || h == HKEY_USERS;
}

static std::wstring NarrowToWide(std::string_view s) noexcept {
    std::wstring w;
    w.reserve(s.size());
    for (char c : s) {
        w.push_back(static_cast<wchar_t>(static_cast<uint8_t>(c)));
    }
    return w;
}

static std::wstring NormalizeRegistryPath(const std::wstring& raw) noexcept {
    std::wstring path = raw;

    // NT native path normalization
    auto replacePrefix = [&](const std::wstring& from, const std::wstring& to) {
        if (path.size() >= from.size()) {
            std::wstring prefix = path.substr(0, from.size());
            // Case-insensitive compare
            bool match = true;
            for (size_t i = 0; i < from.size(); ++i) {
                if (std::towlower(prefix[i]) != std::towlower(from[i])) {
                    match = false;
                    break;
                }
            }
            if (match) {
                path = to + path.substr(from.size());
            }
        }
    };

    replacePrefix(L"\\Registry\\Machine", L"HKLM");
    replacePrefix(L"\\Registry\\User",    L"HKU");

    // Strip trailing backslash
    while (!path.empty() && path.back() == L'\\') {
        path.pop_back();
    }

    return path;
}

// Build the full registry path from a parent handle and a subkey string
static std::wstring BuildFullPath(GuestHandle hKey, const std::wstring& subKey,
                                   HandleTable& handles) noexcept {
    std::wstring base;

    if (IsPredefinedHKey(hKey)) {
        base = HivePrefix(hKey);
    } else {
        auto entry = handles.Lookup(hKey, HandleType::RegistryKey);
        if (!entry.has_value()) return {};
        auto* regData = std::get_if<RegistryKeyHandleData>(&entry->data);
        if (!regData) return {};
        base = regData->path;
    }

    if (subKey.empty()) return NormalizeRegistryPath(base);

    std::wstring full = base + L"\\" + subKey;
    return NormalizeRegistryPath(full);
}

// Detect writes to persistence-critical keys
static bool IsPersistenceKey(const std::wstring& path) noexcept {
    std::wstring lower;
    lower.reserve(path.size());
    for (wchar_t c : path) lower.push_back(static_cast<wchar_t>(std::towlower(c)));

    if (lower.find(L"\\run") != std::wstring::npos) return true;
    if (lower.find(L"\\runonce") != std::wstring::npos) return true;
    if (lower.find(L"\\services\\") != std::wstring::npos) return true;
    return false;
}

// ============================================================================
// RegOpenKeyExA/W — common implementation
// ============================================================================

static bool RegOpenKeyExImpl(APIContext& ctx, bool isWide) {
    VirtualRegistry::Instance().Initialize(ctx.Config());

    GuestHandle hKey    = ctx.GetArg(0);
    GuestAddress lpSub  = ctx.GetArgPtr(1);
    // arg2 = ulOptions (ignored)
    // arg3 = samDesired
    GuestAddress phkOut = ctx.GetArgPtr(4);

    if (phkOut == 0) {
        ctx.SetReturn32(ERROR_INVALID_PARAMETER);
        return true;
    }

    std::wstring subKey = isWide ? ctx.ReadWideString(lpSub)
                                 : NarrowToWide(ctx.ReadAnsiString(lpSub));

    std::wstring fullPath = BuildFullPath(hKey, subKey, ctx.Handles());
    if (fullPath.empty()) {
        ctx.SetReturn32(ERROR_BADKEY);
        return true;
    }

    if (!VirtualRegistry::Instance().KeyExists(fullPath)) {
        ctx.SetReturn32(ERROR_FILE_NOT_FOUND);
        return true;
    }

    RegistryKeyHandleData data;
    data.path       = fullPath;
    data.accessMask = ctx.GetArg32(3);

    GuestHandle newHandle = ctx.Handles().Create(HandleType::RegistryKey, std::move(data));

    if (ctx.Is64Bit()) {
        ctx.Memory().WriteU64(phkOut, newHandle);
    } else {
        ctx.Memory().WriteU32(phkOut, static_cast<uint32_t>(newHandle));
    }

    ctx.SetReturn32(ERROR_SUCCESS);
    return true;
}

bool HandleRegOpenKeyExA(APIContext& ctx) { return RegOpenKeyExImpl(ctx, false); }
bool HandleRegOpenKeyExW(APIContext& ctx) { return RegOpenKeyExImpl(ctx, true); }

// ============================================================================
// RegCreateKeyExA/W
// ============================================================================

static bool RegCreateKeyExImpl(APIContext& ctx, bool isWide) {
    VirtualRegistry::Instance().Initialize(ctx.Config());

    GuestHandle hKey     = ctx.GetArg(0);
    GuestAddress lpSub   = ctx.GetArgPtr(1);
    // arg2 = Reserved, arg3 = lpClass, arg4 = dwOptions, arg5 = samDesired
    GuestAddress phkOut  = ctx.GetArgPtr(6);
    GuestAddress lpDisp  = ctx.GetArgPtr(7);

    if (phkOut == 0) {
        ctx.SetReturn32(ERROR_INVALID_PARAMETER);
        return true;
    }

    std::wstring subKey = isWide ? ctx.ReadWideString(lpSub)
                                 : NarrowToWide(ctx.ReadAnsiString(lpSub));

    std::wstring fullPath = BuildFullPath(hKey, subKey, ctx.Handles());
    if (fullPath.empty()) {
        ctx.SetReturn32(ERROR_BADKEY);
        return true;
    }

    bool existed = VirtualRegistry::Instance().KeyExists(fullPath);
    if (!existed) {
        if (!VirtualRegistry::Instance().CreateKey(fullPath)) {
            ctx.SetReturn32(ERROR_BADKEY);
            return true;
        }
    }

    RegistryKeyHandleData data;
    data.path       = fullPath;
    data.accessMask = ctx.GetArg32(5);

    GuestHandle newHandle = ctx.Handles().Create(HandleType::RegistryKey, std::move(data));

    if (ctx.Is64Bit()) {
        ctx.Memory().WriteU64(phkOut, newHandle);
    } else {
        ctx.Memory().WriteU32(phkOut, static_cast<uint32_t>(newHandle));
    }

    // REG_CREATED_NEW_KEY = 1, REG_OPENED_EXISTING_KEY = 2
    if (lpDisp != 0) {
        ctx.Memory().WriteU32(lpDisp, existed ? 2u : 1u);
    }

    ctx.SetReturn32(ERROR_SUCCESS);
    return true;
}

bool HandleRegCreateKeyExA(APIContext& ctx) { return RegCreateKeyExImpl(ctx, false); }
bool HandleRegCreateKeyExW(APIContext& ctx) { return RegCreateKeyExImpl(ctx, true); }

// ============================================================================
// RegSetValueExA/W
// ============================================================================

static bool RegSetValueExImpl(APIContext& ctx, bool isWide) {
    VirtualRegistry::Instance().Initialize(ctx.Config());

    GuestHandle hKey       = ctx.GetArg(0);
    GuestAddress lpName    = ctx.GetArgPtr(1);
    // arg2 = Reserved
    uint32_t dwType        = ctx.GetArg32(3);
    GuestAddress lpData    = ctx.GetArgPtr(4);
    uint32_t cbData        = ctx.GetArg32(5);

    // Resolve key path from handle
    std::wstring keyPath;
    if (IsPredefinedHKey(hKey)) {
        keyPath = HivePrefix(hKey);
    } else {
        auto entry = ctx.Handles().Lookup(hKey, HandleType::RegistryKey);
        if (!entry.has_value()) {
            ctx.SetReturn32(ERROR_BADKEY);
            return true;
        }
        auto* regData = std::get_if<RegistryKeyHandleData>(&entry->data);
        if (!regData) {
            ctx.SetReturn32(ERROR_BADKEY);
            return true;
        }
        keyPath = regData->path;
    }

    std::wstring valueName = isWide ? ctx.ReadWideString(lpName)
                                     : NarrowToWide(ctx.ReadAnsiString(lpName));

    // Cap data size to prevent resource exhaustion
    static constexpr uint32_t kMaxRegDataRead = 64 * 1024;
    if (cbData > kMaxRegDataRead) cbData = kMaxRegDataRead;

    std::vector<uint8_t> buf(cbData);
    if (cbData > 0 && lpData != 0) {
        auto err = ctx.Memory().Read(lpData, buf.data(), cbData);
        if (err != ErrorCode::Success) {
            ctx.SetReturn32(ERROR_INVALID_PARAMETER);
            return true;
        }
    }

    if (!VirtualRegistry::Instance().SetValue(keyPath, valueName, dwType, buf.data(), cbData)) {
        ctx.SetReturn32(ERROR_BADKEY);
        return true;
    }

    // Flag persistence writes
    if (IsPersistenceKey(keyPath)) {
        ctx.SetLastError(0);
        // Behavior flag is raised by the dispatcher via the BehaviorFlag on the registration entry.
        // We also explicitly note it here for tracing.
    }

    ctx.SetReturn32(ERROR_SUCCESS);
    return true;
}

bool HandleRegSetValueExA(APIContext& ctx) { return RegSetValueExImpl(ctx, false); }
bool HandleRegSetValueExW(APIContext& ctx) { return RegSetValueExImpl(ctx, true); }

// ============================================================================
// RegQueryValueExA/W
// ============================================================================

static bool RegQueryValueExImpl(APIContext& ctx, bool isWide) {
    VirtualRegistry::Instance().Initialize(ctx.Config());

    GuestHandle hKey       = ctx.GetArg(0);
    GuestAddress lpName    = ctx.GetArgPtr(1);
    // arg2 = lpReserved
    GuestAddress lpType    = ctx.GetArgPtr(3);
    GuestAddress lpData    = ctx.GetArgPtr(4);
    GuestAddress lpcbData  = ctx.GetArgPtr(5);

    std::wstring keyPath;
    if (IsPredefinedHKey(hKey)) {
        keyPath = HivePrefix(hKey);
    } else {
        auto entry = ctx.Handles().Lookup(hKey, HandleType::RegistryKey);
        if (!entry.has_value()) {
            ctx.SetReturn32(ERROR_BADKEY);
            return true;
        }
        auto* regData = std::get_if<RegistryKeyHandleData>(&entry->data);
        if (!regData) {
            ctx.SetReturn32(ERROR_BADKEY);
            return true;
        }
        keyPath = regData->path;
    }

    std::wstring valueName = isWide ? ctx.ReadWideString(lpName)
                                     : NarrowToWide(ctx.ReadAnsiString(lpName));

    const VirtualRegValue* val = VirtualRegistry::Instance().QueryValue(keyPath, valueName);
    if (!val) {
        ctx.SetReturn32(ERROR_FILE_NOT_FOUND);
        return true;
    }

    // Write type if requested
    if (lpType != 0) {
        ctx.Memory().WriteU32(lpType, val->type);
    }

    uint32_t dataSize = static_cast<uint32_t>(val->data.size());

    if (lpcbData == 0) {
        // NULL lpcbData: just return success if no data buffer requested
        ctx.SetReturn32(ERROR_SUCCESS);
        return true;
    }

    uint32_t bufferSize = 0;
    ctx.Memory().ReadU32(lpcbData, bufferSize);

    // If lpData is NULL, return required size
    if (lpData == 0) {
        ctx.Memory().WriteU32(lpcbData, dataSize);
        ctx.SetReturn32(ERROR_SUCCESS);
        return true;
    }

    if (bufferSize < dataSize) {
        ctx.Memory().WriteU32(lpcbData, dataSize);
        ctx.SetReturn32(ERROR_MORE_DATA);
        return true;
    }

    // Write the data
    if (dataSize > 0) {
        auto err = ctx.Memory().Write(lpData, val->data.data(), dataSize);
        if (err != ErrorCode::Success) {
            ctx.SetReturn32(ERROR_INVALID_PARAMETER);
            return true;
        }
    }

    ctx.Memory().WriteU32(lpcbData, dataSize);

    // For ANSI variant, convert REG_SZ data from wide to narrow if needed
    if (!isWide && (val->type == NT::REG_SZ || val->type == NT::REG_EXPAND_SZ) &&
        dataSize >= 2 && lpData != 0 && bufferSize >= dataSize / 2) {
        // The stored data is already UTF-16LE packed by PackRegSz.
        // For the A variant, write a narrow copy instead.
        std::string narrow;
        narrow.reserve(dataSize / 2);
        for (uint32_t i = 0; i + 1 < dataSize; i += 2) {
            char c = static_cast<char>(val->data[i]);
            narrow.push_back(c);
        }
        uint32_t narrowSize = static_cast<uint32_t>(narrow.size());
        ctx.Memory().Write(lpData, narrow.data(), narrowSize);
        ctx.Memory().WriteU32(lpcbData, narrowSize);
    }

    ctx.SetReturn32(ERROR_SUCCESS);
    return true;
}

bool HandleRegQueryValueExA(APIContext& ctx) { return RegQueryValueExImpl(ctx, false); }
bool HandleRegQueryValueExW(APIContext& ctx) { return RegQueryValueExImpl(ctx, true); }

// ============================================================================
// RegDeleteKeyA/W
// ============================================================================

static bool RegDeleteKeyImpl(APIContext& ctx, bool isWide) {
    VirtualRegistry::Instance().Initialize(ctx.Config());

    GuestHandle hKey    = ctx.GetArg(0);
    GuestAddress lpSub  = ctx.GetArgPtr(1);

    std::wstring subKey = isWide ? ctx.ReadWideString(lpSub)
                                 : NarrowToWide(ctx.ReadAnsiString(lpSub));

    std::wstring fullPath = BuildFullPath(hKey, subKey, ctx.Handles());
    if (fullPath.empty()) {
        ctx.SetReturn32(ERROR_BADKEY);
        return true;
    }

    if (!VirtualRegistry::Instance().DeleteKey(fullPath)) {
        ctx.SetReturn32(ERROR_FILE_NOT_FOUND);
        return true;
    }

    ctx.SetReturn32(ERROR_SUCCESS);
    return true;
}

bool HandleRegDeleteKeyA(APIContext& ctx) { return RegDeleteKeyImpl(ctx, false); }
bool HandleRegDeleteKeyW(APIContext& ctx) { return RegDeleteKeyImpl(ctx, true); }

// ============================================================================
// RegDeleteValueA/W
// ============================================================================

static bool RegDeleteValueImpl(APIContext& ctx, bool isWide) {
    VirtualRegistry::Instance().Initialize(ctx.Config());

    GuestHandle hKey     = ctx.GetArg(0);
    GuestAddress lpName  = ctx.GetArgPtr(1);

    std::wstring keyPath;
    if (IsPredefinedHKey(hKey)) {
        keyPath = HivePrefix(hKey);
    } else {
        auto entry = ctx.Handles().Lookup(hKey, HandleType::RegistryKey);
        if (!entry.has_value()) {
            ctx.SetReturn32(ERROR_BADKEY);
            return true;
        }
        auto* regData = std::get_if<RegistryKeyHandleData>(&entry->data);
        if (!regData) {
            ctx.SetReturn32(ERROR_BADKEY);
            return true;
        }
        keyPath = regData->path;
    }

    std::wstring valueName = isWide ? ctx.ReadWideString(lpName)
                                     : NarrowToWide(ctx.ReadAnsiString(lpName));

    if (!VirtualRegistry::Instance().DeleteValue(keyPath, valueName)) {
        ctx.SetReturn32(ERROR_FILE_NOT_FOUND);
        return true;
    }

    ctx.SetReturn32(ERROR_SUCCESS);
    return true;
}

bool HandleRegDeleteValueA(APIContext& ctx) { return RegDeleteValueImpl(ctx, false); }
bool HandleRegDeleteValueW(APIContext& ctx) { return RegDeleteValueImpl(ctx, true); }

// ============================================================================
// RegCloseKey
// ============================================================================

bool HandleRegCloseKey(APIContext& ctx) {
    GuestHandle hKey = ctx.GetArg(0);

    // Predefined keys cannot be closed
    if (IsPredefinedHKey(hKey)) {
        ctx.SetReturn32(ERROR_SUCCESS);
        return true;
    }

    if (!ctx.Handles().Close(hKey)) {
        ctx.SetReturn32(ERROR_BADKEY);
        return true;
    }

    ctx.SetReturn32(ERROR_SUCCESS);
    return true;
}

// ============================================================================
// RegEnumKeyExA/W
// ============================================================================

static bool RegEnumKeyExImpl(APIContext& ctx, bool isWide) {
    VirtualRegistry::Instance().Initialize(ctx.Config());

    GuestHandle hKey        = ctx.GetArg(0);
    uint32_t    dwIndex     = ctx.GetArg32(1);
    GuestAddress lpName     = ctx.GetArgPtr(2);
    GuestAddress lpcchName  = ctx.GetArgPtr(3);
    // arg4 = lpReserved, arg5 = lpClass, arg6 = lpcchClass, arg7 = lpftLastWriteTime

    std::wstring keyPath;
    if (IsPredefinedHKey(hKey)) {
        keyPath = HivePrefix(hKey);
    } else {
        auto entry = ctx.Handles().Lookup(hKey, HandleType::RegistryKey);
        if (!entry.has_value()) {
            ctx.SetReturn32(ERROR_BADKEY);
            return true;
        }
        auto* regData = std::get_if<RegistryKeyHandleData>(&entry->data);
        if (!regData) {
            ctx.SetReturn32(ERROR_BADKEY);
            return true;
        }
        keyPath = regData->path;
    }

    auto subKey = VirtualRegistry::Instance().EnumSubKey(keyPath, dwIndex);
    if (!subKey.has_value()) {
        ctx.SetReturn32(ERROR_NO_MORE_ITEMS);
        return true;
    }

    if (lpcchName == 0 || lpName == 0) {
        ctx.SetReturn32(ERROR_INVALID_PARAMETER);
        return true;
    }

    uint32_t bufChars = 0;
    ctx.Memory().ReadU32(lpcchName, bufChars);

    const std::wstring& name = subKey.value();

    if (isWide) {
        uint32_t needed = static_cast<uint32_t>(name.size());
        if (bufChars <= needed) {
            ctx.Memory().WriteU32(lpcchName, needed + 1);
            ctx.SetReturn32(ERROR_MORE_DATA);
            return true;
        }
        ctx.WriteWideString(lpName, name, bufChars);
        ctx.Memory().WriteU32(lpcchName, needed);
    } else {
        std::string narrow;
        narrow.reserve(name.size());
        for (wchar_t wc : name) narrow.push_back(static_cast<char>(wc & 0x7F));
        uint32_t needed = static_cast<uint32_t>(narrow.size());
        if (bufChars <= needed) {
            ctx.Memory().WriteU32(lpcchName, needed + 1);
            ctx.SetReturn32(ERROR_MORE_DATA);
            return true;
        }
        ctx.WriteAnsiString(lpName, narrow, bufChars);
        ctx.Memory().WriteU32(lpcchName, needed);
    }

    // Write zero-filled FILETIME if requested (arg7)
    GuestAddress lpft = ctx.GetArgPtr(7);
    if (lpft != 0) {
        ctx.Memory().WriteU64(lpft, 0);
    }

    ctx.SetReturn32(ERROR_SUCCESS);
    return true;
}

bool HandleRegEnumKeyExA(APIContext& ctx) { return RegEnumKeyExImpl(ctx, false); }
bool HandleRegEnumKeyExW(APIContext& ctx) { return RegEnumKeyExImpl(ctx, true); }

// ============================================================================
// RegEnumValueA/W
// ============================================================================

static bool RegEnumValueImpl(APIContext& ctx, bool isWide) {
    VirtualRegistry::Instance().Initialize(ctx.Config());

    GuestHandle hKey        = ctx.GetArg(0);
    uint32_t    dwIndex     = ctx.GetArg32(1);
    GuestAddress lpName     = ctx.GetArgPtr(2);
    GuestAddress lpcchName  = ctx.GetArgPtr(3);
    // arg4 = lpReserved
    GuestAddress lpType     = ctx.GetArgPtr(5);
    GuestAddress lpData     = ctx.GetArgPtr(6);
    GuestAddress lpcbData   = ctx.GetArgPtr(7);

    std::wstring keyPath;
    if (IsPredefinedHKey(hKey)) {
        keyPath = HivePrefix(hKey);
    } else {
        auto entry = ctx.Handles().Lookup(hKey, HandleType::RegistryKey);
        if (!entry.has_value()) {
            ctx.SetReturn32(ERROR_BADKEY);
            return true;
        }
        auto* regData = std::get_if<RegistryKeyHandleData>(&entry->data);
        if (!regData) {
            ctx.SetReturn32(ERROR_BADKEY);
            return true;
        }
        keyPath = regData->path;
    }

    auto valEntry = VirtualRegistry::Instance().EnumValue(keyPath, dwIndex);
    if (!valEntry.has_value()) {
        ctx.SetReturn32(ERROR_NO_MORE_ITEMS);
        return true;
    }

    if (lpcchName == 0 || lpName == 0) {
        ctx.SetReturn32(ERROR_INVALID_PARAMETER);
        return true;
    }

    // Write value name
    uint32_t nameBufChars = 0;
    ctx.Memory().ReadU32(lpcchName, nameBufChars);

    const std::wstring& vName = valEntry->name;

    if (isWide) {
        uint32_t needed = static_cast<uint32_t>(vName.size());
        if (nameBufChars <= needed) {
            ctx.Memory().WriteU32(lpcchName, needed + 1);
            ctx.SetReturn32(ERROR_MORE_DATA);
            return true;
        }
        ctx.WriteWideString(lpName, vName, nameBufChars);
        ctx.Memory().WriteU32(lpcchName, needed);
    } else {
        std::string narrow;
        narrow.reserve(vName.size());
        for (wchar_t wc : vName) narrow.push_back(static_cast<char>(wc & 0x7F));
        uint32_t needed = static_cast<uint32_t>(narrow.size());
        if (nameBufChars <= needed) {
            ctx.Memory().WriteU32(lpcchName, needed + 1);
            ctx.SetReturn32(ERROR_MORE_DATA);
            return true;
        }
        ctx.WriteAnsiString(lpName, narrow, nameBufChars);
        ctx.Memory().WriteU32(lpcchName, needed);
    }

    // Write type
    if (lpType != 0) {
        ctx.Memory().WriteU32(lpType, valEntry->type);
    }

    // Write data
    uint32_t dataSize = static_cast<uint32_t>(valEntry->data.size());
    if (lpcbData != 0) {
        uint32_t dataBufSize = 0;
        ctx.Memory().ReadU32(lpcbData, dataBufSize);

        if (lpData != 0 && dataBufSize >= dataSize && dataSize > 0) {
            ctx.Memory().Write(lpData, valEntry->data.data(), dataSize);
        } else if (lpData != 0 && dataBufSize < dataSize) {
            ctx.Memory().WriteU32(lpcbData, dataSize);
            ctx.SetReturn32(ERROR_MORE_DATA);
            return true;
        }
        ctx.Memory().WriteU32(lpcbData, dataSize);
    }

    ctx.SetReturn32(ERROR_SUCCESS);
    return true;
}

bool HandleRegEnumValueA(APIContext& ctx) { return RegEnumValueImpl(ctx, false); }
bool HandleRegEnumValueW(APIContext& ctx) { return RegEnumValueImpl(ctx, true); }

// ============================================================================
// Registration
// ============================================================================

void RegisterRegistryAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "advapi32.dll", "RegOpenKeyExA",    HandleRegOpenKeyExA,    5, false },
        { "advapi32.dll", "RegOpenKeyExW",    HandleRegOpenKeyExW,    5, false },
        { "advapi32.dll", "RegCreateKeyExA",  HandleRegCreateKeyExA,  9, false },
        { "advapi32.dll", "RegCreateKeyExW",  HandleRegCreateKeyExW,  9, false },
        { "advapi32.dll", "RegSetValueExA",   HandleRegSetValueExA,   6, false },
        { "advapi32.dll", "RegSetValueExW",   HandleRegSetValueExW,   6, false },
        { "advapi32.dll", "RegQueryValueExA", HandleRegQueryValueExA, 6, false },
        { "advapi32.dll", "RegQueryValueExW", HandleRegQueryValueExW, 6, false },
        { "advapi32.dll", "RegDeleteKeyA",    HandleRegDeleteKeyA,    2, false },
        { "advapi32.dll", "RegDeleteKeyW",    HandleRegDeleteKeyW,    2, false },
        { "advapi32.dll", "RegDeleteValueA",  HandleRegDeleteValueA,  2, false },
        { "advapi32.dll", "RegDeleteValueW",  HandleRegDeleteValueW,  2, false },
        { "advapi32.dll", "RegCloseKey",      HandleRegCloseKey,      1, false },
        { "advapi32.dll", "RegEnumKeyExA",    HandleRegEnumKeyExA,    8, false },
        { "advapi32.dll", "RegEnumKeyExW",    HandleRegEnumKeyExW,    8, false },
        { "advapi32.dll", "RegEnumValueA",    HandleRegEnumValueA,    8, false },
        { "advapi32.dll", "RegEnumValueW",    HandleRegEnumValueW,    8, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Advapi32
