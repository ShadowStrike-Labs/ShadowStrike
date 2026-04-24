/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * NtRegistry.cpp — Nt* registry syscall handlers
 *
 * Implements a virtual registry tree pre-populated with realistic
 * Windows 10 Pro values. Anti-VM registry keys (hardware descriptions,
 * BIOS data, MachineGuid) contain non-VM-artifact values that match
 * a genuine Dell workstation. Writes to persistence locations
 * (Run, RunOnce, Services) are flagged for behavioral analysis.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "NtRegistry.hpp"
#include "../APIDispatcher.hpp"

#include <algorithm>
#include <cstring>
#include <map>
#include <shared_mutex>
#include <vector>

// DESIGN: Guest writebacks via WriteU32/U64/Write are [[nodiscard]]; target
// pointers here are either null-checked or proven valid by a size check
// above. A guest AV on writeback is a guest fault. Pragma is namespace-
// scoped; explicit guards remain intact.
#pragma warning(push)
#pragma warning(disable : 4834 6031)

namespace Phantom::WinAPI::Ntdll {

// ============================================================================
// Virtual Registry — Thread-safe in-memory registry tree
// ============================================================================

namespace {

struct RegValue {
    uint32_t             type = NT::REG_NONE;
    std::vector<uint8_t> data;
};

struct RegKey {
    std::map<std::wstring, RegValue, std::less<>> values;
    std::vector<std::wstring>                     subkeys;
};

// Case-insensitive wide string uppercase conversion
static std::wstring ToUpper(std::wstring_view sv) {
    std::wstring result(sv);
    std::transform(result.begin(), result.end(), result.begin(),
                   [](wchar_t c) -> wchar_t {
                       return (c >= L'a' && c <= L'z') ? (c - L'a' + L'A') : c;
                   });
    return result;
}

// Encode a wide string as REG_SZ byte data (UTF-16LE with null terminator)
static std::vector<uint8_t> MakeRegSz(const wchar_t* str) {
    size_t chars = std::wcslen(str) + 1; // include null
    std::vector<uint8_t> data(chars * 2);
    std::memcpy(data.data(), str, chars * 2);
    return data;
}

// Encode a DWORD as REG_DWORD byte data
static std::vector<uint8_t> MakeRegDword(uint32_t val) {
    std::vector<uint8_t> data(4);
    std::memcpy(data.data(), &val, 4);
    return data;
}

// Encode a QWORD as REG_QWORD byte data (kept for future value seeding)
[[maybe_unused]] static std::vector<uint8_t> MakeRegQword(uint64_t val) {
    std::vector<uint8_t> data(8);
    std::memcpy(data.data(), &val, 8);
    return data;
}

// ============================================================================
// VirtualRegistry — Meyers' singleton with shared_mutex protection
// ============================================================================

class VirtualRegistry {
public:
    static VirtualRegistry& Instance() {
        static VirtualRegistry inst;
        return inst;
    }

    // Check if a key exists (case-insensitive path)
    [[nodiscard]] bool KeyExists(const std::wstring& path) const {
        std::shared_lock lock(m_mutex);
        return m_keys.contains(ToUpper(path));
    }

    // Get a key (returns nullptr if not found)
    [[nodiscard]] const RegKey* GetKey(const std::wstring& path) const {
        std::shared_lock lock(m_mutex);
        auto it = m_keys.find(ToUpper(path));
        return (it != m_keys.end()) ? &it->second : nullptr;
    }

    // Get a specific value from a key
    [[nodiscard]] const RegValue* GetValue(const std::wstring& keyPath,
                                           const std::wstring& valueName) const {
        std::shared_lock lock(m_mutex);
        auto it = m_keys.find(ToUpper(keyPath));
        if (it == m_keys.end()) return nullptr;
        auto vit = it->second.values.find(ToUpper(valueName));
        return (vit != it->second.values.end()) ? &vit->second : nullptr;
    }

    // Create or open a key. Returns true if newly created.
    bool CreateKey(const std::wstring& path) {
        std::unique_lock lock(m_mutex);
        auto upper = ToUpper(path);
        if (m_keys.contains(upper)) return false;

        m_keys[upper] = RegKey{};

        // Add to parent's subkey list
        auto lastSep = upper.rfind(L'\\');
        if (lastSep != std::wstring::npos) {
            auto parentPath = upper.substr(0, lastSep);
            auto childName = upper.substr(lastSep + 1);
            auto pit = m_keys.find(parentPath);
            if (pit != m_keys.end()) {
                auto& subs = pit->second.subkeys;
                if (std::find(subs.begin(), subs.end(), childName) == subs.end())
                    subs.push_back(childName);
            }
        }
        return true;
    }

    // Set a value under a key
    void SetValue(const std::wstring& keyPath, const std::wstring& valueName,
                  uint32_t type, const uint8_t* data, uint32_t dataSize) {
        std::unique_lock lock(m_mutex);
        auto upper = ToUpper(keyPath);
        auto& key = m_keys[upper];
        auto& val = key.values[ToUpper(valueName)];
        val.type = type;
        val.data.assign(data, data + dataSize);
    }

    // Delete a key
    bool DeleteKey(const std::wstring& path) {
        std::unique_lock lock(m_mutex);
        auto upper = ToUpper(path);
        auto it = m_keys.find(upper);
        if (it == m_keys.end()) return false;

        // Remove from parent's subkey list
        auto lastSep = upper.rfind(L'\\');
        if (lastSep != std::wstring::npos) {
            auto parentPath = upper.substr(0, lastSep);
            auto childName = upper.substr(lastSep + 1);
            auto pit = m_keys.find(parentPath);
            if (pit != m_keys.end()) {
                auto& subs = pit->second.subkeys;
                subs.erase(std::remove(subs.begin(), subs.end(), childName), subs.end());
            }
        }
        m_keys.erase(it);
        return true;
    }

    // Delete a value from a key
    bool DeleteValue(const std::wstring& keyPath, const std::wstring& valueName) {
        std::unique_lock lock(m_mutex);
        auto it = m_keys.find(ToUpper(keyPath));
        if (it == m_keys.end()) return false;
        return it->second.values.erase(ToUpper(valueName)) > 0;
    }

    // Get subkeys (for enumeration). Returns copy for thread safety.
    [[nodiscard]] std::vector<std::wstring> GetSubkeys(const std::wstring& path) const {
        std::shared_lock lock(m_mutex);
        auto it = m_keys.find(ToUpper(path));
        if (it == m_keys.end()) return {};
        return it->second.subkeys;
    }

    // Get value names (for enumeration). Returns vector of (name, type, data).
    struct ValueEntry {
        std::wstring         name;
        uint32_t             type;
        std::vector<uint8_t> data;
    };

    [[nodiscard]] std::vector<ValueEntry> GetValues(const std::wstring& path) const {
        std::shared_lock lock(m_mutex);
        std::vector<ValueEntry> result;
        auto it = m_keys.find(ToUpper(path));
        if (it == m_keys.end()) return result;
        for (const auto& [name, val] : it->second.values) {
            result.push_back({ name, val.type, val.data });
        }
        return result;
    }

private:
    VirtualRegistry() { InitDefaults(); }
    VirtualRegistry(const VirtualRegistry&) = delete;
    VirtualRegistry& operator=(const VirtualRegistry&) = delete;

    mutable std::shared_mutex m_mutex;
    std::map<std::wstring, RegKey, std::less<>> m_keys;

    // Helper to add a key with its subkey registered in the parent
    void AddKey(const std::wstring& path) {
        m_keys[path] = RegKey{};
        auto lastSep = path.rfind(L'\\');
        if (lastSep != std::wstring::npos) {
            auto parentPath = path.substr(0, lastSep);
            auto childName = path.substr(lastSep + 1);
            auto pit = m_keys.find(parentPath);
            if (pit != m_keys.end()) {
                pit->second.subkeys.push_back(childName);
            }
        }
    }

    void AddValue(const std::wstring& keyPath, const std::wstring& valueName,
                  uint32_t type, std::vector<uint8_t> data) {
        m_keys[keyPath].values[valueName] = RegValue{ type, std::move(data) };
    }

    void InitDefaults() {
        // === Root keys ===
        m_keys[L"HKLM"] = RegKey{};
        m_keys[L"HKU"]  = RegKey{};
        m_keys[L"HKCU"] = RegKey{};

        // === HKLM\SOFTWARE hierarchy ===
        AddKey(L"HKLM\\SOFTWARE");
        AddKey(L"HKLM\\SOFTWARE\\MICROSOFT");
        AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT");
        AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION");
        AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\CRYPTOGRAPHY");
        AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION");
        AddKey(L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\UNINSTALL");

        // CurrentVersion values — realistic Windows 10 Pro 22H2
        auto cv = L"HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION";
        AddValue(cv, L"PRODUCTNAME",         NT::REG_SZ,     MakeRegSz(L"Windows 10 Pro"));
        AddValue(cv, L"CURRENTBUILDNUMBER",  NT::REG_SZ,     MakeRegSz(L"19045"));
        AddValue(cv, L"CURRENTBUILD",        NT::REG_SZ,     MakeRegSz(L"19045"));
        AddValue(cv, L"BUILDLAB",            NT::REG_SZ,     MakeRegSz(L"19045.vb_release.191206-1406"));
        AddValue(cv, L"BUILDLABEX",          NT::REG_SZ,     MakeRegSz(L"19045.1.amd64fre.vb_release.191206-1406"));
        AddValue(cv, L"CURRENTVERSION",      NT::REG_SZ,     MakeRegSz(L"6.3"));
        AddValue(cv, L"CURRENTMAJORVERSIONNUMBER", NT::REG_DWORD, MakeRegDword(10));
        AddValue(cv, L"CURRENTMINORVERSIONNUMBER", NT::REG_DWORD, MakeRegDword(0));
        AddValue(cv, L"UBR",                NT::REG_DWORD, MakeRegDword(4355));
        AddValue(cv, L"DISPLAYVERSION",     NT::REG_SZ,     MakeRegSz(L"22H2"));
        AddValue(cv, L"EDITIONID",          NT::REG_SZ,     MakeRegSz(L"Professional"));
        AddValue(cv, L"INSTALLATIONTYPE",   NT::REG_SZ,     MakeRegSz(L"Client"));
        AddValue(cv, L"PRODUCTID",          NT::REG_SZ,     MakeRegSz(L"00330-80000-00000-AA174"));
        AddValue(cv, L"REGISTEREDOWNER",    NT::REG_SZ,     MakeRegSz(L"JSmith"));
        AddValue(cv, L"SYSTEMROOT",         NT::REG_SZ,     MakeRegSz(L"C:\\Windows"));
        AddValue(cv, L"INSTALLDATE",        NT::REG_DWORD, MakeRegDword(1672531200)); // Jan 2023

        // Cryptography — MachineGuid
        AddValue(L"HKLM\\SOFTWARE\\MICROSOFT\\CRYPTOGRAPHY",
                 L"MACHINEGUID", NT::REG_SZ,
                 MakeRegSz(L"a4f7c3d2-8b1e-4f56-9d3a-7e2c1b5f8a09"));

        // === HKLM\SYSTEM hierarchy ===
        AddKey(L"HKLM\\SYSTEM");
        AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET");
        AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\CONTROL");
        AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\SERVICES");
        AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\DISK");
        AddKey(L"HKLM\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\TCPIP");

        // === HKLM\HARDWARE hierarchy — anti-VM critical ===
        AddKey(L"HKLM\\HARDWARE");
        AddKey(L"HKLM\\HARDWARE\\DESCRIPTION");
        AddKey(L"HKLM\\HARDWARE\\DESCRIPTION\\SYSTEM");
        AddKey(L"HKLM\\HARDWARE\\DESCRIPTION\\SYSTEM\\BIOS");
        AddKey(L"HKLM\\HARDWARE\\DESCRIPTION\\SYSTEM\\CENTRALPROCESSOR");
        AddKey(L"HKLM\\HARDWARE\\DESCRIPTION\\SYSTEM\\CENTRALPROCESSOR\\0");

        auto hw = L"HKLM\\HARDWARE\\DESCRIPTION\\SYSTEM";
        AddValue(hw, L"SYSTEMBIOSVERSION",  NT::REG_MULTI_SZ, MakeRegSz(L"DELL   - 1072009\0"));
        AddValue(hw, L"SYSTEMBIOSDATE",     NT::REG_SZ,       MakeRegSz(L"04/10/2023"));
        AddValue(hw, L"VIDEOBIOSVERSION",   NT::REG_MULTI_SZ, MakeRegSz(L"Intel(R) UHD Graphics\0"));

        auto bios = L"HKLM\\HARDWARE\\DESCRIPTION\\SYSTEM\\BIOS";
        AddValue(bios, L"SYSTEMMANUFACTURER", NT::REG_SZ, MakeRegSz(L"Dell Inc."));
        AddValue(bios, L"SYSTEMPRODUCTNAME",  NT::REG_SZ, MakeRegSz(L"Precision 5570"));
        AddValue(bios, L"SYSTEMFAMILY",       NT::REG_SZ, MakeRegSz(L"Precision"));
        AddValue(bios, L"BASEBOARD MANUFACTURER", NT::REG_SZ, MakeRegSz(L"Dell Inc."));
        AddValue(bios, L"BASEBOARD PRODUCT",  NT::REG_SZ, MakeRegSz(L"0R5P8G"));
        AddValue(bios, L"BIOSVENDOR",         NT::REG_SZ, MakeRegSz(L"Dell Inc."));
        AddValue(bios, L"BIOSVERSION",        NT::REG_SZ, MakeRegSz(L"2.17.1246"));
        AddValue(bios, L"BIOSRELEASEDATE",    NT::REG_SZ, MakeRegSz(L"04/10/2023"));

        auto cpu = L"HKLM\\HARDWARE\\DESCRIPTION\\SYSTEM\\CENTRALPROCESSOR\\0";
        AddValue(cpu, L"PROCESSORNAMESTRING", NT::REG_SZ,
                 MakeRegSz(L"Intel(R) Core(TM) i7-12700H"));
        AddValue(cpu, L"IDENTIFIER",          NT::REG_SZ,
                 MakeRegSz(L"Intel64 Family 6 Model 154 Stepping 3"));
        AddValue(cpu, L"VENDORIDENTIFIER",    NT::REG_SZ, MakeRegSz(L"GenuineIntel"));
        AddValue(cpu, L"~MHZ",               NT::REG_DWORD, MakeRegDword(2688));
        AddValue(cpu, L"FEATURESET",         NT::REG_DWORD, MakeRegDword(0x7CDEFBBF));

        // === HKCU keys ===
        AddKey(L"HKCU\\SOFTWARE");
        AddKey(L"HKCU\\SOFTWARE\\MICROSOFT");
        AddKey(L"HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS");
        AddKey(L"HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION");
        AddKey(L"HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN");
        AddKey(L"HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNONCE");
        AddKey(L"HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER");

        // HKU
        AddKey(L"HKU\\.DEFAULT");
    }
};

// ============================================================================
// Path normalization
// ============================================================================

static std::wstring NormalizeRegistryPath(const std::wstring& raw) {
    std::wstring path = ToUpper(raw);

    // Strip leading backslash
    if (!path.empty() && path[0] == L'\\')
        path = path.substr(1);

    // Strip trailing backslash
    while (!path.empty() && path.back() == L'\\')
        path.pop_back();

    // NT → short form conversion
    if (path.starts_with(L"REGISTRY\\MACHINE\\"))
        path = L"HKLM\\" + path.substr(17);
    else if (path == L"REGISTRY\\MACHINE")
        path = L"HKLM";
    else if (path.starts_with(L"REGISTRY\\USER\\"))
        path = L"HKU\\" + path.substr(14);
    else if (path == L"REGISTRY\\USER")
        path = L"HKU";

    // Map HKU\<current user SID> → HKCU
    // Real SIDs start with S-1-5-21-... ; for our fake user we map HKU\.DEFAULT → HKCU too
    if (path.starts_with(L"HKU\\S-1-5-21-"))
        path = L"HKCU\\" + path.substr(path.find(L'\\', 4) + 1);

    return path;
}

// ============================================================================
// Persistence path detection
// ============================================================================

static bool IsPersistencePath(const std::wstring& path) {
    auto upper = ToUpper(path);
    // T1547.001 Run/RunOnce (per-user + per-machine)
    if (upper.find(L"\\RUN") != std::wstring::npos ||
        upper.find(L"\\RUNONCE") != std::wstring::npos) {
        return true;
    }
    // T1543.003 Services
    if (upper.find(L"\\SERVICES\\") != std::wstring::npos) {
        return true;
    }
    // T1547.004 Winlogon Helper DLL (Userinit / Shell / AppInit_DLLs)
    if (upper.find(L"\\WINLOGON") != std::wstring::npos ||
        upper.find(L"APPINIT_DLLS") != std::wstring::npos) {
        return true;
    }
    // T1547.005 Security Support Provider, T1547.014 Active Setup
    if (upper.find(L"\\LSA\\") != std::wstring::npos ||
        upper.find(L"\\ACTIVE SETUP\\") != std::wstring::npos) {
        return true;
    }
    // T1546.012 Image File Execution Options debugger hijack
    if (upper.find(L"IMAGE FILE EXECUTION OPTIONS") != std::wstring::npos) {
        return true;
    }
    // T1546.001 Shell Open / COM hijack patterns
    if (upper.find(L"\\SHELL\\OPEN\\COMMAND") != std::wstring::npos) {
        return true;
    }
    return false;
}

// Detect paths that indicate EDR / AV / Windows-Defender tampering
// (T1562.001 Impair Defenses).
static bool IsDefenseTamperingPath(const std::wstring& path) {
    auto upper = ToUpper(path);
    return upper.find(L"\\WINDOWS DEFENDER") != std::wstring::npos ||
           upper.find(L"\\MICROSOFT\\AMSI") != std::wstring::npos ||
           upper.find(L"\\SECURITYHEALTHSERVICE") != std::wstring::npos ||
           upper.find(L"\\WSCSVC") != std::wstring::npos ||
           upper.find(L"\\WINDEFEND") != std::wstring::npos ||
           upper.find(L"\\POLICIES\\MICROSOFT\\WINDOWS DEFENDER")
               != std::wstring::npos ||
           upper.find(L"\\SENSE\\") != std::wstring::npos ||      // Defender ATP
           upper.find(L"\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\MPS")
               != std::wstring::npos ||                          // Firewall
           upper.find(L"\\SYSTEM\\CURRENTCONTROLSET\\CONTROL\\LSA\\DISABLERESTRICTEDADMIN")
               != std::wstring::npos;
}

// Detect paths that indicate UAC / security-policy tampering
static bool IsSecurityPolicyPath(const std::wstring& path) {
    auto upper = ToUpper(path);
    return upper.find(L"\\POLICIES\\SYSTEM") != std::wstring::npos ||
           upper.find(L"\\FIREWALLPOLICY") != std::wstring::npos ||
           upper.find(L"\\UACDISABLENOTIFY") != std::wstring::npos;
}

// ============================================================================
// OBJECT_ATTRIBUTES helper — reads key path from guest memory
// ============================================================================

static std::wstring ReadKeyPath(APIContext& ctx, GuestAddress objAttrAddr,
                                GuestHandle rootHandle = kNullHandle) {
    if (objAttrAddr == 0) return {};

    // OBJECT_ATTRIBUTES x64 layout:
    //   +0x08: HANDLE  RootDirectory
    //   +0x10: PUNICODE_STRING ObjectName
    uint64_t rootDir = 0;
    uint64_t objNamePtr = 0;
    ctx.Memory().ReadU64(objAttrAddr + 0x08, rootDir);
    ctx.Memory().ReadU64(objAttrAddr + 0x10, objNamePtr);

    std::wstring name;
    if (objNamePtr != 0) {
        name = ctx.ReadUnicodeString(objNamePtr);
    }

    // Resolve relative path via RootDirectory handle
    GuestHandle effectiveRoot = (rootDir != 0) ? rootDir : rootHandle;
    if (effectiveRoot != 0 && effectiveRoot != kNullHandle) {
        auto entry = ctx.Handles().Lookup(effectiveRoot, HandleType::RegistryKey);
        if (entry) {
            auto* keyData = std::get_if<RegistryKeyHandleData>(&entry->data);
            if (keyData && !keyData->path.empty()) {
                if (!name.empty())
                    name = keyData->path + L"\\" + name;
                else
                    name = keyData->path;
            }
        }
    }

    return NormalizeRegistryPath(name);
}

// Cap for registry value data size (defense against resource exhaustion)
static constexpr uint32_t kMaxRegValueSize = 1024 * 1024; // 1 MB

} // anonymous namespace

// ============================================================================
// HandleNtOpenKey
// ============================================================================

bool HandleNtOpenKey(APIContext& ctx) {
    auto keyHandleAddr = ctx.GetArgPtr(0);
    // Arg1: DesiredAccess
    auto objAttrAddr   = ctx.GetArgPtr(2);

    if (keyHandleAddr == 0 || objAttrAddr == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    std::wstring keyPath = ReadKeyPath(ctx, objAttrAddr);
    if (keyPath.empty()) {
        ctx.SetReturnNtStatus(NT::STATUS_OBJECT_PATH_SYNTAX_BAD);
        return true;
    }

    auto& reg = VirtualRegistry::Instance();

    // Ensure key exists (auto-create known parents for realistic behavior)
    if (!reg.KeyExists(keyPath)) {
        ctx.SetReturnNtStatus(NT::STATUS_OBJECT_NAME_NOT_FOUND);
        return true;
    }

    // Create handle
    RegistryKeyHandleData keyData;
    keyData.path = keyPath;
    keyData.accessMask = ctx.GetArg32(1);

    GuestHandle handle = ctx.Handles().Create(HandleType::RegistryKey, keyData);
    ctx.Memory().WriteU64(keyHandleAddr, handle);
    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// HandleNtCreateKey
// ============================================================================

bool HandleNtCreateKey(APIContext& ctx) {
    auto keyHandleAddr  = ctx.GetArgPtr(0);
    // Arg1: DesiredAccess
    auto objAttrAddr    = ctx.GetArgPtr(2);
    // Arg3: TitleIndex (ignored)
    // Arg4: Class UNICODE_STRING (ignored)
    // Arg5: CreateOptions
    auto dispositionAddr = ctx.GetArgPtr(6);

    if (keyHandleAddr == 0 || objAttrAddr == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    std::wstring keyPath = ReadKeyPath(ctx, objAttrAddr);
    if (keyPath.empty()) {
        ctx.SetReturnNtStatus(NT::STATUS_OBJECT_PATH_SYNTAX_BAD);
        return true;
    }

    auto& reg = VirtualRegistry::Instance();

    // Determine disposition: created new or opened existing
    bool isNew = reg.CreateKey(keyPath);

    uint32_t disposition = isNew ? 1 : 2; // REG_CREATED_NEW_KEY / REG_OPENED_EXISTING_KEY
    if (dispositionAddr != 0)
        ctx.Memory().WriteU32(dispositionAddr, disposition);

    // Create handle
    RegistryKeyHandleData keyData;
    keyData.path = keyPath;
    keyData.accessMask = ctx.GetArg32(1);

    GuestHandle handle = ctx.Handles().Create(HandleType::RegistryKey, keyData);
    ctx.Memory().WriteU64(keyHandleAddr, handle);

    // IOC: T1547 / T1543 persistence-key creation. Dispatcher metadata sets
    // a generic RegistryPersistence on NtSetValueKey only; a bare NtCreateKey
    // into a persistence root (e.g. creating a brand-new service key) is
    // itself a high-confidence persistence signal.
    if (IsPersistencePath(keyPath)) {
        ctx.AddBehaviorFlag(BehaviorFlag::RegistryPersistence);
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
    }
    if (IsDefenseTamperingPath(keyPath)) {
        ctx.AddBehaviorFlag(BehaviorFlag::DefenseEvasion);
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
    }

    // Persistence detection is handled automatically by the dispatcher
    // via BehaviorFlag::RegistryPersistence in the KnownAPIEntry metadata.

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// HandleNtSetValueKey
// ============================================================================

bool HandleNtSetValueKey(APIContext& ctx) {
    auto keyHandle    = ctx.GetArg(0);
    auto valueNameAddr = ctx.GetArgPtr(1);
    // Arg2: TitleIndex (ignored)
    auto valueType    = ctx.GetArg32(3);
    auto dataAddr     = ctx.GetArgPtr(4);
    auto dataSize     = ctx.GetArg32(5);

    // Validate handle
    auto entry = ctx.Handles().Lookup(keyHandle, HandleType::RegistryKey);
    if (!entry) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    auto* keyData = std::get_if<RegistryKeyHandleData>(&entry->data);
    if (!keyData) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    // Read value name
    std::wstring valueName;
    if (valueNameAddr != 0)
        valueName = ctx.ReadUnicodeString(valueNameAddr);

    // Cap data size to prevent resource exhaustion
    if (dataSize > kMaxRegValueSize) {
        ctx.SetReturnNtStatus(NT::STATUS_INSUFFICIENT_RESOURCES);
        return true;
    }

    // Read value data from guest memory
    std::vector<uint8_t> data(dataSize);
    if (dataSize > 0 && dataAddr != 0) {
        auto err = ctx.Memory().Read(dataAddr, data.data(), dataSize);
        if (err != ErrorCode::Success) {
            ctx.SetReturnNtStatus(NT::STATUS_ACCESS_VIOLATION);
            return true;
        }
    }

    VirtualRegistry::Instance().SetValue(keyData->path, valueName,
                                         valueType, data.data(), dataSize);

    // IOC: classify the write target.
    // Persistence (T1547/T1546/T1543/T1037) always emits RegistryPersistence.
    // The dispatcher only catches the Win32 RegSetValueEx variant generically;
    // here we add specific technique-level flags so DefenseEvasion fires when
    // the target is a known EDR-tamper key — critical for NGAV correlation.
    if (IsPersistencePath(keyData->path)) {
        ctx.AddBehaviorFlag(BehaviorFlag::RegistryPersistence);
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);

        // T1546.012 IFEO Debugger hijack is BOTH persistence AND
        // privilege escalation / execution hijack.
        auto upperPath = ToUpper(keyData->path);
        auto upperName = ToUpper(valueName);
        if (upperPath.find(L"IMAGE FILE EXECUTION OPTIONS")
                != std::wstring::npos &&
            upperName == L"DEBUGGER") {
            ctx.AddBehaviorFlag(BehaviorFlag::DefenseEvasion);
            ctx.AddBehaviorFlag(BehaviorFlag::PrivilegeEscalation);
        }
    }

    if (IsDefenseTamperingPath(keyData->path)) {
        ctx.AddBehaviorFlag(BehaviorFlag::DefenseEvasion);
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
    }

    // Value-level tamper detection: well-known kill-switch DWORDs.
    // REG_DWORD (type 4) with data == 0 into these names is the canonical
    // Defender/AMSI disable pattern (T1562.001).
    if (valueType == NT::REG_DWORD && dataSize == 4 && !data.empty()) {
        uint32_t v = 0;
        std::memcpy(&v, data.data(), 4);
        auto upperName = ToUpper(valueName);
        const bool killSwitch =
            (upperName == L"DISABLEANTISPYWARE" ||
             upperName == L"DISABLEREALTIMEMONITORING" ||
             upperName == L"DISABLEBEHAVIORMONITORING" ||
             upperName == L"DISABLEONACCESSPROTECTION" ||
             upperName == L"DISABLESCANONREALTIMEENABLE" ||
             upperName == L"DISABLEIOAVPROTECTION" ||
             upperName == L"DISABLEBLOCKATFIRSTSEEN" ||
             upperName == L"SPYNETREPORTING" ||
             upperName == L"SUBMITSAMPLESCONSENT" ||
             upperName == L"AMSIENABLE" ||
             upperName == L"ENABLELUA" ||
             upperName == L"CONSENTPROMPTBEHAVIORADMIN" ||
             upperName == L"ENABLEVIRTUALIZATION" ||
             upperName == L"ENABLEFIREWALL" ||
             upperName == L"ENABLELOGFILE");
        if (killSwitch && v == 0) {
            ctx.AddBehaviorFlag(BehaviorFlag::DefenseEvasion);
            ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
        }
    }

    if (IsSecurityPolicyPath(keyData->path)) {
        ctx.AddBehaviorFlag(BehaviorFlag::DefenseEvasion);
    }

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// HandleNtQueryValueKey
// ============================================================================

bool HandleNtQueryValueKey(APIContext& ctx) {
    auto keyHandle      = ctx.GetArg(0);
    auto valueNameAddr  = ctx.GetArgPtr(1);
    auto infoClass      = ctx.GetArg32(2);
    auto infoAddr       = ctx.GetArgPtr(3);
    auto infoLength     = ctx.GetArg32(4);
    auto retLenAddr     = ctx.GetArgPtr(5);

    auto writeRetLen = [&](uint32_t len) {
        if (retLenAddr != 0)
            ctx.Memory().WriteU32(retLenAddr, len);
    };

    // Validate handle
    auto entry = ctx.Handles().Lookup(keyHandle, HandleType::RegistryKey);
    if (!entry) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    auto* keyData = std::get_if<RegistryKeyHandleData>(&entry->data);
    if (!keyData) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    // Read value name
    std::wstring valueName;
    if (valueNameAddr != 0)
        valueName = ctx.ReadUnicodeString(valueNameAddr);

    // Look up value
    auto* regVal = VirtualRegistry::Instance().GetValue(keyData->path, valueName);
    if (!regVal) {
        ctx.SetReturnNtStatus(NT::STATUS_OBJECT_NAME_NOT_FOUND);
        return true;
    }

    uint32_t dataLen = static_cast<uint32_t>(regVal->data.size());
    std::wstring upperName = ToUpper(valueName);
    uint32_t nameByteLen = static_cast<uint32_t>(upperName.size() * 2);

    switch (infoClass) {
    case 2: { // KeyValuePartialInformation
        // Layout: TitleIndex(4) + Type(4) + DataLength(4) + Data[]
        uint32_t requiredSize = 12 + dataLen;
        writeRetLen(requiredSize);

        if (infoLength < requiredSize) {
            ctx.SetReturnNtStatus(NT::STATUS_BUFFER_TOO_SMALL);
            return true;
        }

        ctx.Memory().WriteU32(infoAddr + 0x00, 0);           // TitleIndex
        ctx.Memory().WriteU32(infoAddr + 0x04, regVal->type); // Type
        ctx.Memory().WriteU32(infoAddr + 0x08, dataLen);      // DataLength
        if (dataLen > 0) {
            ctx.Memory().Write(infoAddr + 0x0C, regVal->data.data(), dataLen);
        }

        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    case 1: { // KeyValueFullInformation
        // Layout: TitleIndex(4) + Type(4) + DataOffset(4) + DataLength(4) +
        //         NameLength(4) + Name[] + [padding] + Data[]
        uint32_t nameAligned = (nameByteLen + 7) & ~7u;
        uint32_t dataOffset = 20 + nameAligned;
        uint32_t requiredSize = dataOffset + dataLen;
        writeRetLen(requiredSize);

        if (infoLength < requiredSize) {
            ctx.SetReturnNtStatus(NT::STATUS_BUFFER_TOO_SMALL);
            return true;
        }

        ctx.Memory().WriteU32(infoAddr + 0x00, 0);           // TitleIndex
        ctx.Memory().WriteU32(infoAddr + 0x04, regVal->type); // Type
        ctx.Memory().WriteU32(infoAddr + 0x08, dataOffset);   // DataOffset
        ctx.Memory().WriteU32(infoAddr + 0x0C, dataLen);      // DataLength
        ctx.Memory().WriteU32(infoAddr + 0x10, nameByteLen);  // NameLength
        if (nameByteLen > 0) {
            ctx.Memory().Write(infoAddr + 0x14, upperName.c_str(), nameByteLen);
        }
        if (dataLen > 0) {
            ctx.Memory().Write(infoAddr + dataOffset, regVal->data.data(), dataLen);
        }

        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    default:
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_INFO_CLASS);
        return true;
    }
}

// ============================================================================
// HandleNtDeleteKey
// ============================================================================

bool HandleNtDeleteKey(APIContext& ctx) {
    auto keyHandle = ctx.GetArg(0);

    auto entry = ctx.Handles().Lookup(keyHandle, HandleType::RegistryKey);
    if (!entry) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    auto* keyData = std::get_if<RegistryKeyHandleData>(&entry->data);
    if (!keyData) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    VirtualRegistry::Instance().DeleteKey(keyData->path);

    // IOC: T1070.009 Indicator Removal — Clear Persistence, or T1562.001
    // deleting a defender/EDR key.
    if (IsPersistencePath(keyData->path) ||
        IsDefenseTamperingPath(keyData->path)) {
        ctx.AddBehaviorFlag(BehaviorFlag::DefenseEvasion);
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
    }

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// HandleNtDeleteValueKey
// ============================================================================

bool HandleNtDeleteValueKey(APIContext& ctx) {
    auto keyHandle     = ctx.GetArg(0);
    auto valueNameAddr = ctx.GetArgPtr(1);

    auto entry = ctx.Handles().Lookup(keyHandle, HandleType::RegistryKey);
    if (!entry) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    auto* keyData = std::get_if<RegistryKeyHandleData>(&entry->data);
    if (!keyData) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    std::wstring valueName;
    if (valueNameAddr != 0)
        valueName = ctx.ReadUnicodeString(valueNameAddr);

    bool removed = VirtualRegistry::Instance().DeleteValue(keyData->path, valueName);

    // IOC: deleting a persistence/defense value is an evasion signal.
    if (removed &&
        (IsPersistencePath(keyData->path) ||
         IsDefenseTamperingPath(keyData->path))) {
        ctx.AddBehaviorFlag(BehaviorFlag::DefenseEvasion);
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
    }

    ctx.SetReturnNtStatus(removed ? NT::STATUS_SUCCESS : NT::STATUS_OBJECT_NAME_NOT_FOUND);
    return true;
}

// ============================================================================
// HandleNtEnumerateKey
// ============================================================================

bool HandleNtEnumerateKey(APIContext& ctx) {
    auto keyHandle   = ctx.GetArg(0);
    auto index       = ctx.GetArg32(1);
    auto infoClass   = ctx.GetArg32(2);
    auto infoAddr    = ctx.GetArgPtr(3);
    auto infoLength  = ctx.GetArg32(4);
    auto retLenAddr  = ctx.GetArgPtr(5);

    auto writeRetLen = [&](uint32_t len) {
        if (retLenAddr != 0)
            ctx.Memory().WriteU32(retLenAddr, len);
    };

    auto entry = ctx.Handles().Lookup(keyHandle, HandleType::RegistryKey);
    if (!entry) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    auto* keyData = std::get_if<RegistryKeyHandleData>(&entry->data);
    if (!keyData) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    auto subkeys = VirtualRegistry::Instance().GetSubkeys(keyData->path);
    if (index >= subkeys.size()) {
        ctx.SetReturnNtStatus(NT::STATUS_NO_MORE_ENTRIES);
        return true;
    }

    const auto& subkeyName = subkeys[index];
    uint32_t nameByteLen = static_cast<uint32_t>(subkeyName.size() * 2);

    // KeyBasicInformation (class 0):
    //   +0x00: LARGE_INTEGER LastWriteTime (8)
    //   +0x08: ULONG TitleIndex (4)
    //   +0x0C: ULONG NameLength (4)
    //   +0x10: WCHAR Name[] (variable)
    if (infoClass == 0 || infoClass == 1) {
        uint32_t requiredSize = 0x10 + nameByteLen;
        writeRetLen(requiredSize);

        if (infoLength < requiredSize) {
            ctx.SetReturnNtStatus(NT::STATUS_BUFFER_TOO_SMALL);
            return true;
        }

        // Fake last write time
        int64_t fakeTime = 133'801'824'000'000'000LL;
        ctx.Memory().WriteU64(infoAddr + 0x00, static_cast<uint64_t>(fakeTime));
        ctx.Memory().WriteU32(infoAddr + 0x08, 0);              // TitleIndex
        ctx.Memory().WriteU32(infoAddr + 0x0C, nameByteLen);    // NameLength
        if (nameByteLen > 0) {
            ctx.Memory().Write(infoAddr + 0x10, subkeyName.c_str(), nameByteLen);
        }

        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    ctx.SetReturnNtStatus(NT::STATUS_INVALID_INFO_CLASS);
    return true;
}

// ============================================================================
// HandleNtEnumerateValueKey
// ============================================================================

bool HandleNtEnumerateValueKey(APIContext& ctx) {
    auto keyHandle   = ctx.GetArg(0);
    auto index       = ctx.GetArg32(1);
    auto infoClass   = ctx.GetArg32(2);
    auto infoAddr    = ctx.GetArgPtr(3);
    auto infoLength  = ctx.GetArg32(4);
    auto retLenAddr  = ctx.GetArgPtr(5);

    auto writeRetLen = [&](uint32_t len) {
        if (retLenAddr != 0)
            ctx.Memory().WriteU32(retLenAddr, len);
    };

    auto entry = ctx.Handles().Lookup(keyHandle, HandleType::RegistryKey);
    if (!entry) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    auto* keyData = std::get_if<RegistryKeyHandleData>(&entry->data);
    if (!keyData) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    auto values = VirtualRegistry::Instance().GetValues(keyData->path);
    if (index >= values.size()) {
        ctx.SetReturnNtStatus(NT::STATUS_NO_MORE_ENTRIES);
        return true;
    }

    const auto& val = values[index];
    uint32_t nameByteLen = static_cast<uint32_t>(val.name.size() * 2);
    uint32_t dataLen = static_cast<uint32_t>(val.data.size());

    switch (infoClass) {
    case 2: { // KeyValuePartialInformation — no name, just type+data
        uint32_t requiredSize = 12 + dataLen;
        writeRetLen(requiredSize);

        if (infoLength < requiredSize) {
            ctx.SetReturnNtStatus(NT::STATUS_BUFFER_TOO_SMALL);
            return true;
        }

        ctx.Memory().WriteU32(infoAddr + 0x00, 0);        // TitleIndex
        ctx.Memory().WriteU32(infoAddr + 0x04, val.type);  // Type
        ctx.Memory().WriteU32(infoAddr + 0x08, dataLen);   // DataLength
        if (dataLen > 0)
            ctx.Memory().Write(infoAddr + 0x0C, val.data.data(), dataLen);

        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    case 1: { // KeyValueFullInformation — includes name
        uint32_t nameAligned = (nameByteLen + 7) & ~7u;
        uint32_t dataOffset = 20 + nameAligned;
        uint32_t requiredSize = dataOffset + dataLen;
        writeRetLen(requiredSize);

        if (infoLength < requiredSize) {
            ctx.SetReturnNtStatus(NT::STATUS_BUFFER_TOO_SMALL);
            return true;
        }

        ctx.Memory().WriteU32(infoAddr + 0x00, 0);            // TitleIndex
        ctx.Memory().WriteU32(infoAddr + 0x04, val.type);      // Type
        ctx.Memory().WriteU32(infoAddr + 0x08, dataOffset);    // DataOffset
        ctx.Memory().WriteU32(infoAddr + 0x0C, dataLen);       // DataLength
        ctx.Memory().WriteU32(infoAddr + 0x10, nameByteLen);   // NameLength
        if (nameByteLen > 0)
            ctx.Memory().Write(infoAddr + 0x14, val.name.c_str(), nameByteLen);
        if (dataLen > 0)
            ctx.Memory().Write(infoAddr + dataOffset, val.data.data(), dataLen);

        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    case 0: { // KeyValueBasicInformation — name only, no data
        uint32_t requiredSize = 12 + nameByteLen;
        writeRetLen(requiredSize);

        if (infoLength < requiredSize) {
            ctx.SetReturnNtStatus(NT::STATUS_BUFFER_TOO_SMALL);
            return true;
        }

        ctx.Memory().WriteU32(infoAddr + 0x00, 0);            // TitleIndex
        ctx.Memory().WriteU32(infoAddr + 0x04, val.type);      // Type
        ctx.Memory().WriteU32(infoAddr + 0x08, nameByteLen);   // NameLength
        if (nameByteLen > 0)
            ctx.Memory().Write(infoAddr + 0x0C, val.name.c_str(), nameByteLen);

        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    default:
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_INFO_CLASS);
        return true;
    }
}

// ============================================================================
// Registration
// ============================================================================

void RegisterNtRegistry(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration regs[] = {
        { "ntdll.dll", "NtOpenKey",           HandleNtOpenKey,           3, true  },
        { "ntdll.dll", "NtCreateKey",         HandleNtCreateKey,         7, false },
        { "ntdll.dll", "NtSetValueKey",       HandleNtSetValueKey,       6, false },
        { "ntdll.dll", "NtQueryValueKey",     HandleNtQueryValueKey,     6, true  },
        { "ntdll.dll", "NtDeleteKey",         HandleNtDeleteKey,         1, false },
        { "ntdll.dll", "NtDeleteValueKey",    HandleNtDeleteValueKey,    2, false },
        { "ntdll.dll", "NtEnumerateKey",      HandleNtEnumerateKey,      6, false },
        { "ntdll.dll", "NtEnumerateValueKey", HandleNtEnumerateValueKey, 6, false },
    };
    dispatcher.RegisterBatch(regs, static_cast<uint32_t>(std::size(regs)));
}

} // namespace Phantom::WinAPI::Ntdll

#pragma warning(pop)
