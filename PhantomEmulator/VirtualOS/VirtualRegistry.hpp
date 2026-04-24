/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * VirtualRegistry.hpp — Centralized virtual registry hive
 *
 * Single authoritative registry backing for all API layers (NtRegistry,
 * RegistryAPI). Pre-populated with ~200+ realistic Windows 10 Pro 22H2
 * entries with zero VM/sandbox artifacts. Monitors persistence writes
 * (Run, RunOnce, Services, Winlogon, IFEO, AppInit_DLLs) as high-
 * priority IOCs.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../Common/Types.hpp"
#include "../Common/Config.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <shared_mutex>
#include <map>
#include <memory>

namespace Phantom::VirtualOS {

// ============================================================================
// Registry value types (matching Windows REG_* constants)
// ============================================================================

namespace RegType {
    static constexpr uint32_t None              = 0;   // REG_NONE
    static constexpr uint32_t SZ                = 1;   // REG_SZ
    static constexpr uint32_t ExpandSZ          = 2;   // REG_EXPAND_SZ
    static constexpr uint32_t Binary            = 3;   // REG_BINARY
    static constexpr uint32_t DWord             = 4;   // REG_DWORD
    static constexpr uint32_t DWordBE           = 5;   // REG_DWORD_BIG_ENDIAN
    static constexpr uint32_t Link              = 6;   // REG_LINK
    static constexpr uint32_t MultiSZ           = 7;   // REG_MULTI_SZ
    static constexpr uint32_t QWord             = 11;  // REG_QWORD
}

// ============================================================================
// Predefined root key handles (matching Windows HKEY_* constants)
// ============================================================================

namespace RootKey {
    static constexpr uint64_t HKCR  = 0x80000000ULL;  // HKEY_CLASSES_ROOT
    static constexpr uint64_t HKCU  = 0x80000001ULL;  // HKEY_CURRENT_USER
    static constexpr uint64_t HKLM  = 0x80000002ULL;  // HKEY_LOCAL_MACHINE
    static constexpr uint64_t HKU   = 0x80000003ULL;  // HKEY_USERS
    static constexpr uint64_t HKCC  = 0x80000005ULL;  // HKEY_CURRENT_CONFIG
}

// ============================================================================
// Registry value descriptor
// ============================================================================

struct RegValue {
    std::wstring            name;
    uint32_t                type = RegType::None;
    std::vector<uint8_t>    data;
};

// ============================================================================
// Registry key metadata
// ============================================================================

struct RegKeyInfo {
    std::wstring                fullPath;
    std::vector<std::wstring>   subKeyNames;
    std::vector<RegValue>       values;
    uint64_t                    lastWriteTime = 0;
    bool                        isPrePopulated = true;
};

// ============================================================================
// IOC: Registry write event (persistence detection)
// ============================================================================

struct RegistryWriteIOC {
    std::wstring            keyPath;
    std::wstring            valueName;
    uint32_t                valueType;
    std::vector<uint8_t>    data;
    bool                    isPersistence;  // Run/RunOnce/Services write
    bool                    isAutoStart;    // Service with auto-start type
};

// ============================================================================
// VirtualRegistry — Centralized, thread-safe, Meyers' singleton
// ============================================================================

class VirtualRegistry {
public:
    [[nodiscard]] static VirtualRegistry& Instance() noexcept;

    void Initialize(const EmulationConfig& config) noexcept;
    void Reset() noexcept;

    // === Key Operations ===
    [[nodiscard]] bool KeyExists(std::wstring_view fullPath) const noexcept;
    [[nodiscard]] bool CreateKey(std::wstring_view fullPath) noexcept;
    bool DeleteKey(std::wstring_view fullPath) noexcept;

    [[nodiscard]] std::vector<std::wstring> GetSubkeys(std::wstring_view fullPath) const noexcept;
    [[nodiscard]] std::optional<std::wstring> EnumSubKey(std::wstring_view fullPath,
                                                         uint32_t index) const noexcept;

    // === Value Operations ===
    bool SetValue(std::wstring_view keyPath, std::wstring_view valueName,
                  uint32_t type, const uint8_t* data, uint32_t dataSize) noexcept;

    /// Returns a locked snapshot of a value. The returned object never aliases
    /// internal registry storage and remains valid after concurrent mutation.
    [[nodiscard]] std::optional<RegValue> QueryValue(std::wstring_view keyPath,
                                                     std::wstring_view valueName) const noexcept;

    bool DeleteValue(std::wstring_view keyPath, std::wstring_view valueName) noexcept;

    [[nodiscard]] std::vector<RegValue> GetValues(std::wstring_view keyPath) const noexcept;
    [[nodiscard]] std::optional<RegValue> EnumValue(std::wstring_view keyPath,
                                                     uint32_t index) const noexcept;

    // === Key metadata ===
    [[nodiscard]] uint32_t GetSubkeyCount(std::wstring_view keyPath) const noexcept;
    [[nodiscard]] uint32_t GetValueCount(std::wstring_view keyPath) const noexcept;
    [[nodiscard]] uint32_t GetMaxValueNameLen(std::wstring_view keyPath) const noexcept;
    [[nodiscard]] uint32_t GetMaxValueDataLen(std::wstring_view keyPath) const noexcept;

    // === Path Utilities ===
    [[nodiscard]] static std::wstring NormalizePath(std::wstring_view path) noexcept;
    [[nodiscard]] static std::wstring ResolveRootHandle(uint64_t rootHandle,
                                                         std::wstring_view subKey) noexcept;
    [[nodiscard]] static bool IsRootHandle(uint64_t handle) noexcept;

    // === IOC Tracking ===
    [[nodiscard]] std::vector<RegistryWriteIOC> GetWriteIOCs() const noexcept;
    [[nodiscard]] bool HasPersistenceWrites() const noexcept;

private:
    VirtualRegistry() noexcept = default;
    VirtualRegistry(const VirtualRegistry&) = delete;
    VirtualRegistry& operator=(const VirtualRegistry&) = delete;

    void PopulateDefaults(const EmulationConfig& config);
    void AddKey(std::wstring_view path);
    void AddStrValue(std::wstring_view keyPath, std::wstring_view name,
                     std::wstring_view value);
    void AddExpandSzValue(std::wstring_view keyPath, std::wstring_view name,
                          std::wstring_view value);
    void AddDwordValue(std::wstring_view keyPath, std::wstring_view name,
                       uint32_t value);
    void AddQwordValue(std::wstring_view keyPath, std::wstring_view name,
                       uint64_t value);
    void AddBinaryValue(std::wstring_view keyPath, std::wstring_view name,
                        const std::vector<uint8_t>& data);
    void AddMultiSzValue(std::wstring_view keyPath, std::wstring_view name,
                         const std::vector<std::wstring>& strings);

    [[nodiscard]] static bool IsPersistencePath(std::wstring_view path) noexcept;
    [[nodiscard]] static bool IsAutoStartService(std::wstring_view path,
                                                  std::wstring_view valueName,
                                                  const std::vector<uint8_t>& data) noexcept;

    mutable std::shared_mutex           m_mutex;
    std::map<std::wstring, RegKeyInfo, std::less<>>  m_keys;
    std::vector<RegistryWriteIOC>       m_writeIOCs;
    bool                                m_initialized = false;

    static constexpr size_t kMaxKeys            = 50000;
    static constexpr size_t kMaxValuesPerKey     = 1000;
    static constexpr size_t kMaxValueData        = 1 * 1024 * 1024;  // 1 MB per value
    static constexpr size_t kMaxWriteIOCs        = 10000;
};

} // namespace Phantom::VirtualOS
