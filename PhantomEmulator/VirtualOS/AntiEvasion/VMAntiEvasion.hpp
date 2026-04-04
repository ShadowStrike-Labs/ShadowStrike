/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * VMAntiEvasion.hpp — VM/sandbox detection bypass
 *
 * Sophisticated malware detects VMs through dozens of fingerprints:
 * CPUID hypervisor bit, VM-specific files/processes/registry keys,
 * MAC address OUI prefixes, SMBIOS data, device names, and more.
 * This module ensures NONE of these fingerprints trigger, while
 * tracking every check attempt as a behavioral IOC.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <atomic>
#include <shared_mutex>

namespace Phantom::VirtualOS::AntiEvasion {

// ============================================================================
// VMAntiEvasion — Comprehensive VM/sandbox detection bypass
// ============================================================================

class VMAntiEvasion {
public:
    [[nodiscard]] static VMAntiEvasion& Instance() noexcept;

    void Initialize(const EmulationConfig& config) noexcept;
    void Reset() noexcept;

    // === CPUID-based checks ===
    [[nodiscard]] bool        HasHypervisorBit() const noexcept;
    [[nodiscard]] std::string GetCPUVendor() const noexcept;
    [[nodiscard]] std::string GetCPUBrandString() const noexcept;

    // === Registry-based checks ===
    [[nodiscard]] bool HasVMRegistryKeys() const noexcept;
    [[nodiscard]] std::vector<std::wstring> GetSafeRegistryKeys() const noexcept;

    // === File system checks ===
    [[nodiscard]] bool HasVMFiles() const noexcept;
    [[nodiscard]] bool HasVMDrivers() const noexcept;

    // === Process checks ===
    [[nodiscard]] bool HasVMProcesses() const noexcept;
    [[nodiscard]] std::vector<std::wstring> GetVMProcessBlocklist() const noexcept;

    // === Hardware checks ===
    [[nodiscard]] bool HasVMMACAddress() const noexcept;
    [[nodiscard]] bool HasVMDeviceNames() const noexcept;
    [[nodiscard]] bool HasSmallDisk() const noexcept;
    [[nodiscard]] bool HasFewProcessors() const noexcept;
    [[nodiscard]] bool HasLowRAM() const noexcept;
    [[nodiscard]] bool HasLowScreenResolution() const noexcept;

    // === Firmware/SMBIOS checks ===
    [[nodiscard]] bool HasVMFirmware() const noexcept;
    [[nodiscard]] bool HasVMBIOS() const noexcept;

    // === Red pill / blue pill techniques ===
    [[nodiscard]] bool RedPillCheck() const noexcept;
    [[nodiscard]] bool NoPillCheck() const noexcept;

    // === Sandbox-specific checks ===
    [[nodiscard]] bool     IsSandbox() const noexcept;
    [[nodiscard]] bool     HasRecentUserActivity() const noexcept;
    [[nodiscard]] uint32_t GetRecentFileCount() const noexcept;
    [[nodiscard]] uint32_t GetInstalledSoftwareCount() const noexcept;
    [[nodiscard]] uint32_t GetBrowserHistoryCount() const noexcept;

    // === Known VM artifact blocklists ===
    [[nodiscard]] static bool IsVMFileName(std::wstring_view filename) noexcept;
    [[nodiscard]] static bool IsVMRegistryKey(std::wstring_view keyPath) noexcept;
    [[nodiscard]] static bool IsVMProcessName(std::wstring_view processName) noexcept;
    [[nodiscard]] static bool IsVMDriverName(std::wstring_view driverName) noexcept;
    [[nodiscard]] static bool IsVMMACPrefix(const uint8_t mac[6]) noexcept;
    [[nodiscard]] static bool IsVMDeviceName(std::wstring_view deviceName) noexcept;

    // === Evasion attempt tracking ===
    void RecordVMCheckAttempt(std::string_view technique) noexcept;
    [[nodiscard]] uint32_t GetVMCheckCount() const noexcept;
    [[nodiscard]] std::vector<std::string> GetDetectedTechniques() const noexcept;

private:
    VMAntiEvasion() noexcept = default;
    ~VMAntiEvasion() noexcept = default;
    VMAntiEvasion(const VMAntiEvasion&) = delete;
    VMAntiEvasion& operator=(const VMAntiEvasion&) = delete;

    // Case-insensitive wide string comparison helper
    [[nodiscard]] static bool WideStringContainsCaseInsensitive(
        std::wstring_view haystack, std::wstring_view needle) noexcept;

    mutable std::shared_mutex     m_mutex;
    std::vector<std::string>      m_detectedTechniques;
    mutable std::atomic<uint32_t> m_vmCheckCount{0};

    bool m_initialized = false;

    static constexpr uint32_t kMaxTrackedTechniques = 4096;
};

} // namespace Phantom::VirtualOS::AntiEvasion
