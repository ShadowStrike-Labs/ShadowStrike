/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * EnvironmentAntiEvasion.hpp — Hardware/system info faker
 *
 * Malware queries CPUID, system info, firmware tables, MAC addresses,
 * etc. to detect VMs and sandboxes. This module provides centralized,
 * consistent responses mimicking a real Dell Precision 5570 workstation
 * with an Intel i7-12700H CPU.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"
#include <cstdint>
#include <array>
#include <string>
#include <vector>
#include <shared_mutex>

namespace Phantom::VirtualOS::AntiEvasion {

// ============================================================================
// CPUIDResult — Mirrors the EAX/EBX/ECX/EDX register output
// ============================================================================

struct CPUIDResult {
    uint32_t eax = 0;
    uint32_t ebx = 0;
    uint32_t ecx = 0;
    uint32_t edx = 0;
};

// ============================================================================
// EnvironmentAntiEvasion — Centralized hardware/system identity
// ============================================================================

class EnvironmentAntiEvasion {
public:
    [[nodiscard]] static EnvironmentAntiEvasion& Instance() noexcept;

    void Initialize(const EmulationConfig& config) noexcept;
    void Reset() noexcept;

    // CPUID — the single most important anti-VM check
    [[nodiscard]] CPUIDResult GetCPUID(uint32_t leaf, uint32_t subleaf = 0) const noexcept;

    // System info
    [[nodiscard]] uint32_t GetProcessorCount() const noexcept;
    [[nodiscard]] uint64_t GetTotalPhysicalMemory() const noexcept;
    [[nodiscard]] uint64_t GetAvailablePhysicalMemory() const noexcept;
    [[nodiscard]] uint64_t GetTotalDiskSpace() const noexcept;
    [[nodiscard]] uint64_t GetFreeDiskSpace() const noexcept;
    [[nodiscard]] uint32_t GetScreenWidth() const noexcept;
    [[nodiscard]] uint32_t GetScreenHeight() const noexcept;

    // MAC address (first network adapter)
    [[nodiscard]] std::array<uint8_t, 6> GetMACAddress() const noexcept;

    // Firmware/SMBIOS
    struct SMBIOSData {
        std::string manufacturer;
        std::string product;
        std::string serialNumber;
        std::string biosVendor;
        std::string biosVersion;
        std::string biosDate;
        std::vector<uint8_t> rawTable;
    };
    [[nodiscard]] const SMBIOSData& GetSMBIOS() const noexcept;

    // Device names
    [[nodiscard]] std::string GetDiskModel() const noexcept;
    [[nodiscard]] std::string GetGPUName() const noexcept;

    // Computer/User info
    [[nodiscard]] const std::wstring& GetComputerName() const noexcept;
    [[nodiscard]] const std::wstring& GetUserName() const noexcept;
    [[nodiscard]] const std::wstring& GetDomainName() const noexcept;

private:
    EnvironmentAntiEvasion() noexcept = default;
    ~EnvironmentAntiEvasion() noexcept = default;
    EnvironmentAntiEvasion(const EnvironmentAntiEvasion&) = delete;
    EnvironmentAntiEvasion& operator=(const EnvironmentAntiEvasion&) = delete;

    void BuildCPUIDTable() noexcept;
    void BuildSMBIOSTable() noexcept;

    struct CPUIDEntry {
        uint32_t leaf;
        uint32_t subleaf;
        CPUIDResult result;
    };

    mutable std::shared_mutex m_mutex;
    std::vector<CPUIDEntry> m_cpuidTable;
    SMBIOSData              m_smbios;

    // Cached environment values
    uint32_t    m_processorCount    = 8;
    uint64_t    m_totalPhysicalMem  = 16ULL * 1024 * 1024 * 1024;
    uint64_t    m_totalDiskSpace    = 512ULL * 1024 * 1024 * 1024;
    uint32_t    m_screenWidth       = 1920;
    uint32_t    m_screenHeight      = 1080;
    std::array<uint8_t, 6> m_macAddress{};

    std::wstring m_computerName;
    std::wstring m_userName;
    std::wstring m_domainName;

    bool m_initialized = false;
};

} // namespace Phantom::VirtualOS::AntiEvasion
