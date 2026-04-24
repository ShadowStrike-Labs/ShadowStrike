/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#pragma once

#include "../Common/Types.hpp"
#include "../Common/Config.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <array>
#include <shared_mutex>

// Forward declarations for VirtualOS subsystems
namespace Phantom {
    class VirtualMemory;
}

namespace Phantom::VirtualOS {
    class VirtualFileSystem;
    class VirtualRegistry;
    class VirtualProcess;
    class VirtualNetwork;
}

namespace Phantom::VirtualOS::AntiEvasion {
    class TimingAntiEvasion;
    class EnvironmentAntiEvasion;
    class DebuggerAntiEvasion;
    class VMAntiEvasion;
}

namespace Phantom::VirtualOS {

// Validation result
struct EnvironmentValidation {
    bool isValid = false;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
};

// Complete environment snapshot (for serialization / reporting)
struct EnvironmentSnapshot {
    // Identity
    std::wstring computerName;
    std::wstring userName;
    std::wstring domainName;

    // Hardware
    std::string cpuBrand;
    uint32_t processorCount;
    uint64_t totalRAM;
    uint64_t totalDisk;
    std::string diskModel;
    std::string gpuName;
    std::array<uint8_t, 6> macAddress;

    // OS
    uint32_t osBuild;
    std::string windowsEdition;

    // Timing
    uint64_t startTSC;
    uint64_t startTickCount;
    uint64_t startFileTime;

    // Process
    uint32_t emulatedPID;
    uint32_t parentPID;
    uint32_t initialTID;
    uint32_t processCount;  // fake process table size

    // Session
    uint32_t fileSystemEntries;
    uint32_t registryKeys;
};

class EnvironmentBuilder {
public:
    [[nodiscard]] static EnvironmentBuilder& Instance() noexcept;

    // === Primary Interface ===

    // Initialize the complete virtual environment
    // This is the ONLY call needed — it initializes everything in correct order
    // Returns false if config validation fails
    [[nodiscard]] bool Build(const EmulationConfig& config) noexcept;

    // Build PEB/TEB structures in guest memory
    // Must be called AFTER VirtualMemory is initialized
    [[nodiscard]] bool BuildPEBTEB(VirtualMemory& memory) noexcept;

    // Build PEB LDR data (loaded module list)
    // Must be called AFTER modules are loaded
    [[nodiscard]] bool BuildLdrData(VirtualMemory& memory) noexcept;

    // Reset all subsystems for a new session
    void Reset() noexcept;

    // === Validation ===

    // Check that the environment is internally consistent
    [[nodiscard]] EnvironmentValidation Validate() const noexcept;

    // === Snapshot ===

    // Get a snapshot of the current environment (for reporting)
    [[nodiscard]] EnvironmentSnapshot GetSnapshot() const noexcept;

    // === Convenience Accessors ===

    [[nodiscard]] EmulationConfig GetConfig() const noexcept;
    [[nodiscard]] bool IsInitialized() const noexcept;

    // PEB/TEB addresses (set during BuildPEBTEB)
    [[nodiscard]] GuestAddress GetPEBAddress() const noexcept;
    [[nodiscard]] GuestAddress GetTEBAddress() const noexcept;
    [[nodiscard]] GuestAddress GetPEBLdrDataAddress() const noexcept;

private:
    EnvironmentBuilder() noexcept = default;
    EnvironmentBuilder(const EnvironmentBuilder&) = delete;
    EnvironmentBuilder& operator=(const EnvironmentBuilder&) = delete;

    // Initialization phases (called by Build in order)
    void ResetUnlocked() noexcept;
    void RandomizeSessionValues(EmulationConfig& config) noexcept;
    bool InitializeSubsystems(const EmulationConfig& config) noexcept;
    bool ValidateConsistency() noexcept;
    [[nodiscard]] EnvironmentValidation ValidateUnlocked() const noexcept;
    [[nodiscard]] bool ValidateConfigInput(const EmulationConfig& config,
                                           EnvironmentValidation* validation) const noexcept;

    // PEB/TEB building helpers
    bool WritePEB(VirtualMemory& memory) noexcept;
    bool WriteTEB(VirtualMemory& memory) noexcept;
    bool WriteProcessParameters(VirtualMemory& memory) noexcept;
    bool WriteLdrData(VirtualMemory& memory) noexcept;

    EmulationConfig m_config;
    bool m_initialized = false;
    mutable std::shared_mutex m_mutex;

    // PEB/TEB guest addresses
    GuestAddress m_pebAddress = 0;
    GuestAddress m_tebAddress = 0;
    GuestAddress m_processParamsAddress = 0;
    GuestAddress m_ldrDataAddress = 0;
    GuestAddress m_processHeapAddress = 0;
};

} // namespace Phantom::VirtualOS
