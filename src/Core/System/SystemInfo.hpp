/**
 * ============================================================================
 * ShadowStrike Core System - SYSTEM INFO (The Context Provider)
 * ============================================================================
 *
 * @file SystemInfo.hpp
 * @brief Enterprise-grade system information and environment detection.
 *
 * This module provides comprehensive system telemetry and environment
 * detection capabilities essential for security decisions, heuristics
 * adjustment, and threat detection.
 *
 * Key Capabilities:
 * =================
 * 1. HARDWARE DETECTION
 *    - CPU features (virtualization, AES-NI, etc.)
 *    - Memory configuration
 *    - Storage devices
 *    - Network interfaces
 *
 * 2. OS INFORMATION
 *    - Windows version/build
 *    - Installed features
 *    - Security settings
 *    - Update status
 *
 * 3. ENVIRONMENT DETECTION
 *    - Virtual machine detection
 *    - Sandbox detection
 *    - Debugger detection
 *    - Safe mode detection
 *
 * 4. MACHINE FINGERPRINTING
 *    - Unique machine ID
 *    - Hardware fingerprint
 *    - Installation ID
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1497.001: System Checks (VM/Sandbox detection)
 * - T1082: System Information Discovery
 * - T1124: System Time Discovery
 * - T1614: System Location Discovery
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see Utils/SystemUtils.hpp for low-level utilities
 * @see AntiEvasion/ for evasion detection
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/SystemUtils.hpp"        // Core system utilities
#include "../../Utils/RegistryUtils.hpp"      // Registry-based system info
#include "../../Utils/NetworkUtils.hpp"       // Network interface detection
#include "../../Utils/ProcessUtils.hpp"       // Process environment

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <chrono>
#include <atomic>
#include <shared_mutex>

namespace ShadowStrike {
namespace Core {
namespace System {

// Forward declaration is inside the class definition for PIMPL pattern

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum VirtualizationType
 * @brief Detected virtualization platform.
 */
enum class VirtualizationType : uint8_t {
    None = 0,
    VMware = 1,
    VirtualBox = 2,
    HyperV = 3,
    QEMU = 4,
    KVM = 5,
    Xen = 6,
    Parallels = 7,
    AmazonEC2 = 8,
    AzureVM = 9,
    GoogleCloud = 10,
    Unknown = 255
};

/**
 * @enum CloudVMType
 * @brief Cloud provider VM type (legitimate cloud, not suspicious).
 */
enum class CloudVMType : uint8_t {
    None = 0,
    AWS = 1,
    Azure = 2,
    GCP = 3,
    DigitalOcean = 4,
    Linode = 5,
    Oracle = 6,
    Unknown = 255
};

/**
 * @enum SandboxType
 * @brief Detected sandbox environment.
 */
enum class SandboxType : uint8_t {
    None = 0,
    CuckooSandbox = 1,
    JoeSandbox = 2,
    AnyRun = 3,
    HybridAnalysis = 4,
    WindowsSandbox = 5,
    Generic = 255
};

/**
 * @enum BootMode
 * @brief System boot mode.
 */
enum class BootMode : uint8_t {
    Normal = 0,
    SafeMode = 1,
    SafeModeWithNetworking = 2,
    DirectoryServicesRepair = 3,
    WinRE = 4
};

/**
 * @enum ProcessorArchitecture
 * @brief CPU architecture.
 */
enum class ProcessorArchitecture : uint8_t {
    Unknown = 0,
    X86 = 1,
    X64 = 2,
    ARM = 3,
    ARM64 = 4
};

/**
 * @enum PowerState
 * @brief System power state.
 */
enum class PowerState : uint8_t {
    Unknown = 0,
    ACPower = 1,
    Battery = 2,
    BatteryLow = 3,
    BatteryCritical = 4
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct OSVersion
 * @brief Operating system version details.
 */
struct alignas(64) OSVersion {
    uint32_t majorVersion{ 0 };
    uint32_t minorVersion{ 0 };
    uint32_t buildNumber{ 0 };
    uint32_t revisionNumber{ 0 };
    std::wstring displayVersion;      // e.g., "23H2"
    std::wstring edition;             // e.g., "Professional"
    std::wstring productName;         // e.g., "Windows 11"
    bool isServer{ false };
    bool isWorkstation{ true };
};

/**
 * @struct CPUInfo
 * @brief Processor information.
 */
struct alignas(128) CPUInfo {
    std::wstring vendor;              // e.g., "GenuineIntel"
    std::wstring brand;               // e.g., "Intel Core i9-13900K"
    ProcessorArchitecture architecture{ ProcessorArchitecture::Unknown };
    uint32_t physicalCores{ 0 };
    uint32_t logicalCores{ 0 };
    uint32_t baseMHz{ 0 };
    uint32_t maxMHz{ 0 };
    uint32_t cacheL1KB{ 0 };
    uint32_t cacheL2KB{ 0 };
    uint32_t cacheL3KB{ 0 };
    
    // Feature flags
    bool hasSSE42{ false };
    bool hasAVX{ false };
    bool hasAVX2{ false };
    bool hasAVX512{ false };
    bool hasAESNI{ false };
    bool hasSHA{ false };
    bool hasVirtualization{ false };  // VT-x/AMD-V
    bool hasHypervisorBit{ false };   // Hypervisor present
};

/**
 * @struct MemoryInfo
 * @brief System memory information.
 */
struct alignas(64) MemoryInfo {
    uint64_t totalPhysicalBytes{ 0 };
    uint64_t availablePhysicalBytes{ 0 };
    uint64_t totalVirtualBytes{ 0 };
    uint64_t availableVirtualBytes{ 0 };
    uint64_t totalPageFileBytes{ 0 };
    uint64_t availablePageFileBytes{ 0 };
    uint32_t memoryLoad{ 0 };          // 0-100%
};

/**
 * @struct StorageInfo
 * @brief Storage device information.
 */
struct alignas(64) StorageInfo {
    std::wstring devicePath;
    std::wstring model;
    std::wstring serialNumber;
    uint64_t totalBytes{ 0 };
    bool isSSD{ false };
    bool isRemovable{ false };
    bool isSystemDrive{ false };
};

/**
 * @struct NetworkInterfaceInfo
 * @brief Network interface information.
 */
struct alignas(64) NetworkInterfaceInfo {
    std::wstring name;
    std::wstring description;
    std::wstring macAddress;
    std::vector<std::wstring> ipv4Addresses;
    std::vector<std::wstring> ipv6Addresses;
    bool isUp{ false };
    bool isLoopback{ false };
    bool isVirtual{ false };
    uint64_t speedMbps{ 0 };
};

/**
 * @struct VirtualizationInfo
 * @brief Virtualization detection results.
 */
struct alignas(64) VirtualizationInfo {
    bool isVirtualized{ false };
    bool isCloudVM{ false };           // True if running on AWS/Azure/GCP (legitimate)
    VirtualizationType type{ VirtualizationType::None };
    CloudVMType cloudType{ CloudVMType::None };
    double confidence{ 0.0 };
    std::wstring hypervisorName;
    std::wstring vmToolsVersion;
    std::vector<std::wstring> indicators;
};

/**
 * @struct SandboxInfo
 * @brief Sandbox detection results.
 */
struct alignas(64) SandboxInfo {
    bool isSandboxed{ false };
    SandboxType type{ SandboxType::None };
    double confidence{ 0.0 };
    std::vector<std::wstring> indicators;
};

/**
 * @struct DebuggerInfo
 * @brief Debugger detection results.
 */
struct alignas(32) DebuggerInfo {
    bool isDebuggerPresent{ false };
    bool isKernelDebuggerPresent{ false };
    bool isRemoteDebuggerPresent{ false };
    std::wstring debuggerName;
};

/**
 * @struct MachineFingerprint
 * @brief Unique machine identification.
 */
struct alignas(128) MachineFingerprint {
    std::wstring machineId;           // Persistent unique ID
    std::wstring hardwareFingerprint; // Hardware-based hash
    std::wstring installationId;      // OS installation ID
    std::wstring biosSerial;
    std::wstring motherboardSerial;
    std::vector<std::wstring> macAddresses;
    std::vector<std::wstring> diskSerials;
};

/**
 * @struct SecuritySettings
 * @brief System security configuration.
 */
struct alignas(64) SecuritySettings {
    bool isSecureBoot{ false };
    bool isBitLockerEnabled{ false };
    bool isUACEnabled{ false };
    uint32_t uacLevel{ 0 };
    bool isDefenderEnabled{ false };
    bool isFirewallEnabled{ false };
    bool isDEPEnabled{ false };
    bool isASLREnabled{ false };
    bool isSMEPEnabled{ false };
    bool isCredentialGuard{ false };
};

/**
 * @struct SystemSnapshot
 * @brief Complete system snapshot.
 */
struct alignas(256) SystemSnapshot {
    OSVersion os;
    CPUInfo cpu;
    MemoryInfo memory;
    std::vector<StorageInfo> storage;
    std::vector<NetworkInterfaceInfo> network;
    VirtualizationInfo virtualization;
    SandboxInfo sandbox;
    DebuggerInfo debugger;
    MachineFingerprint fingerprint;
    SecuritySettings security;
    BootMode bootMode{ BootMode::Normal };
    PowerState powerState{ PowerState::Unknown };
    std::chrono::system_clock::time_point bootTime;
    std::chrono::system_clock::time_point snapshotTime;
};

/**
 * @struct SystemInfoStatistics
 * @brief Runtime statistics.
 */
struct alignas(64) SystemInfoStatistics {
    std::atomic<uint64_t> queriesExecuted{ 0 };
    std::atomic<uint64_t> vmDetections{ 0 };
    std::atomic<uint64_t> sandboxDetections{ 0 };
    std::atomic<uint64_t> debuggerDetections{ 0 };
    
    void Reset() noexcept;
};

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class SystemInfo
 * @brief Enterprise-grade system information provider.
 *
 * Thread-safe singleton providing comprehensive system information
 * and environment detection capabilities.
 */
class SystemInfo {
    // Forward declaration of PIMPL implementation struct
    struct SystemInfoImpl;

public:
    /**
     * @brief Gets singleton instance.
     */
    [[nodiscard]] static SystemInfo& Instance() noexcept;

    /**
     * @brief Check if singleton instance has been created.
     * @return True if instance exists.
     */
    [[nodiscard]] static bool HasInstance() noexcept;

    /**
     * @brief Initializes system info (caches static data).
     */
    [[nodiscard]] bool Initialize();

    /**
     * @brief Shuts down system info.
     */
    void Shutdown() noexcept;

    /**
     * @brief Check if system info is initialized.
     * @return True if initialized.
     */
    [[nodiscard]] bool IsInitialized() const noexcept;
    
    /**
     * @brief Refreshes dynamic information.
     */
    void Refresh();
    
    // ========================================================================
    // BASIC SYSTEM INFORMATION
    // ========================================================================
    
    /**
     * @brief Gets OS version information.
     */
    [[nodiscard]] const OSVersion& GetOSVersion() const noexcept;
    
    /**
     * @brief Gets CPU information.
     */
    [[nodiscard]] const CPUInfo& GetCPUInfo() const noexcept;
    
    /**
     * @brief Gets current memory status.
     */
    [[nodiscard]] MemoryInfo GetMemoryInfo() const;
    
    /**
     * @brief Gets storage device information.
     */
    [[nodiscard]] std::vector<StorageInfo> GetStorageInfo() const;
    
    /**
     * @brief Gets network interface information.
     */
    [[nodiscard]] std::vector<NetworkInterfaceInfo> GetNetworkInfo() const;
    
    // ========================================================================
    // ENVIRONMENT DETECTION
    // ========================================================================
    
    /**
     * @brief Detects virtualization.
     */
    [[nodiscard]] VirtualizationInfo DetectVirtualization() const;
    
    /**
     * @brief Checks if running in a VM.
     */
    [[nodiscard]] bool IsVirtualMachine() const;
    
    /**
     * @brief Detects sandbox environment.
     */
    [[nodiscard]] SandboxInfo DetectSandbox() const;
    
    /**
     * @brief Checks if running in a sandbox.
     */
    [[nodiscard]] bool IsSandboxed() const;
    
    /**
     * @brief Detects debugger presence.
     */
    [[nodiscard]] DebuggerInfo DetectDebugger() const;
    
    /**
     * @brief Checks if debugger is present.
     */
    [[nodiscard]] bool IsDebuggerPresent() const;
    
    /**
     * @brief Gets current boot mode.
     */
    [[nodiscard]] BootMode GetBootMode() const;
    
    /**
     * @brief Checks if in Safe Mode.
     */
    [[nodiscard]] bool IsSafeMode() const;
    
    // ========================================================================
    // MACHINE IDENTIFICATION
    // ========================================================================
    
    /**
     * @brief Gets machine fingerprint.
     */
    [[nodiscard]] MachineFingerprint GetMachineFingerprint() const;
    
    /**
     * @brief Gets unique machine ID.
     */
    [[nodiscard]] std::wstring GetMachineId() const;
    
    /**
     * @brief Gets hardware fingerprint hash.
     */
    [[nodiscard]] std::wstring GetHardwareFingerprint() const;
    
    // ========================================================================
    // SECURITY STATUS
    // ========================================================================
    
    /**
     * @brief Gets security settings.
     */
    [[nodiscard]] SecuritySettings GetSecuritySettings() const;
    
    /**
     * @brief Checks if running with admin privileges.
     */
    [[nodiscard]] bool IsElevated() const;
    
    /**
     * @brief Gets system uptime.
     */
    [[nodiscard]] std::chrono::milliseconds GetUptime() const;
    
    /**
     * @brief Gets system boot time.
     */
    [[nodiscard]] std::chrono::system_clock::time_point GetBootTime() const;
    
    /**
     * @brief Gets current power state.
     */
    [[nodiscard]] PowerState GetPowerState() const;
    
    // ========================================================================
    // COMPLETE SNAPSHOT
    // ========================================================================
    
    /**
     * @brief Gets complete system snapshot.
     */
    [[nodiscard]] SystemSnapshot GetSnapshot() const;
    
    // ========================================================================
    // STATISTICS & DIAGNOSTICS
    // ========================================================================

    [[nodiscard]] const SystemInfoStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

    /**
     * @brief Get system info version.
     * @return Version string.
     */
    [[nodiscard]] static std::string GetVersionString() noexcept;

    /**
     * @brief Run self-test.
     * @return True if all tests pass.
     */
    [[nodiscard]] bool SelfTest();

    /**
     * @brief Run diagnostics.
     * @return Diagnostic messages.
     */
    [[nodiscard]] std::vector<std::wstring> RunDiagnostics() const;

    // ========================================================================
    // EXPORT
    // ========================================================================

    /**
     * @brief Export system snapshot.
     * @param outputPath Output file path.
     * @return True if successful.
     */
    [[nodiscard]] bool ExportSnapshot(const std::wstring& outputPath) const;

private:
    SystemInfo();
    ~SystemInfo();

    // Delete copy/move
    SystemInfo(const SystemInfo&) = delete;
    SystemInfo& operator=(const SystemInfo&) = delete;
    SystemInfo(SystemInfo&&) = delete;
    SystemInfo& operator=(SystemInfo&&) = delete;

    std::unique_ptr<SystemInfoImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetVirtualizationTypeName(VirtualizationType type) noexcept;
[[nodiscard]] std::string_view GetSandboxTypeName(SandboxType type) noexcept;
[[nodiscard]] std::string_view GetBootModeName(BootMode mode) noexcept;
[[nodiscard]] std::string_view GetProcessorArchitectureName(ProcessorArchitecture arch) noexcept;
[[nodiscard]] std::string_view GetPowerStateName(PowerState state) noexcept;

}  // namespace System
}  // namespace Core
}  // namespace ShadowStrike