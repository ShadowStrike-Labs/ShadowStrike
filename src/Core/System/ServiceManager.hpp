/**
 * ============================================================================
 * ShadowStrike Core System - SERVICE MANAGER (The Orchestrator)
 * ============================================================================
 *
 * @file ServiceManager.hpp
 * @brief Enterprise-grade Windows Service and kernel driver lifecycle manager.
 *
 * This module provides comprehensive service management for the antivirus
 * platform including self-protection, driver loading, service remediation,
 * and ELAM (Early Launch Anti-Malware) integration.
 *
 * Key Capabilities:
 * =================
 * 1. SERVICE LIFECYCLE
 *    - Install/uninstall services
 *    - Start/stop/restart with dependencies
 *    - Configuration modification
 *    - Failure recovery setup
 *
 * 2. DRIVER MANAGEMENT
 *    - Minifilter loading (FltMgr)
 *    - Altitude management
 *    - ELAM driver support
 *    - WDF driver support
 *
 * 3. SELF-PROTECTION
 *    - Tamper detection
 *    - Service configuration monitoring
 *    - Automatic restart on failure
 *    - Privilege verification
 *
 * 4. THREAT REMEDIATION
 *    - Disable malicious services
 *    - Kill persistent malware
 *    - Clean service registry entries
 *    - Driver unload for rootkits
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1543.003: Windows Service
 * - T1569.002: Service Execution
 * - T1489: Service Stop
 * - T1562.001: Disable Security Tools
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see DriverAnalyzer.hpp for driver security analysis
 * @see ProcessMonitor.hpp for process-level control
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/SystemUtils.hpp"        // OS info, privilege checks
#include "../../Utils/RegistryUtils.hpp"      // Service registry operations
#include "../../Utils/FileUtils.hpp"          // Binary path validation
#include "../../Utils/CertUtils.hpp"          // Driver signature verification
#include "../../Utils/ProcessUtils.hpp"       // Process handle operations

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <shared_mutex>

namespace ShadowStrike {
namespace Core {
namespace System {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class ServiceManagerImpl;

// ============================================================================
// CONSTANTS
// ============================================================================
namespace ServiceManagerConstants {

// Service control codes
constexpr uint32_t CONTROL_STOP = 0x00000001;
constexpr uint32_t CONTROL_PAUSE = 0x00000002;
constexpr uint32_t CONTROL_CONTINUE = 0x00000003;
constexpr uint32_t CONTROL_INTERROGATE = 0x00000004;
constexpr uint32_t CONTROL_SHUTDOWN = 0x00000005;

// Timeouts
constexpr uint32_t DEFAULT_TIMEOUT_MS = 30000;
constexpr uint32_t DRIVER_LOAD_TIMEOUT_MS = 60000;

// Minifilter altitudes (our range)
constexpr uint32_t ALTITUDE_AV_FILTER = 320000;     // Anti-virus filter
constexpr uint32_t ALTITUDE_ACTIVITY_MONITOR = 389000; // Activity monitor

}  // namespace ServiceManagerConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum ServiceState
 * @brief Current state of a service.
 */
enum class ServiceState : uint8_t {
    Unknown = 0,
    Stopped = 1,
    StartPending = 2,
    StopPending = 3,
    Running = 4,
    ContinuePending = 5,
    PausePending = 6,
    Paused = 7
};

/**
 * @enum ServiceType
 * @brief Type of Windows service.
 */
enum class ServiceType : uint8_t {
    Unknown = 0,
    KernelDriver = 1,              // SERVICE_KERNEL_DRIVER
    FileSystemDriver = 2,          // SERVICE_FILE_SYSTEM_DRIVER
    Win32OwnProcess = 3,           // SERVICE_WIN32_OWN_PROCESS
    Win32ShareProcess = 4,         // SERVICE_WIN32_SHARE_PROCESS
    InteractiveProcess = 5,        // With SERVICE_INTERACTIVE_PROCESS
    UserService = 6                // Per-user service
};

/**
 * @enum StartType
 * @brief Service start type.
 */
enum class StartType : uint8_t {
    Unknown = 0,
    BootStart = 1,                 // Driver started by kernel loader
    SystemStart = 2,               // Driver started during kernel init
    AutoStart = 3,                 // Started by SCM at boot
    DemandStart = 4,               // Started manually
    Disabled = 5                   // Cannot be started
};

/**
 * @enum ServiceThreatLevel
 * @brief Threat level assessment for a service.
 */
enum class ServiceThreatLevel : uint8_t {
    Safe = 0,
    Unknown = 1,
    Suspicious = 2,
    Malicious = 3,
    Rootkit = 4
};

/**
 * @enum FailureAction
 * @brief Action to take on service failure.
 */
enum class FailureAction : uint8_t {
    None = 0,
    Restart = 1,
    Reboot = 2,
    RunCommand = 3
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct ServiceInfo
 * @brief Comprehensive service information.
 */
struct alignas(128) ServiceInfo {
    // Identity
    std::wstring serviceName;
    std::wstring displayName;
    std::wstring description;
    
    // Configuration
    ServiceType serviceType{ ServiceType::Unknown };
    StartType startType{ StartType::Unknown };
    std::wstring binaryPath;
    std::wstring loadOrderGroup;
    std::vector<std::wstring> dependencies;
    
    // Account
    std::wstring serviceAccount;
    bool isLocalSystem{ false };
    
    // Status
    ServiceState state{ ServiceState::Unknown };
    uint32_t processId{ 0 };
    uint32_t exitCode{ 0 };
    
    // Security
    bool isSigned{ false };
    std::wstring signerName;
    std::wstring signerThumbprint;
    ServiceThreatLevel threatLevel{ ServiceThreatLevel::Unknown };
    
    // Timestamps
    std::chrono::system_clock::time_point installTime;
    std::chrono::system_clock::time_point lastStartTime;
    
    // Flags
    bool acceptsStop{ false };
    bool acceptsPause{ false };
    bool isProtected{ false };      // PPL or critical
    bool isMicrosoft{ false };
};

/**
 * @struct ServiceConfig
 * @brief Configuration for installing a new service.
 */
struct alignas(64) ServiceConfig {
    std::wstring serviceName;
    std::wstring displayName;
    std::wstring description;
    std::wstring binaryPath;
    ServiceType serviceType{ ServiceType::Win32OwnProcess };
    StartType startType{ StartType::AutoStart };
    std::wstring loadOrderGroup;
    std::vector<std::wstring> dependencies;
    std::wstring serviceAccount;      // Empty = LocalSystem
    std::wstring password;
    
    // Failure recovery
    bool configureRecovery{ false };
    FailureAction firstFailure{ FailureAction::Restart };
    FailureAction secondFailure{ FailureAction::Restart };
    FailureAction subsequentFailures{ FailureAction::None };
    uint32_t resetPeriodSeconds{ 86400 };
    uint32_t restartDelayMs{ 60000 };
};

/**
 * @struct MinifilterInfo
 * @brief Information about a minifilter driver.
 */
struct alignas(64) MinifilterInfo {
    std::wstring filterName;
    uint32_t numberOfInstances{ 0 };
    uint32_t altitude{ 0 };              // Parsed numeric altitude value
    uint32_t frameID{ 0 };               // Filter manager frame ID
    bool isLoaded{ false };
    std::vector<std::wstring> volumes;
};

/**
 * @struct DriverLoadRequest
 * @brief Request to load a kernel driver.
 */
struct DriverLoadRequest {
    std::wstring driverName;
    std::wstring driverPath;
    std::wstring displayName;
    bool isMinifilter{ false };
    uint32_t altitude{ 0 };           // For minifilters
    StartType startType{ StartType::DemandStart };
};

/**
 * @struct ServiceChangeEvent
 * @brief Event for service state change.
 */
struct alignas(64) ServiceChangeEvent {
    std::wstring serviceName;
    ServiceState previousState{ ServiceState::Unknown };
    ServiceState newState{ ServiceState::Unknown };
    std::chrono::system_clock::time_point timestamp;
    bool wasExpected{ true };
};

/**
 * @struct TamperDetectionResult
 * @brief Result of tamper detection check.
 */
struct alignas(64) TamperDetectionResult {
    bool isTampered{ false };
    bool binaryModified{ false };
    bool configModified{ false };
    bool startTypeChanged{ false };
    bool accountChanged{ false };
    std::wstring expectedBinaryPath;
    std::wstring actualBinaryPath;
    std::wstring details;
};

/**
 * @struct ServiceManagerConfig
 * @brief Configuration for service manager.
 */
struct alignas(32) ServiceManagerConfig {
    bool enableSelfProtection{ true };
    bool monitorServiceChanges{ true };
    bool autoRestartOnFailure{ true };
    bool validateSignatures{ true };
    uint32_t watchdogIntervalMs{ 5000 };
    
    // Our service names
    std::wstring mainServiceName{ L"ShadowStrikeAV" };
    std::wstring driverServiceName{ L"ShadowStrikeDriver" };
    
    static ServiceManagerConfig CreateDefault() noexcept;
    static ServiceManagerConfig CreateHighSecurity() noexcept;
};

/**
 * @struct ServiceManagerStatistics
 * @brief Runtime statistics.
 */
struct alignas(128) ServiceManagerStatistics {
    std::atomic<uint64_t> servicesEnumerated{ 0 };
    std::atomic<uint64_t> servicesStarted{ 0 };
    std::atomic<uint64_t> servicesStopped{ 0 };
    std::atomic<uint64_t> driversLoaded{ 0 };
    std::atomic<uint64_t> driversUnloaded{ 0 };
    std::atomic<uint64_t> remediationActions{ 0 };
    std::atomic<uint64_t> tamperAttempts{ 0 };
    std::atomic<uint64_t> selfRecoveries{ 0 };
    
    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using ServiceChangeCallback = std::function<void(const ServiceChangeEvent& event)>;
using TamperAlertCallback = std::function<void(const TamperDetectionResult& result)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class ServiceManager
 * @brief Enterprise-grade Windows service lifecycle manager.
 *
 * Thread-safe singleton providing comprehensive service management
 * with self-protection and threat remediation capabilities.
 */
class ServiceManager {
public:
    /**
     * @brief Gets singleton instance.
     */
    static ServiceManager& Instance();
    
    /**
     * @brief Initializes service manager.
     */
    bool Initialize(const ServiceManagerConfig& config);
    
    /**
     * @brief Shuts down service manager.
     */
    void Shutdown() noexcept;
    
    // ========================================================================
    // SERVICE ENUMERATION
    // ========================================================================
    
    /**
     * @brief Enumerates all services on the system.
     */
    [[nodiscard]] std::vector<ServiceInfo> EnumerateServices() const;
    
    /**
     * @brief Enumerates kernel drivers only.
     */
    [[nodiscard]] std::vector<ServiceInfo> EnumerateDrivers() const;
    
    /**
     * @brief Gets detailed info for a specific service.
     */
    [[nodiscard]] std::optional<ServiceInfo> GetServiceInfo(
        const std::wstring& serviceName) const;
    
    /**
     * @brief Checks if a service exists.
     */
    [[nodiscard]] bool ServiceExists(const std::wstring& serviceName) const;
    
    /**
     * @brief Gets current state of a service.
     */
    [[nodiscard]] ServiceState GetServiceState(
        const std::wstring& serviceName) const;
    
    // ========================================================================
    // SERVICE LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Installs a new service.
     */
    [[nodiscard]] bool InstallService(const ServiceConfig& config);
    
    /**
     * @brief Uninstalls a service.
     */
    [[nodiscard]] bool UninstallService(
        const std::wstring& serviceName,
        bool force = false);
    
    /**
     * @brief Starts a service.
     */
    [[nodiscard]] bool StartService(
        const std::wstring& serviceName,
        const std::vector<std::wstring>& args = {},
        uint32_t timeoutMs = ServiceManagerConstants::DEFAULT_TIMEOUT_MS);
    
    /**
     * @brief Stops a service.
     */
    [[nodiscard]] bool StopService(
        const std::wstring& serviceName,
        bool stopDependents = true,
        uint32_t timeoutMs = ServiceManagerConstants::DEFAULT_TIMEOUT_MS);
    
    /**
     * @brief Restarts a service.
     */
    [[nodiscard]] bool RestartService(
        const std::wstring& serviceName,
        uint32_t timeoutMs = ServiceManagerConstants::DEFAULT_TIMEOUT_MS);
    
    /**
     * @brief Pauses a service.
     */
    [[nodiscard]] bool PauseService(const std::wstring& serviceName);
    
    /**
     * @brief Continues a paused service.
     */
    [[nodiscard]] bool ContinueService(const std::wstring& serviceName);
    
    /**
     * @brief Modifies service start type.
     */
    [[nodiscard]] bool SetStartType(
        const std::wstring& serviceName,
        StartType startType);
    
    /**
     * @brief Configures failure recovery actions.
     */
    [[nodiscard]] bool ConfigureRecovery(
        const std::wstring& serviceName,
        FailureAction firstFailure,
        FailureAction secondFailure,
        FailureAction subsequentFailures,
        uint32_t resetPeriodSeconds = 86400,
        uint32_t restartDelayMs = 60000);
    
    // ========================================================================
    // DRIVER MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Loads a kernel driver.
     */
    [[nodiscard]] bool LoadDriver(const DriverLoadRequest& request);
    
    /**
     * @brief Unloads a kernel driver.
     */
    [[nodiscard]] bool UnloadDriver(
        const std::wstring& driverName,
        bool force = false);
    
    /**
     * @brief Loads a minifilter driver.
     * @param filterName Name of the minifilter to load.
     * @param driverPath Full path to the minifilter driver file (.sys).
     * @param altitude Minifilter altitude (determines load order).
     */
    [[nodiscard]] bool LoadMinifilter(
        const std::wstring& filterName,
        const std::wstring& driverPath,
        uint32_t altitude = ServiceManagerConstants::ALTITUDE_AV_FILTER);
    
    /**
     * @brief Unloads a minifilter driver.
     */
    [[nodiscard]] bool UnloadMinifilter(const std::wstring& filterName);
    
    /**
     * @brief Gets info about loaded minifilters.
     */
    [[nodiscard]] std::vector<MinifilterInfo> GetLoadedMinifilters() const;
    
    /**
     * @brief Checks if our minifilter is loaded.
     */
    [[nodiscard]] bool IsMinifilterLoaded(const std::wstring& filterName) const;
    
    // ========================================================================
    // SELF-PROTECTION
    // ========================================================================
    
    /**
     * @brief Verifies our service hasn't been tampered with.
     */
    [[nodiscard]] TamperDetectionResult VerifyServiceIntegrity(
        const std::wstring& serviceName) const;
    
    /**
     * @brief Protects a service configuration from modification.
     */
    [[nodiscard]] bool ProtectService(const std::wstring& serviceName);
    
    /**
     * @brief Starts the self-protection watchdog.
     */
    void StartWatchdog();
    
    /**
     * @brief Stops the self-protection watchdog.
     */
    void StopWatchdog();
    
    /**
     * @brief Checks if watchdog is running.
     */
    [[nodiscard]] bool IsWatchdogRunning() const noexcept;
    
    // ========================================================================
    // THREAT REMEDIATION
    // ========================================================================
    
    /**
     * @brief Disables a malicious service.
     */
    [[nodiscard]] bool DisableMaliciousService(
        const std::wstring& serviceName,
        bool quarantineBinary = true);
    
    /**
     * @brief Removes a malicious driver from the system.
     */
    [[nodiscard]] bool RemoveMaliciousDriver(
        const std::wstring& driverName,
        bool rebootRequired = false);
    
    /**
     * @brief Cleans orphaned service registry entries.
     */
    [[nodiscard]] uint32_t CleanOrphanedServices();
    
    /**
     * @brief Gets services with suspicious characteristics.
     */
    [[nodiscard]] std::vector<ServiceInfo> GetSuspiciousServices() const;
    
    // ========================================================================
    // CALLBACKS AND EVENTS
    // ========================================================================
    
    /**
     * @brief Registers callback for service state changes.
     */
    uint64_t RegisterServiceChangeCallback(ServiceChangeCallback callback);
    
    /**
     * @brief Unregisters service change callback.
     */
    void UnregisterServiceChangeCallback(uint64_t callbackId);
    
    /**
     * @brief Registers callback for tamper alerts.
     */
    uint64_t RegisterTamperAlertCallback(TamperAlertCallback callback);
    
    /**
     * @brief Unregisters tamper alert callback.
     */
    void UnregisterTamperAlertCallback(uint64_t callbackId);
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] const ServiceManagerStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

private:
    ServiceManager();
    ~ServiceManager();
    
    ServiceManager(const ServiceManager&) = delete;
    ServiceManager& operator=(const ServiceManager&) = delete;
    
    std::unique_ptr<ServiceManagerImpl> m_impl;
};

}  // namespace System
}  // namespace Core
}  // namespace ShadowStrike