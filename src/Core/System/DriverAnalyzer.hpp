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
 * ============================================================================
 * ShadowStrike Core System - DRIVER ANALYZER (The Kernel Inspector)
 * ============================================================================
 *
 * @file DriverAnalyzer.hpp
 * @brief Enterprise-grade kernel driver security analysis engine.
 *
 * This module provides comprehensive analysis of kernel drivers including
 * enumeration, signature verification, rootkit detection, and IOCTL monitoring.
 *
 * Key Capabilities:
 * =================
 * 1. DRIVER ENUMERATION
 *    - Loaded driver listing
 *    - Hidden driver detection
 *    - Module base address verification
 *    - Load order analysis
 *
 * 2. SIGNATURE VERIFICATION
 *    - Authenticode validation
 *    - WHQL certification check
 *    - Catalog file verification
 *    - Code integrity status
 *
 * 3. ROOTKIT DETECTION
 *    - DKOM (Direct Kernel Object Manipulation)
 *    - SSDT hooking detection
 *    - IDT modification detection
 *    - Driver object hiding
 *
 * 4. THREAT ASSESSMENT
 *    - Vulnerable driver detection (LOLDrivers)
 *    - Known malicious driver patterns
 *    - Suspicious callback registration
 *    - IOCTL handler analysis
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1014: Rootkit
 * - T1068: Exploitation for Privilege Escalation
 * - T1543.003: Windows Service (Driver installation)
 * - T1547.006: Kernel Modules and Extensions
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see ServiceManager.hpp for driver loading
 * @see HashStore.hpp for known driver hashes
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/SystemUtils.hpp"        // OS info, CPU features
#include "../../Utils/FileUtils.hpp"          // File operations
#include "../../Utils/ProcessUtils.hpp"       // Process/module enumeration
#include "../../Utils/CertUtils.hpp"          // Signature verification
#include "../../Utils/HashUtils.hpp"          // Hash computation
#include "../../HashStore/HashStore.hpp"      // Known driver hash lookup
#include "../../ThreatIntel/ThreatIntelLookup.hpp"  // Threat intelligence
#include "../../Whitelist/WhiteListStore.hpp" // Trusted driver whitelist

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
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
class DriverAnalyzerImpl;

// Infrastructure forward declarations for dependency injection
namespace SignatureStore { class HashStore; }
namespace ThreatIntel { class ThreatIntelLookup; }
namespace Whitelist { class WhitelistStore; }

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum DriverType
 * @brief Type of kernel driver.
 */
enum class DriverType : uint8_t {
    Unknown = 0,
    KernelDriver = 1,              // Standard kernel driver
    FileSystemDriver = 2,          // File system driver
    MinifilterDriver = 3,          // Minifilter driver
    NetworkDriver = 4,             // Network miniport/protocol
    USBDriver = 5,                 // USB driver
    DisplayDriver = 6,             // Display driver
    PrintDriver = 7,               // Print driver
    BootDriver = 8                 // Boot-start driver
};

/**
 * @enum DriverSignatureStatus
 * @brief Driver signature verification status.
 */
enum class DriverSignatureStatus : uint8_t {
    Unknown = 0,
    Unsigned = 1,
    SignedValid = 2,
    SignedExpired = 3,
    SignedRevoked = 4,
    SignedUntrusted = 5,
    WHQLCertified = 6,
    MicrosoftSigned = 7,
    TestSigned = 8
};

/**
 * @enum DriverThreatLevel
 * @brief Threat level assessment.
 */
enum class DriverThreatLevel : uint8_t {
    Safe = 0,
    Unknown = 1,
    Suspicious = 2,
    VulnerableDriver = 3,          // Known vulnerable (BYOVD)
    Malicious = 4,
    Rootkit = 5
};

/**
 * @enum RootkitTechnique
 * @brief Detected rootkit technique.
 */
enum class RootkitTechnique : uint8_t {
    None = 0,
    DKOMProcessHiding = 1,         // EPROCESS unlinking
    DKOMDriverHiding = 2,          // Module list manipulation
    SSDTHooking = 3,               // SSDT modification
    IDTHooking = 4,                // IDT modification
    IATHooking = 5,                // Import table hooking
    InlineHooking = 6,             // Function patching
    FilterDriverHooking = 7,       // File system filter attack
    CallbackManipulation = 8       // Notify callback tampering
};

/**
 * @enum VulnerableDriverCategory
 * @brief Category of known vulnerable driver.
 */
enum class VulnerableDriverCategory : uint8_t {
    None = 0,
    ArbitraryRead = 1,             // Kernel memory read
    ArbitraryWrite = 2,            // Kernel memory write
    CodeExecution = 3,             // Arbitrary code execution
    PrivilegeEscalation = 4,       // Token manipulation
    RegistryAccess = 5,            // Registry manipulation
    ProcessAccess = 6              // Process manipulation
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct DriverInfo
 * @brief Comprehensive driver information.
 */
struct alignas(256) DriverInfo {
    // Identity
    std::wstring driverName;
    std::wstring driverPath;
    std::wstring serviceName;
    std::wstring description;
    DriverType driverType{ DriverType::Unknown };
    
    // Memory
    uint64_t baseAddress{ 0 };
    uint64_t imageSize{ 0 };
    uint64_t entryPoint{ 0 };
    
    // Version
    std::wstring fileVersion;
    std::wstring productVersion;
    std::wstring companyName;
    std::wstring productName;
    
    // Signature
    DriverSignatureStatus signatureStatus{ DriverSignatureStatus::Unknown };
    std::wstring signerName;
    std::wstring signerThumbprint;
    std::chrono::system_clock::time_point signatureTimestamp;
    bool isWHQL{ false };
    bool isMicrosoftSigned{ false };
    
    // Hashes
    std::string sha256Hash;
    std::string sha1Hash;
    std::string md5Hash;
    
    // Security assessment
    DriverThreatLevel threatLevel{ DriverThreatLevel::Unknown };
    bool isKnownVulnerable{ false };
    std::vector<VulnerableDriverCategory> vulnerabilities;
    std::vector<std::wstring> cveIds;
    
    // Runtime
    bool isLoaded{ false };
    std::chrono::system_clock::time_point loadTime;
    uint32_t loadOrder{ 0 };
    
    // Flags
    bool isBootStart{ false };
    bool isSystemStart{ false };
    bool isHidden{ false };
    bool hasCallbacksRegistered{ false };
};

/**
 * @struct RootkitIndicator
 * @brief Detected rootkit indicator.
 */
struct alignas(64) RootkitIndicator {
    RootkitTechnique technique{ RootkitTechnique::None };
    std::wstring description;
    std::wstring targetDriver;
    uint64_t targetAddress{ 0 };
    std::vector<uint8_t> originalBytes;
    std::vector<uint8_t> modifiedBytes;
    uint8_t severity{ 0 };
    double confidence{ 0.0 };
};

/**
 * @struct DriverCallbackInfo
 * @brief Information about registered driver callbacks.
 */
struct alignas(64) DriverCallbackInfo {
    std::wstring callbackType;        // e.g., "ProcessNotify", "ImageLoad"
    std::wstring driverName;
    uint64_t callbackAddress{ 0 };
    bool isSuspicious{ false };
    std::wstring reason;
};

/**
 * @struct IOCTLInfo
 * @brief IOCTL handler information.
 */
struct alignas(32) IOCTLInfo {
    uint32_t ioctlCode{ 0 };
    uint64_t handlerAddress{ 0 };
    std::wstring description;
    bool isKnownDangerous{ false };
};

/**
 * @struct DriverScanResult
 * @brief Complete driver scan result.
 */
struct alignas(256) DriverScanResult {
    // Summary
    uint32_t totalDrivers{ 0 };
    uint32_t unsignedDrivers{ 0 };
    uint32_t hiddenDrivers{ 0 };
    uint32_t suspiciousDrivers{ 0 };
    uint32_t vulnerableDrivers{ 0 };
    uint32_t maliciousDrivers{ 0 };
    
    // Details
    std::vector<DriverInfo> drivers;
    std::vector<DriverInfo> hiddenDriversFound;
    std::vector<RootkitIndicator> rootkitIndicators;
    std::vector<DriverCallbackInfo> suspiciousCallbacks;
    
    // Integrity
    bool ssdtIntact{ true };
    bool idtIntact{ true };
    bool moduleListIntact{ true };
    
    std::chrono::milliseconds scanDuration{ 0 };
};

/**
 * @struct VulnerableDriverEntry
 * @brief Known vulnerable driver database entry.
 */
struct VulnerableDriverEntry {
    std::string sha256Hash;
    std::wstring driverName;
    std::wstring vendor;
    std::vector<std::wstring> cveIds;
    VulnerableDriverCategory category{ VulnerableDriverCategory::None };
    std::wstring description;
    bool canBeExploited{ true };
};

/**
 * @struct DriverAnalyzerConfig
 * @brief Configuration for driver analyzer.
 */
struct alignas(32) DriverAnalyzerConfig {
    bool verifySignatures{ true };
    bool detectHiddenDrivers{ true };
    bool scanForRootkits{ true };
    bool checkVulnerableDrivers{ true };
    bool monitorCallbacks{ true };
    bool analyzeIOCTL{ false };        // Deep analysis, slower
    
    static DriverAnalyzerConfig CreateDefault() noexcept;
    static DriverAnalyzerConfig CreateDeep() noexcept;
    static DriverAnalyzerConfig CreateQuick() noexcept;
};

/**
 * @struct DriverAnalyzerStatistics
 * @brief Runtime statistics.
 */
struct alignas(128) DriverAnalyzerStatistics {
    std::atomic<uint64_t> driversAnalyzed{ 0 };
    std::atomic<uint64_t> signaturesVerified{ 0 };
    std::atomic<uint64_t> hiddenDriversFound{ 0 };
    std::atomic<uint64_t> rootkitIndicatorsFound{ 0 };
    std::atomic<uint64_t> vulnerableDriversFound{ 0 };
    std::atomic<uint64_t> maliciousDriversFound{ 0 };
    
    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using DriverLoadCallback = std::function<void(const DriverInfo& driver)>;
using RootkitAlertCallback = std::function<void(const RootkitIndicator& indicator)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class DriverAnalyzer
 * @brief Enterprise-grade kernel driver security analyzer.
 *
 * Thread-safe singleton providing comprehensive driver analysis
 * and rootkit detection capabilities.
 */
class DriverAnalyzer {
public:
    /**
     * @brief Gets singleton instance.
     */
    static DriverAnalyzer& Instance();
    
    /**
     * @brief Initializes driver analyzer.
     */
    bool Initialize(const DriverAnalyzerConfig& config);
    
    /**
     * @brief Shuts down driver analyzer.
     */
    void Shutdown() noexcept;
    
    // ========================================================================
    // DRIVER ENUMERATION
    // ========================================================================
    
    /**
     * @brief Enumerates all loaded drivers.
     */
    [[nodiscard]] std::vector<DriverInfo> EnumerateDrivers() const;
    
    /**
     * @brief Enumerates drivers including hidden ones.
     */
    [[nodiscard]] std::vector<DriverInfo> EnumerateDriversDeep() const;
    
    /**
     * @brief Gets info for a specific driver.
     */
    [[nodiscard]] std::optional<DriverInfo> GetDriverInfo(
        const std::wstring& driverName) const;
    
    /**
     * @brief Gets info by driver base address.
     */
    [[nodiscard]] std::optional<DriverInfo> GetDriverByAddress(
        uint64_t address) const;
    
    /**
     * @brief Checks if a driver is loaded.
     */
    [[nodiscard]] bool IsDriverLoaded(const std::wstring& driverName) const;
    
    // ========================================================================
    // SIGNATURE VERIFICATION
    // ========================================================================
    
    /**
     * @brief Verifies driver signature.
     */
    [[nodiscard]] DriverSignatureStatus VerifySignature(
        const std::wstring& driverPath) const;
    
    /**
     * @brief Gets all unsigned drivers.
     */
    [[nodiscard]] std::vector<DriverInfo> GetUnsignedDrivers() const;
    
    /**
     * @brief Gets all non-Microsoft signed drivers.
     */
    [[nodiscard]] std::vector<DriverInfo> GetThirdPartyDrivers() const;
    
    // ========================================================================
    // ROOTKIT DETECTION
    // ========================================================================
    
    /**
     * @brief Performs full rootkit scan.
     */
    [[nodiscard]] std::vector<RootkitIndicator> ScanForRootkits() const;
    
    /**
     * @brief Detects hidden drivers.
     */
    [[nodiscard]] std::vector<DriverInfo> DetectHiddenDrivers() const;
    
    /**
     * @brief Checks SSDT integrity.
     */
    [[nodiscard]] bool VerifySSDTIntegrity() const;
    
    /**
     * @brief Checks IDT integrity.
     */
    [[nodiscard]] bool VerifyIDTIntegrity() const;
    
    /**
     * @brief Gets suspicious kernel callbacks.
     */
    [[nodiscard]] std::vector<DriverCallbackInfo> GetSuspiciousCallbacks() const;
    
    // ========================================================================
    // THREAT ASSESSMENT
    // ========================================================================
    
    /**
     * @brief Analyzes driver for threats.
     */
    [[nodiscard]] DriverInfo AnalyzeDriver(const std::wstring& driverPath) const;
    
    /**
     * @brief Checks if driver is known vulnerable (BYOVD).
     */
    [[nodiscard]] bool IsVulnerableDriver(const std::wstring& sha256Hash) const;
    
    /**
     * @brief Gets vulnerable driver info.
     */
    [[nodiscard]] std::optional<VulnerableDriverEntry> GetVulnerableDriverInfo(
        const std::wstring& sha256Hash) const;
    
    /**
     * @brief Gets all vulnerable drivers currently loaded.
     */
    [[nodiscard]] std::vector<DriverInfo> GetLoadedVulnerableDrivers() const;
    
    /**
     * @brief Checks if driver is known malicious.
     */
    [[nodiscard]] bool IsMaliciousDriver(const std::wstring& sha256Hash) const;
    
    // ========================================================================
    // FULL SCAN
    // ========================================================================
    
    /**
     * @brief Performs comprehensive driver scan.
     */
    [[nodiscard]] DriverScanResult PerformFullScan() const;
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Registers callback for driver load events.
     */
    uint64_t RegisterDriverLoadCallback(DriverLoadCallback callback);
    
    /**
     * @brief Unregisters driver load callback.
     */
    void UnregisterDriverLoadCallback(uint64_t callbackId);
    
    /**
     * @brief Registers callback for rootkit alerts.
     */
    uint64_t RegisterRootkitAlertCallback(RootkitAlertCallback callback);
    
    /**
     * @brief Unregisters rootkit alert callback.
     */
    void UnregisterRootkitAlertCallback(uint64_t callbackId);
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] const DriverAnalyzerStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

private:
    DriverAnalyzer();
    ~DriverAnalyzer();
    
    DriverAnalyzer(const DriverAnalyzer&) = delete;
    DriverAnalyzer& operator=(const DriverAnalyzer&) = delete;
    
    std::unique_ptr<DriverAnalyzerImpl> m_impl;
};

}  // namespace System
}  // namespace Core
}  // namespace ShadowStrike
