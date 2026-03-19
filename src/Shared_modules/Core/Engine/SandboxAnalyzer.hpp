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
 * ShadowStrike NGAV - SANDBOX ANALYZER MODULE
 * ============================================================================
 *
 * @file SandboxAnalyzer.hpp
 * @brief Enterprise-grade isolated sandbox analysis environment for dynamic
 *        malware detonation, behavioral monitoring, and artifact extraction.
 *
 * Provides full system-level sandbox analysis using isolated VM/container
 * environments to safely detonate and analyze malicious samples.
 *
 * SANDBOX ANALYSIS CAPABILITIES:
 * ==============================
 *
 * 1. ENVIRONMENT MANAGEMENT
 *    - Hyper-V integration
 *    - VMware support
 *    - Container isolation (Docker/WC)
 *    - Snapshot management
 *    - Resource allocation
 *
 * 2. EXECUTION MONITORING
 *    - Process creation tracking
 *    - File system monitoring
 *    - Registry monitoring
 *    - Network capture
 *    - API call logging
 *
 * 3. BEHAVIORAL ANALYSIS
 *    - Persistence mechanisms
 *    - Evasion attempts
 *    - C2 communication
 *    - Data exfiltration
 *    - Anti-analysis detection
 *
 * 4. ARTIFACT EXTRACTION
 *    - Dropped files
 *    - Memory dumps
 *    - Network captures
 *    - Registry exports
 *    - Decrypted payloads
 *
 * 5. REPORTING
 *    - Threat scoring
 *    - IOC extraction
 *    - MITRE ATT&CK mapping
 *    - Detailed timelines
 *
 * @note Thread-safe singleton design.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <map>
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <filesystem>
#include <span>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../../Utils/Logger.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/NetworkUtils.hpp"
#include "../../ThreatIntel/ThreatIntelLookup.hpp"
#include "../../PatternStore/PatternStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Core::Engine {
    class SandboxAnalyzerImpl;
}

namespace ShadowStrike {
namespace Core {
namespace Engine {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace SandboxConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Default analysis timeout (seconds)
    inline constexpr uint32_t DEFAULT_TIMEOUT_SECONDS = 120;
    
    /// @brief Maximum analysis timeout
    inline constexpr uint32_t MAX_TIMEOUT_SECONDS = 600;
    
    /// @brief Maximum concurrent analyses
    inline constexpr uint32_t MAX_CONCURRENT_ANALYSES = 4;
    
    /// @brief Maximum dropped files to extract
    inline constexpr size_t MAX_DROPPED_FILES = 1000;
    
    /// @brief Maximum memory dump size (1 GB)
    inline constexpr size_t MAX_MEMORY_DUMP_SIZE = 1024 * 1024 * 1024;
    
    /// @brief Maximum PCAP size (256 MB)
    inline constexpr size_t MAX_PCAP_SIZE = 256 * 1024 * 1024;

}  // namespace SandboxConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
namespace fs = std::filesystem;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Sandbox environment type
 */
enum class SandboxEnvironment : uint8_t {
    HyperV          = 0,
    VMware          = 1,
    VirtualBox      = 2,
    Docker          = 3,
    WindowsContainer= 4,
    QEMU            = 5,
    Custom          = 6
};

/**
 * @brief Guest OS type
 */
enum class GuestOSType : uint8_t {
    Windows10_x64   = 0,
    Windows11_x64   = 1,
    Windows7_x64    = 2,
    Windows7_x86    = 3,
    WindowsServer2019 = 4,
    WindowsServer2022 = 5,
    Linux_Ubuntu    = 6,
    Linux_CentOS    = 7,
    MacOS           = 8,
    Android         = 9,
    Custom          = 10
};

/**
 * @brief Analysis status
 */
enum class AnalysisStatus : uint8_t {
    Pending         = 0,
    Preparing       = 1,
    Running         = 2,
    Completed       = 3,
    Timeout         = 4,
    Failed          = 5,
    Cancelled       = 6
};

/**
 * @brief Threat score level
 */
enum class ThreatScoreLevel : uint8_t {
    Clean           = 0,    ///< 0-20
    Suspicious      = 1,    ///< 21-40
    LikelyMalicious = 2,    ///< 41-60
    Malicious       = 3,    ///< 61-80
    HighlyMalicious = 4     ///< 81-100
};

/**
 * @brief Behavior category
 */
enum class BehaviorCategory : uint8_t {
    FileSystem      = 0,
    Registry        = 1,
    Process         = 2,
    Network         = 3,
    Memory          = 4,
    Persistence     = 5,
    Evasion         = 6,
    Discovery       = 7,
    Collection      = 8,
    Exfiltration    = 9,
    Impact          = 10,
    Defense_Evasion = 11,
    Credential_Access = 12,
    Lateral_Movement = 13
};

/**
 * @brief Analyzer status
 */
enum class SandboxStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Analyzing       = 3,
    Paused          = 4,
    Error           = 5,
    Stopping        = 6,
    Stopped         = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief VM configuration
 */
struct VMConfiguration {
    /// @brief Environment type
    SandboxEnvironment environment = SandboxEnvironment::HyperV;
    
    /// @brief Guest OS type
    GuestOSType guestOS = GuestOSType::Windows10_x64;
    
    /// @brief VM name/ID
    std::string vmName;
    
    /// @brief Snapshot name
    std::string snapshotName;
    
    /// @brief Memory (MB)
    uint32_t memoryMb = 4096;
    
    /// @brief CPU cores
    uint32_t cpuCores = 2;
    
    /// @brief Network isolation
    bool networkIsolation = true;
    
    /// @brief Allow internet access (isolated by default)
    bool allowInternet = false;
    
    /// @brief Simulated internet
    bool simulatedInternet = true;
    
    [[nodiscard]] bool IsValid() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Process event
 */
struct ProcessEvent {
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief Event type
    std::string eventType;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Parent process ID
    uint32_t parentProcessId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Command line
    std::wstring commandLine;
    
    /// @brief Image path
    fs::path imagePath;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief File event
 */
struct FileEvent {
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief Event type (create/modify/delete)
    std::string eventType;
    
    /// @brief File path
    fs::path filePath;
    
    /// @brief File size
    uint64_t fileSize = 0;
    
    /// @brief File hash (SHA-256)
    std::string sha256Hash;
    
    /// @brief Process that performed operation
    std::wstring processName;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Registry event
 */
struct RegistryEvent {
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief Event type (create/modify/delete)
    std::string eventType;
    
    /// @brief Key path
    std::wstring keyPath;
    
    /// @brief Value name
    std::wstring valueName;
    
    /// @brief Value data
    std::string valueData;
    
    /// @brief Process that performed operation
    std::wstring processName;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Network event
 */
struct NetworkEvent {
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief Protocol (TCP/UDP/HTTP/DNS)
    std::string protocol;
    
    /// @brief Source IP
    std::string sourceIP;
    
    /// @brief Source port
    uint16_t sourcePort = 0;
    
    /// @brief Destination IP
    std::string destinationIP;
    
    /// @brief Destination port
    uint16_t destinationPort = 0;
    
    /// @brief Hostname (for DNS/HTTP)
    std::string hostname;
    
    /// @brief URL (for HTTP)
    std::string url;
    
    /// @brief Data sent (bytes)
    uint64_t bytesSent = 0;
    
    /// @brief Data received (bytes)
    uint64_t bytesReceived = 0;
    
    /// @brief Process that performed operation
    std::wstring processName;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Behavioral indicator
 */
struct BehavioralIndicator {
    /// @brief Indicator ID
    std::string indicatorId;
    
    /// @brief Description
    std::string description;
    
    /// @brief Category
    BehaviorCategory category = BehaviorCategory::FileSystem;
    
    /// @brief Severity (1-10)
    uint32_t severity = 1;
    
    /// @brief MITRE ATT&CK technique ID
    std::string mitreId;
    
    /// @brief MITRE ATT&CK technique name
    std::string mitreName;
    
    /// @brief Evidence
    std::vector<std::string> evidence;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Extracted artifact
 */
struct ExtractedArtifact {
    /// @brief Artifact type
    std::string artifactType;
    
    /// @brief Original path
    fs::path originalPath;
    
    /// @brief Extracted path
    fs::path extractedPath;
    
    /// @brief Size
    uint64_t size = 0;
    
    /// @brief SHA-256 hash
    std::string sha256Hash;
    
    /// @brief File type
    std::string fileType;
    
    /// @brief Is malicious
    bool isMalicious = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief IOC (Indicator of Compromise)
 */
struct ExtractedIOC {
    /// @brief IOC type (hash/ip/domain/url)
    std::string iocType;
    
    /// @brief IOC value
    std::string value;
    
    /// @brief Context
    std::string context;
    
    /// @brief Confidence
    float confidence = 0.0f;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Sandbox analysis verdict
 */
struct SandboxVerdict {
    /// @brief Is malicious
    bool isMalicious = false;
    
    /// @brief Threat score (0-100)
    int threatScore = 0;
    
    /// @brief Threat score level
    ThreatScoreLevel scoreLevel = ThreatScoreLevel::Clean;
    
    /// @brief Malware family (if identified)
    std::string malwareFamily;
    
    /// @brief Malware type
    std::string malwareType;
    
    /// @brief Behavior summary
    std::vector<std::string> behaviorSummary;
    
    /// @brief Behavioral indicators
    std::vector<BehavioralIndicator> indicators;
    
    /// @brief Process events
    std::vector<ProcessEvent> processEvents;
    
    /// @brief File events
    std::vector<FileEvent> fileEvents;
    
    /// @brief Registry events
    std::vector<RegistryEvent> registryEvents;
    
    /// @brief Network events
    std::vector<NetworkEvent> networkEvents;
    
    /// @brief Extracted artifacts
    std::vector<ExtractedArtifact> artifacts;
    
    /// @brief Extracted IOCs
    std::vector<ExtractedIOC> iocs;
    
    /// @brief MITRE ATT&CK techniques
    std::set<std::string> mitreIds;
    
    /// @brief Analysis status
    AnalysisStatus status = AnalysisStatus::Pending;
    
    /// @brief Analysis duration (seconds)
    uint32_t durationSeconds = 0;
    
    /// @brief VM used
    std::string vmUsed;
    
    /// @brief Errors/warnings
    std::vector<std::string> warnings;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Analysis options
 */
struct SandboxAnalysisOptions {
    /// @brief Analysis timeout (seconds)
    uint32_t timeoutSeconds = SandboxConstants::DEFAULT_TIMEOUT_SECONDS;
    
    /// @brief Preferred VM
    std::string preferredVM;
    
    /// @brief Preferred OS
    GuestOSType preferredOS = GuestOSType::Windows10_x64;
    
    /// @brief Command line arguments
    std::wstring arguments;
    
    /// @brief Working directory
    fs::path workingDirectory;
    
    /// @brief Enable network monitoring
    bool monitorNetwork = true;
    
    /// @brief Enable process monitoring
    bool monitorProcesses = true;
    
    /// @brief Enable file monitoring
    bool monitorFiles = true;
    
    /// @brief Enable registry monitoring
    bool monitorRegistry = true;
    
    /// @brief Extract dropped files
    bool extractDroppedFiles = true;
    
    /// @brief Create memory dump
    bool createMemoryDump = false;
    
    /// @brief Create network capture
    bool createNetworkCapture = true;
    
    /// @brief Inject DLL (for instrumentation)
    fs::path instrumentationDll;
    
    /// @brief Priority (higher = more urgent)
    uint32_t priority = 0;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Statistics
 */
struct SandboxStatistics {
    std::atomic<uint64_t> totalAnalyses{0};
    std::atomic<uint64_t> maliciousDetected{0};
    std::atomic<uint64_t> cleanSamples{0};
    std::atomic<uint64_t> timeouts{0};
    std::atomic<uint64_t> failures{0};
    std::atomic<uint64_t> processEventsLogged{0};
    std::atomic<uint64_t> fileEventsLogged{0};
    std::atomic<uint64_t> networkEventsLogged{0};
    std::atomic<uint64_t> artifactsExtracted{0};
    std::atomic<uint64_t> iocsExtracted{0};
    std::atomic<uint64_t> totalAnalysisTimeSeconds{0};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct SandboxAnalyzerConfiguration {
    /// @brief Enable sandbox analysis
    bool enabled = true;
    
    /// @brief VM configurations
    std::vector<VMConfiguration> vms;
    
    /// @brief Maximum concurrent analyses
    uint32_t maxConcurrentAnalyses = SandboxConstants::MAX_CONCURRENT_ANALYSES;
    
    /// @brief Default timeout (seconds)
    uint32_t defaultTimeoutSeconds = SandboxConstants::DEFAULT_TIMEOUT_SECONDS;
    
    /// @brief Artifact storage path
    fs::path artifactStoragePath;
    
    /// @brief Report storage path
    fs::path reportStoragePath;
    
    /// @brief Agent port (for communication with sandbox)
    uint16_t agentPort = 8443;
    
    /// @brief Cleanup after analysis
    bool cleanupAfterAnalysis = true;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using AnalysisProgressCallback = std::function<void(const std::string& taskId, uint32_t progress, const std::string& status)>;
using AnalysisCompleteCallback = std::function<void(const std::string& taskId, const SandboxVerdict& verdict)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// SANDBOX ANALYZER CLASS
// ============================================================================

/**
 * @class SandboxAnalyzer
 * @brief Enterprise sandbox analysis
 */
class SandboxAnalyzer final {
public:
    [[nodiscard]] static SandboxAnalyzer& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    SandboxAnalyzer(const SandboxAnalyzer&) = delete;
    SandboxAnalyzer& operator=(const SandboxAnalyzer&) = delete;
    SandboxAnalyzer(SandboxAnalyzer&&) = delete;
    SandboxAnalyzer& operator=(SandboxAnalyzer&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const SandboxAnalyzerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] SandboxStatus GetStatus() const noexcept;

    // ========================================================================
    // ANALYSIS
    // ========================================================================
    
    /// @brief Analyze file (synchronous)
    [[nodiscard]] SandboxVerdict Analyze(const std::wstring& filePath, uint32_t timeoutSeconds = SandboxConstants::DEFAULT_TIMEOUT_SECONDS);
    
    /// @brief Analyze file with options
    [[nodiscard]] SandboxVerdict Analyze(const fs::path& filePath, const SandboxAnalysisOptions& options = {});
    
    /// @brief Submit file for analysis (async)
    [[nodiscard]] std::string SubmitForAnalysis(const fs::path& filePath, const SandboxAnalysisOptions& options = {});
    
    /// @brief Get analysis result
    [[nodiscard]] std::optional<SandboxVerdict> GetAnalysisResult(const std::string& taskId) const;
    
    /// @brief Cancel analysis
    [[nodiscard]] bool CancelAnalysis(const std::string& taskId);
    
    /// @brief Get pending analyses
    [[nodiscard]] std::vector<std::string> GetPendingAnalyses() const;

    // ========================================================================
    // VM MANAGEMENT
    // ========================================================================
    
    /// @brief Get available VMs
    [[nodiscard]] std::vector<VMConfiguration> GetAvailableVMs() const;
    
    /// @brief Get VM status
    [[nodiscard]] std::string GetVMStatus(const std::string& vmName) const;
    
    /// @brief Revert VM to snapshot
    [[nodiscard]] bool RevertToSnapshot(const std::string& vmName, const std::string& snapshotName);
    
    /// @brief Start VM
    [[nodiscard]] bool StartVM(const std::string& vmName);
    
    /// @brief Stop VM
    [[nodiscard]] bool StopVM(const std::string& vmName);

    // ========================================================================
    // ARTIFACT MANAGEMENT
    // ========================================================================
    
    /// @brief Get extracted artifacts for task
    [[nodiscard]] std::vector<ExtractedArtifact> GetArtifacts(const std::string& taskId) const;
    
    /// @brief Download artifact
    [[nodiscard]] bool DownloadArtifact(const std::string& taskId, const std::string& artifactId, const fs::path& destination);
    
    /// @brief Get memory dump
    [[nodiscard]] std::optional<fs::path> GetMemoryDump(const std::string& taskId) const;
    
    /// @brief Get network capture
    [[nodiscard]] std::optional<fs::path> GetNetworkCapture(const std::string& taskId) const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterProgressCallback(AnalysisProgressCallback callback);
    void RegisterCompleteCallback(AnalysisCompleteCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] SandboxStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    SandboxAnalyzer();
    ~SandboxAnalyzer();
    
    std::unique_ptr<SandboxAnalyzerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetSandboxEnvironmentName(SandboxEnvironment env) noexcept;
[[nodiscard]] std::string_view GetGuestOSTypeName(GuestOSType os) noexcept;
[[nodiscard]] std::string_view GetAnalysisStatusName(AnalysisStatus status) noexcept;
[[nodiscard]] std::string_view GetThreatScoreLevelName(ThreatScoreLevel level) noexcept;
[[nodiscard]] std::string_view GetBehaviorCategoryName(BehaviorCategory category) noexcept;

/// @brief Calculate threat score level from numeric score
[[nodiscard]] ThreatScoreLevel CalculateThreatLevel(int score);

/// @brief Check if Hyper-V is available
[[nodiscard]] bool IsHyperVAvailable();

}  // namespace Engine
}  // namespace Core
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_SANDBOX_ANALYZE(path) \
    ::ShadowStrike::Core::Engine::SandboxAnalyzer::Instance().Analyze(path)

#define SS_SANDBOX_IS_MALICIOUS(path) \
    ::ShadowStrike::Core::Engine::SandboxAnalyzer::Instance().Analyze(path).isMalicious
