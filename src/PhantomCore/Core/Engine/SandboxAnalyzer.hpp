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
 *    - Hyper-V integration via PowerShell/WMI
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

namespace ShadowStrike {
namespace Core {
namespace Engine {

// ----------------------------------------------------------------------------
// Forward declarations to keep the public ABI / header dependency surface low.
// ----------------------------------------------------------------------------
} // namespace Engine
} // namespace Core
namespace ThreatIntel {
class ThreatIntelIndex;
}
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

    /// @brief Maximum events per category to prevent unbounded growth
    inline constexpr size_t MAX_EVENTS_PER_CATEGORY = 10000;

    /// @brief Maximum memory dump size (1 GB)
    inline constexpr size_t MAX_MEMORY_DUMP_SIZE = 1024ULL * 1024 * 1024;

    /// @brief Maximum PCAP size (256 MB)
    inline constexpr size_t MAX_PCAP_SIZE = 256ULL * 1024 * 1024;

    /// @brief PowerShell command timeout (ms) for VM operations
    inline constexpr DWORD PS_COMMAND_TIMEOUT_MS = 60000;

    /// @brief VM readiness polling interval (ms)
    inline constexpr uint32_t VM_READY_POLL_MS = 2000;

    /// @brief Maximum VM readiness wait (seconds)
    inline constexpr uint32_t VM_READY_MAX_WAIT_S = 120;

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
 * @brief Analysis pipeline status
 */
enum class AnalysisStatus : uint8_t {
    Queued          = 0,
    Preparing       = 1,
    Transferring    = 2,
    Executing       = 3,
    Monitoring      = 4,
    Capturing       = 5,
    Analyzing       = 6,
    Completed       = 7,
    Failed          = 8,
    Timeout         = 9,
    Cancelled       = 10
};

/**
 * @brief VM lifecycle state
 */
enum class VMState : uint8_t {
    Stopped         = 0,
    Starting        = 1,
    Running         = 2,
    Paused          = 3,
    Stopping        = 4,
    Error           = 5,
    Restoring       = 6
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
// ERROR TYPE
// ============================================================================

/**
 * @brief Structured error from sandbox operations
 */
struct SandboxError {
    DWORD code = ERROR_SUCCESS;
    std::wstring message;
    std::wstring context;

    [[nodiscard]] bool HasError() const noexcept { return code != ERROR_SUCCESS; }
    void Clear() noexcept { code = ERROR_SUCCESS; message.clear(); context.clear(); }
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief VM configuration
 */
struct VMConfiguration {
    SandboxEnvironment environment = SandboxEnvironment::HyperV;
    GuestOSType guestOS = GuestOSType::Windows10_x64;
    std::string vmName;
    std::string snapshotName;
    uint32_t memoryMb = 4096;
    uint32_t cpuCores = 2;
    bool networkIsolation = true;
    bool allowInternet = false;
    bool simulatedInternet = true;

    [[nodiscard]] bool IsValid() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Process event
 */
struct ProcessEvent {
    SystemTimePoint timestamp;
    std::string eventType;
    uint32_t processId = 0;
    uint32_t parentProcessId = 0;
    std::wstring processName;
    std::wstring commandLine;
    fs::path imagePath;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief File event
 */
struct FileEvent {
    SystemTimePoint timestamp;
    std::string eventType;
    fs::path filePath;
    uint64_t fileSize = 0;
    std::string sha256Hash;
    std::wstring processName;
    uint32_t processId = 0;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Registry event
 */
struct RegistryEvent {
    SystemTimePoint timestamp;
    std::string eventType;
    std::wstring keyPath;
    std::wstring valueName;
    std::string valueData;
    std::wstring processName;
    uint32_t processId = 0;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Network event
 */
struct NetworkEvent {
    SystemTimePoint timestamp;
    std::string protocol;
    std::string sourceIP;
    uint16_t sourcePort = 0;
    std::string destinationIP;
    uint16_t destinationPort = 0;
    std::string hostname;
    std::string url;
    uint64_t bytesSent = 0;
    uint64_t bytesReceived = 0;
    std::wstring processName;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Behavioral indicator
 */
struct BehavioralIndicator {
    std::string indicatorId;
    std::string description;
    BehaviorCategory category = BehaviorCategory::FileSystem;
    uint32_t severity = 1;  ///< 1-10 scale
    std::string mitreId;
    std::string mitreName;
    std::vector<std::string> evidence;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Extracted artifact
 */
struct ExtractedArtifact {
    std::string artifactType;
    fs::path originalPath;
    fs::path extractedPath;
    uint64_t size = 0;
    std::string sha256Hash;
    std::string fileType;
    bool isMalicious = false;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief IOC (Indicator of Compromise)
 */
struct ExtractedIOC {
    std::string iocType;
    std::string value;
    std::string context;
    float confidence = 0.0f;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Sandbox analysis verdict
 */
struct SandboxVerdict {
    bool isMalicious = false;
    int threatScore = 0;
    ThreatScoreLevel scoreLevel = ThreatScoreLevel::Clean;
    std::string malwareFamily;
    std::string malwareType;
    std::vector<std::string> behaviorSummary;
    std::vector<BehavioralIndicator> indicators;
    std::vector<ProcessEvent> processEvents;
    std::vector<FileEvent> fileEvents;
    std::vector<RegistryEvent> registryEvents;
    std::vector<NetworkEvent> networkEvents;
    std::vector<ExtractedArtifact> artifacts;
    std::vector<ExtractedIOC> iocs;
    std::set<std::string> mitreIds;
    AnalysisStatus status = AnalysisStatus::Queued;
    uint32_t durationSeconds = 0;
    std::string vmUsed;
    std::vector<std::string> warnings;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Analysis options
 */
struct SandboxAnalysisOptions {
    uint32_t timeoutSeconds = SandboxConstants::DEFAULT_TIMEOUT_SECONDS;
    std::string preferredVM;
    GuestOSType preferredOS = GuestOSType::Windows10_x64;
    std::wstring arguments;
    fs::path workingDirectory;
    bool monitorNetwork = true;
    bool monitorProcesses = true;
    bool monitorFiles = true;
    bool monitorRegistry = true;
    bool extractDroppedFiles = true;
    bool createMemoryDump = false;
    bool createNetworkCapture = true;
    fs::path instrumentationDll;
    uint32_t priority = 0;

    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Configuration
 */
struct SandboxAnalyzerConfiguration {
    bool enabled = true;
    std::vector<VMConfiguration> vms;
    uint32_t maxConcurrentAnalyses = SandboxConstants::MAX_CONCURRENT_ANALYSES;
    uint32_t defaultTimeoutSeconds = SandboxConstants::DEFAULT_TIMEOUT_SECONDS;
    fs::path artifactStoragePath;
    fs::path reportStoragePath;
    uint16_t agentPort = 8443;
    bool cleanupAfterAnalysis = true;

    /**
     * @brief Optional non-owning threat-intelligence index used to correlate
     *        observed IOCs (file hashes, domains, IPs) with known indicators.
     *
     * The pointee must outlive the SandboxAnalyzer instance. May be nullptr,
     * in which case correlation is silently skipped.
     */
    ThreatIntel::ThreatIntelIndex* threatIntel = nullptr;

    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using AnalysisProgressCallback = std::function<void(const std::string& taskId, uint32_t progress, const std::string& status)>;
using AnalysisCompleteCallback = std::function<void(const std::string& taskId, const SandboxVerdict& verdict)>;
#ifndef SHADOWSTRIKE_ENGINE_ERROR_CALLBACK_DEFINED
#define SHADOWSTRIKE_ENGINE_ERROR_CALLBACK_DEFINED
using ErrorCallback = std::function<void(const std::string& message, int code)>;
#endif

// ============================================================================
// SANDBOX ANALYZER CLASS
// ============================================================================

/**
 * @class SandboxAnalyzer
 * @brief Enterprise sandbox analysis engine (Meyers singleton, PIMPL)
 */
class SandboxAnalyzer final {
public:
    [[nodiscard]] static SandboxAnalyzer& Instance() noexcept;

    SandboxAnalyzer(const SandboxAnalyzer&) = delete;
    SandboxAnalyzer& operator=(const SandboxAnalyzer&) = delete;
    SandboxAnalyzer(SandboxAnalyzer&&) = delete;
    SandboxAnalyzer& operator=(SandboxAnalyzer&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const SandboxAnalyzerConfiguration& config = {},
                                  SandboxError* err = nullptr) noexcept;
    void Shutdown() noexcept;
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] SandboxStatus GetStatus() const noexcept;

    // ========================================================================
    // ANALYSIS
    // ========================================================================

    [[nodiscard]] SandboxVerdict Analyze(const fs::path& filePath,
                                         const SandboxAnalysisOptions& options = {},
                                         SandboxError* err = nullptr) noexcept;

    [[nodiscard]] std::string SubmitForAnalysis(const fs::path& filePath,
                                                 const SandboxAnalysisOptions& options = {},
                                                 SandboxError* err = nullptr) noexcept;

    [[nodiscard]] std::optional<SandboxVerdict> GetAnalysisResult(const std::string& taskId) const noexcept;
    [[nodiscard]] bool CancelAnalysis(const std::string& taskId) noexcept;
    [[nodiscard]] std::vector<std::string> GetPendingAnalyses() const noexcept;

    // ========================================================================
    // VM MANAGEMENT
    // ========================================================================

    [[nodiscard]] std::vector<VMConfiguration> GetAvailableVMs() const noexcept;
    [[nodiscard]] std::string GetVMStatus(const std::string& vmName) const noexcept;
    [[nodiscard]] bool RevertToSnapshot(const std::string& vmName, const std::string& snapshotName) noexcept;
    [[nodiscard]] bool StartVM(const std::string& vmName) noexcept;
    [[nodiscard]] bool StopVM(const std::string& vmName) noexcept;

    // ========================================================================
    // ARTIFACT MANAGEMENT
    // ========================================================================

    [[nodiscard]] std::vector<ExtractedArtifact> GetArtifacts(const std::string& taskId) const noexcept;
    [[nodiscard]] bool DownloadArtifact(const std::string& taskId, const std::string& artifactId,
                                         const fs::path& destination) noexcept;
    [[nodiscard]] std::optional<fs::path> GetMemoryDump(const std::string& taskId) const noexcept;
    [[nodiscard]] std::optional<fs::path> GetNetworkCapture(const std::string& taskId) const noexcept;

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void RegisterProgressCallback(AnalysisProgressCallback callback) noexcept;
    void RegisterCompleteCallback(AnalysisCompleteCallback callback) noexcept;
    void RegisterErrorCallback(ErrorCallback callback) noexcept;
    void UnregisterCallbacks() noexcept;

    // ========================================================================
    // STATISTICS
    // ========================================================================

    struct Statistics {
        std::atomic<uint64_t> totalAnalyses{0};
        std::atomic<uint64_t> maliciousSamplesDetected{0};
        std::atomic<uint64_t> vmsStarted{0};
        std::atomic<uint64_t> vmsStopped{0};
        std::atomic<uint64_t> snapshotsRestored{0};
        std::atomic<uint64_t> filesTransferred{0};
        std::atomic<uint64_t> artifactsExtracted{0};
        std::atomic<uint64_t> totalAnalysisTimeSeconds{0};
        std::atomic<uint64_t> timeouts{0};
        std::atomic<uint64_t> failures{0};
        TimePoint startTime = Clock::now();

        void Reset() noexcept;
    };

    [[nodiscard]] const Statistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

    [[nodiscard]] bool SelfTest() noexcept;
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    SandboxAnalyzer() noexcept;
    ~SandboxAnalyzer();

    class Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] const wchar_t* SandboxEnvironmentToString(SandboxEnvironment env) noexcept;
[[nodiscard]] const wchar_t* GuestOSTypeToString(GuestOSType os) noexcept;
[[nodiscard]] const wchar_t* AnalysisStatusToString(AnalysisStatus status) noexcept;
[[nodiscard]] const wchar_t* ThreatScoreLevelToString(ThreatScoreLevel level) noexcept;
[[nodiscard]] ThreatScoreLevel CalculateThreatLevel(int score) noexcept;
[[nodiscard]] bool IsHyperVAvailable() noexcept;

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
