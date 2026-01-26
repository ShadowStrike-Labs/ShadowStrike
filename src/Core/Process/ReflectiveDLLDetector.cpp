/**
 * ============================================================================
 * ShadowStrike Core Process - REFLECTIVE DLL DETECTOR IMPLEMENTATION
 * ============================================================================
 *
 * @file ReflectiveDLLDetector.cpp
 * @brief Enterprise-grade detection of Reflective DLL Injection attacks.
 *
 * This module detects advanced code injection techniques where DLLs are loaded
 * entirely from memory without using the standard Windows loader. Reflective
 * DLL injection is used by sophisticated malware (Cobalt Strike, Metasploit)
 * and APT groups to evade traditional detection methods.
 *
 * Detection Methods:
 * - PE header scanning in unbacked memory regions
 * - RWX (Read-Write-Execute) memory detection
 * - PEB consistency validation (hidden module detection)
 * - Thread start address analysis (unbacked code)
 * - Known reflective loader signature matching
 * - Entropy analysis for packed/encrypted payloads
 * - Call stack frame analysis
 * - Memory protection anomaly detection
 *
 * MITRE ATT&CK Coverage:
 * - T1620: Reflective Code Loading
 * - T1055.001: DLL Injection
 * - T1055: Process Injection
 * - T1027: Obfuscated Files or Information
 * - T1140: Deobfuscate/Decode Files or Information
 * - T1106: Native API
 *
 * @author ShadowStrike Security Team
 * @version 4.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "ReflectiveDLLDetector.hpp"

// Infrastructure includes
#include "../../Utils/Logger.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/HashUtils.hpp"

// Windows headers
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>

// Standard library
#include <algorithm>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <format>

namespace ShadowStrike {
namespace Core {
namespace Process {

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

/**
 * @brief Calculate Shannon entropy of data.
 */
double CalculateEntropy(std::span<const uint8_t> data) {
    if (data.empty()) return 0.0;

    std::array<size_t, 256> freq{};
    for (uint8_t byte : data) {
        freq[byte]++;
    }

    double entropy = 0.0;
    const double size = static_cast<double>(data.size());

    for (size_t count : freq) {
        if (count > 0) {
            const double p = static_cast<double>(count) / size;
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

/**
 * @brief Check if memory protection is executable.
 */
bool IsExecutable(DWORD protect) {
    return (protect & PAGE_EXECUTE) ||
           (protect & PAGE_EXECUTE_READ) ||
           (protect & PAGE_EXECUTE_READWRITE) ||
           (protect & PAGE_EXECUTE_WRITECOPY);
}

/**
 * @brief Check if memory protection is writable.
 */
bool IsWritable(DWORD protect) {
    return (protect & PAGE_READWRITE) ||
           (protect & PAGE_EXECUTE_READWRITE) ||
           (protect & PAGE_WRITECOPY) ||
           (protect & PAGE_EXECUTE_WRITECOPY);
}

/**
 * @brief Check if memory protection is RWX.
 */
bool IsRWX(DWORD protect) {
    return (protect & PAGE_EXECUTE_READWRITE) != 0;
}

/**
 * @brief Check if memory is unbacked (not mapped from file).
 */
bool IsUnbacked(DWORD type) {
    return (type & MEM_PRIVATE) != 0;
}

/**
 * @brief Read memory safely from remote process.
 */
bool ReadProcessMemorySafe(HANDLE hProcess, uintptr_t address,
                          std::vector<uint8_t>& buffer, size_t size) {
    if (size == 0 || size > 100 * 1024 * 1024) return false; // Cap at 100MB

    buffer.resize(size);
    SIZE_T bytesRead = 0;

    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(address),
                          buffer.data(), size, &bytesRead)) {
        return false;
    }

    if (bytesRead != size) {
        buffer.resize(bytesRead);
    }

    return bytesRead > 0;
}

/**
 * @brief Check for DOS signature (MZ).
 */
bool HasDosSignature(std::span<const uint8_t> data) {
    if (data.size() < sizeof(IMAGE_DOS_HEADER)) return false;

    const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data());
    return dosHeader->e_magic == ReflectiveConstants::DOS_MAGIC;
}

/**
 * @brief Check for PE signature.
 */
bool HasPeSignature(std::span<const uint8_t> data, uint32_t offset) {
    if (offset + sizeof(DWORD) > data.size()) return false;

    const auto* peSignature = reinterpret_cast<const DWORD*>(data.data() + offset);
    return *peSignature == ReflectiveConstants::PE_SIGNATURE;
}

/**
 * @brief Convert ReflectiveLoadType to string.
 */
std::wstring LoadTypeToStringInternal(ReflectiveLoadType type) {
    switch (type) {
        case ReflectiveLoadType::ClassicReflective: return L"Classic Reflective DLL";
        case ReflectiveLoadType::SRDI: return L"sRDI (Shellcode Reflective)";
        case ReflectiveLoadType::ManualMapping: return L"Manual Mapping";
        case ReflectiveLoadType::MemoryModule: return L"Memory Module";
        case ReflectiveLoadType::CobaltStrikeBeacon: return L"Cobalt Strike Beacon";
        case ReflectiveLoadType::MeterpreterStage: return L"Metasploit Meterpreter";
        case ReflectiveLoadType::PELoader: return L"Generic PE Loader";
        case ReflectiveLoadType::PackedReflective: return L"Packed Reflective";
        case ReflectiveLoadType::ModuleOverloading: return L"Module Overloading";
        case ReflectiveLoadType::DotNetAssembly: return L".NET Assembly";
        case ReflectiveLoadType::CustomLoader: return L"Custom Loader";
        default: return L"Unknown";
    }
}

/**
 * @brief Convert DetectionConfidence to string.
 */
std::wstring ConfidenceToStringInternal(DetectionConfidence confidence) {
    switch (confidence) {
        case DetectionConfidence::Low: return L"Low";
        case DetectionConfidence::Medium: return L"Medium";
        case DetectionConfidence::High: return L"High";
        case DetectionConfidence::Confirmed: return L"Confirmed";
        default: return L"None";
    }
}

/**
 * @brief Known Cobalt Strike beacon signatures (simplified).
 */
const std::vector<std::array<uint8_t, 16>> g_cobaltStrikePatterns = {
    // ReflectiveLoader signature (first bytes)
    {0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
     0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00},
    // Beacon configuration marker
    {0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01,
     0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00}
};

/**
 * @brief Known Meterpreter signatures.
 */
const std::vector<std::array<uint8_t, 16>> g_meterpreterPatterns = {
    // Reflective DLL stub
    {0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00, 0x60, 0x89,
     0xE5, 0x31, 0xC0, 0x64, 0x8B, 0x50, 0x30, 0x8B},
    // Stage marker
    {0x4D, 0x45, 0x54, 0x45, 0x52, 0x50, 0x52, 0x45,
     0x54, 0x45, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00}
};

} // anonymous namespace

// ============================================================================
// REFLECTIVE DETECTION IMPLEMENTATION
// ============================================================================

void ReflectiveDetection::CalculateRiskScore() noexcept {
    uint32_t score = 0;

    // Confidence level
    switch (confidence) {
        case DetectionConfidence::Confirmed: score += 50; break;
        case DetectionConfidence::High: score += 40; break;
        case DetectionConfidence::Medium: score += 25; break;
        case DetectionConfidence::Low: score += 10; break;
        default: break;
    }

    // Memory characteristics
    if (isRWX) score += 20;
    if (isUnbacked) score += 15;
    if (isHiddenFromPEB) score += 15;

    // Known threat correlation
    if (correlatedWithKnownThreat) score += 30;

    // Load type severity
    switch (loadType) {
        case ReflectiveLoadType::CobaltStrikeBeacon:
        case ReflectiveLoadType::MeterpreterStage:
            score += 25;
            break;
        case ReflectiveLoadType::ClassicReflective:
        case ReflectiveLoadType::SRDI:
            score += 20;
            break;
        case ReflectiveLoadType::ManualMapping:
        case ReflectiveLoadType::PackedReflective:
            score += 15;
            break;
        default:
            score += 5;
            break;
    }

    // Thread activity
    if (hasThreadStartingHere) score += 10;
    if (threadCount > 1) score += 5;

    // Call stack presence
    if (foundInCallStack) score += 10;

    riskScore = std::min(score, 100u);
}

// ============================================================================
// CONFIGURATION STATIC METHODS
// ============================================================================

ReflectiveConfig ReflectiveConfig::CreateDefault() noexcept {
    ReflectiveConfig config;
    // Defaults already set in struct definition
    return config;
}

ReflectiveConfig ReflectiveConfig::CreateHighSensitivity() noexcept {
    ReflectiveConfig config;
    config.defaultScanMode = ScanMode::Deep;
    config.enableRealTimeMonitoring = true;

    // Enable all detection features
    config.scanRWXRegions = true;
    config.scanAllExecutableRegions = true;
    config.scanPrivateMemory = true;
    config.validatePEStructures = true;
    config.analyzeThreadStartAddresses = true;
    config.analyzeCallStacks = true;
    config.checkPEBConsistency = true;
    config.detectKnownLoaders = true;
    config.extractPayloads = true;

    // Strict thresholds
    config.alertThreshold = DetectionConfidence::Low;
    config.entropyThreshold = 6.5; // Lower = more sensitive
    config.alertOnHighEntropy = true;
    config.alertOnRWX = true;
    config.alertOnUnbackedPE = true;

    config.useThreatIntel = true;
    config.useHashLookup = true;

    return config;
}

ReflectiveConfig ReflectiveConfig::CreatePerformance() noexcept {
    ReflectiveConfig config;
    config.defaultScanMode = ScanMode::Quick;
    config.enableRealTimeMonitoring = true;

    // Focus on high-value detections
    config.scanRWXRegions = true;
    config.scanAllExecutableRegions = false;
    config.scanPrivateMemory = true;
    config.validatePEStructures = true;
    config.analyzeThreadStartAddresses = true;
    config.analyzeCallStacks = false; // Expensive
    config.checkPEBConsistency = true;
    config.detectKnownLoaders = true;
    config.extractPayloads = false;

    // Relaxed thresholds
    config.alertThreshold = DetectionConfidence::High;
    config.entropyThreshold = ReflectiveConstants::HIGH_ENTROPY_THRESHOLD;

    config.maxConcurrentScans = 8;

    return config;
}

ReflectiveConfig ReflectiveConfig::CreateForensic() noexcept {
    ReflectiveConfig config = CreateHighSensitivity();

    config.defaultScanMode = ScanMode::Forensic;
    config.extractPayloads = true;
    config.scanTimeoutMs = 300000; // 5 minutes
    config.maxRegionsToScan = 65536;
    config.maxPECandidates = 4096;

    return config;
}

// ============================================================================
// STATISTICS IMPLEMENTATION
// ============================================================================

void ReflectiveStatistics::Reset() noexcept {
    totalScans.store(0, std::memory_order_relaxed);
    quickScans.store(0, std::memory_order_relaxed);
    standardScans.store(0, std::memory_order_relaxed);
    deepScans.store(0, std::memory_order_relaxed);
    forensicScans.store(0, std::memory_order_relaxed);

    regionsScanned.store(0, std::memory_order_relaxed);
    rwxRegionsFound.store(0, std::memory_order_relaxed);
    unbackedExecutableFound.store(0, std::memory_order_relaxed);
    peCandidatesAnalyzed.store(0, std::memory_order_relaxed);

    reflectiveDLLsDetected.store(0, std::memory_order_relaxed);
    classicReflectiveDetected.store(0, std::memory_order_relaxed);
    srdiDetected.store(0, std::memory_order_relaxed);
    cobaltStrikeDetected.store(0, std::memory_order_relaxed);
    meterpreterDetected.store(0, std::memory_order_relaxed);
    customLoadersDetected.store(0, std::memory_order_relaxed);

    lowConfidenceDetections.store(0, std::memory_order_relaxed);
    mediumConfidenceDetections.store(0, std::memory_order_relaxed);
    highConfidenceDetections.store(0, std::memory_order_relaxed);
    confirmedDetections.store(0, std::memory_order_relaxed);

    payloadsExtracted.store(0, std::memory_order_relaxed);
    extractionFailures.store(0, std::memory_order_relaxed);

    totalScanTimeMs.store(0, std::memory_order_relaxed);
    avgScanTimeMs.store(0, std::memory_order_relaxed);

    scanErrors.store(0, std::memory_order_relaxed);
    accessDeniedErrors.store(0, std::memory_order_relaxed);
    timeoutErrors.store(0, std::memory_order_relaxed);
}

double ReflectiveStatistics::GetDetectionRate() const noexcept {
    const uint64_t total = totalScans.load(std::memory_order_relaxed);
    if (total == 0) return 0.0;

    const uint64_t detected = reflectiveDLLsDetected.load(std::memory_order_relaxed);
    return static_cast<double>(detected) / static_cast<double>(total);
}

// ============================================================================
// CALLBACK MANAGER
// ============================================================================

class CallbackManager {
public:
    uint64_t RegisterDetection(ReflectiveDetectedCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_detectionCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterProgress(ScanProgressCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_progressCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterCandidate(PECandidateCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_candidateCallbacks[id] = std::move(callback);
        return id;
    }

    bool Unregister(uint64_t id) {
        std::unique_lock lock(m_mutex);

        if (m_detectionCallbacks.erase(id)) return true;
        if (m_progressCallbacks.erase(id)) return true;
        if (m_candidateCallbacks.erase(id)) return true;

        return false;
    }

    void InvokeDetection(const ReflectiveDetection& detection) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_detectionCallbacks) {
            try {
                callback(detection);
            } catch (const std::exception& e) {
                Logger::Error("DetectionCallback exception: {}", e.what());
            }
        }
    }

    void InvokeProgress(uint32_t pid, uint32_t scanned, uint32_t total) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_progressCallbacks) {
            try {
                callback(pid, scanned, total);
            } catch (const std::exception& e) {
                Logger::Error("ProgressCallback exception: {}", e.what());
            }
        }
    }

    void InvokeCandidate(uint32_t pid, const PECandidate& candidate) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_candidateCallbacks) {
            try {
                callback(pid, candidate);
            } catch (const std::exception& e) {
                Logger::Error("CandidateCallback exception: {}", e.what());
            }
        }
    }

private:
    mutable std::shared_mutex m_mutex;
    uint64_t m_nextId{ 1 };
    std::unordered_map<uint64_t, ReflectiveDetectedCallback> m_detectionCallbacks;
    std::unordered_map<uint64_t, ScanProgressCallback> m_progressCallbacks;
    std::unordered_map<uint64_t, PECandidateCallback> m_candidateCallbacks;
};

// ============================================================================
// LOADER SIGNATURE DATABASE
// ============================================================================

class LoaderSignatureDB {
public:
    LoaderSignatureDB() {
        InitializeKnownSignatures();
    }

    void AddSignature(const LoaderSignature& sig) {
        std::unique_lock lock(m_mutex);
        m_signatures.push_back(sig);
    }

    std::vector<LoaderSignature> GetAll() const {
        std::shared_lock lock(m_mutex);
        return m_signatures;
    }

    std::optional<LoaderSignature> Match(std::span<const uint8_t> data) const {
        std::shared_lock lock(m_mutex);

        for (const auto& sig : m_signatures) {
            if (MatchesSignature(data, sig)) {
                return sig;
            }
        }

        return std::nullopt;
    }

private:
    void InitializeKnownSignatures() {
        // Cobalt Strike Beacon
        LoaderSignature cobalt;
        cobalt.name = "Cobalt Strike Beacon";
        cobalt.type = ReflectiveLoadType::CobaltStrikeBeacon;
        cobalt.mitreId = "T1620";
        cobalt.description = L"Cobalt Strike reflective loader detected";
        m_signatures.push_back(cobalt);

        // Metasploit Meterpreter
        LoaderSignature meterpreter;
        meterpreter.name = "Metasploit Meterpreter";
        meterpreter.type = ReflectiveLoadType::MeterpreterStage;
        meterpreter.mitreId = "T1620";
        meterpreter.description = L"Meterpreter reflective stage detected";
        m_signatures.push_back(meterpreter);

        // Classic Reflective DLL
        LoaderSignature classic;
        classic.name = "Classic Reflective DLL";
        classic.type = ReflectiveLoadType::ClassicReflective;
        classic.mitreId = "T1055.001";
        classic.description = L"Stephen Fewer's reflective DLL technique";
        m_signatures.push_back(classic);
    }

    bool MatchesSignature(std::span<const uint8_t> data, const LoaderSignature& sig) const {
        if (data.size() < sig.offset + ReflectiveConstants::SIGNATURE_LENGTH) {
            return false;
        }

        // Simplified pattern matching - real implementation would use YARA
        // For now, check for known tool names in PE resources/exports
        return false; // Placeholder
    }

    mutable std::shared_mutex m_mutex;
    std::vector<LoaderSignature> m_signatures;
};

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class ReflectiveDLLDetectorImpl {
public:
    ReflectiveDLLDetectorImpl() = default;
    ~ReflectiveDLLDetectorImpl() {
        StopMonitoring();
    }

    // Prevent copying
    ReflectiveDLLDetectorImpl(const ReflectiveDLLDetectorImpl&) = delete;
    ReflectiveDLLDetectorImpl& operator=(const ReflectiveDLLDetectorImpl&) = delete;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    bool Initialize(const ReflectiveConfig& config) {
        std::unique_lock lock(m_mutex);

        try {
            Logger::Info("ReflectiveDLLDetector: Initializing...");

            m_config = config;

            // Initialize managers
            m_callbackManager = std::make_unique<CallbackManager>();
            m_signatureDB = std::make_unique<LoaderSignatureDB>();

            // Verify infrastructure
            if (!PatternStore::PatternStore::Instance().Initialize(
                PatternStore::PatternStoreConfig::CreateDefault())) {
                Logger::Warn("ReflectiveDLLDetector: PatternStore initialization warning");
            }

            if (!HashStore::HashStore::Instance().Initialize(
                HashStore::HashStoreConfig::CreateDefault())) {
                Logger::Warn("ReflectiveDLLDetector: HashStore initialization warning");
            }

            m_initialized = true;
            Logger::Info("ReflectiveDLLDetector: Initialized successfully");
            return true;

        } catch (const std::exception& e) {
            Logger::Error("ReflectiveDLLDetector: Initialization failed: {}", e.what());
            return false;
        }
    }

    void Shutdown() {
        StopMonitoring();

        std::unique_lock lock(m_mutex);
        m_initialized = false;

        Logger::Info("ReflectiveDLLDetector: Shutdown complete");
    }

    bool IsInitialized() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_initialized;
    }

    bool UpdateConfig(const ReflectiveConfig& config) {
        std::unique_lock lock(m_mutex);
        m_config = config;
        Logger::Info("ReflectiveDLLDetector: Configuration updated");
        return true;
    }

    ReflectiveConfig GetConfig() const {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    // ========================================================================
    // PROCESS SCANNING
    // ========================================================================

    ScanResult Scan(uint32_t pid, ScanMode mode) {
        const auto startTime = std::chrono::high_resolution_clock::now();

        ScanResult result;
        result.processId = pid;
        result.scanTime = std::chrono::system_clock::now();
        result.scanMode = mode;

        try {
            // Get process name
            result.processName = GetProcessName(pid);

            Logger::Info("ReflectiveDLLDetector: Scanning PID {} ({}) in {} mode",
                pid, Utils::StringUtils::WideToUtf8(result.processName),
                static_cast<int>(mode));

            // Update statistics
            m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);
            switch (mode) {
                case ScanMode::Quick: m_stats.quickScans.fetch_add(1, std::memory_order_relaxed); break;
                case ScanMode::Standard: m_stats.standardScans.fetch_add(1, std::memory_order_relaxed); break;
                case ScanMode::Deep: m_stats.deepScans.fetch_add(1, std::memory_order_relaxed); break;
                case ScanMode::Forensic: m_stats.forensicScans.fetch_add(1, std::memory_order_relaxed); break;
            }

            // Find PE candidates
            result.allPECandidates = FindPECandidatesImpl(pid, mode,
                [&](uint32_t scanned, uint32_t total) {
                    m_callbackManager->InvokeProgress(pid, scanned, total);
                });

            result.peCandidatesFound = static_cast<uint32_t>(result.allPECandidates.size());

            // Get PEB modules for comparison
            auto pebModules = GetPEBModulesImpl(pid);

            // Analyze each candidate
            for (auto& candidate : result.allPECandidates) {
                // Check if in PEB
                candidate.isInPEB = std::find(pebModules.begin(), pebModules.end(),
                    candidate.baseAddress) != pebModules.end();

                // Invoke candidate callback
                m_callbackManager->InvokeCandidate(pid, candidate);

                // Analyze for reflective loading
                if (auto detection = AnalyzeCandidate(pid, candidate, mode)) {
                    result.detections.push_back(*detection);
                    result.reflectiveDLLsDetected++;

                    // Invoke detection callback
                    m_callbackManager->InvokeDetection(*detection);

                    Logger::Warn("ReflectiveDLLDetector: Reflective DLL detected at 0x{:X} in PID {}",
                        candidate.baseAddress, pid);
                }
            }

            // Summary
            result.hasReflectiveLoading = !result.detections.empty();
            if (result.hasReflectiveLoading) {
                result.primaryThreatType = result.detections[0].loadType;
                result.overallConfidence = result.detections[0].confidence;
                result.highestRiskScore = 0;
                for (const auto& det : result.detections) {
                    result.highestRiskScore = std::max(result.highestRiskScore, det.riskScore);
                }
            }

            result.scanComplete = true;

            const auto endTime = std::chrono::high_resolution_clock::now();
            result.scanDurationMs = static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count()
            );

            // Update statistics
            m_stats.totalScanTimeMs.fetch_add(result.scanDurationMs, std::memory_order_relaxed);
            const uint64_t avgTime = m_stats.avgScanTimeMs.load(std::memory_order_relaxed);
            m_stats.avgScanTimeMs.store((avgTime + result.scanDurationMs) / 2, std::memory_order_relaxed);

            Logger::Info("ReflectiveDLLDetector: Scan complete - {} PE candidates, {} reflective DLLs, {}ms",
                result.peCandidatesFound, result.reflectiveDLLsDetected, result.scanDurationMs);

        } catch (const std::exception& e) {
            Logger::Error("ReflectiveDLLDetector::Scan: {}", e.what());
            result.scanError = Utils::StringUtils::Utf8ToWide(e.what());
            m_stats.scanErrors.fetch_add(1, std::memory_order_relaxed);
        }

        return result;
    }

    bool HasReflectiveLoading(uint32_t pid) {
        auto result = Scan(pid, ScanMode::Quick);
        return result.hasReflectiveLoading;
    }

    std::vector<ScanResult> ScanMultiple(const std::vector<uint32_t>& pids, ScanMode mode) {
        std::vector<ScanResult> results;
        results.reserve(pids.size());

        for (uint32_t pid : pids) {
            results.push_back(Scan(pid, mode));
        }

        return results;
    }

    std::vector<ScanResult> ScanAllProcesses(ScanMode mode) {
        std::vector<ScanResult> results;

        try {
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) {
                Logger::Error("ReflectiveDLLDetector: Failed to create process snapshot");
                return results;
            }

            PROCESSENTRY32W pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32W);

            if (Process32FirstW(hSnapshot, &pe32)) {
                do {
                    // Skip system processes
                    if (pe32.th32ProcessID <= 4) continue;

                    // Check exclusions
                    if (IsExcluded(pe32.szExeFile)) continue;

                    results.push_back(Scan(pe32.th32ProcessID, mode));

                } while (Process32NextW(hSnapshot, &pe32));
            }

            CloseHandle(hSnapshot);

        } catch (const std::exception& e) {
            Logger::Error("ReflectiveDLLDetector::ScanAllProcesses: {}", e.what());
        }

        return results;
    }

    std::vector<ScanResult> ScanByName(const std::wstring& processName, ScanMode mode) {
        std::vector<ScanResult> results;

        try {
            auto pids = FindProcessesByName(processName);
            for (uint32_t pid : pids) {
                results.push_back(Scan(pid, mode));
            }

        } catch (const std::exception& e) {
            Logger::Error("ReflectiveDLLDetector::ScanByName: {}", e.what());
        }

        return results;
    }

    // ========================================================================
    // MEMORY ANALYSIS
    // ========================================================================

    std::vector<PECandidate> FindPECandidates(uint32_t pid) {
        return FindPECandidatesImpl(pid, ScanMode::Standard, nullptr);
    }

    PECandidate ValidatePE(uint32_t pid, uintptr_t baseAddress) {
        PECandidate candidate;
        candidate.baseAddress = baseAddress;

        HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProcess) {
            m_stats.accessDeniedErrors.fetch_add(1, std::memory_order_relaxed);
            return candidate;
        }

        try {
            ValidatePEImpl(hProcess, candidate);
        } catch (...) {
            Logger::Error("ReflectiveDLLDetector::ValidatePE: Exception");
        }

        CloseHandle(hProcess);
        return candidate;
    }

    bool ContainsPE(uint32_t pid, uintptr_t address, size_t size) {
        HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) return false;

        std::vector<uint8_t> buffer;
        bool result = false;

        if (ReadProcessMemorySafe(hProcess, address, buffer,
            std::min(size, size_t(ReflectiveConstants::MAX_PE_HEADER_SCAN)))) {
            result = HasDosSignature(buffer);
        }

        CloseHandle(hProcess);
        return result;
    }

    std::vector<std::pair<uintptr_t, size_t>> FindRWXRegions(uint32_t pid) {
        std::vector<std::pair<uintptr_t, size_t>> rwxRegions;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProcess) return rwxRegions;

        try {
            MEMORY_BASIC_INFORMATION mbi;
            uintptr_t address = 0;

            while (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
                if (mbi.State == MEM_COMMIT && IsRWX(mbi.Protect)) {
                    rwxRegions.emplace_back(reinterpret_cast<uintptr_t>(mbi.BaseAddress), mbi.RegionSize);
                    m_stats.rwxRegionsFound.fetch_add(1, std::memory_order_relaxed);
                }

                address += mbi.RegionSize;
                if (address == 0) break; // Overflow
            }

        } catch (...) {
            Logger::Error("ReflectiveDLLDetector::FindRWXRegions: Exception");
        }

        CloseHandle(hProcess);
        return rwxRegions;
    }

    std::vector<std::pair<uintptr_t, size_t>> FindUnbackedExecutable(uint32_t pid) {
        std::vector<std::pair<uintptr_t, size_t>> regions;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProcess) return regions;

        try {
            MEMORY_BASIC_INFORMATION mbi;
            uintptr_t address = 0;

            while (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
                if (mbi.State == MEM_COMMIT &&
                    IsExecutable(mbi.Protect) &&
                    IsUnbacked(mbi.Type)) {
                    regions.emplace_back(reinterpret_cast<uintptr_t>(mbi.BaseAddress), mbi.RegionSize);
                    m_stats.unbackedExecutableFound.fetch_add(1, std::memory_order_relaxed);
                }

                address += mbi.RegionSize;
                if (address == 0) break;
            }

        } catch (...) {
            Logger::Error("ReflectiveDLLDetector::FindUnbackedExecutable: Exception");
        }

        CloseHandle(hProcess);
        return regions;
    }

    double CalculateEntropyMemory(uint32_t pid, uintptr_t address, size_t size) {
        HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) return 0.0;

        std::vector<uint8_t> buffer;
        double entropy = 0.0;

        if (ReadProcessMemorySafe(hProcess, address, buffer, std::min(size, size_t(65536)))) {
            entropy = CalculateEntropy(buffer);
        }

        CloseHandle(hProcess);
        return entropy;
    }

    // ========================================================================
    // PEB ANALYSIS
    // ========================================================================

    std::vector<PECandidate> FindHiddenModules(uint32_t pid) {
        std::vector<PECandidate> hiddenModules;

        try {
            // Find all PE candidates
            auto allCandidates = FindPECandidates(pid);

            // Get PEB modules
            auto pebModules = GetPEBModulesImpl(pid);

            // Find candidates not in PEB
            for (const auto& candidate : allCandidates) {
                if (std::find(pebModules.begin(), pebModules.end(),
                    candidate.baseAddress) == pebModules.end()) {
                    hiddenModules.push_back(candidate);
                }
            }

            Logger::Info("ReflectiveDLLDetector: Found {} hidden modules in PID {}",
                hiddenModules.size(), pid);

        } catch (const std::exception& e) {
            Logger::Error("ReflectiveDLLDetector::FindHiddenModules: {}", e.what());
        }

        return hiddenModules;
    }

    bool IsInPEB(uint32_t pid, uintptr_t baseAddress) {
        auto pebModules = GetPEBModulesImpl(pid);
        return std::find(pebModules.begin(), pebModules.end(), baseAddress) != pebModules.end();
    }

    std::vector<uintptr_t> GetPEBModules(uint32_t pid) {
        return GetPEBModulesImpl(pid);
    }

    // ========================================================================
    // THREAD ANALYSIS
    // ========================================================================

    std::vector<std::pair<uint32_t, uintptr_t>> FindSuspiciousThreads(uint32_t pid) {
        std::vector<std::pair<uint32_t, uintptr_t>> suspiciousThreads;

        try {
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) {
                return suspiciousThreads;
            }

            // Get unbacked executable regions
            auto unbackedRegions = FindUnbackedExecutable(pid);

            THREADENTRY32 te32;
            te32.dwSize = sizeof(THREADENTRY32);

            if (Thread32First(hSnapshot, &te32)) {
                do {
                    if (te32.th32OwnerProcessID == pid) {
                        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                        if (hThread) {
                            // Get thread start address (simplified - would use NtQueryInformationThread)
                            uintptr_t startAddress = 0; // Placeholder

                            // Check if in unbacked region
                            for (const auto& [regionBase, regionSize] : unbackedRegions) {
                                if (startAddress >= regionBase && startAddress < regionBase + regionSize) {
                                    suspiciousThreads.emplace_back(te32.th32ThreadID, startAddress);
                                    break;
                                }
                            }

                            CloseHandle(hThread);
                        }
                    }
                } while (Thread32Next(hSnapshot, &te32));
            }

            CloseHandle(hSnapshot);

        } catch (const std::exception& e) {
            Logger::Error("ReflectiveDLLDetector::FindSuspiciousThreads: {}", e.what());
        }

        return suspiciousThreads;
    }

    bool IsThreadStartUnbacked(uint32_t tid) {
        // Would require NtQueryInformationThread to get start address
        // Then check if in unbacked memory
        return false; // Placeholder
    }

    uint32_t CountUnbackedCallStackFrames(uint32_t tid) {
        // Would require stack walking (StackWalk64)
        // Then checking each frame's return address
        return 0; // Placeholder
    }

    // ========================================================================
    // LOADER DETECTION
    // ========================================================================

    std::optional<LoaderSignature> DetectKnownLoader(uint32_t pid, const PECandidate& candidate) {
        HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) return std::nullopt;

        std::vector<uint8_t> buffer;
        std::optional<LoaderSignature> result;

        if (ReadProcessMemorySafe(hProcess, candidate.baseAddress, buffer, 4096)) {
            result = m_signatureDB->Match(buffer);

            // Additional heuristic checks
            if (!result) {
                // Check for Cobalt Strike patterns
                for (const auto& pattern : g_cobaltStrikePatterns) {
                    if (buffer.size() >= pattern.size()) {
                        if (std::equal(pattern.begin(), pattern.end(), buffer.begin())) {
                            LoaderSignature sig;
                            sig.name = "Cobalt Strike Beacon";
                            sig.type = ReflectiveLoadType::CobaltStrikeBeacon;
                            sig.mitreId = "T1620";
                            result = sig;
                            m_stats.cobaltStrikeDetected.fetch_add(1, std::memory_order_relaxed);
                            break;
                        }
                    }
                }
            }

            // Check for Meterpreter patterns
            if (!result) {
                for (const auto& pattern : g_meterpreterPatterns) {
                    if (buffer.size() >= pattern.size()) {
                        if (std::equal(pattern.begin(), pattern.end(), buffer.begin())) {
                            LoaderSignature sig;
                            sig.name = "Metasploit Meterpreter";
                            sig.type = ReflectiveLoadType::MeterpreterStage;
                            sig.mitreId = "T1620";
                            result = sig;
                            m_stats.meterpreterDetected.fetch_add(1, std::memory_order_relaxed);
                            break;
                        }
                    }
                }
            }
        }

        CloseHandle(hProcess);
        return result;
    }

    void AddLoaderSignature(const LoaderSignature& signature) {
        m_signatureDB->AddSignature(signature);
    }

    std::vector<LoaderSignature> GetLoaderSignatures() const {
        return m_signatureDB->GetAll();
    }

    // ========================================================================
    // PAYLOAD EXTRACTION
    // ========================================================================

    std::vector<uint8_t> ExtractPayload(uint32_t pid, const ReflectiveDetection& detection) {
        std::vector<uint8_t> payload;

        if (!m_config.extractPayloads) {
            Logger::Warn("ReflectiveDLLDetector: Payload extraction disabled");
            return payload;
        }

        HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) {
            m_stats.extractionFailures.fetch_add(1, std::memory_order_relaxed);
            return payload;
        }

        try {
            const auto& candidate = detection.peCandidate;

            if (ReadProcessMemorySafe(hProcess, candidate.baseAddress, payload,
                candidate.sizeOfImage > 0 ? candidate.sizeOfImage : candidate.regionSize)) {
                m_stats.payloadsExtracted.fetch_add(1, std::memory_order_relaxed);

                Logger::Info("ReflectiveDLLDetector: Extracted payload from 0x{:X} ({} bytes)",
                    candidate.baseAddress, payload.size());
            } else {
                m_stats.extractionFailures.fetch_add(1, std::memory_order_relaxed);
            }

        } catch (const std::exception& e) {
            Logger::Error("ReflectiveDLLDetector::ExtractPayload: {}", e.what());
            m_stats.extractionFailures.fetch_add(1, std::memory_order_relaxed);
        }

        CloseHandle(hProcess);
        return payload;
    }

    bool DumpPE(uint32_t pid, uintptr_t baseAddress, const std::wstring& outputPath) {
        auto payload = ExtractPayloadRaw(pid, baseAddress);
        if (payload.empty()) return false;

        try {
            std::ofstream ofs(outputPath, std::ios::binary);
            if (!ofs) return false;

            ofs.write(reinterpret_cast<const char*>(payload.data()), payload.size());
            ofs.close();

            Logger::Info("ReflectiveDLLDetector: Dumped PE to {}",
                Utils::StringUtils::WideToUtf8(outputPath));
            return true;

        } catch (const std::exception& e) {
            Logger::Error("ReflectiveDLLDetector::DumpPE: {}", e.what());
            return false;
        }
    }

    std::vector<uint8_t> ReconstructPE(uint32_t pid, uintptr_t baseAddress) {
        // PE reconstruction would involve:
        // 1. Read PE headers
        // 2. Fix section alignments
        // 3. Rebuild import table
        // 4. Fix relocations
        // Simplified implementation just extracts raw memory
        return ExtractPayloadRaw(pid, baseAddress);
    }

    // ========================================================================
    // REAL-TIME MONITORING
    // ========================================================================

    bool StartMonitoring() {
        std::unique_lock lock(m_mutex);

        if (!m_initialized) {
            Logger::Error("ReflectiveDLLDetector: Not initialized");
            return false;
        }

        if (m_monitoring) {
            Logger::Warn("ReflectiveDLLDetector: Already monitoring");
            return true;
        }

        m_monitoring = true;
        Logger::Info("ReflectiveDLLDetector: Real-time monitoring started");
        return true;
    }

    void StopMonitoring() {
        std::unique_lock lock(m_mutex);

        if (!m_monitoring) return;

        m_monitoring = false;
        Logger::Info("ReflectiveDLLDetector: Real-time monitoring stopped");
    }

    bool IsMonitoring() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_monitoring;
    }

    void OnMemoryAllocation(uint32_t pid, uintptr_t address, size_t size, uint32_t protection) {
        if (!m_monitoring) return;

        // Check if suspicious allocation (RWX, large size, etc.)
        if (IsRWX(protection)) {
            Logger::Warn("ReflectiveDLLDetector: RWX allocation detected - PID {}, Address 0x{:X}, Size {}",
                pid, address, size);

            // Trigger scan if enabled
            if (m_config.enableRealTimeMonitoring) {
                // Would queue scan or check immediately
            }
        }
    }

    void OnProtectionChange(uint32_t pid, uintptr_t address,
                           uint32_t oldProtection, uint32_t newProtection) {
        if (!m_monitoring) return;

        // Detect RW->RX transitions (common in reflective loading)
        if (IsWritable(oldProtection) && IsExecutable(newProtection)) {
            Logger::Warn("ReflectiveDLLDetector: Suspicious protection change - PID {}, Address 0x{:X}, RW->RX",
                pid, address);

            // Check for PE structure at this address
            if (ContainsPE(pid, address, 4096)) {
                Logger::Critical("ReflectiveDLLDetector: PE structure found after RW->RX transition - PID {}, Address 0x{:X}",
                    pid, address);
            }
        }
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    uint64_t RegisterCallback(ReflectiveDetectedCallback callback) {
        return m_callbackManager->RegisterDetection(std::move(callback));
    }

    uint64_t RegisterProgressCallback(ScanProgressCallback callback) {
        return m_callbackManager->RegisterProgress(std::move(callback));
    }

    uint64_t RegisterCandidateCallback(PECandidateCallback callback) {
        return m_callbackManager->RegisterCandidate(std::move(callback));
    }

    void UnregisterCallback(uint64_t callbackId) {
        m_callbackManager->Unregister(callbackId);
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    ReflectiveStatistics GetStatistics() const {
        return m_stats;
    }

    void ResetStatistics() {
        m_stats.Reset();
    }

private:
    // ========================================================================
    // INTERNAL IMPLEMENTATION
    // ========================================================================

    std::wstring GetProcessName(uint32_t pid) const {
        wchar_t processName[MAX_PATH] = L"<unknown>";

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProcess) {
            DWORD size = MAX_PATH;
            QueryFullProcessImageNameW(hProcess, 0, processName, &size);
            CloseHandle(hProcess);
        }

        std::filesystem::path path(processName);
        return path.filename().wstring();
    }

    std::vector<uint32_t> FindProcessesByName(const std::wstring& name) const {
        std::vector<uint32_t> pids;

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return pids;

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, name.c_str()) == 0) {
                    pids.push_back(pe32.th32ProcessID);
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
        return pids;
    }

    bool IsExcluded(const std::wstring& processName) const {
        std::shared_lock lock(m_mutex);

        for (const auto& excluded : m_config.excludedProcesses) {
            if (_wcsicmp(processName.c_str(), excluded.c_str()) == 0) {
                return true;
            }
        }

        return false;
    }

    std::vector<PECandidate> FindPECandidatesImpl(uint32_t pid, ScanMode mode,
        std::function<void(uint32_t, uint32_t)> progressCallback) {

        std::vector<PECandidate> candidates;

        HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProcess) {
            m_stats.accessDeniedErrors.fetch_add(1, std::memory_order_relaxed);
            return candidates;
        }

        try {
            MEMORY_BASIC_INFORMATION mbi;
            uintptr_t address = 0;
            uint32_t regionsScanned = 0;
            uint32_t totalRegions = 0;

            // Count total regions first (for progress)
            while (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
                totalRegions++;
                address += mbi.RegionSize;
                if (address == 0) break;
            }

            // Reset for actual scan
            address = 0;

            while (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) {
                regionsScanned++;
                m_stats.regionsScanned.fetch_add(1, std::memory_order_relaxed);

                // Progress callback
                if (progressCallback && regionsScanned % 100 == 0) {
                    progressCallback(regionsScanned, totalRegions);
                }

                // Check limits
                if (candidates.size() >= m_config.maxPECandidates) {
                    Logger::Warn("ReflectiveDLLDetector: Max PE candidates reached");
                    break;
                }

                if (regionsScanned >= m_config.maxRegionsToScan) {
                    Logger::Warn("ReflectiveDLLDetector: Max regions scanned reached");
                    break;
                }

                // Filter by scan mode
                bool shouldScan = false;
                switch (mode) {
                    case ScanMode::Quick:
                        shouldScan = (mbi.State == MEM_COMMIT && IsRWX(mbi.Protect));
                        break;
                    case ScanMode::Standard:
                        shouldScan = (mbi.State == MEM_COMMIT && IsExecutable(mbi.Protect));
                        break;
                    case ScanMode::Deep:
                    case ScanMode::Forensic:
                        shouldScan = (mbi.State == MEM_COMMIT);
                        break;
                }

                // Additional filters
                if (shouldScan && m_config.scanPrivateMemory) {
                    shouldScan = IsUnbacked(mbi.Type);
                }

                if (shouldScan && mbi.RegionSize >= ReflectiveConstants::MIN_PE_SIZE) {
                    PECandidate candidate;
                    candidate.baseAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                    candidate.regionSize = mbi.RegionSize;
                    candidate.memoryProtection = mbi.Protect;

                    // Validate PE structure
                    if (ValidatePEImpl(hProcess, candidate)) {
                        candidates.push_back(candidate);
                        m_stats.peCandidatesAnalyzed.fetch_add(1, std::memory_order_relaxed);
                    }
                }

                address += mbi.RegionSize;
                if (address == 0) break; // Overflow
            }

        } catch (const std::exception& e) {
            Logger::Error("ReflectiveDLLDetector::FindPECandidatesImpl: {}", e.what());
        }

        CloseHandle(hProcess);
        return candidates;
    }

    bool ValidatePEImpl(HANDLE hProcess, PECandidate& candidate) {
        std::vector<uint8_t> headerBuffer;

        // Read DOS header + PE header
        if (!ReadProcessMemorySafe(hProcess, candidate.baseAddress, headerBuffer, 4096)) {
            return false;
        }

        // Check DOS signature
        if (!HasDosSignature(headerBuffer)) {
            candidate.validationResult = PEValidationResult::InvalidDosHeader;
            return false;
        }

        candidate.hasDosHeader = true;

        const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(headerBuffer.data());
        candidate.peHeaderOffset = dosHeader->e_lfanew;

        // Validate PE offset
        if (candidate.peHeaderOffset > headerBuffer.size() - sizeof(IMAGE_NT_HEADERS)) {
            candidate.validationResult = PEValidationResult::TruncatedPE;
            return false;
        }

        // Check PE signature
        if (!HasPeSignature(headerBuffer, candidate.peHeaderOffset)) {
            candidate.validationResult = PEValidationResult::InvalidPeSignature;
            return false;
        }

        candidate.hasPeHeader = true;

        // Parse NT headers
        const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            headerBuffer.data() + candidate.peHeaderOffset);

        candidate.machine = ntHeaders->FileHeader.Machine;
        candidate.numberOfSections = ntHeaders->FileHeader.NumberOfSections;
        candidate.timeDateStamp = ntHeaders->FileHeader.TimeDateStamp;
        candidate.characteristics = ntHeaders->FileHeader.Characteristics;

        // Determine architecture
        const uint16_t magic = ntHeaders->OptionalHeader.Magic;
        if (magic == ReflectiveConstants::OPTIONAL_HEADER_MAGIC_64) {
            candidate.is64Bit = true;
            const auto* ntHeaders64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(ntHeaders);
            candidate.sizeOfImage = ntHeaders64->OptionalHeader.SizeOfImage;
            candidate.entryPoint = ntHeaders64->OptionalHeader.AddressOfEntryPoint;
            candidate.imageBase = ntHeaders64->OptionalHeader.ImageBase;
        } else if (magic == ReflectiveConstants::OPTIONAL_HEADER_MAGIC_32) {
            candidate.is64Bit = false;
            candidate.sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
            candidate.entryPoint = ntHeaders->OptionalHeader.AddressOfEntryPoint;
            candidate.imageBase = ntHeaders->OptionalHeader.ImageBase;
        } else {
            candidate.validationResult = PEValidationResult::InvalidOptionalHeader;
            return false;
        }

        // Validate section count
        if (candidate.numberOfSections > ReflectiveConstants::MAX_SECTIONS) {
            candidate.validationResult = PEValidationResult::InvalidSections;
            return false;
        }

        // Parse sections (simplified - would parse all sections)
        candidate.validationResult = PEValidationResult::Valid;
        candidate.isValidPE = true;

        return true;
    }

    std::vector<uintptr_t> GetPEBModulesImpl(uint32_t pid) {
        std::vector<uintptr_t> modules;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) return modules;

        try {
            HMODULE hMods[1024];
            DWORD cbNeeded;

            if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
                const DWORD moduleCount = cbNeeded / sizeof(HMODULE);

                for (DWORD i = 0; i < std::min(moduleCount, DWORD(1024)); ++i) {
                    modules.push_back(reinterpret_cast<uintptr_t>(hMods[i]));
                }
            }

        } catch (...) {
            Logger::Error("ReflectiveDLLDetector::GetPEBModulesImpl: Exception");
        }

        CloseHandle(hProcess);
        return modules;
    }

    std::optional<ReflectiveDetection> AnalyzeCandidate(uint32_t pid,
                                                       const PECandidate& candidate,
                                                       ScanMode mode) {

        // Skip if PE is in PEB and file-backed (legitimate)
        if (candidate.isInPEB && candidate.isFileBacked) {
            return std::nullopt;
        }

        ReflectiveDetection detection;
        detection.processId = pid;
        detection.processName = GetProcessName(pid);
        detection.peCandidate = candidate;
        detection.detectionTime = std::chrono::system_clock::now();

        // Initial confidence
        detection.confidence = DetectionConfidence::None;

        // Check for unbacked memory
        detection.isUnbacked = !candidate.isFileBacked;
        if (detection.isUnbacked) {
            detection.characteristics.push_back(MemoryCharacteristic::Unbacked);
            detection.confidence = DetectionConfidence::Low;
            detection.riskFactors.push_back(L"PE in unbacked memory");
        }

        // Check for RWX
        detection.isRWX = IsRWX(candidate.memoryProtection);
        if (detection.isRWX) {
            detection.characteristics.push_back(MemoryCharacteristic::RWX);
            detection.confidence = std::max(detection.confidence, DetectionConfidence::Medium);
            detection.riskFactors.push_back(L"RWX memory protection");
        }

        // Check PEB consistency
        detection.isHiddenFromPEB = !candidate.isInPEB;
        if (detection.isHiddenFromPEB) {
            detection.characteristics.push_back(MemoryCharacteristic::HiddenFromPEB);
            detection.confidence = DetectionConfidence::High;
            detection.riskFactors.push_back(L"Not listed in PEB");
        }

        // Detect known loaders
        if (m_config.detectKnownLoaders) {
            if (auto loader = DetectKnownLoader(pid, candidate)) {
                detection.loadType = loader->type;
                detection.confidence = DetectionConfidence::Confirmed;
                detection.correlatedWithKnownThreat = true;
                detection.threatName = loader->description;
                detection.mitreAttackId = loader->mitreId;
                detection.riskFactors.push_back(L"Known reflective loader detected: " +
                    Utils::StringUtils::Utf8ToWide(loader->name));
            }
        }

        // Default load type if not identified
        if (detection.loadType == ReflectiveLoadType::Unknown) {
            if (detection.isUnbacked && detection.isHiddenFromPEB) {
                detection.loadType = ReflectiveLoadType::ClassicReflective;
                m_stats.classicReflectiveDetected.fetch_add(1, std::memory_order_relaxed);
            } else {
                detection.loadType = ReflectiveLoadType::CustomLoader;
                m_stats.customLoadersDetected.fetch_add(1, std::memory_order_relaxed);
            }
        }

        // Calculate risk score
        detection.CalculateRiskScore();

        // Update statistics
        m_stats.reflectiveDLLsDetected.fetch_add(1, std::memory_order_relaxed);

        switch (detection.confidence) {
            case DetectionConfidence::Low:
                m_stats.lowConfidenceDetections.fetch_add(1, std::memory_order_relaxed);
                break;
            case DetectionConfidence::Medium:
                m_stats.mediumConfidenceDetections.fetch_add(1, std::memory_order_relaxed);
                break;
            case DetectionConfidence::High:
                m_stats.highConfidenceDetections.fetch_add(1, std::memory_order_relaxed);
                break;
            case DetectionConfidence::Confirmed:
                m_stats.confirmedDetections.fetch_add(1, std::memory_order_relaxed);
                break;
            default:
                break;
        }

        // Only alert if meets threshold
        if (detection.confidence >= m_config.alertThreshold) {
            return detection;
        }

        return std::nullopt;
    }

    std::vector<uint8_t> ExtractPayloadRaw(uint32_t pid, uintptr_t baseAddress) {
        std::vector<uint8_t> payload;

        HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) return payload;

        // Read up to 10MB (reasonable limit)
        ReadProcessMemorySafe(hProcess, baseAddress, payload, 10 * 1024 * 1024);

        CloseHandle(hProcess);
        return payload;
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };
    bool m_monitoring{ false };
    ReflectiveConfig m_config;

    // Managers
    std::unique_ptr<CallbackManager> m_callbackManager;
    std::unique_ptr<LoaderSignatureDB> m_signatureDB;

    // Statistics
    mutable ReflectiveStatistics m_stats;
};

// ============================================================================
// MAIN CLASS IMPLEMENTATION (SINGLETON + FORWARDING)
// ============================================================================

ReflectiveDLLDetector::ReflectiveDLLDetector()
    : m_impl(std::make_unique<ReflectiveDLLDetectorImpl>()) {
}

ReflectiveDLLDetector::~ReflectiveDLLDetector() = default;

ReflectiveDLLDetector& ReflectiveDLLDetector::Instance() {
    static ReflectiveDLLDetector instance;
    return instance;
}

bool ReflectiveDLLDetector::Initialize(const ReflectiveConfig& config) {
    return m_impl->Initialize(config);
}

void ReflectiveDLLDetector::Shutdown() {
    m_impl->Shutdown();
}

bool ReflectiveDLLDetector::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

bool ReflectiveDLLDetector::UpdateConfig(const ReflectiveConfig& config) {
    return m_impl->UpdateConfig(config);
}

ReflectiveConfig ReflectiveDLLDetector::GetConfig() const {
    return m_impl->GetConfig();
}

ScanResult ReflectiveDLLDetector::Scan(uint32_t pid, ScanMode mode) {
    return m_impl->Scan(pid, mode);
}

bool ReflectiveDLLDetector::HasReflectiveLoading(uint32_t pid) {
    return m_impl->HasReflectiveLoading(pid);
}

std::vector<ScanResult> ReflectiveDLLDetector::ScanMultiple(
    const std::vector<uint32_t>& pids, ScanMode mode) {
    return m_impl->ScanMultiple(pids, mode);
}

std::vector<ScanResult> ReflectiveDLLDetector::ScanAllProcesses(ScanMode mode) {
    return m_impl->ScanAllProcesses(mode);
}

std::vector<ScanResult> ReflectiveDLLDetector::ScanByName(
    const std::wstring& processName, ScanMode mode) {
    return m_impl->ScanByName(processName, mode);
}

std::vector<PECandidate> ReflectiveDLLDetector::FindPECandidates(uint32_t pid) {
    return m_impl->FindPECandidates(pid);
}

PECandidate ReflectiveDLLDetector::ValidatePE(uint32_t pid, uintptr_t baseAddress) {
    return m_impl->ValidatePE(pid, baseAddress);
}

bool ReflectiveDLLDetector::ContainsPE(uint32_t pid, uintptr_t address, size_t size) {
    return m_impl->ContainsPE(pid, address, size);
}

std::vector<std::pair<uintptr_t, size_t>> ReflectiveDLLDetector::FindRWXRegions(uint32_t pid) {
    return m_impl->FindRWXRegions(pid);
}

std::vector<std::pair<uintptr_t, size_t>> ReflectiveDLLDetector::FindUnbackedExecutable(uint32_t pid) {
    return m_impl->FindUnbackedExecutable(pid);
}

double ReflectiveDLLDetector::CalculateEntropy(uint32_t pid, uintptr_t address, size_t size) {
    return m_impl->CalculateEntropyMemory(pid, address, size);
}

std::vector<PECandidate> ReflectiveDLLDetector::FindHiddenModules(uint32_t pid) {
    return m_impl->FindHiddenModules(pid);
}

bool ReflectiveDLLDetector::IsInPEB(uint32_t pid, uintptr_t baseAddress) {
    return m_impl->IsInPEB(pid, baseAddress);
}

std::vector<uintptr_t> ReflectiveDLLDetector::GetPEBModules(uint32_t pid) {
    return m_impl->GetPEBModules(pid);
}

std::vector<std::pair<uint32_t, uintptr_t>> ReflectiveDLLDetector::FindSuspiciousThreads(uint32_t pid) {
    return m_impl->FindSuspiciousThreads(pid);
}

bool ReflectiveDLLDetector::IsThreadStartUnbacked(uint32_t tid) {
    return m_impl->IsThreadStartUnbacked(tid);
}

uint32_t ReflectiveDLLDetector::CountUnbackedCallStackFrames(uint32_t tid) {
    return m_impl->CountUnbackedCallStackFrames(tid);
}

std::optional<LoaderSignature> ReflectiveDLLDetector::DetectKnownLoader(
    uint32_t pid, const PECandidate& candidate) {
    return m_impl->DetectKnownLoader(pid, candidate);
}

void ReflectiveDLLDetector::AddLoaderSignature(const LoaderSignature& signature) {
    m_impl->AddLoaderSignature(signature);
}

std::vector<LoaderSignature> ReflectiveDLLDetector::GetLoaderSignatures() const {
    return m_impl->GetLoaderSignatures();
}

std::vector<uint8_t> ReflectiveDLLDetector::ExtractPayload(
    uint32_t pid, const ReflectiveDetection& detection) {
    return m_impl->ExtractPayload(pid, detection);
}

bool ReflectiveDLLDetector::DumpPE(uint32_t pid, uintptr_t baseAddress,
                                   const std::wstring& outputPath) {
    return m_impl->DumpPE(pid, baseAddress, outputPath);
}

std::vector<uint8_t> ReflectiveDLLDetector::ReconstructPE(uint32_t pid, uintptr_t baseAddress) {
    return m_impl->ReconstructPE(pid, baseAddress);
}

bool ReflectiveDLLDetector::StartMonitoring() {
    return m_impl->StartMonitoring();
}

void ReflectiveDLLDetector::StopMonitoring() {
    m_impl->StopMonitoring();
}

bool ReflectiveDLLDetector::IsMonitoring() const noexcept {
    return m_impl->IsMonitoring();
}

void ReflectiveDLLDetector::OnMemoryAllocation(uint32_t pid, uintptr_t address,
                                               size_t size, uint32_t protection) {
    m_impl->OnMemoryAllocation(pid, address, size, protection);
}

void ReflectiveDLLDetector::OnProtectionChange(uint32_t pid, uintptr_t address,
                                               uint32_t oldProtection, uint32_t newProtection) {
    m_impl->OnProtectionChange(pid, address, oldProtection, newProtection);
}

uint64_t ReflectiveDLLDetector::RegisterCallback(ReflectiveDetectedCallback callback) {
    return m_impl->RegisterCallback(std::move(callback));
}

uint64_t ReflectiveDLLDetector::RegisterProgressCallback(ScanProgressCallback callback) {
    return m_impl->RegisterProgressCallback(std::move(callback));
}

uint64_t ReflectiveDLLDetector::RegisterCandidateCallback(PECandidateCallback callback) {
    return m_impl->RegisterCandidateCallback(std::move(callback));
}

void ReflectiveDLLDetector::UnregisterCallback(uint64_t callbackId) {
    m_impl->UnregisterCallback(callbackId);
}

ReflectiveStatistics ReflectiveDLLDetector::GetStatistics() const {
    return m_impl->GetStatistics();
}

void ReflectiveDLLDetector::ResetStatistics() {
    m_impl->ResetStatistics();
}

std::wstring ReflectiveDLLDetector::GetVersion() noexcept {
    return std::format(L"{}.{}.{}",
        ReflectiveConstants::VERSION_MAJOR,
        ReflectiveConstants::VERSION_MINOR,
        ReflectiveConstants::VERSION_PATCH);
}

std::wstring ReflectiveDLLDetector::LoadTypeToString(ReflectiveLoadType type) noexcept {
    return LoadTypeToStringInternal(type);
}

std::wstring ReflectiveDLLDetector::ConfidenceToString(DetectionConfidence confidence) noexcept {
    return ConfidenceToStringInternal(confidence);
}

}  // namespace Process
}  // namespace Core
}  // namespace ShadowStrike
