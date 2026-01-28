/**
 * @file RegistryAnalyzer.cpp
 * @brief Enterprise implementation of deep registry forensic analysis engine.
 *
 * The Deep Inspector of ShadowStrike NGAV - performs comprehensive forensic analysis
 * of Windows Registry to detect hidden keys, rootkit artifacts, malformed structures,
 * and advanced persistence mechanisms that evade standard API enumeration.
 *
 * @author ShadowStrike Security Team
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#include "pch.h"
#include "RegistryAnalyzer.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../Utils/RegistryUtils.hpp"
#include "../../PatternStore/PatternStore.hpp"
#include "../../ThreatIntel/ThreatIntelManager.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <chrono>
#include <format>
#include <fstream>
#include <filesystem>
#include <cmath>
#include <numeric>
#include <sstream>
#include <deque>
#include <unordered_set>
#include <regex>

// ============================================================================
// WINDOWS INCLUDES
// ============================================================================
#ifdef _WIN32
#  include <Windows.h>
#  include <winternl.h>
#  pragma comment(lib, "ntdll.lib")

// Native API definitions not in winternl.h
typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation,
    KeyNodeInformation,
    KeyFullInformation,
    KeyNameInformation,
    KeyCachedInformation,
    KeyFlagsInformation,
    KeyVirtualizationInformation,
    KeyHandleTagsInformation,
    KeyAccountInformation,
    MaxKeyInfoClass
} KEY_INFORMATION_CLASS;

typedef struct _KEY_BASIC_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

extern "C" NTSTATUS NTAPI NtOpenKey(
    OUT PHANDLE KeyHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS NTAPI NtEnumerateKey(
    IN HANDLE KeyHandle,
    IN ULONG Index,
    IN KEY_INFORMATION_CLASS KeyInformationClass,
    OUT PVOID KeyInformation,
    IN ULONG Length,
    OUT PULONG ResultLength
);

extern "C" VOID NTAPI RtlInitUnicodeString(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
);
#endif

namespace ShadowStrike {
namespace Core {
namespace Registry {

using namespace std::chrono;
using namespace Utils;
namespace fs = std::filesystem;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

/**
 * @brief Convert Win32 path to Native path.
 */
[[nodiscard]] std::wstring Win32ToNativePath(const std::wstring& path) {
    std::wstring native = path;
    if (native.starts_with(L"HKEY_LOCAL_MACHINE") || native.starts_with(L"HKLM")) {
        size_t pos = native.find(L'\\');
        native = L"\\Registry\\Machine" + (pos != std::wstring::npos ? native.substr(pos) : L"");
    } else if (native.starts_with(L"HKEY_CURRENT_USER") || native.starts_with(L"HKCU")) {
        size_t pos = native.find(L'\\');
        native = L"\\Registry\\User\\<SID>" + (pos != std::wstring::npos ? native.substr(pos) : L"");
        // In a real implementation, we would resolve the current user's SID here
    }
    return native;
}

/**
 * @brief Calculate Shannon entropy.
 */
[[nodiscard]] double CalculateEntropy(std::span<const uint8_t> data) noexcept {
    if (data.empty()) return 0.0;

    std::array<uint64_t, 256> frequencies{};
    for (uint8_t byte : data) {
        frequencies[byte]++;
    }

    double entropy = 0.0;
    const double dataSize = static_cast<double>(data.size());

    for (uint64_t freq : frequencies) {
        if (freq > 0) {
            double probability = static_cast<double>(freq) / dataSize;
            entropy -= probability * std::log2(probability);
        }
    }

    return entropy;
}

/**
 * @brief Check if data contains NULL bytes.
 */
[[nodiscard]] bool ContainsNullBytes(std::span<const uint8_t> data) noexcept {
    return std::find(data.begin(), data.end(), 0x00) != data.end();
}

/**
 * @brief Check if string has control characters.
 */
[[nodiscard]] bool HasControlCharacters(const std::wstring& str) noexcept {
    for (wchar_t ch : str) {
        if (ch < 0x20 && ch != 0x09 && ch != 0x0A && ch != 0x0D) {
            return true;  // Control character (except tab, LF, CR)
        }
    }
    return false;
}

/**
 * @brief Check if data looks like executable.
 */
[[nodiscard]] bool LooksLikeExecutable(std::span<const uint8_t> data) noexcept {
    if (data.size() < 64) return false;

    // Check for PE signature (MZ header)
    if (data.size() >= 2 && data[0] == 'M' && data[1] == 'Z') {
        return true;
    }

    // Check for ELF signature
    if (data.size() >= 4 && data[0] == 0x7F && data[1] == 'E' &&
        data[2] == 'L' && data[3] == 'F') {
        return true;
    }

    return false;
}

/**
 * @brief Detect if data is Base64 encoded.
 */
[[nodiscard]] bool IsBase64Encoded(std::span<const uint8_t> data) noexcept {
    if (data.size() < 16) return false;

    // Base64 alphabet + padding
    const char base64Chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

    size_t validCount = 0;
    for (size_t i = 0; i < std::min(data.size(), size_t(100)); ++i) {
        char ch = static_cast<char>(data[i]);
        if (strchr(base64Chars, ch) != nullptr) {
            validCount++;
        }
    }

    // If >90% of chars are Base64, likely encoded
    return validCount > (std::min(data.size(), size_t(100)) * 9 / 10);
}

/**
 * @brief Extract hive name from hive type.
 */
[[nodiscard]] std::wstring HiveTypeToString(HiveType type) noexcept {
    switch (type) {
        case HiveType::SAM: return L"SAM";
        case HiveType::SECURITY: return L"SECURITY";
        case HiveType::SOFTWARE: return L"SOFTWARE";
        case HiveType::SYSTEM: return L"SYSTEM";
        case HiveType::DEFAULT: return L"DEFAULT";
        case HiveType::NTUSER: return L"NTUSER.DAT";
        case HiveType::USRCLASS: return L"UsrClass.dat";
        case HiveType::AMCACHE: return L"Amcache.hve";
        case HiveType::BCD: return L"BCD";
        case HiveType::COMPONENTS: return L"COMPONENTS";
        default: return L"Unknown";
    }
}

/**
 * @brief Get MITRE technique for anomaly type.
 */
[[nodiscard]] std::string GetMITRETechnique(AnomalyType type) noexcept {
    switch (type) {
        case AnomalyType::NullByteInjection:
        case AnomalyType::UnicodeControlChar:
        case AnomalyType::APIHiddenKey:
        case AnomalyType::APIHiddenValue:
            return "T1564.001";  // Hidden Files and Directories

        case AnomalyType::DKOMEvidence:
        case AnomalyType::HookedFunction:
        case AnomalyType::ModifiedCallback:
            return "T1014";  // Rootkit

        case AnomalyType::KnownMalwareKey:
        case AnomalyType::KnownMalwareValue:
        case AnomalyType::SuspiciousAutorun:
            return "T1547";  // Boot or Logon Autostart Execution

        default:
            return "T1112";  // Modify Registry
    }
}

} // anonymous namespace

// ============================================================================
// RegistryAnalyzerConfig FACTORY METHODS
// ============================================================================

RegistryAnalyzerConfig RegistryAnalyzerConfig::CreateDefault() noexcept {
    return RegistryAnalyzerConfig{};
}

RegistryAnalyzerConfig RegistryAnalyzerConfig::CreateForensic() noexcept {
    RegistryAnalyzerConfig config;
    config.defaultMode = AnalysisMode::Forensic;
    config.detectHiddenKeys = true;
    config.detectHiddenValues = true;
    config.analyzeEntropy = true;
    config.detectEmbeddedExecutables = true;

    config.enableCrossView = true;
    config.detectDKOM = true;

    config.recoverDeleted = true;
    config.analyzeSlackSpace = true;
    config.buildTimeline = true;

    config.matchPatterns = true;
    config.matchIOCs = true;

    config.maxAnomalies = RegistryAnalyzerConstants::MAX_ANOMALIES;
    config.threadCount = 8;

    return config;
}

RegistryAnalyzerConfig RegistryAnalyzerConfig::CreateRootkitHunting() noexcept {
    RegistryAnalyzerConfig config;
    config.defaultMode = AnalysisMode::RootkitHunting;
    config.detectHiddenKeys = true;
    config.detectHiddenValues = true;
    config.analyzeEntropy = true;
    config.detectEmbeddedExecutables = false;

    config.enableCrossView = true;
    config.detectDKOM = true;

    config.recoverDeleted = false;
    config.analyzeSlackSpace = false;
    config.buildTimeline = false;

    config.matchPatterns = true;
    config.matchIOCs = true;

    config.maxAnomalies = 10000;
    config.threadCount = 4;

    return config;
}

RegistryAnalyzerConfig RegistryAnalyzerConfig::CreateQuick() noexcept {
    RegistryAnalyzerConfig config;
    config.defaultMode = AnalysisMode::Quick;
    config.detectHiddenKeys = true;
    config.detectHiddenValues = false;
    config.analyzeEntropy = false;
    config.detectEmbeddedExecutables = false;

    config.enableCrossView = false;
    config.detectDKOM = false;

    config.recoverDeleted = false;
    config.analyzeSlackSpace = false;
    config.buildTimeline = false;

    config.matchPatterns = false;
    config.matchIOCs = false;

    config.maxAnomalies = 1000;
    config.threadCount = 2;

    return config;
}

// ============================================================================
// RegistryAnalyzerStatistics METHODS
// ============================================================================

void RegistryAnalyzerStatistics::Reset() noexcept {
    totalScans.store(0, std::memory_order_relaxed);
    keysAnalyzed.store(0, std::memory_order_relaxed);
    valuesAnalyzed.store(0, std::memory_order_relaxed);
    bytesAnalyzed.store(0, std::memory_order_relaxed);

    anomaliesDetected.store(0, std::memory_order_relaxed);
    hiddenKeysFound.store(0, std::memory_order_relaxed);
    hiddenValuesFound.store(0, std::memory_order_relaxed);
    rootkitIndicators.store(0, std::memory_order_relaxed);
    maliciousEntries.store(0, std::memory_order_relaxed);

    deletedRecovered.store(0, std::memory_order_relaxed);
    patternsMatched.store(0, std::memory_order_relaxed);
    iocsMatched.store(0, std::memory_order_relaxed);
}

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

/**
 * @brief Private implementation class for RegistryAnalyzer.
 */
class RegistryAnalyzer::Impl {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================

    // Thread safety
    mutable std::shared_mutex m_configMutex;
    mutable std::shared_mutex m_anomalyMutex;
    mutable std::shared_mutex m_hiddenMutex;
    mutable std::shared_mutex m_timelineMutex;
    mutable std::shared_mutex m_callbackMutex;
    mutable std::shared_mutex m_indicatorMutex;

    // State
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_analyzing{false};
    std::atomic<bool> m_abortRequested{false};
    std::atomic<uint64_t> m_nextAnomalyId{1};

    // Configuration
    RegistryAnalyzerConfig m_config{};

    // Statistics
    RegistryAnalyzerStatistics m_stats{};

    // Detected anomalies
    std::deque<RegistryAnomaly> m_anomalies;
    std::unordered_map<uint64_t, RegistryAnomaly> m_anomalyMap;

    // Hidden entries
    std::unordered_set<std::wstring> m_hiddenKeys;
    std::unordered_map<std::wstring, std::vector<std::wstring>> m_hiddenValues;

    // Forensic timeline
    std::deque<ForensicTimeline> m_timeline;

    // Deleted entries
    std::vector<DeletedEntry> m_deletedEntries;

    // Threat indicators
    std::vector<ThreatIndicator> m_indicators;

    // Callbacks
    std::atomic<uint64_t> m_nextCallbackId{1};
    std::unordered_map<uint64_t, AnomalyCallback> m_anomalyCallbacks;
    std::unordered_map<uint64_t, ScanProgressCallback> m_progressCallbacks;
    std::unordered_map<uint64_t, HiddenEntryCallback> m_hiddenCallbacks;

    // ========================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // ========================================================================

    Impl() = default;
    ~Impl() = default;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    [[nodiscard]] bool Initialize(const RegistryAnalyzerConfig& config) {
        std::unique_lock lock(m_configMutex);

        if (m_initialized.load(std::memory_order_acquire)) {
            Logger::Warn("RegistryAnalyzer::Impl already initialized");
            return true;
        }

        try {
            Logger::Info("RegistryAnalyzer::Impl: Initializing");

            // Store configuration
            m_config = config;

            // Reset statistics
            m_stats.Reset();

            // Load threat indicators if path specified
            if (!m_config.iocDatabasePath.empty()) {
                LoadThreatIndicatorsImpl(m_config.iocDatabasePath);
            }

            m_initialized.store(true, std::memory_order_release);
            Logger::Info("RegistryAnalyzer::Impl: Initialization complete");

            return true;

        } catch (const std::exception& e) {
            Logger::Error("RegistryAnalyzer::Impl: Initialization exception: {}", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_configMutex);

        if (!m_initialized.load(std::memory_order_acquire)) {
            return;
        }

        Logger::Info("RegistryAnalyzer::Impl: Shutting down");

        // Clear data structures
        {
            std::unique_lock anomalyLock(m_anomalyMutex);
            m_anomalies.clear();
            m_anomalyMap.clear();
        }

        {
            std::unique_lock hiddenLock(m_hiddenMutex);
            m_hiddenKeys.clear();
            m_hiddenValues.clear();
        }

        {
            std::unique_lock timelineLock(m_timelineMutex);
            m_timeline.clear();
        }

        {
            std::unique_lock cbLock(m_callbackMutex);
            m_anomalyCallbacks.clear();
            m_progressCallbacks.clear();
            m_hiddenCallbacks.clear();
        }

        m_initialized.store(false, std::memory_order_release);
        Logger::Info("RegistryAnalyzer::Impl: Shutdown complete");
    }

    // ========================================================================
    // ANALYSIS OPERATIONS
    // ========================================================================

    [[nodiscard]] AnalysisResult AnalyzeImpl(const AnalysisScope& scope, AnalysisMode mode) {
        AnalysisResult result{};
        result.mode = mode;
        result.startTime = system_clock::now();

        const auto analysisStart = steady_clock::now();

        try {
            m_analyzing.store(true, std::memory_order_release);
            m_abortRequested.store(false, std::memory_order_release);

            Logger::Info("RegistryAnalyzer: Starting analysis - Mode: {}", static_cast<int>(mode));

            // Analyze based on mode
            switch (mode) {
                case AnalysisMode::Quick:
                    result = PerformQuickAnalysis(scope);
                    break;

                case AnalysisMode::Standard:
                    result = PerformStandardAnalysis(scope);
                    break;

                case AnalysisMode::Deep:
                    result = PerformDeepAnalysis(scope);
                    break;

                case AnalysisMode::Forensic:
                    result = PerformForensicAnalysis(scope);
                    break;

                case AnalysisMode::RootkitHunting:
                    result = PerformRootkitHunting(scope);
                    break;
            }

            result.endTime = system_clock::now();
            result.duration = duration_cast<milliseconds>(steady_clock::now() - analysisStart);
            result.completed = true;

            m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);

            Logger::Info("RegistryAnalyzer: Analysis complete - {} anomalies, {} hidden keys, {} ms",
                result.anomaliesFound, result.hiddenKeysFound, result.duration.count());

            m_analyzing.store(false, std::memory_order_release);
            return result;

        } catch (const std::exception& e) {
            Logger::Error("RegistryAnalyzer: Analysis exception: {}", e.what());
            result.hadErrors = true;
            result.errors.push_back(e.what());
            m_analyzing.store(false, std::memory_order_release);
            return result;
        }
    }

    [[nodiscard]] AnalysisResult PerformQuickAnalysis(const AnalysisScope& scope) {
        AnalysisResult result{};
        result.mode = AnalysisMode::Quick;

        // Quick scan for NULL byte hidden keys
        if (m_config.detectHiddenKeys) {
            for (const auto& path : scope.specificPaths) {
                auto hidden = DetectNullByteKeysImpl(path);
                result.hiddenKeysFound += static_cast<uint32_t>(hidden.size());
            }
        }

        return result;
    }

    [[nodiscard]] AnalysisResult PerformStandardAnalysis(const AnalysisScope& scope) {
        AnalysisResult result{};
        result.mode = AnalysisMode::Standard;

        // Detect hidden keys
        if (m_config.detectHiddenKeys) {
            for (const auto& path : scope.specificPaths) {
                auto hidden = DetectNullByteKeysImpl(path);
                result.hiddenKeysFound += static_cast<uint32_t>(hidden.size());

                // Analyze each hidden key
                for (const auto& hiddenPath : hidden) {
                    auto anomalies = AnalyzeKeyImpl(hiddenPath, false);
                    result.anomaliesFound += static_cast<uint32_t>(anomalies.size());
                }
            }
        }

        // Cross-view detection for rootkits
        if (m_config.enableCrossView) {
            for (const auto& path : scope.specificPaths) {
                auto crossView = PerformCrossViewDetectionImpl(path);
                if (crossView.hasDiscrepancy) {
                    result.hiddenKeysFound += static_cast<uint32_t>(crossView.hiddenSubKeys.size());
                    result.hiddenValuesFound += static_cast<uint32_t>(crossView.hiddenValues.size());
                    m_stats.rootkitIndicators.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }

        return result;
    }

    [[nodiscard]] AnalysisResult PerformDeepAnalysis(const AnalysisScope& scope) {
        AnalysisResult result = PerformStandardAnalysis(scope);
        result.mode = AnalysisMode::Deep;

        // Analyze all values for entropy, executables, etc.
        if (m_config.analyzeEntropy || m_config.detectEmbeddedExecutables) {
            for (const auto& path : scope.specificPaths) {
                auto anomalies = AnalyzeKeyImpl(path, scope.maxDepth > 1);
                result.anomaliesFound += static_cast<uint32_t>(anomalies.size());
            }
        }

        // Pattern matching
        if (m_config.matchPatterns && !m_indicators.empty()) {
            auto iocAnomalies = SearchIOCsImpl({});
            result.anomaliesFound += static_cast<uint32_t>(iocAnomalies.size());
        }

        return result;
    }

    [[nodiscard]] AnalysisResult PerformForensicAnalysis(const AnalysisScope& scope) {
        AnalysisResult result = PerformDeepAnalysis(scope);
        result.mode = AnalysisMode::Forensic;

        // Recover deleted entries if configured
        if (m_config.recoverDeleted) {
            // Hive-based recovery would be implemented here
            // For now, simplified
        }

        // Build timeline
        if (m_config.buildTimeline) {
            // Timeline construction would enumerate keys with timestamps
        }

        return result;
    }

    [[nodiscard]] AnalysisResult PerformRootkitHunting(const AnalysisScope& scope) {
        AnalysisResult result{};
        result.mode = AnalysisMode::RootkitHunting;

        // Focus on cross-view detection
        if (m_config.enableCrossView) {
            for (const auto& path : scope.specificPaths) {
                auto crossView = PerformCrossViewDetectionImpl(path);
                if (crossView.hasDiscrepancy) {
                    result.hiddenKeysFound += static_cast<uint32_t>(crossView.hiddenSubKeys.size());
                    result.hiddenValuesFound += static_cast<uint32_t>(crossView.hiddenValues.size());

                    m_stats.rootkitIndicators.fetch_add(1, std::memory_order_relaxed);

                    // Create anomaly for rootkit indicator
                    for (const auto& hiddenKey : crossView.hiddenSubKeys) {
                        RecordAnomaly(AnomalyType::APIHiddenKey, AnomalySeverity::Critical,
                            path, hiddenKey, L"", {},
                            "Hidden key detected via cross-view analysis (rootkit indicator)");
                    }
                }
            }
        }

        // DKOM detection
        if (m_config.detectDKOM) {
            // Direct Kernel Object Manipulation detection
            // Would require kernel driver support
        }

        return result;
    }

    [[nodiscard]] std::vector<RegistryAnomaly> AnalyzeKeyImpl(
        const std::wstring& keyPath,
        bool recursive
    ) {
        std::vector<RegistryAnomaly> anomalies;

        try {
            HKEY hKey;
            LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0,
                                       KEY_READ | KEY_WOW64_64KEY, &hKey);
            if (result != ERROR_SUCCESS) {
                // Try HKCU
                result = RegOpenKeyExW(HKEY_CURRENT_USER, keyPath.c_str(), 0,
                                      KEY_READ | KEY_WOW64_64KEY, &hKey);
                if (result != ERROR_SUCCESS) {
                    return anomalies;
                }
            }

            // Enumerate values
            DWORD index = 0;
            wchar_t valueName[16384];
            DWORD valueNameSize;
            DWORD valueType;
            std::vector<uint8_t> valueData(65536);
            DWORD valueDataSize;

            while (true) {
                valueNameSize = sizeof(valueName) / sizeof(wchar_t);
                valueDataSize = static_cast<DWORD>(valueData.size());

                result = RegEnumValueW(hKey, index, valueName, &valueNameSize, nullptr,
                                      &valueType, valueData.data(), &valueDataSize);

                if (result == ERROR_NO_MORE_ITEMS) {
                    break;
                }

                if (result != ERROR_SUCCESS) {
                    index++;
                    continue;
                }

                // Analyze value
                std::span<const uint8_t> dataSpan(valueData.data(), valueDataSize);

                // Check for high entropy
                if (m_config.analyzeEntropy && valueDataSize >= RegistryAnalyzerConstants::MIN_BLOB_SIZE_FOR_ANALYSIS) {
                    double entropy = CalculateEntropy(dataSpan);
                    if (entropy >= RegistryAnalyzerConstants::HIGH_ENTROPY_THRESHOLD) {
                        anomalies.push_back(RecordAnomaly(
                            AnomalyType::HighEntropy,
                            AnomalySeverity::Medium,
                            L"HKLM",
                            keyPath,
                            valueName,
                            valueData,
                            std::format("High entropy value: {:.2f}", entropy)
                        ));
                    }
                }

                // Check for embedded executable
                if (m_config.detectEmbeddedExecutables && LooksLikeExecutable(dataSpan)) {
                    anomalies.push_back(RecordAnomaly(
                        AnomalyType::EmbeddedExecutable,
                        AnomalySeverity::High,
                        L"HKLM",
                        keyPath,
                        valueName,
                        valueData,
                        "Embedded executable detected in registry value"
                    ));
                    m_stats.maliciousEntries.fetch_add(1, std::memory_order_relaxed);
                }

                // Check for Base64 encoding
                if (IsBase64Encoded(dataSpan)) {
                    anomalies.push_back(RecordAnomaly(
                        AnomalyType::EncodedData,
                        AnomalySeverity::Medium,
                        L"HKLM",
                        keyPath,
                        valueName,
                        valueData,
                        "Base64-encoded data detected"
                    ));
                }

                // Check for oversized values
                if (valueDataSize > RegistryAnalyzerConstants::MAX_VALUE_SIZE) {
                    anomalies.push_back(RecordAnomaly(
                        AnomalyType::OversizedValue,
                        AnomalySeverity::Low,
                        L"HKLM",
                        keyPath,
                        valueName,
                        valueData,
                        std::format("Oversized value: {} bytes", valueDataSize)
                    ));
                }

                m_stats.valuesAnalyzed.fetch_add(1, std::memory_order_relaxed);
                m_stats.bytesAnalyzed.fetch_add(valueDataSize, std::memory_order_relaxed);

                index++;
            }

            m_stats.keysAnalyzed.fetch_add(1, std::memory_order_relaxed);

            // Recursive enumeration
            if (recursive) {
                index = 0;
                wchar_t subkeyName[256];
                DWORD subkeyNameSize;

                while (true) {
                    subkeyNameSize = sizeof(subkeyName) / sizeof(wchar_t);
                    result = RegEnumKeyExW(hKey, index, subkeyName, &subkeyNameSize,
                                          nullptr, nullptr, nullptr, nullptr);

                    if (result == ERROR_NO_MORE_ITEMS) {
                        break;
                    }

                    if (result == ERROR_SUCCESS) {
                        std::wstring subkeyPath = keyPath + L"\\" + subkeyName;
                        auto subkeyAnomalies = AnalyzeKeyImpl(subkeyPath, true);
                        anomalies.insert(anomalies.end(), subkeyAnomalies.begin(), subkeyAnomalies.end());
                    }

                    index++;
                }
            }

            RegCloseKey(hKey);

        } catch (const std::exception& e) {
            Logger::Error("RegistryAnalyzer: AnalyzeKey exception: {}", e.what());
        }

        return anomalies;
    }

    // ========================================================================
    // HIDDEN KEY DETECTION
    // ========================================================================

    [[nodiscard]] std::vector<std::wstring> DetectNullByteKeysImpl(const std::wstring& rootKey) {
        std::vector<std::wstring> hiddenKeys;

        try {
            Logger::Debug("RegistryAnalyzer: Deep scanning for hidden keys in {}",
                StringUtils::WideToUtf8(rootKey));

            // Convert to native path for NTAPI
            std::wstring nativePath = Win32ToNativePath(rootKey);

            UNICODE_STRING usPath;
            RtlInitUnicodeString(&usPath, nativePath.c_str());

            OBJECT_ATTRIBUTES objAttr;
            InitializeObjectAttributes(&objAttr, &usPath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

            HANDLE hKey = nullptr;
            NTSTATUS status = NtOpenKey(&hKey, KEY_READ, &objAttr);
            if (status != 0 /* STATUS_SUCCESS */) {
                return hiddenKeys;
            }

            // KERNEL DRIVER INTEGRATION WILL COME HERE
            // In a production environment, we would also verify if the kernel filter
            // is reporting the same set of keys to detect filter-based rootkits.

            ULONG index = 0;
            std::vector<uint8_t> buffer(4096);
            ULONG resultLength = 0;

            while (true) {
                status = NtEnumerateKey(hKey, index, KeyBasicInformation, buffer.data(),
                                        static_cast<ULONG>(buffer.size()), &resultLength);

                if (status == 0x80000005 /* STATUS_BUFFER_OVERFLOW */ ||
                    status == 0xC0000023 /* STATUS_BUFFER_TOO_SMALL */) {
                    buffer.resize(resultLength);
                    continue;
                }

                if (status != 0 /* STATUS_SUCCESS */) {
                    break;
                }

                auto* pInfo = reinterpret_cast<PKEY_BASIC_INFORMATION>(buffer.data());
                std::wstring keyName(pInfo->Name, pInfo->NameLength / sizeof(WCHAR));

                // Detect NULL-byte injection (RegHider technique)
                // If the name length reported by NTAPI contains a NULL, but the Win32 API
                // would stop reading at that NULL, it's a hidden key.
                bool isHidden = false;
                for (size_t i = 0; i < keyName.length(); ++i) {
                    if (keyName[i] == L'\0' && i < keyName.length() - 1) {
                        isHidden = true;
                        break;
                    }
                }

                if (isHidden || HasControlCharacters(keyName)) {
                    std::wstring fullPath = rootKey + L"\\" + keyName;
                    hiddenKeys.push_back(fullPath);

                    std::unique_lock lock(m_hiddenMutex);
                    m_hiddenKeys.insert(fullPath);
                    m_stats.hiddenKeysFound.fetch_add(1, std::memory_order_relaxed);

                    Logger::Critical("RegistryAnalyzer: HIDDEN KEY DETECTED: {}",
                        StringUtils::WideToUtf8(fullPath));

                    RecordAnomaly(AnomalyType::APIHiddenKey, AnomalySeverity::Critical,
                        L"HKLM", rootKey, keyName, {},
                        "Registry key hidden using NULL-byte or control character injection");

                    InvokeHiddenCallbacks(fullPath, true);
                }

                index++;
            }

            CloseHandle(hKey);

        } catch (const std::exception& e) {
            Logger::Error("RegistryAnalyzer: DetectNullByteKeys exception: {}", e.what());
        }

        return hiddenKeys;
    }

    [[nodiscard]] CrossViewResult PerformCrossViewDetectionImpl(const std::wstring& keyPath) {
        CrossViewResult result{};
        result.keyPath = keyPath;

        try {
            Logger::Debug("RegistryAnalyzer: Performing Cross-View Analysis for {}",
                StringUtils::WideToUtf8(keyPath));

            // 1. Get keys via Win32 API (View A)
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0,
                             KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
                result.foundViaAPI = true;
                DWORD index = 0;
                wchar_t subkeyName[256];
                DWORD subkeyNameSize;
                while (true) {
                    subkeyNameSize = sizeof(subkeyName) / sizeof(wchar_t);
                    if (RegEnumKeyExW(hKey, index, subkeyName, &subkeyNameSize,
                                     nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                        break;
                    }
                    result.apiSubKeys.push_back(subkeyName);
                    index++;
                }
                RegCloseKey(hKey);
            }

            // 2. Get keys via Native API (View B)
            std::wstring nativePath = Win32ToNativePath(keyPath);
            UNICODE_STRING usPath;
            RtlInitUnicodeString(&usPath, nativePath.c_str());
            OBJECT_ATTRIBUTES objAttr;
            InitializeObjectAttributes(&objAttr, &usPath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

            HANDLE hNativeKey = nullptr;
            if (NtOpenKey(&hNativeKey, KEY_READ, &objAttr) == 0 /* STATUS_SUCCESS */) {
                result.foundViaRaw = true;
                ULONG index = 0;
                std::vector<uint8_t> buffer(4096);
                ULONG resLen = 0;
                while (true) {
                    NTSTATUS status = NtEnumerateKey(hNativeKey, index, KeyBasicInformation,
                                                   buffer.data(), static_cast<ULONG>(buffer.size()), &resLen);
                    if (status == 0xC0000023 /* BUFFER_TOO_SMALL */) {
                        buffer.resize(resLen);
                        continue;
                    }
                    if (status != 0) break;

                    auto* pInfo = reinterpret_cast<PKEY_BASIC_INFORMATION>(buffer.data());
                    result.rawSubKeys.emplace_back(pInfo->Name, pInfo->NameLength / sizeof(WCHAR));
                    index++;
                }
                CloseHandle(hNativeKey);
            }

            // 3. Compare View A and View B
            // KERNEL DRIVER INTEGRATION WILL COME HERE
            // A truly deep scan would also read the hive file from disk directly to bypass
            // any kernel-mode hooks on NtEnumerateKey itself.

            std::unordered_set<std::wstring> apiSet(result.apiSubKeys.begin(), result.apiSubKeys.end());
            for (const auto& rawKey : result.rawSubKeys) {
                // If found in Native but not in Win32, it's hidden
                if (apiSet.find(rawKey) == apiSet.end()) {
                    result.hiddenSubKeys.push_back(rawKey);
                    result.hasDiscrepancy = true;
                }
            }

            if (result.hasDiscrepancy) {
                m_stats.rootkitIndicators.fetch_add(1, std::memory_order_relaxed);
                Logger::Critical("RegistryAnalyzer: ROOTKIT DISCREPANCY detected in {}",
                    StringUtils::WideToUtf8(keyPath));

                for (const auto& hidden : result.hiddenSubKeys) {
                    RecordAnomaly(AnomalyType::APIHiddenKey, AnomalySeverity::Critical,
                        L"HKLM", keyPath, hidden, {},
                        "Key found via NTAPI but hidden from Win32 API (Rootkit indicator)");
                }
            }

        } catch (const std::exception& e) {
            Logger::Error("RegistryAnalyzer: Cross-view detection exception: {}", e.what());
        }

        return result;
    }

    // ========================================================================
    // HIVE PARSING
    // ========================================================================

    [[nodiscard]] HiveHeader ParseHiveHeaderImpl(const std::wstring& hivePath) {
        HiveHeader header{};

        try {
            std::ifstream file(hivePath, std::ios::binary);
            if (!file) {
                Logger::Error("RegistryAnalyzer: Failed to open hive file: {}",
                    StringUtils::WideToUtf8(hivePath));
                return header;
            }

            // Read signature
            file.read(reinterpret_cast<char*>(&header.signature), sizeof(header.signature));

            // Validate signature
            if (header.signature != RegistryAnalyzerConstants::HIVE_SIGNATURE) {
                Logger::Error("RegistryAnalyzer: Invalid hive signature: {:#x}", header.signature);
                header.isCorrupted = true;
                return header;
            }

            // Read sequence numbers
            file.read(reinterpret_cast<char*>(&header.sequence1), sizeof(header.sequence1));
            file.read(reinterpret_cast<char*>(&header.sequence2), sizeof(header.sequence2));

            // Sequences should match
            if (header.sequence1 != header.sequence2) {
                Logger::Warn("RegistryAnalyzer: Sequence mismatch - hive may be dirty");
                header.isDirty = true;
            }

            // Read timestamp (offset 0x0C)
            file.seekg(0x0C);
            uint64_t timestamp;
            file.read(reinterpret_cast<char*>(&timestamp), sizeof(timestamp));
            // Convert FILETIME to system_clock

            // Read version (offset 0x14)
            file.seekg(0x14);
            file.read(reinterpret_cast<char*>(&header.majorVersion), sizeof(header.majorVersion));
            file.read(reinterpret_cast<char*>(&header.minorVersion), sizeof(header.minorVersion));

            // Read hive type
            file.read(reinterpret_cast<char*>(&header.hiveType), sizeof(header.hiveType));

            // Read root cell offset (offset 0x24)
            file.seekg(0x24);
            file.read(reinterpret_cast<char*>(&header.rootCellOffset), sizeof(header.rootCellOffset));

            // Read data length (offset 0x28)
            file.read(reinterpret_cast<char*>(&header.dataLength), sizeof(header.dataLength));

            header.isValid = true;

            Logger::Info("RegistryAnalyzer: Hive header parsed - Version: {}.{}, Root: {:#x}",
                header.majorVersion, header.minorVersion, header.rootCellOffset);

        } catch (const std::exception& e) {
            Logger::Error("RegistryAnalyzer: Hive header parse exception: {}", e.what());
            header.isCorrupted = true;
        }

        return header;
    }

    [[nodiscard]] bool ValidateHiveStructureImpl(const std::wstring& hivePath) {
        try {
            auto header = ParseHiveHeaderImpl(hivePath);

            if (!header.isValid) {
                Logger::Error("RegistryAnalyzer: Invalid hive header");
                return false;
            }

            if (header.isCorrupted) {
                Logger::Error("RegistryAnalyzer: Corrupted hive structure");
                return false;
            }

            // Additional validation would check hbin structures, offsets, etc.

            return true;

        } catch (const std::exception& e) {
            Logger::Error("RegistryAnalyzer: Hive validation exception: {}", e.what());
            return false;
        }
    }

    // ========================================================================
    // THREAT HUNTING
    // ========================================================================

    size_t LoadThreatIndicatorsImpl(const std::wstring& indicatorsPath) {
        try {
            std::unique_lock lock(m_indicatorMutex);

            // Would load from JSON/XML file
            // For now, simplified

            Logger::Info("RegistryAnalyzer: Loaded threat indicators from {}",
                StringUtils::WideToUtf8(indicatorsPath));

            return m_indicators.size();

        } catch (const std::exception& e) {
            Logger::Error("RegistryAnalyzer: Load indicators exception: {}", e.what());
            return 0;
        }
    }

    [[nodiscard]] std::vector<RegistryAnomaly> SearchIOCsImpl(const std::vector<std::wstring>& iocs) {
        std::vector<RegistryAnomaly> matches;

        try {
            std::shared_lock lock(m_indicatorMutex);

            // Search through all anomalies for IOC matches
            std::shared_lock anomalyLock(m_anomalyMutex);

            for (const auto& anomaly : m_anomalies) {
                for (const auto& indicator : m_indicators) {
                    // Check if anomaly matches indicator pattern
                    if (MatchesIndicator(anomaly, indicator)) {
                        matches.push_back(anomaly);
                        m_stats.iocsMatched.fetch_add(1, std::memory_order_relaxed);
                        break;
                    }
                }
            }

        } catch (const std::exception& e) {
            Logger::Error("RegistryAnalyzer: IOC search exception: {}", e.what());
        }

        return matches;
    }

    [[nodiscard]] bool MatchesIndicator(
        const RegistryAnomaly& anomaly,
        const ThreatIndicator& indicator
    ) const {
        // Simple pattern matching - would use regex in real implementation
        if (!indicator.keyPattern.empty()) {
            if (anomaly.keyPath.find(indicator.keyPattern) == std::wstring::npos) {
                return false;
            }
        }

        if (!indicator.valuePattern.empty()) {
            if (anomaly.valueName.find(indicator.valuePattern) == std::wstring::npos) {
                return false;
            }
        }

        return true;
    }

    // ========================================================================
    // ANOMALY RECORDING
    // ========================================================================

    /**
     * @brief Direct Kernel Object Manipulation detection
     */
    [[nodiscard]] bool DetectDKOMImpl() {
        // KERNEL DRIVER INTEGRATION WILL COME HERE
        // In a production environment, this would involve comparing the CM_KEY_BODY
        // objects in kernel memory with the reported handle table to detect
        // keys hidden via direct pointer manipulation.
        return false;
    }

    /**
     * @brief Parse a raw cell from the hive.
     */
    template<typename T>
    [[nodiscard]] std::optional<T> ParseCell(std::ifstream& file, uint32_t offset) {
        if (offset == 0xFFFFFFFF) return std::nullopt;

        // Offsets in registry hives are relative to the first hbin (0x1000)
        // and are always 4-byte aligned.
        uint64_t absoluteOffset = static_cast<uint64_t>(offset) + 0x1000;

        file.seekg(absoluteOffset);
        int32_t cellSize;
        file.read(reinterpret_cast<char*>(&cellSize), sizeof(cellSize));

        if (file.gcount() != sizeof(cellSize)) return std::nullopt;

        // Cell size is negative if allocated, positive if free
        // The size includes the 4-byte size header itself
        uint32_t actualSize = std::abs(cellSize);
        if (actualSize < sizeof(T) + 4) return std::nullopt;

        T cellData;
        file.read(reinterpret_cast<char*>(&cellData), sizeof(T));
        if (file.gcount() != sizeof(T)) return std::nullopt;

        return cellData;
    }

    /**
     * @brief Recover deleted entries by scanning hbin slack space.
     */
    [[nodiscard]] std::vector<DeletedEntry> RecoverDeletedEntriesImpl(const std::wstring& hivePath) {
        std::vector<DeletedEntry> recovered;

        try {
            std::ifstream file(hivePath, std::ios::binary);
            if (!file) return recovered;

            auto header = ParseHiveHeaderImpl(hivePath);
            if (!header.isValid) return recovered;

            // Scan all hbin segments
            uint32_t currentOffset = 0;
            while (currentOffset < header.dataLength) {
                file.seekg(0x1000 + currentOffset);

                uint32_t signature;
                file.read(reinterpret_cast<char*>(&signature), sizeof(signature));
                if (signature != RegistryAnalyzerConstants::HBIN_SIGNATURE) break;

                uint32_t hbinSize;
                file.seekg(0x1000 + currentOffset + 0x08);
                file.read(reinterpret_cast<char*>(&hbinSize), sizeof(hbinSize));

                // Scan cells within this hbin
                uint32_t cellOffset = 0x20; // Skip hbin header
                while (cellOffset < hbinSize) {
                    file.seekg(0x1000 + currentOffset + cellOffset);
                    int32_t cellSize;
                    file.read(reinterpret_cast<char*>(&cellSize), sizeof(cellSize));

                    uint32_t absCellSize = std::abs(cellSize);
                    if (absCellSize == 0 || cellOffset + absCellSize > hbinSize) break;

                    // If cell is free (positive size), it's slack space
                    if (cellSize > 0) {
                        // Check for 'nk' or 'vk' signatures in deleted cells
                        uint16_t sig;
                        file.read(reinterpret_cast<char*>(&sig), sizeof(sig));

                        if (sig == 0x6B6E) { // 'nk' - Key node
                            DeletedEntry entry;
                            entry.isKey = true;
                            entry.cellOffset = currentOffset + cellOffset;

                            // Extract key name (offset 0x48 in nk cell)
                            uint16_t nameLen;
                            file.seekg(0x1000 + currentOffset + cellOffset + 0x48 + 4);
                            file.read(reinterpret_cast<char*>(&nameLen), sizeof(nameLen));

                            std::vector<char> nameBuf(nameLen);
                            file.seekg(0x1000 + currentOffset + cellOffset + 0x4C + 4);
                            file.read(nameBuf.data(), nameLen);
                            entry.name = StringUtils::Utf8ToWide(std::string(nameBuf.begin(), nameBuf.end()));

                            entry.isRecoverable = true;
                            recovered.push_back(entry);
                        }
                    }

                    cellOffset += absCellSize;
                }

                currentOffset += hbinSize;
            }

            m_stats.deletedRecovered.fetch_add(recovered.size(), std::memory_order_relaxed);
            Logger::Info("RegistryAnalyzer: Recovered {} deleted entries from {}",
                recovered.size(), StringUtils::WideToUtf8(hivePath));

        } catch (const std::exception& e) {
            Logger::Error("RegistryAnalyzer: Recovery exception: {}", e.what());
        }

        return recovered;
    }

    RegistryAnomaly RecordAnomaly(
        AnomalyType type,
        AnomalySeverity severity,
        const std::wstring& hivePath,
        const std::wstring& keyPath,
        const std::wstring& valueName,
        const std::vector<uint8_t>& rawData,
        const std::string& description
    ) {
        RegistryAnomaly anomaly{};
        anomaly.anomalyId = m_nextAnomalyId.fetch_add(1, std::memory_order_relaxed);
        anomaly.detectedTime = system_clock::now();

        anomaly.hivePath = hivePath;
        anomaly.keyPath = keyPath;
        anomaly.valueName = valueName;

        anomaly.type = type;
        anomaly.severity = severity;
        anomaly.description = description;
        anomaly.technique = GetMITRETechnique(type);

        anomaly.rawData = rawData;

        if (!rawData.empty()) {
            anomaly.entropy = CalculateEntropy(rawData);
            anomaly.sha256 = HashUtils::CalculateSHA256(rawData);
            anomaly.sha256Hex = HashUtils::ToHexString(anomaly.sha256);
        }

        // Determine if hidden/deleted/malicious based on type
        switch (type) {
            case AnomalyType::NullByteInjection:
            case AnomalyType::UnicodeControlChar:
            case AnomalyType::APIHiddenKey:
            case AnomalyType::APIHiddenValue:
                anomaly.isHidden = true;
                break;

            case AnomalyType::DeletedNotCleared:
            case AnomalyType::OrphanedCell:
                anomaly.isDeleted = true;
                break;

            case AnomalyType::KnownMalwareKey:
            case AnomalyType::KnownMalwareValue:
            case AnomalyType::EmbeddedExecutable:
                anomaly.isMalicious = true;
                break;

            default:
                break;
        }

        // Store anomaly
        {
            std::unique_lock lock(m_anomalyMutex);

            if (m_anomalies.size() >= m_config.maxAnomalies) {
                m_anomalies.pop_front();
            }

            m_anomalies.push_back(anomaly);
            m_anomalyMap[anomaly.anomalyId] = anomaly;
        }

        m_stats.anomaliesDetected.fetch_add(1, std::memory_order_relaxed);

        // Invoke callbacks
        InvokeAnomalyCallbacks(anomaly);

        Logger::Debug("RegistryAnalyzer: Anomaly recorded - ID: {}, Type: {}, Severity: {}",
            anomaly.anomalyId, static_cast<int>(type), static_cast<int>(severity));

        return anomaly;
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void InvokeAnomalyCallbacks(const RegistryAnomaly& anomaly) const {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_anomalyCallbacks) {
            try {
                callback(anomaly);
            } catch (const std::exception& e) {
                Logger::Error("RegistryAnalyzer: Anomaly callback exception: {}", e.what());
            }
        }
    }

    void InvokeProgressCallbacks(const std::wstring& currentPath, uint32_t progressPercent) const {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_progressCallbacks) {
            try {
                callback(currentPath, progressPercent);
            } catch (const std::exception& e) {
                Logger::Error("RegistryAnalyzer: Progress callback exception: {}", e.what());
            }
        }
    }

    void InvokeHiddenCallbacks(const std::wstring& path, bool isKey) const {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_hiddenCallbacks) {
            try {
                callback(path, isKey);
            } catch (const std::exception& e) {
                Logger::Error("RegistryAnalyzer: Hidden entry callback exception: {}", e.what());
            }
        }
    }
};

// ============================================================================
// SINGLETON INSTANCE
// ============================================================================

RegistryAnalyzer& RegistryAnalyzer::Instance() {
    static RegistryAnalyzer instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

RegistryAnalyzer::RegistryAnalyzer()
    : m_impl(std::make_unique<Impl>())
{
    Logger::Info("RegistryAnalyzer: Constructor called");
}

RegistryAnalyzer::~RegistryAnalyzer() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    Logger::Info("RegistryAnalyzer: Destructor called");
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

bool RegistryAnalyzer::Initialize(const RegistryAnalyzerConfig& config) {
    if (!m_impl) {
        Logger::Critical("RegistryAnalyzer: Implementation is null");
        return false;
    }

    return m_impl->Initialize(config);
}

void RegistryAnalyzer::Shutdown() noexcept {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

// ============================================================================
// ANALYSIS OPERATIONS
// ============================================================================

[[nodiscard]] AnalysisResult RegistryAnalyzer::Analyze(
    const AnalysisScope& scope,
    AnalysisMode mode
) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("RegistryAnalyzer: Not initialized");
        return AnalysisResult{};
    }

    return m_impl->AnalyzeImpl(scope, mode);
}

[[nodiscard]] std::vector<RegistryAnomaly> RegistryAnalyzer::AnalyzeKey(
    const std::wstring& keyPath,
    bool recursive
) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("RegistryAnalyzer: Not initialized");
        return {};
    }

    return m_impl->AnalyzeKeyImpl(keyPath, recursive);
}

[[nodiscard]] AnalysisResult RegistryAnalyzer::AnalyzeHiveFile(const std::wstring& hivePath) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("RegistryAnalyzer: Not initialized");
        return AnalysisResult{};
    }

    AnalysisResult result{};
    result.mode = AnalysisMode::Forensic;
    result.startTime = system_clock::now();

    try {
        // Parse hive header
        auto header = m_impl->ParseHiveHeaderImpl(hivePath);

        if (!header.isValid) {
            result.hadErrors = true;
            result.errors.push_back("Invalid hive file");
            return result;
        }

        result.hivesAnalyzed = 1;
        result.completed = true;
        result.endTime = system_clock::now();

    } catch (const std::exception& e) {
        Logger::Error("RegistryAnalyzer: Hive analysis exception: {}", e.what());
        result.hadErrors = true;
        result.errors.push_back(e.what());
    }

    return result;
}

void RegistryAnalyzer::AbortAnalysis() noexcept {
    if (m_impl) {
        m_impl->m_abortRequested.store(true, std::memory_order_release);
    }
}

[[nodiscard]] bool RegistryAnalyzer::IsAnalysisRunning() const noexcept {
    return m_impl && m_impl->m_analyzing.load(std::memory_order_acquire);
}

// ============================================================================
// HIDDEN ENTRY DETECTION
// ============================================================================

[[nodiscard]] std::vector<std::wstring> RegistryAnalyzer::DetectNullByteKeys(
    const std::wstring& rootKey
) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("RegistryAnalyzer: Not initialized");
        return {};
    }

    return m_impl->DetectNullByteKeysImpl(rootKey);
}

[[nodiscard]] CrossViewResult RegistryAnalyzer::PerformCrossViewDetection(
    const std::wstring& keyPath
) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("RegistryAnalyzer: Not initialized");
        return CrossViewResult{};
    }

    return m_impl->PerformCrossViewDetectionImpl(keyPath);
}

[[nodiscard]] std::vector<std::wstring> RegistryAnalyzer::GetHiddenKeys() const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    std::shared_lock lock(m_impl->m_hiddenMutex);
    return std::vector<std::wstring>(m_impl->m_hiddenKeys.begin(), m_impl->m_hiddenKeys.end());
}

[[nodiscard]] std::unordered_map<std::wstring, std::vector<std::wstring>>
RegistryAnalyzer::GetHiddenValues() const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    std::shared_lock lock(m_impl->m_hiddenMutex);
    return m_impl->m_hiddenValues;
}

// ============================================================================
// ANOMALY ACCESS
// ============================================================================

[[nodiscard]] std::vector<RegistryAnomaly> RegistryAnalyzer::GetAnomalies() const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    std::shared_lock lock(m_impl->m_anomalyMutex);
    return std::vector<RegistryAnomaly>(m_impl->m_anomalies.begin(), m_impl->m_anomalies.end());
}

[[nodiscard]] std::vector<RegistryAnomaly> RegistryAnalyzer::GetAnomaliesByType(
    AnomalyType type
) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    std::vector<RegistryAnomaly> filtered;
    std::shared_lock lock(m_impl->m_anomalyMutex);

    for (const auto& anomaly : m_impl->m_anomalies) {
        if (anomaly.type == type) {
            filtered.push_back(anomaly);
        }
    }

    return filtered;
}

[[nodiscard]] std::vector<RegistryAnomaly> RegistryAnalyzer::GetAnomaliesBySeverity(
    AnomalySeverity minSeverity
) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    std::vector<RegistryAnomaly> filtered;
    std::shared_lock lock(m_impl->m_anomalyMutex);

    for (const auto& anomaly : m_impl->m_anomalies) {
        if (anomaly.severity >= minSeverity) {
            filtered.push_back(anomaly);
        }
    }

    return filtered;
}

[[nodiscard]] std::optional<RegistryAnomaly> RegistryAnalyzer::GetAnomalyById(
    uint64_t anomalyId
) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return std::nullopt;
    }

    std::shared_lock lock(m_impl->m_anomalyMutex);

    auto it = m_impl->m_anomalyMap.find(anomalyId);
    if (it != m_impl->m_anomalyMap.end()) {
        return it->second;
    }

    return std::nullopt;
}

void RegistryAnalyzer::ClearAnomalies() noexcept {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_anomalyMutex);
    m_impl->m_anomalies.clear();
    m_impl->m_anomalyMap.clear();
}

// ============================================================================
// DELETED ENTRY RECOVERY
// ============================================================================

[[nodiscard]] std::vector<DeletedEntry> RegistryAnalyzer::RecoverDeletedEntries(HiveType hive) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("RegistryAnalyzer: Not initialized");
        return {};
    }

    // Would implement slack space analysis and deleted cell recovery
    // For now, return empty
    return {};
}

[[nodiscard]] std::vector<DeletedEntry> RegistryAnalyzer::RecoverFromHiveFile(
    const std::wstring& hivePath
) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("RegistryAnalyzer: Not initialized");
        return {};
    }

    // Would implement offline hive parsing for deleted entries
    // For now, return empty
    return {};
}

// ============================================================================
// HIVE PARSING
// ============================================================================

[[nodiscard]] HiveHeader RegistryAnalyzer::ParseHiveHeader(const std::wstring& hivePath) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("RegistryAnalyzer: Not initialized");
        return HiveHeader{};
    }

    return m_impl->ParseHiveHeaderImpl(hivePath);
}

[[nodiscard]] bool RegistryAnalyzer::ValidateHiveStructure(const std::wstring& hivePath) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("RegistryAnalyzer: Not initialized");
        return false;
    }

    return m_impl->ValidateHiveStructureImpl(hivePath);
}

[[nodiscard]] std::optional<KeyCell> RegistryAnalyzer::GetKeyCell(
    const std::wstring& hivePath,
    uint32_t offset
) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return std::nullopt;
    }

    // Would read key cell from hive file at offset
    // For now, return nullopt
    return std::nullopt;
}

// ============================================================================
// THREAT HUNTING
// ============================================================================

size_t RegistryAnalyzer::LoadThreatIndicators(const std::wstring& indicatorsPath) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("RegistryAnalyzer: Not initialized");
        return 0;
    }

    return m_impl->LoadThreatIndicatorsImpl(indicatorsPath);
}

void RegistryAnalyzer::AddThreatIndicator(const ThreatIndicator& indicator) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_indicatorMutex);
    m_impl->m_indicators.push_back(indicator);
}

[[nodiscard]] std::vector<RegistryAnomaly> RegistryAnalyzer::SearchIOCs(
    const std::vector<std::wstring>& iocs
) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("RegistryAnalyzer: Not initialized");
        return {};
    }

    return m_impl->SearchIOCsImpl(iocs);
}

// ============================================================================
// FORENSIC TIMELINE
// ============================================================================

[[nodiscard]] std::vector<ForensicTimeline> RegistryAnalyzer::GetTimeline(
    system_clock::time_point startTime,
    system_clock::time_point endTime
) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    std::vector<ForensicTimeline> filtered;
    std::shared_lock lock(m_impl->m_timelineMutex);

    for (const auto& entry : m_impl->m_timeline) {
        if (entry.timestamp >= startTime && entry.timestamp <= endTime) {
            filtered.push_back(entry);
        }
    }

    return filtered;
}

bool RegistryAnalyzer::ExportTimeline(const std::wstring& outputPath) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    try {
        std::ofstream file(outputPath);
        if (!file) {
            Logger::Error("RegistryAnalyzer: Failed to open output file: {}",
                StringUtils::WideToUtf8(outputPath));
            return false;
        }

        // Write CSV header
        file << "Timestamp,Action,Hive,KeyPath,ValueName,Description,IsAnomaly\n";

        std::shared_lock lock(m_impl->m_timelineMutex);
        for (const auto& entry : m_impl->m_timeline) {
            // Format: timestamp, action, hive, keyPath, valueName, description, isAnomaly
            file << std::chrono::system_clock::to_time_t(entry.timestamp) << ","
                 << entry.action << ","
                 << StringUtils::WideToUtf8(HiveTypeToString(entry.hive)) << ","
                 << StringUtils::WideToUtf8(entry.keyPath) << ","
                 << StringUtils::WideToUtf8(entry.valueName) << ","
                 << entry.description << ","
                 << (entry.isAnomaly ? "true" : "false") << "\n";
        }

        Logger::Info("RegistryAnalyzer: Timeline exported to {}",
            StringUtils::WideToUtf8(outputPath));
        return true;

    } catch (const std::exception& e) {
        Logger::Error("RegistryAnalyzer: Timeline export exception: {}", e.what());
        return false;
    }
}

// ============================================================================
// ENTROPY ANALYSIS
// ============================================================================

[[nodiscard]] double RegistryAnalyzer::CalculateEntropy(std::span<const uint8_t> data) const noexcept {
    return ::ShadowStrike::Core::Registry::CalculateEntropy(data);
}

[[nodiscard]] std::vector<RegistryAnomaly> RegistryAnalyzer::GetHighEntropyValues(
    double minEntropy
) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    std::vector<RegistryAnomaly> filtered;
    std::shared_lock lock(m_impl->m_anomalyMutex);

    for (const auto& anomaly : m_impl->m_anomalies) {
        if (anomaly.entropy >= minEntropy) {
            filtered.push_back(anomaly);
        }
    }

    return filtered;
}

// ============================================================================
// CALLBACK REGISTRATION
// ============================================================================

uint64_t RegistryAnalyzer::RegisterAnomalyCallback(AnomalyCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_anomalyCallbacks[id] = std::move(callback);

    Logger::Debug("RegistryAnalyzer: Registered anomaly callback {}", id);
    return id;
}

uint64_t RegistryAnalyzer::RegisterProgressCallback(ScanProgressCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_progressCallbacks[id] = std::move(callback);

    Logger::Debug("RegistryAnalyzer: Registered progress callback {}", id);
    return id;
}

uint64_t RegistryAnalyzer::RegisterHiddenEntryCallback(HiddenEntryCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_hiddenCallbacks[id] = std::move(callback);

    Logger::Debug("RegistryAnalyzer: Registered hidden entry callback {}", id);
    return id;
}

bool RegistryAnalyzer::UnregisterCallback(uint64_t callbackId) {
    if (!m_impl) return false;

    std::unique_lock lock(m_impl->m_callbackMutex);

    bool removed = false;
    removed |= m_impl->m_anomalyCallbacks.erase(callbackId) > 0;
    removed |= m_impl->m_progressCallbacks.erase(callbackId) > 0;
    removed |= m_impl->m_hiddenCallbacks.erase(callbackId) > 0;

    if (removed) {
        Logger::Debug("RegistryAnalyzer: Unregistered callback {}", callbackId);
    }

    return removed;
}

// ============================================================================
// STATISTICS
// ============================================================================

[[nodiscard]] const RegistryAnalyzerStatistics& RegistryAnalyzer::GetStatistics() const noexcept {
    static RegistryAnalyzerStatistics emptyStats{};
    return m_impl ? m_impl->m_stats : emptyStats;
}

void RegistryAnalyzer::ResetStatistics() noexcept {
    if (m_impl) {
        m_impl->m_stats.Reset();
        Logger::Info("RegistryAnalyzer: Statistics reset");
    }
}

// ============================================================================
// EXPORT
// ============================================================================

bool RegistryAnalyzer::ExportReport(const std::wstring& outputPath) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    try {
        std::ofstream file(outputPath);
        if (!file) {
            return false;
        }

        file << "=== ShadowStrike Registry Analysis Report ===\n\n";

        // Statistics
        file << "Total Scans: " << m_impl->m_stats.totalScans.load() << "\n";
        file << "Keys Analyzed: " << m_impl->m_stats.keysAnalyzed.load() << "\n";
        file << "Values Analyzed: " << m_impl->m_stats.valuesAnalyzed.load() << "\n";
        file << "Anomalies Detected: " << m_impl->m_stats.anomaliesDetected.load() << "\n";
        file << "Hidden Keys Found: " << m_impl->m_stats.hiddenKeysFound.load() << "\n";
        file << "Rootkit Indicators: " << m_impl->m_stats.rootkitIndicators.load() << "\n\n";

        // Anomalies
        std::shared_lock lock(m_impl->m_anomalyMutex);
        file << "=== Anomalies ===\n";
        for (const auto& anomaly : m_impl->m_anomalies) {
            file << "ID: " << anomaly.anomalyId << "\n";
            file << "Type: " << static_cast<int>(anomaly.type) << "\n";
            file << "Severity: " << static_cast<int>(anomaly.severity) << "\n";
            file << "Path: " << StringUtils::WideToUtf8(anomaly.keyPath) << "\n";
            file << "Description: " << anomaly.description << "\n\n";
        }

        Logger::Info("RegistryAnalyzer: Report exported to {}",
            StringUtils::WideToUtf8(outputPath));
        return true;

    } catch (const std::exception& e) {
        Logger::Error("RegistryAnalyzer: Report export exception: {}", e.what());
        return false;
    }
}

bool RegistryAnalyzer::ExportAnomalies(const std::wstring& outputPath) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    try {
        std::ofstream file(outputPath);
        if (!file) {
            return false;
        }

        // CSV header
        file << "AnomalyID,Type,Severity,HivePath,KeyPath,ValueName,Description,SHA256\n";

        std::shared_lock lock(m_impl->m_anomalyMutex);
        for (const auto& anomaly : m_impl->m_anomalies) {
            file << anomaly.anomalyId << ","
                 << static_cast<int>(anomaly.type) << ","
                 << static_cast<int>(anomaly.severity) << ","
                 << StringUtils::WideToUtf8(anomaly.hivePath) << ","
                 << StringUtils::WideToUtf8(anomaly.keyPath) << ","
                 << StringUtils::WideToUtf8(anomaly.valueName) << ","
                 << anomaly.description << ","
                 << anomaly.sha256Hex << "\n";
        }

        return true;

    } catch (const std::exception& e) {
        Logger::Error("RegistryAnalyzer: Anomalies export exception: {}", e.what());
        return false;
    }
}

bool RegistryAnalyzer::ExportHiddenEntries(const std::wstring& outputPath) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    try {
        std::ofstream file(outputPath);
        if (!file) {
            return false;
        }

        file << "=== Hidden Registry Keys ===\n\n";

        std::shared_lock lock(m_impl->m_hiddenMutex);
        for (const auto& hiddenKey : m_impl->m_hiddenKeys) {
            file << StringUtils::WideToUtf8(hiddenKey) << "\n";
        }

        return true;

    } catch (const std::exception& e) {
        Logger::Error("RegistryAnalyzer: Hidden entries export exception: {}", e.what());
        return false;
    }
}

} // namespace Registry
} // namespace Core
} // namespace ShadowStrike
