/**
 * @file TimeBasedEvasionDetector.cpp
 * @brief Enterprise implementation of timing-based sandbox/analysis evasion detection.
 *
 * Detects malware techniques: RDTSC abuse, sleep bombing, timing API checks,
 * NTP evasion, hardware timer abuse, and side-channel timing attacks.
 *
 * @author ShadowStrike Security Team
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */
#include "pch.h"
#include "TimeBasedEvasionDetector.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/ThreadPool.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../Utils/NetworkUtils.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <chrono>
#include <cmath>
#include <format>
#include <map>
#include <numeric>
#include <unordered_set>

#ifdef _WIN32
#  include <intrin.h>
#  include <winternl.h>
#  include <Psapi.h>
#  pragma comment(lib, "ntdll.lib")
#  pragma comment(lib, "psapi.lib")
#endif

namespace ShadowStrike {
    namespace AntiEvasion {

        using namespace std::chrono;
        using namespace Utils;

        // ====================================================================
        // IMPLEMENTATION STRUCTURES
        // ====================================================================

        /**
         * @brief Cache entry for analysis results with TTL.
         */
        struct CacheEntry {
            TimingEvasionResult result{};
            steady_clock::time_point cacheTime{};

            [[nodiscard]] bool IsExpired(milliseconds ttl) const noexcept {
                return (steady_clock::now() - cacheTime) > ttl;
            }
        };

        /**
         * @brief Process monitoring state.
         */
        struct ProcessMonitorState {
            uint32_t processId = 0;
            MonitoringState state = MonitoringState::Inactive;
            steady_clock::time_point startTime{};
            steady_clock::time_point lastTickTime{};
            std::vector<TimingEventRecord> eventHistory;

            // Timing baselines for anomaly detection
            uint64_t baselineTickCount = 0;
            uint64_t baselineQPC = 0;
            steady_clock::time_point baselineTime{};
        };

        /**
         * @brief RDTSC tracking data for a process.
         */
        struct RDTSCTracker {
            uint64_t callCount = 0;
            uint64_t lastValue = 0;
            std::vector<uint64_t> deltas;
            steady_clock::time_point firstCall{};
            steady_clock::time_point lastCall{};
        };

        /**
         * @brief Sleep call tracking.
         */
        struct SleepTracker {
            uint32_t callCount = 0;
            uint64_t totalRequestedMs = 0;
            uint64_t totalActualMs = 0;
            std::vector<uint64_t> durations;
            std::vector<steady_clock::time_point> timestamps;
        };

        // ====================================================================
        // PIMPL IMPLEMENTATION
        // ====================================================================

        /**
         * @brief Private implementation (PIMPL pattern for ABI stability).
         */
        class TimeBasedEvasionDetector::Impl {
        public:
            // Thread safety
            mutable std::shared_mutex m_mutex;

            // Initialization state
            std::atomic<bool> m_initialized{ false };

            // Configuration
            TimingDetectorConfig m_config{};

            // Thread pool for async operations
            std::shared_ptr<Utils::ThreadPool> m_threadPool;

            // Pattern store for timing patterns
            std::shared_ptr<PatternStore::PatternStore> m_patternStore;

            // Statistics
            TimingDetectorStats m_stats{};

            // Result cache (process ID -> cache entry)
            std::unordered_map<uint32_t, CacheEntry> m_resultCache;

            // Monitored processes
            std::unordered_map<uint32_t, ProcessMonitorState> m_monitoredProcesses;

            // RDTSC tracking per process
            std::unordered_map<uint32_t, RDTSCTracker> m_rdtscTrackers;

            // Sleep tracking per process
            std::unordered_map<uint32_t, SleepTracker> m_sleepTrackers;

            // Callbacks
            std::atomic<uint64_t> m_nextCallbackId{ 1 };
            std::map<uint64_t, TimingEvasionCallback> m_callbacks;
            std::map<uint64_t, TimingEventCallback> m_eventCallbacks;

            // Monitoring control
            std::atomic<bool> m_shutdownRequested{ false };

            // System timing baseline (captured at init)
            uint64_t m_systemQPCFrequency = 0;
            steady_clock::time_point m_initTime{};

            /**
             * @brief Constructor.
             */
            Impl() = default;

            /**
             * @brief Destructor.
             */
            ~Impl() = default;

            /**
             * @brief Initialize implementation.
             */
            [[nodiscard]] bool Initialize(
                std::shared_ptr<Utils::ThreadPool> threadPool,
                const TimingDetectorConfig& config
            ) {
                std::unique_lock lock(m_mutex);

                if (m_initialized.load(std::memory_order_acquire)) {
                    SS_LOG_WARN(L"AntiEvasion", L"TimeBasedEvasionDetector already initialized");
                    return true;
                }

                try {
                    // Validate thread pool
                    if (!threadPool) {
                        SS_LOG_ERROR(L"AntiEvasion", L"TimeBasedEvasionDetector: Null thread pool");
                        return false;
                    }
                    m_threadPool = threadPool;

                    // Store configuration
                    m_config = config;

                    // Initialize pattern store for timing patterns
                    m_patternStore = std::make_shared<PatternStore::PatternStore>();

                    // Capture system timing baselines
                    m_initTime = steady_clock::now();

#ifdef _WIN32
                    LARGE_INTEGER freq{};
                    if (QueryPerformanceFrequency(&freq)) {
                        m_systemQPCFrequency = static_cast<uint64_t>(freq.QuadPart);
                    }
#endif

                    // Reset statistics
                    m_stats.Reset();

                    m_initialized.store(true, std::memory_order_release);
                    SS_LOG_INFO(L"AntiEvasion", L"TimeBasedEvasionDetector initialized successfully");
                    return true;

                } catch (const std::exception& e) {
                    SS_LOG_ERROR(L"AntiEvasion", L"TimeBasedEvasionDetector initialization failed: %hs", e.what());
                    return false;
                }
            }

            /**
             * @brief Shutdown implementation.
             */
            void Shutdown() {
                std::unique_lock lock(m_mutex);

                if (!m_initialized.load(std::memory_order_acquire)) {
                    return;
                }

                m_shutdownRequested.store(true, std::memory_order_release);

                // Stop all monitoring
                m_monitoredProcesses.clear();

                // Clear caches
                m_resultCache.clear();
                m_rdtscTrackers.clear();
                m_sleepTrackers.clear();

                // Clear callbacks
                m_callbacks.clear();
                m_eventCallbacks.clear();

                m_initialized.store(false, std::memory_order_release);
                SS_LOG_INFO(L"AntiEvasion", L"TimeBasedEvasionDetector shutdown complete");
            }

            /**
             * @brief Check if cached result exists and is valid.
             */
            [[nodiscard]] std::optional<TimingEvasionResult> GetCachedResultInternal(
                uint32_t processId
            ) const {
                std::shared_lock lock(m_mutex);

                if (!m_config.enableResultCache) {
                    return std::nullopt;
                }

                auto it = m_resultCache.find(processId);
                if (it == m_resultCache.end()) {
                    return std::nullopt;
                }

                if (it->second.IsExpired(m_config.resultCacheTTL)) {
                    return std::nullopt;
                }

                return it->second.result;
            }

            /**
             * @brief Update result cache.
             */
            void UpdateCacheInternal(uint32_t processId, const TimingEvasionResult& result) {
                std::unique_lock lock(m_mutex);

                if (!m_config.enableResultCache) {
                    return;
                }

                CacheEntry entry{};
                entry.result = result;
                entry.cacheTime = steady_clock::now();

                m_resultCache[processId] = entry;
            }

            /**
             * @brief Get process information.
             */
            [[nodiscard]] bool GetProcessInfo(
                uint32_t processId,
                TimingEvasionResult& result
            ) {
                try {
#ifdef _WIN32
                    HANDLE hProcess = OpenProcess(
                        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                        FALSE,
                        processId
                    );

                    if (!hProcess) {
                        SS_LOG_WARN(L"AntiEvasion", L"Failed to open process %u: %lu", processId, GetLastError());
                        return false;
                    }

                    // RAII wrapper for process handle
                    struct ProcessHandleGuard {
                        HANDLE handle;
                        ~ProcessHandleGuard() { if (handle) CloseHandle(handle); }
                    } guard{ hProcess };

                    // Get process name
                    wchar_t processPath[MAX_PATH] = {};
                    DWORD pathLen = MAX_PATH;
                    if (QueryFullProcessImageNameW(hProcess, 0, processPath, &pathLen)) {
                        result.processPath = processPath;

                        // Extract process name from path
                        std::wstring path(processPath);
                        size_t lastSlash = path.find_last_of(L"\\/");
                        if (lastSlash != std::wstring::npos) {
                            result.processName = path.substr(lastSlash + 1);
                        }
                    }

                    // Get parent process ID
                    PROCESS_BASIC_INFORMATION pbi{};
                    ULONG returnLength = 0;

                    typedef NTSTATUS(WINAPI* NtQueryInformationProcessPtr)(
                        HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

                    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
                    if (ntdll) {
                        auto NtQueryInformationProcess =
                            reinterpret_cast<NtQueryInformationProcessPtr>(
                                GetProcAddress(ntdll, "NtQueryInformationProcess"));

                        if (NtQueryInformationProcess) {
                            if (NT_SUCCESS(NtQueryInformationProcess(
                                hProcess, ProcessBasicInformation,
                                &pbi, sizeof(pbi), &returnLength))) {
                                result.parentProcessId = static_cast<uint32_t>(
                                    static_cast<uintptr_t>(pbi.UniqueProcessId)
                                );
                            }
                        }
                    }

                    result.processId = processId;
                    return true;
#else
                    return false;
#endif
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(L"AntiEvasion", L"GetProcessInfo failed for PID %u: %hs", processId, e.what());
                    return false;
                }
            }
        };

        // ====================================================================
        // SINGLETON INSTANCE
        // ====================================================================

        TimeBasedEvasionDetector& TimeBasedEvasionDetector::Instance() {
            static TimeBasedEvasionDetector instance;
            return instance;
        }

        // ====================================================================
        // CONSTRUCTOR / DESTRUCTOR
        // ====================================================================

        TimeBasedEvasionDetector::TimeBasedEvasionDetector()
            : m_impl(std::make_unique<Impl>())
        {
        }

        TimeBasedEvasionDetector::~TimeBasedEvasionDetector() {
            if (m_impl) {
                m_impl->Shutdown();
            }
        }

        // ====================================================================
        // LIFECYCLE MANAGEMENT
        // ====================================================================

        bool TimeBasedEvasionDetector::Initialize(
            std::shared_ptr<Utils::ThreadPool> threadPool
        ) {
            return Initialize(threadPool, TimingDetectorConfig::CreateDefault());
        }

        bool TimeBasedEvasionDetector::Initialize(
            std::shared_ptr<Utils::ThreadPool> threadPool,
            const TimingDetectorConfig& config
        ) {
            if (!m_impl) {
                SS_LOG_FATAL(L"AntiEvasion", L"TimeBasedEvasionDetector: Implementation is null");
                return false;
            }

            return m_impl->Initialize(threadPool, config);
        }

        void TimeBasedEvasionDetector::Shutdown() {
            if (m_impl) {
                m_impl->Shutdown();
            }
        }

        bool TimeBasedEvasionDetector::IsInitialized() const noexcept {
            return m_impl && m_impl->m_initialized.load(std::memory_order_acquire);
        }

        void TimeBasedEvasionDetector::UpdateConfig(const TimingDetectorConfig& config) {
            if (!m_impl) return;

            std::unique_lock lock(m_impl->m_mutex);
            m_impl->m_config = config;
            SS_LOG_INFO(L"AntiEvasion", L"TimeBasedEvasionDetector configuration updated");
        }

        TimingDetectorConfig TimeBasedEvasionDetector::GetConfig() const {
            if (!m_impl) return TimingDetectorConfig{};

            std::shared_lock lock(m_impl->m_mutex);
            return m_impl->m_config;
        }

        // ====================================================================
        // SINGLE PROCESS ANALYSIS
        // ====================================================================

        TimingEvasionResult TimeBasedEvasionDetector::AnalyzeProcess(uint32_t processId) {
            TimingEvasionResult result{};

            if (!IsInitialized()) {
                result.errorMessage = L"Detector not initialized";
                SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeProcess called but detector not initialized");
                m_impl->m_stats.analysisErrors.fetch_add(1, std::memory_order_relaxed);
                return result;
            }

            const auto analysisStart = steady_clock::now();
            result.analysisStartTime = system_clock::now();

            try {
                // Check cache first
                if (auto cached = m_impl->GetCachedResultInternal(processId)) {
                    m_impl->m_stats.cacheHits.fetch_add(1, std::memory_order_relaxed);
                    SS_LOG_INFO(L"AntiEvasion", L"Returning cached result for PID %u", processId);
                    return *cached;
                }
                m_impl->m_stats.cacheMisses.fetch_add(1, std::memory_order_relaxed);

                // Get process information
                if (!m_impl->GetProcessInfo(processId, result)) {
                    result.errorMessage = L"Failed to open process or access denied";
                    m_impl->m_stats.analysisErrors.fetch_add(1, std::memory_order_relaxed);
                    return result;
                }

                // Perform detection checks based on configuration
                if (m_impl->m_config.detectRDTSC) {
                    CheckRDTSCAbuse(processId, result);
                }

                if (m_impl->m_config.detectSleepEvasion) {
                    CheckSleepEvasion(processId, result);
                }

                if (m_impl->m_config.detectAPITiming) {
                    CheckTimerAnomalies(processId, result);
                    CheckTimeDriftChecks(processId, result);
                }

                if (m_impl->m_config.detectNTPEvasion) {
                    CheckNTPEvasion(processId, result);
                }

                if (m_impl->m_config.detectHardwareTimers) {
                    CheckHardwareTimers(processId, result);
                }

                // Correlate findings if enabled
                if (m_impl->m_config.enableCorrelation) {
                    CorrelateFindings(result);
                }

                // Calculate threat score
                CalculateThreatScore(result);

                // Add MITRE mappings
                if (m_impl->m_config.enableMitreMapping) {
                    AddMitreMappings(result);
                }

                // Mark analysis complete
                result.analysisEndTime = system_clock::now();
                result.analysisDurationMs = duration_cast<milliseconds>(
                    result.analysisEndTime - result.analysisStartTime
                ).count();
                result.analysisComplete = true;

                // Determine if evasive
                result.isEvasive = !result.findings.empty() &&
                    result.confidence >= m_impl->m_config.minReportableConfidence;

                // Update statistics
                m_impl->m_stats.totalProcessesAnalyzed.fetch_add(1, std::memory_order_relaxed);
                if (result.isEvasive) {
                    m_impl->m_stats.totalEvasionsDetected.fetch_add(1, std::memory_order_relaxed);
                }

                const auto analysisDuration = duration_cast<microseconds>(
                    steady_clock::now() - analysisStart
                ).count();
                m_impl->m_stats.avgAnalysisDurationUs.store(
                    analysisDuration, std::memory_order_relaxed
                );
                m_impl->m_stats.lastAnalysisTimestamp.store(
                    duration_cast<seconds>(system_clock::now().time_since_epoch()).count(),
                    std::memory_order_relaxed
                );

                // Update cache
                UpdateCache(processId, result);

                // Invoke callbacks if evasive
                if (result.isEvasive) {
                    InvokeCallbacks(result);
                }

                SS_LOG_INFO(L"AntiEvasion", L"Analysis complete for PID %u - Evasive: %d, Confidence: %.1f%%",
                    processId, result.isEvasive, result.confidence);

            } catch (const std::exception& e) {
                result.errorMessage = StringUtils::ToWide(
                    std::string("Analysis exception: ") + e.what()
                );
                result.analysisComplete = false;
                m_impl->m_stats.analysisErrors.fetch_add(1, std::memory_order_relaxed);
                SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeProcess exception for PID %u: %hs", processId, e.what());
            }

            return result;
        }

        bool TimeBasedEvasionDetector::AnalyzeProcessAsync(
            uint32_t processId,
            std::function<void(TimingEvasionResult)> callback
        ) {
            if (!IsInitialized() || !m_impl->m_threadPool) {
                SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeProcessAsync: Not initialized or no thread pool");
                return false;
            }

            if (!callback) {
                SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeProcessAsync: Null callback");
                return false;
            }

            try {
                // Submit to thread pool
                m_impl->m_threadPool->Submit([this, processId, cb = std::move(callback)](const Utils::TaskContext&) {
                    auto result = AnalyzeProcess(processId);
                    cb(std::move(result));
                }, Utils::TaskPriority::Normal);

                return true;

            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeProcessAsync failed: %hs", e.what());
                return false;
            }
        }

        bool TimeBasedEvasionDetector::QuickScanProcess(uint32_t processId) {
            if (!IsInitialized()) {
                return false;
            }

            try {
                // Quick checks - just look for obvious indicators
                TimingEvasionResult result{};

                if (!m_impl->GetProcessInfo(processId, result)) {
                    return false;
                }

                // Quick RDTSC check
                CheckRDTSCAbuse(processId, result);
                if (!result.findings.empty()) {
                    return true;
                }

                // Quick sleep check
                CheckSleepEvasion(processId, result);
                if (!result.findings.empty()) {
                    return true;
                }

                return false;

            } catch (...) {
                return false;
            }
        }

        // ====================================================================
        // SPECIFIC ANALYSIS METHODS
        // ====================================================================

        RDTSCAnalysis TimeBasedEvasionDetector::AnalyzeRDTSC(uint32_t processId) {
            RDTSCAnalysis analysis{};
            analysis.processId = processId;

            if (!IsInitialized()) {
                return analysis;
            }

            try {
                std::shared_lock lock(m_impl->m_mutex);

                auto it = m_impl->m_rdtscTrackers.find(processId);
                if (it == m_impl->m_rdtscTrackers.end()) {
                    return analysis;
                }

                const auto& tracker = it->second;
                analysis.rdtscCount = tracker.callCount;

                if (!tracker.deltas.empty()) {
                    // Calculate statistics
                    analysis.avgDeltaNs = std::accumulate(
                        tracker.deltas.begin(), tracker.deltas.end(), 0ULL
                    ) / tracker.deltas.size();

                    analysis.minDeltaNs = *std::min_element(
                        tracker.deltas.begin(), tracker.deltas.end()
                    );

                    analysis.maxDeltaNs = *std::max_element(
                        tracker.deltas.begin(), tracker.deltas.end()
                    );

                    // Calculate standard deviation
                    double sum = 0.0;
                    for (auto delta : tracker.deltas) {
                        double diff = static_cast<double>(delta) - analysis.avgDeltaNs;
                        sum += diff * diff;
                    }
                    analysis.deltaStdDev = std::sqrt(sum / tracker.deltas.size());
                }

                // Calculate calls per second
                if (tracker.firstCall != tracker.lastCall) {
                    auto duration = duration_cast<milliseconds>(
                        tracker.lastCall - tracker.firstCall
                    ).count();
                    if (duration > 0) {
                        analysis.callsPerSecond = (tracker.callCount * 1000.0) / duration;
                    }
                }

                analysis.observationDurationMs = duration_cast<milliseconds>(
                    steady_clock::now() - tracker.firstCall
                ).count();

                // Detect high frequency
                analysis.highFrequencyDetected =
                    analysis.callsPerSecond > m_impl->m_config.rdtscFrequencyThreshold;

                // Detect delta checking (VM detection)
                analysis.deltaCheckDetected =
                    analysis.maxDeltaNs > m_impl->m_config.rdtscDeltaThresholdNs;

                // Detect frequency measurement
                analysis.frequencyMeasurementDetected =
                    tracker.deltas.size() > 10 && analysis.deltaStdDev > 100.0;

                // Calculate confidence
                float confidenceFactors = 0.0f;
                int factorCount = 0;

                if (analysis.highFrequencyDetected) {
                    confidenceFactors += 40.0f;
                    factorCount++;
                }
                if (analysis.deltaCheckDetected) {
                    confidenceFactors += 35.0f;
                    factorCount++;
                }
                if (analysis.frequencyMeasurementDetected) {
                    confidenceFactors += 25.0f;
                    factorCount++;
                }

                analysis.confidence = factorCount > 0 ? confidenceFactors : 0.0f;

            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeRDTSC exception: %hs", e.what());
            }

            return analysis;
        }

        SleepAnalysis TimeBasedEvasionDetector::AnalyzeSleep(uint32_t processId) {
            SleepAnalysis analysis{};
            analysis.processId = processId;

            if (!IsInitialized()) {
                return analysis;
            }

            try {
                std::shared_lock lock(m_impl->m_mutex);

                auto it = m_impl->m_sleepTrackers.find(processId);
                if (it == m_impl->m_sleepTrackers.end()) {
                    return analysis;
                }

                const auto& tracker = it->second;
                analysis.sleepCallCount = tracker.callCount;
                analysis.totalRequestedDurationMs = tracker.totalRequestedMs;
                analysis.totalActualDurationMs = tracker.totalActualMs;

                if (tracker.callCount > 0) {
                    analysis.avgRequestedDurationMs = tracker.totalRequestedMs / tracker.callCount;
                    analysis.avgActualDurationMs = tracker.totalActualMs / tracker.callCount;
                }

                if (!tracker.durations.empty()) {
                    analysis.maxRequestedDurationMs = *std::max_element(
                        tracker.durations.begin(), tracker.durations.end()
                    );
                    analysis.sleepDurations = tracker.durations;
                }

                // Calculate acceleration ratio
                if (tracker.totalRequestedMs > 0) {
                    analysis.accelerationRatio = static_cast<double>(tracker.totalActualMs) /
                        static_cast<double>(tracker.totalRequestedMs);
                }

                // Detect sleep bombing
                analysis.sleepBombingDetected =
                    analysis.maxRequestedDurationMs > m_impl->m_config.sleepEvasionThresholdMs;

                // Detect acceleration (sandbox fast-forward)
                analysis.accelerationDetected =
                    analysis.accelerationRatio < m_impl->m_config.sleepAccelerationThreshold &&
                    tracker.callCount >= 3;

                // Detect fragmentation
                if (tracker.durations.size() >= m_impl->m_config.minSleepFragments) {
                    // Check if many small sleeps that sum to a large value
                    uint64_t avgDuration = tracker.totalRequestedMs / tracker.durations.size();

                    if (avgDuration < 1000 && tracker.totalRequestedMs > 10000) {
                        analysis.fragmentationDetected = true;
                        analysis.fragmentedSleepCount = static_cast<uint32_t>(tracker.durations.size());
                        analysis.avgFragmentDurationMs = avgDuration;
                    }
                }

                // Calculate confidence
                float confidence = 0.0f;
                if (analysis.sleepBombingDetected) confidence += 30.0f;
                if (analysis.accelerationDetected) confidence += 45.0f;
                if (analysis.fragmentationDetected) confidence += 25.0f;

                analysis.confidence = std::min(confidence, 100.0f);

            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeSleep exception: %hs", e.what());
            }

            return analysis;
        }

        APITimingAnalysis TimeBasedEvasionDetector::AnalyzeAPITiming(uint32_t processId) {
            APITimingAnalysis analysis{};
            analysis.processId = processId;

            if (!IsInitialized()) {
                return analysis;
            }

            try {
#ifdef _WIN32
                // Measure current QPC frequency
                LARGE_INTEGER freq{};
                if (QueryPerformanceFrequency(&freq)) {
                    analysis.qpcFrequencyHz = static_cast<uint64_t>(freq.QuadPart);
                    analysis.expectedQpcFrequencyHz = m_impl->m_systemQPCFrequency;

                    if (analysis.expectedQpcFrequencyHz > 0) {
                        double deviation = std::abs(
                            static_cast<double>(analysis.qpcFrequencyHz) -
                            static_cast<double>(analysis.expectedQpcFrequencyHz)
                        ) / static_cast<double>(analysis.expectedQpcFrequencyHz) * 100.0;

                        analysis.qpcFrequencyDeviation = deviation;
                        analysis.qpcAnomalyDetected =
                            deviation > m_impl->m_config.qpcAnomalyPercent;
                    }
                }

                // Calculate confidence
                float confidence = 0.0f;
                if (analysis.qpcAnomalyDetected) confidence += 40.0f;
                if (analysis.tickCountAnomalyDetected) confidence += 35.0f;
                if (analysis.crossCheckDetected) confidence += 25.0f;

                analysis.confidence = std::min(confidence, 100.0f);
#endif

            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeAPITiming exception: %hs", e.what());
            }

            return analysis;
        }

        NTPAnalysis TimeBasedEvasionDetector::AnalyzeNTP(uint32_t processId) {
            NTPAnalysis analysis{};
            analysis.processId = processId;

            if (!IsInitialized()) {
                return analysis;
            }

            try {
                // Use NetworkUtils to check for NTP connections (UDP port 123)
                std::vector<Utils::NetworkUtils::ConnectionInfo> connections;
                if (Utils::NetworkUtils::GetConnectionsByProcess(processId, connections)) {
                    for (const auto& conn : connections) {
                        if (conn.remotePort == 123 && conn.protocol == Utils::NetworkUtils::ProtocolType::UDP) {
                            analysis.ntpQueryCount++;
                            analysis.ntpServers.push_back(conn.remoteAddress.ToString());
                            analysis.ntpEvasionDetected = true;
                        }
                    }
                }

                // If we found NTP servers, calculate confidence
                if (analysis.ntpEvasionDetected) {
                    // Enterprise heuristic: Valid NTP usually happens once at startup or at long intervals.
                    // Evasion attempts might query repeatedly to check for time warping.

                    if (analysis.ntpQueryCount > 1) {
                        analysis.confidence = 85.0f; // High confidence if multiple queries observed
                    } else {
                        // Single query could be legitimate time sync, check context
                        // If process is not a browser or system service, it's suspicious
                        // We lack process category info here, so we default to medium confidence
                        analysis.confidence = 60.0f;
                    }
                }

            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"AntiEvasion", L"AnalyzeNTP exception: %hs", e.what());
            }

            return analysis;
        }

        bool TimeBasedEvasionDetector::DetectSleepAcceleration(uint32_t processId) {
            auto sleepAnalysis = AnalyzeSleep(processId);
            return sleepAnalysis.accelerationDetected;
        }

        bool TimeBasedEvasionDetector::DetectTimingAntiDebug(uint32_t processId) {
            if (!IsInitialized()) {
                return false;
            }

            try {
                // Detect timing-based anti-debugging by checking for:
                // 1. High-frequency timing calls in tight loops
                // 2. Delta checks between timing calls
                // 3. Multiple timing API cross-checks

                auto rdtscAnalysis = AnalyzeRDTSC(processId);
                if (rdtscAnalysis.highFrequencyDetected && rdtscAnalysis.deltaCheckDetected) {
                    return true;
                }

                auto apiAnalysis = AnalyzeAPITiming(processId);
                if (apiAnalysis.crossCheckDetected) {
                    return true;
                }

                return false;

            } catch (...) {
                return false;
            }
        }

        // ====================================================================
        // CONTINUOUS MONITORING
        // ====================================================================

        bool TimeBasedEvasionDetector::StartMonitoring(uint32_t processId) {
            if (!IsInitialized()) {
                SS_LOG_ERROR(L"AntiEvasion", L"StartMonitoring: Detector not initialized");
                return false;
            }

            try {
                std::unique_lock lock(m_impl->m_mutex);

                // Check process limit
                if (m_impl->m_monitoredProcesses.size() >= m_impl->m_config.maxMonitoredProcesses) {
                    SS_LOG_WARN(L"AntiEvasion", L"StartMonitoring: Maximum monitored processes reached");
                    return false;
                }

                // Create monitoring state
                ProcessMonitorState state{};
                state.processId = processId;
                state.state = MonitoringState::Active;
                state.startTime = steady_clock::now();
                state.lastTickTime = steady_clock::now();

                m_impl->m_monitoredProcesses[processId] = state;
                m_impl->m_stats.currentlyMonitoring.fetch_add(1, std::memory_order_relaxed);

                SS_LOG_INFO(L"AntiEvasion", L"Started monitoring PID %u", processId);
                return true;

            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"AntiEvasion", L"StartMonitoring failed: %hs", e.what());
                return false;
            }
        }

        void TimeBasedEvasionDetector::StopMonitoring(uint32_t processId) {
            if (!m_impl) return;

            std::unique_lock lock(m_impl->m_mutex);

            auto it = m_impl->m_monitoredProcesses.find(processId);
            if (it != m_impl->m_monitoredProcesses.end()) {
                m_impl->m_monitoredProcesses.erase(it);
                m_impl->m_stats.currentlyMonitoring.fetch_sub(1, std::memory_order_relaxed);
                SS_LOG_INFO(L"AntiEvasion", L"Stopped monitoring PID %u", processId);
            }
        }

        void TimeBasedEvasionDetector::StopAllMonitoring() {
            if (!m_impl) return;

            std::unique_lock lock(m_impl->m_mutex);

            size_t count = m_impl->m_monitoredProcesses.size();
            m_impl->m_monitoredProcesses.clear();
            m_impl->m_stats.currentlyMonitoring.store(0, std::memory_order_relaxed);

            SS_LOG_INFO(L"AntiEvasion", L"Stopped monitoring all %zu processes", count);
        }

        bool TimeBasedEvasionDetector::IsMonitoring(uint32_t processId) const {
            if (!m_impl) return false;

            std::shared_lock lock(m_impl->m_mutex);
            return m_impl->m_monitoredProcesses.find(processId) !=
                m_impl->m_monitoredProcesses.end();
        }

        MonitoringState TimeBasedEvasionDetector::GetMonitoringState(uint32_t processId) const {
            if (!m_impl) return MonitoringState::Inactive;

            std::shared_lock lock(m_impl->m_mutex);

            auto it = m_impl->m_monitoredProcesses.find(processId);
            if (it != m_impl->m_monitoredProcesses.end()) {
                return it->second.state;
            }

            return MonitoringState::Inactive;
        }

        void TimeBasedEvasionDetector::PauseMonitoring(uint32_t processId) {
            if (!m_impl) return;

            std::unique_lock lock(m_impl->m_mutex);

            auto it = m_impl->m_monitoredProcesses.find(processId);
            if (it != m_impl->m_monitoredProcesses.end()) {
                it->second.state = MonitoringState::Paused;
                SS_LOG_INFO(L"AntiEvasion", L"Paused monitoring PID %u", processId);
            }
        }

        void TimeBasedEvasionDetector::ResumeMonitoring(uint32_t processId) {
            if (!m_impl) return;

            std::unique_lock lock(m_impl->m_mutex);

            auto it = m_impl->m_monitoredProcesses.find(processId);
            if (it != m_impl->m_monitoredProcesses.end()) {
                it->second.state = MonitoringState::Active;
                SS_LOG_INFO(L"AntiEvasion", L"Resumed monitoring PID %u", processId);
            }
        }

        std::vector<uint32_t> TimeBasedEvasionDetector::GetMonitoredProcesses() const {
            if (!m_impl) return {};

            std::shared_lock lock(m_impl->m_mutex);

            std::vector<uint32_t> processes;
            processes.reserve(m_impl->m_monitoredProcesses.size());

            for (const auto& [pid, state] : m_impl->m_monitoredProcesses) {
                processes.push_back(pid);
            }

            return processes;
        }

        // ====================================================================
        // CALLBACKS
        // ====================================================================

        uint64_t TimeBasedEvasionDetector::RegisterCallback(TimingEvasionCallback callback) {
            if (!m_impl || !callback) {
                return 0;
            }

            std::unique_lock lock(m_impl->m_mutex);

            uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
            m_impl->m_callbacks[id] = std::move(callback);

            SS_LOG_INFO(L"AntiEvasion", L"Registered timing evasion callback ID %llu", id);
            return id;
        }

        bool TimeBasedEvasionDetector::UnregisterCallback(uint64_t callbackId) {
            if (!m_impl) return false;

            std::unique_lock lock(m_impl->m_mutex);

            auto it = m_impl->m_callbacks.find(callbackId);
            if (it != m_impl->m_callbacks.end()) {
                m_impl->m_callbacks.erase(it);
                SS_LOG_INFO(L"AntiEvasion", L"Unregistered callback ID %llu", callbackId);
                return true;
            }

            return false;
        }

        uint64_t TimeBasedEvasionDetector::RegisterEventCallback(TimingEventCallback callback) {
            if (!m_impl || !callback) {
                return 0;
            }

            std::unique_lock lock(m_impl->m_mutex);

            uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
            m_impl->m_eventCallbacks[id] = std::move(callback);

            SS_LOG_INFO(L"AntiEvasion", L"Registered timing event callback ID %llu", id);
            return id;
        }

        bool TimeBasedEvasionDetector::UnregisterEventCallback(uint64_t callbackId) {
            if (!m_impl) return false;

            std::unique_lock lock(m_impl->m_mutex);

            auto it = m_impl->m_eventCallbacks.find(callbackId);
            if (it != m_impl->m_eventCallbacks.end()) {
                m_impl->m_eventCallbacks.erase(it);
                return true;
            }

            return false;
        }

        // ====================================================================
        // STATISTICS & DIAGNOSTICS
        // ====================================================================

        TimingDetectorStats TimeBasedEvasionDetector::GetStats() const {
            if (!m_impl) return TimingDetectorStats{};

            // Atomic loads - no lock needed
            return m_impl->m_stats;
        }

        void TimeBasedEvasionDetector::ResetStats() {
            if (m_impl) {
                m_impl->m_stats.Reset();
                SS_LOG_INFO(L"AntiEvasion", L"TimeBasedEvasionDetector statistics reset");
            }
        }

        std::optional<TimingEvasionResult> TimeBasedEvasionDetector::GetCachedResult(
            uint32_t processId
        ) const {
            if (!m_impl) return std::nullopt;
            return m_impl->GetCachedResultInternal(processId);
        }

        void TimeBasedEvasionDetector::ClearCache() {
            if (!m_impl) return;

            std::unique_lock lock(m_impl->m_mutex);
            m_impl->m_resultCache.clear();
            SS_LOG_INFO(L"AntiEvasion", L"Cleared timing evasion result cache");
        }

        void TimeBasedEvasionDetector::ClearCacheForProcess(uint32_t processId) {
            if (!m_impl) return;

            std::unique_lock lock(m_impl->m_mutex);
            m_impl->m_resultCache.erase(processId);
        }

        std::vector<TimingEventRecord> TimeBasedEvasionDetector::GetEventHistory(
            uint32_t processId,
            size_t maxEvents
        ) const {
            if (!m_impl) return {};

            std::shared_lock lock(m_impl->m_mutex);

            auto it = m_impl->m_monitoredProcesses.find(processId);
            if (it == m_impl->m_monitoredProcesses.end()) {
                return {};
            }

            const auto& history = it->second.eventHistory;

            if (maxEvents == 0 || maxEvents >= history.size()) {
                return history;
            }

            // Return most recent events
            return std::vector<TimingEventRecord>(
                history.end() - maxEvents,
                history.end()
            );
        }

        // ====================================================================
        // INTERNAL ANALYSIS METHODS
        // ====================================================================

        void TimeBasedEvasionDetector::CheckRDTSCAbuse(
            uint32_t processId,
            TimingEvasionResult& result
        ) {
            try {
                auto analysis = AnalyzeRDTSC(processId);

                if (analysis.HasRDTSCEvasion() &&
                    analysis.confidence >= m_impl->m_config.minReportableConfidence) {

                    TimingEvasionFinding finding{};
                    finding.detectionTime = system_clock::now();
                    finding.detectionMethod = TimingDetectionMethod::HardwareCounters;
                    finding.confidence = analysis.confidence;
                    finding.severity = ConfidenceToSeverity(analysis.confidence);

                    if (analysis.highFrequencyDetected) {
                        finding.type = TimingEvasionType::RDTSCHighFrequency;
                        finding.description = L"High-frequency RDTSC instruction execution detected";
                        finding.technicalDetails = StringUtils::ToWide(
                            std::format("RDTSC calls/sec: {:.2f}, Threshold: {}",
                                analysis.callsPerSecond,
                                m_impl->m_config.rdtscFrequencyThreshold)
                        );
                    } else if (analysis.deltaCheckDetected) {
                        finding.type = TimingEvasionType::RDTSCDeltaCheck;
                        finding.description = L"RDTSC delta check for VM/hypervisor detection";
                        finding.technicalDetails = StringUtils::ToWide(
                            std::format("Max RDTSC delta: {} ns, Threshold: {} ns",
                                analysis.maxDeltaNs,
                                m_impl->m_config.rdtscDeltaThresholdNs)
                        );
                    } else if (analysis.frequencyMeasurementDetected) {
                        finding.type = TimingEvasionType::TSCFrequencyMeasurement;
                        finding.description = L"TSC frequency measurement for VM detection";
                        finding.technicalDetails = StringUtils::ToWide(
                            std::format("Delta std dev: {:.2f}", analysis.deltaStdDev)
                        );
                    }

                    finding.mitreId = TimingEvasionTypeToMitre(finding.type);
                    result.findings.push_back(finding);
                    result.detectedTypes.set(static_cast<size_t>(finding.type));

                    // Update result statistics
                    result.rdtscCallCount = analysis.rdtscCount;
                    result.avgRdtscDeltaNs = analysis.avgDeltaNs;
                    result.maxRdtscDeltaNs = analysis.maxDeltaNs;

                    m_impl->m_stats.detectionsByType[static_cast<size_t>(finding.type)]
                        .fetch_add(1, std::memory_order_relaxed);
                }

            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"AntiEvasion", L"CheckRDTSCAbuse exception: %hs", e.what());
            }
        }

        void TimeBasedEvasionDetector::CheckTimeDriftChecks(
            uint32_t processId,
            TimingEvasionResult& result
        ) {
            try {
                auto analysis = AnalyzeAPITiming(processId);

                if (analysis.HasAPITimingEvasion() &&
                    analysis.confidence >= m_impl->m_config.minReportableConfidence) {

                    TimingEvasionFinding finding{};
                    finding.detectionTime = system_clock::now();
                    finding.detectionMethod = TimingDetectionMethod::APIHooking;
                    finding.confidence = analysis.confidence;
                    finding.severity = ConfidenceToSeverity(analysis.confidence);

                    if (analysis.tickCountAnomalyDetected) {
                        finding.type = TimingEvasionType::GetTickCountDelta;
                        finding.description = L"GetTickCount anomaly detected";
                    } else if (analysis.qpcAnomalyDetected) {
                        finding.type = TimingEvasionType::QPCAnomaly;
                        finding.description = L"QueryPerformanceCounter frequency anomaly";
                        finding.technicalDetails = StringUtils::ToWide(
                            std::format("QPC deviation: {:.2f}%", analysis.qpcFrequencyDeviation)
                        );
                    } else if (analysis.crossCheckDetected) {
                        finding.type = TimingEvasionType::TimingAPICrossCheck;
                        finding.description = L"Multiple timing API cross-validation detected";
                    }

                    finding.mitreId = TimingEvasionTypeToMitre(finding.type);
                    result.findings.push_back(finding);
                    result.detectedTypes.set(static_cast<size_t>(finding.type));

                    result.getTickCountCalls = analysis.getTickCountCalls;
                    result.qpcCallCount = analysis.qpcCalls;

                    m_impl->m_stats.detectionsByType[static_cast<size_t>(finding.type)]
                        .fetch_add(1, std::memory_order_relaxed);
                }

            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"AntiEvasion", L"CheckTimeDriftChecks exception: %hs", e.what());
            }
        }

        void TimeBasedEvasionDetector::CheckTimerAnomalies(
            uint32_t processId,
            TimingEvasionResult& result
        ) {
            try {
                // Enterprise implementation: Check for timer resolution manipulation (timeBeginPeriod)
                // Malware often lowers timer resolution to 1ms to make Sleep(1) faster or more precise
                // for timing attacks.

                // We check loaded modules for winmm.dll which exports timeBeginPeriod
                std::vector<ProcessUtils::ProcessModuleInfo> modules;
                if (ProcessUtils::EnumerateProcessModules(processId, modules)) {
                    bool winmmLoaded = false;
                    for (const auto& mod : modules) {
                        if (StringUtils::ToLower(mod.name) == L"winmm.dll") {
                            winmmLoaded = true;
                            break;
                        }
                    }

                    if (winmmLoaded) {
                        // If winmm is loaded, we check if the process exhibits high-frequency sleep patterns
                        // which would necessitate timer resolution changes.
                        auto sleepAnalysis = AnalyzeSleep(processId);

                        // If we have many small sleeps and winmm is loaded, it's a potential indicator
                        // of timer resolution tampering for evasion or evasion-related timing.
                        if (sleepAnalysis.sleepCallCount > 50 && sleepAnalysis.avgActualDurationMs <= 15) { // 15.625ms is default tick
                             TimingEvasionFinding finding{};
                             finding.type = TimingEvasionType::TimeGetTimeCheck; // Re-using existing enum or closest match
                             finding.description = L"Potential timer resolution manipulation detected";
                             finding.technicalDetails = L"High frequency small sleeps with winmm.dll loaded. Avg Duration: " +
                                                      std::to_wstring(sleepAnalysis.avgActualDurationMs) + L"ms";
                             finding.confidence = 45.0f; // Medium confidence as legitimate games/media apps do this too
                             finding.severity = TimingEvasionSeverity::Medium;
                             finding.mitreId = TimingEvasionTypeToMitre(finding.type);
                             finding.detectionTime = system_clock::now();

                             result.findings.push_back(finding);
                             result.detectedTypes.set(static_cast<size_t>(finding.type));
                             m_impl->m_stats.detectionsByType[static_cast<size_t>(finding.type)]
                                 .fetch_add(1, std::memory_order_relaxed);
                        }
                    }
                }
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"AntiEvasion", L"CheckTimerAnomalies exception: %hs", e.what());
            }
        }

        void TimeBasedEvasionDetector::CheckSleepEvasion(
            uint32_t processId,
            TimingEvasionResult& result
        ) {
            try {
                auto analysis = AnalyzeSleep(processId);

                if (analysis.HasSleepEvasion() &&
                    analysis.confidence >= m_impl->m_config.minReportableConfidence) {

                    TimingEvasionFinding finding{};
                    finding.detectionTime = system_clock::now();
                    finding.detectionMethod = TimingDetectionMethod::DynamicMonitoring;
                    finding.confidence = analysis.confidence;
                    finding.severity = ConfidenceToSeverity(analysis.confidence);

                    if (analysis.sleepBombingDetected) {
                        finding.type = TimingEvasionType::SleepBombing;
                        finding.description = L"Sleep bombing detected (extended sleep to timeout analysis)";
                        finding.technicalDetails = StringUtils::ToWide(
                            std::format("Max sleep duration: {} ms", analysis.maxRequestedDurationMs)
                        );
                    } else if (analysis.accelerationDetected) {
                        finding.type = TimingEvasionType::SleepAccelerationDetect;
                        finding.description = L"Sleep acceleration detection (sandbox fast-forward)";
                        finding.technicalDetails = StringUtils::ToWide(
                            std::format("Acceleration ratio: {:.3f}", analysis.accelerationRatio)
                        );
                    } else if (analysis.fragmentationDetected) {
                        finding.type = TimingEvasionType::SleepFragmentation;
                        finding.description = L"Fragmented sleeps to evade acceleration";
                        finding.technicalDetails = StringUtils::ToWide(
                            std::format("Fragment count: {}, Avg duration: {} ms",
                                analysis.fragmentedSleepCount,
                                analysis.avgFragmentDurationMs)
                        );
                    }

                    finding.mitreId = TimingEvasionTypeToMitre(finding.type);
                    result.findings.push_back(finding);
                    result.detectedTypes.set(static_cast<size_t>(finding.type));

                    result.sleepCallCount = analysis.sleepCallCount;
                    result.totalSleepDurationMs = analysis.totalRequestedDurationMs;
                    result.actualSleepDurationMs = analysis.totalActualDurationMs;

                    m_impl->m_stats.detectionsByType[static_cast<size_t>(finding.type)]
                        .fetch_add(1, std::memory_order_relaxed);
                }

            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"AntiEvasion", L"CheckSleepEvasion exception: %hs", e.what());
            }
        }

        void TimeBasedEvasionDetector::CheckNTPEvasion(
            uint32_t processId,
            TimingEvasionResult& result
        ) {
            try {
                auto analysis = AnalyzeNTP(processId);

                if (analysis.HasNTPEvasion() &&
                    analysis.confidence >= m_impl->m_config.minReportableConfidence) {

                    TimingEvasionFinding finding{};
                    finding.detectionTime = system_clock::now();
                    finding.detectionMethod = TimingDetectionMethod::DynamicMonitoring;
                    finding.confidence = analysis.confidence;
                    finding.severity = ConfidenceToSeverity(analysis.confidence);

                    if (analysis.ntpEvasionDetected) {
                        finding.type = TimingEvasionType::NTPQuery;
                        finding.description = L"NTP server query for time validation";

                        if (!analysis.ntpServers.empty()) {
                             finding.technicalDetails = L"Servers: ";
                             for(size_t i=0; i < std::min(analysis.ntpServers.size(), (size_t)3); ++i) {
                                 finding.technicalDetails += analysis.ntpServers[i] + L" ";
                             }
                        }
                    } else if (analysis.externalValidationDetected) {
                        finding.type = TimingEvasionType::ExternalTimeValidation;
                        finding.description = L"External time source validation";
                    }

                    finding.mitreId = TimingEvasionTypeToMitre(finding.type);
                    result.findings.push_back(finding);
                    result.detectedTypes.set(static_cast<size_t>(finding.type));

                    result.ntpQueryCount = analysis.ntpQueryCount;

                    m_impl->m_stats.detectionsByType[static_cast<size_t>(finding.type)]
                        .fetch_add(1, std::memory_order_relaxed);
                }

            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"AntiEvasion", L"CheckNTPEvasion exception: %hs", e.what());
            }
        }

        void TimeBasedEvasionDetector::CheckHardwareTimers(
            uint32_t processId,
            TimingEvasionResult& result
        ) {
             // Basic user-mode check: look for suspicious loaded modules (drivers)
             // that enable direct hardware access (e.g., WinIo, InpOut)
             try {
                 std::vector<ProcessUtils::ProcessModuleInfo> modules;
                 if (ProcessUtils::EnumerateProcessModules(processId, modules)) {
                     for (const auto& mod : modules) {
                         std::wstring nameLower = StringUtils::ToLower(mod.name);
                         if (nameLower.find(L"winio") != std::wstring::npos ||
                             nameLower.find(L"inpout") != std::wstring::npos ||
                             nameLower.find(L"giveio") != std::wstring::npos) {

                             TimingEvasionFinding finding{};
                             finding.type = TimingEvasionType::HardwareTimerDirect;
                             finding.severity = TimingEvasionSeverity::High;
                             finding.confidence = 90.0f;
                             finding.detectionMethod = TimingDetectionMethod::StaticAnalysis;
                             finding.description = L"Suspicious hardware access driver loaded";
                             finding.technicalDetails = L"Module: " + mod.name;
                             finding.detectionTime = system_clock::now();
                             finding.mitreId = TimingEvasionTypeToMitre(finding.type);

                             result.findings.push_back(finding);
                             result.detectedTypes.set(static_cast<size_t>(finding.type));
                             m_impl->m_stats.detectionsByType[static_cast<size_t>(finding.type)]
                                 .fetch_add(1, std::memory_order_relaxed);
                         }
                     }
                 }
             } catch(...) {
                 SS_LOG_ERROR(L"AntiEvasion", L"CheckHardwareTimers failed to enumerate modules for PID %u", processId);
             }
        }

        void TimeBasedEvasionDetector::CorrelateFindings(TimingEvasionResult& result) {
            if (result.findings.size() < 2) {
                return;
            }

            try {
                // Check for multi-technique evasion
                std::unordered_set<TimingEvasionType> uniqueTypes;
                for (const auto& finding : result.findings) {
                    uniqueTypes.insert(finding.type);
                }

                if (uniqueTypes.size() >= 3) {
                    // Multiple different techniques - strong indicator
                    TimingEvasionFinding correlatedFinding{};
                    correlatedFinding.type = TimingEvasionType::MultiTechniqueEvasion;
                    correlatedFinding.severity = TimingEvasionSeverity::Critical;
                    correlatedFinding.confidence = 95.0f;
                    correlatedFinding.detectionMethod = TimingDetectionMethod::BehavioralHeuristics;
                    correlatedFinding.description = L"Multiple timing evasion techniques combined";
                    correlatedFinding.technicalDetails = StringUtils::ToWide(
                        std::format("Detected {} distinct timing techniques", uniqueTypes.size())
                    );
                    correlatedFinding.detectionTime = system_clock::now();
                    correlatedFinding.mitreId = TimingEvasionTypeToMitre(correlatedFinding.type);

                    result.findings.push_back(correlatedFinding);
                    result.detectedTypes.set(static_cast<size_t>(correlatedFinding.type));
                }

            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"AntiEvasion", L"CorrelateFindings exception: %hs", e.what());
            }
        }

        void TimeBasedEvasionDetector::CalculateThreatScore(TimingEvasionResult& result) {
            if (result.findings.empty()) {
                result.threatScore = 0.0f;
                result.confidence = 0.0f;
                result.severity = TimingEvasionSeverity::Info;
                return;
            }

            try {
                // Calculate weighted threat score
                float totalScore = 0.0f;
                float maxConfidence = 0.0f;
                TimingEvasionSeverity maxSeverity = TimingEvasionSeverity::Info;

                for (const auto& finding : result.findings) {
                    // Weight by severity
                    float severityWeight = static_cast<float>(finding.severity) / 100.0f;
                    float findingScore = finding.confidence * severityWeight;

                    totalScore += findingScore;
                    maxConfidence = std::max(maxConfidence, finding.confidence);

                    if (finding.severity > maxSeverity) {
                        maxSeverity = finding.severity;
                        result.primaryEvasionType = finding.type;
                    }
                }

                // Normalize threat score (0-100)
                result.threatScore = std::min(totalScore, 100.0f);
                result.confidence = maxConfidence;
                result.severity = maxSeverity;

                SS_LOG_INFO(L"AntiEvasion", L"Calculated threat score: %.1f, Confidence: %.1f%%, Severity: %hs",
                    result.threatScore, result.confidence,
                    TimingEvasionSeverityToString(result.severity));

            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"AntiEvasion", L"CalculateThreatScore exception: %hs", e.what());
            }
        }

        void TimeBasedEvasionDetector::AddMitreMappings(TimingEvasionResult& result) {
            try {
                std::unordered_set<std::string> uniqueMitreIds;

                for (const auto& finding : result.findings) {
                    if (!finding.mitreId.empty()) {
                        uniqueMitreIds.insert(finding.mitreId);
                    }
                }

                result.mitreIds.assign(uniqueMitreIds.begin(), uniqueMitreIds.end());
                std::sort(result.mitreIds.begin(), result.mitreIds.end());

            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"AntiEvasion", L"AddMitreMappings exception: %hs", e.what());
            }
        }

        void TimeBasedEvasionDetector::MonitoringTick(uint32_t processId) {
            if (!m_impl) return;

            try {
                // Perform periodic analysis for monitored process
                auto result = AnalyzeProcess(processId);

                if (result.isEvasive) {
                    InvokeCallbacks(result);
                }

            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"AntiEvasion", L"MonitoringTick exception for PID %u: %hs", processId, e.what());
            }
        }

        void TimeBasedEvasionDetector::InvokeCallbacks(const TimingEvasionResult& result) {
            if (!m_impl) return;

            try {
                std::shared_lock lock(m_impl->m_mutex);

                for (const auto& [id, callback] : m_impl->m_callbacks) {
                    try {
                        callback(result);
                    } catch (const std::exception& e) {
                        SS_LOG_ERROR(L"AntiEvasion", L"Callback %llu exception: %hs", id, e.what());
                    }
                }

            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"AntiEvasion", L"InvokeCallbacks exception: %hs", e.what());
            }
        }

        void TimeBasedEvasionDetector::RecordTimingEvent(const TimingEventRecord& event) {
            if (!m_impl) return;

            try {
                std::unique_lock lock(m_impl->m_mutex);

                // Add to process event history
                auto it = m_impl->m_monitoredProcesses.find(event.processId);
                if (it != m_impl->m_monitoredProcesses.end()) {
                    auto& history = it->second.eventHistory;

                    // Enforce size limit
                    if (history.size() >= m_impl->m_config.maxEventsPerProcess) {
                        // Remove oldest event
                        history.erase(history.begin());
                    }

                    history.push_back(event);
                }

                // Invoke event callbacks
                for (const auto& [id, callback] : m_impl->m_eventCallbacks) {
                    try {
                        callback(event);
                    } catch (...) {
                        // Ignore callback exceptions
                    }
                }

                m_impl->m_stats.totalEventsProcessed.fetch_add(1, std::memory_order_relaxed);

            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"AntiEvasion", L"RecordTimingEvent exception: %hs", e.what());
            }
        }

        void TimeBasedEvasionDetector::UpdateCache(
            uint32_t processId,
            const TimingEvasionResult& result
        ) {
            if (m_impl) {
                m_impl->UpdateCacheInternal(processId, result);
            }
        }

    } // namespace AntiEvasion
} // namespace ShadowStrike
