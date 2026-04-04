#include "pch.h"
#include "EmulationEngine.hpp"

#include "../../Utils/Logger.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/ThreadPool.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cctype>
#include <cstdio>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#ifdef PHANTOM_EMULATOR_AVAILABLE
#include "../../../../PhantomEmulator/Integration/EmulationSession.hpp"
#include "../../../../PhantomEmulator/Integration/EmulationResult.hpp"
#include "../../../../PhantomEmulator/Integration/ResultConverter.hpp"
#endif

namespace ShadowStrike::Core::Engine {

namespace {

constexpr const wchar_t* kLogCategory = L"EmulationEngine";

[[nodiscard]] std::string ToLowerAscii(std::string_view value) {
    std::string lowered(value);
    std::transform(lowered.begin(), lowered.end(), lowered.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return lowered;
}

[[nodiscard]] std::wstring ToWide(std::string_view value) {
    return Utils::StringUtils::ToWide(value);
}

[[nodiscard]] EmulationStats SnapshotStats(const EmulationStats& stats) {
    EmulationStats snapshot;
    snapshot.totalSessions.store(stats.totalSessions.load(std::memory_order_relaxed), std::memory_order_relaxed);
    snapshot.successfulCompletions.store(stats.successfulCompletions.load(std::memory_order_relaxed), std::memory_order_relaxed);
    snapshot.timeouts.store(stats.timeouts.load(std::memory_order_relaxed), std::memory_order_relaxed);
    snapshot.errors.store(stats.errors.load(std::memory_order_relaxed), std::memory_order_relaxed);
    snapshot.malwareDetections.store(stats.malwareDetections.load(std::memory_order_relaxed), std::memory_order_relaxed);
    snapshot.successfulUnpacks.store(stats.successfulUnpacks.load(std::memory_order_relaxed), std::memory_order_relaxed);
    snapshot.totalInstructions.store(stats.totalInstructions.load(std::memory_order_relaxed), std::memory_order_relaxed);
    snapshot.totalAPICalls.store(stats.totalAPICalls.load(std::memory_order_relaxed), std::memory_order_relaxed);
    snapshot.totalFilesCaptured.store(stats.totalFilesCaptured.load(std::memory_order_relaxed), std::memory_order_relaxed);
    snapshot.activeSessions.store(stats.activeSessions.load(std::memory_order_relaxed), std::memory_order_relaxed);
    snapshot.avgEmulationTimeUs.store(stats.avgEmulationTimeUs.load(std::memory_order_relaxed), std::memory_order_relaxed);
    snapshot.phantomEmulatorAvailable = stats.phantomEmulatorAvailable;
    return snapshot;
}

[[nodiscard]] std::optional<APICallRecord> HighestSeverityAPI(const std::vector<APICallRecord>& calls) {
    if (calls.empty()) {
        return std::nullopt;
    }

    return *std::max_element(calls.begin(), calls.end(),
        [](const APICallRecord& lhs, const APICallRecord& rhs) {
            return static_cast<uint8_t>(lhs.severity) < static_cast<uint8_t>(rhs.severity);
        });
}

[[nodiscard]] EmulationResult BuildInputErrorResult(uint64_t sessionId, std::wstring_view message, EmulationArch arch) {
    EmulationResult result;
    result.sessionId = sessionId;
    result.backend = EmulationBackend::PhantomEmulator;
    result.architecture = arch;
    result.state = EmulationState::Error;
    result.exitReason = EmulationExitReason::InternalError;
    result.errorMessage.assign(message);
    result.startTime = std::chrono::system_clock::now();
    result.endTime = result.startTime;
    return result;
}

} // namespace

class EmulationEngine::Impl {
public:
    mutable std::shared_mutex m_mutex;
    std::atomic<bool> m_initialized{ false };

    std::shared_ptr<Utils::ThreadPool> m_threadPool;
    SignatureStore::SignatureStore* m_signatureStore = nullptr;
    PatternStore::PatternStore* m_patternStore = nullptr;
    HashStore::HashStore* m_hashStore = nullptr;
    ThreatIntel::ThreatIntelIndex* m_threatIntel = nullptr;

    EmulationStats m_stats;
    EmulationConfig m_defaultConfig;

    struct ActiveSession {
        uint64_t sessionId = 0;
        EmulationConfig config;
        std::atomic<EmulationState> state{ EmulationState::Uninitialized };
        std::atomic<uint64_t> instructionCount{ 0 };
        std::atomic<size_t> apiCallCount{ 0 };
        EmulationBackend backend = EmulationBackend::PhantomEmulator;
        std::chrono::steady_clock::time_point startTime;
        std::atomic<bool> shouldStop{ false };
#ifdef PHANTOM_EMULATOR_AVAILABLE
        std::unique_ptr<Phantom::EmulationSession> phantomSession;
#endif
    };

    std::unordered_map<uint64_t, std::unique_ptr<ActiveSession>> m_sessions;
    std::atomic<uint64_t> m_nextSessionId{ 1 };

    struct CallbackStore {
        std::unordered_map<uint64_t, APICallCallback> apiCallbacks;
        std::unordered_map<uint64_t, FileDropCallback> fileDropCallbacks;
        std::unordered_map<uint64_t, NetworkActivityCallback> networkCallbacks;
        std::unordered_map<uint64_t, UnpackLayerCallback> unpackCallbacks;
        std::atomic<uint64_t> nextId{ 1 };
    } m_callbacks;

    bool Initialize(std::shared_ptr<Utils::ThreadPool> tp,
                    SignatureStore::SignatureStore* ss,
                    PatternStore::PatternStore* ps,
                    HashStore::HashStore* hs,
                    ThreatIntel::ThreatIntelIndex* ti) noexcept;
    void Shutdown() noexcept;

    EmulationResult RunPE(std::span<const uint8_t> data, const EmulationConfig& config) noexcept;
    EmulationResult RunShellcode(std::span<const uint8_t> data, bool is64, const EmulationConfig& config) noexcept;
    EmulationResult RunBuffer(std::span<const uint8_t> data, uint64_t base, uint64_t entry, EmulationArch arch, const EmulationConfig& config) noexcept;

#ifdef PHANTOM_EMULATOR_AVAILABLE
    Phantom::EmulationConfig ConvertConfig(const EmulationConfig& cfg) const noexcept;
    EmulationResult ConvertAndEnrich(const Phantom::PhantomEmulationResult& pr, uint64_t sessionId) noexcept;
    void FireCallbacks(const EmulationResult& result) noexcept;
#endif

    uint64_t CreateSession(const EmulationConfig& config) noexcept;
    void RemoveSession(uint64_t sessionId, bool revertCreate = false) noexcept;
    ActiveSession* GetSessionEntry(uint64_t sessionId) noexcept;
    void FinalizeSession(uint64_t sessionId, const EmulationResult& result) noexcept;
    void UpdateAverageTime(uint64_t emulationTimeUs) noexcept;
    EmulationResult RunPE(std::span<const uint8_t> data, const EmulationConfig& config, uint64_t sessionId) noexcept;
    EmulationResult RunShellcode(std::span<const uint8_t> data, bool is64, const EmulationConfig& config, uint64_t sessionId) noexcept;
    EmulationResult RunBuffer(std::span<const uint8_t> data, uint64_t base, uint64_t entry, EmulationArch arch, const EmulationConfig& config, uint64_t sessionId) noexcept;
};

bool EmulationEngine::Impl::Initialize(std::shared_ptr<Utils::ThreadPool> tp,
                                       SignatureStore::SignatureStore* ss,
                                       PatternStore::PatternStore* ps,
                                       HashStore::HashStore* hs,
                                       ThreatIntel::ThreatIntelIndex* ti) noexcept {
    try {
        if (!tp) {
            SS_LOG_ERROR(kLogCategory, L"Initialize: thread pool is required");
            return false;
        }

        if (m_initialized.exchange(true, std::memory_order_acq_rel)) {
            return true;
        }

        {
            std::unique_lock lock(m_mutex);
            m_threadPool = std::move(tp);
            m_signatureStore = ss;
            m_patternStore = ps;
            m_hashStore = hs;
            m_threatIntel = ti;
            m_defaultConfig = EmulationConfig::CreateDefault();
            m_stats.phantomEmulatorAvailable = true;
        }

        SS_LOG_INFO(kLogCategory, L"Initialized with PhantomEmulator backend");
        return true;
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(kLogCategory, L"Initialize exception: %ls", ToWide(ex.what()).c_str());
        m_initialized.store(false, std::memory_order_release);
        return false;
    } catch (...) {
        SS_LOG_ERROR(kLogCategory, L"Initialize exception: unknown error");
        m_initialized.store(false, std::memory_order_release);
        return false;
    }
}

void EmulationEngine::Impl::Shutdown() noexcept {
    try {
        if (!m_initialized.exchange(false, std::memory_order_acq_rel)) {
            return;
        }

        std::vector<ActiveSession*> sessions;
        {
            std::shared_lock lock(m_mutex);
            sessions.reserve(m_sessions.size());
            for (const auto& [sessionId, session] : m_sessions) {
                (void)sessionId;
                sessions.push_back(session.get());
            }
        }

        for (auto* session : sessions) {
            session->shouldStop.store(true, std::memory_order_release);
            session->state.store(EmulationState::Terminated, std::memory_order_release);
#ifdef PHANTOM_EMULATOR_AVAILABLE
            if (session->phantomSession) {
                session->phantomSession->RequestAbort();
            }
#endif
        }

        {
            std::unique_lock lock(m_mutex);
            m_threadPool.reset();
            m_signatureStore = nullptr;
            m_patternStore = nullptr;
            m_hashStore = nullptr;
            m_threatIntel = nullptr;
        }

        SS_LOG_INFO(kLogCategory, L"Shutdown requested");
    } catch (...) {
        SS_LOG_ERROR(kLogCategory, L"Shutdown exception");
    }
}

uint64_t EmulationEngine::Impl::CreateSession(const EmulationConfig& config) noexcept {
    try {
        auto session = std::make_unique<ActiveSession>();
        const uint64_t sessionId = m_nextSessionId.fetch_add(1, std::memory_order_relaxed);
        session->sessionId = sessionId;
        session->config = config;
        session->state.store(EmulationState::Ready, std::memory_order_relaxed);
        session->startTime = std::chrono::steady_clock::now();

        {
            std::unique_lock lock(m_mutex);
            m_sessions.emplace(sessionId, std::move(session));
        }

        m_stats.totalSessions.fetch_add(1, std::memory_order_relaxed);
        m_stats.activeSessions.fetch_add(1, std::memory_order_relaxed);
        return sessionId;
    } catch (...) {
        return 0;
    }
}

void EmulationEngine::Impl::RemoveSession(uint64_t sessionId, bool revertCreate) noexcept {
    std::unique_lock lock(m_mutex);
    const auto erased = m_sessions.erase(sessionId);
    lock.unlock();

    if (revertCreate && erased > 0) {
        m_stats.totalSessions.fetch_sub(1, std::memory_order_relaxed);
        m_stats.activeSessions.fetch_sub(1, std::memory_order_relaxed);
    }
}

EmulationEngine::Impl::ActiveSession* EmulationEngine::Impl::GetSessionEntry(uint64_t sessionId) noexcept {
    std::shared_lock lock(m_mutex);
    const auto it = m_sessions.find(sessionId);
    return it != m_sessions.end() ? it->second.get() : nullptr;
}

void EmulationEngine::Impl::UpdateAverageTime(uint64_t emulationTimeUs) noexcept {
    const uint64_t active = m_stats.activeSessions.load(std::memory_order_relaxed);
    const uint64_t completed = m_stats.totalSessions.load(std::memory_order_relaxed) - active;
    if (completed == 0) {
        return;
    }

    const uint64_t previous = m_stats.avgEmulationTimeUs.load(std::memory_order_relaxed);
    const uint64_t updated = previous + ((emulationTimeUs > previous)
        ? (emulationTimeUs - previous) / completed
        : -((previous - emulationTimeUs) / completed));
    m_stats.avgEmulationTimeUs.store(updated, std::memory_order_relaxed);
}

void EmulationEngine::Impl::FinalizeSession(uint64_t sessionId, const EmulationResult& result) noexcept {
    if (auto* session = GetSessionEntry(sessionId)) {
        session->instructionCount.store(result.instructionsExecuted, std::memory_order_relaxed);
        session->apiCallCount.store(result.apiCallCount, std::memory_order_relaxed);
        session->state.store(result.state, std::memory_order_relaxed);
    }

    m_stats.activeSessions.fetch_sub(1, std::memory_order_relaxed);

    if (result.exitReason == EmulationExitReason::Timeout || result.state == EmulationState::Timeout) {
        m_stats.timeouts.fetch_add(1, std::memory_order_relaxed);
    } else if (result.state == EmulationState::Error ||
               result.exitReason == EmulationExitReason::InternalError ||
               result.exitReason == EmulationExitReason::Exception ||
               result.exitReason == EmulationExitReason::InvalidInstruction ||
               result.exitReason == EmulationExitReason::AccessViolation ||
               result.exitReason == EmulationExitReason::PrivilegedInstruction) {
        m_stats.errors.fetch_add(1, std::memory_order_relaxed);
    } else {
        m_stats.successfulCompletions.fetch_add(1, std::memory_order_relaxed);
    }

    if (result.isMalicious) {
        m_stats.malwareDetections.fetch_add(1, std::memory_order_relaxed);
    }
    if (result.unpackSuccessful) {
        m_stats.successfulUnpacks.fetch_add(1, std::memory_order_relaxed);
    }

    m_stats.totalInstructions.fetch_add(result.instructionsExecuted, std::memory_order_relaxed);
    m_stats.totalAPICalls.fetch_add(static_cast<uint64_t>(result.apiCallCount), std::memory_order_relaxed);
    m_stats.totalFilesCaptured.fetch_add(static_cast<uint64_t>(result.droppedFiles.size()), std::memory_order_relaxed);
    UpdateAverageTime(result.emulationTimeMs * 1000ULL);
}

#ifdef PHANTOM_EMULATOR_AVAILABLE
Phantom::EmulationConfig EmulationEngine::Impl::ConvertConfig(const EmulationConfig& cfg) const noexcept {
    Phantom::EmulationConfig converted;
    converted.maxInstructions = cfg.maxInstructions;
    converted.maxAPIcalls = static_cast<uint64_t>(cfg.maxAPICalls);
    converted.maxWallTime = std::chrono::milliseconds(cfg.timeoutMs);
    converted.maxGuestMemory = cfg.memoryLimit;
    converted.maxUnpackLayers = cfg.maxUnpackLayers;
    converted.enableFileSystem = cfg.enableFileSystemMonitoring;
    converted.enableRegistry = cfg.enableRegistryMonitoring;
    converted.enableNetwork = cfg.enableNetworkMonitoring && cfg.simulateNetwork;
    converted.enableUnpacking = cfg.enableUnpacking;
    converted.captureUnpackLayers = cfg.saveUnpackedPayload;
    converted.enableTimingAcceleration = cfg.hookTimingAPIs;
    converted.enableAntiDebugBypass = cfg.enableAntiEvasion;
    converted.enableAntiVMBypass = cfg.hideEmulationArtifacts;
    converted.enableAntiSandboxBypass = cfg.realisticEnvironment;
    converted.enableBehaviorMonitor = true;
    converted.enableAPISequenceAnalysis = true;
    converted.enableMemoryForensics = cfg.enableMemoryScanning;
    converted.enableMITREMapping = cfg.enableMitreMapping;
    converted.enableIOCExtraction = true;
    converted.enableAPITrace = cfg.enableAPITracing;
    converted.enableInstructionTrace = cfg.instructionTracing;
    converted.enableMemoryTrace = cfg.memoryAccessTracing;
    converted.trackMemoryAccess = cfg.memoryAccessTracing;
    converted.target = (cfg.targetArch == EmulationArch::X86 || cfg.force32Bit)
        ? Phantom::EmulationTarget::PE32
        : Phantom::EmulationTarget::PE64;
    converted.cpuMode = (cfg.targetArch == EmulationArch::X86 || cfg.force32Bit)
        ? Phantom::CPUMode::Protected32
        : Phantom::CPUMode::Long64;
    return converted;
}

EmulationResult EmulationEngine::Impl::ConvertAndEnrich(const Phantom::PhantomEmulationResult& pr,
                                                        uint64_t sessionId) noexcept {
    Phantom::Integration::PhantomEmulationResult bridge{};
    bridge.stopReason = pr.execution.stopReason;
    bridge.target = pr.execution.is64Bit ? Phantom::EmulationTarget::PE64 : Phantom::EmulationTarget::PE32;
    bridge.instructionsExecuted = pr.execution.instructionsExecuted;
    bridge.emulationTimeMs = pr.execution.wallTimeMs;
    bridge.peakMemoryUsage = pr.execution.peakMemoryUsage;
    bridge.contextSwitches = 0;
    bridge.exceptionsHandled = 0;
    bridge.verdict = const_cast<Phantom::ThreatVerdict*>(&pr.verdict);
    bridge.apiCalls = pr.apiCalls;
    bridge.behaviorAlerts = pr.behaviorAlerts;
    bridge.mitreTechniques = pr.mitreTechniques;
    bridge.unpackLayers = pr.unpacking.layers;
    bridge.unpackedPayload = pr.unpacking.finalPayload;
    bridge.unpackSuccessful = pr.unpacking.successful;
    bridge.unpackedSha256.clear();
    bridge.iocReport = &pr.iocReport;
    bridge.memoryFindings = pr.memoryFindings;
    bridge.memoryRegions = {};
    bridge.networkConnections = pr.network.connections;
    bridge.networkAlerts = pr.network.alerts;
    bridge.evasionAttempts = pr.evasionAttempts;
    bridge.evasionSummary = &pr.evasionSummary;
    bridge.yaraMatches = {};
    bridge.memoryYaraMatches = {};
    bridge.patternMatches = {};
    bridge.sessionId = sessionId;

    auto result = Phantom::Integration::ResultConverter::Convert(bridge);
    result.backend = EmulationBackend::PhantomEmulator;
    result.sessionId = sessionId;
    result.endTime = std::chrono::system_clock::now();
    result.startTime = result.endTime - std::chrono::milliseconds(result.emulationTimeMs);

    if (!pr.success) {
        result.emulationComplete = false;
        if (result.errorMessage.empty()) {
            result.errorMessage = ToWide(pr.errorMessage);
        }
        if (result.state != EmulationState::Timeout && result.state != EmulationState::Terminated) {
            result.state = EmulationState::Error;
            result.exitReason = EmulationExitReason::InternalError;
        }
    }

    return result;
}

void EmulationEngine::Impl::FireCallbacks(const EmulationResult& result) noexcept {
    std::vector<APICallCallback> apiCallbacks;
    std::vector<FileDropCallback> fileCallbacks;
    std::vector<NetworkActivityCallback> networkCallbacks;
    std::vector<UnpackLayerCallback> unpackCallbacks;

    {
        std::shared_lock lock(m_mutex);
        apiCallbacks.reserve(m_callbacks.apiCallbacks.size());
        fileCallbacks.reserve(m_callbacks.fileDropCallbacks.size());
        networkCallbacks.reserve(m_callbacks.networkCallbacks.size());
        unpackCallbacks.reserve(m_callbacks.unpackCallbacks.size());

        for (const auto& [id, cb] : m_callbacks.apiCallbacks) {
            (void)id;
            apiCallbacks.push_back(cb);
        }
        for (const auto& [id, cb] : m_callbacks.fileDropCallbacks) {
            (void)id;
            fileCallbacks.push_back(cb);
        }
        for (const auto& [id, cb] : m_callbacks.networkCallbacks) {
            (void)id;
            networkCallbacks.push_back(cb);
        }
        for (const auto& [id, cb] : m_callbacks.unpackCallbacks) {
            (void)id;
            unpackCallbacks.push_back(cb);
        }
    }

    for (const auto& cb : apiCallbacks) {
        for (const auto& call : result.apiCalls) {
            try { cb(call); } catch (...) {}
        }
    }
    for (const auto& cb : fileCallbacks) {
        for (const auto& file : result.droppedFiles) {
            try { cb(file); } catch (...) {}
        }
    }
    for (const auto& cb : networkCallbacks) {
        for (const auto& net : result.networkActivities) {
            try { cb(net); } catch (...) {}
        }
    }
    for (const auto& cb : unpackCallbacks) {
        for (const auto& layer : result.unpackLayers) {
            try { cb(layer); } catch (...) {}
        }
    }
}
#endif

EmulationResult EmulationEngine::Impl::RunPE(std::span<const uint8_t> data, const EmulationConfig& config) noexcept {
    return RunPE(data, config, 0);
}

EmulationResult EmulationEngine::Impl::RunPE(std::span<const uint8_t> data,
                                             const EmulationConfig& config,
                                             uint64_t sessionId) noexcept {
    EmulationResult result;
    const uint64_t sid = sessionId != 0 ? sessionId : CreateSession(config);
    if (sid == 0) {
        return BuildInputErrorResult(0, L"Failed to create emulation session", EmulationArch::X64);
    }

    auto* active = GetSessionEntry(sid);
    if (!active) {
        return BuildInputErrorResult(sid, L"Failed to locate emulation session", EmulationArch::X64);
    }

    active->state.store(EmulationState::Running, std::memory_order_relaxed);
    active->startTime = std::chrono::steady_clock::now();
    active->config = config;

    try {
        if (!m_initialized.load(std::memory_order_acquire)) {
            result = BuildInputErrorResult(sid, L"EmulationEngine is not initialized", EmulationArch::X64);
        } else if (data.empty()) {
            result = BuildInputErrorResult(sid, L"PE input buffer is empty", EmulationArch::X64);
        } else if (active->shouldStop.load(std::memory_order_acquire)) {
            result = BuildInputErrorResult(sid, L"Session terminated before execution", EmulationArch::X64);
            result.state = EmulationState::Terminated;
            result.exitReason = EmulationExitReason::UserTerminated;
#ifdef PHANTOM_EMULATOR_AVAILABLE
        } else {
            const auto phantomConfig = ConvertConfig(config);
            active->phantomSession = std::make_unique<Phantom::EmulationSession>(phantomConfig);
            if (active->shouldStop.load(std::memory_order_acquire)) {
                active->phantomSession->RequestAbort();
            }

            const auto phantomResult = active->phantomSession->EmulatePE(data);
            result = ConvertAndEnrich(phantomResult, sid);
#else
        } else {
            result = BuildInputErrorResult(sid, L"PhantomEmulator not available in this build", EmulationArch::X64);
#endif
        }
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(kLogCategory, L"RunPE exception: %ls", ToWide(ex.what()).c_str());
        result = BuildInputErrorResult(sid, L"PE emulation raised an exception", EmulationArch::X64);
    } catch (...) {
        SS_LOG_ERROR(kLogCategory, L"RunPE exception: unknown error");
        result = BuildInputErrorResult(sid, L"PE emulation raised an unknown exception", EmulationArch::X64);
    }

    result.sessionId = sid;
    result.backend = EmulationBackend::PhantomEmulator;
    result.inputSize = data.size();
    if (result.endTime == std::chrono::system_clock::time_point{}) {
        result.endTime = std::chrono::system_clock::now();
    }
    if (result.startTime == std::chrono::system_clock::time_point{}) {
        result.startTime = result.endTime - std::chrono::milliseconds(result.emulationTimeMs);
    }
    if (result.architecture == EmulationArch::X64 && (config.force32Bit || config.targetArch == EmulationArch::X86)) {
        result.architecture = EmulationArch::X86;
    }

    FinalizeSession(sid, result);
#ifdef PHANTOM_EMULATOR_AVAILABLE
    FireCallbacks(result);
#endif
    RemoveSession(sid);
    return result;
}

EmulationResult EmulationEngine::Impl::RunShellcode(std::span<const uint8_t> data,
                                                    bool is64,
                                                    const EmulationConfig& config) noexcept {
    return RunShellcode(data, is64, config, 0);
}

EmulationResult EmulationEngine::Impl::RunShellcode(std::span<const uint8_t> data,
                                                    bool is64,
                                                    const EmulationConfig& config,
                                                    uint64_t sessionId) noexcept {
    EmulationConfig effectiveConfig = config;
    effectiveConfig.mode = EmulationMode::Shellcode;
    effectiveConfig.targetArch = is64 ? EmulationArch::X64 : EmulationArch::X86;
    effectiveConfig.force32Bit = !is64;

    EmulationResult result;
    const uint64_t sid = sessionId != 0 ? sessionId : CreateSession(effectiveConfig);
    if (sid == 0) {
        return BuildInputErrorResult(0, L"Failed to create emulation session", effectiveConfig.targetArch);
    }

    auto* active = GetSessionEntry(sid);
    if (!active) {
        return BuildInputErrorResult(sid, L"Failed to locate emulation session", effectiveConfig.targetArch);
    }

    active->state.store(EmulationState::Running, std::memory_order_relaxed);
    active->startTime = std::chrono::steady_clock::now();
    active->config = effectiveConfig;

    try {
        if (!m_initialized.load(std::memory_order_acquire)) {
            result = BuildInputErrorResult(sid, L"EmulationEngine is not initialized", effectiveConfig.targetArch);
        } else if (data.empty()) {
            result = BuildInputErrorResult(sid, L"Shellcode input buffer is empty", effectiveConfig.targetArch);
        } else if (active->shouldStop.load(std::memory_order_acquire)) {
            result = BuildInputErrorResult(sid, L"Session terminated before execution", effectiveConfig.targetArch);
            result.state = EmulationState::Terminated;
            result.exitReason = EmulationExitReason::UserTerminated;
#ifdef PHANTOM_EMULATOR_AVAILABLE
        } else {
            auto phantomConfig = ConvertConfig(effectiveConfig);
            phantomConfig.cpuMode = is64 ? Phantom::CPUMode::Long64 : Phantom::CPUMode::Protected32;
            phantomConfig.target = is64 ? Phantom::EmulationTarget::Shellcode64 : Phantom::EmulationTarget::Shellcode32;
            active->phantomSession = std::make_unique<Phantom::EmulationSession>(phantomConfig);
            if (active->shouldStop.load(std::memory_order_acquire)) {
                active->phantomSession->RequestAbort();
            }

            const auto phantomResult = active->phantomSession->EmulateShellcode(data, is64);
            result = ConvertAndEnrich(phantomResult, sid);
#else
        } else {
            result = BuildInputErrorResult(sid, L"PhantomEmulator not available in this build", effectiveConfig.targetArch);
#endif
        }
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(kLogCategory, L"RunShellcode exception: %ls", ToWide(ex.what()).c_str());
        result = BuildInputErrorResult(sid, L"Shellcode emulation raised an exception", effectiveConfig.targetArch);
    } catch (...) {
        SS_LOG_ERROR(kLogCategory, L"RunShellcode exception: unknown error");
        result = BuildInputErrorResult(sid, L"Shellcode emulation raised an unknown exception", effectiveConfig.targetArch);
    }

    result.sessionId = sid;
    result.backend = EmulationBackend::PhantomEmulator;
    result.architecture = effectiveConfig.targetArch;
    result.inputSize = data.size();
    if (result.endTime == std::chrono::system_clock::time_point{}) {
        result.endTime = std::chrono::system_clock::now();
    }
    if (result.startTime == std::chrono::system_clock::time_point{}) {
        result.startTime = result.endTime - std::chrono::milliseconds(result.emulationTimeMs);
    }

    FinalizeSession(sid, result);
#ifdef PHANTOM_EMULATOR_AVAILABLE
    FireCallbacks(result);
#endif
    RemoveSession(sid);
    return result;
}

EmulationResult EmulationEngine::Impl::RunBuffer(std::span<const uint8_t> data,
                                                 uint64_t base,
                                                 uint64_t entry,
                                                 EmulationArch arch,
                                                 const EmulationConfig& config) noexcept {
    return RunBuffer(data, base, entry, arch, config, 0);
}

EmulationResult EmulationEngine::Impl::RunBuffer(std::span<const uint8_t> data,
                                                 uint64_t base,
                                                 uint64_t entry,
                                                 EmulationArch arch,
                                                 const EmulationConfig& config,
                                                 uint64_t sessionId) noexcept {
    EmulationConfig effectiveConfig = config;
    effectiveConfig.targetArch = arch;
    effectiveConfig.force32Bit = arch == EmulationArch::X86;

    EmulationResult result;
    const uint64_t sid = sessionId != 0 ? sessionId : CreateSession(effectiveConfig);
    if (sid == 0) {
        return BuildInputErrorResult(0, L"Failed to create emulation session", arch);
    }

    auto* active = GetSessionEntry(sid);
    if (!active) {
        return BuildInputErrorResult(sid, L"Failed to locate emulation session", arch);
    }

    active->state.store(EmulationState::Running, std::memory_order_relaxed);
    active->startTime = std::chrono::steady_clock::now();
    active->config = effectiveConfig;

    try {
        if (!m_initialized.load(std::memory_order_acquire)) {
            result = BuildInputErrorResult(sid, L"EmulationEngine is not initialized", arch);
        } else if (data.empty()) {
            result = BuildInputErrorResult(sid, L"Buffer input is empty", arch);
        } else if (active->shouldStop.load(std::memory_order_acquire)) {
            result = BuildInputErrorResult(sid, L"Session terminated before execution", arch);
            result.state = EmulationState::Terminated;
            result.exitReason = EmulationExitReason::UserTerminated;
#ifdef PHANTOM_EMULATOR_AVAILABLE
        } else {
            auto phantomConfig = ConvertConfig(effectiveConfig);
            phantomConfig.cpuMode = arch == EmulationArch::X86 ? Phantom::CPUMode::Protected32 : Phantom::CPUMode::Long64;
            phantomConfig.target = arch == EmulationArch::X86 ? Phantom::EmulationTarget::Shellcode32 : Phantom::EmulationTarget::Shellcode64;
            active->phantomSession = std::make_unique<Phantom::EmulationSession>(phantomConfig);
            if (active->shouldStop.load(std::memory_order_acquire)) {
                active->phantomSession->RequestAbort();
            }

            const auto phantomResult = active->phantomSession->EmulateBuffer(data, base, entry, arch == EmulationArch::X64);
            result = ConvertAndEnrich(phantomResult, sid);
#else
        } else {
            result = BuildInputErrorResult(sid, L"PhantomEmulator not available in this build", arch);
#endif
        }
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(kLogCategory, L"RunBuffer exception: %ls", ToWide(ex.what()).c_str());
        result = BuildInputErrorResult(sid, L"Buffer emulation raised an exception", arch);
    } catch (...) {
        SS_LOG_ERROR(kLogCategory, L"RunBuffer exception: unknown error");
        result = BuildInputErrorResult(sid, L"Buffer emulation raised an unknown exception", arch);
    }

    result.sessionId = sid;
    result.backend = EmulationBackend::PhantomEmulator;
    result.architecture = arch;
    result.inputSize = data.size();
    if (result.endTime == std::chrono::system_clock::time_point{}) {
        result.endTime = std::chrono::system_clock::now();
    }
    if (result.startTime == std::chrono::system_clock::time_point{}) {
        result.startTime = result.endTime - std::chrono::milliseconds(result.emulationTimeMs);
    }

    FinalizeSession(sid, result);
#ifdef PHANTOM_EMULATOR_AVAILABLE
    FireCallbacks(result);
#endif
    RemoveSession(sid);
    return result;
}

uint32_t CPUState::GetReg32(const std::string& name) const noexcept {
    return static_cast<uint32_t>(GetReg64(name) & 0xFFFFFFFFULL);
}

uint64_t CPUState::GetReg64(const std::string& name) const noexcept {
    const auto reg = ToLowerAscii(name);
    if (reg == "rax" || reg == "eax") return rax;
    if (reg == "rbx" || reg == "ebx") return rbx;
    if (reg == "rcx" || reg == "ecx") return rcx;
    if (reg == "rdx" || reg == "edx") return rdx;
    if (reg == "rsi" || reg == "esi") return rsi;
    if (reg == "rdi" || reg == "edi") return rdi;
    if (reg == "rbp" || reg == "ebp") return rbp;
    if (reg == "rsp" || reg == "esp") return rsp;
    if (reg == "rip" || reg == "eip") return rip;
    if (reg == "r8") return r8;
    if (reg == "r9") return r9;
    if (reg == "r10") return r10;
    if (reg == "r11") return r11;
    if (reg == "r12") return r12;
    if (reg == "r13") return r13;
    if (reg == "r14") return r14;
    if (reg == "r15") return r15;
    if (reg == "rflags" || reg == "eflags") return rflags;
    return 0;
}

void CPUState::SetReg(const std::string& name, uint64_t value) noexcept {
    const auto reg = ToLowerAscii(name);
    if (reg == "rax" || reg == "eax") rax = value;
    else if (reg == "rbx" || reg == "ebx") rbx = value;
    else if (reg == "rcx" || reg == "ecx") rcx = value;
    else if (reg == "rdx" || reg == "edx") rdx = value;
    else if (reg == "rsi" || reg == "esi") rsi = value;
    else if (reg == "rdi" || reg == "edi") rdi = value;
    else if (reg == "rbp" || reg == "ebp") rbp = value;
    else if (reg == "rsp" || reg == "esp") rsp = value;
    else if (reg == "rip" || reg == "eip") rip = value;
    else if (reg == "r8") r8 = value;
    else if (reg == "r9") r9 = value;
    else if (reg == "r10") r10 = value;
    else if (reg == "r11") r11 = value;
    else if (reg == "r12") r12 = value;
    else if (reg == "r13") r13 = value;
    else if (reg == "r14") r14 = value;
    else if (reg == "r15") r15 = value;
    else if (reg == "rflags" || reg == "eflags") rflags = value;
}

std::string CPUState::ToString() const {
    std::ostringstream stream;
    stream << "RIP=0x" << std::hex << rip
           << " RSP=0x" << rsp
           << " RAX=0x" << rax
           << " RBX=0x" << rbx
           << " RCX=0x" << rcx
           << " RDX=0x" << rdx;
    return stream.str();
}

std::wstring EmulationResult::GetSummary() const {
    std::wstringstream stream;
    stream << L"Session " << sessionId
           << L" | State=" << ToWide(EmulationStateToString(state))
           << L" | Backend=" << ToWide(EmulationBackendToString(backend))
           << L" | Instructions=" << instructionsExecuted
           << L" | APIs=" << apiCallCount;

    if (isMalicious) {
        stream << L" | Verdict=Malicious";
        if (!threatName.empty()) {
            stream << L" (" << ToWide(threatName) << L")";
        }
    } else {
        stream << L" | Verdict=Clean";
    }

    return stream.str();
}

std::optional<APICallRecord> EmulationResult::GetHighestSeverityAPI() const {
    return HighestSeverityAPI(apiCalls);
}

void EmulationResult::Clear() noexcept {
    *this = EmulationResult{};
}

EmulationEngine& EmulationEngine::Instance() {
    static EmulationEngine instance;
    return instance;
}

EmulationEngine::EmulationEngine()
    : m_impl(std::make_unique<Impl>()) {
}

EmulationEngine::~EmulationEngine() {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

bool EmulationEngine::Initialize(std::shared_ptr<Utils::ThreadPool> threadPool) {
    return m_impl->Initialize(std::move(threadPool), nullptr, nullptr, nullptr, nullptr);
}

bool EmulationEngine::Initialize(std::shared_ptr<Utils::ThreadPool> threadPool,
                                 SignatureStore::SignatureStore* signatureStore,
                                 PatternStore::PatternStore* patternStore,
                                 HashStore::HashStore* hashStore,
                                 ThreatIntel::ThreatIntelIndex* threatIntel) {
    return m_impl->Initialize(std::move(threadPool), signatureStore, patternStore, hashStore, threatIntel);
}

void EmulationEngine::Shutdown() {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

bool EmulationEngine::IsInitialized() const noexcept {
    return m_impl && m_impl->m_initialized.load(std::memory_order_acquire);
}

bool EmulationEngine::IsHardwareAccelerationAvailable() const noexcept {
    return false;
}

std::vector<EmulationBackend> EmulationEngine::GetAvailableBackends() const {
    return { EmulationBackend::PhantomEmulator };
}

EmulationResult EmulationEngine::EmulatePE(const std::vector<uint8_t>& fileData, const EmulationConfig& config) {
    return m_impl->RunPE(std::span<const uint8_t>(fileData), config);
}

EmulationResult EmulationEngine::EmulatePE(std::span<const uint8_t> fileData, const EmulationConfig& config) {
    return m_impl->RunPE(fileData, config);
}

uint64_t EmulationEngine::EmulatePEAsync(std::vector<uint8_t> fileData,
                                         const EmulationConfig& config,
                                         EmulationCompleteCallback callback) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire) || !m_impl->m_threadPool) {
        return 0;
    }

    const uint64_t sessionId = m_impl->CreateSession(config);
    if (sessionId == 0) {
        return 0;
    }

    try {
        auto* implPtr = m_impl.get();
        m_impl->m_threadPool->Submit(
            [implPtr, fileData = std::move(fileData), config, callback = std::move(callback), sessionId](const Utils::TaskContext&) mutable {
                auto result = implPtr->RunPE(std::span<const uint8_t>(fileData), config, sessionId);
                result.sessionId = sessionId;
                if (callback) {
                    try { callback(result); } catch (...) {}
                }
                return result.sessionId;
            },
            Utils::TaskPriority::Normal,
            "EmulatePEAsync");
        return sessionId;
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(kLogCategory, L"EmulatePEAsync submit failed: %ls", ToWide(ex.what()).c_str());
        m_impl->RemoveSession(sessionId, true);
        return 0;
    } catch (...) {
        SS_LOG_ERROR(kLogCategory, L"EmulatePEAsync submit failed: unknown error");
        m_impl->RemoveSession(sessionId, true);
        return 0;
    }
}

EmulationResult EmulationEngine::EmulatePE(const std::vector<uint8_t>& fileData,
                                           uint32_t timeoutMs,
                                           uint64_t maxInstructions) {
    EmulationConfig config = GetDefaultConfig();
    config.timeoutMs = timeoutMs;
    config.maxInstructions = maxInstructions;
    return m_impl->RunPE(std::span<const uint8_t>(fileData), config);
}

EmulationResult EmulationEngine::EmulateShellcode(const std::vector<uint8_t>& code,
                                                  bool is64Bit,
                                                  const EmulationConfig& config) {
    return m_impl->RunShellcode(std::span<const uint8_t>(code), is64Bit, config);
}

EmulationResult EmulationEngine::EmulateShellcode(std::span<const uint8_t> code,
                                                  bool is64Bit,
                                                  const EmulationConfig& config) {
    return m_impl->RunShellcode(code, is64Bit, config);
}

uint64_t EmulationEngine::EmulateShellcodeAsync(std::vector<uint8_t> code,
                                                bool is64Bit,
                                                const EmulationConfig& config,
                                                EmulationCompleteCallback callback) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire) || !m_impl->m_threadPool) {
        return 0;
    }

    EmulationConfig effectiveConfig = config;
    effectiveConfig.mode = EmulationMode::Shellcode;
    effectiveConfig.targetArch = is64Bit ? EmulationArch::X64 : EmulationArch::X86;
    effectiveConfig.force32Bit = !is64Bit;

    const uint64_t sessionId = m_impl->CreateSession(effectiveConfig);
    if (sessionId == 0) {
        return 0;
    }

    try {
        auto* implPtr = m_impl.get();
        m_impl->m_threadPool->Submit(
            [implPtr, code = std::move(code), is64Bit, config = effectiveConfig, callback = std::move(callback), sessionId](const Utils::TaskContext&) mutable {
                auto result = implPtr->RunShellcode(std::span<const uint8_t>(code), is64Bit, config, sessionId);
                result.sessionId = sessionId;
                if (callback) {
                    try { callback(result); } catch (...) {}
                }
                return result.sessionId;
            },
            Utils::TaskPriority::Normal,
            "EmulateShellcodeAsync");
        return sessionId;
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(kLogCategory, L"EmulateShellcodeAsync submit failed: %ls", ToWide(ex.what()).c_str());
        m_impl->RemoveSession(sessionId, true);
        return 0;
    } catch (...) {
        SS_LOG_ERROR(kLogCategory, L"EmulateShellcodeAsync submit failed: unknown error");
        m_impl->RemoveSession(sessionId, true);
        return 0;
    }
}

EmulationResult EmulationEngine::EmulateBuffer(std::span<const uint8_t> buffer,
                                               uint64_t baseAddress,
                                               uint64_t entryPoint,
                                               EmulationArch arch,
                                               const EmulationConfig& config) {
    return m_impl->RunBuffer(buffer, baseAddress, entryPoint, arch, config);
}

EmulationResult EmulationEngine::UnpackPE(const std::vector<uint8_t>& fileData, const EmulationConfig& config) {
    EmulationConfig unpackConfig = config;
    unpackConfig.mode = EmulationMode::UnpackOnly;
    unpackConfig.enableUnpacking = true;
    return m_impl->RunPE(std::span<const uint8_t>(fileData), unpackConfig);
}

PackerType EmulationEngine::DetectPacker(const std::vector<uint8_t>& fileData) {
    return DetectPackerDetailed(fileData).first;
}

std::pair<PackerType, std::string> EmulationEngine::DetectPackerDetailed(const std::vector<uint8_t>& fileData) {
    EmulationConfig config = EmulationConfig::CreateFast();
    config.mode = EmulationMode::UnpackOnly;
    config.maxInstructions = 1'000'000;
    config.timeoutMs = 2000;

    const auto result = m_impl->RunPE(std::span<const uint8_t>(fileData), config);
    if (!result.detectedPackers.empty()) {
        return { result.detectedPackers.front(), result.packerName };
    }

    return { IsPELikelyPacked(std::span<const uint8_t>(fileData)) ? PackerType::CustomCrypter : PackerType::None, "" };
}

size_t EmulationEngine::GetActiveSessionCount() const noexcept {
    if (!m_impl) {
        return 0;
    }

    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_sessions.size();
}

std::optional<EmulationSession> EmulationEngine::GetSession(uint64_t sessionId) const {
    if (!m_impl) {
        return std::nullopt;
    }

    std::shared_lock lock(m_impl->m_mutex);
    const auto it = m_impl->m_sessions.find(sessionId);
    if (it == m_impl->m_sessions.end()) {
        return std::nullopt;
    }

    EmulationSession snapshot;
    snapshot.sessionId = it->second->sessionId;
    snapshot.state.store(it->second->state.load(std::memory_order_relaxed), std::memory_order_relaxed);
    snapshot.config = it->second->config;
    snapshot.startTime = it->second->startTime;
    snapshot.instructionCount.store(it->second->instructionCount.load(std::memory_order_relaxed), std::memory_order_relaxed);
    snapshot.apiCallCount.store(it->second->apiCallCount.load(std::memory_order_relaxed), std::memory_order_relaxed);
    snapshot.activeBackend = it->second->backend;
    return snapshot;
}

bool EmulationEngine::TerminateSession(uint64_t sessionId) {
    if (!m_impl) {
        return false;
    }

    auto* session = m_impl->GetSessionEntry(sessionId);
    if (!session) {
        return false;
    }

    session->shouldStop.store(true, std::memory_order_release);
    session->state.store(EmulationState::Terminated, std::memory_order_release);
#ifdef PHANTOM_EMULATOR_AVAILABLE
    if (session->phantomSession) {
        session->phantomSession->RequestAbort();
    }
#endif
    return true;
}

void EmulationEngine::TerminateAllSessions() {
    if (!m_impl) {
        return;
    }

    std::vector<uint64_t> sessions;
    {
        std::shared_lock lock(m_impl->m_mutex);
        sessions.reserve(m_impl->m_sessions.size());
        for (const auto& [sessionId, session] : m_impl->m_sessions) {
            (void)session;
            sessions.push_back(sessionId);
        }
    }

    for (const auto sessionId : sessions) {
        TerminateSession(sessionId);
    }
}

bool EmulationEngine::PauseSession(uint64_t sessionId) {
    (void)sessionId;
    return false;
}

bool EmulationEngine::ResumeSession(uint64_t sessionId) {
    (void)sessionId;
    return false;
}

uint64_t EmulationEngine::RegisterAPICallback(APICallCallback callback) {
    if (!m_impl || !callback) {
        return 0;
    }

    const uint64_t callbackId = m_impl->m_callbacks.nextId.fetch_add(1, std::memory_order_relaxed);
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_callbacks.apiCallbacks.emplace(callbackId, std::move(callback));
    return callbackId;
}

bool EmulationEngine::UnregisterAPICallback(uint64_t callbackId) {
    if (!m_impl) {
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);
    return m_impl->m_callbacks.apiCallbacks.erase(callbackId) > 0;
}

uint64_t EmulationEngine::RegisterFileDropCallback(FileDropCallback callback) {
    if (!m_impl || !callback) {
        return 0;
    }

    const uint64_t callbackId = m_impl->m_callbacks.nextId.fetch_add(1, std::memory_order_relaxed);
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_callbacks.fileDropCallbacks.emplace(callbackId, std::move(callback));
    return callbackId;
}

bool EmulationEngine::UnregisterFileDropCallback(uint64_t callbackId) {
    if (!m_impl) {
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);
    return m_impl->m_callbacks.fileDropCallbacks.erase(callbackId) > 0;
}

uint64_t EmulationEngine::RegisterNetworkCallback(NetworkActivityCallback callback) {
    if (!m_impl || !callback) {
        return 0;
    }

    const uint64_t callbackId = m_impl->m_callbacks.nextId.fetch_add(1, std::memory_order_relaxed);
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_callbacks.networkCallbacks.emplace(callbackId, std::move(callback));
    return callbackId;
}

bool EmulationEngine::UnregisterNetworkCallback(uint64_t callbackId) {
    if (!m_impl) {
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);
    return m_impl->m_callbacks.networkCallbacks.erase(callbackId) > 0;
}

uint64_t EmulationEngine::RegisterUnpackCallback(UnpackLayerCallback callback) {
    if (!m_impl || !callback) {
        return 0;
    }

    const uint64_t callbackId = m_impl->m_callbacks.nextId.fetch_add(1, std::memory_order_relaxed);
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_callbacks.unpackCallbacks.emplace(callbackId, std::move(callback));
    return callbackId;
}

bool EmulationEngine::UnregisterUnpackCallback(uint64_t callbackId) {
    if (!m_impl) {
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);
    return m_impl->m_callbacks.unpackCallbacks.erase(callbackId) > 0;
}

EmulationStats EmulationEngine::GetStats() const {
    if (!m_impl) {
        return EmulationStats{};
    }

    return SnapshotStats(m_impl->m_stats);
}

void EmulationEngine::ResetStats() {
    if (m_impl) {
        m_impl->m_stats.Reset();
        m_impl->m_stats.phantomEmulatorAvailable = true;
    }
}

void EmulationEngine::SetDefaultConfig(const EmulationConfig& config) {
    if (!m_impl) {
        return;
    }

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_defaultConfig = config;
}

EmulationConfig EmulationEngine::GetDefaultConfig() const {
    if (!m_impl) {
        return EmulationConfig::CreateDefault();
    }

    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_defaultConfig;
}

void EmulationEngine::SetSignatureStore(SignatureStore::SignatureStore* store) {
    if (!m_impl) {
        return;
    }

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_signatureStore = store;
}

void EmulationEngine::SetPatternStore(PatternStore::PatternStore* store) {
    if (!m_impl) {
        return;
    }

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_patternStore = store;
}

void EmulationEngine::SetHashStore(HashStore::HashStore* store) {
    if (!m_impl) {
        return;
    }

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_hashStore = store;
}

void EmulationEngine::SetThreatIntelIndex(ThreatIntel::ThreatIntelIndex* index) {
    if (!m_impl) {
        return;
    }

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_threatIntel = index;
}

bool IsWHPAvailable() noexcept {
    return false;
}

bool IsHyperVEnabled() noexcept {
    return false;
}

bool HasWHPPrivileges() noexcept {
    return false;
}

double CalculateEntropy(const uint8_t* data, size_t size) noexcept {
    if (!data || size == 0) {
        return 0.0;
    }

    std::array<uint64_t, 256> frequencies{};
    for (size_t i = 0; i < size; ++i) {
        ++frequencies[data[i]];
    }

    double entropy = 0.0;
    const double total = static_cast<double>(size);
    for (const auto count : frequencies) {
        if (count == 0) {
            continue;
        }

        const double probability = static_cast<double>(count) / total;
        entropy -= probability * std::log2(probability);
    }

    return entropy;
}

bool IsPELikelyPacked(std::span<const uint8_t> peData) noexcept {
    if (peData.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(peData.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
        dos->e_lfanew <= 0 ||
        static_cast<size_t>(dos->e_lfanew) + sizeof(uint32_t) > peData.size()) {
        return false;
    }

    const double entropy = CalculateEntropy(peData.data(), std::min<size_t>(peData.size(), 64 * 1024));
    if (entropy >= EmulationConstants::PACKED_ENTROPY_THRESHOLD) {
        return true;
    }

    const std::string data(reinterpret_cast<const char*>(peData.data()), peData.size());
    return data.find("UPX!") != std::string::npos || data.find("MPRESS1") != std::string::npos;
}

uint64_t DetectOEP(std::span<const uint8_t> memoryDump, uint64_t imageBase) noexcept {
    if (memoryDump.size() < 8) {
        return 0;
    }

    for (size_t i = 0; i + 4 < memoryDump.size(); ++i) {
        const uint8_t b0 = memoryDump[i];
        const uint8_t b1 = memoryDump[i + 1];
        const uint8_t b2 = memoryDump[i + 2];

        const bool prologue32 = b0 == 0x55 && b1 == 0x8B && b2 == 0xEC;
        const bool prologue64 = b0 == 0x48 && b1 == 0x89 && (b2 == 0x5C || b2 == 0xE5);
        const bool stackFrame = b0 == 0x53 && b1 == 0x56 && b2 == 0x57;

        if (prologue32 || prologue64 || stackFrame) {
            return imageBase + i;
        }
    }

    return 0;
}

APICategory CategorizeAPI(std::string_view dllName, std::string_view funcName) noexcept {
    const auto dll = ToLowerAscii(dllName);
    const auto func = ToLowerAscii(funcName);

    if (dll.find("kernel32") != std::string::npos || func.find("file") != std::string::npos) {
        return APICategory::FileSystem;
    }
    if (dll.find("advapi32") != std::string::npos || func.find("reg") != std::string::npos) {
        return APICategory::Registry;
    }
    if (dll.find("ws2_32") != std::string::npos || dll.find("wininet") != std::string::npos ||
        func.find("connect") != std::string::npos || func.find("send") != std::string::npos) {
        return APICategory::Network;
    }
    if (func.find("process") != std::string::npos || func.find("thread") != std::string::npos) {
        return APICategory::Process;
    }
    if (func.find("alloc") != std::string::npos || func.find("protect") != std::string::npos ||
        func.find("memory") != std::string::npos) {
        return APICategory::Memory;
    }
    if (func.find("debug") != std::string::npos || func.find("tick") != std::string::npos ||
        func.find("sleep") != std::string::npos) {
        return APICategory::AntiAnalysis;
    }
    return APICategory::Unknown;
}

APISeverity AssessAPISeverity(std::string_view dllName,
                              std::string_view funcName,
                              const std::vector<std::string>& args) noexcept {
    const auto dll = ToLowerAscii(dllName);
    const auto func = ToLowerAscii(funcName);
    (void)args;

    if (func.find("writeprocessmemory") != std::string::npos ||
        func.find("createremotethread") != std::string::npos ||
        func.find("ntmapviewofsection") != std::string::npos) {
        return APISeverity::Critical;
    }
    if (func.find("virtualallocex") != std::string::npos ||
        func.find("regsetvalue") != std::string::npos ||
        func.find("createprocess") != std::string::npos) {
        return APISeverity::High;
    }
    if (dll.find("wininet") != std::string::npos ||
        func.find("connect") != std::string::npos ||
        func.find("download") != std::string::npos) {
        return APISeverity::Medium;
    }
    if (func.find("createfile") != std::string::npos ||
        func.find("writefile") != std::string::npos) {
        return APISeverity::Low;
    }
    return APISeverity::Benign;
}

} // namespace ShadowStrike::Core::Engine
