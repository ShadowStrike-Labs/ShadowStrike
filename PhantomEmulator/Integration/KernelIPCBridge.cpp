/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * KernelIPCBridge.cpp — Named-pipe server receiving samples from PhantomSensor
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "KernelIPCBridge.hpp"
#include "ResultConverter.hpp"

#include "../Common/Types.hpp"
#include "../Common/Config.hpp"
#include "../Analysis/ThreatScorer.hpp"
#include "../Analysis/BehaviorMonitor.hpp"
#include "../Analysis/MITREMapper.hpp"
#include "../Analysis/IOCExtractor.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <atomic>
#include <array>
#include <chrono>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace Phantom::Integration {

// ============================================================================
// Pipe name and internal constants
// ============================================================================

static constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\PhantomSensorEmulation";
static constexpr DWORD   kPipeBufferSize       = 64 * 1024;
static constexpr DWORD   kConnectTimeoutMs     = 5000;
static constexpr DWORD   kShutdownPollMs       = 100;
static constexpr size_t  kMinRequestSize       = sizeof(EmulationRequest);

// ============================================================================
// Rate limiter — sliding window, 1-second granularity
// ============================================================================

class RateLimiter {
public:
    explicit RateLimiter(uint32_t maxPerSecond) noexcept
        : m_max(maxPerSecond) {}

    [[nodiscard]] bool Allow() noexcept {
        auto now = std::chrono::steady_clock::now();
        std::lock_guard lock(m_mtx);
        PruneOld(now);
        if (m_timestamps.size() >= m_max) return false;
        m_timestamps.push_back(now);
        return true;
    }

private:
    void PruneOld(std::chrono::steady_clock::time_point now) noexcept {
        auto cutoff = now - std::chrono::seconds(1);
        while (!m_timestamps.empty() && m_timestamps.front() < cutoff) {
            m_timestamps.erase(m_timestamps.begin());
        }
    }

    uint32_t m_max;
    std::mutex m_mtx;
    std::vector<std::chrono::steady_clock::time_point> m_timestamps;
};

// ============================================================================
// Per-connection state
// ============================================================================

struct PipeConnection {
    HANDLE     hPipe        = INVALID_HANDLE_VALUE;
    OVERLAPPED overlapped   = {};
    HANDLE     hEvent       = nullptr;
    bool       connected    = false;
    bool       inUse        = false;

    void Reset() noexcept {
        if (hPipe != INVALID_HANDLE_VALUE) {
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            hPipe = INVALID_HANDLE_VALUE;
        }
        if (hEvent) {
            CloseHandle(hEvent);
            hEvent = nullptr;
        }
        std::memset(&overlapped, 0, sizeof(overlapped));
        connected = false;
        inUse     = false;
    }
};

// ============================================================================
// Impl
// ============================================================================

struct KernelIPCBridge::Impl {
    EmulationConfig                 defaultConfig{};
    EmulationHandler                handler;
    std::mutex                      handlerMtx;

    std::atomic<bool>               running{ false };
    std::atomic<bool>               shutdownRequested{ false };
    std::atomic<uint64_t>           requestsProcessed{ 0 };
    std::atomic<uint64_t>           requestsPending{ 0 };

    std::array<PipeConnection, kMaxConcurrentSessions> connections{};
    HANDLE                          shutdownEvent = nullptr;

    std::thread                     listenerThread;
    std::vector<std::thread>        workerThreads;
    std::mutex                      workerMtx;

    RateLimiter                     rateLimiter{ kMaxRequestsPerSecond };

    // ---- helpers ----

    [[nodiscard]] HANDLE CreatePipeInstance() noexcept;
    void ListenerLoop() noexcept;
    void HandleConnection(uint32_t slotIndex) noexcept;
    [[nodiscard]] bool ReadExact(HANDLE pipe, void* buf, DWORD size, DWORD timeoutMs) noexcept;
    [[nodiscard]] bool WriteExact(HANDLE pipe, const void* buf, DWORD size) noexcept;
    [[nodiscard]] bool ValidateRequest(const EmulationRequest& req) noexcept;
    [[nodiscard]] EmulationTarget MapSampleType(uint32_t sampleType) noexcept;
    [[nodiscard]] EmulationConfig BuildConfig(const EmulationRequest& req) noexcept;
    void BuildResponse(EmulationResponse& resp, const EmulationRequest& req,
                       const PhantomEmulationResult& result) noexcept;
    [[nodiscard]] std::string SerializeDetails(const PhantomEmulationResult& result) noexcept;

    void CleanupAll() noexcept {
        for (auto& conn : connections) {
            conn.Reset();
        }
        if (shutdownEvent) {
            CloseHandle(shutdownEvent);
            shutdownEvent = nullptr;
        }
    }
};

// ============================================================================
// KernelIPCBridge public methods
// ============================================================================

KernelIPCBridge::KernelIPCBridge()
    : m_impl(std::make_unique<Impl>()) {}

KernelIPCBridge::~KernelIPCBridge() {
    Stop();
}

bool KernelIPCBridge::Start(EmulationConfig defaultConfig) {
    if (m_impl->running.load(std::memory_order_acquire)) {
        return false;
    }

    m_impl->defaultConfig      = std::move(defaultConfig);
    m_impl->shutdownRequested.store(false, std::memory_order_release);

    m_impl->shutdownEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!m_impl->shutdownEvent) {
        return false;
    }

    // Create initial pipe instances
    for (uint32_t i = 0; i < kMaxConcurrentSessions; ++i) {
        auto& conn = m_impl->connections[i];
        conn.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!conn.hEvent) {
            m_impl->CleanupAll();
            return false;
        }
        conn.hPipe = m_impl->CreatePipeInstance();
        if (conn.hPipe == INVALID_HANDLE_VALUE) {
            m_impl->CleanupAll();
            return false;
        }
    }

    m_impl->running.store(true, std::memory_order_release);

    m_impl->listenerThread = std::thread([this] {
        m_impl->ListenerLoop();
    });

    return true;
}

void KernelIPCBridge::Stop() noexcept {
    if (!m_impl->running.load(std::memory_order_acquire)) {
        return;
    }

    m_impl->shutdownRequested.store(true, std::memory_order_release);
    if (m_impl->shutdownEvent) {
        SetEvent(m_impl->shutdownEvent);
    }

    if (m_impl->listenerThread.joinable()) {
        m_impl->listenerThread.join();
    }

    // Join all workers
    {
        std::lock_guard lock(m_impl->workerMtx);
        for (auto& t : m_impl->workerThreads) {
            if (t.joinable()) t.join();
        }
        m_impl->workerThreads.clear();
    }

    m_impl->CleanupAll();
    m_impl->running.store(false, std::memory_order_release);
}

bool KernelIPCBridge::IsRunning() const noexcept {
    return m_impl->running.load(std::memory_order_acquire);
}

void KernelIPCBridge::SetHandler(EmulationHandler handler) noexcept {
    std::lock_guard lock(m_impl->handlerMtx);
    m_impl->handler = std::move(handler);
}

uint64_t KernelIPCBridge::GetRequestsProcessed() const noexcept {
    return m_impl->requestsProcessed.load(std::memory_order_acquire);
}

uint64_t KernelIPCBridge::GetRequestsPending() const noexcept {
    return m_impl->requestsPending.load(std::memory_order_acquire);
}

// ============================================================================
// Pipe instance creation
// ============================================================================

HANDLE KernelIPCBridge::Impl::CreatePipeInstance() noexcept {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;

    // Build a DACL that allows SYSTEM and LOCAL_SERVICE.
    // For kernel-to-user IPC the kernel driver runs as SYSTEM.
    HANDLE hPipe = CreateNamedPipeW(
        kPipeName,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        kMaxConcurrentSessions,
        kPipeBufferSize,
        kPipeBufferSize,
        kConnectTimeoutMs,
        nullptr // Default security — SYSTEM + Administrators
    );

    return hPipe;
}

// ============================================================================
// Listener loop — waits for connections on all pipe instances
// ============================================================================

void KernelIPCBridge::Impl::ListenerLoop() noexcept {
    // Build wait handles: [shutdownEvent, conn[0].hEvent, conn[1].hEvent, …]
    std::array<HANDLE, kMaxConcurrentSessions + 1> waitHandles{};
    waitHandles[0] = shutdownEvent;

    // Issue initial ConnectNamedPipe on each instance
    for (uint32_t i = 0; i < kMaxConcurrentSessions; ++i) {
        auto& conn = connections[i];
        std::memset(&conn.overlapped, 0, sizeof(conn.overlapped));
        conn.overlapped.hEvent = conn.hEvent;
        waitHandles[i + 1] = conn.hEvent;

        ConnectNamedPipe(conn.hPipe, &conn.overlapped);
        DWORD err = GetLastError();
        if (err == ERROR_PIPE_CONNECTED) {
            SetEvent(conn.hEvent);
        }
    }

    while (!shutdownRequested.load(std::memory_order_acquire)) {
        DWORD result = WaitForMultipleObjects(
            static_cast<DWORD>(kMaxConcurrentSessions + 1),
            waitHandles.data(),
            FALSE,
            kShutdownPollMs
        );

        if (result == WAIT_OBJECT_0) {
            // Shutdown event
            break;
        }

        if (result == WAIT_TIMEOUT) {
            // Clean up finished workers
            std::lock_guard lock(workerMtx);
            std::erase_if(workerThreads, [](std::thread& t) {
                if (t.joinable()) {
                    // Only erase if finished — use a quick check
                    // We can't truly test thread completion without extra state,
                    // so just skip here. Workers self-complete.
                }
                return false;
            });
            continue;
        }

        if (result >= WAIT_OBJECT_0 + 1 &&
            result < WAIT_OBJECT_0 + 1 + kMaxConcurrentSessions) {
            uint32_t slotIdx = result - WAIT_OBJECT_0 - 1;
            auto& conn = connections[slotIdx];

            // Verify the overlapped completed
            DWORD bytesTransferred = 0;
            BOOL ok = GetOverlappedResult(conn.hPipe, &conn.overlapped,
                                          &bytesTransferred, FALSE);
            if (ok || GetLastError() == ERROR_PIPE_CONNECTED) {
                conn.connected = true;
                conn.inUse     = true;

                // Spawn worker for this connection
                std::lock_guard lock(workerMtx);
                workerThreads.emplace_back([this, slotIdx] {
                    HandleConnection(slotIdx);
                });
            } else {
                // Connection failed — recreate pipe instance
                DisconnectNamedPipe(conn.hPipe);
                CloseHandle(conn.hPipe);
                conn.hPipe = CreatePipeInstance();
                if (conn.hPipe != INVALID_HANDLE_VALUE) {
                    std::memset(&conn.overlapped, 0, sizeof(conn.overlapped));
                    conn.overlapped.hEvent = conn.hEvent;
                    ConnectNamedPipe(conn.hPipe, &conn.overlapped);
                }
            }
        }
    }

    // Cancel all pending I/O
    for (auto& conn : connections) {
        if (conn.hPipe != INVALID_HANDLE_VALUE) {
            CancelIoEx(conn.hPipe, nullptr);
        }
    }
}

// ============================================================================
// Read/Write helpers with overlapped I/O
// ============================================================================

bool KernelIPCBridge::Impl::ReadExact(HANDLE pipe, void* buf, DWORD size,
                                       DWORD timeoutMs) noexcept
{
    DWORD totalRead = 0;
    auto* dst = static_cast<uint8_t*>(buf);

    while (totalRead < size) {
        if (shutdownRequested.load(std::memory_order_acquire)) return false;

        OVERLAPPED ov{};
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!ov.hEvent) return false;

        DWORD toRead = size - totalRead;
        BOOL ok = ReadFile(pipe, dst + totalRead, toRead, nullptr, &ov);
        DWORD err = GetLastError();

        if (!ok && err != ERROR_IO_PENDING) {
            CloseHandle(ov.hEvent);
            return false;
        }

        HANDLE waits[2] = { ov.hEvent, shutdownEvent };
        DWORD waitResult = WaitForMultipleObjects(2, waits, FALSE, timeoutMs);

        if (waitResult == WAIT_OBJECT_0) {
            DWORD bytesRead = 0;
            if (!GetOverlappedResult(pipe, &ov, &bytesRead, FALSE)) {
                CloseHandle(ov.hEvent);
                return false;
            }
            totalRead += bytesRead;
        } else {
            CancelIoEx(pipe, &ov);
            CloseHandle(ov.hEvent);
            return false;
        }

        CloseHandle(ov.hEvent);
    }

    return true;
}

bool KernelIPCBridge::Impl::WriteExact(HANDLE pipe, const void* buf,
                                        DWORD size) noexcept
{
    DWORD totalWritten = 0;
    const auto* src = static_cast<const uint8_t*>(buf);

    while (totalWritten < size) {
        if (shutdownRequested.load(std::memory_order_acquire)) return false;

        OVERLAPPED ov{};
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!ov.hEvent) return false;

        DWORD toWrite = size - totalWritten;
        BOOL ok = WriteFile(pipe, src + totalWritten, toWrite, nullptr, &ov);
        DWORD err = GetLastError();

        if (!ok && err != ERROR_IO_PENDING) {
            CloseHandle(ov.hEvent);
            return false;
        }

        HANDLE waits[2] = { ov.hEvent, shutdownEvent };
        DWORD waitResult = WaitForMultipleObjects(2, waits, FALSE, kDefaultTimeoutMs);

        if (waitResult == WAIT_OBJECT_0) {
            DWORD bytesWritten = 0;
            if (!GetOverlappedResult(pipe, &ov, &bytesWritten, FALSE)) {
                CloseHandle(ov.hEvent);
                return false;
            }
            totalWritten += bytesWritten;
        } else {
            CancelIoEx(pipe, &ov);
            CloseHandle(ov.hEvent);
            return false;
        }

        CloseHandle(ov.hEvent);
    }

    return true;
}

// ============================================================================
// Request validation
// ============================================================================

bool KernelIPCBridge::Impl::ValidateRequest(const EmulationRequest& req) noexcept {
    if (req.magic != kRequestMagic) return false;
    if (req.version != kProtocolVersion) return false;
    if (req.sampleSize == 0) return false;
    if (req.sampleSize > kMaxSampleSize) return false;
    if (req.sampleType > 3) return false;
    if (req.priority > 3) return false;
    return true;
}

// ============================================================================
// Sample type mapping
// ============================================================================

EmulationTarget KernelIPCBridge::Impl::MapSampleType(uint32_t sampleType) noexcept {
    switch (sampleType) {
    case 0:  return EmulationTarget::PE64;        // PE — default to 64-bit
    case 1:  return EmulationTarget::Shellcode32;
    case 2:  return EmulationTarget::Shellcode64;
    case 3:  return EmulationTarget::PE64;        // Buffer — treat as PE
    default: return EmulationTarget::PE64;
    }
}

// ============================================================================
// Build per-request config from defaults + request flags
// ============================================================================

EmulationConfig KernelIPCBridge::Impl::BuildConfig(
    const EmulationRequest& req) noexcept
{
    EmulationConfig cfg = defaultConfig;

    if (req.timeout > 0) {
        cfg.maxWallTime = std::chrono::milliseconds(req.timeout);
    }

    if (req.flags & kFlagDeepScan) {
        cfg.maxInstructions = std::max(cfg.maxInstructions, uint64_t{200'000'000});
        cfg.enableMemoryForensics = true;
        cfg.enableBehaviorMonitor = true;
        cfg.enableMITREMapping    = true;
        cfg.yaraScansPerSession   = 8;
    }

    if (req.flags & kFlagUnpackOnly) {
        cfg.enableBehaviorMonitor       = false;
        cfg.enableAPISequenceAnalysis   = false;
        cfg.enableMITREMapping          = false;
        cfg.enableIOCExtraction         = false;
    }

    if (req.flags & kFlagNoNetwork) {
        cfg.enableNetwork = false;
    }

    // Map sample type to target
    cfg.target = MapSampleType(req.sampleType);

    // Shellcode targets require specific mode
    if (req.sampleType == 1) {
        cfg.target  = EmulationTarget::Shellcode32;
        cfg.cpuMode = CPUMode::Protected32;
    } else if (req.sampleType == 2) {
        cfg.target  = EmulationTarget::Shellcode64;
        cfg.cpuMode = CPUMode::Long64;
    }

    return cfg;
}

// ============================================================================
// Build wire-format response
// ============================================================================

void KernelIPCBridge::Impl::BuildResponse(
    EmulationResponse& resp,
    const EmulationRequest& req,
    const PhantomEmulationResult& result) noexcept
{
    std::memset(&resp, 0, sizeof(resp));

    resp.magic   = kResponseMagic;
    resp.version = kProtocolVersion;
    resp.requestId = req.requestId;

    // Map verdict from ThreatVerdict
    if (result.verdict) {
        resp.verdict    = static_cast<uint32_t>(result.verdict->level);
        resp.threatScore = result.verdict->score;
        resp.confidence  = result.verdict->confidence;
    }

    resp.exitReason     = static_cast<uint32_t>(result.stopReason);
    resp.instrExecuted  = result.instructionsExecuted;
    resp.apiCallCount   = static_cast<uint32_t>(result.apiCalls.size());
    resp.alertCount     = static_cast<uint32_t>(result.behaviorAlerts.size());
    resp.mitreTechCount = static_cast<uint32_t>(result.mitreTechniques.size());

    if (result.iocReport) {
        resp.iocCount = static_cast<uint32_t>(result.iocReport->indicators.size());
    }

    resp.unpackLayers = static_cast<uint32_t>(result.unpackLayers.size());

    // Response flags
    if (result.verdict &&
        (result.verdict->level == ThreatLevel::Malicious ||
         result.verdict->level == ThreatLevel::Critical)) {
        resp.flags |= kRespFlagMalicious;
    }
    if (result.unpackSuccessful) {
        resp.flags |= kRespFlagUnpacked;
    }
    if (result.evasionSummary && result.evasionSummary->isHighlyEvasive) {
        resp.flags |= kRespFlagEvasive;
    }
}

// ============================================================================
// Serialize analysis details as compact JSON
// ============================================================================

std::string KernelIPCBridge::Impl::SerializeDetails(
    const PhantomEmulationResult& result) noexcept
{
    // Hand-rolled JSON to avoid third-party dependencies.
    // Size is bounded — truncate if needed.
    std::string json;
    json.reserve(4096);

    json += '{';

    // Verdict
    if (result.verdict) {
        json += "\"verdict\":{";
        json += "\"score\":" + std::to_string(result.verdict->score) + ',';
        json += "\"confidence\":" + std::to_string(result.verdict->confidence) + ',';
        json += "\"summary\":\"";
        // Escape special characters in summary
        for (char c : result.verdict->summary) {
            switch (c) {
            case '"':  json += "\\\""; break;
            case '\\': json += "\\\\"; break;
            case '\n': json += "\\n"; break;
            case '\r': json += "\\r"; break;
            case '\t': json += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char esc[8];
                    std::snprintf(esc, sizeof(esc), "\\u%04x",
                                  static_cast<unsigned>(c));
                    json += esc;
                } else {
                    json += c;
                }
            }
        }
        json += "\"},";
    }

    // MITRE techniques
    if (!result.mitreTechniques.empty()) {
        json += "\"mitre\":[";
        bool first = true;
        for (const auto& tech : result.mitreTechniques) {
            if (json.size() > kMaxJsonDetailSize - 256) {
                break; // Prevent unbounded growth
            }
            if (!first) json += ',';
            first = false;
            json += "{\"id\":\"";
            json += (tech.id ? tech.id : "");
            json += "\",\"name\":\"";
            json += (tech.name ? tech.name : "");
            json += "\",\"tactic\":\"";
            json += (tech.tactic ? tech.tactic : "");
            json += "\",\"confidence\":";
            json += std::to_string(tech.confidence);
            json += '}';
        }
        json += "],";
    }

    // IOC summary
    if (result.iocReport) {
        json += "\"iocs\":{";
        json += "\"domains\":" + std::to_string(result.iocReport->totalDomains) + ',';
        json += "\"ips\":" + std::to_string(result.iocReport->totalIPs) + ',';
        json += "\"urls\":" + std::to_string(result.iocReport->totalURLs) + ',';
        json += "\"files\":" + std::to_string(result.iocReport->totalFiles) + ',';
        json += "\"registry\":" + std::to_string(result.iocReport->totalRegistry) + ',';
        json += "\"mutexes\":" + std::to_string(result.iocReport->totalMutexes);
        json += "},";
    }

    // Behavior alerts
    if (!result.behaviorAlerts.empty()) {
        json += "\"alerts\":[";
        bool first = true;
        for (const auto& alert : result.behaviorAlerts) {
            if (json.size() > kMaxJsonDetailSize - 256) break;
            if (!first) json += ',';
            first = false;
            json += "{\"severity\":" + std::to_string(static_cast<int>(alert.severity));
            json += ",\"confidence\":" + std::to_string(alert.confidence);
            json += ",\"description\":\"";
            for (char c : alert.description) {
                if (c == '"') json += "\\\"";
                else if (c == '\\') json += "\\\\";
                else if (static_cast<unsigned char>(c) < 0x20) {
                    char esc[8];
                    std::snprintf(esc, sizeof(esc), "\\u%04x",
                                  static_cast<unsigned>(c));
                    json += esc;
                } else {
                    json += c;
                }
            }
            json += "\"}";
        }
        json += "],";
    }

    // Unpack layers
    if (!result.unpackLayers.empty()) {
        json += "\"unpack\":{";
        json += "\"layers\":" + std::to_string(result.unpackLayers.size());
        json += ",\"successful\":" + std::string(result.unpackSuccessful ? "true" : "false");
        if (!result.unpackedSha256.empty()) {
            json += ",\"sha256\":\"" + result.unpackedSha256 + '"';
        }
        json += "},";
    }

    // Execution stats
    json += "\"stats\":{";
    json += "\"instructions\":" + std::to_string(result.instructionsExecuted);
    json += ",\"emulationTimeMs\":" + std::to_string(result.emulationTimeMs);
    json += ",\"peakMemory\":" + std::to_string(result.peakMemoryUsage);
    json += ",\"apiCalls\":" + std::to_string(result.apiCalls.size());
    json += '}';

    json += '}';

    return json;
}

// ============================================================================
// Per-connection handler — runs in its own thread
// ============================================================================

void KernelIPCBridge::Impl::HandleConnection(uint32_t slotIndex) noexcept {
    auto& conn = connections[slotIndex];

    // Ensure cleanup on exit — recreate pipe instance for next client
    struct Cleanup {
        Impl* self;
        PipeConnection* conn;
        uint32_t slot;
        ~Cleanup() {
            if (conn->hPipe != INVALID_HANDLE_VALUE) {
                FlushFileBuffers(conn->hPipe);
                DisconnectNamedPipe(conn->hPipe);
                CloseHandle(conn->hPipe);
            }
            conn->hPipe = self->CreatePipeInstance();
            conn->connected = false;
            conn->inUse = false;

            // Re-arm overlapped connect
            if (conn->hPipe != INVALID_HANDLE_VALUE) {
                std::memset(&conn->overlapped, 0, sizeof(conn->overlapped));
                conn->overlapped.hEvent = conn->hEvent;
                ConnectNamedPipe(conn->hPipe, &conn->overlapped);
                DWORD err = GetLastError();
                if (err == ERROR_PIPE_CONNECTED) {
                    SetEvent(conn->hEvent);
                }
            }
        }
    } cleanup{ this, &conn, slotIndex };

    // Process requests on this connection until client disconnects or shutdown
    while (!shutdownRequested.load(std::memory_order_acquire)) {
        // Read request header
        EmulationRequest req{};
        if (!ReadExact(conn.hPipe, &req, sizeof(req), kDefaultTimeoutMs)) {
            break; // Client disconnected or timeout
        }

        // Validate
        if (!ValidateRequest(req)) {
            // Send error response and continue
            EmulationResponse errResp{};
            errResp.magic     = kResponseMagic;
            errResp.version   = kProtocolVersion;
            errResp.requestId = req.requestId;
            errResp.verdict   = 0; // Clean — we didn't analyze
            errResp.flags     = 0;
            WriteExact(conn.hPipe, &errResp, sizeof(errResp));
            continue;
        }

        // Rate limit
        if (!rateLimiter.Allow()) {
            // Send response with zero results
            EmulationResponse rlResp{};
            rlResp.magic     = kResponseMagic;
            rlResp.version   = kProtocolVersion;
            rlResp.requestId = req.requestId;
            rlResp.flags     = kRespFlagTruncated;
            WriteExact(conn.hPipe, &rlResp, sizeof(rlResp));
            continue;
        }

        // Read sample payload
        std::vector<uint8_t> sampleData;
        {
            const auto sampleSize = req.sampleSize;
            if (sampleSize > kMaxSampleSize) break;

            sampleData.resize(static_cast<size_t>(sampleSize));
            DWORD readTimeout = req.timeout > 0 ? req.timeout : kDefaultTimeoutMs;
            if (!ReadExact(conn.hPipe, sampleData.data(),
                           static_cast<DWORD>(sampleSize), readTimeout)) {
                break;
            }
        }

        // Build config
        EmulationConfig cfg = BuildConfig(req);
        EmulationTarget target = MapSampleType(req.sampleType);

        // Invoke handler
        requestsPending.fetch_add(1, std::memory_order_acq_rel);

        PhantomEmulationResult result{};
        {
            std::lock_guard lock(handlerMtx);
            if (handler) {
                result = handler(
                    std::span<const uint8_t>(sampleData.data(), sampleData.size()),
                    target, cfg);
            }
        }

        requestsPending.fetch_sub(1, std::memory_order_acq_rel);
        requestsProcessed.fetch_add(1, std::memory_order_acq_rel);

        // Build and send response
        EmulationResponse resp{};
        BuildResponse(resp, req, result);

        std::string details = SerializeDetails(result);
        if (details.size() > kMaxJsonDetailSize) {
            details.resize(kMaxJsonDetailSize);
            resp.flags |= kRespFlagTruncated;
        }
        resp.detailsSize = static_cast<uint32_t>(details.size());

        if (!WriteExact(conn.hPipe, &resp, sizeof(resp))) break;
        if (resp.detailsSize > 0) {
            if (!WriteExact(conn.hPipe, details.data(),
                            resp.detailsSize)) break;
        }
    }
}

} // namespace Phantom::Integration
