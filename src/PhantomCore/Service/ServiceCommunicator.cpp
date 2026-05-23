#include "pch.h"
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
 * ShadowStrike NGAV - SERVICE COMMUNICATION IMPLEMENTATION
 * ============================================================================
 *
 * @file ServiceCommunicator.cpp
 * @brief Implementation of the ServiceCommunicator class using Windows Named Pipes.
 *
 * This implementation uses Overlapped I/O with a thread pool to handle multiple
 * concurrent client connections efficiently. It enforces strict security
 * using Security Descriptors to allow access only to SYSTEM and Administrators.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "ServiceCommunicator.hpp"
#include "../Utils/ThreadPool.hpp"

// Standard library includes
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <map>
#include <sstream>
#include <iomanip>
#include <atomic>
#include <future>
#include <algorithm>
#include <unordered_map>

// Third-party
// nlohmann/json is used for proper JSON parsing in the AuthHandshake handler.
#include <nlohmann/json.hpp>

// Windows SDK
#include <sddl.h>
#include <aclapi.h>

namespace ShadowStrike {
namespace Service {

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================
std::atomic<bool> ServiceCommunicator::s_instanceCreated{false};

// ============================================================================
// UTILITY HELPERS
// ============================================================================

namespace {
    // RAII wrapper for handles
    struct ScopedHandle {
        HANDLE handle;
        ScopedHandle(HANDLE h = INVALID_HANDLE_VALUE) : handle(h) {}
        ~ScopedHandle() { if (IsValid()) CloseHandle(handle); }
        bool IsValid() const { return handle != INVALID_HANDLE_VALUE && handle != nullptr; }
        operator HANDLE() const { return handle; }
        // Prevent copying
        ScopedHandle(const ScopedHandle&) = delete;
        ScopedHandle& operator=(const ScopedHandle&) = delete;
        // Allow moving
        ScopedHandle(ScopedHandle&& other) noexcept : handle(other.handle) { other.handle = INVALID_HANDLE_VALUE; }
        ScopedHandle& operator=(ScopedHandle&& other) noexcept {
            if (this != &other) {
                if (IsValid()) CloseHandle(handle);
                handle = other.handle;
                other.handle = INVALID_HANDLE_VALUE;
            }
            return *this;
        }
    };

    // Protocol Header structure (packed for wire format)
    #pragma pack(push, 1)
    struct WireHeader {
        uint32_t magic;
        uint32_t command;
        uint32_t payloadSize;
        uint64_t timestamp;
    };
    #pragma pack(pop)
}

// ============================================================================
// STATISTICS IMPLEMENTATION
// ============================================================================

CommunicatorStats::CommunicatorStats(const CommunicatorStats& other) noexcept {
    *this = other;
}

CommunicatorStats& CommunicatorStats::operator=(const CommunicatorStats& other) noexcept {
    if (this == &other) {
        return *this;
    }

    messagesReceived.store(other.messagesReceived.load(std::memory_order_relaxed), std::memory_order_relaxed);
    messagesSent.store(other.messagesSent.load(std::memory_order_relaxed), std::memory_order_relaxed);
    bytesReceived.store(other.bytesReceived.load(std::memory_order_relaxed), std::memory_order_relaxed);
    bytesSent.store(other.bytesSent.load(std::memory_order_relaxed), std::memory_order_relaxed);
    connectionAttempts.store(other.connectionAttempts.load(std::memory_order_relaxed), std::memory_order_relaxed);
    activeConnections.store(other.activeConnections.load(std::memory_order_relaxed), std::memory_order_relaxed);
    droppedPackets.store(other.droppedPackets.load(std::memory_order_relaxed), std::memory_order_relaxed);
    authFailures.store(other.authFailures.load(std::memory_order_relaxed), std::memory_order_relaxed);

    return *this;
}

void CommunicatorStats::Reset() noexcept {
    messagesReceived = 0;
    messagesSent = 0;
    bytesReceived = 0;
    bytesSent = 0;
    connectionAttempts = 0;
    activeConnections = 0;
    droppedPackets = 0;
    authFailures = 0;
}

std::string CommunicatorStats::ToJson() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"messagesReceived\":" << messagesReceived.load() << ",";
    ss << "\"messagesSent\":" << messagesSent.load() << ",";
    ss << "\"bytesReceived\":" << bytesReceived.load() << ",";
    ss << "\"bytesSent\":" << bytesSent.load() << ",";
    ss << "\"connectionAttempts\":" << connectionAttempts.load() << ",";
    ss << "\"activeConnections\":" << activeConnections.load() << ",";
    ss << "\"droppedPackets\":" << droppedPackets.load() << ",";
    ss << "\"authFailures\":" << authFailures.load();
    ss << "}";
    return ss.str();
}

std::string IpcMessage::ToJson() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"type\":" << static_cast<uint32_t>(type) << ",";
    ss << "\"size\":" << payloadSize << ",";
    ss << "\"timestamp\":" << timestamp;
    ss << "}";
    return ss.str();
}

// ============================================================================
// SERVICE COMMUNICATOR IMPLEMENTATION (PIMPL)
// ============================================================================

class ServiceCommunicatorImpl {
public:
    ServiceCommunicatorImpl();
    ~ServiceCommunicatorImpl();

    bool Initialize();
    bool Start();
    void Stop();
    bool IsRunning() const noexcept;

    void RegisterHandler(CommandType type, CommandHandler handler);
    void RegisterV2Handler(CommandType type, V2CommandHandler handler);
    size_t Broadcast(CommandType type, const std::vector<uint8_t>& payload);
    size_t BroadcastEvent(CommandType eventType, const std::vector<uint8_t>& serializedEnvelope);
    void MarkClientAuthenticatedById(uint64_t clientId);
    void RevokeClientAuthenticationById(uint64_t clientId);
    [[nodiscard]] bool IsClientAuthenticatedById(uint64_t clientId) const;
    [[nodiscard]] uint32_t GetClientSessionIdById(uint64_t clientId) const;
    void SendResponseEnvelopeToClient(uint64_t clientId, CommandType type, uint64_t requestId, std::string_view jsonPayload);

    CommunicatorStats GetStats() const;
    void ResetStats();
    bool SelfTest();

private:
    // Client connection context
    struct ClientContext {
        OVERLAPPED overlapped;
        ScopedHandle pipeHandle;
        std::vector<uint8_t> buffer;
        bool pendingIO;
        uint64_t clientId;
        ServiceCommunicatorImpl* server;

        ClientContext() : pipeHandle(INVALID_HANDLE_VALUE), pendingIO(false), clientId(0), server(nullptr) {
            ZeroMemory(&overlapped, sizeof(OVERLAPPED));
            buffer.resize(CommunicationConstants::IN_BUFFER_SIZE);
        }
    };

    // Internal methods
    void ListenLoop();
    void HandleClient(std::shared_ptr<ClientContext> client);
    bool ProcessMessage(CommandType cmd, const std::vector<uint8_t>& data, std::vector<uint8_t>& response);
    void ProcessV2Message(uint64_t clientId, uint32_t sessionId, CommandType cmd, uint64_t requestId, std::string_view json);
    bool CreatePipeSecurityDescriptor();
    [[nodiscard]] ScopedHandle CreatePipeInstance(bool requireFirstInstance);
    void CleanupDisconnectedClients();

    // Performs a bounded-time overlapped WriteFile on an overlapped-mode
    // pipe handle. Returns true on full write within @timeoutMs; on timeout
    // the IO is cancelled with CancelIoEx so the handle remains usable for
    // teardown. @bytesWritten reflects what the kernel reports completed.
    [[nodiscard]] bool TimedWrite(HANDLE pipe,
                                  const void* data,
                                  DWORD size,
                                  DWORD timeoutMs,
                                  DWORD& bytesWritten) noexcept;

    // Member variables
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_initialized{false};

    // Security
    PSECURITY_DESCRIPTOR m_pSecurityDescriptor{nullptr};
    SECURITY_ATTRIBUTES m_sa{0};

    // Threading
    std::thread m_listenThread;
    std::unique_ptr<Utils::ThreadPool> m_clientThreadPool;
    mutable std::shared_mutex m_mutex; // Protects handlers and clients map

    // Manual-reset stop event signaled by Stop(). Used by ListenLoop's
    // overlapped ConnectNamedPipe wait so shutdown does not depend on a
    // dummy client-side connect (which can race or be denied by the
    // pipe ACL during driver-resume scenarios).
    ScopedHandle m_stopEvent;

    // Handlers
    std::map<CommandType, CommandHandler> m_handlers;
    std::map<CommandType, V2CommandHandler> m_v2Handlers;

    // Clients
    struct TokenBucket {
        std::chrono::steady_clock::time_point lastRefill{ std::chrono::steady_clock::now() };
        double tokens{ 20.0 }; // Start full.

        static constexpr double kRate     = 20.0; // events / second
        static constexpr double kCapacity = 20.0; // burst cap

        // Returns true if a token was consumed (event allowed).
        [[nodiscard]] bool TryConsume() noexcept {
            const auto   now = std::chrono::steady_clock::now();
            const double dt  = std::chrono::duration<double>(now - lastRefill).count();
            tokens    = std::min(kCapacity, tokens + dt * kRate);
            lastRefill = now;
            if (tokens >= 1.0) { tokens -= 1.0; return true; }
            return false;
        }
    };

    struct ActiveClient {
        ScopedHandle         pipe;
        uint64_t             id{ 0 };
        std::atomic<bool>    authenticated{ false };
        // Windows session ID of the connecting process, recorded at accept time
        // via GetNamedPipeClientSessionId. Used by the AuthHandshake handler to
        // verify per-session IpcAuthToken without needing impersonation mid-call.
        std::uint32_t        sessionId{ 0 };
        // Per-event-type token buckets; keyed by CommandType raw uint32.
        // Protected by bucketMutex (separate from m_clientsMutex).
        std::mutex                              bucketMutex;
        std::unordered_map<uint32_t, TokenBucket> rateBuckets;

        // Non-copyable, non-movable (atomic + mutex members).
        ActiveClient() = default;
        ActiveClient(const ActiveClient&) = delete;
        ActiveClient& operator=(const ActiveClient&) = delete;
        ActiveClient(ActiveClient&&) = delete;
        ActiveClient& operator=(ActiveClient&&) = delete;
    };
    std::vector<std::shared_ptr<ActiveClient>> m_activeClients;
    mutable std::mutex m_clientsMutex; // Protects m_activeClients

    // Stats
    CommunicatorStats m_stats;

    // The first pipe instance is created synchronously in Start() so a squatted
    // or otherwise unavailable pipe name is visible to SCM instead of becoming
    // a silent RUNNING-without-IPC service state.
    ScopedHandle m_primedPipe;
};

// ----------------------------------------------------------------------------
// Implementation Details
// ----------------------------------------------------------------------------

ServiceCommunicatorImpl::ServiceCommunicatorImpl() {
    m_stats.Reset();
}

ServiceCommunicatorImpl::~ServiceCommunicatorImpl() {
    Stop();
    if (m_pSecurityDescriptor) {
        LocalFree(m_pSecurityDescriptor);
    }
}

bool ServiceCommunicatorImpl::CreatePipeSecurityDescriptor() {
    // Strict SDDL:
    //   O:SY                       - Owner = SYSTEM (prevents owner-rights bypass)
    //   G:SY                       - Primary group = SYSTEM
    //   D:P                        - Protected DACL (no inheritance from parent)
    //     (A;;GA;;;SY)             - SYSTEM: Generic All
    //     (A;;GA;;;BA)             - Built-in Administrators: Generic All
    //     (A;;GRGW;;;IU)           - Interactive users: client read/write only
    //     (A;;GRGW;;;AU)           - Authenticated users: client read/write only
    //   S:(ML;;NW;;;LW)            - Low-integrity clients cannot write up.
    //
    // The pipe DACL is not the trust boundary for Home UI access.  It only
    // allows local user-session clients to reach AuthHandshake; the per-session
    // IpcAuthToken and recorded pipe client session ID remain the authorization
    // gate.  Denying Medium-IL users here breaks every non-elevated UI/tray.
    const wchar_t* sddl =
        L"O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)(A;;GRGW;;;AU)S:(ML;;NW;;;LW)";

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,
            SDDL_REVISION_1,
            &m_pSecurityDescriptor,
            nullptr)) {
        SS_LOG_ERROR(L"IPC", L"Failed to create security descriptor. Error: %lu", GetLastError());
        return false;
    }

    m_sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    m_sa.lpSecurityDescriptor = m_pSecurityDescriptor;
    m_sa.bInheritHandle = FALSE;

    return true;
}

bool ServiceCommunicatorImpl::Initialize() {
    if (m_initialized) return true;

    if (!CreatePipeSecurityDescriptor()) {
        return false;
    }

    // Create the manual-reset stop event used to break the accept loop.
    HANDLE hStop = CreateEventW(nullptr, /*manualReset=*/TRUE, /*initial=*/FALSE, nullptr);
    if (hStop == nullptr) {
        SS_LOG_ERROR(L"IPC", L"CreateEvent (stop) failed. Error: %lu", GetLastError());
        return false;
    }
    m_stopEvent = ScopedHandle(hStop);

    // Register default handlers
    RegisterHandler(CommandType::Heartbeat, [](CommandType, const std::vector<uint8_t>&, std::vector<uint8_t>&) {
        return true; // Simple ACK
    });

    // Initialize thread pool for client handling (bounded to prevent DoS)
    Utils::ThreadPoolConfig poolConfig;
    poolConfig.minThreads = 2;
    poolConfig.maxThreads = 16;  // Cap concurrent client handlers
    m_clientThreadPool = std::make_unique<Utils::ThreadPool>(poolConfig);

    m_initialized = true;
    SS_LOG_INFO(L"IPC", L"ServiceCommunicator initialized with secure SDDL.");
    return true;
}

ScopedHandle ServiceCommunicatorImpl::CreatePipeInstance(bool requireFirstInstance) {
    const DWORD openMode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED |
                           (requireFirstInstance ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0);

    HANDLE hPipe = CreateNamedPipeW(
        CommunicationConstants::PIPE_NAME,
        openMode,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        CommunicationConstants::MAX_CONCURRENT_CLIENTS,
        CommunicationConstants::OUT_BUFFER_SIZE,
        CommunicationConstants::IN_BUFFER_SIZE,
        0,
        &m_sa
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        SS_LOG_ERROR(L"IPC",
            L"CreateNamedPipeW(%ls, first=%u) failed. Error: %lu",
            CommunicationConstants::PIPE_NAME,
            requireFirstInstance ? 1u : 0u,
            err);
    }

    return ScopedHandle(hPipe);
}

bool ServiceCommunicatorImpl::Start() {
    if (!m_initialized) {
        if (!Initialize()) return false;
    }

    if (m_running) return true;
    if (m_stopEvent.IsValid()) {
        ResetEvent(m_stopEvent);
    }

    m_primedPipe = CreatePipeInstance(/*requireFirstInstance=*/true);
    if (!m_primedPipe.IsValid()) {
        const DWORD err = GetLastError();
        SS_LOG_ERROR(L"IPC",
            L"First IPC pipe instance for %ls could not be created (err=%lu). "
            L"Refusing to report service readiness without Home IPC.",
            CommunicationConstants::PIPE_NAME,
            err);
        return false;
    }

    m_running = true;
    m_listenThread = std::thread(&ServiceCommunicatorImpl::ListenLoop, this);

    SS_LOG_INFO(L"IPC", L"IPC Server started on %ls; first pipe instance published.",
                CommunicationConstants::PIPE_NAME);
    return true;
}

void ServiceCommunicatorImpl::Stop() {
    if (!m_running) return;

    m_running = false;

    // Signal the stop event first so an in-flight ConnectNamedPipe wait
    // returns immediately via WaitForMultipleObjects without needing a
    // privileged dummy connect (the pipe ACL would otherwise reject any
    // non-SYSTEM/non-Admin process trying to "kick" the accept loop).
    if (m_stopEvent.IsValid()) {
        SetEvent(m_stopEvent);
    }

    if (m_listenThread.joinable()) {
        m_listenThread.join();
    }

    // Tear down the thread pool BEFORE closing client pipes so that any
    // in-flight HandleClient task observes m_running == false and exits
    // its read loop cleanly, releasing its ClientContext-owned handle.
    if (m_clientThreadPool) {
        m_clientThreadPool->Shutdown(/*waitForCompletion=*/true);
    }

    // Close all client connections (duplicated handles in m_activeClients).
    {
        std::lock_guard<std::mutex> lock(m_clientsMutex);
        m_activeClients.clear(); // ScopedHandle destructors will close handles
    }

    SS_LOG_INFO(L"IPC", L"IPC Server stopped.");
}

bool ServiceCommunicatorImpl::IsRunning() const noexcept {
    return m_running;
}

void ServiceCommunicatorImpl::ListenLoop() {
    // Counter used to assign per-connection client IDs. Atomic because Stop()
    // tears the loop down asynchronously and future maintenance may legitimately
    // spawn auxiliary accept threads; cheap to make it correct now.
    static std::atomic<uint64_t> s_idCounter{0};

    while (m_running) {
        CleanupDisconnectedClients();

        // Check concurrent client limit
        {
            std::lock_guard<std::mutex> lock(m_clientsMutex);
            if (m_activeClients.size() >= CommunicationConstants::MAX_CONCURRENT_CLIENTS) {
                // Backoff briefly; honor stop event so shutdown isn't delayed.
                if (m_stopEvent.IsValid() &&
                    WaitForSingleObject(m_stopEvent, 100) == WAIT_OBJECT_0) {
                    break;
                }
                continue;
            }
        }

        ScopedHandle pipeGuard;
        if (m_primedPipe.IsValid()) {
            pipeGuard = std::move(m_primedPipe);
        } else {
            pipeGuard = CreatePipeInstance(/*requireFirstInstance=*/false);
        }

        if (!pipeGuard.IsValid()) {
            const DWORD err = GetLastError();
            if (m_stopEvent.IsValid() &&
                WaitForSingleObject(m_stopEvent, 1000) == WAIT_OBJECT_0) {
                break;
            }
            SS_LOG_WARN(L"IPC",
                L"CreateNamedPipe retry scheduled after transient failure %lu.", err);
            continue;
        }
        HANDLE hPipe = pipeGuard.handle;

        m_stats.connectionAttempts++;

        // Overlapped accept: ConnectNamedPipe on a FILE_FLAG_OVERLAPPED handle
        // MUST be issued with a non-null OVERLAPPED structure; passing nullptr
        // (the previous behaviour) is documented as invalid and on some Windows
        // builds leaves the pipe in an unrecoverable state.
        HANDLE hConnectEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (hConnectEvent == nullptr) {
            SS_LOG_ERROR(L"IPC", L"CreateEvent (connect) failed. Error: %lu",
                         GetLastError());
            continue; // pipeGuard closes hPipe
        }
        ScopedHandle eventGuard(hConnectEvent);

        OVERLAPPED ov = {};
        ov.hEvent = hConnectEvent;

        BOOL connected = FALSE;
        if (ConnectNamedPipe(hPipe, &ov)) {
            // Some Windows builds return TRUE for an immediate connect; treat
            // as already-connected.
            connected = TRUE;
        } else {
            const DWORD err = GetLastError();
            if (err == ERROR_PIPE_CONNECTED) {
                connected = TRUE;
                SetEvent(hConnectEvent);
            } else if (err == ERROR_IO_PENDING) {
                HANDLE waitHandles[2] = { hConnectEvent, m_stopEvent };
                const DWORD waitResult = WaitForMultipleObjects(
                    2, waitHandles, FALSE, INFINITE);
                if (waitResult == WAIT_OBJECT_0) {
                    DWORD transferred = 0;
                    if (GetOverlappedResult(hPipe, &ov, &transferred, FALSE)) {
                        connected = TRUE;
                    } else {
                        SS_LOG_WARN(L"IPC", L"ConnectNamedPipe GOR failed. Error: %lu",
                                    GetLastError());
                    }
                } else {
                    // Stop requested: cancel pending IO and drop the pipe.
                    CancelIoEx(hPipe, &ov);
                    DWORD transferred = 0;
                    (void)GetOverlappedResult(hPipe, &ov, &transferred, TRUE);
                    break; // outer while; pipeGuard / eventGuard run
                }
            } else {
                SS_LOG_WARN(L"IPC", L"ConnectNamedPipe failed. Error: %lu", err);
            }
        }

        if (!connected) {
            // Recycle the pipe handle on failure (RAII closes it).
            continue;
        }

        SS_LOG_INFO(L"IPC", L"Client connected.");

        auto clientCtx = std::make_shared<ClientContext>();
        clientCtx->pipeHandle = ScopedHandle(pipeGuard.handle); // Transfer ownership
        pipeGuard.handle = INVALID_HANDLE_VALUE;                 // disarm guard
        clientCtx->server = this;
        clientCtx->clientId =
            s_idCounter.fetch_add(1, std::memory_order_relaxed) + 1;

        // Add to active clients list for broadcasting
        bool added = false;
        {
            std::lock_guard<std::mutex> lock(m_clientsMutex);

            // Duplicate the pipe handle for the broadcast/response side.
            // We MUST verify the duplicate succeeded — the previous code stored
            // an uninitialised handle on failure, which the broadcast path
            // would then use as a target for WriteFile.
            HANDLE hDup = nullptr;
            if (!DuplicateHandle(GetCurrentProcess(),
                                 clientCtx->pipeHandle.handle,
                                 GetCurrentProcess(),
                                 &hDup,
                                 0,
                                 FALSE,
                                 DUPLICATE_SAME_ACCESS)) {
                SS_LOG_ERROR(L"IPC",
                    L"DuplicateHandle failed for client %llu (err=%lu); refusing.",
                    clientCtx->clientId, GetLastError());
            } else {
                auto activeClient = std::make_shared<ActiveClient>();
                activeClient->pipe = ScopedHandle(hDup);
                activeClient->id   = clientCtx->clientId;

                // Record the Windows session ID of the connecting client for
                // use by the AuthHandshake v2 handler (IpcAuthToken::Verify
                // requires sessionId).
                ULONG sessionId = 0;
                if (!GetNamedPipeClientSessionId(clientCtx->pipeHandle.handle,
                                                 &sessionId)) {
                    SS_LOG_ERROR(L"IPC",
                        L"GetNamedPipeClientSessionId failed for client %llu (err=%lu); rejecting connection",
                        clientCtx->clientId, GetLastError());
                } else if (sessionId == 0) {
                    SS_LOG_ERROR(L"IPC",
                        L"Client %llu resolved to non-interactive session 0; rejecting connection",
                        clientCtx->clientId);
                } else {
                    activeClient->sessionId = static_cast<std::uint32_t>(sessionId);
                    m_activeClients.push_back(std::move(activeClient));
                    added = true;
                }
            }
        }

        if (!added) {
            // Couldn't duplicate handle: drop the client (clientCtx destruct
            // closes the original pipe handle).
            continue;
        }

        m_stats.activeConnections++;

        // Submit client handling to bounded thread pool
        if (m_clientThreadPool) {
            auto future = m_clientThreadPool->Submit(
                [this, clientCtx](const Utils::TaskContext&) {
                    HandleClient(clientCtx);
                });
            (void)future;  // Fire-and-forget: client lifetime managed by HandleClient
        } else {
            SS_LOG_ERROR(L"IPC", L"ThreadPool unavailable, rejecting client %llu",
                         clientCtx->clientId);
            // Rollback the active-client entry we just registered.
            std::lock_guard<std::mutex> lock(m_clientsMutex);
            m_activeClients.erase(
                std::remove_if(m_activeClients.begin(), m_activeClients.end(),
                    [id = clientCtx->clientId](const auto& c) { return c->id == id; }),
                m_activeClients.end());
            m_stats.activeConnections--;
        }
    }
}

// ----------------------------------------------------------------------------
// Bounded-time overlapped WriteFile helper.
//
// Required because the listen/accept pipes are created with
// FILE_FLAG_OVERLAPPED; passing a NULL lpOverlapped to WriteFile on such a
// handle is documented as undefined behaviour and can corrupt data or hang.
// Centralising the implementation also lets every broadcast path enforce a
// timeout so a single slow/stalled UI client cannot wedge the entire service.
// ----------------------------------------------------------------------------
bool ServiceCommunicatorImpl::TimedWrite(HANDLE pipe,
                                         const void* data,
                                         DWORD size,
                                         DWORD timeoutMs,
                                         DWORD& bytesWritten) noexcept
{
    bytesWritten = 0;
    if (pipe == nullptr || pipe == INVALID_HANDLE_VALUE ||
        data == nullptr || size == 0) {
        return false;
    }

    HANDLE hEvent = CreateEventW(nullptr, /*manualReset=*/TRUE,
                                 /*initial=*/FALSE, nullptr);
    if (hEvent == nullptr) {
        return false;
    }
    ScopedHandle evGuard(hEvent);

    OVERLAPPED ov = {};
    ov.hEvent = hEvent;

    if (WriteFile(pipe, data, size, &bytesWritten, &ov)) {
        return bytesWritten == size;
    }

    const DWORD err = GetLastError();
    if (err != ERROR_IO_PENDING) {
        return false;
    }

    const DWORD wait = WaitForSingleObject(hEvent, timeoutMs);
    if (wait != WAIT_OBJECT_0) {
        // Timed out or wait failure — cancel and drain to release the buffer.
        CancelIoEx(pipe, &ov);
        DWORD drained = 0;
        (void)GetOverlappedResult(pipe, &ov, &drained, TRUE);
        bytesWritten = drained;
        return false;
    }

    if (!GetOverlappedResult(pipe, &ov, &bytesWritten, FALSE)) {
        return false;
    }
    return bytesWritten == size;
}

void ServiceCommunicatorImpl::HandleClient(std::shared_ptr<ClientContext> client) {
    // Message loop
    std::vector<uint8_t> accumulator;
    DWORD bytesRead = 0;

    // Overlapped I/O read loop with event-based completion

    HANDLE hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    client->overlapped.hEvent = hEvent;

    while (m_running) {
        if (!ReadFile(client->pipeHandle, client->buffer.data(),
                      static_cast<DWORD>(client->buffer.size()), &bytesRead, &client->overlapped)) {

            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                WaitForSingleObject(hEvent, INFINITE);
                if (!GetOverlappedResult(client->pipeHandle, &client->overlapped, &bytesRead, FALSE)) {
                    break; // Error or disconnected
                }
            } else if (err == ERROR_BROKEN_PIPE) {
                break; // Client disconnected
            } else {
                SS_LOG_ERROR(L"IPC", L"ReadFile failed. Error: %lu", err);
                break;
            }
        }

        if (bytesRead > 0) {
            m_stats.bytesReceived += bytesRead;
            // Append to accumulator
            size_t oldSize = accumulator.size();
            accumulator.resize(oldSize + bytesRead);
            memcpy(accumulator.data() + oldSize, client->buffer.data(), bytesRead);

            // Try to process message(s)
            // Wire format v1: [Magic:4][Command:4][Size:4][Timestamp:8][Payload:Size]
            // Wire format v2: [Magic:4][Version:2][Reserved:2][Type:4][RequestId:8][PayloadSize:4][JSON:PayloadSize]
            while (accumulator.size() >= sizeof(WireHeader)) {
                const auto* headerPtr = reinterpret_cast<const WireHeader*>(accumulator.data());

                if (headerPtr->magic != CommunicationConstants::PROTOCOL_MAGIC) {
                    SS_LOG_WARN(L"IPC", L"Invalid protocol magic from client %llu. Dropping.", client->clientId);
                    m_stats.droppedPackets++;
                    goto disconnect;
                }

                // ── V2 detection ─────────────────────────────────────────────────────────
                // V2 Envelope overlaps the v1 WireHeader:
                //   bytes [4-5] = Envelope::version  (uint16, expected == 1)
                //   bytes [6-7] = Envelope::reserved (uint16, expected == 0)
                //   bytes [8-11]= Envelope::type     (CommandType, v2 range >= 100)
                //   bytes [20-23]= Envelope::payloadSize (uint32, real JSON length)
                // We need at least 24 bytes before committing to the v2 path.
                if (accumulator.size() >= 24u) {
                    // Use memcpy into typed locals to avoid strict-aliasing and
                    // alignment UB on the raw byte stream. The accumulator's
                    // backing storage is not guaranteed to be 4/8-byte aligned
                    // after the std::vector::erase calls below.
                    uint16_t v2ver  = 0;
                    uint16_t v2res  = 0;
                    uint32_t v2type = 0;
                    std::memcpy(&v2ver,  accumulator.data() + 4, sizeof(v2ver));
                    std::memcpy(&v2res,  accumulator.data() + 6, sizeof(v2res));
                    std::memcpy(&v2type, accumulator.data() + 8, sizeof(v2type));

                    constexpr uint32_t kV2CommandMin = 100u;
                    constexpr uint32_t kV2CommandMax = 400u;

                    if (v2ver == 1u && v2res == 0u &&
                        v2type >= kV2CommandMin && v2type <= kV2CommandMax)
                    {
                        uint32_t realPayloadSize = 0;
                        std::memcpy(&realPayloadSize,
                                    accumulator.data() + 20,
                                    sizeof(realPayloadSize));

                        if (realPayloadSize > CommunicationConstants::MAX_MESSAGE_SIZE) {
                            SS_LOG_WARN(L"IPC", L"V2 payload too large (%u) from client %llu. Dropping.",
                                realPayloadSize, client->clientId);
                            m_stats.droppedPackets++;
                            goto disconnect;
                        }

                        const size_t totalV2Size = 24u + realPayloadSize;
                        if (accumulator.size() < totalV2Size) {
                            break; // Wait for more data
                        }

                        uint64_t requestId = 0;
                        std::memcpy(&requestId,
                                    accumulator.data() + 12,
                                    sizeof(requestId));
                        const CommandType v2cmd  = static_cast<CommandType>(v2type);

                        const std::string_view jsonView(
                            reinterpret_cast<const char*>(accumulator.data() + 24),
                            realPayloadSize);

                        m_stats.messagesReceived++;

                        // Resolve session ID once under lock to avoid repeated contention.
                        uint32_t sessionId = GetClientSessionIdById(client->clientId);
                        ProcessV2Message(client->clientId, sessionId, v2cmd, requestId, jsonView);

                        accumulator.erase(accumulator.begin(),
                                          accumulator.begin() + static_cast<std::ptrdiff_t>(totalV2Size));
                        continue;
                    }
                } else {
                    // Have 20-23 bytes: can't determine v2 vs v1 definitively yet; wait.
                    // (In PIPE_TYPE_MESSAGE mode each ReadFile delivers one full frame,
                    //  so this branch is reachable only for very short v1 messages like
                    //  a bare 20-byte Heartbeat.)
                    // Check if v1 payloadSize = 0 to disambiguate:
                    if (headerPtr->command == 1u && headerPtr->payloadSize > 0u) {
                        // Could be partial v2 frame; wait for rest.
                        break;
                    }
                    // Fall through to v1 path.
                }

                // ── V1 path ───────────────────────────────────────────────────────────────
                // Copy the header into a properly aligned local to avoid UB on
                // unaligned reads from the byte-stream accumulator.
                WireHeader v1Header{};
                std::memcpy(&v1Header, accumulator.data(), sizeof(WireHeader));
                const WireHeader* const header = &v1Header;

                if (header->payloadSize > CommunicationConstants::MAX_MESSAGE_SIZE) {
                    SS_LOG_WARN(L"IPC", L"Message too large (%u). Dropping client.", header->payloadSize);
                    m_stats.droppedPackets++;
                    goto disconnect;
                }

                size_t totalMsgSize = sizeof(WireHeader) + header->payloadSize;
                if (accumulator.size() >= totalMsgSize) {
                    // Full message received
                    std::vector<uint8_t> payload(
                        accumulator.begin() + sizeof(WireHeader),
                        accumulator.begin() + totalMsgSize
                    );

                    std::vector<uint8_t> response;
                    CommandType cmd = static_cast<CommandType>(header->command);

                    m_stats.messagesReceived++;

                    if (ProcessMessage(cmd, payload, response)) {
                        // If this was an AuthHandshake and the response indicates success,
                        // mark the client as authenticated for BroadcastEvent delivery.
                        if (cmd == CommandType::AuthHandshake && !response.empty()) {
                            // Parse the response JSON properly to extract the root-level "ok"
                            // boolean. String-search is unsafe — a malicious error message
                            // or nested field could contain the substring and bypass auth.
                            bool authOk = false;
                            try {
                                auto j = nlohmann::json::parse(
                                    response.begin(), response.end(),
                                    /*callback=*/nullptr,
                                    /*allow_exceptions=*/false);
                                if (!j.is_discarded() && j.is_object()) {
                                    const auto it = j.find("ok");
                                    if (it != j.end() &&
                                        it->is_boolean() &&
                                        it->get<bool>()) {
                                        authOk = true;
                                    }
                                }
                            } catch (...) {
                                authOk = false;
                            }
                            if (authOk) {
                                MarkClientAuthenticatedById(client->clientId);
                            } else {
                                m_stats.authFailures++;
                                SS_LOG_WARN(L"IPC",
                                    L"AuthHandshake for client %llu returned ok=false.",
                                    client->clientId);
                            }
                        }
                        // Send response
                        // Construct response header
                        WireHeader respHeader;
                        respHeader.magic = CommunicationConstants::PROTOCOL_MAGIC;
                        respHeader.command = header->command; // Echo command ID or use specific response ID
                        respHeader.payloadSize = static_cast<uint32_t>(response.size());
                        respHeader.timestamp = std::chrono::system_clock::now().time_since_epoch().count();

                        std::vector<uint8_t> respBuffer;
                        respBuffer.resize(sizeof(WireHeader) + response.size());
                        memcpy(respBuffer.data(), &respHeader, sizeof(WireHeader));
                        if (!response.empty()) {
                            memcpy(respBuffer.data() + sizeof(WireHeader), response.data(), response.size());
                        }

                        DWORD bytesWritten = 0;
                        if (TimedWrite(client->pipeHandle,
                                       respBuffer.data(),
                                       static_cast<DWORD>(respBuffer.size()),
                                       CommunicationConstants::WRITE_TIMEOUT_MS,
                                       bytesWritten)) {
                            m_stats.bytesSent += bytesWritten;
                            m_stats.messagesSent++;
                        } else {
                            SS_LOG_WARN(L"IPC",
                                L"v1 response write failed/timeout for client %llu (err=%lu)",
                                client->clientId, GetLastError());
                            goto disconnect;
                        }
                    }

                    // Remove processed message from accumulator
                    accumulator.erase(accumulator.begin(), accumulator.begin() + totalMsgSize);
                } else {
                    // Waiting for more data
                    break;
                }
            }
        }
    }

disconnect:
    CloseHandle(hEvent);
    // Remove from active clients; auth is revoked implicitly by removal.
    {
        std::lock_guard<std::mutex> lock(m_clientsMutex);
        m_activeClients.erase(
            std::remove_if(m_activeClients.begin(), m_activeClients.end(),
                [id = client->clientId](const auto& c) { return c->id == id; }),
            m_activeClients.end()
        );
    }
    m_stats.activeConnections--;
    SS_LOG_INFO(L"IPC", L"Client %llu disconnected.", client->clientId);
}

bool ServiceCommunicatorImpl::ProcessMessage(CommandType cmd, const std::vector<uint8_t>& data, std::vector<uint8_t>& response) {
    CommandHandler handler;
    {
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        const auto it = m_handlers.find(cmd);
        if (it == m_handlers.end()) {
            SS_LOG_WARN(L"IPC", L"No handler registered for command %u", static_cast<uint32_t>(cmd));
            return false;
        }

        handler = it->second;
    }

    try {
        return handler(cmd, data, response);
    } catch (...) {
        SS_LOG_ERROR(L"IPC", L"Unhandled exception while processing command %u", static_cast<uint32_t>(cmd));
        return false;
    }
}

void ServiceCommunicatorImpl::RegisterHandler(CommandType type, CommandHandler handler) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    m_handlers[type] = handler;
}

void ServiceCommunicatorImpl::RegisterV2Handler(CommandType type, V2CommandHandler handler) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    m_v2Handlers[type] = std::move(handler);
}

bool ServiceCommunicatorImpl::IsClientAuthenticatedById(uint64_t clientId) const {
    std::lock_guard<std::mutex> lk(m_clientsMutex);
    for (const auto& c : m_activeClients) {
        if (c->id == clientId)
            return c->authenticated.load(std::memory_order_acquire);
    }
    return false;
}

uint32_t ServiceCommunicatorImpl::GetClientSessionIdById(uint64_t clientId) const {
    std::lock_guard<std::mutex> lk(m_clientsMutex);
    for (const auto& c : m_activeClients) {
        if (c->id == clientId)
            return c->sessionId;
    }
    return 0u;
}

void ServiceCommunicatorImpl::SendResponseEnvelopeToClient(
    uint64_t clientId, CommandType type, uint64_t requestId, std::string_view jsonPayload)
{
    if (jsonPayload.size() > CommunicationConstants::MAX_MESSAGE_SIZE) {
        SS_LOG_WARN(L"IPC",
            L"SendResponseEnvelope: payload too large (%zu) for client %llu, type %u",
            jsonPayload.size(), clientId, static_cast<uint32_t>(type));
        return;
    }

    // Build the 24-byte v2 Envelope header.
    constexpr size_t kHeaderSize = 24u;
    const uint32_t payloadSize = static_cast<uint32_t>(jsonPayload.size());

    std::vector<uint8_t> buf;
    buf.reserve(kHeaderSize + payloadSize);

    // [0-3]  magic
    const uint32_t magic = CommunicationConstants::PROTOCOL_MAGIC;
    buf.insert(buf.end(), reinterpret_cast<const uint8_t*>(&magic),
                           reinterpret_cast<const uint8_t*>(&magic) + 4);
    // [4-5]  version = 1; [6-7] reserved = 0
    const uint16_t version = 1u, reserved = 0u;
    buf.insert(buf.end(), reinterpret_cast<const uint8_t*>(&version),
                           reinterpret_cast<const uint8_t*>(&version) + 2);
    buf.insert(buf.end(), reinterpret_cast<const uint8_t*>(&reserved),
                           reinterpret_cast<const uint8_t*>(&reserved) + 2);
    // [8-11]  type
    const uint32_t typeVal = static_cast<uint32_t>(type);
    buf.insert(buf.end(), reinterpret_cast<const uint8_t*>(&typeVal),
                           reinterpret_cast<const uint8_t*>(&typeVal) + 4);
    // [12-19] requestId
    buf.insert(buf.end(), reinterpret_cast<const uint8_t*>(&requestId),
                           reinterpret_cast<const uint8_t*>(&requestId) + 8);
    // [20-23] payloadSize
    buf.insert(buf.end(), reinterpret_cast<const uint8_t*>(&payloadSize),
                           reinterpret_cast<const uint8_t*>(&payloadSize) + 4);
    // [24+]  JSON body
    buf.insert(buf.end(), reinterpret_cast<const uint8_t*>(jsonPayload.data()),
                           reinterpret_cast<const uint8_t*>(jsonPayload.data()) + payloadSize);

    // Snapshot the target pipe handle under lock, then write without holding it.
    std::shared_ptr<ActiveClient> target;
    {
        std::lock_guard<std::mutex> lk(m_clientsMutex);
        for (auto& c : m_activeClients) {
            if (c->id == clientId) { target = c; break; }
        }
    }
    if (!target) {
        SS_LOG_WARN(L"IPC", L"SendResponseEnvelope: client %llu not found", clientId);
        return;
    }

    DWORD written = 0;
    if (!TimedWrite(target->pipe, buf.data(),
                    static_cast<DWORD>(buf.size()),
                    CommunicationConstants::WRITE_TIMEOUT_MS, written)) {
        SS_LOG_WARN(L"IPC", L"SendResponseEnvelope: write failed/timeout (err=%lu) for client %llu",
            GetLastError(), clientId);
    } else {
        m_stats.bytesSent  += written;
        m_stats.messagesSent++;
    }
}

void ServiceCommunicatorImpl::ProcessV2Message(
    uint64_t clientId, uint32_t sessionId, CommandType cmd, uint64_t requestId, std::string_view json)
{
    V2CommandHandler handler;
    {
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        const auto it = m_v2Handlers.find(cmd);
        if (it == m_v2Handlers.end()) {
            SS_LOG_WARN(L"IPC", L"No v2 handler for command %u from client %llu",
                static_cast<uint32_t>(cmd), clientId);
            return;
        }
        handler = it->second;
    }

    try {
        handler(clientId, sessionId, requestId, json);
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(L"IPC", L"Exception in v2 handler for command %u: %hs",
            static_cast<uint32_t>(cmd), ex.what());
    } catch (...) {
        SS_LOG_ERROR(L"IPC", L"Unknown exception in v2 handler for command %u",
            static_cast<uint32_t>(cmd));
    }
}

size_t ServiceCommunicatorImpl::Broadcast(CommandType type, const std::vector<uint8_t>& payload) {
    // Snapshot targets under the mutex, then run blocking writes lock-free so a
    // single slow client cannot stall accept/disconnect on the global lock.
    struct WriteTarget {
        std::shared_ptr<ActiveClient> client; // keep handle alive
        HANDLE                        pipe;
    };
    std::vector<WriteTarget> targets;
    {
        std::lock_guard<std::mutex> lock(m_clientsMutex);
        targets.reserve(m_activeClients.size());
        for (auto& c : m_activeClients) {
            targets.push_back({ c, static_cast<HANDLE>(c->pipe) });
        }
    }

    WireHeader header;
    header.magic = CommunicationConstants::PROTOCOL_MAGIC;
    header.command = static_cast<uint32_t>(type);
    header.payloadSize = static_cast<uint32_t>(payload.size());
    header.timestamp = static_cast<uint64_t>(
        std::chrono::system_clock::now().time_since_epoch().count());

    std::vector<uint8_t> packet;
    packet.resize(sizeof(WireHeader) + payload.size());
    std::memcpy(packet.data(), &header, sizeof(WireHeader));
    if (!payload.empty()) {
        std::memcpy(packet.data() + sizeof(WireHeader), payload.data(), payload.size());
    }

    size_t count = 0;
    for (auto& tgt : targets) {
        DWORD written = 0;
        if (TimedWrite(tgt.pipe, packet.data(),
                       static_cast<DWORD>(packet.size()),
                       CommunicationConstants::WRITE_TIMEOUT_MS, written)) {
            ++count;
            m_stats.messagesSent++;
            m_stats.bytesSent += written;
        } else {
            SS_LOG_WARN(L"IPC",
                L"Broadcast write failed/timeout for client %llu (err=%lu)",
                tgt.client->id, GetLastError());
        }
    }
    return count;
}

size_t ServiceCommunicatorImpl::BroadcastEvent(CommandType                       eventType,
                                               const std::vector<uint8_t>&       serializedEnvelope)
{
    if (serializedEnvelope.empty()) {
        SS_LOG_WARN(L"IPC", L"BroadcastEvent called with empty serializedEnvelope for type %u",
                    static_cast<uint32_t>(eventType));
        return 0;
    }

    const uint32_t typeKey = static_cast<uint32_t>(eventType);

    // Snapshot eligible targets under lock, then release before doing blocking
    // I/O.  Holding m_clientsMutex across WriteFile would allow a slow or
    // malicious client to stall client connection/disconnection globally.
    struct WriteTarget {
        std::shared_ptr<ActiveClient> client; // keeps the ActiveClient alive
        HANDLE                        pipe;
    };
    std::vector<WriteTarget> targets;

    {
        std::lock_guard<std::mutex> lk(m_clientsMutex);
        targets.reserve(m_activeClients.size());
        for (auto& client : m_activeClients) {
            if (!client->authenticated.load(std::memory_order_acquire))
                continue;

            // Apply rate limit under its own lock — separate from m_clientsMutex.
            {
                std::lock_guard<std::mutex> bl(client->bucketMutex);
                auto& bucket = client->rateBuckets[typeKey];
                if (!bucket.TryConsume()) {
                    m_stats.droppedPackets++;
                    SS_LOG_WARN(L"IPC",
                        L"BroadcastEvent rate-limited client %llu for event type %u",
                        client->id, typeKey);
                    continue;
                }
            }

            targets.push_back({ client, static_cast<HANDLE>(client->pipe) });
        }
    } // m_clientsMutex released here — WriteFile runs lock-free

    size_t count = 0;
    for (auto& tgt : targets) {
        DWORD written = 0;
        if (TimedWrite(tgt.pipe, serializedEnvelope.data(),
                       static_cast<DWORD>(serializedEnvelope.size()),
                       CommunicationConstants::WRITE_TIMEOUT_MS, written)) {
            ++count;
            m_stats.messagesSent++;
            m_stats.bytesSent += written;
        } else {
            SS_LOG_WARN(L"IPC",
                L"BroadcastEvent write failed/timeout for client %llu: %lu",
                tgt.client->id, GetLastError());
        }
    }
    return count;
}

void ServiceCommunicatorImpl::MarkClientAuthenticatedById(uint64_t clientId)
{
    std::lock_guard<std::mutex> lk(m_clientsMutex);
    for (auto& client : m_activeClients) {
        if (client->id == clientId) {
            client->authenticated.store(true, std::memory_order_release);
            SS_LOG_INFO(L"IPC", L"Client %llu marked as authenticated.", clientId);
            return;
        }
    }
    SS_LOG_WARN(L"IPC", L"MarkClientAuthenticatedById: client %llu not found.", clientId);
}

void ServiceCommunicatorImpl::RevokeClientAuthenticationById(uint64_t clientId)
{
    std::lock_guard<std::mutex> lk(m_clientsMutex);
    for (auto& client : m_activeClients) {
        if (client->id == clientId) {
            client->authenticated.store(false, std::memory_order_release);
            return;
        }
    }
}

void ServiceCommunicatorImpl::CleanupDisconnectedClients() {
    std::lock_guard<std::mutex> lock(m_clientsMutex);
    // Remove handles that are invalid?
    // Active clients are removed by their threads when they exit.
    // This method might check for stale connections if we implemented heartbeat checks here.
}

CommunicatorStats ServiceCommunicatorImpl::GetStats() const {
    return m_stats;
}

void ServiceCommunicatorImpl::ResetStats() {
    m_stats.Reset();
}

bool ServiceCommunicatorImpl::SelfTest() {
    // 1. Check SDDL creation
    if (!m_pSecurityDescriptor && !CreatePipeSecurityDescriptor()) return false;

    // 2. Register a test handler
    RegisterHandler(CommandType::Unknown, [](CommandType, const std::vector<uint8_t>&, std::vector<uint8_t>&) { return true; });

    return true;
}

// ============================================================================
// SERVICE COMMUNICATOR PUBLIC INTERFACE
// ============================================================================

ServiceCommunicator::ServiceCommunicator()
    : m_impl(std::make_unique<ServiceCommunicatorImpl>()) {
    s_instanceCreated = true;
}

ServiceCommunicator::~ServiceCommunicator() = default;

ServiceCommunicator& ServiceCommunicator::Instance() noexcept {
    static ServiceCommunicator instance;
    return instance;
}

bool ServiceCommunicator::Initialize() {
    return m_impl->Initialize();
}

bool ServiceCommunicator::Start() {
    return m_impl->Start();
}

void ServiceCommunicator::Stop() {
    m_impl->Stop();
}

bool ServiceCommunicator::IsRunning() const noexcept {
    return m_impl->IsRunning();
}

void ServiceCommunicator::RegisterHandler(CommandType type, CommandHandler handler) {
    m_impl->RegisterHandler(type, handler);
}

void ServiceCommunicator::RegisterV2Handler(CommandType type, V2CommandHandler handler) {
    m_impl->RegisterV2Handler(type, std::move(handler));
}

bool ServiceCommunicator::IsClientAuthenticated(std::uint64_t clientId) const {
    return m_impl->IsClientAuthenticatedById(clientId);
}

void ServiceCommunicator::SendResponseEnvelope(std::uint64_t    clientId,
                                               CommandType      type,
                                               std::uint64_t    requestId,
                                               std::string_view jsonPayload) {
    m_impl->SendResponseEnvelopeToClient(clientId, type, requestId, jsonPayload);
}

size_t ServiceCommunicator::Broadcast(CommandType type, const std::string& payload) {
    std::vector<uint8_t> binaryPayload(payload.begin(), payload.end());
    return m_impl->Broadcast(type, binaryPayload);
}

size_t ServiceCommunicator::Broadcast(CommandType type, const std::vector<uint8_t>& payload) {
    return m_impl->Broadcast(type, payload);
}

size_t ServiceCommunicator::BroadcastEvent(CommandType                      eventType,
                                            const std::vector<std::uint8_t>& serializedEnvelope) {
    return m_impl->BroadcastEvent(eventType, serializedEnvelope);
}

void ServiceCommunicator::MarkClientAuthenticated(std::uint64_t clientId) {
    m_impl->MarkClientAuthenticatedById(clientId);
}

void ServiceCommunicator::RevokeClientAuthentication(std::uint64_t clientId) {
    m_impl->RevokeClientAuthenticationById(clientId);
}

CommunicatorStats ServiceCommunicator::GetStats() const {
    return m_impl->GetStats();
}

void ServiceCommunicator::ResetStats() {
    m_impl->ResetStats();
}

bool ServiceCommunicator::SelfTest() {
    return m_impl->SelfTest();
}

std::string ServiceCommunicator::GetVersionString() noexcept {
    return "3.0.0";
}

} // namespace Service
} // namespace ShadowStrike
