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
    size_t Broadcast(CommandType type, const std::vector<uint8_t>& payload);
    size_t BroadcastEvent(CommandType eventType, const std::vector<uint8_t>& serializedEnvelope);
    void MarkClientAuthenticatedById(uint64_t clientId);
    void RevokeClientAuthenticationById(uint64_t clientId);

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
    bool CreatePipeSecurityDescriptor();
    void CleanupDisconnectedClients();

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

    // Handlers
    std::map<CommandType, CommandHandler> m_handlers;

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
    std::mutex m_clientsMutex; // Protects m_activeClients

    // Stats
    CommunicatorStats m_stats;
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
    // D: (DACL)
    // (A;;GA;;;SY) - Allow Generic All (Full Control) to SYSTEM
    // (A;;GA;;;BA) - Allow Generic All (Full Control) to Built-in Administrators
    // Deny everyone else implicitly
    const wchar_t* sddl = L"D:(A;;GA;;;SY)(A;;GA;;;BA)";

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

bool ServiceCommunicatorImpl::Start() {
    if (!m_initialized) {
        if (!Initialize()) return false;
    }

    if (m_running) return true;

    m_running = true;
    m_listenThread = std::thread(&ServiceCommunicatorImpl::ListenLoop, this);

    SS_LOG_INFO(L"IPC", L"IPC Server started on %ls", CommunicationConstants::PIPE_NAME);
    return true;
}

void ServiceCommunicatorImpl::Stop() {
    if (!m_running) return;

    m_running = false;

    // Connect a dummy client to unblock ConnectNamedPipe if it's stuck waiting
    HANDLE hPipe = CreateFileW(
        CommunicationConstants::PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, 0, nullptr
    );
    if (hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe);
    }

    if (m_listenThread.joinable()) {
        m_listenThread.join();
    }

    // Close all client connections
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
    while (m_running) {
        CleanupDisconnectedClients();

        // Check concurrent client limit
        {
            std::lock_guard<std::mutex> lock(m_clientsMutex);
            if (m_activeClients.size() >= CommunicationConstants::MAX_CONCURRENT_CLIENTS) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
        }

        HANDLE hPipe = CreateNamedPipeW(
            CommunicationConstants::PIPE_NAME,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, // Bi-directional, Overlapped
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, // Message mode
            CommunicationConstants::MAX_CONCURRENT_CLIENTS,
            CommunicationConstants::OUT_BUFFER_SIZE,
            CommunicationConstants::IN_BUFFER_SIZE,
            0, // Default timeout
            &m_sa
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            SS_LOG_ERROR(L"IPC", L"CreateNamedPipe failed. Error: %lu", GetLastError());
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            continue;
        }

        m_stats.connectionAttempts++;

        // Wait for client connection
        // Note: In a fully optimized IOCP model, we'd use ConnectEx or bind the handle to IOCP immediately.
        // For simplicity and clarity in this enterprise implementation, we'll use blocking ConnectNamedPipe
        // in this thread, but handle the connected client in a detached thread/task.
        // Since we have a dummy client connect in Stop(), this won't block indefinitely on shutdown.

        // We actually need Overlapped ConnectNamedPipe to be interruptible properly or use a loop.
        // Using synchronous connect here for simplicity as Accept loop is common for named pipes.
        BOOL connected = ConnectNamedPipe(hPipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (connected) {
            SS_LOG_INFO(L"IPC", L"Client connected.");

            auto clientCtx = std::make_shared<ClientContext>();
            clientCtx->pipeHandle = hPipe; // Transfer ownership
            clientCtx->server = this;
            static uint64_t idCounter = 0;
            clientCtx->clientId = ++idCounter;

            // Add to active clients list for broadcasting
            {
                std::lock_guard<std::mutex> lock(m_clientsMutex);
                auto activeClient = std::make_shared<ActiveClient>();
                // Duplicate handle for the active clients list (broadcast needs its own handle)
                // while the ThreadPool task owns the original via ClientContext
                HANDLE hDup;
                DuplicateHandle(GetCurrentProcess(), hPipe, GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS);
                activeClient->pipe = hDup;
                activeClient->id = clientCtx->clientId;
                m_activeClients.push_back(activeClient);
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
                CloseHandle(hPipe);
            }
        } else {
            CloseHandle(hPipe);
        }
    }
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
            // Wire format: [Magic:4][Command:4][Size:4][Timestamp:8][Payload:Size]
            while (accumulator.size() >= sizeof(WireHeader)) {
                WireHeader* header = reinterpret_cast<WireHeader*>(accumulator.data());

                if (header->magic != CommunicationConstants::PROTOCOL_MAGIC) {
                    SS_LOG_WARN(L"IPC", L"Invalid protocol magic. Dropping client.");
                    m_stats.droppedPackets++;
                    goto disconnect;
                }

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
                        WriteFile(client->pipeHandle, respBuffer.data(), static_cast<DWORD>(respBuffer.size()), &bytesWritten, nullptr);
                        m_stats.bytesSent += bytesWritten;
                        m_stats.messagesSent++;
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

size_t ServiceCommunicatorImpl::Broadcast(CommandType type, const std::vector<uint8_t>& payload) {
    std::lock_guard<std::mutex> lock(m_clientsMutex);
    size_t count = 0;

    WireHeader header;
    header.magic = CommunicationConstants::PROTOCOL_MAGIC;
    header.command = static_cast<uint32_t>(type);
    header.payloadSize = static_cast<uint32_t>(payload.size());
    header.timestamp = std::chrono::system_clock::now().time_since_epoch().count();

    std::vector<uint8_t> packet;
    packet.resize(sizeof(WireHeader) + payload.size());
    memcpy(packet.data(), &header, sizeof(WireHeader));
    if (!payload.empty()) {
        memcpy(packet.data() + sizeof(WireHeader), payload.data(), payload.size());
    }

    for (auto& client : m_activeClients) {
        DWORD written = 0;
        // Blocking write per client — acceptable for named pipe broadcast
        // (kernel-mode filtering ensures only trusted SYSTEM/Admin clients connect)
        if (WriteFile(client->pipe, packet.data(), static_cast<DWORD>(packet.size()), &written, nullptr)) {
            count++;
            m_stats.messagesSent++;
            m_stats.bytesSent += written;
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
        if (WriteFile(tgt.pipe,
                      serializedEnvelope.data(),
                      static_cast<DWORD>(serializedEnvelope.size()),
                      &written, nullptr)) {
            ++count;
            m_stats.messagesSent++;
            m_stats.bytesSent += written;
        } else {
            SS_LOG_WARN(L"IPC",
                L"BroadcastEvent WriteFile failed for client %llu: %lu",
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
