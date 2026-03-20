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
#include "pch.h"
#include "ServiceCommunication.hpp"

#include <algorithm>
#include <sstream>
#include <random>
#include <cassert>
#include <sddl.h>
#include <AclAPI.h>

#pragma comment(lib, "Advapi32.lib")

namespace ShadowStrike {
namespace Communication {

// ============================================================================
// HELPERS
// ============================================================================

static std::string GenerateSessionId() {
    static std::atomic<uint64_t> s_counter{0};
    const uint64_t seq = s_counter.fetch_add(1, std::memory_order_relaxed);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    char buf[64]{};
    std::snprintf(buf, sizeof(buf), "SES-%llX-%04llX",
                  static_cast<unsigned long long>(ms),
                  static_cast<unsigned long long>(seq & 0xFFFF));
    return buf;
}

static std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (const char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char hex[8];
                    std::snprintf(hex, sizeof(hex), "\\u%04x",
                                  static_cast<unsigned>(static_cast<unsigned char>(c)));
                    out += hex;
                } else {
                    out += c;
                }
                break;
        }
    }
    return out;
}

static std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    const int len = WideCharToMultiByte(CP_UTF8, 0, w.data(),
                                        static_cast<int>(w.size()),
                                        nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string s(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(),
                        static_cast<int>(w.size()),
                        s.data(), len, nullptr, nullptr);
    return s;
}

// CRC32 (ISO 3309 polynomial)
static uint32_t Crc32Table[256];
static std::once_flag s_crc32InitFlag;

static void InitCrc32Table() {
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        for (int j = 0; j < 8; ++j)
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        Crc32Table[i] = crc;
    }
}

static uint32_t ComputeCrc32(const void* data, size_t len, uint32_t init = 0xFFFFFFFF) {
    std::call_once(s_crc32InitFlag, InitCrc32Table);
    uint32_t crc = init;
    const auto* p = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < len; ++i)
        crc = Crc32Table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    return ~crc;
}

// RAII handle wrapper
struct HandleGuard {
    HANDLE h = INVALID_HANDLE_VALUE;
    HandleGuard() = default;
    explicit HandleGuard(HANDLE handle) : h(handle) {}
    ~HandleGuard() { Close(); }
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
    HandleGuard(HandleGuard&& o) noexcept : h(o.h) { o.h = INVALID_HANDLE_VALUE; }
    HandleGuard& operator=(HandleGuard&& o) noexcept {
        if (this != &o) { Close(); h = o.h; o.h = INVALID_HANDLE_VALUE; }
        return *this;
    }
    void Close() {
        if (h != INVALID_HANDLE_VALUE && h != nullptr) {
            CloseHandle(h);
            h = INVALID_HANDLE_VALUE;
        }
    }
    [[nodiscard]] bool IsValid() const noexcept {
        return h != INVALID_HANDLE_VALUE && h != nullptr;
    }
    HANDLE Release() noexcept { HANDLE tmp = h; h = INVALID_HANDLE_VALUE; return tmp; }
};

// RAII for SECURITY_ATTRIBUTES with LocalFree
struct SecurityDescriptorGuard {
    PSECURITY_DESCRIPTOR sd = nullptr;
    ~SecurityDescriptorGuard() { if (sd) LocalFree(sd); }
};

// Checks if the caller connected to the named pipe is a local administrator.
// Uses ImpersonateNamedPipeClient + token membership check.
static bool IsCallerAdmin(HANDLE pipeHandle) {
    if (!ImpersonateNamedPipeClient(pipeHandle))
        return false;

    HANDLE token = nullptr;
    bool isAdmin = false;

    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &token)) {
        BYTE sidBuf[SECURITY_MAX_SID_SIZE];
        DWORD sidSize = sizeof(sidBuf);
        if (CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, sidBuf, &sidSize)) {
            BOOL isMember = FALSE;
            if (CheckTokenMembership(token, sidBuf, &isMember))
                isAdmin = (isMember != FALSE);
        }
        CloseHandle(token);
    }

    RevertToSelf();
    return isAdmin;
}

// Commands that require administrator privileges to execute.
static bool IsPrivilegedCommand(MessageType type) {
    switch (type) {
        case MessageType::CmdSetConfig:
        case MessageType::CmdResetConfig:
        case MessageType::CmdStopScan:
        case MessageType::CmdCancelScan:
        case MessageType::CmdCancelUpdate:
        case MessageType::CmdDelete:
            return true;
        default:
            return false;
    }
}

// ============================================================================
// CONNECTED CLIENT (INTERNAL)
// ============================================================================

struct ConnectedClient {
    std::string sessionId;
    HandleGuard pipeHandle;
    ClientType clientType = ClientType::Unknown;
    uint32_t processId = 0;
    std::atomic<ConnectionState> state{ConnectionState::Disconnected};
    std::chrono::system_clock::time_point connectedTime;
    TimePoint lastActivity;
    std::atomic<uint64_t> messagesSent{0};
    std::atomic<uint64_t> messagesReceived{0};
    std::atomic<uint32_t> sequence{0};
    bool isAuthenticated = false;
    uint64_t capabilities = 0;
    std::thread readerThread;
    std::mutex writeMutex;
    std::atomic<bool> running{false};

    // Per-client rate limiting (only accessed by this client's reader thread)
    uint32_t messagesThisWindow = 0;
    TimePoint rateWindowStart{Clock::now()};

    ConnectedClient() = default;
    ~ConnectedClient() {
        running.store(false, std::memory_order_release);
        if (readerThread.joinable())
            readerThread.join();
    }
    ConnectedClient(const ConnectedClient&) = delete;
    ConnectedClient& operator=(const ConnectedClient&) = delete;
};

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

class ServiceCommunicationImpl {
public:
    ServiceCommunicationImpl() = default;
    ~ServiceCommunicationImpl() { Shutdown(); }

    // Lifecycle
    bool Initialize(const ServiceCommConfiguration& config);
    bool Start(bool isService);
    void Stop();
    void Shutdown();
    bool IsInitialized() const noexcept { return m_initialized.load(std::memory_order_acquire); }
    bool IsRunning() const noexcept { return m_running.load(std::memory_order_acquire); }
    ServiceCommStatus GetStatus() const noexcept { return m_status.load(std::memory_order_acquire); }

    bool UpdateConfiguration(const ServiceCommConfiguration& config);
    ServiceCommConfiguration GetConfiguration() const;

    // Client side
    bool Connect(const std::wstring& pipeName, uint32_t timeoutMs);
    void Disconnect();
    bool IsConnected() const noexcept;
    ConnectionState GetConnectionState() const noexcept;

    // Messaging
    void SendCommand(const std::string& cmd);
    bool SendMessage(const ServiceMessage& msg);
    bool SendMessageToSession(const ServiceMessage& msg, const std::string& sessionId);
    std::optional<ServiceMessage> SendRequest(const ServiceMessage& req, uint32_t timeoutMs);
    void Broadcast(const ServiceMessage& msg);

    // High-level commands
    bool RequestScan(MessageType scanType, const std::vector<std::wstring>& targets, uint32_t opts);
    bool RequestStopScan();
    std::optional<std::string> RequestStatus();
    std::optional<std::string> RequestConfiguration();
    bool SendConfigurationUpdate(const std::string& json);

    // Events
    void SendThreatEvent(uint64_t threatId, const std::string& name, const std::wstring& path,
                         uint8_t sev, uint8_t action);
    void SendProgressEvent(uint64_t taskId, uint16_t progress, uint64_t processed,
                           uint64_t total, const std::wstring& item);
    void SendSystemAlert(const std::string& type, const std::string& msg, uint8_t sev);

    // Session management
    std::vector<ClientSession> GetConnectedClients() const;
    size_t GetClientCount() const noexcept;
    bool DisconnectClient(const std::string& sessionId);
    void DisconnectAllClients();

    // Callbacks
    void SetMessageCallback(std::function<void(const std::string&)> cb);
    void RegisterMessageCallback(ServiceMessageCallback cb);
    void RegisterConnectionCallback(ConnectionCallback cb);
    void RegisterCommandCallback(CommandCallback cb);
    void RegisterErrorCallback(ServiceErrorCallback cb);
    void UnregisterCallbacks();

    // Statistics
    ServiceCommStatisticsSnapshot GetStatistics() const noexcept;
    void ResetStatistics();
    bool SelfTest();

private:
    // Server-side
    void ListenerLoop();
    HANDLE CreateServerPipe();
    void AcceptClient(HANDLE pipeHandle);
    void ClientReaderLoop(const std::string& sessionId);

    // Client-side
    void ClientReaderLoopSelf();

    // Shared
    bool WriteMessage(HANDLE pipe, std::mutex& writeLock, const MessageHeader& hdr,
                      const void* payload, size_t payloadLen);
    bool ReadMessage(HANDLE pipe, MessageHeader& hdr, std::vector<uint8_t>& payload);
    void ProcessMessage(const std::string& sessionId, const MessageHeader& hdr,
                        const std::vector<uint8_t>& payload);
    void HandleHandshake(const std::string& sessionId, const MessageHeader& hdr,
                         const std::vector<uint8_t>& payload);
    void HandleCommand(const std::string& sessionId, const MessageHeader& hdr,
                       const std::vector<uint8_t>& payload);
    void HandleHeartbeat(const std::string& sessionId, const MessageHeader& hdr);

    // Heartbeat
    void HeartbeatLoop();

    void NotifyError(const std::string& msg, int code);
    void NotifyConnection(const ClientSession& session, bool connected);

    ConnectedClient* FindClient(const std::string& sessionId);

    // Pending requests (for SendRequest)
    struct PendingRequest {
        std::promise<ServiceMessage> promise;
        TimePoint deadline;
    };

    // Config
    ServiceCommConfiguration m_config;
    mutable std::shared_mutex m_configMutex;

    // State
    std::atomic<ServiceCommStatus> m_status{ServiceCommStatus::Uninitialized};
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_running{false};
    bool m_isService = false;

    // Server-side: listener + clients
    std::thread m_listenerThread;
    std::thread m_heartbeatThread;
    HANDLE m_listenerStopEvent = INVALID_HANDLE_VALUE;
    std::vector<std::unique_ptr<ConnectedClient>> m_clients;
    mutable std::shared_mutex m_clientsMutex;

    // Client-side: single connection
    HandleGuard m_clientPipe;
    std::thread m_clientReaderThread;
    std::atomic<ConnectionState> m_clientState{ConnectionState::Disconnected};
    std::atomic<uint32_t> m_clientSequence{0};
    std::mutex m_clientWriteMutex;

    // Pending requests
    std::unordered_map<uint32_t, std::shared_ptr<PendingRequest>> m_pendingRequests;
    std::mutex m_pendingMutex;

    // Callbacks
    std::function<void(const std::string&)> m_legacyCb;
    ServiceMessageCallback m_messageCb;
    ConnectionCallback m_connectionCb;
    CommandCallback m_commandCb;
    ServiceErrorCallback m_errorCb;
    mutable std::mutex m_callbackMutex;

    // Statistics
    ServiceCommStatistics m_stats;
};

// ============================================================================
// LIFECYCLE
// ============================================================================

bool ServiceCommunicationImpl::Initialize(const ServiceCommConfiguration& config) {
    ServiceCommStatus expected = ServiceCommStatus::Uninitialized;
    if (!m_status.compare_exchange_strong(expected, ServiceCommStatus::Initializing,
                                          std::memory_order_acq_rel)) {
        Utils::Logger::Warn("[ServiceComm] Already initialized (status={})",
                            static_cast<int>(expected));
        return false;
    }

    if (!config.IsValid()) {
        Utils::Logger::Error("[ServiceComm] Invalid configuration");
        m_status.store(ServiceCommStatus::Error, std::memory_order_release);
        return false;
    }

    {
        std::unique_lock lock(m_configMutex);
        m_config = config;
    }

    m_stats.Reset();

    m_initialized.store(true, std::memory_order_release);
    m_status.store(ServiceCommStatus::Stopped, std::memory_order_release);

    Utils::Logger::Info("[ServiceComm] Initialized — pipe={}, max_clients={}, encryption={}",
                        WideToUtf8(config.pipeName), config.maxClients,
                        config.enableEncryption ? "on" : "off");
    return true;
}

bool ServiceCommunicationImpl::Start(bool isService) {
    if (!m_initialized.load(std::memory_order_acquire)) {
        Utils::Logger::Error("[ServiceComm] Not initialized");
        return false;
    }

    if (m_running.load(std::memory_order_acquire)) {
        Utils::Logger::Warn("[ServiceComm] Already running");
        return false;
    }

    m_isService = isService;
    m_running.store(true, std::memory_order_release);

    if (m_isService) {
        m_listenerStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (m_listenerStopEvent == nullptr || m_listenerStopEvent == INVALID_HANDLE_VALUE) {
            Utils::Logger::Error("[ServiceComm] CreateEvent failed: {}", GetLastError());
            m_running.store(false, std::memory_order_release);
            return false;
        }

        m_listenerThread = std::thread([this] { ListenerLoop(); });
        m_heartbeatThread = std::thread([this] { HeartbeatLoop(); });

        m_status.store(ServiceCommStatus::Listening, std::memory_order_release);
        Utils::Logger::Info("[ServiceComm] Server started — listening for clients");
    } else {
        m_status.store(ServiceCommStatus::Running, std::memory_order_release);
        Utils::Logger::Info("[ServiceComm] Client mode started");
    }

    return true;
}

void ServiceCommunicationImpl::Stop() {
    if (!m_running.exchange(false, std::memory_order_acq_rel))
        return;

    m_status.store(ServiceCommStatus::Stopping, std::memory_order_release);

    // Signal listener to stop
    if (m_listenerStopEvent != INVALID_HANDLE_VALUE && m_listenerStopEvent != nullptr) {
        SetEvent(m_listenerStopEvent);
    }

    // Disconnect all clients (server side)
    DisconnectAllClients();

    // Disconnect self (client side)
    Disconnect();

    // Join threads
    if (m_listenerThread.joinable())
        m_listenerThread.join();
    if (m_heartbeatThread.joinable())
        m_heartbeatThread.join();

    if (m_listenerStopEvent != INVALID_HANDLE_VALUE && m_listenerStopEvent != nullptr) {
        CloseHandle(m_listenerStopEvent);
        m_listenerStopEvent = INVALID_HANDLE_VALUE;
    }

    // Fail all pending requests
    {
        std::lock_guard lock(m_pendingMutex);
        for (auto& [seq, req] : m_pendingRequests) {
            ServiceMessage empty;
            empty.type = MessageType::ResponseError;
            req->promise.set_value(std::move(empty));
        }
        m_pendingRequests.clear();
    }

    m_status.store(ServiceCommStatus::Stopped, std::memory_order_release);
    Utils::Logger::Info("[ServiceComm] Stopped");
}

void ServiceCommunicationImpl::Shutdown() {
    Stop();
    m_initialized.store(false, std::memory_order_release);
}

bool ServiceCommunicationImpl::UpdateConfiguration(const ServiceCommConfiguration& config) {
    if (!config.IsValid()) return false;
    std::unique_lock lock(m_configMutex);
    m_config = config;
    return true;
}

ServiceCommConfiguration ServiceCommunicationImpl::GetConfiguration() const {
    std::shared_lock lock(m_configMutex);
    return m_config;
}

// ============================================================================
// CLIENT-SIDE CONNECTION
// ============================================================================

bool ServiceCommunicationImpl::Connect(const std::wstring& pipeName, uint32_t timeoutMs) {
    if (m_clientState.load(std::memory_order_acquire) == ConnectionState::Connected)
        return true;

    m_clientState.store(ConnectionState::Connecting, std::memory_order_release);

    // Wait for pipe availability
    if (!WaitNamedPipeW(pipeName.c_str(), timeoutMs)) {
        const DWORD err = GetLastError();
        if (err != ERROR_SEM_TIMEOUT) {
            Utils::Logger::Error("[ServiceComm] WaitNamedPipe failed: {}", err);
        }
        m_clientState.store(ConnectionState::Disconnected, std::memory_order_release);
        m_stats.connectionsFailed.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    HANDLE hPipe = CreateFileW(
        pipeName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        nullptr);

    if (hPipe == INVALID_HANDLE_VALUE) {
        Utils::Logger::Error("[ServiceComm] CreateFile for pipe failed: {}", GetLastError());
        m_clientState.store(ConnectionState::Disconnected, std::memory_order_release);
        m_stats.connectionsFailed.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    // Set pipe to message mode
    DWORD mode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(hPipe, &mode, nullptr, nullptr);

    m_clientPipe = HandleGuard(hPipe);
    m_clientState.store(ConnectionState::Authenticating, std::memory_order_release);

    // Send handshake
    HandshakeMessage hs{};
    hs.header.magic = ServiceCommConstants::PROTOCOL_MAGIC;
    hs.header.version = ServiceCommConstants::PROTOCOL_VERSION;
    hs.header.type = MessageType::Handshake;
    hs.header.sequence = m_clientSequence.fetch_add(1, std::memory_order_relaxed);
    hs.header.payloadLength = sizeof(HandshakeMessage) - sizeof(MessageHeader);
    hs.clientType = ClientType::GUI;
    hs.processId = GetCurrentProcessId();

    const auto* payloadStart = reinterpret_cast<const uint8_t*>(&hs) + sizeof(MessageHeader);
    hs.header.checksum = ComputeCrc32(payloadStart, hs.header.payloadLength);

    DWORD written = 0;
    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent) {
        m_clientPipe.Close();
        m_clientState.store(ConnectionState::Disconnected, std::memory_order_release);
        return false;
    }
    HandleGuard ovEventGuard(ov.hEvent);

    if (!WriteFile(m_clientPipe.h, &hs, sizeof(hs), &written, &ov)) {
        if (GetLastError() == ERROR_IO_PENDING) {
            if (WaitForSingleObject(ov.hEvent, timeoutMs) != WAIT_OBJECT_0) {
                CancelIo(m_clientPipe.h);
                m_clientPipe.Close();
                m_clientState.store(ConnectionState::Disconnected, std::memory_order_release);
                return false;
            }
            GetOverlappedResult(m_clientPipe.h, &ov, &written, FALSE);
        } else {
            m_clientPipe.Close();
            m_clientState.store(ConnectionState::Disconnected, std::memory_order_release);
            return false;
        }
    }

    m_clientState.store(ConnectionState::Connected, std::memory_order_release);
    m_stats.connectionsTotal.fetch_add(1, std::memory_order_relaxed);

    // Start reader thread
    m_clientReaderThread = std::thread([this] { ClientReaderLoopSelf(); });

    Utils::Logger::Info("[ServiceComm] Connected to service pipe");
    return true;
}

void ServiceCommunicationImpl::Disconnect() {
    const auto prev = m_clientState.exchange(ConnectionState::Disconnected,
                                              std::memory_order_acq_rel);
    if (prev == ConnectionState::Disconnected)
        return;

    // Cancel pending I/O before closing handle
    if (m_clientPipe.IsValid())
        CancelIoEx(m_clientPipe.h, nullptr);

    m_clientPipe.Close();

    if (m_clientReaderThread.joinable())
        m_clientReaderThread.join();
}

bool ServiceCommunicationImpl::IsConnected() const noexcept {
    return m_clientState.load(std::memory_order_acquire) == ConnectionState::Connected;
}

ConnectionState ServiceCommunicationImpl::GetConnectionState() const noexcept {
    return m_clientState.load(std::memory_order_acquire);
}

// ============================================================================
// MESSAGING
// ============================================================================

void ServiceCommunicationImpl::SendCommand(const std::string& cmd) {
    ServiceMessage msg;
    msg.type = MessageType::CmdStartScan;
    msg.payload.assign(cmd.begin(), cmd.end());
    SendMessage(msg);
}

bool ServiceCommunicationImpl::SendMessage(const ServiceMessage& msg) {
    if (!m_isService) {
        // Client mode: send on client pipe
        if (!m_clientPipe.IsValid()) return false;
        MessageHeader hdr{};
        hdr.magic = ServiceCommConstants::PROTOCOL_MAGIC;
        hdr.version = ServiceCommConstants::PROTOCOL_VERSION;
        hdr.type = msg.type;
        hdr.sequence = m_clientSequence.fetch_add(1, std::memory_order_relaxed);
        hdr.responseTo = msg.responseTo;
        hdr.payloadLength = static_cast<uint32_t>(
            std::min(msg.payload.size(), ServiceCommConstants::MAX_MESSAGE_SIZE));
        hdr.checksum = ComputeCrc32(msg.payload.data(), hdr.payloadLength);

        return WriteMessage(m_clientPipe.h, m_clientWriteMutex, hdr,
                            msg.payload.data(), hdr.payloadLength);
    } else {
        // Server mode: broadcast to all
        Broadcast(msg);
        return true;
    }
}

bool ServiceCommunicationImpl::SendMessageToSession(const ServiceMessage& msg,
                                                     const std::string& sessionId) {
    std::shared_lock lock(m_clientsMutex);
    ConnectedClient* client = FindClient(sessionId);
    if (!client || !client->pipeHandle.IsValid()) return false;

    MessageHeader hdr{};
    hdr.magic = ServiceCommConstants::PROTOCOL_MAGIC;
    hdr.version = ServiceCommConstants::PROTOCOL_VERSION;
    hdr.type = msg.type;
    hdr.sequence = client->sequence.fetch_add(1, std::memory_order_relaxed);
    hdr.responseTo = msg.responseTo;
    hdr.payloadLength = static_cast<uint32_t>(
        std::min(msg.payload.size(), ServiceCommConstants::MAX_MESSAGE_SIZE));
    hdr.checksum = ComputeCrc32(msg.payload.data(), hdr.payloadLength);

    return WriteMessage(client->pipeHandle.h, client->writeMutex, hdr,
                        msg.payload.data(), hdr.payloadLength);
}

std::optional<ServiceMessage> ServiceCommunicationImpl::SendRequest(
    const ServiceMessage& req, uint32_t timeoutMs) {
    const uint32_t seq = m_isService ? 0 :
        m_clientSequence.fetch_add(1, std::memory_order_relaxed);

    auto pending = std::make_shared<PendingRequest>();
    pending->deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
    auto future = pending->promise.get_future();

    {
        std::lock_guard lock(m_pendingMutex);
        m_pendingRequests[seq] = pending;
    }

    ServiceMessage reqCopy = req;
    reqCopy.sequence = seq;
    if (!SendMessage(reqCopy)) {
        std::lock_guard lock(m_pendingMutex);
        m_pendingRequests.erase(seq);
        return std::nullopt;
    }

    if (future.wait_for(std::chrono::milliseconds(timeoutMs)) != std::future_status::ready) {
        std::lock_guard lock(m_pendingMutex);
        m_pendingRequests.erase(seq);
        return std::nullopt;
    }

    return future.get();
}

void ServiceCommunicationImpl::Broadcast(const ServiceMessage& msg) {
    std::shared_lock lock(m_clientsMutex);
    for (auto& client : m_clients) {
        if (!client || !client->pipeHandle.IsValid() ||
            client->state.load(std::memory_order_acquire) != ConnectionState::Connected)
            continue;

        MessageHeader hdr{};
        hdr.magic = ServiceCommConstants::PROTOCOL_MAGIC;
        hdr.version = ServiceCommConstants::PROTOCOL_VERSION;
        hdr.type = msg.type;
        hdr.sequence = client->sequence.fetch_add(1, std::memory_order_relaxed);
        hdr.payloadLength = static_cast<uint32_t>(
            std::min(msg.payload.size(), ServiceCommConstants::MAX_MESSAGE_SIZE));
        hdr.checksum = ComputeCrc32(msg.payload.data(), hdr.payloadLength);

        WriteMessage(client->pipeHandle.h, client->writeMutex, hdr,
                     msg.payload.data(), hdr.payloadLength);
    }
}

// ============================================================================
// HIGH-LEVEL COMMANDS
// ============================================================================

bool ServiceCommunicationImpl::RequestScan(MessageType scanType,
                                            const std::vector<std::wstring>& targets,
                                            uint32_t opts) {
    ServiceMessage msg;
    msg.type = scanType;

    // Serialize targets as JSON array
    std::string json = "{\"options\":" + std::to_string(opts) + ",\"targets\":[";
    for (size_t i = 0; i < targets.size(); ++i) {
        if (i > 0) json += ",";
        json += "\"" + JsonEscape(WideToUtf8(targets[i])) + "\"";
    }
    json += "]}";
    msg.payload.assign(json.begin(), json.end());
    return SendMessage(msg);
}

bool ServiceCommunicationImpl::RequestStopScan() {
    ServiceMessage msg;
    msg.type = MessageType::CmdStopScan;
    return SendMessage(msg);
}

std::optional<std::string> ServiceCommunicationImpl::RequestStatus() {
    ServiceMessage req;
    req.type = MessageType::QueryStatus;
    auto resp = SendRequest(req, 5000);
    if (!resp) return std::nullopt;
    return resp->GetPayloadString();
}

std::optional<std::string> ServiceCommunicationImpl::RequestConfiguration() {
    ServiceMessage req;
    req.type = MessageType::CmdGetConfig;
    auto resp = SendRequest(req, 5000);
    if (!resp) return std::nullopt;
    return resp->GetPayloadString();
}

bool ServiceCommunicationImpl::SendConfigurationUpdate(const std::string& json) {
    ServiceMessage msg;
    msg.type = MessageType::CmdSetConfig;
    msg.payload.assign(json.begin(), json.end());
    return SendMessage(msg);
}

// ============================================================================
// EVENT SENDERS
// ============================================================================

void ServiceCommunicationImpl::SendThreatEvent(uint64_t threatId, const std::string& name,
                                                const std::wstring& path, uint8_t sev,
                                                uint8_t action) {
    std::string json = "{\"threatId\":" + std::to_string(threatId) + ",";
    json += "\"name\":\"" + JsonEscape(name) + "\",";
    json += "\"path\":\"" + JsonEscape(WideToUtf8(path)) + "\",";
    json += "\"severity\":" + std::to_string(sev) + ",";
    json += "\"action\":" + std::to_string(action) + "}";

    ServiceMessage msg;
    msg.type = MessageType::EventThreat;
    msg.payload.assign(json.begin(), json.end());
    Broadcast(msg);
}

void ServiceCommunicationImpl::SendProgressEvent(uint64_t taskId, uint16_t progress,
                                                  uint64_t processed, uint64_t total,
                                                  const std::wstring& item) {
    std::string json = "{\"taskId\":" + std::to_string(taskId) + ",";
    json += "\"progress\":" + std::to_string(progress) + ",";
    json += "\"processed\":" + std::to_string(processed) + ",";
    json += "\"total\":" + std::to_string(total);
    if (!item.empty())
        json += ",\"currentItem\":\"" + JsonEscape(WideToUtf8(item)) + "\"";
    json += "}";

    ServiceMessage msg;
    msg.type = MessageType::EventScanProgress;
    msg.payload.assign(json.begin(), json.end());
    Broadcast(msg);
}

void ServiceCommunicationImpl::SendSystemAlert(const std::string& type,
                                                const std::string& message,
                                                uint8_t sev) {
    std::string json = "{\"alertType\":\"" + JsonEscape(type) + "\",";
    json += "\"message\":\"" + JsonEscape(message) + "\",";
    json += "\"severity\":" + std::to_string(sev) + "}";

    ServiceMessage msg;
    msg.type = MessageType::EventSystemAlert;
    msg.payload.assign(json.begin(), json.end());
    Broadcast(msg);
}

// ============================================================================
// SESSION MANAGEMENT
// ============================================================================

std::vector<ClientSession> ServiceCommunicationImpl::GetConnectedClients() const {
    std::shared_lock lock(m_clientsMutex);
    std::vector<ClientSession> result;
    result.reserve(m_clients.size());
    for (const auto& c : m_clients) {
        if (!c) continue;
        ClientSession s;
        s.sessionId = c->sessionId;
        s.clientType = c->clientType;
        s.processId = c->processId;
        s.pipeHandle = c->pipeHandle.h;
        s.state = c->state.load(std::memory_order_acquire);
        s.connectedTime = c->connectedTime;
        s.lastActivity = c->lastActivity;
        s.messagesSent = c->messagesSent.load(std::memory_order_relaxed);
        s.messagesReceived = c->messagesReceived.load(std::memory_order_relaxed);
        s.sequence.store(c->sequence.load(std::memory_order_relaxed), std::memory_order_relaxed);
        s.isAuthenticated = c->isAuthenticated;
        s.capabilities = c->capabilities;
        result.push_back(std::move(s));
    }
    return result;
}

size_t ServiceCommunicationImpl::GetClientCount() const noexcept {
    std::shared_lock lock(m_clientsMutex);
    size_t count = 0;
    for (const auto& c : m_clients) {
        if (c && c->state.load(std::memory_order_relaxed) == ConnectionState::Connected) ++count;
    }
    return count;
}

bool ServiceCommunicationImpl::DisconnectClient(const std::string& sessionId) {
    std::unique_lock lock(m_clientsMutex);
    for (auto it = m_clients.begin(); it != m_clients.end(); ++it) {
        if (*it && (*it)->sessionId == sessionId) {
            (*it)->running.store(false, std::memory_order_release);
            (*it)->state.store(ConnectionState::Disconnected, std::memory_order_release);
            if ((*it)->pipeHandle.IsValid())
                CancelIoEx((*it)->pipeHandle.h, nullptr);

            // Must release lock before joining reader thread to avoid deadlock
            auto client = std::move(*it);
            m_clients.erase(it);
            lock.unlock();

            // Join the reader thread outside the lock
            if (client->readerThread.joinable())
                client->readerThread.join();

            Utils::Logger::Info("[ServiceComm] Client disconnected: {}", sessionId);
            return true;
        }
    }
    return false;
}

void ServiceCommunicationImpl::DisconnectAllClients() {
    std::vector<std::unique_ptr<ConnectedClient>> snapshot;
    {
        std::unique_lock lock(m_clientsMutex);
        snapshot = std::move(m_clients);
        m_clients.clear();
    }

    for (auto& client : snapshot) {
        if (!client) continue;
        client->running.store(false, std::memory_order_release);
        client->state.store(ConnectionState::Disconnected, std::memory_order_release);
        if (client->pipeHandle.IsValid())
            CancelIoEx(client->pipeHandle.h, nullptr);
        if (client->readerThread.joinable())
            client->readerThread.join();
    }
}

// ============================================================================
// CALLBACKS
// ============================================================================

void ServiceCommunicationImpl::SetMessageCallback(std::function<void(const std::string&)> cb) {
    std::lock_guard lock(m_callbackMutex);
    m_legacyCb = std::move(cb);
}

void ServiceCommunicationImpl::RegisterMessageCallback(ServiceMessageCallback cb) {
    std::lock_guard lock(m_callbackMutex);
    m_messageCb = std::move(cb);
}

void ServiceCommunicationImpl::RegisterConnectionCallback(ConnectionCallback cb) {
    std::lock_guard lock(m_callbackMutex);
    m_connectionCb = std::move(cb);
}

void ServiceCommunicationImpl::RegisterCommandCallback(CommandCallback cb) {
    std::lock_guard lock(m_callbackMutex);
    m_commandCb = std::move(cb);
}

void ServiceCommunicationImpl::RegisterErrorCallback(ServiceErrorCallback cb) {
    std::lock_guard lock(m_callbackMutex);
    m_errorCb = std::move(cb);
}

void ServiceCommunicationImpl::UnregisterCallbacks() {
    std::lock_guard lock(m_callbackMutex);
    m_legacyCb = nullptr;
    m_messageCb = nullptr;
    m_connectionCb = nullptr;
    m_commandCb = nullptr;
    m_errorCb = nullptr;
}

// ============================================================================
// STATISTICS
// ============================================================================

ServiceCommStatisticsSnapshot ServiceCommunicationImpl::GetStatistics() const noexcept {
    return m_stats.TakeSnapshot();
}

void ServiceCommunicationImpl::ResetStatistics() {
    m_stats.Reset();
}

bool ServiceCommunicationImpl::SelfTest() {
    if (!m_initialized.load(std::memory_order_acquire))
        return false;
    return m_status.load(std::memory_order_acquire) != ServiceCommStatus::Error;
}

// ============================================================================
// SERVER — LISTENER
// ============================================================================

HANDLE ServiceCommunicationImpl::CreateServerPipe() {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    SecurityDescriptorGuard sdGuard;

    // Secure DACL: SYSTEM=Full, Admins=Full, Interactive Users=Read+Write
    const wchar_t* sddl = L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &sdGuard.sd, nullptr)) {
        Utils::Logger::Error("[ServiceComm] SDDL conversion failed: {}", GetLastError());
        return INVALID_HANDLE_VALUE;
    }
    sa.lpSecurityDescriptor = sdGuard.sd;
    sa.bInheritHandle = FALSE;

    std::wstring pipeName;
    {
        std::shared_lock lock(m_configMutex);
        pipeName = m_config.pipeName;
    }

    HANDLE hPipe = CreateNamedPipeW(
        pipeName.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_UNLIMITED_INSTANCES,
        static_cast<DWORD>(ServiceCommConstants::MAX_MESSAGE_SIZE),
        static_cast<DWORD>(ServiceCommConstants::MAX_MESSAGE_SIZE),
        0,
        &sa);

    if (hPipe == INVALID_HANDLE_VALUE) {
        // First instance flag may fail if pipe exists; retry without it
        hPipe = CreateNamedPipeW(
            pipeName.c_str(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            static_cast<DWORD>(ServiceCommConstants::MAX_MESSAGE_SIZE),
            static_cast<DWORD>(ServiceCommConstants::MAX_MESSAGE_SIZE),
            0,
            &sa);
    }

    return hPipe;
}

void ServiceCommunicationImpl::ListenerLoop() {
    Utils::Logger::Debug("[ServiceComm] Listener thread started");

    while (m_running.load(std::memory_order_acquire)) {
        HANDLE hPipe = CreateServerPipe();
        if (hPipe == INVALID_HANDLE_VALUE) {
            Utils::Logger::Error("[ServiceComm] CreateNamedPipe failed: {}", GetLastError());
            m_stats.errors.fetch_add(1, std::memory_order_relaxed);
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        OVERLAPPED ov{};
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!ov.hEvent) {
            CloseHandle(hPipe);
            continue;
        }
        HandleGuard ovEventGuard(ov.hEvent);

        BOOL connected = ConnectNamedPipe(hPipe, &ov);
        if (!connected) {
            const DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                HANDLE waitHandles[2] = { ov.hEvent, m_listenerStopEvent };
                const DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);

                if (waitResult == WAIT_OBJECT_0 + 1 ||
                    !m_running.load(std::memory_order_acquire)) {
                    CancelIo(hPipe);
                    CloseHandle(hPipe);
                    break;
                }

                if (waitResult != WAIT_OBJECT_0) {
                    CloseHandle(hPipe);
                    continue;
                }
            } else if (err == ERROR_PIPE_CONNECTED) {
                // Client already connected
            } else {
                Utils::Logger::Error("[ServiceComm] ConnectNamedPipe failed: {}", err);
                CloseHandle(hPipe);
                m_stats.errors.fetch_add(1, std::memory_order_relaxed);
                continue;
            }
        }

        // Check max clients
        uint32_t maxClients = 0;
        {
            std::shared_lock lock(m_configMutex);
            maxClients = m_config.maxClients;
        }
        if (GetClientCount() >= maxClients) {
            Utils::Logger::Warn("[ServiceComm] Max clients reached ({}), rejecting", maxClients);
            CloseHandle(hPipe);
            m_stats.connectionsFailed.fetch_add(1, std::memory_order_relaxed);
            continue;
        }

        AcceptClient(hPipe);
    }

    Utils::Logger::Debug("[ServiceComm] Listener thread exiting");
}

void ServiceCommunicationImpl::AcceptClient(HANDLE pipeHandle) {
    auto client = std::make_unique<ConnectedClient>();
    client->sessionId = GenerateSessionId();
    client->pipeHandle = HandleGuard(pipeHandle);
    client->state.store(ConnectionState::Authenticating, std::memory_order_release);
    client->connectedTime = std::chrono::system_clock::now();
    client->lastActivity = Clock::now();
    client->running.store(true, std::memory_order_release);

    // Get client PID (security check)
    ULONG clientPid = 0;
    if (GetNamedPipeClientProcessId(pipeHandle, &clientPid))
        client->processId = clientPid;

    m_stats.connectionsTotal.fetch_add(1, std::memory_order_relaxed);

    const std::string sessionId = client->sessionId;

    // Start reader thread for this client
    client->readerThread = std::thread([this, sid = sessionId] { ClientReaderLoop(sid); });

    {
        std::unique_lock lock(m_clientsMutex);
        m_clients.push_back(std::move(client));
    }

    Utils::Logger::Info("[ServiceComm] Client accepted: session={}, pid={}",
                        sessionId, clientPid);
}

// ============================================================================
// SERVER — PER-CLIENT READER
// ============================================================================

void ServiceCommunicationImpl::ClientReaderLoop(const std::string& sessionId) {
    Utils::Logger::Debug("[ServiceComm] Client reader started: {}", sessionId);

    while (m_running.load(std::memory_order_acquire)) {
        // Copy pipe handle under lock — prevents UAF on ConnectedClient
        HANDLE pipeHandle = INVALID_HANDLE_VALUE;
        bool clientRunning = false;
        {
            std::shared_lock lock(m_clientsMutex);
            ConnectedClient* client = FindClient(sessionId);
            if (!client) break;
            clientRunning = client->running.load(std::memory_order_acquire);
            pipeHandle = client->pipeHandle.h;
        }
        if (!clientRunning || pipeHandle == INVALID_HANDLE_VALUE)
            break;

        MessageHeader hdr{};
        std::vector<uint8_t> payload;

        // ReadMessage on copied handle — safe because handle is not closed until
        // after this thread joins (DisconnectClient joins before destruction).
        // CancelIoEx will cause ReadFile to fail, breaking out of this loop.
        if (!ReadMessage(pipeHandle, hdr, payload)) {
            Utils::Logger::Debug("[ServiceComm] Client reader pipe error: {}", sessionId);
            break;
        }

        // Read config for rate limiting BEFORE client lock (lock ordering: config → clients)
        bool rateLimitEnabled = false;
        uint32_t maxMps = 0;
        {
            std::shared_lock cfgLock(m_configMutex);
            rateLimitEnabled = m_config.enableRateLimiting;
            maxMps = m_config.maxMessagesPerSecond;
        }

        // Re-acquire lock to update client stats
        bool rateLimitExceeded = false;
        {
            std::shared_lock lock(m_clientsMutex);
            ConnectedClient* client = FindClient(sessionId);
            if (!client) break;

            client->lastActivity = Clock::now();
            client->messagesReceived.fetch_add(1, std::memory_order_relaxed);
            m_stats.messagesReceived.fetch_add(1, std::memory_order_relaxed);
            m_stats.bytesReceived.fetch_add(sizeof(hdr) + payload.size(), std::memory_order_relaxed);

            const auto typeIdx = static_cast<uint16_t>(hdr.type);
            if (typeIdx < m_stats.byMessageType.size())
                m_stats.byMessageType[typeIdx].fetch_add(1, std::memory_order_relaxed);

            // Per-client rate limiting (rateWindowStart only written by this reader thread)
            if (rateLimitEnabled && maxMps > 0) {
                const auto now = Clock::now();
                const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    now - client->rateWindowStart);
                if (elapsed.count() >= 1) {
                    client->messagesThisWindow = 0;
                    client->rateWindowStart = now;
                }
                if (++client->messagesThisWindow > maxMps) {
                    Utils::Logger::Warn("[ServiceComm] Client {} exceeded rate limit ({}/s), disconnecting",
                                        sessionId, maxMps);
                    client->running.store(false, std::memory_order_release);
                    rateLimitExceeded = true;
                }
            }
        }

        if (rateLimitExceeded)
            break;

        ProcessMessage(sessionId, hdr, payload);
    }

    // Notify disconnection — re-acquire lock to safely access client
    {
        std::shared_lock lock(m_clientsMutex);
        ConnectedClient* client = FindClient(sessionId);
        if (client) {
            client->state.store(ConnectionState::Disconnected, std::memory_order_release);
            client->running.store(false, std::memory_order_release);

            ClientSession session;
            session.sessionId = sessionId;
            session.clientType = client->clientType;
            session.processId = client->processId;

            ConnectionCallback cb;
            {
                std::lock_guard cbLock(m_callbackMutex);
                cb = m_connectionCb;
            }
            if (cb) {
                try { cb(session, false); }
                catch (...) {}
            }
        }
    }

    Utils::Logger::Debug("[ServiceComm] Client reader exiting: {}", sessionId);
}

// ============================================================================
// CLIENT — SELF READER
// ============================================================================

void ServiceCommunicationImpl::ClientReaderLoopSelf() {
    Utils::Logger::Debug("[ServiceComm] Client self-reader started");

    while (m_clientState.load(std::memory_order_acquire) == ConnectionState::Connected) {
        if (!m_clientPipe.IsValid())
            break;

        MessageHeader hdr{};
        std::vector<uint8_t> payload;

        if (!ReadMessage(m_clientPipe.h, hdr, payload)) {
            m_clientState.store(ConnectionState::Disconnected, std::memory_order_release);
            Utils::Logger::Warn("[ServiceComm] Disconnected from service (read error)");
            break;
        }

        m_stats.messagesReceived.fetch_add(1, std::memory_order_relaxed);
        m_stats.bytesReceived.fetch_add(sizeof(hdr) + payload.size(), std::memory_order_relaxed);

        // Check if this is a response to a pending request
        if (hdr.responseTo != 0) {
            std::lock_guard lock(m_pendingMutex);
            auto it = m_pendingRequests.find(hdr.responseTo);
            if (it != m_pendingRequests.end()) {
                ServiceMessage resp;
                resp.type = hdr.type;
                resp.sequence = hdr.sequence;
                resp.responseTo = hdr.responseTo;
                resp.payload = std::move(payload);
                resp.timestamp = std::chrono::system_clock::now();
                it->second->promise.set_value(std::move(resp));
                m_pendingRequests.erase(it);
                continue;
            }
        }

        // Dispatch to callbacks
        ServiceMessage msg;
        msg.type = hdr.type;
        msg.sequence = hdr.sequence;
        msg.payload = std::move(payload);
        msg.timestamp = std::chrono::system_clock::now();

        ServiceMessageCallback cb;
        std::function<void(const std::string&)> legacyCb;
        {
            std::lock_guard cbLock(m_callbackMutex);
            cb = m_messageCb;
            legacyCb = m_legacyCb;
        }
        if (cb) {
            try { cb(msg, ""); }
            catch (...) {}
        }
        if (legacyCb) {
            try { legacyCb(msg.GetPayloadString()); }
            catch (...) {}
        }
    }

    Utils::Logger::Debug("[ServiceComm] Client self-reader exiting");
}

// ============================================================================
// SHARED I/O
// ============================================================================

bool ServiceCommunicationImpl::WriteMessage(HANDLE pipe, std::mutex& writeLock,
                                             const MessageHeader& hdr,
                                             const void* payload, size_t payloadLen) {
    if (pipe == INVALID_HANDLE_VALUE || pipe == nullptr)
        return false;

    std::lock_guard lock(writeLock);

    // Write header
    DWORD written = 0;
    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent) return false;
    HandleGuard ovGuard(ov.hEvent);

    if (!WriteFile(pipe, &hdr, sizeof(hdr), &written, &ov)) {
        if (GetLastError() == ERROR_IO_PENDING) {
            if (WaitForSingleObject(ov.hEvent, 5000) != WAIT_OBJECT_0) {
                CancelIo(pipe);
                return false;
            }
            if (!GetOverlappedResult(pipe, &ov, &written, FALSE))
                return false;
        } else {
            return false;
        }
    }

    // Write payload
    if (payloadLen > 0 && payload) {
        ResetEvent(ov.hEvent);
        if (!WriteFile(pipe, payload, static_cast<DWORD>(payloadLen), &written, &ov)) {
            if (GetLastError() == ERROR_IO_PENDING) {
                if (WaitForSingleObject(ov.hEvent, 5000) != WAIT_OBJECT_0) {
                    CancelIo(pipe);
                    return false;
                }
                if (!GetOverlappedResult(pipe, &ov, &written, FALSE))
                    return false;
            } else {
                return false;
            }
        }
    }

    m_stats.messagesSent.fetch_add(1, std::memory_order_relaxed);
    m_stats.bytesSent.fetch_add(sizeof(hdr) + payloadLen, std::memory_order_relaxed);
    return true;
}

bool ServiceCommunicationImpl::ReadMessage(HANDLE pipe, MessageHeader& hdr,
                                            std::vector<uint8_t>& payload) {
    if (pipe == INVALID_HANDLE_VALUE || pipe == nullptr)
        return false;

    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent) return false;
    HandleGuard ovGuard(ov.hEvent);

    // Read header
    DWORD bytesRead = 0;
    if (!ReadFile(pipe, &hdr, sizeof(hdr), &bytesRead, &ov)) {
        if (GetLastError() == ERROR_IO_PENDING) {
            if (WaitForSingleObject(ov.hEvent, 30000) != WAIT_OBJECT_0) {
                CancelIo(pipe);
                return false;
            }
            if (!GetOverlappedResult(pipe, &ov, &bytesRead, FALSE))
                return false;
        } else {
            return false;
        }
    }

    if (bytesRead < sizeof(MessageHeader))
        return false;

    // Validate magic
    if (hdr.magic != ServiceCommConstants::PROTOCOL_MAGIC) {
        Utils::Logger::Warn("[ServiceComm] Invalid magic: 0x{:08X}", hdr.magic);
        m_stats.errors.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    // Validate payload length
    if (hdr.payloadLength > ServiceCommConstants::MAX_MESSAGE_SIZE) {
        Utils::Logger::Warn("[ServiceComm] Payload too large: {} bytes", hdr.payloadLength);
        m_stats.errors.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    // Read payload
    if (hdr.payloadLength > 0) {
        payload.resize(hdr.payloadLength);
        ResetEvent(ov.hEvent);

        if (!ReadFile(pipe, payload.data(), hdr.payloadLength, &bytesRead, &ov)) {
            if (GetLastError() == ERROR_IO_PENDING) {
                if (WaitForSingleObject(ov.hEvent, 10000) != WAIT_OBJECT_0) {
                    CancelIo(pipe);
                    return false;
                }
                if (!GetOverlappedResult(pipe, &ov, &bytesRead, FALSE))
                    return false;
            } else {
                return false;
            }
        }

        if (bytesRead < hdr.payloadLength) {
            payload.resize(bytesRead);
        }

        // Verify checksum
        const uint32_t computed = ComputeCrc32(payload.data(), bytesRead);
        if (computed != hdr.checksum) {
            Utils::Logger::Warn("[ServiceComm] Checksum mismatch: expected=0x{:08X}, got=0x{:08X}",
                                hdr.checksum, computed);
            m_stats.errors.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
    }

    return true;
}

// ============================================================================
// MESSAGE PROCESSING
// ============================================================================

void ServiceCommunicationImpl::ProcessMessage(const std::string& sessionId,
                                               const MessageHeader& hdr,
                                               const std::vector<uint8_t>& payload) {
    switch (hdr.type) {
        case MessageType::Handshake:
            HandleHandshake(sessionId, hdr, payload);
            break;

        case MessageType::Heartbeat:
            HandleHeartbeat(sessionId, hdr);
            break;

        case MessageType::Disconnect: {
            Utils::Logger::Info("[ServiceComm] Client {} sent disconnect", sessionId);
            std::shared_lock lock(m_clientsMutex);
            ConnectedClient* client = FindClient(sessionId);
            if (client) {
                client->state.store(ConnectionState::Disconnected, std::memory_order_release);
                client->running.store(false, std::memory_order_release);
            }
            break;
        }

        default: {
            // Response to pending request
            if (hdr.responseTo != 0) {
                std::lock_guard lock(m_pendingMutex);
                auto it = m_pendingRequests.find(hdr.responseTo);
                if (it != m_pendingRequests.end()) {
                    ServiceMessage resp;
                    resp.type = hdr.type;
                    resp.sequence = hdr.sequence;
                    resp.responseTo = hdr.responseTo;
                    resp.payload = payload;
                    resp.timestamp = std::chrono::system_clock::now();
                    it->second->promise.set_value(std::move(resp));
                    m_pendingRequests.erase(it);
                    return;
                }
            }

            // Commands: dispatch to command callback
            const auto typeVal = static_cast<uint16_t>(hdr.type);
            if (typeVal >= 0x0100 && typeVal < 0x1000) {
                HandleCommand(sessionId, hdr, payload);
                return;
            }

            // Events/general: dispatch to message callback
            ServiceMessage msg;
            msg.type = hdr.type;
            msg.sequence = hdr.sequence;
            msg.payload = payload;
            msg.timestamp = std::chrono::system_clock::now();
            msg.sourceSession = sessionId;

            ServiceMessageCallback cb;
            std::function<void(const std::string&)> legacyCb;
            {
                std::lock_guard cbLock(m_callbackMutex);
                cb = m_messageCb;
                legacyCb = m_legacyCb;
            }
            if (cb) {
                try { cb(msg, sessionId); }
                catch (...) {}
            }
            if (legacyCb) {
                try { legacyCb(msg.GetPayloadString()); }
                catch (...) {}
            }
            break;
        }
    }
}

void ServiceCommunicationImpl::HandleHandshake(const std::string& sessionId,
                                                const MessageHeader& hdr,
                                                const std::vector<uint8_t>& payload) {
    std::shared_lock lock(m_clientsMutex);
    ConnectedClient* client = FindClient(sessionId);
    if (!client) return;

    // HandshakeMessage payload layout (pack(1)):
    //   [0]       ClientType (1 byte)
    //   [1..16]   clientVersion (16 bytes = 4x uint32_t)
    //   [17..48]  sessionToken (32 bytes)
    //   [49..52]  processId (4 bytes)
    //   [53..60]  capabilities (8 bytes)
    constexpr size_t kMinPayload = 1 + 16 + 32 + 4 + 8;  // 61 bytes

    if (payload.size() >= kMinPayload) {
        const auto* p = payload.data();

        // Validate ClientType range
        const uint8_t ctRaw = p[0];
        ClientType ct = (ctRaw <= static_cast<uint8_t>(ClientType::API))
                        ? static_cast<ClientType>(ctRaw)
                        : ClientType::Unknown;

        uint32_t pid = 0;
        uint64_t caps = 0;
        memcpy(&pid, p + 1 + 16 + 32, sizeof(pid));
        memcpy(&caps, p + 1 + 16 + 32 + 4, sizeof(caps));

        client->clientType = ct;
        if (pid != 0) client->processId = pid;
        client->capabilities = caps;
    }

    client->state.store(ConnectionState::Connected, std::memory_order_release);
    client->isAuthenticated = true;

    // Send HandshakeAck
    MessageHeader ack{};
    ack.magic = ServiceCommConstants::PROTOCOL_MAGIC;
    ack.version = ServiceCommConstants::PROTOCOL_VERSION;
    ack.type = MessageType::HandshakeAck;
    ack.sequence = client->sequence.fetch_add(1, std::memory_order_relaxed);
    ack.responseTo = hdr.sequence;
    ack.payloadLength = 0;
    ack.checksum = 0;

    WriteMessage(client->pipeHandle.h, client->writeMutex, ack, nullptr, 0);

    // Snapshot fields before releasing lock to avoid UAF in logger/callback
    ClientSession session;
    session.sessionId = sessionId;
    session.clientType = client->clientType;
    session.processId = client->processId;
    session.state = ConnectionState::Connected;
    session.connectedTime = client->connectedTime;

    lock.unlock();
    NotifyConnection(session, true);

    Utils::Logger::Info("[ServiceComm] Client authenticated: session={}, type={}, pid={}",
                        sessionId,
                        GetClientTypeName(session.clientType),
                        session.processId);
}

void ServiceCommunicationImpl::HandleCommand(const std::string& sessionId,
                                              const MessageHeader& hdr,
                                              const std::vector<uint8_t>& payload) {
    // Enforce privilege check for config-changing / protection-disabling commands
    if (IsPrivilegedCommand(hdr.type)) {
        HANDLE pipeHandle = INVALID_HANDLE_VALUE;
        {
            std::shared_lock lock(m_clientsMutex);
            ConnectedClient* client = FindClient(sessionId);
            if (client)
                pipeHandle = client->pipeHandle.h;
        }

        if (pipeHandle == INVALID_HANDLE_VALUE || !IsCallerAdmin(pipeHandle)) {
            Utils::Logger::Warn("[ServiceComm] Non-admin attempted privileged command '{}' from {}",
                                GetMessageTypeName(hdr.type), sessionId);
            m_stats.authFailures.fetch_add(1, std::memory_order_relaxed);

            // Send PermissionDenied response
            std::string errJson = "{\"error\":\"PermissionDenied\","
                                  "\"message\":\"Administrative privileges required\"}";
            MessageHeader resp{};
            resp.magic = ServiceCommConstants::PROTOCOL_MAGIC;
            resp.version = ServiceCommConstants::PROTOCOL_VERSION;
            resp.type = MessageType::ResponseError;
            resp.responseTo = hdr.sequence;
            resp.payloadLength = static_cast<uint32_t>(errJson.size());
            resp.checksum = ComputeCrc32(errJson.data(), errJson.size());

            std::shared_lock lock(m_clientsMutex);
            ConnectedClient* client = FindClient(sessionId);
            if (client) {
                resp.sequence = client->sequence.fetch_add(1, std::memory_order_relaxed);
                WriteMessage(client->pipeHandle.h, client->writeMutex, resp,
                             errJson.data(), errJson.size());
            }
            return;
        }
    }

    CommandCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_commandCb;
    }

    std::vector<uint8_t> response;
    bool handled = false;

    if (cb) {
        try { handled = cb(hdr.type, payload, response); }
        catch (const std::exception& ex) {
            Utils::Logger::Error("[ServiceComm] Command callback threw: {}", ex.what());
        }
    }

    // Send response
    MessageHeader resp{};
    resp.magic = ServiceCommConstants::PROTOCOL_MAGIC;
    resp.version = ServiceCommConstants::PROTOCOL_VERSION;
    resp.type = handled ? MessageType::ResponseOk : MessageType::ResponseError;
    resp.responseTo = hdr.sequence;
    resp.payloadLength = static_cast<uint32_t>(
        std::min(response.size(), ServiceCommConstants::MAX_MESSAGE_SIZE));
    resp.checksum = response.empty() ? 0 : ComputeCrc32(response.data(), resp.payloadLength);

    std::shared_lock lock(m_clientsMutex);
    ConnectedClient* client = FindClient(sessionId);
    if (client) {
        resp.sequence = client->sequence.fetch_add(1, std::memory_order_relaxed);
        WriteMessage(client->pipeHandle.h, client->writeMutex, resp,
                     response.empty() ? nullptr : response.data(), resp.payloadLength);
    }
}

void ServiceCommunicationImpl::HandleHeartbeat(const std::string& sessionId,
                                                const MessageHeader& hdr) {
    std::shared_lock lock(m_clientsMutex);
    ConnectedClient* client = FindClient(sessionId);
    if (!client) return;

    client->lastActivity = Clock::now();

    MessageHeader ack{};
    ack.magic = ServiceCommConstants::PROTOCOL_MAGIC;
    ack.version = ServiceCommConstants::PROTOCOL_VERSION;
    ack.type = MessageType::HeartbeatAck;
    ack.sequence = client->sequence.fetch_add(1, std::memory_order_relaxed);
    ack.responseTo = hdr.sequence;
    ack.payloadLength = 0;
    ack.checksum = 0;

    WriteMessage(client->pipeHandle.h, client->writeMutex, ack, nullptr, 0);
}

// ============================================================================
// HEARTBEAT
// ============================================================================

void ServiceCommunicationImpl::HeartbeatLoop() {
    Utils::Logger::Debug("[ServiceComm] Heartbeat thread started");

    while (m_running.load(std::memory_order_acquire)) {
        uint32_t interval = 0;
        {
            std::shared_lock lock(m_configMutex);
            interval = m_config.heartbeatIntervalMs;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(interval));

        if (!m_running.load(std::memory_order_acquire))
            break;

        // Send heartbeat to all connected clients; unique_lock for stale-client state writes
        std::unique_lock lock(m_clientsMutex);
        const auto now = Clock::now();
        for (auto& client : m_clients) {
            if (!client || client->state.load(std::memory_order_acquire) != ConnectionState::Connected)
                continue;

            // Check for stale connections (3x heartbeat interval)
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - client->lastActivity);
            if (elapsed.count() > static_cast<int64_t>(interval) * 3) {
                Utils::Logger::Warn("[ServiceComm] Client {} timed out", client->sessionId);
                client->state.store(ConnectionState::Disconnected, std::memory_order_release);
                client->running.store(false, std::memory_order_release);
                if (client->pipeHandle.IsValid())
                    CancelIoEx(client->pipeHandle.h, nullptr);
                continue;
            }

            MessageHeader hb{};
            hb.magic = ServiceCommConstants::PROTOCOL_MAGIC;
            hb.version = ServiceCommConstants::PROTOCOL_VERSION;
            hb.type = MessageType::Heartbeat;
            hb.sequence = client->sequence.fetch_add(1, std::memory_order_relaxed);
            hb.payloadLength = 0;
            hb.checksum = 0;

            WriteMessage(client->pipeHandle.h, client->writeMutex, hb, nullptr, 0);
        }
    }

    Utils::Logger::Debug("[ServiceComm] Heartbeat thread exiting");
}

// ============================================================================
// HELPERS
// ============================================================================

void ServiceCommunicationImpl::NotifyError(const std::string& msg, int code) {
    Utils::Logger::Error("[ServiceComm] {}", msg);
    ServiceErrorCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_errorCb;
    }
    if (cb) {
        try { cb(msg, code); }
        catch (...) {}
    }
}

void ServiceCommunicationImpl::NotifyConnection(const ClientSession& session, bool connected) {
    ConnectionCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_connectionCb;
    }
    if (cb) {
        try { cb(session, connected); }
        catch (...) {}
    }
}

ConnectedClient* ServiceCommunicationImpl::FindClient(const std::string& sessionId) {
    // Caller must hold m_clientsMutex
    for (auto& c : m_clients) {
        if (c && c->sessionId == sessionId)
            return c.get();
    }
    return nullptr;
}

// ============================================================================
// SINGLETON
// ============================================================================

std::atomic<bool> ServiceCommunication::s_instanceCreated{false};

ServiceCommunication& ServiceCommunication::Instance() noexcept {
    static ServiceCommunication instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool ServiceCommunication::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

ServiceCommunication::ServiceCommunication()
    : m_impl(std::make_unique<ServiceCommunicationImpl>()) {}

ServiceCommunication::~ServiceCommunication() = default;

// ============================================================================
// FORWARDING — LIFECYCLE
// ============================================================================

bool ServiceCommunication::Initialize(const ServiceCommConfiguration& config) {
    return m_impl->Initialize(config);
}

bool ServiceCommunication::Start(bool isService) {
    return m_impl->Start(isService);
}

void ServiceCommunication::Stop() { m_impl->Stop(); }
void ServiceCommunication::Shutdown() { m_impl->Shutdown(); }
bool ServiceCommunication::IsInitialized() const noexcept { return m_impl->IsInitialized(); }
bool ServiceCommunication::IsRunning() const noexcept { return m_impl->IsRunning(); }
ServiceCommStatus ServiceCommunication::GetStatus() const noexcept { return m_impl->GetStatus(); }

bool ServiceCommunication::UpdateConfiguration(const ServiceCommConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}
ServiceCommConfiguration ServiceCommunication::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

// ============================================================================
// FORWARDING — CONNECTION
// ============================================================================

bool ServiceCommunication::Connect(const std::wstring& pipeName, uint32_t timeoutMs) {
    return m_impl->Connect(pipeName, timeoutMs);
}
void ServiceCommunication::Disconnect() { m_impl->Disconnect(); }
bool ServiceCommunication::IsConnected() const noexcept { return m_impl->IsConnected(); }
ConnectionState ServiceCommunication::GetConnectionState() const noexcept { return m_impl->GetConnectionState(); }

// ============================================================================
// FORWARDING — MESSAGING
// ============================================================================

void ServiceCommunication::SendCommand(const std::string& cmd) { m_impl->SendCommand(cmd); }
bool ServiceCommunication::SendMessage(const ServiceMessage& msg) { return m_impl->SendMessage(msg); }
bool ServiceCommunication::SendMessage(const ServiceMessage& msg, const std::string& sessionId) {
    return m_impl->SendMessageToSession(msg, sessionId);
}
std::optional<ServiceMessage> ServiceCommunication::SendRequest(const ServiceMessage& req, uint32_t timeoutMs) {
    return m_impl->SendRequest(req, timeoutMs);
}
void ServiceCommunication::Broadcast(const ServiceMessage& msg) { m_impl->Broadcast(msg); }

// ============================================================================
// FORWARDING — COMMANDS
// ============================================================================

bool ServiceCommunication::RequestScan(MessageType t, const std::vector<std::wstring>& targets, uint32_t opts) {
    return m_impl->RequestScan(t, targets, opts);
}
bool ServiceCommunication::RequestStopScan() { return m_impl->RequestStopScan(); }
std::optional<std::string> ServiceCommunication::RequestStatus() { return m_impl->RequestStatus(); }
std::optional<std::string> ServiceCommunication::RequestConfiguration() { return m_impl->RequestConfiguration(); }
bool ServiceCommunication::SendConfigurationUpdate(const std::string& j) { return m_impl->SendConfigurationUpdate(j); }

// ============================================================================
// FORWARDING — EVENTS
// ============================================================================

void ServiceCommunication::SendThreatEvent(uint64_t id, const std::string& name,
                                            const std::wstring& path, uint8_t sev, uint8_t action) {
    m_impl->SendThreatEvent(id, name, path, sev, action);
}

void ServiceCommunication::SendProgressEvent(uint64_t taskId, uint16_t progress,
                                              uint64_t processed, uint64_t total,
                                              const std::wstring& item) {
    m_impl->SendProgressEvent(taskId, progress, processed, total, item);
}

void ServiceCommunication::SendSystemAlert(const std::string& type, const std::string& msg,
                                            uint8_t sev) {
    m_impl->SendSystemAlert(type, msg, sev);
}

// ============================================================================
// FORWARDING — SESSIONS
// ============================================================================

std::vector<ClientSession> ServiceCommunication::GetConnectedClients() const { return m_impl->GetConnectedClients(); }
size_t ServiceCommunication::GetClientCount() const noexcept { return m_impl->GetClientCount(); }
bool ServiceCommunication::DisconnectClient(const std::string& id) { return m_impl->DisconnectClient(id); }
void ServiceCommunication::DisconnectAllClients() { m_impl->DisconnectAllClients(); }

// ============================================================================
// FORWARDING — CALLBACKS
// ============================================================================

void ServiceCommunication::SetMessageCallback(std::function<void(const std::string&)> cb) { m_impl->SetMessageCallback(std::move(cb)); }
void ServiceCommunication::RegisterMessageCallback(ServiceMessageCallback cb) { m_impl->RegisterMessageCallback(std::move(cb)); }
void ServiceCommunication::RegisterConnectionCallback(ConnectionCallback cb) { m_impl->RegisterConnectionCallback(std::move(cb)); }
void ServiceCommunication::RegisterCommandCallback(CommandCallback cb) { m_impl->RegisterCommandCallback(std::move(cb)); }
void ServiceCommunication::RegisterErrorCallback(ServiceErrorCallback cb) { m_impl->RegisterErrorCallback(std::move(cb)); }
void ServiceCommunication::UnregisterCallbacks() { m_impl->UnregisterCallbacks(); }

// ============================================================================
// FORWARDING — STATISTICS
// ============================================================================

ServiceCommStatisticsSnapshot ServiceCommunication::GetStatistics() const { return m_impl->GetStatistics(); }
void ServiceCommunication::ResetStatistics() { m_impl->ResetStatistics(); }
bool ServiceCommunication::SelfTest() { return m_impl->SelfTest(); }

std::string ServiceCommunication::GetVersionString() noexcept {
    char buf[32]{};
    std::snprintf(buf, sizeof(buf), "%u.%u.%u",
                  ServiceCommConstants::VERSION_MAJOR,
                  ServiceCommConstants::VERSION_MINOR,
                  ServiceCommConstants::VERSION_PATCH);
    return buf;
}

// ============================================================================
// STRUCT METHODS
// ============================================================================

std::string ClientSession::ToJson() const {
    std::string j = "{";
    j += "\"sessionId\":\"" + JsonEscape(sessionId) + "\",";
    j += "\"clientType\":\"" + std::string(GetClientTypeName(clientType)) + "\",";
    j += "\"processId\":" + std::to_string(processId) + ",";
    j += "\"state\":\"" + std::string(GetConnectionStateName(state)) + "\",";
    j += "\"messagesSent\":" + std::to_string(messagesSent) + ",";
    j += "\"messagesReceived\":" + std::to_string(messagesReceived) + ",";
    j += "\"authenticated\":" + std::string(isAuthenticated ? "true" : "false");
    j += "}";
    return j;
}

std::string ServiceMessage::GetPayloadString() const {
    if (payload.empty()) return {};
    return std::string(reinterpret_cast<const char*>(payload.data()), payload.size());
}

void ServiceMessage::SetPayloadString(const std::string& str) {
    payload.assign(str.begin(), str.end());
}

bool ServiceCommConfiguration::IsValid() const noexcept {
    return !pipeName.empty() && maxClients > 0 && maxClients <= 256 &&
           maxMessagesPerSecond > 0;
}

// ============================================================================
// STATISTICS METHODS
// ============================================================================

void ServiceCommStatistics::Reset() noexcept {
    messagesReceived.store(0, std::memory_order_relaxed);
    messagesSent.store(0, std::memory_order_relaxed);
    bytesReceived.store(0, std::memory_order_relaxed);
    bytesSent.store(0, std::memory_order_relaxed);
    connectionsTotal.store(0, std::memory_order_relaxed);
    connectionsFailed.store(0, std::memory_order_relaxed);
    authFailures.store(0, std::memory_order_relaxed);
    errors.store(0, std::memory_order_relaxed);
    for (auto& a : byMessageType) a.store(0, std::memory_order_relaxed);
    startTime = Clock::now();
}

ServiceCommStatisticsSnapshot ServiceCommStatistics::TakeSnapshot() const noexcept {
    ServiceCommStatisticsSnapshot snap;
    snap.messagesReceived = messagesReceived.load(std::memory_order_relaxed);
    snap.messagesSent = messagesSent.load(std::memory_order_relaxed);
    snap.bytesReceived = bytesReceived.load(std::memory_order_relaxed);
    snap.bytesSent = bytesSent.load(std::memory_order_relaxed);
    snap.connectionsTotal = connectionsTotal.load(std::memory_order_relaxed);
    snap.connectionsFailed = connectionsFailed.load(std::memory_order_relaxed);
    snap.authFailures = authFailures.load(std::memory_order_relaxed);
    snap.errors = errors.load(std::memory_order_relaxed);
    for (size_t i = 0; i < byMessageType.size(); ++i)
        snap.byMessageType[i] = byMessageType[i].load(std::memory_order_relaxed);
    return snap;
}

std::string ServiceCommStatisticsSnapshot::ToJson() const {
    std::string j = "{";
    j += "\"messagesReceived\":" + std::to_string(messagesReceived) + ",";
    j += "\"messagesSent\":" + std::to_string(messagesSent) + ",";
    j += "\"bytesReceived\":" + std::to_string(bytesReceived) + ",";
    j += "\"bytesSent\":" + std::to_string(bytesSent) + ",";
    j += "\"connectionsTotal\":" + std::to_string(connectionsTotal) + ",";
    j += "\"connectionsFailed\":" + std::to_string(connectionsFailed) + ",";
    j += "\"authFailures\":" + std::to_string(authFailures) + ",";
    j += "\"errors\":" + std::to_string(errors);
    j += "}";
    return j;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetMessageTypeName(MessageType type) noexcept {
    switch (type) {
        case MessageType::Handshake:       return "Handshake";
        case MessageType::HandshakeAck:    return "HandshakeAck";
        case MessageType::Heartbeat:       return "Heartbeat";
        case MessageType::HeartbeatAck:    return "HeartbeatAck";
        case MessageType::Disconnect:      return "Disconnect";
        case MessageType::Error:           return "Error";
        case MessageType::CmdStartScan:    return "CmdStartScan";
        case MessageType::CmdStopScan:     return "CmdStopScan";
        case MessageType::CmdPauseScan:    return "CmdPauseScan";
        case MessageType::CmdResumeScan:   return "CmdResumeScan";
        case MessageType::CmdQuickScan:    return "CmdQuickScan";
        case MessageType::CmdFullScan:     return "CmdFullScan";
        case MessageType::CmdCustomScan:   return "CmdCustomScan";
        case MessageType::CmdCancelScan:   return "CmdCancelScan";
        case MessageType::CmdCheckUpdate:  return "CmdCheckUpdate";
        case MessageType::CmdStartUpdate:  return "CmdStartUpdate";
        case MessageType::CmdCancelUpdate: return "CmdCancelUpdate";
        case MessageType::CmdQuarantine:   return "CmdQuarantine";
        case MessageType::CmdRestore:      return "CmdRestore";
        case MessageType::CmdDelete:       return "CmdDelete";
        case MessageType::CmdGetQuarantine:return "CmdGetQuarantine";
        case MessageType::CmdGetConfig:    return "CmdGetConfig";
        case MessageType::CmdSetConfig:    return "CmdSetConfig";
        case MessageType::CmdResetConfig:  return "CmdResetConfig";
        case MessageType::QueryStatus:     return "QueryStatus";
        case MessageType::QueryStats:      return "QueryStats";
        case MessageType::QueryLicense:    return "QueryLicense";
        case MessageType::QueryModules:    return "QueryModules";
        case MessageType::EventThreat:     return "EventThreat";
        case MessageType::EventScanProgress: return "EventScanProgress";
        case MessageType::EventScanComplete: return "EventScanComplete";
        case MessageType::EventUpdateAvail:  return "EventUpdateAvail";
        case MessageType::EventUpdateProgress: return "EventUpdateProgress";
        case MessageType::EventUpdateComplete: return "EventUpdateComplete";
        case MessageType::EventSystemAlert:  return "EventSystemAlert";
        case MessageType::EventModuleStatus: return "EventModuleStatus";
        case MessageType::EventQuarantine:   return "EventQuarantine";
        case MessageType::Response:        return "Response";
        case MessageType::ResponseOk:      return "ResponseOk";
        case MessageType::ResponseError:   return "ResponseError";
        default:                           return "Unknown";
    }
}

std::string_view GetConnectionStateName(ConnectionState state) noexcept {
    switch (state) {
        case ConnectionState::Disconnected:   return "Disconnected";
        case ConnectionState::Connecting:     return "Connecting";
        case ConnectionState::Authenticating: return "Authenticating";
        case ConnectionState::Connected:      return "Connected";
        case ConnectionState::Error:          return "Error";
        default:                              return "Unknown";
    }
}

std::string_view GetClientTypeName(ClientType type) noexcept {
    switch (type) {
        case ClientType::Unknown:    return "Unknown";
        case ClientType::GUI:        return "GUI";
        case ClientType::CLI:        return "CLI";
        case ClientType::Tray:       return "Tray";
        case ClientType::Management: return "Management";
        case ClientType::API:        return "API";
        default:                     return "Unknown";
    }
}

std::string_view GetAuthResultName(AuthResult result) noexcept {
    switch (result) {
        case AuthResult::Success:         return "Success";
        case AuthResult::InvalidToken:    return "InvalidToken";
        case AuthResult::Expired:         return "Expired";
        case AuthResult::PermissionDenied:return "PermissionDenied";
        case AuthResult::TooManyClients:  return "TooManyClients";
        case AuthResult::InternalError:   return "InternalError";
        default:                          return "Unknown";
    }
}

bool CreateSecurePipeSecurityDescriptor(SECURITY_ATTRIBUTES& sa) {
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;

    // SYSTEM=Full, Administrators=Full, Interactive Users=Read+Write
    const wchar_t* sddl = L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";
    return ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, SDDL_REVISION_1, &sa.lpSecurityDescriptor, nullptr) != FALSE;
}

uint32_t CalculateMessageChecksum(const MessageHeader& header,
                                   const void* payload, size_t payloadSize) {
    (void)header;
    if (!payload || payloadSize == 0) return 0;
    return ComputeCrc32(payload, payloadSize);
}

bool VerifyMessageChecksum(const MessageHeader& header,
                            const void* payload, size_t payloadSize) {
    if (header.payloadLength == 0 && header.checksum == 0)
        return true;
    return CalculateMessageChecksum(header, payload, payloadSize) == header.checksum;
}

}  // namespace Communication
}  // namespace ShadowStrike

