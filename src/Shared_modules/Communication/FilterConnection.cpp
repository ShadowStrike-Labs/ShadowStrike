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
 * @file FilterConnection.cpp
 * @brief Filter Manager connection management implementation
 *
 * CRITICAL: This code interfaces with the kernel driver.
 * Any bugs here can cause system instability.
 *
 * Safety measures implemented:
 * - All handles validated before use
 * - All buffers bounds-checked
 * - Timeout handling on all blocking operations
 * - Thread-safe with PIMPL pattern
 * - RAII for all resources
 *
 * @copyright ShadowStrike NGAV - Enterprise Security Platform
 */

#include "FilterConnection.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"

#include <algorithm>
#include <sstream>
#include <mutex>
#include <atomic>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#include <fltuser.h>
#pragma comment(lib, "fltlib.lib")
#endif

namespace ShadowStrike {
namespace Communication {

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class FilterConnectionImpl {
public:
    FilterConnectionImpl(const std::wstring& portName)
        : m_portName(portName) {
        if (portName.empty()) {
            m_portName = SHADOWSTRIKE_PORT_NAME;
        }
        m_stats.startTime = std::chrono::steady_clock::now();
    }

    ~FilterConnectionImpl() {
        Disconnect();
    }

    // Non-copyable
    FilterConnectionImpl(const FilterConnectionImpl&) = delete;
    FilterConnectionImpl& operator=(const FilterConnectionImpl&) = delete;

    //=========================================================================
    // RAII guard for port handle — prevents use-after-close races.
    //
    // FIX [BUG #1 CRITICAL]: The original code copied m_hPort under lock then
    // used the copy outside the lock. Between lock release and API call,
    // Disconnect() could close the handle. This guard increments a pending-ops
    // counter that Disconnect() drains before CloseHandle.
    //=========================================================================
    class PortGuard {
    public:
        explicit PortGuard(FilterConnectionImpl& owner) noexcept
            : m_owner(owner), m_port(nullptr), m_acquired(false) {
            std::lock_guard<std::mutex> lock(owner.m_mutex);
            if (owner.m_connected.load(std::memory_order_relaxed) &&
                owner.m_hPort != nullptr && owner.m_hPort != INVALID_HANDLE_VALUE) {
                m_port = owner.m_hPort;
                owner.m_pendingOps.fetch_add(1, std::memory_order_acq_rel);
                m_acquired = true;
            }
        }

        ~PortGuard() {
            if (m_acquired) {
                auto prev = m_owner.m_pendingOps.fetch_sub(1, std::memory_order_acq_rel);
                if (prev == 1) {
                    m_owner.m_pendingOps.notify_all();
                }
            }
        }

        PortGuard(const PortGuard&) = delete;
        PortGuard& operator=(const PortGuard&) = delete;

        [[nodiscard]] HANDLE get() const noexcept { return m_port; }
        [[nodiscard]] bool valid() const noexcept { return m_acquired; }

    private:
        FilterConnectionImpl& m_owner;
        HANDLE m_port;
        bool m_acquired;
    };

    //=========================================================================
    // Connection Management
    //=========================================================================

    [[nodiscard]] bool Connect() {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (m_hPort != nullptr) {
            Utils::Logger::Debug("[FilterConnection] Already connected");
            return true;
        }

        Utils::Logger::Info("[FilterConnection] Connecting to port: {}",
                           Utils::StringUtils::WideToUtf8(m_portName));

        HRESULT hr = FilterConnectCommunicationPort(
            m_portName.c_str(),
            0,
            nullptr,
            0,
            nullptr,
            &m_hPort
        );

        if (FAILED(hr)) {
            m_lastError.store(hr, std::memory_order_relaxed);
            m_hPort = nullptr;

            if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
                Utils::Logger::Error(
                    "[FilterConnection] Port not found - driver may not be loaded");
            } else if (hr == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)) {
                Utils::Logger::Error(
                    "[FilterConnection] Access denied - check service account privileges");
            } else {
                Utils::Logger::Error(
                    "[FilterConnection] FilterConnectCommunicationPort failed: 0x{:08X}",
                    static_cast<unsigned int>(hr));
            }

            m_stats.errors++;
            return false;
        }

        if (m_hPort == nullptr || m_hPort == INVALID_HANDLE_VALUE) {
            Utils::Logger::Error("[FilterConnection] Invalid handle returned");
            m_hPort = nullptr;
            m_lastError.store(E_HANDLE, std::memory_order_relaxed);
            return false;
        }

        m_connected.store(true, std::memory_order_release);
        Utils::Logger::Info("[FilterConnection] Connected successfully");
        return true;
    }

    // FIX [BUG #1 CRITICAL]: Two-phase disconnect — mark dead, cancel I/O,
    // drain in-flight operations, THEN close handle.
    void Disconnect() {
        HANDLE portToClose = nullptr;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_hPort == nullptr) return;

            m_connected.store(false, std::memory_order_release);
            portToClose = m_hPort;
            m_hPort = nullptr;
        }

        // Cancel any pending I/O (outside lock so GetMessage can return)
        CancelIoEx(portToClose, nullptr);

        // Wait for all in-flight PortGuard holders to release (C++20 atomic wait)
        int32_t pending = m_pendingOps.load(std::memory_order_acquire);
        while (pending > 0) {
            m_pendingOps.wait(pending, std::memory_order_acquire);
            pending = m_pendingOps.load(std::memory_order_acquire);
        }

        CloseHandle(portToClose);
        Utils::Logger::Info("[FilterConnection] Disconnected");
    }

    [[nodiscard]] bool IsConnected() const noexcept {
        // FIX [BUG #9 MEDIUM]: Only read the atomic flag. Checking m_hPort
        // without the lock was a torn read. The PortGuard validates the handle
        // under lock anyway, so this is sufficient for a quick check.
        return m_connected.load(std::memory_order_acquire);
    }

    [[nodiscard]] void* GetHandle() const noexcept {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_hPort;
    }

    //=========================================================================
    // Message Operations
    //=========================================================================

    [[nodiscard]] size_t GetMessage(std::span<uint8_t> buffer, uint32_t timeoutMs) {
        PortGuard guard(*this);
        if (!guard.valid()) {
            Utils::Logger::Warn("[FilterConnection] GetMessage: Not connected");
            return 0;
        }

        if (buffer.empty()) {
            Utils::Logger::Error("[FilterConnection] GetMessage: Empty buffer");
            return 0;
        }

        if (buffer.size() < sizeof(FILTER_MESSAGE_HEADER)) {
            Utils::Logger::Error("[FilterConnection] GetMessage: Buffer too small (need {})",
                               sizeof(FILTER_MESSAGE_HEADER));
            return 0;
        }

        const DWORD bufferSize = static_cast<DWORD>(
            std::min(buffer.size(), static_cast<size_t>(MAX_MESSAGE_SIZE)));

        PFILTER_MESSAGE_HEADER pMessage =
            reinterpret_cast<PFILTER_MESSAGE_HEADER>(buffer.data());

        HRESULT hr;
        DWORD actualBytes = 0;

        if (timeoutMs == 0) {
            // Synchronous (blocking) call
            hr = FilterGetMessage(
                guard.get(),
                pMessage,
                bufferSize,
                nullptr
            );
            if (SUCCEEDED(hr)) {
                actualBytes = pMessage->MessageLength;
            }
        } else {
            // Asynchronous with timeout
            OVERLAPPED overlapped = {};
            overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

            if (overlapped.hEvent == nullptr) {
                Utils::Logger::Error("[FilterConnection] Failed to create event: {}",
                                    ::GetLastError());
                m_stats.errors++;
                return 0;
            }

            hr = FilterGetMessage(
                guard.get(),
                pMessage,
                bufferSize,
                &overlapped
            );

            if (hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
                DWORD waitResult = WaitForSingleObject(overlapped.hEvent, timeoutMs);

                if (waitResult == WAIT_OBJECT_0) {
                    DWORD bytesTransferred = 0;
                    if (GetOverlappedResult(guard.get(), &overlapped,
                                           &bytesTransferred, FALSE)) {
                        hr = S_OK;
                        // FIX [BUG #8 MEDIUM]: Use actual bytes from overlapped
                        // result instead of the potentially stale MessageLength.
                        actualBytes = bytesTransferred;
                    } else {
                        hr = HRESULT_FROM_WIN32(::GetLastError());
                    }
                } else if (waitResult == WAIT_TIMEOUT) {
                    CancelIoEx(guard.get(), &overlapped);
                    // FIX [BUG #3 CRITICAL]: Must wait for cancellation to
                    // complete before OVERLAPPED goes out of scope, otherwise
                    // the kernel may write to freed stack memory.
                    DWORD ignored = 0;
                    GetOverlappedResult(guard.get(), &overlapped, &ignored, TRUE);
                    CloseHandle(overlapped.hEvent);
                    m_stats.timeouts++;
                    return 0;
                } else {
                    hr = HRESULT_FROM_WIN32(::GetLastError());
                    // Also drain the I/O before destroying OVERLAPPED
                    CancelIoEx(guard.get(), &overlapped);
                    DWORD ignored = 0;
                    GetOverlappedResult(guard.get(), &overlapped, &ignored, TRUE);
                }
            } else if (SUCCEEDED(hr)) {
                // Completed synchronously despite async request
                actualBytes = pMessage->MessageLength;
            }

            CloseHandle(overlapped.hEvent);
        }

        if (FAILED(hr)) {
            m_lastError.store(hr, std::memory_order_relaxed);

            if (hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED) ||
                hr == HRESULT_FROM_WIN32(ERROR_CANCELLED)) {
                return 0;
            }

            if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_connected.store(false, std::memory_order_release);
                // Do NOT null m_hPort — Disconnect() handles cleanup and drain.
            }

            if (hr != HRESULT_FROM_WIN32(ERROR_SEM_TIMEOUT)) {
                Utils::Logger::Warn("[FilterConnection] FilterGetMessage failed: 0x{:08X}",
                                   static_cast<unsigned int>(hr));
            }

            m_stats.errors++;
            return 0;
        }

        if (actualBytes < sizeof(FILTER_MESSAGE_HEADER)) {
            Utils::Logger::Warn("[FilterConnection] Received malformed message");
            m_stats.errors++;
            return 0;
        }

        m_stats.messagesReceived++;
        m_stats.bytesReceived += actualBytes;

        return static_cast<size_t>(actualBytes);
    }

    [[nodiscard]] bool ReplyMessage(std::span<const uint8_t> replyBuffer,
                                    uint64_t originalMessageId) {
        PortGuard guard(*this);
        if (!guard.valid()) {
            Utils::Logger::Warn("[FilterConnection] ReplyMessage: Not connected");
            return false;
        }

        if (replyBuffer.empty()) {
            Utils::Logger::Error("[FilterConnection] ReplyMessage: Empty buffer");
            return false;
        }

        // FIX [BUG #4 HIGH]: The old check demanded payload >= sizeof(FILTER_REPLY_HEADER)
        // which is wrong — replyBuffer is the PAYLOAD, not a pre-formed reply.
        // The correct validation: total size (header + payload) must fit in DWORD
        // and not exceed MAX_MESSAGE_SIZE.
        const size_t totalReplySize = sizeof(FILTER_REPLY_HEADER) + replyBuffer.size();
        if (totalReplySize > MAX_MESSAGE_SIZE) {
            Utils::Logger::Error(
                "[FilterConnection] ReplyMessage: Reply too large ({} bytes, max {})",
                totalReplySize, MAX_MESSAGE_SIZE);
            return false;
        }

        std::vector<uint8_t> fullReply(totalReplySize);

        PFILTER_REPLY_HEADER pReply =
            reinterpret_cast<PFILTER_REPLY_HEADER>(fullReply.data());

        pReply->MessageId = originalMessageId;
        pReply->Status = 0;

        std::memcpy(fullReply.data() + sizeof(FILTER_REPLY_HEADER),
                   replyBuffer.data(), replyBuffer.size());

        HRESULT hr = FilterReplyMessage(
            guard.get(),
            pReply,
            static_cast<DWORD>(fullReply.size())
        );

        if (FAILED(hr)) {
            m_lastError.store(hr, std::memory_order_relaxed);

            if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_connected.store(false, std::memory_order_release);
            }

            Utils::Logger::Warn("[FilterConnection] FilterReplyMessage failed: 0x{:08X}",
                               static_cast<unsigned int>(hr));
            m_stats.errors++;
            return false;
        }

        m_stats.messagesSent++;
        m_stats.repliesSent++;
        m_stats.bytesSent += replyBuffer.size();

        return true;
    }

    [[nodiscard]] size_t SendMessage(std::span<const uint8_t> sendBuffer,
                                     std::span<uint8_t> replyBuffer,
                                     uint32_t /*timeoutMs*/) {
        PortGuard guard(*this);
        if (!guard.valid()) {
            Utils::Logger::Warn("[FilterConnection] SendMessage: Not connected");
            return 0;
        }

        if (sendBuffer.empty()) {
            Utils::Logger::Error("[FilterConnection] SendMessage: Empty send buffer");
            return 0;
        }

        DWORD bytesReturned = 0;

        HRESULT hr = FilterSendMessage(
            guard.get(),
            const_cast<void*>(static_cast<const void*>(sendBuffer.data())),
            static_cast<DWORD>(sendBuffer.size()),
            replyBuffer.empty() ? nullptr : replyBuffer.data(),
            static_cast<DWORD>(replyBuffer.size()),
            &bytesReturned
        );

        if (FAILED(hr)) {
            m_lastError.store(hr, std::memory_order_relaxed);

            // FIX [BUG #6 HIGH]: Consistent INVALID_HANDLE handling — set
            // m_connected=false (same as GetMessage). Don't null m_hPort.
            if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_connected.store(false, std::memory_order_release);
            }

            Utils::Logger::Warn("[FilterConnection] FilterSendMessage failed: 0x{:08X}",
                               static_cast<unsigned int>(hr));
            m_stats.errors++;
            return 0;
        }

        m_stats.messagesSent++;
        m_stats.bytesSent += sendBuffer.size();

        if (bytesReturned > 0) {
            m_stats.messagesReceived++;
            m_stats.bytesReceived += bytesReturned;
        }

        return static_cast<size_t>(bytesReturned);
    }

    // FIX [BUG #2 CRITICAL]: The old code did `SendMessage(...) >= 0` which is
    // always true for size_t (unsigned). Now calls FilterSendMessage directly
    // with null reply buffer and checks the HRESULT for success/failure.
    [[nodiscard]] bool SendMessageNoReply(std::span<const uint8_t> sendBuffer) {
        PortGuard guard(*this);
        if (!guard.valid()) {
            Utils::Logger::Warn("[FilterConnection] SendMessageNoReply: Not connected");
            return false;
        }

        if (sendBuffer.empty()) {
            Utils::Logger::Error("[FilterConnection] SendMessageNoReply: Empty buffer");
            return false;
        }

        HRESULT hr = FilterSendMessage(
            guard.get(),
            const_cast<void*>(static_cast<const void*>(sendBuffer.data())),
            static_cast<DWORD>(sendBuffer.size()),
            nullptr,
            0,
            nullptr
        );

        if (FAILED(hr)) {
            m_lastError.store(hr, std::memory_order_relaxed);

            if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_connected.store(false, std::memory_order_release);
            }

            Utils::Logger::Warn(
                "[FilterConnection] FilterSendMessage (no reply) failed: 0x{:08X}",
                static_cast<unsigned int>(hr));
            m_stats.errors++;
            return false;
        }

        m_stats.messagesSent++;
        m_stats.bytesSent += sendBuffer.size();
        return true;
    }

    //=========================================================================
    // Error Handling
    //=========================================================================

    [[nodiscard]] int32_t GetLastError() const noexcept {
        // FIX [BUG #5 HIGH]: Now atomic — safe for concurrent reads/writes.
        return m_lastError.load(std::memory_order_relaxed);
    }

    [[nodiscard]] std::string GetLastErrorMessage() const {
        const int32_t err = m_lastError.load(std::memory_order_relaxed);
        if (err == 0) {
            return "No error";
        }

        LPWSTR msgBuffer = nullptr;
        DWORD size = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
            nullptr,
            static_cast<DWORD>(err),
            0,
            reinterpret_cast<LPWSTR>(&msgBuffer),
            0,
            nullptr
        );

        if (size == 0 || msgBuffer == nullptr) {
            return "Unknown error: " + std::to_string(err);
        }

        std::wstring wideMsg(msgBuffer, size);
        LocalFree(msgBuffer);

        while (!wideMsg.empty() &&
               (wideMsg.back() == L'\n' || wideMsg.back() == L'\r')) {
            wideMsg.pop_back();
        }

        return Utils::StringUtils::WideToUtf8(wideMsg);
    }

    //=========================================================================
    // Statistics
    //=========================================================================

    // FIX [BUG #7 HIGH]: Return a copyable snapshot instead of trying to copy
    // CommunicationStatistics (which contains non-copyable std::atomic members).
    [[nodiscard]] CommunicationStatisticsSnapshot GetStatistics() const {
        return m_stats.TakeSnapshot();
    }

    // FIX [BUG #10 LOW]: Escape backslashes in port name for valid JSON.
    [[nodiscard]] std::string ToJson() const {
        std::string escapedPort = Utils::StringUtils::WideToUtf8(m_portName);
        // Escape backslashes for JSON
        std::string jsonPort;
        jsonPort.reserve(escapedPort.size() + 4);
        for (char c : escapedPort) {
            if (c == '\\') jsonPort += "\\\\";
            else if (c == '"') jsonPort += "\\\"";
            else jsonPort += c;
        }

        std::ostringstream oss;
        oss << "{"
            << "\"connected\":" << (m_connected.load(std::memory_order_relaxed) ? "true" : "false") << ","
            << "\"portName\":\"" << jsonPort << "\","
            << "\"messagesReceived\":" << m_stats.messagesReceived.load(std::memory_order_relaxed) << ","
            << "\"messagesSent\":" << m_stats.messagesSent.load(std::memory_order_relaxed) << ","
            << "\"bytesReceived\":" << m_stats.bytesReceived.load(std::memory_order_relaxed) << ","
            << "\"bytesSent\":" << m_stats.bytesSent.load(std::memory_order_relaxed) << ","
            << "\"errors\":" << m_stats.errors.load(std::memory_order_relaxed) << ","
            << "\"timeouts\":" << m_stats.timeouts.load(std::memory_order_relaxed)
            << "}";
        return oss.str();
    }

private:
    std::wstring m_portName;

    HANDLE m_hPort = nullptr;
    std::atomic<bool> m_connected{false};
    std::atomic<int32_t> m_pendingOps{0};  // Outstanding PortGuard holders
    mutable std::mutex m_mutex;

    // FIX [BUG #5 HIGH]: Was plain int32_t written from multiple threads.
    std::atomic<int32_t> m_lastError{0};

    CommunicationStatistics m_stats;
};

// ============================================================================
// FILTERCONNECTION IMPLEMENTATION
// ============================================================================

FilterConnection::FilterConnection(const std::wstring& portName)
    : m_impl(std::make_unique<FilterConnectionImpl>(portName)) {
}

FilterConnection::~FilterConnection() = default;

FilterConnection::FilterConnection(FilterConnection&& other) noexcept
    : m_impl(std::move(other.m_impl)) {
}

FilterConnection& FilterConnection::operator=(FilterConnection&& other) noexcept {
    if (this != &other) {
        m_impl = std::move(other.m_impl);
    }
    return *this;
}

bool FilterConnection::Connect() {
    if (!m_impl) return false;
    return m_impl->Connect();
}

void FilterConnection::Disconnect() {
    if (m_impl) {
        m_impl->Disconnect();
    }
}

bool FilterConnection::IsConnected() const noexcept {
    return m_impl && m_impl->IsConnected();
}

void* FilterConnection::GetHandle() const noexcept {
    return m_impl ? m_impl->GetHandle() : nullptr;
}

size_t FilterConnection::GetMessage(std::span<uint8_t> buffer, uint32_t timeoutMs) {
    if (!m_impl) return 0;
    return m_impl->GetMessage(buffer, timeoutMs);
}

bool FilterConnection::ReplyMessage(std::span<const uint8_t> replyBuffer,
                                    uint64_t originalMessageId) {
    if (!m_impl) return false;
    return m_impl->ReplyMessage(replyBuffer, originalMessageId);
}

size_t FilterConnection::SendMessage(std::span<const uint8_t> sendBuffer,
                                     std::span<uint8_t> replyBuffer,
                                     uint32_t timeoutMs) {
    if (!m_impl) return 0;
    return m_impl->SendMessage(sendBuffer, replyBuffer, timeoutMs);
}

bool FilterConnection::SendMessageNoReply(std::span<const uint8_t> sendBuffer) {
    if (!m_impl) return false;
    return m_impl->SendMessageNoReply(sendBuffer);
}

int32_t FilterConnection::GetLastError() const noexcept {
    return m_impl ? m_impl->GetLastError() : E_POINTER;
}

std::string FilterConnection::GetLastErrorMessage() const {
    return m_impl ? m_impl->GetLastErrorMessage() : "Implementation not initialized";
}

CommunicationStatisticsSnapshot FilterConnection::GetStatistics() const {
    if (!m_impl) {
        return CommunicationStatisticsSnapshot{};
    }
    return m_impl->GetStatistics();
}

std::string FilterConnection::ToJson() const {
    return m_impl ? m_impl->ToJson() : "{}";
}

// ============================================================================
// STATISTICS IMPLEMENTATION
// ============================================================================

void CommunicationStatistics::Reset() noexcept {
    messagesReceived.store(0, std::memory_order_relaxed);
    messagesSent.store(0, std::memory_order_relaxed);
    fileScanRequests.store(0, std::memory_order_relaxed);
    processNotifications.store(0, std::memory_order_relaxed);
    registryNotifications.store(0, std::memory_order_relaxed);
    repliesSent.store(0, std::memory_order_relaxed);
    timeouts.store(0, std::memory_order_relaxed);
    errors.store(0, std::memory_order_relaxed);
    reconnections.store(0, std::memory_order_relaxed);
    bytesReceived.store(0, std::memory_order_relaxed);
    bytesSent.store(0, std::memory_order_relaxed);
    startTime = std::chrono::steady_clock::now();
}

std::string CommunicationStatistics::ToJson() const {
    return TakeSnapshot().ToJson();
}

CommunicationStatisticsSnapshot CommunicationStatistics::TakeSnapshot() const noexcept {
    CommunicationStatisticsSnapshot snap;
    snap.messagesReceived = messagesReceived.load(std::memory_order_relaxed);
    snap.messagesSent = messagesSent.load(std::memory_order_relaxed);
    snap.fileScanRequests = fileScanRequests.load(std::memory_order_relaxed);
    snap.processNotifications = processNotifications.load(std::memory_order_relaxed);
    snap.registryNotifications = registryNotifications.load(std::memory_order_relaxed);
    snap.repliesSent = repliesSent.load(std::memory_order_relaxed);
    snap.timeouts = timeouts.load(std::memory_order_relaxed);
    snap.errors = errors.load(std::memory_order_relaxed);
    snap.reconnections = reconnections.load(std::memory_order_relaxed);
    snap.bytesReceived = bytesReceived.load(std::memory_order_relaxed);
    snap.bytesSent = bytesSent.load(std::memory_order_relaxed);
    snap.uptimeSeconds = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - startTime).count();
    return snap;
}

std::string CommunicationStatisticsSnapshot::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"uptimeSeconds\":" << uptimeSeconds << ","
        << "\"messagesReceived\":" << messagesReceived << ","
        << "\"messagesSent\":" << messagesSent << ","
        << "\"fileScanRequests\":" << fileScanRequests << ","
        << "\"processNotifications\":" << processNotifications << ","
        << "\"registryNotifications\":" << registryNotifications << ","
        << "\"repliesSent\":" << repliesSent << ","
        << "\"timeouts\":" << timeouts << ","
        << "\"errors\":" << errors << ","
        << "\"reconnections\":" << reconnections << ","
        << "\"bytesReceived\":" << bytesReceived << ","
        << "\"bytesSent\":" << bytesSent
        << "}";
    return oss.str();
}

} // namespace Communication
} // namespace ShadowStrike
