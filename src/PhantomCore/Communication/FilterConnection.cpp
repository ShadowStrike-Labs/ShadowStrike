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
#include "../SelfProtection/CryptoManager.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <sstream>
#include <mutex>
#include <atomic>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#include <fltuser.h>
#pragma comment(lib, "fltlib.lib")
#endif

// Include AFTER fltuser.h so __FLT_USER_STRUCTURES_H__ is defined,
// preventing MessageProtocol.h from redefining FILTER_MESSAGE_HEADER.
#include "../../../PhantomSensor/Shared/MessageProtocol.h"
#include "../../../PhantomSensor/Shared/MessageTypes.h"

namespace ShadowStrike {
namespace Communication {

namespace {

#pragma pack(push, 1)
struct KernelEncHeader {
    uint32_t magic;
    uint16_t version;
    uint16_t algorithm;
    uint32_t flags;
    uint32_t plaintextSize;
    uint32_t ciphertextSize;
    uint8_t nonce[12];
    uint8_t tag[16];
    uint64_t keyId;
    uint32_t aadSize;
    int64_t timestamp;
    uint32_t headerCrc32;
};
#pragma pack(pop)

static_assert(sizeof(KernelEncHeader) == 72, "KernelEncHeader size mismatch");

constexpr uint32_t kKernelEncMagic = 'RCNE';
constexpr uint16_t kKernelEncVersion = 2;
constexpr uint16_t kKernelEncAlgorithmAes256Gcm = 2;
constexpr uint32_t kKernelEncFlagUseAad = 0x00000002;
constexpr uint32_t kKernelEncCrc32Polynomial = 0xEDB88320UL;

[[nodiscard]] std::string WideToUtf8String(const std::wstring& value) noexcept {
    if (value.empty()) {
        return {};
    }

    if (value.size() > static_cast<size_t>(INT_MAX)) {
        return {};
    }

    const int requiredBytes = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr
    );
    if (requiredBytes <= 0) {
        return {};
    }

    std::string utf8(static_cast<size_t>(requiredBytes), '\0');
    const int converted = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        utf8.data(),
        requiredBytes,
        nullptr,
        nullptr
    );
    if (converted != requiredBytes) {
        return {};
    }

    return utf8;
}

[[nodiscard]] DWORD GetDeliveredMessageSize(
    const uint8_t* buffer,
    size_t bufferSize
) noexcept {
    constexpr size_t kTransportHeaderSize = sizeof(FILTER_MESSAGE_HEADER) +
                                            sizeof(SHADOWSTRIKE_MESSAGE_HEADER);

    if (buffer == nullptr || bufferSize < kTransportHeaderSize) {
        return 0;
    }

    const auto* ssHeader = reinterpret_cast<const SHADOWSTRIKE_MESSAGE_HEADER*>(
        buffer + sizeof(FILTER_MESSAGE_HEADER)
    );
    if (ssHeader->TotalSize < sizeof(SHADOWSTRIKE_MESSAGE_HEADER)) {
        return 0;
    }

    const size_t totalSize = sizeof(FILTER_MESSAGE_HEADER) + ssHeader->TotalSize;
    if (totalSize > bufferSize || totalSize > static_cast<size_t>(MAXDWORD)) {
        return 0;
    }

    return static_cast<DWORD>(totalSize);
}

[[nodiscard]] uint32_t ComputeKernelEncHeaderCrc32(const void* data, size_t size) noexcept {
    const auto* bytes = static_cast<const uint8_t*>(data);
    uint32_t crc = 0xFFFFFFFFu;

    for (size_t i = 0; i < size; ++i) {
        crc ^= bytes[i];
        for (int bit = 0; bit < 8; ++bit) {
            const uint32_t mask = 0u - (crc & 1u);
            crc = (crc >> 1) ^ (kKernelEncCrc32Polynomial & mask);
        }
    }

    return crc ^ 0xFFFFFFFFu;
}

[[nodiscard]] int64_t GetKernelEncTimestamp() noexcept {
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);

    ULARGE_INTEGER value{};
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;
    return static_cast<int64_t>(value.QuadPart);
}

}  // namespace

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class FilterConnectionImpl {
public:
    FilterConnectionImpl(const std::wstring& portName)
        : m_portName(portName) {
        if (portName.empty()) {
            m_portName = SS_COMM_PORT_NAME;
        }
        m_stats.startTime = std::chrono::steady_clock::now();
        m_sessionKey.fill(0);
    }

    ~FilterConnectionImpl() {
        Disconnect();
        // Unconditionally scrub key material — even if encryption was never
        // established, the array may contain partial key data from a failed
        // key exchange attempt.
        ShadowStrike::Security::CryptoManager::Instance().SecureZero(
            m_sessionKey.data(), m_sessionKey.size());
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

    [[nodiscard]] bool Connect(bool registerAsPrimaryScanner) {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (m_hPort != nullptr) {
            Utils::Logger::Debug("[FilterConnection] Already connected");
            return true;
        }

        const std::string connectMessage =
            std::string("[FilterConnection] Connecting to port: ") +
            WideToUtf8String(m_portName);
        Utils::Logger::Info(connectMessage.c_str());

        // The kernel minifilter (ShadowStrikeConnectNotify) inspects the
        // connection context: ConnectionType==1 designates this connection as
        // the primary scanner port (the ONLY connection the kernel sends scan
        // requests / notifications to and the one whose session key gates those
        // sends); auxiliary connections pass 0. We additionally carry the
        // SHA-256 of our OWN executable so the kernel can use the identical
        // value as the key-exchange input WITHOUT performing any file I/O in
        // its connect callback (file I/O there re-enters the minifilter and can
        // deadlock the filesystem stack). The connection is independently
        // authenticated kernel-side (exact image path + SYSTEM token).
        SHADOWSTRIKE_CONNECTION_CONTEXT connCtx{};
        connCtx.ConnectionType = registerAsPrimaryScanner ? 1u : 0u;
        {
            using namespace ShadowStrike::Security;
            auto& crypto = CryptoManager::Instance();
            wchar_t exePath[MAX_PATH]{};
            GetModuleFileNameW(nullptr, exePath, MAX_PATH);
            auto hashOpt = crypto.HashFile(std::wstring(exePath), HashAlgorithm::SHA256);
            if (!hashOpt.has_value() || hashOpt->size() < sizeof(connCtx.ClientImageHash)) {
                Utils::Logger::Error("[FilterConnection] Connect: failed to hash own "
                                     "image for key exchange");
                m_lastError.store(E_FAIL, std::memory_order_relaxed);
                m_stats.errors++;
                return false;
            }
            // Same SHA-256 the kernel will use as the KWK input and that
            // ReceiveKeyExchange() recomputes to unwrap the session key.
            std::copy(hashOpt->begin(),
                      hashOpt->begin() + sizeof(connCtx.ClientImageHash),
                      connCtx.ClientImageHash);
        }

        HRESULT hr = FilterConnectCommunicationPort(
            m_portName.c_str(),
            0,
            &connCtx,
            sizeof(connCtx),
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

        // Receive key exchange message from kernel.
        // The kernel sends SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE immediately after
        // accepting the connection. We must receive and process it before any
        // other communication can occur.
        if (!ReceiveKeyExchange()) {
            Utils::Logger::Error("[FilterConnection] Key exchange failed — "
                                 "encryption not established, disconnecting");
            m_connected.store(false, std::memory_order_release);
            CloseHandle(m_hPort);
            m_hPort = nullptr;
            return false;
        }

        Utils::Logger::Info("[FilterConnection] Connected successfully (encrypted)");
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

        // Mark encryption as torn down so new PortGuard holders that call
        // Encrypt/Decrypt will see the flag and skip crypto. Existing holders
        // that already passed the check may still read the key — but they
        // hold PortGuard, so we MUST wait for them before scrubbing.
        m_encryptionEstablished.store(false, std::memory_order_release);

        // Cancel any pending I/O (outside lock so GetMessage can return)
        CancelIoEx(portToClose, nullptr);

        // Wait for all in-flight PortGuard holders to release (C++20 atomic wait).
        // CRITICAL: key material must NOT be scrubbed until all holders have
        // finished — they may still reference m_sessionKey / m_sessionNoncePrefix.
        int32_t pending = m_pendingOps.load(std::memory_order_acquire);
        while (pending > 0) {
            m_pendingOps.wait(pending, std::memory_order_acquire);
            pending = m_pendingOps.load(std::memory_order_acquire);
        }

        // All in-flight operations drained — safe to scrub key material.
        ShadowStrike::Security::CryptoManager::Instance().SecureZero(
            m_sessionKey.data(), m_sessionKey.size());
        ShadowStrike::Security::CryptoManager::Instance().SecureZero(
            m_sessionNoncePrefix.data(), m_sessionNoncePrefix.size());
        m_nonceCounter.store(0, std::memory_order_relaxed);

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
                actualBytes = GetDeliveredMessageSize(buffer.data(), bufferSize);
                if (actualBytes == 0) {
                    hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
                }
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
                actualBytes = GetDeliveredMessageSize(buffer.data(), bufferSize);
                if (actualBytes == 0) {
                    hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
                }
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

            if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_DATA)) {
                // Delivered frame failed the two-header size/framing check (see
                // GetDeliveredMessageSize) -- an unusable/desynced frame. The
                // receive worker handles this with escalating back-off + a
                // single aggregated warning, so logging EVERY occurrence at Warn
                // only floods the log (field: 3392 lines in 3.3s). Keep per-frame
                // at Debug; genuine transport errors (other codes) still warn.
                Utils::Logger::Debug("[FilterConnection] FilterGetMessage: unusable frame (0x{:08X})",
                                     static_cast<unsigned int>(hr));
            } else if (hr != HRESULT_FROM_WIN32(ERROR_SEM_TIMEOUT)) {
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

        // Decrypt if message has SHADOWSTRIKE_MSG_FLAG_ENCRYPTED set
        size_t decryptedBytes = static_cast<size_t>(actualBytes);
        if (!DecryptReceivedMessage(buffer.data(), decryptedBytes)) {
            Utils::Logger::Warn("[FilterConnection] GetMessage: Decryption failed, dropping message");
            m_stats.errors++;
            return 0;
        }

        return decryptedBytes;
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

        // Encrypt reply payload if session key established — NEVER fall back to plaintext
        std::span<const uint8_t> actualReply = replyBuffer;
        std::vector<uint8_t> encryptedReply;
        if (m_encryptionEstablished.load(std::memory_order_acquire) &&
            replyBuffer.size() > sizeof(SHADOWSTRIKE_MESSAGE_HEADER)) {
            if (EncryptSendMessage(replyBuffer, encryptedReply)) {
                actualReply = std::span<const uint8_t>(encryptedReply);
            } else {
                Utils::Logger::Error("[FilterConnection] ReplyMessage: Encryption failed, "
                                     "dropping reply (no plaintext fallback)");
                m_stats.errors++;
                return false;
            }
        }

        // FIX [BUG #4 HIGH]: The old check demanded payload >= sizeof(FILTER_REPLY_HEADER)
        // which is wrong — replyBuffer is the PAYLOAD, not a pre-formed reply.
        // The correct validation: total size (header + payload) must fit in DWORD
        // and not exceed MAX_MESSAGE_SIZE.
        const size_t totalReplySize = sizeof(FILTER_REPLY_HEADER) + actualReply.size();
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
                   actualReply.data(), actualReply.size());

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

            // STATUS_FLT_NO_WAITER_FOR_REPLY (0x801F0020): the kernel already
            // stopped waiting for this message — either it was sent one-way, or a
            // blocking scan's wait timed out. This is a benign race, not a channel
            // error. Do NOT warn per event (that was a primary contributor to the
            // CPU/log storm) and do NOT count it as a hard error. The caller
            // gates replies on ReplyLength, so this path should now be rare.
            constexpr HRESULT kFltNoWaiterForReply = static_cast<HRESULT>(0x801F0020L);
            if (hr == kFltNoWaiterForReply) {
                Utils::Logger::Debug(
                    "[FilterConnection] Reply had no kernel waiter (msgId={})",
                    originalMessageId);
                return false;
            }

            Utils::Logger::Warn("[FilterConnection] FilterReplyMessage failed: 0x{:08X}",
                               static_cast<unsigned int>(hr));
            m_stats.errors++;
            return false;
        }

        m_stats.messagesSent++;
        m_stats.repliesSent++;
        m_stats.bytesSent += actualReply.size();

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

        // Encrypt if session key established — NEVER fall back to plaintext
        std::vector<uint8_t> encryptedBuf;
        std::span<const uint8_t> actualSend = sendBuffer;
        if (m_encryptionEstablished.load(std::memory_order_acquire) &&
            sendBuffer.size() > sizeof(SHADOWSTRIKE_MESSAGE_HEADER)) {
            if (EncryptSendMessage(sendBuffer, encryptedBuf)) {
                actualSend = std::span<const uint8_t>(encryptedBuf);
            } else {
                Utils::Logger::Error("[FilterConnection] SendMessage: Encryption failed, "
                                     "dropping message (no plaintext fallback)");
                m_stats.errors++;
                return 0;
            }
        }

        DWORD bytesReturned = 0;

        HRESULT hr = FilterSendMessage(
            guard.get(),
            const_cast<void*>(static_cast<const void*>(actualSend.data())),
            static_cast<DWORD>(actualSend.size()),
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

        // Encrypt if session key established — NEVER fall back to plaintext
        std::vector<uint8_t> encryptedBuf;
        std::span<const uint8_t> actualSend = sendBuffer;
        if (m_encryptionEstablished.load(std::memory_order_acquire) &&
            sendBuffer.size() > sizeof(SHADOWSTRIKE_MESSAGE_HEADER)) {
            if (EncryptSendMessage(sendBuffer, encryptedBuf)) {
                actualSend = std::span<const uint8_t>(encryptedBuf);
            } else {
                Utils::Logger::Error("[FilterConnection] SendMessageNoReply: Encryption failed, "
                                     "dropping message (no plaintext fallback)");
                m_stats.errors++;
                return false;
            }
        }

        HRESULT hr = FilterSendMessage(
            guard.get(),
            const_cast<void*>(static_cast<const void*>(actualSend.data())),
            static_cast<DWORD>(actualSend.size()),
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

        return WideToUtf8String(wideMsg);
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
        std::string escapedPort = WideToUtf8String(m_portName);
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

    // Per-session encryption state
    std::array<uint8_t, 32> m_sessionKey;
    std::array<uint8_t, 4> m_sessionNoncePrefix{};
    std::atomic<bool> m_encryptionEstablished{false};
    std::atomic<uint64_t> m_nonceCounter{0};

    // Driver attestation enforcement policy.
    // true = hard-fail if driver signature/hash cannot be verified (production).
    // false = warn-only mode for development/testing environments.
    bool m_enforceDriverAttestation{true};

    //=========================================================================
    // Key Exchange
    //=========================================================================

    /**
     * @brief Receive and process the key exchange message from the kernel.
     *
     * After FilterConnectCommunicationPort succeeds, the kernel immediately sends
     * a SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE containing:
     *   - Salt[32]: HKDF salt for deriving KWK
     *   - WrappedSessionKey[32]: Session key encrypted with KWK
     *   - Nonce[12]: GCM nonce for the wrapping operation
     *   - Tag[16]: GCM auth tag
     *   - SessionNoncePrefix[4]: Prefix for message nonces
     *
     * User-mode derives KWK = HKDF(SHA256, ownImageHash, salt, "ShadowStrike-KWK-v1"),
     * then unwraps the session key using AES-256-GCM.
     */
    [[nodiscard]] bool ReceiveKeyExchange() {
        using namespace ShadowStrike::Security;
        auto& crypto = CryptoManager::Instance();

        // Allocate buffer for key exchange message
        constexpr size_t kBufSize = sizeof(FILTER_MESSAGE_HEADER) +
                                     sizeof(SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE);
        std::vector<uint8_t> buf(kBufSize, 0);

        // Receive with 10-second timeout
        OVERLAPPED ov{};
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (ov.hEvent == nullptr) {
            Utils::Logger::Error("[FilterConnection] KEX: CreateEvent failed: {}",
                                 GetLastError());
            return false;
        }

        HRESULT hr = FilterGetMessage(
            m_hPort,
            reinterpret_cast<PFILTER_MESSAGE_HEADER>(buf.data()),
            static_cast<DWORD>(kBufSize),
            &ov);

        if (hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
            DWORD waitResult = WaitForSingleObject(ov.hEvent, 10000);
            if (waitResult != WAIT_OBJECT_0) {
                CancelIoEx(m_hPort, &ov);
                // Drain the cancelled I/O to prevent kernel writing to freed stack OVERLAPPED
                DWORD ignored = 0;
                GetOverlappedResult(m_hPort, &ov, &ignored, TRUE);
                CloseHandle(ov.hEvent);
                Utils::Logger::Error("[FilterConnection] KEX: Timeout waiting for key exchange");
                return false;
            }
        } else if (FAILED(hr)) {
            CloseHandle(ov.hEvent);
            Utils::Logger::Error("[FilterConnection] KEX: FilterGetMessage failed: 0x{:08X}",
                                 static_cast<unsigned int>(hr));
            return false;
        }

        DWORD bytesReceived = 0;
        if (!GetOverlappedResult(m_hPort, &ov, &bytesReceived, FALSE)) {
            CloseHandle(ov.hEvent);
            Utils::Logger::Error("[FilterConnection] KEX: GetOverlappedResult failed: {}",
                                 GetLastError());
            return false;
        }
        CloseHandle(ov.hEvent);

        if (bytesReceived < sizeof(FILTER_MESSAGE_HEADER) + sizeof(SHADOWSTRIKE_MESSAGE_HEADER)) {
            Utils::Logger::Error("[FilterConnection] KEX: Message too small ({} bytes)",
                                 bytesReceived);
            return false;
        }

        // Verify this is a key exchange message
        auto* ssHeader = reinterpret_cast<const SHADOWSTRIKE_MESSAGE_HEADER*>(
            buf.data() + sizeof(FILTER_MESSAGE_HEADER));

        if (ssHeader->MessageType != FilterMessageType_KeyExchange) {
            Utils::Logger::Error("[FilterConnection] KEX: Expected key exchange message, got type={}",
                                 ssHeader->MessageType);
            return false;
        }

        if (bytesReceived < sizeof(FILTER_MESSAGE_HEADER) + sizeof(SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE)) {
            Utils::Logger::Error("[FilterConnection] KEX: Truncated key exchange ({} bytes)",
                                 bytesReceived);
            return false;
        }

        auto* kexMsg = reinterpret_cast<const SHADOWSTRIKE_KEY_EXCHANGE_MESSAGE*>(
            buf.data() + sizeof(FILTER_MESSAGE_HEADER));

        //
        // Derive KWK (Key-Wrapping-Key) from our own executable image hash + salt.
        // This mirrors what the kernel did with the same inputs.
        //
        // Get our own executable hash (same hash the kernel verified during connect)
        //
        std::vector<uint8_t> ownImageHash;
        {
            wchar_t exePath[MAX_PATH]{};
            GetModuleFileNameW(nullptr, exePath, MAX_PATH);
            auto hashOpt = crypto.HashFile(std::wstring(exePath), HashAlgorithm::SHA256);
            if (!hashOpt.has_value() || hashOpt->size() < 32) {
                Utils::Logger::Error("[FilterConnection] KEX: Failed to hash own executable");
                return false;
            }
            ownImageHash = std::move(*hashOpt);
        }

        // Derive KWK = HKDF(SHA256, imageHash, salt, "ShadowStrike-KWK-v1")
        static const std::string kwkInfo = "ShadowStrike-KWK-v1";
        std::span<const uint8_t> saltSpan(kexMsg->Salt, sizeof(kexMsg->Salt));

        auto kwk = crypto.HKDF(
            std::span<const uint8_t>(ownImageHash.data(), ownImageHash.size()),
            saltSpan,
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(kwkInfo.data()), kwkInfo.size()),
            32,
            HashAlgorithm::SHA256);

        if (kwk.size() != 32) {
            Utils::Logger::Error("[FilterConnection] KEX: KWK derivation failed");
            return false;
        }

        // Unwrap session key: decrypt WrappedSessionKey with KWK, using Salt as AAD
        auto decrypted = crypto.Decrypt(
            std::span<const uint8_t>(kexMsg->WrappedSessionKey, sizeof(kexMsg->WrappedSessionKey)),
            std::span<const uint8_t>(kwk.data(), kwk.size()),
            SymmetricAlgorithm::AES_256_GCM,
            std::span<const uint8_t>(kexMsg->Nonce, sizeof(kexMsg->Nonce)),
            std::span<const uint8_t>(kexMsg->Tag, sizeof(kexMsg->Tag)),
            saltSpan);

        // Scrub KWK immediately
        crypto.SecureZero(kwk.data(), kwk.size());

        if (decrypted.plaintext.size() != 32) {
            Utils::Logger::Error("[FilterConnection] KEX: Session key unwrap failed "
                                 "(got {} bytes, expected 32)", decrypted.plaintext.size());
            return false;
        }

        // Store session key, nonce prefix, and mark encryption as established
        std::copy(decrypted.plaintext.begin(), decrypted.plaintext.end(), m_sessionKey.begin());
        crypto.SecureZero(decrypted.plaintext.data(), decrypted.plaintext.size());

        std::copy(kexMsg->SessionNoncePrefix,
                  kexMsg->SessionNoncePrefix + sizeof(kexMsg->SessionNoncePrefix),
                  m_sessionNoncePrefix.begin());

        m_nonceCounter.store(0, std::memory_order_relaxed);
        m_encryptionEstablished.store(true, std::memory_order_release);

        // ── APT DEFENSE: Validate kernel driver attestation ──────────
        // Before trusting this encrypted channel, verify the driver binary
        // is Authenticode-signed and matches the expected hash. This blocks
        // nation-state actors from injecting a rogue driver that speaks our
        // protocol but exfiltrates data.
        {
            wchar_t systemDir[MAX_PATH]{};
            GetSystemDirectoryW(systemDir, MAX_PATH);
            std::wstring driverPath = std::wstring(systemDir) + L"\\drivers\\PhantomSensor.sys";

            // Hash the driver binary independently to get its actual hash.
            // This is the hash we expect to verify against the Authenticode signature.
            auto driverHashOpt = crypto.HashFile(driverPath, HashAlgorithm::SHA256);
            if (!driverHashOpt.has_value() || driverHashOpt->size() < 32) {
                Utils::Logger::Error("[FilterConnection] KEX: Failed to hash driver binary at {}",
                    WideToUtf8String(driverPath));
                if (m_enforceDriverAttestation) {
                    // Hard-fail: cannot trust a channel when we cannot even hash the driver
                    crypto.SecureZero(m_sessionKey.data(), m_sessionKey.size());
                    m_encryptionEstablished.store(false, std::memory_order_release);
                    return false;
                }
                Utils::Logger::Warn("[FilterConnection] KEX: Driver hash failed but "
                                    "enforcement is DISABLED (dev mode)");
            }
            else {
                // Verify driver Authenticode signature and attestation
                if (!crypto.ValidateKernelDriverAttestation(driverPath, *driverHashOpt)) {
                    Utils::Logger::Error("[FilterConnection] KEX: Driver attestation FAILED — "
                                         "Authenticode signature invalid or hash mismatch for {}",
                                         WideToUtf8String(driverPath));

                    if (m_enforceDriverAttestation) {
                        // HARD-FAIL: The driver binary is not trusted.
                        // Tear down encryption and refuse to communicate.
                        crypto.SecureZero(m_sessionKey.data(), m_sessionKey.size());
                        m_encryptionEstablished.store(false, std::memory_order_release);
                        Utils::Logger::Error("[FilterConnection] KEX: Connection refused — "
                                             "driver attestation enforcement active");
                        return false;
                    }
                    // Dev/test mode: warn but continue
                    Utils::Logger::Warn("[FilterConnection] KEX: Driver attestation failed but "
                                        "enforcement is DISABLED — SOC alert recommended");
                }
                else {
                    Utils::Logger::Info("[FilterConnection] KEX: Driver attestation passed — "
                                        "Authenticode signature verified");
                }
            }
        }

        // Scrub the key exchange buffer — contains salt, wrapped key, nonce,
        // tag that are sensitive key-derivation inputs.
        crypto.SecureZero(buf.data(), buf.size());

        Utils::Logger::Info("[FilterConnection] Key exchange complete — "
                            "AES-256-GCM encryption established");
        return true;
    }

    //=========================================================================
    // Encryption Helpers
    //=========================================================================

    /**
     * @brief Decrypt an encrypted message payload in-place.
     *
     * Checks the SHADOWSTRIKE_MSG_FLAG_ENCRYPTED flag in the message header.
     * If set, decrypts the data portion (after SHADOWSTRIKE_MESSAGE_HEADER)
     * using the per-session AES-256-GCM key, with the header as AAD.
     *
     * @param buffer Raw message buffer (FILTER_MESSAGE_HEADER + SHADOWSTRIKE payload)
     * @param actualBytes Total bytes received (updated if decryption changes size)
     * @return true if no encryption flag set, or if decryption succeeded
     */
    bool DecryptReceivedMessage(uint8_t* buffer, size_t& actualBytes) {
        if (!m_encryptionEstablished.load(std::memory_order_acquire)) return true;

        // The filter message starts with FILTER_MESSAGE_HEADER, followed by
        // our SHADOWSTRIKE_MESSAGE_HEADER and payload.
        if (actualBytes < sizeof(FILTER_MESSAGE_HEADER) + sizeof(SHADOWSTRIKE_MESSAGE_HEADER))
            return true;  // Too small to contain encrypted data

        auto* ssHeader = reinterpret_cast<SHADOWSTRIKE_MESSAGE_HEADER*>(
            buffer + sizeof(FILTER_MESSAGE_HEADER));

        if (!(ssHeader->Flags & SHADOWSTRIKE_MSG_FLAG_ENCRYPTED))
            return true;  // Not encrypted

        // ── APT DEFENSE: Verify message HMAC if HMAC flag is set ─────
        // The kernel sets SHADOWSTRIKE_MSG_FLAG_HMAC when it appends a 32-byte
        // HMAC-SHA256 tag after the encrypted payload. Verify before any
        // decryption to detect tampering/replay early.
        if (ssHeader->Flags & SHADOWSTRIKE_MSG_FLAG_HMAC) {
            constexpr size_t kHmacSize = 32;
            if (actualBytes < sizeof(FILTER_MESSAGE_HEADER) +
                              sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + kHmacSize) {
                Utils::Logger::Warn("[FilterConnection] HMAC flag set but message too small");
                return false;
            }

            // HMAC covers everything from SHADOWSTRIKE_MESSAGE_HEADER to end of encrypted data
            const size_t hmacOffset = actualBytes - kHmacSize;
            std::span<const uint8_t> messageSpan(
                reinterpret_cast<const uint8_t*>(ssHeader),
                hmacOffset - sizeof(FILTER_MESSAGE_HEADER));
            std::span<const uint8_t> hmacSpan(
                buffer + hmacOffset, kHmacSize);
            std::span<const uint8_t> keySpan(m_sessionKey.data(), m_sessionKey.size());

            using namespace ShadowStrike::Security;
            if (!CryptoManager::Instance().VerifyKernelMessageIntegrity(
                    messageSpan, hmacSpan, keySpan)) {
                Utils::Logger::Error("[FilterConnection] Kernel message HMAC verification FAILED "
                                     "— potential tampering or replay attack");
                return false;
            }

            // Strip HMAC from buffer so decryption sees only the encrypted payload
            actualBytes -= kHmacSize;
        }

        // Data portion starts after SHADOWSTRIKE_MESSAGE_HEADER
        const size_t dataOffset = sizeof(FILTER_MESSAGE_HEADER) + sizeof(SHADOWSTRIKE_MESSAGE_HEADER);
        if (actualBytes <= dataOffset) return false;

        const size_t encDataSize = actualBytes - dataOffset;
        uint8_t* encData = buffer + dataOffset;
        if (encDataSize < sizeof(KernelEncHeader)) {
            Utils::Logger::Warn("[FilterConnection] Encrypted payload too small for kernel ENC_HEADER");
            return false;
        }

        const auto* encHeader = reinterpret_cast<const KernelEncHeader*>(encData);
        if (encHeader->magic != kKernelEncMagic ||
            encHeader->version != kKernelEncVersion ||
            encHeader->algorithm != kKernelEncAlgorithmAes256Gcm) {
            Utils::Logger::Warn("[FilterConnection] Invalid kernel encryption header");
            return false;
        }

        const uint32_t expectedHeaderCrc = ComputeKernelEncHeaderCrc32(
            encHeader, offsetof(KernelEncHeader, headerCrc32));
        if (encHeader->headerCrc32 != expectedHeaderCrc) {
            Utils::Logger::Warn("[FilterConnection] Kernel ENC_HEADER CRC mismatch");
            return false;
        }

        if (encHeader->aadSize != sizeof(SHADOWSTRIKE_MESSAGE_HEADER) ||
            encHeader->plaintextSize != encHeader->ciphertextSize ||
            encDataSize < sizeof(KernelEncHeader) + encHeader->ciphertextSize) {
            Utils::Logger::Warn("[FilterConnection] Invalid encrypted payload sizes");
            return false;
        }

        using namespace ShadowStrike::Security;
        auto& crypto = CryptoManager::Instance();
        std::span<const uint8_t> keySpan(m_sessionKey.data(), m_sessionKey.size());
        std::span<const uint8_t> nonceSpan(encHeader->nonce, sizeof(encHeader->nonce));
        std::span<const uint8_t> tagSpan(encHeader->tag, sizeof(encHeader->tag));

        // AAD must match byte-for-byte what the KERNEL authenticated when it
        // encrypted this message. The kernel sets the HMAC flag in the on-wire
        // SHADOWSTRIKE_MESSAGE_HEADER *before* GCM encryption and feeds that
        // exact header — HMAC flag included — as the GCM AAD
        // (CommPort.c:2816-2834). The received on-wire header is therefore the
        // AAD verbatim; clearing the HMAC flag here would make the AAD differ
        // from the kernel's by exactly that bit, causing GCM authentication to
        // fail on every encrypted scan request (and the scanner to never reply).
        std::span<const uint8_t> aadSpan(
            reinterpret_cast<const uint8_t*>(ssHeader), sizeof(SHADOWSTRIKE_MESSAGE_HEADER));
        std::span<const uint8_t> ciphertextSpan(
            encData + sizeof(KernelEncHeader), encHeader->ciphertextSize);

        auto result = crypto.Decrypt(
            ciphertextSpan,
            keySpan,
            SymmetricAlgorithm::AES_256_GCM,
            nonceSpan,
            tagSpan,
            aadSpan);

        if (result.plaintext.size() != encHeader->plaintextSize) {
            Utils::Logger::Warn("[FilterConnection] AES-256-GCM decryption failed "
                                "(authentication failure or size mismatch)");
            return false;
        }

        if (result.plaintext.size() <= encDataSize) {
            memcpy(encData, result.plaintext.data(), result.plaintext.size());
            actualBytes = dataOffset + result.plaintext.size();
            ssHeader->DataSize = static_cast<ULONG>(result.plaintext.size());
            ssHeader->TotalSize = static_cast<ULONG>(
                sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + result.plaintext.size());
            ssHeader->Flags &= ~SHADOWSTRIKE_MSG_FLAG_ENCRYPTED;
            if (!result.plaintext.empty()) {
                crypto.SecureZero(result.plaintext.data(), result.plaintext.size());
            }
        } else {
            Utils::Logger::Error("[FilterConnection] Decrypted plaintext ({} bytes) exceeds "
                                 "encrypted buffer ({} bytes) — corrupted message",
                                 result.plaintext.size(), encDataSize);
            return false;
        }

        return true;
    }

    /**
     * @brief Encrypt a message payload before sending to kernel.
     *
     * @param plainBuffer Original message data
     * @param[out] encryptedBuffer Output encrypted buffer
     * @return true if encryption succeeded
     */
    bool EncryptSendMessage(std::span<const uint8_t> plainBuffer,
                            std::vector<uint8_t>& encryptedBuffer) {
        if (!m_encryptionEstablished.load(std::memory_order_acquire))
            return false;

        if (plainBuffer.size() <= sizeof(SHADOWSTRIKE_MESSAGE_HEADER)) {
            encryptedBuffer.assign(plainBuffer.begin(), plainBuffer.end());
            return true;
        }

        using namespace ShadowStrike::Security;
        auto& crypto = CryptoManager::Instance();

        // Split into header + data
        const auto* header = reinterpret_cast<const SHADOWSTRIKE_MESSAGE_HEADER*>(plainBuffer.data());
        const size_t dataSize = plainBuffer.size() - sizeof(SHADOWSTRIKE_MESSAGE_HEADER);
        const uint8_t* data = plainBuffer.data() + sizeof(SHADOWSTRIKE_MESSAGE_HEADER);

        // Guard against integer overflow in size calculations.
        // dataSize + sizeof(KernelEncHeader) must fit in uint32_t (ULONG) since
        // kernel-side DataSize/TotalSize fields are ULONG.
        constexpr size_t kMaxEncPayload =
            static_cast<size_t>(UINT32_MAX) - sizeof(SHADOWSTRIKE_MESSAGE_HEADER);
        const size_t encPayloadSize = sizeof(KernelEncHeader) + dataSize;
        if (dataSize > kMaxEncPayload - sizeof(KernelEncHeader) ||
            encPayloadSize > kMaxEncPayload) {
            Utils::Logger::Error("[FilterConnection] EncryptSendMessage: payload too large "
                                 "({} bytes)", dataSize);
            return false;
        }

        // Nonce counter exhaustion check (mirrors kernel ENC_NONCE_COUNTER_MAX).
        // With uint64_t this is practically unreachable, but parity with kernel
        // prevents theoretical nonce reuse on counter wrap.
        constexpr uint64_t kNonceCounterMax = 0x7FFFFFFFFFFFFFFFuLL;
        const uint64_t counter = m_nonceCounter.fetch_add(1, std::memory_order_relaxed);
        if (counter >= kNonceCounterMax) {
            Utils::Logger::Error("[FilterConnection] Nonce counter exhausted — "
                                 "session key must be rotated");
            return false;
        }

        // Build structured nonce: [prefix(4) || counter(8)]
        // This ensures nonces are unique across sessions (prefix) and messages (counter).
        std::array<uint8_t, 12> nonce{};
        memcpy(nonce.data(), m_sessionNoncePrefix.data(), 4);
        memcpy(nonce.data() + 4, &counter, sizeof(counter));

        // Compute AAD from header with FINAL flags/size (as receiver will see it)
        SHADOWSTRIKE_MESSAGE_HEADER aadHeader = *header;
        aadHeader.Flags |= SHADOWSTRIKE_MSG_FLAG_ENCRYPTED;
        aadHeader.DataSize = static_cast<ULONG>(encPayloadSize);
        aadHeader.TotalSize = static_cast<ULONG>(
            sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + encPayloadSize);

        std::span<const uint8_t> keySpan(m_sessionKey.data(), m_sessionKey.size());
        std::span<const uint8_t> nonceSpan(nonce.data(), nonce.size());
        std::span<const uint8_t> aadSpan(
            reinterpret_cast<const uint8_t*>(&aadHeader), sizeof(aadHeader));

        auto result = crypto.Encrypt(
            std::span<const uint8_t>(data, dataSize),
            keySpan,
            SymmetricAlgorithm::AES_256_GCM,
            nonceSpan,
            aadSpan);

        if (result.ciphertext.empty() && dataSize > 0) {
            Utils::Logger::Error("[FilterConnection] Encryption failed");
            return false;
        }

        if (result.tag.size() != 16 || result.ciphertext.size() != dataSize) {
            Utils::Logger::Error("[FilterConnection] Encryption returned unexpected AES-GCM layout");
            return false;
        }

        KernelEncHeader innerHeader{};
        innerHeader.magic = kKernelEncMagic;
        innerHeader.version = kKernelEncVersion;
        innerHeader.algorithm = kKernelEncAlgorithmAes256Gcm;
        innerHeader.flags = kKernelEncFlagUseAad;
        innerHeader.plaintextSize = static_cast<uint32_t>(dataSize);
        innerHeader.ciphertextSize = static_cast<uint32_t>(result.ciphertext.size());
        memcpy(innerHeader.nonce, nonce.data(), nonce.size());
        memcpy(innerHeader.tag, result.tag.data(), result.tag.size());
        innerHeader.keyId = 0;
        innerHeader.aadSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER);
        innerHeader.timestamp = GetKernelEncTimestamp();
        innerHeader.headerCrc32 = ComputeKernelEncHeaderCrc32(
            &innerHeader, offsetof(KernelEncHeader, headerCrc32));

        // Wire format: [SHADOWSTRIKE_MESSAGE_HEADER][KernelEncHeader][ciphertext]
        encryptedBuffer.resize(sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + encPayloadSize);

        auto* outHeader = reinterpret_cast<SHADOWSTRIKE_MESSAGE_HEADER*>(encryptedBuffer.data());
        *outHeader = aadHeader;

        uint8_t* payloadDst = encryptedBuffer.data() + sizeof(SHADOWSTRIKE_MESSAGE_HEADER);
        memcpy(payloadDst, &innerHeader, sizeof(innerHeader));
        memcpy(payloadDst + sizeof(innerHeader),
               result.ciphertext.data(),
               result.ciphertext.size());

        // Scrub nonce (contains counter) — key was not copied
        crypto.SecureZero(nonce.data(), nonce.size());

        // ── APT DEFENSE: Append HMAC-SHA256 for message integrity ────
        // Set the HMAC flag and append a 32-byte HMAC over the entire
        // SHADOWSTRIKE_MESSAGE_HEADER + encrypted payload. The kernel
        // verifies this before decrypting, blocking injection attacks.
        {
            outHeader->Flags |= SHADOWSTRIKE_MSG_FLAG_HMAC;

            std::span<const uint8_t> msgSpan(
                encryptedBuffer.data() + 0,  // Start from SHADOWSTRIKE_MESSAGE_HEADER
                encryptedBuffer.size());
            std::span<const uint8_t> keySpan(m_sessionKey.data(), m_sessionKey.size());

            auto hmac = crypto.ComputeKernelMessageHMAC(msgSpan, keySpan);
            if (hmac.size() == 32) {
                encryptedBuffer.insert(encryptedBuffer.end(), hmac.begin(), hmac.end());
            } else {
                Utils::Logger::Warn("[FilterConnection] Failed to compute outgoing HMAC — "
                                    "sending without integrity tag");
                outHeader->Flags &= ~SHADOWSTRIKE_MSG_FLAG_HMAC;
            }
        }

        return true;
    }
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

bool FilterConnection::Connect(bool registerAsPrimaryScanner) {
    if (!m_impl) return false;
    return m_impl->Connect(registerAsPrimaryScanner);
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
