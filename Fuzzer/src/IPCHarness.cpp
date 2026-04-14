// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
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
 * @file IPCHarness.cpp
 * @brief Implementation of the ServiceCommunication IPC fuzz harness.
 *
 * Drives hostile named-pipe frames through the production listener, per-client
 * reader, challenge-response authentication, encrypted message handling, replay
 * tracking, and command-dispatch boundary in ServiceCommunication.
 */

#include "ShadowStrike/Fuzzer/Harnesses/IPCHarness.hpp"
#include "ShadowStrike/Fuzzer/Core/FuzzLoop.hpp"

#include "Communication/ServiceCommunication.hpp"
#include "SelfProtection/CryptoManager.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <malloc.h>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace ShadowStrike::Fuzzer {
namespace {

namespace ServiceComm = ShadowStrike::Communication;
namespace ServiceConst = ShadowStrike::Communication::ServiceCommConstants;
namespace SSCrypto = ShadowStrike::Security;

using ServiceComm::ClientType;
using ServiceComm::CommandCallback;
using ServiceComm::ConnectionState;
using ServiceComm::HandshakeChallengeMessage;
using ServiceComm::HandshakeMessage;
using ServiceComm::HandshakeResponseMessage;
using ServiceComm::MessageHeader;
using ServiceComm::MessageType;
using ServiceComm::ServiceCommConfiguration;
using ServiceComm::ServiceCommStatisticsSnapshot;
using ServiceComm::ServiceCommunication;

constexpr DWORD kIoTimeoutMs = 100;
constexpr DWORD kPipeReadyTimeoutMs = 250;
constexpr DWORD kPostSendSettleMs = 1;
constexpr size_t kMaxStructuredPayload = 4096;
constexpr size_t kMaxDirectWireInput = 16 * 1024;
constexpr size_t kMinChallengePayloadSize =
    ServiceConst::CHALLENGE_SIZE + ServiceConst::AES_KEY_SIZE;

struct HandleGuard {
    HANDLE h = INVALID_HANDLE_VALUE;

    HandleGuard() = default;
    explicit HandleGuard(HANDLE handle) noexcept : h(handle) {}
    ~HandleGuard() { Close(); }

    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;

    HandleGuard(HandleGuard&& other) noexcept : h(other.h) {
        other.h = INVALID_HANDLE_VALUE;
    }

    HandleGuard& operator=(HandleGuard&& other) noexcept {
        if (this != &other) {
            Close();
            h = other.h;
            other.h = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    void Close() noexcept {
        if (h != INVALID_HANDLE_VALUE && h != nullptr) {
            CloseHandle(h);
            h = INVALID_HANDLE_VALUE;
        }
    }

    [[nodiscard]] bool IsValid() const noexcept {
        return h != INVALID_HANDLE_VALUE && h != nullptr;
    }
};

struct WireFrame {
    MessageHeader header{};
    std::vector<uint8_t> payload;
};

struct CallbackState {
    std::atomic<uint32_t> totalCalls{0};
    std::atomic<uint32_t> privilegedCalls{0};
    std::atomic<uint32_t> queryCalls{0};
};

struct AuthSession {
    HandleGuard pipe;
    std::array<uint8_t, ServiceConst::AES_KEY_SIZE> sessionKey{};
    uint32_t nextSequence = 1;
    uint64_t nextNonce = 0;
};

enum class IPCScenario : uint8_t {
    DirectWire,
    OversizedHeader,
    TruncatedHandshake,
    EncryptedWithoutKey,
    PreAuthPrivileged,
    OutOfOrderHandshakeResponse,
    VersionSkewHandshake,
    AuthenticatedEncrypted
};

constexpr uint8_t kAuthenticatedScenarioTag = 0xA7;

[[nodiscard]] std::string_view ScenarioName(IPCScenario scenario) noexcept {
    switch (scenario) {
    case IPCScenario::DirectWire:
        return "direct";
    case IPCScenario::OversizedHeader:
        return "oversize";
    case IPCScenario::TruncatedHandshake:
        return "truncated";
    case IPCScenario::EncryptedWithoutKey:
        return "encrypted-without-key";
    case IPCScenario::PreAuthPrivileged:
        return "preauth-privileged";
    case IPCScenario::OutOfOrderHandshakeResponse:
        return "out-of-order-response";
    case IPCScenario::VersionSkewHandshake:
        return "version-skew";
    case IPCScenario::AuthenticatedEncrypted:
        return "authenticated-flow";
    }

    return "unknown";
}

std::string ExceptionCodeToStringInternal(DWORD code) noexcept {
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:         return "EXCEPTION_ACCESS_VIOLATION";
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
    case EXCEPTION_BREAKPOINT:               return "EXCEPTION_BREAKPOINT";
    case EXCEPTION_DATATYPE_MISALIGNMENT:    return "EXCEPTION_DATATYPE_MISALIGNMENT";
    case EXCEPTION_FLT_DENORMAL_OPERAND:     return "EXCEPTION_FLT_DENORMAL_OPERAND";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:       return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
    case EXCEPTION_FLT_INEXACT_RESULT:       return "EXCEPTION_FLT_INEXACT_RESULT";
    case EXCEPTION_FLT_INVALID_OPERATION:    return "EXCEPTION_FLT_INVALID_OPERATION";
    case EXCEPTION_FLT_OVERFLOW:             return "EXCEPTION_FLT_OVERFLOW";
    case EXCEPTION_FLT_STACK_CHECK:          return "EXCEPTION_FLT_STACK_CHECK";
    case EXCEPTION_FLT_UNDERFLOW:            return "EXCEPTION_FLT_UNDERFLOW";
    case EXCEPTION_GUARD_PAGE:               return "EXCEPTION_GUARD_PAGE";
    case EXCEPTION_ILLEGAL_INSTRUCTION:      return "EXCEPTION_ILLEGAL_INSTRUCTION";
    case EXCEPTION_IN_PAGE_ERROR:            return "EXCEPTION_IN_PAGE_ERROR";
    case EXCEPTION_INT_DIVIDE_BY_ZERO:       return "EXCEPTION_INT_DIVIDE_BY_ZERO";
    case EXCEPTION_INT_OVERFLOW:             return "EXCEPTION_INT_OVERFLOW";
    case EXCEPTION_INVALID_DISPOSITION:      return "EXCEPTION_INVALID_DISPOSITION";
    case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "EXCEPTION_NONCONTINUABLE_EXCEPTION";
    case EXCEPTION_PRIV_INSTRUCTION:         return "EXCEPTION_PRIV_INSTRUCTION";
    case EXCEPTION_SINGLE_STEP:              return "EXCEPTION_SINGLE_STEP";
    case EXCEPTION_STACK_OVERFLOW:           return "EXCEPTION_STACK_OVERFLOW";
    case STATUS_HEAP_CORRUPTION:             return "STATUS_HEAP_CORRUPTION";
    default: {
        char buffer[32]{};
        std::snprintf(buffer, sizeof(buffer), "EXCEPTION_0x%08lX", code);
        return buffer;
    }
    }
}

bool TraceEnabled() noexcept {
    static const bool enabled = [] {
        wchar_t buffer[4]{};
        const DWORD length = GetEnvironmentVariableW(L"SHADOWSTRIKE_FUZZ_TRACE", buffer, static_cast<DWORD>(std::size(buffer)));
        return length != 0;
    }();
    return enabled;
}

void Trace(std::string_view message) {
    if (!TraceEnabled()) {
        return;
    }

    std::cerr << "[IPCFuzzer][trace] " << message << '\n';
}

void CaptureFirstIssue(HarnessResult& result, std::string_view message) {
    if (result.errorMessage.empty()) {
        result.errorMessage.assign(message.data(), message.size());
    }
}

void RecordValidationIssue(HarnessResult& result, std::string_view message) {
    ++result.validationIssueCount;
    CaptureFirstIssue(result, message);
}

void RecordAnomaly(HarnessResult& result, std::string_view message) {
    ++result.anomalyCount;
    CaptureFirstIssue(result, message);
}

uint32_t ReadLe32(std::span<const uint8_t> input, size_t offset, uint32_t fallback) noexcept {
    if (offset >= input.size()) {
        return fallback;
    }

    uint32_t value = 0;
    const size_t copySize = std::min(sizeof(value), input.size() - offset);
    std::memcpy(&value, input.data() + offset, copySize);
    return value;
}

[[nodiscard]] IPCScenario SelectScenario(std::span<const uint8_t> input) noexcept {
    if (input.size() >= sizeof(MessageHeader)) {
        MessageHeader header{};
        std::memcpy(&header, input.data(), sizeof(header));

        if (header.magic == ServiceConst::PROTOCOL_MAGIC) {
            if (header.type == MessageType::Handshake) {
                return header.version == ServiceConst::PROTOCOL_VERSION
                    ? IPCScenario::TruncatedHandshake
                    : IPCScenario::VersionSkewHandshake;
            }

            if (header.type == MessageType::HandshakeResponse) {
                return IPCScenario::OutOfOrderHandshakeResponse;
            }

            if ((header.flags & ServiceConst::MSG_FLAG_ENCRYPTED) != 0U) {
                return IPCScenario::EncryptedWithoutKey;
            }

            if (header.type == MessageType::CmdSetConfig) {
                return IPCScenario::PreAuthPrivileged;
            }
        }
    }

    if (!input.empty() && input.front() == kAuthenticatedScenarioTag) {
        return IPCScenario::AuthenticatedEncrypted;
    }

    const uint32_t selector = ReadLe32(input, 0, 0x49504332U) ^
        ReadLe32(input, 4, 0xA5A55A5AU) ^
        static_cast<uint32_t>(input.size());
    if ((selector & 0x7U) == 0U) {
        return IPCScenario::AuthenticatedEncrypted;
    }

    switch ((selector >> 3U) % 7U) {
    case 0:
        return IPCScenario::DirectWire;
    case 1:
        return IPCScenario::OversizedHeader;
    case 2:
        return IPCScenario::TruncatedHandshake;
    case 3:
        return IPCScenario::EncryptedWithoutKey;
    case 4:
        return IPCScenario::PreAuthPrivileged;
    case 5:
        return IPCScenario::OutOfOrderHandshakeResponse;
    default:
        return IPCScenario::VersionSkewHandshake;
    }
}

uint64_t ReadLe64(std::span<const uint8_t> input, size_t offset, uint64_t fallback) noexcept {
    if (offset >= input.size()) {
        return fallback;
    }

    uint64_t value = 0;
    const size_t copySize = std::min(sizeof(value), input.size() - offset);
    std::memcpy(&value, input.data() + offset, copySize);
    return value;
}

bool LooksLikeCompleteStructuredFrame(std::span<const uint8_t> input) noexcept {
    if (input.size() < sizeof(MessageHeader)) {
        return false;
    }

    MessageHeader header{};
    std::memcpy(&header, input.data(), sizeof(header));
    if (header.magic != ServiceConst::PROTOCOL_MAGIC) {
        return false;
    }

    const uint64_t requiredSize = static_cast<uint64_t>(sizeof(MessageHeader)) +
                                  static_cast<uint64_t>(header.payloadLength);
    return requiredSize <= input.size();
}

uint32_t ComputeCrc32(std::span<const uint8_t> data) noexcept {
    static uint32_t table[256]{};
    static std::once_flag tableInit;

    std::call_once(tableInit, [] {
        for (uint32_t index = 0; index < 256; ++index) {
            uint32_t crc = index;
            for (int round = 0; round < 8; ++round) {
                crc = (crc >> 1U) ^ ((crc & 1U) != 0U ? 0xEDB88320U : 0U);
            }
            table[index] = crc;
        }
    });

    uint32_t crc = 0xFFFFFFFFU;
    for (const uint8_t byte : data) {
        crc = table[(crc ^ byte) & 0xFFU] ^ (crc >> 8U);
    }
    return ~crc;
}

void EnsureCryptoReady(HarnessResult& result) {
    auto& crypto = SSCrypto::CryptoManager::Instance();
    if (crypto.IsInitialized()) {
        Trace("EnsureCryptoReady: already initialized");
        return;
    }

    Trace("EnsureCryptoReady: initializing");
    if (!crypto.Initialize({})) {
        RecordValidationIssue(result, "CryptoManager initialization failed for IPC harness.");
        Trace("EnsureCryptoReady: initialization failed");
    } else {
        Trace("EnsureCryptoReady: initialization succeeded");
    }
}

std::wstring BuildPipeName(std::span<const uint8_t> input) {
    static std::atomic<uint64_t> counter{0};
    const uint64_t seq = counter.fetch_add(1, std::memory_order_relaxed);
    const uint32_t tag = ReadLe32(input, 0, 0x49504331U);

    wchar_t buffer[160]{};
    std::swprintf(
        buffer,
        std::size(buffer),
        L"\\\\.\\pipe\\ShadowStrikeFuzzerIPC_%lu_%016llX_%08X",
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long long>(seq),
        static_cast<unsigned int>(tag));
    return buffer;
}

std::vector<uint8_t> BoundedPayload(std::span<const uint8_t> input, size_t maxSize = kMaxStructuredPayload) {
    const size_t payloadSize = std::min(input.size(), maxSize);
    std::vector<uint8_t> payload(payloadSize);
    if (payloadSize > 0) {
        std::memcpy(payload.data(), input.data(), payloadSize);
    }
    return payload;
}

std::vector<uint8_t> BuildCommandPayload(std::span<const uint8_t> input) {
    std::vector<uint8_t> payload = BoundedPayload(input, kMaxStructuredPayload);
    if (payload.empty()) {
        payload.assign({'q', 'u', 'e', 'r', 'y'});
    }
    return payload;
}

HandshakeMessage BuildHandshakeMessage(std::span<const uint8_t> input, uint32_t sequence, uint32_t version) {
    HandshakeMessage message{};
    message.header.magic = ServiceConst::PROTOCOL_MAGIC;
    message.header.version = version;
    message.header.type = MessageType::Handshake;
    message.header.sequence = sequence;
    message.header.responseTo = 0;
    message.header.flags = 0;
    message.header.payloadLength = sizeof(HandshakeMessage) - sizeof(MessageHeader);
    message.clientType = static_cast<ClientType>(ReadLe32(input, 0, static_cast<uint32_t>(ClientType::CLI)) %
                                                (static_cast<uint32_t>(ClientType::API) + 1U));
    for (size_t index = 0; index < std::size(message.clientVersion); ++index) {
        message.clientVersion[index] = ReadLe32(input, 1 + index * sizeof(uint32_t), static_cast<uint32_t>(index + 1));
    }

    const size_t tokenCopy = std::min(input.size(), sizeof(message.sessionToken));
    if (tokenCopy > 0) {
        std::memcpy(message.sessionToken, input.data(), tokenCopy);
    }

    const uint32_t pid = ReadLe32(input, 32, GetCurrentProcessId());
    message.processId = pid == 0 ? GetCurrentProcessId() : pid;
    message.capabilities = ReadLe64(input, 40, 0x10000000ULL);

    const auto payload = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(&message) + sizeof(MessageHeader),
        message.header.payloadLength);
    message.header.checksum = ComputeCrc32(payload);
    return message;
}

WireFrame BuildPlaintextFrame(
    MessageType type,
    uint32_t sequence,
    std::span<const uint8_t> payload,
    uint32_t responseTo = 0,
    uint32_t version = ServiceConst::PROTOCOL_VERSION,
    uint32_t magic = ServiceConst::PROTOCOL_MAGIC,
    uint16_t flags = 0) {
    WireFrame frame{};
    frame.payload.assign(payload.begin(), payload.end());
    frame.header.magic = magic;
    frame.header.version = version;
    frame.header.type = type;
    frame.header.flags = flags;
    frame.header.sequence = sequence;
    frame.header.responseTo = responseTo;
    frame.header.payloadLength = static_cast<uint32_t>(frame.payload.size());
    if ((flags & ServiceConst::MSG_FLAG_ENCRYPTED) == 0 && !frame.payload.empty()) {
        frame.header.checksum = ComputeCrc32(frame.payload);
    }
    return frame;
}

std::optional<std::vector<uint8_t>> GetOrCreatePipePsk(HarnessResult& result) {
    auto& crypto = SSCrypto::CryptoManager::Instance();
    auto existing = crypto.RetrieveKey(ServiceConst::PSK_KEY_ID);
    if (existing.has_value() && !existing->empty()) {
        return existing;
    }

    auto generated = crypto.GenerateRandomKey(ServiceConst::AES_KEY_SIZE);
    if (generated.size() != ServiceConst::AES_KEY_SIZE) {
        RecordValidationIssue(result, "Failed to generate ServiceCommunication pre-shared key.");
        return std::nullopt;
    }

    const std::string keyId = crypto.StoreKey(
        std::span<const uint8_t>(generated.data(), generated.size()),
        SSCrypto::KeyType::Symmetric,
        SSCrypto::KeyStorage::DPAPI,
        ServiceConst::PSK_KEY_ID);
    if (keyId.empty()) {
        crypto.SecureZero(generated.data(), generated.size());
        RecordValidationIssue(result, "Failed to persist ServiceCommunication pre-shared key.");
        return std::nullopt;
    }

    return generated;
}

bool WaitForPipeReady(const std::wstring& pipeName, DWORD timeoutMs) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    do {
        if (WaitNamedPipeW(pipeName.c_str(), 10)) {
            return true;
        }

        const DWORD err = GetLastError();
        if (err != ERROR_FILE_NOT_FOUND && err != ERROR_SEM_TIMEOUT) {
            return false;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    } while (std::chrono::steady_clock::now() < deadline);

    return false;
}

std::optional<HandleGuard> ConnectRawClient(const std::wstring& pipeName) {
    Trace("ConnectRawClient: waiting for pipe");
    if (!WaitForPipeReady(pipeName, kPipeReadyTimeoutMs)) {
        Trace("ConnectRawClient: WaitForPipeReady failed");
        return std::nullopt;
    }

    Trace("ConnectRawClient: opening pipe");
    HandleGuard pipe(CreateFileW(
        pipeName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        nullptr));
    if (!pipe.IsValid()) {
        Trace("ConnectRawClient: CreateFileW failed");
        return std::nullopt;
    }

    DWORD mode = PIPE_READMODE_BYTE;
    if (!SetNamedPipeHandleState(pipe.h, &mode, nullptr, nullptr)) {
        Trace("ConnectRawClient: SetNamedPipeHandleState failed");
        return std::nullopt;
    }

    Trace("ConnectRawClient: connected");
    return pipe;
}

bool WriteExact(HANDLE pipe, const void* buffer, DWORD size, DWORD timeoutMs) {
    if (size == 0) {
        return true;
    }

    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (ov.hEvent == nullptr || ov.hEvent == INVALID_HANDLE_VALUE) {
        return false;
    }
    HandleGuard eventGuard(ov.hEvent);

    DWORD transferred = 0;
    if (!WriteFile(pipe, buffer, size, &transferred, &ov)) {
        const DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING) {
            return false;
        }

        if (WaitForSingleObject(ov.hEvent, timeoutMs) != WAIT_OBJECT_0) {
            CancelIoEx(pipe, &ov);
            return false;
        }

        if (!GetOverlappedResult(pipe, &ov, &transferred, FALSE)) {
            return false;
        }
    }

    return transferred == size;
}

bool ReadExact(HANDLE pipe, void* buffer, DWORD size, DWORD timeoutMs) {
    if (size == 0) {
        return true;
    }

    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (ov.hEvent == nullptr || ov.hEvent == INVALID_HANDLE_VALUE) {
        return false;
    }
    HandleGuard eventGuard(ov.hEvent);

    DWORD transferred = 0;
    if (!ReadFile(pipe, buffer, size, &transferred, &ov)) {
        const DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING) {
            return false;
        }

        if (WaitForSingleObject(ov.hEvent, timeoutMs) != WAIT_OBJECT_0) {
            CancelIoEx(pipe, &ov);
            return false;
        }

        if (!GetOverlappedResult(pipe, &ov, &transferred, FALSE)) {
            return false;
        }
    }

    return transferred == size;
}

bool SendFrame(HANDLE pipe, const WireFrame& frame, size_t payloadBytesToWrite = SIZE_MAX) {
    if (!WriteExact(pipe, &frame.header, static_cast<DWORD>(sizeof(frame.header)), kIoTimeoutMs)) {
        return false;
    }

    const size_t bytesToWrite = std::min(frame.payload.size(), payloadBytesToWrite);
    if (bytesToWrite == 0) {
        return true;
    }

    return WriteExact(
        pipe,
        frame.payload.data(),
        static_cast<DWORD>(bytesToWrite),
        kIoTimeoutMs);
}

bool SendRawBytes(HANDLE pipe, std::span<const uint8_t> bytes) {
    if (bytes.empty()) {
        return true;
    }

    return WriteExact(pipe, bytes.data(), static_cast<DWORD>(bytes.size()), kIoTimeoutMs);
}

std::optional<WireFrame> TryReadFrame(HANDLE pipe, DWORD timeoutMs) {
    WireFrame frame{};
    if (!ReadExact(pipe, &frame.header, static_cast<DWORD>(sizeof(frame.header)), timeoutMs)) {
        return std::nullopt;
    }

    if (frame.header.payloadLength > ServiceConst::MAX_MESSAGE_SIZE + ServiceConst::HMAC_SIZE) {
        return std::nullopt;
    }

    frame.payload.resize(frame.header.payloadLength);
    if (!frame.payload.empty() &&
        !ReadExact(pipe, frame.payload.data(), static_cast<DWORD>(frame.payload.size()), timeoutMs)) {
        return std::nullopt;
    }

    return frame;
}

void StartServer(
    const std::wstring& pipeName,
    const std::shared_ptr<CallbackState>& callbacks,
    HarnessResult& result) {
    auto& service = ServiceCommunication::Instance();
    Trace("StartServer: pre-shutdown");
    service.UnregisterCallbacks();
    service.Shutdown();
    Trace("StartServer: post-shutdown");

    ServiceCommConfiguration config{};
    config.enabled = true;
    config.isService = true;
    config.pipeName = pipeName;
    config.maxClients = 4;
    config.connectionTimeoutMs = 150;
    config.heartbeatIntervalMs = 250;
    config.enableAuthentication = true;
    config.enableEncryption = true;
    config.enableRateLimiting = true;
    config.maxMessagesPerSecond = 512;
    config.enableAuditLog = true;

    Trace("StartServer: initialize");
    if (!service.Initialize(config)) {
        RecordValidationIssue(result, "ServiceCommunication initialization failed for IPC harness.");
        Trace("StartServer: initialize failed");
        return;
    }

    service.RegisterCommandCallback([callbacks](MessageType cmd, const std::vector<uint8_t>& payload, std::vector<uint8_t>& response) {
        callbacks->totalCalls.fetch_add(1, std::memory_order_relaxed);
        const auto typeValue = static_cast<uint16_t>(cmd);
        if (typeValue >= 0x0400U && typeValue < 0x0500U) {
            callbacks->privilegedCalls.fetch_add(1, std::memory_order_relaxed);
        }
        if (cmd == MessageType::QueryStatus || cmd == MessageType::QueryStats || cmd == MessageType::CmdQuickScan) {
            callbacks->queryCalls.fetch_add(1, std::memory_order_relaxed);
        }

        response.assign({'o', 'k'});
        if (!payload.empty()) {
            response.push_back(':');
            const size_t copy = std::min<size_t>(payload.size(), 16);
            response.insert(response.end(), payload.begin(), payload.begin() + copy);
        }
        return true;
    });

    Trace("StartServer: start");
    if (!service.Start(true)) {
        RecordValidationIssue(result, "ServiceCommunication server start failed for IPC harness.");
        service.UnregisterCallbacks();
        service.Shutdown();
        Trace("StartServer: start failed");
        return;
    }

    Trace("StartServer: service started");
    if (!WaitForPipeReady(pipeName, kPipeReadyTimeoutMs)) {
        RecordValidationIssue(result, "ServiceCommunication listener did not expose a ready named pipe.");
        service.UnregisterCallbacks();
        service.Shutdown();
    }
    Trace("StartServer: pipe reported ready");
}

void StopServer() {
    Trace("StopServer: begin");
    auto& service = ServiceCommunication::Instance();
    Trace("StopServer: disconnect-clients");
    service.DisconnectAllClients();
    Trace("StopServer: unregister-callbacks");
    service.UnregisterCallbacks();
    Trace("StopServer: shutdown");
    service.Shutdown();
    Trace("StopServer: end");
}

ServiceCommStatisticsSnapshot SnapshotStats() {
    return ServiceCommunication::Instance().GetStatistics();
}

void PauseForServer() {
    std::this_thread::sleep_for(std::chrono::milliseconds(kPostSendSettleMs));
}

bool StatsAdvanced(
    const ServiceCommStatisticsSnapshot& before,
    const ServiceCommStatisticsSnapshot& after) noexcept {
    return after.messagesReceived > before.messagesReceived ||
           after.errors > before.errors ||
           after.authFailures > before.authFailures;
}

AuthSession AuthenticateRawSession(
    const std::wstring& pipeName,
    std::span<const uint8_t> input,
    HarnessResult& result) {
    AuthSession session{};
    auto clientPipe = ConnectRawClient(pipeName);
    if (!clientPipe.has_value()) {
        RecordValidationIssue(result, "Failed to connect raw client to ServiceCommunication pipe.");
        return session;
    }

    session.pipe = std::move(*clientPipe);

    const HandshakeMessage handshake = BuildHandshakeMessage(input, 1, ServiceConst::PROTOCOL_VERSION);
    if (!WriteExact(session.pipe.h, &handshake, static_cast<DWORD>(sizeof(handshake)), kIoTimeoutMs)) {
        RecordValidationIssue(result, "Failed to send handshake frame to ServiceCommunication.");
        session.pipe.Close();
        return session;
    }

    const auto challengeFrame = TryReadFrame(session.pipe.h, kIoTimeoutMs);
    if (!challengeFrame.has_value() ||
        challengeFrame->header.type != MessageType::HandshakeChallenge ||
        challengeFrame->payload.size() < kMinChallengePayloadSize) {
        RecordValidationIssue(result, "Failed to receive a valid HandshakeChallenge frame.");
        session.pipe.Close();
        return session;
    }

    auto psk = GetOrCreatePipePsk(result);
    if (!psk.has_value()) {
        session.pipe.Close();
        return session;
    }

    auto& crypto = SSCrypto::CryptoManager::Instance();
    const std::span<const uint8_t> challenge(
        challengeFrame->payload.data(),
        ServiceConst::CHALLENGE_SIZE);
    const std::span<const uint8_t> salt(
        challengeFrame->payload.data() + ServiceConst::CHALLENGE_SIZE,
        ServiceConst::AES_KEY_SIZE);

    const auto hmac = crypto.HMAC(challenge, std::span<const uint8_t>(psk->data(), psk->size()));
    if (hmac.size() < ServiceConst::HMAC_SIZE) {
        crypto.SecureZero(psk->data(), psk->size());
        RecordValidationIssue(result, "Failed to compute handshake HMAC for IPC auth.");
        session.pipe.Close();
        return session;
    }

    HandshakeResponseMessage response{};
    response.header.magic = ServiceConst::PROTOCOL_MAGIC;
    response.header.version = ServiceConst::PROTOCOL_VERSION;
    response.header.type = MessageType::HandshakeResponse;
    response.header.flags = 0;
    response.header.sequence = 2;
    response.header.responseTo = challengeFrame->header.sequence;
    response.header.payloadLength = sizeof(HandshakeResponseMessage) - sizeof(MessageHeader);
    std::memcpy(response.hmacResponse, hmac.data(), ServiceConst::HMAC_SIZE);
    const auto responsePayload = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(&response) + sizeof(MessageHeader),
        response.header.payloadLength);
    response.header.checksum = ComputeCrc32(responsePayload);

    if (!WriteExact(session.pipe.h, &response, static_cast<DWORD>(sizeof(response)), kIoTimeoutMs)) {
        crypto.SecureZero(psk->data(), psk->size());
        RecordValidationIssue(result, "Failed to send HandshakeResponse frame.");
        session.pipe.Close();
        return session;
    }

    const auto ackFrame = TryReadFrame(session.pipe.h, kIoTimeoutMs);
    if (!ackFrame.has_value() || ackFrame->header.type != MessageType::HandshakeAck) {
        crypto.SecureZero(psk->data(), psk->size());
        RecordValidationIssue(result, "HandshakeAck was not returned after a valid challenge response.");
        session.pipe.Close();
        return session;
    }

    const std::string hkdfInfo(ServiceConst::HKDF_SESSION_INFO);
    const auto sessionKey = crypto.HKDF(
        std::span<const uint8_t>(psk->data(), psk->size()),
        salt,
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(hkdfInfo.data()),
            hkdfInfo.size()),
        ServiceConst::AES_KEY_SIZE);
    crypto.SecureZero(psk->data(), psk->size());

    if (sessionKey.size() != ServiceConst::AES_KEY_SIZE) {
        RecordValidationIssue(result, "Failed to derive the authenticated IPC session key.");
        session.pipe.Close();
        return session;
    }

    std::memcpy(session.sessionKey.data(), sessionKey.data(), session.sessionKey.size());
    auto mutableSessionKey = sessionKey;
    crypto.SecureZero(mutableSessionKey.data(), mutableSessionKey.size());
    session.nextSequence = 3;
    session.nextNonce = 0;
    return session;
}

WireFrame BuildEncryptedCommandFrame(
    MessageType type,
    uint32_t sequence,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> sessionKey,
    uint64_t nonceCounter,
    HarnessResult& result) {
    WireFrame frame{};
    frame.header.magic = ServiceConst::PROTOCOL_MAGIC;
    frame.header.version = ServiceConst::PROTOCOL_VERSION;
    frame.header.type = type;
    frame.header.sequence = sequence;
    frame.header.responseTo = 0;
    frame.header.flags = 0;
    frame.header.payloadLength = static_cast<uint32_t>(plaintext.size());
    frame.header.checksum = 0;

    std::array<uint8_t, ServiceConst::GCM_NONCE_SIZE> nonce{};
    std::memcpy(nonce.data(), &nonceCounter, sizeof(nonceCounter));
    nonce[8] = 0x00;

    MessageHeader aadHeader = frame.header;
    aadHeader.flags |= ServiceConst::MSG_FLAG_ENCRYPTED;
    aadHeader.payloadLength = static_cast<uint32_t>(
        ServiceConst::GCM_NONCE_SIZE + plaintext.size() + ServiceConst::GCM_TAG_SIZE);

    auto& crypto = SSCrypto::CryptoManager::Instance();
    const auto enc = crypto.Encrypt(
        plaintext,
        sessionKey,
        SSCrypto::SymmetricAlgorithm::AES_256_GCM,
        nonce,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&aadHeader), sizeof(aadHeader)));
    if (!enc.IsSuccess() || (enc.ciphertext.empty() && !plaintext.empty()) || enc.tag.size() != ServiceConst::GCM_TAG_SIZE) {
        RecordValidationIssue(result, "Failed to build encrypted IPC command frame.");
        return frame;
    }

    frame.payload.reserve(nonce.size() + enc.ciphertext.size() + enc.tag.size() + ServiceConst::HMAC_SIZE);
    frame.payload.insert(frame.payload.end(), nonce.begin(), nonce.end());
    frame.payload.insert(frame.payload.end(), enc.ciphertext.begin(), enc.ciphertext.end());
    frame.payload.insert(frame.payload.end(), enc.tag.begin(), enc.tag.end());

    frame.header.flags = ServiceConst::MSG_FLAG_ENCRYPTED | ServiceConst::MSG_FLAG_HMAC;
    frame.header.payloadLength = static_cast<uint32_t>(frame.payload.size() + ServiceConst::HMAC_SIZE);

    std::vector<uint8_t> hmacInput;
    hmacInput.reserve(sizeof(frame.header) + frame.payload.size());
    hmacInput.insert(
        hmacInput.end(),
        reinterpret_cast<const uint8_t*>(&frame.header),
        reinterpret_cast<const uint8_t*>(&frame.header) + sizeof(frame.header));
    hmacInput.insert(hmacInput.end(), frame.payload.begin(), frame.payload.end());

    const auto hmac = crypto.ComputeKernelMessageHMAC(
        std::span<const uint8_t>(hmacInput.data(), hmacInput.size()),
        sessionKey);
    if (hmac.size() != ServiceConst::HMAC_SIZE) {
        RecordValidationIssue(result, "Failed to compute encrypted IPC frame HMAC.");
        frame.payload.clear();
        return frame;
    }

    frame.payload.insert(frame.payload.end(), hmac.begin(), hmac.end());
    return frame;
}

bool ExerciseDirectWireMutation(
    const std::wstring& pipeName,
    std::span<const uint8_t> input,
    HarnessResult& result) {
    if (LooksLikeCompleteStructuredFrame(input)) {
        return false;
    }

    auto clientPipe = ConnectRawClient(pipeName);
    if (!clientPipe.has_value()) {
        RecordValidationIssue(result, "Failed to connect direct-wire fuzz client.");
        return false;
    }

    const ServiceCommStatisticsSnapshot before = SnapshotStats();
    const size_t byteCount = std::min(input.size(), kMaxDirectWireInput);
    const std::span<const uint8_t> wire = input.first(byteCount);
    const bool writeOk = SendRawBytes(clientPipe->h, wire);
    clientPipe->Close();
    PauseForServer();
    const ServiceCommStatisticsSnapshot after = SnapshotStats();

    if (!writeOk && !wire.empty()) {
        RecordValidationIssue(result, "Direct raw IPC write failed unexpectedly.");
    }
    return StatsAdvanced(before, after);
}

bool ExerciseOversizedHeader(const std::wstring& pipeName, HarnessResult& result) {
    auto clientPipe = ConnectRawClient(pipeName);
    if (!clientPipe.has_value()) {
        RecordValidationIssue(result, "Failed to connect oversize-header client.");
        return false;
    }

    WireFrame frame{};
    frame.header.magic = ServiceConst::PROTOCOL_MAGIC;
    frame.header.version = ServiceConst::PROTOCOL_VERSION;
    frame.header.type = MessageType::Handshake;
    frame.header.sequence = 10;
    frame.header.payloadLength = static_cast<uint32_t>(ServiceConst::MAX_MESSAGE_SIZE + 1);

    const ServiceCommStatisticsSnapshot before = SnapshotStats();
    const bool sent = SendFrame(clientPipe->h, frame);
    clientPipe->Close();
    PauseForServer();
    const ServiceCommStatisticsSnapshot after = SnapshotStats();

    if (!sent) {
        RecordValidationIssue(result, "Failed to send oversized IPC header.");
    }
    return StatsAdvanced(before, after);
}

bool ExerciseTruncatedHandshake(
    const std::wstring& pipeName,
    std::span<const uint8_t> input,
    HarnessResult& result) {
    auto clientPipe = ConnectRawClient(pipeName);
    if (!clientPipe.has_value()) {
        RecordValidationIssue(result, "Failed to connect truncated-handshake client.");
        return false;
    }

    const HandshakeMessage handshake = BuildHandshakeMessage(input, 11, ServiceConst::PROTOCOL_VERSION);
    WireFrame frame{};
    frame.header = handshake.header;
    const auto payload = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(&handshake) + sizeof(MessageHeader),
        handshake.header.payloadLength);
    frame.payload.assign(payload.begin(), payload.end());

    const size_t partial = std::min<size_t>(frame.payload.size(), std::max<size_t>(1, frame.payload.size() / 2));
    const ServiceCommStatisticsSnapshot before = SnapshotStats();
    const bool sent = SendFrame(clientPipe->h, frame, partial);
    clientPipe->Close();
    PauseForServer();
    const ServiceCommStatisticsSnapshot after = SnapshotStats();

    if (!sent) {
        RecordValidationIssue(result, "Failed to send truncated handshake frame.");
    }
    return StatsAdvanced(before, after);
}

bool ExerciseEncryptedWithoutKey(
    const std::wstring& pipeName,
    std::span<const uint8_t> input,
    HarnessResult& result) {
    auto clientPipe = ConnectRawClient(pipeName);
    if (!clientPipe.has_value()) {
        RecordValidationIssue(result, "Failed to connect encrypted-without-key client.");
        return false;
    }

    auto payload = BuildCommandPayload(input);
    WireFrame frame = BuildPlaintextFrame(
        MessageType::QueryStatus,
        20,
        payload,
        0,
        ServiceConst::PROTOCOL_VERSION,
        ServiceConst::PROTOCOL_MAGIC,
        ServiceConst::MSG_FLAG_ENCRYPTED | ServiceConst::MSG_FLAG_HMAC);
    frame.header.checksum = 0;

    const ServiceCommStatisticsSnapshot before = SnapshotStats();
    const bool sent = SendFrame(clientPipe->h, frame);
    clientPipe->Close();
    PauseForServer();
    const ServiceCommStatisticsSnapshot after = SnapshotStats();

    if (!sent) {
        RecordValidationIssue(result, "Failed to send encrypted-without-key frame.");
    }
    return StatsAdvanced(before, after);
}

bool ExercisePreAuthPrivilegedCommand(
    const std::wstring& pipeName,
    std::span<const uint8_t> input,
    const std::shared_ptr<CallbackState>& callbacks,
    HarnessResult& result) {
    auto clientPipe = ConnectRawClient(pipeName);
    if (!clientPipe.has_value()) {
        RecordValidationIssue(result, "Failed to connect pre-auth privileged-command client.");
        return false;
    }

    const uint32_t callbacksBefore = callbacks->totalCalls.load(std::memory_order_relaxed);
    const ServiceCommStatisticsSnapshot before = SnapshotStats();
    const WireFrame frame = BuildPlaintextFrame(MessageType::CmdSetConfig, 30, BuildCommandPayload(input));
    const bool sent = SendFrame(clientPipe->h, frame);
    clientPipe->Close();
    PauseForServer();
    const ServiceCommStatisticsSnapshot after = SnapshotStats();

    if (!sent) {
        RecordValidationIssue(result, "Failed to send pre-auth privileged command frame.");
    }

    if (callbacks->totalCalls.load(std::memory_order_relaxed) != callbacksBefore) {
        RecordAnomaly(result, "Unauthenticated privileged IPC command reached the command callback.");
    }

    return StatsAdvanced(before, after);
}

bool ExerciseOutOfOrderHandshakeResponse(
    const std::wstring& pipeName,
    std::span<const uint8_t> input,
    const std::shared_ptr<CallbackState>& callbacks,
    HarnessResult& result) {
    auto clientPipe = ConnectRawClient(pipeName);
    if (!clientPipe.has_value()) {
        RecordValidationIssue(result, "Failed to connect out-of-order handshake client.");
        return false;
    }

    HandshakeResponseMessage response{};
    response.header.magic = ServiceConst::PROTOCOL_MAGIC;
    response.header.version = ServiceConst::PROTOCOL_VERSION;
    response.header.type = MessageType::HandshakeResponse;
    response.header.sequence = 40;
    response.header.responseTo = 0;
    response.header.payloadLength = sizeof(HandshakeResponseMessage) - sizeof(MessageHeader);

    auto fuzzPayload = BoundedPayload(input, sizeof(response.hmacResponse));
    if (fuzzPayload.size() < sizeof(response.hmacResponse)) {
        fuzzPayload.resize(sizeof(response.hmacResponse), 0xA5);
    }
    std::memcpy(response.hmacResponse, fuzzPayload.data(), sizeof(response.hmacResponse));
    const auto payload = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(&response) + sizeof(MessageHeader),
        response.header.payloadLength);
    response.header.checksum = ComputeCrc32(payload);

    const uint32_t callbacksBefore = callbacks->totalCalls.load(std::memory_order_relaxed);
    const ServiceCommStatisticsSnapshot before = SnapshotStats();
    const bool sent = WriteExact(clientPipe->h, &response, static_cast<DWORD>(sizeof(response)), kIoTimeoutMs);
    clientPipe->Close();
    PauseForServer();
    const ServiceCommStatisticsSnapshot after = SnapshotStats();

    if (!sent) {
        RecordValidationIssue(result, "Failed to send out-of-order HandshakeResponse.");
    }

    if (callbacks->totalCalls.load(std::memory_order_relaxed) != callbacksBefore) {
        RecordAnomaly(result, "Out-of-order HandshakeResponse unexpectedly reached the command callback.");
    }

    return StatsAdvanced(before, after);
}

bool ExerciseVersionSkewHandshake(
    const std::wstring& pipeName,
    std::span<const uint8_t> input,
    HarnessResult& result) {
    auto clientPipe = ConnectRawClient(pipeName);
    if (!clientPipe.has_value()) {
        RecordValidationIssue(result, "Failed to connect version-skew handshake client.");
        return false;
    }

    const HandshakeMessage handshake = BuildHandshakeMessage(input, 50, 0xDEAD0001U);
    const ServiceCommStatisticsSnapshot before = SnapshotStats();
    const bool sent = WriteExact(clientPipe->h, &handshake, static_cast<DWORD>(sizeof(handshake)), kIoTimeoutMs);
    bool reachedHandshake = false;
    if (sent) {
        const auto challenge = TryReadFrame(clientPipe->h, kIoTimeoutMs);
        reachedHandshake = challenge.has_value() && challenge->header.type == MessageType::HandshakeChallenge;
    }

    clientPipe->Close();
    PauseForServer();
    const ServiceCommStatisticsSnapshot after = SnapshotStats();

    if (!sent) {
        RecordValidationIssue(result, "Failed to send version-skew handshake.");
    }
    return reachedHandshake || StatsAdvanced(before, after);
}

bool ExerciseAuthenticatedEncryptedFlow(
    const std::wstring& pipeName,
    std::span<const uint8_t> input,
    const std::shared_ptr<CallbackState>& callbacks,
    HarnessResult& result) {
    AuthSession session = AuthenticateRawSession(pipeName, input, result);
    if (!session.pipe.IsValid()) {
        return false;
    }

    bool reachedDeepPath = true;
    const uint32_t callbackCountBefore = callbacks->totalCalls.load(std::memory_order_relaxed);
    auto commandPayload = BuildCommandPayload(input);
    WireFrame queryFrame = BuildEncryptedCommandFrame(
        MessageType::QueryStatus,
        session.nextSequence++,
        commandPayload,
        std::span<const uint8_t>(session.sessionKey.data(), session.sessionKey.size()),
        session.nextNonce++,
        result);
    if (queryFrame.payload.empty()) {
        session.pipe.Close();
        return false;
    }

    const ServiceCommStatisticsSnapshot before = SnapshotStats();
    if (!SendFrame(session.pipe.h, queryFrame)) {
        RecordValidationIssue(result, "Failed to send authenticated encrypted IPC command.");
        session.pipe.Close();
        return false;
    }

    const auto response = TryReadFrame(session.pipe.h, kIoTimeoutMs);
    PauseForServer();
    const ServiceCommStatisticsSnapshot after = SnapshotStats();

    if (callbacks->totalCalls.load(std::memory_order_relaxed) <= callbackCountBefore) {
        RecordValidationIssue(result, "Authenticated encrypted IPC command did not reach the command callback.");
        reachedDeepPath = false;
    }

    if (!response.has_value()) {
        RecordValidationIssue(result, "Authenticated encrypted IPC command produced no response frame.");
        reachedDeepPath = false;
    } else if (response->header.responseTo != queryFrame.header.sequence) {
        RecordValidationIssue(result, "IPC responseTo did not reference the encrypted command sequence.");
        reachedDeepPath = false;
    }

    if (!StatsAdvanced(before, after)) {
        RecordValidationIssue(result, "Authenticated encrypted IPC command did not advance server statistics.");
        reachedDeepPath = false;
    }

    const uint32_t callbackCountAfterValid = callbacks->totalCalls.load(std::memory_order_relaxed);
    if (!SendFrame(session.pipe.h, queryFrame)) {
        RecordValidationIssue(result, "Failed to replay the encrypted IPC frame.");
        reachedDeepPath = false;
    }
    PauseForServer();
    if (callbacks->totalCalls.load(std::memory_order_relaxed) != callbackCountAfterValid) {
        RecordAnomaly(result, "Replay of an encrypted IPC frame reached command dispatch.");
        reachedDeepPath = false;
    }

    WireFrame tamperedFrame = BuildEncryptedCommandFrame(
        MessageType::QueryStatus,
        session.nextSequence++,
        commandPayload,
        std::span<const uint8_t>(session.sessionKey.data(), session.sessionKey.size()),
        session.nextNonce++,
        result);
    if (!tamperedFrame.payload.empty()) {
        tamperedFrame.payload.back() ^= 0x5AU;
        if (!SendFrame(session.pipe.h, tamperedFrame)) {
            RecordValidationIssue(result, "Failed to send tampered-HMAC encrypted IPC frame.");
            reachedDeepPath = false;
        }
        PauseForServer();
        if (callbacks->totalCalls.load(std::memory_order_relaxed) != callbackCountAfterValid) {
            RecordAnomaly(result, "Tampered-HMAC encrypted IPC frame reached command dispatch.");
            reachedDeepPath = false;
        }
    }

    auto& crypto = SSCrypto::CryptoManager::Instance();
    crypto.SecureZero(session.sessionKey.data(), session.sessionKey.size());
    session.pipe.Close();
    PauseForServer();
    return reachedDeepPath;
}

bool WriteSeedFile(const std::filesystem::path& path, std::span<const uint8_t> bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        return false;
    }

    if (!bytes.empty()) {
        output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }

    return output.good();
}

std::optional<std::vector<uint8_t>> ReadFileBytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return std::nullopt;
    }

    input.seekg(0, std::ios::end);
    const auto end = input.tellg();
    if (end < 0) {
        return std::nullopt;
    }

    std::vector<uint8_t> bytes(static_cast<size_t>(end));
    input.seekg(0, std::ios::beg);
    if (!bytes.empty()) {
        input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!input) {
            return std::nullopt;
        }
    }

    return bytes;
}

void EnsureSeedFilePresent(
    const std::filesystem::path& path,
    std::span<const uint8_t> bytes) {
    std::error_code ec;
    if (std::filesystem::is_regular_file(path, ec)) {
        return;
    }

    (void)WriteSeedFile(path, bytes);
}

void EnsureSeedCorpus(const std::filesystem::path& corpusDir) {
    const std::array<uint8_t, 16> authenticatedSeed{
        kAuthenticatedScenarioTag, 'a', 'u', 't', 'h', '-', 'i', 'p',
        'c', 0x01, 0x02, 0x03, 0x10, 0x20, 0x30, 0x40
    };
    EnsureSeedFilePresent(
        corpusDir / "seed-authenticated-lane.bin",
        std::span<const uint8_t>(authenticatedSeed.data(), authenticatedSeed.size()));

    const HandshakeMessage handshake = BuildHandshakeMessage({}, 1, ServiceConst::PROTOCOL_VERSION);
    const auto handshakeBytes = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(&handshake),
        sizeof(handshake));
    EnsureSeedFilePresent(corpusDir / "seed-handshake.bin", handshakeBytes);

    const HandshakeMessage versionSkewHandshake = BuildHandshakeMessage({}, 2, 0xDEAD0001U);
    const auto versionSkewBytes = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(&versionSkewHandshake),
        sizeof(versionSkewHandshake));
    EnsureSeedFilePresent(corpusDir / "seed-handshake-version-skew.bin", versionSkewBytes);

    const WireFrame command = BuildPlaintextFrame(
        MessageType::CmdSetConfig,
        3,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>("{\"mode\":\"off\"}"), 14));
    std::vector<uint8_t> commandBytes(sizeof(command.header) + command.payload.size());
    std::memcpy(commandBytes.data(), &command.header, sizeof(command.header));
    if (!command.payload.empty()) {
        std::memcpy(commandBytes.data() + sizeof(command.header), command.payload.data(), command.payload.size());
    }
    EnsureSeedFilePresent(
        corpusDir / "seed-preauth-cmdsetconfig.bin",
        std::span<const uint8_t>(commandBytes.data(), commandBytes.size()));

    HandshakeResponseMessage response{};
    response.header.magic = ServiceConst::PROTOCOL_MAGIC;
    response.header.version = ServiceConst::PROTOCOL_VERSION;
    response.header.type = MessageType::HandshakeResponse;
    response.header.sequence = 4;
    response.header.payloadLength = sizeof(HandshakeResponseMessage) - sizeof(MessageHeader);
    std::fill(std::begin(response.hmacResponse), std::end(response.hmacResponse), 0xA5U);
    const auto responsePayload = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(&response) + sizeof(MessageHeader),
        response.header.payloadLength);
    response.header.checksum = ComputeCrc32(responsePayload);
    const auto responseBytes = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(&response),
        sizeof(response));
    EnsureSeedFilePresent(corpusDir / "seed-out-of-order-response.bin", responseBytes);
}

}  // namespace

std::string IPCHarness::ExceptionCodeToString(unsigned long code) noexcept {
    return ExceptionCodeToStringInternal(static_cast<DWORD>(code));
}

bool IPCHarness::ExerciseIPCImpl(
    const uint8_t* data,
    size_t size,
    HarnessResult& result)
{
    if (TraceEnabled()) {
        static std::atomic<uint64_t> runCounter{0};
        const uint64_t runId = runCounter.fetch_add(1, std::memory_order_relaxed) + 1;
        std::cerr << "[IPCFuzzer][trace] ExerciseIPCImpl: start run=" << runId
                  << " size=" << size << '\n';
    }

    const auto startTime = std::chrono::high_resolution_clock::now();
    const std::span<const uint8_t> input =
        (data != nullptr && size != 0)
            ? std::span<const uint8_t>(data, size)
            : std::span<const uint8_t>{};

    EnsureCryptoReady(result);
    if (result.validationIssueCount != 0) {
        return false;
    }

    const auto pipeName = BuildPipeName(input);
    const auto callbacks = std::make_shared<CallbackState>();
    StartServer(pipeName, callbacks, result);
    if (!ServiceCommunication::Instance().IsRunning()) {
        return false;
    }

    const IPCScenario scenario = SelectScenario(input);
    bool reachedDeepPath = false;
    Trace(std::string("ExerciseIPCImpl: scenario=") + std::string(ScenarioName(scenario)));
    switch (scenario) {
    case IPCScenario::DirectWire:
        reachedDeepPath = ExerciseDirectWireMutation(pipeName, input, result);
        break;
    case IPCScenario::OversizedHeader:
        reachedDeepPath = ExerciseOversizedHeader(pipeName, result);
        break;
    case IPCScenario::TruncatedHandshake:
        reachedDeepPath = ExerciseTruncatedHandshake(pipeName, input, result);
        break;
    case IPCScenario::EncryptedWithoutKey:
        reachedDeepPath = ExerciseEncryptedWithoutKey(pipeName, input, result);
        break;
    case IPCScenario::PreAuthPrivileged:
        reachedDeepPath = ExercisePreAuthPrivilegedCommand(pipeName, input, callbacks, result);
        break;
    case IPCScenario::OutOfOrderHandshakeResponse:
        reachedDeepPath = ExerciseOutOfOrderHandshakeResponse(pipeName, input, callbacks, result);
        break;
    case IPCScenario::VersionSkewHandshake:
        reachedDeepPath = ExerciseVersionSkewHandshake(pipeName, input, result);
        break;
    case IPCScenario::AuthenticatedEncrypted:
        reachedDeepPath = ExerciseAuthenticatedEncryptedFlow(pipeName, input, callbacks, result);
        break;
    }
    Trace("ExerciseIPCImpl: stopping server");

    StopServer();

    const auto endTime = std::chrono::high_resolution_clock::now();
    result.parseTimeNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime).count());
    result.parsedOk = result.parsedOk || reachedDeepPath;
    return result.parsedOk;
}

unsigned long IPCHarness::SEHCallIPC(
    const uint8_t* data,
    size_t size,
    HarnessResult* pResult) noexcept
{
    DWORD exceptionCode = 0;
    __try {
        ExerciseIPCImpl(data, size, *pResult);
    }
    __except (exceptionCode = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
        if (exceptionCode == EXCEPTION_STACK_OVERFLOW) {
            if (_resetstkoflw() == 0) {
                TerminateProcess(GetCurrentProcess(), exceptionCode);
            }
        }

        if (exceptionCode == STATUS_HEAP_CORRUPTION) {
            TerminateProcess(GetCurrentProcess(), exceptionCode);
        }
    }

    return exceptionCode;
}

HarnessResult IPCHarness::Run(std::span<const uint8_t> input) noexcept {
    HarnessResult result{};

    try {
        const DWORD exceptionCode = SEHCallIPC(
            input.empty() ? nullptr : input.data(),
            input.size(),
            &result);
        if (exceptionCode != 0) {
            result.crashed = true;
            result.crashSignal = ExceptionCodeToString(exceptionCode);
        }
    } catch (const std::exception& ex) {
        result.crashed = true;
        result.crashSignal = "CPP_EXCEPTION";
        result.errorMessage = ex.what();
    } catch (...) {
        result.crashed = true;
        result.crashSignal = "CPP_UNKNOWN_EXCEPTION";
    }

    return result;
}

HarnessFunction IPCHarness::GetHarnessFunction() noexcept {
    return [](std::span<const uint8_t> input) -> HarnessResult {
        return Run(input);
    };
}

std::string_view IPCHarness::GetName() noexcept {
    return "ipc";
}

std::string_view IPCHarness::GetDescription() noexcept {
    return "ServiceCommunication named-pipe protocol fuzz harness for hostile framing, auth, and encrypted command flows";
}

int RunIPCFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config) noexcept
{
    if (!InstallCtrlCHandler()) {
        std::cerr << "[IPCFuzzer] Warning: Failed to install Ctrl+C handler\n";
    }

    const auto corpusDir = workspaceDir / "corpora" / "ipc";
    const auto crashDir = workspaceDir / "crashes" / "ipc";

    std::error_code ec;
    std::filesystem::create_directories(corpusDir, ec);
    if (ec) {
        std::cerr << "[IPCFuzzer] Failed to create corpus directory: " << corpusDir << '\n';
        return 1;
    }

    ec.clear();
    std::filesystem::create_directories(crashDir, ec);
    if (ec) {
        std::cerr << "[IPCFuzzer] Failed to create crash directory: " << crashDir << '\n';
        return 1;
    }

    EnsureSeedCorpus(corpusDir);
    const auto sanitySeed = ReadFileBytes(corpusDir / "seed-preauth-cmdsetconfig.bin");
    if (!sanitySeed.has_value()) {
        std::cerr << "[IPCFuzzer] Failed to read IPC sanity seed\n";
        return 1;
    }

    const HarnessResult sanityResult = IPCHarness::Run(*sanitySeed);
    if (sanityResult.crashed || !sanityResult.parsedOk) {
        std::cerr << "[IPCFuzzer] IPC sanity check failed";
        if (!sanityResult.errorMessage.empty()) {
            std::cerr << ": " << sanityResult.errorMessage;
        }
        if (!sanityResult.crashSignal.empty()) {
            std::cerr << " (" << sanityResult.crashSignal << ')';
        }
        std::cerr << '\n';
        return 1;
    }

    FuzzLoopConfig loopConfig = config;
    loopConfig.targetName = std::string(IPCHarness::GetName());

    std::cout << "[IPCFuzzer] Starting IPC fuzzing...\n";
    std::cout << "[IPCFuzzer] Corpus: " << corpusDir << '\n';
    std::cout << "[IPCFuzzer] Crashes: " << crashDir << '\n';

    FuzzLoop loop(corpusDir, crashDir, IPCHarness::GetHarnessFunction(), loopConfig);
    const bool success = loop.Run();
    const auto& stats = loop.GetStatistics();

    std::cout << "\n[IPCFuzzer] Final Results:\n";
    std::cout << "  Total iterations: " << stats.totalIterations << '\n';
    std::cout << "  Unique crashes:   " << stats.uniqueCrashes << '\n';
    std::cout << "  Total crashes:    " << stats.crashesFound << '\n';
    std::cout << "  Final corpus:     " << stats.corpusSize << '\n';
    std::cout << "  Parse success:    " << stats.parseSuccesses << '\n';
    std::cout << "  Parse failure:    " << stats.parseFailures << '\n';
    std::cout << "  Duration:         " << (stats.durationMs / 1000) << "s\n";
    std::cout << "  Speed:            " << std::fixed << std::setprecision(1)
              << stats.iterationsPerSecond << " iter/s\n";

    StopServer();
    return success ? 0 : 1;
}

}  // namespace ShadowStrike::Fuzzer
