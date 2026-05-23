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
 * ShadowStrike NGAV - TRAY IPC HELPER IMPLEMENTATION
 * ============================================================================
 *
 * @file TrayIpc.cpp
 * @brief Pure Win32 IPC client for the tray process.
 *
 * Wire protocol cross-reference: UI\IPC\Messages.hpp (source of truth).
 *
 * CommandType values used (cross-referenced from
 * PhantomCore\Service\ServiceCommunicator.hpp, reproduced inline to avoid
 * pulling in that header's Logger.hpp dependency into the tray TU):
 *   AuthHandshake  = 199
 *   UpdateConfig   = 30   (SetGlobalMode → {"globalMode": <n>})
 *   PauseProtection= 210  ({"minutes": <n>})
 *   ResumeProtection=211
 *   StartScan      = 20   ({"scope":"fast"})
 *   GetStatus      = 10
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

// Windows headers before everything else.
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>

#include "TrayIpc.hpp"

// <format> MUST be included before Logger.hpp: Logger.hpp uses
// std::format_string<> without including <format> itself (see TrayApp.cpp note).
#include <format>
#include <PhantomCore/Utils/Logger.hpp>

// IpcAuthToken — header is pure C++; compiled into PhantomCoreLib.lib.
#include <PhantomCore/Service/IpcAuthToken.hpp>

// nlohmann/json — no Qt dependency; available via $(SolutionDir)include.
#include <nlohmann/json.hpp>

#include <cstring>
#include <vector>

namespace ShadowStrike::PhantomHome::Tray::IPC {

// ============================================================================
// Protocol constants (cross-reference: UI\IPC\Messages.hpp)
// ============================================================================

// Wire magic bytes: "SSAV" in ASCII, little-endian uint32.
static constexpr std::uint32_t kIpcMagic       = 0x53534156u;
static constexpr std::uint16_t kProtocolVersion = 1u;
static constexpr std::uint32_t kMaxPayloadBytes = 1u << 20;  // 1 MiB cap
static constexpr std::size_t   kHeaderSize      = 24u;

// CommandType values mirrored from ServiceCommunicator.hpp.
// Do NOT use the enum directly here — that header pulls in Logger.hpp with
// platform macro ordering assumptions incompatible with this TU.
static constexpr std::uint32_t kCmdAuthHandshake  = 199u;
static constexpr std::uint32_t kCmdGetStatus       = 10u;
static constexpr std::uint32_t kCmdStartScan       = 20u;
static constexpr std::uint32_t kCmdUpdateConfig    = 30u;
static constexpr std::uint32_t kCmdPauseProtection = 210u;
static constexpr std::uint32_t kCmdResumeProtection= 211u;

// Pipe name — must match CommunicationConstants::PIPE_NAME in
// ServiceCommunicator.hpp.
static constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\ShadowStrikeServicePipe";

// State-query timeout.
static constexpr DWORD kStateQueryTimeoutMs = 500u;

// Log category.
static constexpr wchar_t kLogCategory[] = L"TrayIpc";

// ============================================================================
// Wire serialization helpers (all fields little-endian)
// ============================================================================

// Writes a LE integer of arbitrary width into dst.
template<typename T>
static void WriteLE(std::uint8_t* dst, T val) noexcept {
    static_assert(std::is_unsigned_v<T>);
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        dst[i] = static_cast<std::uint8_t>(val & 0xFFu);
        val >>= 8u;
    }
}

// Reads a LE integer of arbitrary width from src.
template<typename T>
static T ReadLE(const std::uint8_t* src) noexcept {
    static_assert(std::is_unsigned_v<T>);
    T val = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        val |= static_cast<T>(src[i]) << (i * 8u);
    }
    return val;
}

/**
 * @brief Serialise one wire frame into a byte vector.
 *
 * Layout (24-byte header, all LE):
 *   [0 .. 3]  magic        uint32  0x53534156
 *   [4 .. 5]  version      uint16  1
 *   [6 .. 7]  reserved     uint16  0
 *   [8 .. 11] type         uint32  CommandType
 *   [12..19]  requestId    uint64
 *   [20..23]  payloadSize  uint32
 *   [24..]    payload      UTF-8 JSON
 */
[[nodiscard]] static std::vector<std::uint8_t>
SerializeFrame(std::uint32_t   commandType,
               std::uint64_t   requestId,
               const std::string& jsonPayload) noexcept
{
    const std::uint32_t payloadSize =
        static_cast<std::uint32_t>(jsonPayload.size());

    if (payloadSize > kMaxPayloadBytes) return {};

    std::vector<std::uint8_t> buf(kHeaderSize + payloadSize);
    std::uint8_t* h = buf.data();

    WriteLE<std::uint32_t>(h +  0, kIpcMagic);
    WriteLE<std::uint16_t>(h +  4, kProtocolVersion);
    WriteLE<std::uint16_t>(h +  6, 0u);                // reserved
    WriteLE<std::uint32_t>(h +  8, commandType);
    WriteLE<std::uint64_t>(h + 12, requestId);
    WriteLE<std::uint32_t>(h + 20, payloadSize);

    if (payloadSize > 0) {
        std::memcpy(h + kHeaderSize, jsonPayload.data(), payloadSize);
    }
    return buf;
}

// ============================================================================
// TrayIpc — implementation
// ============================================================================

TrayIpc& TrayIpc::Instance() noexcept {
    static TrayIpc instance;
    return instance;
}

TrayIpc::TrayIpc() noexcept = default;

TrayIpc::~TrayIpc() noexcept {
    Close();
}

// ---------------------------------------------------------------------------
// ConnectHandle — opens the named pipe (no auth).
// Caller must hold m_mutex.
// ---------------------------------------------------------------------------

[[nodiscard]] bool TrayIpc::ConnectHandle() noexcept {
    if (m_pipe != INVALID_HANDLE_VALUE) return true;

    HANDLE h = CreateFileW(
        kPipeName,
        GENERIC_READ | GENERIC_WRITE,
        0,               // no sharing
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        nullptr);

    if (h == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PIPE_BUSY) {
            SS_LOG_WARN(kLogCategory,
                L"CreateFileW('%ls') failed (GLE=%lu); service may not be running",
                kPipeName, err);
        }
        return false;
    }

    // Switch to message-read mode so ReadFile boundaries align with WriteFile.
    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(h, &mode, nullptr, nullptr)) {
        SS_LOG_WARN(kLogCategory,
            L"SetNamedPipeHandleState(PIPE_READMODE_MESSAGE) failed (GLE=%lu)",
            GetLastError());
        CloseHandle(h);
        return false;
    }

    m_pipe = h;
    return true;
}

// ---------------------------------------------------------------------------
// Authenticate — send AuthHandshake after pipe connect.
// Caller must hold m_mutex.
// ---------------------------------------------------------------------------

[[nodiscard]] bool TrayIpc::Authenticate() noexcept {
    const std::string token = ShadowStrike::Service::IpcAuthToken::ReadForCurrentSession();
    if (token.empty()) {
        SS_LOG_ERROR(kLogCategory,
            L"IpcAuthToken::ReadForCurrentSession() returned empty; cannot authenticate");
        return false;
    }

    nlohmann::json payload = nlohmann::json::object();
    payload["token"] = token;

    const std::string payloadStr = payload.dump();
    const std::uint64_t reqId   = m_nextRequestId.fetch_add(1u, std::memory_order_relaxed);

    if (!WriteFrame(kCmdAuthHandshake, reqId, payloadStr)) {
        SS_LOG_ERROR(kLogCategory, L"Failed to send AuthHandshake frame");
        return false;
    }

    // Read the AuthHandshake response (2 s timeout — generous for auth).
    std::string   respPayload;
    std::uint32_t respType     = 0;
    std::uint64_t respReqId    = 0;

    if (!ReadFrame(2000u, respPayload, respType, respReqId)) {
        SS_LOG_ERROR(kLogCategory, L"No AuthHandshake response within 2 s");
        return false;
    }

    // Validate: response requestId must match, and payload must have ok=true.
    if (respReqId != reqId) {
        SS_LOG_ERROR(kLogCategory,
            L"AuthHandshake response requestId mismatch (expected %llu, got %llu)",
            static_cast<unsigned long long>(reqId),
            static_cast<unsigned long long>(respReqId));
        return false;
    }

    try {
        const auto j = nlohmann::json::parse(respPayload);
        if (!j.value("ok", false)) {
            SS_LOG_ERROR(kLogCategory,
                L"AuthHandshake rejected by service: %hs",
                j.dump().c_str());
            return false;
        }
    } catch (const nlohmann::json::exception& ex) {
        SS_LOG_ERROR(kLogCategory,
            L"AuthHandshake response JSON parse error: %hs", ex.what());
        return false;
    }

    SS_LOG_INFO(kLogCategory, L"AuthHandshake succeeded");
    return true;
}

// ---------------------------------------------------------------------------
// Open
// ---------------------------------------------------------------------------

bool TrayIpc::Open() noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_pipe != INVALID_HANDLE_VALUE) return true;  // already open

    if (!ConnectHandle()) return false;
    if (!Authenticate()) {
        CloseHandle(m_pipe);
        m_pipe = INVALID_HANDLE_VALUE;
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Close
// ---------------------------------------------------------------------------

void TrayIpc::Close() noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(m_pipe);
        m_pipe = INVALID_HANDLE_VALUE;
    }
}

// ---------------------------------------------------------------------------
// Reconnect — called on ERROR_BROKEN_PIPE; best-effort once.
// Caller must hold m_mutex.
// ---------------------------------------------------------------------------

bool TrayIpc::Reconnect() noexcept {
    if (m_pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(m_pipe);
        m_pipe = INVALID_HANDLE_VALUE;
    }

    SS_LOG_INFO(kLogCategory, L"Attempting pipe reconnect after broken-pipe error");

    if (!ConnectHandle()) {
        SS_LOG_WARN(kLogCategory, L"Reconnect: pipe not available; caching Unknown state");
        return false;
    }
    if (!Authenticate()) {
        SS_LOG_WARN(kLogCategory, L"Reconnect: re-authentication failed; closing pipe");
        CloseHandle(m_pipe);
        m_pipe = INVALID_HANDLE_VALUE;
        return false;
    }

    SS_LOG_INFO(kLogCategory, L"Reconnect succeeded");
    return true;
}

// ---------------------------------------------------------------------------
// WriteFrame — overlapped synchronous write.
// Caller must hold m_mutex.
// ---------------------------------------------------------------------------

bool TrayIpc::WriteFrame(std::uint32_t commandType,
                          std::uint64_t requestId,
                          const std::string& jsonPayload) noexcept
{
    if (m_pipe == INVALID_HANDLE_VALUE) return false;

    const auto buf = SerializeFrame(commandType, requestId, jsonPayload);
    if (buf.empty()) {
        SS_LOG_ERROR(kLogCategory,
            L"WriteFrame: serialisation failed (payload too large?)");
        return false;
    }

    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent) {
        SS_LOG_LAST_ERROR(kLogCategory, L"WriteFrame: CreateEventW failed");
        return false;
    }

    DWORD written = 0;
    BOOL ok = WriteFile(m_pipe,
                        buf.data(),
                        static_cast<DWORD>(buf.size()),
                        &written,
                        &ov);

    if (!ok) {
        const DWORD err = GetLastError();
        if (err == ERROR_IO_PENDING) {
            // Wait up to 2 s for the write to complete.
            const DWORD waitResult = WaitForSingleObject(ov.hEvent, 2000u);
            if (waitResult == WAIT_OBJECT_0) {
                ok = GetOverlappedResult(m_pipe, &ov, &written, FALSE);
            } else {
                SS_LOG_WARN(kLogCategory,
                    L"WriteFrame: write timed out (waitResult=%lu)", waitResult);
                CancelIo(m_pipe);
            }
        } else if (err == ERROR_BROKEN_PIPE || err == ERROR_NO_DATA) {
            CloseHandle(ov.hEvent);
            // Signal broken pipe to caller for reconnect handling.
            SetLastError(ERROR_BROKEN_PIPE);
            return false;
        } else {
            SS_LOG_WARN(kLogCategory,
                L"WriteFrame: WriteFile failed (GLE=%lu)", err);
            CloseHandle(ov.hEvent);
            return false;
        }
    }

    CloseHandle(ov.hEvent);

    if (!ok || written != static_cast<DWORD>(buf.size())) {
        SS_LOG_WARN(kLogCategory,
            L"WriteFrame: incomplete write (%lu of %zu bytes)",
            written, buf.size());
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// ReadFrame — overlapped read with explicit timeout.
// Caller must hold m_mutex.
// ---------------------------------------------------------------------------

bool TrayIpc::ReadFrame(DWORD          timeoutMs,
                         std::string&   payloadOut,
                         std::uint32_t& typeOut,
                         std::uint64_t& requestIdOut) noexcept
{
    if (m_pipe == INVALID_HANDLE_VALUE) return false;

    // Read the fixed-size header first.
    std::uint8_t header[kHeaderSize]{};
    DWORD        bytesRead = 0;

    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent) {
        SS_LOG_LAST_ERROR(kLogCategory, L"ReadFrame: CreateEventW failed");
        return false;
    }

    auto guardEvent = [&]() noexcept { CloseHandle(ov.hEvent); };

    BOOL ok = ReadFile(m_pipe, header, kHeaderSize, &bytesRead, &ov);
    if (!ok) {
        const DWORD err = GetLastError();
        if (err == ERROR_IO_PENDING) {
            const DWORD waitResult = WaitForSingleObject(ov.hEvent, timeoutMs);
            if (waitResult != WAIT_OBJECT_0) {
                CancelIo(m_pipe);
                guardEvent();
                return false;
            }
            ok = GetOverlappedResult(m_pipe, &ov, &bytesRead, FALSE);
        } else {
            guardEvent();
            return false;
        }
    }

    if (!ok || bytesRead != kHeaderSize) {
        guardEvent();
        return false;
    }

    // Validate magic and version.
    const std::uint32_t magic = ReadLE<std::uint32_t>(header + 0);
    if (magic != kIpcMagic) {
        SS_LOG_ERROR(kLogCategory,
            L"ReadFrame: invalid magic 0x%08X (expected 0x%08X)",
            magic, kIpcMagic);
        guardEvent();
        return false;
    }

    // Decode header fields.
    typeOut      = ReadLE<std::uint32_t>(header +  8);
    requestIdOut = ReadLE<std::uint64_t>(header + 12);
    const std::uint32_t payloadSize = ReadLE<std::uint32_t>(header + 20);

    if (payloadSize > kMaxPayloadBytes) {
        SS_LOG_ERROR(kLogCategory,
            L"ReadFrame: payload size %lu exceeds cap %lu; dropping frame",
            payloadSize, kMaxPayloadBytes);
        guardEvent();
        return false;
    }

    // Read payload if present.
    payloadOut.clear();
    if (payloadSize > 0) {
        payloadOut.resize(payloadSize);

        ResetEvent(ov.hEvent);
        DWORD payloadRead = 0;
        ok = ReadFile(m_pipe,
                      payloadOut.data(),
                      payloadSize,
                      &payloadRead,
                      &ov);

        if (!ok) {
            const DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                const DWORD waitResult = WaitForSingleObject(ov.hEvent, timeoutMs);
                if (waitResult != WAIT_OBJECT_0) {
                    CancelIo(m_pipe);
                    guardEvent();
                    return false;
                }
                ok = GetOverlappedResult(m_pipe, &ov, &payloadRead, FALSE);
            } else {
                guardEvent();
                return false;
            }
        }

        if (!ok || payloadRead != payloadSize) {
            guardEvent();
            return false;
        }
    }

    guardEvent();
    return true;
}

// ---------------------------------------------------------------------------
// SendAndForget — helper to send a command with requestId = 0.
// Caller must hold m_mutex.
// ---------------------------------------------------------------------------

static bool SendAndForgetInternal(TrayIpc& ipc,
                                   std::uint32_t cmd,
                                   const std::string& json) noexcept;

// We need to call WriteFrame from a free function — use a lambda trick.
// Actually just replicate the send inside each method; the pattern is simple.

// ---------------------------------------------------------------------------
// SetGlobalMode
// ---------------------------------------------------------------------------

void TrayIpc::SetGlobalMode(int mode) noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);

    nlohmann::json payload = nlohmann::json::object();
    payload["globalMode"] = mode;
    const std::string json = payload.dump();

    if (!WriteFrame(kCmdUpdateConfig, 0u, json)) {
        if (GetLastError() == ERROR_BROKEN_PIPE) {
            if (Reconnect()) (void)WriteFrame(kCmdUpdateConfig, 0u, json);
        }
    }
}

// ---------------------------------------------------------------------------
// PauseProtection
// ---------------------------------------------------------------------------

void TrayIpc::PauseProtection(int minutes) noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);

    nlohmann::json payload = nlohmann::json::object();
    payload["minutes"] = minutes;
    const std::string json = payload.dump();

    if (!WriteFrame(kCmdPauseProtection, 0u, json)) {
        if (GetLastError() == ERROR_BROKEN_PIPE) {
            if (Reconnect()) (void)WriteFrame(kCmdPauseProtection, 0u, json);
        }
    }
}

// ---------------------------------------------------------------------------
// ResumeProtection
// ---------------------------------------------------------------------------

void TrayIpc::ResumeProtection() noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);

    const std::string json = "{}";
    if (!WriteFrame(kCmdResumeProtection, 0u, json)) {
        if (GetLastError() == ERROR_BROKEN_PIPE) {
            if (Reconnect()) (void)WriteFrame(kCmdResumeProtection, 0u, json);
        }
    }
}

// ---------------------------------------------------------------------------
// StartFastScan
// ---------------------------------------------------------------------------

void TrayIpc::StartFastScan() noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);

    nlohmann::json payload = nlohmann::json::object();
    payload["scope"] = "fast";
    const std::string json = payload.dump();

    if (!WriteFrame(kCmdStartScan, 0u, json)) {
        if (GetLastError() == ERROR_BROKEN_PIPE) {
            if (Reconnect()) (void)WriteFrame(kCmdStartScan, 0u, json);
        }
    }
}

// ---------------------------------------------------------------------------
// GetState — synchronous, 500 ms timeout.
// ---------------------------------------------------------------------------

bool TrayIpc::GetState(TrayState& out) noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);

    // Ensure connected.
    if (m_pipe == INVALID_HANDLE_VALUE) {
        if (!ConnectHandle() || !Authenticate()) {
            out = m_lastState;
            return false;
        }
    }

    const std::uint64_t reqId = m_nextRequestId.fetch_add(1u, std::memory_order_relaxed);
    const std::string   json  = "{}";

    auto sendQuery = [&]() -> bool {
        if (!WriteFrame(kCmdGetStatus, reqId, json)) {
            if (GetLastError() == ERROR_BROKEN_PIPE) {
                if (!Reconnect()) return false;
                // Re-issue with a fresh requestId after reconnect.
                return WriteFrame(kCmdGetStatus, reqId, json);
            }
            return false;
        }
        return true;
    };

    if (!sendQuery()) {
        SS_LOG_WARN(kLogCategory, L"GetState: failed to send GetStatus request");
        out = m_lastState;
        return false;
    }

    // Read response — must correlate to our reqId within timeout.
    for (int attempt = 0; attempt < 4; ++attempt) {
        std::string   payload;
        std::uint32_t type   = 0;
        std::uint64_t rspId  = 0;

        if (!ReadFrame(kStateQueryTimeoutMs, payload, type, rspId)) {
            SS_LOG_WARN(kLogCategory,
                L"GetState: ReadFrame failed or timed out (attempt %d)", attempt + 1);
            break;
        }

        // Discard frames not correlated to our query.
        if (rspId != reqId) continue;

        // Parse response payload.
        try {
            const auto j = nlohmann::json::parse(payload);

            if (!j.value("ok", false)) {
                SS_LOG_WARN(kLogCategory,
                    L"GetState: service returned error: %hs", j.dump().c_str());
                out = m_lastState;
                return false;
            }

            // Expected payload shape:
            // { "ok": true, "health": "healthy"|"atRisk"|"critical",
            //   "globalMode": <int>, "paused": <bool>,
            //   "pausedSecondsRemaining": <int> }

            const auto healthStr = j.value("health", std::string("unknown"));
            if      (healthStr == "healthy")  m_lastState.health = TrayState::Health::Healthy;
            else if (healthStr == "atRisk")   m_lastState.health = TrayState::Health::AtRisk;
            else if (healthStr == "critical") m_lastState.health = TrayState::Health::Critical;
            else                              m_lastState.health = TrayState::Health::Unknown;

            m_lastState.globalMode            = static_cast<std::uint8_t>(
                                                    j.value("globalMode", 0));
            m_lastState.paused                = j.value("paused", false);
            const std::uint32_t pausedSeconds = static_cast<std::uint32_t>(
                j.value("pausedSecondsRemaining", j.value("pausedRemainingSec", 0)));
            m_lastState.pausedMinutesRemaining = static_cast<std::uint32_t>(
                (pausedSeconds + 59u) / 60u);

            out = m_lastState;
            return true;

        } catch (const nlohmann::json::exception& ex) {
            SS_LOG_ERROR(kLogCategory,
                L"GetState: JSON parse error: %hs", ex.what());
            break;
        }
    }

    out = m_lastState;
    return false;
}

} // namespace ShadowStrike::PhantomHome::Tray::IPC
