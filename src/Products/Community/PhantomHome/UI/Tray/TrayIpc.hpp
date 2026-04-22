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
 * ShadowStrike NGAV - TRAY IPC HELPER
 * ============================================================================
 *
 * @file TrayIpc.hpp
 * @brief Lightweight, pure Win32 fire-and-forget IPC client for the system-tray
 *        process. Connects to the same named pipe as the Qt UI client but
 *        imposes no Qt dependency.
 *
 * Wire protocol cross-reference: UI\IPC\Messages.hpp (source of truth).
 * Header layout (all LE, 24 bytes total):
 *   Offset  0 — magic       (uint32): 0x53534156 ("SSAV")
 *   Offset  4 — version     (uint16): 1
 *   Offset  6 — reserved    (uint16): 0x0000
 *   Offset  8 — type        (uint32): CommandType numeric value
 *   Offset 12 — requestId   (uint64): 0 for fire-and-forget; non-zero for sync
 *   Offset 20 — payloadSize (uint32): byte length of UTF-8 JSON payload
 *   Offset 24 — payload     (payloadSize bytes): UTF-8 JSON
 *
 * Thread safety:
 *   All public methods are thread-safe. A single std::mutex guards the pipe
 *   handle. Reconnection on ERROR_BROKEN_PIPE is attempted once per call;
 *   if it fails, the handle is set to INVALID_HANDLE_VALUE and methods return
 *   gracefully with cached state.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>

namespace ShadowStrike::PhantomHome::Tray::IPC {

// ============================================================================
// TrayState
//   Snapshot of service health queried by TrayIpc::GetState().
//   Distinct from TrayApp::TrayState (enum for icon selection).
// ============================================================================

struct TrayState {
    enum class Health : std::uint8_t {
        Healthy  = 0,
        AtRisk   = 1,
        Critical = 2,
        Unknown  = 3,
    };

    Health        health               = Health::Unknown;
    std::uint8_t  globalMode           = 0;  ///< ProtectionMode numeric value
    bool          paused               = false;
    std::uint32_t pausedMinutesRemaining = 0;
};

// ============================================================================
// TrayIpc
//   Meyers' singleton. Provides best-effort, fire-and-forget IPC verbs.
//   Callers must not hold the singleton reference across long operations;
//   each method acquires the internal mutex for its duration only.
// ============================================================================

class [[nodiscard]] TrayIpc final {
public:
    TrayIpc(const TrayIpc&)            = delete;
    TrayIpc& operator=(const TrayIpc&) = delete;
    TrayIpc(TrayIpc&&)                 = delete;
    TrayIpc& operator=(TrayIpc&&)      = delete;

    // Returns the process-singleton instance.
    [[nodiscard]] static TrayIpc& Instance() noexcept;

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    /**
     * @brief Open the named pipe and perform the AuthHandshake.
     *
     * Safe to call multiple times (idempotent if already open).
     * @return true if the pipe is open and authenticated after this call.
     */
    [[nodiscard]] bool Open() noexcept;

    /**
     * @brief Close the named pipe handle.
     *
     * Safe to call even if the pipe is not open.
     */
    void Close() noexcept;

    // -------------------------------------------------------------------------
    // Fire-and-forget commands
    // -------------------------------------------------------------------------

    /**
     * @brief Send SetGlobalMode to the service.
     *
     * Routes as UpdateConfig (CommandType = 30) with payload {"globalMode": mode}.
     * @param mode  ProtectionMode numeric value.
     */
    void SetGlobalMode(int mode) noexcept;

    /**
     * @brief Temporarily suspend real-time protection.
     *
     * Routes as PauseProtection (CommandType = 210) with {"minutes": minutes}.
     * @param minutes  Duration; 0 means indefinite.
     */
    void PauseProtection(int minutes) noexcept;

    /**
     * @brief Resume real-time protection.
     *
     * Routes as ResumeProtection (CommandType = 211).
     */
    void ResumeProtection() noexcept;

    /**
     * @brief Start a fast (quick) scan.
     *
     * Routes as StartScan (CommandType = 20) with {"scope":"fast"}.
     */
    void StartFastScan() noexcept;

    // -------------------------------------------------------------------------
    // Synchronous state query
    // -------------------------------------------------------------------------

    /**
     * @brief Query current service state into @p out.
     *
     * Sends GetStatus (CommandType = 10) and awaits a response with a 500 ms
     * timeout. On timeout, disconnection, or any error, @p out retains its
     * last successfully populated values (or defaults on first call).
     *
     * @param out  Receives the latest state on success.
     * @return     true if the response was received and parsed successfully.
     */
    [[nodiscard]] bool GetState(TrayState& out) noexcept;

private:
    TrayIpc() noexcept;
    ~TrayIpc() noexcept;

    // ---- Wire helpers -------------------------------------------------------

    /**
     * @brief Write a complete wire frame to the pipe.
     *
     * Serialises the 24-byte header + JSON payload and writes synchronously.
     * Caller must hold m_mutex.
     *
     * @param commandType  CommandType numeric value (NOT the enum; avoids
     *                     depending on ServiceCommunicator.hpp from this TU).
     * @param requestId    0 for fire-and-forget; non-zero for correlated reply.
     * @param jsonPayload  UTF-8 JSON string (must be pre-validated by caller).
     * @return true on success.
     */
    [[nodiscard]] bool WriteFrame(std::uint32_t commandType,
                                  std::uint64_t requestId,
                                  const std::string& jsonPayload) noexcept;

    /**
     * @brief Read one complete wire frame from the pipe (blocking).
     *
     * Enforces @p timeoutMs via overlapped I/O + WaitForSingleObject.
     * Caller must hold m_mutex.
     *
     * @param timeoutMs     Read deadline in milliseconds.
     * @param payloadOut    Receives the JSON payload bytes on success.
     * @param typeOut       Receives the CommandType field from the header.
     * @param requestIdOut  Receives the requestId field from the header.
     * @return true if a complete, structurally valid frame was read.
     */
    [[nodiscard]] bool ReadFrame(DWORD timeoutMs,
                                  std::string&   payloadOut,
                                  std::uint32_t& typeOut,
                                  std::uint64_t& requestIdOut) noexcept;

    /**
     * @brief Perform the AuthHandshake exchange.
     *
     * Must be called immediately after CreateFileW succeeds.
     * Caller must hold m_mutex.
     * @return true if the service accepted the token.
     */
    [[nodiscard]] bool Authenticate() noexcept;

    /**
     * @brief Attempt to reconnect once after a broken-pipe error.
     *
     * Caller must hold m_mutex.
     * @return true if reconnection and re-authentication succeeded.
     */
    [[nodiscard]] bool Reconnect() noexcept;

    /**
     * @brief Connect the pipe handle (CreateFileW) without authenticating.
     *
     * Caller must hold m_mutex.
     * @return true on success.
     */
    [[nodiscard]] bool ConnectHandle() noexcept;

    // ---- State --------------------------------------------------------------

    std::mutex     m_mutex;
    HANDLE         m_pipe{ INVALID_HANDLE_VALUE };

    // Monotonically incrementing; never 0 (0 is reserved for fire-and-forget).
    std::atomic<std::uint64_t> m_nextRequestId{ 1 };

    // Last successfully retrieved state; returned on query failure.
    TrayState      m_lastState{};
};

} // namespace ShadowStrike::PhantomHome::Tray::IPC
