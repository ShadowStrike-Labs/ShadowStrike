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
 * ShadowStrike NGAV - SESSION-SCOPED IPC AUTH TOKEN
 * ============================================================================
 *
 * @file IpcAuthToken.hpp
 * @brief Per-session cryptographic token used to authenticate pipe clients.
 *
 * OVERVIEW
 * --------
 * The ShadowStrike service generates a 32-byte cryptographically random nonce
 * (via BCryptGenRandom) per interactive session and writes it — base64-encoded
 * — to a per-user file:
 *
 *   <user LOCALAPPDATA>\ShadowStrike\ui.token
 *
 * A restrictive DACL on that file grants FILE_GENERIC_READ | FILE_GENERIC_WRITE
 * only to:
 *   • The owning session user's SID
 *   • LocalSystem (the service account)
 *
 * The UI client reads this token on startup and sends it as part of the
 * AuthHandshake command. The service verifies it via a constant-time comparison
 * against the in-memory cache.
 *
 * SECURITY PROPERTIES
 * -------------------
 * • Nonce source: BCryptGenRandom (BCRYPT_USE_SYSTEM_PREFERRED_RNG) — never rand().
 * • Constant-time comparison: manual volatile XOR reduction — no early exit.
 * • File ACL: PROTECTED_DACL, no inherited ACEs, explicit allow-list only.
 * • Token rotates on every service restart (EnsureForSession generates fresh).
 * • RtlSecureZeroMemory clears sensitive stack buffers before returning.
 *
 * THREAD SAFETY
 * -------------
 * All public members are thread-safe via a Meyers-singleton internal cache
 * protected by std::shared_mutex (readers concurrent, writer exclusive).
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace ShadowStrike::Service {

/**
 * @class IpcAuthToken
 * @brief Session-scoped IPC authentication token facility.
 *
 * All methods are static; there is no instance state visible to callers.
 * Internal state (per-session token cache) is held in a Meyers singleton
 * that is NOT exposed through this header.
 */
class [[nodiscard]] IpcAuthToken {
public:
    // =========================================================================
    // SERVICE-SIDE API
    // =========================================================================

    /**
     * @brief Ensure a valid auth token exists for the given Windows session.
     *
     * If no token has been issued yet for sessionId (or the cache is cold),
     * generates a fresh 32-byte nonce, base64-encodes it, writes it to:
     *   <session user LOCALAPPDATA>\ShadowStrike\ui.token
     * with a restrictive DACL, caches it in memory, and returns it.
     *
     * If the cache already holds a token for sessionId, returns the cached
     * value without touching the file system (idempotent within a service
     * lifetime).
     *
     * @param sessionId  Windows logon session ID (from WTSGetActiveConsoleSessionId
     *                   or WTSEnumerateSessions).
     * @return Base64-encoded 32-byte token string on success, or an empty string
     *         if the session has no interactive user, BCryptGenRandom fails,
     *         or the file cannot be written / secured.
     *
     * @note Requires SE_TCB_PRIVILEGE to call WTSQueryUserToken.
     * @note NOT noexcept — may allocate; callers must handle empty return.
     */
    [[nodiscard]] static std::string EnsureForSession(std::uint32_t sessionId);

    /**
     * @brief Request provisioning for a session WITHOUT blocking the caller.
     *
     * Exists because EnsureForSession is not safe to call from every thread.
     * It performs WTSQueryUserToken, resolves the user's profile path and
     * writes the token file, holding the cache lock throughout. That write
     * passes through our own minifilter, so the kernel asks user mode for a
     * verdict on it - and if the calling thread is one that services verdicts
     * or IPC, it is now blocked on a reply only it could have produced. The
     * observable result was a system-wide stall for the whole scan deadline,
     * repeating every time the UI retried its handshake.
     *
     * This entry point hands the work to a detached thread where blocking is
     * harmless, and returns immediately. Calls are de-duplicated per session:
     * the UI retries its handshake on a timer, so an un-guarded version would
     * spawn a thread per attempt and each would contend for the same lock.
     *
     * Fire-and-forget by design. Callers should report "not ready, retry" to
     * their client rather than waiting on the result.
     *
     * @param sessionId  Windows logon session ID. Session 0 and 0xFFFFFFFF are
     *                   ignored: they are non-interactive and have no profile.
     */
    static void RequestProvisionAsync(std::uint32_t sessionId) noexcept;

    /**
     * @brief Verify a client-supplied auth token for the given session.
     *
     * Compares tokenBase64 against the cached token for sessionId using a
     * constant-time byte-by-byte comparison (volatile XOR reduction) to
     * resist timing attacks.
     *
     * @param sessionId    Windows logon session ID of the connecting client
     *                     (derived from ImpersonateNamedPipeClient +
     *                     GetTokenInformation on the pipe thread).
     * @param tokenBase64  Token string received from the client.
     * @return true if and only if the token matches the cached value for the
     *         session; false on any mismatch, empty input, or unknown session.
     *
     * @note noexcept — safe to call from pipe-read worker threads.
     */
    [[nodiscard]] static bool Verify(std::uint32_t   sessionId,
                                     std::string_view tokenBase64) noexcept;

    // =========================================================================
    // CLIENT-SIDE API
    // =========================================================================

    /**
     * @brief Read the auth token for the current user session from disk.
     *
     * Uses SHGetKnownFolderPath(FOLDERID_LocalAppData) to locate the token
     * file for the CURRENT user (nullptr hToken → current process user), then
     * reads and returns its content.
     *
     * @return Base64-encoded token string, or an empty string if the file does
     *         not exist, is empty, or cannot be read.
     *
     * @note Called from the UI process (un-elevated user context).
     */
    [[nodiscard]] static std::string ReadForCurrentSession();

    // =========================================================================
    // NON-COPYABLE / NON-MOVABLE
    // =========================================================================
    IpcAuthToken()                               = delete;
    ~IpcAuthToken()                              = delete;
    IpcAuthToken(const IpcAuthToken&)            = delete;
    IpcAuthToken& operator=(const IpcAuthToken&) = delete;
    IpcAuthToken(IpcAuthToken&&)                 = delete;
    IpcAuthToken& operator=(IpcAuthToken&&)      = delete;
};

} // namespace ShadowStrike::Service
