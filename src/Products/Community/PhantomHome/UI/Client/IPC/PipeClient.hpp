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
 * ShadowStrike NGAV - PHANTOM HOME UI IPC PIPE CLIENT
 * ============================================================================
 *
 * @file PipeClient.hpp
 * @brief Asynchronous named-pipe client that connects the PhantomHome UI to
 *        the privileged ShadowStrike service via the secure IPC pipe.
 *
 * ARCHITECTURE
 * ------------
 * A single dedicated std::jthread owns all pipe I/O using overlapped (async)
 * ReadFile / WriteFile. Callbacks are always marshalled to the Qt main thread
 * via QMetaObject::invokeMethod(qApp, ..., Qt::QueuedConnection), so QML
 * bindings and signal handlers are always invoked on the right thread.
 *
 * State machine
 * -------------
 *   Disconnected → Connecting → Authenticating → Connected
 *                                                    ↓
 *                             Reconnecting ← (connection loss)
 *                                 ↓
 *                            (backoff) → Connecting
 *   Fatal — terminal state; requires process restart to recover.
 *
 * Thread safety
 * -------------
 * • State:          std::shared_mutex (readers concurrent, writer exclusive)
 * • Pending map:    std::mutex
 * • Outbound queue: std::mutex + HANDLE auto-reset event (queue-not-empty signal)
 * • Subscriptions:  std::mutex
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * ============================================================================
 */

#pragma once

// Qt headers — must be included before any Windows.h re-inclusion.
#include <QObject>
#include <QJsonObject>

// Standard library
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>

// ShadowStrike infrastructure — CommandType is defined here.
#include <PhantomCore/Service/ServiceCommunicator.hpp>

namespace ShadowStrike::PhantomHome::UI::IPC {

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Observable connection state of the PipeClient.
 *
 * Exposed as a Q_PROPERTY so QML components can bind to it directly.
 * The underlying int value is stable across releases.
 */
enum class PipeClientState : int {
    Disconnected   = 0,  ///< No pipe handle open, not attempting to connect.
    Connecting     = 1,  ///< CreateFileW in progress; pipe may not be available yet.
    Authenticating = 2,  ///< Pipe connected; AuthHandshake exchange in progress.
    Connected      = 3,  ///< Authenticated; normal operation.
    Reconnecting   = 4,  ///< Connection was lost; pending exponential-backoff retry.
    Fatal          = 5,  ///< Unrecoverable — auth rejected or token unavailable.
};

// ============================================================================
// RESPONSE TYPES
// ============================================================================

/**
 * @brief Structured result of a SendAndExpect call.
 *
 * On timeout, disconnection, or backpressure, ok is false and errorCode
 * carries a machine-readable token:
 *   "timeout"      — no response within the requested window.
 *   "disconnected" — pipe was lost before the response arrived.
 *   "stopped"      — PipeClient::Stop() was called.
 *   "backpressure" — pending map / outbound queue is at capacity.
 */
struct Response {
    bool        ok           = false;
    QString     errorCode;
    QString     errorMessage;
    QJsonObject payload;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/** Invoked on the Qt main thread when a response or synthetic error arrives. */
using ResponseCallback = std::function<void(const Response&)>;

/** Invoked on the Qt main thread for each matching push-event envelope. */
using EventCallback    = std::function<void(const QJsonObject&)>;

// ============================================================================
// PIPE CLIENT
// ============================================================================

/**
 * @class PipeClient
 * @brief Meyers-singleton QObject that owns the service-side pipe connection.
 *
 * Usage:
 * @code
 *   PipeClient& client = PipeClient::Instance();
 *   if (client.Start()) {
 *       client.Subscribe(CommandType::ProtectionStateChanged, [](const QJsonObject& ev) {
 *           // handle push event
 *       });
 *       auto reqId = client.SendAndExpect(CommandType::GetStatus, {}, [](const Response& r) {
 *           if (r.ok) { ... }
 *       });
 *   }
 * @endcode
 *
 * Thread safety: all public methods are thread-safe. Callbacks always arrive
 * on the Qt main thread.
 */
class PipeClient final : public QObject {
    Q_OBJECT

    // QML-accessible properties.
    Q_PROPERTY(int  state     READ stateRaw    NOTIFY stateChanged)
    Q_PROPERTY(bool connected READ isConnected NOTIFY stateChanged)

public:
    // ========================================================================
    // SINGLETON
    // ========================================================================

    /**
     * @brief Meyers' singleton accessor.
     *
     * @warning Must first be called from the Qt main thread.
     *          The singleton is destroyed at program exit; Stop() is called
     *          automatically in the destructor.
     */
    [[nodiscard]] static PipeClient& Instance();

    PipeClient(const PipeClient&)            = delete;
    PipeClient& operator=(const PipeClient&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    /**
     * @brief Start the I/O thread and begin connecting to the service pipe.
     *
     * Idempotent — calling Start() while already running is a no-op.
     *
     * @return true  if the I/O thread was launched successfully.
     * @return false if internal event creation failed (system resource
     *               exhaustion — extremely rare).
     */
    [[nodiscard]] bool Start();

    /**
     * @brief Stop the I/O thread, cancel all pending I/O, and resolve all
     *        in-flight requests with errorCode="stopped".
     *
     * Blocks until the I/O thread has exited. Safe to call from any thread.
     * After Stop(), the state transitions to Disconnected.
     */
    void Stop();

    // ========================================================================
    // STATE ACCESSORS
    // ========================================================================

    /** Q_PROPERTY READ for 'connected'. */
    [[nodiscard]] bool isConnected()  const noexcept;

    /** Public API alias — capitalised per ShadowStrike naming convention. */
    [[nodiscard]] bool IsConnected()  const noexcept;

    /** Q_PROPERTY READ for 'state'. Returns the raw int value of the enum. */
    [[nodiscard]] int  stateRaw()     const noexcept;

    [[nodiscard]] PipeClientState CurrentState() const noexcept;

    // ========================================================================
    // MESSAGING
    // ========================================================================

    /**
     * @brief Enqueue a fire-and-forget message (no response expected).
     *
     * The envelope is assigned requestId = 0 so the service does not send
     * back a response frame. If the outbound queue is at capacity (256 items),
     * the call is a no-op and a WARN is logged.
     *
     * Safe to call from any thread.
     */
    void Send(ShadowStrike::Service::CommandType t, const QJsonObject& p);

    /**
     * @brief Enqueue a message and register a callback for its response.
     *
     * @param t        Command type.
     * @param p        JSON payload.
     * @param onDone   Invoked on the Qt main thread with the service's
     *                 response, or with ok=false on timeout/disconnect/stop.
     * @param timeout  How long to wait before synthesising a timeout response.
     *
     * @return The request ID assigned to this message (non-zero on success).
     *         Returns 0 if the pending map or outbound queue is full
     *         (backpressure) — onDone is NOT called in that case; the caller
     *         receives a QMetaObject-posted synthetic Response{false,"backpressure"}.
     *
     * Safe to call from any thread.
     */
    [[nodiscard]] std::uint64_t SendAndExpect(
        ShadowStrike::Service::CommandType t,
        const QJsonObject&                 p,
        ResponseCallback                   onDone,
        std::chrono::milliseconds          timeout = std::chrono::milliseconds{5000});

    // ========================================================================
    // EVENT SUBSCRIPTIONS
    // ========================================================================

    /**
     * @brief Subscribe to a server-push event type.
     *
     * Subscriptions survive reconnects — they are stored independently of
     * the pipe handle. Multiple subscriptions for the same event type are
     * all invoked.
     *
     * @param eventType  The CommandType code in the push-event range (102–105).
     * @param cb         Callback invoked on the Qt main thread.
     * @return An opaque subscription token for use with Unsubscribe().
     */
    [[nodiscard]] std::uint64_t Subscribe(
        ShadowStrike::Service::CommandType eventType,
        EventCallback                      cb);

    /**
     * @brief Cancel a subscription previously created by Subscribe().
     *
     * No-op if the token is not recognised. Safe to call from any thread.
     */
    void Unsubscribe(std::uint64_t token);

signals:
    // ========================================================================
    // SIGNALS (marshalled to Qt main thread by the I/O thread)
    // ========================================================================

    /** Emitted whenever the PipeClientState changes. */
    void stateChanged();

    /**
     * @brief Emitted for every state transition with human-readable context.
     *
     * @param from    Previous PipeClientState cast to int.
     * @param to      New PipeClientState cast to int.
     * @param reason  Short English description of why the transition occurred.
     */
    void stateTransition(int from, int to, const QString& reason);

    /**
     * @brief Emitted when the service explicitly rejects authentication.
     *
     * After this signal the client enters the Fatal state and will not
     * attempt to reconnect. The UI should prompt the user to restart.
     */
    void authRejected(const QString& reason);

private:
    explicit PipeClient(QObject* parent = nullptr);
    ~PipeClient() override;

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace ShadowStrike::PhantomHome::UI::IPC
