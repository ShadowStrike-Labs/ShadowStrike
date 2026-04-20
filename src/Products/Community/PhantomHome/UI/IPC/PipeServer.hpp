/*
 * ShadowStrike - Enterprise NGAV Platform
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * Licensed under GNU AGPL-v3. See LICENSE.txt at the repository root.
 */

/**
 * @file PipeServer.hpp
 * @brief Service-side named-pipe server for PhantomHome UI IPC.
 *
 * - Named pipe: `\\.\pipe\ShadowStrike.Phantom.UI.<SessionId>`
 * - SDDL ACL: SYSTEM + Administrators + INTERACTIVE users (read/write)
 * - Overlapped I/O with a bounded worker-thread pool
 * - Framed protocol: [uint32 LE length][CBOR payload], length <= kMaxFrameBytes
 * - Graceful shutdown via dedicated stop event
 * - Per-connection correlation state held in ClientContext
 *
 * Threading model
 * ---------------
 *  Accept thread  : owns the listening pipe-instance handle, waits for
 *                   ConnectNamedPipe overlapped completion, hands off connected
 *                   pipes to worker threads, then creates the next instance.
 *  Worker threads : blocking framed reads; each inbound frame is delivered to
 *                   the user-supplied handler synchronously, replies are written
 *                   back before the next read. Push messages from the handler
 *                   go through PushToClient() which serializes writes per
 *                   connection.
 *
 * This header deliberately avoids any Qt/std::format_string that breaks the
 * service-only TU. Logging uses Utils::Logger narrow API.
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "Messages.hpp"

namespace ShadowStrike::PhantomHome::IPC {

class PipeServer;

/**
 * @brief Per-connection context passed to the message handler.
 */
class ClientContext {
public:
    ClientContext(PipeServer& server, HANDLE pipe, std::uint32_t client_pid);
    ~ClientContext();

    ClientContext(const ClientContext&) = delete;
    ClientContext& operator=(const ClientContext&) = delete;

    [[nodiscard]] std::uint32_t ClientProcessId() const noexcept { return client_pid_; }
    [[nodiscard]] bool          AuthenticatedPrivileged() const noexcept { return authenticated_privileged_.load(); }
    void                        SetAuthenticatedPrivileged(bool v) noexcept { authenticated_privileged_.store(v); }

    /**
     * @brief Send a server-push message (e.g. EventDetection, EventPerfMetrics).
     *        Serialized against any concurrent reply write on the same pipe.
     * @return true on success, false if the pipe has been disconnected or the
     *         frame exceeded kMaxFrameBytes.
     */
    [[nodiscard]] bool PushMessage(MessageType type, const nlohmann::json& payload);

    HANDLE PipeHandle() const noexcept { return pipe_; }

private:
    friend class PipeServer;

    PipeServer&               server_;
    HANDLE                    pipe_{INVALID_HANDLE_VALUE};
    std::uint32_t             client_pid_{0};
    std::atomic<bool>         authenticated_privileged_{false};
    std::mutex                write_mutex_;
};

/**
 * @brief Handler signature. Must either populate `reply_payload` (for request/reply
 *        messages) and set `reply_type`, or leave `reply_type == MessageType::Error`
 *        with `reply_payload` populated via ErrorPayload::ToJson().
 *
 * The handler runs on a worker thread. It MUST be thread-safe and MUST NOT block
 * indefinitely. Any exception is caught by the server and converted into an Error
 * reply with code Internal.
 */
using MessageHandler = std::function<void(ClientContext& ctx,
                                          const FrameEnvelope& request,
                                          MessageType& reply_type,
                                          nlohmann::json& reply_payload)>;

/**
 * @brief Named-pipe server. Construct, SetHandler, Start, Stop.
 */
class PipeServer {
public:
    struct Options {
        std::uint32_t session_id{0};                 // interactive session id (WTSGetActiveConsoleSessionId or current)
        std::uint32_t max_concurrent_connections{kMaxPipeInstances};
        std::uint32_t worker_threads{4};
        std::uint32_t read_timeout_ms{kPipeReadTimeoutMs};
        std::uint32_t write_timeout_ms{kPipeWriteTimeoutMs};
        std::wstring  sddl{std::wstring(kPipeSddl)};
    };

    explicit PipeServer(Options options);
    ~PipeServer();

    PipeServer(const PipeServer&) = delete;
    PipeServer& operator=(const PipeServer&) = delete;

    void SetHandler(MessageHandler handler);

    /// Start the accept + worker threads. Idempotent on already-running.
    [[nodiscard]] bool Start();

    /// Signal stop, close accept handle, wait for workers.
    void Stop() noexcept;

    /// Broadcast a push message to all currently connected clients. Best-effort.
    void Broadcast(MessageType type, const nlohmann::json& payload);

    [[nodiscard]] std::wstring PipeFullName() const;

    [[nodiscard]] bool IsRunning() const noexcept { return running_.load(); }

private:
    friend class ClientContext;

    void AcceptLoop();
    void WorkerLoop(std::shared_ptr<ClientContext> ctx);

    [[nodiscard]] HANDLE CreatePipeInstance(bool first);
    [[nodiscard]] bool   HandshakeFrame(ClientContext& ctx);
    [[nodiscard]] bool   ReadFrame(HANDLE pipe, std::vector<std::uint8_t>& out);
    [[nodiscard]] bool   WriteFrame(HANDLE pipe, std::mutex& m, std::span<const std::uint8_t> bytes);

    Options                                     options_;
    std::atomic<bool>                           running_{false};
    std::atomic<bool>                           stopping_{false};
    HANDLE                                      stop_event_{nullptr};
    std::thread                                 accept_thread_;
    std::mutex                                  clients_mutex_;
    std::vector<std::shared_ptr<ClientContext>> clients_;
    std::vector<std::thread>                    workers_;
    MessageHandler                              handler_;
    std::mutex                                  handler_mutex_;
};

}  // namespace ShadowStrike::PhantomHome::IPC
