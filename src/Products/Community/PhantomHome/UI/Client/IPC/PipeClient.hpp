/*
 * ShadowStrike - Enterprise NGAV Platform
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * Licensed under GNU AGPL-v3. See LICENSE.txt at the repository root.
 */

/**
 * @file PipeClient.hpp
 * @brief Client-side IPC for the PhantomHome UI process.
 *
 * Connects to `\\.\pipe\ShadowStrike.Phantom.UI.<SessionId>` hosted by
 * ShadowStrikePhantomService. Offers:
 *   - Synchronous Request(type, payload, timeout) -> std::optional<FrameEnvelope>
 *   - Asynchronous RequestAsync(type, payload, callback)
 *   - Push-message dispatch via PushCallback (EventDetection, EventScanProgress,
 *     EventPerfMetrics, etc.)
 *   - Auto-reconnect with exponential backoff
 *
 * Qt-agnostic. The Qt UI layer wraps this via a thin QObject adapter that
 * marshals callbacks onto the GUI thread.
 */

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "../../IPC/Messages.hpp"

namespace ShadowStrike::PhantomHome::IPC {

using PushCallback  = std::function<void(const FrameEnvelope&)>;
using StateCallback = std::function<void(bool connected)>;

class PipeClient {
public:
    struct Options {
        std::uint32_t session_id{0};
        std::chrono::milliseconds connect_timeout{5000};
        std::chrono::milliseconds request_timeout{10000};
        std::chrono::milliseconds reconnect_min{500};
        std::chrono::milliseconds reconnect_max{15000};
        std::string   client_build{"ShadowStrike-Phantom-Home-UI"};
    };

    explicit PipeClient(Options options);
    ~PipeClient();

    PipeClient(const PipeClient&) = delete;
    PipeClient& operator=(const PipeClient&) = delete;

    void SetPushCallback(PushCallback cb);
    void SetStateCallback(StateCallback cb);

    /// Start background connect + read loop. Non-blocking.
    void Start();

    /// Stop the client; cancels pending futures.
    void Stop() noexcept;

    [[nodiscard]] bool IsConnected() const noexcept { return connected_.load(); }

    /**
     * @brief Synchronous request / reply.
     * @returns Reply envelope, or std::nullopt on timeout / disconnect.
     */
    [[nodiscard]] std::optional<FrameEnvelope> Request(MessageType type,
                                                       const nlohmann::json& payload);

    /**
     * @brief Fire-and-forget request; completion invoked on an internal thread.
     *        Callback receives std::nullopt on timeout / disconnect.
     */
    using RequestCallback = std::function<void(std::optional<FrameEnvelope>)>;
    void RequestAsync(MessageType type,
                      const nlohmann::json& payload,
                      RequestCallback callback);

private:
    struct Pending {
        std::promise<std::optional<FrameEnvelope>> promise;
    };

    void ConnectLoop();
    void ReadLoop();
    [[nodiscard]] bool PerformHandshake();
    [[nodiscard]] bool ReadFrame(std::vector<std::uint8_t>& out);
    [[nodiscard]] bool WriteFrame(std::span<const std::uint8_t> bytes);
    [[nodiscard]] std::uint64_t NextCorrelationId() noexcept;
    void DispatchReply(const FrameEnvelope& env);
    void NotifyConnected(bool c);
    void CancelAllPending();

    Options                                                 options_;
    std::atomic<bool>                                       running_{false};
    std::atomic<bool>                                       stopping_{false};
    std::atomic<bool>                                       connected_{false};
    std::atomic<std::uint64_t>                              next_corr_id_{1};
    HANDLE                                                  pipe_{INVALID_HANDLE_VALUE};
    std::mutex                                              write_mutex_;
    std::thread                                             connect_thread_;
    std::thread                                             read_thread_;
    std::mutex                                              pending_mutex_;
    std::unordered_map<std::uint64_t, std::shared_ptr<Pending>> pending_;
    PushCallback                                            push_cb_;
    StateCallback                                           state_cb_;
    std::mutex                                              cb_mutex_;
};

}  // namespace ShadowStrike::PhantomHome::IPC
