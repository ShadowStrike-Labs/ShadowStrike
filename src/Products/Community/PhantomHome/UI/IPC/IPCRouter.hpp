/*
 * ShadowStrike - Enterprise NGAV Platform
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * Licensed under GNU AGPL-v3. See LICENSE.txt at the repository root.
 */

/**
 * @file IPCRouter.hpp
 * @brief Service-side message dispatcher. Maps MessageType -> typed handler.
 *
 * The router is a Meyers' singleton that delegates to the engine subsystems:
 *   - HomeProductOrchestrator (module lifecycle, state, pause/resume)
 *   - ScanEngine (on-demand scans, job management)
 *   - QuarantineManager (quarantine list, delete, restore)
 *   - ConfigManager (exclusions, detection action)
 *
 * Per-message handlers are plain member functions returning a JSON payload.
 *
 * Adding a new message type
 * -------------------------
 *   1. Define its payload struct in Messages.hpp (ToJson/FromJson).
 *   2. Add a new case in Dispatch().
 *   3. Implement Handle<XYZ>() in IPCRouter.cpp.
 *
 * Unauthenticated / privileged gating
 * -----------------------------------
 *   Mutating operations (SetModuleEnable, SetExclusions, PauseProtection,
 *   QuarantineDelete, TriggerUpdate) are routed through
 *   RequirePrivileged(ctx); they reject with ErrorCode::ElevationRequired
 *   unless the ClientContext has been marked privileged (elevation token
 *   verified out of band).
 */

#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>

#include "PipeServer.hpp"
#include "Messages.hpp"

namespace ShadowStrike::Products::Home {
class HomeProductOrchestrator;
}

namespace ShadowStrike::PhantomHome::IPC {

class IPCRouter final {
public:
    [[nodiscard]] static IPCRouter& Instance() noexcept;

    void Bind(::ShadowStrike::Products::Home::HomeProductOrchestrator& orch) noexcept;
    void BindPipeServer(PipeServer& server) noexcept;

    /// Route a request envelope to its typed handler. Populates reply_type
    /// and reply_payload. Never throws; internal exceptions are converted to
    /// Error replies.
    void Dispatch(ClientContext& ctx,
                  const FrameEnvelope& req,
                  MessageType& reply_type,
                  nlohmann::json& reply_payload) noexcept;

    /// Graceful teardown: cancel active scans, stop pause timer.
    void Shutdown() noexcept;

private:
    IPCRouter()  = default;
    ~IPCRouter();
    IPCRouter(const IPCRouter&)            = delete;
    IPCRouter& operator=(const IPCRouter&) = delete;

    [[nodiscard]] bool RequirePrivileged(ClientContext& ctx,
                                         MessageType& reply_type,
                                         nlohmann::json& reply_payload) const noexcept;

    // --- Handlers ---
    void HandlePing(ClientContext&, const FrameEnvelope&,
                    MessageType&, nlohmann::json&) noexcept;
    void HandleGetState(ClientContext&, const FrameEnvelope&,
                        MessageType&, nlohmann::json&) noexcept;
    void HandleGetModuleStatus(ClientContext&, const FrameEnvelope&,
                               MessageType&, nlohmann::json&) noexcept;
    void HandleSetModuleEnable(ClientContext&, const FrameEnvelope&,
                               MessageType&, nlohmann::json&) noexcept;
    void HandleScanStart(ClientContext&, const FrameEnvelope&,
                         MessageType&, nlohmann::json&) noexcept;
    void HandleScanCancel(ClientContext&, const FrameEnvelope&,
                          MessageType&, nlohmann::json&) noexcept;
    void HandlePauseProtection(ClientContext&, const FrameEnvelope&,
                               MessageType&, nlohmann::json&) noexcept;
    void HandleResumeProtection(ClientContext&, const FrameEnvelope&,
                                MessageType&, nlohmann::json&) noexcept;
    void HandleGetExclusions(ClientContext&, const FrameEnvelope&,
                             MessageType&, nlohmann::json&) noexcept;
    void HandleSetExclusions(ClientContext&, const FrameEnvelope&,
                             MessageType&, nlohmann::json&) noexcept;
    void HandleGetDetectionAction(ClientContext&, const FrameEnvelope&,
                                  MessageType&, nlohmann::json&) noexcept;
    void HandleSetDetectionAction(ClientContext&, const FrameEnvelope&,
                                  MessageType&, nlohmann::json&) noexcept;
    void HandleQuarantineList(ClientContext&, const FrameEnvelope&,
                              MessageType&, nlohmann::json&) noexcept;
    void HandleQuarantineDelete(ClientContext&, const FrameEnvelope&,
                                MessageType&, nlohmann::json&) noexcept;
    void HandleQuarantineRestore(ClientContext&, const FrameEnvelope&,
                                 MessageType&, nlohmann::json&) noexcept;
    void HandleGetUpdateStatus(ClientContext&, const FrameEnvelope&,
                               MessageType&, nlohmann::json&) noexcept;
    void HandleTriggerUpdate(ClientContext&, const FrameEnvelope&,
                             MessageType&, nlohmann::json&) noexcept;
    void HandleSubscribePerfMetrics(ClientContext&, const FrameEnvelope&,
                                    MessageType&, nlohmann::json&) noexcept;
    void HandleGetReports(ClientContext&, const FrameEnvelope&,
                          MessageType&, nlohmann::json&) noexcept;

    void HandleUnimplemented(MessageType requested,
                             MessageType& reply_type,
                             nlohmann::json& reply_payload) const noexcept;

    void MakeError(MessageType& reply_type, nlohmann::json& reply_payload,
                   ErrorCode code, const char* message) const noexcept;

    // --- Active scan tracking ---
    struct ActiveScan {
        std::uint64_t scan_id{0};
        std::shared_ptr<std::atomic<bool>> cancelled;
        std::thread    worker;

        ActiveScan() : cancelled(std::make_shared<std::atomic<bool>>(false)) {}
    };

    void CleanupCompletedScans() noexcept;

    // --- Members ---
    mutable std::mutex                                        mutex_;
    ::ShadowStrike::Products::Home::HomeProductOrchestrator*  orch_{nullptr};
    PipeServer*                                               pipe_server_{nullptr};

    std::atomic<std::uint64_t>                                next_scan_id_{1};
    std::mutex                                                scans_mutex_;
    std::unordered_map<std::uint64_t, std::unique_ptr<ActiveScan>> active_scans_;

    // Pause auto-resume timer
    std::mutex                    pause_timer_mutex_;
    std::condition_variable       pause_timer_cv_;
    std::thread                   pause_timer_thread_;
    std::atomic<bool>             pause_timer_active_{false};
    std::atomic<bool>             shutting_down_{false};
};

}  // namespace ShadowStrike::PhantomHome::IPC
