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
 * The router is a Meyers' singleton that owns no state of its own; it delegates
 * to a HomeProductOrchestrator reference supplied via Bind(). Per-message
 * handlers are plain member functions returning a JSON payload.
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
 *   RequirePrivileged(ctx); they reject with ErrorCode::PermissionDenied
 *   unless the ClientContext has been marked privileged (elevation token
 *   verified out of band).
 */

#pragma once

#include <mutex>

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

    /// Route a request envelope to its typed handler. Populates reply_type
    /// and reply_payload. Never throws; internal exceptions are converted to
    /// Error replies.
    void Dispatch(ClientContext& ctx,
                  const FrameEnvelope& req,
                  MessageType& reply_type,
                  nlohmann::json& reply_payload) noexcept;

private:
    IPCRouter()  = default;
    ~IPCRouter() = default;
    IPCRouter(const IPCRouter&)            = delete;
    IPCRouter& operator=(const IPCRouter&) = delete;

    [[nodiscard]] bool RequirePrivileged(ClientContext& ctx,
                                         MessageType& reply_type,
                                         nlohmann::json& reply_payload) const noexcept;

    void HandleGetState(ClientContext&, const FrameEnvelope&,
                        MessageType&, nlohmann::json&) noexcept;
    void HandleGetModuleStatus(ClientContext&, const FrameEnvelope&,
                               MessageType&, nlohmann::json&) noexcept;
    void HandlePing(ClientContext&, const FrameEnvelope&,
                    MessageType&, nlohmann::json&) noexcept;
    void HandleUnimplemented(MessageType requested,
                             MessageType& reply_type,
                             nlohmann::json& reply_payload) const noexcept;

    mutable std::mutex                                        mutex_;
    ::ShadowStrike::Products::Home::HomeProductOrchestrator*  orch_{nullptr};
};

}  // namespace ShadowStrike::PhantomHome::IPC
