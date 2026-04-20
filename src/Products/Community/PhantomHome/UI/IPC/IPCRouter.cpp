/*
 * ShadowStrike - Enterprise NGAV Platform
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * Licensed under GNU AGPL-v3. See LICENSE.txt at the repository root.
 */

/**
 * @file IPCRouter.cpp
 */

#include "IPCRouter.hpp"

#include <format>

#include "../../HomeProductOrchestrator.hpp"
#include "PhantomCore/Utils/Logger.hpp"

namespace ShadowStrike::PhantomHome::IPC {

IPCRouter& IPCRouter::Instance() noexcept {
    static IPCRouter inst;
    return inst;
}

void IPCRouter::Bind(::ShadowStrike::Products::Home::HomeProductOrchestrator& orch) noexcept {
    std::scoped_lock lk(mutex_);
    orch_ = &orch;
}

void IPCRouter::HandleUnimplemented(MessageType requested,
                                    MessageType& reply_type,
                                    nlohmann::json& reply_payload) const noexcept {
    reply_type = MessageType::Error;
    ErrorPayload ep;
    ep.code    = ErrorCode::UnknownMessageType;
    ep.message = "message type not implemented";
    reply_payload = ep.ToJson();
    (void)requested;
}

bool IPCRouter::RequirePrivileged(ClientContext& ctx,
                                  MessageType& reply_type,
                                  nlohmann::json& reply_payload) const noexcept {
    if (ctx.AuthenticatedPrivileged()) return true;
    reply_type = MessageType::Error;
    reply_payload = ErrorPayload{ErrorCode::ElevationRequired,
                                 "elevation required"}.ToJson();
    return false;
}

void IPCRouter::HandlePing(ClientContext&, const FrameEnvelope&,
                           MessageType& reply_type, nlohmann::json& reply_payload) noexcept {
    reply_type = MessageType::Pong;
    reply_payload = nlohmann::json::object();
}

void IPCRouter::HandleGetState(ClientContext&, const FrameEnvelope&,
                               MessageType& reply_type, nlohmann::json& reply_payload) noexcept {
    ProtectionStateReply r;
    {
        std::scoped_lock lk(mutex_);
        if (orch_ && orch_->IsInitialized()) {
            r.state = OverallState::Green;
        } else {
            r.state = OverallState::Amber;
        }
    }
    r.reason             = {};
    r.active_threats     = 0;
    r.last_update_unix   = 0;
    reply_type     = MessageType::GetStateReply;
    reply_payload  = r.ToJson();
}

void IPCRouter::HandleGetModuleStatus(ClientContext&, const FrameEnvelope&,
                                      MessageType& reply_type, nlohmann::json& reply_payload) noexcept {
    GetModuleStatusReply r;
    {
        std::scoped_lock lk(mutex_);
        if (orch_ && orch_->IsInitialized()) {
            // Future: enumerate registered modules. For the scaffolding commit
            // we return an empty list rather than fabricating data.
        }
    }
    reply_type    = MessageType::GetModuleStatusReply;
    reply_payload = r.ToJson();
}

void IPCRouter::Dispatch(ClientContext& ctx,
                         const FrameEnvelope& req,
                         MessageType& reply_type,
                         nlohmann::json& reply_payload) noexcept {
    try {
        switch (req.type) {
            case MessageType::Ping:             HandlePing(ctx, req, reply_type, reply_payload);             return;
            case MessageType::GetState:         HandleGetState(ctx, req, reply_type, reply_payload);         return;
            case MessageType::GetModuleStatus:  HandleGetModuleStatus(ctx, req, reply_type, reply_payload);  return;

            // Mutating ops: require elevation token first.
            case MessageType::SetModuleEnable:
            case MessageType::SetExclusions:
            case MessageType::SetDetectionAction:
            case MessageType::PauseProtection:
            case MessageType::ResumeProtection:
            case MessageType::QuarantineDelete:
            case MessageType::QuarantineRestore:
            case MessageType::TriggerUpdate:
                if (!RequirePrivileged(ctx, reply_type, reply_payload)) return;
                HandleUnimplemented(req.type, reply_type, reply_payload);
                return;

            default:
                HandleUnimplemented(req.type, reply_type, reply_payload);
                return;
        }
    } catch (const std::exception& e) {
        reply_type    = MessageType::Error;
        reply_payload = ErrorPayload{ErrorCode::Internal, e.what()}.ToJson();
    } catch (...) {
        reply_type    = MessageType::Error;
        reply_payload = ErrorPayload{ErrorCode::Internal, "unknown"}.ToJson();
    }
}

}  // namespace ShadowStrike::PhantomHome::IPC
