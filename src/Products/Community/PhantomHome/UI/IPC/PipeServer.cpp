/*
 * ShadowStrike - Enterprise NGAV Platform
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * Licensed under GNU AGPL-v3. See LICENSE.txt at the repository root.
 */

/**
 * @file PipeServer.cpp
 * @brief Implementation of the PhantomHome UI named-pipe server (service side).
 */

#include "PipeServer.hpp"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <format>
#include <span>

#include <aclapi.h>
#include <sddl.h>

#include "PhantomCore/Utils/Logger.hpp"

#pragma comment(lib, "advapi32.lib")

namespace ShadowStrike::PhantomHome::IPC {

namespace {

/// RAII wrapper for SECURITY_DESCRIPTOR built from an SDDL string.
class SecurityDescriptor {
public:
    explicit SecurityDescriptor(std::wstring_view sddl) {
        PSECURITY_DESCRIPTOR sd = nullptr;
        if (::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.data(), SDDL_REVISION_1, &sd, nullptr)) {
            sd_ = sd;
        }
    }
    ~SecurityDescriptor() {
        if (sd_) ::LocalFree(sd_);
    }
    SecurityDescriptor(const SecurityDescriptor&) = delete;
    SecurityDescriptor& operator=(const SecurityDescriptor&) = delete;
    [[nodiscard]] PSECURITY_DESCRIPTOR Get() const noexcept { return sd_; }

private:
    PSECURITY_DESCRIPTOR sd_{nullptr};
};

/// Fill SECURITY_ATTRIBUTES from an SDDL-derived security descriptor.
static bool MakeSecurityAttributes(const SecurityDescriptor& sd, SECURITY_ATTRIBUTES& sa) {
    if (!sd.Get()) return false;
    sa.nLength              = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = sd.Get();
    sa.bInheritHandle       = FALSE;
    return true;
}

/// Write exactly `size` bytes to the pipe (blocking). Returns false on disconnect / short write.
static bool WriteExact(HANDLE pipe, const void* buf, std::uint32_t size) {
    const auto* p = static_cast<const std::uint8_t*>(buf);
    std::uint32_t written = 0;
    while (written < size) {
        DWORD w = 0;
        if (!::WriteFile(pipe, p + written, size - written, &w, nullptr) || w == 0) {
            return false;
        }
        written += w;
    }
    return true;
}

/// Read exactly `size` bytes from the pipe (blocking). Returns false on disconnect / EOF.
static bool ReadExact(HANDLE pipe, void* buf, std::uint32_t size) {
    auto* p = static_cast<std::uint8_t*>(buf);
    std::uint32_t read = 0;
    while (read < size) {
        DWORD r = 0;
        if (!::ReadFile(pipe, p + read, size - read, &r, nullptr) || r == 0) {
            return false;
        }
        read += r;
    }
    return true;
}

}  // namespace

// ==========================================================================
// ClientContext
// ==========================================================================

ClientContext::ClientContext(PipeServer& server, HANDLE pipe, std::uint32_t client_pid)
    : server_(server), pipe_(pipe), client_pid_(client_pid) {}

ClientContext::~ClientContext() {
    if (pipe_ != INVALID_HANDLE_VALUE) {
        ::FlushFileBuffers(pipe_);
        ::DisconnectNamedPipe(pipe_);
        ::CloseHandle(pipe_);
        pipe_ = INVALID_HANDLE_VALUE;
    }
}

bool ClientContext::PushMessage(MessageType type, const nlohmann::json& payload) {
    FrameEnvelope env;
    env.version        = kProtocolVersion;
    env.type           = type;
    env.correlation_id = 0;                 // push: no correlation
    env.payload        = payload;
    const auto bytes = EncodeEnvelopeCbor(env);
    if (bytes.size() > kMaxFrameBytes) return false;

    return server_.WriteFrame(pipe_, write_mutex_, std::span<const std::uint8_t>(bytes));
}

// ==========================================================================
// PipeServer
// ==========================================================================

PipeServer::PipeServer(Options options) : options_(std::move(options)) {
    stop_event_ = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
}

PipeServer::~PipeServer() {
    Stop();
    if (stop_event_) ::CloseHandle(stop_event_);
}

std::wstring PipeServer::PipeFullName() const {
    std::wstring prefix(kPipeNamePrefix.begin(), kPipeNamePrefix.end());
    return prefix + std::to_wstring(options_.session_id);
}

void PipeServer::SetHandler(MessageHandler handler) {
    std::scoped_lock lk(handler_mutex_);
    handler_ = std::move(handler);
}

bool PipeServer::Start() {
    if (running_.exchange(true)) return true;
    stopping_.store(false);
    ::ResetEvent(stop_event_);

    try {
        accept_thread_ = std::thread(&PipeServer::AcceptLoop, this);
    } catch (const std::system_error& e) {
        ShadowStrike::Utils::Logger::Error(
            "PipeServer: failed to launch accept thread: {}", e.what());
        running_.store(false);
        return false;
    }
    ShadowStrike::Utils::Logger::Info(
        "PipeServer: started, pipe prefix session={}", options_.session_id);
    return true;
}

void PipeServer::Stop() noexcept {
    if (!running_.exchange(false)) return;
    stopping_.store(true);
    if (stop_event_) ::SetEvent(stop_event_);

    // Closing pipe instances forces blocking Read/Write to fail, which unwinds
    // the worker threads. Accept thread uses stop_event_ + the next CreateFile
    // attempt from any client — which we deliberately do not issue.
    {
        std::scoped_lock lk(clients_mutex_);
        for (auto& c : clients_) {
            if (c && c->pipe_ != INVALID_HANDLE_VALUE) {
                ::CancelIoEx(c->pipe_, nullptr);
            }
        }
    }

    if (accept_thread_.joinable()) accept_thread_.join();
    for (auto& t : workers_) {
        if (t.joinable()) t.join();
    }
    workers_.clear();
    {
        std::scoped_lock lk(clients_mutex_);
        clients_.clear();
    }
    ShadowStrike::Utils::Logger::Info("PipeServer: stopped");
}

HANDLE PipeServer::CreatePipeInstance(bool first) {
    SecurityDescriptor sd(options_.sddl);
    SECURITY_ATTRIBUTES sa{};
    if (!MakeSecurityAttributes(sd, sa)) {
        ShadowStrike::Utils::Logger::Error(
            "PipeServer: invalid SDDL, cannot build security descriptor");
        return INVALID_HANDLE_VALUE;
    }

    const auto name = PipeFullName();
    DWORD open_mode = PIPE_ACCESS_DUPLEX;
    if (first) open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;

    // Message mode is intentional — we implement our own framing on top, but
    // message mode gives us cheap protection against a rogue client writing
    // an 8 GB "string" — single WriteFile from our side is atomic in bytes.
    const HANDLE h = ::CreateNamedPipeW(
        name.c_str(),
        open_mode,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        options_.max_concurrent_connections,
        /*nOutBufferSize=*/ 64 * 1024,
        /*nInBufferSize=*/  64 * 1024,
        /*nDefaultTimeOut=*/ 0,
        &sa);
    if (h == INVALID_HANDLE_VALUE) {
        ShadowStrike::Utils::Logger::Error(
            "PipeServer: CreateNamedPipeW failed, gle={}", ::GetLastError());
    }
    return h;
}

void PipeServer::AcceptLoop() {
    bool first = true;
    while (!stopping_.load()) {
        HANDLE pipe = CreatePipeInstance(first);
        first = false;
        if (pipe == INVALID_HANDLE_VALUE) {
            if (stopping_.load()) break;
            ::Sleep(200);
            continue;
        }

        // Blocking ConnectNamedPipe — Stop() closes the handle to unblock.
        BOOL ok = ::ConnectNamedPipe(pipe, nullptr);
        if (!ok && ::GetLastError() != ERROR_PIPE_CONNECTED) {
            ::CloseHandle(pipe);
            if (stopping_.load()) break;
            continue;
        }

        ULONG client_pid = 0;
        if (!::GetNamedPipeClientProcessId(pipe, &client_pid)) {
            ::DisconnectNamedPipe(pipe);
            ::CloseHandle(pipe);
            continue;
        }

        auto ctx = std::make_shared<ClientContext>(*this, pipe, client_pid);
        {
            std::scoped_lock lk(clients_mutex_);
            if (clients_.size() >= options_.max_concurrent_connections) {
                ShadowStrike::Utils::Logger::Warn(
                    "PipeServer: rejecting client pid={} (max={})",
                    client_pid, options_.max_concurrent_connections);
                continue;    // ctx destructor closes pipe
            }
            clients_.push_back(ctx);
        }

        try {
            workers_.emplace_back(&PipeServer::WorkerLoop, this, ctx);
        } catch (const std::system_error& e) {
            ShadowStrike::Utils::Logger::Error(
                "PipeServer: failed to spawn worker: {}", e.what());
            std::scoped_lock lk(clients_mutex_);
            clients_.erase(std::remove(clients_.begin(), clients_.end(), ctx), clients_.end());
        }
    }
}

bool PipeServer::ReadFrame(HANDLE pipe, std::vector<std::uint8_t>& out) {
    std::uint32_t len_le = 0;
    if (!ReadExact(pipe, &len_le, sizeof(len_le))) return false;
    if (len_le == 0 || len_le > kMaxFrameBytes) return false;
    out.resize(len_le);
    return ReadExact(pipe, out.data(), len_le);
}

bool PipeServer::WriteFrame(HANDLE pipe, std::mutex& m, std::span<const std::uint8_t> bytes) {
    if (bytes.size() > kMaxFrameBytes) return false;
    const std::uint32_t len_le = static_cast<std::uint32_t>(bytes.size());
    std::scoped_lock lk(m);
    if (!WriteExact(pipe, &len_le, sizeof(len_le))) return false;
    return WriteExact(pipe, bytes.data(), len_le);
}

bool PipeServer::HandshakeFrame(ClientContext& ctx) {
    std::vector<std::uint8_t> buf;
    if (!ReadFrame(ctx.PipeHandle(), buf)) return false;

    auto env = DecodeEnvelopeCbor(std::span<const std::uint8_t>(buf));
    if (!env || env->type != MessageType::Hello || env->version != kProtocolVersion) {
        return false;
    }
    auto hello = Hello::FromJson(env->payload);
    if (!hello) return false;

    FrameEnvelope reply;
    reply.version        = kProtocolVersion;
    reply.type           = MessageType::HelloOk;
    reply.correlation_id = env->correlation_id;
    HelloOk ok;
    ok.server_version = kProtocolVersion;
    ok.server_build   = "ShadowStrike-Phantom-Home";
    ok.capabilities   = 0;
    reply.payload = ok.ToJson();

    const auto enc = EncodeEnvelopeCbor(reply);
    return WriteFrame(ctx.PipeHandle(), ctx.write_mutex_,
                      std::span<const std::uint8_t>(enc));
}

void PipeServer::WorkerLoop(std::shared_ptr<ClientContext> ctx) {
    if (!HandshakeFrame(*ctx)) {
        ShadowStrike::Utils::Logger::Warn(
            "PipeServer: handshake failed for client pid={}", ctx->ClientProcessId());
    } else {
        while (!stopping_.load()) {
            std::vector<std::uint8_t> buf;
            if (!ReadFrame(ctx->PipeHandle(), buf)) break;

            auto env = DecodeEnvelopeCbor(std::span<const std::uint8_t>(buf));
            if (!env) {
                FrameEnvelope err;
                err.version = kProtocolVersion;
                err.type    = MessageType::Error;
                err.payload = ErrorPayload{ErrorCode::InvalidFrame, "malformed frame"}.ToJson();
                const auto b = EncodeEnvelopeCbor(err);
                (void)WriteFrame(ctx->PipeHandle(), ctx->write_mutex_,
                                 std::span<const std::uint8_t>(b));
                break;
            }

            MessageType    reply_type = MessageType::Error;
            nlohmann::json reply_payload;

            MessageHandler handler_copy;
            {
                std::scoped_lock lk(handler_mutex_);
                handler_copy = handler_;
            }
            if (handler_copy) {
                try {
                    handler_copy(*ctx, *env, reply_type, reply_payload);
                } catch (const std::exception& e) {
                    reply_type    = MessageType::Error;
                    reply_payload = ErrorPayload{ErrorCode::Internal, e.what()}.ToJson();
                } catch (...) {
                    reply_type    = MessageType::Error;
                    reply_payload = ErrorPayload{ErrorCode::Internal, "unknown"}.ToJson();
                }
            } else {
                reply_type    = MessageType::Error;
                reply_payload = ErrorPayload{ErrorCode::Internal, "no handler"}.ToJson();
            }

            FrameEnvelope reply;
            reply.version        = kProtocolVersion;
            reply.type           = reply_type;
            reply.correlation_id = env->correlation_id;
            reply.payload        = std::move(reply_payload);
            const auto b = EncodeEnvelopeCbor(reply);
            if (!WriteFrame(ctx->PipeHandle(), ctx->write_mutex_,
                            std::span<const std::uint8_t>(b))) {
                break;
            }
        }
    }

    // De-register this client
    {
        std::scoped_lock lk(clients_mutex_);
        clients_.erase(std::remove_if(clients_.begin(), clients_.end(),
                                      [&](const std::shared_ptr<ClientContext>& c) {
                                          return c.get() == ctx.get();
                                      }),
                       clients_.end());
    }
}

void PipeServer::Broadcast(MessageType type, const nlohmann::json& payload) {
    std::vector<std::shared_ptr<ClientContext>> snapshot;
    {
        std::scoped_lock lk(clients_mutex_);
        snapshot = clients_;
    }
    for (auto& c : snapshot) {
        if (c) (void)c->PushMessage(type, payload);
    }
}

}  // namespace ShadowStrike::PhantomHome::IPC
