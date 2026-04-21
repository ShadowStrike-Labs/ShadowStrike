/*
 * ShadowStrike - Enterprise NGAV Platform
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * Licensed under GNU AGPL-v3. See LICENSE.txt at the repository root.
 */

/**
 * @file PipeClient.cpp
 */

#include "PipeClient.hpp"

#include <algorithm>
#include <array>
#include <format>
#include <span>

#include "PhantomCore/Utils/Logger.hpp"

namespace ShadowStrike::PhantomHome::IPC {

namespace {

constexpr const wchar_t* kPhantomServiceName = L"ShadowStrikePhantomService";

class ScopedHandle {
public:
    ScopedHandle() = default;
    explicit ScopedHandle(HANDLE h) : h_(h) {}
    ~ScopedHandle() {
        if (h_ != nullptr && h_ != INVALID_HANDLE_VALUE) {
            ::CloseHandle(h_);
        }
    }

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    [[nodiscard]] HANDLE get() const noexcept { return h_; }
    [[nodiscard]] HANDLE* put() noexcept { return &h_; }
    [[nodiscard]] bool valid() const noexcept {
        return h_ != nullptr && h_ != INVALID_HANDLE_VALUE;
    }

private:
    HANDLE h_{nullptr};
};

class ScopedServiceHandle {
public:
    ScopedServiceHandle() = default;
    explicit ScopedServiceHandle(SC_HANDLE h) : h_(h) {}
    ~ScopedServiceHandle() {
        if (h_ != nullptr) {
            ::CloseServiceHandle(h_);
        }
    }

    ScopedServiceHandle(const ScopedServiceHandle&) = delete;
    ScopedServiceHandle& operator=(const ScopedServiceHandle&) = delete;

    [[nodiscard]] SC_HANDLE get() const noexcept { return h_; }
    [[nodiscard]] bool valid() const noexcept { return h_ != nullptr; }

private:
    SC_HANDLE h_{nullptr};
};

static bool QueryTokenInformation(HANDLE token,
                                  TOKEN_INFORMATION_CLASS klass,
                                  std::vector<std::uint8_t>& out) {
    DWORD need = 0;
    ::GetTokenInformation(token, klass, nullptr, 0, &need);
    if (need == 0 || need > 64 * 1024) return false;
    out.assign(need, 0);
    return ::GetTokenInformation(token, klass, out.data(), need, &need) != FALSE;
}

static bool IsLocalSystemToken(HANDLE token) {
    std::vector<std::uint8_t> user_buf;
    if (!QueryTokenInformation(token, TokenUser, user_buf)) return false;

    const auto* user = reinterpret_cast<const TOKEN_USER*>(user_buf.data());
    if (!user || !user->User.Sid || !::IsValidSid(user->User.Sid)) return false;

    std::array<std::uint8_t, SECURITY_MAX_SID_SIZE> sid_buf{};
    DWORD sid_size = static_cast<DWORD>(sid_buf.size());
    if (!::CreateWellKnownSid(WinLocalSystemSid, nullptr, sid_buf.data(), &sid_size)) {
        return false;
    }

    return ::EqualSid(user->User.Sid, sid_buf.data()) != FALSE;
}

static std::optional<DWORD> QueryExpectedServicePid() {
    ScopedServiceHandle scm(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.valid()) return std::nullopt;

    ScopedServiceHandle svc(::OpenServiceW(scm.get(), kPhantomServiceName, SERVICE_QUERY_STATUS));
    if (!svc.valid()) return std::nullopt;

    SERVICE_STATUS_PROCESS status{};
    DWORD bytes_needed = 0;
    if (!::QueryServiceStatusEx(svc.get(),
                                SC_STATUS_PROCESS_INFO,
                                reinterpret_cast<LPBYTE>(&status),
                                sizeof(status),
                                &bytes_needed)) {
        return std::nullopt;
    }

    if (status.dwCurrentState != SERVICE_RUNNING || status.dwProcessId == 0) {
        return std::nullopt;
    }

    return status.dwProcessId;
}

static bool WriteExact(HANDLE pipe, const void* buf, std::uint32_t size) {
    const auto* p = static_cast<const std::uint8_t*>(buf);
    std::uint32_t written = 0;
    while (written < size) {
        DWORD w = 0;
        if (!::WriteFile(pipe, p + written, size - written, &w, nullptr) || w == 0) return false;
        written += w;
    }
    return true;
}

static bool ReadExact(HANDLE pipe, void* buf, std::uint32_t size) {
    auto* p = static_cast<std::uint8_t*>(buf);
    std::uint32_t read = 0;
    while (read < size) {
        DWORD r = 0;
        if (!::ReadFile(pipe, p + read, size - read, &r, nullptr) || r == 0) return false;
        read += r;
    }
    return true;
}

static std::wstring BuildPipeName(std::uint32_t /*session_id*/) {
    // Session-independent; see PipeServer::PipeFullName for rationale.
    return std::wstring(kPipeNamePrefix.begin(), kPipeNamePrefix.end());
}

}  // namespace

PipeClient::PipeClient(Options options) : options_(std::move(options)) {}

PipeClient::~PipeClient() { Stop(); }

void PipeClient::SetPushCallback(PushCallback cb) {
    std::scoped_lock lk(cb_mutex_);
    push_cb_ = std::move(cb);
}

void PipeClient::SetStateCallback(StateCallback cb) {
    std::scoped_lock lk(cb_mutex_);
    state_cb_ = std::move(cb);
}

void PipeClient::Start() {
    if (running_.exchange(true)) return;
    stopping_.store(false);
    try {
        connect_thread_ = std::thread(&PipeClient::ConnectLoop, this);
    } catch (const std::system_error& e) {
        ShadowStrike::Utils::Logger::Error("PipeClient: thread launch failed: {}", e.what());
        running_.store(false);
    }
}

void PipeClient::Stop() noexcept {
    if (!running_.exchange(false)) return;
    stopping_.store(true);
    connected_.store(false);

    HANDLE h = pipe_;
    if (h != INVALID_HANDLE_VALUE) {
        ::CancelIoEx(h, nullptr);
        ::CloseHandle(h);
        pipe_ = INVALID_HANDLE_VALUE;
    }
    if (connect_thread_.joinable()) connect_thread_.join();
    if (read_thread_.joinable())    read_thread_.join();
    CancelAllPending();
    JoinAsyncThreads();
}

void PipeClient::CancelAllPending() {
    std::unordered_map<std::uint64_t, std::shared_ptr<Pending>> snapshot;
    {
        std::scoped_lock lk(pending_mutex_);
        snapshot = std::move(pending_);
        pending_.clear();
    }
    for (auto& [id, p] : snapshot) {
        try { p->promise.set_value(std::nullopt); } catch (...) {}
    }
}

void PipeClient::JoinAsyncThreads() noexcept {
    std::vector<std::thread> snapshot;
    {
        std::scoped_lock lk(async_threads_mutex_);
        snapshot.swap(async_threads_);
    }

    for (auto& t : snapshot) {
        if (t.joinable()) {
            t.join();
        }
    }
}

void PipeClient::NotifyConnected(bool c) {
    connected_.store(c);
    StateCallback cb;
    {
        std::scoped_lock lk(cb_mutex_);
        cb = state_cb_;
    }
    if (cb) {
        try { cb(c); } catch (...) {}
    }
}

std::uint64_t PipeClient::NextCorrelationId() noexcept {
    return next_corr_id_.fetch_add(1, std::memory_order_relaxed);
}

bool PipeClient::ReadFrame(std::vector<std::uint8_t>& out) {
    std::uint32_t len_le = 0;
    if (!ReadExact(pipe_, &len_le, sizeof(len_le))) return false;
    if (len_le == 0 || len_le > kMaxFrameBytes) return false;
    out.resize(len_le);
    return ReadExact(pipe_, out.data(), len_le);
}

bool PipeClient::WriteFrame(std::span<const std::uint8_t> bytes) {
    if (bytes.size() > kMaxFrameBytes) return false;
    const std::uint32_t len_le = static_cast<std::uint32_t>(bytes.size());
    std::scoped_lock lk(write_mutex_);
    if (!WriteExact(pipe_, &len_le, sizeof(len_le))) return false;
    return WriteExact(pipe_, bytes.data(), len_le);
}

bool PipeClient::VerifyServerIdentity(HANDLE pipe) const {
    ULONG server_pid = 0;
    if (!::GetNamedPipeServerProcessId(pipe, &server_pid) || server_pid == 0) {
        ShadowStrike::Utils::Logger::Warn(
            "PipeClient: failed to query pipe server pid gle={}", ::GetLastError());
        return false;
    }

    const auto expected_pid = QueryExpectedServicePid();
    if (!expected_pid || *expected_pid != static_cast<DWORD>(server_pid)) {
        ShadowStrike::Utils::Logger::Warn(
            "PipeClient: rejecting pipe server pid={} because it does not match the SCM service instance",
            server_pid);
        return false;
    }

    ScopedHandle process(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, server_pid));
    if (!process.valid()) {
        ShadowStrike::Utils::Logger::Warn(
            "PipeClient: failed to open pipe server process pid={} gle={}",
            server_pid, ::GetLastError());
        return false;
    }

    ScopedHandle token;
    if (!::OpenProcessToken(process.get(), TOKEN_QUERY, token.put()) || !token.valid()) {
        ShadowStrike::Utils::Logger::Warn(
            "PipeClient: failed to open pipe server token pid={} gle={}",
            server_pid, ::GetLastError());
        return false;
    }

    if (!IsLocalSystemToken(token.get())) {
        ShadowStrike::Utils::Logger::Warn(
            "PipeClient: rejecting non-LocalSystem pipe server pid={}", server_pid);
        return false;
    }

    return true;
}

bool PipeClient::PerformHandshake() {
    FrameEnvelope env;
    env.version        = kProtocolVersion;
    env.type           = MessageType::Hello;
    env.correlation_id = NextCorrelationId();
    Hello h;
    h.client_version = kProtocolVersion;
    h.client_build   = options_.client_build;
    h.session_id     = options_.session_id;
    env.payload      = h.ToJson();

    const auto bytes = EncodeEnvelopeCbor(env);
    if (!WriteFrame(std::span<const std::uint8_t>(bytes))) return false;

    std::vector<std::uint8_t> in;
    if (!ReadFrame(in)) return false;

    auto reply = DecodeEnvelopeCbor(std::span<const std::uint8_t>(in));
    if (!reply || reply->type != MessageType::HelloOk) return false;
    auto ok = HelloOk::FromJson(reply->payload);
    if (!ok) return false;
    if (ok->server_version != kProtocolVersion) return false;
    return true;
}

void PipeClient::ConnectLoop() {
    auto backoff = options_.reconnect_min;
    while (!stopping_.load()) {
        const auto name = BuildPipeName(options_.session_id);

        // Wait for pipe to become available (service may not be up yet).
        if (!::WaitNamedPipeW(name.c_str(),
                              static_cast<DWORD>(options_.connect_timeout.count()))) {
            if (stopping_.load()) break;
            std::this_thread::sleep_for(backoff);
            backoff = std::min(backoff * 2, options_.reconnect_max);
            continue;
        }

        HANDLE h = ::CreateFileW(name.c_str(),
                                 GENERIC_READ | GENERIC_WRITE,
                                 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            if (stopping_.load()) break;
            std::this_thread::sleep_for(backoff);
            backoff = std::min(backoff * 2, options_.reconnect_max);
            continue;
        }

        if (!VerifyServerIdentity(h)) {
            ::CloseHandle(h);
            if (stopping_.load()) break;
            std::this_thread::sleep_for(backoff);
            backoff = std::min(backoff * 2, options_.reconnect_max);
            continue;
        }

        DWORD mode = PIPE_READMODE_BYTE;
        ::SetNamedPipeHandleState(h, &mode, nullptr, nullptr);
        pipe_ = h;

        if (!PerformHandshake()) {
            ::CloseHandle(h);
            pipe_ = INVALID_HANDLE_VALUE;
            std::this_thread::sleep_for(backoff);
            backoff = std::min(backoff * 2, options_.reconnect_max);
            continue;
        }

        NotifyConnected(true);
        backoff = options_.reconnect_min;

        if (read_thread_.joinable()) read_thread_.join();
        try {
            read_thread_ = std::thread(&PipeClient::ReadLoop, this);
            read_thread_.join();
        } catch (const std::system_error& e) {
            ShadowStrike::Utils::Logger::Error("PipeClient: read thread spawn failed: {}", e.what());
        }

        NotifyConnected(false);
        CancelAllPending();

        HANDLE old = pipe_;
        pipe_ = INVALID_HANDLE_VALUE;
        if (old != INVALID_HANDLE_VALUE) ::CloseHandle(old);

        if (stopping_.load()) break;
    }
}

void PipeClient::ReadLoop() {
    while (!stopping_.load()) {
        std::vector<std::uint8_t> buf;
        if (!ReadFrame(buf)) break;
        auto env = DecodeEnvelopeCbor(std::span<const std::uint8_t>(buf));
        if (!env) break;       // malformed => drop connection

        if (env->correlation_id == 0) {
            // server push
            PushCallback cb;
            {
                std::scoped_lock lk(cb_mutex_);
                cb = push_cb_;
            }
            if (cb) {
                try { cb(*env); } catch (...) {}
            }
        } else {
            DispatchReply(*env);
        }
    }
}

void PipeClient::DispatchReply(const FrameEnvelope& env) {
    std::shared_ptr<Pending> p;
    {
        std::scoped_lock lk(pending_mutex_);
        auto it = pending_.find(env.correlation_id);
        if (it != pending_.end()) {
            p = it->second;
            pending_.erase(it);
        }
    }
    if (p) {
        try { p->promise.set_value(env); } catch (...) {}
    }
}

std::optional<FrameEnvelope> PipeClient::Request(MessageType type, const nlohmann::json& payload) {
    if (!connected_.load()) return std::nullopt;

    FrameEnvelope env;
    env.version        = kProtocolVersion;
    env.type           = type;
    env.correlation_id = NextCorrelationId();
    env.payload        = payload;

    auto p = std::make_shared<Pending>();
    auto fut = p->promise.get_future();
    {
        std::scoped_lock lk(pending_mutex_);
        pending_[env.correlation_id] = p;
    }

    const auto bytes = EncodeEnvelopeCbor(env);
    if (!WriteFrame(std::span<const std::uint8_t>(bytes))) {
        std::scoped_lock lk(pending_mutex_);
        pending_.erase(env.correlation_id);
        return std::nullopt;
    }

    if (fut.wait_for(options_.request_timeout) != std::future_status::ready) {
        std::scoped_lock lk(pending_mutex_);
        pending_.erase(env.correlation_id);
        return std::nullopt;
    }
    try { return fut.get(); }
    catch (...) { return std::nullopt; }
}

void PipeClient::RequestAsync(MessageType type,
                              const nlohmann::json& payload,
                              RequestCallback callback) {
    std::thread worker([this, type, payload, cb = std::move(callback)]() mutable {
        auto r = Request(type, payload);
        try { cb(std::move(r)); } catch (...) {}
    });

    std::scoped_lock lk(async_threads_mutex_);
    async_threads_.emplace_back(std::move(worker));
}

}  // namespace ShadowStrike::PhantomHome::IPC
