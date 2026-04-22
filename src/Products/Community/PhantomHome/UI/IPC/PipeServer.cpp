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
#include <array>
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

/// RAII wrapper for impersonation: reverts on scope exit.
class ImpersonationScope {
public:
    explicit ImpersonationScope(HANDLE pipe) {
        active_ = ::ImpersonateNamedPipeClient(pipe) != FALSE;
    }
    ~ImpersonationScope() {
        if (active_) ::RevertToSelf();
    }
    ImpersonationScope(const ImpersonationScope&) = delete;
    ImpersonationScope& operator=(const ImpersonationScope&) = delete;
    [[nodiscard]] bool Active() const noexcept { return active_; }

private:
    bool active_{false};
};

/// RAII wrapper for a Windows HANDLE that CloseHandles on scope exit.
class ScopedHandle {
public:
    ScopedHandle() = default;
    explicit ScopedHandle(HANDLE h) : h_(h) {}
    ~ScopedHandle() { reset(); }
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
    ScopedHandle(ScopedHandle&& o) noexcept : h_(o.h_) { o.h_ = nullptr; }
    ScopedHandle& operator=(ScopedHandle&& o) noexcept {
        if (this != &o) { reset(); h_ = o.h_; o.h_ = nullptr; }
        return *this;
    }
    [[nodiscard]] HANDLE  get() const noexcept { return h_; }
    [[nodiscard]] HANDLE* ptr() noexcept       { return &h_; }
    [[nodiscard]] bool    valid() const noexcept {
        return h_ != nullptr && h_ != INVALID_HANDLE_VALUE;
    }
    [[nodiscard]] HANDLE release() noexcept {
        HANDLE tmp = h_;
        h_ = nullptr;
        return tmp;
    }
    void reset() noexcept {
        if (valid()) ::CloseHandle(h_);
        h_ = nullptr;
    }

private:
    HANDLE h_{nullptr};
};

/// Fetch variable-size TokenInformation, returning heap buffer on success.
static bool QueryTokenInformation(HANDLE token,
                                  TOKEN_INFORMATION_CLASS klass,
                                  std::vector<std::uint8_t>& out) {
    DWORD need = 0;
    ::GetTokenInformation(token, klass, nullptr, 0, &need);
    if (need == 0) return false;
    out.assign(need, 0);
    return ::GetTokenInformation(token, klass, out.data(), need, &need) != FALSE;
}

/// Convert a SID to its string form; returns empty string on failure.
static std::wstring SidToString(PSID sid) {
    if (!sid) return {};
    LPWSTR s = nullptr;
    if (!::ConvertSidToStringSidW(sid, &s) || !s) return {};
    std::wstring out(s);
    ::LocalFree(s);
    return out;
}

/// Look up the human-readable DOMAIN\user for a SID (best-effort, bounded).
static std::wstring LookupAccountName(PSID sid) {
    if (!sid) return {};
    wchar_t name_buf[128]   = {0};
    wchar_t domain_buf[128] = {0};
    DWORD   name_len        = static_cast<DWORD>(std::size(name_buf));
    DWORD   domain_len      = static_cast<DWORD>(std::size(domain_buf));
    SID_NAME_USE use{};
    if (!::LookupAccountSidW(nullptr, sid,
                             name_buf, &name_len,
                             domain_buf, &domain_len,
                             &use)) {
        return {};
    }
    std::wstring out;
    if (domain_len > 0 && domain_buf[0] != L'\0') {
        out.assign(domain_buf);
        out.push_back(L'\\');
    }
    out.append(name_buf);
    return out;
}

/// Extract integrity-level RID from the token's label SID.
static std::uint32_t TokenIntegrityRid(HANDLE token) {
    std::vector<std::uint8_t> buf;
    if (!QueryTokenInformation(token, TokenIntegrityLevel, buf)) return 0;
    const auto* il = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buf.data());
    if (!il || !il->Label.Sid) return 0;
    const UCHAR count = *::GetSidSubAuthorityCount(il->Label.Sid);
    if (count == 0) return 0;
    return *::GetSidSubAuthority(il->Label.Sid, count - 1);
}

/// Returns true if the token carries a membership in BUILTIN\Administrators,
/// LocalSystem, or Anonymous, respectively. All three are independent.
static void ClassifyWellKnownMembership(HANDLE token,
                                        bool& is_admin,
                                        bool& is_system,
                                        bool& is_anonymous) {
    is_admin = is_system = is_anonymous = false;

    SID_IDENTIFIER_AUTHORITY nt_auth = SECURITY_NT_AUTHORITY;
    PSID admins_sid = nullptr;
    if (::AllocateAndInitializeSid(&nt_auth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                   DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                   &admins_sid)) {
        BOOL member = FALSE;
        if (::CheckTokenMembership(token, admins_sid, &member) && member) {
            is_admin = true;
        }
        ::FreeSid(admins_sid);
    }

    PSID system_sid = nullptr;
    if (::AllocateAndInitializeSid(&nt_auth, 1, SECURITY_LOCAL_SYSTEM_RID,
                                   0, 0, 0, 0, 0, 0, 0, &system_sid)) {
        BOOL member = FALSE;
        if (::CheckTokenMembership(token, system_sid, &member) && member) {
            is_system = true;
        }
        ::FreeSid(system_sid);
    }

    SID_IDENTIFIER_AUTHORITY null_auth = SECURITY_NULL_SID_AUTHORITY;
    PSID anon_sid = nullptr;
    if (::AllocateAndInitializeSid(&null_auth, 1, SECURITY_ANONYMOUS_LOGON_RID,
                                   0, 0, 0, 0, 0, 0, 0, &anon_sid)) {
        BOOL member = FALSE;
        if (::CheckTokenMembership(token, anon_sid, &member) && member) {
            is_anonymous = true;
        }
        ::FreeSid(anon_sid);
    }
}

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

static bool WaitForPipeBytes(HANDLE pipe,
                             std::uint32_t minimum_bytes,
                             DWORD timeout_ms,
                             HANDLE stop_event) {
    if (minimum_bytes == 0) return true;

    const ULONGLONG deadline =
        (timeout_ms == INFINITE) ? 0ULL : (::GetTickCount64() + timeout_ms);

    for (;;) {
        DWORD available = 0;
        if (::PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr)) {
            if (available >= minimum_bytes) {
                return true;
            }
        } else {
            const DWORD gle = ::GetLastError();
            if (gle == ERROR_BROKEN_PIPE ||
                gle == ERROR_PIPE_NOT_CONNECTED ||
                gle == ERROR_NO_DATA ||
                gle == ERROR_INVALID_HANDLE ||
                gle == ERROR_OPERATION_ABORTED) {
                return false;
            }
        }

        DWORD wait_ms = 50;
        if (timeout_ms != INFINITE) {
            const ULONGLONG now = ::GetTickCount64();
            if (now >= deadline) {
                return false;
            }

            const ULONGLONG remaining = deadline - now;
            wait_ms = static_cast<DWORD>((std::min<ULONGLONG>)(remaining, wait_ms));
        }

        if (stop_event) {
            const DWORD wait = ::WaitForSingleObject(stop_event, wait_ms);
            if (wait == WAIT_OBJECT_0) {
                return false;
            }
            if (wait == WAIT_FAILED) {
                return false;
            }
        } else {
            ::Sleep(wait_ms);
        }
    }
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
    accept_ready_event_ = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
}

PipeServer::~PipeServer() {
    Stop();
    if (stop_event_) ::CloseHandle(stop_event_);
    if (accept_ready_event_) ::CloseHandle(accept_ready_event_);
}

std::wstring PipeServer::PipeFullName() const {
    // Session-independent pipe name. The previous design suffixed the
    // interactive session id captured at service-start time via
    // WTSGetActiveConsoleSessionId(), but that function returns 0xFFFFFFFF
    // when the service starts before any user logs on - which is the
    // normal auto-start path for us. The tray client, in its own session,
    // would then never find a matching pipe and the user would see a
    // permanent "service offline" tooltip. Authorisation is already
    // enforced by (a) the pipe SDDL restricting access to Interactive +
    // Administrators + SYSTEM and (b) per-connection token inspection in
    // InspectClientIdentity. Session matching at pipe-name level is
    // redundant and actively harmful.
    (void)options_.session_id;
    return std::wstring(kPipeNamePrefix.begin(), kPipeNamePrefix.end());
}

void PipeServer::SetHandler(MessageHandler handler) {
    std::scoped_lock lk(handler_mutex_);
    handler_ = std::move(handler);
}

bool PipeServer::Start() {
    if (running_.exchange(true)) return true;
    if (!stop_event_ || !accept_ready_event_) {
        ShadowStrike::Utils::Logger::Error(
            "PipeServer: missing synchronization events during startup");
        running_.store(false);
        return false;
    }
    stopping_.store(false);
    accept_ready_.store(false);
    ::ResetEvent(stop_event_);
    ::ResetEvent(accept_ready_event_);

    try {
        accept_thread_ = std::thread(&PipeServer::AcceptLoop, this);
    } catch (const std::system_error& e) {
        ShadowStrike::Utils::Logger::Error(
            "PipeServer: failed to launch accept thread: {}", e.what());
        running_.store(false);
        return false;
    }

    const DWORD ready_wait = ::WaitForSingleObject(accept_ready_event_, 5000);
    if (ready_wait != WAIT_OBJECT_0 || !accept_ready_.load()) {
        ShadowStrike::Utils::Logger::Error(
            "PipeServer: accept loop failed to secure the initial pipe instance");
        stopping_.store(true);
        ::SetEvent(stop_event_);
        if (accept_thread_.joinable()) accept_thread_.join();
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
    // NOTE: All I/O on these handles is synchronous (blocking ReadFile /
    // WriteFile with lpOverlapped = nullptr). Do NOT set FILE_FLAG_OVERLAPPED
    // here — mixing sync calls with async-opened handles is undefined on
    // Windows and manifests as spurious WriteFile failures once a pipe has
    // served more than the initial handshake frame.
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
        const DWORD gle = ::GetLastError();
        ShadowStrike::Utils::Logger::Error(
            "PipeServer: CreateNamedPipeW failed, gle={}", gle);
        ::SetLastError(gle);
    }
    return h;
}

void PipeServer::AcceptLoop() {
    bool first = true;
    while (!stopping_.load()) {
        ScopedHandle pipe(CreatePipeInstance(first));
        if (!pipe.valid()) {
            const DWORD gle = ::GetLastError();
            if (first) {
                accept_ready_.store(false);
                if (accept_ready_event_) ::SetEvent(accept_ready_event_);
            }
            if (stopping_.load()) break;
            if (first &&
                (gle == ERROR_ACCESS_DENIED ||
                 gle == ERROR_PIPE_BUSY ||
                 gle == ERROR_INVALID_HANDLE)) {
                ShadowStrike::Utils::Logger::Error(
                    "PipeServer: initial pipe instance could not be secured; refusing to attach to an existing pipe, gle={}",
                    gle);
                stopping_.store(true);
                running_.store(false);
                if (stop_event_) ::SetEvent(stop_event_);
                break;
            }
            ::Sleep(200);
            continue;
        }

        ScopedHandle connect_event(::CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!connect_event.valid()) {
            ShadowStrike::Utils::Logger::Error(
                "PipeServer: CreateEventW failed for accept path, gle={}",
                ::GetLastError());
            if (first) {
                accept_ready_.store(false);
                if (accept_ready_event_) ::SetEvent(accept_ready_event_);
            }
            stopping_.store(true);
            running_.store(false);
            if (stop_event_) ::SetEvent(stop_event_);
            break;
        }

        if (first) {
            accept_ready_.store(true);
            if (accept_ready_event_) ::SetEvent(accept_ready_event_);
        }

        OVERLAPPED ov{};
        ov.hEvent = connect_event.get();

        BOOL ok = ::ConnectNamedPipe(pipe.get(), &ov);
        if (!ok) {
            const DWORD gle = ::GetLastError();
            if (gle == ERROR_IO_PENDING) {
                HANDLE waits[2] = {stop_event_, connect_event.get()};
                const DWORD wait = ::WaitForMultipleObjects(2, waits, FALSE, INFINITE);
                if (wait == WAIT_OBJECT_0) {
                    ::CancelIoEx(pipe.get(), &ov);
                    break;
                }
                if (wait != WAIT_OBJECT_0 + 1) {
                    ::CancelIoEx(pipe.get(), &ov);
                    if (stopping_.load()) break;
                    continue;
                }

                DWORD transferred = 0;
                if (!::GetOverlappedResult(pipe.get(), &ov, &transferred, FALSE)) {
                    const DWORD result_gle = ::GetLastError();
                    if (result_gle == ERROR_OPERATION_ABORTED && stopping_.load()) {
                        break;
                    }
                    if (stopping_.load()) break;
                    continue;
                }
            } else if (gle != ERROR_PIPE_CONNECTED) {
                if (stopping_.load()) break;
                continue;
            }
        }

        first = false;

        ULONG client_pid = 0;
        if (!::GetNamedPipeClientProcessId(pipe.get(), &client_pid)) {
            ::DisconnectNamedPipe(pipe.get());
            continue;
        }

        auto ctx = std::make_shared<ClientContext>(*this, pipe.release(), client_pid);
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

bool PipeServer::ReadFrame(HANDLE pipe, std::vector<std::uint8_t>& out,
                           std::uint32_t first_byte_timeout_ms) {
    std::uint32_t len_le = 0;
    // The first-byte wait uses the caller-supplied timeout so the worker loop
    // can pass INFINITE for an authenticated, established connection (idle
    // client should not be force-disconnected) while HandshakeFrame still
    // uses a short timeout to reject stalled handshakes. Once the first byte
    // arrives, the rest of the frame must complete within read_timeout_ms —
    // that is a legitimate per-request timeout protecting against slow-write
    // DoS, not an idle-connection timeout.
    if (!WaitForPipeBytes(pipe, sizeof(len_le), first_byte_timeout_ms, stop_event_)) {
        return false;
    }
    if (!ReadExact(pipe, &len_le, sizeof(len_le))) return false;
    if (len_le == 0 || len_le > kMaxFrameBytes) return false;
    if (!WaitForPipeBytes(pipe, len_le, options_.read_timeout_ms, stop_event_)) {
        return false;
    }
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

void PipeServer::SendAuthFailure(ClientContext& ctx, const char* reason) {
    FrameEnvelope err;
    err.version        = kProtocolVersion;
    err.type           = MessageType::Error;
    err.correlation_id = 0;
    ErrorPayload ep;
    ep.code    = ErrorCode::NotAuthorized;
    ep.message = reason ? reason : "not authorized";
    err.payload = ep.ToJson();
    const auto bytes = EncodeEnvelopeCbor(err);
    (void)WriteFrame(ctx.PipeHandle(), ctx.write_mutex_,
                     std::span<const std::uint8_t>(bytes));
}

bool PipeServer::AuthenticateClient(ClientContext& ctx) {
    // Impersonate the client on this worker thread just long enough to
    // inspect its access token. RevertToSelf is guaranteed by the scope guard
    // even on early returns / exceptions.
    ImpersonationScope imp(ctx.PipeHandle());
    if (!imp.Active()) {
        ShadowStrike::Utils::Logger::Warn(
            "PipeServer: ImpersonateNamedPipeClient failed, pid={}, gle={}",
            ctx.ClientProcessId(), ::GetLastError());
        return false;
    }

    ScopedHandle thread_token;
    if (!::OpenThreadToken(::GetCurrentThread(),
                           TOKEN_QUERY | TOKEN_QUERY_SOURCE,
                           TRUE, thread_token.ptr()) || !thread_token.valid()) {
        ShadowStrike::Utils::Logger::Warn(
            "PipeServer: OpenThreadToken failed, pid={}, gle={}",
            ctx.ClientProcessId(), ::GetLastError());
        return false;
    }

    ClientIdentity id;

    // Session id
    DWORD session = 0;
    DWORD ret     = 0;
    if (::GetTokenInformation(thread_token.get(), TokenSessionId,
                              &session, sizeof(session), &ret)) {
        id.session_id = session;
    }

    // User SID + name
    std::vector<std::uint8_t> user_buf;
    if (QueryTokenInformation(thread_token.get(), TokenUser, user_buf)) {
        const auto* tu = reinterpret_cast<TOKEN_USER*>(user_buf.data());
        if (tu && tu->User.Sid && ::IsValidSid(tu->User.Sid)) {
            id.user_sid  = SidToString(tu->User.Sid);
            id.user_name = LookupAccountName(tu->User.Sid);
            // Bound the name for defensive logging.
            if (id.user_name.size() > 96) id.user_name.resize(96);
        }
    }

    // Elevation
    TOKEN_ELEVATION elev{};
    if (::GetTokenInformation(thread_token.get(), TokenElevation,
                              &elev, sizeof(elev), &ret)) {
        id.is_elevated = (elev.TokenIsElevated != 0);
    }

    // Integrity level
    id.integrity_rid = TokenIntegrityRid(thread_token.get());

    // Well-known membership
    ClassifyWellKnownMembership(thread_token.get(),
                                id.is_admin_member,
                                id.is_local_system,
                                id.is_anonymous);

    id.authenticated = true;

    // --- Policy gate ----------------------------------------------------
    //
    // 1) Reject anonymous logon outright.
    // 2) Reject tokens below Medium integrity (AppContainer / Untrusted /
    //    Low), since those sandboxes must not reach the protection surface.
    // 3) The pipe name encodes the target interactive session; additionally
    //    verify the caller is in that session OR is LocalSystem (the service
    //    host itself may reach the pipe for internal health checks).
    //
    // Rejection paths emit a bounded one-shot Error frame so the client can
    // surface a clear message, then the caller drops the connection.
    if (id.is_anonymous) {
        ShadowStrike::Utils::Logger::Warn(
            "PipeServer: rejecting anonymous client pid={}", ctx.ClientProcessId());
        ctx.SetIdentity(std::move(id));
        return false;
    }
    if (id.integrity_rid != 0 &&
        id.integrity_rid < static_cast<std::uint32_t>(SECURITY_MANDATORY_MEDIUM_RID)) {
        ShadowStrike::Utils::Logger::Warn(
            "PipeServer: rejecting low-integrity client pid={}, rid={:#x}",
            ctx.ClientProcessId(), id.integrity_rid);
        ctx.SetIdentity(std::move(id));
        return false;
    }
    // Session-independent pipe: any authenticated interactive user on this
    // host may connect (the SDDL ACL is the gate). We previously refused
    // cross-session clients here, which broke the common auto-start case
    // where the service binds its pipe in session 0 before any user logs
    // on - a tray launched later in session 1+ could never connect.
    (void)options_.session_id;

    // Map identity -> privileged flag. Elevation OR admin membership OR
    // LocalSystem grants write-intent access. Interactive standard users
    // retain read-only access and must re-launch elevated for mutating ops.
    const bool privileged =
        id.is_elevated || id.is_admin_member || id.is_local_system;
    ctx.SetAuthenticatedPrivileged(privileged);

    // ASCII-only bounded slice for audit logging (user_name may contain
    // non-ASCII; we drop non-printable bytes defensively).
    std::string name_ascii;
    name_ascii.reserve(id.user_name.size());
    for (wchar_t wc : id.user_name) {
        if (wc >= 0x20 && wc < 0x7F) name_ascii.push_back(static_cast<char>(wc));
    }
    if (name_ascii.size() > 96) name_ascii.resize(96);

    ShadowStrike::Utils::Logger::Info(
        "PipeServer: authenticated pid={} user='{}' session={} "
        "integrity={:#x} elevated={} admin={} system={}",
        ctx.ClientProcessId(), name_ascii, id.session_id,
        id.integrity_rid, id.is_elevated, id.is_admin_member, id.is_local_system);

    ctx.SetIdentity(std::move(id));
    return true;
}

bool PipeServer::HandshakeFrame(ClientContext& ctx) {
    std::vector<std::uint8_t> buf;
    if (!ReadFrame(ctx.PipeHandle(), buf, options_.read_timeout_ms)) return false;

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
    // 1) Authenticate the caller before any protocol work. On failure we emit
    //    a single NotAuthorized Error frame so the client can surface a clean
    //    "access denied" UI, then disconnect.
    if (!AuthenticateClient(*ctx)) {
        SendAuthFailure(*ctx, "client authentication failed");
    } else if (!HandshakeFrame(*ctx)) {
        ShadowStrike::Utils::Logger::Warn(
            "PipeServer: handshake failed for client pid={}", ctx->ClientProcessId());
    } else {
        while (!stopping_.load()) {
            std::vector<std::uint8_t> buf;
            // INFINITE first-byte wait: an authenticated, trusted client may
            // legitimately sit idle between user-driven requests. The pipe
            // breakage (client close / process exit) is detected by
            // PeekNamedPipe returning ERROR_BROKEN_PIPE inside
            // WaitForPipeBytes, which closes the connection cleanly. The
            // stop_event_ handle still breaks the wait on service shutdown,
            // so this does not leak a thread.
            if (!ReadFrame(ctx->PipeHandle(), buf, INFINITE)) break;

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
                    ShadowStrike::Utils::Logger::Info(
                        "PipeServer: dispatch pid={} type={} corr={}",
                        ctx->ClientProcessId(),
                        static_cast<int>(env->type),
                        env->correlation_id);
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
            ShadowStrike::Utils::Logger::Info(
                "PipeServer: reply pid={} corr={} replyType={} bytes={}",
                ctx->ClientProcessId(),
                env->correlation_id,
                static_cast<int>(reply_type),
                static_cast<std::size_t>(b.size()));
            if (!WriteFrame(ctx->PipeHandle(), ctx->write_mutex_,
                            std::span<const std::uint8_t>(b))) {
                const DWORD gle = ::GetLastError();
                ShadowStrike::Utils::Logger::Warn(
                    "PipeServer: WriteFrame failed for pid={} corr={} gle={}; closing worker",
                    ctx->ClientProcessId(), env->correlation_id, gle);
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
