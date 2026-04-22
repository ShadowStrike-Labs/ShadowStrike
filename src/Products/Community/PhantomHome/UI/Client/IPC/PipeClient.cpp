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
 * ShadowStrike NGAV - PHANTOM HOME UI IPC PIPE CLIENT IMPLEMENTATION
 * ============================================================================
 *
 * @file PipeClient.cpp
 * @brief Full implementation of the service-side named-pipe IPC client.
 *
 * Threading model:
 *   I/O thread  — dedicated std::jthread running IoThreadProc; owns the pipe
 *                 handle and all overlapped I/O.  Never touches Qt objects
 *                 directly — all callbacks are posted via invokeMethod.
 *   Watchdog    — separate std::jthread scanning pending-request map every
 *                 250 ms for expired entries and synthesising timeout responses.
 *   Qt main     — all ResponseCallback / EventCallback invocations arrive here
 *                 via Qt::QueuedConnection.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * ============================================================================
 */

// NotUsing precompiled header — this TU mixes Qt and Windows raw API.
#include "PipeClient.hpp"

// Logger MUST precede Qt headers (Windows.h macro ordering).
#include <PhantomCore/Utils/Logger.hpp>
#include <PhantomCore/Service/IpcAuthToken.hpp>
#include <Products/Community/PhantomHome/UI/IPC/Messages.hpp>

// Qt
#include <QCoreApplication>
#include <QJsonDocument>
#include <QMetaObject>
#include <QPointer>

// Standard library
#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <shared_mutex>
#include <span>
#include <stop_token>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

// Windows SDK (already pulled in by Logger.hpp → Windows.h).
// Explicit supplement for named-pipe / overlapped I/O symbols:
#include <winerror.h>

namespace ShadowStrike::PhantomHome::UI::IPC {

using namespace ShadowStrike::Service;
using namespace ShadowStrike::PhantomHome::IPC;

// ============================================================================
// MODULE-PRIVATE CONSTANTS
// ============================================================================

namespace {

constexpr const wchar_t* kLog          = L"PipeClient";
constexpr std::size_t    kMaxPending   = 256;
constexpr std::size_t    kMaxQueue     = 256;
constexpr DWORD          kAuthTimeoutMs = 3000;
constexpr DWORD          kWatchdogMs   = 250;

// Build version string re-used in AuthHandshake payload.
constexpr const char*    kClientBuild  = "3.0.0";

} // namespace

// ============================================================================
// RAII HANDLE WRAPPER
// ============================================================================

struct UniqueHandle {
    HANDLE h = INVALID_HANDLE_VALUE;

    UniqueHandle() noexcept = default;
    explicit UniqueHandle(HANDLE h_) noexcept : h(h_) {}

    ~UniqueHandle() noexcept { reset(); }

    UniqueHandle(UniqueHandle&& o) noexcept
        : h(std::exchange(o.h, INVALID_HANDLE_VALUE)) {}

    UniqueHandle& operator=(UniqueHandle&& o) noexcept {
        if (this != &o) {
            reset();
            h = std::exchange(o.h, INVALID_HANDLE_VALUE);
        }
        return *this;
    }

    UniqueHandle(const UniqueHandle&)            = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    void reset() noexcept {
        if (valid()) {
            CloseHandle(h);
            h = INVALID_HANDLE_VALUE;
        }
    }

    [[nodiscard]] bool   valid()  const noexcept { return h != INVALID_HANDLE_VALUE && h != nullptr; }
    [[nodiscard]] HANDLE get()    const noexcept { return h; }
    void                 release() noexcept       { h = INVALID_HANDLE_VALUE; }
};

// ============================================================================
// JSON CONVERSION HELPERS (module-private)
// ============================================================================

namespace {

[[nodiscard]] nlohmann::json QJsonObjectToNlohmann(const QJsonObject& obj)
{
    QJsonDocument doc(obj);
    const std::string jsonStr = doc.toJson(QJsonDocument::Compact).toStdString();
    auto j = nlohmann::json::parse(jsonStr, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded()) return nlohmann::json::object();
    return j;
}

[[nodiscard]] QJsonObject NlohmannToQJsonObject(const nlohmann::json& j)
{
    if (!j.is_object()) return {};
    try {
        const std::string jsonStr = j.dump();
        const QJsonDocument doc   = QJsonDocument::fromJson(
            QByteArray(jsonStr.data(), static_cast<qsizetype>(jsonStr.size())));
        return doc.object();
    } catch (...) {
        return {};
    }
}

// Marshal a callback to the Qt main thread safely.
// Guards against a destroyed QCoreApplication (can happen at static dtor).
template<typename Fn>
void PostToMain(Fn&& fn)
{
    QCoreApplication* app = QCoreApplication::instance();
    if (!app) {
        // Application is shutting down; skip the marshal.
        return;
    }
    QMetaObject::invokeMethod(app, std::forward<Fn>(fn), Qt::QueuedConnection);
}

} // namespace

// ============================================================================
// IMPL DECLARATION
// ============================================================================

struct PipeClient::Impl {

    // ---- Construction -------------------------------------------------------
    explicit Impl(PipeClient* owner) noexcept;
    ~Impl();

    // ---- Public surface called from PipeClient's public methods -------------
    [[nodiscard]] bool Start();
    void               Stop();

    [[nodiscard]] bool            IsConnected()  const noexcept;
    [[nodiscard]] int             StateRaw()     const noexcept;
    [[nodiscard]] PipeClientState CurrentState() const noexcept;

    void                 Send(CommandType t, const QJsonObject& p);
    [[nodiscard]] std::uint64_t SendAndExpect(CommandType t, const QJsonObject& p,
                                              ResponseCallback onDone,
                                              std::chrono::milliseconds timeout);
    [[nodiscard]] std::uint64_t Subscribe(CommandType eventType, EventCallback cb);
    void                 Unsubscribe(std::uint64_t token);

    // ---- State --------------------------------------------------------------
    mutable std::shared_mutex m_stateMutex;
    PipeClientState           m_state{ PipeClientState::Disconnected };
    std::atomic<bool>         m_fatalFlag{ false };

    // ---- I/O thread ---------------------------------------------------------
    UniqueHandle  m_stopEvent;    // manual-reset; set in Stop()
    UniqueHandle  m_queueSignal;  // auto-reset; set when m_outQueue gains an item
    std::jthread  m_ioThread;
    std::jthread  m_watchdogThread;

    // ---- Pending requests ---------------------------------------------------
    struct PendingEntry {
        std::chrono::steady_clock::time_point expiry;
        ResponseCallback                      cb;
    };
    std::mutex                                    m_pendingMutex;
    std::unordered_map<std::uint64_t, PendingEntry> m_pendingRequests;

    // ---- Outbound queue -----------------------------------------------------
    std::mutex                           m_queueMutex;
    std::queue<std::vector<std::uint8_t>> m_outQueue;

    // ---- Subscriptions ------------------------------------------------------
    std::mutex m_subsMutex;
    std::unordered_map<std::uint64_t,
        std::pair<CommandType, EventCallback>> m_subscriptions;

    // ---- Atomic IDs ---------------------------------------------------------
    std::atomic<std::uint64_t> m_nextRequestId{ 1 };
    std::atomic<std::uint64_t> m_nextSubId{ 1 };

    // ---- Back-pointer -------------------------------------------------------
    PipeClient* const m_q;

    // ---- I/O thread procedures ----------------------------------------------
    void IoThreadProc(std::stop_token stoken);

    [[nodiscard]] UniqueHandle  AttemptConnect(std::stop_token stoken);
    [[nodiscard]] bool          PerformAuth(HANDLE hPipe, std::stop_token stoken);
    [[nodiscard]] bool          RunIoLoop(HANDLE hPipe, std::stop_token stoken);

    void WatchdogProc(std::stop_token stoken);

    // ---- Helpers ------------------------------------------------------------
    void TransitionState(PipeClientState newState, const wchar_t* reason);
    void FailAllPending(const char* errorCode, const char* errorMsg);
    void DrainOutboundWithError(const char* errorCode);

    [[nodiscard]] bool EnqueueSerialized(std::vector<std::uint8_t> data);
    [[nodiscard]] std::vector<std::uint8_t> BuildEnvelope(CommandType t,
                                                          std::uint64_t reqId,
                                                          const QJsonObject& p);

    void OnEnvelopeReceived(const Envelope& env);
    void ResolveResponse(std::uint64_t reqId, Response resp);
    void FanOutEvent(CommandType type, QJsonObject payload);

    // Overlapped write helper: write data, handle ERROR_IO_PENDING using
    // waitHandles[2]={writeEvent, stopEvent}, cancel on stop signal.
    [[nodiscard]] bool DoWrite(HANDLE hPipe, OVERLAPPED& ovlp,
                               const std::vector<std::uint8_t>& data);
};

// ============================================================================
// IMPL — CONSTRUCTION / DESTRUCTION
// ============================================================================

PipeClient::Impl::Impl(PipeClient* owner) noexcept
    : m_q(owner)
{
    m_stopEvent   = UniqueHandle(CreateEventW(nullptr, /*manual*/TRUE,  FALSE, nullptr));
    m_queueSignal = UniqueHandle(CreateEventW(nullptr, /*auto*/ FALSE, FALSE, nullptr));
}

PipeClient::Impl::~Impl()
{
    Stop();
}

// ============================================================================
// IMPL — LIFECYCLE
// ============================================================================

bool PipeClient::Impl::Start()
{
    // If either event creation failed (system resource exhaustion), abort.
    if (!m_stopEvent.valid() || !m_queueSignal.valid()) {
        SS_LOG_ERROR(kLog, L"PipeClient::Start — event creation failed (resource exhaustion).");
        return false;
    }

    // Idempotency: don't restart if already running.
    {
        std::shared_lock lk(m_stateMutex);
        if (m_state != PipeClientState::Disconnected &&
            m_state != PipeClientState::Fatal) {
            return true;
        }
    }

    // Reset stop event and fatal flag so the new io thread can proceed.
    ResetEvent(m_stopEvent.get());
    m_fatalFlag.store(false, std::memory_order_release);

    m_ioThread       = std::jthread([this](std::stop_token st) { IoThreadProc(st); });
    m_watchdogThread = std::jthread([this](std::stop_token st) { WatchdogProc(st); });

    SS_LOG_INFO(kLog, L"PipeClient started — I/O and watchdog threads launched.");
    return true;
}

void PipeClient::Impl::Stop()
{
    if (m_stopEvent.valid()) {
        SetEvent(m_stopEvent.get());
    }

    if (m_ioThread.joinable()) {
        m_ioThread.request_stop();
        m_ioThread.join();
    }
    if (m_watchdogThread.joinable()) {
        m_watchdogThread.request_stop();
        m_watchdogThread.join();
    }

    // Drain any remaining pending requests synchronously (no Qt event loop
    // needed — we call the callbacks directly from the caller's thread since
    // the I/O thread is already joined and no callbacks are being posted).
    FailAllPending("stopped", "PipeClient was stopped");

    TransitionState(PipeClientState::Disconnected, L"Stop() called");
    SS_LOG_INFO(kLog, L"PipeClient stopped.");
}

// ============================================================================
// IMPL — STATE ACCESSORS
// ============================================================================

bool PipeClient::Impl::IsConnected() const noexcept
{
    std::shared_lock lk(m_stateMutex);
    return m_state == PipeClientState::Connected;
}

int PipeClient::Impl::StateRaw() const noexcept
{
    std::shared_lock lk(m_stateMutex);
    return static_cast<int>(m_state);
}

PipeClientState PipeClient::Impl::CurrentState() const noexcept
{
    std::shared_lock lk(m_stateMutex);
    return m_state;
}

// ============================================================================
// IMPL — MESSAGING (called from any thread)
// ============================================================================

void PipeClient::Impl::Send(CommandType t, const QJsonObject& p)
{
    auto data = BuildEnvelope(t, /*requestId=*/0, p);
    if (data.empty()) {
        SS_LOG_WARN(kLog, L"Send: envelope serialisation failed for verb %u",
                    static_cast<unsigned>(t));
        return;
    }
    if (!EnqueueSerialized(std::move(data))) {
        SS_LOG_WARN(kLog, L"Send: outbound queue full (backpressure) for verb %u",
                    static_cast<unsigned>(t));
    }
}

std::uint64_t PipeClient::Impl::SendAndExpect(CommandType t, const QJsonObject& p,
                                               ResponseCallback onDone,
                                               std::chrono::milliseconds timeout)
{
    // Check pending map capacity first (under lock).
    {
        std::lock_guard lk(m_pendingMutex);
        if (m_pendingRequests.size() >= kMaxPending) {
            // Backpressure — post a synthetic error to maintain the contract.
            PostToMain([cb = std::move(onDone)]() {
                Response r;
                r.ok           = false;
                r.errorCode    = QStringLiteral("backpressure");
                r.errorMessage = QStringLiteral("Pending-request capacity exhausted");
                cb(r);
            });
            return 0;
        }
    }

    const std::uint64_t reqId = m_nextRequestId.fetch_add(1, std::memory_order_relaxed);

    auto data = BuildEnvelope(t, reqId, p);
    if (data.empty()) {
        SS_LOG_WARN(kLog, L"SendAndExpect: serialisation failed for verb %u",
                    static_cast<unsigned>(t));
        PostToMain([cb = std::move(onDone)]() {
            Response r;
            r.ok           = false;
            r.errorCode    = QStringLiteral("serialisation");
            r.errorMessage = QStringLiteral("Envelope serialisation failed");
            cb(r);
        });
        return 0;
    }

    // Register pending entry.
    {
        std::lock_guard lk(m_pendingMutex);
        m_pendingRequests.emplace(reqId, PendingEntry{
            std::chrono::steady_clock::now() + timeout,
            std::move(onDone)
        });
    }

    // Enqueue the serialised bytes.
    if (!EnqueueSerialized(std::move(data))) {
        // Queue is full — remove the pending entry and report backpressure.
        ResponseCallback cb;
        {
            std::lock_guard lk(m_pendingMutex);
            auto it = m_pendingRequests.find(reqId);
            if (it != m_pendingRequests.end()) {
                cb = std::move(it->second.cb);
                m_pendingRequests.erase(it);
            }
        }
        if (cb) {
            PostToMain([cb = std::move(cb)]() {
                Response r;
                r.ok           = false;
                r.errorCode    = QStringLiteral("backpressure");
                r.errorMessage = QStringLiteral("Outbound queue capacity exhausted");
                cb(r);
            });
        }
        return 0;
    }

    return reqId;
}

std::uint64_t PipeClient::Impl::Subscribe(CommandType eventType, EventCallback cb)
{
    const std::uint64_t token = m_nextSubId.fetch_add(1, std::memory_order_relaxed);
    std::lock_guard lk(m_subsMutex);
    m_subscriptions.emplace(token, std::make_pair(eventType, std::move(cb)));
    return token;
}

void PipeClient::Impl::Unsubscribe(std::uint64_t token)
{
    std::lock_guard lk(m_subsMutex);
    m_subscriptions.erase(token);
}

// ============================================================================
// IMPL — HELPERS
// ============================================================================

void PipeClient::Impl::TransitionState(PipeClientState newState, const wchar_t* reason)
{
    PipeClientState old;
    {
        std::unique_lock lk(m_stateMutex);
        old = m_state;
        if (old == newState) return;
        m_state = newState;
    }

    if (newState == PipeClientState::Fatal) {
        m_fatalFlag.store(true, std::memory_order_release);
    }

    SS_LOG_INFO(kLog, L"State %d → %d: %ls",
                static_cast<int>(old), static_cast<int>(newState), reason);

    const int from     = static_cast<int>(old);
    const int to       = static_cast<int>(newState);
    const QString qReason = QString::fromWCharArray(reason);

    PostToMain([qObj = QPointer<PipeClient>(m_q), from, to, qReason]() {
        if (qObj) {
            emit qObj->stateChanged();
            emit qObj->stateTransition(from, to, qReason);
        }
    });
}

void PipeClient::Impl::FailAllPending(const char* errorCode, const char* errorMsg)
{
    std::unordered_map<std::uint64_t, PendingEntry> snapshot;
    {
        std::lock_guard lk(m_pendingMutex);
        snapshot = std::move(m_pendingRequests);
        m_pendingRequests.clear();
    }
    for (auto& [reqId, entry] : snapshot) {
        Response r;
        r.ok           = false;
        r.errorCode    = QString::fromLatin1(errorCode);
        r.errorMessage = QString::fromLatin1(errorMsg);
        PostToMain([cb = std::move(entry.cb), r]() mutable { cb(r); });
    }
}

void PipeClient::Impl::DrainOutboundWithError(const char* errorCode)
{
    // Grab any requests from the outbound queue whose pending entries haven't
    // been assigned a response yet, and resolve them with the given error.
    // Note: items in m_outQueue that have no pending entry (fire-and-forget)
    // are simply discarded here.
    std::queue<std::vector<std::uint8_t>> local;
    {
        std::lock_guard lk(m_queueMutex);
        local = std::move(m_outQueue);
        // Reconstruct empty queue.
        m_outQueue = {};
    }
    // Items discarded — callers who registered pending entries will be resolved
    // by FailAllPending.
    (void)local;
    (void)errorCode;
}

bool PipeClient::Impl::EnqueueSerialized(std::vector<std::uint8_t> data)
{
    {
        std::lock_guard lk(m_queueMutex);
        if (m_outQueue.size() >= kMaxQueue) return false;
        m_outQueue.push(std::move(data));
    }
    // Signal the I/O thread that a new item is available.
    if (m_queueSignal.valid()) SetEvent(m_queueSignal.get());
    return true;
}

std::vector<std::uint8_t> PipeClient::Impl::BuildEnvelope(CommandType t,
                                                           std::uint64_t reqId,
                                                           const QJsonObject& p)
{
    Envelope env;
    env.type      = t;
    env.requestId = reqId;
    env.payload   = QJsonObjectToNlohmann(p);
    return env.Serialize();
}

// ============================================================================
// IMPL — OVERLAPPED WRITE HELPER
// ============================================================================

bool PipeClient::Impl::DoWrite(HANDLE hPipe, OVERLAPPED& ovlp,
                                const std::vector<std::uint8_t>& data)
{
    HANDLE hWriteEv = ovlp.hEvent;
    ResetEvent(hWriteEv);

    DWORD written = 0;
    BOOL ok = WriteFile(hPipe, data.data(), static_cast<DWORD>(data.size()),
                        &written, &ovlp);
    if (ok) {
        // Immediate synchronous completion.
        return true;
    }

    DWORD err = GetLastError();
    if (err != ERROR_IO_PENDING) {
        SS_LOG_WARN(kLog, L"WriteFile failed immediately: %lu", err);
        return false;
    }

    // Wait for write to finish or stop signal.
    HANDLE waits[2] = { hWriteEv, m_stopEvent.get() };
    DWORD  wr       = WaitForMultipleObjects(2, waits, FALSE, INFINITE);

    if (wr == WAIT_OBJECT_0 + 1) {
        // Stop requested — cancel this I/O.
        CancelIoEx(hPipe, &ovlp);
        DWORD tmp = 0;
        GetOverlappedResult(hPipe, &ovlp, &tmp, TRUE);
        return false;
    }

    if (wr != WAIT_OBJECT_0) {
        SS_LOG_WARN(kLog, L"WaitForMultipleObjects (write) unexpected: %lu", wr);
        return false;
    }

    if (!GetOverlappedResult(hPipe, &ovlp, &written, FALSE)) {
        DWORD werr = GetLastError();
        SS_LOG_WARN(kLog, L"GetOverlappedResult (write) failed: %lu", werr);
        return false;
    }

    return true;
}

// ============================================================================
// IMPL — IO THREAD: CONNECT LOOP
// ============================================================================

UniqueHandle PipeClient::Impl::AttemptConnect(std::stop_token stoken)
{
    DWORD backoffMs = 250;

    while (!stoken.stop_requested()) {
        HANDLE h = CreateFileW(
            CommunicationConstants::PIPE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0,           // no sharing
            nullptr,     // default security
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            nullptr);

        if (h != INVALID_HANDLE_VALUE) {
            DWORD mode = PIPE_READMODE_MESSAGE;
            if (!SetNamedPipeHandleState(h, &mode, nullptr, nullptr)) {
                SS_LOG_WARN(kLog, L"SetNamedPipeHandleState failed: %lu — closing pipe.",
                            GetLastError());
                CloseHandle(h);
                // Fall through to backoff.
            } else {
                return UniqueHandle(h);
            }
        } else {
            DWORD err = GetLastError();
            if (err == ERROR_PIPE_BUSY) {
                // Server has instances but all are busy; use the documented wait.
                if (!WaitNamedPipeW(CommunicationConstants::PIPE_NAME, 2000)) {
                    SS_LOG_INFO(kLog, L"WaitNamedPipeW timed out — retrying.");
                }
                continue; // Retry without backoff increment.
            }
            SS_LOG_WARN(kLog, L"CreateFileW failed: %lu — backoff %lu ms.", err, backoffMs);
        }

        // Exponential backoff with cancellable sleep.
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(backoffMs);
        while (!stoken.stop_requested() &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        backoffMs = std::min(backoffMs * 2, DWORD{5000});
    }

    return {}; // stop_requested
}

// ============================================================================
// IMPL — IO THREAD: AUTH HANDSHAKE
// ============================================================================

bool PipeClient::Impl::PerformAuth(HANDLE hPipe, std::stop_token stoken)
{
    // Read the session token from disk.
    const std::string token = IpcAuthToken::ReadForCurrentSession();
    if (token.empty()) {
        SS_LOG_ERROR(kLog,
            L"IpcAuthToken::ReadForCurrentSession returned empty — "
            L"cannot authenticate. Entering Fatal state.");
        TransitionState(PipeClientState::Fatal, L"Auth token unavailable — cannot authenticate");
        return false;
    }

    // Build the AuthHandshake envelope.
    const std::uint64_t authReqId = m_nextRequestId.fetch_add(1, std::memory_order_relaxed);

    Envelope authEnv;
    authEnv.type      = CommandType::AuthHandshake;
    authEnv.requestId = authReqId;
    authEnv.payload   = {
        { "token",           token         },
        { "protocolVersion", static_cast<std::int64_t>(kProtocolVersion) },
        { "clientBuild",     kClientBuild  }
    };

    const auto wireData = authEnv.Serialize();
    if (wireData.empty()) {
        SS_LOG_ERROR(kLog, L"Failed to serialise AuthHandshake envelope.");
        TransitionState(PipeClientState::Fatal, L"Auth envelope serialisation failed");
        return false;
    }

    // Write the AuthHandshake using overlapped I/O (cancellable on stop).
    UniqueHandle hWriteEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!hWriteEvent.valid()) {
        SS_LOG_ERROR(kLog, L"CreateEvent for auth write failed: %lu", GetLastError());
        return false;
    }

    OVERLAPPED writeOvlp{};
    writeOvlp.hEvent = hWriteEvent.get();

    if (!DoWrite(hPipe, writeOvlp, wireData)) {
        SS_LOG_ERROR(kLog, L"Failed to write AuthHandshake to pipe.");
        if (stoken.stop_requested()) return false;
        TransitionState(PipeClientState::Fatal, L"Auth write failed");
        return false;
    }

    if (stoken.stop_requested()) return false;

    // Read the auth response with a kAuthTimeoutMs deadline.
    constexpr std::size_t kReadBufSize =
        static_cast<std::size_t>(kMaxPayloadBytes) + 24u + 64u;
    std::vector<std::uint8_t> readBuf(kReadBufSize);

    UniqueHandle hReadEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!hReadEvent.valid()) {
        SS_LOG_ERROR(kLog, L"CreateEvent for auth read failed: %lu", GetLastError());
        return false;
    }

    OVERLAPPED readOvlp{};
    readOvlp.hEvent = hReadEvent.get();

    ResetEvent(hReadEvent.get());
    DWORD bytesRead = 0;
    BOOL  readOk    = ReadFile(hPipe, readBuf.data(),
                               static_cast<DWORD>(readBuf.size()),
                               &bytesRead, &readOvlp);

    if (!readOk && GetLastError() != ERROR_IO_PENDING) {
        DWORD err = GetLastError();
        SS_LOG_ERROR(kLog, L"ReadFile for auth response failed: %lu", err);
        return false;
    }

    // Wait up to kAuthTimeoutMs for the response or a stop signal.
    HANDLE waits[2] = { hReadEvent.get(), m_stopEvent.get() };
    DWORD  wr       = WaitForMultipleObjects(2, waits, FALSE, kAuthTimeoutMs);

    if (wr == WAIT_OBJECT_0 + 1 || stoken.stop_requested()) {
        // Stop requested.
        CancelIoEx(hPipe, &readOvlp);
        DWORD tmp = 0; GetOverlappedResult(hPipe, &readOvlp, &tmp, TRUE);
        return false;
    }

    if (wr == WAIT_TIMEOUT) {
        CancelIoEx(hPipe, &readOvlp);
        DWORD tmp = 0; GetOverlappedResult(hPipe, &readOvlp, &tmp, TRUE);
        SS_LOG_ERROR(kLog, L"Auth handshake timed out after %lu ms.", kAuthTimeoutMs);
        TransitionState(PipeClientState::Fatal, L"Auth handshake timed out");
        PostToMain([qObj = QPointer<PipeClient>(m_q)]() {
            if (qObj) emit qObj->authRejected(QStringLiteral("AUTH_TIMEOUT"));
        });
        return false;
    }

    if (wr != WAIT_OBJECT_0) {
        SS_LOG_ERROR(kLog, L"WaitForMultipleObjects (auth read) failed: %lu", GetLastError());
        return false;
    }

    if (!GetOverlappedResult(hPipe, &readOvlp, &bytesRead, FALSE)) {
        SS_LOG_ERROR(kLog, L"GetOverlappedResult (auth read) failed: %lu", GetLastError());
        return false;
    }

    readBuf.resize(bytesRead);
    const auto maybeEnv = Envelope::Deserialize(
        std::span<const std::uint8_t>(readBuf.data(), readBuf.size()));

    if (!maybeEnv) {
        SS_LOG_ERROR(kLog, L"Auth response envelope failed to deserialise (%lu bytes).",
                     bytesRead);
        TransitionState(PipeClientState::Fatal, L"Auth response malformed");
        return false;
    }

    // Check for explicit AuthFailed push.
    if (maybeEnv->type == CommandType::AuthFailed) {
        const auto reason = GetField<std::string>(maybeEnv->payload, "reason")
                                .value_or("AUTH_REJECTED");
        SS_LOG_ERROR(kLog, L"Service rejected authentication: %hs", reason.c_str());
        TransitionState(PipeClientState::Fatal, L"Auth rejected by service");
        const QString qReason = QString::fromStdString(reason);
        PostToMain([qObj = QPointer<PipeClient>(m_q), qReason]() {
            if (qObj) emit qObj->authRejected(qReason);
        });
        return false;
    }

    // Check ok field in the response payload.
    const auto okField = GetField<bool>(maybeEnv->payload, "ok");
    if (!okField.has_value() || !okField.value()) {
        std::string reason = "AUTH_FAILED";
        if (maybeEnv->payload.contains("error")) {
            auto r = GetField<std::string>(maybeEnv->payload.at("error"), "code");
            if (r.has_value()) reason = r.value();
        }
        SS_LOG_ERROR(kLog, L"Auth handshake response: ok=false — %hs", reason.c_str());
        TransitionState(PipeClientState::Fatal, L"Auth rejected — ok=false");
        const QString qReason = QString::fromStdString(reason);
        PostToMain([qObj = QPointer<PipeClient>(m_q), qReason]() {
            if (qObj) emit qObj->authRejected(qReason);
        });
        return false;
    }

    SS_LOG_INFO(kLog, L"Authentication succeeded (reqId=%llu).", authReqId);
    return true;
}

// ============================================================================
// IMPL — IO THREAD: MAIN I/O LOOP
// ============================================================================

bool PipeClient::Impl::RunIoLoop(HANDLE hPipe, std::stop_token stoken)
{
    // Per-iteration read buffer — sized to the maximum possible frame.
    constexpr std::size_t kReadBufSize =
        static_cast<std::size_t>(kMaxPayloadBytes) + 24u + 64u;
    std::vector<std::uint8_t> readBuf(kReadBufSize);

    UniqueHandle hReadEvent (CreateEventW(nullptr, TRUE,  FALSE, nullptr));
    UniqueHandle hWriteEvent(CreateEventW(nullptr, TRUE,  FALSE, nullptr));
    if (!hReadEvent.valid() || !hWriteEvent.valid()) {
        SS_LOG_ERROR(kLog, L"Failed to create I/O events for IoLoop: %lu", GetLastError());
        return true; // trigger reconnect
    }

    OVERLAPPED readOvlp{}, writeOvlp{};
    readOvlp.hEvent  = hReadEvent.get();
    writeOvlp.hEvent = hWriteEvent.get();

    bool         readIssued          = false;
    std::uint32_t consecutiveFails   = 0;
    constexpr std::uint32_t kMaxFails = 3;

    while (!stoken.stop_requested()) {

        // ── Issue pending read ─────────────────────────────────────────────
        if (!readIssued) {
            ResetEvent(hReadEvent.get());
            DWORD bytesRead = 0;
            BOOL  ok        = ReadFile(hPipe, readBuf.data(),
                                       static_cast<DWORD>(readBuf.size()),
                                       &bytesRead, &readOvlp);
            if (ok) {
                // Immediate synchronous completion.
                const auto maybeEnv = Envelope::Deserialize(
                    std::span<const std::uint8_t>(readBuf.data(), bytesRead));
                if (!maybeEnv) {
                    ++consecutiveFails;
                    SS_LOG_WARN(kLog, L"Deserialise failed (%lu bytes); failures=%u",
                                bytesRead, consecutiveFails);
                    if (consecutiveFails >= kMaxFails) {
                        SS_LOG_ERROR(kLog, L"3 consecutive read failures — disconnecting.");
                        return true; // trigger reconnect
                    }
                } else {
                    consecutiveFails = 0;
                    OnEnvelopeReceived(*maybeEnv);
                    if (m_fatalFlag.load(std::memory_order_acquire)) return false;
                }
                // readIssued remains false — will re-issue on next iteration.
                continue;
            } else {
                DWORD err = GetLastError();
                if (err == ERROR_IO_PENDING) {
                    readIssued = true;
                } else if (err == ERROR_BROKEN_PIPE ||
                           err == ERROR_PIPE_NOT_CONNECTED ||
                           err == ERROR_NO_DATA) {
                    SS_LOG_INFO(kLog, L"Pipe disconnected during ReadFile: %lu", err);
                    return true; // trigger reconnect
                } else {
                    SS_LOG_WARN(kLog, L"ReadFile failed: %lu", err);
                    return true;
                }
            }
        }

        // ── Drain outbound queue (one item per iteration) ──────────────────
        {
            std::vector<std::uint8_t> outItem;
            {
                std::lock_guard lk(m_queueMutex);
                if (!m_outQueue.empty()) {
                    outItem = std::move(m_outQueue.front());
                    m_outQueue.pop();
                }
            }
            if (!outItem.empty()) {
                if (!DoWrite(hPipe, writeOvlp, outItem)) {
                    DWORD err = GetLastError();
                    if (err == ERROR_BROKEN_PIPE || err == ERROR_NO_DATA ||
                        err == ERROR_PIPE_NOT_CONNECTED) {
                        SS_LOG_INFO(kLog, L"Pipe lost during write: %lu", err);
                    } else {
                        SS_LOG_WARN(kLog, L"Write failed: %lu", err);
                    }
                    DrainOutboundWithError("disconnected");
                    return !stoken.stop_requested(); // reconnect unless stopping
                }
                continue; // Check queue again immediately.
            }
        }

        // ── Wait for read completion, stop, or new queue item ─────────────
        HANDLE waits[3] = {
            hReadEvent.get(),     // [0] read complete
            m_stopEvent.get(),    // [1] shutdown
            m_queueSignal.get()   // [2] new outbound item (auto-reset)
        };
        DWORD wr = WaitForMultipleObjects(3, waits, FALSE, INFINITE);

        if (wr == WAIT_OBJECT_0 + 0) {
            // Read completed.
            if (readIssued) {
                DWORD bytesRead = 0;
                if (!GetOverlappedResult(hPipe, &readOvlp, &bytesRead, FALSE)) {
                    DWORD err = GetLastError();
                    if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED) {
                        SS_LOG_INFO(kLog, L"Pipe disconnected (read result): %lu", err);
                        return true;
                    }
                    ++consecutiveFails;
                    SS_LOG_WARN(kLog, L"GetOverlappedResult failed: %lu; failures=%u",
                                err, consecutiveFails);
                    if (consecutiveFails >= kMaxFails) {
                        SS_LOG_ERROR(kLog, L"3 consecutive failures — disconnecting.");
                        return true;
                    }
                    readIssued = false;
                    continue;
                }

                readIssued = false;
                const auto maybeEnv = Envelope::Deserialize(
                    std::span<const std::uint8_t>(readBuf.data(), bytesRead));

                if (!maybeEnv) {
                    ++consecutiveFails;
                    SS_LOG_WARN(kLog, L"Deserialise failed (%lu bytes); failures=%u",
                                bytesRead, consecutiveFails);
                    if (consecutiveFails >= kMaxFails) {
                        SS_LOG_ERROR(kLog, L"3 consecutive deserialise failures — disconnecting.");
                        return true;
                    }
                } else {
                    consecutiveFails = 0;
                    OnEnvelopeReceived(*maybeEnv);
                    if (m_fatalFlag.load(std::memory_order_acquire)) return false;
                }
            }

        } else if (wr == WAIT_OBJECT_0 + 1) {
            // Stop event — cancel any pending read.
            if (readIssued) {
                CancelIoEx(hPipe, &readOvlp);
                DWORD tmp = 0;
                GetOverlappedResult(hPipe, &readOvlp, &tmp, TRUE);
            }
            return false; // do not reconnect

        } else if (wr == WAIT_OBJECT_0 + 2) {
            // queueSignal fired (auto-reset, already cleared by WaitForMultipleObjects).
            // The loop top will drain the queue.

        } else {
            // WAIT_FAILED or unexpected.
            SS_LOG_ERROR(kLog, L"WaitForMultipleObjects failed in IoLoop: %lu", GetLastError());
            return true; // trigger reconnect
        }
    }

    // stop_token requested.
    if (readIssued) {
        CancelIoEx(hPipe, &readOvlp);
        DWORD tmp = 0;
        GetOverlappedResult(hPipe, &readOvlp, &tmp, TRUE);
    }
    return false;
}

// ============================================================================
// IMPL — IO THREAD: MAIN PROC
// ============================================================================

void PipeClient::Impl::IoThreadProc(std::stop_token stoken)
{
    DWORD reconnectBackoffMs = 250;

    while (!stoken.stop_requested() &&
           !m_fatalFlag.load(std::memory_order_acquire)) {

        // ── CONNECTING ───────────────────────────────────────────────────────
        TransitionState(PipeClientState::Connecting, L"Attempting pipe connection");

        UniqueHandle hPipe = AttemptConnect(stoken);
        if (!hPipe.valid()) {
            // stop_requested — exit.
            break;
        }
        if (stoken.stop_requested()) break;

        // ── AUTHENTICATING ───────────────────────────────────────────────────
        TransitionState(PipeClientState::Authenticating, L"Pipe connected; authenticating");

        if (!PerformAuth(hPipe.get(), stoken)) {
            // Fatal or stopped.
            break;
        }
        if (stoken.stop_requested()) break;

        // ── CONNECTED ────────────────────────────────────────────────────────
        TransitionState(PipeClientState::Connected, L"Authentication succeeded");

        // Signal the I/O loop that there may be queued outbound data.
        if (m_queueSignal.valid()) SetEvent(m_queueSignal.get());

        const bool shouldReconnect = RunIoLoop(hPipe.get(), stoken);

        if (!shouldReconnect || stoken.stop_requested() ||
            m_fatalFlag.load(std::memory_order_acquire)) {
            break;
        }

        // ── RECONNECTING ─────────────────────────────────────────────────────
        TransitionState(PipeClientState::Reconnecting,
                        L"Connection lost — pending reconnect with backoff");

        FailAllPending("disconnected", "Pipe connection was lost");
        DrainOutboundWithError("disconnected");

        // Exponential backoff: 250→500→1000→2000→cap 5000 ms.
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(reconnectBackoffMs);
        while (!stoken.stop_requested() &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        reconnectBackoffMs = std::min(reconnectBackoffMs * 2, DWORD{5000});
    }

    // Final cleanup.
    FailAllPending("stopped", "PipeClient I/O thread exited");
    TransitionState(PipeClientState::Disconnected, L"I/O thread exited");
    SS_LOG_INFO(kLog, L"IoThreadProc exited.");
}

// ============================================================================
// IMPL — WATCHDOG THREAD
// ============================================================================

void PipeClient::Impl::WatchdogProc(std::stop_token stoken)
{
    while (!stoken.stop_requested()) {
        // Sleep in 10ms slices so we honour stop_token promptly.
        for (int i = 0; i < static_cast<int>(kWatchdogMs / 10) && !stoken.stop_requested(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (stoken.stop_requested()) break;

        const auto now = std::chrono::steady_clock::now();
        std::vector<std::pair<std::uint64_t, ResponseCallback>> expired;

        {
            std::lock_guard lk(m_pendingMutex);
            for (auto it = m_pendingRequests.begin(); it != m_pendingRequests.end(); ) {
                if (it->second.expiry <= now) {
                    expired.emplace_back(it->first, std::move(it->second.cb));
                    it = m_pendingRequests.erase(it);
                } else {
                    ++it;
                }
            }
        }

        for (auto& [reqId, cb] : expired) {
            SS_LOG_WARN(kLog, L"Request %llu timed out.", reqId);
            PostToMain([cb = std::move(cb)]() mutable {
                Response r;
                r.ok           = false;
                r.errorCode    = QStringLiteral("timeout");
                r.errorMessage = QStringLiteral("No response within the requested timeout");
                cb(r);
            });
        }
    }
    SS_LOG_INFO(kLog, L"WatchdogProc exited.");
}

// ============================================================================
// IMPL — INCOMING ENVELOPE DISPATCHER
// ============================================================================

void PipeClient::Impl::OnEnvelopeReceived(const Envelope& env)
{
    // AuthFailed push — go Fatal immediately.
    if (env.type == CommandType::AuthFailed) {
        const auto reason = GetField<std::string>(env.payload, "reason")
                                .value_or("AUTH_FAILED");
        SS_LOG_ERROR(kLog, L"Service pushed AuthFailed: %hs — entering Fatal state.",
                     reason.c_str());
        TransitionState(PipeClientState::Fatal, L"AuthFailed push received from service");
        const QString qReason = QString::fromStdString(reason);
        PostToMain([qObj = QPointer<PipeClient>(m_q), qReason]() {
            if (qObj) emit qObj->authRejected(qReason);
        });
        return;
    }

    if (env.requestId != 0) {
        // This is a response to a tracked request.
        ResponseCallback cb;
        {
            std::lock_guard lk(m_pendingMutex);
            const auto it = m_pendingRequests.find(env.requestId);
            if (it != m_pendingRequests.end()) {
                cb = std::move(it->second.cb);
                m_pendingRequests.erase(it);
            }
        }
        if (cb) {
            Response r;
            const auto okField = GetField<bool>(env.payload, "ok");
            r.ok = okField.has_value() && okField.value();
            if (!r.ok) {
                // Try to extract structured error from payload.
                if (env.payload.contains("error") && env.payload.at("error").is_object()) {
                    const auto& errObj = env.payload.at("error");
                    auto code = GetField<std::string>(errObj, "code");
                    auto msg  = GetField<std::string>(errObj, "message");
                    r.errorCode    = code ? QString::fromStdString(*code) : QString{};
                    r.errorMessage = msg  ? QString::fromStdString(*msg)  : QString{};
                }
            } else {
                r.payload = NlohmannToQJsonObject(env.payload);
            }
            PostToMain([cb = std::move(cb), r]() mutable { cb(r); });
        }
        return;
    }

    // requestId == 0: unsolicited push event — fan out to subscribers.
    FanOutEvent(env.type, NlohmannToQJsonObject(env.payload));
}

void PipeClient::Impl::FanOutEvent(CommandType type, QJsonObject payload)
{
    std::vector<EventCallback> cbs;
    {
        std::lock_guard lk(m_subsMutex);
        for (const auto& [token, pair] : m_subscriptions) {
            if (pair.first == type) {
                cbs.push_back(pair.second);
            }
        }
    }
    for (auto& cb : cbs) {
        PostToMain([cb, payload]() mutable { cb(payload); });
    }
}

// ============================================================================
// PIPECLIENT — PUBLIC INTERFACE
// ============================================================================

PipeClient::PipeClient(QObject* parent)
    : QObject(parent)
    , m_impl(std::make_unique<Impl>(this))
{}

PipeClient::~PipeClient()
{
    m_impl->Stop();
}

PipeClient& PipeClient::Instance()
{
    static PipeClient s_instance;
    return s_instance;
}

bool PipeClient::Start()
{
    return m_impl->Start();
}

void PipeClient::Stop()
{
    m_impl->Stop();
}

bool PipeClient::isConnected() const noexcept
{
    return m_impl->IsConnected();
}

bool PipeClient::IsConnected() const noexcept
{
    return m_impl->IsConnected();
}

int PipeClient::stateRaw() const noexcept
{
    return m_impl->StateRaw();
}

PipeClientState PipeClient::CurrentState() const noexcept
{
    return m_impl->CurrentState();
}

void PipeClient::Send(ShadowStrike::Service::CommandType t, const QJsonObject& p)
{
    m_impl->Send(t, p);
}

std::uint64_t PipeClient::SendAndExpect(ShadowStrike::Service::CommandType t,
                                         const QJsonObject& p,
                                         ResponseCallback onDone,
                                         std::chrono::milliseconds timeout)
{
    return m_impl->SendAndExpect(t, p, std::move(onDone), timeout);
}

std::uint64_t PipeClient::Subscribe(ShadowStrike::Service::CommandType eventType,
                                     EventCallback cb)
{
    return m_impl->Subscribe(eventType, std::move(cb));
}

void PipeClient::Unsubscribe(std::uint64_t token)
{
    m_impl->Unsubscribe(token);
}

} // namespace ShadowStrike::PhantomHome::UI::IPC
