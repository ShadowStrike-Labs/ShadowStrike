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
 * @file WindowActivator.cpp
 * @brief Named-pipe server that forwards single-instance activation requests
 *        from subsequent process invocations to the Qt main thread.
 *
 * Server loop:
 *   for each connection:
 *     CreateNamedPipeW (overlapped)
 *     ConnectNamedPipe (overlapped — waitable on a stop event)
 *     ReadFile 4 bytes
 *     If payload == kActivateToken → QMetaObject::invokeMethod(activate, Queued)
 *     DisconnectNamedPipe, loop
 *
 * All pipe operations are overlapped so the stop event can interrupt a
 * blocked ConnectNamedPipe or ReadFile without a race.  A single OVERLAPPED
 * and a pair of HANDLEs (pipe + stop event) are reused across iterations.
 */

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>

#include <Products/Community/PhantomHome/UI/Client/WindowActivator.hpp>

#include <QApplication>
#include <QMetaObject>

#include <PhantomCore/Utils/Logger.hpp>

#include <cstring>

namespace ShadowStrike::PhantomHome::UI {

// ============================================================================
// RAII handle wrapper (local to this TU)
// ============================================================================

namespace {

class UniqueHandle final {
public:
    explicit UniqueHandle(HANDLE h = INVALID_HANDLE_VALUE) noexcept : m_h{h} {}
    ~UniqueHandle() noexcept { reset(); }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& o) noexcept : m_h{o.m_h} { o.m_h = INVALID_HANDLE_VALUE; }
    UniqueHandle& operator=(UniqueHandle&& o) noexcept {
        if (this != &o) { reset(); m_h = o.m_h; o.m_h = INVALID_HANDLE_VALUE; }
        return *this;
    }

    [[nodiscard]] HANDLE get() const noexcept { return m_h; }
    [[nodiscard]] bool   valid() const noexcept {
        return m_h != INVALID_HANDLE_VALUE && m_h != nullptr;
    }

    void reset(HANDLE h = INVALID_HANDLE_VALUE) noexcept {
        if (valid()) { ::CloseHandle(m_h); }
        m_h = h;
    }

private:
    HANDLE m_h;
};

} // anonymous namespace

// ============================================================================
// WindowActivator
// ============================================================================

WindowActivator::WindowActivator(QObject* parent)
    : QObject{parent}
{}

WindowActivator::~WindowActivator()
{
    Stop();
}

void WindowActivator::Start()
{
    // Idempotent — do not re-launch if already running.
    if (m_serverThread.joinable()) return;

    m_stop.store(false, std::memory_order_release);

    m_serverThread = std::jthread([this]() noexcept {
        ServerLoop();
    });
}

void WindowActivator::Stop() noexcept
{
    m_stop.store(true, std::memory_order_release);

    // If the server thread is blocked on ConnectNamedPipe or ReadFile we
    // cannot cancel it directly from here without the pipe handle; however
    // it checks m_stop between iterations and the OS will cancel outstanding
    // overlapped I/O when the pipe handle goes out of scope.  The jthread
    // destructor join() will block briefly until that happens.
    if (m_serverThread.joinable()) {
        m_serverThread.request_stop();
        m_serverThread.join();
    }
}

// ============================================================================
// PIPE SERVER LOOP
// ============================================================================

void WindowActivator::ServerLoop() noexcept
{
    using namespace ShadowStrike::Utils;

    // One stop event shared across all overlapped operations so we can
    // interrupt any blocked I/O when m_stop is set.
    UniqueHandle stopEvent{::CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    if (!stopEvent.valid()) {
        SS_LOG_ERROR(L"PhantomHome.WindowActivator",
                     L"CreateEventW for stop event failed (error=%lu); "
                     L"activation pipe server will not run",
                     ::GetLastError());
        return;
    }

    while (!m_stop.load(std::memory_order_acquire)) {
        // ── Create the server-side pipe instance ───────────────────────────
        HANDLE rawPipe = ::CreateNamedPipeW(
            kPipeName,
            PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            /*nMaxInstances*/  1,
            /*nOutBuf*/        0,
            /*nInBuf*/         64,
            /*defaultTimeout*/ 0,
            /*security*/       nullptr);

        if (rawPipe == INVALID_HANDLE_VALUE) {
            SS_LOG_WARN(L"PhantomHome.WindowActivator",
                        L"CreateNamedPipeW failed (error=%lu); retrying in 1 s",
                        ::GetLastError());
            // Back-off before retry to avoid spin-looping on persistent error.
            ::WaitForSingleObject(stopEvent.get(), 1000);
            continue;
        }

        UniqueHandle pipe{rawPipe};

        // ── Wait for a client to connect (overlapped) ──────────────────────
        OVERLAPPED ov{};
        UniqueHandle ioEvent{::CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        if (!ioEvent.valid()) {
            SS_LOG_ERROR(L"PhantomHome.WindowActivator",
                         L"CreateEventW for I/O failed (error=%lu)", ::GetLastError());
            break;
        }
        ov.hEvent = ioEvent.get();

        if (!::ConnectNamedPipe(pipe.get(), &ov)) {
            const DWORD err = ::GetLastError();
            if (err == ERROR_IO_PENDING) {
                // Wait for connection or stop request.
                const HANDLE waitHandles[2] = {ov.hEvent, stopEvent.get()};
                const DWORD  waitResult = ::WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
                if (waitResult != WAIT_OBJECT_0) {
                    // Stop requested (or wait failed).
                    ::CancelIo(pipe.get());
                    break;
                }
            } else if (err != ERROR_PIPE_CONNECTED) {
                SS_LOG_WARN(L"PhantomHome.WindowActivator",
                            L"ConnectNamedPipe failed (error=%lu); discarding pipe",
                            err);
                continue;
            }
        }

        if (m_stop.load(std::memory_order_acquire)) break;

        // ── Read the activation token ──────────────────────────────────────
        char    buf[sizeof(kActivateToken)] = {};
        DWORD   bytesRead = 0;
        OVERLAPPED rdOv{};
        UniqueHandle rdEvent{::CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        if (!rdEvent.valid()) {
            ::DisconnectNamedPipe(pipe.get());
            continue;
        }
        rdOv.hEvent = rdEvent.get();

        if (!::ReadFile(pipe.get(), buf, static_cast<DWORD>(sizeof(buf)), &bytesRead, &rdOv)) {
            const DWORD err = ::GetLastError();
            if (err == ERROR_IO_PENDING) {
                const HANDLE waitHandles[2] = {rdOv.hEvent, stopEvent.get()};
                const DWORD  waitResult = ::WaitForMultipleObjects(2, waitHandles, FALSE, 5000);
                if (waitResult == WAIT_OBJECT_0) {
                    ::GetOverlappedResult(pipe.get(), &rdOv, &bytesRead, FALSE);
                } else {
                    ::CancelIo(pipe.get());
                    ::DisconnectNamedPipe(pipe.get());
                    if (waitResult == WAIT_TIMEOUT) continue;
                    break;  // Stop requested.
                }
            } else {
                SS_LOG_WARN(L"PhantomHome.WindowActivator",
                            L"ReadFile on activation pipe failed (error=%lu)", err);
                ::DisconnectNamedPipe(pipe.get());
                continue;
            }
        }

        // ── Validate and dispatch ──────────────────────────────────────────
        if (bytesRead == sizeof(kActivateToken) &&
            std::memcmp(buf, kActivateToken, sizeof(kActivateToken)) == 0)
        {
            SS_LOG_INFO(L"PhantomHome.WindowActivator",
                        L"Activation request received from second instance");

            // Dispatch to the Qt main thread; safe to call from any thread.
            QMetaObject::invokeMethod(this,
                                      &WindowActivator::activate,
                                      Qt::QueuedConnection);
        } else {
            SS_LOG_WARN(L"PhantomHome.WindowActivator",
                        L"Received %lu bytes on activation pipe but token did not match; "
                        L"ignoring (possible spoofing attempt)",
                        bytesRead);
        }

        ::DisconnectNamedPipe(pipe.get());
    }

    SS_LOG_INFO(L"PhantomHome.WindowActivator", L"Activation pipe server stopped");
}

} // namespace ShadowStrike::PhantomHome::UI

// Required when Q_OBJECT is in a .cpp file — include the moc output directly.
// The MOC CustomBuild in the vcxproj runs moc on WindowActivator.hpp and
// produces $(IntDir)moc_WindowActivator.cpp, which is compiled separately.
// Nothing to include here since the class is declared in the header.
