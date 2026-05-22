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
 * @file WindowActivator.hpp
 * @brief QObject bridge that receives single-instance activation requests
 *        from subsequent process invocations via a named pipe server.
 *
 * A second instance writes either the legacy fixed "SHOW" token (4 bytes) or
 * an activation frame carrying its command line to
 *   \\.\pipe\ShadowStrike.PhantomHome.UI.Activate
 * This class owns a dedicated jthread running the pipe server loop and
 * emits activate() on the Qt main thread via QMetaObject::invokeMethod
 * with Qt::QueuedConnection — QML handlers are always dispatched safely
 * without requiring an explicit thread affinity check at the call site.
 */
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>

#include <QObject>
#include <QString>

#include <atomic>
#include <thread>

namespace ShadowStrike::PhantomHome::UI {

class WindowActivator final : public QObject {
    Q_OBJECT

public:
    explicit WindowActivator(QObject* parent = nullptr);
    ~WindowActivator() override;

    WindowActivator(const WindowActivator&)            = delete;
    WindowActivator& operator=(const WindowActivator&) = delete;
    WindowActivator(WindowActivator&&)                 = delete;
    WindowActivator& operator=(WindowActivator&&)      = delete;

    /**
     * @brief Start the named pipe server thread. Idempotent — calling
     *        Start() while already running is a no-op.
     */
    void Start();

    /**
     * @brief Stop the pipe server thread and release all handles.
     *        Blocks until the server thread has exited. Safe to call from
     *        any thread.
     */
    void Stop() noexcept;

    /**
     * @brief Named pipe path shared between the server (this class) and the
     *        client (a second process instance that wants to activate us).
     */
    static constexpr wchar_t kPipeName[] =
        L"\\\\.\\pipe\\ShadowStrike.PhantomHome.UI.Activate";

    /**
     * @brief Legacy token written by older second instances to request activation.
     *        Four bytes so the ReadFile is atomic on the pipe granularity.
     */
    static constexpr char kLegacyActivateToken[4] = {'S','H','O','W'};

    /**
     * @brief Current activation frame magic followed by a little-endian uint32
     *        payload length and UTF-16LE command-line bytes.
     */
    static constexpr char kActivationFrameMagic[4] = {'S','S','A','1'};

    /**
     * @brief Hard cap for activation payloads accepted from the local pipe.
     */
    static constexpr DWORD kMaxActivationPayloadBytes = 16u * 1024u;

signals:
    /**
     * @brief Emitted on the Qt main thread when a second process instance
     *        requests that this window be raised and activated.
     *
     * @param commandLine Full command line from the second instance when the
     *        v1 activation frame is used; empty for legacy SHOW activations.
     */
    void activate(QString commandLine);

private:
    void ServerLoop() noexcept;

    std::atomic<bool> m_stop{false};
    std::jthread      m_serverThread;
};

} // namespace ShadowStrike::PhantomHome::UI
