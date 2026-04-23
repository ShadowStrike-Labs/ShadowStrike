/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file HomeIpcDispatcher.hpp
 * @brief Service-side IPC handler that wires every PhantomHome UI command verb
 *        to its backend implementation.
 *
 * Design:
 *   - Meyers' singleton (no globals, no double-checked locking).
 *   - PIMPL: pause-timer state and scan-tracking state are hidden in Impl.
 *   - RAII: all resources managed by smart pointers and RAII wrappers.
 *   - Thread-safe: all mutable state in Impl is protected by appropriate
 *     mutexes; handlers may be invoked concurrently from the thread pool.
 *
 * Usage (once, after ServiceCommunicator::Start()):
 * @code
 *   HomeIpcDispatcher::Instance().Install(ServiceCommunicator::Instance());
 * @endcode
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 */

#pragma once

#include <memory>

namespace ShadowStrike::Service {

class ServiceCommunicator;

/**
 * @class HomeIpcDispatcher
 * @brief Meyers' singleton that installs per-CommandType V2 handlers for every
 *        PhantomHome UI verb into a ServiceCommunicator instance.
 *
 * Call Install() once at service startup (after ServiceCommunicator::Start()).
 * Call Uninstall() before ServiceCommunicator::Stop() to replace all handlers
 * with no-ops.
 */
class HomeIpcDispatcher final {
public:
    // =========================================================================
    // Singleton
    // =========================================================================

    /// @brief Return the process-singleton instance (Meyers' pattern).
    [[nodiscard]] static HomeIpcDispatcher& Instance();

    // Non-copyable, non-movable.
    HomeIpcDispatcher(const HomeIpcDispatcher&)            = delete;
    HomeIpcDispatcher& operator=(const HomeIpcDispatcher&) = delete;
    HomeIpcDispatcher(HomeIpcDispatcher&&)                 = delete;
    HomeIpcDispatcher& operator=(HomeIpcDispatcher&&)      = delete;

    // =========================================================================
    // Lifecycle
    // =========================================================================

    /**
     * @brief Wire every PhantomHome UI handler into @p svc.
     *
     * Registers V2CommandHandler callbacks for all verbs (199-291 and legacy
     * aliases 10, 20, 21, 30, 31, 50). Handlers are active immediately; safe
     * to call while @p svc is already accepting connections.
     *
     * Thread-safe: RegisterV2Handler is internally mutex-protected.
     *
     * @param svc   Running ServiceCommunicator instance.
     */
    void Install(ServiceCommunicator& svc);

    /**
     * @brief Replace all registered handlers with no-ops.
     *
     * Allows the ServiceCommunicator to shut down cleanly without racing
     * against in-flight handler invocations that reference dispatcher state.
     *
     * @param svc   ServiceCommunicator instance passed to Install().
     */
    void Uninstall(ServiceCommunicator& svc);

private:
    HomeIpcDispatcher();
    ~HomeIpcDispatcher();

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace ShadowStrike::Service
