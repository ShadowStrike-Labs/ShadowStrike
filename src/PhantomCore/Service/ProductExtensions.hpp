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
 */
/**
 * ============================================================================
 * ShadowStrike NGAV - PRODUCT EXTENSIONS HOOK
 * ============================================================================
 *
 * @file ProductExtensions.hpp
 * @brief Runtime registration point for product-specific module orchestration.
 *
 * Design:
 *   PhantomCore is a product-agnostic engine. Product-specific subsystems
 *   (PhantomHome consumer features, PhantomEDR forensics, PhantomXDR SIEM
 *   bridges, etc.) must not be referenced by name from PhantomCore.
 *
 *   This header declares a single extension point: a product binary may, at
 *   static-initialization time, register a pair of lifecycle callbacks. The
 *   main service (AntivirusService) invokes them after PhantomCore is up and
 *   before PhantomCore is torn down. If no product registers, the hook is a
 *   silent no-op - PhantomCore binaries and plain tests link cleanly.
 *
 *   Only one product per process is supported. A second registration logs a
 *   fatal warning and is rejected (last-writer-does-not-win, first wins).
 *
 *   Thread-safety:
 *     - SetProductEntry is intended to run before threads exist (C++ static
 *       init in the product entry translation unit), but it is nevertheless
 *       serialized with a mutex because nothing in the language forbids a
 *       library from triggering static init off the main thread.
 *     - InitializeProduct / ShutdownProduct are called at well-defined service
 *       lifecycle points from a single thread (service control).
 *     - The lifecycle callbacks themselves MUST NOT throw. They are invoked
 *       inside noexcept guards; any escaping exception is swallowed with a
 *       fatal log.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>

namespace ShadowStrike {
namespace Service {

/**
 * @class ProductExtensions
 * @brief Meyers' singleton that wires a product-specific orchestrator into the
 *        PhantomCore service lifecycle.
 *
 * Typical usage from a product binary (e.g. PhantomHome):
 *
 *   namespace {
 *       struct HomeProductRegistrar {
 *           HomeProductRegistrar() noexcept {
 *               ::ShadowStrike::Service::ProductExtensions::Instance().SetProductEntry(
 *                   "PhantomHome",
 *                   []() noexcept -> bool {
 *                       try {
 *                           using Orch = ::ShadowStrike::Products::Home::HomeProductOrchestrator;
 *                           return Orch::Instance().Initialize() && Orch::Instance().Start();
 *                       } catch (...) { return false; }
 *                   },
 *                   []() noexcept {
 *                       try {
 *                           ::ShadowStrike::Products::Home::HomeProductOrchestrator::Instance().Shutdown();
 *                       } catch (...) {}
 *                   });
 *           }
 *       };
 *       const HomeProductRegistrar g_homeRegistrar{};
 *   }
 */
class ProductExtensions final {
public:
    /// Returns true on success, false if initialization failed. Contract: must
    /// not throw. Enforced by a try/catch wrapper inside InitializeProduct().
    using InitializeFn = std::function<bool()>;

    /// Contract: must not throw. Enforced by try/catch in ShutdownProduct().
    using ShutdownFn = std::function<void()>;

    [[nodiscard]] static ProductExtensions& Instance() noexcept;

    /**
     * @brief Register a product's lifecycle callbacks.
     *
     * Called from a product entry translation unit, typically during static
     * initialization. Only the first registration is accepted; subsequent
     * registrations are logged as fatal configuration errors and ignored.
     *
     * @param productName Human-readable product name (for logs). Truncated
     *                    defensively to 64 chars.
     * @param initializeAndStart Callback invoked by InitializeProduct().
     * @param shutdown Callback invoked by ShutdownProduct().
     */
    void SetProductEntry(std::string_view productName,
                         InitializeFn initializeAndStart,
                         ShutdownFn shutdown) noexcept;

    /**
     * @brief Invoke the registered product's initialize+start callback.
     *
     * Called by AntivirusService::Initialize() as the last init step, after
     * all PhantomCore subsystems are up. If no product is registered, this
     * returns true (no-op, logs at INFO level).
     *
     * @return true if the product initialized successfully (or no product
     *         registered); false on product-reported failure or on exception.
     */
    [[nodiscard]] bool InitializeProduct() noexcept;

    /**
     * @brief Invoke the registered product's shutdown callback.
     *
     * Called by AntivirusService::Stop() BEFORE PhantomCore teardown so that
     * product modules can quiesce while core services are still up.
     * Idempotent: safe to call multiple times; safe to call without a prior
     * InitializeProduct().
     */
    void ShutdownProduct() noexcept;

    /// @brief Whether a product has registered itself.
    [[nodiscard]] bool HasProduct() const noexcept;

    /// @brief Registered product name, or empty if none.
    [[nodiscard]] std::string ProductName() const;

    /// @brief Whether InitializeProduct() has been called and succeeded.
    [[nodiscard]] bool IsInitialized() const noexcept;

    ProductExtensions(const ProductExtensions&) = delete;
    ProductExtensions& operator=(const ProductExtensions&) = delete;
    ProductExtensions(ProductExtensions&&) = delete;
    ProductExtensions& operator=(ProductExtensions&&) = delete;

private:
    ProductExtensions() = default;
    ~ProductExtensions() = default;

    mutable std::mutex m_mutex;
    std::string m_productName;
    InitializeFn m_initStart;
    ShutdownFn m_shutdown;
    std::atomic<bool> m_registered{false};
    std::atomic<bool> m_initialized{false};
};

}  // namespace Service
}  // namespace ShadowStrike
