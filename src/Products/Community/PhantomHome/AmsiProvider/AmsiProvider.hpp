/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file AmsiProvider.hpp
 * @brief PhantomHome AMSI provider — implements IAntimalwareProvider for the
 *        Windows Antimalware Scan Interface, gated by the per-module
 *        ProtectionMode so the UI can control scanning aggressiveness.
 *
 * CLSID: {6F2E9D28-4A1C-4B3E-8E1F-0C7A6F0DA1FF}
 * Generated once via UUIDv4, 2026-01-15; must NEVER be regenerated.
 *
 * Scan pipeline (in priority order):
 *   1. Whitelist / known-clean hash  → AMSI_RESULT_NOT_DETECTED
 *   2. SignatureStore exact hash hit  → mode-dependent block
 *   3. PatternStore pattern match     → mode-dependent block
 *   4. ThreatIntel reputation score   → mode-dependent block
 *   5. PhantomCortex AI verdict       → mode-dependent block
 *
 * Mode semantics:
 *   Off        – return NOT_DETECTED immediately; no processing.
 *   Passive    – run full pipeline; never block; emit SS_LOG_INFO telemetry.
 *   Balanced   – block only on hash/sig exact match or ThreatIntel malicious;
 *                ambiguous pattern + AI → NOT_DETECTED + SS_LOG_INFO log.
 *   Aggressive – block on hash/sig OR pattern OR ThreatIntel suspicious OR
 *                AI confidence >= 0.50.
 */

#pragma once

// ── Windows / COM pre-requisites ─────────────────────────────────────────────
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <combaseapi.h>
#include <amsi.h>

// ── Standard library ──────────────────────────────────────────────────────────
#include <atomic>
#include <cstdint>
#include <memory>

// ── PhantomHome infrastructure ────────────────────────────────────────────────
#include "Products/Community/PhantomHome/HomeProductOrchestrator.hpp"

namespace ShadowStrike {
namespace Products {
namespace Home {

/**
 * @class AmsiProvider
 * @brief COM object implementing IAntimalwareProvider.
 *
 * Thread Safety: All public methods are thread-safe.  Mode is read
 * via std::atomic on every Scan() call (no lock on hot path).
 * Stats counters are atomic.  The underlying SignatureStore /
 * ThreatIntelStore / PhantomCortex calls are already thread-safe.
 */
class AmsiProvider final : public IAntimalwareProvider {
public:
    AmsiProvider();
    ~AmsiProvider();

    AmsiProvider(const AmsiProvider&)            = delete;
    AmsiProvider& operator=(const AmsiProvider&) = delete;

    // ── IUnknown ─────────────────────────────────────────────────────────────
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override;
    ULONG   STDMETHODCALLTYPE AddRef()                                override;
    ULONG   STDMETHODCALLTYPE Release()                               override;

    // ── IAntimalwareProvider ─────────────────────────────────────────────────
    HRESULT STDMETHODCALLTYPE Scan(IAmsiStream* stream,
                                   AMSI_RESULT* result) override;
    void    STDMETHODCALLTYPE CloseSession(ULONGLONG session) override;
    HRESULT STDMETHODCALLTYPE DisplayName(LPWSTR* displayName) override;

    // ── PhantomHome module API ───────────────────────────────────────────────

    /// Called by the wiring's initialize() lambda before Start().
    /// Allocates and initialises SignatureStore + ThreatIntelStore.
    [[nodiscard]] bool Initialize();

    /// Called by the wiring's shutdown() lambda.
    void Shutdown() noexcept;

    void                 SetMode(ProtectionMode m) noexcept;
    [[nodiscard]] ProtectionMode Mode() const noexcept;

    // ── Statistics ────────────────────────────────────────────────────────────
    struct Stats {
        std::uint64_t scans;
        std::uint64_t blocked;
        std::uint64_t clean;
    };
    [[nodiscard]] Stats GetStats() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

/**
 * @brief Factory function used by the service to obtain the provider.
 *
 * The COM infrastructure is hosted in-process inside
 * ShadowStrikePhantomService.exe; there is no DllGetClassObject.
 * The wiring layer calls this function once during Initialize() and
 * registers the resulting pointer with the AmsiProvider singleton
 * wrapper.  Caller takes ownership via *ppv (must call Release()).
 */
[[nodiscard]] HRESULT CreateAmsiProvider(IAntimalwareProvider** ppv) noexcept;

}  // namespace Home
}  // namespace Products
}  // namespace ShadowStrike
