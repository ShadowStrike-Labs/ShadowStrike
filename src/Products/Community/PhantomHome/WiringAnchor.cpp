/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file WiringAnchor.cpp
 * @brief Force-link anchor for every PhantomHome *Wiring.cpp translation unit.
 *
 * MSVC /OPT:REF + /LTCG can elide translation units whose only contribution
 * is a dynamically-initialised internal-linkage global (the `const XxxRegistrar
 * g_xxxRegistrar{};` pattern). Taking the address of an external-linkage
 * keep-alive function declared in each wiring TU creates a reference edge that
 * the linker cannot prune, which in turn forces the registrar's .CRT$XCU entry
 * to be emitted.
 *
 * EnsureAllModulesWired() is called from HomeProductOrchestrator::InitializeLocked()
 * before the module list is enumerated. It does no runtime work beyond a
 * series of volatile pointer writes; the entire point is the reference graph.
 */

#include "pch.h"

#include <cstddef>

extern "C" {
    void PhantomHome_KeepAlive_EmailProtection()      noexcept;
    void PhantomHome_KeepAlive_USBProtection()        noexcept;
    void PhantomHome_KeepAlive_WebProtection()        noexcept;
    void PhantomHome_KeepAlive_IoT()                  noexcept;
    void PhantomHome_KeepAlive_GameMode()             noexcept;
    void PhantomHome_KeepAlive_CryptoMiners()         noexcept;
    void PhantomHome_KeepAlive_Config()               noexcept;
    void PhantomHome_KeepAlive_BankingTrojanDetector() noexcept;
    void PhantomHome_KeepAlive_CertificatePinning()   noexcept;
    void PhantomHome_KeepAlive_KeyloggerProtection()  noexcept;
    void PhantomHome_KeepAlive_ScreenshotBlocker()    noexcept;
    void PhantomHome_KeepAlive_SecureBrowser()        noexcept;
    void PhantomHome_KeepAlive_TransactionMonitor()   noexcept;
    void PhantomHome_KeepAlive_Backup()               noexcept;
    void PhantomHome_KeepAlive_CookieManager()        noexcept;
    void PhantomHome_KeepAlive_DataLeakProtection()   noexcept;
    void PhantomHome_KeepAlive_DNSLeakProtection()    noexcept;
    void PhantomHome_KeepAlive_IPLeakProtection()     noexcept;
    void PhantomHome_KeepAlive_LocationPrivacy()      noexcept;
    void PhantomHome_KeepAlive_MicrophoneGuard()      noexcept;
    void PhantomHome_KeepAlive_PrivacyCleaner()       noexcept;
    void PhantomHome_KeepAlive_WebcamProtector()      noexcept;
    void PhantomHome_KeepAlive_ZeroTrust()            noexcept;
    void PhantomHome_KeepAlive_AmsiProvider()         noexcept;
    void PhantomHome_KeepAlive_NetworkAttackBlocker() noexcept;
}

namespace ShadowStrike {
namespace Products {
namespace Home {

void EnsureAllModulesWired() noexcept {
    // Aggregate-initialised, volatile-qualified table of every PhantomHome
    // wiring TU's KeepAlive symbol. The volatile qualifier on the array
    // elements blocks the compiler from eliminating the reads; the static
    // storage duration plus an external read below blocks the linker
    // (/OPT:REF + /LTCG) from eliding the address-taken externs and the
    // .CRT$XCU registrar globals that anchor each TU's static initializer.
    //
    // Using a constant-initialised aggregate (rather than sequential writes
    // to a single sink) ensures every entry is materialised as an
    // address-of operation at translation-unit scope, which is a strictly
    // stronger reference edge for whole-program optimisation passes than
    // a function-scope sink assignment sequence.
    using KeepAliveFn = void(*)();
    static KeepAliveFn const volatile kKeepAliveTable[] = {
        &PhantomHome_KeepAlive_EmailProtection,
        &PhantomHome_KeepAlive_USBProtection,
        &PhantomHome_KeepAlive_WebProtection,
        &PhantomHome_KeepAlive_IoT,
        &PhantomHome_KeepAlive_GameMode,
        &PhantomHome_KeepAlive_CryptoMiners,
        &PhantomHome_KeepAlive_Config,
        &PhantomHome_KeepAlive_BankingTrojanDetector,
        &PhantomHome_KeepAlive_CertificatePinning,
        &PhantomHome_KeepAlive_KeyloggerProtection,
        &PhantomHome_KeepAlive_ScreenshotBlocker,
        &PhantomHome_KeepAlive_SecureBrowser,
        &PhantomHome_KeepAlive_TransactionMonitor,
        &PhantomHome_KeepAlive_Backup,
        &PhantomHome_KeepAlive_CookieManager,
        &PhantomHome_KeepAlive_DataLeakProtection,
        &PhantomHome_KeepAlive_DNSLeakProtection,
        &PhantomHome_KeepAlive_IPLeakProtection,
        &PhantomHome_KeepAlive_LocationPrivacy,
        &PhantomHome_KeepAlive_MicrophoneGuard,
        &PhantomHome_KeepAlive_PrivacyCleaner,
        &PhantomHome_KeepAlive_WebcamProtector,
        &PhantomHome_KeepAlive_ZeroTrust,
        &PhantomHome_KeepAlive_AmsiProvider,
        &PhantomHome_KeepAlive_NetworkAttackBlocker,
    };

    // Force the optimiser to assume the table is observed by reading every
    // element through its volatile-qualified type into a volatile sink.
    // This is the canonical "use" of a volatile object: the abstract machine
    // must perform each read, so the address-taken externs cannot be pruned.
    static void const* volatile sink = nullptr;
    for (std::size_t i = 0; i < sizeof(kKeepAliveTable) / sizeof(kKeepAliveTable[0]); ++i) {
        sink = reinterpret_cast<void const*>(kKeepAliveTable[i]);
    }
    (void)sink;
}

}  // namespace Home
}  // namespace Products
}  // namespace ShadowStrike
