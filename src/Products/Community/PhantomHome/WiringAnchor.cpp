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
    // Each assignment forces the linker to retain the referenced TU.
    // volatile prevents the compiler from optimising these writes away;
    // the linker sees real uses and cannot elide the symbol.
    static volatile void* sink = nullptr;
    sink = reinterpret_cast<void*>(&PhantomHome_KeepAlive_EmailProtection);
    sink = reinterpret_cast<void*>(&PhantomHome_KeepAlive_USBProtection);
    sink = reinterpret_cast<void*>(&PhantomHome_KeepAlive_WebProtection);
    sink = reinterpret_cast<void*>(&PhantomHome_KeepAlive_IoT);
    sink = reinterpret_cast<void*>(&PhantomHome_KeepAlive_GameMode);
    sink = reinterpret_cast<void*>(&PhantomHome_KeepAlive_CryptoMiners);
    sink = reinterpret_cast<void*>(&PhantomHome_KeepAlive_Config);
    sink = reinterpret_cast<void*>(&PhantomHome_KeepAlive_BankingTrojanDetector);
    sink = reinterpret_cast<void*>(&PhantomHome_KeepAlive_CertificatePinning);
    sink = reinterpret_cast<void*>(&PhantomHome_KeepAlive_KeyloggerProtection);
    sink = reinterpret_cast<void*>(&PhantomHome_KeepAlive_ScreenshotBlocker);
    sink = reinterpret_cast<void*>(&PhantomHome_KeepAlive_SecureBrowser);
    sink = reinterpret_cast<void*>(&PhantomHome_KeepAlive_TransactionMonitor);
    sink = reinterpret_cast<void*>(&PhantomHome_KeepAlive_Backup);
    sink = reinterpret_cast<void*>(&PhantomHome_KeepAlive_CookieManager);
    sink = reinterpret_cast<void*>(&PhantomHome_KeepAlive_DataLeakProtection);
    sink = reinterpret_cast<void*>(&PhantomHome_KeepAlive_DNSLeakProtection);
    sink = reinterpret_cast<void*>(&PhantomHome_KeepAlive_IPLeakProtection);
    sink = reinterpret_cast<void*>(&PhantomHome_KeepAlive_LocationPrivacy);
    sink = reinterpret_cast<void*>(&PhantomHome_KeepAlive_MicrophoneGuard);
    sink = reinterpret_cast<void*>(&PhantomHome_KeepAlive_PrivacyCleaner);
    sink = reinterpret_cast<void*>(&PhantomHome_KeepAlive_WebcamProtector);
    sink = reinterpret_cast<void*>(&PhantomHome_KeepAlive_ZeroTrust);
    sink = reinterpret_cast<void*>(&PhantomHome_KeepAlive_AmsiProvider);
    sink = reinterpret_cast<void*>(&PhantomHome_KeepAlive_NetworkAttackBlocker);
    (void)sink;
}

}  // namespace Home
}  // namespace Products
}  // namespace ShadowStrike
