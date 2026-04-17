/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * ============================================================================
 * ShadowStrike PhantomHome - BANKING MODULE WIRING
 * ============================================================================
 *
 * @file BankingWiring.cpp
 * @brief Registers every Banking subsystem module with HomeProductOrchestrator.
 *
 * Modules registered (CoreProtections phase, all gated by "Home/Banking/Enabled"):
 *   - BankingTrojanDetector  : trojan/banker malware detection in process memory
 *   - SecureBrowser          : hardened browser launch and session isolation
 *   - KeyloggerProtection    : kernel-level keystroke interception prevention
 *   - ScreenshotBlocker      : blocks unauthorized screen-capture APIs
 *   - CertificatePinning     : TLS certificate pinning for financial domains
 *   - TransactionMonitor     : behavioral analysis of active financial sessions
 *
 * Registration is performed by a namespace-scope static object so that
 * RegisterModule() is called before main() runs, matching the pattern
 * established in HomeProductEntry.cpp and ConfigWiring.cpp.
 *
 * Include strategy: each Banking module header defines a local ModuleStatus enum
 * in ShadowStrike::Banking, preventing all six headers from co-existing in one TU.
 * This file therefore forward-declares only the lifecycle interface of each
 * Banking class — the minimal complete type required to call Instance(),
 * Initialize(), Start(), and Shutdown().  The full class definitions live in
 * each module's own .hpp/.cpp; the linker resolves all symbols correctly at
 * link time because the method signatures and name-mangling are identical.
 *
 * SecureBrowser and CertificatePinning expose only Initialize/Shutdown (no
 * Start); their start callbacks return true immediately, which is correct
 * per the ModuleDescriptor contract.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#include "../HomeProductOrchestrator.hpp"
#include "../../../../PhantomCore/Utils/Logger.hpp"

// ============================================================================
// Lifecycle-only forward declarations for each Banking module.
//
// Each Banking module header defines a local ModuleStatus enum that conflicts
// when multiple headers are included in a single translation unit.  We therefore
// declare only the three lifecycle methods used by the orchestrator.  All
// declared methods exactly match those in the corresponding .hpp files.
// ============================================================================
namespace ShadowStrike {
namespace Banking {

class BankingTrojanDetector final {
public:
    [[nodiscard]] static BankingTrojanDetector& Instance() noexcept;
    [[nodiscard]] bool Initialize();
    [[nodiscard]] bool Start();
    void Shutdown();
private:
    BankingTrojanDetector() = default;
    ~BankingTrojanDetector() = default;
};

class SecureBrowser final {
public:
    [[nodiscard]] static SecureBrowser& Instance() noexcept;
    [[nodiscard]] bool Initialize();
    void Shutdown();
private:
    SecureBrowser() = default;
    ~SecureBrowser() = default;
};

class KeyloggerProtection final {
public:
    [[nodiscard]] static KeyloggerProtection& Instance() noexcept;
    [[nodiscard]] bool Initialize();
    [[nodiscard]] bool Start();
    void Shutdown();
private:
    KeyloggerProtection() = default;
    ~KeyloggerProtection() = default;
};

class ScreenshotBlocker final {
public:
    [[nodiscard]] static ScreenshotBlocker& Instance() noexcept;
    [[nodiscard]] bool Initialize();
    [[nodiscard]] bool Start();
    void Shutdown();
private:
    ScreenshotBlocker() = default;
    ~ScreenshotBlocker() = default;
};

class CertificatePinning final {
public:
    [[nodiscard]] static CertificatePinning& Instance() noexcept;
    [[nodiscard]] bool Initialize();
    void Shutdown();
private:
    CertificatePinning() = default;
    ~CertificatePinning() = default;
};

class TransactionMonitor final {
public:
    [[nodiscard]] static TransactionMonitor& Instance() noexcept;
    [[nodiscard]] bool Initialize();
    [[nodiscard]] bool Start();
    void Shutdown();
private:
    TransactionMonitor() = default;
    ~TransactionMonitor() = default;
};

}  // namespace Banking
}  // namespace ShadowStrike

// ============================================================================

namespace {

constexpr const wchar_t* kLogCategory = L"BankingWiring";

struct BankingModuleRegistrar final {
    BankingModuleRegistrar() noexcept {
        try {
            using ::ShadowStrike::Products::Home::HomeProductOrchestrator;
            using ::ShadowStrike::Products::Home::ModuleDescriptor;
            using ::ShadowStrike::Products::Home::ModulePhase;

            auto& orch = HomeProductOrchestrator::Instance();

            // ----------------------------------------------------------------
            // BankingTrojanDetector
            // ----------------------------------------------------------------
            orch.RegisterModule(ModuleDescriptor{
                .name             = "BankingTrojanDetector",
                .enabledConfigKey = "Home/Banking/Enabled",
                .phase            = ModulePhase::CoreProtections,

                .initialize = []() -> bool {
                    try {
                        return ShadowStrike::Banking::BankingTrojanDetector::Instance()
                            .Initialize();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BankingTrojanDetector: Initialize() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BankingTrojanDetector: Initialize() threw unknown exception");
                        return false;
                    }
                },

                .start = []() -> bool {
                    try {
                        return ShadowStrike::Banking::BankingTrojanDetector::Instance()
                            .Start();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BankingTrojanDetector: Start() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BankingTrojanDetector: Start() threw unknown exception");
                        return false;
                    }
                },

                .shutdown = []() noexcept {
                    try {
                        ShadowStrike::Banking::BankingTrojanDetector::Instance()
                            .Shutdown();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BankingTrojanDetector: Shutdown() threw: %hs", ex.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"BankingTrojanDetector: Shutdown() threw unknown exception");
                    }
                }
            });

            // ----------------------------------------------------------------
            // SecureBrowser  (Initialize / Shutdown only — no Start)
            // ----------------------------------------------------------------
            orch.RegisterModule(ModuleDescriptor{
                .name             = "SecureBrowser",
                .enabledConfigKey = "Home/Banking/Enabled",
                .phase            = ModulePhase::CoreProtections,

                .initialize = []() -> bool {
                    try {
                        return ShadowStrike::Banking::SecureBrowser::Instance()
                            .Initialize();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"SecureBrowser: Initialize() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"SecureBrowser: Initialize() threw unknown exception");
                        return false;
                    }
                },

                // SecureBrowser activates its protections inside Initialize();
                // there are no background threads to start separately.
                .start = []() -> bool {
                    return true;
                },

                .shutdown = []() noexcept {
                    try {
                        ShadowStrike::Banking::SecureBrowser::Instance()
                            .Shutdown();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"SecureBrowser: Shutdown() threw: %hs", ex.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"SecureBrowser: Shutdown() threw unknown exception");
                    }
                }
            });

            // ----------------------------------------------------------------
            // KeyloggerProtection
            // ----------------------------------------------------------------
            orch.RegisterModule(ModuleDescriptor{
                .name             = "KeyloggerProtection",
                .enabledConfigKey = "Home/Banking/Enabled",
                .phase            = ModulePhase::CoreProtections,

                .initialize = []() -> bool {
                    try {
                        return ShadowStrike::Banking::KeyloggerProtection::Instance()
                            .Initialize();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"KeyloggerProtection: Initialize() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"KeyloggerProtection: Initialize() threw unknown exception");
                        return false;
                    }
                },

                .start = []() -> bool {
                    try {
                        return ShadowStrike::Banking::KeyloggerProtection::Instance()
                            .Start();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"KeyloggerProtection: Start() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"KeyloggerProtection: Start() threw unknown exception");
                        return false;
                    }
                },

                .shutdown = []() noexcept {
                    try {
                        ShadowStrike::Banking::KeyloggerProtection::Instance()
                            .Shutdown();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"KeyloggerProtection: Shutdown() threw: %hs", ex.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"KeyloggerProtection: Shutdown() threw unknown exception");
                    }
                }
            });

            // ----------------------------------------------------------------
            // ScreenshotBlocker
            // ----------------------------------------------------------------
            orch.RegisterModule(ModuleDescriptor{
                .name             = "ScreenshotBlocker",
                .enabledConfigKey = "Home/Banking/Enabled",
                .phase            = ModulePhase::CoreProtections,

                .initialize = []() -> bool {
                    try {
                        return ShadowStrike::Banking::ScreenshotBlocker::Instance()
                            .Initialize();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"ScreenshotBlocker: Initialize() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"ScreenshotBlocker: Initialize() threw unknown exception");
                        return false;
                    }
                },

                .start = []() -> bool {
                    try {
                        return ShadowStrike::Banking::ScreenshotBlocker::Instance()
                            .Start();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"ScreenshotBlocker: Start() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"ScreenshotBlocker: Start() threw unknown exception");
                        return false;
                    }
                },

                .shutdown = []() noexcept {
                    try {
                        ShadowStrike::Banking::ScreenshotBlocker::Instance()
                            .Shutdown();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"ScreenshotBlocker: Shutdown() threw: %hs", ex.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"ScreenshotBlocker: Shutdown() threw unknown exception");
                    }
                }
            });

            // ----------------------------------------------------------------
            // CertificatePinning  (Initialize / Shutdown only — no Start)
            // ----------------------------------------------------------------
            orch.RegisterModule(ModuleDescriptor{
                .name             = "CertificatePinning",
                .enabledConfigKey = "Home/Banking/Enabled",
                .phase            = ModulePhase::CoreProtections,

                .initialize = []() -> bool {
                    try {
                        return ShadowStrike::Banking::CertificatePinning::Instance()
                            .Initialize();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CertificatePinning: Initialize() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CertificatePinning: Initialize() threw unknown exception");
                        return false;
                    }
                },

                // CertificatePinning installs its WinHTTP/WinInet hooks inside
                // Initialize(); no background work to start separately.
                .start = []() -> bool {
                    return true;
                },

                .shutdown = []() noexcept {
                    try {
                        ShadowStrike::Banking::CertificatePinning::Instance()
                            .Shutdown();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CertificatePinning: Shutdown() threw: %hs", ex.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"CertificatePinning: Shutdown() threw unknown exception");
                    }
                }
            });

            // ----------------------------------------------------------------
            // TransactionMonitor
            // ----------------------------------------------------------------
            orch.RegisterModule(ModuleDescriptor{
                .name             = "TransactionMonitor",
                .enabledConfigKey = "Home/Banking/Enabled",
                .phase            = ModulePhase::CoreProtections,

                .initialize = []() -> bool {
                    try {
                        return ShadowStrike::Banking::TransactionMonitor::Instance()
                            .Initialize();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"TransactionMonitor: Initialize() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"TransactionMonitor: Initialize() threw unknown exception");
                        return false;
                    }
                },

                .start = []() -> bool {
                    try {
                        return ShadowStrike::Banking::TransactionMonitor::Instance()
                            .Start();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"TransactionMonitor: Start() threw: %hs", ex.what());
                        return false;
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"TransactionMonitor: Start() threw unknown exception");
                        return false;
                    }
                },

                .shutdown = []() noexcept {
                    try {
                        ShadowStrike::Banking::TransactionMonitor::Instance()
                            .Shutdown();
                    } catch (const std::exception& ex) {
                        SS_LOG_ERROR(kLogCategory,
                            L"TransactionMonitor: Shutdown() threw: %hs", ex.what());
                    } catch (...) {
                        SS_LOG_ERROR(kLogCategory,
                            L"TransactionMonitor: Shutdown() threw unknown exception");
                    }
                }
            });

        } catch (...) {
            // Static-init-time: logger may not be available. Swallow silently.
        }
    }
};

// Namespace-scope object — constructed before main(), exactly once per
// PhantomHome binary (unnamed namespace prevents ODR issues in other TUs).
const BankingModuleRegistrar g_bankingModuleRegistrar{};

}  // namespace
