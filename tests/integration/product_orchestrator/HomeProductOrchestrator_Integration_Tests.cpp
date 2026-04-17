/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Integration Tests - PhantomHome Product Orchestrator
 *
 * Validates that HomeProductOrchestrator correctly assembles the PhantomHome
 * product out of the 10 subsystem folders at static-init time, and that its
 * lifecycle primitives (Initialize / Start / Shutdown) preserve every
 * architectural invariant the engine depends on.
 *
 * No mocks on the orchestrator itself. The singleton is exercised directly
 * and every assertion reads real state. Synthetic probe modules are used
 * to isolate lifecycle behaviour from the real protection modules, since
 * their real Initialize() methods touch OS hooks that aren't viable in CI.
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <mutex>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "../../../src/PhantomCore/Config/ConfigManager.hpp"
#include "../../../src/Products/Community/PhantomHome/HomeProductOrchestrator.hpp"

namespace SS_H = ShadowStrike::Products::Home;

namespace {

struct ExpectedModule {
    std::string_view name;
    std::string_view configKey;
    SS_H::ModulePhase phase;
};

// Architectural contract. When a new subsystem gets wired, append its tuple
// here so the integration test catches missing or mis-phased registrations.
constexpr std::array<ExpectedModule, 27> kExpectedMinimum = {{
    // Foundation
    { "HomeConfig",              "",                         SS_H::ModulePhase::Foundation      },
    // CoreProtections - Email
    { "EmailProtection",         "Home/Email/Enabled",       SS_H::ModulePhase::CoreProtections },
    // CoreProtections - Banking (6 per-module wiring TUs)
    { "BankingTrojanDetector",   "Home/Banking/Enabled",     SS_H::ModulePhase::CoreProtections },
    { "SecureBrowser",           "Home/Banking/Enabled",     SS_H::ModulePhase::CoreProtections },
    { "KeyloggerProtection",     "Home/Banking/Enabled",     SS_H::ModulePhase::CoreProtections },
    { "ScreenshotBlocker",       "Home/Banking/Enabled",     SS_H::ModulePhase::CoreProtections },
    { "CertificatePinning",      "Home/Banking/Enabled",     SS_H::ModulePhase::CoreProtections },
    { "TransactionMonitor",      "Home/Banking/Enabled",     SS_H::ModulePhase::CoreProtections },
    // CoreProtections - CryptoMiner / Web / USB
    { "CryptoMinerDetector",     "Home/CryptoMiner/Enabled", SS_H::ModulePhase::CoreProtections },
    { "BrowserProtection",       "Home/Web/Enabled",         SS_H::ModulePhase::CoreProtections },
    { "AdBlocker",               "Home/Web/Enabled",         SS_H::ModulePhase::CoreProtections },
    { "USBScanner",              "Home/USB/Enabled",         SS_H::ModulePhase::CoreProtections },
    { "USBDeviceMonitor",        "Home/USB/Enabled",         SS_H::ModulePhase::CoreProtections },
    // OnDemand - Privacy (8 per-module wiring TUs)
    { "CookieManager",           "Home/Privacy/Enabled",     SS_H::ModulePhase::OnDemand        },
    { "LocationPrivacy",         "Home/Privacy/Enabled",     SS_H::ModulePhase::OnDemand        },
    { "MicrophoneGuard",         "Home/Privacy/Enabled",     SS_H::ModulePhase::OnDemand        },
    { "WebcamProtector",         "Home/Privacy/Enabled",     SS_H::ModulePhase::OnDemand        },
    { "DataLeakProtection",      "Home/Privacy/Enabled",     SS_H::ModulePhase::OnDemand        },
    { "DNSLeakProtection",       "Home/Privacy/Enabled",     SS_H::ModulePhase::OnDemand        },
    { "PrivacyIPLeakProtection", "Home/Privacy/Enabled",     SS_H::ModulePhase::OnDemand        },
    { "PrivacyCleaner",          "Home/Privacy/Enabled",     SS_H::ModulePhase::OnDemand        },
    // UserExperience - GameMode
    { "GameProcessDetector",     "Home/Gaming/Enabled",      SS_H::ModulePhase::UserExperience  },
    { "GameModeManager",         "Home/Gaming/Enabled",      SS_H::ModulePhase::UserExperience  },
    { "PerformanceOptimizer",    "Home/Gaming/Enabled",      SS_H::ModulePhase::UserExperience  },
    { "OverlayProtection",       "Home/Gaming/Enabled",      SS_H::ModulePhase::UserExperience  },
    // Background
    { "BackupManager",           "Home/Backup/Enabled",      SS_H::ModulePhase::Background      },
}};

constexpr std::string_view kProbePrefix = "OrchestratorIntegTest::";

[[nodiscard]] std::string ProbeName(std::string_view label) {
    static std::atomic<std::uint64_t> s_counter{0};
    return std::string(kProbePrefix) + std::string(label) + "_" +
           std::to_string(s_counter.fetch_add(1, std::memory_order_relaxed));
}

struct ProbeModule {
    std::string name;
    std::atomic<int> initCalls{0};
    std::atomic<int> startCalls{0};
    std::atomic<int> shutdownCalls{0};
    std::chrono::steady_clock::time_point initAt{};
    std::chrono::steady_clock::time_point startAt{};
    std::chrono::steady_clock::time_point shutdownAt{};
    bool initShouldFail = false;
    bool startShouldFail = false;
    bool initShouldThrow = false;

    SS_H::ModuleDescriptor Build(std::string_view configKey,
                                 SS_H::ModulePhase phase) {
        SS_H::ModuleDescriptor d;
        d.name = name;
        d.enabledConfigKey = std::string(configKey);
        d.phase = phase;
        d.initialize = [this]() -> bool {
            initAt = std::chrono::steady_clock::now();
            initCalls.fetch_add(1, std::memory_order_relaxed);
            if (initShouldThrow) {
                throw std::runtime_error("probe init throw");
            }
            return !initShouldFail;
        };
        d.start = [this]() -> bool {
            startAt = std::chrono::steady_clock::now();
            startCalls.fetch_add(1, std::memory_order_relaxed);
            return !startShouldFail;
        };
        d.shutdown = [this]() {
            shutdownAt = std::chrono::steady_clock::now();
            shutdownCalls.fetch_add(1, std::memory_order_relaxed);
        };
        return d;
    }
};

}  // namespace

class HomeOrchestratorIntegration : public ::testing::Test {
protected:
    [[nodiscard]] std::vector<SS_H::ModuleStatus> RealModuleStatuses() const {
        auto all = SS_H::HomeProductOrchestrator::Instance().GetStatus();
        all.erase(
            std::remove_if(all.begin(), all.end(),
                [](const SS_H::ModuleStatus& s) {
                    return s.name.rfind(kProbePrefix, 0) == 0;
                }),
            all.end());
        return all;
    }
};

// ---------------------------------------------------------------------------
// Group 1: Registration completeness
// ---------------------------------------------------------------------------

TEST_F(HomeOrchestratorIntegration, AllExpectedModulesAreRegistered) {
    const auto real = RealModuleStatuses();
    std::set<std::string> names;
    for (const auto& s : real) names.insert(s.name);

    for (const auto& expected : kExpectedMinimum) {
        EXPECT_TRUE(names.count(std::string(expected.name)) != 0)
            << "Wired module missing from orchestrator registry: "
            << expected.name;
    }
}

TEST_F(HomeOrchestratorIntegration, RegistryMeetsMinimumSize) {
    const auto real = RealModuleStatuses();
    EXPECT_GE(real.size(), kExpectedMinimum.size())
        << "Registry has only " << real.size()
        << " real modules; expected at least "
        << kExpectedMinimum.size();
}

// ---------------------------------------------------------------------------
// Group 2: Phase and config gate assignments
// ---------------------------------------------------------------------------

TEST_F(HomeOrchestratorIntegration, PhasesMatchContract) {
    const auto real = RealModuleStatuses();
    for (const auto& expected : kExpectedMinimum) {
        auto it = std::find_if(real.begin(), real.end(),
            [&](const SS_H::ModuleStatus& s) {
                return s.name == expected.name;
            });
        ASSERT_NE(it, real.end())
            << "Missing module: " << expected.name;
        EXPECT_EQ(it->phase, expected.phase)
            << "Module '" << expected.name << "' is in the wrong phase";
    }
}

TEST_F(HomeOrchestratorIntegration, FoundationPhaseContainsHomeConfig) {
    auto s = SS_H::HomeProductOrchestrator::Instance()
                 .GetModuleStatus("HomeConfig");
    ASSERT_TRUE(s.has_value());
    EXPECT_EQ(s->phase, SS_H::ModulePhase::Foundation);
}

TEST_F(HomeOrchestratorIntegration, BackgroundPhaseContainsBackupManager) {
    auto s = SS_H::HomeProductOrchestrator::Instance()
                 .GetModuleStatus("BackupManager");
    ASSERT_TRUE(s.has_value());
    EXPECT_EQ(s->phase, SS_H::ModulePhase::Background);
}

// ---------------------------------------------------------------------------
// Group 3: Registry uniqueness and lookup
// ---------------------------------------------------------------------------

TEST_F(HomeOrchestratorIntegration, NoDuplicateModuleNames) {
    const auto all = SS_H::HomeProductOrchestrator::Instance().GetStatus();
    std::set<std::string> seen;
    for (const auto& s : all) {
        EXPECT_TRUE(seen.insert(s.name).second)
            << "Duplicate module name in registry: " << s.name;
    }
}

TEST_F(HomeOrchestratorIntegration, GetModuleStatusReturnsNulloptForUnknown) {
    auto s = SS_H::HomeProductOrchestrator::Instance()
                 .GetModuleStatus("NoSuchModuleName_XYZ_12345");
    EXPECT_FALSE(s.has_value());
}

TEST_F(HomeOrchestratorIntegration, GetModuleStatusIsCaseSensitive) {
    auto upper = SS_H::HomeProductOrchestrator::Instance()
                     .GetModuleStatus("HOMECONFIG");
    EXPECT_FALSE(upper.has_value())
        << "Module lookup should be case-sensitive";
}

// ---------------------------------------------------------------------------
// Group 4: Synthetic lifecycle - phase ordering, failure isolation, gates
// ---------------------------------------------------------------------------

TEST_F(HomeOrchestratorIntegration, ProbeRegistrationRejectsDuplicates) {
    ProbeModule a{ProbeName("dup")};
    auto descA = a.Build("", SS_H::ModulePhase::Foundation);
    EXPECT_TRUE(SS_H::HomeProductOrchestrator::Instance().RegisterModule(descA));

    ProbeModule b{a.name};
    auto descB = b.Build("", SS_H::ModulePhase::Foundation);
    EXPECT_FALSE(SS_H::HomeProductOrchestrator::Instance().RegisterModule(descB));
}

TEST_F(HomeOrchestratorIntegration, ProbeRegistrationRejectsNullCallbacks) {
    SS_H::ModuleDescriptor d;
    d.name = ProbeName("nullcb");
    d.enabledConfigKey = "";
    d.phase = SS_H::ModulePhase::Foundation;
    d.initialize = nullptr;
    d.start = []() { return true; };
    d.shutdown = []() {};
    EXPECT_FALSE(SS_H::HomeProductOrchestrator::Instance().RegisterModule(d));
}

TEST_F(HomeOrchestratorIntegration, ProbeDisabledByConfigIsNotInitialized) {
    const std::string disabledKey = "Home/_Test/DisabledProbe";
    (void)ShadowStrike::Config::ConfigManager::Instance()
              .SetValue<bool>(disabledKey, false);

    ProbeModule probe{ProbeName("disabled")};
    auto desc = probe.Build(disabledKey, SS_H::ModulePhase::Foundation);
    ASSERT_TRUE(SS_H::HomeProductOrchestrator::Instance().RegisterModule(desc));

    (void)SS_H::HomeProductOrchestrator::Instance().Initialize();

    auto s = SS_H::HomeProductOrchestrator::Instance().GetModuleStatus(probe.name);
    ASSERT_TRUE(s.has_value());
    EXPECT_EQ(s->state, SS_H::ModuleState::Disabled);
    EXPECT_EQ(probe.initCalls.load(), 0);
    EXPECT_EQ(probe.startCalls.load(), 0);
}

TEST_F(HomeOrchestratorIntegration, ProbeFailureIsIsolatedAndDoesNotStopPeers) {
    ProbeModule bad{ProbeName("bad")};
    bad.initShouldFail = true;
    ProbeModule good{ProbeName("good")};

    ASSERT_TRUE(SS_H::HomeProductOrchestrator::Instance().RegisterModule(
        bad.Build("", SS_H::ModulePhase::OnDemand)));
    ASSERT_TRUE(SS_H::HomeProductOrchestrator::Instance().RegisterModule(
        good.Build("", SS_H::ModulePhase::OnDemand)));

    (void)SS_H::HomeProductOrchestrator::Instance().Initialize();

    auto sBad  = SS_H::HomeProductOrchestrator::Instance().GetModuleStatus(bad.name);
    auto sGood = SS_H::HomeProductOrchestrator::Instance().GetModuleStatus(good.name);

    ASSERT_TRUE(sBad.has_value());
    ASSERT_TRUE(sGood.has_value());
    EXPECT_EQ(sBad->state,  SS_H::ModuleState::Failed);
    EXPECT_EQ(sGood->state, SS_H::ModuleState::Initialized);
    EXPECT_EQ(bad.initCalls.load(),  1);
    EXPECT_EQ(good.initCalls.load(), 1);
}

TEST_F(HomeOrchestratorIntegration, ProbeInitThrowIsCaughtAndMarkedFailed) {
    ProbeModule thrower{ProbeName("thrower")};
    thrower.initShouldThrow = true;
    ASSERT_TRUE(SS_H::HomeProductOrchestrator::Instance().RegisterModule(
        thrower.Build("", SS_H::ModulePhase::OnDemand)));

    (void)SS_H::HomeProductOrchestrator::Instance().Initialize();

    auto s = SS_H::HomeProductOrchestrator::Instance().GetModuleStatus(thrower.name);
    ASSERT_TRUE(s.has_value());
    EXPECT_EQ(s->state, SS_H::ModuleState::Failed);
    EXPECT_FALSE(s->lastError.empty());
}

TEST_F(HomeOrchestratorIntegration, ProbeStartRunsAfterInitializeSucceeds) {
    ProbeModule probe{ProbeName("lifecycle")};
    ASSERT_TRUE(SS_H::HomeProductOrchestrator::Instance().RegisterModule(
        probe.Build("", SS_H::ModulePhase::UserExperience)));

    (void)SS_H::HomeProductOrchestrator::Instance().Initialize();
    (void)SS_H::HomeProductOrchestrator::Instance().Start();

    auto s = SS_H::HomeProductOrchestrator::Instance().GetModuleStatus(probe.name);
    ASSERT_TRUE(s.has_value());
    EXPECT_EQ(s->state, SS_H::ModuleState::Running);
    EXPECT_EQ(probe.initCalls.load(),  1);
    EXPECT_EQ(probe.startCalls.load(), 1);
    EXPECT_LE(probe.initAt, probe.startAt);
}

TEST_F(HomeOrchestratorIntegration, ShutdownIsIdempotentAndReverseOrder) {
    ProbeModule first{ProbeName("shutdown_first")};
    ProbeModule second{ProbeName("shutdown_second")};
    ASSERT_TRUE(SS_H::HomeProductOrchestrator::Instance().RegisterModule(
        first.Build("", SS_H::ModulePhase::Background)));
    ASSERT_TRUE(SS_H::HomeProductOrchestrator::Instance().RegisterModule(
        second.Build("", SS_H::ModulePhase::Background)));

    (void)SS_H::HomeProductOrchestrator::Instance().Initialize();
    (void)SS_H::HomeProductOrchestrator::Instance().Start();

    SS_H::HomeProductOrchestrator::Instance().Shutdown();

    EXPECT_EQ(first.shutdownCalls.load(),  1);
    EXPECT_EQ(second.shutdownCalls.load(), 1);
    EXPECT_GE(first.shutdownAt, second.shutdownAt);

    SS_H::HomeProductOrchestrator::Instance().Shutdown();
    EXPECT_EQ(first.shutdownCalls.load(),  1);
    EXPECT_EQ(second.shutdownCalls.load(), 1);
}

// ---------------------------------------------------------------------------
// Group 5: Concurrent registration
// ---------------------------------------------------------------------------

TEST_F(HomeOrchestratorIntegration, ConcurrentRegistrationIsRaceFree) {
    constexpr int kThreadCount = 8;
    constexpr int kPerThread   = 16;

    std::vector<std::thread> threads;
    std::atomic<int> successes{0};

    for (int t = 0; t < kThreadCount; ++t) {
        threads.emplace_back([&, t]() {
            for (int i = 0; i < kPerThread; ++i) {
                SS_H::ModuleDescriptor d;
                d.name = std::string(kProbePrefix) + "race_" +
                         std::to_string(t) + "_" + std::to_string(i);
                d.enabledConfigKey = "";
                d.phase = SS_H::ModulePhase::Foundation;
                d.initialize = []() { return true; };
                d.start = []() { return true; };
                d.shutdown = []() {};
                if (SS_H::HomeProductOrchestrator::Instance().RegisterModule(d)) {
                    successes.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }
    for (auto& th : threads) th.join();

    EXPECT_EQ(successes.load(), kThreadCount * kPerThread)
        << "Concurrent RegisterModule lost writes";
}
