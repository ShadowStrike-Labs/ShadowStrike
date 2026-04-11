/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Integration Tests - StartupAnalyzer
 *
 * ============================================================================
 * PURPOSE
 * ============================================================================
 * Validates StartupAnalyzer: startup item enumeration, lifecycle management,
 * statistics integrity, and registry/persistence wiring under real conditions.
 *
 * ============================================================================
 * TEST GROUPS
 * ============================================================================
 *   GROUP 1  StartupAnalyzer_Lifecycle  - init, shutdown, idempotency
 *   GROUP 2  StartupAnalyzer_Items      - item enumeration, source/category queries
 *   GROUP 3  StartupAnalyzer_Stats      - statistics increment and reset
 *   GROUP 4  StartupAnalyzer_Wiring     - registry monitor and persistence wiring
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <string>

// PersistenceDetector and RegistryAnalyzer both define ScanProgressCallback.
#define ScanProgressCallback PersistenceDetectorScanProgressCallback
#include "../../../src/PhantomCore/Core/Registry/PersistenceDetector.hpp"
#undef ScanProgressCallback
#include "../../../src/PhantomCore/Core/Registry/RegistryMonitor.hpp"
#include "../../../src/PhantomCore/Core/Registry/StartupAnalyzer.hpp"

// =============================================================================
// Test fixture
// =============================================================================
class StartupAnalyzerIntegrationTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        s_suiteReady  = false;
        s_skipReason.clear();

        namespace Reg = ShadowStrike::Core::Registry;
        auto& analyzer  = Reg::StartupAnalyzer::Instance();
        auto& monitor   = Reg::RegistryMonitor::Instance();
        auto& detector  = Reg::PersistenceDetector::Instance();

        analyzer.Shutdown();
        monitor.Shutdown();
        detector.Shutdown();

        if (!monitor.Initialize(Reg::RegistryMonitorConfig::CreateDefault())) {
            s_skipReason = "RegistryMonitor initialization failed"; return;
        }
        if (!detector.Initialize(Reg::PersistenceDetectorConfig::CreateQuick())) {
            monitor.Shutdown();
            s_skipReason = "PersistenceDetector initialization failed"; return;
        }
        if (!analyzer.Initialize()) {
            detector.Shutdown(); monitor.Shutdown();
            s_skipReason = "StartupAnalyzer initialization failed"; return;
        }
        s_suiteReady = true;
    }

    static void TearDownTestSuite() {
        namespace Reg = ShadowStrike::Core::Registry;
        Reg::StartupAnalyzer::Instance().Shutdown();
        Reg::PersistenceDetector::Instance().Shutdown();
        Reg::RegistryMonitor::Instance().Shutdown();
        s_suiteReady = false;
    }

    void SetUp() override {
        if (!s_suiteReady) {
            GTEST_SKIP() << (s_skipReason.empty()
                ? "StartupAnalyzer suite setup failed" : s_skipReason);
        }
        namespace Reg = ShadowStrike::Core::Registry;
        auto& analyzer = Reg::StartupAnalyzer::Instance();
        if (!analyzer.IsInitialized()) {
            if (!analyzer.Initialize()) {
                GTEST_SKIP() << "StartupAnalyzer re-initialization failed";
            }
        }
        analyzer.ResetStatistics();
    }

    static inline bool        s_suiteReady{ false };
    static inline std::string s_skipReason;
};

// =============================================================================
// GROUP 1 - StartupAnalyzer_Lifecycle
// =============================================================================

TEST_F(StartupAnalyzerIntegrationTest,
       StartupAnalyzer_Lifecycle_InitializeWithDefaultConfig_Succeeds) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& analyzer = Reg::StartupAnalyzer::Instance();
    analyzer.Shutdown();
    EXPECT_TRUE(analyzer.Initialize(Reg::StartupAnalyzerConfig::CreateDefault()));
    EXPECT_TRUE(analyzer.IsInitialized());
}

TEST_F(StartupAnalyzerIntegrationTest,
       StartupAnalyzer_Lifecycle_ShutdownAndReinitialize_IsIdempotent) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& analyzer = Reg::StartupAnalyzer::Instance();
    analyzer.Shutdown();
    analyzer.Shutdown();  // double-shutdown must be safe
    EXPECT_TRUE(analyzer.Initialize());
    EXPECT_TRUE(analyzer.Initialize());  // double-init must be safe
    EXPECT_TRUE(analyzer.IsInitialized());
}

TEST_F(StartupAnalyzerIntegrationTest,
       StartupAnalyzer_Lifecycle_IsInitialized_AfterShutdown_ReturnsFalse) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& analyzer = Reg::StartupAnalyzer::Instance();
    analyzer.Shutdown();
    EXPECT_FALSE(analyzer.IsInitialized());
    ASSERT_TRUE(analyzer.Initialize());  // restore for subsequent tests
}

// =============================================================================
// GROUP 2 - StartupAnalyzer_Items
// =============================================================================

TEST_F(StartupAnalyzerIntegrationTest,
       StartupAnalyzer_Items_GetStartupItems_ReturnsVector) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& analyzer = Reg::StartupAnalyzer::Instance();
    analyzer.RefreshItems();

    const auto items = analyzer.GetStartupItems();
    if (items.empty()) {
        GTEST_SKIP() << "No startup items present on this system";
    }

    const auto& first = items.front();
    ASSERT_NE(first.itemId, 0u);

    const auto byId = analyzer.GetItemById(first.itemId);
    ASSERT_TRUE(byId.has_value());
    EXPECT_EQ(byId->itemId, first.itemId);
    EXPECT_EQ(byId->source, first.source);

    if (!first.name.empty()) {
        const auto byName = analyzer.GetItem(first.name);
        ASSERT_TRUE(byName.has_value());
        EXPECT_EQ(byName->itemId, first.itemId);
    }

    const auto bySource = analyzer.GetItemsBySource(first.source);
    EXPECT_TRUE(std::any_of(bySource.begin(), bySource.end(),
        [&](const Reg::StartupItem& item) { return item.itemId == first.itemId; }));

    const auto byCategory = analyzer.GetItemsByCategory(first.category);
    EXPECT_TRUE(std::any_of(byCategory.begin(), byCategory.end(),
        [&](const Reg::StartupItem& item) { return item.itemId == first.itemId; }));
}

TEST_F(StartupAnalyzerIntegrationTest,
       StartupAnalyzer_Items_GetItemsBySource_RunKey_CompletesWithoutError) {
    namespace Reg = ShadowStrike::Core::Registry;
    EXPECT_NO_FATAL_FAILURE({
        const auto items = Reg::StartupAnalyzer::Instance()
                               .GetItemsBySource(Reg::StartupSource::RegistryRun_HKLM);
        (void)items.size();
    });
}

TEST_F(StartupAnalyzerIntegrationTest,
       StartupAnalyzer_Items_RefreshItems_DoesNotCrash) {
    namespace Reg = ShadowStrike::Core::Registry;
    EXPECT_NO_FATAL_FAILURE(Reg::StartupAnalyzer::Instance().RefreshItems());
}

TEST_F(StartupAnalyzerIntegrationTest,
       StartupAnalyzer_Items_GetItem_NonExistentName_ReturnsNullopt) {
    namespace Reg = ShadowStrike::Core::Registry;
    const auto item = Reg::StartupAnalyzer::Instance()
                          .GetItem(L"__ShadowStrike_NonExistentItem_XYZ__");
    EXPECT_FALSE(item.has_value());
}

TEST_F(StartupAnalyzerIntegrationTest,
       StartupAnalyzer_Items_GetItemById_ZeroId_ReturnsNullopt) {
    namespace Reg = ShadowStrike::Core::Registry;
    const auto item = Reg::StartupAnalyzer::Instance().GetItemById(0u);
    EXPECT_FALSE(item.has_value());
}

// =============================================================================
// GROUP 3 - StartupAnalyzer_Stats
// =============================================================================

TEST_F(StartupAnalyzerIntegrationTest,
       StartupAnalyzer_Stats_GetStatistics_AfterGetStartupItems_TotalItemsNonZero) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& analyzer = Reg::StartupAnalyzer::Instance();
    analyzer.ResetStatistics();
    analyzer.RefreshItems();
    const auto items = analyzer.GetStartupItems();
    if (items.empty()) { GTEST_SKIP() << "No startup items found; skipping stat check"; }

    const auto& stats = analyzer.GetStatistics();
    EXPECT_GT(stats.totalItemsAnalyzed.load(std::memory_order_relaxed), 0u);
}

TEST_F(StartupAnalyzerIntegrationTest,
       StartupAnalyzer_Stats_ResetStatistics_ClearsAllCounters) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& analyzer = Reg::StartupAnalyzer::Instance();
    (void)analyzer.GetStartupItems();  // drive counters
    analyzer.ResetStatistics();
    const auto& s = analyzer.GetStatistics();
    EXPECT_EQ(s.totalItemsAnalyzed.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(s.alertsGenerated.load(std::memory_order_relaxed),    0u);
    EXPECT_EQ(s.itemsDisabled.load(std::memory_order_relaxed),      0u);
    EXPECT_EQ(s.itemsEnabled.load(std::memory_order_relaxed),       0u);
}

TEST_F(StartupAnalyzerIntegrationTest,
       StartupAnalyzer_Callbacks_NullCallbacksReturnZero) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& analyzer = Reg::StartupAnalyzer::Instance();

    EXPECT_EQ(analyzer.RegisterNewItemCallback(Reg::NewItemCallback{}), 0u);
    EXPECT_EQ(analyzer.RegisterAlertCallback(Reg::StartupAlertCallback{}), 0u);
    EXPECT_EQ(analyzer.RegisterChangeCallback(Reg::ItemChangeCallback{}), 0u);
    EXPECT_FALSE(analyzer.UnregisterCallback(0u));
}

// =============================================================================
// GROUP 4 - StartupAnalyzer_Wiring
// =============================================================================

TEST_F(StartupAnalyzerIntegrationTest,
       StartupAnalyzer_Wiring_WireRegistryMonitor_DoesNotCrash) {
    namespace Reg = ShadowStrike::Core::Registry;
    EXPECT_NO_FATAL_FAILURE(Reg::StartupAnalyzer::Instance().WireRegistryMonitor());
}

TEST_F(StartupAnalyzerIntegrationTest,
       StartupAnalyzer_Wiring_WirePersistenceDetector_DoesNotCrash) {
    namespace Reg = ShadowStrike::Core::Registry;
    EXPECT_NO_FATAL_FAILURE(Reg::StartupAnalyzer::Instance().WirePersistenceDetector());
}

TEST_F(StartupAnalyzerIntegrationTest,
       StartupAnalyzer_Wiring_OnRegistryChange_WithEmptyPath_DoesNotCrash) {
    namespace Reg = ShadowStrike::Core::Registry;
    const std::vector<uint8_t> emptyData;
    EXPECT_NO_FATAL_FAILURE(
        Reg::StartupAnalyzer::Instance().OnRegistryChange(
            L"", L"", emptyData, 0u, L""));
}

TEST_F(StartupAnalyzerIntegrationTest,
       StartupAnalyzer_Wiring_OnKernelRegistryNotification_WithKnownPath_DoesNotCrash) {
    namespace Reg = ShadowStrike::Core::Registry;
    EXPECT_NO_FATAL_FAILURE(
        Reg::StartupAnalyzer::Instance().OnKernelRegistryNotification(
            L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            L"TestValue",
            static_cast<uint32_t>(::GetCurrentProcessId())));
}
