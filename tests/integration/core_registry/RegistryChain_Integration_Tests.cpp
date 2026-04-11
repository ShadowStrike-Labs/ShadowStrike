/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Integration Tests - Registry Chain
 *
 * ============================================================================
 * PURPOSE
 * ============================================================================
 * Tests end-to-end integration between the Registry chain modules:
 *   RegistryMonitor    -> real-time registry event capture, callbacks, stats
 *   RegistryAnalyzer   -> hive scanning, anomaly detection, key analysis
 *   PersistenceDetector -> autorun/persistence entry enumeration and scoring
 *
 * Tests use real Win32 registry operations under:
 *   HKCU\Software\ShadowStrikeTests\IntegrationTest_<PID>
 *
 * All keys created by these tests are deleted in TearDownTestSuite.
 *
 * ============================================================================
 * TEST GROUPS
 * ============================================================================
 *   GROUP 1  RegistryMonitor_Lifecycle        - init, stats, rule/callback lifecycle
 *   GROUP 2  RegistryAnalyzer_Analysis        - HKCU scope analysis, key analysis
 *   GROUP 3  PersistenceDetector_Scan         - critical scans and entry summaries
 *   GROUP 4  RegistryChain_WriteAndDetect     - write key, round-trip, chain detect
 *   GROUP 5  RegistryChain_Concurrency        - parallel analyze and stats
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "../../../src/Shared_modules/Core/Registry/RegistryMonitor.hpp"
#include "../../../src/Shared_modules/Core/Registry/RegistryAnalyzer.hpp"
// PersistenceDetector and RegistryAnalyzer both define ScanProgressCallback; alias for this TU.
#define ScanProgressCallback PersistenceDetectorScanProgressCallback
#include "../../../src/Shared_modules/Core/Registry/PersistenceDetector.hpp"
#undef ScanProgressCallback

namespace {

constexpr wchar_t kRegistryTestRootRelative[] = L"Software\\ShadowStrikeTests";
constexpr wchar_t kRegistryTestRootFull[]     = L"HKCU\\Software\\ShadowStrikeTests";

[[nodiscard]] std::string Narrow(const std::wstring& value) {
    if (value.empty()) { return {}; }
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, value.c_str(),
                                        static_cast<int>(value.size()),
                                        nullptr, 0, nullptr, nullptr);
    if (n <= 0) { return "(conversion failed)"; }
    std::string out(static_cast<size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()),
                          out.data(), n, nullptr, nullptr);
    return out;
}

[[nodiscard]] uint64_t LoadAtomic(const std::atomic<uint64_t>& v) noexcept {
    return v.load(std::memory_order_relaxed);
}

// ---------------------------------------------------------------------------
// RAII handle
// ---------------------------------------------------------------------------
class ScopedRegistryHandle {
public:
    ScopedRegistryHandle() noexcept = default;
    explicit ScopedRegistryHandle(HKEY h) noexcept : m_handle(h) {}
    ~ScopedRegistryHandle() noexcept { Reset(); }
    ScopedRegistryHandle(const ScopedRegistryHandle&)            = delete;
    ScopedRegistryHandle& operator=(const ScopedRegistryHandle&) = delete;
    ScopedRegistryHandle(ScopedRegistryHandle&& o) noexcept : m_handle(o.m_handle) { o.m_handle = nullptr; }
    ScopedRegistryHandle& operator=(ScopedRegistryHandle&& o) noexcept {
        if (this != &o) { Reset(); m_handle = o.m_handle; o.m_handle = nullptr; }
        return *this;
    }
    [[nodiscard]] HKEY  Get()     const noexcept { return m_handle; }
    [[nodiscard]] HKEY* Receive() noexcept        { Reset(); return &m_handle; }
    void Reset(HKEY h = nullptr) noexcept {
        if (m_handle) { ::RegCloseKey(m_handle); }
        m_handle = h;
    }
private:
    HKEY m_handle{ nullptr };
};

// ---------------------------------------------------------------------------
// Registry helpers
// ---------------------------------------------------------------------------
[[nodiscard]] std::wstring MakeSuiteSubKeyPath() {
    return std::wstring(kRegistryTestRootRelative)
         + L"\\IntegrationTest_" + std::to_wstring(::GetCurrentProcessId());
}
[[nodiscard]] std::wstring MakeSuiteFullKeyPath() {
    return std::wstring(kRegistryTestRootFull)
         + L"\\IntegrationTest_" + std::to_wstring(::GetCurrentProcessId());
}
[[nodiscard]] LSTATUS DeleteTreeIfExists(const std::wstring& sub) noexcept {
    const LSTATUS s = ::RegDeleteTreeW(HKEY_CURRENT_USER, sub.c_str());
    return (s == ERROR_SUCCESS || s == ERROR_FILE_NOT_FOUND || s == ERROR_PATH_NOT_FOUND)
               ? ERROR_SUCCESS : s;
}
[[nodiscard]] LSTATUS CreateKeyRecursive(const std::wstring& sub, ScopedRegistryHandle* h) {
    if (!h) { return ERROR_INVALID_PARAMETER; }
    DWORD disp = 0;
    return ::RegCreateKeyExW(HKEY_CURRENT_USER, sub.c_str(), 0, nullptr,
                             REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE,
                             nullptr, h->Receive(), &disp);
}
[[nodiscard]] LSTATUS SetStringValue(HKEY k, const std::wstring& name, const std::wstring& data) {
    const DWORD bytes = static_cast<DWORD>((data.size() + 1) * sizeof(wchar_t));
    return ::RegSetValueExW(k, name.c_str(), 0, REG_SZ,
                            reinterpret_cast<const BYTE*>(data.c_str()), bytes);
}
[[nodiscard]] LSTATUS QueryStringValue(HKEY k, const std::wstring& name, std::wstring* out) {
    if (!out) { return ERROR_INVALID_PARAMETER; }
    DWORD type = 0, bytes = 0;
    LSTATUS s = ::RegQueryValueExW(k, name.c_str(), nullptr, &type, nullptr, &bytes);
    if (s != ERROR_SUCCESS) { return s; }
    if (type != REG_SZ && type != REG_EXPAND_SZ) { return ERROR_INVALID_DATATYPE; }
    std::wstring buf(bytes / sizeof(wchar_t), L'\0');
    s = ::RegQueryValueExW(k, name.c_str(), nullptr, &type,
                           reinterpret_cast<LPBYTE>(buf.data()), &bytes);
    if (s != ERROR_SUCCESS) { return s; }
    if (!buf.empty() && buf.back() == L'\0') { buf.pop_back(); }
    *out = std::move(buf);
    return ERROR_SUCCESS;
}

}  // namespace

// =============================================================================
// Test fixture
// =============================================================================
class RegistryChainIntegrationTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        s_suiteReady = false;
        s_skipReason.clear();
        s_suiteSubKeyPath  = MakeSuiteSubKeyPath();
        s_suiteFullKeyPath = MakeSuiteFullKeyPath();

        namespace Reg = ShadowStrike::Core::Registry;
        auto& monitor  = Reg::RegistryMonitor::Instance();
        auto& analyzer = Reg::RegistryAnalyzer::Instance();
        auto& detector = Reg::PersistenceDetector::Instance();

        monitor.Shutdown();
        analyzer.Shutdown();
        detector.Shutdown();

        if (!monitor.Initialize(Reg::RegistryMonitorConfig::CreateDefault())) {
            s_skipReason = L"RegistryMonitor initialization failed"; return;
        }
        if (!analyzer.Initialize(Reg::RegistryAnalyzerConfig::CreateDefault())) {
            monitor.Shutdown();
            s_skipReason = L"RegistryAnalyzer initialization failed"; return;
        }
        if (!detector.Initialize(Reg::PersistenceDetectorConfig::CreateQuick())) {
            analyzer.Shutdown(); monitor.Shutdown();
            s_skipReason = L"PersistenceDetector initialization failed"; return;
        }
        ScopedRegistryHandle kh;
        if (CreateKeyRecursive(s_suiteSubKeyPath, &kh) != ERROR_SUCCESS) {
            detector.Shutdown(); analyzer.Shutdown(); monitor.Shutdown();
            s_skipReason = L"Failed to create HKCU test isolation key"; return;
        }
        s_suiteReady = true;
    }

    static void TearDownTestSuite() {
        DeleteTreeIfExists(kRegistryTestRootRelative);
        namespace Reg = ShadowStrike::Core::Registry;
        Reg::PersistenceDetector::Instance().Shutdown();
        Reg::RegistryAnalyzer::Instance().Shutdown();
        Reg::RegistryMonitor::Instance().Shutdown();
        s_suiteReady = false;
    }

    void SetUp() override {
        if (!s_suiteReady) {
            GTEST_SKIP() << Narrow(s_skipReason.empty()
                ? L"Registry chain suite setup failed" : s_skipReason);
        }
        if (!EnsureModulesInitialized()) {
            GTEST_SKIP() << Narrow(s_skipReason.empty()
                ? L"Registry chain modules unavailable" : s_skipReason);
        }
        namespace Reg = ShadowStrike::Core::Registry;
        Reg::RegistryMonitor::Instance().ResetStatistics();
        Reg::RegistryAnalyzer::Instance().ResetStatistics();
        Reg::RegistryAnalyzer::Instance().ClearAnomalies();
        Reg::PersistenceDetector::Instance().ResetStatistics();
        ASSERT_EQ(ResetIsolationKey(), ERROR_SUCCESS) << "Failed to reset HKCU test key";
    }

    void TearDown() override {
        EXPECT_EQ(ResetIsolationKey(), ERROR_SUCCESS) << "Failed to clean HKCU test key";
    }

    [[nodiscard]] static bool EnsureModulesInitialized() {
        namespace Reg = ShadowStrike::Core::Registry;
        auto& monitor  = Reg::RegistryMonitor::Instance();
        auto& analyzer = Reg::RegistryAnalyzer::Instance();
        auto& detector = Reg::PersistenceDetector::Instance();
        if (!monitor.Initialize(Reg::RegistryMonitorConfig::CreateDefault())) {
            s_skipReason = L"RegistryMonitor reinitialization failed"; return false;
        }
        if (!analyzer.Initialize(Reg::RegistryAnalyzerConfig::CreateDefault())) {
            s_skipReason = L"RegistryAnalyzer reinitialization failed"; return false;
        }
        if (!detector.Initialize(Reg::PersistenceDetectorConfig::CreateQuick())) {
            s_skipReason = L"PersistenceDetector reinitialization failed"; return false;
        }
        return true;
    }

    [[nodiscard]] static LSTATUS ResetIsolationKey() {
        LSTATUS s = DeleteTreeIfExists(s_suiteSubKeyPath);
        if (s != ERROR_SUCCESS) { return s; }
        ScopedRegistryHandle kh;
        return CreateKeyRecursive(s_suiteSubKeyPath, &kh);
    }

    [[nodiscard]] static std::wstring MakeChildFullKeyPath(const std::wstring& child) {
        return s_suiteFullKeyPath + L"\\" + child;
    }
    [[nodiscard]] static std::wstring MakeChildSubKeyPath(const std::wstring& child) {
        return s_suiteSubKeyPath + L"\\" + child;
    }

    static inline bool         s_suiteReady{ false };
    static inline std::wstring s_skipReason;
    static inline std::wstring s_suiteSubKeyPath;
    static inline std::wstring s_suiteFullKeyPath;
};

// =============================================================================
// GROUP 1 - RegistryMonitor_Lifecycle
// =============================================================================

TEST_F(RegistryChainIntegrationTest,
       RegistryMonitor_Lifecycle_InitializeWithDefaultConfig_ReturnsTrue) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& monitor = Reg::RegistryMonitor::Instance();
    monitor.Shutdown();
    EXPECT_TRUE(monitor.Initialize(Reg::RegistryMonitorConfig::CreateDefault()));
}

TEST_F(RegistryChainIntegrationTest,
       RegistryMonitor_Lifecycle_GetStatistics_AfterInit_ReturnsZeroCounts) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& monitor = Reg::RegistryMonitor::Instance();
    monitor.Shutdown();
    ASSERT_TRUE(monitor.Initialize(Reg::RegistryMonitorConfig::CreateDefault()));
    monitor.ResetStatistics();
    const auto& s = monitor.GetStatistics();

    EXPECT_EQ(LoadAtomic(s.totalEvents),         0u);
    EXPECT_EQ(LoadAtomic(s.createKeyEvents),     0u);
    EXPECT_EQ(LoadAtomic(s.setValueEvents),      0u);
    EXPECT_EQ(LoadAtomic(s.deleteKeyEvents),     0u);
    EXPECT_EQ(LoadAtomic(s.deleteValueEvents),   0u);
    EXPECT_EQ(LoadAtomic(s.renameEvents),        0u);
    EXPECT_EQ(LoadAtomic(s.allowedOperations),   0u);
    EXPECT_EQ(LoadAtomic(s.blockedOperations),   0u);
    EXPECT_EQ(LoadAtomic(s.silentDropped),       0u);
    EXPECT_EQ(LoadAtomic(s.persistenceAttempts), 0u);
    EXPECT_EQ(LoadAtomic(s.filelessPayloads),    0u);
    EXPECT_EQ(LoadAtomic(s.securityChanges),     0u);
    EXPECT_EQ(LoadAtomic(s.selfDefenseBlocks),   0u);
    EXPECT_EQ(LoadAtomic(s.alertsGenerated),     0u);
    EXPECT_EQ(LoadAtomic(s.criticalAlerts),      0u);
    EXPECT_EQ(LoadAtomic(s.avgCallbackTimeUs),   0u);
    EXPECT_EQ(LoadAtomic(s.maxCallbackTimeUs),   0u);
    EXPECT_EQ(LoadAtomic(s.droppedEvents),       0u);
}

TEST_F(RegistryChainIntegrationTest,
       RegistryMonitor_Lifecycle_ShutdownAndReinitialize_IsIdempotent) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& monitor = Reg::RegistryMonitor::Instance();
    monitor.Shutdown();
    monitor.Shutdown();  // double-shutdown must be safe
    const auto cfg = Reg::RegistryMonitorConfig::CreateDefault();
    EXPECT_TRUE(monitor.Initialize(cfg));
    EXPECT_TRUE(monitor.Initialize(cfg));  // double-init must be safe
}

TEST_F(RegistryChainIntegrationTest,
       RegistryMonitor_Lifecycle_RegisterAlertCallback_ReturnsNonZeroId) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& monitor = Reg::RegistryMonitor::Instance();
    const uint64_t id = monitor.RegisterAlertCallback(
        [](const Reg::RegistryAlert&) {});
    EXPECT_GT(id, 0u);
    EXPECT_TRUE(monitor.UnregisterCallback(id));
}

TEST_F(RegistryChainIntegrationTest,
       RegistryMonitor_Lifecycle_RegisterEventCallback_ReturnsNonZeroId) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& monitor = Reg::RegistryMonitor::Instance();
    const uint64_t id = monitor.RegisterEventCallback(
        [](const Reg::RegistryEvent&, Reg::RegistryVerdict) {});
    EXPECT_GT(id, 0u);
    EXPECT_TRUE(monitor.UnregisterCallback(id));
}

TEST_F(RegistryChainIntegrationTest,
       RegistryMonitor_Lifecycle_RegisterValueCallback_UnregisterSucceeds) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& monitor = Reg::RegistryMonitor::Instance();
    const uint64_t id = monitor.RegisterValueCallback(
        [](const Reg::RegistryEvent&, const Reg::ValueAnalysis&) {});
    ASSERT_GT(id, 0u);
    EXPECT_TRUE(monitor.UnregisterCallback(id));
}

TEST_F(RegistryChainIntegrationTest,
       RegistryMonitor_Lifecycle_UnregisterInvalidCallback_ReturnsFalse) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& monitor = Reg::RegistryMonitor::Instance();
    // ID 0 and an impossible large ID must both be rejected.
    EXPECT_FALSE(monitor.UnregisterCallback(0u));
    EXPECT_FALSE(monitor.UnregisterCallback(UINT64_MAX));
}

TEST_F(RegistryChainIntegrationTest,
       RegistryMonitor_Lifecycle_StartAndStop_WhenInitialized_DoesNotCrash) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& monitor = Reg::RegistryMonitor::Instance();
    // Start may fail when the kernel driver is absent (expected in CI).
    // We only require that both calls complete without crashing.
    (void)monitor.Start();
    monitor.Stop();
    monitor.Stop();  // double-stop must be safe
}

TEST_F(RegistryChainIntegrationTest,
       RegistryMonitor_Lifecycle_AddAndRemoveRule_RoundTrips) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& monitor = Reg::RegistryMonitor::Instance();
    Reg::RegistryRule rule{};
    rule.name           = "TestRule";
    rule.keyPathPattern = L"HKCU\\Software\\ShadowStrikeTests\\*";
    rule.action         = Reg::RuleAction::Alert;
    rule.enabled        = true;
    const uint64_t id = monitor.AddRule(rule);
    ASSERT_GT(id, 0u);
    EXPECT_TRUE(monitor.RemoveRule(id));
}

TEST_F(RegistryChainIntegrationTest,
       RegistryMonitor_Lifecycle_RemoveRule_InvalidId_ReturnsFalse) {
    namespace Reg = ShadowStrike::Core::Registry;
    EXPECT_FALSE(Reg::RegistryMonitor::Instance().RemoveRule(0u));
    EXPECT_FALSE(Reg::RegistryMonitor::Instance().RemoveRule(UINT64_MAX));
}

TEST_F(RegistryChainIntegrationTest,
       RegistryMonitor_Lifecycle_AddProtectedKey_WhenInitialized_DoesNotCrash) {
    namespace Reg = ShadowStrike::Core::Registry;
    EXPECT_NO_FATAL_FAILURE(
        Reg::RegistryMonitor::Instance().AddProtectedKey(
            L"HKCU\\Software\\ShadowStrikeTests\\Protected"));
}

TEST_F(RegistryChainIntegrationTest,
       RegistryMonitor_Lifecycle_ProtectedKey_RoundTripsAndMatchesSubkey) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& monitor = Reg::RegistryMonitor::Instance();

    const std::wstring key = L"HKCU\\Software\\ShadowStrikeTests\\Protected";
    const std::wstring child = key + L"\\Child";

    monitor.RemoveProtectedKey(key);
    monitor.AddProtectedKey(key);

    EXPECT_TRUE(monitor.IsProtectedKey(key));
    EXPECT_TRUE(monitor.IsProtectedKey(child));
    EXPECT_TRUE(monitor.IsProtectedKey(L"hkcu\\software\\shadowstriketests\\protected"));

    monitor.RemoveProtectedKey(key);
    EXPECT_FALSE(monitor.IsProtectedKey(key));
    EXPECT_FALSE(monitor.IsProtectedKey(child));
}

// =============================================================================
// GROUP 2 - RegistryAnalyzer_Analysis
// =============================================================================

TEST_F(RegistryChainIntegrationTest,
       RegistryAnalyzer_Analysis_InitializeWithDefaultConfig_Succeeds) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& analyzer = Reg::RegistryAnalyzer::Instance();
    analyzer.Shutdown();
    EXPECT_TRUE(analyzer.Initialize(Reg::RegistryAnalyzerConfig::CreateDefault()));
}

TEST_F(RegistryChainIntegrationTest,
       RegistryAnalyzer_Analysis_Analyze_NTUSEROnlyScope_ReturnsCompleted) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& analyzer = Reg::RegistryAnalyzer::Instance();
    const uint64_t before = analyzer.GetStatistics().keysAnalyzed.load(std::memory_order_relaxed);

    Reg::AnalysisScope scope{};
    scope.analyzeSAM      = false;
    scope.analyzeSECURITY = false;
    scope.analyzeSOFTWARE = false;
    scope.analyzeSYSTEM   = false;
    scope.analyzeNTUSER   = true;
    scope.analyzeUSRCLASS = false;
    scope.maxDepth        = 2;
    scope.specificPaths   = { L"HKCU\\Software\\Microsoft" };

    const auto result = analyzer.Analyze(scope, Reg::AnalysisMode::Deep);
    const uint64_t after = analyzer.GetStatistics().keysAnalyzed.load(std::memory_order_relaxed);

    EXPECT_TRUE(result.completed);
    EXPECT_FALSE(result.hadErrors);
    EXPECT_GT(after, before);
}

TEST_F(RegistryChainIntegrationTest,
       RegistryAnalyzer_Analysis_Analyze_SpecificPath_HKCUSoftware_Succeeds) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& analyzer = Reg::RegistryAnalyzer::Instance();
    const uint64_t before = analyzer.GetStatistics().keysAnalyzed.load(std::memory_order_relaxed);

    Reg::AnalysisScope scope{};
    scope.analyzeSAM      = false;
    scope.analyzeSECURITY = false;
    scope.analyzeSOFTWARE = false;
    scope.analyzeSYSTEM   = false;
    scope.analyzeNTUSER   = true;
    scope.analyzeUSRCLASS = false;
    scope.maxDepth        = 1;
    scope.specificPaths   = { L"HKCU\\Software" };

    const auto result = analyzer.Analyze(scope, Reg::AnalysisMode::Deep);
    const uint64_t after = analyzer.GetStatistics().keysAnalyzed.load(std::memory_order_relaxed);

    EXPECT_TRUE(result.completed);
    EXPECT_FALSE(result.hadErrors);
    EXPECT_GT(after, before);
}

TEST_F(RegistryChainIntegrationTest,
       RegistryAnalyzer_Analysis_AnalyzeKey_KnownSoftwareKey_CompletesWithoutError) {
    namespace Reg = ShadowStrike::Core::Registry;
    // On a clean system this returns 0 anomalies; we only assert no crash/throw.
    EXPECT_NO_FATAL_FAILURE({
        const auto anomalies = Reg::RegistryAnalyzer::Instance().AnalyzeKey(
            L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion", true);
        (void)anomalies.size();
    });
}

TEST_F(RegistryChainIntegrationTest,
       RegistryAnalyzer_Analysis_GetAnomalies_CountConsistentWithAnalysisResult) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& analyzer = Reg::RegistryAnalyzer::Instance();

    Reg::AnalysisScope scope{};
    scope.analyzeNTUSER = true;
    scope.maxDepth      = 1;
    scope.specificPaths = { L"HKCU\\Software" };

    const auto result = analyzer.Analyze(scope, Reg::AnalysisMode::Standard);
    ASSERT_TRUE(result.completed);

    const auto anomalies = analyzer.GetAnomalies();
    const auto persisted = analyzer.GetStatistics().anomaliesDetected.load(std::memory_order_relaxed);

    // The scan result counts anomalies surfaced through the current analysis result, while
    // GetAnomalies() exposes the analyzer's persisted anomaly store. The persisted store must
    // be self-consistent with statistics, and it must never contain fewer anomalies than the
    // result reports for the same analysis.
    EXPECT_EQ(anomalies.size(), persisted);
    EXPECT_GE(anomalies.size(), static_cast<size_t>(result.anomaliesFound));
}

TEST_F(RegistryChainIntegrationTest,
       RegistryAnalyzer_Analysis_GetHiddenKeys_AfterAnalysis_CompletesWithoutError) {
    namespace Reg = ShadowStrike::Core::Registry;
    EXPECT_NO_FATAL_FAILURE({
        const auto hidden = Reg::RegistryAnalyzer::Instance().GetHiddenKeys();
        (void)hidden.size();
    });
}

TEST_F(RegistryChainIntegrationTest,
       RegistryAnalyzer_Analysis_ResetStatistics_ClearsAllCounters) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& analyzer = Reg::RegistryAnalyzer::Instance();

    Reg::AnalysisScope scope{};
    scope.analyzeNTUSER = true;
    scope.maxDepth      = 1;
    scope.specificPaths = { L"HKCU\\Software" };
    (void)analyzer.Analyze(scope, Reg::AnalysisMode::Standard);

    analyzer.ResetStatistics();
    const auto& s = analyzer.GetStatistics();
    EXPECT_EQ(s.totalScans.load(std::memory_order_relaxed),        0u);
    EXPECT_EQ(s.keysAnalyzed.load(std::memory_order_relaxed),      0u);
    EXPECT_EQ(s.valuesAnalyzed.load(std::memory_order_relaxed),    0u);
    EXPECT_EQ(s.anomaliesDetected.load(std::memory_order_relaxed), 0u);
}

TEST_F(RegistryChainIntegrationTest,
       RegistryAnalyzer_Analysis_DetectNullByteKeys_HKCUSoftware_CompletesWithoutError) {
    namespace Reg = ShadowStrike::Core::Registry;
    EXPECT_NO_FATAL_FAILURE({
        const auto hidden = Reg::RegistryAnalyzer::Instance()
                                .DetectNullByteKeys(L"HKCU\\Software");
        (void)hidden.size();
    });
}

// =============================================================================
// GROUP 3 - PersistenceDetector_Scan
// =============================================================================

TEST_F(RegistryChainIntegrationTest,
       PersistenceDetector_Scan_InitializeWithQuickConfig_Succeeds) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& detector = Reg::PersistenceDetector::Instance();
    detector.Shutdown();
    EXPECT_TRUE(detector.Initialize(Reg::PersistenceDetectorConfig::CreateQuick()));
}

TEST_F(RegistryChainIntegrationTest,
       PersistenceDetector_Scan_ScanCritical_EntriesSizeMatchesTotal) {
    namespace Reg = ShadowStrike::Core::Registry;
    const auto result = Reg::PersistenceDetector::Instance().ScanCritical();
    // The vector must contain exactly totalEntries elements.
    EXPECT_EQ(result.entries.size(), static_cast<size_t>(result.totalEntries));
    EXPECT_EQ(result.errorsEncountered, 0u);
}

TEST_F(RegistryChainIntegrationTest,
       PersistenceDetector_Scan_ScanResult_CategorizedEntriesSumEqualsTotal) {
    namespace Reg = ShadowStrike::Core::Registry;
    const auto result = Reg::PersistenceDetector::Instance().ScanCritical();
    ASSERT_EQ(result.errorsEncountered, 0u);
    const uint32_t sum = result.safeEntries + result.suspiciousEntries
                       + result.maliciousEntries + result.unknownEntries;
    EXPECT_EQ(result.totalEntries, sum);
}

TEST_F(RegistryChainIntegrationTest,
       PersistenceDetector_Scan_ResolveTarget_SystemBinary_PreservesOriginalPath) {
    namespace Reg = ShadowStrike::Core::Registry;
    const auto target = Reg::PersistenceDetector::Instance()
                            .ResolveTarget(L"svchost.exe");
    EXPECT_FALSE(target.originalPath.empty());
    EXPECT_EQ(target.originalPath, L"svchost.exe");
}

TEST_F(RegistryChainIntegrationTest,
       PersistenceDetector_Scan_ScanCritical_LocationsScannedPositive) {
    namespace Reg = ShadowStrike::Core::Registry;
    const auto result = Reg::PersistenceDetector::Instance().ScanCritical();
    EXPECT_EQ(result.errorsEncountered, 0u);
    EXPECT_GT(result.locationsScanned, 0u);
}

TEST_F(RegistryChainIntegrationTest,
       PersistenceDetector_Scan_EntriesByTypeSumEqualsTotal) {
    namespace Reg = ShadowStrike::Core::Registry;
    const auto result = Reg::PersistenceDetector::Instance().ScanCritical();
    ASSERT_EQ(result.errorsEncountered, 0u);

    uint32_t sum = 0;
    for (const auto& [type, count] : result.entriesByType) {
        (void)type;
        sum += count;
    }

    EXPECT_EQ(sum, result.totalEntries);
}

TEST_F(RegistryChainIntegrationTest,
       PersistenceDetector_Scan_GetStatistics_AfterScan_IncrementsTotalScans) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& detector = Reg::PersistenceDetector::Instance();
    const uint64_t before = detector.GetStatistics().totalScans.load(std::memory_order_relaxed);
    (void)detector.ScanCritical();
    const uint64_t after = detector.GetStatistics().totalScans.load(std::memory_order_relaxed);
    EXPECT_GT(after, before);
}

TEST_F(RegistryChainIntegrationTest,
       PersistenceDetector_Scan_ResetStatistics_ClearsAllCounters) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& detector = Reg::PersistenceDetector::Instance();
    (void)detector.ScanCritical();
    detector.ResetStatistics();
    const auto& s = detector.GetStatistics();
    EXPECT_EQ(s.totalScans.load(std::memory_order_relaxed),          0u);
    EXPECT_EQ(s.entriesScanned.load(std::memory_order_relaxed),      0u);
    EXPECT_EQ(s.alertsGenerated.load(std::memory_order_relaxed),     0u);
    EXPECT_EQ(s.persistenceAttempts.load(std::memory_order_relaxed), 0u);
}

// =============================================================================
// GROUP 4 - RegistryChain_WriteAndDetect
// =============================================================================

TEST_F(RegistryChainIntegrationTest,
       RegistryChain_WriteAndDetect_WriteAndRead_HKCUTestKey_RoundTrips) {
    const std::wstring subKey = MakeChildSubKeyPath(L"RoundTrip");

    ScopedRegistryHandle kh;
    ASSERT_EQ(CreateKeyRecursive(subKey, &kh), ERROR_SUCCESS)
        << "RegCreateKeyExW failed";

    const std::wstring expected = L"ShadowStrike_RegistryChain_Test";
    ASSERT_EQ(SetStringValue(kh.Get(), L"Payload", expected), ERROR_SUCCESS)
        << "RegSetValueExW failed";

    std::wstring actual;
    ASSERT_EQ(QueryStringValue(kh.Get(), L"Payload", &actual), ERROR_SUCCESS)
        << "RegQueryValueExW failed";

    EXPECT_EQ(actual, expected);
}

TEST_F(RegistryChainIntegrationTest,
       RegistryChain_WriteAndDetect_AnalyzeKey_WrittenTestKey_CompletesWithoutError) {
    namespace Reg = ShadowStrike::Core::Registry;
    const std::wstring subKey  = MakeChildSubKeyPath(L"ChainDetect");
    const std::wstring fullKey = MakeChildFullKeyPath(L"ChainDetect");

    ScopedRegistryHandle kh;
    ASSERT_EQ(CreateKeyRecursive(subKey, &kh), ERROR_SUCCESS);
    ASSERT_EQ(SetStringValue(kh.Get(), L"Payload", L"TestValue"), ERROR_SUCCESS);

    EXPECT_NO_FATAL_FAILURE({
        const auto anomalies = Reg::RegistryAnalyzer::Instance()
                                   .AnalyzeKey(fullKey, false);
        (void)anomalies.size();
    });
}

TEST_F(RegistryChainIntegrationTest,
       RegistryChain_WriteAndDetect_AnalyzeRealTime_RunKey_PersistenceAttemptDetected) {
    namespace Reg = ShadowStrike::Core::Registry;
    const auto analysis = Reg::PersistenceDetector::Instance().AnalyzeRealTimeFull(
        L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"ShadowStrikeTestValue",
        L"notepad.exe");

    EXPECT_TRUE(analysis.isPersistenceAttempt);
    EXPECT_EQ(analysis.detectedType, Reg::PersistenceType::RunKey);
    EXPECT_FALSE(analysis.resolvedTarget.empty());
}

// =============================================================================
// GROUP 5 - RegistryChain_Concurrency
// =============================================================================

TEST_F(RegistryChainIntegrationTest,
       RegistryChain_Concurrency_ParallelAnalyze_FourThreads_AllComplete) {
    namespace Reg = ShadowStrike::Core::Registry;
    constexpr int kThreads = 4;

    std::vector<Reg::AnalysisResult> results(kThreads);
    std::vector<std::thread> threads;
    threads.reserve(kThreads);

    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([i, &results]() {
            Reg::AnalysisScope scope{};
            scope.analyzeNTUSER = true;
            scope.maxDepth      = 1;
            scope.specificPaths = { L"HKCU\\Software" };
            results[i] = Reg::RegistryAnalyzer::Instance()
                             .Analyze(scope, Reg::AnalysisMode::Standard);
        });
    }
    for (auto& t : threads) { t.join(); }

    for (int i = 0; i < kThreads; ++i) {
        EXPECT_TRUE(results[i].completed)
            << "Thread " << i << " analysis did not complete";
        EXPECT_FALSE(results[i].hadErrors)
            << "Thread " << i << " analysis reported errors";
    }
}

TEST_F(RegistryChainIntegrationTest,
       RegistryChain_Concurrency_ConcurrentStatisticsRead_WhileScanInFlight_NoCrash) {
    namespace Reg = ShadowStrike::Core::Registry;
    std::atomic<bool> done{ false };

    std::thread scanThread([&done]() {
        (void)Reg::PersistenceDetector::Instance().ScanCritical();
        done.store(true, std::memory_order_release);
    });

    std::thread readerThread([&done]() {
        while (!done.load(std::memory_order_acquire)) {
            (void)Reg::PersistenceDetector::Instance()
                      .GetStatistics()
                      .totalScans.load(std::memory_order_relaxed);
        }
    });

    scanThread.join();
    readerThread.join();

    SUCCEED();  // reaching here means no crash / data race
}
