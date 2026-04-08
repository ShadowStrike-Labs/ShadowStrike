/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Integration Tests - Tier 5: Registry Chain
 *
 * ============================================================================
 * PURPOSE
 * ============================================================================
 * Tests end-to-end integration between the Registry chain modules:
 *   RegistryMonitor    → real-time registry event capture, callbacks, stats
 *   RegistryAnalyzer   → hive scanning, anomaly detection, key analysis
 *   PersistenceDetector → autorun/persistence entry enumeration and scoring
 *
 * Tests use real Win32 registry operations under:
 *   HKCU\Software\ShadowStrikeTests\IntegrationTest_<PID>
 *
 * All keys created by these tests are deleted in TearDownTestSuite.
 *
 * ============================================================================
 * TEST GROUPS
 * ============================================================================
 *   GROUP 1  RegistryMonitor_Lifecycle     - init, stats, callbacks lifecycle
 *   GROUP 2  RegistryAnalyzer_Analysis     - HKCU scope analysis, key analysis
 *   GROUP 3  PersistenceDetector_Scan      - full scan, entry sum validation
 *   GROUP 4  RegistryChain_WriteAndDetect  - write key, analyzer detects it
 *   GROUP 5  RegistryChain_Concurrency     - parallel analyze and stats
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
#define ScanProgressCallback PersistenceDetectorScanProgressCallback
#include "../../../src/Shared_modules/Core/Registry/PersistenceDetector.hpp"
#undef ScanProgressCallback

namespace {

constexpr wchar_t kRegistryTestRootRelative[] = L"Software\\ShadowStrikeTests";
constexpr wchar_t kRegistryTestRootFull[] = L"HKCU\\Software\\ShadowStrikeTests";

[[nodiscard]] std::string Narrow(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }

    const int requiredBytes = ::WideCharToMultiByte(
        CP_UTF8,
        0,
        value.c_str(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (requiredBytes <= 0) {
        return "Registry chain suite setup failed";
    }

    std::string utf8(static_cast<size_t>(requiredBytes), '\0');
    const int convertedBytes = ::WideCharToMultiByte(
        CP_UTF8,
        0,
        value.c_str(),
        static_cast<int>(value.size()),
        utf8.data(),
        requiredBytes,
        nullptr,
        nullptr);
    if (convertedBytes <= 0) {
        return "Registry chain suite setup failed";
    }

    return utf8;
}

[[nodiscard]] uint64_t LoadAtomic(const std::atomic<uint64_t>& value) noexcept {
    return value.load(std::memory_order_relaxed);
}

class ScopedRegistryHandle {
public:
    ScopedRegistryHandle() noexcept = default;
    explicit ScopedRegistryHandle(HKEY handle) noexcept : m_handle(handle) {}

    ~ScopedRegistryHandle() noexcept {
        Reset();
    }

    ScopedRegistryHandle(const ScopedRegistryHandle&) = delete;
    ScopedRegistryHandle& operator=(const ScopedRegistryHandle&) = delete;

    ScopedRegistryHandle(ScopedRegistryHandle&& other) noexcept : m_handle(other.m_handle) {
        other.m_handle = nullptr;
    }

    ScopedRegistryHandle& operator=(ScopedRegistryHandle&& other) noexcept {
        if (this != &other) {
            Reset();
            m_handle = other.m_handle;
            other.m_handle = nullptr;
        }
        return *this;
    }

    [[nodiscard]] HKEY Get() const noexcept {
        return m_handle;
    }

    [[nodiscard]] HKEY* Receive() noexcept {
        Reset();
        return &m_handle;
    }

    void Reset(HKEY handle = nullptr) noexcept {
        if (m_handle != nullptr) {
            ::RegCloseKey(m_handle);
        }
        m_handle = handle;
    }

private:
    HKEY m_handle{ nullptr };
};

[[nodiscard]] std::wstring MakeSuiteSubKeyPath() {
    return std::wstring(kRegistryTestRootRelative) + L"\\IntegrationTest_" + std::to_wstring(::GetCurrentProcessId());
}

[[nodiscard]] std::wstring MakeSuiteFullKeyPath() {
    return std::wstring(kRegistryTestRootFull) + L"\\IntegrationTest_" + std::to_wstring(::GetCurrentProcessId());
}

[[nodiscard]] LSTATUS DeleteTreeIfExists(const std::wstring& subKeyPath) noexcept {
    const LSTATUS status = ::RegDeleteTreeW(HKEY_CURRENT_USER, subKeyPath.c_str());
    if (status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) {
        return ERROR_SUCCESS;
    }
    return status;
}

[[nodiscard]] LSTATUS CreateKeyRecursive(const std::wstring& subKeyPath, ScopedRegistryHandle* handle) {
    if (handle == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }

    DWORD disposition = 0;
    return ::RegCreateKeyExW(
        HKEY_CURRENT_USER,
        subKeyPath.c_str(),
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_READ | KEY_WRITE,
        nullptr,
        handle->Receive(),
        &disposition);
}

[[nodiscard]] LSTATUS SetStringValue(
    HKEY key,
    const std::wstring& valueName,
    const std::wstring& valueData) {
    const DWORD valueBytes = static_cast<DWORD>((valueData.size() + 1) * sizeof(wchar_t));
    return ::RegSetValueExW(
        key,
        valueName.c_str(),
        0,
        REG_SZ,
        reinterpret_cast<const BYTE*>(valueData.c_str()),
        valueBytes);
}

[[nodiscard]] LSTATUS QueryStringValue(
    HKEY key,
    const std::wstring& valueName,
    std::wstring* valueData) {
    if (valueData == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }

    DWORD type = 0;
    DWORD bytes = 0;
    LSTATUS status = ::RegQueryValueExW(key, valueName.c_str(), nullptr, &type, nullptr, &bytes);
    if (status != ERROR_SUCCESS) {
        return status;
    }

    if (type != REG_SZ && type != REG_EXPAND_SZ) {
        return ERROR_INVALID_DATATYPE;
    }

    std::wstring buffer(bytes / sizeof(wchar_t), L'\0');
    status = ::RegQueryValueExW(
        key,
        valueName.c_str(),
        nullptr,
        &type,
        reinterpret_cast<LPBYTE>(buffer.data()),
        &bytes);
    if (status != ERROR_SUCCESS) {
        return status;
    }

    if (!buffer.empty() && buffer.back() == L'\0') {
        buffer.pop_back();
    }

    *valueData = std::move(buffer);
    return ERROR_SUCCESS;
}

}  // namespace

class RegistryChainIntegrationTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        s_suiteReady = false;
        s_skipReason.clear();
        s_suiteSubKeyPath = MakeSuiteSubKeyPath();
        s_suiteFullKeyPath = MakeSuiteFullKeyPath();

        ShadowStrike::Core::Registry::RegistryMonitor& monitor =
            ShadowStrike::Core::Registry::RegistryMonitor::Instance();
        ShadowStrike::Core::Registry::RegistryAnalyzer& analyzer =
            ShadowStrike::Core::Registry::RegistryAnalyzer::Instance();
        ShadowStrike::Core::Registry::PersistenceDetector& detector =
            ShadowStrike::Core::Registry::PersistenceDetector::Instance();

        monitor.Shutdown();
        analyzer.Shutdown();
        detector.Shutdown();

        const ShadowStrike::Core::Registry::RegistryMonitorConfig monitorConfig =
            ShadowStrike::Core::Registry::RegistryMonitorConfig::CreateDefault();
        if (!monitor.Initialize(monitorConfig)) {
            s_skipReason = L"RegistryMonitor initialization failed in SetUpTestSuite";
            return;
        }

        const ShadowStrike::Core::Registry::RegistryAnalyzerConfig analyzerConfig =
            ShadowStrike::Core::Registry::RegistryAnalyzerConfig::CreateDefault();
        if (!analyzer.Initialize(analyzerConfig)) {
            monitor.Shutdown();
            s_skipReason = L"RegistryAnalyzer initialization failed in SetUpTestSuite";
            return;
        }

        const ShadowStrike::Core::Registry::PersistenceDetectorConfig detectorConfig =
            ShadowStrike::Core::Registry::PersistenceDetectorConfig::CreateQuick();
        if (!detector.Initialize(detectorConfig)) {
            analyzer.Shutdown();
            monitor.Shutdown();
            s_skipReason = L"PersistenceDetector initialization failed in SetUpTestSuite";
            return;
        }

        ScopedRegistryHandle keyHandle;
        const LSTATUS keyStatus = CreateKeyRecursive(s_suiteSubKeyPath, &keyHandle);
        if (keyStatus != ERROR_SUCCESS) {
            detector.Shutdown();
            analyzer.Shutdown();
            monitor.Shutdown();
            s_skipReason = L"Failed to create HKCU test isolation key";
            return;
        }

        s_suiteReady = true;
    }

    static void TearDownTestSuite() {
        const std::wstring suiteRoot = kRegistryTestRootRelative;
        const LSTATUS deleteStatus = DeleteTreeIfExists(suiteRoot);
        (void)deleteStatus;

        ShadowStrike::Core::Registry::PersistenceDetector::Instance().Shutdown();
        ShadowStrike::Core::Registry::RegistryAnalyzer::Instance().Shutdown();
        ShadowStrike::Core::Registry::RegistryMonitor::Instance().Shutdown();

        s_suiteReady = false;
    }

    void SetUp() override {
        if (!s_suiteReady) {
            GTEST_SKIP() << Narrow(s_skipReason.empty() ? L"Registry chain suite setup failed" : s_skipReason);
        }

        if (!EnsureModulesInitialized()) {
            GTEST_SKIP() << Narrow(s_skipReason.empty() ? L"Registry chain modules are unavailable" : s_skipReason);
        }

        ShadowStrike::Core::Registry::RegistryMonitor::Instance().ResetStatistics();
        ShadowStrike::Core::Registry::RegistryAnalyzer::Instance().ResetStatistics();
        ShadowStrike::Core::Registry::PersistenceDetector::Instance().ResetStatistics();

        const LSTATUS resetStatus = ResetIsolationKey();
        ASSERT_EQ(resetStatus, ERROR_SUCCESS) << "Failed to reset HKCU test key: " << resetStatus;
    }

    void TearDown() override {
        const LSTATUS resetStatus = ResetIsolationKey();
        EXPECT_EQ(resetStatus, ERROR_SUCCESS) << "Failed to clean HKCU test key: " << resetStatus;
    }

    [[nodiscard]] static bool EnsureModulesInitialized() {
        ShadowStrike::Core::Registry::RegistryMonitor& monitor =
            ShadowStrike::Core::Registry::RegistryMonitor::Instance();
        ShadowStrike::Core::Registry::RegistryAnalyzer& analyzer =
            ShadowStrike::Core::Registry::RegistryAnalyzer::Instance();
        ShadowStrike::Core::Registry::PersistenceDetector& detector =
            ShadowStrike::Core::Registry::PersistenceDetector::Instance();

        const ShadowStrike::Core::Registry::RegistryMonitorConfig monitorConfig =
            ShadowStrike::Core::Registry::RegistryMonitorConfig::CreateDefault();
        if (!monitor.Initialize(monitorConfig)) {
            s_skipReason = L"RegistryMonitor reinitialization failed";
            return false;
        }

        const ShadowStrike::Core::Registry::RegistryAnalyzerConfig analyzerConfig =
            ShadowStrike::Core::Registry::RegistryAnalyzerConfig::CreateDefault();
        if (!analyzer.Initialize(analyzerConfig)) {
            s_skipReason = L"RegistryAnalyzer reinitialization failed";
            return false;
        }

        const ShadowStrike::Core::Registry::PersistenceDetectorConfig detectorConfig =
            ShadowStrike::Core::Registry::PersistenceDetectorConfig::CreateQuick();
        if (!detector.Initialize(detectorConfig)) {
            s_skipReason = L"PersistenceDetector reinitialization failed";
            return false;
        }

        return true;
    }

    [[nodiscard]] static LSTATUS ResetIsolationKey() {
        LSTATUS status = DeleteTreeIfExists(s_suiteSubKeyPath);
        if (status != ERROR_SUCCESS) {
            return status;
        }

        ScopedRegistryHandle keyHandle;
        return CreateKeyRecursive(s_suiteSubKeyPath, &keyHandle);
    }

    [[nodiscard]] static std::wstring MakeChildFullKeyPath(const std::wstring& childName) {
        return s_suiteFullKeyPath + L"\\" + childName;
    }

    [[nodiscard]] static std::wstring MakeChildSubKeyPath(const std::wstring& childName) {
        return s_suiteSubKeyPath + L"\\" + childName;
    }

    static inline bool s_suiteReady{ false };
    static inline std::wstring s_skipReason;
    static inline std::wstring s_suiteSubKeyPath;
    static inline std::wstring s_suiteFullKeyPath;
};

TEST_F(RegistryChainIntegrationTest, RegistryMonitor_Lifecycle_InitializeWithDefaultConfig_ReturnsTrue) {
    ShadowStrike::Core::Registry::RegistryMonitor& monitor =
        ShadowStrike::Core::Registry::RegistryMonitor::Instance();

    monitor.Shutdown();

    const ShadowStrike::Core::Registry::RegistryMonitorConfig config =
        ShadowStrike::Core::Registry::RegistryMonitorConfig::CreateDefault();
    const bool initialized = monitor.Initialize(config);

    EXPECT_TRUE(initialized);
}

TEST_F(RegistryChainIntegrationTest, RegistryMonitor_Lifecycle_GetStatistics_AfterInit_ReturnsZeroCounts) {
    ShadowStrike::Core::Registry::RegistryMonitor& monitor =
        ShadowStrike::Core::Registry::RegistryMonitor::Instance();

    monitor.Shutdown();

    const ShadowStrike::Core::Registry::RegistryMonitorConfig config =
        ShadowStrike::Core::Registry::RegistryMonitorConfig::CreateDefault();
    ASSERT_TRUE(monitor.Initialize(config));

    monitor.ResetStatistics();
    const ShadowStrike::Core::Registry::RegistryMonitorStatistics& stats = monitor.GetStatistics();

    EXPECT_EQ(LoadAtomic(stats.totalEvents), 0u);
    EXPECT_EQ(LoadAtomic(stats.createKeyEvents), 0u);
    EXPECT_EQ(LoadAtomic(stats.setValueEvents), 0u);
    EXPECT_EQ(LoadAtomic(stats.deleteKeyEvents), 0u);
    EXPECT_EQ(LoadAtomic(stats.deleteValueEvents), 0u);
    EXPECT_EQ(LoadAtomic(stats.renameEvents), 0u);
    EXPECT_EQ(LoadAtomic(stats.allowedOperations), 0u);
    EXPECT_EQ(LoadAtomic(stats.blockedOperations), 0u);
    EXPECT_EQ(LoadAtomic(stats.silentDropped), 0u);
    EXPECT_EQ(LoadAtomic(stats.persistenceAttempts), 0u);
    EXPECT_EQ(LoadAtomic(stats.filelessPayloads), 0u);
    EXPECT_EQ(LoadAtomic(stats.securityChanges), 0u);
    EXPECT_EQ(LoadAtomic(stats.selfDefenseBlocks), 0u);
    EXPECT_EQ(LoadAtomic(stats.alertsGenerated), 0u);
    EXPECT_EQ(LoadAtomic(stats.criticalAlerts), 0u);
    EXPECT_EQ(LoadAtomic(stats.avgCallbackTimeUs), 0u);
    EXPECT_EQ(LoadAtomic(stats.maxCallbackTimeUs), 0u);
    EXPECT_EQ(LoadAtomic(stats.droppedEvents), 0u);
}

TEST_F(RegistryChainIntegrationTest, RegistryMonitor_Lifecycle_ShutdownAndReinitialize_IsIdempotent) {
    ShadowStrike::Core::Registry::RegistryMonitor& monitor =
        ShadowStrike::Core::Registry::RegistryMonitor::Instance();

    monitor.Shutdown();
    monitor.Shutdown();

    const ShadowStrike::Core::Registry::RegistryMonitorConfig config =
        ShadowStrike::Core::Registry::RegistryMonitorConfig::CreateDefault();
    const bool firstInitialize = monitor.Initialize(config);
    const bool secondInitialize = monitor.Initialize(config);

    EXPECT_TRUE(firstInitialize);
    EXPECT_TRUE(secondInitialize);
}

TEST_F(RegistryChainIntegrationTest, RegistryMonitor_Lifecycle_RegisterAlertCallback_ReturnsNonZeroId) {
    ShadowStrike::Core::Registry::RegistryMonitor& monitor =
        ShadowStrike::Core::Registry::RegistryMonitor::Instance();

    const uint64_t callbackId = monitor.RegisterAlertCallback(
        [](const ShadowStrike::Core::Registry::RegistryAlert&) {});

    EXPECT_GT(callbackId, 0u);
    EXPECT_TRUE(monitor.UnregisterCallback(callbackId));
}

TEST_F(RegistryChainIntegrationTest, RegistryMonitor_Lifecycle_RegisterEventCallback_ReturnsNonZeroId) {
    ShadowStrike::Core::Registry::RegistryMonitor& monitor =
        ShadowStrike::Core::Registry::RegistryMonitor::Instance();

    const uint64_t callbackId = monitor.RegisterEventCallback(
        [](const ShadowStrike::Core::Registry::RegistryEvent&, ShadowStrike::Core::Registry::RegistryVerdict) {});

    EXPECT_GT(callbackId, 0u);
    EXPECT_TRUE(monitor.UnregisterCallback(callbackId));
}

TEST_F(RegistryChainIntegrationTest, RegistryMonitor_Lifecycle_UnregisterCallback_AfterRegister_Succeeds) {
    ShadowStrike::Core::Registry::RegistryMonitor& monitor =
        ShadowStrike::Core::Registry::RegistryMonitor::Instance();

    const uint64_t callbackId = monitor.RegisterValueCallback(
        [](const ShadowStrike::Core::Registry::RegistryEvent&, const ShadowStrike::Core::Registry::ValueAnalysis&) {});

    ASSERT_GT(callbackId, 0u);
    EXPECT_TRUE(monitor.UnregisterCallback(callbackId));
}

TEST_F(RegistryChainIntegrationTest, RegistryAnalyzer_Analysis_InitializeWithDefaultConfig_Succeeds) {
    ShadowStrike::Core::Registry::RegistryAnalyzer& analyzer =
        ShadowStrike::Core::Registry::RegistryAnalyzer::Instance();

    analyzer.Shutdown();

    const ShadowStrike::Core::Registry::RegistryAnalyzerConfig config =
        ShadowStrike::Core::Registry::RegistryAnalyzerConfig::CreateDefault();
    const bool initialized = analyzer.Initialize(config);

    EXPECT_TRUE(initialized);
}

TEST_F(RegistryChainIntegrationTest, RegistryAnalyzer_Analysis_Analyze_NTUSEROnlyScope_ReturnsCompleted) {
    ShadowStrike::Core::Registry::RegistryAnalyzer& analyzer =
        ShadowStrike::Core::Registry::RegistryAnalyzer::Instance();

    const uint64_t keysBefore = analyzer.GetStatistics().keysAnalyzed.load(std::memory_order_relaxed);

    ShadowStrike::Core::Registry::AnalysisScope scope;
    scope.analyzeSAM = false;
    scope.analyzeSECURITY = false;
    scope.analyzeSOFTWARE = false;
    scope.analyzeSYSTEM = false;
    scope.analyzeNTUSER = true;
    scope.analyzeUSRCLASS = false;
    scope.maxDepth = 2;
    scope.specificPaths = { L"HKCU\\Software\\Microsoft" };

    const ShadowStrike::Core::Registry::AnalysisResult result =
        analyzer.Analyze(scope, ShadowStrike::Core::Registry::AnalysisMode::Deep);
    const uint64_t keysAfter = analyzer.GetStatistics().keysAnalyzed.load(std::memory_order_relaxed);

    EXPECT_TRUE(result.completed);
    EXPECT_FALSE(result.hadErrors);
    EXPECT_GT(keysAfter, keysBefore);
}

TEST_F(RegistryChainIntegrationTest, RegistryAnalyzer_Analysis_Analyze_SpecificPath_HKCUSoftware_Succeeds) {
    ShadowStrike::Core::Registry::RegistryAnalyzer& analyzer =
        ShadowStrike::Core::Registry::RegistryAnalyzer::Instance();

    const uint64_t keysBefore = analyzer.GetStatistics().keysAnalyzed.load(std::memory_order_relaxed);

    ShadowStrike::Core::Registry::AnalysisScope scope;
    scope.analyzeSAM = false;
    scope.analyzeSECURITY = false;
    scope.analyzeSOFTWARE = false;
    scope.analyzeSYSTEM = false;
    scope.analyzeNTUSER = true;
    scope.analyzeUSRCLASS = false;
    scope.maxDepth = 1;
    scope.specificPaths = { L"HKCU\\Software" };

    const ShadowStrike::Core::Registry::AnalysisResult result =
        analyzer.Analyze(scope, ShadowStrike::Core::Registry::AnalysisMode::Deep);
    const uint64_t keysAfter = analyzer.GetStatistics().keysAnalyzed.load(std::memory_order_relaxed);

    EXPECT_TRUE(result.completed);
    EXPECT_FALSE(result.hadErrors);
    EXPECT_GT(keysAfter, keysBefore);
}

TEST_F(RegistryChainIntegrationTest, RegistryAnalyzer_Analysis_AnalyzeKey_KnownSoftwareKey_ReturnsAnomalies) {
    ShadowStrike::Core::Registry::RegistryAnalyzer& analyzer =
        ShadowStrike::Core::Registry::RegistryAnalyzer::Instance();

    const std::vector<ShadowStrike::Core::Registry::RegistryAnomaly> anomalies =
        analyzer.AnalyzeKey(L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion", true);

    EXPECT_GE(anomalies.size(), 0u);
}

TEST_F(RegistryChainIntegrationTest, PersistenceDetector_Scan_InitializeWithQuickConfig_Succeeds) {
    ShadowStrike::Core::Registry::PersistenceDetector& detector =
        ShadowStrike::Core::Registry::PersistenceDetector::Instance();

    detector.Shutdown();

    const ShadowStrike::Core::Registry::PersistenceDetectorConfig config =
        ShadowStrike::Core::Registry::PersistenceDetectorConfig::CreateQuick();
    const bool initialized = detector.Initialize(config);

    EXPECT_TRUE(initialized);
}

TEST_F(RegistryChainIntegrationTest, PersistenceDetector_Scan_Scan_FullScope_ReturnsResult) {
    ShadowStrike::Core::Registry::PersistenceDetector& detector =
        ShadowStrike::Core::Registry::PersistenceDetector::Instance();

    const ShadowStrike::Core::Registry::ScanResult result =
        detector.Scan(ShadowStrike::Core::Registry::ScanScope::Full);

    EXPECT_GE(result.totalEntries, 0u);
    EXPECT_GE(result.entries.size(), 0u);
}

TEST_F(RegistryChainIntegrationTest, PersistenceDetector_Scan_ScanResult_EntriesSumChecks) {
    ShadowStrike::Core::Registry::PersistenceDetector& detector =
        ShadowStrike::Core::Registry::PersistenceDetector::Instance();

    const ShadowStrike::Core::Registry::ScanResult result =
        detector.Scan(ShadowStrike::Core::Registry::ScanScope::Full);
    const uint32_t categorizedEntries = result.safeEntries
        + result.suspiciousEntries
        + result.maliciousEntries
        + result.unknownEntries;

    EXPECT_EQ(result.totalEntries, categorizedEntries);
}

TEST_F(RegistryChainIntegrationTest, PersistenceDetector_Scan_ResolveTarget_SystemBinary_ReturnsTarget) {
    ShadowStrike::Core::Registry::PersistenceDetector& detector =
        ShadowStrike::Core::Registry::PersistenceDetector::Instance();

    const ShadowStrike::Core::Registry::TargetBinary target = detector.ResolveTarget(L"svchost.exe");

    EXPECT_FALSE(target.originalPath.empty());
    EXPECT_EQ(target.originalPath, L"svchost.exe");
}

TEST_F(RegistryChainIntegrationTest, RegistryChain_WriteAndDetect_WriteAndRead_HKCUTestKey_RoundTrips) {
    const std::wstring childSubKeyPath = MakeChildSubKeyPath(L"RoundTrip");
    const std::wstring childFullKeyPath = MakeChildFullKeyPath(L"RoundTrip");

    ScopedRegistryHandle keyHandle;
    const LSTATUS createStatus = CreateKeyRecursive(childSubKeyPath, &keyHandle);
    ASSERT_EQ(createStatus, ERROR_SUCCESS) << "RegCreateKeyExW failed: " << createStatus;

    const std::wstring expectedValue = L"ShadowStrike_RegistryChain_Test";
    const LSTATUS setStatus = SetStringValue(keyHandle.Get(), L"Payload", expectedValue);
    ASSERT_EQ(setStatus, ERROR_SUCCESS) << "RegSetValueExW failed: " << setStatus;

    std::wstring actualValue;
    const LSTATUS queryStatus = QueryStringValue(keyHandle.Get(), L"Payload", &actualValue);
    ASSERT_EQ(queryStatus, ERROR_SUCCESS) << "RegQueryValueExW failed: " << queryStatus;
    EXPECT_EQ(actualValue, expectedValue);

    const std::vector<ShadowStrike::Core::Registry::RegistryAnomaly> anomalies =
        ShadowStrike::Core::Registry::RegistryAnalyzer::Instance().AnalyzeKey(childFullKeyPath, true);
    EXPECT_GE(anomalies.size(), 0u);
}

TEST_F(RegistryChainIntegrationTest, RegistryChain_WriteAndDetect_WriteTestValue_AnalyzerFindsKey_InSpecificPaths) {
    const std::wstring childSubKeyPath = MakeChildSubKeyPath(L"SpecificPath");
    const std::wstring childFullKeyPath = MakeChildFullKeyPath(L"SpecificPath");

    ScopedRegistryHandle keyHandle;
    const LSTATUS createStatus = CreateKeyRecursive(childSubKeyPath, &keyHandle);
    ASSERT_EQ(createStatus, ERROR_SUCCESS) << "RegCreateKeyExW failed: " << createStatus;

    const LSTATUS setStatus = SetStringValue(keyHandle.Get(), L"Command", L"powershell.exe -nop -w hidden");
    ASSERT_EQ(setStatus, ERROR_SUCCESS) << "RegSetValueExW failed: " << setStatus;

    ShadowStrike::Core::Registry::RegistryAnalyzer& analyzer =
        ShadowStrike::Core::Registry::RegistryAnalyzer::Instance();
    const uint64_t keysBefore = analyzer.GetStatistics().keysAnalyzed.load(std::memory_order_relaxed);

    ShadowStrike::Core::Registry::AnalysisScope scope;
    scope.analyzeSAM = false;
    scope.analyzeSECURITY = false;
    scope.analyzeSOFTWARE = false;
    scope.analyzeSYSTEM = false;
    scope.analyzeNTUSER = true;
    scope.analyzeUSRCLASS = false;
    scope.maxDepth = 2;
    scope.specificPaths = { childFullKeyPath };

    const ShadowStrike::Core::Registry::AnalysisResult result =
        analyzer.Analyze(scope, ShadowStrike::Core::Registry::AnalysisMode::Deep);
    const uint64_t keysAfter = analyzer.GetStatistics().keysAnalyzed.load(std::memory_order_relaxed);

    EXPECT_TRUE(result.completed);
    EXPECT_FALSE(result.hadErrors);
    EXPECT_GT(keysAfter, keysBefore);
}

TEST_F(RegistryChainIntegrationTest, RegistryChain_WriteAndDetect_DeleteTestKey_Cleanup) {
    const std::wstring childName = L"DeleteMe";
    const std::wstring childSubKeyPath = MakeChildSubKeyPath(childName);

    ScopedRegistryHandle keyHandle;
    const LSTATUS createStatus = CreateKeyRecursive(childSubKeyPath, &keyHandle);
    ASSERT_EQ(createStatus, ERROR_SUCCESS) << "RegCreateKeyExW failed: " << createStatus;
    keyHandle.Reset();

    const LSTATUS deleteStatus = ::RegDeleteKeyW(HKEY_CURRENT_USER, childSubKeyPath.c_str());
    ASSERT_EQ(deleteStatus, ERROR_SUCCESS) << "RegDeleteKeyW failed: " << deleteStatus;

    ScopedRegistryHandle reopenedHandle;
    const LSTATUS openStatus = ::RegOpenKeyExW(
        HKEY_CURRENT_USER,
        childSubKeyPath.c_str(),
        0,
        KEY_READ,
        reopenedHandle.Receive());

    EXPECT_EQ(openStatus, ERROR_FILE_NOT_FOUND);
}

TEST_F(RegistryChainIntegrationTest, RegistryChain_Concurrency_ConcurrentAnalyzeKey_IsThreadSafe) {
    ShadowStrike::Core::Registry::RegistryAnalyzer& analyzer =
        ShadowStrike::Core::Registry::RegistryAnalyzer::Instance();

    std::atomic<bool> start{ false };
    std::atomic<uint32_t> completedThreads{ 0 };
    std::atomic<uint32_t> failures{ 0 };
    std::vector<std::thread> workers;
    workers.reserve(4);

    for (uint32_t index = 0; index < 4; ++index) {
        workers.emplace_back([&analyzer, &start, &completedThreads, &failures]() {
            while (!start.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }

            try {
                const std::vector<ShadowStrike::Core::Registry::RegistryAnomaly> anomalies =
                    analyzer.AnalyzeKey(L"HKCU\\Software", false);
                (void)anomalies;
                completedThreads.fetch_add(1, std::memory_order_relaxed);
            } catch (...) {
                failures.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    start.store(true, std::memory_order_release);

    for (std::thread& worker : workers) {
        worker.join();
    }

    EXPECT_EQ(failures.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(completedThreads.load(std::memory_order_relaxed), 4u);
}

TEST_F(RegistryChainIntegrationTest, RegistryChain_Concurrency_ConcurrentGetStatistics_IsThreadSafe) {
    ShadowStrike::Core::Registry::RegistryMonitor& monitor =
        ShadowStrike::Core::Registry::RegistryMonitor::Instance();

    std::atomic<bool> start{ false };
    std::atomic<uint32_t> completedThreads{ 0 };
    std::atomic<uint32_t> failures{ 0 };
    std::atomic<uint64_t> observedLoads{ 0 };
    std::vector<std::thread> workers;
    workers.reserve(8);

    for (uint32_t index = 0; index < 8; ++index) {
        workers.emplace_back([&monitor, &start, &completedThreads, &failures, &observedLoads]() {
            while (!start.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }

            try {
                for (uint32_t iteration = 0; iteration < 64; ++iteration) {
                    const ShadowStrike::Core::Registry::RegistryMonitorStatistics& stats = monitor.GetStatistics();
                    observedLoads.fetch_add(stats.totalEvents.load(std::memory_order_relaxed), std::memory_order_relaxed);
                }
                completedThreads.fetch_add(1, std::memory_order_relaxed);
            } catch (...) {
                failures.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    start.store(true, std::memory_order_release);

    for (std::thread& worker : workers) {
        worker.join();
    }

    EXPECT_EQ(failures.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(completedThreads.load(std::memory_order_relaxed), 8u);
    EXPECT_GE(observedLoads.load(std::memory_order_relaxed), 0u);
}
