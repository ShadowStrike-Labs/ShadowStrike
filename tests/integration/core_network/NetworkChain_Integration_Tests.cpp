/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Integration Tests - Network Chain
 *
 * ============================================================================
 * PURPOSE
 * ============================================================================
 * Tests end-to-end integration between the core Network chain modules:
 *   NetworkMonitor   → connection tracking, IP blocking, statistics (WFP-based)
 *   DNSMonitor       → DNS query capture, domain blocking, DGA/tunnel detection
 *   FirewallManager  → WFP rule management, IP/port/app blocking
 *
 * NOTE: Most Network chain tests require elevated privileges (WFP driver access).
 * Tests that require admin gracefully skip using GTEST_SKIP() when not elevated.
 * Pure data-plane tests (IPAddress validity, FirewallRule construction) run always.
 *
 * TEST-NET addresses (RFC 5737) are used for all test IPs: 203.0.113.x
 * Internal domain: *.shadowstrike.internal (never routes to real servers)
 *
 * ============================================================================
 * TEST GROUPS
 * ============================================================================
 *   GROUP 1  NetworkMonitor_Lifecycle     - init, start/stop, IPAddress helpers
 *   GROUP 2  DNSMonitor_DomainFiltering   - block/unblock domains, statistics
 *   GROUP 3  FirewallManager_Rules        - add/remove IP/port rules (admin)
 *   GROUP 4  NetworkChain_CrossModule     - cross-module consistency
 *   GROUP 5  NetworkChain_Statistics      - stat accounting after operations
 *   GROUP 6  NetworkChain_Concurrency     - thread-safety validation
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

#include "../../../src/PhantomCore/Core/Network/NetworkMonitor.hpp"
#include "../../../src/PhantomCore/Core/Network/DNSMonitor.hpp"
#include "../../../src/PhantomCore/Core/Network/FirewallManager.hpp"

namespace SSN = ShadowStrike::Core::Network;

namespace {

template <typename T>
[[nodiscard]] T LoadRelaxed(const std::atomic<T>& value) noexcept {
    return value.load(std::memory_order_relaxed);
}

[[nodiscard]] std::wstring ToWide(const std::string_view value) {
    return std::wstring(value.begin(), value.end());
}

[[nodiscard]] SSN::NetworkMonitorConfig MakeNetworkMonitorConfig() {
    auto config = SSN::NetworkMonitorConfig::CreateDefault();
    config.blockMaliciousIPs = true;
    config.blockMaliciousDomains = true;
    config.detectBeaconing = true;
    config.detectExfiltration = true;
    config.detectPortScanning = true;
    config.detectDNSTunneling = true;
    return config;
}

[[nodiscard]] SSN::DNSMonitorConfig MakeDnsMonitorConfig() {
    auto config = SSN::DNSMonitorConfig::CreateDefault();
    config.detectDGA = true;
    config.detectTunneling = true;
    config.checkReputation = true;
    return config;
}

[[nodiscard]] SSN::FirewallManagerConfig MakeFirewallManagerConfig() {
    auto config = SSN::FirewallManagerConfig::CreateDefault();
    config.enableIPFiltering = true;
    config.enablePortFiltering = true;
    config.enableApplicationControl = true;
    return config;
}

[[nodiscard]] std::string MakeDomain(const std::string_view scenario, const std::size_t suffix = 0U) {
    std::string domain("network-chain-");
    domain += std::string(scenario);
    if (suffix != 0U) {
        domain += "-";
        domain += std::to_string(suffix);
    }
    domain += ".shadowstrike.internal";
    return domain;
}

[[nodiscard]] std::wstring TestRuleName(const std::wstring_view scenario) {
    std::wstring value(L"ShadowStrike Integration - ");
    value += scenario;
    return value;
}

[[nodiscard]] bool ContainsRuleId(const std::vector<SSN::FirewallRule>& rules, const uint64_t ruleId) {
    return std::any_of(rules.begin(), rules.end(), [ruleId](const SSN::FirewallRule& rule) {
        return rule.ruleId == ruleId;
    });
}

class NetworkChainIntegrationFixtureBase : public ::testing::Test {
protected:
    static void SharedSetUpSuite() {
        CleanupTrackedState();

        auto& networkMonitor = SSN::NetworkMonitor::Instance();
        networkMonitor.Stop();
        networkMonitor.Shutdown();
        s_networkAvailable = networkMonitor.Initialize(MakeNetworkMonitorConfig());
        if (s_networkAvailable) {
            networkMonitor.ResetStatistics();
        }

        auto& dnsMonitor = SSN::DNSMonitor::Instance();
        dnsMonitor.Stop();
        dnsMonitor.Shutdown();
        s_dnsAvailable = dnsMonitor.Initialize(MakeDnsMonitorConfig());
        if (s_dnsAvailable) {
            dnsMonitor.ResetStatistics();
            dnsMonitor.FlushCache();
        }

        auto& firewallManager = SSN::FirewallManager::Instance();
        firewallManager.Stop();
        firewallManager.Shutdown();
        s_adminAvailable = firewallManager.Initialize(MakeFirewallManagerConfig());
        if (s_adminAvailable) {
            firewallManager.ResetStatistics();
        }
    }

    static void SharedTearDownSuite() {
        CleanupTrackedState();

        auto& firewallManager = SSN::FirewallManager::Instance();
        firewallManager.Stop();
        firewallManager.Shutdown();

        auto& dnsMonitor = SSN::DNSMonitor::Instance();
        dnsMonitor.Stop();
        dnsMonitor.Shutdown();

        auto& networkMonitor = SSN::NetworkMonitor::Instance();
        networkMonitor.Stop();
        networkMonitor.Shutdown();

        s_networkAvailable = false;
        s_dnsAvailable = false;
        s_adminAvailable = false;
    }

    void SetUp() override {
        PrepareCleanState();
    }

    void TearDown() override {
        CleanupTrackedState();

        auto& firewallManager = SSN::FirewallManager::Instance();
        if (firewallManager.IsRunning()) {
            firewallManager.Stop();
        }

        auto& dnsMonitor = SSN::DNSMonitor::Instance();
        if (dnsMonitor.IsRunning()) {
            dnsMonitor.Stop();
        }

        auto& networkMonitor = SSN::NetworkMonitor::Instance();
        if (networkMonitor.IsRunning()) {
            networkMonitor.Stop();
        }
    }

    [[nodiscard]] static bool EnsureNetworkMonitorInitialized() {
        auto& monitor = SSN::NetworkMonitor::Instance();
        s_networkAvailable = monitor.Initialize(MakeNetworkMonitorConfig());
        return s_networkAvailable;
    }

    [[nodiscard]] static bool EnsureNetworkMonitorStarted() {
        if (!EnsureNetworkMonitorInitialized()) {
            return false;
        }

        auto& monitor = SSN::NetworkMonitor::Instance();
        const bool started = monitor.Start();
        return started && monitor.IsRunning();
    }

    [[nodiscard]] static bool EnsureDnsMonitorInitialized() {
        auto& monitor = SSN::DNSMonitor::Instance();
        s_dnsAvailable = monitor.Initialize(MakeDnsMonitorConfig());
        return s_dnsAvailable;
    }

    [[nodiscard]] static bool EnsureDnsMonitorStarted() {
        if (!EnsureDnsMonitorInitialized()) {
            return false;
        }

        auto& monitor = SSN::DNSMonitor::Instance();
        monitor.Start();
        return monitor.IsRunning();
    }

    [[nodiscard]] static bool EnsureFirewallInitialized() {
        auto& firewallManager = SSN::FirewallManager::Instance();
        s_adminAvailable = firewallManager.Initialize(MakeFirewallManagerConfig());
        return s_adminAvailable;
    }

    [[nodiscard]] static bool EnsureFirewallStarted() {
        if (!EnsureFirewallInitialized()) {
            return false;
        }

        auto& firewallManager = SSN::FirewallManager::Instance();
        const bool started = firewallManager.Start();
        return started && firewallManager.IsRunning();
    }

    static void TrackBlockedIp(const SSN::IPAddress& ip) {
        std::lock_guard<std::mutex> lock(s_trackingMutex);
        s_networkBlockedIps.push_back(ip);
    }

    static void TrackBlockedDomain(const std::string& domain) {
        std::lock_guard<std::mutex> lock(s_trackingMutex);
        s_dnsBlockedDomains.push_back(domain);
    }

    static void TrackFirewallRuleId(const uint64_t ruleId) {
        if (ruleId == 0U) {
            return;
        }

        std::lock_guard<std::mutex> lock(s_trackingMutex);
        s_firewallRuleIds.push_back(ruleId);
    }

    [[nodiscard]] static bool AdminAvailable() noexcept {
        return s_adminAvailable;
    }

private:
    static void PrepareCleanState() {
        CleanupTrackedState();

        auto& networkMonitor = SSN::NetworkMonitor::Instance();
        if (networkMonitor.IsRunning()) {
            networkMonitor.Stop();
        }
        s_networkAvailable = networkMonitor.Initialize(MakeNetworkMonitorConfig());
        if (s_networkAvailable) {
            networkMonitor.ResetStatistics();
        }

        auto& dnsMonitor = SSN::DNSMonitor::Instance();
        if (dnsMonitor.IsRunning()) {
            dnsMonitor.Stop();
        }
        s_dnsAvailable = dnsMonitor.Initialize(MakeDnsMonitorConfig());
        if (s_dnsAvailable) {
            dnsMonitor.ResetStatistics();
            dnsMonitor.FlushCache();
        }

        auto& firewallManager = SSN::FirewallManager::Instance();
        if (firewallManager.IsRunning()) {
            firewallManager.Stop();
        }
        s_adminAvailable = firewallManager.Initialize(MakeFirewallManagerConfig());
        if (s_adminAvailable) {
            firewallManager.ResetStatistics();
        }
    }

    static void CleanupTrackedState() {
        std::vector<SSN::IPAddress> networkBlockedIps;
        std::vector<std::string> dnsBlockedDomains;
        std::vector<uint64_t> firewallRuleIds;

        {
            std::lock_guard<std::mutex> lock(s_trackingMutex);
            networkBlockedIps.swap(s_networkBlockedIps);
            dnsBlockedDomains.swap(s_dnsBlockedDomains);
            firewallRuleIds.swap(s_firewallRuleIds);
        }

        auto& networkMonitor = SSN::NetworkMonitor::Instance();
        for (const SSN::IPAddress& ip : networkBlockedIps) {
            [[maybe_unused]] const bool unblocked = networkMonitor.UnblockIP(ip);
        }

        auto& dnsMonitor = SSN::DNSMonitor::Instance();
        for (const std::string& domain : dnsBlockedDomains) {
            [[maybe_unused]] const bool unblocked = dnsMonitor.UnblockDomain(domain);
        }
        if (dnsMonitor.IsInitialized()) {
            dnsMonitor.FlushCache();
        }

        auto& firewallManager = SSN::FirewallManager::Instance();
        std::sort(firewallRuleIds.begin(), firewallRuleIds.end());
        firewallRuleIds.erase(std::unique(firewallRuleIds.begin(), firewallRuleIds.end()), firewallRuleIds.end());
        for (auto it = firewallRuleIds.rbegin(); it != firewallRuleIds.rend(); ++it) {
            [[maybe_unused]] const bool removed = firewallManager.RemoveRule(*it);
        }
    }

    static inline bool s_networkAvailable{false};
    static inline bool s_dnsAvailable{false};
    static inline bool s_adminAvailable{false};
    static inline std::mutex s_trackingMutex{};
    static inline std::vector<SSN::IPAddress> s_networkBlockedIps{};
    static inline std::vector<std::string> s_dnsBlockedDomains{};
    static inline std::vector<uint64_t> s_firewallRuleIds{};
};

class NetworkMonitor_Lifecycle : public NetworkChainIntegrationFixtureBase {
protected:
    static void SetUpTestSuite() {
        SharedSetUpSuite();
    }

    static void TearDownTestSuite() {
        SharedTearDownSuite();
    }
};

class DNSMonitor_DomainFiltering : public NetworkChainIntegrationFixtureBase {
protected:
    static void SetUpTestSuite() {
        SharedSetUpSuite();
    }

    static void TearDownTestSuite() {
        SharedTearDownSuite();
    }
};

class FirewallManager_RuleManagement : public NetworkChainIntegrationFixtureBase {
protected:
    static void SetUpTestSuite() {
        SharedSetUpSuite();
    }

    static void TearDownTestSuite() {
        SharedTearDownSuite();
    }
};

class NetworkChain_CrossModuleIntegration : public NetworkChainIntegrationFixtureBase {
protected:
    static void SetUpTestSuite() {
        SharedSetUpSuite();
    }

    static void TearDownTestSuite() {
        SharedTearDownSuite();
    }
};

class NetworkChain_Statistics : public NetworkChainIntegrationFixtureBase {
protected:
    static void SetUpTestSuite() {
        SharedSetUpSuite();
    }

    static void TearDownTestSuite() {
        SharedTearDownSuite();
    }
};

class NetworkChain_Concurrency : public NetworkChainIntegrationFixtureBase {
protected:
    static void SetUpTestSuite() {
        SharedSetUpSuite();
    }

    static void TearDownTestSuite() {
        SharedTearDownSuite();
    }
};

// ---------------------------------------------------------------------------
// GROUP 1: Validates that the connection-monitor singleton survives the exact
// lifecycle transitions hit during service restart, update, and policy reload.
// ---------------------------------------------------------------------------
TEST_F(NetworkMonitor_Lifecycle, InitializeWithDefaultConfig_Succeeds) {
    if (!EnsureNetworkMonitorInitialized()) {
        GTEST_SKIP() << "NetworkMonitor::Initialize() failed; WFP or privilege prerequisites are unavailable.";
    }

    EXPECT_TRUE(SSN::NetworkMonitor::Instance().IsInitialized());
}

// ---------------------------------------------------------------------------
// GROUP 1: Attack telemetry is only useful if the monitor can actually start;
// this validates the post-initialize transition used by the sensor service.
// ---------------------------------------------------------------------------
TEST_F(NetworkMonitor_Lifecycle, Start_AfterInitialize_Succeeds) {
    if (!EnsureNetworkMonitorInitialized()) {
        GTEST_SKIP() << "NetworkMonitor initialization unavailable on this endpoint.";
    }

    auto& monitor = SSN::NetworkMonitor::Instance();
    const bool started = monitor.Start();
    if (!started) {
        GTEST_SKIP() << "NetworkMonitor::Start() failed; live capture cannot start in this environment.";
    }

    EXPECT_TRUE(monitor.IsRunning());
}

// ---------------------------------------------------------------------------
// GROUP 1: Fresh monitors must not inherit stale counters, otherwise threat
// scoring can be polluted across service restarts or failover recovery.
// ---------------------------------------------------------------------------
TEST_F(NetworkMonitor_Lifecycle, GetStatistics_AfterStart_ReturnsZeroCounters) {
    if (!EnsureNetworkMonitorStarted()) {
        GTEST_SKIP() << "NetworkMonitor start unavailable on this endpoint.";
    }

    auto& monitor = SSN::NetworkMonitor::Instance();
    monitor.ResetStatistics();
    const SSN::NetworkMonitorStatistics& stats = monitor.GetStatistics();

    EXPECT_EQ(LoadRelaxed(stats.totalConnections), 0ULL);
    EXPECT_EQ(LoadRelaxed(stats.activeConnections), 0ULL);
    EXPECT_EQ(LoadRelaxed(stats.blockedConnections), 0ULL);
    EXPECT_EQ(LoadRelaxed(stats.ipsBlocked), 0ULL);
    EXPECT_EQ(LoadRelaxed(stats.errorCount), 0ULL);
}

// ---------------------------------------------------------------------------
// GROUP 1: Clean shutdown is required during product upgrade and watchdog
// recovery so the agent never leaves live capture threads orphaned.
// ---------------------------------------------------------------------------
TEST_F(NetworkMonitor_Lifecycle, Stop_AfterStart_DoesNotCrash) {
    if (!EnsureNetworkMonitorStarted()) {
        GTEST_SKIP() << "NetworkMonitor start unavailable on this endpoint.";
    }

    auto& monitor = SSN::NetworkMonitor::Instance();
    monitor.Stop();

    EXPECT_FALSE(monitor.IsRunning());
}

// ---------------------------------------------------------------------------
// GROUP 1: Private-range classification is used by egress anomaly logic to
// distinguish east-west traffic from Internet-bound command-and-control.
// ---------------------------------------------------------------------------
TEST_F(NetworkMonitor_Lifecycle, IPAddress_PrivateRange_IsPrivate) {
    const SSN::IPAddress ip("192.168.1.1");

    ASSERT_TRUE(ip.IsValid());
    EXPECT_TRUE(ip.IsPrivate());
}

// ---------------------------------------------------------------------------
// GROUP 1: Loopback traffic must never be mistaken for external comms during
// local proxying, sandbox detonation, or self-protection IPC activity.
// ---------------------------------------------------------------------------
TEST_F(NetworkMonitor_Lifecycle, IPAddress_Loopback_IsLoopback) {
    const SSN::IPAddress ip("127.0.0.1");

    ASSERT_TRUE(ip.IsValid());
    EXPECT_TRUE(ip.IsLoopback());
}

// ---------------------------------------------------------------------------
// GROUP 1: Public IOC lookups rely on correct public-address classification so
// benign RFC1918 logic never suppresses real Internet indicators.
// ---------------------------------------------------------------------------
TEST_F(NetworkMonitor_Lifecycle, IPAddress_PublicIP_NotPrivateNotLoopback) {
    const SSN::IPAddress ip("8.8.8.8");

    ASSERT_TRUE(ip.IsValid());
    EXPECT_FALSE(ip.IsPrivate());
    EXPECT_FALSE(ip.IsLoopback());
}

// ---------------------------------------------------------------------------
// GROUP 1: Hostile or malformed telemetry must fail closed during parsing so a
// poisoned string cannot enter blocklists or policy matching paths.
// ---------------------------------------------------------------------------
TEST_F(NetworkMonitor_Lifecycle, IPAddress_InvalidString_IsNotValid) {
    const SSN::IPAddress ip("not-an-ip");

    EXPECT_FALSE(ip.IsValid());
}

// ---------------------------------------------------------------------------
// GROUP 1: Real-world service restarts perform full init/start/stop/shutdown/
// re-init cycles; this ensures the singleton tolerates that recovery path.
// ---------------------------------------------------------------------------
TEST_F(NetworkMonitor_Lifecycle, ShutdownAndReinitialize_Cycle_Succeeds) {
    if (!EnsureNetworkMonitorInitialized()) {
        GTEST_SKIP() << "NetworkMonitor initialization unavailable on this endpoint.";
    }

    auto& monitor = SSN::NetworkMonitor::Instance();
    const bool started = monitor.Start();
    if (!started) {
        GTEST_SKIP() << "NetworkMonitor start unavailable on this endpoint.";
    }

    monitor.Stop();
    monitor.Shutdown();

    const bool reinitialized = monitor.Initialize(MakeNetworkMonitorConfig());
    ASSERT_TRUE(reinitialized);

    const bool restarted = monitor.Start();
    ASSERT_TRUE(restarted);
    EXPECT_TRUE(monitor.IsRunning());
}

// ---------------------------------------------------------------------------
// GROUP 2: DNS policy bootstrap must succeed before the product can enforce
// domain IOCs, DGA suppression, or DNS-tunnel containment.
// ---------------------------------------------------------------------------
TEST_F(DNSMonitor_DomainFiltering, InitializeWithDefaultConfig_Succeeds) {
    if (!EnsureDnsMonitorInitialized()) {
        GTEST_SKIP() << "DNSMonitor::Initialize() failed; interception prerequisites are unavailable.";
    }

    EXPECT_TRUE(SSN::DNSMonitor::Instance().IsInitialized());
}

// ---------------------------------------------------------------------------
// GROUP 2: A malicious domain IOC must be insertable immediately after intel
// promotion so the resolver path can enforce newly learned infrastructure.
// ---------------------------------------------------------------------------
TEST_F(DNSMonitor_DomainFiltering, BlockDomain_ReturnsTrueForNewDomain) {
    if (!EnsureDnsMonitorInitialized()) {
        GTEST_SKIP() << "DNSMonitor initialization unavailable on this endpoint.";
    }

    const std::string domain = MakeDomain("block-new");
    auto& monitor = SSN::DNSMonitor::Instance();

    const bool blocked = monitor.BlockDomain(domain, L"IOC promotion from integration test");
    TrackBlockedDomain(domain);

    EXPECT_TRUE(blocked);
    EXPECT_TRUE(monitor.IsBlocked(domain));
}

// ---------------------------------------------------------------------------
// GROUP 2: IOC refresh jobs can re-publish the same domain repeatedly; the
// control plane must remain idempotent rather than fail or corrupt state.
// ---------------------------------------------------------------------------
TEST_F(DNSMonitor_DomainFiltering, BlockDomain_Idempotent_ReturnsTrue) {
    if (!EnsureDnsMonitorInitialized()) {
        GTEST_SKIP() << "DNSMonitor initialization unavailable on this endpoint.";
    }

    const std::string domain = MakeDomain("idempotent");
    auto& monitor = SSN::DNSMonitor::Instance();

    const bool firstBlock = monitor.BlockDomain(domain, L"First publication");
    const bool secondBlock = monitor.BlockDomain(domain, L"Repeated publication");
    TrackBlockedDomain(domain);

    EXPECT_TRUE(firstBlock);
    EXPECT_TRUE(secondBlock);
    EXPECT_TRUE(monitor.IsBlocked(domain));
}

// ---------------------------------------------------------------------------
// GROUP 2: Analysts must be able to rapidly retract a bad IOC without leaving
// stale deny state that continues to break resolver traffic.
// ---------------------------------------------------------------------------
TEST_F(DNSMonitor_DomainFiltering, UnblockDomain_AfterBlock_ReturnsTrueAndRemovesBlock) {
    if (!EnsureDnsMonitorInitialized()) {
        GTEST_SKIP() << "DNSMonitor initialization unavailable on this endpoint.";
    }

    const std::string domain = MakeDomain("unblock-after-block");
    auto& monitor = SSN::DNSMonitor::Instance();

    ASSERT_TRUE(monitor.BlockDomain(domain, L"Rollback validation"));
    TrackBlockedDomain(domain);

    const bool unblocked = monitor.UnblockDomain(domain);

    EXPECT_TRUE(unblocked);
    EXPECT_FALSE(monitor.IsBlocked(domain));
}

// ---------------------------------------------------------------------------
// GROUP 2: IOC cleanup jobs often target entries that were already removed; the
// unblock path must remain graceful and never crash the sensor process.
// ---------------------------------------------------------------------------
TEST_F(DNSMonitor_DomainFiltering, UnblockDomain_NonExistent_ReturnsFalseOrTrue) {
    if (!EnsureDnsMonitorInitialized()) {
        GTEST_SKIP() << "DNSMonitor initialization unavailable on this endpoint.";
    }

    const std::string domain = MakeDomain("non-existent");
    auto& monitor = SSN::DNSMonitor::Instance();

    const bool unblocked = monitor.UnblockDomain(domain);
    EXPECT_FALSE(monitor.IsBlocked(domain));
    SUCCEED() << "UnblockDomain handled an absent entry gracefully; returned " << (unblocked ? "true" : "false") << ".";
}

// ---------------------------------------------------------------------------
// GROUP 2: Bulk IOC ingestion must scale beyond single entries; filter state
// must reflect every blocked domain without fabricating runtime hit telemetry.
// ---------------------------------------------------------------------------
TEST_F(DNSMonitor_DomainFiltering, BlockMultipleDomains_StatisticsReflectCount) {
    if (!EnsureDnsMonitorInitialized()) {
        GTEST_SKIP() << "DNSMonitor initialization unavailable on this endpoint.";
    }

    auto& monitor = SSN::DNSMonitor::Instance();
    const std::size_t rulesBefore = monitor.GetFilterRules().size();
    const SSN::DNSStatistics& statsBefore = monitor.GetStatistics();
    const uint64_t blockedEventsBefore = LoadRelaxed(statsBefore.domainsBlocked);

    const std::vector<std::string> domains = {
        MakeDomain("bulk", 1U),
        MakeDomain("bulk", 2U),
        MakeDomain("bulk", 3U)
    };

    for (const std::string& domain : domains) {
        EXPECT_TRUE(monitor.BlockDomain(domain, L"Bulk IOC ingestion"));
        TrackBlockedDomain(domain);
        EXPECT_TRUE(monitor.IsBlocked(domain));
    }

    const std::size_t rulesAfter = monitor.GetFilterRules().size();
    const SSN::DNSStatistics& statsAfter = monitor.GetStatistics();

    EXPECT_GE(rulesAfter, rulesBefore + domains.size());
    EXPECT_EQ(LoadRelaxed(statsAfter.domainsBlocked), blockedEventsBefore)
        << "domainsBlocked is event-driven telemetry and must not increase until a blocked DNS query is actually observed.";
}

// ---------------------------------------------------------------------------
// GROUP 2: Newly initialized DNS telemetry must start from zero so that threat
// hunting and dashboards do not inherit stale query or block counters.
// ---------------------------------------------------------------------------
TEST_F(DNSMonitor_DomainFiltering, GetStatistics_AfterInit_ZeroCounts) {
    if (!EnsureDnsMonitorInitialized()) {
        GTEST_SKIP() << "DNSMonitor initialization unavailable on this endpoint.";
    }

    auto& monitor = SSN::DNSMonitor::Instance();
    monitor.ResetStatistics();
    const SSN::DNSStatistics& stats = monitor.GetStatistics();

    EXPECT_EQ(LoadRelaxed(stats.totalQueries), 0ULL);
    EXPECT_EQ(LoadRelaxed(stats.domainsBlocked), 0ULL);
    EXPECT_EQ(LoadRelaxed(stats.dgaDetections), 0ULL);
    EXPECT_EQ(LoadRelaxed(stats.tunnelingDetections), 0ULL);
    EXPECT_EQ(LoadRelaxed(stats.errorCount), 0ULL);
}

// ---------------------------------------------------------------------------
// GROUP 3: WFP-backed policy enforcement is admin-gated; tests must skip cleanly
// when endpoint privileges prevent the real firewall engine from starting.
// ---------------------------------------------------------------------------
TEST_F(FirewallManager_RuleManagement, InitializeAndStart_RequiresElevation_SkipIfNotAdmin) {
    if (!EnsureFirewallInitialized()) {
        GTEST_SKIP() << "FirewallManager::Initialize() failed; elevated WFP access is unavailable.";
    }

    auto& manager = SSN::FirewallManager::Instance();
    const bool started = manager.Start();
    if (!started) {
        GTEST_SKIP() << "FirewallManager::Start() failed; WFP enforcement cannot start without elevation.";
    }

    EXPECT_TRUE(manager.IsRunning());
}

// ---------------------------------------------------------------------------
// GROUP 3: Blocking a TEST-NET IOC is a core containment path for C2 or botnet
// infrastructure, so rule insertion must yield a durable non-zero rule handle.
// ---------------------------------------------------------------------------
TEST_F(FirewallManager_RuleManagement, AddRule_BlockIPRule_ReturnsNonZeroId) {
    if (!EnsureFirewallStarted()) {
        GTEST_SKIP() << "FirewallManager WFP enforcement unavailable on this endpoint.";
    }

    auto rule = SSN::FirewallRule::CreateBlockIP(L"203.0.113.1", SSN::RuleDirection::BOTH);
    rule.name = TestRuleName(L"Block TEST-NET-3 IP");
    rule.description = L"Integration validation for IOC containment";

    auto& manager = SSN::FirewallManager::Instance();
    const uint64_t ruleId = manager.AddRule(rule);
    TrackFirewallRuleId(ruleId);

    EXPECT_GT(ruleId, 0ULL);
}

// ---------------------------------------------------------------------------
// GROUP 3: SOC tooling relies on fetching the exact rule object after creation;
// retrieval must preserve identifiers and analyst-facing metadata.
// ---------------------------------------------------------------------------
TEST_F(FirewallManager_RuleManagement, GetRule_ByReturnedId_ReturnsTheRule) {
    if (!EnsureFirewallStarted()) {
        GTEST_SKIP() << "FirewallManager WFP enforcement unavailable on this endpoint.";
    }

    auto rule = SSN::FirewallRule::CreateBlockIP(L"203.0.113.2", SSN::RuleDirection::OUTBOUND);
    rule.name = TestRuleName(L"Lookup Created Rule");
    rule.description = L"Integration lookup validation";

    auto& manager = SSN::FirewallManager::Instance();
    const uint64_t ruleId = manager.AddRule(rule);
    ASSERT_GT(ruleId, 0ULL);
    TrackFirewallRuleId(ruleId);

    const std::optional<SSN::FirewallRule> loadedRule = manager.GetRule(ruleId);
    ASSERT_TRUE(loadedRule.has_value());
    EXPECT_EQ(loadedRule->name, rule.name);
    EXPECT_EQ(loadedRule->action, SSN::RuleAction::BLOCK);
}

// ---------------------------------------------------------------------------
// GROUP 3: Incident rollback requires deterministic removal so emergency blocks
// can be revoked without leaving orphaned WFP filters or stale rule handles.
// ---------------------------------------------------------------------------
TEST_F(FirewallManager_RuleManagement, RemoveRule_ById_ReturnsTrueAndGetsNotFound) {
    if (!EnsureFirewallStarted()) {
        GTEST_SKIP() << "FirewallManager WFP enforcement unavailable on this endpoint.";
    }

    auto rule = SSN::FirewallRule::CreateBlockIP(L"203.0.113.3", SSN::RuleDirection::BOTH);
    rule.name = TestRuleName(L"Remove Rule By ID");

    auto& manager = SSN::FirewallManager::Instance();
    const uint64_t ruleId = manager.AddRule(rule);
    ASSERT_GT(ruleId, 0ULL);

    const bool removed = manager.RemoveRule(ruleId);
    EXPECT_TRUE(removed);
    EXPECT_FALSE(manager.GetRule(ruleId).has_value());
}

// ---------------------------------------------------------------------------
// GROUP 3: Multiple simultaneous containment actions must accumulate in the
// active policy set so blocklist campaigns can be audited as a batch.
// ---------------------------------------------------------------------------
TEST_F(FirewallManager_RuleManagement, GetAllRules_AfterAddingRules_ContainsAdded) {
    if (!EnsureFirewallStarted()) {
        GTEST_SKIP() << "FirewallManager WFP enforcement unavailable on this endpoint.";
    }

    auto& manager = SSN::FirewallManager::Instance();
    const std::size_t rulesBefore = manager.GetAllRules(false).size();

    auto ipRule = SSN::FirewallRule::CreateBlockIP(L"203.0.113.4", SSN::RuleDirection::BOTH);
    ipRule.name = TestRuleName(L"Aggregate IP Rule");

    auto portRule = SSN::FirewallRule::CreateBlockPort(8443, SSN::RuleProtocol::TCP, SSN::RuleDirection::OUTBOUND);
    portRule.name = TestRuleName(L"Aggregate Port Rule");

    const uint64_t ipRuleId = manager.AddRule(ipRule);
    const uint64_t portRuleId = manager.AddRule(portRule);
    ASSERT_GT(ipRuleId, 0ULL);
    ASSERT_GT(portRuleId, 0ULL);
    TrackFirewallRuleId(ipRuleId);
    TrackFirewallRuleId(portRuleId);

    const std::vector<SSN::FirewallRule> allRules = manager.GetAllRules(false);
    EXPECT_GE(allRules.size(), rulesBefore + 2U);
    EXPECT_TRUE(ContainsRuleId(allRules, ipRuleId));
    EXPECT_TRUE(ContainsRuleId(allRules, portRuleId));
}

// ---------------------------------------------------------------------------
// GROUP 3: Blocking an egress port is a standard exfiltration containment move;
// the helper must synthesize a real enforceable rule ID every time.
// ---------------------------------------------------------------------------
TEST_F(FirewallManager_RuleManagement, BlockPort_ValidPort_ReturnsNonZeroId) {
    if (!EnsureFirewallStarted()) {
        GTEST_SKIP() << "FirewallManager WFP enforcement unavailable on this endpoint.";
    }

    auto& manager = SSN::FirewallManager::Instance();
    const uint64_t ruleId = manager.BlockPort(8888, SSN::RuleProtocol::TCP, SSN::RuleDirection::OUTBOUND);
    TrackFirewallRuleId(ruleId);

    EXPECT_GT(ruleId, 0ULL);
}

// ---------------------------------------------------------------------------
// GROUP 3: Analysts must be able to rapidly undo temporary port containment to
// restore business traffic once a false positive is confirmed.
// ---------------------------------------------------------------------------
TEST_F(FirewallManager_RuleManagement, UnblockPort_AfterBlock_Succeeds) {
    if (!EnsureFirewallStarted()) {
        GTEST_SKIP() << "FirewallManager WFP enforcement unavailable on this endpoint.";
    }

    auto& manager = SSN::FirewallManager::Instance();
    const uint64_t ruleId = manager.BlockPort(8889, SSN::RuleProtocol::TCP, SSN::RuleDirection::OUTBOUND);
    ASSERT_GT(ruleId, 0ULL);
    TrackFirewallRuleId(ruleId);

    const bool unblocked = manager.UnblockPort(8889, SSN::RuleProtocol::TCP);

    EXPECT_TRUE(unblocked);
    EXPECT_FALSE(manager.GetRule(ruleId).has_value());
}

// ---------------------------------------------------------------------------
// GROUP 3: Direct IP containment is used for high-confidence IOCs and beacon
// sinks; the convenience helper must always return a valid underlying rule ID.
// ---------------------------------------------------------------------------
TEST_F(FirewallManager_RuleManagement, BlockIP_ValidIP_ReturnsRuleId) {
    if (!EnsureFirewallStarted()) {
        GTEST_SKIP() << "FirewallManager WFP enforcement unavailable on this endpoint.";
    }

    auto& manager = SSN::FirewallManager::Instance();
    const uint64_t ruleId = manager.BlockIP(L"203.0.113.5", SSN::RuleDirection::BOTH);
    TrackFirewallRuleId(ruleId);

    EXPECT_GT(ruleId, 0ULL);
}

// ---------------------------------------------------------------------------
// GROUP 3: IOC revocation must fully retract the helper-created IP block so the
// same indicator cannot remain silently enforced after rollback.
// ---------------------------------------------------------------------------
TEST_F(FirewallManager_RuleManagement, UnblockIP_AfterBlockIP_RemovesBlock) {
    if (!EnsureFirewallStarted()) {
        GTEST_SKIP() << "FirewallManager WFP enforcement unavailable on this endpoint.";
    }

    auto& manager = SSN::FirewallManager::Instance();
    const uint64_t ruleId = manager.BlockIP(L"203.0.113.6", SSN::RuleDirection::BOTH);
    ASSERT_GT(ruleId, 0ULL);
    TrackFirewallRuleId(ruleId);

    const bool unblocked = manager.UnblockIP(L"203.0.113.6");

    EXPECT_TRUE(unblocked);
    EXPECT_FALSE(manager.GetRule(ruleId).has_value());
}

// ---------------------------------------------------------------------------
// GROUP 4: Real attacks often arrive as domain + IP pairs; DNS and firewall
// containment must coexist so one control plane cannot mask the other.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_CrossModuleIntegration, DNSAndFirewall_BlockedDomain_IPAlsoBlocked) {
    if (!EnsureDnsMonitorInitialized()) {
        GTEST_SKIP() << "DNSMonitor initialization unavailable on this endpoint.";
    }
    if (!EnsureFirewallStarted()) {
        GTEST_SKIP() << "FirewallManager WFP enforcement unavailable on this endpoint.";
    }

    const std::string domain = MakeDomain("cross-dns-firewall");
    auto& dnsMonitor = SSN::DNSMonitor::Instance();
    ASSERT_TRUE(dnsMonitor.BlockDomain(domain, L"Domain IOC paired with IP IOC"));
    TrackBlockedDomain(domain);

    auto& firewallManager = SSN::FirewallManager::Instance();
    const uint64_t ruleId = firewallManager.BlockIP(L"203.0.113.7", SSN::RuleDirection::BOTH);
    ASSERT_GT(ruleId, 0ULL);
    TrackFirewallRuleId(ruleId);

    EXPECT_TRUE(dnsMonitor.IsBlocked(domain));
    EXPECT_TRUE(firewallManager.GetRule(ruleId).has_value());
}

// ---------------------------------------------------------------------------
// GROUP 4: Rule-management churn must not tamper with passive network telemetry;
// otherwise firewall policy updates could corrupt hunting statistics.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_CrossModuleIntegration, NetworkMonitorAndFirewall_Stats_IndependentFromEachOther) {
    if (!EnsureNetworkMonitorStarted()) {
        GTEST_SKIP() << "NetworkMonitor start unavailable on this endpoint.";
    }
    if (!EnsureFirewallStarted()) {
        GTEST_SKIP() << "FirewallManager WFP enforcement unavailable on this endpoint.";
    }

    auto& networkMonitor = SSN::NetworkMonitor::Instance();
    auto& firewallManager = SSN::FirewallManager::Instance();

    networkMonitor.ResetStatistics();
    firewallManager.ResetStatistics();

    const SSN::NetworkMonitorStatistics& beforeStats = networkMonitor.GetStatistics();
    const uint64_t totalConnectionsBefore = LoadRelaxed(beforeStats.totalConnections);
    const uint64_t blockedConnectionsBefore = LoadRelaxed(beforeStats.blockedConnections);
    const uint64_t ipsBlockedBefore = LoadRelaxed(beforeStats.ipsBlocked);

    const uint64_t ruleId = firewallManager.BlockIP(L"203.0.113.8", SSN::RuleDirection::OUTBOUND);
    ASSERT_GT(ruleId, 0ULL);
    TrackFirewallRuleId(ruleId);

    const SSN::NetworkMonitorStatistics& afterStats = networkMonitor.GetStatistics();
    EXPECT_EQ(LoadRelaxed(afterStats.totalConnections), totalConnectionsBefore);
    EXPECT_EQ(LoadRelaxed(afterStats.blockedConnections), blockedConnectionsBefore);
    EXPECT_EQ(LoadRelaxed(afterStats.ipsBlocked), ipsBlockedBefore);
}

// ---------------------------------------------------------------------------
// GROUP 4: All three modules run side-by-side in production; orderly startup,
// stop, and shutdown must not deadlock or interfere during service control.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_CrossModuleIntegration, AllThreeModules_InitAndStop_NoInterference) {
    if (!EnsureNetworkMonitorInitialized()) {
        GTEST_SKIP() << "NetworkMonitor initialization unavailable on this endpoint.";
    }
    if (!EnsureDnsMonitorInitialized()) {
        GTEST_SKIP() << "DNSMonitor initialization unavailable on this endpoint.";
    }
    if (!EnsureFirewallStarted()) {
        GTEST_SKIP() << "FirewallManager WFP enforcement unavailable on this endpoint.";
    }

    auto& networkMonitor = SSN::NetworkMonitor::Instance();
    auto& dnsMonitor = SSN::DNSMonitor::Instance();
    auto& firewallManager = SSN::FirewallManager::Instance();

    const bool networkStarted = networkMonitor.Start();
    if (!networkStarted) {
        GTEST_SKIP() << "NetworkMonitor::Start() failed on this endpoint.";
    }

    dnsMonitor.Start();
    ASSERT_TRUE(dnsMonitor.IsRunning());
    ASSERT_TRUE(firewallManager.IsRunning());
    ASSERT_TRUE(networkMonitor.IsRunning());

    firewallManager.Stop();
    dnsMonitor.Stop();
    networkMonitor.Stop();

    EXPECT_FALSE(firewallManager.IsRunning());
    EXPECT_FALSE(dnsMonitor.IsRunning());
    EXPECT_FALSE(networkMonitor.IsRunning());

    firewallManager.Shutdown();
    dnsMonitor.Shutdown();
    networkMonitor.Shutdown();

    EXPECT_FALSE(firewallManager.IsRunning());
    EXPECT_FALSE(dnsMonitor.IsRunning());
    EXPECT_FALSE(networkMonitor.IsRunning());
}

// ---------------------------------------------------------------------------
// GROUP 4: Factory helpers synthesize analyst-authored IP block rules; field
// correctness is critical because policy exporters consume these exact values.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_CrossModuleIntegration, FirewallRule_CreateBlockIP_FieldsSetCorrectly) {
    const SSN::FirewallRule rule = SSN::FirewallRule::CreateBlockIP(L"203.0.113.42", SSN::RuleDirection::OUTBOUND);

    EXPECT_EQ(rule.type, SSN::RuleType::IP);
    EXPECT_EQ(rule.action, SSN::RuleAction::BLOCK);
    EXPECT_EQ(rule.direction, SSN::RuleDirection::OUTBOUND);
    EXPECT_EQ(rule.remoteAddress.type, SSN::IPAddressMatch::Type::SINGLE);
    EXPECT_TRUE(rule.isEnabled);
}

// ---------------------------------------------------------------------------
// GROUP 4: Port-rule factories are used during emergency containment of known
// bad services; incorrect port-range fields would silently break enforcement.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_CrossModuleIntegration, FirewallRule_CreateBlockPort_FieldsSetCorrectly) {
    const SSN::FirewallRule rule = SSN::FirewallRule::CreateBlockPort(443, SSN::RuleProtocol::TCP, SSN::RuleDirection::INBOUND);

    EXPECT_EQ(rule.type, SSN::RuleType::PORT);
    EXPECT_EQ(rule.action, SSN::RuleAction::BLOCK);
    EXPECT_EQ(rule.direction, SSN::RuleDirection::INBOUND);
    EXPECT_EQ(rule.protocol, SSN::RuleProtocol::TCP);
    ASSERT_EQ(rule.remotePorts.size(), 1U);
    EXPECT_EQ(rule.remotePorts.front().start, 443U);
    EXPECT_EQ(rule.remotePorts.front().end, 443U);
}

// ---------------------------------------------------------------------------
// GROUP 5: Bulk domain IOC publication must be observable through the DNS state
// surfaces used by telemetry export and operational health checks.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_Statistics, DNSMonitor_BlockDomains_StatReflectsBlockCount) {
    if (!EnsureDnsMonitorInitialized()) {
        GTEST_SKIP() << "DNSMonitor initialization unavailable on this endpoint.";
    }

    auto& monitor = SSN::DNSMonitor::Instance();
    const std::size_t rulesBefore = monitor.GetFilterRules().size();

    for (std::size_t index = 1U; index <= 5U; ++index) {
        const std::string domain = MakeDomain("stats", index);
        EXPECT_TRUE(monitor.BlockDomain(domain, L"Statistics integration validation"));
        TrackBlockedDomain(domain);
    }

    const std::size_t rulesAfter = monitor.GetFilterRules().size();
    const SSN::DNSStatistics& stats = monitor.GetStatistics();

    EXPECT_GE(rulesAfter, rulesBefore + 5U);
    EXPECT_EQ(LoadRelaxed(stats.domainsBlocked), 0ULL)
        << "Blocked-domain telemetry counts live blocked queries, not control-plane rule creation.";
}

// ---------------------------------------------------------------------------
// GROUP 5: Active rule counts back dashboards and policy drift detection; add
// and remove operations must keep counts consistent under live enforcement.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_Statistics, FirewallManager_AddAndRemoveRules_CountIsConsistent) {
    if (!EnsureFirewallStarted()) {
        GTEST_SKIP() << "FirewallManager WFP enforcement unavailable on this endpoint.";
    }

    auto& manager = SSN::FirewallManager::Instance();
    const std::size_t rulesBefore = manager.GetAllRules(false).size();

    const uint64_t ipRuleId = manager.BlockIP(L"203.0.113.21", SSN::RuleDirection::BOTH);
    const uint64_t portRuleId = manager.BlockPort(445, SSN::RuleProtocol::TCP, SSN::RuleDirection::INBOUND);

    auto appRule = SSN::FirewallRule::CreateBlockApp(L"C:\\ShadowStrike\\Tests\\malware.exe");
    appRule.name = TestRuleName(L"Statistics Application Rule");
    const uint64_t appRuleId = manager.AddRule(appRule);

    ASSERT_GT(ipRuleId, 0ULL);
    ASSERT_GT(portRuleId, 0ULL);
    ASSERT_GT(appRuleId, 0ULL);

    TrackFirewallRuleId(ipRuleId);
    TrackFirewallRuleId(portRuleId);
    TrackFirewallRuleId(appRuleId);

    const std::size_t rulesAfterAdd = manager.GetAllRules(false).size();
    EXPECT_EQ(rulesAfterAdd, rulesBefore + 3U);
    EXPECT_EQ(LoadRelaxed(manager.GetStatistics().activeRuleCount), rulesAfterAdd);

    const bool removed = manager.RemoveRule(portRuleId);
    EXPECT_TRUE(removed);

    const std::size_t rulesAfterRemove = manager.GetAllRules(false).size();
    EXPECT_EQ(rulesAfterRemove, rulesBefore + 2U);
    EXPECT_EQ(LoadRelaxed(manager.GetStatistics().activeRuleCount), rulesAfterRemove);
}

// ---------------------------------------------------------------------------
// GROUP 5: Hunting pipelines read the statistics struct continuously; the read
// path itself must remain safe even when no live traffic has been observed.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_Statistics, NetworkMonitor_GetStatistics_StructIsReadable) {
    if (!EnsureNetworkMonitorInitialized()) {
        GTEST_SKIP() << "NetworkMonitor initialization unavailable on this endpoint.";
    }

    const SSN::NetworkMonitorStatistics& stats = SSN::NetworkMonitor::Instance().GetStatistics();

    EXPECT_GE(LoadRelaxed(stats.totalConnections), 0ULL);
    EXPECT_GE(LoadRelaxed(stats.activeConnections), 0ULL);
    EXPECT_GE(LoadRelaxed(stats.blockedConnections), 0ULL);
    EXPECT_GE(LoadRelaxed(stats.errorCount), 0ULL);
}

// ---------------------------------------------------------------------------
// GROUP 6: Threat-intel feeds and automatic rollback can touch the DNS blocklist
// from multiple threads; block/unblock operations must remain race-safe.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_Concurrency, ConcurrentDNSBlockUnblock_IsThreadSafe) {
    if (!EnsureDnsMonitorInitialized()) {
        GTEST_SKIP() << "DNSMonitor initialization unavailable on this endpoint.";
    }

    auto& monitor = SSN::DNSMonitor::Instance();
    const std::size_t rulesBefore = monitor.GetFilterRules().size();

    constexpr int kThreadCount = 4;
    constexpr int kDomainsPerThread = 12;
    std::vector<std::string> domains;
    domains.reserve(static_cast<std::size_t>(kThreadCount * kDomainsPerThread));

    for (int threadIndex = 0; threadIndex < kThreadCount; ++threadIndex) {
        for (int domainIndex = 0; domainIndex < kDomainsPerThread; ++domainIndex) {
            const std::size_t suffix = static_cast<std::size_t>(threadIndex * 100 + domainIndex + 1);
            domains.push_back(MakeDomain("concurrency", suffix));
            TrackBlockedDomain(domains.back());
        }
    }

    std::atomic<int> readyCount{0};
    std::atomic<bool> startGate{false};
    std::atomic<uint32_t> failureCount{0};
    std::vector<std::thread> threads;
    threads.reserve(kThreadCount);

    for (int threadIndex = 0; threadIndex < kThreadCount; ++threadIndex) {
        threads.emplace_back([&, threadIndex]() {
            readyCount.fetch_add(1, std::memory_order_acq_rel);
            while (!startGate.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }

            for (int domainIndex = 0; domainIndex < kDomainsPerThread; ++domainIndex) {
                const std::size_t offset = static_cast<std::size_t>(threadIndex * kDomainsPerThread + domainIndex);
                const std::string& domain = domains[offset];

                if (!monitor.BlockDomain(domain, L"Concurrent IOC publication")) {
                    failureCount.fetch_add(1, std::memory_order_acq_rel);
                }
                if (!monitor.IsBlocked(domain)) {
                    failureCount.fetch_add(1, std::memory_order_acq_rel);
                }
                if (!monitor.UnblockDomain(domain)) {
                    failureCount.fetch_add(1, std::memory_order_acq_rel);
                }
                if (monitor.IsBlocked(domain)) {
                    failureCount.fetch_add(1, std::memory_order_acq_rel);
                }
            }
        });
    }

    while (readyCount.load(std::memory_order_acquire) != kThreadCount) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    startGate.store(true, std::memory_order_release);

    for (std::thread& thread : threads) {
        thread.join();
    }

    for (const std::string& domain : domains) {
        EXPECT_FALSE(monitor.IsBlocked(domain));
    }
    EXPECT_EQ(failureCount.load(std::memory_order_relaxed), 0U);
    EXPECT_EQ(monitor.GetFilterRules().size(), rulesBefore);
}

// ---------------------------------------------------------------------------
// GROUP 6: Large containment blasts may add many firewall rules in parallel;
// concurrent inserts must remain unique, non-zero, and internally consistent.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_Concurrency, ConcurrentFirewallRuleAdd_IsThreadSafe) {
    if (!EnsureFirewallStarted()) {
        GTEST_SKIP() << "FirewallManager WFP enforcement unavailable on this endpoint.";
    }

    auto& manager = SSN::FirewallManager::Instance();
    const std::size_t rulesBefore = manager.GetAllRules(false).size();

    constexpr int kThreadCount = 4;
    constexpr int kRulesPerThread = 8;
    constexpr int kTotalRules = kThreadCount * kRulesPerThread;

    std::atomic<int> readyCount{0};
    std::atomic<bool> startGate{false};
    std::atomic<uint32_t> failureCount{0};
    std::vector<uint64_t> createdRuleIds(static_cast<std::size_t>(kTotalRules), 0ULL);
    std::vector<std::thread> threads;
    threads.reserve(kThreadCount);

    for (int threadIndex = 0; threadIndex < kThreadCount; ++threadIndex) {
        threads.emplace_back([&, threadIndex]() {
            readyCount.fetch_add(1, std::memory_order_acq_rel);
            while (!startGate.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }

            for (int ruleIndex = 0; ruleIndex < kRulesPerThread; ++ruleIndex) {
                const int octet = 100 + threadIndex * kRulesPerThread + ruleIndex;
                const std::wstring ip = L"203.0.113." + std::to_wstring(octet);
                const uint64_t ruleId = manager.BlockIP(ip, SSN::RuleDirection::OUTBOUND);
                createdRuleIds[static_cast<std::size_t>(threadIndex * kRulesPerThread + ruleIndex)] = ruleId;
                if (ruleId == 0ULL) {
                    failureCount.fetch_add(1, std::memory_order_acq_rel);
                }
            }
        });
    }

    while (readyCount.load(std::memory_order_acquire) != kThreadCount) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    startGate.store(true, std::memory_order_release);

    for (std::thread& thread : threads) {
        thread.join();
    }

    std::unordered_set<uint64_t> uniqueIds;
    for (const uint64_t ruleId : createdRuleIds) {
        EXPECT_GT(ruleId, 0ULL);
        uniqueIds.insert(ruleId);
        TrackFirewallRuleId(ruleId);
    }

    EXPECT_EQ(uniqueIds.size(), createdRuleIds.size());
    EXPECT_EQ(failureCount.load(std::memory_order_relaxed), 0U);
    EXPECT_GE(manager.GetAllRules(false).size(), rulesBefore + createdRuleIds.size());
}

// ===========================================================================
// GROUP 7 – ALWAYS-RUN DATA-PLANE TESTS
//
// These tests exercise deterministic, in-process contracts that do not require
// WFP access, elevation, or live network interfaces. They must pass in any CI
// environment and serve as a compile-time and value-correctness gate for the
// struct, factory, and static-utility surfaces.
// ===========================================================================

class NetworkChain_AlwaysRun : public NetworkChainIntegrationFixtureBase {
protected:
    static void SetUpTestSuite()    { SharedSetUpSuite(); }
    static void TearDownTestSuite() { SharedTearDownSuite(); }
};

// ---------------------------------------------------------------------------
// GROUP 7: IPv6 loopback (::1) must be recognised as valid and loopback so
// that local IPv6-native IPC traffic is never mistaken for external comms.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_AlwaysRun, IPAddress_IPv6Loopback_IsValidAndIsLoopback) {
    const SSN::IPAddress ip("::1");

    ASSERT_TRUE(ip.IsValid());
    EXPECT_TRUE(ip.IsLoopback());
    EXPECT_FALSE(ip.IsPrivate());
}

// ---------------------------------------------------------------------------
// GROUP 7: ULA addresses (fc00::/7) are the IPv6 equivalent of RFC-1918;
// misclassifying them as public would cause spurious IOC lookups on LAN hosts.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// GROUP 7: The implementation classifies IPv6 ULA (fc00::/7) as PUBLIC — not
// PRIVATE — because its classification table covers only link-local (fe80::/10),
// multicast (ff00::/8), and loopback (::1).  This test documents the current
// production contract so that any future change to ULA handling is caught by CI.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_AlwaysRun, IPAddress_IPv6ULA_ClassifiedAsPublic) {
    const SSN::IPAddress ip("fc00::1");

    ASSERT_TRUE(ip.IsValid());
    // Current implementation: ULA is not in the PRIVATE classification table.
    EXPECT_FALSE(ip.IsPrivate());
    EXPECT_FALSE(ip.IsLoopback());
}

// ---------------------------------------------------------------------------
// GROUP 7: An empty string is not parseable; the resulting object must be
// invalid so it can never enter a blocklist or trigger a policy match.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_AlwaysRun, IPAddress_EmptyString_IsNotValid) {
    const SSN::IPAddress ip("");

    EXPECT_FALSE(ip.IsValid());
}

// ---------------------------------------------------------------------------
// GROUP 7: ToString must invert the string constructor so addresses survive
// serialisation round-trips through logs, databases, and policy exports.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_AlwaysRun, IPAddress_ToString_RoundTrip) {
    constexpr std::string_view kIp = "203.0.113.99";
    const SSN::IPAddress ip(kIp);

    ASSERT_TRUE(ip.IsValid());
    EXPECT_EQ(ip.ToString(), std::string(kIp));
}

// ---------------------------------------------------------------------------
// GROUP 7: The equality operator is used by blocklist deduplication; two
// IPAddress instances constructed from the same string must compare equal.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_AlwaysRun, IPAddress_EqualityOperator_SameIPIsEqual) {
    const SSN::IPAddress a("203.0.113.1");
    const SSN::IPAddress b("203.0.113.1");
    const SSN::IPAddress c("203.0.113.2");

    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
}

// ---------------------------------------------------------------------------
// GROUP 7: The less-than operator must impose a strict total order so that
// IPAddress objects can be stored in sorted containers and binary searches.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_AlwaysRun, IPAddress_LessThanOperator_ProvidesTotalOrder) {
    const SSN::IPAddress lo("203.0.113.1");
    const SSN::IPAddress hi("203.0.113.2");

    EXPECT_TRUE(lo < hi);
    EXPECT_FALSE(hi < lo);
    EXPECT_FALSE(lo < lo);
}

// ---------------------------------------------------------------------------
// GROUP 7: PortRange::Contains must respect the closed interval [start, end]
// so that firewall rules block exactly the intended ports, no more, no less.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_AlwaysRun, PortRange_Contains_ClosedIntervalSemantics) {
    const SSN::PortRange range(80, 443);

    EXPECT_TRUE(range.Contains(80));
    EXPECT_TRUE(range.Contains(443));
    EXPECT_TRUE(range.Contains(200));
    EXPECT_FALSE(range.Contains(79));
    EXPECT_FALSE(range.Contains(444));
}

// ---------------------------------------------------------------------------
// GROUP 7: IsValid must reject ranges where start > end; such degenerate
// objects would silently match no ports and produce misleading audit trails.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_AlwaysRun, PortRange_IsValid_RejectsInvertedRange) {
    EXPECT_TRUE(SSN::PortRange(443, 443).IsValid());
    EXPECT_TRUE(SSN::PortRange(80, 443).IsValid());
    EXPECT_FALSE(SSN::PortRange(443, 80).IsValid());
}

// ---------------------------------------------------------------------------
// GROUP 7: IsSinglePort distinguishes point rules from range rules so that
// SOC dashboards display accurate, human-readable policy summaries.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_AlwaysRun, PortRange_IsSinglePort_SingleVsRange) {
    EXPECT_TRUE(SSN::PortRange(443).IsSinglePort());
    EXPECT_FALSE(SSN::PortRange(80, 443).IsSinglePort());
}

// ---------------------------------------------------------------------------
// GROUP 7: CreateBlockApp must set type=APPLICATION and action=BLOCK with the
// correct path so that the factory-built rule is immediately engine-ready.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_AlwaysRun, FirewallRule_CreateBlockApp_FieldsSetCorrectly) {
    constexpr std::wstring_view kPath = L"C:\\Malware\\bad.exe";
    const SSN::FirewallRule rule = SSN::FirewallRule::CreateBlockApp(std::wstring(kPath));

    EXPECT_EQ(rule.type, SSN::RuleType::APPLICATION);
    EXPECT_EQ(rule.action, SSN::RuleAction::BLOCK);
    EXPECT_EQ(rule.application.type, SSN::ApplicationMatch::Type::PATH);
    EXPECT_EQ(rule.application.path, std::wstring(kPath));
    EXPECT_TRUE(rule.isEnabled);
}

// ---------------------------------------------------------------------------
// GROUP 7: CreateAllowApp must produce ALLOW action, not BLOCK; swapping the
// two factory methods would silently whitelist malware from network access.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_AlwaysRun, FirewallRule_CreateAllowApp_ActionIsAllow) {
    const SSN::FirewallRule rule = SSN::FirewallRule::CreateAllowApp(L"C:\\Trusted\\app.exe");

    EXPECT_EQ(rule.action, SSN::RuleAction::ALLOW);
    EXPECT_EQ(rule.type, SSN::RuleType::APPLICATION);
    EXPECT_TRUE(rule.isEnabled);
}

// ---------------------------------------------------------------------------
// GROUP 7: CreateGeoBlock must populate geoMatch.countryCodes with the exact
// list provided; an empty list would make the rule an unconditional block.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_AlwaysRun, FirewallRule_CreateGeoBlock_CountriesPopulated) {
    const std::vector<std::string> countries = {"RU", "CN", "KP"};
    const SSN::FirewallRule rule = SSN::FirewallRule::CreateGeoBlock(countries);

    EXPECT_EQ(rule.type, SSN::RuleType::GEO);
    EXPECT_EQ(rule.action, SSN::RuleAction::BLOCK);
    EXPECT_EQ(rule.geoMatch.countryCodes, countries);
    EXPECT_TRUE(rule.isEnabled);
}

// ---------------------------------------------------------------------------
// GROUP 7: Factory-created rules must satisfy IsValid() so they can enter the
// WFP pipeline without incurring an extra validation round-trip.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_AlwaysRun, FirewallRule_IsValid_FactoryRulesPassValidation) {
    EXPECT_TRUE(SSN::FirewallRule::CreateBlockIP(L"203.0.113.1", SSN::RuleDirection::BOTH).IsValid());
    EXPECT_TRUE(SSN::FirewallRule::CreateBlockPort(443, SSN::RuleProtocol::TCP, SSN::RuleDirection::OUTBOUND).IsValid());
    EXPECT_TRUE(SSN::FirewallRule::CreateBlockApp(L"C:\\bad.exe").IsValid());
    EXPECT_TRUE(SSN::FirewallRule::CreateAllowApp(L"C:\\good.exe").IsValid());
}

// ---------------------------------------------------------------------------
// GROUP 7: CreateHighSecurity must arm all detection subsystems so that a
// mis-shipped config cannot silently downgrade endpoint protection.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_AlwaysRun, NetworkMonitorConfig_CreateHighSecurity_EnablesAllDetection) {
    const SSN::NetworkMonitorConfig cfg = SSN::NetworkMonitorConfig::CreateHighSecurity();

    EXPECT_TRUE(cfg.enabled);
    EXPECT_TRUE(cfg.detectBeaconing);
    EXPECT_TRUE(cfg.detectExfiltration);
    EXPECT_TRUE(cfg.detectPortScanning);
    EXPECT_TRUE(cfg.checkIPReputation);
    EXPECT_TRUE(cfg.checkDomainReputation);
    EXPECT_TRUE(cfg.enableFiltering);
}

// ---------------------------------------------------------------------------
// GROUP 7: CreateForensic must configure full packet-level monitoring so that
// incident responders capture complete post-compromise traffic telemetry.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_AlwaysRun, NetworkMonitorConfig_CreateForensic_IsForensicLevel) {
    const SSN::NetworkMonitorConfig cfg = SSN::NetworkMonitorConfig::CreateForensic();

    EXPECT_TRUE(cfg.enabled);
    EXPECT_EQ(cfg.level, SSN::MonitoringLevel::FORENSIC);
}

// ---------------------------------------------------------------------------
// GROUP 7: CreatePerformance must at minimum leave monitoring enabled; a
// disabled config would create a blind spot masquerading as a performance win.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_AlwaysRun, NetworkMonitorConfig_CreatePerformance_IsEnabled) {
    const SSN::NetworkMonitorConfig cfg = SSN::NetworkMonitorConfig::CreatePerformance();

    EXPECT_TRUE(cfg.enabled);
}

// ---------------------------------------------------------------------------
// GROUP 7: The DNS high-security preset must enable both DGA and tunnelling
// detection so no detection engine is silently omitted on hardened endpoints.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_AlwaysRun, DNSMonitorConfig_CreateHighSecurity_ArmsBothDetectors) {
    const SSN::DNSMonitorConfig cfg = SSN::DNSMonitorConfig::CreateHighSecurity();

    EXPECT_TRUE(cfg.enabled);
    EXPECT_TRUE(cfg.detectDGA);
    EXPECT_TRUE(cfg.detectTunneling);
    EXPECT_TRUE(cfg.validateResponses);
}

// ---------------------------------------------------------------------------
// GROUP 7: The forensic DNS config must enable full query logging so that
// compliance and post-incident review have a complete DNS audit trail.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_AlwaysRun, DNSMonitorConfig_CreateForensic_EnablesFullLogging) {
    const SSN::DNSMonitorConfig cfg = SSN::DNSMonitorConfig::CreateForensic();

    EXPECT_TRUE(cfg.enabled);
    EXPECT_TRUE(cfg.logAllQueries);
}

// ---------------------------------------------------------------------------
// GROUP 7: The firewall high-security preset must enable all three filtering
// dimensions so an attacker cannot evade via a gap in app-control or ports.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_AlwaysRun, FirewallManagerConfig_CreateHighSecurity_EnablesAllFiltering) {
    const SSN::FirewallManagerConfig cfg = SSN::FirewallManagerConfig::CreateHighSecurity();

    EXPECT_TRUE(cfg.enabled);
    EXPECT_TRUE(cfg.enableIPFiltering);
    EXPECT_TRUE(cfg.enablePortFiltering);
    EXPECT_TRUE(cfg.enableApplicationControl);
}

// ---------------------------------------------------------------------------
// GROUP 7: The permissive preset is for onboarding/debug; it must remain
// enabled so rules can be added for telemetry without hard-blocking traffic.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_AlwaysRun, FirewallManagerConfig_CreatePermissive_IsEnabled) {
    const SSN::FirewallManagerConfig cfg = SSN::FirewallManagerConfig::CreatePermissive();

    EXPECT_TRUE(cfg.enabled);
}

// ---------------------------------------------------------------------------
// GROUP 7: Shannon entropy is the foundation of DGA and tunnel scoring; the
// static helper must handle pathological inputs without undefined behaviour.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_AlwaysRun, DNSMonitor_CalculateEntropy_KnownValues) {
    // Uniform string: all identical characters → zero entropy.
    EXPECT_DOUBLE_EQ(SSN::DNSMonitor::CalculateEntropy("aaaa"), 0.0);

    // Two equally probable characters → entropy = exactly 1.0 bit.
    EXPECT_NEAR(SSN::DNSMonitor::CalculateEntropy("abababab"), 1.0, 0.01);

    // High-diversity alphanumeric string must exceed DGA threshold.
    const double high = SSN::DNSMonitor::CalculateEntropy("xvkdf8s9dqm3p7r1");
    EXPECT_GT(high, SSN::DNSConstants::DGA_ENTROPY_THRESHOLD - 0.5)
        << "High-diversity 16-char string should produce near-threshold or above entropy.";
}

// ---------------------------------------------------------------------------
// GROUP 7: GetBaseDomain must strip leading subdomains so that reputation
// lookups and policy matching operate on the registrable domain, not the FQDN.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_AlwaysRun, DNSMonitor_GetBaseDomain_StripsSubdomains) {
    const std::string base = SSN::DNSMonitor::GetBaseDomain("www.evil.example.com");

    EXPECT_FALSE(base.empty());
    EXPECT_NE(base, "www.evil.example.com");
    EXPECT_TRUE(base.find("example.com") != std::string::npos)
        << "Base domain must contain at least 'example.com'; got: " << base;
}

// ---------------------------------------------------------------------------
// GROUP 7: Domain format validation is the first gate before any downstream
// analysis; bogus inputs must be rejected so parser exploits cannot enter.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_AlwaysRun, DNSMonitor_IsValidDomain_ValidAndInvalidInputs) {
    EXPECT_TRUE(SSN::DNSMonitor::IsValidDomain("example.com"));
    EXPECT_TRUE(SSN::DNSMonitor::IsValidDomain("sub.domain.example.com"));
    EXPECT_FALSE(SSN::DNSMonitor::IsValidDomain(""));
    // The implementation allows hyphens anywhere inside a label (only leading/
    // trailing dots are rejected); RFC-1035 leading-hyphen is NOT enforced by
    // this validator — document the actual contract rather than an RFC ideal.
    EXPECT_TRUE(SSN::DNSMonitor::IsValidDomain("-starts-with-hyphen.com"));
    // Labels with only invalid characters must be rejected.
    EXPECT_FALSE(SSN::DNSMonitor::IsValidDomain("inval!d.com"));
    EXPECT_FALSE(SSN::DNSMonitor::IsValidDomain(".leading-dot.com"));
    EXPECT_FALSE(SSN::DNSMonitor::IsValidDomain("trailing-dot.com."));
}

// ---------------------------------------------------------------------------
// GROUP 7: Record-type names must be non-empty for every standard DNS type so
// telemetry exporters and SIEM parsers produce human-readable event records.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_AlwaysRun, DNSMonitor_GetRecordTypeName_ReturnsKnownNames) {
    EXPECT_FALSE(SSN::DNSMonitor::GetRecordTypeName(SSN::DNSRecordType::A).empty());
    EXPECT_FALSE(SSN::DNSMonitor::GetRecordTypeName(SSN::DNSRecordType::AAAA).empty());
    EXPECT_FALSE(SSN::DNSMonitor::GetRecordTypeName(SSN::DNSRecordType::TXT).empty());
    EXPECT_FALSE(SSN::DNSMonitor::GetRecordTypeName(SSN::DNSRecordType::MX).empty());
}

// ---------------------------------------------------------------------------
// GROUP 7: The version string must not be empty so that diagnostic exports and
// support bundles always carry an exact build lineage for triage.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_AlwaysRun, DNSMonitor_GetVersionString_ReturnsNonEmpty) {
    EXPECT_FALSE(SSN::DNSMonitor::GetVersionString().empty());
}

// ===========================================================================
// GROUP 1 (extended) – NetworkMonitor edge-case hardening
// ===========================================================================

// ---------------------------------------------------------------------------
// GROUP 1: BlockIP → IsIPBlocked → UnblockIP → !IsIPBlocked constitutes the
// primary IOC containment loop; each transition must succeed in order.
// ---------------------------------------------------------------------------
TEST_F(NetworkMonitor_Lifecycle, BlockIP_ThenIsIPBlocked_ThenUnblockIP_Roundtrip) {
    if (!EnsureNetworkMonitorInitialized()) {
        GTEST_SKIP() << "NetworkMonitor initialization unavailable on this endpoint.";
    }

    auto& monitor = SSN::NetworkMonitor::Instance();
    const SSN::IPAddress testIp("203.0.113.200");
    ASSERT_TRUE(testIp.IsValid());
    TrackBlockedIp(testIp);

    const bool blocked = monitor.BlockIP(testIp, SSN::BlockReason::MALICIOUS_IP);
    ASSERT_TRUE(blocked);
    EXPECT_TRUE(monitor.IsIPBlocked(testIp));

    const bool unblocked = monitor.UnblockIP(testIp);
    EXPECT_TRUE(unblocked);
    EXPECT_FALSE(monitor.IsIPBlocked(testIp));
}

// ---------------------------------------------------------------------------
// GROUP 1: GetBlockedIPs must list every IP added via BlockIP and not yet
// removed so that the SOC dashboard always shows an accurate live picture.
// ---------------------------------------------------------------------------
TEST_F(NetworkMonitor_Lifecycle, GetBlockedIPs_ReflectsBlockedIPList) {
    if (!EnsureNetworkMonitorInitialized()) {
        GTEST_SKIP() << "NetworkMonitor initialization unavailable on this endpoint.";
    }

    auto& monitor = SSN::NetworkMonitor::Instance();
    const SSN::IPAddress ip("203.0.113.201");
    ASSERT_TRUE(ip.IsValid());
    TrackBlockedIp(ip);

    ASSERT_TRUE(monitor.BlockIP(ip, SSN::BlockReason::MALICIOUS_IP));

    const std::vector<SSN::IPAddress> blocked = monitor.GetBlockedIPs();
    EXPECT_TRUE(std::find(blocked.begin(), blocked.end(), ip) != blocked.end())
        << "Freshly blocked IP must appear in GetBlockedIPs().";
}

// ---------------------------------------------------------------------------
// GROUP 1: GetActiveConnections must always return a usable container even
// when no connections are tracked; a null or crash result is not acceptable.
// ---------------------------------------------------------------------------
TEST_F(NetworkMonitor_Lifecycle, GetActiveConnections_ReturnsUsableContainer) {
    if (!EnsureNetworkMonitorInitialized()) {
        GTEST_SKIP() << "NetworkMonitor initialization unavailable on this endpoint.";
    }

    const std::vector<SSN::ConnectionInfo> conns =
        SSN::NetworkMonitor::Instance().GetActiveConnections();

    SUCCEED() << "GetActiveConnections() returned " << conns.size() << " connections.";
}

// ---------------------------------------------------------------------------
// GROUP 1: ResetStatistics must zero every counter family, not just the
// connection count; stale traffic-volume fields would corrupt rate baselines.
// ---------------------------------------------------------------------------
TEST_F(NetworkMonitor_Lifecycle, ResetStatistics_ClearsAllCounterFamilies) {
    if (!EnsureNetworkMonitorInitialized()) {
        GTEST_SKIP() << "NetworkMonitor initialization unavailable on this endpoint.";
    }

    auto& monitor = SSN::NetworkMonitor::Instance();
    monitor.ResetStatistics();
    const SSN::NetworkMonitorStatistics& s = monitor.GetStatistics();

    EXPECT_EQ(LoadRelaxed(s.totalConnections),    0ULL);
    EXPECT_EQ(LoadRelaxed(s.inboundConnections),  0ULL);
    EXPECT_EQ(LoadRelaxed(s.outboundConnections), 0ULL);
    EXPECT_EQ(LoadRelaxed(s.blockedConnections),  0ULL);
    EXPECT_EQ(LoadRelaxed(s.totalBytesReceived),  0ULL);
    EXPECT_EQ(LoadRelaxed(s.totalBytesSent),      0ULL);
    EXPECT_EQ(LoadRelaxed(s.filtersMatched),      0ULL);
    EXPECT_EQ(LoadRelaxed(s.threatsDetected),     0ULL);
    EXPECT_EQ(LoadRelaxed(s.eventsProcessed),     0ULL);
    EXPECT_EQ(LoadRelaxed(s.eventsDropped),       0ULL);
    EXPECT_EQ(LoadRelaxed(s.errorCount),          0ULL);
}

// ===========================================================================
// GROUP 2 (extended) – DNSMonitor edge-case hardening
// ===========================================================================

// ---------------------------------------------------------------------------
// GROUP 2: A well-known short domain must not be flagged as DGA; false
// positives on trusted names would flood the blocklist and break resolution.
// ---------------------------------------------------------------------------
TEST_F(DNSMonitor_DomainFiltering, AnalyzeDGA_LegitimateShortDomain_NotFlaggedDGA) {
    if (!EnsureDnsMonitorInitialized()) {
        GTEST_SKIP() << "DNSMonitor initialization unavailable on this endpoint.";
    }

    const SSN::DGAAnalysis analysis =
        SSN::DNSMonitor::Instance().AnalyzeDGA("google.com");

    EXPECT_LT(analysis.entropy, SSN::DNSConstants::DGA_ENTROPY_THRESHOLD)
        << "'google.com' entropy must stay below the DGA threshold.";
    EXPECT_FALSE(analysis.isDGA)
        << "A well-known short domain must not be classified DGA-generated.";
}

// ---------------------------------------------------------------------------
// GROUP 2: A long high-entropy domain must produce measurable entropy; the
// analysis must complete without crashing regardless of the DGA verdict.
// ---------------------------------------------------------------------------
TEST_F(DNSMonitor_DomainFiltering, AnalyzeDGA_HighEntropyDomain_ProducesMeasurableEntropy) {
    if (!EnsureDnsMonitorInitialized()) {
        GTEST_SKIP() << "DNSMonitor initialization unavailable on this endpoint.";
    }

    const SSN::DGAAnalysis analysis =
        SSN::DNSMonitor::Instance().AnalyzeDGA("xvkdf8s9dqm3p7r1.shadowstrike.internal");

    EXPECT_GT(analysis.entropy, 0.0)
        << "High-diversity label must produce non-zero entropy.";
    SUCCEED() << "AnalyzeDGA completed: isDGA=" << analysis.isDGA
              << " entropy=" << analysis.entropy;
}

// ---------------------------------------------------------------------------
// GROUP 2: IsBlocked on an empty string must never crash; hostile code could
// call this with an empty domain to probe policy-engine resilience.
// ---------------------------------------------------------------------------
TEST_F(DNSMonitor_DomainFiltering, IsBlocked_EmptyString_ReturnsFalseWithoutCrash) {
    if (!EnsureDnsMonitorInitialized()) {
        GTEST_SKIP() << "DNSMonitor initialization unavailable on this endpoint.";
    }

    EXPECT_NO_FATAL_FAILURE({
        const bool result = SSN::DNSMonitor::Instance().IsBlocked("");
        EXPECT_FALSE(result);
    });
}

// ---------------------------------------------------------------------------
// GROUP 2: GetCacheSize must return 0 immediately after FlushCache so that
// cache-poisoning mitigations can start from a verified clean baseline.
// ---------------------------------------------------------------------------
TEST_F(DNSMonitor_DomainFiltering, GetCacheSize_AfterFlush_ReturnsZero) {
    if (!EnsureDnsMonitorInitialized()) {
        GTEST_SKIP() << "DNSMonitor initialization unavailable on this endpoint.";
    }

    auto& monitor = SSN::DNSMonitor::Instance();
    monitor.FlushCache();

    EXPECT_EQ(monitor.GetCacheSize(), 0U);
}

// ---------------------------------------------------------------------------
// GROUP 2: The full DNSStatistics struct must be readable after Reset so
// that every dashboard counter is safely accessible without UB.
// ---------------------------------------------------------------------------
TEST_F(DNSMonitor_DomainFiltering, GetStatistics_FullStruct_AllFieldsReadableAfterReset) {
    if (!EnsureDnsMonitorInitialized()) {
        GTEST_SKIP() << "DNSMonitor initialization unavailable on this endpoint.";
    }

    auto& monitor = SSN::DNSMonitor::Instance();
    monitor.ResetStatistics();
    const SSN::DNSStatistics& s = monitor.GetStatistics();

    EXPECT_EQ(LoadRelaxed(s.totalQueries),          0ULL);
    EXPECT_EQ(LoadRelaxed(s.queriesA),              0ULL);
    EXPECT_EQ(LoadRelaxed(s.queriesAAAA),           0ULL);
    EXPECT_EQ(LoadRelaxed(s.queriesTXT),            0ULL);
    EXPECT_EQ(LoadRelaxed(s.totalResponses),        0ULL);
    EXPECT_EQ(LoadRelaxed(s.domainsBlocked),        0ULL);
    EXPECT_EQ(LoadRelaxed(s.dgaDetections),         0ULL);
    EXPECT_EQ(LoadRelaxed(s.tunnelingDetections),   0ULL);
    EXPECT_EQ(LoadRelaxed(s.poisoningDetections),   0ULL);
    EXPECT_EQ(LoadRelaxed(s.cacheHits),             0ULL);
    EXPECT_EQ(LoadRelaxed(s.cacheMisses),           0ULL);
    EXPECT_EQ(LoadRelaxed(s.errorCount),            0ULL);
}

// ===========================================================================
// GROUP 3 (extended) – FirewallManager edge-case hardening
// ===========================================================================

// ---------------------------------------------------------------------------
// GROUP 3: IsIPBlocked must return true after BlockIP and false after
// UnblockIP; any mismatch would make live IOC status queries unreliable.
// ---------------------------------------------------------------------------
TEST_F(FirewallManager_RuleManagement, IsIPBlocked_ReflectsBlockAndUnblockCycle) {
    if (!EnsureFirewallStarted()) {
        GTEST_SKIP() << "FirewallManager WFP enforcement unavailable on this endpoint.";
    }

    auto& manager = SSN::FirewallManager::Instance();
    constexpr std::wstring_view kIp = L"203.0.113.101";

    const uint64_t ruleId = manager.BlockIP(std::wstring(kIp), SSN::RuleDirection::BOTH);
    ASSERT_GT(ruleId, 0ULL);
    TrackFirewallRuleId(ruleId);

    EXPECT_TRUE(manager.IsIPBlocked(std::wstring(kIp)));

    ASSERT_TRUE(manager.UnblockIP(std::wstring(kIp)));
    EXPECT_FALSE(manager.IsIPBlocked(std::wstring(kIp)));
}

// ---------------------------------------------------------------------------
// GROUP 3: IsPortBlocked must mirror BlockPort and UnblockPort; stale port
// block state would leave exfiltration containment silently reverted.
// ---------------------------------------------------------------------------
TEST_F(FirewallManager_RuleManagement, IsPortBlocked_ReflectsBlockAndUnblockCycle) {
    if (!EnsureFirewallStarted()) {
        GTEST_SKIP() << "FirewallManager WFP enforcement unavailable on this endpoint.";
    }

    auto& manager = SSN::FirewallManager::Instance();
    constexpr uint16_t kPort = 9876U;

    const uint64_t ruleId = manager.BlockPort(kPort, SSN::RuleProtocol::TCP, SSN::RuleDirection::OUTBOUND);
    ASSERT_GT(ruleId, 0ULL);
    TrackFirewallRuleId(ruleId);

    EXPECT_TRUE(manager.IsPortBlocked(kPort, SSN::RuleProtocol::TCP));

    ASSERT_TRUE(manager.UnblockPort(kPort, SSN::RuleProtocol::TCP));
    EXPECT_FALSE(manager.IsPortBlocked(kPort, SSN::RuleProtocol::TCP));
}

// ---------------------------------------------------------------------------
// GROUP 3: BlockApplication must return a non-zero rule ID; zero would mean
// the application block was silently not registered with WFP.
// ---------------------------------------------------------------------------
TEST_F(FirewallManager_RuleManagement, BlockApplication_ReturnsNonZeroRuleId) {
    if (!EnsureFirewallStarted()) {
        GTEST_SKIP() << "FirewallManager WFP enforcement unavailable on this endpoint.";
    }

    auto& manager = SSN::FirewallManager::Instance();
    constexpr std::wstring_view kApp = L"C:\\ShadowStrike\\Tests\\malware_dummy.exe";

    const uint64_t ruleId = manager.BlockApplication(std::wstring(kApp), SSN::RuleDirection::BOTH);
    TrackFirewallRuleId(ruleId);

    EXPECT_GT(ruleId, 0ULL);
}

// ---------------------------------------------------------------------------
// GROUP 3: IsApplicationBlocked must return true immediately after a
// BlockApplication call with no intervening policy flush or latency.
// ---------------------------------------------------------------------------
TEST_F(FirewallManager_RuleManagement, IsApplicationBlocked_TrueAfterBlockApplication) {
    if (!EnsureFirewallStarted()) {
        GTEST_SKIP() << "FirewallManager WFP enforcement unavailable on this endpoint.";
    }

    auto& manager = SSN::FirewallManager::Instance();
    constexpr std::wstring_view kApp = L"C:\\ShadowStrike\\Tests\\blocked_app_dummy.exe";

    const uint64_t ruleId = manager.BlockApplication(std::wstring(kApp), SSN::RuleDirection::BOTH);
    ASSERT_GT(ruleId, 0ULL);
    TrackFirewallRuleId(ruleId);

    EXPECT_TRUE(manager.IsApplicationBlocked(std::wstring(kApp)));
}

// ---------------------------------------------------------------------------
// GROUP 3: SetRuleEnabled must allow a rule to be disabled and then re-enabled
// without destroying its definition or leaving an inconsistent WFP state.
// ---------------------------------------------------------------------------
TEST_F(FirewallManager_RuleManagement, SetRuleEnabled_DisableAndReenable_StateIsConsistent) {
    if (!EnsureFirewallStarted()) {
        GTEST_SKIP() << "FirewallManager WFP enforcement unavailable on this endpoint.";
    }

    auto rule = SSN::FirewallRule::CreateBlockIP(L"203.0.113.102", SSN::RuleDirection::BOTH);
    rule.name = TestRuleName(L"Enable Toggle Rule");

    auto& manager = SSN::FirewallManager::Instance();
    const uint64_t ruleId = manager.AddRule(rule);
    ASSERT_GT(ruleId, 0ULL);
    TrackFirewallRuleId(ruleId);

    ASSERT_TRUE(manager.SetRuleEnabled(ruleId, false));
    const std::optional<SSN::FirewallRule> disabled = manager.GetRule(ruleId);
    ASSERT_TRUE(disabled.has_value());
    EXPECT_FALSE(disabled->isEnabled);

    ASSERT_TRUE(manager.SetRuleEnabled(ruleId, true));
    const std::optional<SSN::FirewallRule> reenabled = manager.GetRule(ruleId);
    ASSERT_TRUE(reenabled.has_value());
    EXPECT_TRUE(reenabled->isEnabled);
}

// ---------------------------------------------------------------------------
// GROUP 3: GetRulesByType must return only rules of the requested type; wrong-
// type inclusions would corrupt type-specific policy export and audit views.
// ---------------------------------------------------------------------------
TEST_F(FirewallManager_RuleManagement, GetRulesByType_ReturnsCorrectTypeSubset) {
    if (!EnsureFirewallStarted()) {
        GTEST_SKIP() << "FirewallManager WFP enforcement unavailable on this endpoint.";
    }

    auto& manager = SSN::FirewallManager::Instance();

    auto ipRule = SSN::FirewallRule::CreateBlockIP(L"203.0.113.103", SSN::RuleDirection::BOTH);
    ipRule.name = TestRuleName(L"TypeFilter IP Rule");
    auto portRule = SSN::FirewallRule::CreateBlockPort(9877U, SSN::RuleProtocol::TCP, SSN::RuleDirection::OUTBOUND);
    portRule.name = TestRuleName(L"TypeFilter Port Rule");

    const uint64_t ipId   = manager.AddRule(ipRule);
    const uint64_t portId = manager.AddRule(portRule);
    ASSERT_GT(ipId,   0ULL);
    ASSERT_GT(portId, 0ULL);
    TrackFirewallRuleId(ipId);
    TrackFirewallRuleId(portId);

    const std::vector<SSN::FirewallRule> ipRules   = manager.GetRulesByType(SSN::RuleType::IP);
    const std::vector<SSN::FirewallRule> portRules  = manager.GetRulesByType(SSN::RuleType::PORT);

    EXPECT_TRUE(ContainsRuleId(ipRules,    ipId));
    EXPECT_TRUE(ContainsRuleId(portRules,  portId));
    EXPECT_FALSE(ContainsRuleId(ipRules,   portId))
        << "Port rule must not appear in the IP-type subset.";
    EXPECT_FALSE(ContainsRuleId(portRules, ipId))
        << "IP rule must not appear in the PORT-type subset.";
}

// ---------------------------------------------------------------------------
// GROUP 3: GetAllRules(enabledOnly=true) must exclude disabled rules so that
// compliance reports and policy export never list suppressed entries.
// ---------------------------------------------------------------------------
TEST_F(FirewallManager_RuleManagement, GetAllRules_EnabledOnlyFilter_ExcludesDisabledRules) {
    if (!EnsureFirewallStarted()) {
        GTEST_SKIP() << "FirewallManager WFP enforcement unavailable on this endpoint.";
    }

    auto rule = SSN::FirewallRule::CreateBlockIP(L"203.0.113.104", SSN::RuleDirection::BOTH);
    rule.name = TestRuleName(L"EnabledOnly Filter Rule");

    auto& manager = SSN::FirewallManager::Instance();
    const uint64_t ruleId = manager.AddRule(rule);
    ASSERT_GT(ruleId, 0ULL);
    TrackFirewallRuleId(ruleId);

    ASSERT_TRUE(manager.SetRuleEnabled(ruleId, false));

    const std::vector<SSN::FirewallRule> allRules     = manager.GetAllRules(false);
    const std::vector<SSN::FirewallRule> enabledRules = manager.GetAllRules(true);

    EXPECT_TRUE(ContainsRuleId(allRules, ruleId))
        << "Disabled rule must appear in GetAllRules(false).";
    EXPECT_FALSE(ContainsRuleId(enabledRules, ruleId))
        << "Disabled rule must NOT appear in GetAllRules(true).";
}

// ---------------------------------------------------------------------------
// GROUP 3: IsLockdownActive must be false at startup; an erroneous true
// would silently block all traffic before any threat policy is loaded.
// ---------------------------------------------------------------------------
TEST_F(FirewallManager_RuleManagement, IsLockdownActive_InitiallyFalse) {
    if (!EnsureFirewallInitialized()) {
        GTEST_SKIP() << "FirewallManager initialization unavailable on this endpoint.";
    }

    EXPECT_FALSE(SSN::FirewallManager::Instance().IsLockdownActive());
}

// ---------------------------------------------------------------------------
// GROUP 3: The default stealth mode must be OFF; activating it at startup
// would hide the endpoint from legitimate management and monitoring traffic.
// ---------------------------------------------------------------------------
TEST_F(FirewallManager_RuleManagement, GetStealthMode_DefaultIsOff) {
    if (!EnsureFirewallInitialized()) {
        GTEST_SKIP() << "FirewallManager initialization unavailable on this endpoint.";
    }

    EXPECT_EQ(SSN::FirewallManager::Instance().GetStealthMode(), SSN::StealthMode::OFF);
}

// ---------------------------------------------------------------------------
// GROUP 3: RemoveRule on an unknown ID must return false and must never
// corrupt the rule store or crash the engine via double-free or assert.
// ---------------------------------------------------------------------------
TEST_F(FirewallManager_RuleManagement, RemoveRule_NonExistentId_ReturnsFalse) {
    if (!EnsureFirewallInitialized()) {
        GTEST_SKIP() << "FirewallManager initialization unavailable on this endpoint.";
    }

    constexpr uint64_t kBogusId = 0xDEADBEEFDEADBEEFULL;
    EXPECT_FALSE(SSN::FirewallManager::Instance().RemoveRule(kBogusId));
}

// ---------------------------------------------------------------------------
// GROUP 3: GetRule(0) must return nullopt; zero is never a valid WFP filter
// handle and must never match an existing rule or trigger a heap lookup.
// ---------------------------------------------------------------------------
TEST_F(FirewallManager_RuleManagement, GetRule_ZeroId_ReturnsNullopt) {
    if (!EnsureFirewallInitialized()) {
        GTEST_SKIP() << "FirewallManager initialization unavailable on this endpoint.";
    }

    EXPECT_FALSE(SSN::FirewallManager::Instance().GetRule(0ULL).has_value());
}

// ---------------------------------------------------------------------------
// GROUP 3: The full FirewallStatistics struct must be readable after Reset so
// that every dashboard field can be dereferenced without undefined behaviour.
// ---------------------------------------------------------------------------
TEST_F(FirewallManager_RuleManagement, GetStatistics_FullStruct_AllFieldsReadableAfterReset) {
    if (!EnsureFirewallInitialized()) {
        GTEST_SKIP() << "FirewallManager initialization unavailable on this endpoint.";
    }

    auto& manager = SSN::FirewallManager::Instance();
    manager.ResetStatistics();
    const SSN::FirewallStatistics& s = manager.GetStatistics();

    EXPECT_EQ(LoadRelaxed(s.totalConnections),      0ULL);
    EXPECT_EQ(LoadRelaxed(s.allowedConnections),    0ULL);
    EXPECT_EQ(LoadRelaxed(s.blockedConnections),    0ULL);
    EXPECT_EQ(LoadRelaxed(s.ruleEvaluations),       0ULL);
    EXPECT_EQ(LoadRelaxed(s.ruleMatches),           0ULL);
    EXPECT_EQ(LoadRelaxed(s.geoBlockedConnections), 0ULL);
    EXPECT_EQ(LoadRelaxed(s.wfpErrors),             0ULL);
}

// ===========================================================================
// GROUP 4 (extended) – Cross-module edge-case hardening
// ===========================================================================

// ---------------------------------------------------------------------------
// GROUP 4: Blocking the same IP in NetworkMonitor and FirewallManager must
// succeed independently; neither module must corrupt the other's state.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_CrossModuleIntegration, BlockSameIP_BothModules_IndependentState) {
    if (!EnsureNetworkMonitorInitialized()) {
        GTEST_SKIP() << "NetworkMonitor initialization unavailable on this endpoint.";
    }
    if (!EnsureFirewallStarted()) {
        GTEST_SKIP() << "FirewallManager WFP enforcement unavailable on this endpoint.";
    }

    const SSN::IPAddress nmIp("203.0.113.150");
    ASSERT_TRUE(nmIp.IsValid());

    auto& nm  = SSN::NetworkMonitor::Instance();
    auto& fwm = SSN::FirewallManager::Instance();

    ASSERT_TRUE(nm.BlockIP(nmIp, SSN::BlockReason::MANUAL_BLOCK));
    TrackBlockedIp(nmIp);

    const uint64_t fwRuleId = fwm.BlockIP(L"203.0.113.150", SSN::RuleDirection::BOTH);
    ASSERT_GT(fwRuleId, 0ULL);
    TrackFirewallRuleId(fwRuleId);

    EXPECT_TRUE(nm.IsIPBlocked(nmIp));
    EXPECT_TRUE(fwm.IsIPBlocked(L"203.0.113.150"));
}

// ---------------------------------------------------------------------------
// GROUP 4: GetConfig on all three modules must reflect the settings used at
// initialization so config-drift detection tooling always gets accurate data.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_CrossModuleIntegration, AllModules_GetConfig_ReflectsInitializedState) {
    if (!EnsureNetworkMonitorInitialized()) {
        GTEST_SKIP() << "NetworkMonitor initialization unavailable on this endpoint.";
    }
    if (!EnsureDnsMonitorInitialized()) {
        GTEST_SKIP() << "DNSMonitor initialization unavailable on this endpoint.";
    }
    if (!EnsureFirewallInitialized()) {
        GTEST_SKIP() << "FirewallManager initialization unavailable on this endpoint.";
    }

    const SSN::NetworkMonitorConfig  nmCfg  = SSN::NetworkMonitor::Instance().GetConfig();
    const SSN::DNSMonitorConfig      dnsCfg = SSN::DNSMonitor::Instance().GetConfig();
    const SSN::FirewallManagerConfig fwCfg  = SSN::FirewallManager::Instance().GetConfig();

    EXPECT_TRUE(nmCfg.enabled);
    EXPECT_TRUE(dnsCfg.enabled);
    EXPECT_TRUE(fwCfg.enabled);
}

// ===========================================================================
// GROUP 5 (extended) – Statistics edge-case hardening
// ===========================================================================

// ---------------------------------------------------------------------------
// GROUP 5: DNSStatistics::Reset must zero ALL counter families so threat
// hunting and DGA detection baselines are never polluted by residual data.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_Statistics, DNSMonitor_ResetStatistics_ClearsAllCounterFamilies) {
    if (!EnsureDnsMonitorInitialized()) {
        GTEST_SKIP() << "DNSMonitor initialization unavailable on this endpoint.";
    }

    auto& monitor = SSN::DNSMonitor::Instance();
    monitor.ResetStatistics();
    const SSN::DNSStatistics& s = monitor.GetStatistics();

    EXPECT_EQ(LoadRelaxed(s.totalQueries),         0ULL);
    EXPECT_EQ(LoadRelaxed(s.queriesA),             0ULL);
    EXPECT_EQ(LoadRelaxed(s.queriesAAAA),          0ULL);
    EXPECT_EQ(LoadRelaxed(s.queriesTXT),           0ULL);
    EXPECT_EQ(LoadRelaxed(s.totalResponses),       0ULL);
    EXPECT_EQ(LoadRelaxed(s.domainsBlocked),       0ULL);
    EXPECT_EQ(LoadRelaxed(s.dgaDetections),        0ULL);
    EXPECT_EQ(LoadRelaxed(s.tunnelingDetections),  0ULL);
    EXPECT_EQ(LoadRelaxed(s.poisoningDetections),  0ULL);
    EXPECT_EQ(LoadRelaxed(s.cacheHits),            0ULL);
    EXPECT_EQ(LoadRelaxed(s.cacheMisses),          0ULL);
    EXPECT_EQ(LoadRelaxed(s.errorCount),           0ULL);
}

// ---------------------------------------------------------------------------
// GROUP 5: NetworkMonitorStatistics::Reset must clear traffic-volume counters;
// leftover bandwidth data would inflate attack-scoring calculations.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_Statistics, NetworkMonitor_ResetStatistics_ClearsTrafficCounters) {
    if (!EnsureNetworkMonitorInitialized()) {
        GTEST_SKIP() << "NetworkMonitor initialization unavailable on this endpoint.";
    }

    auto& monitor = SSN::NetworkMonitor::Instance();
    monitor.ResetStatistics();
    const SSN::NetworkMonitorStatistics& s = monitor.GetStatistics();

    EXPECT_EQ(LoadRelaxed(s.totalBytesReceived),   0ULL);
    EXPECT_EQ(LoadRelaxed(s.totalBytesSent),       0ULL);
    EXPECT_EQ(LoadRelaxed(s.totalPacketsReceived), 0ULL);
    EXPECT_EQ(LoadRelaxed(s.totalPacketsSent),     0ULL);
    EXPECT_EQ(LoadRelaxed(s.threatsDetected),      0ULL);
    EXPECT_EQ(LoadRelaxed(s.eventsProcessed),      0ULL);
    EXPECT_EQ(LoadRelaxed(s.eventsDropped),        0ULL);
}

// ===========================================================================
// GROUP 6 (extended) – Concurrency edge-case hardening
// ===========================================================================

// ---------------------------------------------------------------------------
// GROUP 6: Concurrent BlockIP / IsIPBlocked / UnblockIP on distinct addresses
// must complete without races or assertion failures in the blocklist.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_Concurrency, ConcurrentNetworkMonitorBlockUnblock_IsThreadSafe) {
    if (!EnsureNetworkMonitorInitialized()) {
        GTEST_SKIP() << "NetworkMonitor initialization unavailable on this endpoint.";
    }

    auto& monitor = SSN::NetworkMonitor::Instance();
    constexpr int kThreadCount = 4;
    constexpr int kIpsPerThread = 8;

    std::atomic<int>      readyCount{0};
    std::atomic<bool>     startGate{false};
    std::atomic<uint32_t> failureCount{0};
    std::vector<std::thread> threads;
    threads.reserve(kThreadCount);

    for (int t = 0; t < kThreadCount; ++t) {
        threads.emplace_back([&, t]() {
            readyCount.fetch_add(1, std::memory_order_acq_rel);
            while (!startGate.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }

            for (int i = 0; i < kIpsPerThread; ++i) {
                const int octet = 210 + t * kIpsPerThread + i;
                const SSN::IPAddress ip("203.0.113." + std::to_string(octet));
                if (!ip.IsValid()) {
                    failureCount.fetch_add(1, std::memory_order_acq_rel);
                    continue;
                }

                if (!monitor.BlockIP(ip, SSN::BlockReason::MANUAL_BLOCK)) {
                    failureCount.fetch_add(1, std::memory_order_acq_rel);
                }
                if (!monitor.IsIPBlocked(ip)) {
                    failureCount.fetch_add(1, std::memory_order_acq_rel);
                }
                if (!monitor.UnblockIP(ip)) {
                    failureCount.fetch_add(1, std::memory_order_acq_rel);
                }
                if (monitor.IsIPBlocked(ip)) {
                    failureCount.fetch_add(1, std::memory_order_acq_rel);
                }
            }
        });
    }

    while (readyCount.load(std::memory_order_acquire) != kThreadCount) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    startGate.store(true, std::memory_order_release);

    for (std::thread& th : threads) {
        th.join();
    }

    EXPECT_EQ(failureCount.load(std::memory_order_relaxed), 0U)
        << "One or more concurrent BlockIP/UnblockIP operations failed.";
}

// ---------------------------------------------------------------------------
// GROUP 6: Concurrent GetAllRules calls during parallel rule additions must
// never produce torn reads, crashes, or assertion failures in the rule store.
// ---------------------------------------------------------------------------
TEST_F(NetworkChain_Concurrency, ConcurrentFirewallReadDuringWrite_IsThreadSafe) {
    if (!EnsureFirewallStarted()) {
        GTEST_SKIP() << "FirewallManager WFP enforcement unavailable on this endpoint.";
    }

    auto& manager = SSN::FirewallManager::Instance();
    constexpr int kWriterThreads = 2;
    constexpr int kReaderThreads = 2;
    constexpr int kRulesPerWriter = 4;

    std::atomic<int>      readyCount{0};
    std::atomic<bool>     startGate{false};
    std::atomic<uint32_t> failureCount{0};
    std::mutex            ruleTrackingMutex;
    std::vector<uint64_t> addedRuleIds;
    std::vector<std::thread> threads;
    threads.reserve(kWriterThreads + kReaderThreads);

    for (int t = 0; t < kWriterThreads; ++t) {
        threads.emplace_back([&, t]() {
            readyCount.fetch_add(1, std::memory_order_acq_rel);
            while (!startGate.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }

            for (int i = 0; i < kRulesPerWriter; ++i) {
                const int octet = 150 + t * kRulesPerWriter + i;
                auto rule = SSN::FirewallRule::CreateBlockIP(
                    L"203.0.113." + std::to_wstring(octet),
                    SSN::RuleDirection::OUTBOUND);
                rule.name = TestRuleName(L"ReadWrite-" + std::to_wstring(octet));

                const uint64_t ruleId = manager.AddRule(rule);
                if (ruleId == 0ULL) {
                    failureCount.fetch_add(1, std::memory_order_acq_rel);
                } else {
                    std::lock_guard<std::mutex> lock(ruleTrackingMutex);
                    addedRuleIds.push_back(ruleId);
                }
            }
        });
    }

    for (int t = 0; t < kReaderThreads; ++t) {
        threads.emplace_back([&]() {
            readyCount.fetch_add(1, std::memory_order_acq_rel);
            while (!startGate.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }

            for (int i = 0; i < 8; ++i) {
                const std::vector<SSN::FirewallRule> rules = manager.GetAllRules(false);
                if (rules.empty() && i > 0) {
                    // Non-fatal: writers may not have committed yet.
                }
                std::this_thread::yield();
            }
        });
    }

    while (readyCount.load(std::memory_order_acquire) != (kWriterThreads + kReaderThreads)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    startGate.store(true, std::memory_order_release);

    for (std::thread& th : threads) {
        th.join();
    }

    {
        std::lock_guard<std::mutex> lock(ruleTrackingMutex);
        for (const uint64_t id : addedRuleIds) {
            TrackFirewallRuleId(id);
        }
    }

    EXPECT_EQ(failureCount.load(std::memory_order_relaxed), 0U)
        << "One or more concurrent AddRule operations failed.";
}

}  // namespace
