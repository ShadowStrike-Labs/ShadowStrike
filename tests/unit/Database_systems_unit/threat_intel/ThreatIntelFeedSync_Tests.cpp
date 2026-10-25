/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file ThreatIntelFeedSync_Tests.cpp
 * @brief A registered feed is downloaded soon, parsed by the right parser, and lands in the store
 *        with the feed's meaning attached (task 259).
 *
 * The field symptom was a ThreatIntelStore with 0 indicators after 18 minutes of uptime with three
 * feeds "active". Five defects stood between registration and a stored indicator: the first sync
 * was one full interval (1-6 h) away on every start; the store's feeds carried no protocol, so a
 * plain-text body went to the JSON parser; the manager had no target store and discarded what it
 * parsed; parsed entries carried no reputation, confidence or TTL; and nothing was logged. These
 * cases drive a real manager and a real store with a scripted HTTP client - no network.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "PhantomCore/ThreatIntel/ThreatIntelFeedManager.hpp"
#include "PhantomCore/ThreatIntel/ThreatIntelStore.hpp"

#include <atomic>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <future>
#include <memory>
#include <string>
#include <thread>

using namespace ShadowStrike::ThreatIntel;

namespace {

/// Answers every request with one scripted status and body, and counts requests.
class ScriptedHttpClient final : public IHttpClient {
public:
    ScriptedHttpClient(int status, std::string body) : m_status(status), m_body(std::move(body)) {}

    HttpResponse Execute(const HttpRequest&) override {
        ++requests;
        HttpResponse r;
        r.statusCode = m_status;
        r.statusMessage = m_status == 200 ? "OK" : "Service Unavailable";
        r.body.assign(m_body.begin(), m_body.end());
        return r;
    }
    std::future<HttpResponse> ExecuteAsync(const HttpRequest& request) override {
        std::promise<HttpResponse> p;
        p.set_value(Execute(request));
        return p.get_future();
    }
    void SetDefaultHeaders(const std::unordered_map<std::string, std::string>&) override {}
    void SetProxy(const std::string&) override {}
    std::string GetLastError() const override { return {}; }

    std::atomic<int> requests{0};

private:
    int m_status;
    std::string m_body;
};

constexpr const char* kFeodoBody = "# Feodo Tracker recommended blocklist\n203.0.113.7\n198.51.100.23\n";
constexpr const char* kUrlhausBody =
    "id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
    "\"1\",\"2026-10-25 10:00:00\",\"http://malware.example/a.exe\",\"online\",\"\",\"malware_download\",\"\",\"\",\"x\"\n"
    "\"2\",\"2026-10-25 10:01:00\",\"http://malware.example/b.exe\",\"online\",\"\",\"malware_download\",\"\",\"\",\"x\"\n";

uint64_t Now() { return static_cast<uint64_t>(std::time(nullptr)); }

class ScratchDir {
public:
    ScratchDir()
        : path(std::filesystem::temp_directory_path() /
               ("ss_feedsync_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()))) {
        std::filesystem::create_directories(path);
    }
    ~ScratchDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
    std::filesystem::path path;
};

std::shared_ptr<ThreatIntelStore> OpenStore(const ScratchDir& dir) {
    auto store = std::make_shared<ThreatIntelStore>();
    StoreConfig cfg;
    cfg.databasePath = (dir.path / "ti.db").wstring();
    cfg.enableCache = true;
    cfg.enableAutoFeedUpdate = false;
    return store->Initialize(cfg) ? store : nullptr;
}

std::unique_ptr<ThreatIntelFeedManager> StartedManager(std::shared_ptr<IHttpClient> http, uint32_t initialDelay = 60) {
    auto mgr = std::make_unique<ThreatIntelFeedManager>();
    ThreatIntelFeedManager::Config cfg;
    cfg.initialSyncDelaySeconds = initialDelay;
    cfg.enableHealthMonitoring = false;
    if (!mgr->Initialize(cfg)) return nullptr;
    mgr->SetHttpClient(std::move(http));
    return mgr;
}

ThreatFeedConfig Feodo(uint32_t intervalSeconds = 7200) {
    auto cfg = ThreatFeedConfig::CreateFeodoTracker();
    cfg.syncIntervalSeconds = intervalSeconds;
    return cfg;
}

}  // namespace

// ============================================================================
// When a feed syncs
// ============================================================================

TEST(FeedSyncSchedule, TheFirstSyncIsDueShortlyAfterStartNotAfterAFullInterval) {
    auto http = std::make_shared<ScriptedHttpClient>(200, kFeodoBody);
    auto mgr = StartedManager(http, 60);
    ASSERT_TRUE(mgr);
    ASSERT_TRUE(mgr->AddFeed(Feodo(6 * 3600)));
    const uint64_t before = Now();
    ASSERT_TRUE(mgr->Start());

    const auto* stats = mgr->GetFeedStats("feodotracker");
    ASSERT_NE(nullptr, stats);
    const uint64_t due = stats->nextScheduledSync.load();
    EXPECT_GE(due, before + 60);
    EXPECT_LE(due, Now() + 120) << "the first sync was scheduled " << (due - before)
                                << " s out; a full interval means a short-lived service never syncs";
    (void)mgr->Stop(5000);
}

TEST(FeedSyncSchedule, AFailedSyncIsRetriedWithinMinutesAndBacksOff) {
    auto http = std::make_shared<ScriptedHttpClient>(503, "");
    auto mgr = StartedManager(http);
    ASSERT_TRUE(mgr);
    ASSERT_TRUE(mgr->AddFeed(Feodo(6 * 3600)));

    EXPECT_FALSE(mgr->SyncFeed("feodotracker").success);
    const uint64_t first = mgr->GetFeedStats("feodotracker")->nextScheduledSync.load() - Now();
    EXPECT_GE(first, 295u);
    EXPECT_LE(first, 300u) << "a failure waited " << first << " s instead of the 300 s retry";

    EXPECT_FALSE(mgr->SyncFeed("feodotracker").success);
    const uint64_t second = mgr->GetFeedStats("feodotracker")->nextScheduledSync.load() - Now();
    EXPECT_GE(second, 595u);
    EXPECT_LE(second, 600u) << "the second consecutive failure should double the delay";
}

TEST(FeedSyncSchedule, ARecentSuccessKeepsTheRegularScheduleAcrossARestart) {
    auto http = std::make_shared<ScriptedHttpClient>(200, kFeodoBody);
    auto mgr = StartedManager(http);
    ASSERT_TRUE(mgr);
    ASSERT_TRUE(mgr->AddFeed(Feodo(7200)));
    ASSERT_TRUE(mgr->SyncFeed("feodotracker").success);

    ASSERT_TRUE(mgr->Start());
    const uint64_t due = mgr->GetFeedStats("feodotracker")->nextScheduledSync.load();
    EXPECT_GE(due, Now() + 7000) << "a feed that just synced must not download again at start";
    (void)mgr->Stop(5000);
}

TEST(FeedSyncSchedule, TheSchedulerSyncsAFeedAgainAfterStopAndStart) {
    // Stop() cancels every feed so a download in flight ends quickly. The flag must be cleared
    // by Start(), or WorkerThread skips every task of that feed for the rest of the process.
    auto http = std::make_shared<ScriptedHttpClient>(200, kFeodoBody);
    auto mgr = StartedManager(http, 0);
    ASSERT_TRUE(mgr);
    ASSERT_TRUE(mgr->AddFeed(Feodo(7200)));

    const auto waitForRequests = [&](int n) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        while (http->requests.load() < n && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        return http->requests.load() >= n;
    };

    ASSERT_TRUE(mgr->Start());
    ASSERT_TRUE(waitForRequests(1)) << "the scheduler never ran the first sync";
    ASSERT_TRUE(mgr->Stop(5000));

    // Make the feed due again: a fresh success would otherwise keep its 2 h schedule.
    const_cast<FeedStats*>(mgr->GetFeedStats("feodotracker"))->lastSuccessfulSync.store(0);
    ASSERT_TRUE(mgr->Start());
    EXPECT_TRUE(waitForRequests(2)) << "after Stop and Start the feed never synced again";
    (void)mgr->Stop(5000);
}

// ============================================================================
// What a sync stores
// ============================================================================

TEST(FeedSyncStore, AnIpBlocklistLandsInTheStoreAsMalicious) {
    ScratchDir dir;
    auto store = OpenStore(dir);
    ASSERT_TRUE(store);
    auto http = std::make_shared<ScriptedHttpClient>(200, kFeodoBody);
    auto mgr = StartedManager(http);
    ASSERT_TRUE(mgr);
    mgr->SetTargetStore(store);
    ASSERT_TRUE(mgr->AddFeed(Feodo()));

    const auto result = mgr->SyncFeed("feodotracker");
    ASSERT_TRUE(result.success) << result.errorMessage;
    EXPECT_EQ(2u, result.totalFetched);
    EXPECT_EQ(2u, result.newIOCs);

    const auto hit = store->LookupIPv4("203.0.113.7");
    ASSERT_TRUE(hit.found) << "a synced indicator is not in the store";
    EXPECT_EQ(ReputationLevel::Malicious, hit.reputation)
        << "the feed's default reputation was not applied, so the hit means nothing";
    EXPECT_FALSE(store->LookupIPv4("192.0.2.1").found);

    mgr.reset();
    store->Shutdown();
}

TEST(FeedSyncStore, UrlIndicatorsAreDroppedRatherThanStoredAsFakeStringReferences) {
    ScratchDir dir;
    auto store = OpenStore(dir);
    ASSERT_TRUE(store);
    auto http = std::make_shared<ScriptedHttpClient>(200, kUrlhausBody);
    auto mgr = StartedManager(http);
    ASSERT_TRUE(mgr);
    mgr->SetTargetStore(store);
    ASSERT_TRUE(mgr->AddFeed(ThreatFeedConfig::CreateURLhaus()));

    const auto result = mgr->SyncFeed("urlhaus");
    ASSERT_TRUE(result.success) << result.errorMessage;
    EXPECT_EQ(2u, result.totalFetched);
    EXPECT_EQ(0u, result.newIOCs) << "a URL keyed by a hash in the string-offset field was stored";
    EXPECT_EQ(2u, result.invalidIOCs);

    mgr.reset();
    store->Shutdown();
}

TEST(FeedSyncStore, TheStoreRegistersItsDefaultFeedsAndSchedulesThemSoon) {
    ScratchDir dir;
    auto store = OpenStore(dir);
    ASSERT_TRUE(store);
    EXPECT_GE(store->RegisterDefaultFeeds(), 2u);
    EXPECT_TRUE(store->GetFeedStatus("feodotracker").has_value());
    EXPECT_TRUE(store->GetFeedStatus("etopen-compromised-ips").has_value());
    EXPECT_FALSE(store->GetFeedStatus("urlhaus").has_value())
        << "URLhaus indicators cannot be stored yet, so downloading it costs bandwidth for nothing";

    store->StartFeedUpdates();
    const auto status = store->GetFeedStatus("feodotracker");
    ASSERT_TRUE(status.has_value());
    const auto wait = std::chrono::duration_cast<std::chrono::seconds>(
        status->nextUpdateTime - std::chrono::system_clock::now()).count();
    EXPECT_LE(wait, 125) << "the shared store's first sync is " << wait << " s away";
    store->Shutdown();
}

// ============================================================================
// Which parser a store-level feed gets
// ============================================================================

TEST(FeedManagerConfigMapping, TheFeedTypeChoosesTheParser) {
    FeedConfiguration plain;
    plain.feedId = "plain";
    plain.url = "https://feeds.example/list.txt";
    plain.type = FeedType::PlainText;
    const auto p = ToFeedManagerConfig(plain);
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(FeedProtocol::CSV_HTTP, p->protocol) << "plain text went to the JSON parser";
    EXPECT_EQ('\0', p->parser.csvDelimiter);
    EXPECT_FALSE(p->parser.csvHasHeader);
    EXPECT_EQ("https://feeds.example/list.txt", p->endpoint.baseUrl);

    plain.type = FeedType::CSV;
    EXPECT_EQ(FeedProtocol::CSV_HTTP, ToFeedManagerConfig(plain)->protocol);
    plain.type = FeedType::JSON;
    EXPECT_EQ(FeedProtocol::JSON_HTTP, ToFeedManagerConfig(plain)->protocol);
    plain.type = FeedType::STIX_TAXII;
    EXPECT_EQ(FeedProtocol::STIX_TAXII, ToFeedManagerConfig(plain)->protocol);
    plain.type = FeedType::YARA;
    EXPECT_FALSE(ToFeedManagerConfig(plain).has_value()) << "no parser reads YARA";
    plain.type = FeedType::Unknown;
    EXPECT_FALSE(ToFeedManagerConfig(plain).has_value()) << "an unstated format is not guessed as JSON";
}

TEST(FeedManagerConfigMapping, AuthenticationIsMappedByNameNotByValue) {
    FeedConfiguration c;
    c.feedId = "auth";
    c.url = "https://feeds.example/x";
    c.type = FeedType::JSON;
    c.authType = FeedAuthType::Custom;   // 6, which is AuthMethod::HMAC by value
    EXPECT_EQ(AuthMethod::Custom, ToFeedManagerConfig(c)->auth.method);
    c.authType = FeedAuthType::APIKey;
    EXPECT_EQ(AuthMethod::ApiKey, ToFeedManagerConfig(c)->auth.method);
}

TEST(FeedParsers, AParsedEntryStartsUnknownNotSafeOrIndeterminate) {
    // Reputation 0 is Safe, so a zeroed entry is not neutral either.
    CsvFeedParser parser;
    ParserConfig cfg;
    cfg.csvDelimiter = '\0';
    cfg.csvHasHeader = false;
    const std::string body = "203.0.113.7\n";
    std::vector<IOCEntry> out;
    ASSERT_TRUE(parser.Parse(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(body.data()), body.size()),
                             out, cfg));
    ASSERT_EQ(1u, out.size());
    EXPECT_EQ(ReputationLevel::Unknown, out[0].reputation);
    EXPECT_EQ(ConfidenceLevel::None, out[0].confidence);
    EXPECT_EQ(0u, out[0].expirationTime);
    EXPECT_EQ(0u, out[0].entryId);
}
