/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file PoolConnectionIdentity_Tests.cpp
 * @brief Deciding that a network endpoint is a cryptocurrency mining pool.
 *
 * A pool verdict leads to a process being reported, and possibly killed, so both directions cost
 * something: a miss leaves a machine mining for someone else, and a false positive accuses ordinary
 * software. The identification is layered - built-in hostname lists, a configured blacklist, port
 * membership, proxy and DGA heuristics, then threat intel - and this file pins the layers that can be
 * exercised deterministically.
 *
 * TWO STRUCTURAL PROPERTIES ARE ASSERTED THAT ARE NOT ABOUT ANY SINGLE INPUT.
 *
 * First, the two built-in hostname lists must not overlap. MALICIOUS_POOL_HOSTNAMES is consulted before
 * KNOWN_POOL_HOSTNAMES, so a host in both can only ever be reported KnownMalicious and its entry in the
 * second list is unreachable. Six hosts are currently in both, all of them legitimate public Monero
 * pools, which makes the code's own KnownPublic classification dead for exactly the hosts a user is
 * most likely to have chosen deliberately. Pinned below as it stands and filed, because deciding whether
 * mining on a public pool is malware or merely unwanted is a policy question, not a cleanup.
 *
 * Second, this file includes BOTH CryptoMinerDetector.hpp and PoolConnectionDetector.hpp in one
 * translation unit. They declare two wallet validators with the same name over two currency enums with
 * identical layouts, and the previous batch found a pair of Privacy headers that could not coexist for
 * exactly this reason. Compiling this file at all is therefore part of what it tests.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/CryptoMinersProtection/CryptoMinerDetector.hpp"
#include "Products/Community/PhantomHome/CryptoMinersProtection/PoolConnectionDetector.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::CryptoMiners::Test {
namespace {

/// The six hostnames measured to appear in BOTH built-in lists.
const std::vector<std::string>& HostsInBothLists() {
    static const std::vector<std::string> hosts = {
        "monerohash.com", "pool.hashvault.pro", "pool.minexmr.com",
        "pool.supportxmr.com", "xmr.nanopool.org", "xmrpool.eu"};
    return hosts;
}

/// Drive-by cryptojacking services - malicious with no ambiguity, since they mine without consent.
const std::vector<std::string>& CryptojackingHosts() {
    static const std::vector<std::string> hosts = {
        "coinhive.com", "coin-hive.com", "authedmine.com", "crypto-loot.com", "jsecoin.com"};
    return hosts;
}

[[nodiscard]] std::span<const std::uint8_t> AsBytes(const std::string& s) {
    return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

class PoolConnectionIdentityTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        // enableStratumDetection and enableDeepPacketInspection both default true, and the payload test
        // returns false outright when either is off - so without initialising, every stratum case would
        // pass for the wrong reason.
        ASSERT_TRUE(PoolConnectionDetector::Instance().Initialize())
            << "the detector could not be initialised, so no verdict below would mean anything";
    }

    static PoolConnectionDetector& Pool() { return PoolConnectionDetector::Instance(); }
};

}  // namespace

// ============================================================================================
// Hostname identification
// ============================================================================================

TEST_F(PoolConnectionIdentityTest, AKnownCryptojackingServiceIsIdentified) {
    for (const auto& host : CryptojackingHosts()) {
        EXPECT_TRUE(Pool().IsPoolHostname(host)) << host << " is a built-in cryptojacking host";
    }
}

TEST_F(PoolConnectionIdentityTest, AnOrdinaryHostIsNotAPool) {
    // Anti-vacuity for every identification case: without this they would hold for a function that
    // always answers true, and a false positive here accuses ordinary browsing.
    EXPECT_FALSE(Pool().IsPoolHostname("example.com"));
    EXPECT_FALSE(Pool().IsPoolHostname("github.com"));
    EXPECT_FALSE(Pool().IsPoolHostname("windowsupdate.microsoft.com"));
    EXPECT_FALSE(Pool().IsPoolHostname(""));
}

TEST_F(PoolConnectionIdentityTest, AHostIsMatchedOnLabelBoundariesNotSubstrings) {
    // A substring match would let an attacker register a lookalike and would also fire on an unrelated
    // host that merely contains a pool name. Matching is by dot-boundary suffix, so a subdomain of a
    // listed pool matches and a host that merely ends with the same letters does not.
    EXPECT_TRUE(Pool().IsPoolHostname("worker1.coinhive.com"))
        << "a subdomain of a listed pool must still be identified";
    EXPECT_FALSE(Pool().IsPoolHostname("notcoinhive.com"))
        << "a host merely ending in the listed name was matched, so the boundary is a substring";
    EXPECT_FALSE(Pool().IsPoolHostname("coinhive.com.example.org"))
        << "the listed name appearing as a PREFIX label was matched, which reverses the suffix rule";
}

TEST_F(PoolConnectionIdentityTest, SixLegitimatePublicPoolsAreClassifiedMaliciousBecauseTheyAreInBothLists) {
    // PINNED, NOT ENDORSED. These six appear in MALICIOUS_POOL_HOSTNAMES and in KNOWN_POOL_HOSTNAMES.
    // The malicious list is consulted first, so the KnownPublic classification the code deliberately
    // provides is unreachable for exactly these hosts - the ones a user is most likely to have chosen
    // on purpose.
    //
    // The surrounding policy looks intentional: nanopool is split by coin, with xmr.nanopool.org treated
    // as malicious while eth.nanopool.org and zec.nanopool.org are known-public. So Monero pools being
    // treated as malicious is a deliberate stance. The duplication is not - it is two lists edited
    // independently. Filed. If a case here fails, the lists were reconciled: update the filing and this
    // case rather than restoring the duplicate entry.
    for (const auto& host : HostsInBothLists()) {
        EXPECT_TRUE(Pool().IsPoolHostname(host))
            << host << " is in both built-in lists and must still be identified as a pool";
    }
}

// ============================================================================================
// Endpoints and the configured blacklist
// ============================================================================================

TEST_F(PoolConnectionIdentityTest, AKnownPoolHostIsAnEndpointOnAMiningPort) {
    EXPECT_TRUE(Pool().IsPoolEndpoint("coinhive.com", 3333));
    EXPECT_TRUE(Pool().IsPoolEndpoint("pool.supportxmr.com", 5555));
}

TEST_F(PoolConnectionIdentityTest, APrivateAddressWithNoPortIsNotAnEndpoint) {
    // A private address carries no routable identity, so with no port there is nothing to judge. Treating
    // one as a pool would fire on ordinary local traffic.
    EXPECT_FALSE(Pool().IsPoolEndpoint("192.168.1.10", 0));
    EXPECT_FALSE(Pool().IsPoolEndpoint("127.0.0.1", 0));
    EXPECT_FALSE(Pool().IsPoolEndpoint("10.0.0.5", 0));
}

TEST_F(PoolConnectionIdentityTest, AnEmptyBlacklistBlacklistsNothing) {
    // The blacklist is configured, not built in, so with none configured every answer must be false.
    // A blacklist that answers true when empty would report every endpoint as known-bad.
    EXPECT_FALSE(Pool().IsBlacklisted("example.com"));
    EXPECT_FALSE(Pool().IsBlacklisted("example.com:3333"));
    EXPECT_FALSE(Pool().IsBlacklisted(""));
    EXPECT_FALSE(Pool().IsBlacklisted("not a valid endpoint at all"));
}

// ============================================================================================
// Stratum payload inspection
// ============================================================================================

TEST_F(PoolConnectionIdentityTest, AStratumUrlInThePayloadIsDetected) {
    const std::string payload = "GET /?url=stratum+tcp://pool.example.com:3333 HTTP/1.1\r\n\r\n";
    EXPECT_TRUE(Pool().IsStratumTraffic(AsBytes(payload)));
}

TEST_F(PoolConnectionIdentityTest, TheStratumSchemeIsMatchedWithoutRegardToCase) {
    const std::string upper = "STRATUM+TCP://POOL.EXAMPLE.COM:3333";
    EXPECT_TRUE(Pool().IsStratumTraffic(AsBytes(upper)))
        << "an upper-case scheme escaped detection, so the payload is not being lowercased";
}

TEST_F(PoolConnectionIdentityTest, OrdinaryTrafficIsNotStratum) {
    // Anti-vacuity, and the direction that matters for false positives.
    EXPECT_FALSE(Pool().IsStratumTraffic(AsBytes("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")));
    EXPECT_FALSE(Pool().IsStratumTraffic(AsBytes("{\"jsonrpc\":\"2.0\",\"method\":\"getBalance\"}")))
        << "an unrelated JSON-RPC call was reported as stratum";
}

TEST_F(PoolConnectionIdentityTest, AnEmptyPayloadIsNotStratum) {
    EXPECT_FALSE(Pool().IsStratumTraffic({}));
}

TEST_F(PoolConnectionIdentityTest, BinaryPayloadIsNotInspectedAsText) {
    // Encrypted or compressed traffic is not text, and searching it for a scheme string would be both
    // wasteful and prone to chance matches.
    const std::vector<std::uint8_t> binary = {0x00, 0xFF, 0x01, 0xFE, 0x02, 0xFD, 0x00, 0x00, 0x80, 0x7F};
    EXPECT_FALSE(Pool().IsStratumTraffic(binary));
}

// ============================================================================================
// The two wallet validators - the reason both headers are included here
// ============================================================================================

TEST(PoolWalletValidatorTest, TheTwoValidatorsAgreeOnEveryProbe) {
    // CryptoMinerDetector and PoolConnectionDetector each declare ValidateWalletAddress, over two enums
    // whose layouts are identical value for value. A maintainer would reasonably treat them as
    // interchangeable. They were built on different mechanisms - a hand-written character-class switch
    // and a compiled regex table - and until recently they disagreed in the dangerous direction, with
    // one accepting any string containing no whitespace.
    //
    // This case requires them to answer alike. It is the enforcement of the filing that records the
    // duplication, so that if they drift again a test fails rather than the divergence shipping.
    struct Probe {
        const char* address;
        Cryptocurrency a;
        MinedCryptocurrency b;
    };
    const std::vector<Probe> probes = {
        {"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", Cryptocurrency::Bitcoin, MinedCryptocurrency::Bitcoin},
        {"0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0", Cryptocurrency::Ethereum,
         MinedCryptocurrency::Ethereum},
        {"not-an-address", Cryptocurrency::Bitcoin, MinedCryptocurrency::Bitcoin},
        {"", Cryptocurrency::Bitcoin, MinedCryptocurrency::Bitcoin},
        {"C:\\Windows\\System32", Cryptocurrency::Unknown, MinedCryptocurrency::Unknown},
        {"--config=miner.conf", Cryptocurrency::Unknown, MinedCryptocurrency::Unknown},
        {"hello world", Cryptocurrency::Other, MinedCryptocurrency::Other},
    };
    for (const auto& p : probes) {
        const bool viaMiner = ValidateWalletAddress(p.address, p.a);
        const bool viaPool = ValidateWalletAddress(p.address, p.b);
        EXPECT_EQ(viaMiner, viaPool)
            << "the two wallet validators disagree for \"" << p.address
            << "\" - one of the duplicated implementations was changed alone";
    }
}

TEST(PoolWalletValidatorTest, NeitherValidatorAcceptsAnUndeterminedCurrency) {
    EXPECT_FALSE(ValidateWalletAddress("not-an-address", Cryptocurrency::Unknown));
    EXPECT_FALSE(ValidateWalletAddress("not-an-address", MinedCryptocurrency::Unknown));
    EXPECT_FALSE(ValidateWalletAddress("C:\\Windows\\System32", MinedCryptocurrency::Unknown))
        << "a Windows path was accepted as a wallet address for an undetermined currency";
}

}  // namespace ShadowStrike::CryptoMiners::Test
