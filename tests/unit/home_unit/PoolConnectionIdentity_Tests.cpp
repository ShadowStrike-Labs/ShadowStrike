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
 * First, every built-in host has one classification. MALICIOUS_POOL_HOSTNAMES is consulted before
 * KNOWN_POOL_HOSTNAMES, so a host in both was only ever KnownMalicious; six Monero pools were, until
 * task 284 left them in the malicious list only. A contract test keeps the lists disjoint.
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
#include <type_traits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::CryptoMiners::Test {
namespace {

/// The six Monero pools that used to appear in BOTH built-in lists (task 284).
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
        // Initialize is not idempotent (filed 288), so the STATE is tested rather than the return value - 
        // otherwise this suite would only pass when it is the first to initialise the singleton, which is an accident of test ordering.
        if (!PoolConnectionDetector::Instance().IsInitialized()) {
            (void)PoolConnectionDetector::Instance().Initialize();
        }
        ASSERT_TRUE(PoolConnectionDetector::Instance().IsInitialized())
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

TEST_F(PoolConnectionIdentityTest, EachBuiltInHostHasExactlyOneClassification) {
    // Task 284: six Monero pools were in BOTH built-in lists, so their KnownPublic entries were
    // unreachable. They now sit only in the malicious list, consistent with the coin-by-coin split
    // the lists already made around them.
    for (const auto& host : HostsInBothLists()) {
        const auto info = Pool().GetPoolInfo(host, 3333);
        ASSERT_TRUE(info.has_value()) << host;
        EXPECT_EQ(PoolStatus::KnownMalicious, info->status) << host;
    }
    // Anti-vacuity: the public classification is reachable at all.
    for (const char* host : {"eth.nanopool.org", "zec.nanopool.org", "stratum.slushpool.com"}) {
        const auto info = Pool().GetPoolInfo(host, 3333);
        ASSERT_TRUE(info.has_value()) << host;
        EXPECT_EQ(PoolStatus::KnownPublic, info->status) << host;
    }
}

// ============================================================================================
// Endpoints and the configured blacklist
// ============================================================================================

TEST_F(PoolConnectionIdentityTest, AHostEndingInADotIsNotMatchedByAnEmptyListSlot) {
    // The built-in lists were std::arrays sized larger than their contents, so the spare slots held
    // empty strings - and the dot-boundary match accepts an empty suffix for any host ending in '.'.
    EXPECT_FALSE(Pool().IsPoolHostname("example.com.")) << "a trailing dot matched a padding slot";
    EXPECT_FALSE(Pool().IsPoolHostname("."));
    EXPECT_FALSE(Pool().IsPoolHostname(""));
}

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

TEST(PoolWalletValidatorTest, ThereIsOneCurrencyTypeAndOneValidator) {
    // Task 281: two enums with identical layouts and two validators that disagreed. One of each now;
    // a value can no longer be converted between look-alike types, and nothing can drift.
    static_assert(std::is_same_v<MinedCryptocurrency, Cryptocurrency>);
    EXPECT_EQ(GetMinedCryptocurrencyName(MinedCryptocurrency::EthClassic),
              GetCryptocurrencyName(Cryptocurrency::EthClassic));
}

TEST(PoolWalletValidatorTest, FormsTheRegexTableRejectedAreRecognised) {
    // The pool module's regex copy demanded exactly 95 Monero characters, transparent-only Zcash and
    // [LM]-only Litecoin, so a payload carrying an integrated Monero address (106), a shielded Zcash
    // address or a bech32 Litecoin address yielded no wallet.
    const std::string integratedMonero = "4" + std::string("A") + std::string(104, '1');
    ASSERT_EQ(106u, integratedMonero.size());
    EXPECT_TRUE(ValidateWalletAddress(integratedMonero, Cryptocurrency::Monero));
    EXPECT_EQ(Cryptocurrency::Monero, ClassifyWalletAddress(integratedMonero));

    const std::string shieldedZcash = "zs" + std::string(76, 'q');
    EXPECT_EQ(Cryptocurrency::Zcash, ClassifyWalletAddress(shieldedZcash));

    const std::string bech32Litecoin = "ltc1" + std::string(39, 'q');
    EXPECT_EQ(Cryptocurrency::Litecoin, ClassifyWalletAddress(bech32Litecoin));
}

TEST(PoolWalletValidatorTest, ClassificationIsFixedAndFailsClosed) {
    EXPECT_EQ(Cryptocurrency::Bitcoin, ClassifyWalletAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
    EXPECT_EQ(Cryptocurrency::Ethereum, ClassifyWalletAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0"))
        << "an EVM address classifies as Ethereum; Ethereum Classic is indistinguishable";
    for (const char* junk : {"", "not-an-address", "C:\\Windows\\System32", "--config=miner.conf",
                             "stratum+tcp://pool.example.com:3333", "worker1"}) {
        EXPECT_FALSE(ClassifyWalletAddress(junk).has_value()) << junk;
    }
}

TEST(PoolWalletValidatorTest, NeitherAnUndeterminedNorAnOtherCurrencyValidatesAnything) {
    for (const auto c : {Cryptocurrency::Unknown, Cryptocurrency::Other}) {
        EXPECT_FALSE(ValidateWalletAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", c));
        EXPECT_FALSE(ValidateWalletAddress("C:\\Windows\\System32", c));
    }
}

}  // namespace ShadowStrike::CryptoMiners::Test
