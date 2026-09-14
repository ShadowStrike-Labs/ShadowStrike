/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file MiningPortAndWallet_Tests.cpp
 * @brief The two identity tests that decide whether a connection looks like cryptocurrency mining.
 *
 * IsMiningPort and ValidateWalletAddress are both allowlist-shaped, and both feed a judgement about a
 * process the user may then have killed. The dangerous direction differs between them:
 *
 *   IsMiningPort answering YES for a port that is not a mining port accuses ordinary software. The
 *   ports that matter most are the ones NOT in the list - 80, 443 and 8080 - because a mining verdict
 *   on those would fire on essentially all network activity. Those negatives are asserted first.
 *
 *   ValidateWalletAddress answering YES for something that is not a wallet manufactures evidence; the
 *   cross-currency cases matter because a Bitcoin address accepted as Monero would attribute a payout
 *   to the wrong chain in a report a user reads.
 *
 * Two entries of the port list are pinned with their collisions named rather than quietly trusted:
 * 8888 is the default Jupyter Notebook port and 5555 is Android Debug Bridge over TCP. Both are real
 * stratum ports as well, so the entries are correct - but a bare port match on either will meet
 * legitimate software, which is worth knowing before the signal is given weight on its own.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/CryptoMinersProtection/CryptoMinerDetector.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace ShadowStrike::CryptoMiners::Test {
namespace {

/// MinerConstants::STRATUM_PORTS, restated so removing one from the product fails a case here.
const std::vector<std::uint16_t>& StratumPorts() {
    static const std::vector<std::uint16_t> ports = {
        3333, 3334, 3335, 3336, 4444, 5555, 7777, 8888, 9999, 14433, 14444, 45560, 45700};
    return ports;
}

}  // namespace

// ============================================================================================
// Ports
// ============================================================================================

TEST(MiningPortTest, TheWebPortsAreNotMiningPorts) {
    // The assertion that matters most. A mining verdict on 80, 443 or 8080 would fire on ordinary
    // browsing, so these must never be classified as stratum ports however the list grows.
    EXPECT_FALSE(IsMiningPort(80)) << "HTTP would be reported as mining traffic";
    EXPECT_FALSE(IsMiningPort(443)) << "HTTPS would be reported as mining traffic";
    EXPECT_FALSE(IsMiningPort(8080)) << "the common alternate HTTP port would be reported as mining";
    EXPECT_FALSE(IsMiningPort(53)) << "DNS";
    EXPECT_FALSE(IsMiningPort(22)) << "SSH";
    EXPECT_FALSE(IsMiningPort(3389)) << "RDP";
    EXPECT_FALSE(IsMiningPort(445)) << "SMB";
}

TEST(MiningPortTest, EveryListedStratumPortIsRecognised) {
    for (const std::uint16_t port : StratumPorts()) {
        EXPECT_TRUE(IsMiningPort(port)) << port << " is in STRATUM_PORTS but was not recognised";
    }
}

TEST(MiningPortTest, PortZeroAndUnrelatedHighPortsAreNotMiningPorts) {
    EXPECT_FALSE(IsMiningPort(0));
    EXPECT_FALSE(IsMiningPort(1));
    EXPECT_FALSE(IsMiningPort(65535));
    EXPECT_FALSE(IsMiningPort(3332)) << "one below the default stratum port";
    EXPECT_FALSE(IsMiningPort(3337)) << "one above the listed stratum range";
}

TEST(MiningPortTest, TwoListedPortsCollideWithCommonLegitimateSoftware) {
    // PINNED WITH THE COLLISION NAMED. Both are genuine stratum ports, so the list is not wrong - but
    // 8888 is the default Jupyter Notebook port and 5555 is Android Debug Bridge over TCP, so a bare
    // port match on either meets software that has nothing to do with mining. Recorded here so the
    // collision is a known property rather than a surprise in the field, and so that anyone weighting
    // a port match on its own sees this first.
    EXPECT_TRUE(IsMiningPort(8888)) << "8888 also serves Jupyter Notebook by default";
    EXPECT_TRUE(IsMiningPort(5555)) << "5555 also serves Android Debug Bridge over TCP";
}

// ============================================================================================
// Wallet addresses
// ============================================================================================

TEST(WalletAddressTest, ACanonicalAddressOfItsOwnCurrencyIsAccepted) {
    // Anti-vacuity for every rejection case below. If these fail, the patterns are too strict and the
    // detector cannot recognise a real payout address at all.
    EXPECT_TRUE(ValidateWalletAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", Cryptocurrency::Bitcoin))
        << "the Bitcoin genesis address was rejected";
    EXPECT_TRUE(ValidateWalletAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
                                      Cryptocurrency::Ethereum))
        << "a well-formed 0x-prefixed 40-hex-digit address was rejected";
}

TEST(WalletAddressTest, GarbageIsRejectedForEveryCurrency) {
    const std::vector<Cryptocurrency> currencies = {
        Cryptocurrency::Bitcoin,  Cryptocurrency::Ethereum, Cryptocurrency::Monero,
        Cryptocurrency::Litecoin, Cryptocurrency::Ravencoin, Cryptocurrency::Zcash};
    for (const Cryptocurrency currency : currencies) {
        EXPECT_FALSE(ValidateWalletAddress("", currency)) << "an empty string was accepted";
        EXPECT_FALSE(ValidateWalletAddress("not-an-address", currency));
        EXPECT_FALSE(ValidateWalletAddress("hello world", currency))
            << "a string containing a space was accepted as a wallet address";
    }
}

TEST(WalletAddressTest, AnAddressIsNotAcceptedForTheWrongChain) {
    // A payout address attributed to the wrong currency is wrong evidence in a report the user reads.
    EXPECT_FALSE(ValidateWalletAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
                                       Cryptocurrency::Bitcoin))
        << "an Ethereum address was accepted as Bitcoin";
    EXPECT_FALSE(ValidateWalletAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                                       Cryptocurrency::Ethereum))
        << "a Bitcoin address was accepted as Ethereum";
}

TEST(WalletAddressTest, AnUndeterminedCurrencyValidatesNothing) {
    // The catch-all branch previously returned true for ANY string containing no whitespace, so a file
    // path and a command-line flag were both wallet addresses. A wallet address is reported to the user
    // as a miner's payout address, so accepting arbitrary tokens manufactures evidence.
    //
    // Unknown is reachable rather than theoretical: DetectCryptocurrency yields it and the result field
    // is left as Unknown when detection fails.
    for (const Cryptocurrency currency : {Cryptocurrency::Unknown, Cryptocurrency::Other}) {
        EXPECT_FALSE(ValidateWalletAddress("not-an-address", currency));
        EXPECT_FALSE(ValidateWalletAddress("hello world", currency));
        EXPECT_FALSE(ValidateWalletAddress("C:\\Windows\\System32", currency))
            << "a Windows path was accepted as a wallet address";
        EXPECT_FALSE(ValidateWalletAddress("--config=miner.conf", currency))
            << "a command-line flag was accepted as a wallet address";
        EXPECT_FALSE(ValidateWalletAddress("stratum+tcp://pool.example.com:3333", currency))
            << "a pool URL was accepted as a wallet address";
        EXPECT_FALSE(ValidateWalletAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", currency))
            << "even a real Bitcoin address must not validate under an undetermined currency - the "
               "question asked was about a currency that is not known";
    }
}

TEST(WalletAddressTest, EthereumClassicIsValidatedAsAnEvmAddress) {
    // ETC addresses are EVM addresses, identical in form to Ethereum's. Previously this currency fell
    // into the whitespace catch-all and had no validation at all.
    EXPECT_TRUE(ValidateWalletAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
                                      Cryptocurrency::EthClassic));
    EXPECT_FALSE(ValidateWalletAddress("not-an-address", Cryptocurrency::EthClassic));
    EXPECT_FALSE(ValidateWalletAddress("C:\\Windows\\System32", Cryptocurrency::EthClassic));
    EXPECT_FALSE(ValidateWalletAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
                                       Cryptocurrency::EthClassic))
        << "a 39-digit address was accepted";
}

TEST(WalletAddressTest, ErgoRejectsTheShapesTheCatchAllUsedToAccept) {
    // Deliberately a charset and length bound rather than a precise format, because Ergo has several
    // address forms - see the note in the source. What matters is that the shapes the old branch
    // accepted are now rejected.
    EXPECT_FALSE(ValidateWalletAddress("C:\\Windows\\System32\\drivers\\etc\\hosts",
                                       Cryptocurrency::Ergo))
        << "a Windows path was accepted - the backslash is not in the base58 alphabet";
    EXPECT_FALSE(ValidateWalletAddress("--config=miner.conf-and-some-padding-to-length",
                                       Cryptocurrency::Ergo))
        << "a command-line flag was accepted";
    EXPECT_FALSE(ValidateWalletAddress("stratum+tcp://pool.example.com:3333/worker1",
                                       Cryptocurrency::Ergo))
        << "a pool URL was accepted";
    EXPECT_FALSE(ValidateWalletAddress("short", Cryptocurrency::Ergo)) << "below the length bound";
}

TEST(WalletAddressTest, AnEthereumAddressMustHaveExactlyFortyHexDigits) {
    EXPECT_FALSE(ValidateWalletAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb", 
                                       Cryptocurrency::Ethereum))
        << "a 39-digit address was accepted";
    EXPECT_FALSE(ValidateWalletAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb00",
                                       Cryptocurrency::Ethereum))
        << "a 41-digit address was accepted";
    EXPECT_FALSE(ValidateWalletAddress("742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
                                       Cryptocurrency::Ethereum))
        << "an address with no 0x prefix was accepted";
    EXPECT_FALSE(ValidateWalletAddress("0xZZZd35Cc6634C0532925a3b844Bc9e7595f0bEb0",
                                       Cryptocurrency::Ethereum))
        << "an address containing non-hex characters was accepted";
}

}  // namespace ShadowStrike::CryptoMiners::Test
