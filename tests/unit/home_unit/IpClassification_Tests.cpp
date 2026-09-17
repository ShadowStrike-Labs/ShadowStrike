/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file IpClassification_Tests.cpp
 * @brief Deciding whether an address is private, and whether it is IPv6.
 *
 * GetPublicIP sets isPrivate on an address it believes to be the machine's public address, so a
 * misclassification either records a non-routable address as the user's public IP or reports a real one as
 * internal. Both directions matter, so the ranges are asserted at their edges rather than in their middles.
 *
 * THE RANGE EDGES ARE THE POINT. A range test written as a text prefix rather than as a bit mask covers only
 * part of its range, and that is precisely the defect this file was written against: fe80::/10 fixes ten
 * bits, so it spans fe80:: to febf::, and comparing the literal text "fe80" reported fe90::, fea0:: and
 * febf:: as public.
 *
 * TWO IMPLEMENTATIONS OF THIS PREDICATE EXIST IN THE PRODUCT. ShadowStrike::Privacy::IsPrivateIP compares
 * text; ShadowStrike::IoT::IsPrivateIP delegates to an inet_pton and bit-mask version. Only the Privacy one
 * is exercised here, because including both headers would mean deciding which is canonical - and that
 * decision is filed rather than made by a test. Two behaviours where they still differ are pinned below with
 * that filing named, so the divergence cannot narrow silently.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/Privacy/IPLeakProtection.hpp"

#include <string>

namespace ShadowStrike::Privacy::IpTest {

// ============================================================================================
// IPv4 private ranges
// ============================================================================================

TEST(PrivateIpV4Test, TheRfc1918RangesArePrivate) {
    EXPECT_TRUE(IsPrivateIP("10.0.0.1"));
    EXPECT_TRUE(IsPrivateIP("10.255.255.254"));
    EXPECT_TRUE(IsPrivateIP("192.168.0.1"));
    EXPECT_TRUE(IsPrivateIP("192.168.255.254"));
    EXPECT_TRUE(IsPrivateIP("172.16.0.1"));
    EXPECT_TRUE(IsPrivateIP("172.31.255.254"));
}

TEST(PrivateIpV4Test, TheEdgesOfTheOneSevenTwoRangeAreCorrect) {
    // 172.16.0.0/12 is 172.16 through 172.31 inclusive. Both neighbours must be outside, or the range is
    // one octet too wide - and 172.32 upward is publicly routable space.
    EXPECT_FALSE(IsPrivateIP("172.15.255.254")) << "172.15 is public and was reported private";
    EXPECT_TRUE(IsPrivateIP("172.16.0.0"));
    EXPECT_TRUE(IsPrivateIP("172.31.255.255"));
    EXPECT_FALSE(IsPrivateIP("172.32.0.1")) << "172.32 is public and was reported private";
}

TEST(PrivateIpV4Test, LoopbackAndLinkLocalArePrivate) {
    EXPECT_TRUE(IsPrivateIP("127.0.0.1"));
    EXPECT_TRUE(IsPrivateIP("127.255.255.254"));
    EXPECT_TRUE(IsPrivateIP("169.254.1.1")) << "RFC 3927 link-local";
}

TEST(PrivateIpV4Test, OrdinaryPublicAddressesAreNotPrivate) {
    // Anti-vacuity: without this every assertion above would hold for a function returning true.
    EXPECT_FALSE(IsPrivateIP("8.8.8.8"));
    EXPECT_FALSE(IsPrivateIP("1.1.1.1"));
    EXPECT_FALSE(IsPrivateIP("203.0.113.1"));
    EXPECT_FALSE(IsPrivateIP("11.0.0.1")) << "adjacent to 10/8 but outside it";
    EXPECT_FALSE(IsPrivateIP("192.169.0.1")) << "adjacent to 192.168/16 but outside it";
    EXPECT_FALSE(IsPrivateIP(""));
}

// ============================================================================================
// IPv6 ranges - where the defect was
// ============================================================================================

TEST(PrivateIpV6Test, LoopbackAndUniqueLocalArePrivate) {
    EXPECT_TRUE(IsPrivateIP("::1"));
    EXPECT_TRUE(IsPrivateIP("fc00::1")) << "unique-local, low half of fc00::/7";
    EXPECT_TRUE(IsPrivateIP("fd12:3456::1")) << "unique-local, high half of fc00::/7";
    EXPECT_TRUE(IsPrivateIP("FD12:3456::1")) << "the same address in upper case";
}

TEST(PrivateIpV6Test, TheWholeLinkLocalRangeIsPrivate) {
    // The defect this file was written against. fe80::/10 fixes ten bits, so the third hex digit may be
    // 8, 9, a or b. A literal "fe80" comparison covered only the first sixteenth of the range.
    EXPECT_TRUE(IsPrivateIP("fe80::1")) << "the base of the range";
    EXPECT_TRUE(IsPrivateIP("fe90::1")) << "inside fe80::/10 and was reported public";
    EXPECT_TRUE(IsPrivateIP("fea0::1")) << "inside fe80::/10 and was reported public";
    EXPECT_TRUE(IsPrivateIP("febf:ffff::1")) << "the top of the range";
    EXPECT_TRUE(IsPrivateIP("FE90::1")) << "the same address in upper case";
}

TEST(PrivateIpV6Test, AddressesJustOutsideLinkLocalAreNotPrivate) {
    // Anti-vacuity for the case above, and the reason the fix tests four specific digits rather than
    // widening to any "fe" prefix: fe7f:: and fec0:: are outside fe80::/10.
    EXPECT_FALSE(IsPrivateIP("fe7f::1")) << "below fe80::/10 and was reported private";
    EXPECT_FALSE(IsPrivateIP("fec0::1")) << "above fe80::/10 and was reported private";
    EXPECT_FALSE(IsPrivateIP("fe00::1"));
}

TEST(PrivateIpV6Test, OrdinaryGlobalAddressesAreNotPrivate) {
    EXPECT_FALSE(IsPrivateIP("2001:4860:4860::8888")) << "a public resolver";
    EXPECT_FALSE(IsPrivateIP("2606:4700:4700::1111"));
    EXPECT_FALSE(IsPrivateIP("::"));
}

// ============================================================================================
// Behaviour pinned as measured, with the filing named
// ============================================================================================

TEST(PrivateIpV6Test, CarrierGradeNatIsNotTreatedAsPrivate) {
    // PINNED, NOT ENDORSED. 100.64.0.0/10 is RFC 6598 shared address space, used by ISPs for carrier-grade
    // NAT and not globally routable - but neither implementation in the product classifies it as private.
    //
    // Whether a CGNAT address observed as the machine's public address represents a leak is a product
    // question rather than an arithmetic one, so it is filed rather than changed. If this case now fails,
    // that decision was taken: update the filing and this case rather than reverting.
    EXPECT_FALSE(IsPrivateIP("100.64.0.1"))
        << "carrier-grade NAT is now treated as private - a deliberate decision was made, update the filing";
    EXPECT_FALSE(IsPrivateIP("100.127.255.254"));
}

TEST(PrivateIpV4Test, AMalformedAddressIsNotValidatedBeforeClassification) {
    // PINNED, NOT ENDORSED. This implementation compares text and never parses the address, so an octet
    // outside 0-255 is still classified by its prefix. The sibling implementation in IoT/IPLeakProtection
    // rejects it, because that one parses with inet_pton first.
    //
    // Filed together with the duplication. If this case now fails, the two implementations were converged -
    // which is the recommended outcome; delete this case and note it on the filing.
    EXPECT_TRUE(IsPrivateIP("10.999.999.999"))
        << "the address is now validated before classification, so the implementations may have converged";
}

// ============================================================================================
// IPv6 detection
// ============================================================================================

TEST(IpV6DetectionTest, AnAddressContainingAColonIsTreatedAsIPv6) {
    EXPECT_TRUE(IsIPv6Address("::1"));
    EXPECT_TRUE(IsIPv6Address("fe80::1"));
    EXPECT_TRUE(IsIPv6Address("2001:db8::1"));
}

TEST(IpV6DetectionTest, AnIPv4AddressIsNotIPv6) {
    EXPECT_FALSE(IsIPv6Address("192.168.1.1"));
    EXPECT_FALSE(IsIPv6Address("8.8.8.8"));
    EXPECT_FALSE(IsIPv6Address(""));
}

TEST(IpV6DetectionTest, TheTestIsAColonAndNothingMore) {
    // PINNED AS MEASURED. The predicate is a single find(':'), so anything containing a colon qualifies -
    // including a host with a port, which is a shape a caller could plausibly pass. Recorded so the
    // looseness is a known property rather than a surprise, and so a caller knows to strip a port first.
    EXPECT_TRUE(IsIPv6Address("example.com:8080"))
        << "a host:port is no longer reported as IPv6, so the predicate was tightened - good, but check "
           "callers that relied on the loose behaviour";
    EXPECT_TRUE(IsIPv6Address("not:an:address"));
}

}  // namespace ShadowStrike::Privacy::IpTest
