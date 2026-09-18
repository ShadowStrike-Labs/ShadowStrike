// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * ShadowStrike Phantom - Privacy domain and geofence identity tests
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 */

/**
 * @file PrivacyDomainAndGeofence_Tests.cpp
 * @brief Pins the DNS domain validator, the block-list key normalisation, and geofence containment.
 *
 * Three questions, all decided by code that had no test.
 *
 * IS THIS A DOMAIN. IsValidDomainName gates BlockDomain, WhitelistDomain, ResolveDomain and the blocklist
 * import, so anything it refuses cannot be blocked. It was refusing a root-terminated FQDN - the form DNS
 * uses on the wire - because the trailing dot leaves an empty final label. NormalizeDomain strips that dot,
 * and ImportBlocklist normalises before validating, so the module already accepted the form from a file
 * while refusing it from the API. The cases below pin the ordering at both sites.
 *
 * IS THIS DOMAIN BLOCKED. Six sites touch the blocked set and all six normalise the key first. That is
 * easy to break by adding a seventh, and the failure is silent: the entry is stored under a key no lookup
 * produces. The round-trip cases pin case folding and the trailing dot in both directions.
 *
 * IS THIS POINT INSIDE THE FENCE. GeofenceRegion::Contains dispatches on shape. The circle converts
 * kilometres from the haversine to metres; the polygon is ray casting; the rectangle takes min and max of
 * two opposite corners, which discards which corner was which and so cannot represent a region crossing the
 * antimeridian. That last one is pinned as it behaves today, with the filing referenced - see the comment on
 * the case itself before changing it.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <string>

#include "Products/Community/PhantomHome/Privacy/DNSLeakProtection.hpp"
#include "Products/Community/PhantomHome/Privacy/LocationPrivacy.hpp"

namespace {

using ShadowStrike::Privacy::IsValidDomainName;

// ============================================================================
// IsValidDomainName - the gate on every domain the module will act on
// ============================================================================

TEST(DnsDomainValidator, AcceptsOrdinaryNames) {
    EXPECT_TRUE(IsValidDomainName("example.com"));
    EXPECT_TRUE(IsValidDomainName("a.co"));
    EXPECT_TRUE(IsValidDomainName("sub.domain.example.co.uk"));
    EXPECT_TRUE(IsValidDomainName("xn--80ak6aa92e.com")) << "punycode is ordinary alphanumeric plus hyphen";
    EXPECT_TRUE(IsValidDomainName("EXAMPLE.COM")) << "case is not a validity question";
    EXPECT_TRUE(IsValidDomainName("my-host.example.com")) << "an interior hyphen is legal";
}

TEST(DnsDomainValidator, RejectsWhatIsNotADomain) {
    EXPECT_FALSE(IsValidDomainName("")) << "empty";
    EXPECT_FALSE(IsValidDomainName("localhost")) << "no dot, so no TLD to check";
    EXPECT_FALSE(IsValidDomainName("invalid domain with spaces"));
    EXPECT_FALSE(IsValidDomainName("example..com")) << "an empty interior label";
    EXPECT_FALSE(IsValidDomainName(".example.com")) << "an empty leading label";
    EXPECT_FALSE(IsValidDomainName("-example.com")) << "a label may not begin with a hyphen";
    EXPECT_FALSE(IsValidDomainName("example-.com")) << "a label may not end with a hyphen";
    EXPECT_FALSE(IsValidDomainName("exa_mple.com")) << "underscore is not permitted in a hostname label";
    EXPECT_FALSE(IsValidDomainName("example.c")) << "a one-character TLD";
    EXPECT_FALSE(IsValidDomainName("example.c0m")) << "a TLD must be entirely alphabetic";
    EXPECT_FALSE(IsValidDomainName("192.168.1.1")) << "an address is not a domain: the TLD is numeric";
}

TEST(DnsDomainValidator, EnforcesTheLengthBounds) {
    // 63 is the label limit and 253 the name limit. Both edges, because a bound is where the defect lives.
    const std::string label63(63, 'a');
    const std::string label64(64, 'a');
    EXPECT_TRUE(IsValidDomainName(label63 + ".com"));
    EXPECT_FALSE(IsValidDomainName(label64 + ".com"));

    // Each label contributes 9 bytes ("aaaaaaaa.") and the TLD 3, so growth stops while another label plus
    // the TLD still fits. Computed rather than hand-counted: a hand-written bound overshot to 255.
    std::string longName;
    while (longName.size() + 9 + 3 <= 253) {
        longName += "aaaaaaaa.";
    }
    longName += "com";
    ASSERT_LE(longName.size(), 253u);
    EXPECT_TRUE(IsValidDomainName(longName));

    std::string tooLong = longName;
    while (tooLong.size() <= 253) {
        tooLong = "a" + tooLong;
    }
    ASSERT_GT(tooLong.size(), 253u);
    ASSERT_LE(tooLong.find('.'), 63u) << "rejected for the name length, not a label length";
    EXPECT_FALSE(IsValidDomainName(tooLong)) << "past the 253-byte name limit";
}

TEST(DnsDomainValidator, ARootTerminatedNameHasAnEmptyFinalLabelAndIsRefused) {
    // This is WHY the validation order matters, and it is deliberately left as it is. The validator sees an
    // empty final label and refuses. Teaching it to tolerate one terminal dot would also have it accept
    // "example.com..", so the module normalises first instead - see the round-trip case below.
    EXPECT_FALSE(IsValidDomainName("example.com."))
        << "if this now passes, IsValidDomainName was taught about the root label - check that "
           "\"example.com..\" is still refused, and that BlockDomain still normalises first";
    EXPECT_FALSE(IsValidDomainName("example.com.."));
}

// ============================================================================
// The blocked-domain key - stored and queried under one canonical form
// ============================================================================

// DNSLeakProtection is a singleton - private constructor, deleted copy and move, reached through
// Instance() - so the fixture cannot hold one. Every suite in this binary shares the one object, which is
// why initialisation happens once per suite and why each case cleans up the keys it adds.
class DnsBlocklistKeyTest : public ::testing::Test {
protected:
    static ShadowStrike::Privacy::DNSLeakProtection& Dns() {
        return ShadowStrike::Privacy::DNSLeakProtection::Instance();
    }

    static void SetUpTestSuite() {
        // Initialize is not idempotent (filed 288): the second call returns false and is indistinguishable
        // from a genuine failure. State is tested rather than assumed.
        if (!Dns().IsInitialized()) {
            (void)Dns().Initialize();
        }
        ASSERT_TRUE(Dns().IsInitialized()) << "DNSLeakProtection could not be initialised";
    }
};

TEST_F(DnsBlocklistKeyTest, ABlockedDomainIsFoundRegardlessOfHowItIsSpelled) {
    ASSERT_TRUE(Dns().BlockDomain("Ads.Example.COM"));

    EXPECT_TRUE(Dns().IsDomainBlocked("ads.example.com")) << "stored lowercase";
    EXPECT_TRUE(Dns().IsDomainBlocked("Ads.Example.COM")) << "queried as written";
    EXPECT_TRUE(Dns().IsDomainBlocked("ADS.EXAMPLE.COM")) << "queried uppercase";
    EXPECT_TRUE(Dns().IsDomainBlocked("ads.example.com.")) << "queried root-terminated";

    EXPECT_TRUE(Dns().UnblockDomain("ADS.EXAMPLE.COM")) << "removal normalises the same way";
    EXPECT_FALSE(Dns().IsDomainBlocked("ads.example.com"));
}

TEST_F(DnsBlocklistKeyTest, ARootTerminatedNameCanBeBlockedBecauseValidationFollowsNormalisation) {
    // The fix. Before it, BlockDomain validated the raw argument, so this returned false while
    // ImportBlocklist accepted the identical string from a file and IsDomainBlocked answered questions
    // about it.
    ASSERT_TRUE(Dns().BlockDomain("tracker.example.net."))
        << "a root-terminated FQDN is a valid DNS name and the module canonicalises it";

    EXPECT_TRUE(Dns().IsDomainBlocked("tracker.example.net"));
    EXPECT_TRUE(Dns().IsDomainBlocked("tracker.example.net."));
    EXPECT_TRUE(Dns().UnblockDomain("tracker.example.net"));
}

TEST_F(DnsBlocklistKeyTest, NormalisingFirstDidNotWidenWhatCountsAsADomain) {
    // Anti-regression for the fix: lowercasing and stripping one trailing dot cannot rescue a bad name.
    EXPECT_FALSE(Dns().BlockDomain("")) << "empty";
    EXPECT_FALSE(Dns().BlockDomain("."))            << "one dot normalises to empty";
    EXPECT_FALSE(Dns().BlockDomain("no dots here"));
    EXPECT_FALSE(Dns().BlockDomain("example..com"));
    EXPECT_FALSE(Dns().BlockDomain("example.com..")) << "two trailing dots leave an empty label behind";
    EXPECT_FALSE(Dns().BlockDomain("-bad.example.com"));
    EXPECT_FALSE(Dns().BlockDomain("example.c0m"));
    EXPECT_FALSE(Dns().IsDomainBlocked("example..com")) << "and nothing was stored under any of those";
}

TEST_F(DnsBlocklistKeyTest, AnUnknownDomainIsNotBlocked) {
    // Non-vacuity: without this the cases above would pass against a predicate that always answers true.
    EXPECT_FALSE(Dns().IsDomainBlocked("never.blocked.example.org"));
}

// ============================================================================
// Geofence containment
// ============================================================================

using ShadowStrike::Privacy::GeofenceRegion;
using ShadowStrike::Privacy::GeofenceShape;
using ShadowStrike::Privacy::GeoLocation;

GeoLocation At(double latitude, double longitude) {
    GeoLocation location;
    location.latitude = latitude;
    location.longitude = longitude;
    return location;
}

TEST(GeofenceContainment, TheHaversineDistanceIsInKilometres) {
    // The circle branch multiplies this by 1000 before comparing with radiusMeters, so the unit is the
    // load-bearing part. One degree of latitude is about 111 km.
    const double oneDegree = At(0.0, 0.0).DistanceTo(At(1.0, 0.0));
    EXPECT_NEAR(111.19, oneDegree, 1.0) << "kilometres, not metres or radians";
    EXPECT_DOUBLE_EQ(0.0, At(51.5, -0.12).DistanceTo(At(51.5, -0.12))) << "a point is zero from itself";

    // Symmetric, and longitude degrees shrink with latitude.
    EXPECT_NEAR(At(10.0, 20.0).DistanceTo(At(30.0, 40.0)),
                At(30.0, 40.0).DistanceTo(At(10.0, 20.0)), 1e-9);
    EXPECT_LT(At(60.0, 0.0).DistanceTo(At(60.0, 1.0)), At(0.0, 0.0).DistanceTo(At(0.0, 1.0)));
}

TEST(GeofenceContainment, ACircleIsMeasuredInMetresFromItsCentre) {
    GeofenceRegion fence;
    fence.shape = GeofenceShape::Circle;
    fence.center = At(48.8584, 2.2945);
    fence.radiusMeters = 1000.0;

    EXPECT_TRUE(fence.Contains(fence.center)) << "the centre is inside";
    EXPECT_TRUE(fence.Contains(At(48.8620, 2.2945))) << "about 400 m north";
    EXPECT_FALSE(fence.Contains(At(48.8800, 2.2945))) << "about 2.4 km north";
    EXPECT_FALSE(fence.Contains(At(-48.8584, -2.2945))) << "the antipode of the centre";

    // The boundary, from the other direction: a radius large enough must admit the far point.
    fence.radiusMeters = 5000.0;
    EXPECT_TRUE(fence.Contains(At(48.8800, 2.2945)));
}

TEST(GeofenceContainment, ARectangleIsBoundedByTwoOppositeCorners) {
    GeofenceRegion fence;
    fence.shape = GeofenceShape::Rectangle;
    fence.boundaries = {At(10.0, 20.0), At(30.0, 40.0)};

    EXPECT_TRUE(fence.Contains(At(20.0, 30.0))) << "the middle";
    EXPECT_TRUE(fence.Contains(At(10.0, 20.0))) << "a corner is inside - the comparison is inclusive";
    EXPECT_TRUE(fence.Contains(At(30.0, 40.0))) << "the opposite corner";
    EXPECT_FALSE(fence.Contains(At(9.99, 30.0))) << "just south";
    EXPECT_FALSE(fence.Contains(At(20.0, 40.01))) << "just east";

    // Corner order must not matter: min and max are taken.
    GeofenceRegion reversed;
    reversed.shape = GeofenceShape::Rectangle;
    reversed.boundaries = {At(30.0, 40.0), At(10.0, 20.0)};
    EXPECT_TRUE(reversed.Contains(At(20.0, 30.0)));
}

TEST(GeofenceContainment, ARectangleCrossingTheAntimeridianCoversTheWrongHalfOfTheWorld) {
    // PINNED AS IT BEHAVES TODAY, NOT AS IT SHOULD. Taking min and max of the two corner longitudes
    // discards which corner was east, so a region from +170 to -170 - twenty degrees wide across the date
    // line - is read as the 340 degrees between them instead.
    //
    // If this case starts failing, the rectangle was taught to wrap. That is the improvement the filing
    // asks for: update the filing and this comment rather than restoring the old expectations.
    GeofenceRegion fence;
    fence.shape = GeofenceShape::Rectangle;
    fence.boundaries = {At(-10.0, 170.0), At(10.0, -170.0)};

    EXPECT_FALSE(fence.Contains(At(0.0, 175.0)))
        << "inside the intended region, currently excluded";
    EXPECT_FALSE(fence.Contains(At(0.0, -175.0)))
        << "also inside the intended region, currently excluded";
    EXPECT_TRUE(fence.Contains(At(0.0, 0.0)))
        << "the far side of the planet, currently included";
}

TEST(GeofenceContainment, APolygonUsesRayCasting) {
    GeofenceRegion fence;
    fence.shape = GeofenceShape::Polygon;
    fence.boundaries = {At(0.0, 0.0), At(0.0, 10.0), At(10.0, 10.0), At(10.0, 0.0)};

    EXPECT_TRUE(fence.Contains(At(5.0, 5.0))) << "the centre of a square";
    EXPECT_FALSE(fence.Contains(At(15.0, 5.0))) << "north of it";
    EXPECT_FALSE(fence.Contains(At(5.0, 15.0))) << "east of it";
    EXPECT_FALSE(fence.Contains(At(-5.0, -5.0))) << "outside both ways";

    // Concave, where a naive bounding-box test would answer wrongly: an L shape whose notch is empty.
    GeofenceRegion ell;
    ell.shape = GeofenceShape::Polygon;
    ell.boundaries = {At(0.0, 0.0), At(0.0, 10.0), At(4.0, 10.0),
                      At(4.0, 4.0), At(10.0, 4.0), At(10.0, 0.0)};
    EXPECT_TRUE(ell.Contains(At(2.0, 2.0))) << "in the arm";
    EXPECT_TRUE(ell.Contains(At(8.0, 2.0))) << "in the foot";
    EXPECT_FALSE(ell.Contains(At(8.0, 8.0))) << "in the notch, inside the bounding box but outside the L";
}

TEST(GeofenceContainment, ADegenerateFenceContainsNothing) {
    // Fail closed: too few points for the shape must not admit everything.
    GeofenceRegion oneCorner;
    oneCorner.shape = GeofenceShape::Rectangle;
    oneCorner.boundaries = {At(10.0, 20.0)};
    EXPECT_FALSE(oneCorner.Contains(At(10.0, 20.0))) << "a rectangle needs two corners";

    GeofenceRegion twoPointPolygon;
    twoPointPolygon.shape = GeofenceShape::Polygon;
    twoPointPolygon.boundaries = {At(0.0, 0.0), At(10.0, 10.0)};
    EXPECT_FALSE(twoPointPolygon.Contains(At(5.0, 5.0))) << "a polygon needs three vertices";

    GeofenceRegion emptyCircle;
    emptyCircle.shape = GeofenceShape::Circle;
    emptyCircle.center = At(0.0, 0.0);
    emptyCircle.radiusMeters = 0.0;
    EXPECT_TRUE(emptyCircle.Contains(At(0.0, 0.0))) << "zero distance is within a zero radius";
    EXPECT_FALSE(emptyCircle.Contains(At(0.001, 0.0)));
}

}  // namespace
