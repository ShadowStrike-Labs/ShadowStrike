/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file BrowserHttpsPredicate_Tests.cpp
 * @brief Whether a URL is carried over TLS - the predicate a transport judgement rests on.
 *
 * IsHTTPS is one line, and it is the correct one line: it lowercases the URL and requires "https://"
 * at position zero. The near-misses are what make it worth pinning, because the tempting shorter
 * spellings are all wrong in the same direction - they answer YES for a plaintext URL:
 *
 *     url.find("https") != npos        yes for http://https.evil.com
 *     url.find("https") == 0           yes for https-evil.com/  (no scheme at all)
 *     url.starts_with("https://")      no for HTTPS://EXAMPLE.COM, which is a valid URL
 *
 * Every one of those turns a plaintext page into a secure one, which is the direction that matters: a
 * caller asking this question is deciding whether the transport can be trusted. So the cases below are
 * weighted towards inputs that must NOT be HTTPS, and each names the wrong implementation it rules out.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/WebProtection/BrowserProtection.hpp"

#include <string>

namespace ShadowStrike::WebBrowser::Test {
namespace {

TEST(BrowserHttpsPredicateTest, APlainHttpsUrlIsHttps) {
    EXPECT_TRUE(IsHTTPS("https://example.com"));
    EXPECT_TRUE(IsHTTPS("https://example.com/path?q=1#frag"));
    EXPECT_TRUE(IsHTTPS("https://user:pass@example.com:8443/path"));
}

TEST(BrowserHttpsPredicateTest, TheSchemeIsMatchedWithoutRegardToCase) {
    // A scheme is case-insensitive per RFC 3986, and browsers accept these. A starts_with against a
    // lower-case literal would answer no.
    EXPECT_TRUE(IsHTTPS("HTTPS://EXAMPLE.COM"));
    EXPECT_TRUE(IsHTTPS("HtTpS://example.com"));
}

TEST(BrowserHttpsPredicateTest, PlainHttpIsNotHttps) {
    EXPECT_FALSE(IsHTTPS("http://example.com"));
    EXPECT_FALSE(IsHTTPS("HTTP://EXAMPLE.COM"));
}

TEST(BrowserHttpsPredicateTest, AHostNamedAfterTheSchemeIsNotHttps) {
    // Rules out find("https") != npos. A plaintext page on a host containing the word must not be
    // reported as secure - and this is a shape an attacker chooses deliberately.
    EXPECT_FALSE(IsHTTPS("http://https.evil.com"))
        << "a plaintext URL was reported as HTTPS because its HOST contains the scheme name";
    EXPECT_FALSE(IsHTTPS("http://example.com/https://inner"))
        << "a plaintext URL was reported as HTTPS because its PATH contains the scheme";
    EXPECT_FALSE(IsHTTPS("http://example.com/?next=https://elsewhere"))
        << "a plaintext URL was reported as HTTPS because a QUERY VALUE contains the scheme";
}

TEST(BrowserHttpsPredicateTest, TheSeparatorIsRequired) {
    // Rules out find("https") == 0. Without the "://" a bare host that merely begins with the letters
    // would qualify, and there is no transport at all here.
    EXPECT_FALSE(IsHTTPS("https-evil.com/login"))
        << "a scheme-less host beginning with the letters was reported as HTTPS";
    EXPECT_FALSE(IsHTTPS("httpsx://example.com"));
    EXPECT_FALSE(IsHTTPS("https:/example.com")) << "one slash short of a scheme separator";
    EXPECT_FALSE(IsHTTPS("https"));
}

TEST(BrowserHttpsPredicateTest, TheSchemeMustStartTheUrl) {
    EXPECT_FALSE(IsHTTPS(" https://example.com"))
        << "a leading space made the scheme start at position one, and it was still accepted";
    EXPECT_FALSE(IsHTTPS("\thttps://example.com"));
}

TEST(BrowserHttpsPredicateTest, AnEmptyOrSchemelessUrlIsNotHttps) {
    EXPECT_FALSE(IsHTTPS(""));
    EXPECT_FALSE(IsHTTPS("example.com"));
    EXPECT_FALSE(IsHTTPS("//example.com")) << "a protocol-relative URL has no scheme of its own";
    EXPECT_FALSE(IsHTTPS("ftp://example.com"));
    EXPECT_FALSE(IsHTTPS("file:///C:/secret.txt"));
    EXPECT_FALSE(IsHTTPS("wss://example.com")) << "secure, but not HTTPS";
}

}  // namespace
}  // namespace ShadowStrike::WebBrowser::Test
