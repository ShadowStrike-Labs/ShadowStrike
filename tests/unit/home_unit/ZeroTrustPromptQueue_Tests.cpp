/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file ZeroTrustPromptQueue_Tests.cpp
 * @brief The prompt queue's identity, its capacity policy, and what it refuses.
 *
 * The header documents a capacity of 64 with the oldest item silently evicted when the cap is
 * reached. That policy is the difference between a bounded queue and unbounded growth driven by
 * process launches, so it is asserted rather than trusted.
 *
 * STANDING DECISIONS (task 269). AlwaysAllow and AlwaysBlock used to be permanent: nothing could
 * remove one, and AlwaysBlock was forgotten at restart while AlwaysAllow survived. Both can now be
 * listed and revoked, AlwaysBlock is persisted, and every case that grants one revokes it, so no
 * state outlives the test.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/ZeroTrustGuard/ZeroTrustPromptQueue.hpp"
#include "PhantomCore/Config/ConfigManager.hpp"

#include <chrono>
#include <set>
#include <string>

namespace ShadowStrike::Products::Home::ZeroTrust::Test {
namespace {

[[nodiscard]] ZeroTrustPromptItem MakeItem(const std::wstring& path, double score = 0.5) {
    ZeroTrustPromptItem item;
    item.imagePath = path;
    item.publisherSubject = L"";
    item.processSessionId = 1;
    item.score = score;
    item.createdAt = std::chrono::system_clock::now();
    return item;
}

class ZeroTrustPromptQueueTest : public ::testing::Test {
protected:
    ZeroTrustPromptQueue& queue = ZeroTrustPromptQueue::Instance();
};

TEST_F(ZeroTrustPromptQueueTest, AnEnqueuedItemGetsANonZeroIdentity) {
    // Zero is the sentinel for "no item" on the ZeroTrustPromptItem default, so a real id must
    // never be zero or a caller cannot tell success from failure.
    const auto id = queue.Enqueue(MakeItem(L"C:\\test\\identity-probe.exe"));
    EXPECT_NE(0u, id);
}

TEST_F(ZeroTrustPromptQueueTest, EachEnqueueGetsADistinctIdentity) {
    // Two prompts sharing an id would let a user's answer to one resolve the other.
    std::set<std::uint64_t> ids;
    for (int i = 0; i < 8; ++i) {
        const auto id = queue.Enqueue(MakeItem(L"C:\\test\\distinct.exe", 0.1 * i));
        EXPECT_TRUE(ids.insert(id).second) << "duplicate prompt id " << id;
    }
}

TEST_F(ZeroTrustPromptQueueTest, AnEnqueuedItemIsVisibleInTheSnapshot) {
    const std::wstring path = L"C:\\test\\snapshot-probe.exe";
    const auto id = queue.Enqueue(MakeItem(path));

    bool found = false;
    for (const auto& item : queue.Snapshot()) {
        if (item.id == id) {
            found = true;
            EXPECT_EQ(path, item.imagePath);
            break;
        }
    }
    EXPECT_TRUE(found) << "an enqueued prompt is not visible to the UI snapshot";
}

TEST_F(ZeroTrustPromptQueueTest, TheQueueIsBoundedByItsDocumentedCapacity) {
    // The header documents a cap of 64 with the oldest silently evicted. Without the cap, a burst
    // of process launches grows this queue without limit.
    for (int i = 0; i < 96; ++i) {
        (void)queue.Enqueue(MakeItem(L"C:\\test\\capacity-probe.exe", 0.01 * i));
    }
    EXPECT_LE(queue.Snapshot().size(), 64u)
        << "the prompt queue exceeded its documented capacity of 64, so process launches can grow "
           "it without bound";
}

TEST_F(ZeroTrustPromptQueueTest, ResolvingAnUnknownIdentityFails) {
    // A stale UI answer must not report success, or the caller believes a prompt was handled.
    EXPECT_FALSE(queue.Resolve(0, ZeroTrustPromptQueue::UserChoice::Allow));
    EXPECT_FALSE(queue.Resolve(0xFFFFFFFFFFFFFFFFull, ZeroTrustPromptQueue::UserChoice::Allow));
}

TEST_F(ZeroTrustPromptQueueTest, ResolvingRemovesThePromptFromTheSnapshot) {
    // Allow and Block are the non-persistent choices, so they are safe to exercise.
    const auto id = queue.Enqueue(MakeItem(L"C:\\test\\resolve-probe.exe"));
    EXPECT_TRUE(queue.Resolve(id, ZeroTrustPromptQueue::UserChoice::Allow));

    for (const auto& item : queue.Snapshot()) {
        EXPECT_NE(id, item.id) << "a resolved prompt is still queued, so the UI would show it again";
    }
    EXPECT_FALSE(queue.Resolve(id, ZeroTrustPromptQueue::UserChoice::Allow))
        << "the same prompt was resolved twice, so one user answer can be replayed";
}

TEST_F(ZeroTrustPromptQueueTest, APathThatWasNeverAllowedIsNotAlwaysAllowed) {
    // Anti-vacuity in the safe direction: proves the always-allow lookup does not answer true for
    // arbitrary input, without granting anything.
    EXPECT_FALSE(queue.IsAlwaysAllowed(L"C:\\test\\never-granted.exe", L""));
    EXPECT_FALSE(queue.IsAlwaysDenied(L"C:\\test\\never-denied.exe"));
    EXPECT_FALSE(queue.IsAlwaysAllowed(L"", L""));
}

TEST_F(ZeroTrustPromptQueueTest, SettingTheSessionOfAnUnknownPromptFails) {
    EXPECT_FALSE(queue.SetProcessSessionId(0, 1));
    EXPECT_FALSE(queue.SetProcessSessionId(0xFFFFFFFFFFFFFFFFull, 1));
}

TEST_F(ZeroTrustPromptQueueTest, TheSessionOfAQueuedPromptCanBeSet) {
    const auto id = queue.Enqueue(MakeItem(L"C:\\test\\session-probe.exe"));
    EXPECT_TRUE(queue.SetProcessSessionId(id, 7))
        << "the session id captured at the Evaluate call site could not be attached to its prompt";
    (void)queue.Resolve(id, ZeroTrustPromptQueue::UserChoice::Allow);
}

using DK = ZeroTrustPromptQueue::DecisionKind;

[[nodiscard]] bool Lists(const ZeroTrustPromptQueue& q, DK kind, const std::wstring& subject) {
    for (const auto& d : q.StandingDecisions()) {
        if (d.kind == kind && d.subject == subject) return true;
    }
    return false;
}

/// The persisted always-block entry for `path`, read back from configuration.
[[nodiscard]] bool DenyIsPersisted(const std::wstring& path) {
    auto& cfg = ::ShadowStrike::Config::ConfigManager::Instance();
    const std::string want(path.begin(), path.end());   // ASCII test paths
    for (const auto& [key, value] : cfg.GetAllValues(::ShadowStrike::Config::ConfigLayer::User)) {
        const auto* text = std::get_if<std::string>(&value);
        if (text && *text == want && key.rfind("Home/ZeroTrust/AlwaysDeny/", 0) == 0) return true;
    }
    return false;
}

TEST_F(ZeroTrustPromptQueueTest, AnAlwaysBlockIsPersistedListedAndRevocable) {
    (void)::ShadowStrike::Config::ConfigManager::Instance();
    const std::wstring path = L"C:\\test\\zt-always-block-probe.exe";
    const auto id = queue.Enqueue(MakeItem(path));
    ASSERT_NE(0u, id);
    ASSERT_TRUE(queue.Resolve(id, ZeroTrustPromptQueue::UserChoice::AlwaysBlock));

    EXPECT_TRUE(queue.IsAlwaysDenied(path));
    EXPECT_TRUE(Lists(queue, DK::DenyPath, path));
    EXPECT_TRUE(DenyIsPersisted(path)) << "an always-block was forgotten at restart";

    EXPECT_TRUE(queue.Revoke(DK::DenyPath, path));
    EXPECT_FALSE(queue.IsAlwaysDenied(path));
    EXPECT_FALSE(Lists(queue, DK::DenyPath, path));
    EXPECT_FALSE(DenyIsPersisted(path)) << "a revoked block would return at the next start";
    EXPECT_FALSE(queue.Revoke(DK::DenyPath, path)) << "revoking twice reports a decision that is gone";
}

TEST_F(ZeroTrustPromptQueueTest, APersistedBlockIsRestoredAtStartAndRevokedEverywhere) {
    auto& cfg = ::ShadowStrike::Config::ConfigManager::Instance();
    const std::wstring path = L"C:\\test\\zt-restart-probe.exe";
    // An entry written by an earlier run, under a key name this run would not compute.
    ASSERT_TRUE(cfg.SetValue<std::string>("Home/ZeroTrust/AlwaysDeny/0000000000000000_path",
                                          "C:\\test\\zt-restart-probe.exe"));
    queue.LoadPersistedDecisions();
    EXPECT_TRUE(queue.IsAlwaysDenied(path)) << "a persisted always-block was not restored";

    EXPECT_TRUE(queue.Revoke(DK::DenyPath, path));
    EXPECT_FALSE(DenyIsPersisted(path)) << "an entry under another key name survived revocation";
    queue.LoadPersistedDecisions();
    EXPECT_FALSE(queue.IsAlwaysDenied(path));
}

TEST_F(ZeroTrustPromptQueueTest, AnAlwaysAllowCanBeRevoked) {
    // Unsigned, so session-only by design: nothing persisted, but it must still be undoable.
    const std::wstring path = L"C:\\test\\zt-always-allow-probe.exe";
    const auto id = queue.Enqueue(MakeItem(path));
    ASSERT_TRUE(queue.Resolve(id, ZeroTrustPromptQueue::UserChoice::AlwaysAllow));
    EXPECT_TRUE(queue.IsAlwaysAllowed(path, L""));
    EXPECT_TRUE(Lists(queue, DK::AllowPath, path));

    EXPECT_TRUE(queue.Revoke(DK::AllowPath, path));
    EXPECT_FALSE(queue.IsAlwaysAllowed(path, L""));
    EXPECT_FALSE(queue.Revoke(DK::AllowPublisher, path)) << "a path is not a publisher";
    EXPECT_FALSE(queue.Revoke(DK::AllowPath, L""));
}

}  // namespace
}  // namespace ShadowStrike::Products::Home::ZeroTrust::Test
