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
 * WHAT THESE CASES DELIBERATELY DO NOT DO: they never resolve a prompt with AlwaysAllow or
 * AlwaysBlock. Those decisions are permanent - there is no API on the class and no IPC verb that
 * removes an entry from the always-allow or always-deny sets, and the allow decision is persisted
 * to ConfigManager for signed binaries. A test that granted one would leave state behind for every
 * later test in the process and possibly on disk. That missing revocation path is filed as its own
 * defect; until it exists, the always-* arms are not safely testable and saying so is more honest
 * than polluting the suite to reach them.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/ZeroTrustGuard/ZeroTrustPromptQueue.hpp"

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

}  // namespace
}  // namespace ShadowStrike::Products::Home::ZeroTrust::Test
