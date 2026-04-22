/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file ZeroTrustPromptQueue.hpp
 * @brief Bounded asynchronous prompt queue for uncertain-verdict user prompts.
 *
 * When ZeroTrustGuard emits Verdict::Uncertain with UncertainBehavior::Prompt,
 * the execution hook enqueues a PromptEntry here and may block on WaitFor()
 * until the UI IPC layer delivers an Answer(). The queue is bounded to 64
 * pending entries; overflow evicts the oldest pending entry with Timeout.
 *
 * The queue is a standalone Meyers' singleton so it can be driven by both
 * the ZeroTrustGuard (producer) and the home-ipc-dispatcher (consumer).
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ShadowStrike::PhantomCore::RealTime::ZeroTrust {

// ============================================================================
// PROMPT ANSWER ENUMERATION
// ============================================================================

enum class PromptAnswer : std::uint8_t {
    Pending = 0,
    Allow   = 1,
    Block   = 2,
    Timeout = 3,
};

// ============================================================================
// PROMPT ENTRY
// ============================================================================

struct PromptEntry {
    std::uint64_t id                              = 0;
    std::chrono::system_clock::time_point createdAt;
    std::wstring imagePath;
    std::string  sha256;
    std::string  publisher;
    double       computedTrust                    = 0.0;
    std::string  reason;
    PromptAnswer answer                           = PromptAnswer::Pending;
};

// ============================================================================
// ZERO TRUST PROMPT QUEUE — MEYERS' SINGLETON
// ============================================================================

class [[nodiscard]] ZeroTrustPromptQueue final {
public:
    [[nodiscard]] static ZeroTrustPromptQueue& Instance();

    ZeroTrustPromptQueue(const ZeroTrustPromptQueue&)            = delete;
    ZeroTrustPromptQueue& operator=(const ZeroTrustPromptQueue&) = delete;

    /**
     * @brief Enqueue a new prompt.
     *
     * If the queue already holds kMaxPending entries whose answer is Pending,
     * the oldest such entry is auto-answered Timeout and evicted before
     * inserting the new one.
     *
     * @return Opaque monotonically-increasing ID for the new entry.
     */
    [[nodiscard]] std::uint64_t Enqueue(PromptEntry entry);

    /**
     * @brief Block until the prompt is answered or the timeout elapses.
     *
     * On timeout the entry is marked Timeout internally and Timeout is
     * returned. The caller must not assume the ID remains valid after Timeout.
     */
    [[nodiscard]] PromptAnswer WaitFor(std::uint64_t id,
                                       std::chrono::milliseconds timeout);

    /**
     * @brief Deliver an answer from the UI IPC layer.
     * @return false if no entry with the given id is found or it is already
     *         answered.
     */
    [[nodiscard]] bool Answer(std::uint64_t id, PromptAnswer answer);

    /// @brief Return all entries whose answer is Pending (for UI polling).
    [[nodiscard]] std::vector<PromptEntry> ListPending() const;

    /**
     * @brief Purge entries older than maxAge whose answer is not Pending.
     *
     * Safe to call periodically from a maintenance background thread.
     */
    void PurgeOld(std::chrono::seconds maxAge = std::chrono::seconds{60});

    /// @brief Maximum number of simultaneously pending (unanswered) prompts.
    static constexpr std::size_t kMaxPending = 64;

private:
    ZeroTrustPromptQueue();
    ~ZeroTrustPromptQueue();
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace ShadowStrike::PhantomCore::RealTime::ZeroTrust
