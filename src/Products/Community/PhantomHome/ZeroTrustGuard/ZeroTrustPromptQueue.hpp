/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file ZeroTrustPromptQueue.hpp
 * @brief PhantomHome-facing bounded prompt queue for uncertain-verdict user prompts.
 *
 * ROLE:
 * =====
 * When ZeroTrustGuard::Evaluate() returns ZeroTrustDecision::Uncertain with
 * ZeroTrustUncertainBehavior::Prompt, the process-execution hook enqueues a
 * ZeroTrustPromptItem here. The PhantomHome UI service thread calls
 * DequeueBlocking() to pick up items and present decision dialogs to the user.
 * Resolve() delivers the user's choice back into the queue.
 *
 * LIFETIME MANAGEMENT:
 * ====================
 * Items expire after 60 seconds. Every mutating operation (Enqueue, Resolve,
 * DequeueBlocking, Snapshot) performs a cheap sweep to prune expired items
 * before acting on the queue. This prevents unbounded growth in pathological
 * cases.
 *
 * ALWAYS-ALLOW / ALWAYS-DENY:
 * ============================
 * UserChoice::AlwaysAllow and UserChoice::AlwaysBlock register the image path
 * and publisher subject into persistent or in-memory caches that are checked
 * by ZeroTrustGuard::Evaluate() before the scored path. AlwaysAllow is
 * persisted to ConfigManager; AlwaysBlock is held in an in-memory deny-cache
 * owned by this queue (caller is responsible for persistence if needed).
 *
 * THREAD SAFETY:
 * ==============
 * All public methods are fully thread-safe. std::mutex + condition_variable_any
 * is used (not shared_mutex) because the queue modifies state on every read.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::Home::ZeroTrust {

// ============================================================================
// PROMPT ITEM
// ============================================================================

/**
 * @brief A single pending user-decision prompt.
 *
 * Represents one uncertain process-launch event that could not be resolved
 * automatically by the configured UncertainBehavior policy.
 */
struct ZeroTrustPromptItem {
    /// @brief Monotonically increasing, unique within this process lifetime.
    std::uint64_t id = 0;

    /// @brief Full image path of the process awaiting a verdict.
    std::wstring imagePath;

    /// @brief Authenticode publisher subject (empty if unsigned).
    std::wstring publisherSubject;

    /// @brief Windows session the process runs in (for UI session routing).
    std::uint32_t processSessionId = 0;

    /// @brief Blended trust score that fell in the uncertain band [0.0, 1.0].
    double score = 0.0;

    /// @brief When the prompt was created. Used for 60-second expiry pruning.
    std::chrono::system_clock::time_point createdAt;
};

// ============================================================================
// PROMPT QUEUE — MEYERS' SINGLETON
// ============================================================================

/**
 * @class ZeroTrustPromptQueue
 * @brief Bounded FIFO queue for zero-trust prompt delivery to the PhantomHome UI.
 *
 * Capacity: kMaxCapacity (64). When the cap is reached, the oldest item is
 * silently evicted before the new one is inserted.
 *
 * Retention: 60 seconds. Items older than this are pruned automatically.
 */
class ZeroTrustPromptQueue final {
public:
    /// @brief Maximum simultaneous pending prompts.
    static constexpr std::size_t kMaxCapacity = 64;

    /// @brief Prompt retention period before automatic expiry.
    static constexpr std::chrono::seconds kRetentionPeriod{60};

    /// @brief Meyers' singleton accessor.
    [[nodiscard]] static ZeroTrustPromptQueue& Instance();

    ZeroTrustPromptQueue(const ZeroTrustPromptQueue&)            = delete;
    ZeroTrustPromptQueue& operator=(const ZeroTrustPromptQueue&) = delete;

    // ---- Producer side (called by ZeroTrustGuard) --------------------------

    /**
     * @brief Enqueue a new prompt item.
     *
     * If the queue is at kMaxCapacity, the oldest item is evicted first.
     * Expired items are pruned before checking capacity.
     *
     * @return The assigned monotonic ID (>0), or 0 if the item was dropped
     *         because the queue is full after eviction and the item itself
     *         already expired before insertion.
     */
    [[nodiscard]] std::uint64_t Enqueue(ZeroTrustPromptItem&& item);

    /**
     * @brief Attach a Windows session ID to a previously enqueued item.
     *
     * Used by the PhantomHome adapter to enrich bridge-created prompt items
     * (whose PhantomCore source lacks the session field) with the session id
     * captured at the PhantomHome Evaluate() call site. Idempotent.
     *
     * @return true if the item was found and updated; false if the id is no
     *         longer present (evicted/expired/resolved).
     */
    bool SetProcessSessionId(std::uint64_t id, std::uint32_t sessionId);

    // ---- Consumer side (called by the UI service thread) -------------------

    /**
     * @brief Block until an item is available, the stop token fires, or 60s
     *        retention sweeps remove all pending items.
     *
     * Returns the oldest item that has not yet been resolved and is not
     * expired. If the queue becomes empty (all items expired or resolved),
     * waits for the next Enqueue.
     *
     * Returns nullopt when the stop_token is signalled or Stop() is called.
     */
    [[nodiscard]] std::optional<ZeroTrustPromptItem> DequeueBlocking(std::stop_token st);

    // ---- Resolution --------------------------------------------------------

    /**
     * @brief Deliver a user decision for the given prompt ID.
     *
     * UserChoice mapping:
     *   Allow       → remove from queue; allow this execution.
     *   Block       → remove from queue; block this execution.
     *   AlwaysAllow → remove from queue; persist path to always-allow set;
     *                 future Evaluate() calls with this path return Allow
     *                 without scoring.
     *   AlwaysBlock → remove from queue; add path to in-memory deny cache;
     *                 future Evaluate() calls with this path return Block
     *                 without scoring.
     *
     * @return true if the item was found and resolved.
     *         false if no item with the given id exists (logs WARN).
     */
    enum class UserChoice : std::uint8_t {
        Allow       = 0,
        Block       = 1,
        AlwaysAllow = 2,
        AlwaysBlock = 3,
    };

    [[nodiscard]] bool Resolve(std::uint64_t id, UserChoice choice);

    // ---- UI polling --------------------------------------------------------

    /**
     * @brief Return a snapshot of all non-expired items for UI binding.
     *
     * Does NOT remove items from the queue. Prunes expired items as a side
     * effect before building the snapshot.
     */
    [[nodiscard]] std::vector<ZeroTrustPromptItem> Snapshot() const;

    // ---- Always-allow / always-deny queries (called by ZeroTrustGuard) -----

    /**
     * @brief Check whether the given image path or publisher subject is in
     *        the always-allow set (added by AlwaysAllow resolution).
     */
    [[nodiscard]] bool IsAlwaysAllowed(std::wstring_view imagePath,
                                       std::wstring_view publisherSubject) const;

    /**
     * @brief Check whether the given image path is in the in-memory deny
     *        cache (added by AlwaysBlock resolution).
     */
    [[nodiscard]] bool IsAlwaysDenied(std::wstring_view imagePath) const;

    // ---- Lifecycle ---------------------------------------------------------

    /**
     * @brief Load persisted always-allow entries from ConfigManager.
     *        Must be called once at service startup before Evaluate() is used.
     */
    void LoadPersistedAllowList();

    /**
     * @brief Signal all DequeueBlocking callers to return nullopt.
     *
     * Idempotent. Called during service shutdown so UI threads can exit
     * cleanly without needing an externally signalled stop_token.
     */
    void Stop();

private:
    ZeroTrustPromptQueue();
    ~ZeroTrustPromptQueue();

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace ShadowStrike::Products::Home::ZeroTrust
