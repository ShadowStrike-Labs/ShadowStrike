/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file ZeroTrustPromptQueue.cpp
 * @brief Implementation of the PhantomHome ZeroTrust prompt queue and the
 *        concrete body of the PhantomCore ZeroTrustPromptQueue singleton.
 *
 * TWO CLASSES ARE IMPLEMENTED HERE:
 * ===================================
 * 1. ShadowStrike::PhantomCore::RealTime::ZeroTrust::ZeroTrustPromptQueue
 *    - The backend used by PhantomCore::ZeroTrustGuard::Decide() for its
 *      internal Uncertain+Prompt flow (Enqueue/WaitFor/Answer/ListPending).
 *    - Implemented in the PhantomHome layer because it requires UI-layer
 *      semantics (bridging to the product queue) and depends on service
 *      infrastructure not available inside PhantomCore.
 *
 * 2. ShadowStrike::Products::Home::ZeroTrust::ZeroTrustPromptQueue
 *    - The PhantomHome-facing UI queue surfaced to service threads and the
 *      UI IPC layer. Provides DequeueBlocking (stop_token), Resolve
 *      (UserChoice), Snapshot, AlwaysAllow/AlwaysBlock caches, and Stop().
 *
 * DESIGN NOTES:
 * =============
 * - The PhantomHome queue is the authoritative store. The PhantomCore queue
 *   bridges into it by converting PromptEntry → ZeroTrustPromptItem.
 * - AlwaysAllow entries are persisted to ConfigManager under
 *   "Home/ZeroTrust/AlwaysAllow/" keys so they survive service restarts.
 * - AlwaysBlock entries are in-memory only (per specification).
 * - Capacity: 64. Retention: 60 s. Pruned on every mutating call.
 */

#include "ZeroTrustPromptQueue.hpp"
#include "ZeroTrustGuard.hpp"

#include "../../../../PhantomCore/Config/ConfigManager.hpp"
#include "../../../../PhantomCore/Utils/Logger.hpp"
#include "../../../../PhantomCore/RealTime/ZeroTrust/ZeroTrustPromptQueue.hpp"

#ifndef NOMINMAX
#  define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

// ============================================================================
// SHARED CONFIG KEY PREFIX FOR ALWAYS-ALLOW PERSISTENCE
// ============================================================================
namespace {
constexpr const char*    kAllowKeyPrefix  = "Home/ZeroTrust/AlwaysAllow/";
constexpr const wchar_t* kLogCat          = L"ZeroTrustPromptQueue.Home";
constexpr const wchar_t* kLogCatCore      = L"ZeroTrustPromptQueue.Core";
}

// ============================================================================
// ─── PART 1: PhantomCore::ZeroTrustPromptQueue implementation ───────────────
// ============================================================================

namespace ShadowStrike::PhantomCore::RealTime::ZeroTrust {

// Forward-declared from PhantomHome queue (defined below).
// Bridges PromptEntry → ZeroTrustPromptItem and enqueues to the Home queue.
static std::uint64_t BridgeEnqueueToHomeQueue(PromptEntry entry);

// ──────────────────────────────────────────────────────────────────────────────

struct ZeroTrustPromptQueue::Impl {
    mutable std::mutex           m_mutex;
    std::condition_variable      m_cv;
    std::deque<PromptEntry>      m_queue;
    std::atomic<std::uint64_t>   m_nextId{1};

    Impl()  = default;
    ~Impl() = default;

    Impl(const Impl&)            = delete;
    Impl& operator=(const Impl&) = delete;
};

// ──────────────────────────────────────────────────────────────────────────────

ZeroTrustPromptQueue& ZeroTrustPromptQueue::Instance() {
    static ZeroTrustPromptQueue s_instance;
    return s_instance;
}

ZeroTrustPromptQueue::ZeroTrustPromptQueue()
    : m_impl(std::make_unique<Impl>())
{}

ZeroTrustPromptQueue::~ZeroTrustPromptQueue() = default;

// ──────────────────────────────────────────────────────────────────────────────

std::uint64_t ZeroTrustPromptQueue::Enqueue(PromptEntry entry) {
    const std::uint64_t id = m_impl->m_nextId.fetch_add(1, std::memory_order_relaxed);
    entry.id = id;
    entry.answer = PromptAnswer::Pending;
    if (entry.createdAt == std::chrono::system_clock::time_point{}) {
        entry.createdAt = std::chrono::system_clock::now();
    }

    // Bridge to the PhantomHome UI queue.
    BridgeEnqueueToHomeQueue(entry);

    {
        std::scoped_lock lock(m_impl->m_mutex);

        // Evict oldest pending entry if at capacity.
        if (m_impl->m_queue.size() >= kMaxPending) {
            m_impl->m_queue.pop_front();
        }

        m_impl->m_queue.push_back(std::move(entry));
    }

    m_impl->m_cv.notify_all();
    return id;
}

PromptAnswer ZeroTrustPromptQueue::WaitFor(std::uint64_t id,
                                            std::chrono::milliseconds timeout)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;

    std::unique_lock lock(m_impl->m_mutex);
    while (true) {
        bool found = false;
        for (auto& e : m_impl->m_queue) {
            if (e.id == id) {
                found = true;
                if (e.answer != PromptAnswer::Pending) {
                    return e.answer;
                }
                break;
            }
        }

        if (!found) {
            return PromptAnswer::Timeout;
        }

        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            // Mark as Timeout in the queue so Answer() ignores it.
            for (auto& e : m_impl->m_queue) {
                if (e.id == id && e.answer == PromptAnswer::Pending) {
                    e.answer = PromptAnswer::Timeout;
                }
            }
            return PromptAnswer::Timeout;
        }

        const auto remaining = deadline - now;
        m_impl->m_cv.wait_for(lock, remaining);
    }
}

bool ZeroTrustPromptQueue::Answer(std::uint64_t id, PromptAnswer answer) {
    {
        std::scoped_lock lock(m_impl->m_mutex);
        for (auto& e : m_impl->m_queue) {
            if (e.id == id) {
                if (e.answer != PromptAnswer::Pending) {
                    return false; // Already answered.
                }
                e.answer = answer;
                m_impl->m_cv.notify_all();
                return true;
            }
        }
    }

    SS_LOG_WARN(kLogCatCore,
        L"ZeroTrustPromptQueue.Core: Answer(%llu) — id not found",
        static_cast<unsigned long long>(id));
    return false;
}

std::vector<PromptEntry> ZeroTrustPromptQueue::ListPending() const {
    std::scoped_lock lock(m_impl->m_mutex);
    std::vector<PromptEntry> out;
    for (const auto& e : m_impl->m_queue) {
        if (e.answer == PromptAnswer::Pending) {
            out.push_back(e);
        }
    }
    return out;
}

void ZeroTrustPromptQueue::PurgeOld(std::chrono::seconds maxAge) {
    const auto cutoff = std::chrono::system_clock::now() - maxAge;
    std::scoped_lock lock(m_impl->m_mutex);
    auto it = m_impl->m_queue.begin();
    while (it != m_impl->m_queue.end()) {
        if (it->createdAt < cutoff && it->answer != PromptAnswer::Pending) {
            it = m_impl->m_queue.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace ShadowStrike::PhantomCore::RealTime::ZeroTrust

// ============================================================================
// ─── PART 2: PhantomHome::ZeroTrustPromptQueue implementation ───────────────
// ============================================================================

namespace ShadowStrike::Products::Home::ZeroTrust {

// ──────────────────────────────────────────────────────────────────────────────

struct ZeroTrustPromptQueue::Impl {
    mutable std::mutex              m_mutex;
    std::condition_variable_any     m_cv;
    std::deque<ZeroTrustPromptItem> m_queue;
    std::atomic<std::uint64_t>      m_nextId{1};
    bool                            m_stopped{false};

    // Always-allow: paths/publishers persisted to ConfigManager.
    std::unordered_set<std::wstring> m_alwaysAllowPaths;
    std::unordered_set<std::wstring> m_alwaysAllowPublishers;

    // Always-deny: in-memory only (per spec).
    std::unordered_set<std::wstring> m_alwaysDenyPaths;

    Impl()  = default;
    ~Impl() = default;

    Impl(const Impl&)            = delete;
    Impl& operator=(const Impl&) = delete;

    /// @brief Remove items older than kRetentionPeriod. Must be called with m_mutex held.
    void PruneExpiredLocked() {
        const auto cutoff = std::chrono::system_clock::now() - kRetentionPeriod;
        auto it = m_queue.begin();
        while (it != m_queue.end()) {
            if (it->createdAt < cutoff) {
                it = m_queue.erase(it);
            } else {
                ++it;
            }
        }
    }
};

// ──────────────────────────────────────────────────────────────────────────────

ZeroTrustPromptQueue& ZeroTrustPromptQueue::Instance() {
    static ZeroTrustPromptQueue s_instance;
    return s_instance;
}

ZeroTrustPromptQueue::ZeroTrustPromptQueue()
    : m_impl(std::make_unique<Impl>())
{}

ZeroTrustPromptQueue::~ZeroTrustPromptQueue() {
    Stop();
}

// ──────────────────────────────────────────────────────────────────────────────

std::uint64_t ZeroTrustPromptQueue::Enqueue(ZeroTrustPromptItem&& item) {
    // If the item already carries a Core-assigned ID (bridge path), preserve it.
    // Otherwise generate a fresh monotonic ID.
    if (item.id == 0) {
        item.id = m_impl->m_nextId.fetch_add(1, std::memory_order_relaxed);
    }
    if (item.createdAt == std::chrono::system_clock::time_point{}) {
        item.createdAt = std::chrono::system_clock::now();
    }

    // Capture ID before the move so we can return it after push_back.
    const std::uint64_t assignedId = item.id;

    // Validate that the item is not already expired before inserting.
    const auto now = std::chrono::system_clock::now();
    if (item.createdAt + kRetentionPeriod <= now) {
        SS_LOG_WARN(kLogCat,
            L"ZeroTrustPromptQueue.Home: Enqueue() — item already expired; dropped");
        return 0;
    }

    {
        std::scoped_lock lock(m_impl->m_mutex);

        m_impl->PruneExpiredLocked();

        // If still at capacity, evict the oldest item.
        if (m_impl->m_queue.size() >= kMaxCapacity) {
            SS_LOG_WARN(kLogCat,
                L"ZeroTrustPromptQueue.Home: Queue full (cap=%zu); "
                L"evicting oldest item id=%llu",
                kMaxCapacity,
                static_cast<unsigned long long>(m_impl->m_queue.front().id));
            m_impl->m_queue.pop_front();
        }

        m_impl->m_queue.push_back(std::move(item));
    }

    m_impl->m_cv.notify_all();
    return assignedId;
}

// ──────────────────────────────────────────────────────────────────────────────

std::optional<ZeroTrustPromptItem>
ZeroTrustPromptQueue::DequeueBlocking(std::stop_token st) {
    std::unique_lock lock(m_impl->m_mutex);

    while (true) {
        if (m_impl->m_stopped || st.stop_requested()) {
            return std::nullopt;
        }

        m_impl->PruneExpiredLocked();

        if (!m_impl->m_queue.empty()) {
            ZeroTrustPromptItem item = std::move(m_impl->m_queue.front());
            m_impl->m_queue.pop_front();
            return item;
        }

        // Wait for either a new item, a stop signal, or a retention sweep.
        m_impl->m_cv.wait(lock, st, [this]() noexcept {
            return m_impl->m_stopped || !m_impl->m_queue.empty();
        });
    }
}

// ──────────────────────────────────────────────────────────────────────────────

bool ZeroTrustPromptQueue::Resolve(std::uint64_t id, UserChoice choice) {
    std::wstring imagePath;
    std::wstring publisherSubject;

    {
        std::scoped_lock lock(m_impl->m_mutex);
        m_impl->PruneExpiredLocked();

        auto it = std::find_if(m_impl->m_queue.begin(), m_impl->m_queue.end(),
                               [id](const ZeroTrustPromptItem& x) {
                                   return x.id == id;
                               });

        if (it == m_impl->m_queue.end()) {
            SS_LOG_WARN(kLogCat,
                L"ZeroTrustPromptQueue.Home: Resolve(id=%llu) — id not found",
                static_cast<unsigned long long>(id));
            return false;
        }

        imagePath        = it->imagePath;
        publisherSubject = it->publisherSubject;
        m_impl->m_queue.erase(it);
    }

    // Also Answer() the PhantomCore-side queue so any WaitFor() callers unblock.
    using CoreAnswer = ::ShadowStrike::PhantomCore::RealTime::ZeroTrust::PromptAnswer;
    auto& coreQueue = ::ShadowStrike::PhantomCore::RealTime::ZeroTrust::
                          ZeroTrustPromptQueue::Instance();

    switch (choice) {
        case UserChoice::Allow:
            if (!coreQueue.Answer(id, CoreAnswer::Allow)) {
                SS_LOG_WARN(kLogCat,
                    L"ZeroTrustPromptQueue.Home: coreQueue.Answer(Allow) returned false "
                    L"for id=%llu — entry may have already expired",
                    static_cast<unsigned long long>(id));
            }
            SS_LOG_INFO(kLogCat,
                L"ZeroTrustPromptQueue.Home: id=%llu resolved Allow for '%.128ls'",
                static_cast<unsigned long long>(id), imagePath.c_str());
            break;

        case UserChoice::Block:
            if (!coreQueue.Answer(id, CoreAnswer::Block)) {
                SS_LOG_WARN(kLogCat,
                    L"ZeroTrustPromptQueue.Home: coreQueue.Answer(Block) returned false "
                    L"for id=%llu — entry may have already expired",
                    static_cast<unsigned long long>(id));
            }
            SS_LOG_INFO(kLogCat,
                L"ZeroTrustPromptQueue.Home: id=%llu resolved Block for '%.128ls'",
                static_cast<unsigned long long>(id), imagePath.c_str());
            break;

        case UserChoice::AlwaysAllow: {
            if (!coreQueue.Answer(id, CoreAnswer::Allow)) {
                SS_LOG_WARN(kLogCat,
                    L"ZeroTrustPromptQueue.Home: coreQueue.Answer(Allow/AlwaysAllow) "
                    L"returned false for id=%llu",
                    static_cast<unsigned long long>(id));
            }

            {
                std::scoped_lock lock(m_impl->m_mutex);
                if (!imagePath.empty()) {
                    m_impl->m_alwaysAllowPaths.insert(imagePath);
                }
                if (!publisherSubject.empty()) {
                    m_impl->m_alwaysAllowPublishers.insert(publisherSubject);
                }
            }

            // Persist to ConfigManager.
            if (::ShadowStrike::Config::ConfigManager::HasInstance()) {
                auto& cfg = ::ShadowStrike::Config::ConfigManager::Instance();
                using Layer = ::ShadowStrike::Config::ConfigLayer;

                // Build a stable key by hashing the path string.
                // We use a deterministic encoding: base64-ish hex of wchar bytes.
                // For simplicity, we store the narrow UTF-8 form as a config value
                // under a sanitised key.
                std::string key = kAllowKeyPrefix;
                // Encode image path as a hex digest to avoid invalid key chars.
                {
                    std::uint64_t h = 14695981039346656037ULL; // FNV-1a offset basis
                    for (wchar_t c : imagePath) {
                        h ^= static_cast<std::uint64_t>(c);
                        h *= 1099511628211ULL;
                    }
                    char buf[20]{};
                    snprintf(buf, sizeof(buf), "%016llX", static_cast<unsigned long long>(h));
                    key += buf;
                }

                if (!cfg.SetValue<bool>(key, true, Layer::User)) {
                    SS_LOG_WARN(kLogCat,
                        L"ZeroTrustPromptQueue.Home: ConfigManager.SetValue(allow key) failed");
                }
                // Store the readable path as a sibling key for diagnostics.
                const std::string keyPath = key + "_path";
                // Convert to narrow for storage.
                const int needed = ::WideCharToMultiByte(CP_UTF8, 0,
                    imagePath.data(), static_cast<int>(imagePath.size()),
                    nullptr, 0, nullptr, nullptr);
                if (needed > 0) {
                    std::string narrow(static_cast<std::size_t>(needed), '\0');
                    ::WideCharToMultiByte(CP_UTF8, 0, imagePath.data(),
                        static_cast<int>(imagePath.size()),
                        narrow.data(), needed, nullptr, nullptr);
                    if (!cfg.SetValue<std::string>(keyPath, narrow, Layer::User)) {
                        SS_LOG_WARN(kLogCat,
                            L"ZeroTrustPromptQueue.Home: ConfigManager.SetValue(path key) failed");
                    }
                }
            }

            SS_LOG_INFO(kLogCat,
                L"ZeroTrustPromptQueue.Home: id=%llu AlwaysAllow registered "
                L"for '%.128ls'",
                static_cast<unsigned long long>(id), imagePath.c_str());
            break;
        }

        case UserChoice::AlwaysBlock: {
            if (!coreQueue.Answer(id, CoreAnswer::Block)) {
                SS_LOG_WARN(kLogCat,
                    L"ZeroTrustPromptQueue.Home: coreQueue.Answer(Block/AlwaysBlock) "
                    L"returned false for id=%llu",
                    static_cast<unsigned long long>(id));
            }

            {
                std::scoped_lock lock(m_impl->m_mutex);
                if (!imagePath.empty()) {
                    m_impl->m_alwaysDenyPaths.insert(imagePath);
                }
            }

            SS_LOG_WARN(kLogCat,
                L"ZeroTrustPromptQueue.Home: id=%llu AlwaysBlock registered "
                L"for '%.128ls'",
                static_cast<unsigned long long>(id), imagePath.c_str());
            break;
        }
    }

    m_impl->m_cv.notify_all();
    return true;
}

// ──────────────────────────────────────────────────────────────────────────────

std::vector<ZeroTrustPromptItem> ZeroTrustPromptQueue::Snapshot() const {
    std::scoped_lock lock(m_impl->m_mutex);
    m_impl->PruneExpiredLocked();

    std::vector<ZeroTrustPromptItem> out;
    out.reserve(m_impl->m_queue.size());
    for (const auto& item : m_impl->m_queue) {
        out.push_back(item);
    }
    return out;
}

// ──────────────────────────────────────────────────────────────────────────────

bool ZeroTrustPromptQueue::IsAlwaysAllowed(std::wstring_view imagePath,
                                            std::wstring_view publisherSubject) const
{
    std::scoped_lock lock(m_impl->m_mutex);
    if (!imagePath.empty()
        && m_impl->m_alwaysAllowPaths.count(std::wstring(imagePath))) {
        return true;
    }
    if (!publisherSubject.empty()
        && m_impl->m_alwaysAllowPublishers.count(std::wstring(publisherSubject))) {
        return true;
    }
    return false;
}

bool ZeroTrustPromptQueue::IsAlwaysDenied(std::wstring_view imagePath) const {
    if (imagePath.empty()) return false;
    std::scoped_lock lock(m_impl->m_mutex);
    return m_impl->m_alwaysDenyPaths.count(std::wstring(imagePath)) > 0;
}

// ──────────────────────────────────────────────────────────────────────────────

void ZeroTrustPromptQueue::LoadPersistedAllowList() {
    if (!::ShadowStrike::Config::ConfigManager::HasInstance()) {
        return;
    }

    auto& cfg = ::ShadowStrike::Config::ConfigManager::Instance();

    // Enumerate all values under the AlwaysAllow prefix.
    // Each entry has a hex-digest key (bool=true) and a <key>_path sibling
    // (string = narrow UTF-8 path). We read the path siblings.
    const auto all = cfg.GetAllValues(
        ::ShadowStrike::Config::ConfigLayer::User);

    std::size_t loaded = 0;
    {
        std::scoped_lock lock(m_impl->m_mutex);
        for (const auto& [key, val] : all) {
            // We look for keys ending in "_path" under our prefix.
            if (key.rfind(kAllowKeyPrefix, 0) != 0) continue;
            if (key.size() < 5
                || key.substr(key.size() - 5) != "_path") continue;

            // Extract the stored narrow path.
            const auto* strPtr = std::get_if<std::string>(&val);
            if (!strPtr || strPtr->empty()) continue;

            // Convert from narrow UTF-8 to wide.
            const int needed = ::MultiByteToWideChar(CP_UTF8, 0,
                strPtr->data(), static_cast<int>(strPtr->size()),
                nullptr, 0);
            if (needed <= 0) continue;

            std::wstring wpath(static_cast<std::size_t>(needed), L'\0');
            ::MultiByteToWideChar(CP_UTF8, 0, strPtr->data(),
                static_cast<int>(strPtr->size()),
                wpath.data(), needed);

            m_impl->m_alwaysAllowPaths.insert(std::move(wpath));
            ++loaded;
        }
    }

    SS_LOG_INFO(kLogCat,
        L"ZeroTrustPromptQueue.Home: Loaded %zu persisted always-allow path(s)",
        loaded);
}

void ZeroTrustPromptQueue::Stop() {
    {
        std::scoped_lock lock(m_impl->m_mutex);
        m_impl->m_stopped = true;
    }
    m_impl->m_cv.notify_all();
}

} // namespace ShadowStrike::Products::Home::ZeroTrust

// ============================================================================
// ─── Bridge function: PhantomCore queue → PhantomHome queue ─────────────────
// ============================================================================

namespace ShadowStrike::PhantomCore::RealTime::ZeroTrust {

static std::uint64_t BridgeEnqueueToHomeQueue(PromptEntry entry) {
    using HomeQueue = ::ShadowStrike::Products::Home::ZeroTrust::ZeroTrustPromptQueue;
    using HomeItem  = ::ShadowStrike::Products::Home::ZeroTrust::ZeroTrustPromptItem;

    HomeItem item;
    item.id           = entry.id;      // Preserve Core-assigned ID so Home::Resolve → Core::Answer() succeeds.
    item.imagePath    = entry.imagePath;
    item.score        = entry.computedTrust;
    item.createdAt    = entry.createdAt;

    // Convert narrow publisher to wide.
    if (!entry.publisher.empty()) {
        const int needed = ::MultiByteToWideChar(CP_UTF8, 0,
            entry.publisher.data(), static_cast<int>(entry.publisher.size()),
            nullptr, 0);
        if (needed > 0) {
            item.publisherSubject.resize(static_cast<std::size_t>(needed));
            ::MultiByteToWideChar(CP_UTF8, 0,
                entry.publisher.data(), static_cast<int>(entry.publisher.size()),
                item.publisherSubject.data(), needed);
        }
    }

    return HomeQueue::Instance().Enqueue(std::move(item));
}

} // namespace ShadowStrike::PhantomCore::RealTime::ZeroTrust
