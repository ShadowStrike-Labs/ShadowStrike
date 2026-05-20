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
constexpr const char*    kAllowKeyPrefix     = "Home/ZeroTrust/AlwaysAllow/";
constexpr const char*    kAllowPubKeyPrefix  = "Home/ZeroTrust/AlwaysAllowPub/";
constexpr const wchar_t* kLogCat             = L"ZeroTrustPromptQueue.Home";
constexpr const wchar_t* kLogCatCore         = L"ZeroTrustPromptQueue.Core";

// Defensive caps on user-controlled strings inside PromptItems. The hot path
// gets these from the process-execution hook and they must not be trusted to
// have any particular length. Caps are generous (well above MAX_PATH and the
// typical Authenticode subject) but bound worst-case allocations.
constexpr std::size_t kMaxImagePathChars     = 32768;   ///< 64 KiB UTF-16.
constexpr std::size_t kMaxPublisherChars     = 1024;    ///< 2 KiB UTF-16.

// FNV-1a 64-bit digest of a wide string. Used to derive stable, ASCII-only
// ConfigManager keys from arbitrary user paths/publishers.
[[nodiscard]] inline std::string Fnv1aHexW(std::wstring_view s) noexcept {
    std::uint64_t h = 14695981039346656037ULL;
    for (wchar_t c : s) {
        h ^= static_cast<std::uint64_t>(static_cast<std::uint32_t>(c));
        h *= 1099511628211ULL;
    }
    char buf[17]{};
    (void)std::snprintf(buf, sizeof(buf), "%016llX",
                        static_cast<unsigned long long>(h));
    return std::string(buf);
}

[[nodiscard]] inline std::string WideToUtf8(std::wstring_view ws) {
    if (ws.empty()) return {};
    const int needed = ::WideCharToMultiByte(CP_UTF8, 0,
        ws.data(), static_cast<int>(ws.size()),
        nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(static_cast<std::size_t>(needed), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()),
        out.data(), needed, nullptr, nullptr);
    return out;
}

[[nodiscard]] inline std::wstring Utf8ToWide(std::string_view s) {
    if (s.empty()) return {};
    const int needed = ::MultiByteToWideChar(CP_UTF8, 0,
        s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (needed <= 0) return {};
    std::wstring out(static_cast<std::size_t>(needed), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
        out.data(), needed);
    return out;
}

inline void TruncateInPlace(std::wstring& s, std::size_t maxChars) {
    if (s.size() > maxChars) {
        s.resize(maxChars);
    }
}
} // namespace

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
    // ------------------------------------------------------------------
    // Defensive length caps on user-controlled strings sourced from the
    // process-execution hook. This bounds worst-case allocation regardless
    // of what the kernel hook hands us.
    // ------------------------------------------------------------------
    TruncateInPlace(item.imagePath,        kMaxImagePathChars);
    TruncateInPlace(item.publisherSubject, kMaxPublisherChars);

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

        // Once Stop() has been signalled, no further items may enter the queue:
        // there is no consumer to drain them and they would leak until process
        // teardown.
        if (m_impl->m_stopped) {
            SS_LOG_WARN(kLogCat,
                L"ZeroTrustPromptQueue.Home: Enqueue() rejected — queue stopped");
            return 0;
        }

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

bool ZeroTrustPromptQueue::SetProcessSessionId(std::uint64_t id,
                                                std::uint32_t sessionId) {
    if (id == 0) {
        return false;
    }
    std::scoped_lock lock(m_impl->m_mutex);
    for (auto& item : m_impl->m_queue) {
        if (item.id == id) {
            item.processSessionId = sessionId;
            return true;
        }
    }
    return false;
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

            // ----------------------------------------------------------------
            // Persistence policy.
            //
            // Path-based AlwaysAllow is intentionally NOT persisted to
            // ConfigManager for unsigned binaries. Without a publisher subject
            // we cannot bind the user's trust decision to anything other than
            // the literal pathname; an attacker who can later drop a different
            // binary at the same path would inherit the allow-list entry, and
            // process-launch hot path has no hash to verify against.
            //
            // For signed binaries we persist BOTH:
            //   - the image-path entry (so subsequent launches of the exact
            //     same trusted binary go through the fast path), and
            //   - the publisher-subject entry (so any signed binary from the
            //     same trusted publisher is honoured).
            //
            // AlwaysBlock is in-memory only by spec.
            // ----------------------------------------------------------------
            const bool persist =
                ::ShadowStrike::Config::ConfigManager::HasInstance()
                && !publisherSubject.empty();

            if (persist) {
                auto& cfg = ::ShadowStrike::Config::ConfigManager::Instance();
                using Layer = ::ShadowStrike::Config::ConfigLayer;

                if (!imagePath.empty()) {
                    const std::string key     = std::string(kAllowKeyPrefix)
                                                + Fnv1aHexW(imagePath);
                    const std::string keyPath = key + "_path";

                    if (!cfg.SetValue<bool>(key, true, Layer::User)) {
                        SS_LOG_WARN(kLogCat,
                            L"ZeroTrustPromptQueue.Home: ConfigManager.SetValue(allow key) failed");
                    }
                    const std::string narrowPath = WideToUtf8(imagePath);
                    if (!narrowPath.empty()) {
                        if (!cfg.SetValue<std::string>(keyPath, narrowPath, Layer::User)) {
                            SS_LOG_WARN(kLogCat,
                                L"ZeroTrustPromptQueue.Home: ConfigManager.SetValue(path key) failed");
                        }
                    }
                }

                // Publisher subject sibling. Lets the user honour any signed
                // binary from the same publisher after restart.
                {
                    const std::string pubKey     = std::string(kAllowPubKeyPrefix)
                                                   + Fnv1aHexW(publisherSubject);
                    const std::string pubKeyPath = pubKey + "_pub";

                    if (!cfg.SetValue<bool>(pubKey, true, Layer::User)) {
                        SS_LOG_WARN(kLogCat,
                            L"ZeroTrustPromptQueue.Home: ConfigManager.SetValue(publisher key) failed");
                    }
                    const std::string narrowPub = WideToUtf8(publisherSubject);
                    if (!narrowPub.empty()) {
                        if (!cfg.SetValue<std::string>(pubKeyPath, narrowPub, Layer::User)) {
                            SS_LOG_WARN(kLogCat,
                                L"ZeroTrustPromptQueue.Home: ConfigManager.SetValue(publisher path key) failed");
                        }
                    }
                }
            } else if (!::ShadowStrike::Config::ConfigManager::HasInstance()) {
                SS_LOG_WARN(kLogCat,
                    L"ZeroTrustPromptQueue.Home: AlwaysAllow not persisted "
                    L"(ConfigManager unavailable); session-only");
            } else {
                // Unsigned binary path. The in-memory allow-list still applies
                // for the current process lifetime, but we do not persist a
                // pathname-only allow rule (binary-swap replay risk).
                SS_LOG_WARN(kLogCat,
                    L"ZeroTrustPromptQueue.Home: AlwaysAllow kept session-only — "
                    L"unsigned binary at '%.128ls' (no publisher to bind to)",
                    imagePath.c_str());
            }

            SS_LOG_INFO(kLogCat,
                L"ZeroTrustPromptQueue.Home: id=%llu AlwaysAllow registered "
                L"for '%.128ls' (persisted=%hs)",
                static_cast<unsigned long long>(id),
                imagePath.c_str(),
                persist ? "true" : "false");
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

    // Pull a snapshot of the User layer once. GetAllValues() may take its own
    // locks inside ConfigManager; keep this off-hot-path and outside our own
    // queue mutex so we never lock-order-invert against the hot path.
    const auto all = cfg.GetAllValues(
        ::ShadowStrike::Config::ConfigLayer::User);

    const std::string allowPrefix    = kAllowKeyPrefix;
    const std::string allowPubPrefix = kAllowPubKeyPrefix;
    constexpr std::string_view kPathSuffix = "_path";
    constexpr std::string_view kPubSuffix  = "_pub";

    std::size_t loadedPaths = 0;
    std::size_t loadedPubs  = 0;

    {
        std::scoped_lock lock(m_impl->m_mutex);
        for (const auto& [key, val] : all) {
            const auto* strPtr = std::get_if<std::string>(&val);
            if (!strPtr || strPtr->empty()) continue;

            // Image-path siblings: "<allowPrefix><digest>_path" → narrow UTF-8 path.
            if (key.size() >= allowPrefix.size() + kPathSuffix.size()
                && key.compare(0, allowPrefix.size(), allowPrefix) == 0
                && key.compare(key.size() - kPathSuffix.size(),
                               kPathSuffix.size(), kPathSuffix) == 0)
            {
                // Cap on load to defend against a tampered config file.
                if (strPtr->size() > kMaxImagePathChars * 4 /* UTF-8 worst-case */) {
                    SS_LOG_WARN(kLogCat,
                        L"ZeroTrustPromptQueue.Home: persisted path entry exceeds cap; skipped");
                    continue;
                }
                std::wstring wpath = Utf8ToWide(*strPtr);
                if (wpath.empty()) continue;
                TruncateInPlace(wpath, kMaxImagePathChars);
                m_impl->m_alwaysAllowPaths.insert(std::move(wpath));
                ++loadedPaths;
                continue;
            }

            // Publisher-subject siblings: "<allowPubPrefix><digest>_pub" → narrow UTF-8 subject.
            if (key.size() >= allowPubPrefix.size() + kPubSuffix.size()
                && key.compare(0, allowPubPrefix.size(), allowPubPrefix) == 0
                && key.compare(key.size() - kPubSuffix.size(),
                               kPubSuffix.size(), kPubSuffix) == 0)
            {
                if (strPtr->size() > kMaxPublisherChars * 4) {
                    SS_LOG_WARN(kLogCat,
                        L"ZeroTrustPromptQueue.Home: persisted publisher entry exceeds cap; skipped");
                    continue;
                }
                std::wstring wpub = Utf8ToWide(*strPtr);
                if (wpub.empty()) continue;
                TruncateInPlace(wpub, kMaxPublisherChars);
                m_impl->m_alwaysAllowPublishers.insert(std::move(wpub));
                ++loadedPubs;
                continue;
            }
        }
    }

    SS_LOG_INFO(kLogCat,
        L"ZeroTrustPromptQueue.Home: Loaded %zu always-allow path(s), %zu publisher(s)",
        loadedPaths, loadedPubs);
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
    item.publisherSubject = Utf8ToWide(entry.publisher);

    // Apply defensive caps before the Home queue does, so the WARN below
    // (if Home::Enqueue rejects a stopped queue / full queue) does not
    // ride on an oversize buffer.
    TruncateInPlace(item.imagePath,        kMaxImagePathChars);
    TruncateInPlace(item.publisherSubject, kMaxPublisherChars);

    return HomeQueue::Instance().Enqueue(std::move(item));
}

} // namespace ShadowStrike::PhantomCore::RealTime::ZeroTrust
