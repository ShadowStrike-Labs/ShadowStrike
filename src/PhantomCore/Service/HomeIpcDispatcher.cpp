/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file HomeIpcDispatcher.cpp
 * @brief Implementation of the HomeIpcDispatcher — the service-side IPC
 *        handler that wires every PhantomHome UI command verb to its backend.
 *
 * Handler inventory (v2 CommandType values):
 *   199  AuthHandshake          — validate IpcAuthToken; mark client auth'd
 *   10   GetStatus              — global mode, paused state, module count
 *   250  GetDashboard           — headline + recommendation + threat counts
 *   30   UpdateConfig           — globalMode shortcut + Home/* key writes
 *   31   GetConfig              — read Home/* config prefix
 *   200  ListModules            — orchestrator + catalog cross-reference
 *   201  SetModuleEnabled       — enable/disable a named module
 *   202  SetModuleMode          — change ProtectionMode for a named module
 *   210  PauseProtection        — pause all modules for N minutes
 *   211  ResumeProtection       — resume paused modules
 *   20   StartScan              — start fast/full/custom scan async
 *   21   StopScan               — cancel an in-progress scan
 *   222  GetScanProgress        — poll scan progress by scan id
 *   230  ListQuarantine         — paginated quarantine item list
 *   50   QuarantineAction       — restore / delete / deleteAll
 *   240  GetReports             — paginated historical event reports
 *   270  ListPGTIFeeds          — enumerate PGTI feed status
 *   271  SetPGTIFeedEnabled     — enable/disable a PGTI feed
 *   272  RefreshPGTIFeeds       — force-refresh PGTI feeds
 *   290  GetRecommendations     — list active recommendations
 *   291  DismissRecommendation  — dismiss a recommendation by id
 *   280  GetZeroTrustState      — query ZeroTrustGuard config
 *   281  SetZeroTrustConfig     — update ZeroTrustGuard config
 *   282  AnswerZeroTrustPrompt  — resolve a pending ZeroTrust prompt
 *   260  SubscribeEvents        — acknowledged; push is auto
 *
 * Security contract:
 *   - Every handler except AuthHandshake requires IsClientAuthenticated().
 *   - All JSON payloads are depth-validated before field extraction.
 *   - List handlers cap result sets at 200 items.
 *   - Sensitive handlers (UpdateConfig/SetSetting/SetZeroTrustConfig) log
 *     only verb + key list, never values.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 */

#include "pch.h"
#include "HomeIpcDispatcher.hpp"
#include "../Diagnostics/DiagTrace.hpp"
#include "ServiceCommunicator.hpp"
#include "IpcAuthToken.hpp"
#include "EventPush.hpp"

#include <algorithm>
#include <limits>

// PhantomHome subsystems
#include "../../Products/Community/PhantomHome/HomeProductOrchestrator.hpp"
#include "../../Products/Community/PhantomHome/UI/Shared/ModuleCatalog.hpp"
#include "../../Products/Community/PhantomHome/ThreatIntel/PgtiFeedManager.hpp"
#include "../../Products/Community/PhantomHome/Recommendations/RecommendationsEngine.hpp"
#include "../../Products/Community/PhantomHome/HeadlineState/HeadlineStateService.hpp"
#include "../../Products/Community/PhantomHome/Reports/HomeReportsStore.hpp"
#include "../../Products/Community/PhantomHome/ZeroTrustGuard/ZeroTrustGuard.hpp"
#include "../../Products/Community/PhantomHome/ZeroTrustGuard/ZeroTrustPromptQueue.hpp"

// PhantomCore subsystems
#include "../Core/Engine/ScanEngine.hpp"
#include "../Core/Engine/QuarantineManager.hpp"
#include "../Config/ConfigManager.hpp"
#include "../Utils/Logger.hpp"

// Standard library
#include <atomic>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <future>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <variant>
#include <vector>

// Third-party
#include <nlohmann/json.hpp>

// Windows SDK
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

namespace ShadowStrike::Service {

using namespace ShadowStrike::Products::Home;
using namespace ShadowStrike::Products::Home::ThreatIntel;
using namespace ShadowStrike::Products::Home::Recommendations;
using namespace ShadowStrike::Products::Home::HeadlineState;
using namespace ShadowStrike::Products::Home::ZeroTrust;
using namespace ShadowStrike::PhantomHome::Reports;
using namespace ShadowStrike::Products::Home::UI;
using namespace ShadowStrike::Core::Engine;
using ShadowStrike::Config::ConfigManager;

// ============================================================================
// Constants
// ============================================================================

static constexpr const wchar_t* kLogCat        = L"HomeIpc";
static constexpr std::uint32_t  kProtocolVer   = 1u;
static constexpr std::size_t    kMaxListItems  = 200u;

// Scan targets NAMED in a progress reply. The COUNT reported alongside is
// always exact; this caps only the list, because the reply is polled about
// twice a second and a several-hundred-file selection would otherwise put the
// whole path set on the wire on every poll. A caller needs enough to name
// what is being scanned, not to reconstruct the selection.
static constexpr std::size_t    kMaxReportedScanTargets = 8u;
static constexpr std::size_t    kMaxResponseBytes = 512u * 1024u;  // 512 KiB
static constexpr std::uint32_t  kMaxJsonDepth  = 8u;
static constexpr std::uint32_t  kMaxJsonNodes  = 4096u;

void LogBroadcastResult(const wchar_t* context, std::size_t delivered) noexcept {
    if (delivered == 0u) {
        SS_LOG_DEBUG(kLogCat, L"%ls broadcast had no authenticated subscribers", context ? context : L"event");
    }
}

// ============================================================================
// JSON helpers (service-side, independent of Messages.hpp)
// ============================================================================

namespace {

/// Depth + node counter to guard against deeply-nested / excessively-wide JSON.
struct JsonValidator {
    std::uint32_t nodes{ 0 };
    std::uint32_t maxDepth;

    [[nodiscard]] bool Visit(const nlohmann::json& j, std::uint32_t depth = 0) noexcept {
        if (depth > maxDepth) return false;
        if (++nodes > kMaxJsonNodes) return false;
        if (j.is_binary()) return false;
        if (j.is_object() || j.is_array()) {
            for (const auto& child : j) {
                if (!Visit(child, depth + 1)) return false;
            }
        }
        return true;
    }
};

[[nodiscard]] bool ValidateJson(const nlohmann::json& j) noexcept {
    JsonValidator v{ 0, kMaxJsonDepth };
    return v.Visit(j);
}

[[nodiscard]] nlohmann::json MakeErrorResponse(std::string_view code,
                                               std::string_view message) {
    return nlohmann::json{
        {"ok",    false},
        {"error", {
            {"code",    std::string(code)},
            {"message", std::string(message)}
        }}
    };
}

[[nodiscard]] nlohmann::json MakeOk() {
    return nlohmann::json{{"ok", true}};
}

/// Parse raw JSON string and validate depth/node constraints.
/// Returns a discarded json on parse failure; an empty (but not discarded)
/// object ({}) when the depth/node limit is exceeded.
[[nodiscard]] nlohmann::json SafeParse(std::string_view raw) noexcept {
    auto j = nlohmann::json::parse(raw, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded()) return j;
    if (!ValidateJson(j)) return nlohmann::json::object(); // depth exceeded
    return j;
}

template<typename T>
[[nodiscard]] std::optional<T> Field(const nlohmann::json& obj,
                                     std::string_view key) noexcept {
    try {
        const auto it = obj.find(key);
        if (it == obj.end()) return std::nullopt;
        return it->template get<T>();
    } catch (...) { return std::nullopt; }
}

/// Convert a ConfigValue variant to a nlohmann::json node.
[[nodiscard]] nlohmann::json ConfigValueToJson(const Config::ConfigValue& cv) {
    return std::visit([](const auto& v) -> nlohmann::json {
        using T = std::decay_t<decltype(v)>;
        if constexpr (std::is_same_v<T, std::monostate>)           return nullptr;
        else if constexpr (std::is_same_v<T, bool>)                return v;
        else if constexpr (std::is_same_v<T, int32_t>)             return v;
        else if constexpr (std::is_same_v<T, int64_t>)             return v;
        else if constexpr (std::is_same_v<T, uint32_t>)            return v;
        else if constexpr (std::is_same_v<T, uint64_t>)            return v;
        else if constexpr (std::is_same_v<T, double>)              return v;
        else if constexpr (std::is_same_v<T, std::string>)         return v;
        else if constexpr (std::is_same_v<T, std::wstring>)        return "<wstring>";
        else if constexpr (std::is_same_v<T, std::vector<std::string>>) {
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& s : v) arr.push_back(s);
            return arr;
        }
        else if constexpr (std::is_same_v<T, std::vector<int64_t>>) {
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& x : v) arr.push_back(x);
            return arr;
        }
        else if constexpr (std::is_same_v<T, std::map<std::string,std::string>>) {
            nlohmann::json obj = nlohmann::json::object();
            for (const auto& [k,val] : v) obj[k] = val;
            return obj;
        }
        return nullptr;
    }, cv);
}

/// Convert a std::wstring to std::string (narrow UTF-8 best-effort).
[[nodiscard]] std::string WideToNarrow(const std::wstring& w) {
    if (w.empty()) return {};
    const int need = WideCharToMultiByte(CP_UTF8, 0, w.data(),
        static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (need <= 0) return {};
    std::string out(static_cast<std::size_t>(need), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
        out.data(), need, nullptr, nullptr);
    return out;
}

/// Convert a UTF-8 std::string to std::wstring. A naive char-by-char copy
/// truncates UTF-8 multi-byte sequences and silently corrupts non-ASCII file
/// paths supplied by the UI; the engine then either fails to find files or,
/// worse, scans an unintended target. MultiByteToWideChar with CP_UTF8 is the
/// only correct conversion.
[[nodiscard]] std::wstring NarrowToWide(std::string_view s) {
    if (s.empty()) return {};
    const int need = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (need <= 0) return {};
    std::wstring out(static_cast<std::size_t>(need), L'\0');
    const int written = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        s.data(), static_cast<int>(s.size()), out.data(), need);
    if (written <= 0) return {};
    return out;
}

} // anonymous namespace

// ============================================================================
// PIMPL
// ============================================================================

struct HomeIpcDispatcher::Impl {
    // ---- Pause state --------------------------------------------------------
    //
    // The original implementation spawned a detached std::thread that held a
    // bare `this` pointer and dereferenced Impl members (pauseEndTime, the
    // mutex, the atomic flag) *after* signalling the resume side-effects.
    // On service shutdown the detached thread continued to touch Impl members
    // after this object was destroyed — undefined behaviour even though the
    // singleton lives for the process lifetime, because std::terminate races
    // and pending DllMain teardown can disturb member storage.
    //
    // A std::jthread joined by Impl's destructor eliminates the dangling-this
    // window; a stop_token gates the resume side-effects so a shutdown does
    // not flip protection state on its way out.
    mutable std::mutex                                      pauseMutex;
    std::condition_variable                                 pauseCv;
    std::optional<std::chrono::steady_clock::time_point>    pauseEndTime;
    std::atomic<bool>                                       pauseTimerActive{false};
    std::jthread                                            pauseTimerThread;

    ~Impl() {
        // Request stop then notify so the timer wakes and observes the token
        // before std::jthread's own destructor joins. Without the notify, the
        // wait_until predicate is never re-evaluated and the join blocks
        // indefinitely.
        if (pauseTimerThread.joinable()) {
            pauseTimerThread.request_stop();
        }
        pauseCv.notify_all();
    }

    void ScheduleResume(std::chrono::seconds delay) {
        {
            std::lock_guard<std::mutex> lk(pauseMutex);
            pauseEndTime = std::chrono::steady_clock::now() + delay;
        }
        pauseCv.notify_all();

        if (pauseTimerActive.exchange(true)) {
            // An active timer thread is already waiting; it observes the new
            // deadline via the predicate when the CV wakes it up above.
            return;
        }

        if (pauseTimerThread.joinable()) {
            // Previous timer thread has finished (pauseTimerActive was false).
            // Drain it cleanly before re-arming.
            pauseTimerThread.request_stop();
            pauseTimerThread.join();
        }

        pauseTimerThread = std::jthread([this](std::stop_token stoken) {
            // Always release the active flag, regardless of how we exit.
            struct ActiveGuard {
                std::atomic<bool>& flag;
                ~ActiveGuard() { flag.store(false, std::memory_order_release); }
            } guard{pauseTimerActive};

            bool ranToCompletion = false;
            {
                std::unique_lock<std::mutex> lk(pauseMutex);
                while (!stoken.stop_requested() && pauseEndTime.has_value()) {
                    const auto target = *pauseEndTime;
                    pauseCv.wait_until(lk, target, [&] {
                        return stoken.stop_requested()
                            || !pauseEndTime.has_value()
                            || *pauseEndTime != target;
                    });
                    if (stoken.stop_requested()) return;
                    if (!pauseEndTime.has_value()) return;
                    if (std::chrono::steady_clock::now() >= *pauseEndTime) {
                        pauseEndTime.reset();
                        ranToCompletion = true;
                        break;
                    }
                    // Deadline was moved; loop and wait on the new target.
                }
            }

            if (!ranToCompletion || stoken.stop_requested()) return;

            HomeProductOrchestrator::Instance().ResumeAllModules();

            const auto ev = Events::BuildProtectionStateChanged(
                "active", "auto-resume after timed pause");
            if (!ev.empty()) {
                const auto delivered = ServiceCommunicator::Instance().BroadcastEvent(
                    CommandType::ProtectionStateChanged, ev);
                LogBroadcastResult(L"auto-resume protection-state", delivered);
            }
        });
    }

    [[nodiscard]] std::int64_t PauseRemainingSec() const {
        std::lock_guard<std::mutex> lk(pauseMutex);
        if (!pauseEndTime) return 0;
        const auto now = std::chrono::steady_clock::now();
        if (now >= *pauseEndTime) return 0;
        return static_cast<std::int64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                *pauseEndTime - now).count());
    }

    // ---- Active scan tracking -----------------------------------------------
    struct ScanRecord {
        std::string           scanId;
        std::atomic<float>    percent{0.0f};
        std::atomic<uint64_t> itemsScanned{0};
        std::atomic<uint64_t> threatsFound{0};
        std::atomic<bool>     cancelRequested{false};

        //
        // WHAT THE SCAN IS, not merely how far along it is.
        //
        // Without these the only progress surface can describe any scan in one
        // way, and it picked "Quick Scan" - so a right-click scan of a single
        // file was reported to the user as a Quick Scan of their whole machine.
        // The scope was known at StartScan and thrown away one statement later.
        //
        // Guarded by stateMutex rather than made atomic because they are
        // strings, and the reply already takes that lock to read stateStr.
        //
        std::string              scope{"fast"};
        std::vector<std::string> targets;
        std::size_t              targetCount{0};

        //
        // THE ENGINE'S OWN PROGRESS FIELDS. Every one of these is produced by
        // ScanBatch's emitter - the only emitter QuickScan, FullScan and
        // CustomScan reach - and every one was discarded here.
        //
        // totalBytes IS ABSENT DELIBERATELY. The engine cannot know it without
        // stat-ing every file before the scan begins, so it is genuinely
        // unset rather than merely unreported, and carrying a constant zero
        // to a progress bar would be the defect this change removes.
        //
        std::atomic<uint64_t> totalFiles{0};
        std::atomic<uint64_t> bytesScanned{0};
        std::atomic<uint64_t> elapsedMs{0};
        std::atomic<uint64_t> estimatedRemainingMs{0};
        std::atomic<uint64_t> filesPerSecond{0};
        std::atomic<uint64_t> bytesPerSecond{0};

        mutable std::mutex    stateMutex;
        std::string           stateStr{"running"};
        std::wstring          currentPath;
        std::future<DirectoryScanResult> future;
    };

    mutable std::shared_mutex                             scanMutex;
    std::map<std::string, std::shared_ptr<ScanRecord>>   activeScans;
    std::atomic<std::uint64_t>                           scanIdCounter{0};

    [[nodiscard]] std::string NewScanId() {
        return "scan-" + std::to_string(++scanIdCounter);
    }

    void AddScan(std::shared_ptr<ScanRecord> rec) {
        std::unique_lock<std::shared_mutex> lk(scanMutex);
        activeScans[rec->scanId] = std::move(rec);
    }

    [[nodiscard]] std::shared_ptr<ScanRecord> FindScan(const std::string& id) const {
        std::shared_lock<std::shared_mutex> lk(scanMutex);
        const auto it = activeScans.find(id);
        return it != activeScans.end() ? it->second : nullptr;
    }

    // ---- Config key allow-list ----------------------------------------------
    //
    // ConfigManager::SetValue accepts arbitrary string keys. Even with the
    // "Home/" prefix gate, untrusted callers could submit pathological keys
    // (excessive length, embedded control bytes, traversal sequences) that
    // bloat the config store or surface oddly in audit trails. Bound the
    // suffix length and reject control characters and ".." segments.
    [[nodiscard]] static bool IsAllowedConfigKey(std::string_view key) noexcept {
        static constexpr std::size_t kMaxConfigKeyLen = 256u;
        if (key.size() <= 5u || key.size() > kMaxConfigKeyLen) return false;
        if (key.substr(0, 5) != "Home/") return false;

        for (std::size_t i = 5; i < key.size(); ++i) {
            const unsigned char c = static_cast<unsigned char>(key[i]);
            if (c < 0x20 || c == 0x7F) return false;     // control bytes
            if (c == '\\' || c == '\"') return false;     // never legitimate
        }
        // Reject any ".." segment to block path-traversal-shaped keys.
        if (key.find("..") != std::string_view::npos) return false;
        // Reject consecutive or trailing separators.
        if (key.find("//") != std::string_view::npos) return false;
        if (key.back() == '/') return false;
        return true;
    }

    [[nodiscard]] static bool IsAllowedConfigPrefix(std::string_view prefix) noexcept {
        if (prefix == "Home/") return true;
        return IsAllowedConfigKey(prefix);
    }
};

// ============================================================================
// Singleton
// ============================================================================

HomeIpcDispatcher& HomeIpcDispatcher::Instance() {
    static HomeIpcDispatcher instance;
    return instance;
}

HomeIpcDispatcher::HomeIpcDispatcher()
    : m_impl(std::make_unique<Impl>()) {}

HomeIpcDispatcher::~HomeIpcDispatcher() = default;

// ============================================================================
// Install
// ============================================================================

void HomeIpcDispatcher::Install(ServiceCommunicator& svc) {
    SS_LOG_INFO(kLogCat, L"Installing HomeIpcDispatcher handlers");

    Impl* impl = m_impl.get();

    // ── Uniform auth guard ─────────────────────────────────────────────────────
    // Returns true (= handled, error reply sent) when the client is NOT auth'd.
    auto CheckAuth = [&svc](std::uint64_t clientId,
                             std::uint64_t requestId,
                             CommandType   cmd) -> bool {
        if (!svc.IsClientAuthenticated(clientId)) {
            SS_LOG_WARN(kLogCat,
                L"Unauthenticated client %llu attempted verb %u — rejected",
                clientId, static_cast<uint32_t>(cmd));
            const auto r = MakeErrorResponse("unauthenticated",
                "AuthHandshake required before this verb");
            svc.SendResponseEnvelope(clientId, cmd, requestId, r.dump());
            return true;
        }
        return false;
    };

    // ── JSON parse guard ───────────────────────────────────────────────────────
    // On failure sends an error reply and returns an empty (non-discarded) object.
    auto ParseOrReject = [&svc](std::uint64_t   clientId,
                                 std::uint64_t   requestId,
                                 CommandType     cmd,
                                 std::string_view raw) -> nlohmann::json {
        if (raw.size() > 1u << 20u) {  // 1 MiB hard cap
            svc.SendResponseEnvelope(clientId, cmd, requestId,
                MakeErrorResponse("payload_too_large",
                    "JSON payload exceeds 1 MiB").dump());
            return nlohmann::json{};
        }
        auto j = SafeParse(raw);
        if (j.is_discarded()) {
            svc.SendResponseEnvelope(clientId, cmd, requestId,
                MakeErrorResponse("validation_failed",
                    "JSON parse failed or structure limit exceeded").dump());
            return nlohmann::json{};
        }
        return j;
    };

    // ==========================================================================
    // 199 — AuthHandshake
    // ==========================================================================
    svc.RegisterV2Handler(CommandType::AuthHandshake,
        [&svc](std::uint64_t clientId, std::uint32_t sessionId,
               std::uint64_t requestId, std::string_view raw)
    {
        SS_LOG_INFO(kLogCat, L"AuthHandshake clientId=%llu session=%u req=%llu",
            clientId, sessionId, requestId);

        const auto sendErr = [&](std::string_view code, std::string_view msg) {
            svc.SendResponseEnvelope(clientId, CommandType::AuthHandshake, requestId,
                MakeErrorResponse(code, msg).dump());
        };

        if (raw.size() > 1u << 20u) { sendErr("payload_too_large", ""); return; }

        auto j = SafeParse(raw);
        if (j.is_discarded()) { sendErr("validation_failed", "bad JSON"); return; }

        const auto protoVer = Field<std::uint32_t>(j, "protocolVersion");
        if (!protoVer || *protoVer != kProtocolVer) {
            nlohmann::json e = MakeErrorResponse("version_mismatch",
                "Unsupported protocol version");
            e["expected"] = kProtocolVer;
            svc.SendResponseEnvelope(clientId, CommandType::AuthHandshake, requestId,
                e.dump());
            return;
        }

        const auto token = Field<std::string>(j, "token");
        if (!token || token->empty()) { sendErr("auth_failed", "Missing token"); return; }

        if (!IpcAuthToken::Verify(sessionId, *token)) {
            // ------------------------------------------------------------------
            // This used to "self-heal" by calling EnsureForSession() right here,
            // on the IPC handler thread. EnsureForSession does WTSQueryUserToken,
            // resolves the user's profile path and then WRITES THE TOKEN FILE -
            // all blocking, and all while holding the token cache lock.
            //
            // That write goes through our own minifilter. The kernel then asks
            // user mode for a verdict on it, and the thread that must produce
            // that verdict is this one, currently blocked inside the write. Every
            // other process's file operations queue behind it, so the whole
            // machine stalls until the scan deadline expires. The owner observed
            // exactly this: the system freezes the instant the UI displays
            // "Authenticating the service session", frees for three to five
            // seconds when the handshake times out and the UI reports
            // "Service connection interrupted, retrying", then freezes again on
            // the next attempt.
            //
            // Commit 760a4557 created the window this runs in: provisioning was
            // moved to a detached thread so Start() could complete, which means
            // the service reports RUNNING before the token file exists. The UI
            // connects into that gap, Verify misses, and the miss used to be
            // repaired on the worst possible thread.
            //
            // An IPC handler must never perform file I/O. Report not-ready and
            // let the client retry - it already does, on a timer - while the
            // provisioning thread does the write where blocking is harmless.
            // ------------------------------------------------------------------
            SS_DIAG("SvcAuth", "AuthHandshake token miss clientId=%llu session=%u"
                               " -> replying auth_not_ready (no I/O on this thread)",
                    clientId, sessionId);

            IpcAuthToken::RequestProvisionAsync(sessionId);

            SS_LOG_WARN(kLogCat,
                L"AuthHandshake not ready clientId=%llu session=%u "
                L"(token not yet provisioned; provisioning requested, client should retry)",
                clientId, sessionId);

            nlohmann::json e = MakeErrorResponse("auth_not_ready",
                "Session token is still being provisioned; retry shortly");
            e["retryable"] = true;
            svc.SendResponseEnvelope(clientId, CommandType::AuthHandshake, requestId,
                e.dump());
            return;
        }

        svc.MarkClientAuthenticated(clientId);
        SS_LOG_INFO(kLogCat, L"AuthHandshake SUCCESS clientId=%llu session=%u",
            clientId, sessionId);
        SS_DIAG("SvcAuth", "AuthHandshake SUCCESS clientId=%llu session=%u",
                clientId, sessionId);
        svc.SendResponseEnvelope(clientId, CommandType::AuthHandshake, requestId,
            nlohmann::json{{"ok", true}}.dump());
    });

    // ==========================================================================
    // 10 — GetStatus
    // ==========================================================================
    svc.RegisterV2Handler(CommandType::GetStatus,
        [&svc, impl, CheckAuth](std::uint64_t clientId, std::uint32_t,
                                 std::uint64_t requestId, std::string_view)
    {
        if (CheckAuth(clientId, requestId, CommandType::GetStatus)) return;
        SS_LOG_INFO(kLogCat, L"GetStatus clientId=%llu req=%llu", clientId, requestId);

        const auto& orch     = HomeProductOrchestrator::Instance();
        const bool  paused   = orch.IsPaused();
        const auto  modules  = orch.GetStatus();
        const bool  running  = orch.IsRunning();
        const bool  initialized = orch.IsInitialized();
        const int   gMode    = ConfigManager::Instance().GetValue<int>(
            "Home/GlobalMode", static_cast<int>(ProtectionMode::Balanced));
        const auto failedCount = std::count_if(modules.begin(), modules.end(),
            [](const auto& m) { return m.state == ModuleState::Failed; });
        const std::string health = !running && !initialized
            ? "critical"
            : (failedCount == 0 ? "healthy" : "atRisk");
        const auto rawPausedRemainingSec = impl->PauseRemainingSec();
        const std::uint32_t pausedRemainingSec =
            rawPausedRemainingSec <= 0
                ? 0u
                : (rawPausedRemainingSec > static_cast<decltype(rawPausedRemainingSec)>(
                       std::numeric_limits<std::uint32_t>::max())
                       ? std::numeric_limits<std::uint32_t>::max()
                       : static_cast<std::uint32_t>(rawPausedRemainingSec));

        nlohmann::json resp{
            {"ok",                true},
            {"health",            health},
            {"globalMode",        gMode},
            {"paused",            paused},
            {"pausedRemainingSec", pausedRemainingSec},
            {"pausedSecondsRemaining", pausedRemainingSec},
            {"pausedMinutesRemaining", static_cast<std::uint32_t>((pausedRemainingSec + 59u) / 60u)},
            {"failedModulesCount", static_cast<std::uint32_t>(failedCount)},
            {"modulesCount",      static_cast<std::uint32_t>(modules.size())}
        };
        svc.SendResponseEnvelope(clientId, CommandType::GetStatus, requestId, resp.dump());
    });

    // ==========================================================================
    // 250 — GetDashboard
    // ==========================================================================
    svc.RegisterV2Handler(CommandType::GetDashboard,
        [&svc, CheckAuth](std::uint64_t clientId, std::uint32_t,
                           std::uint64_t requestId, std::string_view)
    {
        if (CheckAuth(clientId, requestId, CommandType::GetDashboard)) return;
        SS_LOG_INFO(kLogCat, L"GetDashboard clientId=%llu req=%llu", clientId, requestId);

        const auto headline = HeadlineStateService::Instance().Snapshot();
        const auto recs     = RecommendationsEngine::Instance().Snapshot();

        ReportQuery q;
        q.kind        = ReportKind::ThreatDetected;
        q.max_entries = 100;
        const auto threats = HomeReportsStore::Instance().Query(q);

        nlohmann::json resp{
            {"ok",                   true},
            {"headlineState",        StateToString(headline.state)},
            {"primaryKey",           headline.primaryKey},
            {"secondaryKey",         headline.secondaryKey},
            {"criticalCount",        headline.criticalCount},
            {"atRiskCount",          headline.atRiskCount},
            {"recommendationsCount", static_cast<std::uint32_t>(recs.size())},
            {"recentThreatsCount",   static_cast<std::uint32_t>(threats.size())}
        };
        svc.SendResponseEnvelope(clientId, CommandType::GetDashboard, requestId, resp.dump());
    });

    // ==========================================================================
    // 260 — SubscribeEvents (acknowledged; push is automatic after auth)
    // ==========================================================================
    svc.RegisterV2Handler(CommandType::SubscribeEvents,
        [&svc, CheckAuth](std::uint64_t clientId, std::uint32_t,
                           std::uint64_t requestId, std::string_view)
    {
        if (CheckAuth(clientId, requestId, CommandType::SubscribeEvents)) return;
        SS_LOG_INFO(kLogCat, L"SubscribeEvents clientId=%llu req=%llu", clientId, requestId);
        svc.SendResponseEnvelope(clientId, CommandType::SubscribeEvents, requestId,
            MakeOk().dump());
    });

    // ==========================================================================
    // 30 — UpdateConfig
    // ==========================================================================
    svc.RegisterV2Handler(CommandType::UpdateConfig,
        [&svc, CheckAuth, ParseOrReject](std::uint64_t clientId, std::uint32_t,
                                          std::uint64_t requestId, std::string_view raw)
    {
        if (CheckAuth(clientId, requestId, CommandType::UpdateConfig)) return;

        auto j = ParseOrReject(clientId, requestId, CommandType::UpdateConfig, raw);
        if (j.is_discarded()) return;

        // Compatibility shortcut: {globalMode: int}
        if (j.contains("globalMode")) {
            const auto mode = Field<int>(j, "globalMode");
            if (!mode || *mode < 0 || *mode > 3) {
                svc.SendResponseEnvelope(clientId, CommandType::UpdateConfig, requestId,
                    MakeErrorResponse("invalid_value",
                        "globalMode must be 0-3").dump());
                return;
            }
            SS_LOG_INFO(kLogCat, L"UpdateConfig globalMode clientId=%llu", clientId);
            if (!ConfigManager::Instance().SetValue("Home/GlobalMode", *mode)) {
                svc.SendResponseEnvelope(clientId, CommandType::UpdateConfig, requestId,
                    MakeErrorResponse("config_write_failed", "globalMode could not be persisted").dump());
                return;
            }
            svc.SendResponseEnvelope(clientId, CommandType::UpdateConfig, requestId,
                MakeOk().dump());
            return;
        }

        const auto key = Field<std::string>(j, "key");
        if (!key) {
            svc.SendResponseEnvelope(clientId, CommandType::UpdateConfig, requestId,
                MakeErrorResponse("missing_field", "key is required").dump());
            return;
        }
        if (!Impl::IsAllowedConfigKey(*key)) {
            svc.SendResponseEnvelope(clientId, CommandType::UpdateConfig, requestId,
                MakeErrorResponse("forbidden_key",
                    "Only Home/* keys are writable via IPC").dump());
            return;
        }

        SS_LOG_INFO(kLogCat, L"UpdateConfig key=[%hs] clientId=%llu", key->c_str(), clientId);

        if (!j.contains("value")) {
            svc.SendResponseEnvelope(clientId, CommandType::UpdateConfig, requestId,
                MakeErrorResponse("missing_field", "value is required").dump());
            return;
        }
        const auto& valNode = j["value"];
        bool persisted = false;
        if (valNode.is_string()) {
            persisted = ConfigManager::Instance().SetValue(*key, valNode.get<std::string>());
        } else if (valNode.is_number_integer()) {
            persisted = ConfigManager::Instance().SetValue(*key, valNode.get<int32_t>());
        } else if (valNode.is_boolean()) {
            persisted = ConfigManager::Instance().SetValue(*key, valNode.get<bool>());
        } else {
            svc.SendResponseEnvelope(clientId, CommandType::UpdateConfig, requestId,
                MakeErrorResponse("unsupported_type",
                    "value must be string, integer, or boolean").dump());
            return;
        }

        if (!persisted) {
            svc.SendResponseEnvelope(clientId, CommandType::UpdateConfig, requestId,
                MakeErrorResponse("config_write_failed", "configuration value could not be persisted").dump());
            return;
        }

        svc.SendResponseEnvelope(clientId, CommandType::UpdateConfig, requestId,
            MakeOk().dump());
    });

    // ==========================================================================
    // 31 — GetConfig
    // ==========================================================================
    svc.RegisterV2Handler(CommandType::GetConfig,
        [&svc, CheckAuth, ParseOrReject](std::uint64_t clientId, std::uint32_t,
                                          std::uint64_t requestId, std::string_view raw)
    {
        if (CheckAuth(clientId, requestId, CommandType::GetConfig)) return;

        nlohmann::json prefix_j;
        std::string prefix = "Home/";
        if (!raw.empty()) {
            prefix_j = ParseOrReject(clientId, requestId, CommandType::GetConfig, raw);
            if (prefix_j.is_discarded()) return;
            prefix = Field<std::string>(prefix_j, "prefix").value_or("Home/");
        }

        if (!Impl::IsAllowedConfigPrefix(prefix)) {
            svc.SendResponseEnvelope(clientId, CommandType::GetConfig, requestId,
                MakeErrorResponse("forbidden_prefix",
                    "Only Home/* prefixes are readable").dump());
            return;
        }

        SS_LOG_INFO(kLogCat, L"GetConfig prefix=[%hs] clientId=%llu", prefix.c_str(), clientId);

        const auto allKeys = ConfigManager::Instance().GetAllKeys();
        nlohmann::json values = nlohmann::json::object();
        for (const auto& k : allKeys) {
            if (k.size() < prefix.size() || k.substr(0, prefix.size()) != prefix)
                continue;
            const auto cv = ConfigManager::Instance().GetRawValue(k);
            values[k] = ConfigValueToJson(cv);
        }

        nlohmann::json resp{{"ok", true}, {"values", std::move(values)}};
        svc.SendResponseEnvelope(clientId, CommandType::GetConfig, requestId, resp.dump());
    });

    // ==========================================================================
    // 200 — ListModules
    // ==========================================================================
    svc.RegisterV2Handler(CommandType::ListModules,
        [&svc, CheckAuth](std::uint64_t clientId, std::uint32_t,
                           std::uint64_t requestId, std::string_view)
    {
        if (CheckAuth(clientId, requestId, CommandType::ListModules)) return;
        SS_LOG_INFO(kLogCat, L"ListModules clientId=%llu req=%llu", clientId, requestId);

        const auto& orch    = HomeProductOrchestrator::Instance();
        const auto& catalog = ModuleCatalog::Instance();
        const auto  statuses = orch.GetStatus();

        nlohmann::json items = nlohmann::json::array();
        for (const auto& ms : statuses) {
            nlohmann::json entry{
                {"id",          ms.name},
                {"displayName", ms.displayName.empty() ? ms.name : ms.displayName},
                {"group",       ms.group},
                {"phase",       static_cast<int>(ms.phase)},
                {"state",       static_cast<int>(ms.state)},
                {"currentMode", static_cast<int>(ms.currentMode)},
                {"lastError",   ms.lastError}
            };

            switch (ms.state) {
            case ModuleState::Initialized:
            case ModuleState::Running:
                entry["statusHealth"] = 0;
                entry["statusLabel"] = "healthy";
                break;
            case ModuleState::Failed:
                entry["statusHealth"] = 2;
                entry["statusLabel"] = "critical";
                break;
            case ModuleState::Disabled:
            case ModuleState::Stopped:
                entry["statusHealth"] = -1;
                entry["statusLabel"] = "off";
                break;
            case ModuleState::Registered:
            case ModuleState::Unregistered:
            default:
                entry["statusHealth"] = 1;
                entry["statusLabel"] = "warning";
                break;
            }
            if (!ms.lastError.empty()) {
                entry["statusDetail"] = ms.lastError;
            }

            if (const CatalogEntry* cat = catalog.FindById(ms.name)) {
                entry["displayNameKey"]     = cat->displayNameKey;
                entry["descriptionKey"]     = cat->descriptionKey;
                entry["iconId"]             = cat->iconId;
                entry["category"]           = static_cast<int>(cat->category);
                entry["supportedModesMask"] = cat->supportedModesMask;
                entry["binary"]             = cat->binary;
                entry["detailPage"]         = cat->detailPage;
                entry["premium"]            = cat->premium;
            }

            items.push_back(std::move(entry));
            if (items.size() >= kMaxListItems) break;
        }

        nlohmann::json resp{{"ok", true}, {"modules", std::move(items)}};
        svc.SendResponseEnvelope(clientId, CommandType::ListModules, requestId, resp.dump());
    });

    // ==========================================================================
    // 201 — SetModuleEnabled
    // ==========================================================================
    svc.RegisterV2Handler(CommandType::SetModuleEnabled,
        [&svc, CheckAuth, ParseOrReject](std::uint64_t clientId, std::uint32_t,
                                          std::uint64_t requestId, std::string_view raw)
    {
        if (CheckAuth(clientId, requestId, CommandType::SetModuleEnabled)) return;

        auto j = ParseOrReject(clientId, requestId, CommandType::SetModuleEnabled, raw);
        if (j.is_discarded()) return;

        const auto id      = Field<std::string>(j, "id");
        const auto enabled = Field<bool>(j, "enabled");
        if (!id || !enabled.has_value()) {
            svc.SendResponseEnvelope(clientId, CommandType::SetModuleEnabled, requestId,
                MakeErrorResponse("missing_field", "id and enabled are required").dump());
            return;
        }

        SS_LOG_INFO(kLogCat, L"SetModuleEnabled id=[%hs] enabled=%d clientId=%llu",
            id->c_str(), *enabled ? 1 : 0, clientId);

        const ProtectionMode targetMode =
            *enabled ? ProtectionMode::Balanced : ProtectionMode::Off;
        const bool ok = HomeProductOrchestrator::Instance().SetModuleMode(*id, targetMode);

        nlohmann::json resp{{"ok", ok}};
        if (!ok) {
            resp["error"] = {{"code","module_not_found"},
                             {"message","Unknown module id"}};
        }
        svc.SendResponseEnvelope(clientId, CommandType::SetModuleEnabled, requestId,
            resp.dump());
    });

    // ==========================================================================
    // 202 — SetModuleMode
    // ==========================================================================
    svc.RegisterV2Handler(CommandType::SetModuleMode,
        [&svc, CheckAuth, ParseOrReject](std::uint64_t clientId, std::uint32_t,
                                          std::uint64_t requestId, std::string_view raw)
    {
        if (CheckAuth(clientId, requestId, CommandType::SetModuleMode)) return;

        auto j = ParseOrReject(clientId, requestId, CommandType::SetModuleMode, raw);
        if (j.is_discarded()) return;

        const auto id   = Field<std::string>(j, "id");
        const auto mode = Field<int>(j, "mode");
        if (!id || !mode) {
            svc.SendResponseEnvelope(clientId, CommandType::SetModuleMode, requestId,
                MakeErrorResponse("missing_field", "id and mode are required").dump());
            return;
        }
        if (*mode < 0 || *mode > 3) {
            svc.SendResponseEnvelope(clientId, CommandType::SetModuleMode, requestId,
                MakeErrorResponse("invalid_value", "mode must be 0-3").dump());
            return;
        }

        SS_LOG_INFO(kLogCat, L"SetModuleMode id=[%hs] mode=%d clientId=%llu",
            id->c_str(), *mode, clientId);

        const ProtectionMode pm = static_cast<ProtectionMode>(*mode);
        const bool ok = HomeProductOrchestrator::Instance().SetModuleMode(*id, pm);

        nlohmann::json resp{{"ok", ok}};
        if (ok) {
            resp["currentMode"] = *mode;
        } else {
            resp["error"] = {{"code","module_not_found"},
                             {"message","Unknown module id or mode not supported"}};
        }
        svc.SendResponseEnvelope(clientId, CommandType::SetModuleMode, requestId, resp.dump());
    });

    // ==========================================================================
    // 210 — PauseProtection
    // ==========================================================================
    svc.RegisterV2Handler(CommandType::PauseProtection,
        [&svc, impl, CheckAuth, ParseOrReject](std::uint64_t clientId, std::uint32_t,
                                                std::uint64_t requestId, std::string_view raw)
    {
        if (CheckAuth(clientId, requestId, CommandType::PauseProtection)) return;

        auto j = ParseOrReject(clientId, requestId, CommandType::PauseProtection, raw);
        if (j.is_discarded()) return;

        const int minutes = Field<int>(j, "minutes").value_or(15);
        if (minutes < 1 || minutes > 1440) {
            svc.SendResponseEnvelope(clientId, CommandType::PauseProtection, requestId,
                MakeErrorResponse("invalid_value", "minutes must be 1-1440").dump());
            return;
        }

        SS_LOG_INFO(kLogCat, L"PauseProtection minutes=%d clientId=%llu", minutes, clientId);

        HomeProductOrchestrator::Instance().PauseAllModules();
        impl->ScheduleResume(std::chrono::seconds(static_cast<int64_t>(minutes) * 60));

        const auto ev = Events::BuildProtectionStateChanged("paused", "user-requested pause");
        if (!ev.empty()) {
            const auto delivered = svc.BroadcastEvent(CommandType::ProtectionStateChanged, ev);
            LogBroadcastResult(L"pause protection-state", delivered);
        }

        nlohmann::json resp{{"ok", true}, {"pausedRemainingSec", minutes * 60}};
        svc.SendResponseEnvelope(clientId, CommandType::PauseProtection, requestId, resp.dump());
    });

    // ==========================================================================
    // 211 — ResumeProtection
    // ==========================================================================
    svc.RegisterV2Handler(CommandType::ResumeProtection,
        [&svc, impl, CheckAuth](std::uint64_t clientId, std::uint32_t,
                                 std::uint64_t requestId, std::string_view)
    {
        if (CheckAuth(clientId, requestId, CommandType::ResumeProtection)) return;
        SS_LOG_INFO(kLogCat, L"ResumeProtection clientId=%llu", clientId);

        HomeProductOrchestrator::Instance().ResumeAllModules();
        {
            std::lock_guard<std::mutex> lk(impl->pauseMutex);
            impl->pauseEndTime.reset();
        }

        const auto ev = Events::BuildProtectionStateChanged("active", "user-requested resume");
        if (!ev.empty()) {
            const auto delivered = svc.BroadcastEvent(CommandType::ProtectionStateChanged, ev);
            LogBroadcastResult(L"resume protection-state", delivered);
        }

        svc.SendResponseEnvelope(clientId, CommandType::ResumeProtection, requestId,
            MakeOk().dump());
    });

    // ==========================================================================
    // StartScan  (CommandType::StartScan = 20, also routed via 220)
    // ==========================================================================
    auto StartScanHandler = [&svc, impl, CheckAuth, ParseOrReject](
        std::uint64_t clientId, std::uint32_t, std::uint64_t requestId,
        std::string_view raw)
    {
        if (CheckAuth(clientId, requestId, CommandType::StartScan)) return;

        auto j = ParseOrReject(clientId, requestId, CommandType::StartScan, raw);
        if (j.is_discarded()) return;

        const auto scope = Field<std::string>(j, "scope").value_or("fast");
        SS_LOG_INFO(kLogCat, L"StartScan scope=[%hs] clientId=%llu", scope.c_str(), clientId);

        auto rec = std::make_shared<Impl::ScanRecord>();
        rec->scanId = impl->NewScanId();
        const std::string scanId = rec->scanId;

        // Set BEFORE AddScan publishes the record, so no lookup can ever
        // observe a scan whose scope is still the default. The target list
        // cannot be set here because it is only parsed inside the custom
        // branch below, which is why that branch takes the lock.
        rec->scope = scope;

        // Register the record in the activeScans map *before* spawning the
        // async task or the watcher thread. The progress callback and the
        // watcher both look the record up by id via FindScan; if AddScan
        // raced after std::async, an early progress event or a fast-completing
        // scan could observe an empty map and silently drop completion.
        impl->AddScan(rec);

        ScanProgressCallback progressCb =
            [impl, scanId, &svc](const ScanProgress& p) mutable {
                auto r = impl->FindScan(scanId);
                if (!r) return;
                r->percent.store(p.percentComplete, std::memory_order_relaxed);
                r->itemsScanned.store(p.filesScanned, std::memory_order_relaxed);

                // Relaxed for the same reason percent and itemsScanned are:
                // these are independent progress readings polled on a timer,
                // not a set of values that must be mutually consistent. A
                // reply that pairs one poll's file count with the next poll's
                // byte count is indistinguishable to a user from a reply that
                // arrived a few milliseconds later.
                r->totalFiles.store(p.totalFiles, std::memory_order_relaxed);
                r->bytesScanned.store(p.bytesScanned, std::memory_order_relaxed);
                r->filesPerSecond.store(p.filesPerSecond, std::memory_order_relaxed);
                r->bytesPerSecond.store(p.bytesPerSecond, std::memory_order_relaxed);
                r->elapsedMs.store(
                    static_cast<uint64_t>(p.elapsed.count() > 0 ? p.elapsed.count() : 0),
                    std::memory_order_relaxed);
                r->estimatedRemainingMs.store(
                    static_cast<uint64_t>(p.estimatedRemaining.count() > 0
                                          ? p.estimatedRemaining.count()
                                          : 0),
                    std::memory_order_relaxed);

                {
                    std::lock_guard<std::mutex> lk(r->stateMutex);
                    r->currentPath = p.currentFile;
                }
                // THE REAL ID, NOT A LITERAL. The UI stores whatever this event
                // carries as its current scan id, so a 0 here overwrote the id
                // StartScan had just returned and every later GetScanProgress
                // asked for a scan that does not exist - which fails, and the
                // poll then stops updating silently.
                //
                // threatsFound is read from the record rather than from p:
                // ScanProgress carries no verdict information at all, which is
                // why a literal was there. The engine reports detections per root
                // in ScanStatistics, and the watcher below folds that in.
                const auto ev = Events::BuildScanProgressEvent(
                    scanId,
                    static_cast<int>(p.percentComplete),
                    p.filesScanned,
                    r->threatsFound.load(std::memory_order_relaxed));
                if (!ev.empty()) {
                    const auto delivered = svc.BroadcastEvent(CommandType::ScanProgressEvent, ev);
                    LogBroadcastResult(L"scan progress", delivered);
                }
            };

        if (scope == "full") {
            rec->future = std::async(std::launch::async,
                [progressCb = std::move(progressCb)]() mutable {
                    return ScanEngine::Instance().FullScan(std::move(progressCb));
                });
        } else if (scope == "custom") {
            std::vector<std::wstring> paths;
            if (j.contains("paths") && j["paths"].is_array()) {
                for (const auto& p : j["paths"]) {
                    if (!p.is_string()) continue;
                    const auto s = p.get<std::string>();
                    auto wide = NarrowToWide(s);
                    if (wide.empty()) {
                        // Reject the whole request rather than silently
                        // scanning a partial path set on UTF-8 conversion
                        // failure — that would surprise the user and could be
                        // exploited to redirect scope.
                        svc.SendResponseEnvelope(clientId, CommandType::StartScan, requestId,
                            MakeErrorResponse("invalid_value",
                                "paths must contain valid UTF-8 strings").dump());
                        return;
                    }
                    paths.push_back(std::move(wide));
                }
            }
            if (paths.empty()) {
                svc.SendResponseEnvelope(clientId, CommandType::StartScan, requestId,
                    MakeErrorResponse("missing_field",
                        "paths required for custom scope").dump());
                return;
            }
            // WHAT the user asked for, recorded before the work starts so the
            // first poll can already name it.
            //
            // The full count is always exact; the list itself is capped,
            // because this reply is polled roughly twice a second and a
            // multi-hundred-file selection would put the entire path set on
            // the wire on every single poll. A UI needs enough to name the
            // target, not the whole selection.
            {
                std::lock_guard<std::mutex> lk(rec->stateMutex);
                rec->targetCount = paths.size();
                rec->targets.clear();
                for (const auto& w : paths) {
                    if (rec->targets.size() >= kMaxReportedScanTargets) break;
                    rec->targets.push_back(WideToNarrow(w));
                }
            }

            rec->future = std::async(std::launch::async,
                [p2 = std::move(paths), progressCb = std::move(progressCb)]() mutable {
                    return ScanEngine::Instance().CustomScan(p2, std::move(progressCb));
                });
        } else {
            // fast / quick (default)
            rec->future = std::async(std::launch::async,
                [progressCb = std::move(progressCb)]() mutable {
                    return ScanEngine::Instance().QuickScan(std::move(progressCb));
                });
        }

        // Watcher thread: COLLECT the outcome once the scan finishes.
        //
        // THE RESULT MUST BE TAKEN, NOT MERELY WAITED FOR. This called
        // future.wait() and returned, so the DirectoryScanResult - the only
        // object carrying what the scan actually found - was destroyed unread.
        // ScanRecord::threatsFound was declared and written by nothing, so
        // GetScanProgress reported a field with no producer and every on-demand
        // scan announced zero detections whatever it had found.
        //
        // NO TERMINAL EVENT IS BROADCAST FROM HERE, deliberately. The poll reply
        // already carries state and threatsFound, and with the id fixed above the
        // UI polling works, so a push would add nothing while capturing a
        // reference to the service in a DETACHED thread that may outlive it.
        std::thread([impl, localId = scanId]() mutable {
            auto r = impl->FindScan(localId);
            if (!r || !r->future.valid()) return;

            std::uint64_t infected = 0;
            bool failed = false;
            try {
                const DirectoryScanResult out = r->future.get();
                infected = out.statistics.filesInfected;
            } catch (const std::exception& ex) {
                // std::async re-throws the task's exception from get(). This
                // thread is detached, so letting one escape would terminate the
                // process - and reporting "completed" for a scan that threw is
                // exactly the over-claimed outcome this change removes.
                failed = true;
                SS_LOG_ERROR(kLogCat, L"Scan [%hs] failed: %hs",
                             localId.c_str(), ex.what());
            } catch (...) {
                failed = true;
                SS_LOG_ERROR(kLogCat, L"Scan [%hs] failed with a non-standard "
                             L"exception", localId.c_str());
            }

            // Only CONFIRMED detections are reported as threats. Suspicious is a
            // deliberately separate class - monitored and counted, never
            // quarantined - so folding it in here would tell a user that a
            // heuristic hit is malware. Surfacing it needs its own UI field.
            r->threatsFound.store(infected, std::memory_order_relaxed);
            {
                std::lock_guard<std::mutex> lk(r->stateMutex);
                r->stateStr = failed ? "failed" : "completed";
            }
            r->percent.store(100.0f, std::memory_order_relaxed);

            //
            // THE FIRST PRODUCER HomeReportsStore HAS EVER HAD.
            //
            // The store, its bounded ring, its Query filter, IPC command 240,
            // the view model with CSV export and a 340-line QML page were all
            // built and none of them had a writer: Record, RecordScanCompleted
            // and RecordThreatDetected had exactly four matches across the
            // whole tree - two declarations and two definitions - and ZERO
            // callers. So the Reports page rendered "No results" permanently,
            // and RecommendationsEngine rules R4 and R6, which both read this
            // store, could never fire.
            //
            // RecordScanCompleted's own declaration says "Fast-path helper used
            // by the IPC scan worker". This IS the IPC scan worker, so the
            // helper is finally called from the site it was written for rather
            // than a new one being invented beside it.
            //
            // WHY THIS SITE IS SAFE, stated because it is the question that
            // matters most here: this body runs on a DETACHED std::thread after
            // future.get() has already returned, so it is not on any kernel
            // callback. AlertSystem::RaiseAlert - the other obvious chokepoint
            // for a producer - IS reachable from
            // RealTimeProtection::OnKernelProcessNotify through the ransomware
            // fan-out, which is the callback the kernel blocks CreateProcess on,
            // so a producer there needs a non-blocking hand-off and is
            // deliberately left for its own change.
            //
            const auto scanned = r->itemsScanned.load(std::memory_order_relaxed);
            const auto elapsed =
                static_cast<std::int64_t>(r->elapsedMs.load(std::memory_order_relaxed));

            if (!failed) {
                HomeReportsStore::Instance().RecordScanCompleted(
                    localId, scanned, infected, elapsed);
            } else {
                // A SCAN THAT DID NOT FINISH IS RECORDED TOO, because "my scan
                // stopped" is exactly what a user opens this page to find out,
                // and an absent entry is indistinguishable from a scan that was
                // never started.
                //
                // RecordScanCompleted is NOT used for it: that helper's name is
                // its contract, and routing a failure through it would file the
                // failure as a completion. ReportKind has no failure member, so
                // the outcome is carried by the severity and the title instead -
                // an honest use of the vocabulary that exists rather than a new
                // enumerator added to a wire type as a side effect of this
                // change. That gap is real and named here rather than papered
                // over.
                ReportEntry entry{};
                entry.kind          = ReportKind::ScanCompleted;
                entry.severity      = ReportSeverity::Medium;
                entry.module        = "ScanEngine";
                entry.title         = "Scan did not finish";
                entry.description   =
                    "The scan stopped before completing, so its results cover "
                    "only the files reached up to that point.";
                entry.action        = "None";
                entry.scan_id       = localId;
                entry.files_scanned = scanned;
                entry.threats_found = infected;
                entry.duration_ms   = elapsed;
                HomeReportsStore::Instance().Record(std::move(entry));
            }
        }).detach();

        nlohmann::json resp{{"ok", true}, {"scanId", scanId}};
        svc.SendResponseEnvelope(clientId, CommandType::StartScan, requestId, resp.dump());
    };
    svc.RegisterV2Handler(CommandType::StartScan, StartScanHandler);
    // v2 spec numeric routing alias for StartScan
    svc.RegisterV2Handler(static_cast<CommandType>(220), StartScanHandler);

    // ==========================================================================
    // StopScan  (CommandType::StopScan = 21, also routed via 221)
    // ==========================================================================
    auto StopScanHandler = [&svc, impl, CheckAuth, ParseOrReject](
        std::uint64_t clientId, std::uint32_t, std::uint64_t requestId,
        std::string_view raw)
    {
        if (CheckAuth(clientId, requestId, CommandType::StopScan)) return;

        auto j = ParseOrReject(clientId, requestId, CommandType::StopScan, raw);
        if (j.is_discarded()) return;

        const auto scanId = Field<std::string>(j, "scanId");
        if (!scanId) {
            svc.SendResponseEnvelope(clientId, CommandType::StopScan, requestId,
                MakeErrorResponse("missing_field", "scanId is required").dump());
            return;
        }

        SS_LOG_INFO(kLogCat, L"StopScan id=[%hs] clientId=%llu", scanId->c_str(), clientId);

        auto r = impl->FindScan(*scanId);
        if (!r) {
            svc.SendResponseEnvelope(clientId, CommandType::StopScan, requestId,
                MakeErrorResponse("not_found", "Scan not found").dump());
            return;
        }
        r->cancelRequested.store(true, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lk(r->stateMutex);
            r->stateStr = "cancelled";
        }
        svc.SendResponseEnvelope(clientId, CommandType::StopScan, requestId,
            MakeOk().dump());
    };
    svc.RegisterV2Handler(CommandType::StopScan, StopScanHandler);
    svc.RegisterV2Handler(static_cast<CommandType>(221), StopScanHandler);

    // ==========================================================================
    // 222 — GetScanProgress
    // ==========================================================================
    svc.RegisterV2Handler(CommandType::GetScanProgress,
        [&svc, impl, CheckAuth, ParseOrReject](std::uint64_t clientId, std::uint32_t,
                                                std::uint64_t requestId, std::string_view raw)
    {
        if (CheckAuth(clientId, requestId, CommandType::GetScanProgress)) return;

        auto j = ParseOrReject(clientId, requestId, CommandType::GetScanProgress, raw);
        if (j.is_discarded()) return;

        const auto scanId = Field<std::string>(j, "scanId");
        if (!scanId) {
            svc.SendResponseEnvelope(clientId, CommandType::GetScanProgress, requestId,
                MakeErrorResponse("missing_field", "scanId is required").dump());
            return;
        }

        auto r = impl->FindScan(*scanId);
        if (!r) {
            svc.SendResponseEnvelope(clientId, CommandType::GetScanProgress, requestId,
                MakeErrorResponse("not_found", "Scan not found").dump());
            return;
        }

        std::string state, currentPath, scanScope;
        std::vector<std::string> scanTargets;
        std::size_t scanTargetCount = 0;
        {
            std::lock_guard<std::mutex> lk(r->stateMutex);
            state = r->stateStr;
            currentPath = WideToNarrow(r->currentPath);
            scanScope = r->scope;
            scanTargets = r->targets;
            scanTargetCount = r->targetCount;
        }

        // EVERY FIELD HERE HAS A PRODUCER, which is why totalBytes is not
        // among them: the engine leaves it unset because it cannot know the
        // total without a full pre-pass, and reporting a constant zero to a
        // progress bar is the defect this reply already carries a comment
        // about from the threatsFound case.
        nlohmann::json resp{
            {"ok",           true},
            {"state",        state},
            {"scope",        scanScope},
            {"targets",      scanTargets},
            {"targetCount",  scanTargetCount},
            {"percent",      static_cast<int>(r->percent.load(std::memory_order_relaxed))},
            {"itemsScanned", r->itemsScanned.load(std::memory_order_relaxed)},
            {"totalFiles",   r->totalFiles.load(std::memory_order_relaxed)},
            {"bytesScanned", r->bytesScanned.load(std::memory_order_relaxed)},
            {"elapsedMs",    r->elapsedMs.load(std::memory_order_relaxed)},
            {"estimatedRemainingMs",
                             r->estimatedRemainingMs.load(std::memory_order_relaxed)},
            {"filesPerSecond",
                             r->filesPerSecond.load(std::memory_order_relaxed)},
            {"bytesPerSecond",
                             r->bytesPerSecond.load(std::memory_order_relaxed)},
            {"threatsFound", r->threatsFound.load(std::memory_order_relaxed)},
            {"currentPath",  currentPath}
        };
        svc.SendResponseEnvelope(clientId, CommandType::GetScanProgress, requestId, resp.dump());
    });

    // ==========================================================================
    // 230 — ListQuarantine
    // ==========================================================================
    svc.RegisterV2Handler(CommandType::ListQuarantine,
        [&svc, CheckAuth, ParseOrReject](std::uint64_t clientId, std::uint32_t,
                                          std::uint64_t requestId, std::string_view raw)
    {
        if (CheckAuth(clientId, requestId, CommandType::ListQuarantine)) return;

        nlohmann::json j;
        if (!raw.empty()) {
            j = ParseOrReject(clientId, requestId, CommandType::ListQuarantine, raw);
            if (j.is_discarded()) return;
        }

        const std::size_t offset = static_cast<std::size_t>(
            Field<int>(j, "offset").value_or(0));
        const std::size_t limit  = std::min(
            static_cast<std::size_t>(std::max(0, Field<int>(j, "limit").value_or(50))),
            kMaxListItems);

        SS_LOG_INFO(kLogCat, L"ListQuarantine offset=%zu limit=%zu clientId=%llu",
            offset, limit, clientId);

        const auto all = QuarantineManager::Instance().GetActiveEntries();

        const std::size_t total   = all.size();
        const std::size_t start   = std::min(offset, total);
        const std::size_t end     = std::min(start + limit, total);
        const bool        hasMore = end < total;

        nlohmann::json items = nlohmann::json::array();
        for (std::size_t i = start; i < end; ++i) {
            const auto& e = all[i];
            const auto qTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                e.quarantineTime.time_since_epoch()).count();
            items.push_back({
                {"id",              std::to_string(e.entryId)},
                {"originalPath",    WideToNarrow(e.originalPath)},
                {"fileName",        WideToNarrow(e.fileName)},
                {"threatName",      WideToNarrow(e.threatName)},
                {"threatScore",     e.threatScore},
                {"priority",        static_cast<int>(e.priority)},
                {"quarantinedAtMs", qTimeMs}
            });
        }

        nlohmann::json resp{
            {"ok",    true},
            {"items", std::move(items)},
            {"total", total}
        };
        if (hasMore) resp["nextOffset"] = end;
        svc.SendResponseEnvelope(clientId, CommandType::ListQuarantine, requestId,
            resp.dump());
    });

    // ==========================================================================
    // QuarantineAction  (CommandType::QuarantineAction = 50, also 231)
    // ==========================================================================
    auto QuarantineActionHandler = [&svc, CheckAuth, ParseOrReject](
        std::uint64_t clientId, std::uint32_t, std::uint64_t requestId,
        std::string_view raw)
    {
        if (CheckAuth(clientId, requestId, CommandType::QuarantineAction)) return;

        auto j = ParseOrReject(clientId, requestId, CommandType::QuarantineAction, raw);
        if (j.is_discarded()) return;

        const auto action = Field<std::string>(j, "action");
        if (!action) {
            svc.SendResponseEnvelope(clientId, CommandType::QuarantineAction, requestId,
                MakeErrorResponse("missing_field", "action is required").dump());
            return;
        }

        SS_LOG_INFO(kLogCat, L"QuarantineAction action=[%hs] clientId=%llu",
            action->c_str(), clientId);

        auto& qm = QuarantineManager::Instance();
        bool  ok = false;

        const auto ParseEntryId = [&j]() -> std::optional<std::uint64_t> {
            if (const auto numericId = Field<std::uint64_t>(j, "id")) {
                return numericId;
            }
            if (const auto stringId = Field<std::string>(j, "id")) {
                if (stringId->empty()) {
                    return std::nullopt;
                }
                std::uint64_t parsedId = 0;
                const char* const first = stringId->data();
                const char* const last = first + stringId->size();
                const auto [ptr, ec] = std::from_chars(first, last, parsedId);
                if (ec == std::errc{} && ptr == last) {
                    return parsedId;
                }
            }
            return std::nullopt;
        };

        if (*action == "restore") {
            const auto id = ParseEntryId();
            if (!id) {
                svc.SendResponseEnvelope(clientId, CommandType::QuarantineAction, requestId,
                    MakeErrorResponse("missing_field", "id required for restore").dump());
                return;
            }
            RestoreRequest req;
            req.entryId = *id;
            ok = qm.RestoreFile(req).IsSuccess();
        } else if (*action == "delete") {
            const auto id = ParseEntryId();
            if (!id) {
                svc.SendResponseEnvelope(clientId, CommandType::QuarantineAction, requestId,
                    MakeErrorResponse("missing_field", "id required for delete").dump());
                return;
            }
            ok = qm.DeleteFile(*id);
        } else if (*action == "deleteAll") {
            ok = qm.DeleteAllEntries() > 0;
        } else {
            svc.SendResponseEnvelope(clientId, CommandType::QuarantineAction, requestId,
                MakeErrorResponse("invalid_action",
                    "action must be restore, delete, or deleteAll").dump());
            return;
        }

        nlohmann::json resp{{"ok", ok}};
        if (!ok) {
            resp["error"] = {{"code","operation_failed"},
                             {"message","Quarantine operation failed"}};
        }
        svc.SendResponseEnvelope(clientId, CommandType::QuarantineAction, requestId,
            resp.dump());
    };
    svc.RegisterV2Handler(CommandType::QuarantineAction, QuarantineActionHandler);
    svc.RegisterV2Handler(static_cast<CommandType>(231), QuarantineActionHandler);

    // ==========================================================================
    // 240 — GetReports
    // ==========================================================================
    svc.RegisterV2Handler(CommandType::GetReports,
        [&svc, CheckAuth, ParseOrReject](std::uint64_t clientId, std::uint32_t,
                                          std::uint64_t requestId, std::string_view raw)
    {
        if (CheckAuth(clientId, requestId, CommandType::GetReports)) return;

        nlohmann::json j;
        if (!raw.empty()) {
            j = ParseOrReject(clientId, requestId, CommandType::GetReports, raw);
            if (j.is_discarded()) return;
        }

        const std::size_t offset = static_cast<std::size_t>(
            Field<int>(j, "offset").value_or(0));
        const std::size_t limit  = std::min(
            static_cast<std::size_t>(std::max(0, Field<int>(j, "limit").value_or(50))),
            kMaxListItems);

        std::optional<ReportKind>     kindFilter;
        std::optional<ReportSeverity> severityFilter;
        std::optional<std::int64_t>   sinceMs;
        std::optional<std::int64_t>   untilMs;

        // THE CONSUMER SIDE OF A FILTER THAT HAD ONLY A PRODUCER.
        //
        // ReportsModel::buildFilter has always serialised a time range, and
        // this handler read neither key, so the range was silently discarded
        // on every request. It went unnoticed because the QML passed a null
        // datetime at both call sites, so the keys never reached the wire and
        // the missing consumer could not be observed from either end.
        //
        // ReportQuery::min_severity was worse: the store's Query has always
        // honoured it and nothing anywhere ever set it.
        //
        // THE RANGE IS EPOCH MILLISECONDS, NOT ISO 8601. ReportEntry stores
        // timestamp_unix_ms, so a numeric bound compares directly with no
        // conversion and no new date parser on a path that takes untrusted
        // input from the UI pipe. It also removes a real ambiguity: a local
        // QDateTime rendered with Qt::ISODate carries NO zone offset, so this
        // side could not have known which zone it was reading.
        if (j.contains("filter") && j["filter"].is_object()) {
            const auto& filter = j["filter"];

            if (const auto cat = Field<int>(filter, "category"))
                kindFilter = static_cast<ReportKind>(*cat);

            // A REJECTED FILTER MEANS "NO FILTER", AND THAT DIRECTION IS
            // DELIBERATE. This is a read-only view, so the failure that matters
            // is HIDING a report rather than showing an extra one. Clamping an
            // out-of-range severity up to Critical would conceal everything
            // below it and look exactly like a quiet machine. Refusing the
            // field shows more than asked, which is the direction a security
            // history can afford to err in.
            if (const auto sev = Field<int>(filter, "minSeverity")) {
                if (*sev >= static_cast<int>(ReportSeverity::Info) &&
                    *sev <= static_cast<int>(ReportSeverity::Critical)) {
                    severityFilter = static_cast<ReportSeverity>(*sev);
                } else {
                    SS_LOG_WARN(kLogCat, L"GetReports: minSeverity %d out of "
                        L"range, applying no severity filter", *sev);
                }
            }

            const auto rawFrom = Field<std::int64_t>(filter, "fromMs");
            const auto rawTo   = Field<std::int64_t>(filter, "toMs");

            // An INVERTED range matches nothing, and an empty page is
            // indistinguishable from a machine that recorded nothing. Refuse
            // the PAIR rather than honouring half of a request that cannot be
            // what the caller meant.
            if (rawFrom && rawTo && *rawFrom > *rawTo) {
                SS_LOG_WARN(kLogCat, L"GetReports: inverted time range, "
                    L"applying no time filter");
            } else {
                if (rawFrom && *rawFrom >= 0) sinceMs = *rawFrom;
                if (rawTo   && *rawTo   >= 0) untilMs = *rawTo;
            }
        }

        SS_LOG_INFO(kLogCat, L"GetReports offset=%zu limit=%zu clientId=%llu",
            offset, limit, clientId);

        ReportQuery q;
        q.max_entries = HomeReportsStore::kMaxEntries;
        if (kindFilter)     q.kind          = kindFilter;
        if (severityFilter) q.min_severity  = severityFilter;
        if (sinceMs)        q.since_unix_ms = sinceMs;
        if (untilMs)        q.until_unix_ms = untilMs;

        const auto all    = HomeReportsStore::Instance().Query(q);
        const std::size_t total   = all.size();
        const std::size_t start   = std::min(offset, total);
        const std::size_t end     = std::min(start + limit, total);
        const bool        hasMore = end < total;

        nlohmann::json items = nlohmann::json::array();
        for (std::size_t i = start; i < end; ++i) {
            const auto& e = all[i];
            items.push_back({
                {"id",              std::to_string(e.id)},
                {"timestampMs",     e.timestamp_unix_ms},
                {"kind",            static_cast<std::uint32_t>(e.kind)},
                {"severity",        static_cast<std::uint32_t>(e.severity)},
                {"module",          e.module},
                {"title",           e.title},
                {"description",     e.description},
                {"target",          e.target},
                {"action",          e.action},
                {"scanId",          e.scan_id},
                {"filesScanned",    e.files_scanned},
                {"threatsFound",    e.threats_found},
                {"durationMs",      e.duration_ms}
            });
        }

        nlohmann::json resp{
            {"ok",    true},
            {"items", std::move(items)},
            {"total", total}
        };
        if (hasMore) resp["nextOffset"] = end;
        svc.SendResponseEnvelope(clientId, CommandType::GetReports, requestId, resp.dump());
    });

    // ==========================================================================
    // 270 — ListPGTIFeeds
    // ==========================================================================
    svc.RegisterV2Handler(CommandType::ListPGTIFeeds,
        [&svc, CheckAuth](std::uint64_t clientId, std::uint32_t,
                           std::uint64_t requestId, std::string_view)
    {
        if (CheckAuth(clientId, requestId, CommandType::ListPGTIFeeds)) return;
        SS_LOG_INFO(kLogCat, L"ListPGTIFeeds clientId=%llu", clientId);

        const auto snapshot = PgtiFeedManager::Instance().Snapshot();

        nlohmann::json items = nlohmann::json::array();
        for (const auto& s : snapshot) {
            const char* healthStr = "disabled";
            switch (s.health) {
                case PgtiFeedStatus::Health::Healthy:  healthStr = "healthy";  break;
                case PgtiFeedStatus::Health::Degraded: healthStr = "degraded"; break;
                case PgtiFeedStatus::Health::Failed:   healthStr = "failed";   break;
                case PgtiFeedStatus::Health::Disabled: healthStr = "disabled"; break;
            }
            const auto lastSuccessTs = std::chrono::duration_cast<std::chrono::seconds>(
                s.lastSuccess.time_since_epoch()).count();
            items.push_back({
                {"id",            s.id},
                {"health",        healthStr},
                {"enabled",       s.health != PgtiFeedStatus::Health::Disabled},
                {"lastSuccessTs", lastSuccessTs},
                {"entriesLoaded", s.entriesLoaded},
                {"latencyMs",     s.latencyMs},
                {"lastErrorCode", s.lastErrorCode}
            });
            if (items.size() >= kMaxListItems) break;
        }

        nlohmann::json resp{{"ok", true}, {"feeds", std::move(items)}};
        svc.SendResponseEnvelope(clientId, CommandType::ListPGTIFeeds, requestId, resp.dump());
    });

    // ==========================================================================
    // 271 — SetPGTIFeedEnabled
    // ==========================================================================
    svc.RegisterV2Handler(CommandType::SetPGTIFeedEnabled,
        [&svc, CheckAuth, ParseOrReject](std::uint64_t clientId, std::uint32_t,
                                          std::uint64_t requestId, std::string_view raw)
    {
        if (CheckAuth(clientId, requestId, CommandType::SetPGTIFeedEnabled)) return;

        auto j = ParseOrReject(clientId, requestId, CommandType::SetPGTIFeedEnabled, raw);
        if (j.is_discarded()) return;

        const auto id      = Field<std::string>(j, "id");
        const auto enabled = Field<bool>(j, "enabled");
        if (!id || !enabled.has_value()) {
            svc.SendResponseEnvelope(clientId, CommandType::SetPGTIFeedEnabled, requestId,
                MakeErrorResponse("missing_field", "id and enabled are required").dump());
            return;
        }

        SS_LOG_INFO(kLogCat, L"SetPGTIFeedEnabled id=[%hs] enabled=%d clientId=%llu",
            id->c_str(), *enabled ? 1 : 0, clientId);

        PgtiFeedManager::Instance().SetFeedEnabled(*id, *enabled);
        svc.SendResponseEnvelope(clientId, CommandType::SetPGTIFeedEnabled, requestId,
            MakeOk().dump());
    });

    // ==========================================================================
    // 272 — RefreshPGTIFeeds
    // ==========================================================================
    svc.RegisterV2Handler(CommandType::RefreshPGTIFeeds,
        [&svc, CheckAuth](std::uint64_t clientId, std::uint32_t,
                           std::uint64_t requestId, std::string_view raw)
    {
        if (CheckAuth(clientId, requestId, CommandType::RefreshPGTIFeeds)) return;

        std::string feedId;
        if (!raw.empty()) {
            auto j = SafeParse(raw);
            if (!j.is_discarded())
                feedId = Field<std::string>(j, "id").value_or("");
        }

        SS_LOG_INFO(kLogCat, L"RefreshPGTIFeeds id=[%hs] clientId=%llu",
            feedId.c_str(), clientId);

        const bool ok = PgtiFeedManager::Instance().RefreshNow(feedId);
        nlohmann::json resp{{"ok", ok}};
        if (!ok) {
            resp["error"] = {{"code","not_found"},{"message","Feed id not found"}};
        }
        svc.SendResponseEnvelope(clientId, CommandType::RefreshPGTIFeeds, requestId,
            resp.dump());
    });

    // ==========================================================================
    // 290 — GetRecommendations
    // ==========================================================================
    svc.RegisterV2Handler(CommandType::GetRecommendations,
        [&svc, CheckAuth](std::uint64_t clientId, std::uint32_t,
                           std::uint64_t requestId, std::string_view)
    {
        if (CheckAuth(clientId, requestId, CommandType::GetRecommendations)) return;
        SS_LOG_INFO(kLogCat, L"GetRecommendations clientId=%llu", clientId);

        const auto snapshot = RecommendationsEngine::Instance().Snapshot();

        nlohmann::json items = nlohmann::json::array();
        for (const auto& r : snapshot) {
            nlohmann::json actionsArr = nlohmann::json::array();
            for (const auto& a : r.actions) {
                actionsArr.push_back({
                    {"kind",     static_cast<int>(a.kind)},
                    {"argsJson", a.argsJson},
                    {"labelKey", a.labelKey}
                });
            }
            const auto createdMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                r.createdAt.time_since_epoch()).count();
            items.push_back({
                {"id",          r.id},
                {"severity",    static_cast<int>(r.severity)},
                {"titleKey",    r.titleKey},
                {"detailKey",   r.detailKey},
                {"dismissible", r.dismissible},
                {"createdAtMs", createdMs},
                {"actions",     std::move(actionsArr)}
            });
            if (items.size() >= kMaxListItems) break;
        }

        nlohmann::json resp{{"ok", true}, {"recommendations", std::move(items)}};
        svc.SendResponseEnvelope(clientId, CommandType::GetRecommendations, requestId,
            resp.dump());
    });

    // ==========================================================================
    // 291 — DismissRecommendation
    // ==========================================================================
    svc.RegisterV2Handler(CommandType::DismissRecommendation,
        [&svc, CheckAuth, ParseOrReject](std::uint64_t clientId, std::uint32_t,
                                          std::uint64_t requestId, std::string_view raw)
    {
        if (CheckAuth(clientId, requestId, CommandType::DismissRecommendation)) return;

        auto j = ParseOrReject(clientId, requestId, CommandType::DismissRecommendation, raw);
        if (j.is_discarded()) return;

        const auto id = Field<std::string>(j, "id");
        if (!id) {
            svc.SendResponseEnvelope(clientId, CommandType::DismissRecommendation, requestId,
                MakeErrorResponse("missing_field", "id is required").dump());
            return;
        }

        SS_LOG_INFO(kLogCat, L"DismissRecommendation id=[%hs] clientId=%llu",
            id->c_str(), clientId);

        RecommendationsEngine::Instance().Dismiss(*id);
        svc.SendResponseEnvelope(clientId, CommandType::DismissRecommendation, requestId,
            MakeOk().dump());
    });

    // ==========================================================================
    // 280 — GetZeroTrustState
    // ==========================================================================
    svc.RegisterV2Handler(CommandType::GetZeroTrustState,
        [&svc, CheckAuth](std::uint64_t clientId, std::uint32_t,
                           std::uint64_t requestId, std::string_view)
    {
        if (CheckAuth(clientId, requestId, CommandType::GetZeroTrustState)) return;
        SS_LOG_INFO(kLogCat, L"GetZeroTrustState clientId=%llu", clientId);

        const ZeroTrustConfig cfg = ZeroTrustGuard::Instance().GetConfig();
        nlohmann::json prompts = nlohmann::json::array();
        for (const auto& prompt : ZeroTrustPromptQueue::Instance().Snapshot()) {
            const std::string path = WideToNarrow(prompt.imagePath);
            std::string fileName = path;
            const std::size_t slash = fileName.find_last_of("\\/");
            if (slash != std::string::npos && slash + 1u < fileName.size()) {
                fileName = fileName.substr(slash + 1u);
            }
            prompts.push_back({
                {"promptId",   std::to_string(prompt.id)},
                {"filePath",   path},
                {"fileName",   fileName},
                {"publisher",  WideToNarrow(prompt.publisherSubject)},
                {"trustScore", prompt.score}
            });
        }
        nlohmann::json resp{
            {"ok",                     true},
            {"threshold",              cfg.threshold},
            {"uncertainBand",          cfg.uncertainBand},
            {"requirePublisherSigned", cfg.requirePublisherSigned},
            {"requireWhitelist",       cfg.requireWhitelist},
            {"minReputation",          cfg.minReputation},
            {"minStaticBenign",        cfg.minStaticBenign},
            {"uncertainBehavior",      static_cast<int>(cfg.uncertainBehavior)},
            {"zeroTrustMode",          cfg.zeroTrustMode},
            {"prompts",                std::move(prompts)}
        };
        svc.SendResponseEnvelope(clientId, CommandType::GetZeroTrustState, requestId,
            resp.dump());
    });

    // ==========================================================================
    // 281 — SetZeroTrustConfig
    // ==========================================================================
    svc.RegisterV2Handler(CommandType::SetZeroTrustConfig,
        [&svc, CheckAuth, ParseOrReject](std::uint64_t clientId, std::uint32_t,
                                          std::uint64_t requestId, std::string_view raw)
    {
        if (CheckAuth(clientId, requestId, CommandType::SetZeroTrustConfig)) return;

        auto j = ParseOrReject(clientId, requestId, CommandType::SetZeroTrustConfig, raw);
        if (j.is_discarded()) return;

        // Log verb only; never log config values.
        SS_LOG_INFO(kLogCat, L"SetZeroTrustConfig clientId=%llu", clientId);

        ZeroTrustConfig cfg = ZeroTrustGuard::Instance().GetConfig();

        if (const auto v = Field<double>(j, "threshold"))
            cfg.threshold = *v;
        if (const auto v = Field<double>(j, "uncertainBand"))
            cfg.uncertainBand = *v;
        if (const auto v = Field<bool>(j, "requirePublisherSigned"))
            cfg.requirePublisherSigned = *v;
        if (const auto v = Field<bool>(j, "requireWhitelist"))
            cfg.requireWhitelist = *v;
        if (const auto v = Field<double>(j, "minReputation"))
            cfg.minReputation = *v;
        if (const auto v = Field<double>(j, "minStaticBenign"))
            cfg.minStaticBenign = *v;
        if (const auto v = Field<int>(j, "uncertainBehavior"))
            cfg.uncertainBehavior = static_cast<ZeroTrustUncertainBehavior>(*v);
        if (const auto v = Field<bool>(j, "zeroTrustMode"))
            cfg.zeroTrustMode = *v;

        if (cfg.threshold < 0.0 || cfg.threshold > 1.0) {
            svc.SendResponseEnvelope(clientId, CommandType::SetZeroTrustConfig, requestId,
                MakeErrorResponse("invalid_value",
                    "threshold must be in [0.0, 1.0]").dump());
            return;
        }
        if (cfg.uncertainBand < 0.0 || cfg.uncertainBand > 0.5) {
            svc.SendResponseEnvelope(clientId, CommandType::SetZeroTrustConfig, requestId,
                MakeErrorResponse("invalid_value",
                    "uncertainBand must be in [0.0, 0.5]").dump());
            return;
        }

        ZeroTrustGuard::Instance().SetConfig(cfg);
        svc.SendResponseEnvelope(clientId, CommandType::SetZeroTrustConfig, requestId,
            MakeOk().dump());
    });

    // ==========================================================================
    // 282 — AnswerZeroTrustPrompt
    // ==========================================================================
    svc.RegisterV2Handler(CommandType::AnswerZeroTrustPrompt,
        [&svc, CheckAuth, ParseOrReject](std::uint64_t clientId, std::uint32_t,
                                          std::uint64_t requestId, std::string_view raw)
    {
        if (CheckAuth(clientId, requestId, CommandType::AnswerZeroTrustPrompt)) return;

        auto j = ParseOrReject(clientId, requestId, CommandType::AnswerZeroTrustPrompt, raw);
        if (j.is_discarded()) return;

        const auto ParsePromptId = [&j]() -> std::optional<std::uint64_t> {
            if (const auto numericId = Field<std::uint64_t>(j, "id")) {
                return numericId;
            }
            if (const auto stringId = Field<std::string>(j, "id")) {
                if (stringId->empty()) {
                    return std::nullopt;
                }
                std::uint64_t parsedId = 0;
                const char* const first = stringId->data();
                const char* const last = first + stringId->size();
                const auto [ptr, ec] = std::from_chars(first, last, parsedId);
                if (ec == std::errc{} && ptr == last) {
                    return parsedId;
                }
            }
            return std::nullopt;
        };

        const auto id     = ParsePromptId();
        const auto choice = Field<std::string>(j, "choice");
        if (!id || !choice) {
            svc.SendResponseEnvelope(clientId, CommandType::AnswerZeroTrustPrompt, requestId,
                MakeErrorResponse("missing_field", "id and choice are required").dump());
            return;
        }

        SS_LOG_INFO(kLogCat, L"AnswerZeroTrustPrompt id=%llu choice=[%hs] clientId=%llu",
            *id, choice->c_str(), clientId);

        using UC = ZeroTrustPromptQueue::UserChoice;
        std::optional<UC> uc;
        if      (*choice == "allow")       uc = UC::Allow;
        else if (*choice == "block")       uc = UC::Block;
        else if (*choice == "alwaysAllow") uc = UC::AlwaysAllow;
        else if (*choice == "alwaysBlock") uc = UC::AlwaysBlock;

        if (!uc.has_value()) {
            svc.SendResponseEnvelope(clientId, CommandType::AnswerZeroTrustPrompt, requestId,
                MakeErrorResponse("invalid_choice",
                    "choice must be allow, block, alwaysAllow, or alwaysBlock").dump());
            return;
        }

        const bool ok = ZeroTrustPromptQueue::Instance().Resolve(*id, *uc);
        nlohmann::json resp{{"ok", ok}};
        if (!ok) {
            resp["error"] = {{"code","not_found"},
                             {"message","Prompt id not found or expired"}};
        }
        svc.SendResponseEnvelope(clientId, CommandType::AnswerZeroTrustPrompt, requestId,
            resp.dump());
    });

    SS_LOG_INFO(kLogCat, L"HomeIpcDispatcher: all handlers installed");
}

// ============================================================================
// Uninstall
// ============================================================================

void HomeIpcDispatcher::Uninstall(ServiceCommunicator& svc) {
    SS_LOG_INFO(kLogCat, L"Uninstalling HomeIpcDispatcher handlers");

    const auto noop = [](std::uint64_t, std::uint32_t,
                         std::uint64_t, std::string_view) {};

    const CommandType verbs[] = {
        CommandType::AuthHandshake,
        CommandType::GetStatus,
        CommandType::GetDashboard,
        CommandType::SubscribeEvents,
        CommandType::UpdateConfig,
        CommandType::GetConfig,
        CommandType::ListModules,
        CommandType::SetModuleEnabled,
        CommandType::SetModuleMode,
        CommandType::PauseProtection,
        CommandType::ResumeProtection,
        CommandType::StartScan,
        CommandType::StopScan,
        CommandType::GetScanProgress,
        CommandType::ListQuarantine,
        CommandType::QuarantineAction,
        CommandType::GetReports,
        CommandType::ListPGTIFeeds,
        CommandType::SetPGTIFeedEnabled,
        CommandType::RefreshPGTIFeeds,
        CommandType::GetRecommendations,
        CommandType::DismissRecommendation,
        CommandType::GetZeroTrustState,
        CommandType::SetZeroTrustConfig,
        CommandType::AnswerZeroTrustPrompt,
        static_cast<CommandType>(220),
        static_cast<CommandType>(221),
        static_cast<CommandType>(231),
    };

    for (const auto v : verbs)
        svc.RegisterV2Handler(v, noop);

    SS_LOG_INFO(kLogCat, L"HomeIpcDispatcher: all handlers uninstalled");
}

} // namespace ShadowStrike::Service
