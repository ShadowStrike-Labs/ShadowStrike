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
#include "ServiceCommunicator.hpp"
#include "IpcAuthToken.hpp"
#include "EventPush.hpp"

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
#include <chrono>
#include <condition_variable>
#include <future>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <string_view>
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
            SS_LOG_WARN(kLogCat, L"AuthHandshake FAILED clientId=%llu session=%u",
                clientId, sessionId);
            sendErr("auth_failed", "Token mismatch");
            return;
        }

        svc.MarkClientAuthenticated(clientId);
        SS_LOG_INFO(kLogCat, L"AuthHandshake SUCCESS clientId=%llu session=%u",
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
        const int   gMode    = ConfigManager::Instance().GetValue<int>(
            "Home/GlobalMode", static_cast<int>(ProtectionMode::Balanced));

        nlohmann::json resp{
            {"ok",                true},
            {"globalMode",        gMode},
            {"paused",            paused},
            {"pausedRemainingSec", impl->PauseRemainingSec()},
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

        if (!Impl::IsAllowedConfigKey(prefix)) {
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
                {
                    std::lock_guard<std::mutex> lk(r->stateMutex);
                    r->currentPath = p.currentFile;
                }
                const auto ev = Events::BuildScanProgressEvent(
                    0,
                    static_cast<int>(p.percentComplete),
                    p.filesScanned,
                    0);
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

        // Watcher thread: mark scan done when future completes.
        std::thread([impl, localId = scanId]() mutable {
            auto r = impl->FindScan(localId);
            if (!r || !r->future.valid()) return;
            r->future.wait();
            {
                std::lock_guard<std::mutex> lk(r->stateMutex);
                r->stateStr = "completed";
            }
            r->percent.store(100.0f, std::memory_order_relaxed);
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

        std::string state, currentPath;
        {
            std::lock_guard<std::mutex> lk(r->stateMutex);
            state = r->stateStr;
            currentPath = WideToNarrow(r->currentPath);
        }

        nlohmann::json resp{
            {"ok",           true},
            {"state",        state},
            {"percent",      static_cast<int>(r->percent.load(std::memory_order_relaxed))},
            {"itemsScanned", r->itemsScanned.load(std::memory_order_relaxed)},
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
                {"id",              e.entryId},
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

        if (*action == "restore") {
            const auto id = Field<std::uint64_t>(j, "id");
            if (!id) {
                svc.SendResponseEnvelope(clientId, CommandType::QuarantineAction, requestId,
                    MakeErrorResponse("missing_field", "id required for restore").dump());
                return;
            }
            RestoreRequest req;
            req.entryId = *id;
            ok = qm.RestoreFile(req).IsSuccess();
        } else if (*action == "delete") {
            const auto id = Field<std::uint64_t>(j, "id");
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

        std::optional<ReportKind> kindFilter;
        if (j.contains("filter") && j["filter"].is_object()) {
            if (const auto cat = Field<int>(j["filter"], "category"))
                kindFilter = static_cast<ReportKind>(*cat);
        }

        SS_LOG_INFO(kLogCat, L"GetReports offset=%zu limit=%zu clientId=%llu",
            offset, limit, clientId);

        ReportQuery q;
        q.max_entries = HomeReportsStore::kMaxEntries;
        if (kindFilter) q.kind = kindFilter;

        const auto all    = HomeReportsStore::Instance().Query(q);
        const std::size_t total   = all.size();
        const std::size_t start   = std::min(offset, total);
        const std::size_t end     = std::min(start + limit, total);
        const bool        hasMore = end < total;

        nlohmann::json items = nlohmann::json::array();
        for (std::size_t i = start; i < end; ++i) {
            const auto& e = all[i];
            items.push_back({
                {"id",              e.id},
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
            items.push_back({
                {"id",            s.id},
                {"health",        healthStr},
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
        nlohmann::json resp{
            {"ok",                     true},
            {"threshold",              cfg.threshold},
            {"uncertainBand",          cfg.uncertainBand},
            {"requirePublisherSigned", cfg.requirePublisherSigned},
            {"requireWhitelist",       cfg.requireWhitelist},
            {"minReputation",          cfg.minReputation},
            {"minStaticBenign",        cfg.minStaticBenign},
            {"uncertainBehavior",      static_cast<int>(cfg.uncertainBehavior)},
            {"zeroTrustMode",          cfg.zeroTrustMode}
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

        const auto id     = Field<std::uint64_t>(j, "id");
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
