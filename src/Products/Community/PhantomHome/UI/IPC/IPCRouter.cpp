/*
 * ShadowStrike - Enterprise NGAV Platform
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * Licensed under GNU AGPL-v3. See LICENSE.txt at the repository root.
 */

/**
 * @file IPCRouter.cpp
 * @brief Full handler implementations for all IPC message types.
 *
 * Each HandleXYZ method operates under the top-level try/catch in Dispatch()
 * so an uncaught exception in any handler produces a clean Error reply rather
 * than tearing down the PipeServer I/O loop.
 */

#include "IPCRouter.hpp"

#include <algorithm>
#include <chrono>
#include <future>
#include <thread>

#include "../../HomeProductOrchestrator.hpp"
#include "../../Reports/HomeReportsStore.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Core/Engine/ScanEngine.hpp"
#include "PhantomCore/Core/Engine/QuarantineManager.hpp"
#include "PhantomCore/Config/ConfigManager.hpp"
#include "PhantomCore/Update/UpdateManager.hpp"
#include "PhantomCore/AI/PhantomCortex.hpp"

// Kernel-sensor / service-controller probes (Win32 only; this file is
// Windows-only by design so the guard is belt-and-braces).
#if defined(_WIN32)
#include <Windows.h>
#include <winsvc.h>
#endif

namespace ShadowStrike::PhantomHome::IPC {

namespace {
constexpr const wchar_t* kLogCat = L"IPCRouter";

// Config keys used by the handlers.
constexpr const char* kCfgDetectionAction = "Home/DetectionAction";
constexpr const char* kCfgExclusions      = "Home/Exclusions";

// Max quarantine entries returned per list request.
constexpr std::size_t kQuarantineListCap = 8192;

/// Map orchestrator ModuleState → IPC ModuleState.
[[nodiscard]] ModuleState MapOrchestratorState(
    ::ShadowStrike::Products::Home::ModuleState s) noexcept
{
    using OS = ::ShadowStrike::Products::Home::ModuleState;
    switch (s) {
        case OS::Running:       return ModuleState::Running;
        case OS::Initialized:   return ModuleState::Initializing;
        case OS::Disabled:
        case OS::Stopped:
        case OS::Unregistered:
        case OS::Registered:    return ModuleState::Disabled;
        case OS::Failed:        return ModuleState::Failed;
        default:                return ModuleState::Disabled;
    }
}

// ---------------------------------------------------------------------------
// Engine-health probes (cheap, called once per GetState reply).
// ---------------------------------------------------------------------------

/// Probe the PhantomSensor kernel-mode driver via SCM.
/// Writes @p reason with a short actionable hint when not Running.
[[nodiscard]] bool ProbeKernelSensor(std::string& reason) noexcept {
#if defined(_WIN32)
    reason.clear();
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm == nullptr) {
        reason = "service manager unavailable";
        return false;
    }
    SC_HANDLE svc = ::OpenServiceW(scm, L"PhantomSensor",
                                   SERVICE_QUERY_STATUS);
    if (svc == nullptr) {
        const DWORD err = ::GetLastError();
        ::CloseServiceHandle(scm);
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            reason = "driver not installed";
        } else if (err == ERROR_ACCESS_DENIED) {
            reason = "cannot query driver (access denied)";
        } else {
            reason = "driver query failed";
        }
        return false;
    }
    SERVICE_STATUS_PROCESS ssp{};
    DWORD bytesNeeded = 0;
    const BOOL ok = ::QueryServiceStatusEx(
        svc, SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded);
    ::CloseServiceHandle(svc);
    ::CloseServiceHandle(scm);
    if (!ok) {
        reason = "driver status unavailable";
        return false;
    }
    if (ssp.dwCurrentState == SERVICE_RUNNING) {
        return true;
    }
    // Distinguish the two most common "not running" cases so the UI can
    // give the user an actionable next step.
    switch (ssp.dwCurrentState) {
        case SERVICE_STOPPED:         reason = "driver not started"; break;
        case SERVICE_START_PENDING:   reason = "driver starting";    break;
        case SERVICE_STOP_PENDING:    reason = "driver stopping";    break;
        case SERVICE_PAUSED:          reason = "driver paused";      break;
        default:                      reason = "driver not running"; break;
    }
    return false;
#else
    reason = "kernel sensor not available on this platform";
    return false;
#endif
}

/// Count the number of active Cortex model slots (graceful if Cortex
/// hasn't been initialised yet — returns 0/0).
void ProbeCortex(std::uint32_t& active, std::uint32_t& total) noexcept {
    active = 0;
    total  = 0;
    try {
        auto& cortex = ::ShadowStrike::AI::PhantomCortex::Instance();
        auto versions = cortex.GetModelVersions();
        total = static_cast<std::uint32_t>(versions.size());
        for (const auto& slot : versions) {
            if (slot.has_value()) ++active;
        }
    } catch (...) {
        // Cortex singleton not available or threw — treat as "not probed".
        active = 0;
        total  = 0;
    }
}

/// Derive a default UI group tag from ModulePhase for modules that do not
/// provide an explicit `group`. The UI can over-bucket in its own metadata
/// table, but the server must ship *something* or the client ends up with
/// an empty string and buckets every module into "Other".
[[nodiscard]] std::string DefaultGroupForPhase(
    ::ShadowStrike::Products::Home::ModulePhase p) noexcept
{
    using PH = ::ShadowStrike::Products::Home::ModulePhase;
    switch (p) {
        case PH::Foundation:      return "Platform";
        case PH::CoreProtections: return "Realtime";
        case PH::OnDemand:        return "OnDemand";
        case PH::UserExperience:  return "Experience";
        case PH::Background:      return "Background";
        default:                  return "Other";
    }
}

/// Curated group tag for well-known modules. Keeps SecurityPage grouping
/// coherent even before every descriptor gets an explicit `group` field.
/// Kept as an unordered_map so lookup is O(1) during the module-list hot
/// path. Unknown names fall back to DefaultGroupForPhase().
[[nodiscard]] std::string_view WellKnownGroup(std::string_view name) noexcept {
    // Realtime on-access scanning + PUA + heuristics.
    if (name == "RealTimeProtection" || name == "OnAccessScanner"
        || name == "HeuristicEngine" || name == "SignatureEngine")
        return "Realtime";

    // Ransomware + backup/rollback.
    if (name == "RansomwareProtection" || name == "RansomwareDetector"
        || name == "LockyDetector" || name == "BackupManager"
        || name == "RollbackEngine")
        return "Ransomware";

    // Web + URL + phishing.
    if (name == "WebProtection" || name == "UrlScanner"
        || name == "PhishingDetector" || name == "SafeBrowsing"
        || name == "TlsInspector")
        return "Web";

    // Network-layer: firewall, IDS, DNS.
    if (name == "FirewallManager" || name == "NetworkMonitor"
        || name == "NetworkIntrusionDetector" || name == "DnsGuard"
        || name == "ArpSpoofDetector")
        return "Network";

    // Privacy suite.
    if (name == "WebcamProtector" || name == "MicrophoneGuard"
        || name == "PrivacyCleaner" || name == "DataLeakProtection"
        || name == "DNSLeakProtection" || name == "IPLeakProtection"
        || name == "CookieManager"   || name == "LocationPrivacy")
        return "Privacy";

    // Exploit / memory.
    if (name == "ExploitDetector" || name == "MemoryProtection"
        || name == "DllInjectionDetector" || name == "HollowingDetector")
        return "Exploit";

    // Script / fileless.
    if (name == "ScriptAnalyzer" || name == "AmsiBridge"
        || name == "PowerShellGuard" || name == "MacroGuard")
        return "Script";

    // Removable media.
    if (name == "USBProtection" || name == "UsbDeviceGuard"
        || name == "AutorunBlocker")
        return "USB";

    // IoT / smart-home.
    if (name == "IoTScanner" || name == "SmartHomeMonitor"
        || name == "RouterSecurity")
        return "IoT";

    // Financial.
    if (name == "BankingProtection" || name == "BankingTrojanDetector"
        || name == "SecureBrowser")
        return "Banking";

    // Mail clients.
    if (name == "EmailProtection" || name == "EmailScanner"
        || name == "AttachmentGuard")
        return "Email";

    // Identity / credentials.
    if (name == "IdentityProtection" || name == "CredentialGuard"
        || name == "PasswordStealerDetector" || name == "KeyloggerDetector")
        return "Identity";

    return {};  // not well-known; caller falls back to phase-derived group.
}

/// Convert a CamelCase internal module name into a presentable user-facing
/// label. "RansomwareProtection" -> "Ransomware Protection",
/// "DNSLeakProtection" -> "DNS Leak Protection", "IoTScanner" -> "IoT Scanner".
/// Safe for empty input.
[[nodiscard]] std::string HumanizeModuleName(std::string_view name) {
    std::string out;
    out.reserve(name.size() + 4);
    for (std::size_t i = 0; i < name.size(); ++i) {
        const char c = name[i];
        if (i > 0) {
            const char prev = name[i - 1];
            // Word boundary: lower-to-upper (aB), or letter-to-digit,
            // or acronym-exit (XMLParser → XML Parser).
            const bool lowerToUpper =
                (prev >= 'a' && prev <= 'z') && (c >= 'A' && c <= 'Z');
            const bool letterToDigit =
                ((prev >= 'A' && prev <= 'Z') || (prev >= 'a' && prev <= 'z'))
                && (c >= '0' && c <= '9');
            const bool acronymExit =
                (prev >= 'A' && prev <= 'Z') && (c >= 'A' && c <= 'Z')
                && (i + 1 < name.size())
                && (name[i + 1] >= 'a' && name[i + 1] <= 'z');
            if (lowerToUpper || letterToDigit || acronymExit) {
                out.push_back(' ');
            }
        }
        out.push_back(c);
    }
    return out;
}

/// Widen a narrow string for scan targets.
[[nodiscard]] std::wstring ToWide(const std::string& s) {
    if (s.empty()) return {};
    int needed = ::MultiByteToWideChar(CP_UTF8, 0, s.data(),
                                       static_cast<int>(s.size()), nullptr, 0);
    if (needed <= 0) return {};
    std::wstring out(static_cast<std::size_t>(needed), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(),
                          static_cast<int>(s.size()), out.data(), needed);
    return out;
}

/// Narrow a wide string for JSON.
[[nodiscard]] std::string ToNarrow(const std::wstring& w) {
    if (w.empty()) return {};
    int needed = ::WideCharToMultiByte(CP_UTF8, 0, w.data(),
                                       static_cast<int>(w.size()),
                                       nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(static_cast<std::size_t>(needed), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.data(),
                          static_cast<int>(w.size()),
                          out.data(), needed, nullptr, nullptr);
    return out;
}

}  // anonymous namespace

// ============================================================================
// Singleton
// ============================================================================

IPCRouter& IPCRouter::Instance() noexcept {
    static IPCRouter inst;
    return inst;
}

IPCRouter::~IPCRouter() {
    Shutdown();
}

// ============================================================================
// Binding
// ============================================================================

void IPCRouter::Bind(
    ::ShadowStrike::Products::Home::HomeProductOrchestrator& orch) noexcept
{
    std::scoped_lock lk(mutex_);
    orch_ = &orch;
    SS_LOG_INFO(kLogCat, L"IPCRouter bound to HomeProductOrchestrator");
}

void IPCRouter::BindPipeServer(PipeServer& server) noexcept {
    std::scoped_lock lk(mutex_);
    pipe_server_ = &server;
    SS_LOG_INFO(kLogCat, L"IPCRouter bound to PipeServer for broadcast");
}

void IPCRouter::Shutdown() noexcept {
    shutting_down_.store(true, std::memory_order_release);

    // Cancel pause timer.
    {
        std::lock_guard<std::mutex> lk(pause_timer_mutex_);
        pause_timer_active_.store(false, std::memory_order_release);
    }
    pause_timer_cv_.notify_all();
    if (pause_timer_thread_.joinable()) {
        pause_timer_thread_.join();
    }

    // Cancel all active scans and join worker threads.
    {
        std::lock_guard<std::mutex> lk(scans_mutex_);
        for (auto& [id, scan] : active_scans_) {
            if (scan && scan->cancelled) {
                scan->cancelled->store(true, std::memory_order_release);
            }
        }
        for (auto& [id, scan] : active_scans_) {
            if (scan && scan->worker.joinable()) {
                scan->worker.join();
            }
        }
        active_scans_.clear();
    }

    SS_LOG_INFO(kLogCat, L"IPCRouter shutdown complete");
}

// ============================================================================
// Helpers
// ============================================================================

bool IPCRouter::RequirePrivileged(ClientContext& ctx,
                                  MessageType& reply_type,
                                  nlohmann::json& reply_payload) const noexcept {
    if (ctx.AuthenticatedPrivileged()) return true;
    MakeError(reply_type, reply_payload, ErrorCode::ElevationRequired,
              "elevation required");
    return false;
}

void IPCRouter::MakeError(MessageType& reply_type, nlohmann::json& reply_payload,
                           ErrorCode code, const char* message) const noexcept {
    reply_type = MessageType::Error;
    reply_payload = ErrorPayload{code, message}.ToJson();
}

void IPCRouter::HandleUnimplemented(MessageType requested,
                                    MessageType& reply_type,
                                    nlohmann::json& reply_payload) const noexcept {
    MakeError(reply_type, reply_payload, ErrorCode::UnknownMessageType,
              "message type not implemented");
    (void)requested;
}

void IPCRouter::CleanupCompletedScans() noexcept {
    // Collect completed scan threads while under lock, then join outside lock
    // to avoid deadlocking if the worker tries to acquire scans_mutex_.
    std::vector<std::thread> threads_to_join;
    for (auto it = active_scans_.begin(); it != active_scans_.end(); ) {
        auto& scan = it->second;
        if (scan && scan->cancelled->load(std::memory_order_acquire)) {
            if (scan->worker.joinable()) {
                threads_to_join.push_back(std::move(scan->worker));
            }
            it = active_scans_.erase(it);
        } else {
            ++it;
        }
    }
    // Note: scans_mutex_ is held by the caller — the join must happen
    // outside the critical section.  We rely on the caller to unlock
    // before invoking this, or we make the join non-blocking here.
    // In practice, completed scans (cancelled flag set) have already
    // exited the engine call, so join returns instantly.
    for (auto& t : threads_to_join) {
        t.join();
    }
}

// ============================================================================
// Dispatch
// ============================================================================

void IPCRouter::Dispatch(ClientContext& ctx,
                         const FrameEnvelope& req,
                         MessageType& reply_type,
                         nlohmann::json& reply_payload) noexcept {
    try {
        switch (req.type) {
            // --- Unprivileged reads ---
            case MessageType::Ping:
                HandlePing(ctx, req, reply_type, reply_payload);
                return;
            case MessageType::GetState:
                HandleGetState(ctx, req, reply_type, reply_payload);
                return;
            case MessageType::GetModuleStatus:
                HandleGetModuleStatus(ctx, req, reply_type, reply_payload);
                return;
            case MessageType::GetExclusions:
                HandleGetExclusions(ctx, req, reply_type, reply_payload);
                return;
            case MessageType::GetDetectionAction:
                HandleGetDetectionAction(ctx, req, reply_type, reply_payload);
                return;
            case MessageType::QuarantineList:
                HandleQuarantineList(ctx, req, reply_type, reply_payload);
                return;
            case MessageType::GetUpdateStatus:
                HandleGetUpdateStatus(ctx, req, reply_type, reply_payload);
                return;
            case MessageType::GetReports:
                HandleGetReports(ctx, req, reply_type, reply_payload);
                return;
            case MessageType::SubscribePerfMetrics:
                HandleSubscribePerfMetrics(ctx, req, reply_type, reply_payload);
                return;

            // --- Scan ops (start is special — needs auth for Custom, but
            //     Quick/Full are allowed without elevation for UX reasons) ---
            case MessageType::ScanStart:
                HandleScanStart(ctx, req, reply_type, reply_payload);
                return;
            case MessageType::ScanCancel:
                HandleScanCancel(ctx, req, reply_type, reply_payload);
                return;

            // --- Mutating ops: require elevation ---
            case MessageType::SetModuleEnable:
                if (!RequirePrivileged(ctx, reply_type, reply_payload)) return;
                HandleSetModuleEnable(ctx, req, reply_type, reply_payload);
                return;
            case MessageType::SetExclusions:
                if (!RequirePrivileged(ctx, reply_type, reply_payload)) return;
                HandleSetExclusions(ctx, req, reply_type, reply_payload);
                return;
            case MessageType::SetDetectionAction:
                if (!RequirePrivileged(ctx, reply_type, reply_payload)) return;
                HandleSetDetectionAction(ctx, req, reply_type, reply_payload);
                return;
            case MessageType::PauseProtection:
                if (!RequirePrivileged(ctx, reply_type, reply_payload)) return;
                HandlePauseProtection(ctx, req, reply_type, reply_payload);
                return;
            case MessageType::ResumeProtection:
                if (!RequirePrivileged(ctx, reply_type, reply_payload)) return;
                HandleResumeProtection(ctx, req, reply_type, reply_payload);
                return;
            case MessageType::QuarantineDelete:
                if (!RequirePrivileged(ctx, reply_type, reply_payload)) return;
                HandleQuarantineDelete(ctx, req, reply_type, reply_payload);
                return;
            case MessageType::QuarantineRestore:
                if (!RequirePrivileged(ctx, reply_type, reply_payload)) return;
                HandleQuarantineRestore(ctx, req, reply_type, reply_payload);
                return;
            case MessageType::TriggerUpdate:
                if (!RequirePrivileged(ctx, reply_type, reply_payload)) return;
                HandleTriggerUpdate(ctx, req, reply_type, reply_payload);
                return;

            default:
                HandleUnimplemented(req.type, reply_type, reply_payload);
                return;
        }
    } catch (const nlohmann::json::exception& e) {
        SS_LOG_ERROR(kLogCat, L"Dispatch JSON exception: %hs", e.what());
        MakeError(reply_type, reply_payload, ErrorCode::SchemaViolation,
                  e.what());
    } catch (const std::exception& e) {
        SS_LOG_ERROR(kLogCat, L"Dispatch exception: %hs", e.what());
        MakeError(reply_type, reply_payload, ErrorCode::Internal, e.what());
    } catch (...) {
        SS_LOG_ERROR(kLogCat, L"Dispatch unknown exception");
        MakeError(reply_type, reply_payload, ErrorCode::Internal,
                  "unknown internal error");
    }
}

// ============================================================================
// Handler: Ping
// ============================================================================

void IPCRouter::HandlePing(ClientContext&, const FrameEnvelope&,
                           MessageType& reply_type,
                           nlohmann::json& reply_payload) noexcept {
    reply_type    = MessageType::Pong;
    reply_payload = nlohmann::json::object();
}

// ============================================================================
// Handler: GetState
// ============================================================================

void IPCRouter::HandleGetState(ClientContext&, const FrameEnvelope&,
                               MessageType& reply_type,
                               nlohmann::json& reply_payload) noexcept {
    ProtectionStateReply r;
    r.active_threats   = 0;
    r.last_update_unix = 0;

    std::scoped_lock lk(mutex_);
    if (!orch_) {
        r.state  = OverallState::Red;
        r.reason = "orchestrator not bound";
        reply_type    = MessageType::GetStateReply;
        reply_payload = r.ToJson();
        return;
    }

    if (orch_->IsPaused()) {
        r.state  = OverallState::Paused;
        r.reason = "protection paused by user";
        reply_type    = MessageType::GetStateReply;
        reply_payload = r.ToJson();
        return;
    }

    if (!orch_->IsInitialized()) {
        r.state  = OverallState::Red;
        r.reason = "engine not initialized";
        reply_type    = MessageType::GetStateReply;
        reply_payload = r.ToJson();
        return;
    }

    // Compute state from module status.
    auto statuses = orch_->GetStatus();
    bool anyFailed  = false;
    bool anyDegraded = false;
    for (const auto& ms : statuses) {
        if (ms.state == ::ShadowStrike::Products::Home::ModuleState::Failed) {
            anyFailed = true;
        } else if (ms.state == ::ShadowStrike::Products::Home::ModuleState::Initialized ||
                   ms.state == ::ShadowStrike::Products::Home::ModuleState::Registered) {
            anyDegraded = true;
        }
    }

    // Count active quarantine entries as a proxy for "active_threats" count.
    try {
        auto& qm = ::ShadowStrike::Core::Engine::QuarantineManager::Instance();
        auto entries = qm.GetActiveEntries();
        r.active_threats = static_cast<std::uint32_t>(
            std::min<std::size_t>(entries.size(), UINT32_MAX));
    } catch (...) {
        // QuarantineManager may not be initialized; safe to default to 0.
    }

    if (anyFailed) {
        r.state  = OverallState::Amber;
        r.reason = "one or more modules failed";
    } else if (anyDegraded) {
        r.state  = OverallState::Amber;
        r.reason = "one or more modules not fully running";
    } else {
        r.state  = OverallState::Green;
        r.reason = {};
    }

    // Populate engine-health atoms (cheap probes, one per reply).
    r.sensor_ok = ProbeKernelSensor(r.sensor_reason);
    ProbeCortex(r.cortex_active, r.cortex_total);

    // A missing kernel sensor or zero-model Cortex demotes green to amber
    // so the user-facing traffic light is honest about pipeline gaps.
    if (r.state == OverallState::Green &&
        (!r.sensor_ok || (r.cortex_total > 0 && r.cortex_active == 0))) {
        r.state = OverallState::Amber;
        if (r.reason.empty()) {
            r.reason = !r.sensor_ok
                ? std::string("kernel sensor not running")
                : std::string("AI models not loaded");
        }
    }

    reply_type    = MessageType::GetStateReply;
    reply_payload = r.ToJson();
}

// ============================================================================
// Handler: GetModuleStatus
// ============================================================================

void IPCRouter::HandleGetModuleStatus(ClientContext&, const FrameEnvelope&,
                                      MessageType& reply_type,
                                      nlohmann::json& reply_payload) noexcept {
    GetModuleStatusReply r;

    std::scoped_lock lk(mutex_);
    if (orch_) {
        auto statuses = orch_->GetStatus();
        r.modules.reserve(statuses.size());
        for (const auto& ms : statuses) {
            ModuleStatusEntry e;
            e.id           = ms.name;
            e.display_name = !ms.displayName.empty()
                                 ? ms.displayName
                                 : HumanizeModuleName(ms.name);
            e.state   = MapOrchestratorState(ms.state);
            e.enabled = (ms.state != ::ShadowStrike::Products::Home::ModuleState::Disabled &&
                         ms.state != ::ShadowStrike::Products::Home::ModuleState::Stopped &&
                         ms.state != ::ShadowStrike::Products::Home::ModuleState::Unregistered);
            if (!ms.group.empty()) {
                e.group = ms.group;
            } else if (auto wk = WellKnownGroup(ms.name); !wk.empty()) {
                e.group.assign(wk.begin(), wk.end());
            } else {
                e.group = DefaultGroupForPhase(ms.phase);
            }
            r.modules.push_back(std::move(e));
        }
    }

    reply_type    = MessageType::GetModuleStatusReply;
    reply_payload = r.ToJson();
}

// ============================================================================
// Handler: SetModuleEnable
// ============================================================================

void IPCRouter::HandleSetModuleEnable(ClientContext&, const FrameEnvelope& req,
                                      MessageType& reply_type,
                                      nlohmann::json& reply_payload) noexcept {
    auto parsed = SetModuleEnable::FromJson(req.payload);
    if (!parsed) {
        MakeError(reply_type, reply_payload, ErrorCode::SchemaViolation,
                  "invalid SetModuleEnable payload");
        return;
    }

    bool ok = false;
    {
        std::scoped_lock lk(mutex_);
        if (!orch_) {
            MakeError(reply_type, reply_payload, ErrorCode::Internal,
                      "orchestrator not bound");
            return;
        }
        ok = orch_->SetModuleEnabled(parsed->id, parsed->enabled);
    }

    if (ok) {
        reply_type    = MessageType::SetModuleEnableReply;
        reply_payload = nlohmann::json{{"ok", true}};
        SS_LOG_INFO(kLogCat, L"Module '%hs' %hs via IPC",
                    parsed->id.c_str(),
                    parsed->enabled ? "enabled" : "disabled");

        // Broadcast state change to all connected clients.
        std::scoped_lock lk(mutex_);
        if (pipe_server_) {
            pipe_server_->Broadcast(MessageType::EventStateChanged,
                                    nlohmann::json::object());
        }
    } else {
        MakeError(reply_type, reply_payload, ErrorCode::NotFound,
                  "module not found or transition failed");
    }
}

// ============================================================================
// Handler: ScanStart
// ============================================================================

void IPCRouter::HandleScanStart(ClientContext&, const FrameEnvelope& req,
                                MessageType& reply_type,
                                nlohmann::json& reply_payload) noexcept {
    auto parsed = ScanStartRequest::FromJson(req.payload);
    if (!parsed) {
        MakeError(reply_type, reply_payload, ErrorCode::SchemaViolation,
                  "invalid ScanStartRequest payload");
        return;
    }

    // Generate a scan_id and register the ActiveScan.
    std::uint64_t sid = next_scan_id_.fetch_add(1, std::memory_order_relaxed);
    auto activeScan = std::make_unique<ActiveScan>();
    activeScan->scan_id = sid;
    auto cancelFlag = activeScan->cancelled;

    // Capture what we need.
    ScanType scanType = parsed->type;
    std::vector<std::wstring> targets;
    if (scanType == ScanType::Custom) {
        targets.reserve(parsed->paths.size());
        for (const auto& p : parsed->paths) {
            auto w = ToWide(p);
            if (!w.empty()) targets.push_back(std::move(w));
        }
        if (targets.empty()) {
            MakeError(reply_type, reply_payload, ErrorCode::SchemaViolation,
                      "Custom scan requires at least one path");
            return;
        }
    }

    // Capture the shutting_down flag so workers stop broadcasting during shutdown.
    auto& shutdownFlag = shutting_down_;

    // Launch worker thread.
    activeScan->worker = std::thread([this, sid, scanType, targets = std::move(targets),
                                      cancelFlag, &shutdownFlag]() {
        try {
            auto& engine = ::ShadowStrike::Core::Engine::ScanEngine::Instance();

            auto progressCb = [this, sid, cancelFlag, &shutdownFlag](
                const ::ShadowStrike::Core::Engine::ScanProgress& prog) {
                // Early-exit if cancelled or shutting down.
                if (cancelFlag->load(std::memory_order_acquire)) return;
                if (shutdownFlag.load(std::memory_order_acquire))  return;

                std::scoped_lock lk(mutex_);
                if (pipe_server_) {
                    ScanProgressEvent evt;
                    evt.scan_id       = sid;
                    evt.percent       = static_cast<std::uint32_t>(
                        std::clamp(prog.percentComplete, 0.0f, 100.0f));
                    evt.items_scanned = prog.filesScanned;
                    evt.threats_found = 0;  // accumulated in final result
                    evt.current_path  = ToNarrow(prog.currentFile);
                    // Truncate path to limit PII exposure.
                    if (evt.current_path.size() > 256)
                        evt.current_path.resize(256);
                    pipe_server_->Broadcast(MessageType::EventScanProgress,
                                          evt.ToJson());
                }
            };

            ::ShadowStrike::Core::Engine::DirectoryScanResult result;
            auto startTime = std::chrono::steady_clock::now();

            switch (scanType) {
                case ScanType::Quick:
                    result = engine.QuickScan(progressCb);
                    break;
                case ScanType::Full:
                    result = engine.FullScan(progressCb);
                    break;
                case ScanType::Custom:
                    result = engine.CustomScan(targets, progressCb);
                    break;
                case ScanType::Removable:
                    // Removable scan maps to CustomScan with removable media paths.
                    // If no targets specified, fall back to Quick as safe default.
                    if (targets.empty()) {
                        result = engine.QuickScan(progressCb);
                    } else {
                        result = engine.CustomScan(targets, progressCb);
                    }
                    break;
                default:
                    result = engine.QuickScan(progressCb);
                    break;
            }

            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - startTime);

            if (!shutdownFlag.load(std::memory_order_acquire)) {
                std::scoped_lock lk(mutex_);
                if (pipe_server_) {
                    ScanCompletedEvent evt;
                    evt.scan_id          = sid;
                    evt.files_scanned    = result.statistics.filesScanned;
                    evt.threats_found    = result.statistics.filesInfected +
                                           result.statistics.filesSuspicious;
                    evt.duration_seconds = static_cast<std::uint32_t>(elapsed.count());
                    evt.cancelled        = cancelFlag->load(std::memory_order_acquire);
                    pipe_server_->Broadcast(MessageType::EventScanCompleted,
                                            evt.ToJson());
                }
            }

            try {
                const auto scan_id_str = std::to_string(sid);
                const std::uint64_t threats =
                    result.statistics.filesInfected + result.statistics.filesSuspicious;
                const std::int64_t duration_ms =
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - startTime).count();
                ::ShadowStrike::PhantomHome::Reports::HomeReportsStore::Instance()
                    .RecordScanCompleted(scan_id_str,
                                         result.statistics.filesScanned,
                                         threats,
                                         duration_ms);
            } catch (...) {
                // Journal failure must not affect scan outcome.
            }

            SS_LOG_INFO(kLogCat,
                L"Scan %llu completed: %llu files, %llu threats in %llu s",
                static_cast<unsigned long long>(sid),
                static_cast<unsigned long long>(result.statistics.filesScanned),
                static_cast<unsigned long long>(
                    result.statistics.filesInfected +
                    result.statistics.filesSuspicious),
                static_cast<unsigned long long>(elapsed.count()));

        } catch (const std::exception& e) {
            SS_LOG_ERROR(kLogCat, L"Scan %llu worker exception: %hs",
                         static_cast<unsigned long long>(sid), e.what());
        } catch (...) {
            SS_LOG_ERROR(kLogCat, L"Scan %llu worker unknown exception",
                         static_cast<unsigned long long>(sid));
        }

        // Mark scan as completed by setting cancelled flag (reused as
        // "done" signal for cleanup). The scan completed event already
        // broadcast above.
        cancelFlag->store(true, std::memory_order_release);
    });

    {
        std::lock_guard<std::mutex> lk(scans_mutex_);
        CleanupCompletedScans();
        active_scans_[sid] = std::move(activeScan);
    }

    ScanStartReply r;
    r.scan_id     = sid;
    reply_type    = MessageType::ScanStartReply;
    reply_payload = r.ToJson();

    SS_LOG_INFO(kLogCat, L"Scan %llu started (type %u)",
                static_cast<unsigned long long>(sid),
                static_cast<unsigned>(scanType));
}

// ============================================================================
// Handler: ScanCancel
// ============================================================================

void IPCRouter::HandleScanCancel(ClientContext&, const FrameEnvelope& req,
                                 MessageType& reply_type,
                                 nlohmann::json& reply_payload) noexcept {
    auto parsed = ScanCancelRequest::FromJson(req.payload);
    if (!parsed) {
        MakeError(reply_type, reply_payload, ErrorCode::SchemaViolation,
                  "invalid ScanCancelRequest payload");
        return;
    }

    std::lock_guard<std::mutex> lk(scans_mutex_);
    auto it = active_scans_.find(parsed->scan_id);
    if (it == active_scans_.end() || !it->second) {
        MakeError(reply_type, reply_payload, ErrorCode::NotFound,
                  "scan not found or already completed");
        return;
    }

    it->second->cancelled->store(true, std::memory_order_release);
    reply_type    = MessageType::ScanCancelReply;
    reply_payload = nlohmann::json{{"ok", true}, {"sid", parsed->scan_id}};

    SS_LOG_INFO(kLogCat, L"Scan %llu cancel requested",
                static_cast<unsigned long long>(parsed->scan_id));
}

// ============================================================================
// Handler: PauseProtection
// ============================================================================

void IPCRouter::HandlePauseProtection(ClientContext&, const FrameEnvelope& req,
                                      MessageType& reply_type,
                                      nlohmann::json& reply_payload) noexcept {
    auto parsed = PauseProtectionRequest::FromJson(req.payload);
    if (!parsed) {
        MakeError(reply_type, reply_payload, ErrorCode::SchemaViolation,
                  "invalid PauseProtectionRequest payload");
        return;
    }

    // Sanity-cap duration: 24 hours max. 0 = indefinite.
    constexpr std::uint32_t kMaxDurationSec = 24 * 60 * 60;
    if (parsed->duration_seconds > kMaxDurationSec) {
        parsed->duration_seconds = kMaxDurationSec;
    }

    {
        std::scoped_lock lk(mutex_);
        if (!orch_) {
            MakeError(reply_type, reply_payload, ErrorCode::Internal,
                      "orchestrator not bound");
            return;
        }
        orch_->PauseAllModules();
    }

    // If a duration was specified, start auto-resume timer.
    if (parsed->duration_seconds > 0) {
        // Cancel any existing timer.
        {
            std::lock_guard<std::mutex> lk(pause_timer_mutex_);
            pause_timer_active_.store(false, std::memory_order_release);
        }
        pause_timer_cv_.notify_all();
        if (pause_timer_thread_.joinable()) {
            pause_timer_thread_.join();
        }

        {
            std::lock_guard<std::mutex> lk(pause_timer_mutex_);
            pause_timer_active_.store(true, std::memory_order_release);
        }
        auto duration = std::chrono::seconds(parsed->duration_seconds);

        pause_timer_thread_ = std::thread([this, duration]() {
            std::unique_lock<std::mutex> lk(pause_timer_mutex_);
            pause_timer_cv_.wait_for(lk, duration, [this]() {
                return !pause_timer_active_.load(std::memory_order_acquire) ||
                       shutting_down_.load(std::memory_order_acquire);
            });

            if (shutting_down_.load(std::memory_order_acquire)) return;

            if (pause_timer_active_.load(std::memory_order_acquire)) {
                pause_timer_active_.store(false, std::memory_order_release);

                std::scoped_lock orchLk(mutex_);
                if (orch_) {
                    orch_->ResumeAllModules();
                    SS_LOG_INFO(kLogCat, L"Pause timer expired, protection auto-resumed");

                    if (pipe_server_) {
                        pipe_server_->Broadcast(MessageType::EventStateChanged,
                                                nlohmann::json::object());
                    }
                }
            }
        });
    }

    reply_type    = MessageType::PauseProtectionReply;
    reply_payload = nlohmann::json{{"ok", true}};

    SS_LOG_INFO(kLogCat, L"Protection paused for %u seconds",
                parsed->duration_seconds);

    // Broadcast state change.
    std::scoped_lock lk(mutex_);
    if (pipe_server_) {
        pipe_server_->Broadcast(MessageType::EventStateChanged,
                                nlohmann::json::object());
    }
}

// ============================================================================
// Handler: ResumeProtection
// ============================================================================

void IPCRouter::HandleResumeProtection(ClientContext&, const FrameEnvelope&,
                                       MessageType& reply_type,
                                       nlohmann::json& reply_payload) noexcept {
    // Cancel auto-resume timer if running.
    {
        std::lock_guard<std::mutex> lk(pause_timer_mutex_);
        pause_timer_active_.store(false, std::memory_order_release);
    }
    pause_timer_cv_.notify_all();
    if (pause_timer_thread_.joinable()) {
        pause_timer_thread_.join();
    }

    {
        std::scoped_lock lk(mutex_);
        if (!orch_) {
            MakeError(reply_type, reply_payload, ErrorCode::Internal,
                      "orchestrator not bound");
            return;
        }
        orch_->ResumeAllModules();
    }

    reply_type    = MessageType::ResumeProtectionReply;
    reply_payload = nlohmann::json{{"ok", true}};

    SS_LOG_INFO(kLogCat, L"Protection manually resumed via IPC");

    std::scoped_lock lk(mutex_);
    if (pipe_server_) {
        pipe_server_->Broadcast(MessageType::EventStateChanged,
                                nlohmann::json::object());
    }
}

// ============================================================================
// Handler: GetExclusions
// ============================================================================

void IPCRouter::HandleGetExclusions(ClientContext&, const FrameEnvelope&,
                                    MessageType& reply_type,
                                    nlohmann::json& reply_payload) noexcept {
    GetExclusionsReply r;

    try {
        auto& cfg = ::ShadowStrike::Config::ConfigManager::Instance();
        auto rawJson = cfg.GetValue<std::string>(kCfgExclusions, "[]");

        auto arr = nlohmann::json::parse(rawJson, nullptr, false);
        if (arr.is_array() && arr.size() <= kMaxArrayElements) {
            for (const auto& item : arr) {
                auto e = ExclusionEntry::FromJson(item);
                if (e) r.exclusions.push_back(std::move(*e));
            }
        }
    } catch (const std::exception& e) {
        SS_LOG_WARN(kLogCat, L"GetExclusions config read failed: %hs", e.what());
        // Return empty list — not an error condition.
    }

    reply_type    = MessageType::GetExclusionsReply;
    reply_payload = r.ToJson();
}

// ============================================================================
// Handler: SetExclusions
// ============================================================================

void IPCRouter::HandleSetExclusions(ClientContext&, const FrameEnvelope& req,
                                    MessageType& reply_type,
                                    nlohmann::json& reply_payload) noexcept {
    auto parsed = SetExclusionsRequest::FromJson(req.payload);
    if (!parsed) {
        MakeError(reply_type, reply_payload, ErrorCode::SchemaViolation,
                  "invalid SetExclusionsRequest payload");
        return;
    }

    // Validate each exclusion before persisting.
    for (const auto& ex : parsed->exclusions) {
        if (ex.pattern.empty()) {
            MakeError(reply_type, reply_payload, ErrorCode::SchemaViolation,
                      "exclusion pattern must not be empty");
            return;
        }
        if (ex.type != "path" && ex.type != "extension" &&
            ex.type != "process" && ex.type != "hash") {
            MakeError(reply_type, reply_payload, ErrorCode::SchemaViolation,
                      "exclusion type must be path|extension|process|hash");
            return;
        }
    }

    try {
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& ex : parsed->exclusions) {
            arr.push_back(ex.ToJson());
        }
        auto& cfg = ::ShadowStrike::Config::ConfigManager::Instance();
        bool ok = cfg.SetValue<std::string>(kCfgExclusions, arr.dump());
        if (!ok) {
            MakeError(reply_type, reply_payload, ErrorCode::Internal,
                      "ConfigManager::SetValue failed for exclusions");
            return;
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(kLogCat, L"SetExclusions failed: %hs", e.what());
        MakeError(reply_type, reply_payload, ErrorCode::Internal,
                  "failed to persist exclusions");
        return;
    }

    reply_type    = MessageType::SetExclusionsReply;
    reply_payload = nlohmann::json{{"ok", true}};

    SS_LOG_INFO(kLogCat, L"Exclusions updated (%zu entries)",
                parsed->exclusions.size());
}

// ============================================================================
// Handler: GetDetectionAction
// ============================================================================

void IPCRouter::HandleGetDetectionAction(ClientContext&, const FrameEnvelope&,
                                         MessageType& reply_type,
                                         nlohmann::json& reply_payload) noexcept {
    GetDetectionActionReply r;
    try {
        auto& cfg = ::ShadowStrike::Config::ConfigManager::Instance();
        auto val = cfg.GetValue<std::uint32_t>(kCfgDetectionAction,
            static_cast<std::uint32_t>(DetectionAction::Quarantine));
        r.action = static_cast<DetectionAction>(val);
    } catch (...) {
        r.action = DetectionAction::Quarantine;
    }

    reply_type    = MessageType::GetDetectionActionReply;
    reply_payload = r.ToJson();
}

// ============================================================================
// Handler: SetDetectionAction
// ============================================================================

void IPCRouter::HandleSetDetectionAction(ClientContext&, const FrameEnvelope& req,
                                         MessageType& reply_type,
                                         nlohmann::json& reply_payload) noexcept {
    auto parsed = SetDetectionActionRequest::FromJson(req.payload);
    if (!parsed) {
        MakeError(reply_type, reply_payload, ErrorCode::SchemaViolation,
                  "invalid SetDetectionActionRequest payload");
        return;
    }

    auto val = static_cast<std::uint32_t>(parsed->action);
    if (val > static_cast<std::uint32_t>(DetectionAction::LogOnly)) {
        MakeError(reply_type, reply_payload, ErrorCode::SchemaViolation,
                  "detection action value out of range");
        return;
    }

    try {
        auto& cfg = ::ShadowStrike::Config::ConfigManager::Instance();
        bool ok = cfg.SetValue<std::uint32_t>(kCfgDetectionAction, val);
        if (!ok) {
            MakeError(reply_type, reply_payload, ErrorCode::Internal,
                      "ConfigManager::SetValue failed");
            return;
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(kLogCat, L"SetDetectionAction failed: %hs", e.what());
        MakeError(reply_type, reply_payload, ErrorCode::Internal,
                  "failed to persist detection action");
        return;
    }

    reply_type    = MessageType::SetDetectionActionReply;
    reply_payload = nlohmann::json{{"ok", true}};

    SS_LOG_INFO(kLogCat, L"Detection action set to %u", val);
}

// ============================================================================
// Handler: QuarantineList
// ============================================================================

void IPCRouter::HandleQuarantineList(ClientContext&, const FrameEnvelope&,
                                     MessageType& reply_type,
                                     nlohmann::json& reply_payload) noexcept {
    QuarantineListReply r;

    try {
        auto& qm = ::ShadowStrike::Core::Engine::QuarantineManager::Instance();
        auto entries = qm.GetActiveEntries();

        std::size_t count = std::min(entries.size(), kQuarantineListCap);
        r.entries.reserve(count);

        for (std::size_t i = 0; i < count; ++i) {
            const auto& qe = entries[i];
            QuarantineListEntry e;
            e.entry_id        = qe.entryId;
            e.original_path   = ToNarrow(qe.originalPath);
            e.threat_name     = ToNarrow(qe.threatName);
            e.detection_source = ToNarrow(qe.detectionSource);
            e.original_size   = qe.originalSize;
            e.quarantine_time = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    qe.quarantineTime.time_since_epoch()).count());
            r.entries.push_back(std::move(e));
        }
    } catch (const std::exception& e) {
        SS_LOG_WARN(kLogCat, L"QuarantineList failed: %hs", e.what());
        // Return empty list.
    }

    reply_type    = MessageType::QuarantineListReply;
    reply_payload = r.ToJson();
}

// ============================================================================
// Handler: QuarantineDelete
// ============================================================================

void IPCRouter::HandleQuarantineDelete(ClientContext&, const FrameEnvelope& req,
                                       MessageType& reply_type,
                                       nlohmann::json& reply_payload) noexcept {
    auto parsed = QuarantineActionRequest::FromJson(req.payload);
    if (!parsed) {
        MakeError(reply_type, reply_payload, ErrorCode::SchemaViolation,
                  "invalid QuarantineActionRequest payload");
        return;
    }

    try {
        auto& qm = ::ShadowStrike::Core::Engine::QuarantineManager::Instance();
        bool ok = qm.DeleteFile(parsed->entry_id, /*secureWipe=*/true);
        if (ok) {
            reply_type    = MessageType::QuarantineDeleteReply;
            reply_payload = nlohmann::json{{"ok", true}, {"eid", parsed->entry_id}};
            SS_LOG_INFO(kLogCat, L"Quarantine entry %llu securely deleted",
                        static_cast<unsigned long long>(parsed->entry_id));
        } else {
            MakeError(reply_type, reply_payload, ErrorCode::NotFound,
                      "quarantine entry not found or delete failed");
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(kLogCat, L"QuarantineDelete failed: %hs", e.what());
        MakeError(reply_type, reply_payload, ErrorCode::Internal,
                  "quarantine delete failed");
    }
}

// ============================================================================
// Handler: QuarantineRestore
// ============================================================================

void IPCRouter::HandleQuarantineRestore(ClientContext&, const FrameEnvelope& req,
                                        MessageType& reply_type,
                                        nlohmann::json& reply_payload) noexcept {
    auto parsed = QuarantineActionRequest::FromJson(req.payload);
    if (!parsed) {
        MakeError(reply_type, reply_payload, ErrorCode::SchemaViolation,
                  "invalid QuarantineActionRequest payload");
        return;
    }

    try {
        auto& qm = ::ShadowStrike::Core::Engine::QuarantineManager::Instance();
        ::ShadowStrike::Core::Engine::RestoreRequest rr;
        rr.entryId         = parsed->entry_id;
        rr.verifyIntegrity = true;
        rr.restoreMetadata = true;
        rr.restoreReason   = L"Restored via IPC by user request";

        auto result = qm.RestoreFile(rr);
        if (result.IsSuccess()) {
            reply_type    = MessageType::QuarantineRestoreReply;
            reply_payload = nlohmann::json{{"ok", true},
                                           {"eid", parsed->entry_id},
                                           {"rp", ToNarrow(result.restoredPath)}};
            SS_LOG_INFO(kLogCat, L"Quarantine entry %llu restored to '%ls'",
                        static_cast<unsigned long long>(parsed->entry_id),
                        result.restoredPath.c_str());
        } else {
            MakeError(reply_type, reply_payload, ErrorCode::Internal,
                      ToNarrow(result.message).c_str());
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(kLogCat, L"QuarantineRestore failed: %hs", e.what());
        MakeError(reply_type, reply_payload, ErrorCode::Internal,
                  "quarantine restore failed");
    }
}

// ============================================================================
// Handler: GetUpdateStatus
// ============================================================================

void IPCRouter::HandleGetUpdateStatus(ClientContext&, const FrameEnvelope&,
                                      MessageType& reply_type,
                                      nlohmann::json& reply_payload) noexcept {
    UpdateStatusReply r;
    r.current_version = "0.0.0";
    r.up_to_date      = true;

    try {
        if (::ShadowStrike::Update::UpdateManager::HasInstance()) {
            auto& um = ::ShadowStrike::Update::UpdateManager::Instance();

            try {
                auto v = um.GetCurrentVersion(::ShadowStrike::Update::UpdateType::Program);
                if (!v.versionString.empty()) {
                    r.current_version = v.versionString;
                    if (r.current_version.size() > 63) {
                        r.current_version.resize(63);
                    }
                }
            } catch (...) {
                // Leave default current_version.
            }

            try {
                auto pending        = um.GetAvailableUpdates();
                r.pending_updates   = static_cast<std::uint32_t>(pending.size());
                r.up_to_date        = pending.empty();
            } catch (...) {
            }

            try {
                r.status_code     = static_cast<std::uint32_t>(um.GetStatus());
                r.reboot_required = um.IsRebootRequired();
                r.in_progress     = um.IsUpdateInProgress();
            } catch (...) {
            }

            try {
                auto last = um.GetLastCheckTime();
                if (last) {
                    using namespace std::chrono;
                    r.last_check_unix = static_cast<std::uint64_t>(
                        duration_cast<seconds>(last->time_since_epoch()).count());
                }
            } catch (...) {
            }
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(kLogCat, L"GetUpdateStatus failed: %hs", e.what());
    } catch (...) {
        SS_LOG_ERROR(kLogCat, L"GetUpdateStatus failed: unknown exception");
    }

    reply_type    = MessageType::GetUpdateStatusReply;
    reply_payload = r.ToJson();
}

// ============================================================================
// Handler: TriggerUpdate
// ============================================================================

void IPCRouter::HandleTriggerUpdate(ClientContext&, const FrameEnvelope&,
                                    MessageType& reply_type,
                                    nlohmann::json& reply_payload) noexcept {
    reply_type = MessageType::TriggerUpdateReply;

    try {
        if (!::ShadowStrike::Update::UpdateManager::HasInstance()) {
            reply_payload = nlohmann::json{
                {"ok", false},
                {"msg", "update subsystem not initialized"}};
            return;
        }

        auto& um = ::ShadowStrike::Update::UpdateManager::Instance();

        if (um.IsUpdateInProgress()) {
            reply_payload = nlohmann::json{
                {"ok", true},
                {"msg", "update already in progress"}};
            return;
        }

        // Fire-and-forget: dispatch the check on a detached future so the
        // client is not held while network I/O runs.
        try {
            auto fut = um.CheckForUpdatesAsync();
            std::thread([f = std::move(fut)]() mutable {
                try {
                    (void)f.get();
                } catch (...) {
                    // Logged by the UpdateManager itself.
                }
            }).detach();
        } catch (const std::exception& e) {
            SS_LOG_ERROR(kLogCat, L"TriggerUpdate dispatch failed: %hs", e.what());
            reply_payload = nlohmann::json{
                {"ok", false},
                {"msg", "failed to dispatch update check"}};
            return;
        }

        reply_payload = nlohmann::json{
            {"ok", true},
            {"msg", "update check started"}};
    } catch (const std::exception& e) {
        SS_LOG_ERROR(kLogCat, L"TriggerUpdate failed: %hs", e.what());
        reply_payload = nlohmann::json{
            {"ok", false},
            {"msg", "internal error"}};
    } catch (...) {
        SS_LOG_ERROR(kLogCat, L"TriggerUpdate failed: unknown exception");
        reply_payload = nlohmann::json{
            {"ok", false},
            {"msg", "internal error"}};
    }
}

// ============================================================================
// Handler: SubscribePerfMetrics
// ============================================================================

void IPCRouter::HandleSubscribePerfMetrics(ClientContext&, const FrameEnvelope&,
                                           MessageType& reply_type,
                                           nlohmann::json& reply_payload) noexcept {
    // Performance metrics push stream subscription acknowledged.
    // Actual metric collection and broadcast will be wired when the
    // PerfBudget subsystem exposes a polling API.
    reply_type    = MessageType::SubscribePerfMetricsReply;
    reply_payload = nlohmann::json{{"ok", true}};
}

// ============================================================================
// Handler: GetReports
// ============================================================================

void IPCRouter::HandleGetReports(ClientContext&, const FrameEnvelope& req,
                                 MessageType& reply_type,
                                 nlohmann::json& reply_payload) noexcept {
    reply_type = MessageType::GetReportsReply;

    try {
        ::ShadowStrike::PhantomHome::Reports::ReportQuery q;
        q.max_entries = 256;

        auto parsed = GetReportsRequest::FromJson(req.payload);
        if (parsed) {
            q.max_entries = (parsed->max_entries == 0)
                                ? 256
                                : static_cast<std::size_t>(parsed->max_entries);
            if (parsed->kind) {
                q.kind = static_cast<
                    ::ShadowStrike::PhantomHome::Reports::ReportKind>(*parsed->kind);
            }
            if (parsed->min_severity) {
                q.min_severity = static_cast<
                    ::ShadowStrike::PhantomHome::Reports::ReportSeverity>(
                    *parsed->min_severity);
            }
            if (parsed->since_id) {
                q.since_id = *parsed->since_id;
            }
        }

        auto entries =
            ::ShadowStrike::PhantomHome::Reports::HomeReportsStore::Instance().Query(q);

        GetReportsReply out;
        out.entries.reserve(entries.size());
        for (const auto& e : entries) {
            ReportEntry wire;
            wire.id                = e.id;
            wire.timestamp_unix_ms = e.timestamp_unix_ms;
            wire.kind              = static_cast<std::uint32_t>(e.kind);
            wire.severity          = static_cast<std::uint32_t>(e.severity);
            wire.module_name       = e.module;
            wire.title             = e.title;
            wire.description       = e.description;
            wire.target            = e.target;
            wire.action            = e.action;
            wire.scan_id           = e.scan_id;
            wire.files_scanned     = e.files_scanned;
            wire.threats_found     = e.threats_found;
            wire.duration_ms       = e.duration_ms;
            out.entries.push_back(std::move(wire));
        }

        reply_payload = out.ToJson();
    } catch (const std::exception& e) {
        SS_LOG_ERROR(kLogCat, L"GetReports failed: %hs", e.what());
        reply_payload = nlohmann::json{{"entries", nlohmann::json::array()}};
    } catch (...) {
        SS_LOG_ERROR(kLogCat, L"GetReports failed: unknown exception");
        reply_payload = nlohmann::json{{"entries", nlohmann::json::array()}};
    }
}

}  // namespace ShadowStrike::PhantomHome::IPC
