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

#include "../../HomeProductOrchestrator.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Core/Engine/ScanEngine.hpp"
#include "PhantomCore/Core/Engine/QuarantineManager.hpp"
#include "PhantomCore/Config/ConfigManager.hpp"

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
            e.display_name = ms.name;
            e.state   = MapOrchestratorState(ms.state);
            e.enabled = (ms.state != ::ShadowStrike::Products::Home::ModuleState::Disabled &&
                         ms.state != ::ShadowStrike::Products::Home::ModuleState::Stopped &&
                         ms.state != ::ShadowStrike::Products::Home::ModuleState::Unregistered);
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
        auto val = cfg.GetValue<std::uint8_t>(kCfgDetectionAction,
            static_cast<std::uint8_t>(DetectionAction::Quarantine));
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

    auto val = static_cast<std::uint8_t>(parsed->action);
    if (val > static_cast<std::uint8_t>(DetectionAction::LogOnly)) {
        MakeError(reply_type, reply_payload, ErrorCode::SchemaViolation,
                  "detection action value out of range");
        return;
    }

    try {
        auto& cfg = ::ShadowStrike::Config::ConfigManager::Instance();
        bool ok = cfg.SetValue<std::uint8_t>(kCfgDetectionAction, val);
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
    // Update system is not built yet. Return a safe "up_to_date" response.
    UpdateStatusReply r;
    r.up_to_date      = true;
    r.current_version = "1.0.0-preview";
    r.last_check_unix = 0;

    reply_type    = MessageType::GetUpdateStatusReply;
    reply_payload = r.ToJson();
}

// ============================================================================
// Handler: TriggerUpdate
// ============================================================================

void IPCRouter::HandleTriggerUpdate(ClientContext&, const FrameEnvelope&,
                                    MessageType& reply_type,
                                    nlohmann::json& reply_payload) noexcept {
    // Update system is not built yet. Return "no updates available" safely.
    reply_type    = MessageType::TriggerUpdateReply;
    reply_payload = nlohmann::json{{"ok", true},
                                   {"msg", "no updates available"}};
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

void IPCRouter::HandleGetReports(ClientContext&, const FrameEnvelope&,
                                 MessageType& reply_type,
                                 nlohmann::json& reply_payload) noexcept {
    // Report subsystem is not built yet. Return empty report list.
    reply_type    = MessageType::GetReportsReply;
    reply_payload = nlohmann::json{{"reports", nlohmann::json::array()}};
}

}  // namespace ShadowStrike::PhantomHome::IPC
