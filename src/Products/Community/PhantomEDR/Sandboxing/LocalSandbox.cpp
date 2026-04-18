/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */
#include "pch.h"
#include "Products/Community/PhantomEDR/Sandboxing/LocalSandbox.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <format>
#include <fstream>
#include <mutex>
#include <queue>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <userenv.h>
#pragma comment(lib, "Userenv.lib")

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "PhantomCore/Utils/HashUtils.hpp"

namespace ShadowStrike::Products::PhantomEDR::Sandboxing {

namespace {

using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Utils::Logger;
namespace StringUtils = ShadowStrike::Utils::StringUtils;

constexpr std::string_view kLogPrefix = "[LocalSandbox]";
constexpr uint32_t kMaxConcurrentDetonations = 4;
constexpr uint32_t kDefaultTimeoutMs = 120'000;
constexpr uint64_t kMaxJobMemoryBytes = 512ULL * 1024 * 1024; // 512 MB
constexpr uint32_t kMaxProcessesInJob = 32;

[[nodiscard]] std::string GenerateSubmissionId() {
    auto now = Clock::now().time_since_epoch();
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
    return std::format("sbx-{:016x}", static_cast<uint64_t>(ns));
}

// RAII handle wrapper
struct HandleCloser {
    void operator()(HANDLE h) const noexcept {
        if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
};
using UniqueHandle = std::unique_ptr<void, HandleCloser>;

[[nodiscard]] UniqueHandle WrapHandle(HANDLE h) {
    return UniqueHandle((h && h != INVALID_HANDLE_VALUE) ? h : nullptr);
}

} // anonymous namespace

// ============================================================================
// IMPL
// ============================================================================

class LocalSandboxImpl {
public:
    [[nodiscard]] bool Initialize() {
        std::unique_lock lk(m_mtx);
        if (m_initialized) return true;

        if (!CreateSchema()) {
            Logger::Error("{} Failed to create database schema", kLogPrefix);
            return false;
        }

        if (!PrepareSandboxDirectory()) {
            Logger::Error("{} Failed to prepare sandbox directory", kLogPrefix);
            return false;
        }

        m_shutdownFlag.store(false, std::memory_order_release);
        m_workerThread = std::jthread([this](std::stop_token st) { WorkerLoop(st); });

        m_initialized = true;
        Logger::Info("{} Initialized (max {} concurrent, sandbox dir: {})",
                     kLogPrefix, kMaxConcurrentDetonations, m_sandboxDir);
        return true;
    }

    void Shutdown() {
        std::unique_lock lk(m_mtx);
        if (!m_initialized) return;
        m_shutdownFlag.store(true, std::memory_order_release);

        lk.unlock();
        m_cv.notify_all();

        if (m_workerThread.joinable()) {
            m_workerThread.request_stop();
            m_workerThread.join();
        }

        lk.lock();
        m_initialized = false;
        Logger::Info("{} Shut down", kLogPrefix);
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        std::shared_lock lk(m_mtx);
        return m_initialized;
    }

    [[nodiscard]] std::string Submit(const SandboxSubmission& submission) {
        if (submission.filePath.empty()) {
            Logger::Warn("{} Empty file path in submission", kLogPrefix);
            return {};
        }

        auto id = GenerateSubmissionId();

        DetonationResult result;
        result.submissionId = id;
        result.filePath = submission.filePath;
        result.sha256 = submission.sha256;
        result.fileSize = submission.fileSize;
        result.trigger = submission.trigger;
        result.status = DetonationStatus::Queued;
        result.submittedAt = Clock::now();

        {
            std::unique_lock lk(m_mtx);
            m_results[id] = result;
        }

        // Enqueue for processing
        {
            std::lock_guard qlk(m_queueMtx);
            QueuedItem item;
            item.submissionId = id;
            item.filePath = submission.filePath;
            item.timeoutMs = submission.timeoutSeconds > 0
                ? submission.timeoutSeconds * 1000
                : kDefaultTimeoutMs;
            m_queue.push(std::move(item));
        }
        m_cv.notify_one();

        PersistResult(result);
        Logger::Info("{} Queued submission {} for '{}'", kLogPrefix, id, submission.filePath);
        return id;
    }

    [[nodiscard]] bool Cancel(std::string_view submissionId) {
        std::unique_lock lk(m_mtx);
        auto it = m_results.find(std::string(submissionId));
        if (it == m_results.end()) return false;

        if (it->second.status == DetonationStatus::Queued) {
            it->second.status = DetonationStatus::Cancelled;
            PersistResult(it->second);
            Logger::Info("{} Cancelled queued submission {}", kLogPrefix, submissionId);
            return true;
        }
        // Cannot cancel a running detonation safely (process may be mid-execution)
        Logger::Warn("{} Cannot cancel {} — status: {}", kLogPrefix, submissionId,
                     ToString(it->second.status));
        return false;
    }

    [[nodiscard]] std::optional<DetonationResult> GetResult(std::string_view submissionId) const {
        std::shared_lock lk(m_mtx);
        auto it = m_results.find(std::string(submissionId));
        if (it == m_results.end()) return std::nullopt;
        return it->second;
    }

    [[nodiscard]] std::vector<DetonationResult> GetResultsByHash(std::string_view sha256) const {
        std::shared_lock lk(m_mtx);
        std::vector<DetonationResult> matches;
        for (const auto& [_, r] : m_results) {
            if (r.sha256 == sha256) matches.push_back(r);
        }
        return matches;
    }

    [[nodiscard]] std::string_view BackendName() const noexcept { return "LocalSandbox"; }
    [[nodiscard]] uint32_t MaxConcurrent() const noexcept { return kMaxConcurrentDetonations; }

    [[nodiscard]] uint32_t ActiveCount() const noexcept {
        return m_activeCount.load(std::memory_order_acquire);
    }

private:
    mutable std::shared_mutex m_mtx;
    bool m_initialized = false;
    std::unordered_map<std::string, DetonationResult> m_results;
    std::string m_sandboxDir;

    // Queue
    struct QueuedItem {
        std::string submissionId;
        std::string filePath;
        uint32_t timeoutMs = kDefaultTimeoutMs;
    };

    std::mutex m_queueMtx;
    std::condition_variable m_cv;
    std::queue<QueuedItem> m_queue;
    std::atomic<bool> m_shutdownFlag{false};
    std::atomic<uint32_t> m_activeCount{0};
    std::jthread m_workerThread;

    // ========================================================================
    // SCHEMA
    // ========================================================================

    [[nodiscard]] bool CreateSchema() {
        auto& db = DatabaseManager::Instance();
        DatabaseError dbErr;
        bool ok = db.Execute(
            "CREATE TABLE IF NOT EXISTS sandbox_detonations ("
            "  submission_id TEXT PRIMARY KEY,"
            "  file_path TEXT NOT NULL,"
            "  sha256 TEXT,"
            "  file_size INTEGER DEFAULT 0,"
            "  verdict INTEGER DEFAULT 6,"
            "  status INTEGER DEFAULT 0,"
            "  trigger_type INTEGER DEFAULT 0,"
            "  threat_score INTEGER DEFAULT 0,"
            "  submitted_at INTEGER NOT NULL,"
            "  completed_at INTEGER DEFAULT 0,"
            "  duration_ms INTEGER DEFAULT 0,"
            "  behavior_tags TEXT,"
            "  mitre_ids TEXT,"
            "  error_detail TEXT"
            ");", &dbErr);
        if (!ok) {
            Logger::Error("{} Schema creation failed: {}",
                          kLogPrefix, StringUtils::ToNarrow(dbErr.message));
        }
        return ok;
    }

    // ========================================================================
    // SANDBOX DIRECTORY
    // ========================================================================

    [[nodiscard]] bool PrepareSandboxDirectory() {
        namespace fs = std::filesystem;
        try {
            auto tempDir = fs::temp_directory_path() / "ShadowStrike" / "sandbox";
            fs::create_directories(tempDir);
            m_sandboxDir = tempDir.string();
            return true;
        } catch (const std::exception& ex) {
            Logger::Error("{} Cannot create sandbox dir: {}", kLogPrefix, ex.what());
            return false;
        }
    }

    // ========================================================================
    // WORKER LOOP
    // ========================================================================

    void WorkerLoop(std::stop_token st) {
        Logger::Debug("{} Worker thread started", kLogPrefix);

        while (!st.stop_requested() && !m_shutdownFlag.load(std::memory_order_acquire)) {
            QueuedItem item;
            {
                std::unique_lock qlk(m_queueMtx);
                m_cv.wait_for(qlk, std::chrono::seconds(1), [&] {
                    return !m_queue.empty() || m_shutdownFlag.load(std::memory_order_acquire)
                        || st.stop_requested();
                });

                if (m_queue.empty()) continue;
                if (m_activeCount.load(std::memory_order_acquire) >= kMaxConcurrentDetonations) continue;

                item = std::move(m_queue.front());
                m_queue.pop();
            }

            // Check if cancelled
            {
                std::shared_lock lk(m_mtx);
                auto it = m_results.find(item.submissionId);
                if (it != m_results.end() && it->second.status == DetonationStatus::Cancelled) continue;
            }

            m_activeCount.fetch_add(1, std::memory_order_acq_rel);
            ExecuteDetonation(item);
            m_activeCount.fetch_sub(1, std::memory_order_acq_rel);
        }

        Logger::Debug("{} Worker thread stopped", kLogPrefix);
    }

    // ========================================================================
    // CORE DETONATION ENGINE
    // ========================================================================

    void ExecuteDetonation(const QueuedItem& item) {
        Logger::Info("{} Starting detonation: {} (timeout: {}ms)",
                     kLogPrefix, item.submissionId, item.timeoutMs);

        // Update status to Running
        {
            std::unique_lock lk(m_mtx);
            auto it = m_results.find(item.submissionId);
            if (it != m_results.end()) {
                it->second.status = DetonationStatus::Running;
            }
        }

        DetonationResult result;
        result.submissionId = item.submissionId;
        result.filePath = item.filePath;
        result.submittedAt = Clock::now();

        // 1. Copy file to sandbox directory
        namespace fs = std::filesystem;
        std::string sandboxedPath;
        try {
            auto srcPath = fs::path(item.filePath);
            if (!fs::exists(srcPath)) {
                result.status = DetonationStatus::Failed;
                result.errorDetail = "Source file does not exist";
                FinalizeResult(result);
                return;
            }

            auto dstDir = fs::path(m_sandboxDir) / item.submissionId;
            fs::create_directories(dstDir);

            sandboxedPath = (dstDir / srcPath.filename()).string();
            fs::copy_file(srcPath, sandboxedPath, fs::copy_options::overwrite_existing);

            result.fileSize = fs::file_size(sandboxedPath);
        } catch (const std::exception& ex) {
            result.status = DetonationStatus::Failed;
            result.errorDetail = std::format("File copy failed: {}", ex.what());
            FinalizeResult(result);
            return;
        }

        // 2. Create restricted job object
        auto hJob = WrapHandle(CreateJobObjectW(nullptr, nullptr));
        if (!hJob) {
            result.status = DetonationStatus::Failed;
            result.errorDetail = std::format("CreateJobObject failed: {}", GetLastError());
            FinalizeResult(result);
            return;
        }

        // Configure job limits
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobLimits{};
        jobLimits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
            JOB_OBJECT_LIMIT_PROCESS_MEMORY |
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
            JOB_OBJECT_LIMIT_JOB_TIME |
            JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;

        jobLimits.ProcessMemoryLimit = kMaxJobMemoryBytes;
        jobLimits.BasicLimitInformation.ActiveProcessLimit = kMaxProcessesInJob;
        // Convert timeout to 100ns intervals
        jobLimits.BasicLimitInformation.PerJobUserTimeLimit.QuadPart =
            static_cast<LONGLONG>(item.timeoutMs) * 10'000LL;

        if (!SetInformationJobObject(hJob.get(), JobObjectExtendedLimitInformation,
                                     &jobLimits, sizeof(jobLimits))) {
            result.status = DetonationStatus::Failed;
            result.errorDetail = std::format("SetInformationJobObject (limits) failed: {}", GetLastError());
            FinalizeResult(result);
            return;
        }

        // UI restrictions: no clipboard, no desktop switch, no display changes
        JOBOBJECT_BASIC_UI_RESTRICTIONS uiRestrictions{};
        uiRestrictions.UIRestrictionsClass =
            JOB_OBJECT_UILIMIT_DESKTOP |
            JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
            JOB_OBJECT_UILIMIT_EXITWINDOWS |
            JOB_OBJECT_UILIMIT_GLOBALATOMS |
            JOB_OBJECT_UILIMIT_READCLIPBOARD |
            JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |
            JOB_OBJECT_UILIMIT_WRITECLIPBOARD;

        (void)SetInformationJobObject(hJob.get(), JobObjectBasicUIRestrictions,
                                      &uiRestrictions, sizeof(uiRestrictions));

        // 3. Create restricted token
        HANDLE hPrimaryToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY |
                              TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &hPrimaryToken)) {
            result.status = DetonationStatus::Failed;
            result.errorDetail = std::format("OpenProcessToken failed: {}", GetLastError());
            FinalizeResult(result);
            return;
        }
        auto hPrimary = WrapHandle(hPrimaryToken);

        HANDLE hRestrictedToken = nullptr;
        SID_AND_ATTRIBUTES disableSids[1]{};
        // Disable Administrators group
        BYTE adminSid[SECURITY_MAX_SID_SIZE]{};
        DWORD sidSize = sizeof(adminSid);
        if (CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, adminSid, &sidSize)) {
            disableSids[0].Sid = adminSid;
            disableSids[0].Attributes = 0;
        }

        if (!CreateRestrictedToken(hPrimary.get(), DISABLE_MAX_PRIVILEGE,
                                   1, disableSids, 0, nullptr, 0, nullptr,
                                   &hRestrictedToken)) {
            result.status = DetonationStatus::Failed;
            result.errorDetail = std::format("CreateRestrictedToken failed: {}", GetLastError());
            FinalizeResult(result);
            return;
        }
        auto hRestricted = WrapHandle(hRestrictedToken);

        // 4. Launch the process in the sandbox
        auto widePath = StringUtils::ToWide(sandboxedPath);
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        PROCESS_INFORMATION pi{};
        BOOL created = CreateProcessAsUserW(
            hRestricted.get(),
            widePath.c_str(),
            nullptr,                // no command line args
            nullptr, nullptr,       // default security
            FALSE,                  // no handle inheritance
            CREATE_SUSPENDED | CREATE_NEW_CONSOLE | CREATE_BREAKAWAY_FROM_JOB,
            nullptr,                // inherit environment
            nullptr,                // inherit cwd
            &si, &pi);

        if (!created) {
            // Fallback: try CreateProcessW for non-PE files (scripts etc.)
            created = CreateProcessW(
                nullptr,
                const_cast<LPWSTR>(widePath.c_str()),
                nullptr, nullptr,
                FALSE,
                CREATE_SUSPENDED | CREATE_NEW_CONSOLE | CREATE_BREAKAWAY_FROM_JOB,
                nullptr, nullptr, &si, &pi);
        }

        if (!created) {
            result.status = DetonationStatus::Failed;
            result.errorDetail = std::format("CreateProcess failed: {}", GetLastError());
            FinalizeResult(result);
            return;
        }

        auto hProcess = WrapHandle(pi.hProcess);
        auto hThread = WrapHandle(pi.hThread);

        // Assign to job BEFORE resuming
        if (!AssignProcessToJobObject(hJob.get(), hProcess.get())) {
            Logger::Warn("{} AssignProcessToJobObject failed: {} — terminating",
                         kLogPrefix, GetLastError());
            TerminateProcess(hProcess.get(), 1);
            result.status = DetonationStatus::Failed;
            result.errorDetail = "Failed to assign process to job object";
            FinalizeResult(result);
            return;
        }

        // Resume and wait
        auto startTime = Clock::now();
        ResumeThread(hThread.get());

        DWORD waitResult = WaitForSingleObject(hProcess.get(), item.timeoutMs);
        auto endTime = Clock::now();

        result.durationMs = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count());

        if (waitResult == WAIT_TIMEOUT) {
            TerminateProcess(hProcess.get(), 0xDEAD);
            result.status = DetonationStatus::TimedOut;
            result.verdict = SandboxVerdict::Timeout;
            Logger::Warn("{} Detonation {} timed out after {}ms",
                         kLogPrefix, item.submissionId, item.timeoutMs);
        } else {
            result.status = DetonationStatus::Completed;
        }

        result.completedAt = endTime;

        // 5. Collect artifacts from sandbox directory
        CollectArtifacts(item.submissionId, result);

        // 6. Cleanup sandbox directory
        CleanupSandboxDir(item.submissionId);

        FinalizeResult(result);
    }

    // ========================================================================
    // ARTIFACT COLLECTION
    // ========================================================================

    void CollectArtifacts(const std::string& submissionId, DetonationResult& result) {
        namespace fs = std::filesystem;
        auto sandboxDir = fs::path(m_sandboxDir) / submissionId;

        try {
            // Scan for dropped files (anything beyond the original)
            uint32_t fileCount = 0;
            for (const auto& entry : fs::recursive_directory_iterator(sandboxDir,
                     fs::directory_options::skip_permission_denied)) {
                if (!entry.is_regular_file()) continue;
                if (entry.path().filename().string() == fs::path(result.filePath).filename().string()) continue;

                DroppedFile df;
                df.path = entry.path().string();
                df.size = entry.file_size();

                auto ext = entry.path().extension().string();
                df.isExecutable = (ext == ".exe" || ext == ".dll" || ext == ".bat" ||
                                   ext == ".cmd" || ext == ".ps1" || ext == ".vbs" ||
                                   ext == ".js"  || ext == ".scr");

                result.droppedFiles.push_back(std::move(df));
                ++fileCount;

                if (fileCount >= 256) break; // Cap to prevent abuse
            }

            // Assign behavior tags based on artifacts
            if (!result.droppedFiles.empty()) {
                result.behaviorTags.push_back(BehaviorTag::DropsExecutable);
            }

        } catch (const std::exception& ex) {
            Logger::Warn("{} Artifact collection error for {}: {}",
                         kLogPrefix, submissionId, ex.what());
        }
    }

    // ========================================================================
    // SCORING & VERDICT
    // ========================================================================

    void FinalizeResult(DetonationResult& result) {
        // Assign threat score and verdict based on behaviors
        if (result.status == DetonationStatus::Completed) {
            uint32_t score = 0;
            for (auto tag : result.behaviorTags) {
                switch (tag) {
                    case BehaviorTag::DropsExecutable:    score += 20; break;
                    case BehaviorTag::ModifiesRegistry:   score += 10; break;
                    case BehaviorTag::ContactsC2:         score += 40; break;
                    case BehaviorTag::InjectsProcess:     score += 35; break;
                    case BehaviorTag::CreatesService:     score += 15; break;
                    case BehaviorTag::EscalatesPrivilege: score += 30; break;
                    case BehaviorTag::EncryptsFiles:      score += 45; break;
                    case BehaviorTag::ExfiltratesData:    score += 35; break;
                    case BehaviorTag::DisablesSecurity:   score += 30; break;
                    case BehaviorTag::EvadesSandbox:      score += 25; break;
                    case BehaviorTag::StealsCredentials:  score += 40; break;
                    case BehaviorTag::ModifiesBootRecord: score += 50; break;
                    default: break;
                }
            }
            score = std::min(score, 100u);
            result.threatScore = score;

            if (score >= 70)      result.verdict = SandboxVerdict::Malicious;
            else if (score >= 40) result.verdict = SandboxVerdict::Suspicious;
            else if (score >= 20) result.verdict = SandboxVerdict::Evasive;
            else                  result.verdict = SandboxVerdict::Clean;
        }

        // Store in memory and database
        {
            std::unique_lock lk(m_mtx);
            m_results[result.submissionId] = result;
        }
        PersistResult(result);

        Logger::Info("{} Detonation {} complete: verdict={}, score={}, duration={}ms",
                     kLogPrefix, result.submissionId, ToString(result.verdict),
                     result.threatScore, result.durationMs);
    }

    // ========================================================================
    // PERSISTENCE
    // ========================================================================

    void PersistResult(const DetonationResult& r) {
        auto& db = DatabaseManager::Instance();
        DatabaseError dbErr;

        // Build behavior tags string
        std::string tags;
        for (size_t i = 0; i < r.behaviorTags.size(); ++i) {
            if (i > 0) tags += ',';
            tags += ToString(r.behaviorTags[i]);
        }

        std::string mitreIds;
        for (size_t i = 0; i < r.mitreAttackIds.size(); ++i) {
            if (i > 0) mitreIds += ',';
            mitreIds += r.mitreAttackIds[i];
        }

        auto submittedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            r.submittedAt.time_since_epoch()).count();
        auto completedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            r.completedAt.time_since_epoch()).count();

        db.ExecuteWithParams(
            "INSERT OR REPLACE INTO sandbox_detonations "
            "(submission_id, file_path, sha256, file_size, verdict, status, trigger_type,"
            " threat_score, submitted_at, completed_at, duration_ms, behavior_tags,"
            " mitre_ids, error_detail) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
            &dbErr,
            r.submissionId, r.filePath, r.sha256,
            static_cast<int64_t>(r.fileSize),
            static_cast<int>(r.verdict), static_cast<int>(r.status),
            static_cast<int>(r.trigger), static_cast<int>(r.threatScore),
            submittedMs, completedMs,
            static_cast<int>(r.durationMs), tags, mitreIds, r.errorDetail);
    }

    // ========================================================================
    // CLEANUP
    // ========================================================================

    void CleanupSandboxDir(const std::string& submissionId) {
        namespace fs = std::filesystem;
        try {
            auto dir = fs::path(m_sandboxDir) / submissionId;
            if (fs::exists(dir)) {
                fs::remove_all(dir);
            }
        } catch (const std::exception& ex) {
            Logger::Warn("{} Cleanup failed for {}: {}", kLogPrefix, submissionId, ex.what());
        }
    }
};

// ============================================================================
// PUBLIC INTERFACE
// ============================================================================

LocalSandbox::LocalSandbox() : m_impl(std::make_unique<LocalSandboxImpl>()) {}
LocalSandbox::~LocalSandbox() = default;

LocalSandbox& LocalSandbox::Instance() {
    static LocalSandbox instance;
    return instance;
}

bool LocalSandbox::Initialize() { return m_impl->Initialize(); }
void LocalSandbox::Shutdown() { m_impl->Shutdown(); }
bool LocalSandbox::IsInitialized() const noexcept { return m_impl->IsInitialized(); }
std::string LocalSandbox::Submit(const SandboxSubmission& sub) { return m_impl->Submit(sub); }
bool LocalSandbox::Cancel(std::string_view id) { return m_impl->Cancel(id); }
std::optional<DetonationResult> LocalSandbox::GetResult(std::string_view id) const { return m_impl->GetResult(id); }
std::vector<DetonationResult> LocalSandbox::GetResultsByHash(std::string_view sha256) const { return m_impl->GetResultsByHash(sha256); }
std::string_view LocalSandbox::BackendName() const noexcept { return m_impl->BackendName(); }
uint32_t LocalSandbox::MaxConcurrent() const noexcept { return m_impl->MaxConcurrent(); }
uint32_t LocalSandbox::ActiveCount() const noexcept { return m_impl->ActiveCount(); }

} // namespace ShadowStrike::Products::PhantomEDR::Sandboxing
