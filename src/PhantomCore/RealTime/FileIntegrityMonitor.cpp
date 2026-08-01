/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
/**
 * ============================================================================
 * ShadowStrike Real-Time - FILE INTEGRITY MONITOR IMPLEMENTATION
 * ============================================================================
 *
 * @file FileIntegrityMonitor.cpp
 * @brief Full implementation of the File Integrity Monitor (The Surveyor).
 *
 * Uses Windows BCrypt (via HashUtils) for cryptographic hashing,
 * ReadDirectoryChangesW for real-time change detection, and
 * PE_sig_verf for digital signature verification.
 *
 * @author ShadowStrike Security Team
 * @version 3.1.0
 */

#include "pch.h"
#include "FileIntegrityMonitor.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/ThreadPool.hpp"
#include "../Utils/PE_sig_verf.hpp"

#include <aclapi.h>
#include <sddl.h>
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <thread>

#pragma comment(lib, "version.lib")
#pragma comment(lib, "advapi32.lib")

namespace ShadowStrike {
namespace RealTime {

// ============================================================================
// CONSTEXPR STRING CONVERTERS (declared in HPP)
// ============================================================================

constexpr const char* FileChangeTypeToString(FileChangeType type) noexcept {
    switch (type) {
        case FileChangeType::None:                  return "None";
        case FileChangeType::Created:               return "Created";
        case FileChangeType::Deleted:               return "Deleted";
        case FileChangeType::Modified:              return "Modified";
        case FileChangeType::Renamed:               return "Renamed";
        case FileChangeType::Moved:                 return "Moved";
        case FileChangeType::Replaced:              return "Replaced";
        case FileChangeType::PermissionsChanged:    return "PermissionsChanged";
        case FileChangeType::OwnerChanged:          return "OwnerChanged";
        case FileChangeType::TimestampsChanged:     return "TimestampsChanged";
        case FileChangeType::AttributesChanged:     return "AttributesChanged";
        case FileChangeType::ADSAdded:              return "ADSAdded";
        case FileChangeType::ADSRemoved:            return "ADSRemoved";
        case FileChangeType::ADSModified:           return "ADSModified";
        case FileChangeType::SignatureInvalidated:   return "SignatureInvalidated";
        default:                                     return "Unknown";
    }
}

constexpr const char* FileCategoryToString(FileCategory category) noexcept {
    switch (category) {
        case FileCategory::Unknown:             return "Unknown";
        case FileCategory::SystemDLL:           return "SystemDLL";
        case FileCategory::SystemExecutable:    return "SystemExecutable";
        case FileCategory::BootFile:            return "BootFile";
        case FileCategory::Driver:              return "Driver";
        case FileCategory::SecurityComponent:   return "SecurityComponent";
        case FileCategory::ConfigurationFile:   return "ConfigurationFile";
        case FileCategory::RegistryHive:        return "RegistryHive";
        case FileCategory::ApplicationBinary:   return "ApplicationBinary";
        case FileCategory::ApplicationConfig:   return "ApplicationConfig";
        case FileCategory::LogFile:             return "LogFile";
        case FileCategory::UserData:            return "UserData";
        case FileCategory::Temporary:           return "Temporary";
        case FileCategory::Custom:              return "Custom";
        default:                                return "Unknown";
    }
}

constexpr const char* FileChangeToMitre(FileChangeType type) noexcept {
    switch (type) {
        case FileChangeType::Created:               return "T1105";
        case FileChangeType::Modified:              return "T1565.001";
        case FileChangeType::Deleted:               return "T1070.004";
        case FileChangeType::Renamed:               return "T1036.005";
        case FileChangeType::Moved:                 return "T1036.005";
        case FileChangeType::Replaced:              return "T1574.001";
        case FileChangeType::PermissionsChanged:    return "T1222";
        case FileChangeType::OwnerChanged:          return "T1222";
        case FileChangeType::TimestampsChanged:     return "T1070.006";
        case FileChangeType::AttributesChanged:     return "T1564.001";
        case FileChangeType::ADSAdded:              return "T1564.004";
        case FileChangeType::ADSRemoved:            return "T1564.004";
        case FileChangeType::ADSModified:           return "T1564.004";
        case FileChangeType::SignatureInvalidated:   return "T1553.002";
        default:                                     return "T1565";
    }
}

// ============================================================================
// FREE UTILITY FUNCTIONS (declared in HPP)
// ============================================================================

namespace {
    constexpr size_t MAX_PATH_LEN         = 32767;
    constexpr size_t MAX_DIR_WATCHES      = 60;
    constexpr DWORD  DIR_NOTIFY_BUFFER_SZ = 64 * 1024;
    constexpr size_t MAX_CHANGE_HISTORY   = 50000;
    constexpr size_t MAX_VIOLATIONS       = 50000;

    uint64_t GenerateEventId() noexcept {
        static std::atomic<uint64_t> s_counter{1};
        return s_counter.fetch_add(1, std::memory_order_relaxed);
    }

    std::chrono::system_clock::time_point FileTimeToSysClock(const FILETIME& ft) noexcept {
        ULARGE_INTEGER ull;
        ull.LowPart  = ft.dwLowDateTime;
        ull.HighPart = ft.dwHighDateTime;
        constexpr uint64_t EPOCH_DIFF = 116444736000000000ULL;
        if (ull.QuadPart < EPOCH_DIFF) return {};
        return std::chrono::system_clock::time_point(
            std::chrono::milliseconds((ull.QuadPart - EPOCH_DIFF) / 10000));
    }

    Utils::HashUtils::Algorithm MapHashAlgorithm(HashAlgorithm algo) noexcept {
        switch (algo) {
            case HashAlgorithm::SHA256: return Utils::HashUtils::Algorithm::SHA256;
            case HashAlgorithm::SHA512: return Utils::HashUtils::Algorithm::SHA512;
            case HashAlgorithm::SHA1:   return Utils::HashUtils::Algorithm::SHA1;
            case HashAlgorithm::MD5:    return Utils::HashUtils::Algorithm::MD5;
            default:                    return Utils::HashUtils::Algorithm::SHA256;
        }
    }

    bool ComputeFileHashHex(const std::wstring& path, HashAlgorithm algo,
                            std::string& outHex) noexcept {
        Utils::HashUtils::Hasher hasher(MapHashAlgorithm(algo));
        if (!hasher.Init()) return false;

        HANDLE hFile = ::CreateFileW(
            path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING,
            FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        LARGE_INTEGER fileSize{};
        if (!::GetFileSizeEx(hFile, &fileSize) ||
            fileSize.QuadPart > static_cast<LONGLONG>(Utils::HashUtils::MAX_HASH_FILE_SIZE)) {
            ::CloseHandle(hFile);
            return false;
        }

        constexpr DWORD BUF_SZ = 1u << 20;
        auto buf = std::make_unique<uint8_t[]>(BUF_SZ);
        DWORD bytesRead = 0;
        bool ok = true;
        while (::ReadFile(hFile, buf.get(), BUF_SZ, &bytesRead, nullptr) && bytesRead > 0) {
            if (!hasher.Update(buf.get(), bytesRead)) { ok = false; break; }
        }
        ::CloseHandle(hFile);
        if (!ok) return false;
        return hasher.FinalHex(outHex, false);
    }

    FileAttributes CollectFileAttributes(const std::wstring& path) noexcept {
        FileAttributes attrs{};
        WIN32_FILE_ATTRIBUTE_DATA data{};
        if (!::GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data))
            return attrs;

        attrs.size       = (static_cast<uint64_t>(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
        attrs.attributes = data.dwFileAttributes;
        attrs.creationTime     = FileTimeToSysClock(data.ftCreationTime);
        attrs.modificationTime = FileTimeToSysClock(data.ftLastWriteTime);
        attrs.accessTime       = FileTimeToSysClock(data.ftLastAccessTime);
        attrs.isReadOnly   = (data.dwFileAttributes & FILE_ATTRIBUTE_READONLY)   != 0;
        attrs.isHidden     = (data.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)     != 0;
        attrs.isSystem     = (data.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)     != 0;
        attrs.isArchive    = (data.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE)    != 0;
        attrs.isCompressed = (data.dwFileAttributes & FILE_ATTRIBUTE_COMPRESSED) != 0;
        attrs.isEncrypted  = (data.dwFileAttributes & FILE_ATTRIBUTE_ENCRYPTED)  != 0;
        attrs.isSparse     = (data.dwFileAttributes & FILE_ATTRIBUTE_SPARSE_FILE)!= 0;

        Utils::FileUtils::Error err{};
        std::vector<Utils::FileUtils::AlternateStreamInfo> streams;
        if (Utils::FileUtils::ListAlternateStreams(path, streams, &err)) {
            attrs.hasADS   = !streams.empty();
            attrs.adsCount = static_cast<uint32_t>(streams.size());
        }
        return attrs;
    }

    FileSecurityInfo CollectSecurityInfo(const std::wstring& path) noexcept {
        FileSecurityInfo info{};
        PSECURITY_DESCRIPTOR pSD = nullptr;
        PSID pOwner = nullptr;
        PSID pGroup = nullptr;
        PACL pDacl  = nullptr;

        DWORD result = ::GetNamedSecurityInfoW(
            path.c_str(), SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
            DACL_SECURITY_INFORMATION,
            &pOwner, &pGroup, &pDacl, nullptr, &pSD);
        if (result != ERROR_SUCCESS) return info;

        auto sidToStr = [](PSID sid, std::wstring& out) {
            LPWSTR str = nullptr;
            if (sid && ::ConvertSidToStringSidW(sid, &str)) {
                out = str;
                ::LocalFree(str);
            }
        };

        sidToStr(pOwner, info.ownerSid);
        sidToStr(pGroup, info.groupSid);
        info.hasDACL = (pDacl != nullptr);

        if (pDacl) {
            std::string hex;
            [[maybe_unused]] bool ok = Utils::HashUtils::ComputeHex(
                Utils::HashUtils::Algorithm::SHA256,
                pDacl, pDacl->AclSize, hex, false);
            info.aclHash = std::move(hex);
        }

        if (pOwner) {
            wchar_t name[256]{};
            wchar_t domain[256]{};
            DWORD nameLen = 256, domLen = 256;
            SID_NAME_USE use{};
            if (::LookupAccountSidW(nullptr, pOwner, name, &nameLen, domain, &domLen, &use))
                info.ownerName = std::wstring(domain) + L"\\" + name;
        }

        if (pSD) ::LocalFree(pSD);
        return info;
    }

    FileSignatureInfo CollectSignatureInfo(const std::wstring& path) noexcept {
        FileSignatureInfo sig{};
        Utils::pe_sig_utils::PEFileSignatureVerifier verifier;
        Utils::pe_sig_utils::SignatureInfo si{};
        Utils::pe_sig_utils::Error err{};

        if (!verifier.VerifyPESignature(path, si, &err)) return sig;

        sig.isSigned       = si.isSigned;
        sig.signatureValid = si.isVerified && si.isChainTrusted;
        sig.signerName     = si.signerName;
        sig.issuer         = si.issuerName;
        sig.thumbprint     = Utils::StringUtils::ToNarrow(si.thumbprint);
        sig.isMicrosoftSigned = (si.signerName.find(L"Microsoft") != std::wstring::npos);
        sig.isOSComponent     = sig.isMicrosoftSigned &&
                                (si.signerName.find(L"Windows") != std::wstring::npos);
        return sig;
    }

    std::wstring GetProcessNameFromPid(uint32_t pid) noexcept {
        if (pid == 0) return L"System";
        HANDLE hProc = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProc) return L"<unknown:" + std::to_wstring(pid) + L">";
        wchar_t buf[MAX_PATH]{};
        DWORD sz = MAX_PATH;
        std::wstring name;
        if (::QueryFullProcessImageNameW(hProc, 0, buf, &sz))
            name = buf;
        ::CloseHandle(hProc);
        return name;
    }

    bool WildcardMatch(std::wstring_view str, std::wstring_view pat) noexcept {
        size_t si = 0, pi = 0;
        size_t starIdx = std::wstring_view::npos, matchIdx = 0;
        while (si < str.size()) {
            if (pi < pat.size() && (::towlower(pat[pi]) == ::towlower(str[si]) || pat[pi] == L'?')) {
                ++si; ++pi;
            } else if (pi < pat.size() && pat[pi] == L'*') {
                starIdx = pi++; matchIdx = si;
            } else if (starIdx != std::wstring_view::npos) {
                pi = starIdx + 1; si = ++matchIdx;
            } else {
                return false;
            }
        }
        while (pi < pat.size() && pat[pi] == L'*') ++pi;
        return pi == pat.size();
    }

    bool IsPEFile(const std::wstring& path) noexcept {
        auto endsWith = [&](const wchar_t* ext) {
            if (path.size() < wcslen(ext)) return false;
            return _wcsicmp(path.c_str() + path.size() - wcslen(ext), ext) == 0;
        };
        return endsWith(L".exe") || endsWith(L".dll") || endsWith(L".sys") || endsWith(L".ocx");
    }

} // anonymous namespace

// Free functions declared in HPP

std::wstring NormalizeFilePath(const std::wstring& path) noexcept {
    if (path.empty()) return {};
    try {
        // Resolve through reparse points (junctions/symlinks) via GetFinalPathNameByHandleW
        HANDLE hFile = ::CreateFileW(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                     nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            auto buf = std::make_unique<wchar_t[]>(MAX_PATH_LEN);
            DWORD len = ::GetFinalPathNameByHandleW(hFile, buf.get(), MAX_PATH_LEN,
                                                     FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
            ::CloseHandle(hFile);
            if (len > 0 && len < MAX_PATH_LEN) {
                std::wstring result(buf.get(), len);
                // Strip \\?\ prefix if present
                if (result.size() > 4 && result.compare(0, 4, L"\\\\?\\") == 0)
                    result = result.substr(4);
                std::transform(result.begin(), result.end(), result.begin(), ::towlower);
                return result;
            }
        }
        // Fallback for non-existent files: lexical normalization only
        auto buf = std::make_unique<wchar_t[]>(MAX_PATH_LEN);
        DWORD len = ::GetFullPathNameW(path.c_str(), MAX_PATH_LEN, buf.get(), nullptr);
        if (len == 0 || len >= MAX_PATH_LEN) {
            std::wstring result(path);
            std::transform(result.begin(), result.end(), result.begin(), ::towlower);
            return result;
        }
        std::wstring result(buf.get(), len);
        std::transform(result.begin(), result.end(), result.begin(), ::towlower);
        return result;
    } catch (const std::exception& ex) {
        SS_LOG_WARN(L"FIM", L"NormalizeFilePath exception for '%s': %hs", path.c_str(), ex.what());
        return {};
    } catch (...) {
        SS_LOG_WARN(L"FIM", L"NormalizeFilePath unknown exception for: %s", path.c_str());
        return {};
    }
}

bool PathMatchesPattern(const std::wstring& path, const std::wstring& pattern) noexcept {
    return WildcardMatch(path, pattern);
}

std::wstring GetSystemDirectory() noexcept {
    return Utils::SystemUtils::GetSystemDirectoryPath();
}

std::wstring GetWindowsDirectory() noexcept {
    return Utils::SystemUtils::GetWindowsDirectoryPath();
}

bool IsSystemFile(const std::wstring& filePath) noexcept {
    std::wstring norm = NormalizeFilePath(filePath);
    return norm.find(L"\\windows\\system32\\") != std::wstring::npos ||
           norm.find(L"\\windows\\syswow64\\") != std::wstring::npos;
}

std::vector<std::wstring> EnumerateDirectory(
    const std::wstring& directoryPath, bool recursive) noexcept {
    std::vector<std::wstring> result;
    try {
        Utils::FileUtils::WalkOptions wOpts;
        wOpts.recursive = recursive;
        Utils::FileUtils::Error err{};
        (void)Utils::FileUtils::WalkDirectory(directoryPath, wOpts,
            [&](const std::wstring& filePath, const WIN32_FIND_DATAW&) -> bool {
                result.push_back(filePath);
                return result.size() < FIMConstants::MAX_MONITORED_FILES;
            }, &err);
    } catch (...) {}
    return result;
}

std::optional<std::pair<std::wstring, std::wstring>> GetFileVersionInfo(
    const std::wstring& filePath) noexcept {
    DWORD dummy = 0;
    DWORD size = ::GetFileVersionInfoSizeW(filePath.c_str(), &dummy);
    if (size == 0) return std::nullopt;

    auto data = std::make_unique<uint8_t[]>(size);
    if (!::GetFileVersionInfoW(filePath.c_str(), 0, size, data.get()))
        return std::nullopt;

    VS_FIXEDFILEINFO* ffi = nullptr;
    UINT ffiLen = 0;
    if (!::VerQueryValueW(data.get(), L"\\", reinterpret_cast<LPVOID*>(&ffi), &ffiLen) || !ffi)
        return std::nullopt;

    auto verStr = [](DWORD ms, DWORD ls) -> std::wstring {
        return std::to_wstring(HIWORD(ms)) + L"." + std::to_wstring(LOWORD(ms)) + L"." +
               std::to_wstring(HIWORD(ls)) + L"." + std::to_wstring(LOWORD(ls));
    };

    return std::make_pair(
        verStr(ffi->dwFileVersionMS, ffi->dwFileVersionLS),
        verStr(ffi->dwProductVersionMS, ffi->dwProductVersionLS));
}

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

struct FileIntegrityMonitor::Impl {

    // ---- Internal atomic stats ----
    struct InternalStats {
        std::atomic<uint64_t> monitoredFiles{0};
        std::atomic<uint64_t> monitoredDirectories{0};
        std::atomic<uint64_t> changesDetected{0};
        std::atomic<uint64_t> violations{0};
        std::atomic<uint64_t> violationsRemediated{0};
        std::atomic<uint64_t> verificationsPerformed{0};
        std::atomic<uint64_t> verificationsPassed{0};
        std::atomic<uint64_t> verificationsFailed{0};
        std::atomic<uint64_t> baselinesCreated{0};
        std::atomic<uint64_t> baselinesUpdated{0};
        std::atomic<uint64_t> restoresPerformed{0};
        std::atomic<uint64_t> restoresFailed{0};
        std::atomic<uint64_t> totalVerificationTimeMs{0};

        FIMStats Snapshot() const noexcept {
            FIMStats s{};
            s.monitoredFiles         = monitoredFiles.load(std::memory_order_relaxed);
            s.monitoredDirectories   = monitoredDirectories.load(std::memory_order_relaxed);
            s.changesDetected        = changesDetected.load(std::memory_order_relaxed);
            s.violations             = violations.load(std::memory_order_relaxed);
            s.violationsRemediated   = violationsRemediated.load(std::memory_order_relaxed);
            s.verificationsPerformed = verificationsPerformed.load(std::memory_order_relaxed);
            s.verificationsPassed    = verificationsPassed.load(std::memory_order_relaxed);
            s.verificationsFailed    = verificationsFailed.load(std::memory_order_relaxed);
            s.baselinesCreated       = baselinesCreated.load(std::memory_order_relaxed);
            s.baselinesUpdated       = baselinesUpdated.load(std::memory_order_relaxed);
            s.restoresPerformed      = restoresPerformed.load(std::memory_order_relaxed);
            s.restoresFailed         = restoresFailed.load(std::memory_order_relaxed);
            auto perf = verificationsPerformed.load(std::memory_order_relaxed);
            s.avgVerificationTimeMs  = perf > 0
                ? totalVerificationTimeMs.load(std::memory_order_relaxed) / perf : 0;
            return s;
        }
    };

    // ---- Directory Watch handle ----
    struct DirWatch {
        std::wstring                   directory;
        HANDLE                         hDir   = INVALID_HANDLE_VALUE;
        OVERLAPPED                     overlapped{};
        std::unique_ptr<uint8_t[]>     buffer;
        bool                           recursive = true;
        bool                           active    = false;
        /// Consecutive failed attempts to re-establish this watch. A watch is
        /// never silently abandoned: losing it means losing integrity coverage
        /// for that directory, so it is retried with back-off and only reported
        /// as lost when the directory itself is gone.
        uint32_t                       recoverFailures = 0;
        uint64_t                       nextRecoverTick = 0;

        DirWatch() : buffer(std::make_unique<uint8_t[]>(DIR_NOTIFY_BUFFER_SZ)) {
            overlapped.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        }
        ~DirWatch() {
            if (hDir != INVALID_HANDLE_VALUE) {
                ::CancelIoEx(hDir, &overlapped);
                ::CloseHandle(hDir);
            }
            if (overlapped.hEvent) ::CloseHandle(overlapped.hEvent);
        }
        DirWatch(const DirWatch&) = delete;
        DirWatch& operator=(const DirWatch&) = delete;
    };

    // ---- Callback entry ----
    struct CallbackEntry {
        uint64_t id;
        FileChangeCallback callback;
    };
    struct ViolationCbEntry {
        uint64_t id;
        ViolationCallback callback;
    };
    struct VerificationCbEntry {
        uint64_t id;
        VerificationCallback callback;
    };
    struct RestoreCbEntry {
        uint64_t id;
        RestoreCallback callback;
    };

    // ---- State ----
    enum class State { Uninitialized, Ready, Monitoring, ShuttingDown };
    std::atomic<State>               state{State::Uninitialized};
    std::shared_ptr<Utils::ThreadPool> threadPool;
    FIMConfig                        config;
    InternalStats                    stats;

    mutable std::shared_mutex        configMutex;
    mutable std::shared_mutex        baselineMutex;
    mutable std::shared_mutex        violationMutex;
    mutable std::shared_mutex        historyMutex;
    mutable std::shared_mutex        callbackMutex;
    mutable std::shared_mutex        ruleMutex;
    mutable std::shared_mutex        dirWatchMutex;

    // Baseline data — keyed by normalized path
    std::unordered_map<std::wstring, FileBaseline> baselines;

    // Change tracking
    std::deque<FileChangeEvent>      changeHistory;
    std::deque<IntegrityViolation>   violationList;

    // Rules
    std::vector<MonitoringRule>      rules;

    // Directory watches
    std::vector<std::unique_ptr<DirWatch>> dirWatches;

    // Callbacks
    std::vector<CallbackEntry>       changeCallbacks;
    std::vector<ViolationCbEntry>    violationCallbacks;
    std::vector<VerificationCbEntry> verificationCallbacks;
    std::vector<RestoreCbEntry>      restoreCallbacks;
    std::atomic<uint64_t>            nextCallbackId{1};

    // External integrations
    HashStore::HashStore*            hashStore{nullptr};
    Database::DatabaseManager*       databaseManager{nullptr};
    Backup::FileBackupManager*       backupManager{nullptr};

    // Threads
    std::thread                      dirMonitorThread;
    std::thread                      verifyThread;
    std::thread                      changeQueueThread;
    std::atomic<bool>                stopFlag{false};

    // Change queue with debouncing
    struct PendingChange {
        std::wstring       path;
        FileChangeType     type;
        uint32_t           processId;
        std::chrono::steady_clock::time_point timestamp;
    };
    std::mutex                       changeQueueMutex;
    std::condition_variable          changeQueueCV;
    std::deque<PendingChange>        pendingChanges;

    // ================================================================
    // LIFECYCLE
    // ================================================================

    bool DoInitialize(std::shared_ptr<Utils::ThreadPool> tp,
                      const FIMConfig& cfg) noexcept {
        auto expected = State::Uninitialized;
        if (!state.compare_exchange_strong(expected, State::Ready))
            return false;

        threadPool = std::move(tp);
        {
            std::unique_lock lk(configMutex);
            config = cfg;
        }
        stopFlag.store(false, std::memory_order_release);
        SS_LOG_INFO(L"FIM", L"FileIntegrityMonitor initialized");
        return true;
    }

    void DoShutdown() noexcept {
        auto cur = state.load(std::memory_order_acquire);
        if (cur == State::Uninitialized) return;

        if (cur == State::Monitoring)
            DoStop();

        state.store(State::ShuttingDown, std::memory_order_release);

        {
            std::unique_lock lk(dirWatchMutex);
            dirWatches.clear();
        }
        {
            std::unique_lock lk(baselineMutex);
            baselines.clear();
        }
        {
            std::unique_lock lk(historyMutex);
            changeHistory.clear();
        }
        {
            std::unique_lock lk(violationMutex);
            violationList.clear();
        }
        threadPool.reset();
        state.store(State::Uninitialized, std::memory_order_release);
        SS_LOG_INFO(L"FIM", L"FileIntegrityMonitor shutdown complete");
    }

    void DoStart() {
        auto expected = State::Ready;
        if (!state.compare_exchange_strong(expected, State::Monitoring))
            return;

        // Ensure any previous threads are fully joined before launching new ones
        if (dirMonitorThread.joinable()) dirMonitorThread.join();
        if (verifyThread.joinable())     verifyThread.join();
        if (changeQueueThread.joinable()) changeQueueThread.join();

        stopFlag.store(false, std::memory_order_release);

        dirMonitorThread = std::thread([this] {
            ::SetThreadDescription(::GetCurrentThread(), L"FIM-DirMonitor");
            DirectoryMonitorLoop();
        });

        verifyThread = std::thread([this] {
            ::SetThreadDescription(::GetCurrentThread(), L"FIM-Verify");
            ScheduledVerificationLoop();
        });

        changeQueueThread = std::thread([this] {
            ::SetThreadDescription(::GetCurrentThread(), L"FIM-ChangeQ");
            ChangeQueueProcessor();
        });

        SetupSystemWatches();

        size_t bl;
        {
            std::shared_lock lk(baselineMutex);
            bl = baselines.size();
        }
        SS_LOG_INFO(L"FIM", L"Monitoring started with %zu baselines", bl);
    }

    void DoStop() noexcept {
        // Signal threads to stop BEFORE changing state to prevent DoStart() re-entry race
        stopFlag.store(true, std::memory_order_release);
        state.store(State::Ready, std::memory_order_release);

        changeQueueCV.notify_all();

        {
            std::shared_lock lk(dirWatchMutex);
            for (auto& dw : dirWatches) {
                if (dw && dw->hDir != INVALID_HANDLE_VALUE) {
                    ::CancelIoEx(dw->hDir, &dw->overlapped);
                    ::SetEvent(dw->overlapped.hEvent);
                }
            }
        }

        if (dirMonitorThread.joinable()) dirMonitorThread.join();
        if (verifyThread.joinable())     verifyThread.join();
        if (changeQueueThread.joinable()) changeQueueThread.join();

        // [FIM-A-005] Drain any pending changes so a subsequent StartMonitoring
        // doesn't inherit stale events from the previous session.
        {
            std::lock_guard lkQ(changeQueueMutex);
            pendingChanges.clear();
        }

        SS_LOG_INFO(L"FIM", L"Monitoring stopped");
    }

    // ================================================================
    // FILE CLASSIFICATION (private method declared in HPP)
    // ================================================================

    FileCategory ClassifyFileImpl(const std::wstring& normPath) const noexcept {
        auto pathContains = [&](const wchar_t* sub) {
            return normPath.find(sub) != std::wstring::npos;
        };
        auto endsWith = [&](const wchar_t* ext) {
            if (normPath.size() < wcslen(ext)) return false;
            return normPath.compare(normPath.size() - wcslen(ext), wcslen(ext), ext) == 0;
        };

        if (pathContains(L"\\windows\\system32\\drivers\\") || endsWith(L".sys"))
            return FileCategory::Driver;
        if (pathContains(L"\\windows\\system32\\config\\"))
            return FileCategory::RegistryHive;
        if (pathContains(L"\\windows\\boot\\") || pathContains(L"\\efi\\microsoft\\boot\\"))
            return FileCategory::BootFile;
        if (endsWith(L".dll") && (pathContains(L"\\windows\\system32\\") ||
            pathContains(L"\\windows\\syswow64\\")))
            return FileCategory::SystemDLL;
        if (endsWith(L".exe") && (pathContains(L"\\windows\\system32\\") ||
            pathContains(L"\\windows\\syswow64\\")))
            return FileCategory::SystemExecutable;
        if (pathContains(L"\\program files\\windows defender") ||
            pathContains(L"\\programdata\\microsoft\\windows defender") ||
            pathContains(L"\\shadowstrike"))
            return FileCategory::SecurityComponent;
        if (endsWith(L".exe") || endsWith(L".com") || endsWith(L".scr"))
            return FileCategory::ApplicationBinary;
        if (endsWith(L".dll") || endsWith(L".ocx"))
            return FileCategory::ApplicationBinary;
        if (endsWith(L".log") || endsWith(L".evtx") || endsWith(L".etl"))
            return FileCategory::LogFile;
        if (endsWith(L".ini") || endsWith(L".cfg") || endsWith(L".conf") ||
            endsWith(L".xml") || endsWith(L".json") || endsWith(L".yaml"))
            return FileCategory::ConfigurationFile;
        if (endsWith(L".tmp") || pathContains(L"\\temp\\"))
            return FileCategory::Temporary;
        return FileCategory::Unknown;
    }

    // ================================================================
    // BASELINE OPERATIONS
    // ================================================================

    bool DoCreateBaseline(const std::wstring& filePath) {
        std::wstring normPath = NormalizeFilePath(filePath);
        if (normPath.empty()) return false;

        HashAlgorithm algo;
        bool calcSecondary;
        size_t maxFiles;
        {
            std::shared_lock lk(configMutex);
            algo = config.hashAlgorithm;
            calcSecondary = config.calculateSecondaryHash;
            maxFiles = config.maxMonitoredFiles;
        }

        FileBaseline baseline{};
        baseline.path           = filePath;
        baseline.normalizedPath = normPath;

        // Primary hash
        if (!ComputeFileHashHex(normPath, algo, baseline.hashSHA256)) {
            SS_LOG_WARN(L"FIM", L"Failed to hash for baseline: %s", normPath.c_str());
            return false;
        }

        // Secondary hash
        if (calcSecondary)
            ComputeFileHashHex(normPath, HashAlgorithm::SHA512, baseline.hashSHA512);

        baseline.attributes = CollectFileAttributes(normPath);
        baseline.security   = CollectSecurityInfo(normPath);
        baseline.category   = ClassifyFileImpl(normPath);

        if (IsPEFile(normPath)) {
            baseline.signature = CollectSignatureInfo(normPath);
            auto ver = ::ShadowStrike::RealTime::GetFileVersionInfo(normPath);
            if (ver) {
                baseline.fileVersion    = ver->first;
                baseline.productVersion = ver->second;
            }
        }

        baseline.baselineTime    = std::chrono::system_clock::now();
        baseline.lastVerification = baseline.baselineTime;
        baseline.status          = VerificationStatus::Verified;
        baseline.isCritical      = (baseline.category == FileCategory::Driver ||
                                    baseline.category == FileCategory::BootFile ||
                                    baseline.category == FileCategory::SecurityComponent ||
                                    baseline.category == FileCategory::SystemDLL ||
                                    baseline.category == FileCategory::SystemExecutable);

        {
            std::unique_lock lk(baselineMutex);
            if (baselines.size() >= maxFiles) {
                SS_LOG_WARN(L"FIM", L"Baseline limit reached (%zu), cannot add: %s",
                            maxFiles, normPath.c_str());
                return false;
            }
            auto it = baselines.find(normPath);
            if (it != baselines.end()) {
                it->second = std::move(baseline);
                stats.baselinesUpdated.fetch_add(1, std::memory_order_relaxed);
            } else {
                baselines.emplace(normPath, std::move(baseline));
                stats.baselinesCreated.fetch_add(1, std::memory_order_relaxed);
                stats.monitoredFiles.fetch_add(1, std::memory_order_relaxed);
            }
        }
        return true;
    }

    size_t DoCreateBaselines(const std::wstring& dirPath, bool recursive) {
        std::wstring normDir = NormalizeFilePath(dirPath);
        if (normDir.empty()) return 0;

        size_t count = 0;
        size_t maxFiles;
        {
            std::shared_lock lk(configMutex);
            maxFiles = config.maxMonitoredFiles;
        }

        Utils::FileUtils::WalkOptions wOpts;
        wOpts.recursive = recursive;
        wOpts.cancelFlag = &stopFlag;
        Utils::FileUtils::Error err{};
        (void)Utils::FileUtils::WalkDirectory(normDir, wOpts,
            [&](const std::wstring& filePath, const WIN32_FIND_DATAW&) -> bool {
                {
                    std::shared_lock lk(baselineMutex);
                    if (baselines.size() >= maxFiles) return false;
                }
                if (DoCreateBaseline(filePath)) ++count;
                return !stopFlag.load(std::memory_order_relaxed);
            }, &err);

        SS_LOG_INFO(L"FIM", L"Created %zu baselines in: %s", count, normDir.c_str());
        return count;
    }

    // ================================================================
    // VERIFICATION
    // ================================================================

    VerificationResult DoVerifyFile(const std::wstring& filePath) {
        auto startTime = std::chrono::steady_clock::now();
        std::wstring normPath = NormalizeFilePath(filePath);

        VerificationResult result{};
        result.filePath = normPath;

        FileBaseline storedBaseline;
        {
            std::shared_lock lk(baselineMutex);
            auto it = baselines.find(normPath);
            if (it == baselines.end()) {
                result.status = VerificationStatus::NoBaseline;
                return result;
            }
            storedBaseline = it->second;
            result.hasBaseline = true;
            result.expectedHash = storedBaseline.hashSHA256;
        }

        DWORD fileAttrs = ::GetFileAttributesW(normPath.c_str());
        if (fileAttrs == INVALID_FILE_ATTRIBUTES) {
            DWORD err = ::GetLastError();
            if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
                result.status = VerificationStatus::NotFound;
                RecordViolation(normPath, FileChangeType::Deleted, storedBaseline);
            } else if (err == ERROR_ACCESS_DENIED) {
                result.status = VerificationStatus::AccessDenied;
                result.errorMessage = L"Access denied";
            } else {
                result.status = VerificationStatus::Error;
                result.errorMessage = L"GetFileAttributes failed: " + std::to_wstring(err);
            }
            return result;
        }

        // Hash check — always use SHA-256 to match the hashSHA256 baseline field
        if (!ComputeFileHashHex(normPath, HashAlgorithm::SHA256, result.currentHash)) {
            result.status = VerificationStatus::Error;
            result.errorMessage = L"Hash computation failed";
            return result;
        }

        result.hashMatches = (result.currentHash == storedBaseline.hashSHA256);

        // Attribute check
        FileAttributes currentAttrs = CollectFileAttributes(normPath);
        result.attributesMatch = (currentAttrs.size == storedBaseline.attributes.size &&
                                  currentAttrs.attributes == storedBaseline.attributes.attributes);

        // Permission check
        FileSecurityInfo currentSec = CollectSecurityInfo(normPath);
        result.permissionsMatch = (currentSec.ownerSid == storedBaseline.security.ownerSid &&
                                   currentSec.aclHash == storedBaseline.security.aclHash);

        // Signature check
        if (IsPEFile(normPath)) {
            FileSignatureInfo currentSig = CollectSignatureInfo(normPath);
            result.signatureValid = (currentSig.isSigned == storedBaseline.signature.isSigned &&
                                     currentSig.thumbprint == storedBaseline.signature.thumbprint);
        } else {
            result.signatureValid = true;
        }

        // Determine status and record violations
        if (result.hashMatches && result.attributesMatch &&
            result.permissionsMatch && result.signatureValid) {
            result.status = VerificationStatus::Verified;
            stats.verificationsPassed.fetch_add(1, std::memory_order_relaxed);
        } else {
            result.status = VerificationStatus::Violated;
            stats.verificationsFailed.fetch_add(1, std::memory_order_relaxed);

            if (!result.hashMatches)
                result.violations.push_back(FileChangeType::Modified);
            if (!result.attributesMatch)
                result.violations.push_back(FileChangeType::AttributesChanged);
            if (!result.permissionsMatch)
                result.violations.push_back(FileChangeType::PermissionsChanged);
            if (!result.signatureValid)
                result.violations.push_back(FileChangeType::SignatureInvalidated);

            RecordViolation(normPath, result.violations.empty()
                ? FileChangeType::Modified : result.violations.front(), storedBaseline);

            // Update baseline lastVerification
            {
                std::unique_lock lk(baselineMutex);
                auto it = baselines.find(normPath);
                if (it != baselines.end()) {
                    it->second.lastVerification = std::chrono::system_clock::now();
                    it->second.status = VerificationStatus::Violated;
                }
            }
        }

        auto elapsed = std::chrono::steady_clock::now() - startTime;
        result.verificationTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
        stats.verificationsPerformed.fetch_add(1, std::memory_order_relaxed);
        stats.totalVerificationTimeMs.fetch_add(result.verificationTimeMs, std::memory_order_relaxed);

        // Fire verification callbacks
        {
            std::shared_lock lk(callbackMutex);
            for (auto& cb : verificationCallbacks) {
                try { if (cb.callback) cb.callback(result); } catch (...) {}
            }
        }

        return result;
    }

    BatchVerificationResult DoBatchVerify(const std::vector<std::wstring>& paths) {
        BatchVerificationResult batch{};
        batch.startTime = std::chrono::system_clock::now();

        for (auto& p : paths) {
            if (stopFlag.load(std::memory_order_relaxed)) break;
            auto r = DoVerifyFile(p);
            batch.totalFiles++;

            switch (r.status) {
                case VerificationStatus::Verified:    batch.verifiedOK++; break;
                case VerificationStatus::Violated:    batch.violations++; break;
                case VerificationStatus::NotFound:    batch.notFound++;   break;
                default:                              batch.errors++;     break;
            }
            batch.results.push_back(std::move(r));
        }

        batch.endTime = std::chrono::system_clock::now();
        batch.totalTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            batch.endTime - batch.startTime).count();
        return batch;
    }

    // ================================================================
    // CHANGE HANDLING
    // ================================================================

    void EnqueueChange(const std::wstring& path, FileChangeType type, uint32_t pid) {
        std::wstring normPath = NormalizeFilePath(path);
        if (normPath.empty()) return;

        {
            std::lock_guard lk(changeQueueMutex);
            if (pendingChanges.size() >= FIMConstants::MAX_PENDING_CHANGES) {
                SS_LOG_WARN(L"FIM", L"Change queue full, dropping: %s", normPath.c_str());
                return;
            }
            pendingChanges.push_back({normPath, type, pid,
                                      std::chrono::steady_clock::now()});
        }
        changeQueueCV.notify_one();
    }

    FIMAction ProcessChangeEvent(const FileChangeEvent& event) {
        stats.changesDetected.fetch_add(1, std::memory_order_relaxed);

        // Record history
        {
            std::unique_lock lk(historyMutex);
            if (changeHistory.size() >= MAX_CHANGE_HISTORY)
                changeHistory.pop_front();
            changeHistory.push_back(event);
        }

        // Invoke callbacks — aggregate action
        FIMAction action = FIMAction::LogOnly;
        {
            std::shared_lock lk(callbackMutex);
            for (auto& cb : changeCallbacks) {
                try {
                    if (cb.callback) {
                        FIMAction a = cb.callback(event);
                        if (static_cast<uint8_t>(a) > static_cast<uint8_t>(action))
                            action = a;
                    }
                } catch (...) {
                    SS_LOG_WARN(L"FIM", L"Change callback threw exception");
                }
            }
        }
        return action;
    }

    void ProcessFileChange(const std::wstring& normPath, FileChangeType changeType,
                           uint32_t processId) {
        FileChangeEvent evt{};
        evt.eventId     = GenerateEventId();
        evt.filePath    = normPath;
        evt.changeType  = changeType;
        evt.timestamp   = std::chrono::system_clock::now();
        evt.processId   = processId;
        evt.processName = GetProcessNameFromPid(processId);
        evt.processPath = evt.processName;
        evt.category    = ClassifyFileImpl(normPath);
        evt.mitreTechnique = FileChangeToMitre(changeType);

        // Check baseline
        FileBaseline storedBaseline;
        bool hasBaseline = false;
        {
            std::shared_lock lk(baselineMutex);
            auto it = baselines.find(normPath);
            if (it != baselines.end()) {
                hasBaseline = true;
                storedBaseline = it->second;
            }
        }

        if (hasBaseline && changeType != FileChangeType::Deleted) {
            std::string currentHash;
            if (ComputeFileHashHex(normPath, HashAlgorithm::SHA256, currentHash)) {
                evt.oldHash = storedBaseline.hashSHA256;
                evt.newHash = currentHash;
                if (currentHash != storedBaseline.hashSHA256) {
                    RecordViolation(normPath, changeType, storedBaseline);
                }
            }
        }

        // Collect current attrs
        if (changeType != FileChangeType::Deleted) {
            evt.newAttributes = CollectFileAttributes(normPath);
            evt.newSize       = evt.newAttributes.size;
        }
        if (hasBaseline) {
            evt.oldAttributes = storedBaseline.attributes;
            evt.oldSize       = storedBaseline.attributes.size;
        }

        evt.riskScore = CalculateRiskScoreImpl(evt);
        evt.actionTaken = ProcessChangeEvent(evt);
    }

    // ================================================================
    // VIOLATION RECORDING
    // ================================================================

    void RecordViolation(const std::wstring& path, FileChangeType changeType,
                         const FileBaseline& baseline) {
        IntegrityViolation v{};
        v.violationId     = GenerateEventId();
        v.filePath        = path;
        v.violationType   = changeType;
        v.expectedHash    = baseline.hashSHA256;
        v.category        = baseline.category;
        v.timestamp       = std::chrono::system_clock::now();
        v.processId       = 0;
        v.baseline        = std::make_shared<FileBaseline>(baseline);

        if (changeType != FileChangeType::Deleted) {
            std::string currentHash;
            HashAlgorithm algo;
            {
                std::shared_lock lk(configMutex);
                algo = config.hashAlgorithm;
            }
            if (ComputeFileHashHex(path, algo, currentHash))
                v.actualHash = currentHash;
            v.currentAttributes = CollectFileAttributes(path);
        }

        // Severity based on category
        switch (baseline.category) {
            case FileCategory::BootFile:          v.severity = FIMConstants::BOOT_FILE_MODIFICATION_SCORE; break;
            case FileCategory::SystemDLL:         v.severity = FIMConstants::SYSTEM_DLL_MODIFICATION_SCORE; break;
            case FileCategory::SystemExecutable:  v.severity = FIMConstants::SYSTEM_DLL_MODIFICATION_SCORE; break;
            case FileCategory::SecurityComponent: v.severity = FIMConstants::SECURITY_COMPONENT_SCORE; break;
            case FileCategory::Driver:            v.severity = FIMConstants::BOOT_FILE_MODIFICATION_SCORE; break;
            case FileCategory::RegistryHive:      v.severity = FIMConstants::SECURITY_COMPONENT_SCORE; break;
            case FileCategory::ConfigurationFile: v.severity = FIMConstants::CONFIG_FILE_MODIFICATION_SCORE; break;
            default:                              v.severity = FIMConstants::PERMISSION_CHANGE_SCORE; break;
        }

        {
            std::unique_lock lk(violationMutex);
            if (violationList.size() >= MAX_VIOLATIONS)
                violationList.pop_front();
            violationList.push_back(v);
        }
        stats.violations.fetch_add(1, std::memory_order_relaxed);

        // Fire violation callbacks
        {
            std::shared_lock lk(callbackMutex);
            for (auto& cb : violationCallbacks) {
                try { if (cb.callback) cb.callback(v); } catch (...) {}
            }
        }

        SS_LOG_WARN(L"FIM", L"VIOLATION [%hs] %hs: %s",
                    FileCategoryToString(baseline.category),
                    FileChangeTypeToString(changeType),
                    path.c_str());
    }

    // ================================================================
    // RISK SCORE (private method declared in HPP)
    // ================================================================

    double CalculateRiskScoreImpl(const FileChangeEvent& event) const noexcept {
        double score = 0.0;
        switch (event.category) {
            case FileCategory::BootFile:          score = FIMConstants::BOOT_FILE_MODIFICATION_SCORE; break;
            case FileCategory::SystemDLL:         score = FIMConstants::SYSTEM_DLL_MODIFICATION_SCORE; break;
            case FileCategory::SystemExecutable:  score = FIMConstants::SYSTEM_DLL_MODIFICATION_SCORE; break;
            case FileCategory::Driver:            score = FIMConstants::BOOT_FILE_MODIFICATION_SCORE; break;
            case FileCategory::SecurityComponent: score = FIMConstants::SECURITY_COMPONENT_SCORE; break;
            case FileCategory::ConfigurationFile: score = FIMConstants::CONFIG_FILE_MODIFICATION_SCORE; break;
            case FileCategory::RegistryHive:      score = FIMConstants::SECURITY_COMPONENT_SCORE; break;
            default:                              score = 30.0; break;
        }

        if (event.changeType == FileChangeType::Deleted ||
            event.changeType == FileChangeType::Replaced)
            score = (std::min)(score + 10.0, 100.0);
        if (event.changeType == FileChangeType::PermissionsChanged)
            score = (std::max)(score, FIMConstants::PERMISSION_CHANGE_SCORE);

        return score;
    }

    // ================================================================
    // RULE EVALUATION
    // ================================================================

    std::optional<std::string> EvaluateRules(const std::wstring& normPath) const {
        std::shared_lock lk(ruleMutex);
        for (auto& rule : rules) {
            if (!rule.enabled) continue;
            if (PathMatchesPattern(normPath, rule.pathPattern))
                return rule.ruleId;
        }
        return std::nullopt;
    }

    // ================================================================
    // THREADS
    // ================================================================

    /// @brief Re-establish a directory watch whose handle stopped working.
    ///
    /// A watch that stops functioning is a hole in integrity coverage, so the
    /// monitor repairs it rather than dropping it: the directory handle is
    /// reopened and change notification is re-armed. Failures back off
    /// (1s, 2s, 4s ... capped) so a directory that is genuinely gone cannot
    /// cost CPU, and the caller is told whether coverage was restored.
    [[nodiscard]] bool RearmDirWatch(DirWatch& dw) noexcept {
        constexpr DWORD NOTIFY_FILTER =
            FILE_NOTIFY_CHANGE_FILE_NAME  | FILE_NOTIFY_CHANGE_DIR_NAME   |
            FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE       |
            FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SECURITY   |
            FILE_NOTIFY_CHANGE_CREATION;

        if (dw.hDir != INVALID_HANDLE_VALUE) {
            ::CancelIoEx(dw.hDir, &dw.overlapped);
            ::CloseHandle(dw.hDir);
            dw.hDir = INVALID_HANDLE_VALUE;
        }
        if (dw.overlapped.hEvent) {
            ::ResetEvent(dw.overlapped.hEvent);
        }

        HANDLE hDir = ::CreateFileW(
            dw.directory.c_str(), FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
        if (hDir == INVALID_HANDLE_VALUE) {
            return false;
        }

        OVERLAPPED fresh{};
        fresh.hEvent = dw.overlapped.hEvent;
        dw.overlapped = fresh;
        dw.hDir = hDir;

        if (!::ReadDirectoryChangesW(dw.hDir, dw.buffer.get(), DIR_NOTIFY_BUFFER_SZ,
                                     dw.recursive ? TRUE : FALSE, NOTIFY_FILTER,
                                     nullptr, &dw.overlapped, nullptr)) {
            ::CloseHandle(dw.hDir);
            dw.hDir = INVALID_HANDLE_VALUE;
            return false;
        }

        dw.active = true;
        dw.recoverFailures = 0;
        dw.nextRecoverTick = 0;
        return true;
    }

    /// @brief Repair a watch, or schedule the next attempt if repair failed.
    void RecoverOrSchedule(DirWatch& dw, const wchar_t* why) noexcept {
        if (RearmDirWatch(dw)) {
            SS_LOG_INFO(L"FIM", L"Restored directory watch after %s: %s",
                        why, dw.directory.c_str());
            return;
        }

        dw.active = false;
        ++dw.recoverFailures;
        const uint64_t backoffMs =
            (std::min)(1000ull << (std::min)(dw.recoverFailures, 5u), 30000ull);
        dw.nextRecoverTick = ::GetTickCount64() + backoffMs;

        const DWORD attrs = ::GetFileAttributesW(dw.directory.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            SS_LOG_WARN(L"FIM",
                L"Directory no longer present, integrity coverage dropped for: %s (%s)",
                dw.directory.c_str(), why);
        } else {
            SS_LOG_WARN(L"FIM",
                L"Could not re-arm watch for %s after %s; retrying in %llu ms "
                L"(attempt %u) - integrity coverage is currently degraded",
                dw.directory.c_str(), why,
                static_cast<unsigned long long>(backoffMs), dw.recoverFailures);
        }
    }

    void DirectoryMonitorLoop() {
        SS_LOG_DEBUG(L"FIM", L"Directory monitor thread started");

        while (!stopFlag.load(std::memory_order_acquire)) {
            std::vector<HANDLE>       handles;
            std::vector<std::wstring> handleDirs; // [FIM-A-001] lookup key

            // Try to bring degraded watches back. Integrity coverage must not
            // stay silently reduced because a directory was briefly unavailable
            // (a volume that went offline, a folder recreated by an installer).
            {
                const uint64_t nowTick = ::GetTickCount64();
                std::unique_lock lk(dirWatchMutex);
                for (auto& candidate : dirWatches) {
                    if (!candidate || candidate->active) continue;
                    if (candidate->nextRecoverTick > nowTick) continue;
                    if (::GetFileAttributesW(candidate->directory.c_str()) ==
                        INVALID_FILE_ATTRIBUTES) {
                        // Still gone; schedule the next look without churning.
                        candidate->nextRecoverTick = nowTick + 30000;
                        continue;
                    }
                    RecoverOrSchedule(*candidate, L"scheduled recovery");
                }
            }

            {
                std::shared_lock lk(dirWatchMutex);
                for (size_t i = 0; i < dirWatches.size() && i < MAX_DIR_WATCHES; ++i) {
                    if (dirWatches[i] && dirWatches[i]->active &&
                        dirWatches[i]->overlapped.hEvent) {
                        handles.push_back(dirWatches[i]->overlapped.hEvent);
                        handleDirs.push_back(dirWatches[i]->directory);
                    }
                }
            }

            if (handles.empty()) {
                ::Sleep(500);
                continue;
            }

            DWORD waitResult = ::WaitForMultipleObjects(
                static_cast<DWORD>(handles.size()), handles.data(), FALSE, 1000);

            if (stopFlag.load(std::memory_order_relaxed)) break;

            // WAIT_FAILED must be handled explicitly. It is returned
            // IMMEDIATELY (not after the timeout), so without this branch a
            // single unusable handle in the array — a watched directory that was
            // deleted, a volume that went away — turns this loop into a full
            // core spin that never ends. Drop the watches whose handles no
            // longer wait cleanly, and back off briefly so a transient failure
            // can never burn CPU either.
            if (waitResult == WAIT_FAILED) {
                const DWORD err = ::GetLastError();
                SS_LOG_WARN(L"FIM",
                    L"WaitForMultipleObjects failed (err=%u) over %zu watch handles; "
                    L"pruning unusable watches", err, handles.size());

                size_t pruned = 0;
                {
                    std::unique_lock lk(dirWatchMutex);
                    for (auto& candidate : dirWatches) {
                        if (!candidate || !candidate->active ||
                            !candidate->overlapped.hEvent) {
                            continue;
                        }
                        // A healthy event handle answers a zero-timeout wait
                        // with either signalled or timeout; anything else means
                        // the handle itself is unusable.
                        const DWORD probe =
                            ::WaitForSingleObject(candidate->overlapped.hEvent, 0);
                        if (probe == WAIT_FAILED) {
                            // Repair rather than retire: dropping the watch
                            // would silently end integrity coverage here.
                            RecoverOrSchedule(*candidate, L"unusable wait handle");
                            ++pruned;
                        }
                    }
                }

                if (pruned == 0) {
                    // Could not attribute the failure to a specific watch;
                    // never retry in a tight loop.
                    ::Sleep(500);
                }
                continue;
            }

            if (waitResult >= WAIT_OBJECT_0 &&
                waitResult < WAIT_OBJECT_0 + handles.size()) {

                // [FIM-A-001] Re-find the watch by directory name. Index-based
                // lookup is unsafe: RemoveMonitoredDirectory may have erased
                // and shifted entries while we were waiting. Looking up by the
                // captured directory name guarantees we either operate on the
                // intended watch or skip safely.
                const std::wstring& targetDir = handleDirs[waitResult - WAIT_OBJECT_0];
                const HANDLE signalledEvent = handles[waitResult - WAIT_OBJECT_0];

                std::shared_lock lk(dirWatchMutex);
                DirWatch* dw = nullptr;
                for (auto& candidate : dirWatches) {
                    if (candidate && candidate->active &&
                        candidate->directory == targetDir) {
                        dw = candidate.get();
                        break;
                    }
                }
                if (!dw) {
                    // The watch disappeared while we were waiting. The event is
                    // still SIGNALLED, so returning here without clearing it
                    // would make the next wait return instantly and spin the
                    // CPU forever. Clear it before moving on.
                    ::ResetEvent(signalledEvent);
                    continue;
                }

                DWORD bytesReturned = 0;
                if (!::GetOverlappedResult(dw->hDir, &dw->overlapped,
                                            &bytesReturned, FALSE)) {
                    const DWORD err = ::GetLastError();
                    // Same hazard as above: the event is signalled and must not
                    // be left that way. ERROR_IO_INCOMPLETE is benign (the
                    // result is simply not ready yet), anything else means this
                    // watch is broken and is retired rather than spun on.
                    ::ResetEvent(dw->overlapped.hEvent);
                    if (err != ERROR_IO_INCOMPLETE) {
                        SS_LOG_WARN(L"FIM",
                            L"GetOverlappedResult failed for %s (err=%u); re-establishing watch",
                            dw->directory.c_str(), err);
                        RecoverOrSchedule(*dw, L"overlapped result failure");
                    }
                    continue;
                }

                if (bytesReturned > 0)
                    ProcessDirectoryNotifications(dw->buffer.get(), bytesReturned, dw->directory);

                ::ResetEvent(dw->overlapped.hEvent);
                constexpr DWORD NOTIFY_FILTER =
                    FILE_NOTIFY_CHANGE_FILE_NAME  | FILE_NOTIFY_CHANGE_DIR_NAME   |
                    FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE       |
                    FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SECURITY   |
                    FILE_NOTIFY_CHANGE_CREATION;

                if (!::ReadDirectoryChangesW(
                        dw->hDir, dw->buffer.get(), DIR_NOTIFY_BUFFER_SZ,
                        dw->recursive ? TRUE : FALSE, NOTIFY_FILTER,
                        nullptr, &dw->overlapped, nullptr)) {
                    SS_LOG_WARN(L"FIM",
                        L"ReadDirectoryChangesW re-arm failed for %s (err=%u); "
                        L"re-establishing watch",
                        dw->directory.c_str(), ::GetLastError());
                    RecoverOrSchedule(*dw, L"re-arm failure");
                }
            }
        }
        SS_LOG_DEBUG(L"FIM", L"Directory monitor thread exiting");
    }

    void ProcessDirectoryNotifications(const uint8_t* buf, DWORD size,
                                        const std::wstring& baseDir) {
        // [FIM-A-002] Strict bounds validation against hostile/malformed
        // FILE_NOTIFY_INFORMATION chains. We must never read past buf+size.
        if (!buf || size < sizeof(FILE_NOTIFY_INFORMATION)) return;

        const uint8_t* const end    = buf + size;
        const uint8_t*       cursor = buf;

        while (true) {
            // Ensure we can read the fixed header
            if (cursor + sizeof(FILE_NOTIFY_INFORMATION) > end) break;

            const auto* info = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(cursor);

            // Ensure the FileName payload is fully within [buf, end)
            const size_t headerSize = offsetof(FILE_NOTIFY_INFORMATION, FileName);
            if (info->FileNameLength % sizeof(wchar_t) != 0) break;
            if (info->FileNameLength > static_cast<DWORD>(end - cursor) - headerSize) break;

            const DWORD nameLen = info->FileNameLength / sizeof(wchar_t);
            if (nameLen > 0 && nameLen < MAX_PATH_LEN) {
                std::wstring fileName(info->FileName, nameLen);
                std::wstring fullPath = baseDir + L"\\" + fileName;

                FileChangeType changeType;
                switch (info->Action) {
                    case FILE_ACTION_ADDED:            changeType = FileChangeType::Created; break;
                    case FILE_ACTION_REMOVED:          changeType = FileChangeType::Deleted; break;
                    case FILE_ACTION_MODIFIED:         changeType = FileChangeType::Modified; break;
                    case FILE_ACTION_RENAMED_OLD_NAME: changeType = FileChangeType::Renamed; break;
                    case FILE_ACTION_RENAMED_NEW_NAME: changeType = FileChangeType::Renamed; break;
                    default:                           changeType = FileChangeType::Modified; break;
                }
                EnqueueChange(fullPath, changeType, 0);
            }

            if (info->NextEntryOffset == 0) break;

            // NextEntryOffset must move forward and stay within the buffer.
            if (info->NextEntryOffset < headerSize + info->FileNameLength) break;
            if (info->NextEntryOffset > static_cast<DWORD>(end - cursor)) break;
            cursor += info->NextEntryOffset;
        }
    }

    void ScheduledVerificationLoop() {
        SS_LOG_DEBUG(L"FIM", L"Verification thread started");

        while (!stopFlag.load(std::memory_order_acquire)) {
            uint32_t intervalSec;
            {
                std::shared_lock lk(configMutex);
                intervalSec = config.verifyIntervalSec;
            }

            for (uint32_t i = 0; i < intervalSec; ++i) {
                if (stopFlag.load(std::memory_order_relaxed)) return;
                ::Sleep(1000);
            }
            if (stopFlag.load(std::memory_order_relaxed)) return;

            SS_LOG_DEBUG(L"FIM", L"Running scheduled verification cycle");
            std::vector<std::wstring> paths;
            {
                std::shared_lock lk(baselineMutex);
                paths.reserve(baselines.size());
                for (auto& [p, _] : baselines) paths.push_back(p);
            }
            DoBatchVerify(paths);
        }
        SS_LOG_DEBUG(L"FIM", L"Verification thread exiting");
    }

    void ChangeQueueProcessor() {
        SS_LOG_DEBUG(L"FIM", L"Change queue processor started");
        const auto DEBOUNCE = std::chrono::milliseconds(FIMConstants::CHANGE_DEBOUNCE_MS);

        while (!stopFlag.load(std::memory_order_acquire)) {
            PendingChange change{};
            bool hasChange = false;

            {
                std::unique_lock lk(changeQueueMutex);
                changeQueueCV.wait_for(lk, std::chrono::milliseconds(500),
                    [this] {
                        return !pendingChanges.empty() ||
                               stopFlag.load(std::memory_order_relaxed);
                    });
                if (stopFlag.load(std::memory_order_relaxed)) break;

                if (!pendingChanges.empty()) {
                    auto elapsed = std::chrono::steady_clock::now() - pendingChanges.front().timestamp;
                    if (elapsed >= DEBOUNCE) {
                        change = std::move(pendingChanges.front());
                        pendingChanges.pop_front();
                        hasChange = true;
                    }
                }
            }

            if (hasChange)
                ProcessFileChange(change.path, change.type, change.processId);
        }
        SS_LOG_DEBUG(L"FIM", L"Change queue processor exiting");
    }

    // ================================================================
    // SYSTEM WATCHES & DIRECTORY MANAGEMENT
    // ================================================================

    bool DoAddMonitoredDirectory(const std::wstring& dirPath, bool recursive) {
        std::wstring normDir = NormalizeFilePath(dirPath);
        if (normDir.empty()) return false;

        HANDLE hDir = ::CreateFileW(
            normDir.c_str(), FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
        if (hDir == INVALID_HANDLE_VALUE) {
            SS_LOG_WARN(L"FIM", L"Cannot open directory for monitoring: %s (err=%u)",
                        normDir.c_str(), ::GetLastError());
            return false;
        }

        auto dw = std::make_unique<DirWatch>();
        dw->directory = normDir;
        dw->hDir      = hDir;
        dw->recursive = recursive;
        dw->active    = true;

        constexpr DWORD NOTIFY_FILTER =
            FILE_NOTIFY_CHANGE_FILE_NAME  | FILE_NOTIFY_CHANGE_DIR_NAME   |
            FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE       |
            FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SECURITY   |
            FILE_NOTIFY_CHANGE_CREATION;

        BOOL ok = ::ReadDirectoryChangesW(
            dw->hDir, dw->buffer.get(), DIR_NOTIFY_BUFFER_SZ,
            recursive ? TRUE : FALSE, NOTIFY_FILTER,
            nullptr, &dw->overlapped, nullptr);
        if (!ok) {
            SS_LOG_WARN(L"FIM", L"ReadDirectoryChangesW failed: %s (err=%u)",
                        normDir.c_str(), ::GetLastError());
            return false;
        }

        {
            std::unique_lock lk(dirWatchMutex);
            if (dirWatches.size() >= MAX_DIR_WATCHES) {
                SS_LOG_WARN(L"FIM", L"Directory watch limit reached (%zu)", MAX_DIR_WATCHES);
                return false;
            }
            dirWatches.push_back(std::move(dw));
        }
        stats.monitoredDirectories.fetch_add(1, std::memory_order_relaxed);
        SS_LOG_INFO(L"FIM", L"Monitoring directory: %s (recursive=%s)",
                    normDir.c_str(), recursive ? L"yes" : L"no");
        return true;
    }

    void SetupSystemWatches() {
        FIMConfig cfg;
        {
            std::shared_lock lk(configMutex);
            cfg = config;
        }

        std::wstring sys32  = Utils::SystemUtils::GetSystemDirectoryPath();
        std::wstring winDir = Utils::SystemUtils::GetWindowsDirectoryPath();

        // [FIM-A-004] Deduplicate against existing watches. Without this,
        // every Start/Stop cycle re-adds the same system directories and
        // eventually saturates MAX_DIR_WATCHES, blocking user-added watches.
        auto alreadyWatching = [this](const std::wstring& target) -> bool {
            std::wstring norm = NormalizeFilePath(target);
            std::shared_lock lk(dirWatchMutex);
            for (const auto& dw : dirWatches) {
                if (dw && dw->directory == norm) return true;
            }
            return false;
        };

        if (cfg.monitorDrivers && !sys32.empty()) {
            std::wstring p = sys32 + L"\\drivers";
            if (!alreadyWatching(p)) DoAddMonitoredDirectory(p, true);
        }
        if (cfg.monitorSystemFiles && !sys32.empty()) {
            if (!alreadyWatching(sys32)) DoAddMonitoredDirectory(sys32, false);
        }
        if (cfg.monitorBootFiles && !winDir.empty()) {
            std::wstring p = winDir + L"\\boot";
            if (!alreadyWatching(p)) DoAddMonitoredDirectory(p, true);
        }
    }

    // ================================================================
    // BASELINE IMPORT/EXPORT
    // ================================================================

    bool DoExportBaselines(const std::wstring& filePath) const {
        std::shared_lock lk(baselineMutex);
        std::ostringstream oss;
        oss << "# ShadowStrike FIM Baseline Export\n";
        oss << "# Entries: " << baselines.size() << "\n";

        for (auto& [path, bl] : baselines) {
            oss << Utils::StringUtils::ToNarrow(path) << "|"
                << bl.hashSHA256 << "|"
                << bl.attributes.size << "|"
                << Utils::StringUtils::ToNarrow(bl.security.ownerSid) << "|"
                << static_cast<int>(bl.category) << "|"
                << bl.version << "\n";
        }

        Utils::FileUtils::Error err{};
        return Utils::FileUtils::WriteAllTextUtf8Atomic(filePath, oss.str(), &err);
    }

    bool DoImportBaselines(const std::wstring& filePath) {
        Utils::FileUtils::Error err{};
        std::string content;
        if (!Utils::FileUtils::ReadAllTextUtf8(filePath, content, &err))
            return false;

        // [FIM-A-003] Snapshot config under configMutex once, instead of
        // touching config.maxMonitoredFiles unsynchronized from the hot loop.
        size_t maxFiles;
        {
            std::shared_lock lkCfg(configMutex);
            maxFiles = config.maxMonitoredFiles;
        }

        std::istringstream iss(content);
        std::string line;
        size_t imported = 0;

        while (std::getline(iss, line)) {
            if (line.empty() || line[0] == '#') continue;

            size_t p1 = line.find('|');
            if (p1 == std::string::npos) continue;
            size_t p2 = line.find('|', p1 + 1);
            if (p2 == std::string::npos) continue;

            std::wstring path = Utils::StringUtils::ToWide(line.substr(0, p1));
            std::string hash  = line.substr(p1 + 1, p2 - p1 - 1);

            std::wstring normPath = NormalizeFilePath(path);
            if (normPath.empty()) continue;

            FileBaseline bl{};
            bl.path           = path;
            bl.normalizedPath = normPath;
            bl.hashSHA256     = hash;
            bl.baselineTime   = std::chrono::system_clock::now();
            bl.category       = ClassifyFileImpl(normPath);

            {
                std::unique_lock lk2(baselineMutex);
                if (baselines.size() >= maxFiles) break;
                baselines[normPath] = std::move(bl);
            }
            ++imported;
        }
        SS_LOG_INFO(L"FIM", L"Imported %zu baselines from: %s",
                    imported, filePath.c_str());
        return imported > 0;
    }

}; // struct Impl

// ============================================================================
// SINGLETON + PUBLIC API
// ============================================================================

FileIntegrityMonitor::FileIntegrityMonitor()
    : m_impl(std::make_unique<Impl>()) {}

FileIntegrityMonitor::~FileIntegrityMonitor() {
    if (m_impl) m_impl->DoShutdown();
}

FileIntegrityMonitor& FileIntegrityMonitor::Instance() noexcept {
    static FileIntegrityMonitor instance;
    return instance;
}

// ---- Lifecycle ----

bool FileIntegrityMonitor::Initialize() {
    return m_impl->DoInitialize(nullptr, FIMConfig::CreateDefault());
}

bool FileIntegrityMonitor::Initialize(std::shared_ptr<Utils::ThreadPool> threadPool) {
    return m_impl->DoInitialize(std::move(threadPool), FIMConfig::CreateDefault());
}

bool FileIntegrityMonitor::Initialize(
    std::shared_ptr<Utils::ThreadPool> threadPool, const FIMConfig& config) {
    return m_impl->DoInitialize(std::move(threadPool), config);
}

void FileIntegrityMonitor::Shutdown() noexcept {
    m_impl->DoShutdown();
}

void FileIntegrityMonitor::StartMonitoring() {
    m_impl->DoStart();
}

void FileIntegrityMonitor::StopMonitoring() {
    m_impl->DoStop();
}

bool FileIntegrityMonitor::IsMonitoring() const noexcept {
    return m_impl->state.load(std::memory_order_acquire) == Impl::State::Monitoring;
}

void FileIntegrityMonitor::UpdateConfig(const FIMConfig& config) {
    std::unique_lock lk(m_impl->configMutex);
    m_impl->config = config;
    SS_LOG_INFO(L"FIM", L"Configuration updated");
}

FIMConfig FileIntegrityMonitor::GetConfig() const {
    std::shared_lock lk(m_impl->configMutex);
    return m_impl->config;
}

// ---- Baseline Management ----

bool FileIntegrityMonitor::CreateBaseline(const std::wstring& filePath) {
    return m_impl->DoCreateBaseline(filePath);
}

size_t FileIntegrityMonitor::CreateBaselines(const std::wstring& directoryPath, bool recursive) {
    return m_impl->DoCreateBaselines(directoryPath, recursive);
}

bool FileIntegrityMonitor::UpdateBaseline(const std::wstring& filePath) {
    return m_impl->DoCreateBaseline(filePath);
}

bool FileIntegrityMonitor::DeleteBaseline(const std::wstring& filePath) {
    std::wstring normPath = NormalizeFilePath(filePath);
    std::unique_lock lk(m_impl->baselineMutex);
    return m_impl->baselines.erase(normPath) > 0;
}

std::optional<FileBaseline> FileIntegrityMonitor::GetBaseline(const std::wstring& filePath) const {
    std::wstring normPath = NormalizeFilePath(filePath);
    std::shared_lock lk(m_impl->baselineMutex);
    auto it = m_impl->baselines.find(normPath);
    if (it == m_impl->baselines.end()) return std::nullopt;
    return it->second;
}

std::vector<FileBaseline> FileIntegrityMonitor::GetAllBaselines() const {
    std::shared_lock lk(m_impl->baselineMutex);
    std::vector<FileBaseline> result;
    result.reserve(m_impl->baselines.size());
    for (auto& [_, bl] : m_impl->baselines)
        result.push_back(bl);
    return result;
}

std::vector<FileBaseline> FileIntegrityMonitor::GetBaselinesByCategory(FileCategory category) const {
    std::shared_lock lk(m_impl->baselineMutex);
    std::vector<FileBaseline> result;
    for (auto& [_, bl] : m_impl->baselines) {
        if (bl.category == category) result.push_back(bl);
    }
    return result;
}

bool FileIntegrityMonitor::ImportBaselines(const std::wstring& filePath) {
    return m_impl->DoImportBaselines(filePath);
}

bool FileIntegrityMonitor::ExportBaselines(const std::wstring& filePath) const {
    return m_impl->DoExportBaselines(filePath);
}

size_t FileIntegrityMonitor::CreateSystemBaselines() {
    SS_LOG_INFO(L"FIM", L"Creating system baselines...");
    size_t total = 0;
    std::wstring sys32  = Utils::SystemUtils::GetSystemDirectoryPath();
    std::wstring winDir = Utils::SystemUtils::GetWindowsDirectoryPath();

    if (!sys32.empty())
        total += m_impl->DoCreateBaselines(sys32 + L"\\drivers", true);
    if (!winDir.empty())
        total += m_impl->DoCreateBaselines(winDir + L"\\boot", true);

    SS_LOG_INFO(L"FIM", L"System baselines created: %zu entries", total);
    return total;
}

// ---- Verification ----

VerificationResult FileIntegrityMonitor::VerifyIntegrity(const std::wstring& filePath) {
    return m_impl->DoVerifyFile(filePath);
}

BatchVerificationResult FileIntegrityMonitor::VerifyDirectory(
    const std::wstring& directoryPath, bool recursive) {
    std::wstring normDir = NormalizeFilePath(directoryPath);
    std::vector<std::wstring> paths;
    {
        std::shared_lock lk(m_impl->baselineMutex);
        for (auto& [p, _] : m_impl->baselines) {
            if (p.find(normDir) == 0) paths.push_back(p);
        }
    }
    return m_impl->DoBatchVerify(paths);
}

BatchVerificationResult FileIntegrityMonitor::VerifyAll() {
    std::vector<std::wstring> paths;
    {
        std::shared_lock lk(m_impl->baselineMutex);
        paths.reserve(m_impl->baselines.size());
        for (auto& [p, _] : m_impl->baselines) paths.push_back(p);
    }
    return m_impl->DoBatchVerify(paths);
}

BatchVerificationResult FileIntegrityMonitor::VerifyByCategory(FileCategory category) {
    std::vector<std::wstring> paths;
    {
        std::shared_lock lk(m_impl->baselineMutex);
        for (auto& [p, bl] : m_impl->baselines) {
            if (bl.category == category) paths.push_back(p);
        }
    }
    return m_impl->DoBatchVerify(paths);
}

bool FileIntegrityMonitor::QuickVerify(const std::wstring& filePath) {
    std::wstring normPath = NormalizeFilePath(filePath);

    FileBaseline storedBaseline;
    {
        std::shared_lock lk(m_impl->baselineMutex);
        auto it = m_impl->baselines.find(normPath);
        if (it == m_impl->baselines.end()) return false;
        storedBaseline = it->second;
    }

    std::string currentHash;
    if (!ComputeFileHashHex(normPath, HashAlgorithm::SHA256, currentHash)) return false;
    return currentHash == storedBaseline.hashSHA256;
}

// ---- Change Handling ----

FIMAction FileIntegrityMonitor::OnFileChanged(const FileChangeEvent& event) {
    return m_impl->ProcessChangeEvent(event);
}

void FileIntegrityMonitor::OnFileChanged(const std::wstring& filePath,
                                          FileChangeType changeType,
                                          uint32_t processId) {
    m_impl->EnqueueChange(filePath, changeType, processId);
}

std::vector<FileChangeEvent> FileIntegrityMonitor::GetRecentChanges(size_t count) const {
    std::shared_lock lk(m_impl->historyMutex);
    size_t n = (std::min)(count, m_impl->changeHistory.size());
    return {m_impl->changeHistory.end() - static_cast<ptrdiff_t>(n),
            m_impl->changeHistory.end()};
}

std::vector<FileChangeEvent> FileIntegrityMonitor::GetFileChanges(
    const std::wstring& filePath) const {
    std::wstring normPath = NormalizeFilePath(filePath);
    std::shared_lock lk(m_impl->historyMutex);
    std::vector<FileChangeEvent> result;
    for (auto& evt : m_impl->changeHistory) {
        if (evt.filePath == normPath) result.push_back(evt);
    }
    return result;
}

// ---- Remediation ----

bool FileIntegrityMonitor::RestoreFile(const std::wstring& filePath) {
    std::wstring normPath = NormalizeFilePath(filePath);
    if (normPath.empty()) return false;

    // Locate the baseline to find backup path and expected hash
    std::wstring backupPath;
    std::string expectedHash;
    {
        std::shared_lock lk(m_impl->baselineMutex);
        auto it = m_impl->baselines.find(normPath);
        if (it == m_impl->baselines.end()) {
            SS_LOG_WARN(L"FIM", L"RestoreFile: no baseline for: %s", normPath.c_str());
            m_impl->stats.restoresFailed.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        backupPath   = it->second.backupPath;
        expectedHash = it->second.hashSHA256;
    }

    if (backupPath.empty()) {
        SS_LOG_WARN(L"FIM", L"RestoreFile: no backup path in baseline for: %s", normPath.c_str());
        m_impl->stats.restoresFailed.fetch_add(1, std::memory_order_relaxed);
        std::shared_lock lk(m_impl->callbackMutex);
        for (auto& cb : m_impl->restoreCallbacks) {
            try { if (cb.callback) cb.callback(filePath, false); } catch (...) {}
        }
        return false;
    }

    // Perform the actual restore: copy backup over tampered file
    if (!::CopyFileW(backupPath.c_str(), normPath.c_str(), FALSE)) {
        DWORD err = ::GetLastError();
        SS_LOG_ERROR(L"FIM", L"RestoreFile: CopyFileW failed (0x%08X) src=%s dst=%s",
                     err, backupPath.c_str(), normPath.c_str());
        m_impl->stats.restoresFailed.fetch_add(1, std::memory_order_relaxed);
        std::shared_lock lk(m_impl->callbackMutex);
        for (auto& cb : m_impl->restoreCallbacks) {
            try { if (cb.callback) cb.callback(filePath, false); } catch (...) {}
        }
        return false;
    }

    // Post-restore integrity verification
    std::string restoredHash;
    bool verified = false;
    if (ComputeFileHashHex(normPath, HashAlgorithm::SHA256, restoredHash)) {
        verified = (restoredHash == expectedHash);
        if (!verified) {
            SS_LOG_ERROR(L"FIM", L"RestoreFile: post-restore hash mismatch for: %s", normPath.c_str());
        }
    }

    if (!verified) {
        m_impl->stats.restoresFailed.fetch_add(1, std::memory_order_relaxed);
        std::shared_lock lk(m_impl->callbackMutex);
        for (auto& cb : m_impl->restoreCallbacks) {
            try { if (cb.callback) cb.callback(filePath, false); } catch (...) {}
        }
        return false;
    }

    m_impl->stats.restoresPerformed.fetch_add(1, std::memory_order_relaxed);
    SS_LOG_INFO(L"FIM", L"RestoreFile: successfully restored: %s", normPath.c_str());

    std::shared_lock lk(m_impl->callbackMutex);
    for (auto& cb : m_impl->restoreCallbacks) {
        try { if (cb.callback) cb.callback(filePath, true); } catch (...) {}
    }
    return true;
}

bool FileIntegrityMonitor::RestoreFile(const std::wstring& filePath, uint32_t /*version*/) {
    return RestoreFile(filePath);
}

size_t FileIntegrityMonitor::RestoreAllViolations() {
    std::vector<std::wstring> violatedPaths;
    {
        std::shared_lock lk(m_impl->violationMutex);
        for (auto& v : m_impl->violationList) {
            if (!v.wasRemediated)
                violatedPaths.push_back(v.filePath);
        }
    }

    size_t restored = 0;
    for (auto& path : violatedPaths) {
        if (RestoreFile(path)) ++restored;
    }
    return restored;
}

std::vector<IntegrityViolation> FileIntegrityMonitor::GetViolations() const {
    std::shared_lock lk(m_impl->violationMutex);
    return {m_impl->violationList.begin(), m_impl->violationList.end()};
}

std::vector<IntegrityViolation> FileIntegrityMonitor::GetUnresolvedViolations() const {
    std::shared_lock lk(m_impl->violationMutex);
    std::vector<IntegrityViolation> result;
    for (auto& v : m_impl->violationList) {
        if (!v.wasRemediated) result.push_back(v);
    }
    return result;
}

void FileIntegrityMonitor::ResolveViolation(uint64_t violationId) {
    std::unique_lock lk(m_impl->violationMutex);
    for (auto& v : m_impl->violationList) {
        if (v.violationId == violationId) {
            v.wasRemediated = true;
            m_impl->stats.violationsRemediated.fetch_add(1, std::memory_order_relaxed);
            return;
        }
    }
}

// ---- Rule Management ----

bool FileIntegrityMonitor::AddRule(const MonitoringRule& rule) {
    if (rule.ruleId.empty()) return false;
    std::unique_lock lk(m_impl->ruleMutex);
    for (auto& r : m_impl->rules) {
        if (r.ruleId == rule.ruleId) return false;
    }
    MonitoringRule r = rule;
    if (r.created == std::chrono::system_clock::time_point{})
        r.created = std::chrono::system_clock::now();
    m_impl->rules.push_back(std::move(r));
    return true;
}

bool FileIntegrityMonitor::RemoveRule(const std::string& ruleId) {
    std::unique_lock lk(m_impl->ruleMutex);
    auto it = std::remove_if(m_impl->rules.begin(), m_impl->rules.end(),
        [&](const MonitoringRule& r) { return r.ruleId == ruleId; });
    if (it == m_impl->rules.end()) return false;
    m_impl->rules.erase(it, m_impl->rules.end());
    return true;
}

void FileIntegrityMonitor::SetRuleEnabled(const std::string& ruleId, bool enabled) {
    std::unique_lock lk(m_impl->ruleMutex);
    for (auto& r : m_impl->rules) {
        if (r.ruleId == ruleId) {
            r.enabled = enabled;
            return;
        }
    }
}

std::optional<MonitoringRule> FileIntegrityMonitor::GetRule(const std::string& ruleId) const {
    std::shared_lock lk(m_impl->ruleMutex);
    for (auto& r : m_impl->rules) {
        if (r.ruleId == ruleId) return r;
    }
    return std::nullopt;
}

std::vector<MonitoringRule> FileIntegrityMonitor::GetRules() const {
    std::shared_lock lk(m_impl->ruleMutex);
    return m_impl->rules;
}

bool FileIntegrityMonitor::LoadRulesFromFile(const std::wstring& filePath) {
    Utils::FileUtils::Error err{};
    std::string content;
    if (!Utils::FileUtils::ReadAllTextUtf8(filePath, content, &err))
        return false;

    std::istringstream iss(content);
    std::string line;
    size_t loaded = 0;

    while (std::getline(iss, line)) {
        if (line.empty() || line[0] == '#') continue;
        size_t p1 = line.find('|');
        if (p1 == std::string::npos) continue;
        size_t p2 = line.find('|', p1 + 1);
        if (p2 == std::string::npos) continue;

        MonitoringRule rule{};
        rule.ruleId     = line.substr(0, p1);
        rule.name       = Utils::StringUtils::ToWide(line.substr(p1 + 1, p2 - p1 - 1));
        rule.pathPattern = Utils::StringUtils::ToWide(line.substr(p2 + 1));
        rule.enabled    = true;
        rule.created    = std::chrono::system_clock::now();

        if (AddRule(rule)) ++loaded;
    }
    SS_LOG_INFO(L"FIM", L"Loaded %zu rules from: %s", loaded, filePath.c_str());
    return loaded > 0;
}

bool FileIntegrityMonitor::SaveRulesToFile(const std::wstring& filePath) const {
    std::shared_lock lk(m_impl->ruleMutex);
    std::ostringstream oss;
    oss << "# ShadowStrike FIM Rules\n";
    for (auto& r : m_impl->rules) {
        oss << r.ruleId << "|"
            << Utils::StringUtils::ToNarrow(r.name) << "|"
            << Utils::StringUtils::ToNarrow(r.pathPattern) << "\n";
    }
    Utils::FileUtils::Error err{};
    return Utils::FileUtils::WriteAllTextUtf8Atomic(filePath, oss.str(), &err);
}

// ---- Directory Monitoring ----

bool FileIntegrityMonitor::AddMonitoredDirectory(
    const std::wstring& directoryPath, bool recursive) {
    return m_impl->DoAddMonitoredDirectory(directoryPath, recursive);
}

void FileIntegrityMonitor::RemoveMonitoredDirectory(const std::wstring& dirPath) {
    std::wstring normDir = NormalizeFilePath(dirPath);
    std::unique_lock lk(m_impl->dirWatchMutex);
    auto it = std::remove_if(m_impl->dirWatches.begin(), m_impl->dirWatches.end(),
        [&](const std::unique_ptr<Impl::DirWatch>& dw) {
            return dw->directory == normDir;
        });
    if (it != m_impl->dirWatches.end())
        m_impl->dirWatches.erase(it, m_impl->dirWatches.end());
}

std::vector<std::wstring> FileIntegrityMonitor::GetMonitoredDirectories() const {
    std::shared_lock lk(m_impl->dirWatchMutex);
    std::vector<std::wstring> result;
    result.reserve(m_impl->dirWatches.size());
    for (auto& dw : m_impl->dirWatches)
        result.push_back(dw->directory);
    return result;
}

// ---- Query ----

bool FileIntegrityMonitor::IsFileMonitored(const std::wstring& filePath) const {
    std::wstring normPath = NormalizeFilePath(filePath);
    std::shared_lock lk(m_impl->baselineMutex);
    return m_impl->baselines.count(normPath) > 0;
}

FileCategory FileIntegrityMonitor::GetFileCategory(const std::wstring& filePath) const {
    return m_impl->ClassifyFileImpl(NormalizeFilePath(filePath));
}

std::string FileIntegrityMonitor::CalculateFileHash(
    const std::wstring& filePath, HashAlgorithm algorithm) const {
    std::string hex;
    ComputeFileHashHex(filePath, algorithm, hex);
    return hex;
}

std::optional<FileAttributes> FileIntegrityMonitor::QueryFileAttributes(
    const std::wstring& filePath) const {
    DWORD attrs = ::GetFileAttributesW(filePath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return std::nullopt;
    return CollectFileAttributes(filePath);
}

std::optional<FileSignatureInfo> FileIntegrityMonitor::GetFileSignature(
    const std::wstring& filePath) const {
    if (!IsPEFile(filePath)) return std::nullopt;
    auto sig = CollectSignatureInfo(filePath);
    if (!sig.isSigned && sig.signerName.empty()) return std::nullopt;
    return sig;
}

// ---- Statistics ----

FIMStats FileIntegrityMonitor::GetStats() const {
    return m_impl->stats.Snapshot();
}

void FileIntegrityMonitor::ResetStats() {
    auto& s = m_impl->stats;
    s.changesDetected.store(0, std::memory_order_relaxed);
    s.violations.store(0, std::memory_order_relaxed);
    s.violationsRemediated.store(0, std::memory_order_relaxed);
    s.verificationsPerformed.store(0, std::memory_order_relaxed);
    s.verificationsPassed.store(0, std::memory_order_relaxed);
    s.verificationsFailed.store(0, std::memory_order_relaxed);
    s.baselinesCreated.store(0, std::memory_order_relaxed);
    s.baselinesUpdated.store(0, std::memory_order_relaxed);
    s.restoresPerformed.store(0, std::memory_order_relaxed);
    s.restoresFailed.store(0, std::memory_order_relaxed);
    s.totalVerificationTimeMs.store(0, std::memory_order_relaxed);
}

// ---- Compliance Reporting ----

bool FileIntegrityMonitor::GenerateComplianceReport(
    const std::wstring& outputPath,
    const std::vector<std::string>& complianceTags) const {

    auto stats = m_impl->stats.Snapshot();
    std::ostringstream oss;
    oss << "# ShadowStrike FIM Compliance Report\n";
    oss << "# Generated: " << std::chrono::system_clock::now().time_since_epoch().count() << "\n\n";

    oss << "## Summary\n";
    oss << "Monitored Files: " << stats.monitoredFiles << "\n";
    oss << "Monitored Directories: " << stats.monitoredDirectories << "\n";
    oss << "Verifications Performed: " << stats.verificationsPerformed << "\n";
    oss << "Verifications Passed: " << stats.verificationsPassed << "\n";
    oss << "Verifications Failed: " << stats.verificationsFailed << "\n";
    oss << "Violations: " << stats.violations << "\n";
    oss << "Violations Remediated: " << stats.violationsRemediated << "\n";

    if (!complianceTags.empty()) {
        oss << "\n## Compliance Tags\n";
        for (auto& tag : complianceTags) oss << "- " << tag << "\n";
    }

    // Per-category breakdown
    oss << "\n## Baselines by Category\n";
    {
        std::shared_lock lk(m_impl->baselineMutex);
        std::map<FileCategory, size_t> catCounts;
        for (auto& [_, bl] : m_impl->baselines)
            catCounts[bl.category]++;
        for (auto& [cat, cnt] : catCounts)
            oss << FileCategoryToString(cat) << ": " << cnt << "\n";
    }

    // Unresolved violations
    oss << "\n## Unresolved Violations\n";
    {
        std::shared_lock lk(m_impl->violationMutex);
        for (auto& v : m_impl->violationList) {
            if (!v.wasRemediated) {
                oss << Utils::StringUtils::ToNarrow(v.filePath)
                    << " [" << FileChangeTypeToString(v.violationType) << "]"
                    << " severity=" << v.severity << "\n";
            }
        }
    }

    Utils::FileUtils::Error err{};
    return Utils::FileUtils::WriteAllTextUtf8Atomic(outputPath, oss.str(), &err);
}

std::vector<FileChangeEvent> FileIntegrityMonitor::GetAuditLog(
    std::chrono::system_clock::time_point startTime,
    std::chrono::system_clock::time_point endTime) const {
    std::shared_lock lk(m_impl->historyMutex);
    std::vector<FileChangeEvent> result;
    for (auto& evt : m_impl->changeHistory) {
        if (evt.timestamp >= startTime && evt.timestamp <= endTime)
            result.push_back(evt);
    }
    return result;
}

// ---- Callbacks ----

uint64_t FileIntegrityMonitor::RegisterChangeCallback(FileChangeCallback callback) {
    if (!callback) return 0;
    uint64_t id = m_impl->nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    std::unique_lock lk(m_impl->callbackMutex);
    m_impl->changeCallbacks.push_back({id, std::move(callback)});
    return id;
}

bool FileIntegrityMonitor::UnregisterChangeCallback(uint64_t callbackId) {
    std::unique_lock lk(m_impl->callbackMutex);
    auto& cbs = m_impl->changeCallbacks;
    auto it = std::remove_if(cbs.begin(), cbs.end(),
        [callbackId](const Impl::CallbackEntry& e) { return e.id == callbackId; });
    if (it == cbs.end()) return false;
    cbs.erase(it, cbs.end());
    return true;
}

uint64_t FileIntegrityMonitor::RegisterViolationCallback(ViolationCallback callback) {
    if (!callback) return 0;
    uint64_t id = m_impl->nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    std::unique_lock lk(m_impl->callbackMutex);
    m_impl->violationCallbacks.push_back({id, std::move(callback)});
    return id;
}

bool FileIntegrityMonitor::UnregisterViolationCallback(uint64_t callbackId) {
    std::unique_lock lk(m_impl->callbackMutex);
    auto& cbs = m_impl->violationCallbacks;
    auto it = std::remove_if(cbs.begin(), cbs.end(),
        [callbackId](const Impl::ViolationCbEntry& e) { return e.id == callbackId; });
    if (it == cbs.end()) return false;
    cbs.erase(it, cbs.end());
    return true;
}

uint64_t FileIntegrityMonitor::RegisterVerificationCallback(VerificationCallback callback) {
    if (!callback) return 0;
    uint64_t id = m_impl->nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    std::unique_lock lk(m_impl->callbackMutex);
    m_impl->verificationCallbacks.push_back({id, std::move(callback)});
    return id;
}

bool FileIntegrityMonitor::UnregisterVerificationCallback(uint64_t callbackId) {
    std::unique_lock lk(m_impl->callbackMutex);
    auto& cbs = m_impl->verificationCallbacks;
    auto it = std::remove_if(cbs.begin(), cbs.end(),
        [callbackId](const Impl::VerificationCbEntry& e) { return e.id == callbackId; });
    if (it == cbs.end()) return false;
    cbs.erase(it, cbs.end());
    return true;
}

uint64_t FileIntegrityMonitor::RegisterRestoreCallback(RestoreCallback callback) {
    if (!callback) return 0;
    uint64_t id = m_impl->nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    std::unique_lock lk(m_impl->callbackMutex);
    m_impl->restoreCallbacks.push_back({id, std::move(callback)});
    return id;
}

bool FileIntegrityMonitor::UnregisterRestoreCallback(uint64_t callbackId) {
    std::unique_lock lk(m_impl->callbackMutex);
    auto& cbs = m_impl->restoreCallbacks;
    auto it = std::remove_if(cbs.begin(), cbs.end(),
        [callbackId](const Impl::RestoreCbEntry& e) { return e.id == callbackId; });
    if (it == cbs.end()) return false;
    cbs.erase(it, cbs.end());
    return true;
}

// ---- External Integration ----

void FileIntegrityMonitor::SetHashStore(HashStore::HashStore* store) {
    m_impl->hashStore = store;
}

void FileIntegrityMonitor::SetDatabaseManager(Database::DatabaseManager* manager) {
    m_impl->databaseManager = manager;
}

void FileIntegrityMonitor::SetFileBackupManager(Backup::FileBackupManager* manager) {
    m_impl->backupManager = manager;
}

// ---- Private methods (declared in HPP) ----

void FileIntegrityMonitor::InitializeSystemMonitoring() {
    m_impl->SetupSystemWatches();
}

void FileIntegrityMonitor::DirectoryMonitorThread() {
    m_impl->DirectoryMonitorLoop();
}

void FileIntegrityMonitor::ScheduledVerificationThread() {
    m_impl->ScheduledVerificationLoop();
}

void FileIntegrityMonitor::ProcessChangeQueue() {
    m_impl->ChangeQueueProcessor();
}

FileCategory FileIntegrityMonitor::ClassifyFile(const std::wstring& filePath) const {
    return m_impl->ClassifyFileImpl(NormalizeFilePath(filePath));
}

double FileIntegrityMonitor::CalculateRiskScore(const FileChangeEvent& event) const {
    return m_impl->CalculateRiskScoreImpl(event);
}

FIMAction FileIntegrityMonitor::InvokeChangeCallbacks(const FileChangeEvent& event) {
    return m_impl->ProcessChangeEvent(event);
}

void FileIntegrityMonitor::InvokeViolationCallbacks(const IntegrityViolation& violation) {
    std::shared_lock lk(m_impl->callbackMutex);
    for (auto& cb : m_impl->violationCallbacks) {
        try { if (cb.callback) cb.callback(violation); } catch (...) {}
    }
}

} // namespace RealTime
} // namespace ShadowStrike