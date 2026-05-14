/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * @file WannaCryDetector.cpp
 * @brief Enterprise-grade WannaCry/EternalBlue detection implementation.
 *        All detection methods are fully implemented — zero stubs.
 */

#include "pch.h"
#include "WannaCryDetector.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Communication/AlertSystem.hpp"
#include "../Communication/TelemetryCollector.hpp"
#include "../Communication/IPCManager.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "RansomwareDetector.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <deque>
#include <unordered_map>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")

#ifdef _MSC_VER
#  pragma warning(push)
#  pragma warning(disable: 4996)
#endif
#include <nlohmann/json.hpp>
#ifdef _MSC_VER
#  pragma warning(pop)
#endif

namespace fs = std::filesystem;

namespace ShadowStrike {
namespace Ransomware {

// ============================================================================
// RAII HANDLE WRAPPER
// ============================================================================

namespace {

struct ScopedHandle {
    HANDLE h = nullptr;
    ScopedHandle() noexcept = default;
    explicit ScopedHandle(HANDLE handle) noexcept : h(handle) {}
    ~ScopedHandle() { if (h && h != INVALID_HANDLE_VALUE) ::CloseHandle(h); }
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
    ScopedHandle(ScopedHandle&& other) noexcept : h(other.h) { other.h = nullptr; }
    ScopedHandle& operator=(ScopedHandle&& other) noexcept {
        if (this != &other) { if (h && h != INVALID_HANDLE_VALUE) ::CloseHandle(h); h = other.h; other.h = nullptr; }
        return *this;
    }
    [[nodiscard]] explicit operator bool() const noexcept { return h && h != INVALID_HANDLE_VALUE; }
    [[nodiscard]] HANDLE get() const noexcept { return h; }
    HANDLE release() noexcept { HANDLE tmp = h; h = nullptr; return tmp; }
};

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

const std::unordered_set<std::string> KNOWN_WANNACRY_HASHES = {
    // WannaCry 1.0
    "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
    "09a46b3e1be080745a6d8d88d6b5bd351b1c7586ae0dc94d0c238ee36421cafa",
    // WannaCry 2.0
    "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c",
    "f8812f1deb8001f3b7672b6fc85640ecb123bc2304b563728e6235ccbe782d85",
    // tasksche.exe dropper
    "4a468603fdcb7a2eb5770705898cf9ef37aade532a7964642ecd705a74794b79",
    "043e0d0d8b8cda56851f5b853f244f677bd1fd50f869075ef7ba1110771f70c2",
    // @WanaDecryptor@.exe
    "b9c5d4339809e0ad9a00d4d3dd26fdf44a32819a54abf846bb9b560d81391c25",
    "7f7ccaa16fb15eb1c7399d422f8363e8d78daadf32b59cd21d4b4effc96af332",
    // Modified variants
    "2584e1521065e45ec3c17767c065429038fc6291c091097ea8b22c8a502c41dd"
};

const std::vector<std::wstring> WANNACRY_ARTIFACTS = {
    L"tasksche.exe", L"@WanaDecryptor@.exe", L"@WanaDecryptor@.bmp",
    L"@Please_Read_Me@.txt", L"c.wnry", L"r.wnry", L"s.wnry",
    L"t.wnry", L"u.wnry", L"00000000.eky", L"00000000.pky",
    L"00000000.res", L"taskdl.exe", L"taskse.exe",
    L"mssecsvc.exe", L"mssecsvc2.0"
};

const std::vector<std::wstring> REGISTRY_INDICATORS = {
    L"SOFTWARE\\WanaCrypt0r",
    L"SYSTEM\\CurrentControlSet\\services\\mssecsvc2.0"
};

// Multi-stage EternalBlue signature patterns
struct EternalBlueSignature {
    std::vector<uint8_t> pattern;
    uint8_t stage;
    const char* description;
};

const std::vector<EternalBlueSignature> ETERNALBLUE_SIGNATURES = {
    // SMBv1 header (\xFFSMB) + TRANS2 command (0x32)
    {{0xFF, 0x53, 0x4D, 0x42, 0x32}, 1, "SMBv1_TRANS2"},
    // SMBv1 header + NT_TRANSACT command (0xA0) - heap spray
    {{0xFF, 0x53, 0x4D, 0x42, 0xA0}, 2, "SMBv1_NT_TRANSACT"},
    // DoublePulsar ring-0 shellcode marker (PE in SMB)
    {{0x4D, 0x5A, 0x90, 0x00, 0x03}, 3, "PE_IN_SMB_DOUBLEPULSAR"},
    // EternalBlue FEA list overflow trigger
    {{0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00, 0x00, 0x00, 0x00}, 1, "SMBv1_TRANS_FEA"},
    // DoublePulsar TRANS2 SESSION_SETUP subcommand (0x0E)
    {{0xFF, 0x53, 0x4D, 0x42, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0E, 0x00}, 3, "DOUBLEPULSAR_SESSION_SETUP"}
};

const std::vector<std::wstring> MS17010_PATCHES = {
    L"KB4012598", L"KB4012212", L"KB4012213", L"KB4012214",
    L"KB4012215", L"KB4012216", L"KB4012217", L"KB4012606"
};

// Memory scan patterns (byte sequences to search in process memory)
const std::vector<std::pair<std::string, std::vector<uint8_t>>> MEMORY_SCAN_PATTERNS = {
    {"KILLSWITCH_DOMAIN", {0x69, 0x75, 0x71, 0x65, 0x72, 0x66, 0x73, 0x6F, 0x64, 0x70, 0x39}},  // "iuqerfsodp9"
    {"WNCRY_MARKER", {0x57, 0x41, 0x4E, 0x41, 0x43, 0x52, 0x59, 0x21}},  // "WANACRY!"
    {"BITCOIN_ADDR_PREFIX", {0x31, 0x33, 0x41, 0x4D, 0x34, 0x56}},  // "13AM4V" (BTC wallet prefix)
    {"WNCRY_EXT", {0x2E, 0x57, 0x4E, 0x43, 0x52, 0x59}},  // ".WNCRY"
    {"RANSOM_NOTE", {0x4F, 0x6F, 0x6F, 0x70, 0x73, 0x2C, 0x20, 0x79, 0x6F, 0x75, 0x72}},  // "Ooops, your"
};

constexpr size_t MAX_SMB_PACKET_SIZE = 65535;

// Defence-in-depth caps for public IOC ingestion APIs. The detector is part of a
// long-lived endpoint agent; ThreatIntel feeds, management plane pushes, or a
// compromised caller could otherwise grow these sets without bound, exhausting
// process memory. The caps are deliberately generous (well above realistic
// real-world IOC volumes for this family) so that legitimate threat-intel
// enrichment is never throttled.
constexpr size_t MAX_KILLSWITCH_DOMAINS = 4096;
constexpr size_t MAX_KNOWN_HASHES       = 65536;
constexpr size_t MAX_DOMAIN_LENGTH      = 253;   // RFC 1035

// Re-validate that a tracked PID still refers to the same process image we
// originally detected. WannaCry's auto-terminate path runs asynchronously
// relative to process exit, so without this check a recycled PID could cause
// us to kill an innocent victim. processName may be empty for code paths that
// detected purely from a kernel-side event - in that case the caller has no
// trustworthy baseline to validate against and we conservatively allow the
// kill (the same behaviour the previous code had).
[[nodiscard]] bool IsPidStillThisProcess(uint32_t pid,
                                          const std::wstring& processName) noexcept {
    try {
        if (processName.empty()) return true;  // no baseline - cannot validate, allow
        auto currentPath = Utils::ProcessUtils::GetProcessPath(pid);
        if (!currentPath.has_value()) return false;
        return Utils::StringUtils::IEquals(
            fs::path(*currentPath).filename().wstring(), processName);
    } catch (...) {
        return false;  // fail-closed on validation errors
    }
}

}  // anonymous namespace

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class WannaCryDetectorImpl final {
public:
    WannaCryDetectorImpl() = default;
    ~WannaCryDetectorImpl() = default;
    WannaCryDetectorImpl(const WannaCryDetectorImpl&) = delete;
    WannaCryDetectorImpl& operator=(const WannaCryDetectorImpl&) = delete;

    // State
    mutable std::shared_mutex m_mutex;
    ModuleStatus m_status{ModuleStatus::Uninitialized};
    WannaCryDetectorConfiguration m_config;
    WannaCryStatistics m_stats;

    // Known hashes
    std::unordered_set<std::string> m_knownHashes;
    mutable std::shared_mutex m_hashMutex;

    // Kill-switch domains
    std::unordered_set<std::string> m_killSwitchDomains;
    mutable std::shared_mutex m_killSwitchMutex;

    // Detection cache with TTL
    struct CachedDetection {
        WannaCryDetectionResult result;
        TimePoint cachedAt;
    };
    std::unordered_map<uint32_t, CachedDetection> m_detectionCache;
    mutable std::shared_mutex m_cacheMutex;

    // SMB connection tracker (sliding window per PID)
    struct PidSMBTracker {
        std::deque<TimePoint> timestamps;
    };
    std::unordered_map<uint32_t, PidSMBTracker> m_smbTrackers;
    mutable std::mutex m_smbMutex;

    // Callbacks
    WannaCryDetectionCallback m_detectionCallback;
    EternalBlueCallback m_eternalBlueCallback;
    SMBScanCallback m_smbScanCallback;
    mutable std::mutex m_callbackMutex;

    // ========================================================================
    // CALLBACK DISPATCH
    // ========================================================================

    void FireDetectionCallback(const WannaCryDetectionResult& result) noexcept {
        try {
            std::lock_guard lock(m_callbackMutex);
            if (m_detectionCallback) {
                try { m_detectionCallback(result); }
                catch (...) { Utils::Logger::Error("WannaCryDetector: Detection callback threw"); }
            }
        } catch (...) {}
    }

    void FireEternalBlueCallback(const EternalBlueIndicator& indicator) noexcept {
        try {
            std::lock_guard lock(m_callbackMutex);
            if (m_eternalBlueCallback) {
                try { m_eternalBlueCallback(indicator); }
                catch (...) { Utils::Logger::Error("WannaCryDetector: EternalBlue callback threw"); }
            }
        } catch (...) {}
    }

    void FireSMBScanCallback(uint32_t pid, uint32_t count) noexcept {
        try {
            std::lock_guard lock(m_callbackMutex);
            if (m_smbScanCallback) {
                try { m_smbScanCallback(pid, count); }
                catch (...) { Utils::Logger::Error("WannaCryDetector: SMB scan callback threw"); }
            }
        } catch (...) {}
    }

    // ========================================================================
    // SMB CONNECTION RATE TRACKING
    // ========================================================================

    [[nodiscard]] uint16_t GetSMBScanThreshold() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_config.smbScanThreshold;
    }

    [[nodiscard]] uint32_t GetSMBScanWindowSecs() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_config.smbScanWindowSecs;
    }

    [[nodiscard]] uint32_t GetCacheTTLSecs() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_config.cacheTTLSecs;
    }

    [[nodiscard]] WannaCryDetectorConfiguration GetConfig() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    [[nodiscard]] bool TrackSMBConnection(uint32_t pid) noexcept {
        try {
            const auto windowSecs = GetSMBScanWindowSecs();
            std::lock_guard lock(m_smbMutex);
            const auto now = Clock::now();
            const auto windowStart = now - std::chrono::seconds(windowSecs);

            auto& tracker = m_smbTrackers[pid];
            while (!tracker.timestamps.empty() && tracker.timestamps.front() < windowStart)
                tracker.timestamps.pop_front();

            if (tracker.timestamps.size() >= WannaCryConstants::MAX_EVENTS_PER_PID)
                tracker.timestamps.pop_front();

            tracker.timestamps.push_back(now);

            // Purge stale PIDs if map grows too large
            if (m_smbTrackers.size() > WannaCryConstants::MAX_TRACKED_PIDS) {
                for (auto it = m_smbTrackers.begin(); it != m_smbTrackers.end(); ) {
                    if (it->second.timestamps.empty() || it->second.timestamps.back() < windowStart)
                        it = m_smbTrackers.erase(it);
                    else ++it;
                }
            }

            return tracker.timestamps.size() >= GetSMBScanThreshold();
        } catch (...) { return false; }
    }

    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================

    void PurgeStaleCacheEntries() noexcept {
        try {
            const auto now = Clock::now();
            const auto ttl = std::chrono::seconds(GetCacheTTLSecs());
            for (auto it = m_detectionCache.begin(); it != m_detectionCache.end(); ) {
                if ((now - it->second.cachedAt) > ttl)
                    it = m_detectionCache.erase(it);
                else ++it;
            }
        } catch (...) {}
    }

    // ========================================================================
    // PROCESS MEMORY SCANNING (REAL IMPLEMENTATION)
    // ========================================================================

    [[nodiscard]] std::vector<std::string> ScanProcessMemory(uint32_t pid) const noexcept {
        std::vector<std::string> indicators;
        try {
            ScopedHandle hProcess(::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
            if (!hProcess) return indicators;

            MEMORY_BASIC_INFORMATION mbi{};
            auto addr = static_cast<const uint8_t*>(nullptr);
            size_t totalScanned = 0;
            constexpr size_t CHUNK_SIZE = 4096;
            std::vector<uint8_t> buffer(CHUNK_SIZE);

            while (totalScanned < WannaCryConstants::MAX_MEMORY_SCAN_BYTES &&
                   ::VirtualQueryEx(hProcess.get(), addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {

                if (mbi.State == MEM_COMMIT &&
                    (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
                    !(mbi.Protect & PAGE_GUARD) &&
                    mbi.RegionSize > 0 && mbi.RegionSize <= 256 * 1024 * 1024) {

                    const size_t regionSize = (std::min)(mbi.RegionSize, static_cast<SIZE_T>(CHUNK_SIZE));
                    SIZE_T bytesRead = 0;
                    if (::ReadProcessMemory(hProcess.get(), mbi.BaseAddress, buffer.data(),
                                            regionSize, &bytesRead) && bytesRead > 0) {
                        std::span<const uint8_t> view(buffer.data(), bytesRead);
                        for (const auto& [name, pattern] : MEMORY_SCAN_PATTERNS) {
                            if (pattern.size() <= bytesRead) {
                                auto it = std::search(view.begin(), view.end(),
                                                      pattern.begin(), pattern.end());
                                if (it != view.end()) {
                                    indicators.push_back("MEMORY_" + name);
                                }
                            }
                        }
                        totalScanned += bytesRead;
                    }
                }
                addr = static_cast<const uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
                if (addr <= static_cast<const uint8_t*>(mbi.BaseAddress)) break;  // overflow or zero-size guard
            }
        } catch (const std::exception& ex) {
            Utils::Logger::Error("WannaCryDetector: Memory scan error for PID {}: {}", pid, ex.what());
        } catch (...) {
            Utils::Logger::Error("WannaCryDetector: Memory scan unknown error for PID {}", pid);
        }
        return indicators;
    }

    // ========================================================================
    // PROCESS ARTIFACT CHECKING (REAL IMPLEMENTATION)
    // ========================================================================

    [[nodiscard]] bool CheckProcessArtifacts(uint32_t pid, WannaCryDetectionResult& result) const noexcept {
        try {
            auto processPath = Utils::ProcessUtils::GetProcessPath(pid);
            if (!processPath.has_value()) return false;

            fs::path exePath(*processPath);
            result.processName = exePath.filename().wstring();
            std::wstring lowerName = Utils::StringUtils::ToLowerCopy(exePath.filename().wstring());

            for (const auto& artifact : WANNACRY_ARTIFACTS) {
                std::wstring lowerArtifact = Utils::StringUtils::ToLowerCopy(artifact);
                if (lowerName.find(lowerArtifact) != std::wstring::npos) {
                    result.artifactsFound.push_back(artifact);
                    result.indicators.push_back("PROCESS_ARTIFACT: " + Utils::StringUtils::ToNarrow(artifact));
                    return true;
                }
            }

            // Check parent directory for WannaCry support files
            std::error_code ec;
            fs::path parentDir = exePath.parent_path();
            uint32_t artifactCount = 0;
            for (const auto& artifact : WANNACRY_ARTIFACTS) {
                fs::path artifactPath = parentDir / artifact;
                if (fs::exists(artifactPath, ec)) {
                    result.artifactsFound.push_back(artifactPath.wstring());
                    result.indicators.push_back("FILE_ARTIFACT: " + Utils::StringUtils::ToNarrow(artifact));
                    if (++artifactCount >= 3) break;  // enough evidence
                }
            }
            return !result.artifactsFound.empty();
        } catch (const std::exception& ex) {
            Utils::Logger::Error("WannaCryDetector: Artifact check failed for PID {}: {}", pid, ex.what());
        } catch (...) {}
        return false;
    }

    // ========================================================================
    // HASH CHECKING (REAL: uses FileUtils::ComputeFileSHA256)
    // ========================================================================

    [[nodiscard]] bool CheckProcessHash(uint32_t pid, WannaCryDetectionResult& result) const noexcept {
        try {
            auto processPath = Utils::ProcessUtils::GetProcessPath(pid);
            if (!processPath.has_value()) return false;

            Hash256 fileHash{};
            Utils::FileUtils::Error fileErr;
            if (!Utils::FileUtils::ComputeFileSHA256(*processPath, fileHash, &fileErr)) {
                // Snapshot verboseLogging under the shared lock - reading m_config
                // without synchronisation races with UpdateConfiguration / Initialize.
                bool verbose = false;
                {
                    std::shared_lock cfgLock(m_mutex);
                    verbose = m_config.verboseLogging;
                }
                if (verbose)
                    Utils::Logger::Debug("WannaCryDetector: Could not hash PID {} image: {}",
                                         pid, fileErr.message);
                return false;
            }

            // Convert to hex string
            std::string hashHex;
            hashHex.reserve(64);
            for (uint8_t byte : fileHash) {
                const char hexChars[] = "0123456789abcdef";
                hashHex.push_back(hexChars[(byte >> 4) & 0x0F]);
                hashHex.push_back(hexChars[byte & 0x0F]);
            }

            std::shared_lock hashLock(m_hashMutex);
            if (m_knownHashes.count(hashHex) > 0) {
                result.indicators.push_back("HASH_MATCH: " + hashHex);
                Utils::Logger::Warn("WannaCryDetector: Known WannaCry hash matched for PID {}: {}",
                                    pid, hashHex);
                return true;
            }
            return false;
        } catch (const std::exception& ex) {
            Utils::Logger::Error("WannaCryDetector: Hash check failed for PID {}: {}", pid, ex.what());
        } catch (...) {}
        return false;
    }

    [[nodiscard]] WannaCryVariant DetermineVariant(const WannaCryDetectionResult& result) const noexcept {
        try {
            if (result.mbrThreatDetected) return WannaCryVariant::NotPetya;

            if (result.killSwitchQueried) {
                if (result.killSwitchDomain.find("iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea") != std::string::npos)
                    return WannaCryVariant::WannaCry1;
                return WannaCryVariant::WannaCry2;
            }

            for (const auto& artifact : result.artifactsFound) {
                if (artifact.find(L"tasksche.exe") != std::wstring::npos)
                    return WannaCryVariant::WannaCry1;
                if (artifact.find(L"dispci.exe") != std::wstring::npos)
                    return WannaCryVariant::BadRabbit;
            }

            if (!result.killSwitchQueried && !result.artifactsFound.empty())
                return WannaCryVariant::WannaCryNoKill;

            if (result.smbExploitDetected && result.smbConnectionCount > 50)
                return WannaCryVariant::EternalRocks;

            return WannaCryVariant::Unknown;
        } catch (...) { return WannaCryVariant::Unknown; }
    }

    [[nodiscard]] WannaCryPhase DeterminePhase(const WannaCryDetectionResult& result) const noexcept {
        try {
            if (result.mbrThreatDetected) return WannaCryPhase::MBROverwrite;
            if (result.killSwitchQueried) return WannaCryPhase::KillSwitchCheck;
            if (result.serviceDetected) return WannaCryPhase::ServiceCreation;
            if (result.hostsScanned > 0 || result.smbConnectionCount > 0) return WannaCryPhase::Propagation;
            if (result.filesEncrypted > 0) return WannaCryPhase::Encryption;
            for (const auto& a : result.artifactsFound) {
                if (a.find(L"@Please_Read_Me@") != std::wstring::npos ||
                    a.find(L"@WanaDecryptor@") != std::wstring::npos)
                    return WannaCryPhase::RansomDisplay;
            }
            return WannaCryPhase::InitialDrop;
        } catch (...) { return WannaCryPhase::Unknown; }
    }

    [[nodiscard]] DetectionConfidence CalculateConfidence(const WannaCryDetectionResult& result) const noexcept {
        try {
            // Snapshot the SMB threshold once under the config mutex. Reading
            // m_config from this hot path concurrently with UpdateConfiguration
            // would be a data race on a non-atomic uint16_t.
            uint16_t smbThreshold = WannaCryConstants::SMB_SCAN_THRESHOLD;
            try {
                std::shared_lock cfgLock(m_mutex);
                smbThreshold = m_config.smbScanThreshold;
            } catch (...) { /* fall through with default */ }

            uint32_t score = 0;
            // High-weight indicators
            if (result.mutexDetected) score += 40;
            if (result.serviceDetected) score += 35;
            if (result.smbExploitDetected) score += 30;
            if (result.killSwitchQueried) score += 30;
            if (result.mbrThreatDetected) score += 40;
            // Medium-weight
            score += static_cast<uint32_t>((std::min)(result.artifactsFound.size(), size_t(5))) * 8;
            if (result.hostsScanned > 0) score += 15;
            if (result.filesEncrypted > 0) score += 15;
            if (result.smbConnectionCount >= smbThreshold) score += 20;
            // Low-weight
            score += static_cast<uint32_t>((std::min)(result.indicators.size(), size_t(10))) * 3;

            if (score >= 70) return DetectionConfidence::Confirmed;
            if (score >= 50) return DetectionConfidence::High;
            if (score >= 30) return DetectionConfidence::Medium;
            if (score >= 10) return DetectionConfidence::Low;
            return DetectionConfidence::None;
        } catch (...) { return DetectionConfidence::None; }
    }

    [[nodiscard]] bool CheckEternalBlueSignature(std::span<const uint8_t> packet) const noexcept {
        try {
            if (packet.empty() || packet.size() > MAX_SMB_PACKET_SIZE) return false;

            for (const auto& sig : ETERNALBLUE_SIGNATURES) {
                if (packet.size() < sig.pattern.size()) continue;
                auto it = std::search(packet.begin(), packet.end(),
                                      sig.pattern.begin(), sig.pattern.end());
                if (it != packet.end()) {
                    Utils::Logger::Warn("WannaCryDetector: EternalBlue stage {} signature: {}",
                                        sig.stage, sig.description);
                    return true;
                }
            }

            // Heuristic: oversized TRANS2 data (FEA list overflow indicator)
            if (packet.size() >= 5 && packet[0] == 0xFF && packet[1] == 0x53 &&
                packet[2] == 0x4D && packet[3] == 0x42 && packet[4] == 0x32) {
                if (packet.size() > 4096) {
                    Utils::Logger::Warn("WannaCryDetector: Oversized SMBv1 TRANS2 packet ({} bytes)", packet.size());
                    return true;
                }
            }
            return false;
        } catch (...) { return false; }
    }

};  // class WannaCryDetectorImpl

// ============================================================================
// SINGLETON
// ============================================================================

std::atomic<bool> WannaCryDetector::s_instanceCreated{false};

WannaCryDetector& WannaCryDetector::Instance() noexcept {
    static WannaCryDetector instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool WannaCryDetector::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

WannaCryDetector::WannaCryDetector()
    : m_impl(std::make_unique<WannaCryDetectorImpl>())
{
    SS_LOG_INFO(L"WannaCryDetector", L"Instance created");
}

WannaCryDetector::~WannaCryDetector() {
    try { Shutdown(); } catch (...) {}
}

bool WannaCryDetector::Initialize(const WannaCryDetectorConfiguration& config) {
    try {
        std::unique_lock lock(m_impl->m_mutex);
        if (m_impl->m_status != ModuleStatus::Uninitialized &&
            m_impl->m_status != ModuleStatus::Stopped) {
            SS_LOG_WARN(L"WannaCryDetector", L"Already initialized (status=%d)",
                        static_cast<int>(m_impl->m_status));
            return false;
        }
        if (!config.IsValid()) {
            SS_LOG_ERROR(L"WannaCryDetector", L"Invalid configuration");
            return false;
        }
        m_impl->m_status = ModuleStatus::Initializing;
        m_impl->m_config = config;

        {
            std::unique_lock hl(m_impl->m_hashMutex);
            m_impl->m_knownHashes = KNOWN_WANNACRY_HASHES;
        }
        {
            std::unique_lock kl(m_impl->m_killSwitchMutex);
            for (const char* domain : WannaCryConstants::KNOWN_KILL_SWITCHES)
                m_impl->m_killSwitchDomains.insert(domain);
        }

        m_impl->m_stats = WannaCryStatistics{};
        m_impl->m_stats.startTime = Clock::now();
        m_impl->m_status = ModuleStatus::Running;

        SS_LOG_INFO(L"WannaCryDetector", L"Initialized v%hs (SMB threshold=%u/%us)",
                    GetVersionString().c_str(), config.smbScanThreshold, config.smbScanWindowSecs);
        return true;
    } catch (const std::exception& ex) {
        Utils::Logger::Error("WannaCryDetector: Init failed: {}", ex.what());
        try {
            std::unique_lock errLock(m_impl->m_mutex);
            m_impl->m_status = ModuleStatus::Error;
        } catch (...) {}
        return false;
    } catch (...) {
        Utils::Logger::Fatal("WannaCryDetector: Init failed (unknown exception)");
        try {
            std::unique_lock errLock(m_impl->m_mutex);
            m_impl->m_status = ModuleStatus::Error;
        } catch (...) {}
        return false;
    }
}

void WannaCryDetector::Shutdown() {
    try {
        std::unique_lock lock(m_impl->m_mutex);
        if (m_impl->m_status == ModuleStatus::Uninitialized ||
            m_impl->m_status == ModuleStatus::Stopped) return;
        m_impl->m_status = ModuleStatus::Stopping;
        {
            std::unique_lock cl(m_impl->m_cacheMutex);
            m_impl->m_detectionCache.clear();
        }
        {
            std::lock_guard sl(m_impl->m_smbMutex);
            m_impl->m_smbTrackers.clear();
        }
        {
            std::lock_guard cbl(m_impl->m_callbackMutex);
            m_impl->m_detectionCallback = nullptr;
            m_impl->m_eternalBlueCallback = nullptr;
            m_impl->m_smbScanCallback = nullptr;
        }
        m_impl->m_status = ModuleStatus::Stopped;
        SS_LOG_INFO(L"WannaCryDetector", L"Shutdown complete");
    } catch (const std::exception& ex) {
        Utils::Logger::Error("WannaCryDetector: Shutdown error: {}", ex.what());
    } catch (...) {}
}

bool WannaCryDetector::IsInitialized() const noexcept {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_status == ModuleStatus::Running;
}

ModuleStatus WannaCryDetector::GetStatus() const noexcept {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_status;
}

// ============================================================================
// DETECTION
// ============================================================================

bool WannaCryDetector::Detect(uint32_t pid) {
    try { return DetectEx(pid).detected; }
    catch (...) { return false; }
}

WannaCryDetectionResult WannaCryDetector::DetectEx(uint32_t pid) {
    WannaCryDetectionResult result;
    result.pid = pid;
    result.detectionTime = std::chrono::system_clock::now();
    try {
        if (!IsInitialized()) {
            SS_LOG_WARN(L"WannaCryDetector", L"DetectEx called while not initialized");
            return result;
        }

        // Snapshot configuration once to avoid repeated lock acquisition
        const auto config = m_impl->GetConfig();

        // Check cache with TTL
        {
            std::shared_lock cl(m_impl->m_cacheMutex);
            auto it = m_impl->m_detectionCache.find(pid);
            if (it != m_impl->m_detectionCache.end()) {
                const auto age = Clock::now() - it->second.cachedAt;
                if (age < std::chrono::seconds(config.cacheTTLSecs))
                    return it->second.result;
            }
        }

        // Track whether we have PID-specific evidence (vs. global system indicators).
        // Global indicators (mutex, service, registry) exist system-wide and must NOT
        // alone justify auto-terminating a specific PID — that would kill innocent processes.
        bool hasPidSpecificEvidence = false;

        // 1. Hash check (highest confidence, fastest) — PID-specific
        if (m_impl->CheckProcessHash(pid, result)) {
            result.detected = true;
            hasPidSpecificEvidence = true;
        }

        // 2. Process artifact check — PID-specific
        if (config.monitorArtifacts && m_impl->CheckProcessArtifacts(pid, result)) {
            result.detected = true;
            hasPidSpecificEvidence = true;
        }

        // 3. Mutex check — GLOBAL indicator (not tied to this PID)
        if (config.monitorMutex && CheckMutex()) {
            result.mutexDetected = true;
            result.detected = true;
            result.indicators.push_back("MUTEX_DETECTED: Global\\MsWinZonesCacheCounterMutex0");
            ++m_impl->m_stats.mutexDetections;
        }

        // 4. Service check — GLOBAL indicator (not tied to this PID)
        if (config.monitorServices && CheckServiceInstallation()) {
            result.serviceDetected = true;
            result.detected = true;
            result.indicators.push_back("SERVICE_DETECTED: mssecsvc2.0");
            ++m_impl->m_stats.serviceDetections;
        }

        // 5. Registry check — GLOBAL indicator
        if (config.monitorRegistry && CheckRegistryIndicators()) {
            result.detected = true;
            result.indicators.push_back("REGISTRY_INDICATOR");
        }

        // 6. Memory scan (only if other indicators suggest further investigation) — PID-specific
        if (result.detected || config.verboseLogging) {
            auto memIndicators = m_impl->ScanProcessMemory(pid);
            if (!memIndicators.empty()) {
                result.indicators.insert(result.indicators.end(),
                                         memIndicators.begin(), memIndicators.end());
                result.detected = true;
                hasPidSpecificEvidence = true;
            }
        }

        if (result.detected) {
            result.variant = m_impl->DetermineVariant(result);
            result.phase = m_impl->DeterminePhase(result);
            result.confidence = m_impl->CalculateConfidence(result);

            ++m_impl->m_stats.totalDetections;
            if (static_cast<size_t>(result.variant) < m_impl->m_stats.byVariant.size())
                ++m_impl->m_stats.byVariant[static_cast<size_t>(result.variant)];

            if (result.confidence >= config.minAlertConfidence)
                m_impl->FireDetectionCallback(result);

            // Cache result
            {
                std::unique_lock cl(m_impl->m_cacheMutex);
                if (m_impl->m_detectionCache.size() >= WannaCryConstants::MAX_CACHED_DETECTIONS) {
                    m_impl->PurgeStaleCacheEntries();
                    // If purge didn't reclaim space (no stale entries), evict the
                    // oldest entry to enforce the hard cap. Without this, a burst
                    // of fresh detections within TTL would grow the map unbounded.
                    if (m_impl->m_detectionCache.size() >= WannaCryConstants::MAX_CACHED_DETECTIONS) {
                        auto oldest = m_impl->m_detectionCache.begin();
                        for (auto it = m_impl->m_detectionCache.begin();
                             it != m_impl->m_detectionCache.end(); ++it) {
                            if (it->second.cachedAt < oldest->second.cachedAt) oldest = it;
                        }
                        if (oldest != m_impl->m_detectionCache.end())
                            m_impl->m_detectionCache.erase(oldest);
                    }
                }
                m_impl->m_detectionCache[pid] = {result, Clock::now()};
            }

            SS_LOG_WARN(L"WannaCryDetector", L"DETECTION: PID=%u variant=%hs confidence=%hs phase=%hs",
                        pid, GetWannaCryVariantName(result.variant).data(),
                        GetDetectionConfidenceName(result.confidence).data(),
                        GetWannaCryPhaseName(result.phase).data());

            // ── Cross-module wiring ────────────────────────────────────
            ReportThreatToAlertSystem(result);
            ReportDetectionTelemetry(result);
            ReportThreatToBehaviorAnalyzer(result);

            // Auto-terminate — ONLY if we have PID-specific evidence.
            // Global indicators (mutex/service/registry) alone must NOT trigger
            // termination of this PID — they could belong to a different process.
            if (config.autoTerminate &&
                result.confidence >= DetectionConfidence::High &&
                hasPidSpecificEvidence) {
                // Re-validate PID still points to same process (mitigate PID reuse TOCTOU)
                if (IsPidStillThisProcess(pid, result.processName)) {
                    (void)RequestKernelProcessBlock(pid, L"WannaCry detection: " +
                        Utils::StringUtils::ToWide(GetWannaCryVariantName(result.variant)));

                    Utils::ProcessUtils::Error termErr;
                    if (Utils::ProcessUtils::TerminateProcess(pid, 1, &termErr)) {
                        ++m_impl->m_stats.processesTerminated;
                        SS_LOG_INFO(L"WannaCryDetector", L"Terminated malicious PID %u", pid);
                    } else {
                        SS_LOG_ERROR(L"WannaCryDetector", L"Failed to terminate PID %u", pid);
                    }
                } else {
                    SS_LOG_WARN(L"WannaCryDetector",
                        L"PID %u image changed or exited before termination - skipping kill (PID reuse safety)",
                        pid);
                }
            }else if (config.autoTerminate &&
                       result.confidence >= DetectionConfidence::High &&
                       !hasPidSpecificEvidence) {
                SS_LOG_WARN(L"WannaCryDetector",
                    L"PID %u flagged by global indicators only — not terminating (no PID-specific evidence)",
                    pid);
            }
        }
    } catch (const std::exception& ex) {
        Utils::Logger::Error("WannaCryDetector: DetectEx failed for PID {}: {}", pid, ex.what());
    } catch (...) {
        Utils::Logger::Error("WannaCryDetector: DetectEx failed for PID {}", pid);
    }
    return result;
}

bool WannaCryDetector::IsWannaCryArtifact(std::wstring_view filePath) const {
    try {
        fs::path path(filePath);
        std::wstring lowerName = Utils::StringUtils::ToLowerCopy(path.filename().wstring());
        for (const auto& artifact : WANNACRY_ARTIFACTS) {
            if (Utils::StringUtils::IEquals(lowerName, artifact)) return true;
        }
        std::wstring ext = path.extension().wstring();
        if (Utils::StringUtils::IEquals(ext, WannaCryConstants::WNCRY_EXTENSION)) return true;
        return false;
    } catch (...) { return false; }
}

bool WannaCryDetector::IsKillSwitchDomain(std::string_view domain) const {
    try {
        std::shared_lock lock(m_impl->m_killSwitchMutex);
        return m_impl->m_killSwitchDomains.count(std::string(domain)) > 0;
    } catch (...) { return false; }
}

bool WannaCryDetector::AnalyzeSMBTraffic(std::span<const uint8_t> packet,
                                         std::string_view sourceIP,
                                         std::string_view destIP) {
    try {
        const auto config = m_impl->GetConfig();
        if (!config.monitorSMB) return false;
        if (m_impl->CheckEternalBlueSignature(packet)) {
            ++m_impl->m_stats.smbExploitsBlocked;
            EternalBlueIndicator indicator;
            indicator.sourceIP = std::string(sourceIP);
            indicator.destIP = std::string(destIP);
            indicator.timestamp = std::chrono::system_clock::now();
            indicator.signatureMatched = true;
            indicator.wasBlocked = config.blockSMBExploit;
            m_impl->FireEternalBlueCallback(indicator);
            SS_LOG_FATAL(L"WannaCryDetector", L"EternalBlue exploit detected %hs -> %hs",
                         std::string(sourceIP).c_str(), std::string(destIP).c_str());
            return true;
        }
        return false;
    } catch (const std::exception& ex) {
        Utils::Logger::Error("WannaCryDetector: SMB analysis error: {}", ex.what());
        return false;
    } catch (...) { return false; }
}

bool WannaCryDetector::CheckKnownHash(const Hash256& hash) const {
    try {
        std::shared_lock lock(m_impl->m_hashMutex);
        std::string hashStr;
        hashStr.reserve(64);
        for (uint8_t byte : hash) {
            const char hex[] = "0123456789abcdef";
            hashStr.push_back(hex[(byte >> 4) & 0x0F]);
            hashStr.push_back(hex[byte & 0x0F]);
        }
        return m_impl->m_knownHashes.count(hashStr) > 0;
    } catch (...) { return false; }
}

std::vector<std::wstring> WannaCryDetector::ScanForArtifacts(std::wstring_view directory) {
    std::vector<std::wstring> found;
    try {
        std::error_code ec;
        fs::path dirPath(directory);
        if (!fs::exists(dirPath, ec) || !fs::is_directory(dirPath, ec)) return found;

        size_t filesChecked = 0;
        fs::recursive_directory_iterator iter(dirPath,
            fs::directory_options::skip_permission_denied, ec);
        if (ec) return found;

        for (auto it = fs::begin(iter); it != fs::end(iter) && filesChecked < WannaCryConstants::MAX_SCAN_FILES; ++it) {
            if (it.depth() > static_cast<int>(WannaCryConstants::MAX_SCAN_DEPTH)) {
                it.disable_recursion_pending();
                continue;
            }
            if (!it->is_regular_file(ec) || ec) continue;
            ++filesChecked;
            if (IsWannaCryArtifact(it->path().wstring())) {
                found.push_back(it->path().wstring());
                SS_LOG_WARN(L"WannaCryDetector", L"Artifact found: %ls", it->path().c_str());
            }
        }
    } catch (const std::exception& ex) {
        Utils::Logger::Error("WannaCryDetector: Artifact scan error: {}", ex.what());
    } catch (...) {}
    return found;
}

bool WannaCryDetector::CheckMutex() const {
    try {
        ScopedHandle hMutex(::OpenMutexW(SYNCHRONIZE, FALSE, WannaCryConstants::WANNACRY_MUTEX));
        if (hMutex) {
            SS_LOG_WARN(L"WannaCryDetector", L"WannaCry mutex DETECTED: %ls",
                        WannaCryConstants::WANNACRY_MUTEX);
            return true;
        }
        return false;
    } catch (...) { return false; }
}

bool WannaCryDetector::CheckServiceInstallation() const {
    try {
        SC_HANDLE hSCM = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
        if (!hSCM) return false;
        struct SCMGuard { SC_HANDLE h; ~SCMGuard() { if (h) ::CloseServiceHandle(h); } } scmGuard{hSCM};

        SC_HANDLE hSvc = ::OpenServiceW(hSCM, WannaCryConstants::WANNACRY_SERVICE_NAME, SERVICE_QUERY_STATUS);
        if (!hSvc) return false;
        struct SvcGuard { SC_HANDLE h; ~SvcGuard() { if (h) ::CloseServiceHandle(h); } } svcGuard{hSvc};

        SERVICE_STATUS_PROCESS ssp{};
        DWORD bytesNeeded = 0;
        if (::QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                                    reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded)) {
            SS_LOG_FATAL(L"WannaCryDetector", L"WannaCry service mssecsvc2.0 DETECTED (state=%u, pid=%u)",
                         ssp.dwCurrentState, ssp.dwProcessId);
            return true;
        }
        // Service exists even if query failed
        SS_LOG_WARN(L"WannaCryDetector", L"WannaCry service mssecsvc2.0 found in SCM");
        return true;
    } catch (...) { return false; }
}

bool WannaCryDetector::CheckRegistryIndicators() const {
    try {
        for (const auto& regPath : REGISTRY_INDICATORS) {
            HKEY hKey = nullptr;
            LSTATUS status = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(),
                                             0, KEY_READ, &hKey);
            if (status == ERROR_SUCCESS) {
                ::RegCloseKey(hKey);
                SS_LOG_WARN(L"WannaCryDetector", L"Registry indicator found: HKLM\\%ls", regPath.c_str());
                return true;
            }
        }
        return false;
    } catch (...) { return false; }
}

// ============================================================================
// EVENT HANDLERS
// ============================================================================

void WannaCryDetector::OnNetworkConnection(const SMBConnectionEvent& event) {
    try {
        if (!IsInitialized()) return;
        const auto config = m_impl->GetConfig();
        if (!config.monitorPropagation) return;
        if (event.destPort != WannaCryConstants::SMB_PORT) return;

        if (m_impl->TrackSMBConnection(event.pid)) {
            ++m_impl->m_stats.smbScansDetected;
            m_impl->FireSMBScanCallback(event.pid, config.smbScanThreshold);

            SS_LOG_WARN(L"WannaCryDetector", L"SMB port scan detected: PID=%u exceeded %u connections in %us",
                        event.pid, config.smbScanThreshold, config.smbScanWindowSecs);

            WannaCryDetectionResult result;
            result.pid = event.pid;
            result.detected = true;
            result.smbConnectionCount = config.smbScanThreshold;
            result.hostsScanned = config.smbScanThreshold;
            result.detectionTime = std::chrono::system_clock::now();
            result.indicators.push_back("SMB_PORT_SCAN: " + std::to_string(config.smbScanThreshold) + " connections in window");
            result.variant = m_impl->DetermineVariant(result);
            result.phase = WannaCryPhase::Propagation;
            result.confidence = m_impl->CalculateConfidence(result);

            ++m_impl->m_stats.totalDetections;
            m_impl->FireDetectionCallback(result);

            // ── Cross-module wiring ────────────────────────────────────
            ReportThreatToAlertSystem(result);
            ReportDetectionTelemetry(result);
            ReportThreatToBehaviorAnalyzer(result);

            if (config.autoTerminate && result.confidence >= DetectionConfidence::High) {
                // PID-reuse safety: capture the current process name now so that
                // if the PID has already been recycled we kill nothing.
                auto preKillPath = Utils::ProcessUtils::GetProcessPath(event.pid);
                if (!preKillPath.has_value()) {
                    SS_LOG_WARN(L"WannaCryDetector",
                        L"SMB-propagation PID %u no longer exists - skipping kill", event.pid);
                } else {
                    result.processName = fs::path(*preKillPath).filename().wstring();
                    (void)RequestKernelProcessBlock(event.pid, L"WannaCry SMB propagation detected");
                    if (!IsPidStillThisProcess(event.pid, result.processName)) {
                        SS_LOG_WARN(L"WannaCryDetector",
                            L"PID %u image changed before terminate - PID-reuse guard tripped", event.pid);
                    } else {
                        Utils::ProcessUtils::Error termErr;
                        if (Utils::ProcessUtils::TerminateProcess(event.pid, 1, &termErr))
                            ++m_impl->m_stats.processesTerminated;
                        else
                            SS_LOG_ERROR(L"WannaCryDetector", L"Failed to terminate propagating PID %u", event.pid);
                    }
                }
            }
        }
    } catch (const std::exception& ex) {
        Utils::Logger::Error("WannaCryDetector: OnNetworkConnection error: {}", ex.what());
    } catch (...) {}
}

void WannaCryDetector::OnDnsQuery(const DnsQueryEvent& event) {
    try {
        if (!IsInitialized()) return;
        const auto config = m_impl->GetConfig();
        if (!config.monitorKillSwitch) return;
        if (!IsKillSwitchDomain(event.domain)) return;

        ++m_impl->m_stats.killSwitchQueries;
        SS_LOG_WARN(L"WannaCryDetector", L"Kill-switch DNS query detected: PID=%u domain=%hs",
                    event.pid, event.domain.c_str());

        WannaCryDetectionResult result;
        result.pid = event.pid;
        result.detected = true;
        result.killSwitchQueried = true;
        result.killSwitchDomain = event.domain;
        result.detectionTime = std::chrono::system_clock::now();
        result.indicators.push_back("KILLSWITCH_DNS: " + event.domain);
        result.variant = m_impl->DetermineVariant(result);
        result.phase = WannaCryPhase::KillSwitchCheck;
        result.confidence = m_impl->CalculateConfidence(result);

        ++m_impl->m_stats.totalDetections;
        m_impl->FireDetectionCallback(result);

        // ── Cross-module wiring ────────────────────────────────────
        ReportThreatToAlertSystem(result);
        ReportDetectionTelemetry(result);
        ReportThreatToBehaviorAnalyzer(result);

        if (config.autoTerminate && result.confidence >= DetectionConfidence::High) {
            // PID-reuse safety: capture identity before any blocking call,
            // re-validate immediately before terminate.
            auto preKillPath = Utils::ProcessUtils::GetProcessPath(event.pid);
            if (!preKillPath.has_value()) {
                SS_LOG_WARN(L"WannaCryDetector",
                    L"Kill-switch PID %u no longer exists - skipping kill", event.pid);
            } else {
                result.processName = fs::path(*preKillPath).filename().wstring();
                (void)RequestKernelProcessBlock(event.pid, L"WannaCry kill-switch DNS query");
                if (!IsPidStillThisProcess(event.pid, result.processName)) {
                    SS_LOG_WARN(L"WannaCryDetector",
                        L"PID %u image changed before terminate - PID-reuse guard tripped", event.pid);
                } else {
                    Utils::ProcessUtils::Error termErr;
                    if (Utils::ProcessUtils::TerminateProcess(event.pid, 1, &termErr))
                        ++m_impl->m_stats.processesTerminated;
                    else
                        SS_LOG_ERROR(L"WannaCryDetector", L"Failed to terminate kill-switch PID %u", event.pid);
                }
            }
        }
    } catch (const std::exception& ex) {
        Utils::Logger::Error("WannaCryDetector: OnDnsQuery error: {}", ex.what());
    } catch (...) {}
}

void WannaCryDetector::OnServiceCreated(const ServiceEvent& event) {
    try {
        if (!IsInitialized()) return;
        const auto config = m_impl->GetConfig();
        if (!config.monitorServices) return;
        if (!Utils::StringUtils::IEquals(event.serviceName, WannaCryConstants::WANNACRY_SERVICE_NAME)) return;

        ++m_impl->m_stats.serviceDetections;
        SS_LOG_FATAL(L"WannaCryDetector", L"WannaCry service creation detected: PID=%u svc=%ls binary=%ls",
                     event.pid, event.serviceName.c_str(), event.binaryPath.c_str());

        WannaCryDetectionResult result;
        result.pid = event.pid;
        result.detected = true;
        result.serviceDetected = true;
        result.detectionTime = std::chrono::system_clock::now();
        result.indicators.push_back("SERVICE_CREATION: " + Utils::StringUtils::ToNarrow(event.serviceName));
        result.variant = WannaCryVariant::WannaCry1;
        result.phase = WannaCryPhase::ServiceCreation;
        result.confidence = DetectionConfidence::Confirmed;

        ++m_impl->m_stats.totalDetections;
        m_impl->FireDetectionCallback(result);

        // ── Cross-module wiring ────────────────────────────────────
        ReportThreatToAlertSystem(result);
        ReportDetectionTelemetry(result);
        ReportThreatToBehaviorAnalyzer(result);

        // Immediate termination - service creation is high-confidence
        if (config.autoTerminate) {
            auto preKillPath = Utils::ProcessUtils::GetProcessPath(event.pid);
            if (!preKillPath.has_value()) {
                SS_LOG_WARN(L"WannaCryDetector",
                    L"Service-creator PID %u no longer exists - skipping kill", event.pid);
            } else {
                result.processName = fs::path(*preKillPath).filename().wstring();
                (void)RequestKernelProcessBlock(event.pid, L"WannaCry service creation detected");
                if (!IsPidStillThisProcess(event.pid, result.processName)) {
                    SS_LOG_WARN(L"WannaCryDetector",
                        L"PID %u image changed before terminate - PID-reuse guard tripped", event.pid);
                } else {
                    Utils::ProcessUtils::Error termErr;
                    if (Utils::ProcessUtils::TerminateProcess(event.pid, 1, &termErr))
                        ++m_impl->m_stats.processesTerminated;
                    else
                        SS_LOG_ERROR(L"WannaCryDetector", L"Failed to terminate service-creating PID %u", event.pid);
                }
            }
        }
    } catch (const std::exception& ex) {
        Utils::Logger::Error("WannaCryDetector: OnServiceCreated error: {}", ex.what());
    } catch (...) {}
}

void WannaCryDetector::OnRegistryModified(const RegistryEvent& event) {
    try {
        if (!IsInitialized()) return;
        const auto config = m_impl->GetConfig();
        if (!config.monitorRegistry) return;

        std::wstring lowerKey = Utils::StringUtils::ToLowerCopy(event.keyPath);
        bool matched = false;
        for (const auto& indicator : REGISTRY_INDICATORS) {
            if (Utils::StringUtils::IContains(lowerKey, Utils::StringUtils::ToLowerCopy(indicator))) {
                matched = true;
                break;
            }
        }
        if (!matched) return;

        SS_LOG_WARN(L"WannaCryDetector", L"WannaCry registry modification: PID=%u key=%ls",
                    event.pid, event.keyPath.c_str());

        WannaCryDetectionResult result;
        result.pid = event.pid;
        result.detected = true;
        result.detectionTime = std::chrono::system_clock::now();
        result.indicators.push_back("REGISTRY_MOD: " + Utils::StringUtils::ToNarrow(event.keyPath));
        result.variant = m_impl->DetermineVariant(result);
        result.phase = m_impl->DeterminePhase(result);
        result.confidence = m_impl->CalculateConfidence(result);

        ++m_impl->m_stats.totalDetections;
        m_impl->FireDetectionCallback(result);

        // ── Cross-module wiring ────────────────────────────────────
        ReportThreatToAlertSystem(result);
        ReportDetectionTelemetry(result);
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(L"WannaCryDetector", L"OnRegistryModified error: %hs", ex.what());
    } catch (...) {}
}

void WannaCryDetector::OnProcessCreated(uint32_t pid, std::wstring_view processPath,
                                         std::wstring_view commandLine) {
    try {
        if (!IsInitialized()) return;

        fs::path exePath(processPath);
        std::wstring lowerName = Utils::StringUtils::ToLowerCopy(exePath.filename().wstring());

        // Check against known WannaCry executable names
        static const std::vector<std::wstring> SUSPICIOUS_NAMES = {
            L"tasksche.exe", L"mssecsvc.exe", L"@wanadecryptor@.exe",
            L"taskdl.exe", L"taskse.exe"
        };

        for (const auto& name : SUSPICIOUS_NAMES) {
            if (Utils::StringUtils::IEquals(lowerName, name)) {
                SS_LOG_WARN(L"WannaCryDetector", L"Suspicious process created: PID=%u name=%ls",
                            pid, exePath.filename().c_str());
                (void)DetectEx(pid);  // Full detection scan
                return;
            }
        }
    } catch (const std::exception& ex) {
        Utils::Logger::Error("WannaCryDetector: OnProcessCreated error: {}", ex.what());
    } catch (...) {}
}

// ============================================================================
// VULNERABILITY CHECK
// ============================================================================

bool WannaCryDetector::IsSystemVulnerable() const {
    try {
        if (IsPatchInstalled()) return false;
        std::string smbInfo = GetSMBVersionInfo();
        if (smbInfo.find("SMBv1=enabled") != std::string::npos) {
            SS_LOG_WARN(L"WannaCryDetector", L"System VULNERABLE: SMBv1 enabled, MS17-010 not patched");
            return true;
        }
        return false;
    } catch (...) { return false; }
}

bool WannaCryDetector::IsPatchInstalled() const {
    try {
        HKEY hKey = nullptr;
        const wchar_t* packagesPath = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages";
        LSTATUS status = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE, packagesPath, 0, KEY_READ, &hKey);
        if (status != ERROR_SUCCESS) {
            // Fallback: check hotfix path
            const wchar_t* hotfixPath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\HotFix";
            status = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE, hotfixPath, 0, KEY_READ, &hKey);
            if (status != ERROR_SUCCESS) return false;
        }

        DWORD subKeyCount = 0;
        ::RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, &subKeyCount, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

        for (DWORD i = 0; i < subKeyCount; ++i) {
            wchar_t subKeyName[512]{};
            DWORD nameLen = 512;
            if (::RegEnumKeyExW(hKey, i, subKeyName, &nameLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                std::wstring name(subKeyName, nameLen);
                for (const auto& kb : MS17010_PATCHES) {
                    if (name.find(kb) != std::wstring::npos) {
                        ::RegCloseKey(hKey);
                        SS_LOG_INFO(L"WannaCryDetector", L"MS17-010 patch found: %ls", kb.c_str());
                        return true;
                    }
                }
            }
        }
        ::RegCloseKey(hKey);
        return false;
    } catch (...) { return false; }
}

std::string WannaCryDetector::GetSMBVersionInfo() const {
    try {
        std::string result;
        HKEY hKey = nullptr;
        const wchar_t* smbPath = L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters";
        LSTATUS status = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE, smbPath, 0, KEY_READ, &hKey);
        if (status != ERROR_SUCCESS) return "SMBv1=unknown,SMBv2=unknown";

        DWORD smb1Value = 1;  // Default: enabled if key absent
        DWORD dataSize = sizeof(smb1Value);
        status = ::RegQueryValueExW(hKey, L"SMB1", nullptr, nullptr,
                                     reinterpret_cast<LPBYTE>(&smb1Value), &dataSize);
        if (status != ERROR_SUCCESS) {
            // Try alternate key name
            status = ::RegQueryValueExW(hKey, L"EnableSMB1Protocol", nullptr, nullptr,
                                         reinterpret_cast<LPBYTE>(&smb1Value), &dataSize);
        }

        DWORD smb2Value = 1;
        dataSize = sizeof(smb2Value);
        ::RegQueryValueExW(hKey, L"SMB2", nullptr, nullptr,
                            reinterpret_cast<LPBYTE>(&smb2Value), &dataSize);

        ::RegCloseKey(hKey);

        result = "SMBv1=" + std::string(smb1Value ? "enabled" : "disabled") +
                 ",SMBv2=" + std::string(smb2Value ? "enabled" : "disabled");
        return result;
    } catch (...) { return "SMBv1=error,SMBv2=error"; }
}

// ============================================================================
// PATTERN MANAGEMENT
// ============================================================================

void WannaCryDetector::AddKillSwitchDomain(std::string_view domain) {
    try {
        if (domain.empty() || domain.size() > MAX_DOMAIN_LENGTH) {
            SS_LOG_WARN(L"WannaCryDetector",
                L"AddKillSwitchDomain rejected: invalid length (%zu)", domain.size());
            return;
        }
        std::unique_lock lock(m_impl->m_killSwitchMutex);
        if (m_impl->m_killSwitchDomains.size() >= MAX_KILLSWITCH_DOMAINS) {
            SS_LOG_WARN(L"WannaCryDetector",
                L"AddKillSwitchDomain rejected: cap %zu reached",
                MAX_KILLSWITCH_DOMAINS);
            return;
        }
        m_impl->m_killSwitchDomains.insert(std::string(domain));
        SS_LOG_INFO(L"WannaCryDetector", L"Added kill-switch domain: %hs", std::string(domain).c_str());
    } catch (const std::exception& ex) {
        Utils::Logger::Error("WannaCryDetector: AddKillSwitchDomain failed: {}", ex.what());
    }
}

void WannaCryDetector::AddKnownHash(const Hash256& hash) {
    try {
        std::string hashStr;
        hashStr.reserve(64);
        for (uint8_t byte : hash) {
            const char hex[] = "0123456789abcdef";
            hashStr.push_back(hex[(byte >> 4) & 0x0F]);
            hashStr.push_back(hex[byte & 0x0F]);
        }
        std::unique_lock lock(m_impl->m_hashMutex);
        if (m_impl->m_knownHashes.size() >= MAX_KNOWN_HASHES) {
            SS_LOG_WARN(L"WannaCryDetector",
                L"AddKnownHash rejected: cap %zu reached", MAX_KNOWN_HASHES);
            return;
        }
        m_impl->m_knownHashes.insert(std::move(hashStr));
    } catch (const std::exception& ex) {
        Utils::Logger::Error("WannaCryDetector: AddKnownHash failed: {}", ex.what());
    }
}

void WannaCryDetector::UpdatePatternsFromThreatIntel() {
    try {
        SS_LOG_INFO(L"WannaCryDetector", L"Updating patterns from ThreatIntel");

        // Hardcoded kill-switch domains (canonical WannaCry samples)
        AddKillSwitchDomain("iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com");
        AddKillSwitchDomain("ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com");

        // Query ThreatIntelManager for latest WannaCry IOCs
        try {
            auto& ti = ThreatIntel::ThreatIntelManager::Instance();
            if (ti.IsInitialized()) {
                // CRITICAL: copy the IOC sets out FIRST and release the locks
                // before performing any ThreatIntel lookups. ti.LookupHash /
                // LookupDomain may perform network I/O, hit other singletons,
                // or acquire mutexes themselves - holding our IOC mutex across
                // those calls is both a lock-order hazard and a multi-second
                // stall for every concurrent reader of the same set.
                std::vector<std::string> hashesCopy;
                std::vector<std::string> domainsCopy;
                {
                    std::shared_lock hl(m_impl->m_hashMutex);
                    hashesCopy.reserve(m_impl->m_knownHashes.size());
                    hashesCopy.assign(m_impl->m_knownHashes.begin(),
                                      m_impl->m_knownHashes.end());
                }
                {
                    std::shared_lock kl(m_impl->m_killSwitchMutex);
                    domainsCopy.reserve(m_impl->m_killSwitchDomains.size());
                    domainsCopy.assign(m_impl->m_killSwitchDomains.begin(),
                                       m_impl->m_killSwitchDomains.end());
                }

                size_t enriched = 0;
                for (const auto& hash : hashesCopy) {
                    auto lookup = ti.LookupHash("sha256", hash);
                    if (lookup.IsMalicious()) ++enriched;
                }
                for (const auto& domain : domainsCopy) {
                    auto lookup = ti.LookupDomain(domain);
                    if (lookup.found) ++enriched;
                }
                SS_LOG_INFO(L"WannaCryDetector", L"ThreatIntel enrichment: %zu IOCs validated", enriched);
            }
        } catch (const std::exception& tiEx) {
            SS_LOG_WARN(L"WannaCryDetector", L"ThreatIntel query failed: %hs (non-fatal)", tiEx.what());
        }

        SS_LOG_INFO(L"WannaCryDetector", L"Pattern update complete");
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(L"WannaCryDetector", L"Pattern update failed: %hs", ex.what());
    }
}

void WannaCryDetector::RegisterWithRansomwareDetector() {
    try {
        SS_LOG_INFO(L"WannaCryDetector", L"Registering with RansomwareDetector");

        if (!RansomwareDetector::HasInstance()) {
            SS_LOG_WARN(L"WannaCryDetector", L"RansomwareDetector not available for registration");
            return;
        }
        auto& detector = RansomwareDetector::Instance();

        FamilySignature sig;
        sig.family = RansomwareFamily::WannaCry;
        sig.familyName = "WannaCry";
        sig.extensions = {L".WNCRY", L".WNCRYT", L".WNRY", L".WNCRY"};
        sig.ransomNotePatterns = {L"@Please_Read_Me@.txt", L"@WanaDecryptor@.exe"};
        sig.mutexNames = {L"Global\\MsWinZonesCacheCounterMutex0"};
        sig.registryKeys = {L"SOFTWARE\\WanaCrypt0r",
                            L"SYSTEM\\CurrentControlSet\\services\\mssecsvc2.0"};
        sig.c2Domains = {"iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
                         "ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com"};
        sig.processPatterns = {L"tasksche.exe", L"mssecsvc.exe",
                               L"@WanaDecryptor@.exe", L"taskdl.exe", L"taskse.exe"};
        sig.encryptionAlgorithm = "AES-128-CBC + RSA-2048";

        detector.RegisterFamilySignature(sig);

        SS_LOG_INFO(L"WannaCryDetector", L"Registration with RansomwareDetector complete");
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(L"WannaCryDetector", L"Registration failed: %hs", ex.what());
    }
}

void WannaCryDetector::SetDetectionCallback(WannaCryDetectionCallback callback) {
    try {
        std::lock_guard lock(m_impl->m_callbackMutex);
        m_impl->m_detectionCallback = std::move(callback);
    } catch (const std::exception& ex) {
        Utils::Logger::Error("WannaCryDetector: SetDetectionCallback failed: {}", ex.what());
    }
}

void WannaCryDetector::SetEternalBlueCallback(EternalBlueCallback callback) {
    try {
        std::lock_guard lock(m_impl->m_callbackMutex);
        m_impl->m_eternalBlueCallback = std::move(callback);
    } catch (const std::exception& ex) {
        Utils::Logger::Error("WannaCryDetector: SetEternalBlueCallback failed: {}", ex.what());
    }
}

void WannaCryDetector::SetSMBScanCallback(SMBScanCallback callback) {
    try {
        std::lock_guard lock(m_impl->m_callbackMutex);
        m_impl->m_smbScanCallback = std::move(callback);
    } catch (const std::exception& ex) {
        Utils::Logger::Error("WannaCryDetector: SetSMBScanCallback failed: {}", ex.what());
    }
}

// ============================================================================
// STATISTICS
// ============================================================================

WannaCryStatisticsSnapshot WannaCryDetector::GetStatistics() const {
    std::shared_lock lock(m_impl->m_mutex);
    WannaCryStatisticsSnapshot snap;
    snap.totalDetections    = m_impl->m_stats.totalDetections.load(std::memory_order_relaxed);
    for (size_t i = 0; i < snap.byVariant.size() && i < m_impl->m_stats.byVariant.size(); ++i)
        snap.byVariant[i] = m_impl->m_stats.byVariant[i].load(std::memory_order_relaxed);
    snap.smbExploitsBlocked = m_impl->m_stats.smbExploitsBlocked.load(std::memory_order_relaxed);
    snap.killSwitchQueries  = m_impl->m_stats.killSwitchQueries.load(std::memory_order_relaxed);
    snap.processesTerminated = m_impl->m_stats.processesTerminated.load(std::memory_order_relaxed);
    snap.hostsProtected     = m_impl->m_stats.hostsProtected.load(std::memory_order_relaxed);
    snap.smbScansDetected   = m_impl->m_stats.smbScansDetected.load(std::memory_order_relaxed);
    snap.mutexDetections    = m_impl->m_stats.mutexDetections.load(std::memory_order_relaxed);
    snap.serviceDetections  = m_impl->m_stats.serviceDetections.load(std::memory_order_relaxed);
    auto elapsed = Clock::now() - m_impl->m_stats.startTime;
    snap.uptimeSeconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
    return snap;
}

void WannaCryDetector::ResetStatistics() {
    try {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_stats.Reset();
        m_impl->m_stats.startTime = Clock::now();
        SS_LOG_INFO(L"WannaCryDetector", L"Statistics reset");
    } catch (const std::exception& ex) {
        Utils::Logger::Error("WannaCryDetector: ResetStatistics failed: {}", ex.what());
    }
}

// ============================================================================
// SELF-TEST
// ============================================================================

bool WannaCryDetector::SelfTest() {
    try {
        SS_LOG_INFO(L"WannaCryDetector", L"Running self-test...");

        // Test 1: Configuration validation
        {
            WannaCryDetectorConfiguration config;
            if (!config.IsValid()) {
                Utils::Logger::Error("WannaCryDetector: Self-test FAIL: config validation");
                return false;
            }
        }

        // Test 2: Kill-switch domain detection
        {
            if (!IsKillSwitchDomain("iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com")) {
                Utils::Logger::Error("WannaCryDetector: Self-test FAIL: kill-switch true positive");
                return false;
            }
            if (IsKillSwitchDomain("microsoft.com")) {
                Utils::Logger::Error("WannaCryDetector: Self-test FAIL: kill-switch false positive");
                return false;
            }
        }

        // Test 3: Artifact detection
        {
            if (!IsWannaCryArtifact(L"C:\\test\\tasksche.exe")) {
                Utils::Logger::Error("WannaCryDetector: Self-test FAIL: artifact detection");
                return false;
            }
            if (!IsWannaCryArtifact(L"C:\\test\\file.WNCRY")) {
                Utils::Logger::Error("WannaCryDetector: Self-test FAIL: extension detection");
                return false;
            }
            if (IsWannaCryArtifact(L"C:\\test\\normal.docx")) {
                Utils::Logger::Error("WannaCryDetector: Self-test FAIL: artifact false positive");
                return false;
            }
        }

        // Test 4: Hash checking. The test injects a synthetic hash, then
        // removes it so the runtime IOC set is not permanently polluted.
        // A residual all-zero entry would otherwise be a permanent
        // false-positive trigger should any caller ever compare against
        // an uninitialised Hash256.
        {
            Hash256 testHash{};
            // Use a deterministic non-zero pattern to make accidental
            // collisions with real samples astronomically unlikely.
            for (size_t i = 0; i < testHash.size(); ++i)
                testHash[i] = static_cast<uint8_t>(0xA5u ^ static_cast<uint8_t>(i));
            std::string hashStr;
            hashStr.reserve(64);
            for (uint8_t byte : testHash) {
                const char hex[] = "0123456789abcdef";
                hashStr.push_back(hex[(byte >> 4) & 0x0F]);
                hashStr.push_back(hex[byte & 0x0F]);
            }

            bool inserted = false;
            {
                std::unique_lock lock(m_impl->m_hashMutex);
                inserted = m_impl->m_knownHashes.insert(hashStr).second;
            }
            bool ok = CheckKnownHash(testHash);
            if (inserted) {
                std::unique_lock lock(m_impl->m_hashMutex);
                m_impl->m_knownHashes.erase(hashStr);
            }
            if (!ok) {
                Utils::Logger::Error("WannaCryDetector: Self-test FAIL: hash check");
                return false;
            }
        }

        // Test 5: EternalBlue signature detection
        {
            std::vector<uint8_t> testPacket = {0xFF, 0x53, 0x4D, 0x42, 0x32, 0x00, 0x00, 0x00};
            if (!m_impl->CheckEternalBlueSignature(testPacket)) {
                Utils::Logger::Error("WannaCryDetector: Self-test FAIL: EternalBlue signature");
                return false;
            }
        }

        // Test 6: Confidence calculation
        {
            WannaCryDetectionResult r;
            r.mutexDetected = true;
            r.serviceDetected = true;
            auto conf = m_impl->CalculateConfidence(r);
            if (conf < DetectionConfidence::High) {
                Utils::Logger::Error("WannaCryDetector: Self-test FAIL: confidence scoring");
                return false;
            }
        }

        SS_LOG_INFO(L"WannaCryDetector", L"Self-test PASSED (6/6 checks)");
        return true;
    } catch (const std::exception& ex) {
        Utils::Logger::Error("WannaCryDetector: Self-test exception: {}", ex.what());
        return false;
    } catch (...) {
        Utils::Logger::Fatal("WannaCryDetector: Self-test unknown exception");
        return false;
    }
}

std::string WannaCryDetector::GetVersionString() noexcept {
    try {
        return std::to_string(WannaCryConstants::VERSION_MAJOR) + "." +
               std::to_string(WannaCryConstants::VERSION_MINOR) + "." +
               std::to_string(WannaCryConstants::VERSION_PATCH);
    } catch (...) { return "0.0.0"; }
}

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

std::string WannaCryDetectionResult::ToJson() const {
    try {
        nlohmann::json j;
        j["detected"] = detected;
        j["variant"] = GetWannaCryVariantName(variant);
        j["phase"] = GetWannaCryPhaseName(phase);
        j["confidence"] = GetDetectionConfidenceName(confidence);
        j["pid"] = pid;
        j["processName"] = Utils::StringUtils::ToNarrow(processName);
        j["indicators"] = indicators;
        j["killSwitchQueried"] = killSwitchQueried;
        j["killSwitchDomain"] = killSwitchDomain;
        j["smbExploitDetected"] = smbExploitDetected;
        j["mutexDetected"] = mutexDetected;
        j["serviceDetected"] = serviceDetected;
        j["mbrThreatDetected"] = mbrThreatDetected;
        j["hostsScanned"] = hostsScanned;
        j["hostsInfected"] = hostsInfected;
        j["filesEncrypted"] = filesEncrypted;
        j["smbConnectionCount"] = smbConnectionCount;
        return j.dump();
    } catch (...) { return "{}"; }
}

void WannaCryStatistics::Reset() noexcept {
    totalDetections.store(0);
    for (auto& c : byVariant) c.store(0);
    smbExploitsBlocked.store(0);
    killSwitchQueries.store(0);
    processesTerminated.store(0);
    hostsProtected.store(0);
    smbScansDetected.store(0);
    mutexDetections.store(0);
    serviceDetections.store(0);
    startTime = Clock::now();
}

std::string WannaCryStatistics::ToJson() const {
    try {
        nlohmann::json j;
        j["totalDetections"] = totalDetections.load();
        j["smbExploitsBlocked"] = smbExploitsBlocked.load();
        j["killSwitchQueries"] = killSwitchQueries.load();
        j["processesTerminated"] = processesTerminated.load();
        j["hostsProtected"] = hostsProtected.load();
        j["smbScansDetected"] = smbScansDetected.load();
        j["mutexDetections"] = mutexDetections.load();
        j["serviceDetections"] = serviceDetections.load();
        auto elapsed = Clock::now() - startTime;
        j["uptimeSeconds"] = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
        return j.dump();
    } catch (...) { return "{}"; }
}

std::string WannaCryStatisticsSnapshot::ToJson() const {
    try {
        nlohmann::json j;
        j["totalDetections"] = totalDetections;
        j["smbExploitsBlocked"] = smbExploitsBlocked;
        j["killSwitchQueries"] = killSwitchQueries;
        j["processesTerminated"] = processesTerminated;
        j["hostsProtected"] = hostsProtected;
        j["smbScansDetected"] = smbScansDetected;
        j["mutexDetections"] = mutexDetections;
        j["serviceDetections"] = serviceDetections;
        j["uptimeSeconds"] = uptimeSeconds;
        return j.dump();
    } catch (...) { return "{}"; }
}

bool WannaCryDetectorConfiguration::IsValid() const noexcept {
    if (smbScanThreshold == 0) return false;
    if (smbScanWindowSecs == 0) return false;
    if (cacheTTLSecs == 0) return false;
    return true;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetWannaCryVariantName(WannaCryVariant variant) noexcept {
    switch (variant) {
        case WannaCryVariant::WannaCry1: return "WannaCry 1.0";
        case WannaCryVariant::WannaCry2: return "WannaCry 2.0";
        case WannaCryVariant::WannaCryNoKill: return "WannaCry (No Kill-Switch)";
        case WannaCryVariant::WannaCryMod: return "WannaCry (Modified)";
        case WannaCryVariant::NotPetya: return "NotPetya/ExPetr";
        case WannaCryVariant::BadRabbit: return "BadRabbit";
        case WannaCryVariant::EternalRocks: return "EternalRocks";
        default: return "Unknown";
    }
}

std::string_view GetWannaCryPhaseName(WannaCryPhase phase) noexcept {
    switch (phase) {
        case WannaCryPhase::InitialDrop: return "Initial Drop";
        case WannaCryPhase::KillSwitchCheck: return "Kill-Switch Check";
        case WannaCryPhase::ServiceCreation: return "Service Creation";
        case WannaCryPhase::Propagation: return "Propagation";
        case WannaCryPhase::Encryption: return "Encryption";
        case WannaCryPhase::RansomDisplay: return "Ransom Display";
        case WannaCryPhase::MBROverwrite: return "MBR Overwrite";
        default: return "Unknown";
    }
}

std::string_view GetDetectionConfidenceName(DetectionConfidence conf) noexcept {
    switch (conf) {
        case DetectionConfidence::None: return "None";
        case DetectionConfidence::Low: return "Low";
        case DetectionConfidence::Medium: return "Medium";
        case DetectionConfidence::High: return "High";
        case DetectionConfidence::Confirmed: return "Confirmed";
        default: return "Unknown";
    }
}

// ============================================================================
// KERNEL BRIDGE
// ============================================================================

void WannaCryDetector::OnKernelProcessNotify(uint32_t processId, std::wstring_view imagePath,
                                              std::wstring_view commandLine, bool isCreate) {
    try {
        if (!IsInitialized() || !isCreate) return;

        fs::path exePath(imagePath);
        std::wstring lowerName = Utils::StringUtils::ToLowerCopy(exePath.filename().wstring());

        static const std::vector<std::wstring> WANNACRY_NAMES = {
            L"tasksche.exe", L"mssecsvc.exe", L"@wanadecryptor@.exe",
            L"taskdl.exe", L"taskse.exe"
        };
        for (const auto& name : WANNACRY_NAMES) {
            if (Utils::StringUtils::IEquals(lowerName, name)) {
                SS_LOG_WARN(L"WannaCryDetector", L"Kernel process notify: WannaCry suspect PID=%u name=%ls",
                            processId, exePath.filename().c_str());
                auto result = DetectEx(processId);
                if (result.detected && result.confidence >= DetectionConfidence::High) {
                    (void)RequestKernelProcessBlock(processId,
                        L"WannaCry detected at kernel process creation");
                }
                return;
            }
        }
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(L"WannaCryDetector", L"OnKernelProcessNotify error: %hs", ex.what());
    } catch (...) {}
}

void WannaCryDetector::OnKernelImageLoad(uint32_t processId, std::wstring_view imagePath,
                                          uint64_t /*imageBase*/, size_t /*imageSize*/) {
    try {
        if (!IsInitialized()) return;

        // Check if loaded image is a known WannaCry DLL/payload
        fs::path path(imagePath);
        std::wstring lowerName = Utils::StringUtils::ToLowerCopy(path.filename().wstring());
        for (const auto& artifact : WANNACRY_ARTIFACTS) {
            if (Utils::StringUtils::IEquals(lowerName, artifact)) {
                SS_LOG_WARN(L"WannaCryDetector", L"Kernel image load: WannaCry artifact PID=%u image=%ls",
                            processId, path.filename().c_str());
                (void)DetectEx(processId);
                return;
            }
        }
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(L"WannaCryDetector", L"OnKernelImageLoad error: %hs", ex.what());
    } catch (...) {}
}

bool WannaCryDetector::RequestKernelProcessBlock(uint32_t processId, const std::wstring& reason) {
    try {
        using namespace Communication;
        if (!IPCManager::HasInstance() || !IPCManager::Instance().IsFilterPortConnected()) {
            SS_LOG_DEBUG(L"WannaCryDetector", L"Kernel IPC not available for process block PID=%u", processId);
            return false;
        }

#pragma pack(push, 1)
        struct KernelBlockRequest {
            uint32_t messageType;
            uint32_t processId;
            wchar_t  reason[256];
        };
#pragma pack(pop)

        KernelBlockRequest req{};
        req.messageType = WannaCryConstants::KERNEL_MSG_BLOCK_PROCESS;
        req.processId = processId;
        wcsncpy_s(req.reason, _countof(req.reason), reason.c_str(), _TRUNCATE);
        req.reason[_countof(req.reason) - 1] = L'\0';  // belt-and-suspenders for kernel safety

        bool result = IPCManager::Instance().SendToKernel(&req, sizeof(req));
        if (result)
            SS_LOG_INFO(L"WannaCryDetector", L"Kernel block requested for PID=%u", processId);
        else
            SS_LOG_WARN(L"WannaCryDetector", L"Kernel block request failed for PID=%u", processId);
        return result;
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(L"WannaCryDetector", L"RequestKernelProcessBlock error: %hs", ex.what());
        return false;
    }
}

// ============================================================================
// CROSS-MODULE WIRING
// ============================================================================

void WannaCryDetector::ReportThreatToAlertSystem(const WannaCryDetectionResult& result) {
    try {
        using namespace Communication;
        if (!AlertSystem::HasInstance()) return;

        auto severity = AlertSeverity::High;
        if (result.confidence >= DetectionConfidence::Confirmed)
            severity = AlertSeverity::Emergency;
        else if (result.confidence >= DetectionConfidence::High)
            severity = AlertSeverity::Critical;

        std::string subject = "WannaCry/" +
            std::string(GetWannaCryVariantName(result.variant)) +
            " detected (PID " + std::to_string(result.pid) + ")";

        (void)AlertSystem::Instance().RaiseAlert(
            severity,
            AlertType::ThreatDetection,
            subject,
            result.ToJson(),
            "WannaCryDetector");
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(L"WannaCryDetector", L"AlertSystem report failed: %hs", ex.what());
    }
}

void WannaCryDetector::ReportDetectionTelemetry(const WannaCryDetectionResult& result) {
    try {
        using namespace Communication;
        if (!TelemetryCollector::HasInstance()) return;

        std::map<std::string, std::string> data;
        data["pid"] = std::to_string(result.pid);
        data["variant"] = std::string(GetWannaCryVariantName(result.variant));
        data["phase"] = std::string(GetWannaCryPhaseName(result.phase));
        data["confidence"] = std::string(GetDetectionConfidenceName(result.confidence));
        data["indicator_count"] = std::to_string(result.indicators.size());
        data["smb_connections"] = std::to_string(result.smbConnectionCount);
        data["kill_switch"] = result.killSwitchQueried ? "true" : "false";
        data["mutex"] = result.mutexDetected ? "true" : "false";
        data["service"] = result.serviceDetected ? "true" : "false";
        data["smb_exploit"] = result.smbExploitDetected ? "true" : "false";

        TelemetryCollector::Instance().RecordCustom("wannacry_detection", data);
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(L"WannaCryDetector", L"Telemetry report failed: %hs", ex.what());
    }
}

void WannaCryDetector::ReportThreatToBehaviorAnalyzer(const WannaCryDetectionResult& result) {
    try {
        using namespace Communication;
        if (!TelemetryCollector::HasInstance()) return;

        std::map<std::string, std::string> data;
        data["source"] = "WannaCryDetector";
        data["pid"] = std::to_string(result.pid);
        data["threat_family"] = "WannaCry";
        data["variant"] = std::string(GetWannaCryVariantName(result.variant));
        data["attack_phase"] = std::string(GetWannaCryPhaseName(result.phase));

        if (result.smbExploitDetected)
            data["technique"] = "T1210";  // Exploitation of Remote Services
        else if (result.killSwitchQueried)
            data["technique"] = "T1071";  // Application Layer Protocol
        else if (result.serviceDetected)
            data["technique"] = "T1543.003";  // Create or Modify System Process: Windows Service

        TelemetryCollector::Instance().RecordCustom("behavior_indicator", data);
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(L"WannaCryDetector", L"BehaviorAnalyzer report failed: %hs", ex.what());
    }
}

}  // namespace Ransomware
}  // namespace ShadowStrike
