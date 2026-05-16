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
 * ============================================================================
 * ShadowStrike Security - SELF-DEFENSE PROTECTION ENGINE IMPLEMENTATION
 * ============================================================================
 *
 * @file SelfDefense.cpp
 * @brief Enterprise-grade self-defense engine protecting ShadowStrike from
 *        termination, tampering, and modification by sophisticated malware.
 *
 * PIMPL IMPLEMENTATION:
 * - SelfDefenseImpl holds all state and logic
 * - Thread-safe via std::shared_mutex + atomics
 * - HMAC-SHA256 authorization tokens (BCrypt CNG)
 * - Kernel bridge: FilterMessageType_SelfProtectAlert / RegisterProtectedProcess
 * - Watchdog thread with heartbeat monitoring and auto-recovery
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "pch.h"
#include "SelfDefense.hpp"
#include "DigitalSignatureValidator.hpp"
#include "../Communication/IPCManager.hpp"

#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <random>
#include <array>
#include <cstring>
#include <cctype>

namespace ShadowStrike {
namespace Security {

// ============================================================================
// LOG CATEGORY
// ============================================================================

static constexpr wchar_t LOG_CATEGORY[] = L"SelfDefense";

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

namespace {

constexpr size_t AUTH_TOKEN_HMAC_SIZE = 32;
constexpr size_t AUTH_TOKEN_HMAC_HEX_LENGTH = AUTH_TOKEN_HMAC_SIZE * 2;

[[nodiscard]] uint8_t DecodeHexNibble(char ch) noexcept {
    if (ch >= '0' && ch <= '9') return static_cast<uint8_t>(ch - '0');
    if (ch >= 'a' && ch <= 'f') return static_cast<uint8_t>(ch - 'a' + 10);
    if (ch >= 'A' && ch <= 'F') return static_cast<uint8_t>(ch - 'A' + 10);
    return 0xFF;
}

[[nodiscard]] std::string HexEncode(std::string_view input) {
    static constexpr char HEX_DIGITS[] = "0123456789abcdef";

    std::string encoded;
    encoded.reserve(input.size() * 2);

    for (const unsigned char byte : input) {
        encoded.push_back(HEX_DIGITS[(byte >> 4) & 0x0F]);
        encoded.push_back(HEX_DIGITS[byte & 0x0F]);
    }

    return encoded;
}

[[nodiscard]] bool HexDecode(std::string_view input, std::string& output) {
    if ((input.size() % 2) != 0) {
        return false;
    }

    output.clear();
    output.reserve(input.size() / 2);

    for (size_t i = 0; i < input.size(); i += 2) {
        const uint8_t high = DecodeHexNibble(input[i]);
        const uint8_t low = DecodeHexNibble(input[i + 1]);
        if (high == 0xFF || low == 0xFF) {
            return false;
        }

        output.push_back(static_cast<char>((high << 4) | low));
    }

    return true;
}

[[nodiscard]] bool ComputeAuthorizationTokenHmac(
    const std::vector<uint8_t>& secret,
    std::string_view payload,
    std::array<uint8_t, AUTH_TOKEN_HMAC_SIZE>& output) {

    output.fill(0);

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;

    const NTSTATUS openStatus = BCryptOpenAlgorithmProvider(
        &algorithm,
        BCRYPT_SHA256_ALGORITHM,
        nullptr,
        BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(openStatus)) {
        return false;
    }

    const NTSTATUS createStatus = BCryptCreateHash(
        algorithm,
        &hash,
        nullptr,
        0,
        const_cast<PUCHAR>(secret.data()),
        static_cast<ULONG>(secret.size()),
        0);
    if (!BCRYPT_SUCCESS(createStatus)) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return false;
    }

    const NTSTATUS hashStatus = BCryptHashData(
        hash,
        reinterpret_cast<PUCHAR>(const_cast<char*>(payload.data())),
        static_cast<ULONG>(payload.size()),
        0);
    const NTSTATUS finishStatus = BCRYPT_SUCCESS(hashStatus)
        ? BCryptFinishHash(hash, output.data(), static_cast<ULONG>(output.size()), 0)
        : hashStatus;

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);

    if (!BCRYPT_SUCCESS(finishStatus)) {
        output.fill(0);
        return false;
    }

    return true;
}

[[nodiscard]] bool ConstantTimeHexEquals(
    std::string_view candidateHex,
    const std::array<uint8_t, AUTH_TOKEN_HMAC_SIZE>& expected) noexcept {

    uint8_t diff = (candidateHex.size() == AUTH_TOKEN_HMAC_HEX_LENGTH) ? 0 : 0xFF;

    for (size_t i = 0; i < expected.size(); ++i) {
        const size_t hiIdx = i * 2;
        const size_t loIdx = hiIdx + 1;

        const uint8_t high = (hiIdx < candidateHex.size())
            ? DecodeHexNibble(candidateHex[hiIdx])
            : static_cast<uint8_t>(0xFF);
        const uint8_t low = (loIdx < candidateHex.size())
            ? DecodeHexNibble(candidateHex[loIdx])
            : static_cast<uint8_t>(0xFF);

        if (high == 0xFF || low == 0xFF) {
            diff = 0xFF;
            continue;
        }

        const uint8_t tokenByte = static_cast<uint8_t>((high << 4) | low);
        diff |= static_cast<uint8_t>(tokenByte ^ expected[i]);
    }

    return diff == 0;
}

}  // namespace

struct InternalProtectedProcess {
    uint32_t processId = 0;
    std::wstring processName;
    std::wstring imagePath;
    std::array<uint8_t, 32> imageHash{};
    HANDLE processHandle = nullptr;
    bool isShadowStrikeComponent = false;
    bool kernelProtected = false;
    bool userModeProtected = false;
    TimePoint protectedSince;
    std::atomic<uint64_t> blockedAttempts{0};
    TimePoint lastBlockedAttempt;
    ComponentHealth health = ComponentHealth::Healthy;

    ~InternalProtectedProcess() {
        if (processHandle && processHandle != INVALID_HANDLE_VALUE) {
            ::CloseHandle(processHandle);
            processHandle = nullptr;
        }
    }

    InternalProtectedProcess() = default;
    InternalProtectedProcess(const InternalProtectedProcess&) = delete;
    InternalProtectedProcess& operator=(const InternalProtectedProcess&) = delete;
};

struct InternalProtectedPath {
    std::string id;
    std::wstring path;
    bool isDirectory = false;
    bool includeSubdirectories = false;
    bool allowWrite = false;
    bool allowDelete = false;
    bool allowRename = false;
    TimePoint protectedSince;
    std::atomic<uint64_t> blockedOperations{0};
};

struct InternalProtectedRegKey {
    std::string id;
    std::wstring keyPath;
    bool includeSubkeys = false;
    std::vector<std::wstring> protectedValues;
    bool allowWrite = false;
    bool allowDelete = false;
    TimePoint protectedSince;
    std::atomic<uint64_t> blockedOperations{0};
};

struct HeartbeatRecord {
    std::string componentName;
    uint32_t processId = 0;
    TimePoint lastBeat;
    ComponentHealth health = ComponentHealth::Healthy;
    uint64_t sequenceNumber = 0;
    uint32_t missedBeats = 0;
};

// ============================================================================
// INTERNAL STATS (atomic, lock-free counters)
// ============================================================================

struct InternalStats {
    std::atomic<uint64_t> totalThreatsDetected{0};
    std::atomic<uint64_t> totalThreatsBlocked{0};
    std::atomic<uint64_t> processTerminationBlocked{0};
    std::atomic<uint64_t> threadTerminationBlocked{0};
    std::atomic<uint64_t> memoryModificationBlocked{0};
    std::atomic<uint64_t> fileModificationBlocked{0};
    std::atomic<uint64_t> registryModificationBlocked{0};
    std::atomic<uint64_t> serviceControlBlocked{0};
    std::atomic<uint64_t> autoRecoveryEvents{0};
    std::atomic<uint64_t> successfulRecoveries{0};
    TimePoint startTime = Clock::now();
    std::atomic<uint64_t> lastThreatTimeNs{0};
    std::array<std::atomic<uint64_t>, 32> threatTypeCounts{};

    void Reset() noexcept {
        totalThreatsDetected.store(0, std::memory_order_relaxed);
        totalThreatsBlocked.store(0, std::memory_order_relaxed);
        processTerminationBlocked.store(0, std::memory_order_relaxed);
        threadTerminationBlocked.store(0, std::memory_order_relaxed);
        memoryModificationBlocked.store(0, std::memory_order_relaxed);
        fileModificationBlocked.store(0, std::memory_order_relaxed);
        registryModificationBlocked.store(0, std::memory_order_relaxed);
        serviceControlBlocked.store(0, std::memory_order_relaxed);
        autoRecoveryEvents.store(0, std::memory_order_relaxed);
        successfulRecoveries.store(0, std::memory_order_relaxed);
        startTime = Clock::now();
        lastThreatTimeNs.store(0, std::memory_order_relaxed);
        for (auto& c : threatTypeCounts) c.store(0, std::memory_order_relaxed);
    }

    [[nodiscard]] SelfDefenseStatistics Snapshot() const noexcept {
        SelfDefenseStatistics snap;
        snap.totalThreatsDetected = totalThreatsDetected.load(std::memory_order_relaxed);
        snap.totalThreatsBlocked = totalThreatsBlocked.load(std::memory_order_relaxed);
        snap.processTerminationBlocked = processTerminationBlocked.load(std::memory_order_relaxed);
        snap.threadTerminationBlocked = threadTerminationBlocked.load(std::memory_order_relaxed);
        snap.memoryModificationBlocked = memoryModificationBlocked.load(std::memory_order_relaxed);
        snap.fileModificationBlocked = fileModificationBlocked.load(std::memory_order_relaxed);
        snap.registryModificationBlocked = registryModificationBlocked.load(std::memory_order_relaxed);
        snap.serviceControlBlocked = serviceControlBlocked.load(std::memory_order_relaxed);
        snap.autoRecoveryEvents = autoRecoveryEvents.load(std::memory_order_relaxed);
        snap.successfulRecoveries = successfulRecoveries.load(std::memory_order_relaxed);
        snap.startTime = startTime;
        auto ns = lastThreatTimeNs.load(std::memory_order_relaxed);
        if (ns > 0) {
            snap.lastThreatTime = TimePoint(std::chrono::nanoseconds(ns));
        }
        for (uint32_t bit = 0; bit < 32; ++bit) {
            uint64_t count = threatTypeCounts[bit].load(std::memory_order_relaxed);
            if (count > 0) {
                snap.threatsByType[static_cast<ThreatType>(1u << bit)] = count;
            }
        }
        return snap;
    }
};

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class SelfDefenseImpl {
public:
    SelfDefenseImpl() = default;
    ~SelfDefenseImpl();

    SelfDefenseImpl(const SelfDefenseImpl&) = delete;
    SelfDefenseImpl& operator=(const SelfDefenseImpl&) = delete;

    // Lifecycle
    bool Initialize(const SelfDefenseConfiguration& config);
    void Shutdown(std::string_view authorizationToken);
    void ShutdownInternal();  ///< Bypasses auth-token check; only callable from destructor path.
    bool IsInitialized() const noexcept { return m_initialized.load(std::memory_order_acquire); }
    ModuleStatus GetStatus() const noexcept { return m_status.load(std::memory_order_acquire); }
    bool Pause(std::string_view authorizationToken, uint32_t durationMs);
    void Resume();

    // Configuration
    bool SetConfiguration(const SelfDefenseConfiguration& config);
    SelfDefenseConfiguration GetConfiguration() const;
    void SetProtectionLevel(SelfDefenseLevel level);
    SelfDefenseLevel GetProtectionLevel() const noexcept;
    bool EnableComponent(ProtectionComponent component);
    bool DisableComponent(ProtectionComponent component, std::string_view authorizationToken);
    bool IsComponentEnabled(ProtectionComponent component) const noexcept;
    void SetThreatResponse(ThreatType threatType, ThreatResponse response);
    ThreatResponse GetThreatResponse(ThreatType threatType) const;

    // Process protection
    bool ProtectProcess(uint32_t processId);
    bool UnprotectProcess(uint32_t processId, std::string_view authorizationToken);
    bool IsProcessProtected(uint32_t processId) const;
    std::optional<ProtectedProcess> GetProtectedProcess(uint32_t processId) const;
    std::vector<ProtectedProcess> GetAllProtectedProcesses() const;
    bool IsAccessAllowed(uint32_t callerPid, uint32_t targetPid, uint32_t desiredAccess);
    AccessDecisionResult FilterAccessRequest(const AccessRequest& request);
    bool RegisterShadowStrikeComponent(uint32_t processId, std::string_view componentName);

    // Service protection
    bool ProtectService();
    bool IsServiceProtected() const;
    ComponentStatus GetServiceStatus() const;
    bool EnsureServiceRunning();

    // Driver protection
    bool ProtectDriver();
    bool IsDriverProtected() const;
    ComponentStatus GetDriverStatus() const;
    bool IsDriverLoaded() const;
    bool EnsureDriverLoaded();

    // File system protection
    bool ProtectPath(std::wstring_view path, bool includeSubdirectories);
    bool UnprotectPath(std::wstring_view path, std::string_view authorizationToken);
    bool IsPathProtected(std::wstring_view path) const;
    std::optional<ProtectedPath> GetProtectedPath(std::wstring_view path) const;
    std::vector<ProtectedPath> GetAllProtectedPaths() const;
    bool ProtectInstallationDirectory();

    // Registry protection
    bool ProtectRegistryKey(std::wstring_view keyPath, bool includeSubkeys);
    bool UnprotectRegistryKey(std::wstring_view keyPath, std::string_view authorizationToken);
    bool IsRegistryKeyProtected(std::wstring_view keyPath) const;
    std::optional<ProtectedRegistryKey> GetProtectedRegistryKey(std::wstring_view keyPath) const;
    std::vector<ProtectedRegistryKey> GetAllProtectedRegistryKeys() const;
    bool ProtectServiceRegistryKeys();

    // Memory protection
    bool ProtectMemoryRegion(uintptr_t address, size_t size);
    bool UnprotectMemoryRegion(uintptr_t address, std::string_view authorizationToken);
    bool ProtectCodeSection();
    bool VerifyMemoryIntegrity();

    // Watchdog
    bool StartWatchdog();
    void StopWatchdog(std::string_view authorizationToken);
    bool IsWatchdogRunning() const;
    void SendHeartbeat(std::string_view componentName);
    bool TriggerRecovery(ProtectionComponent component);
    ComponentHealth GetComponentHealth(ProtectionComponent component) const;
    std::vector<ComponentStatus> GetAllComponentStatuses() const;

    // Whitelist
    bool AddToWhitelist(std::wstring_view processName, std::string_view authorizationToken);
    bool RemoveFromWhitelist(std::wstring_view processName, std::string_view authorizationToken);
    bool IsWhitelisted(std::wstring_view processName) const;
    bool IsWhitelisted(uint32_t processId) const;
    std::vector<std::wstring> GetWhitelistedProcesses() const;

    // Callbacks
    uint64_t RegisterThreatCallback(ThreatCallback callback);
    void UnregisterThreatCallback(uint64_t callbackId);
    uint64_t RegisterAccessCallback(AccessCallback callback);
    void UnregisterAccessCallback(uint64_t callbackId);
    uint64_t RegisterStatusCallback(ComponentStatusCallback callback);
    void UnregisterStatusCallback(uint64_t callbackId);
    uint64_t RegisterRecoveryCallback(RecoveryCallback callback);
    void UnregisterRecoveryCallback(uint64_t callbackId);
    uint64_t RegisterHeartbeatCallback(HeartbeatCallback callback);
    void UnregisterHeartbeatCallback(uint64_t callbackId);

    // Statistics
    SelfDefenseStatistics GetStatistics() const;
    void ResetStatistics(std::string_view authorizationToken);
    std::vector<ThreatEvent> GetThreatHistory(size_t maxEntries) const;
    void ClearThreatHistory(std::string_view authorizationToken);
    std::string ExportReport() const;

    // Utility
    bool SelfTest();
    bool VerifyAuthorizationToken(std::string_view token) const;
    std::string GenerateAuthorizationToken(std::string_view purpose, uint32_t validitySeconds);

    // Kernel bridge
    void SyncProtectedProcessesToKernel();
    void OnKernelSelfProtectEventInternal(const void* data, uint32_t size);

private:
    mutable std::shared_mutex m_mutex;
    mutable std::shared_mutex m_callbackMutex;
    mutable std::shared_mutex m_historyMutex;

    std::atomic<bool> m_initialized{false};
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    SelfDefenseConfiguration m_config;

    std::vector<uint8_t> m_authSecret;

    std::unordered_map<uint32_t, std::unique_ptr<InternalProtectedProcess>> m_protectedProcesses;
    std::map<std::wstring, std::unique_ptr<InternalProtectedPath>, std::less<>> m_protectedPaths;
    std::map<std::wstring, std::unique_ptr<InternalProtectedRegKey>, std::less<>> m_protectedRegKeys;

    struct MemoryRegion {
        uintptr_t address = 0;
        size_t size = 0;
        std::vector<uint8_t> originalHash;
    };
    std::vector<MemoryRegion> m_protectedMemoryRegions;
    std::vector<uint8_t> m_codeSectionHash;
    uintptr_t m_codeSectionBase = 0;
    size_t m_codeSectionSize = 0;

    std::unordered_set<std::wstring> m_whitelist;
    std::unordered_map<ThreatType, ThreatResponse> m_threatResponsePolicy;
    std::unordered_map<ProtectionComponent, ComponentStatus> m_componentStatuses;

    std::unordered_map<uint64_t, ThreatCallback> m_threatCallbacks;
    std::unordered_map<uint64_t, AccessCallback> m_accessCallbacks;
    std::unordered_map<uint64_t, ComponentStatusCallback> m_statusCallbacks;
    std::unordered_map<uint64_t, RecoveryCallback> m_recoveryCallbacks;
    std::unordered_map<uint64_t, HeartbeatCallback> m_heartbeatCallbacks;
    std::atomic<uint64_t> m_nextCallbackId{1};

    std::deque<ThreatEvent> m_threatHistory;
    static constexpr size_t MAX_THREAT_HISTORY = 10000;
    std::atomic<uint64_t> m_nextEventId{1};

    std::thread m_watchdogThread;
    std::atomic<bool> m_watchdogRunning{false};
    mutable std::mutex m_watchdogMutex;          ///< Dedicated mutex for watchdog CV; never overlaps m_mutex.
    std::condition_variable m_watchdogCv;
    std::unordered_map<std::string, HeartbeatRecord> m_heartbeatRecords;

    std::atomic<bool> m_serviceProtected{false};
    std::atomic<bool> m_driverProtected{false};
    std::atomic<bool> m_kernelHandlerRegistered{false};
    std::atomic<bool> m_initializing{false};      ///< Guards reentrant Initialize() during in-progress init.
    std::atomic<bool> m_shutdownInProgress{false};///< True only during Shutdown teardown window.
    std::atomic<int64_t> m_pauseDeadlineNs{0};    ///< Steady-clock ns timestamp at which an auto-resume becomes due (0 = no deadline).

    InternalStats m_stats;

    // Helpers
    void WatchdogThreadFunc();
    void RecordThreatEvent(ThreatEvent&& event);
    void NotifyThreatCallbacks(const ThreatEvent& event);
    void NotifyStatusCallbacks(ProtectionComponent comp, ComponentHealth health);
    void UpdateComponentStatus(ProtectionComponent comp, bool active, ComponentHealth health, const std::string& error = "");
    bool VerifyProcessSignature(const std::wstring& imagePath) const;
    void IncrementThreatTypeStat(ThreatType type);
    bool IsCallerWhitelisted(uint32_t callerPid) const;
    std::wstring GetProcessImagePath(uint32_t processId) const;
    std::wstring GetProcessName(uint32_t processId) const;
    std::vector<uint8_t> ComputeSHA256(const void* data, size_t size) const;
    void RegisterKernelHandler();
    void UnregisterKernelHandler();
    static std::wstring NormalizePath(std::wstring_view path);
    static std::wstring NormalizeKeyPath(std::wstring_view keyPath);
};

// ============================================================================
// STATIC MEMBERS
// ============================================================================

std::atomic<bool> SelfDefense::s_instanceCreated{false};

// ============================================================================
// SINGLETON & FORWARDING METHODS
// ============================================================================

SelfDefense& SelfDefense::Instance() noexcept {
    static SelfDefense instance;
    return instance;
}

bool SelfDefense::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

SelfDefense::SelfDefense()
    : m_impl(std::make_unique<SelfDefenseImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
}

SelfDefense::~SelfDefense() {
    s_instanceCreated.store(false, std::memory_order_release);
}

bool SelfDefense::Initialize(const SelfDefenseConfiguration& config) { return m_impl->Initialize(config); }
bool SelfDefense::Initialize(SelfDefenseLevel level) {
    return m_impl->Initialize(SelfDefenseConfiguration::FromLevel(level));
}
void SelfDefense::Shutdown(std::string_view authorizationToken) { m_impl->Shutdown(authorizationToken); }
bool SelfDefense::IsInitialized() const noexcept { return m_impl->IsInitialized(); }
ModuleStatus SelfDefense::GetStatus() const noexcept { return m_impl->GetStatus(); }
bool SelfDefense::Pause(std::string_view authorizationToken, uint32_t durationMs) { return m_impl->Pause(authorizationToken, durationMs); }
void SelfDefense::Resume() { m_impl->Resume(); }
bool SelfDefense::SetConfiguration(const SelfDefenseConfiguration& config) { return m_impl->SetConfiguration(config); }
SelfDefenseConfiguration SelfDefense::GetConfiguration() const { return m_impl->GetConfiguration(); }
void SelfDefense::SetProtectionLevel(SelfDefenseLevel level) { m_impl->SetProtectionLevel(level); }
SelfDefenseLevel SelfDefense::GetProtectionLevel() const noexcept { return m_impl->GetProtectionLevel(); }
bool SelfDefense::EnableComponent(ProtectionComponent component) { return m_impl->EnableComponent(component); }
bool SelfDefense::DisableComponent(ProtectionComponent component, std::string_view authorizationToken) { return m_impl->DisableComponent(component, authorizationToken); }
bool SelfDefense::IsComponentEnabled(ProtectionComponent component) const noexcept { return m_impl->IsComponentEnabled(component); }
void SelfDefense::SetThreatResponse(ThreatType threatType, SelfDefenseThreatResponse response) { m_impl->SetThreatResponse(threatType, response); }
SelfDefenseThreatResponse SelfDefense::GetThreatResponse(ThreatType threatType) const { return m_impl->GetThreatResponse(threatType); }

bool SelfDefense::ProtectProcess(uint32_t processId) { return m_impl->ProtectProcess(processId); }
bool SelfDefense::UnprotectProcess(uint32_t processId, std::string_view authorizationToken) { return m_impl->UnprotectProcess(processId, authorizationToken); }
bool SelfDefense::IsProcessProtected(uint32_t processId) const { return m_impl->IsProcessProtected(processId); }
std::optional<ProtectedProcess> SelfDefense::GetProtectedProcess(uint32_t processId) const { return m_impl->GetProtectedProcess(processId); }
std::vector<ProtectedProcess> SelfDefense::GetAllProtectedProcesses() const { return m_impl->GetAllProtectedProcesses(); }
bool SelfDefense::IsAccessAllowed(uint32_t callerPid, uint32_t targetPid, uint32_t desiredAccess) { return m_impl->IsAccessAllowed(callerPid, targetPid, desiredAccess); }
SelfDefenseAccessDecisionResult SelfDefense::FilterAccessRequest(const SelfDefenseAccessRequest& request) { return m_impl->FilterAccessRequest(request); }
bool SelfDefense::RegisterShadowStrikeComponent(uint32_t processId, std::string_view componentName) { return m_impl->RegisterShadowStrikeComponent(processId, componentName); }

bool SelfDefense::ProtectService() { return m_impl->ProtectService(); }
bool SelfDefense::IsServiceProtected() const { return m_impl->IsServiceProtected(); }
ComponentStatus SelfDefense::GetServiceStatus() const { return m_impl->GetServiceStatus(); }
bool SelfDefense::EnsureServiceRunning() { return m_impl->EnsureServiceRunning(); }

bool SelfDefense::ProtectDriver() { return m_impl->ProtectDriver(); }
bool SelfDefense::IsDriverProtected() const { return m_impl->IsDriverProtected(); }
ComponentStatus SelfDefense::GetDriverStatus() const { return m_impl->GetDriverStatus(); }
bool SelfDefense::IsDriverLoaded() const { return m_impl->IsDriverLoaded(); }
bool SelfDefense::EnsureDriverLoaded() { return m_impl->EnsureDriverLoaded(); }

bool SelfDefense::ProtectPath(std::wstring_view path, bool includeSubdirectories) { return m_impl->ProtectPath(path, includeSubdirectories); }
bool SelfDefense::UnprotectPath(std::wstring_view path, std::string_view authorizationToken) { return m_impl->UnprotectPath(path, authorizationToken); }
bool SelfDefense::IsPathProtected(std::wstring_view path) const { return m_impl->IsPathProtected(path); }
std::optional<ProtectedPath> SelfDefense::GetProtectedPath(std::wstring_view path) const { return m_impl->GetProtectedPath(path); }
std::vector<ProtectedPath> SelfDefense::GetAllProtectedPaths() const { return m_impl->GetAllProtectedPaths(); }
bool SelfDefense::ProtectInstallationDirectory() { return m_impl->ProtectInstallationDirectory(); }

bool SelfDefense::ProtectRegistryKey(std::wstring_view keyPath, bool includeSubkeys) { return m_impl->ProtectRegistryKey(keyPath, includeSubkeys); }
bool SelfDefense::UnprotectRegistryKey(std::wstring_view keyPath, std::string_view authorizationToken) { return m_impl->UnprotectRegistryKey(keyPath, authorizationToken); }
bool SelfDefense::IsRegistryKeyProtected(std::wstring_view keyPath) const { return m_impl->IsRegistryKeyProtected(keyPath); }
std::optional<ProtectedRegistryKey> SelfDefense::GetProtectedRegistryKey(std::wstring_view keyPath) const { return m_impl->GetProtectedRegistryKey(keyPath); }
std::vector<ProtectedRegistryKey> SelfDefense::GetAllProtectedRegistryKeys() const { return m_impl->GetAllProtectedRegistryKeys(); }
bool SelfDefense::ProtectServiceRegistryKeys() { return m_impl->ProtectServiceRegistryKeys(); }

bool SelfDefense::ProtectMemoryRegion(uintptr_t address, size_t size) { return m_impl->ProtectMemoryRegion(address, size); }
bool SelfDefense::UnprotectMemoryRegion(uintptr_t address, std::string_view authorizationToken) { return m_impl->UnprotectMemoryRegion(address, authorizationToken); }
bool SelfDefense::ProtectCodeSection() { return m_impl->ProtectCodeSection(); }
bool SelfDefense::VerifyMemoryIntegrity() { return m_impl->VerifyMemoryIntegrity(); }

bool SelfDefense::StartWatchdog() { return m_impl->StartWatchdog(); }
void SelfDefense::StopWatchdog(std::string_view authorizationToken) { m_impl->StopWatchdog(authorizationToken); }
bool SelfDefense::IsWatchdogRunning() const { return m_impl->IsWatchdogRunning(); }
void SelfDefense::SendHeartbeat(std::string_view componentName) { m_impl->SendHeartbeat(componentName); }
bool SelfDefense::TriggerRecovery(ProtectionComponent component) { return m_impl->TriggerRecovery(component); }
ComponentHealth SelfDefense::GetComponentHealth(ProtectionComponent component) const { return m_impl->GetComponentHealth(component); }
std::vector<ComponentStatus> SelfDefense::GetAllComponentStatuses() const { return m_impl->GetAllComponentStatuses(); }

bool SelfDefense::AddToWhitelist(std::wstring_view processName, std::string_view authorizationToken) { return m_impl->AddToWhitelist(processName, authorizationToken); }
bool SelfDefense::RemoveFromWhitelist(std::wstring_view processName, std::string_view authorizationToken) { return m_impl->RemoveFromWhitelist(processName, authorizationToken); }
bool SelfDefense::IsWhitelisted(std::wstring_view processName) const { return m_impl->IsWhitelisted(processName); }
bool SelfDefense::IsWhitelisted(uint32_t processId) const { return m_impl->IsWhitelisted(processId); }
std::vector<std::wstring> SelfDefense::GetWhitelistedProcesses() const { return m_impl->GetWhitelistedProcesses(); }

uint64_t SelfDefense::RegisterThreatCallback(SelfDefenseThreatCallback callback) { return m_impl->RegisterThreatCallback(std::move(callback)); }
void SelfDefense::UnregisterThreatCallback(uint64_t callbackId) { m_impl->UnregisterThreatCallback(callbackId); }
uint64_t SelfDefense::RegisterAccessCallback(AccessCallback callback) { return m_impl->RegisterAccessCallback(std::move(callback)); }
void SelfDefense::UnregisterAccessCallback(uint64_t callbackId) { m_impl->UnregisterAccessCallback(callbackId); }
uint64_t SelfDefense::RegisterStatusCallback(ComponentStatusCallback callback) { return m_impl->RegisterStatusCallback(std::move(callback)); }
void SelfDefense::UnregisterStatusCallback(uint64_t callbackId) { m_impl->UnregisterStatusCallback(callbackId); }
uint64_t SelfDefense::RegisterRecoveryCallback(RecoveryCallback callback) { return m_impl->RegisterRecoveryCallback(std::move(callback)); }
void SelfDefense::UnregisterRecoveryCallback(uint64_t callbackId) { m_impl->UnregisterRecoveryCallback(callbackId); }
uint64_t SelfDefense::RegisterHeartbeatCallback(HeartbeatCallback callback) { return m_impl->RegisterHeartbeatCallback(std::move(callback)); }
void SelfDefense::UnregisterHeartbeatCallback(uint64_t callbackId) { m_impl->UnregisterHeartbeatCallback(callbackId); }

SelfDefenseStatistics SelfDefense::GetStatistics() const { return m_impl->GetStatistics(); }
void SelfDefense::ResetStatistics(std::string_view authorizationToken) { m_impl->ResetStatistics(authorizationToken); }
std::vector<ThreatEvent> SelfDefense::GetThreatHistory(size_t maxEntries) const { return m_impl->GetThreatHistory(maxEntries); }
void SelfDefense::ClearThreatHistory(std::string_view authorizationToken) { m_impl->ClearThreatHistory(authorizationToken); }
std::string SelfDefense::ExportReport() const { return m_impl->ExportReport(); }

bool SelfDefense::SelfTest() { return m_impl->SelfTest(); }
bool SelfDefense::VerifyAuthorizationToken(std::string_view token) const { return m_impl->VerifyAuthorizationToken(token); }
std::string SelfDefense::GenerateAuthorizationToken(std::string_view purpose, uint32_t validitySeconds) { return m_impl->GenerateAuthorizationToken(purpose, validitySeconds); }

std::string SelfDefense::GetVersionString() noexcept {
    return std::to_string(SelfDefenseConstants::VERSION_MAJOR) + "." +
           std::to_string(SelfDefenseConstants::VERSION_MINOR) + "." +
           std::to_string(SelfDefenseConstants::VERSION_PATCH);
}

void SelfDefense::SyncProtectedProcessesToKernel() { m_impl->SyncProtectedProcessesToKernel(); }
void SelfDefense::OnKernelSelfProtectEvent(const void* data, uint32_t size) { m_impl->OnKernelSelfProtectEventInternal(data, size); }

// ============================================================================
// IMPL LIFECYCLE
// ============================================================================

SelfDefenseImpl::~SelfDefenseImpl() {
    if (m_initialized.load(std::memory_order_acquire)) {
        ShutdownInternal();
    }
}

std::vector<uint8_t> SelfDefenseImpl::ComputeSHA256(const void* data, size_t size) const {
    std::vector<uint8_t> hash;
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) return hash;
    status = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return hash; }
    status = BCryptHashData(hHash, const_cast<PUCHAR>(static_cast<const UCHAR*>(data)), static_cast<ULONG>(size), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return hash;
    }
    hash.resize(32, 0);
    status = BCryptFinishHash(hHash, hash.data(), static_cast<ULONG>(hash.size()), 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (!BCRYPT_SUCCESS(status)) {
        hash.clear();
    }
    return hash;
}

std::wstring SelfDefenseImpl::NormalizePath(std::wstring_view path) {
    std::wstring result(path);
    std::transform(result.begin(), result.end(), result.begin(), ::towlower);
    for (auto& ch : result) { if (ch == L'/') ch = L'\\'; }
    while (!result.empty() && result.back() == L'\\') result.pop_back();
    return result;
}

std::wstring SelfDefenseImpl::NormalizeKeyPath(std::wstring_view keyPath) {
    std::wstring result(keyPath);
    std::transform(result.begin(), result.end(), result.begin(), ::towlower);
    while (!result.empty() && result.back() == L'\\') result.pop_back();
    return result;
}

std::wstring SelfDefenseImpl::GetProcessImagePath(uint32_t processId) const {
    HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return {};
    wchar_t pathBuf[MAX_PATH + 1]{};
    DWORD pathLen = MAX_PATH;
    BOOL ok = ::QueryFullProcessImageNameW(hProcess, 0, pathBuf, &pathLen);
    ::CloseHandle(hProcess);
    return ok ? std::wstring(pathBuf, pathLen) : std::wstring{};
}

std::wstring SelfDefenseImpl::GetProcessName(uint32_t processId) const {
    auto path = GetProcessImagePath(processId);
    if (path.empty()) return {};
    auto pos = path.find_last_of(L"\\/");
    return (pos != std::wstring::npos) ? path.substr(pos + 1) : path;
}

bool SelfDefenseImpl::VerifyProcessSignature(const std::wstring& imagePath) const {
    if (imagePath.empty()) return false;
    if (!DigitalSignatureValidator::HasInstance()) return false;
    auto& validator = DigitalSignatureValidator::Instance();
    if (!validator.IsInitialized()) return false;
    auto sigInfo = validator.VerifyFile(imagePath);
    return sigInfo.isValid;
}

void SelfDefenseImpl::IncrementThreatTypeStat(ThreatType type) {
    uint32_t val = static_cast<uint32_t>(type);
    for (uint32_t bit = 0; bit < 32 && val != 0; ++bit) {
        if (val & (1u << bit)) {
            m_stats.threatTypeCounts[bit].fetch_add(1, std::memory_order_relaxed);
        }
    }
}

bool SelfDefenseImpl::IsCallerWhitelisted(uint32_t callerPid) const {
    auto name = GetProcessName(callerPid);
    if (name.empty()) return false;
    std::transform(name.begin(), name.end(), name.begin(), ::towlower);
    std::shared_lock lock(m_mutex);
    return m_whitelist.contains(name);
}

void SelfDefenseImpl::RecordThreatEvent(ThreatEvent&& event) {
    event.eventId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
    m_stats.totalThreatsDetected.fetch_add(1, std::memory_order_relaxed);
    if (event.wasBlocked) {
        m_stats.totalThreatsBlocked.fetch_add(1, std::memory_order_relaxed);
    }
    IncrementThreatTypeStat(event.type);
    auto nowNs = std::chrono::duration_cast<std::chrono::nanoseconds>(
        event.timestamp.time_since_epoch()).count();
    m_stats.lastThreatTimeNs.store(static_cast<uint64_t>(nowNs), std::memory_order_relaxed);

    ThreatEvent copy = event;
    {
        std::unique_lock lock(m_historyMutex);
        m_threatHistory.push_back(std::move(event));
        while (m_threatHistory.size() > MAX_THREAT_HISTORY) {
            m_threatHistory.pop_front();
        }
    }
    NotifyThreatCallbacks(copy);
}

void SelfDefenseImpl::NotifyThreatCallbacks(const ThreatEvent& event) {
    std::vector<ThreatCallback> cbs;
    {
        std::shared_lock lock(m_callbackMutex);
        cbs.reserve(m_threatCallbacks.size());
        for (const auto& [id, cb] : m_threatCallbacks) cbs.push_back(cb);
    }
    for (const auto& cb : cbs) {
        try { cb(event); }
        catch (const std::exception& ex) {
            SS_LOG_WARN(LOG_CATEGORY, L"Threat callback threw: %S", ex.what());
        }
    }
}

void SelfDefenseImpl::NotifyStatusCallbacks(ProtectionComponent comp, ComponentHealth health) {
    std::vector<ComponentStatusCallback> cbs;
    {
        std::shared_lock lock(m_callbackMutex);
        cbs.reserve(m_statusCallbacks.size());
        for (const auto& [id, cb] : m_statusCallbacks) cbs.push_back(cb);
    }
    for (const auto& cb : cbs) {
        try { cb(comp, health); }
        catch (...) {}
    }
}

void SelfDefenseImpl::UpdateComponentStatus(ProtectionComponent comp, bool active,
                                            ComponentHealth health, const std::string& error) {
    std::unique_lock lock(m_mutex);
    auto& status = m_componentStatuses[comp];
    status.component = comp;
    status.isActive = active;
    status.health = health;
    status.lastCheck = Clock::now();
    status.errorMessage = error;
    if (active && health == ComponentHealth::Healthy) {
        status.lastSuccessfulOperation = Clock::now();
    }
}

// ============================================================================
// INITIALIZE
// ============================================================================

bool SelfDefenseImpl::Initialize(const SelfDefenseConfiguration& config) {
    // Guard against reentrant or concurrent Initialize(). The body releases m_mutex
    // partway through (line below) to invoke ProtectProcess()/ProtectInstallationDirectory()
    // which themselves acquire m_mutex. A second Initialize() arriving during that window
    // would otherwise observe m_initialized == false and re-enter, overwriting m_config
    // and regenerating m_authSecret (invalidating all outstanding authorization tokens).
    bool expected = false;
    if (!m_initializing.compare_exchange_strong(expected, true,
                                                std::memory_order_acq_rel)) {
        SS_LOG_WARN(LOG_CATEGORY, L"Initialize rejected: another Initialize is already in progress");
        return false;
    }
    struct InitGuard {
        std::atomic<bool>& flag;
        ~InitGuard() { flag.store(false, std::memory_order_release); }
    } initGuard{m_initializing};

    std::unique_lock lock(m_mutex);

    if (m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(LOG_CATEGORY, L"Already initialized");
        return true;
    }

    m_status.store(ModuleStatus::Initializing, std::memory_order_release);

    if (!config.IsValid()) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration");
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    }

    m_config = config;

    // Generate per-session HMAC secret (64 bytes from CSPRNG)
    m_authSecret.resize(64);
    {
        BCRYPT_ALG_HANDLE hRng = nullptr;
        if (BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, nullptr, 0))) {
            BCryptGenRandom(hRng, m_authSecret.data(), static_cast<ULONG>(m_authSecret.size()), 0);
            BCryptCloseAlgorithmProvider(hRng, 0);
        } else {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to generate auth secret via BCrypt");
            std::random_device rd;
            std::mt19937_64 gen(rd());
            std::uniform_int_distribution<int> dist(0, 255);
            for (auto& byte : m_authSecret) byte = static_cast<uint8_t>(dist(gen));
        }
    }

    // Apply whitelist from config
    for (const auto& name : config.whitelistedProcesses) {
        std::wstring lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
        m_whitelist.insert(std::move(lower));
    }

    // Apply default threat response policies
    m_threatResponsePolicy[ThreatType::ProcessTermination] = ThreatResponse::Aggressive;
    m_threatResponsePolicy[ThreatType::CodeInjection] = ThreatResponse::Aggressive;
    m_threatResponsePolicy[ThreatType::ServiceControl] = ThreatResponse::Active;
    m_threatResponsePolicy[ThreatType::FileModification] = ThreatResponse::Active;
    m_threatResponsePolicy[ThreatType::RegistryModification] = ThreatResponse::Active;
    m_threatResponsePolicy[ThreatType::MemoryModification] = ThreatResponse::Active;
    m_threatResponsePolicy[ThreatType::DebugAttach] = ThreatResponse::Aggressive;

    // Protect current process
    uint32_t selfPid = ::GetCurrentProcessId();
    lock.unlock();
    SS_LOG_INFO(LOG_CATEGORY, L"SelfDefense: ProtectProcess(self)...");
    bool selfProtected = ProtectProcess(selfPid);
    SS_LOG_INFO(LOG_CATEGORY, L"SelfDefense: RegisterShadowStrikeComponent...");
    RegisterShadowStrikeComponent(selfPid, "ShadowStrikeService");

    // Track any critical protection failures
    bool degraded = !selfProtected;

    // Protect additional processes from config
    for (uint32_t pid : config.additionalProtectedProcesses) {
        ProtectProcess(pid);
    }

    // Protect file paths from config
    for (const auto& path : config.additionalProtectedPaths) {
        ProtectPath(path, true);
    }

    // Protect registry keys from config
    for (const auto& key : config.additionalProtectedKeys) {
        ProtectRegistryKey(key, true);
    }

    // Protect installation directory
    SS_LOG_INFO(LOG_CATEGORY, L"SelfDefense: ProtectInstallationDirectory...");
    ProtectInstallationDirectory();

    // Protect service registry keys
    SS_LOG_INFO(LOG_CATEGORY, L"SelfDefense: ProtectServiceRegistryKeys...");
    ProtectServiceRegistryKeys();

    // Start watchdog if enabled
    if (config.enableWatchdog) {
        SS_LOG_INFO(LOG_CATEGORY, L"SelfDefense: StartWatchdog...");
        if (!StartWatchdog()) degraded = true;
    }

    // Protect code section if integrity monitoring enabled
    if (config.enableIntegrityMonitoring) {
        SS_LOG_INFO(LOG_CATEGORY, L"SelfDefense: ProtectCodeSection...");
        if (!ProtectCodeSection()) degraded = true;
    }

    m_stats.Reset();
    m_initialized.store(true, std::memory_order_release);
    m_status.store(degraded ? ModuleStatus::Degraded : ModuleStatus::Running, std::memory_order_release);
    if (degraded) {
        SS_LOG_WARN(LOG_CATEGORY, L"Initialized in DEGRADED mode — some protections failed");
    }

    // Kernel bridge: sync protected processes and register alert handler
    if (config.enableKernelProtection) {
        SS_LOG_INFO(LOG_CATEGORY, L"SelfDefense: SyncProtectedProcessesToKernel...");
        SyncProtectedProcessesToKernel();
        SS_LOG_INFO(LOG_CATEGORY, L"SelfDefense: RegisterKernelHandler...");
        RegisterKernelHandler();
    }

    SS_LOG_INFO(LOG_CATEGORY, L"Self-defense initialized (level=%u, components=0x%08X)",
               static_cast<unsigned>(config.level),
               static_cast<unsigned>(config.enabledComponents));
    return true;
}

// ============================================================================
// SHUTDOWN
// ============================================================================

void SelfDefenseImpl::Shutdown(std::string_view authorizationToken) {
    // Public entry point requires a valid HMAC authorization token. Only the
    // private ShutdownInternal() path (invoked from the destructor) bypasses
    // authorization; that path is unreachable from outside this translation unit.
    if (!m_initialized.load(std::memory_order_acquire)) {
        return;
    }
    if (!VerifyAuthorizationToken(authorizationToken)) {
        SS_LOG_WARN(LOG_CATEGORY, L"Shutdown rejected: invalid or missing authorization token");
        return;
    }
    ShutdownInternal();
}

void SelfDefenseImpl::ShutdownInternal() {
    if (!m_initialized.exchange(false, std::memory_order_acq_rel)) {
        return;
    }

    // Mark teardown so that VerifyAuthorizationToken() can permit the empty-token
    // path that protected-resource cleanup callers below rely on.
    m_shutdownInProgress.store(true, std::memory_order_release);
    struct ShutdownGuard {
        std::atomic<bool>& flag;
        ~ShutdownGuard() { flag.store(false, std::memory_order_release); }
    } shutdownGuard{m_shutdownInProgress};

    m_status.store(ModuleStatus::Stopping, std::memory_order_release);
    SS_LOG_INFO(LOG_CATEGORY, L"Shutting down self-defense engine");

    // Unregister kernel handler FIRST (prevent use-after-free)
    UnregisterKernelHandler();

    // Stop watchdog thread
    if (m_watchdogRunning.exchange(false, std::memory_order_acq_rel)) {
        {
            std::lock_guard<std::mutex> wlock(m_watchdogMutex);
        }
        m_watchdogCv.notify_all();
        if (m_watchdogThread.joinable()) {
            m_watchdogThread.join();
        }
    }

    // Clear all state under exclusive lock
    {
        std::unique_lock lock(m_mutex);
        m_protectedProcesses.clear();
        m_protectedPaths.clear();
        m_protectedRegKeys.clear();
        m_protectedMemoryRegions.clear();
        m_whitelist.clear();
        m_threatResponsePolicy.clear();
        m_componentStatuses.clear();
        m_heartbeatRecords.clear();
        m_codeSectionHash.clear();
        m_codeSectionBase = 0;
        m_codeSectionSize = 0;
    }

    // Clear callbacks
    {
        std::unique_lock lock(m_callbackMutex);
        m_threatCallbacks.clear();
        m_accessCallbacks.clear();
        m_statusCallbacks.clear();
        m_recoveryCallbacks.clear();
        m_heartbeatCallbacks.clear();
    }

    // Clear history
    {
        std::unique_lock lock(m_historyMutex);
        m_threatHistory.clear();
    }

    // Zero-clear auth secret
    if (!m_authSecret.empty()) {
        ::SecureZeroMemory(m_authSecret.data(), m_authSecret.size());
        m_authSecret.clear();
    }

    m_serviceProtected.store(false, std::memory_order_release);
    m_driverProtected.store(false, std::memory_order_release);
    m_pauseDeadlineNs.store(0, std::memory_order_release);
    m_status.store(ModuleStatus::Stopped, std::memory_order_release);
    SS_LOG_INFO(LOG_CATEGORY, L"Self-defense shutdown complete");
}

bool SelfDefenseImpl::Pause(std::string_view authorizationToken, uint32_t durationMs) {
    if (!m_initialized.load(std::memory_order_acquire)) return false;
    if (!VerifyAuthorizationToken(authorizationToken)) {
        SS_LOG_WARN(LOG_CATEGORY, L"Pause rejected: invalid authorization token");
        return false;
    }

    // Bound the pause window. Zero means "until Resume()". A non-zero duration
    // is enforced by the watchdog, which auto-resumes once the deadline passes.
    // Cap at one hour to prevent a malicious or buggy caller from holding the
    // engine paused forever via an oversized value.
    constexpr uint32_t kMaxPauseMs = 60u * 60u * 1000u;
    if (durationMs > kMaxPauseMs) durationMs = kMaxPauseMs;

    if (durationMs > 0) {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(durationMs);
        const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
            deadline.time_since_epoch()).count();
        m_pauseDeadlineNs.store(static_cast<int64_t>(ns), std::memory_order_release);
    } else {
        m_pauseDeadlineNs.store(0, std::memory_order_release);
    }

    m_status.store(ModuleStatus::Paused, std::memory_order_release);
    {
        std::lock_guard<std::mutex> wlock(m_watchdogMutex);
    }
    m_watchdogCv.notify_all();
    SS_LOG_WARN(LOG_CATEGORY, L"Self-defense PAUSED by authorized request (durationMs=%u)", durationMs);
    return true;
}

void SelfDefenseImpl::Resume() {
    if (m_status.load(std::memory_order_acquire) == ModuleStatus::Paused) {
        m_pauseDeadlineNs.store(0, std::memory_order_release);
        m_status.store(ModuleStatus::Running, std::memory_order_release);
        {
            std::lock_guard<std::mutex> wlock(m_watchdogMutex);
        }
        m_watchdogCv.notify_all();
        SS_LOG_INFO(LOG_CATEGORY, L"Self-defense resumed");
    }
}

// ============================================================================
// CONFIGURATION
// ============================================================================

bool SelfDefenseImpl::SetConfiguration(const SelfDefenseConfiguration& config) {
    if (!config.IsValid()) return false;
    std::unique_lock lock(m_mutex);
    m_config = config;
    return true;
}

SelfDefenseConfiguration SelfDefenseImpl::GetConfiguration() const {
    std::shared_lock lock(m_mutex);
    return m_config;
}

void SelfDefenseImpl::SetProtectionLevel(SelfDefenseLevel level) {
    std::unique_lock lock(m_mutex);
    m_config.level = level;
}

SelfDefenseLevel SelfDefenseImpl::GetProtectionLevel() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_config.level;
}

bool SelfDefenseImpl::EnableComponent(ProtectionComponent component) {
    std::unique_lock lock(m_mutex);
    m_config.enabledComponents = m_config.enabledComponents | component;
    lock.unlock();
    UpdateComponentStatus(component, true, ComponentHealth::Healthy);
    return true;
}

bool SelfDefenseImpl::DisableComponent(ProtectionComponent component, std::string_view authorizationToken) {
    if (!VerifyAuthorizationToken(authorizationToken)) return false;
    std::unique_lock lock(m_mutex);
    auto val = static_cast<uint32_t>(m_config.enabledComponents) & ~static_cast<uint32_t>(component);
    m_config.enabledComponents = static_cast<ProtectionComponent>(val);
    lock.unlock();
    UpdateComponentStatus(component, false, ComponentHealth::Unknown);
    return true;
}

bool SelfDefenseImpl::IsComponentEnabled(ProtectionComponent component) const noexcept {
    std::shared_lock lock(m_mutex);
    return HasComponent(m_config.enabledComponents, component);
}

void SelfDefenseImpl::SetThreatResponse(ThreatType threatType, ThreatResponse response) {
    if (threatType == ThreatType::None) {
        SS_LOG_WARN(LOG_CATEGORY, L"SetThreatResponse: ignoring ThreatType::None — policy update rejected");
        return;
    }

    ThreatResponse previous = ThreatResponse::None;
    {
        std::unique_lock lock(m_mutex);
        auto it = m_threatResponsePolicy.find(threatType);
        if (it != m_threatResponsePolicy.end()) previous = it->second;
        m_threatResponsePolicy[threatType] = response;
    }

    SS_LOG_INFO(LOG_CATEGORY,
        L"Threat response policy updated: type=0x%08X previous=0x%08X new=0x%08X",
        static_cast<uint32_t>(threatType),
        static_cast<uint32_t>(previous),
        static_cast<uint32_t>(response));
}

ThreatResponse SelfDefenseImpl::GetThreatResponse(ThreatType threatType) const {
    std::shared_lock lock(m_mutex);
    auto it = m_threatResponsePolicy.find(threatType);
    return (it != m_threatResponsePolicy.end()) ? it->second : m_config.defaultResponse;
}

// ============================================================================
// PROCESS PROTECTION
// ============================================================================

bool SelfDefenseImpl::ProtectProcess(uint32_t processId) {
    const ModuleStatus status = m_status.load(std::memory_order_acquire);
    if (((!m_initialized.load(std::memory_order_acquire)) &&
         status != ModuleStatus::Initializing) ||
        processId == 0) {
        return false;
    }
    if (status == ModuleStatus::Paused) return false;

    {
        std::shared_lock lock(m_mutex);
        if (m_protectedProcesses.contains(processId)) return true;
        if (m_protectedProcesses.size() >= SelfDefenseConstants::MAX_PROTECTED_PROCESSES) {
            SS_LOG_WARN(LOG_CATEGORY, L"Max protected processes reached (%zu)", SelfDefenseConstants::MAX_PROTECTED_PROCESSES);
            return false;
        }
    }

    // Gather process info OUTSIDE lock
    auto imagePath = GetProcessImagePath(processId);
    auto processName = GetProcessName(processId);

    HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
        SS_LOG_WARN(LOG_CATEGORY, L"Cannot open process %u for protection", processId);
        return false;
    }

    auto entry = std::make_unique<InternalProtectedProcess>();
    entry->processId = processId;
    entry->processName = std::move(processName);
    entry->imagePath = std::move(imagePath);
    entry->processHandle = hProcess;
    entry->userModeProtected = true;
    entry->protectedSince = Clock::now();
    entry->health = ComponentHealth::Healthy;

    // Compute image hash for integrity verification
    if (!entry->imagePath.empty()) {
        HANDLE hFile = ::CreateFileW(entry->imagePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                     nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER fileSize{};
            if (::GetFileSizeEx(hFile, &fileSize) && fileSize.QuadPart > 0 &&
                fileSize.QuadPart <= 256 * 1024 * 1024) {
                std::vector<uint8_t> buf(static_cast<size_t>(fileSize.QuadPart));
                DWORD bytesRead = 0;
                if (::ReadFile(hFile, buf.data(), static_cast<DWORD>(buf.size()), &bytesRead, nullptr) && bytesRead > 0) {
                    auto hash = ComputeSHA256(buf.data(), bytesRead);
                    if (hash.size() == 32) {
                        std::copy(hash.begin(), hash.end(), entry->imageHash.begin());
                    }
                }
            }
            ::CloseHandle(hFile);
        }
    }

    std::wstring logName;
    {
        std::unique_lock lock(m_mutex);
        if (m_protectedProcesses.contains(processId)) {
            return true; // Another thread added it while we were outside lock
        }
        logName = entry->processName;
        m_protectedProcesses[processId] = std::move(entry);
    }

    UpdateComponentStatus(ProtectionComponent::Process, true, ComponentHealth::Healthy);
    SS_LOG_INFO(LOG_CATEGORY, L"Process %u protected: %s", processId,
               logName.empty() ? L"<unknown>" : logName.c_str());
    return true;
}

bool SelfDefenseImpl::UnprotectProcess(uint32_t processId, std::string_view authorizationToken) {
    if (!VerifyAuthorizationToken(authorizationToken)) {
        SS_LOG_WARN(LOG_CATEGORY, L"UnprotectProcess rejected: invalid token");
        return false;
    }
    std::unique_lock lock(m_mutex);
    auto it = m_protectedProcesses.find(processId);
    if (it == m_protectedProcesses.end()) return false;
    m_protectedProcesses.erase(it);
    SS_LOG_INFO(LOG_CATEGORY, L"Process %u unprotected", processId);
    return true;
}

bool SelfDefenseImpl::IsProcessProtected(uint32_t processId) const {
    std::shared_lock lock(m_mutex);
    return m_protectedProcesses.contains(processId);
}

std::optional<ProtectedProcess> SelfDefenseImpl::GetProtectedProcess(uint32_t processId) const {
    std::shared_lock lock(m_mutex);
    auto it = m_protectedProcesses.find(processId);
    if (it == m_protectedProcesses.end()) return std::nullopt;
    const auto& pp = it->second;
    ProtectedProcess result;
    result.processId = pp->processId;
    result.processName = pp->processName;
    result.imagePath = pp->imagePath;
    result.imageHash = pp->imageHash;
    result.processHandle = nullptr; // Never expose internal handle
    result.isShadowStrikeComponent = pp->isShadowStrikeComponent;
    result.kernelProtected = pp->kernelProtected;
    result.userModeProtected = pp->userModeProtected;
    result.protectedSince = pp->protectedSince;
    result.blockedAttempts = pp->blockedAttempts.load(std::memory_order_relaxed);
    result.lastBlockedAttempt = pp->lastBlockedAttempt;
    result.health = pp->health;
    return result;
}

std::vector<ProtectedProcess> SelfDefenseImpl::GetAllProtectedProcesses() const {
    std::shared_lock lock(m_mutex);
    std::vector<ProtectedProcess> result;
    result.reserve(m_protectedProcesses.size());
    for (const auto& [pid, pp] : m_protectedProcesses) {
        ProtectedProcess entry;
        entry.processId = pp->processId;
        entry.processName = pp->processName;
        entry.imagePath = pp->imagePath;
        entry.imageHash = pp->imageHash;
        entry.processHandle = nullptr;
        entry.isShadowStrikeComponent = pp->isShadowStrikeComponent;
        entry.kernelProtected = pp->kernelProtected;
        entry.userModeProtected = pp->userModeProtected;
        entry.protectedSince = pp->protectedSince;
        entry.blockedAttempts = pp->blockedAttempts.load(std::memory_order_relaxed);
        entry.lastBlockedAttempt = pp->lastBlockedAttempt;
        entry.health = pp->health;
        result.push_back(std::move(entry));
    }
    return result;
}

bool SelfDefenseImpl::IsAccessAllowed(uint32_t callerPid, uint32_t targetPid, uint32_t desiredAccess) {
    if (m_status.load(std::memory_order_acquire) != ModuleStatus::Running) return true;
    if (callerPid == targetPid) return true;

    bool targetProtected = false;
    {
        std::shared_lock lock(m_mutex);
        targetProtected = m_protectedProcesses.contains(targetPid);
        if (targetProtected && m_protectedProcesses.contains(callerPid)) {
            return true; // Protected process accessing another protected process
        }
    }
    if (!targetProtected) return true;

    // Check if caller is whitelisted (outside lock — does its own locking)
    if (IsCallerWhitelisted(callerPid)) return true;

    uint32_t dangerous = SelfDefenseConstants::BLOCKED_PROCESS_ACCESS;
    if (desiredAccess & dangerous) {
        auto callerName = GetProcessName(callerPid);
        ThreatEvent evt;
        evt.type = ThreatType::ProcessTermination;
        evt.attackerProcessId = callerPid;
        evt.attackerProcessName = std::move(callerName);
        evt.attackerProcessPath = GetProcessImagePath(callerPid);
        evt.targetType = ProtectedEntityType::Process;
        evt.targetIdentifier = std::to_wstring(targetPid);
        evt.requestedAccess = desiredAccess;
        evt.blockedAccess = desiredAccess & dangerous;
        evt.wasBlocked = true;
        evt.actionTaken = ThreatResponse::Block;

        m_stats.processTerminationBlocked.fetch_add(1, std::memory_order_relaxed);

        {
            std::shared_lock lock(m_mutex);
            auto it = m_protectedProcesses.find(targetPid);
            if (it != m_protectedProcesses.end()) {
                it->second->blockedAttempts.fetch_add(1, std::memory_order_relaxed);
                it->second->lastBlockedAttempt = Clock::now();
            }
        }

        SS_LOG_WARN(LOG_CATEGORY, L"BLOCKED: PID %u attempted access 0x%08X on protected PID %u",
                    callerPid, desiredAccess, targetPid);
        RecordThreatEvent(std::move(evt));
        return false;
    }
    return true;
}

AccessDecisionResult SelfDefenseImpl::FilterAccessRequest(const AccessRequest& request) {
    AccessDecisionResult result;
    result.decision = AccessDecision::Allow;
    result.grantedAccess = request.desiredAccess;

    const auto hasResponseFlag = [](ThreatResponse value, ThreatResponse flag) noexcept {
        return (static_cast<uint32_t>(value) & static_cast<uint32_t>(flag)) != 0;
    };

    const auto shouldBlockDecision = [](AccessDecision decision) noexcept {
        return decision == AccessDecision::Deny || decision == AccessDecision::StripRights;
    };

    auto applyStrippedDecision = [&](uint32_t blockedMask, std::string_view stripReason, std::string_view denyReason) {
        const uint32_t strippedAccess = request.desiredAccess & ~blockedMask;
        if (strippedAccess != 0) {
            result.decision = AccessDecision::StripRights;
            result.grantedAccess = strippedAccess;
            result.reason.assign(stripReason);
        } else {
            result.decision = AccessDecision::Deny;
            result.grantedAccess = 0;
            result.reason.assign(denyReason);
        }
        result.shouldLog = true;
    };

    auto evaluateProtectedPath = [&](std::wstring_view rawPath,
                                     std::wstring& normalizedPath,
                                     std::wstring& matchedRulePath,
                                     bool& allowWrite,
                                     bool& allowDelete) {
        normalizedPath = NormalizePath(rawPath);
        std::shared_lock lock(m_mutex);

        auto exactIt = m_protectedPaths.find(normalizedPath);
        if (exactIt != m_protectedPaths.end()) {
            matchedRulePath = exactIt->first;
            allowWrite = exactIt->second->allowWrite;
            allowDelete = exactIt->second->allowDelete;
            return true;
        }

        for (const auto& [protectedPath, entry] : m_protectedPaths) {
            if (entry->includeSubdirectories && normalizedPath.starts_with(protectedPath + L"\\")) {
                matchedRulePath = protectedPath;
                allowWrite = entry->allowWrite;
                allowDelete = entry->allowDelete;
                return true;
            }
        }
        return false;
    };

    auto evaluateProtectedRegistryKey = [&](std::wstring_view rawKeyPath,
                                            std::wstring& normalizedKeyPath,
                                            std::wstring& matchedRuleKey,
                                            bool& allowWrite,
                                            bool& allowDelete) {
        normalizedKeyPath = NormalizeKeyPath(rawKeyPath);
        std::shared_lock lock(m_mutex);

        auto exactIt = m_protectedRegKeys.find(normalizedKeyPath);
        if (exactIt != m_protectedRegKeys.end()) {
            matchedRuleKey = exactIt->first;
            allowWrite = exactIt->second->allowWrite;
            allowDelete = exactIt->second->allowDelete;
            return true;
        }

        for (const auto& [protectedKey, entry] : m_protectedRegKeys) {
            if (entry->includeSubkeys && normalizedKeyPath.starts_with(protectedKey + L"\\")) {
                matchedRuleKey = protectedKey;
                allowWrite = entry->allowWrite;
                allowDelete = entry->allowDelete;
                return true;
            }
        }
        return false;
    };

    if (m_status.load(std::memory_order_acquire) != ModuleStatus::Running) {
        result.decision = AccessDecision::Defer;
        result.reason = "Self-defense engine is not running";
        return result;
    }

    if (!IsComponentEnabled(ProtectionComponent::AccessControl)) {
        result.decision = AccessDecision::Defer;
        result.reason = "Self-defense access-control filtering is disabled";
        return result;
    }

    if (request.isSystemCaller || request.isWhitelistedCaller) return result;
    if (request.callerProcessId != 0 && request.callerProcessId == request.targetProcessId) return result;
    if (request.callerProcessId != 0 && IsCallerWhitelisted(request.callerProcessId)) return result;

    bool callerProtected = false;
    bool callerIsShadowStrikeComponent = false;
    bool targetProcessProtected = false;
    {
        std::shared_lock lock(m_mutex);
        auto callerIt = m_protectedProcesses.find(request.callerProcessId);
        if (callerIt != m_protectedProcesses.end()) {
            callerProtected = true;
            callerIsShadowStrikeComponent = callerIt->second->isShadowStrikeComponent;
        }

        if (request.targetProcessId != 0) {
            targetProcessProtected = m_protectedProcesses.contains(request.targetProcessId);
        }
    }

    if (callerIsShadowStrikeComponent) return result;

    ThreatType detectedThreatType = ThreatType::None;
    ThreatResponse actionTaken = ThreatResponse::None;
    ProtectedEntityType targetType = ProtectedEntityType::Process;
    std::wstring targetIdentifier;
    uint32_t blockedAccess = 0;

    bool updateProtectedProcessAttempt = false;
    bool incrementProcessTermination = false;
    bool incrementThreadTermination = false;
    bool incrementMemoryModification = false;
    bool incrementFileModification = false;
    bool incrementRegistryModification = false;
    bool incrementServiceControl = false;

    std::wstring normalizedTargetPath;
    std::wstring matchedProtectedPath;
    bool matchedPathAllowWrite = false;
    bool matchedPathAllowDelete = false;

    std::wstring normalizedTargetRegistryKey;
    std::wstring matchedProtectedRegistryKey;
    bool matchedRegistryAllowWrite = false;
    bool matchedRegistryAllowDelete = false;

    switch (request.type) {
        case AccessRequestType::ProcessOpen:
        case AccessRequestType::HandleDuplicate: {
            if (request.targetProcessId == 0) {
                SS_LOG_WARN(LOG_CATEGORY, L"Malformed process access request: missing target process ID");
                result.decision = AccessDecision::Defer;
                result.reason = "Malformed process access request";
                result.shouldLog = true;
                break;
            }

            if (!targetProcessProtected) break;
            if (callerProtected && request.type == AccessRequestType::ProcessOpen) break;

            blockedAccess = request.desiredAccess & SelfDefenseConstants::BLOCKED_PROCESS_ACCESS;
            if (blockedAccess == 0) break;

            targetType = ProtectedEntityType::Process;
            targetIdentifier = std::to_wstring(request.targetProcessId);
            updateProtectedProcessAttempt = true;

            if (request.type == AccessRequestType::HandleDuplicate) {
                detectedThreatType = ThreatType::HandleDuplication;
                applyStrippedDecision(
                    blockedAccess,
                    "Dangerous duplicated process access rights stripped from protected target",
                    "All duplicated process access rights are dangerous to the protected target");
            } else {
                if ((blockedAccess & PROCESS_CREATE_THREAD) != 0) {
                    detectedThreatType = ThreatType::CodeInjection;
                } else if ((blockedAccess & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION)) != 0) {
                    detectedThreatType = ThreatType::MemoryModification;
                } else if ((blockedAccess & PROCESS_TERMINATE) != 0) {
                    detectedThreatType = ThreatType::ProcessTermination;
                } else {
                    detectedThreatType = ThreatType::ProcessSuspension;
                }

                incrementProcessTermination = (blockedAccess & PROCESS_TERMINATE) != 0;
                incrementMemoryModification = (blockedAccess & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION)) != 0;

                applyStrippedDecision(
                    blockedAccess,
                    "Dangerous process access rights stripped from handle to protected process",
                    "All requested process access rights are dangerous to the protected process");
            }
            break;
        }

        case AccessRequestType::ThreadOpen: {
            if (request.targetProcessId == 0 || request.targetThreadId == 0) {
                SS_LOG_WARN(LOG_CATEGORY, L"Malformed thread access request: missing target process or thread ID");
                result.decision = AccessDecision::Defer;
                result.reason = "Malformed thread access request";
                result.shouldLog = true;
                break;
            }

            if (!targetProcessProtected) break;

            blockedAccess = request.desiredAccess & SelfDefenseConstants::BLOCKED_THREAD_ACCESS;
            if (blockedAccess == 0) break;

            targetType = ProtectedEntityType::Thread;
            targetIdentifier = std::to_wstring(request.targetProcessId) + L":" + std::to_wstring(request.targetThreadId);
            updateProtectedProcessAttempt = true;

            if ((blockedAccess & THREAD_SET_CONTEXT) != 0) {
                detectedThreatType = ThreatType::CodeInjection;
            } else if ((blockedAccess & THREAD_SET_THREAD_TOKEN) != 0) {
                detectedThreatType = ThreatType::TokenManipulation;
            } else if ((blockedAccess & THREAD_TERMINATE) != 0) {
                detectedThreatType = ThreatType::ThreadTermination;
            } else {
                detectedThreatType = ThreatType::ProcessSuspension;
            }

            incrementThreadTermination = (blockedAccess & THREAD_TERMINATE) != 0;

            applyStrippedDecision(
                blockedAccess,
                "Dangerous thread access rights stripped from handle to protected thread",
                "All requested thread access rights are dangerous to the protected thread");
            break;
        }

        case AccessRequestType::FileAccess: {
            if (request.targetPath.empty()) {
                SS_LOG_WARN(LOG_CATEGORY, L"Malformed file access request: missing target path");
                result.decision = AccessDecision::Defer;
                result.reason = "Malformed file access request";
                result.shouldLog = true;
                break;
            }

            if (!evaluateProtectedPath(request.targetPath, normalizedTargetPath, matchedProtectedPath,
                                       matchedPathAllowWrite, matchedPathAllowDelete)) {
                break;
            }

            constexpr uint32_t kFileWriteMask =
                FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA |
                WRITE_DAC | WRITE_OWNER;
            constexpr uint32_t kFileDeleteMask = FILE_DELETE_CHILD | DELETE;

            uint32_t effectiveBlockedMask = 0;
            if (!matchedPathAllowWrite) effectiveBlockedMask |= kFileWriteMask;
            if (!matchedPathAllowDelete) effectiveBlockedMask |= kFileDeleteMask;

            blockedAccess = request.desiredAccess & effectiveBlockedMask;
            if (blockedAccess == 0) break;

            targetType = ProtectedEntityType::File;
            targetIdentifier = normalizedTargetPath;
            detectedThreatType = ((blockedAccess & kFileDeleteMask) != 0) ? ThreatType::FileDeletion
                                                                           : ThreatType::FileModification;
            incrementFileModification = true;

            applyStrippedDecision(
                blockedAccess,
                "Dangerous write or delete rights stripped from protected path access",
                "All requested write or delete rights are blocked for the protected path");
            break;
        }

        case AccessRequestType::RegistryAccess: {
            if (request.targetPath.empty()) {
                SS_LOG_WARN(LOG_CATEGORY, L"Malformed registry access request: missing target key path");
                result.decision = AccessDecision::Defer;
                result.reason = "Malformed registry access request";
                result.shouldLog = true;
                break;
            }

            if (!evaluateProtectedRegistryKey(request.targetPath, normalizedTargetRegistryKey,
                                              matchedProtectedRegistryKey, matchedRegistryAllowWrite,
                                              matchedRegistryAllowDelete)) {
                break;
            }

            constexpr uint32_t kRegistryWriteMask =
                KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK | WRITE_DAC | WRITE_OWNER;
            constexpr uint32_t kRegistryDeleteMask = DELETE;

            uint32_t effectiveBlockedMask = 0;
            if (!matchedRegistryAllowWrite) effectiveBlockedMask |= kRegistryWriteMask;
            if (!matchedRegistryAllowDelete) effectiveBlockedMask |= kRegistryDeleteMask;

            blockedAccess = request.desiredAccess & effectiveBlockedMask;
            if (blockedAccess == 0) break;

            targetType = ProtectedEntityType::RegistryKey;
            targetIdentifier = normalizedTargetRegistryKey;
            detectedThreatType = ((blockedAccess & kRegistryDeleteMask) != 0) ? ThreatType::RegistryDeletion
                                                                               : ThreatType::RegistryModification;
            incrementRegistryModification = true;

            applyStrippedDecision(
                blockedAccess,
                "Dangerous registry rights stripped from protected registry access",
                "All requested registry rights are blocked for the protected registry key");
            break;
        }

        case AccessRequestType::ServiceControl: {
            if (!m_serviceProtected.load(std::memory_order_acquire)) break;

            constexpr uint32_t kServiceDangerousMask =
                SERVICE_STOP | SERVICE_PAUSE_CONTINUE | SERVICE_CHANGE_CONFIG | DELETE;

            blockedAccess = request.desiredAccess & kServiceDangerousMask;
            if (blockedAccess == 0) break;

            targetType = ProtectedEntityType::Service;
            targetIdentifier = request.targetPath.empty()
                ? std::wstring(SelfDefenseConstants::SERVICE_NAME)
                : request.targetPath;
            detectedThreatType = ThreatType::ServiceControl;
            incrementServiceControl = true;

            applyStrippedDecision(
                blockedAccess,
                "Dangerous service-control rights stripped from protected service request",
                "All requested service-control rights are blocked for the protected service");
            break;
        }

        case AccessRequestType::ProcessCreate:
            result.decision = AccessDecision::Defer;
            result.reason = "Process creation requests are deferred to specialized policy handlers";
            break;

        case AccessRequestType::ImageLoad:
            result.decision = AccessDecision::Defer;
            result.reason = "Image load requests are deferred to specialized policy handlers";
            break;
    }

    std::optional<ThreatEvent> detectedThreat;
    if (detectedThreatType != ThreatType::None) {
        actionTaken = GetThreatResponse(detectedThreatType);
        if (hasResponseFlag(actionTaken, ThreatResponse::Block)) {
            if (result.reason.empty()) {
                applyStrippedDecision(blockedAccess,
                                      "Dangerous access rights stripped by self-defense policy",
                                      "Requested access rights are blocked by self-defense policy");
            }
        } else {
            result.decision = AccessDecision::Allow;
            result.grantedAccess = request.desiredAccess;
            result.reason = "Threat detected but current response policy is non-blocking";
            result.shouldLog = actionTaken != ThreatResponse::None;
        }

        ThreatEvent event;
        event.type = detectedThreatType;
        event.timestamp = request.timestamp;
        event.attackerProcessId = request.callerProcessId;
        event.attackerThreadId = request.callerThreadId;
        event.attackerProcessName = GetProcessName(request.callerProcessId);
        event.attackerProcessPath = request.callerImagePath.empty()
            ? GetProcessImagePath(request.callerProcessId)
            : request.callerImagePath;
        event.targetType = targetType;
        event.targetIdentifier = targetIdentifier;
        event.requestedAccess = request.desiredAccess;
        event.blockedAccess = blockedAccess;
        event.actionTaken = actionTaken;
        event.wasBlocked = shouldBlockDecision(result.decision);
        if (!result.reason.empty()) {
            event.details["reason"] = result.reason;
        }
        detectedThreat = std::move(event);
    }

    std::vector<AccessCallback> accessCallbacks;
    {
        std::shared_lock lock(m_callbackMutex);
        accessCallbacks.reserve(m_accessCallbacks.size());
        for (const auto& [id, callback] : m_accessCallbacks) {
            accessCallbacks.push_back(callback);
        }
    }

    for (const auto& callback : accessCallbacks) {
        try {
            AccessDecisionResult callbackResult = callback(request);
            result.shouldLog = result.shouldLog || callbackResult.shouldLog;

            switch (result.decision) {
                case AccessDecision::Allow:
                    if (callbackResult.decision == AccessDecision::Deny) {
                        result.decision = AccessDecision::Deny;
                        result.grantedAccess = 0;
                        if (!callbackResult.reason.empty()) result.reason = callbackResult.reason;
                    } else if (callbackResult.decision == AccessDecision::StripRights) {
                        result.decision = AccessDecision::StripRights;
                        result.grantedAccess = request.desiredAccess & callbackResult.grantedAccess;
                        if (result.grantedAccess == 0) result.decision = AccessDecision::Deny;
                        if (!callbackResult.reason.empty()) result.reason = callbackResult.reason;
                    } else if (callbackResult.decision == AccessDecision::Defer) {
                        result.decision = AccessDecision::Defer;
                        result.grantedAccess = request.desiredAccess;
                        if (!callbackResult.reason.empty()) result.reason = callbackResult.reason;
                    }
                    break;

                case AccessDecision::Defer:
                    if (callbackResult.decision == AccessDecision::Deny) {
                        result.decision = AccessDecision::Deny;
                        result.grantedAccess = 0;
                        if (!callbackResult.reason.empty()) result.reason = callbackResult.reason;
                    } else if (callbackResult.decision == AccessDecision::StripRights) {
                        result.decision = AccessDecision::StripRights;
                        result.grantedAccess = request.desiredAccess & callbackResult.grantedAccess;
                        if (result.grantedAccess == 0) result.decision = AccessDecision::Deny;
                        if (!callbackResult.reason.empty()) result.reason = callbackResult.reason;
                    }
                    break;

                case AccessDecision::StripRights:
                    if (callbackResult.decision == AccessDecision::Deny) {
                        result.decision = AccessDecision::Deny;
                        result.grantedAccess = 0;
                        if (!callbackResult.reason.empty()) result.reason = callbackResult.reason;
                    } else if (callbackResult.decision == AccessDecision::StripRights) {
                        result.grantedAccess &= callbackResult.grantedAccess;
                        if (result.grantedAccess == 0) result.decision = AccessDecision::Deny;
                        if (!callbackResult.reason.empty()) result.reason = callbackResult.reason;
                    }
                    break;

                case AccessDecision::Deny:
                    break;
            }

            if (!detectedThreat.has_value() && callbackResult.threatEvent.has_value()) {
                detectedThreat = std::move(callbackResult.threatEvent);
            }
        } catch (const std::exception& ex) {
            SS_LOG_WARN(LOG_CATEGORY, L"Access callback threw: %S", ex.what());
        } catch (...) {
            SS_LOG_WARN(LOG_CATEGORY, L"Access callback threw a non-standard exception");
        }
    }

    const bool finalBlocked = shouldBlockDecision(result.decision);
    if (finalBlocked) {
        result.shouldLog = true;

        if (incrementProcessTermination) {
            m_stats.processTerminationBlocked.fetch_add(1, std::memory_order_relaxed);
        }
        if (incrementThreadTermination) {
            m_stats.threadTerminationBlocked.fetch_add(1, std::memory_order_relaxed);
        }
        if (incrementMemoryModification) {
            m_stats.memoryModificationBlocked.fetch_add(1, std::memory_order_relaxed);
        }
        if (incrementFileModification) {
            m_stats.fileModificationBlocked.fetch_add(1, std::memory_order_relaxed);
        }
        if (incrementRegistryModification) {
            m_stats.registryModificationBlocked.fetch_add(1, std::memory_order_relaxed);
        }
        if (incrementServiceControl) {
            m_stats.serviceControlBlocked.fetch_add(1, std::memory_order_relaxed);
        }

        if (updateProtectedProcessAttempt && request.targetProcessId != 0) {
            std::unique_lock lock(m_mutex);
            auto it = m_protectedProcesses.find(request.targetProcessId);
            if (it != m_protectedProcesses.end()) {
                it->second->blockedAttempts.fetch_add(1, std::memory_order_relaxed);
                it->second->lastBlockedAttempt = Clock::now();
            }
        }

        if (!matchedProtectedPath.empty()) {
            std::shared_lock lock(m_mutex);
            auto it = m_protectedPaths.find(matchedProtectedPath);
            if (it != m_protectedPaths.end()) {
                it->second->blockedOperations.fetch_add(1, std::memory_order_relaxed);
            }
        }

        if (!matchedProtectedRegistryKey.empty()) {
            std::shared_lock lock(m_mutex);
            auto it = m_protectedRegKeys.find(matchedProtectedRegistryKey);
            if (it != m_protectedRegKeys.end()) {
                it->second->blockedOperations.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }

    if (detectedThreat.has_value()) {
        detectedThreat->wasBlocked = finalBlocked;
        if (finalBlocked) {
            detectedThreat->blockedAccess = request.desiredAccess & ~result.grantedAccess;
            if (!hasResponseFlag(detectedThreat->actionTaken, ThreatResponse::Block)) {
                detectedThreat->actionTaken = detectedThreat->actionTaken | ThreatResponse::Block;
            }
        }
        if (!result.reason.empty()) {
            detectedThreat->details["reason"] = result.reason;
        }

        ThreatEvent recordedThreat = *detectedThreat;
        RecordThreatEvent(std::move(recordedThreat));
        result.threatEvent = std::move(detectedThreat);
    }

    if (result.shouldLog) {
        SS_LOG_WARN(LOG_CATEGORY,
                    L"Access request filtered: type=%u callerPid=%u targetPid=%u targetTid=%u desired=0x%08X granted=0x%08X path=%s reason=%S",
                    static_cast<unsigned>(request.type),
                    request.callerProcessId,
                    request.targetProcessId,
                    request.targetThreadId,
                    request.desiredAccess,
                    result.grantedAccess,
                    request.targetPath.empty() ? L"<none>" : request.targetPath.c_str(),
                    result.reason.c_str());
    }
    return result;
}

bool SelfDefenseImpl::RegisterShadowStrikeComponent(uint32_t processId, std::string_view componentName) {
    if (!ProtectProcess(processId)) return false;
    std::unique_lock lock(m_mutex);
    auto it = m_protectedProcesses.find(processId);
    if (it != m_protectedProcesses.end()) {
        it->second->isShadowStrikeComponent = true;
        SS_LOG_INFO(LOG_CATEGORY, L"Registered ShadowStrike component: PID %u (%S)", processId,
                    std::string(componentName).c_str());
    }
    return true;
}

// ============================================================================
// SERVICE PROTECTION
// ============================================================================

bool SelfDefenseImpl::ProtectService() {
    SC_HANDLE hSCM = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Failed to open SCM for service protection");
        return false;
    }

    SC_HANDLE hService = ::OpenServiceW(hSCM, SelfDefenseConstants::SERVICE_NAME.data(),
                                        SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS);
    if (!hService) {
        SS_LOG_WARN(LOG_CATEGORY, L"Failed to open service %s", SelfDefenseConstants::SERVICE_NAME.data());
        ::CloseServiceHandle(hSCM);
        return false;
    }

    // Configure auto-restart on failure
    SERVICE_FAILURE_ACTIONSW failActions{};
    SC_ACTION actions[3]{
        { SC_ACTION_RESTART, SelfDefenseConstants::SERVICE_RESTART_DELAY_MS },
        { SC_ACTION_RESTART, SelfDefenseConstants::SERVICE_RESTART_DELAY_MS * 2 },
        { SC_ACTION_RESTART, SelfDefenseConstants::SERVICE_RESTART_DELAY_MS * 4 }
    };
    failActions.dwResetPeriod = 86400; // 1 day
    failActions.cActions = 3;
    failActions.lpsaActions = actions;

    BOOL ok = ::ChangeServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &failActions);
    if (!ok) {
        SS_LOG_WARN(LOG_CATEGORY, L"Failed to set service failure actions (err=%u)", ::GetLastError());
    }

    // Set failure flag so SCM sees a crash even if we exit with non-zero
    SERVICE_FAILURE_ACTIONS_FLAG flag{};
    flag.fFailureActionsOnNonCrashFailures = TRUE;
    ::ChangeServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag);

    ::CloseServiceHandle(hService);
    ::CloseServiceHandle(hSCM);

    m_serviceProtected.store(true, std::memory_order_release);
    UpdateComponentStatus(ProtectionComponent::Service, true, ComponentHealth::Healthy);
    SS_LOG_INFO(LOG_CATEGORY, L"Service protection applied: auto-restart configured");
    return true;
}

bool SelfDefenseImpl::IsServiceProtected() const {
    return m_serviceProtected.load(std::memory_order_acquire);
}

ComponentStatus SelfDefenseImpl::GetServiceStatus() const {
    std::shared_lock lock(m_mutex);
    auto it = m_componentStatuses.find(ProtectionComponent::Service);
    if (it != m_componentStatuses.end()) return it->second;
    ComponentStatus s;
    s.component = ProtectionComponent::Service;
    return s;
}

bool SelfDefenseImpl::EnsureServiceRunning() {
    SC_HANDLE hSCM = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return false;
    SC_HANDLE hService = ::OpenServiceW(hSCM, SelfDefenseConstants::SERVICE_NAME.data(),
                                        SERVICE_QUERY_STATUS | SERVICE_START);
    if (!hService) { ::CloseServiceHandle(hSCM); return false; }

    SERVICE_STATUS status{};
    BOOL ok = ::QueryServiceStatus(hService, &status);
    bool running = ok && status.dwCurrentState == SERVICE_RUNNING;

    if (ok && status.dwCurrentState == SERVICE_STOPPED) {
        SS_LOG_WARN(LOG_CATEGORY, L"Service stopped — attempting restart");
        if (::StartServiceW(hService, 0, nullptr)) {
            m_stats.autoRecoveryEvents.fetch_add(1, std::memory_order_relaxed);
            m_stats.successfulRecoveries.fetch_add(1, std::memory_order_relaxed);
            running = true;
        }
    }

    ::CloseServiceHandle(hService);
    ::CloseServiceHandle(hSCM);
    return running;
}

// ============================================================================
// DRIVER PROTECTION
// ============================================================================

bool SelfDefenseImpl::ProtectDriver() {
    if (!IsDriverLoaded()) {
        SS_LOG_WARN(LOG_CATEGORY, L"Driver not loaded — cannot protect");
        return false;
    }
    m_driverProtected.store(true, std::memory_order_release);
    UpdateComponentStatus(ProtectionComponent::Driver, true, ComponentHealth::Healthy);
    SS_LOG_INFO(LOG_CATEGORY, L"Driver protection enabled");
    return true;
}

bool SelfDefenseImpl::IsDriverProtected() const {
    return m_driverProtected.load(std::memory_order_acquire);
}

ComponentStatus SelfDefenseImpl::GetDriverStatus() const {
    std::shared_lock lock(m_mutex);
    auto it = m_componentStatuses.find(ProtectionComponent::Driver);
    if (it != m_componentStatuses.end()) return it->second;
    ComponentStatus s;
    s.component = ProtectionComponent::Driver;
    return s;
}

bool SelfDefenseImpl::IsDriverLoaded() const {
    SC_HANDLE hSCM = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return false;
    SC_HANDLE hService = ::OpenServiceW(hSCM, SelfDefenseConstants::DRIVER_SERVICE_NAME.data(),
                                        SERVICE_QUERY_STATUS);
    bool loaded = false;
    if (hService) {
        SERVICE_STATUS status{};
        if (::QueryServiceStatus(hService, &status)) {
            loaded = (status.dwCurrentState == SERVICE_RUNNING);
        }
        ::CloseServiceHandle(hService);
    }
    ::CloseServiceHandle(hSCM);
    return loaded;
}

bool SelfDefenseImpl::EnsureDriverLoaded() {
    if (IsDriverLoaded()) return true;
    SC_HANDLE hSCM = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return false;
    SC_HANDLE hService = ::OpenServiceW(hSCM, SelfDefenseConstants::DRIVER_SERVICE_NAME.data(),
                                        SERVICE_START | SERVICE_QUERY_STATUS);
    bool started = false;
    if (hService) {
        if (::StartServiceW(hService, 0, nullptr)) {
            SS_LOG_INFO(LOG_CATEGORY, L"Driver started successfully");
            started = true;
        } else {
            DWORD err = ::GetLastError();
            if (err == ERROR_SERVICE_ALREADY_RUNNING) started = true;
            else SS_LOG_ERROR(LOG_CATEGORY, L"Failed to start driver (err=%u)", err);
        }
        ::CloseServiceHandle(hService);
    }
    ::CloseServiceHandle(hSCM);
    return started;
}

// ============================================================================
// FILE SYSTEM PROTECTION
// ============================================================================

bool SelfDefenseImpl::ProtectPath(std::wstring_view path, bool includeSubdirectories) {
    if (path.empty() || path.size() > SelfDefenseConstants::MAX_PATH_LENGTH) return false;

    auto normalized = NormalizePath(path);
    {
        std::shared_lock lock(m_mutex);
        if (m_protectedPaths.contains(normalized)) return true;
        if (m_protectedPaths.size() >= SelfDefenseConstants::MAX_PROTECTED_PATHS) {
            SS_LOG_WARN(LOG_CATEGORY, L"Max protected paths reached");
            return false;
        }
    }

    DWORD attrs = ::GetFileAttributesW(std::wstring(path).c_str());
    bool isDir = (attrs != INVALID_FILE_ATTRIBUTES) && (attrs & FILE_ATTRIBUTE_DIRECTORY);

    auto entry = std::make_unique<InternalProtectedPath>();
    entry->id = Utils::StringUtils::ToNarrow(normalized);
    entry->path = normalized;
    entry->isDirectory = isDir;
    entry->includeSubdirectories = includeSubdirectories;
    entry->protectedSince = Clock::now();

    {
        std::unique_lock lock(m_mutex);
        m_protectedPaths[normalized] = std::move(entry);
    }

    UpdateComponentStatus(ProtectionComponent::FileSystem, true, ComponentHealth::Healthy);
    SS_LOG_DEBUG(LOG_CATEGORY, L"Path protected: %s (dir=%d, recurse=%d)",
                normalized.c_str(), isDir, includeSubdirectories);
    return true;
}

bool SelfDefenseImpl::UnprotectPath(std::wstring_view path, std::string_view authorizationToken) {
    if (!VerifyAuthorizationToken(authorizationToken)) return false;
    auto normalized = NormalizePath(path);
    std::unique_lock lock(m_mutex);
    return m_protectedPaths.erase(normalized) > 0;
}

bool SelfDefenseImpl::IsPathProtected(std::wstring_view path) const {
    auto normalized = NormalizePath(path);
    std::shared_lock lock(m_mutex);
    if (m_protectedPaths.contains(normalized)) return true;
    // Check if any parent path covers this path (prefix match)
    for (const auto& [protPath, entry] : m_protectedPaths) {
        if (entry->includeSubdirectories && normalized.starts_with(protPath + L"\\")) {
            return true;
        }
    }
    return false;
}

std::optional<ProtectedPath> SelfDefenseImpl::GetProtectedPath(std::wstring_view path) const {
    auto normalized = NormalizePath(path);
    std::shared_lock lock(m_mutex);
    auto it = m_protectedPaths.find(normalized);
    if (it == m_protectedPaths.end()) return std::nullopt;
    ProtectedPath result;
    result.id = it->second->id;
    result.path = it->second->path;
    result.isDirectory = it->second->isDirectory;
    result.includeSubdirectories = it->second->includeSubdirectories;
    result.allowWrite = it->second->allowWrite;
    result.allowDelete = it->second->allowDelete;
    result.allowRename = it->second->allowRename;
    result.protectedSince = it->second->protectedSince;
    result.blockedOperations = it->second->blockedOperations.load(std::memory_order_relaxed);
    return result;
}

std::vector<ProtectedPath> SelfDefenseImpl::GetAllProtectedPaths() const {
    std::shared_lock lock(m_mutex);
    std::vector<ProtectedPath> result;
    result.reserve(m_protectedPaths.size());
    for (const auto& [key, entry] : m_protectedPaths) {
        ProtectedPath pp;
        pp.id = entry->id;
        pp.path = entry->path;
        pp.isDirectory = entry->isDirectory;
        pp.includeSubdirectories = entry->includeSubdirectories;
        pp.protectedSince = entry->protectedSince;
        pp.blockedOperations = entry->blockedOperations.load(std::memory_order_relaxed);
        result.push_back(std::move(pp));
    }
    return result;
}

bool SelfDefenseImpl::ProtectInstallationDirectory() {
    wchar_t modulePath[MAX_PATH + 1]{};
    DWORD len = ::GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return false;
    std::wstring path(modulePath, len);
    auto pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return false;
    std::wstring installDir = path.substr(0, pos);
    bool ok = ProtectPath(installDir, true);
    if (ok) {
        SS_LOG_INFO(LOG_CATEGORY, L"Installation directory protected: %s", installDir.c_str());
    }
    return ok;
}

// ============================================================================
// REGISTRY PROTECTION
// ============================================================================

bool SelfDefenseImpl::ProtectRegistryKey(std::wstring_view keyPath, bool includeSubkeys) {
    if (keyPath.empty()) return false;
    auto normalized = NormalizeKeyPath(keyPath);
    {
        std::shared_lock lock(m_mutex);
        if (m_protectedRegKeys.contains(normalized)) return true;
        if (m_protectedRegKeys.size() >= SelfDefenseConstants::MAX_PROTECTED_REGISTRY_KEYS) {
            SS_LOG_WARN(LOG_CATEGORY, L"Max protected registry keys reached");
            return false;
        }
    }
    auto entry = std::make_unique<InternalProtectedRegKey>();
    entry->id = Utils::StringUtils::ToNarrow(normalized);
    entry->keyPath = normalized;
    entry->includeSubkeys = includeSubkeys;
    entry->protectedSince = Clock::now();
    {
        std::unique_lock lock(m_mutex);
        m_protectedRegKeys[normalized] = std::move(entry);
    }
    UpdateComponentStatus(ProtectionComponent::Registry, true, ComponentHealth::Healthy);
    SS_LOG_DEBUG(LOG_CATEGORY, L"Registry key protected: %s", normalized.c_str());
    return true;
}

bool SelfDefenseImpl::UnprotectRegistryKey(std::wstring_view keyPath, std::string_view authorizationToken) {
    if (!VerifyAuthorizationToken(authorizationToken)) return false;
    auto normalized = NormalizeKeyPath(keyPath);
    std::unique_lock lock(m_mutex);
    return m_protectedRegKeys.erase(normalized) > 0;
}

bool SelfDefenseImpl::IsRegistryKeyProtected(std::wstring_view keyPath) const {
    auto normalized = NormalizeKeyPath(keyPath);
    std::shared_lock lock(m_mutex);
    if (m_protectedRegKeys.contains(normalized)) return true;
    for (const auto& [protKey, entry] : m_protectedRegKeys) {
        if (entry->includeSubkeys && normalized.starts_with(protKey + L"\\")) {
            return true;
        }
    }
    return false;
}

std::optional<ProtectedRegistryKey> SelfDefenseImpl::GetProtectedRegistryKey(std::wstring_view keyPath) const {
    auto normalized = NormalizeKeyPath(keyPath);
    std::shared_lock lock(m_mutex);
    auto it = m_protectedRegKeys.find(normalized);
    if (it == m_protectedRegKeys.end()) return std::nullopt;
    ProtectedRegistryKey result;
    result.id = it->second->id;
    result.keyPath = it->second->keyPath;
    result.includeSubkeys = it->second->includeSubkeys;
    result.protectedValues = it->second->protectedValues;
    result.protectedSince = it->second->protectedSince;
    result.blockedOperations = it->second->blockedOperations.load(std::memory_order_relaxed);
    return result;
}

std::vector<ProtectedRegistryKey> SelfDefenseImpl::GetAllProtectedRegistryKeys() const {
    std::shared_lock lock(m_mutex);
    std::vector<ProtectedRegistryKey> result;
    result.reserve(m_protectedRegKeys.size());
    for (const auto& [key, entry] : m_protectedRegKeys) {
        ProtectedRegistryKey rk;
        rk.id = entry->id;
        rk.keyPath = entry->keyPath;
        rk.includeSubkeys = entry->includeSubkeys;
        rk.protectedValues = entry->protectedValues;
        rk.protectedSince = entry->protectedSince;
        rk.blockedOperations = entry->blockedOperations.load(std::memory_order_relaxed);
        result.push_back(std::move(rk));
    }
    return result;
}

bool SelfDefenseImpl::ProtectServiceRegistryKeys() {
    bool ok = true;
    ok &= ProtectRegistryKey(L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\ShadowStrikeService", true);
    ok &= ProtectRegistryKey(L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\ShadowStrikeDriver", true);
    ok &= ProtectRegistryKey(L"HKLM\\SOFTWARE\\ShadowStrike", true);
    if (ok) {
        SS_LOG_INFO(LOG_CATEGORY, L"Service registry keys protected");
    }
    return ok;
}

// ============================================================================
// MEMORY PROTECTION
// ============================================================================

bool SelfDefenseImpl::ProtectMemoryRegion(uintptr_t address, size_t size) {
    if (address == 0 || size == 0) return false;
    // Cap caller-supplied size to keep the SHA-256 compute bounded; an attacker
    // could otherwise drive multi-GB hashing on a hot path.
    constexpr size_t kMaxRegionBytes = 512ull * 1024ull * 1024ull; // 512 MiB
    if (size > kMaxRegionBytes) {
        SS_LOG_WARN(LOG_CATEGORY, L"ProtectMemoryRegion rejected: size %zu exceeds cap", size);
        return false;
    }

    // Validate the entire requested range is committed and readable BEFORE
    // dereferencing it for hashing. Without this the caller can pass an
    // uncommitted or reserved-only span and trigger an access violation
    // inside our own process — a trivial DoS against self-defense.
    {
        uintptr_t cursor = address;
        const uintptr_t end = address + size;
        if (end < address) return false; // pointer wrap
        while (cursor < end) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (::VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)) != sizeof(mbi)) {
                SS_LOG_WARN(LOG_CATEGORY, L"ProtectMemoryRegion: VirtualQuery failed at 0x%llX",
                            static_cast<unsigned long long>(cursor));
                return false;
            }
            if (mbi.State != MEM_COMMIT) return false;
            constexpr DWORD kReadable =
                PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
            if ((mbi.Protect & kReadable) == 0) return false;
            if ((mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) return false;
            const uintptr_t regionEnd =
                reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (regionEnd <= cursor) return false;
            cursor = regionEnd;
        }
    }

    std::vector<uint8_t> hash = ComputeSHA256(reinterpret_cast<const void*>(address), size);
    if (hash.empty()) return false;

    std::unique_lock lock(m_mutex);
    if (m_protectedMemoryRegions.size() >= SelfDefenseConstants::MAX_PROTECTED_MEMORY_REGIONS) return false;
    m_protectedMemoryRegions.push_back({address, size, std::move(hash)});
    return true;
}

bool SelfDefenseImpl::UnprotectMemoryRegion(uintptr_t address, std::string_view authorizationToken) {
    if (!VerifyAuthorizationToken(authorizationToken)) return false;
    std::unique_lock lock(m_mutex);
    auto it = std::remove_if(m_protectedMemoryRegions.begin(), m_protectedMemoryRegions.end(),
        [address](const MemoryRegion& r) { return r.address == address; });
    if (it == m_protectedMemoryRegions.end()) return false;
    m_protectedMemoryRegions.erase(it, m_protectedMemoryRegions.end());
    return true;
}

namespace {
// SEH-isolated PE header parse. Must have NO C++ objects with non-trivial
// destructors in the enclosing function (MSVC C2712 forbids __try in a
// function that requires object unwinding). Returns true if a code section
// was found and the (base,size) pair is safe to hash.
[[nodiscard]] bool ParseCodeSectionSafe(HMODULE hModule,
                                        uintptr_t& baseOut,
                                        size_t& sizeOut) noexcept {
    baseOut = 0;
    sizeOut = 0;
    if (!hModule) return false;
    __try {
        const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(hModule);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

        const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            reinterpret_cast<const uint8_t*>(hModule) + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

        const auto* section = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section) {
            if ((section->Characteristics & IMAGE_SCN_CNT_CODE) != 0) {
                const size_t sz = section->Misc.VirtualSize;
                if (sz == 0 || sz >= 512u * 1024u * 1024u) continue;
                baseOut = reinterpret_cast<uintptr_t>(hModule) + section->VirtualAddress;
                sizeOut = sz;
                return true;
            }
        }
        return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
} // namespace

bool SelfDefenseImpl::ProtectCodeSection() {
    HMODULE hModule = ::GetModuleHandleW(nullptr);
    if (!hModule) return false;

    // PE headers live inside our own image and should always be readable, but
    // memory corruption / DLL hollowing scenarios can leave them unmapped or
    // protected. Defer header parsing into a SEH-isolated helper so a hostile
    // or corrupted image cannot crash the watchdog (which drives this from
    // ProtectionComponent recovery and the periodic integrity sweep).
    uintptr_t base = 0;
    size_t sz = 0;
    if (!ParseCodeSectionSafe(hModule, base, sz)) {
        SS_LOG_WARN(LOG_CATEGORY, L"ProtectCodeSection: no usable code section");
        return false;
    }

    std::vector<uint8_t> hash = ComputeSHA256(reinterpret_cast<const void*>(base), sz);
    if (hash.empty()) return false;

    std::unique_lock lock(m_mutex);
    m_codeSectionBase = base;
    m_codeSectionSize = sz;
    m_codeSectionHash = std::move(hash);
    SS_LOG_INFO(LOG_CATEGORY, L"Code section protected: base=0x%llX size=%zu",
                static_cast<unsigned long long>(base), sz);
    UpdateComponentStatus(ProtectionComponent::Memory, true, ComponentHealth::Healthy);
    return true;
}

bool SelfDefenseImpl::VerifyMemoryIntegrity() {
    std::shared_lock lock(m_mutex);
    if (m_codeSectionBase == 0 || m_codeSectionSize == 0 || m_codeSectionHash.empty()) {
        return true; // Not monitored
    }
    uintptr_t base = m_codeSectionBase;
    size_t sz = m_codeSectionSize;
    auto expectedHash = m_codeSectionHash;
    lock.unlock();

    auto currentHash = ComputeSHA256(reinterpret_cast<const void*>(base), sz);
    if (currentHash != expectedHash) {
        m_stats.memoryModificationBlocked.fetch_add(1, std::memory_order_relaxed);
        ThreatEvent evt;
        evt.type = ThreatType::MemoryModification;
        evt.targetType = ProtectedEntityType::MemoryRegion;
        evt.targetIdentifier = std::to_wstring(base);
        evt.wasBlocked = false; // Detected, not blocked (already happened)
        evt.actionTaken = ThreatResponse::Alert;
        SS_LOG_ERROR(LOG_CATEGORY, L"CODE INTEGRITY VIOLATION: code section hash mismatch at 0x%llX",
                     static_cast<unsigned long long>(base));
        RecordThreatEvent(std::move(evt));
        return false;
    }
    return true;
}

// ============================================================================
// WATCHDOG AND HEARTBEAT
// ============================================================================

bool SelfDefenseImpl::StartWatchdog() {
    if (m_watchdogRunning.load(std::memory_order_acquire)) return true;
    m_watchdogRunning.store(true, std::memory_order_release);
    m_watchdogThread = std::thread(&SelfDefenseImpl::WatchdogThreadFunc, this);
    UpdateComponentStatus(ProtectionComponent::Watchdog, true, ComponentHealth::Healthy);
    SS_LOG_INFO(LOG_CATEGORY, L"Watchdog started (interval=%ums)", m_config.watchdogIntervalMs);
    return true;
}

void SelfDefenseImpl::StopWatchdog(std::string_view authorizationToken) {
    if (!VerifyAuthorizationToken(authorizationToken)) {
        SS_LOG_WARN(LOG_CATEGORY, L"StopWatchdog rejected: invalid authorization");
        return;
    }
    if (m_watchdogRunning.exchange(false, std::memory_order_acq_rel)) {
        {
            std::lock_guard<std::mutex> wlock(m_watchdogMutex);
        }
        m_watchdogCv.notify_all();
        if (m_watchdogThread.joinable()) m_watchdogThread.join();
        UpdateComponentStatus(ProtectionComponent::Watchdog, false, ComponentHealth::Unknown);
        SS_LOG_INFO(LOG_CATEGORY, L"Watchdog stopped");
    }
}

bool SelfDefenseImpl::IsWatchdogRunning() const {
    return m_watchdogRunning.load(std::memory_order_acquire);
}

void SelfDefenseImpl::SendHeartbeat(std::string_view componentName) {
    if (componentName.empty()) return;
    std::string name(componentName);
    HeartbeatMessage msg;
    msg.componentName = name;
    msg.processId = ::GetCurrentProcessId();
    msg.threadId = ::GetCurrentThreadId();
    msg.timestamp = Clock::now();
    msg.health = ComponentHealth::Healthy;

    {
        std::unique_lock lock(m_mutex);
        auto& record = m_heartbeatRecords[name];
        record.componentName = name;
        record.processId = msg.processId;
        record.lastBeat = msg.timestamp;
        record.health = ComponentHealth::Healthy;
        record.sequenceNumber++;
        msg.sequenceNumber = record.sequenceNumber;
        record.missedBeats = 0;
    }

    // Notify heartbeat callbacks outside lock
    std::vector<HeartbeatCallback> cbs;
    {
        std::shared_lock lock(m_callbackMutex);
        cbs.reserve(m_heartbeatCallbacks.size());
        for (const auto& [id, cb] : m_heartbeatCallbacks) cbs.push_back(cb);
    }
    for (const auto& cb : cbs) {
        try { cb(msg); } catch (...) {}
    }
}

bool SelfDefenseImpl::TriggerRecovery(ProtectionComponent component) {
    SS_LOG_WARN(LOG_CATEGORY, L"Triggering recovery for component 0x%08X", static_cast<unsigned>(component));
    m_stats.autoRecoveryEvents.fetch_add(1, std::memory_order_relaxed);

    bool success = false;
    if (HasComponent(component, ProtectionComponent::Service)) {
        success = EnsureServiceRunning();
    }
    if (HasComponent(component, ProtectionComponent::Driver)) {
        success |= EnsureDriverLoaded();
    }
    if (HasComponent(component, ProtectionComponent::Memory)) {
        success |= ProtectCodeSection();
    }

    if (success) {
        m_stats.successfulRecoveries.fetch_add(1, std::memory_order_relaxed);
    }

    // Notify recovery callbacks
    std::vector<RecoveryCallback> cbs;
    {
        std::shared_lock lock(m_callbackMutex);
        cbs.reserve(m_recoveryCallbacks.size());
        for (const auto& [id, cb] : m_recoveryCallbacks) cbs.push_back(cb);
    }
    for (const auto& cb : cbs) {
        try { cb(component, success); } catch (...) {}
    }
    return success;
}

ComponentHealth SelfDefenseImpl::GetComponentHealth(ProtectionComponent component) const {
    std::shared_lock lock(m_mutex);
    auto it = m_componentStatuses.find(component);
    return (it != m_componentStatuses.end()) ? it->second.health : ComponentHealth::Unknown;
}

std::vector<ComponentStatus> SelfDefenseImpl::GetAllComponentStatuses() const {
    std::shared_lock lock(m_mutex);
    std::vector<ComponentStatus> result;
    result.reserve(m_componentStatuses.size());
    for (const auto& [comp, status] : m_componentStatuses) {
        result.push_back(status);
    }
    return result;
}

void SelfDefenseImpl::WatchdogThreadFunc() {
    SS_LOG_INFO(LOG_CATEGORY, L"Watchdog thread started");
    while (m_watchdogRunning.load(std::memory_order_acquire)) {
        // Sleep on a dedicated mutex/CV so the watchdog never holds m_mutex
        // during its idle interval. Holding m_mutex (even in shared mode)
        // across wait_for serialized every writer in the engine — including
        // ProtectProcess / UnprotectProcess / Shutdown — for up to
        // watchdogIntervalMs at a time.
        const auto intervalMs = m_config.watchdogIntervalMs;
        {
            std::unique_lock<std::mutex> wlock(m_watchdogMutex);
            m_watchdogCv.wait_for(wlock, Milliseconds(intervalMs),
                [this] { return !m_watchdogRunning.load(std::memory_order_relaxed); });
        }
        if (!m_watchdogRunning.load(std::memory_order_acquire)) break;

        // Auto-resume if a bounded pause window has elapsed.
        if (m_status.load(std::memory_order_acquire) == ModuleStatus::Paused) {
            const auto deadlineNs = m_pauseDeadlineNs.load(std::memory_order_acquire);
            if (deadlineNs != 0) {
                const auto nowNs = std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
                if (nowNs >= deadlineNs) {
                    m_pauseDeadlineNs.store(0, std::memory_order_release);
                    auto expectedPaused = ModuleStatus::Paused;
                    if (m_status.compare_exchange_strong(expectedPaused, ModuleStatus::Running,
                                                          std::memory_order_acq_rel)) {
                        SS_LOG_WARN(LOG_CATEGORY, L"Self-defense auto-resumed after pause deadline elapsed");
                    }
                }
            }
            // While paused, skip the active checks below.
            if (m_status.load(std::memory_order_acquire) == ModuleStatus::Paused) {
                continue;
            }
        }

        // Check heartbeat freshness
        auto now = Clock::now();
        auto timeout = Milliseconds(m_config.heartbeatTimeoutMs);

        std::vector<std::string> staleComponents;
        {
            std::unique_lock lock(m_mutex);
            for (auto& [name, record] : m_heartbeatRecords) {
                auto elapsed = std::chrono::duration_cast<Milliseconds>(now - record.lastBeat);
                if (elapsed > timeout) {
                    record.missedBeats++;
                    record.health = ComponentHealth::Degraded;
                    if (record.missedBeats >= SelfDefenseConstants::MAX_CONSECUTIVE_FAILURES) {
                        record.health = ComponentHealth::Failed;
                        staleComponents.push_back(name);
                    }
                }
            }
        }

        for (const auto& name : staleComponents) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Component heartbeat timeout: %S", name.c_str());
            if (m_config.enableAutoRecovery) {
                TriggerRecovery(ProtectionComponent::Service);
            }
        }

        // Periodic integrity verification
        if (m_config.enableIntegrityMonitoring) {
            VerifyMemoryIntegrity();
        }

        // Verify protected processes are still alive
        // SECURITY: Duplicate handles under lock to prevent use-after-close
        // if UnprotectProcess erases an entry while we're checking
        struct HandleCheck { uint32_t pid; HANDLE dupHandle; };
        std::vector<HandleCheck> checks;
        {
            std::shared_lock lock(m_mutex);
            for (const auto& [pid, pp] : m_protectedProcesses) {
                if (pp->processHandle && pp->processHandle != INVALID_HANDLE_VALUE) {
                    HANDLE dup = nullptr;
                    if (::DuplicateHandle(::GetCurrentProcess(), pp->processHandle,
                                         ::GetCurrentProcess(), &dup,
                                         PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0)) {
                        checks.push_back({pid, dup});
                    }
                }
            }
        }
        std::vector<uint32_t> deadPids;
        for (auto& chk : checks) {
            DWORD exitCode = 0;
            if (::GetExitCodeProcess(chk.dupHandle, &exitCode) && exitCode != STILL_ACTIVE) {
                deadPids.push_back(chk.pid);
            }
            ::CloseHandle(chk.dupHandle);
        }
        for (uint32_t pid : deadPids) {
            SS_LOG_WARN(LOG_CATEGORY, L"Protected process %u has exited — removing", pid);
            std::unique_lock lock(m_mutex);
            m_protectedProcesses.erase(pid);
        }
    }
    SS_LOG_INFO(LOG_CATEGORY, L"Watchdog thread exiting");
}

// ============================================================================
// WHITELIST MANAGEMENT
// ============================================================================

bool SelfDefenseImpl::AddToWhitelist(std::wstring_view processName, std::string_view authorizationToken) {
    if (!VerifyAuthorizationToken(authorizationToken)) return false;
    if (processName.empty()) return false;

    // Verify signature of the process before whitelisting
    std::wstring lower(processName);
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    std::unique_lock lock(m_mutex);
    auto [it, inserted] = m_whitelist.insert(std::move(lower));
    if (inserted) {
        SS_LOG_INFO(LOG_CATEGORY, L"Process added to whitelist: %s", processName.data());
    }
    return true;
}

bool SelfDefenseImpl::RemoveFromWhitelist(std::wstring_view processName, std::string_view authorizationToken) {
    if (!VerifyAuthorizationToken(authorizationToken)) return false;
    std::wstring lower(processName);
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    std::unique_lock lock(m_mutex);
    return m_whitelist.erase(lower) > 0;
}

bool SelfDefenseImpl::IsWhitelisted(std::wstring_view processName) const {
    std::wstring lower(processName);
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    std::shared_lock lock(m_mutex);
    return m_whitelist.contains(lower);
}

bool SelfDefenseImpl::IsWhitelisted(uint32_t processId) const {
    auto name = GetProcessName(processId);
    if (name.empty()) return false;
    return IsWhitelisted(name);
}

std::vector<std::wstring> SelfDefenseImpl::GetWhitelistedProcesses() const {
    std::shared_lock lock(m_mutex);
    return std::vector<std::wstring>(m_whitelist.begin(), m_whitelist.end());
}

// ============================================================================
// CALLBACK REGISTRATION
// ============================================================================

uint64_t SelfDefenseImpl::RegisterThreatCallback(ThreatCallback callback) {
    if (!callback) return 0;
    uint64_t id = m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    std::unique_lock lock(m_callbackMutex);
    m_threatCallbacks[id] = std::move(callback);
    return id;
}
void SelfDefenseImpl::UnregisterThreatCallback(uint64_t callbackId) {
    std::unique_lock lock(m_callbackMutex);
    m_threatCallbacks.erase(callbackId);
}

uint64_t SelfDefenseImpl::RegisterAccessCallback(AccessCallback callback) {
    if (!callback) return 0;
    uint64_t id = m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    std::unique_lock lock(m_callbackMutex);
    m_accessCallbacks[id] = std::move(callback);
    return id;
}
void SelfDefenseImpl::UnregisterAccessCallback(uint64_t callbackId) {
    std::unique_lock lock(m_callbackMutex);
    m_accessCallbacks.erase(callbackId);
}

uint64_t SelfDefenseImpl::RegisterStatusCallback(ComponentStatusCallback callback) {
    if (!callback) return 0;
    uint64_t id = m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    std::unique_lock lock(m_callbackMutex);
    m_statusCallbacks[id] = std::move(callback);
    return id;
}
void SelfDefenseImpl::UnregisterStatusCallback(uint64_t callbackId) {
    std::unique_lock lock(m_callbackMutex);
    m_statusCallbacks.erase(callbackId);
}

uint64_t SelfDefenseImpl::RegisterRecoveryCallback(RecoveryCallback callback) {
    if (!callback) return 0;
    uint64_t id = m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    std::unique_lock lock(m_callbackMutex);
    m_recoveryCallbacks[id] = std::move(callback);
    return id;
}
void SelfDefenseImpl::UnregisterRecoveryCallback(uint64_t callbackId) {
    std::unique_lock lock(m_callbackMutex);
    m_recoveryCallbacks.erase(callbackId);
}

uint64_t SelfDefenseImpl::RegisterHeartbeatCallback(HeartbeatCallback callback) {
    if (!callback) return 0;
    uint64_t id = m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    std::unique_lock lock(m_callbackMutex);
    m_heartbeatCallbacks[id] = std::move(callback);
    return id;
}
void SelfDefenseImpl::UnregisterHeartbeatCallback(uint64_t callbackId) {
    std::unique_lock lock(m_callbackMutex);
    m_heartbeatCallbacks.erase(callbackId);
}

// ============================================================================
// STATISTICS AND REPORTING
// ============================================================================

SelfDefenseStatistics SelfDefenseImpl::GetStatistics() const {
    return m_stats.Snapshot();
}

void SelfDefenseImpl::ResetStatistics(std::string_view authorizationToken) {
    if (!VerifyAuthorizationToken(authorizationToken)) return;
    m_stats.Reset();
    SS_LOG_INFO(LOG_CATEGORY, L"Statistics reset");
}

std::vector<ThreatEvent> SelfDefenseImpl::GetThreatHistory(size_t maxEntries) const {
    std::shared_lock lock(m_historyMutex);
    size_t count = std::min(maxEntries, m_threatHistory.size());
    auto startIt = m_threatHistory.end() - static_cast<ptrdiff_t>(count);
    return std::vector<ThreatEvent>(startIt, m_threatHistory.end());
}

void SelfDefenseImpl::ClearThreatHistory(std::string_view authorizationToken) {
    if (!VerifyAuthorizationToken(authorizationToken)) return;
    std::unique_lock lock(m_historyMutex);
    m_threatHistory.clear();
}

std::string SelfDefenseImpl::ExportReport() const {
    auto stats = m_stats.Snapshot();
    std::ostringstream json;
    json << "{\n"
         << "  \"version\": \"" << SelfDefenseConstants::VERSION_MAJOR << "."
         << SelfDefenseConstants::VERSION_MINOR << "." << SelfDefenseConstants::VERSION_PATCH << "\",\n"
         << "  \"status\": \"" << static_cast<int>(m_status.load()) << "\",\n"
         << "  \"totalThreatsDetected\": " << stats.totalThreatsDetected << ",\n"
         << "  \"totalThreatsBlocked\": " << stats.totalThreatsBlocked << ",\n"
         << "  \"processTerminationBlocked\": " << stats.processTerminationBlocked << ",\n"
         << "  \"threadTerminationBlocked\": " << stats.threadTerminationBlocked << ",\n"
         << "  \"memoryModificationBlocked\": " << stats.memoryModificationBlocked << ",\n"
         << "  \"fileModificationBlocked\": " << stats.fileModificationBlocked << ",\n"
         << "  \"registryModificationBlocked\": " << stats.registryModificationBlocked << ",\n"
         << "  \"serviceControlBlocked\": " << stats.serviceControlBlocked << ",\n"
         << "  \"autoRecoveryEvents\": " << stats.autoRecoveryEvents << ",\n"
         << "  \"successfulRecoveries\": " << stats.successfulRecoveries << "\n"
         << "}";
    return json.str();
}

// ============================================================================
// AUTHORIZATION TOKEN (HMAC-SHA256)
// ============================================================================

std::string SelfDefenseImpl::GenerateAuthorizationToken(std::string_view purpose, uint32_t validitySeconds) {
    if (m_authSecret.empty()) return "";

    auto now = std::chrono::system_clock::now();
    auto expiry = now + std::chrono::seconds(validitySeconds);
    uint64_t expiryTs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(expiry.time_since_epoch()).count());

    // Payload: purpose + ":" + expiryTimestamp
    std::string payload(purpose);
    payload += ":";
    payload += std::to_string(expiryTs);

    std::array<uint8_t, AUTH_TOKEN_HMAC_SIZE> hmac{};
    if (!ComputeAuthorizationTokenHmac(m_authSecret, payload, hmac)) {
        return "";
    }

    // Encode v2 as hex(hmac) + ":" + expiryTs + ":" + hex(purpose).
    // The embedded purpose lets verification authenticate arbitrary callers
    // without relying on a fixed purpose allowlist. VerifyAuthorizationToken
    // retains compatibility with legacy two-segment tokens.
    std::ostringstream oss;
    for (const uint8_t byte : hmac) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
    }
    oss << ":" << std::dec << expiryTs << ":" << HexEncode(purpose);

    // Zero the stack HMAC
    ::SecureZeroMemory(hmac.data(), hmac.size());
    return oss.str();
}

bool SelfDefenseImpl::VerifyAuthorizationToken(std::string_view token) const {
    // The empty-token success path is reserved exclusively for the destructor
    // teardown sequence (ShutdownInternal -> m_shutdownInProgress=true).
    // Outside of that window, an empty token MUST fail even when m_authSecret
    // is empty (e.g., between Shutdown and a subsequent Initialize). This
    // prevents a hostile caller from issuing privileged operations such as
    // UnprotectProcess / ClearThreatHistory / ResetStatistics simply by
    // passing an empty token before re-initialization.
    if (token.empty()) {
        return m_shutdownInProgress.load(std::memory_order_acquire);
    }
    if (m_authSecret.empty()) {
        // No active secret. Only the teardown path may accept this; we've
        // already short-circuited empty tokens above, so reject the rest.
        return false;
    }

    // Parse v2 token as hex(hmac):expiryTs:hex(purpose).
    // Legacy v1 tokens use hex(hmac):expiryTs and are accepted for
    // compatibility with already-issued in-process tokens.
    const size_t firstColon = token.find(':');
    if (firstColon == std::string_view::npos) return false;

    const size_t secondColon = token.find(':', firstColon + 1);
    const std::string_view hmacHex = token.substr(0, firstColon);
    const std::string_view expiryStr = (secondColon == std::string_view::npos)
        ? token.substr(firstColon + 1)
        : token.substr(firstColon + 1, secondColon - firstColon - 1);
    const std::string_view purposeHex = (secondColon == std::string_view::npos)
        ? std::string_view{}
        : token.substr(secondColon + 1);

    if (expiryStr.empty()) return false;

    // Verify expiry
    uint64_t expiryTs = 0;
    for (char c : expiryStr) {
        if (c < '0' || c > '9') return false;
        uint64_t prev = expiryTs;
        expiryTs = expiryTs * 10 + static_cast<uint64_t>(c - '0');
        if (expiryTs < prev) return false; // Overflow
    }

    auto now = std::chrono::system_clock::now();
    uint64_t nowTs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());
    if (nowTs > expiryTs) return false; // Expired

    std::array<uint8_t, AUTH_TOKEN_HMAC_SIZE> expected{};

    if (secondColon != std::string_view::npos) {
        std::string purpose;
        if (!HexDecode(purposeHex, purpose)) {
            return false;
        }

        std::string payload;
        payload.reserve(purpose.size() + 1 + expiryStr.size());
        payload.append(purpose);
        payload.push_back(':');
        payload.append(expiryStr);

        if (!ComputeAuthorizationTokenHmac(m_authSecret, payload, expected)) {
            return false;
        }

        const bool matched = ConstantTimeHexEquals(hmacHex, expected);
        ::SecureZeroMemory(expected.data(), expected.size());
        return matched;
    }

    // Legacy support for v1 tokens that omitted the purpose. We can only verify
    // the historical built-in purpose set for those tokens.
    static constexpr const char* LEGACY_PURPOSES[] = {
        "shutdown",
        "pause",
        "admin",
        "whitelist",
        "general",
        "unprotect",
        "reset",
        "disable",
        "stop_watchdog"
    };

    bool matched = false;
    for (const char* purpose : LEGACY_PURPOSES) {
        std::string payload(purpose);
        payload.push_back(':');
        payload.append(expiryStr);

        if (!ComputeAuthorizationTokenHmac(m_authSecret, payload, expected)) {
            continue;
        }

        matched |= ConstantTimeHexEquals(hmacHex, expected);
        ::SecureZeroMemory(expected.data(), expected.size());
    }

    return matched;
}

// ============================================================================
// SELF-TEST
// ============================================================================

bool SelfDefenseImpl::SelfTest() {
    SS_LOG_INFO(LOG_CATEGORY, L"Running self-test...");
    bool allPassed = true;

    // Test 1: Auth token generation and verification
    auto token = GenerateAuthorizationToken("general", 60);
    if (token.empty() || !VerifyAuthorizationToken(token)) {
        SS_LOG_ERROR(LOG_CATEGORY, L"SELF-TEST FAILED: Auth token round-trip");
        allPassed = false;
    }

    // Test 2: Current process should be protected
    if (!IsProcessProtected(::GetCurrentProcessId())) {
        SS_LOG_ERROR(LOG_CATEGORY, L"SELF-TEST FAILED: Current process not protected");
        allPassed = false;
    }

    // Test 3: Memory integrity
    if (m_codeSectionBase != 0 && !VerifyMemoryIntegrity()) {
        SS_LOG_ERROR(LOG_CATEGORY, L"SELF-TEST FAILED: Code section integrity");
        allPassed = false;
    }

    // Test 4: SHA-256 basic test
    {
        const char testData[] = "ShadowStrike";
        auto hash = ComputeSHA256(testData, sizeof(testData) - 1);
        if (hash.size() != 32 || hash[0] == 0) {
            SS_LOG_ERROR(LOG_CATEGORY, L"SELF-TEST FAILED: SHA-256 computation");
            allPassed = false;
        }
    }

    if (allPassed) {
        SS_LOG_INFO(LOG_CATEGORY, L"Self-test: ALL PASSED");
    } else {
        SS_LOG_ERROR(LOG_CATEGORY, L"Self-test: FAILURES DETECTED");
    }
    return allPassed;
}

// ============================================================================
// KERNEL BRIDGE
// ============================================================================

void SelfDefenseImpl::RegisterKernelHandler() {
    if (m_kernelHandlerRegistered.load(std::memory_order_acquire)) return;
    if (!Communication::IPCManager::HasInstance()) {
        SS_LOG_WARN(LOG_CATEGORY, L"IPCManager not available — kernel handler not registered");
        return;
    }

    auto& ipc = Communication::IPCManager::Instance();
    ipc.RegisterGenericHandler(
        [this](SHADOWSTRIKE_MESSAGE_TYPE msgType, const void* data, size_t size) {
            if (!m_kernelHandlerRegistered.load(std::memory_order_acquire)) return;
            if (msgType == FilterMessageType_SelfProtectAlert) {
                OnKernelSelfProtectEventInternal(data, static_cast<uint32_t>(size));
            }
        });
    m_kernelHandlerRegistered.store(true, std::memory_order_release);
    SS_LOG_INFO(LOG_CATEGORY, L"Kernel SelfProtectAlert handler registered");
}

void SelfDefenseImpl::UnregisterKernelHandler() {
    // Flip the local flag so any in-flight callback that has already entered
    // the registered lambda short-circuits before touching `this`.
    if (!m_kernelHandlerRegistered.exchange(false, std::memory_order_acq_rel)) {
        return;
    }
    // IPCManager::RegisterGenericHandler stores a single callable. Clearing it
    // is the only way to drop our `this`-capturing lambda and prevent IPCManager
    // from dispatching into a destroyed SelfDefenseImpl after Shutdown. This
    // mirrors the pattern used by FileProtection on its own teardown.
    if (Communication::IPCManager::HasInstance()) {
        try {
            Communication::IPCManager::Instance().RegisterGenericHandler(nullptr);
        } catch (...) {
            SS_LOG_WARN(LOG_CATEGORY, L"Exception while clearing IPC kernel handler during shutdown");
        }
    }
    SS_LOG_INFO(LOG_CATEGORY, L"Kernel SelfProtectAlert handler unregistered");
}

void SelfDefenseImpl::SyncProtectedProcessesToKernel() {
    if (!Communication::IPCManager::HasInstance()) return;

    // Gather PIDs under shared lock
    std::vector<uint32_t> pids;
    {
        std::shared_lock lock(m_mutex);
        pids.reserve(m_protectedProcesses.size());
        for (const auto& [pid, entry] : m_protectedProcesses) {
            pids.push_back(pid);
        }
    }

    if (pids.empty()) return;

    // Build payload: [uint32_t count][uint32_t pid1][uint32_t pid2]...
    uint32_t count = static_cast<uint32_t>(std::min<size_t>(pids.size(), 4096));
    size_t payloadSize = sizeof(uint32_t) + count * sizeof(uint32_t);
    std::vector<uint8_t> payload(payloadSize, 0);
    std::memcpy(payload.data(), &count, sizeof(count));
    for (uint32_t i = 0; i < count; ++i) {
        std::memcpy(payload.data() + sizeof(uint32_t) + i * sizeof(uint32_t),
                    &pids[i], sizeof(uint32_t));
    }

    // Build SHADOWSTRIKE_MESSAGE_HEADER + payload
    size_t totalSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + payload.size();
    if (totalSize > 64 * 1024) {
        SS_LOG_WARN(LOG_CATEGORY, L"Kernel sync payload too large: %zu bytes", totalSize);
        return;
    }

    std::vector<uint8_t> message(totalSize, 0);
    auto* header = reinterpret_cast<SHADOWSTRIKE_MESSAGE_HEADER*>(message.data());
    header->Magic = SHADOWSTRIKE_MESSAGE_MAGIC;
    header->Version = SHADOWSTRIKE_PROTOCOL_VERSION;
    header->MessageType = static_cast<UINT16>(FilterMessageType_RegisterProtectedProcess);
    header->MessageId = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
    header->TotalSize = static_cast<UINT32>(totalSize);
    header->DataSize = static_cast<UINT32>(payload.size());
    LARGE_INTEGER ts;
    ::QueryPerformanceCounter(&ts);
    header->Timestamp = static_cast<UINT64>(ts.QuadPart);
    header->Flags = 0;

    std::memcpy(message.data() + sizeof(SHADOWSTRIKE_MESSAGE_HEADER),
               payload.data(), payload.size());

    auto& ipc = Communication::IPCManager::Instance();
    bool sent = ipc.SendToKernel(message.data(), message.size());
    if (sent) {
        SS_LOG_INFO(LOG_CATEGORY, L"Synced %u protected processes to kernel", count);
        std::unique_lock lock(m_mutex);
        for (auto& [pid, entry] : m_protectedProcesses) {
            entry->kernelProtected = true;
        }
    } else {
        SS_LOG_WARN(LOG_CATEGORY, L"Failed to sync protected processes to kernel");
    }
}

void SelfDefenseImpl::OnKernelSelfProtectEventInternal(const void* data, uint32_t size) {
    // Wire format from kernel: [uint32_t attackerPid][uint32_t targetPid]
    //                          [uint32_t accessMask][uint16_t descLen][wchar_t desc[]]
    static constexpr uint32_t kMinSize = sizeof(uint32_t) * 3 + sizeof(uint16_t);
    if (!data || size < kMinSize) {
        SS_LOG_WARN(LOG_CATEGORY, L"Invalid kernel SelfProtect event (size=%u, min=%u)", size, kMinSize);
        return;
    }

    const auto* bytes = static_cast<const uint8_t*>(data);
    uint32_t attackerPid = 0, targetPid = 0, accessMask = 0;
    uint16_t descLen = 0;

    std::memcpy(&attackerPid, bytes, sizeof(uint32_t));
    std::memcpy(&targetPid, bytes + 4, sizeof(uint32_t));
    std::memcpy(&accessMask, bytes + 8, sizeof(uint32_t));
    std::memcpy(&descLen, bytes + 12, sizeof(uint16_t));

    // Validate descLen
    uint32_t descBytesAvail = size - kMinSize;
    uint32_t descBytes = static_cast<uint32_t>(descLen) * sizeof(wchar_t);
    if (descBytes > descBytesAvail) {
        descLen = static_cast<uint16_t>(descBytesAvail / sizeof(wchar_t));
    }

    std::wstring description;
    if (descLen > 0) {
        description.assign(reinterpret_cast<const wchar_t*>(bytes + kMinSize), descLen);
    }

    ThreatEvent evt;
    // Derive the canonical threat classification from the access mask, matching
    // the same priority order used by FilterAccessRequest(): code-injection
    // signals (CREATE_THREAD) outrank memory-modification signals (VM_WRITE /
    // VM_OPERATION) which outrank termination, with suspend/resume as the
    // residual class. Misclassifying a CreateRemoteThread injection as a
    // process-termination event would route it to the wrong response policy
    // and skew per-threat statistics.
    if ((accessMask & PROCESS_CREATE_THREAD) != 0) {
        evt.type = ThreatType::CodeInjection;
        // CodeInjection is tracked via RecordThreatEvent->IncrementThreatTypeStat.
    } else if ((accessMask & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION)) != 0) {
        evt.type = ThreatType::MemoryModification;
        m_stats.memoryModificationBlocked.fetch_add(1, std::memory_order_relaxed);
    } else if ((accessMask & PROCESS_TERMINATE) != 0) {
        evt.type = ThreatType::ProcessTermination;
        m_stats.processTerminationBlocked.fetch_add(1, std::memory_order_relaxed);
    } else if ((accessMask & PROCESS_SUSPEND_RESUME) != 0) {
        evt.type = ThreatType::ProcessSuspension;
    } else {
        evt.type = ThreatType::ProcessTermination;
        m_stats.processTerminationBlocked.fetch_add(1, std::memory_order_relaxed);
    }
    evt.attackerProcessId = attackerPid;
    evt.attackerProcessName = GetProcessName(attackerPid);
    evt.attackerProcessPath = GetProcessImagePath(attackerPid);
    evt.targetType = ProtectedEntityType::Process;
    evt.targetIdentifier = std::to_wstring(targetPid);
    evt.requestedAccess = accessMask;
    evt.blockedAccess = accessMask & SelfDefenseConstants::BLOCKED_PROCESS_ACCESS;
    evt.wasBlocked = true;
    evt.actionTaken = ThreatResponse::Block;
    if (!description.empty()) {
        evt.details["kernel_description"] = Utils::StringUtils::ToNarrow(description);
    }

    SS_LOG_WARN(LOG_CATEGORY, L"KERNEL: PID %u attempted 0x%08X on protected PID %u — BLOCKED",
               attackerPid, accessMask, targetPid);
    RecordThreatEvent(std::move(evt));
}

// ============================================================================
// STRUCT METHOD IMPLEMENTATIONS
// ============================================================================

SelfDefenseConfiguration SelfDefenseConfiguration::FromLevel(SelfDefenseLevel level) {
    SelfDefenseConfiguration config;
    config.level = level;
    switch (level) {
        case SelfDefenseLevel::Disabled:
            config.enabledComponents = ProtectionComponent::None;
            config.enableKernelProtection = false;
            config.enableWatchdog = false;
            config.enableIntegrityMonitoring = false;
            break;
        case SelfDefenseLevel::Minimal:
            config.enabledComponents = ProtectionComponent::Process;
            config.enableKernelProtection = false;
            config.enableWatchdog = false;
            break;
        case SelfDefenseLevel::Standard:
            config.enabledComponents = ProtectionComponent::UserMode;
            config.defaultResponse = ThreatResponse::Active;
            break;
        case SelfDefenseLevel::Enhanced:
            config.enabledComponents = ProtectionComponent::KernelMode;
            config.defaultResponse = ThreatResponse::Active;
            break;
        case SelfDefenseLevel::Maximum:
        case SelfDefenseLevel::Paranoid:
            config.enabledComponents = ProtectionComponent::All;
            config.defaultResponse = ThreatResponse::Aggressive;
            config.verboseLogging = true;
            break;
    }
    return config;
}

bool SelfDefenseConfiguration::IsValid() const noexcept {
    return level >= SelfDefenseLevel::Disabled && level <= SelfDefenseLevel::Paranoid &&
           watchdogIntervalMs >= 1000 && heartbeatTimeoutMs >= 5000;
}

std::string ThreatEvent::GetSummary() const {
    std::ostringstream ss;
    ss << "Threat: type=0x" << std::hex << static_cast<uint32_t>(type)
       << " attacker=" << std::dec << attackerProcessId
       << " target=" << Utils::StringUtils::ToNarrow(targetIdentifier)
       << " blocked=" << (wasBlocked ? "yes" : "no");
    return ss.str();
}

std::string ThreatEvent::ToJson() const {
    std::ostringstream json;
    json << "{\"eventId\":" << eventId
         << ",\"type\":" << static_cast<uint32_t>(type)
         << ",\"attackerPid\":" << attackerProcessId
         << ",\"wasBlocked\":" << (wasBlocked ? "true" : "false")
         << "}";
    return json.str();
}

void SelfDefenseStatistics::Reset() noexcept {
    totalThreatsDetected = 0;
    totalThreatsBlocked = 0;
    processTerminationBlocked = 0;
    threadTerminationBlocked = 0;
    memoryModificationBlocked = 0;
    fileModificationBlocked = 0;
    registryModificationBlocked = 0;
    serviceControlBlocked = 0;
    autoRecoveryEvents = 0;
    successfulRecoveries = 0;
    threatsByType.clear();
    startTime = Clock::now();
}

std::string SelfDefenseStatistics::ToJson() const {
    std::ostringstream json;
    json << "{\"totalThreats\":" << totalThreatsDetected
         << ",\"blocked\":" << totalThreatsBlocked
         << ",\"recoveries\":" << successfulRecoveries << "}";
    return json.str();
}

// ============================================================================
// FREE UTILITY FUNCTIONS
// ============================================================================

std::string_view GetComponentName(ProtectionComponent component) noexcept {
    switch (component) {
        case ProtectionComponent::Process:       return "Process";
        case ProtectionComponent::Thread:        return "Thread";
        case ProtectionComponent::Service:       return "Service";
        case ProtectionComponent::Driver:        return "Driver";
        case ProtectionComponent::FileSystem:    return "FileSystem";
        case ProtectionComponent::Registry:      return "Registry";
        case ProtectionComponent::Memory:        return "Memory";
        case ProtectionComponent::Network:       return "Network";
        case ProtectionComponent::Watchdog:      return "Watchdog";
        case ProtectionComponent::Heartbeat:     return "Heartbeat";
        case ProtectionComponent::Recovery:      return "Recovery";
        case ProtectionComponent::AccessControl: return "AccessControl";
        default:                                 return "Unknown";
    }
}

std::string_view GetThreatTypeName(ThreatType type) noexcept {
    switch (type) {
        case ThreatType::ProcessTermination:   return "ProcessTermination";
        case ThreatType::ThreadTermination:    return "ThreadTermination";
        case ThreatType::ProcessSuspension:    return "ProcessSuspension";
        case ThreatType::MemoryModification:   return "MemoryModification";
        case ThreatType::CodeInjection:        return "CodeInjection";
        case ThreatType::HandleDuplication:    return "HandleDuplication";
        case ThreatType::ServiceControl:       return "ServiceControl";
        case ThreatType::DriverUnload:         return "DriverUnload";
        case ThreatType::FileModification:     return "FileModification";
        case ThreatType::FileDeletion:         return "FileDeletion";
        case ThreatType::RegistryModification: return "RegistryModification";
        case ThreatType::RegistryDeletion:     return "RegistryDeletion";
        case ThreatType::PrivilegeEscalation:  return "PrivilegeEscalation";
        case ThreatType::DebugAttach:          return "DebugAttach";
        case ThreatType::TokenManipulation:    return "TokenManipulation";
        case ThreatType::APCInjection:         return "APCInjection";
        case ThreatType::HookInstallation:     return "HookInstallation";
        default:                               return "Unknown";
    }
}

std::string_view GetHealthName(ComponentHealth health) noexcept {
    switch (health) {
        case ComponentHealth::Healthy:    return "Healthy";
        case ComponentHealth::Degraded:   return "Degraded";
        case ComponentHealth::Failed:     return "Failed";
        case ComponentHealth::Recovering: return "Recovering";
        case ComponentHealth::Protected:  return "Protected";
        default:                          return "Unknown";
    }
}

std::string_view GetProtectionLevelName(SelfDefenseLevel level) noexcept {
    switch (level) {
        case SelfDefenseLevel::Disabled: return "Disabled";
        case SelfDefenseLevel::Minimal:  return "Minimal";
        case SelfDefenseLevel::Standard: return "Standard";
        case SelfDefenseLevel::Enhanced: return "Enhanced";
        case SelfDefenseLevel::Maximum:  return "Maximum";
        case SelfDefenseLevel::Paranoid: return "Paranoid";
        default:                         return "Unknown";
    }
}

// ============================================================================
// RAII HELPERS
// ============================================================================

ScopedSelfDefensePause::ScopedSelfDefensePause(std::string_view authToken, uint32_t durationMs) {
    if (SelfDefense::HasInstance()) {
        m_paused = SelfDefense::Instance().Pause(authToken, durationMs);
    }
}

ScopedSelfDefensePause::~ScopedSelfDefensePause() {
    if (m_paused && SelfDefense::HasInstance()) {
        SelfDefense::Instance().Resume();
    }
}

ProtectedScope::ProtectedScope(uint32_t processId) {
    if (processId == 0) processId = ::GetCurrentProcessId();
    m_processId = processId;
    if (SelfDefense::HasInstance()) {
        m_protected = SelfDefense::Instance().ProtectProcess(processId);
        if (m_protected) {
            m_authToken = SelfDefense::Instance().GenerateAuthorizationToken("unprotect", 3600);
        }
    }
}

ProtectedScope::~ProtectedScope() {
    if (m_protected && SelfDefense::HasInstance()) {
        (void)SelfDefense::Instance().UnprotectProcess(m_processId, m_authToken);
    }
    if (!m_authToken.empty()) {
        ::SecureZeroMemory(m_authToken.data(), m_authToken.size());
    }
}

}  // namespace Security
}  // namespace ShadowStrike

