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
 * @file IPCManager.cpp
 * @brief Implementation of kernel-user mode IPC Manager
 *
 * This is the CRITICAL integration point between the kernel minifilter
 * driver and user-mode scanning components.
 *
 * @copyright ShadowStrike NGAV - Enterprise Security Platform
 */

#include "pch.h"
#include "FilterPortGate.hpp"
#include "IPCManager.hpp"
#include "FilterConnection.hpp"
#include "ThreatIntelPusher.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../RealTime/MemoryProtection.hpp"
#include "../Service/BootTrace.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <aclapi.h>
#include <sddl.h>
#include <wintrust.h>
#include <softpub.h>

#ifdef _WIN32
#pragma comment(lib, "fltlib.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wintrust.lib")
#endif

namespace ShadowStrike {
namespace Communication {

namespace {

// ----------------------------------------------------------------------------
// Minifilter auto-load fallback
//
// PhantomSensor's SCM entry is registered as SERVICE_DEMAND_START (the only
// start-type proven safe for this driver: SERVICE_SYSTEM_START causes a
// bugcheck in early-boot DriverEntry context, tracked separately).  As a
// consequence the kernel does NOT auto-load PhantomSensor at boot; only the
// install-time FilterLoad call gets the driver into the filter manager and
// it disappears again on reboot.
//
// To restore the minifilter on every boot, ShadowStrikePhantomService
// (LocalSystem) calls FilterLoad here, just before the first
// FilterConnectCommunicationPort attempt.  FilterLoad is idempotent
// (ERROR_ALREADY_EXISTS == success) and is safe to invoke repeatedly from
// reconnect paths.  SeLoadDriverPrivilege is enabled defensively because
// LocalSystem holds the privilege but it may be present-but-disabled on
// the token.
// ----------------------------------------------------------------------------

constexpr wchar_t kPhantomMinifilterName[] = L"PhantomSensor";

[[nodiscard]] bool EnableTokenPrivilege(LPCWSTR privilegeName) noexcept {
    HANDLE rawToken = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(),
                            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                            &rawToken) || rawToken == nullptr) {
        return false;
    }

    struct TokenGuard {
        HANDLE h;
        ~TokenGuard() { if (h) ::CloseHandle(h); }
    } guard{rawToken};

    LUID luid{};
    if (!::LookupPrivilegeValueW(nullptr, privilegeName, &luid)) {
        return false;
    }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!::AdjustTokenPrivileges(guard.h, FALSE, &tp,
                                 sizeof(TOKEN_PRIVILEGES),
                                 nullptr, nullptr)) {
        return false;
    }
    // AdjustTokenPrivileges returns TRUE even if the privilege was not held;
    // GetLastError() distinguishes the two cases.
    return ::GetLastError() == ERROR_SUCCESS;
}

[[nodiscard]] HRESULT EnsurePhantomMinifilterLoaded() noexcept {
    (void)EnableTokenPrivilege(SE_LOAD_DRIVER_NAME);

    const HRESULT hr = ::FilterLoad(kPhantomMinifilterName);
    if (SUCCEEDED(hr)) {
        Utils::Logger::Info(
            "[IPCManager] FilterLoad('PhantomSensor') succeeded");
        return S_OK;
    }
    if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
        Utils::Logger::Debug(
            "[IPCManager] Minifilter 'PhantomSensor' already loaded");
        return S_OK;
    }
    // ERROR_SERVICE_DOES_NOT_EXIST means the SCM entry is missing — driver
    // install never ran or was rolled back.  ERROR_PRIVILEGE_NOT_HELD means
    // the service token lacks SeLoadDriverPrivilege (should not happen for
    // LocalSystem).  Surface the exact code so triage doesn't guess.
    Utils::Logger::Error(
        "[IPCManager] FilterLoad('PhantomSensor') failed: 0x{:08X}",
        static_cast<unsigned int>(hr));
    return hr;
}

}  // namespace

// ============================================================================
// STATIC MEMBERS
// ============================================================================

std::atomic<bool> IPCManager::s_instanceCreated{false};

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class IPCManagerImpl {
public:
    IPCManagerImpl() = default;
    ~IPCManagerImpl() = default;

    // Configuration
    IPCConfiguration config;
    mutable std::shared_mutex configMutex;

    // Statistics
    IPCStatistics stats;

    // Callbacks
    ConnectionCallback connectionCallback;
    ErrorCallback errorCallback;
    mutable std::mutex callbackMutex;

    // Message buffers (pool for performance - avoids allocations in hot path)
    static constexpr size_t BUFFER_POOL_SIZE = 16;
    std::array<std::vector<uint8_t>, BUFFER_POOL_SIZE> bufferPool;
    std::atomic<uint32_t> nextBufferIndex{0};

    // Pending replies for async operations
    struct PendingReply {
        uint64_t messageId;
        TimePoint expirationTime;
        std::promise<SHADOWSTRIKE_SCAN_VERDICT_REPLY> promise;
    };
    std::unordered_map<uint64_t, std::unique_ptr<PendingReply>> pendingReplies;
    mutable std::mutex pendingMutex;

    // Message ID generator (atomic for thread safety)
    std::atomic<uint64_t> nextMessageId{1};

    // Shutdown event for clean termination
    HANDLE shutdownEvent = nullptr;

    [[nodiscard]] std::vector<uint8_t>& GetBuffer() noexcept {
        uint32_t index = nextBufferIndex.fetch_add(1, std::memory_order_relaxed) % BUFFER_POOL_SIZE;
        auto& buffer = bufferPool[index];
        if (buffer.size() < IPCConstants::MAX_MESSAGE_SIZE) {
            buffer.resize(IPCConstants::MAX_MESSAGE_SIZE);
        }
        return buffer;
    }

    [[nodiscard]] uint64_t GenerateMessageId() noexcept {
        return nextMessageId.fetch_add(1, std::memory_order_relaxed);
    }

    void NotifyError(const std::string& message, int code) {
        std::lock_guard lock(callbackMutex);
        if (errorCallback) {
            try {
                errorCallback(message, code);
            } catch (...) {
                // Don't let callback exceptions propagate
            }
        }
    }

    void NotifyConnectionChange(ChannelType channel, ConnectionStatus status) {
        std::lock_guard lock(callbackMutex);
        if (connectionCallback) {
            try {
                connectionCallback(channel, status);
            } catch (...) {
                // Don't let callback exceptions propagate
            }
        }
    }
};

// ============================================================================
// SINGLETON INSTANCE
// ============================================================================

IPCManager& IPCManager::Instance() noexcept {
    static IPCManager instance;
    return instance;
}

bool IPCManager::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

IPCManager::IPCManager()
    : m_impl(std::make_unique<IPCManagerImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);

    // Create shutdown event
    m_impl->shutdownEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    Utils::Logger::Info("[IPCManager] Instance created - version {}",
                        GetVersionString());
}

IPCManager::~IPCManager() {
    Shutdown();

    if (m_impl->shutdownEvent != nullptr) {
        CloseHandle(m_impl->shutdownEvent);
        m_impl->shutdownEvent = nullptr;
    }

    s_instanceCreated.store(false, std::memory_order_release);
    Utils::Logger::Info("[IPCManager] Instance destroyed");
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

bool IPCManager::Initialize(const IPCConfiguration& config) {
    ::ShadowStrikeAppendBootTrace(L"ipc-Initialize-enter");
    IPCStatus expected = IPCStatus::Uninitialized;
    if (!m_status.compare_exchange_strong(expected, IPCStatus::Initializing)) {
        IPCStatus current = m_status.load(std::memory_order_acquire);
        wchar_t tag[80];
        swprintf(tag, _countof(tag),
                 L"ipc-Initialize-CAS-FAIL-status=%d-returning=%d",
                 static_cast<int>(current),
                 current != IPCStatus::Error ? 1 : 0);
        ::ShadowStrikeAppendBootTrace(tag);
        Utils::Logger::Warn("[IPCManager] Already initialized (status: {})",
                            static_cast<int>(current));
        return current != IPCStatus::Error;
    }
    ::ShadowStrikeAppendBootTrace(L"ipc-Initialize-CAS-ok");

    if (!config.IsValid()) {
        Utils::Logger::Error("[IPCManager] Invalid configuration provided");
        ::ShadowStrikeAppendBootTrace(L"ipc-Initialize-config-INVALID");
        m_status.store(IPCStatus::Error);
        return false;
    }

    {
        std::unique_lock lock(m_impl->configMutex);
        m_impl->config = config;
    }

    // Pre-allocate buffer pool
    for (auto& buffer : m_impl->bufferPool) {
        try {
            buffer.reserve(IPCConstants::MAX_MESSAGE_SIZE);
        } catch (const std::bad_alloc& e) {
            Utils::Logger::Error("[IPCManager] Failed to allocate buffer pool: {}", e.what());
            ::ShadowStrikeAppendBootTrace(L"ipc-Initialize-bufferpool-OOM");
            m_status.store(IPCStatus::Error);
            return false;
        }
    }

    // Create IOCP for async I/O if enabled
    if (config.useIOCP) {
        m_hIOCP = CreateIoCompletionPort(
            INVALID_HANDLE_VALUE,
            nullptr,
            0,
            config.workerThreadCount
        );

        if (m_hIOCP == nullptr) {
            DWORD error = GetLastError();
            Utils::Logger::Error("[IPCManager] Failed to create IOCP: {}", error);
            wchar_t tag[80];
            swprintf(tag, _countof(tag), L"ipc-Initialize-IOCP-FAIL-gle=%lu", error);
            ::ShadowStrikeAppendBootTrace(tag);
            m_status.store(IPCStatus::Error);
            return false;
        }
    }

    // Reset shutdown event
    if (m_impl->shutdownEvent != nullptr) {
        ResetEvent(m_impl->shutdownEvent);
    }

    m_impl->stats.startTime = Clock::now();
    m_status.store(IPCStatus::Stopped);
    ::ShadowStrikeAppendBootTrace(L"ipc-Initialize-status-store-Stopped");

    Utils::Logger::Info("[IPCManager] Initialized successfully");
    Utils::Logger::Info("[IPCManager]   Filter port: {}",
                        Utils::StringUtils::ToNarrow(config.filterPortName));
    Utils::Logger::Info("[IPCManager]   Worker threads: {}", config.workerThreadCount);
    Utils::Logger::Info("[IPCManager]   Reply timeout: {} ms", config.replyTimeoutMs);

    return true;
}

bool IPCManager::Start(uint32_t workerThreadCount) {
    ::ShadowStrikeAppendBootTrace(L"ipc-Start-enter");
    IPCStatus expected = IPCStatus::Stopped;
    if (!m_status.compare_exchange_strong(expected, IPCStatus::Running)) {
        IPCStatus current = m_status.load(std::memory_order_acquire);

        // Idempotent start. The IPC manager has two legitimate start paths that
        // both run during service bring-up:
        //   * Full build: RealTimeProtection::InitializeIPCManager() initializes
        //     the manager, registers the kernel scan/process/image/registry
        //     handlers, starts it, and connects the filter port.
        //   * Focused build: RealTimeProtection skips IPC, and
        //     AntivirusService::Start() is the sole starter.
        // In the full build AntivirusService::Start() still calls Start() a
        // second time after RealTimeProtection has already brought the manager
        // up. A redundant Start() against an already-running manager MUST be a
        // no-op success: returning false here makes the second caller treat
        // bring-up as fatal, tearing down RealTimeProtection and aborting the
        // service before the PhantomHome UI IPC pipe (ServiceCommunicator) ever
        // starts, which surfaces to the user as "service offline".
        if (current == IPCStatus::Running) {
            ::ShadowStrikeAppendBootTrace(L"ipc-Start-already-running-ok");
            Utils::Logger::Info("[IPCManager] Start requested while already running; treating as no-op success");
            return true;
        }

        wchar_t tag[64];
        swprintf(tag, _countof(tag), L"ipc-Start-CAS-FAIL-status=%d", static_cast<int>(current));
        ::ShadowStrikeAppendBootTrace(tag);
        Utils::Logger::Warn("[IPCManager] Cannot start - current status: {}",
                            static_cast<int>(current));
        return false;
    }
    ::ShadowStrikeAppendBootTrace(L"ipc-Start-CAS-ok");

    m_running.store(true, std::memory_order_release);

    // Reset shutdown event
    if (m_impl->shutdownEvent != nullptr) {
        ResetEvent(m_impl->shutdownEvent);
    }

    // BOOT-GRACE: defer first filter-port connect by 3 seconds.
    //
    // Previously Start() invoked ConnectFilterPort() synchronously here.
    // On a clean install + first reboot the kernel minifilter is still
    // warming up while ShadowStrikePhantomService is autoloading; a
    // synchronous FilterConnectCommunicationPort against an unready port
    // returns ERROR_FILE_NOT_FOUND and, if the port is being torn down
    // mid-init, can wedge the service in FltMgr internals during the
    // exact window that winlogon expects the SCM critical-service set to
    // settle. Instead, prime the reconnect back-off so the worker
    // routine's coordinated reconnect path (single claim, exponential
    // back-off, ACCESS_DENIED ceiling already in place) drives the very
    // first attempt 3 s into the future. Honors the 5-strike
    // ACCESS_DENIED ceiling already implemented in ConnectFilterPort.
    if (m_impl->config.enableFilterPort) {
        constexpr uint32_t kFilterPortFirstConnectGraceMs = 3000;
        m_reconnectBackoffMs.store(kFilterPortFirstConnectGraceMs,
                                   std::memory_order_release);
        ::ShadowStrikeAppendBootTrace(L"ipc-Start-ConnectFilterPort-deferred-3s");
        Utils::Logger::Info(
            "[IPCManager] Filter port first-connect deferred {} ms "
            "(boot-grace; reconnect path handles the attempt)",
            kFilterPortFirstConnectGraceMs);
    } else {
        ::ShadowStrikeAppendBootTrace(L"ipc-Start-ConnectFilterPort-disabled");
    }

    // Start worker threads
    uint32_t numWorkers = (workerThreadCount > 0)
                          ? workerThreadCount
                          : m_impl->config.workerThreadCount;

    if (numWorkers == 0) {
        numWorkers = std::thread::hardware_concurrency();
        if (numWorkers == 0) numWorkers = 4;  // Fallback
    }

    m_workerThreads.reserve(numWorkers);

    for (uint32_t i = 0; i < numWorkers; ++i) {
        try {
            m_workerThreads.emplace_back(&IPCManager::WorkerRoutine, this);
        } catch (const std::system_error& e) {
            Utils::Logger::Error("[IPCManager] Failed to create worker thread {}: {}",
                                 i, e.what());
        }
    }

    if (m_workerThreads.empty()) {
        ::ShadowStrikeAppendBootTrace(L"ipc-Start-NoWorkers-FAIL");
        Utils::Logger::Error("[IPCManager] No worker threads created");
        m_running.store(false);
        m_status.store(IPCStatus::Error);
        return false;
    }

    {
        wchar_t tag[80];
        swprintf(tag, _countof(tag), L"ipc-Start-leave-workers=%zu",
                 m_workerThreads.size());
        ::ShadowStrikeAppendBootTrace(tag);
    }

    Utils::Logger::Info("[IPCManager] Started with {} worker threads",
                        m_workerThreads.size());

    return true;
}

void IPCManager::Stop() {
    if (!m_running.load(std::memory_order_acquire)) {
        return;
    }

    Utils::Logger::Info("[IPCManager] Stopping...");
    m_status.store(IPCStatus::Stopping);
    m_running.store(false, std::memory_order_release);

    // Re-gate scan servicing until the engine re-signals readiness on next start.
    m_scanServicingReady.store(false, std::memory_order_release);

    // Signal shutdown event
    if (m_impl->shutdownEvent != nullptr) {
        SetEvent(m_impl->shutdownEvent);
    }

    // Post completion packets to wake up IOCP workers
    if (m_hIOCP != nullptr) {
        for (size_t i = 0; i < m_workerThreads.size(); ++i) {
            PostQueuedCompletionStatus(m_hIOCP, 0, 0, nullptr);
        }
    }

    // Cancel any pending filter operations
    {
        HANDLE hPort = m_hPort.load(std::memory_order_acquire);
        if (hPort != nullptr) {
            CancelIoEx(hPort, nullptr);
        }
    }

    // Worker threads block in m_primaryConnection->GetMessage(); cancelling the
    // liveness gate handle above no longer wakes them. Cancel the encrypted
    // primary-scanner connection's pending I/O now so each worker observes
    // m_running == false and exits — otherwise the join() below would deadlock.
    // Disconnect() is idempotent; DisconnectFilterPort() performs the full
    // teardown (key scrub + handle close + reset).
    {
        std::shared_ptr<FilterConnection> conn;
        {
            std::lock_guard<std::mutex> connLock(m_primaryConnMutex);
            conn = m_primaryConnection;
        }
        if (conn) {
            conn->Disconnect();
        }
    }

    // Wait for all workers to finish
    for (auto& thread : m_workerThreads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    m_workerThreads.clear();

    // Disconnect channels
    DisconnectFilterPort();
    DisconnectPipe();

    m_status.store(IPCStatus::Stopped);
    Utils::Logger::Info("[IPCManager] Stopped");
}

void IPCManager::Shutdown() {
    Stop();

    // Close IOCP handle
    if (m_hIOCP != nullptr) {
        CloseHandle(m_hIOCP);
        m_hIOCP = nullptr;
    }

    // Close all shared memory regions
    {
        std::unique_lock lock(m_sharedMemoryMutex);
        for (auto& [name, region] : m_sharedMemory) {
            if (region.baseAddress != nullptr) {
                UnmapViewOfFile(region.baseAddress);
                region.baseAddress = nullptr;
            }
            if (region.mappingHandle != nullptr) {
                CloseHandle(region.mappingHandle);
                region.mappingHandle = nullptr;
            }
            if (region.eventHandle != nullptr) {
                CloseHandle(region.eventHandle);
                region.eventHandle = nullptr;
            }
        }
        m_sharedMemory.clear();
    }

    // Clear pending replies
    {
        std::lock_guard lock(m_impl->pendingMutex);
        m_impl->pendingReplies.clear();
    }

    m_status.store(IPCStatus::Uninitialized);
    Utils::Logger::Info("[IPCManager] Shutdown complete");
}

bool IPCManager::IsInitialized() const noexcept {
    auto status = m_status.load(std::memory_order_acquire);
    return status != IPCStatus::Uninitialized && status != IPCStatus::Error;
}

bool IPCManager::IsConnected() const noexcept {
    return m_connected.load(std::memory_order_acquire);
}

IPCStatus IPCManager::GetStatus() const noexcept {
    return m_status.load(std::memory_order_acquire);
}

bool IPCManager::UpdateConfiguration(const IPCConfiguration& config) {
    if (!config.IsValid()) {
        Utils::Logger::Error("[IPCManager] Invalid configuration");
        return false;
    }

    std::unique_lock lock(m_impl->configMutex);
    m_impl->config = config;

    Utils::Logger::Info("[IPCManager] Configuration updated");
    return true;
}

IPCConfiguration IPCManager::GetConfiguration() const {
    std::shared_lock lock(m_impl->configMutex);
    return m_impl->config;
}

// ============================================================================
// FILTER PORT OPERATIONS
// ============================================================================

bool IPCManager::ConnectFilterPort() {
    // FIX [BUG #17]: Serialize concurrent connect attempts. Multiple worker
    // threads detecting a null m_hPort would otherwise race here, leaking
    // FilterConnectCommunicationPort handles and constructing duplicate
    // primary/push FilterConnection instances.
    std::lock_guard<std::mutex> connectLock(m_connectMutex);

    if (m_hPort.load(std::memory_order_acquire) != nullptr) {
        Utils::Logger::Debug("[IPCManager] Filter port already connected");
        return true;
    }

    std::wstring portName;
    {
        std::shared_lock lock(m_impl->configMutex);
        portName = m_impl->config.filterPortName;
    }

    Utils::Logger::Info("[IPCManager] Connecting to filter port: {}",
                        Utils::StringUtils::ToNarrow(portName));

    // Ensure PhantomSensor minifilter is resident in the kernel before
    // attempting the port connect.  The driver service is registered as
    // SERVICE_DEMAND_START (SYSTEM_START triggers an early-boot bugcheck
    // tracked separately), so without this call the filter is absent on
    // every reboot and FilterConnectCommunicationPort fails with
    // ERROR_FILE_NOT_FOUND / ERROR_ACCESS_DENIED.  Idempotent and cheap.
    const HRESULT ensureHr = EnsurePhantomMinifilterLoaded();
    if (FAILED(ensureHr)) {
        m_lastFilterPortHr = ensureHr;
        m_impl->NotifyError("Minifilter load failed",
                            static_cast<int>(ensureHr));
        // Fall through to FilterConnect: it may still succeed if the filter
        // was loaded by another agent in the interim.  The connect failure
        // path below carries the authoritative diagnostic for the user.
    }

    // FIX [BUG #11]: Use temp handle — FilterConnectCommunicationPort writes
    // directly to &handle. Storing into atomic<HANDLE> address isn't portable.
    HANDLE hPortTemp = nullptr;
    HRESULT hr = FilterPortGate::Connect(
        portName,
        nullptr,
        0,
        &hPortTemp,
        "IPCManager"
    );

    if (FAILED(hr)) {
        m_lastFilterPortHr = hr;

        if (hr == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)) {
            const uint32_t streak =
                m_accessDeniedStreak.fetch_add(1, std::memory_order_acq_rel) + 1;

            // First N attempts log at error level; once we reach the ceiling
            // we transition the IPCManager to a *terminal* error state and
            // stop trying entirely. ACCESS_DENIED from the filter port is a
            // structural denial (port DACL rejected SYSTEM, or the kernel
            // ConnectNotify callback rejected this exe). Retrying does not
            // help — only re-install, service-identity fix, or driver
            // rebuild will. Continuing to hammer the kernel just pollutes
            // logs and burns CPU.
            if (streak <= kAccessDeniedAttemptCeiling) {
                Utils::Logger::Error(
                    "[IPCManager] FilterConnectCommunicationPort ACCESS_DENIED "
                    "(attempt {}/{}) - driver port DACL rejected SYSTEM, or "
                    "ConnectNotify rejected this exe ({}). Check driver DbgView "
                    "for '[ShadowStrike] ConnectNotify DENY' log line.",
                    streak, kAccessDeniedAttemptCeiling,
                    Utils::StringUtils::ToNarrow(portName));
            }

            if (streak >= kAccessDeniedAttemptCeiling) {
                if (!m_filterPortPermanentlyDenied.exchange(
                        true, std::memory_order_acq_rel)) {
                    Utils::Logger::Error(
                        "[IPCManager] Filter port permanently denied after {} "
                        "consecutive ACCESS_DENIED responses. Disabling further "
                        "reconnect attempts. UI should surface 'Driver "
                        "communication denied - service token / signed image "
                        "mismatch - check ShadowStrikePhantomService.exe path "
                        "and signature' (0x80070005).", streak);
                    m_status.store(IPCStatus::Error, std::memory_order_release);
                    m_impl->NotifyConnectionChange(
                        ChannelType::FilterPort, ConnectionStatus::Error);
                    m_impl->NotifyError(
                        "Driver communication denied (0x80070005). The kernel "
                        "driver rejected this service's identity. Re-run the "
                        "installer or contact support.",
                        static_cast<int>(hr));
                }
            }
        } else if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
            // Transient: driver may still be coming up; keep trying.
            Utils::Logger::Warn(
                "[IPCManager] FilterConnectCommunicationPort: driver port not "
                "yet present ({}). Will retry.",
                Utils::StringUtils::ToNarrow(portName));
        } else {
            Utils::Logger::Error(
                "[IPCManager] FilterConnectCommunicationPort failed: 0x{:08X}",
                static_cast<unsigned int>(hr));
        }

        m_impl->NotifyError("Filter port connection failed", static_cast<int>(hr));
        return false;
    }

    // On success, reset the denial streak so a stale state from a previous
    // boot cycle cannot poison this session.
    m_accessDeniedStreak.store(0, std::memory_order_release);
    m_filterPortPermanentlyDenied.store(false, std::memory_order_release);
    m_lastFilterPortHr = S_OK;

    // Associate with IOCP AFTER the gate key-exchange drain below. The drain
    // issues an overlapped FilterGetMessage with a stack OVERLAPPED; if the
    // handle were associated with the completion port first, that operation's
    // completion packet (referencing the stack OVERLAPPED) would be queued to
    // the port and outlive this scope, leaving a dangling pointer in the IOCP
    // queue. Associating afterward means the drain only signals its own event
    // and queues nothing.
    m_hPort.store(hPortTemp, std::memory_order_release);
    m_connected.store(true, std::memory_order_release);
    m_impl->NotifyConnectionChange(ChannelType::FilterPort, ConnectionStatus::Connected);

    // The raw m_hPort connection occupies a kernel client-port slot but is NOT
    // the primary scanner — the kernel sends it exactly one message: the
    // post-connect key-exchange blob, delivered via a blocking FltSendMessage.
    // The receive workers now pump the dedicated primary-scanner connection
    // (m_primaryConnection), not this handle, so nothing would otherwise retire
    // that pending kernel send. Drain it once here so the kernel's
    // FltSendMessage completes and the slot is kept alive instead of being
    // force-closed after its 30s timeout. We intentionally do not process the
    // key material: this handle is a connect/liveness gate only and is never
    // used for encrypted I/O.
    {
        std::vector<uint8_t> kexDrain(1024, 0);
        OVERLAPPED ov{};
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (ov.hEvent != nullptr) {
            HRESULT drainHr = FilterGetMessage(
                hPortTemp,
                reinterpret_cast<PFILTER_MESSAGE_HEADER>(kexDrain.data()),
                static_cast<DWORD>(kexDrain.size()),
                &ov);

            if (drainHr == HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
                if (WaitForSingleObject(ov.hEvent, 10000) != WAIT_OBJECT_0) {
                    // Cancel and fully drain the I/O before the OVERLAPPED on
                    // the stack goes out of scope, so the kernel can never write
                    // to freed memory.
                    CancelIoEx(hPortTemp, &ov);
                    DWORD ignored = 0;
                    GetOverlappedResult(hPortTemp, &ov, &ignored, TRUE);
                    Utils::Logger::Warn("[IPCManager] Gate key-exchange drain timed out "
                                        "on liveness connection");
                } else {
                    DWORD drained = 0;
                    GetOverlappedResult(hPortTemp, &ov, &drained, FALSE);
                    Utils::Logger::Debug("[IPCManager] Gate key-exchange drained ({} bytes)",
                                         drained);
                }
            } else if (SUCCEEDED(drainHr)) {
                DWORD drained = 0;
                GetOverlappedResult(hPortTemp, &ov, &drained, FALSE);
                Utils::Logger::Debug("[IPCManager] Gate key-exchange drained synchronously "
                                     "({} bytes)", drained);
            } else {
                Utils::Logger::Warn("[IPCManager] Gate key-exchange drain failed: 0x{:08X}",
                                    static_cast<unsigned int>(drainHr));
            }

            CloseHandle(ov.hEvent);
        }
        Utils::Logger::Debug("[IPCManager] Gate key-exchange drain complete");
        SecureZeroMemory(kexDrain.data(), kexDrain.size());
    }

    // Now that the bounded overlapped drain has fully completed (its stack
    // OVERLAPPED is retired), associate the gate handle with the IOCP for any
    // future async operations. No completion packet can reference freed memory.
    if (m_hIOCP != nullptr) {
        HANDLE result = CreateIoCompletionPort(
            hPortTemp,
            m_hIOCP,
            reinterpret_cast<ULONG_PTR>(hPortTemp),
            0
        );

        if (result == nullptr) {
            Utils::Logger::Warn("[IPCManager] Failed to associate port with IOCP: {}",
                               GetLastError());
        }
    }

    // Create dedicated push connection + ThreatIntelPusher
    {
        std::lock_guard lock(m_pusherMutex);
        try {
            m_pushConnection = std::make_unique<FilterConnection>(portName);
            if (m_pushConnection->Connect()) {
                m_pusher = std::make_unique<ThreatIntelPusher>(*m_pushConnection);
                Utils::Logger::Info("[IPCManager] ThreatIntelPusher created on dedicated push connection");
            } else {
                Utils::Logger::Warn("[IPCManager] Push connection failed — ThreatIntelPusher unavailable");
                m_pushConnection.reset();
            }
        } catch (const std::exception& e) {
            Utils::Logger::Error("[IPCManager] Failed to create ThreatIntelPusher: {}", e.what());
            m_pusher.reset();
            m_pushConnection.reset();
        }
    }

    // Create primary encrypted connection for kernel scan I/O.
    // This connection registers as the kernel's PRIMARY SCANNER port
    // (ConnectionContext type == 1): the minifilter routes all scan requests
    // and notifications here and gates them on this connection's established
    // session key. The receive workers pump this connection (see WorkerRoutine)
    // and ReplyToKernel replies on it, so the WDK MessageId scope and the
    // session key are always consistent between receive and reply.
    {
        std::lock_guard lock(m_primaryConnMutex);
        try {
            m_primaryConnection = std::make_shared<FilterConnection>(portName);
            if (m_primaryConnection->Connect(/*registerAsPrimaryScanner=*/true)) {
                Utils::Logger::Info("[IPCManager] Primary encrypted scanner connection established");
            } else {
                Utils::Logger::Error("[IPCManager] Primary encrypted scanner connection FAILED — "
                                      "kernel scan requests cannot be served until reconnect");
                m_primaryConnection.reset();
            }
        } catch (const std::exception& e) {
            Utils::Logger::Error("[IPCManager] Failed to create primary FilterConnection: {}",
                                  e.what());
            m_primaryConnection.reset();
        }
    }

    // Connect succeeded — reset reconnect back-off so the next disconnect
    // starts retrying at the configured base interval, not at the cap.
    m_reconnectBackoffMs.store(0, std::memory_order_relaxed);

    // Report the AUTHORITATIVE channel state. The control handle above can
    // open even when the encrypted primary-scanner channel did not establish,
    // so a blanket "Successfully connected" would mask a degraded kernel link.
    bool encryptedChannelUp;
    {
        std::lock_guard lock(m_primaryConnMutex);
        encryptedChannelUp = (m_primaryConnection != nullptr);
    }
    if (encryptedChannelUp) {
        Utils::Logger::Info("[IPCManager] Filter port connected; encrypted primary scanner channel established");
    } else {
        Utils::Logger::Warn("[IPCManager] Filter port connected (control handle only) — encrypted primary "
                            "scanner channel NOT established; kernel scan I/O degraded until reconnect");
    }
    return true;
}

void IPCManager::DisconnectFilterPort() {
    // Tear down primary encrypted connection
    {
        std::lock_guard lock(m_primaryConnMutex);
        if (m_primaryConnection) {
            m_primaryConnection->Disconnect();
            m_primaryConnection.reset();
        }
    }

    // Tear down pusher before closing the port
    {
        std::lock_guard lock(m_pusherMutex);
        m_pusher.reset();
        if (m_pushConnection) {
            m_pushConnection->Disconnect();
            m_pushConnection.reset();
        }
    }

    // FIX [BUG #11]: Atomic exchange prevents double-close race between
    // Stop() and worker threads seeing ERROR_INVALID_HANDLE.
    HANDLE hOld = m_hPort.exchange(nullptr, std::memory_order_acq_rel);
    if (hOld != nullptr) {
        CancelIoEx(hOld, nullptr);
        CloseHandle(hOld);
        m_connected.store(false, std::memory_order_release);

        m_impl->NotifyConnectionChange(ChannelType::FilterPort, ConnectionStatus::Disconnected);
        Utils::Logger::Info("[IPCManager] Disconnected from filter port");
    }
}

bool IPCManager::IsFilterPortConnected() const noexcept {
    return m_hPort.load(std::memory_order_acquire) != nullptr
        && m_connected.load(std::memory_order_acquire);
}

ThreatIntelPusher* IPCManager::GetPusher() noexcept {
    std::lock_guard lock(m_pusherMutex);
    return m_pusher.get();
}

bool IPCManager::SendToKernel(
    const void* message,
    size_t messageSize,
    void* reply,
    size_t* replySize,
    uint32_t timeoutMs) {

    if (message == nullptr || messageSize == 0) {
        Utils::Logger::Error("[IPCManager] Invalid message parameters");
        return false;
    }

    if (messageSize > IPCConstants::MAX_MESSAGE_SIZE) {
        Utils::Logger::Error("[IPCManager] Message too large: {} > {}",
                             messageSize, IPCConstants::MAX_MESSAGE_SIZE);
        return false;
    }

    // FIX [BUG #7]: Guard against reply != nullptr && replySize == nullptr
    if (reply != nullptr && replySize == nullptr) {
        Utils::Logger::Error("[IPCManager] reply buffer provided but replySize is null");
        return false;
    }

    auto startTime = Clock::now();

    // Wait briefly for the channel, but ONLY before it has ever come up.
    //
    // Refusing to send is correct - we never fall back to plaintext - but simply
    // dropping was not, because these 31 call sites carry two very different
    // kinds of traffic. Some are one-shot events (a ransomware block request, a
    // script block) where a loss is a missed action. Others push CONFIGURATION
    // the kernel needs for the rest of the session: the protected registry key
    // list (RegistryProtection), protected process and file sets
    // (ProcessProtection, FileProtection), the self-defense config (SelfDefense),
    // the ROP pattern database, honeypot registrations. Dropping one of those
    // leaves the corresponding kernel-side protection permanently unconfigured,
    // silently, for the whole session - the same silent-inertness failure mode
    // that has already cost this project several inert detection modules.
    //
    // The observed drops are a startup ordering race: config pushes run before
    // the port is established. Waiting a bounded moment resolves the race without
    // relaxing the plaintext refusal. The wait is deliberately confined to the
    // never-yet-connected case: once the channel has been up, a failure means a
    // teardown or reconnect, where the reconnect path owns recovery and blocking
    // a caller (including ransomware-response paths) would be harmful.
    {
        std::lock_guard lock(m_primaryConnMutex);
        m_everConnected = m_everConnected ||
                          (m_primaryConnection && m_primaryConnection->IsConnected());
    }
    if (!m_everConnected) {
        constexpr auto kStartupChannelWait = std::chrono::milliseconds(2000);
        constexpr auto kPollInterval       = std::chrono::milliseconds(25);
        const auto deadline = Clock::now() + kStartupChannelWait;
        while (Clock::now() < deadline) {
            {
                std::lock_guard lock(m_primaryConnMutex);
                if (m_primaryConnection && m_primaryConnection->IsConnected()) {
                    m_everConnected = true;
                    break;
                }
            }
            if (!m_running.load(std::memory_order_acquire)) break;
            std::this_thread::sleep_for(kPollInterval);
        }
        if (m_everConnected) {
            Utils::Logger::Info("[IPCManager] SendToKernel: waited for the encrypted channel "
                                "at startup rather than dropping a {}-byte message", messageSize);
        }
    }

    // Route through FilterConnection for encryption
    {
        std::lock_guard lock(m_primaryConnMutex);
        if (m_primaryConnection && m_primaryConnection->IsConnected()) {
            std::span<const uint8_t> sendBuf(
                static_cast<const uint8_t*>(message), messageSize);

            if (reply && replySize) {
                std::span<uint8_t> replyBuf(
                    static_cast<uint8_t*>(reply), *replySize);
                size_t bytesReturned = m_primaryConnection->SendMessage(
                    sendBuf, replyBuf, timeoutMs);
                *replySize = bytesReturned;
                if (bytesReturned == 0) {
                    m_impl->stats.errors.fetch_add(1, std::memory_order_relaxed);
                    return false;
                }
            } else {
                if (!m_primaryConnection->SendMessageNoReply(sendBuf)) {
                    m_impl->stats.errors.fetch_add(1, std::memory_order_relaxed);
                    return false;
                }
            }

            auto endTime = Clock::now();
            auto latencyUs = std::chrono::duration_cast<std::chrono::microseconds>(
                endTime - startTime).count();

            m_impl->stats.messagesSent.fetch_add(1, std::memory_order_relaxed);
            m_impl->stats.bytesSent.fetch_add(messageSize, std::memory_order_relaxed);

            uint64_t currentAvg = m_impl->stats.avgLatencyUs.load(std::memory_order_relaxed);
            m_impl->stats.avgLatencyUs.store(
                (currentAvg * 95 + static_cast<uint64_t>(latencyUs) * 5) / 100,
                std::memory_order_relaxed);

            uint64_t currentMax = m_impl->stats.maxLatencyUs.load(std::memory_order_relaxed);
            uint64_t newLatency = static_cast<uint64_t>(latencyUs);
            while (newLatency > currentMax) {
                if (m_impl->stats.maxLatencyUs.compare_exchange_weak(
                        currentMax, newLatency, std::memory_order_relaxed)) {
                    break;
                }
            }

            return true;
        }
    }

    // Still no channel. Refusing is correct - plaintext is never an option - but
    // report enough to identify WHAT was lost. An anonymous "channel unavailable"
    // cannot distinguish a dropped one-shot event from a dropped configuration
    // push that leaves a kernel protection unconfigured for the session, and that
    // distinction is the difference between a missed action and a silent gap.
    {
        uint32_t msgType = 0;
        if (messageSize >= sizeof(SHADOWSTRIKE_MESSAGE_HEADER)) {
            msgType = reinterpret_cast<const SHADOWSTRIKE_MESSAGE_HEADER*>(message)->MessageType;
        }
        Utils::Logger::Error("[IPCManager] SendToKernel: encrypted channel unavailable; "
                             "refusing plaintext fallback - DROPPED messageType={} size={} "
                             "everConnected={}. If this carried protection configuration, that "
                             "configuration is now absent kernel-side until it is re-pushed.",
                             msgType, messageSize, m_everConnected ? "yes" : "no");
    }
    m_impl->stats.errors.fetch_add(1, std::memory_order_relaxed);
    return false;
}

// ============================================================================
// NAMED PIPE OPERATIONS
// ============================================================================

bool IPCManager::CreatePipeServer(const std::wstring& pipeName) {
    if (m_hPipe != nullptr) {
        Utils::Logger::Warn("[IPCManager] Pipe server already exists");
        return false;
    }

    // Create secure DACL for pipe
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, FALSE };
    if (!CreateSecurePipeDacl(sa)) {
        Utils::Logger::Warn("[IPCManager] Failed to create secure DACL, using default");
    }

    m_hPipe = CreateNamedPipeW(
        pipeName.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1,  // FIX [BUG #16]: Single instance prevents named pipe squatting attacks
        static_cast<DWORD>(IPCConstants::MAX_MESSAGE_SIZE),
        static_cast<DWORD>(IPCConstants::MAX_MESSAGE_SIZE),
        0,
        &sa
    );

    // Free security descriptor if allocated
    if (sa.lpSecurityDescriptor != nullptr) {
        LocalFree(sa.lpSecurityDescriptor);
    }

    if (m_hPipe == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        Utils::Logger::Error("[IPCManager] CreateNamedPipe failed: {}", error);
        m_hPipe = nullptr;
        return false;
    }

    Utils::Logger::Info("[IPCManager] Created pipe server: {}",
                        Utils::StringUtils::ToNarrow(pipeName));
    return true;
}

bool IPCManager::ConnectToPipe(const std::wstring& pipeName) {
    // Wait for pipe to be available
    if (!WaitNamedPipeW(pipeName.c_str(), 5000)) {
        Utils::Logger::Error("[IPCManager] Pipe not available: {}", GetLastError());
        return false;
    }

    m_hPipe = CreateFileW(
        pipeName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        nullptr
    );

    if (m_hPipe == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        Utils::Logger::Error("[IPCManager] Failed to connect to pipe: {}", error);
        m_hPipe = nullptr;
        return false;
    }

    // Set message mode
    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(m_hPipe, &mode, nullptr, nullptr)) {
        Utils::Logger::Warn("[IPCManager] Failed to set pipe message mode: {}",
                            GetLastError());
    }

    Utils::Logger::Info("[IPCManager] Connected to pipe: {}",
                        Utils::StringUtils::ToNarrow(pipeName));
    return true;
}

void IPCManager::DisconnectPipe() {
    // FIX [BUG #18]: Atomic exchange prevents racing Send/Disconnect from
    // double-closing the pipe handle when Stop() runs concurrently with
    // an in-flight SendCommand path.
    HANDLE hOld = m_hPipe.exchange(nullptr, std::memory_order_acq_rel);
    if (hOld != nullptr) {
        FlushFileBuffers(hOld);
        DisconnectNamedPipe(hOld);
        CloseHandle(hOld);
        Utils::Logger::Info("[IPCManager] Pipe disconnected");
    }
}

bool IPCManager::SendPipeMessage(const void* data, size_t size) {
    if (data == nullptr || size == 0) {
        return false;
    }

    // FIX [BUG #19]: Cap outbound pipe writes at MAX_MESSAGE_SIZE. Without
    // this, a malformed caller could pass a multi-gigabyte buffer that the
    // peer's receive ring buffer is not sized for, dead-locking the pipe.
    if (size > IPCConstants::MAX_MESSAGE_SIZE) {
        Utils::Logger::Error("[IPCManager] SendPipeMessage rejected: {} > MAX_MESSAGE_SIZE ({})",
                             size, IPCConstants::MAX_MESSAGE_SIZE);
        m_impl->stats.errors.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    // FIX [BUG #18]: Snapshot pipe handle once so a concurrent DisconnectPipe
    // cannot close it between the null-check and the WriteFile call.
    HANDLE hPipe = m_hPipe.load(std::memory_order_acquire);
    if (hPipe == nullptr) {
        Utils::Logger::Error("[IPCManager] Cannot send - pipe not connected");
        return false;
    }

    DWORD bytesWritten = 0;
    OVERLAPPED overlapped = {};
    overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    if (overlapped.hEvent == nullptr) {
        return false;
    }

    BOOL result = WriteFile(
        hPipe,
        data,
        static_cast<DWORD>(size),
        &bytesWritten,
        &overlapped
    );

    if (!result) {
        DWORD error = GetLastError();
        if (error == ERROR_IO_PENDING) {
            // Wait for completion
            DWORD waitResult = WaitForSingleObject(overlapped.hEvent, 5000);
            if (waitResult == WAIT_OBJECT_0) {
                GetOverlappedResult(hPipe, &overlapped, &bytesWritten, FALSE);
            } else {
                // FIX [BUG #8]: After CancelIoEx, MUST drain with
                // GetOverlappedResult(bWait=TRUE) before OVERLAPPED goes out
                // of scope. Without this, the kernel may write to freed stack.
                CancelIoEx(hPipe, &overlapped);
                GetOverlappedResult(hPipe, &overlapped, &bytesWritten, TRUE);
                CloseHandle(overlapped.hEvent);
                return false;
            }
        } else {
            CloseHandle(overlapped.hEvent);
            return false;
        }
    }

    CloseHandle(overlapped.hEvent);

    m_impl->stats.messagesSent++;
    m_impl->stats.bytesSent += bytesWritten;

    return bytesWritten == static_cast<DWORD>(size);
}

void IPCManager::SendCommand(const std::string& cmd) {
    if (!cmd.empty()) {
        if (!SendPipeMessage(cmd.data(), cmd.size())) {
            Utils::Logger::Warn("[IPCManager] Failed to send command over named pipe");
            m_impl->stats.errors++;
        }
    }
}

// ============================================================================
// SHARED MEMORY OPERATIONS
// ============================================================================

bool IPCManager::CreateSharedMemory(const std::wstring& name, size_t size, bool writable) {
    std::unique_lock lock(m_sharedMemoryMutex);

    if (m_sharedMemory.contains(name)) {
        Utils::Logger::Warn("[IPCManager] Shared memory already exists: {}",
                            Utils::StringUtils::ToNarrow(name));
        return true;  // Already exists, consider it success
    }

    SharedMemoryRegion region;
    region.name = name;
    region.size = size;
    region.isWritable = writable;

    // FIX [BUG #13]: Create restricted SECURITY_ATTRIBUTES (SYSTEM + Admins only)
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, FALSE };
    PSECURITY_DESCRIPTOR pSD = nullptr;

    // SDDL: D:P(A;;GA;;;SY)(A;;GA;;;BA) = SYSTEM full + Admins full, deny all others
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;SY)(A;;GA;;;BA)",
            SDDL_REVISION_1,
            &pSD,
            nullptr)) {
        sa.lpSecurityDescriptor = pSD;
    } else {
        Utils::Logger::Warn("[IPCManager] Failed to create shared memory DACL: {}", GetLastError());
    }

    // Create file mapping
    region.mappingHandle = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        &sa,
        writable ? PAGE_READWRITE : PAGE_READONLY,
        static_cast<DWORD>(size >> 32),
        static_cast<DWORD>(size & 0xFFFFFFFF),
        name.c_str()
    );

    // FIX [BUG #21]: Detect named-mapping squatting BEFORE freeing pSD.
    // If an attacker pre-created the mapping with a permissive DACL, our
    // SECURITY_ATTRIBUTES are silently ignored — CreateFileMapping returns
    // a handle to the existing object. ERROR_ALREADY_EXISTS reveals this.
    DWORD mappingErr = (region.mappingHandle != nullptr) ? GetLastError() : ERROR_SUCCESS;

    if (pSD != nullptr) {
        LocalFree(pSD);
    }

    if (region.mappingHandle == nullptr) {
        Utils::Logger::Error("[IPCManager] CreateFileMapping failed: {}", GetLastError());
        return false;
    }

    if (mappingErr == ERROR_ALREADY_EXISTS) {
        Utils::Logger::Error("[IPCManager] Refusing to use pre-existing shared mapping '{}' "
                             "(possible squatting attack)",
                             Utils::StringUtils::ToNarrow(name));
        CloseHandle(region.mappingHandle);
        return false;
    }

    // Map view of file
    region.baseAddress = MapViewOfFile(
        region.mappingHandle,
        writable ? FILE_MAP_ALL_ACCESS : FILE_MAP_READ,
        0, 0, size
    );

    if (region.baseAddress == nullptr) {
        Utils::Logger::Error("[IPCManager] MapViewOfFile failed: {}", GetLastError());
        CloseHandle(region.mappingHandle);
        return false;
    }

    // Create signaling event with the same restricted DACL as the mapping.
    // FIX [BUG #22]: Without an explicit SD the event inherits a default DACL
    // that allows the interactive user to set/reset it, which would let any
    // local process spoof "data ready" or starve consumers.
    SECURITY_ATTRIBUTES eventSa = { sizeof(SECURITY_ATTRIBUTES), nullptr, FALSE };
    PSECURITY_DESCRIPTOR pEventSD = nullptr;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;SY)(A;;GA;;;BA)",
            SDDL_REVISION_1,
            &pEventSD,
            nullptr)) {
        eventSa.lpSecurityDescriptor = pEventSD;
    }

    std::wstring eventName = name + L"_Event";
    region.eventHandle = CreateEventW(&eventSa, FALSE, FALSE, eventName.c_str());
    DWORD eventErr = (region.eventHandle != nullptr) ? GetLastError() : ERROR_SUCCESS;

    if (pEventSD != nullptr) {
        LocalFree(pEventSD);
    }

    if (region.eventHandle != nullptr && eventErr == ERROR_ALREADY_EXISTS) {
        Utils::Logger::Error("[IPCManager] Refusing pre-existing event object '{}' "
                             "(possible squatting attack)",
                             Utils::StringUtils::ToNarrow(eventName));
        CloseHandle(region.eventHandle);
        UnmapViewOfFile(region.baseAddress);
        CloseHandle(region.mappingHandle);
        return false;
    }

    m_sharedMemory[name] = std::move(region);

    Utils::Logger::Info("[IPCManager] Created shared memory: {} ({} bytes)",
                        Utils::StringUtils::ToNarrow(name), size);
    return true;
}

bool IPCManager::OpenSharedMemory(const std::wstring& name, bool writable) {
    std::unique_lock lock(m_sharedMemoryMutex);

    if (m_sharedMemory.contains(name)) {
        return true;
    }

    SharedMemoryRegion region;
    region.name = name;
    region.isWritable = writable;

    region.mappingHandle = OpenFileMappingW(
        writable ? FILE_MAP_ALL_ACCESS : FILE_MAP_READ,
        FALSE,
        name.c_str()
    );

    if (region.mappingHandle == nullptr) {
        Utils::Logger::Error("[IPCManager] OpenFileMapping failed: {}", GetLastError());
        return false;
    }

    region.baseAddress = MapViewOfFile(
        region.mappingHandle,
        writable ? FILE_MAP_ALL_ACCESS : FILE_MAP_READ,
        0, 0, 0
    );

    if (region.baseAddress == nullptr) {
        Utils::Logger::Error("[IPCManager] MapViewOfFile failed: {}", GetLastError());
        CloseHandle(region.mappingHandle);
        return false;
    }

    // FIX [BUG #23]: VirtualQuery returns the size of the contiguously-committed
    // region, which a hostile producer could grow far beyond what we expect.
    // Cap against MAX_MAPPING_SIZE before storing so subsequent consumers cannot
    // be tricked into reading past our ConfiguredSize.
    constexpr size_t kMaxMappingSize = static_cast<size_t>(1) << 30;  // 1 GiB hard cap
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(region.baseAddress, &mbi, sizeof(mbi))) {
        if (mbi.RegionSize == 0 || mbi.RegionSize > kMaxMappingSize) {
            Utils::Logger::Error("[IPCManager] OpenSharedMemory rejected '{}': region size {} "
                                 "out of bounds",
                                 Utils::StringUtils::ToNarrow(name),
                                 static_cast<uint64_t>(mbi.RegionSize));
            UnmapViewOfFile(region.baseAddress);
            CloseHandle(region.mappingHandle);
            return false;
        }
        region.size = mbi.RegionSize;
    } else {
        Utils::Logger::Error("[IPCManager] VirtualQuery failed for '{}': {}",
                             Utils::StringUtils::ToNarrow(name), GetLastError());
        UnmapViewOfFile(region.baseAddress);
        CloseHandle(region.mappingHandle);
        return false;
    }

    // Open signaling event
    std::wstring eventName = name + L"_Event";
    region.eventHandle = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, eventName.c_str());

    m_sharedMemory[name] = std::move(region);
    return true;
}

void* IPCManager::GetSharedMemoryPtr(const std::wstring& name) {
    std::shared_lock lock(m_sharedMemoryMutex);
    auto it = m_sharedMemory.find(name);
    return (it != m_sharedMemory.end()) ? it->second.baseAddress : nullptr;
}

void IPCManager::SignalSharedMemory(const std::wstring& name) {
    std::shared_lock lock(m_sharedMemoryMutex);
    auto it = m_sharedMemory.find(name);
    if (it != m_sharedMemory.end() && it->second.eventHandle != nullptr) {
        SetEvent(it->second.eventHandle);
    }
}

bool IPCManager::WaitSharedMemory(const std::wstring& name, uint32_t timeoutMs) {
    HANDLE eventHandle = nullptr;
    {
        std::shared_lock lock(m_sharedMemoryMutex);
        auto it = m_sharedMemory.find(name);
        if (it != m_sharedMemory.end()) {
            eventHandle = it->second.eventHandle;
        }
    }

    if (eventHandle == nullptr) {
        return false;
    }

    return WaitForSingleObject(eventHandle, timeoutMs) == WAIT_OBJECT_0;
}

void IPCManager::CloseSharedMemory(const std::wstring& name) {
    std::unique_lock lock(m_sharedMemoryMutex);
    auto it = m_sharedMemory.find(name);
    if (it != m_sharedMemory.end()) {
        if (it->second.baseAddress != nullptr) {
            UnmapViewOfFile(it->second.baseAddress);
        }
        if (it->second.mappingHandle != nullptr) {
            CloseHandle(it->second.mappingHandle);
        }
        if (it->second.eventHandle != nullptr) {
            CloseHandle(it->second.eventHandle);
        }
        m_sharedMemory.erase(it);
        Utils::Logger::Info("[IPCManager] Closed shared memory: {}",
                            Utils::StringUtils::ToNarrow(name));
    }
}

// ============================================================================
// HANDLER REGISTRATION
// ============================================================================

void IPCManager::RegisterFileScanHandler(FileScanCallback handler) {
    std::lock_guard lock(m_handlerMutex);
    m_fileScanHandler = std::move(handler);
    Utils::Logger::Info("[IPCManager] Registered file scan handler");
}

void IPCManager::RegisterProcessHandler(ProcessNotifyCallback handler) {
    std::lock_guard lock(m_handlerMutex);
    m_processHandler = std::move(handler);
    Utils::Logger::Info("[IPCManager] Registered process handler");
}

void IPCManager::RegisterImageLoadHandler(ImageLoadCallback handler) {
    std::lock_guard lock(m_handlerMutex);
    m_imageLoadHandler = std::move(handler);
    Utils::Logger::Info("[IPCManager] Registered image load handler");
}

void IPCManager::RegisterRegistryHandler(RegistryOpCallback handler) {
    std::lock_guard lock(m_handlerMutex);
    m_registryHandler = std::move(handler);
    Utils::Logger::Info("[IPCManager] Registered registry handler");
}

void IPCManager::RegisterGenericHandler(GenericMessageCallback handler) {
    std::lock_guard lock(m_handlerMutex);
    m_genericHandler = std::move(handler);
}

void IPCManager::SetMessageCallback(std::function<void(const std::string&)> cb) {
    std::lock_guard lock(m_handlerMutex);
    m_messageCallback = std::move(cb);
}

void IPCManager::UnregisterHandlers() {
    std::lock_guard lock(m_handlerMutex);
    m_fileScanHandler = nullptr;
    m_processHandler = nullptr;
    m_imageLoadHandler = nullptr;
    m_registryHandler = nullptr;
    m_genericHandler = nullptr;
    m_messageCallback = nullptr;
    Utils::Logger::Info("[IPCManager] Unregistered all handlers");
}

// ============================================================================
// CONNECTION MANAGEMENT
// ============================================================================

ConnectionInfo IPCManager::GetConnectionInfo(ChannelType channel) const {
    ConnectionInfo info;
    info.channelType = channel;
    info.lastActivity = Clock::now();

    switch (channel) {
        case ChannelType::FilterPort:
            info.status = m_hPort.load(std::memory_order_acquire) != nullptr
                          ? ConnectionStatus::Connected
                          : ConnectionStatus::Disconnected;
            {
                std::shared_lock lock(m_impl->configMutex);
                info.endpoint = m_impl->config.filterPortName;
            }
            break;

        case ChannelType::NamedPipe:
            info.status = m_hPipe != nullptr
                          ? ConnectionStatus::Connected
                          : ConnectionStatus::Disconnected;
            // Left empty deliberately. This channel has no configured endpoint:
            // the name it used to report came from config.servicePipeName, which
            // was a duplicate of ServiceCommConstants::SERVICE_PIPE_NAME and has
            // been removed, and nothing in this build can open this transport
            // anyway (CreatePipeServer has no callers). Reporting a plausible
            // pipe name for a channel that is never opened is how a status
            // display comes to describe a connection that does not exist - the
            // same class of defect as the UI reporting the driver ONLINE while
            // the kernel channel was refused. An empty endpoint alongside
            // Disconnected is the accurate answer.
            info.endpoint.clear();
            break;

        default:
            info.status = ConnectionStatus::Disconnected;
            break;
    }

    info.messagesReceived = m_impl->stats.messagesReceived.load();
    info.messagesSent = m_impl->stats.messagesSent.load();
    info.bytesReceived = m_impl->stats.bytesReceived.load();
    info.bytesSent = m_impl->stats.bytesSent.load();
    info.reconnectCount = static_cast<uint32_t>(m_impl->stats.reconnects.load());

    return info;
}

std::vector<ConnectionInfo> IPCManager::GetAllConnections() const {
    std::vector<ConnectionInfo> connections;
    connections.reserve(3);

    connections.push_back(GetConnectionInfo(ChannelType::FilterPort));
    connections.push_back(GetConnectionInfo(ChannelType::NamedPipe));
    connections.push_back(GetConnectionInfo(ChannelType::SharedMemory));

    return connections;
}

void IPCManager::Reconnect(ChannelType channel) {
    Utils::Logger::Info("[IPCManager] Reconnecting channel: {}",
                        std::string(GetChannelTypeName(channel)));

    switch (channel) {
        case ChannelType::FilterPort:
            DisconnectFilterPort();
            if (ConnectFilterPort()) {
                m_impl->stats.reconnects++;
            }
            break;

        case ChannelType::NamedPipe:
            // Deliberately does nothing beyond dropping any handle.
            //
            // This branch used to call ConnectToPipe(config.servicePipeName),
            // which was a "reconnect" of a channel nothing ever connects in the
            // first place: CreatePipeServer has no callers and the only caller of
            // ConnectToPipe was this line. It also counted a reconnect in the
            // statistics, so the numbers reported channel recoveries that never
            // happened - a counter that reads healthy for work not done is worse
            // than an absent one.
            //
            // The name it read has been removed as a duplicate of
            // ServiceCommConstants::SERVICE_PIPE_NAME. When this transport is
            // either wired up or removed as its own change, this branch is where
            // a real reconnect belongs, and it must name its channel explicitly.
            DisconnectPipe();
            Utils::Logger::Warn("[IPCManager] Reconnect(NamedPipe): this transport has no "
                                "connect path in this build; nothing to re-establish");
            break;

        default:
            break;
    }
}

// ============================================================================
// CALLBACKS
// ============================================================================

void IPCManager::RegisterConnectionCallback(ConnectionCallback callback) {
    std::lock_guard lock(m_impl->callbackMutex);
    m_impl->connectionCallback = std::move(callback);
}

void IPCManager::RegisterErrorCallback(ErrorCallback callback) {
    std::lock_guard lock(m_impl->callbackMutex);
    m_impl->errorCallback = std::move(callback);
}

void IPCManager::UnregisterCallbacks() {
    std::lock_guard lock(m_impl->callbackMutex);
    m_impl->connectionCallback = nullptr;
    m_impl->errorCallback = nullptr;
}

// ============================================================================
// STATISTICS
// ============================================================================

IPCStatisticsSnapshot IPCManager::GetStatistics() const {
    return TakeSnapshot(m_impl->stats);
}

void IPCManager::ResetStatistics() {
    m_impl->stats.Reset();
    Utils::Logger::Info("[IPCManager] Statistics reset");
}

// ============================================================================
// WORKER ROUTINE - Core message processing loop
// ============================================================================

void IPCManager::WorkerRoutine() {
    {
        std::ostringstream oss;
        oss << std::this_thread::get_id();
        Utils::Logger::Debug("[IPCManager] Worker thread {} started", oss.str());
    }

    // LATENCY-CRITICAL PATH.
    //
    // These workers answer the kernel's scan requests. The minifilter holds the
    // originating file operation until the verdict comes back, so every file
    // open on the machine is waiting on this thread - if it loses the CPU to a
    // background sweep, the whole desktop stalls even while total CPU looks
    // moderate. Name the threads and run them above normal so verdict latency
    // is protected; background monitors run below normal for the same reason.
    ::SetThreadDescription(::GetCurrentThread(), L"SS-KernelScanReply");
    ::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);

    // Reserve a stack region so the process-wide unhandled-exception filter can
    // still run (and hand the crash off to the dumper thread) if a scan on this
    // worker overflows the stack. Without this reserve the filter executes on
    // the already-exhausted stack and the crash minidump comes back 0 bytes.
    {
        ULONG stackGuaranteeBytes = 256u * 1024u;
        (void)::SetThreadStackGuarantee(&stackGuaranteeBytes);
    }

    // Allocate per-thread receive buffer.
    // Wire format: [FILTER_MESSAGE_HEADER (fltmgr, 16 bytes on x64)] [SHADOWSTRIKE_MESSAGE_HEADER (40 bytes)] [payload]
    // Both sizes are asserted - the transport prefix in FilterPortGate.hpp, the
    // application header in MessageProtocol.h - because this comment previously
    // said 12 bytes and nothing contradicted it.
    std::vector<uint8_t> buffer(IPCConstants::MAX_MESSAGE_SIZE);

    // Consecutive "unusable receive" counter: GetMessage returned 0 while the
    // channel still reports connected (integrity / decryption / framing
    // failure). Used to bound a desync spin with escalating back-off; a healthy
    // message resets it. See the received==0 handling below.
    uint32_t badReceiveStreak = 0;
    constexpr uint32_t kBadReceiveResyncThreshold = 16;
    // Applied only once a streak proves the condition is sustained. Modest by
    // design: its whole job is to stop a core spinning, and anything longer
    // starves the reply path that kernel threads are waiting on.
    constexpr uint32_t kSustainedDesyncBackoffMs  = 10;

    while (m_running.load(std::memory_order_acquire)) {
        // Snapshot the encrypted primary-scanner connection. The kernel routes
        // scan requests and notifications exclusively to the primary-scanner
        // slot, so this is the connection we must receive on. shared_ptr keeps
        // the object alive across the (possibly blocking) receive even if
        // DisconnectFilterPort resets m_primaryConnection concurrently.
        std::shared_ptr<FilterConnection> conn;
        {
            std::lock_guard<std::mutex> connLock(m_primaryConnMutex);
            conn = m_primaryConnection;
        }
        if (!conn || !conn->IsConnected()) {
            // If the filter port has been *permanently* denied by the
            // kernel driver, do not even attempt to reconnect — the only
            // outcomes are wasted CPU and log spam. Sleep in short chunks
            // so shutdown is still observed promptly.
            if (m_filterPortPermanentlyDenied.load(std::memory_order_acquire)) {
                for (uint32_t waited = 0;
                     waited < 5000 && m_running.load(std::memory_order_acquire);
                     waited += 250) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(250));
                }
                continue;
            }

            // FIX: Coordinated reconnect with exponential back-off.
            // Previously every worker thread independently looped sleep(100ms)
            // + ConnectFilterPort(), producing up to N×10 ConnectNotify calls
            // per second against the kernel minifilter. During first-boot
            // service start (driver freshly loaded, VMware host under I/O
            // pressure) this storm wedged the guest. Now only one worker
            // owns the reconnect claim at a time; the others idle until the
            // port becomes available again.
            bool expected = false;
            if (!m_reconnectClaim.compare_exchange_strong(
                    expected, true, std::memory_order_acq_rel)) {
                // Another worker is driving reconnect — wait passively.
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                continue;
            }

            // Read configuration snapshot.
            bool wantReconnect;
            uint32_t baseDelayMs;
            {
                std::shared_lock lock(m_impl->configMutex);
                wantReconnect = m_impl->config.autoReconnect &&
                                m_running.load(std::memory_order_acquire);
                baseDelayMs = m_impl->config.reconnectDelayMs;
            }

            if (!wantReconnect) {
                m_reconnectClaim.store(false, std::memory_order_release);
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                continue;
            }

            // Compute current back-off (capped at 30 s) and wait. Use a
            // chunked sleep so shutdown is observed promptly.
            uint32_t backoff = m_reconnectBackoffMs.load(std::memory_order_relaxed);
            if (backoff == 0) {
                backoff = baseDelayMs > 0 ? baseDelayMs : 1000u;
            }
            constexpr uint32_t kReconnectBackoffCapMs = 30000u;
            if (backoff > kReconnectBackoffCapMs) {
                backoff = kReconnectBackoffCapMs;
            }

            for (uint32_t waited = 0;
                 waited < backoff && m_running.load(std::memory_order_acquire);
                 waited += 250) {
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
            }

            if (!m_running.load(std::memory_order_acquire)) {
                m_reconnectClaim.store(false, std::memory_order_release);
                continue;
            }

            const bool ok = ConnectFilterPort();
            if (!ok) {
                Utils::Logger::Debug("[IPCManager] Filter port reconnect attempt failed");
                m_impl->stats.errors.fetch_add(1, std::memory_order_relaxed);
                // Double the back-off (cap 30 s) for the next attempt.
                uint32_t next = backoff * 2u;
                if (next > kReconnectBackoffCapMs) next = kReconnectBackoffCapMs;
                m_reconnectBackoffMs.store(next, std::memory_order_relaxed);
            }
            // Success path resets m_reconnectBackoffMs inside ConnectFilterPort.

            m_reconnectClaim.store(false, std::memory_order_release);
            continue;
        }

        // Receive the next message on the encrypted primary-scanner connection.
        // GetMessage verifies the message HMAC and performs in-place
        // AES-256-GCM decryption, rewriting the SHADOWSTRIKE_MESSAGE_HEADER to
        // plaintext sizes and clearing the ENCRYPTED flag, so the two-header
        // parsing below operates on cleartext exactly as it did on the legacy
        // raw path. A return of 0 means shutdown/cancel, a dropped message that
        // failed integrity/decryption, or a torn-down channel — in every case
        // we re-evaluate the loop guard (and reconnect on the next iteration).
        // Clear the two-header region before every receive.
        //
        // This buffer is allocated once per worker and reused for the life of the
        // thread, and the kernel writes only as many bytes as the frame holds.
        // Without this, a frame shorter than both headers leaves the remaining
        // header bytes holding the tail of the PREVIOUS, larger message - so a
        // runt frame can present a valid Magic and Version it never carried. The
        // length check below is the primary guard; this makes the failure mode
        // deterministic rather than dependent on what happened to be here before.
        //
        // FileSystemFilter's reader already does exactly this, deliberately, with
        // the same reasoning recorded at the memset. This path had the reasoning
        // written down - "the buffer is pooled/reused and NOT zeroed" - without
        // the corresponding clear.
        std::memset(buffer.data(), 0,
                    sizeof(FILTER_MESSAGE_HEADER) + sizeof(SHADOWSTRIKE_MESSAGE_HEADER));

        const auto recv = conn->GetMessage(
            std::span<uint8_t>(buffer.data(), buffer.size()), 0);

        // A frame that failed integrity or decryption still leaves a kernel
        // thread parked inside FltSendMessage, and Filter Manager wrote its
        // MessageId in cleartext ahead of our payload, so it CAN be answered.
        // Answer it before doing anything else.
        //
        // Fail-open with CacheResult = 0 is the correct verdict here, and it does
        // not weaken detection: the driver already degrades an unanswered scan to
        // "not scanned, allowed" once the timeout expires, so the outcome for the
        // file is identical either way. What differs is that a timeout also feeds
        // the scan-bridge circuit breaker, which trips on reply-timeout RATE and
        // then skips the create-path scan entirely for its recovery window. Not
        // answering therefore risks switching scanning off wholesale, which is a
        // far larger loss than one uncached allow. CacheResult = 0 keeps the
        // verdict out of the kernel cache so the very next access is rescanned.
        if (recv.ReplyOwed()) {
            SHADOWSTRIKE_SCAN_VERDICT_REPLY failOpen = {};
            failOpen.MessageId   = 0;   // app-level id was inside the payload we
                                        // could not decrypt; the driver reads only
                                        // Verdict and ThreatScore from a reply.
            failOpen.Verdict     = static_cast<UINT8>(Verdict_Clean);
            failOpen.ThreatScore = 0;
            failOpen.ResultCode  = 0;
            failOpen.CacheResult = 0;   // never cache a verdict we did not compute
            failOpen.CacheTTL    = 0;

            if (!ReplyToKernel(recv.replyOwedId, failOpen)) {
                Utils::Logger::Debug("[IPCManager] Fail-open reply not delivered for "
                                     "messageId {} (waiter already gone)", recv.replyOwedId);
            }

            static std::atomic<uint64_t> s_failOpenReplies{ 0 };
            const uint64_t fo = s_failOpenReplies.fetch_add(1, std::memory_order_relaxed) + 1;
            if (fo == 1 || (fo % 100) == 0) {
                Utils::Logger::Warn("[IPCManager] Answered {} undecryptable frame(s) fail-open "
                                    "to release the kernel waiter - investigate the channel, "
                                    "these are not expected in steady state", fo);
            }
        }

        const size_t received = recv.payloadBytes;
        if (received == 0) {
            if (!m_running.load(std::memory_order_acquire)) {
                Utils::Logger::Debug("[IPCManager] Worker: receive returned 0 during shutdown");
                break;
            }
            if (!conn->IsConnected()) {
                // Channel torn down -> the reconnect path at the top of the loop
                // (with its own coordinated back-off) handles re-establishment.
                m_connected.store(false, std::memory_order_release);
                badReceiveStreak = 0;
                continue;
            }
            // Connected, but the delivered frame was UNUSABLE (integrity /
            // decryption / two-header framing failure -> GetMessage returned 0).
            //
            // WHAT THIS USED TO SAY, AND WHY IT WAS WRONG
            //
            // This block previously attributed the failures to "a kernel-side
            // frame framing/GCM issue" and deferred the real fix, applying
            // escalating back-off from the very first bad frame. The attribution
            // was incorrect and it cost weeks of investigation aimed at the
            // driver. The cause was in user mode, three layers above this line:
            // FilterGetMessage was being called without the mandatory OVERLAPPED
            // on an asynchronous port handle, so the kernel completed the
            // operation after the call returned and wrote the delivered bytes
            // into storage the caller no longer owned. The frames were intact
            // when the driver sent them; we corrupted them on arrival. The field
            // evidence quoted here - 3392 FilterGetMessage failures in 3.3
            // seconds, pegging a core, immediately preceding a process death -
            // was that defect, not a protocol defect.
            //
            // WHY A STREAK GUARD STILL EARNS ITS PLACE
            //
            // Not as a stand-in for a fix, but because busy-waiting on a channel
            // that reports connected while delivering nothing usable is a hazard
            // regardless of what causes it. Keeping a bound here is cheap
            // insurance against a spin; keeping a *diagnosis* here was the
            // mistake.
            //
            // THE COST MODEL IS NOW INVERTED, DELIBERATELY
            //
            // Sleeping from the first bad frame made sense when failures were
            // continuous. After the fix they are rare - 4 in 81 seconds of
            // sustained load, about 0.01% of traffic - and the next frame is
            // almost certainly fine. Sleeping on a one-off therefore delays
            // legitimate scan traffic for nothing, and the old 50 ms ceiling
            // starved the reply path, which made the freeze it was meant to
            // mitigate worse. So: no delay at all until a streak proves the
            // condition is sustained rather than transient, then a bounded sleep
            // purely to stop the spin.
            //
            // The residual bad frames are NOT explained by the fix above and are
            // tracked separately. This guard does not pretend to explain them.
            ++badReceiveStreak;
            if (badReceiveStreak < kBadReceiveResyncThreshold) {
                // Transient: retry immediately, cost nothing.
                continue;
            }

            if (badReceiveStreak == kBadReceiveResyncThreshold) {
                Utils::Logger::Warn(
                    "[IPCManager] {} consecutive unusable receives on a connected "
                    "channel - sustained condition, throttling to avoid a spin. "
                    "Individual frame failures are counted separately.",
                    badReceiveStreak);
                m_impl->stats.errors.fetch_add(1, std::memory_order_relaxed);
            }

            // Sustained only. Fixed and modest: enough to stop a core spinning,
            // short enough that the reply path is not starved.
            std::this_thread::sleep_for(std::chrono::milliseconds(kSustainedDesyncBackoffMs));
            continue;
        }
        badReceiveStreak = 0;  // healthy frame -> reset the bad-receive streak

        // The single length guard for this frame is the two-header check below.
        // A separate `received < sizeof(FILTER_MESSAGE_HEADER)` test used to sit
        // here; it is subsumed, and having two thresholds with two different
        // messages for one condition only made it harder to tell which fired.
        // pWdkHeader is a cast, not a dereference, so forming it here is safe.

        // FILTER_MESSAGE_HEADER (carries the WDK MessageId used for the reply)
        // sits at the start of the decrypted buffer.
        PFILTER_MESSAGE_HEADER pWdkHeader =
            reinterpret_cast<PFILTER_MESSAGE_HEADER>(buffer.data());

        // FIX [BUG #1,#2]: Proper two-header parsing.
        // After FILTER_MESSAGE_HEADER comes SHADOWSTRIKE_MESSAGE_HEADER + payload.
        constexpr size_t kWdkHeaderSize = sizeof(FILTER_MESSAGE_HEADER);
        constexpr size_t kAppHeaderSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER);

        // Bound the RECEIVED byte count, not the allocation.
        //
        // This test used to read `buffer.size() < kWdkHeaderSize + kAppHeaderSize`,
        // which compares against MAX_MESSAGE_SIZE and therefore could never fail -
        // it did not bound the frame at all. Four header fields (Magic, Version,
        // TotalSize, DataSize) were then read unconditionally, so for any frame
        // shorter than both headers some or all of those 40 bytes came from
        // whatever the previous, larger message left in this buffer. The boot log
        // records kernel messages of 1796, 136 and 48 bytes; 48 is short of the 56
        // needed. FilterConnection also returns such a frame unexamined, because a
        // frame that cannot hold a header is not one it can inspect.
        //
        // Getting this wrong does not fail loudly: a stale Magic can make a runt
        // frame look valid, and a valid short frame gets rejected. On this path a
        // rejected frame is a file answered fail-open.
        if (received < kWdkHeaderSize + kAppHeaderSize) {
            Utils::Logger::Warn(
                "[IPCManager] Runt frame: {} bytes received, {} needed for the transport "
                "and application headers; discarding without reading header fields",
                received, static_cast<uint32_t>(kWdkHeaderSize + kAppHeaderSize));
            m_impl->stats.errors.fetch_add(1, std::memory_order_relaxed);
            continue;
        }

        auto* pAppHeader = reinterpret_cast<PSHADOWSTRIKE_MESSAGE_HEADER>(
            buffer.data() + kWdkHeaderSize);

        // Validate magic
        if (pAppHeader->Magic != SHADOWSTRIKE_MESSAGE_MAGIC) {
            Utils::Logger::Warn("[IPCManager] Invalid message magic: 0x{:08X}",
                                pAppHeader->Magic);
            m_impl->stats.errors.fetch_add(1, std::memory_order_relaxed);
            continue;
        }

        // FIX [BUG #20]: Reject mismatched protocol versions.
        // Without this check a downgraded/forged kernel header with stale
        // semantics would be silently parsed against the current PODs.
        if (pAppHeader->Version != SHADOWSTRIKE_PROTOCOL_VERSION) {
            Utils::Logger::Warn("[IPCManager] Unsupported protocol version: {} (expected {})",
                                static_cast<unsigned>(pAppHeader->Version),
                                static_cast<unsigned>(SHADOWSTRIKE_PROTOCOL_VERSION));
            m_impl->stats.errors.fetch_add(1, std::memory_order_relaxed);
            continue;
        }

        // FIX [BUG #20]: Self-consistency check — TotalSize must equal the
        // exact framed size (header + DataSize). Mismatch indicates a malformed
        // or replayed frame and must be discarded before further dispatch.
        if (pAppHeader->TotalSize != kAppHeaderSize + pAppHeader->DataSize) {
            Utils::Logger::Warn("[IPCManager] TotalSize mismatch: total={} hdr+data={}",
                                pAppHeader->TotalSize,
                                static_cast<uint32_t>(kAppHeaderSize + pAppHeader->DataSize));
            m_impl->stats.errors.fetch_add(1, std::memory_order_relaxed);
            continue;
        }

        // Validate DataSize against the bytes actually received this iteration.
        // The buffer is pooled/reused and NOT zeroed between messages, so the
        // framed message (both headers + payload) must fit within `received`;
        // bounding against buffer.size() instead would risk dispatching stale
        // bytes left over from a previous, larger message.
        if (kWdkHeaderSize + kAppHeaderSize + pAppHeader->DataSize > received) {
            Utils::Logger::Error("[IPCManager] DataSize {} exceeds received bounds ({} bytes)",
                                 pAppHeader->DataSize,
                                 received);
            m_impl->stats.errors.fetch_add(1, std::memory_order_relaxed);
            continue;
        }

        m_impl->stats.messagesReceived.fetch_add(1, std::memory_order_relaxed);
        m_impl->stats.bytesReceived.fetch_add(
            kAppHeaderSize + pAppHeader->DataSize, std::memory_order_relaxed);

        // Dispatch with WDK MessageId (needed for FilterReplyMessage)
        DispatchMessage(buffer.data(), pWdkHeader->MessageId);
    }

    {
        std::ostringstream oss;
        oss << std::this_thread::get_id();
        Utils::Logger::Debug("[IPCManager] Worker thread {} exiting", oss.str());
    }
}

void IPCManager::SetScanServicingReady(bool ready) noexcept {
    const bool prev = m_scanServicingReady.exchange(ready, std::memory_order_release);
    if (prev != ready) {
        Utils::Logger::Info("[IPCManager] Scan servicing {} (engine {})",
                            ready ? "ENABLED" : "disabled",
                            ready ? "ready" : "not ready");
    }
}

bool IPCManager::IsScanServicingReady() const noexcept {
    return m_scanServicingReady.load(std::memory_order_acquire);
}

void IPCManager::DispatchMessage(uint8_t* buffer, uint64_t messageId) {
    if (!buffer) return;

    // FIX [BUG #1,#2,#3,#5]: Parse two-header wire format correctly.
    // buffer layout: [FILTER_MESSAGE_HEADER (WDK)] [SHADOWSTRIKE_MESSAGE_HEADER] [payload]
    constexpr size_t kWdkHeaderSize = sizeof(FILTER_MESSAGE_HEADER);
    constexpr size_t kAppHeaderSize = sizeof(SHADOWSTRIKE_MESSAGE_HEADER);

    auto* pAppHeader = reinterpret_cast<PSHADOWSTRIKE_MESSAGE_HEADER>(
        buffer + kWdkHeaderSize);
    uint8_t* pPayload = buffer + kWdkHeaderSize + kAppHeaderSize;

    SHADOWSTRIKE_SCAN_VERDICT verdict = Verdict_Unknown;
    bool needsReply = false;

    // FIX [BUG #14]: Snapshot handlers under lock, invoke outside lock.
    // Holding the mutex during file scan I/O would serialize all worker threads.
    FileScanCallback fileScanHandler;
    ProcessNotifyCallback processHandler;
    ImageLoadCallback imageLoadHandler;
    RegistryOpCallback registryHandler;
    GenericMessageCallback genericHandler;

    {
        std::lock_guard lock(m_handlerMutex);
        fileScanHandler  = m_fileScanHandler;
        processHandler   = m_processHandler;
        imageLoadHandler = m_imageLoadHandler;
        registryHandler  = m_registryHandler;
        genericHandler   = m_genericHandler;
    }

    switch (static_cast<SHADOWSTRIKE_MESSAGE_TYPE>(pAppHeader->MessageType)) {
        case FilterMessageType_ScanRequest: {
            // READY-GATE: until RealTimeProtection has fully initialized, do not
            // route file-create scans into the still-warming-up engine. Reply
            // immediately with a fail-open Verdict_Clean so the kernel gets a
            // fast verdict instead of timing out. This removes the cold-boot
            // scan storm (reply-timeout flood -> login I/O stall) and shrinks
            // the window that drives the concurrent-logging heap corruption.
            if (!m_scanServicingReady.load(std::memory_order_acquire)) {
                verdict = Verdict_Clean;
                needsReply = true;
                auto idxGated = static_cast<size_t>(FilterMessageType_ScanRequest);
                if (idxGated < m_impl->stats.byMessageType.size()) {
                    m_impl->stats.byMessageType[idxGated].fetch_add(1, std::memory_order_relaxed);
                }
                break;
            }
            if (fileScanHandler) {
                if (pAppHeader->DataSize < sizeof(FILE_SCAN_REQUEST)) {
                    Utils::Logger::Error("[IPCManager] Truncated FileScanRequest: {} < {}",
                                         pAppHeader->DataSize, sizeof(FILE_SCAN_REQUEST));
                    break;
                }

                auto* req = reinterpret_cast<PFILE_SCAN_REQUEST>(pPayload);
                try {
                    verdict = fileScanHandler(*req);
                    needsReply = true;
                } catch (const std::exception& e) {
                    Utils::Logger::Error("[IPCManager] File scan handler exception: {}", e.what());
                    verdict = Verdict_Error;
                    needsReply = true;
                }
            }

            auto idx = static_cast<size_t>(FilterMessageType_ScanRequest);
            if (idx < m_impl->stats.byMessageType.size()) {
                m_impl->stats.byMessageType[idx].fetch_add(1, std::memory_order_relaxed);
            }
            break;
        }

        case FilterMessageType_ProcessNotify: {
            if (processHandler) {
                if (pAppHeader->DataSize < sizeof(ProcessNotifyRequest)) {
                    Utils::Logger::Error("[IPCManager] Truncated ProcessNotify payload: {} < {}",
                                         pAppHeader->DataSize, sizeof(ProcessNotifyRequest));
                    break;
                }
                auto* req = reinterpret_cast<ProcessNotifyRequest*>(pPayload);

                // Validate variable-length bounds: imagePathLength + commandLineLength must fit
                uint32_t varOffset = static_cast<uint32_t>(sizeof(ProcessNotifyRequest));
                uint32_t remaining = pAppHeader->DataSize - varOffset;
                if (req->imagePathLength > remaining ||
                    req->commandLineLength > (remaining - req->imagePathLength)) {
                    Utils::Logger::Error("[IPCManager] ProcessNotify variable data exceeds buffer: "
                                         "imgPath={} cmdLine={} available={}",
                                         req->imagePathLength, req->commandLineLength, remaining);
                    break;
                }

                try {
                    verdict = processHandler(*req);
                } catch (const std::exception& e) {
                    Utils::Logger::Error("[IPCManager] Process handler exception: {}", e.what());
                }
            }
            break;
        }

        // =====================================================================
        // IMAGE LOAD NOTIFICATIONS (DLL/driver injection detection)
        // =====================================================================
        case FilterMessageType_ImageLoad: {
            if (imageLoadHandler) {
                if (pAppHeader->DataSize < sizeof(ImageLoadRequest)) {
                    Utils::Logger::Error("[IPCManager] Truncated ImageLoad payload: {} < {}",
                                         pAppHeader->DataSize, sizeof(ImageLoadRequest));
                    break;
                }
                auto* req = reinterpret_cast<ImageLoadRequest*>(pPayload);

                // Validate variable-length bounds
                uint32_t varOffset = static_cast<uint32_t>(sizeof(ImageLoadRequest));
                if (req->imagePathLength > (pAppHeader->DataSize - varOffset)) {
                    Utils::Logger::Error("[IPCManager] ImageLoad imagePath exceeds buffer: {} > {}",
                                         req->imagePathLength, pAppHeader->DataSize - varOffset);
                    break;
                }

                try {
                    verdict = imageLoadHandler(*req);
                } catch (const std::exception& e) {
                    Utils::Logger::Error("[IPCManager] ImageLoad handler exception: {}", e.what());
                }
            } else if (genericHandler) {
                try {
                    genericHandler(FilterMessageType_ImageLoad, pPayload, pAppHeader->DataSize);
                } catch (const std::exception& e) {
                    Utils::Logger::Error("[IPCManager] Generic ImageLoad handler exception: {}", e.what());
                }
            }
            auto idx = static_cast<size_t>(FilterMessageType_ImageLoad);
            if (idx < m_impl->stats.byMessageType.size()) {
                m_impl->stats.byMessageType[idx].fetch_add(1, std::memory_order_relaxed);
            }
            break;
        }

        // =====================================================================
        // REGISTRY NOTIFICATIONS (persistence, defense evasion)
        // =====================================================================
        case FilterMessageType_RegistryNotify: {
            if (registryHandler) {
                if (pAppHeader->DataSize < sizeof(RegistryOpRequest)) {
                    Utils::Logger::Error("[IPCManager] Truncated RegistryNotify payload: {} < {}",
                                         pAppHeader->DataSize, sizeof(RegistryOpRequest));
                    break;
                }
                auto* req = reinterpret_cast<RegistryOpRequest*>(pPayload);

                // Validate variable-length bounds: keyPath + valueName + data must fit.
                //
                // These rejections are CORRECT - a length that overruns the payload must
                // never be trusted - but they used to report no values at all, which is
                // precisely why an observed run of them could not be explained. The
                // producer side has been read and is self-consistent (ScanBridge.c sizes
                // the buffer from the same clamped lengths it writes into the header, with
                // two WCHARs of terminator slack, so its own guards cannot fail), and the
                // layouts are now pinned by static_assert. So a rejection here means the
                // frame did not arrive as the driver built it, and identifying that needs
                // the actual numbers rather than an adjective.
                uint32_t varOffset = static_cast<uint32_t>(sizeof(RegistryOpRequest));
                uint32_t remaining = pAppHeader->DataSize - varOffset;
                const uint32_t declaredTotal =
                    static_cast<uint32_t>(req->keyPathLength) +
                    static_cast<uint32_t>(req->valueNameLength) + req->dataSize;

                if (req->keyPathLength > remaining) {
                    Utils::Logger::Error("[IPCManager] RegistryNotify keyPath exceeds buffer: "
                                         "keyPathLength={} remaining={} DataSize={} "
                                         "valueNameLength={} dataSize={} declaredTotal={} pid={}",
                                         req->keyPathLength, remaining, pAppHeader->DataSize,
                                         req->valueNameLength, req->dataSize, declaredTotal,
                                         req->processId);
                    break;
                }
                remaining -= req->keyPathLength;
                if (req->valueNameLength > remaining) {
                    Utils::Logger::Error("[IPCManager] RegistryNotify valueName exceeds buffer: "
                                         "valueNameLength={} remaining={} DataSize={} "
                                         "keyPathLength={} dataSize={} declaredTotal={} pid={} op={}",
                                         req->valueNameLength, remaining, pAppHeader->DataSize,
                                         req->keyPathLength, req->dataSize, declaredTotal,
                                         req->processId, static_cast<unsigned>(req->operation));
                    break;
                }
                remaining -= req->valueNameLength;
                if (req->dataSize > remaining) {
                    Utils::Logger::Error("[IPCManager] RegistryNotify data exceeds buffer: "
                                         "dataSize={} remaining={} DataSize={} keyPathLength={} "
                                         "valueNameLength={} declaredTotal={} pid={}",
                                         req->dataSize, remaining, pAppHeader->DataSize,
                                         req->keyPathLength, req->valueNameLength, declaredTotal,
                                         req->processId);
                    break;
                }

                try {
                    verdict = registryHandler(*req);
                } catch (const std::exception& e) {
                    Utils::Logger::Error("[IPCManager] Registry handler exception: {}", e.what());
                }
            } else if (genericHandler) {
                try {
                    genericHandler(FilterMessageType_RegistryNotify, pPayload, pAppHeader->DataSize);
                } catch (const std::exception& e) {
                    Utils::Logger::Error("[IPCManager] Generic Registry handler exception: {}", e.what());
                }
            }
            auto idx = static_cast<size_t>(FilterMessageType_RegistryNotify);
            if (idx < m_impl->stats.byMessageType.size()) {
                m_impl->stats.byMessageType[idx].fetch_add(1, std::memory_order_relaxed);
            }
            break;
        }

        // =====================================================================
        // THREAD NOTIFICATIONS (remote thread injection, Heaven's Gate)
        // =====================================================================
        case FilterMessageType_ThreadNotify: {
            if (genericHandler) {
                try {
                    genericHandler(FilterMessageType_ThreadNotify, pPayload, pAppHeader->DataSize);
                } catch (const std::exception& e) {
                    Utils::Logger::Error("[IPCManager] ThreadNotify handler exception: {}", e.what());
                }
            }
            auto idx = static_cast<size_t>(FilterMessageType_ThreadNotify);
            if (idx < m_impl->stats.byMessageType.size()) {
                m_impl->stats.byMessageType[idx].fetch_add(1, std::memory_order_relaxed);
            }
            break;
        }

        // =====================================================================
        // SECURITY ALERTS (high-priority kernel detections)
        // =====================================================================
        case FilterMessageType_HandleAlert: {
            if (genericHandler) {
                try {
                    genericHandler(FilterMessageType_HandleAlert, pPayload, pAppHeader->DataSize);
                } catch (const std::exception& e) {
                    Utils::Logger::Error("[IPCManager] HandleAlert handler exception: {}", e.what());
                }
            }
            auto idx = static_cast<size_t>(FilterMessageType_HandleAlert);
            if (idx < m_impl->stats.byMessageType.size()) {
                m_impl->stats.byMessageType[idx].fetch_add(1, std::memory_order_relaxed);
            }
            break;
        }

        case FilterMessageType_RansomwareAlert: {
            if (genericHandler) {
                try {
                    genericHandler(FilterMessageType_RansomwareAlert, pPayload, pAppHeader->DataSize);
                } catch (const std::exception& e) {
                    Utils::Logger::Error("[IPCManager] RansomwareAlert handler exception: {}", e.what());
                }
            }
            auto idx = static_cast<size_t>(FilterMessageType_RansomwareAlert);
            if (idx < m_impl->stats.byMessageType.size()) {
                m_impl->stats.byMessageType[idx].fetch_add(1, std::memory_order_relaxed);
            }
            break;
        }

        case FilterMessageType_BehavioralAlert: {
            if (genericHandler) {
                try {
                    genericHandler(FilterMessageType_BehavioralAlert, pPayload, pAppHeader->DataSize);
                } catch (const std::exception& e) {
                    Utils::Logger::Error("[IPCManager] BehavioralAlert handler exception: {}", e.what());
                }
            }
            auto idx = static_cast<size_t>(FilterMessageType_BehavioralAlert);
            if (idx < m_impl->stats.byMessageType.size()) {
                m_impl->stats.byMessageType[idx].fetch_add(1, std::memory_order_relaxed);
            }
            break;
        }

        // =====================================================================
        // FILE OPERATION EVENTS (rename/delete evaluated by PreSetInformation)
        // =====================================================================
        //
        // These carry the driver's own verdict on a rename or delete, including
        // operations it BLOCKED - which never reach a post-operation callback, so
        // no other path can report them.
        //
        // The payload is SHADOWSTRIKE_FILE_OPERATION_EVENT. It is bounded below
        // because a handler must not be handed a DataSize that cannot contain the
        // fixed part of the structure: the driver frames it correctly now, but a
        // consumer that trusts DataSize blindly reads past the payload for any
        // frame that does not, and this is the one message class where a
        // malformed frame has actually shipped.
        case FilterMessageType_FileOperationEvent: {
            if (pAppHeader->DataSize < sizeof(SHADOWSTRIKE_FILE_OPERATION_EVENT)) {
                Utils::Logger::Warn(
                    "[IPCManager] FileOperationEvent payload too small ({} bytes, need at "
                    "least {}); discarding rather than parsing a short structure",
                    pAppHeader->DataSize,
                    static_cast<uint32_t>(sizeof(SHADOWSTRIKE_FILE_OPERATION_EVENT)));
                m_impl->stats.errors.fetch_add(1, std::memory_order_relaxed);
                break;
            }
            if (genericHandler) {
                try {
                    genericHandler(FilterMessageType_FileOperationEvent, pPayload, pAppHeader->DataSize);
                } catch (const std::exception& e) {
                    Utils::Logger::Error("[IPCManager] FileOperationEvent handler exception: {}", e.what());
                }
            }
            auto idx = static_cast<size_t>(FilterMessageType_FileOperationEvent);
            if (idx < m_impl->stats.byMessageType.size()) {
                m_impl->stats.byMessageType[idx].fetch_add(1, std::memory_order_relaxed);
            }
            break;
        }

        case FilterMessageType_MemoryAlert: {
            // Route to MemoryProtection engine for kernel event processing
            try {
                RealTime::MemoryProtection::Instance().ProcessKernelMemoryAlert(
                    static_cast<uint32_t>(FilterMessageType_MemoryAlert), pPayload, pAppHeader->DataSize);
            } catch (const std::exception& e) {
                Utils::Logger::Error("[IPCManager] MemoryAlert handler exception: {}", e.what());
            }
            auto idx = static_cast<size_t>(FilterMessageType_MemoryAlert);
            if (idx < m_impl->stats.byMessageType.size()) {
                m_impl->stats.byMessageType[idx].fetch_add(1, std::memory_order_relaxed);
            }
            break;
        }

        case FilterMessageType_NetworkAlert: {
            if (genericHandler) {
                try {
                    genericHandler(FilterMessageType_NetworkAlert, pPayload, pAppHeader->DataSize);
                } catch (const std::exception& e) {
                    Utils::Logger::Error("[IPCManager] NetworkAlert handler exception: {}", e.what());
                }
            }
            auto idx = static_cast<size_t>(FilterMessageType_NetworkAlert);
            if (idx < m_impl->stats.byMessageType.size()) {
                m_impl->stats.byMessageType[idx].fetch_add(1, std::memory_order_relaxed);
            }
            break;
        }

        case FilterMessageType_SyscallAlert: {
            if (genericHandler) {
                try {
                    genericHandler(FilterMessageType_SyscallAlert, pPayload, pAppHeader->DataSize);
                } catch (const std::exception& e) {
                    Utils::Logger::Error("[IPCManager] SyscallAlert handler exception: {}", e.what());
                }
            }
            auto idx = static_cast<size_t>(FilterMessageType_SyscallAlert);
            if (idx < m_impl->stats.byMessageType.size()) {
                m_impl->stats.byMessageType[idx].fetch_add(1, std::memory_order_relaxed);
            }
            break;
        }

        case FilterMessageType_SelfProtectAlert: {
            if (genericHandler) {
                try {
                    genericHandler(FilterMessageType_SelfProtectAlert, pPayload, pAppHeader->DataSize);
                } catch (const std::exception& e) {
                    Utils::Logger::Error("[IPCManager] SelfProtectAlert handler exception: {}", e.what());
                }
            }
            auto idx = static_cast<size_t>(FilterMessageType_SelfProtectAlert);
            if (idx < m_impl->stats.byMessageType.size()) {
                m_impl->stats.byMessageType[idx].fetch_add(1, std::memory_order_relaxed);
            }
            break;
        }

        case FilterMessageType_ThreatScoreNotify: {
            if (genericHandler) {
                try {
                    genericHandler(FilterMessageType_ThreatScoreNotify, pPayload, pAppHeader->DataSize);
                } catch (const std::exception& e) {
                    Utils::Logger::Error("[IPCManager] ThreatScoreNotify handler exception: {}", e.what());
                }
            }
            auto idx = static_cast<size_t>(FilterMessageType_ThreatScoreNotify);
            if (idx < m_impl->stats.byMessageType.size()) {
                m_impl->stats.byMessageType[idx].fetch_add(1, std::memory_order_relaxed);
            }
            break;
        }

        // =====================================================================
        // FILE OPERATION NOTIFICATIONS (ransomware backup, file events)
        // =====================================================================
        case FilterMessageType_NamedPipeEvent:
        case FilterMessageType_FileBackupEvent:
        case FilterMessageType_FileRollbackEvent: {
            if (genericHandler) {
                try {
                    genericHandler(
                        static_cast<SHADOWSTRIKE_MESSAGE_TYPE>(pAppHeader->MessageType),
                        pPayload, pAppHeader->DataSize);
                } catch (const std::exception& e) {
                    Utils::Logger::Error("[IPCManager] FileOp handler exception for type {}: {}",
                                         pAppHeader->MessageType, e.what());
                }
            }
            auto idx = static_cast<size_t>(pAppHeader->MessageType);
            if (idx < m_impl->stats.byMessageType.size()) {
                m_impl->stats.byMessageType[idx].fetch_add(1, std::memory_order_relaxed);
            }
            break;
        }

        // =====================================================================
        // ALPC NOTIFICATIONS (sandbox escape, impersonation, lateral movement)
        // =====================================================================
        case FilterMessageType_AlpcPortCreated:
        case FilterMessageType_AlpcPortConnected:
        case FilterMessageType_AlpcPortDisconnected:
        case FilterMessageType_AlpcSuspiciousAccess:
        case FilterMessageType_AlpcImpersonation:
        case FilterMessageType_AlpcSandboxEscape:
        case FilterMessageType_AlpcRateLimitExceeded: {
            if (genericHandler) {
                try {
                    genericHandler(
                        static_cast<SHADOWSTRIKE_MESSAGE_TYPE>(pAppHeader->MessageType),
                        pPayload, pAppHeader->DataSize);
                } catch (const std::exception& e) {
                    Utils::Logger::Error("[IPCManager] ALPC handler exception for type {}: {}",
                                         pAppHeader->MessageType, e.what());
                }
            }
            auto idx = static_cast<size_t>(pAppHeader->MessageType);
            if (idx < m_impl->stats.byMessageType.size()) {
                m_impl->stats.byMessageType[idx].fetch_add(1, std::memory_order_relaxed);
            }
            break;
        }

        // =====================================================================
        // CONTROL / POLICY MESSAGES (status queries, config updates)
        // =====================================================================
        case FilterMessageType_Register:
        case FilterMessageType_Heartbeat:
        case FilterMessageType_Unregister:
        case FilterMessageType_QueryDriverStatus:
        case FilterMessageType_ExclusionQuery:
            break;

        // =====================================================================
        // USER→KERNEL PUSH ACKNOWLEDGEMENTS (data push reply handling)
        // These message types are user→kernel (outbound) and should not arrive
        // as inbound dispatches. Log if they do — indicates protocol mismatch.
        // =====================================================================
        case FilterMessageType_PushHashDatabase:
        case FilterMessageType_PushPatternDatabase:
        case FilterMessageType_PushSignatureDatabase:
        case FilterMessageType_PushIoCFeed:
        case FilterMessageType_PushWhitelist:
        case FilterMessageType_UpdateBehavioralRules:
        case FilterMessageType_PushNetworkIoC:
        case FilterMessageType_ExclusionUpdate:
        case FilterMessageType_ConfigUpdate:
        case FilterMessageType_UpdatePolicy:
        case FilterMessageType_EnableFiltering:
        case FilterMessageType_DisableFiltering:
        case FilterMessageType_RegisterProtectedProcess:
        case FilterMessageType_ScanVerdict:
            Utils::Logger::Warn("[IPCManager] Received outbound-only message type {} as inbound — protocol mismatch",
                                pAppHeader->MessageType);
            break;

        default:
            if (genericHandler) {
                try {
                    genericHandler(
                        static_cast<SHADOWSTRIKE_MESSAGE_TYPE>(pAppHeader->MessageType),
                        pPayload,
                        pAppHeader->DataSize);
                } catch (const std::exception& e) {
                    Utils::Logger::Error("[IPCManager] Generic handler exception for type {}: {}",
                                         pAppHeader->MessageType, e.what());
                }
            } else {
                Utils::Logger::Warn("[IPCManager] Unhandled message type: {}",
                                    pAppHeader->MessageType);
            }
            break;
    }

    // Reply to the kernel ONLY when it is actually waiting for one.
    //
    // The WDK FILTER_MESSAGE_HEADER.ReplyLength — set by Filter Manager from the
    // reply buffer the driver passed to FltSendMessage — is the authoritative
    // contract: it is > 0 for a blocking scan awaiting a verdict, and 0 for
    // one-way sends (image-load / process / registry notifications and the
    // key-exchange), which have NO kernel waiter. Deciding by message type alone
    // and replying unconditionally made us call FilterReplyMessage on messages
    // with no waiter, which returns STATUS_FLT_NO_WAITER_FOR_REPLY (0x801F0020).
    // At kernel notification rates that became a self-sustaining reply/error/log
    // storm that pegged the CPU and starved the UI pipe (the "service offline"
    // flapping). Honor the contract instead of guessing from the type.
    const auto* pWdkHeader = reinterpret_cast<const FILTER_MESSAGE_HEADER*>(buffer);
    const bool kernelAwaitingReply = (pWdkHeader->ReplyLength > 0);

    if (needsReply && kernelAwaitingReply) {
        SHADOWSTRIKE_SCAN_VERDICT_REPLY verdictReply = {};
        verdictReply.MessageId  = pAppHeader->MessageId;
        verdictReply.Verdict    = static_cast<UINT8>(verdict);
        verdictReply.ThreatScore = (verdict == Verdict_Malicious) ? 100 : 0;
        verdictReply.ResultCode = 0;
        verdictReply.CacheResult = (verdict == Verdict_Clean) ? 1 : 0;
        verdictReply.CacheTTL   = (verdict == Verdict_Clean) ? 300 : 0;

        if (!ReplyToKernel(messageId, verdictReply)) {
            // Rare benign race: a blocking scan whose kernel waiter already timed
            // out before we finished. Not actionable, and must never be logged
            // per-message (that was part of the storm) — Debug only.
            Utils::Logger::Debug("[IPCManager] Reply not delivered for messageId {} "
                                 "(kernel waiter gone)", messageId);
        }

        auto vIdx = static_cast<size_t>(verdict);
        if (vIdx < m_impl->stats.byVerdict.size()) {
            m_impl->stats.byVerdict[vIdx].fetch_add(1, std::memory_order_relaxed);
        }
    } else if (needsReply && !kernelAwaitingReply) {
        // Kernel sent this scan-typed message one-way (ReplyLength == 0): it is
        // NOT waiting for a verdict, so replying would fail NO_WAITER. Skipping
        // is correct. Rate-limited so the field logs can confirm this fix
        // without reintroducing per-message spam.
        static std::atomic<uint64_t> s_skippedNoWaiter{ 0 };
        const uint64_t n = s_skippedNoWaiter.fetch_add(1, std::memory_order_relaxed) + 1;
        if (n == 1 || (n % 2000) == 0) {
            Utils::Logger::Info("[IPCManager] Skipped {} one-way kernel message reply(ies) "
                                "(ReplyLength=0, no waiter) — expected, not an error", n);
        }
    }
}

bool IPCManager::ReplyToKernel(
    uint64_t messageId,
    const SHADOWSTRIKE_SCAN_VERDICT_REPLY& verdictReply) {

    // Route through FilterConnection for encryption
    {
        std::lock_guard lock(m_primaryConnMutex);
        if (m_primaryConnection && m_primaryConnection->IsConnected()) {
            std::span<const uint8_t> replyBuf(
                reinterpret_cast<const uint8_t*>(&verdictReply),
                sizeof(verdictReply));
            if (!m_primaryConnection->ReplyMessage(replyBuf, messageId)) {
                // ReplyMessage already logs the precise cause at the right level
                // (benign NO_WAITER at Debug; genuine encryption failure at Error
                // with a stat bump). Keep this path quiet to avoid double-logging
                // the storm we just fixed.
                Utils::Logger::Debug("[IPCManager] ReplyToKernel: reply not delivered for msgId {}",
                                     messageId);
                return false;
            }
            return true;
        }
    }

    Utils::Logger::Error("[IPCManager] ReplyToKernel: encrypted channel unavailable; "
                         "refusing plaintext fallback for msgId {}", messageId);
    m_impl->stats.errors.fetch_add(1, std::memory_order_relaxed);
    return false;
}

// ============================================================================
// SELF TEST
// ============================================================================

bool IPCManager::SelfTest() {
    Utils::Logger::Info("[IPCManager] Running self-test...");
    bool allPassed = true;
    int testNum = 0;

    // Test 1: Configuration validation
    testNum++;
    {
        IPCConfiguration config;
        if (!config.IsValid()) {
            Utils::Logger::Error("[IPCManager] Test {} FAILED: Default config invalid", testNum);
            allPassed = false;
        } else {
            Utils::Logger::Debug("[IPCManager] Test {} PASSED: Config validation", testNum);
        }
    }

    // Test 2: Buffer pool allocation
    testNum++;
    {
        try {
            auto& buffer1 = m_impl->GetBuffer();
            auto& buffer2 = m_impl->GetBuffer();

            if (buffer1.size() < IPCConstants::MAX_MESSAGE_SIZE ||
                buffer2.size() < IPCConstants::MAX_MESSAGE_SIZE) {
                Utils::Logger::Error("[IPCManager] Test {} FAILED: Buffer size incorrect", testNum);
                allPassed = false;
            } else {
                Utils::Logger::Debug("[IPCManager] Test {} PASSED: Buffer pool", testNum);
            }
        } catch (...) {
            Utils::Logger::Error("[IPCManager] Test {} FAILED: Buffer pool exception", testNum);
            allPassed = false;
        }
    }

    // Test 3: Message ID generation (monotonically increasing)
    testNum++;
    {
        uint64_t id1 = m_impl->GenerateMessageId();
        uint64_t id2 = m_impl->GenerateMessageId();
        uint64_t id3 = m_impl->GenerateMessageId();

        if (id1 >= id2 || id2 >= id3) {
            Utils::Logger::Error("[IPCManager] Test {} FAILED: Message IDs not increasing", testNum);
            allPassed = false;
        } else {
            Utils::Logger::Debug("[IPCManager] Test {} PASSED: Message ID generation", testNum);
        }
    }

    // Test 4: Statistics reset
    testNum++;
    {
        m_impl->stats.messagesReceived = 100;
        m_impl->stats.Reset();
        if (m_impl->stats.messagesReceived.load() != 0) {
            Utils::Logger::Error("[IPCManager] Test {} FAILED: Stats not reset", testNum);
            allPassed = false;
        } else {
            Utils::Logger::Debug("[IPCManager] Test {} PASSED: Statistics reset", testNum);
        }
    }

    // Test 5: Enum name lookups
    testNum++;
    {
        auto cmdName = GetMessageTypeName(FilterMessageType_ScanRequest);
        auto verdictName = GetVerdictName(Verdict_Malicious);

        if (cmdName.empty() || verdictName.empty()) {
            Utils::Logger::Error("[IPCManager] Test {} FAILED: Enum name lookup", testNum);
            allPassed = false;
        } else {
            Utils::Logger::Debug("[IPCManager] Test {} PASSED: Enum name lookup", testNum);
        }
    }

    if (allPassed) {
        Utils::Logger::Info("[IPCManager] Self-test PASSED ({} tests)", testNum);
    } else {
        Utils::Logger::Error("[IPCManager] Self-test FAILED");
    }

    return allPassed;
}

std::string IPCManager::GetVersionString() noexcept {
    std::ostringstream oss;
    oss << IPCConstants::VERSION_MAJOR << "."
        << IPCConstants::VERSION_MINOR << "."
        << IPCConstants::VERSION_PATCH;
    return oss.str();
}

// ============================================================================
// HELPER STRUCTURE IMPLEMENTATIONS
// ============================================================================

bool IPCConfiguration::IsValid() const noexcept {
    if (filterPortName.empty()) {
        return false;
    }
    if (workerThreadCount == 0 || workerThreadCount > 64) {
        return false;
    }
    if (maxQueueDepth == 0 || maxQueueDepth > 1000000) {
        return false;
    }
    if (replyTimeoutMs == 0 || replyTimeoutMs > 300000) {  // Max 5 minutes
        return false;
    }
    return true;
}

void IPCStatistics::Reset() noexcept {
    messagesReceived.store(0, std::memory_order_relaxed);
    messagesSent.store(0, std::memory_order_relaxed);
    messagesDropped.store(0, std::memory_order_relaxed);
    bytesReceived.store(0, std::memory_order_relaxed);
    bytesSent.store(0, std::memory_order_relaxed);
    timeouts.store(0, std::memory_order_relaxed);
    errors.store(0, std::memory_order_relaxed);
    reconnects.store(0, std::memory_order_relaxed);
    avgLatencyUs.store(0, std::memory_order_relaxed);
    maxLatencyUs.store(0, std::memory_order_relaxed);

    for (auto& counter : byMessageType) {
        counter.store(0, std::memory_order_relaxed);
    }
    for (auto& counter : byVerdict) {
        counter.store(0, std::memory_order_relaxed);
    }

    startTime = Clock::now();
}

std::string IPCStatistics::ToJson() const {
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();

    std::ostringstream oss;
    oss << "{"
        << "\"uptimeSeconds\":" << uptime << ","
        << "\"messagesReceived\":" << messagesReceived.load() << ","
        << "\"messagesSent\":" << messagesSent.load() << ","
        << "\"messagesDropped\":" << messagesDropped.load() << ","
        << "\"bytesReceived\":" << bytesReceived.load() << ","
        << "\"bytesSent\":" << bytesSent.load() << ","
        << "\"timeouts\":" << timeouts.load() << ","
        << "\"errors\":" << errors.load() << ","
        << "\"reconnects\":" << reconnects.load() << ","
        << "\"avgLatencyUs\":" << avgLatencyUs.load() << ","
        << "\"maxLatencyUs\":" << maxLatencyUs.load()
        << "}";
    return oss.str();
}

std::string IPCStatisticsSnapshot::ToJson() const {
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();

    std::ostringstream oss;
    oss << "{"
        << "\"uptimeSeconds\":" << uptime << ","
        << "\"messagesReceived\":" << messagesReceived << ","
        << "\"messagesSent\":" << messagesSent << ","
        << "\"messagesDropped\":" << messagesDropped << ","
        << "\"bytesReceived\":" << bytesReceived << ","
        << "\"bytesSent\":" << bytesSent << ","
        << "\"timeouts\":" << timeouts << ","
        << "\"errors\":" << errors << ","
        << "\"reconnects\":" << reconnects << ","
        << "\"avgLatencyUs\":" << avgLatencyUs << ","
        << "\"maxLatencyUs\":" << maxLatencyUs
        << "}";
    return oss.str();
}

std::string ConnectionInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"channelType\":\"" << GetChannelTypeName(channelType) << "\","
        << "\"status\":\"" << GetConnectionStatusName(status) << "\","
        << "\"endpoint\":\"" << Utils::StringUtils::ToNarrow(endpoint) << "\","
        << "\"messagesReceived\":" << messagesReceived << ","
        << "\"messagesSent\":" << messagesSent << ","
        << "\"bytesReceived\":" << bytesReceived << ","
        << "\"bytesSent\":" << bytesSent << ","
        << "\"reconnectCount\":" << reconnectCount
        << "}";
    return oss.str();
}

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

std::string_view GetMessageTypeName(SHADOWSTRIKE_MESSAGE_TYPE type) noexcept {
    switch (type) {
        case FilterMessageType_None:          return "None";
        case FilterMessageType_Register:      return "Register";
        case FilterMessageType_Unregister:    return "Unregister";
        case FilterMessageType_Heartbeat:     return "Heartbeat";
        case FilterMessageType_ScanRequest:   return "ScanRequest";
        case FilterMessageType_ScanVerdict:   return "ScanVerdict";
        case FilterMessageType_ConfigUpdate:  return "ConfigUpdate";
        case FilterMessageType_ProcessNotify: return "ProcessNotify";
        case FilterMessageType_ThreadNotify:  return "ThreadNotify";
        case FilterMessageType_ImageLoad:     return "ImageLoad";
        case FilterMessageType_RegistryNotify:return "RegistryNotify";
        case FilterMessageType_BehavioralAlert: return "BehavioralAlert";
        case FilterMessageType_MemoryAlert:   return "MemoryAlert";
        case FilterMessageType_NetworkAlert:  return "NetworkAlert";
        case FilterMessageType_HandleAlert:   return "HandleAlert";
        case FilterMessageType_RansomwareAlert: return "RansomwareAlert";
        case FilterMessageType_FileOperationEvent: return "FileOperationEvent";
        default: return "Unknown";
    }
}

std::string_view GetVerdictName(SHADOWSTRIKE_SCAN_VERDICT verdict) noexcept {
    switch (verdict) {
        case Verdict_Unknown: return "Unknown";
        case Verdict_Clean: return "Clean";
        case Verdict_Malicious: return "Malicious";
        case Verdict_Suspicious: return "Suspicious";
        case Verdict_Error: return "Error";
        case Verdict_Timeout: return "Timeout";
        default: return "Invalid";
    }
}

std::string_view GetChannelTypeName(ChannelType type) noexcept {
    switch (type) {
        case ChannelType::FilterPort:   return "FilterPort";
        case ChannelType::NamedPipe:    return "NamedPipe";
        case ChannelType::SharedMemory: return "SharedMemory";
        case ChannelType::LocalSocket:  return "LocalSocket";
        default:                        return "Unknown";
    }
}

std::string_view GetConnectionStatusName(ConnectionStatus status) noexcept {
    switch (status) {
        case ConnectionStatus::Disconnected:    return "Disconnected";
        case ConnectionStatus::Connecting:      return "Connecting";
        case ConnectionStatus::Connected:       return "Connected";
        case ConnectionStatus::Authenticating:  return "Authenticating";
        case ConnectionStatus::Ready:           return "Ready";
        case ConnectionStatus::Reconnecting:    return "Reconnecting";
        case ConnectionStatus::Error:           return "Error";
        default:                                return "Unknown";
    }
}

bool CreateSecurePipeDacl(SECURITY_ATTRIBUTES& sa) {
    // FIX [BUG #10 CRITICAL]: NULL DACL = Everyone full access.
    // Build proper DACL: SYSTEM + Administrators only.
    //
    // SDDL string breakdown:
    //   D:P         — DACL present, protected (no inheritance)
    //   (A;;GA;;;SY) — Allow GENERIC_ALL to SYSTEM
    //   (A;;GA;;;BA) — Allow GENERIC_ALL to Built-in Administrators
    PSECURITY_DESCRIPTOR pSD = nullptr;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;SY)(A;;GA;;;BA)",
            SDDL_REVISION_1,
            &pSD,
            nullptr)) {
        Utils::Logger::Error("[IPCManager] ConvertStringSecurityDescriptor failed: {}",
                             GetLastError());
        return false;
    }

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = pSD;
    sa.bInheritHandle = FALSE;

    return true;
}

bool VerifyDriverSignature(const std::wstring& driverPath) {
    if (driverPath.empty()) {
        return false;
    }

    // FIX [BUG #11 CRITICAL]: Stub always returned true — complete security bypass.
    // Implement real Authenticode verification via WinVerifyTrust.

    GUID actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct      = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = driverPath.c_str();
    fileInfo.hFile         = nullptr;
    fileInfo.pgKnownSubject= nullptr;

    WINTRUST_DATA trustData = {};
    trustData.cbStruct            = sizeof(WINTRUST_DATA);
    trustData.pPolicyCallbackData = nullptr;
    trustData.pSIPClientData      = nullptr;
    trustData.dwUIChoice          = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trustData.dwUnionChoice       = WTD_CHOICE_FILE;
    trustData.pFile               = &fileInfo;
    trustData.dwStateAction       = WTD_STATEACTION_VERIFY;
    trustData.hWVTStateData       = nullptr;
    trustData.dwProvFlags         = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG status = WinVerifyTrust(
        static_cast<HWND>(INVALID_HANDLE_VALUE),
        &actionId,
        &trustData
    );

    // Clean up state
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(
        static_cast<HWND>(INVALID_HANDLE_VALUE),
        &actionId,
        &trustData
    );

    if (status != ERROR_SUCCESS) {
        Utils::Logger::Error("[IPCManager] Driver signature verification FAILED "
                             "for '{}': WinVerifyTrust returned 0x{:08X}",
                             Utils::StringUtils::ToNarrow(driverPath),
                             static_cast<unsigned long>(status));
        return false;
    }

    Utils::Logger::Info("[IPCManager] Driver signature verified: {}",
                        Utils::StringUtils::ToNarrow(driverPath));
    return true;
}

}  // namespace Communication
}  // namespace ShadowStrike
