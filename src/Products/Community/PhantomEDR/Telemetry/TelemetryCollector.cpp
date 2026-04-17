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
// ===========================================================================
// ShadowStrike – PhantomEDR Telemetry Collector Implementation
//
// Orchestrates the full event pipeline:
//   SubmitEvent → bounded queue → flush thread → TelemetryFilter → LocalTelemetryStore
//
// Threading model:
//   - Submission:    mutex + condition_variable_any on the pending queue
//   - Flush worker:  std::jthread, wakes on batch-size threshold or timer
//   - Maintenance:   std::jthread, periodic retention purge
//   - Event IDs:     monotonic std::atomic<uint64_t>
//   - Stats:         atomic counters
//
// Overflow policy: when the queue exceeds maxPendingEvents, the OLDEST
// events are dropped so the caller is never blocked.
// ===========================================================================

#include "pch.h"
#include "TelemetryCollector.hpp"

#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>

#include "LocalTelemetryStore.hpp"
#include "PhantomCore/Utils/Logger.hpp"

namespace ShadowStrike::Products::PhantomEDR::Telemetry {

// ============================================================================
// TELEMETRY COLLECTOR IMPLEMENTATION  (PIMPL — free class, NOT nested)
// ============================================================================

class TelemetryCollectorImpl {
public:
    TelemetryCollectorImpl()  = default;
    ~TelemetryCollectorImpl();

    // -- Lifecycle -----------------------------------------------------------
    bool Initialize(const CollectorConfig& config);
    void Shutdown();
    bool IsRunning() const noexcept { return m_running.load(std::memory_order_acquire); }

    // -- Event submission ----------------------------------------------------
    void SubmitEvent(TelemetryEvent&& event);

    void SubmitProcessEvent(ProcessEventType type, uint32_t pid, uint32_t parentPid,
                            std::wstring processName, std::wstring processPath,
                            std::wstring commandLine, EventSeverity severity);

    void SubmitFileEvent(FileEventType type, uint32_t pid,
                         std::wstring filePath, EventSeverity severity);

    void SubmitRegistryEvent(RegistryEventType type, uint32_t pid,
                             std::wstring keyPath, std::wstring valueName,
                             EventSeverity severity);

    void SubmitNetworkEvent(NetworkEventType type, uint32_t pid,
                            std::string remoteAddr, uint16_t remotePort,
                            std::string localAddr,  uint16_t localPort,
                            EventSeverity severity);

    // -- Query ---------------------------------------------------------------
    QueryResult Query(const QueryParams& params);
    std::optional<TelemetryEvent> GetEventById(uint64_t eventId);

    // -- Statistics ----------------------------------------------------------
    TelemetryStats GetStats();

private:
    // -- Worker threads ------------------------------------------------------
    void FlushLoop(std::stop_token token);
    void MaintenanceLoop(std::stop_token token);

    // -- Internal batch processing -------------------------------------------
    void ProcessBatch(std::vector<TelemetryEvent>&& batch);
    void FlushRemaining();

    // -- Configuration -------------------------------------------------------
    CollectorConfig m_config{};

    // -- Pending-event queue -------------------------------------------------
    std::deque<TelemetryEvent>    m_queue;
    mutable std::mutex            m_queueMutex;
    std::condition_variable_any   m_flushCV;

    // -- Maintenance CV (for interruptible sleep) ----------------------------
    std::mutex                    m_maintenanceMutex;
    std::condition_variable_any   m_maintenanceCV;

    // -- Workers (stored in a vector, joined in Shutdown) --------------------
    std::vector<std::jthread>     m_workers;

    // -- Monotonic event-ID counter ------------------------------------------
    std::atomic<uint64_t> m_nextEventId{1};

    // -- Statistics ----------------------------------------------------------
    std::atomic<uint64_t> m_receivedCount{0};
    std::atomic<uint64_t> m_storedCount{0};
    std::atomic<uint64_t> m_droppedCount{0};

    // -- State ---------------------------------------------------------------
    std::atomic<bool> m_running{false};
};

// ============================================================================
// DESTRUCTOR
// ============================================================================

TelemetryCollectorImpl::~TelemetryCollectorImpl()
{
    if (m_running.load(std::memory_order_acquire)) {
        Shutdown();
    }
}

// ============================================================================
// LIFECYCLE
// ============================================================================

bool TelemetryCollectorImpl::Initialize(const CollectorConfig& config)
{
    if (m_running.load(std::memory_order_acquire)) {
        ShadowStrike::Utils::Logger::Warn(
            "[TelemetryCollector] Already running — ignoring duplicate Initialize");
        return false;
    }

    // Validate critical config bounds
    if (config.batchFlushSize == 0) {
        ShadowStrike::Utils::Logger::Error(
            "[TelemetryCollector] Invalid batchFlushSize=0");
        return false;
    }
    if (config.maxPendingEvents == 0) {
        ShadowStrike::Utils::Logger::Error(
            "[TelemetryCollector] Invalid maxPendingEvents=0");
        return false;
    }

    m_config = config;

    // Resolve DB path: use explicit telemetryDbPath, fall back to storeConfig
    if (!m_config.telemetryDbPath.empty()) {
        m_config.storeConfig.databasePath = m_config.telemetryDbPath;
    }

    // Initialize the storage backend (singleton)
    auto& store = LocalTelemetryStore::Instance();
    if (!store.Initialize(m_config.storeConfig)) {
        ShadowStrike::Utils::Logger::Error(
            "[TelemetryCollector] Failed to initialise LocalTelemetryStore");
        return false;
    }

    // Initialize the filter (singleton)
    auto& filter = TelemetryFilter::Instance();
    if (!filter.Initialize(m_config.filterConfig)) {
        ShadowStrike::Utils::Logger::Error(
            "[TelemetryCollector] Failed to initialise TelemetryFilter");
        return false;
    }

    // Reset counters
    m_receivedCount.store(0, std::memory_order_relaxed);
    m_storedCount.store(0, std::memory_order_relaxed);
    m_droppedCount.store(0, std::memory_order_relaxed);
    m_nextEventId.store(1, std::memory_order_relaxed);

    m_running.store(true, std::memory_order_release);

    // Spawn workers — stored in vector, joined in Shutdown()
    m_workers.reserve(2);
    m_workers.emplace_back([this](std::stop_token t) { FlushLoop(std::move(t)); });
    m_workers.emplace_back([this](std::stop_token t) { MaintenanceLoop(std::move(t)); });

    ShadowStrike::Utils::Logger::Info(
        "[TelemetryCollector] Initialised — batchSize={}, flushMs={}, maxPending={}, purgeMin={}",
        m_config.batchFlushSize, m_config.batchFlushIntervalMs,
        m_config.maxPendingEvents, m_config.purgeCheckIntervalMin);

    return true;
}

void TelemetryCollectorImpl::Shutdown()
{
    if (!m_running.exchange(false, std::memory_order_acq_rel)) {
        return;
    }

    ShadowStrike::Utils::Logger::Info("[TelemetryCollector] Shutdown initiated");

    // Signal all workers to stop
    for (auto& w : m_workers) {
        w.request_stop();
    }

    // Wake up sleeping workers so they notice the stop token
    m_flushCV.notify_all();
    m_maintenanceCV.notify_all();

    // Join all workers
    for (auto& w : m_workers) {
        if (w.joinable()) {
            w.join();
        }
    }
    m_workers.clear();

    // Flush remaining queued events
    FlushRemaining();

    // Shut down filter and store
    TelemetryFilter::Instance().Shutdown();
    LocalTelemetryStore::Instance().Shutdown();

    ShadowStrike::Utils::Logger::Info(
        "[TelemetryCollector] Shutdown complete — received={}, stored={}, dropped={}",
        m_receivedCount.load(std::memory_order_relaxed),
        m_storedCount.load(std::memory_order_relaxed),
        m_droppedCount.load(std::memory_order_relaxed));
}

// ============================================================================
// EVENT SUBMISSION
// ============================================================================

void TelemetryCollectorImpl::SubmitEvent(TelemetryEvent&& event)
{
    if (!m_running.load(std::memory_order_acquire)) {
        return;
    }

    // Stamp mandatory fields
    event.eventId   = m_nextEventId.fetch_add(1, std::memory_order_relaxed);
    event.timestamp = std::chrono::system_clock::now();
    event.threadId  = ::GetCurrentThreadId();

    {
        std::lock_guard lock(m_queueMutex);

        // Overflow policy: drop OLDEST events when at capacity
        if (m_queue.size() >= m_config.maxPendingEvents) {
            const size_t toDrop =
                m_queue.size() - m_config.maxPendingEvents + 1;
            for (size_t i = 0; i < toDrop; ++i) {
                m_queue.pop_front();
            }
            m_droppedCount.fetch_add(toDrop, std::memory_order_relaxed);
            ShadowStrike::Utils::Logger::Warn(
                "[TelemetryCollector] Queue overflow — dropped {} oldest events",
                toDrop);
        }

        m_queue.push_back(std::move(event));
    }

    m_receivedCount.fetch_add(1, std::memory_order_relaxed);
    m_flushCV.notify_one();
}

// -- Convenience helpers build a TelemetryEvent and call SubmitEvent ---------

void TelemetryCollectorImpl::SubmitProcessEvent(
    ProcessEventType type, uint32_t pid, uint32_t parentPid,
    std::wstring processName, std::wstring processPath,
    std::wstring commandLine, EventSeverity severity)
{
    TelemetryEvent ev{};
    ev.category        = EventCategory::Process;
    ev.severity        = severity;
    ev.processId       = pid;
    ev.parentProcessId = parentPid;
    ev.processName     = std::move(processName);
    ev.processPath     = std::move(processPath);

    ProcessEventData data{};
    data.type        = type;
    data.commandLine = std::move(commandLine);
    ev.payload       = std::move(data);

    SubmitEvent(std::move(ev));
}

void TelemetryCollectorImpl::SubmitFileEvent(
    FileEventType type, uint32_t pid,
    std::wstring filePath, EventSeverity severity)
{
    TelemetryEvent ev{};
    ev.category  = EventCategory::File;
    ev.severity  = severity;
    ev.processId = pid;

    FileEventData data{};
    data.type     = type;
    data.filePath = std::move(filePath);
    ev.payload    = std::move(data);

    SubmitEvent(std::move(ev));
}

void TelemetryCollectorImpl::SubmitRegistryEvent(
    RegistryEventType type, uint32_t pid,
    std::wstring keyPath, std::wstring valueName,
    EventSeverity severity)
{
    TelemetryEvent ev{};
    ev.category  = EventCategory::Registry;
    ev.severity  = severity;
    ev.processId = pid;

    RegistryEventData data{};
    data.type      = type;
    data.keyPath   = std::move(keyPath);
    data.valueName = std::move(valueName);
    ev.payload     = std::move(data);

    SubmitEvent(std::move(ev));
}

void TelemetryCollectorImpl::SubmitNetworkEvent(
    NetworkEventType type, uint32_t pid,
    std::string remoteAddr, uint16_t remotePort,
    std::string localAddr,  uint16_t localPort,
    EventSeverity severity)
{
    TelemetryEvent ev{};
    ev.category  = EventCategory::Network;
    ev.severity  = severity;
    ev.processId = pid;

    NetworkEventData data{};
    data.type          = type;
    data.remoteAddress = std::move(remoteAddr);
    data.remotePort    = remotePort;
    data.localAddress  = std::move(localAddr);
    data.localPort     = localPort;
    ev.payload         = std::move(data);

    SubmitEvent(std::move(ev));
}

// ============================================================================
// QUERY (pass-through to store)
// ============================================================================

QueryResult TelemetryCollectorImpl::Query(const QueryParams& params)
{
    return LocalTelemetryStore::Instance().Query(params);
}

std::optional<TelemetryEvent> TelemetryCollectorImpl::GetEventById(uint64_t eventId)
{
    return LocalTelemetryStore::Instance().GetEventById(eventId);
}

// ============================================================================
// STATISTICS
// ============================================================================

TelemetryStats TelemetryCollectorImpl::GetStats()
{
    TelemetryStats stats{};
    stats.totalEventsReceived = m_receivedCount.load(std::memory_order_relaxed);
    stats.totalEventsStored   = m_storedCount.load(std::memory_order_relaxed);
    stats.totalEventsFiltered = TelemetryFilter::Instance().GetFilteredCount();
    stats.totalEventsDropped  = m_droppedCount.load(std::memory_order_relaxed);

    {
        std::lock_guard lock(m_queueMutex);
        stats.pendingEvents = m_queue.size();
    }

    return stats;
}

// ============================================================================
// FLUSH WORKER
// ============================================================================

void TelemetryCollectorImpl::FlushLoop(std::stop_token token)
{
    ShadowStrike::Utils::Logger::Debug("[TelemetryCollector] Flush worker started");

    while (!token.stop_requested()) {
        std::vector<TelemetryEvent> batch;

        {
            std::unique_lock lock(m_queueMutex);

            // Wait until batch-size threshold, timeout, or stop
            m_flushCV.wait_for(lock, token,
                std::chrono::milliseconds(m_config.batchFlushIntervalMs),
                [this] { return m_queue.size() >= m_config.batchFlushSize; });

            if (m_queue.empty()) {
                if (token.stop_requested()) break;
                continue;
            }

            const size_t count = std::min(
                static_cast<size_t>(m_config.batchFlushSize), m_queue.size());
            batch.reserve(count);

            for (size_t i = 0; i < count; ++i) {
                batch.push_back(std::move(m_queue.front()));
                m_queue.pop_front();
            }
        }

        ProcessBatch(std::move(batch));
    }

    ShadowStrike::Utils::Logger::Debug("[TelemetryCollector] Flush worker exiting");
}

// ============================================================================
// MAINTENANCE WORKER
// ============================================================================

void TelemetryCollectorImpl::MaintenanceLoop(std::stop_token token)
{
    ShadowStrike::Utils::Logger::Debug("[TelemetryCollector] Maintenance worker started");

    while (!token.stop_requested()) {
        {
            std::unique_lock lock(m_maintenanceMutex);
            m_maintenanceCV.wait_for(lock, token,
                std::chrono::minutes(m_config.purgeCheckIntervalMin),
                [] { return false; });  // always timeout-driven
        }

        if (token.stop_requested()) break;

        ShadowStrike::Utils::Logger::Debug(
            "[TelemetryCollector] Running retention purge (retentionDays={})",
            m_config.storeConfig.retentionDays);

        const auto maxAge =
            std::chrono::hours(
                static_cast<int64_t>(m_config.storeConfig.retentionDays) * 24);

        if (!LocalTelemetryStore::Instance().PurgeOldEvents(maxAge)) {
            ShadowStrike::Utils::Logger::Warn(
                "[TelemetryCollector] Retention purge failed");
        }
    }

    ShadowStrike::Utils::Logger::Debug("[TelemetryCollector] Maintenance worker exiting");
}

// ============================================================================
// BATCH PROCESSING
// ============================================================================

void TelemetryCollectorImpl::ProcessBatch(std::vector<TelemetryEvent>&& batch)
{
    if (batch.empty()) return;

    auto& filter = TelemetryFilter::Instance();

    std::vector<TelemetryEvent> accepted;
    accepted.reserve(batch.size());

    for (auto& ev : batch) {
        if (filter.ShouldKeep(ev)) {
            accepted.push_back(std::move(ev));
        }
    }

    if (accepted.empty()) return;

    auto& store = LocalTelemetryStore::Instance();

    if (!store.StoreBatch(std::span<const TelemetryEvent>(accepted))) {
        ShadowStrike::Utils::Logger::Error(
            "[TelemetryCollector] StoreBatch failed for {} events — events dropped",
            accepted.size());
        m_droppedCount.fetch_add(accepted.size(), std::memory_order_relaxed);
    } else {
        m_storedCount.fetch_add(accepted.size(), std::memory_order_relaxed);
    }
}

void TelemetryCollectorImpl::FlushRemaining()
{
    std::vector<TelemetryEvent> remaining;

    {
        std::lock_guard lock(m_queueMutex);
        remaining.reserve(m_queue.size());
        while (!m_queue.empty()) {
            remaining.push_back(std::move(m_queue.front()));
            m_queue.pop_front();
        }
    }

    if (!remaining.empty()) {
        ShadowStrike::Utils::Logger::Info(
            "[TelemetryCollector] Flushing {} remaining events during shutdown",
            remaining.size());
        ProcessBatch(std::move(remaining));
    }
}

// ============================================================================
// TELEMETRY COLLECTOR — SINGLETON + FORWARDING
// ============================================================================

TelemetryCollector& TelemetryCollector::Instance()
{
    static TelemetryCollector instance;
    return instance;
}

TelemetryCollector::TelemetryCollector()
    : m_impl(std::make_unique<TelemetryCollectorImpl>()) {}

TelemetryCollector::~TelemetryCollector() = default;

bool TelemetryCollector::Initialize(const CollectorConfig& config) {
    return m_impl->Initialize(config);
}

void TelemetryCollector::Shutdown() {
    m_impl->Shutdown();
}

bool TelemetryCollector::IsRunning() const noexcept {
    return m_impl->IsRunning();
}

void TelemetryCollector::SubmitEvent(TelemetryEvent&& event) {
    m_impl->SubmitEvent(std::move(event));
}

void TelemetryCollector::SubmitProcessEvent(
    ProcessEventType type, uint32_t pid, uint32_t parentPid,
    std::wstring processName, std::wstring processPath,
    std::wstring commandLine, EventSeverity severity)
{
    m_impl->SubmitProcessEvent(type, pid, parentPid,
        std::move(processName), std::move(processPath),
        std::move(commandLine), severity);
}

void TelemetryCollector::SubmitFileEvent(
    FileEventType type, uint32_t pid,
    std::wstring filePath, EventSeverity severity)
{
    m_impl->SubmitFileEvent(type, pid, std::move(filePath), severity);
}

void TelemetryCollector::SubmitRegistryEvent(
    RegistryEventType type, uint32_t pid,
    std::wstring keyPath, std::wstring valueName, EventSeverity severity)
{
    m_impl->SubmitRegistryEvent(type, pid, std::move(keyPath),
        std::move(valueName), severity);
}

void TelemetryCollector::SubmitNetworkEvent(
    NetworkEventType type, uint32_t pid,
    std::string remoteAddr, uint16_t remotePort,
    std::string localAddr,  uint16_t localPort, EventSeverity severity)
{
    m_impl->SubmitNetworkEvent(type, pid,
        std::move(remoteAddr), remotePort,
        std::move(localAddr), localPort, severity);
}

QueryResult TelemetryCollector::Query(const QueryParams& params) {
    return m_impl->Query(params);
}

std::optional<TelemetryEvent> TelemetryCollector::GetEventById(uint64_t eventId) {
    return m_impl->GetEventById(eventId);
}

TelemetryStats TelemetryCollector::GetStats() const {
    return m_impl->GetStats();
}

} // namespace ShadowStrike::Products::PhantomEDR::Telemetry
