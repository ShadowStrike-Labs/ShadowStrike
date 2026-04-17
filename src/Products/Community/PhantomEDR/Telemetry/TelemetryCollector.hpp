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
// ShadowStrike – PhantomEDR Telemetry Collector
//
// Main orchestrator that receives real-time events from PhantomCore
// callbacks, queues them in a bounded concurrent queue, filters through
// TelemetryFilter, and persists passing events via LocalTelemetryStore.
// ===========================================================================
#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>

#include "TelemetryTypes.hpp"
#include "ITelemetryStore.hpp"
#include "TelemetryFilter.hpp"

namespace ShadowStrike::Products::PhantomEDR::Telemetry {

class TelemetryCollectorImpl;

// ============================================================================
// COLLECTOR CONFIGURATION
// ============================================================================

struct CollectorConfig {
    StoreConfig  storeConfig;               ///< Forwarded to LocalTelemetryStore
    FilterConfig filterConfig;              ///< Forwarded to TelemetryFilter

    uint32_t batchFlushSize        = 100;   ///< Flush when batch reaches this size
    uint32_t batchFlushIntervalMs  = 5000;  ///< Flush every N ms regardless of batch
    uint32_t maxPendingEvents      = 50000; ///< Queue capacity before dropping oldest
    uint32_t purgeCheckIntervalMin = 60;    ///< Retention-purge check interval (min)

    std::filesystem::path telemetryDbPath;  ///< Path to telemetry SQLite database
};

// ============================================================================
// TELEMETRY COLLECTOR  (Meyers' Singleton + PIMPL)
// ============================================================================

class TelemetryCollector {
public:
    [[nodiscard]] static TelemetryCollector& Instance();

    [[nodiscard]] bool Initialize(const CollectorConfig& config);
    void Shutdown();
    [[nodiscard]] bool IsRunning() const noexcept;

    // ---- Event submission (thread-safe, non-blocking) ----------------------
    void SubmitEvent(TelemetryEvent&& event);

    void SubmitProcessEvent(ProcessEventType type, uint32_t pid, uint32_t parentPid,
                            std::wstring processName, std::wstring processPath,
                            std::wstring commandLine,
                            EventSeverity severity = EventSeverity::Info);

    void SubmitFileEvent(FileEventType type, uint32_t pid,
                         std::wstring filePath,
                         EventSeverity severity = EventSeverity::Info);

    void SubmitRegistryEvent(RegistryEventType type, uint32_t pid,
                             std::wstring keyPath, std::wstring valueName = L"",
                             EventSeverity severity = EventSeverity::Info);

    void SubmitNetworkEvent(NetworkEventType type, uint32_t pid,
                            std::string remoteAddr, uint16_t remotePort,
                            std::string localAddr,  uint16_t localPort,
                            EventSeverity severity = EventSeverity::Info);

    // ---- Query (pass-through to ITelemetryStore) ---------------------------
    [[nodiscard]] QueryResult Query(const QueryParams& params);
    [[nodiscard]] std::optional<TelemetryEvent> GetEventById(uint64_t eventId);

    // ---- Statistics --------------------------------------------------------
    [[nodiscard]] TelemetryStats GetStats() const;

private:
    TelemetryCollector();
    ~TelemetryCollector();
    TelemetryCollector(const TelemetryCollector&)            = delete;
    TelemetryCollector& operator=(const TelemetryCollector&) = delete;

    std::unique_ptr<TelemetryCollectorImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::Telemetry
