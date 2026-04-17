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
 * ShadowStrike – PhantomEDR Telemetry Store Interface
 * ============================================================================
 *
 * @file ITelemetryStore.hpp
 * @brief Abstract interface for telemetry storage backends.
 *
 * The Community edition ships with LocalTelemetryStore (SQLite).
 * Pro/Enterprise editions can inject cloud-backed implementations
 * (e.g. Elasticsearch, Splunk, S3) behind the same interface.
 *
 * All implementations must be:
 * - Thread-safe for concurrent Store/Query from multiple producers
 * - Resilient to disk-full, corruption, and timeout conditions
 * - Capable of bounded-size operation via purge and retention policies
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 */
#pragma once

#include "TelemetryTypes.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::Telemetry {

// ============================================================================
// STORE CONFIGURATION
// ============================================================================

/// @brief Configuration parameters for a telemetry store backend.
struct StoreConfig {
    std::filesystem::path dbPath;                                        ///< SQLite database file path
    uint64_t maxStorageSizeBytes  = 2ULL * 1024ULL * 1024ULL * 1024ULL;  ///< Hard cap (default 2 GB)
    uint32_t retentionDays        = 30;                                  ///< Events older than this are purged
    uint32_t batchInsertSize      = 100;                                 ///< Rows per transaction batch
    uint32_t vacuumIntervalHours  = 24;                                  ///< Auto-VACUUM cadence
    bool     walMode              = true;                                ///< Enable WAL for concurrent readers
};

// ============================================================================
// TELEMETRY STORE INTERFACE
// ============================================================================

/// @brief Abstract interface for telemetry persistence backends.
class ITelemetryStore {
public:
    virtual ~ITelemetryStore() = default;

    // -- Lifecycle -----------------------------------------------------------

    /// @brief Open the backing store and prepare it for use.
    [[nodiscard]] virtual bool Initialize(const StoreConfig& config) = 0;

    /// @brief Flush pending data and release all resources.
    virtual void Shutdown() = 0;

    /// @brief Check whether the store has been successfully initialized.
    [[nodiscard]] virtual bool IsInitialized() const noexcept = 0;

    // -- Write ---------------------------------------------------------------

    /// @brief Persist a single telemetry event.
    [[nodiscard]] virtual bool Store(TelemetryEvent&& event) = 0;

    /// @brief Persist a batch of events inside a single transaction.
    [[nodiscard]] virtual bool StoreBatch(std::vector<TelemetryEvent>&& events) = 0;

    // -- Read ----------------------------------------------------------------

    /// @brief Execute a filtered, paginated query over stored events.
    [[nodiscard]] virtual QueryResult Query(const QueryParams& params) = 0;

    /// @brief Retrieve a single event by its unique identifier.
    [[nodiscard]] virtual std::optional<TelemetryEvent> GetById(uint64_t eventId) = 0;

    // -- Maintenance ---------------------------------------------------------

    /// @brief Delete events older than the given cutoff and return the count deleted.
    [[nodiscard]] virtual uint64_t PurgeOlderThan(std::chrono::system_clock::time_point cutoff) = 0;

    /// @brief Return the total number of stored events.
    [[nodiscard]] virtual uint64_t GetEventCount() const = 0;

    /// @brief Return the on-disk size of the backing store in bytes.
    [[nodiscard]] virtual uint64_t GetStorageSizeBytes() const = 0;

    /// @brief Return a snapshot of aggregate pipeline statistics.
    [[nodiscard]] virtual TelemetryStats GetStats() const = 0;

    /// @brief Zero all pipeline counters.
    virtual void ResetStats() = 0;

protected:
    ITelemetryStore() = default;
    ITelemetryStore(const ITelemetryStore&) = default;
    ITelemetryStore& operator=(const ITelemetryStore&) = default;
};

} // namespace ShadowStrike::Products::PhantomEDR::Telemetry
