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
 * ShadowStrike – PhantomEDR Local Telemetry Store (Community Edition)
 * ============================================================================
 *
 * @file LocalTelemetryStore.hpp
 * @brief SQLite-backed ITelemetryStore for the Community edition.
 *
 * Stores all EDR telemetry events in a local SQLite database using WAL
 * mode for concurrent reader access.  A background maintenance thread
 * enforces retention policies and storage caps automatically.
 *
 * Uses the PIMPL idiom for ABI stability — the implementation class
 * (LocalTelemetryStoreImpl) is defined in the .cpp translation unit.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 */
#pragma once

#include "ITelemetryStore.hpp"

#include <memory>

namespace ShadowStrike::Products::PhantomEDR::Telemetry {

// Forward declaration — defined in LocalTelemetryStore.cpp
class LocalTelemetryStoreImpl;

/// @brief Community-edition telemetry store backed by a dedicated local SQLite database.
class LocalTelemetryStore final : public ITelemetryStore {
public:
    LocalTelemetryStore();
    ~LocalTelemetryStore() override;

    // Non-copyable, non-movable
    LocalTelemetryStore(const LocalTelemetryStore&) = delete;
    LocalTelemetryStore& operator=(const LocalTelemetryStore&) = delete;
    LocalTelemetryStore(LocalTelemetryStore&&) = delete;
    LocalTelemetryStore& operator=(LocalTelemetryStore&&) = delete;

    // -- ITelemetryStore interface -------------------------------------------

    [[nodiscard]] bool Initialize(const StoreConfig& config) override;
    void Shutdown() override;
    [[nodiscard]] bool IsInitialized() const noexcept override;

    [[nodiscard]] bool Store(TelemetryEvent&& event) override;
    [[nodiscard]] bool StoreBatch(std::vector<TelemetryEvent>&& events) override;

    [[nodiscard]] QueryResult Query(const QueryParams& params) override;
    [[nodiscard]] std::optional<TelemetryEvent> GetById(uint64_t eventId) override;

    [[nodiscard]] uint64_t PurgeOlderThan(std::chrono::system_clock::time_point cutoff) override;
    [[nodiscard]] uint64_t GetEventCount() const override;
    [[nodiscard]] uint64_t GetStorageSizeBytes() const override;
    [[nodiscard]] TelemetryStats GetStats() const override;
    void ResetStats() override;

private:
    std::unique_ptr<LocalTelemetryStoreImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::Telemetry
