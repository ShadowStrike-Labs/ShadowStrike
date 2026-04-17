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
// ShadowStrike – PhantomEDR Telemetry Serializer
//
// ECS (Elastic Common Schema) compatible JSON serializer for telemetry
// events.  Produces JSON documents suitable for:
//   - Localhost dashboard REST API
//   - Export to external SIEM/SOAR (Pro/Enterprise TelemetryForwarder)
//   - Forensic report generation
//   - NDJSON streaming for bulk ingestion
//
// ECS Reference: https://www.elastic.co/guide/en/ecs/current/index.html
// ===========================================================================
#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "TelemetryTypes.hpp"

namespace ShadowStrike::Products::PhantomEDR::Telemetry {

class TelemetrySerializerImpl;

// ============================================================================
// SERIALIZER CONFIGURATION
// ============================================================================

struct SerializerConfig {
    bool prettyPrint      = false;   ///< Indent JSON output for human readability
    int  indentSpaces     = 2;       ///< Indent width when prettyPrint is enabled
    bool includeMetadata  = true;    ///< Include extensible metadata map in output
    bool includeAgent     = true;    ///< Include agent.* and host.* ECS fields
    std::string agentName = "ShadowStrike-PhantomEDR";
    std::string agentVersion;        ///< Agent version string (e.g. "1.0.0")
    std::string hostName;            ///< Override host name (auto-detected if empty)
    std::string hostId;              ///< Override host ID (auto-detected if empty)
};

// ============================================================================
// TELEMETRY SERIALIZER  (Meyers' Singleton + PIMPL)
// ============================================================================

class TelemetrySerializer {
public:
    [[nodiscard]] static TelemetrySerializer& Instance();

    [[nodiscard]] bool Initialize(const SerializerConfig& config);
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    // ---- Single-event serialization ----------------------------------------

    /// Serialize one TelemetryEvent to an ECS-compatible JSON string.
    [[nodiscard]] bool Serialize(const TelemetryEvent& event,
                                 std::string& outJson) const;

    // ---- Batch serialization -----------------------------------------------

    /// Serialize a batch of events as a JSON array.
    [[nodiscard]] bool SerializeBatch(std::span<const TelemetryEvent> events,
                                      std::string& outJson) const;

    /// Serialize a batch as NDJSON (newline-delimited JSON, one event per line).
    [[nodiscard]] bool SerializeNDJSON(std::span<const TelemetryEvent> events,
                                       std::string& outNdjson) const;

    // ---- Deserialization ---------------------------------------------------

    /// Deserialize an ECS JSON string back to a TelemetryEvent.
    [[nodiscard]] bool Deserialize(std::string_view json,
                                    TelemetryEvent& outEvent) const;

    /// Deserialize a JSON array or NDJSON block into a vector of events.
    [[nodiscard]] bool DeserializeBatch(std::string_view json,
                                        std::vector<TelemetryEvent>& outEvents) const;

    // ---- Statistics serialization ------------------------------------------

    /// Serialize TelemetryStats to JSON for the dashboard API.
    [[nodiscard]] bool SerializeStats(const TelemetryStats& stats,
                                      std::string& outJson) const;

private:
    TelemetrySerializer();
    ~TelemetrySerializer();
    TelemetrySerializer(const TelemetrySerializer&)            = delete;
    TelemetrySerializer& operator=(const TelemetrySerializer&) = delete;

    std::unique_ptr<TelemetrySerializerImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::Telemetry
