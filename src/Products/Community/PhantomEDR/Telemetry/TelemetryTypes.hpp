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
 * ShadowStrike – PhantomEDR Telemetry Type Definitions
 * ============================================================================
 *
 * @file TelemetryTypes.hpp
 * @brief Core type definitions for the EDR telemetry subsystem.
 *
 * Defines all shared enums, event structures, query parameters, and
 * statistics types used across the telemetry pipeline. These types
 * are consumed by ITelemetryStore implementations and telemetry producers.
 *
 * DESIGN NOTES:
 * - All enums use explicit underlying types for stable serialization
 * - Event payload is a tagged variant for type-safe category dispatch
 * - TelemetryStats uses plain integers (atomics are internal to stores)
 * - QueryParams supports composable filtering via std::optional fields
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 */
#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::Telemetry {

// ============================================================================
// EVENT CLASSIFICATION ENUMS
// ============================================================================

/// @brief Top-level event category for telemetry classification.
enum class EventCategory : uint8_t {
    Process     = 0,
    File        = 1,
    Registry    = 2,
    Network     = 3,
    DNS         = 4,
    Module      = 5,
    User        = 6,
    Service     = 7,
    WMI         = 8,
    PowerShell  = 9,
    AMSI        = 10
};

/// @brief Number of distinct EventCategory values. Used for fixed-size arrays.
inline constexpr size_t kEventCategoryCount = 11;

/// @brief Severity classification for telemetry events.
enum class EventSeverity : uint8_t {
    Info     = 0,
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4
};

// ============================================================================
// CATEGORY-SPECIFIC EVENT TYPE ENUMS
// ============================================================================

/// @brief Sub-types for process-related events.
enum class ProcessEventType : uint8_t {
    Created           = 0,
    Terminated        = 1,
    Injected          = 2,
    Hollowed          = 3,
    ImageLoaded       = 4,
    ThreadCreated     = 5,
    HandleDuplicated  = 6
};

/// @brief Sub-types for file-system events.
enum class FileEventType : uint8_t {
    Created          = 0,
    Modified         = 1,
    Deleted          = 2,
    Renamed          = 3,
    Moved            = 4,
    AttributeChanged = 5,
    StreamCreated    = 6
};

/// @brief Sub-types for registry events.
enum class RegistryEventType : uint8_t {
    KeyCreated   = 0,
    KeyDeleted   = 1,
    ValueSet     = 2,
    ValueDeleted = 3,
    KeyRenamed   = 4,
    KeySecurity  = 5
};

/// @brief Sub-types for network events.
enum class NetworkEventType : uint8_t {
    ConnectionOpened = 0,
    ConnectionClosed = 1,
    DataSent         = 2,
    DataReceived     = 3,
    DNSQuery         = 4,
    DNSResponse      = 5,
    ListenStart      = 6
};

// ============================================================================
// CONSTEXPR ENUM-TO-STRING HELPERS
// ============================================================================

/// @brief Convert EventCategory to its string representation.
[[nodiscard]] constexpr std::string_view ToString(EventCategory cat) noexcept {
    switch (cat) {
        case EventCategory::Process:    return "Process";
        case EventCategory::File:       return "File";
        case EventCategory::Registry:   return "Registry";
        case EventCategory::Network:    return "Network";
        case EventCategory::DNS:        return "DNS";
        case EventCategory::Module:     return "Module";
        case EventCategory::User:       return "User";
        case EventCategory::Service:    return "Service";
        case EventCategory::WMI:        return "WMI";
        case EventCategory::PowerShell: return "PowerShell";
        case EventCategory::AMSI:       return "AMSI";
    }
    return "Unknown";
}

/// @brief Convert EventSeverity to its string representation.
[[nodiscard]] constexpr std::string_view ToString(EventSeverity sev) noexcept {
    switch (sev) {
        case EventSeverity::Info:     return "Info";
        case EventSeverity::Low:      return "Low";
        case EventSeverity::Medium:   return "Medium";
        case EventSeverity::High:     return "High";
        case EventSeverity::Critical: return "Critical";
    }
    return "Unknown";
}

/// @brief Convert ProcessEventType to its string representation.
[[nodiscard]] constexpr std::string_view ToString(ProcessEventType t) noexcept {
    switch (t) {
        case ProcessEventType::Created:          return "Created";
        case ProcessEventType::Terminated:       return "Terminated";
        case ProcessEventType::Injected:         return "Injected";
        case ProcessEventType::Hollowed:         return "Hollowed";
        case ProcessEventType::ImageLoaded:      return "ImageLoaded";
        case ProcessEventType::ThreadCreated:    return "ThreadCreated";
        case ProcessEventType::HandleDuplicated: return "HandleDuplicated";
    }
    return "Unknown";
}

/// @brief Convert FileEventType to its string representation.
[[nodiscard]] constexpr std::string_view ToString(FileEventType t) noexcept {
    switch (t) {
        case FileEventType::Created:          return "Created";
        case FileEventType::Modified:         return "Modified";
        case FileEventType::Deleted:          return "Deleted";
        case FileEventType::Renamed:          return "Renamed";
        case FileEventType::Moved:            return "Moved";
        case FileEventType::AttributeChanged: return "AttributeChanged";
        case FileEventType::StreamCreated:    return "StreamCreated";
    }
    return "Unknown";
}

/// @brief Convert RegistryEventType to its string representation.
[[nodiscard]] constexpr std::string_view ToString(RegistryEventType t) noexcept {
    switch (t) {
        case RegistryEventType::KeyCreated:   return "KeyCreated";
        case RegistryEventType::KeyDeleted:   return "KeyDeleted";
        case RegistryEventType::ValueSet:     return "ValueSet";
        case RegistryEventType::ValueDeleted: return "ValueDeleted";
        case RegistryEventType::KeyRenamed:   return "KeyRenamed";
        case RegistryEventType::KeySecurity:  return "KeySecurity";
    }
    return "Unknown";
}

/// @brief Convert NetworkEventType to its string representation.
[[nodiscard]] constexpr std::string_view ToString(NetworkEventType t) noexcept {
    switch (t) {
        case NetworkEventType::ConnectionOpened: return "ConnectionOpened";
        case NetworkEventType::ConnectionClosed: return "ConnectionClosed";
        case NetworkEventType::DataSent:         return "DataSent";
        case NetworkEventType::DataReceived:     return "DataReceived";
        case NetworkEventType::DNSQuery:         return "DNSQuery";
        case NetworkEventType::DNSResponse:      return "DNSResponse";
        case NetworkEventType::ListenStart:      return "ListenStart";
    }
    return "Unknown";
}

// ============================================================================
// EVENT PAYLOAD DATA STRUCTURES
// ============================================================================

/// @brief Payload data specific to process events.
struct ProcessEventData {
    ProcessEventType subType = ProcessEventType::Created;
    std::wstring commandLine;
    std::string  imageHash;          ///< SHA-256 hex of the process image
    std::string  parentImageHash;    ///< SHA-256 hex of the parent image
    uint32_t     integrityLevel = 0; ///< Windows integrity level (SECURITY_MANDATORY_*)
    bool         isElevated = false;
    bool         isSystem   = false;
    std::wstring targetProcessName;  ///< Target for injection/hollowing events
    uint32_t     targetProcessId = 0;
};

/// @brief Payload data specific to file-system events.
struct FileEventData {
    FileEventType subType = FileEventType::Created;
    std::wstring filePath;
    std::wstring oldFilePath;     ///< Previous path for rename/move operations
    std::string  fileHash;        ///< SHA-256 hex of the file content
    uint64_t     fileSize = 0;
    uint32_t     fileAttributes = 0; ///< Win32 FILE_ATTRIBUTE_* flags
};

/// @brief Payload data specific to registry events.
struct RegistryEventData {
    RegistryEventType subType = RegistryEventType::KeyCreated;
    std::wstring keyPath;
    std::wstring valueName;
    uint32_t     valueType = 0;   ///< REG_DWORD, REG_SZ, etc.
    std::vector<uint8_t> valueData;
    std::vector<uint8_t> oldValueData;
};

/// @brief Payload data specific to network events.
struct NetworkEventData {
    NetworkEventType subType = NetworkEventType::ConnectionOpened;
    std::string  localAddr;
    uint16_t     localPort = 0;
    std::string  remoteAddr;
    uint16_t     remotePort = 0;
    uint16_t     protocol = 0;       ///< IPPROTO_TCP (6), IPPROTO_UDP (17), etc.
    uint64_t     bytesTransferred = 0;
    std::string  dnsQuery;
    std::vector<std::string> dnsResponse;
};

// ============================================================================
// EVENT PAYLOAD VARIANT
// ============================================================================

/// @brief Type-safe union of all event payload types.
///        std::monostate represents events with no category-specific payload
///        (e.g. User, Service, WMI, PowerShell, AMSI); additional data for
///        those categories is carried in the metadata map.
using EventPayload = std::variant<
    std::monostate,
    ProcessEventData,
    FileEventData,
    RegistryEventData,
    NetworkEventData
>;

// ============================================================================
// CORE EVENT RECORD
// ============================================================================

/// @brief The fundamental telemetry event record.
///        Every security-relevant observation flows through this structure.
struct TelemetryEvent {
    uint64_t                                     eventId = 0;  ///< Monotonically increasing, assigned by the store
    std::chrono::system_clock::time_point        timestamp{};
    EventCategory                                category  = EventCategory::Process;
    EventSeverity                                severity  = EventSeverity::Info;
    uint32_t                                     processId       = 0;
    uint32_t                                     parentProcessId = 0;
    uint32_t                                     threadId        = 0;
    std::wstring                                 processName;
    std::wstring                                 processPath;
    std::wstring                                 userName;
    std::string                                  sessionId;      ///< Correlation session identifier
    std::string                                  mitreAttackId;  ///< MITRE ATT&CK technique (e.g. "T1055.001")
    EventPayload                                 payload;
    std::unordered_map<std::string, std::string> metadata;       ///< Extensible key-value tags
};

// ============================================================================
// QUERY PARAMETERS
// ============================================================================

/// @brief Composable filter parameters for querying the telemetry store.
///        Only non-nullopt fields are included in the WHERE clause.
struct QueryParams {
    std::optional<EventCategory>                          category;
    std::optional<EventSeverity>                          minSeverity;
    std::optional<uint32_t>                               processId;
    std::optional<std::chrono::system_clock::time_point>  startTime;
    std::optional<std::chrono::system_clock::time_point>  endTime;
    std::optional<std::string>                            mitreAttackId;
    std::optional<std::wstring>                           processNamePattern;  ///< SQL LIKE pattern
    uint32_t maxResults = 1000;
    uint32_t offset     = 0;
};

/// @brief Result envelope for a telemetry query.
struct QueryResult {
    std::vector<TelemetryEvent> events;
    uint64_t totalCount = 0;   ///< Total matching rows (ignoring LIMIT/OFFSET)
    bool     hasMore    = false;
};

// ============================================================================
// AGGREGATE STATISTICS
// ============================================================================

/// @brief Snapshot of telemetry pipeline counters.
///        Values are plain integers copied from internal atomics.
struct TelemetryStats {
    uint64_t eventsReceived  = 0;
    uint64_t eventsStored    = 0;
    uint64_t eventsDropped   = 0;
    uint64_t eventsFiltered  = 0;
    std::array<uint64_t, kEventCategoryCount> eventsByCategory{};
    uint64_t storageUsedBytes = 0;
    uint64_t purgeCount       = 0;
};

} // namespace ShadowStrike::Products::PhantomEDR::Telemetry
