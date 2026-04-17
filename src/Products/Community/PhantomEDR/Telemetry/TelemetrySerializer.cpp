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
// ShadowStrike – PhantomEDR Telemetry Serializer Implementation
//
// ECS (Elastic Common Schema) v8.x compatible serialization.  Every
// TelemetryEvent is mapped to the corresponding ECS field set:
//
//   EventCategory::Process  → ecs.event.category:"process",  process.*
//   EventCategory::File     → ecs.event.category:"file",     file.*
//   EventCategory::Registry → ecs.event.category:"registry", registry.*
//   EventCategory::Network  → ecs.event.category:"network",  source.* / destination.*
//   Other                   → ecs.event.category:<name>,     custom fields in labels.*
//
// Threading: all public methods are const — no internal mutation.  The
// serializer holds only configuration captured at Initialize time and
// static host metadata.  Multiple threads may call Serialize concurrently.
// ===========================================================================

#include "pch.h"
#include "TelemetrySerializer.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <shared_mutex>
#include <sstream>

#include <nlohmann/json.hpp>

#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

namespace ShadowStrike::Products::PhantomEDR::Telemetry {

using Json = nlohmann::json;

// ============================================================================
// ANONYMOUS HELPERS
// ============================================================================

namespace {

/// Format system_clock::time_point as ISO 8601 with milliseconds and 'Z' suffix.
/// Example: "2026-04-17T13:02:33.681Z"
std::string FormatISO8601(const std::chrono::system_clock::time_point& tp) noexcept
{
    try {
        const auto epoch = tp.time_since_epoch();
        const auto secs  = std::chrono::duration_cast<std::chrono::seconds>(epoch);
        const auto ms    = std::chrono::duration_cast<std::chrono::milliseconds>(epoch) - secs;

        const std::time_t tt = std::chrono::system_clock::to_time_t(tp);
        std::tm utc{};
#ifdef _WIN32
        if (gmtime_s(&utc, &tt) != 0) return {};
#else
        if (!gmtime_r(&tt, &utc)) return {};
#endif
        // "YYYY-MM-DDTHH:MM:SS.mmmZ" = 24 chars + NUL
        char buf[32]{};
        const int written = std::snprintf(buf, sizeof(buf),
            "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
            utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday,
            utc.tm_hour, utc.tm_min, utc.tm_sec,
            static_cast<int>(ms.count()));
        if (written <= 0 || written >= static_cast<int>(sizeof(buf))) return {};
        return std::string(buf, static_cast<size_t>(written));
    }
    catch (...) {
        return {};
    }
}

/// Parse ISO 8601 timestamp back to time_point.
bool ParseISO8601(std::string_view str,
                  std::chrono::system_clock::time_point& out) noexcept
{
    if (str.size() < 20) return false;  // minimum "YYYY-MM-DDTHH:MM:SSZ"

    std::tm utc{};
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0, ms = 0;

    // Parse mandatory components
    auto r = std::from_chars(str.data(), str.data() + 4, year);
    if (r.ec != std::errc{} || *r.ptr != '-') return false;
    r = std::from_chars(r.ptr + 1, str.data() + 7, month);
    if (r.ec != std::errc{} || *r.ptr != '-') return false;
    r = std::from_chars(r.ptr + 1, str.data() + 10, day);
    if (r.ec != std::errc{} || *r.ptr != 'T') return false;
    r = std::from_chars(r.ptr + 1, str.data() + 13, hour);
    if (r.ec != std::errc{} || *r.ptr != ':') return false;
    r = std::from_chars(r.ptr + 1, str.data() + 16, minute);
    if (r.ec != std::errc{} || *r.ptr != ':') return false;
    r = std::from_chars(r.ptr + 1, str.data() + 19, second);
    if (r.ec != std::errc{}) return false;

    // Optional milliseconds ".NNN"
    const char* p = r.ptr;
    if (p < str.data() + str.size() && *p == '.') {
        ++p;
        const char* msEnd = std::min(p + 3, str.data() + str.size());
        r = std::from_chars(p, msEnd, ms);
        if (r.ec != std::errc{}) ms = 0;
        p = r.ptr;
    }

    // Expect trailing 'Z' (we only handle UTC)
    if (p >= str.data() + str.size() || *p != 'Z') return false;

    // Validate ranges
    if (month < 1 || month > 12 || day < 1 || day > 31) return false;
    if (hour > 23 || minute > 59 || second > 60) return false;
    if (ms < 0 || ms > 999) return false;

    utc.tm_year  = year - 1900;
    utc.tm_mon   = month - 1;
    utc.tm_mday  = day;
    utc.tm_hour  = hour;
    utc.tm_min   = minute;
    utc.tm_sec   = second;
    utc.tm_isdst = 0;

#ifdef _WIN32
    const std::time_t tt = _mkgmtime(&utc);
#else
    const std::time_t tt = timegm(&utc);
#endif
    if (tt == static_cast<std::time_t>(-1)) return false;

    out = std::chrono::system_clock::from_time_t(tt)
        + std::chrono::milliseconds(ms);
    return true;
}

/// Map EventCategory to ECS event.category array entry.
std::string_view CategoryToECS(EventCategory cat) noexcept
{
    switch (cat) {
        case EventCategory::Process:    return "process";
        case EventCategory::File:       return "file";
        case EventCategory::Registry:   return "registry";
        case EventCategory::Network:    return "network";
        case EventCategory::DNS:        return "network";
        case EventCategory::Module:     return "driver";
        case EventCategory::User:       return "iam";
        case EventCategory::Service:    return "configuration";
        case EventCategory::WMI:        return "process";
        case EventCategory::PowerShell: return "process";
        case EventCategory::AMSI:       return "intrusion_detection";
    }
    return "host";
}

/// Map EventSeverity to ECS numeric severity (0–100 scale).
int SeverityToECS(EventSeverity sev) noexcept
{
    switch (sev) {
        case EventSeverity::Info:     return 0;
        case EventSeverity::Low:      return 25;
        case EventSeverity::Medium:   return 50;
        case EventSeverity::High:     return 75;
        case EventSeverity::Critical: return 100;
    }
    return 0;
}

/// Map ProcessEventType to ECS event.type entries.
std::vector<std::string> ProcessTypeToECS(ProcessEventType t)
{
    switch (t) {
        case ProcessEventType::Created:          return {"start", "creation"};
        case ProcessEventType::Terminated:       return {"end"};
        case ProcessEventType::Injected:         return {"change", "info"};
        case ProcessEventType::Hollowed:         return {"change", "info"};
        case ProcessEventType::ImageLoaded:      return {"info"};
        case ProcessEventType::ThreadCreated:    return {"start"};
        case ProcessEventType::HandleDuplicated: return {"info"};
    }
    return {"info"};
}

/// Map FileEventType to ECS event.type entries.
std::vector<std::string> FileTypeToECS(FileEventType t)
{
    switch (t) {
        case FileEventType::Created:          return {"creation"};
        case FileEventType::Modified:         return {"change"};
        case FileEventType::Deleted:          return {"deletion"};
        case FileEventType::Renamed:          return {"change"};
        case FileEventType::Moved:            return {"change"};
        case FileEventType::AttributeChanged: return {"change"};
        case FileEventType::StreamCreated:    return {"creation"};
    }
    return {"info"};
}

/// Map RegistryEventType to ECS event.type entries.
std::vector<std::string> RegistryTypeToECS(RegistryEventType t)
{
    switch (t) {
        case RegistryEventType::KeyCreated:   return {"creation"};
        case RegistryEventType::KeyDeleted:   return {"deletion"};
        case RegistryEventType::ValueSet:     return {"change"};
        case RegistryEventType::ValueDeleted: return {"deletion"};
        case RegistryEventType::KeyRenamed:   return {"change"};
        case RegistryEventType::KeySecurity:  return {"change"};
    }
    return {"info"};
}

/// Map NetworkEventType to ECS event.type entries.
std::vector<std::string> NetworkTypeToECS(NetworkEventType t)
{
    switch (t) {
        case NetworkEventType::ConnectionOpened: return {"start", "connection"};
        case NetworkEventType::ConnectionClosed: return {"end", "connection"};
        case NetworkEventType::DataSent:         return {"info", "connection"};
        case NetworkEventType::DataReceived:     return {"info", "connection"};
        case NetworkEventType::DNSQuery:         return {"info", "protocol"};
        case NetworkEventType::DNSResponse:      return {"info", "protocol"};
        case NetworkEventType::ListenStart:      return {"start"};
    }
    return {"info"};
}

/// Narrow helper: convert wstring to UTF-8 using existing Utils.
std::string Narrow(const std::wstring& ws)
{
    if (ws.empty()) return {};
    return ShadowStrike::Utils::StringUtils::WStringToString(ws);
}

} // anonymous namespace

// ============================================================================
// TELEMETRY SERIALIZER IMPLEMENTATION  (PIMPL — free class, NOT nested)
// ============================================================================

class TelemetrySerializerImpl {
public:
    TelemetrySerializerImpl() = default;
    ~TelemetrySerializerImpl() = default;

    // -- Lifecycle -----------------------------------------------------------
    bool Initialize(const SerializerConfig& config);
    void Shutdown();
    bool IsInitialized() const noexcept { return m_initialized.load(std::memory_order_acquire); }

    // -- Serialize -----------------------------------------------------------
    bool Serialize(const TelemetryEvent& event, std::string& outJson) const;
    bool SerializeBatch(std::span<const TelemetryEvent> events, std::string& outJson) const;
    bool SerializeNDJSON(std::span<const TelemetryEvent> events, std::string& outNdjson) const;

    // -- Deserialize ---------------------------------------------------------
    bool Deserialize(std::string_view json, TelemetryEvent& outEvent) const;
    bool DeserializeBatch(std::string_view json, std::vector<TelemetryEvent>& outEvents) const;

    // -- Stats ---------------------------------------------------------------
    bool SerializeStats(const TelemetryStats& stats, std::string& outJson) const;

private:
    // -- Core mapping --------------------------------------------------------
    Json EventToECS(const TelemetryEvent& event) const;
    bool ECSToEvent(const Json& j, TelemetryEvent& event) const;

    // -- Payload serializers -------------------------------------------------
    void SerializeProcessPayload(const ProcessEventData& d, Json& j) const;
    void SerializeFilePayload(const FileEventData& d, Json& j) const;
    void SerializeRegistryPayload(const RegistryEventData& d, Json& j) const;
    void SerializeNetworkPayload(const NetworkEventData& d, Json& j) const;

    // -- Payload deserializers -----------------------------------------------
    bool DeserializeProcessPayload(const Json& j, ProcessEventData& d) const;
    bool DeserializeFilePayload(const Json& j, FileEventData& d) const;
    bool DeserializeRegistryPayload(const Json& j, RegistryEventData& d) const;
    bool DeserializeNetworkPayload(const Json& j, NetworkEventData& d) const;

    // -- Configuration (immutable after Initialize) --------------------------
    SerializerConfig m_config;
    std::string      m_resolvedHostName;
    std::string      m_resolvedHostId;

    std::atomic<bool> m_initialized{false};
};

// ============================================================================
// LIFECYCLE
// ============================================================================

bool TelemetrySerializerImpl::Initialize(const SerializerConfig& config)
{
    if (m_initialized.load(std::memory_order_acquire)) {
        ShadowStrike::Utils::Logger::Warn(
            "[TelemetrySerializer] Already initialized — ignoring duplicate call");
        return false;
    }

    m_config = config;

    // Resolve hostname if not explicitly set
    if (m_config.hostName.empty()) {
        wchar_t compName[MAX_COMPUTERNAME_LENGTH + 1]{};
        DWORD   compLen = MAX_COMPUTERNAME_LENGTH + 1;
        if (::GetComputerNameW(compName, &compLen)) {
            m_resolvedHostName = Narrow(std::wstring(compName, compLen));
        } else {
            m_resolvedHostName = "unknown";
        }
    } else {
        m_resolvedHostName = m_config.hostName;
    }

    // Resolve host ID: use SMBIOS UUID via registry as a stable machine identifier
    if (m_config.hostId.empty()) {
        HKEY hKey = nullptr;
        if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Cryptography",
                0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
        {
            wchar_t machGuid[128]{};
            DWORD   guidLen = sizeof(machGuid);
            DWORD   type    = 0;
            if (::RegQueryValueExW(hKey, L"MachineGuid", nullptr, &type,
                    reinterpret_cast<BYTE*>(machGuid), &guidLen) == ERROR_SUCCESS
                && type == REG_SZ)
            {
                m_resolvedHostId = Narrow(std::wstring(machGuid, guidLen / sizeof(wchar_t)));
                // Trim trailing null if present
                while (!m_resolvedHostId.empty() && m_resolvedHostId.back() == '\0') {
                    m_resolvedHostId.pop_back();
                }
            }
            ::RegCloseKey(hKey);
        }
        if (m_resolvedHostId.empty()) {
            m_resolvedHostId = "unknown";
        }
    } else {
        m_resolvedHostId = m_config.hostId;
    }

    m_initialized.store(true, std::memory_order_release);

    ShadowStrike::Utils::Logger::Info(
        "[TelemetrySerializer] Initialized — host={}, pretty={}, agent={}",
        m_resolvedHostName, m_config.prettyPrint, m_config.agentName);

    return true;
}

void TelemetrySerializerImpl::Shutdown()
{
    m_initialized.store(false, std::memory_order_release);
    ShadowStrike::Utils::Logger::Info("[TelemetrySerializer] Shutdown");
}

// ============================================================================
// SINGLE-EVENT SERIALIZATION
// ============================================================================

bool TelemetrySerializerImpl::Serialize(const TelemetryEvent& event,
                                         std::string& outJson) const
{
    if (!m_initialized.load(std::memory_order_acquire)) return false;

    try {
        const Json j = EventToECS(event);
        outJson = m_config.prettyPrint
            ? j.dump(m_config.indentSpaces)
            : j.dump(-1);
        return true;
    }
    catch (const std::exception& ex) {
        ShadowStrike::Utils::Logger::Error(
            "[TelemetrySerializer] Serialize failed: {}", ex.what());
        return false;
    }
}

// ============================================================================
// BATCH SERIALIZATION
// ============================================================================

bool TelemetrySerializerImpl::SerializeBatch(
    std::span<const TelemetryEvent> events, std::string& outJson) const
{
    if (!m_initialized.load(std::memory_order_acquire)) return false;

    try {
        Json arr = Json::array();
        arr.get_ref<Json::array_t&>().reserve(events.size());

        for (const auto& ev : events) {
            arr.push_back(EventToECS(ev));
        }

        outJson = m_config.prettyPrint
            ? arr.dump(m_config.indentSpaces)
            : arr.dump(-1);
        return true;
    }
    catch (const std::exception& ex) {
        ShadowStrike::Utils::Logger::Error(
            "[TelemetrySerializer] SerializeBatch failed: {}", ex.what());
        return false;
    }
}

bool TelemetrySerializerImpl::SerializeNDJSON(
    std::span<const TelemetryEvent> events, std::string& outNdjson) const
{
    if (!m_initialized.load(std::memory_order_acquire)) return false;

    try {
        // Pre-reserve: ~512 bytes per event is a reasonable estimate
        outNdjson.clear();
        outNdjson.reserve(events.size() * 512);

        for (const auto& ev : events) {
            const Json j = EventToECS(ev);
            outNdjson += j.dump(-1);  // always compact for NDJSON
            outNdjson += '\n';
        }

        return true;
    }
    catch (const std::exception& ex) {
        ShadowStrike::Utils::Logger::Error(
            "[TelemetrySerializer] SerializeNDJSON failed: {}", ex.what());
        return false;
    }
}

// ============================================================================
// DESERIALIZATION
// ============================================================================

bool TelemetrySerializerImpl::Deserialize(std::string_view json,
                                           TelemetryEvent& outEvent) const
{
    if (!m_initialized.load(std::memory_order_acquire)) return false;
    if (json.empty()) return false;

    try {
        const Json j = Json::parse(json, nullptr, false);
        if (j.is_discarded()) {
            ShadowStrike::Utils::Logger::Warn(
                "[TelemetrySerializer] Deserialize: invalid JSON input");
            return false;
        }
        return ECSToEvent(j, outEvent);
    }
    catch (const std::exception& ex) {
        ShadowStrike::Utils::Logger::Error(
            "[TelemetrySerializer] Deserialize failed: {}", ex.what());
        return false;
    }
}

bool TelemetrySerializerImpl::DeserializeBatch(
    std::string_view json, std::vector<TelemetryEvent>& outEvents) const
{
    if (!m_initialized.load(std::memory_order_acquire)) return false;
    if (json.empty()) return false;

    try {
        // Detect NDJSON vs JSON array
        const bool isNdjson = (!json.empty() && json.front() != '[');

        if (isNdjson) {
            // Parse line by line
            size_t pos = 0;
            while (pos < json.size()) {
                const size_t eol = json.find('\n', pos);
                const auto line = (eol != std::string_view::npos)
                    ? json.substr(pos, eol - pos)
                    : json.substr(pos);

                if (!line.empty()) {
                    const Json j = Json::parse(line, nullptr, false);
                    if (!j.is_discarded()) {
                        TelemetryEvent ev{};
                        if (ECSToEvent(j, ev)) {
                            outEvents.push_back(std::move(ev));
                        }
                    }
                }

                pos = (eol != std::string_view::npos) ? eol + 1 : json.size();
            }
        } else {
            // JSON array
            const Json arr = Json::parse(json, nullptr, false);
            if (arr.is_discarded() || !arr.is_array()) return false;

            outEvents.reserve(arr.size());
            for (const auto& item : arr) {
                TelemetryEvent ev{};
                if (ECSToEvent(item, ev)) {
                    outEvents.push_back(std::move(ev));
                }
            }
        }

        return !outEvents.empty();
    }
    catch (const std::exception& ex) {
        ShadowStrike::Utils::Logger::Error(
            "[TelemetrySerializer] DeserializeBatch failed: {}", ex.what());
        return false;
    }
}

// ============================================================================
// STATISTICS SERIALIZATION
// ============================================================================

bool TelemetrySerializerImpl::SerializeStats(const TelemetryStats& stats,
                                              std::string& outJson) const
{
    if (!m_initialized.load(std::memory_order_acquire)) return false;

    try {
        Json j = Json::object();

        j["@timestamp"]   = FormatISO8601(std::chrono::system_clock::now());
        j["event"]["kind"]     = "metric";
        j["event"]["dataset"]  = "shadowstrike.telemetry.stats";

        // Pipeline counters
        auto& pipeline = j["shadowstrike"]["telemetry"]["pipeline"];
        pipeline["events_received"]  = stats.totalEventsReceived;
        pipeline["events_stored"]    = stats.totalEventsStored;
        pipeline["events_dropped"]   = stats.totalEventsDropped;
        pipeline["events_filtered"]  = stats.totalEventsFiltered;
        pipeline["events_pending"]   = stats.pendingEvents;
        pipeline["purge_count"]      = stats.purgeCount;
        pipeline["storage_bytes"]    = stats.storageUsedBytes;

        // Per-category breakdown
        auto& byCategory = pipeline["by_category"];
        static constexpr std::string_view kCatNames[] = {
            "process", "file", "registry", "network", "dns",
            "module", "user", "service", "wmi", "powershell", "amsi"
        };
        for (size_t i = 0; i < kEventCategoryCount && i < std::size(kCatNames); ++i) {
            byCategory[std::string(kCatNames[i])] = stats.eventsByCategory[i];
        }

        if (m_config.includeAgent) {
            j["agent"]["name"]    = m_config.agentName;
            j["agent"]["version"] = m_config.agentVersion;
            j["host"]["name"]     = m_resolvedHostName;
            j["host"]["id"]       = m_resolvedHostId;
        }

        outJson = m_config.prettyPrint
            ? j.dump(m_config.indentSpaces)
            : j.dump(-1);
        return true;
    }
    catch (const std::exception& ex) {
        ShadowStrike::Utils::Logger::Error(
            "[TelemetrySerializer] SerializeStats failed: {}", ex.what());
        return false;
    }
}

// ============================================================================
// CORE ECS MAPPING:  TelemetryEvent → JSON
// ============================================================================

Json TelemetrySerializerImpl::EventToECS(const TelemetryEvent& event) const
{
    Json j = Json::object();

    // -- ECS base fields --
    j["@timestamp"] = FormatISO8601(event.timestamp);

    // event.* field set
    j["event"]["id"]       = std::to_string(event.eventId);
    j["event"]["kind"]     = "event";
    j["event"]["category"] = Json::array({std::string(CategoryToECS(event.category))});
    j["event"]["severity"] = SeverityToECS(event.severity);
    j["event"]["dataset"]  = "shadowstrike.edr.telemetry";
    j["event"]["module"]   = "shadowstrike";

    // ECS event.type depends on the payload sub-type
    std::visit([&](const auto& payload) {
        using T = std::decay_t<decltype(payload)>;
        if constexpr (std::is_same_v<T, ProcessEventData>) {
            j["event"]["type"] = ProcessTypeToECS(payload.subType);
            j["event"]["action"] = std::string(ToString(payload.subType));
        } else if constexpr (std::is_same_v<T, FileEventData>) {
            j["event"]["type"] = FileTypeToECS(payload.subType);
            j["event"]["action"] = std::string(ToString(payload.subType));
        } else if constexpr (std::is_same_v<T, RegistryEventData>) {
            j["event"]["type"] = RegistryTypeToECS(payload.subType);
            j["event"]["action"] = std::string(ToString(payload.subType));
        } else if constexpr (std::is_same_v<T, NetworkEventData>) {
            j["event"]["type"] = NetworkTypeToECS(payload.subType);
            j["event"]["action"] = std::string(ToString(payload.subType));
        } else {
            j["event"]["type"] = Json::array({"info"});
            j["event"]["action"] = std::string(ToString(event.category));
        }
    }, event.payload);

    // -- process.* field set (present on almost every event) --
    if (event.processId != 0) {
        j["process"]["pid"]  = event.processId;
        if (!event.processName.empty())
            j["process"]["name"] = Narrow(event.processName);
        if (!event.processPath.empty())
            j["process"]["executable"] = Narrow(event.processPath);
        if (event.parentProcessId != 0)
            j["process"]["parent"]["pid"] = event.parentProcessId;
        if (event.threadId != 0)
            j["process"]["thread"]["id"] = event.threadId;
    }

    // -- user.name --
    if (!event.userName.empty()) {
        j["user"]["name"] = Narrow(event.userName);
    }

    // -- threat.technique (MITRE ATT&CK) --
    if (!event.mitreAttackId.empty()) {
        j["threat"]["technique"]["id"]   = Json::array({event.mitreAttackId});
        j["threat"]["framework"]         = "MITRE ATT&CK";
    }

    // -- Payload-specific ECS fields --
    std::visit([&](const auto& payload) {
        using T = std::decay_t<decltype(payload)>;
        if constexpr (std::is_same_v<T, ProcessEventData>) {
            SerializeProcessPayload(payload, j);
        } else if constexpr (std::is_same_v<T, FileEventData>) {
            SerializeFilePayload(payload, j);
        } else if constexpr (std::is_same_v<T, RegistryEventData>) {
            SerializeRegistryPayload(payload, j);
        } else if constexpr (std::is_same_v<T, NetworkEventData>) {
            SerializeNetworkPayload(payload, j);
        }
    }, event.payload);

    // -- agent/host ECS fields --
    if (m_config.includeAgent) {
        j["agent"]["name"]    = m_config.agentName;
        j["agent"]["type"]    = "edr";
        j["agent"]["version"] = m_config.agentVersion;
        j["host"]["name"]     = m_resolvedHostName;
        j["host"]["id"]       = m_resolvedHostId;
    }

    // -- Correlation session --
    if (!event.sessionId.empty()) {
        j["session"]["id"] = event.sessionId;
    }

    // -- Extensible metadata → ECS labels.* --
    if (m_config.includeMetadata && !event.metadata.empty()) {
        for (const auto& [k, v] : event.metadata) {
            j["labels"][k] = v;
        }
    }

    // -- ShadowStrike extensions (not in core ECS) --
    j["shadowstrike"]["event"]["category"]        = std::string(ToString(event.category));
    j["shadowstrike"]["event"]["severity"]         = std::string(ToString(event.severity));
    j["shadowstrike"]["event"]["internal_id"]      = event.eventId;

    return j;
}

// ============================================================================
// PAYLOAD SERIALIZERS
// ============================================================================

void TelemetrySerializerImpl::SerializeProcessPayload(
    const ProcessEventData& d, Json& j) const
{
    if (!d.commandLine.empty())
        j["process"]["command_line"] = Narrow(d.commandLine);
    if (!d.imageHash.empty())
        j["process"]["hash"]["sha256"] = d.imageHash;
    if (!d.parentImageHash.empty())
        j["process"]["parent"]["hash"]["sha256"] = d.parentImageHash;

    j["process"]["integrity_level"] = d.integrityLevel;

    if (d.isElevated)
        j["process"]["elevated"] = true;
    if (d.isSystem)
        j["process"]["user"]["id"] = "S-1-5-18";  // NT AUTHORITY\SYSTEM

    // Injection/hollowing target
    if (d.targetProcessId != 0) {
        j["process"]["target"]["pid"]  = d.targetProcessId;
        if (!d.targetProcessName.empty())
            j["process"]["target"]["name"] = Narrow(d.targetProcessName);
    }
}

void TelemetrySerializerImpl::SerializeFilePayload(
    const FileEventData& d, Json& j) const
{
    if (!d.filePath.empty())
        j["file"]["path"] = Narrow(d.filePath);
    if (!d.oldFilePath.empty())
        j["file"]["previous"]["path"] = Narrow(d.oldFilePath);
    if (!d.fileHash.empty())
        j["file"]["hash"]["sha256"] = d.fileHash;
    if (d.fileSize > 0)
        j["file"]["size"] = d.fileSize;
    if (d.fileAttributes != 0)
        j["file"]["attributes"] = d.fileAttributes;
}

void TelemetrySerializerImpl::SerializeRegistryPayload(
    const RegistryEventData& d, Json& j) const
{
    if (!d.keyPath.empty())
        j["registry"]["path"] = Narrow(d.keyPath);
    if (!d.valueName.empty())
        j["registry"]["value"] = Narrow(d.valueName);
    if (d.valueType != 0)
        j["registry"]["data"]["type"] = d.valueType;
}

void TelemetrySerializerImpl::SerializeNetworkPayload(
    const NetworkEventData& d, Json& j) const
{
    // ECS uses source.* and destination.* for network events
    if (!d.localAddr.empty()) {
        j["source"]["ip"]   = d.localAddr;
        j["source"]["port"] = d.localPort;
    }
    if (!d.remoteAddr.empty()) {
        j["destination"]["ip"]   = d.remoteAddr;
        j["destination"]["port"] = d.remotePort;
    }

    if (d.protocol != 0) {
        j["network"]["iana_number"] = d.protocol;
        if (d.protocol == 6)
            j["network"]["transport"] = "tcp";
        else if (d.protocol == 17)
            j["network"]["transport"] = "udp";
    }

    if (d.bytesTransferred > 0)
        j["network"]["bytes"] = d.bytesTransferred;

    if (!d.dnsQuery.empty()) {
        j["dns"]["question"]["name"] = d.dnsQuery;
        if (!d.dnsResponse.empty()) {
            Json answers = Json::array();
            for (const auto& ans : d.dnsResponse) {
                answers.push_back(Json{{"data", ans}});
            }
            j["dns"]["answers"] = std::move(answers);
        }
    }
}

// ============================================================================
// CORE ECS MAPPING:  JSON → TelemetryEvent
// ============================================================================

bool TelemetrySerializerImpl::ECSToEvent(const Json& j,
                                          TelemetryEvent& event) const
{
    try {
        // @timestamp
        if (j.contains("@timestamp") && j["@timestamp"].is_string()) {
            if (!ParseISO8601(j["@timestamp"].get<std::string>(), event.timestamp)) {
                return false;
            }
        }

        // event.id
        if (j.contains("event") && j["event"].contains("id")) {
            const auto& idVal = j["event"]["id"];
            if (idVal.is_string()) {
                event.eventId = std::stoull(idVal.get<std::string>());
            } else if (idVal.is_number_unsigned()) {
                event.eventId = idVal.get<uint64_t>();
            }
        }

        // event.severity
        if (j.contains("event") && j["event"].contains("severity")) {
            const int sev = j["event"]["severity"].get<int>();
            if (sev >= 100)     event.severity = EventSeverity::Critical;
            else if (sev >= 75) event.severity = EventSeverity::High;
            else if (sev >= 50) event.severity = EventSeverity::Medium;
            else if (sev >= 25) event.severity = EventSeverity::Low;
            else                event.severity = EventSeverity::Info;
        }

        // ShadowStrike internal category (more precise than ECS category)
        if (j.contains("shadowstrike") &&
            j["shadowstrike"].contains("event") &&
            j["shadowstrike"]["event"].contains("category"))
        {
            const auto catStr = j["shadowstrike"]["event"]["category"].get<std::string>();
            // Map string back to enum
            static const std::unordered_map<std::string, EventCategory> kCatMap = {
                {"Process",    EventCategory::Process},
                {"File",       EventCategory::File},
                {"Registry",   EventCategory::Registry},
                {"Network",    EventCategory::Network},
                {"DNS",        EventCategory::DNS},
                {"Module",     EventCategory::Module},
                {"User",       EventCategory::User},
                {"Service",    EventCategory::Service},
                {"WMI",        EventCategory::WMI},
                {"PowerShell", EventCategory::PowerShell},
                {"AMSI",       EventCategory::AMSI},
            };
            if (auto it = kCatMap.find(catStr); it != kCatMap.end()) {
                event.category = it->second;
            }
        }

        // ShadowStrike internal_id (canonical event ID)
        if (j.contains("shadowstrike") &&
            j["shadowstrike"].contains("event") &&
            j["shadowstrike"]["event"].contains("internal_id"))
        {
            event.eventId = j["shadowstrike"]["event"]["internal_id"].get<uint64_t>();
        }

        // process.*
        if (j.contains("process")) {
            const auto& proc = j["process"];
            if (proc.contains("pid"))
                event.processId = proc["pid"].get<uint32_t>();
            if (proc.contains("name"))
                event.processName = ShadowStrike::Utils::StringUtils::utf8_to_wstring(
                    proc["name"].get<std::string>().c_str());
            if (proc.contains("executable"))
                event.processPath = ShadowStrike::Utils::StringUtils::utf8_to_wstring(
                    proc["executable"].get<std::string>().c_str());
            if (proc.contains("parent") && proc["parent"].contains("pid"))
                event.parentProcessId = proc["parent"]["pid"].get<uint32_t>();
            if (proc.contains("thread") && proc["thread"].contains("id"))
                event.threadId = proc["thread"]["id"].get<uint32_t>();
        }

        // user.name
        if (j.contains("user") && j["user"].contains("name")) {
            event.userName = ShadowStrike::Utils::StringUtils::utf8_to_wstring(
                j["user"]["name"].get<std::string>().c_str());
        }

        // threat.technique (MITRE ATT&CK)
        if (j.contains("threat") && j["threat"].contains("technique")) {
            const auto& tech = j["threat"]["technique"];
            if (tech.contains("id") && tech["id"].is_array() && !tech["id"].empty()) {
                event.mitreAttackId = tech["id"][0].get<std::string>();
            }
        }

        // session.id
        if (j.contains("session") && j["session"].contains("id")) {
            event.sessionId = j["session"]["id"].get<std::string>();
        }

        // labels.* → metadata
        if (j.contains("labels") && j["labels"].is_object()) {
            for (auto it = j["labels"].begin(); it != j["labels"].end(); ++it) {
                if (it.value().is_string()) {
                    event.metadata[it.key()] = it.value().get<std::string>();
                } else {
                    event.metadata[it.key()] = it.value().dump();
                }
            }
        }

        // -- Category-specific payload deserialization --
        switch (event.category) {
            case EventCategory::Process: {
                ProcessEventData d{};
                DeserializeProcessPayload(j, d);
                event.payload = std::move(d);
                break;
            }
            case EventCategory::File: {
                FileEventData d{};
                DeserializeFilePayload(j, d);
                event.payload = std::move(d);
                break;
            }
            case EventCategory::Registry: {
                RegistryEventData d{};
                DeserializeRegistryPayload(j, d);
                event.payload = std::move(d);
                break;
            }
            case EventCategory::Network:
            case EventCategory::DNS: {
                NetworkEventData d{};
                DeserializeNetworkPayload(j, d);
                event.payload = std::move(d);
                break;
            }
            default:
                event.payload = std::monostate{};
                break;
        }

        return true;
    }
    catch (const std::exception& ex) {
        ShadowStrike::Utils::Logger::Error(
            "[TelemetrySerializer] ECSToEvent failed: {}", ex.what());
        return false;
    }
}

// ============================================================================
// PAYLOAD DESERIALIZERS
// ============================================================================

bool TelemetrySerializerImpl::DeserializeProcessPayload(
    const Json& j, ProcessEventData& d) const
{
    // Map ECS event.action back to ProcessEventType
    if (j.contains("event") && j["event"].contains("action")) {
        const auto action = j["event"]["action"].get<std::string>();
        static const std::unordered_map<std::string, ProcessEventType> kMap = {
            {"Created",          ProcessEventType::Created},
            {"Terminated",       ProcessEventType::Terminated},
            {"Injected",         ProcessEventType::Injected},
            {"Hollowed",         ProcessEventType::Hollowed},
            {"ImageLoaded",      ProcessEventType::ImageLoaded},
            {"ThreadCreated",    ProcessEventType::ThreadCreated},
            {"HandleDuplicated", ProcessEventType::HandleDuplicated},
        };
        if (auto it = kMap.find(action); it != kMap.end())
            d.subType = it->second;
    }

    if (j.contains("process")) {
        const auto& proc = j["process"];
        if (proc.contains("command_line"))
            d.commandLine = ShadowStrike::Utils::StringUtils::utf8_to_wstring(
                proc["command_line"].get<std::string>().c_str());
        if (proc.contains("hash") && proc["hash"].contains("sha256"))
            d.imageHash = proc["hash"]["sha256"].get<std::string>();
        if (proc.contains("parent") && proc["parent"].contains("hash") &&
            proc["parent"]["hash"].contains("sha256"))
            d.parentImageHash = proc["parent"]["hash"]["sha256"].get<std::string>();
        if (proc.contains("integrity_level"))
            d.integrityLevel = proc["integrity_level"].get<uint32_t>();
        if (proc.contains("elevated"))
            d.isElevated = proc["elevated"].get<bool>();
        if (proc.contains("user") && proc["user"].contains("id"))
            d.isSystem = (proc["user"]["id"].get<std::string>() == "S-1-5-18");
        if (proc.contains("target")) {
            const auto& tgt = proc["target"];
            if (tgt.contains("pid"))
                d.targetProcessId = tgt["pid"].get<uint32_t>();
            if (tgt.contains("name"))
                d.targetProcessName = ShadowStrike::Utils::StringUtils::utf8_to_wstring(
                    tgt["name"].get<std::string>().c_str());
        }
    }

    return true;
}

bool TelemetrySerializerImpl::DeserializeFilePayload(
    const Json& j, FileEventData& d) const
{
    if (j.contains("event") && j["event"].contains("action")) {
        const auto action = j["event"]["action"].get<std::string>();
        static const std::unordered_map<std::string, FileEventType> kMap = {
            {"Created",          FileEventType::Created},
            {"Modified",         FileEventType::Modified},
            {"Deleted",          FileEventType::Deleted},
            {"Renamed",          FileEventType::Renamed},
            {"Moved",            FileEventType::Moved},
            {"AttributeChanged", FileEventType::AttributeChanged},
            {"StreamCreated",    FileEventType::StreamCreated},
        };
        if (auto it = kMap.find(action); it != kMap.end())
            d.subType = it->second;
    }

    if (j.contains("file")) {
        const auto& file = j["file"];
        if (file.contains("path"))
            d.filePath = ShadowStrike::Utils::StringUtils::utf8_to_wstring(
                file["path"].get<std::string>().c_str());
        if (file.contains("previous") && file["previous"].contains("path"))
            d.oldFilePath = ShadowStrike::Utils::StringUtils::utf8_to_wstring(
                file["previous"]["path"].get<std::string>().c_str());
        if (file.contains("hash") && file["hash"].contains("sha256"))
            d.fileHash = file["hash"]["sha256"].get<std::string>();
        if (file.contains("size"))
            d.fileSize = file["size"].get<uint64_t>();
        if (file.contains("attributes"))
            d.fileAttributes = file["attributes"].get<uint32_t>();
    }

    return true;
}

bool TelemetrySerializerImpl::DeserializeRegistryPayload(
    const Json& j, RegistryEventData& d) const
{
    if (j.contains("event") && j["event"].contains("action")) {
        const auto action = j["event"]["action"].get<std::string>();
        static const std::unordered_map<std::string, RegistryEventType> kMap = {
            {"KeyCreated",   RegistryEventType::KeyCreated},
            {"KeyDeleted",   RegistryEventType::KeyDeleted},
            {"ValueSet",     RegistryEventType::ValueSet},
            {"ValueDeleted", RegistryEventType::ValueDeleted},
            {"KeyRenamed",   RegistryEventType::KeyRenamed},
            {"KeySecurity",  RegistryEventType::KeySecurity},
        };
        if (auto it = kMap.find(action); it != kMap.end())
            d.subType = it->second;
    }

    if (j.contains("registry")) {
        const auto& reg = j["registry"];
        if (reg.contains("path"))
            d.keyPath = ShadowStrike::Utils::StringUtils::utf8_to_wstring(
                reg["path"].get<std::string>().c_str());
        if (reg.contains("value"))
            d.valueName = ShadowStrike::Utils::StringUtils::utf8_to_wstring(
                reg["value"].get<std::string>().c_str());
        if (reg.contains("data") && reg["data"].contains("type"))
            d.valueType = reg["data"]["type"].get<uint32_t>();
    }

    return true;
}

bool TelemetrySerializerImpl::DeserializeNetworkPayload(
    const Json& j, NetworkEventData& d) const
{
    if (j.contains("event") && j["event"].contains("action")) {
        const auto action = j["event"]["action"].get<std::string>();
        static const std::unordered_map<std::string, NetworkEventType> kMap = {
            {"ConnectionOpened", NetworkEventType::ConnectionOpened},
            {"ConnectionClosed", NetworkEventType::ConnectionClosed},
            {"DataSent",         NetworkEventType::DataSent},
            {"DataReceived",     NetworkEventType::DataReceived},
            {"DNSQuery",         NetworkEventType::DNSQuery},
            {"DNSResponse",      NetworkEventType::DNSResponse},
            {"ListenStart",      NetworkEventType::ListenStart},
        };
        if (auto it = kMap.find(action); it != kMap.end())
            d.subType = it->second;
    }

    // ECS source.* → local
    if (j.contains("source")) {
        const auto& src = j["source"];
        if (src.contains("ip"))
            d.localAddr = src["ip"].get<std::string>();
        if (src.contains("port"))
            d.localPort = src["port"].get<uint16_t>();
    }

    // ECS destination.* → remote
    if (j.contains("destination")) {
        const auto& dst = j["destination"];
        if (dst.contains("ip"))
            d.remoteAddr = dst["ip"].get<std::string>();
        if (dst.contains("port"))
            d.remotePort = dst["port"].get<uint16_t>();
    }

    // network.*
    if (j.contains("network")) {
        const auto& net = j["network"];
        if (net.contains("iana_number"))
            d.protocol = net["iana_number"].get<uint16_t>();
        if (net.contains("bytes"))
            d.bytesTransferred = net["bytes"].get<uint64_t>();
    }

    // dns.*
    if (j.contains("dns")) {
        const auto& dns = j["dns"];
        if (dns.contains("question") && dns["question"].contains("name"))
            d.dnsQuery = dns["question"]["name"].get<std::string>();
        if (dns.contains("answers") && dns["answers"].is_array()) {
            d.dnsResponse.reserve(dns["answers"].size());
            for (const auto& ans : dns["answers"]) {
                if (ans.contains("data"))
                    d.dnsResponse.push_back(ans["data"].get<std::string>());
            }
        }
    }

    return true;
}

// ============================================================================
// TELEMETRY SERIALIZER — SINGLETON + FORWARDING
// ============================================================================

TelemetrySerializer& TelemetrySerializer::Instance()
{
    static TelemetrySerializer instance;
    return instance;
}

TelemetrySerializer::TelemetrySerializer()
    : m_impl(std::make_unique<TelemetrySerializerImpl>()) {}

TelemetrySerializer::~TelemetrySerializer() = default;

bool TelemetrySerializer::Initialize(const SerializerConfig& config) {
    return m_impl->Initialize(config);
}

void TelemetrySerializer::Shutdown() {
    m_impl->Shutdown();
}

bool TelemetrySerializer::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

bool TelemetrySerializer::Serialize(const TelemetryEvent& event,
                                     std::string& outJson) const {
    return m_impl->Serialize(event, outJson);
}

bool TelemetrySerializer::SerializeBatch(
    std::span<const TelemetryEvent> events, std::string& outJson) const {
    return m_impl->SerializeBatch(events, outJson);
}

bool TelemetrySerializer::SerializeNDJSON(
    std::span<const TelemetryEvent> events, std::string& outNdjson) const {
    return m_impl->SerializeNDJSON(events, outNdjson);
}

bool TelemetrySerializer::Deserialize(std::string_view json,
                                       TelemetryEvent& outEvent) const {
    return m_impl->Deserialize(json, outEvent);
}

bool TelemetrySerializer::DeserializeBatch(
    std::string_view json, std::vector<TelemetryEvent>& outEvents) const {
    return m_impl->DeserializeBatch(json, outEvents);
}

bool TelemetrySerializer::SerializeStats(const TelemetryStats& stats,
                                          std::string& outJson) const {
    return m_impl->SerializeStats(stats, outJson);
}

} // namespace ShadowStrike::Products::PhantomEDR::Telemetry
