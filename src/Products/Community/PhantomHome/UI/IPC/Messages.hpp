/*
 * ShadowStrike - Enterprise NGAV Platform
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * Licensed under GNU AGPL-v3. See LICENSE.txt at the repository root.
 */

/**
 * @file Messages.hpp
 * @brief Shared IPC schema between PhantomHomeService and PhantomHomeUI (Qt client).
 *
 * Wire format
 * -----------
 *   [ uint32 LE length ][ CBOR payload ]
 *
 * Payload is a CBOR map encoded via nlohmann::json::to_cbor. The envelope is:
 *   { "v": <uint8 version>, "t": <uint16 type>, "id": <uint64 correlation id>,
 *     "p": <type-specific payload> }
 *
 * Rationale
 * ---------
 *  - CBOR chosen over JSON for throughput and schema evolvability; over raw
 *    binary structs for ABI stability across UI/service upgrade skew.
 *  - Versioned envelope; unknown message types are rejected; unknown payload
 *    fields are silently ignored so older clients keep working.
 *  - Size cap enforced at transport (`kMaxFrameBytes`).
 *
 * This header must compile from both the Win32 service-side PipeServer and the
 * Qt UI client PipeClient without pulling in Qt symbols. Only <nlohmann/json.hpp>
 * and the C++20 standard library are permitted here.
 */

#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <nlohmann/json.hpp>

namespace ShadowStrike::PhantomHome::IPC {

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

inline constexpr std::uint8_t  kProtocolVersion      = 1;
inline constexpr std::uint32_t kMaxFrameBytes        = 256u * 1024u;   // 256 KiB cap
inline constexpr std::uint32_t kMaxStringBytes       = 8u   * 1024u;   // 8 KiB per string field
inline constexpr std::uint32_t kMaxArrayElements     = 4096u;           // generic array cap
inline constexpr std::uint32_t kMaxPipeInstances     = 16u;             // per interactive session
inline constexpr std::uint32_t kPipeReadTimeoutMs    = 10u * 1000u;     // 10 s
inline constexpr std::uint32_t kPipeWriteTimeoutMs   = 5u  * 1000u;     // 5  s

inline constexpr std::string_view kPipeNamePrefix = R"(\\.\pipe\ShadowStrike.Phantom.UI.)";

// SDDL: SYSTEM + Administrators + INTERACTIVE users have Read+Write; all others denied.
inline constexpr std::wstring_view kPipeSddl =
    L"D:(A;;GRGW;;;SY)(A;;GRGW;;;BA)(A;;GRGW;;;IU)";

// ---------------------------------------------------------------------------
// Message type registry (stable ordinals; append-only)
// ---------------------------------------------------------------------------

enum class MessageType : std::uint16_t {
    // --- Handshake ---
    Hello                      = 0x0001,
    HelloOk                    = 0x0002,
    Ping                       = 0x0003,
    Pong                       = 0x0004,
    Error                      = 0x00FF,

    // --- Protection state ---
    GetState                   = 0x0100,
    GetStateReply              = 0x0101,
    EventStateChanged          = 0x0102,   // server push

    // --- Module status / config ---
    GetModuleStatus            = 0x0200,
    GetModuleStatusReply       = 0x0201,
    SetModuleEnable            = 0x0202,
    SetModuleEnableReply       = 0x0203,
    GetExclusions              = 0x0210,
    GetExclusionsReply         = 0x0211,
    SetExclusions              = 0x0212,
    SetExclusionsReply         = 0x0213,
    GetDetectionAction         = 0x0220,
    GetDetectionActionReply    = 0x0221,
    SetDetectionAction         = 0x0222,
    SetDetectionActionReply    = 0x0223,

    // --- Scan ---
    ScanStart                  = 0x0300,
    ScanStartReply             = 0x0301,
    ScanCancel                 = 0x0302,
    ScanCancelReply            = 0x0303,
    EventScanProgress          = 0x0304,   // server push
    EventScanCompleted         = 0x0305,   // server push

    // --- Quarantine ---
    QuarantineList             = 0x0400,
    QuarantineListReply        = 0x0401,
    QuarantineRestore          = 0x0402,
    QuarantineRestoreReply     = 0x0403,
    QuarantineDelete           = 0x0404,
    QuarantineDeleteReply      = 0x0405,
    QuarantineSubmitFalsePos   = 0x0406,
    QuarantineSubmitFalsePosReply = 0x0407,

    // --- Events ---
    EventDetection             = 0x0500,   // server push

    // --- Reports ---
    GetReports                 = 0x0600,
    GetReportsReply            = 0x0601,

    // --- Updates ---
    GetUpdateStatus            = 0x0700,
    GetUpdateStatusReply       = 0x0701,
    TriggerUpdate              = 0x0702,
    TriggerUpdateReply         = 0x0703,

    // --- Runtime control ---
    PauseProtection            = 0x0800,
    PauseProtectionReply       = 0x0801,
    ResumeProtection           = 0x0802,
    ResumeProtectionReply      = 0x0803,

    // --- Performance metrics (server push stream) ---
    SubscribePerfMetrics       = 0x0900,
    SubscribePerfMetricsReply  = 0x0901,
    EventPerfMetrics           = 0x0902,
};

// ---------------------------------------------------------------------------
// Enumerations (mirrored in QML via integer constants)
// ---------------------------------------------------------------------------

enum class OverallState : std::uint8_t {
    Unknown = 0,
    Green   = 1,   // "We are protecting you"
    Amber   = 2,   // "Attention needed"
    Red     = 3,   // "Your device is at risk"
    Paused  = 4,
};

enum class DetectionAction : std::uint8_t {
    Ask       = 0,
    Quarantine = 1,
    Delete    = 2,
    LogOnly   = 3,
};

enum class ScanType : std::uint8_t {
    Quick     = 0,
    Full      = 1,
    Custom    = 2,
    Removable = 3,
};

enum class Severity : std::uint8_t {
    Info     = 0,
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4,
};

enum class ModuleState : std::uint8_t {
    Disabled     = 0,
    Initializing = 1,
    Running      = 2,
    Degraded     = 3,
    Failed       = 4,
};

// ---------------------------------------------------------------------------
// Error codes used in `Error` responses
// ---------------------------------------------------------------------------

enum class ErrorCode : std::uint16_t {
    Ok                       = 0,
    InvalidFrame             = 1,
    UnknownMessageType       = 2,
    SchemaViolation          = 3,
    FieldTooLarge            = 4,
    NotAuthorized            = 5,   // client lacks privilege
    ElevationRequired        = 6,   // UAC token needed for this op
    ProtocolVersionMismatch  = 7,
    Internal                 = 8,
    RateLimited              = 9,
    NotFound                 = 10,
    Busy                     = 11,
    Cancelled                = 12,
};

// ---------------------------------------------------------------------------
// Frame envelope helpers
// ---------------------------------------------------------------------------

struct FrameEnvelope {
    std::uint8_t   version{kProtocolVersion};
    MessageType    type{MessageType::Error};
    std::uint64_t  correlation_id{0};
    nlohmann::json payload;          // CBOR-native object or null
};

/// Serialize envelope to the on-wire CBOR byte stream (without length prefix).
[[nodiscard]] inline std::vector<std::uint8_t>
EncodeEnvelopeCbor(const FrameEnvelope& env) {
    nlohmann::json obj = {
        {"v",  env.version},
        {"t",  static_cast<std::uint16_t>(env.type)},
        {"id", env.correlation_id},
        {"p",  env.payload},
    };
    return nlohmann::json::to_cbor(obj);
}

/// Parse a CBOR byte stream into an envelope. Returns std::nullopt on any
/// malformed / missing-field / out-of-range / oversized input. Callers MUST
/// treat nullopt as a hostile frame and drop the connection.
[[nodiscard]] inline std::optional<FrameEnvelope>
DecodeEnvelopeCbor(std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.empty() || bytes.size() > kMaxFrameBytes) {
        return std::nullopt;
    }
    try {
        nlohmann::json obj = nlohmann::json::from_cbor(
            bytes.begin(), bytes.end(),
            /*strict=*/true,
            /*allow_exceptions=*/false);

        if (obj.is_discarded() || !obj.is_object()) {
            return std::nullopt;
        }
        if (!obj.contains("v") || !obj["v"].is_number_unsigned()) return std::nullopt;
        if (!obj.contains("t") || !obj["t"].is_number_unsigned()) return std::nullopt;
        if (!obj.contains("id") || !obj["id"].is_number_unsigned()) return std::nullopt;
        if (!obj.contains("p")) return std::nullopt;

        const auto v  = obj["v"].get<std::uint64_t>();
        const auto t  = obj["t"].get<std::uint64_t>();
        const auto id = obj["id"].get<std::uint64_t>();

        if (v > (std::numeric_limits<std::uint8_t>::max)())  return std::nullopt;
        if (t > (std::numeric_limits<std::uint16_t>::max)()) return std::nullopt;

        FrameEnvelope env;
        env.version        = static_cast<std::uint8_t>(v);
        env.type           = static_cast<MessageType>(t);
        env.correlation_id = id;
        env.payload        = std::move(obj["p"]);
        return env;
    } catch (...) {
        return std::nullopt;
    }
}

// ---------------------------------------------------------------------------
// Strongly typed message payload structs.
//
// Each struct owns ToJson() / FromJson() helpers. All field accessors defensively
// validate type and size; FromJson returns std::nullopt on any schema violation.
// ---------------------------------------------------------------------------

namespace detail {

[[nodiscard]] inline bool GetStringBounded(const nlohmann::json& j,
                                           std::string_view key,
                                           std::string& out,
                                           std::size_t max_bytes = kMaxStringBytes) noexcept {
    if (!j.contains(key) || !j[key].is_string()) return false;
    const auto& s = j[key].get_ref<const std::string&>();
    if (s.size() > max_bytes) return false;
    out = s;
    return true;
}

template <std::integral T>
[[nodiscard]] inline bool GetUint(const nlohmann::json& j, std::string_view key, T& out) noexcept {
    if (!j.contains(key) || !j[key].is_number_unsigned()) return false;
    const auto v = j[key].get<std::uint64_t>();
    if (v > static_cast<std::uint64_t>((std::numeric_limits<T>::max)())) return false;
    out = static_cast<T>(v);
    return true;
}

[[nodiscard]] inline bool GetBool(const nlohmann::json& j, std::string_view key, bool& out) noexcept {
    if (!j.contains(key) || !j[key].is_boolean()) return false;
    out = j[key].get<bool>();
    return true;
}

}  // namespace detail

// ---- Hello / HelloOk ------------------------------------------------------

struct Hello {
    std::uint8_t client_version{kProtocolVersion};
    std::string  client_build{};           // e.g. "1.0.0+abcd"
    std::uint32_t session_id{0};           // Windows interactive session id

    [[nodiscard]] nlohmann::json ToJson() const {
        return {{"cv", client_version}, {"cb", client_build}, {"sid", session_id}};
    }
    [[nodiscard]] static std::optional<Hello> FromJson(const nlohmann::json& j) {
        if (!j.is_object()) return std::nullopt;
        Hello h;
        if (!detail::GetUint(j, "cv", h.client_version)) return std::nullopt;
        if (!detail::GetStringBounded(j, "cb", h.client_build, 128)) return std::nullopt;
        if (!detail::GetUint(j, "sid", h.session_id)) return std::nullopt;
        return h;
    }
};

struct HelloOk {
    std::uint8_t server_version{kProtocolVersion};
    std::string  server_build{};
    std::uint64_t capabilities{0};         // bitmask reserved for future

    [[nodiscard]] nlohmann::json ToJson() const {
        return {{"sv", server_version}, {"sb", server_build}, {"cap", capabilities}};
    }
    [[nodiscard]] static std::optional<HelloOk> FromJson(const nlohmann::json& j) {
        if (!j.is_object()) return std::nullopt;
        HelloOk h;
        if (!detail::GetUint(j, "sv", h.server_version)) return std::nullopt;
        if (!detail::GetStringBounded(j, "sb", h.server_build, 128)) return std::nullopt;
        if (!detail::GetUint(j, "cap", h.capabilities)) return std::nullopt;
        return h;
    }
};

// ---- Error ---------------------------------------------------------------

struct ErrorPayload {
    ErrorCode   code{ErrorCode::Internal};
    std::string message{};                 // human-readable, MUST NOT contain PII

    [[nodiscard]] nlohmann::json ToJson() const {
        return {{"c", static_cast<std::uint16_t>(code)}, {"m", message}};
    }
    [[nodiscard]] static std::optional<ErrorPayload> FromJson(const nlohmann::json& j) {
        if (!j.is_object()) return std::nullopt;
        ErrorPayload e;
        std::uint16_t c{};
        if (!detail::GetUint(j, "c", c)) return std::nullopt;
        if (!detail::GetStringBounded(j, "m", e.message, 512)) return std::nullopt;
        e.code = static_cast<ErrorCode>(c);
        return e;
    }
};

// ---- State ---------------------------------------------------------------

struct ProtectionStateReply {
    OverallState state{OverallState::Unknown};
    std::string  reason{};                 // short human-readable reason
    std::uint32_t active_threats{0};
    std::uint64_t last_update_unix{0};

    [[nodiscard]] nlohmann::json ToJson() const {
        return {{"s", static_cast<std::uint8_t>(state)},
                {"r", reason},
                {"at", active_threats},
                {"lu", last_update_unix}};
    }
    [[nodiscard]] static std::optional<ProtectionStateReply> FromJson(const nlohmann::json& j) {
        if (!j.is_object()) return std::nullopt;
        ProtectionStateReply r;
        std::uint8_t s{};
        if (!detail::GetUint(j, "s", s)) return std::nullopt;
        if (!detail::GetStringBounded(j, "r", r.reason, 256)) return std::nullopt;
        if (!detail::GetUint(j, "at", r.active_threats)) return std::nullopt;
        if (!detail::GetUint(j, "lu", r.last_update_unix)) return std::nullopt;
        r.state = static_cast<OverallState>(s);
        return r;
    }
};

// ---- Module status -------------------------------------------------------

struct ModuleStatusEntry {
    std::string   id{};                    // canonical module id, e.g. "PhantomHome.Privacy.WebcamProtector"
    std::string   display_name{};
    ModuleState   state{ModuleState::Disabled};
    bool          enabled{false};
    std::string   group{};                 // "Realtime" / "Network" / "Device" / "Advanced" / ...

    [[nodiscard]] nlohmann::json ToJson() const {
        return {{"id", id}, {"n", display_name},
                {"s", static_cast<std::uint8_t>(state)},
                {"e", enabled}, {"g", group}};
    }
    [[nodiscard]] static std::optional<ModuleStatusEntry> FromJson(const nlohmann::json& j) {
        if (!j.is_object()) return std::nullopt;
        ModuleStatusEntry e;
        if (!detail::GetStringBounded(j, "id", e.id, 256)) return std::nullopt;
        if (!detail::GetStringBounded(j, "n",  e.display_name, 128)) return std::nullopt;
        std::uint8_t s{};
        if (!detail::GetUint(j, "s", s)) return std::nullopt;
        if (!detail::GetBool(j, "e", e.enabled)) return std::nullopt;
        if (!detail::GetStringBounded(j, "g", e.group, 64)) return std::nullopt;
        e.state = static_cast<ModuleState>(s);
        return e;
    }
};

struct GetModuleStatusReply {
    std::vector<ModuleStatusEntry> modules{};

    [[nodiscard]] nlohmann::json ToJson() const {
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& m : modules) arr.push_back(m.ToJson());
        return {{"m", arr}};
    }
    [[nodiscard]] static std::optional<GetModuleStatusReply> FromJson(const nlohmann::json& j) {
        if (!j.is_object() || !j.contains("m") || !j["m"].is_array()) return std::nullopt;
        const auto& arr = j["m"];
        if (arr.size() > kMaxArrayElements) return std::nullopt;
        GetModuleStatusReply r;
        r.modules.reserve(arr.size());
        for (const auto& item : arr) {
            auto e = ModuleStatusEntry::FromJson(item);
            if (!e) return std::nullopt;
            r.modules.push_back(std::move(*e));
        }
        return r;
    }
};

struct SetModuleEnable {
    std::string id{};
    bool        enabled{false};

    [[nodiscard]] nlohmann::json ToJson() const { return {{"id", id}, {"e", enabled}}; }
    [[nodiscard]] static std::optional<SetModuleEnable> FromJson(const nlohmann::json& j) {
        if (!j.is_object()) return std::nullopt;
        SetModuleEnable s;
        if (!detail::GetStringBounded(j, "id", s.id, 256)) return std::nullopt;
        if (!detail::GetBool(j, "e", s.enabled)) return std::nullopt;
        return s;
    }
};

// ---- Scan ---------------------------------------------------------------

struct ScanStartRequest {
    ScanType               type{ScanType::Quick};
    std::vector<std::string> paths{};     // only for Custom

    [[nodiscard]] nlohmann::json ToJson() const {
        return {{"t", static_cast<std::uint8_t>(type)}, {"p", paths}};
    }
    [[nodiscard]] static std::optional<ScanStartRequest> FromJson(const nlohmann::json& j) {
        if (!j.is_object()) return std::nullopt;
        ScanStartRequest r;
        std::uint8_t t{};
        if (!detail::GetUint(j, "t", t)) return std::nullopt;
        r.type = static_cast<ScanType>(t);
        if (!j.contains("p") || !j["p"].is_array()) return std::nullopt;
        const auto& arr = j["p"];
        if (arr.size() > 1024) return std::nullopt;            // per-scan path cap
        for (const auto& s : arr) {
            if (!s.is_string()) return std::nullopt;
            const auto& ref = s.get_ref<const std::string&>();
            if (ref.size() > 32 * 1024) return std::nullopt;   // 32 KiB path cap
            r.paths.push_back(ref);
        }
        return r;
    }
};

struct ScanStartReply {
    std::uint64_t scan_id{0};

    [[nodiscard]] nlohmann::json ToJson() const { return {{"sid", scan_id}}; }
    [[nodiscard]] static std::optional<ScanStartReply> FromJson(const nlohmann::json& j) {
        if (!j.is_object()) return std::nullopt;
        ScanStartReply r;
        if (!detail::GetUint(j, "sid", r.scan_id)) return std::nullopt;
        return r;
    }
};

struct ScanProgressEvent {
    std::uint64_t scan_id{0};
    std::uint32_t percent{0};              // 0..100
    std::uint64_t items_scanned{0};
    std::uint64_t threats_found{0};
    std::string   current_path{};          // truncated to avoid PII leak in logs

    [[nodiscard]] nlohmann::json ToJson() const {
        return {{"sid", scan_id}, {"pct", percent},
                {"is", items_scanned}, {"tf", threats_found}, {"cp", current_path}};
    }
    [[nodiscard]] static std::optional<ScanProgressEvent> FromJson(const nlohmann::json& j) {
        if (!j.is_object()) return std::nullopt;
        ScanProgressEvent e;
        if (!detail::GetUint(j, "sid", e.scan_id)) return std::nullopt;
        if (!detail::GetUint(j, "pct", e.percent) || e.percent > 100) return std::nullopt;
        if (!detail::GetUint(j, "is", e.items_scanned)) return std::nullopt;
        if (!detail::GetUint(j, "tf", e.threats_found)) return std::nullopt;
        if (!detail::GetStringBounded(j, "cp", e.current_path, 2048)) return std::nullopt;
        return e;
    }
};

// ---- Detection event -----------------------------------------------------

struct DetectionEvent {
    std::uint64_t unix_ts{0};
    Severity      severity{Severity::Info};
    std::string   module_id{};
    std::string   threat_name{};
    std::string   object_hash_sha256{};   // hex, 64 chars
    std::string   object_path{};          // may be redacted
    DetectionAction action_taken{DetectionAction::LogOnly};

    [[nodiscard]] nlohmann::json ToJson() const {
        return {{"ts",  unix_ts},
                {"sev", static_cast<std::uint8_t>(severity)},
                {"mid", module_id},
                {"th",  threat_name},
                {"h",   object_hash_sha256},
                {"p",   object_path},
                {"a",   static_cast<std::uint8_t>(action_taken)}};
    }
    [[nodiscard]] static std::optional<DetectionEvent> FromJson(const nlohmann::json& j) {
        if (!j.is_object()) return std::nullopt;
        DetectionEvent e;
        std::uint8_t sev{}, act{};
        if (!detail::GetUint(j, "ts", e.unix_ts)) return std::nullopt;
        if (!detail::GetUint(j, "sev", sev)) return std::nullopt;
        if (!detail::GetStringBounded(j, "mid", e.module_id, 256)) return std::nullopt;
        if (!detail::GetStringBounded(j, "th",  e.threat_name, 256)) return std::nullopt;
        if (!detail::GetStringBounded(j, "h",   e.object_hash_sha256, 64)) return std::nullopt;
        if (!detail::GetStringBounded(j, "p",   e.object_path, 2048)) return std::nullopt;
        if (!detail::GetUint(j, "a", act)) return std::nullopt;
        e.severity     = static_cast<Severity>(sev);
        e.action_taken = static_cast<DetectionAction>(act);
        return e;
    }
};

// ---- Perf metrics --------------------------------------------------------

struct PerfMetricsEvent {
    std::uint32_t cpu_pct_engine{0};       // 0..100 of one core
    std::uint32_t cpu_pct_system{0};
    std::uint64_t mem_bytes_engine{0};
    std::uint64_t disk_read_bps{0};
    std::uint64_t disk_write_bps{0};
    std::uint64_t net_rx_bps{0};
    std::uint64_t net_tx_bps{0};

    [[nodiscard]] nlohmann::json ToJson() const {
        return {{"ce", cpu_pct_engine}, {"cs", cpu_pct_system},
                {"me", mem_bytes_engine}, {"dr", disk_read_bps}, {"dw", disk_write_bps},
                {"nr", net_rx_bps}, {"nt", net_tx_bps}};
    }
    [[nodiscard]] static std::optional<PerfMetricsEvent> FromJson(const nlohmann::json& j) {
        if (!j.is_object()) return std::nullopt;
        PerfMetricsEvent e;
        if (!detail::GetUint(j, "ce", e.cpu_pct_engine)) return std::nullopt;
        if (!detail::GetUint(j, "cs", e.cpu_pct_system)) return std::nullopt;
        if (!detail::GetUint(j, "me", e.mem_bytes_engine)) return std::nullopt;
        if (!detail::GetUint(j, "dr", e.disk_read_bps)) return std::nullopt;
        if (!detail::GetUint(j, "dw", e.disk_write_bps)) return std::nullopt;
        if (!detail::GetUint(j, "nr", e.net_rx_bps)) return std::nullopt;
        if (!detail::GetUint(j, "nt", e.net_tx_bps)) return std::nullopt;
        return e;
    }
};

// ---- PauseProtection -----------------------------------------------------

struct PauseProtectionRequest {
    std::uint32_t duration_seconds{0};     // 0 == until reboot
    std::string   elevation_token{};       // opaque token obtained via UAC helper

    [[nodiscard]] nlohmann::json ToJson() const {
        return {{"d", duration_seconds}, {"et", elevation_token}};
    }
    [[nodiscard]] static std::optional<PauseProtectionRequest> FromJson(const nlohmann::json& j) {
        if (!j.is_object()) return std::nullopt;
        PauseProtectionRequest r;
        if (!detail::GetUint(j, "d", r.duration_seconds)) return std::nullopt;
        if (!detail::GetStringBounded(j, "et", r.elevation_token, 1024)) return std::nullopt;
        return r;
    }
};

}  // namespace ShadowStrike::PhantomHome::IPC
