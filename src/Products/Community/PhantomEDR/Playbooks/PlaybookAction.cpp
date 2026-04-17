/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
#include "pch.h"
#include "Products/Community/PhantomEDR/Playbooks/PlaybookAction.hpp"

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/ThreatIntel/ThreatIntelFormat.hpp"
#include "PhantomCore/ThreatIntel/ThreatIntelStore.hpp"
#include "PhantomCore/Utils/FileUtils.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "Products/Community/PhantomEDR/IncidentResponse/ContainmentEngine.hpp"
#include "Products/Community/PhantomEDR/IncidentResponse/RemediationEngine.hpp"

#include <format>
#include <memory>
#include <shared_mutex>

namespace ShadowStrike::Products::PhantomEDR::Playbooks {

namespace {

using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Products::PhantomEDR::IncidentResponse::ContainmentEngine;
using ShadowStrike::Products::PhantomEDR::IncidentResponse::RemediationEngine;
using ShadowStrike::ThreatIntel::IOCType;
using ShadowStrike::ThreatIntel::IOCTypeToString;
using ShadowStrike::ThreatIntel::ReputationLevel;
using ShadowStrike::ThreatIntel::StoreConfig;
using ShadowStrike::ThreatIntel::StoreLookupResult;
using ShadowStrike::ThreatIntel::ThreatIntelStore;
using ShadowStrike::Utils::Logger;
using ShadowStrike::Utils::StringUtils::ToWide;
namespace FileUtils = ShadowStrike::Utils::FileUtils;
using ShadowStrike::Utils::FileUtils::Exists;

constexpr std::string_view kLogPrefix = "[PlaybookAction]";
constexpr std::string_view kCreateNotificationsTable = R"(
    CREATE TABLE IF NOT EXISTS playbook_notifications (
        notification_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        severity TEXT NOT NULL,
        subject TEXT NOT NULL,
        details TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );
)";

constexpr std::string_view kCreateEvidenceTable = R"(
    CREATE TABLE IF NOT EXISTS playbook_evidence (
        evidence_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        incident_id TEXT NOT NULL,
        pid INTEGER NOT NULL,
        file_path TEXT NOT NULL,
        file_exists INTEGER NOT NULL,
        file_size INTEGER NOT NULL,
        is_directory INTEGER NOT NULL,
        status TEXT NOT NULL,
        captured_at INTEGER NOT NULL
    );
)";

[[nodiscard]] int64_t ToUnixMillis(const std::chrono::system_clock::time_point value) noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(value.time_since_epoch()).count();
}

[[nodiscard]] std::string JsonToString(const Json& value) {
    if (value.is_string()) {
        return value.get<std::string>();
    }

    if (value.is_boolean()) {
        return value.get<bool>() ? "true" : "false";
    }

    if (value.is_number_integer()) {
        return std::to_string(value.get<int64_t>());
    }

    if (value.is_number_unsigned()) {
        return std::to_string(value.get<uint64_t>());
    }

    if (value.is_number_float()) {
        return std::format("{}", value.get<double>());
    }

    return value.dump();
}

[[nodiscard]] std::string GetStringParameter(const Json& parameters, const std::string_view key) {
    const auto it = parameters.find(key);
    if (it == parameters.end() || it->is_null()) {
        return {};
    }

    return JsonToString(*it);
}

[[nodiscard]] uint32_t GetUInt32Parameter(const Json& parameters, const std::string_view key) {
    const auto it = parameters.find(key);
    if (it == parameters.end() || it->is_null()) {
        return 0;
    }

    if (it->is_number_unsigned()) {
        return it->get<uint32_t>();
    }
    if (it->is_number_integer()) {
        return static_cast<uint32_t>(std::max<int64_t>(0, it->get<int64_t>()));
    }
    if (it->is_string()) {
        try {
            return static_cast<uint32_t>(std::stoul(it->get<std::string>()));
        } catch (...) {
            return 0;
        }
    }

    return 0;
}

[[nodiscard]] Json BuildLookupDetails(const std::string_view iocType, const std::string_view value, const StoreLookupResult& result) {
    Json details = {
        { "ioc_type", std::string(iocType) },
        { "value", std::string(value) },
        { "found", result.found },
        { "from_cache", result.fromCache },
        { "score", result.score },
        { "reputation", static_cast<int>(result.reputation) },
        { "confidence", static_cast<int>(result.confidence) },
        { "category", static_cast<int>(result.category) },
        { "latency_ns", result.latencyNs }
    };

    if (result.entry.has_value()) {
        Json entryDetails = Json::object();
        entryDetails["type"] = IOCTypeToString(result.entry->type);
        entryDetails["severity"] = result.entry->severity;
        entryDetails["threat_score"] = result.entry->GetThreatScore();
        entryDetails["source_count"] = result.entry->sourceCount;
        details["entry"] = std::move(entryDetails);
    }

    return details;
}

} // namespace

class PlaybookActionImpl {
public:
    bool initialized = false;
    mutable std::shared_mutex mutex;
    std::unique_ptr<ThreatIntelStore> threatIntelStore;
};

PlaybookAction& PlaybookAction::Instance() {
    static PlaybookAction instance;
    return instance;
}

PlaybookAction::PlaybookAction()
    : m_impl(std::make_unique<PlaybookActionImpl>()) {
}

PlaybookAction::~PlaybookAction() = default;

bool PlaybookAction::Initialize() {
    std::unique_lock lock(m_impl->mutex);
    if (m_impl->initialized) {
        return true;
    }

    DatabaseError dbError;
    if (!DatabaseManager::Instance().Execute(kCreateNotificationsTable.data(), &dbError) ||
        !DatabaseManager::Instance().Execute(kCreateEvidenceTable.data(), &dbError)) {
        Logger::Error(
            "{} Failed to initialize playbook action schema: {}",
            kLogPrefix,
            ShadowStrike::Utils::StringUtils::ToNarrow(dbError.message));
        return false;
    }

    m_impl->initialized = true;
    Logger::Info("{} Initialized successfully", kLogPrefix);
    return true;
}

void PlaybookAction::Shutdown() {
    std::unique_lock lock(m_impl->mutex);
    if (!m_impl->initialized) {
        return;
    }

    if (m_impl->threatIntelStore != nullptr && m_impl->threatIntelStore->IsInitialized()) {
        m_impl->threatIntelStore->Shutdown();
    }
    m_impl->threatIntelStore.reset();
    m_impl->initialized = false;
    Logger::Info("{} Shutdown complete", kLogPrefix);
}

bool PlaybookAction::IsInitialized() const {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->initialized;
}

ActionResult PlaybookAction::ExecuteAction(
    const PlaybookActionType action,
    const Json& parameters,
    Json& context,
    const std::string_view runId) {
    const auto startedAt = std::chrono::steady_clock::now();
    ActionResult result;
    result.action = action;

    if (!IsInitialized()) {
        result.message = "PlaybookAction is not initialized";
        Logger::Error("{} {}", kLogPrefix, result.message);
        return result;
    }

    switch (action) {
        case PlaybookActionType::IsolateEndpoint: {
            auto& containment = ContainmentEngine::Instance();
            if (!containment.IsInitialized() && !containment.Initialize()) {
                result.message = "ContainmentEngine initialization failed";
                break;
            }

            const std::string incidentId = GetStringParameter(parameters, "incident_id");
            const std::string reason = GetStringParameter(parameters, "reason");
            const std::string effectiveIncidentId = incidentId.empty() ? std::string(runId) : incidentId;

            result.success = containment.IsolateNetwork(effectiveIncidentId);
            result.message = result.success ? "Endpoint isolation completed" : "Endpoint isolation failed";
            result.details = {
                { "incident_id", effectiveIncidentId },
                { "reason", reason }
            };
            break;
        }
        case PlaybookActionType::KillProcess: {
            auto& containment = ContainmentEngine::Instance();
            if (!containment.IsInitialized() && !containment.Initialize()) {
                result.message = "ContainmentEngine initialization failed";
                break;
            }

            const uint32_t pid = GetUInt32Parameter(parameters, "pid");
            if (pid == 0) {
                result.message = "Missing or invalid pid parameter";
                break;
            }

            result.success = containment.TerminateProcess(pid, true);
            result.message = result.success ? "Process terminated" : "Process termination failed";
            result.details = { { "pid", pid } };
            break;
        }
        case PlaybookActionType::QuarantineFile: {
            auto& remediation = RemediationEngine::Instance();
            if (!remediation.IsInitialized() && !remediation.Initialize()) {
                result.message = "RemediationEngine initialization failed";
                break;
            }

            const std::string filePath = GetStringParameter(parameters, "file_path");
            const std::string incidentId = GetStringParameter(parameters, "incident_id");
            if (filePath.empty()) {
                result.message = "Missing file_path parameter";
                break;
            }

            const std::wstring filePathWide = ToWide(filePath);
            if (!Exists(filePathWide, nullptr)) {
                result.message = "Target file does not exist";
                result.details = { { "file_path", filePath } };
                break;
            }

            result.success = remediation.QuarantineFile(
                incidentId.empty() ? std::string(runId) : incidentId,
                filePathWide);
            result.message = result.success ? "File quarantined" : "File quarantine failed";
            result.details = { { "file_path", filePath } };
            break;
        }
        case PlaybookActionType::BlockIP: {
            auto& containment = ContainmentEngine::Instance();
            if (!containment.IsInitialized() && !containment.Initialize()) {
                result.message = "ContainmentEngine initialization failed";
                break;
            }

            const std::string ipAddress = GetStringParameter(parameters, "ip_address");
            if (ipAddress.empty()) {
                result.message = "Missing ip_address parameter";
                break;
            }

            result.success = containment.BlockIPAddress(ipAddress);
            result.message = result.success ? "IP blocked" : "IP block failed";
            result.details = { { "ip_address", ipAddress } };
            break;
        }
        case PlaybookActionType::DisableUser: {
            auto& containment = ContainmentEngine::Instance();
            if (!containment.IsInitialized() && !containment.Initialize()) {
                result.message = "ContainmentEngine initialization failed";
                break;
            }

            const std::string userName = GetStringParameter(parameters, "user_name");
            if (userName.empty()) {
                result.message = "Missing user_name parameter";
                break;
            }

            result.success = containment.LockUserAccount(ToWide(userName));
            result.message = result.success ? "User account disabled" : "User account disablement failed";
            result.details = { { "user_name", userName } };
            break;
        }
        case PlaybookActionType::CollectEvidence: {
            const uint32_t pid = GetUInt32Parameter(parameters, "pid");
            const std::string filePath = GetStringParameter(parameters, "file_path");
            const std::string incidentId = GetStringParameter(parameters, "incident_id");
            if (pid == 0 && filePath.empty()) {
                result.message = "CollectEvidence requires pid or file_path";
                break;
            }

            FileUtils::FileStat fileStat{};
            FileUtils::Error fileError;
            const std::wstring filePathWide = ToWide(filePath);
            const bool hasFilePath = !filePath.empty();
            const bool statSuccess = hasFilePath ? FileUtils::Stat(filePathWide, fileStat, &fileError) : false;
            const std::string evidenceId = std::format(
                "{}-evidence-{}",
                runId.empty() ? "playbook" : std::string(runId),
                ToUnixMillis(std::chrono::system_clock::now()));

            DatabaseError dbError;
            result.success = DatabaseManager::Instance().ExecuteWithParams(
                "INSERT INTO playbook_evidence "
                "(evidence_id, run_id, incident_id, pid, file_path, file_exists, file_size, is_directory, status, captured_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                &dbError,
                evidenceId,
                std::string(runId),
                incidentId.empty() ? std::string(runId) : incidentId,
                static_cast<int64_t>(pid),
                filePath,
                statSuccess && fileStat.exists ? 1 : 0,
                static_cast<int64_t>(statSuccess ? fileStat.size : 0),
                statSuccess && fileStat.isDirectory ? 1 : 0,
                statSuccess || !hasFilePath ? "captured" : fileError.message,
                ToUnixMillis(std::chrono::system_clock::now()));

            result.message = result.success ? "Evidence collection completed" : "Evidence collection failed";
            result.details = {
                { "evidence_id", evidenceId },
                { "pid", pid },
                { "file_path", filePath },
                { "file_exists", statSuccess && fileStat.exists },
                { "file_size", statSuccess ? fileStat.size : 0 },
                { "status", result.success ? "captured" : ShadowStrike::Utils::StringUtils::ToNarrow(dbError.message) }
            };
            break;
        }
        case PlaybookActionType::EnrichIOC: {
            std::unique_lock lock(m_impl->mutex);
            if (m_impl->threatIntelStore == nullptr) {
                m_impl->threatIntelStore = std::make_unique<ThreatIntelStore>();
            }
            if (!m_impl->threatIntelStore->IsInitialized()) {
                StoreConfig config = StoreConfig::CreateLowMemory();
                config.enableAutoFeedUpdate = false;
                config.enableAutoFeedUpdates = false;
                config.enableTAXIISupport = false;
                config.enableSTIXSupport = true;
                config.enableStatistics = false;
                if (!m_impl->threatIntelStore->Initialize(config)) {
                    result.message = "ThreatIntelStore initialization failed";
                    break;
                }
            }

            const std::string iocTypeToken = GetStringParameter(parameters, "ioc_type");
            const std::string value = GetStringParameter(parameters, "value");
            if (iocTypeToken.empty() || value.empty()) {
                result.message = "EnrichIOC requires ioc_type and value";
                break;
            }

            const std::string token = NormalizeEnumToken(iocTypeToken);
            StoreLookupResult lookup;
            if (token == "ipv4" || token == "ip" || token == "ip_address") {
                lookup = m_impl->threatIntelStore->LookupIPv4(value);
            } else if (token == "ipv6") {
                lookup = m_impl->threatIntelStore->LookupIPv6(value);
            } else if (token == "domain" || token == "hostname") {
                lookup = m_impl->threatIntelStore->LookupDomain(value);
            } else if (token == "url") {
                lookup = m_impl->threatIntelStore->LookupURL(value);
            } else if (token == "email") {
                lookup = m_impl->threatIntelStore->LookupEmail(value);
            } else if (token == "ja3" || token == "ja3s") {
                lookup = m_impl->threatIntelStore->LookupJA3(value);
            } else if (token == "cve") {
                lookup = m_impl->threatIntelStore->LookupCVE(value);
            } else if (token == "file_hash" || token == "hash" || token == "sha256") {
                lookup = m_impl->threatIntelStore->LookupHash("SHA256", value);
            } else {
                lookup = m_impl->threatIntelStore->LookupIOC(IOCType::Unknown, value);
            }

            result.success = true;
            result.message = lookup.found ? "IOC enrichment completed" : "IOC not present in threat intelligence";
            result.details = BuildLookupDetails(iocTypeToken, value, lookup);
            context["enrichment"] = result.details;
            break;
        }
        case PlaybookActionType::NotifyLocal: {
            const std::string severity = GetStringParameter(parameters, "severity");
            const std::string subject = GetStringParameter(parameters, "subject");
            const std::string details = GetStringParameter(parameters, "details");
            const std::string notificationId = std::format(
                "{}-{}",
                runId.empty() ? "playbook" : std::string(runId),
                ToUnixMillis(std::chrono::system_clock::now()));

            DatabaseError dbError;
            result.success = DatabaseManager::Instance().ExecuteWithParams(
                "INSERT INTO playbook_notifications (notification_id, run_id, severity, subject, details, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?);",
                &dbError,
                notificationId,
                std::string(runId),
                severity,
                subject,
                details,
                ToUnixMillis(std::chrono::system_clock::now()));

            if (!result.success) {
                result.message = std::format(
                    "Failed to persist local notification: {}",
                    ShadowStrike::Utils::StringUtils::ToNarrow(dbError.message));
                Logger::Error("{} {}", kLogPrefix, result.message);
                break;
            }

            const std::string severityToken = NormalizeEnumToken(severity);
            if (severityToken == "critical" || severityToken == "error" || severityToken == "emergency") {
                Logger::Error("{} {}", kLogPrefix, subject.empty() ? details : std::format("{} - {}", subject, details));
            } else if (severityToken == "high" || severityToken == "warn" || severityToken == "warning") {
                Logger::Warn("{} {}", kLogPrefix, subject.empty() ? details : std::format("{} - {}", subject, details));
            } else if (severityToken == "debug") {
                Logger::Debug("{} {}", kLogPrefix, subject.empty() ? details : std::format("{} - {}", subject, details));
            } else {
                Logger::Info("{} {}", kLogPrefix, subject.empty() ? details : std::format("{} - {}", subject, details));
            }

            result.message = "Local notification recorded";
            result.details = {
                { "notification_id", notificationId },
                { "severity", severity },
                { "subject", subject },
                { "details", details }
            };
            break;
        }
    }

    result.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startedAt).count();
    return result;
}

} // namespace ShadowStrike::Products::PhantomEDR::Playbooks
