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
#include "Products/Community/PhantomEDR/Playbooks/PlaybookLibrary.hpp"

#include "PhantomCore/Utils/Logger.hpp"

#include <algorithm>
#include <format>
#include <shared_mutex>
#include <unordered_map>

namespace ShadowStrike::Products::PhantomEDR::Playbooks {

namespace {

using ShadowStrike::Utils::Logger;

constexpr std::string_view kLogPrefix = "[PlaybookLibrary]";

[[nodiscard]] Json ActionStep(
    std::string_view id,
    std::string_view name,
    std::string_view action,
    Json parameters,
    std::string_view storeResultAs = {},
    std::string_view onFailure = "stop") {
    Json step = {
        { "id", std::string(id) },
        { "name", std::string(name) },
        { "type", "action" },
        { "action", std::string(action) },
        { "parameters", std::move(parameters) },
        { "on_failure", std::string(onFailure) }
    };

    if (!storeResultAs.empty()) {
        step["store_result_as"] = std::string(storeResultAs);
    }

    return step;
}

[[nodiscard]] Json DelayStep(
    std::string_view id,
    std::string_view name,
    const uint64_t delayMs) {
    return Json{
        { "id", std::string(id) },
        { "name", std::string(name) },
        { "type", "delay" },
        { "duration_ms", delayMs }
    };
}

[[nodiscard]] Json ConditionStep(
    std::string_view id,
    std::string_view name,
    Json condition,
    Json thenSteps,
    Json elseSteps = Json::array()) {
    return Json{
        { "id", std::string(id) },
        { "name", std::string(name) },
        { "type", "condition" },
        { "condition", std::move(condition) },
        { "then", std::move(thenSteps) },
        { "else", std::move(elseSteps) }
    };
}

[[nodiscard]] Json ParallelStep(std::string_view id, std::string_view name, Json steps) {
    return Json{
        { "id", std::string(id) },
        { "name", std::string(name) },
        { "type", "parallel" },
        { "steps", std::move(steps) }
    };
}

[[nodiscard]] Json LoopStep(
    std::string_view id,
    std::string_view name,
    std::string_view itemsPath,
    std::string_view iteratorName,
    Json steps) {
    return Json{
        { "id", std::string(id) },
        { "name", std::string(name) },
        { "type", "loop" },
        { "items_path", std::string(itemsPath) },
        { "iterator", std::string(iteratorName) },
        { "steps", std::move(steps) },
        { "store_result_as", std::format("{}_results", id) }
    };
}

[[nodiscard]] Json BuildRansomwareContainment() {
    return Json{
        { "id", "ransomware_containment" },
        { "name", "Ransomware Containment" },
        { "description", "Contain suspected ransomware activity through local host isolation, process termination, evidence capture, and operator notification." },
        { "version", "1.0.0" },
        { "enabled", true },
        { "default_timeout_ms", 300000 },
        { "default_context", Json::object() },
        { "steps", Json::array({
            ActionStep("notify-start", "Notify ransomware response start", "notify_local", {
                { "severity", "critical" },
                { "subject", "Ransomware containment initiated" },
                { "details", "Playbook {{playbook.id}} started for host {{alert.hostname}}" }
            }),
            ParallelStep("containment-actions", "Execute containment actions", Json::array({
                ActionStep("isolate-host", "Isolate impacted endpoint", "isolate_endpoint", {
                    { "incident_id", "{{incident.id}}" },
                    { "reason", "Automated ransomware containment for host {{alert.hostname}}" }
                }),
                ActionStep("terminate-process", "Terminate suspicious process", "kill_process", {
                    { "pid", "{{alert.process_id}}" }
                }, {}, "continue"),
                ActionStep("quarantine-primary-file", "Quarantine detected payload", "quarantine_file", {
                    { "incident_id", "{{incident.id}}" },
                    { "file_path", "{{alert.file_path}}" }
                }, {}, "continue")
            })),
            ActionStep("collect-evidence", "Collect forensic evidence", "collect_evidence", {
                { "incident_id", "{{incident.id}}" },
                { "pid", "{{alert.process_id}}" },
                { "file_path", "{{alert.file_path}}" }
            }, "evidence_result", "continue"),
            LoopStep("enrich-iocs", "Enrich observed indicators", "alert.iocs", "ioc", Json::array({
                ActionStep("enrich-indicator", "Enrich indicator", "enrich_ioc", {
                    { "ioc_type", "{{loop.ioc.type}}" },
                    { "value", "{{loop.ioc.value}}" }
                }, "enrichment", "continue")
            })),
            ConditionStep("block-remote-ip", "Block remote IP when present", {
                { "path", "alert.remote_ip" },
                { "operator", "exists" }
            }, Json::array({
                ActionStep("block-ip", "Block remote command-and-control IP", "block_ip", {
                    { "ip_address", "{{alert.remote_ip}}" },
                    { "reason", "Ransomware containment for {{alert.hostname}}" }
                }, {}, "continue")
            })),
            DelayStep("cooldown", "Cooldown before final notification", 2000),
            ActionStep("notify-complete", "Notify containment completion", "notify_local", {
                { "severity", "high" },
                { "subject", "Ransomware containment completed" },
                { "details", "Playbook {{playbook.id}} finished for incident {{incident.id}}" }
            })
        }) }
    };
}

[[nodiscard]] Json BuildLateralMovementLockdown() {
    return Json{
        { "id", "lateral_movement_lockdown" },
        { "name", "Lateral Movement Lockdown" },
        { "description", "Stop east-west movement by isolating the device, blocking remote IPs, and disabling compromised accounts." },
        { "version", "1.0.0" },
        { "enabled", true },
        { "default_timeout_ms", 240000 },
        { "steps", Json::array({
            ActionStep("notify-start", "Notify lockdown start", "notify_local", {
                { "severity", "high" },
                { "subject", "Lateral movement lockdown initiated" },
                { "details", "ShadowStrike detected lateral movement on {{alert.hostname}}" }
            }),
            ActionStep("isolate-endpoint", "Isolate endpoint", "isolate_endpoint", {
                { "incident_id", "{{incident.id}}" },
                { "reason", "Potential lateral movement detected" }
            }),
            ConditionStep("disable-user-if-present", "Disable impacted account when present", {
                { "path", "alert.user_name" },
                { "operator", "exists" }
            }, Json::array({
                ActionStep("disable-user", "Disable compromised account", "disable_user", {
                    { "user_name", "{{alert.user_name}}" }
                })
            })),
            LoopStep("block-suspect-ips", "Block suspicious peer IPs", "alert.peer_ips", "peer_ip", Json::array({
                ActionStep("block-ip", "Block peer IP", "block_ip", {
                    { "ip_address", "{{loop.peer_ip}}" },
                    { "reason", "Automated lateral movement lockdown" }
                }, {}, "continue")
            })),
            ActionStep("collect-evidence", "Collect evidence", "collect_evidence", {
                { "incident_id", "{{incident.id}}" },
                { "pid", "{{alert.process_id}}" },
                { "file_path", "{{alert.file_path}}" }
            }, "evidence_result", "continue")
        }) }
    };
}

[[nodiscard]] Json BuildCredentialTheftResponse() {
    return Json{
        { "id", "credential_theft_response" },
        { "name", "Credential Theft Response" },
        { "description", "Protect local assets after credential theft activity with account disablement, process termination, enrichment, and notification." },
        { "version", "1.0.0" },
        { "enabled", true },
        { "default_timeout_ms", 180000 },
        { "steps", Json::array({
            ActionStep("notify-start", "Notify credential theft response", "notify_local", {
                { "severity", "critical" },
                { "subject", "Credential theft response initiated" },
                { "details", "Credential theft playbook started for {{alert.hostname}}" }
            }),
            ConditionStep("disable-user-if-present", "Disable targeted user", {
                { "path", "alert.user_name" },
                { "operator", "exists" }
            }, Json::array({
                ActionStep("disable-user", "Disable user account", "disable_user", {
                    { "user_name", "{{alert.user_name}}" }
                })
            })),
            ActionStep("terminate-credential-tool", "Terminate credential theft process", "kill_process", {
                { "pid", "{{alert.process_id}}" }
            }, {}, "continue"),
            ConditionStep("quarantine-tooling", "Quarantine associated binary", {
                { "path", "alert.file_path" },
                { "operator", "exists" }
            }, Json::array({
                ActionStep("quarantine-file", "Quarantine credential theft tool", "quarantine_file", {
                    { "incident_id", "{{incident.id}}" },
                    { "file_path", "{{alert.file_path}}" }
                }, {}, "continue")
            })),
            LoopStep("enrich-destinations", "Enrich exfiltration destinations", "alert.destination_iocs", "destination", Json::array({
                ActionStep("enrich-destination", "Enrich destination indicator", "enrich_ioc", {
                    { "ioc_type", "{{loop.destination.type}}" },
                    { "value", "{{loop.destination.value}}" }
                }, "destination_enrichment", "continue")
            })),
            ActionStep("collect-evidence", "Collect evidence", "collect_evidence", {
                { "incident_id", "{{incident.id}}" },
                { "pid", "{{alert.process_id}}" },
                { "file_path", "{{alert.file_path}}" }
            }, "evidence_result", "continue")
        }) }
    };
}

[[nodiscard]] Json BuildMalwareQuarantine() {
    return Json{
        { "id", "malware_quarantine" },
        { "name", "Malware Quarantine" },
        { "description", "Quarantine a malicious file, terminate its process, capture evidence, and notify local responders." },
        { "version", "1.0.0" },
        { "enabled", true },
        { "default_timeout_ms", 180000 },
        { "steps", Json::array({
            ActionStep("notify-start", "Notify malware quarantine", "notify_local", {
                { "severity", "high" },
                { "subject", "Malware quarantine initiated" },
                { "details", "Malware quarantine running for {{alert.file_path}}" }
            }),
            ActionStep("quarantine-file", "Quarantine malicious file", "quarantine_file", {
                { "incident_id", "{{incident.id}}" },
                { "file_path", "{{alert.file_path}}" }
            }),
            ActionStep("kill-process", "Terminate executing process", "kill_process", {
                { "pid", "{{alert.process_id}}" }
            }, {}, "continue"),
            ActionStep("collect-evidence", "Collect evidence", "collect_evidence", {
                { "incident_id", "{{incident.id}}" },
                { "pid", "{{alert.process_id}}" },
                { "file_path", "{{alert.file_path}}" }
            }, "evidence_result", "continue"),
            ActionStep("notify-finish", "Notify completion", "notify_local", {
                { "severity", "medium" },
                { "subject", "Malware quarantine complete" },
                { "details", "Quarantine actions completed for incident {{incident.id}}" }
            })
        }) }
    };
}

[[nodiscard]] Json BuildSuspiciousProcessInvestigation() {
    return Json{
        { "id", "suspicious_process_investigation" },
        { "name", "Suspicious Process Investigation" },
        { "description", "Gather local evidence and enrich indicators for suspicious process activity without immediately isolating the endpoint." },
        { "version", "1.0.0" },
        { "enabled", true },
        { "default_timeout_ms", 180000 },
        { "steps", Json::array({
            ActionStep("notify-start", "Notify investigation start", "notify_local", {
                { "severity", "medium" },
                { "subject", "Suspicious process investigation started" },
                { "details", "Investigating process {{alert.process_id}} on {{alert.hostname}}" }
            }),
            ActionStep("collect-evidence", "Collect process evidence", "collect_evidence", {
                { "incident_id", "{{incident.id}}" },
                { "pid", "{{alert.process_id}}" },
                { "file_path", "{{alert.file_path}}" }
            }, "evidence_result"),
            LoopStep("enrich-observed-iocs", "Enrich observed indicators", "alert.iocs", "ioc", Json::array({
                ActionStep("enrich-ioc", "Enrich IOC", "enrich_ioc", {
                    { "ioc_type", "{{loop.ioc.type}}" },
                    { "value", "{{loop.ioc.value}}" }
                }, "enrichment", "continue")
            })),
            ConditionStep("escalate-high-risk", "Escalate on high severity", {
                { "path", "alert.severity" },
                { "operator", "in" },
                { "value", Json::array({ "high", "critical", "emergency" }) }
            }, Json::array({
                ActionStep("notify-escalation", "Notify investigation escalation", "notify_local", {
                    { "severity", "high" },
                    { "subject", "Suspicious process investigation escalated" },
                    { "details", "High severity suspicious process requires responder review" }
                })
            }))
        }) }
    };
}

} // namespace

class PlaybookLibraryImpl {
public:
    bool initialized = false;
    mutable std::shared_mutex mutex;
    std::unordered_map<std::string, Json> documents;
};

PlaybookLibrary& PlaybookLibrary::Instance() {
    static PlaybookLibrary instance;
    return instance;
}

PlaybookLibrary::PlaybookLibrary()
    : m_impl(std::make_unique<PlaybookLibraryImpl>()) {
}

PlaybookLibrary::~PlaybookLibrary() = default;

bool PlaybookLibrary::Initialize() {
    std::unique_lock lock(m_impl->mutex);
    if (m_impl->initialized) {
        return true;
    }

    m_impl->documents.clear();
    m_impl->documents.emplace("ransomware_containment", BuildRansomwareContainment());
    m_impl->documents.emplace("lateral_movement_lockdown", BuildLateralMovementLockdown());
    m_impl->documents.emplace("credential_theft_response", BuildCredentialTheftResponse());
    m_impl->documents.emplace("malware_quarantine", BuildMalwareQuarantine());
    m_impl->documents.emplace("suspicious_process_investigation", BuildSuspiciousProcessInvestigation());
    m_impl->initialized = true;

    Logger::Info("{} Loaded {} built-in playbooks", kLogPrefix, m_impl->documents.size());
    return true;
}

void PlaybookLibrary::Shutdown() {
    std::unique_lock lock(m_impl->mutex);
    if (!m_impl->initialized) {
        return;
    }

    m_impl->documents.clear();
    m_impl->initialized = false;
    Logger::Info("{} Shutdown complete", kLogPrefix);
}

bool PlaybookLibrary::IsInitialized() const {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->initialized;
}

std::vector<std::string> PlaybookLibrary::GetPlaybookIds() const {
    std::shared_lock lock(m_impl->mutex);
    std::vector<std::string> ids;
    ids.reserve(m_impl->documents.size());

    for (const auto& [id, _] : m_impl->documents) {
        ids.push_back(id);
    }

    std::sort(ids.begin(), ids.end());
    return ids;
}

std::optional<Json> PlaybookLibrary::GetPlaybookDocument(std::string_view playbookId) const {
    std::shared_lock lock(m_impl->mutex);
    const auto it = m_impl->documents.find(std::string(playbookId));
    if (it == m_impl->documents.end()) {
        return std::nullopt;
    }

    return it->second;
}

std::vector<Json> PlaybookLibrary::GetPlaybookDocuments() const {
    std::shared_lock lock(m_impl->mutex);
    std::vector<Json> documents;
    documents.reserve(m_impl->documents.size());

    for (const auto& [_, document] : m_impl->documents) {
        documents.push_back(document);
    }

    return documents;
}

} // namespace ShadowStrike::Products::PhantomEDR::Playbooks
