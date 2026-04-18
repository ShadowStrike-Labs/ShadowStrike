/*
 * ShadowStrike - Enterprise NGAV/EDR/XDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

#include <format>
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "PhantomCore/Database/DatabaseManager.hpp"
#include "Products/Community/PhantomXDR/AIAssistant/AssistantTypes.hpp"
#include "Products/Community/PhantomXDR/AIAssistant/IncidentSummarizer.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::AIAssistant {

namespace {

constexpr const char* kLogPrefix = "[XDR::AIAssistant::IncidentSummarizer]";

using Clock = std::chrono::system_clock;
using DB    = ShadowStrike::Database::DatabaseManager;
using DBErr = ShadowStrike::Database::DatabaseError;
namespace SU = ShadowStrike::Utils::StringUtils;
using ShadowStrike::Utils::Logger;
namespace XDR = ShadowStrike::Products::PhantomXDR::XDRCorrelation;

[[nodiscard]] int64_t ToUnixMilliseconds(const TimePoint timePoint) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch()).count();
}

[[nodiscard]] TimePoint FromUnixMilliseconds(const int64_t milliseconds) {
    return TimePoint{std::chrono::milliseconds(milliseconds)};
}

[[nodiscard]] std::string GenerateSummaryId() {
    static std::atomic<uint64_t> sequence{0};
    return std::format("XDRS-{:X}-{:04X}",
                       static_cast<uint64_t>(Clock::now().time_since_epoch().count()),
                       sequence.fetch_add(1, std::memory_order_relaxed) & 0xFFFFULL);
}

[[nodiscard]] std::string EscapeStorage(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size() + 8);
    for (const char ch : value) {
        switch (ch) {
            case '\\': escaped += "\\\\"; break;
            case '\n': escaped += "\\n"; break;
            case '|':  escaped += "\\p"; break;
            default:   escaped.push_back(ch); break;
        }
    }
    return escaped;
}

[[nodiscard]] std::string UnescapeStorage(std::string_view value) {
    std::string unescaped;
    unescaped.reserve(value.size());
    for (size_t index = 0; index < value.size(); ++index) {
        if (value[index] == '\\' && index + 1 < value.size()) {
            ++index;
            switch (value[index]) {
                case 'n': unescaped.push_back('\n'); break;
                case 'p': unescaped.push_back('|'); break;
                case '\\': unescaped.push_back('\\'); break;
                default: unescaped.push_back(value[index]); break;
            }
        } else {
            unescaped.push_back(value[index]);
        }
    }
    return unescaped;
}

[[nodiscard]] std::string SerializeList(const std::vector<std::string>& values) {
    std::ostringstream stream;
    for (size_t index = 0; index < values.size(); ++index) {
        if (index != 0) {
            stream << '|';
        }
        stream << EscapeStorage(values[index]);
    }
    return stream.str();
}

[[nodiscard]] std::vector<std::string> DeserializeList(std::string_view values) {
    std::vector<std::string> result;
    std::string current;
    bool escaped = false;

    for (const char ch : values) {
        if (escaped) {
            current.push_back('\\');
            current.push_back(ch);
            escaped = false;
            continue;
        }

        if (ch == '\\') {
            escaped = true;
            continue;
        }

        if (ch == '|') {
            result.push_back(UnescapeStorage(current));
            current.clear();
            continue;
        }

        current.push_back(ch);
    }

    if (!current.empty() || !values.empty()) {
        result.push_back(UnescapeStorage(current));
    }

    return result;
}

[[nodiscard]] const char* SeverityToString(const XDR::IncidentSeverity severity) noexcept {
    switch (severity) {
        case XDR::IncidentSeverity::Critical: return "Critical";
        case XDR::IncidentSeverity::High:     return "High";
        case XDR::IncidentSeverity::Medium:   return "Medium";
        case XDR::IncidentSeverity::Low:      return "Low";
        case XDR::IncidentSeverity::Info:     return "Informational";
    }
    return "Informational";
}

[[nodiscard]] const char* SummaryLevelToString(const SummaryLevel level) noexcept {
    switch (level) {
        case SummaryLevel::Brief:     return "Brief";
        case SummaryLevel::Standard:  return "Standard";
        case SummaryLevel::Detailed:  return "Detailed";
        case SummaryLevel::Executive: return "Executive";
    }
    return "Standard";
}

[[nodiscard]] XDR::IncidentSeverity VerdictToSeverity(const XDR::CorrelationVerdict verdict) noexcept {
    switch (verdict) {
        case XDR::CorrelationVerdict::Critical:      return XDR::IncidentSeverity::Critical;
        case XDR::CorrelationVerdict::Malicious:     return XDR::IncidentSeverity::High;
        case XDR::CorrelationVerdict::Suspicious:    return XDR::IncidentSeverity::Medium;
        case XDR::CorrelationVerdict::Informational: return XDR::IncidentSeverity::Low;
        case XDR::CorrelationVerdict::Benign:        return XDR::IncidentSeverity::Info;
    }
    return XDR::IncidentSeverity::Info;
}

[[nodiscard]] const char* DomainToString(const XDR::XDREventDomain domain) noexcept {
    switch (domain) {
        case XDR::XDREventDomain::Endpoint: return "endpoint";
        case XDR::XDREventDomain::Network:  return "network";
        case XDR::XDREventDomain::Identity: return "identity";
        case XDR::XDREventDomain::Email:    return "email";
        case XDR::XDREventDomain::Cloud:    return "cloud";
        case XDR::XDREventDomain::Unknown:  return "unknown";
    }
    return "unknown";
}

[[nodiscard]] std::string PhaseToString(const XDR::StorylinePhase phase) {
    switch (phase) {
        case XDR::StorylinePhase::Reconnaissance:      return "Reconnaissance";
        case XDR::StorylinePhase::ResourceDevelopment: return "Resource Development";
        case XDR::StorylinePhase::InitialAccess:       return "Initial Access";
        case XDR::StorylinePhase::Execution:           return "Execution";
        case XDR::StorylinePhase::Persistence:         return "Persistence";
        case XDR::StorylinePhase::PrivilegeEscalation: return "Privilege Escalation";
        case XDR::StorylinePhase::DefenseEvasion:      return "Defense Evasion";
        case XDR::StorylinePhase::CredentialAccess:    return "Credential Access";
        case XDR::StorylinePhase::Discovery:           return "Discovery";
        case XDR::StorylinePhase::LateralMovement:     return "Lateral Movement";
        case XDR::StorylinePhase::Collection:          return "Collection";
        case XDR::StorylinePhase::CommandAndControl:   return "Command and Control";
        case XDR::StorylinePhase::Exfiltration:        return "Exfiltration";
        case XDR::StorylinePhase::Impact:              return "Impact";
        case XDR::StorylinePhase::Unknown:             return "Unknown";
    }
    return "Unknown";
}

[[nodiscard]] std::unordered_map<std::string, std::string> BuildMitreCatalog() {
    return {
        { "T1003", "OS Credential Dumping used to extract passwords, hashes, or Kerberos material." },
        { "T1005", "Data from Local System collection focused on sensitive local files." },
        { "T1016", "System Network Configuration Discovery to inventory network posture." },
        { "T1018", "Remote System Discovery used to identify reachable hosts for follow-on actions." },
        { "T1021", "Remote Services used for lateral movement over protocols such as SMB, RDP, or WinRM." },
        { "T1027", "Obfuscated or Compressed Files and Information intended to hinder analysis." },
        { "T1036", "Masquerading designed to make malicious artifacts appear legitimate." },
        { "T1041", "Exfiltration Over C2 Channel to hide theft within beacon traffic." },
        { "T1046", "Network Service Scanning used to map exposed services and internal attack paths." },
        { "T1047", "Windows Management Instrumentation for remote execution or system control." },
        { "T1053", "Scheduled Task or Job persistence used to re-launch malware automatically." },
        { "T1055", "Process Injection to execute payloads inside trusted processes." },
        { "T1059", "Command and Scripting Interpreter abuse through shells such as PowerShell or cmd.exe." },
        { "T1068", "Exploitation for Privilege Escalation to obtain higher permissions." },
        { "T1070", "Indicator Removal on Host to delete or alter forensic evidence." },
        { "T1071", "Application Layer Protocol C2 traffic tunneled through standard protocols." },
        { "T1078", "Valid Accounts abuse using legitimate credentials for stealthy access." },
        { "T1082", "System Information Discovery to profile host configuration and defenses." },
        { "T1083", "File and Directory Discovery to locate sensitive content or tooling paths." },
        { "T1090", "Proxy use to route malicious traffic through intermediate infrastructure." },
        { "T1105", "Ingress Tool Transfer where the adversary downloads additional tooling." },
        { "T1110", "Brute Force attempts against authentication surfaces." },
        { "T1136", "Create Account activity establishing a foothold or backup identity." },
        { "T1140", "Deobfuscate or Decode Files and Information before execution." },
        { "T1190", "Exploit Public-Facing Application to achieve initial compromise." },
        { "T1204", "User Execution relying on a victim to launch content or approve an action." },
        { "T1218", "System Binary Proxy Execution through signed LOLBINs such as rundll32 or mshta." },
        { "T1486", "Data Encrypted for Impact consistent with ransomware operations." },
        { "T1489", "Service Stop activity intended to weaken defenses or business services." },
        { "T1490", "Inhibit System Recovery by deleting backups or recovery options." },
        { "T1505", "Server Software Component persistence through malicious server modules." },
        { "T1543", "Create or Modify System Process for persistent service execution." },
        { "T1546", "Event Triggered Execution persistence using WMI, shell extensions, or other hooks." },
        { "T1547", "Boot or Logon Autostart Execution persistence at user or system startup." },
        { "T1550", "Use Alternate Authentication Material such as pass-the-hash or tickets." },
        { "T1552", "Unsecured Credentials discovery in files, registry, or configuration stores." },
        { "T1555", "Credentials from Password Stores theft from browsers or OS-managed vaults." },
        { "T1562", "Impair Defenses through tampering with security controls or logs." },
        { "T1566", "Phishing used to obtain access or execute malicious payloads." },
        { "T1570", "Lateral Tool Transfer across hosts to stage malware internally." },
        { "T1571", "Non-Standard Port usage to evade simple network allowlisting." },
        { "T1583", "Acquire Infrastructure for attacker-controlled domains or servers." },
        { "T1595", "Active Scanning activity against target infrastructure." }
    };
}

} // anonymous namespace

class IncidentSummarizerImpl final {
public:
    std::atomic<bool>                                initialized{false};
    mutable std::shared_mutex                        mutex;
    mutable std::unordered_map<std::string, IncidentSummary> summaryCache;
    std::unordered_map<std::string, std::string>     mitreCatalog;

    [[nodiscard]] bool Initialize();
    void               Shutdown();
    [[nodiscard]] bool CreateSchema() const;
    [[nodiscard]] IncidentSummary SummarizeStoryline(const XDR::Storyline& sl, SummaryLevel level);
    [[nodiscard]] IncidentSummary SummarizeCorrelationMatch(const XDR::CorrelationMatch& match,
                                                            const std::vector<XDR::XDREvent>& events,
                                                            SummaryLevel level);
    [[nodiscard]] std::string GenerateExecutiveBrief(const std::vector<IncidentSummary>& summaries) const;
    [[nodiscard]] std::optional<IncidentSummary> GetCachedSummary(std::string_view storylineId) const;

private:
    [[nodiscard]] std::string ResolveMitreDescription(std::string_view techniqueId) const;
    [[nodiscard]] std::string BuildMitreSummary(const std::vector<std::string>& tactics,
                                                const std::vector<std::string>& techniques) const;
    [[nodiscard]] std::vector<std::string> BuildRecommendations(const XDR::Storyline& sl) const;
    [[nodiscard]] std::vector<std::string> BuildRecommendations(const XDR::CorrelationMatch& match,
                                                                const std::vector<XDR::XDREvent>& events) const;
    [[nodiscard]] std::vector<std::string> BuildAffectedAssets(const XDR::Storyline& sl) const;
    [[nodiscard]] std::vector<std::string> BuildAffectedAssets(const std::vector<XDR::XDREvent>& events,
                                                               std::string_view linkedEntity) const;
    [[nodiscard]] std::string BuildStorylineNarrative(const XDR::Storyline& sl, SummaryLevel level) const;
    [[nodiscard]] std::string BuildMatchNarrative(const XDR::CorrelationMatch& match,
                                                  const std::vector<XDR::XDREvent>& events,
                                                  SummaryLevel level) const;
    void PersistSummary(const IncidentSummary& summary) const;
};

[[nodiscard]] bool IncidentSummarizerImpl::CreateSchema() const {
    auto& db = DB::Instance();
    DBErr err;

    constexpr std::string_view kSchema = R"SQL(
        CREATE TABLE IF NOT EXISTS xdr_incident_summaries (
            storyline_id            TEXT PRIMARY KEY,
            summary_id              TEXT NOT NULL,
            summary_level           INTEGER NOT NULL,
            title                   TEXT NOT NULL,
            narrative               TEXT NOT NULL,
            recommendations         TEXT DEFAULT '',
            affected_assets         TEXT DEFAULT '',
            mitre_mapping_summary   TEXT DEFAULT '',
            generated_at_ms         INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_xdr_incident_summary_time
            ON xdr_incident_summaries(generated_at_ms DESC);
    )SQL";

    if (!db.Execute(kSchema, &err)) {
        Logger::Error("{} Failed to create incident summary schema: {}",
                      kLogPrefix, SU::ToNarrow(err.message));
        return false;
    }

    return true;
}

[[nodiscard]] bool IncidentSummarizerImpl::Initialize() {
    if (initialized.load(std::memory_order_acquire)) {
        return true;
    }

    Logger::Info("{} Initializing incident summarizer...", kLogPrefix);

    if (!CreateSchema()) {
        return false;
    }

    {
        std::unique_lock lock(mutex);
        mitreCatalog = BuildMitreCatalog();
    }

    initialized.store(true, std::memory_order_release);
    Logger::Info("{} Incident summarizer initialized with {} MITRE mappings",
                 kLogPrefix, mitreCatalog.size());
    return true;
}

void IncidentSummarizerImpl::Shutdown() {
    if (!initialized.exchange(false, std::memory_order_acq_rel)) {
        return;
    }

    std::unique_lock lock(mutex);
    Logger::Info("{} Incident summarizer shut down ({} cached summaries)",
                 kLogPrefix, summaryCache.size());
    summaryCache.clear();
    mitreCatalog.clear();
}

[[nodiscard]] std::string IncidentSummarizerImpl::ResolveMitreDescription(std::string_view techniqueId) const {
    std::shared_lock lock(mutex);

    auto it = mitreCatalog.find(std::string(techniqueId));
    if (it != mitreCatalog.end()) {
        return it->second;
    }

    const auto dotIndex = techniqueId.find('.');
    if (dotIndex != std::string_view::npos) {
        it = mitreCatalog.find(std::string(techniqueId.substr(0, dotIndex)));
        if (it != mitreCatalog.end()) {
            return it->second;
        }
    }

    return "No curated plain-language description is available for this technique yet.";
}

[[nodiscard]] std::string IncidentSummarizerImpl::BuildMitreSummary(
    const std::vector<std::string>& tactics,
    const std::vector<std::string>& techniques) const {
    std::ostringstream stream;
    stream << "Tactics observed: ";
    if (tactics.empty()) {
        stream << "none recorded";
    } else {
        for (size_t index = 0; index < tactics.size(); ++index) {
            if (index != 0) {
                stream << ", ";
            }
            stream << tactics[index];
        }
    }

    if (!techniques.empty()) {
        stream << ". Techniques: ";
        for (size_t index = 0; index < techniques.size(); ++index) {
            if (index != 0) {
                stream << "; ";
            }
            stream << techniques[index] << " — " << ResolveMitreDescription(techniques[index]);
        }
    }

    return stream.str();
}

[[nodiscard]] std::vector<std::string> IncidentSummarizerImpl::BuildAffectedAssets(const XDR::Storyline& sl) const {
    std::set<std::string> assets;
    for (const auto& host : sl.affectedHosts) {
        if (!host.empty()) {
            assets.insert(std::format("host:{}", host));
        }
    }
    for (const auto& user : sl.affectedUsers) {
        if (!user.empty()) {
            assets.insert(std::format("user:{}", user));
        }
    }

    return { assets.begin(), assets.end() };
}

[[nodiscard]] std::vector<std::string> IncidentSummarizerImpl::BuildAffectedAssets(
    const std::vector<XDR::XDREvent>& events,
    std::string_view linkedEntity) const {
    std::set<std::string> assets;
    if (!linkedEntity.empty()) {
        assets.insert(std::format("entity:{}", linkedEntity));
    }

    for (const auto& event : events) {
        if (!event.hostName.empty()) {
            assets.insert(std::format("host:{}", event.hostName));
        }
        if (!event.userName.empty()) {
            assets.insert(std::format("user:{}", event.userName));
        }
        if (!event.ipAddress.empty()) {
            assets.insert(std::format("ip:{}", event.ipAddress));
        }
    }

    return { assets.begin(), assets.end() };
}

[[nodiscard]] std::vector<std::string> IncidentSummarizerImpl::BuildRecommendations(const XDR::Storyline& sl) const {
    std::vector<std::string> recommendations{
        "Validate the initiating account and host against change-control records before taking remediation action.",
        "Preserve endpoint, identity, and network telemetry associated with this storyline for forensic continuity."
    };

    if (sl.severity >= XDR::IncidentSeverity::High) {
        recommendations.push_back("Isolate affected hosts from the network until credential exposure and lateral movement risk are contained.");
    }

    if (std::find(sl.mitreTechniques.begin(), sl.mitreTechniques.end(), "T1003") != sl.mitreTechniques.end()) {
        recommendations.push_back("Reset credentials used on impacted hosts and review Kerberos ticket activity for follow-on abuse.");
    }
    if (std::find(sl.mitreTechniques.begin(), sl.mitreTechniques.end(), "T1486") != sl.mitreTechniques.end()) {
        recommendations.push_back("Prioritize backup integrity checks and disable write access to shared storage paths to limit encryption spread.");
    }
    if (std::find(sl.mitreTechniques.begin(), sl.mitreTechniques.end(), "T1021") != sl.mitreTechniques.end()) {
        recommendations.push_back("Audit recent remote-service logons, restrict east-west administrative protocols, and rotate privileged credentials.");
    }
    if (recommendations.size() < 4) {
        recommendations.push_back("Review persistence mechanisms referenced in the storyline and remove any unauthorized tasks, services, or autoruns.");
    }

    return recommendations;
}

[[nodiscard]] std::vector<std::string> IncidentSummarizerImpl::BuildRecommendations(
    const XDR::CorrelationMatch& match,
    const std::vector<XDR::XDREvent>& events) const {
    std::vector<std::string> recommendations{
        "Confirm the correlation rule scope and preserve all matched telemetry before containment changes are applied.",
        "Investigate the linked entity across endpoint, identity, and network data to validate whether the activity spans multiple domains."
    };

    if (VerdictToSeverity(match.verdict) >= XDR::IncidentSeverity::High) {
        recommendations.push_back("Escalate for containment review and consider host isolation if the linked entity is still active.");
    }

    for (const auto& event : events) {
        if (event.mitreAttackId == "T1078") {
            recommendations.push_back("Invalidate or rotate the linked credentials and review additional valid-account usage from the same entity.");
            break;
        }
        if (event.mitreAttackId == "T1021") {
            recommendations.push_back("Review remote-service access paths and temporarily restrict SMB, RDP, or WinRM from the impacted source.");
            break;
        }
    }

    return recommendations;
}

[[nodiscard]] std::string IncidentSummarizerImpl::BuildStorylineNarrative(const XDR::Storyline& sl,
                                                                          const SummaryLevel level) const {
    std::ostringstream stream;
    stream << SeverityToString(sl.severity) << " incident spanning "
           << sl.nodes.size() << " correlated node(s) from "
           << std::max<size_t>(1, sl.mitreTactics.size()) << " ATT&CK tactic(s). ";

    if (!sl.narrative.empty()) {
        stream << sl.narrative << ' ';
    }

    const size_t eventLimit =
        level == SummaryLevel::Brief ? 2 :
        level == SummaryLevel::Standard ? 4 :
        level == SummaryLevel::Executive ? 3 : sl.nodes.size();

    if (!sl.nodes.empty()) {
        stream << "Observed progression:";
        for (size_t index = 0; index < std::min(eventLimit, sl.nodes.size()); ++index) {
            const auto& node = sl.nodes[index];
            stream << std::format(" [{}] {}", PhaseToString(node.phase), node.description);
        }
        if (eventLimit < sl.nodes.size()) {
            stream << std::format(" Additional {} node(s) omitted for brevity.", sl.nodes.size() - eventLimit);
        }
    }

    if (level == SummaryLevel::Detailed && !sl.mitreTechniques.empty()) {
        stream << " Technique context: ";
        for (size_t index = 0; index < sl.mitreTechniques.size(); ++index) {
            if (index != 0) {
                stream << ' ';
            }
            stream << std::format("{} ({})", sl.mitreTechniques[index],
                                  ResolveMitreDescription(sl.mitreTechniques[index]));
        }
    }

    return stream.str();
}

[[nodiscard]] std::string IncidentSummarizerImpl::BuildMatchNarrative(
    const XDR::CorrelationMatch& match,
    const std::vector<XDR::XDREvent>& events,
    const SummaryLevel level) const {
    std::ostringstream stream;
    stream << std::format("{} correlation '{}' matched {} event(s) with {}% confidence. ",
                          SeverityToString(VerdictToSeverity(match.verdict)),
                          match.ruleName,
                          match.matchedEventIds.size(),
                          static_cast<int>(match.confidence));

    if (!match.linkedEntity.empty()) {
        stream << std::format("Linked entity: {}. ", match.linkedEntity);
    }

    if (!events.empty()) {
        const size_t eventLimit =
            level == SummaryLevel::Brief ? 2 :
            level == SummaryLevel::Standard ? 3 :
            level == SummaryLevel::Executive ? 2 : events.size();

        stream << "Representative telemetry:";
        for (size_t index = 0; index < std::min(eventLimit, events.size()); ++index) {
            const auto& event = events[index];
            stream << std::format(" [{}:{}] {}",
                                  DomainToString(event.domain),
                                  event.mitreAttackId.empty() ? "no-technique" : event.mitreAttackId,
                                  event.sourceModule.empty() ? "cross-domain event" : event.sourceModule);
        }
        if (eventLimit < events.size()) {
            stream << std::format(" Additional {} event(s) omitted.", events.size() - eventLimit);
        }
    }

    if (level == SummaryLevel::Detailed) {
        std::unordered_set<std::string> techniques;
        for (const auto& event : events) {
            if (!event.mitreAttackId.empty()) {
                techniques.insert(event.mitreAttackId);
            }
        }
        if (!techniques.empty()) {
            stream << " Technique rationale:";
            for (const auto& technique : techniques) {
                stream << std::format(" {} ({})", technique, ResolveMitreDescription(technique));
            }
        }
    }

    return stream.str();
}

void IncidentSummarizerImpl::PersistSummary(const IncidentSummary& summary) const {
    auto& db = DB::Instance();
    DBErr err;

    const bool persisted = db.ExecuteWithParams(
        "INSERT INTO xdr_incident_summaries "
        "(storyline_id, summary_id, summary_level, title, narrative, recommendations, affected_assets, mitre_mapping_summary, generated_at_ms) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(storyline_id) DO UPDATE SET "
        "summary_id = excluded.summary_id, "
        "summary_level = excluded.summary_level, "
        "title = excluded.title, "
        "narrative = excluded.narrative, "
        "recommendations = excluded.recommendations, "
        "affected_assets = excluded.affected_assets, "
        "mitre_mapping_summary = excluded.mitre_mapping_summary, "
        "generated_at_ms = excluded.generated_at_ms",
        &err,
        summary.storylineId,
        summary.summaryId,
        static_cast<int>(summary.level),
        summary.title,
        summary.narrative,
        SerializeList(summary.recommendations),
        SerializeList(summary.affectedAssets),
        summary.mitreMappingSummary,
        ToUnixMilliseconds(summary.generatedAt));

    if (!persisted) {
        Logger::Warn("{} Failed to persist summary for '{}': {}",
                     kLogPrefix, summary.storylineId, SU::ToNarrow(err.message));
    }
}

[[nodiscard]] IncidentSummary IncidentSummarizerImpl::SummarizeStoryline(const XDR::Storyline& sl,
                                                                         const SummaryLevel level) {
    IncidentSummary summary;
    summary.summaryId = GenerateSummaryId();
    summary.storylineId = sl.storylineId;
    summary.level = level;
    summary.title = std::format("{} storyline summary: {}",
                                SeverityToString(sl.severity),
                                sl.title.empty() ? sl.storylineId : sl.title);
    summary.narrative = BuildStorylineNarrative(sl, level);
    summary.recommendations = BuildRecommendations(sl);
    summary.affectedAssets = BuildAffectedAssets(sl);
    summary.mitreMappingSummary = BuildMitreSummary(sl.mitreTactics, sl.mitreTechniques);
    summary.generatedAt = Clock::now();

    {
        std::unique_lock lock(mutex);
        summaryCache[summary.storylineId] = summary;
    }

    PersistSummary(summary);
    Logger::Info("{} Generated {} summary for storyline '{}'",
                 kLogPrefix, SummaryLevelToString(level), summary.storylineId);
    return summary;
}

[[nodiscard]] IncidentSummary IncidentSummarizerImpl::SummarizeCorrelationMatch(
    const XDR::CorrelationMatch& match,
    const std::vector<XDR::XDREvent>& events,
    const SummaryLevel level) {
    std::vector<XDR::XDREvent> matchedEvents;
    matchedEvents.reserve(match.matchedEventIds.size());

    std::unordered_set<uint64_t> eventIds(match.matchedEventIds.begin(), match.matchedEventIds.end());
    for (const auto& event : events) {
        if (eventIds.contains(event.eventId)) {
            matchedEvents.push_back(event);
        }
    }

    std::sort(matchedEvents.begin(), matchedEvents.end(),
              [](const XDR::XDREvent& left, const XDR::XDREvent& right) {
                  return left.timestamp < right.timestamp;
              });

    std::vector<std::string> tactics;
    std::vector<std::string> techniques;
    {
        std::set<std::string> tacticSet;
        std::set<std::string> techniqueSet;
        for (const auto& event : matchedEvents) {
            if (!event.mitreTactic.empty()) {
                tacticSet.insert(event.mitreTactic);
            }
            if (!event.mitreAttackId.empty()) {
                techniqueSet.insert(event.mitreAttackId);
            }
        }
        tactics.assign(tacticSet.begin(), tacticSet.end());
        techniques.assign(techniqueSet.begin(), techniqueSet.end());
    }

    IncidentSummary summary;
    summary.summaryId = GenerateSummaryId();
    summary.storylineId = std::format("match:{}", match.matchId);
    summary.level = level;
    summary.title = std::format("{} correlation summary: {}",
                                SeverityToString(VerdictToSeverity(match.verdict)),
                                match.ruleName.empty() ? match.matchId : match.ruleName);
    summary.narrative = BuildMatchNarrative(match, matchedEvents, level);
    summary.recommendations = BuildRecommendations(match, matchedEvents);
    summary.affectedAssets = BuildAffectedAssets(matchedEvents, match.linkedEntity);
    summary.mitreMappingSummary = BuildMitreSummary(tactics, techniques);
    summary.generatedAt = Clock::now();

    {
        std::unique_lock lock(mutex);
        summaryCache[summary.storylineId] = summary;
    }

    PersistSummary(summary);
    Logger::Info("{} Generated {} summary for correlation match '{}'",
                 kLogPrefix, SummaryLevelToString(level), match.matchId);
    return summary;
}

[[nodiscard]] std::string IncidentSummarizerImpl::GenerateExecutiveBrief(
    const std::vector<IncidentSummary>& summaries) const {
    if (summaries.empty()) {
        return "No incident summaries are currently available for executive briefing.";
    }

    std::set<std::string> affectedAssets;
    std::set<std::string> priorityActions;

    for (const auto& summary : summaries) {
        for (const auto& asset : summary.affectedAssets) {
            affectedAssets.insert(asset);
        }
        for (size_t index = 0; index < std::min<size_t>(2, summary.recommendations.size()); ++index) {
            priorityActions.insert(summary.recommendations[index]);
        }
    }

    std::ostringstream stream;
    stream << std::format("Executive brief: {} incident summary item(s) reviewed. ", summaries.size());
    stream << "Headline incidents: ";
    for (size_t index = 0; index < std::min<size_t>(3, summaries.size()); ++index) {
        if (index != 0) {
            stream << " | ";
        }
        stream << summaries[index].title;
    }

    if (!affectedAssets.empty()) {
        stream << " Impacted assets: ";
        size_t index = 0;
        for (const auto& asset : affectedAssets) {
            if (index++ != 0) {
                stream << ", ";
            }
            stream << asset;
            if (index >= 6) {
                break;
            }
        }
        if (affectedAssets.size() > 6) {
            stream << ", additional assets omitted";
        }
    }

    if (!priorityActions.empty()) {
        stream << " Priority actions: ";
        size_t index = 0;
        for (const auto& action : priorityActions) {
            if (index++ != 0) {
                stream << " | ";
            }
            stream << action;
            if (index >= 3) {
                break;
            }
        }
    }

    return stream.str();
}

[[nodiscard]] std::optional<IncidentSummary> IncidentSummarizerImpl::GetCachedSummary(std::string_view storylineId) const {
    {
        std::shared_lock lock(mutex);
        auto it = summaryCache.find(std::string(storylineId));
        if (it != summaryCache.end()) {
            return it->second;
        }
    }

    auto& db = DB::Instance();
    DBErr err;
    auto result = db.QueryWithParams(
        "SELECT summary_id, summary_level, title, narrative, recommendations, affected_assets, mitre_mapping_summary, generated_at_ms "
        "FROM xdr_incident_summaries WHERE storyline_id = ?",
        &err,
        std::string(storylineId));

    if (err.HasError()) {
        Logger::Warn("{} Failed to retrieve cached summary for '{}': {}",
                     kLogPrefix, std::string(storylineId), SU::ToNarrow(err.message));
        return std::nullopt;
    }

    if (!result.Next()) {
        return std::nullopt;
    }

    IncidentSummary summary;
    summary.storylineId = std::string(storylineId);
    summary.summaryId = result.GetString(0);
    summary.level = static_cast<SummaryLevel>(result.GetInt(1));
    summary.title = result.GetString(2);
    summary.narrative = result.GetString(3);
    summary.recommendations = DeserializeList(result.IsNull(4) ? std::string_view{} : std::string_view(result.GetString(4)));
    summary.affectedAssets = DeserializeList(result.IsNull(5) ? std::string_view{} : std::string_view(result.GetString(5)));
    summary.mitreMappingSummary = result.IsNull(6) ? std::string{} : result.GetString(6);
    summary.generatedAt = FromUnixMilliseconds(result.GetInt64(7));

    {
        std::unique_lock lock(mutex);
        summaryCache[summary.storylineId] = summary;
    }

    return summary;
}

IncidentSummarizer& IncidentSummarizer::Instance() {
    static IncidentSummarizer instance;
    return instance;
}

bool IncidentSummarizer::HasInstance() noexcept {
    return Instance().IsInitialized();
}

IncidentSummarizer::IncidentSummarizer()
    : m_impl(std::make_unique<IncidentSummarizerImpl>()) {
}

IncidentSummarizer::~IncidentSummarizer() {
    Shutdown();
}

bool IncidentSummarizer::Initialize() {
    return m_impl->Initialize();
}

void IncidentSummarizer::Shutdown() {
    m_impl->Shutdown();
}

bool IncidentSummarizer::IsInitialized() const noexcept {
    return m_impl->initialized.load(std::memory_order_acquire);
}

IncidentSummary IncidentSummarizer::SummarizeStoryline(const Storyline& sl, const SummaryLevel level) {
    return m_impl->SummarizeStoryline(sl, level);
}

IncidentSummary IncidentSummarizer::SummarizeCorrelationMatch(const CorrelationMatch& match,
                                                              const std::vector<XDREvent>& events,
                                                              const SummaryLevel level) {
    return m_impl->SummarizeCorrelationMatch(match, events, level);
}

std::string IncidentSummarizer::GenerateExecutiveBrief(const std::vector<IncidentSummary>& summaries) const {
    return m_impl->GenerateExecutiveBrief(summaries);
}

std::optional<IncidentSummary> IncidentSummarizer::GetCachedSummary(std::string_view storylineId) const {
    return m_impl->GetCachedSummary(storylineId);
}

} // namespace ShadowStrike::Products::PhantomXDR::AIAssistant
