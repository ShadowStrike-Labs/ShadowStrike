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
#include "Products/Community/PhantomXDR/AIAssistant/QueryTranslator.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::AIAssistant {

namespace {

constexpr const char* kLogPrefix = "[XDR::AIAssistant::QueryTranslator]";
constexpr uint32_t    kDefaultHistoryLimit = 100;
constexpr uint32_t    kMaxHistoryLimit     = 1000;

using Clock = std::chrono::system_clock;
using DB    = ShadowStrike::Database::DatabaseManager;
using DBErr = ShadowStrike::Database::DatabaseError;
namespace SU = ShadowStrike::Utils::StringUtils;
using ShadowStrike::Utils::Logger;

struct QueryPattern final {
    std::string              name;
    std::vector<std::string> triggers;
    std::string              ssqlTemplate;
    std::string              kqlTemplate;
    std::string              sigmaCategory;
    std::vector<std::string> sigmaIndicators;
    std::string              explanation;
    double                   baseConfidence{0.0};
};

[[nodiscard]] int64_t ToUnixMilliseconds(const TimePoint timePoint) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch()).count();
}

[[nodiscard]] std::string NormalizeText(std::string_view text) {
    std::string normalized;
    normalized.reserve(text.size());

    bool previousWasSpace = true;
    for (const unsigned char ch : text) {
        if (std::isalnum(ch) != 0) {
            normalized.push_back(static_cast<char>(std::tolower(ch)));
            previousWasSpace = false;
        } else if (!previousWasSpace) {
            normalized.push_back(' ');
            previousWasSpace = true;
        }
    }

    while (!normalized.empty() && normalized.back() == ' ') {
        normalized.pop_back();
    }

    return normalized;
}

[[nodiscard]] bool ContainsPhrase(const std::string& normalizedText, const std::string& trigger) {
    return !trigger.empty() && normalizedText.find(trigger) != std::string::npos;
}

[[nodiscard]] std::string GenerateQueryId() {
    static std::atomic<uint64_t> sequence{0};
    return std::format("XDRQ-{:X}-{:04X}",
                       static_cast<uint64_t>(Clock::now().time_since_epoch().count()),
                       sequence.fetch_add(1, std::memory_order_relaxed) & 0xFFFFULL);
}

[[nodiscard]] const char* QueryLanguageToString(const QueryLanguage language) noexcept {
    switch (language) {
        case QueryLanguage::Natural: return "Natural";
        case QueryLanguage::SSQL:    return "SSQL";
        case QueryLanguage::KQL:     return "KQL";
        case QueryLanguage::Sigma:   return "Sigma";
    }
    return "Natural";
}

[[nodiscard]] QueryLanguage QueryLanguageFromInt(const int value) noexcept {
    switch (value) {
        case 1: return QueryLanguage::SSQL;
        case 2: return QueryLanguage::KQL;
        case 3: return QueryLanguage::Sigma;
        default: return QueryLanguage::Natural;
    }
}

[[nodiscard]] std::string BuildSigmaRule(const QueryPattern& pattern, std::string_view naturalLanguage) {
    std::string detectionList;
    for (size_t index = 0; index < pattern.sigmaIndicators.size(); ++index) {
        detectionList += std::format("        - '{}'\n", pattern.sigmaIndicators[index]);
    }

    return std::format(
        "title: {}\n"
        "id: {}\n"
        "status: stable\n"
        "description: Generated from analyst request: {}\n"
        "logsource:\n"
        "    product: shadowstrike\n"
        "    category: {}\n"
        "detection:\n"
        "    selection:\n"
        "        keywords:\n"
        "{}"
        "    condition: selection\n"
        "fields:\n"
        "    - user\n"
        "    - host\n"
        "    - process\n"
        "falsepositives:\n"
        "    - Administrative activity\n"
        "level: high\n",
        pattern.name,
        pattern.name.empty() ? "xdr-generated-rule" : pattern.name,
        std::string(naturalLanguage),
        pattern.sigmaCategory,
        detectionList);
}

[[nodiscard]] const std::vector<QueryPattern>& GetPatterns() {
    static const std::vector<QueryPattern> kPatterns{
        {
            "Processes By Admin",
            { "show me processes by admin", "processes by admin", "admin processes" },
            "SELECT * FROM processes WHERE user = 'admin' ORDER BY timestamp DESC LIMIT 250;",
            "DeviceProcessEvents | where AccountName =~ 'admin' | sort by Timestamp desc | take 250",
            "process_creation",
            { "admin", "process_create" },
            "Maps direct administrator process review requests to process telemetry filtered on the admin account.",
            0.97
        },
        {
            "Suspicious DNS Queries",
            { "find dns queries to suspicious domains", "dns queries to suspicious domains", "suspicious dns domains" },
            "SELECT * FROM dns_events WHERE (is_newly_observed = 1 OR domain_entropy >= 3.8 OR reputation = 'suspicious') AND query_type IN ('A', 'AAAA', 'TXT') ORDER BY timestamp DESC LIMIT 500;",
            "DnsEvents | where QueryType in~ ('A','AAAA','TXT') and (DomainEntropy >= 3.8 or Reputation =~ 'suspicious' or IsNewlyObserved == true) | sort by Timestamp desc | take 500",
            "dns",
            { "dns", "high entropy domain", "newly observed domain" },
            "Targets DNS activity indicative of DGAs or suspicious first-seen domains using entropy and reputation guardrails.",
            0.98
        },
        {
            "Failed Logins Last Hour",
            { "show failed logins in the last hour", "failed logins last hour", "login failures last hour" },
            "SELECT * FROM identity_events WHERE event_type = 'login_failure' AND timestamp >= datetime('now', '-1 hour') ORDER BY timestamp DESC LIMIT 500;",
            "IdentityLogonEvents | where ActionType =~ 'LogonFailed' and Timestamp >= ago(1h) | sort by Timestamp desc | take 500",
            "authentication",
            { "logon failed", "authentication failure" },
            "Builds an identity-centric query scoped to the last hour of failed authentication activity.",
            0.98
        },
        {
            "Lateral Movement Hunt",
            { "find lateral movement", "hunt lateral movement", "lateral movement activity" },
            "SELECT n.*, i.user_name, i.host_name FROM network_events n JOIN identity_events i ON n.session_id = i.session_id WHERE (n.remote_port IN (135, 139, 445, 3389, 5985, 5986) OR n.protocol IN ('SMB', 'RDP', 'WINRM')) AND i.event_type IN ('remote_logon', 'privileged_logon') ORDER BY n.timestamp DESC LIMIT 500;",
            "DeviceNetworkEvents | where RemotePort in (135,139,445,3389,5985,5986) or Protocol in~ ('SMB','RDP','WINRM') | join kind=inner (IdentityLogonEvents | where ActionType in~ ('RemoteLogon','PrivilegedLogon')) on SessionId | sort by Timestamp desc | take 500",
            "network_connection",
            { "smb", "rdp", "winrm", "remote logon" },
            "Correlates identity and network telemetry to surface common east-west movement techniques.",
            0.99
        },
        {
            "PowerShell Downloads",
            { "powershell downloads", "powershell download cradle", "download via powershell" },
            "SELECT * FROM process_events WHERE process_name = 'powershell.exe' AND command_line LIKE '%DownloadString%' OR command_line LIKE '%Invoke-WebRequest%' ORDER BY timestamp DESC LIMIT 250;",
            "DeviceProcessEvents | where FileName =~ 'powershell.exe' and (ProcessCommandLine has 'DownloadString' or ProcessCommandLine has 'Invoke-WebRequest') | sort by Timestamp desc | take 250",
            "process_creation",
            { "powershell.exe", "downloadstring", "invoke-webrequest" },
            "Focuses on download cradles frequently used for payload staging and in-memory execution.",
            0.94
        },
        {
            "Encoded PowerShell",
            { "encoded powershell", "powershell encodedcommand", "base64 powershell" },
            "SELECT * FROM process_events WHERE process_name = 'powershell.exe' AND (command_line LIKE '%-enc%' OR command_line LIKE '%-encodedcommand%') ORDER BY timestamp DESC LIMIT 250;",
            "DeviceProcessEvents | where FileName =~ 'powershell.exe' and (ProcessCommandLine has '-enc' or ProcessCommandLine has '-encodedcommand') | sort by Timestamp desc | take 250",
            "process_creation",
            { "powershell.exe", "-enc", "-encodedcommand" },
            "Identifies obfuscated PowerShell execution through encoded command switches.",
            0.95
        },
        {
            "Rundll32 Abuse",
            { "suspicious rundll32", "rundll32 abuse", "rundll32 suspicious command line" },
            "SELECT * FROM process_events WHERE process_name = 'rundll32.exe' AND (command_line LIKE '%.dll,%' OR command_line LIKE '%javascript:%' OR command_line LIKE '%http%') ORDER BY timestamp DESC LIMIT 250;",
            "DeviceProcessEvents | where FileName =~ 'rundll32.exe' and (ProcessCommandLine has '.dll,' or ProcessCommandLine has 'javascript:' or ProcessCommandLine has 'http') | sort by Timestamp desc | take 250",
            "process_creation",
            { "rundll32.exe", "javascript:", ".dll," },
            "Surfaces suspicious rundll32 invocation patterns associated with LOLBIN abuse.",
            0.93
        },
        {
            "Credential Dumping",
            { "credential dumping", "lsass access", "dump credentials" },
            "SELECT * FROM process_events WHERE (target_process = 'lsass.exe' OR command_line LIKE '%sekurlsa%' OR command_line LIKE '%MiniDumpWriteDump%') ORDER BY timestamp DESC LIMIT 250;",
            "DeviceProcessEvents | where InitiatingProcessCommandLine has_any ('sekurlsa','MiniDumpWriteDump') or TargetProcessName =~ 'lsass.exe' | sort by Timestamp desc | take 250",
            "process_access",
            { "lsass.exe", "sekurlsa", "MiniDumpWriteDump" },
            "Looks for credential dumping indicators against LSASS and known dumping primitives.",
            0.97
        },
        {
            "Process Injection",
            { "process injection", "inject into process", "suspicious memory injection" },
            "SELECT * FROM memory_events WHERE event_type IN ('process_injection', 'remote_thread_create', 'reflective_load') ORDER BY timestamp DESC LIMIT 250;",
            "DeviceEvents | where ActionType in~ ('ProcessInjection','RemoteThreadCreated','ReflectiveLoad') | sort by Timestamp desc | take 250",
            "process_access",
            { "process injection", "remote thread", "reflective load" },
            "Maps common memory-manipulation signals to process injection telemetry.",
            0.96
        },
        {
            "Suspicious Service Installs",
            { "suspicious service installs", "new malicious service", "service installation" },
            "SELECT * FROM service_events WHERE event_type = 'service_install' AND (image_path LIKE '%AppData%' OR image_path LIKE '%Temp%' OR start_type = 'auto') ORDER BY timestamp DESC LIMIT 250;",
            "DeviceEvents | where ActionType =~ 'ServiceInstalled' and (AdditionalFields has 'AppData' or AdditionalFields has 'Temp' or ServiceStartType =~ 'Auto') | sort by Timestamp desc | take 250",
            "service",
            { "service installed", "appdata", "temp" },
            "Finds newly installed services with suspicious persistence-oriented image paths or startup behavior.",
            0.92
        },
        {
            "Scheduled Task Persistence",
            { "scheduled task persistence", "malicious scheduled tasks", "suspicious scheduled task" },
            "SELECT * FROM scheduler_events WHERE event_type IN ('task_created', 'task_updated') AND (task_command LIKE '%powershell%' OR task_command LIKE '%cmd.exe%' OR run_level = 'highest') ORDER BY timestamp DESC LIMIT 250;",
            "DeviceScheduledTaskEvents | where ActionType in~ ('TaskCreated','TaskUpdated') and (TaskCommand has 'powershell' or TaskCommand has 'cmd.exe' or RunLevel =~ 'Highest') | sort by Timestamp desc | take 250",
            "scheduled_task",
            { "task created", "powershell", "run level highest" },
            "Focuses on scheduled-task persistence using scripting engines or elevated run levels.",
            0.93
        },
        {
            "Registry Autoruns",
            { "registry autoruns", "autorun registry changes", "persistence registry key" },
            "SELECT * FROM registry_events WHERE registry_path LIKE 'HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run%' OR registry_path LIKE 'HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run%' ORDER BY timestamp DESC LIMIT 250;",
            "DeviceRegistryEvents | where RegistryKey has_any ('\\\\CurrentVersion\\\\Run', '\\\\CurrentVersion\\\\RunOnce') | sort by Timestamp desc | take 250",
            "registry_set",
            { "currentversion\\run", "currentversion\\runonce" },
            "Captures common autorun persistence modifications in user and machine run keys.",
            0.94
        },
        {
            "Beaconing Traffic",
            { "beaconing traffic", "c2 beaconing", "periodic network beacon" },
            "SELECT * FROM network_events WHERE periodicity_score >= 0.85 AND bytes_out > 0 AND destination_reputation <> 'trusted' ORDER BY timestamp DESC LIMIT 250;",
            "DeviceNetworkEvents | where PeriodicityScore >= 0.85 and SentBytes > 0 and RemoteUrlCategory !in~ ('Trusted') | sort by Timestamp desc | take 250",
            "network_connection",
            { "periodic outbound", "untrusted destination" },
            "Hunts for low-volume periodic network callbacks consistent with beaconing.",
            0.95
        },
        {
            "Rare Outbound Connections",
            { "rare outbound connections", "unusual outbound traffic", "rare external connections" },
            "SELECT * FROM network_events WHERE is_rare_destination = 1 AND direction = 'outbound' ORDER BY timestamp DESC LIMIT 250;",
            "DeviceNetworkEvents | where Direction =~ 'Outbound' and IsRareDestination == true | sort by Timestamp desc | take 250",
            "network_connection",
            { "rare destination", "outbound connection" },
            "Identifies outbound communications to destinations not commonly observed in the environment.",
            0.91
        },
        {
            "SMB Brute Force",
            { "smb brute force", "multiple smb failures", "brute force over smb" },
            "SELECT * FROM identity_events WHERE event_type = 'login_failure' AND protocol = 'SMB' GROUP BY source_ip, target_host HAVING COUNT(*) >= 5 ORDER BY MAX(timestamp) DESC LIMIT 100;",
            "IdentityLogonEvents | where ActionType =~ 'LogonFailed' and Protocol =~ 'SMB' | summarize Failures=count(), LastSeen=max(Timestamp) by SourceIp, TargetDeviceName | where Failures >= 5 | sort by LastSeen desc | take 100",
            "authentication",
            { "smb", "logon failed" },
            "Aggregates repeated SMB login failures that commonly precede password spraying or brute force activity.",
            0.95
        },
        {
            "Privilege Escalation",
            { "privilege escalation", "elevated token abuse", "uac bypass" },
            "SELECT * FROM privilege_events WHERE event_type IN ('token_elevation', 'uac_bypass', 'se_debug_enabled') ORDER BY timestamp DESC LIMIT 250;",
            "DeviceEvents | where ActionType in~ ('TokenElevation','UacBypass','SeDebugPrivilegeEnabled') | sort by Timestamp desc | take 250",
            "privilege_escalation",
            { "token elevation", "uac bypass", "sedebug" },
            "Maps analyst requests to high-signal privilege escalation telemetry.",
            0.94
        },
        {
            "PsExec Remote Execution",
            { "psexec remote execution", "psexec activity", "remote execution via psexec" },
            "SELECT * FROM process_events WHERE process_name IN ('psexec.exe', 'psexesvc.exe') OR service_name = 'PSEXESVC' ORDER BY timestamp DESC LIMIT 250;",
            "DeviceProcessEvents | where FileName in~ ('psexec.exe','psexesvc.exe') or InitiatingProcessCommandLine has 'PSEXESVC' | sort by Timestamp desc | take 250",
            "process_creation",
            { "psexec.exe", "psexesvc.exe", "PSEXESVC" },
            "Hunts for PsExec-based remote execution artifacts and service deployment.",
            0.96
        },
        {
            "Suspicious WMI",
            { "suspicious wmi activity", "wmi remote execution", "wmic abuse" },
            "SELECT * FROM process_events WHERE process_name IN ('wmic.exe', 'WmiPrvSE.exe') AND (command_line LIKE '%process call create%' OR parent_process = 'WmiPrvSE.exe') ORDER BY timestamp DESC LIMIT 250;",
            "DeviceProcessEvents | where FileName in~ ('wmic.exe','WmiPrvSE.exe') and (ProcessCommandLine has 'process call create' or InitiatingProcessFileName =~ 'WmiPrvSE.exe') | sort by Timestamp desc | take 250",
            "wmi",
            { "wmic.exe", "wmiprvse.exe", "process call create" },
            "Surfaces remote-execution and process-spawning patterns tied to WMI abuse.",
            0.94
        },
        {
            "Office Child Processes",
            { "office spawning child processes", "suspicious child processes of office", "office macro execution" },
            "SELECT * FROM process_events WHERE parent_process IN ('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe') AND process_name IN ('cmd.exe', 'powershell.exe', 'wscript.exe', 'mshta.exe') ORDER BY timestamp DESC LIMIT 250;",
            "DeviceProcessEvents | where InitiatingProcessFileName in~ ('winword.exe','excel.exe','powerpnt.exe','outlook.exe') and FileName in~ ('cmd.exe','powershell.exe','wscript.exe','mshta.exe') | sort by Timestamp desc | take 250",
            "process_creation",
            { "winword.exe", "powershell.exe", "mshta.exe" },
            "Detects Office-to-script or Office-to-shell child-process chains frequently driven by malicious documents.",
            0.97
        },
        {
            "Large Data Exfiltration",
            { "large data exfiltration", "data exfiltration", "bulk outbound transfer" },
            "SELECT * FROM network_events WHERE direction = 'outbound' AND bytes_out >= 104857600 AND destination_reputation <> 'trusted' ORDER BY timestamp DESC LIMIT 250;",
            "DeviceNetworkEvents | where Direction =~ 'Outbound' and SentBytes >= 104857600 and RemoteUrlCategory !in~ ('Trusted') | sort by Timestamp desc | take 250",
            "network_connection",
            { "outbound", "large transfer", "untrusted destination" },
            "Targets high-volume outbound transfers to untrusted infrastructure for exfiltration review.",
            0.95
        },
        {
            "Ransomware Behaviors",
            { "ransomware behavior", "mass file encryption", "ransomware activity" },
            "SELECT * FROM file_events WHERE (rename_rate_per_min >= 200 OR entropy_after_write >= 7.2 OR extension IN ('.locked', '.encrypted', '.crypt')) ORDER BY timestamp DESC LIMIT 250;",
            "DeviceFileEvents | where RenameRatePerMinute >= 200 or EntropyAfterWrite >= 7.2 or FileName endswith '.locked' or FileName endswith '.encrypted' or FileName endswith '.crypt' | sort by Timestamp desc | take 250",
            "file_event",
            { ".locked", ".encrypted", "high entropy write" },
            "Highlights high-rate rename and encryption signals aligned with ransomware execution.",
            0.98
        },
        {
            "Unsigned System32 Binaries",
            { "unsigned binaries in system32", "unsigned system32 executable", "unsigned binary under system32" },
            "SELECT * FROM file_events WHERE file_path LIKE 'C:\\\\Windows\\\\System32\\\\%' AND signer_status = 'unsigned' ORDER BY timestamp DESC LIMIT 250;",
            "DeviceFileEvents | where FolderPath startswith 'C:\\\\Windows\\\\System32\\\\' and Signer =~ 'Unsigned' | sort by Timestamp desc | take 250",
            "file_event",
            { "system32", "unsigned" },
            "Finds unsigned executables or DLLs placed in System32, a strong persistence and masquerading signal.",
            0.92
        },
        {
            "Admin Group Changes",
            { "admin group changes", "added to administrators group", "unusual admin group changes" },
            "SELECT * FROM identity_events WHERE event_type IN ('group_member_added', 'group_member_removed') AND target_group IN ('Administrators', 'Domain Admins', 'Enterprise Admins') ORDER BY timestamp DESC LIMIT 250;",
            "IdentityDirectoryEvents | where ActionType in~ ('GroupMemberAdded','GroupMemberRemoved') and TargetGroupName in~ ('Administrators','Domain Admins','Enterprise Admins') | sort by Timestamp desc | take 250",
            "iam",
            { "group member added", "administrators", "domain admins" },
            "Tracks privilege-bearing directory group membership changes requiring rapid review.",
            0.96
        },
        {
            "New Local Admins",
            { "new local admins", "newly created local admins", "local administrator account created" },
            "SELECT * FROM identity_events WHERE event_type = 'user_created' AND assigned_groups LIKE '%Administrators%' ORDER BY timestamp DESC LIMIT 250;",
            "IdentityDirectoryEvents | where ActionType =~ 'UserCreated' and AssignedGroups has 'Administrators' | sort by Timestamp desc | take 250",
            "iam",
            { "user created", "administrators" },
            "Surfaces creation of new accounts immediately granted local administrator privileges.",
            0.94
        },
        {
            "Cloud OAuth Consent Abuse",
            { "oauth consent abuse", "suspicious oauth app consent", "malicious oauth grant" },
            "SELECT * FROM cloud_events WHERE event_type = 'oauth_consent_granted' AND (scope LIKE '%offline_access%' OR scope LIKE '%mail.read%' OR app_reputation = 'unknown') ORDER BY timestamp DESC LIMIT 250;",
            "CloudAppEvents | where ActionType =~ 'OAuthConsentGranted' and (Scopes has 'offline_access' or Scopes has 'mail.read' or AppReputation =~ 'Unknown') | sort by Timestamp desc | take 250",
            "cloud",
            { "oauth consent granted", "offline_access", "unknown app" },
            "Targets cloud application consent grants that can enable persistent mailbox or API access.",
            0.90
        }
    };

    return kPatterns;
}

} // anonymous namespace

class QueryTranslatorImpl final {
public:
    std::atomic<bool>         initialized{false};
    mutable std::shared_mutex mutex;
    std::vector<HuntQuery>    recentTranslations;

    [[nodiscard]] bool Initialize();
    void               Shutdown();
    [[nodiscard]] bool CreateSchema() const;
    [[nodiscard]] std::optional<HuntQuery> Translate(std::string_view naturalLanguage, QueryLanguage targetLanguage);
    [[nodiscard]] std::vector<HuntQuery>   GetTranslationHistory(uint32_t limit) const;

private:
    void PersistTranslation(const HuntQuery& query);
    void CacheTranslation(const HuntQuery& query);
};

[[nodiscard]] bool QueryTranslatorImpl::CreateSchema() const {
    auto& db = DB::Instance();
    DBErr err;

    constexpr std::string_view kSchema = R"SQL(
        CREATE TABLE IF NOT EXISTS xdr_query_translations (
            query_id           TEXT PRIMARY KEY,
            natural_language   TEXT NOT NULL,
            translated_query   TEXT NOT NULL,
            target_lang        INTEGER NOT NULL,
            confidence         REAL NOT NULL,
            explanation        TEXT DEFAULT '',
            created_at_ms      INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_xdr_query_translation_time
            ON xdr_query_translations(created_at_ms DESC);
        CREATE INDEX IF NOT EXISTS idx_xdr_query_translation_lang
            ON xdr_query_translations(target_lang);
    )SQL";

    if (!db.Execute(kSchema, &err)) {
        Logger::Error("{} Failed to create translation schema: {}",
                      kLogPrefix, SU::ToNarrow(err.message));
        return false;
    }

    return true;
}

[[nodiscard]] bool QueryTranslatorImpl::Initialize() {
    if (initialized.load(std::memory_order_acquire)) {
        return true;
    }

    Logger::Info("{} Initializing query translator...", kLogPrefix);

    if (!CreateSchema()) {
        return false;
    }

    initialized.store(true, std::memory_order_release);
    Logger::Info("{} Query translator initialized with {} hunt templates",
                 kLogPrefix, GetPatterns().size());
    return true;
}

void QueryTranslatorImpl::Shutdown() {
    if (!initialized.exchange(false, std::memory_order_acq_rel)) {
        return;
    }

    std::unique_lock lock(mutex);
    Logger::Info("{} Query translator shut down after caching {} translations",
                 kLogPrefix, recentTranslations.size());
    recentTranslations.clear();
}

void QueryTranslatorImpl::CacheTranslation(const HuntQuery& query) {
    std::unique_lock lock(mutex);
    recentTranslations.insert(recentTranslations.begin(), query);
    if (recentTranslations.size() > kMaxHistoryLimit) {
        recentTranslations.resize(kMaxHistoryLimit);
    }
}

void QueryTranslatorImpl::PersistTranslation(const HuntQuery& query) {
    auto& db = DB::Instance();
    DBErr err;

    const bool persisted = db.ExecuteWithParams(
        "INSERT INTO xdr_query_translations "
        "(query_id, natural_language, translated_query, target_lang, confidence, explanation, created_at_ms) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        &err,
        query.queryId,
        query.naturalLanguage,
        query.translatedQuery,
        static_cast<int>(query.targetLang),
        query.confidence,
        query.explanation,
        ToUnixMilliseconds(Clock::now()));

    if (!persisted) {
        Logger::Warn("{} Failed to persist translation '{}': {}",
                     kLogPrefix, query.queryId, SU::ToNarrow(err.message));
    }
}

[[nodiscard]] std::optional<HuntQuery> QueryTranslatorImpl::Translate(std::string_view naturalLanguage,
                                                                      const QueryLanguage targetLanguage) {
    if (!initialized.load(std::memory_order_acquire)) {
        Logger::Warn("{} Translate requested before initialization", kLogPrefix);
        return std::nullopt;
    }

    const std::string normalized = NormalizeText(naturalLanguage);
    if (normalized.empty()) {
        return std::nullopt;
    }

    const QueryPattern* bestPattern = nullptr;
    size_t bestMatches = 0;
    double bestScore = 0.0;

    for (const auto& pattern : GetPatterns()) {
        size_t matches = 0;
        for (const auto& trigger : pattern.triggers) {
            if (ContainsPhrase(normalized, trigger)) {
                ++matches;
            }
        }

        if (matches == 0) {
            continue;
        }

        const double score = pattern.baseConfidence + static_cast<double>(matches - 1) * 0.02;
        if (matches > bestMatches || (matches == bestMatches && score > bestScore)) {
            bestPattern = &pattern;
            bestMatches = matches;
            bestScore = score;
        }
    }

    if (bestPattern == nullptr) {
        Logger::Debug("{} No translation template matched '{}'", kLogPrefix, std::string(naturalLanguage));
        return std::nullopt;
    }

    HuntQuery query;
    query.queryId = GenerateQueryId();
    query.naturalLanguage = std::string(naturalLanguage);
    query.targetLang = targetLanguage;
    query.confidence = std::min(0.995, bestScore);
    query.explanation = std::format("{} Matched template '{}' using {} trigger(s); emitting {} output.",
                                    bestPattern->explanation,
                                    bestPattern->name,
                                    bestMatches,
                                    QueryLanguageToString(targetLanguage));

    switch (targetLanguage) {
        case QueryLanguage::SSQL:
            query.translatedQuery = bestPattern->ssqlTemplate;
            break;
        case QueryLanguage::KQL:
            query.translatedQuery = bestPattern->kqlTemplate;
            break;
        case QueryLanguage::Sigma:
            query.translatedQuery = BuildSigmaRule(*bestPattern, naturalLanguage);
            break;
        case QueryLanguage::Natural:
        default:
            query.translatedQuery = std::string(naturalLanguage);
            break;
    }

    CacheTranslation(query);
    PersistTranslation(query);

    Logger::Info("{} Translated query '{}' to {} with confidence {:.2f}",
                 kLogPrefix, query.queryId, QueryLanguageToString(targetLanguage), query.confidence);
    return query;
}

[[nodiscard]] std::vector<HuntQuery> QueryTranslatorImpl::GetTranslationHistory(const uint32_t limit) const {
    const uint32_t boundedLimit = std::clamp(limit == 0 ? kDefaultHistoryLimit : limit, 1U, kMaxHistoryLimit);

    auto& db = DB::Instance();
    DBErr err;
    auto result = db.QueryWithParams(
        "SELECT query_id, natural_language, translated_query, target_lang, confidence, explanation "
        "FROM xdr_query_translations ORDER BY created_at_ms DESC LIMIT ?",
        &err,
        static_cast<int>(boundedLimit));

    if (err.HasError()) {
        Logger::Warn("{} Failed to read translation history: {}",
                     kLogPrefix, SU::ToNarrow(err.message));
        std::shared_lock lock(mutex);
        const size_t fallbackCount = std::min(recentTranslations.size(), static_cast<size_t>(boundedLimit));
        return std::vector<HuntQuery>(recentTranslations.begin(),
                                      recentTranslations.begin() + fallbackCount);
    }

    std::vector<HuntQuery> history;
    history.reserve(boundedLimit);
    while (result.Next()) {
        HuntQuery query;
        query.queryId = result.GetString(0);
        query.naturalLanguage = result.GetString(1);
        query.translatedQuery = result.GetString(2);
        query.targetLang = QueryLanguageFromInt(result.GetInt(3));
        query.confidence = result.GetDouble(4);
        query.explanation = result.IsNull(5) ? std::string{} : result.GetString(5);
        history.push_back(std::move(query));
    }

    return history;
}

QueryTranslator& QueryTranslator::Instance() {
    static QueryTranslator instance;
    return instance;
}

bool QueryTranslator::HasInstance() noexcept {
    return Instance().IsInitialized();
}

QueryTranslator::QueryTranslator()
    : m_impl(std::make_unique<QueryTranslatorImpl>()) {
}

QueryTranslator::~QueryTranslator() {
    Shutdown();
}

bool QueryTranslator::Initialize() {
    return m_impl->Initialize();
}

void QueryTranslator::Shutdown() {
    m_impl->Shutdown();
}

bool QueryTranslator::IsInitialized() const noexcept {
    return m_impl->initialized.load(std::memory_order_acquire);
}

std::optional<HuntQuery> QueryTranslator::TranslateToSSQL(std::string_view naturalLanguage) {
    return m_impl->Translate(naturalLanguage, QueryLanguage::SSQL);
}

std::optional<HuntQuery> QueryTranslator::TranslateToKQL(std::string_view naturalLanguage) {
    return m_impl->Translate(naturalLanguage, QueryLanguage::KQL);
}

std::optional<HuntQuery> QueryTranslator::TranslateToSigma(std::string_view naturalLanguage) {
    return m_impl->Translate(naturalLanguage, QueryLanguage::Sigma);
}

std::vector<HuntQuery> QueryTranslator::GetTranslationHistory(const uint32_t limit) const {
    return m_impl->GetTranslationHistory(limit);
}

} // namespace ShadowStrike::Products::PhantomXDR::AIAssistant
