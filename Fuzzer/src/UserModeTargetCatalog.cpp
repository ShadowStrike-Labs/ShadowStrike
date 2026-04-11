#include "ShadowStrike/Fuzzer/Targets/UserModeTargetCatalog.hpp"

#include "ShadowStrike/Fuzzer/Core/AttackSurface.hpp"

#include <algorithm>
#include <sstream>
#include <string_view>

namespace ShadowStrike::Fuzzer {

namespace {

[[nodiscard]] std::string EscapeJson(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size() + 8);

    for (const char ch : value) {
        switch (ch) {
        case '\\': escaped += "\\\\"; break;
        case '"': escaped += "\\\""; break;
        case '\b': escaped += "\\b"; break;
        case '\f': escaped += "\\f"; break;
        case '\n': escaped += "\\n"; break;
        case '\r': escaped += "\\r"; break;
        case '\t': escaped += "\\t"; break;
        default:
            escaped.push_back(ch);
            break;
        }
    }

    return escaped;
}

void RenderStringArray(std::ostringstream& stream,
    std::string_view name,
    const std::vector<std::string>& values,
    std::string_view indent)
{
    stream << indent << '"' << name << "\": [";
    if (!values.empty()) {
        stream << '\n';
        for (std::size_t index = 0; index < values.size(); ++index) {
            stream << indent << "  \"" << EscapeJson(values[index]) << '"';
            if (index + 1 != values.size()) {
                stream << ',';
            }
            stream << '\n';
        }
        stream << indent;
    }
    stream << ']';
}

[[nodiscard]] UserModeCampaign MakeCampaign(
    std::string id,
    std::string targetId,
    std::string name,
    const UserModeCampaignType type,
    std::string harness,
    std::string objective,
    std::vector<std::string> seedSources,
    std::vector<std::string> mutationAxes,
    std::vector<std::string> invariants,
    std::vector<std::string> telemetry)
{
    return UserModeCampaign{
        std::move(id),
        std::move(targetId),
        std::move(name),
        type,
        std::move(harness),
        std::move(objective),
        std::move(seedSources),
        std::move(mutationAxes),
        std::move(invariants),
        std::move(telemetry)
    };
}

[[nodiscard]] std::vector<UserModeTargetDescriptor> BuildTargets() {
    std::vector<UserModeTargetDescriptor> targets;
    targets.reserve(4);

    targets.push_back(UserModeTargetDescriptor{
        "phantomcore.usermode.filter-port-client",
        "phantomcore.ipc.filter-port-client",
        "PhantomCore",
        UserModeExecutionKind::BrokerProcess,
        "Kernel-to-user filter-port client session handling in FilterConnection and IPCManager.",
        {
            "Run the broker in a process-isolated worker with deterministic reconnect logic.",
            "Capture user-mode dumps and ETW traces for disconnects, timeouts, and crypto failures."
        },
        {
            "Tear down the worker process after any key-exchange or reply-correlation fault.",
            "Never reuse session keys across replay attempts."
        },
        {
            MakeCampaign(
                "phantomcore.filter-port.key-exchange",
                "phantomcore.usermode.filter-port-client",
                "Key exchange resilience",
                UserModeCampaignType::SessionProtocol,
                "FilterConnection handshake harness",
                "Validate that malformed key-exchange and encrypted message sequences fail explicitly without deadlock or key reuse.",
                { "key-exchange-inbound-baseline.bin", "kernel-variants\\key-exchange-missing-encrypted-flag.bin", "kernel-variants\\key-exchange-zero-tag.bin" },
                { "auth-tag corruption", "nonce prefix skew", "missing encrypted flag", "message-id mismatch" },
                { "No deadlock on disconnect.", "Rejected key exchange must zeroize session material.", "Reply state must remain synchronized." },
                { "handshake latency", "disconnect reason", "heap corruption signal" }),
            MakeCampaign(
                "phantomcore.filter-port.async-cancel",
                "phantomcore.usermode.filter-port-client",
                "Async cancellation races",
                UserModeCampaignType::AsyncStress,
                "FilterConnection overlapped I/O harness",
                "Stress cancellation, reconnect, and reply-correlation races around asynchronous filter-port traffic.",
                { "register-baseline.bin", "heartbeat-baseline.bin", "query-driver-status-baseline.bin" },
                { "disconnect while awaiting reply", "duplicate message ids", "late reply after cancel", "concurrent shutdown" },
                { "Cancellation must not leak handles.", "Late replies must not resurrect freed state.", "Reconnect path must reinitialize callbacks cleanly." },
                { "cancel-to-teardown latency", "handle count delta", "reconnect success rate" })
        }
    });

    targets.push_back(UserModeTargetDescriptor{
        "phantomcore.usermode.named-pipe-broker",
        "phantomcore.ipc.named-pipe-broker",
        "PhantomCore",
        UserModeExecutionKind::BrokerProcess,
        "Privileged local named-pipe broker and authentication/session management path in ServiceCommunication.",
        {
            "Start the broker under a non-interactive test account with explicit ACL auditing.",
            "Capture named-pipe connection logs and worker restart telemetry."
        },
        {
            "Recycle the worker after any malformed authentication frame that reaches command dispatch.",
            "Bound concurrent clients to avoid masking correctness defects with resource exhaustion."
        },
        {
            MakeCampaign(
                "phantomcore.named-pipe.auth-fragmentation",
                "phantomcore.usermode.named-pipe-broker",
                "Authentication fragmentation",
                UserModeCampaignType::SessionProtocol,
                "ServiceCommunication pipe harness",
                "Exercise fragmented and reordered handshake frames to verify unauthorized clients never reach privileged command handling.",
                { "synthetic named-pipe handshake corpus", "split-token session frames" },
                { "frame fragmentation", "pipe squatting attempts", "auth token truncation", "out-of-order control messages" },
                { "Unauthorized clients must fail before command dispatch.", "Listener remains live after malformed sessions." },
                { "auth failure code", "listener uptime", "client disconnect count" }),
            MakeCampaign(
                "phantomcore.named-pipe.client-churn",
                "phantomcore.usermode.named-pipe-broker",
                "Client churn under overlapped I/O",
                UserModeCampaignType::AsyncStress,
                "ServiceCommunication churn harness",
                "Stress max-client handling, overlapped teardown, and rapid reconnect storms.",
                { "synthetic pipe session corpus" },
                { "rapid connect-disconnect", "overlapped read cancellation", "session handle exhaustion", "duplicate client identifiers" },
                { "Max-client limits must hold under churn.", "Listener thread must remain responsive." },
                { "accept backlog", "worker restart count", "peak client count" })
        }
    });

    targets.push_back(UserModeTargetDescriptor{
        "phantomcore.usermode.pe-parser",
        "phantomcore.parser.peparser",
        "PhantomCore",
        UserModeExecutionKind::InProcessParser,
        "PE front-door parsing and validation path in PEParser and PEValidation.",
        {
            "Run under a process-isolated parser harness with page heap and crash dump capture enabled."
        },
        {
            "Quarantine every crashing sample and replay only against a fresh parser worker."
        },
        {
            MakeCampaign(
                "phantomcore.pe-parser.header-boundaries",
                "phantomcore.usermode.pe-parser",
                "Header boundary validation",
                UserModeCampaignType::ParserFrontDoor,
                "PEParser front-door harness",
                "Drive malformed DOS/NT headers, truncated section tables, and directory overlaps through the parser entry points.",
                { "curated PE baseline corpus", "malformed PE boundary corpus" },
                { "header offset overflow", "section count skew", "directory overlap", "resource recursion" },
                { "No integer overflow.", "No out-of-bounds read.", "Failures must be explicit and deterministic." },
                { "parse latency", "exception code", "coverage delta" }),
            MakeCampaign(
                "phantomcore.pe-parser.differential-validation",
                "phantomcore.usermode.pe-parser",
                "Validation differential",
                UserModeCampaignType::DifferentialParsing,
                "PEParser vs PEValidation differential harness",
                "Compare parse and validation outcomes to catch inconsistent normalization or acceptance logic.",
                { "normalized PE corpus", "mutated directory graph corpus" },
                { "normalization skew", "certificate directory corruption", "import recursion" },
                { "Parser and validator must agree on fatal corruption boundaries." },
                { "decision divergence count", "coverage delta", "parse-result consistency" })
        }
    });

    targets.push_back(UserModeTargetDescriptor{
        "phantomcore.usermode.threatintel",
        "phantomcore.parser.threatintel",
        "PhantomCore",
        UserModeExecutionKind::InProcessParser,
        "Threat-intel feed import and normalization pipeline across JSON, XML, and IOC ingestion helpers.",
        {
            "Run the importer with explicit store snapshots so partial imports can be compared against a clean baseline."
        },
        {
            "Reset stores after each malformed feed that reaches commit logic.",
            "Treat silent partial import success as a correctness failure."
        },
        {
            MakeCampaign(
                "phantomcore.threatintel.feed-parsing",
                "phantomcore.usermode.threatintel",
                "Feed parsing front door",
                UserModeCampaignType::ParserFrontDoor,
                "ThreatIntel importer harness",
                "Exercise nested object expansion, malformed URLs/domains, and invalid expiry metadata across importers.",
                { "baseline IOC feed corpus", "malformed JSON/XML feed corpus" },
                { "nested object explosion", "expiry underflow/overflow", "domain normalization skew", "confidence range corruption" },
                { "Invalid feeds fail explicitly.", "No silent partial store corruption." },
                { "import latency", "entries accepted", "entries rejected" }),
            MakeCampaign(
                "phantomcore.threatintel.normalization-stability",
                "phantomcore.usermode.threatintel",
                "Normalization stability",
                UserModeCampaignType::DifferentialParsing,
                "ThreatIntel normalization differential harness",
                "Compare deduplication and normalization output across equivalent but differently encoded feeds.",
                { "equivalent IOC corpus", "encoding variation corpus" },
                { "URL canonicalization skew", "case-folding mismatch", "duplicate feed merging drift" },
                { "Equivalent feeds must converge to identical normalized records." },
                { "deduplication delta", "normalized record count", "decision divergence count" })
        }
    });

    return targets;
}

}  // namespace

std::string_view ToString(const UserModeExecutionKind kind) {
    switch (kind) {
    case UserModeExecutionKind::BrokerProcess:
        return "broker-process";
    case UserModeExecutionKind::InProcessParser:
        return "in-process-parser";
    case UserModeExecutionKind::DifferentialHarness:
        return "differential-harness";
    }

    return "unknown";
}

std::string_view ToString(const UserModeCampaignType type) {
    switch (type) {
    case UserModeCampaignType::SessionProtocol:
        return "session-protocol";
    case UserModeCampaignType::AsyncStress:
        return "async-stress";
    case UserModeCampaignType::ParserFrontDoor:
        return "parser-front-door";
    case UserModeCampaignType::DifferentialParsing:
        return "differential-parsing";
    }

    return "unknown";
}

const std::vector<UserModeTargetDescriptor>& UserModeTargetCatalog::GetDefaultTargets() {
    static const std::vector<UserModeTargetDescriptor> targets = BuildTargets();
    return targets;
}

const UserModeTargetDescriptor* UserModeTargetCatalog::FindById(const std::string_view id) {
    const auto& targets = GetDefaultTargets();
    const auto match = std::find_if(targets.begin(), targets.end(),
        [&](const UserModeTargetDescriptor& target) { return target.id == id; });
    return match == targets.end() ? nullptr : &(*match);
}

std::string UserModeTargetCatalog::DescribeText(const UserModeTargetDescriptor& target) {
    std::ostringstream stream;
    stream << "User-Mode Target: " << target.id << '\n'
           << "Surface: " << target.surfaceId << '\n'
           << "Execution: " << ToString(target.execution) << '\n'
           << "Description: " << target.description << "\n\n"
           << "Campaigns:\n";

    for (const auto& campaign : target.campaigns) {
        stream << "  * " << campaign.id << " (" << ToString(campaign.type) << ")\n"
               << "    Harness: " << campaign.harness << '\n'
               << "    Objective: " << campaign.objective << '\n';
    }

    return stream.str();
}

std::string UserModeTargetCatalog::RenderJson(const std::vector<UserModeTargetDescriptor>& targets) {
    std::ostringstream stream;
    stream << "{\n  \"targets\": [\n";

    for (std::size_t targetIndex = 0; targetIndex < targets.size(); ++targetIndex) {
        const auto& target = targets[targetIndex];
        const auto* surface = AttackSurfaceRegistry::FindById(target.surfaceId);

        stream << "    {\n"
               << "      \"id\": \"" << EscapeJson(target.id) << "\",\n"
               << "      \"surfaceId\": \"" << EscapeJson(target.surfaceId) << "\",\n"
               << "      \"component\": \"" << EscapeJson(target.component) << "\",\n"
               << "      \"execution\": \"" << ToString(target.execution) << "\",\n"
               << "      \"description\": \"" << EscapeJson(target.description) << "\",\n";

        if (surface != nullptr) {
            stream << "      \"surfaceMetadata\": {\n"
                   << "        \"component\": \"" << EscapeJson(surface->component) << "\",\n"
                   << "        \"protocolOrFormat\": \"" << EscapeJson(surface->protocolOrFormat) << "\",\n"
                   << "        \"entryPoint\": \"" << EscapeJson(surface->entryPoint) << "\"\n"
                   << "      },\n";
        }

        RenderStringArray(stream, "prerequisites", target.prerequisites, "      ");
        stream << ",\n";
        RenderStringArray(stream, "guardrails", target.guardrails, "      ");
        stream << ",\n";

        stream << "      \"campaigns\": [";
        if (!target.campaigns.empty()) {
            stream << '\n';
            for (std::size_t campaignIndex = 0; campaignIndex < target.campaigns.size(); ++campaignIndex) {
                const auto& campaign = target.campaigns[campaignIndex];
                stream << "        {\n"
                       << "          \"id\": \"" << EscapeJson(campaign.id) << "\",\n"
                       << "          \"targetId\": \"" << EscapeJson(campaign.targetId) << "\",\n"
                       << "          \"name\": \"" << EscapeJson(campaign.name) << "\",\n"
                       << "          \"type\": \"" << ToString(campaign.type) << "\",\n"
                       << "          \"harness\": \"" << EscapeJson(campaign.harness) << "\",\n"
                       << "          \"objective\": \"" << EscapeJson(campaign.objective) << "\",\n";
                RenderStringArray(stream, "seedSources", campaign.seedSources, "          ");
                stream << ",\n";
                RenderStringArray(stream, "mutationAxes", campaign.mutationAxes, "          ");
                stream << ",\n";
                RenderStringArray(stream, "invariants", campaign.invariants, "          ");
                stream << ",\n";
                RenderStringArray(stream, "telemetry", campaign.telemetry, "          ");
                stream << '\n'
                       << "        }";

                if (campaignIndex + 1 != target.campaigns.size()) {
                    stream << ',';
                }
                stream << '\n';
            }
            stream << "      ";
        }
        stream << "]\n"
               << "    }";

        if (targetIndex + 1 != targets.size()) {
            stream << ',';
        }
        stream << '\n';
    }

    stream << "  ]\n}\n";
    return stream.str();
}

}  // namespace ShadowStrike::Fuzzer
