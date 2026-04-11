#include "ShadowStrike/Fuzzer/Core/HarnessAdapterCatalog.hpp"

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

[[nodiscard]] bool Contains(const std::vector<std::string>& values, std::string_view candidate) {
    return std::find(values.begin(), values.end(), candidate) != values.end();
}

[[nodiscard]] std::vector<HarnessAdapterDescriptor> BuildAdapters() {
    return {
        HarnessAdapterDescriptor{
            "adapter.phantomsensor.vm-campaign",
            HarnessAdapterKind::KernelVmCampaign,
            "kernel-vm-lane",
            "ShadowStrikeKernelVmRunner",
            "Snapshot-backed VM campaign runner for PhantomSensor comm-port and policy-plane fuzz plans.",
            { "phantomsensor-vm-campaign" },
            {
                "phantomsensor.kernel.control-plane",
                "phantomsensor.kernel.scan-broker",
                "phantomsensor.kernel.policy-plane",
                "phantomsensor.kernel.data-push"
            },
            {
                "pipeline\\queue",
                "state\\runs",
                "telemetry\\health",
                "vm\\profiles",
                "vm\\crash-collection",
                "corpora\\kernel\\baseline",
                "corpora\\kernel\\variants"
            },
            {
                "Verify the referenced snapshot profile exists before worker launch.",
                "Validate every queued step artifact exists and matches the expected schema family.",
                "Refuse execution when a prior crash bucket has not yet been replayed against a clean snapshot."
            },
            {
                "kernel memory dump",
                "worker console transcript",
                "driver health counters",
                "replay bundle"
            },
            {
                "VM bugcheck",
                "comm-port disconnect without explicit denial",
                "stale snapshot lineage",
                "broker reconnect failure"
            },
            {
                "Never execute on the developer host.",
                "Run a single kernel campaign per VM snapshot lineage.",
                "Restore a clean snapshot before replaying any crash bucket."
            }
        },
        HarnessAdapterDescriptor{
            "adapter.phantomcore.filter-port-broker",
            HarnessAdapterKind::BrokerSession,
            "usermode-broker-lane",
            "ShadowStrikeBrokerHarness",
            "Process-isolated broker harness for FilterConnection and IPCManager filter-port session campaigns.",
            {
                "FilterConnection handshake harness",
                "FilterConnection overlapped I/O harness"
            },
            { "phantomcore.usermode.filter-port-client" },
            {
                "pipeline\\queue",
                "state\\runs",
                "telemetry\\coverage",
                "crashes\\incoming",
                "corpora\\usermode\\broker"
            },
            {
                "Enable page heap for the worker process.",
                "Recreate broker session state before every replay attempt.",
                "Validate asynchronous reply correlation tables are empty before shutdown."
            },
            {
                "user-mode minidump",
                "coverage bitmap",
                "disconnect telemetry",
                "session replay bundle"
            },
            {
                "Unhandled exception",
                "heap corruption signal",
                "reply correlation desynchronization",
                "handle leak regression"
            },
            {
                "Terminate the worker after every key-exchange fault.",
                "Do not reuse session keys across iterations."
            }
        },
        HarnessAdapterDescriptor{
            "adapter.phantomcore.named-pipe-broker",
            HarnessAdapterKind::BrokerSession,
            "usermode-broker-lane",
            "ShadowStrikeBrokerHarness",
            "Privileged named-pipe harness for ServiceCommunication authentication and churn campaigns.",
            {
                "ServiceCommunication pipe harness",
                "ServiceCommunication churn harness"
            },
            { "phantomcore.usermode.named-pipe-broker" },
            {
                "pipeline\\queue",
                "state\\runs",
                "telemetry\\coverage",
                "crashes\\incoming",
                "corpora\\usermode\\broker"
            },
            {
                "Verify the pipe security descriptor before worker launch.",
                "Bound concurrent clients to the target-defined ceiling.",
                "Reset the listener after any malformed authentication frame that reaches command dispatch."
            },
            {
                "user-mode minidump",
                "pipe connection log",
                "ACL audit trail",
                "replay bundle"
            },
            {
                "Unauthorized command dispatch",
                "listener starvation",
                "worker restart storm",
                "session handle exhaustion"
            },
            {
                "Malformed authentication frames must never reach privileged command handling.",
                "Listener uptime must remain measurable under client churn."
            }
        },
        HarnessAdapterDescriptor{
            "adapter.phantomcore.pe-frontdoor",
            HarnessAdapterKind::ParserFrontDoor,
            "usermode-parser-lane",
            "ShadowStrikeParserHarness",
            "Process-isolated PE parser harness for front-door header and directory corruption campaigns.",
            { "PEParser front-door harness" },
            { "phantomcore.usermode.pe-parser" },
            {
                "pipeline\\queue",
                "state\\runs",
                "telemetry\\coverage",
                "crashes\\incoming",
                "corpora\\usermode\\parser"
            },
            {
                "Enable page heap and fail-fast exception capture.",
                "Replay every crashing sample in a fresh worker process.",
                "Validate parser failure codes remain deterministic across retries."
            },
            {
                "user-mode minidump",
                "coverage bitmap",
                "parser decision log",
                "sample quarantine bundle"
            },
            {
                "out-of-bounds read",
                "integer overflow",
                "access violation",
                "nondeterministic parse result"
            },
            {
                "No crashing sample may be promoted into the long-lived corpus.",
                "Failures must remain explicit and reproducible."
            }
        },
        HarnessAdapterDescriptor{
            "adapter.phantomcore.pe-differential",
            HarnessAdapterKind::DifferentialParser,
            "usermode-parser-lane",
            "ShadowStrikeParserHarness",
            "Differential parser harness that compares PEParser and PEValidation outcomes on equivalent inputs.",
            { "PEParser vs PEValidation differential harness" },
            { "phantomcore.usermode.pe-parser" },
            {
                "pipeline\\queue",
                "state\\runs",
                "telemetry\\coverage",
                "crashes\\incoming",
                "corpora\\usermode\\parser"
            },
            {
                "Launch parser and validator in the same worker only when mutable state is fully reset between iterations.",
                "Emit an explicit divergence report for every fatal-boundary mismatch.",
                "Replay divergence cases before promotion into the regression corpus."
            },
            {
                "normalization diff report",
                "coverage bitmap",
                "decision divergence ledger"
            },
            {
                "fatal-boundary disagreement",
                "validator-only acceptance",
                "parser-only acceptance",
                "worker crash"
            },
            {
                "Equivalent PE corruption must not yield contradictory fatality decisions."
            }
        },
        HarnessAdapterDescriptor{
            "adapter.phantomcore.threatintel-frontdoor",
            HarnessAdapterKind::ParserFrontDoor,
            "usermode-parser-lane",
            "ShadowStrikeThreatIntelHarness",
            "Importer harness for threat-intel feed parsing and malformed IOC ingestion campaigns.",
            { "ThreatIntel importer harness" },
            { "phantomcore.usermode.threatintel" },
            {
                "pipeline\\queue",
                "state\\runs",
                "telemetry\\coverage",
                "crashes\\incoming",
                "corpora\\usermode\\parser"
            },
            {
                "Snapshot the destination stores before every import attempt.",
                "Reject silent partial-import success as a correctness failure.",
                "Reset stores after malformed feeds that reach commit logic."
            },
            {
                "user-mode minidump",
                "store diff report",
                "accepted/rejected IOC counters",
                "replay bundle"
            },
            {
                "silent partial import",
                "store corruption",
                "worker crash",
                "normalization drift"
            },
            {
                "Invalid feeds must fail explicitly.",
                "Store state must be restorable between iterations."
            }
        },
        HarnessAdapterDescriptor{
            "adapter.phantomcore.threatintel-differential",
            HarnessAdapterKind::DifferentialParser,
            "usermode-parser-lane",
            "ShadowStrikeThreatIntelHarness",
            "Differential threat-intel harness that compares normalization results across equivalent encodings.",
            { "ThreatIntel normalization differential harness" },
            { "phantomcore.usermode.threatintel" },
            {
                "pipeline\\queue",
                "state\\runs",
                "telemetry\\coverage",
                "crashes\\incoming",
                "corpora\\usermode\\parser"
            },
            {
                "Emit canonical-record hashes for every normalized feed.",
                "Replay equivalent feed pairs before closing a divergence bucket.",
                "Refuse promotion when equivalence checks are incomplete."
            },
            {
                "normalized record hash ledger",
                "decision divergence report",
                "coverage bitmap"
            },
            {
                "equivalent-feed divergence",
                "deduplication drift",
                "worker crash",
                "nondeterministic record ordering"
            },
            {
                "Equivalent feeds must converge to identical normalized records."
            }
        }
    };
}

}  // namespace

std::string_view ToString(const HarnessAdapterKind kind) {
    switch (kind) {
    case HarnessAdapterKind::KernelVmCampaign:
        return "kernel-vm-campaign";
    case HarnessAdapterKind::BrokerSession:
        return "broker-session";
    case HarnessAdapterKind::ParserFrontDoor:
        return "parser-front-door";
    case HarnessAdapterKind::DifferentialParser:
        return "differential-parser";
    }

    return "unknown";
}

const std::vector<HarnessAdapterDescriptor>& HarnessAdapterCatalog::GetDefaultAdapters() {
    static const std::vector<HarnessAdapterDescriptor> adapters = BuildAdapters();
    return adapters;
}

const HarnessAdapterDescriptor* HarnessAdapterCatalog::FindById(std::string_view id) {
    const auto& adapters = GetDefaultAdapters();
    const auto match = std::find_if(adapters.begin(), adapters.end(),
        [&](const HarnessAdapterDescriptor& adapter) { return adapter.id == id; });
    return match == adapters.end() ? nullptr : &(*match);
}

const HarnessAdapterDescriptor* HarnessAdapterCatalog::FindForPlan(const CampaignExecutionPlan& plan) {
    const auto& adapters = GetDefaultAdapters();
    const std::string laneId =
        plan.executionLane == "kernel-vm" ? "kernel-vm-lane" :
        plan.executionLane == "user-mode-broker" ? "usermode-broker-lane" :
        plan.executionLane == "user-mode-parser" ? "usermode-parser-lane" :
        "differential-decoder-lane";

    const auto match = std::find_if(adapters.begin(), adapters.end(),
        [&](const HarnessAdapterDescriptor& adapter) {
            return adapter.laneId == laneId &&
                Contains(adapter.acceptedHarnessNames, plan.harness) &&
                Contains(adapter.acceptedTargetIds, plan.targetId);
        });
    return match == adapters.end() ? nullptr : &(*match);
}

std::string HarnessAdapterCatalog::DescribeText(const HarnessAdapterDescriptor& adapter) {
    std::ostringstream stream;
    stream << adapter.id << '\n'
           << "Kind: " << ToString(adapter.kind) << '\n'
           << "Lane: " << adapter.laneId << '\n'
           << "Worker image: " << adapter.workerImage << '\n'
           << "Description: " << adapter.description << '\n';
    return stream.str();
}

std::string HarnessAdapterCatalog::RenderJson(const std::vector<HarnessAdapterDescriptor>& adapters) {
    std::ostringstream stream;
    stream << "{\n  \"adapters\": [\n";

    for (std::size_t index = 0; index < adapters.size(); ++index) {
        const auto& adapter = adapters[index];
        stream << "    {\n"
               << "      \"id\": \"" << EscapeJson(adapter.id) << "\",\n"
               << "      \"kind\": \"" << ToString(adapter.kind) << "\",\n"
               << "      \"laneId\": \"" << EscapeJson(adapter.laneId) << "\",\n"
               << "      \"workerImage\": \"" << EscapeJson(adapter.workerImage) << "\",\n"
               << "      \"description\": \"" << EscapeJson(adapter.description) << "\",\n";
        RenderStringArray(stream, "acceptedHarnessNames", adapter.acceptedHarnessNames, "      ");
        stream << ",\n";
        RenderStringArray(stream, "acceptedTargetIds", adapter.acceptedTargetIds, "      ");
        stream << ",\n";
        RenderStringArray(stream, "requiredWorkspaceDirectories", adapter.requiredWorkspaceDirectories, "      ");
        stream << ",\n";
        RenderStringArray(stream, "preflightChecks", adapter.preflightChecks, "      ");
        stream << ",\n";
        RenderStringArray(stream, "outputs", adapter.outputs, "      ");
        stream << ",\n";
        RenderStringArray(stream, "failureSignals", adapter.failureSignals, "      ");
        stream << ",\n";
        RenderStringArray(stream, "guardrails", adapter.guardrails, "      ");
        stream << "\n    }";

        if (index + 1 != adapters.size()) {
            stream << ',';
        }
        stream << '\n';
    }

    stream << "  ]\n}\n";
    return stream.str();
}

}  // namespace ShadowStrike::Fuzzer
