#include "ShadowStrike/Fuzzer/Targets/KernelTargetCatalog.hpp"

#include "ShadowStrike/Fuzzer/Core/AttackSurface.hpp"
#include "ShadowStrike/Fuzzer/Protocol/KernelMessageFactory.hpp"

#include <algorithm>
#include <sstream>
#include <string_view>
#include <vector>

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

[[nodiscard]] KernelCampaignStep MakeStep(
    const std::uint32_t order,
    std::string artifactId,
    std::string deliveryPhase,
    std::string objective,
    std::string expectation,
    const bool resetConnectionAfter = false)
{
    return KernelCampaignStep{
        order,
        std::move(artifactId),
        std::move(deliveryPhase),
        std::move(objective),
        std::move(expectation),
        resetConnectionAfter
    };
}

[[nodiscard]] KernelCampaign MakeCampaign(
    std::string id,
    std::string targetId,
    std::string name,
    const KernelCampaignType type,
    std::string objective,
    const bool requiresFreshSession,
    const std::uint32_t maxArtifactsPerIteration,
    std::vector<std::string> guardrails,
    std::vector<std::string> crashSignals,
    std::vector<std::string> telemetry,
    std::vector<KernelCampaignStep> steps)
{
    return KernelCampaign{
        std::move(id),
        std::move(targetId),
        std::move(name),
        type,
        std::move(objective),
        requiresFreshSession,
        maxArtifactsPerIteration,
        std::move(guardrails),
        std::move(crashSignals),
        std::move(telemetry),
        std::move(steps)
    };
}

[[nodiscard]] std::vector<KernelTargetDescriptor> BuildTargets() {
    std::vector<KernelTargetDescriptor> targets;
    targets.reserve(4);

    targets.push_back(KernelTargetDescriptor{
        "phantomsensor.kernel.control-plane",
        "phantomsensor.commport.control-plane",
        "PhantomSensor",
        KernelTransportKind::FilterManagerCommPort,
        KernelIsolationMode::VmSnapshotWithRebootOnCrash,
        "phantomsensor-control-clean",
        1500u,
        "Session establishment and control-plane validation for the PhantomSensor Filter Manager communication port.",
        {
            "Install the signed PhantomSensor driver and confirm the comm-port endpoint is reachable.",
            "Attach a VM-side agent capable of reconnecting after driver-initiated disconnects.",
            "Capture kernel crash dumps and Filter Manager diagnostics for every failed iteration."
        },
        {
            "Never execute this target on the developer host.",
            "Restore a clean VM snapshot before each crash-signature bucket replay.",
            "Terminate the session immediately after malformed header rejection or broker disconnect."
        },
        {
            MakeCampaign(
                "phantomsensor.control-plane.session-bootstrap",
                "phantomsensor.kernel.control-plane",
                "Session bootstrap",
                KernelCampaignType::StatefulSession,
                "Drive the register-heartbeat-driver-status flow and verify the kernel accepts canonical control traffic while rejecting malformed headers cleanly.",
                true,
                4u,
                {
                    "Reconnect through a fresh client handle on every iteration.",
                    "Abort the iteration on unexpected kernel silence after a driver-status query."
                },
                {
                    "Kernel bugcheck",
                    "Comm-port disconnect without explicit denial",
                    "Handle leak causing subsequent connection failure"
                },
                {
                    "Connect latency",
                    "Disconnect reason",
                    "Driver-status round-trip time"
                },
                {
                    MakeStep(1u, "register-baseline", "connect", "Establish a canonical user-mode registration session.", "Session accepted or explicitly denied without crash."),
                    MakeStep(2u, "heartbeat-baseline", "steady-state", "Exercise the keep-alive path on a healthy session.", "Heartbeat accepted without resetting the session."),
                    MakeStep(3u, "query-driver-status-baseline", "reply-path", "Exercise the explicit response path for control queries.", "Driver returns a well-formed status reply."),
                    MakeStep(4u, "query-driver-status-no-ack", "fault-injection", "Probe reply-path handling when the no-ack flag conflicts with a reply-required query.", "Kernel rejects or disconnects the client without bugcheck.", true)
                }),
            MakeCampaign(
                "phantomsensor.control-plane.header-faults",
                "phantomsensor.kernel.control-plane",
                "Header fault injection",
                KernelCampaignType::StateTransition,
                "Stress message admission logic with invalid magic and unsupported-version registration frames.",
                true,
                2u,
                {
                    "Use a fresh snapshot after every crash or persistent comm-port refusal.",
                    "Do not reuse a connection after malformed registration traffic."
                },
                {
                    "Kernel bugcheck",
                    "Persistent inability to reconnect",
                    "Corrupted session state surviving snapshot restore"
                },
                {
                    "Reject path timing",
                    "Disconnect count",
                    "Crash bucket fingerprint"
                },
                {
                    MakeStep(1u, "register-invalid-magic", "connect", "Corrupt the protocol sentinel during registration.", "Kernel rejects the frame and preserves driver stability.", true),
                    MakeStep(2u, "register-unsupported-version", "connect", "Advertise an unsupported protocol version during registration.", "Kernel rejects the frame without state corruption.", true)
                })
        }
    });

    targets.push_back(KernelTargetDescriptor{
        "phantomsensor.kernel.scan-broker",
        "phantomsensor.commport.scan-request",
        "PhantomSensor",
        KernelTransportKind::FilterManagerCommPort,
        KernelIsolationMode::VmSnapshotWithRebootOnCrash,
        "phantomsensor-scan-broker-clean",
        1000u,
        "Variable-length scan request campaigns focused on reply-required broker state and tail-length validation.",
        {
            "Prime the user-mode scan broker so reply-required requests have a live consumer.",
            "Enable crash dump capture for minifilter and broker-side faults.",
            "Collect broker timeout telemetry to distinguish logic hangs from hard crashes."
        },
        {
            "Reset the VM snapshot after any scan request that wedges the broker reply path.",
            "Cap each boot to a bounded number of reply-required requests to avoid unbounded queue growth."
        },
        {
            MakeCampaign(
                "phantomsensor.scan-broker.reply-required",
                "phantomsensor.kernel.scan-broker",
                "Reply-required scan flow",
                KernelCampaignType::RequestReply,
                "Validate that canonical scan requests produce a verdict path and malformed variable tails are rejected safely.",
                true,
                3u,
                {
                    "Run the broker with deterministic policy so verdict timing is attributable.",
                    "Treat broker timeout as a failure signal equivalent to a lost reply."
                },
                {
                    "Kernel bugcheck",
                    "Hung pre-create path",
                    "Reply queue leak or dead session"
                },
                {
                    "Scan verdict latency",
                    "Rejected request count",
                    "Queue depth before disconnect"
                },
                {
                    MakeStep(1u, "register-baseline", "connect", "Open a valid comm-port session before scan traffic.", "Session accepted."),
                    MakeStep(2u, "scan-request-baseline", "request", "Issue a canonical reply-required file scan request.", "Kernel forwards the request and maintains broker state."),
                    MakeStep(3u, "scan-request-truncated-tail", "fault-injection", "Truncate the variable tail while header lengths still advertise the original request.", "Kernel rejects or tears down the session without bugcheck.", true)
                }),
            MakeCampaign(
                "phantomsensor.scan-broker.length-overclaim",
                "phantomsensor.kernel.scan-broker",
                "Length overclaim validation",
                KernelCampaignType::StateTransition,
                "Exercise file-path and process-name overclaim handling for variable-length scan payloads.",
                true,
                3u,
                {
                    "Use a fresh connection after every malformed scan request."
                },
                {
                    "Kernel bugcheck",
                    "Stuck verdict wait",
                    "Memory corruption symptoms in subsequent sessions"
                },
                {
                    "Parser reject path",
                    "Disconnect timing",
                    "Crash bucket signature"
                },
                {
                    MakeStep(1u, "register-baseline", "connect", "Establish a clean session.", "Session accepted."),
                    MakeStep(2u, "scan-request-path-length-overclaim", "fault-injection", "Overclaim UTF-16 file path length beyond the serialized bytes.", "Kernel rejects without over-read.", true),
                    MakeStep(3u, "scan-request-process-name-overclaim", "fault-injection", "Overclaim UTF-16 process-name length beyond the serialized bytes.", "Kernel rejects without over-read.", true)
                })
        }
    });

    targets.push_back(KernelTargetDescriptor{
        "phantomsensor.kernel.policy-plane",
        "phantomsensor.commport.policy-update",
        "PhantomSensor",
        KernelTransportKind::FilterManagerCommPort,
        KernelIsolationMode::VmSnapshotWithRebootOnCrash,
        "phantomsensor-policy-clean",
        500u,
        "Policy and protected-process update campaigns targeting queue tuning, fail-closed switches, and self-protection enrollment.",
        {
            "Persist a baseline driver policy snapshot before fuzzing mutable policy messages.",
            "Validate that the user-mode broker can reconnect after policy-induced session resets."
        },
        {
            "Restore baseline policy after every mutation that changes queue or blocking semantics.",
            "Treat any unexplained policy persistence across snapshot restore as a blocking defect."
        },
        {
            MakeCampaign(
                "phantomsensor.policy-plane.queue-pressure",
                "phantomsensor.kernel.policy-plane",
                "Queue pressure policy churn",
                KernelCampaignType::StateTransition,
                "Drive policy updates that push queue parameters to saturation and verify the kernel rejects or clamps them safely.",
                true,
                3u,
                {
                    "Reapply a canonical policy after every saturation attempt."
                },
                {
                    "Kernel bugcheck",
                    "Unbounded nonpaged allocation growth",
                    "Persistent broker starvation"
                },
                {
                    "Queue depth",
                    "Policy apply latency",
                    "Post-update broker health"
                },
                {
                    MakeStep(1u, "register-baseline", "connect", "Establish a clean session before policy mutation.", "Session accepted."),
                    MakeStep(2u, "policy-update-baseline", "request", "Apply a canonical policy update to establish a known-good baseline.", "Kernel accepts and reports healthy steady state."),
                    MakeStep(3u, "policy-update-queue-saturation", "fault-injection", "Drive queue and timeout fields to extreme values.", "Kernel rejects, clamps, or disconnects safely without destabilizing the driver.", true)
                }),
            MakeCampaign(
                "phantomsensor.policy-plane.protected-process",
                "phantomsensor.kernel.policy-plane",
                "Protected-process enrollment",
                KernelCampaignType::StateTransition,
                "Exercise self-protection registration after policy initialization.",
                true,
                3u,
                {
                    "Target only synthetic test processes inside the VM."
                },
                {
                    "Kernel bugcheck",
                    "Driver-side stale protection entry",
                    "Unexpected tamper lockout of the broker"
                },
                {
                    "Protection registration status",
                    "Driver-side entry count",
                    "Reconnect success"
                },
                {
                    MakeStep(1u, "register-baseline", "connect", "Open a clean session for policy and protection traffic.", "Session accepted."),
                    MakeStep(2u, "policy-update-baseline", "request", "Ensure the driver is operating under canonical policy.", "Policy accepted."),
                    MakeStep(3u, "register-protected-process-baseline", "request", "Register a synthetic protected process name and identifier.", "Kernel accepts or rejects cleanly without corrupting protection state.")
                })
        }
    });

    targets.push_back(KernelTargetDescriptor{
        "phantomsensor.kernel.data-push",
        "phantomsensor.commport.data-push-batches",
        "PhantomSensor",
        KernelTransportKind::FilterManagerCommPort,
        KernelIsolationMode::VmSnapshotWithRebootOnCrash,
        "phantomsensor-data-sync-clean",
        600u,
        "Batch-oriented threat-intel synchronization campaigns for hash and exclusion update handlers.",
        {
            "Reset threat-intel stores to a known baseline between iterations.",
            "Collect queue and allocation telemetry while large batches are being processed."
        },
        {
            "Bound each iteration to a single batch mutation after a clean registration handshake.",
            "Restore the VM snapshot after any intake path that leaks state into subsequent runs."
        },
        {
            MakeCampaign(
                "phantomsensor.data-push.hash-batches",
                "phantomsensor.kernel.data-push",
                "Hash batch intake",
                KernelCampaignType::BatchIngestion,
                "Validate fixed-size batch accounting and maximum-entry enforcement for IOC synchronization.",
                true,
                3u,
                {
                    "Do not chain multiple malformed hash batches on one connection."
                },
                {
                    "Kernel bugcheck",
                    "Store corruption",
                    "Queue starvation"
                },
                {
                    "Entries accepted/rejected",
                    "Batch processing latency",
                    "Post-batch reconnect success"
                },
                {
                    MakeStep(1u, "register-baseline", "connect", "Establish a clean session before hash synchronization.", "Session accepted."),
                    MakeStep(2u, "push-hash-database-baseline", "request", "Send a canonical single-entry hash batch.", "Kernel processes the batch without instability."),
                    MakeStep(3u, "push-hash-database-entrycount-mismatch", "fault-injection", "Advertise more entries than are present in the serialized payload.", "Kernel rejects the batch without out-of-bounds reads.", true),
                    MakeStep(4u, "push-hash-database-batch-limit-plus-one", "fault-injection", "Exceed SHADOWSTRIKE_PUSH_MAX_BATCH_ENTRIES by one.", "Kernel refuses the batch without destabilizing stores.", true)
                }),
            MakeCampaign(
                "phantomsensor.data-push.exclusion-updates",
                "phantomsensor.kernel.data-push",
                "Exclusion update validation",
                KernelCampaignType::BatchIngestion,
                "Exercise variable-length exclusion updates and verify length validation across trust bypass surfaces.",
                true,
                2u,
                {
                    "Reset exclusion state between iterations."
                },
                {
                    "Kernel bugcheck",
                    "Persistent stale exclusion entry",
                    "Path normalization corruption"
                },
                {
                    "Exclusion apply status",
                    "Reject path timing",
                    "Reconnect success"
                },
                {
                    MakeStep(1u, "register-baseline", "connect", "Open a session for exclusion management traffic.", "Session accepted."),
                    MakeStep(2u, "exclusion-update-baseline", "request", "Apply a canonical path exclusion update.", "Kernel accepts or cleanly rejects the exclusion."),
                    MakeStep(3u, "exclusion-update-value-length-overclaim", "fault-injection", "Overclaim the exclusion value tail beyond the serialized bytes.", "Kernel rejects without over-read or stale trust state.", true)
                })
        }
    });

    return targets;
}

[[nodiscard]] const BinarySeedArtifact* FindArtifact(std::string_view id) {
    static const std::vector<BinarySeedArtifact> corpus = KernelMessageFactory::BuildFullSeedSet();
    const auto match = std::find_if(corpus.begin(), corpus.end(),
        [&](const BinarySeedArtifact& artifact) { return artifact.id == id; });
    return match == corpus.end() ? nullptr : &(*match);
}

}  // namespace

std::string_view ToString(const KernelTransportKind kind) {
    switch (kind) {
    case KernelTransportKind::FilterManagerCommPort:
        return "filter-manager-comm-port";
    case KernelTransportKind::CallbackReplay:
        return "callback-replay";
    }

    return "unknown";
}

std::string_view ToString(const KernelIsolationMode mode) {
    switch (mode) {
    case KernelIsolationMode::VmSnapshotOnly:
        return "vm-snapshot-only";
    case KernelIsolationMode::VmSnapshotWithRebootOnCrash:
        return "vm-snapshot-with-reboot-on-crash";
    }

    return "unknown";
}

std::string_view ToString(const KernelCampaignType type) {
    switch (type) {
    case KernelCampaignType::StatefulSession:
        return "stateful-session";
    case KernelCampaignType::RequestReply:
        return "request-reply";
    case KernelCampaignType::BatchIngestion:
        return "batch-ingestion";
    case KernelCampaignType::StateTransition:
        return "state-transition";
    }

    return "unknown";
}

const std::vector<KernelTargetDescriptor>& KernelTargetCatalog::GetDefaultTargets() {
    static const std::vector<KernelTargetDescriptor> targets = BuildTargets();
    return targets;
}

const KernelTargetDescriptor* KernelTargetCatalog::FindById(const std::string_view id) {
    const auto& targets = GetDefaultTargets();
    const auto match = std::find_if(targets.begin(), targets.end(),
        [&](const KernelTargetDescriptor& target) { return target.id == id; });
    return match == targets.end() ? nullptr : &(*match);
}

std::string KernelTargetCatalog::DescribeText(const KernelTargetDescriptor& target) {
    std::ostringstream stream;
    stream << "Kernel Target: " << target.id << '\n'
           << "Surface: " << target.surfaceId << '\n'
           << "Transport: " << ToString(target.transport) << '\n'
           << "Isolation: " << ToString(target.isolation) << '\n'
           << "Snapshot Profile: " << target.snapshotProfile << '\n'
           << "Max Iterations Per Boot: " << target.maxIterationsPerBoot << '\n'
           << "Description: " << target.description << "\n\n";

    stream << "Prerequisites:\n";
    for (const auto& item : target.prerequisites) {
        stream << "  - " << item << '\n';
    }

    stream << "\nGuardrails:\n";
    for (const auto& item : target.guardrails) {
        stream << "  - " << item << '\n';
    }

    stream << "\nCampaigns:\n";
    for (const auto& campaign : target.campaigns) {
        stream << "  * " << campaign.id << " (" << ToString(campaign.type) << ")\n"
               << "    Objective: " << campaign.objective << '\n'
               << "    Steps:\n";
        for (const auto& step : campaign.steps) {
            stream << "      " << step.order << ". " << step.artifactId
                   << " [" << step.deliveryPhase << "] - " << step.expectation << '\n';
        }
    }

    return stream.str();
}

std::string KernelTargetCatalog::RenderJson(const std::vector<KernelTargetDescriptor>& targets) {
    std::ostringstream stream;
    stream << "{\n  \"targets\": [\n";

    for (std::size_t targetIndex = 0; targetIndex < targets.size(); ++targetIndex) {
        const auto& target = targets[targetIndex];
        const auto* surface = AttackSurfaceRegistry::FindById(target.surfaceId);

        stream << "    {\n"
               << "      \"id\": \"" << EscapeJson(target.id) << "\",\n"
               << "      \"surfaceId\": \"" << EscapeJson(target.surfaceId) << "\",\n"
               << "      \"component\": \"" << EscapeJson(target.component) << "\",\n"
               << "      \"transport\": \"" << ToString(target.transport) << "\",\n"
               << "      \"isolation\": \"" << ToString(target.isolation) << "\",\n"
               << "      \"snapshotProfile\": \"" << EscapeJson(target.snapshotProfile) << "\",\n"
               << "      \"maxIterationsPerBoot\": " << target.maxIterationsPerBoot << ",\n"
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
                       << "          \"objective\": \"" << EscapeJson(campaign.objective) << "\",\n"
                       << "          \"requiresFreshSession\": " << (campaign.requiresFreshSession ? "true" : "false") << ",\n"
                       << "          \"maxArtifactsPerIteration\": " << campaign.maxArtifactsPerIteration << ",\n";
                RenderStringArray(stream, "guardrails", campaign.guardrails, "          ");
                stream << ",\n";
                RenderStringArray(stream, "crashSignals", campaign.crashSignals, "          ");
                stream << ",\n";
                RenderStringArray(stream, "telemetry", campaign.telemetry, "          ");
                stream << ",\n";

                stream << "          \"steps\": [";
                if (!campaign.steps.empty()) {
                    stream << '\n';
                    for (std::size_t stepIndex = 0; stepIndex < campaign.steps.size(); ++stepIndex) {
                        const auto& step = campaign.steps[stepIndex];
                        const auto* artifact = FindArtifact(step.artifactId);

                        stream << "            {\n"
                               << "              \"order\": " << step.order << ",\n"
                               << "              \"artifactId\": \"" << EscapeJson(step.artifactId) << "\",\n"
                               << "              \"deliveryPhase\": \"" << EscapeJson(step.deliveryPhase) << "\",\n"
                               << "              \"objective\": \"" << EscapeJson(step.objective) << "\",\n"
                               << "              \"expectation\": \"" << EscapeJson(step.expectation) << "\",\n"
                               << "              \"resetConnectionAfter\": " << (step.resetConnectionAfter ? "true" : "false");

                        if (artifact != nullptr) {
                            stream << ",\n"
                                   << "              \"artifact\": {\n"
                                   << "                \"kind\": \"" << ToString(artifact->kind) << "\",\n"
                                   << "                \"surfaceId\": \"" << EscapeJson(artifact->surfaceId) << "\",\n"
                                   << "                \"schemaId\": \"" << EscapeJson(artifact->schemaId) << "\",\n"
                                   << "                \"parentId\": \"" << EscapeJson(artifact->parentId) << "\",\n"
                                   << "                \"fileName\": \"" << EscapeJson(artifact->fileName) << "\"\n"
                                   << "              }\n"
                                   << "            }";
                        } else {
                            stream << "\n            }";
                        }

                        if (stepIndex + 1 != campaign.steps.size()) {
                            stream << ',';
                        }
                        stream << '\n';
                    }
                    stream << "          ";
                }
                stream << "]\n"
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
