#include "ShadowStrike/Fuzzer/Core/AttackSurface.hpp"

#include <algorithm>
#include <initializer_list>
#include <sstream>

namespace ShadowStrike::Fuzzer {

namespace {

[[nodiscard]] const char* ToString(const AttackSurfaceFamily family) noexcept {
    switch (family) {
    case AttackSurfaceFamily::KernelCommPort: return "KernelCommPort";
    case AttackSurfaceFamily::KernelCallbackReplay: return "KernelCallbackReplay";
    case AttackSurfaceFamily::UserModeIpc: return "UserModeIpc";
    case AttackSurfaceFamily::Parser: return "Parser";
    case AttackSurfaceFamily::Emulator: return "Emulator";
    case AttackSurfaceFamily::Disassembler: return "Disassembler";
    }

    return "Unknown";
}

[[nodiscard]] const char* ToString(const TrustBoundary boundary) noexcept {
    switch (boundary) {
    case TrustBoundary::UserToKernel: return "UserToKernel";
    case TrustBoundary::KernelToUser: return "KernelToUser";
    case TrustBoundary::LocalServiceToBroker: return "LocalServiceToBroker";
    case TrustBoundary::UntrustedContentToEngine: return "UntrustedContentToEngine";
    }

    return "Unknown";
}

[[nodiscard]] const char* ToString(const ExecutionLane lane) noexcept {
    switch (lane) {
    case ExecutionLane::InProcess: return "InProcess";
    case ExecutionLane::BrokerProcess: return "BrokerProcess";
    case ExecutionLane::IsolatedVmKernel: return "IsolatedVmKernel";
    }

    return "Unknown";
}

[[nodiscard]] const char* ToString(const RiskTier tier) noexcept {
    switch (tier) {
    case RiskTier::Critical: return "Critical";
    case RiskTier::High: return "High";
    case RiskTier::Medium: return "Medium";
    }

    return "Unknown";
}

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

template <typename Collection>
void AppendJsonArray(std::ostringstream& stream, const Collection& values) {
    stream << '[';

    bool first = true;
    for (const auto& value : values) {
        if (!first) {
            stream << ',';
        }

        first = false;
        stream << '"' << EscapeJson(value) << '"';
    }

    stream << ']';
}

[[nodiscard]] AttackSurfaceDescriptor MakeSurface(
    std::string id,
    std::string component,
    std::string entryPoint,
    std::string protocolOrFormat,
    const AttackSurfaceFamily family,
    const TrustBoundary boundary,
    const ExecutionLane lane,
    const RiskTier tier,
    const bool stateful,
    const bool requiresVmIsolation,
    std::initializer_list<std::string> schemaSources,
    std::initializer_list<std::string> mutationAxes,
    std::initializer_list<std::string> invariants)
{
    return AttackSurfaceDescriptor{
        std::move(id),
        std::move(component),
        std::move(entryPoint),
        std::move(protocolOrFormat),
        family,
        boundary,
        lane,
        tier,
        stateful,
        requiresVmIsolation,
        std::vector<std::string>(schemaSources),
        std::vector<std::string>(mutationAxes),
        std::vector<std::string>(invariants)
    };
}

[[nodiscard]] std::vector<AttackSurfaceDescriptor> BuildRegistry() {
    std::vector<AttackSurfaceDescriptor> surfaces;
    surfaces.reserve(11);

    surfaces.push_back(MakeSurface(
        "phantomsensor.commport.control-plane",
        "PhantomSensor",
        "ShadowStrikeMessageNotify / ShadowStrikeValidateInputBuffer",
        "Filter Manager comm-port control messages",
        AttackSurfaceFamily::KernelCommPort,
        TrustBoundary::UserToKernel,
        ExecutionLane::IsolatedVmKernel,
        RiskTier::Critical,
        true,
        true,
        {
            "PhantomSensor\\Shared\\MessageProtocol.h",
            "PhantomSensor\\Shared\\MessageTypes.h",
            "PhantomSensor\\PhantomSensor\\Communication\\CommPort.c"
        },
        {
            "header size skew",
            "message type confusion",
            "replay and reorder",
            "encrypted vs plaintext framing",
            "invalid state transitions"
        },
        {
            "no bugcheck",
            "invalid input rejected with explicit status",
            "client slot reference counts remain balanced"
        }));

    surfaces.push_back(MakeSurface(
        "phantomsensor.commport.scan-request",
        "PhantomSensor",
        "FILE_SCAN_REQUEST payload parser",
        "Variable-length file scan request",
        AttackSurfaceFamily::KernelCommPort,
        TrustBoundary::UserToKernel,
        ExecutionLane::IsolatedVmKernel,
        RiskTier::Critical,
        true,
        true,
        {
            "PhantomSensor\\Shared\\MessageProtocol.h",
            "PhantomSensor\\Shared\\SharedDefs.h"
        },
        {
            "path and process-name length skew",
            "metadata contradiction",
            "oversized file and access flags",
            "truncated variable tail"
        },
        {
            "no pool overread",
            "payload boundaries honored",
            "verdict path fails closed on malformed request"
        }));

    surfaces.push_back(MakeSurface(
        "phantomsensor.commport.policy-update",
        "PhantomSensor",
        "ShadowStrikeHandleUpdatePolicy",
        "Policy update payload",
        AttackSurfaceFamily::KernelCommPort,
        TrustBoundary::UserToKernel,
        ExecutionLane::IsolatedVmKernel,
        RiskTier::Critical,
        true,
        true,
        {
            "PhantomSensor\\Shared\\SharedDefs.h",
            "PhantomSensor\\PhantomSensor\\Communication\\CommPort.c"
        },
        {
            "boolean matrix contradictions",
            "timeout and queue bound extremes",
            "batch tuning overflow",
            "repeat update churn"
        },
        {
            "policy application never corrupts driver state",
            "limits remain bounded",
            "rejected updates preserve prior stable configuration"
        }));

    surfaces.push_back(MakeSurface(
        "phantomsensor.commport.data-push-batches",
        "PhantomSensor",
        "Kernel data-push handlers",
        "Hash / pattern / signature / IOC / whitelist / exclusion batches",
        AttackSurfaceFamily::KernelCommPort,
        TrustBoundary::UserToKernel,
        ExecutionLane::IsolatedVmKernel,
        RiskTier::Critical,
        true,
        true,
        {
            "PhantomSensor\\Shared\\MessageProtocol.h",
            "PhantomSensor\\Shared\\MessageTypes.h"
        },
        {
            "batch header inconsistency",
            "entry count overflow",
            "variable-length IOC payload truncation",
            "mixed verdict and reputation values"
        },
        {
            "no unbounded kernel allocation",
            "entry acceptance and rejection counts remain consistent",
            "partial failures never poison subsequent batches"
        }));

    surfaces.push_back(MakeSurface(
        "phantomsensor.callback-replay.registry-and-alpc",
        "PhantomSensor",
        "Registry / ALPC / process notification serialization",
        "Callback-fed telemetry and alert payloads",
        AttackSurfaceFamily::KernelCallbackReplay,
        TrustBoundary::KernelToUser,
        ExecutionLane::IsolatedVmKernel,
        RiskTier::High,
        true,
        true,
        {
            "PhantomSensor\\Shared\\MessageProtocol.h",
            "PhantomSensor\\PhantomSensor\\Callbacks\\Registry\\RegistryCallback.c",
            "PhantomSensor\\PhantomSensor\\ALPC\\AlpcPortMonitor.c"
        },
        {
            "invalid path lengths",
            "zero and sentinel process IDs",
            "unknown enum values",
            "duplicate event storms"
        },
        {
            "serialization never overruns buffers",
            "message ordering remains recoverable",
            "user-mode consumers can reject malformed payloads deterministically"
        }));

    surfaces.push_back(MakeSurface(
        "phantomcore.ipc.filter-port-client",
        "PhantomCore",
        "FilterConnection / IPCManager",
        "Kernel filter-port client session",
        AttackSurfaceFamily::UserModeIpc,
        TrustBoundary::KernelToUser,
        ExecutionLane::BrokerProcess,
        RiskTier::Critical,
        true,
        false,
        {
            "src\\PhantomCore\\Communication\\FilterConnection.cpp",
            "src\\PhantomCore\\Communication\\IPCManager.cpp",
            "PhantomSensor\\Shared\\MessageProtocol.h"
        },
        {
            "async cancellation races",
            "reply correlation mismatches",
            "key exchange corruption",
            "encrypted message truncation"
        },
        {
            "no deadlock on disconnect",
            "invalid messages fail without reply confusion",
            "key material is never reused after teardown"
        }));

    surfaces.push_back(MakeSurface(
        "phantomcore.ipc.named-pipe-broker",
        "PhantomCore",
        "ServiceCommunication named pipe listener",
        "Privileged local pipe protocol",
        AttackSurfaceFamily::UserModeIpc,
        TrustBoundary::LocalServiceToBroker,
        ExecutionLane::BrokerProcess,
        RiskTier::High,
        true,
        false,
        {
            "src\\PhantomCore\\Communication\\ServiceCommunication.cpp"
        },
        {
            "pipe squatting attempts",
            "session handshake fragmentation",
            "auth bypass framing",
            "client churn under overlapped I/O"
        },
        {
            "unauthorized clients never reach command handling",
            "listener remains live after malformed sessions",
            "max-client limits hold under churn"
        }));

    surfaces.push_back(MakeSurface(
        "phantomcore.parser.peparser",
        "PhantomCore",
        "PEParser / PEValidation",
        "PE32 and PE32+ images",
        AttackSurfaceFamily::Parser,
        TrustBoundary::UntrustedContentToEngine,
        ExecutionLane::InProcess,
        RiskTier::High,
        false,
        false,
        {
            "src\\PhantomCore\\PEParser\\PEParser.cpp",
            "src\\PhantomCore\\PEParser\\PEValidation.cpp"
        },
        {
            "header offset overflow",
            "directory overlap",
            "section table truncation",
            "resource and import recursion"
        },
        {
            "no integer overflow",
            "no out-of-bounds read",
            "parse result is internally self-consistent"
        }));

    surfaces.push_back(MakeSurface(
        "phantomcore.parser.threatintel",
        "PhantomCore",
        "ThreatIntelImporter / feed parsers",
        "IOC feeds, STIX-like objects, XML and JSON threat intel",
        AttackSurfaceFamily::Parser,
        TrustBoundary::UntrustedContentToEngine,
        ExecutionLane::InProcess,
        RiskTier::High,
        false,
        false,
        {
            "src\\PhantomCore\\ThreatIntel\\ThreatIntelImporter.cpp",
            "src\\PhantomCore\\ThreatIntel\\ThreatIntelFeedManager_parsers.cpp",
            "src\\PhantomCore\\ThreatIntel\\ThreatIntelFormat.cpp"
        },
        {
            "feed truncation",
            "nested object explosion",
            "URL and domain normalization skew",
            "invalid expiry and confidence ranges"
        },
        {
            "no silent partial import corruption",
            "deduplication remains stable",
            "invalid feeds fail explicitly"
        }));

    surfaces.push_back(MakeSurface(
        "phantomemulator.loader-and-dispatch",
        "PhantomEmulator",
        "Loader / APIDispatcher / NtFile handlers",
        "Synthetic program images and emulated API traces",
        AttackSurfaceFamily::Emulator,
        TrustBoundary::UntrustedContentToEngine,
        ExecutionLane::InProcess,
        RiskTier::High,
        true,
        false,
        {
            "PhantomEmulator\\Core\\Loader",
            "PhantomEmulator\\WinAPI\\APIDispatcher.cpp",
            "PhantomEmulator\\WinAPI\\Ntdll\\NtFile.cpp"
        },
        {
            "malformed import graphs",
            "API argument count skew",
            "syscall dispatch mismatch",
            "WoW64 boundary transitions"
        },
        {
            "decode and dispatch must not desynchronize engine state",
            "invalid traces terminate cleanly",
            "emulated handles remain internally consistent"
        }));

    surfaces.push_back(MakeSurface(
        "phantomdisassembler.decoder",
        "PhantomDisassembler",
        "Decoder / Formatter",
        "Instruction byte streams",
        AttackSurfaceFamily::Disassembler,
        TrustBoundary::UntrustedContentToEngine,
        ExecutionLane::InProcess,
        RiskTier::High,
        false,
        false,
        {
            "PhantomDisassembler\\Decoder.cpp",
            "PhantomDisassembler\\Formatter.cpp"
        },
        {
            "prefix storms",
            "length boundary truncation",
            "invalid modrm and sib combinations",
            "formatter round-trip stress"
        },
        {
            "decode length is never negative or zero for accepted instructions",
            "formatter never reads past decoded operands",
            "malformed streams fail without heap corruption"
        }));

    return surfaces;
}

}  // namespace

const std::vector<AttackSurfaceDescriptor>& AttackSurfaceRegistry::GetDefaultRegistry() noexcept {
    static const std::vector<AttackSurfaceDescriptor> registry = BuildRegistry();
    return registry;
}

const AttackSurfaceDescriptor* AttackSurfaceRegistry::FindById(const std::string_view id) noexcept {
    const auto& registry = GetDefaultRegistry();
    const auto match = std::find_if(registry.begin(), registry.end(),
        [&](const AttackSurfaceDescriptor& surface) { return surface.id == id; });

    return match == registry.end() ? nullptr : &(*match);
}

std::string AttackSurfaceRegistry::RenderJson(const std::vector<AttackSurfaceDescriptor>& surfaces) {
    std::ostringstream stream;
    stream << "{\n  \"attackSurfaces\": [\n";

    for (std::size_t index = 0; index < surfaces.size(); ++index) {
        const auto& surface = surfaces[index];
        stream << "    {\n"
               << "      \"id\": \"" << EscapeJson(surface.id) << "\",\n"
               << "      \"component\": \"" << EscapeJson(surface.component) << "\",\n"
               << "      \"entryPoint\": \"" << EscapeJson(surface.entryPoint) << "\",\n"
               << "      \"protocolOrFormat\": \"" << EscapeJson(surface.protocolOrFormat) << "\",\n"
               << "      \"family\": \"" << ToString(surface.family) << "\",\n"
               << "      \"trustBoundary\": \"" << ToString(surface.boundary) << "\",\n"
               << "      \"executionLane\": \"" << ToString(surface.executionLane) << "\",\n"
               << "      \"riskTier\": \"" << ToString(surface.riskTier) << "\",\n"
               << "      \"stateful\": " << (surface.stateful ? "true" : "false") << ",\n"
               << "      \"requiresVmIsolation\": " << (surface.requiresVmIsolation ? "true" : "false") << ",\n"
               << "      \"schemaSources\": ";
        AppendJsonArray(stream, surface.schemaSources);
        stream << ",\n      \"mutationAxes\": ";
        AppendJsonArray(stream, surface.mutationAxes);
        stream << ",\n      \"invariants\": ";
        AppendJsonArray(stream, surface.invariants);
        stream << "\n    }";

        if (index + 1 != surfaces.size()) {
            stream << ',';
        }

        stream << '\n';
    }

    stream << "  ]\n}\n";
    return stream.str();
}

std::string AttackSurfaceRegistry::DescribeText(const AttackSurfaceDescriptor& surface) {
    std::ostringstream stream;
    stream << "Id: " << surface.id << '\n'
           << "Component: " << surface.component << '\n'
           << "Entry point: " << surface.entryPoint << '\n'
           << "Protocol/Format: " << surface.protocolOrFormat << '\n'
           << "Family: " << ToString(surface.family) << '\n'
           << "Trust boundary: " << ToString(surface.boundary) << '\n'
           << "Execution lane: " << ToString(surface.executionLane) << '\n'
           << "Risk tier: " << ToString(surface.riskTier) << '\n'
           << "Stateful: " << (surface.stateful ? "yes" : "no") << '\n'
           << "Requires VM isolation: " << (surface.requiresVmIsolation ? "yes" : "no") << '\n';

    stream << "Schema sources:\n";
    for (const auto& schema : surface.schemaSources) {
        stream << "  - " << schema << '\n';
    }

    stream << "Mutation axes:\n";
    for (const auto& axis : surface.mutationAxes) {
        stream << "  - " << axis << '\n';
    }

    stream << "Invariants:\n";
    for (const auto& invariant : surface.invariants) {
        stream << "  - " << invariant << '\n';
    }

    return stream.str();
}

}  // namespace ShadowStrike::Fuzzer
