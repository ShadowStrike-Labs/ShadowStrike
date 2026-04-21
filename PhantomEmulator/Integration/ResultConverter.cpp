/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ResultConverter.cpp — Full conversion from Phantom analysis types to
 *                       ShadowStrike::Core::Engine::EmulationResult
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "ResultConverter.hpp"

// Phantom types
#include "../Common/Types.hpp"
#include "../Common/Config.hpp"
#include "../WinAPI/APITypes.hpp"
#include "../Analysis/ThreatScorer.hpp"
#include "../Analysis/BehaviorMonitor.hpp"
#include "../Analysis/MITREMapper.hpp"
#include "../Analysis/UnpackingEngine.hpp"
#include "../Analysis/IOCExtractor.hpp"
#include "../Analysis/MemoryForensics.hpp"
#include "../Analysis/NetworkBehaviorAnalyzer.hpp"
#include "../Analysis/EvasionDetector.hpp"

// ShadowStrike types
#include "../../src/PhantomCore/Core/Engine/EmulationEngine.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <unordered_set>

namespace Phantom::Integration {

// ============================================================================
// Enum mapping helpers
// ============================================================================

ShadowStrike::Core::Engine::EmulationState
ResultConverter::ConvertStopReason(Phantom::StopReason reason) noexcept
{
    using SS = ShadowStrike::Core::Engine::EmulationState;
    switch (reason) {
    case StopReason::None:               return SS::Running;
    case StopReason::InstructionLimit:   return SS::InstructionLimit;
    case StopReason::TimeLimit:          return SS::Timeout;
    case StopReason::MemoryLimit:        return SS::MemoryLimit;
    case StopReason::ExitProcess:        return SS::Completed;
    case StopReason::UnpackComplete:     return SS::Completed;
    case StopReason::Breakpoint:         return SS::Paused;
    case StopReason::UserAborted:        return SS::Terminated;
    case StopReason::InvalidInstruction: return SS::Error;
    case StopReason::AccessViolation:    return SS::Error;
    case StopReason::DivideByZero:       return SS::Error;
    case StopReason::StackOverflow:      return SS::Error;
    case StopReason::Crashed:            return SS::Error;
    case StopReason::Syscall:            return SS::Completed;
    case StopReason::APICallTrap:        return SS::Detected;
    default:                             return SS::Error;
    }
}

ShadowStrike::Core::Engine::EmulationExitReason
ResultConverter::ConvertExitReason(Phantom::StopReason reason) noexcept
{
    using SS = ShadowStrike::Core::Engine::EmulationExitReason;
    switch (reason) {
    case StopReason::None:               return SS::Unknown;
    case StopReason::InstructionLimit:   return SS::InstructionLimit;
    case StopReason::TimeLimit:          return SS::Timeout;
    case StopReason::MemoryLimit:        return SS::MemoryLimit;
    case StopReason::ExitProcess:        return SS::NormalExit;
    case StopReason::UnpackComplete:     return SS::UnpackComplete;
    case StopReason::Breakpoint:         return SS::Breakpoint;
    case StopReason::UserAborted:        return SS::UserTerminated;
    case StopReason::InvalidInstruction: return SS::InvalidInstruction;
    case StopReason::AccessViolation:    return SS::AccessViolation;
    case StopReason::DivideByZero:       return SS::Exception;
    case StopReason::StackOverflow:      return SS::Exception;
    case StopReason::Crashed:            return SS::Exception;
    case StopReason::Syscall:            return SS::NormalExit;
    case StopReason::APICallTrap:        return SS::MalwareDetected;
    default:                             return SS::InternalError;
    }
}

ShadowStrike::Core::Engine::APICategory
ResultConverter::ConvertAPICategory(Phantom::APICategory cat) noexcept
{
    using SS = ShadowStrike::Core::Engine::APICategory;
    switch (cat) {
    case Phantom::APICategory::FileSystem:      return SS::FileSystem;
    case Phantom::APICategory::Registry:        return SS::Registry;
    case Phantom::APICategory::Process:         return SS::Process;
    case Phantom::APICategory::Thread:          return SS::Process;
    case Phantom::APICategory::Memory:          return SS::Memory;
    case Phantom::APICategory::Network:         return SS::Network;
    case Phantom::APICategory::Crypto:          return SS::Crypto;
    case Phantom::APICategory::Security:        return SS::Security;
    case Phantom::APICategory::ModuleLoading:   return SS::DynamicCode;
    case Phantom::APICategory::Synchronization: return SS::Sync;
    case Phantom::APICategory::SystemInfo:      return SS::SystemInfo;
    case Phantom::APICategory::AntiDebug:       return SS::AntiAnalysis;
    case Phantom::APICategory::AntiVM:          return SS::AntiAnalysis;
    case Phantom::APICategory::COM:             return SS::Unknown;
    case Phantom::APICategory::Service:         return SS::Service;
    case Phantom::APICategory::Environment:     return SS::SystemInfo;
    case Phantom::APICategory::Time:            return SS::SystemInfo;
    case Phantom::APICategory::Console:         return SS::UI;
    case Phantom::APICategory::Unknown:         return SS::Unknown;
    default:                                    return SS::Unknown;
    }
}

ShadowStrike::Core::Engine::APISeverity
ResultConverter::ConvertAlertSeverity(Phantom::AlertSeverity sev) noexcept
{
    using SS = ShadowStrike::Core::Engine::APISeverity;
    switch (sev) {
    case AlertSeverity::Info:     return SS::Benign;
    case AlertSeverity::Low:      return SS::Low;
    case AlertSeverity::Medium:   return SS::Medium;
    case AlertSeverity::High:     return SS::High;
    case AlertSeverity::Critical: return SS::Critical;
    default:                      return SS::Benign;
    }
}

ShadowStrike::Core::Engine::PackerType
ResultConverter::ConvertPackerType(Phantom::PackerType packer) noexcept
{
    using SS = ShadowStrike::Core::Engine::PackerType;

    // Phantom::PackerType is uint8_t, ShadowStrike::PackerType is uint16_t.
    // Both share the same semantic values for common packers but with different
    // numeric assignments.  Map explicitly.
    switch (packer) {
    case Phantom::PackerType::Unknown:          return SS::Unknown;
    case Phantom::PackerType::UPX:              return SS::UPX;
    case Phantom::PackerType::ASPack:           return SS::ASPack;
    case Phantom::PackerType::PECompact:        return SS::PECompact;
    case Phantom::PackerType::Themida:          return SS::Themida;
    case Phantom::PackerType::VMProtect:        return SS::VMProtect;
    case Phantom::PackerType::Armadillo:        return SS::Armadillo;
    case Phantom::PackerType::MPRESS:           return SS::MPRESS;
    case Phantom::PackerType::Petite:           return SS::Petite;
    case Phantom::PackerType::FSG:              return SS::FSG;
    case Phantom::PackerType::MEW:              return SS::MEW;
    case Phantom::PackerType::NsPack:           return SS::NsPack;
    case Phantom::PackerType::Obsidium:         return SS::Obsidium;
    case Phantom::PackerType::ExeCryptor:       return SS::ExeCryptor;
    case Phantom::PackerType::ASProtect:        return SS::ASProtect;
    case Phantom::PackerType::Enigma:           return SS::Enigma;
    case Phantom::PackerType::CodeVirtualizer:  return SS::CodeVirtualizer;
    case Phantom::PackerType::DotNetObfuscator: return SS::ConfuserEx;
    case Phantom::PackerType::PackerCustom:     return SS::CustomCrypter;
    // Phantom-only packers that don't have a 1:1 ShadowStrike match
    case Phantom::PackerType::PEtite:           return SS::Petite;
    case Phantom::PackerType::tElock:           return SS::CustomCrypter;
    case Phantom::PackerType::PESpin:           return SS::CustomCrypter;
    case Phantom::PackerType::MoleBox:          return SS::CustomCrypter;
    case Phantom::PackerType::BoxedApp:         return SS::CustomCrypter;
    case Phantom::PackerType::StarForce:        return SS::CustomCrypter;
    case Phantom::PackerType::SafeDisc:         return SS::CustomCrypter;
    case Phantom::PackerType::SecuROM:          return SS::CustomCrypter;
    case Phantom::PackerType::AutoIt:           return SS::CustomCrypter;
    case Phantom::PackerType::NSIS:             return SS::CustomCrypter;
    case Phantom::PackerType::InnoSetup:        return SS::CustomCrypter;
    case Phantom::PackerType::PyInstaller:      return SS::CustomCrypter;
    default:                                    return SS::Unknown;
    }
}

ShadowStrike::Core::Engine::EmulationArch
ResultConverter::ConvertTarget(Phantom::EmulationTarget target) noexcept
{
    using SS = ShadowStrike::Core::Engine::EmulationArch;
    switch (target) {
    case EmulationTarget::PE32:          return SS::X86;
    case EmulationTarget::PE64:          return SS::X64;
    case EmulationTarget::Shellcode32:   return SS::X86;
    case EmulationTarget::Shellcode64:   return SS::X64;
    case EmulationTarget::DLL32:         return SS::X86;
    case EmulationTarget::DLL64:         return SS::X64;
    default:                             return SS::X64;
    }
}

std::string
ResultConverter::MalwareCategoryName(Phantom::MalwareCategory cat) noexcept
{
    switch (cat) {
    case MalwareCategory::Unknown:        return "Unknown";
    case MalwareCategory::Trojan:         return "Trojan";
    case MalwareCategory::Ransomware:     return "Ransomware";
    case MalwareCategory::Worm:           return "Worm";
    case MalwareCategory::Backdoor:       return "Backdoor";
    case MalwareCategory::RAT:            return "RAT";
    case MalwareCategory::Dropper:        return "Dropper";
    case MalwareCategory::Downloader:     return "Downloader";
    case MalwareCategory::Rootkit:        return "Rootkit";
    case MalwareCategory::Keylogger:      return "Keylogger";
    case MalwareCategory::Spyware:        return "Spyware";
    case MalwareCategory::Adware:         return "Adware";
    case MalwareCategory::CoinMiner:      return "CoinMiner";
    case MalwareCategory::Wiper:          return "Wiper";
    case MalwareCategory::BankingTrojan:  return "BankingTrojan";
    case MalwareCategory::InfoStealer:    return "InfoStealer";
    case MalwareCategory::Botnet:         return "Botnet";
    case MalwareCategory::Exploit:        return "Exploit";
    case MalwareCategory::APTImplant:     return "APTImplant";
    case MalwareCategory::Fileless:       return "Fileless";
    default:                              return "Unknown";
    }
}

// ============================================================================
// APICallDetail → APICallRecord
// ============================================================================

ShadowStrike::Core::Engine::APICallRecord
ResultConverter::ConvertAPICall(const Phantom::APICallDetail& call) noexcept
{
    ShadowStrike::Core::Engine::APICallRecord rec{};

    rec.timestamp       = std::chrono::steady_clock::now();
    rec.callerAddress   = 0; // Phantom doesn't track caller address separately
    rec.returnAddress   = call.returnAddress;
    rec.dllName         = call.dllName ? call.dllName : "";
    rec.functionName    = call.funcName ? call.funcName : "";
    rec.category        = ConvertAPICategory(call.category);
    rec.severity        = ShadowStrike::Core::Engine::APISeverity::Low;
    rec.returnValue     = call.returnValue;
    rec.success         = call.succeeded;
    rec.instructionCount = call.instructionNum;
    rec.threadId        = call.threadId;

    // Classify severity based on behavior flags
    const auto flags = static_cast<uint32_t>(call.behaviorFlags);
    if (flags & (static_cast<uint32_t>(BehaviorFlag::ProcessInjection)
               | static_cast<uint32_t>(BehaviorFlag::ProcessHollowing)
               | static_cast<uint32_t>(BehaviorFlag::DLLInjection)
               | static_cast<uint32_t>(BehaviorFlag::CodeInjection))) {
        rec.severity = ShadowStrike::Core::Engine::APISeverity::Critical;
    } else if (flags & (static_cast<uint32_t>(BehaviorFlag::RegistryPersistence)
                      | static_cast<uint32_t>(BehaviorFlag::PrivilegeEscalation)
                      | static_cast<uint32_t>(BehaviorFlag::CredentialAccess))) {
        rec.severity = ShadowStrike::Core::Engine::APISeverity::High;
    } else if (flags & (static_cast<uint32_t>(BehaviorFlag::NetworkC2)
                      | static_cast<uint32_t>(BehaviorFlag::AntiAnalysis)
                      | static_cast<uint32_t>(BehaviorFlag::DefenseEvasion)
                      | static_cast<uint32_t>(BehaviorFlag::SuspiciousAPI))) {
        rec.severity = ShadowStrike::Core::Engine::APISeverity::Medium;
    } else if (flags & (static_cast<uint32_t>(BehaviorFlag::FileDropped)
                      | static_cast<uint32_t>(BehaviorFlag::MemoryManipulation))) {
        rec.severity = ShadowStrike::Core::Engine::APISeverity::Low;
    } else {
        rec.severity = ShadowStrike::Core::Engine::APISeverity::Benign;
    }

    // Serialize arguments to strings
    rec.arguments.reserve(call.argCount);
    for (uint32_t i = 0; i < call.argCount && i < 8; ++i) {
        char buf[24];
        std::snprintf(buf, sizeof(buf), "0x%llX",
                      static_cast<unsigned long long>(call.args[i]));
        rec.arguments.emplace_back(buf);
    }

    if (call.wasBlocked) {
        rec.notes = "Blocked by emulator policy";
    }

    return rec;
}

// ============================================================================
// MITRETechnique → DetectedTechnique
// ============================================================================

ShadowStrike::Core::Engine::DetectedTechnique
ResultConverter::ConvertMITRE(const Phantom::MITRETechnique& tech) noexcept
{
    ShadowStrike::Core::Engine::DetectedTechnique dt{};
    dt.techniqueId   = tech.id   ? tech.id   : "";
    dt.techniqueName = tech.name ? tech.name : "";
    dt.tactic        = tech.tactic ? tech.tactic : "";
    dt.confidence    = tech.confidence;
    dt.detectionTime = std::chrono::steady_clock::now();

    // Combine evidence vector into a single evidence string
    std::string combined;
    for (size_t i = 0; i < tech.evidence.size(); ++i) {
        if (i > 0) combined += "; ";
        combined += tech.evidence[i];
    }
    dt.evidence = std::move(combined);

    return dt;
}

// ============================================================================
// Phantom UnpackLayer → ShadowStrike UnpackLayer
// ============================================================================

ShadowStrike::Core::Engine::UnpackLayer
ResultConverter::ConvertUnpackLayer(const Phantom::UnpackLayer& layer) noexcept
{
    ShadowStrike::Core::Engine::UnpackLayer out{};
    out.layerNumber         = layer.layerIndex;
    out.packerType          = ConvertPackerType(layer.packer);
    out.packerVersion       = "";
    out.originalEntryPoint  = layer.entryPoint;
    out.unpackedEntryPoint  = layer.oep;
    out.unpackedBase        = layer.codeBase;
    out.unpackedSize        = layer.codeSize;
    out.unpackedData        = layer.dumpedPE;
    out.sha256              = ""; // Caller can compute if needed
    out.entropyBefore       = layer.entropyBefore;
    out.entropyAfter        = layer.entropyAfter;
    out.instructionsExecuted = layer.instructionsExecuted;
    out.unpackTimeMs        = 0; // Phantom tracks instruction count, not wall time per layer
    out.oepConfidence       = layer.isComplete ? 1.0f : 0.5f;

    switch (layer.oepMethod) {
    case OEPMethod::WXTransition:       out.detectionMethod = "W-X Transition"; break;
    case OEPMethod::TailJump:           out.detectionMethod = "Tail Jump"; break;
    case OEPMethod::APICallAfterDecode: out.detectionMethod = "API Call After Decode"; break;
    case OEPMethod::EntropyDrop:        out.detectionMethod = "Entropy Drop"; break;
    case OEPMethod::IATReconstruction:  out.detectionMethod = "IAT Reconstruction"; break;
    case OEPMethod::StackFrame:         out.detectionMethod = "Stack Frame Prologue"; break;
    case OEPMethod::SectionEntry:       out.detectionMethod = "Section Entry"; break;
    case OEPMethod::UserDefined:        out.detectionMethod = "User Breakpoint"; break;
    default:                            out.detectionMethod = "Unknown"; break;
    }

    return out;
}

// ============================================================================
// Helper: classify an API call as "suspicious" by checking behavior flags
// ============================================================================

static bool IsAPISuspicious(const Phantom::APICallDetail& call) noexcept
{
    const auto flags = static_cast<uint32_t>(call.behaviorFlags);
    return flags != static_cast<uint32_t>(BehaviorFlag::None);
}

// ============================================================================
// Helper: determine IsMalicious from ThreatLevel
// ============================================================================

static bool IsThreatLevelMalicious(ThreatLevel level) noexcept
{
    return level == ThreatLevel::Malicious || level == ThreatLevel::Critical;
}

// ============================================================================
// Helper: build threat name from verdict
// ============================================================================

static std::string BuildThreatName(const ThreatVerdict& verdict) noexcept
{
    if (verdict.level == ThreatLevel::Clean) return "";
    std::string name = ResultConverter::MalwareCategoryName(verdict.primaryCategory);
    if (verdict.secondaryCategory != MalwareCategory::Unknown) {
        name += '/';
        name += ResultConverter::MalwareCategoryName(verdict.secondaryCategory);
    }
    return name;
}

// ============================================================================
// Helper: extract network data from IOC entries
// ============================================================================

static void ExtractNetworkFromIOCs(
    const IOCReport& report,
    std::unordered_set<std::string>& domains,
    std::unordered_set<std::string>& ips) noexcept
{
    for (const auto& ioc : report.indicators) {
        switch (ioc.type) {
        case IOCType::Domain:
            domains.insert(ioc.value);
            break;
        case IOCType::IPv4:
        case IOCType::IPv6:
            ips.insert(ioc.value);
            break;
        default:
            break;
        }
    }
}

// ============================================================================
// Helper: convert NetworkConnection → NetworkActivity
// ============================================================================

static ShadowStrike::Core::Engine::NetworkActivity
ConvertNetworkConnection(const Phantom::NetworkConnection& conn) noexcept
{
    ShadowStrike::Core::Engine::NetworkActivity act{};

    // Map protocol string to NetworkActivity::Type
    if (conn.protocol == "tcp" || conn.protocol == "TCP") {
        act.type = ShadowStrike::Core::Engine::NetworkActivity::Type::TCPConnect;
    } else if (conn.protocol == "udp" || conn.protocol == "UDP") {
        act.type = ShadowStrike::Core::Engine::NetworkActivity::Type::UDPSend;
    } else if (conn.protocol == "http" || conn.protocol == "HTTP") {
        act.type = ShadowStrike::Core::Engine::NetworkActivity::Type::HTTPRequest;
    } else if (conn.protocol == "https" || conn.protocol == "HTTPS") {
        act.type = ShadowStrike::Core::Engine::NetworkActivity::Type::HTTPSRequest;
    } else if (conn.protocol == "dns" || conn.protocol == "DNS") {
        act.type = ShadowStrike::Core::Engine::NetworkActivity::Type::DNSQuery;
    } else {
        act.type = ShadowStrike::Core::Engine::NetworkActivity::Type::Unknown;
    }

    act.ipAddress   = conn.remoteAddr;
    act.port        = conn.remotePort;
    act.protocol    = conn.protocol;
    act.timestamp   = std::chrono::steady_clock::now();
    act.success     = (conn.connectionCount > 0);
    act.isC2Indicator = conn.isBeaconing;

    if (conn.isBeaconing) {
        act.notes = "Beaconing pattern detected";
    }

    return act;
}

// ============================================================================
// Helper: convert Phantom::MemoryRegion → ShadowStrike::MemoryRegion
// ============================================================================

static ShadowStrike::Core::Engine::MemoryRegion
ConvertMemoryRegion(const Phantom::MemoryRegion& mr) noexcept
{
    ShadowStrike::Core::Engine::MemoryRegion out{};
    out.baseAddress = mr.base;
    out.size        = mr.size;

    if (mr.isStack) {
        out.type = ShadowStrike::Core::Engine::MemoryRegionType::Stack;
    } else if (mr.isHeap) {
        out.type = ShadowStrike::Core::Engine::MemoryRegionType::Heap;
    } else if (mr.isMapped) {
        out.type = ShadowStrike::Core::Engine::MemoryRegionType::MappedFile;
    } else {
        out.type = ShadowStrike::Core::Engine::MemoryRegionType::Unknown;
    }

    out.protection = static_cast<uint32_t>(mr.protection);
    out.readable   = (static_cast<uint8_t>(mr.protection) &
                      static_cast<uint8_t>(MemProt::Read)) != 0;
    out.writable   = (static_cast<uint8_t>(mr.protection) &
                      static_cast<uint8_t>(MemProt::Write)) != 0;
    out.executable = (static_cast<uint8_t>(mr.protection) &
                      static_cast<uint8_t>(MemProt::Execute)) != 0;
    out.committed  = true;
    out.dirty      = mr.wasWritten;

    return out;
}

// ============================================================================
// Helper: map BehaviorAlert to injection-attempt strings
// ============================================================================

static void CollectInjectionAttempts(
    std::span<const BehaviorAlert> alerts,
    std::vector<std::string>& injections) noexcept
{
    for (const auto& alert : alerts) {
        switch (alert.category) {
        case BehaviorCategory::ProcessInjection:
        case BehaviorCategory::ProcessHollowing:
        case BehaviorCategory::DLLInjection:
        case BehaviorCategory::ReflectiveDLLLoad:
        case BehaviorCategory::ShellcodeExecution:
            injections.push_back(alert.description);
            break;
        default:
            break;
        }
    }
}

// ============================================================================
// Helper: map BehaviorAlert to anti-analysis technique strings
// ============================================================================

static void CollectAntiAnalysis(
    std::span<const BehaviorAlert> alerts,
    std::vector<std::string>& techniques) noexcept
{
    for (const auto& alert : alerts) {
        if (alert.category == BehaviorCategory::DefenseEvasion) {
            techniques.push_back(alert.description);
        }
    }
}

// ============================================================================
// Helper: count threads from API calls (distinct threadId values)
// ============================================================================

static uint32_t CountUniqueThreads(
    std::span<const APICallDetail> calls) noexcept
{
    if (calls.empty()) return 0;

    // Small bitset-style counting — threadIds in Phantom are uint16_t
    constexpr size_t kMaxThreadBits = 65536 / 64;
    uint64_t seen[kMaxThreadBits]{};

    uint32_t count = 0;
    for (const auto& call : calls) {
        const uint16_t tid = call.threadId;
        const size_t word = tid / 64;
        const uint64_t bit = uint64_t{1} << (tid % 64);
        if ((seen[word] & bit) == 0) {
            seen[word] |= bit;
            ++count;
        }
    }
    return count;
}

// ============================================================================
// Helper: count unique API names
// ============================================================================

static size_t CountUniqueAPIs(
    std::span<const APICallDetail> calls) noexcept
{
    std::unordered_set<std::string> unique;
    unique.reserve(calls.size() / 4 + 1);
    for (const auto& call : calls) {
        if (call.funcName) {
            unique.emplace(call.funcName);
        }
    }
    return unique.size();
}

// ============================================================================
// Helper: build API summary (category → count)
// ============================================================================

static std::unordered_map<ShadowStrike::Core::Engine::APICategory, uint32_t>
BuildAPISummary(std::span<const APICallDetail> calls) noexcept
{
    std::unordered_map<ShadowStrike::Core::Engine::APICategory, uint32_t> summary;
    for (const auto& call : calls) {
        auto cat = ResultConverter::ConvertAPICategory(call.category);
        ++summary[cat];
    }
    return summary;
}

// ============================================================================
// Helper: find primary MITRE tactic
// ============================================================================

static std::string FindPrimaryTactic(
    std::span<const MITRETechnique> techniques) noexcept
{
    if (techniques.empty()) return "";

    // Count tactic occurrences, weighted by confidence
    struct TacticScore { float total = 0.0f; uint32_t count = 0; };
    std::unordered_map<std::string, TacticScore> scores;

    for (const auto& tech : techniques) {
        if (tech.tactic) {
            auto& s = scores[tech.tactic];
            s.total += tech.confidence;
            ++s.count;
        }
    }

    std::string best;
    float bestScore = -1.0f;
    for (const auto& [tactic, s] : scores) {
        if (s.total > bestScore) {
            bestScore = s.total;
            best = tactic;
        }
    }
    return best;
}

// ============================================================================
// Helper: extract file-related IOCs into dropped/deleted/modified/read lists
// ============================================================================

static void ClassifyFileIOCs(
    const IOCReport& report,
    std::vector<std::wstring>& deleted,
    std::vector<std::wstring>& modified,
    std::vector<std::wstring>& filesRead) noexcept
{
    for (const auto& ioc : report.indicators) {
        if (ioc.type != IOCType::FilePath && ioc.type != IOCType::FileName) {
            continue;
        }
        // Convert UTF-8 value to wstring
        std::wstring wpath(ioc.value.begin(), ioc.value.end());

        // Use context to classify
        if (ioc.context.find("delete") != std::string::npos ||
            ioc.context.find("Delete") != std::string::npos) {
            deleted.push_back(std::move(wpath));
        } else if (ioc.context.find("write") != std::string::npos ||
                   ioc.context.find("Write") != std::string::npos ||
                   ioc.context.find("create") != std::string::npos ||
                   ioc.context.find("Create") != std::string::npos) {
            modified.push_back(std::move(wpath));
        } else {
            filesRead.push_back(std::move(wpath));
        }
    }
}

// ============================================================================
// Helper: extract registry IOCs into RegistryModification records
// ============================================================================

static void ClassifyRegistryIOCs(
    const IOCReport& report,
    std::vector<ShadowStrike::Core::Engine::RegistryModification>& mods,
    std::vector<ShadowStrike::Core::Engine::RegistryModification>& persistence) noexcept
{
    for (const auto& ioc : report.indicators) {
        if (ioc.type != IOCType::RegistryKey && ioc.type != IOCType::RegistryValue) {
            continue;
        }

        ShadowStrike::Core::Engine::RegistryModification rm{};
        rm.keyPath   = std::wstring(ioc.value.begin(), ioc.value.end());
        rm.success   = true;
        rm.timestamp = std::chrono::steady_clock::now();

        if (ioc.type == IOCType::RegistryValue) {
            rm.operation = ShadowStrike::Core::Engine::RegistryModification::Operation::SetValue;
        } else {
            rm.operation = ShadowStrike::Core::Engine::RegistryModification::Operation::CreateKey;
        }

        // Check for persistence-related registry paths
        const auto& val = ioc.value;
        bool isPersistence =
            val.find("\\Run") != std::string::npos ||
            val.find("\\RunOnce") != std::string::npos ||
            val.find("\\Services\\") != std::string::npos ||
            val.find("\\CurrentVersion\\Image File Execution") != std::string::npos ||
            val.find("\\Shell\\Open\\Command") != std::string::npos ||
            val.find("\\Winlogon\\") != std::string::npos ||
            val.find("\\Explorer\\ShellIconOverlayIdentifiers") != std::string::npos ||
            val.find("\\AppInit_DLLs") != std::string::npos ||
            val.find("\\Policies\\Explorer\\Run") != std::string::npos;

        rm.isPersistenceAttempt = isPersistence;
        mods.push_back(rm);

        if (isPersistence) {
            rm.notes = "Persistence mechanism: " + ioc.context;
            persistence.push_back(std::move(rm));
        }
    }
}

// ============================================================================
// Convert() — Full PhantomEmulationResult → ShadowStrike EmulationResult
// ============================================================================

ShadowStrike::Core::Engine::EmulationResult
ResultConverter::Convert(const PhantomEmulationResult& pr) noexcept
{
    ShadowStrike::Core::Engine::EmulationResult out{};

    // ---- Detection Status ----
    if (pr.verdict) {
        out.isMalicious    = IsThreatLevelMalicious(pr.verdict->level);
        out.threatScore    = pr.verdict->score;
        out.confidence     = pr.verdict->confidence;
        out.threatName     = BuildThreatName(*pr.verdict);
        out.threatCategory = MalwareCategoryName(pr.verdict->primaryCategory);
        out.threatFamily   = pr.verdict->summary;
    }

    // ---- Emulation Status ----
    out.state              = ConvertStopReason(pr.stopReason);
    out.exitReason         = ConvertExitReason(pr.stopReason);
    out.backend            = ShadowStrike::Core::Engine::EmulationBackend::Auto;
    out.architecture       = ConvertTarget(pr.target);
    out.emulationComplete  = (pr.stopReason == StopReason::ExitProcess ||
                              pr.stopReason == StopReason::UnpackComplete);

    // If detected as malicious, override state
    if (out.isMalicious && out.state == ShadowStrike::Core::Engine::EmulationState::Completed) {
        out.state = ShadowStrike::Core::Engine::EmulationState::Detected;
    }

    // ---- Execution Statistics ----
    out.instructionsExecuted = pr.instructionsExecuted;
    out.emulationTimeMs      = pr.emulationTimeMs;
    out.peakMemoryUsage      = pr.peakMemoryUsage;
    out.contextSwitches      = pr.contextSwitches;
    out.exceptionsHandled    = pr.exceptionsHandled;

    if (pr.emulationTimeMs > 0) {
        out.instructionsPerSecond =
            static_cast<double>(pr.instructionsExecuted) /
            (static_cast<double>(pr.emulationTimeMs) / 1000.0);
    }

    // ---- API Activity ----
    out.apiCallCount  = pr.apiCalls.size();
    out.uniqueAPIsCount = CountUniqueAPIs(pr.apiCalls);

    out.apiCalls.reserve(pr.apiCalls.size());
    for (const auto& call : pr.apiCalls) {
        auto converted = ConvertAPICall(call);
        if (IsAPISuspicious(call)) {
            out.suspiciousAPIs.push_back(converted);
        }
        out.apiCalls.push_back(std::move(converted));
    }

    out.apiSummary = BuildAPISummary(pr.apiCalls);

    // ---- Process / Thread ----
    out.threadsCreated = CountUniqueThreads(pr.apiCalls);

    // Collect injection attempts from behavior alerts
    CollectInjectionAttempts(pr.behaviorAlerts, out.injectionAttempts);

    // ---- MITRE ATT&CK ----
    out.mitreTechniques.reserve(pr.mitreTechniques.size());
    for (const auto& tech : pr.mitreTechniques) {
        out.mitreTechniques.push_back(ConvertMITRE(tech));
    }
    out.primaryTactic = FindPrimaryTactic(pr.mitreTechniques);

    // ---- Unpacking ----
    out.wasPacked = !pr.unpackLayers.empty();
    out.unpackSuccessful = pr.unpackSuccessful;
    out.unpackedSha256   = pr.unpackedSha256;

    if (!pr.unpackedPayload.empty()) {
        out.unpackedPayload.assign(pr.unpackedPayload.begin(),
                                   pr.unpackedPayload.end());
    }

    out.unpackLayers.reserve(pr.unpackLayers.size());
    for (const auto& layer : pr.unpackLayers) {
        out.unpackLayers.push_back(ConvertUnpackLayer(layer));
        auto ssPackerType = ConvertPackerType(layer.packer);
        if (ssPackerType != ShadowStrike::Core::Engine::PackerType::Unknown) {
            out.detectedPackers.push_back(ssPackerType);
        }
    }

    // Build packer name from first detected packer
    if (!pr.unpackLayers.empty()) {
        out.packerName = PackerTypeName(pr.unpackLayers[0].packer);
    }

    // ---- YARA / Signatures ----
    out.yaraMatches.assign(pr.yaraMatches.begin(), pr.yaraMatches.end());
    out.memoryYaraMatches.assign(pr.memoryYaraMatches.begin(),
                                 pr.memoryYaraMatches.end());
    out.patternMatches.assign(pr.patternMatches.begin(),
                              pr.patternMatches.end());

    // ---- Memory Regions ----
    out.memoryRegions.reserve(pr.memoryRegions.size());
    for (const auto& mr : pr.memoryRegions) {
        auto converted = ConvertMemoryRegion(mr);
        if (converted.executable && converted.writable) {
            out.rwxRegions.push_back(converted);
        }
        out.memoryRegions.push_back(std::move(converted));
    }

    // Suspicious regions from memory findings
    for (const auto& finding : pr.memoryFindings) {
        ShadowStrike::Core::Engine::MemoryRegion sr{};
        sr.baseAddress = finding.address;
        sr.size        = finding.size;
        sr.entropy     = finding.entropy;
        sr.type        = ShadowStrike::Core::Engine::MemoryRegionType::Unknown;

        switch (finding.type) {
        case MemoryFinding::ShellcodeNopSled:
        case MemoryFinding::ShellcodeDecoderStub:
        case MemoryFinding::ShellcodeEggHunter:
        case MemoryFinding::ShellcodeEncodedPayload:
        case MemoryFinding::StackShellcode:
            sr.type = ShadowStrike::Core::Engine::MemoryRegionType::Shellcode;
            break;
        case MemoryFinding::HeapSprayPattern:
        case MemoryFinding::HeapSprayNopRun:
            sr.type = ShadowStrike::Core::Engine::MemoryRegionType::Heap;
            break;
        case MemoryFinding::PEHeaderInMemory:
        case MemoryFinding::PEDOSStub:
            sr.type = ShadowStrike::Core::Engine::MemoryRegionType::Image;
            break;
        default:
            break;
        }

        sr.committed = true;
        out.suspiciousRegions.push_back(std::move(sr));
    }

    // ---- Network Activity ----
    out.networkActivities.reserve(pr.networkConnections.size());
    for (const auto& conn : pr.networkConnections) {
        auto act = ConvertNetworkConnection(conn);
        if (act.isC2Indicator) {
            out.c2Indicators.push_back(act);
        }
        out.networkActivities.push_back(std::move(act));
    }

    // Extract domains/IPs from IOC report
    if (pr.iocReport) {
        ExtractNetworkFromIOCs(*pr.iocReport, out.domainsContacted,
                               out.ipsContacted);
    }

    // ---- File System Activity ----
    if (pr.iocReport) {
        ClassifyFileIOCs(*pr.iocReport, out.deletedFiles, out.modifiedFiles,
                         out.filesRead);
    }

    // ---- Registry Activity ----
    if (pr.iocReport) {
        ClassifyRegistryIOCs(*pr.iocReport, out.registryModifications,
                             out.persistenceAttempts);
    }

    // ---- Evasion Detection ----
    CollectAntiAnalysis(pr.behaviorAlerts, out.antiAnalysisTechniques);

    if (pr.evasionSummary) {
        out.vmDetectionAttempts       = pr.evasionSummary->antiVMCount;
        out.debuggerDetectionAttempts = pr.evasionSummary->antiDebugCount;
        out.sandboxDetectionAttempts  = pr.evasionSummary->antiSandboxCount;
        out.timingCheckAttempts       = pr.evasionSummary->antiAnalysisCount;
    }

    // Supplement anti-analysis from evasion attempts
    for (const auto& ev : pr.evasionAttempts) {
        if (!ev.description.empty()) {
            // Avoid duplicates
            bool found = false;
            for (const auto& existing : out.antiAnalysisTechniques) {
                if (existing == ev.description) { found = true; break; }
            }
            if (!found) {
                out.antiAnalysisTechniques.push_back(ev.description);
            }
        }
    }

    // ---- Metadata ----
    out.sessionId     = pr.sessionId;
    out.startTime     = std::chrono::system_clock::now() -
                        std::chrono::milliseconds(pr.emulationTimeMs);
    out.endTime       = std::chrono::system_clock::now();
    out.inputSha256   = pr.inputSha256;
    out.inputSize     = pr.inputSize;
    out.inputFileType = pr.inputFileType;

    return out;
}

} // namespace Phantom::Integration
