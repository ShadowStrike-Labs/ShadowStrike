/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * EmulationSession.cpp — Master orchestrator implementation
 *
 * Wires CPU, Memory, MemoryTracker, APIDispatcher, EnvironmentBuilder,
 * PELoader, ShellcodeLoader, and all 11 analysis modules into a single
 * emulation pipeline. Each Emulate*() call executes the full lifecycle:
 *   Phase 1: Environment setup (memory, PEB/TEB, OS subsystems)
 *   Phase 2: Payload loading (PE or shellcode)
 *   Phase 3: API dispatcher wiring (hook addresses, import resolution)
 *   Phase 4: CPU execution with live analysis callbacks
 *   Phase 5: Post-execution bulk analysis (forensics, strings, crypto, IOCs)
 *   Phase 6: Threat scoring and result collection
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "EmulationSession.hpp"

// Core
#include "../Core/CPU/CPU.hpp"
#include "../Core/Memory/VirtualMemory.hpp"
#include "../Core/Memory/MemoryTracker.hpp"

// Loaders
#include "../Core/Loader/PELoader.hpp"
#include "../Core/Loader/ShellcodeLoader.hpp"
#include "../Core/Loader/ExportResolver.hpp"
#include "../Core/Loader/ImportResolver.hpp"
#include "../Core/Loader/HashResolver.hpp"

// Exception Handling
#include "../Core/CPU/ExceptionDispatcher.hpp"
#include "../Core/CPU/HardwareBreakpoints.hpp"

// WinAPI
#include "../WinAPI/APIDispatcher.hpp"
#include "../WinAPI/Bcrypt/BcryptAPI.hpp"
#include "../WinAPI/Amsi/AmsiAPI.hpp"
#include "../WinAPI/Ntdll/EtwAPI.hpp"
#include "../WinAPI/Vss/VssAPI.hpp"
#include "../WinAPI/Ole32/WmiEmulation.hpp"

// CLR/.NET Analysis
#include "../Analysis/DotNetAnalyzer.hpp"

// VirtualOS
#include "../VirtualOS/EnvironmentBuilder.hpp"

// Integration
#include "YaraScanner.hpp"
#include "ProcessManager.hpp"

// WoW64
#include "../Core/WoW64/WoW64Layer.hpp"

// Hardware Acceleration (Phase 6)
#include "../Core/Accel/SIMDEngine.hpp"
#include "../Core/Accel/CryptoAccelerator.hpp"
#include "../Core/Accel/MemoryScanAccel.hpp"
#include "../Core/JIT/JITOptimizer.hpp"

// Kernel-Mode Emulation (Phase 7)
#include "../Core/Kernel/KernelAddressSpace.hpp"
#include "../Core/Kernel/KernelStructures.hpp"
#include "../Core/Kernel/MSREmulation.hpp"
#include "../Core/Kernel/RingTransition.hpp"
#include "../Core/Kernel/DriverLoader.hpp"
#include "../Analysis/DKOMDetector.hpp"
#include "../WinAPI/Kernel/KernelAPI.hpp"

// Analysis (all 11 modules)
#include "../Analysis/BehaviorMonitor.hpp"
#include "../Analysis/APISequenceAnalyzer.hpp"
#include "../Analysis/MemoryForensics.hpp"
#include "../Analysis/UnpackingEngine.hpp"
#include "../Analysis/ThreatScorer.hpp"
#include "../Analysis/MITREMapper.hpp"
#include "../Analysis/IOCExtractor.hpp"
#include "../Analysis/StringExtractor.hpp"
#include "../Analysis/CryptoDetector.hpp"
#include "../Analysis/NetworkBehaviorAnalyzer.hpp"
#include "../Analysis/EvasionDetector.hpp"

// Common
#include "../Common/Platform.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>

namespace Phantom {

// ============================================================================
// Internal Constants
// ============================================================================

// API hook region: a contiguous virtual memory block where each registered API
// gets a unique 8-byte-aligned sentinel address. When the CPU's RIP lands in
// this range, the API call callback fires and dispatches to the correct handler.
static constexpr GuestAddress kAPIHookBase = 0x00007FFE0F000000ULL;
static constexpr GuestSize    kAPIHookSize = 0x1000000ULL; // 16 MB

// Maximum bytes to scan from a single memory region during post-analysis to
// prevent pathological allocations from dominating scan time.
static constexpr size_t kMaxRegionScanBytes = 32ULL * 1024 * 1024;

// W-X transition batch limit: cap the number of transitions processed in one
// pass from the MemoryTracker to bound post-analysis latency.
static constexpr uint32_t kWXTransitionBatchLimit = 4096;

// Stack base address used for raw buffer emulation when no PELoader/
// ShellcodeLoader is involved.
static constexpr GuestAddress kBufferStackBase = 0x0000000090000000ULL;

// Shadow-space size for x64 Windows calling convention (4 register home + return addr)
static constexpr GuestSize kShadowSpace = 0x28;

// Periodic abort-check interval. Bit-mask applied to the instruction counter
// so we only check every N instructions. 0xFFF = every 4096 instructions.
static constexpr uint64_t kAbortCheckMask = 0xFFF;

// ============================================================================
// Helper: case-insensitive C-string comparison for API name matching
// ============================================================================

namespace {

[[nodiscard]] bool StrEqCI(const char* a, const char* b) noexcept {
    if (!a || !b) return false;
    while (*a && *b) {
        char ca = *a;
        char cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return false;
        ++a;
        ++b;
    }
    return *a == *b;
}

[[nodiscard]] bool StrContainsCI(const char* haystack, const char* needle) noexcept {
    if (!haystack || !needle || !*needle) return false;
    for (; *haystack; ++haystack) {
        const char* h = haystack;
        const char* n = needle;
        while (*h && *n) {
            char ch = *h;
            char cn = *n;
            if (ch >= 'A' && ch <= 'Z') ch += 32;
            if (cn >= 'A' && cn <= 'Z') cn += 32;
            if (ch != cn) break;
            ++h;
            ++n;
        }
        if (!*n) return true;
    }
    return false;
}

[[nodiscard]] bool IsNetworkCategory(APICategory cat) noexcept {
    return cat == APICategory::Network;
}

[[nodiscard]] bool IsCryptoCategory(APICategory cat) noexcept {
    return cat == APICategory::Crypto;
}

[[nodiscard]] bool IsFileSystemCategory(APICategory cat) noexcept {
    return cat == APICategory::FileSystem;
}

[[nodiscard]] bool IsRegistryCategory(APICategory cat) noexcept {
    return cat == APICategory::Registry;
}

[[nodiscard]] bool IsProcessCategory(APICategory cat) noexcept {
    return cat == APICategory::Process;
}

[[nodiscard]] bool IsAntiDebugCategory(APICategory cat) noexcept {
    return cat == APICategory::AntiDebug;
}

[[nodiscard]] bool IsAntiVMCategory(APICategory cat) noexcept {
    return cat == APICategory::AntiVM;
}

[[nodiscard]] bool IsTimingCategory(APICategory cat) noexcept {
    return cat == APICategory::Time;
}

[[nodiscard]] bool IsServiceCategory(APICategory cat) noexcept {
    return cat == APICategory::Service;
}

[[nodiscard]] bool IsSyncCategory(APICategory cat) noexcept {
    return cat == APICategory::Synchronization;
}

// Determine if an API function name relates to DNS queries
[[nodiscard]] bool IsDnsRelated(const char* funcName) noexcept {
    return StrContainsCI(funcName, "DnsQuery") ||
           StrContainsCI(funcName, "getaddrinfo") ||
           StrContainsCI(funcName, "gethostbyname") ||
           StrContainsCI(funcName, "GetAddrInfo");
}

// Determine if an API function name relates to HTTP requests
[[nodiscard]] bool IsHttpRelated(const char* funcName) noexcept {
    return StrContainsCI(funcName, "HttpSendRequest") ||
           StrContainsCI(funcName, "HttpOpenRequest") ||
           StrContainsCI(funcName, "WinHttpSendRequest") ||
           StrContainsCI(funcName, "WinHttpOpenRequest") ||
           StrContainsCI(funcName, "InternetOpenUrl") ||
           StrContainsCI(funcName, "URLDownloadToFile");
}

// Determine if an API function name relates to network connections
[[nodiscard]] bool IsConnectRelated(const char* funcName) noexcept {
    return StrEqCI(funcName, "connect") ||
           StrContainsCI(funcName, "InternetConnect") ||
           StrContainsCI(funcName, "WinHttpConnect") ||
           StrContainsCI(funcName, "WSAConnect");
}

// Determine if an API function name relates to sending data
[[nodiscard]] bool IsSendRelated(const char* funcName) noexcept {
    return StrEqCI(funcName, "send") ||
           StrEqCI(funcName, "sendto") ||
           StrContainsCI(funcName, "WSASend") ||
           StrContainsCI(funcName, "InternetWriteFile") ||
           StrContainsCI(funcName, "WinHttpWriteData");
}

// Determine if an API function name relates to receiving data
[[nodiscard]] bool IsRecvRelated(const char* funcName) noexcept {
    return StrEqCI(funcName, "recv") ||
           StrEqCI(funcName, "recvfrom") ||
           StrContainsCI(funcName, "WSARecv") ||
           StrContainsCI(funcName, "InternetReadFile") ||
           StrContainsCI(funcName, "WinHttpReadData");
}

// Determine if an API function name relates to mutex creation
[[nodiscard]] bool IsMutexRelated(const char* funcName) noexcept {
    return StrContainsCI(funcName, "CreateMutex") ||
           StrContainsCI(funcName, "OpenMutex");
}

// Determine if an API function name relates to pipe creation
[[nodiscard]] bool IsPipeRelated(const char* funcName) noexcept {
    return StrContainsCI(funcName, "CreateNamedPipe") ||
           StrContainsCI(funcName, "CreatePipe");
}

// Determine if an API function name relates to service creation
[[nodiscard]] bool IsServiceCreation(const char* funcName) noexcept {
    return StrContainsCI(funcName, "CreateService") ||
           StrContainsCI(funcName, "OpenService");
}

// Determine if an API function name relates to process creation
[[nodiscard]] bool IsProcessCreation(const char* funcName) noexcept {
    return StrContainsCI(funcName, "CreateProcess") ||
           StrContainsCI(funcName, "ShellExecute") ||
           StrContainsCI(funcName, "WinExec");
}

// Determine if an API is a crypto function (CryptXxx or BCryptXxx)
[[nodiscard]] bool IsCryptoAPICall(const char* funcName) noexcept {
    return StrContainsCI(funcName, "Crypt") ||
           StrContainsCI(funcName, "BCrypt") ||
           StrContainsCI(funcName, "CryptEncrypt") ||
           StrContainsCI(funcName, "CryptDecrypt") ||
           StrContainsCI(funcName, "CryptHashData");
}

// Determine if an API function relates to user-agent strings
[[nodiscard]] bool IsUserAgentRelated(const char* funcName) noexcept {
    return StrContainsCI(funcName, "InternetOpen") ||
           StrContainsCI(funcName, "WinHttpOpen");
}

} // anonymous namespace

// ============================================================================
// PIMPL Implementation
// ============================================================================

struct EmulationSession::Impl {

    // ========================================================================
    // Member Variables
    // ========================================================================

    // Configuration (copy-owned by the session)
    EmulationConfig m_config;

    // Core subsystems
    CPU            m_cpu;
    VirtualMemory  m_memory;
    MemoryTracker  m_tracker;

    // Export resolver (populated by PELoader for loaded DLLs)
    ExportResolver m_exports;

    // API dispatcher (constructed after m_memory is initialised)
    std::unique_ptr<APIDispatcher> m_dispatcher;

    // Analysis modules (all 11)
    BehaviorMonitor         m_behaviorMonitor;
    APISequenceAnalyzer     m_apiSequenceAnalyzer;
    MemoryForensics         m_memoryForensics;
    UnpackingEngine         m_unpackingEngine;
    ThreatScorer            m_threatScorer;
    MITREMapper             m_mitreMapper;
    IOCExtractor            m_iocExtractor;
    StringExtractor         m_stringExtractor;
    CryptoDetector          m_cryptoDetector;
    NetworkBehaviorAnalyzer m_networkAnalyzer;
    EvasionDetector         m_evasionDetector;

    // Phase 2 modules — API hash resolution, YARA scanning, exception dispatch
    HashResolver            m_hashResolver;
    YaraScanner             m_yaraScanner;
    ExceptionDispatcher     m_exceptionDispatcher;

    // Phase 3 modules — hardware breakpoints, multi-process, WoW64
    HardwareBreakpoints     m_hwBreakpoints;
    ProcessManager          m_processManager;
    WoW64Layer              m_wow64Layer;

    // Phase 5 .NET/CLR analysis result (populated by CollectDotNetForensics)
    CLR::DotNetAnalysisResult m_dotNetResult;

    // Phase 6 hardware acceleration modules
    SIMDEngine          m_simdEngine;
    CryptoAccelerator   m_cryptoAccelerator;
    MemoryScanAccel     m_memoryScanAccel;
    JITOptimizer        m_jitOptimizer;

    // Session state
    std::atomic<bool> m_abortRequested{false};
    bool              m_executed = false;

    // Wall-clock timing
    uint64_t m_startTicks = 0;
    uint64_t m_tickFreq   = 0;

    // Loaded target descriptor (filled by Load* methods)
    struct LoadedTarget {
        GuestAddress entryPoint = 0;
        GuestAddress imageBase  = 0;
        GuestSize    imageSize  = 0;
        bool         is64Bit    = true;
    };

    // ========================================================================
    // Construction
    // ========================================================================

    explicit Impl(const EmulationConfig& config) noexcept
        : m_config(config)
        , m_memory(config.maxGuestMemory)
        , m_behaviorMonitor(config)
        , m_apiSequenceAnalyzer(config)
        , m_memoryForensics(config)
        , m_unpackingEngine(config)
        , m_threatScorer(config)
        , m_iocExtractor(config)
        , m_stringExtractor(config)
        , m_cryptoDetector(config)
        , m_networkAnalyzer(config)
        , m_evasionDetector(config)
        , m_processManager(config)
    {}

    // ========================================================================
    // Input Validation
    // ========================================================================

    [[nodiscard]] bool ValidateConfig(std::string& errorOut) const noexcept {
        if (m_config.maxInstructions == 0) {
            errorOut = "Config validation: maxInstructions must be > 0";
            return false;
        }
        if (m_config.maxGuestMemory == 0) {
            errorOut = "Config validation: maxGuestMemory must be > 0";
            return false;
        }
        if (m_config.maxGuestMemory > kMaxGuestMemory) {
            errorOut = "Config validation: maxGuestMemory exceeds platform limit (" +
                       std::to_string(kMaxGuestMemory) + " bytes)";
            return false;
        }
        if (m_config.stackSize == 0 || m_config.stackSize > m_config.maxGuestMemory) {
            errorOut = "Config validation: invalid stackSize";
            return false;
        }
        if (m_config.maxWallTime.count() <= 0) {
            errorOut = "Config validation: maxWallTime must be > 0";
            return false;
        }
        return true;
    }

    [[nodiscard]] bool ValidatePEInput(std::span<const uint8_t> peData,
                                       std::string& errorOut) const noexcept {
        if (peData.empty()) {
            errorOut = "EmulatePE: empty PE data";
            return false;
        }
        // Minimum size: DOS header (64 bytes) + PE signature pointer at offset 0x3C
        if (peData.size() < 64) {
            errorOut = "EmulatePE: PE data too small for DOS header (need >= 64 bytes, got " +
                       std::to_string(peData.size()) + ")";
            return false;
        }
        // Validate MZ signature
        if (peData[0] != 0x4D || peData[1] != 0x5A) {
            errorOut = "EmulatePE: invalid MZ signature (expected 0x4D5A, got 0x" +
                       ToHexByte(peData[0]) + ToHexByte(peData[1]) + ")";
            return false;
        }
        // Read e_lfanew (PE header offset) at 0x3C
        uint32_t lfanew = 0;
        std::memcpy(&lfanew, peData.data() + 0x3C, sizeof(uint32_t));
        if (lfanew == 0 || lfanew >= peData.size()) {
            errorOut = "EmulatePE: e_lfanew (0x" + ToHex32(lfanew) +
                       ") points outside PE data";
            return false;
        }
        // Validate PE signature at e_lfanew
        if (lfanew + 4 > peData.size()) {
            errorOut = "EmulatePE: PE header truncated at e_lfanew offset";
            return false;
        }
        uint32_t peSig = 0;
        std::memcpy(&peSig, peData.data() + lfanew, sizeof(uint32_t));
        if (peSig != 0x00004550) { // "PE\0\0"
            errorOut = "EmulatePE: invalid PE signature at e_lfanew (expected 0x4550, got 0x" +
                       ToHex32(peSig) + ")";
            return false;
        }
        // Validate minimum COFF header
        if (lfanew + 24 > peData.size()) {
            errorOut = "EmulatePE: PE COFF header truncated";
            return false;
        }
        // Validate machine type
        uint16_t machine = 0;
        std::memcpy(&machine, peData.data() + lfanew + 4, sizeof(uint16_t));
        if (machine != 0x014C && machine != 0x8664) {
            errorOut = "EmulatePE: unsupported machine type 0x" + ToHex16(machine);
            return false;
        }
        // Size cap: reject PE files larger than configured guest memory
        if (peData.size() > m_config.maxGuestMemory) {
            errorOut = "EmulatePE: PE file size (" + std::to_string(peData.size()) +
                       " bytes) exceeds maxGuestMemory limit";
            return false;
        }
        return true;
    }

    [[nodiscard]] bool ValidateShellcodeInput(std::span<const uint8_t> code,
                                               std::string& errorOut) const noexcept {
        if (code.empty()) {
            errorOut = "EmulateShellcode: empty shellcode buffer";
            return false;
        }
        if (code.size() > m_config.maxGuestMemory) {
            errorOut = "EmulateShellcode: buffer size (" + std::to_string(code.size()) +
                       " bytes) exceeds maxGuestMemory limit";
            return false;
        }
        return true;
    }

    [[nodiscard]] bool ValidateBufferInput(std::span<const uint8_t> buffer,
                                            GuestAddress base, GuestAddress entry,
                                            std::string& errorOut) const noexcept {
        if (buffer.empty()) {
            errorOut = "EmulateBuffer: empty buffer";
            return false;
        }
        if (buffer.size() > m_config.maxGuestMemory) {
            errorOut = "EmulateBuffer: buffer size exceeds maxGuestMemory limit";
            return false;
        }
        if (entry < base) {
            errorOut = "EmulateBuffer: entry point (0x" + ToHex64(entry) +
                       ") is below buffer base (0x" + ToHex64(base) + ")";
            return false;
        }
        if ((entry - base) >= buffer.size()) {
            errorOut = "EmulateBuffer: entry point offset (0x" +
                       ToHex64(entry - base) + ") exceeds buffer size (" +
                       std::to_string(buffer.size()) + ")";
            return false;
        }
        // Check for address overflow: base + size must not wrap
        if (base + buffer.size() < base) {
            errorOut = "EmulateBuffer: address overflow (base + size wraps)";
            return false;
        }
        return true;
    }

    // ========================================================================
    // Hex formatting helpers (allocation-free for small integers)
    // ========================================================================

    [[nodiscard]] static std::string ToHexByte(uint8_t val) noexcept {
        char buf[3];
        static constexpr char hex[] = "0123456789ABCDEF";
        buf[0] = hex[(val >> 4) & 0xF];
        buf[1] = hex[val & 0xF];
        buf[2] = '\0';
        return std::string(buf, 2);
    }

    [[nodiscard]] static std::string ToHex16(uint16_t val) noexcept {
        char buf[5];
        static constexpr char hex[] = "0123456789ABCDEF";
        buf[0] = hex[(val >> 12) & 0xF];
        buf[1] = hex[(val >> 8) & 0xF];
        buf[2] = hex[(val >> 4) & 0xF];
        buf[3] = hex[val & 0xF];
        buf[4] = '\0';
        return std::string(buf, 4);
    }

    [[nodiscard]] static std::string ToHex32(uint32_t val) noexcept {
        char buf[9];
        static constexpr char hex[] = "0123456789ABCDEF";
        for (int i = 7; i >= 0; --i) {
            buf[i] = hex[val & 0xF];
            val >>= 4;
        }
        buf[8] = '\0';
        return std::string(buf, 8);
    }

    [[nodiscard]] static std::string ToHex64(uint64_t val) noexcept {
        char buf[17];
        static constexpr char hex[] = "0123456789ABCDEF";
        for (int i = 15; i >= 0; --i) {
            buf[i] = hex[val & 0xF];
            val >>= 4;
        }
        buf[16] = '\0';
        return std::string(buf, 16);
    }

    // ========================================================================
    // Phase 1: Environment Setup
    // ========================================================================
    // Builds the virtual Windows environment: PEB, TEB, LDR data,
    // virtual filesystem/registry/process tables, anti-evasion modules.

    [[nodiscard]] bool SetupEnvironment(std::string& errorOut) noexcept {
        // Reset the singleton environment builder for this session
        auto& envBuilder = VirtualOS::EnvironmentBuilder::Instance();
        envBuilder.Reset();

        // Reset Phase 4 module singletons so each session starts clean
        WinAPI::Amsi::AmsiState::Instance().Reset();
        WinAPI::Ntdll::EtwState::Instance().Reset();
        WinAPI::Vss::VssDetector::Instance().Reset();
        WinAPI::Ole32::WmiState::Instance().Reset();
        CLR::DotNetAnalyzer::Instance().Reset();

        // Build the full virtual environment: filesystem, registry, process
        // table, network, timing, anti-evasion subsystems
        if (!envBuilder.Build(m_config)) {
            errorOut = "EnvironmentBuilder::Build failed — config validation error";

            // Attempt to get detailed validation errors
            auto validation = envBuilder.Validate();
            if (!validation.errors.empty()) {
                errorOut += ": " + validation.errors.front();
            }
            return false;
        }

        // Write PEB and TEB structures into guest memory
        if (!envBuilder.BuildPEBTEB(m_memory)) {
            errorOut = "EnvironmentBuilder::BuildPEBTEB failed — could not write "
                       "PEB/TEB structures into guest memory (allocation at 0x" +
                       ToHex64(WinConst::kPEBAddress64) + " may have failed)";
            return false;
        }

        return true;
    }

    // ========================================================================
    // Phase 2a: API Dispatcher Setup
    // ========================================================================
    // Constructs the APIDispatcher, registers all DLL handlers, and allocates
    // the hook memory region in guest address space.

    [[nodiscard]] bool SetupAPIDispatcher(std::string& errorOut) noexcept {
        // Construct dispatcher with reference to our memory and config
        m_dispatcher = std::make_unique<APIDispatcher>(m_memory, m_config);

        // Register all built-in DLL modules: ntdll, kernel32, advapi32,
        // ws2_32, wininet, winhttp, user32, shell32, ole32, urlmon
        m_dispatcher->RegisterAll();

        // Allocate the hook region in guest memory as RX. The CPU detects
        // when RIP enters this range and fires the APICallCallback before
        // fetching any real instructions from this region.
        auto allocResult = m_memory.Allocate(kAPIHookBase, kAPIHookSize, MemProt::RX);
        if (!allocResult.has_value()) {
            errorOut = "Failed to allocate API hook region (" +
                       std::to_string(kAPIHookSize) + " bytes at 0x" +
                       ToHex64(kAPIHookBase) + ") — guest memory pressure";
            return false;
        }

        // Verify the allocation landed where we requested (critical for
        // address-based dispatch to work correctly)
        if (allocResult.value() != kAPIHookBase) {
            errorOut = "API hook region allocated at wrong address (wanted 0x" +
                       ToHex64(kAPIHookBase) + ", got 0x" +
                       ToHex64(allocResult.value()) + ")";
            return false;
        }

        return true;
    }

    // ========================================================================
    // Phase 2b: Load PE Executable
    // ========================================================================

    [[nodiscard]] bool LoadPE(ByteSpan peData, LoadedTarget& target,
                              std::string& errorOut) noexcept {
        // Create an import resolver backed by our export database
        ImportResolver imports(m_exports);
        imports.SetAPIHookRange(kAPIHookBase, kAPIHookSize);

        // API hooks must be registered before PELoader resolves the import
        // table; otherwise IAT slots receive auto-allocated addresses that do
        // not match the dispatcher's handler map.
        m_dispatcher->WireImports(imports, kAPIHookBase, kAPIHookSize);

        // Construct the PE loader
        PELoader loader(m_memory, m_exports, imports);

        // Parse and map the PE into guest memory
        auto result = loader.Load(peData, m_config);
        if (!result.Ok()) {
            errorOut = "PE load failed";
            if (!result.errorDetail.empty()) {
                errorOut += ": " + result.errorDetail;
            }
            errorOut += " (ErrorCode " +
                        std::to_string(static_cast<uint32_t>(result.error)) + ")";
            return false;
        }

        const auto& image = result.image;

        // Validate the loaded image has a sane entry point
        if (image.entryPoint == 0) {
            errorOut = "PE load succeeded but entry point is null";
            return false;
        }

        // Fill in the target descriptor
        target.entryPoint = image.entryPoint;
        target.imageBase  = image.imageBase;
        target.imageSize  = image.totalMapped;
        target.is64Bit    = image.is64Bit;

        // Build the PEB LDR data now that modules are mapped in memory.
        // This populates the InLoadOrderModuleList/InMemoryOrderModuleList
        // that malware frequently walks to find DLL bases.
        auto& envBuilder = VirtualOS::EnvironmentBuilder::Instance();
        if (!envBuilder.BuildLdrData(m_memory)) {
            // Non-fatal: some analysis is still possible without LDR data.
            // Many PE samples work fine without it, but anti-analysis malware
            // may behave differently.
        }

        // Configure the CPU's initial register state from the PE image:
        // RIP = entry point, RSP = stack top, GS:0x30 = TEB, etc.
        loader.PrepareCPUState(m_cpu, image, m_config);

        // Run packer detection on the loaded image. This happens before
        // execution starts so we can tag known packers in the result even
        // if unpacking fails or the sample is not packed.
        RunPackerDetection(image.imageBase, image.totalMapped);

        // Build the API hash table from resolved exports. This enables
        // detection of hash-based import resolution used by shellcode
        // and packers (e.g., CRC32-rotate, DJB2, FNV-1a lookups).
        m_hashResolver.BuildFromExports(m_exports);

        // Notify MemoryForensics about the initial allocations for baseline
        NotifyInitialAllocations(image);

        return true;
    }

    // ========================================================================
    // Phase 2c: Load Shellcode
    // ========================================================================

    [[nodiscard]] bool LoadShellcode(ByteSpan code, bool is64Bit,
                                     LoadedTarget& target,
                                     std::string& errorOut) noexcept {
        ImportResolver imports(m_exports);
        imports.SetAPIHookRange(kAPIHookBase, kAPIHookSize);

        ShellcodeLoader loader(m_memory);
        auto result = loader.Load(code, m_config);

        if (!result.Ok()) {
            errorOut = "Shellcode load failed (ErrorCode " +
                       std::to_string(static_cast<uint32_t>(result.error)) + ")";
            return false;
        }

        const auto& sc = result.shellcode;

        if (sc.entryPoint == 0) {
            errorOut = "Shellcode load succeeded but entry point is null";
            return false;
        }

        target.entryPoint = sc.entryPoint;
        target.imageBase  = sc.codeBase;
        target.imageSize  = sc.codeSize;
        target.is64Bit    = is64Bit;

        // Wire dispatcher hooks for shellcode — many shellcodes resolve and
        // call Win32 APIs via PEB walking + GetProcAddress patterns
        m_dispatcher->WireImports(imports, kAPIHookBase, kAPIHookSize);

        // Build LDR data
        auto& envBuilder = VirtualOS::EnvironmentBuilder::Instance();
        // DESIGN: BuildLdrData failure is non-fatal for shellcode — many
        // shellcode payloads either don't walk LDR at all or tolerate a
        // partially-populated PEB_LDR_DATA. We continue regardless and let
        // the in-guest code fall over deterministically if it depends on it,
        // which produces a cleaner emulation trace than aborting the session.
        (void)envBuilder.BuildLdrData(m_memory);

        // Configure CPU registers for shellcode entry
        loader.PrepareCPUState(m_cpu, sc, m_config);

        // Build hash table for shellcode's hash-based import resolution
        m_hashResolver.BuildFromExports(m_exports);

        return true;
    }

    // ========================================================================
    // Phase 2d: Load Raw Buffer
    // ========================================================================

    [[nodiscard]] bool LoadBuffer(ByteSpan buffer,
                                  GuestAddress base, GuestAddress entry,
                                  bool is64Bit,
                                  LoadedTarget& target,
                                  std::string& errorOut) noexcept {
        // Allocate and write the buffer into guest memory as RWX
        auto allocResult = m_memory.Allocate(base, buffer.size(), MemProt::RWX);
        if (!allocResult.has_value()) {
            errorOut = "EmulateBuffer: failed to allocate " +
                       std::to_string(buffer.size()) + " bytes at 0x" +
                       ToHex64(base) + " in guest memory";
            return false;
        }

        GuestAddress actualBase = allocResult.value();

        // Write the buffer contents
        auto writeErr = m_memory.Write(actualBase, buffer.data(),
                                       static_cast<uint32_t>(buffer.size()));
        if (writeErr != ErrorCode::Success) {
            errorOut = "EmulateBuffer: Write failed (ErrorCode " +
                       std::to_string(static_cast<uint32_t>(writeErr)) + ")";
            return false;
        }

        // Track the RWX allocation for analysis
        m_tracker.RecordRWXAllocation(actualBase, buffer.size());

        target.entryPoint = entry;
        target.imageBase  = actualBase;
        target.imageSize  = buffer.size();
        target.is64Bit    = is64Bit;

        // Wire API dispatcher even for raw buffers
        ImportResolver imports(m_exports);
        imports.SetAPIHookRange(kAPIHookBase, kAPIHookSize);
        m_dispatcher->WireImports(imports, kAPIHookBase, kAPIHookSize);

        auto& envBuilder = VirtualOS::EnvironmentBuilder::Instance();
        // DESIGN: BuildLdrData failure is non-fatal for raw buffers (same
        // reasoning as the shellcode path above).
        (void)envBuilder.BuildLdrData(m_memory);

        // Configure CPU manually (no PE/shellcode loader to do this)
        SetupCPUForBuffer(entry, is64Bit, errorOut);

        // Build hash table for buffer's hash-based import resolution
        m_hashResolver.BuildFromExports(m_exports);

        return true;
    }

    // ========================================================================
    // CPU Setup for Raw Buffer
    // ========================================================================

    void SetupCPUForBuffer(GuestAddress entry, bool is64Bit,
                           std::string& errorOut) noexcept {
        CPUState& cpu = m_cpu.State();
        if (is64Bit) {
            cpu.Reset64();
        } else {
            cpu.Reset32();
        }
        cpu.SetRIP(entry);

        // Allocate a stack for execution
        auto stackAlloc = m_memory.Allocate(kBufferStackBase,
                                             m_config.stackSize, MemProt::RW);
        if (stackAlloc.has_value()) {
            GuestAddress stackTop = stackAlloc.value() + m_config.stackSize;
            // Align to 16-byte boundary and reserve shadow space
            GuestAddress rsp = AlignDown(stackTop - kShadowSpace, 16);
            cpu.SetReg64(GPR::RSP, rsp);
            cpu.SetReg64(GPR::RBP, rsp);

            // Write a sentinel return address on the stack. When the buffer
            // code executes RET, it will jump to an unmapped address and
            // trigger an access violation — a clean exit signal.
            constexpr uint64_t kSentinelReturn = 0xDEADDEADDEADDEADULL;
            const ErrorCode wErr = m_memory.WriteU64(rsp, kSentinelReturn);
            if (wErr != ErrorCode::Success) {
                // Sentinel write failed — buffer return semantics will fall
                // through to whatever zero/uninit data is on the stack page,
                // but the page itself is mapped RW so execution can proceed.
                // Surface the condition on the error channel for diagnostics
                // without aborting the session.
                errorOut = "EmulateBuffer: stack sentinel WriteU64 failed (ErrorCode " +
                           std::to_string(static_cast<uint32_t>(wErr)) + ") — continuing";
            }
        } else {
            // Stack allocation failed: the CPU has no valid RSP and the very
            // first push/call inside the buffer will fault. Make the failure
            // explicit so callers / telemetry see a real reason instead of
            // a silent crash trace.
            errorOut = "EmulateBuffer: failed to allocate " +
                       std::to_string(m_config.stackSize) +
                       " bytes for guest stack at 0x" + ToHex64(kBufferStackBase);
        }

        // Set segment bases for TEB/PEB access
        auto& envBuilder = VirtualOS::EnvironmentBuilder::Instance();
        if (envBuilder.IsInitialized()) {
            cpu.SetSegmentBase(SegReg::GS, envBuilder.GetTEBAddress());
        }
    }

    // ========================================================================
    // Packer Detection (pre-execution)
    // ========================================================================

    void RunPackerDetection(GuestAddress imageBase, GuestSize imageSize) noexcept {
        if (!m_config.enableUnpacking) return;

        PackerType packer = m_unpackingEngine.DetectPacker(
            m_memory, imageBase, imageSize);

        if (packer != PackerType::Unknown) {
            m_threatScorer.AddPackerDetection(packer);
            m_mitreMapper.OnPackerDetected(packer);
        }
    }

    // ========================================================================
    // Notify Initial Allocations to MemoryForensics
    // ========================================================================

    void NotifyInitialAllocations(const LoadedImage& image) noexcept {
        if (!m_config.enableMemoryForensics) return;

        // Notify about the main image mapping
        if (image.imageBase != 0 && image.totalMapped > 0) {
            m_memoryForensics.OnAllocation(image.imageBase,
                                           image.totalMapped, MemProt::RX);
        }

        // Notify about stack allocation
        if (image.stackBase != 0) {
            GuestSize stackSize = image.stackTop > image.stackBase
                                ? image.stackTop - image.stackBase
                                : m_config.stackSize;
            m_memoryForensics.OnAllocation(image.stackBase, stackSize, MemProt::RW);
        }

        // Notify about heap allocation
        if (image.heapBase != 0) {
            m_memoryForensics.OnAllocation(image.heapBase,
                                           m_config.heapSize, MemProt::RW);
        }
    }

    // ========================================================================
    // Phase 3: Wire CPU Callbacks
    // ========================================================================
    // Sets up all CPU callback hooks to integrate the API dispatcher and
    // analysis modules into the execution loop. The APICallCallback is the
    // most critical path — it fires for every emulated Win32/NT API call.

    void WireCPUCallbacks(const LoadedTarget& target) noexcept {
        // DESIGN: target is reserved for future per-target callback tuning
        // (e.g., enabling 32-bit-specific FS/GS context callbacks for WoW64
        // PEs). Currently the global hook range is sufficient. Keep the
        // parameter so the wiring contract is stable across future tuning.
        (void)target;
        // Tell the CPU where our hook sentinel addresses live
        m_cpu.SetAPIHookRange(kAPIHookBase, kAPIHookSize);

        // === API Call Callback (HOT PATH) ===
        // Called every time the CPU's RIP enters the hook region. Must:
        //   1. Dispatch the call to the correct handler
        //   2. Feed the call detail to all live-analysis modules
        //   3. Route network/crypto/IOC events to specialised analysers
        //
        // This is invoked 10K–100K+ times per session. Every microsecond
        // of overhead here multiplies across the entire trace.
        m_cpu.SetAPICallCallback(
            [this](CPUState& cpu, VirtualMemory& mem,
                   GuestAddress hookAddr) -> bool {
                return OnAPICall(cpu, mem, hookAddr);
            });

        // === Syscall Callback ===
        // Handles SYSCALL/SYSENTER instructions.
        m_cpu.SetSyscallCallback(
            [this](CPUState& cpu, VirtualMemory& mem) -> bool {
                return OnSyscall(cpu, mem);
            });

        // === Post-Instruction Callback ===
        // Per-instruction callback for unpacking heuristics. Only registered
        // when unpacking or full instruction trace is enabled because it
        // adds significant overhead to every instruction.
        if (m_config.enableInstructionTrace || m_config.enableUnpacking) {
            m_cpu.SetPostInstructionCallback(
                [this](const CPUState& cpu,
                       const DecodedInstruction& instr) {
                    OnPostInstruction(cpu, instr);
                });
        }

        // === Pre-Instruction Callback ===
        // Lightweight periodic checks: abort request, wall-clock time limit.
        // Uses a bitmask to fire only every 4096 instructions.
        m_cpu.SetPreInstructionCallback(
            [this](const CPUState& cpu,
                   const DecodedInstruction& instr) -> bool {
                return OnPreInstruction(cpu, instr);
            });

        // === Interrupt Callback ===
        // Routes software interrupts (INT 0x2E for legacy syscalls, INT3 for
        // breakpoints).
        m_cpu.SetInterruptCallback(
            [this](CPUState& cpu, VirtualMemory& mem, uint8_t vector) -> bool {
                return OnInterrupt(cpu, mem, vector);
            });

        // === Exception Dispatcher ===
        // Wire the ExceptionDispatcher into the CPU so that faults
        // (AV, divide-by-zero, etc.) route through VEH/SEH before
        // stopping. Enables analysis of malware that uses structured
        // exception handling for anti-debug or control-flow obfuscation.
        m_cpu.SetExceptionDispatcher(&m_exceptionDispatcher);

        // === Hardware Breakpoints ===
        // Wire the debug register engine into the CPU loop. This enables
        // DR0-DR3 execute/data breakpoint checks on every instruction and
        // Trap Flag single-step processing. Critical for:
        // - Anti-debug detection (malware reading/clearing DR7)
        // - Analysis tool support (analyst-set hardware BPs)
        // - INT1 exception generation for VEH/SEH dispatch
        m_cpu.SetHardwareBreakpoints(&m_hwBreakpoints);
    }

    // ========================================================================
    // CPU Callback: API Call (HOT PATH)
    // ========================================================================

    bool OnAPICall(CPUState& cpu, VirtualMemory& mem,
                   GuestAddress hookAddr) noexcept {
        // Step 1: Dispatch the call through the API framework
        bool handled = m_dispatcher->Dispatch(cpu, mem, hookAddr);
        if (!handled) {
            // Unknown API or handler returned false (e.g., ExitProcess).
            // If blockExternalCalls is off, we still want to continue.
            if (m_config.blockExternalCalls) {
                return false;
            }
            // Unrecognised call with blockExternalCalls=false: skip and continue.
            // The dispatcher already set RAX=0 / STATUS_NOT_IMPLEMENTED.
            return true;
        }

        // Step 2: Retrieve the just-logged call detail
        const auto& callLog = m_dispatcher->GetCallLog();
        if (callLog.empty()) {
            return true;
        }
        const APICallDetail& call = callLog.back();
        uint32_t callIndex = m_dispatcher->GetCallCount() - 1;

        // Step 3: Feed to live-analysis modules
        DispatchToAnalysisModules(call, callIndex, cpu);

        // Step 4: Route category-specific events to specialised analysers
        RouteNetworkEvents(call);
        RouteCryptoEvents(call);
        RouteIOCEvents(call);
        RouteEvasionEvents(call, cpu);
        RouteProcessEvents(call, cpu);

        // Step 5: Check for abort between API calls
        if (m_abortRequested.load(std::memory_order_relaxed)) {
            m_cpu.RequestAbort();
        }

        return true;
    }

    // ========================================================================
    // Feed API Call to Core Analysis Modules
    // ========================================================================

    void DispatchToAnalysisModules(const APICallDetail& call,
                                   uint32_t callIndex,
                                   const CPUState& cpu) noexcept {
        // BehaviorMonitor: stateful behavioral detection (process injection,
        // hollowing, persistence, credential access, etc.)
        if (m_config.enableBehaviorMonitor) {
            m_behaviorMonitor.OnAPICall(call, callIndex);
        }

        // APISequenceAnalyzer: N-gram pattern matching and Markov chain
        // transition anomaly detection on the API call sequence
        if (m_config.enableAPISequenceAnalysis) {
            m_apiSequenceAnalyzer.OnAPICall(call, callIndex);
        }

        // MITREMapper: maps each API call to MITRE ATT&CK techniques
        if (m_config.enableMITREMapping) {
            m_mitreMapper.OnAPICall(call);
        }

        // IOCExtractor: extracts IOCs from API call parameters
        // (file paths, registry keys, URLs, mutexes, etc.)
        if (m_config.enableIOCExtraction) {
            m_iocExtractor.OnAPICall(call);
        }

        // EvasionDetector: detects anti-debug, anti-VM, anti-sandbox attempts
        m_evasionDetector.OnAPICall(call);

        // UnpackingEngine: tracks API calls for OEP detection heuristics
        // (first API call after a long API-free decoding loop suggests OEP)
        if (m_config.enableUnpacking && call.funcName) {
            m_unpackingEngine.OnAPICall(call.funcName, cpu.instructionCount);
        }
    }

    // ========================================================================
    // Route Network-Related API Calls
    // ========================================================================
    // The NetworkBehaviorAnalyzer uses fine-grained event methods rather than
    // raw APICallDetail. We classify network-relevant API calls and route the
    // extracted parameters to the correct event handler.

    void RouteNetworkEvents(const APICallDetail& call) noexcept {
        if (!call.funcName) return;

        // Only process network-category APIs or known network functions
        if (!IsNetworkCategory(call.category) && !IsHttpRelated(call.funcName)) {
            return;
        }

        // DNS resolution
        if (IsDnsRelated(call.funcName)) {
            // arg[0] is typically the domain name pointer; we use the function
            // name as a proxy since we can't read the string from guest memory
            // in this hot path (IOCExtractor handles the actual extraction)
            m_networkAnalyzer.OnDnsQuery(call.funcName);
            return;
        }

        // Connection establishment
        if (IsConnectRelated(call.funcName)) {
            // For connect/InternetConnect, args vary but arg[0] or arg[1] is
            // typically the address and port
            m_networkAnalyzer.OnConnect("", 0, "tcp");
            return;
        }

        // Sending data
        if (IsSendRelated(call.funcName)) {
            // arg[1] is typically the buffer size
            uint32_t bytes = static_cast<uint32_t>(call.args[1] & 0xFFFFFFFF);
            m_networkAnalyzer.OnSend("", 0, bytes);
            return;
        }

        // Receiving data
        if (IsRecvRelated(call.funcName)) {
            uint32_t bytes = static_cast<uint32_t>(call.args[1] & 0xFFFFFFFF);
            m_networkAnalyzer.OnReceive("", 0, bytes);
            return;
        }

        // HTTP requests
        if (IsHttpRelated(call.funcName)) {
            m_networkAnalyzer.OnHttpRequest("", call.funcName, "");
            return;
        }

        // User-agent strings (InternetOpenA/W, WinHttpOpen)
        if (IsUserAgentRelated(call.funcName)) {
            m_iocExtractor.OnUserAgent(call.funcName);
        }
    }

    // ========================================================================
    // Route Crypto-Related API Calls
    // ========================================================================

    void RouteCryptoEvents(const APICallDetail& call) noexcept {
        if (!call.funcName) return;

        if (IsCryptoCategory(call.category) || IsCryptoAPICall(call.funcName)) {
            m_cryptoDetector.OnCryptoAPICall(call.funcName, call.args);
        }
    }

    // ========================================================================
    // Route IOC-Specific Events
    // ========================================================================
    // The IOCExtractor has granular event methods for specific IOC types.
    // We route API calls to the most specific handler available.

    void RouteIOCEvents(const APICallDetail& call) noexcept {
        if (!call.funcName) return;

        // Mutex creation
        if (IsMutexRelated(call.funcName)) {
            // The actual mutex name extraction is handled by IOCExtractor::OnAPICall.
            // This is a supplementary notification path.
            return;
        }

        // Named pipe creation
        if (IsPipeRelated(call.funcName)) {
            m_iocExtractor.OnPipeCreate(call.funcName);
            return;
        }

        // Service creation
        if (IsServiceCategory(call.category) && IsServiceCreation(call.funcName)) {
            // Service name extraction handled by IOCExtractor::OnAPICall
            return;
        }

        // Process creation (for command line IOC extraction)
        if (IsProcessCategory(call.category) && IsProcessCreation(call.funcName)) {
            // Command line extraction handled by IOCExtractor::OnAPICall
            return;
        }
    }

    // ========================================================================
    // Route Evasion-Specific Events
    // ========================================================================

    void RouteEvasionEvents(const APICallDetail& call,
                            const CPUState& cpu) noexcept {
        if (!call.funcName) return;

        // Timing-related checks: GetTickCount, QueryPerformanceCounter, etc.
        if (IsTimingCategory(call.category)) {
            m_evasionDetector.OnTimingCheck(cpu.rip, cpu.instructionCount);
        }

        // Anti-debug checks
        if (IsAntiDebugCategory(call.category)) {
            m_evasionDetector.OnEnvironmentQuery("anti-debug", call.funcName);
        }

        // Anti-VM checks
        if (IsAntiVMCategory(call.category)) {
            m_evasionDetector.OnEnvironmentQuery("anti-vm", call.funcName);
        }
    }

    // ========================================================================
    // Route Process/Injection Events to ProcessManager
    // ========================================================================
    // Detects cross-process operations used by sophisticated injection chains:
    // process hollowing, DLL injection, APC injection, thread hijacking.
    // Each matched API is routed to the ProcessManager's specialized handler.

    void RouteProcessEvents(const APICallDetail& call,
                            const CPUState& cpu) noexcept {
        // DESIGN: cpu is reserved for future register-derived heuristics
        // (e.g., reading thread-context register snapshots for SetThreadContext
        // to capture the staged shellcode RIP). Currently all routing
        // decisions are derived from the API call detail's argument array.
        (void)cpu;
        if (!m_config.enableMultiProcess || !call.funcName) return;

        const std::string_view fn{call.funcName};

        // === Process creation ===
        if (fn == "CreateProcessW" || fn == "CreateProcessA" ||
            fn == "CreateProcessInternalW" || fn == "NtCreateUserProcess") {
            // args[4] = dwCreationFlags (CREATE_SUSPENDED = 0x4)
            ProcessCreationFlags flags = ProcessCreationFlags::None;
            if (call.argCount > 4 && (call.args[4] & 0x4u)) {
                flags = ProcessCreationFlags::CreateSuspended;
            }
            // DESIGN: returned child PID is intentionally unused here —
            // ProcessManager retains the new entry in its internal table and
            // future routing (WriteProcessMemory, NtCreateThreadEx, etc.)
            // looks the child up by guest-supplied targetPid. Discarding the
            // return value here does not leak any state.
            (void)m_processManager.CreateChildProcess(
                L"<unknown>",   // imagePath (extracted by IOCExtractor)
                L"<unknown>",   // commandLine
                flags,
                1);             // parentPid = emulated process
            return;
        }

        // === Cross-process memory write (classic DLL/shellcode injection) ===
        // OnCrossProcessWrite takes ByteSpan — we construct an empty span here
        // because the actual data lives in guest memory. The ProcessManager
        // captures it internally using the injected region tracking.
        if (fn == "WriteProcessMemory" || fn == "NtWriteVirtualMemory") {
            uint32_t targetPid = static_cast<uint32_t>(call.args[0] & 0xFFFFFFFF);
            m_processManager.OnCrossProcessWrite(targetPid, call.args[1], {});
            return;
        }

        // === Cross-process memory allocation ===
        if (fn == "VirtualAllocEx" || fn == "NtAllocateVirtualMemory") {
            uint32_t targetPid = static_cast<uint32_t>(call.args[0] & 0xFFFFFFFF);
            GuestAddress addr = call.returnValue;
            auto size = static_cast<GuestSize>(call.args[2] & 0xFFFFFFFF);
            uint32_t protect = static_cast<uint32_t>(call.args[3] & 0xFFFFFFFF);
            m_processManager.OnCrossProcessAlloc(targetPid, addr, size, protect);
            return;
        }

        // === Section unmap (process hollowing step) ===
        if (fn == "NtUnmapViewOfSection" || fn == "NtUnmapViewOfSectionEx") {
            uint32_t targetPid = static_cast<uint32_t>(call.args[0] & 0xFFFFFFFF);
            m_processManager.OnSectionUnmap(targetPid, call.args[1]);
            return;
        }

        // === Thread context modification (process hollowing / thread hijack) ===
        if (fn == "SetThreadContext" || fn == "NtSetContextThread" ||
            fn == "Wow64SetThreadContext") {
            uint32_t targetPid = static_cast<uint32_t>(call.args[0] & 0xFFFFFFFF);
            uint32_t threadId  = static_cast<uint32_t>(call.args[1] & 0xFFFFFFFF);
            GuestAddress newRip = call.args[2];
            m_processManager.OnContextModification(targetPid, threadId, newRip);
            return;
        }

        // === Remote thread creation (classic DLL injection finale) ===
        if (fn == "CreateRemoteThread" || fn == "CreateRemoteThreadEx" ||
            fn == "NtCreateThreadEx" || fn == "RtlCreateUserThread") {
            uint32_t targetPid = static_cast<uint32_t>(call.args[0] & 0xFFFFFFFF);
            GuestAddress startAddr = call.args[2];
            uint64_t parameter = call.args[3];
            m_processManager.OnRemoteThreadCreation(targetPid, startAddr, parameter);
            return;
        }

        // === APC queue (early-bird injection, atom bombing step) ===
        if (fn == "QueueUserAPC" || fn == "NtQueueApcThread" ||
            fn == "NtQueueApcThreadEx") {
            uint32_t targetPid = static_cast<uint32_t>(call.args[0] & 0xFFFFFFFF);
            uint32_t threadId  = static_cast<uint32_t>(call.args[1] & 0xFFFFFFFF);
            GuestAddress apcRoutine = call.args[2];
            m_processManager.OnAPCQueue(targetPid, threadId, apcRoutine);
            return;
        }

        // === Resume thread (final step for many injection chains) ===
        if (fn == "ResumeThread" || fn == "NtResumeThread") {
            uint32_t targetPid = static_cast<uint32_t>(call.args[0] & 0xFFFFFFFF);
            // DESIGN: ResumeProcess returns false for unknown PIDs — that's
            // expected when the guest resumes a process it didn't create
            // through our emulator (e.g., the initial sample). The detection
            // value is in the *attempt*, which ProcessManager has already
            // recorded internally.
            (void)m_processManager.ResumeProcess(targetPid);
            return;
        }
    }

    // ========================================================================
    // CPU Callback: Syscall
    // ========================================================================

    bool OnSyscall(CPUState& cpu, VirtualMemory& mem) noexcept {
        // WoW64 syscall thunking: 32-bit processes on 64-bit Windows use a
        // translation layer. If the sample is a WoW64 process, intercept
        // and translate the syscall number through the thunk table before
        // dispatching to the standard 64-bit syscall handler.
        if (m_config.enableWoW64 && m_wow64Layer.IsInitialized()) {
            // Thunk 32-bit syscall number to 64-bit equivalent. A failed
            // thunk (unknown 32-bit syscall index) leaves the CPU state
            // unchanged so the standard 64-bit dispatcher below can still
            // reject it cleanly via DispatchSyscall returning false.
            (void)m_wow64Layer.ThunkSyscall(cpu, mem);
        }

        bool handled = m_dispatcher->DispatchSyscall(cpu, mem);

        // After syscall dispatch, feed the call to analysis modules the same
        // way we do for regular API calls (the dispatcher logs syscalls too)
        if (handled) {
            const auto& callLog = m_dispatcher->GetCallLog();
            if (!callLog.empty()) {
                const APICallDetail& call = callLog.back();
                uint32_t callIndex = m_dispatcher->GetCallCount() - 1;
                DispatchToAnalysisModules(call, callIndex, cpu);
                RouteNetworkEvents(call);
                RouteCryptoEvents(call);
                RouteIOCEvents(call);
                RouteEvasionEvents(call, cpu);
                RouteProcessEvents(call, cpu);
            }
        }

        return handled;
    }

    // ========================================================================
    // CPU Callback: Post-Instruction
    // ========================================================================

    void OnPostInstruction(const CPUState& cpu,
                           [[maybe_unused]] const DecodedInstruction& instr) noexcept {
        // Unpacking engine: per-instruction tracking for OEP detection.
        // This is the only module that needs per-instruction callbacks.
        if (m_config.enableUnpacking) {
            m_unpackingEngine.OnInstruction(cpu.rip, cpu.instructionCount);
        }
    }

    // ========================================================================
    // CPU Callback: Pre-Instruction
    // ========================================================================

    [[nodiscard]] bool OnPreInstruction(
        const CPUState& cpu,
        const DecodedInstruction& instr) noexcept {
        if (instr.prefixes.hasEVEX) {
            m_evasionDetector.OnInstructionProbe(
                cpu.rip, cpu.instructionCount, "EVEX / AVX-512 prefixed instruction");
        }

        // Only check every kAbortCheckMask instructions to amortise overhead
        if ((cpu.instructionCount & kAbortCheckMask) != 0) {
            return true;
        }

        // Check for external abort request
        if (m_abortRequested.load(std::memory_order_relaxed)) {
            return false;
        }

        // Check wall-clock time limit periodically (not every 4K instructions,
        // but every 64K to keep timing overhead minimal)
        if ((cpu.instructionCount & 0xFFFF) == 0 && m_tickFreq > 0) {
            uint64_t now = Platform::GetHighResolutionTicks();
            uint64_t elapsedMs = ((now - m_startTicks) * 1000ULL) / m_tickFreq;
            uint64_t limitMs = static_cast<uint64_t>(m_config.maxWallTime.count());
            if (elapsedMs >= limitMs) {
                return false; // Wall-clock time exceeded
            }
        }

        return true;
    }

    // ========================================================================
    // CPU Callback: Interrupt
    // ========================================================================

    bool OnInterrupt(CPUState& cpu, VirtualMemory& mem,
                     uint8_t vector) noexcept {
        switch (vector) {
            case 0x2E:
                // INT 0x2E: legacy Windows syscall interface (WinXP/2003)
                return OnSyscall(cpu, mem);

            case 0x03:
            case 0xCC:
                // INT3: software breakpoint — stop execution
                return false;

            case 0x01:
                // Single-step trap (TF flag) — used by some anti-debug techniques.
                // Feed to evasion detector and continue.
                m_evasionDetector.OnTimingCheck(cpu.rip, cpu.instructionCount);
                return true;

            case 0x0D:
                // General Protection Fault — stop execution
                return false;

            case 0x0E:
                // Page Fault — stop execution (we don't do demand paging)
                return false;

            case 0x06:
                // Invalid Opcode — stop execution
                return false;

            default:
                // Unknown software interrupt — ignore and continue.
                // Malware sometimes triggers interrupts to confuse analysis.
                return true;
        }
    }

    // ========================================================================
    // Phase 4: Execute CPU
    // ========================================================================

    [[nodiscard]] ExecutionResult RunCPU() noexcept {
        m_startTicks = Platform::GetHighResolutionTicks();
        m_tickFreq   = Platform::GetTickFrequency();

        // Enable full memory access tracing if requested
        if (m_config.trackMemoryAccess) {
            m_tracker.SetFullTracing(true);
        }

        // Run the CPU execution loop. This returns when:
        // - Instruction/time/memory limit hit
        // - Access violation or other fault
        // - ExitProcess called
        // - Unpack complete detected
        // - External abort requested
        ExecutionResult cpuResult = m_cpu.Execute(m_memory, &m_tracker, m_config);

        return cpuResult;
    }

    // ========================================================================
    // Phase 5: Post-Execution Analysis
    // ========================================================================
    // Runs all analysis passes that require the complete execution trace or
    // the final memory image. These execute once after the CPU loop terminates.

    void RunPostAnalysis(const LoadedTarget& target) noexcept {
        // 5a: Process W-X transitions accumulated by MemoryTracker
        ProcessWXTransitions(target);

        // 5b: Feed memory access records to BehaviorMonitor
        FeedMemoryAccessRecords();

        // 5c: Memory forensics — deep scan all allocated guest memory
        RunMemoryForensics();

        // 5d: String extraction — extract strings from all allocated regions
        RunStringExtraction();

        // 5e: Crypto detection — scan for crypto artefacts
        RunCryptoDetection();

        // 5f: IOC memory scanning — look for embedded IOCs in memory
        RunIOCMemoryScan();

        // 5g: Unpacking post-processing
        RunUnpackingPostProcess(target);

        // 5h: YARA rule scanning — scan all guest memory regions
        //     against built-in and user-supplied YARA rules.
        //     This runs after unpacking so we scan unpacked content.
        RunYaraScan();

        // 5i: BCrypt forensic data — extract any cryptographic keys
        //     captured during emulation (ransomware detection heuristic).
        CollectBcryptForensics();

        // 5j: Feed all accumulated signals to ThreatScorer
        FeedThreatScorer();

        // 5k: Feed post-analysis results to MITRE mapper
        FeedMITREMapper();

        // 5l: Hardware breakpoint anti-debug analysis
        //     Collects DR7 manipulation events from the CPU loop. Malware that
        //     reads/writes debug registers to detect or evade analysis tools
        //     triggers these events. Feed them to EvasionDetector + ThreatScorer.
        CollectHWBPDetections();

        // 5m: Process injection chain analysis
        //     Finalize injection chain detection — correlate all cross-process
        //     operations (VirtualAllocEx→WriteProcessMemory→CreateRemoteThread)
        //     into classified injection techniques.
        CollectProcessInjectionResults();

        // 5n: WoW64 evasion analysis
        //     Collect Heaven's Gate transition events and FS/Registry redirection
        //     bypass attempts. These indicate deliberate WoW64 exploitation.
        CollectWoW64Results();

        // 5o: AMSI bypass detection — collect scan content and bypass events.
        //     Malware that patches AmsiScanBuffer or returns AMSI_RESULT_CLEAN
        //     triggers bypass events with high threat weight.
        CollectAmsiForensics();

        // 5p: ETW telemetry blinding — collect provider patching events.
        //     Attackers disable ETW to blind EDR sensors (T1562.006).
        CollectEtwForensics();

        // 5q: VSS shadow copy deletion — strong ransomware indicator.
        //     Correlates vssadmin/wmic/bcdedit/wbadmin/diskshadow/COM and
        //     registry-based disabling of System Restore and backup services.
        CollectVssForensics();

        // 5r: WMI reconnaissance and persistence — track WQL queries,
        //     anti-VM checks, shadow copy deletion via WMI, and WMI event
        //     subscriptions used for fileless persistence (T1546.003).
        CollectWmiForensics();

        // 5s: .NET/CLR analysis — parse ECMA-335 metadata, disassemble MSIL,
        //     execute static constructors for string decryption, detect obfuscation
        //     (ConfuserEx, .NET Reactor, etc.), classify P/Invoke imports, and
        //     extract embedded payloads from managed assemblies (T1027, T1620).
        CollectDotNetForensics(target);

        // 5t: Hardware-accelerated memory scanning — SIMD-optimized shellcode
        //     detection, ROP gadget discovery, packed region identification, and
        //     page-level entropy mapping. Supplements the existing MemoryForensics
        //     with host-CPU-native acceleration paths.
        RunAcceleratedMemoryScan();

        // 5u: Hardware-accelerated crypto analysis — AES-NI/SHA-NI scanning for
        //     embedded crypto constants, key schedules, and encrypted regions.
        //     Supplements CryptoDetector with hardware-native detection.
        RunAcceleratedCryptoScan();

        // 5v: Kernel-mode integrity analysis — DKOM detection, SSDT/IDT hook
        //     scanning, MSR tampering check, ring transition anomalies, and
        //     loaded driver security audit. Only runs when kernel emulation
        //     subsystem was initialized (i.e., driver sample loaded).
        RunKernelIntegrityScan();
    }

    // ========================================================================
    // 5a: Process W-X Transitions
    // ========================================================================

    void ProcessWXTransitions(const LoadedTarget& target) noexcept {
        // DESIGN: target is reserved for future imageBase/imageSize-aware
        // filtering (e.g., suppressing WX events that fall inside the loaded
        // PE's legitimate code section). Current pipeline treats every WX
        // page as a candidate; suppression happens downstream in the
        // unpacking engine which already has the image layout.
        (void)target;
        auto wxPages = m_tracker.GetWriteExecutePages();
        if (wxPages.empty()) return;

        uint64_t instrCount = m_cpu.State().instructionCount;
        uint32_t processed = 0;

        for (GuestAddress page : wxPages) {
            if (processed >= kWXTransitionBatchLimit) break;

            // Feed to BehaviorMonitor
            if (m_config.enableBehaviorMonitor) {
                m_behaviorMonitor.OnWXTransition(page, instrCount);
            }

            // Feed to UnpackingEngine
            if (m_config.enableUnpacking) {
                m_unpackingEngine.OnWXTransition(
                    m_memory, m_tracker, page, page, instrCount);
            }

            // Feed to MemoryForensics
            if (m_config.enableMemoryForensics) {
                m_memoryForensics.OnWXTransition(m_memory, page);
            }

            ++processed;
        }

        // Also process RWX allocations which are inherently suspicious
        auto rwxAllocs = m_tracker.GetRWXAllocations();
        for (const auto& [base, size] : rwxAllocs) {
            if (m_config.enableMemoryForensics) {
                m_memoryForensics.OnAllocation(base, size, MemProt::RWX);
            }
        }
    }

    // ========================================================================
    // 5b: Feed Memory Access Records to BehaviorMonitor
    // ========================================================================

    void FeedMemoryAccessRecords() noexcept {
        if (!m_config.enableBehaviorMonitor) return;
        if (!m_config.trackMemoryAccess) return;

        auto accessLog = m_tracker.GetAccessLog();
        // Cap the number of records to prevent unbounded post-analysis time
        constexpr size_t kMaxRecordsToFeed = 100'000;
        size_t count = std::min(accessLog.size(), kMaxRecordsToFeed);

        for (size_t i = 0; i < count; ++i) {
            m_behaviorMonitor.OnMemoryEvent(accessLog[i]);
        }
    }

    // ========================================================================
    // 5c: Memory Forensics
    // ========================================================================

    void RunMemoryForensics() noexcept {
        if (!m_config.enableMemoryForensics) return;
        m_memoryForensics.ScanAll(m_memory, m_tracker);
    }

    // ========================================================================
    // 5d: String Extraction
    // ========================================================================

    void RunStringExtraction() noexcept {
        m_stringExtractor.ScanAll(m_memory);
    }

    // ========================================================================
    // 5e: Crypto Detection
    // ========================================================================

    void RunCryptoDetection() noexcept {
        m_cryptoDetector.ScanAll(m_memory);
    }

    // ========================================================================
    // 5f: IOC Memory Scanning
    // ========================================================================

    void RunIOCMemoryScan() noexcept {
        if (!m_config.enableIOCExtraction) return;

        // Feed suspicious strings to the IOC extractor as potential IOCs
        const auto& strings = m_stringExtractor.GetStrings();
        for (const auto& str : strings) {
            if (str.suspiciousness >= 0.3f) {
                m_iocExtractor.OnStringFound(str.value, str.address);
            }
        }
    }

    // ========================================================================
    // 5g: Unpacking Post-Processing
    // ========================================================================

    void RunUnpackingPostProcess(const LoadedTarget& target) noexcept {
        if (!m_config.enableUnpacking) return;

        // If the unpacking engine detected that unpacking is complete,
        // attempt to dump the final unpacked PE from guest memory
        if (m_unpackingEngine.IsComplete()) {
            GuestAddress oep = m_unpackingEngine.GetFinalOEP();
            if (oep != 0 && target.imageBase != 0 && target.imageSize > 0) {
                // Try to dump a valid PE from memory at the OEP. DumpPE
                // returns the dumped image bytes; we currently do not stage
                // the dump into the result struct (it is exposed to callers
                // through GetLayers()/GetFinalOEP() metadata). Capture the
                // value to satisfy [[nodiscard]] without changing observable
                // behaviour.
                auto dumped = m_unpackingEngine.DumpPE(
                    m_memory, target.imageBase, target.imageSize);
                (void)dumped;

                // Attempt import reconstruction on the unpacked PE. A
                // failed reconstruction (e.g., partial IAT) is non-fatal —
                // the unpacking engine has already published the layer
                // history, which is the primary unpacking artefact.
                VirtualMemory& memRef = m_memory;
                (void)m_unpackingEngine.ReconstructImports(
                    memRef, target.imageBase, target.imageSize);
            }
        }

        // Even if unpacking didn't "complete", dump entropy history for analysis.
        // The entropy trend over time helps classify packing behaviour.
    }

    // ========================================================================
    // 5h: YARA Rule Scanning
    // ========================================================================
    // Scan all guest memory with built-in detection rules. Runs after
    // unpacking so we catch both packed and unpacked payloads.

    void RunYaraScan() noexcept {
        // Initialize the YARA scanner (loads built-in rules on first call)
        if (!m_yaraScanner.Initialize()) {
            return; // Non-fatal — continue analysis without YARA
        }

        // Use ScanAllGuestMemory to scan the entire guest address space
        auto results = m_yaraScanner.ScanAllGuestMemory(m_memory);

        // Feed YARA matches into the threat scorer and MITRE mapper
        for (const auto& match : results) {
            // Each YARA match contributes to the threat score via custom factor
            float severity = 0.5f;
            if (match.severity == "critical") severity = 1.0f;
            else if (match.severity == "malicious") severity = 0.85f;
            else if (match.severity == "suspicious") severity = 0.5f;
            else severity = 0.1f;

            ScoringFactor factor;
            factor.source = "YARA";
            factor.description = "YARA: " + match.ruleName;
            factor.weight = severity;
            factor.score = severity;
            factor.confidence = 0.9f;
            m_threatScorer.AddCustomFactor(factor);

            // YARA mitre tags feed into MITRE mapper as evasion/technique events
            for (const auto& tag : match.mitreTags) {
                m_mitreMapper.OnEvasionAttempt(tag);
            }
        }
    }

    // ========================================================================
    // 5i: BCrypt Forensic Data Collection
    // ========================================================================
    // Collect crypto keys, algorithms, and usage patterns captured by the
    // BCrypt API emulation layer during execution.

    void CollectBcryptForensics() noexcept {
        auto& bcryptState = WinAPI::Bcrypt::BCryptState::Instance();

        // Check for ransomware-like crypto patterns:
        // >= 100 encrypt operations + AES key presence + RSA public key
        if (bcryptState.IsRansomwareBehavior()) {
            ScoringFactor factor;
            factor.source = "BCrypt";
            factor.description = "Ransomware crypto pattern detected (AES+RSA bulk encryption)";
            factor.weight = 0.95f;
            factor.score = 0.95f;
            factor.confidence = 0.9f;
            m_threatScorer.AddCustomFactor(factor);

            // Extract captured keys for forensic output
            auto capturedKeys = bcryptState.GetCapturedKeys();
            for (const auto& key : capturedKeys) {
                // Feed to crypto detector as API call observations
                static const uint64_t args[1] = { 0 };
                m_cryptoDetector.OnCryptoAPICall(key.algorithm.c_str(), args);
            }
        }
    }

    // ========================================================================
    // 5j: Feed Accumulated Signals to ThreatScorer
    // ========================================================================

    void FeedThreatScorer() noexcept {
        // Behavioral alerts
        if (m_config.enableBehaviorMonitor) {
            for (const auto& alert : m_behaviorMonitor.GetAlerts()) {
                m_threatScorer.AddBehaviorAlert(alert);
            }
        }

        // API sequence matches
        if (m_config.enableAPISequenceAnalysis) {
            for (const auto& match : m_apiSequenceAnalyzer.GetMatches()) {
                m_threatScorer.AddSequenceMatch(match);
            }
        }

        // Memory findings
        if (m_config.enableMemoryForensics) {
            for (const auto& finding : m_memoryForensics.GetFindings()) {
                m_threatScorer.AddMemoryFinding(finding);
            }
        }

        // Dispatcher behavior flags
        if (m_dispatcher) {
            m_threatScorer.AddBehaviorFlags(m_dispatcher->GetBehaviorFlags());
        }

        // MITRE technique mappings
        if (m_config.enableMITREMapping) {
            for (const auto& tech : m_mitreMapper.GetMappedTechniques()) {
                if (tech.id) {
                    m_threatScorer.AddMITRETechnique(tech.id, tech.confidence);
                }
            }
        }

        // Evasion attempts
        for (const auto& attempt : m_evasionDetector.GetAttempts()) {
            m_threatScorer.AddEvasionAttempt(attempt.description, attempt.severity);
        }

        // Packer detections from all unpack layers
        if (m_config.enableUnpacking) {
            for (const auto& layer : m_unpackingEngine.GetLayers()) {
                if (layer.packer != PackerType::Unknown) {
                    m_threatScorer.AddPackerDetection(layer.packer);
                }
            }
        }

        // Network indicators as custom scoring factors
        if (m_networkAnalyzer.HasC2Indicators()) {
            ScoringFactor c2Factor;
            c2Factor.source = "NetworkBehaviorAnalyzer";
            c2Factor.description = "C2 communication indicators detected";
            c2Factor.weight = 0.8f;
            c2Factor.score = 0.8f;
            c2Factor.confidence = 0.7f;
            m_threatScorer.AddCustomFactor(c2Factor);
        }

        if (m_networkAnalyzer.HasExfiltrationIndicators()) {
            ScoringFactor exfilFactor;
            exfilFactor.source = "NetworkBehaviorAnalyzer";
            exfilFactor.description = "Data exfiltration indicators detected";
            exfilFactor.weight = 0.7f;
            exfilFactor.score = 0.7f;
            exfilFactor.confidence = 0.6f;
            m_threatScorer.AddCustomFactor(exfilFactor);
        }

        // Crypto stats as custom scoring factors
        auto cryptoStats = m_cryptoDetector.GetStats();
        if (cryptoStats.hasRansomwareIndicator) {
            ScoringFactor ransomFactor;
            ransomFactor.source = "CryptoDetector";
            ransomFactor.description = "Ransomware crypto pattern: AES+RSA+file enum";
            ransomFactor.weight = 0.9f;
            ransomFactor.score = 0.9f;
            ransomFactor.confidence = 0.8f;
            m_threatScorer.AddCustomFactor(ransomFactor);
        }

        if (cryptoStats.hasC2Encryption) {
            ScoringFactor c2CryptoFactor;
            c2CryptoFactor.source = "CryptoDetector";
            c2CryptoFactor.description = "Encrypted C2 communication pattern";
            c2CryptoFactor.weight = 0.6f;
            c2CryptoFactor.score = 0.6f;
            c2CryptoFactor.confidence = 0.5f;
            m_threatScorer.AddCustomFactor(c2CryptoFactor);
        }
    }

    // ========================================================================
    // 5i: Feed Post-Analysis Results to MITRE Mapper
    // ========================================================================

    void FeedMITREMapper() noexcept {
        if (!m_config.enableMITREMapping) return;

        // Behavioral alerts
        if (m_config.enableBehaviorMonitor) {
            for (const auto& alert : m_behaviorMonitor.GetAlerts()) {
                m_mitreMapper.OnBehaviorAlert(alert);
            }
        }

        // Dispatcher behavior flags
        if (m_dispatcher) {
            m_mitreMapper.OnBehaviorFlags(m_dispatcher->GetBehaviorFlags());
        }

        // Memory findings
        if (m_config.enableMemoryForensics) {
            for (const auto& finding : m_memoryForensics.GetFindings()) {
                m_mitreMapper.OnMemoryFinding(finding);
            }
        }

        // Evasion findings
        for (const auto& attempt : m_evasionDetector.GetAttempts()) {
            m_mitreMapper.OnEvasionAttempt(attempt.description);
        }

        // Packer detections
        if (m_config.enableUnpacking) {
            for (const auto& layer : m_unpackingEngine.GetLayers()) {
                if (layer.packer != PackerType::Unknown) {
                    m_mitreMapper.OnPackerDetected(layer.packer);
                }
            }
        }
    }

    // ========================================================================
    // 5l: Hardware Breakpoint Anti-Debug Collection
    // ========================================================================

    void CollectHWBPDetections() noexcept {
        // Retrieve all anti-debug detection events accumulated during
        // emulation: DR7 reads, DR7 writes, INT1 generation, TF manipulation
        const auto& detections = m_hwBreakpoints.GetDetections();
        if (detections.empty()) return;

        // Map DebugDetectionEvent::Type to a human-readable description
        // for the EvasionDetector and MITRE mapper
        auto typeToString = [](DebugDetectionEvent::Type type) -> const char* {
            switch (type) {
                case DebugDetectionEvent::Type::ReadDR0_DR3:
                    return "read_dr0_dr3";
                case DebugDetectionEvent::Type::ReadDR6:
                    return "read_dr6";
                case DebugDetectionEvent::Type::ReadDR7:
                    return "read_dr7";
                case DebugDetectionEvent::Type::WriteDR7_Clear:
                    return "write_dr7_clear";
                case DebugDetectionEvent::Type::WriteDR0_DR3_Set:
                    return "write_dr0_dr3_set";
                case DebugDetectionEvent::Type::CheckTrapFlag:
                    return "check_trap_flag";
                case DebugDetectionEvent::Type::TimingCheck:
                    return "rdtsc_timing_check";
                case DebugDetectionEvent::Type::ExceptionBasedDetect:
                    return "exception_based_detect";
                default:
                    return "unknown_dr_event";
            }
        };

        for (const auto& det : detections) {
            const char* desc = typeToString(det.type);

            // Feed to EvasionDetector — these are strong anti-debug indicators
            m_evasionDetector.OnEnvironmentQuery("hwbp-antidebug", desc);

            // Feed to ThreatScorer — DR manipulation is almost always malicious
            if (true /*scoring always active*/) {
                // Severity: write/clear operations are more suspicious than reads
                float severity = (det.type == DebugDetectionEvent::Type::WriteDR7_Clear ||
                                  det.type == DebugDetectionEvent::Type::WriteDR0_DR3_Set)
                                     ? 0.85f : 0.6f;
                m_threatScorer.AddEvasionAttempt(desc, severity);
            }

            // Feed to MITRE mapper: T1622 (Debugger Evasion)
            if (m_config.enableMITREMapping) {
                m_mitreMapper.OnEvasionAttempt(desc);
            }
        }
    }

    // ========================================================================
    // 5m: Process Injection Chain Analysis
    // ========================================================================

    void CollectProcessInjectionResults() noexcept {
        if (!m_config.enableMultiProcess) return;

        // Iterate all child processes and collect injection technique detections
        auto childPids = m_processManager.GetChildProcessIds();
        if (childPids.empty()) return;

        // Map InjectionTechnique to a human-readable string for MITRE mapping
        auto techniqueToString = [](InjectionTechnique tech) -> const char* {
            switch (tech) {
                case InjectionTechnique::ProcessHollowing:       return "T1055.012_process_hollowing";
                case InjectionTechnique::ClassicDLLInjection:    return "T1055.001_dll_injection";
                case InjectionTechnique::ReflectiveDLLInjection: return "T1055.001_reflective_dll_injection";
                case InjectionTechnique::APCInjection:           return "T1055.004_apc_injection";
                case InjectionTechnique::AtomBombing:            return "T1055_atom_bombing";
                case InjectionTechnique::ProcessDoppelganging:   return "T1055.013_process_doppelganging";
                case InjectionTechnique::EarlyBirdInjection:     return "T1055.004_early_bird_injection";
                case InjectionTechnique::ThreadHijacking:        return "T1055.003_thread_hijacking";
                case InjectionTechnique::ParentPIDSpoof:         return "T1134.004_parent_pid_spoof";
                default: return nullptr;
            }
        };

        for (uint32_t pid : childPids) {
            InjectionTechnique tech = m_processManager.GetDetectedTechnique(pid);
            if (tech == InjectionTechnique::None) continue;

            const char* desc = techniqueToString(tech);
            if (!desc) continue;

            // Feed to ThreatScorer — injection chains are HIGH confidence malicious
            if (true /*scoring always active*/) {
                m_threatScorer.AddEvasionAttempt(desc, 0.95f);
            }

            // Feed to MITRE mapper — process injection maps to T1055 sub-techniques
            if (m_config.enableMITREMapping) {
                m_mitreMapper.OnEvasionAttempt(desc);
            }
        }

        // Collect inter-process events for result reporting
        const auto& events = m_processManager.GetEvents();
        for (const auto& evt : events) {
            if (evt.type == ProcessEvent::Type::HollowingDetected ||
                evt.type == ProcessEvent::Type::InjectionDetected) {
                m_evasionDetector.OnEnvironmentQuery(
                    "process-injection",
                    evt.type == ProcessEvent::Type::HollowingDetected
                        ? "hollowing_detected" : "injection_detected");
            }
        }
    }

    // ========================================================================
    // 5n: WoW64 Evasion Analysis
    // ========================================================================

    void CollectWoW64Results() noexcept {
        if (!m_config.enableWoW64 || !m_wow64Layer.IsInitialized()) return;

        const auto& events = m_wow64Layer.GetHeavensGateEvents();
        if (events.empty()) return;

        for (const auto& evt : events) {
            // Only flag evasion attempts — normal WoW64 transitions are expected
            if (!evt.isEvasionAttempt) continue;

            const char* desc =
                (evt.direction == WoW64Transition::HeavensGate32to64)
                    ? "heavens_gate_32to64_evasion"
                    : "heavens_gate_64to32_evasion";

            // Heaven's Gate transitions → strong evasion indicator
            m_evasionDetector.OnEnvironmentQuery("wow64-evasion", desc);

            if (true /*scoring always active*/) {
                m_threatScorer.AddEvasionAttempt(desc, 0.80f);
            }

            if (m_config.enableMITREMapping) {
                // T1106 (Native API) + T1055 (Process Injection, specifically for
                // WoW64 Heaven's Gate abuse in malware like Dridex, TrickBot)
                m_mitreMapper.OnEvasionAttempt(desc);
            }
        }
    }

    // ========================================================================
    // 5o: AMSI Bypass Detection Forensics
    // ========================================================================
    // Collects AMSI scan content and bypass events. Malware that patches
    // AmsiScanBuffer or returns AMSI_RESULT_CLEAN without scanning triggers
    // bypass events — strong evasion indicator (T1562.001).

    void CollectAmsiForensics() noexcept {
        if (!m_config.enableAMSI) return;

        auto& amsi = WinAPI::Amsi::AmsiState::Instance();
        const auto bypassEvents = amsi.GetBypassEvents();
        if (bypassEvents.empty()) return;

        for (const auto& evt : bypassEvents) {
            // DESIGN: per-event detail is intentionally not unpacked here —
            // every entry in the AMSI bypass log corresponds to one bypass
            // attempt and feeds a single detection. The static description
            // string below is what the threat scorer / MITRE mapper key on.
            (void)evt;
            const char* desc = "amsi_bypass_detected";

            m_evasionDetector.OnEnvironmentQuery("amsi-bypass", desc);

            m_threatScorer.AddEvasionAttempt(desc, 0.85f);

            if (m_config.enableMITREMapping) {
                // T1562.001 — Impair Defenses: Disable or Modify Tools
                m_mitreMapper.OnEvasionAttempt(desc);
            }
        }

        // If AMSI was patched (force-return bypass), add extra scoring weight
        if (amsi.WasAmsiPatched()) {
            ScoringFactor amsiFactor;
            amsiFactor.source = "AmsiAPI";
            amsiFactor.description = "AMSI scan interface patched (defense evasion)";
            amsiFactor.weight = 0.85f;
            amsiFactor.score = 0.85f;
            amsiFactor.confidence = 0.9f;
            m_threatScorer.AddCustomFactor(amsiFactor);
        }
    }

    // ========================================================================
    // 5p: ETW Telemetry Blinding Forensics
    // ========================================================================
    // Collects ETW provider patching/blinding events. Attackers disable ETW
    // to blind EDR sensors from receiving process, thread, image load, and
    // network events (T1562.006 — Indicator Blocking).

    void CollectEtwForensics() noexcept {
        if (!m_config.enableETW) return;

        auto& etw = WinAPI::Ntdll::EtwState::Instance();
        const auto blindingEvents = etw.GetBlindingEvents();
        if (blindingEvents.empty()) return;

        for (const auto& evt : blindingEvents) {
            // DESIGN: see CollectAmsiForensics — each event maps 1:1 to a
            // detection keyed off the static description below.
            (void)evt;
            const char* desc = "etw_telemetry_blinding";

            m_evasionDetector.OnEnvironmentQuery("etw-blinding", desc);

            m_threatScorer.AddEvasionAttempt(desc, 0.80f);

            if (m_config.enableMITREMapping) {
                // T1562.006 — Impair Defenses: Indicator Blocking
                m_mitreMapper.OnEvasionAttempt(desc);
            }
        }

        if (etw.WasEtwPatched()) {
            ScoringFactor etwFactor;
            etwFactor.source = "EtwAPI";
            etwFactor.description = "ETW provider patched/disabled (telemetry blinding)";
            etwFactor.weight = 0.80f;
            etwFactor.score = 0.80f;
            etwFactor.confidence = 0.85f;
            m_threatScorer.AddCustomFactor(etwFactor);
        }
    }

    // ========================================================================
    // 5q: VSS Shadow Copy Deletion Forensics
    // ========================================================================
    // Collects VSS deletion events across all detection vectors: command-line
    // (vssadmin/wmic/bcdedit/wbadmin/cipher/diskshadow/PowerShell), COM CLSID
    // creation, and registry disabling. Multiple independent deletion methods
    // is a very strong ransomware indicator (T1490 — Inhibit System Recovery).

    void CollectVssForensics() noexcept {
        if (!m_config.enableVSS) return;

        auto& vss = WinAPI::Vss::VssDetector::Instance();
        if (vss.GetDeleteAttemptCount() == 0) return;

        // HasRansomwareBehavior() checks for ≥2 distinct deletion methods
        if (vss.HasRansomwareBehavior()) {
            ScoringFactor vssFactor;
            vssFactor.source = "VssDetector";
            vssFactor.description = "Shadow copy deletion via multiple methods (ransomware)";
            vssFactor.weight = 0.95f;
            vssFactor.score = vss.GetRansomwareScore();
            vssFactor.confidence = 0.95f;
            m_threatScorer.AddCustomFactor(vssFactor);
        } else {
            // Single method — still suspicious but lower confidence
            ScoringFactor vssFactor;
            vssFactor.source = "VssDetector";
            vssFactor.description = "Shadow copy deletion attempt detected";
            vssFactor.weight = 0.70f;
            vssFactor.score = 0.70f;
            vssFactor.confidence = 0.7f;
            m_threatScorer.AddCustomFactor(vssFactor);
        }

        if (m_config.enableMITREMapping) {
            // T1490 — Inhibit System Recovery
            m_mitreMapper.OnEvasionAttempt("vss_shadow_copy_deletion");
        }
    }

    // ========================================================================
    // 5r: WMI Reconnaissance & Persistence Forensics
    // ========================================================================
    // Collects WMI query events for system reconnaissance (anti-VM, hardware
    // enumeration), shadow copy deletion via WMI, and WMI event subscription
    // persistence (T1047, T1546.003, T1518, T1082).

    void CollectWmiForensics() noexcept {
        if (!m_config.enableWMI) return;

        auto& wmi = WinAPI::Ole32::WmiState::Instance();

        // Anti-VM WMI queries (SELECT * FROM Win32_ComputerSystem WHERE Manufacturer LIKE '%VMware%')
        if (wmi.HasAntiVMQuery()) {
            m_evasionDetector.OnEnvironmentQuery("wmi-antivm", "wmi_anti_vm_query");

            ScoringFactor vmFactor;
            vmFactor.source = "WmiEmulation";
            vmFactor.description = "WMI anti-VM/sandbox enumeration detected";
            vmFactor.weight = 0.65f;
            vmFactor.score = 0.65f;
            vmFactor.confidence = 0.75f;
            m_threatScorer.AddCustomFactor(vmFactor);

            if (m_config.enableMITREMapping) {
                m_mitreMapper.OnEvasionAttempt("wmi_anti_vm_recon");
            }
        }

        // Shadow copy deletion via WMI (WMIC invocation or ExecQuery)
        if (wmi.HasShadowCopyDeletion()) {
            ScoringFactor wmiVssFactor;
            wmiVssFactor.source = "WmiEmulation";
            wmiVssFactor.description = "WMI-based shadow copy deletion (ransomware)";
            wmiVssFactor.weight = 0.90f;
            wmiVssFactor.score = 0.90f;
            wmiVssFactor.confidence = 0.9f;
            m_threatScorer.AddCustomFactor(wmiVssFactor);
        }

        // WMI event subscription persistence (T1546.003)
        if (wmi.HasPersistenceAttempt()) {
            ScoringFactor persistFactor;
            persistFactor.source = "WmiEmulation";
            persistFactor.description = "WMI event subscription persistence (fileless)";
            persistFactor.weight = 0.85f;
            persistFactor.score = 0.85f;
            persistFactor.confidence = 0.8f;
            m_threatScorer.AddCustomFactor(persistFactor);

            if (m_config.enableMITREMapping) {
                m_mitreMapper.OnEvasionAttempt("wmi_event_subscription_persistence");
            }
        }

        // System reconnaissance via WMI queries
        uint32_t reconCount = wmi.GetReconQueryCount();
        if (reconCount >= 3) {
            ScoringFactor reconFactor;
            reconFactor.source = "WmiEmulation";
            reconFactor.description = "Extensive WMI system reconnaissance";
            reconFactor.weight = 0.50f;
            reconFactor.score = std::min(0.70f, 0.30f + (reconCount * 0.05f));
            reconFactor.confidence = 0.6f;
            m_threatScorer.AddCustomFactor(reconFactor);

            if (m_config.enableMITREMapping) {
                m_mitreMapper.OnEvasionAttempt("wmi_system_reconnaissance");
            }
        }
    }

    // ========================================================================
    // 5s: .NET/CLR Analysis
    // ========================================================================

    void CollectDotNetForensics(const LoadedTarget& target) noexcept {
        if (!m_config.enableDotNetAnalysis) return;

        // Check if the loaded PE is a .NET assembly before running full analysis
        if (!CLR::DotNetAnalyzer::IsDotNetAssembly(m_memory, target.imageBase)) return;

        auto& analyzer = CLR::DotNetAnalyzer::Instance();
        auto dotNetResult = analyzer.Analyze(m_memory, target.imageBase);

        // Skip if no meaningful .NET metadata was found
        if (dotNetResult.methodDefCount == 0 && dotNetResult.typeDefCount == 0) return;

        // Use the analyzer's built-in threat score (computed from all signals)
        float threatScore = analyzer.GetLastThreatScore();

        // Feed threat score to the global scorer
        if (threatScore > 0.1f) {
            ScoringFactor dotnetFactor;
            dotnetFactor.source = "DotNetAnalyzer";
            dotnetFactor.description = "Managed assembly threat analysis";
            dotnetFactor.weight = threatScore;
            dotnetFactor.score = threatScore;
            dotnetFactor.confidence = 0.8f;
            m_threatScorer.AddCustomFactor(dotnetFactor);
        }

        // Feed obfuscation detections to evasion detector
        for (const auto& obf : dotNetResult.obfuscationIndicators) {
            std::string obfName;
            switch (obf) {
                case CLR::DotNetObfuscation::StringEncryption:       obfName = "string_encryption"; break;
                case CLR::DotNetObfuscation::ControlFlowFlattening:  obfName = "control_flow_flatten"; break;
                case CLR::DotNetObfuscation::MethodProxying:         obfName = "method_proxying"; break;
                case CLR::DotNetObfuscation::AntiTamper:             obfName = "anti_tamper"; break;
                case CLR::DotNetObfuscation::AntiDecompile:          obfName = "anti_decompile"; break;
                case CLR::DotNetObfuscation::NameObfuscation:        obfName = "name_obfuscation"; break;
                case CLR::DotNetObfuscation::ResourceEncryption:     obfName = "resource_encryption"; break;
                case CLR::DotNetObfuscation::VirtualizationProtect:  obfName = "virtualization_protect"; break;
                case CLR::DotNetObfuscation::MixedModeAssembly:      obfName = "mixed_mode"; break;
                case CLR::DotNetObfuscation::MethodBodyEncryption:   obfName = "method_body_encryption"; break;
                default: obfName = "unknown_obfuscation"; break;
            }
            m_evasionDetector.OnEnvironmentQuery("dotnet-obfuscation", obfName);
        }

        // Feed MITRE ATT&CK technique IDs from the analyzer
        if (m_config.enableMITREMapping) {
            for (const auto& mitreId : analyzer.GetLastMITREIDs()) {
                m_mitreMapper.OnEvasionAttempt("dotnet_" + mitreId);
            }
            if (!dotNetResult.detectedObfuscator.empty()) {
                m_mitreMapper.OnEvasionAttempt("dotnet_obfuscator_" + dotNetResult.detectedObfuscator);
            }
        }

        // Feed suspicious P/Invoke declarations to evasion detector
        for (const auto& pinvoke : dotNetResult.pInvokeImports) {
            if (!pinvoke.moduleName.empty() && !pinvoke.importName.empty()) {
                m_evasionDetector.OnEnvironmentQuery(
                    "dotnet-pinvoke",
                    pinvoke.moduleName + "!" + pinvoke.importName);
            }
        }

        // Store the result for later collection
        m_dotNetResult = std::move(dotNetResult);
    }

    // ========================================================================
    // 5t: Hardware-Accelerated Memory Scanning
    // ========================================================================

    void RunAcceleratedMemoryScan() noexcept {
        if (!m_config.enableHardwareAccel) return;
        if (!m_config.enableMemoryScanAccel) return;

        // The MemoryScanAccel::ScanAll walks every allocated guest region,
        // computing per-page entropy, detecting shellcode patterns, scanning
        // for ROP gadgets, and identifying packed/encrypted regions using
        // SIMD-accelerated primitives from SIMDEngine.
        auto scanResult = m_memoryScanAccel.ScanAll(m_memory);

        // Feed shellcode matches to the existing analysis pipeline as
        // W→X transitions (the closest existing BehaviorMonitor event)
        if (m_config.enableBehaviorMonitor) {
            uint64_t instrCount = m_cpu.State().instructionCount;
            for (const auto& match : scanResult.shellcodeMatches) {
                if (match.confidence >= 0.6f) {
                    m_behaviorMonitor.OnWXTransition(match.address, instrCount);
                }
            }
        }

        // Feed ROP gadget clusters to evasion detector as an environment query
        if (scanResult.ropGadgets.size() > 20) {
            m_evasionDetector.OnEnvironmentQuery(
                "accel-rop-cluster",
                "Found " + std::to_string(scanResult.ropGadgets.size()) +
                " ROP gadgets in executable memory");
        }

        // Feed packed high-entropy W-X regions to BehaviorMonitor
        if (m_config.enableBehaviorMonitor) {
            uint64_t instrCount = m_cpu.State().instructionCount;
            for (const auto& packed : scanResult.packedRegions) {
                if (packed.avgEntropy > 7.0 && packed.hasWriteExecute) {
                    m_behaviorMonitor.OnWXTransition(packed.base, instrCount);
                }
            }
        }

        // Store for result collection
        m_accelMemoryScanResult = std::move(scanResult);
    }

    // ========================================================================
    // 5u: Hardware-Accelerated Crypto Analysis
    // ========================================================================

    void RunAcceleratedCryptoScan() noexcept {
        if (!m_config.enableHardwareAccel) return;
        if (!m_config.enableCryptoAcceleration) return;

        // Focus on W→X pages — the most security-relevant memory regions.
        // These are pages that were written to and then executed, indicating
        // unpacked/decrypted code (ransomware, packers, shellcode).
        auto wxPages = m_tracker.GetWriteExecutePages();

        constexpr uint32_t kScanPageSz = 4096;
        constexpr size_t kMaxPagesToScan = 2048;  // Cap to prevent unbounded scan
        size_t pagesScanned = 0;

        for (GuestAddress page : wxPages) {
            if (pagesScanned >= kMaxPagesToScan) break;

            uint8_t pageData[kScanPageSz];
            auto readErr = m_memory.Read(page, pageData, kScanPageSz);
            if (readErr != ErrorCode::Success) continue;
            ++pagesScanned;

            ByteSpan span{pageData, kScanPageSz};

            // AES content detection (S-box, RCON, key schedule patterns)
            auto aesResult = m_cryptoAccelerator.DetectAESContent(span, page);
            if (aesResult.hasAESPatterns || !aesResult.sboxLocations.empty() ||
                !aesResult.keyCandidates.empty()) {
                m_accelAESDetections.push_back(std::move(aesResult));
            }

            // ChaCha20/Salsa20 stream cipher detection
            if (m_cryptoAccelerator.DetectChaChaPattern(span)) {
                // Feed as a crypto API observation to leverage existing pipeline
                static const uint64_t dummyArgs[1] = { page };
                m_cryptoDetector.OnCryptoAPICall("ChaCha20-Detected", dummyArgs);
            }

            // Full encryption analysis on high-entropy W-X pages
            auto analysis = m_cryptoAccelerator.AnalyzeEncryption(span, page);
            if (analysis.isLikelyRansomware &&
                !m_accelEncryptionAnalysis.isLikelyRansomware) {
                m_accelEncryptionAnalysis = analysis;
            }

            // RSA public key scanning
            auto rsaKeys = m_cryptoAccelerator.FindRSAPublicKeys(span, page);
            if (!rsaKeys.empty()) {
                static const uint64_t rsaArgs[1] = { rsaKeys.front() };
                m_cryptoDetector.OnCryptoAPICall("RSA-PublicKey-Found", rsaArgs);
            }
        }

        // Also scan RWX allocations (these are inherently suspicious)
        auto rwxAllocs = m_tracker.GetRWXAllocations();
        for (const auto& [base, size] : rwxAllocs) {
            if (pagesScanned >= kMaxPagesToScan) break;
            if (size < kScanPageSz) continue;

            uint8_t pageData[kScanPageSz];
            auto readErr = m_memory.Read(base, pageData, kScanPageSz);
            if (readErr != ErrorCode::Success) continue;
            ++pagesScanned;

            ByteSpan span{pageData, kScanPageSz};
            auto aesResult = m_cryptoAccelerator.DetectAESContent(span, base);
            if (aesResult.hasAESPatterns || !aesResult.sboxLocations.empty()) {
                m_accelAESDetections.push_back(std::move(aesResult));
            }
        }
    }

    // Accelerated scan results (stored between analysis and collection)
    MemoryScanResult m_accelMemoryScanResult;
    std::vector<AESDetectionResult> m_accelAESDetections;
    EncryptionAnalysis m_accelEncryptionAnalysis;

    // Kernel-mode analysis state (Phase 7)
    bool m_kernelInitialized = false;

    // ========================================================================
    // 5v: Kernel Integrity Scan (Phase 7)
    // ========================================================================

    void InitializeKernelSubsystems() noexcept {
        if (!m_config.enableKernelEmulation) return;

        // Initialize kernel address space with guest memory
        auto& kernelAS = KernelAddressSpace::Instance();
        kernelAS.Reset();
        if (!kernelAS.Initialize(m_memory)) return;

        // Initialize kernel object manager (EPROCESS, SSDT, IDT)
        auto& objMgr = KernelObjectManager::Instance();
        objMgr.Reset();
        if (!objMgr.Initialize(m_memory)) return;
        objMgr.InitializeSSDT();
        objMgr.InitializeIDT();

        // Initialize MSR emulation with Win10 defaults
        auto& msrEmu = MSREmulation::Instance();
        msrEmu.Reset();
        msrEmu.InitializeDefaults();

        // Initialize ring transition engine
        auto& ringTrans = RingTransition::Instance();
        ringTrans.Reset();
        ringTrans.Initialize(m_cpu.State(), msrEmu);

        // Initialize driver loader
        auto& drvLoader = DriverLoader::Instance();
        drvLoader.Reset();
        drvLoader.Initialize(m_memory);

        // Create initial System (PID 4) and smss.exe (PID 348) processes
        objMgr.CreateProcess(4, 0, "System");
        objMgr.CreateProcess(348, 4, "smss.exe");

        // Initialize high-level DKOM detector with correlation engine
        auto& dkom = DKOMDetector::Instance();
        dkom.Reset();
        dkom.Initialize();
        dkom.SetRootkitScoreThreshold(m_config.rootkitScoreThreshold);

        // Reset kernel API tracker for clean session state
        WinAPI::Kernel::KernelAPITracker::Instance().Reset();

        m_kernelInitialized = true;
    }

    void RunKernelIntegrityScan() noexcept {
        if (!m_config.enableKernelEmulation || !m_kernelInitialized) return;

        auto& objMgr = KernelObjectManager::Instance();

        // DKOM detection — scan for unlinked processes, threads, drivers
        if (m_config.enableDKOMDetection) {
            auto dkomResults = objMgr.ScanForDKOM();
            for (auto& det : dkomResults) {
                m_kernelDKOMDetections.push_back(std::move(det));
            }
        }

        // SSDT hook detection
        if (m_config.enableSSDTIntegrity) {
            auto hooked = objMgr.DetectSSDTHooks();
            m_kernelSSDTHooks.insert(m_kernelSSDTHooks.end(),
                                     hooked.begin(), hooked.end());
            if (!hooked.empty()) {
                m_threatScorer.AddEvasionAttempt(
                    "SSDT hooks detected: " + std::to_string(hooked.size()) +
                    " entries modified", 0.9f);
                m_mitreMapper.OnEvasionAttempt("ssdt_hook_kernel");
            }
        }

        // IDT hook detection
        if (m_config.enableIDTIntegrity) {
            auto hookedVec = objMgr.DetectIDTHooks();
            m_kernelIDTHooks.insert(m_kernelIDTHooks.end(),
                                    hookedVec.begin(), hookedVec.end());
            if (!hookedVec.empty()) {
                m_threatScorer.AddEvasionAttempt(
                    "IDT hooks detected: " + std::to_string(hookedVec.size()) +
                    " vectors modified", 0.85f);
            }
        }

        // MSR tampering check
        if (m_config.enableMSRMonitoring) {
            auto& msrEmu = MSREmulation::Instance();
            auto msrMods = msrEmu.DetectModifications();
            if (!msrMods.empty()) {
                m_kernelMSRTampered = true;
                auto& dkom = DKOMDetector::Instance();
                for (const auto& mod : msrMods) {
                    m_threatScorer.AddEvasionAttempt(
                        "MSR tampering: " + mod.msrName, 0.88f);
                    m_mitreMapper.OnEvasionAttempt("msr_modification_" + mod.msrName);
                    dkom.OnMSRWrite(mod.msrIndex, mod.currentValue);
                }
            }
        }

        // Ring transition anomaly detection
        if (m_config.enableRingTransitionCheck) {
            auto& ringTrans = RingTransition::Instance();
            auto& dkom = DKOMDetector::Instance();
            auto anomalies = ringTrans.DetectAnomalies();
            for (const auto& anomaly : anomalies) {
                m_threatScorer.AddEvasionAttempt(
                    "Ring transition anomaly: " + anomaly.description, 0.7f);
                dkom.OnRingTransition(anomaly.event.fromRing, anomaly.event.toRing);
            }
        }

        // Process list integrity
        m_kernelProcessListCorrupted = !objMgr.ValidateProcessList();
        if (m_kernelProcessListCorrupted) {
            m_threatScorer.AddEvasionAttempt(
                "Kernel process list integrity violation (DKOM)", 0.95f);
            m_mitreMapper.OnEvasionAttempt("dkom_process_unlinking");
        }

        // SSDT integrity
        m_kernelSSDTIntegrityFailed = !objMgr.ValidateSSDTIntegrity();

        // Driver security analysis — audit all loaded drivers
        auto& drvLoader = DriverLoader::Instance();
        auto loadedDrivers = drvLoader.GetLoadedDrivers();
        for (const auto& drv : loadedDrivers) {
            auto secReport = drvLoader.AnalyzeDriverSecurity(drv);
            if (secReport.hasSuspiciousImports) {
                for (const auto& technique : secReport.mitreTechniques) {
                    m_kernelMitreTechniques.push_back(technique);
                }
            }
        }

        // Feed kernel API call telemetry into DKOMDetector for correlation
        // Must run BEFORE RunFullScan() so correlation data is available
        {
            auto& tracker = WinAPI::Kernel::KernelAPITracker::Instance();
            m_kernelAPIReport = tracker.GenerateReport();
            auto& dkom = DKOMDetector::Instance();
            for (const auto& call : m_kernelAPIReport.calls) {
                if (call.isSuspicious) {
                    dkom.OnAPICall(call.apiName, static_cast<uint32_t>(call.arg1));
                }
            }
        }

        // High-level DKOM analysis — runs the DKOMDetector correlation engine
        // which cross-references kernel object state with behavioral signals
        // (API calls, MSR writes, ring transitions) for severity scoring
        {
            auto& dkom = DKOMDetector::Instance();
            auto report = dkom.RunFullScan();
            m_kernelDKOMReport = std::move(report);

            for (const auto& tech : m_kernelDKOMReport.mitreTechniquesUsed) {
                m_kernelMitreTechniques.push_back(tech);
            }
        }

        // Propagate kernel API MITRE techniques to the global mapper
        for (const auto& tech : m_kernelAPIReport.mitreTechniques) {
            m_kernelMitreTechniques.push_back(tech);
            m_mitreMapper.OnEvasionAttempt(tech);
        }

        // Compute rootkit score
        ComputeRootkitScore();
    }

    void ComputeRootkitScore() noexcept {
        float score = 0.0f;

        // Low-level DKOM findings from KernelObjectManager
        for (const auto& det : m_kernelDKOMDetections) {
            switch (det.type) {
                case DKOMDetection::Type::ProcessUnlinked: score += 20.0f; break;
                case DKOMDetection::Type::SSDTHooked:      score += 25.0f; break;
                case DKOMDetection::Type::IDTHooked:        score += 22.0f; break;
                case DKOMDetection::Type::TokenSwapped:     score += 18.0f; break;
                case DKOMDetection::Type::DriverUnlinked:   score += 15.0f; break;
                case DKOMDetection::Type::ThreadUnlinked:   score += 12.0f; break;
                case DKOMDetection::Type::CallbackRemoved:  score += 10.0f; break;
            }
        }

        // SSDT/IDT hooks
        score += static_cast<float>(m_kernelSSDTHooks.size()) * 5.0f;
        score += static_cast<float>(m_kernelIDTHooks.size()) * 4.0f;

        // MSR tampering
        if (m_kernelMSRTampered) score += 15.0f;

        // Process list corruption
        if (m_kernelProcessListCorrupted) score += 20.0f;

        // Incorporate DKOMDetector high-level composite score (behavioral correlation)
        // Weight at 0.3 to blend with the raw structural findings
        if (m_kernelDKOMReport.overallRootkitScore > 0.0f) {
            score += m_kernelDKOMReport.overallRootkitScore * 0.3f;
        }

        // Incorporate kernel API suspicious activity score
        if (m_kernelAPIReport.suspiciousCalls > 0) {
            score += std::min(static_cast<float>(m_kernelAPIReport.suspiciousCalls) * 3.0f, 20.0f);
        }
        if (m_kernelAPIReport.usesDirectSSDTAccess) score += 10.0f;
        if (m_kernelAPIReport.usesAPCInjection)     score += 8.0f;
        if (m_kernelAPIReport.usesMmMapIoSpace)     score += 6.0f;

        // Cap at 100
        m_kernelRootkitScore = (score > 100.0f) ? 100.0f : score;
        m_kernelRootkitDetected =
            (m_kernelRootkitScore >= m_config.rootkitScoreThreshold);
    }

    // Kernel analysis state (stored between analysis and collection)
    std::vector<DKOMDetection> m_kernelDKOMDetections;
    std::vector<uint32_t>      m_kernelSSDTHooks;
    std::vector<uint8_t>       m_kernelIDTHooks;
    std::vector<std::string>   m_kernelMitreTechniques;
    DKOMAnalysisReport         m_kernelDKOMReport;
    WinAPI::Kernel::KernelAPIReport m_kernelAPIReport;
    float                      m_kernelRootkitScore = 0.0f;
    bool                       m_kernelRootkitDetected = false;
    bool                       m_kernelProcessListCorrupted = false;
    bool                       m_kernelSSDTIntegrityFailed = false;
    bool                       m_kernelMSRTampered = false;

    // ========================================================================
    // Phase 6: Collect Results
    // ========================================================================

    [[nodiscard]] PhantomEmulationResult CollectResults(
        const ExecutionResult& cpuResult,
        const LoadedTarget& target) noexcept
    {
        PhantomEmulationResult result;

        // === Verdict ===
        result.verdict = m_threatScorer.GenerateVerdict();

        // === Execution Statistics ===
        CollectExecutionStats(result, cpuResult, target);

        // === API Trace ===
        CollectAPITrace(result);

        // === Behavioural Analysis ===
        CollectBehavioralResults(result);

        // === Memory Forensics ===
        CollectMemoryForensicsResults(result);

        // === Unpacking ===
        CollectUnpackingResults(result);

        // === MITRE ATT&CK ===
        CollectMITREResults(result);

        // === IOC Extraction ===
        CollectIOCResults(result);

        // === Evasion Detection ===
        CollectEvasionResults(result);

        // === Network Behaviour ===
        CollectNetworkResults(result);

        // === Strings ===
        CollectStringResults(result);

        // === Crypto ===
        CollectCryptoResults(result);

        // === .NET/CLR Analysis ===
        result.dotNetAnalysis = std::move(m_dotNetResult);

        // === Hardware Acceleration (Phase 6) ===
        CollectAccelerationResults(result);

        // === Kernel-Mode Emulation (Phase 7) ===
        CollectKernelResults(result);

        // === Session Status ===
        DetermineSessionStatus(result, cpuResult);

        return result;
    }

    // ========================================================================
    // Result Collection Sub-Methods
    // ========================================================================

    void CollectExecutionStats(PhantomEmulationResult& result,
                               const ExecutionResult& cpuResult,
                               const LoadedTarget& target) noexcept {
        result.execution.stopReason           = cpuResult.reason;
        result.execution.errorCode            = cpuResult.errorCode;
        result.execution.instructionsExecuted  = cpuResult.instructionsExecuted;
        result.execution.apiCallCount          = cpuResult.apiCallCount;
        result.execution.lastRIP               = cpuResult.lastRIP;
        result.execution.faultAddress           = cpuResult.faultAddress;
        result.execution.is64Bit               = target.is64Bit;
        result.execution.peakMemoryUsage       = m_memory.GetAllocatedBytes();

        // Compute wall time from high-resolution timer
        uint64_t endTicks = Platform::GetHighResolutionTicks();
        if (m_tickFreq > 0 && endTicks >= m_startTicks) {
            result.execution.wallTimeMs =
                ((endTicks - m_startTicks) * 1000ULL) / m_tickFreq;
        }
    }

    void CollectAPITrace(PhantomEmulationResult& result) noexcept {
        if (m_config.enableAPITrace && m_dispatcher) {
            result.apiCalls = m_dispatcher->GetCallLog();
        }
        if (m_dispatcher) {
            result.aggregateBehaviorFlags = m_dispatcher->GetBehaviorFlags();
        }
    }

    void CollectBehavioralResults(PhantomEmulationResult& result) noexcept {
        if (m_config.enableBehaviorMonitor) {
            const auto& alerts = m_behaviorMonitor.GetAlerts();
            result.behaviorAlerts.assign(alerts.begin(), alerts.end());
        }

        if (m_config.enableAPISequenceAnalysis) {
            const auto& matches = m_apiSequenceAnalyzer.GetMatches();
            result.sequenceMatches.assign(matches.begin(), matches.end());

            const auto& anomalies = m_apiSequenceAnalyzer.GetAnomalies();
            result.transitionAnomalies.assign(anomalies.begin(), anomalies.end());
        }
    }

    void CollectMemoryForensicsResults(PhantomEmulationResult& result) noexcept {
        if (!m_config.enableMemoryForensics) return;

        const auto& findings = m_memoryForensics.GetFindings();
        result.memoryFindings.assign(findings.begin(), findings.end());

        const auto& payloads = m_memoryForensics.GetExtractedPayloads();
        result.extractedPayloads.assign(payloads.begin(), payloads.end());
    }

    void CollectUnpackingResults(PhantomEmulationResult& result) noexcept {
        if (!m_config.enableUnpacking) return;

        const auto& layers = m_unpackingEngine.GetLayers();
        result.unpacking.layers.assign(layers.begin(), layers.end());
        result.unpacking.finalOEP   = m_unpackingEngine.GetFinalOEP();
        result.unpacking.oepMethod  = m_unpackingEngine.GetOEPMethod();
        result.unpacking.successful = m_unpackingEngine.IsComplete();

        // Find the first known packer across all layers
        for (const auto& layer : layers) {
            if (layer.packer != PackerType::Unknown) {
                result.unpacking.detectedPacker = layer.packer;
                break;
            }
        }

        // Extract the final unpacked payload from the last complete layer
        for (auto it = layers.rbegin(); it != layers.rend(); ++it) {
            if (it->isComplete && !it->dumpedPE.empty()) {
                result.unpacking.finalPayload = it->dumpedPE;
                break;
            }
        }
    }

    void CollectMITREResults(PhantomEmulationResult& result) noexcept {
        if (!m_config.enableMITREMapping) return;

        const auto& techniques = m_mitreMapper.GetMappedTechniques();
        result.mitreTechniques.assign(techniques.begin(), techniques.end());
        result.killChainCoverage = m_mitreMapper.GetKillChainCoverage();
    }

    void CollectIOCResults(PhantomEmulationResult& result) noexcept {
        if (!m_config.enableIOCExtraction) return;
        result.iocReport = m_iocExtractor.GenerateReport();
    }

    void CollectEvasionResults(PhantomEmulationResult& result) noexcept {
        const auto& attempts = m_evasionDetector.GetAttempts();
        result.evasionAttempts.assign(attempts.begin(), attempts.end());
        result.evasionSummary = m_evasionDetector.GetSummary();
    }

    void CollectNetworkResults(PhantomEmulationResult& result) noexcept {
        const auto& conns = m_networkAnalyzer.GetConnections();
        result.network.connections.assign(conns.begin(), conns.end());

        const auto& alerts = m_networkAnalyzer.GetAlerts();
        result.network.alerts.assign(alerts.begin(), alerts.end());

        result.network.totalBytesSent     = m_networkAnalyzer.GetTotalBytesSent();
        result.network.totalBytesReceived  = m_networkAnalyzer.GetTotalBytesReceived();
        result.network.hasC2Indicators     = m_networkAnalyzer.HasC2Indicators();
        result.network.hasExfiltration     = m_networkAnalyzer.HasExfiltrationIndicators();
    }

    void CollectStringResults(PhantomEmulationResult& result) noexcept {
        const auto& strings = m_stringExtractor.GetStrings();
        result.extractedStrings.assign(strings.begin(), strings.end());
    }

    void CollectCryptoResults(PhantomEmulationResult& result) noexcept {
        const auto& findings = m_cryptoDetector.GetFindings();
        result.cryptoFindings.assign(findings.begin(), findings.end());
        result.cryptoStats = m_cryptoDetector.GetStats();
    }

    void CollectAccelerationResults(PhantomEmulationResult& result) noexcept {
        // SIMD feature availability
        result.simdAvailable  = m_simdEngine.HasSSE2();
        result.aesniAvailable = m_simdEngine.HasAESNI();
        result.shaniAvailable = m_simdEngine.HasSHANI();

        // Memory scan acceleration results
        if (m_config.enableHardwareAccel && m_config.enableMemoryScanAccel) {
            result.accelMemoryScan = std::move(m_accelMemoryScanResult);
        }

        // AES detection results from hardware-accelerated scanning
        if (m_config.enableHardwareAccel && m_config.enableCryptoAcceleration) {
            result.accelAESDetections = std::move(m_accelAESDetections);
            result.accelEncryptionAnalysis = m_accelEncryptionAnalysis;
        }

        // JIT optimizer statistics
        if (m_config.enableJITOptimizer) {
            result.jitOptimizerStats = m_jitOptimizer.GetStats();
        }
    }

    void CollectKernelResults(PhantomEmulationResult& result) noexcept {
        if (!m_config.enableKernelEmulation || !m_kernelInitialized) return;

        // DKOM detections
        result.dkomDetections = std::move(m_kernelDKOMDetections);

        // SSDT / IDT hook vectors
        result.ssdtHookedEntries = std::move(m_kernelSSDTHooks);
        result.idtHookedVectors  = std::move(m_kernelIDTHooks);

        // Loaded driver descriptors
        auto& drvLoader = DriverLoader::Instance();
        auto loadedDrivers = drvLoader.GetLoadedDrivers();
        result.loadedDrivers.reserve(loadedDrivers.size());
        for (auto& drv : loadedDrivers) {
            result.loadedDrivers.push_back(std::move(drv));
        }

        // Rootkit analysis
        result.rootkitScore              = m_kernelRootkitScore;
        result.rootkitDetected           = m_kernelRootkitDetected;
        result.processListCorrupted      = m_kernelProcessListCorrupted;
        result.ssdtIntegrityFailed       = m_kernelSSDTIntegrityFailed;
        result.msrTamperingDetected      = m_kernelMSRTampered;
        result.kernelMitreTechniques     = std::move(m_kernelMitreTechniques);

        // Aggregate kernel API call counts from KernelAPITracker
        result.kernelAPICalls       = m_kernelAPIReport.totalCalls;
        result.suspiciousKernelAPIs = m_kernelAPIReport.suspiciousCalls;
    }

    void DetermineSessionStatus(PhantomEmulationResult& result,
                                const ExecutionResult& cpuResult) noexcept {
        // A session is "successful" if execution completed without an
        // unrecoverable internal error. Resource limits, ExitProcess, user
        // abort, and unpack completion are all considered successful outcomes
        // because the analysis data is still valid and useful.
        result.success =
            cpuResult.errorCode == ErrorCode::Success ||
            cpuResult.reason == StopReason::ExitProcess ||
            cpuResult.reason == StopReason::InstructionLimit ||
            cpuResult.reason == StopReason::TimeLimit ||
            cpuResult.reason == StopReason::MemoryLimit ||
            cpuResult.reason == StopReason::UserAborted ||
            cpuResult.reason == StopReason::UnpackComplete ||
            cpuResult.reason == StopReason::Breakpoint;

        if (!result.success) {
            result.errorMessage = "Emulation terminated: ";
            result.errorMessage += GetEmulatorErrorCategory().message(
                static_cast<int>(cpuResult.errorCode));
            result.errorMessage += " (StopReason=" +
                std::to_string(static_cast<int>(cpuResult.reason)) + ")";

            if (cpuResult.faultAddress != 0) {
                result.errorMessage += " at address 0x" +
                    ToHex64(cpuResult.faultAddress);
            }
        }
    }

    // ========================================================================
    // Master Execution Pipeline
    // ========================================================================

    [[nodiscard]] PhantomEmulationResult ExecutePipeline(
        const LoadedTarget& target) noexcept
    {
        // Phase 2.5: Initialize WoW64 layer for 32-bit samples
        // Must run after environment setup and before CPU callbacks,
        // because it modifies segment descriptors and CS selector.
        if (m_config.enableWoW64 && !target.is64Bit) {
            if (m_wow64Layer.Initialize(m_memory, m_cpu.State())) {
                // SetupFor32BitPE failure leaves WoW64 partially initialised
                // (Initialize already succeeded). The session will still
                // execute under 32-bit segments; a missed setup just means
                // some thunks won't fire — the dispatcher will surface that
                // as unhandled APIs rather than crash the emulator.
                (void)m_wow64Layer.SetupFor32BitPE(
                    m_memory, m_cpu.State(),
                    target.imageBase, target.entryPoint);
            }
        }

        // Phase 2.7: Initialize kernel-mode emulation subsystems
        // Sets up kernel address space, object manager (EPROCESS/SSDT/IDT),
        // MSR emulation, ring transition engine, and driver loader.
        InitializeKernelSubsystems();

        // Phase 3: Wire CPU callbacks to analysis modules
        WireCPUCallbacks(target);

        // Phase 4: Run the CPU execution loop
        ExecutionResult cpuResult = RunCPU();

        // Phase 5: Post-execution bulk analysis
        RunPostAnalysis(target);

        // Phase 6: Collect all results into the output struct
        return CollectResults(cpuResult, target);
    }

    // ========================================================================
    // Error Result Factory
    // ========================================================================

    [[nodiscard]] static PhantomEmulationResult MakeErrorResult(
        const std::string& message) noexcept
    {
        PhantomEmulationResult result;
        result.success = false;
        result.errorMessage = message;
        result.execution.stopReason = StopReason::Crashed;
        result.execution.errorCode = ErrorCode::InternalError;
        return result;
    }
};

// ============================================================================
// EmulationSession — Public Interface
// ============================================================================

EmulationSession::EmulationSession(const EmulationConfig& config) noexcept
    : m_impl(nullptr)
{
    // DESIGN: ctor is declared noexcept but std::make_unique<Impl>(config)
    // can throw std::bad_alloc (Impl owns dozens of subsystems and reserves
    // multiple vectors during construction). Catch the allocation failure
    // and leave m_impl null — every public Emulate* / RequestAbort /
    // GetConfig method already null-guards m_impl, so a session
    // constructed under memory pressure becomes inert and surfaces a
    // clean error to the caller instead of std::terminate.
    try {
        m_impl = std::make_unique<Impl>(config);
    } catch (const std::bad_alloc&) {
        // m_impl stays nullptr; subsequent Emulate* calls return a
        // PhantomEmulationResult with success=false.
    } catch (const std::exception&) {
        // Any other subsystem-construction exception is caught for the
        // same reason — exception types are not part of the noexcept
        // contract and must not escape.
    }
}

EmulationSession::~EmulationSession() noexcept = default;

EmulationSession::EmulationSession(EmulationSession&&) noexcept = default;

EmulationSession& EmulationSession::operator=(EmulationSession&&) noexcept = default;

// ============================================================================
// EmulatePE
// ============================================================================

PhantomEmulationResult EmulationSession::EmulatePE(
    std::span<const uint8_t> peData) noexcept
{
    if (!m_impl) {
        return Impl::MakeErrorResult("EmulationSession: null implementation");
    }

    if (m_impl->m_executed) {
        return Impl::MakeErrorResult(
            "EmulationSession: already consumed — construct a new session");
    }
    m_impl->m_executed = true;

    // Validate configuration
    std::string errorMsg;
    if (!m_impl->ValidateConfig(errorMsg)) {
        return Impl::MakeErrorResult(errorMsg);
    }

    // Validate PE input data
    if (!m_impl->ValidatePEInput(peData, errorMsg)) {
        return Impl::MakeErrorResult(errorMsg);
    }

    // Phase 1: Set up virtual Windows environment
    if (!m_impl->SetupEnvironment(errorMsg)) {
        return Impl::MakeErrorResult(errorMsg);
    }

    // Phase 2a: Build API dispatcher and hook region
    if (!m_impl->SetupAPIDispatcher(errorMsg)) {
        return Impl::MakeErrorResult(errorMsg);
    }

    // Phase 2b: Parse and load the PE into guest memory
    Impl::LoadedTarget target;
    if (!m_impl->LoadPE(peData, target, errorMsg)) {
        return Impl::MakeErrorResult(errorMsg);
    }

    // Phases 3–6: Wire callbacks, execute, analyse, collect
    return m_impl->ExecutePipeline(target);
}

// ============================================================================
// EmulateShellcode
// ============================================================================

PhantomEmulationResult EmulationSession::EmulateShellcode(
    std::span<const uint8_t> code, bool is64Bit) noexcept
{
    if (!m_impl) {
        return Impl::MakeErrorResult("EmulationSession: null implementation");
    }

    if (m_impl->m_executed) {
        return Impl::MakeErrorResult(
            "EmulationSession: already consumed — construct a new session");
    }
    m_impl->m_executed = true;

    std::string errorMsg;
    if (!m_impl->ValidateConfig(errorMsg)) {
        return Impl::MakeErrorResult(errorMsg);
    }

    if (!m_impl->ValidateShellcodeInput(code, errorMsg)) {
        return Impl::MakeErrorResult(errorMsg);
    }

    // Phase 1: Environment setup
    if (!m_impl->SetupEnvironment(errorMsg)) {
        return Impl::MakeErrorResult(errorMsg);
    }

    // Phase 2a: API dispatcher
    if (!m_impl->SetupAPIDispatcher(errorMsg)) {
        return Impl::MakeErrorResult(errorMsg);
    }

    // Phase 2c: Load shellcode
    Impl::LoadedTarget target;
    if (!m_impl->LoadShellcode(code, is64Bit, target, errorMsg)) {
        return Impl::MakeErrorResult(errorMsg);
    }

    // Phases 3–6
    return m_impl->ExecutePipeline(target);
}

// ============================================================================
// EmulateBuffer
// ============================================================================

PhantomEmulationResult EmulationSession::EmulateBuffer(
    std::span<const uint8_t> buffer,
    GuestAddress base,
    GuestAddress entry,
    bool is64Bit) noexcept
{
    if (!m_impl) {
        return Impl::MakeErrorResult("EmulationSession: null implementation");
    }

    if (m_impl->m_executed) {
        return Impl::MakeErrorResult(
            "EmulationSession: already consumed — construct a new session");
    }
    m_impl->m_executed = true;

    std::string errorMsg;
    if (!m_impl->ValidateConfig(errorMsg)) {
        return Impl::MakeErrorResult(errorMsg);
    }

    if (!m_impl->ValidateBufferInput(buffer, base, entry, errorMsg)) {
        return Impl::MakeErrorResult(errorMsg);
    }

    // Phase 1: Environment setup
    if (!m_impl->SetupEnvironment(errorMsg)) {
        return Impl::MakeErrorResult(errorMsg);
    }

    // Phase 2a: API dispatcher
    if (!m_impl->SetupAPIDispatcher(errorMsg)) {
        return Impl::MakeErrorResult(errorMsg);
    }

    // Phase 2d: Load raw buffer
    Impl::LoadedTarget target;
    if (!m_impl->LoadBuffer(buffer, base, entry, is64Bit, target, errorMsg)) {
        return Impl::MakeErrorResult(errorMsg);
    }

    // Phases 3–6
    return m_impl->ExecutePipeline(target);
}

// ============================================================================
// RequestAbort (thread-safe)
// ============================================================================

void EmulationSession::RequestAbort() noexcept {
    if (m_impl) {
        m_impl->m_abortRequested.store(true, std::memory_order_release);
        // Also request abort on the CPU directly — this ensures the CPU loop
        // checks even if no API calls or pre-instruction callbacks fire.
        m_impl->m_cpu.RequestAbort();
    }
}

// ============================================================================
// GetConfig
// ============================================================================

const EmulationConfig& EmulationSession::GetConfig() const noexcept {
    // DESIGN: return a stable fallback when the session was constructed
    // under memory pressure (m_impl == nullptr) or has been moved-from.
    // The fallback is a default-initialised EmulationConfig with a static
    // storage duration so the returned reference remains valid for the
    // lifetime of the process. Avoids a null dereference for callers that
    // probe configuration after a failed construction.
    if (!m_impl) {
        static const EmulationConfig kDefaultConfig{};
        return kDefaultConfig;
    }
    return m_impl->m_config;
}

} // namespace Phantom
