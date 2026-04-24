/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 *
 * EnvironmentBuilder — Master orchestrator for virtual environment setup.
 * Initializes all VirtualOS subsystems in dependency order, randomizes
 * session-specific values, validates cross-system consistency, and builds
 * guest PEB/TEB/LDR structures for x64 Windows 10 22H2 emulation.
 */

#include "EnvironmentBuilder.hpp"
#include "../Common/Config.hpp"
#include "../Common/Errors.hpp"
#include "../Common/Constants.hpp"
#include "../Core/Memory/VirtualMemory.hpp"

// VirtualOS subsystem headers (developed in parallel — each is a Meyers'
// Singleton exposing ::Instance() and ::Initialize(const EmulationConfig&))
#include "VirtualFileSystem.hpp"
#include "VirtualRegistry.hpp"
#include "VirtualProcess.hpp"
#include "VirtualNetwork.hpp"
#include "AntiEvasion/TimingAntiEvasion.hpp"
#include "AntiEvasion/EnvironmentAntiEvasion.hpp"
#include "AntiEvasion/DebuggerAntiEvasion.hpp"
#include "AntiEvasion/VMAntiEvasion.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <vector>

namespace Phantom::VirtualOS {

namespace {

// ============================================================================
// Guest Memory Layout — Fixed Addresses for OS Structures
// ============================================================================

// RTL_USER_PROCESS_PARAMETERS and associated string data
static constexpr GuestAddress kProcessParamsBase    = 0x0000000020000000ULL;
static constexpr GuestSize    kProcessParamsSize    = 2 * kPageSize;
static constexpr GuestAddress kProcessParamsStrBase = kProcessParamsBase + kPageSize;

// PEB_LDR_DATA + LDR_DATA_TABLE_ENTRY array + string buffers
static constexpr GuestAddress kLdrDataBase          = 0x0000000020010000ULL;
static constexpr GuestSize    kLdrRegionSize        = 4 * kPageSize;

// PEB_LDR_DATA layout
static constexpr uint32_t kLdrHeaderSize  = 0x60;   // Rounded up for alignment
static constexpr uint32_t kLdrEntryStride = 0x80;   // 0x70 entry + 0x10 padding
static constexpr uint32_t kMaxLdrModules  = 16;
// String buffer offset from kLdrDataBase: past header + max entries
static constexpr uint32_t kLdrStringOff   = kLdrHeaderSize +
                                            kMaxLdrModules * kLdrEntryStride;

// Environment variable block
static constexpr GuestAddress kEnvBlockBase         = 0x0000000020020000ULL;
static constexpr GuestSize    kEnvBlockSize         = kPageSize;

// ProcessHeaps pointer array (PEB.ProcessHeaps points here)
static constexpr GuestAddress kProcessHeapArrayBase = 0x0000000020030000ULL;

// Identity strings flow into fixed-size guest PEB/process-parameter regions.
// Keep them comfortably below Windows' USHORT-backed UNICODE_STRING limit and
// below realistic endpoint identity lengths to avoid partial guest writes.
static constexpr size_t kMaxIdentityChars = 64;
static constexpr size_t kMaxUnicodeStringChars = 0x7FFE / sizeof(wchar_t);
static constexpr uint64_t kMinTscFrequencyHz = 1'000'000'000ULL;
static constexpr uint64_t kMaxTscFrequencyHz = 10'000'000'000ULL;
static constexpr uint64_t kMaxPhysicalMemoryBytes = 1ULL << 50; // 1 PiB

// ============================================================================
// PEB Field Offsets — x64 Windows 10 22H2
// Verified against ntdll!_PEB structure layout
// ============================================================================

namespace PEBOff {
    constexpr uint32_t BeingDebugged            = 0x002;
    constexpr uint32_t BitField                 = 0x003;
    constexpr uint32_t Mutant                   = 0x008;
    constexpr uint32_t ImageBaseAddress         = 0x010;
    constexpr uint32_t Ldr                      = 0x018;
    constexpr uint32_t ProcessParameters        = 0x020;
    constexpr uint32_t SubSystemData            = 0x028;
    constexpr uint32_t ProcessHeap              = 0x030;
    constexpr uint32_t ReadOnlySharedMemBase    = 0x088;
    constexpr uint32_t SharedData               = 0x090;
    constexpr uint32_t NumberOfProcessors       = 0x0B8;
    constexpr uint32_t NtGlobalFlag             = 0x0BC;
    constexpr uint32_t CriticalSectionTimeout   = 0x0C8;
    constexpr uint32_t HeapSegmentReserve       = 0x0D0;
    constexpr uint32_t HeapSegmentCommit        = 0x0D8;
    constexpr uint32_t HeapDeCommitTotalFree    = 0x0E0;
    constexpr uint32_t HeapDeCommitFreeBlock    = 0x0E8;
    constexpr uint32_t NumberOfHeaps            = 0x0F0;
    constexpr uint32_t MaximumNumberOfHeaps     = 0x0F4;
    constexpr uint32_t ProcessHeaps             = 0x0F8;
    constexpr uint32_t GdiSharedHandleTable     = 0x100;
    constexpr uint32_t OSMajorVersion           = 0x2C0;
    constexpr uint32_t OSMinorVersion           = 0x2C4;
    constexpr uint32_t OSBuildNumber            = 0x2C8;
    constexpr uint32_t OSCSDVersion             = 0x2CA;
    constexpr uint32_t OSPlatformId             = 0x2CC;
    constexpr uint32_t ImageSubsystem           = 0x2D0;
    constexpr uint32_t ImageSubsystemMajor      = 0x2D4;
    constexpr uint32_t ImageSubsystemMinor      = 0x2D8;
    constexpr uint32_t SessionId                = 0x378;
} // namespace PEBOff

// ============================================================================
// TEB Field Offsets — x64 Windows 10 22H2
// ============================================================================

namespace TEBOff {
    constexpr uint32_t ExceptionList            = 0x000;
    constexpr uint32_t StackBase                = 0x008;
    constexpr uint32_t StackLimit               = 0x010;
    constexpr uint32_t SubSystemTib             = 0x018;
    constexpr uint32_t FiberData                = 0x020;
    constexpr uint32_t ArbitraryUserPointer     = 0x028;
    constexpr uint32_t Self                     = 0x030;
    constexpr uint32_t EnvironmentPointer       = 0x038;
    constexpr uint32_t ClientIdProcess          = 0x040;
    constexpr uint32_t ClientIdThread           = 0x048;
    constexpr uint32_t ActiveRpcHandle          = 0x050;
    constexpr uint32_t Tls                      = 0x058;
    constexpr uint32_t PEB                      = 0x060;
    constexpr uint32_t LastErrorValue           = 0x068;
    constexpr uint32_t CountOfOwnedCritSecs     = 0x06C;
    constexpr uint32_t CsrClientThread          = 0x070;
    constexpr uint32_t Win32ThreadInfo          = 0x078;
    constexpr uint32_t CurrentLocale            = 0x0E10;
    constexpr uint32_t ReservedForOle           = 0x1250;
} // namespace TEBOff

// ============================================================================
// RTL_USER_PROCESS_PARAMETERS Field Offsets (x64)
// ============================================================================

namespace PPOff {
    constexpr uint32_t MaximumLength            = 0x000;
    constexpr uint32_t Length                    = 0x004;
    constexpr uint32_t Flags                    = 0x008;
    constexpr uint32_t ConsoleHandle            = 0x010;
    constexpr uint32_t CurrentDirectoryPath     = 0x020; // UNICODE_STRING (16 bytes)
    constexpr uint32_t CurrentDirectoryHandle   = 0x030;
    constexpr uint32_t DllPath                  = 0x040; // UNICODE_STRING
    constexpr uint32_t ImagePathName            = 0x050; // UNICODE_STRING
    constexpr uint32_t CommandLine              = 0x060; // UNICODE_STRING
    constexpr uint32_t Environment              = 0x070;
    constexpr uint32_t StructSize               = 0x400; // Conservative allocation
} // namespace PPOff

// ============================================================================
// PEB_LDR_DATA Field Offsets (x64)
// ============================================================================

namespace LDROff {
    constexpr uint32_t Length                    = 0x000;
    constexpr uint32_t Initialized              = 0x004;
    constexpr uint32_t SsHandle                 = 0x008;
    constexpr uint32_t InLoadOrderList          = 0x010;
    constexpr uint32_t InMemoryOrderList        = 0x020;
    constexpr uint32_t InInitOrderList          = 0x030;
    constexpr uint32_t EntryInProgress          = 0x040;
    constexpr uint32_t ShutdownInProgress       = 0x048;
    constexpr uint32_t ShutdownThreadId         = 0x050;
    constexpr uint32_t HeaderSize               = 0x058;
} // namespace LDROff

// ============================================================================
// LDR_DATA_TABLE_ENTRY Field Offsets (x64)
// ============================================================================

namespace LDREntOff {
    constexpr uint32_t InLoadOrderLinks         = 0x000; // LIST_ENTRY (16 bytes)
    constexpr uint32_t InMemoryOrderLinks       = 0x010;
    constexpr uint32_t InInitOrderLinks         = 0x020;
    constexpr uint32_t DllBase                  = 0x030;
    constexpr uint32_t EntryPoint               = 0x038;
    constexpr uint32_t SizeOfImage              = 0x040;
    constexpr uint32_t FullDllName              = 0x048; // UNICODE_STRING (16 bytes)
    constexpr uint32_t BaseDllName              = 0x058; // UNICODE_STRING (16 bytes)
    constexpr uint32_t Flags                    = 0x068;
    constexpr uint32_t LoadCount                = 0x06C;
    constexpr uint32_t TlsIndex                 = 0x06E;
    constexpr uint32_t EntrySize                = 0x070;
} // namespace LDREntOff

// ============================================================================
// Module Descriptor — local struct for LDR module list building
// ============================================================================

struct ModuleDescriptor {
    std::wstring fullPath;
    std::wstring baseName;
    GuestAddress dllBase;
    GuestAddress entryPoint;
    uint32_t     sizeOfImage;
    bool         inInitOrder; // Main exe is NOT in InInitializationOrder
};

[[nodiscard]] constexpr bool FitsGuestRange(
    GuestAddress start,
    GuestSize size,
    GuestAddress exclusiveLimit) noexcept
{
    if (start > exclusiveLimit) return false;
    const GuestSize available = exclusiveLimit - start;
    return size <= available;
}

// ============================================================================
// Helper: Write wide string as UTF-16LE to guest memory
// ============================================================================

static bool WriteWideString(
    VirtualMemory& memory,
    GuestAddress   addr,
    const std::wstring& str,
    GuestAddress   exclusiveLimit) noexcept
{
    if (str.size() > kMaxUnicodeStringChars) return false;

    const GuestSize byteLen = static_cast<GuestSize>(str.size()) * sizeof(wchar_t);
    const GuestSize totalBytes = byteLen + sizeof(wchar_t);
    if (totalBytes < byteLen || !FitsGuestRange(addr, totalBytes, exclusiveLimit)) {
        return false;
    }

    for (size_t i = 0; i < str.size(); ++i) {
        const auto ch = static_cast<uint16_t>(str[i]);
        if (memory.WriteU16(addr + static_cast<GuestAddress>(i * sizeof(wchar_t)), ch)
            != ErrorCode::Success)
            return false;
    }
    // Null terminator
    return memory.WriteU16(
        addr + static_cast<GuestAddress>(str.size() * sizeof(wchar_t)), 0
    ) == ErrorCode::Success;
}

// ============================================================================
// Helper: Write UNICODE_STRING struct (16 bytes on x64) + string data,
// advance the cursor past the written string data (8-byte aligned)
// ============================================================================

static bool WriteUnicodeString(
    VirtualMemory& memory,
    GuestAddress   structAddr,
    GuestAddress&  cursor,
    const std::wstring& str,
    GuestAddress   stringLimit) noexcept
{
    if (str.size() > kMaxUnicodeStringChars) return false;

    const GuestSize byteLen64 = static_cast<GuestSize>(str.size()) * sizeof(wchar_t);
    const GuestSize maxLen64 = byteLen64 + sizeof(wchar_t);
    if (maxLen64 < byteLen64 ||
        maxLen64 > std::numeric_limits<uint16_t>::max() ||
        !FitsGuestRange(cursor, maxLen64, stringLimit)) {
        return false;
    }

    const GuestAddress nextCursor = AlignUp(cursor + maxLen64, 8);
    if (nextCursor < cursor || nextCursor > stringLimit) {
        return false;
    }

    const auto byteLen = static_cast<uint16_t>(byteLen64);
    const auto maxLen  = static_cast<uint16_t>(maxLen64);

    // UNICODE_STRING layout: Length(2) + MaximumLength(2) + pad(4) + Buffer(8)
    if (memory.WriteU16(structAddr + 0, byteLen) != ErrorCode::Success) return false;
    if (memory.WriteU16(structAddr + 2, maxLen)  != ErrorCode::Success) return false;
    if (memory.WriteU32(structAddr + 4, 0)       != ErrorCode::Success) return false;
    if (memory.WriteU64(structAddr + 8, cursor)  != ErrorCode::Success) return false;

    if (!WriteWideString(memory, cursor, str, stringLimit)) return false;

    cursor = nextCursor;
    return true;
}

// ============================================================================
// Helper: Write a LIST_ENTRY (Flink + Blink, 16 bytes total)
// ============================================================================

static bool WriteListEntry(
    VirtualMemory& memory,
    GuestAddress   addr,
    GuestAddress   flink,
    GuestAddress   blink) noexcept
{
    if (memory.WriteU64(addr + 0, flink) != ErrorCode::Success) return false;
    return memory.WriteU64(addr + 8, blink) == ErrorCode::Success;
}

// ============================================================================
// Helper: Extract CPU brand string from CPUID constants
// ============================================================================

static std::string ExtractCPUIDBrandString() noexcept {
    char brand[49] = {};
    static_assert(sizeof(CPUID::kBrand) == 48, "CPUID brand array must be 48 bytes");
    std::memcpy(brand, CPUID::kBrand, 48);
    brand[48] = '\0';

    size_t len = 48;
    while (len > 0 && (brand[len - 1] == '\0' || brand[len - 1] == ' '))
        --len;
    return std::string(brand, len);
}

// ============================================================================
// Helper: Build default module list for PEB LDR data
// ============================================================================

static std::vector<ModuleDescriptor> BuildDefaultModuleList(
    const std::wstring& userName) noexcept
{
    std::vector<ModuleDescriptor> modules;
    modules.reserve(4);

    const std::wstring samplePath =
        L"C:\\Users\\" + userName + L"\\Desktop\\sample.exe";

    // Main executable — NOT in InInitializationOrder
    modules.push_back({
        samplePath,
        L"sample.exe",
        WinConst::kDefaultImageBase64,
        WinConst::kDefaultImageBase64 + 0x1000,
        0x00010000,
        false
    });

    // ntdll.dll — first DLL initialized
    modules.push_back({
        L"C:\\Windows\\System32\\ntdll.dll",
        L"ntdll.dll",
        WinConst::kNtdllBase64,
        0,
        0x001F0000,
        true
    });

    // kernel32.dll
    modules.push_back({
        L"C:\\Windows\\System32\\kernel32.dll",
        L"kernel32.dll",
        WinConst::kKernel32Base64,
        WinConst::kKernel32Base64 + 0x1000,
        0x000F0000,
        true
    });

    // KernelBase.dll
    modules.push_back({
        L"C:\\Windows\\System32\\KernelBase.dll",
        L"KernelBase.dll",
        WinConst::kKernelBaseBase64,
        WinConst::kKernelBaseBase64 + 0x1000,
        0x00340000,
        true
    });

    return modules;
}

// ============================================================================
// Helper: Write environment variable block to guest memory
// Format: NAME=VALUE\0 pairs terminated by a double null
// ============================================================================

static bool WriteEnvironmentBlock(
    VirtualMemory& memory,
    GuestAddress   base,
    const EmulationConfig& cfg) noexcept
{
    struct EnvVar { std::wstring name; std::wstring value; };

    const std::wstring user(cfg.userName);
    const std::vector<EnvVar> vars = {
        { L"COMPUTERNAME",            std::wstring(cfg.computerName) },
        { L"USERNAME",                user },
        { L"USERDOMAIN",             std::wstring(cfg.domainName) },
        { L"SYSTEMROOT",             L"C:\\Windows" },
        { L"WINDIR",                 L"C:\\Windows" },
        { L"PATH",                   L"C:\\Windows\\system32;C:\\Windows" },
        { L"TEMP",                   L"C:\\Users\\" + user + L"\\AppData\\Local\\Temp" },
        { L"TMP",                    L"C:\\Users\\" + user + L"\\AppData\\Local\\Temp" },
        { L"PROCESSOR_ARCHITECTURE", L"AMD64" },
        { L"NUMBER_OF_PROCESSORS",   std::to_wstring(cfg.processorCount) },
        { L"OS",                     L"Windows_NT" },
        { L"USERPROFILE",            L"C:\\Users\\" + user },
    };

    GuestAddress cursor = base;

    for (const auto& var : vars) {
        const std::wstring entry = var.name + L"=" + var.value;
        if (entry.size() > kMaxUnicodeStringChars) return false;
        const auto byteSize = static_cast<GuestSize>((entry.size() + 1) * sizeof(wchar_t));
        if (!FitsGuestRange(cursor, byteSize + sizeof(wchar_t), base + kEnvBlockSize)) {
            return false;
        }

        if (!WriteWideString(memory, cursor, entry, base + kEnvBlockSize)) return false;
        cursor += byteSize;
    }

    // Double null terminator (marks end of environment block)
    return memory.WriteU16(cursor, 0) == ErrorCode::Success;
}

} // anonymous namespace

// ============================================================================
// Meyers' Singleton
// ============================================================================

EnvironmentBuilder& EnvironmentBuilder::Instance() noexcept {
    static EnvironmentBuilder instance;
    return instance;
}

// ============================================================================
// Build — Master Initialization Sequence
// ============================================================================

bool EnvironmentBuilder::Build(const EmulationConfig& config) noexcept {
    std::unique_lock lock(m_mutex);

    ResetUnlocked();

    // 1. Copy config and randomize session-specific values
    m_config = config;
    RandomizeSessionValues(m_config);

    if (!ValidateConfigInput(m_config, nullptr)) {
        ResetUnlocked();
        return false;
    }

    // 2. Initialize all subsystems in dependency order
    if (!InitializeSubsystems(m_config)) {
        ResetUnlocked();
        return false;
    }

    // 3. Validate cross-system consistency
    if (!ValidateConsistency()) {
        ResetUnlocked();
        return false;
    }

    // 4. Set fixed guest addresses from codebase constants
    m_pebAddress           = WinConst::kPEBAddress64;
    m_tebAddress           = WinConst::kTEBAddress64;
    m_processParamsAddress = kProcessParamsBase;
    m_ldrDataAddress       = kLdrDataBase;
    m_processHeapAddress   = WinConst::kProcessHeapBase64;

    m_initialized = true;
    return true;
}

// ============================================================================
// Reset — Tear Down All Subsystems (reverse initialization order)
// ============================================================================

void EnvironmentBuilder::Reset() noexcept {
    std::unique_lock lock(m_mutex);
    ResetUnlocked();
}

void EnvironmentBuilder::ResetUnlocked() noexcept {
    // Reverse of InitializeSubsystems order
    VirtualProcess::Instance().Reset();
    VirtualNetwork::Instance().Reset();
    VirtualRegistry::Instance().Reset();
    VirtualFileSystem::Instance().Reset();
    AntiEvasion::VMAntiEvasion::Instance().Reset();
    AntiEvasion::DebuggerAntiEvasion::Instance().Reset();
    AntiEvasion::EnvironmentAntiEvasion::Instance().Reset();
    AntiEvasion::TimingAntiEvasion::Instance().Reset();

    m_initialized          = false;
    m_pebAddress           = 0;
    m_tebAddress           = 0;
    m_processParamsAddress = 0;
    m_ldrDataAddress       = 0;
    m_processHeapAddress   = 0;
    m_config               = {};
}

// ============================================================================
// RandomizeSessionValues — Per-Session Variation
// Ensures each emulation session has unique timing / identity values
// to defeat fingerprint-based evasion
// ============================================================================

void EnvironmentBuilder::RandomizeSessionValues(EmulationConfig& config) noexcept {
    // PCG-style LCG: deterministic within session, varies across sessions
    // Seeded from config address XOR constant for per-instance diversity
    uint64_t seed = reinterpret_cast<uint64_t>(&config) ^ 0x5DEECE66DULL;
    auto nextRand = [&seed]() -> uint32_t {
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        return static_cast<uint32_t>(seed >> 16);
    };

    // Randomize tick count if at default (0)
    // Range: 300 000 – 900 000 ms → ~5–15 minutes uptime (realistic)
    if (config.fakeTickCount == 0) {
        config.fakeTickCount = 300000 + (nextRand() % 600000);
    }

    // Ensure processor count is plausible (guards against zero or absurd values)
    if (config.processorCount == 0) {
        config.processorCount = 4 + (nextRand() % 5); // 4–8 cores
    }

    // Ensure OS build is populated
    if (config.osBuildNumber == 0) {
        config.osBuildNumber = 19045; // Windows 10 22H2
    }

    // Ensure TSC frequency is set
    if (config.fakeTSCFrequency == 0) {
        config.fakeTSCFrequency = 3'200'000'000ULL +
                                  (static_cast<uint64_t>(nextRand() % 10) * 100'000'000ULL);
    }
}

// ============================================================================
// InitializeSubsystems — Strict Dependency-Ordered Initialization
//
// Order:
//   1. AntiEvasion::TimingAntiEvasion          (no deps)
//   2. AntiEvasion::EnvironmentAntiEvasion     (no deps)
//   3. AntiEvasion::DebuggerAntiEvasion        (no deps)
//   4. AntiEvasion::VMAntiEvasion              (no deps)
//   5. VirtualFileSystem                        (needs config.userName for paths)
//   6. VirtualRegistry                          (needs config for hardware values)
//   7. VirtualNetwork                           (needs config.computerName)
//   8. VirtualProcess                           (needs config for PID/process list)
// ============================================================================

bool EnvironmentBuilder::InitializeSubsystems(const EmulationConfig& config) noexcept {
    // Anti-evasion modules (independent, no cross-dependencies) — Initialize is
    // void and infallible; subsystems remain in a benign default state if config
    // is minimal.
    AntiEvasion::TimingAntiEvasion::Instance().Initialize(config);
    AntiEvasion::EnvironmentAntiEvasion::Instance().Initialize(config);
    AntiEvasion::DebuggerAntiEvasion::Instance().Initialize(config);
    AntiEvasion::VMAntiEvasion::Instance().Initialize(config);

    // Virtual filesystem (user profile paths depend on config.userName)
    if (config.enableFileSystem) {
        VirtualFileSystem::Instance().Initialize(config);
    }

    // Virtual registry (hardware descriptors, OS version keys)
    if (config.enableRegistry) {
        VirtualRegistry::Instance().Initialize(config);
    }

    // Virtual network (hostname derives from config.computerName)
    if (config.enableNetwork) {
        VirtualNetwork::Instance().Initialize(config);
    }

    // Virtual process (PID assignment, process table population)
    VirtualProcess::Instance().Initialize(config);

    return true;
}

// ============================================================================
// ValidateConsistency — Cross-Subsystem Coherence Gate
// Called during Build(); returns false on critical errors
// ============================================================================

bool EnvironmentBuilder::ValidateConsistency() noexcept {
    auto result = ValidateUnlocked();
    return result.errors.empty();
}

// ============================================================================
// Validate — Full Cross-System Consistency Report
// ============================================================================

EnvironmentValidation EnvironmentBuilder::Validate() const noexcept {
    std::shared_lock lock(m_mutex);
    return ValidateUnlocked();
}

EnvironmentValidation EnvironmentBuilder::ValidateUnlocked() const noexcept {
    EnvironmentValidation result;
    result.isValid = true;

    if (!m_initialized && m_config.fakeTickCount == 0) {
        result.warnings.emplace_back(
            "Validation called before Build(); limited checks available");
        return result;
    }

    if (!ValidateConfigInput(m_config, &result)) {
        // Continue collecting cross-subsystem drift so callers get a complete report.
    }

    // ----------------------------------------------------------------
    // Check 1: Processor count within plausible hardware bounds
    // (malware rejects obvious sandbox fingerprints like 1-core systems)
    // ----------------------------------------------------------------
    if (m_config.processorCount == 0 || m_config.processorCount > 128) {
        result.errors.emplace_back(
            "Processor count out of range: " +
            std::to_string(m_config.processorCount));
        result.isValid = false;
    }

    // ----------------------------------------------------------------
    // Check 2: TSC frequency consistency between TimingAntiEvasion and
    // emulation config (malware cross-references RDTSC vs QueryPerformanceCounter)
    // ----------------------------------------------------------------
    auto& tAE = AntiEvasion::TimingAntiEvasion::Instance();
    if (tAE.GetTSCFrequency() != m_config.fakeTSCFrequency) {
        result.warnings.emplace_back(
            "TimingAntiEvasion TSC frequency (" +
            std::to_string(tAE.GetTSCFrequency()) +
            ") differs from config (" +
            std::to_string(m_config.fakeTSCFrequency) + ")");
    }

    // ----------------------------------------------------------------
    // Check 3: Emulated PID resolvable from the fake process list
    // ----------------------------------------------------------------
    auto& vProc = VirtualProcess::Instance();
    const auto currentPID = vProc.GetCurrentPID();
    if (!vProc.GetProcessByPID(currentPID).has_value()) {
        result.errors.emplace_back(
            "Emulated PID " + std::to_string(currentPID) +
            " not found in fake process list");
        result.isValid = false;
    }

    // ----------------------------------------------------------------
    // Check 4: Parent PID consistent between DebuggerAntiEvasion
    // and VirtualProcess (malware compares NtQueryInformationProcess
    // parent PID with CreateToolhelp32Snapshot parent PID)
    // ----------------------------------------------------------------
    auto& dbgAE = AntiEvasion::DebuggerAntiEvasion::Instance();
    if (dbgAE.GetParentProcessId() != vProc.GetParentPID()) {
        result.errors.emplace_back(
            "Parent PID mismatch: DebuggerAntiEvasion=" +
            std::to_string(dbgAE.GetParentProcessId()) +
            " VirtualProcess=" +
            std::to_string(vProc.GetParentPID()));
        result.isValid = false;
    }

    return result;
}

bool EnvironmentBuilder::ValidateConfigInput(
    const EmulationConfig& config,
    EnvironmentValidation* validation) const noexcept
{
    auto fail = [validation](std::string message) noexcept {
        if (validation) {
            validation->errors.emplace_back(std::move(message));
            validation->isValid = false;
        }
        return false;
    };

    bool ok = true;

    if (config.computerName.size() > kMaxIdentityChars) {
        ok = fail("Computer name exceeds virtual environment identity limit");
    }
    if (config.userName.size() > kMaxIdentityChars) {
        ok = fail("User name exceeds virtual environment identity limit");
    }
    if (config.domainName.size() > kMaxIdentityChars) {
        ok = fail("Domain name exceeds virtual environment identity limit");
    }
    if (config.windowsVersion.size() > kMaxIdentityChars) {
        ok = fail("Windows version string exceeds virtual environment identity limit");
    }
    if (config.processorCount == 0 || config.processorCount > 128) {
        ok = fail("Processor count must be in range 1..128 after session randomization");
    }
    if (config.osBuildNumber > std::numeric_limits<uint16_t>::max()) {
        ok = fail("OS build number exceeds PEB.OSBuildNumber USHORT range");
    }
    if (config.fakeTSCFrequency < kMinTscFrequencyHz ||
        config.fakeTSCFrequency > kMaxTscFrequencyHz) {
        ok = fail("TSC frequency is outside plausible endpoint CPU bounds");
    }
    if (config.totalPhysicalMem == 0 ||
        config.totalPhysicalMem > kMaxPhysicalMemoryBytes) {
        ok = fail("Total physical memory is outside supported endpoint bounds");
    }

    return ok;
}

// ============================================================================
// BuildPEBTEB — Write PEB, TEB, and ProcessParameters to Guest Memory
// Must be called AFTER Build() and AFTER VirtualMemory is initialized
// ============================================================================

bool EnvironmentBuilder::BuildPEBTEB(VirtualMemory& memory) noexcept {
    std::shared_lock lock(m_mutex);
    if (!m_initialized) return false;

    // Write structures in dependency order:
    // ProcessParameters first (PEB.ProcessParameters points to it)
    // PEB second (TEB.PEB points to it)
    // TEB last
    if (!WriteProcessParameters(memory)) return false;
    if (!WritePEB(memory))               return false;
    if (!WriteTEB(memory))               return false;

    return true;
}

// ============================================================================
// BuildLdrData — Public entry point for LDR data construction
// Must be called AFTER modules are loaded into guest memory
// ============================================================================

bool EnvironmentBuilder::BuildLdrData(VirtualMemory& memory) noexcept {
    std::shared_lock lock(m_mutex);
    if (!m_initialized) return false;
    return WriteLdrData(memory);
}

// ============================================================================
// WritePEB — Process Environment Block (x64, ~0x7EC bytes used)
//
// CRITICAL anti-debug fields:
//   PEB+0x002 BeingDebugged  MUST be 0
//   PEB+0x0BC NtGlobalFlag   MUST be 0
//
// Malware reads these via gs:[0x60] → PEB, then checks offsets directly.
// ============================================================================

bool EnvironmentBuilder::WritePEB(VirtualMemory& memory) noexcept {
    const GuestAddress peb = m_pebAddress;

    // Allocate PEB region (single 4 KB page; PEB structure fits within)
    auto region = memory.Allocate(peb, kPageSize, MemProt::RW);
    if (!region.has_value()) return false;

    // Typed write helpers for concise, readable field population
    auto w8  = [&](GuestAddress a, uint8_t  v) {
        return memory.WriteU8(a, v)  == ErrorCode::Success;
    };
    auto w16 = [&](GuestAddress a, uint16_t v) {
        return memory.WriteU16(a, v) == ErrorCode::Success;
    };
    auto w32 = [&](GuestAddress a, uint32_t v) {
        return memory.WriteU32(a, v) == ErrorCode::Success;
    };
    auto w64 = [&](GuestAddress a, uint64_t v) {
        return memory.WriteU64(a, v) == ErrorCode::Success;
    };

    // 0x002: BeingDebugged = 0 — CRITICAL: malware reads this first
    if (!w8(peb + PEBOff::BeingDebugged, 0)) return false;

    // 0x003: BitField = 0x04 (IsImageDynamicallyRelocated)
    if (!w8(peb + PEBOff::BitField, 0x04)) return false;

    // 0x008: Mutant = INVALID_HANDLE_VALUE
    if (!w64(peb + PEBOff::Mutant, WinConst::INVALID_HANDLE_VALUE)) return false;

    // 0x010: ImageBaseAddress — PE64 default image base
    if (!w64(peb + PEBOff::ImageBaseAddress, WinConst::kDefaultImageBase64)) return false;

    // 0x018: Ldr → PEB_LDR_DATA (populated later by BuildLdrData)
    if (!w64(peb + PEBOff::Ldr, m_ldrDataAddress)) return false;

    // 0x020: ProcessParameters → RTL_USER_PROCESS_PARAMETERS
    if (!w64(peb + PEBOff::ProcessParameters, m_processParamsAddress)) return false;

    // 0x028: SubSystemData = 0
    if (!w64(peb + PEBOff::SubSystemData, 0)) return false;

    // 0x030: ProcessHeap
    if (!w64(peb + PEBOff::ProcessHeap, m_processHeapAddress)) return false;

    // 0x088: ReadOnlySharedMemoryBase = 0x7FFE0000 (KUSER_SHARED_DATA)
    if (!w64(peb + PEBOff::ReadOnlySharedMemBase, 0x7FFE0000ULL)) return false;

    // 0x090: SharedData = 0x7FFE0000
    if (!w64(peb + PEBOff::SharedData, 0x7FFE0000ULL)) return false;

    // 0x0B8: NumberOfProcessors
    if (!w32(peb + PEBOff::NumberOfProcessors, m_config.processorCount)) return false;

    // 0x0BC: NtGlobalFlag = 0 — CRITICAL: FLG_HEAP_* flags leak debugger presence
    if (!w32(peb + PEBOff::NtGlobalFlag, 0)) return false;

    // 0x0C8: CriticalSectionTimeout = -1
    if (!w64(peb + PEBOff::CriticalSectionTimeout, 0xFFFFFFFFFFFFFFFFULL)) return false;

    // 0x0D0: HeapSegmentReserve = 1 MB
    if (!w64(peb + PEBOff::HeapSegmentReserve, 1024ULL * 1024)) return false;

    // 0x0D8: HeapSegmentCommit = 4 KB
    if (!w64(peb + PEBOff::HeapSegmentCommit, 4096ULL)) return false;

    // 0x0E0: HeapDeCommitTotalFreeThreshold = 64 KB
    if (!w64(peb + PEBOff::HeapDeCommitTotalFree, 64ULL * 1024)) return false;

    // 0x0E8: HeapDeCommitFreeBlockThreshold = 4 KB
    if (!w64(peb + PEBOff::HeapDeCommitFreeBlock, 4096ULL)) return false;

    // 0x0F0: NumberOfHeaps = 1
    if (!w32(peb + PEBOff::NumberOfHeaps, 1)) return false;

    // 0x0F4: MaximumNumberOfHeaps = 16
    if (!w32(peb + PEBOff::MaximumNumberOfHeaps, 16)) return false;

    // 0x0F8: ProcessHeaps → array containing one heap base pointer
    if (!w64(peb + PEBOff::ProcessHeaps, kProcessHeapArrayBase)) return false;

    // Allocate and populate the ProcessHeaps array (single entry)
    auto heapArrayRegion = memory.Allocate(kProcessHeapArrayBase, kPageSize, MemProt::RW);
    if (!heapArrayRegion.has_value()) return false;
    if (!w64(kProcessHeapArrayBase, m_processHeapAddress)) return false;

    // 0x2C0: OSMajorVersion = 10
    if (!w32(peb + PEBOff::OSMajorVersion, 10)) return false;

    // 0x2C4: OSMinorVersion = 0
    if (!w32(peb + PEBOff::OSMinorVersion, 0)) return false;

    // 0x2C8: OSBuildNumber
    if (!w16(peb + PEBOff::OSBuildNumber,
             static_cast<uint16_t>(m_config.osBuildNumber))) return false;

    // 0x2CA: OSCSDVersion = 0 (no service pack)
    if (!w16(peb + PEBOff::OSCSDVersion, 0)) return false;

    // 0x2CC: OSPlatformId = 2 (VER_PLATFORM_WIN32_NT)
    if (!w32(peb + PEBOff::OSPlatformId, 2)) return false;

    // 0x2D0: ImageSubsystem = 3 (IMAGE_SUBSYSTEM_WINDOWS_CUI)
    if (!w32(peb + PEBOff::ImageSubsystem, 3)) return false;

    // 0x2D4: ImageSubsystemMajorVersion = 10
    if (!w32(peb + PEBOff::ImageSubsystemMajor, 10)) return false;

    // 0x2D8: ImageSubsystemMinorVersion = 0
    if (!w32(peb + PEBOff::ImageSubsystemMinor, 0)) return false;

    // 0x378: SessionId = 1
    if (!w32(peb + PEBOff::SessionId, 1)) return false;

    return true;
}

// ============================================================================
// WriteTEB — Thread Environment Block (x64)
//
// CRITICAL self-reference fields:
//   TEB+0x030 Self         MUST point to TEB itself  (gs:[0x30])
//   TEB+0x060 PEB pointer  MUST point to PEB         (gs:[0x60])
//
// Malware locates PEB via: mov rax, gs:[0x60]
// Some shellcode locates TEB via: mov rax, gs:[0x30]
// ============================================================================

bool EnvironmentBuilder::WriteTEB(VirtualMemory& memory) noexcept {
    const GuestAddress teb = m_tebAddress;

    // TEB fields extend to offset 0x1258; allocate 2 pages (8 KB)
    auto region = memory.Allocate(teb, 2 * kPageSize, MemProt::RW);
    if (!region.has_value()) return false;

    auto w32 = [&](GuestAddress a, uint32_t v) {
        return memory.WriteU32(a, v) == ErrorCode::Success;
    };
    auto w64 = [&](GuestAddress a, uint64_t v) {
        return memory.WriteU64(a, v) == ErrorCode::Success;
    };

    const auto& vProc = VirtualProcess::Instance();
    const uint32_t pid = vProc.GetCurrentPID();
    const uint32_t tid = vProc.GetCurrentTID();
    if (pid == 0 || tid == 0) return false;

    // 0x000: NtTib.ExceptionList = -1 (no SEH chain in x64 — uses unwind tables)
    if (!w64(teb + TEBOff::ExceptionList, 0xFFFFFFFFFFFFFFFFULL)) return false;

    // 0x008: NtTib.StackBase (high address — top of committed stack)
    if (!w64(teb + TEBOff::StackBase, WinConst::kStackTop64)) return false;

    // 0x010: NtTib.StackLimit (low address — bottom of committed stack)
    if (!w64(teb + TEBOff::StackLimit, WinConst::kStackBase64)) return false;

    // 0x018: NtTib.SubSystemTib = 0
    if (!w64(teb + TEBOff::SubSystemTib, 0)) return false;

    // 0x020: NtTib.FiberData = 0x1E00 (version identifier on non-fiber threads)
    if (!w64(teb + TEBOff::FiberData, 0x1E00ULL)) return false;

    // 0x028: NtTib.ArbitraryUserPointer = 0
    if (!w64(teb + TEBOff::ArbitraryUserPointer, 0)) return false;

    // 0x030: NtTib.Self → TEB address (CRITICAL: self-referencing pointer)
    if (!w64(teb + TEBOff::Self, teb)) return false;

    // 0x038: EnvironmentPointer = 0
    if (!w64(teb + TEBOff::EnvironmentPointer, 0)) return false;

    // 0x040: ClientId.UniqueProcess (8-byte HANDLE on x64)
    if (!w64(teb + TEBOff::ClientIdProcess, static_cast<uint64_t>(pid))) return false;

    // 0x048: ClientId.UniqueThread (8-byte HANDLE on x64)
    if (!w64(teb + TEBOff::ClientIdThread, static_cast<uint64_t>(tid))) return false;

    // 0x050: ActiveRpcHandle = 0
    if (!w64(teb + TEBOff::ActiveRpcHandle, 0)) return false;

    // 0x058: ThreadLocalStoragePointer = 0
    if (!w64(teb + TEBOff::Tls, 0)) return false;

    // 0x060: ProcessEnvironmentBlock → PEB (CRITICAL: primary PEB lookup path)
    if (!w64(teb + TEBOff::PEB, m_pebAddress)) return false;

    // 0x068: LastErrorValue = 0
    if (!w32(teb + TEBOff::LastErrorValue, 0)) return false;

    // 0x06C: CountOfOwnedCriticalSections = 0
    if (!w32(teb + TEBOff::CountOfOwnedCritSecs, 0)) return false;

    // 0x070: CsrClientThread = 0
    if (!w64(teb + TEBOff::CsrClientThread, 0)) return false;

    // 0x078: Win32ThreadInfo = 0
    if (!w64(teb + TEBOff::Win32ThreadInfo, 0)) return false;

    // 0x0E10: CurrentLocale = 0x0409 (en-US)
    if (!w64(teb + TEBOff::CurrentLocale, 0x0409ULL)) return false;

    // 0x1250: ReservedForOle = 0
    if (!w64(teb + TEBOff::ReservedForOle, 0)) return false;

    return true;
}

// ============================================================================
// WriteProcessParameters — RTL_USER_PROCESS_PARAMETERS
// Contains current directory, image path, command line, and environment
// ============================================================================

bool EnvironmentBuilder::WriteProcessParameters(VirtualMemory& memory) noexcept {
    const GuestAddress ppBase = m_processParamsAddress;

    // Allocate structure + string data (2 pages)
    auto region = memory.Allocate(ppBase, kProcessParamsSize, MemProt::RW);
    if (!region.has_value()) return false;

    // Allocate environment block
    auto envRegion = memory.Allocate(kEnvBlockBase, kEnvBlockSize, MemProt::RW);
    if (!envRegion.has_value()) return false;

    auto w32 = [&](GuestAddress a, uint32_t v) {
        return memory.WriteU32(a, v) == ErrorCode::Success;
    };
    auto w64 = [&](GuestAddress a, uint64_t v) {
        return memory.WriteU64(a, v) == ErrorCode::Success;
    };

    // Build path strings from config identity
    const std::wstring userDir = L"C:\\Users\\" + std::wstring(m_config.userName);
    const std::wstring desktop = userDir + L"\\Desktop";
    const std::wstring imgPath = desktop + L"\\sample.exe";
    const std::wstring cmdLine = L"\"" + imgPath + L"\"";
    const std::wstring dllPath; // Empty for standalone executables

    // 0x000: MaximumLength
    if (!w32(ppBase + PPOff::MaximumLength, PPOff::StructSize)) return false;

    // 0x004: Length
    if (!w32(ppBase + PPOff::Length, PPOff::StructSize)) return false;

    // 0x008: Flags = 0x6001 (RTL_USER_PROC_PARAMS_NORMALIZED |
    //                         RTL_USER_PROC_SECURE_PROCESS)
    if (!w32(ppBase + PPOff::Flags, 0x6001)) return false;

    // 0x010: ConsoleHandle — synthetic console handle
    if (!w64(ppBase + PPOff::ConsoleHandle, 0x0000000000000044ULL)) return false;

    // String data is written into the string buffer region
    GuestAddress strCursor = kProcessParamsStrBase;

    // 0x020: CurrentDirectory.DosPath (UNICODE_STRING)
    if (!WriteUnicodeString(memory, ppBase + PPOff::CurrentDirectoryPath,
                            strCursor, desktop, ppBase + kProcessParamsSize))
        return false;

    // 0x040: DllPath (UNICODE_STRING) — empty
    if (!WriteUnicodeString(memory, ppBase + PPOff::DllPath,
                            strCursor, dllPath, ppBase + kProcessParamsSize))
        return false;

    // 0x050: ImagePathName (UNICODE_STRING)
    if (!WriteUnicodeString(memory, ppBase + PPOff::ImagePathName,
                            strCursor, imgPath, ppBase + kProcessParamsSize))
        return false;

    // 0x060: CommandLine (UNICODE_STRING)
    if (!WriteUnicodeString(memory, ppBase + PPOff::CommandLine,
                            strCursor, cmdLine, ppBase + kProcessParamsSize))
        return false;

    // 0x070: Environment → environment variable block
    if (!w64(ppBase + PPOff::Environment, kEnvBlockBase)) return false;

    // Populate the environment block
    if (!WriteEnvironmentBlock(memory, kEnvBlockBase, m_config)) return false;

    return true;
}

// ============================================================================
// WriteLdrData — PEB_LDR_DATA + Module Entries (Circular Doubly-Linked Lists)
//
// Builds three proper circular doubly-linked lists:
//   1. InLoadOrderModuleList      — all modules
//   2. InMemoryOrderModuleList    — all modules (offset +0x10 in entry)
//   3. InInitializationOrderModuleList — DLLs only (not main exe)
//
// Each LIST_ENTRY.Flink/Blink points to the LIST_ENTRY field within
// the target structure (not to the structure base).
// ============================================================================

bool EnvironmentBuilder::WriteLdrData(VirtualMemory& memory) noexcept {
    const GuestAddress ldrBase = m_ldrDataAddress;

    // Allocate LDR region (header + entries + string buffers)
    auto region = memory.Allocate(ldrBase, kLdrRegionSize, MemProt::RW);
    if (!region.has_value()) return false;

    auto w32 = [&](GuestAddress a, uint32_t v) {
        return memory.WriteU32(a, v) == ErrorCode::Success;
    };
    auto w64 = [&](GuestAddress a, uint64_t v) {
        return memory.WriteU64(a, v) == ErrorCode::Success;
    };

    // Build the default module list
    const auto modules = BuildDefaultModuleList(m_config.userName);
    const auto moduleCount = static_cast<uint32_t>(modules.size());

    if (moduleCount == 0 || moduleCount > kMaxLdrModules)
        return false;

    // Compute addresses for each entry
    auto entryAddr = [&](uint32_t idx) -> GuestAddress {
        return ldrBase + kLdrHeaderSize +
               static_cast<GuestAddress>(idx) * kLdrEntryStride;
    };

    // List head addresses within PEB_LDR_DATA
    const GuestAddress loadOrderHead  = ldrBase + LDROff::InLoadOrderList;
    const GuestAddress memOrderHead   = ldrBase + LDROff::InMemoryOrderList;
    const GuestAddress initOrderHead  = ldrBase + LDROff::InInitOrderList;

    // ----------------------------------------------------------------
    // Write PEB_LDR_DATA header
    // ----------------------------------------------------------------

    // 0x000: Length
    if (!w32(ldrBase + LDROff::Length, LDROff::HeaderSize)) return false;

    // 0x004: Initialized = TRUE
    if (!w32(ldrBase + LDROff::Initialized, 1)) return false;

    // 0x008: SsHandle = 0
    if (!w64(ldrBase + LDROff::SsHandle, 0)) return false;

    // ----------------------------------------------------------------
    // Build InLoadOrderModuleList (all modules, in load order)
    // Circular: Head → Entry[0] → Entry[1] → ... → Entry[N-1] → Head
    // ----------------------------------------------------------------
    {
        // Head.Flink → first entry's InLoadOrderLinks
        const GuestAddress firstEntry = entryAddr(0) + LDREntOff::InLoadOrderLinks;
        const GuestAddress lastEntry  = entryAddr(moduleCount - 1) +
                                        LDREntOff::InLoadOrderLinks;

        if (!WriteListEntry(memory, loadOrderHead, firstEntry, lastEntry))
            return false;

        for (uint32_t i = 0; i < moduleCount; ++i) {
            const GuestAddress cur = entryAddr(i) + LDREntOff::InLoadOrderLinks;
            const GuestAddress flink = (i + 1 < moduleCount)
                ? entryAddr(i + 1) + LDREntOff::InLoadOrderLinks
                : loadOrderHead;
            const GuestAddress blink = (i > 0)
                ? entryAddr(i - 1) + LDREntOff::InLoadOrderLinks
                : loadOrderHead;

            if (!WriteListEntry(memory, cur, flink, blink))
                return false;
        }
    }

    // ----------------------------------------------------------------
    // Build InMemoryOrderModuleList (all modules, same order)
    // LIST_ENTRY at offset +0x010 within each entry
    // ----------------------------------------------------------------
    {
        const GuestAddress firstEntry = entryAddr(0) + LDREntOff::InMemoryOrderLinks;
        const GuestAddress lastEntry  = entryAddr(moduleCount - 1) +
                                        LDREntOff::InMemoryOrderLinks;

        if (!WriteListEntry(memory, memOrderHead, firstEntry, lastEntry))
            return false;

        for (uint32_t i = 0; i < moduleCount; ++i) {
            const GuestAddress cur = entryAddr(i) + LDREntOff::InMemoryOrderLinks;
            const GuestAddress flink = (i + 1 < moduleCount)
                ? entryAddr(i + 1) + LDREntOff::InMemoryOrderLinks
                : memOrderHead;
            const GuestAddress blink = (i > 0)
                ? entryAddr(i - 1) + LDREntOff::InMemoryOrderLinks
                : memOrderHead;

            if (!WriteListEntry(memory, cur, flink, blink))
                return false;
        }
    }

    // ----------------------------------------------------------------
    // Build InInitializationOrderModuleList (DLLs only — excludes main exe)
    // LIST_ENTRY at offset +0x020 within each entry
    // ----------------------------------------------------------------
    {
        // Collect indices of modules that are in init order
        std::vector<uint32_t> initIndices;
        initIndices.reserve(moduleCount);
        for (uint32_t i = 0; i < moduleCount; ++i) {
            if (modules[i].inInitOrder)
                initIndices.push_back(i);
        }

        if (initIndices.empty()) {
            // Empty list: head points to itself
            if (!WriteListEntry(memory, initOrderHead, initOrderHead, initOrderHead))
                return false;
        } else {
            const GuestAddress firstInit =
                entryAddr(initIndices.front()) + LDREntOff::InInitOrderLinks;
            const GuestAddress lastInit  =
                entryAddr(initIndices.back()) + LDREntOff::InInitOrderLinks;

            if (!WriteListEntry(memory, initOrderHead, firstInit, lastInit))
                return false;

            for (size_t j = 0; j < initIndices.size(); ++j) {
                const uint32_t idx = initIndices[j];
                const GuestAddress cur =
                    entryAddr(idx) + LDREntOff::InInitOrderLinks;

                const GuestAddress flink = (j + 1 < initIndices.size())
                    ? entryAddr(initIndices[j + 1]) + LDREntOff::InInitOrderLinks
                    : initOrderHead;
                const GuestAddress blink = (j > 0)
                    ? entryAddr(initIndices[j - 1]) + LDREntOff::InInitOrderLinks
                    : initOrderHead;

                if (!WriteListEntry(memory, cur, flink, blink))
                    return false;
            }
        }
    }

    // ----------------------------------------------------------------
    // Write per-module data (DllBase, EntryPoint, SizeOfImage, names)
    // ----------------------------------------------------------------
    GuestAddress strCursor = ldrBase + kLdrStringOff;

    for (uint32_t i = 0; i < moduleCount; ++i) {
        const GuestAddress entry = entryAddr(i);
        const auto& mod = modules[i];

        // 0x030: DllBase
        if (!w64(entry + LDREntOff::DllBase, mod.dllBase)) return false;

        // 0x038: EntryPoint
        if (!w64(entry + LDREntOff::EntryPoint, mod.entryPoint)) return false;

        // 0x040: SizeOfImage
        if (!w64(entry + LDREntOff::SizeOfImage,
                 static_cast<uint64_t>(mod.sizeOfImage))) return false;

        // 0x048: FullDllName (UNICODE_STRING + string data)
        if (!WriteUnicodeString(memory, entry + LDREntOff::FullDllName,
                                strCursor, mod.fullPath, ldrBase + kLdrRegionSize))
            return false;

        // 0x058: BaseDllName (UNICODE_STRING + string data)
        if (!WriteUnicodeString(memory, entry + LDREntOff::BaseDllName,
                                strCursor, mod.baseName, ldrBase + kLdrRegionSize))
            return false;

        // 0x068: Flags — LDRP_IMAGE_DLL | LDRP_ENTRY_PROCESSED | LDRP_LOAD_NOTIFICATIONS_SENT
        const uint32_t ldrFlags = mod.inInitOrder
            ? 0x000C4004u   // DLL: processed + notifications sent + image DLL
            : 0x00084004u;  // EXE: processed + entry processed + image DLL
        if (!w32(entry + LDREntOff::Flags, ldrFlags)) return false;

        // 0x06C: ObsoleteLoadCount = 0xFFFF (static load)
        if (memory.WriteU16(entry + LDREntOff::LoadCount, 0xFFFF)
            != ErrorCode::Success)
            return false;

        // 0x06E: TlsIndex = 0
        if (memory.WriteU16(entry + LDREntOff::TlsIndex, 0)
            != ErrorCode::Success)
            return false;
    }

    // Ensure modules NOT in init order have zeroed InInitOrderLinks
    // (already zeroed by allocator, but verify explicitly for main exe)
    for (uint32_t i = 0; i < moduleCount; ++i) {
        if (!modules[i].inInitOrder) {
            if (!WriteListEntry(memory,
                    entryAddr(i) + LDREntOff::InInitOrderLinks, 0, 0))
                return false;
        }
    }

    return true;
}

// ============================================================================
// GetSnapshot — Collect Environment State for Reporting
// ============================================================================

EnvironmentSnapshot EnvironmentBuilder::GetSnapshot() const noexcept {
    std::shared_lock lock(m_mutex);
    EnvironmentSnapshot snap{};

    // Identity — directly from config
    snap.computerName   = m_config.computerName;
    snap.userName       = m_config.userName;
    snap.domainName     = m_config.domainName;

    // Hardware
    snap.cpuBrand       = ExtractCPUIDBrandString();
    snap.processorCount = m_config.processorCount;
    snap.totalRAM       = m_config.totalPhysicalMem;
    snap.totalDisk      = 512ULL * 1024 * 1024 * 1024; // 512 GB
    snap.diskModel      = "Samsung SSD 970 EVO Plus 500GB";
    snap.gpuName        = "NVIDIA GeForce RTX 3060";
    snap.macAddress     = { 0xD4, 0x5D, 0x64, 0xA1, 0xB2, 0xC3 };

    // OS
    snap.osBuild        = m_config.osBuildNumber;
    snap.windowsEdition = "Windows 10 Pro";

    // Timing — derived from config values
    snap.startTickCount = m_config.fakeTickCount;
    snap.startTSC       = m_config.fakeTickCount *
                          (m_config.fakeTSCFrequency / 1000);
    // FILETIME: 100-ns intervals since 1601-01-01
    // Approximate: 2024-03-15 10:30:00 UTC + tick-based offset
    static constexpr uint64_t kBaseFileTime = 133556250000000000ULL;
    snap.startFileTime  = kBaseFileTime +
                          (m_config.fakeTickCount * 10000ULL);

    // Process — authoritative values come from VirtualProcess so PEB/TEB,
    // snapshots, and process-query APIs cannot drift apart.
    if (m_initialized) {
        const auto& vProc = VirtualProcess::Instance();
        snap.emulatedPID        = vProc.GetCurrentPID();
        snap.parentPID          = vProc.GetParentPID();
        snap.initialTID         = vProc.GetCurrentTID();
        snap.processCount      = static_cast<uint32_t>(
            vProc.GetProcessList().size());
        snap.fileSystemEntries = 0;
        snap.registryKeys      = 0;
    }

    return snap;
}

// ============================================================================
// Accessor Methods
// ============================================================================

EmulationConfig EnvironmentBuilder::GetConfig() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_config;
}

bool EnvironmentBuilder::IsInitialized() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_initialized;
}

GuestAddress EnvironmentBuilder::GetPEBAddress() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_pebAddress;
}

GuestAddress EnvironmentBuilder::GetTEBAddress() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_tebAddress;
}

GuestAddress EnvironmentBuilder::GetPEBLdrDataAddress() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_ldrDataAddress;
}

} // namespace Phantom::VirtualOS
