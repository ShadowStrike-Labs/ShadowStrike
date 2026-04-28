/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#include "WoW64Layer.hpp"
#include "../CPU/State/CPUState.hpp"
#include "../Memory/VirtualMemory.hpp"
#include "../../Common/Constants.hpp"
#include "../../Common/Errors.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <new>
#include <unordered_map>

namespace Phantom {

// ============================================================================
// WoW64 Address Constants
// ============================================================================
// These mirror real Windows WoW64 memory layout. Malware walks these
// structures directly, so addresses must be realistic.

namespace WoW64Const {

    // Typical Windows TEB32/PEB32 locations (low 4GB, user-mode)
    static constexpr GuestAddress kTEB32Address  = 0x7EFDD000ULL;
    static constexpr GuestAddress kPEB32Address  = 0x7FFD8000ULL;
    static constexpr GuestAddress kTEB64Address  = WinConst::kTEBAddress64;
    static constexpr GuestAddress kPEB64Address  = WinConst::kPEBAddress64;

    // WoW64 DLL base addresses (emulated stubs)
    static constexpr GuestAddress kWow64DllBase     = 0x74C00000ULL;
    static constexpr GuestAddress kWow64CpuDllBase  = 0x74C50000ULL;
    static constexpr GuestAddress kWow64WinDllBase  = 0x74CA0000ULL;
    static constexpr GuestAddress kNtdll32Base      = 0x77000000ULL;
    static constexpr GuestAddress kNtdll64Base      = WinConst::kNtdllBase64;

    // wow64cpu!X86SwitchTo64BitMode stub location
    static constexpr GuestAddress kTransitionStub   = 0x74C50100ULL;
    // wow64!Wow64SystemServiceEx stub location
    static constexpr GuestAddress kSystemService    = 0x74C00200ULL;

    // Selectors matching real Windows WoW64 GDT
    static constexpr uint16_t kCS32Selector  = 0x0023;  // 32-bit code, DPL=3
    static constexpr uint16_t kCS64Selector  = 0x0033;  // 64-bit code, DPL=3
    static constexpr uint16_t kSS32Selector  = 0x002B;  // 32-bit stack, DPL=3
    static constexpr uint16_t kDS32Selector  = 0x002B;  // 32-bit data, DPL=3
    static constexpr uint16_t kFS32Selector  = 0x0053;  // FS for 32-bit TEB
    static constexpr uint16_t kGS64Selector  = 0x002B;  // GS for 64-bit TEB

    // GDT layout in guest memory
    static constexpr GuestAddress kGDTBase   = 0x00006000ULL;
    static constexpr uint32_t kGDTSize       = 0x1000;  // 4KB for GDT

    // Address space limit for 32-bit WoW64 processes
    static constexpr GuestAddress kWoW64AddressLimit = 0x100000000ULL; // 4GB

    // Maximum Heaven's Gate events before we stop recording
    static constexpr uint32_t kMaxGateEvents = 1024;

    // Maximum registered syscall translations
    static constexpr uint32_t kMaxSyscallEntries = 2048;

    // 32-bit stack-based calling convention: params start at ESP+4 (return addr at ESP)
    static constexpr uint32_t kStackParamBase32 = 4;

    // TEB32 field offsets (from NT_TIB32)
    static constexpr uint32_t kTEB32_SEH          = 0x00;  // ExceptionList
    static constexpr uint32_t kTEB32_StackBase     = 0x04;  // StackBase
    static constexpr uint32_t kTEB32_StackLimit    = 0x08;  // StackLimit
    static constexpr uint32_t kTEB32_Self          = 0x18;  // Self (FS:[0x18])
    static constexpr uint32_t kTEB32_PEB           = 0x30;  // ProcessEnvironmentBlock
    static constexpr uint32_t kTEB32_LastError      = 0x34;  // LastErrorValue
    static constexpr uint32_t kTEB32_ThreadId       = 0x24;  // ClientId.UniqueThread
    static constexpr uint32_t kTEB32_ProcessId      = 0x20;  // ClientId.UniqueProcess
    static constexpr uint32_t kTEB32_TlsSlots       = 0xE10; // TlsSlots[64]
    static constexpr uint32_t kTEB32_Size           = 0x1000;

    // PEB32 field offsets
    static constexpr uint32_t kPEB32_BeingDebugged  = 0x02;
    static constexpr uint32_t kPEB32_ImageBase      = 0x08;
    static constexpr uint32_t kPEB32_Ldr            = 0x0C;
    static constexpr uint32_t kPEB32_ProcessParams  = 0x10;
    static constexpr uint32_t kPEB32_ProcessHeap    = 0x18;
    static constexpr uint32_t kPEB32_NumberOfProc   = 0x64;
    static constexpr uint32_t kPEB32_OSMajorVersion = 0xA4;
    static constexpr uint32_t kPEB32_OSMinorVersion = 0xA8;
    static constexpr uint32_t kPEB32_OSBuildNumber  = 0xAC;
    static constexpr uint32_t kPEB32_Size           = 0x480;

} // namespace WoW64Const

// ============================================================================
// Common WoW64 Syscall Table
// ============================================================================
// Maps 32-bit (WoW64) syscall numbers to 64-bit NT syscall numbers.
// Numbers correspond to Windows 10 21H2+ (build 19044+).
// Only the most common syscalls used by malware are mapped here.

struct DefaultSyscallEntry {
    uint32_t wow64Num;
    uint32_t nativeNum;
    uint8_t  params32;
    uint8_t  params64;
    bool     ptrThunk;
};

static const std::array<DefaultSyscallEntry, 65> kDefaultSyscalls = {{
    // File operations
    { 0x0055, 0x0055, 11, 11, true  }, // NtCreateFile
    { 0x0006, 0x0006,  6,  6, true  }, // NtOpenFile
    { 0x0008, 0x0008,  9,  9, true  }, // NtReadFile
    { 0x0009, 0x0009,  9,  9, true  }, // NtWriteFile
    { 0x000F, 0x000F,  1,  1, false }, // NtClose
    { 0x0005, 0x0005,  5,  5, true  }, // NtQueryInformationFile
    { 0x0027, 0x0027,  5,  5, true  }, // NtSetInformationFile
    { 0x0035, 0x0035, 11, 11, true  }, // NtCreateSection

    // Process/Thread operations
    { 0x004A, 0x004A,  8,  8, true  }, // NtCreateProcess
    { 0x004B, 0x004B, 11, 11, true  }, // NtCreateProcessEx
    { 0x004E, 0x004E,  8,  8, true  }, // NtCreateThread
    { 0x00C1, 0x00C1, 11, 11, true  }, // NtCreateThreadEx
    { 0x0025, 0x0025,  3,  3, true  }, // NtOpenProcess
    { 0x0026, 0x0026,  4,  4, true  }, // NtOpenThread
    { 0x002C, 0x002C,  1,  1, false }, // NtTerminateProcess
    { 0x0053, 0x0053,  2,  2, false }, // NtTerminateThread
    { 0x0023, 0x0023,  5,  5, true  }, // NtQueryInformationProcess
    { 0x0022, 0x0022,  5,  5, true  }, // NtQueryInformationThread
    { 0x0050, 0x0050,  2,  2, false }, // NtResumeThread
    { 0x0051, 0x0051,  2,  2, false }, // NtSuspendThread

    // Memory operations
    { 0x0018, 0x0018,  6,  6, true  }, // NtAllocateVirtualMemory
    { 0x001E, 0x001E,  4,  4, true  }, // NtFreeVirtualMemory
    { 0x0050, 0x0050,  5,  5, true  }, // NtProtectVirtualMemory
    { 0x0020, 0x0020,  3,  3, true  }, // NtQueryVirtualMemory
    { 0x003A, 0x003A,  5,  5, true  }, // NtReadVirtualMemory
    { 0x003B, 0x003B,  5,  5, true  }, // NtWriteVirtualMemory
    { 0x0028, 0x0028,  6,  6, true  }, // NtMapViewOfSection
    { 0x002A, 0x002A,  2,  2, true  }, // NtUnmapViewOfSection

    // Registry operations
    { 0x001A, 0x001A,  7,  7, true  }, // NtCreateKey
    { 0x0012, 0x0012,  3,  3, true  }, // NtOpenKey
    { 0x0017, 0x0017,  6,  6, true  }, // NtQueryValueKey
    { 0x0060, 0x0060,  4,  4, true  }, // NtSetValueKey
    { 0x003D, 0x003D,  1,  1, false }, // NtDeleteKey
    { 0x0041, 0x0041,  2,  2, true  }, // NtDeleteValueKey
    { 0x0013, 0x0013,  8,  8, true  }, // NtEnumerateKey
    { 0x0014, 0x0014,  6,  6, true  }, // NtEnumerateValueKey

    // Synchronization
    { 0x0001, 0x0001,  5,  5, true  }, // NtWaitForSingleObject
    { 0x000B, 0x000B,  6,  6, true  }, // NtWaitForMultipleObjects
    { 0x0048, 0x0048,  4,  4, true  }, // NtCreateEvent
    { 0x0030, 0x0030,  2,  2, false }, // NtSetEvent
    { 0x0032, 0x0032,  2,  2, false }, // NtResetEvent
    { 0x004C, 0x004C,  5,  5, true  }, // NtCreateMutant
    { 0x0031, 0x0031,  2,  2, true  }, // NtReleaseMutant
    { 0x0049, 0x0049,  5,  5, true  }, // NtCreateSemaphore

    // Token/Security
    { 0x0024, 0x0024,  6,  6, true  }, // NtOpenProcessToken
    { 0x0021, 0x0021,  3,  3, true  }, // NtOpenThreadToken
    { 0x0016, 0x0016,  8,  8, true  }, // NtQueryInformationToken
    { 0x003E, 0x003E, 13, 13, true  }, // NtCreateToken
    { 0x0066, 0x0066,  4,  4, true  }, // NtAdjustPrivilegesToken

    // System information
    { 0x0036, 0x0036,  4,  4, true  }, // NtQuerySystemInformation
    { 0x0019, 0x0019,  2,  2, true  }, // NtQueryPerformanceCounter
    { 0x001B, 0x001B,  2,  2, true  }, // NtQuerySystemTime

    // Object management
    { 0x0010, 0x0010,  2,  2, true  }, // NtDuplicateObject (partial — 7 params)
    { 0x000D, 0x000D,  5,  5, true  }, // NtQueryObject
    { 0x0058, 0x0058,  4,  4, true  }, // NtSetSecurityObject

    // Miscellaneous
    { 0x001F, 0x001F,  4,  4, true  }, // NtDeviceIoControlFile (10 params)
    { 0x002E, 0x002E,  2,  2, true  }, // NtDelayExecution
    { 0x00AC, 0x00AC,  3,  3, true  }, // NtQueueApcThread
    { 0x0002, 0x0002,  4,  4, true  }, // NtCallbackReturn
    { 0x002D, 0x002D,  2,  2, false }, // NtContinue
    { 0x0004, 0x0004,  2,  2, true  }, // NtRaiseException

    // Loader-related
    { 0x0037, 0x0037,  3,  3, true  }, // NtQuerySection
    { 0x0068, 0x0068,  3,  3, true  }, // NtQueryAttributesFile
    { 0x006B, 0x006B,  4,  4, true  }, // NtFlushBuffersFile
    { 0x009C, 0x009C, 11, 11, true  }, // NtCreateUserProcess
}};

// ============================================================================
// File System Redirection Exclusions
// ============================================================================
// These subdirectories under System32 are NOT redirected to SysWOW64.

static constexpr std::array<std::wstring_view, 8> kFsRedirectionExclusions = {{
    L"catroot",
    L"catroot2",
    L"drivers\\etc",
    L"logfiles",
    L"spool",
    L"driverstore",
    L"wbem",
    L"windowspowershell",
}};

// ============================================================================
// Registry Redirection Exclusions
// ============================================================================
// These subkeys under HKLM\Software are NOT redirected to WOW6432Node.

static constexpr std::array<std::wstring_view, 6> kRegistryRedirectionExclusions = {{
    L"Classes",
    L"Microsoft\\COM3",
    L"Microsoft\\Cryptography\\Calais\\Current",
    L"Microsoft\\Cryptography\\Calais\\Readers",
    L"Microsoft\\Cryptography\\Services",
    L"Microsoft\\Windows\\CurrentVersion\\Run",
}};

// ============================================================================
// PIMPL Implementation
// ============================================================================

struct WoW64Layer::Impl {
    WoW64ProcessInfo processInfo{};
    std::vector<HeavensGateEvent> gateEvents;
    std::unordered_map<uint32_t, SyscallTranslation> syscallMap;

    bool initialized = false;
    bool fsRedirectionEnabled = true;

    // Counters
    uint32_t transitionCount = 0;
    uint32_t syscallThunkCount = 0;
    uint32_t heavensGateCount = 0;

    // GDT guest address
    GuestAddress gdtBase = WoW64Const::kGDTBase;

    Impl() noexcept {
        try {
            gateEvents.reserve(256);
            syscallMap.reserve(kDefaultSyscalls.size());
        } catch (const std::bad_alloc&) {
        }
    }
};

// ============================================================================
// Case-insensitive wstring prefix match
// ============================================================================

static bool WideStartsWithCI(std::wstring_view str, std::wstring_view prefix) noexcept {
    if (str.size() < prefix.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        wchar_t a = str[i];
        wchar_t b = prefix[i];
        // ASCII-range case fold only — sufficient for Windows paths
        if (a >= L'A' && a <= L'Z') a += 32;
        if (b >= L'A' && b <= L'Z') b += 32;
        if (a != b) return false;
    }
    return true;
}

[[nodiscard]] static std::wstring MakeWideCopy(std::wstring_view value) noexcept {
    try {
        return std::wstring(value);
    } catch (const std::bad_alloc&) {
        return {};
    }
}

static void IncrementSaturating(uint32_t& value) noexcept {
    if (value < (std::numeric_limits<uint32_t>::max)()) {
        ++value;
    }
}

[[nodiscard]] static bool AddGuestAddress(GuestAddress base, GuestAddress offset, GuestAddress& out) noexcept {
    if (offset > (std::numeric_limits<GuestAddress>::max)() - base) {
        return false;
    }
    out = base + offset;
    return true;
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

WoW64Layer::WoW64Layer() noexcept
    : m_impl(nullptr) {
    try {
        m_impl = std::make_unique<Impl>();
    } catch (const std::bad_alloc&) {
        m_impl.reset();
    }
}

WoW64Layer::~WoW64Layer() noexcept = default;

// ============================================================================
// Initialization
// ============================================================================

[[nodiscard]] bool WoW64Layer::Initialize(VirtualMemory& memory,
                                           CPUState& cpu) noexcept {
    if (!m_impl) return false;
    if (m_impl->initialized) return true;

    // Populate process info with canonical addresses
    auto& info = m_impl->processInfo;
    info.teb32 = WoW64Const::kTEB32Address;
    info.peb32 = WoW64Const::kPEB32Address;
    info.teb64 = WoW64Const::kTEB64Address;
    info.peb64 = WoW64Const::kPEB64Address;

    info.wow64DllBase    = WoW64Const::kWow64DllBase;
    info.wow64CpuDllBase = WoW64Const::kWow64CpuDllBase;
    info.wow64WinDllBase = WoW64Const::kWow64WinDllBase;
    info.ntdll32Base     = WoW64Const::kNtdll32Base;
    info.ntdll64Base     = WoW64Const::kNtdll64Base;

    info.wow64TransitionStub = WoW64Const::kTransitionStub;
    info.wow64SystemService  = WoW64Const::kSystemService;

    auto fail = [&memory, &info, this]() noexcept {
        static_cast<void>(memory.Free(info.teb32, WoW64Const::kTEB32_Size));
        static_cast<void>(memory.Free(info.peb32, WoW64Const::kPEB32_Size));
        static_cast<void>(memory.Free(m_impl->gdtBase, WoW64Const::kGDTSize));
        static_cast<void>(memory.Free(info.wow64CpuDllBase, kPageSize));
        static_cast<void>(memory.Free(info.wow64DllBase, kPageSize));
        m_impl->syscallMap.clear();
        return false;
    };

    // Allocate and initialize TEB32 in guest memory
    auto teb32Region = memory.Allocate(
        info.teb32, WoW64Const::kTEB32_Size, MemProt::RW);
    if (!teb32Region.has_value()) return fail();

    // Allocate and initialize PEB32 in guest memory
    auto peb32Region = memory.Allocate(
        info.peb32, WoW64Const::kPEB32_Size, MemProt::RW);
    if (!peb32Region.has_value()) return fail();

    // --- Fill TEB32 with realistic values ---
    // NT_TIB32.ExceptionList = -1 (no SEH handler yet)
    const uint32_t sehSentinel = 0xFFFFFFFF;
    if (memory.WriteU32(info.teb32 + WoW64Const::kTEB32_SEH, sehSentinel) != ErrorCode::Success)
        return fail();

    // StackBase/StackLimit — use typical WoW64 32-bit stack location
    const uint32_t stackBase32  = 0x00B00000;
    const uint32_t stackLimit32 = 0x00A00000;
    if (memory.WriteU32(info.teb32 + WoW64Const::kTEB32_StackBase, stackBase32) != ErrorCode::Success)
        return fail();
    if (memory.WriteU32(info.teb32 + WoW64Const::kTEB32_StackLimit, stackLimit32) != ErrorCode::Success)
        return fail();

    // Self pointer: FS:[0x18] = &TEB32
    const uint32_t teb32Lo = static_cast<uint32_t>(info.teb32);
    if (memory.WriteU32(info.teb32 + WoW64Const::kTEB32_Self, teb32Lo) != ErrorCode::Success)
        return fail();

    // ProcessId / ThreadId (realistic fake values)
    const uint32_t fakePid = 4728;
    const uint32_t fakeTid = 8812;
    if (memory.WriteU32(info.teb32 + WoW64Const::kTEB32_ProcessId, fakePid) != ErrorCode::Success)
        return fail();
    if (memory.WriteU32(info.teb32 + WoW64Const::kTEB32_ThreadId, fakeTid) != ErrorCode::Success)
        return fail();

    // PEB pointer
    const uint32_t peb32Lo = static_cast<uint32_t>(info.peb32);
    if (memory.WriteU32(info.teb32 + WoW64Const::kTEB32_PEB, peb32Lo) != ErrorCode::Success)
        return fail();

    // LastErrorValue = 0
    if (memory.WriteU32(info.teb32 + WoW64Const::kTEB32_LastError, 0) != ErrorCode::Success)
        return fail();

    // --- Fill PEB32 with realistic values ---
    // BeingDebugged = 0 (anti-evasion)
    if (memory.WriteU8(info.peb32 + WoW64Const::kPEB32_BeingDebugged, 0) != ErrorCode::Success)
        return fail();

    // ImageBaseAddress — will be set later in SetupFor32BitPE
    if (memory.WriteU32(info.peb32 + WoW64Const::kPEB32_ImageBase,
                        static_cast<uint32_t>(WinConst::kDefaultImageBase32)) != ErrorCode::Success)
        return fail();

    // ProcessHeap
    const uint32_t heap32 = static_cast<uint32_t>(WinConst::kProcessHeapBase64);
    if (memory.WriteU32(info.peb32 + WoW64Const::kPEB32_ProcessHeap, heap32) != ErrorCode::Success)
        return fail();

    // NumberOfProcessors
    if (memory.WriteU32(info.peb32 + WoW64Const::kPEB32_NumberOfProc, 8) != ErrorCode::Success)
        return fail();

    // OS version: Windows 10.0.19045
    if (memory.WriteU32(info.peb32 + WoW64Const::kPEB32_OSMajorVersion, 10) != ErrorCode::Success)
        return fail();
    if (memory.WriteU32(info.peb32 + WoW64Const::kPEB32_OSMinorVersion, 0) != ErrorCode::Success)
        return fail();
    if (memory.WriteU32(info.peb32 + WoW64Const::kPEB32_OSBuildNumber, 19045) != ErrorCode::Success)
        return fail();

    // Allocate minimal GDT region in guest memory
    auto gdtRegion = memory.Allocate(
        m_impl->gdtBase, WoW64Const::kGDTSize, MemProt::RW);
    if (!gdtRegion.has_value()) return fail();

    // Setup segment descriptors
    if (!SetupSegmentDescriptors(memory, cpu)) return fail();

    // Allocate stub pages for WoW64 DLLs (minimal — just enough for transition detection)
    // wow64cpu.dll stub page containing the transition thunk
    auto cpuStubRegion = memory.Allocate(
        info.wow64CpuDllBase, kPageSize, MemProt::RW);
    if (!cpuStubRegion.has_value()) return fail();

    // Write a recognizable pattern at the transition stub address.
    // Real wow64cpu!X86SwitchTo64BitMode does: jmp far [0x33:target]
    // We write a magic signature so we can identify legitimate transitions.
    // EA XX XX XX XX 33 00 = JMP FAR ptr16:32 (opcode 0xEA, offset, selector 0x33)
    const uint8_t transitionStubCode[] = {
        0xEA,                                       // JMP FAR
        0x00, 0x02, 0xC0, 0x74,                     // offset (kSystemService low 32)
        0x33, 0x00,                                  // selector 0x0033
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,   // INT3 padding
        0xCC, 0xCC,
    };
    if (memory.Write(info.wow64TransitionStub, transitionStubCode,
                     static_cast<uint32_t>(sizeof(transitionStubCode))) != ErrorCode::Success)
        return fail();
    if (!memory.Protect(info.wow64CpuDllBase, kPageSize, MemProt::RX))
        return fail();

    // wow64.dll stub page containing Wow64SystemServiceEx
    auto wow64StubRegion = memory.Allocate(
        info.wow64DllBase, kPageSize, MemProt::RW);
    if (!wow64StubRegion.has_value()) return fail();

    // Write a minimal stub at Wow64SystemServiceEx: INT 0x2E (syscall trap)
    const uint8_t sysServiceCode[] = {
        0xCD, 0x2E,     // INT 0x2E — triggers emulator syscall handling
        0xC3,           // RET
        0xCC, 0xCC,     // INT3 padding
    };
    if (memory.Write(info.wow64SystemService, sysServiceCode,
                     static_cast<uint32_t>(sizeof(sysServiceCode))) != ErrorCode::Success)
        return fail();
    if (!memory.Protect(info.wow64DllBase, kPageSize, MemProt::RX))
        return fail();

    // Load default syscall translation table
    try {
        for (const auto& entry : kDefaultSyscalls) {
            if (m_impl->syscallMap.size() >= WoW64Const::kMaxSyscallEntries) break;
            SyscallTranslation t;
            t.wow64Number       = entry.wow64Num;
            t.nativeNumber      = entry.nativeNum;
            t.paramCount32      = entry.params32;
            t.paramCount64      = entry.params64;
            t.needsPointerThunk = entry.ptrThunk;
            m_impl->syscallMap.insert_or_assign(t.wow64Number, t);
        }
    } catch (const std::bad_alloc&) {
        return fail();
    }

    m_impl->initialized = true;
    return true;
}

[[nodiscard]] bool WoW64Layer::SetupFor32BitPE(VirtualMemory& memory,
                                                CPUState& cpu,
                                                GuestAddress imageBase,
                                                GuestAddress entryPoint) noexcept {
    if (!m_impl || !m_impl->initialized) return false;

    // Validate the image is in the low 4GB (WoW64 address space)
    if (imageBase >= WoW64Const::kWoW64AddressLimit) return false;
    if (entryPoint >= WoW64Const::kWoW64AddressLimit) return false;

    // Update PEB32.ImageBaseAddress
    const auto& info = m_impl->processInfo;
    if (memory.WriteU32(info.peb32 + WoW64Const::kPEB32_ImageBase,
                        static_cast<uint32_t>(imageBase)) != ErrorCode::Success)
        return false;

    // Switch CPU to 32-bit mode for PE execution
    SwitchTo32Bit(cpu);

    // Set entry point
    cpu.SetRIP(entryPoint);

    return true;
}

[[nodiscard]] bool WoW64Layer::IsInitialized() const noexcept {
    return m_impl && m_impl->initialized;
}

// ============================================================================
// Segment Descriptor Management
// ============================================================================

// Encode a segment descriptor into the 8-byte GDT entry format.
// We write directly to guest memory at the GDT.
static void EncodeGDTEntry(uint8_t out[8],
                           uint32_t base,
                           uint32_t limit,
                           uint8_t type,
                           uint8_t dpl,
                           bool is32bit,
                           bool is64bit,
                           bool present,
                           bool granularity) noexcept {
    // Limit: low 16 bits in [0:1], high 4 bits in [6] bits 0-3
    uint32_t limitField = granularity ? (limit >> 12) : limit;
    out[0] = static_cast<uint8_t>(limitField & 0xFF);
    out[1] = static_cast<uint8_t>((limitField >> 8) & 0xFF);

    // Base: [2-4] = low 24 bits, [7] = high 8 bits
    out[2] = static_cast<uint8_t>(base & 0xFF);
    out[3] = static_cast<uint8_t>((base >> 8) & 0xFF);
    out[4] = static_cast<uint8_t>((base >> 16) & 0xFF);

    // Access byte [5]: P(1) DPL(2) S(1) Type(4)
    uint8_t access = type & 0x0F;
    access |= (1 << 4);                       // S=1 (code/data segment)
    access |= ((dpl & 0x03) << 5);            // DPL
    if (present) access |= (1 << 7);          // P=1
    out[5] = access;

    // Flags + limit high nibble [6]: G(1) D/B(1) L(1) AVL(1) LimitHi(4)
    uint8_t flags = static_cast<uint8_t>((limitField >> 16) & 0x0F);
    if (granularity) flags |= (1 << 7);       // G=1 (4KB granularity)
    if (is32bit)     flags |= (1 << 6);       // D/B=1 (32-bit)
    if (is64bit)     flags |= (1 << 5);       // L=1 (64-bit code)
    out[6] = flags;

    // Base high byte [7]
    out[7] = static_cast<uint8_t>((base >> 24) & 0xFF);
}

[[nodiscard]] bool WoW64Layer::SetupSegmentDescriptors(VirtualMemory& memory,
                                                        CPUState& cpu) noexcept {
    if (!m_impl) return false;

    const auto& info = m_impl->processInfo;
    const GuestAddress gdtBase = m_impl->gdtBase;

    // Zero the entire GDT first
    std::array<uint8_t, 8> nullEntry{};
    // Entry 0: null descriptor (required by x86)
    if (memory.Write(gdtBase, nullEntry.data(), 8) != ErrorCode::Success)
        return false;

    uint8_t entry[8] = {};

    // --- CS32: selector 0x23 = index 4, TI=0, RPL=3 ---
    // 32-bit code segment, execute/read, DPL=3, limit=4GB
    EncodeGDTEntry(entry, 0, 0xFFFFFFFF, 0x0B, 3, true, false, true, true);
    GuestAddress cs32Offset = gdtBase + (WoW64Const::kCS32Selector >> 3) * 8;
    if (memory.Write(cs32Offset, entry, 8) != ErrorCode::Success)
        return false;

    // --- SS/DS: selector 0x2B = index 5, TI=0, RPL=3 ---
    // 32-bit data segment, read/write, DPL=3, limit=4GB
    EncodeGDTEntry(entry, 0, 0xFFFFFFFF, 0x03, 3, true, false, true, true);
    GuestAddress ssOffset = gdtBase + (WoW64Const::kSS32Selector >> 3) * 8;
    if (memory.Write(ssOffset, entry, 8) != ErrorCode::Success)
        return false;

    // --- CS64: selector 0x33 = index 6, TI=0, RPL=3 ---
    // 64-bit code segment, execute/read, DPL=3, L=1, D=0
    EncodeGDTEntry(entry, 0, 0xFFFFFFFF, 0x0B, 3, false, true, true, true);
    GuestAddress cs64Offset = gdtBase + (WoW64Const::kCS64Selector >> 3) * 8;
    if (memory.Write(cs64Offset, entry, 8) != ErrorCode::Success)
        return false;

    // --- FS: selector 0x53 = index 10, TI=0, RPL=3 ---
    // FS base = TEB32 address (for 32-bit code: FS:[0x18] = self, FS:[0x30] = PEB)
    uint32_t fsBase = static_cast<uint32_t>(info.teb32);
    EncodeGDTEntry(entry, fsBase, 0xFFF, 0x03, 3, true, false, true, false);
    GuestAddress fsOffset = gdtBase + (WoW64Const::kFS32Selector >> 3) * 8;
    if (memory.Write(fsOffset, entry, 8) != ErrorCode::Success)
        return false;

    // --- Apply to CPUState ---

    // CS32
    cpu.SetSegmentSelector(SegReg::CS, WoW64Const::kCS32Selector);
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].base    = 0;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].limit   = 0xFFFFFFFF;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].is32bit = true;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].is64bit = false;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].dpl     = 3;

    // SS
    cpu.SetSegmentSelector(SegReg::SS, WoW64Const::kSS32Selector);
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].base    = 0;
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].limit   = 0xFFFFFFFF;
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].is32bit = true;
    cpu.segments[static_cast<uint8_t>(SegReg::SS)].is64bit = false;

    // DS
    cpu.SetSegmentSelector(SegReg::DS, WoW64Const::kDS32Selector);
    cpu.segments[static_cast<uint8_t>(SegReg::DS)].base    = 0;
    cpu.segments[static_cast<uint8_t>(SegReg::DS)].limit   = 0xFFFFFFFF;

    // ES (same as DS)
    cpu.SetSegmentSelector(SegReg::ES, WoW64Const::kDS32Selector);
    cpu.segments[static_cast<uint8_t>(SegReg::ES)].base    = 0;
    cpu.segments[static_cast<uint8_t>(SegReg::ES)].limit   = 0xFFFFFFFF;

    // FS — 32-bit TEB
    cpu.SetSegmentSelector(SegReg::FS, WoW64Const::kFS32Selector);
    cpu.SetSegmentBase(SegReg::FS, info.teb32);
    cpu.segments[static_cast<uint8_t>(SegReg::FS)].limit   = WoW64Const::kTEB32_Size - 1;
    cpu.segments[static_cast<uint8_t>(SegReg::FS)].is32bit = true;

    // GS — 64-bit TEB (used after transition to 64-bit mode)
    cpu.SetSegmentSelector(SegReg::GS, WoW64Const::kGS64Selector);
    cpu.SetSegmentBase(SegReg::GS, info.teb64);

    return true;
}

[[nodiscard]] uint16_t WoW64Layer::GetCS32Selector() const noexcept {
    return WoW64Const::kCS32Selector;
}

[[nodiscard]] uint16_t WoW64Layer::GetCS64Selector() const noexcept {
    return WoW64Const::kCS64Selector;
}

// ============================================================================
// CPU Mode Switching
// ============================================================================

void WoW64Layer::SwitchTo32Bit(CPUState& cpu) noexcept {
    if (!m_impl) return;

    cpu.mode = CPUMode::Protected32;

    // Update CS to 32-bit selector
    cpu.SetSegmentSelector(SegReg::CS, WoW64Const::kCS32Selector);
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].base    = 0;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].limit   = 0xFFFFFFFF;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].is32bit = true;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].is64bit = false;

    // FS base points to TEB32
    cpu.SetSegmentBase(SegReg::FS, m_impl->processInfo.teb32);

    // Truncate RSP to 32-bit ESP (WoW64 uses 32-bit stack in 32-bit mode)
    uint64_t rsp = cpu.RSP();
    cpu.SetReg32(GPR::RSP, static_cast<uint32_t>(rsp));

    IncrementSaturating(m_impl->transitionCount);
}

void WoW64Layer::SwitchTo64Bit(CPUState& cpu) noexcept {
    if (!m_impl) return;

    cpu.mode = CPUMode::Long64;

    // Update CS to 64-bit selector
    cpu.SetSegmentSelector(SegReg::CS, WoW64Const::kCS64Selector);
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].base    = 0;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].limit   = 0xFFFFFFFF;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].is32bit = false;
    cpu.segments[static_cast<uint8_t>(SegReg::CS)].is64bit = true;

    // GS base points to TEB64
    cpu.SetSegmentBase(SegReg::GS, m_impl->processInfo.teb64);

    IncrementSaturating(m_impl->transitionCount);
}

// ============================================================================
// Heaven's Gate Detection
// ============================================================================

[[nodiscard]] bool WoW64Layer::DetectHeavensGate(
    const CPUState& cpu,
    uint16_t targetSelector,
    GuestAddress targetOffset,
    WoW64Transition& outTransition) noexcept {

    outTransition = WoW64Transition::None;
    if (!m_impl || !m_impl->initialized) return false;

    const bool currentIs32 = cpu.Is32Bit();
    const bool currentIs64 = cpu.Is64Bit();

    // 32-bit code performing far call/jmp to 64-bit selector
    if (currentIs32 && targetSelector == WoW64Const::kCS64Selector) {
        // Check if this goes through the legitimate transition stub
        const auto& info = m_impl->processInfo;
        if (targetOffset == info.wow64TransitionStub ||
            targetOffset == info.wow64SystemService) {
            outTransition = WoW64Transition::Wow64SystemService;
        } else {
            outTransition = WoW64Transition::HeavensGate32to64;
        }
        return true;
    }

    // 64-bit code performing far call/jmp to 32-bit selector
    if (currentIs64 && targetSelector == WoW64Const::kCS32Selector) {
        outTransition = WoW64Transition::HeavensGate64to32;
        return true;
    }

    return false;
}

void WoW64Layer::ProcessTransition(CPUState& cpu,
                                    WoW64Transition transition,
                                    GuestAddress targetRIP) noexcept {
    if (!m_impl) return;

    // Record the event (bounded)
    if (m_impl->gateEvents.size() < WoW64Const::kMaxGateEvents) {
        HeavensGateEvent event{};
        event.sourceRIP = cpu.GetRIP();
        event.targetRIP = targetRIP;
        event.direction = transition;
        event.instructionCount = cpu.instructionCount;

        // Flag evasion: any transition not through the official wow64cpu stub
        event.isEvasionAttempt =
            (transition == WoW64Transition::HeavensGate32to64 ||
             transition == WoW64Transition::HeavensGate64to32);

        try {
            m_impl->gateEvents.push_back(event);
        } catch (const std::bad_alloc&) {
        }
    }

    // Perform the actual mode switch
    switch (transition) {
        case WoW64Transition::Wow64SystemService:
        case WoW64Transition::HeavensGate32to64:
        case WoW64Transition::TurboThunk:
            SwitchTo64Bit(cpu);
            cpu.SetRIP(targetRIP);
            IncrementSaturating(m_impl->heavensGateCount);
            break;

        case WoW64Transition::HeavensGate64to32:
            SwitchTo32Bit(cpu);
            cpu.SetRIP(targetRIP);
            IncrementSaturating(m_impl->heavensGateCount);
            break;

        case WoW64Transition::None:
            break;
    }
}

[[nodiscard]] const std::vector<HeavensGateEvent>&
WoW64Layer::GetHeavensGateEvents() const noexcept {
    static const std::vector<HeavensGateEvent> empty;
    if (!m_impl) return empty;
    return m_impl->gateEvents;
}

// ============================================================================
// Syscall Thunking (32-bit → 64-bit)
// ============================================================================

[[nodiscard]] bool WoW64Layer::ThunkSyscall(CPUState& cpu,
                                             VirtualMemory& memory) noexcept {
    if (!m_impl || !m_impl->initialized) return false;

    // In 32-bit WoW64 mode, the syscall number is in EAX
    const uint32_t syscallNum = cpu.GetReg32(GPR::RAX);

    // Look up the translation
    auto it = m_impl->syscallMap.find(syscallNum);
    if (it == m_impl->syscallMap.end()) {
        // Unknown syscall — pass the number through unchanged.
        // The emulator's syscall handler will deal with it.
        IncrementSaturating(m_impl->syscallThunkCount);
        return true;
    }

    const SyscallTranslation& trans = it->second;

    // Read 32-bit parameters from the stack.
    // In the 32-bit cdecl/stdcall convention:
    //   [ESP+0]  = return address
    //   [ESP+4]  = param 1
    //   [ESP+8]  = param 2
    //   ...
    const uint32_t esp = cpu.GetReg32(GPR::RSP);
    const uint8_t paramCount = std::min<uint8_t>(trans.paramCount32, 16);

    std::array<uint64_t, 16> params{};
    for (uint8_t i = 0; i < paramCount; ++i) {
        uint32_t val32 = 0;
        GuestAddress paramAddr = 0;
        if (!AddGuestAddress(static_cast<GuestAddress>(esp),
                             WoW64Const::kStackParamBase32 +
                                 (static_cast<GuestAddress>(i) * 4),
                             paramAddr)) {
            return false;
        }

        // Validate the parameter address is in WoW64 range
        if (paramAddr >= WoW64Const::kWoW64AddressLimit) return false;

        if (memory.ReadU32(paramAddr, val32) != ErrorCode::Success)
            return false;

        // If this syscall has pointer parameters, zero-extend to 64-bit.
        // All 32-bit values are zero-extended regardless; the pointer flag
        // is informational for the syscall handler.
        params[i] = static_cast<uint64_t>(val32);
    }

    // Translate to 64-bit calling convention (Windows x64 ABI):
    //   RCX = param 1, RDX = param 2, R8 = param 3, R9 = param 4
    //   [RSP+0x28] = param 5, [RSP+0x30] = param 6, ...
    // Remaining params go to the 64-bit stack shadow space.
    // We need to set up the 64-bit stack frame:
    //   RSP must have 32 bytes of shadow space + any additional params.
    if (paramCount > 4) {
        // Calculate stack space needed: shadow(32) + overflow params
        const uint32_t overflowCount = paramCount - 4;
        const uint64_t rsp64 = cpu.RSP();
        // Stack grows down — allocate shadow + overflow
        const uint64_t frameSize = 0x20 + (static_cast<uint64_t>(overflowCount) * 8);
        const uint64_t newRsp = rsp64 - frameSize;

        // Validate the new RSP won't wrap or go out of bounds
        if (newRsp > rsp64) return false; // underflow check

        // Write overflow parameters to the stack
        for (uint32_t i = 0; i < overflowCount; ++i) {
            GuestAddress slotAddr = 0;
            if (!AddGuestAddress(newRsp,
                                 0x20 + (static_cast<GuestAddress>(i) * 8),
                                 slotAddr)) {
                return false;
            }
            if (memory.WriteU64(slotAddr, params[4 + i]) != ErrorCode::Success)
                return false;
        }

        cpu.SetReg64(GPR::RSP, newRsp);
    }

    // Commit register state only after all memory writes have succeeded.
    cpu.SetReg64(GPR::RAX, static_cast<uint64_t>(trans.nativeNumber));
    if (paramCount >= 1) cpu.SetReg64(GPR::RCX, params[0]);
    if (paramCount >= 2) cpu.SetReg64(GPR::RDX, params[1]);
    if (paramCount >= 3) cpu.SetReg64(GPR::R8,  params[2]);
    if (paramCount >= 4) cpu.SetReg64(GPR::R9,  params[3]);

    IncrementSaturating(m_impl->syscallThunkCount);
    return true;
}

void WoW64Layer::RegisterSyscallTranslation(const SyscallTranslation& entry) noexcept {
    if (!m_impl) return;
    if (m_impl->syscallMap.size() >= WoW64Const::kMaxSyscallEntries) return;
    if (entry.paramCount32 > 16 || entry.paramCount64 > 16) return;
    try {
        m_impl->syscallMap.insert_or_assign(entry.wow64Number, entry);
    } catch (const std::bad_alloc&) {
    }
}

// ============================================================================
// Address Translation
// ============================================================================

[[nodiscard]] GuestAddress WoW64Layer::Widen32To64(uint32_t addr32) const noexcept {
    // Zero-extend 32-bit address to 64-bit.
    // In WoW64, all 32-bit addresses are in the low 4GB — zero extension is correct.
    return static_cast<GuestAddress>(addr32);
}

[[nodiscard]] uint32_t WoW64Layer::Narrow64To32(GuestAddress addr64) const noexcept {
    // If the address is above 4GB, it cannot be represented in 32-bit.
    if (addr64 >= WoW64Const::kWoW64AddressLimit) return 0;
    return static_cast<uint32_t>(addr64);
}

[[nodiscard]] bool WoW64Layer::IsWoW64Address(GuestAddress addr) const noexcept {
    return addr < WoW64Const::kWoW64AddressLimit;
}

// ============================================================================
// TEB/PEB Access
// ============================================================================

[[nodiscard]] const WoW64ProcessInfo& WoW64Layer::GetProcessInfo() const noexcept {
    // Static fallback for null impl (should never happen in practice)
    static const WoW64ProcessInfo empty{};
    if (!m_impl) return empty;
    return m_impl->processInfo;
}

[[nodiscard]] GuestAddress WoW64Layer::GetTEB32() const noexcept {
    if (!m_impl) return 0;
    return m_impl->processInfo.teb32;
}

[[nodiscard]] GuestAddress WoW64Layer::GetTEB64() const noexcept {
    if (!m_impl) return 0;
    return m_impl->processInfo.teb64;
}

// ============================================================================
// File System Redirection
// ============================================================================

[[nodiscard]] std::wstring WoW64Layer::RedirectPath(std::wstring_view path) const noexcept {
    if (!m_impl) return MakeWideCopy(path);
    if (!m_impl->fsRedirectionEnabled) return MakeWideCopy(path);

    // WoW64 redirects C:\Windows\System32\ → C:\Windows\SysWOW64\
    // Case-insensitive match
    static constexpr std::wstring_view kSystem32Prefix = L"C:\\Windows\\System32\\";
    static constexpr std::wstring_view kSystem32PrefixAlt = L"C:\\Windows\\system32\\";

    if (!WideStartsWithCI(path, kSystem32Prefix)) {
        return MakeWideCopy(path);
    }

    // Extract the relative path after System32
    std::wstring_view relativePath = path.substr(kSystem32Prefix.size());

    // Check exclusions: certain subdirectories are NOT redirected
    for (const auto& exclusion : kFsRedirectionExclusions) {
        if (WideStartsWithCI(relativePath, exclusion)) {
            // Check that it's a directory boundary (next char is \ or end)
            if (relativePath.size() == exclusion.size() ||
                relativePath[exclusion.size()] == L'\\') {
                return MakeWideCopy(path);
            }
        }
    }

    // Perform the redirect
    try {
        std::wstring result;
        result.reserve(path.size() + 4); // SysWOW64 is slightly longer
        result = L"C:\\Windows\\SysWOW64\\";
        result.append(relativePath);
        return result;
    } catch (const std::bad_alloc&) {
        return {};
    }
}

[[nodiscard]] bool WoW64Layer::IsFsRedirectionDisabled() const noexcept {
    if (!m_impl) return false;
    return !m_impl->fsRedirectionEnabled;
}

void WoW64Layer::SetFsRedirection(bool enabled) noexcept {
    if (!m_impl) return;
    m_impl->fsRedirectionEnabled = enabled;
}

// ============================================================================
// Registry Redirection
// ============================================================================

[[nodiscard]] std::wstring WoW64Layer::RedirectRegistryKey(
    std::wstring_view keyPath) const noexcept {
    if (!m_impl) return MakeWideCopy(keyPath);

    // WoW64 redirects HKLM\Software\* → HKLM\Software\WOW6432Node\*
    // With specific exclusions.
    static constexpr std::wstring_view kSoftwarePrefix = L"HKLM\\Software\\";
    static constexpr std::wstring_view kSoftwarePrefixAlt = L"HKLM\\SOFTWARE\\";

    if (!WideStartsWithCI(keyPath, kSoftwarePrefix)) {
        return MakeWideCopy(keyPath);
    }

    // Extract the relative path after "HKLM\Software\"
    std::wstring_view relativePath = keyPath.substr(kSoftwarePrefix.size());

    // Already redirected? Don't double-redirect.
    static constexpr std::wstring_view kWow6432Node = L"WOW6432Node\\";
    if (WideStartsWithCI(relativePath, kWow6432Node)) {
        return MakeWideCopy(keyPath);
    }

    // Check exclusions
    for (const auto& exclusion : kRegistryRedirectionExclusions) {
        if (WideStartsWithCI(relativePath, exclusion)) {
            if (relativePath.size() == exclusion.size() ||
                relativePath[exclusion.size()] == L'\\') {
                return MakeWideCopy(keyPath);
            }
        }
    }

    // Perform the redirect: HKLM\Software\X → HKLM\Software\WOW6432Node\X
    try {
        std::wstring result;
        result.reserve(keyPath.size() + kWow6432Node.size());
        result = kSoftwarePrefix;
        result += kWow6432Node;
        result.append(relativePath);
        return result;
    } catch (const std::bad_alloc&) {
        return {};
    }
}

// ============================================================================
// Statistics
// ============================================================================

[[nodiscard]] uint32_t WoW64Layer::GetTransitionCount() const noexcept {
    if (!m_impl) return 0;
    return m_impl->transitionCount;
}

[[nodiscard]] uint32_t WoW64Layer::GetSyscallThunkCount() const noexcept {
    if (!m_impl) return 0;
    return m_impl->syscallThunkCount;
}

[[nodiscard]] uint32_t WoW64Layer::GetHeavensGateCount() const noexcept {
    if (!m_impl) return 0;
    return m_impl->heavensGateCount;
}

} // namespace Phantom
