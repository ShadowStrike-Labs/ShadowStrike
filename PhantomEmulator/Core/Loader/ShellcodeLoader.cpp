/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ShellcodeLoader.cpp — Raw shellcode loader implementation
 *
 * Allocates RWX memory for the code, sets up stack/heap, and builds minimal
 * PEB/TEB structures. Real-world shellcode (Cobalt Strike, Metasploit, custom
 * loaders) walks TEB→PEB→Ldr to find kernel32.dll, so the PEB/TEB must be
 * structurally valid even for "raw" shellcode analysis.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "ShellcodeLoader.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

namespace Phantom {

// ============================================================================
// Anonymous helpers
// ============================================================================

namespace {

// Maximum shellcode size (anti-DoS: 16 MB is generous for any real shellcode)
constexpr GuestSize kMaxShellcodeSize = 16ULL * 1024 * 1024;

// Preferred shellcode base addresses (realistic for heap/VirtualAlloc results)
constexpr GuestAddress kShellcodeBase64 = 0x0000000000010000ULL;
constexpr GuestAddress kShellcodeBase32 = 0x00010000;

// Stack base for shellcode (separate from PE loader defaults)
constexpr GuestAddress kScStackBase64 = 0x0000000080000000ULL;
constexpr GuestAddress kScStackBase32 = 0x00F00000;

// Heap base for shellcode
constexpr GuestAddress kScHeapBase64 = 0x0000000000100000ULL;
constexpr GuestAddress kScHeapBase32 = 0x00200000;

// Sentinel return address (triggers clean stop when shellcode returns)
constexpr uint64_t kSentinelReturn64 = 0xDEAD'DEAD'DEAD'DEADULL;
constexpr uint32_t kSentinelReturn32 = 0xDEAD'DEAD;

// LDR_DATA offset within PEB page
constexpr uint32_t kLdrDataOffset = 0x400;

// Write a scalar value at a specific offset from a base guest address
[[nodiscard]] bool AddGuestAddress(GuestAddress base, GuestAddress offset, GuestAddress& out) noexcept {
    if (offset > (std::numeric_limits<GuestAddress>::max)() - base) {
        return false;
    }
    out = base + offset;
    return true;
}

[[nodiscard]] bool AlignUpChecked(GuestSize value, GuestSize alignment, GuestSize& out) noexcept {
    if (alignment == 0 || value > (std::numeric_limits<GuestSize>::max)() - (alignment - 1)) {
        return false;
    }
    out = AlignUp(value, alignment);
    return out >= value;
}

[[nodiscard]] bool ToU32Address(GuestAddress value, uint32_t& out) noexcept {
    if (value > (std::numeric_limits<uint32_t>::max)()) {
        return false;
    }
    out = static_cast<uint32_t>(value);
    return true;
}

template <typename T>
ErrorCode WriteAt(VirtualMemory& mem, GuestAddress base, uint32_t offset, T value) noexcept {
    GuestAddress target = 0;
    if (!AddGuestAddress(base, offset, target)) {
        return ErrorCode::InvalidAddress;
    }
    return mem.Write(target, &value, sizeof(T));
}

} // anonymous namespace

// ============================================================================
// Constructor
// ============================================================================

ShellcodeLoader::ShellcodeLoader(VirtualMemory& memory) noexcept
    : m_memory(memory)
{}

// ============================================================================
// Load — Allocate memory, copy shellcode, set up execution environment
// ============================================================================

ShellcodeLoader::LoadResult ShellcodeLoader::Load(
    ByteSpan shellcodeData,
    const EmulationConfig& config) noexcept
{
    LoadResult result{};

    // ---- 1. Validate shellcode size ----------------------------------------
    if (shellcodeData.empty()) {
        result.error = ErrorCode::InvalidAddress;
        return result;
    }
    if (shellcodeData.size() > kMaxShellcodeSize) {
        result.error = ErrorCode::PETooLarge;
        return result;
    }

    const bool is64 = (config.target == EmulationTarget::Shellcode64);
    result.shellcode.is64Bit = is64;

    GuestSize codeAllocSize = 0;
    if (!AlignUpChecked(static_cast<GuestSize>(shellcodeData.size()), kPageSize, codeAllocSize)) {
        result.error = ErrorCode::PETooLarge;
        return result;
    }

    // ---- 2. Allocate RWX region for shellcode ------------------------------
    // Shellcode needs RWX because real shellcode is self-modifying and
    // typically lands in heap or VirtualAlloc'd memory with full permissions.
    const GuestAddress preferredBase = is64 ? kShellcodeBase64 : kShellcodeBase32;

    auto codeOpt = m_memory.Allocate(preferredBase, codeAllocSize, MemProt::RWX);
    if (!codeOpt) {
        codeOpt = m_memory.Allocate(0, codeAllocSize, MemProt::RWX);
        if (!codeOpt) {
            result.error = ErrorCode::OutOfMemory;
            return result;
        }
    }

    result.shellcode.codeBase   = *codeOpt;
    result.shellcode.entryPoint = *codeOpt; // Entry = start of shellcode
    result.shellcode.codeSize   = static_cast<GuestSize>(shellcodeData.size());

    // ---- 3. Copy shellcode bytes into allocated region ----------------------
    auto mapErr = m_memory.Write(
        result.shellcode.codeBase,
        shellcodeData.data(),
        static_cast<uint32_t>(shellcodeData.size()));

    if (mapErr != ErrorCode::Success) {
        result.error = mapErr;
        return result;
    }

    // ---- 4. Allocate stack -------------------------------------------------
    GuestSize stackSize = 0;
    if (!AlignUpChecked(config.stackSize > 0 ? config.stackSize : kStackSize, kPageSize, stackSize)) {
        result.error = ErrorCode::OutOfMemory;
        return result;
    }

    const GuestAddress stackPreferred = is64 ? kScStackBase64 : kScStackBase32;

    auto stackOpt = m_memory.Allocate(stackPreferred, stackSize, MemProt::RW);
    if (!stackOpt) {
        stackOpt = m_memory.Allocate(0, stackSize, MemProt::RW);
        if (!stackOpt) {
            result.error = ErrorCode::OutOfMemory;
            return result;
        }
    }

    result.shellcode.stackBase = *stackOpt;
    if (!AddGuestAddress(*stackOpt, stackSize, result.shellcode.stackTop)) {
        result.error = ErrorCode::InvalidAddress;
        return result;
    }

    // Guard page at the bottom for stack overflow detection
    if (!m_memory.Protect(result.shellcode.stackBase, kPageSize,
                          MemProt::RW | MemProt::Guard)) {
        result.error = ErrorCode::InvalidAddress;
        return result;
    }

    // ---- 5. Allocate heap --------------------------------------------------
    GuestSize heapSize = 0;
    if (!AlignUpChecked(config.heapSize > 0 ? config.heapSize : kHeapInitial, kPageSize, heapSize)) {
        result.error = ErrorCode::OutOfMemory;
        return result;
    }

    const GuestAddress heapPreferred = is64 ? kScHeapBase64 : kScHeapBase32;

    auto heapOpt = m_memory.Allocate(heapPreferred, heapSize, MemProt::RW);
    if (!heapOpt) {
        heapOpt = m_memory.Allocate(0, heapSize, MemProt::RW);
        if (!heapOpt) {
            result.error = ErrorCode::OutOfMemory;
            return result;
        }
    }

    result.shellcode.heapBase = *heapOpt;

    // ---- 6. Create minimal PEB ---------------------------------------------
    {
        auto err = CreateMinimalPEB(result.shellcode, config);
        if (err != ErrorCode::Success) {
            result.error = err;
            return result;
        }
    }

    // ---- 7. Create minimal TEB ---------------------------------------------
    {
        auto err = CreateMinimalTEB(result.shellcode, config);
        if (err != ErrorCode::Success) {
            result.error = err;
            return result;
        }
    }

    return result;
}

// ============================================================================
// PrepareCPUState — Set up CPU registers for shellcode execution
// ============================================================================

void ShellcodeLoader::PrepareCPUState(
    CPU& cpu,
    const LoadedShellcode& sc,
    const EmulationConfig& config) noexcept
{
    static_cast<void>(config);
    auto& state = cpu.State();

    if (sc.is64Bit) {
        // ---- 64-bit shellcode setup ----
        cpu.Reset64();
        state.SetRIP(sc.entryPoint);

        // RSP: simulate post-CALL state (RSP % 16 == 8)
        GuestAddress rsp = AlignDown(sc.stackTop, 16) - 8;

        // Write sentinel return address at [RSP]
        if (m_memory.WriteU64(rsp, kSentinelReturn64) != ErrorCode::Success) {
            return;
        }
        state.SetReg64(GPR::RSP, rsp);

        // Zero all GP registers except RSP
        state.SetReg64(GPR::RAX, 0);
        state.SetReg64(GPR::RCX, 0);
        state.SetReg64(GPR::RDX, 0);
        state.SetReg64(GPR::RBX, 0);
        state.SetReg64(GPR::RBP, 0);
        state.SetReg64(GPR::RSI, 0);
        state.SetReg64(GPR::RDI, 0);
        state.SetReg64(GPR::R8,  0);
        state.SetReg64(GPR::R9,  0);
        state.SetReg64(GPR::R10, 0);
        state.SetReg64(GPR::R11, 0);
        state.SetReg64(GPR::R12, 0);
        state.SetReg64(GPR::R13, 0);
        state.SetReg64(GPR::R14, 0);
        state.SetReg64(GPR::R15, 0);

        // GS segment base → TEB (for GS:[0x30] → TEB.Self access)
        state.SetSegmentBase(SegReg::GS, sc.tebAddress);

        // CS for 64-bit long mode
        state.SetSegmentSelector(SegReg::CS, 0x33);
        state.segments[static_cast<uint8_t>(SegReg::CS)].is64bit = true;
        state.segments[static_cast<uint8_t>(SegReg::CS)].is32bit = false;

    } else {
        // ---- 32-bit shellcode setup ----
        cpu.Reset32();
        state.SetRIP(sc.entryPoint);

        GuestAddress esp = AlignDown(sc.stackTop, 4) - 4;

        // Write sentinel return address
        if (m_memory.WriteU32(esp, kSentinelReturn32) != ErrorCode::Success) {
            return;
        }
        uint32_t esp32 = 0;
        if (!ToU32Address(esp, esp32)) {
            return;
        }
        state.SetReg32(GPR::RSP, esp32);

        // Zero all GP registers except ESP
        state.SetReg32(GPR::RAX, 0);
        state.SetReg32(GPR::RCX, 0);
        state.SetReg32(GPR::RDX, 0);
        state.SetReg32(GPR::RBX, 0);
        state.SetReg32(GPR::RBP, 0);
        state.SetReg32(GPR::RSI, 0);
        state.SetReg32(GPR::RDI, 0);

        // FS segment base → TEB (for FS:[0x18] → TEB.Self access)
        state.SetSegmentBase(SegReg::FS, sc.tebAddress);

        // CS for 32-bit protected mode
        state.SetSegmentSelector(SegReg::CS, 0x23);
        state.segments[static_cast<uint8_t>(SegReg::CS)].is64bit = false;
        state.segments[static_cast<uint8_t>(SegReg::CS)].is32bit = true;
    }
}

// ============================================================================
// CreateMinimalPEB — Minimal PEB for shellcode analysis
//
// Shellcode typically accesses the PEB through:
//   mov rax, gs:[0x60]   ; x64: TEB→PEB at TEB+0x60
//   mov eax, fs:[0x30]   ; x86: TEB→PEB at TEB+0x30
//
// Then walks PEB.Ldr→InLoadOrderModuleList to find kernel32.dll base.
// We provide empty module lists here; the ExportResolver populates them
// when API hooks are registered.
// ============================================================================

ErrorCode ShellcodeLoader::CreateMinimalPEB(
    LoadedShellcode& sc,
    const EmulationConfig& config) noexcept
{
    const GuestAddress pebAddr = WinConst::kPEBAddress64;

    auto pebOpt = m_memory.Allocate(pebAddr, kPageSize, MemProt::RW);
    if (!pebOpt) {
        pebOpt = m_memory.Allocate(0, kPageSize, MemProt::RW);
        if (!pebOpt) return ErrorCode::OutOfMemory;
    }
    sc.pebAddress = *pebOpt;

    const GuestAddress peb = sc.pebAddress;
    const GuestAddress ldrAddr = peb + kLdrDataOffset;
    ErrorCode err = ErrorCode::Success;

    if (sc.is64Bit) {
        // ---- x64 PEB ----

        // BeingDebugged = 0
        err = WriteAt(m_memory, peb, 0x002, static_cast<uint8_t>(0));
        if (err != ErrorCode::Success) return err;

        // Mutant = -1
        err = WriteAt(m_memory, peb, 0x008, static_cast<uint64_t>(0xFFFFFFFFFFFFFFFFULL));
        if (err != ErrorCode::Success) return err;

        // ImageBaseAddress = 0 (no main image for shellcode)
        err = WriteAt(m_memory, peb, 0x010, static_cast<uint64_t>(0));
        if (err != ErrorCode::Success) return err;

        // Ldr pointer
        err = WriteAt(m_memory, peb, 0x018, ldrAddr);
        if (err != ErrorCode::Success) return err;

        // ProcessHeap
        err = WriteAt(m_memory, peb, 0x030, sc.heapBase);
        if (err != ErrorCode::Success) return err;

        // NumberOfProcessors
        err = WriteAt(m_memory, peb, 0x0BC, config.processorCount);
        if (err != ErrorCode::Success) return err;

        // OSMajorVersion = 10
        err = WriteAt(m_memory, peb, 0x0E8, static_cast<uint32_t>(10));
        if (err != ErrorCode::Success) return err;

        // OSMinorVersion = 0
        err = WriteAt(m_memory, peb, 0x0EC, static_cast<uint32_t>(0));
        if (err != ErrorCode::Success) return err;

        // OSBuildNumber = 19045
        err = WriteAt(m_memory, peb, 0x0F0, static_cast<uint16_t>(config.osBuildNumber));
        if (err != ErrorCode::Success) return err;

        // OSPlatformId = 2 (VER_PLATFORM_WIN32_NT)
        err = WriteAt(m_memory, peb, 0x0F4, static_cast<uint32_t>(2));
        if (err != ErrorCode::Success) return err;

        // NtGlobalFlag = 0 (anti-debug)
        err = WriteAt(m_memory, peb, 0x118, static_cast<uint32_t>(0));
        if (err != ErrorCode::Success) return err;

        // ---- PEB_LDR_DATA (x64) — empty circular lists ----
        err = WriteAt(m_memory, ldrAddr, 0x000, static_cast<uint32_t>(0x58));
        if (err != ErrorCode::Success) return err;
        err = WriteAt(m_memory, ldrAddr, 0x004, static_cast<uint8_t>(1));
        if (err != ErrorCode::Success) return err;

        // InLoadOrderModuleList → self
        const GuestAddress listHead0 = ldrAddr + 0x010;
        err = WriteAt(m_memory, ldrAddr, 0x010, listHead0);
        if (err != ErrorCode::Success) return err;
        err = WriteAt(m_memory, ldrAddr, 0x018, listHead0);
        if (err != ErrorCode::Success) return err;

        // InMemoryOrderModuleList → self
        const GuestAddress listHead1 = ldrAddr + 0x020;
        err = WriteAt(m_memory, ldrAddr, 0x020, listHead1);
        if (err != ErrorCode::Success) return err;
        err = WriteAt(m_memory, ldrAddr, 0x028, listHead1);
        if (err != ErrorCode::Success) return err;

        // InInitializationOrderModuleList → self
        const GuestAddress listHead2 = ldrAddr + 0x030;
        err = WriteAt(m_memory, ldrAddr, 0x030, listHead2);
        if (err != ErrorCode::Success) return err;
        err = WriteAt(m_memory, ldrAddr, 0x038, listHead2);
        if (err != ErrorCode::Success) return err;

    } else {
        // ---- x86 PEB ----

        // BeingDebugged = 0
        err = WriteAt(m_memory, peb, 0x002, static_cast<uint8_t>(0));
        if (err != ErrorCode::Success) return err;

        // Mutant = -1
        err = WriteAt(m_memory, peb, 0x004, static_cast<uint32_t>(0xFFFFFFFF));
        if (err != ErrorCode::Success) return err;

        // ImageBaseAddress = 0
        err = WriteAt(m_memory, peb, 0x008, static_cast<uint32_t>(0));
        if (err != ErrorCode::Success) return err;

        // Ldr pointer
        uint32_t ldrAddr32 = 0;
        if (!ToU32Address(ldrAddr, ldrAddr32)) return ErrorCode::InvalidAddress;
        err = WriteAt(m_memory, peb, 0x00C, ldrAddr32);
        if (err != ErrorCode::Success) return err;

        // ProcessHeap
        uint32_t heapBase32 = 0;
        if (!ToU32Address(sc.heapBase, heapBase32)) return ErrorCode::InvalidAddress;
        err = WriteAt(m_memory, peb, 0x018, heapBase32);
        if (err != ErrorCode::Success) return err;

        // NumberOfProcessors
        err = WriteAt(m_memory, peb, 0x064, config.processorCount);
        if (err != ErrorCode::Success) return err;

        // NtGlobalFlag = 0
        err = WriteAt(m_memory, peb, 0x068, static_cast<uint32_t>(0));
        if (err != ErrorCode::Success) return err;

        // OSMajorVersion = 10
        err = WriteAt(m_memory, peb, 0x0A4, static_cast<uint32_t>(10));
        if (err != ErrorCode::Success) return err;

        // OSMinorVersion = 0
        err = WriteAt(m_memory, peb, 0x0A8, static_cast<uint32_t>(0));
        if (err != ErrorCode::Success) return err;

        // OSBuildNumber = 19045
        err = WriteAt(m_memory, peb, 0x0AC, static_cast<uint16_t>(config.osBuildNumber));
        if (err != ErrorCode::Success) return err;

        // OSPlatformId = 2
        err = WriteAt(m_memory, peb, 0x0B0, static_cast<uint32_t>(2));
        if (err != ErrorCode::Success) return err;

        // ---- PEB_LDR_DATA (x86) — empty circular lists ----
        err = WriteAt(m_memory, ldrAddr, 0x000, static_cast<uint32_t>(0x30));
        if (err != ErrorCode::Success) return err;
        err = WriteAt(m_memory, ldrAddr, 0x004, static_cast<uint8_t>(1));
        if (err != ErrorCode::Success) return err;

        GuestAddress listAddr = 0;
        uint32_t list0 = 0;
        if (!AddGuestAddress(ldrAddr, 0x00C, listAddr) ||
            !ToU32Address(listAddr, list0)) return ErrorCode::InvalidAddress;
        err = WriteAt(m_memory, ldrAddr, 0x00C, list0);
        if (err != ErrorCode::Success) return err;
        err = WriteAt(m_memory, ldrAddr, 0x010, list0);
        if (err != ErrorCode::Success) return err;

        uint32_t list1 = 0;
        if (!AddGuestAddress(ldrAddr, 0x014, listAddr) ||
            !ToU32Address(listAddr, list1)) return ErrorCode::InvalidAddress;
        err = WriteAt(m_memory, ldrAddr, 0x014, list1);
        if (err != ErrorCode::Success) return err;
        err = WriteAt(m_memory, ldrAddr, 0x018, list1);
        if (err != ErrorCode::Success) return err;

        uint32_t list2 = 0;
        if (!AddGuestAddress(ldrAddr, 0x01C, listAddr) ||
            !ToU32Address(listAddr, list2)) return ErrorCode::InvalidAddress;
        err = WriteAt(m_memory, ldrAddr, 0x01C, list2);
        if (err != ErrorCode::Success) return err;
        err = WriteAt(m_memory, ldrAddr, 0x020, list2);
        if (err != ErrorCode::Success) return err;
    }

    return ErrorCode::Success;
}

// ============================================================================
// CreateMinimalTEB — Minimal Thread Environment Block for shellcode
//
// The TEB Self pointer is the most critical field — shellcode uses:
//   mov rax, gs:[0x30]   ; TEB.Self (x64)
//   mov eax, fs:[0x18]   ; TEB.Self (x86)
// to find the TEB, then reads TEB→PEB to start the PEB walk.
// ============================================================================

ErrorCode ShellcodeLoader::CreateMinimalTEB(
    LoadedShellcode& sc,
    const EmulationConfig& config) noexcept
{
    static_cast<void>(config);
    const GuestAddress tebAddr = WinConst::kTEBAddress64;

    auto tebOpt = m_memory.Allocate(tebAddr, kPageSize, MemProt::RW);
    if (!tebOpt) {
        tebOpt = m_memory.Allocate(0, kPageSize, MemProt::RW);
        if (!tebOpt) return ErrorCode::OutOfMemory;
    }
    sc.tebAddress = *tebOpt;

    const GuestAddress teb = sc.tebAddress;
    ErrorCode err = ErrorCode::Success;

    if (sc.is64Bit) {
        // ---- x64 TEB ----

        // ExceptionList = 0 (x64 uses unwind tables)
        err = WriteAt(m_memory, teb, 0x000, static_cast<uint64_t>(0));
        if (err != ErrorCode::Success) return err;

        // StackBase (high address)
        err = WriteAt(m_memory, teb, 0x008, sc.stackTop);
        if (err != ErrorCode::Success) return err;

        // StackLimit (above guard page)
        GuestAddress stackLimit = 0;
        if (!AddGuestAddress(sc.stackBase, kPageSize, stackLimit)) return ErrorCode::InvalidAddress;
        err = WriteAt(m_memory, teb, 0x010, stackLimit);
        if (err != ErrorCode::Success) return err;

        // Self → TEB (GS:[0x30])
        err = WriteAt(m_memory, teb, 0x030, teb);
        if (err != ErrorCode::Success) return err;

        // ClientId.UniqueProcess
        err = WriteAt(m_memory, teb, 0x040, static_cast<uint64_t>(4096));
        if (err != ErrorCode::Success) return err;

        // ClientId.UniqueThread
        err = WriteAt(m_memory, teb, 0x048, static_cast<uint64_t>(4100));
        if (err != ErrorCode::Success) return err;

        // PEB pointer
        err = WriteAt(m_memory, teb, 0x060, sc.pebAddress);
        if (err != ErrorCode::Success) return err;

        // LastErrorValue = 0
        err = WriteAt(m_memory, teb, 0x068, static_cast<uint32_t>(0));
        if (err != ErrorCode::Success) return err;

    } else {
        // ---- x86 TEB ----

        // ExceptionList = -1 (end of SEH chain)
        err = WriteAt(m_memory, teb, 0x000, static_cast<uint32_t>(0xFFFFFFFF));
        if (err != ErrorCode::Success) return err;

        // StackBase (high address)
        uint32_t stackTop32 = 0;
        if (!ToU32Address(sc.stackTop, stackTop32)) return ErrorCode::InvalidAddress;
        err = WriteAt(m_memory, teb, 0x004, stackTop32);
        if (err != ErrorCode::Success) return err;

        // StackLimit (above guard page)
        GuestAddress stackLimit = 0;
        uint32_t stackLimit32 = 0;
        if (!AddGuestAddress(sc.stackBase, kPageSize, stackLimit) ||
            !ToU32Address(stackLimit, stackLimit32)) return ErrorCode::InvalidAddress;
        err = WriteAt(m_memory, teb, 0x008, stackLimit32);
        if (err != ErrorCode::Success) return err;

        // Self → TEB (FS:[0x18])
        uint32_t teb32 = 0;
        if (!ToU32Address(teb, teb32)) return ErrorCode::InvalidAddress;
        err = WriteAt(m_memory, teb, 0x018, teb32);
        if (err != ErrorCode::Success) return err;

        // ClientId.UniqueProcess
        err = WriteAt(m_memory, teb, 0x024, static_cast<uint32_t>(4096));
        if (err != ErrorCode::Success) return err;

        // ClientId.UniqueThread
        err = WriteAt(m_memory, teb, 0x028, static_cast<uint32_t>(4100));
        if (err != ErrorCode::Success) return err;

        // PEB pointer
        uint32_t peb32 = 0;
        if (!ToU32Address(sc.pebAddress, peb32)) return ErrorCode::InvalidAddress;
        err = WriteAt(m_memory, teb, 0x030, peb32);
        if (err != ErrorCode::Success) return err;

        // LastErrorValue = 0
        err = WriteAt(m_memory, teb, 0x034, static_cast<uint32_t>(0));
        if (err != ErrorCode::Success) return err;
    }

    return ErrorCode::Success;
}

} // namespace Phantom
