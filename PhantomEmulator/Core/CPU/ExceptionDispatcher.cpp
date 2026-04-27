/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ExceptionDispatcher.cpp — SEH/VEH exception dispatch engine
 *
 * Full implementation of Windows exception dispatch modeling inside the
 * emulated guest. Builds NT EXCEPTION_RECORD and CONTEXT structures on
 * the guest stack, walks VEH and SEH handler chains for behavioral
 * analysis, and detects anti-debug / anti-analysis abuse of the
 * exception mechanism.
 *
 * Key design decisions:
 *   - We do NOT re-enter the CPU execution loop to run handlers.
 *     Instead we use heuristics: VEH handlers registered for breakpoint
 *     or single-step exceptions are assumed to handle those exceptions
 *     (this is the dominant malware anti-debug pattern).
 *   - SEH chain walks are always read-only analysis — we walk the
 *     linked list, log handler addresses, check for abuse, and return
 *     unhandled so the emulator can decide next steps.
 *   - All chain walks are capped (256 SEH entries, 64 VEH handlers)
 *     to prevent infinite loops on corrupted guest memory.
 *   - All guest pointer reads are validated before dereference.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "ExceptionDispatcher.hpp"
#include "State/CPUState.hpp"
#include "../Memory/VirtualMemory.hpp"
#include "../../Common/Constants.hpp"

#include <vector>
#include <atomic>
#include <algorithm>
#include <cstring>
#include <limits>
#include <new>
#include <shared_mutex>

namespace Phantom {

// ============================================================================
// Internal Constants
// ============================================================================

namespace {

// ExceptionFlags field values (distinct from the EXCEPTION_NONCONTINUABLE
// exception *code* 0xC0000025 — this is the per-record flag bit).
constexpr uint32_t kExFlagContinuable     = 0;
constexpr uint32_t kExFlagNoncontinuable  = 1;

// CONTEXT_ALL for x64
constexpr uint32_t kContextAll = 0x10001F;

// Sentinel marking end of SEH chain
constexpr uint64_t kSEHEndOfChain64 = 0xFFFFFFFFFFFFFFFFULL;
constexpr uint32_t kSEHEndOfChain32 = 0xFFFFFFFF;

// Minimum plausible guest address (below this is almost certainly invalid)
constexpr GuestAddress kMinValidAddress = 0x10000;

// Maximum exception parameters in EXCEPTION_RECORD
constexpr uint32_t kMaxExceptionParams = 15;

// ========================================================================
// Guest-space EXCEPTION_RECORD layout offsets
// ========================================================================
// Offset  Field
// 0x00    DWORD   ExceptionCode
// 0x04    DWORD   ExceptionFlags
// 0x08    QWORD   ExceptionRecord (chained, 0 for first)
// 0x10    QWORD   ExceptionAddress (RIP at fault)
// 0x18    DWORD   NumberParameters
// 0x1C    (4 bytes padding for alignment)
// 0x20    QWORD[15] ExceptionInformation
// Total: 0x98 bytes

constexpr uint32_t kExRecSize            = 0x98;
constexpr uint32_t kExRecCodeOff         = 0x00;
constexpr uint32_t kExRecFlagsOff        = 0x04;
constexpr uint32_t kExRecRecordOff       = 0x08;
constexpr uint32_t kExRecAddressOff      = 0x10;
constexpr uint32_t kExRecNumParamsOff    = 0x18;
constexpr uint32_t kExRecInfoOff         = 0x20;

// ========================================================================
// Guest-space CONTEXT layout offsets (simplified — GPRs + RIP + RFLAGS)
// ========================================================================
// We use the real Windows CONTEXT offsets for the fields we care about
// so that any guest code inspecting the context sees valid data.
//
// Offset  Field
// 0x000   DWORD   ContextFlags
// 0x044   DWORD   EFlags
// 0x078   QWORD   Rax
// 0x080   QWORD   Rcx
// 0x088   QWORD   Rdx
// 0x090   QWORD   Rbx
// 0x098   QWORD   Rsp
// 0x0A0   QWORD   Rbp
// 0x0A8   QWORD   Rsi
// 0x0B0   QWORD   Rdi
// 0x0B8   QWORD   R8
// 0x0C0   QWORD   R9
// 0x0C8   QWORD   R10
// 0x0D0   QWORD   R11
// 0x0D8   QWORD   R12
// 0x0E0   QWORD   R13
// 0x0E8   QWORD   R14
// 0x0F0   QWORD   R15
// 0x0F8   QWORD   Rip
// Total allocation: 0x100 bytes (rounded up for alignment)

constexpr uint32_t kCtxSize              = 0x100;
constexpr uint32_t kCtxFlagsOff          = 0x000;
constexpr uint32_t kCtxEFlagsOff         = 0x044;
constexpr uint32_t kCtxRaxOff            = 0x078;
constexpr uint32_t kCtxR8Off             = 0x0B8;
constexpr uint32_t kCtxRipOff            = 0x0F8;

// ========================================================================
// EXCEPTION_POINTERS layout (two QWORDs)
// ========================================================================

constexpr uint32_t kExPtrsSize           = 0x10;

// ========================================================================
// Stack frame layout (low address → high address)
//   [frame_base + 0x000] EXCEPTION_RECORD  (0x98 bytes)
//   [frame_base + 0x0A0] CONTEXT           (0x100 bytes, 8-byte aligned)
//   [frame_base + 0x1A0] EXCEPTION_POINTERS(0x10 bytes)
//   Total: 0x1B0 bytes
// ========================================================================

constexpr uint32_t kFrameExRecOff        = 0x000;
constexpr uint32_t kFrameCtxOff          = 0x0A0;
constexpr uint32_t kFrameExPtrsOff       = 0x1A0;
constexpr uint32_t kTotalFrameSize       = 0x1B0;

[[nodiscard]] bool AddGuestOffset(GuestAddress base, uint64_t offset, GuestAddress& result) noexcept {
    if ((std::numeric_limits<GuestAddress>::max)() - base < offset) {
        return false;
    }
    result = base + offset;
    return true;
}

} // anonymous namespace

// ============================================================================
// PIMPL Implementation
// ============================================================================

struct ExceptionDispatcher::Impl {

    // VEH handler addresses (guest code pointers, ordered front-to-back)
    std::vector<GuestAddress> vehHandlers;

    // Statistics
    std::atomic<uint32_t> exceptionsDispatched{0};

    // Anti-evasion abuse detection flags
    struct AbuseFlags {
        bool vehForBreakpoint        = false; // VEH registered + BP exception seen
        bool vehForSingleStep        = false; // VEH registered + SS exception seen
        bool sehHandlerInWritableMem = false; // Handler resides in W memory (shellcode)
        bool sehChainCorruption      = false; // Circular / malformed chain
        bool sehHandlerAtNull        = false; // Handler at address 0
        bool sehHandlerOutsideImage  = false; // Handler outside plausible code regions
        uint32_t deliberateExceptions = 0;    // Exceptions that look intentional
    } abuse;

    mutable std::shared_mutex mutex;

    // Limits
    static constexpr uint32_t kMaxVEHHandlers       = 64;
    static constexpr uint32_t kMaxSEHChainEntries    = 256;
    static constexpr uint32_t kDeliberateThreshold   = 10;

    // --------------------------------------------------------------------
    // Helpers
    // --------------------------------------------------------------------

    [[nodiscard]] bool HasAnyAbuse() const noexcept {
        return abuse.vehForBreakpoint
            || abuse.vehForSingleStep
            || abuse.sehHandlerInWritableMem
            || abuse.sehChainCorruption
            || abuse.sehHandlerAtNull
            || abuse.sehHandlerOutsideImage
            || (abuse.deliberateExceptions > kDeliberateThreshold);
    }

    // Check if a handler address looks suspicious.
    [[nodiscard]] bool IsHandlerSuspicious(
        GuestAddress handler, VirtualMemory& mem) const noexcept
    {
        if (handler == kGuestNull) return true;
        if (handler < kMinValidAddress) return true;

        // Check if the handler resides in writable memory (code should be RX)
        auto prot = mem.GetProtection(handler);
        if (prot.has_value() && HasProt(*prot, MemProt::Write)) return true;

        return false;
    }

    // Check if a handler is plausibly inside a loaded module.
    // Heuristic: typical image ranges from Constants.hpp.
    [[nodiscard]] static bool IsOutsideImageRange(GuestAddress handler) noexcept {
        // x64 EXE default range: 0x140000000 ± 256 MB
        const bool inExeRange =
            (handler >= 0x0000000100000000ULL && handler < 0x0000000200000000ULL);

        // x64 system DLL range (our virtual DLLs): 0x7FFE00000000 ± 1 GB
        const bool inDllRange =
            (handler >= 0x00007FFD00000000ULL && handler < 0x00007FFF00000000ULL);

        // x86 EXE default range: 0x400000 – 0x80000000
        const bool in32Range =
            (handler >= 0x00400000 && handler < 0x80000000);

        return !(inExeRange || inDllRange || in32Range);
    }

    // Build an EXCEPTION_RECORD at the given guest base address.
    [[nodiscard]] ErrorCode BuildExceptionRecord(
        VirtualMemory& mem,
        GuestAddress base,
        uint32_t code,
        uint32_t flags,
        GuestAddress exceptionAddress,
        uint32_t numParams,
        const uint64_t* params) noexcept
    {
        GuestAddress tmp = 0;
        if (!AddGuestOffset(base, kExRecSize - 1, tmp)) {
            return ErrorCode::AddressOverflow;
        }

        // Zero the entire record first
        uint8_t zeroes[kExRecSize]{};
        auto ec = mem.Write(base, zeroes, kExRecSize);
        if (ec != ErrorCode::Success) return ec;

        ec = mem.WriteU32(base + kExRecCodeOff, code);
        if (ec != ErrorCode::Success) return ec;

        ec = mem.WriteU32(base + kExRecFlagsOff, flags);
        if (ec != ErrorCode::Success) return ec;

        ec = mem.WriteU64(base + kExRecRecordOff, 0);
        if (ec != ErrorCode::Success) return ec;

        ec = mem.WriteU64(base + kExRecAddressOff, exceptionAddress);
        if (ec != ErrorCode::Success) return ec;

        const uint32_t safeCount = (params == nullptr)
            ? 0
            : ((numParams > kMaxExceptionParams) ? kMaxExceptionParams : numParams);

        ec = mem.WriteU32(base + kExRecNumParamsOff, safeCount);
        if (ec != ErrorCode::Success) return ec;

        for (uint32_t i = 0; i < safeCount && params != nullptr; ++i) {
            GuestAddress paramAddress = 0;
            if (!AddGuestOffset(base, kExRecInfoOff + static_cast<uint64_t>(i) * 8, paramAddress)) {
                return ErrorCode::AddressOverflow;
            }
            ec = mem.WriteU64(paramAddress, params[i]);
            if (ec != ErrorCode::Success) return ec;
        }

        return ErrorCode::Success;
    }

    // Save CPU GPRs + RIP + RFLAGS into a guest-space CONTEXT at `base`.
    [[nodiscard]] ErrorCode SaveContext(
        VirtualMemory& mem,
        GuestAddress base,
        const CPUState& cpu) noexcept
    {
        GuestAddress tmp = 0;
        if (!AddGuestOffset(base, kCtxSize - 1, tmp)) {
            return ErrorCode::AddressOverflow;
        }

        // Zero the context area
        uint8_t zeroes[kCtxSize]{};
        auto ec = mem.Write(base, zeroes, kCtxSize);
        if (ec != ErrorCode::Success) return ec;

        // ContextFlags
        ec = mem.WriteU32(base + kCtxFlagsOff, kContextAll);
        if (ec != ErrorCode::Success) return ec;

        // EFLAGS
        ec = mem.WriteU32(base + kCtxEFlagsOff,
                          static_cast<uint32_t>(cpu.eflags.Raw()));
        if (ec != ErrorCode::Success) return ec;

        // RAX through RDI (GPR indices 0–7)
        for (uint8_t i = 0; i < 8; ++i) {
            GuestAddress regAddress = 0;
            if (!AddGuestOffset(base, kCtxRaxOff + static_cast<uint64_t>(i) * 8, regAddress)) {
                return ErrorCode::AddressOverflow;
            }
            ec = mem.WriteU64(regAddress, cpu.GetReg64(static_cast<GPR>(i)));
            if (ec != ErrorCode::Success) return ec;
        }

        // R8 through R15 (GPR indices 8–15)
        for (uint8_t i = 0; i < 8; ++i) {
            GuestAddress regAddress = 0;
            if (!AddGuestOffset(base, kCtxR8Off + static_cast<uint64_t>(i) * 8, regAddress)) {
                return ErrorCode::AddressOverflow;
            }
            ec = mem.WriteU64(regAddress, cpu.GetReg64(static_cast<GPR>(8 + i)));
            if (ec != ErrorCode::Success) return ec;
        }

        // RIP
        ec = mem.WriteU64(base + kCtxRipOff, cpu.GetRIP());
        return ec;
    }

    // Restore CPU GPRs + RIP + RFLAGS from a guest-space CONTEXT at `base`.
    [[nodiscard]] ErrorCode RestoreContext(
        VirtualMemory& mem,
        GuestAddress base,
        CPUState& cpu) noexcept
    {
        GuestAddress tmp = 0;
        if (!AddGuestOffset(base, kCtxSize - 1, tmp)) {
            return ErrorCode::AddressOverflow;
        }

        uint32_t eflags = 0;
        auto ec = mem.ReadU32(base + kCtxEFlagsOff, eflags);
        if (ec != ErrorCode::Success) return ec;
        cpu.eflags.SetRaw(eflags);

        for (uint8_t i = 0; i < 8; ++i) {
            uint64_t val = 0;
            GuestAddress regAddress = 0;
            if (!AddGuestOffset(base, kCtxRaxOff + static_cast<uint64_t>(i) * 8, regAddress)) {
                return ErrorCode::AddressOverflow;
            }
            ec = mem.ReadU64(regAddress, val);
            if (ec != ErrorCode::Success) return ec;
            cpu.SetReg64(static_cast<GPR>(i), val);
        }

        for (uint8_t i = 0; i < 8; ++i) {
            uint64_t val = 0;
            GuestAddress regAddress = 0;
            if (!AddGuestOffset(base, kCtxR8Off + static_cast<uint64_t>(i) * 8, regAddress)) {
                return ErrorCode::AddressOverflow;
            }
            ec = mem.ReadU64(regAddress, val);
            if (ec != ErrorCode::Success) return ec;
            cpu.SetReg64(static_cast<GPR>(8 + i), val);
        }

        uint64_t rip = 0;
        ec = mem.ReadU64(base + kCtxRipOff, rip);
        if (ec != ErrorCode::Success) return ec;
        cpu.SetRIP(rip);

        return ErrorCode::Success;
    }

    // Read the head of the SEH ExceptionList from the TEB.
    [[nodiscard]] GuestAddress GetExceptionListHead(
        const CPUState& cpu, VirtualMemory& mem) const noexcept
    {
        // TEB base comes from the segment register:
        //   x64: GS segment base = TEB address
        //   x86: FS segment base = TEB address
        // NtTib.ExceptionList is at offset 0x00 of the TEB.

        GuestAddress tebBase = 0;
        if (cpu.Is64Bit()) {
            tebBase = cpu.GetSegment(SegReg::GS).base;
        } else {
            tebBase = cpu.GetSegment(SegReg::FS).base;
        }

        if (tebBase < kMinValidAddress) return kSEHEndOfChain64;

        uint64_t listHead = 0;
        if (cpu.Is64Bit()) {
            if (mem.ReadU64(tebBase, listHead) != ErrorCode::Success)
                return kSEHEndOfChain64;
        } else {
            uint32_t head32 = 0;
            if (mem.ReadU32(tebBase, head32) != ErrorCode::Success)
                return static_cast<GuestAddress>(kSEHEndOfChain32);
            listHead = head32;
        }

        return listHead;
    }

    // Walk the SEH chain in guest memory.
    // If `recordAbuse` is true, populate the abuse flags.
    // Returns the number of valid entries traversed.
    [[nodiscard]] uint32_t WalkSEHChain(
        CPUState& cpu,
        VirtualMemory& mem,
        bool recordAbuse) noexcept
    {
        const bool is64 = cpu.Is64Bit();
        const uint64_t endSentinel = is64 ? kSEHEndOfChain64
                                          : static_cast<uint64_t>(kSEHEndOfChain32);

        GuestAddress current = GetExceptionListHead(cpu, mem);
        uint32_t depth = 0;

        // Track visited addresses to detect circular chains
        // Use a simple bounded array — 256 entries max
        GuestAddress visited[kMaxSEHChainEntries]{};

        while (current != endSentinel && current >= kMinValidAddress
               && depth < kMaxSEHChainEntries)
        {
            // Circular chain detection
            for (uint32_t i = 0; i < depth; ++i) {
                if (visited[i] == current) {
                    if (recordAbuse) abuse.sehChainCorruption = true;
                    return depth;
                }
            }
            visited[depth] = current;

            // Read EXCEPTION_REGISTRATION_RECORD:
            //   QWORD/DWORD  Next
            //   QWORD/DWORD  Handler
            GuestAddress next    = 0;
            GuestAddress handler = 0;

            if (is64) {
                uint64_t nextVal = 0, handlerVal = 0;
                GuestAddress handlerAddress = 0;
                if (!AddGuestOffset(current, 8, handlerAddress)) {
                    if (recordAbuse) abuse.sehChainCorruption = true;
                    break;
                }
                if (mem.ReadU64(current, nextVal) != ErrorCode::Success) break;
                if (mem.ReadU64(handlerAddress, handlerVal) != ErrorCode::Success) break;
                next    = nextVal;
                handler = handlerVal;
            } else {
                uint32_t nextVal = 0, handlerVal = 0;
                GuestAddress handlerAddress = 0;
                if (!AddGuestOffset(current, 4, handlerAddress)) {
                    if (recordAbuse) abuse.sehChainCorruption = true;
                    break;
                }
                if (mem.ReadU32(current, nextVal) != ErrorCode::Success) break;
                if (mem.ReadU32(handlerAddress, handlerVal) != ErrorCode::Success) break;
                next    = nextVal;
                handler = handlerVal;
            }

            if (recordAbuse) {
                if (handler == kGuestNull) {
                    abuse.sehHandlerAtNull = true;
                }

                if (IsHandlerSuspicious(handler, mem)) {
                    abuse.sehHandlerInWritableMem = true;
                }

                if (handler >= kMinValidAddress && IsOutsideImageRange(handler)) {
                    abuse.sehHandlerOutsideImage = true;
                }
            }

            ++depth;
            current = next;
        }

        // If we hit the cap, flag corruption
        if (depth >= kMaxSEHChainEntries && recordAbuse) {
            abuse.sehChainCorruption = true;
        }

        return depth;
    }

    // Flag specific exception codes as likely-deliberate evasion.
    void AnalyzeExceptionForEvasion(uint32_t code) noexcept {
        switch (code) {
            case ExceptionDispatcher::EXCEPTION_BREAKPOINT:
            case ExceptionDispatcher::EXCEPTION_SINGLE_STEP:
            case ExceptionDispatcher::EXCEPTION_GUARD_PAGE:
            case ExceptionDispatcher::EXCEPTION_INT_DIVIDE_BY_ZERO:
                if (abuse.deliberateExceptions < (std::numeric_limits<uint32_t>::max)()) {
                    ++abuse.deliberateExceptions;
                }
                break;
            default:
                break;
        }
    }
};

// ============================================================================
// Construction / Destruction / Move
// ============================================================================

ExceptionDispatcher::ExceptionDispatcher() noexcept
{
    try {
        m_impl = std::make_unique<Impl>();
        m_impl->vehHandlers.reserve(Impl::kMaxVEHHandlers);
    } catch (const std::bad_alloc&) {
        m_impl.reset();
    }
}

ExceptionDispatcher::~ExceptionDispatcher() noexcept = default;

ExceptionDispatcher::ExceptionDispatcher(ExceptionDispatcher&&) noexcept = default;
ExceptionDispatcher& ExceptionDispatcher::operator=(ExceptionDispatcher&&) noexcept = default;

// ============================================================================
// VEH Management
// ============================================================================

void ExceptionDispatcher::AddVEH(GuestAddress handler, bool first) noexcept {
    if (!m_impl || handler < kMinValidAddress) return;

    std::unique_lock lock(m_impl->mutex);

    if (m_impl->vehHandlers.size() >= Impl::kMaxVEHHandlers) return;

    // Prevent duplicate registrations
    auto it = std::find(m_impl->vehHandlers.begin(),
                        m_impl->vehHandlers.end(), handler);
    if (it != m_impl->vehHandlers.end()) return;

    if (first) {
        try {
            m_impl->vehHandlers.insert(m_impl->vehHandlers.begin(), handler);
        } catch (const std::bad_alloc&) {
            return;
        }
    } else {
        try {
            m_impl->vehHandlers.push_back(handler);
        } catch (const std::bad_alloc&) {
            return;
        }
    }
}

void ExceptionDispatcher::RemoveVEH(GuestAddress handler) noexcept {
    if (!m_impl) return;
    std::unique_lock lock(m_impl->mutex);

    auto it = std::find(m_impl->vehHandlers.begin(),
                        m_impl->vehHandlers.end(), handler);
    if (it != m_impl->vehHandlers.end()) {
        m_impl->vehHandlers.erase(it);
    }
}

// ============================================================================
// DispatchException — Main Dispatch Logic
// ============================================================================

bool ExceptionDispatcher::DispatchException(
    CPUState& cpu,
    VirtualMemory& mem,
    uint32_t exceptionCode,
    GuestAddress faultAddress,
    bool isContinuable,
    uint32_t numParams,
    const uint64_t* params) noexcept
{
    if (!m_impl) {
        return false;
    }
    (void)faultAddress; // Used only indirectly via params for AV exceptions
    m_impl->exceptionsDispatched.fetch_add(1, std::memory_order_relaxed);

    // ----------------------------------------------------------------
    // 1. Record exception pattern for anti-evasion analysis
    // ----------------------------------------------------------------
    m_impl->AnalyzeExceptionForEvasion(exceptionCode);

    // ----------------------------------------------------------------
    // 2. Build guest-space stack frame (EXCEPTION_RECORD + CONTEXT +
    //    EXCEPTION_POINTERS) for behavioral fidelity.
    // ----------------------------------------------------------------
    const GuestAddress originalRsp = cpu.RSP();

    // Align new RSP down to 16-byte boundary after subtracting the frame
    if (originalRsp < kTotalFrameSize) {
        return false;
    }
    const GuestAddress newRsp = AlignDown(originalRsp - kTotalFrameSize, 16);

    // Validate the guest stack region is writable before committing
    GuestAddress frameEnd = 0;
    if (!AddGuestOffset(newRsp, kTotalFrameSize - 1, frameEnd)) {
        return false;
    }
    if (!mem.IsAccessible(newRsp, MemProt::Write) ||
        !mem.IsAccessible(frameEnd, MemProt::Write))
    {
        // Stack is not writable — cannot build frame.
        // This is itself noteworthy (possible stack overflow or corruption).
        return false;
    }

    const GuestAddress exRecAddr    = newRsp + kFrameExRecOff;
    const GuestAddress ctxAddr      = newRsp + kFrameCtxOff;
    const GuestAddress exPtrsAddr   = newRsp + kFrameExPtrsOff;

    const uint32_t exFlags = isContinuable ? kExFlagContinuable
                                           : kExFlagNoncontinuable;

    // Build the EXCEPTION_RECORD
    auto ec = m_impl->BuildExceptionRecord(
        mem, exRecAddr, exceptionCode, exFlags,
        cpu.GetRIP(), numParams, params);

    if (ec != ErrorCode::Success) return false;

    // Save current CPU state into the CONTEXT
    ec = m_impl->SaveContext(mem, ctxAddr, cpu);
    if (ec != ErrorCode::Success) return false;

    // Write EXCEPTION_POINTERS { &ExceptionRecord, &Context }
    ec = mem.WriteU64(exPtrsAddr, exRecAddr);
    if (ec != ErrorCode::Success) return false;
    GuestAddress contextPointerAddress = 0;
    if (!AddGuestOffset(exPtrsAddr, 8, contextPointerAddress)) return false;
    ec = mem.WriteU64(contextPointerAddress, ctxAddr);
    if (ec != ErrorCode::Success) return false;

    // Commit the new stack pointer so the frame is visible to analysis
    cpu.SetReg64(GPR::RSP, newRsp);

    // ----------------------------------------------------------------
    // 3. VEH dispatch (heuristic — we cannot re-enter the CPU loop)
    // ----------------------------------------------------------------
    {
        std::shared_lock lock(m_impl->mutex);

        const bool isAntiDebugException =
            (exceptionCode == EXCEPTION_BREAKPOINT ||
             exceptionCode == EXCEPTION_SINGLE_STEP);

        if (!m_impl->vehHandlers.empty()) {
            // Track VEH + anti-debug correlation
            if (exceptionCode == EXCEPTION_BREAKPOINT) {
                m_impl->abuse.vehForBreakpoint = true;
            }
            if (exceptionCode == EXCEPTION_SINGLE_STEP) {
                m_impl->abuse.vehForSingleStep = true;
            }

            // Heuristic: if VEH handlers are registered and the exception
            // is a classic anti-debug exception, assume the first handler
            // returns EXCEPTION_CONTINUE_EXECUTION. This lets the emulation
            // continue through malware anti-debug tricks.
            if (isAntiDebugException && isContinuable) {
                // Restore the original RSP (handler "returned" cleanly)
                cpu.SetReg64(GPR::RSP, originalRsp);
                return true;
            }
        }
    }

    // ----------------------------------------------------------------
    // 4. SEH chain walk (read-only analysis)
    // ----------------------------------------------------------------
    (void)m_impl->WalkSEHChain(cpu, mem, /*recordAbuse=*/true);

    // We do not execute SEH handlers. Restore the stack pointer so the
    // emulator caller sees the original state (minus the context save
    // which was for record-building only).
    cpu.SetReg64(GPR::RSP, originalRsp);

    // Return false — exception was not handled. The emulator caller
    // (CPU execution loop) should decide whether to stop or continue.
    return false;
}

// ============================================================================
// DispatchFromError — Map ErrorCode to NT Exception
// ============================================================================

bool ExceptionDispatcher::DispatchFromError(
    CPUState& cpu,
    VirtualMemory& mem,
    ErrorCode error,
    GuestAddress faultAddress) noexcept
{
    if (!m_impl) {
        return false;
    }
    uint32_t exCode = 0;
    bool continuable = true;
    uint64_t infoParams[2]{};
    uint32_t numParams = 0;

    switch (error) {
        case ErrorCode::AccessViolationRead:
            exCode = EXCEPTION_ACCESS_VIOLATION;
            infoParams[0] = 0; // 0 = read
            infoParams[1] = faultAddress;
            numParams = 2;
            break;

        case ErrorCode::AccessViolationWrite:
            exCode = EXCEPTION_ACCESS_VIOLATION;
            infoParams[0] = 1; // 1 = write
            infoParams[1] = faultAddress;
            numParams = 2;
            break;

        case ErrorCode::AccessViolationExec:
            exCode = EXCEPTION_ACCESS_VIOLATION;
            infoParams[0] = 8; // 8 = DEP violation
            infoParams[1] = faultAddress;
            numParams = 2;
            break;

        case ErrorCode::DivideByZero:
            exCode = EXCEPTION_INT_DIVIDE_BY_ZERO;
            break;

        case ErrorCode::DivideOverflow:
            exCode = EXCEPTION_INT_OVERFLOW;
            break;

        case ErrorCode::StackOverflow:
            exCode = EXCEPTION_STACK_OVERFLOW;
            continuable = false;
            break;

        case ErrorCode::GuardPageViolation:
            exCode = EXCEPTION_GUARD_PAGE;
            infoParams[0] = 0;
            infoParams[1] = faultAddress;
            numParams = 2;
            break;

        case ErrorCode::PrivilegedInstruction:
            exCode = EXCEPTION_PRIV_INSTRUCTION;
            break;

        case ErrorCode::InvalidOpcode:
        case ErrorCode::UnsupportedOpcode:
            exCode = EXCEPTION_ILLEGAL_INSTRUCTION;
            break;

        default:
            // No mapping — cannot dispatch
            return false;
    }

    return DispatchException(cpu, mem, exCode, faultAddress,
                             continuable, numParams, infoParams);
}

// ============================================================================
// Diagnostics
// ============================================================================

uint32_t ExceptionDispatcher::GetExceptionsDispatched() const noexcept {
    if (!m_impl) {
        return 0;
    }
    return m_impl->exceptionsDispatched.load(std::memory_order_relaxed);
}

uint32_t ExceptionDispatcher::GetSEHChainDepth(
    CPUState& cpu, VirtualMemory& mem) const noexcept
{
    if (!m_impl) {
        return 0;
    }
    // Read-only walk (no abuse recording to avoid mutating const-qualified path)
    const bool is64 = cpu.Is64Bit();
    const uint64_t endSentinel = is64 ? kSEHEndOfChain64
                                      : static_cast<uint64_t>(kSEHEndOfChain32);

    GuestAddress current = m_impl->GetExceptionListHead(cpu, mem);
    uint32_t depth = 0;

    GuestAddress visited[Impl::kMaxSEHChainEntries]{};

    while (current != endSentinel && current >= kMinValidAddress
           && depth < Impl::kMaxSEHChainEntries)
    {
        // Circular chain detection
        for (uint32_t i = 0; i < depth; ++i) {
            if (visited[i] == current) return depth;
        }
        visited[depth] = current;

        GuestAddress next = 0;
        if (is64) {
            uint64_t nextVal = 0;
            if (mem.ReadU64(current, nextVal) != ErrorCode::Success) break;
            next = nextVal;
        } else {
            uint32_t nextVal = 0;
            if (mem.ReadU32(current, nextVal) != ErrorCode::Success) break;
            next = nextVal;
        }

        ++depth;
        current = next;
    }

    return depth;
}

bool ExceptionDispatcher::DetectedSEHAbuse() const noexcept {
    if (!m_impl) {
        return false;
    }
    return m_impl->HasAnyAbuse();
}

// ============================================================================
// Reset
// ============================================================================

void ExceptionDispatcher::Reset() noexcept {
    if (!m_impl) {
        return;
    }
    std::unique_lock lock(m_impl->mutex);

    m_impl->vehHandlers.clear();
    m_impl->exceptionsDispatched.store(0, std::memory_order_relaxed);

    m_impl->abuse.vehForBreakpoint        = false;
    m_impl->abuse.vehForSingleStep        = false;
    m_impl->abuse.sehHandlerInWritableMem = false;
    m_impl->abuse.sehChainCorruption      = false;
    m_impl->abuse.sehHandlerAtNull        = false;
    m_impl->abuse.sehHandlerOutsideImage  = false;
    m_impl->abuse.deliberateExceptions     = 0;
}

} // namespace Phantom
