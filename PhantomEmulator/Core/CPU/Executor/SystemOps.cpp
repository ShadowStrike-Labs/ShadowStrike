/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * SystemOps.cpp — CPUID, RDTSC, RDTSCP, NOP
 *                 Anti-evasion: returns fake Intel Core i7-10700K values.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "../CPU.hpp"
#include "../../../Common/Constants.hpp"
#include <cstring>

namespace Phantom {

namespace {

constexpr uint64_t kSupportedXStateMask = 0x07; // x87, SSE, AVX upper halves
constexpr uint32_t kMxcsrWritableMask = 0x0000FFBF;

[[nodiscard]] bool CanAddGuestOffset(GuestAddress base, uint64_t offset, GuestAddress& result) noexcept {
    if (base > (std::numeric_limits<GuestAddress>::max)() - offset) return false;
    result = base + offset;
    return true;
}

[[nodiscard]] ErrorCode WriteGuestOffset(
    VirtualMemory& mem,
    GuestAddress base,
    uint64_t offset,
    const void* src,
    uint32_t bytes) noexcept
{
    GuestAddress target = 0;
    if (!CanAddGuestOffset(base, offset, target)) return ErrorCode::AddressOverflow;
    return mem.Write(target, src, bytes);
}

[[nodiscard]] ErrorCode ReadGuestOffset(
    VirtualMemory& mem,
    GuestAddress base,
    uint64_t offset,
    void* dst,
    uint32_t bytes) noexcept
{
    GuestAddress target = 0;
    if (!CanAddGuestOffset(base, offset, target)) return ErrorCode::AddressOverflow;
    return mem.Read(target, dst, bytes);
}

[[nodiscard]] bool HasMemoryOperand0(const DecodedInstruction& inst) noexcept {
    return inst.HasOperand(0) && inst.Op(0).IsMemory();
}

[[nodiscard]] uint64_t DeterministicEntropySample(uint64_t seed) noexcept {
    seed ^= seed >> 12;
    seed ^= seed << 25;
    seed ^= seed >> 27;
    return seed * 0x2545F4914F6CDD1DULL;
}

} // namespace

ErrorCode CPU::ExecuteSystem(const DecodedInstruction& inst, VirtualMemory& mem) noexcept {
    if (inst.opcodeMap == OpcodeMap::TwoByte) {
        // === CPUID (0F A2) ===
        if (inst.opcode == 0xA2) {
            uint32_t leaf = m_state.GetReg32(GPR::RAX);
            uint32_t subleaf = m_state.GetReg32(GPR::RCX);
            uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;

            switch (leaf) {
                case 0: // Vendor string + max basic leaf
                    eax = CPUID::kMaxBasicLeaf;
                    ebx = CPUID::kVendorEBX;
                    ecx = CPUID::kVendorECX;
                    edx = CPUID::kVendorEDX;
                    break;

                case 1: { // Version info + feature flags
                    eax = CPUID::kVersionInfo;
                    // EBX: brand=0, CLFLUSH=8 (64-byte line), logical procs=8, APIC=0
                    ebx = 0x00800800;
                    ecx = CPUID::kFeatureECX;
                    edx = CPUID::kFeatureEDX;
                    break;
                }

                case 2: // Cache/TLB descriptors (simplified)
                    eax = 0x76035A01;
                    ebx = 0x00F0B5FF;
                    ecx = 0x00000000;
                    edx = 0x00C10000;
                    break;

                case 4: // Deterministic cache (Intel)
                    if (subleaf == 0) { eax = 0x1C004121; ebx = 0x01C0003F; ecx = 0x0000003F; edx = 0; }
                    else if (subleaf == 1) { eax = 0x1C004122; ebx = 0x01C0003F; ecx = 0x0000003F; edx = 0; }
                    else if (subleaf == 2) { eax = 0x1C004143; ebx = 0x03C0003F; ecx = 0x000003FF; edx = 0; }
                    else if (subleaf == 3) { eax = 0x1C03C163; ebx = 0x04C0003F; ecx = 0x00003FFF; edx = 0; }
                    break;

                case 7: // Structured extended features
                    if (subleaf == 0) {
                        eax = 0; // Max subleaf
                        ebx = 0x029C67AF; // ERMS, RDSEED, ADX, SMAP, CLFLUSHOPT, etc.
                        ecx = 0;
                        edx = 0;
                    }
                    break;

                case 0x0B: // Extended topology
                    if (subleaf == 0) { eax = 1; ebx = 2; ecx = 0x100; edx = 0; }
                    else if (subleaf == 1) { eax = 4; ebx = 8; ecx = 0x201; edx = 0; }
                    break;

                case 0x80000000: // Max extended leaf
                    eax = CPUID::kMaxExtLeaf;
                    break;

                case 0x80000001: // Extended feature flags
                    ecx = 0x00000121; // LAHF/SAHF, LZCNT, PREFETCHW
                    edx = 0x2C100800; // SYSCALL, NX, 1GB pages, RDTSCP, LM
                    break;

                case 0x80000002:
                case 0x80000003:
                case 0x80000004: { // Processor brand string
                    uint32_t idx = (leaf - 0x80000002) * 4;
                    eax = CPUID::kBrand[idx];
                    ebx = CPUID::kBrand[idx + 1];
                    ecx = CPUID::kBrand[idx + 2];
                    edx = CPUID::kBrand[idx + 3];
                    break;
                }

                case 0x80000007: // Invariant TSC
                    edx = 0x00000100; // Invariant TSC bit
                    break;

                case 0x80000008: // Address sizes
                    eax = 0x00003028; // 48-bit virtual, 40-bit physical
                    break;

                default:
                    // Unknown leaf: return zeros (standard behavior)
                    break;
            }

            m_state.SetReg32(GPR::RAX, eax);
            m_state.SetReg32(GPR::RBX, ebx);
            m_state.SetReg32(GPR::RCX, ecx);
            m_state.SetReg32(GPR::RDX, edx);
            return ErrorCode::Success;
        }

        // === RDTSC (0F 31) ===
        if (inst.opcode == 0x31) {
            m_state.SetReg32(GPR::RAX, static_cast<uint32_t>(m_state.tsc));
            m_state.SetReg32(GPR::RDX, static_cast<uint32_t>(m_state.tsc >> 32));
            return ErrorCode::Success;
        }

        // === RDTSCP (0F 01 F9) — returns TSC + processor ID ===
        if (inst.opcode == 0x01 && inst.modrm == 0xF9) {
            m_state.SetReg32(GPR::RAX, static_cast<uint32_t>(m_state.tsc));
            m_state.SetReg32(GPR::RDX, static_cast<uint32_t>(m_state.tsc >> 32));
            m_state.SetReg32(GPR::RCX, 0); // IA32_TSC_AUX = 0 (processor 0)
            return ErrorCode::Success;
        }

        // === XGETBV (0F 01 D0) — get extended control register ===
        if (inst.opcode == 0x01 && inst.modrm == 0xD0) {
            uint32_t xcr = m_state.GetReg32(GPR::RCX);
            if (xcr == 0) {
                // XCR0: report x87 + SSE + AVX enabled
                // Bit 0 = x87, Bit 1 = SSE, Bit 2 = AVX
                uint64_t xcr0 = 0x07;
                m_state.SetReg32(GPR::RAX, static_cast<uint32_t>(xcr0));
                m_state.SetReg32(GPR::RDX, static_cast<uint32_t>(xcr0 >> 32));
            } else {
                // Unknown XCR — return zeros
                m_state.SetReg32(GPR::RAX, 0);
                m_state.SetReg32(GPR::RDX, 0);
            }
            return ErrorCode::Success;
        }

        // === SYSCALL (0F 05) — invoke syscall callback ===
        if (inst.opcode == 0x05) {
            if (m_syscallCallback) {
                if (m_syscallCallback(m_state, mem)) {
                    return ErrorCode::Success;
                }
            }
            return ErrorCode::InvalidSystemCall;
        }

        // === UD2 (0F 0B) — intentional undefined instruction ===
        if (inst.opcode == 0x0B) {
            return ErrorCode::InvalidOpcode;
        }

        // === WRMSR (0F 30) — write MSR (stub: log and ignore) ===
        if (inst.opcode == 0x30) {
            // In a sandboxed emulator, we silently consume MSR writes.
            // ECX = MSR index, EDX:EAX = value to write.
            // No state change — the emulator does not model real MSRs.
            return ErrorCode::Success;
        }

        // === RDMSR (0F 32) — read MSR (return fake values) ===
        if (inst.opcode == 0x32) {
            uint32_t msrIndex = m_state.GetReg32(GPR::RCX);
            uint32_t eax = 0, edx = 0;

            switch (msrIndex) {
                case 0xC0000103: // IA32_TSC_AUX — processor ID for RDTSCP
                    eax = 0;
                    edx = 0;
                    break;
                case 0x1B: // IA32_APIC_BASE
                    eax = 0xFEE00900; // Default APIC base, BSP flag set
                    edx = 0;
                    break;
                case 0x174: // IA32_SYSENTER_CS
                    eax = 0x0023;
                    break;
                case 0x175: // IA32_SYSENTER_ESP
                case 0x176: // IA32_SYSENTER_EIP
                    break; // Return zeros
                case 0xC0000080: // IA32_EFER
                    eax = 0x00000D01; // LME, LMA, SCE, NXE
                    break;
                case 0xC0000081: // IA32_STAR (SYSCALL selectors)
                    eax = 0;
                    edx = 0x00230010; // SYSRET CS/SS = 0x23/0x2B, SYSCALL CS/SS = 0x10/0x18
                    break;
                case 0xC0000082: // IA32_LSTAR (SYSCALL target RIP)
                    break; // Return zero — emulator handles SYSCALL via callback
                default:
                    // Unknown MSR — return zeros (safe default)
                    break;
            }

            m_state.SetReg32(GPR::RAX, eax);
            m_state.SetReg32(GPR::RDX, edx);
            return ErrorCode::Success;
        }

        // === MFENCE (0F AE /6), LFENCE (0F AE /5), SFENCE (0F AE /7) ===
        // === CLFLUSH (0F AE /7 with memory operand) ===
        // === XSAVE/XRSTOR/XSAVEOPT (0F AE /4,/5,/6 with memory operand) ===
        if (inst.opcode == 0xAE) {
            uint8_t ext = inst.opcodeExt;
            uint8_t mod = (inst.modrm >> 6) & 3;

            // LFENCE (mod=3, ext=5) — no-op in emulator
            if (ext == 5 && mod == 3) return ErrorCode::Success;

            // MFENCE (mod=3, ext=6) — no-op in emulator
            if (ext == 6 && mod == 3) return ErrorCode::Success;

            // SFENCE (mod=3, ext=7) — no-op in emulator
            if (ext == 7 && mod == 3) return ErrorCode::Success;

            // CLFLUSH (ext=7, memory operand) — no-op in emulator
            if (ext == 7 && mod != 3) {
                return HasMemoryOperand0(inst) ? ErrorCode::Success : ErrorCode::InvalidOperandSize;
            }

            // XSAVE (0F AE /4, memory operand)
            // XSAVEOPT (0F AE /6, memory operand) — same format, hint optimization only
            if ((ext == 4 || ext == 6) && mod != 3) {
                if (!HasMemoryOperand0(inst)) return ErrorCode::InvalidOperandSize;
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);

                // EDX:EAX = requested-feature bitmap (RFBM)
                uint64_t rfbm = (static_cast<uint64_t>(m_state.GetReg32(GPR::RDX)) << 32)
                              | m_state.GetReg32(GPR::RAX);
                rfbm &= kSupportedXStateMask;

                // Component 0: x87 FPU state (bytes 0-159 of legacy region)
                if (rfbm & 1) {
                    // FXSAVE-format legacy area: FCW(2) + FSW(2) + FTW(1) + reserved(1)
                    // + FOP(2) + FIP(8) + FDP(8) + MXCSR(4) + MXCSR_MASK(4) = 32 bytes header
                    // Then 8 × 16-byte FPU registers = 128 bytes → total 160 bytes at offset 0
                    uint8_t legacyHdr[32]{};
                    // FCW at [0..1]
                    std::memcpy(legacyHdr, &m_state.fpuControl, 2);
                    // FSW at [2..3]
                    std::memcpy(legacyHdr + 2, &m_state.fpuStatus, 2);
                    // Abridged FTW at [4] — convert full tag word to abridged form
                    uint8_t abridgedTag = 0;
                    for (int i = 0; i < 8; ++i) {
                        if (((m_state.fpuTag >> (i * 2)) & 3) != 3)
                            abridgedTag |= (1 << i);
                    }
                    legacyHdr[4] = abridgedTag;
                    // FOP at [6..7]
                    std::memcpy(legacyHdr + 6, &m_state.fpuOpcode, 2);
                    // FIP at [8..15]
                    std::memcpy(legacyHdr + 8, &m_state.fpuIP, 8);
                    // FDP at [16..23]
                    std::memcpy(legacyHdr + 16, &m_state.fpuDP, 8);
                    // MXCSR at [24..27]
                    std::memcpy(legacyHdr + 24, &m_state.mxcsr, 4);
                    // MXCSR_MASK at [28..31]
                    uint32_t mxcsrMask = 0x0000FFBF;
                    std::memcpy(legacyHdr + 28, &mxcsrMask, 4);

                    auto err = WriteGuestOffset(mem, addr, 0, legacyHdr, 32);
                    if (err != ErrorCode::Success) return err;

                    // x87 data registers: 8 × 16 bytes at offset 32 (within legacy 160-byte area)
                    for (int i = 0; i < 8; ++i) {
                        uint8_t fpuBuf[16]{};
                        auto ld = m_state.fpuStack[i].value;
                        std::memcpy(fpuBuf, &ld, sizeof(ld) <= 16 ? sizeof(ld) : 16);
                        err = WriteGuestOffset(mem, addr, 32 + static_cast<uint32_t>(i) * 16, fpuBuf, 16);
                        if (err != ErrorCode::Success) return err;
                    }
                }

                // Component 1: SSE state (XMM registers at bytes 160-415 of legacy region)
                if (rfbm & 2) {
                    for (uint8_t i = 0; i < 16; ++i) {
                        auto err = WriteGuestOffset(mem, addr, 160 + static_cast<uint32_t>(i) * 16,
                                                    m_state.xmm[i].u8, 16);
                        if (err != ErrorCode::Success) return err;
                    }
                }

                // XSAVE header (bytes 512-575)
                uint8_t header[64]{};
                // XSTATE_BV at [512..519] = which components are saved
                uint64_t xstateBv = rfbm & kSupportedXStateMask;
                std::memcpy(header, &xstateBv, 8);
                auto err = WriteGuestOffset(mem, addr, 512, header, 64);
                if (err != ErrorCode::Success) return err;

                // Component 2: AVX upper YMM (bytes 576-831, 16 × 16 bytes)
                if (rfbm & 4) {
                    for (uint8_t i = 0; i < 16; ++i) {
                        err = WriteGuestOffset(mem, addr, 576 + static_cast<uint32_t>(i) * 16,
                                               m_state.ymmHigh[i].u8, 16);
                        if (err != ErrorCode::Success) return err;
                    }
                }

                return ErrorCode::Success;
            }

            // XRSTOR (0F AE /5, memory operand)
            if (ext == 5 && mod != 3) {
                if (!HasMemoryOperand0(inst)) return ErrorCode::InvalidOperandSize;
                GuestAddress addr = CalculateEffectiveAddress(inst.Op(0), inst);

                // EDX:EAX = requested-feature bitmap (RFBM)
                uint64_t rfbm = (static_cast<uint64_t>(m_state.GetReg32(GPR::RDX)) << 32)
                              | m_state.GetReg32(GPR::RAX);
                rfbm &= kSupportedXStateMask;

                // Read XSAVE header to determine which components are present
                uint8_t header[64]{};
                auto err = ReadGuestOffset(mem, addr, 512, header, 64);
                if (err != ErrorCode::Success) return err;
                uint64_t xstateBv = 0;
                std::memcpy(&xstateBv, header, 8);
                xstateBv &= kSupportedXStateMask;

                // Only restore components in both RFBM and XSTATE_BV
                uint64_t restoreMask = rfbm & xstateBv;

                // Component 0: x87 FPU state
                if (restoreMask & 1) {
                    uint8_t legacyHdr[32]{};
                    err = ReadGuestOffset(mem, addr, 0, legacyHdr, 32);
                    if (err != ErrorCode::Success) return err;

                    std::memcpy(&m_state.fpuControl, legacyHdr, 2);
                    std::memcpy(&m_state.fpuStatus, legacyHdr + 2, 2);
                    uint8_t abridgedTag = legacyHdr[4];
                    m_state.fpuTag = 0;
                    for (int i = 0; i < 8; ++i) {
                        if (!(abridgedTag & (1 << i)))
                            m_state.fpuTag |= (3 << (i * 2)); // empty
                    }
                    std::memcpy(&m_state.fpuOpcode, legacyHdr + 6, 2);
                    std::memcpy(&m_state.fpuIP, legacyHdr + 8, 8);
                    std::memcpy(&m_state.fpuDP, legacyHdr + 16, 8);
                    std::memcpy(&m_state.mxcsr, legacyHdr + 24, 4);
                    m_state.mxcsr &= kMxcsrWritableMask;

                    for (int i = 0; i < 8; ++i) {
                        uint8_t fpuBuf[16]{};
                        err = ReadGuestOffset(mem, addr, 32 + static_cast<uint32_t>(i) * 16, fpuBuf, 16);
                        if (err != ErrorCode::Success) return err;
                        std::memcpy(&m_state.fpuStack[i].value, fpuBuf,
                                    sizeof(m_state.fpuStack[i].value) <= 16
                                        ? sizeof(m_state.fpuStack[i].value) : 16);
                    }
                } else if (rfbm & 1) {
                    // Component in RFBM but not in XSTATE_BV: restore to init state
                    m_state.fpuControl = 0x037F;
                    m_state.fpuStatus = 0;
                    m_state.fpuTag = 0xFFFF;
                    for (int i = 0; i < 8; ++i) m_state.fpuStack[i].value = 0.0L;
                }

                // Component 1: SSE state
                if (restoreMask & 2) {
                    for (uint8_t i = 0; i < 16; ++i) {
                        err = ReadGuestOffset(mem, addr, 160 + static_cast<uint32_t>(i) * 16,
                                              m_state.xmm[i].u8, 16);
                        if (err != ErrorCode::Success) return err;
                    }
                } else if (rfbm & 2) {
                    for (uint8_t i = 0; i < 16; ++i) m_state.xmm[i].Clear();
                    m_state.mxcsr = 0x1F80;
                }

                // Component 2: AVX upper YMM
                if (restoreMask & 4) {
                    for (uint8_t i = 0; i < 16; ++i) {
                        err = ReadGuestOffset(mem, addr, 576 + static_cast<uint32_t>(i) * 16,
                                              m_state.ymmHigh[i].u8, 16);
                        if (err != ErrorCode::Success) return err;
                    }
                } else if (rfbm & 4) {
                    for (uint8_t i = 0; i < 16; ++i) m_state.ymmHigh[i].Clear();
                }

                return ErrorCode::Success;
            }

            return ErrorCode::UnimplementedOpcode;
        }

        // === PREFETCH hints (0F 18 /0-3) — no-op in emulator ===
        if (inst.opcode == 0x18) {
            uint8_t ext = inst.opcodeExt;
            uint8_t mod = (inst.modrm >> 6) & 3;
            if (ext <= 3) return (mod != 3 && HasMemoryOperand0(inst)) ? ErrorCode::Success : ErrorCode::InvalidOperandSize;
            return ErrorCode::UnimplementedOpcode;
        }
    }

    // === OneByte map system instructions ===
    if (inst.opcodeMap == OpcodeMap::OneByte) {
        // === PAUSE (F3 90) — spin-loop hint, advance TSC ===
        if (inst.opcode == 0x90 && inst.prefixes.hasRep) {
            m_state.tsc += m_state.tscIncrement * 40; // ~40x normal cost
            return ErrorCode::Success;
        }

        // === INT n (CD xx) — software interrupt ===
        if (inst.opcode == 0xCD) {
            uint8_t vector = static_cast<uint8_t>(inst.immediate & 0xFF);

            // INT 0x2E — Windows fast syscall (legacy NT path)
            if (vector == 0x2E) {
                if (m_syscallCallback) {
                    if (m_syscallCallback(m_state, mem)) {
                        return ErrorCode::Success;
                    }
                }
                return ErrorCode::InvalidSystemCall;
            }

            // INT 3 (CD 03) — breakpoint (alternate encoding)
            if (vector == 3) {
                if (m_interruptCallback) {
                    if (m_interruptCallback(m_state, mem, 3)) {
                        return ErrorCode::Success;
                    }
                }
                return ErrorCode::InvalidSystemCall;
            }

            // General interrupt — invoke callback
            if (m_interruptCallback) {
                if (m_interruptCallback(m_state, mem, vector)) {
                    return ErrorCode::Success;
                }
            }
            return ErrorCode::InvalidSystemCall;
        }
    }

    return ErrorCode::UnimplementedOpcode;
}

// ============================================================================
// RDRAND / RDSEED  (0F C7 /6 and /7 with mod=3)
// ============================================================================
// Returns a pseudorandom value in the destination register and sets CF=1
// to indicate success. We use a 64-bit xorshift PRNG seeded from the
// emulated TSC to avoid pulling in <random> and to remain deterministic
// within a single emulation session (important for reproducible analysis).

ErrorCode CPU::ExecuteRdRandSeed(const DecodedInstruction& inst, VirtualMemory& /*mem*/) noexcept {
    // Validate opcode
    if (inst.opcodeMap != OpcodeMap::TwoByte || inst.opcode != 0xC7)
        return ErrorCode::UnimplementedOpcode;

    uint8_t ext = inst.opcodeExt;
    uint8_t mod = (inst.modrm >> 6) & 3;

    // RDRAND = /6 mod=3, RDSEED = /7 mod=3
    if ((ext != 6 && ext != 7) || mod != 3)
        return ErrorCode::UnimplementedOpcode;

    uint64_t seed = m_state.tsc ^
                    (m_state.instructionCount * 0x9E3779B97F4A7C15ULL) ^
                    (static_cast<uint64_t>(ext) << 56) ^
                    0x5DEECE66DULL;
    if (seed == 0) seed = 1;
    uint64_t value = DeterministicEntropySample(seed);

    // Destination is the register encoded in ModRM.rm (bits 2:0 + REX.B)
    uint8_t regIdx = (inst.modrm & 7) | (inst.prefixes.rexB ? 8 : 0);
    auto reg = static_cast<GPR>(regIdx);

    switch (inst.operandSize) {
        case OperandSize::Size16:
            m_state.SetReg16(reg, static_cast<uint16_t>(value));
            break;
        case OperandSize::Size32:
            m_state.SetReg32(reg, static_cast<uint32_t>(value));
            break;
        case OperandSize::Size64:
            m_state.SetReg64(reg, value);
            break;
        default:
            return ErrorCode::InvalidOperandSize;
    }

    // CF=1 indicates success (hardware had enough entropy).
    // In emulation we always succeed. OF=SF=ZF=AF=PF=0 per spec.
    m_state.eflags.SetCF(true);
    m_state.eflags.SetOF(false);
    m_state.eflags.SetSF(false);
    m_state.eflags.SetZF(false);
    m_state.eflags.SetPF(false);

    return ErrorCode::Success;
}

} // namespace Phantom
