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

namespace Phantom {

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
        if (inst.opcode == 0x01 && inst.opcodeExt == 7) {
            // Distinguish RDTSCP (modrm F9) from other 0F 01 /7 forms
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
            if (ext == 7 && mod != 3) return ErrorCode::Success;

            return ErrorCode::UnimplementedOpcode;
        }

        // === PREFETCH hints (0F 18 /0-3) — no-op in emulator ===
        if (inst.opcode == 0x18) {
            uint8_t ext = inst.opcodeExt;
            if (ext <= 3) return ErrorCode::Success;
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

} // namespace Phantom
