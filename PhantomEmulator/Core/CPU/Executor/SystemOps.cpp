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

ErrorCode CPU::ExecuteSystem(const DecodedInstruction& inst, VirtualMemory&) noexcept {
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
            m_state.SetReg32(GPR::RAX, static_cast<uint32_t>(m_state.tsc));
            m_state.SetReg32(GPR::RDX, static_cast<uint32_t>(m_state.tsc >> 32));
            m_state.SetReg32(GPR::RCX, 0); // IA32_TSC_AUX = 0 (processor 0)
            return ErrorCode::Success;
        }
    }

    return ErrorCode::UnimplementedOpcode;
}

} // namespace Phantom
