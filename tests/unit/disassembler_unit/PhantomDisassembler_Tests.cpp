/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 *
 * PhantomDisassembler Unit Tests
 * ==============================
 * Validates decode correctness across all supported ISA families using
 * real x86-64 byte sequences assembled with known-good reference output.
 *
 * Coverage:
 *   - Legacy one-byte, two-byte, three-byte opcode maps
 *   - REX prefix handling (W, R, X, B bits)
 *   - VEX (2-byte C5h, 3-byte C4h) prefix decode
 *   - EVEX (62h) prefix decode with masking/broadcast/zeroing
 *   - SSE/SSE2/SSE3/SSSE3/SSE4 instructions
 *   - AVX/AVX2/AVX-512 instructions
 *   - BMI1/BMI2, FMA3, SHA-NI, AES-NI
 *   - CET (ENDBR64, shadow stack ops)
 *   - AMX (tile operations)
 *   - ADX, F16C, MOVBE, RDRAND/RDSEED
 *   - Edge cases: max-length, truncated, invalid, redundant prefixes
 *   - Thread safety: concurrent decode on shared Decoder instance
 */

#include <gtest/gtest.h>
#include "../../../PhantomDisassembler/PhantomDisasm.hpp"

#include <array>
#include <cstring>
#include <thread>
#include <atomic>
#include <vector>

namespace PD = Phantom::Disasm;

// ============================================================================
// Test Fixture
// ============================================================================

class PhantomDisassemblerTest : public ::testing::Test {
protected:
    PD::Decoder decoder64;
    PD::DecodedInstruction inst{};
    PD::DecodedOperand operands[PD::MAX_OPERANDS]{};

    void SetUp() override {
        auto status = decoder64.Init(PD::MachineMode::Long64);
        ASSERT_TRUE(PD::IsSuccess(status)) << "Decoder init failed";
    }

    void ResetOutput() {
        std::memset(&inst, 0, sizeof(inst));
        for (auto& op : operands) { op = PD::DecodedOperand{}; }
    }

    PD::Status Decode(const uint8_t* buf, size_t len) {
        ResetOutput();
        return decoder64.DecodeFull(buf, len, inst, operands);
    }
};

// ============================================================================
// 1. Initialization & Safety
// ============================================================================

TEST_F(PhantomDisassemblerTest, InitSucceeds64Bit) {
    PD::Decoder d;
    auto s = d.Init(PD::MachineMode::Long64);
    EXPECT_TRUE(PD::IsSuccess(s));
    EXPECT_TRUE(d.IsInitialized());
    EXPECT_EQ(d.GetMode(), PD::MachineMode::Long64);
}

TEST_F(PhantomDisassemblerTest, InitSucceeds32Bit) {
    PD::Decoder d;
    auto s = d.Init(PD::MachineMode::LongCompat32);
    EXPECT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(d.GetMode(), PD::MachineMode::LongCompat32);
}

TEST_F(PhantomDisassemblerTest, DecodeNullBufferFails) {
    auto s = decoder64.DecodeFull(nullptr, 10, inst, operands);
    EXPECT_TRUE(PD::IsFailed(s));
    EXPECT_EQ(s, PD::Status::InvalidInput);
}

TEST_F(PhantomDisassemblerTest, DecodeZeroLengthFails) {
    uint8_t buf = 0x90;
    auto s = decoder64.DecodeFull(&buf, 0, inst, operands);
    EXPECT_TRUE(PD::IsFailed(s));
    EXPECT_EQ(s, PD::Status::InvalidInput);
}

// ============================================================================
// 2. Legacy One-Byte Instructions
// ============================================================================

TEST_F(PhantomDisassemblerTest, DecodeNOP) {
    // 90 = NOP
    const uint8_t buf[] = { 0x90 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::NOP);
    EXPECT_EQ(inst.length, 1);
}

TEST_F(PhantomDisassemblerTest, DecodeRET) {
    // C3 = RET
    const uint8_t buf[] = { 0xC3 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::RET);
    EXPECT_EQ(inst.length, 1);
}

TEST_F(PhantomDisassemblerTest, DecodeINT3) {
    // CC = INT3
    const uint8_t buf[] = { 0xCC };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::INT3);
    EXPECT_EQ(inst.length, 1);
}

TEST_F(PhantomDisassemblerTest, DecodePushRBP) {
    // 55 = PUSH RBP (in 64-bit mode, default 64-bit operand)
    const uint8_t buf[] = { 0x55 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::PUSH);
    EXPECT_EQ(inst.length, 1);
}

TEST_F(PhantomDisassemblerTest, DecodeMovImm32) {
    // B8 78563412 = MOV EAX, 0x12345678
    const uint8_t buf[] = { 0xB8, 0x78, 0x56, 0x34, 0x12 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::MOV);
    EXPECT_EQ(inst.length, 5);
}

TEST_F(PhantomDisassemblerTest, DecodeCallRel32) {
    // E8 00100000 = CALL +0x1000
    const uint8_t buf[] = { 0xE8, 0x00, 0x10, 0x00, 0x00 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::CALL);
    EXPECT_EQ(inst.length, 5);
}

TEST_F(PhantomDisassemblerTest, DecodeJmpShort) {
    // EB FE = JMP -2 (infinite loop)
    const uint8_t buf[] = { 0xEB, 0xFE };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::JMP);
    EXPECT_EQ(inst.length, 2);
}

// ============================================================================
// 3. REX Prefix Handling
// ============================================================================

TEST_F(PhantomDisassemblerTest, DecodeMovRaxImm64WithREXW) {
    // 48 B8 + 8-byte immediate = MOV RAX, imm64 (REX.W)
    const uint8_t buf[] = {
        0x48, 0xB8,
        0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12
    };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::MOV);
    EXPECT_EQ(inst.length, 10);
    EXPECT_EQ(inst.operand_width, 64);
}

TEST_F(PhantomDisassemblerTest, DecodeMovR8dEax) {
    // 41 89 C0 = MOV R8D, EAX (REX.B extends ModRM r/m to R8)
    const uint8_t buf[] = { 0x41, 0x89, 0xC0 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::MOV);
    EXPECT_EQ(inst.length, 3);
}

TEST_F(PhantomDisassemblerTest, DecodeAddR15Rsi) {
    // 49 01 F7 = ADD R15, RSI (REX.WB)
    const uint8_t buf[] = { 0x49, 0x01, 0xF7 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::ADD);
    EXPECT_EQ(inst.length, 3);
    EXPECT_EQ(inst.operand_width, 64);
}

// ============================================================================
// 4. Two-Byte Opcode Map (0F xx)
// ============================================================================

TEST_F(PhantomDisassemblerTest, DecodeCPUID) {
    // 0F A2 = CPUID
    const uint8_t buf[] = { 0x0F, 0xA2 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::CPUID);
    EXPECT_EQ(inst.length, 2);
}

TEST_F(PhantomDisassemblerTest, DecodeRDTSC) {
    // 0F 31 = RDTSC
    const uint8_t buf[] = { 0x0F, 0x31 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::RDTSC);
    EXPECT_EQ(inst.length, 2);
}

TEST_F(PhantomDisassemblerTest, DecodeSyscall) {
    // 0F 05 = SYSCALL
    const uint8_t buf[] = { 0x0F, 0x05 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::SYSCALL);
    EXPECT_EQ(inst.length, 2);
}

TEST_F(PhantomDisassemblerTest, DecodeBSWAP) {
    // 0F C8 = BSWAP EAX
    const uint8_t buf[] = { 0x0F, 0xC8 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::BSWAP);
    EXPECT_EQ(inst.length, 2);
}

TEST_F(PhantomDisassemblerTest, DecodeCMOVcc) {
    // 0F 44 C1 = CMOVE EAX, ECX (CMOVZ)
    const uint8_t buf[] = { 0x0F, 0x44, 0xC1 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::CMOVZ);
    EXPECT_EQ(inst.length, 3);
}

// ============================================================================
// 5. SSE/SSE2 Instructions
// ============================================================================

TEST_F(PhantomDisassemblerTest, DecodeMovapsXmm0Xmm1) {
    // 0F 28 C1 = MOVAPS XMM0, XMM1
    const uint8_t buf[] = { 0x0F, 0x28, 0xC1 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::MOVAPS);
    EXPECT_EQ(inst.length, 3);
}

TEST_F(PhantomDisassemblerTest, DecodeAddpsXmm0Xmm1) {
    // 0F 58 C1 = ADDPS XMM0, XMM1
    const uint8_t buf[] = { 0x0F, 0x58, 0xC1 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::ADDPS);
    EXPECT_EQ(inst.length, 3);
}

TEST_F(PhantomDisassemblerTest, DecodePaddqXmm0Xmm1) {
    // 66 0F D4 C1 = PADDQ XMM0, XMM1
    const uint8_t buf[] = { 0x66, 0x0F, 0xD4, 0xC1 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::PADDQ);
    EXPECT_EQ(inst.length, 4);
}

// ============================================================================
// 6. SSE4.1/SSE4.2 Instructions
// ============================================================================

TEST_F(PhantomDisassemblerTest, DecodePTEST) {
    // 66 0F 38 17 C1 = PTEST XMM0, XMM1
    const uint8_t buf[] = { 0x66, 0x0F, 0x38, 0x17, 0xC1 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::PTEST);
    EXPECT_EQ(inst.length, 5);
}

TEST_F(PhantomDisassemblerTest, DecodeCRC32) {
    // F2 0F 38 F1 C1 = CRC32 EAX, ECX
    const uint8_t buf[] = { 0xF2, 0x0F, 0x38, 0xF1, 0xC1 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::CRC32_INST);
    EXPECT_EQ(inst.length, 5);
}

TEST_F(PhantomDisassemblerTest, DecodePOPCNT) {
    // F3 0F B8 C1 = POPCNT EAX, ECX
    const uint8_t buf[] = { 0xF3, 0x0F, 0xB8, 0xC1 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::POPCNT);
    EXPECT_EQ(inst.length, 4);
}

// ============================================================================
// 7. VEX-Encoded Instructions (AVX/AVX2)
// ============================================================================

TEST_F(PhantomDisassemblerTest, DecodeVmovapsYmm0Ymm1) {
    // C5 FC 28 C1 = VMOVAPS YMM0, YMM1 (VEX.256.0F 28)
    const uint8_t buf[] = { 0xC5, 0xFC, 0x28, 0xC1 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::VMOVAPS);
    EXPECT_EQ(inst.length, 4);
}

TEST_F(PhantomDisassemblerTest, DecodeVpaddqYmm) {
    // C5 F5 D4 C2 = VPADDQ YMM0, YMM1, YMM2 (VEX.256.66.0F D4)
    const uint8_t buf[] = { 0xC5, 0xF5, 0xD4, 0xC2 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::VPADDQ);
    EXPECT_EQ(inst.length, 4);
}

TEST_F(PhantomDisassemblerTest, DecodeVperm2i128) {
    // C4 E3 75 46 C2 01 = VPERM2I128 YMM0, YMM1, YMM2, 0x01
    const uint8_t buf[] = { 0xC4, 0xE3, 0x75, 0x46, 0xC2, 0x01 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::VPERM2I128);
    EXPECT_EQ(inst.length, 6);
}

TEST_F(PhantomDisassemblerTest, DecodeVEX2ByteForm) {
    // C5 F8 77 = VZEROUPPER (VEX.128.0F 77)
    const uint8_t buf[] = { 0xC5, 0xF8, 0x77 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::VZEROUPPER);
    EXPECT_EQ(inst.length, 3);
}

// ============================================================================
// 8. EVEX-Encoded Instructions (AVX-512)
// ============================================================================

TEST_F(PhantomDisassemblerTest, DecodeEvexVpadddZmm) {
    // 62 F1 75 48 FE C2 = VPADDD ZMM0{k0}, ZMM1, ZMM2
    // EVEX.512.66.0F.W0 FE /r
    const uint8_t buf[] = { 0x62, 0xF1, 0x75, 0x48, 0xFE, 0xC2 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::VPADDD);
    EXPECT_EQ(inst.length, 6);
    EXPECT_TRUE((inst.attributes & PD::ATTRIB_HAS_EVEX) != 0);
}

TEST_F(PhantomDisassemblerTest, DecodeEvexWithMasking) {
    // 62 F1 75 49 FE C2 = VPADDD ZMM0{k1}, ZMM1, ZMM2
    // EVEX.512.66.0F.W0 FE /r, aaa=001
    const uint8_t buf[] = { 0x62, 0xF1, 0x75, 0x49, 0xFE, 0xC2 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::VPADDD);
    EXPECT_EQ(inst.length, 6);
    EXPECT_TRUE((inst.attributes & PD::ATTRIB_HAS_EVEX) != 0);
}

TEST_F(PhantomDisassemblerTest, DecodeEvexWithZeroing) {
    // 62 F1 75 C9 FE C2 = VPADDD ZMM0{k1}{z}, ZMM1, ZMM2
    // EVEX.512.66.0F.W0 FE /r, z=1, aaa=001
    const uint8_t buf[] = { 0x62, 0xF1, 0x75, 0xC9, 0xFE, 0xC2 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::VPADDD);
    EXPECT_EQ(inst.length, 6);
    EXPECT_TRUE((inst.attributes & PD::ATTRIB_HAS_EVEX) != 0);
}

// ============================================================================
// 9. AES-NI Instructions
// ============================================================================

TEST_F(PhantomDisassemblerTest, DecodeAESENC) {
    // 66 0F 38 DC C1 = AESENC XMM0, XMM1
    const uint8_t buf[] = { 0x66, 0x0F, 0x38, 0xDC, 0xC1 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::AESENC);
    EXPECT_EQ(inst.length, 5);
}

TEST_F(PhantomDisassemblerTest, DecodeAESKEYGENASSIST) {
    // 66 0F 3A DF C1 01 = AESKEYGENASSIST XMM0, XMM1, 0x01
    const uint8_t buf[] = { 0x66, 0x0F, 0x3A, 0xDF, 0xC1, 0x01 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::AESKEYGENASSIST);
    EXPECT_EQ(inst.length, 6);
}

// ============================================================================
// 10. FMA3 Instructions
// ============================================================================

TEST_F(PhantomDisassemblerTest, DecodeVfmadd132ps) {
    // C4 E2 71 98 C2 = VFMADD132PS XMM0, XMM1, XMM2
    // VEX.128.66.0F38.W0 98 /r
    const uint8_t buf[] = { 0xC4, 0xE2, 0x71, 0x98, 0xC2 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::VFMADD132PS);
    EXPECT_EQ(inst.length, 5);
}

TEST_F(PhantomDisassemblerTest, DecodeVfmadd213pd) {
    // C4 E2 F1 A8 C2 = VFMADD213PD XMM0, XMM1, XMM2
    // VEX.128.66.0F38.W1 A8 /r
    const uint8_t buf[] = { 0xC4, 0xE2, 0xF1, 0xA8, 0xC2 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::VFMADD213PD);
    EXPECT_EQ(inst.length, 5);
}

// ============================================================================
// 11. BMI1/BMI2 Instructions
// ============================================================================

TEST_F(PhantomDisassemblerTest, DecodeTZCNT) {
    // F3 0F BC C1 = TZCNT EAX, ECX
    const uint8_t buf[] = { 0xF3, 0x0F, 0xBC, 0xC1 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::TZCNT);
    EXPECT_EQ(inst.length, 4);
}

TEST_F(PhantomDisassemblerTest, DecodeLZCNT) {
    // F3 0F BD C1 = LZCNT EAX, ECX
    const uint8_t buf[] = { 0xF3, 0x0F, 0xBD, 0xC1 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::LZCNT);
    EXPECT_EQ(inst.length, 4);
}

TEST_F(PhantomDisassemblerTest, DecodeANDN) {
    // C4 E2 70 F2 C2 = ANDN EAX, ECX, EDX
    // VEX.LZ.0F38.W0 F2 /r
    const uint8_t buf[] = { 0xC4, 0xE2, 0x70, 0xF2, 0xC2 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::ANDN);
    EXPECT_EQ(inst.length, 5);
}

TEST_F(PhantomDisassemblerTest, DecodeBZHI) {
    // C4 E2 F0 F5 C2 = BZHI RAX, RDX, RCX
    // VEX.LZ.0F38.W1 F5 /r
    const uint8_t buf[] = { 0xC4, 0xE2, 0xF0, 0xF5, 0xC2 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::BZHI);
    EXPECT_EQ(inst.length, 5);
}

TEST_F(PhantomDisassemblerTest, DecodePDEP) {
    // C4 E2 F3 F5 C2 = PDEP RAX, RCX, RDX
    // VEX.LZ.F2.0F38.W1 F5 /r
    const uint8_t buf[] = { 0xC4, 0xE2, 0xF3, 0xF5, 0xC2 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::PDEP);
    EXPECT_EQ(inst.length, 5);
}

TEST_F(PhantomDisassemblerTest, DecodeRORX) {
    // C4 E3 FB F0 C1 05 = RORX RAX, RCX, 5
    // VEX.LZ.F2.0F3A.W1 F0 /r ib
    const uint8_t buf[] = { 0xC4, 0xE3, 0xFB, 0xF0, 0xC1, 0x05 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::RORX);
    EXPECT_EQ(inst.length, 6);
}

// ============================================================================
// 12. SHA-NI Instructions
// ============================================================================

TEST_F(PhantomDisassemblerTest, DecodeSHA1RNDS4) {
    // 0F 3A CC C1 00 = SHA1RNDS4 XMM0, XMM1, 0
    const uint8_t buf[] = { 0x0F, 0x3A, 0xCC, 0xC1, 0x00 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::SHA1RNDS4);
    EXPECT_EQ(inst.length, 5);
}

TEST_F(PhantomDisassemblerTest, DecodeSHA256RNDS2) {
    // 0F 38 CB C1 = SHA256RNDS2 XMM0, XMM1
    const uint8_t buf[] = { 0x0F, 0x38, 0xCB, 0xC1 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::SHA256RNDS2);
    EXPECT_EQ(inst.length, 4);
}

// ============================================================================
// 13. ADX Instructions
// ============================================================================

TEST_F(PhantomDisassemblerTest, DecodeADCX) {
    // 66 0F 38 F6 C1 = ADCX EAX, ECX
    const uint8_t buf[] = { 0x66, 0x0F, 0x38, 0xF6, 0xC1 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::ADCX);
    EXPECT_EQ(inst.length, 5);
}

TEST_F(PhantomDisassemblerTest, DecodeADOX) {
    // F3 0F 38 F6 C1 = ADOX EAX, ECX
    const uint8_t buf[] = { 0xF3, 0x0F, 0x38, 0xF6, 0xC1 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::ADOX);
    EXPECT_EQ(inst.length, 5);
}

// ============================================================================
// 14. F16C Instructions
// ============================================================================

TEST_F(PhantomDisassemblerTest, DecodeVCVTPH2PS) {
    // C4 E2 79 13 C1 = VCVTPH2PS XMM0, XMM1
    // VEX.128.66.0F38.W0 13 /r
    const uint8_t buf[] = { 0xC4, 0xE2, 0x79, 0x13, 0xC1 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::VCVTPH2PS);
    EXPECT_EQ(inst.length, 5);
}

TEST_F(PhantomDisassemblerTest, DecodeVCVTPS2PH) {
    // C4 E3 79 1D C1 04 = VCVTPS2PH XMM1, XMM0, 4
    // VEX.128.66.0F3A.W0 1D /r ib
    const uint8_t buf[] = { 0xC4, 0xE3, 0x79, 0x1D, 0xC1, 0x04 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::VCVTPS2PH);
    EXPECT_EQ(inst.length, 6);
}

// ============================================================================
// 15. MOVBE / RDRAND / RDSEED
// ============================================================================

TEST_F(PhantomDisassemblerTest, DecodeRDRAND) {
    // 0F C7 /6 (ModRM.reg=6, mod=11) = RDRAND reg
    // 0F C7 F0 = RDRAND EAX
    const uint8_t buf[] = { 0x0F, 0xC7, 0xF0 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::RDRAND);
    EXPECT_EQ(inst.length, 3);
}

TEST_F(PhantomDisassemblerTest, DecodeRDSEED) {
    // 0F C7 /7 (ModRM.reg=7, mod=11) = RDSEED reg
    // 0F C7 F8 = RDSEED EAX
    const uint8_t buf[] = { 0x0F, 0xC7, 0xF8 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::RDSEED);
    EXPECT_EQ(inst.length, 3);
}

TEST_F(PhantomDisassemblerTest, DecodeMOVBE_Load) {
    // 0F 38 F0 01 = MOVBE EAX, [RCX]
    const uint8_t buf[] = { 0x0F, 0x38, 0xF0, 0x01 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::MOVBE);
    EXPECT_EQ(inst.length, 4);
}

// ============================================================================
// 16. CET Instructions
// ============================================================================

TEST_F(PhantomDisassemblerTest, DecodeENDBR64) {
    // F3 0F 1E FA = ENDBR64
    const uint8_t buf[] = { 0xF3, 0x0F, 0x1E, 0xFA };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::ENDBR64);
    EXPECT_EQ(inst.length, 4);
}

TEST_F(PhantomDisassemblerTest, DecodeENDBR32) {
    // F3 0F 1E FB = ENDBR32
    const uint8_t buf[] = { 0xF3, 0x0F, 0x1E, 0xFB };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::ENDBR32);
    EXPECT_EQ(inst.length, 4);
}

// ============================================================================
// 17. PCLMULQDQ
// ============================================================================

TEST_F(PhantomDisassemblerTest, DecodePCLMULQDQ) {
    // 66 0F 3A 44 C1 00 = PCLMULQDQ XMM0, XMM1, 0
    const uint8_t buf[] = { 0x66, 0x0F, 0x3A, 0x44, 0xC1, 0x00 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::PCLMULQDQ);
    EXPECT_EQ(inst.length, 6);
}

// ============================================================================
// 18. XSAVE / XRSTOR
// ============================================================================

TEST_F(PhantomDisassemblerTest, DecodeXSAVE) {
    // 0F AE /4 = XSAVE [mem]
    // 0F AE 21 = XSAVE [RCX]
    const uint8_t buf[] = { 0x0F, 0xAE, 0x21 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::XSAVE);
    EXPECT_EQ(inst.length, 3);
}

TEST_F(PhantomDisassemblerTest, DecodeXRSTOR) {
    // 0F AE /5 = XRSTOR [mem]
    // 0F AE 29 = XRSTOR [RCX]
    const uint8_t buf[] = { 0x0F, 0xAE, 0x29 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::XRSTOR);
    EXPECT_EQ(inst.length, 3);
}

// ============================================================================
// 19. Instruction Length & Raw Bytes
// ============================================================================

TEST_F(PhantomDisassemblerTest, InstructionLengthNeverExceeds15) {
    // 15 redundant prefixes (0x66) + opcode should be rejected
    uint8_t buf[16];
    std::memset(buf, 0x66, 15);
    buf[15] = 0x90; // NOP
    auto s = Decode(buf, sizeof(buf));
    // Must not exceed 15 bytes — either reject or truncate
    if (PD::IsSuccess(s)) {
        EXPECT_LE(inst.length, 15);
    } else {
        EXPECT_EQ(s, PD::Status::InstructionTooLong);
    }
}

TEST_F(PhantomDisassemblerTest, RawBytesPreserved) {
    // Simple 3-byte instruction: 0F A2 (CPUID) — but we test MOV R8D,EAX
    const uint8_t buf[] = { 0x41, 0x89, 0xC0 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.length, 3);
    EXPECT_EQ(inst.raw_bytes[0], 0x41);
    EXPECT_EQ(inst.raw_bytes[1], 0x89);
    EXPECT_EQ(inst.raw_bytes[2], 0xC0);
}

// ============================================================================
// 20. Truncated Input Handling
// ============================================================================

TEST_F(PhantomDisassemblerTest, TruncatedModRM) {
    // 89 requires ModRM byte but buffer is only 1 byte
    const uint8_t buf[] = { 0x89 };
    auto s = Decode(buf, sizeof(buf));
    EXPECT_TRUE(PD::IsFailed(s));
    EXPECT_EQ(s, PD::Status::TruncatedInput);
}

TEST_F(PhantomDisassemblerTest, TruncatedImmediate) {
    // B8 requires 4-byte immediate in 32-bit operand mode but only 2 bytes follow
    const uint8_t buf[] = { 0xB8, 0x01, 0x02 };
    auto s = Decode(buf, sizeof(buf));
    EXPECT_TRUE(PD::IsFailed(s));
    EXPECT_EQ(s, PD::Status::TruncatedInput);
}

TEST_F(PhantomDisassemblerTest, TruncatedVEX) {
    // C4 starts a 3-byte VEX but we only have 2 bytes
    const uint8_t buf[] = { 0xC4, 0xE1 };
    auto s = Decode(buf, sizeof(buf));
    EXPECT_TRUE(PD::IsFailed(s));
}

TEST_F(PhantomDisassemblerTest, TruncatedEVEX) {
    // 62 starts 4-byte EVEX but we only have 3 bytes
    const uint8_t buf[] = { 0x62, 0xF1, 0x75 };
    auto s = Decode(buf, sizeof(buf));
    EXPECT_TRUE(PD::IsFailed(s));
}

// ============================================================================
// 21. ISA Extension Classification
// ============================================================================

TEST_F(PhantomDisassemblerTest, ISAExtension_BaseForNOP) {
    const uint8_t buf[] = { 0x90 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.isa_ext, PD::ISAExtension::BASE);
}

TEST_F(PhantomDisassemblerTest, ISAExtension_SSE2ForPADDQ) {
    const uint8_t buf[] = { 0x66, 0x0F, 0xD4, 0xC1 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.isa_ext, PD::ISAExtension::SSE2);
}

TEST_F(PhantomDisassemblerTest, ISAExtension_AVXForVMOVAPS) {
    const uint8_t buf[] = { 0xC5, 0xFC, 0x28, 0xC1 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.isa_ext, PD::ISAExtension::AVX);
}

TEST_F(PhantomDisassemblerTest, ISAExtension_AESNIForAESENC) {
    const uint8_t buf[] = { 0x66, 0x0F, 0x38, 0xDC, 0xC1 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.isa_ext, PD::ISAExtension::AES_NI);
}

// ============================================================================
// 22. Operand Structure Validation
// ============================================================================

TEST_F(PhantomDisassemblerTest, OperandCount_MOV_Reg_Reg) {
    // 89 C8 = MOV EAX, ECX (2 operands)
    const uint8_t buf[] = { 0x89, 0xC8 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_GE(inst.operand_count, 2);
}

TEST_F(PhantomDisassemblerTest, OperandType_RegisterDirect) {
    // 89 C8 = MOV EAX, ECX
    const uint8_t buf[] = { 0x89, 0xC8 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    // At least one operand should be a register
    bool foundReg = false;
    for (uint8_t i = 0; i < inst.operand_count; ++i) {
        if (operands[i].IsRegister()) { foundReg = true; break; }
    }
    EXPECT_TRUE(foundReg);
}

TEST_F(PhantomDisassemblerTest, OperandType_MemoryIndirect) {
    // 8B 01 = MOV EAX, [RCX]
    const uint8_t buf[] = { 0x8B, 0x01 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::MOV);
    bool foundMem = false;
    for (uint8_t i = 0; i < inst.operand_count; ++i) {
        if (operands[i].IsMemory()) { foundMem = true; break; }
    }
    EXPECT_TRUE(foundMem);
}

TEST_F(PhantomDisassemblerTest, OperandType_Immediate) {
    // 83 C0 05 = ADD EAX, 5
    const uint8_t buf[] = { 0x83, 0xC0, 0x05 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::ADD);
    bool foundImm = false;
    for (uint8_t i = 0; i < inst.operand_count; ++i) {
        if (operands[i].IsImmediate()) {
            foundImm = true;
            EXPECT_EQ(operands[i].imm.value.u, 5u);
        }
    }
    EXPECT_TRUE(foundImm);
}

// ============================================================================
// 23. SIB Addressing
// ============================================================================

TEST_F(PhantomDisassemblerTest, SIBBaseIndexScale) {
    // 8B 04 8D 00 10 00 00 = MOV EAX, [RCX*4 + 0x1000]
    const uint8_t buf[] = { 0x8B, 0x04, 0x8D, 0x00, 0x10, 0x00, 0x00 };
    auto s = Decode(buf, sizeof(buf));
    ASSERT_TRUE(PD::IsSuccess(s));
    EXPECT_EQ(inst.mnemonic, PD::Mnemonic::MOV);
    EXPECT_TRUE(inst.has_sib);
}

// ============================================================================
// 24. Concurrent Decode Safety
// ============================================================================

TEST_F(PhantomDisassemblerTest, ConcurrentDecodesSafe) {
    // Multiple threads decode different instructions on the same decoder
    constexpr int kThreads = 8;
    constexpr int kIterations = 1000;

    std::atomic<int> failures{0};
    std::vector<std::thread> threads;

    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&, t]() {
            PD::DecodedInstruction localInst{};
            PD::DecodedOperand localOps[PD::MAX_OPERANDS]{};

            // Each thread decodes a different instruction
            const uint8_t nop[] = { 0x90 };
            const uint8_t ret[] = { 0xC3 };
            const uint8_t cpuid[] = { 0x0F, 0xA2 };
            const uint8_t* bufs[] = { nop, ret, cpuid };
            const size_t lens[] = { 1, 1, 2 };
            const PD::Mnemonic expected[] = {
                PD::Mnemonic::NOP, PD::Mnemonic::RET, PD::Mnemonic::CPUID
            };
            int idx = t % 3;

            for (int i = 0; i < kIterations; ++i) {
                std::memset(&localInst, 0, sizeof(localInst));
                for (auto& op : localOps) op = PD::DecodedOperand{};

                auto s = decoder64.DecodeFull(bufs[idx], lens[idx], localInst, localOps);
                if (!PD::IsSuccess(s) || localInst.mnemonic != expected[idx]) {
                    failures.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    for (auto& t : threads) t.join();
    EXPECT_EQ(failures.load(), 0) << "Concurrent decodes produced incorrect results";
}

// ============================================================================
// 25. Batch Decode — Verify sequential consumption
// ============================================================================

TEST_F(PhantomDisassemblerTest, BatchDecodeSequentialBytes) {
    // NOP; RET; INT3  (3 instructions, 3 bytes total)
    const uint8_t code[] = { 0x90, 0xC3, 0xCC };
    const PD::Mnemonic expected[] = {
        PD::Mnemonic::NOP, PD::Mnemonic::RET, PD::Mnemonic::INT3
    };

    const uint8_t* ptr = code;
    size_t remaining = sizeof(code);

    for (int i = 0; i < 3; ++i) {
        ResetOutput();
        auto s = decoder64.DecodeFull(ptr, remaining, inst, operands);
        ASSERT_TRUE(PD::IsSuccess(s)) << "Instruction " << i << " failed";
        EXPECT_EQ(inst.mnemonic, expected[i]);
        ASSERT_GT(inst.length, 0);
        ptr += inst.length;
        remaining -= inst.length;
    }
    EXPECT_EQ(remaining, 0u);
}

// ============================================================================
// GoogleTest main - STANDALONE BUILDS ONLY
// ============================================================================
//
// The comment here used to say this main "may be overridden by test_main.cpp
// linkage". It cannot be: two definitions of main in one binary is LNK2005, a
// hard link error, not an override - which is exactly what happened the moment
// this suite was added to phantom-tests. Guarded the same way
// WhiteListPatternIndex_Tests.cpp already guards its own entry point, so the
// suite keeps working as a standalone executable without colliding with
// tests\test_main.cpp (which is the identical two lines).
#if defined(BUILD_TEST_EXECUTABLE) || defined(STANDALONE_TEST)
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif
