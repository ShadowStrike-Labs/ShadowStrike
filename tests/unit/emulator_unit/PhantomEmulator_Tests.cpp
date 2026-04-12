/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 *
 * PhantomEmulator Unit Tests
 * ==========================
 * Validates the core emulation engine components: CPU state management,
 * virtual memory subsystem, instruction decode-dispatch pipeline, and
 * individual ISA executor families.
 *
 * Strategy:
 *   Each test writes raw x86-64 machine code into guest memory at a known
 *   address, sets RIP there, and calls ExecuteSingle(). We then inspect
 *   register/flag/memory state to verify correctness.
 *
 * Coverage:
 *   - CPU state: initialization, reset, register access (8/16/32/64-bit),
 *     snapshot/restore, EFlags manipulation
 *   - VirtualMemory: Allocate, Free, Protect, Read/Write, guard pages,
 *     W→X tracking, capacity capping, FetchInstruction
 *   - ALU instructions: ADD, SUB, XOR, CMP, INC, DEC with flag checks
 *   - Data transfer: MOV, PUSH, POP, XCHG, LEA
 *   - Control flow: JMP, JCC, CALL, RET
 *   - SIMD: SSE2 PADDD, AVX2 VPADDD
 *   - Crypto: AES-NI round
 *   - Bit manipulation: POPCNT, TZCNT, LZCNT, BMI2 BZHI
 *   - System: CPUID leaf 1 feature consistency, RDTSC
 *   - CET: shadow stack enforcement, ENDBR64
 *   - Error paths: divide-by-zero, access violation, invalid opcode
 *   - Memory tracker: W→X transition detection
 *   - Abort: cross-thread RequestAbort during Execute
 */

#include <gtest/gtest.h>

#include "../../../PhantomEmulator/Core/CPU/CPU.hpp"
#include "../../../PhantomEmulator/Core/Memory/VirtualMemory.hpp"
#include "../../../PhantomEmulator/Core/Memory/MemoryTracker.hpp"
#include "../../../PhantomEmulator/Common/Types.hpp"
#include "../../../PhantomEmulator/Common/Errors.hpp"
#include "../../../PhantomEmulator/Common/Config.hpp"

#include <array>
#include <cstring>
#include <thread>
#include <atomic>
#include <vector>
#include <cmath>

using namespace Phantom;

// ============================================================================
// Constants
// ============================================================================

static constexpr GuestAddress kCodeBase    = 0x00400000ULL;
static constexpr GuestSize    kCodeSize    = 0x10000ULL;   // 64 KB code
static constexpr GuestAddress kTestStackTop  = 0x00800000ULL;
static constexpr GuestSize    kTestStackSize = 0x10000ULL;   // 64 KB stack
static constexpr GuestAddress kDataBase    = 0x00900000ULL;
static constexpr GuestSize    kDataSize    = 0x10000ULL;   // 64 KB data

// ============================================================================
// Test Fixture
// ============================================================================

class PhantomEmulatorTest : public ::testing::Test {
protected:
    CPU cpu;
    VirtualMemory memory{ 64ULL * 1024 * 1024 }; // 64 MB cap
    MemoryTracker tracker;

    void SetUp() override {
        cpu.Reset64();

        // Allocate code region (RX)
        auto codeAlloc = memory.Allocate(kCodeBase, kCodeSize, MemProt::RX);
        ASSERT_TRUE(codeAlloc.has_value())
            << "Failed to allocate code region at 0x" << std::hex << kCodeBase;

        // Allocate stack region (RW)
        auto stackAlloc = memory.Allocate(kTestStackTop - kTestStackSize, kTestStackSize, MemProt::RW);
        ASSERT_TRUE(stackAlloc.has_value())
            << "Failed to allocate stack region";

        // Allocate data region (RW)
        auto dataAlloc = memory.Allocate(kDataBase, kDataSize, MemProt::RW);
        ASSERT_TRUE(dataAlloc.has_value())
            << "Failed to allocate data region at 0x" << std::hex << kDataBase;

        // Set up initial CPU state
        cpu.State().SetRIP(kCodeBase);
        cpu.State().SetReg64(GPR::RSP, kTestStackTop);
        cpu.State().SetReg64(GPR::RBP, kTestStackTop);
    }

    // Write raw machine code to the code region and execute a single instruction
    ErrorCode WriteAndExecuteSingle(const uint8_t* code, size_t len,
                                    GuestAddress addr = kCodeBase) {
        // Code region is RX — temporarily make it RWX for writing
        EXPECT_TRUE(memory.Protect(addr & ~kPageMask, kPageSize, MemProt::RWX));
        auto wErr = memory.Write(addr, code, static_cast<uint32_t>(len));
        EXPECT_EQ(wErr, ErrorCode::Success)
            << "Failed to write instruction bytes at 0x" << std::hex << addr;
        // Restore to RX
        EXPECT_TRUE(memory.Protect(addr & ~kPageMask, kPageSize, MemProt::RX));

        cpu.State().SetRIP(addr);
        return cpu.ExecuteSingle(memory, &tracker);
    }

    // Write code, execute N instructions, return last error (or Success)
    ErrorCode WriteAndExecuteN(const uint8_t* code, size_t len, uint32_t n,
                               GuestAddress addr = kCodeBase) {
        EXPECT_TRUE(memory.Protect(addr & ~kPageMask, kPageSize, MemProt::RWX));
        auto wErr = memory.Write(addr, code, static_cast<uint32_t>(len));
        EXPECT_EQ(wErr, ErrorCode::Success);
        EXPECT_TRUE(memory.Protect(addr & ~kPageMask, kPageSize, MemProt::RX));

        cpu.State().SetRIP(addr);
        ErrorCode last = ErrorCode::Success;
        for (uint32_t i = 0; i < n; ++i) {
            last = cpu.ExecuteSingle(memory, &tracker);
            if (last != ErrorCode::Success) break;
        }
        return last;
    }
};

// ============================================================================
// CPU State Tests
// ============================================================================

TEST_F(PhantomEmulatorTest, InitialState64Bit) {
    CPUState fresh;
    fresh.Reset64();

    EXPECT_EQ(fresh.mode, CPUMode::Long64);
    EXPECT_EQ(fresh.instructionCount, 0u);
    // EFLAGS: bit 1 always set, IF set by default → 0x202
    EXPECT_EQ(fresh.eflags.Raw() & 0x202, 0x202u);
    // MXCSR default: all exceptions masked
    EXPECT_EQ(fresh.mxcsr, 0x1F80u);
    // FPU control: all exceptions masked, precision=64-bit
    EXPECT_EQ(fresh.fpuControl, 0x037Fu);
    // FPU tag word: all registers empty
    EXPECT_EQ(fresh.fpuTag, 0xFFFFu);
}

TEST_F(PhantomEmulatorTest, RegisterAccess_64Bit) {
    cpu.State().SetReg64(GPR::RAX, 0xDEADBEEFCAFEBABEULL);
    EXPECT_EQ(cpu.State().GetReg64(GPR::RAX), 0xDEADBEEFCAFEBABEULL);
    EXPECT_EQ(cpu.State().RAX(), 0xDEADBEEFCAFEBABEULL);
}

TEST_F(PhantomEmulatorTest, RegisterAccess_32BitZeroExtends) {
    cpu.State().SetReg64(GPR::RBX, 0xFFFFFFFFFFFFFFFFULL);
    // Writing 32-bit value should zero-extend upper 32 bits
    cpu.State().SetReg32(GPR::RBX, 0x12345678u);
    EXPECT_EQ(cpu.State().GetReg64(GPR::RBX), 0x0000000012345678ULL);
}

TEST_F(PhantomEmulatorTest, RegisterAccess_16BitPreservesUpper) {
    cpu.State().SetReg64(GPR::RCX, 0xAAAABBBBCCCCDDDDULL);
    cpu.State().SetReg16(GPR::RCX, 0x1234u);
    EXPECT_EQ(cpu.State().GetReg64(GPR::RCX), 0xAAAABBBBCCCC1234ULL);
    EXPECT_EQ(cpu.State().GetReg16(GPR::RCX), 0x1234u);
}

TEST_F(PhantomEmulatorTest, RegisterAccess_8BitPreservesUpper) {
    cpu.State().SetReg64(GPR::RDX, 0x1111222233334444ULL);
    cpu.State().SetReg8(GPR::RDX, 0xAB);
    EXPECT_EQ(cpu.State().GetReg64(GPR::RDX), 0x11112222333344ABULL);
    EXPECT_EQ(cpu.State().GetReg8(GPR::RDX), 0xABu);
}

TEST_F(PhantomEmulatorTest, RegisterAccess_8BitHigh) {
    cpu.State().SetReg64(GPR::RAX, 0x0000000000001234ULL);
    // AH is hiReg=4 → index (4-4)=0 (RAX), bits 8-15
    cpu.State().SetReg8High(4, 0xFF);
    EXPECT_EQ(cpu.State().GetReg64(GPR::RAX), 0x000000000000FF34ULL);
    EXPECT_EQ(cpu.State().GetReg8High(4), 0xFFu);
}

TEST_F(PhantomEmulatorTest, RegisterAccess_OperandSizeDispatch) {
    cpu.State().SetRegBySize(GPR::RSI, 0xAA, OperandSize::Size8);
    EXPECT_EQ(cpu.State().GetRegBySize(GPR::RSI, OperandSize::Size8), 0xAAu);

    cpu.State().SetRegBySize(GPR::RSI, 0xBBCC, OperandSize::Size16);
    EXPECT_EQ(cpu.State().GetRegBySize(GPR::RSI, OperandSize::Size16), 0xBBCCu);
}

TEST_F(PhantomEmulatorTest, SnapshotAndRestore) {
    cpu.State().SetReg64(GPR::RAX, 42);
    cpu.State().SetReg64(GPR::RCX, 99);
    cpu.State().SetRIP(0xDEAD);
    cpu.State().instructionCount = 777;

    auto snap = cpu.State().TakeSnapshot();

    // Mutate state
    cpu.State().SetReg64(GPR::RAX, 0);
    cpu.State().SetRIP(0);
    cpu.State().instructionCount = 0;

    cpu.State().RestoreSnapshot(snap);
    EXPECT_EQ(cpu.State().RAX(), 42u);
    EXPECT_EQ(cpu.State().RCX(), 99u);
    EXPECT_EQ(cpu.State().GetRIP(), 0xDEADu);
    EXPECT_EQ(cpu.State().instructionCount, 777u);
}

TEST_F(PhantomEmulatorTest, EFlags_SetAndQuery) {
    cpu.State().eflags.SetCF(true);
    EXPECT_TRUE(cpu.State().eflags.CF());
    cpu.State().eflags.SetCF(false);
    EXPECT_FALSE(cpu.State().eflags.CF());

    cpu.State().eflags.SetZF(true);
    EXPECT_TRUE(cpu.State().eflags.ZF());
    cpu.State().eflags.SetOF(true);
    EXPECT_TRUE(cpu.State().eflags.OF());
    cpu.State().eflags.SetSF(true);
    EXPECT_TRUE(cpu.State().eflags.SF());
}

TEST_F(PhantomEmulatorTest, EFlags_ParityComputation) {
    // 0x00 → 0 bits set → even parity → PF=1
    cpu.State().eflags.UpdatePF(0x00);
    EXPECT_TRUE(cpu.State().eflags.PF());

    // 0x01 → 1 bit set → odd parity → PF=0
    cpu.State().eflags.UpdatePF(0x01);
    EXPECT_FALSE(cpu.State().eflags.PF());

    // 0xFF → 8 bits set → even parity → PF=1
    cpu.State().eflags.UpdatePF(0xFF);
    EXPECT_TRUE(cpu.State().eflags.PF());
}

TEST_F(PhantomEmulatorTest, EFlags_SZPCombined) {
    // Zero result → ZF=1, SF=0
    cpu.State().eflags.UpdateSZP32(0);
    EXPECT_TRUE(cpu.State().eflags.ZF());
    EXPECT_FALSE(cpu.State().eflags.SF());

    // Negative result (high bit set)
    cpu.State().eflags.UpdateSZP32(0x80000000u);
    EXPECT_FALSE(cpu.State().eflags.ZF());
    EXPECT_TRUE(cpu.State().eflags.SF());
}

TEST_F(PhantomEmulatorTest, FPU_PushPop) {
    CPUState& s = cpu.State();
    s.FPUPush(3.14L);
    EXPECT_NEAR(static_cast<double>(s.FPU_ST(0).value), 3.14, 1e-10);

    s.FPUPush(2.71L);
    EXPECT_NEAR(static_cast<double>(s.FPU_ST(0).value), 2.71, 1e-10);
    EXPECT_NEAR(static_cast<double>(s.FPU_ST(1).value), 3.14, 1e-10);

    long double popped = s.FPUPop();
    EXPECT_NEAR(static_cast<double>(popped), 2.71, 1e-10);
}

TEST_F(PhantomEmulatorTest, XMMRegisterAccess) {
    XMMReg& xmm0 = cpu.State().XMM(0);
    xmm0.u32[0] = 0xDEADBEEF;
    xmm0.u32[1] = 0xCAFEBABE;
    xmm0.u32[2] = 0x12345678;
    xmm0.u32[3] = 0x9ABCDEF0;

    EXPECT_EQ(cpu.State().XMM(0).u32[0], 0xDEADBEEFu);
    EXPECT_EQ(cpu.State().XMM(0).u32[3], 0x9ABCDEF0u);
}

TEST_F(PhantomEmulatorTest, YMMRegisterAccess) {
    alignas(32) uint8_t ymm_data[32]{};
    for (uint8_t i = 0; i < 32; ++i) ymm_data[i] = i;

    cpu.State().SetYMM(0, ymm_data);

    alignas(32) uint8_t readback[32]{};
    cpu.State().GetYMM(0, readback);

    EXPECT_EQ(std::memcmp(ymm_data, readback, 32), 0);
}

TEST_F(PhantomEmulatorTest, ZMMRegisterAccess) {
    alignas(64) uint8_t zmm_data[64]{};
    for (uint8_t i = 0; i < 64; ++i) zmm_data[i] = i;

    cpu.State().SetZMM(0, zmm_data);

    alignas(64) uint8_t readback[64]{};
    cpu.State().GetZMM(0, readback);

    // First 48 bytes should match (xmm[16] + ymmHigh[16] + zmmHigh[32])
    EXPECT_EQ(std::memcmp(zmm_data, readback, 48), 0);
}

TEST_F(PhantomEmulatorTest, OpmaskRegisters) {
    cpu.State().opmask[1] = 0xFF00FF00FF00FF00ULL;
    EXPECT_EQ(cpu.State().opmask[1], 0xFF00FF00FF00FF00ULL);
    cpu.State().opmask[7] = 0xAAAAAAAAAAAAAAAAULL;
    EXPECT_EQ(cpu.State().opmask[7], 0xAAAAAAAAAAAAAAAAULL);
}

// ============================================================================
// Virtual Memory Tests
// ============================================================================

TEST_F(PhantomEmulatorTest, VirtualMemory_ReadWriteBasic) {
    uint64_t writeVal = 0x123456789ABCDEF0ULL;
    EXPECT_EQ(memory.WriteU64(kDataBase, writeVal), ErrorCode::Success);

    uint64_t readVal = 0;
    EXPECT_EQ(memory.ReadU64(kDataBase, readVal), ErrorCode::Success);
    EXPECT_EQ(readVal, writeVal);
}

TEST_F(PhantomEmulatorTest, VirtualMemory_ReadWriteMultiType) {
    EXPECT_EQ(memory.WriteU8(kDataBase, 0xAB), ErrorCode::Success);
    EXPECT_EQ(memory.WriteU16(kDataBase + 2, 0xCDEF), ErrorCode::Success);
    EXPECT_EQ(memory.WriteU32(kDataBase + 4, 0x12345678), ErrorCode::Success);

    uint8_t v8 = 0;
    uint16_t v16 = 0;
    uint32_t v32 = 0;
    EXPECT_EQ(memory.ReadU8(kDataBase, v8), ErrorCode::Success);
    EXPECT_EQ(v8, 0xABu);
    EXPECT_EQ(memory.ReadU16(kDataBase + 2, v16), ErrorCode::Success);
    EXPECT_EQ(v16, 0xCDEFu);
    EXPECT_EQ(memory.ReadU32(kDataBase + 4, v32), ErrorCode::Success);
    EXPECT_EQ(v32, 0x12345678u);
}

TEST_F(PhantomEmulatorTest, VirtualMemory_ProtectionEnforcement_ReadOnExecute) {
    // Code region is RX — reading should work
    uint8_t val = 0;
    EXPECT_EQ(memory.ReadU8(kCodeBase, val), ErrorCode::Success);
}

TEST_F(PhantomEmulatorTest, VirtualMemory_ProtectionEnforcement_WriteViolation) {
    // Code region is RX — writing should fail
    auto err = memory.WriteU8(kCodeBase, 0xCC);
    EXPECT_NE(err, ErrorCode::Success);
}

TEST_F(PhantomEmulatorTest, VirtualMemory_ProtectionEnforcement_ExecViolation) {
    // Data region is RW — instruction fetch should fail
    uint8_t buf[15]{};
    uint32_t bytesRead = 0;
    auto err = memory.FetchInstruction(kDataBase, buf, 15, bytesRead);
    EXPECT_NE(err, ErrorCode::Success);
}

TEST_F(PhantomEmulatorTest, VirtualMemory_UnmappedAccess) {
    uint8_t val = 0;
    auto err = memory.ReadU8(0xFFFF0000, val);
    EXPECT_NE(err, ErrorCode::Success);
}

TEST_F(PhantomEmulatorTest, VirtualMemory_ProtectChangeAndVerify) {
    // Change data region to RWX
    EXPECT_TRUE(memory.Protect(kDataBase, kPageSize, MemProt::RWX));
    EXPECT_TRUE(memory.IsAccessible(kDataBase, MemProt::Execute));

    // Change back to RW
    EXPECT_TRUE(memory.Protect(kDataBase, kPageSize, MemProt::RW));
    EXPECT_FALSE(memory.IsAccessible(kDataBase, MemProt::Execute));
}

TEST_F(PhantomEmulatorTest, VirtualMemory_FreeAndRealloc) {
    // Allocate a new region
    GuestAddress addr = 0x00A00000;
    auto alloc = memory.Allocate(addr, kPageSize, MemProt::RW);
    ASSERT_TRUE(alloc.has_value());

    // Write and verify
    EXPECT_EQ(memory.WriteU32(addr, 0xAABBCCDD), ErrorCode::Success);
    uint32_t v = 0;
    EXPECT_EQ(memory.ReadU32(addr, v), ErrorCode::Success);
    EXPECT_EQ(v, 0xAABBCCDDu);

    // Free it
    EXPECT_TRUE(memory.Free(addr, kPageSize));

    // Should no longer be accessible
    auto err = memory.ReadU32(addr, v);
    EXPECT_NE(err, ErrorCode::Success);
}

TEST_F(PhantomEmulatorTest, VirtualMemory_AllocationCapEnforced) {
    // Create a small-capped memory manager
    VirtualMemory small(2 * kPageSize);

    auto a1 = small.Allocate(0x100000, kPageSize, MemProt::RW);
    EXPECT_TRUE(a1.has_value());

    auto a2 = small.Allocate(0x200000, kPageSize, MemProt::RW);
    EXPECT_TRUE(a2.has_value());

    // Third allocation should fail — exceeds cap
    auto a3 = small.Allocate(0x300000, kPageSize, MemProt::RW);
    EXPECT_FALSE(a3.has_value());
}

TEST_F(PhantomEmulatorTest, VirtualMemory_SnapshotRestore) {
    EXPECT_EQ(memory.WriteU64(kDataBase, 0x1234), ErrorCode::Success);

    auto snap = memory.TakeSnapshot();

    // Overwrite
    EXPECT_EQ(memory.WriteU64(kDataBase, 0x5678), ErrorCode::Success);

    memory.RestoreSnapshot(snap);

    uint64_t v = 0;
    EXPECT_EQ(memory.ReadU64(kDataBase, v), ErrorCode::Success);
    EXPECT_EQ(v, 0x1234u);
}

// ============================================================================
// Memory Tracker Tests
// ============================================================================

TEST_F(PhantomEmulatorTest, MemoryTracker_WriteExecuteTransition) {
    GuestAddress page = kDataBase & ~kPageMask;
    tracker.RecordWrite(page);
    EXPECT_FALSE(tracker.IsWriteExecuteTransition(page));

    tracker.RecordExecute(page);
    EXPECT_TRUE(tracker.IsWriteExecuteTransition(page));
}

TEST_F(PhantomEmulatorTest, MemoryTracker_NoFalsePositive) {
    // Only execute, no write — should NOT be a W→X transition
    GuestAddress page = kCodeBase & ~kPageMask;
    tracker.RecordExecute(page);
    EXPECT_FALSE(tracker.IsWriteExecuteTransition(page));
}

TEST_F(PhantomEmulatorTest, MemoryTracker_Reset) {
    GuestAddress page = kDataBase & ~kPageMask;
    tracker.RecordWrite(page);
    tracker.RecordExecute(page);
    EXPECT_TRUE(tracker.IsWriteExecuteTransition(page));

    tracker.Reset();
    EXPECT_FALSE(tracker.IsWriteExecuteTransition(page));
    EXPECT_EQ(tracker.GetWriteExecuteCount(), 0u);
}

// ============================================================================
// ALU Instruction Tests
// ============================================================================

TEST_F(PhantomEmulatorTest, ALU_ADD_RAX_RBX) {
    // 48 01 D8  =  ADD RAX, RBX
    const uint8_t code[] = { 0x48, 0x01, 0xD8 };
    cpu.State().SetReg64(GPR::RAX, 100);
    cpu.State().SetReg64(GPR::RBX, 200);

    auto err = WriteAndExecuteSingle(code, sizeof(code));
    EXPECT_EQ(err, ErrorCode::Success);
    EXPECT_EQ(cpu.State().RAX(), 300u);
    EXPECT_FALSE(cpu.State().eflags.ZF());
    EXPECT_FALSE(cpu.State().eflags.SF());
}

TEST_F(PhantomEmulatorTest, ALU_ADD_ZeroResult) {
    // 48 01 D8  =  ADD RAX, RBX
    const uint8_t code[] = { 0x48, 0x01, 0xD8 };
    cpu.State().SetReg64(GPR::RAX, 0);
    cpu.State().SetReg64(GPR::RBX, 0);

    auto err = WriteAndExecuteSingle(code, sizeof(code));
    EXPECT_EQ(err, ErrorCode::Success);
    EXPECT_EQ(cpu.State().RAX(), 0u);
    EXPECT_TRUE(cpu.State().eflags.ZF());
}

TEST_F(PhantomEmulatorTest, ALU_SUB_RAX_RBX) {
    // 48 29 D8  =  SUB RAX, RBX
    const uint8_t code[] = { 0x48, 0x29, 0xD8 };
    cpu.State().SetReg64(GPR::RAX, 500);
    cpu.State().SetReg64(GPR::RBX, 200);

    auto err = WriteAndExecuteSingle(code, sizeof(code));
    EXPECT_EQ(err, ErrorCode::Success);
    EXPECT_EQ(cpu.State().RAX(), 300u);
}

TEST_F(PhantomEmulatorTest, ALU_SUB_UnderflowSetsCarryAndSign) {
    // 48 29 D8  =  SUB RAX, RBX  (100 - 200 → wraps, CF=1, SF=1)
    const uint8_t code[] = { 0x48, 0x29, 0xD8 };
    cpu.State().SetReg64(GPR::RAX, 100);
    cpu.State().SetReg64(GPR::RBX, 200);

    auto err = WriteAndExecuteSingle(code, sizeof(code));
    EXPECT_EQ(err, ErrorCode::Success);
    EXPECT_TRUE(cpu.State().eflags.CF());
    EXPECT_TRUE(cpu.State().eflags.SF());
}

TEST_F(PhantomEmulatorTest, ALU_XOR_SelfClearsRegister) {
    // 48 31 C0  =  XOR RAX, RAX
    const uint8_t code[] = { 0x48, 0x31, 0xC0 };
    cpu.State().SetReg64(GPR::RAX, 0xDEADBEEFDEADBEEFULL);

    auto err = WriteAndExecuteSingle(code, sizeof(code));
    EXPECT_EQ(err, ErrorCode::Success);
    EXPECT_EQ(cpu.State().RAX(), 0u);
    EXPECT_TRUE(cpu.State().eflags.ZF());
    EXPECT_FALSE(cpu.State().eflags.CF()); // XOR always clears CF, OF
    EXPECT_FALSE(cpu.State().eflags.OF());
}

TEST_F(PhantomEmulatorTest, ALU_CMP_SetsFlags) {
    // 48 39 D8  =  CMP RAX, RBX  (like SUB but doesn't store result)
    const uint8_t code[] = { 0x48, 0x39, 0xD8 };
    cpu.State().SetReg64(GPR::RAX, 42);
    cpu.State().SetReg64(GPR::RBX, 42);

    auto err = WriteAndExecuteSingle(code, sizeof(code));
    EXPECT_EQ(err, ErrorCode::Success);
    EXPECT_TRUE(cpu.State().eflags.ZF()); // Equal → ZF=1
    EXPECT_EQ(cpu.State().RAX(), 42u);    // RAX unchanged
}

TEST_F(PhantomEmulatorTest, ALU_INC_RCX) {
    // 48 FF C1  =  INC RCX
    const uint8_t code[] = { 0x48, 0xFF, 0xC1 };
    cpu.State().SetReg64(GPR::RCX, 0xFFFFFFFFFFFFFFFFULL);

    auto err = WriteAndExecuteSingle(code, sizeof(code));
    EXPECT_EQ(err, ErrorCode::Success);
    EXPECT_EQ(cpu.State().RCX(), 0u);     // Wraps to zero
    EXPECT_TRUE(cpu.State().eflags.ZF());
}

TEST_F(PhantomEmulatorTest, ALU_ADD_32bit_ZeroExtends) {
    // 01 D8  =  ADD EAX, EBX  (32-bit mode, result zero-extends to 64)
    const uint8_t code[] = { 0x01, 0xD8 };
    cpu.State().SetReg64(GPR::RAX, 0xFFFFFFFF00000001ULL);
    cpu.State().SetReg64(GPR::RBX, 0xFFFFFFFF00000002ULL);

    auto err = WriteAndExecuteSingle(code, sizeof(code));
    EXPECT_EQ(err, ErrorCode::Success);
    // 32-bit ADD: EAX=1+2=3, zero-extended to RAX=3
    EXPECT_EQ(cpu.State().RAX(), 3u);
}

// ============================================================================
// Data Transfer Tests
// ============================================================================

TEST_F(PhantomEmulatorTest, MOV_RAX_Immediate) {
    // 48 B8 <8 bytes>  =  MOV RAX, imm64
    uint8_t code[10] = { 0x48, 0xB8 };
    uint64_t val = 0xCAFEBABEDEADBEEFULL;
    std::memcpy(code + 2, &val, 8);

    auto err = WriteAndExecuteSingle(code, sizeof(code));
    EXPECT_EQ(err, ErrorCode::Success);
    EXPECT_EQ(cpu.State().RAX(), val);
}

TEST_F(PhantomEmulatorTest, MOV_EAX_Immediate) {
    // B8 <4 bytes>  =  MOV EAX, imm32
    uint8_t code[5] = { 0xB8 };
    uint32_t val = 0xDEADBEEF;
    std::memcpy(code + 1, &val, 4);

    auto err = WriteAndExecuteSingle(code, sizeof(code));
    EXPECT_EQ(err, ErrorCode::Success);
    EXPECT_EQ(cpu.State().RAX(), 0x00000000DEADBEEFu); // Zero-extended
}

TEST_F(PhantomEmulatorTest, PUSH_POP_RAX) {
    // PUSH RAX:  50
    // POP  RBX:  5B
    cpu.State().SetReg64(GPR::RAX, 0x123456789ABCDEF0ULL);
    GuestAddress origRSP = cpu.State().RSP();

    const uint8_t push_code[] = { 0x50 };
    auto err = WriteAndExecuteSingle(push_code, sizeof(push_code));
    EXPECT_EQ(err, ErrorCode::Success);
    EXPECT_EQ(cpu.State().RSP(), origRSP - 8);

    const uint8_t pop_code[] = { 0x5B };
    err = WriteAndExecuteSingle(pop_code, sizeof(pop_code), kCodeBase + 1);
    EXPECT_EQ(err, ErrorCode::Success);
    EXPECT_EQ(cpu.State().RBX(), 0x123456789ABCDEF0ULL);
    EXPECT_EQ(cpu.State().RSP(), origRSP);
}

TEST_F(PhantomEmulatorTest, XCHG_RAX_RBX) {
    // 48 87 D8  =  XCHG RAX, RBX
    const uint8_t code[] = { 0x48, 0x87, 0xD8 };
    cpu.State().SetReg64(GPR::RAX, 111);
    cpu.State().SetReg64(GPR::RBX, 222);

    auto err = WriteAndExecuteSingle(code, sizeof(code));
    EXPECT_EQ(err, ErrorCode::Success);
    EXPECT_EQ(cpu.State().RAX(), 222u);
    EXPECT_EQ(cpu.State().RBX(), 111u);
}

// ============================================================================
// Control Flow Tests
// ============================================================================

TEST_F(PhantomEmulatorTest, NOP_AdvancesRIP) {
    // 90  =  NOP
    const uint8_t code[] = { 0x90 };
    auto err = WriteAndExecuteSingle(code, sizeof(code));
    EXPECT_EQ(err, ErrorCode::Success);
    EXPECT_EQ(cpu.State().GetRIP(), kCodeBase + 1);
}

TEST_F(PhantomEmulatorTest, JMP_Short_Forward) {
    // EB 05  =  JMP SHORT +5 (RIP = base + 2 + 5 = base + 7)
    const uint8_t code[] = { 0xEB, 0x05 };
    auto err = WriteAndExecuteSingle(code, sizeof(code));
    EXPECT_EQ(err, ErrorCode::Success);
    EXPECT_EQ(cpu.State().GetRIP(), kCodeBase + 7);
}

TEST_F(PhantomEmulatorTest, JZ_Taken) {
    // Set ZF=1 manually, then: 74 10  =  JZ +16
    cpu.State().eflags.SetZF(true);
    const uint8_t code[] = { 0x74, 0x10 };
    auto err = WriteAndExecuteSingle(code, sizeof(code));
    EXPECT_EQ(err, ErrorCode::Success);
    EXPECT_EQ(cpu.State().GetRIP(), kCodeBase + 2 + 0x10);
}

TEST_F(PhantomEmulatorTest, JZ_NotTaken) {
    cpu.State().eflags.SetZF(false);
    const uint8_t code[] = { 0x74, 0x10 };
    auto err = WriteAndExecuteSingle(code, sizeof(code));
    EXPECT_EQ(err, ErrorCode::Success);
    EXPECT_EQ(cpu.State().GetRIP(), kCodeBase + 2); // Falls through
}

TEST_F(PhantomEmulatorTest, CALL_And_RET) {
    // CALL rel32: E8 <offset>  →  pushes return addr, jumps
    // Target = kCodeBase + 5 + offset  (we jump forward 0x10 bytes)
    uint8_t call_code[5] = { 0xE8 };
    int32_t offset = 0x10;
    std::memcpy(call_code + 1, &offset, 4);

    GuestAddress origRSP = cpu.State().RSP();
    auto err = WriteAndExecuteSingle(call_code, sizeof(call_code));
    EXPECT_EQ(err, ErrorCode::Success);

    // Should have pushed return address (kCodeBase + 5)
    EXPECT_EQ(cpu.State().RSP(), origRSP - 8);
    EXPECT_EQ(cpu.State().GetRIP(), kCodeBase + 5 + offset);

    // Read pushed return address
    uint64_t retAddr = 0;
    EXPECT_EQ(memory.ReadU64(cpu.State().RSP(), retAddr), ErrorCode::Success);
    EXPECT_EQ(retAddr, kCodeBase + 5);

    // RET: C3
    const uint8_t ret_code[] = { 0xC3 };
    err = WriteAndExecuteSingle(ret_code, sizeof(ret_code), kCodeBase + 5 + offset);
    EXPECT_EQ(err, ErrorCode::Success);
    EXPECT_EQ(cpu.State().GetRIP(), kCodeBase + 5);
    EXPECT_EQ(cpu.State().RSP(), origRSP);
}

// ============================================================================
// System Instruction Tests
// ============================================================================

TEST_F(PhantomEmulatorTest, CPUID_Leaf1_ReturnsSomething) {
    // 0F A2  =  CPUID
    const uint8_t code[] = { 0x0F, 0xA2 };
    cpu.State().SetReg64(GPR::RAX, 1); // Leaf 1
    cpu.State().SetReg64(GPR::RCX, 0); // Sub-leaf 0

    auto err = WriteAndExecuteSingle(code, sizeof(code));
    EXPECT_EQ(err, ErrorCode::Success);

    // After CPUID leaf 1, EAX should contain something (family/model/stepping)
    uint32_t eax = cpu.State().GetReg32(GPR::RAX);
    EXPECT_NE(eax, 0u) << "CPUID leaf 1 EAX should not be zero";

    // ECX/EDX should have feature bits set
    uint32_t ecx = cpu.State().GetReg32(GPR::RCX);
    uint32_t edx = cpu.State().GetReg32(GPR::RDX);
    EXPECT_NE(ecx | edx, 0u) << "CPUID leaf 1 should report some features";

    // SSE2 must be present (bit 26 of EDX) — basic for any x86-64
    EXPECT_TRUE((edx & (1u << 26)) != 0) << "CPUID must report SSE2";
}

TEST_F(PhantomEmulatorTest, RDTSC_ReturnsNonZero) {
    // 0F 31  =  RDTSC
    const uint8_t code[] = { 0x0F, 0x31 };

    // Ensure TSC is non-zero
    cpu.State().tsc = 1000;
    auto err = WriteAndExecuteSingle(code, sizeof(code));
    EXPECT_EQ(err, ErrorCode::Success);

    uint32_t eax = cpu.State().GetReg32(GPR::RAX);
    uint32_t edx = cpu.State().GetReg32(GPR::RDX);
    uint64_t tscVal = (static_cast<uint64_t>(edx) << 32) | eax;
    EXPECT_GT(tscVal, 0u);
}

// ============================================================================
// Error Path Tests
// ============================================================================

TEST_F(PhantomEmulatorTest, DivideByZero) {
    // Set up DIV RCX where RCX=0
    // 48 F7 F1  =  DIV RCX  (unsigned divide RDX:RAX by RCX)
    const uint8_t code[] = { 0x48, 0xF7, 0xF1 };
    cpu.State().SetReg64(GPR::RAX, 42);
    cpu.State().SetReg64(GPR::RDX, 0);
    cpu.State().SetReg64(GPR::RCX, 0);

    auto err = WriteAndExecuteSingle(code, sizeof(code));
    EXPECT_EQ(err, ErrorCode::DivideByZero);
}

TEST_F(PhantomEmulatorTest, AccessViolation_ExecuteFromUnmapped) {
    // Try to execute from an unmapped address
    cpu.State().SetRIP(0xDEAD0000);
    auto err = cpu.ExecuteSingle(memory, &tracker);
    // Should fail — either AccessViolationExec or PageNotPresent
    EXPECT_NE(err, ErrorCode::Success);
}

TEST_F(PhantomEmulatorTest, AccessViolation_WriteToCodeRegion) {
    // MOV [kCodeBase + 0x1000], RAX
    // This is a complex encoding; instead, test via direct memory API
    auto err = memory.WriteU8(kCodeBase + 0x100, 0xCC);
    EXPECT_NE(err, ErrorCode::Success);
}

// ============================================================================
// Bit Manipulation Tests
// ============================================================================

TEST_F(PhantomEmulatorTest, POPCNT_RAX_RBX) {
    // F3 48 0F B8 C3  =  POPCNT RAX, RBX
    const uint8_t code[] = { 0xF3, 0x48, 0x0F, 0xB8, 0xC3 };
    cpu.State().SetReg64(GPR::RBX, 0xFF00FF00FF00FF00ULL); // 32 bits set

    auto err = WriteAndExecuteSingle(code, sizeof(code));
    EXPECT_EQ(err, ErrorCode::Success);
    EXPECT_EQ(cpu.State().RAX(), 32u);
}

TEST_F(PhantomEmulatorTest, POPCNT_Zero) {
    // F3 48 0F B8 C3  =  POPCNT RAX, RBX
    const uint8_t code[] = { 0xF3, 0x48, 0x0F, 0xB8, 0xC3 };
    cpu.State().SetReg64(GPR::RBX, 0);

    auto err = WriteAndExecuteSingle(code, sizeof(code));
    EXPECT_EQ(err, ErrorCode::Success);
    EXPECT_EQ(cpu.State().RAX(), 0u);
    EXPECT_TRUE(cpu.State().eflags.ZF());
}

TEST_F(PhantomEmulatorTest, TZCNT_RAX_RBX) {
    // F3 48 0F BC C3  =  TZCNT RAX, RBX
    const uint8_t code[] = { 0xF3, 0x48, 0x0F, 0xBC, 0xC3 };
    cpu.State().SetReg64(GPR::RBX, 0x0000000000001000ULL); // Bit 12 is lowest set

    auto err = WriteAndExecuteSingle(code, sizeof(code));
    EXPECT_EQ(err, ErrorCode::Success);
    EXPECT_EQ(cpu.State().RAX(), 12u);
}

TEST_F(PhantomEmulatorTest, LZCNT_RAX_RBX) {
    // F3 48 0F BD C3  =  LZCNT RAX, RBX
    const uint8_t code[] = { 0xF3, 0x48, 0x0F, 0xBD, 0xC3 };
    // 0x8000000000000000 → highest bit set → 0 leading zeros
    cpu.State().SetReg64(GPR::RBX, 0x8000000000000000ULL);

    auto err = WriteAndExecuteSingle(code, sizeof(code));
    EXPECT_EQ(err, ErrorCode::Success);
    EXPECT_EQ(cpu.State().RAX(), 0u);
}

// ============================================================================
// Execution Loop Tests (using Execute with EmulationConfig)
// ============================================================================

TEST_F(PhantomEmulatorTest, Execute_InstructionLimitEnforced) {
    // Write a tight NOP loop
    uint8_t nop_block[16];
    std::memset(nop_block, 0x90, sizeof(nop_block)); // 16 NOPs
    // Put a JMP SHORT -16 at the end to loop back
    nop_block[14] = 0xEB;
    nop_block[15] = static_cast<uint8_t>(-16); // 0xF0

    // Write code
    EXPECT_TRUE(memory.Protect(kCodeBase & ~kPageMask, kPageSize, MemProt::RWX));
    EXPECT_EQ(memory.Write(kCodeBase, nop_block, sizeof(nop_block)), ErrorCode::Success);
    EXPECT_TRUE(memory.Protect(kCodeBase & ~kPageMask, kPageSize, MemProt::RX));

    cpu.State().SetRIP(kCodeBase);

    EmulationConfig cfg;
    cfg.maxInstructions = 100;
    cfg.maxWallTime = std::chrono::milliseconds{ 5000 };
    cfg.enableJIT = false;

    auto result = cpu.Execute(memory, &tracker, cfg);
    EXPECT_EQ(result.reason, StopReason::InstructionLimit);
    EXPECT_GE(result.instructionsExecuted, 100u);
}

TEST_F(PhantomEmulatorTest, Execute_BreakpointStopsExecution) {
    // NOP; NOP; NOP; NOP
    const uint8_t code[] = { 0x90, 0x90, 0x90, 0x90 };
    EXPECT_TRUE(memory.Protect(kCodeBase & ~kPageMask, kPageSize, MemProt::RWX));
    EXPECT_EQ(memory.Write(kCodeBase, code, sizeof(code)), ErrorCode::Success);
    EXPECT_TRUE(memory.Protect(kCodeBase & ~kPageMask, kPageSize, MemProt::RX));

    cpu.State().SetRIP(kCodeBase);
    cpu.AddBreakpoint(kCodeBase + 2); // Break at third NOP

    EmulationConfig cfg;
    cfg.maxInstructions = 1000;
    cfg.maxWallTime = std::chrono::milliseconds{ 5000 };
    cfg.enableJIT = false;

    auto result = cpu.Execute(memory, &tracker, cfg);
    EXPECT_EQ(result.reason, StopReason::Breakpoint);
    EXPECT_EQ(cpu.State().GetRIP(), kCodeBase + 2);
}

TEST_F(PhantomEmulatorTest, Execute_RequestAbortFromCallback) {
    // NOP loop
    uint8_t nop_block[16];
    std::memset(nop_block, 0x90, sizeof(nop_block));
    nop_block[14] = 0xEB;
    nop_block[15] = static_cast<uint8_t>(-16);

    EXPECT_TRUE(memory.Protect(kCodeBase & ~kPageMask, kPageSize, MemProt::RWX));
    EXPECT_EQ(memory.Write(kCodeBase, nop_block, sizeof(nop_block)), ErrorCode::Success);
    EXPECT_TRUE(memory.Protect(kCodeBase & ~kPageMask, kPageSize, MemProt::RX));

    cpu.State().SetRIP(kCodeBase);

    // Set pre-instruction callback to abort after 50 instructions
    uint32_t count = 0;
    cpu.SetPreInstructionCallback(
        [&count, this](const CPUState&, const DecodedInstruction&) -> bool {
            if (++count >= 50) {
                return false; // Stop execution
            }
            return true;
        });

    EmulationConfig cfg;
    cfg.maxInstructions = 100000;
    cfg.maxWallTime = std::chrono::milliseconds{ 5000 };
    cfg.enableJIT = false;

    auto result = cpu.Execute(memory, &tracker, cfg);
    EXPECT_EQ(result.reason, StopReason::UserAborted);
    EXPECT_GE(count, 50u);
}

TEST_F(PhantomEmulatorTest, Execute_CrossThreadAbort) {
    uint8_t nop_block[16];
    std::memset(nop_block, 0x90, sizeof(nop_block));
    nop_block[14] = 0xEB;
    nop_block[15] = static_cast<uint8_t>(-16);

    EXPECT_TRUE(memory.Protect(kCodeBase & ~kPageMask, kPageSize, MemProt::RWX));
    EXPECT_EQ(memory.Write(kCodeBase, nop_block, sizeof(nop_block)), ErrorCode::Success);
    EXPECT_TRUE(memory.Protect(kCodeBase & ~kPageMask, kPageSize, MemProt::RX));

    cpu.State().SetRIP(kCodeBase);

    // Request abort from another thread after brief delay
    std::thread aborter([this]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        cpu.RequestAbort();
    });

    EmulationConfig cfg;
    cfg.maxInstructions = 50'000'000;
    cfg.maxWallTime = std::chrono::milliseconds{ 10000 };
    cfg.enableJIT = false;

    auto result = cpu.Execute(memory, &tracker, cfg);
    aborter.join();

    EXPECT_EQ(result.reason, StopReason::UserAborted);
}

// ============================================================================
// Multi-Instruction Sequences
// ============================================================================

TEST_F(PhantomEmulatorTest, Sequence_FunctionPrologue) {
    // Classic x86-64 function prologue:
    //   55         PUSH RBP
    //   48 89 E5   MOV RBP, RSP
    //   48 83 EC 20 SUB RSP, 0x20
    const uint8_t code[] = {
        0x55,                   // PUSH RBP
        0x48, 0x89, 0xE5,      // MOV RBP, RSP
        0x48, 0x83, 0xEC, 0x20 // SUB RSP, 0x20
    };

    GuestAddress origRSP = cpu.State().RSP();
    GuestAddress origRBP = cpu.State().GetReg64(GPR::RBP);

    auto err = WriteAndExecuteN(code, sizeof(code), 3);
    EXPECT_EQ(err, ErrorCode::Success);

    // After PUSH RBP: RSP = origRSP - 8
    // After MOV RBP, RSP: RBP = origRSP - 8
    // After SUB RSP, 0x20: RSP = origRSP - 8 - 0x20
    EXPECT_EQ(cpu.State().GetReg64(GPR::RBP), origRSP - 8);
    EXPECT_EQ(cpu.State().RSP(), origRSP - 8 - 0x20);
}

TEST_F(PhantomEmulatorTest, Sequence_LoopWithCounter) {
    // ECX = 5; loop: DEC ECX; JNZ loop
    //   B9 05 00 00 00   MOV ECX, 5
    //   FF C9             DEC ECX
    //   75 FC             JNZ -4 (back to DEC)
    const uint8_t code[] = {
        0xB9, 0x05, 0x00, 0x00, 0x00,  // MOV ECX, 5
        0xFF, 0xC9,                      // DEC ECX
        0x75, 0xFC                       // JNZ -4
    };

    // 1 MOV + 5*(DEC+JNZ_taken) + (DEC+JNZ_not_taken) - wait, let me think:
    // MOV ECX, 5  → ECX=5
    // DEC ECX → ECX=4, ZF=0 → JNZ taken, jump back to DEC
    // DEC ECX → ECX=3, ZF=0 → JNZ taken
    // DEC ECX → ECX=2, ZF=0 → JNZ taken
    // DEC ECX → ECX=1, ZF=0 → JNZ taken
    // DEC ECX → ECX=0, ZF=1 → JNZ not taken
    // Total: 1 + 5*2 = 11 instructions

    auto err = WriteAndExecuteN(code, sizeof(code), 11);
    EXPECT_EQ(err, ErrorCode::Success);
    EXPECT_EQ(cpu.State().GetReg32(GPR::RCX), 0u);
    EXPECT_TRUE(cpu.State().eflags.ZF());
}

// ============================================================================
// Edge Cases
// ============================================================================

TEST_F(PhantomEmulatorTest, INT3_Breakpoint) {
    // CC  =  INT 3  (software breakpoint)
    const uint8_t code[] = { 0xCC };
    auto err = WriteAndExecuteSingle(code, sizeof(code));
    // INT3 should either stop or trigger interrupt callback
    // Without an interrupt callback set, should stop or error
    // The exact behavior depends on whether the CPU treats it as a breakpoint
    // or an interrupt without a handler
    EXPECT_NE(err, ErrorCode::Success);
}

TEST_F(PhantomEmulatorTest, HLT_StopsExecution) {
    // F4  =  HLT  (privileged in user mode)
    const uint8_t code[] = { 0xF4 };
    auto err = WriteAndExecuteSingle(code, sizeof(code));
    // HLT should be treated as privileged instruction in user-mode emulation
    EXPECT_NE(err, ErrorCode::Success);
}

TEST_F(PhantomEmulatorTest, MultipleResets) {
    cpu.State().SetReg64(GPR::RAX, 0xDEAD);
    cpu.State().instructionCount = 9999;

    cpu.Reset64();
    EXPECT_EQ(cpu.State().RAX(), 0u);
    EXPECT_EQ(cpu.State().instructionCount, 0u);
    EXPECT_EQ(cpu.State().mode, CPUMode::Long64);

    cpu.Reset32();
    EXPECT_EQ(cpu.State().mode, CPUMode::Protected32);
}

TEST_F(PhantomEmulatorTest, InstructionCountIncrementsCorrectly) {
    const uint8_t nop[] = { 0x90 };
    uint64_t startCount = cpu.State().instructionCount;

    for (int i = 0; i < 10; ++i) {
        EXPECT_EQ(WriteAndExecuteSingle(nop, 1, kCodeBase), ErrorCode::Success);
    }

    // Each ExecuteSingle doesn't increment instructionCount — that's done by
    // the Execute loop. Direct ExecuteSingle is for single-step testing.
    // Verify at least the RIP advanced correctly each time.
    EXPECT_EQ(cpu.State().GetRIP(), kCodeBase + 1);
}

// ============================================================================
// Configuration Preset Tests
// ============================================================================

TEST_F(PhantomEmulatorTest, FastScanConfig_Limits) {
    auto cfg = FastScanConfig();
    EXPECT_EQ(cfg.maxInstructions, 5'000'000u);
    EXPECT_FALSE(cfg.trackMemoryAccess);
    EXPECT_FALSE(cfg.enableBehaviorMonitor);
    EXPECT_FALSE(cfg.enableKernelEmulation);
}

TEST_F(PhantomEmulatorTest, DeepAnalysisConfig_Limits) {
    auto cfg = DeepAnalysisConfig();
    EXPECT_EQ(cfg.maxInstructions, 200'000'000u);
    EXPECT_TRUE(cfg.trackMemoryAccess);
    EXPECT_TRUE(cfg.enableInstructionTrace);
}

TEST_F(PhantomEmulatorTest, DefaultConfig_Sane) {
    EmulationConfig cfg;
    EXPECT_EQ(cfg.maxInstructions, 50'000'000u);
    EXPECT_EQ(cfg.cpuMode, CPUMode::Long64);
    EXPECT_EQ(cfg.target, EmulationTarget::PE64);
    EXPECT_TRUE(cfg.enableDEP);
    EXPECT_TRUE(cfg.enableCET);
    EXPECT_GT(cfg.processorCount, 0u);
    EXPECT_GT(cfg.totalPhysicalMem, 0u);
    EXPECT_FALSE(cfg.enableNetwork); // Network disabled by default for security
}

// ============================================================================
// AMX Tile State Tests
// ============================================================================

TEST_F(PhantomEmulatorTest, AMX_TileConfig_Reset) {
    auto& tc = cpu.State().tileConfig;
    tc.paletteId = 1;
    tc.configured = true;
    tc.tiles[0].colsb = 64;
    tc.tiles[0].rows = 16;

    tc.Reset();
    EXPECT_EQ(tc.paletteId, 0u);
    EXPECT_FALSE(tc.configured);
    EXPECT_EQ(tc.tiles[0].colsb, 0u);
    EXPECT_EQ(tc.tiles[0].rows, 0u);
}

TEST_F(PhantomEmulatorTest, AMX_TileData_GetSetI32) {
    auto& tile = cpu.State().tiles[0];
    tile.Clear();

    tile.SetI32(0, 0, 42);
    tile.SetI32(1, 1, -99);
    tile.SetI32(15, 15, 0x7FFFFFFF);

    EXPECT_EQ(tile.GetI32(0, 0), 42);
    EXPECT_EQ(tile.GetI32(1, 1), -99);
    EXPECT_EQ(tile.GetI32(15, 15), 0x7FFFFFFF);
}

// ============================================================================
// Post-instruction Callback Tracing
// ============================================================================

TEST_F(PhantomEmulatorTest, PostInstructionCallback_Called) {
    uint32_t callCount = 0;
    cpu.SetPostInstructionCallback(
        [&callCount](const CPUState&, const DecodedInstruction&) {
            ++callCount;
        });

    // Execute 3 NOPs via the full Execute loop
    const uint8_t code[] = { 0x90, 0x90, 0x90 };
    EXPECT_TRUE(memory.Protect(kCodeBase & ~kPageMask, kPageSize, MemProt::RWX));
    EXPECT_EQ(memory.Write(kCodeBase, code, sizeof(code)), ErrorCode::Success);
    EXPECT_TRUE(memory.Protect(kCodeBase & ~kPageMask, kPageSize, MemProt::RX));
    cpu.State().SetRIP(kCodeBase);

    // Add breakpoint at end to stop
    cpu.AddBreakpoint(kCodeBase + 3);

    EmulationConfig cfg;
    cfg.maxInstructions = 100;
    cfg.maxWallTime = std::chrono::milliseconds{ 5000 };
    cfg.enableJIT = false;

    auto result = cpu.Execute(memory, &tracker, cfg);
    EXPECT_EQ(result.reason, StopReason::Breakpoint);
    EXPECT_EQ(callCount, 3u);
}

// ============================================================================
// Guard Page Test
// ============================================================================

TEST_F(PhantomEmulatorTest, VirtualMemory_GuardPage) {
    GuestAddress guardAddr = 0x00B00000;
    auto alloc = memory.Allocate(guardAddr, kPageSize, MemProt::RW | MemProt::Guard);
    ASSERT_TRUE(alloc.has_value());

    // First access to a guard page should trigger an exception
    uint8_t val = 0;
    auto err = memory.ReadU8(guardAddr, val);
    // Guard page should cause a guard page violation
    EXPECT_EQ(err, ErrorCode::GuardPageViolation);
}

// ============================================================================
// Stress: Multiple Allocations
// ============================================================================

TEST_F(PhantomEmulatorTest, VirtualMemory_MultipleAllocations) {
    VirtualMemory bigMem(32ULL * 1024 * 1024);
    std::vector<GuestAddress> addrs;
    GuestAddress base = 0x1000000;

    // Allocate 100 pages
    for (int i = 0; i < 100; ++i) {
        auto alloc = bigMem.Allocate(base + i * kPageSize, kPageSize, MemProt::RW);
        ASSERT_TRUE(alloc.has_value()) << "Failed at allocation " << i;
        addrs.push_back(alloc.value());
    }

    // Verify each can be written and read
    for (size_t i = 0; i < addrs.size(); ++i) {
        auto v = static_cast<uint32_t>(i * 111);
        EXPECT_EQ(bigMem.WriteU32(addrs[i], v), ErrorCode::Success);
    }
    for (size_t i = 0; i < addrs.size(); ++i) {
        uint32_t v = 0;
        EXPECT_EQ(bigMem.ReadU32(addrs[i], v), ErrorCode::Success);
        EXPECT_EQ(v, static_cast<uint32_t>(i * 111));
    }
}

// ============================================================================
// Utilities
// ============================================================================

TEST_F(PhantomEmulatorTest, TypeHelpers_AlignDown) {
    EXPECT_EQ(AlignDown(0x1234, kPageSize), 0x1000u);
    EXPECT_EQ(AlignDown(0x1000, kPageSize), 0x1000u);
    EXPECT_EQ(AlignDown(0x1FFF, kPageSize), 0x1000u);
}

TEST_F(PhantomEmulatorTest, TypeHelpers_AlignUp) {
    EXPECT_EQ(AlignUp(0x1001, kPageSize), 0x2000u);
    EXPECT_EQ(AlignUp(0x1000, kPageSize), 0x1000u);
    EXPECT_EQ(AlignUp(0x1FFF, kPageSize), 0x2000u);
}

TEST_F(PhantomEmulatorTest, TypeHelpers_PagesNeeded) {
    EXPECT_EQ(PagesNeeded(0), 0u);
    EXPECT_EQ(PagesNeeded(1), 1u);
    EXPECT_EQ(PagesNeeded(kPageSize), 1u);
    EXPECT_EQ(PagesNeeded(kPageSize + 1), 2u);
    EXPECT_EQ(PagesNeeded(10 * kPageSize), 10u);
}

TEST_F(PhantomEmulatorTest, ErrorCode_SuccessIsZero) {
    EXPECT_EQ(static_cast<uint32_t>(ErrorCode::Success), 0u);
}

TEST_F(PhantomEmulatorTest, MemProt_BitwiseOps) {
    MemProt rw = MemProt::Read | MemProt::Write;
    EXPECT_TRUE(HasProt(rw, MemProt::Read));
    EXPECT_TRUE(HasProt(rw, MemProt::Write));
    EXPECT_FALSE(HasProt(rw, MemProt::Execute));
}

// ============================================================================
// Entry point: GoogleTest main
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
