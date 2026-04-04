/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * JITCompiler.hpp — Just-In-Time compilation framework for hot paths
 *
 * Strategy: Identify frequently-executed basic blocks via the profiler,
 * compile them to native x64 code for direct execution. This is an
 * OPTIONAL optimization layer — the interpreter remains the fallback.
 *
 * Design notes:
 *   - Only compiles basic blocks (single entry, single exit)
 *   - Compiled code runs in an RWX region managed by VirtualAlloc
 *   - Each compiled block has an entry stub that checks guest state
 *   - Compiled code calls back into the emulator for memory access
 *     and API dispatch (no full native execution)
 *   - Code cache is bounded (default 4MB) with LRU eviction
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../CPU/Executor/Decoder/Instruction.hpp"
#include "../CPU/State/CPUState.hpp"
#include "../Memory/VirtualMemory.hpp"
#include "../../Common/Types.hpp"

#include <cstdint>
#include <memory>

namespace Phantom {

struct CompiledBlock {
    GuestAddress guestAddress = 0;
    uint8_t*     nativeCode = nullptr;
    uint32_t     nativeSize = 0;
    uint32_t     guestInstrCount = 0;
    uint64_t     lastUsed = 0;
    uint64_t     executionCount = 0;
    bool         isValid = false;
};

static constexpr uint32_t kDefaultCodeCacheSize = 4u * 1024u * 1024u;
static constexpr uint32_t kMaxCompiledBlocks = 4096;

class X64Emitter {
public:
    explicit X64Emitter(uint8_t* buffer, uint32_t capacity) noexcept;

    void EmitByte(uint8_t b) noexcept;
    void EmitDword(uint32_t v) noexcept;
    void EmitQword(uint64_t v) noexcept;

    void EmitPush(uint8_t reg) noexcept;
    void EmitPop(uint8_t reg) noexcept;
    void EmitMovRegImm64(uint8_t reg, uint64_t imm) noexcept;
    void EmitMovRegReg(uint8_t dst, uint8_t src) noexcept;
    void EmitMovRegMem(uint8_t dst, uint8_t base, int32_t disp) noexcept;
    void EmitMovMemReg(uint8_t base, int32_t disp, uint8_t src) noexcept;
    void EmitAddRegImm32(uint8_t reg, int32_t imm) noexcept;
    void EmitSubRegImm32(uint8_t reg, int32_t imm) noexcept;
    void EmitCall(void* target) noexcept;
    void EmitRet() noexcept;
    void EmitJmp(int32_t offset) noexcept;
    void EmitNop(uint32_t count = 1) noexcept;

    [[nodiscard]] uint32_t GetOffset() const noexcept;
    [[nodiscard]] uint8_t* GetBuffer() const noexcept;

private:
    void EmitRex(bool w, uint8_t r, uint8_t x, uint8_t b) noexcept;
    [[nodiscard]] bool CanEmit(uint32_t bytes) const noexcept;

    uint8_t* m_buffer = nullptr;
    uint32_t m_capacity = 0;
    uint32_t m_offset = 0;
};

enum class JITStrategy : uint8_t {
    Disabled,
    BasicBlock,
    Trace,
    SuperBlock,
};

class JITCompiler {
public:
    explicit JITCompiler(JITStrategy strategy = JITStrategy::Disabled) noexcept;
    ~JITCompiler() noexcept;

    JITCompiler(const JITCompiler&) = delete;
    JITCompiler& operator=(const JITCompiler&) = delete;
    JITCompiler(JITCompiler&&) noexcept;
    JITCompiler& operator=(JITCompiler&&) noexcept;

    [[nodiscard]] bool Initialize(uint32_t cacheSizeBytes = kDefaultCodeCacheSize) noexcept;
    void Shutdown() noexcept;

    [[nodiscard]] CompiledBlock* Lookup(GuestAddress address) noexcept;

    [[nodiscard]] bool CompileBlock(
        GuestAddress address,
        const DecodedInstruction* instructions,
        uint32_t instrCount) noexcept;

    void Invalidate(GuestAddress start, GuestSize size) noexcept;

    [[nodiscard]] uint32_t Execute(
        CompiledBlock& block,
        CPUState& cpu,
        VirtualMemory& memory) noexcept;

    [[nodiscard]] uint32_t GetCompiledBlockCount() const noexcept;
    [[nodiscard]] uint32_t GetCodeCacheUsed() const noexcept;
    [[nodiscard]] double GetCacheHitRate() const noexcept;

    void SetStrategy(JITStrategy strategy) noexcept;
    [[nodiscard]] JITStrategy GetStrategy() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom
