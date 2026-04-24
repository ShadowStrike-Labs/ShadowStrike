/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * Rtl.cpp — Ntdll RTL function handler implementations
 *
 * Per-heap allocation tracking detects cross-heap frees and double-frees.
 * All guest memory access goes through VirtualMemory — no direct host pointers.
 * String operations cap lengths defensively against hostile input.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "Rtl.hpp"
#include "../APIDispatcher.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Errors.hpp"

#include <algorithm>
#include <cstring>
#include <unordered_map>
#include <vector>

// DESIGN: RTL handlers perform many guest memory writebacks; targets are
// validated by explicit bounds/null checks or by the guest allocator.
// A guest AV on writeback is a guest fault.
#pragma warning(push)
#pragma warning(disable : 4834 6031)

namespace Phantom::WinAPI::Ntdll {
namespace {

// ============================================================================
// Constants
// ============================================================================

static constexpr GuestSize   kMaxAllocSize      = 128ULL * 1024 * 1024;
static constexpr GuestSize   kMaxCopySize       = 16ULL * 1024 * 1024;
static constexpr uint32_t    kMaxAnsiLen         = 4096;
static constexpr uint32_t    kMaxWideChars       = 2048;
static constexpr uint32_t    kChunkSize          = 4096;
static constexpr GuestSize   kHeapAlignment      = 16;
static constexpr uint32_t    kHeapZeroMemory     = 0x00000008;
static constexpr uint32_t    kHeapReallocInPlace = 0x00000010;

// ============================================================================
// Heap State — Per-heap allocation tracking (Meyers' singleton)
// ============================================================================

struct HeapState {
    GuestAddress regionBase = 0;
    GuestSize    regionSize = 0;
    std::unordered_map<GuestAddress, GuestSize> blocks;
};

struct RtlState {
    // heapHandle → per-heap state
    std::unordered_map<GuestAddress, HeapState> heaps;
    // Buffers allocated by Rtl string conversion functions
    std::unordered_map<GuestAddress, GuestSize> stringAllocs;

    static RtlState& Get() noexcept {
        static RtlState instance;
        return instance;
    }
};

// ============================================================================
// Helpers
// ============================================================================

[[nodiscard]] static GuestSize AlignAlloc(GuestSize size) noexcept {
    if (size == 0) size = 1;
    return (size + kHeapAlignment - 1) & ~(kHeapAlignment - 1);
}

// UNICODE_STRING / ANSI_STRING share the same physical layout:
//   x64: u16 Length | u16 MaxLen | u32 pad | u64 Buffer  (16 bytes)
//   x86: u16 Length | u16 MaxLen | u32 Buffer             (8 bytes)
struct GuestCountedString {
    uint16_t     length    = 0;
    uint16_t     maxLength = 0;
    GuestAddress buffer    = 0;
};

[[nodiscard]] static bool ReadCountedString(APIContext& ctx, GuestAddress addr,
                                            GuestCountedString& out) noexcept {
    auto& mem = ctx.Memory();
    if (mem.ReadU16(addr, out.length) != ErrorCode::Success)     return false;
    if (mem.ReadU16(addr + 2, out.maxLength) != ErrorCode::Success) return false;
    if (ctx.Is64Bit()) {
        uint64_t ptr = 0;
        if (mem.ReadU64(addr + 8, ptr) != ErrorCode::Success) return false;
        out.buffer = ptr;
    } else {
        uint32_t ptr = 0;
        if (mem.ReadU32(addr + 4, ptr) != ErrorCode::Success) return false;
        out.buffer = static_cast<GuestAddress>(ptr);
    }
    return true;
}

[[nodiscard]] static bool WriteCountedString(APIContext& ctx, GuestAddress addr,
                                             const GuestCountedString& cs) noexcept {
    auto& mem = ctx.Memory();
    if (mem.WriteU16(addr, cs.length) != ErrorCode::Success)     return false;
    if (mem.WriteU16(addr + 2, cs.maxLength) != ErrorCode::Success) return false;
    if (ctx.Is64Bit()) {
        return mem.WriteU64(addr + 8, cs.buffer) == ErrorCode::Success;
    }
    return mem.WriteU32(addr + 4, static_cast<uint32_t>(cs.buffer)) == ErrorCode::Success;
}

static void ZeroGuestRegion(VirtualMemory& mem, GuestAddress addr, GuestSize size) noexcept {
    static constexpr uint8_t zeros[kChunkSize] = {};
    GuestSize remaining = size;
    GuestSize offset    = 0;
    while (remaining > 0) {
        const auto chunk = static_cast<uint32_t>(std::min<GuestSize>(remaining, kChunkSize));
        if (mem.Write(addr + offset, zeros, chunk) != ErrorCode::Success) break;
        offset    += chunk;
        remaining -= chunk;
    }
}

// ============================================================================
// Heap Management Handlers
// ============================================================================

static bool HandleRtlAllocateHeap(APIContext& ctx) {
    const GuestAddress heapHandle = ctx.GetArgPtr(0);
    const uint32_t     flags      = ctx.GetArg32(1);
    const GuestSize    rawSize    = ctx.GetArg(2);

    if (rawSize > kMaxAllocSize) {
        ctx.SetReturn(0);
        return true;
    }

    const GuestSize allocSize = AlignAlloc(rawSize);

    auto result = ctx.Memory().Allocate(0, allocSize, MemProt::RW);
    if (!result.has_value()) {
        ctx.SetReturn(0);
        return true;
    }

    const GuestAddress addr = *result;
    auto& heap = RtlState::Get().heaps[heapHandle];
    heap.blocks[addr] = allocSize;

    if (flags & kHeapZeroMemory) {
        ZeroGuestRegion(ctx.Memory(), addr, allocSize);
    }

    ctx.SetReturn(addr);
    return true;
}

static bool HandleRtlFreeHeap(APIContext& ctx) {
    const GuestAddress heapHandle = ctx.GetArgPtr(0);
    const GuestAddress baseAddr   = ctx.GetArgPtr(2);

    if (baseAddr == 0) {
        ctx.SetReturnBool(true);
        return true;
    }

    auto& state = RtlState::Get();
    auto heapIt = state.heaps.find(heapHandle);

    if (heapIt == state.heaps.end()) {
        ctx.SetReturnBool(false);
        return true;
    }

    auto blockIt = heapIt->second.blocks.find(baseAddr);
    if (blockIt == heapIt->second.blocks.end()) {
        // Cross-heap or double-free detection: check other heaps
        for (const auto& [otherHandle, otherHeap] : state.heaps) {
            if (otherHandle != heapHandle && otherHeap.blocks.count(baseAddr)) {
                // Cross-heap free — behavioral signal, do not actually free
                ctx.SetReturnBool(false);
                return true;
            }
        }
        ctx.SetReturnBool(false);
        return true;
    }

    const GuestSize blockSize = blockIt->second;
    heapIt->second.blocks.erase(blockIt);
    ctx.Memory().Free(baseAddr, blockSize);

    ctx.SetReturnBool(true);
    return true;
}

static bool HandleRtlReAllocateHeap(APIContext& ctx) {
    const GuestAddress heapHandle = ctx.GetArgPtr(0);
    const uint32_t     flags      = ctx.GetArg32(1);
    const GuestAddress oldAddr    = ctx.GetArgPtr(2);
    const GuestSize    newRawSize = ctx.GetArg(3);

    if (newRawSize > kMaxAllocSize) {
        ctx.SetReturn(0);
        return true;
    }

    auto& state = RtlState::Get();
    auto& heap  = state.heaps[heapHandle];

    // NULL old pointer behaves like alloc
    if (oldAddr == 0) {
        const GuestSize allocSize = AlignAlloc(newRawSize);
        auto result = ctx.Memory().Allocate(0, allocSize, MemProt::RW);
        if (!result.has_value()) { ctx.SetReturn(0); return true; }
        heap.blocks[*result] = allocSize;
        if (flags & kHeapZeroMemory) {
            ZeroGuestRegion(ctx.Memory(), *result, allocSize);
        }
        ctx.SetReturn(*result);
        return true;
    }

    auto blockIt = heap.blocks.find(oldAddr);
    if (blockIt == heap.blocks.end()) {
        ctx.SetReturn(0);
        return true;
    }

    const GuestSize oldSize     = blockIt->second;
    const GuestSize newAllocSize = AlignAlloc(newRawSize);

    // In-place only: succeed only if shrinking
    if (flags & kHeapReallocInPlace) {
        if (newAllocSize <= oldSize) {
            blockIt->second = newAllocSize;
            ctx.SetReturn(oldAddr);
            return true;
        }
        ctx.SetReturn(0);
        return true;
    }

    auto newResult = ctx.Memory().Allocate(0, newAllocSize, MemProt::RW);
    if (!newResult.has_value()) {
        ctx.SetReturn(0);
        return true;
    }

    const GuestAddress newAddr  = *newResult;
    const GuestSize    copySize = std::min(oldSize, newAllocSize);

    // Copy old content
    if (copySize > 0 && copySize <= kMaxCopySize) {
        std::vector<uint8_t> buf(static_cast<size_t>(copySize));
        if (ctx.Memory().Read(oldAddr, buf.data(), static_cast<uint32_t>(copySize)) == ErrorCode::Success) {
            ctx.Memory().Write(newAddr, buf.data(), static_cast<uint32_t>(copySize));
        }
    }

    // Zero-fill new tail bytes
    if ((flags & kHeapZeroMemory) && newAllocSize > oldSize) {
        ZeroGuestRegion(ctx.Memory(), newAddr + oldSize, newAllocSize - oldSize);
    }

    heap.blocks.erase(blockIt);
    ctx.Memory().Free(oldAddr, oldSize);
    heap.blocks[newAddr] = newAllocSize;

    ctx.SetReturn(newAddr);
    return true;
}

static bool HandleRtlSizeHeap(APIContext& ctx) {
    const GuestAddress heapHandle = ctx.GetArgPtr(0);
    const GuestAddress baseAddr   = ctx.GetArgPtr(2);

    auto& state = RtlState::Get();
    auto heapIt = state.heaps.find(heapHandle);
    if (heapIt == state.heaps.end()) {
        ctx.SetReturn(~GuestSize{0});
        return true;
    }

    auto blockIt = heapIt->second.blocks.find(baseAddr);
    if (blockIt == heapIt->second.blocks.end()) {
        ctx.SetReturn(~GuestSize{0});
        return true;
    }

    ctx.SetReturn(blockIt->second);
    return true;
}

static bool HandleRtlCreateHeap(APIContext& ctx) {
    // Allocate a single page to serve as the heap "descriptor".
    // Individual allocations within the heap use VirtualMemory::Allocate.
    auto region = ctx.Memory().Allocate(0, kPageSize, MemProt::RW);
    if (!region.has_value()) {
        ctx.SetReturn(0);
        return true;
    }

    const GuestAddress heapAddr = *region;

    HeapState hs;
    hs.regionBase = heapAddr;
    hs.regionSize = kPageSize;
    RtlState::Get().heaps[heapAddr] = std::move(hs);

    ctx.SetReturn(heapAddr);
    return true;
}

static bool HandleRtlDestroyHeap(APIContext& ctx) {
    const GuestAddress heapHandle = ctx.GetArgPtr(0);

    auto& state = RtlState::Get();
    auto heapIt = state.heaps.find(heapHandle);
    if (heapIt == state.heaps.end()) {
        ctx.SetReturn(heapHandle); // non-NULL = failure
        return true;
    }

    // Free every block tracked under this heap
    for (const auto& [addr, size] : heapIt->second.blocks) {
        ctx.Memory().Free(addr, size);
    }

    // Free the heap descriptor region itself
    if (heapIt->second.regionBase != 0) {
        ctx.Memory().Free(heapIt->second.regionBase, heapIt->second.regionSize);
    }

    state.heaps.erase(heapIt);

    ctx.SetReturn(0); // NULL = success
    return true;
}

// ============================================================================
// Memory Operation Handlers
// ============================================================================

static bool HandleRtlCopyMemory(APIContext& ctx) {
    const GuestAddress dest = ctx.GetArgPtr(0);
    const GuestAddress src  = ctx.GetArgPtr(1);
    const GuestSize    len  = ctx.GetArg(2);

    if (len == 0 || dest == 0 || src == 0) return true;
    if (len > kMaxCopySize) return true;

    auto& mem = ctx.Memory();
    uint8_t buf[kChunkSize];
    GuestSize remaining = len;
    GuestSize offset    = 0;

    while (remaining > 0) {
        const auto chunk = static_cast<uint32_t>(std::min<GuestSize>(remaining, kChunkSize));
        if (mem.Read(src + offset, buf, chunk) != ErrorCode::Success) break;
        if (mem.Write(dest + offset, buf, chunk) != ErrorCode::Success) break;
        offset    += chunk;
        remaining -= chunk;
    }
    // Void function — no return value
    return true;
}

static bool HandleRtlMoveMemory(APIContext& ctx) {
    const GuestAddress dest = ctx.GetArgPtr(0);
    const GuestAddress src  = ctx.GetArgPtr(1);
    const GuestSize    len  = ctx.GetArg(2);

    if (len == 0 || dest == 0 || src == 0) return true;
    if (len > kMaxCopySize) return true;

    // Read entire source first for overlap safety
    std::vector<uint8_t> buffer(static_cast<size_t>(len));
    auto& mem = ctx.Memory();
    if (mem.Read(src, buffer.data(), static_cast<uint32_t>(len)) != ErrorCode::Success) return true;
    mem.Write(dest, buffer.data(), static_cast<uint32_t>(len));
    return true;
}

static bool HandleRtlZeroMemory(APIContext& ctx) {
    const GuestAddress dest = ctx.GetArgPtr(0);
    const GuestSize    len  = ctx.GetArg(1);

    if (len == 0 || dest == 0) return true;
    if (len > kMaxCopySize) return true;

    ZeroGuestRegion(ctx.Memory(), dest, len);
    return true;
}

static bool HandleRtlFillMemory(APIContext& ctx) {
    const GuestAddress dest = ctx.GetArgPtr(0);
    const GuestSize    len  = ctx.GetArg(1);
    const uint8_t      fill = static_cast<uint8_t>(ctx.GetArg32(2));

    if (len == 0 || dest == 0) return true;
    if (len > kMaxCopySize) return true;

    uint8_t buf[kChunkSize];
    std::memset(buf, fill, kChunkSize);

    auto& mem = ctx.Memory();
    GuestSize remaining = len;
    GuestSize offset    = 0;

    while (remaining > 0) {
        const auto chunk = static_cast<uint32_t>(std::min<GuestSize>(remaining, kChunkSize));
        if (mem.Write(dest + offset, buf, chunk) != ErrorCode::Success) break;
        offset    += chunk;
        remaining -= chunk;
    }
    return true;
}

static bool HandleRtlCompareMemory(APIContext& ctx) {
    const GuestAddress src1 = ctx.GetArgPtr(0);
    const GuestAddress src2 = ctx.GetArgPtr(1);
    const GuestSize    len  = ctx.GetArg(2);

    if (len == 0) { ctx.SetReturn(0); return true; }
    if (src1 == 0 || src2 == 0 || len > kMaxCopySize) {
        ctx.SetReturn(0);
        return true;
    }

    auto& mem = ctx.Memory();
    uint8_t buf1[kChunkSize], buf2[kChunkSize];
    GuestSize matched   = 0;
    GuestSize remaining = len;
    GuestSize offset    = 0;

    while (remaining > 0) {
        const auto chunk = static_cast<uint32_t>(std::min<GuestSize>(remaining, kChunkSize));
        if (mem.Read(src1 + offset, buf1, chunk) != ErrorCode::Success) break;
        if (mem.Read(src2 + offset, buf2, chunk) != ErrorCode::Success) break;

        for (uint32_t i = 0; i < chunk; ++i) {
            if (buf1[i] != buf2[i]) {
                ctx.SetReturn(matched + i);
                return true;
            }
        }
        matched   += chunk;
        offset    += chunk;
        remaining -= chunk;
    }

    ctx.SetReturn(matched);
    return true;
}

// ============================================================================
// String Operation Handlers
// ============================================================================

static bool HandleRtlInitUnicodeString(APIContext& ctx) {
    const GuestAddress destAddr = ctx.GetArgPtr(0);
    const GuestAddress srcAddr  = ctx.GetArgPtr(1);
    if (destAddr == 0) return true;

    GuestCountedString us{};

    if (srcAddr != 0) {
        const std::wstring str = ctx.ReadWideString(srcAddr, kMaxWideChars);
        uint32_t byteLen = static_cast<uint32_t>(str.size()) * 2;
        if (byteLen > 0xFFFE) byteLen = 0xFFFE;
        us.length    = static_cast<uint16_t>(byteLen);
        us.maxLength = static_cast<uint16_t>(byteLen + 2);
        us.buffer    = srcAddr;
    }

    WriteCountedString(ctx, destAddr, us);
    return true;
}

static bool HandleRtlInitAnsiString(APIContext& ctx) {
    const GuestAddress destAddr = ctx.GetArgPtr(0);
    const GuestAddress srcAddr  = ctx.GetArgPtr(1);
    if (destAddr == 0) return true;

    GuestCountedString as{};

    if (srcAddr != 0) {
        const std::string str = ctx.ReadAnsiString(srcAddr, kMaxAnsiLen);
        uint32_t len = static_cast<uint32_t>(str.size());
        if (len > 0xFFFE) len = 0xFFFE;
        as.length    = static_cast<uint16_t>(len);
        as.maxLength = static_cast<uint16_t>(len + 1);
        as.buffer    = srcAddr;
    }

    WriteCountedString(ctx, destAddr, as);
    return true;
}

static bool HandleRtlUnicodeStringToAnsiString(APIContext& ctx) {
    const GuestAddress destAddr  = ctx.GetArgPtr(0);
    const GuestAddress srcAddr   = ctx.GetArgPtr(1);
    const uint32_t     allocDest = ctx.GetArg32(2);

    // Read source UNICODE_STRING
    GuestCountedString src{};
    if (!ReadCountedString(ctx, srcAddr, src)) {
        ctx.SetReturnNtStatus(NT::STATUS_ACCESS_VIOLATION);
        return true;
    }

    uint32_t charCount = src.length / 2;
    if (charCount > kMaxWideChars) charCount = kMaxWideChars;

    // Read wide chars from guest buffer
    std::vector<uint16_t> wchars(charCount);
    if (charCount > 0 && src.buffer != 0) {
        if (ctx.Memory().Read(src.buffer, wchars.data(), charCount * 2) != ErrorCode::Success) {
            ctx.SetReturnNtStatus(NT::STATUS_ACCESS_VIOLATION);
            return true;
        }
    }

    // Simple Unicode→ANSI: map non-ASCII to '?'
    std::vector<uint8_t> ansi(charCount);
    for (uint32_t i = 0; i < charCount; ++i) {
        ansi[i] = (wchars[i] < 128) ? static_cast<uint8_t>(wchars[i]) : static_cast<uint8_t>('?');
    }

    const auto ansiLen    = static_cast<uint16_t>(charCount);
    const auto ansiMaxLen = static_cast<uint16_t>(charCount + 1);

    GuestCountedString dest{};

    if (allocDest) {
        auto bufOpt = ctx.Memory().Allocate(0, ansiMaxLen, MemProt::RW);
        if (!bufOpt) {
            ctx.SetReturnNtStatus(NT::STATUS_NO_MEMORY);
            return true;
        }
        dest.buffer    = *bufOpt;
        dest.length    = ansiLen;
        dest.maxLength = ansiMaxLen;
        RtlState::Get().stringAllocs[dest.buffer] = ansiMaxLen;
    } else {
        if (!ReadCountedString(ctx, destAddr, dest)) {
            ctx.SetReturnNtStatus(NT::STATUS_ACCESS_VIOLATION);
            return true;
        }
        if (dest.maxLength < ansiMaxLen) {
            ctx.SetReturnNtStatus(NT::STATUS_BUFFER_TOO_SMALL);
            return true;
        }
        dest.length = ansiLen;
    }

    if (charCount > 0) {
        ctx.Memory().Write(dest.buffer, ansi.data(), charCount);
    }
    ctx.Memory().WriteU8(dest.buffer + charCount, 0);

    WriteCountedString(ctx, destAddr, dest);
    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

static bool HandleRtlAnsiStringToUnicodeString(APIContext& ctx) {
    const GuestAddress destAddr  = ctx.GetArgPtr(0);
    const GuestAddress srcAddr   = ctx.GetArgPtr(1);
    const uint32_t     allocDest = ctx.GetArg32(2);

    GuestCountedString src{};
    if (!ReadCountedString(ctx, srcAddr, src)) {
        ctx.SetReturnNtStatus(NT::STATUS_ACCESS_VIOLATION);
        return true;
    }

    uint32_t ansiLen = src.length;
    if (ansiLen > kMaxAnsiLen) ansiLen = kMaxAnsiLen;

    std::vector<uint8_t> ansiBytes(ansiLen);
    if (ansiLen > 0 && src.buffer != 0) {
        if (ctx.Memory().Read(src.buffer, ansiBytes.data(), ansiLen) != ErrorCode::Success) {
            ctx.SetReturnNtStatus(NT::STATUS_ACCESS_VIOLATION);
            return true;
        }
    }

    // Simple ANSI→Unicode: widen each byte
    const auto unicodeByteLen = static_cast<uint16_t>(ansiLen * 2);
    const auto unicodeMaxLen  = static_cast<uint16_t>(unicodeByteLen + 2);

    std::vector<uint16_t> wchars(ansiLen);
    for (uint32_t i = 0; i < ansiLen; ++i) {
        wchars[i] = static_cast<uint16_t>(ansiBytes[i]);
    }

    GuestCountedString dest{};

    if (allocDest) {
        auto bufOpt = ctx.Memory().Allocate(0, unicodeMaxLen, MemProt::RW);
        if (!bufOpt) {
            ctx.SetReturnNtStatus(NT::STATUS_NO_MEMORY);
            return true;
        }
        dest.buffer    = *bufOpt;
        dest.length    = unicodeByteLen;
        dest.maxLength = unicodeMaxLen;
        RtlState::Get().stringAllocs[dest.buffer] = unicodeMaxLen;
    } else {
        if (!ReadCountedString(ctx, destAddr, dest)) {
            ctx.SetReturnNtStatus(NT::STATUS_ACCESS_VIOLATION);
            return true;
        }
        if (dest.maxLength < unicodeMaxLen) {
            ctx.SetReturnNtStatus(NT::STATUS_BUFFER_TOO_SMALL);
            return true;
        }
        dest.length = unicodeByteLen;
    }

    if (ansiLen > 0) {
        ctx.Memory().Write(dest.buffer, wchars.data(), ansiLen * 2);
    }
    const uint16_t nullTerm = 0;
    ctx.Memory().WriteU16(dest.buffer + ansiLen * 2, nullTerm);

    WriteCountedString(ctx, destAddr, dest);
    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

static bool HandleRtlFreeUnicodeString(APIContext& ctx) {
    const GuestAddress strAddr = ctx.GetArgPtr(0);
    if (strAddr == 0) return true;

    GuestCountedString cs{};
    if (!ReadCountedString(ctx, strAddr, cs)) return true;

    if (cs.buffer != 0) {
        auto& allocs = RtlState::Get().stringAllocs;
        auto it = allocs.find(cs.buffer);
        if (it != allocs.end()) {
            ctx.Memory().Free(cs.buffer, it->second);
            allocs.erase(it);
        }
    }

    GuestCountedString empty{};
    WriteCountedString(ctx, strAddr, empty);
    return true;
}

static bool HandleRtlFreeAnsiString(APIContext& ctx) {
    const GuestAddress strAddr = ctx.GetArgPtr(0);
    if (strAddr == 0) return true;

    GuestCountedString cs{};
    if (!ReadCountedString(ctx, strAddr, cs)) return true;

    if (cs.buffer != 0) {
        auto& allocs = RtlState::Get().stringAllocs;
        auto it = allocs.find(cs.buffer);
        if (it != allocs.end()) {
            ctx.Memory().Free(cs.buffer, it->second);
            allocs.erase(it);
        }
    }

    GuestCountedString empty{};
    WriteCountedString(ctx, strAddr, empty);
    return true;
}

// ============================================================================
// System Information Handlers
// ============================================================================

static bool HandleRtlGetVersion(APIContext& ctx) {
    const GuestAddress infoAddr = ctx.GetArgPtr(0);
    if (infoAddr == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    auto& mem = ctx.Memory();
    const auto& cfg = ctx.Config();

    // OSVERSIONINFOEXW layout (284 bytes = 0x11C):
    //   0x000: DWORD dwOSVersionInfoSize
    //   0x004: DWORD dwMajorVersion
    //   0x008: DWORD dwMinorVersion
    //   0x00C: DWORD dwBuildNumber
    //   0x010: DWORD dwPlatformId
    //   0x014: WCHAR szCSDVersion[128]  (256 bytes)
    //   0x114: WORD  wServicePackMajor
    //   0x116: WORD  wServicePackMinor
    //   0x118: WORD  wSuiteMask
    //   0x11A: BYTE  wProductType
    //   0x11B: BYTE  wReserved
    static constexpr uint32_t kStructSize = 284;

    // Zero-fill entire struct first
    ZeroGuestRegion(mem, infoAddr, kStructSize);

    mem.WriteU32(infoAddr + 0x000, kStructSize);
    mem.WriteU32(infoAddr + 0x004, 10);                // Windows 10
    mem.WriteU32(infoAddr + 0x008, 0);                 // Minor = 0
    mem.WriteU32(infoAddr + 0x00C, cfg.osBuildNumber); // 19045 (22H2)
    mem.WriteU32(infoAddr + 0x010, 2);                 // VER_PLATFORM_WIN32_NT
    // szCSDVersion left zeroed (no service pack string)
    mem.WriteU16(infoAddr + 0x114, 0);                 // wServicePackMajor
    mem.WriteU16(infoAddr + 0x116, 0);                 // wServicePackMinor
    mem.WriteU16(infoAddr + 0x118, 0x0300);            // VER_SUITE_TERMINAL | VER_SUITE_SINGLEUSERTS
    mem.WriteU8(infoAddr + 0x11A, 1);                  // VER_NT_WORKSTATION

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

static bool HandleRtlGetNtVersionNumbers(APIContext& ctx) {
    const GuestAddress majorAddr = ctx.GetArgPtr(0);
    const GuestAddress minorAddr = ctx.GetArgPtr(1);
    const GuestAddress buildAddr = ctx.GetArgPtr(2);

    auto& mem = ctx.Memory();
    const uint32_t buildNum = ctx.Config().osBuildNumber;

    if (majorAddr != 0) mem.WriteU32(majorAddr, 10);
    if (minorAddr != 0) mem.WriteU32(minorAddr, 0);
    // High nibble 0xF = free build (retail), matches real Windows
    if (buildAddr != 0) mem.WriteU32(buildAddr, 0xF0000000u | buildNum);

    // Void function — no return value
    return true;
}

// ============================================================================
// Decompression Handler (stub — behavioral flag for packed malware)
// ============================================================================

static bool HandleRtlDecompressBuffer(APIContext& ctx) {
    // Calling RtlDecompressBuffer is strong evidence of runtime unpacking.
    // We do not implement actual decompression; the behavioral analysis
    // engine records the call and raises DefenseEvasion via the APIDatabase.
    //
    // IOC: T1027.002 Software Packing — in-memory decompression of embedded
    // payloads is a hallmark of packed/obfuscated malware stages.
    ctx.AddBehaviorFlag(BehaviorFlag::DefenseEvasion);
    ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);

    // Write 0 to *FinalUncompressedSize (arg5) so the caller sees no data
    const GuestAddress finalSizePtr = ctx.GetArgPtr(5);
    if (finalSizePtr != 0) {
        ctx.Memory().WriteU32(finalSizePtr, 0);
    }

    ctx.SetReturnNtStatus(NT::STATUS_NOT_SUPPORTED);
    return true;
}

// ============================================================================
// Registration Table
// ============================================================================

static const APIRegistration kRtlRegistrations[] = {
    // Heap management
    { "ntdll.dll", "RtlAllocateHeap",              HandleRtlAllocateHeap,              3, false },
    { "ntdll.dll", "RtlFreeHeap",                  HandleRtlFreeHeap,                  3, false },
    { "ntdll.dll", "RtlReAllocateHeap",            HandleRtlReAllocateHeap,            4, false },
    { "ntdll.dll", "RtlSizeHeap",                  HandleRtlSizeHeap,                  3, false },
    { "ntdll.dll", "RtlCreateHeap",                HandleRtlCreateHeap,                6, false },
    { "ntdll.dll", "RtlDestroyHeap",               HandleRtlDestroyHeap,               1, false },
    // Memory operations
    { "ntdll.dll", "RtlCopyMemory",                HandleRtlCopyMemory,                3, false },
    { "ntdll.dll", "RtlMoveMemory",                HandleRtlMoveMemory,                3, false },
    { "ntdll.dll", "RtlZeroMemory",                HandleRtlZeroMemory,                2, false },
    { "ntdll.dll", "RtlFillMemory",                HandleRtlFillMemory,                3, false },
    { "ntdll.dll", "RtlCompareMemory",             HandleRtlCompareMemory,             3, false },
    // String operations
    { "ntdll.dll", "RtlInitUnicodeString",         HandleRtlInitUnicodeString,         2, false },
    { "ntdll.dll", "RtlInitAnsiString",            HandleRtlInitAnsiString,            2, false },
    { "ntdll.dll", "RtlUnicodeStringToAnsiString", HandleRtlUnicodeStringToAnsiString, 3, false },
    { "ntdll.dll", "RtlAnsiStringToUnicodeString", HandleRtlAnsiStringToUnicodeString, 3, false },
    { "ntdll.dll", "RtlFreeUnicodeString",         HandleRtlFreeUnicodeString,         1, false },
    { "ntdll.dll", "RtlFreeAnsiString",            HandleRtlFreeAnsiString,            1, false },
    // System information
    { "ntdll.dll", "RtlGetVersion",                HandleRtlGetVersion,                1, false },
    { "ntdll.dll", "RtlGetNtVersionNumbers",       HandleRtlGetNtVersionNumbers,       3, false },
    // Decompression
    { "ntdll.dll", "RtlDecompressBuffer",          HandleRtlDecompressBuffer,          6, false },
};

} // anonymous namespace

// ============================================================================
// Public API
// ============================================================================

void RegisterRtlHandlers(APIDispatcher& dispatcher) noexcept {
    dispatcher.RegisterBatch(kRtlRegistrations,
                             static_cast<uint32_t>(std::size(kRtlRegistrations)));
}

void ResetRtlState() noexcept {
    auto& state = RtlState::Get();
    state.heaps.clear();
    state.stringAllocs.clear();
}

} // namespace Phantom::WinAPI::Ntdll

#pragma warning(pop)

