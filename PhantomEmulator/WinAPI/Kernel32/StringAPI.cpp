/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * StringAPI.cpp — Kernel32 string manipulation API handlers
 *
 * All string operations enforce a hard cap on read/write lengths to
 * prevent a malicious guest from exhausting host memory. The cap
 * (kMaxGuestStringLen) is large enough for any legitimate Win32 usage
 * but small enough to prevent resource exhaustion attacks.
 *
 * MultiByteToWideChar/WideCharToMultiByte perform a simplified
 * ASCII ↔ UTF-16LE conversion. This is sufficient for the overwhelming
 * majority of malware, which operates within the ASCII/Latin-1 range.
 * Full UTF-8 multi-byte sequence handling is intentionally omitted:
 * correctness is secondary to detection, and any malware relying on
 * complex encoding would still be captured by behavioral analysis.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "StringAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

// DESIGN: the guest-memory writeback paths in this translation unit are all
// best-effort content reflows (emulated strncpy / CRT conversion). A partial
// writeback is exactly equivalent to a guest-side AV the guest must handle,
// so the [[nodiscard]] results are intentionally discarded. Pragma is
// namespace-scoped; every path that materially affects control flow (size
// queries, ERROR_INSUFFICIENT_BUFFER) is still checked explicitly.
#pragma warning(push)
#pragma warning(disable : 4834 6031)

namespace Phantom::WinAPI::Kernel32 {

// ============================================================================
// Constants
// ============================================================================

namespace {

// Maximum guest string length we'll read or write (defense against exhaustion)
constexpr uint32_t kMaxGuestStringLen  = 65536;
constexpr uint32_t kMaxGuestStringChars = 32768;

} // anonymous namespace

// ============================================================================
// Registration
// ============================================================================

void RegisterStringAPI(APIDispatcher& dispatcher) noexcept {
    static const APIRegistration regs[] = {
        { "kernel32.dll", "lstrlenA",            HandleLstrlenA,            1, false },
        { "kernel32.dll", "lstrlenW",            HandleLstrlenW,            1, false },
        { "kernel32.dll", "lstrcmpA",            HandleLstrcmpA,            2, false },
        { "kernel32.dll", "lstrcmpW",            HandleLstrcmpW,            2, false },
        { "kernel32.dll", "lstrcpyA",            HandleLstrcpyA,            2, false },
        { "kernel32.dll", "lstrcpyW",            HandleLstrcpyW,            2, false },
        { "kernel32.dll", "MultiByteToWideChar", HandleMultiByteToWideChar, 6, false },
        { "kernel32.dll", "WideCharToMultiByte", HandleWideCharToMultiByte, 8, false },
    };
    dispatcher.RegisterBatch(regs, static_cast<uint32_t>(std::size(regs)));
}

// ============================================================================
// lstrlenA / lstrlenW
// ============================================================================

bool HandleLstrlenA(APIContext& ctx) {
    GuestAddress strAddr = ctx.GetArgPtr(0);
    if (strAddr == 0) {
        ctx.SetReturn32(0);
        return true;
    }

    std::string s = ctx.ReadAnsiString(strAddr, kMaxGuestStringLen);
    ctx.SetReturn32(static_cast<uint32_t>(s.size()));
    return true;
}

bool HandleLstrlenW(APIContext& ctx) {
    GuestAddress strAddr = ctx.GetArgPtr(0);
    if (strAddr == 0) {
        ctx.SetReturn32(0);
        return true;
    }

    std::wstring s = ctx.ReadWideString(strAddr, kMaxGuestStringChars);
    ctx.SetReturn32(static_cast<uint32_t>(s.size()));
    return true;
}

// ============================================================================
// lstrcmpA / lstrcmpW
// ============================================================================

bool HandleLstrcmpA(APIContext& ctx) {
    GuestAddress addr1 = ctx.GetArgPtr(0);
    GuestAddress addr2 = ctx.GetArgPtr(1);

    std::string s1 = (addr1 != 0) ? ctx.ReadAnsiString(addr1, kMaxGuestStringLen) : std::string{};
    std::string s2 = (addr2 != 0) ? ctx.ReadAnsiString(addr2, kMaxGuestStringLen) : std::string{};

    int result = s1.compare(s2);
    // Win32 lstrcmp returns <0, 0, or >0 — same as std::string::compare
    ctx.SetReturn32(static_cast<uint32_t>(static_cast<int32_t>(
        result < 0 ? -1 : (result > 0 ? 1 : 0))));
    return true;
}

bool HandleLstrcmpW(APIContext& ctx) {
    GuestAddress addr1 = ctx.GetArgPtr(0);
    GuestAddress addr2 = ctx.GetArgPtr(1);

    std::wstring s1 = (addr1 != 0) ? ctx.ReadWideString(addr1, kMaxGuestStringChars) : std::wstring{};
    std::wstring s2 = (addr2 != 0) ? ctx.ReadWideString(addr2, kMaxGuestStringChars) : std::wstring{};

    int result = s1.compare(s2);
    ctx.SetReturn32(static_cast<uint32_t>(static_cast<int32_t>(
        result < 0 ? -1 : (result > 0 ? 1 : 0))));
    return true;
}

// ============================================================================
// lstrcpyA / lstrcpyW
// ============================================================================
// Copies from source to destination in guest memory.
// Returns the destination pointer (arg0).
// Capped to prevent unbounded guest memory traversal.

bool HandleLstrcpyA(APIContext& ctx) {
    GuestAddress dstAddr = ctx.GetArgPtr(0);
    GuestAddress srcAddr = ctx.GetArgPtr(1);

    if (dstAddr == 0 || srcAddr == 0) {
        ctx.SetReturn(0);
        return true;
    }

    std::string src = ctx.ReadAnsiString(srcAddr, kMaxGuestStringLen);
    auto len = static_cast<uint32_t>(src.size());

    // Write source + null terminator to destination
    ctx.Memory().Write(dstAddr, src.data(), len);
    uint8_t nul = 0;
    ctx.Memory().Write(dstAddr + len, &nul, 1);

    ctx.SetReturn(dstAddr);
    return true;
}

bool HandleLstrcpyW(APIContext& ctx) {
    GuestAddress dstAddr = ctx.GetArgPtr(0);
    GuestAddress srcAddr = ctx.GetArgPtr(1);

    if (dstAddr == 0 || srcAddr == 0) {
        ctx.SetReturn(0);
        return true;
    }

    std::wstring src = ctx.ReadWideString(srcAddr, kMaxGuestStringChars);

    // Write each wide character as uint16_t (UTF-16LE guest format)
    for (uint32_t i = 0; i < static_cast<uint32_t>(src.size()); ++i) {
        auto ch = static_cast<uint16_t>(src[i]);
        ctx.Memory().WriteU16(dstAddr + i * 2, ch);
    }
    // Null terminator
    ctx.Memory().WriteU16(dstAddr + static_cast<uint32_t>(src.size()) * 2, 0);

    ctx.SetReturn(dstAddr);
    return true;
}

// ============================================================================
// MultiByteToWideChar
// ============================================================================
// int MultiByteToWideChar(
//     UINT CodePage,        // arg0: code page (0=CP_ACP, 65001=CP_UTF8)
//     DWORD dwFlags,        // arg1: flags (ignored in simplified impl)
//     LPCCH lpMultiByteStr, // arg2: source multi-byte string
//     int cbMultiByte,      // arg3: source length (-1 = null-terminated)
//     LPWSTR lpWideCharStr, // arg4: destination wide buffer
//     int cchWideChar       // arg5: dest buffer size in WCHARs (0 = query)
// )
//
// Returns: number of wide characters written, or required size if arg5==0.
// Returns 0 on error (sets last error).

bool HandleMultiByteToWideChar(APIContext& ctx) {
    // arg0: codePage (simplified — treat everything as Latin-1/ASCII)
    // arg1: flags (ignored)
    GuestAddress srcAddr     = ctx.GetArgPtr(2);
    int32_t      cbMultiByte = static_cast<int32_t>(ctx.GetArg32(3));
    GuestAddress dstAddr     = ctx.GetArgPtr(4);
    int32_t      cchWideChar = static_cast<int32_t>(ctx.GetArg32(5));

    if (srcAddr == 0) {
        ctx.SetLastError(Win32::ERROR_INVALID_PARAMETER);
        ctx.SetReturn32(0);
        return true;
    }

    // Determine source bytes
    std::vector<uint8_t> srcBuf;

    if (cbMultiByte == -1) {
        // Null-terminated: read string, then append null byte
        std::string s = ctx.ReadAnsiString(srcAddr, kMaxGuestStringLen);
        srcBuf.assign(s.begin(), s.end());
        srcBuf.push_back(0);
    } else if (cbMultiByte > 0) {
        auto len = static_cast<uint32_t>(
            std::min(cbMultiByte, static_cast<int32_t>(kMaxGuestStringLen)));
        srcBuf.resize(len);
        ctx.Memory().Read(srcAddr, srcBuf.data(), len);
    } else {
        ctx.SetLastError(Win32::ERROR_INVALID_PARAMETER);
        ctx.SetReturn32(0);
        return true;
    }

    // For simplified ASCII/Latin-1 conversion: 1 byte → 1 wide char
    auto requiredChars = static_cast<int32_t>(srcBuf.size());

    // Size query
    if (cchWideChar == 0) {
        ctx.SetReturn32(static_cast<uint32_t>(requiredChars));
        return true;
    }

    // Buffer too small
    if (cchWideChar < requiredChars) {
        ctx.SetLastError(Win32::ERROR_INSUFFICIENT_BUFFER);
        ctx.SetReturn32(0);
        return true;
    }

    // Convert: each byte → uint16_t, write to guest memory
    for (uint32_t i = 0; i < srcBuf.size(); ++i) {
        auto wc = static_cast<uint16_t>(srcBuf[i]);
        ctx.Memory().WriteU16(dstAddr + i * 2, wc);
    }

    ctx.SetReturn32(static_cast<uint32_t>(requiredChars));
    return true;
}

// ============================================================================
// WideCharToMultiByte
// ============================================================================
// int WideCharToMultiByte(
//     UINT CodePage,            // arg0
//     DWORD dwFlags,            // arg1
//     LPCWCH lpWideCharStr,     // arg2: source wide string
//     int cchWideChar,          // arg3: source length in WCHARs (-1 = null-term)
//     LPSTR lpMultiByteStr,     // arg4: destination buffer
//     int cbMultiByte,          // arg5: dest buffer size in bytes (0 = query)
//     LPCCH lpDefaultChar,      // arg6: default char for unmappable (ignored)
//     LPBOOL lpUsedDefaultChar  // arg7: [out] flag if default was used (ignored)
// )

bool HandleWideCharToMultiByte(APIContext& ctx) {
    // arg0: codePage (simplified)
    // arg1: flags (ignored)
    GuestAddress srcAddr     = ctx.GetArgPtr(2);
    int32_t      cchWideChar = static_cast<int32_t>(ctx.GetArg32(3));
    GuestAddress dstAddr     = ctx.GetArgPtr(4);
    int32_t      cbMultiByte = static_cast<int32_t>(ctx.GetArg32(5));
    // arg6, arg7: lpDefaultChar, lpUsedDefaultChar (ignored)

    if (srcAddr == 0) {
        ctx.SetLastError(Win32::ERROR_INVALID_PARAMETER);
        ctx.SetReturn32(0);
        return true;
    }

    // Determine source wide characters
    std::vector<uint16_t> srcBuf;

    if (cchWideChar == -1) {
        // Null-terminated: read wide string, then append null
        std::wstring s = ctx.ReadWideString(srcAddr, kMaxGuestStringChars);
        srcBuf.reserve(s.size() + 1);
        for (wchar_t wc : s) {
            srcBuf.push_back(static_cast<uint16_t>(wc));
        }
        srcBuf.push_back(0);
    } else if (cchWideChar > 0) {
        auto len = static_cast<uint32_t>(
            std::min(cchWideChar, static_cast<int32_t>(kMaxGuestStringChars)));
        srcBuf.resize(len);
        ctx.Memory().Read(srcAddr, srcBuf.data(), len * 2);
    } else {
        ctx.SetLastError(Win32::ERROR_INVALID_PARAMETER);
        ctx.SetReturn32(0);
        return true;
    }

    // For simplified conversion: 1 wide char → 1 byte
    // Non-ASCII chars mapped to '?'
    auto requiredBytes = static_cast<int32_t>(srcBuf.size());

    // Size query
    if (cbMultiByte == 0) {
        ctx.SetReturn32(static_cast<uint32_t>(requiredBytes));
        return true;
    }

    // Buffer too small
    if (cbMultiByte < requiredBytes) {
        ctx.SetLastError(Win32::ERROR_INSUFFICIENT_BUFFER);
        ctx.SetReturn32(0);
        return true;
    }

    // Convert: each uint16_t → byte, write to guest memory
    for (uint32_t i = 0; i < srcBuf.size(); ++i) {
        uint8_t byte = (srcBuf[i] <= 127)
            ? static_cast<uint8_t>(srcBuf[i])
            : static_cast<uint8_t>('?');
        ctx.Memory().WriteU8(dstAddr + i, byte);
    }

    ctx.SetReturn32(static_cast<uint32_t>(requiredBytes));
    return true;
}

} // namespace Phantom::WinAPI::Kernel32

#pragma warning(pop)
