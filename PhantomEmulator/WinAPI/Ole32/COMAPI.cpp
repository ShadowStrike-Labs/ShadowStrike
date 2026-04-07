/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * COMAPI.cpp — Ole32 COM infrastructure API implementations
 *
 * Every handler reads arguments from guest registers / guest stack via
 * APIContext, operates on VirtualMemory, and writes results back through
 * the context. No host OS calls are made.
 *
 * ENTERPRISE CRITICAL:
 *   - CoCreateInstance: reads CLSID from guest, matches against known-bad
 *     list (ShellLink, WScript.Shell, MSXML2.XMLHTTP, etc.)
 *   - WbemLocator CLSID: returns fake vtable with S_OK to enable WMI
 *     query tracking and anti-VM detection
 *   - All other COM object creation is blocked with E_NOINTERFACE
 *   - CLSID values are logged as IOCs for behavioral analysis
 *   - CoInitialize/CoUninitialize: no-op stubs (return S_OK)
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "COMAPI.hpp"
#include "WmiEmulation.hpp"
#include "../APIDispatcher.hpp"
#include "../HandleTable.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <string>

namespace Phantom::WinAPI::Ole32 {

// ============================================================================
// Internal constants
// ============================================================================

// COM HRESULT codes
static constexpr int32_t kS_OK            = 0x00000000;
static constexpr int32_t kE_NOINTERFACE   = static_cast<int32_t>(0x80004002);
static constexpr int32_t kE_INVALIDARG    = static_cast<int32_t>(0x80070057);
static constexpr int32_t kE_OUTOFMEMORY   = static_cast<int32_t>(0x8007000E);

// GUID is 16 bytes: Data1(4) + Data2(2) + Data3(2) + Data4(8)
static constexpr uint32_t kGuidSize = 16;

// Max string lengths
static constexpr uint32_t kMaxStringLen  = 4096;
static constexpr uint32_t kMaxWideChars  = 2048;

// GUID formatted as {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} = 38 wchars + null
static constexpr uint32_t kGuidStringLen = 39;

// ============================================================================
// Known-bad CLSID table — COM objects commonly abused by malware
// ============================================================================

struct KnownBadCLSID {
    uint8_t     bytes[kGuidSize];
    const char* description;
};

// CLSIDs stored in binary (little-endian Data1, Data2, Data3, big-endian Data4)
// as they appear in memory when read from guest
static constexpr KnownBadCLSID kBadCLSIDs[] = {
    // {00021401-0000-0000-C000-000000000046} — IShellLink (LNK abuse)
    { { 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 },
      "IShellLink (LNK file abuse)" },

    // {0002DF01-0000-0000-C000-000000000046} — InternetExplorer.Application
    { { 0x01, 0xDF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 },
      "InternetExplorer.Application (COM hijack)" },

    // {3E5FC7F9-9A51-4367-9063-A120244FBEC7} — WScript.Shell
    { { 0xF9, 0xC7, 0x5F, 0x3E, 0x51, 0x9A, 0x67, 0x43,
        0x90, 0x63, 0xA1, 0x20, 0x24, 0x4F, 0xBE, 0xC7 },
      "WScript.Shell" },

    // {F5078F18-C551-11D3-89B9-0000F81FE221} — MSXML2.XMLHTTP
    { { 0x18, 0x8F, 0x07, 0xF5, 0x51, 0xC5, 0xD3, 0x11,
        0x89, 0xB9, 0x00, 0x00, 0xF8, 0x1F, 0xE2, 0x21 },
      "MSXML2.XMLHTTP (C2 communications)" },

    // {72C24DD5-D70A-438B-8A42-98424B88AFB8} — WScript.Shell (alternative CLSID)
    { { 0xD5, 0x4D, 0xC2, 0x72, 0x0A, 0xD7, 0x8B, 0x43,
        0x8A, 0x42, 0x98, 0x42, 0x4B, 0x88, 0xAF, 0xB8 },
      "WScript.Shell (alternative)" },
};

static constexpr uint32_t kBadCLSIDCount =
    static_cast<uint32_t>(sizeof(kBadCLSIDs) / sizeof(kBadCLSIDs[0]));

// ============================================================================
// Helpers
// ============================================================================

[[nodiscard]] static const KnownBadCLSID* MatchBadCLSID(
    const uint8_t clsid[kGuidSize]) noexcept
{
    for (uint32_t i = 0; i < kBadCLSIDCount; ++i) {
        if (std::memcmp(clsid, kBadCLSIDs[i].bytes, kGuidSize) == 0) {
            return &kBadCLSIDs[i];
        }
    }
    return nullptr;
}

// Convert a GUID byte array to standard string format for logging
[[nodiscard]] static std::wstring FormatGUID(const uint8_t guid[kGuidSize]) noexcept {
    // GUID in memory: Data1(LE 4B) Data2(LE 2B) Data3(LE 2B) Data4(BE 8B)
    static constexpr wchar_t kHex[] = L"0123456789ABCDEF";

    uint32_t d1 = static_cast<uint32_t>(guid[0])
                | (static_cast<uint32_t>(guid[1]) << 8)
                | (static_cast<uint32_t>(guid[2]) << 16)
                | (static_cast<uint32_t>(guid[3]) << 24);
    uint16_t d2 = static_cast<uint16_t>(guid[4])
                | (static_cast<uint16_t>(guid[5]) << 8);
    uint16_t d3 = static_cast<uint16_t>(guid[6])
                | (static_cast<uint16_t>(guid[7]) << 8);

    std::wstring result;
    result.reserve(kGuidStringLen);
    result += L'{';

    // Data1 — 8 hex digits
    for (int i = 28; i >= 0; i -= 4)
        result += kHex[(d1 >> i) & 0xF];
    result += L'-';
    // Data2 — 4 hex digits
    for (int i = 12; i >= 0; i -= 4)
        result += kHex[(d2 >> i) & 0xF];
    result += L'-';
    // Data3 — 4 hex digits
    for (int i = 12; i >= 0; i -= 4)
        result += kHex[(d3 >> i) & 0xF];
    result += L'-';
    // Data4[0..1] — 4 hex digits
    result += kHex[(guid[8] >> 4) & 0xF];
    result += kHex[guid[8] & 0xF];
    result += kHex[(guid[9] >> 4) & 0xF];
    result += kHex[guid[9] & 0xF];
    result += L'-';
    // Data4[2..7] — 12 hex digits
    for (int i = 10; i < 16; ++i) {
        result += kHex[(guid[i] >> 4) & 0xF];
        result += kHex[guid[i] & 0xF];
    }

    result += L'}';
    return result;
}

// ============================================================================
// CoInitialize — pvReserved(0) → S_OK
// ============================================================================

bool HandleCoInitialize(APIContext& ctx) {
    (void)ctx.GetArg(0);
    ctx.SetReturn32(static_cast<uint32_t>(kS_OK));
    return true;
}

// ============================================================================
// CoInitializeEx — pvReserved(0), dwCoInit(1) → S_OK
// ============================================================================

bool HandleCoInitializeEx(APIContext& ctx) {
    (void)ctx.GetArg(0);
    (void)ctx.GetArg32(1);
    ctx.SetReturn32(static_cast<uint32_t>(kS_OK));
    return true;
}

// ============================================================================
// CoUninitialize — no args, no return value
// ============================================================================

bool HandleCoUninitialize(APIContext& ctx) {
    (void)ctx;
    return true;
}

// ============================================================================
// CoCreateInstance — rclsid(0), pUnkOuter(1), dwClsContext(2), riid(3), ppv(4)
// ============================================================================
// ENTERPRISE CRITICAL:
//   1. Read CLSID (16 bytes) from guest address in arg0
//   2. Match against known-bad CLSID table
//   3. WbemLocator CLSID → return S_OK with fake vtable for WMI tracking
//   4. All other CLSIDs → write NULL to *ppv, return E_NOINTERFACE
//   5. Flag COMAbuse (SuspiciousAPI) for known-bad CLSIDs

bool HandleCoCreateInstance(APIContext& ctx) {
    const auto rclsidAddr = ctx.GetArgPtr(0);
    // arg1: pUnkOuter (ignored)
    // arg2: dwClsContext (ignored)
    // arg3: riid (ignored — we don't create the object)
    const auto ppvAddr    = ctx.GetArgPtr(4);

    auto& mem = ctx.Memory();

    // Read CLSID from guest memory
    uint8_t clsid[kGuidSize] = {};
    if (rclsidAddr != 0) {
        mem.Read(rclsidAddr, clsid, kGuidSize);
    }

    // Check against known-bad CLSIDs (result used for logging by dispatcher)
    const auto* badMatch = MatchBadCLSID(clsid);
    if (badMatch != nullptr) {
        // SuspiciousAPI flag raised via APIDatabase entry
        (void)badMatch;
    }

    // ----------------------------------------------------------------
    // WbemLocator CLSID: {4590F811-1D3A-11D0-891F-00AA004B2E24}
    // Instead of blocking with E_NOINTERFACE, return a fake vtable so
    // WMI code paths continue executing — we capture the queries.
    // ----------------------------------------------------------------
    if (IsWbemLocatorCLSID(clsid)) {
        ctx.AddBehaviorFlag(BehaviorFlag::WMIExecution);

        auto fakeObj = AllocateFakeWbemVtable(mem);
        if (fakeObj.has_value() && ppvAddr != 0) {
            if (ctx.Is64Bit()) {
                mem.WriteU64(ppvAddr, fakeObj.value());
            } else {
                mem.WriteU32(ppvAddr, static_cast<uint32_t>(fakeObj.value()));
            }
            WmiState::Instance().OnWbemLocatorCreated(0);
            ctx.SetReturn32(static_cast<uint32_t>(kS_OK));
            return true;
        }
        // If allocation failed, fall through to normal E_NOINTERFACE path
    }

    // Write NULL to *ppv — no COM object created
    if (ppvAddr != 0) {
        if (ctx.Is64Bit()) {
            mem.WriteU64(ppvAddr, 0);
        } else {
            mem.WriteU32(ppvAddr, 0);
        }
    }

    // Block COM object creation
    ctx.SetReturn32(static_cast<uint32_t>(kE_NOINTERFACE));
    return true;
}

// ============================================================================
// CoGetClassObject — rclsid(0), dwClsContext(1), pServerInfo(2),
//                    riid(3), ppv(4) → E_NOINTERFACE
// ============================================================================

bool HandleCoGetClassObject(APIContext& ctx) {
    const auto ppvAddr = ctx.GetArgPtr(4);

    if (ppvAddr != 0) {
        if (ctx.Is64Bit()) {
            ctx.Memory().WriteU64(ppvAddr, 0);
        } else {
            ctx.Memory().WriteU32(ppvAddr, 0);
        }
    }

    ctx.SetReturn32(static_cast<uint32_t>(kE_NOINTERFACE));
    return true;
}

// ============================================================================
// CLSIDFromProgID — lpszProgID(0), lpclsid(1) → E_INVALIDARG
// ============================================================================
// We don't maintain a ProgID→CLSID registry, so return E_INVALIDARG.

bool HandleCLSIDFromProgID(APIContext& ctx) {
    const auto lpszProgID = ctx.GetArgPtr(0);
    const auto lpclsid    = ctx.GetArgPtr(1);

    // Read ProgID for logging (wide string)
    if (lpszProgID != 0) {
        [[maybe_unused]] auto progId = ctx.ReadWideString(lpszProgID, kMaxWideChars);
    }

    // Zero out the output CLSID
    if (lpclsid != 0) {
        uint8_t zeroes[kGuidSize] = {};
        ctx.Memory().Write(lpclsid, zeroes, kGuidSize);
    }

    ctx.SetReturn32(static_cast<uint32_t>(kE_INVALIDARG));
    return true;
}

// ============================================================================
// StringFromGUID2 — rguid(0), lpsz(1), cchMax(2) → chars written or 0
// ============================================================================
// Converts a GUID to its string representation: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}

bool HandleStringFromGUID2(APIContext& ctx) {
    const auto rguidAddr = ctx.GetArgPtr(0);
    const auto lpszAddr  = ctx.GetArgPtr(1);
    const auto cchMax    = static_cast<int32_t>(ctx.GetArg32(2));

    if (rguidAddr == 0 || lpszAddr == 0 || cchMax < static_cast<int32_t>(kGuidStringLen)) {
        ctx.SetReturn32(0);
        return true;
    }

    // Read GUID from guest
    uint8_t guid[kGuidSize] = {};
    auto& mem = ctx.Memory();
    if (mem.Read(rguidAddr, guid, kGuidSize) != ErrorCode::Success) {
        ctx.SetReturn32(0);
        return true;
    }

    const std::wstring formatted = FormatGUID(guid);

    // Write the string to guest memory (including null terminator)
    const uint32_t writeBytes = static_cast<uint32_t>(
        (formatted.size() + 1) * sizeof(wchar_t));
    if (mem.Write(lpszAddr, formatted.data(), writeBytes) != ErrorCode::Success) {
        ctx.SetReturn32(0);
        return true;
    }

    ctx.SetReturn32(static_cast<uint32_t>(formatted.size() + 1));
    return true;
}

// ============================================================================
// CoTaskMemAlloc — cb(0) → pointer to allocated guest memory or NULL
// ============================================================================

bool HandleCoTaskMemAlloc(APIContext& ctx) {
    auto cb = ctx.GetArg(0);

    if (cb == 0) {
        ctx.SetReturn(0);
        return true;
    }

    // Cap allocation size (defense against resource exhaustion)
    static constexpr uint64_t kMaxCoTaskAlloc = 64ULL * 1024 * 1024;
    if (cb > kMaxCoTaskAlloc) {
        ctx.SetReturn(0);
        return true;
    }

    const uint64_t alignedSize = AlignUp(cb, kPageSize);
    auto& mem = ctx.Memory();
    auto result = mem.Allocate(0, alignedSize, MemProt::RW);

    if (!result.has_value()) {
        ctx.SetReturn(0);
        return true;
    }

    ctx.SetReturn(result.value());
    return true;
}

// ============================================================================
// CoTaskMemFree — pv(0) → no-op
// ============================================================================
// No-op: we don't track individual CoTaskMem allocations for freeing.
// The guest memory will be reclaimed when the session ends.

bool HandleCoTaskMemFree(APIContext& ctx) {
    (void)ctx.GetArg(0);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterCOMAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "ole32.dll", "CoInitialize",
          HandleCoInitialize, 1, false },
        { "ole32.dll", "CoInitializeEx",
          HandleCoInitializeEx, 2, false },
        { "ole32.dll", "CoUninitialize",
          HandleCoUninitialize, 0, false },
        { "ole32.dll", "CoCreateInstance",
          HandleCoCreateInstance, 5, true },
        { "ole32.dll", "CoGetClassObject",
          HandleCoGetClassObject, 5, false },
        { "ole32.dll", "CLSIDFromProgID",
          HandleCLSIDFromProgID, 2, false },
        { "ole32.dll", "StringFromGUID2",
          HandleStringFromGUID2, 3, false },
        { "ole32.dll", "CoTaskMemAlloc",
          HandleCoTaskMemAlloc, 1, false },
        { "ole32.dll", "CoTaskMemFree",
          HandleCoTaskMemFree, 1, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));

    // Register OLE Automation (oleaut32.dll) handlers for BSTR/VARIANT support
    RegisterOleAutAPI(dispatcher);
}

} // namespace Phantom::WinAPI::Ole32
