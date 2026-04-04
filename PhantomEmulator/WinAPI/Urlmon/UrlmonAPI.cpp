/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * UrlmonAPI.cpp — Urlmon URL download and validation API implementations
 *
 * Every handler reads arguments from guest registers / guest stack via
 * APIContext, operates on VirtualMemory, and writes results back through
 * the context. No host OS calls are made.
 *
 * ENTERPRISE CRITICAL:
 *   - URLDownloadToFile is one of the most common payload download methods
 *     used by droppers, stagers, and fileless malware
 *   - URL and destination filename are critical IOCs
 *   - Downloads are simulated as success (S_OK) to reveal the full attack
 *     chain, but no actual file is written
 *   - Flags: NetworkC2 (via APIDatabase behavioral detection)
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "UrlmonAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../HandleTable.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <cstring>
#include <string>
#include <string_view>

namespace Phantom::WinAPI::Urlmon {

// ============================================================================
// Internal constants
// ============================================================================

// HRESULT
static constexpr int32_t kS_OK = 0x00000000;

// Max string read length (defense against hostile input)
static constexpr uint32_t kMaxStringLen = 4096;
static constexpr uint32_t kMaxWideChars = 2048;

// ============================================================================
// URLDownloadToFileA — pCaller(0), szURL(1), szFileName(2),
//                      dwReserved(3), lpfnCB(4)
// ============================================================================
// CRITICAL IOC: URL + filename reveal payload staging / drive-by downloads.
// Return S_OK to simulate success and let the malware continue its chain.

bool HandleURLDownloadToFileA(APIContext& ctx) {
    // arg0: pCaller (IUnknown*, ignored)
    const auto szURL      = ctx.GetArgPtr(1);
    const auto szFileName = ctx.GetArgPtr(2);
    // arg3: dwReserved (must be 0, ignored)
    // arg4: lpfnCB (IBindStatusCallback*, ignored)

    std::string url;
    std::string fileName;

    if (szURL != 0) {
        url = ctx.ReadAnsiString(szURL, kMaxStringLen);
    }
    if (szFileName != 0) {
        fileName = ctx.ReadAnsiString(szFileName, kMaxStringLen);
    }

    // URL and filename are captured in the API call log by the dispatcher.
    // The NetworkC2 behavioral flag is raised via the APIDatabase entry.
    // No actual file is created in the virtual filesystem — we simulate
    // success so the malware reveals subsequent stages.

    ctx.SetReturn32(static_cast<uint32_t>(kS_OK));
    return true;
}

// ============================================================================
// URLDownloadToFileW — pCaller(0), szURL(1), szFileName(2),
//                      dwReserved(3), lpfnCB(4)
// ============================================================================

bool HandleURLDownloadToFileW(APIContext& ctx) {
    const auto szURL      = ctx.GetArgPtr(1);
    const auto szFileName = ctx.GetArgPtr(2);

    std::wstring url;
    std::wstring fileName;

    if (szURL != 0) {
        url = ctx.ReadWideString(szURL, kMaxWideChars);
    }
    if (szFileName != 0) {
        fileName = ctx.ReadWideString(szFileName, kMaxWideChars);
    }

    ctx.SetReturn32(static_cast<uint32_t>(kS_OK));
    return true;
}

// ============================================================================
// URLDownloadToCacheFileA — pCaller(0), szURL(1), szFileName(2),
//                           cchFileName(3), dwReserved(4), lpfnCB(5)
// ============================================================================
// Similar to URLDownloadToFile but writes to the URL cache.
// We log the URL and return S_OK, writing a fake cache path.

bool HandleURLDownloadToCacheFileA(APIContext& ctx) {
    const auto szURL       = ctx.GetArgPtr(1);
    const auto szFileName  = ctx.GetArgPtr(2);
    const auto cchFileName = ctx.GetArg32(3);

    std::string url;
    if (szURL != 0) {
        url = ctx.ReadAnsiString(szURL, kMaxStringLen);
    }

    // Write a fake cache file path to the output buffer
    if (szFileName != 0 && cchFileName > 0) {
        static constexpr std::string_view kFakeCachePath =
            "C:\\Users\\JSmith\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.IE5\\cached.tmp";
        const uint32_t writeLen = std::min(
            static_cast<uint32_t>(kFakeCachePath.size()),
            cchFileName - 1);
        auto& mem = ctx.Memory();
        mem.Write(szFileName, kFakeCachePath.data(), writeLen);
        mem.WriteU8(szFileName + writeLen, 0);
    }

    ctx.SetReturn32(static_cast<uint32_t>(kS_OK));
    return true;
}

// ============================================================================
// URLDownloadToCacheFileW — pCaller(0), szURL(1), szFileName(2),
//                           cchFileName(3), dwReserved(4), lpfnCB(5)
// ============================================================================

bool HandleURLDownloadToCacheFileW(APIContext& ctx) {
    const auto szURL       = ctx.GetArgPtr(1);
    const auto szFileName  = ctx.GetArgPtr(2);
    const auto cchFileName = ctx.GetArg32(3);

    std::wstring url;
    if (szURL != 0) {
        url = ctx.ReadWideString(szURL, kMaxWideChars);
    }

    if (szFileName != 0 && cchFileName > 0) {
        static constexpr std::wstring_view kFakeCachePath =
            L"C:\\Users\\JSmith\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.IE5\\cached.tmp";
        const uint32_t writeChars = std::min(
            static_cast<uint32_t>(kFakeCachePath.size()),
            cchFileName - 1);
        auto& mem = ctx.Memory();
        mem.Write(szFileName, kFakeCachePath.data(),
                  writeChars * static_cast<uint32_t>(sizeof(wchar_t)));
        mem.WriteU16(szFileName + writeChars * sizeof(wchar_t), 0);
    }

    ctx.SetReturn32(static_cast<uint32_t>(kS_OK));
    return true;
}

// ============================================================================
// IsValidURL — pBC(0), szURL(1), dwReserved(2) → S_OK
// ============================================================================
// Always return S_OK — all URLs are "valid" in emulation.

bool HandleIsValidURL(APIContext& ctx) {
    const auto szURL = ctx.GetArgPtr(1);

    // Read URL for logging
    if (szURL != 0) {
        [[maybe_unused]] auto url = ctx.ReadWideString(szURL, kMaxWideChars);
    }

    ctx.SetReturn32(static_cast<uint32_t>(kS_OK));
    return true;
}

// ============================================================================
// CoInternetIsFeatureEnabled — FeatureEntry(0), dwFlags(1) → S_OK
// ============================================================================

bool HandleCoInternetIsFeatureEnabled(APIContext& ctx) {
    (void)ctx.GetArg32(0);
    (void)ctx.GetArg32(1);

    ctx.SetReturn32(static_cast<uint32_t>(kS_OK));
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterUrlmonAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "urlmon.dll", "URLDownloadToFileA",
          HandleURLDownloadToFileA, 5, true },
        { "urlmon.dll", "URLDownloadToFileW",
          HandleURLDownloadToFileW, 5, true },
        { "urlmon.dll", "URLDownloadToCacheFileA",
          HandleURLDownloadToCacheFileA, 6, false },
        { "urlmon.dll", "URLDownloadToCacheFileW",
          HandleURLDownloadToCacheFileW, 6, false },
        { "urlmon.dll", "IsValidURL",
          HandleIsValidURL, 3, false },
        { "urlmon.dll", "CoInternetIsFeatureEnabled",
          HandleCoInternetIsFeatureEnabled, 2, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Urlmon
