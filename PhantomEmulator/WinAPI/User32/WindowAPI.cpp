/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * WindowAPI.cpp — User32 window management API implementations
 *
 * Every handler reads arguments from guest registers / guest stack via
 * APIContext, operates on VirtualMemory, and writes results back through
 * the context. No host OS calls are made.
 *
 * ANTI-EVASION:
 *   - FindWindow: ALWAYS NULL for analysis tools (OllyDbg, IDA, Wireshark, etc.)
 *   - FindWindow: Shell_TrayWnd → fake HWND (system looks real)
 *   - SM_REMOTESESSION: 0 (not RDP — defeats sandbox detection)
 *   - Screen resolution: 1920×1080 (defeats low-res VM detection)
 *   - MessageBox: logs text for ransomware note detection
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "WindowAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../HandleTable.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <algorithm>
#include <cstring>
#include <string>
#include <string_view>

// DESIGN: Guest-memory writebacks on GetWindowText/GetClassName are
// [[nodiscard]] but a failed write is a guest-side fault, not ours.
#pragma warning(push)
#pragma warning(disable : 4834 6031)

namespace Phantom::WinAPI::User32 {

// ============================================================================
// Internal constants
// ============================================================================

// Fake HWNDs — realistic but non-colliding with handle table allocations.
// Windows typically uses kernel-allocated desktop heap pointers for HWNDs.
static constexpr uint64_t kFakeDesktopHwnd      = 0x00010010;
static constexpr uint64_t kFakeShellHwnd        = 0x00010020;
static constexpr uint64_t kFakeForegroundHwnd   = 0x00010040;
static constexpr uint64_t kFakeTrayHwnd         = 0x00010030;

// MessageBox return values (matching Windows SDK)
static constexpr uint32_t kIDOK = 1;

// GetSystemMetrics indices
static constexpr int32_t SM_CXSCREEN       = 0;
static constexpr int32_t SM_CYSCREEN       = 1;
static constexpr int32_t SM_CLEANBOOT      = 67;
static constexpr int32_t SM_REMOTESESSION  = 0x1000;

// Screen dimensions — 1920×1080 to look like a real desktop, not a VM
static constexpr int32_t kScreenWidth  = 1920;
static constexpr int32_t kScreenHeight = 1080;

// Cursor position — center of screen
static constexpr int32_t kCursorX = 960;
static constexpr int32_t kCursorY = 540;

// Max string read length (defense against hostile input)
static constexpr uint32_t kMaxStringLen  = 4096;
static constexpr uint32_t kMaxWideChars  = 2048;

// ============================================================================
// Ransom-note keyword detection
// ============================================================================
// MessageBox text containing these substrings may indicate a ransom note.
// Case-insensitive match against lowercased text.

static constexpr std::string_view kRansomKeywords[] = {
    "encrypt",  "decrypt",  "ransom",   "bitcoin",  "btc",
    "wallet",   "payment",  "locked",   "recover",  "your files",
    "your data", "restore", "pay",      "deadline",  "monero",
    "xmr",      "tor",      ".onion",   "key",       "unlock",
};

[[nodiscard]] static bool ContainsRansomKeyword(std::string_view text) noexcept {
    // Convert to lowercase for case-insensitive matching
    std::string lower;
    lower.reserve(text.size());
    for (char c : text) {
        lower.push_back(static_cast<char>((c >= 'A' && c <= 'Z') ? c + 32 : c));
    }
    std::string_view lowView = lower;
    for (const auto& kw : kRansomKeywords) {
        if (lowView.find(kw) != std::string_view::npos) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// Narrow-to-wide helper for shared FindWindow logic
// ============================================================================

[[nodiscard]] static bool IsShellTrayWnd(std::string_view name) noexcept {
    // Case-insensitive comparison
    constexpr std::string_view kTray = "Shell_TrayWnd";
    if (name.size() != kTray.size()) return false;
    for (size_t i = 0; i < name.size(); ++i) {
        char a = name[i];
        char b = kTray[i];
        if (a >= 'A' && a <= 'Z') a += 32;
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b) return false;
    }
    return true;
}

[[nodiscard]] static bool IsShellTrayWndW(std::wstring_view name) noexcept {
    constexpr std::wstring_view kTray = L"Shell_TrayWnd";
    if (name.size() != kTray.size()) return false;
    for (size_t i = 0; i < name.size(); ++i) {
        wchar_t a = name[i];
        wchar_t b = kTray[i];
        if (a >= L'A' && a <= L'Z') a += 32;
        if (b >= L'A' && b <= L'Z') b += 32;
        if (a != b) return false;
    }
    return true;
}

// ============================================================================
// MessageBoxA — hWnd(0), lpText(1), lpCaption(2), uType(3)
// ============================================================================

bool HandleMessageBoxA(APIContext& ctx) {
    // arg0: hWnd (ignored)
    const auto lpText    = ctx.GetArgPtr(1);
    const auto lpCaption = ctx.GetArgPtr(2);
    // arg3: uType (ignored for return, but we read it for logging)

    std::string text;
    std::string caption;

    if (lpText != 0) {
        text = ctx.ReadAnsiString(lpText, kMaxStringLen);
    }
    if (lpCaption != 0) {
        caption = ctx.ReadAnsiString(lpCaption, kMaxStringLen);
    }

    // Check for ransom-note indicators in the message text.
    // Wire SuspiciousAPI explicitly — the APIDatabase entry for MessageBoxA
    // is BehaviorFlag::None, so without this call the ransom-note heuristic
    // was dead (the old comment claimed the dispatcher raised it; it did not).
    if (!text.empty() && ContainsRansomKeyword(text)) {
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn32(kIDOK);
    return true;
}

// ============================================================================
// MessageBoxW — hWnd(0), lpText(1), lpCaption(2), uType(3)
// ============================================================================

bool HandleMessageBoxW(APIContext& ctx) {
    const auto lpText    = ctx.GetArgPtr(1);
    const auto lpCaption = ctx.GetArgPtr(2);

    std::wstring text;
    std::wstring caption;

    if (lpText != 0) {
        text = ctx.ReadWideString(lpText, kMaxWideChars);
    }
    if (lpCaption != 0) {
        caption = ctx.ReadWideString(lpCaption, kMaxWideChars);
    }

    // Check for ransom-note indicators (convert wide to narrow for keyword scan)
    if (!text.empty()) {
        std::string narrow;
        narrow.reserve(text.size());
        for (wchar_t wc : text) {
            narrow.push_back(static_cast<char>(wc < 128 ? wc : '?'));
        }
        if (ContainsRansomKeyword(narrow)) {
            ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
        }
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn32(kIDOK);
    return true;
}

// ============================================================================
// FindWindowA — lpClassName(0), lpWindowName(1)
// ============================================================================
// ANTI-EVASION: Return NULL for all queries EXCEPT Shell_TrayWnd.
// Malware uses FindWindow to detect debuggers (OllyDbg, x64dbg, IDA),
// sandbox tools (Wireshark, ProcessMonitor), and AV products.
// Returning NULL tells the malware none of these tools are running.
// Exception: Shell_TrayWnd must exist or the system looks fake.

bool HandleFindWindowA(APIContext& ctx) {
    const auto lpClassName  = ctx.GetArgPtr(0);
    const auto lpWindowName = ctx.GetArgPtr(1);

    std::string className;
    std::string windowName;

    if (lpClassName != 0) {
        className = ctx.ReadAnsiString(lpClassName, kMaxStringLen);
    }
    if (lpWindowName != 0) {
        windowName = ctx.ReadAnsiString(lpWindowName, kMaxStringLen);
    }

    // Shell_TrayWnd — return fake HWND to look like a real desktop
    if (!className.empty() && IsShellTrayWnd(className)) {
        ctx.SetLastError(Win32::ERROR_SUCCESS);
        ctx.SetReturn(kFakeTrayHwnd);
        return true;
    }

    // ALL other queries: return NULL (no windows found)
    ctx.SetLastError(Win32::ERROR_FILE_NOT_FOUND);
    ctx.SetReturn(0);
    return true;
}

// ============================================================================
// FindWindowW — lpClassName(0), lpWindowName(1)
// ============================================================================

bool HandleFindWindowW(APIContext& ctx) {
    const auto lpClassName  = ctx.GetArgPtr(0);
    const auto lpWindowName = ctx.GetArgPtr(1);

    std::wstring className;
    std::wstring windowName;

    if (lpClassName != 0) {
        className = ctx.ReadWideString(lpClassName, kMaxWideChars);
    }
    if (lpWindowName != 0) {
        windowName = ctx.ReadWideString(lpWindowName, kMaxWideChars);
    }

    if (!className.empty() && IsShellTrayWndW(className)) {
        ctx.SetLastError(Win32::ERROR_SUCCESS);
        ctx.SetReturn(kFakeTrayHwnd);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_FILE_NOT_FOUND);
    ctx.SetReturn(0);
    return true;
}

// ============================================================================
// GetForegroundWindow — no args → fake HWND
// ============================================================================

bool HandleGetForegroundWindow(APIContext& ctx) {
    ctx.SetReturn(kFakeForegroundHwnd);
    return true;
}

// ============================================================================
// GetDesktopWindow — no args → fake HWND
// ============================================================================

bool HandleGetDesktopWindow(APIContext& ctx) {
    ctx.SetReturn(kFakeDesktopHwnd);
    return true;
}

// ============================================================================
// GetShellWindow — no args → fake HWND
// ============================================================================

bool HandleGetShellWindow(APIContext& ctx) {
    ctx.SetReturn(kFakeShellHwnd);
    return true;
}

// ============================================================================
// ShowWindow — hWnd(0), nCmdShow(1) → TRUE
// ============================================================================

bool HandleShowWindow(APIContext& ctx) {
    // No-op: we don't render windows. Return TRUE (previous visibility state).
    (void)ctx.GetArg(0);
    (void)ctx.GetArg32(1);

    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// PostMessageA/W — hWnd(0), Msg(1), wParam(2), lParam(3) → TRUE
// ============================================================================

bool HandlePostMessageA(APIContext& ctx) {
    (void)ctx.GetArg(0);
    (void)ctx.GetArg32(1);
    (void)ctx.GetArg(2);
    (void)ctx.GetArg(3);

    ctx.SetReturnBool(true);
    return true;
}

bool HandlePostMessageW(APIContext& ctx) {
    return HandlePostMessageA(ctx);
}

// ============================================================================
// SendMessageA/W — hWnd(0), Msg(1), wParam(2), lParam(3) → 0
// ============================================================================

bool HandleSendMessageA(APIContext& ctx) {
    (void)ctx.GetArg(0);
    (void)ctx.GetArg32(1);
    (void)ctx.GetArg(2);
    (void)ctx.GetArg(3);

    ctx.SetReturn(0);
    return true;
}

bool HandleSendMessageW(APIContext& ctx) {
    return HandleSendMessageA(ctx);
}

// ============================================================================
// GetSystemMetrics — nIndex(0)
// ============================================================================
// ANTI-EVASION:
//   SM_CXSCREEN / SM_CYSCREEN: 1920×1080 (realistic desktop, not a VM)
//   SM_REMOTESESSION: 0 (not an RDP session — malware checks this)
//   SM_CLEANBOOT: 0 (normal boot)

bool HandleGetSystemMetrics(APIContext& ctx) {
    const auto nIndex = static_cast<int32_t>(ctx.GetArg32(0));

    int32_t result = 0;
    switch (nIndex) {
        case SM_CXSCREEN:      result = kScreenWidth;  break;
        case SM_CYSCREEN:      result = kScreenHeight; break;
        case SM_CLEANBOOT:     result = 0;             break;  // Normal boot
        case SM_REMOTESESSION: result = 0;             break;  // Not RDP
        default:               result = 0;             break;
    }

    ctx.SetReturn32(static_cast<uint32_t>(result));
    return true;
}

// ============================================================================
// SystemParametersInfoA/W — uiAction(0), uiParam(1), pvParam(2), fWinIni(3)
// ============================================================================
// No-op: return TRUE without modifying any parameters.

bool HandleSystemParametersInfoA(APIContext& ctx) {
    (void)ctx.GetArg32(0);
    (void)ctx.GetArg32(1);
    (void)ctx.GetArgPtr(2);
    (void)ctx.GetArg32(3);

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

bool HandleSystemParametersInfoW(APIContext& ctx) {
    return HandleSystemParametersInfoA(ctx);
}

// ============================================================================
// GetCursorPos — lpPoint(0) → writes POINT{960, 540}
// ============================================================================
// POINT structure: { LONG x; LONG y; } = 8 bytes

bool HandleGetCursorPos(APIContext& ctx) {
    const auto lpPoint = ctx.GetArgPtr(0);

    if (lpPoint == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    auto& mem = ctx.Memory();
    // Write x coordinate (LONG = 4 bytes)
    if (mem.WriteValue<int32_t>(lpPoint, kCursorX) != ErrorCode::Success) {
        ctx.FailWithError(Win32::ERROR_NOACCESS);
        return true;
    }
    // Write y coordinate
    if (mem.WriteValue<int32_t>(lpPoint + 4, kCursorY) != ErrorCode::Success) {
        ctx.FailWithError(Win32::ERROR_NOACCESS);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// SetCursorPos — x(0), y(1) → TRUE
// ============================================================================

bool HandleSetCursorPos(APIContext& ctx) {
    (void)ctx.GetArg32(0);
    (void)ctx.GetArg32(1);

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// EnumWindows — lpEnumFunc(0), lParam(1) → TRUE
// ============================================================================
// Return TRUE without calling the callback — pretend there are no windows
// to enumerate. This is safe: malware that enumerates windows is looking
// for analysis tools or trying to interact with other processes.

bool HandleEnumWindows(APIContext& ctx) {
    (void)ctx.GetArgPtr(0);
    (void)ctx.GetArg(1);

    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// GetWindowTextA/W — hWnd(0), lpString(1), nMaxCount(2) → 0
// ============================================================================
// Return 0 (empty text) — no visible windows in our environment.

bool HandleGetWindowTextA(APIContext& ctx) {
    (void)ctx.GetArg(0);
    const auto lpString  = ctx.GetArgPtr(1);
    const auto nMaxCount = ctx.GetArg32(2);

    // Write a null terminator if buffer is valid
    if (lpString != 0 && nMaxCount > 0) {
        ctx.Memory().WriteU8(lpString, 0);
    }

    ctx.SetReturn32(0);
    return true;
}

bool HandleGetWindowTextW(APIContext& ctx) {
    (void)ctx.GetArg(0);
    const auto lpString  = ctx.GetArgPtr(1);
    const auto nMaxCount = ctx.GetArg32(2);

    if (lpString != 0 && nMaxCount > 0) {
        ctx.Memory().WriteU16(lpString, 0);
    }

    ctx.SetReturn32(0);
    return true;
}

// ============================================================================
// GetClassNameA/W — hWnd(0), lpClassName(1), nMaxCount(2) → 0
// ============================================================================

bool HandleGetClassNameA(APIContext& ctx) {
    (void)ctx.GetArg(0);
    const auto lpClassName = ctx.GetArgPtr(1);
    const auto nMaxCount   = ctx.GetArg32(2);

    if (lpClassName != 0 && nMaxCount > 0) {
        ctx.Memory().WriteU8(lpClassName, 0);
    }

    ctx.SetReturn32(0);
    return true;
}

bool HandleGetClassNameW(APIContext& ctx) {
    (void)ctx.GetArg(0);
    const auto lpClassName = ctx.GetArgPtr(1);
    const auto nMaxCount   = ctx.GetArg32(2);

    if (lpClassName != 0 && nMaxCount > 0) {
        ctx.Memory().WriteU16(lpClassName, 0);
    }

    ctx.SetReturn32(0);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterWindowAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "user32.dll", "MessageBoxA",
          HandleMessageBoxA, 4, false },
        { "user32.dll", "MessageBoxW",
          HandleMessageBoxW, 4, false },
        { "user32.dll", "FindWindowA",
          HandleFindWindowA, 2, false },
        { "user32.dll", "FindWindowW",
          HandleFindWindowW, 2, false },
        { "user32.dll", "GetForegroundWindow",
          HandleGetForegroundWindow, 0, false },
        { "user32.dll", "GetDesktopWindow",
          HandleGetDesktopWindow, 0, false },
        { "user32.dll", "GetShellWindow",
          HandleGetShellWindow, 0, false },
        { "user32.dll", "ShowWindow",
          HandleShowWindow, 2, false },
        { "user32.dll", "PostMessageA",
          HandlePostMessageA, 4, false },
        { "user32.dll", "PostMessageW",
          HandlePostMessageW, 4, false },
        { "user32.dll", "SendMessageA",
          HandleSendMessageA, 4, false },
        { "user32.dll", "SendMessageW",
          HandleSendMessageW, 4, false },
        { "user32.dll", "GetSystemMetrics",
          HandleGetSystemMetrics, 1, false },
        { "user32.dll", "SystemParametersInfoA",
          HandleSystemParametersInfoA, 4, false },
        { "user32.dll", "SystemParametersInfoW",
          HandleSystemParametersInfoW, 4, false },
        { "user32.dll", "GetCursorPos",
          HandleGetCursorPos, 1, false },
        { "user32.dll", "SetCursorPos",
          HandleSetCursorPos, 2, false },
        { "user32.dll", "EnumWindows",
          HandleEnumWindows, 2, false },
        { "user32.dll", "GetWindowTextA",
          HandleGetWindowTextA, 3, false },
        { "user32.dll", "GetWindowTextW",
          HandleGetWindowTextW, 3, false },
        { "user32.dll", "GetClassNameA",
          HandleGetClassNameA, 3, false },
        { "user32.dll", "GetClassNameW",
          HandleGetClassNameW, 3, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::User32

#pragma warning(pop)

