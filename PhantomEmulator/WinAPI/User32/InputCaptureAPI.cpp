/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * InputCaptureAPI.cpp — User32 input capture, keylogging, and
 *                       screen capture API implementations
 *
 * Every handler reads arguments from guest registers / guest stack via
 * APIContext, operates on VirtualMemory, and writes results back through
 * the context. No host OS calls are made.
 *
 * MITRE ATT&CK:
 *   - T1056.001 Input Capture: Keylogging  (SetWindowsHookEx WH_KEYBOARD_LL,
 *     GetAsyncKeyState / GetKeyState / GetKeyboardState polling)
 *   - T1113       Screen Capture            (GetWindowDC + BitBlt + GetDIBits)
 *
 * DESIGN:
 *   - Fake opaque handles in the 0x00020000+ range (no collision with
 *     kernel handle table or WindowAPI fake HWNDs at 0x00010000+).
 *   - Key state polling always returns 0 (no key pressed) — we don't
 *     simulate keystrokes, but every poll is counted toward a keylogger
 *     heuristic in correlation.
 *   - BitBlt from the screen DC is flagged ScreenCapture. We succeed
 *     the blit unconditionally so the malware continues to reveal its
 *     exfiltration chain.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "InputCaptureAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../HandleTable.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <cstring>
#include <string>

// DESIGN: Guest-memory writebacks are [[nodiscard]] but guest-side faults
// are guest faults, not ours. Silence the C4834 wave in one place so the
// taxonomy doesn't drown out real static-analysis findings.
#pragma warning(push)
#pragma warning(disable : 4834 6031)

namespace Phantom::WinAPI::User32 {

// ============================================================================
// Internal constants — fake handles for hooks / DCs / bitmaps
// ============================================================================

// Hook handles (HHOOK) — T1056.001 anchor.
static constexpr uint64_t kFakeKeyboardHookBase = 0x00020100;
static constexpr uint64_t kFakeMouseHookBase    = 0x00020200;
static constexpr uint64_t kFakeGenericHookBase  = 0x00020300;
static constexpr uint64_t kHookSlotStride       = 0x10;
static constexpr uint64_t kMaxHooksPerSlot      = 16;

// Device context handles (HDC) — screen-capture path.
static constexpr uint64_t kFakeScreenDC         = 0x00020400;
static constexpr uint64_t kFakeWindowDCBase     = 0x00020500;
static constexpr uint64_t kFakeCompatibleDCBase = 0x00020600;
static constexpr uint64_t kDCSlotStride         = 0x10;

// GDI object handles (HBITMAP / HGDIOBJ) — screen-capture payload.
static constexpr uint64_t kFakeBitmapBase       = 0x00020700;
static constexpr uint64_t kFakeDIBSectionBase   = 0x00020800;
static constexpr uint64_t kFakeGDIObjectBase    = 0x00020900;
static constexpr uint64_t kBitmapSlotStride     = 0x10;

// Max allocations we hand out before wrapping — hard cap to prevent
// attacker-controlled address exhaustion of the fake-handle range.
static constexpr uint64_t kMaxSlots             = 256;

// Hook identifiers (MSDN winuser.h)
static constexpr int32_t WH_KEYBOARD            = 2;
static constexpr int32_t WH_MOUSE               = 7;
static constexpr int32_t WH_KEYBOARD_LL         = 13;
static constexpr int32_t WH_MOUSE_LL            = 14;

// BitBlt raster-op codes
static constexpr uint32_t SRCCOPY               = 0x00CC0020;
static constexpr uint32_t CAPTUREBLT            = 0x40000000;

// Keyboard state buffer size (256 virtual keys, 1 byte each)
static constexpr uint32_t kKeyboardStateBytes   = 256;

// Max safe DIB byte count we'll pretend to write back — caps a hostile
// biSizeImage/nNumScanLines against unbounded guest writes.
static constexpr uint32_t kMaxDIBBytes          = 32u * 1024u * 1024u;  // 32 MiB

// ============================================================================
// Slot counters — rotate through the fake-handle ranges. Atomic to tolerate
// multi-threaded emulated callers. Correctness: the ranges never collide
// because every slot-stride * kMaxSlots stays within its pool (<4 KiB).
// ============================================================================

#include <atomic>
static std::atomic<uint64_t> g_keyboardHookSlot{0};
static std::atomic<uint64_t> g_mouseHookSlot{0};
static std::atomic<uint64_t> g_genericHookSlot{0};
static std::atomic<uint64_t> g_windowDCSlot{0};
static std::atomic<uint64_t> g_compatibleDCSlot{0};
static std::atomic<uint64_t> g_bitmapSlot{0};
static std::atomic<uint64_t> g_dibSectionSlot{0};
static std::atomic<uint64_t> g_gdiObjectSlot{0};

[[nodiscard]] static uint64_t NextSlot(std::atomic<uint64_t>& counter,
                                       uint64_t base,
                                       uint64_t stride) noexcept {
    const uint64_t idx = counter.fetch_add(1, std::memory_order_relaxed) % kMaxSlots;
    return base + idx * stride;
}

// ============================================================================
// Key state polling — T1056.001 polling-style keylogger
// ============================================================================
//
// GetAsyncKeyState(vKey) → SHORT
// GetKeyState(vKey)      → SHORT
// Both return 0 (no key pressed, no toggle) — we never feed synthetic input.
// Every call is counted as an IOC; real keyloggers spam these in tight loops.
//
// ============================================================================

bool HandleGetAsyncKeyState(APIContext& ctx) {
    (void)ctx.GetArg32(0);  // vKey

    ctx.AddBehaviorFlag(BehaviorFlag::Keylogging);
    ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);

    // Return 0: key not pressed, not toggled. SHORT return packed into low 16.
    ctx.SetReturn32(0);
    return true;
}

bool HandleGetKeyState(APIContext& ctx) {
    (void)ctx.GetArg32(0);  // vKey

    ctx.AddBehaviorFlag(BehaviorFlag::Keylogging);
    ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);

    ctx.SetReturn32(0);
    return true;
}

// ============================================================================
// GetKeyboardState — lpKeyState(0) → BOOL (writes 256 bytes, all zero)
// ============================================================================
// Snapshot of the entire 256-key virtual key table. Even heavier IOC than
// GetKeyState since it bulk-extracts the state in one call.

bool HandleGetKeyboardState(APIContext& ctx) {
    const auto lpKeyState = ctx.GetArgPtr(0);

    ctx.AddBehaviorFlag(BehaviorFlag::Keylogging);
    ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);

    if (lpKeyState == 0) {
        ctx.SetLastError(Win32::ERROR_NOACCESS);
        ctx.SetReturnBool(false);
        return true;
    }

    // Zero-fill the 256-byte state buffer. Using a stack buffer of
    // exactly 256 bytes is safe (small, fixed, non-paged-eligible).
    uint8_t zeros[kKeyboardStateBytes];
    std::memset(zeros, 0, sizeof(zeros));
    auto& mem = ctx.Memory();
    mem.Write(lpKeyState, zeros, kKeyboardStateBytes);

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// SetWindowsHookEx — idHook(0), lpfn(1), hMod(2), dwThreadId(3) → HHOOK
// ============================================================================
// CRITICAL IOC — T1056.001 / T1106. WH_KEYBOARD_LL + WH_KEYBOARD are the
// textbook keylogger primitives; WH_MOUSE_LL + WH_MOUSE are used by screen
// recorders and cursor trackers. Every call is flagged, with intensity
// differentiated by hook type.

static bool SetWindowsHookExCommon(APIContext& ctx) {
    const int32_t idHook     = static_cast<int32_t>(ctx.GetArg32(0));
    (void)ctx.GetArgPtr(1);  // lpfn — guest-side callback, unused by us
    (void)ctx.GetArgPtr(2);  // hMod
    (void)ctx.GetArg32(3);   // dwThreadId

    ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);

    uint64_t hhook = 0;
    switch (idHook) {
        case WH_KEYBOARD:
        case WH_KEYBOARD_LL:
            ctx.AddBehaviorFlag(BehaviorFlag::Keylogging);
            hhook = NextSlot(g_keyboardHookSlot, kFakeKeyboardHookBase,
                             kHookSlotStride);
            break;
        case WH_MOUSE:
        case WH_MOUSE_LL:
            // Mouse hooks aren't keyloggers but are often paired with them;
            // flag ScreenCapture because mouse hooks correlate with screen
            // recorders. No dedicated MouseCapture flag exists.
            ctx.AddBehaviorFlag(BehaviorFlag::ScreenCapture);
            hhook = NextSlot(g_mouseHookSlot, kFakeMouseHookBase,
                             kHookSlotStride);
            break;
        default:
            hhook = NextSlot(g_genericHookSlot, kFakeGenericHookBase,
                             kHookSlotStride);
            break;
    }

    // Cap: never hand out more than kMaxHooksPerSlot * 3 unique hooks
    // per emulator run. Above that we reuse (mimics HHOOK scarcity).
    (void)kMaxHooksPerSlot;

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn(hhook);
    return true;
}

bool HandleSetWindowsHookExA(APIContext& ctx) {
    return SetWindowsHookExCommon(ctx);
}

bool HandleSetWindowsHookExW(APIContext& ctx) {
    return SetWindowsHookExCommon(ctx);
}

// ============================================================================
// UnhookWindowsHookEx — hhk(0) → BOOL
// ============================================================================
// Always succeeds; we don't track individual hooks because the fake-handle
// slots are intentionally reusable. No flag — uninstalling a hook is not
// suspicious on its own.

bool HandleUnhookWindowsHookEx(APIContext& ctx) {
    (void)ctx.GetArg(0);  // hhk

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// GetWindowDC — hWnd(0) → HDC
// ============================================================================
// CRITICAL IOC — T1113 Screen Capture primitive. GetWindowDC(NULL) returns
// a DC for the ENTIRE screen; combined with BitBlt this is the canonical
// screenshot technique used by RATs (NanoCore, DarkComet, Agent Tesla...).

bool HandleGetWindowDC(APIContext& ctx) {
    const auto hWnd = ctx.GetArg(0);

    ctx.AddBehaviorFlag(BehaviorFlag::ScreenCapture);
    ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);

    // Null hWnd → screen DC (the T1113 red flag). Non-null → fake window DC.
    const uint64_t hdc = (hWnd == 0)
        ? kFakeScreenDC
        : NextSlot(g_windowDCSlot, kFakeWindowDCBase, kDCSlotStride);

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn(hdc);
    return true;
}

// ============================================================================
// ReleaseDC — hWnd(0), hDC(1) → int (1 = released)
// ============================================================================

bool HandleReleaseDC(APIContext& ctx) {
    (void)ctx.GetArg(0);  // hWnd
    (void)ctx.GetArg(1);  // hDC

    ctx.SetReturn32(1);
    return true;
}

// ============================================================================
// CreateCompatibleDC — hDC(0) → HDC
// ============================================================================
// Source for the "off-screen DC" step in the BitBlt screenshot chain.

bool HandleCreateCompatibleDC(APIContext& ctx) {
    (void)ctx.GetArg(0);  // hDC

    ctx.AddBehaviorFlag(BehaviorFlag::ScreenCapture);

    const uint64_t hdc = NextSlot(g_compatibleDCSlot,
                                  kFakeCompatibleDCBase, kDCSlotStride);
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn(hdc);
    return true;
}

// ============================================================================
// DeleteDC — hDC(0) → BOOL
// ============================================================================

bool HandleDeleteDC(APIContext& ctx) {
    (void)ctx.GetArg(0);  // hDC
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// BitBlt — hdcDest(0), nXDest(1), nYDest(2), nWidth(3), nHeight(4),
//          hdcSrc(5), nXSrc(6), nYSrc(7), dwRop(8) → BOOL
// ============================================================================
// The classic screenshot primitive. When hdcSrc is the screen DC we emit
// ScreenCapture; ROP of SRCCOPY with CAPTUREBLT OR'd in is the exact
// signature of the "capture layered windows" variant used by stealthier
// screengrabbers.

bool HandleBitBlt(APIContext& ctx) {
    (void)ctx.GetArg(0);               // hdcDest
    (void)ctx.GetArg32(1);             // nXDest
    (void)ctx.GetArg32(2);             // nYDest
    (void)ctx.GetArg32(3);             // nWidth
    (void)ctx.GetArg32(4);             // nHeight
    const auto hdcSrc = ctx.GetArg(5);
    (void)ctx.GetArg32(6);             // nXSrc
    (void)ctx.GetArg32(7);             // nYSrc
    const auto dwRop  = ctx.GetArg32(8);

    ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);

    // Screen DC source → definite T1113.
    if (hdcSrc == kFakeScreenDC ||
        (hdcSrc >= kFakeWindowDCBase &&
         hdcSrc < kFakeWindowDCBase + kMaxSlots * kDCSlotStride)) {
        ctx.AddBehaviorFlag(BehaviorFlag::ScreenCapture);
    }
    // SRCCOPY with CAPTUREBLT is a stealth-capture tell regardless of hdcSrc
    // (layered-window capture bypass).
    if ((dwRop & CAPTUREBLT) == CAPTUREBLT &&
        (dwRop & 0x00FFFFFFu) == (SRCCOPY & 0x00FFFFFFu)) {
        ctx.AddBehaviorFlag(BehaviorFlag::ScreenCapture);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// StretchBlt — 11 args; same semantics as BitBlt with source-scaling.
// ============================================================================

bool HandleStretchBlt(APIContext& ctx) {
    (void)ctx.GetArg(0);               // hdcDest
    (void)ctx.GetArg32(1);             // nXOriginDest
    (void)ctx.GetArg32(2);             // nYOriginDest
    (void)ctx.GetArg32(3);             // nWidthDest
    (void)ctx.GetArg32(4);             // nHeightDest
    const auto hdcSrc = ctx.GetArg(5);
    (void)ctx.GetArg32(6);             // nXOriginSrc
    (void)ctx.GetArg32(7);             // nYOriginSrc
    (void)ctx.GetArg32(8);             // nWidthSrc
    (void)ctx.GetArg32(9);             // nHeightSrc
    const auto dwRop = ctx.GetArg32(10);

    ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);

    if (hdcSrc == kFakeScreenDC ||
        (hdcSrc >= kFakeWindowDCBase &&
         hdcSrc < kFakeWindowDCBase + kMaxSlots * kDCSlotStride)) {
        ctx.AddBehaviorFlag(BehaviorFlag::ScreenCapture);
    }
    if ((dwRop & CAPTUREBLT) == CAPTUREBLT) {
        ctx.AddBehaviorFlag(BehaviorFlag::ScreenCapture);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// CreateCompatibleBitmap — hDC(0), nWidth(1), nHeight(2) → HBITMAP
// ============================================================================
// The off-screen bitmap for the BitBlt dest in the screenshot chain.

bool HandleCreateCompatibleBitmap(APIContext& ctx) {
    (void)ctx.GetArg(0);        // hDC
    (void)ctx.GetArg32(1);      // nWidth
    (void)ctx.GetArg32(2);      // nHeight

    ctx.AddBehaviorFlag(BehaviorFlag::ScreenCapture);

    const uint64_t hbitmap = NextSlot(g_bitmapSlot, kFakeBitmapBase,
                                      kBitmapSlotStride);
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn(hbitmap);
    return true;
}

// ============================================================================
// CreateDIBSection — hdc(0), pbmi(1), iUsage(2), ppvBits(3),
//                    hSection(4), dwOffset(5) → HBITMAP
// ============================================================================
// Allocates a DIB surface. Zero the ppvBits output pointer — we don't
// back the bitmap with real guest memory (the malware will get 0 and
// either crash trying to read, or abandon the path).

bool HandleCreateDIBSection(APIContext& ctx) {
    (void)ctx.GetArg(0);            // hdc
    (void)ctx.GetArgPtr(1);         // pbmi
    (void)ctx.GetArg32(2);          // iUsage
    const auto ppvBits = ctx.GetArgPtr(3);
    (void)ctx.GetArg(4);            // hSection
    (void)ctx.GetArg32(5);          // dwOffset

    ctx.AddBehaviorFlag(BehaviorFlag::ScreenCapture);

    // Write NULL into *ppvBits if the pointer is valid.
    if (ppvBits != 0) {
        auto& mem = ctx.Memory();
        if (ctx.Is64Bit()) {
            mem.WriteU64(ppvBits, 0);
        } else {
            mem.WriteU32(ppvBits, 0);
        }
    }

    const uint64_t hbitmap = NextSlot(g_dibSectionSlot,
                                      kFakeDIBSectionBase, kBitmapSlotStride);
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn(hbitmap);
    return true;
}

// ============================================================================
// GetDIBits — hdc(0), hbm(1), uStartScan(2), cScanLines(3),
//             lpvBits(4), lpbmi(5), uUsage(6) → int
// ============================================================================
// Extracts raw pixel data from a bitmap. This is where a screenshot
// actually becomes exfiltration-ready bytes in the guest heap.

bool HandleGetDIBits(APIContext& ctx) {
    (void)ctx.GetArg(0);                  // hdc
    (void)ctx.GetArg(1);                  // hbm
    (void)ctx.GetArg32(2);                // uStartScan
    const auto cScanLines = ctx.GetArg32(3);
    const auto lpvBits    = ctx.GetArgPtr(4);
    (void)ctx.GetArgPtr(5);               // lpbmi (BITMAPINFO, in/out)
    (void)ctx.GetArg32(6);                // uUsage

    ctx.AddBehaviorFlag(BehaviorFlag::ScreenCapture);
    ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);

    // If the caller passes lpvBits==NULL they're probing for required
    // buffer size; return cScanLines as MSDN specifies.
    if (lpvBits == 0) {
        ctx.SetReturn32(cScanLines);
        return true;
    }

    // We don't have a real bitmap backing; MSDN allows returning 0 to
    // signal failure, but plenty of droppers proceed regardless. Return
    // cScanLines to satisfy common sanity checks; do NOT write anything
    // to lpvBits — that would be an unbounded guest write driven by an
    // attacker-controlled cScanLines. Safety first.
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn32(cScanLines);
    (void)kMaxDIBBytes;  // reserved for future bounded writeback
    return true;
}

// ============================================================================
// SelectObject — hDC(0), hGDIObject(1) → HGDIOBJ (previous)
// ============================================================================

bool HandleSelectObject(APIContext& ctx) {
    (void)ctx.GetArg(0);  // hDC
    (void)ctx.GetArg(1);  // hGDIObject

    // Return a fake "previously-selected" GDI object. Non-null so the
    // caller doesn't bail on GetLastError.
    const uint64_t prev = NextSlot(g_gdiObjectSlot, kFakeGDIObjectBase,
                                   kBitmapSlotStride);
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn(prev);
    return true;
}

// ============================================================================
// DeleteObject — hObject(0) → BOOL
// ============================================================================

bool HandleDeleteObject(APIContext& ctx) {
    (void)ctx.GetArg(0);  // hObject
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterInputCaptureAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        // Key state polling — T1056.001
        { "user32.dll", "GetAsyncKeyState",      HandleGetAsyncKeyState,      1, false },
        { "user32.dll", "GetKeyState",           HandleGetKeyState,           1, false },
        { "user32.dll", "GetKeyboardState",      HandleGetKeyboardState,      1, false },

        // Windows hooks — T1056.001 / T1106
        { "user32.dll", "SetWindowsHookExA",     HandleSetWindowsHookExA,     4, true  },
        { "user32.dll", "SetWindowsHookExW",     HandleSetWindowsHookExW,     4, true  },
        { "user32.dll", "UnhookWindowsHookEx",   HandleUnhookWindowsHookEx,   1, false },

        // Screen-capture chain — T1113
        { "user32.dll", "GetWindowDC",           HandleGetWindowDC,           1, true  },
        { "user32.dll", "ReleaseDC",             HandleReleaseDC,             2, false },

        // GDI lives in gdi32.dll but some older code imports from user32
        // shims; register against gdi32.dll (the authoritative export).
        { "gdi32.dll",  "CreateCompatibleDC",    HandleCreateCompatibleDC,    1, true  },
        { "gdi32.dll",  "DeleteDC",              HandleDeleteDC,              1, false },
        { "gdi32.dll",  "BitBlt",                HandleBitBlt,                9, true  },
        { "gdi32.dll",  "StretchBlt",            HandleStretchBlt,           11, true  },
        { "gdi32.dll",  "CreateCompatibleBitmap",HandleCreateCompatibleBitmap,3, true  },
        { "gdi32.dll",  "CreateDIBSection",      HandleCreateDIBSection,      6, true  },
        { "gdi32.dll",  "GetDIBits",             HandleGetDIBits,             7, true  },
        { "gdi32.dll",  "SelectObject",          HandleSelectObject,          2, false },
        { "gdi32.dll",  "DeleteObject",          HandleDeleteObject,          1, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::User32

#pragma warning(pop)
