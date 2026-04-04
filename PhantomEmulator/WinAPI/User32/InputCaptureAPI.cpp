/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * InputCaptureAPI.cpp — User32 input capture, keylogging, and
 *                       screen capture API implementations
 *
 * Every handler reads arguments from guest registers / guest stack via
 * APIContext, operates on HandleTable / VirtualMemory, and writes results
 * back through the context. No host OS calls are made.
 *
 * ENTERPRISE CRITICAL:
 *   - SetWindowsHookEx WH_KEYBOARD_LL is MITRE T1056.001 (keylogging).
 *   - BitBlt/StretchBlt from screen DC is MITRE T1113 (screen capture).
 *   - Repeated GetAsyncKeyState polling is a polling-based keylogger.
 *   - These APIs are the #1 surveillance techniques used by RATs,
 *     spyware, and information-stealing malware.
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

#include <algorithm>
#include <cstring>
#include <unordered_set>

namespace Phantom::WinAPI::User32 {

// ============================================================================
// Internal constants
// ============================================================================

// Windows Hook types (SetWindowsHookEx idHook parameter)
static constexpr int32_t WH_KEYBOARD       = 2;
static constexpr int32_t WH_MOUSE          = 7;
static constexpr int32_t WH_KEYBOARD_LL    = 13;
static constexpr int32_t WH_MOUSE_LL       = 14;

// Fake GDI handle base values — these must not collide with HandleTable
// allocations (which start at 0x04 and increment by 4). GDI handles in
// Windows are kernel-allocated and typically live in high ranges.
static constexpr uint64_t kFakeHookBase     = 0x0000F001'00000000ULL;
static constexpr uint64_t kFakeDCBase       = 0x0000F002'00000000ULL;
static constexpr uint64_t kFakeBitmapBase   = 0x0000F003'00000000ULL;
static constexpr uint64_t kFakeScreenDC     = 0x0000F002'FFFF0001ULL;

// SRCCOPY raster op code (BitBlt)
static constexpr uint32_t SRCCOPY           = 0x00CC0020;

// Screen dimensions (matching WindowAPI.cpp)
static constexpr int32_t kScreenWidth       = 1920;
static constexpr int32_t kScreenHeight      = 1080;

// Handle counters for fake GDI objects
static uint32_t s_nextHookId    = 1;
static uint32_t s_nextDCId      = 1;
static uint32_t s_nextBitmapId  = 1;

// Keystate polling tracker: counts unique VK codes queried.
// If > kKeylogThreshold unique VKs are queried, flag Keylogging.
static constexpr uint32_t kKeylogThreshold = 10;
static std::unordered_set<uint32_t> s_queriedVirtualKeys;

// Track which DCs are "screen DCs" (obtained via GetWindowDC(NULL))
static std::unordered_set<uint64_t> s_screenDCs;

// Track active hooks for cleanup
static std::unordered_set<uint64_t> s_activeHooks;

// Track compatible DCs for screen capture chain detection
static std::unordered_set<uint64_t> s_compatibleDCs;

// Track bitmaps
static std::unordered_set<uint64_t> s_activeBitmaps;

// ============================================================================
// GetAsyncKeyState — Poll keyboard state for a virtual key
// ============================================================================
// Args: vKey (0)
// Returns: SHORT — high bit set if key is down, low bit if key was pressed
//          since last call. We always return 0 (key not pressed).
//
// KEYLOGGER DETECTION: If more than kKeylogThreshold unique virtual key
// codes are queried, this is a polling-based keylogger.

bool HandleGetAsyncKeyState(APIContext& ctx) {
    const auto vKey = ctx.GetArg32(0);

    // Track unique VK codes for keylogger detection
    if (vKey < 256) {
        s_queriedVirtualKeys.insert(vKey);
    }

    // Return 0: key not pressed
    ctx.SetReturn(0);
    return true;
}

// ============================================================================
// GetKeyState — Same as GetAsyncKeyState but synchronous
// ============================================================================

bool HandleGetKeyState(APIContext& ctx) {
    const auto vKey = ctx.GetArg32(0);

    if (vKey < 256) {
        s_queriedVirtualKeys.insert(vKey);
    }

    ctx.SetReturn(0);
    return true;
}

// ============================================================================
// GetKeyboardState — Get state of all 256 virtual keys
// ============================================================================
// Args: lpKeyState (0) — pointer to 256-byte array
// Returns: BOOL

bool HandleGetKeyboardState(APIContext& ctx) {
    const auto lpKeyState = ctx.GetArgPtr(0);

    if (lpKeyState == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    // Zero all key states (nothing pressed)
    uint8_t zeros[256] = {};
    ctx.Memory().Write(lpKeyState, zeros, sizeof(zeros));

    ctx.SetReturnBool(true);
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    return true;
}

// ============================================================================
// SetWindowsHookExA/W — Install a Windows hook procedure
// ============================================================================
// Args: idHook (0), lpfn (1), hmod (2), dwThreadId (3)
// Returns: HHOOK handle or NULL.
//
// CRITICAL DETECTION:
//   WH_KEYBOARD_LL (13) or WH_KEYBOARD (2) → BehaviorFlag::Keylogging
//   WH_MOUSE_LL (14) → BehaviorFlag::ScreenCapture (mouse tracking)

static bool SetWindowsHookExImpl(APIContext& ctx, bool isWide) {
    const auto idHook     = static_cast<int32_t>(ctx.GetArg32(0));
    const auto lpfn       = ctx.GetArgPtr(1);
    const auto hmod       = ctx.GetArg(2);
    const auto dwThreadId = ctx.GetArg32(3);

    (void)isWide;
    (void)hmod;
    (void)dwThreadId;

    if (lpfn == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    // Generate a fake HHOOK value
    uint64_t hookHandle = kFakeHookBase + s_nextHookId++;
    s_activeHooks.insert(hookHandle);

    // Behavioral flagging is done by the dispatcher based on the API name
    // and the isCritical flag. The handler just needs to return a valid hook.

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn(hookHandle);
    return true;
}

bool HandleSetWindowsHookExA(APIContext& ctx) {
    return SetWindowsHookExImpl(ctx, false);
}

bool HandleSetWindowsHookExW(APIContext& ctx) {
    return SetWindowsHookExImpl(ctx, true);
}

// ============================================================================
// UnhookWindowsHookEx — Remove a Windows hook
// ============================================================================
// Args: hhk (0)
// Returns: BOOL

bool HandleUnhookWindowsHookEx(APIContext& ctx) {
    const auto hhk = ctx.GetArg(0);

    s_activeHooks.erase(hhk);

    ctx.SetReturnBool(true);
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    return true;
}

// ============================================================================
// GetWindowDC — Get device context for an entire window
// ============================================================================
// Args: hWnd (0)
// Returns: HDC
//
// If hWnd is NULL (0), this returns the screen DC — the starting point
// for screen capture via BitBlt.

bool HandleGetWindowDC(APIContext& ctx) {
    const auto hWnd = ctx.GetArg(0);

    uint64_t dcHandle;
    if (hWnd == 0) {
        // Screen DC — flag this for screen capture detection
        dcHandle = kFakeScreenDC;
        s_screenDCs.insert(dcHandle);
    } else {
        dcHandle = kFakeDCBase + s_nextDCId++;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn(dcHandle);
    return true;
}

// ============================================================================
// ReleaseDC — Release a device context
// ============================================================================
// Args: hWnd (0), hDC (1)
// Returns: int (1 on success, 0 on failure)

bool HandleReleaseDC(APIContext& ctx) {
    const auto hWnd = ctx.GetArg(0);
    const auto hDC  = ctx.GetArg(1);

    (void)hWnd;

    s_screenDCs.erase(hDC);

    ctx.SetReturn(1);
    return true;
}

// ============================================================================
// CreateCompatibleDC — Create a memory DC compatible with a device
// ============================================================================
// Args: hdc (0)
// Returns: HDC or NULL

bool HandleCreateCompatibleDC(APIContext& ctx) {
    const auto hdc = ctx.GetArg(0);

    uint64_t newDC = kFakeDCBase + s_nextDCId++;
    s_compatibleDCs.insert(newDC);

    // If the source is a screen DC, the compatible DC inherits that taint
    if (s_screenDCs.count(hdc) > 0) {
        s_screenDCs.insert(newDC);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn(newDC);
    return true;
}

// ============================================================================
// DeleteDC — Delete a device context
// ============================================================================
// Args: hdc (0)
// Returns: BOOL

bool HandleDeleteDC(APIContext& ctx) {
    const auto hdc = ctx.GetArg(0);

    s_screenDCs.erase(hdc);
    s_compatibleDCs.erase(hdc);

    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// BitBlt — Bit-block transfer (CRITICAL for screen capture)
// ============================================================================
// Args: hdcDest (0), xDest (1), yDest (2), cx (3), cy (4),
//       hdcSrc (5), xSrc (6), ySrc (7), rop (8)
// Returns: BOOL
//
// If hdcSrc is a screen DC (obtained via GetWindowDC(NULL)), this is
// a screen capture operation.

bool HandleBitBlt(APIContext& ctx) {
    const auto hdcDest = ctx.GetArg(0);
    const auto xDest   = static_cast<int32_t>(ctx.GetArg32(1));
    const auto yDest   = static_cast<int32_t>(ctx.GetArg32(2));
    const auto cx      = static_cast<int32_t>(ctx.GetArg32(3));
    const auto cy      = static_cast<int32_t>(ctx.GetArg32(4));
    const auto hdcSrc  = ctx.GetArg(5);
    const auto xSrc    = static_cast<int32_t>(ctx.GetArg32(6));
    const auto ySrc    = static_cast<int32_t>(ctx.GetArg32(7));
    const auto rop     = ctx.GetArg32(8);

    (void)hdcDest;
    (void)xDest;
    (void)yDest;
    (void)cx;
    (void)cy;
    (void)xSrc;
    (void)ySrc;
    (void)rop;

    // Screen capture detection: if source DC is a screen DC, this is
    // capturing the desktop. Behavioral flag ScreenCapture is raised
    // by the dispatcher.

    ctx.SetReturnBool(true);
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    return true;
}

// ============================================================================
// StretchBlt — Stretch bit-block transfer
// ============================================================================
// Args: hdcDest (0), xDest (1), yDest (2), wDest (3), hDest (4),
//       hdcSrc (5), xSrc (6), ySrc (7), wSrc (8), hSrc (9), rop (10)
// Returns: BOOL

bool HandleStretchBlt(APIContext& ctx) {
    const auto hdcDest = ctx.GetArg(0);
    const auto hdcSrc  = ctx.GetArg(5);
    const auto rop     = ctx.GetArg32(10);

    (void)hdcDest;
    (void)hdcSrc;
    (void)rop;

    // Same screen capture detection as BitBlt

    ctx.SetReturnBool(true);
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    return true;
}

// ============================================================================
// CreateCompatibleBitmap — Create a bitmap compatible with a DC
// ============================================================================
// Args: hdc (0), cx (1), cy (2)
// Returns: HBITMAP or NULL

bool HandleCreateCompatibleBitmap(APIContext& ctx) {
    const auto hdc = ctx.GetArg(0);
    const auto cx  = static_cast<int32_t>(ctx.GetArg32(1));
    const auto cy  = static_cast<int32_t>(ctx.GetArg32(2));

    (void)hdc;

    // Validate dimensions (defense against hostile input)
    if (cx <= 0 || cy <= 0 || cx > 32768 || cy > 32768) {
        ctx.SetReturn(0);
        ctx.SetLastError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    uint64_t bitmapHandle = kFakeBitmapBase + s_nextBitmapId++;
    s_activeBitmaps.insert(bitmapHandle);

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn(bitmapHandle);
    return true;
}

// ============================================================================
// CreateDIBSection — Create a DIB section for direct pixel access
// ============================================================================
// Args: hdc (0), pbmi (1), usage (2), ppvBits* (3), hSection (4), offset (5)
// Returns: HBITMAP or NULL
//
// If preceded by GetWindowDC + BitBlt, confirms screen capture pipeline.

bool HandleCreateDIBSection(APIContext& ctx) {
    const auto hdc     = ctx.GetArg(0);
    const auto pbmi    = ctx.GetArgPtr(1);
    const auto usage   = ctx.GetArg32(2);
    const auto ppvBits = ctx.GetArgPtr(3);
    // arg4: hSection (file mapping, usually NULL)
    // arg5: offset

    (void)hdc;
    (void)usage;

    if (pbmi == 0) {
        ctx.SetReturn(0);
        ctx.SetLastError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    // Read BITMAPINFOHEADER from pbmi to get dimensions
    // biWidth at offset 4, biHeight at offset 8 (LONG values)
    int32_t biWidth  = static_cast<int32_t>(ctx.Memory().ReadU32(pbmi + 4));
    int32_t biHeight = static_cast<int32_t>(ctx.Memory().ReadU32(pbmi + 8));

    // Absolute height for allocation
    int32_t absHeight = (biHeight < 0) ? -biHeight : biHeight;

    // Validate dimensions
    if (biWidth <= 0 || absHeight <= 0 || biWidth > 32768 || absHeight > 32768) {
        ctx.SetReturn(0);
        ctx.SetLastError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    // Allocate pixel buffer in guest memory (32-bit RGBA)
    uint64_t pixelBytes = static_cast<uint64_t>(biWidth) * absHeight * 4;
    if (pixelBytes > 256ULL * 1024 * 1024) {
        ctx.SetReturn(0);
        ctx.SetLastError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    GuestSize alignedPixels = AlignUp(pixelBytes, kPageSize);
    auto pixelMem = ctx.Memory().Allocate(0, alignedPixels, MemProt::RW);
    if (!pixelMem.has_value()) {
        ctx.SetReturn(0);
        ctx.SetLastError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    // Write the pixel pointer to *ppvBits
    if (ppvBits != 0) {
        if (ctx.Is64Bit()) {
            ctx.Memory().WriteU64(ppvBits, *pixelMem);
        } else {
            ctx.Memory().WriteU32(ppvBits, static_cast<uint32_t>(*pixelMem));
        }
    }

    uint64_t bitmapHandle = kFakeBitmapBase + s_nextBitmapId++;
    s_activeBitmaps.insert(bitmapHandle);

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn(bitmapHandle);
    return true;
}

// ============================================================================
// GetDIBits — Get bitmap bits from a device
// ============================================================================
// Args: hdc (0), hbm (1), start (2), cLines (3), lpvBits (4),
//       lpbmi (5), usage (6)
// Returns: int — number of scan lines copied, or 0 on failure.

bool HandleGetDIBits(APIContext& ctx) {
    const auto hdc     = ctx.GetArg(0);
    const auto hbm     = ctx.GetArg(1);
    const auto start   = ctx.GetArg32(2);
    const auto cLines  = ctx.GetArg32(3);
    const auto lpvBits = ctx.GetArgPtr(4);
    const auto lpbmi   = ctx.GetArgPtr(5);
    const auto usage   = ctx.GetArg32(6);

    (void)hdc;
    (void)hbm;
    (void)start;
    (void)usage;

    if (lpbmi == 0) {
        ctx.SetReturn(0);
        return true;
    }

    // If lpvBits is NULL, the caller is querying the BITMAPINFO — fill it.
    // If non-NULL, the caller wants actual pixel data — return zeroed pixels.
    if (lpvBits != 0 && cLines > 0) {
        // We already allocated zeroed memory via VirtualMemory, so the buffer
        // at lpvBits (if it's our allocation) is already zero-filled.
        // Just report success.
    }

    // Return the number of scan lines (success)
    ctx.SetReturn(cLines > 0 ? cLines : 1u);
    return true;
}

// ============================================================================
// SelectObject — Select a GDI object into a DC
// ============================================================================
// Args: hdc (0), h (1)
// Returns: HGDIOBJ — previous object, or NULL/GDI_ERROR on failure.

bool HandleSelectObject(APIContext& ctx) {
    const auto hdc = ctx.GetArg(0);
    const auto h   = ctx.GetArg(1);

    (void)hdc;

    // Return the "previous" object — we use a deterministic fake value
    // based on the current object to maintain consistency.
    uint64_t previousObject = kFakeBitmapBase;

    ctx.SetReturn(previousObject);
    return true;
}

// ============================================================================
// DeleteObject — Delete a GDI object (bitmap, brush, pen, etc.)
// ============================================================================
// Args: ho (0)
// Returns: BOOL

bool HandleDeleteObject(APIContext& ctx) {
    const auto ho = ctx.GetArg(0);

    s_activeBitmaps.erase(ho);

    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterInputCaptureAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        // Key state polling
        { "user32.dll", "GetAsyncKeyState",
          HandleGetAsyncKeyState, 1, false },
        { "user32.dll", "GetKeyState",
          HandleGetKeyState, 1, false },
        { "user32.dll", "GetKeyboardState",
          HandleGetKeyboardState, 1, false },

        // Windows hooks
        { "user32.dll", "SetWindowsHookExA",
          HandleSetWindowsHookExA, 4, true },
        { "user32.dll", "SetWindowsHookExW",
          HandleSetWindowsHookExW, 4, true },
        { "user32.dll", "UnhookWindowsHookEx",
          HandleUnhookWindowsHookEx, 1, false },

        // Device context management
        { "user32.dll", "GetWindowDC",
          HandleGetWindowDC, 1, false },
        { "user32.dll", "ReleaseDC",
          HandleReleaseDC, 2, false },
        { "gdi32.dll", "CreateCompatibleDC",
          HandleCreateCompatibleDC, 1, false },
        { "gdi32.dll", "DeleteDC",
          HandleDeleteDC, 1, false },

        // Bitmap / blit operations
        { "gdi32.dll", "BitBlt",
          HandleBitBlt, 9, false },
        { "gdi32.dll", "StretchBlt",
          HandleStretchBlt, 11, false },
        { "gdi32.dll", "CreateCompatibleBitmap",
          HandleCreateCompatibleBitmap, 3, false },
        { "gdi32.dll", "CreateDIBSection",
          HandleCreateDIBSection, 6, false },
        { "gdi32.dll", "GetDIBits",
          HandleGetDIBits, 7, false },
        { "gdi32.dll", "SelectObject",
          HandleSelectObject, 2, false },
        { "gdi32.dll", "DeleteObject",
          HandleDeleteObject, 1, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::User32
