/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "pch.h"
#include "Products/Community/PhantomHome/UI/SystemTray.hpp"

// ============================================================================
// STANDARD LIBRARY
// ============================================================================

#include <array>
#include <vector>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <condition_variable>
#include <sstream>
#include <algorithm>
#include <cmath>

// ============================================================================
// WINDOWS SDK
// ============================================================================

#include <shellapi.h>
#include <strsafe.h>
#pragma comment(lib, "shell32.lib")

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE
// ============================================================================

#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/RealTime/RealTimeProtection.hpp"
#include "PhantomCore/Core/Engine/ScanEngine.hpp"
#include "PhantomCore/Communication/AlertSystem.hpp"
#include "PhantomCore/Communication/NotificationManager.hpp"

namespace ShadowStrike {
namespace UI {

// ============================================================================
// ICON COLORS — RGBA 32-bit premultiplied alpha
// ============================================================================

namespace IconColors {
    // Shield body
    inline constexpr uint32_t kProtected    = 0xFF2ECC71;  // Green
    inline constexpr uint32_t kScanning     = 0xFF3498DB;  // Blue
    inline constexpr uint32_t kPaused       = 0xFFF1C40F;  // Yellow
    inline constexpr uint32_t kDegraded     = 0xFFE67E22;  // Orange
    inline constexpr uint32_t kStopped      = 0xFFE74C3C;  // Red
    inline constexpr uint32_t kUpdating     = 0xFF1ABC9C;  // Teal/Cyan
    inline constexpr uint32_t kUninitialized= 0xFF95A5A6;  // Gray

    // Shield outline
    inline constexpr uint32_t kOutline      = 0xFF2C3E50;  // Dark navy

    // Checkmark / symbol
    inline constexpr uint32_t kSymbol       = 0xFFFFFFFF;  // White
}

// ============================================================================
// FORWARD: Icon generation
// ============================================================================

static HICON CreateShieldIcon(int size, uint32_t bodyColor, uint32_t outlineColor,
                              uint32_t symbolColor, TrayIconState state);

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class SystemTrayImpl {
public:
    // ── lifecycle ───────────────────────────────────────────────────────
    SystemTrayImpl()  = default;
    ~SystemTrayImpl() { Shutdown(); }

    [[nodiscard]] bool Initialize(const SystemTrayConfig& config);
    void Shutdown();

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_status.load(std::memory_order_acquire) == SystemTrayStatus::Running;
    }

    [[nodiscard]] SystemTrayStatus GetStatus() const noexcept {
        return m_status.load(std::memory_order_acquire);
    }

    [[nodiscard]] bool UpdateConfiguration(const SystemTrayConfig& config);
    [[nodiscard]] SystemTrayConfig GetConfiguration() const;

    // ── icon state ─────────────────────────────────────────────────────
    void SetIconState(TrayIconState state);
    [[nodiscard]] TrayIconState GetIconState() const noexcept {
        return m_iconState.load(std::memory_order_acquire);
    }

    void SetTooltip(std::wstring_view tooltip);
    [[nodiscard]] std::wstring GetTooltip() const;

    void ShowBalloon(std::wstring_view title, std::wstring_view msg,
                     DWORD flags, uint32_t timeoutMs);

    // ── engine integration ─────────────────────────────────────────────
    void RegisterEngineCallbacks();
    void UnregisterEngineCallbacks();
    void SyncStateFromEngine();

    // ── user callbacks ─────────────────────────────────────────────────
    void RegisterActionCallback(TrayActionCallback cb);
    void RegisterClickCallback(TrayClickCallback cb);
    void RegisterExitCallback(TrayExitCallback cb);

    // ── statistics ─────────────────────────────────────────────────────
    [[nodiscard]] SystemTrayStatistics GetStatistics() const;
    void ResetStatistics();
    [[nodiscard]] bool SelfTest();

private:
    // ── thread & window ────────────────────────────────────────────────
    void ThreadProc();
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
    void HandleTrayMessage(LPARAM lp);
    void HandleMenuCommand(TrayMenuAction action);
    void ShowContextMenu();

    // ── icon management ────────────────────────────────────────────────
    bool InstallIcon();
    void RemoveIcon();
    void UpdateIcon();
    void UpdateTooltipInternal();
    void StartAnimation();
    void StopAnimation();
    void OnAnimationTick();

    // ── engine callbacks ───────────────────────────────────────────────
    void OnRTPStateChange(RealTime::ProtectionState prev,
                          RealTime::ProtectionState next,
                          std::wstring_view reason);
    void OnThreatDetected(const RealTime::ThreatEvent& event);
    void OnScanComplete(const Core::Engine::ScanStatistics& stats);

    // ── helpers ────────────────────────────────────────────────────────
    [[nodiscard]] HICON GetOrCreateIcon(TrayIconState state, int size);
    void DestroyIcons();
    void LaunchDashboard();

    // ── state ──────────────────────────────────────────────────────────
    mutable std::shared_mutex           m_mutex;
    std::atomic<SystemTrayStatus>       m_status{SystemTrayStatus::Uninitialized};
    std::atomic<TrayIconState>          m_iconState{TrayIconState::Uninitialized};
    SystemTrayConfig                    m_config;

    // Thread
    std::thread                         m_thread;
    std::atomic<bool>                   m_shutdownRequested{false};
    std::condition_variable             m_initCV;
    std::mutex                          m_initMutex;
    bool                                m_initDone{false};
    bool                                m_initSuccess{false};

    // Win32
    HWND                                m_hwnd{nullptr};
    NOTIFYICONDATAW                     m_nid{};
    UINT                                m_taskbarCreatedMsg{0};
    bool                                m_iconInstalled{false};

    // Icons (cached per state * size)
    static constexpr int kSmallIconSize = 16;
    static constexpr int kLargeIconSize = 32;
    std::array<HICON, 7>                m_smallIcons{};  // indexed by TrayIconState
    std::array<HICON, 7>                m_largeIcons{};

    // Animation
    std::atomic<bool>                   m_animating{false};
    int                                 m_animFrame{0};

    // Tooltip override
    std::wstring                        m_tooltipOverride;

    // Engine callback IDs
    uint64_t                            m_rtpStateCallbackId{0};
    uint64_t                            m_rtpThreatCallbackId{0};
    uint64_t                            m_scanCompleteCallbackId{0};
    bool                                m_callbacksRegistered{false};

    // User callbacks
    TrayActionCallback                  m_actionCallback;
    TrayClickCallback                   m_clickCallback;
    TrayExitCallback                    m_exitCallback;

    // Statistics (atomics)
    std::atomic<uint64_t>               m_statMenusShown{0};
    std::atomic<uint64_t>               m_statDashboardLaunches{0};
    std::atomic<uint64_t>               m_statScansRequested{0};
    std::atomic<uint64_t>               m_statPauseRequests{0};
    std::atomic<uint64_t>               m_statResumeRequests{0};
    std::atomic<uint64_t>               m_statIconStateChanges{0};
    std::atomic<uint64_t>               m_statExplorerRestarts{0};
    std::atomic<uint64_t>               m_statBalloonsSent{0};
    std::chrono::steady_clock::time_point m_startTime;
};

// ============================================================================
// ICON GENERATION — Programmatic Shield Icons via GDI
// ============================================================================

/// Create an ARGB DIB section and return pixel pointer.
static HBITMAP CreateARGBBitmap(HDC hdc, int w, int h, uint32_t** ppBits) {
    BITMAPINFO bmi{};
    bmi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth       = w;
    bmi.bmiHeader.biHeight      = -h;  // top-down
    bmi.bmiHeader.biPlanes      = 1;
    bmi.bmiHeader.biBitCount    = 32;
    bmi.bmiHeader.biCompression = BI_RGB;
    void* bits = nullptr;
    HBITMAP hbm = CreateDIBSection(hdc, &bmi, DIB_RGB_COLORS, &bits, nullptr, 0);
    if (ppBits) *ppBits = static_cast<uint32_t*>(bits);
    return hbm;
}

/// Set a pixel in the ARGB buffer (premultiplied alpha, BGRA layout).
static inline void SetPixelPMA(uint32_t* bits, int stride, int x, int y,
                                uint32_t color) {
    uint8_t a = static_cast<uint8_t>((color >> 24) & 0xFF);
    uint8_t r = static_cast<uint8_t>((color >> 16) & 0xFF);
    uint8_t g = static_cast<uint8_t>((color >> 8)  & 0xFF);
    uint8_t b = static_cast<uint8_t>((color >> 0)  & 0xFF);

    // Premultiply
    r = static_cast<uint8_t>((r * a) / 255);
    g = static_cast<uint8_t>((g * a) / 255);
    b = static_cast<uint8_t>((b * a) / 255);

    bits[y * stride + x] = (static_cast<uint32_t>(a) << 24) |
                            (static_cast<uint32_t>(r) << 16) |
                            (static_cast<uint32_t>(g) << 8)  |
                            (static_cast<uint32_t>(b));
}

/// Check if (x,y) is inside a shield polygon for a given icon size.
static bool IsInsideShield(int x, int y, int size) {
    // Shield shape: rounded top, tapering to a point at bottom center.
    // Parametric: top is a rounded rectangle, bottom is a triangle.
    const float cx = static_cast<float>(size) / 2.0f;
    const float cy = static_cast<float>(size) / 2.0f;
    const float fx = static_cast<float>(x) + 0.5f;
    const float fy = static_cast<float>(y) + 0.5f;

    const float margin = static_cast<float>(size) * 0.0625f;  // ~1px at 16x16
    const float left   = margin;
    const float right  = static_cast<float>(size) - margin;
    const float top    = margin;
    const float mid    = static_cast<float>(size) * 0.55f;    // where triangle starts
    const float bottom = static_cast<float>(size) - margin;

    if (fy < top || fy > bottom) return false;
    if (fx < left || fx > right) return false;

    if (fy <= mid) {
        // Rectangular top with slight shoulder rounding
        return true;
    }

    // Triangle bottom: narrows linearly from full width at mid to center at bottom
    float t = (fy - mid) / (bottom - mid);  // 0..1
    float halfW = ((right - left) / 2.0f) * (1.0f - t);
    return fx >= (cx - halfW) && fx <= (cx + halfW);
}

/// Check if (x,y) is on the shield outline (1px ring).
static bool IsOnShieldOutline(int x, int y, int size) {
    bool inside = IsInsideShield(x, y, size);
    if (!inside) return false;

    // Check if any neighbor is outside → we're on the edge
    for (int dy = -1; dy <= 1; ++dy) {
        for (int dx = -1; dx <= 1; ++dx) {
            if (dx == 0 && dy == 0) continue;
            if (!IsInsideShield(x + dx, y + dy, size)) return true;
        }
    }
    return false;
}

/// Draw a checkmark symbol inside the shield.
static void DrawCheckmark(uint32_t* bits, int stride, int size, uint32_t color) {
    // Checkmark path scaled to icon size
    float s = static_cast<float>(size);
    // Start: (0.25, 0.50), knee: (0.42, 0.62), end: (0.75, 0.30)
    float x0 = s * 0.25f, y0 = s * 0.48f;
    float x1 = s * 0.42f, y1 = s * 0.60f;
    float x2 = s * 0.75f, y2 = s * 0.28f;

    auto drawLine = [&](float ax, float ay, float bx, float by) {
        int steps = static_cast<int>(std::max(std::abs(bx - ax), std::abs(by - ay)) * 2.0f) + 1;
        for (int i = 0; i <= steps; ++i) {
            float t = static_cast<float>(i) / static_cast<float>(steps);
            int px = static_cast<int>(ax + t * (bx - ax));
            int py = static_cast<int>(ay + t * (by - ay));
            if (px >= 0 && px < size && py >= 0 && py < size) {
                SetPixelPMA(bits, stride, px, py, color);
                // Thicken for larger icons
                if (size >= 24 && px + 1 < size)
                    SetPixelPMA(bits, stride, px + 1, py, color);
                if (size >= 24 && py + 1 < size)
                    SetPixelPMA(bits, stride, px, py + 1, color);
            }
        }
    };

    drawLine(x0, y0, x1, y1);
    drawLine(x1, y1, x2, y2);
}

/// Draw a pause symbol (two vertical bars).
static void DrawPauseSymbol(uint32_t* bits, int stride, int size, uint32_t color) {
    float s = static_cast<float>(size);
    int barW = std::max(1, static_cast<int>(s * 0.1f));
    int barH = static_cast<int>(s * 0.30f);
    int top  = static_cast<int>(s * 0.30f);
    int left1 = static_cast<int>(s * 0.35f);
    int left2 = static_cast<int>(s * 0.55f);

    for (int dy = 0; dy < barH; ++dy) {
        for (int dx = 0; dx < barW; ++dx) {
            int y = top + dy;
            if (left1 + dx < size && y < size)
                SetPixelPMA(bits, stride, left1 + dx, y, color);
            if (left2 + dx < size && y < size)
                SetPixelPMA(bits, stride, left2 + dx, y, color);
        }
    }
}

/// Draw an X symbol.
static void DrawXSymbol(uint32_t* bits, int stride, int size, uint32_t color) {
    float s = static_cast<float>(size);
    float x0 = s * 0.30f, y0 = s * 0.28f;
    float x1 = s * 0.70f, y1 = s * 0.58f;

    auto drawLine = [&](float ax, float ay, float bx, float by) {
        int steps = static_cast<int>(std::max(std::abs(bx - ax), std::abs(by - ay)) * 2.0f) + 1;
        for (int i = 0; i <= steps; ++i) {
            float t = static_cast<float>(i) / static_cast<float>(steps);
            int px = static_cast<int>(ax + t * (bx - ax));
            int py = static_cast<int>(ay + t * (by - ay));
            if (px >= 0 && px < size && py >= 0 && py < size)
                SetPixelPMA(bits, stride, px, py, color);
        }
    };

    drawLine(x0, y0, x1, y1);  // top-left to bottom-right
    drawLine(x1, y0, x0, y1);  // top-right to bottom-left
}

/// Draw a circular arrow (update symbol) — simplified as "U" with arrowhead.
static void DrawUpdateSymbol(uint32_t* bits, int stride, int size, uint32_t color) {
    float s  = static_cast<float>(size);
    float cx = s * 0.50f;
    float cy = s * 0.42f;
    float r  = s * 0.15f;

    // Arc
    for (int deg = 30; deg < 330; deg += 3) {
        float rad = static_cast<float>(deg) * 3.14159265f / 180.0f;
        int px = static_cast<int>(cx + r * std::cos(rad));
        int py = static_cast<int>(cy + r * std::sin(rad));
        if (px >= 0 && px < size && py >= 0 && py < size)
            SetPixelPMA(bits, stride, px, py, color);
    }

    // Arrowhead at ~330°
    float arad = 330.0f * 3.14159265f / 180.0f;
    int ax = static_cast<int>(cx + r * std::cos(arad));
    int ay = static_cast<int>(cy + r * std::sin(arad));
    for (int dy = -1; dy <= 1; ++dy)
        for (int dx = 0; dx <= 2; ++dx)
            if (ax + dx >= 0 && ax + dx < size && ay + dy >= 0 && ay + dy < size)
                SetPixelPMA(bits, stride, ax + dx, ay + dy, color);
}

/// Draw a magnifying glass (scan symbol).
static void DrawScanSymbol(uint32_t* bits, int stride, int size, uint32_t color) {
    float s  = static_cast<float>(size);
    float cx = s * 0.42f;
    float cy = s * 0.38f;
    float r  = s * 0.13f;

    // Circle
    for (int deg = 0; deg < 360; deg += 3) {
        float rad = static_cast<float>(deg) * 3.14159265f / 180.0f;
        int px = static_cast<int>(cx + r * std::cos(rad));
        int py = static_cast<int>(cy + r * std::sin(rad));
        if (px >= 0 && px < size && py >= 0 && py < size)
            SetPixelPMA(bits, stride, px, py, color);
    }

    // Handle (line from lower-right of circle downward-right)
    float hx0 = cx + r * 0.707f;
    float hy0 = cy + r * 0.707f;
    float hx1 = hx0 + s * 0.14f;
    float hy1 = hy0 + s * 0.14f;
    int steps = static_cast<int>(s * 0.5f);
    for (int i = 0; i <= steps; ++i) {
        float t = static_cast<float>(i) / static_cast<float>(steps);
        int px = static_cast<int>(hx0 + t * (hx1 - hx0));
        int py = static_cast<int>(hy0 + t * (hy1 - hy0));
        if (px >= 0 && px < size && py >= 0 && py < size)
            SetPixelPMA(bits, stride, px, py, color);
    }
}

/// Master icon factory.
static HICON CreateShieldIcon(int size, uint32_t bodyColor, uint32_t outlineColor,
                              uint32_t symbolColor, TrayIconState state) {
    HDC hdcScreen = GetDC(nullptr);
    if (!hdcScreen) return nullptr;

    uint32_t* colorBits = nullptr;
    HBITMAP hbmColor = CreateARGBBitmap(hdcScreen, size, size, &colorBits);
    if (!hbmColor) { ReleaseDC(nullptr, hdcScreen); return nullptr; }

    // Mask bitmap (monochrome — all zeros = opaque when color has alpha)
    HBITMAP hbmMask = CreateBitmap(size, size, 1, 1, nullptr);
    if (!hbmMask) {
        DeleteObject(hbmColor);
        ReleaseDC(nullptr, hdcScreen);
        return nullptr;
    }

    // Clear mask to all zeros (opaque)
    HDC hdcMask = CreateCompatibleDC(hdcScreen);
    HBITMAP hOldMask = static_cast<HBITMAP>(SelectObject(hdcMask, hbmMask));
    RECT rc = {0, 0, size, size};
    FillRect(hdcMask, &rc, static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
    SelectObject(hdcMask, hOldMask);
    DeleteDC(hdcMask);

    // Draw shield
    for (int y = 0; y < size; ++y) {
        for (int x = 0; x < size; ++x) {
            if (IsOnShieldOutline(x, y, size)) {
                SetPixelPMA(colorBits, size, x, y, outlineColor);
            } else if (IsInsideShield(x, y, size)) {
                SetPixelPMA(colorBits, size, x, y, bodyColor);
            }
            // else: transparent (already zeroed)
        }
    }

    // Draw state symbol
    switch (state) {
        case TrayIconState::Protected:
            DrawCheckmark(colorBits, size, size, symbolColor);
            break;
        case TrayIconState::Scanning:
            DrawScanSymbol(colorBits, size, size, symbolColor);
            break;
        case TrayIconState::Paused:
            DrawPauseSymbol(colorBits, size, size, symbolColor);
            break;
        case TrayIconState::Stopped:
        case TrayIconState::Degraded:
            DrawXSymbol(colorBits, size, size, symbolColor);
            break;
        case TrayIconState::Updating:
            DrawUpdateSymbol(colorBits, size, size, symbolColor);
            break;
        case TrayIconState::Uninitialized:
        default:
            // No symbol for uninitialized (plain gray shield)
            break;
    }

    ICONINFO ii{};
    ii.fIcon    = TRUE;
    ii.hbmMask  = hbmMask;
    ii.hbmColor = hbmColor;
    HICON hIcon = CreateIconIndirect(&ii);

    DeleteObject(hbmColor);
    DeleteObject(hbmMask);
    ReleaseDC(nullptr, hdcScreen);
    return hIcon;
}

// ============================================================================
// COLOR LOOKUP
// ============================================================================

static uint32_t GetBodyColor(TrayIconState state) {
    switch (state) {
        case TrayIconState::Protected:     return IconColors::kProtected;
        case TrayIconState::Scanning:      return IconColors::kScanning;
        case TrayIconState::Paused:        return IconColors::kPaused;
        case TrayIconState::Degraded:      return IconColors::kDegraded;
        case TrayIconState::Stopped:       return IconColors::kStopped;
        case TrayIconState::Updating:      return IconColors::kUpdating;
        case TrayIconState::Uninitialized:
        default:                           return IconColors::kUninitialized;
    }
}

// ============================================================================
// IMPL — ICON MANAGEMENT
// ============================================================================

HICON SystemTrayImpl::GetOrCreateIcon(TrayIconState state, int size) {
    auto idx = static_cast<size_t>(state);
    if (idx >= m_smallIcons.size()) idx = 0;

    auto& cache = (size <= kSmallIconSize) ? m_smallIcons : m_largeIcons;
    if (!cache[idx]) {
        cache[idx] = CreateShieldIcon(
            size,
            GetBodyColor(state),
            IconColors::kOutline,
            IconColors::kSymbol,
            state);
    }
    return cache[idx];
}

void SystemTrayImpl::DestroyIcons() {
    for (auto& h : m_smallIcons) { if (h) { DestroyIcon(h); h = nullptr; } }
    for (auto& h : m_largeIcons) { if (h) { DestroyIcon(h); h = nullptr; } }
}

// ============================================================================
// IMPL — LIFECYCLE
// ============================================================================

bool SystemTrayImpl::Initialize(const SystemTrayConfig& config) {
    if (m_status.load(std::memory_order_acquire) == SystemTrayStatus::Running) {
        SS_LOG_WARN(L"SystemTray", L"Already initialized");
        return true;
    }

    if (!config.IsValid()) {
        SS_LOG_ERROR(L"SystemTray", L"Invalid configuration");
        return false;
    }

    m_status.store(SystemTrayStatus::Initializing, std::memory_order_release);

    {
        std::unique_lock lock(m_mutex);
        m_config = config;
    }

    m_shutdownRequested.store(false, std::memory_order_release);
    m_initDone = false;
    m_initSuccess = false;
    m_startTime = std::chrono::steady_clock::now();

    // Launch dedicated message-pump thread
    m_thread = std::thread(&SystemTrayImpl::ThreadProc, this);

    // Wait for the thread to finish initialization
    {
        std::unique_lock lock(m_initMutex);
        m_initCV.wait(lock, [this] { return m_initDone; });
    }

    if (!m_initSuccess) {
        SS_LOG_ERROR(L"SystemTray", L"Failed to initialize tray icon on message thread");
        m_status.store(SystemTrayStatus::Error, std::memory_order_release);
        if (m_thread.joinable()) {
            m_shutdownRequested.store(true, std::memory_order_release);
            PostMessageW(m_hwnd, WM_QUIT, 0, 0);
            m_thread.join();
        }
        return false;
    }

    m_status.store(SystemTrayStatus::Running, std::memory_order_release);

    if (config.autoRegisterCallbacks) {
        RegisterEngineCallbacks();
    }

    SyncStateFromEngine();

    SS_LOG_INFO(L"SystemTray", L"System tray initialized successfully");
    return true;
}

void SystemTrayImpl::Shutdown() {
    auto expected = SystemTrayStatus::Running;
    if (!m_status.compare_exchange_strong(expected, SystemTrayStatus::Stopping,
                                          std::memory_order_acq_rel)) {
        // Not running — idempotent
        if (expected == SystemTrayStatus::Uninitialized ||
            expected == SystemTrayStatus::Stopped) {
            return;
        }
    }

    UnregisterEngineCallbacks();

    m_shutdownRequested.store(true, std::memory_order_release);

    if (m_hwnd) {
        PostMessageW(m_hwnd, WM_QUIT, 0, 0);
    }

    if (m_thread.joinable()) {
        m_thread.join();
    }

    DestroyIcons();

    m_status.store(SystemTrayStatus::Stopped, std::memory_order_release);
    SS_LOG_INFO(L"SystemTray", L"System tray shut down");
}

bool SystemTrayImpl::UpdateConfiguration(const SystemTrayConfig& config) {
    if (!config.IsValid()) return false;

    std::unique_lock lock(m_mutex);
    bool pollChanged = (m_config.statusPollIntervalMs != config.statusPollIntervalMs);
    bool animChanged = (m_config.enableScanAnimation != config.enableScanAnimation);
    m_config = config;
    lock.unlock();

    // Update poll timer if changed
    if (pollChanged && m_hwnd && config.statusPollIntervalMs > 0) {
        SetTimer(m_hwnd, TrayConstants::TIMER_STATUS_POLL,
                 config.statusPollIntervalMs, nullptr);
    }

    // Stop animation if disabled
    if (animChanged && !config.enableScanAnimation) {
        StopAnimation();
    }

    return true;
}

SystemTrayConfig SystemTrayImpl::GetConfiguration() const {
    std::shared_lock lock(m_mutex);
    return m_config;
}

// ============================================================================
// IMPL — THREAD & WINDOW
// ============================================================================

void SystemTrayImpl::ThreadProc() {
    // Register window class
    constexpr const wchar_t* kClassName = L"ShadowStrikeTrayWnd";

    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance      = GetModuleHandleW(nullptr);
    wc.lpszClassName  = kClassName;
    ATOM atom = RegisterClassExW(&wc);
    if (!atom && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        SS_LOG_ERROR(L"SystemTray", L"RegisterClassExW failed: %u", GetLastError());
        std::lock_guard lock(m_initMutex);
        m_initDone = true;
        m_initSuccess = false;
        m_initCV.notify_one();
        return;
    }

    // Create message-only window
    m_hwnd = CreateWindowExW(
        0, kClassName, L"ShadowStrikeTray", 0,
        0, 0, 0, 0,
        HWND_MESSAGE,     // message-only window
        nullptr,
        GetModuleHandleW(nullptr),
        this);            // pass 'this' via CREATESTRUCT

    if (!m_hwnd) {
        SS_LOG_ERROR(L"SystemTray", L"CreateWindowExW failed: %u", GetLastError());
        std::lock_guard lock(m_initMutex);
        m_initDone = true;
        m_initSuccess = false;
        m_initCV.notify_one();
        return;
    }

    // Store 'this' in window extra
    SetWindowLongPtrW(m_hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));

    // Register for TaskbarCreated (explorer.exe restart)
    m_taskbarCreatedMsg = RegisterWindowMessageW(L"TaskbarCreated");

    // Install the notification icon
    if (!InstallIcon()) {
        SS_LOG_ERROR(L"SystemTray", L"Failed to install notification icon");
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
        std::lock_guard lock(m_initMutex);
        m_initDone = true;
        m_initSuccess = false;
        m_initCV.notify_one();
        return;
    }

    // Start status poll timer
    {
        std::shared_lock lock(m_mutex);
        if (m_config.statusPollIntervalMs > 0) {
            SetTimer(m_hwnd, TrayConstants::TIMER_STATUS_POLL,
                     m_config.statusPollIntervalMs, nullptr);
        }
    }

    // Signal initialization success
    {
        std::lock_guard lock(m_initMutex);
        m_initDone = true;
        m_initSuccess = true;
        m_initCV.notify_one();
    }

    // Message pump
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (m_shutdownRequested.load(std::memory_order_acquire)) break;

        if (msg.message == WM_TIMER) {
            if (msg.wParam == TrayConstants::TIMER_STATUS_POLL) {
                SyncStateFromEngine();
            } else if (msg.wParam == TrayConstants::TIMER_ANIMATION) {
                OnAnimationTick();
            }
            continue;
        }

        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // Cleanup
    KillTimer(m_hwnd, TrayConstants::TIMER_STATUS_POLL);
    KillTimer(m_hwnd, TrayConstants::TIMER_ANIMATION);
    RemoveIcon();
    DestroyWindow(m_hwnd);
    m_hwnd = nullptr;
}

LRESULT CALLBACK SystemTrayImpl::WndProc(HWND hwnd, UINT msg,
                                          WPARAM wp, LPARAM lp) {
    auto* self = reinterpret_cast<SystemTrayImpl*>(
        GetWindowLongPtrW(hwnd, GWLP_USERDATA));

    if (!self) return DefWindowProcW(hwnd, msg, wp, lp);

    // TaskbarCreated — re-install icon after explorer.exe restart
    if (msg == self->m_taskbarCreatedMsg && self->m_taskbarCreatedMsg != 0) {
        SS_LOG_INFO(L"SystemTray", L"TaskbarCreated received — re-installing icon");
        self->m_statExplorerRestarts.fetch_add(1, std::memory_order_relaxed);
        self->m_iconInstalled = false;
        self->InstallIcon();
        return 0;
    }

    switch (msg) {
        case TrayConstants::WM_TRAY_CALLBACK:
            self->HandleTrayMessage(lp);
            return 0;

        case WM_COMMAND: {
            auto action = static_cast<TrayMenuAction>(LOWORD(wp));
            self->HandleMenuCommand(action);
            return 0;
        }

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;

        default:
            break;
    }

    return DefWindowProcW(hwnd, msg, wp, lp);
}

void SystemTrayImpl::HandleTrayMessage(LPARAM lp) {
    UINT event = LOWORD(lp);
    switch (event) {
        case WM_LBUTTONDBLCLK:
            LaunchDashboard();
            break;

        case WM_LBUTTONUP: {
            std::shared_lock lock(m_mutex);
            auto cb = m_clickCallback;
            lock.unlock();
            if (cb) cb();
            break;
        }

        case WM_RBUTTONUP:
        case WM_CONTEXTMENU:
            ShowContextMenu();
            break;

        default:
            break;
    }
}

// ============================================================================
// IMPL — CONTEXT MENU
// ============================================================================

void SystemTrayImpl::ShowContextMenu() {
    HMENU hMenu = CreatePopupMenu();
    if (!hMenu) return;

    m_statMenusShown.fetch_add(1, std::memory_order_relaxed);

    // ── Build menu ──
    // Default item (bold)
    AppendMenuW(hMenu, MF_STRING | MF_DEFAULT,
                static_cast<UINT_PTR>(TrayMenuAction::OpenDashboard),
                L"Open Dashboard");

    AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);

    // Protection status (informational, grayed)
    std::wstring statusText = L"Protection: ";
    switch (m_iconState.load(std::memory_order_acquire)) {
        case TrayIconState::Protected:     statusText += L"Active \x2713"; break;
        case TrayIconState::Scanning:      statusText += L"Scanning...";   break;
        case TrayIconState::Paused:        statusText += L"Paused";        break;
        case TrayIconState::Degraded:      statusText += L"Degraded";      break;
        case TrayIconState::Stopped:       statusText += L"Stopped";       break;
        case TrayIconState::Updating:      statusText += L"Updating...";   break;
        case TrayIconState::Uninitialized: statusText += L"Starting...";   break;
    }
    AppendMenuW(hMenu, MF_STRING | MF_GRAYED, 0, statusText.c_str());

    AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);

    // Scan options
    AppendMenuW(hMenu, MF_STRING,
                static_cast<UINT_PTR>(TrayMenuAction::QuickScan),
                L"Quick Scan");
    AppendMenuW(hMenu, MF_STRING,
                static_cast<UINT_PTR>(TrayMenuAction::FullScan),
                L"Full Scan");

    AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);

    // Pause/Resume protection submenu
    TrayIconState currentState = m_iconState.load(std::memory_order_acquire);
    if (currentState == TrayIconState::Paused) {
        AppendMenuW(hMenu, MF_STRING,
                    static_cast<UINT_PTR>(TrayMenuAction::ResumeProtection),
                    L"Resume Protection");
    } else {
        HMENU hPause = CreatePopupMenu();
        if (hPause) {
            AppendMenuW(hPause, MF_STRING,
                        static_cast<UINT_PTR>(TrayMenuAction::PauseProtection15m),
                        L"Pause for 15 minutes");
            AppendMenuW(hPause, MF_STRING,
                        static_cast<UINT_PTR>(TrayMenuAction::PauseProtection1h),
                        L"Pause for 1 hour");
            AppendMenuW(hPause, MF_STRING,
                        static_cast<UINT_PTR>(TrayMenuAction::PauseProtectionRestart),
                        L"Pause until restart");
            AppendMenuW(hMenu, MF_STRING | MF_POPUP,
                        reinterpret_cast<UINT_PTR>(hPause),
                        L"Pause Protection");
        }
    }

    AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);

    AppendMenuW(hMenu, MF_STRING,
                static_cast<UINT_PTR>(TrayMenuAction::OpenQuarantine),
                L"Quarantine");
    AppendMenuW(hMenu, MF_STRING,
                static_cast<UINT_PTR>(TrayMenuAction::CheckUpdates),
                L"Check for Updates");
    AppendMenuW(hMenu, MF_STRING,
                static_cast<UINT_PTR>(TrayMenuAction::OpenSettings),
                L"Settings");

    AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);

    AppendMenuW(hMenu, MF_STRING,
                static_cast<UINT_PTR>(TrayMenuAction::About),
                L"About ShadowStrike");

    AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);

    AppendMenuW(hMenu, MF_STRING,
                static_cast<UINT_PTR>(TrayMenuAction::Exit),
                L"Exit");

    // ── Show ──
    // Required: SetForegroundWindow before TrackPopupMenu for correct dismiss
    SetForegroundWindow(m_hwnd);

    POINT pt;
    GetCursorPos(&pt);
    TrackPopupMenuEx(hMenu,
                     TPM_LEFTALIGN | TPM_BOTTOMALIGN | TPM_RIGHTBUTTON,
                     pt.x, pt.y, m_hwnd, nullptr);

    // Required: post empty message after TrackPopupMenu
    PostMessageW(m_hwnd, WM_NULL, 0, 0);

    DestroyMenu(hMenu);
}

// ============================================================================
// IMPL — MENU COMMAND DISPATCH
// ============================================================================

void SystemTrayImpl::HandleMenuCommand(TrayMenuAction action) {
    SS_LOG_DEBUG(L"SystemTray", L"Menu action: %S",
                 GetTrayMenuActionName(action).data());

    // Notify user callback first
    {
        std::shared_lock lock(m_mutex);
        auto cb = m_actionCallback;
        lock.unlock();
        if (cb) cb(action);
    }

    switch (action) {
        case TrayMenuAction::OpenDashboard:
            LaunchDashboard();
            break;

        case TrayMenuAction::QuickScan:
            m_statScansRequested.fetch_add(1, std::memory_order_relaxed);
            try {
                auto& engine = Core::Engine::ScanEngine::Instance();
                Core::Engine::DirectoryScanRequest req;
                req.rootPath = L"C:\\";
                req.recursive = true;
                req.maxDepth = 3;
                req.context.type = Core::Engine::ScanType::OnDemand;
                req.context.priority = Core::Engine::ScanPriority::Normal;
                [[maybe_unused]] auto jobId = engine.CreateScanJob(req, Core::Engine::ScanPriority::Normal);
                SS_LOG_INFO(L"SystemTray", L"Quick scan requested from tray");
            } catch (...) {
                SS_LOG_ERROR(L"SystemTray", L"Failed to initiate quick scan");
            }
            break;

        case TrayMenuAction::FullScan:
            m_statScansRequested.fetch_add(1, std::memory_order_relaxed);
            try {
                auto& engine = Core::Engine::ScanEngine::Instance();
                Core::Engine::DirectoryScanRequest req;
                req.rootPath = L"C:\\";
                req.recursive = true;
                req.maxDepth = 100;
                req.context.type = Core::Engine::ScanType::OnDemand;
                req.context.priority = Core::Engine::ScanPriority::Normal;
                [[maybe_unused]] auto jobId = engine.CreateScanJob(req, Core::Engine::ScanPriority::Normal);
                SS_LOG_INFO(L"SystemTray", L"Full scan requested from tray");
            } catch (...) {
                SS_LOG_ERROR(L"SystemTray", L"Failed to initiate full scan");
            }
            break;

        case TrayMenuAction::PauseProtection15m:
            m_statPauseRequests.fetch_add(1, std::memory_order_relaxed);
            try {
                auto& rtp = RealTime::RealTimeProtection::Instance();
                rtp.Pause(15 * 60 * 1000, L"User paused from tray (15 min)");
            } catch (...) {
                SS_LOG_ERROR(L"SystemTray", L"Failed to pause protection");
            }
            break;

        case TrayMenuAction::PauseProtection1h:
            m_statPauseRequests.fetch_add(1, std::memory_order_relaxed);
            try {
                auto& rtp = RealTime::RealTimeProtection::Instance();
                rtp.Pause(60 * 60 * 1000, L"User paused from tray (1 hr)");
            } catch (...) {
                SS_LOG_ERROR(L"SystemTray", L"Failed to pause protection");
            }
            break;

        case TrayMenuAction::PauseProtectionRestart:
            m_statPauseRequests.fetch_add(1, std::memory_order_relaxed);
            try {
                auto& rtp = RealTime::RealTimeProtection::Instance();
                rtp.Pause(0, L"User paused from tray (until restart)");
            } catch (...) {
                SS_LOG_ERROR(L"SystemTray", L"Failed to pause protection");
            }
            break;

        case TrayMenuAction::ResumeProtection:
            m_statResumeRequests.fetch_add(1, std::memory_order_relaxed);
            try {
                auto& rtp = RealTime::RealTimeProtection::Instance();
                rtp.Resume();
            } catch (...) {
                SS_LOG_ERROR(L"SystemTray", L"Failed to resume protection");
            }
            break;

        case TrayMenuAction::OpenQuarantine:
        case TrayMenuAction::CheckUpdates:
        case TrayMenuAction::OpenSettings:
            // These open specific dashboard pages
            LaunchDashboard();
            break;

        case TrayMenuAction::About: {
            std::wstring msg = L"ShadowStrike NGAV/EDR Platform\n"
                               L"Version 1.0.0\n\n"
                               L"Enterprise-grade endpoint protection.\n\n"
                               L"\x00A9 2026 ShadowStrike Security";
            MessageBoxW(nullptr, msg.c_str(), L"About ShadowStrike",
                        MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND);
            break;
        }

        case TrayMenuAction::Exit: {
            bool canExit = true;
            {
                std::shared_lock lock(m_mutex);
                auto cb = m_exitCallback;
                lock.unlock();
                if (cb) canExit = cb();
            }
            if (canExit) {
                SS_LOG_INFO(L"SystemTray", L"Exit requested from tray menu");
                // The host process is responsible for actual shutdown.
                // We just remove the icon and post quit.
                m_shutdownRequested.store(true, std::memory_order_release);
                PostMessageW(m_hwnd, WM_QUIT, 0, 0);
            }
            break;
        }

        default:
            SS_LOG_WARN(L"SystemTray", L"Unknown menu action: %u",
                        static_cast<uint32_t>(action));
            break;
    }
}

// ============================================================================
// IMPL — ICON INSTALL / REMOVE / UPDATE
// ============================================================================

bool SystemTrayImpl::InstallIcon() {
    ZeroMemory(&m_nid, sizeof(m_nid));
    m_nid.cbSize           = sizeof(NOTIFYICONDATAW);
    m_nid.hWnd             = m_hwnd;
    m_nid.uID              = 1;
    m_nid.uFlags           = NIF_ICON | NIF_TIP | NIF_MESSAGE | NIF_SHOWTIP;
    m_nid.uCallbackMessage = TrayConstants::WM_TRAY_CALLBACK;
    m_nid.uVersion         = NOTIFYICON_VERSION_4;

    TrayIconState state = m_iconState.load(std::memory_order_acquire);
    m_nid.hIcon = GetOrCreateIcon(state, kSmallIconSize);

    std::wstring tip = GetTrayIconStateTooltip(state);
    StringCchCopyW(m_nid.szTip, ARRAYSIZE(m_nid.szTip), tip.c_str());

    if (!Shell_NotifyIconW(NIM_ADD, &m_nid)) {
        SS_LOG_ERROR(L"SystemTray", L"Shell_NotifyIconW(NIM_ADD) failed: %u",
                     GetLastError());
        return false;
    }

    Shell_NotifyIconW(NIM_SETVERSION, &m_nid);
    m_iconInstalled = true;
    return true;
}

void SystemTrayImpl::RemoveIcon() {
    if (m_iconInstalled) {
        Shell_NotifyIconW(NIM_DELETE, &m_nid);
        m_iconInstalled = false;
    }
}

void SystemTrayImpl::UpdateIcon() {
    if (!m_iconInstalled) return;

    TrayIconState state = m_iconState.load(std::memory_order_acquire);
    HICON hIcon = GetOrCreateIcon(state, kSmallIconSize);
    if (!hIcon) return;

    m_nid.hIcon  = hIcon;
    m_nid.uFlags = NIF_ICON;
    Shell_NotifyIconW(NIM_MODIFY, &m_nid);
}

void SystemTrayImpl::UpdateTooltipInternal() {
    if (!m_iconInstalled) return;

    std::wstring tip;
    {
        std::shared_lock lock(m_mutex);
        tip = m_tooltipOverride.empty()
            ? GetTrayIconStateTooltip(m_iconState.load(std::memory_order_acquire))
            : m_tooltipOverride;
    }

    // Truncate to Windows maximum
    if (tip.size() > TrayConstants::MAX_TOOLTIP_LENGTH) {
        tip.resize(TrayConstants::MAX_TOOLTIP_LENGTH);
    }

    StringCchCopyW(m_nid.szTip, ARRAYSIZE(m_nid.szTip), tip.c_str());
    m_nid.uFlags = NIF_TIP | NIF_SHOWTIP;
    Shell_NotifyIconW(NIM_MODIFY, &m_nid);
}

// ============================================================================
// IMPL — ANIMATION
// ============================================================================

void SystemTrayImpl::StartAnimation() {
    if (m_animating.load(std::memory_order_acquire)) return;

    std::shared_lock lock(m_mutex);
    if (!m_config.enableScanAnimation) return;
    lock.unlock();

    m_animFrame = 0;
    m_animating.store(true, std::memory_order_release);
    if (m_hwnd) {
        SetTimer(m_hwnd, TrayConstants::TIMER_ANIMATION,
                 TrayConstants::ANIMATION_INTERVAL_MS, nullptr);
    }
}

void SystemTrayImpl::StopAnimation() {
    if (!m_animating.load(std::memory_order_acquire)) return;

    m_animating.store(false, std::memory_order_release);
    if (m_hwnd) {
        KillTimer(m_hwnd, TrayConstants::TIMER_ANIMATION);
    }
    UpdateIcon();  // Restore static icon
}

void SystemTrayImpl::OnAnimationTick() {
    if (!m_animating.load(std::memory_order_acquire)) return;

    // Alternate between Scanning icon and a dimmed version
    m_animFrame = (m_animFrame + 1) % 4;

    // Pulse effect: cycle through alpha variations
    // For simplicity, alternate between Scanning and Uninitialized (blue <-> gray)
    TrayIconState displayState = (m_animFrame % 2 == 0)
        ? TrayIconState::Scanning
        : TrayIconState::Protected;

    HICON hIcon = GetOrCreateIcon(displayState, kSmallIconSize);
    if (hIcon && m_iconInstalled) {
        m_nid.hIcon  = hIcon;
        m_nid.uFlags = NIF_ICON;
        Shell_NotifyIconW(NIM_MODIFY, &m_nid);
    }
}

// ============================================================================
// IMPL — STATE
// ============================================================================

void SystemTrayImpl::SetIconState(TrayIconState state) {
    TrayIconState prev = m_iconState.exchange(state, std::memory_order_acq_rel);
    if (prev == state) return;

    m_statIconStateChanges.fetch_add(1, std::memory_order_relaxed);

    // Manage animation
    if (state == TrayIconState::Scanning) {
        StartAnimation();
    } else if (prev == TrayIconState::Scanning) {
        StopAnimation();
    }

    // Update icon on the message thread
    if (m_hwnd) {
        // PostMessage is thread-safe; the actual Shell_NotifyIconW call
        // happens on the message-pump thread via WM_APP+0x101.
        PostMessageW(m_hwnd, WM_APP + 0x101, 0, 0);
    }

    // Update tooltip
    UpdateTooltipInternal();
}

void SystemTrayImpl::SetTooltip(std::wstring_view tooltip) {
    {
        std::unique_lock lock(m_mutex);
        m_tooltipOverride = std::wstring(tooltip);
    }
    UpdateTooltipInternal();
}

std::wstring SystemTrayImpl::GetTooltip() const {
    std::shared_lock lock(m_mutex);
    if (!m_tooltipOverride.empty()) return m_tooltipOverride;
    return GetTrayIconStateTooltip(m_iconState.load(std::memory_order_acquire));
}

void SystemTrayImpl::ShowBalloon(std::wstring_view title, std::wstring_view msg,
                                  DWORD flags, uint32_t timeoutMs) {
    if (!m_iconInstalled) return;

    m_statBalloonsSent.fetch_add(1, std::memory_order_relaxed);

    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd   = m_hwnd;
    nid.uID    = 1;
    nid.uFlags = NIF_INFO;
    nid.dwInfoFlags = flags | NIIF_NOSOUND;
    nid.uTimeout    = timeoutMs;

    StringCchCopyW(nid.szInfoTitle, ARRAYSIZE(nid.szInfoTitle),
                   std::wstring(title).c_str());
    StringCchCopyW(nid.szInfo, ARRAYSIZE(nid.szInfo),
                   std::wstring(msg).c_str());

    Shell_NotifyIconW(NIM_MODIFY, &nid);
}

// ============================================================================
// IMPL — ENGINE INTEGRATION
// ============================================================================

void SystemTrayImpl::RegisterEngineCallbacks() {
    if (m_callbacksRegistered) return;

    try {
        // RTP state changes
        auto& rtp = RealTime::RealTimeProtection::Instance();
        m_rtpStateCallbackId = rtp.RegisterStateChangeCallback(
            [this](RealTime::ProtectionState prev,
                   RealTime::ProtectionState next,
                   std::wstring_view reason) {
                OnRTPStateChange(prev, next, reason);
            });

        // Threat detection
        m_rtpThreatCallbackId = rtp.RegisterThreatDetectionCallback(
            [this](const RealTime::ThreatEvent& event) {
                OnThreatDetected(event);
            });

        // Scan completion
        auto& engine = Core::Engine::ScanEngine::Instance();
        m_scanCompleteCallbackId = engine.RegisterCompleteCallback(
            [this](const Core::Engine::ScanStatistics& stats) {
                OnScanComplete(stats);
            });

        m_callbacksRegistered = true;
        SS_LOG_DEBUG(L"SystemTray", L"Engine callbacks registered (RTP state=%llu, "
                     L"threat=%llu, scan=%llu)",
                     m_rtpStateCallbackId, m_rtpThreatCallbackId,
                     m_scanCompleteCallbackId);
    } catch (const std::exception& e) {
        SS_LOG_WARN(L"SystemTray", L"Failed to register some engine callbacks: %S",
                    e.what());
    }
}

void SystemTrayImpl::UnregisterEngineCallbacks() {
    if (!m_callbacksRegistered) return;

    try {
        if (m_rtpStateCallbackId || m_rtpThreatCallbackId) {
            auto& rtp = RealTime::RealTimeProtection::Instance();
            if (m_rtpStateCallbackId)   rtp.UnregisterCallback(m_rtpStateCallbackId);
            if (m_rtpThreatCallbackId)  rtp.UnregisterCallback(m_rtpThreatCallbackId);
        }

        if (m_scanCompleteCallbackId) {
            auto& engine = Core::Engine::ScanEngine::Instance();
            engine.UnregisterCompleteCallback(m_scanCompleteCallbackId);
        }
    } catch (...) {
        // Shutdown path — swallow exceptions
    }

    m_rtpStateCallbackId     = 0;
    m_rtpThreatCallbackId    = 0;
    m_scanCompleteCallbackId = 0;
    m_callbacksRegistered    = false;
}

void SystemTrayImpl::SyncStateFromEngine() {
    try {
        auto& rtp = RealTime::RealTimeProtection::Instance();
        auto state = rtp.GetState();

        TrayIconState newState;
        switch (state) {
            case RealTime::ProtectionState::ACTIVE:
                newState = TrayIconState::Protected;
                break;
            case RealTime::ProtectionState::PAUSED:
                newState = TrayIconState::Paused;
                break;
            case RealTime::ProtectionState::DEGRADED:
                newState = TrayIconState::Degraded;
                break;
            case RealTime::ProtectionState::ERROR:
            case RealTime::ProtectionState::DISABLED:
            case RealTime::ProtectionState::SHUTTING_DOWN:
                newState = TrayIconState::Stopped;
                break;
            case RealTime::ProtectionState::INITIALIZING:
            case RealTime::ProtectionState::UNINITIALIZED:
            default:
                newState = TrayIconState::Uninitialized;
                break;
        }

        SetIconState(newState);
    } catch (...) {
        // Engine may not be initialized yet — leave icon as-is
    }
}

void SystemTrayImpl::OnRTPStateChange(RealTime::ProtectionState prev,
                                       RealTime::ProtectionState next,
                                       std::wstring_view reason) {
    TrayIconState newState;
    switch (next) {
        case RealTime::ProtectionState::ACTIVE:
            newState = TrayIconState::Protected;
            break;
        case RealTime::ProtectionState::PAUSED:
            newState = TrayIconState::Paused;
            break;
        case RealTime::ProtectionState::DEGRADED:
            newState = TrayIconState::Degraded;
            break;
        case RealTime::ProtectionState::ERROR:
        case RealTime::ProtectionState::DISABLED:
        case RealTime::ProtectionState::SHUTTING_DOWN:
            newState = TrayIconState::Stopped;
            break;
        default:
            newState = TrayIconState::Uninitialized;
            break;
    }

    SetIconState(newState);

    // Show balloon for significant state changes
    std::shared_lock lock(m_mutex);
    bool showBalloon = m_config.showStateChangeBalloons;
    lock.unlock();

    if (showBalloon) {
        std::wstring title = L"ShadowStrike Protection";
        std::wstring msg;
        DWORD flags = NIIF_INFO;

        switch (next) {
            case RealTime::ProtectionState::ACTIVE:
                msg = L"Real-time protection is active.";
                break;
            case RealTime::ProtectionState::PAUSED:
                msg = L"Real-time protection is paused.";
                flags = NIIF_WARNING;
                break;
            case RealTime::ProtectionState::DEGRADED:
                msg = L"Protection is running in degraded mode.";
                flags = NIIF_WARNING;
                break;
            case RealTime::ProtectionState::ERROR:
                msg = L"Protection encountered an error.";
                flags = NIIF_ERROR;
                break;
            case RealTime::ProtectionState::DISABLED:
                msg = L"Protection has been disabled.";
                flags = NIIF_ERROR;
                break;
            default:
                return;  // No balloon for transitional states
        }

        if (!reason.empty()) {
            msg += L" Reason: ";
            msg += reason;
        }

        ShowBalloon(title, msg, flags, 5000);
    }
}

void SystemTrayImpl::OnThreatDetected(const RealTime::ThreatEvent& event) {
    std::shared_lock lock(m_mutex);
    bool showBalloon = m_config.showThreatBalloons;
    lock.unlock();

    if (showBalloon) {
        // Also forward to NotificationManager for full toast support
        try {
            Communication::NotificationManager::Instance().ShowThreatAlert(
                event.threatName, event.filePath);
        } catch (...) {
            // Fallback to direct balloon
            std::wstring msg = L"Threat blocked: " + event.threatName +
                               L"\nFile: " + event.filePath;
            ShowBalloon(L"Threat Detected", msg, NIIF_WARNING, 8000);
        }
    }
}

void SystemTrayImpl::OnScanComplete(const Core::Engine::ScanStatistics& stats) {
    // Return icon to normal state
    SyncStateFromEngine();

    std::shared_lock lock(m_mutex);
    bool showBalloon = m_config.showScanCompleteBalloons;
    lock.unlock();

    if (showBalloon) {
        std::wstring msg = L"Scan completed. ";
        msg += std::to_wstring(stats.filesScanned) + L" files scanned, ";
        msg += std::to_wstring(stats.filesInfected) + L" threats found.";

        DWORD flags = (stats.filesInfected > 0) ? NIIF_WARNING : NIIF_INFO;
        ShowBalloon(L"Scan Complete", msg, flags, 6000);
    }
}

// ============================================================================
// IMPL — HELPERS
// ============================================================================

void SystemTrayImpl::LaunchDashboard() {
    m_statDashboardLaunches.fetch_add(1, std::memory_order_relaxed);

    std::wstring url;
    {
        std::shared_lock lock(m_mutex);
        url = m_config.dashboardUrl;
    }

    if (url.empty()) {
        url = TrayConstants::DEFAULT_DASHBOARD_URL;
    }

    HINSTANCE result = ShellExecuteW(nullptr, L"open", url.c_str(),
                                      nullptr, nullptr, SW_SHOWNORMAL);
    if (reinterpret_cast<intptr_t>(result) <= 32) {
        SS_LOG_ERROR(L"SystemTray", L"Failed to open dashboard URL: %ls (error %lld)",
                     url.c_str(), reinterpret_cast<intptr_t>(result));
    }
}

// ============================================================================
// IMPL — USER CALLBACKS
// ============================================================================

void SystemTrayImpl::RegisterActionCallback(TrayActionCallback cb) {
    std::unique_lock lock(m_mutex);
    m_actionCallback = std::move(cb);
}

void SystemTrayImpl::RegisterClickCallback(TrayClickCallback cb) {
    std::unique_lock lock(m_mutex);
    m_clickCallback = std::move(cb);
}

void SystemTrayImpl::RegisterExitCallback(TrayExitCallback cb) {
    std::unique_lock lock(m_mutex);
    m_exitCallback = std::move(cb);
}

// ============================================================================
// IMPL — STATISTICS
// ============================================================================

SystemTrayStatistics SystemTrayImpl::GetStatistics() const {
    auto now = std::chrono::steady_clock::now();
    SystemTrayStatistics stats;
    stats.menusShown        = m_statMenusShown.load(std::memory_order_relaxed);
    stats.dashboardLaunches = m_statDashboardLaunches.load(std::memory_order_relaxed);
    stats.scansRequested    = m_statScansRequested.load(std::memory_order_relaxed);
    stats.pauseRequests     = m_statPauseRequests.load(std::memory_order_relaxed);
    stats.resumeRequests    = m_statResumeRequests.load(std::memory_order_relaxed);
    stats.iconStateChanges  = m_statIconStateChanges.load(std::memory_order_relaxed);
    stats.explorerRestarts  = m_statExplorerRestarts.load(std::memory_order_relaxed);
    stats.balloonsSent      = m_statBalloonsSent.load(std::memory_order_relaxed);
    stats.uptimeSeconds     = std::chrono::duration_cast<std::chrono::seconds>(
                                  now - m_startTime).count();
    return stats;
}

void SystemTrayImpl::ResetStatistics() {
    m_statMenusShown.store(0, std::memory_order_relaxed);
    m_statDashboardLaunches.store(0, std::memory_order_relaxed);
    m_statScansRequested.store(0, std::memory_order_relaxed);
    m_statPauseRequests.store(0, std::memory_order_relaxed);
    m_statResumeRequests.store(0, std::memory_order_relaxed);
    m_statIconStateChanges.store(0, std::memory_order_relaxed);
    m_statExplorerRestarts.store(0, std::memory_order_relaxed);
    m_statBalloonsSent.store(0, std::memory_order_relaxed);
    m_startTime = std::chrono::steady_clock::now();
}

bool SystemTrayImpl::SelfTest() {
    if (!IsInitialized()) return false;

    // Verify icon can be created for each state
    for (int s = 0; s <= static_cast<int>(TrayIconState::Updating); ++s) {
        auto state = static_cast<TrayIconState>(s);
        HICON h = CreateShieldIcon(kSmallIconSize,
                                   GetBodyColor(state),
                                   IconColors::kOutline,
                                   IconColors::kSymbol,
                                   state);
        if (!h) {
            SS_LOG_ERROR(L"SystemTray", L"SelfTest: failed to create icon for state %d", s);
            return false;
        }
        DestroyIcon(h);
    }

    return true;
}

// ============================================================================
// SINGLETON — SystemTray
// ============================================================================

std::atomic<bool> SystemTray::s_instanceCreated{false};

SystemTray::SystemTray()  : m_impl(std::make_unique<SystemTrayImpl>()) {}
SystemTray::~SystemTray() = default;

SystemTray& SystemTray::Instance() noexcept {
    static SystemTray instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool SystemTray::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ── Delegators ──────────────────────────────────────────────────────────────

bool SystemTray::Initialize(const SystemTrayConfig& config) { return m_impl->Initialize(config); }
void SystemTray::Shutdown()                                  { m_impl->Shutdown(); }
bool SystemTray::IsInitialized() const noexcept              { return m_impl->IsInitialized(); }
SystemTrayStatus SystemTray::GetStatus() const noexcept      { return m_impl->GetStatus(); }
bool SystemTray::UpdateConfiguration(const SystemTrayConfig& c) { return m_impl->UpdateConfiguration(c); }
SystemTrayConfig SystemTray::GetConfiguration() const        { return m_impl->GetConfiguration(); }

void SystemTray::SetIconState(TrayIconState state)           { m_impl->SetIconState(state); }
TrayIconState SystemTray::GetIconState() const noexcept      { return m_impl->GetIconState(); }
void SystemTray::SetTooltip(std::wstring_view tip)           { m_impl->SetTooltip(tip); }
std::wstring SystemTray::GetTooltip() const                  { return m_impl->GetTooltip(); }

void SystemTray::ShowBalloon(std::wstring_view title, std::wstring_view msg,
                              DWORD flags, uint32_t timeoutMs) {
    m_impl->ShowBalloon(title, msg, flags, timeoutMs);
}

void SystemTray::RegisterEngineCallbacks()     { m_impl->RegisterEngineCallbacks(); }
void SystemTray::UnregisterEngineCallbacks()   { m_impl->UnregisterEngineCallbacks(); }
void SystemTray::SyncStateFromEngine()         { m_impl->SyncStateFromEngine(); }

void SystemTray::RegisterActionCallback(TrayActionCallback cb) { m_impl->RegisterActionCallback(std::move(cb)); }
void SystemTray::RegisterClickCallback(TrayClickCallback cb)   { m_impl->RegisterClickCallback(std::move(cb)); }
void SystemTray::RegisterExitCallback(TrayExitCallback cb)     { m_impl->RegisterExitCallback(std::move(cb)); }

SystemTrayStatistics SystemTray::GetStatistics() const { return m_impl->GetStatistics(); }
void SystemTray::ResetStatistics()                     { m_impl->ResetStatistics(); }
bool SystemTray::SelfTest()                            { return m_impl->SelfTest(); }

std::string SystemTray::GetVersionString() noexcept {
    return std::to_string(TrayConstants::VERSION_MAJOR) + "." +
           std::to_string(TrayConstants::VERSION_MINOR) + "." +
           std::to_string(TrayConstants::VERSION_PATCH);
}

// ============================================================================
// CONFIG VALIDATION
// ============================================================================

bool SystemTrayConfig::IsValid() const noexcept {
    if (!enabled) return true;  // Disabled config is always valid
    if (dashboardUrl.empty()) return false;
    if (statusPollIntervalMs != 0 && statusPollIntervalMs < 1000) return false;
    return true;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetTrayIconStateName(TrayIconState state) noexcept {
    switch (state) {
        case TrayIconState::Uninitialized: return "Uninitialized";
        case TrayIconState::Protected:     return "Protected";
        case TrayIconState::Scanning:      return "Scanning";
        case TrayIconState::Paused:        return "Paused";
        case TrayIconState::Degraded:      return "Degraded";
        case TrayIconState::Stopped:       return "Stopped";
        case TrayIconState::Updating:      return "Updating";
        default:                           return "Unknown";
    }
}

std::wstring GetTrayIconStateTooltip(TrayIconState state) {
    switch (state) {
        case TrayIconState::Protected:
            return L"ShadowStrike — Protected";
        case TrayIconState::Scanning:
            return L"ShadowStrike — Scanning...";
        case TrayIconState::Paused:
            return L"ShadowStrike — Protection Paused";
        case TrayIconState::Degraded:
            return L"ShadowStrike — Degraded Protection";
        case TrayIconState::Stopped:
            return L"ShadowStrike — Protection Stopped";
        case TrayIconState::Updating:
            return L"ShadowStrike — Updating...";
        case TrayIconState::Uninitialized:
        default:
            return L"ShadowStrike — Initializing...";
    }
}

std::string_view GetTrayMenuActionName(TrayMenuAction action) noexcept {
    switch (action) {
        case TrayMenuAction::OpenDashboard:          return "OpenDashboard";
        case TrayMenuAction::QuickScan:              return "QuickScan";
        case TrayMenuAction::FullScan:               return "FullScan";
        case TrayMenuAction::PauseProtection15m:     return "PauseProtection15m";
        case TrayMenuAction::PauseProtection1h:      return "PauseProtection1h";
        case TrayMenuAction::PauseProtectionRestart: return "PauseProtectionRestart";
        case TrayMenuAction::ResumeProtection:       return "ResumeProtection";
        case TrayMenuAction::OpenQuarantine:         return "OpenQuarantine";
        case TrayMenuAction::CheckUpdates:           return "CheckUpdates";
        case TrayMenuAction::OpenSettings:           return "OpenSettings";
        case TrayMenuAction::About:                  return "About";
        case TrayMenuAction::Exit:                   return "Exit";
        default:                                     return "Unknown";
    }
}

std::string_view GetSystemTrayStatusName(SystemTrayStatus status) noexcept {
    switch (status) {
        case SystemTrayStatus::Uninitialized: return "Uninitialized";
        case SystemTrayStatus::Initializing:  return "Initializing";
        case SystemTrayStatus::Running:       return "Running";
        case SystemTrayStatus::Stopping:      return "Stopping";
        case SystemTrayStatus::Stopped:       return "Stopped";
        case SystemTrayStatus::Error:         return "Error";
        default:                              return "Unknown";
    }
}

}  // namespace UI
}  // namespace ShadowStrike
