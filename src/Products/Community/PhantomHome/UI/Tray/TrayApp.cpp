/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * TrayApp.cpp — System-tray process implementation.
 *
 * Responsibilities (this file):
 *   - Single-instance mutex + second-instance signaling
 *   - Win32 window-class registration (message-only window)
 *   - NOTIFYICONDATAW lifecycle: NIM_ADD / NIM_MODIFY / NIM_DELETE
 *   - Icon-add retry loop (Explorer not ready at startup)
 *   - WM_TASKBARCREATED re-add after Explorer restart
 *   - Per-state tooltip text and icon selection
 *   - Launching ShadowStrikePhantomUI.exe on left-click / balloon click
 *   - DPI awareness, COM apartment init, dark-mode title-bar helper
 *   - Graceful shutdown on WM_CLOSE / WM_ENDSESSION / RequestQuit()
 *
 * NOT in this file (separate todos):
 *   - Context-menu population  (tray-menu)
 *   - Service IPC              (tray-ipc)
 *   - HKCU\Run self-install    (tray-autorun)
 */

// Include order: project windows config first, then Windows headers, then STL.
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>
#include <shellapi.h>
#include <dwmapi.h>
#include <objbase.h>
#include <winerror.h>

#include <atomic>
#include <array>
#include <cstdint>
#include <string>

#include "TrayApp.hpp"
#include "TrayIconIds.hpp"
#include "TrayMenu.hpp"
#include "AutoRun.hpp"
#include "TrayIpc.hpp"
#include "InstallProbe.hpp"
#include "PhantomCore/Utils/Logger.hpp"

#pragma comment(lib, "dwmapi.lib")

namespace ShadowStrike::PhantomHome::Tray {

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------

// Tray callback message posted by Shell to our message window.
static constexpr UINT kTrayCallbackMsg = WM_APP + 0x0001;

// Posted by a second process instance to ask us to surface the UI.
static constexpr UINT kWmShowMe = WM_USER + 0x1001;

// Internal: posted to self to open the Qt UI process.
static constexpr UINT kWmOpenUi = WM_USER + 0x2001;

// Internal: posted from SetState() to update icon+tooltip on the UI thread.
static constexpr UINT kWmUpdateIcon = WM_USER + 0x2002;

static constexpr wchar_t kWindowClassName[] = L"ShadowStrike_Tray_MessageWindow";
static constexpr wchar_t kMutexName[]       = L"Local\\ShadowStrike.PhantomHome.Tray";
static constexpr wchar_t kUiExeName[]       = L"ShadowStrikePhantomUI.exe";
static constexpr wchar_t kLogCategory[]     = L"TrayApp";

// Tray icon retry parameters: retry every 2 s for up to 60 s.
static constexpr UINT_PTR kRetryTimerId      = 1u;
static constexpr UINT     kRetryIntervalMs   = 2'000u;
static constexpr int      kMaxRetries        = 30;

// State-poll timer: query TrayIpc every 5 s to refresh icon/tooltip.
static constexpr UINT_PTR kPollTimerId       = 2u;
static constexpr UINT     kPollIntervalMs    = 5'000u;

// Stable tray icon ID used with Shell_NotifyIconW.
static constexpr UINT kIconId = 1u;

// ---------------------------------------------------------------------------
// RAII helpers
// ---------------------------------------------------------------------------

// RAII wrapper for Win32 HANDLE (CloseHandle on destruction).
class UniqueHandle final {
public:
    UniqueHandle() noexcept = default;
    explicit UniqueHandle(HANDLE h) noexcept : h_(h) {}
    ~UniqueHandle() noexcept { close(); }

    UniqueHandle(const UniqueHandle&)            = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& o) noexcept : h_(o.release()) {}
    UniqueHandle& operator=(UniqueHandle&& o) noexcept {
        if (this != &o) { close(); h_ = o.release(); }
        return *this;
    }

    [[nodiscard]] HANDLE get()   const noexcept { return h_; }
    [[nodiscard]] bool   valid() const noexcept { return h_ && h_ != INVALID_HANDLE_VALUE; }
    explicit operator bool()     const noexcept { return valid(); }

    HANDLE release() noexcept { HANDLE tmp = h_; h_ = nullptr; return tmp; }
    void   reset(HANDLE h = nullptr) noexcept { close(); h_ = h; }

private:
    void close() noexcept {
        if (valid()) { CloseHandle(h_); h_ = nullptr; }
    }
    HANDLE h_ = nullptr;
};

// RAII wrapper for HICON (DestroyIcon on destruction).
class UniqueIcon final {
public:
    UniqueIcon() noexcept = default;
    explicit UniqueIcon(HICON h) noexcept : h_(h) {}
    ~UniqueIcon() noexcept { reset(); }

    UniqueIcon(const UniqueIcon&)            = delete;
    UniqueIcon& operator=(const UniqueIcon&) = delete;

    UniqueIcon(UniqueIcon&& o) noexcept : h_(o.release()) {}
    UniqueIcon& operator=(UniqueIcon&& o) noexcept {
        if (this != &o) { reset(); h_ = o.release(); }
        return *this;
    }

    [[nodiscard]] HICON get()  const noexcept { return h_; }
    explicit operator bool()   const noexcept { return h_ != nullptr; }

    HICON release() noexcept { HICON tmp = h_; h_ = nullptr; return tmp; }
    void  reset(HICON h = nullptr) noexcept {
        if (h_) { DestroyIcon(h_); }
        h_ = h;
    }

private:
    HICON h_ = nullptr;
};

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

// Returns a human-readable description for a Win32 error code.
[[nodiscard]] static std::wstring FormatWin32Error(DWORD err) noexcept {
    wchar_t* raw = nullptr;
    const DWORD chars = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&raw), 0, nullptr);

    if (!raw || chars == 0) {
        if (raw) LocalFree(raw);
        return std::wstring(L"Unknown error (0x") + std::to_wstring(err) + L")";
    }

    std::wstring msg(raw, chars);
    LocalFree(raw);

    // Strip trailing whitespace/newlines.
    while (!msg.empty() && (msg.back() == L'\r' || msg.back() == L'\n' || msg.back() == L' '))
        msg.pop_back();

    return msg;
}

// Returns the tooltip string for a given TrayState.
[[nodiscard]] static const wchar_t* TipForState(TrayState s) noexcept {
    switch (s) {
    case TrayState::Healthy:  return L"ShadowStrike Phantom \u2014 Protected";
    case TrayState::AtRisk:   return L"ShadowStrike Phantom \u2014 Attention needed";
    case TrayState::Critical: return L"ShadowStrike Phantom \u2014 Threats detected";
    case TrayState::Paused:   return L"ShadowStrike Phantom \u2014 Protection paused";
    case TrayState::Offline:  return L"ShadowStrike Phantom \u2014 Service unavailable";
    default:                  return L"ShadowStrike Phantom";
    }
}

// Returns the IDI_TRAY_* resource ID for a given TrayState (0 = no resource).
[[nodiscard]] static WORD IconResourceForState(TrayState s) noexcept {
    switch (s) {
    case TrayState::Healthy:  return IDI_TRAY_HEALTHY;
    case TrayState::AtRisk:   return IDI_TRAY_ATRISK;
    case TrayState::Critical: return IDI_TRAY_CRITICAL;
    case TrayState::Paused:   return IDI_TRAY_PAUSED;
    case TrayState::Offline:  return IDI_TRAY_OFFLINE;
    default:                  return 0;
    }
}

// Attempts to apply the Windows 10 immersive dark-mode attribute to hwnd.
// No-op for message-only windows; provided as an extension point for any
// popup or dialog created in the future by the tray process.
static void ApplyDarkModeToWindow(HWND hwnd) noexcept {
    if (!hwnd) return;
    BOOL dark = TRUE;
    // DWMWA_USE_IMMERSIVE_DARK_MODE = 20 (Windows 10 build 18985+)
    if (FAILED(DwmSetWindowAttribute(hwnd, 20, &dark, sizeof(dark)))) {
        // Pre-release value = 19; try as fallback for older Windows 10 builds.
        DwmSetWindowAttribute(hwnd, 19, &dark, sizeof(dark));
    }
}

// Resolves the full path of ShadowStrikePhantomUI.exe by replacing the
// current executable filename in the module path.
[[nodiscard]] static std::wstring GetUiExePath() noexcept {
    wchar_t buf[MAX_PATH + 1]{};
    if (!GetModuleFileNameW(nullptr, buf, MAX_PATH)) {
        return {};
    }
    std::wstring path(buf);
    const auto slash = path.find_last_of(L'\\');
    if (slash == std::wstring::npos) return {};
    path.resize(slash + 1);
    path += kUiExeName;
    return path;
}

// ---------------------------------------------------------------------------
// TrayApp::Impl
// ---------------------------------------------------------------------------

struct TrayApp::Impl {
    // ---- Fields -------------------------------------------------------------

    HINSTANCE       hInst{nullptr};
    HWND            hwndMsg{nullptr};
    NOTIFYICONDATAW nid{};
    UniqueHandle    hMutex;

    // Icons indexed by static_cast<size_t>(TrayState): [0]=Unknown … [5]=Offline.
    std::array<UniqueIcon, 6> icons;

    std::atomic<TrayState> state{TrayState::Unknown};

    // Registered message ID for WM_TASKBARCREATED (varies per session).
    UINT wmTaskbarCreated{0};

    bool iconAdded{false};
    int  retryCount{0};

    // ---- Construction / destruction -----------------------------------------

    Impl()  = default;
    ~Impl() = default;  // UniqueIcon/UniqueHandle RAII handles all cleanup.

    // ---- Icon management ----------------------------------------------------

    void LoadIcons(HINSTANCE hInstance) noexcept {
        const int cx = GetSystemMetrics(SM_CXSMICON);
        const int cy = GetSystemMetrics(SM_CYSMICON);

        // Pre-load the security-shield fallback (used when brand icons are
        // absent, i.e., before the packaging step embeds the .ico files).
        HICON fallback = static_cast<HICON>(
            LoadImageW(nullptr, IDI_SHIELD, IMAGE_ICON, cx, cy, LR_DEFAULTCOLOR));
        if (!fallback) {
            fallback = static_cast<HICON>(
                LoadImageW(nullptr, IDI_APPLICATION, IMAGE_ICON, cx, cy, LR_DEFAULTCOLOR));
        }

        for (int i = 1; i <= 5; ++i) {
            const TrayState s    = static_cast<TrayState>(i);
            const WORD      rid  = IconResourceForState(s);
            HICON ico = static_cast<HICON>(
                LoadImageW(hInstance, MAKEINTRESOURCEW(rid),
                           IMAGE_ICON, cx, cy, LR_DEFAULTCOLOR));
            if (!ico) {
                // Brand icon not yet embedded; clone the fallback handle so
                // each slot owns an independent copy (safe to DestroyIcon later).
                if (fallback) {
                    ico = static_cast<HICON>(
                        CopyImage(fallback, IMAGE_ICON, cx, cy, LR_DEFAULTCOLOR));
                }
                if (!ico) {
                    SS_LOG_WARN(kLogCategory,
                        L"Could not load icon for TrayState %d (brand icon missing, no fallback available)", i);
                }
            }
            if (ico) icons[i].reset(ico);
        }

        // slot 0 (Unknown): clone fallback once more.
        if (fallback) {
            HICON unknownIco = static_cast<HICON>(
                CopyImage(fallback, IMAGE_ICON, cx, cy, LR_DEFAULTCOLOR));
            if (unknownIco) icons[0].reset(unknownIco);
            DestroyIcon(fallback);  // original is no longer needed
        }
    }

    // Returns the HICON for the given state, falling back to Healthy (slot 1)
    // or Unknown (slot 0) if the requested slot is empty.
    [[nodiscard]] HICON IconForState(TrayState s) const noexcept {
        const size_t idx = static_cast<size_t>(s);
        if (idx < icons.size() && icons[idx]) return icons[idx].get();
        if (icons[1])                          return icons[1].get();  // Healthy fallback
        if (icons[0])                          return icons[0].get();  // Unknown fallback
        return nullptr;
    }

    // ---- NOTIFYICONDATAW setup ----------------------------------------------

    void SetupNid(HWND hwnd) noexcept {
        nid                    = {};
        nid.cbSize             = sizeof(NOTIFYICONDATAW);
        nid.hWnd               = hwnd;
        nid.uID                = kIconId;
        nid.uFlags             = NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_SHOWTIP;
        nid.uCallbackMessage   = kTrayCallbackMsg;
        nid.hIcon              = IconForState(TrayState::Unknown);
        wcscpy_s(nid.szTip, TipForState(TrayState::Unknown));
    }

    // ---- Icon add / retry ---------------------------------------------------

    // Attempts NIM_ADD followed by NIM_SETVERSION.
    // Returns true on success; caller is responsible for timer setup on false.
    [[nodiscard]] bool TryAddTrayIcon() noexcept {
        if (!Shell_NotifyIconW(NIM_ADD, &nid)) return false;

        iconAdded = true;

        // Upgrade to version 4 so LOWORD/HIWORD(lParam) split is honoured.
        NOTIFYICONDATAW nidVer{};
        nidVer.cbSize   = sizeof(NOTIFYICONDATAW);
        nidVer.hWnd     = nid.hWnd;
        nidVer.uID      = kIconId;
        nidVer.uVersion = NOTIFYICON_VERSION_4;
        if (!Shell_NotifyIconW(NIM_SETVERSION, &nidVer)) {
            SS_LOG_WARN(kLogCategory,
                L"Shell_NotifyIconW(NIM_SETVERSION) failed (GLE=%lu): %ls",
                GetLastError(), FormatWin32Error(GetLastError()).c_str());
        }
        return true;
    }

    // Removes the tray icon if it was successfully added.
    void RemoveTrayIcon() noexcept {
        if (!iconAdded) return;
        if (!Shell_NotifyIconW(NIM_DELETE, &nid)) {
            SS_LOG_LAST_ERROR(kLogCategory, L"Shell_NotifyIconW(NIM_DELETE) failed");
        }
        iconAdded = false;
    }

    // ---- WM_TRAY_UPDATE_ICON handler ----------------------------------------

    void ApplyStateToIcon() noexcept {
        if (!iconAdded) return;
        const TrayState s = state.load(std::memory_order_acquire);

        nid.uFlags = NIF_ICON | NIF_TIP | NIF_SHOWTIP;
        nid.hIcon  = IconForState(s);
        wcscpy_s(nid.szTip, TipForState(s));

        if (!Shell_NotifyIconW(NIM_MODIFY, &nid)) {
            SS_LOG_LAST_ERROR(kLogCategory, L"Shell_NotifyIconW(NIM_MODIFY) failed");
        }
    }

    // ---- Window procedure ---------------------------------------------------

    static LRESULT CALLBACK StaticWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) noexcept {
        Impl* self = nullptr;

        if (msg == WM_NCCREATE) {
            const auto* cs = reinterpret_cast<const CREATESTRUCTW*>(lp);
            self = static_cast<Impl*>(cs->lpCreateParams);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
            self->hwndMsg = hwnd;
        } else {
            self = reinterpret_cast<Impl*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        }

        if (!self) return DefWindowProcW(hwnd, msg, wp, lp);
        return self->WndProc(hwnd, msg, wp, lp);
    }

    LRESULT WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) noexcept {
        // Dynamically registered message: Explorer restarted → re-add icon.
        if (wmTaskbarCreated != 0 && msg == wmTaskbarCreated) {
            SS_LOG_INFO(kLogCategory, L"WM_TASKBARCREATED received; re-adding tray icon");
            iconAdded  = false;
            retryCount = 0;
            if (!TryAddTrayIcon()) {
                SetTimer(hwnd, kRetryTimerId, kRetryIntervalMs, nullptr);
            }
            return 0;
        }

        switch (msg) {

        // ------------------------------------------------------------------
        // Tray icon callback (NOTIFYICON_VERSION_4 layout):
        //   LOWORD(lParam) = notification event
        //   HIWORD(lParam) = icon ID
        //   GET_X_LPARAM(wParam) = cursor X
        //   GET_Y_LPARAM(wParam) = cursor Y
        // ------------------------------------------------------------------
        case kTrayCallbackMsg: {
            const UINT event = LOWORD(lp);
            switch (event) {
            case NIN_SELECT:
            case WM_LBUTTONUP:
                PostMessageW(hwnd, kWmOpenUi, 0, 0);
                break;
            case WM_RBUTTONUP:
            case WM_CONTEXTMENU:
                TrayApp::Instance().ShowContextMenu(hwnd);
                break;
            case NIN_BALLOONUSERCLICK:
                PostMessageW(hwnd, kWmOpenUi, 0, 0);
                break;
            default:
                break;
            }
            return 0;
        }

        // ------------------------------------------------------------------
        // Second instance signals us: surface the UI on the user's behalf.
        // ------------------------------------------------------------------
        case kWmShowMe:
            SS_LOG_INFO(kLogCategory, L"Received kWmShowMe from second instance");
            PostMessageW(hwnd, kWmOpenUi, 0, 0);
            return 0;

        // ------------------------------------------------------------------
        // Open the UI process (no arguments — surfaces the main dashboard).
        // ------------------------------------------------------------------
        case kWmOpenUi:
            TrayApp::LaunchMainUI();
            return 0;

        // ------------------------------------------------------------------
        // State change from SetState(): refresh icon and tooltip.
        // ------------------------------------------------------------------
        case kWmUpdateIcon:
            ApplyStateToIcon();
            return 0;

        // ------------------------------------------------------------------
        // Icon-add retry timer.
        // ------------------------------------------------------------------
        case WM_TIMER: {
            if (static_cast<UINT_PTR>(wp) == kRetryTimerId) {
                if (TryAddTrayIcon()) {
                    KillTimer(hwnd, kRetryTimerId);
                    SS_LOG_INFO(kLogCategory, L"Tray icon added after %d retry attempt(s)", retryCount + 1);
                } else {
                    ++retryCount;
                    if (retryCount >= kMaxRetries) {
                        KillTimer(hwnd, kRetryTimerId);
                        SS_LOG_ERROR(kLogCategory,
                            L"Tray icon could not be added after %d retries (%d s); giving up",
                            kMaxRetries, (kMaxRetries * kRetryIntervalMs) / 1000);
                    }
                }
            } else if (static_cast<UINT_PTR>(wp) == kPollTimerId) {
                // Poll service state every 5 s; update tray icon/tooltip accordingly.
                IPC::TrayState ipcState{};
                if (IPC::TrayIpc::Instance().GetState(ipcState)) {
                    TrayState newState = TrayState::Unknown;
                    if (ipcState.paused) {
                        newState = TrayState::Paused;
                    } else {
                        switch (ipcState.health) {
                        case IPC::TrayState::Health::Healthy:  newState = TrayState::Healthy;  break;
                        case IPC::TrayState::Health::AtRisk:   newState = TrayState::AtRisk;   break;
                        case IPC::TrayState::Health::Critical: newState = TrayState::Critical; break;
                        default:                               newState = TrayState::Unknown;  break;
                        }
                    }
                    TrayApp::Instance().SetState(newState);
                }
                // On failure, cached last-known state is retained by TrayIpc; no icon update.
            }
            return 0;
        }

        // ------------------------------------------------------------------
        // Shutdown paths.
        // ------------------------------------------------------------------
        case WM_CLOSE:
            SS_LOG_INFO(kLogCategory, L"WM_CLOSE received; requesting graceful exit");
            PostQuitMessage(0);
            return 0;

        case WM_ENDSESSION:
            if (wp) {
                SS_LOG_INFO(kLogCategory, L"WM_ENDSESSION received; requesting graceful exit");
                PostQuitMessage(0);
            }
            return 0;

        default:
            return DefWindowProcW(hwnd, msg, wp, lp);
        }
    }
};

// ---------------------------------------------------------------------------
// TrayApp — Meyers singleton + public API
// ---------------------------------------------------------------------------

TrayApp& TrayApp::Instance() {
    static TrayApp instance;
    return instance;
}

TrayApp::TrayApp()
    : m_impl(std::make_unique<Impl>()) {}

TrayApp::~TrayApp() = default;

int TrayApp::Run(HINSTANCE hInstance) {
    // Per-monitor DPI awareness (v2): must be set before any HWNDs are created.
    if (!SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)) {
        SS_LOG_WARN(kLogCategory,
            L"SetProcessDpiAwarenessContext(PER_MONITOR_V2) failed (GLE=%lu): %ls",
            GetLastError(), FormatWin32Error(GetLastError()).c_str());
    }

    // COM apartment: required for ShellExecuteW and any future shell operations.
    const HRESULT hrCom = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (FAILED(hrCom) && hrCom != RPC_E_CHANGED_MODE) {
        SS_LOG_ERROR(kLogCategory,
            L"CoInitializeEx failed (hr=0x%08lX)", static_cast<unsigned long>(hrCom));
        return 1;
    }
    const bool comOwned = SUCCEEDED(hrCom);

    SS_LOG_INFO(kLogCategory, L"ShadowStrike Phantom Tray starting (PID=%lu)", GetCurrentProcessId());

    // -----------------------------------------------------------------
    // Install probe — refuse to run as an orphan.
    //
    // The tray is a UI surface; if the MSI install anchor is absent OR
    // the tray binary is running outside [INSTALLFOLDER], we are a
    // stale residue (typically: hand-copied artifact from vm_shrd, or
    // an HKCU\Run entry that survived a botched uninstall).  Exit hard,
    // scrub our HKCU\Run self-heal value if we can, and never paint an
    // icon that would mislead the operator into thinking the product
    // is healthy.
    // -----------------------------------------------------------------
    {
        const InstallProbeResult probe = ProbeInstall();
        if (probe.state == InstallState::Orphaned) {
            SS_LOG_ERROR(kLogCategory,
                L"Orphaned tray detected; refusing to start. "
                L"Scrubbing HKCU\\Run autostart and exiting.");
            (void)RemoveAutoRun();  // best-effort cleanup
            if (comOwned) CoUninitialize();
            return 2;  // distinct exit code for orphan refusal
        }
        // InstalledNoSvc is allowed to proceed, but the tray will paint
        // the Offline icon and surface a balloon once the message loop
        // is up (see post-CreateWindow block below).
    }

    // -----------------------------------------------------------------
    // Single-instance mutex
    // -----------------------------------------------------------------
    m_impl->hMutex.reset(CreateMutexW(nullptr, TRUE, kMutexName));
    const DWORD mutexErr = GetLastError();

    if (!m_impl->hMutex.valid()) {
        SS_LOG_ERROR(kLogCategory,
            L"CreateMutexW('%ls') failed (GLE=%lu): %ls",
            kMutexName, mutexErr, FormatWin32Error(mutexErr).c_str());
        if (comOwned) CoUninitialize();
        return 1;
    }

    if (mutexErr == ERROR_ALREADY_EXISTS) {
        // Signal the existing instance to surface the main UI.
        HWND existing = FindWindowW(kWindowClassName, nullptr);
        if (existing) {
            PostMessageW(existing, kWmShowMe, 0, 0);
            SS_LOG_INFO(kLogCategory, L"Another tray instance already running; signaled it (hwnd=0x%p)", existing);
        } else {
            SS_LOG_WARN(kLogCategory,
                L"Another tray instance already running but its window was not found");
        }
        m_impl->hMutex.reset();
        if (comOwned) CoUninitialize();
        return 0;
    }

    m_impl->hInst          = hInstance;
    m_impl->wmTaskbarCreated = RegisterWindowMessageW(L"TaskbarCreated");
    if (!m_impl->wmTaskbarCreated) {
        SS_LOG_WARN(kLogCategory,
            L"RegisterWindowMessageW('TaskbarCreated') failed (GLE=%lu): %ls",
            GetLastError(), FormatWin32Error(GetLastError()).c_str());
    }

    // -----------------------------------------------------------------
    // Register the message-only window class
    // -----------------------------------------------------------------
    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc   = &TrayApp::Impl::StaticWndProc;
    wc.hInstance     = hInstance;
    wc.lpszClassName = kWindowClassName;

    if (!RegisterClassExW(&wc)) {
        const DWORD err = GetLastError();
        if (err != ERROR_CLASS_ALREADY_EXISTS) {
            SS_LOG_ERROR(kLogCategory,
                L"RegisterClassExW('%ls') failed (GLE=%lu): %ls",
                kWindowClassName, err, FormatWin32Error(err).c_str());
            m_impl->hMutex.reset();
            if (comOwned) CoUninitialize();
            return 1;
        }
    }

    // -----------------------------------------------------------------
    // Create the message-only (invisible) window
    // -----------------------------------------------------------------
    HWND hwnd = CreateWindowExW(
        0,
        kWindowClassName,
        L"ShadowStrike Tray",   // title unused on HWND_MESSAGE windows
        0,                       // style
        0, 0, 0, 0,              // position / size: irrelevant
        HWND_MESSAGE,            // message-only parent → never visible
        nullptr, hInstance,
        m_impl.get());           // lpCreateParams → picked up in WM_NCCREATE

    if (!hwnd) {
        const DWORD err = GetLastError();
        SS_LOG_ERROR(kLogCategory,
            L"CreateWindowExW('%ls') failed (GLE=%lu): %ls",
            kWindowClassName, err, FormatWin32Error(err).c_str());
        m_impl->hMutex.reset();
        if (comOwned) CoUninitialize();
        return 1;
    }

    // Extension point: apply dark-mode title bar to any non-message window
    // that may be created in the future by this process.
    ApplyDarkModeToWindow(hwnd);

    // -----------------------------------------------------------------
    // Load tray icons and initialise NOTIFYICONDATAW
    // -----------------------------------------------------------------
    m_impl->LoadIcons(hInstance);
    m_impl->SetupNid(hwnd);

    // -----------------------------------------------------------------
    // Add tray icon (retry on failure, e.g. Shell not ready at startup)
    // -----------------------------------------------------------------
    if (!m_impl->TryAddTrayIcon()) {
        SS_LOG_WARN(kLogCategory,
            L"Shell_NotifyIconW(NIM_ADD) failed; will retry every %u ms for up to %d s",
            kRetryIntervalMs, (kMaxRetries * kRetryIntervalMs) / 1000);
        SetTimer(hwnd, kRetryTimerId, kRetryIntervalMs, nullptr);
    } else {
        SS_LOG_INFO(kLogCategory, L"Tray icon added successfully");
    }

    // Start background IPC connection and 5 s state-poll timer.
    if (IPC::TrayIpc::Instance().Open()) {
        SS_LOG_INFO(kLogCategory, L"TrayIpc connected; starting %u ms state-poll timer", kPollIntervalMs);
    } else {
        SS_LOG_WARN(kLogCategory,
            L"TrayIpc::Open() failed at startup; will retry on each poll tick");
    }
    SetTimer(hwnd, kPollTimerId, kPollIntervalMs, nullptr);

    SS_LOG_INFO(kLogCategory, L"Entering message loop");

    // -----------------------------------------------------------------
    // HKCU\Run self-healing autorun registration (tray-autorun)
    //
    // Only register HKCU autostart when the install probe reported a
    // valid, anchored installation.  Otherwise HKCU\Run becomes a
    // resurrection vector that survives any future MSI uninstall.
    // -----------------------------------------------------------------
    {
        const InstallProbeResult probe = ProbeInstall();
        if (probe.state == InstallState::Installed) {
            if (!EnsureAutoRun()) {
                SS_LOG_WARN(kLogCategory,
                    L"Autorun registration failed; tray will not auto-start on next login.");
            }
        } else {
            SS_LOG_WARN(kLogCategory,
                L"Skipping HKCU\\Run self-heal: install state=%d", static_cast<int>(probe.state));
            (void)RemoveAutoRun();
            if (probe.state == InstallState::InstalledNoSvc) {
                // Force Offline state and emit a one-shot balloon so the
                // operator immediately sees the service is missing.
                TrayApp::Instance().SetState(TrayState::Offline);
            }
        }
    }

    // -----------------------------------------------------------------
    // Message loop
    // -----------------------------------------------------------------
    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // -----------------------------------------------------------------
    // Teardown
    // -----------------------------------------------------------------
    if (m_impl->retryCount > 0) {
        KillTimer(hwnd, kRetryTimerId);
    }
    KillTimer(hwnd, kPollTimerId);
    IPC::TrayIpc::Instance().Close();

    m_impl->RemoveTrayIcon();

    SS_LOG_INFO(kLogCategory,
        L"Tray exiting with code %d", static_cast<int>(msg.wParam));

    m_impl->hMutex.reset();  // Release before CoUninitialize so a new instance can start
    if (comOwned) CoUninitialize();

    return static_cast<int>(msg.wParam);
}

void TrayApp::SetState(TrayState newState) noexcept {
    m_impl->state.store(newState, std::memory_order_release);
    HWND hwnd = m_impl->hwndMsg;
    if (hwnd) PostMessageW(hwnd, kWmUpdateIcon, 0, 0);
}

TrayState TrayApp::CurrentState() const noexcept {
    return m_impl->state.load(std::memory_order_acquire);
}

void TrayApp::ShowContextMenu(HWND owner) {
    auto cmd = ShowTrayContextMenu(owner, CurrentState());
    if (cmd != TrayMenuCmd::None) {
        HandleTrayMenuCmd(cmd);
    }
}

void TrayApp::LaunchMainUI(LPCWSTR args) noexcept {
    const std::wstring uiPath = GetUiExePath();
    if (uiPath.empty()) {
        SS_LOG_ERROR(kLogCategory,
            L"LaunchMainUI: could not resolve UI executable path (GLE=%lu)",
            GetLastError());
        return;
    }

    const HINSTANCE rc = ShellExecuteW(
        nullptr, L"open", uiPath.c_str(), args, nullptr, SW_SHOWNORMAL);

    if (reinterpret_cast<INT_PTR>(rc) <= 32) {
        SS_LOG_ERROR(kLogCategory,
            L"LaunchMainUI: ShellExecuteW('%ls', args='%ls') failed (code=%td)",
            uiPath.c_str(), args ? args : L"(none)",
            reinterpret_cast<INT_PTR>(rc));
    } else {
        SS_LOG_INFO(kLogCategory,
            L"LaunchMainUI: launched '%ls' args='%ls'",
            uiPath.c_str(), args ? args : L"(none)");
    }
}

void TrayApp::RequestQuit() noexcept {
    HWND hwnd = m_impl->hwndMsg;
    if (hwnd) PostMessageW(hwnd, WM_QUIT, 0, 0);
}

} // namespace ShadowStrike::PhantomHome::Tray
