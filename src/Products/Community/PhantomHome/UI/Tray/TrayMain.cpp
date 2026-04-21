/*
 * ShadowStrike - Enterprise NGAV Platform
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * Licensed under GNU AGPL-v3. See LICENSE.txt at the repository root.
 */

/**
 * @file TrayMain.cpp
 * @brief Standalone IPC-only entry point for ShadowStrikePhantomTray.exe.
 *
 * Design
 * ------
 * The tray process runs in the interactive user's Win32 session at medium
 * integrity. It MUST NOT link, load, or otherwise duplicate the PhantomCore
 * scan engine, real-time protection, AI models, or signature database - all
 * of that lives inside ShadowStrikePhantomService.exe at LocalSystem and is
 * reached exclusively over the authenticated named pipe.
 *
 * Rationale: duplicating the engine in an interactive process would (a)
 * burn hundreds of MB of RAM per logged-on user, (b) place the real scan
 * engine inside a process the user can freely debug, dump, and patch, and
 * (c) open race conditions against the LocalSystem engine touching the
 * same on-disk resources (signature DB, quarantine, telemetry).
 *
 * This TU therefore depends only on:
 *   - Windows shell / user32 / gdi32 / advapi32
 *   - Products/Community/PhantomHome/UI/Client/IPC/PipeClient
 *   - Products/Community/PhantomHome/UI/IPC/Messages (header only)
 *   - PhantomCore/Utils/Logger (shared logging; carried by the PhantomCore
 *     static lib that Service and UI also pull).
 *
 * Lifecycle
 * ---------
 *   1. wWinMain acquires a per-session single-instance mutex to stop
 *      multiple trays from stacking up during fast user-switching.
 *   2. Create a hidden message-only window as the NIN_* message sink.
 *   3. Shell_NotifyIconW(NIM_ADD) installs the icon.
 *   4. PipeClient starts, connects to the service, performs the Hello
 *      handshake and begins pumping GetState + server push events.
 *   5. We translate OverallState -> icon + tooltip, and forward menu
 *      actions to the service over IPC.
 *   6. On WM_DESTROY / WM_QUERYENDSESSION we cleanly Shell_NotifyIconW
 *      (NIM_DELETE), PipeClient::Stop, then quit the message loop.
 *   7. We re-register on TaskbarCreated so the icon survives explorer
 *      crashes.
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shellapi.h>
#include <strsafe.h>
#include <wtsapi32.h>
#include <objbase.h>
#include <gdiplus.h>

#include <atomic>
#include <cstdint>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>

#include "PhantomCore/Utils/Logger.hpp"
#include "../PerfBudget/PerfBudget.hpp"
#include "Products/Community/PhantomHome/UI/IPC/Messages.hpp"
#include "Products/Community/PhantomHome/UI/Client/IPC/PipeClient.hpp"

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "gdiplus.lib")

namespace {

namespace ipc = ShadowStrike::PhantomHome::IPC;

// ---- Compile-time constants ------------------------------------------------

constexpr const wchar_t* kClassName       = L"ShadowStrikePhantomTrayClass";
constexpr const wchar_t* kWindowTitle     = L"ShadowStrike Phantom Tray";
constexpr const wchar_t* kMutexName       =
    L"Local\\ShadowStrike.PhantomHome.Tray.SingleInstance";
constexpr const wchar_t* kDashboardExe    = L"ShadowStrikePhantomUI.exe";
constexpr const wchar_t* kTooltipProtect  = L"ShadowStrike Phantom - protected";
constexpr const wchar_t* kTooltipAmber    = L"ShadowStrike Phantom - attention needed";
constexpr const wchar_t* kTooltipRed      = L"ShadowStrike Phantom - at risk";
constexpr const wchar_t* kTooltipPaused   = L"ShadowStrike Phantom - paused";
constexpr const wchar_t* kTooltipOffline  = L"ShadowStrike Phantom - service offline";

constexpr UINT  WM_TRAY_CALLBACK          = WM_APP + 0x100;
constexpr UINT  WM_CONN_STATE             = WM_APP + 0x101;
constexpr UINT  WM_PROTECTION_STATE       = WM_APP + 0x102;
constexpr UINT  ID_TRAY_ICON              = 1;

constexpr UINT_PTR TIMER_POLL_STATE       = 1;
constexpr UINT     POLL_INTERVAL_MS       = 5'000;

constexpr UINT ID_MENU_OPEN_DASHBOARD     = 1001;
constexpr UINT ID_MENU_QUICK_SCAN         = 1002;
constexpr UINT ID_MENU_FULL_SCAN          = 1003;
constexpr UINT ID_MENU_PAUSE_15M          = 1004;
constexpr UINT ID_MENU_PAUSE_1H           = 1005;
constexpr UINT ID_MENU_RESUME             = 1006;
constexpr UINT ID_MENU_OPEN_UI            = 1007;
constexpr UINT ID_MENU_EXIT               = 1099;

// Windows broadcasts TaskbarCreated when explorer restarts; we re-register
// the icon so it survives.
static UINT s_msg_taskbar_created = 0;

// ---- Global tray state (owned by wWinMain thread) --------------------------

struct TrayState {
    HWND                             hwnd{nullptr};
    HICON                            icon_green{nullptr};
    HICON                            icon_amber{nullptr};
    HICON                            icon_red{nullptr};
    HICON                            icon_paused{nullptr};
    HICON                            icon_offline{nullptr};
    // Brand icon loaded from disk (ShadowStrike_Logo.png next to the exe).
    // Unlike the shared system icons above, this one is owned by us and
    // must be released with DestroyIcon on shutdown.
    HICON                            icon_brand{nullptr};
    ULONG_PTR                        gdiplus_token{0};
    bool                             icon_installed{false};

    std::unique_ptr<ipc::PipeClient> client;
    std::atomic<bool>                connected{false};
    std::atomic<std::uint8_t>        protection_state{
        static_cast<std::uint8_t>(ipc::OverallState::Unknown)};
};

TrayState g_state;

// ---- Helpers ---------------------------------------------------------------

[[nodiscard]] HICON LoadSystemIcon(LPCWSTR resource) noexcept {
    // LoadImage with LR_SHARED returns a process-wide shared icon we must
    // not DestroyIcon on; matching the documented Windows contract.
    return static_cast<HICON>(::LoadImageW(
        nullptr, resource, IMAGE_ICON, 0, 0,
        LR_DEFAULTSIZE | LR_SHARED));
}

// Load the brand PNG that ships next to the tray exe and convert it to an
// HICON sized for the notification area. Caller owns the returned HICON and
// must release it with DestroyIcon. Returns nullptr on any failure - the
// caller is expected to fall back to the system shield icon in that case.
[[nodiscard]] HICON LoadBrandIconFromModuleDir() noexcept {
    wchar_t module_path[MAX_PATH] = {};
    const DWORD len = ::GetModuleFileNameW(nullptr, module_path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        return nullptr;
    }
    // Strip the exe filename, leaving a trailing backslash.
    for (DWORD i = len; i > 0; --i) {
        if (module_path[i - 1] == L'\\' || module_path[i - 1] == L'/') {
            module_path[i] = L'\0';
            break;
        }
    }
    wchar_t png_path[MAX_PATH] = {};
    if (FAILED(::StringCchPrintfW(png_path, MAX_PATH,
                                  L"%sassets\\ShadowStrike_Logo.png",
                                  module_path))) {
        return nullptr;
    }
    if (::GetFileAttributesW(png_path) == INVALID_FILE_ATTRIBUTES) {
        return nullptr;  // Not deployed - fine, we fall back.
    }

    // GDI+ is already initialised in wWinMain; creating a Bitmap here is
    // safe. Scope the Bitmap so GetHICON is called before destruction.
    HICON hicon = nullptr;
    {
        Gdiplus::Bitmap bitmap(png_path, FALSE);
        if (bitmap.GetLastStatus() != Gdiplus::Ok) {
            return nullptr;
        }
        // Rescale to the small-icon metric so the tray doesn't downsample a
        // 512x512 PNG every paint.
        const int cx = ::GetSystemMetrics(SM_CXSMICON);
        const int cy = ::GetSystemMetrics(SM_CYSMICON);
        Gdiplus::Bitmap scaled(cx > 0 ? cx : 16, cy > 0 ? cy : 16,
                               PixelFormat32bppARGB);
        Gdiplus::Graphics g(&scaled);
        g.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
        g.SetSmoothingMode(Gdiplus::SmoothingModeHighQuality);
        g.SetPixelOffsetMode(Gdiplus::PixelOffsetModeHighQuality);
        if (g.DrawImage(&bitmap, 0, 0, scaled.GetWidth(), scaled.GetHeight())
                != Gdiplus::Ok) {
            return nullptr;
        }
        if (scaled.GetHICON(&hicon) != Gdiplus::Ok) {
            return nullptr;
        }
    }
    return hicon;
}

[[nodiscard]] std::uint32_t CurrentSessionId() noexcept {
    DWORD sid = 0;
    if (::ProcessIdToSessionId(::GetCurrentProcessId(), &sid)) {
        return sid;
    }
    return 0;
}

[[nodiscard]] HICON PickIconFor(ipc::OverallState s, bool connected) noexcept {
    // Use the brand icon for healthy / informational states so the user
    // visually identifies our product in the tray. Keep the loud system
    // warning / error glyphs for Amber and Red because alert states MUST
    // be distinguishable at a glance even by colourblind users.
    if (!connected) {
        return g_state.icon_brand ? g_state.icon_brand : g_state.icon_offline;
    }
    switch (s) {
        case ipc::OverallState::Green:
            return g_state.icon_brand ? g_state.icon_brand : g_state.icon_green;
        case ipc::OverallState::Amber:  return g_state.icon_amber;
        case ipc::OverallState::Red:    return g_state.icon_red;
        case ipc::OverallState::Paused:
            return g_state.icon_brand ? g_state.icon_brand : g_state.icon_paused;
        case ipc::OverallState::Unknown:
        default:
            return g_state.icon_brand ? g_state.icon_brand : g_state.icon_offline;
    }
}

[[nodiscard]] const wchar_t* PickTooltipFor(ipc::OverallState s, bool connected) noexcept {
    if (!connected) return kTooltipOffline;
    switch (s) {
        case ipc::OverallState::Green:  return kTooltipProtect;
        case ipc::OverallState::Amber:  return kTooltipAmber;
        case ipc::OverallState::Red:    return kTooltipRed;
        case ipc::OverallState::Paused: return kTooltipPaused;
        default:                        return kTooltipOffline;
    }
}

void UpdateIcon() noexcept {
    if (!g_state.icon_installed) return;
    const auto st   = static_cast<ipc::OverallState>(g_state.protection_state.load());
    const bool conn = g_state.connected.load();

    NOTIFYICONDATAW nid{};
    nid.cbSize           = sizeof(nid);
    nid.hWnd             = g_state.hwnd;
    nid.uID              = ID_TRAY_ICON;
    nid.uFlags           = NIF_ICON | NIF_TIP;
    nid.hIcon            = PickIconFor(st, conn);
    ::StringCchCopyW(nid.szTip, ARRAYSIZE(nid.szTip), PickTooltipFor(st, conn));
    (void)::Shell_NotifyIconW(NIM_MODIFY, &nid);
}

bool InstallTrayIcon() noexcept {
    NOTIFYICONDATAW nid{};
    nid.cbSize           = sizeof(nid);
    nid.hWnd             = g_state.hwnd;
    nid.uID              = ID_TRAY_ICON;
    nid.uFlags           = NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_SHOWTIP;
    nid.uCallbackMessage = WM_TRAY_CALLBACK;
    nid.hIcon            = PickIconFor(
        static_cast<ipc::OverallState>(g_state.protection_state.load()),
        g_state.connected.load());
    ::StringCchCopyW(nid.szTip, ARRAYSIZE(nid.szTip),
                     PickTooltipFor(
                         static_cast<ipc::OverallState>(g_state.protection_state.load()),
                         g_state.connected.load()));

    if (!::Shell_NotifyIconW(NIM_ADD, &nid)) {
        return false;
    }
    nid.uVersion = NOTIFYICON_VERSION_4;
    (void)::Shell_NotifyIconW(NIM_SETVERSION, &nid);
    g_state.icon_installed = true;
    return true;
}

void RemoveTrayIcon() noexcept {
    if (!g_state.icon_installed) return;
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd   = g_state.hwnd;
    nid.uID    = ID_TRAY_ICON;
    (void)::Shell_NotifyIconW(NIM_DELETE, &nid);
    g_state.icon_installed = false;
}

void LaunchDashboard() noexcept {
    // Resolve the UI exe as a sibling of the tray exe so we do not execute
    // a different-directory process by mistake. This also prevents PATH-
    // hijacking: even a malicious PATH cannot redirect us.
    wchar_t self[MAX_PATH]{};
    const DWORD n = ::GetModuleFileNameW(nullptr, self, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        ShadowStrike::Utils::Logger::Warn(
            "Tray: GetModuleFileNameW failed gle={}", ::GetLastError());
        return;
    }
    std::wstring path{self, n};
    const auto slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return;
    path.resize(slash + 1);
    path.append(kDashboardExe);

    SHELLEXECUTEINFOW sei{};
    sei.cbSize       = sizeof(sei);
    sei.fMask        = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    sei.lpVerb       = L"open";
    sei.lpFile       = path.c_str();
    sei.nShow        = SW_SHOWNORMAL;
    if (!::ShellExecuteExW(&sei)) {
        ShadowStrike::Utils::Logger::Warn(
            "Tray: ShellExecuteExW '{}' failed gle={}",
            std::string(path.begin(), path.end()),
            ::GetLastError());
        return;
    }
    if (sei.hProcess) {
        ::CloseHandle(sei.hProcess);
    }
}

void SendScan(ipc::ScanType type) noexcept {
    if (!g_state.client) return;
    ipc::ScanStartRequest req{};
    req.type = type;
    g_state.client->RequestAsync(
        ipc::MessageType::ScanStart,
        req.ToJson(),
        [](std::optional<ipc::FrameEnvelope> /*reply*/) noexcept { /* fire-and-forget */ });
}

void SendPause(std::uint32_t duration_seconds) noexcept {
    if (!g_state.client) return;
    // PauseProtectionRequest is schema-stable; we intentionally construct
    // the payload by hand rather than including the full struct to keep
    // this TU decoupled from struct layout churn.
    nlohmann::json payload = { {"d", duration_seconds} };
    g_state.client->RequestAsync(
        ipc::MessageType::PauseProtection,
        payload,
        [](std::optional<ipc::FrameEnvelope>) noexcept {});
}

void SendResume() noexcept {
    if (!g_state.client) return;
    g_state.client->RequestAsync(
        ipc::MessageType::ResumeProtection,
        nlohmann::json::object(),
        [](std::optional<ipc::FrameEnvelope>) noexcept {});
}

void PollProtectionState() noexcept {
    if (!g_state.client || !g_state.connected.load()) return;
    g_state.client->RequestAsync(
        ipc::MessageType::GetState,
        nlohmann::json::object(),
        [](std::optional<ipc::FrameEnvelope> reply) noexcept {
            if (!reply) return;
            auto parsed = ipc::ProtectionStateReply::FromJson(reply->payload);
            if (!parsed) return;
            if (g_state.hwnd) {
                ::PostMessageW(g_state.hwnd, WM_PROTECTION_STATE,
                               static_cast<WPARAM>(parsed->state), 0);
            }
        });
}

void ShowContextMenu(HWND hwnd) noexcept {
    HMENU menu = ::CreatePopupMenu();
    if (!menu) return;

    const bool connected = g_state.connected.load();
    const UINT disabled  = connected ? 0u : static_cast<UINT>(MF_GRAYED);

    ::AppendMenuW(menu, MF_STRING, ID_MENU_OPEN_DASHBOARD, L"Open &Dashboard");
    ::SetMenuDefaultItem(menu, ID_MENU_OPEN_DASHBOARD, FALSE);
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | disabled, ID_MENU_QUICK_SCAN,  L"&Quick scan");
    ::AppendMenuW(menu, MF_STRING | disabled, ID_MENU_FULL_SCAN,   L"&Full scan");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | disabled, ID_MENU_PAUSE_15M,   L"Pause protection &15 minutes");
    ::AppendMenuW(menu, MF_STRING | disabled, ID_MENU_PAUSE_1H,    L"Pause protection &1 hour");
    ::AppendMenuW(menu, MF_STRING | disabled, ID_MENU_RESUME,      L"&Resume protection");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, ID_MENU_OPEN_UI,                L"Open &UI window");
    ::AppendMenuW(menu, MF_STRING, ID_MENU_EXIT,                   L"E&xit");

    POINT pt{};
    ::GetCursorPos(&pt);
    // SetForegroundWindow is required so the menu dismisses on outside click.
    ::SetForegroundWindow(hwnd);
    const UINT cmd = static_cast<UINT>(::TrackPopupMenuEx(
        menu,
        TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_NONOTIFY,
        pt.x, pt.y, hwnd, nullptr));
    ::DestroyMenu(menu);
    // Required by the menu message model.
    ::PostMessageW(hwnd, WM_NULL, 0, 0);

    switch (cmd) {
        case ID_MENU_OPEN_DASHBOARD:
        case ID_MENU_OPEN_UI:
            LaunchDashboard();
            break;
        case ID_MENU_QUICK_SCAN:
            SendScan(ipc::ScanType::Quick);
            break;
        case ID_MENU_FULL_SCAN:
            SendScan(ipc::ScanType::Full);
            break;
        case ID_MENU_PAUSE_15M:
            SendPause(15 * 60);
            break;
        case ID_MENU_PAUSE_1H:
            SendPause(60 * 60);
            break;
        case ID_MENU_RESUME:
            SendResume();
            break;
        case ID_MENU_EXIT:
            ::PostMessageW(hwnd, WM_CLOSE, 0, 0);
            break;
        default:
            break;
    }
}

LRESULT CALLBACK TrayWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) noexcept {
    if (msg == s_msg_taskbar_created && s_msg_taskbar_created != 0) {
        // Explorer restarted - reinstall the icon.
        g_state.icon_installed = false;
        (void)InstallTrayIcon();
        return 0;
    }

    switch (msg) {
        case WM_CREATE:
            ::SetTimer(hwnd, TIMER_POLL_STATE, POLL_INTERVAL_MS, nullptr);
            return 0;

        case WM_TIMER:
            if (wp == TIMER_POLL_STATE) {
                PollProtectionState();
            }
            return 0;

        case WM_CONN_STATE: {
            const bool c = (wp != 0);
            g_state.connected.store(c);
            UpdateIcon();
            if (c) {
                // First reply after reconnect gets us an authoritative state.
                PollProtectionState();
            }
            return 0;
        }

        case WM_PROTECTION_STATE: {
            g_state.protection_state.store(static_cast<std::uint8_t>(wp));
            UpdateIcon();
            return 0;
        }

        case WM_TRAY_CALLBACK: {
            const UINT event = LOWORD(lp);
            if (event == WM_LBUTTONDBLCLK ||
                event == NIN_SELECT ||
                event == NIN_KEYSELECT) {
                LaunchDashboard();
            } else if (event == WM_RBUTTONUP || event == WM_CONTEXTMENU) {
                ShowContextMenu(hwnd);
            }
            return 0;
        }

        case WM_QUERYENDSESSION:
            return TRUE;

        case WM_ENDSESSION:
        case WM_CLOSE:
            ::DestroyWindow(hwnd);
            return 0;

        case WM_DESTROY:
            ::KillTimer(hwnd, TIMER_POLL_STATE);
            RemoveTrayIcon();
            ::PostQuitMessage(0);
            return 0;

        default:
            break;
    }
    return ::DefWindowProcW(hwnd, msg, wp, lp);
}

[[nodiscard]] bool RegisterWindowClass(HINSTANCE inst) noexcept {
    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = TrayWndProc;
    wc.hInstance     = inst;
    wc.lpszClassName = kClassName;
    if (!::RegisterClassExW(&wc)) {
        const DWORD gle = ::GetLastError();
        if (gle != ERROR_CLASS_ALREADY_EXISTS) {
            ShadowStrike::Utils::Logger::Error(
                "Tray: RegisterClassExW failed gle={}", gle);
            return false;
        }
    }
    return true;
}

}  // namespace

extern "C" int WINAPI wWinMain(HINSTANCE inst,
                               HINSTANCE /*prev*/,
                               LPWSTR    /*cmd*/,
                               int       /*show*/) {
    using ::ShadowStrike::PhantomHome::UI::PerfBudget;
    using ::ShadowStrike::PhantomHome::UI::PerfBudgetLimits;

    PerfBudget::Instance().MarkProcessStart();
    {
        PerfBudgetLimits lim{};
        lim.soft_rss_bytes  =  48ull * 1024ull * 1024ull;
        lim.hard_rss_bytes  =  96ull * 1024ull * 1024ull;
        lim.soft_startup_ms = std::chrono::milliseconds{200};
        lim.hard_startup_ms = std::chrono::milliseconds{800};
        PerfBudget::Instance().Start(lim, "PhantomHome.Tray");
    }

    // Per-session single-instance gate.
    HANDLE mutex = ::CreateMutexW(nullptr, TRUE, kMutexName);
    if (!mutex || ::GetLastError() == ERROR_ALREADY_EXISTS) {
        if (mutex) ::CloseHandle(mutex);
        return 0;
    }

    // GDI+ is required to decode the brand PNG. Initialise once for the
    // whole process; a failure here is non-fatal (we simply fall back to
    // the system shield).
    {
        Gdiplus::GdiplusStartupInput gdip_in;
        if (Gdiplus::GdiplusStartup(&g_state.gdiplus_token, &gdip_in, nullptr)
                != Gdiplus::Ok) {
            g_state.gdiplus_token = 0;
        }
    }

    // Load icons up front so state-change paths never allocate.
    if (g_state.gdiplus_token) {
        g_state.icon_brand = LoadBrandIconFromModuleDir();
    }
    g_state.icon_green   = LoadSystemIcon(IDI_SHIELD);
    g_state.icon_amber   = LoadSystemIcon(IDI_WARNING);
    g_state.icon_red     = LoadSystemIcon(IDI_ERROR);
    g_state.icon_paused  = LoadSystemIcon(IDI_INFORMATION);
    g_state.icon_offline = LoadSystemIcon(IDI_APPLICATION);
    if (!g_state.icon_green || !g_state.icon_offline) {
        ShadowStrike::Utils::Logger::Error(
            "Tray: LoadImageW for system icons failed gle={}", ::GetLastError());
        if (g_state.icon_brand) { ::DestroyIcon(g_state.icon_brand); g_state.icon_brand = nullptr; }
        if (g_state.gdiplus_token) { Gdiplus::GdiplusShutdown(g_state.gdiplus_token); g_state.gdiplus_token = 0; }
        ::CloseHandle(mutex);
        return 1;
    }

    s_msg_taskbar_created = ::RegisterWindowMessageW(L"TaskbarCreated");

    if (!RegisterWindowClass(inst)) {
        ::CloseHandle(mutex);
        return 2;
    }

    g_state.hwnd = ::CreateWindowExW(
        0, kClassName, kWindowTitle,
        0, 0, 0, 0, 0,
        HWND_MESSAGE, nullptr, inst, nullptr);
    if (!g_state.hwnd) {
        ShadowStrike::Utils::Logger::Error(
            "Tray: CreateWindowExW failed gle={}", ::GetLastError());
        ::CloseHandle(mutex);
        return 3;
    }

    if (!InstallTrayIcon()) {
        ShadowStrike::Utils::Logger::Error(
            "Tray: Shell_NotifyIconW NIM_ADD failed gle={}", ::GetLastError());
        ::DestroyWindow(g_state.hwnd);
        ::CloseHandle(mutex);
        return 4;
    }

    // The tray is "ready" the moment the icon is on screen. Recording it
    // here gives us an honest cold-start latency number against the budget.
    PerfBudget::Instance().MarkProcessReady();

    // Spin up the IPC client. State callbacks marshal to the GUI thread via
    // PostMessage so we never touch GDI / Shell_NotifyIcon off-thread.
    ipc::PipeClient::Options opts{};
    opts.session_id = CurrentSessionId();
    auto client = std::make_unique<ipc::PipeClient>(opts);
    client->SetStateCallback([](bool connected) noexcept {
        if (g_state.hwnd) {
            ::PostMessageW(g_state.hwnd, WM_CONN_STATE, connected ? 1 : 0, 0);
        }
    });
    client->SetPushCallback([](const ipc::FrameEnvelope& env) noexcept {
        if (env.type != ipc::MessageType::EventStateChanged) return;
        auto parsed = ipc::ProtectionStateReply::FromJson(env.payload);
        if (!parsed || !g_state.hwnd) return;
        ::PostMessageW(g_state.hwnd, WM_PROTECTION_STATE,
                       static_cast<WPARAM>(parsed->state), 0);
    });
    client->Start();
    g_state.client = std::move(client);

    MSG msg{};
    while (::GetMessageW(&msg, nullptr, 0, 0) > 0) {
        ::TranslateMessage(&msg);
        ::DispatchMessageW(&msg);
    }

    // Teardown in reverse: stop IPC before window destruction already happened
    // via WM_DESTROY so the icon is gone; now kill the client and release the
    // single-instance mutex.
    if (g_state.client) {
        g_state.client->Stop();
        g_state.client.reset();
    }
    if (g_state.icon_brand) {
        ::DestroyIcon(g_state.icon_brand);
        g_state.icon_brand = nullptr;
    }
    if (g_state.gdiplus_token) {
        Gdiplus::GdiplusShutdown(g_state.gdiplus_token);
        g_state.gdiplus_token = 0;
    }
    ::CloseHandle(mutex);
    return static_cast<int>(msg.wParam);
}
