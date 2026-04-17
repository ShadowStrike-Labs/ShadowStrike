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
#include "ScreenshotBlocker.hpp"

#include "../Utils/Logger.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/RegistryUtils.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/ThreadPool.hpp"

#include <algorithm>
#include <deque>
#include <format>
#include <nlohmann/json.hpp>
#include <thread>

// Windows API linking
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Gdi32.lib")

namespace ShadowStrike::Banking {

    using namespace Utils;

    // ========================================================================
    // CONSTANTS
    // ========================================================================

    static const std::vector<std::wstring> KNOWN_SCREEN_RECORDERS = {
        L"obs64.exe", L"obs32.exe", L"camtasia.exe", L"snagiteditor.exe",
        L"fraps.exe", L"bandicam.exe", L"hypercam.exe", L"screencast.exe",
        L"lightshot.exe", L"sharex.exe", L"greenshot.exe", L"snippingtool.exe",
        L"snipandsketch.exe", L"gamebar.exe", L"teamviewer.exe", L"anydesk.exe"
    };

    static const std::vector<std::wstring> ACCESSIBILITY_TOOLS = {
        L"narrator.exe", L"magnify.exe", L"osk.exe", L"nvda.exe", L"jaws.exe"
    };

    // ========================================================================
    // IMPLEMENTATION CLASS
    // ========================================================================

    class ScreenshotBlockerImpl {
    public:
        ScreenshotBlockerImpl() = default;
        ~ScreenshotBlockerImpl() {
            Shutdown();
        }

        // --------------------------------------------------------------------
        // Initialization & Lifecycle
        // --------------------------------------------------------------------

        bool Initialize(const ScreenshotBlockerConfiguration& config) {
            std::unique_lock lock(m_mutex);

            if (m_status == ModuleStatus::Running) {
                SS_LOG_WARN(L"ScreenshotBlocker", L"Already initialized");
                return true;
            }

            m_config = config;
            if (!m_config.IsValid()) {
                SS_LOG_ERROR(L"ScreenshotBlocker", L"Invalid configuration");
                m_status = ModuleStatus::Error;
                return false;
            }

            // Load whitelist
            for (const auto& app : m_config.whitelistedApplications) {
                if (m_whitelistedApps.size() < ScreenshotConstants::MAX_WHITELISTED_APPS) {
                    m_whitelistedApps.insert(app);
                }
            }

            for (const auto& proc : m_config.whitelistedProcessNames) {
                if (m_whitelistedProcesses.size() < ScreenshotConstants::MAX_WHITELISTED_APPS) {
                    m_whitelistedProcesses.insert(proc);
                }
            }

            if (m_config.allowAccessibilityTools) {
                for (const auto& tool : ACCESSIBILITY_TOOLS) {
                    if (m_whitelistedProcesses.size() < ScreenshotConstants::MAX_WHITELISTED_APPS) {
                        m_whitelistedProcesses.insert(tool);
                    }
                }
            }

            m_status = ModuleStatus::Initializing;

            // Start background monitor if needed
            if (!m_monitoringThread.joinable()) {
                m_stopMonitoring.store(false, std::memory_order_release);
                m_monitoringThread = std::thread(&ScreenshotBlockerImpl::MonitorThread, this);
            }

            SS_LOG_INFO(L"ScreenshotBlocker", L"Initialized successfully. WDA support: %d",
                IsExcludeFromCaptureSupported());

            m_status = ModuleStatus::Running;
            return true;
        }

        void Shutdown() {
            // Signal the monitor thread to stop BEFORE taking the lock.
            // MonitorThread also acquires m_mutex, so joining while holding
            // the lock would deadlock.
            m_stopMonitoring.store(true, std::memory_order_release);

            if (m_monitoringThread.joinable()) {
                m_monitoringThread.join();
            }

            std::unique_lock lock(m_mutex);

            if (m_status == ModuleStatus::Stopped || m_status == ModuleStatus::Uninitialized) {
                return;
            }

            m_status = ModuleStatus::Stopping;

            // Unprotect all windows
            for (auto it = m_protectedWindows.begin(); it != m_protectedWindows.end(); ) {
                HWND hwnd = reinterpret_cast<HWND>(it->first);
                if (::IsWindow(hwnd)) {
                    ::SetWindowDisplayAffinity(hwnd, WDA_NONE);
                }
                it = m_protectedWindows.erase(it);
            }

            if (m_keyboardHook) {
                ::UnhookWindowsHookEx(m_keyboardHook);
                m_keyboardHook = nullptr;
            }

            UninstallGDIHooks();
            UninstallDirectXHooks();

            m_whitelistedApps.clear();
            m_whitelistedProcesses.clear();
            m_blockedApplications.clear();

            m_status = ModuleStatus::Stopped;
            SS_LOG_INFO(L"ScreenshotBlocker", L"Shutdown complete");
        }

        // --------------------------------------------------------------------
        // Status
        // --------------------------------------------------------------------

        [[nodiscard]] ModuleStatus GetStatus() const noexcept {
            std::shared_lock lock(m_mutex);
            return m_status;
        }

        [[nodiscard]] ScreenshotBlockerConfiguration GetConfig() const {
            std::shared_lock lock(m_mutex);
            return m_config;
        }

        void SetPaused(bool paused) {
            std::unique_lock lock(m_mutex);
            if (paused && m_status == ModuleStatus::Running) {
                m_status = ModuleStatus::Paused;
                SS_LOG_INFO(L"ScreenshotBlocker", L"Protection paused");
            } else if (!paused && m_status == ModuleStatus::Paused) {
                m_status = ModuleStatus::Running;
                SS_LOG_INFO(L"ScreenshotBlocker", L"Protection resumed");
            }
        }

        // --------------------------------------------------------------------
        // Configuration update (without full re-init)
        // --------------------------------------------------------------------

        bool UpdateConfig(const ScreenshotBlockerConfiguration& config) {
            if (!config.IsValid()) {
                SS_LOG_ERROR(L"ScreenshotBlocker", L"Invalid configuration update rejected");
                return false;
            }

            std::unique_lock lock(m_mutex);
            if (m_status != ModuleStatus::Running && m_status != ModuleStatus::Paused) {
                SS_LOG_ERROR(L"ScreenshotBlocker", L"Cannot update config: module not running");
                return false;
            }

            const bool printScreenChanged =
                (m_config.enablePrintScreenBlocking != config.enablePrintScreenBlocking);
            const bool clipboardChanged =
                (m_config.enableClipboardFiltering != config.enableClipboardFiltering);

            m_config = config;

            // Rebuild whitelist
            m_whitelistedApps.clear();
            m_whitelistedProcesses.clear();

            for (const auto& app : m_config.whitelistedApplications) {
                if (m_whitelistedApps.size() < ScreenshotConstants::MAX_WHITELISTED_APPS) {
                    m_whitelistedApps.insert(app);
                }
            }
            for (const auto& proc : m_config.whitelistedProcessNames) {
                if (m_whitelistedProcesses.size() < ScreenshotConstants::MAX_WHITELISTED_APPS) {
                    m_whitelistedProcesses.insert(proc);
                }
            }
            if (m_config.allowAccessibilityTools) {
                for (const auto& tool : ACCESSIBILITY_TOOLS) {
                    if (m_whitelistedProcesses.size() < ScreenshotConstants::MAX_WHITELISTED_APPS) {
                        m_whitelistedProcesses.insert(tool);
                    }
                }
            }

            lock.unlock();

            // Apply changed settings outside the lock
            if (printScreenChanged) {
                BlockPrintScreen(config.enablePrintScreenBlocking);
            }

            SS_LOG_INFO(L"ScreenshotBlocker", L"Configuration updated");
            return true;
        }

        // --------------------------------------------------------------------
        // Window Protection
        // --------------------------------------------------------------------

        bool ProtectWindow(WindowHandle hwnd, BlockingMethod method) {
            HWND nativeHwnd = reinterpret_cast<HWND>(hwnd);

            if (!::IsWindow(nativeHwnd)) {
                SS_LOG_WARN(L"ScreenshotBlocker", L"Invalid window handle: %llu", hwnd);
                return false;
            }

            std::unique_lock lock(m_mutex);

            // Check limit
            if (m_protectedWindows.size() >= ScreenshotConstants::MAX_PROTECTED_WINDOWS) {
                SS_LOG_ERROR(L"ScreenshotBlocker", L"Max protected windows reached");
                return false;
            }

            // Already protected?
            if (m_protectedWindows.count(hwnd)) {
                return true;
            }

            // Determine method
            if (method == BlockingMethod::None || method == BlockingMethod::Combined) {
                method = BlockingMethod::DisplayAffinity;
            }

            // Apply protection
            bool success = false;
            if (method == BlockingMethod::DisplayAffinity) {
                success = ApplyDisplayAffinity(nativeHwnd);
            }

            WindowProtectionCallback callbackCopy;
            ScreenshotProtectedWindow info;

            if (success) {
                info.hwnd = hwnd;
                info.protectionStartTime = std::chrono::system_clock::now();
                info.status = ProtectionStatus::Protected;
                info.appliedMethods.push_back(method);

                // Get process info
                DWORD pid = 0;
                ::GetWindowThreadProcessId(nativeHwnd, &pid);
                info.processId = pid;

                if (auto name = Utils::ProcessUtils::GetProcessName(pid)) {
                    info.processName = *name;
                }

                // Window title
                wchar_t title[256] = {0};
                ::GetWindowTextW(nativeHwnd, title, 256);
                info.windowTitle = title;

                wchar_t cls[256] = {0};
                ::GetClassNameW(nativeHwnd, cls, 256);
                info.windowClass = cls;

                m_protectedWindows[hwnd] = info;
                m_stats.currentlyProtected++;
                m_stats.totalProtectedWindows++;

                SS_LOG_INFO(L"ScreenshotBlocker", L"Protected window %p (%ls)", nativeHwnd, info.windowTitle.c_str());

                callbackCopy = m_windowCallback;
            } else {
                SS_LOG_ERROR(L"ScreenshotBlocker", L"Failed to protect window %p", nativeHwnd);
            }

            lock.unlock();

            // Invoke callback outside the lock to prevent deadlock
            if (success && callbackCopy) {
                callbackCopy(info, true);
            }

            return success;
        }

        bool UnprotectWindow(WindowHandle hwnd) {
            HWND nativeHwnd = reinterpret_cast<HWND>(hwnd);

            std::unique_lock lock(m_mutex);

            auto it = m_protectedWindows.find(hwnd);
            if (it == m_protectedWindows.end()) {
                return false;
            }

            // Remove affinity
            if (::IsWindow(nativeHwnd)) {
                ::SetWindowDisplayAffinity(nativeHwnd, WDA_NONE);
            }

            ScreenshotProtectedWindow info = it->second;
            m_protectedWindows.erase(it);

            if (m_stats.currentlyProtected.load(std::memory_order_relaxed) > 0) {
                m_stats.currentlyProtected--;
            }

            WindowProtectionCallback callbackCopy = m_windowCallback;

            SS_LOG_INFO(L"ScreenshotBlocker", L"Unprotected window %p", nativeHwnd);

            lock.unlock();

            // Invoke callback outside the lock
            if (callbackCopy) {
                callbackCopy(info, false);
            }

            return true;
        }

        [[nodiscard]] bool IsWindowProtected(WindowHandle hwnd) const {
            std::shared_lock lock(m_mutex);
            return m_protectedWindows.count(hwnd) > 0;
        }

        [[nodiscard]] std::optional<ScreenshotProtectedWindow> GetWindowInfo(WindowHandle hwnd) const {
            std::shared_lock lock(m_mutex);
            auto it = m_protectedWindows.find(hwnd);
            if (it != m_protectedWindows.end()) {
                return it->second;
            }
            return std::nullopt;
        }

        // --------------------------------------------------------------------
        // Capture Blocking
        // --------------------------------------------------------------------

        void BlockPrintScreen(bool block) {
            std::unique_lock lock(m_mutex);
            if (block) {
                if (!m_keyboardHook) {
                    m_keyboardHook = ::SetWindowsHookExW(WH_KEYBOARD_LL, KeyboardProc, ::GetModuleHandle(nullptr), 0);
                    if (m_keyboardHook) {
                        SS_LOG_INFO(L"ScreenshotBlocker", L"PrintScreen blocking enabled");
                    } else {
                        SS_LOG_LAST_ERROR(L"ScreenshotBlocker", L"Failed to install keyboard hook");
                    }
                }
            } else {
                if (m_keyboardHook) {
                    ::UnhookWindowsHookEx(m_keyboardHook);
                    m_keyboardHook = nullptr;
                    SS_LOG_INFO(L"ScreenshotBlocker", L"PrintScreen blocking disabled");
                }
            }
            m_config.enablePrintScreenBlocking = block;
        }

        void BlockCaptureApp(std::wstring_view processName) {
            std::wstring lower(processName);
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

            std::unique_lock lock(m_mutex);
            m_blockedApplications.insert(lower);
            SS_LOG_INFO(L"ScreenshotBlocker", L"Blocked capture application: %ls", lower.c_str());
        }

        void UnblockCaptureApp(std::wstring_view processName) {
            std::wstring lower(processName);
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

            std::unique_lock lock(m_mutex);
            m_blockedApplications.erase(lower);
            SS_LOG_INFO(L"ScreenshotBlocker", L"Unblocked capture application: %ls", lower.c_str());
        }

        [[nodiscard]] bool IsCaptureAppBlocked(std::wstring_view processName) const {
            std::wstring lower(processName);
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

            std::shared_lock lock(m_mutex);
            return m_blockedApplications.count(lower) > 0;
        }

        // --------------------------------------------------------------------
        // Whitelist
        // --------------------------------------------------------------------

        void WhitelistApplication(const std::wstring& path, const std::string& reason) {
            std::unique_lock lock(m_mutex);
            if (m_whitelistedApps.size() >= ScreenshotConstants::MAX_WHITELISTED_APPS) {
                SS_LOG_WARN(L"ScreenshotBlocker", L"Whitelist capacity reached, cannot add application");
                return;
            }
            m_whitelistedApps.insert(path);
            SS_LOG_INFO(L"ScreenshotBlocker", L"Whitelisted application: %ls (reason: %hs)",
                path.c_str(), reason.c_str());
        }

        void WhitelistProcess(const std::wstring& processName, const std::string& reason) {
            std::wstring lower = processName;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

            std::unique_lock lock(m_mutex);
            if (m_whitelistedProcesses.size() >= ScreenshotConstants::MAX_WHITELISTED_APPS) {
                SS_LOG_WARN(L"ScreenshotBlocker", L"Whitelist capacity reached, cannot add process");
                return;
            }
            m_whitelistedProcesses.insert(lower);
            SS_LOG_INFO(L"ScreenshotBlocker", L"Whitelisted process: %ls (reason: %hs)",
                lower.c_str(), reason.c_str());
        }

        void RemoveFromWhitelist(const std::wstring& processName) {
            std::wstring lower = processName;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

            std::unique_lock lock(m_mutex);
            m_whitelistedProcesses.erase(lower);
            m_whitelistedApps.erase(processName);
            SS_LOG_INFO(L"ScreenshotBlocker", L"Removed from whitelist: %ls", lower.c_str());
        }

        [[nodiscard]] bool IsWhitelisted(uint32_t processId) const {
            auto procName = Utils::ProcessUtils::GetProcessName(processId);
            if (!procName) {
                return false;
            }

            std::wstring lower = *procName;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

            std::shared_lock lock(m_mutex);
            if (m_whitelistedProcesses.count(lower) > 0) {
                return true;
            }

            // Also check by full path
            auto procPath = Utils::ProcessUtils::GetProcessPath(processId);
            if (procPath && m_whitelistedApps.count(*procPath) > 0) {
                return true;
            }

            return false;
        }

        void LoadAccessibilityWhitelist() {
            std::unique_lock lock(m_mutex);
            for (const auto& tool : ACCESSIBILITY_TOOLS) {
                if (m_whitelistedProcesses.size() < ScreenshotConstants::MAX_WHITELISTED_APPS) {
                    m_whitelistedProcesses.insert(tool);
                }
            }
            SS_LOG_INFO(L"ScreenshotBlocker", L"Loaded %zu accessibility tools into whitelist",
                ACCESSIBILITY_TOOLS.size());
        }

        // --------------------------------------------------------------------
        // Clipboard
        // --------------------------------------------------------------------

        void EnableClipboardFiltering(bool enable) {
            std::unique_lock lock(m_mutex);
            m_config.enableClipboardFiltering = enable;
            SS_LOG_INFO(L"ScreenshotBlocker", L"Clipboard filtering %ls",
                enable ? L"enabled" : L"disabled");
        }

        [[nodiscard]] bool IsClipboardFilteringEnabled() const noexcept {
            std::shared_lock lock(m_mutex);
            return m_config.enableClipboardFiltering;
        }

        void SanitizeClipboard() {
            if (!::OpenClipboard(nullptr)) return;

            // Check for bitmap/image formats
            if (::IsClipboardFormatAvailable(CF_BITMAP) ||
                ::IsClipboardFormatAvailable(CF_DIB) ||
                ::IsClipboardFormatAvailable(CF_DIBV5)) {

                ::EmptyClipboard();
                m_stats.clipboardEventsFiltered++;
                SS_LOG_WARN(L"ScreenshotBlocker", L"Sanitized clipboard image");
            }
            ::CloseClipboard();
        }

        void ClearClipboard() {
            if (::OpenClipboard(nullptr)) {
                ::EmptyClipboard();
                ::CloseClipboard();
            }
        }

        // --------------------------------------------------------------------
        // Helpers
        // --------------------------------------------------------------------

        [[nodiscard]] bool IsExcludeFromCaptureSupported() const {
            SystemUtils::OSVersion osVer;
            if (SystemUtils::QueryOSVersion(osVer)) {
                return osVer.build >= 19041;
            }
            return false;
        }

        [[nodiscard]] bool IsKnownScreenRecorder(std::wstring_view processName) const {
            std::wstring lowerName(processName);
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

            for (const auto& recorder : KNOWN_SCREEN_RECORDERS) {
                if (lowerName.find(recorder) != std::wstring::npos) {
                    return true;
                }
            }
            return false;
        }

        void LogCaptureAttempt(const CaptureAttemptEvent& event) {
            std::unique_lock lock(m_historyMutex);
            m_captureHistory.push_back(event);
            if (m_captureHistory.size() > ScreenshotConstants::MAX_CAPTURE_HISTORY) {
                m_captureHistory.pop_front();
            }

            CaptureAttemptCallback callbackCopy = m_captureCallback;
            lock.unlock();

            if (callbackCopy) {
                callbackCopy(event);
            }
        }

        // --------------------------------------------------------------------
        // Stats & Info
        // --------------------------------------------------------------------

        [[nodiscard]] ScreenshotBlockerStatistics GetStatistics() const {
            return m_stats;
        }

        void ResetStatistics() {
            m_stats.totalProtectedWindows.store(0, std::memory_order_relaxed);
            m_stats.currentlyProtected.store(0, std::memory_order_relaxed);
            m_stats.captureAttemptsDetected.store(0, std::memory_order_relaxed);
            m_stats.captureAttemptsBlocked.store(0, std::memory_order_relaxed);
            m_stats.clipboardEventsFiltered.store(0, std::memory_order_relaxed);
            m_stats.gdiCallsIntercepted.store(0, std::memory_order_relaxed);
            m_stats.dxCallsIntercepted.store(0, std::memory_order_relaxed);
            m_stats.whitelistedPasses.store(0, std::memory_order_relaxed);
            for (auto& counter : m_stats.byCaptureType) {
                counter.store(0, std::memory_order_relaxed);
            }
            m_stats.startTime = Clock::now();
            SS_LOG_INFO(L"ScreenshotBlocker", L"Statistics reset");
        }

        [[nodiscard]] std::vector<ScreenshotProtectedWindow> GetProtectedWindows() const {
            std::shared_lock lock(m_mutex);
            std::vector<ScreenshotProtectedWindow> windows;
            windows.reserve(m_protectedWindows.size());
            for (const auto& [hwnd, info] : m_protectedWindows) {
                windows.push_back(info);
            }
            return windows;
        }

        [[nodiscard]] std::vector<CaptureAttemptEvent> GetRecentAttempts(size_t maxCount) const {
            std::unique_lock lock(m_historyMutex);
            std::vector<CaptureAttemptEvent> result;

            const size_t count = (std::min)(maxCount, m_captureHistory.size());
            result.reserve(count);

            // Return the most recent entries
            auto it = m_captureHistory.end();
            std::advance(it, -static_cast<ptrdiff_t>(count));
            for (; it != m_captureHistory.end(); ++it) {
                result.push_back(*it);
            }
            return result;
        }

        void RegisterCaptureCallback(CaptureAttemptCallback cb) {
            std::unique_lock lock(m_mutex);
            m_captureCallback = std::move(cb);
        }

        void RegisterWindowCallback(WindowProtectionCallback cb) {
            std::unique_lock lock(m_mutex);
            m_windowCallback = std::move(cb);
        }

        void RegisterErrorCb(ErrorCallback cb) {
            std::unique_lock lock(m_mutex);
            m_errorCallback = std::move(cb);
        }

        void ClearCallbacks() {
            std::unique_lock lock(m_mutex);
            m_captureCallback = nullptr;
            m_windowCallback = nullptr;
            m_errorCallback = nullptr;
        }

        // --------------------------------------------------------------------
        // Hooks (User-mode stubs — require injection/detours framework)
        // --------------------------------------------------------------------

        // GDI/DirectX hook installation requires an inline-hooking or
        // detours library injected into target processes.  This module
        // applies SetWindowDisplayAffinity + keyboard hook + clipboard
        // filtering in the local process.  Cross-process API hooking is
        // handled by the PhantomSensor kernel driver callbacks and the
        // PhantomCortex injection pipeline; these entry points return false
        // to signal "not supported at this layer".

        bool InstallGDIHooks() {
            SS_LOG_WARN(L"ScreenshotBlocker",
                L"GDI hooks not available in user-mode module; "
                L"use PhantomSensor for cross-process capture interception");
            return false;
        }

        void UninstallGDIHooks() { /* No-op: hooks not installed at this layer */ }

        bool InstallDirectXHooks() {
            SS_LOG_WARN(L"ScreenshotBlocker",
                L"DirectX hooks not available in user-mode module; "
                L"use PhantomSensor for DXGI capture interception");
            return false;
        }

        void UninstallDirectXHooks() { /* No-op: hooks not installed at this layer */ }

        [[nodiscard]] bool IsPrintScreenBlocked() const noexcept {
            return m_keyboardHook != nullptr;
        }

        // --------------------------------------------------------------------
        // Self-test
        // --------------------------------------------------------------------

        [[nodiscard]] bool SelfTest() {
            // Create an invisible message-only window to verify
            // SetWindowDisplayAffinity works on this system.
            static constexpr wchar_t kClassName[] = L"SSScreenshotBlockerSelfTest";

            WNDCLASSEXW wc = {};
            wc.cbSize = sizeof(wc);
            wc.lpfnWndProc = ::DefWindowProcW;
            wc.hInstance = ::GetModuleHandleW(nullptr);
            wc.lpszClassName = kClassName;

            ATOM atom = ::RegisterClassExW(&wc);
            if (!atom) {
                SS_LOG_WARN(L"ScreenshotBlocker", L"SelfTest: RegisterClassEx failed");
                return false;
            }

            HWND testHwnd = ::CreateWindowExW(
                0, kClassName, L"", WS_OVERLAPPEDWINDOW,
                CW_USEDEFAULT, CW_USEDEFAULT, 1, 1,
                HWND_MESSAGE, nullptr, wc.hInstance, nullptr);

            bool result = false;
            if (testHwnd) {
                result = ApplyDisplayAffinity(testHwnd);
                if (result) {
                    ::SetWindowDisplayAffinity(testHwnd, WDA_NONE);
                }
                ::DestroyWindow(testHwnd);
            } else {
                SS_LOG_WARN(L"ScreenshotBlocker", L"SelfTest: CreateWindowEx failed");
            }

            ::UnregisterClassW(kClassName, wc.hInstance);
            SS_LOG_INFO(L"ScreenshotBlocker", L"SelfTest result: %ls",
                result ? L"PASS" : L"FAIL");
            return result;
        }

    private:
        // Internal state
        mutable std::shared_mutex m_mutex;
        ScreenshotBlockerConfiguration m_config;
        ModuleStatus m_status = ModuleStatus::Uninitialized;

        std::unordered_map<WindowHandle, ScreenshotProtectedWindow> m_protectedWindows;
        std::unordered_set<std::wstring> m_whitelistedApps;
        std::unordered_set<std::wstring> m_whitelistedProcesses;
        std::unordered_set<std::wstring> m_blockedApplications;

        // Hooks
        HHOOK m_keyboardHook = nullptr;

        // Stats
        mutable ScreenshotBlockerStatistics m_stats;

        // History
        mutable std::mutex m_historyMutex;
        std::deque<CaptureAttemptEvent> m_captureHistory;

        // Callbacks
        CaptureAttemptCallback m_captureCallback;
        WindowProtectionCallback m_windowCallback;
        ErrorCallback m_errorCallback;

        // Background thread
        std::thread m_monitoringThread;
        std::atomic<bool> m_stopMonitoring{false};

        // Static hook proc
        static LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
            if (nCode == HC_ACTION) {
                KBDLLHOOKSTRUCT* pkb = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);
                if (pkb && pkb->vkCode == VK_SNAPSHOT) {
                    auto& instance = ScreenshotBlocker::Instance();
                    if (instance.IsPrintScreenBlocked()) {
                        // Record the blocked attempt
                        instance.m_impl->m_stats.captureAttemptsDetected++;
                        instance.m_impl->m_stats.captureAttemptsBlocked++;

                        const auto idx = static_cast<size_t>(
                            (wParam == WM_SYSKEYDOWN || wParam == WM_SYSKEYUP)
                                ? CaptureAttemptType::AltPrintScreen
                                : CaptureAttemptType::PrintScreenKey);
                        if (idx < instance.m_impl->m_stats.byCaptureType.size()) {
                            instance.m_impl->m_stats.byCaptureType[idx]++;
                        }

                        return 1; // Eat the key
                    }
                }
            }
            return ::CallNextHookEx(nullptr, nCode, wParam, lParam);
        }

        bool ApplyDisplayAffinity(HWND hwnd) {
            DWORD affinity = WDA_NONE;

            if (IsExcludeFromCaptureSupported() && m_config.useEnhancedAffinity) {
                affinity = ScreenshotConstants::kWdaExcludeFromCapture;
            } else {
                affinity = ScreenshotConstants::kWdaMonitor;
            }

            if (::SetWindowDisplayAffinity(hwnd, affinity)) {
                return true;
            }

            // Fallback: if WDA_EXCLUDEFROMCAPTURE fails, try WDA_MONITOR
            if (affinity == ScreenshotConstants::kWdaExcludeFromCapture) {
                if (::SetWindowDisplayAffinity(hwnd, ScreenshotConstants::kWdaMonitor)) {
                    return true;
                }
            }

            SS_LOG_LAST_ERROR(L"ScreenshotBlocker", L"SetWindowDisplayAffinity failed");
            return false;
        }

        void MonitorThread() {
            while (!m_stopMonitoring.load(std::memory_order_acquire)) {
                try {
                    // 1. Check integrity of protected windows and purge stale entries
                    {
                        std::unique_lock lock(m_mutex);

                        if (m_status != ModuleStatus::Running) {
                            lock.unlock();
                            std::this_thread::sleep_for(
                                std::chrono::milliseconds(ScreenshotConstants::CAPTURE_SCAN_INTERVAL_MS));
                            continue;
                        }

                        for (auto it = m_protectedWindows.begin(); it != m_protectedWindows.end(); ) {
                            HWND hwnd = reinterpret_cast<HWND>(it->first);
                            if (!::IsWindow(hwnd)) {
                                // Window was destroyed — remove stale entry
                                if (m_stats.currentlyProtected.load(std::memory_order_relaxed) > 0) {
                                    m_stats.currentlyProtected--;
                                }
                                SS_LOG_DEBUG(L"ScreenshotBlocker",
                                    L"Purging stale window %p from protection map", hwnd);
                                it = m_protectedWindows.erase(it);
                                continue;
                            }

                            // Re-apply affinity in case it was removed externally
                            ApplyDisplayAffinity(hwnd);
                            ++it;
                        }
                    }

                    // 2. Clipboard check (polling — used when clipboard listener hooks
                    //    are not available at this layer)
                    {
                        std::shared_lock lock(m_mutex);
                        if (m_config.enableClipboardFiltering &&
                            m_status == ModuleStatus::Running) {
                            lock.unlock();
                            SanitizeClipboard();
                        }
                    }

                } catch (const std::exception& ex) {
                    SS_LOG_ERROR(L"ScreenshotBlocker", L"Monitor thread exception: %hs", ex.what());
                } catch (...) {
                    SS_LOG_ERROR(L"ScreenshotBlocker", L"Monitor thread unknown exception");
                }

                std::this_thread::sleep_for(
                    std::chrono::milliseconds(ScreenshotConstants::CAPTURE_SCAN_INTERVAL_MS));
            }
        }
    };

    // ========================================================================
    // SCREENSHOT BLOCKER IMPLEMENTATION
    // ========================================================================

    std::atomic<bool> ScreenshotBlocker::s_instanceCreated{false};

    ScreenshotBlocker& ScreenshotBlocker::Instance() noexcept {
        static ScreenshotBlocker instance;
        return instance;
    }

    bool ScreenshotBlocker::HasInstance() noexcept {
        return s_instanceCreated.load(std::memory_order_acquire);
    }

    ScreenshotBlocker::ScreenshotBlocker()
        : m_impl(std::make_unique<ScreenshotBlockerImpl>()) {
        s_instanceCreated.store(true, std::memory_order_release);
    }

    ScreenshotBlocker::~ScreenshotBlocker() {
        s_instanceCreated.store(false, std::memory_order_release);
    }

    bool ScreenshotBlocker::Initialize(const ScreenshotBlockerConfiguration& config) {
        return m_impl->Initialize(config);
    }

    void ScreenshotBlocker::Shutdown() {
        m_impl->Shutdown();
    }

    bool ScreenshotBlocker::IsInitialized() const noexcept {
        if (!m_impl) return false;
        const auto status = m_impl->GetStatus();
        return status != ModuleStatus::Uninitialized && status != ModuleStatus::Error;
    }

    ModuleStatus ScreenshotBlocker::GetStatus() const noexcept {
        if (!m_impl) return ModuleStatus::Uninitialized;
        return m_impl->GetStatus();
    }

    bool ScreenshotBlocker::IsRunning() const noexcept {
        return GetStatus() == ModuleStatus::Running;
    }

    bool ScreenshotBlocker::Start() {
        if (!m_impl) return false;
        const auto status = m_impl->GetStatus();
        if (status == ModuleStatus::Running) return true;
        if (status == ModuleStatus::Paused) {
            m_impl->SetPaused(false);
            return true;
        }
        // Not initialized — caller should use Initialize() first
        SS_LOG_ERROR(L"ScreenshotBlocker", L"Start() called but module is not initialized");
        return false;
    }

    bool ScreenshotBlocker::Stop() {
        Shutdown();
        return true;
    }

    void ScreenshotBlocker::Pause() {
        m_impl->SetPaused(true);
    }

    void ScreenshotBlocker::Resume() {
        m_impl->SetPaused(false);
    }

    bool ScreenshotBlocker::UpdateConfiguration(const ScreenshotBlockerConfiguration& config) {
        return m_impl->UpdateConfig(config);
    }

    ScreenshotBlockerConfiguration ScreenshotBlocker::GetConfiguration() const {
        return m_impl->GetConfig();
    }

    bool ScreenshotBlocker::ProtectWindow(WindowHandle hwnd) {
        return m_impl->ProtectWindow(hwnd, BlockingMethod::DisplayAffinity);
    }

    bool ScreenshotBlocker::ProtectWindow(WindowHandle hwnd, BlockingMethod method) {
        return m_impl->ProtectWindow(hwnd, method);
    }

    bool ScreenshotBlocker::UnprotectWindow(WindowHandle hwnd) {
        return m_impl->UnprotectWindow(hwnd);
    }

    bool ScreenshotBlocker::IsWindowProtected(WindowHandle hwnd) const {
        return m_impl->IsWindowProtected(hwnd);
    }

    ProtectionStatus ScreenshotBlocker::GetWindowProtectionStatus(WindowHandle hwnd) const {
        auto info = m_impl->GetWindowInfo(hwnd);
        return info ? info->status : ProtectionStatus::Unprotected;
    }

    std::optional<ScreenshotProtectedWindow> ScreenshotBlocker::GetProtectedWindowInfo(WindowHandle hwnd) const {
        return m_impl->GetWindowInfo(hwnd);
    }

    std::vector<ScreenshotProtectedWindow> ScreenshotBlocker::GetProtectedWindows() const {
        return m_impl->GetProtectedWindows();
    }

    size_t ScreenshotBlocker::ProtectProcessWindows(uint32_t processId) {
        struct EnumData {
            uint32_t targetPid;
            std::vector<HWND> hwnds;
        } data;
        data.targetPid = processId;

        ::EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
            auto* pData = reinterpret_cast<EnumData*>(lParam);
            DWORD pid = 0;
            ::GetWindowThreadProcessId(hwnd, &pid);

            if (pid == pData->targetPid && ::IsWindowVisible(hwnd)) {
                pData->hwnds.push_back(hwnd);
            }
            return TRUE;
        }, reinterpret_cast<LPARAM>(&data));

        size_t count = 0;
        for (HWND hwnd : data.hwnds) {
            if (ProtectWindow(reinterpret_cast<WindowHandle>(hwnd))) {
                count++;
            }
        }
        return count;
    }

    void ScreenshotBlocker::AutoProtectPasswordFields() {
        SS_LOG_INFO(L"ScreenshotBlocker", L"Scanning for password fields to auto-protect");

        // Enumerate top-level windows and look for edit controls with ES_PASSWORD style.
        // Protects the parent window of each password field found.
        struct EnumCtx {
            ScreenshotBlocker* self;
            size_t protectedCount;
        } ctx{this, 0};

        ::EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
            auto* pCtx = reinterpret_cast<EnumCtx*>(lParam);
            if (!::IsWindowVisible(hwnd)) return TRUE;

            // Enumerate child controls looking for password edit fields
            ::EnumChildWindows(hwnd, [](HWND child, LPARAM innerParam) -> BOOL {
                wchar_t className[64] = {};
                ::GetClassNameW(child, className, 64);

                // Standard Edit control with ES_PASSWORD style
                if (_wcsicmp(className, L"Edit") == 0) {
                    LONG_PTR style = ::GetWindowLongPtrW(child, GWL_STYLE);
                    if (style & ES_PASSWORD) {
                        auto* ctx2 = reinterpret_cast<EnumCtx*>(innerParam);
                        // Protect the top-level parent, not the edit control itself
                        HWND topLevel = ::GetAncestor(child, GA_ROOT);
                        if (topLevel && !ctx2->self->IsWindowProtected(
                                reinterpret_cast<WindowHandle>(topLevel))) {
                            if (ctx2->self->ProtectWindow(
                                    reinterpret_cast<WindowHandle>(topLevel))) {
                                ctx2->protectedCount++;
                            }
                        }
                    }
                }
                return TRUE;
            }, lParam);
            return TRUE;
        }, reinterpret_cast<LPARAM>(&ctx));

        SS_LOG_INFO(L"ScreenshotBlocker", L"Auto-protected %zu windows containing password fields",
            ctx.protectedCount);
    }

    void ScreenshotBlocker::BlockPrintScreen(bool block) {
        m_impl->BlockPrintScreen(block);
    }

    bool ScreenshotBlocker::IsPrintScreenBlocked() const noexcept {
        return m_impl->IsPrintScreenBlocked();
    }

    void ScreenshotBlocker::BlockCaptureApplication(std::wstring_view processName) {
        m_impl->BlockCaptureApp(processName);
    }

    void ScreenshotBlocker::UnblockCaptureApplication(std::wstring_view processName) {
        m_impl->UnblockCaptureApp(processName);
    }

    bool ScreenshotBlocker::IsCaptureApplicationBlocked(std::wstring_view processName) const {
        return m_impl->IsCaptureAppBlocked(processName);
    }

    void ScreenshotBlocker::EnableClipboardFiltering(bool enable) {
        m_impl->EnableClipboardFiltering(enable);
    }

    bool ScreenshotBlocker::IsClipboardFilteringEnabled() const noexcept {
        return m_impl->IsClipboardFilteringEnabled();
    }

    void ScreenshotBlocker::SanitizeClipboard() {
        m_impl->SanitizeClipboard();
    }

    void ScreenshotBlocker::ClearClipboard() {
        m_impl->ClearClipboard();
    }

    bool ScreenshotBlocker::IsAdvancedProtectionAvailable() const noexcept {
        return m_impl->IsExcludeFromCaptureSupported();
    }

    bool ScreenshotBlocker::IsExcludeFromCaptureSupported() const noexcept {
        return m_impl->IsExcludeFromCaptureSupported();
    }

    std::vector<BlockingMethod> ScreenshotBlocker::GetSupportedMethods() const {
        std::vector<BlockingMethod> methods;
        methods.push_back(BlockingMethod::DisplayAffinity);
        methods.push_back(BlockingMethod::ClipboardFilter);
        if (m_impl->IsExcludeFromCaptureSupported()) {
            methods.push_back(BlockingMethod::Combined);
        }
        return methods;
    }

    void ScreenshotBlocker::WhitelistApplication(const std::wstring& path, const std::string& reason) {
        m_impl->WhitelistApplication(path, reason);
    }

    void ScreenshotBlocker::WhitelistProcess(const std::wstring& processName, const std::string& reason) {
        m_impl->WhitelistProcess(processName, reason);
    }

    void ScreenshotBlocker::RemoveFromWhitelist(const std::wstring& processName) {
        m_impl->RemoveFromWhitelist(processName);
    }

    bool ScreenshotBlocker::IsWhitelisted(uint32_t processId) const {
        return m_impl->IsWhitelisted(processId);
    }

    void ScreenshotBlocker::LoadAccessibilityWhitelist() {
        m_impl->LoadAccessibilityWhitelist();
    }

    bool ScreenshotBlocker::InstallGDIHooks() {
        return m_impl->InstallGDIHooks();
    }

    void ScreenshotBlocker::UninstallGDIHooks() {
        m_impl->UninstallGDIHooks();
    }

    bool ScreenshotBlocker::InstallDirectXHooks() {
        return m_impl->InstallDirectXHooks();
    }

    void ScreenshotBlocker::UninstallDirectXHooks() {
        m_impl->UninstallDirectXHooks();
    }

    std::vector<CaptureAPIHook> ScreenshotBlocker::GetInstalledHooks() const {
        // No user-mode hooks installed at this layer — cross-process
        // hooking is performed by PhantomSensor.
        return {};
    }

    void ScreenshotBlocker::RegisterCaptureAttemptCallback(CaptureAttemptCallback callback) {
        m_impl->RegisterCaptureCallback(std::move(callback));
    }

    void ScreenshotBlocker::RegisterWindowProtectionCallback(WindowProtectionCallback callback) {
        m_impl->RegisterWindowCallback(std::move(callback));
    }

    void ScreenshotBlocker::RegisterErrorCallback(ErrorCallback callback) {
        m_impl->RegisterErrorCb(std::move(callback));
    }

    void ScreenshotBlocker::UnregisterCallbacks() {
        m_impl->ClearCallbacks();
    }

    ScreenshotBlockerStatistics ScreenshotBlocker::GetStatistics() const {
        return m_impl->GetStatistics();
    }

    void ScreenshotBlocker::ResetStatistics() {
        m_impl->ResetStatistics();
    }

    std::vector<CaptureAttemptEvent> ScreenshotBlocker::GetRecentCaptureAttempts(size_t maxCount) const {
        return m_impl->GetRecentAttempts(maxCount);
    }

    bool ScreenshotBlocker::SelfTest() {
        return m_impl->SelfTest();
    }

    std::string ScreenshotBlocker::GetVersionString() noexcept {
        return std::format("{}.{}.{}",
            ScreenshotConstants::VERSION_MAJOR,
            ScreenshotConstants::VERSION_MINOR,
            ScreenshotConstants::VERSION_PATCH);
    }

    // ========================================================================
    // SERIALIZATION
    // ========================================================================

    std::string ScreenshotProtectedWindow::ToJson() const {
        nlohmann::json j;
        j["hwnd"] = static_cast<uint64_t>(hwnd);
        j["pid"] = processId;
        j["process"] = StringUtils::ToNarrow(processName);
        j["title"] = StringUtils::ToNarrow(windowTitle);
        j["class"] = StringUtils::ToNarrow(windowClass);
        j["status"] = static_cast<int>(status);
        j["is_visible"] = isVisible;
        j["is_minimized"] = isMinimized;
        j["has_focus"] = hasFocus;
        return j.dump();
    }

    std::string CaptureAttemptEvent::ToJson() const {
        nlohmann::json j;
        j["id"] = eventId;
        j["type"] = static_cast<int>(captureType);
        j["type_name"] = std::string(GetCaptureAttemptTypeName(captureType));
        j["source_pid"] = sourceProcessId;
        j["source"] = StringUtils::ToNarrow(sourceProcessName);
        j["target_hwnd"] = static_cast<uint64_t>(targetHwnd);
        j["blocked"] = wasBlocked;
        j["result"] = static_cast<int>(blockingResult);
        j["method"] = static_cast<int>(methodUsed);
        j["whitelisted"] = isWhitelisted;
        if (!details.empty()) {
            j["details"] = details;
        }
        return j.dump();
    }

    std::string ScreenshotBlockerStatistics::ToJson() const {
        nlohmann::json j;
        j["total_protected"] = totalProtectedWindows.load(std::memory_order_relaxed);
        j["currently_protected"] = currentlyProtected.load(std::memory_order_relaxed);
        j["attempts_detected"] = captureAttemptsDetected.load(std::memory_order_relaxed);
        j["blocked_attempts"] = captureAttemptsBlocked.load(std::memory_order_relaxed);
        j["clipboard_filtered"] = clipboardEventsFiltered.load(std::memory_order_relaxed);
        j["gdi_intercepted"] = gdiCallsIntercepted.load(std::memory_order_relaxed);
        j["dx_intercepted"] = dxCallsIntercepted.load(std::memory_order_relaxed);
        j["whitelisted_passes"] = whitelistedPasses.load(std::memory_order_relaxed);
        return j.dump();
    }

    bool ScreenshotBlockerConfiguration::IsValid() const noexcept {
        // At least one protection method must be enabled
        if (!enableDisplayAffinity && !enableGDIHooks && !enableDirectXHooks &&
            !enableClipboardFiltering && !enablePrintScreenBlocking &&
            !enableOverlayObfuscation) {
            return false;
        }

        // Validate whitelist sizes
        if (whitelistedApplications.size() > ScreenshotConstants::MAX_WHITELISTED_APPS ||
            whitelistedProcessNames.size() > ScreenshotConstants::MAX_WHITELISTED_APPS) {
            return false;
        }

        return true;
    }

    void ScreenshotBlockerStatistics::Reset() noexcept {
        totalProtectedWindows.store(0, std::memory_order_relaxed);
        currentlyProtected.store(0, std::memory_order_relaxed);
        captureAttemptsDetected.store(0, std::memory_order_relaxed);
        captureAttemptsBlocked.store(0, std::memory_order_relaxed);
        clipboardEventsFiltered.store(0, std::memory_order_relaxed);
        gdiCallsIntercepted.store(0, std::memory_order_relaxed);
        dxCallsIntercepted.store(0, std::memory_order_relaxed);
        whitelistedPasses.store(0, std::memory_order_relaxed);
        for (auto& counter : byCaptureType) {
            counter.store(0, std::memory_order_relaxed);
        }
        startTime = Clock::now();
    }

    // ========================================================================
    // UTILITY IMPLEMENTATION
    // ========================================================================

    std::string_view GetBlockingMethodName(BlockingMethod method) noexcept {
        switch(method) {
            case BlockingMethod::None: return "None";
            case BlockingMethod::DisplayAffinity: return "DisplayAffinity";
            case BlockingMethod::GDIHooks: return "GDIHooks";
            case BlockingMethod::DirectXHooks: return "DirectXHooks";
            case BlockingMethod::OverlayObfuscation: return "OverlayObfuscation";
            case BlockingMethod::ClipboardFilter: return "ClipboardFilter";
            case BlockingMethod::Combined: return "Combined";
            default: return "Unknown";
        }
    }

    std::string_view GetCaptureAttemptTypeName(CaptureAttemptType type) noexcept {
        switch(type) {
            case CaptureAttemptType::Unknown: return "Unknown";
            case CaptureAttemptType::PrintScreenKey: return "PrintScreenKey";
            case CaptureAttemptType::AltPrintScreen: return "AltPrintScreen";
            case CaptureAttemptType::SnippingTool: return "SnippingTool";
            case CaptureAttemptType::SnipAndSketch: return "SnipAndSketch";
            case CaptureAttemptType::GameBar: return "GameBar";
            case CaptureAttemptType::BitBltCapture: return "BitBltCapture";
            case CaptureAttemptType::StretchBltCapture: return "StretchBltCapture";
            case CaptureAttemptType::PrintWindow: return "PrintWindow";
            case CaptureAttemptType::DesktopDuplication: return "DesktopDuplication";
            case CaptureAttemptType::GetFrontBuffer: return "GetFrontBuffer";
            case CaptureAttemptType::ThirdPartyRecorder: return "ThirdPartyRecorder";
            case CaptureAttemptType::RemoteDesktop: return "RemoteDesktop";
            case CaptureAttemptType::VNCCapture: return "VNCCapture";
            case CaptureAttemptType::TeamViewerCapture: return "TeamViewerCapture";
            case CaptureAttemptType::MagnifierAbuse: return "MagnifierAbuse";
            case CaptureAttemptType::ClipboardCopy: return "ClipboardCopy";
            case CaptureAttemptType::MalwareCapture: return "MalwareCapture";
            default: return "Unknown";
        }
    }

    std::string_view GetProtectionStatusName(ProtectionStatus status) noexcept {
        switch(status) {
            case ProtectionStatus::Unprotected: return "Unprotected";
            case ProtectionStatus::Protected: return "Protected";
            case ProtectionStatus::ProtectionFailed: return "ProtectionFailed";
            case ProtectionStatus::PartialProtection: return "PartialProtection";
            default: return "Unknown";
        }
    }

    std::string_view GetBlockingResultName(BlockingResult result) noexcept {
        switch(result) {
            case BlockingResult::Success: return "Success";
            case BlockingResult::Failed: return "Failed";
            case BlockingResult::NotSupported: return "NotSupported";
            case BlockingResult::Whitelisted: return "Whitelisted";
            case BlockingResult::Timeout: return "Timeout";
            default: return "Unknown";
        }
    }

    bool IsKnownScreenRecorder(std::wstring_view processName) {
        std::wstring lowerName(processName);
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

        for (const auto& recorder : KNOWN_SCREEN_RECORDERS) {
            if (lowerName.find(recorder) != std::wstring::npos) {
                return true;
            }
        }
        return false;
    }

    bool IsAccessibilityTool(std::wstring_view processName) {
        std::wstring lowerName(processName);
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

        for (const auto& tool : ACCESSIBILITY_TOOLS) {
            if (lowerName.find(tool) != std::wstring::npos) {
                return true;
            }
        }
        return false;
    }

} // namespace ShadowStrike::Banking
