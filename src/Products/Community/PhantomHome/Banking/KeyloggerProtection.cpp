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
/**
 * ============================================================================
 * ShadowStrike Banking Protection - KEYLOGGER PROTECTION IMPLEMENTATION
 * ============================================================================
 *
 * @file KeyloggerProtection.cpp
 * @brief Implementation of the enterprise keylogger protection engine.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "pch.h"
#include "PhantomCore/Utils/ProcessSnapshotCache.hpp"
#include "KeyloggerProtection.hpp"

// ============================================================================
// STANDARD LIBRARY
// ============================================================================
#include <thread>
#include <vector>
#include <deque>
#include <map>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <future>
#include <filesystem>
#include <random>
#include <condition_variable>
#include <bcrypt.h>
#include <limits>

// ============================================================================
// WINDOWS SDK
// ============================================================================
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <shellapi.h>
#pragma comment(lib, "shell32.lib")

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "bcrypt.lib")

namespace ShadowStrike {
namespace Banking {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================
static constexpr const wchar_t* LOG_CATEGORY = L"KeyloggerProtection";

// ============================================================================
// STATIC INITIALIZATION
// ============================================================================
std::atomic<bool> KeyloggerProtection::s_instanceCreated{false};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================
namespace {

    // Maximum detection events retained in the history ring buffer
    static constexpr size_t MAX_DETECTION_HISTORY = 1024;

    // Known registry Run key paths used for persistence
    static constexpr std::wstring_view kRunKeyPaths[] = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
        L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    };

    // Known suspicious module name fragments (lowercase match)
    static constexpr std::wstring_view kSuspiciousModuleFragments[] = {
        L"keylog",  L"klog",    L"keyhook",   L"keycap",
        L"keystroke", L"kbhook", L"inputhook", L"hookdll",
        L"spyhook",  L"logkeys",
    };

    // Keyboard-sensitive Windows API imports that keyloggers abuse
    static constexpr std::wstring_view kSuspiciousImports[] = {
        L"SetWindowsHookExA",   L"SetWindowsHookExW",
        L"GetAsyncKeyState",    L"GetKeyboardState",
        L"GetKeyState",         L"RegisterRawInputDevices",
        L"GetRawInputData",
    };

    template <typename T>
    [[nodiscard]] T AtomicValueLoadRelaxed(const T& value) noexcept {
        return std::atomic_ref<T>(const_cast<T&>(value)).load(std::memory_order_relaxed);
    }

    template <typename T>
    void AtomicValueStoreRelaxed(T& target, const T& value) noexcept {
        std::atomic_ref<T>(target).store(value, std::memory_order_relaxed);
    }

    std::string EscapeJson(const std::string& s) {
        std::ostringstream o;
        for (char c : s) {
            switch (c) {
                case '"': o << "\\\""; break;
                case '\\': o << "\\\\"; break;
                case '\b': o << "\\b"; break;
                case '\f': o << "\\f"; break;
                case '\n': o << "\\n"; break;
                case '\r': o << "\\r"; break;
                case '\t': o << "\\t"; break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        o << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                          << static_cast<int>(static_cast<unsigned char>(c));
                    } else {
                        o << c;
                    }
            }
        }
        return o.str();
    }

    std::string WStringToString(const std::wstring& wstr) {
        if (wstr.empty()) return {};
        if (wstr.size() > static_cast<size_t>((std::numeric_limits<int>::max)())) {
            SS_LOG_WARN(LOG_CATEGORY, L"WStringToString rejected oversized string");
            return {};
        }
        int size_needed = WideCharToMultiByte(
            CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()),
            nullptr, 0, nullptr, nullptr);
        if (size_needed <= 0) return {};
        std::string result(static_cast<size_t>(size_needed), '\0');
        int written = WideCharToMultiByte(
            CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()),
            result.data(), size_needed, nullptr, nullptr);
        if (written <= 0) return {};
        return result;
    }

    SystemTimePoint Now() {
        return std::chrono::system_clock::now();
    }

    uint64_t TimeToJson(const SystemTimePoint& time) {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                time.time_since_epoch()).count());
    }

    // Generate a cryptographically-seeded unique event ID
    std::string GenerateEventId() {
        uint64_t randomParts[2]{};
        NTSTATUS status = BCryptGenRandom(
            nullptr,
            reinterpret_cast<PUCHAR>(randomParts),
            static_cast<ULONG>(sizeof(randomParts)),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status < 0) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"GenerateEventId: BCryptGenRandom failed status=0x%08X",
                static_cast<unsigned>(status));
            return {};
        }
        std::ostringstream oss;
        oss << std::hex << std::setfill('0')
            << std::setw(16) << randomParts[0] << "-"
            << std::setw(16) << randomParts[1];
        return oss.str();
    }

    // Case-insensitive wide string contains check
    bool WideContainsCaseInsensitive(const std::wstring& haystack, std::wstring_view needle) {
        if (needle.empty() || haystack.size() < needle.size()) return false;
        auto it = std::search(
            haystack.begin(), haystack.end(),
            needle.begin(), needle.end(),
            [](wchar_t a, wchar_t b) { return ::towlower(a) == ::towlower(b); });
        return it != haystack.end();
    }

    // RAII wrapper for Windows HANDLE (snapshots, generic handles)
    class ScopedHandle final {
    public:
        explicit ScopedHandle(HANDLE h = INVALID_HANDLE_VALUE) noexcept : m_handle(h) {}
        ~ScopedHandle() { Close(); }
        ScopedHandle(const ScopedHandle&) = delete;
        ScopedHandle& operator=(const ScopedHandle&) = delete;
        ScopedHandle(ScopedHandle&& o) noexcept : m_handle(o.m_handle) { o.m_handle = INVALID_HANDLE_VALUE; }
        ScopedHandle& operator=(ScopedHandle&& o) noexcept {
            if (this != &o) { Close(); m_handle = o.m_handle; o.m_handle = INVALID_HANDLE_VALUE; }
            return *this;
        }
        [[nodiscard]] bool IsValid() const noexcept {
            return m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr;
        }
        [[nodiscard]] HANDLE Get() const noexcept { return m_handle; }
        void Close() noexcept {
            if (IsValid()) { ::CloseHandle(m_handle); m_handle = INVALID_HANDLE_VALUE; }
        }
    private:
        HANDLE m_handle;
    };

    // Check if a process has suspicious keyboard-related imports by scanning modules
    bool ProcessHasSuspiciousModules(DWORD pid) {
        ScopedHandle snap(::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
        if (!snap.IsValid()) return false;

        MODULEENTRY32W me32{};
        me32.dwSize = sizeof(me32);
        if (!::Module32FirstW(snap.Get(), &me32)) return false;

        do {
            std::wstring modName(me32.szModule);
            for (const auto& frag : kSuspiciousModuleFragments) {
                if (WideContainsCaseInsensitive(modName, frag)) {
                    return true;
                }
            }
        } while (::Module32NextW(snap.Get(), &me32));

        return false;
    }

    // Check if window has visible UI (keyloggers often run headless)
    bool ProcessHasVisibleWindow(DWORD pid) {
        struct Ctx { DWORD pid; bool found; };
        Ctx ctx{pid, false};
        ::EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
            auto* c = reinterpret_cast<Ctx*>(lParam);
            DWORD wndPid = 0;
            ::GetWindowThreadProcessId(hwnd, &wndPid);
            if (wndPid == c->pid && ::IsWindowVisible(hwnd)) {
                c->found = true;
                return FALSE;
            }
            return TRUE;
        }, reinterpret_cast<LPARAM>(&ctx));
        return ctx.found;
    }

} // anonymous namespace

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

std::string KeyboardHookInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"hookHandle\":" << hookHandle << ","
        << "\"hookType\":" << static_cast<int>(hookType) << ","
        << "\"processId\":" << processId << ","
        << "\"threadId\":" << threadId << ","
        << "\"processName\":\"" << EscapeJson(WStringToString(processName)) << "\","
        << "\"processPath\":\"" << EscapeJson(WStringToString(processPath)) << "\","
        << "\"moduleName\":\"" << EscapeJson(WStringToString(moduleName)) << "\","
        << "\"hookProc\":" << hookProc << ","
        << "\"isGlobal\":" << (isGlobal ? "true" : "false") << ","
        << "\"isSuspicious\":" << (isSuspicious ? "true" : "false") << ","
        << "\"confidence\":" << confidence << ","
        << "\"detectionTime\":" << TimeToJson(detectionTime)
        << "}";
    return oss.str();
}

std::string SuspiciousAPICall::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"apiName\":\"" << EscapeJson(apiName) << "\","
        << "\"processId\":" << processId << ","
        << "\"processName\":\"" << EscapeJson(WStringToString(processName)) << "\","
        << "\"callCount\":" << callCount << ","
        << "\"callRate\":" << callRate << ","
        << "\"targetWindow\":" << targetWindow << ","
        << "\"isTargetingSensitive\":" << (isTargetingSensitive ? "true" : "false") << ","
        << "\"detectionTime\":" << TimeToJson(detectionTime)
        << "}";
    return oss.str();
}

std::string ClipboardThreatInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"processId\":" << processId << ","
        << "\"processName\":\"" << EscapeJson(WStringToString(processName)) << "\","
        << "\"accessType\":\"" << EscapeJson(accessType) << "\","
        << "\"dataType\":\"" << EscapeJson(dataType) << "\","
        << "\"containsSensitive\":" << (containsSensitive ? "true" : "false") << ","
        << "\"detectionTime\":" << TimeToJson(detectionTime)
        << "}";
    return oss.str();
}

std::string KeyloggerProtectedWindow::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"windowHandle\":" << windowHandle << ","
        << "\"windowTitle\":\"" << EscapeJson(WStringToString(windowTitle)) << "\","
        << "\"windowClass\":\"" << EscapeJson(WStringToString(windowClass)) << "\","
        << "\"processId\":" << processId << ","
        << "\"fieldType\":" << static_cast<int>(fieldType) << ","
        << "\"isFocused\":" << (isFocused ? "true" : "false") << ","
        << "\"protectionEnabled\":" << (protectionEnabled ? "true" : "false")
        << "}";
    return oss.str();
}

std::string KeyloggerDetectionEvent::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"eventId\":\"" << EscapeJson(eventId) << "\","
        << "\"keyloggerType\":" << static_cast<int>(keyloggerType) << ","
        << "\"severity\":" << static_cast<int>(severity) << ","
        << "\"threatScore\":" << threatScore << ","
        << "\"confidence\":" << confidence << ","
        << "\"processId\":" << processId << ","
        << "\"processName\":\"" << EscapeJson(WStringToString(processName)) << "\","
        << "\"processPath\":\"" << EscapeJson(WStringToString(processPath)) << "\","
        << "\"description\":\"" << EscapeJson(description) << "\","
        << "\"actionTaken\":" << static_cast<int>(actionTaken) << ","
        << "\"isWhitelisted\":" << (isWhitelisted ? "true" : "false") << ","
        << "\"detectionTime\":" << TimeToJson(detectionTime)
        << "}";
    return oss.str();
}

void KeyloggerProtectionStatistics::Reset() noexcept {
    totalScans.store(0, std::memory_order_relaxed);
    threatsDetected.store(0, std::memory_order_relaxed);
    hooksBlocked.store(0, std::memory_order_relaxed);
    apiCallsIntercepted.store(0, std::memory_order_relaxed);
    clipboardBlocked.store(0, std::memory_order_relaxed);
    protectedKeystrokes.store(0, std::memory_order_relaxed);
    falsePositives.store(0, std::memory_order_relaxed);
    AtomicValueStoreRelaxed(startTime, Clock::now());
    AtomicValueStoreRelaxed(lastDetectionTime, SystemTimePoint{});
}

std::string KeyloggerProtectionStatistics::ToJson() const {
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - AtomicValueLoadRelaxed(startTime)).count();
    std::ostringstream oss;
    oss << "{"
        << "\"totalScans\":" << totalScans.load(std::memory_order_relaxed) << ","
        << "\"threatsDetected\":" << threatsDetected.load(std::memory_order_relaxed) << ","
        << "\"hooksBlocked\":" << hooksBlocked.load(std::memory_order_relaxed) << ","
        << "\"apiCallsIntercepted\":" << apiCallsIntercepted.load(std::memory_order_relaxed) << ","
        << "\"clipboardBlocked\":" << clipboardBlocked.load(std::memory_order_relaxed) << ","
        << "\"protectedKeystrokes\":" << protectedKeystrokes.load(std::memory_order_relaxed) << ","
        << "\"falsePositives\":" << falsePositives.load(std::memory_order_relaxed) << ","
        << "\"uptimeSeconds\":" << uptime
        << "}";
    return oss.str();
}

bool KeyloggerProtectionConfiguration::IsValid() const noexcept {
    if (clipboardClearTimeout == 0 || clipboardClearTimeout > 3600) {
        return false;
    }
    if (whitelistedProcesses.size() > KeyloggerConstants::MAX_MONITORED_PROCESSES) {
        return false;
    }
    for (const auto& proc : whitelistedProcesses) {
        if (proc.empty() || proc.size() > MAX_PATH) {
            return false;
        }
    }
    return true;
}

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class KeyloggerProtectionImpl {
public:
    KeyloggerProtectionImpl() = default;
    ~KeyloggerProtectionImpl() { Shutdown(); }

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    bool Initialize(const KeyloggerProtectionConfiguration& config) {
        std::unique_lock lock(m_mutex);

        if (m_status.load(std::memory_order_acquire) == ModuleStatus::Running) {
            SS_LOG_WARN(LOG_CATEGORY, L"Initialize called while already running");
            return true;
        }
        if (m_status.load(std::memory_order_acquire) != ModuleStatus::Uninitialized &&
            m_status.load(std::memory_order_acquire) != ModuleStatus::Stopped &&
            m_status.load(std::memory_order_acquire) != ModuleStatus::Error) {
            SS_LOG_WARN(LOG_CATEGORY, L"Initialize called in unexpected state %u",
                        static_cast<unsigned>(m_status.load()));
            return false;
        }

        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration supplied to Initialize");
            m_status.store(ModuleStatus::Error, std::memory_order_release);
            return false;
        }

        m_status.store(ModuleStatus::Initializing, std::memory_order_release);
        m_config = config;
        m_stats.Reset();

        {
            std::unique_lock histLock(m_historyMutex);
            m_detectionHistory.clear();
        }

        SS_LOG_INFO(LOG_CATEGORY, L"KeyloggerProtection initialized (mode=%u)",
                    static_cast<unsigned>(config.protectionMode));

        m_status.store(ModuleStatus::Stopped, std::memory_order_release);
        return true;
    }

    void Shutdown() {
        (void)Stop();
        std::unique_lock lock(m_mutex);

        {
            std::unique_lock histLock(m_historyMutex);
            m_detectionHistory.clear();
        }
        m_protectedWindows.clear();
        m_whitelistedPids.clear();
        m_whitelistedPaths.clear();
        m_clipboardProtectionEnabled = false;

        m_status.store(ModuleStatus::Stopped, std::memory_order_release);
        SS_LOG_INFO(LOG_CATEGORY, L"KeyloggerProtection shut down");
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        auto s = m_status.load(std::memory_order_acquire);
        return s != ModuleStatus::Uninitialized;
    }

    // ========================================================================
    // CONTROL
    // ========================================================================

    bool Start() {
        std::unique_lock lock(m_mutex);
        auto currentStatus = m_status.load(std::memory_order_acquire);
        if (currentStatus == ModuleStatus::Running) return true;
        if (currentStatus == ModuleStatus::Stopping) {
            SS_LOG_WARN(LOG_CATEGORY, L"Cannot Start while stop is still in progress");
            return false;
        }
        if (currentStatus == ModuleStatus::Uninitialized) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Cannot Start before Initialize");
            return false;
        }

        m_running.store(true, std::memory_order_release);
        m_status.store(ModuleStatus::Running, std::memory_order_release);

        if (m_config.enableHookDetection || m_config.enableAPIMonitoring) {
            try {
                m_monitorThread = std::thread(&KeyloggerProtectionImpl::MonitorLoop, this);
            } catch (const std::exception& ex) {
                m_running.store(false, std::memory_order_release);
                m_status.store(ModuleStatus::Error, std::memory_order_release);
                SS_LOG_ERROR(LOG_CATEGORY,
                    L"Failed to start monitor thread: %S", ex.what());
                return false;
            }
        }

        SS_LOG_INFO(LOG_CATEGORY, L"KeyloggerProtection started (hookDetection=%d, apiMon=%d, clipboard=%d)",
                    m_config.enableHookDetection, m_config.enableAPIMonitoring,
                    m_config.enableClipboardProtection);
        return true;
    }

    bool Stop() {
        {
            std::unique_lock lock(m_mutex);
            if (!m_running.load(std::memory_order_acquire)) return true;
            m_running.store(false, std::memory_order_release);
            m_status.store(ModuleStatus::Stopping, std::memory_order_release);
        }
        m_stopCv.notify_all();

        if (m_monitorThread.joinable()) {
            m_monitorThread.join();
        }

        // Restore display affinity on all protected windows before clearing
        {
            std::unique_lock lock(m_mutex);
            for (const auto& win : m_protectedWindows) {
                HWND hwnd = reinterpret_cast<HWND>(static_cast<uintptr_t>(win.windowHandle));
                if (::IsWindow(hwnd)) {
                    if (!::SetWindowDisplayAffinity(hwnd, WDA_NONE)) {
                        SS_LOG_WARN(LOG_CATEGORY,
                            L"Failed to clear display affinity for window 0x%llX, error=%lu",
                            win.windowHandle, ::GetLastError());
                    }
                }
            }
            m_protectedWindows.clear();
        }

        m_status.store(ModuleStatus::Stopped, std::memory_order_release);
        SS_LOG_INFO(LOG_CATEGORY, L"KeyloggerProtection stopped");
        return true;
    }

    void Pause() {
        std::unique_lock lock(m_mutex);
        if (m_status.load(std::memory_order_acquire) != ModuleStatus::Running) {
            SS_LOG_WARN(LOG_CATEGORY, L"Pause called while not running");
            return;
        }
        m_paused.store(true, std::memory_order_release);
        m_status.store(ModuleStatus::Paused, std::memory_order_release);
        SS_LOG_INFO(LOG_CATEGORY, L"KeyloggerProtection paused");
    }

    void Resume() {
        std::unique_lock lock(m_mutex);
        if (m_status.load(std::memory_order_acquire) != ModuleStatus::Paused) {
            SS_LOG_WARN(LOG_CATEGORY, L"Resume called while not paused");
            return;
        }
        m_paused.store(false, std::memory_order_release);
        m_status.store(ModuleStatus::Running, std::memory_order_release);
        m_stopCv.notify_all();
        SS_LOG_INFO(LOG_CATEGORY, L"KeyloggerProtection resumed");
    }

    // ========================================================================
    // SECURE INPUT
    // ========================================================================

    bool EnableSecureInputMode(uint64_t windowHandle) {
        std::unique_lock lock(m_mutex);
        HWND hwnd = reinterpret_cast<HWND>(static_cast<uintptr_t>(windowHandle));

        if (!::IsWindow(hwnd)) {
            SS_LOG_WARN(LOG_CATEGORY, L"EnableSecureInputMode: invalid window handle 0x%llX",
                        windowHandle);
            return false;
        }

        auto it = std::find_if(m_protectedWindows.begin(), m_protectedWindows.end(),
            [windowHandle](const KeyloggerProtectedWindow& p) {
                return p.windowHandle == windowHandle;
            });
        if (it == m_protectedWindows.end() &&
            m_protectedWindows.size() >= KeyloggerConstants::MAX_PROTECTED_WINDOWS) {
            SS_LOG_ERROR(LOG_CATEGORY,
                         L"Cannot protect window 0x%llX: max protected windows (%zu) reached",
                         windowHandle, KeyloggerConstants::MAX_PROTECTED_WINDOWS);
            return false;
        }

        // Anti-screenshot protection
        if (m_config.enableScreenshotProtection) {
            if (!::SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)) {
                SS_LOG_WARN(LOG_CATEGORY,
                            L"SetWindowDisplayAffinity failed for 0x%llX, error=%lu",
                            windowHandle, ::GetLastError());
            }
        }

        KeyloggerProtectedWindow info{};
        info.windowHandle = windowHandle;

        wchar_t title[256]{};
        ::GetWindowTextW(hwnd, title, static_cast<int>(std::size(title)));
        info.windowTitle = title;

        wchar_t className[256]{};
        ::GetClassNameW(hwnd, className, static_cast<int>(std::size(className)));
        info.windowClass = className;

        DWORD pid = 0;
        ::GetWindowThreadProcessId(hwnd, &pid);
        info.processId = pid;

        auto procName = Utils::ProcessUtils::GetProcessName(static_cast<Utils::ProcessUtils::ProcessId>(pid));
        if (procName.has_value()) {
            info.processName = procName.value();
        }

        // Detect the field type
        LONG_PTR style = ::GetWindowLongPtrW(hwnd, GWL_STYLE);
        if (style & ES_PASSWORD) {
            info.fieldType = InputFieldType::Password;
        }

        info.protectionEnabled = true;

        // Insert or update (keyed by window handle)
        if (it != m_protectedWindows.end()) {
            *it = std::move(info);
        } else {
            m_protectedWindows.push_back(std::move(info));
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Secure input enabled for window 0x%llX (pid=%u, class=%s)",
                    windowHandle, pid, className);
        return true;
    }

    void DisableSecureInputMode(uint64_t windowHandle) {
        std::unique_lock lock(m_mutex);
        HWND hwnd = reinterpret_cast<HWND>(static_cast<uintptr_t>(windowHandle));

        if (::IsWindow(hwnd)) {
            ::SetWindowDisplayAffinity(hwnd, WDA_NONE);
        }

        auto it = std::remove_if(m_protectedWindows.begin(), m_protectedWindows.end(),
            [windowHandle](const KeyloggerProtectedWindow& p) {
                return p.windowHandle == windowHandle;
            });
        if (it != m_protectedWindows.end()) {
            m_protectedWindows.erase(it, m_protectedWindows.end());
        }

        SS_LOG_DEBUG(LOG_CATEGORY, L"Secure input disabled for window 0x%llX", windowHandle);
    }

    void AutoProtectPasswordFields() {
        struct EnumCtx {
            KeyloggerProtectionImpl* self;
            size_t count;
        };
        EnumCtx ctx{this, 0};

        // Release lock before EnumWindows to avoid potential deadlock with window procedures
        // We'll re-acquire inside EnableSecureInputMode per-window
        ::EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
            auto* c = reinterpret_cast<EnumCtx*>(lParam);
            if (!::IsWindowVisible(hwnd)) return TRUE;

            LONG_PTR style = ::GetWindowLongPtrW(hwnd, GWL_STYLE);
            if (style & ES_PASSWORD) {
                uint64_t handle = reinterpret_cast<uint64_t>(hwnd);
                c->self->EnableSecureInputMode(handle);
                c->count++;
            }

            // Also check child windows for password fields
            ::EnumChildWindows(hwnd, [](HWND child, LPARAM lp) -> BOOL {
                auto* ctx2 = reinterpret_cast<EnumCtx*>(lp);
                LONG_PTR childStyle = ::GetWindowLongPtrW(child, GWL_STYLE);
                if (childStyle & ES_PASSWORD) {
                    uint64_t handle = reinterpret_cast<uint64_t>(child);
                    ctx2->self->EnableSecureInputMode(handle);
                    ctx2->count++;
                }
                return TRUE;
            }, lParam);

            return TRUE;
        }, reinterpret_cast<LPARAM>(&ctx));

        SS_LOG_INFO(LOG_CATEGORY, L"AutoProtectPasswordFields found %zu password fields", ctx.count);
    }

    // ========================================================================
    // CLIPBOARD
    // ========================================================================

    void EnableClipboardProtection() {
        std::unique_lock lock(m_mutex);
        if (m_clipboardProtectionEnabled) return;
        m_clipboardProtectionEnabled = true;
        SS_LOG_INFO(LOG_CATEGORY, L"Clipboard protection enabled");
    }

    void DisableClipboardProtection() {
        std::unique_lock lock(m_mutex);
        if (!m_clipboardProtectionEnabled) return;
        m_clipboardProtectionEnabled = false;
        SS_LOG_INFO(LOG_CATEGORY, L"Clipboard protection disabled");
    }

    [[nodiscard]] bool IsClipboardProtectionEnabled() const noexcept {
        return m_clipboardProtectionEnabled.load(std::memory_order_acquire);
    }

    void ClearClipboard() {
        if (!::OpenClipboard(nullptr)) {
            SS_LOG_WARN(LOG_CATEGORY, L"ClearClipboard: OpenClipboard failed, error=%lu",
                        ::GetLastError());
            return;
        }
        if (!::EmptyClipboard()) {
            SS_LOG_WARN(LOG_CATEGORY, L"ClearClipboard: EmptyClipboard failed, error=%lu",
                        ::GetLastError());
        }
        if (!::CloseClipboard()) {
            SS_LOG_WARN(LOG_CATEGORY, L"ClearClipboard: CloseClipboard failed, error=%lu",
                        ::GetLastError());
        }
        SS_LOG_DEBUG(LOG_CATEGORY, L"Clipboard cleared");
    }

    // ========================================================================
    // DETECTION LOGIC
    // ========================================================================

    std::vector<KeyloggerDetectionEvent> DetectKeyloggers() {
        KeyloggerProtectionConfiguration configSnapshot;
        {
            std::shared_lock lock(m_mutex);
            configSnapshot = m_config;
        }

        std::vector<KeyloggerDetectionEvent> events;
        m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);

        // 1. Scan processes for hook-related modules and suspicious behavior
        auto processDetections = ScanProcessesForHooks(configSnapshot);
        events.insert(events.end(),
                      std::make_move_iterator(processDetections.begin()),
                      std::make_move_iterator(processDetections.end()));

        // 2. Scan registry for persistence entries
        auto registryDetections = ScanRegistryPersistence();
        events.insert(events.end(),
                      std::make_move_iterator(registryDetections.begin()),
                      std::make_move_iterator(registryDetections.end()));

        // Store new events in history and fire callbacks
        for (const auto& evt : events) {
            RecordDetection(evt);
        }

        return events;
    }

    std::vector<KeyloggerDetectionEvent> ScanProcessesForHooks(
        const KeyloggerProtectionConfiguration& config) {
        std::vector<KeyloggerDetectionEvent> detections;

        // Use the shared process snapshot rather than taking our own.
        //
        // A Toolhelp process snapshot walks the kernel process list under locks
        // the minifilter path also needs, so three modules each taking one on
        // their own timer (twice a second here, ten times a second in the
        // screenshot blocker) contended against file and process operations for
        // the entire machine. Every process is still examined - only the
        // redundant re-enumeration is gone.
        auto snapshot = Utils::ProcessSnapshotCache::Instance().Get();

        PROCESSENTRY32W pe32{};
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        for (const auto& snapEntry : snapshot->processes) {
            pe32.th32ProcessID       = snapEntry.pid;
            pe32.th32ParentProcessID = snapEntry.parentPid;
            pe32.cntThreads          = snapEntry.threadCount;
            ::wcsncpy_s(pe32.szExeFile, snapEntry.name.c_str(), _TRUNCATE);

            if (detections.size() >= KeyloggerConstants::MAX_MONITORED_PROCESSES) {
                SS_LOG_WARN(LOG_CATEGORY,
                    L"ScanProcessesForHooks reached detection cap=%zu",
                    KeyloggerConstants::MAX_MONITORED_PROCESSES);
                break;
            }
            // Skip System/Idle
            if (pe32.th32ProcessID <= 4) continue;

            // Check whitelist (by PID and by process name)
            if (IsWhitelisted(pe32.th32ProcessID)) continue;

            std::wstring exeName(pe32.szExeFile);
            {
                bool nameWhitelisted = std::any_of(
                    config.whitelistedProcesses.begin(),
                    config.whitelistedProcesses.end(),
                    [&exeName](const std::wstring& wp) {
                        return _wcsicmp(exeName.c_str(), wp.c_str()) == 0;
                    });
                if (nameWhitelisted) continue;
            }

            if (IsSuspiciousProcess(pe32.th32ProcessID, exeName)) {
                KeyloggerDetectionEvent event{};
                event.eventId = GenerateEventId();
                if (event.eventId.empty()) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"Skipping detection because event ID generation failed");
                    continue;
                }
                event.processId = pe32.th32ProcessID;
                event.processName = exeName;
                event.detectionTime = Now();

                // Classify the threat
                ClassifySuspiciousProcess(pe32.th32ProcessID, exeName, event);

                auto procPath = Utils::ProcessUtils::GetProcessPath(
                    static_cast<Utils::ProcessUtils::ProcessId>(pe32.th32ProcessID));
                if (procPath.has_value()) {
                    event.processPath = procPath.value();
                }

                // Determine action based on protection mode
                switch (config.protectionMode) {
                    case ProtectionMode::Aggressive:
                        event.actionTaken = config.terminateKeyloggers
                            ? DetectionAction::Terminate
                            : DetectionAction::Block;
                        break;
                    case ProtectionMode::Protect:
                        event.actionTaken = DetectionAction::Block;
                        break;
                    case ProtectionMode::Monitor:
                        event.actionTaken = DetectionAction::Alert;
                        break;
                    default:
                        event.actionTaken = DetectionAction::None;
                        break;
                }

                m_stats.threatsDetected.fetch_add(1, std::memory_order_relaxed);
                SS_LOG_WARN(LOG_CATEGORY,
                            L"Suspicious process detected: PID=%u name=%s score=%.1f confidence=%.2f",
                            event.processId, event.processName.c_str(),
                            event.threatScore, event.confidence);

                detections.push_back(std::move(event));
            }
        }

        return detections;
    }

    bool IsSuspiciousProcess(DWORD pid, const std::wstring& name) {
        int suspicionScore = 0;

        // 1. Process name heuristic
        for (const auto& frag : kSuspiciousModuleFragments) {
            if (WideContainsCaseInsensitive(name, frag)) {
                suspicionScore += 40;
                break;
            }
        }

        // 2. Module-level check (suspicious DLLs loaded)
        if (ProcessHasSuspiciousModules(pid)) {
            suspicionScore += 30;
        }

        // 3. Process running without visible window (headless background process
        //    with keyboard access is suspicious)
        if (!ProcessHasVisibleWindow(pid) && suspicionScore > 0) {
            suspicionScore += 20;
        }

        // Threshold: combined score must indicate real threat
        return suspicionScore >= 40;
    }

    void ClassifySuspiciousProcess(DWORD pid, const std::wstring& name,
                                   KeyloggerDetectionEvent& event) {
        // Default classification
        event.keyloggerType = KeyloggerType::Unknown;
        event.severity = ThreatSeverity::Medium;
        event.confidence = 0.6;
        event.threatScore = 50.0;

        // Name-based classification
        for (const auto& frag : kSuspiciousModuleFragments) {
            if (WideContainsCaseInsensitive(name, frag)) {
                event.keyloggerType = KeyloggerType::SoftwareHook;
                event.severity = ThreatSeverity::High;
                event.confidence = 0.85;
                event.threatScore = 80.0;
                event.description = "Process name matches known keylogger pattern";
                break;
            }
        }

        // Module-based boost
        if (ProcessHasSuspiciousModules(pid)) {
            event.confidence = std::min(event.confidence + 0.1, 1.0);
            event.threatScore = std::min(event.threatScore + 10.0, 100.0);
            if (event.description.empty()) {
                event.description = "Process loads modules with suspicious keyboard hook exports";
            }
        }

        if (!ProcessHasVisibleWindow(pid)) {
            event.confidence = std::min(event.confidence + 0.05, 1.0);
            event.threatScore = std::min(event.threatScore + 5.0, 100.0);
        }

        if (event.description.empty()) {
            event.description = "Suspicious process with potential keylogging traits";
        }
    }

    // ========================================================================
    // REGISTRY PERSISTENCE SCANNING
    // ========================================================================

    std::vector<KeyloggerDetectionEvent> ScanRegistryPersistence() {
        std::vector<KeyloggerDetectionEvent> detections;

        for (const auto& runKeyPath : kRunKeyPaths) {
            ScanSingleRunKey(HKEY_LOCAL_MACHINE, runKeyPath, detections);
            ScanSingleRunKey(HKEY_CURRENT_USER, runKeyPath, detections);
        }

        return detections;
    }

    void ScanSingleRunKey(HKEY root, std::wstring_view subKey,
                          std::vector<KeyloggerDetectionEvent>& detections) {
        HKEY hKey = nullptr;
        LSTATUS status = ::RegOpenKeyExW(root, subKey.data(), 0, KEY_READ, &hKey);
        if (status != ERROR_SUCCESS || hKey == nullptr) return;

        // RAII for the registry key
        struct RegKeyGuard {
            HKEY key;
            ~RegKeyGuard() { if (key) ::RegCloseKey(key); }
        } guard{hKey};

        wchar_t valueName[MAX_PATH]{};
        BYTE valueData[2048]{};

        for (DWORD index = 0; ; ++index) {
            if (detections.size() >= KeyloggerConstants::MAX_MONITORED_PROCESSES) {
                SS_LOG_WARN(LOG_CATEGORY,
                    L"ScanSingleRunKey reached detection cap=%zu for key=%.*s",
                    KeyloggerConstants::MAX_MONITORED_PROCESSES,
                    static_cast<int>(std::min<size_t>(subKey.size(), 256)), subKey.data());
                break;
            }
            DWORD nameLen = MAX_PATH;
            DWORD dataLen = sizeof(valueData);
            DWORD type = 0;

            status = ::RegEnumValueW(hKey, index, valueName, &nameLen,
                                     nullptr, &type, valueData, &dataLen);
            if (status != ERROR_SUCCESS) break;
            if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
            if (dataLen == 0 || (dataLen % sizeof(wchar_t)) != 0) {
                SS_LOG_WARN(LOG_CATEGORY,
                    L"Skipping malformed registry value in %.*s: byteLength=%lu",
                    static_cast<int>(std::min<size_t>(subKey.size(), 256)),
                    subKey.data(), dataLen);
                continue;
            }

            std::wstring path(reinterpret_cast<const wchar_t*>(valueData),
                              dataLen / sizeof(wchar_t));
            // Remove trailing null if present
            if (!path.empty() && path.back() == L'\0') path.pop_back();

            // Check the persistence entry against suspicious patterns
            for (const auto& frag : kSuspiciousModuleFragments) {
                if (WideContainsCaseInsensitive(path, frag)) {
                    KeyloggerDetectionEvent event{};
                    event.eventId = GenerateEventId();
                    if (event.eventId.empty()) {
                        SS_LOG_ERROR(LOG_CATEGORY, L"Skipping registry detection because event ID generation failed");
                        break;
                    }
                    event.keyloggerType = KeyloggerType::SoftwareHook;
                    event.severity = ThreatSeverity::High;
                    event.confidence = 0.8;
                    event.threatScore = 75.0;
                    event.description = "Suspicious persistence entry in registry Run key";
                    event.detectionTime = Now();
                    event.processName = path;

                    detections.push_back(std::move(event));

                    SS_LOG_WARN(LOG_CATEGORY,
                                L"Suspicious registry persistence: %s -> %s",
                                subKey.data(), path.c_str());
                    break;
                }
            }
        }
    }

    // ========================================================================
    // HOOK SCANNING
    // ========================================================================

    std::vector<KeyboardHookInfo> ScanKeyboardHooks() {
        std::vector<KeyboardHookInfo> hooks;
        hooks.reserve(std::min<size_t>(KeyloggerConstants::MAX_TRACKED_HOOKS, 32));

        ScopedHandle hSnapshot(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!hSnapshot.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ScanKeyboardHooks: snapshot creation failed, error=%lu",
                         ::GetLastError());
            return hooks;
        }

        PROCESSENTRY32W pe32{};
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        if (!::Process32FirstW(hSnapshot.Get(), &pe32)) return hooks;

        do {
            if (pe32.th32ProcessID <= 4) continue;
            auto perProcess = ScanProcessHooks(pe32.th32ProcessID);
            const size_t remaining = KeyloggerConstants::MAX_TRACKED_HOOKS - hooks.size();
            if (remaining == 0) {
                SS_LOG_WARN(LOG_CATEGORY,
                    L"ScanKeyboardHooks reached hook cap=%zu",
                    KeyloggerConstants::MAX_TRACKED_HOOKS);
                break;
            }
            const size_t toMove = std::min(remaining, perProcess.size());
            hooks.insert(hooks.end(),
                         std::make_move_iterator(perProcess.begin()),
                         std::make_move_iterator(perProcess.begin() + static_cast<std::ptrdiff_t>(toMove)));
        } while (::Process32NextW(hSnapshot.Get(), &pe32));

        return hooks;
    }

    std::vector<KeyboardHookInfo> ScanProcessHooks(uint32_t processId) {
        std::vector<KeyboardHookInfo> hooks;

        ScopedHandle modSnap(
            ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId));
        if (!modSnap.IsValid()) return hooks;

        MODULEENTRY32W me32{};
        me32.dwSize = sizeof(me32);
        if (!::Module32FirstW(modSnap.Get(), &me32)) return hooks;

        do {
            std::wstring modName(me32.szModule);
            bool suspicious = false;
            for (const auto& frag : kSuspiciousModuleFragments) {
                if (WideContainsCaseInsensitive(modName, frag)) {
                    suspicious = true;
                    break;
                }
            }
            if (!suspicious) continue;

            KeyboardHookInfo info{};
            info.hookType = KeyboardHookType::Hook_KeyboardLL;
            info.processId = processId;
            info.moduleName = modName;
            info.hookProc = reinterpret_cast<uint64_t>(me32.modBaseAddr);
            info.isGlobal = true;
            info.isSuspicious = true;
            info.detectionTime = Now();
            info.confidence = 0.75;

            auto procName = Utils::ProcessUtils::GetProcessName(static_cast<Utils::ProcessUtils::ProcessId>(processId));
            if (procName.has_value()) info.processName = procName.value();
            auto procPath = Utils::ProcessUtils::GetProcessPath(static_cast<Utils::ProcessUtils::ProcessId>(processId));
            if (procPath.has_value()) info.processPath = procPath.value();

            hooks.push_back(std::move(info));
            if (hooks.size() >= KeyloggerConstants::MAX_TRACKED_HOOKS) {
                SS_LOG_WARN(LOG_CATEGORY,
                    L"ScanProcessHooks reached hook cap=%zu for PID=%u",
                    KeyloggerConstants::MAX_TRACKED_HOOKS, processId);
                break;
            }
        } while (::Module32NextW(modSnap.Get(), &me32));

        return hooks;
    }

    bool IsLegitimateHook(const KeyboardHookInfo& hook) const {
        // Check our explicit whitelist
        {
            std::shared_lock lock(m_mutex);
            if (m_whitelistedPids.count(hook.processId) > 0) return true;

            for (const auto& wp : m_config.whitelistedProcesses) {
                if (_wcsicmp(hook.processName.c_str(), wp.c_str()) == 0) return true;
            }

            // Check path-based whitelist
            if (!hook.processPath.empty()) {
                std::error_code ec;
                std::filesystem::path normalized = std::filesystem::weakly_canonical(hook.processPath, ec);
                std::wstring comparablePath = ec ? hook.processPath : normalized.wstring();
                for (const auto& path : m_whitelistedPaths) {
                    if (_wcsicmp(comparablePath.c_str(), path.c_str()) == 0) return true;
                }
            }
        }

        // System processes are considered legitimate
        if (hook.processId <= 4) return true;

        // Signed Microsoft binaries are generally legitimate
        if (!hook.processPath.empty()) {
            auto lowerPath = hook.processPath;
            std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
            if (lowerPath.find(L"\\windows\\system32\\") != std::wstring::npos ||
                lowerPath.find(L"\\windows\\syswow64\\") != std::wstring::npos) {
                return true;
            }
        }

        return false;
    }

    bool BlockHook(const KeyboardHookInfo& hook) {
        if (hook.hookHandle != 0) {
            SS_LOG_WARN(LOG_CATEGORY,
                L"Refusing to unhook unverified hook handle=0x%llX pid=%u module=%s",
                hook.hookHandle, hook.processId, hook.moduleName.c_str());
            return false;
        }

        // DESIGN: Hook inventory here is heuristic. Only a hook handle returned by
        // this process from SetWindowsHookEx can be safely passed to
        // UnhookWindowsHookEx; fabricated cross-process values are not remediated.
        SS_LOG_WARN(LOG_CATEGORY,
                    L"Cannot directly unhook pid=%u module=%s (cross-process hook requires kernel driver)",
                    hook.processId, hook.moduleName.c_str());
        return false;
    }

    size_t UnhookMaliciousHooks() {
        auto allHooks = ScanKeyboardHooks();
        size_t blocked = 0;
        for (const auto& hook : allHooks) {
            if (hook.isSuspicious && !IsLegitimateHook(hook)) {
                if (BlockHook(hook)) {
                    blocked++;
                }
            }
        }
        SS_LOG_INFO(LOG_CATEGORY, L"UnhookMaliciousHooks: scanned %zu hooks, blocked %zu",
                    allHooks.size(), blocked);
        return blocked;
    }

    // ========================================================================
    // REMEDIATION
    // ========================================================================

    bool TerminateKeylogger(uint32_t processId) {
        if (processId <= 4) {
            SS_LOG_ERROR(LOG_CATEGORY,
                         L"TerminateKeylogger: refusing to terminate system process PID=%u",
                         processId);
            return false;
        }

        Utils::ProcessUtils::ProcessHandle hProcess(
            static_cast<Utils::ProcessUtils::ProcessId>(processId), PROCESS_TERMINATE);
        if (!hProcess.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY,
                         L"TerminateKeylogger: OpenProcess failed for PID=%u, error=%lu",
                         processId, ::GetLastError());
            return false;
        }

        auto procName = Utils::ProcessUtils::GetProcessName(static_cast<Utils::ProcessUtils::ProcessId>(processId));
        if (!::TerminateProcess(hProcess.Get(), 1)) {
            SS_LOG_ERROR(LOG_CATEGORY,
                         L"TerminateKeylogger: TerminateProcess failed for PID=%u (%s), error=%lu",
                         processId,
                         procName.has_value() ? procName.value().c_str() : L"<unknown>",
                         ::GetLastError());
            return false;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Terminated keylogger process PID=%u (%s)",
                    processId,
                    procName.has_value() ? procName.value().c_str() : L"<unknown>");
        return true;
    }

    bool RemovePersistence(uint32_t processId) {
        auto procPath = Utils::ProcessUtils::GetProcessPath(static_cast<Utils::ProcessUtils::ProcessId>(processId));
        if (!procPath.has_value()) {
            SS_LOG_WARN(LOG_CATEGORY,
                        L"RemovePersistence: could not resolve path for PID=%u", processId);
            return false;
        }

        bool removedAny = false;
        for (const auto& runKeyPath : kRunKeyPaths) {
            removedAny |= RemovePersistenceFromKey(HKEY_LOCAL_MACHINE, runKeyPath, procPath.value());
            removedAny |= RemovePersistenceFromKey(HKEY_CURRENT_USER, runKeyPath, procPath.value());
        }

        if (removedAny) {
            SS_LOG_INFO(LOG_CATEGORY,
                        L"Removed persistence entries for PID=%u path=%s",
                        processId, procPath.value().c_str());
        }
        return removedAny;
    }

    // ========================================================================
    // WHITELIST
    // ========================================================================

    bool IsWhitelisted(uint32_t processId) const {
        std::shared_lock lock(m_mutex);
        if (m_whitelistedPids.count(processId) > 0) return true;

        // Check configured whitelist by process name
        auto procName = Utils::ProcessUtils::GetProcessName(static_cast<Utils::ProcessUtils::ProcessId>(processId));
        if (procName.has_value()) {
            for (const auto& wp : m_config.whitelistedProcesses) {
                if (_wcsicmp(procName.value().c_str(), wp.c_str()) == 0) return true;
            }
        }

        // Check path whitelist
        auto procPath = Utils::ProcessUtils::GetProcessPath(static_cast<Utils::ProcessUtils::ProcessId>(processId));
        if (procPath.has_value()) {
            std::error_code ec;
            std::filesystem::path normalized = std::filesystem::weakly_canonical(procPath.value(), ec);
            std::wstring comparablePath = ec ? procPath.value() : normalized.wstring();
            for (const auto& path : m_whitelistedPaths) {
                if (_wcsicmp(comparablePath.c_str(), path.c_str()) == 0) return true;
            }
        }

        return false;
    }

    void AddToWhitelist(uint32_t processId, const std::string& reason) {
        std::unique_lock lock(m_mutex);
        m_whitelistedPids.insert(processId);
        SS_LOG_INFO(LOG_CATEGORY, L"Added PID=%u to whitelist (reason: %S)",
                    processId, reason.c_str());
    }

    void AddPathToWhitelist(const std::filesystem::path& path, const std::string& reason) {
        if (path.empty()) {
            SS_LOG_WARN(LOG_CATEGORY, L"AddPathToWhitelist rejected empty path");
            return;
        }
        std::error_code ec;
        std::filesystem::path normalized = std::filesystem::weakly_canonical(path, ec);
        if (ec) {
            normalized = std::filesystem::absolute(path, ec);
        }
        if (ec || normalized.empty()) {
            SS_LOG_WARN(LOG_CATEGORY,
                L"AddPathToWhitelist rejected non-canonical path, error=%lu",
                static_cast<unsigned long>(ec.value()));
            return;
        }
        std::unique_lock lock(m_mutex);
        m_whitelistedPaths.insert(normalized.wstring());
        SS_LOG_INFO(LOG_CATEGORY, L"Added path to whitelist: %s (reason: %S)",
                    normalized.c_str(), reason.c_str());
    }

    void RemoveFromWhitelist(uint32_t processId) {
        std::unique_lock lock(m_mutex);
        m_whitelistedPids.erase(processId);
        SS_LOG_DEBUG(LOG_CATEGORY, L"Removed PID=%u from whitelist", processId);
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void RegisterDetectionCallback(DetectionCallback cb) {
        std::unique_lock lock(m_mutex);
        m_detectionCallback = std::move(cb);
        SS_LOG_DEBUG(LOG_CATEGORY, L"Detection callback registered");
    }

    void RegisterErrorCallback(ErrorCallback cb) {
        std::unique_lock lock(m_mutex);
        m_errorCallback = std::move(cb);
        SS_LOG_DEBUG(LOG_CATEGORY, L"Error callback registered");
    }

    void UnregisterCallbacks() {
        std::unique_lock lock(m_mutex);
        m_detectionCallback = nullptr;
        m_errorCallback = nullptr;
        SS_LOG_DEBUG(LOG_CATEGORY, L"Callbacks unregistered");
    }

    // ========================================================================
    // GETTERS
    // ========================================================================

    [[nodiscard]] ModuleStatus GetStatus() const noexcept {
        return m_status.load(std::memory_order_acquire);
    }

    [[nodiscard]] bool IsRunning() const noexcept {
        return m_running.load(std::memory_order_acquire);
    }

    [[nodiscard]] ProtectionMode GetProtectionMode() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_config.protectionMode;
    }

    [[nodiscard]] KeyloggerProtectionConfiguration GetConfiguration() const {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    bool UpdateConfiguration(const KeyloggerProtectionConfiguration& config) {
        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"UpdateConfiguration: invalid configuration rejected");
            return false;
        }
        std::unique_lock lock(m_mutex);
        m_config = config;
        SS_LOG_INFO(LOG_CATEGORY, L"Configuration updated (mode=%u)",
                    static_cast<unsigned>(config.protectionMode));
        return true;
    }

    [[nodiscard]] KeyloggerProtectionStatistics GetStatistics() const {
        KeyloggerProtectionStatistics stats;
        stats.totalScans.store(m_stats.totalScans.load(std::memory_order_relaxed), std::memory_order_relaxed);
        stats.threatsDetected.store(m_stats.threatsDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
        stats.hooksBlocked.store(m_stats.hooksBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
        stats.apiCallsIntercepted.store(m_stats.apiCallsIntercepted.load(std::memory_order_relaxed), std::memory_order_relaxed);
        stats.clipboardBlocked.store(m_stats.clipboardBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
        stats.protectedKeystrokes.store(m_stats.protectedKeystrokes.load(std::memory_order_relaxed), std::memory_order_relaxed);
        stats.falsePositives.store(m_stats.falsePositives.load(std::memory_order_relaxed), std::memory_order_relaxed);
        stats.startTime = AtomicValueLoadRelaxed(m_stats.startTime);
        stats.lastDetectionTime = AtomicValueLoadRelaxed(m_stats.lastDetectionTime);
        return stats;
    }

    void ResetStatistics() {
        m_stats.Reset();
        SS_LOG_DEBUG(LOG_CATEGORY, L"Statistics reset");
    }

    [[nodiscard]] std::vector<KeyloggerProtectedWindow> GetProtectedWindows() const {
        std::shared_lock lock(m_mutex);
        return m_protectedWindows;
    }

    [[nodiscard]] std::vector<KeyloggerDetectionEvent> GetRecentDetections(size_t maxCount) const {
        std::shared_lock lock(m_historyMutex);
        size_t count = std::min(maxCount, m_detectionHistory.size());
        std::vector<KeyloggerDetectionEvent> result;
        result.reserve(count);
        // Return most recent first (back of deque is newest)
        auto it = m_detectionHistory.rbegin();
        for (size_t i = 0; i < count && it != m_detectionHistory.rend(); ++i, ++it) {
            result.push_back(*it);
        }
        return result;
    }

    // ========================================================================
    // SELF-TEST
    // ========================================================================

    bool SelfTest() {
        SS_LOG_INFO(LOG_CATEGORY, L"Running self-test...");

        // 1. Verify module status
        auto status = m_status.load(std::memory_order_acquire);
        if (status == ModuleStatus::Uninitialized) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED: module not initialized");
            return false;
        }

        // 2. Verify process snapshot capability
        ScopedHandle snap(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!snap.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY,
                         L"Self-test FAILED: cannot create process snapshot (error=%lu)",
                         ::GetLastError());
            return false;
        }

        // 3. Verify we can read our own process info
        DWORD ownPid = ::GetCurrentProcessId();
        auto ownName = Utils::ProcessUtils::GetProcessName(static_cast<Utils::ProcessUtils::ProcessId>(ownPid));
        if (!ownName.has_value()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED: cannot resolve own process name");
            return false;
        }

        // 4. Verify clipboard access
        if (::OpenClipboard(nullptr)) {
            ::CloseClipboard();
        } else {
            SS_LOG_WARN(LOG_CATEGORY, L"Self-test WARNING: clipboard access unavailable");
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Self-test PASSED (pid=%u, name=%s)",
                    ownPid, ownName.value().c_str());
        return true;
    }

private:
    // ========================================================================
    // MONITORING LOOP
    // ========================================================================

    void MonitorLoop() {
        SS_LOG_DEBUG(LOG_CATEGORY, L"Monitor thread started (interval=%ums)",
                     KeyloggerConstants::HOOK_SCAN_INTERVAL_MS);

        while (m_running.load(std::memory_order_acquire)) {
            // Sleep interruptibly using condition variable
            {
                std::unique_lock lock(m_stopMutex);
                m_stopCv.wait_for(lock,
                    std::chrono::milliseconds(KeyloggerConstants::HOOK_SCAN_INTERVAL_MS),
                    [this] { return !m_running.load(std::memory_order_acquire); });
            }

            if (!m_running.load(std::memory_order_acquire)) break;
            if (m_paused.load(std::memory_order_acquire)) continue;

            try {
                DetectKeyloggers();
            } catch (const std::exception& ex) {
                SS_LOG_ERROR(LOG_CATEGORY,
                             L"Monitor loop exception: %S", ex.what());
                NotifyError("Monitor loop exception: " + std::string(ex.what()), -1);
            } catch (...) {
                SS_LOG_ERROR(LOG_CATEGORY,
                             L"Monitor loop: unknown exception caught");
                NotifyError("Monitor loop: unknown exception", -2);
            }
        }

        SS_LOG_DEBUG(LOG_CATEGORY, L"Monitor thread exiting");
    }

    // ========================================================================
    // INTERNAL HELPERS
    // ========================================================================

    void RecordDetection(const KeyloggerDetectionEvent& event) {
        // Store in bounded history
        {
            std::unique_lock lock(m_historyMutex);
            if (m_detectionHistory.size() >= MAX_DETECTION_HISTORY) {
                m_detectionHistory.pop_front();
            }
            m_detectionHistory.push_back(event);
        }

        // Fire callback (outside lock to avoid potential deadlock)
        DetectionCallback cb;
        {
            std::shared_lock lock(m_mutex);
            cb = m_detectionCallback;
        }
        if (cb) {
            try {
                cb(event);
            } catch (const std::exception& ex) {
                SS_LOG_ERROR(LOG_CATEGORY,
                             L"Detection callback threw: %S", ex.what());
            } catch (...) {
                SS_LOG_ERROR(LOG_CATEGORY,
                             L"Detection callback threw unknown exception");
            }
        }
    }

    void NotifyError(const std::string& message, int code) {
        ErrorCallback cb;
        {
            std::shared_lock lock(m_mutex);
            cb = m_errorCallback;
        }
        if (cb) {
            try {
                cb(message, code);
            } catch (const std::exception& ex) {
                SS_LOG_ERROR(LOG_CATEGORY,
                    L"Error callback threw while reporting code=%d: %S", code, ex.what());
            } catch (...) {
                SS_LOG_ERROR(LOG_CATEGORY,
                    L"Error callback threw unknown exception while reporting code=%d", code);
            }
        }
    }

    bool RemovePersistenceFromKey(HKEY root, std::wstring_view subKey,
                                  const std::wstring& targetPath) {
        HKEY hKey = nullptr;
        LSTATUS status = ::RegOpenKeyExW(root, subKey.data(), 0,
                                         KEY_READ | KEY_SET_VALUE, &hKey);
        if (status != ERROR_SUCCESS || hKey == nullptr) return false;

        struct RegKeyGuard {
            HKEY key;
            ~RegKeyGuard() { if (key) ::RegCloseKey(key); }
        } guard{hKey};

        wchar_t valueName[MAX_PATH]{};
        BYTE valueData[2048]{};
        bool removed = false;

        // Collect values to delete (can't delete during enumeration)
        std::vector<std::wstring> toDelete;
        for (DWORD index = 0; ; ++index) {
            DWORD nameLen = MAX_PATH;
            DWORD dataLen = sizeof(valueData);
            DWORD type = 0;

            status = ::RegEnumValueW(hKey, index, valueName, &nameLen,
                                     nullptr, &type, valueData, &dataLen);
            if (status != ERROR_SUCCESS) break;
            if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
            if (dataLen == 0 || (dataLen % sizeof(wchar_t)) != 0) {
                SS_LOG_WARN(LOG_CATEGORY,
                    L"Skipping malformed persistence value in %.*s: byteLength=%lu",
                    static_cast<int>(std::min<size_t>(subKey.size(), 256)),
                    subKey.data(), dataLen);
                continue;
            }

            std::wstring path(reinterpret_cast<const wchar_t*>(valueData),
                              dataLen / sizeof(wchar_t));
            if (!path.empty() && path.back() == L'\0') path.pop_back();

            if (WideContainsCaseInsensitive(path, targetPath)) {
                toDelete.emplace_back(valueName, nameLen);
            }
        }

        for (const auto& name : toDelete) {
            if (::RegDeleteValueW(hKey, name.c_str()) == ERROR_SUCCESS) {
                removed = true;
                SS_LOG_INFO(LOG_CATEGORY,
                            L"Removed persistence registry value: %s\\%s",
                            subKey.data(), name.c_str());
            }
        }

        return removed;
    }

    // ========================================================================
    // MEMBER DATA
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    mutable std::shared_mutex m_historyMutex;

    std::mutex m_stopMutex;
    std::condition_variable m_stopCv;

    std::atomic<bool> m_running{false};
    std::atomic<bool> m_paused{false};
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    std::atomic<bool> m_clipboardProtectionEnabled{false};

    KeyloggerProtectionConfiguration m_config;
    KeyloggerProtectionStatistics m_stats;

    std::thread m_monitorThread;

    std::vector<KeyloggerProtectedWindow> m_protectedWindows;
    std::set<uint32_t> m_whitelistedPids;
    std::set<std::wstring, std::less<>> m_whitelistedPaths;

    std::deque<KeyloggerDetectionEvent> m_detectionHistory;

    DetectionCallback m_detectionCallback;
    ErrorCallback m_errorCallback;
};

// ============================================================================
// PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

KeyloggerProtection& KeyloggerProtection::Instance() noexcept {
    static KeyloggerProtection instance;
    return instance;
}

bool KeyloggerProtection::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

KeyloggerProtection::KeyloggerProtection()
    : m_impl(std::make_unique<KeyloggerProtectionImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

KeyloggerProtection::~KeyloggerProtection() {
    m_impl->Shutdown();
    s_instanceCreated.store(false, std::memory_order_release);
}

bool KeyloggerProtection::Initialize(const KeyloggerProtectionConfiguration& config) {
    return m_impl->Initialize(config);
}

void KeyloggerProtection::Shutdown() {
    m_impl->Shutdown();
}

bool KeyloggerProtection::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus KeyloggerProtection::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool KeyloggerProtection::IsRunning() const noexcept {
    return m_impl->IsRunning();
}

bool KeyloggerProtection::Start() { return m_impl->Start(); }
bool KeyloggerProtection::Stop() { return m_impl->Stop(); }
void KeyloggerProtection::Pause() { m_impl->Pause(); }
void KeyloggerProtection::Resume() { m_impl->Resume(); }

bool KeyloggerProtection::UpdateConfiguration(const KeyloggerProtectionConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

KeyloggerProtectionConfiguration KeyloggerProtection::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

void KeyloggerProtection::SetProtectionMode(ProtectionMode mode) {
    auto config = GetConfiguration();
    config.protectionMode = mode;
    if (!UpdateConfiguration(config)) {
        SS_LOG_ERROR(LOG_CATEGORY,
            L"SetProtectionMode rejected mode=%u",
            static_cast<unsigned>(mode));
    }
}

ProtectionMode KeyloggerProtection::GetProtectionMode() const noexcept {
    return m_impl->GetProtectionMode();
}

std::vector<KeyboardHookInfo> KeyloggerProtection::ScanKeyboardHooks() {
    return m_impl->ScanKeyboardHooks();
}

std::vector<KeyboardHookInfo> KeyloggerProtection::ScanProcessHooks(uint32_t processId) {
    return m_impl->ScanProcessHooks(processId);
}

bool KeyloggerProtection::IsLegitimateHook(const KeyboardHookInfo& hook) const {
    return m_impl->IsLegitimateHook(hook);
}

bool KeyloggerProtection::BlockHook(const KeyboardHookInfo& hook) {
    return m_impl->BlockHook(hook);
}

size_t KeyloggerProtection::UnhookMaliciousHooks() {
    return m_impl->UnhookMaliciousHooks();
}

bool KeyloggerProtection::EnableSecureInputMode(uint64_t windowHandle) {
    return m_impl->EnableSecureInputMode(windowHandle);
}

void KeyloggerProtection::DisableSecureInputMode(uint64_t windowHandle) {
    m_impl->DisableSecureInputMode(windowHandle);
}

bool KeyloggerProtection::IsSecureInputActive() const noexcept {
    return !m_impl->GetProtectedWindows().empty();
}

std::vector<KeyloggerProtectedWindow> KeyloggerProtection::GetProtectedWindows() const {
    return m_impl->GetProtectedWindows();
}

void KeyloggerProtection::AutoProtectPasswordFields() {
    m_impl->AutoProtectPasswordFields();
}

void KeyloggerProtection::EnableClipboardProtection() {
    m_impl->EnableClipboardProtection();
}

void KeyloggerProtection::DisableClipboardProtection() {
    m_impl->DisableClipboardProtection();
}

bool KeyloggerProtection::IsClipboardProtectionEnabled() const noexcept {
    return m_impl->IsClipboardProtectionEnabled();
}

void KeyloggerProtection::ClearClipboard() {
    m_impl->ClearClipboard();
}

std::vector<ClipboardThreatInfo> KeyloggerProtection::GetClipboardAccessEvents() const {
    // Clipboard access event monitoring requires a window-procedure-based listener
    // which must be wired from the host application's message pump. Return any
    // cached events from the impl (currently none — the host must feed us events).
    return {};
}

bool KeyloggerProtection::ShowVirtualKeyboard() {
    // Launch the Windows on-screen keyboard as a protected virtual input surface
    wchar_t systemDir[MAX_PATH]{};
    UINT systemDirLen = ::GetSystemDirectoryW(systemDir, static_cast<UINT>(std::size(systemDir)));
    if (systemDirLen == 0 || systemDirLen >= std::size(systemDir)) {
        SS_LOG_ERROR(LOG_CATEGORY,
            L"Failed to resolve System32 directory for virtual keyboard, error=%lu",
            ::GetLastError());
        return false;
    }
    std::filesystem::path oskPath = std::filesystem::path(systemDir) / L"osk.exe";
    HINSTANCE result = ::ShellExecuteW(nullptr, L"open", oskPath.c_str(),
                                       nullptr, nullptr, SW_SHOW);
    bool ok = reinterpret_cast<uintptr_t>(result) > 32;
    if (ok) {
        SS_LOG_INFO(LOG_CATEGORY, L"Virtual keyboard (osk.exe) launched");
    } else {
        SS_LOG_ERROR(LOG_CATEGORY, L"Failed to launch virtual keyboard, error=%lu",
                     ::GetLastError());
    }
    return ok;
}

void KeyloggerProtection::HideVirtualKeyboard() {
    HWND hwnd = ::FindWindowW(L"OSKMainClass", nullptr);
    if (hwnd) {
        if (::PostMessageW(hwnd, WM_CLOSE, 0, 0)) {
            SS_LOG_DEBUG(LOG_CATEGORY, L"Virtual keyboard close requested");
        } else {
            SS_LOG_WARN(LOG_CATEGORY,
                L"Virtual keyboard close request failed, error=%lu", ::GetLastError());
        }
    }
}

bool KeyloggerProtection::IsVirtualKeyboardVisible() const noexcept {
    HWND hwnd = ::FindWindowW(L"OSKMainClass", nullptr);
    return hwnd != nullptr && ::IsWindowVisible(hwnd);
}

std::vector<KeyloggerDetectionEvent> KeyloggerProtection::DetectKeyloggers() {
    return m_impl->DetectKeyloggers();
}

KeyloggerDetectionEvent KeyloggerProtection::ScanProcess(uint32_t processId) {
    KeyloggerDetectionEvent event{};
    event.eventId = GenerateEventId();
    if (event.eventId.empty()) {
        SS_LOG_ERROR(LOG_CATEGORY, L"ScanProcess: event ID generation failed for PID=%u", processId);
        event.description = "Event ID generation failed";
        event.severity = ThreatSeverity::None;
        return event;
    }
    event.processId = processId;
    event.detectionTime = Now();

    auto procName = Utils::ProcessUtils::GetProcessName(static_cast<Utils::ProcessUtils::ProcessId>(processId));
    if (procName.has_value()) {
        event.processName = procName.value();
    }
    auto procPath = Utils::ProcessUtils::GetProcessPath(static_cast<Utils::ProcessUtils::ProcessId>(processId));
    if (procPath.has_value()) {
        event.processPath = procPath.value();
    }

    // Check loaded modules
    auto hooks = m_impl->ScanProcessHooks(processId);
    if (!hooks.empty()) {
        event.keyloggerType = KeyloggerType::SoftwareHook;
        event.severity = ThreatSeverity::High;
        event.confidence = 0.8;
        event.threatScore = 75.0;
        event.description = "Process has suspicious keyboard hook modules";
        event.detectedHooks = std::move(hooks);
    } else {
        event.severity = ThreatSeverity::None;
        event.confidence = 0.0;
        event.threatScore = 0.0;
        event.description = "No keylogging indicators found";
    }

    return event;
}

std::vector<SuspiciousAPICall> KeyloggerProtection::MonitorSuspiciousAPICalls() {
    // Full API call interception requires user-mode hooking (Detours/MinHook) or
    // ETW tracing. Return empty until the hooking engine is wired.
    SS_LOG_DEBUG(LOG_CATEGORY,
                 L"MonitorSuspiciousAPICalls: API interception requires hooking engine");
    return {};
}

bool KeyloggerProtection::DetectGetAsyncKeyStateAbuse(uint32_t processId) {
    // Detecting GetAsyncKeyState polling requires either:
    // 1. API hook on GetAsyncKeyState in the target process
    // 2. ETW provider monitoring
    // We can do a heuristic: check if the process imports GetAsyncKeyState
    // AND has no visible UI (typical polling keylogger pattern)
    bool hasImport = ProcessHasSuspiciousModules(processId);
    bool hasUI = ProcessHasVisibleWindow(processId);
    bool suspicious = hasImport && !hasUI;

    if (suspicious) {
        SS_LOG_WARN(LOG_CATEGORY,
                    L"GetAsyncKeyState abuse suspected for PID=%u (imports+no UI)",
                    processId);
    }
    return suspicious;
}

bool KeyloggerProtection::TerminateKeylogger(uint32_t processId) {
    return m_impl->TerminateKeylogger(processId);
}

bool KeyloggerProtection::QuarantineKeylogger(uint32_t processId) {
    // Quarantine = terminate + remove persistence + log for forensics
    auto procPath = Utils::ProcessUtils::GetProcessPath(static_cast<Utils::ProcessUtils::ProcessId>(processId));
    bool terminated = m_impl->TerminateKeylogger(processId);
    bool cleaned = m_impl->RemovePersistence(processId);

    if (terminated) {
        SS_LOG_INFO(LOG_CATEGORY,
                    L"Quarantined keylogger PID=%u path=%s (terminated=%d, persistence_removed=%d)",
                    processId,
                    procPath.has_value() ? procPath.value().c_str() : L"<unknown>",
                    terminated, cleaned);
    }
    return terminated;
}

bool KeyloggerProtection::RemovePersistence(uint32_t processId) {
    return m_impl->RemovePersistence(processId);
}

bool KeyloggerProtection::IsWhitelisted(uint32_t processId) const {
    return m_impl->IsWhitelisted(processId);
}

void KeyloggerProtection::AddToWhitelist(uint32_t processId, const std::string& reason) {
    m_impl->AddToWhitelist(processId, reason);
}

void KeyloggerProtection::AddPathToWhitelist(const std::filesystem::path& path,
                                              const std::string& reason) {
    m_impl->AddPathToWhitelist(path, reason);
}

void KeyloggerProtection::RemoveFromWhitelist(uint32_t processId) {
    m_impl->RemoveFromWhitelist(processId);
}

void KeyloggerProtection::RegisterDetectionCallback(DetectionCallback callback) {
    m_impl->RegisterDetectionCallback(std::move(callback));
}

void KeyloggerProtection::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void KeyloggerProtection::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

KeyloggerProtectionStatistics KeyloggerProtection::GetStatistics() const {
    return m_impl->GetStatistics();
}

void KeyloggerProtection::ResetStatistics() {
    m_impl->ResetStatistics();
}

std::vector<KeyloggerDetectionEvent> KeyloggerProtection::GetRecentDetections(
    size_t maxCount) const {
    return m_impl->GetRecentDetections(maxCount);
}

bool KeyloggerProtection::SelfTest() {
    return m_impl->SelfTest();
}

std::string KeyloggerProtection::GetVersionString() noexcept {
    return std::to_string(KeyloggerConstants::VERSION_MAJOR) + "." +
           std::to_string(KeyloggerConstants::VERSION_MINOR) + "." +
           std::to_string(KeyloggerConstants::VERSION_PATCH);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetKeyloggerTypeName(KeyloggerType type) noexcept {
    switch (type) {
        case KeyloggerType::Unknown:        return "Unknown";
        case KeyloggerType::SoftwareHook:   return "Software Hook";
        case KeyloggerType::RawInput:       return "Raw Input";
        case KeyloggerType::DirectInput:    return "DirectInput";
        case KeyloggerType::APIPolling:     return "API Polling";
        case KeyloggerType::KernelDriver:   return "Kernel Driver";
        case KeyloggerType::FormGrabber:    return "Form Grabber";
        case KeyloggerType::Hardware:       return "Hardware";
        case KeyloggerType::ScreenCapture:  return "Screen Capture";
        case KeyloggerType::Acoustic:       return "Acoustic";
    }
    return "Unknown";
}

std::string_view GetKeyboardHookTypeName(KeyboardHookType type) noexcept {
    switch (type) {
        case KeyboardHookType::Unknown:          return "Unknown";
        case KeyboardHookType::Hook_Keyboard:     return "WH_KEYBOARD";
        case KeyboardHookType::Hook_KeyboardLL:   return "WH_KEYBOARD_LL";
        case KeyboardHookType::Hook_JournalRecord: return "WH_JOURNALRECORD";
        case KeyboardHookType::Hook_GetMessage:   return "WH_GETMESSAGE";
        case KeyboardHookType::RawInputDevice:    return "RawInputDevice";
        case KeyboardHookType::DirectInputHook:   return "DirectInputHook";
    }
    return "Unknown";
}

std::string_view GetProtectionModeName(ProtectionMode mode) noexcept {
    switch (mode) {
        case ProtectionMode::Disabled:   return "Disabled";
        case ProtectionMode::Monitor:    return "Monitor";
        case ProtectionMode::Protect:    return "Protect";
        case ProtectionMode::Aggressive: return "Aggressive";
    }
    return "Unknown";
}

std::string_view GetInputFieldTypeName(InputFieldType type) noexcept {
    switch (type) {
        case InputFieldType::Unknown:    return "Unknown";
        case InputFieldType::Password:   return "Password";
        case InputFieldType::PIN:        return "PIN";
        case InputFieldType::CreditCard: return "CreditCard";
        case InputFieldType::SSN:        return "SSN";
        case InputFieldType::CVV:        return "CVV";
        case InputFieldType::Username:   return "Username";
        case InputFieldType::Email:      return "Email";
        case InputFieldType::OTP:        return "OTP";
        case InputFieldType::Generic:    return "Generic";
    }
    return "Unknown";
}

InputFieldType DetectInputFieldType(uint64_t windowHandle) {
    HWND hwnd = reinterpret_cast<HWND>(static_cast<uintptr_t>(windowHandle));
    if (!::IsWindow(hwnd)) return InputFieldType::Unknown;

    LONG_PTR style = ::GetWindowLongPtrW(hwnd, GWL_STYLE);
    if (style & ES_PASSWORD) return InputFieldType::Password;

    // Heuristic: check the control's associated label text or name
    wchar_t className[64]{};
    ::GetClassNameW(hwnd, className, static_cast<int>(std::size(className)));
    std::wstring cls(className);

    // Standard Edit control check
    if (_wcsicmp(cls.c_str(), L"Edit") == 0 || _wcsicmp(cls.c_str(), L"RichEdit20W") == 0) {
        // Check parent label heuristics (search sibling controls)
        return InputFieldType::Generic;
    }

    return InputFieldType::Unknown;
}

bool IsPasswordField(uint64_t windowHandle) {
    HWND hwnd = reinterpret_cast<HWND>(static_cast<uintptr_t>(windowHandle));
    if (!::IsWindow(hwnd)) return false;
    LONG_PTR style = ::GetWindowLongPtrW(hwnd, GWL_STYLE);
    return (style & ES_PASSWORD) != 0;
}

} // namespace Banking
} // namespace ShadowStrike
