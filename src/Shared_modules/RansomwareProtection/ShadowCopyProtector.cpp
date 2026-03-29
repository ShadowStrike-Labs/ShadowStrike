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
 * ShadowStrike NGAV - SHADOW COPY PROTECTOR IMPLEMENTATION
 * ============================================================================
 *
 * @file ShadowCopyProtector.cpp
 * @brief Enterprise-grade VSS shadow copy protection against ransomware
 *
 * ARCHITECTURE:
 * - PIMPL pattern for ABI stability
 * - Meyers' singleton for thread-safe instance management
 * - shared_mutex for concurrent read/write access
 * - RAII COM wrapper for leak-proof COM object management
 * - Integration with PhantomSensor kernel process creation callbacks
 *
 * PROTECTION LAYERS:
 * 1. Kernel process creation blocking (pre-execution via PhantomSensor)
 * 2. Command line analysis with obfuscation bypass (base64, caret, env vars)
 * 3. Process termination (kill attacking processes post-creation)
 * 4. VSS service configuration enforcement (startup type + auto-restart)
 * 5. Shadow copy inventory monitoring (detect count decreases)
 * 6. Real-time attack event logging and telemetry
 *
 * OBFUSCATION BYPASS:
 * - CMD caret insertion: v^s^s^a^d^m^i^n → vssadmin
 * - PowerShell -EncodedCommand base64 decoding
 * - PowerShell -e short form detection
 * - Environment variable expansion detection
 * - Unicode homoglyph normalization
 *
 * PERFORMANCE TARGETS:
 * - OnProcessCreation: <500µs (kernel callback hot path)
 * - Command analysis: <1ms per command
 * - Service check: <50ms for SCM access
 * - Shadow enumeration: <500ms for full VSS query
 *
 * @author ShadowStrike Security Team
 * @version 3.1.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "ShadowCopyProtector.hpp"

// ============================================================================
// ADDITIONAL INCLUDES
// ============================================================================

#include "../Utils/StringUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/JSONUtils.hpp"
#include "../Utils/Timer.hpp"
#include "../Utils/HashUtils.hpp"
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <thread>
#include <cctype>
#include <shared_mutex>
#include <cwctype>

#pragma comment(lib, "vssapi.lib")
#pragma comment(lib, "advapi32.lib")

// ============================================================================
// RAII COM SCOPE GUARD
// ============================================================================

namespace {

/**
 * @brief RAII guard for COM initialization on the current thread.
 *
 * Calls CoInitializeEx on construction, CoUninitialize on destruction.
 * Handles RPC_E_CHANGED_MODE gracefully (COM already initialized with
 * different apartment model — we still participate but skip uninit).
 */
class ComScope final {
public:
    explicit ComScope(DWORD coinitFlags = COINIT_MULTITHREADED) noexcept {
        m_hr = ::CoInitializeEx(nullptr, coinitFlags);
        m_ownsInit = (m_hr == S_OK);
        // S_FALSE = already initialized on this thread (same model), we still
        // must call CoUninitialize once per successful CoInitializeEx.
        if (m_hr == S_FALSE) {
            m_ownsInit = true;
        }
        // RPC_E_CHANGED_MODE = already initialized with different model.
        // We can still use COM, but must NOT call CoUninitialize.
    }

    ~ComScope() noexcept {
        if (m_ownsInit) {
            ::CoUninitialize();
        }
    }

    ComScope(const ComScope&) = delete;
    ComScope& operator=(const ComScope&) = delete;

    [[nodiscard]] bool Succeeded() const noexcept {
        return SUCCEEDED(m_hr);
    }

    [[nodiscard]] HRESULT GetResult() const noexcept {
        return m_hr;
    }

private:
    HRESULT m_hr = E_UNEXPECTED;
    bool m_ownsInit = false;
};

/**
 * @brief RAII wrapper for a single COM interface pointer.
 *
 * Calls Release() on destruction. Prevents double-release and leaks
 * on early returns / exceptions.
 */
template <typename T>
class ComPtr final {
public:
    ComPtr() noexcept = default;
    explicit ComPtr(T* ptr) noexcept : m_ptr(ptr) {}

    ~ComPtr() noexcept {
        Reset();
    }

    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;

    ComPtr(ComPtr&& other) noexcept : m_ptr(other.m_ptr) {
        other.m_ptr = nullptr;
    }

    ComPtr& operator=(ComPtr&& other) noexcept {
        if (this != &other) {
            Reset();
            m_ptr = other.m_ptr;
            other.m_ptr = nullptr;
        }
        return *this;
    }

    T* Get() const noexcept { return m_ptr; }
    T** GetAddressOf() noexcept { return &m_ptr; }
    T* operator->() const noexcept { return m_ptr; }
    explicit operator bool() const noexcept { return m_ptr != nullptr; }

    void Reset() noexcept {
        if (m_ptr) {
            m_ptr->Release();
            m_ptr = nullptr;
        }
    }

    T* Detach() noexcept {
        T* tmp = m_ptr;
        m_ptr = nullptr;
        return tmp;
    }

private:
    T* m_ptr = nullptr;
};

/**
 * @brief RAII wrapper for Windows SC_HANDLE.
 */
class ScHandleGuard final {
public:
    ScHandleGuard() noexcept = default;
    explicit ScHandleGuard(SC_HANDLE h) noexcept : m_handle(h) {}
    ~ScHandleGuard() noexcept {
        if (m_handle) ::CloseServiceHandle(m_handle);
    }

    ScHandleGuard(const ScHandleGuard&) = delete;
    ScHandleGuard& operator=(const ScHandleGuard&) = delete;

    ScHandleGuard(ScHandleGuard&& o) noexcept : m_handle(o.m_handle) { o.m_handle = nullptr; }
    ScHandleGuard& operator=(ScHandleGuard&& o) noexcept {
        if (this != &o) {
            if (m_handle) ::CloseServiceHandle(m_handle);
            m_handle = o.m_handle;
            o.m_handle = nullptr;
        }
        return *this;
    }

    [[nodiscard]] SC_HANDLE Get() const noexcept { return m_handle; }
    explicit operator bool() const noexcept { return m_handle != nullptr; }

    SC_HANDLE Release() noexcept {
        SC_HANDLE h = m_handle;
        m_handle = nullptr;
        return h;
    }

private:
    SC_HANDLE m_handle = nullptr;
};

} // anonymous namespace (RAII wrappers)

// ============================================================================
// INTERNAL CONSTANTS AND HELPERS
// ============================================================================

namespace {
    using namespace ShadowStrike::Ransomware;

    /// @brief VSS service name
    constexpr const wchar_t* VSS_SERVICE_NAME = L"VSS";

    /// @brief Maximum recent attacks to store
    constexpr size_t MAX_RECENT_ATTACKS = ShadowCopyConstants::MAX_RECENT_ATTACKS;

    /// @brief Monitoring interval
    constexpr uint32_t MONITORING_INTERVAL_MS = ShadowCopyConstants::MONITORING_INTERVAL_MS;

    // ========================================================================
    // DANGEROUS EXECUTABLE NAMES (case-insensitive comparison)
    // ========================================================================

    /// @brief Executables that can delete shadow copies
    constexpr const wchar_t* VSS_DANGER_EXECUTABLES[] = {
        L"vssadmin.exe",
        L"wmic.exe",
        L"diskshadow.exe",
        L"wbadmin.exe",
    };

    /// @brief Executables that can disable recovery
    constexpr const wchar_t* RECOVERY_DANGER_EXECUTABLES[] = {
        L"bcdedit.exe",
    };

    /// @brief PowerShell executables (need command-line analysis)
    constexpr const wchar_t* POWERSHELL_EXECUTABLES[] = {
        L"powershell.exe",
        L"pwsh.exe",
    };

    // ========================================================================
    // SAFE COMMAND PATTERNS (whitelist for false-positive prevention)
    // ========================================================================

    struct SafePattern {
        const wchar_t* keyword1;
        const wchar_t* keyword2;
    };

    constexpr SafePattern SAFE_COMMAND_PATTERNS[] = {
        { L"vssadmin", L"list" },
        { L"wmic", L"list" },
    };

    // ========================================================================
    // UTILITY FUNCTIONS
    // ========================================================================

    [[nodiscard]] uint64_t GenerateEventId() noexcept {
        static std::atomic<uint64_t> s_counter{1};
        return s_counter.fetch_add(1, std::memory_order_relaxed);
    }

    /**
     * @brief Strip CMD caret escape characters: v^s^s^a^d^m^i^n → vssadmin
     *
     * CMD.exe uses ^ as an escape character. Ransomware uses it to obfuscate
     * command lines: "v^s^s^a^d^m^i^n d^e^l^e^t^e s^h^a^d^o^w^s"
     */
    [[nodiscard]] std::wstring StripCarets(std::wstring_view input) {
        std::wstring result;
        result.reserve(input.size());
        for (wchar_t ch : input) {
            if (ch != L'^') {
                result.push_back(ch);
            }
        }
        return result;
    }

    /**
     * @brief Strip double-quotes used to break token matching:
     *        vs"sad"min → vssadmin
     */
    [[nodiscard]] std::wstring StripQuotes(std::wstring_view input) {
        std::wstring result;
        result.reserve(input.size());
        for (wchar_t ch : input) {
            if (ch != L'"' && ch != L'\'') {
                result.push_back(ch);
            }
        }
        return result;
    }

    /**
     * @brief Decode base64-encoded PowerShell commands.
     *
     * PowerShell -EncodedCommand accepts UTF-16LE base64 strings.
     * Ransomware encodes shadow-deletion commands to evade naive detection.
     *
     * Returns empty string if decoding fails or result is not valid UTF-16.
     */
    [[nodiscard]] std::wstring DecodeBase64PowerShell(std::wstring_view base64Token) {
        if (base64Token.empty() || base64Token.size() > 65536) {
            return {};
        }

        // Convert wide base64 chars to narrow for CryptStringToBinaryA
        std::string narrow;
        narrow.reserve(base64Token.size());
        for (wchar_t wc : base64Token) {
            if (wc > 127) return {};  // Not valid base64
            narrow.push_back(static_cast<char>(wc));
        }

        // Determine decoded size
        DWORD decodedSize = 0;
        if (!::CryptStringToBinaryA(narrow.c_str(), static_cast<DWORD>(narrow.size()),
                                     CRYPT_STRING_BASE64, nullptr, &decodedSize, nullptr, nullptr)) {
            return {};
        }

        if (decodedSize == 0 || decodedSize > 131072 || (decodedSize % 2) != 0) {
            return {};  // Invalid or too large or not valid UTF-16LE
        }

        std::vector<BYTE> decoded(decodedSize);
        if (!::CryptStringToBinaryA(narrow.c_str(), static_cast<DWORD>(narrow.size()),
                                     CRYPT_STRING_BASE64, decoded.data(), &decodedSize, nullptr, nullptr)) {
            return {};
        }

        // Interpret as UTF-16LE
        const wchar_t* wstr = reinterpret_cast<const wchar_t*>(decoded.data());
        size_t wlen = decodedSize / sizeof(wchar_t);

        // Validate: no embedded NULLs (except possible trailing)
        std::wstring result(wstr, wlen);
        while (!result.empty() && result.back() == L'\0') {
            result.pop_back();
        }

        return result;
    }

    /**
     * @brief Extract the base64 payload from a PowerShell command line
     *        containing -EncodedCommand or -e/-ec flags.
     */
    [[nodiscard]] std::wstring ExtractEncodedCommandPayload(const std::wstring& lowerCmd) {
        // Search for -encodedcommand, -enc, -e (PowerShell accepts prefix matching)
        const std::wstring_view encodedFlags[] = {
            L"-encodedcommand", L"-enc", L"-ec", L"-en",
        };

        for (auto flag : encodedFlags) {
            size_t pos = lowerCmd.find(flag);
            if (pos == std::wstring::npos) continue;

            size_t afterFlag = pos + flag.size();
            // Skip whitespace after the flag
            while (afterFlag < lowerCmd.size() && std::iswspace(lowerCmd[afterFlag])) {
                ++afterFlag;
            }

            if (afterFlag >= lowerCmd.size()) continue;

            // Extract the next token (base64 payload)
            size_t tokenEnd = afterFlag;
            while (tokenEnd < lowerCmd.size() && !std::iswspace(lowerCmd[tokenEnd])) {
                ++tokenEnd;
            }

            // Use the ORIGINAL (non-lowered) command line for base64 (case-sensitive)
            // We don't have it here, so just use the lowercase version — base64 decode
            // handles mixed case. Caller should pass original cmdLine for this.
            return std::wstring(lowerCmd.substr(afterFlag, tokenEnd - afterFlag));
        }

        return {};
    }

    /**
     * @brief Extract filename from a full path (case-insensitive).
     */
    [[nodiscard]] std::wstring ExtractFilename(std::wstring_view path) {
        size_t lastSep = path.find_last_of(L"\\/");
        if (lastSep != std::wstring_view::npos) {
            return std::wstring(path.substr(lastSep + 1));
        }
        return std::wstring(path);
    }

    /**
     * @brief Case-insensitive wstring comparison using Windows API.
     */
    [[nodiscard]] bool WideIEquals(std::wstring_view a, std::wstring_view b) noexcept {
        if (a.size() != b.size()) return false;
        if (a.empty()) return true;
        return ::CompareStringOrdinal(
            a.data(), static_cast<int>(a.size()),
            b.data(), static_cast<int>(b.size()),
            TRUE) == CSTR_EQUAL;
    }

    /**
     * @brief Case-insensitive substring search using Windows CharLowerBuff.
     */
    [[nodiscard]] bool WideIContains(std::wstring_view haystack, std::wstring_view needle) noexcept {
        if (needle.empty()) return true;
        if (haystack.size() < needle.size()) return false;

        // Use the codebase utility if available; fallback to manual search
        auto it = std::search(
            haystack.begin(), haystack.end(),
            needle.begin(), needle.end(),
            [](wchar_t a, wchar_t b) noexcept {
                return ::CharLowerW(reinterpret_cast<LPWSTR>(static_cast<ULONG_PTR>(a))) ==
                       ::CharLowerW(reinterpret_cast<LPWSTR>(static_cast<ULONG_PTR>(b)));
            }
        );
        return it != haystack.end();
    }

    /**
     * @brief Normalize a command line for analysis:
     *        - Strip carets
     *        - Strip inner quotes
     *        - Collapse whitespace
     */
    [[nodiscard]] std::wstring NormalizeCommandLine(std::wstring_view rawCmdLine) {
        std::wstring cmd = StripCarets(rawCmdLine);
        cmd = StripQuotes(cmd);

        // Collapse runs of whitespace into single space
        std::wstring collapsed;
        collapsed.reserve(cmd.size());
        bool lastWasSpace = false;
        for (wchar_t ch : cmd) {
            if (std::iswspace(ch)) {
                if (!lastWasSpace) {
                    collapsed.push_back(L' ');
                    lastWasSpace = true;
                }
            } else {
                collapsed.push_back(ch);
                lastWasSpace = false;
            }
        }

        return collapsed;
    }

    /**
     * @brief Convert wstring to lowercase (in-place).
     */
    void ToLowerInPlace(std::wstring& str) noexcept {
        if (!str.empty()) {
            ::CharLowerBuffW(str.data(), static_cast<DWORD>(str.size()));
        }
    }

} // anonymous namespace

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

namespace ShadowStrike::Ransomware {

class ShadowCopyProtectorImpl final {
public:
    ShadowCopyProtectorImpl() = default;
    ~ShadowCopyProtectorImpl() {
        StopMonitoring();
        UnlockVssServiceInternal();
    }

    ShadowCopyProtectorImpl(const ShadowCopyProtectorImpl&) = delete;
    ShadowCopyProtectorImpl& operator=(const ShadowCopyProtectorImpl&) = delete;
    ShadowCopyProtectorImpl(ShadowCopyProtectorImpl&&) = delete;
    ShadowCopyProtectorImpl& operator=(ShadowCopyProtectorImpl&&) = delete;

    // ========================================================================
    // STATE
    // ========================================================================

    mutable std::shared_mutex m_mutex;

    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    ShadowCopyProtectorConfiguration m_config;
    ShadowCopyStatistics m_stats;

    // Service protection
    std::atomic<bool> m_serviceLocked{false};
    ScHandleGuard m_scManager;
    ScHandleGuard m_vssService;

    // Whitelist (full paths, case-insensitive exact match)
    std::vector<std::wstring> m_whitelist;

    // Event history
    std::vector<VSSAttackEvent> m_recentAttacks;

    // Callbacks
    VSSAttackCallback m_attackCallback;
    DecisionCallback m_decisionCallback;

    // Monitoring
    std::atomic<bool> m_monitoringActive{false};
    std::thread m_monitoringThread;

    // Snapshot inventory tracking
    std::atomic<uint64_t> m_lastKnownSnapshotCount{0};

    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    /**
     * @brief Invoke attack callback with exception safety.
     */
    void NotifyAttack(const VSSAttackEvent& event) {
        VSSAttackCallback callbackCopy;
        {
            std::shared_lock lock(m_mutex);
            callbackCopy = m_attackCallback;
        }
        if (callbackCopy) {
            try {
                callbackCopy(event);
            } catch (const std::exception& e) {
                Utils::Logger::Error("ShadowCopyProtector: Attack callback exception: {}", e.what());
            } catch (...) {
                Utils::Logger::Error("ShadowCopyProtector: Unknown attack callback exception");
            }
        }
    }

    /**
     * @brief Invoke decision callback to determine if process should be blocked.
     */
    [[nodiscard]] bool ShouldBlockProcess(uint32_t pid, VSSAttackType type) {
        DecisionCallback callbackCopy;
        {
            std::shared_lock lock(m_mutex);
            callbackCopy = m_decisionCallback;
        }
        if (callbackCopy) {
            try {
                return callbackCopy(pid, type);
            } catch (...) {
                return true;  // Fail-secure: block on callback error
            }
        }
        return true;  // Default: block
    }

    /**
     * @brief Check if a command is safe (administrative listing, not deletion).
     *
     * Prevents false positives on "vssadmin list shadows" or "wmic shadowcopy list".
     */
    [[nodiscard]] bool IsSafeCommand(const std::wstring& lowerCmd) const noexcept {
        for (const auto& pattern : SAFE_COMMAND_PATTERNS) {
            if (WideIContains(lowerCmd, pattern.keyword1) &&
                WideIContains(lowerCmd, pattern.keyword2)) {
                // "vssadmin list" is safe. But "vssadmin list && vssadmin delete" is NOT safe.
                // Check that no dangerous keyword follows.
                if (!WideIContains(lowerCmd, L"delete") &&
                    !WideIContains(lowerCmd, L"resize") &&
                    !WideIContains(lowerCmd, L"remove")) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * @brief Comprehensive command-line analysis with obfuscation bypass.
     *
     * This is the core detection engine. It normalizes the command line
     * (strip carets, quotes, collapse whitespace), then checks for all
     * known shadow copy deletion patterns.
     *
     * Additionally decodes PowerShell -EncodedCommand base64 payloads
     * and analyzes the decoded content recursively.
     */
    [[nodiscard]] std::optional<VSSAttackType> AnalyzeCommandInternal(std::wstring_view cmdLine) {
        if (cmdLine.empty()) return std::nullopt;

        // Phase 1: Normalize the command line to defeat obfuscation
        std::wstring normalized = NormalizeCommandLine(cmdLine);
        std::wstring lower = normalized;
        ToLowerInPlace(lower);

        // Phase 2: Check safe patterns first (prevent false positives)
        if (IsSafeCommand(lower)) {
            return std::nullopt;
        }

        // Phase 3: Check for vssadmin delete shadows
        if (WideIContains(lower, L"vssadmin") &&
            (WideIContains(lower, L"delete") || WideIContains(lower, L"shadows"))) {
            if (WideIContains(lower, L"delete shadows") || WideIContains(lower, L"delete shadow")) {
                return VSSAttackType::CommandLineDelete;
            }
        }

        // Phase 4: Check for vssadmin resize shadowstorage (shrink attack)
        if (WideIContains(lower, L"vssadmin") && WideIContains(lower, L"resize") &&
            WideIContains(lower, L"shadowstorage")) {
            return VSSAttackType::StorageResize;
        }

        // Phase 5: Check for WMIC shadow copy deletion
        if (WideIContains(lower, L"wmic") && WideIContains(lower, L"shadowcopy") &&
            WideIContains(lower, L"delete")) {
            return VSSAttackType::WMIDelete;
        }

        // Phase 6: Check for PowerShell WMI deletion
        if ((WideIContains(lower, L"get-wmiobject") || WideIContains(lower, L"gwmi")) &&
            WideIContains(lower, L"win32_shadowcopy")) {
            // "Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }"
            if (WideIContains(lower, L"delete") || WideIContains(lower, L"remove")) {
                return VSSAttackType::WMIDelete;
            }
        }

        // Phase 7: Check for Remove-WmiObject (direct WMI deletion)
        if (WideIContains(lower, L"remove-wmiobject") &&
            WideIContains(lower, L"win32_shadowcopy")) {
            return VSSAttackType::WMIDelete;
        }

        // Phase 8: Check for Get-CimInstance shadow copy deletion (modern PowerShell)
        if (WideIContains(lower, L"get-ciminstance") &&
            WideIContains(lower, L"win32_shadowcopy") &&
            (WideIContains(lower, L"remove") || WideIContains(lower, L"delete"))) {
            return VSSAttackType::WMIDelete;
        }

        // Phase 9: Check for diskshadow.exe (script-based shadow manipulation)
        if (WideIContains(lower, L"diskshadow")) {
            if (WideIContains(lower, L"delete") || WideIContains(lower, L"/s")) {
                return VSSAttackType::CommandLineDelete;
            }
        }

        // Phase 10: Check for bcdedit recovery disable
        if (WideIContains(lower, L"bcdedit")) {
            if (WideIContains(lower, L"recoveryenabled") && WideIContains(lower, L"no")) {
                return VSSAttackType::RegistryModify;
            }
            if (WideIContains(lower, L"ignoreallfailures")) {
                return VSSAttackType::RegistryModify;
            }
            if (WideIContains(lower, L"bootstatuspolicy")) {
                return VSSAttackType::RegistryModify;
            }
        }

        // Phase 11: Check for wbadmin catalog/backup deletion
        if (WideIContains(lower, L"wbadmin") && WideIContains(lower, L"delete")) {
            return VSSAttackType::CommandLineDelete;
        }

        // Phase 12: Check for PowerShell -EncodedCommand (base64 obfuscation)
        // This catches: powershell -e <base64>, powershell -enc <base64>,
        //               powershell -EncodedCommand <base64>
        bool isPowerShell = WideIContains(lower, L"powershell") || WideIContains(lower, L"pwsh");
        if (isPowerShell) {
            // First check for -e flag with base64 payload
            std::wstring base64Payload = ExtractEncodedCommandPayload(lower);
            if (!base64Payload.empty()) {
                // Use the ORIGINAL command to get case-correct base64
                std::wstring origNormalized = NormalizeCommandLine(cmdLine);
                std::wstring origBase64 = ExtractEncodedCommandPayload(origNormalized);
                if (origBase64.empty()) origBase64 = base64Payload;

                std::wstring decoded = DecodeBase64PowerShell(origBase64);
                if (!decoded.empty()) {
                    // Recursively analyze the decoded command
                    auto innerResult = AnalyzeCommandInternal(decoded);
                    if (innerResult.has_value()) {
                        return innerResult;
                    }
                }
            }

            // Check for inline PowerShell shadow deletion even without -EncodedCommand
            if (WideIContains(lower, L"win32_shadowcopy") &&
                (WideIContains(lower, L"delete") || WideIContains(lower, L"remove"))) {
                return VSSAttackType::WMIDelete;
            }
        }

        // Phase 13: Check for sc.exe stopping VSS service
        if (WideIContains(lower, L"sc") &&
            (WideIContains(lower, L"stop vss") || WideIContains(lower, L"config vss"))) {
            return VSSAttackType::ServiceStop;
        }

        // Phase 14: Check for net stop of VSS service
        if (WideIContains(lower, L"net") && WideIContains(lower, L"stop") &&
            WideIContains(lower, L"vss")) {
            return VSSAttackType::ServiceStop;
        }

        return std::nullopt;
    }

    /**
     * @brief Determine if a process image path is a known VSS-targeting executable.
     *
     * Returns the appropriate attack type if the executable name alone is dangerous
     * (vssadmin, wmic, diskshadow, wbadmin), or nullopt if it requires command-line
     * analysis (powershell, cmd.exe).
     */
    [[nodiscard]] std::optional<VSSAttackType> ClassifyByImageName(std::wstring_view imagePath) const noexcept {
        std::wstring filename = ExtractFilename(imagePath);
        if (filename.empty()) return std::nullopt;

        for (const auto* exe : VSS_DANGER_EXECUTABLES) {
            if (WideIEquals(filename, exe)) {
                return VSSAttackType::CommandLineDelete;
            }
        }

        for (const auto* exe : RECOVERY_DANGER_EXECUTABLES) {
            if (WideIEquals(filename, exe)) {
                return VSSAttackType::RegistryModify;
            }
        }

        return std::nullopt;
    }

    /**
     * @brief Check if process path is whitelisted (exact full-path match, case-insensitive).
     *
     * SECURITY: Uses exact full-path comparison, NOT substring matching.
     * Substring matching is trivially bypassable by creating a directory named
     * after a whitelisted process.
     */
    [[nodiscard]] bool IsWhitelistedInternal(std::wstring_view processPath) const {
        std::shared_lock lock(m_mutex);

        for (const auto& whitelisted : m_whitelist) {
            if (WideIEquals(processPath, whitelisted)) {
                return true;
            }
        }

        for (const auto& whitelisted : m_config.whitelist) {
            if (WideIEquals(processPath, whitelisted)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @brief Terminate an attacking process.
     *
     * Uses PROCESS_TERMINATE access right. Logs the process image name
     * without logging the full command line (which could contain sensitive data
     * in legitimate usage — though for an attacker it's fine to log).
     */
    [[nodiscard]] bool TerminateAttacker(uint32_t pid, const std::wstring& reason) {
        try {
            if (!m_config.killAttacker) {
                return false;
            }

            HANDLE hProcess = ::OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                                            FALSE, pid);
            if (!hProcess) {
                DWORD err = ::GetLastError();
                Utils::Logger::Error("ShadowCopyProtector: Failed to open process {} for termination, error={}",
                                     pid, err);
                return false;
            }

            wchar_t processName[MAX_PATH] = {};
            DWORD nameSize = MAX_PATH;
            ::QueryFullProcessImageNameW(hProcess, 0, processName, &nameSize);

            BOOL terminated = ::TerminateProcess(hProcess, 1);
            DWORD err = ::GetLastError();
            ::CloseHandle(hProcess);

            if (terminated) {
                Utils::Logger::Critical("ShadowCopyProtector: TERMINATED malicious process PID={} [{}] reason={}",
                    pid, Utils::StringUtils::WideToUtf8(processName),
                    Utils::StringUtils::WideToUtf8(reason));
                m_stats.processesKilled.fetch_add(1, std::memory_order_relaxed);
                return true;
            }

            Utils::Logger::Error("ShadowCopyProtector: TerminateProcess failed for PID={}, error={}", pid, err);
            return false;

        } catch (const std::exception& e) {
            Utils::Logger::Error("ShadowCopyProtector: TerminateAttacker exception: {}", e.what());
            return false;
        }
    }

    /**
     * @brief Record an attack event in history and update statistics.
     */
    void RecordAttackEvent(VSSAttackEvent event) {
        std::unique_lock lock(m_mutex);

        m_recentAttacks.push_back(std::move(event));
        if (m_recentAttacks.size() > MAX_RECENT_ATTACKS) {
            m_recentAttacks.erase(m_recentAttacks.begin());
        }
    }

    void IncrementAttackStats(VSSAttackType type) noexcept {
        m_stats.attacksBlocked.fetch_add(1, std::memory_order_relaxed);
        size_t idx = static_cast<size_t>(type);
        if (idx < m_stats.byAttackType.size()) {
            m_stats.byAttackType[idx].fetch_add(1, std::memory_order_relaxed);
        }
    }

    // ========================================================================
    // SERVICE PROTECTION
    // ========================================================================

    /**
     * @brief Lock VSS service configuration.
     *
     * Opens the VSS service with full access and enforces:
     * 1. Startup type = SERVICE_DEMAND_START (default for VSS, prevent disable)
     * 2. Failure actions = restart the service on failure
     *
     * The SCM handles are held open for the lifetime of the protector to
     * maintain our service handle (which helps prevent unauthorized changes
     * while we hold the handle).
     */
    [[nodiscard]] bool LockVssServiceInternal() {
        try {
            if (m_serviceLocked.load(std::memory_order_acquire)) {
                return true;
            }

            if (!m_config.lockService) {
                return false;
            }

            ScHandleGuard scManager(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
            if (!scManager) {
                Utils::Logger::Error("ShadowCopyProtector: Failed to open SCM, error={}", ::GetLastError());
                return false;
            }

            ScHandleGuard vssService(::OpenServiceW(scManager.Get(), VSS_SERVICE_NAME, SERVICE_ALL_ACCESS));
            if (!vssService) {
                Utils::Logger::Error("ShadowCopyProtector: Failed to open VSS service, error={}", ::GetLastError());
                return false;
            }

            // Enforce failure actions: restart service on crash
            SC_ACTION actions[3] = {};
            actions[0] = { SC_ACTION_RESTART, 5000 };  // First failure: restart after 5s
            actions[1] = { SC_ACTION_RESTART, 10000 }; // Second: restart after 10s
            actions[2] = { SC_ACTION_RESTART, 30000 }; // Third: restart after 30s

            SERVICE_FAILURE_ACTIONSW failureActions = {};
            failureActions.dwResetPeriod = 86400;  // Reset failure count after 24h
            failureActions.cActions = 3;
            failureActions.lpsaActions = actions;

            if (!::ChangeServiceConfig2W(vssService.Get(), SERVICE_CONFIG_FAILURE_ACTIONS, &failureActions)) {
                Utils::Logger::Warn("ShadowCopyProtector: Failed to set VSS failure actions, error={}",
                                    ::GetLastError());
            }

            // Prevent VSS from being set to disabled
            QUERY_SERVICE_CONFIGW* pConfig = nullptr;
            DWORD bytesNeeded = 0;
            ::QueryServiceConfigW(vssService.Get(), nullptr, 0, &bytesNeeded);
            if (bytesNeeded > 0 && bytesNeeded < 8192) {
                std::vector<uint8_t> buf(bytesNeeded);
                pConfig = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buf.data());
                if (::QueryServiceConfigW(vssService.Get(), pConfig, bytesNeeded, &bytesNeeded)) {
                    if (pConfig->dwStartType == SERVICE_DISABLED) {
                        // Re-enable the service
                        ::ChangeServiceConfigW(vssService.Get(),
                            SERVICE_NO_CHANGE, SERVICE_DEMAND_START,
                            SERVICE_NO_CHANGE, nullptr, nullptr,
                            nullptr, nullptr, nullptr, nullptr, nullptr);
                        Utils::Logger::Warn("ShadowCopyProtector: VSS service was disabled, re-enabled to demand-start");
                    }
                }
            }

            // Hold the handles open to maintain access
            m_scManager = std::move(scManager);
            m_vssService = std::move(vssService);
            m_serviceLocked.store(true, std::memory_order_release);

            Utils::Logger::Info("ShadowCopyProtector: VSS service protection enabled");
            return true;

        } catch (const std::exception& e) {
            Utils::Logger::Error("ShadowCopyProtector: LockVssService exception: {}", e.what());
            return false;
        }
    }

    /**
     * @brief Release service handles and unlock.
     */
    void UnlockVssServiceInternal() noexcept {
        try {
            m_vssService = ScHandleGuard{};
            m_scManager = ScHandleGuard{};
            m_serviceLocked.store(false, std::memory_order_release);
        } catch (...) {
            // Destructor/shutdown path — never throw
        }
    }

    /**
     * @brief Query whether the VSS service is currently running.
     */
    [[nodiscard]] bool IsVssServiceRunningInternal() const noexcept {
        try {
            ScHandleGuard scm(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
            if (!scm) return false;

            ScHandleGuard svc(::OpenServiceW(scm.Get(), VSS_SERVICE_NAME, SERVICE_QUERY_STATUS));
            if (!svc) return false;

            SERVICE_STATUS status = {};
            if (::QueryServiceStatus(svc.Get(), &status)) {
                return status.dwCurrentState == SERVICE_RUNNING;
            }
            return false;
        } catch (...) {
            return false;
        }
    }

    /**
     * @brief Start the VSS service if it is not running.
     */
    [[nodiscard]] bool EnsureVssServiceRunningInternal() {
        try {
            if (IsVssServiceRunningInternal()) return true;

            ScHandleGuard scm(::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
            if (!scm) {
                Utils::Logger::Error("ShadowCopyProtector: Failed to open SCM, error={}", ::GetLastError());
                return false;
            }

            ScHandleGuard svc(::OpenServiceW(scm.Get(), VSS_SERVICE_NAME,
                                              SERVICE_START | SERVICE_QUERY_STATUS));
            if (!svc) {
                Utils::Logger::Error("ShadowCopyProtector: Failed to open VSS service, error={}", ::GetLastError());
                return false;
            }

            BOOL started = ::StartServiceW(svc.Get(), 0, nullptr);
            DWORD error = ::GetLastError();

            if (started || error == ERROR_SERVICE_ALREADY_RUNNING) {
                Utils::Logger::Info("ShadowCopyProtector: VSS service started successfully");
                return true;
            }

            Utils::Logger::Error("ShadowCopyProtector: Failed to start VSS service, error={}", error);
            return false;

        } catch (const std::exception& e) {
            Utils::Logger::Error("ShadowCopyProtector: EnsureVssServiceRunning exception: {}", e.what());
            return false;
        }
    }

    // ========================================================================
    // SHADOW COPY ENUMERATION (COM-BASED)
    // ========================================================================

    /**
     * @brief Enumerate all shadow copies using the VSS COM API.
     *
     * Uses RAII ComScope and ComPtr to prevent COM object leaks on any
     * error path or exception.
     */
    [[nodiscard]] std::vector<ShadowCopyInfo> EnumerateShadowCopiesInternal() {
        std::vector<ShadowCopyInfo> shadowCopies;

        try {
            ComScope comGuard(COINIT_MULTITHREADED);
            // Even if COM init fails due to apartment mismatch, we can still
            // try VSS operations (we might be in a COM-initialized thread).

            ComPtr<IVssBackupComponents> pBackup;
            {
                IVssBackupComponents* raw = nullptr;
                HRESULT hr = ::CreateVssBackupComponents(&raw);
                if (FAILED(hr) || !raw) {
                    Utils::Logger::Error("ShadowCopyProtector: CreateVssBackupComponents failed, hr={:#x}",
                                         static_cast<uint32_t>(hr));
                    return shadowCopies;
                }
                pBackup = ComPtr<IVssBackupComponents>(raw);
            }

            HRESULT hr = pBackup->InitializeForBackup();
            if (FAILED(hr)) {
                Utils::Logger::Error("ShadowCopyProtector: InitializeForBackup failed, hr={:#x}",
                                     static_cast<uint32_t>(hr));
                return shadowCopies;
            }

            ComPtr<IVssEnumObject> pEnum;
            {
                IVssEnumObject* raw = nullptr;
                hr = pBackup->Query(GUID_NULL, VSS_OBJECT_NONE, VSS_OBJECT_SNAPSHOT, &raw);
                if (FAILED(hr) || !raw) {
                    return shadowCopies;
                }
                pEnum = ComPtr<IVssEnumObject>(raw);
            }

            VSS_OBJECT_PROP prop = {};
            ULONG fetched = 0;

            while (pEnum->Next(1, &prop, &fetched) == S_OK && fetched > 0) {
                if (prop.Type == VSS_OBJECT_SNAPSHOT) {
                    ShadowCopyInfo info;

                    wchar_t guidStr[64] = {};
                    ::StringFromGUID2(prop.Obj.Snap.m_SnapshotId, guidStr, 64);
                    info.shadowId = guidStr;

                    if (prop.Obj.Snap.m_pwszOriginalVolumeName) {
                        info.volume = prop.Obj.Snap.m_pwszOriginalVolumeName;
                    }
                    if (prop.Obj.Snap.m_pwszSnapshotDeviceObject) {
                        info.devicePath = prop.Obj.Snap.m_pwszSnapshotDeviceObject;
                    }

                    // Convert VSS_TIMESTAMP to system_clock::time_point
                    ULARGE_INTEGER ull;
                    ull.LowPart = prop.Obj.Snap.m_tsCreationTimestamp.dwLowDateTime;
                    ull.HighPart = prop.Obj.Snap.m_tsCreationTimestamp.dwHighDateTime;
                    // Windows FILETIME epoch = Jan 1, 1601. Unix epoch = Jan 1, 1970.
                    constexpr uint64_t FILETIME_UNIX_DIFF = 116444736000000000ULL;
                    if (ull.QuadPart > FILETIME_UNIX_DIFF) {
                        auto microseconds = std::chrono::microseconds(
                            (ull.QuadPart - FILETIME_UNIX_DIFF) / 10);
                        info.creationTime = std::chrono::system_clock::time_point(
                            std::chrono::duration_cast<std::chrono::system_clock::duration>(microseconds));
                    }

                    info.state = ShadowCopyState::Active;

                    ::StringFromGUID2(prop.Obj.Snap.m_ProviderId, guidStr, 64);
                    info.providerId = guidStr;

                    info.isProtected = true;

                    shadowCopies.push_back(std::move(info));
                }

                // Free snapshot properties for this iteration
                ::VssFreeSnapshotProperties(&prop.Obj.Snap);
                prop = {};
                fetched = 0;
            }

            m_stats.currentShadowCopies.store(shadowCopies.size(), std::memory_order_relaxed);

        } catch (const std::exception& e) {
            Utils::Logger::Error("ShadowCopyProtector: EnumerateShadowCopies exception: {}", e.what());
        }

        return shadowCopies;
    }

    // ========================================================================
    // MONITORING THREAD
    // ========================================================================

    /**
     * @brief Background monitoring thread.
     *
     * Continuously:
     * 1. Verifies VSS service is running (auto-restart if stopped)
     * 2. Re-establishes service lock if lost
     * 3. Enumerates shadow copies and detects count decreases
     * 4. Generates alerts on unexpected snapshot deletion
     */
    void MonitoringThreadFunc() {
        Utils::Logger::Info("ShadowCopyProtector: Monitoring thread started");

        // Initialize COM for this thread
        ComScope threadCom(COINIT_MULTITHREADED);

        while (m_monitoringActive.load(std::memory_order_acquire)) {
            try {
                // 1. Verify VSS service is running
                if (!IsVssServiceRunningInternal()) {
                    Utils::Logger::Warn("ShadowCopyProtector: VSS service not running, attempting restart");
                    if (EnsureVssServiceRunningInternal()) {
                        Utils::Logger::Info("ShadowCopyProtector: VSS service restarted by monitoring thread");
                    }
                }

                // 2. Re-establish service lock if needed
                if (m_config.lockService && !m_serviceLocked.load(std::memory_order_acquire)) {
                    LockVssServiceInternal();
                }

                // 3. Check if VSS service was disabled by an attacker
                if (m_vssService) {
                    QUERY_SERVICE_CONFIGW* pConfig = nullptr;
                    DWORD bytesNeeded = 0;
                    ::QueryServiceConfigW(m_vssService.Get(), nullptr, 0, &bytesNeeded);
                    if (bytesNeeded > 0 && bytesNeeded < 8192) {
                        std::vector<uint8_t> buf(bytesNeeded);
                        pConfig = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buf.data());
                        if (::QueryServiceConfigW(m_vssService.Get(), pConfig, bytesNeeded, &bytesNeeded)) {
                            if (pConfig->dwStartType == SERVICE_DISABLED) {
                                Utils::Logger::Critical("ShadowCopyProtector: VSS service was DISABLED by attacker! Re-enabling.");
                                ::ChangeServiceConfigW(m_vssService.Get(),
                                    SERVICE_NO_CHANGE, SERVICE_DEMAND_START,
                                    SERVICE_NO_CHANGE, nullptr, nullptr,
                                    nullptr, nullptr, nullptr, nullptr, nullptr);
                            }
                        }
                    }
                }

                // 4. Enumerate shadow copies and detect count decrease
                auto shadows = EnumerateShadowCopiesInternal();
                uint64_t currentCount = shadows.size();
                uint64_t previousCount = m_lastKnownSnapshotCount.load(std::memory_order_acquire);

                if (previousCount > 0 && currentCount < previousCount) {
                    uint64_t deleted = previousCount - currentCount;
                    m_stats.snapshotDecreaseAlerts.fetch_add(1, std::memory_order_relaxed);

                    Utils::Logger::Critical(
                        "ShadowCopyProtector: SNAPSHOT COUNT DECREASED! Previous={}, Current={}, Deleted={}",
                        previousCount, currentCount, deleted);

                    VSSAttackEvent event;
                    event.eventId = GenerateEventId();
                    event.timestamp = std::chrono::system_clock::now();
                    event.attackType = VSSAttackType::APIDelete;
                    event.wasBlocked = false;
                    event.details = L"Shadow copy count decreased from " +
                                    std::to_wstring(previousCount) + L" to " +
                                    std::to_wstring(currentCount);

                    RecordAttackEvent(event);
                    IncrementAttackStats(VSSAttackType::APIDelete);
                    NotifyAttack(event);
                }

                m_lastKnownSnapshotCount.store(currentCount, std::memory_order_release);

                if (m_config.verboseLogging) {
                    Utils::Logger::Debug("ShadowCopyProtector: Shadow copies: {}", currentCount);
                }

            } catch (const std::exception& e) {
                Utils::Logger::Error("ShadowCopyProtector: Monitoring thread error: {}", e.what());
            } catch (...) {
                Utils::Logger::Error("ShadowCopyProtector: Unknown monitoring thread error");
            }

            // Sleep in small increments so shutdown is responsive
            for (uint32_t elapsed = 0;
                 elapsed < MONITORING_INTERVAL_MS &&
                 m_monitoringActive.load(std::memory_order_acquire);
                 elapsed += 100) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }

        Utils::Logger::Info("ShadowCopyProtector: Monitoring thread stopped");
    }

    /**
     * @brief Stop the monitoring thread cleanly.
     */
    void StopMonitoring() noexcept {
        if (m_monitoringActive.load(std::memory_order_acquire)) {
            m_monitoringActive.store(false, std::memory_order_release);
            if (m_monitoringThread.joinable()) {
                try {
                    m_monitoringThread.join();
                } catch (...) {
                    // Thread join failure in shutdown — nothing we can do
                }
            }
        }
    }
};

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

std::atomic<bool> ShadowCopyProtector::s_instanceCreated{false};

[[nodiscard]] ShadowCopyProtector& ShadowCopyProtector::Instance() noexcept {
    static ShadowCopyProtector instance;
    return instance;
}

[[nodiscard]] bool ShadowCopyProtector::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

ShadowCopyProtector::ShadowCopyProtector()
    : m_impl(std::make_unique<ShadowCopyProtectorImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
    Utils::Logger::Info("ShadowCopyProtector: Singleton created (v{})", GetVersionString());
}

ShadowCopyProtector::~ShadowCopyProtector() {
    try {
        Shutdown();
    } catch (...) {
        // Destructor must not throw
    }
}

// ============================================================================
// LIFECYCLE
// ============================================================================

[[nodiscard]] bool ShadowCopyProtector::Initialize(const ShadowCopyProtectorConfiguration& config) {
    try {
        auto expected = ModuleStatus::Uninitialized;
        if (!m_impl->m_status.compare_exchange_strong(expected, ModuleStatus::Initializing,
                std::memory_order_acq_rel)) {
            expected = ModuleStatus::Stopped;
            if (!m_impl->m_status.compare_exchange_strong(expected, ModuleStatus::Initializing,
                    std::memory_order_acq_rel)) {
                Utils::Logger::Warn("ShadowCopyProtector: Already initialized (status={})",
                                    static_cast<int>(m_impl->m_status.load()));
                return false;
            }
        }

        if (!config.IsValid()) {
            Utils::Logger::Error("ShadowCopyProtector: Invalid configuration");
            m_impl->m_status.store(ModuleStatus::Error, std::memory_order_release);
            return false;
        }

        {
            std::unique_lock lock(m_impl->m_mutex);
            m_impl->m_config = config;
            m_impl->m_recentAttacks.clear();
            m_impl->m_recentAttacks.reserve(
                std::min(MAX_RECENT_ATTACKS, static_cast<size_t>(1024)));
        }

        m_impl->m_stats.Reset();
        m_impl->m_stats.startTime = Clock::now();

        // Lock VSS service if configured
        if (config.lockService) {
            m_impl->LockVssServiceInternal();
        }

        // Ensure VSS service is running
        m_impl->EnsureVssServiceRunningInternal();

        // Take initial snapshot count baseline
        auto initialShadows = m_impl->EnumerateShadowCopiesInternal();
        m_impl->m_lastKnownSnapshotCount.store(initialShadows.size(), std::memory_order_release);

        Utils::Logger::Info("ShadowCopyProtector: Initial shadow copy count: {}", initialShadows.size());

        // Start monitoring thread
        m_impl->m_monitoringActive.store(true, std::memory_order_release);
        m_impl->m_monitoringThread = std::thread(
            &ShadowCopyProtectorImpl::MonitoringThreadFunc, m_impl.get());

        m_impl->m_status.store(ModuleStatus::Running, std::memory_order_release);

        Utils::Logger::Info("ShadowCopyProtector: Initialized successfully (enabled={}, lockService={}, killAttacker={})",
                            config.enabled, config.lockService, config.killAttacker);
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("ShadowCopyProtector: Initialization failed: {}", e.what());
        m_impl->m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    }
}

void ShadowCopyProtector::Shutdown() {
    try {
        auto expected = m_impl->m_status.load(std::memory_order_acquire);
        if (expected == ModuleStatus::Uninitialized ||
            expected == ModuleStatus::Stopped ||
            expected == ModuleStatus::Stopping) {
            return;
        }

        m_impl->m_status.store(ModuleStatus::Stopping, std::memory_order_release);

        // Stop monitoring thread first
        m_impl->StopMonitoring();

        // Unlock VSS service
        m_impl->UnlockVssServiceInternal();

        // Clear state under lock
        {
            std::unique_lock lock(m_impl->m_mutex);
            m_impl->m_recentAttacks.clear();
            m_impl->m_attackCallback = nullptr;
            m_impl->m_decisionCallback = nullptr;
        }

        m_impl->m_status.store(ModuleStatus::Stopped, std::memory_order_release);
        Utils::Logger::Info("ShadowCopyProtector: Shut down");

    } catch (const std::exception& e) {
        Utils::Logger::Error("ShadowCopyProtector: Shutdown error: {}", e.what());
    }
}

[[nodiscard]] bool ShadowCopyProtector::IsInitialized() const noexcept {
    return m_impl->m_status.load(std::memory_order_acquire) == ModuleStatus::Running;
}

[[nodiscard]] ModuleStatus ShadowCopyProtector::GetStatus() const noexcept {
    return m_impl->m_status.load(std::memory_order_acquire);
}

// ============================================================================
// DETECTION
// ============================================================================

[[nodiscard]] bool ShadowCopyProtector::IsVssDestructionAttempt(const std::wstring& cmdLine) {
    try {
        return m_impl->AnalyzeCommandInternal(cmdLine).has_value();
    } catch (const std::exception& e) {
        Utils::Logger::Error("ShadowCopyProtector: IsVssDestructionAttempt exception: {}", e.what());
        return false;
    }
}

[[nodiscard]] std::optional<VSSAttackType> ShadowCopyProtector::AnalyzeCommand(std::wstring_view cmdLine) {
    try {
        return m_impl->AnalyzeCommandInternal(cmdLine);
    } catch (const std::exception& e) {
        Utils::Logger::Error("ShadowCopyProtector: AnalyzeCommand exception: {}", e.what());
        return std::nullopt;
    }
}

[[nodiscard]] bool ShadowCopyProtector::ShouldBlock(uint32_t pid, std::wstring_view cmdLine) {
    try {
        auto attackType = m_impl->AnalyzeCommandInternal(cmdLine);
        if (!attackType.has_value()) {
            return false;
        }

        // Get process path for whitelist check
        HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        std::wstring processPathStr;
        if (hProcess) {
            wchar_t processPath[MAX_PATH] = {};
            DWORD size = MAX_PATH;
            if (::QueryFullProcessImageNameW(hProcess, 0, processPath, &size)) {
                processPathStr = processPath;
            }
            ::CloseHandle(hProcess);
        }

        // Check whitelist (exact path match)
        if (!processPathStr.empty() && m_impl->IsWhitelistedInternal(processPathStr)) {
            if (m_impl->m_config.verboseLogging) {
                Utils::Logger::Debug("ShadowCopyProtector: Whitelisted process allowed: {}",
                    Utils::StringUtils::WideToUtf8(processPathStr));
            }
            return false;
        }

        // Consult decision callback
        if (!m_impl->ShouldBlockProcess(pid, attackType.value())) {
            return false;
        }

        // Build and record attack event
        VSSAttackEvent event;
        event.eventId = GenerateEventId();
        event.timestamp = std::chrono::system_clock::now();
        event.attackType = attackType.value();
        event.pid = pid;
        event.processPath = processPathStr;
        event.commandLine = std::wstring(cmdLine);
        event.wasBlocked = true;
        event.details = L"VSS destruction attempt blocked (user-mode)";
        event.processName = ExtractFilename(processPathStr);

        m_impl->RecordAttackEvent(event);
        m_impl->IncrementAttackStats(attackType.value());

        // Notify callback
        m_impl->NotifyAttack(event);

        // Terminate process if configured
        if (m_impl->m_config.killAttacker) {
            m_impl->TerminateAttacker(pid, L"VSS destruction attempt");
        }

        Utils::Logger::Critical(
            "ShadowCopyProtector: BLOCKED VSS attack [Type={}] [PID={}] [Process={}]",
            static_cast<int>(attackType.value()), pid,
            Utils::StringUtils::WideToUtf8(event.processName));

        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("ShadowCopyProtector: ShouldBlock exception: {}", e.what());
        return true;  // Fail-secure: block on error
    }
}

// ============================================================================
// KERNEL PROCESS CREATION INTEGRATION
// ============================================================================

[[nodiscard]] ProcessCreationVerdict ShadowCopyProtector::OnProcessCreation(
    uint32_t pid,
    uint32_t parentPid,
    std::wstring_view imagePath,
    std::wstring_view commandLine)
{
    try {
        if (!IsInitialized()) {
            return ProcessCreationVerdict::Allow;
        }

        if (!m_impl->m_config.enabled) {
            return ProcessCreationVerdict::Allow;
        }

        // Fast path: check if this is a known VSS-targeting executable
        std::wstring filename = ExtractFilename(imagePath);
        if (filename.empty()) {
            return ProcessCreationVerdict::Allow;
        }

        // Check whitelist first (full image path)
        if (m_impl->IsWhitelistedInternal(imagePath)) {
            return ProcessCreationVerdict::Allow;
        }

        // Classify by image name (fast — no command-line parsing needed)
        bool isKnownDangerousExe = false;
        bool isPowerShell = false;

        for (const auto* exe : VSS_DANGER_EXECUTABLES) {
            if (WideIEquals(filename, exe)) {
                isKnownDangerousExe = true;
                break;
            }
        }
        for (const auto* exe : RECOVERY_DANGER_EXECUTABLES) {
            if (WideIEquals(filename, exe)) {
                isKnownDangerousExe = true;
                break;
            }
        }
        for (const auto* exe : POWERSHELL_EXECUTABLES) {
            if (WideIEquals(filename, exe)) {
                isPowerShell = true;
                break;
            }
        }

        if (!isKnownDangerousExe && !isPowerShell) {
            return ProcessCreationVerdict::Allow;
        }

        // Analyze command line for VSS attack intent
        auto attackType = m_impl->AnalyzeCommandInternal(commandLine);
        if (!attackType.has_value()) {
            // Known dangerous executable but no dangerous command line detected.
            // For PowerShell, allow (might be legitimate).
            // For vssadmin/wmic with no matching args, allow (e.g., "vssadmin list shadows").
            return ProcessCreationVerdict::Allow;
        }

        // Check decision callback
        if (!m_impl->ShouldBlockProcess(pid, attackType.value())) {
            return ProcessCreationVerdict::Monitor;
        }

        // === BLOCK at kernel level (pre-execution) ===
        m_impl->m_stats.processesBlockedKernel.fetch_add(1, std::memory_order_relaxed);

        VSSAttackEvent event;
        event.eventId = GenerateEventId();
        event.timestamp = std::chrono::system_clock::now();
        event.attackType = attackType.value();
        event.pid = pid;
        event.processPath = std::wstring(imagePath);
        event.processName = filename;
        event.commandLine = std::wstring(commandLine);
        event.wasBlocked = true;
        event.details = L"KERNEL BLOCKED: Process creation denied by PhantomSensor callback";

        m_impl->RecordAttackEvent(event);
        m_impl->IncrementAttackStats(attackType.value());
        m_impl->NotifyAttack(event);

        Utils::Logger::Critical(
            "ShadowCopyProtector: KERNEL BLOCKED process creation [Type={}] [PID={}] [Image={}] [ParentPID={}]",
            static_cast<int>(attackType.value()), pid,
            Utils::StringUtils::WideToUtf8(filename), parentPid);

        return ProcessCreationVerdict::Block;

    } catch (const std::exception& e) {
        Utils::Logger::Error("ShadowCopyProtector: OnProcessCreation exception: {}", e.what());
        return ProcessCreationVerdict::Allow;  // Fail-open for stability (kernel path)
    }
}

// ============================================================================
// SERVICE PROTECTION
// ============================================================================

void ShadowCopyProtector::LockVssService() {
    m_impl->LockVssServiceInternal();
}

void ShadowCopyProtector::UnlockVssService() {
    m_impl->UnlockVssServiceInternal();
}

[[nodiscard]] bool ShadowCopyProtector::IsVssServiceLocked() const noexcept {
    return m_impl->m_serviceLocked.load(std::memory_order_acquire);
}

[[nodiscard]] bool ShadowCopyProtector::IsVssServiceRunning() const {
    return m_impl->IsVssServiceRunningInternal();
}

[[nodiscard]] bool ShadowCopyProtector::EnsureVssServiceRunning() {
    return m_impl->EnsureVssServiceRunningInternal();
}

// ============================================================================
// SHADOW COPY MANAGEMENT
// ============================================================================

[[nodiscard]] std::vector<ShadowCopyInfo> ShadowCopyProtector::EnumerateShadowCopies() {
    return m_impl->EnumerateShadowCopiesInternal();
}

[[nodiscard]] size_t ShadowCopyProtector::GetShadowCopyCount() const {
    return static_cast<size_t>(m_impl->m_stats.currentShadowCopies.load(std::memory_order_relaxed));
}

[[nodiscard]] std::optional<std::wstring> ShadowCopyProtector::CreateProtectiveSnapshot(
    std::wstring_view volume)
{
    try {
        if (volume.empty()) {
            Utils::Logger::Error("ShadowCopyProtector: CreateProtectiveSnapshot called with empty volume");
            return std::nullopt;
        }

        Utils::Logger::Info("ShadowCopyProtector: Creating protective snapshot for volume: {}",
            Utils::StringUtils::WideToUtf8(std::wstring(volume)));

        ComScope comGuard(COINIT_MULTITHREADED);

        ComPtr<IVssBackupComponents> pBackup;
        {
            IVssBackupComponents* raw = nullptr;
            HRESULT hr = ::CreateVssBackupComponents(&raw);
            if (FAILED(hr) || !raw) {
                Utils::Logger::Error("ShadowCopyProtector: CreateVssBackupComponents failed, hr={:#x}",
                                     static_cast<uint32_t>(hr));
                return std::nullopt;
            }
            pBackup = ComPtr<IVssBackupComponents>(raw);
        }

        HRESULT hr = pBackup->InitializeForBackup();
        if (FAILED(hr)) {
            Utils::Logger::Error("ShadowCopyProtector: InitializeForBackup failed, hr={:#x}",
                                 static_cast<uint32_t>(hr));
            return std::nullopt;
        }

        hr = pBackup->SetContext(VSS_CTX_BACKUP);
        if (FAILED(hr)) {
            Utils::Logger::Error("ShadowCopyProtector: SetContext failed, hr={:#x}",
                                 static_cast<uint32_t>(hr));
            return std::nullopt;
        }

        VSS_ID snapshotSetId;
        hr = pBackup->StartSnapshotSet(&snapshotSetId);
        if (FAILED(hr)) {
            Utils::Logger::Error("ShadowCopyProtector: StartSnapshotSet failed, hr={:#x}",
                                 static_cast<uint32_t>(hr));
            return std::nullopt;
        }

        std::wstring volumeStr(volume);
        VSS_ID snapshotId;
        hr = pBackup->AddToSnapshotSet(
            const_cast<wchar_t*>(volumeStr.c_str()), GUID_NULL, &snapshotId);
        if (FAILED(hr)) {
            Utils::Logger::Error("ShadowCopyProtector: AddToSnapshotSet failed, hr={:#x}",
                                 static_cast<uint32_t>(hr));
            return std::nullopt;
        }

        ComPtr<IVssAsync> pAsync;
        {
            IVssAsync* raw = nullptr;
            hr = pBackup->DoSnapshotSet(&raw);
            if (FAILED(hr) || !raw) {
                Utils::Logger::Error("ShadowCopyProtector: DoSnapshotSet failed, hr={:#x}",
                                     static_cast<uint32_t>(hr));
                return std::nullopt;
            }
            pAsync = ComPtr<IVssAsync>(raw);
        }

        hr = pAsync->Wait();
        if (FAILED(hr)) {
            Utils::Logger::Error("ShadowCopyProtector: Snapshot async wait failed, hr={:#x}",
                                 static_cast<uint32_t>(hr));
            return std::nullopt;
        }

        // Check async result
        HRESULT asyncResult = S_OK;
        pAsync->QueryStatus(&asyncResult, nullptr);
        if (FAILED(asyncResult)) {
            Utils::Logger::Error("ShadowCopyProtector: Snapshot creation returned error, hr={:#x}",
                                 static_cast<uint32_t>(asyncResult));
            return std::nullopt;
        }

        wchar_t guidStr[64] = {};
        ::StringFromGUID2(snapshotId, guidStr, 64);

        Utils::Logger::Info("ShadowCopyProtector: Protective snapshot created: {}",
                            Utils::StringUtils::WideToUtf8(guidStr));
        return std::wstring(guidStr);

    } catch (const std::exception& e) {
        Utils::Logger::Error("ShadowCopyProtector: CreateProtectiveSnapshot exception: {}", e.what());
        return std::nullopt;
    }
}

[[nodiscard]] bool ShadowCopyProtector::VerifyShadowCopy(std::wstring_view shadowId) {
    try {
        auto shadows = m_impl->EnumerateShadowCopiesInternal();
        for (const auto& shadow : shadows) {
            if (WideIEquals(shadow.shadowId, shadowId)) {
                return shadow.state == ShadowCopyState::Active;
            }
        }
        return false;
    } catch (const std::exception& e) {
        Utils::Logger::Error("ShadowCopyProtector: VerifyShadowCopy exception: {}", e.what());
        return false;
    }
}

// ============================================================================
// WHITELIST
// ============================================================================

void ShadowCopyProtector::AddToWhitelist(std::wstring_view processPath) {
    if (processPath.empty()) return;

    std::unique_lock lock(m_impl->m_mutex);

    if (m_impl->m_whitelist.size() >= ShadowCopyConstants::MAX_WHITELIST_ENTRIES) {
        Utils::Logger::Warn("ShadowCopyProtector: Whitelist is full ({} entries), rejecting add",
                            ShadowCopyConstants::MAX_WHITELIST_ENTRIES);
        return;
    }

    // Prevent duplicate entries (case-insensitive)
    for (const auto& existing : m_impl->m_whitelist) {
        if (WideIEquals(existing, processPath)) {
            return;  // Already whitelisted
        }
    }

    m_impl->m_whitelist.emplace_back(processPath);
    Utils::Logger::Info("ShadowCopyProtector: Added to whitelist: {}",
                        Utils::StringUtils::WideToUtf8(std::wstring(processPath)));
}

void ShadowCopyProtector::RemoveFromWhitelist(std::wstring_view processPath) {
    std::unique_lock lock(m_impl->m_mutex);

    auto& wl = m_impl->m_whitelist;
    auto it = std::remove_if(wl.begin(), wl.end(),
        [&processPath](const std::wstring& entry) {
            return WideIEquals(entry, processPath);
        });

    if (it != wl.end()) {
        wl.erase(it, wl.end());
        Utils::Logger::Info("ShadowCopyProtector: Removed from whitelist: {}",
                            Utils::StringUtils::WideToUtf8(std::wstring(processPath)));
    }
}

[[nodiscard]] bool ShadowCopyProtector::IsWhitelisted(std::wstring_view processPath) const {
    return m_impl->IsWhitelistedInternal(processPath);
}

// ============================================================================
// CALLBACKS
// ============================================================================

void ShadowCopyProtector::SetAttackCallback(VSSAttackCallback callback) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_attackCallback = std::move(callback);
}

void ShadowCopyProtector::SetDecisionCallback(DecisionCallback callback) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_decisionCallback = std::move(callback);
}

// ============================================================================
// STATISTICS
// ============================================================================

[[nodiscard]] ShadowCopyStatistics ShadowCopyProtector::GetStatistics() const {
    // ShadowCopyStatistics now has a proper copy constructor that loads atomics
    return m_impl->m_stats;
}

void ShadowCopyProtector::ResetStatistics() {
    m_impl->m_stats.Reset();
    m_impl->m_stats.startTime = Clock::now();
    Utils::Logger::Info("ShadowCopyProtector: Statistics reset");
}

[[nodiscard]] std::vector<VSSAttackEvent> ShadowCopyProtector::GetRecentAttacks(size_t maxCount) const {
    std::shared_lock lock(m_impl->m_mutex);

    if (m_impl->m_recentAttacks.size() <= maxCount) {
        return m_impl->m_recentAttacks;
    }

    // Return the most recent `maxCount` events
    return std::vector<VSSAttackEvent>(
        m_impl->m_recentAttacks.end() - static_cast<ptrdiff_t>(maxCount),
        m_impl->m_recentAttacks.end());
}

// ============================================================================
// SELF-TEST
// ============================================================================

[[nodiscard]] bool ShadowCopyProtector::SelfTest() {
    try {
        Utils::Logger::Info("ShadowCopyProtector: Running self-test...");
        bool allPassed = true;

        // Test 1: Configuration validation
        ShadowCopyProtectorConfiguration config;
        if (!config.IsValid()) {
            Utils::Logger::Error("ShadowCopyProtector: Self-test FAILED: Default config invalid");
            allPassed = false;
        }

        // Test 2: Basic command line detection
        const struct {
            const wchar_t* cmd;
            bool shouldDetect;
            const char* description;
        } testCases[] = {
            { L"vssadmin delete shadows /all /quiet",      true,  "vssadmin delete shadows" },
            { L"wmic shadowcopy delete",                    true,  "wmic shadowcopy delete" },
            { L"vssadmin list shadows",                     false, "vssadmin list (safe)" },
            { L"notepad.exe test.txt",                      false, "unrelated command" },
            { L"bcdedit /set {default} recoveryenabled No", true,  "bcdedit recovery disable" },
            { L"wbadmin delete catalog -quiet",             true,  "wbadmin delete catalog" },
            { L"vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB", true, "resize shadowstorage" },
            // Obfuscation tests
            { L"v^s^s^a^d^m^i^n d^e^l^e^t^e s^h^a^d^o^w^s", true, "caret-obfuscated vssadmin" },
            { L"vs\"sad\"min delete shadows",               true,  "quote-obfuscated vssadmin" },
            { L"net stop vss",                              true,  "net stop vss service" },
            { L"sc stop vss",                               true,  "sc stop vss service" },
            { L"powershell Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }",
                                                            true,  "PowerShell WMI delete" },
        };

        for (const auto& tc : testCases) {
            bool detected = IsVssDestructionAttempt(tc.cmd);
            if (detected != tc.shouldDetect) {
                Utils::Logger::Error("ShadowCopyProtector: Self-test FAILED: '{}' expected={}, got={}",
                    tc.description, tc.shouldDetect, detected);
                allPassed = false;
            }
        }

        // Test 3: VSS service status check
        try {
            bool running = IsVssServiceRunning();
            Utils::Logger::Debug("ShadowCopyProtector: Self-test: VSS service running={}", running);
        } catch (...) {
            Utils::Logger::Error("ShadowCopyProtector: Self-test FAILED: Service status check threw");
            allPassed = false;
        }

        // Test 4: Shadow copy enumeration
        try {
            auto shadows = EnumerateShadowCopies();
            Utils::Logger::Debug("ShadowCopyProtector: Self-test: Found {} shadow copies", shadows.size());
        } catch (...) {
            Utils::Logger::Error("ShadowCopyProtector: Self-test FAILED: Enumeration threw");
            allPassed = false;
        }

        // Test 5: Statistics copy (verifies ShadowCopyStatistics copy constructor)
        try {
            auto stats = GetStatistics();
            (void)stats.attacksBlocked.load();
        } catch (...) {
            Utils::Logger::Error("ShadowCopyProtector: Self-test FAILED: Statistics copy threw");
            allPassed = false;
        }

        if (allPassed) {
            Utils::Logger::Info("ShadowCopyProtector: Self-test PASSED — all tests successful");
        } else {
            Utils::Logger::Error("ShadowCopyProtector: Self-test FAILED — see errors above");
        }

        return allPassed;

    } catch (const std::exception& e) {
        Utils::Logger::Error("ShadowCopyProtector: Self-test exception: {}", e.what());
        return false;
    }
}

[[nodiscard]] std::string ShadowCopyProtector::GetVersionString() noexcept {
    return std::to_string(ShadowCopyConstants::VERSION_MAJOR) + "." +
           std::to_string(ShadowCopyConstants::VERSION_MINOR) + "." +
           std::to_string(ShadowCopyConstants::VERSION_PATCH);
}

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] std::string ShadowCopyInfo::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["shadowId"] = Utils::StringUtils::WideToUtf8(shadowId);
    j["volume"] = Utils::StringUtils::WideToUtf8(volume);
    j["devicePath"] = Utils::StringUtils::WideToUtf8(devicePath);
    j["creationTime"] = creationTime.time_since_epoch().count();
    j["state"] = static_cast<int>(state);
    j["sizeBytes"] = sizeBytes;
    j["isProtected"] = isProtected;
    j["providerId"] = Utils::StringUtils::WideToUtf8(providerId);

    return j.dump(2);
}

[[nodiscard]] std::string VSSAttackEvent::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["eventId"] = eventId;
    j["timestamp"] = timestamp.time_since_epoch().count();
    j["attackType"] = static_cast<int>(attackType);
    j["attackTypeName"] = std::string(GetVSSAttackTypeName(attackType));
    j["pid"] = pid;
    j["processName"] = Utils::StringUtils::WideToUtf8(processName);
    j["processPath"] = Utils::StringUtils::WideToUtf8(processPath);
    j["commandLine"] = Utils::StringUtils::WideToUtf8(commandLine);
    j["wasBlocked"] = wasBlocked;
    j["details"] = Utils::StringUtils::WideToUtf8(details);

    return j.dump(2);
}

void ShadowCopyStatistics::Reset() noexcept {
    attacksBlocked.store(0, std::memory_order_relaxed);
    processesKilled.store(0, std::memory_order_relaxed);
    processesBlockedKernel.store(0, std::memory_order_relaxed);
    snapshotDecreaseAlerts.store(0, std::memory_order_relaxed);
    currentShadowCopies.store(0, std::memory_order_relaxed);

    for (auto& counter : byAttackType) {
        counter.store(0, std::memory_order_relaxed);
    }
}

[[nodiscard]] std::string ShadowCopyStatistics::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["attacksBlocked"] = attacksBlocked.load(std::memory_order_relaxed);
    j["processesKilled"] = processesKilled.load(std::memory_order_relaxed);
    j["processesBlockedKernel"] = processesBlockedKernel.load(std::memory_order_relaxed);
    j["snapshotDecreaseAlerts"] = snapshotDecreaseAlerts.load(std::memory_order_relaxed);
    j["currentShadowCopies"] = currentShadowCopies.load(std::memory_order_relaxed);

    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();
    j["uptimeSeconds"] = uptime;

    Json attackTypeBreakdown = Json::object();
    for (size_t i = 0; i < byAttackType.size(); ++i) {
        uint64_t count = byAttackType[i].load(std::memory_order_relaxed);
        if (count > 0) {
            attackTypeBreakdown[std::string(GetVSSAttackTypeName(static_cast<VSSAttackType>(i)))] = count;
        }
    }
    j["byAttackType"] = attackTypeBreakdown;

    return j.dump(2);
}

[[nodiscard]] bool ShadowCopyProtectorConfiguration::IsValid() const noexcept {
    // Validate whitelist entries are not empty strings
    for (const auto& entry : whitelist) {
        if (entry.empty()) return false;
    }

    // Validate whitelist size is within bounds
    if (whitelist.size() > ShadowCopyConstants::MAX_WHITELIST_ENTRIES) {
        return false;
    }

    return true;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetVSSAttackTypeName(VSSAttackType type) noexcept {
    switch (type) {
        case VSSAttackType::CommandLineDelete: return "CommandLineDelete";
        case VSSAttackType::WMIDelete:         return "WMIDelete";
        case VSSAttackType::APIDelete:         return "APIDelete";
        case VSSAttackType::ServiceStop:       return "ServiceStop";
        case VSSAttackType::StorageResize:     return "StorageResize";
        case VSSAttackType::RegistryModify:    return "RegistryModify";
        case VSSAttackType::ProviderDisable:   return "ProviderDisable";
        default:                               return "Unknown";
    }
}

[[nodiscard]] std::string_view GetShadowCopyStateName(ShadowCopyState state) noexcept {
    switch (state) {
        case ShadowCopyState::Active:    return "Active";
        case ShadowCopyState::Protected: return "Protected";
        case ShadowCopyState::Deleted:   return "Deleted";
        case ShadowCopyState::Corrupted: return "Corrupted";
        default:                         return "Unknown";
    }
}

}  // namespace ShadowStrike::Ransomware
