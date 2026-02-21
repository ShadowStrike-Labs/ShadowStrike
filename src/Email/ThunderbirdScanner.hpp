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
 * ShadowStrike NGAV - THUNDERBIRD SCANNER MODULE
 * ============================================================================
 *
 * @file ThunderbirdScanner.hpp
 * @brief Enterprise-grade Mozilla Thunderbird integration for email security.
 *        Provides native messaging, mailbox monitoring, and extension integration.
 *
 * Provides comprehensive Thunderbird integration including mailbox file monitoring,
 * native messaging host communication, and WebExtension integration.
 *
 * INTEGRATION METHODS:
 * ====================
 *
 * 1. NATIVE MESSAGING HOST
 *    - WebExtension native messaging
 *    - JSON-based protocol
 *    - Bi-directional communication
 *    - Real-time scanning requests
 *    - Status updates
 *
 * 2. MAILBOX FILE MONITORING
 *    - Mbox format parsing
 *    - Maildir format support
 *    - Directory change notification
 *    - New message detection
 *    - Incremental scanning
 *
 * 3. PROFILE MONITORING
 *    - Profile discovery
 *    - Account enumeration
 *    - Folder structure mapping
 *    - Local folder watching
 *    - IMAP cache monitoring
 *
 * 4. SECURITY FEATURES
 *    - Attachment scanning
 *    - Link protection
 *    - Phishing detection
 *    - Malware detection
 *    - Spam filtering
 *
 * SUPPORTED VERSIONS:
 * ===================
 * - Mozilla Thunderbird 78+
 * - Mozilla Thunderbird ESR
 * - Thunderbird Beta
 *
 * INTEGRATION:
 * ============
 * - EmailProtection orchestrator
 * - AttachmentScanner for files
 * - PhishingEmailDetector for content
 * - SpamDetector for filtering
 *
 * @note Uses native messaging for real-time communication.
 * @note Thread-safe singleton design.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <map>
#include <unordered_map>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <filesystem>
#include <thread>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Email {
    class ThunderbirdScannerImpl;
    struct EmailMessage;
    struct EmailScanResult;
}

namespace ShadowStrike {
namespace Email {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace ThunderbirdConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Native messaging host name
    inline constexpr const char* NATIVE_HOST_NAME = "com.shadowstrike.thunderbird";
    
    /// @brief WebExtension ID
    inline constexpr const char* EXTENSION_ID = "shadowstrike@security.com";
    
    /// @brief Default Thunderbird profile folder name
    inline constexpr const char* PROFILE_FOLDER_NAME = "Thunderbird";
    
    /// @brief Minimum supported version
    inline constexpr uint32_t MIN_THUNDERBIRD_VERSION = 78;
    
    /// @brief File change debounce time
    inline constexpr uint32_t FILE_CHANGE_DEBOUNCE_MS = 500;
    
    /// @brief Maximum message size
    inline constexpr size_t MAX_MESSAGE_SIZE = 50 * 1024 * 1024;  // 50MB

    /// @brief Mbox file extensions
    inline constexpr const char* MBOX_EXTENSIONS[] = {
        "", ".msf", ".mbox"
    };

    /// @brief Profile locations (relative to user profile)
    inline constexpr const char* PROFILE_PATHS_WINDOWS[] = {
        "\\AppData\\Roaming\\Thunderbird\\Profiles",
        "\\AppData\\Local\\Thunderbird\\Profiles"
    };

}  // namespace ThunderbirdConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
namespace fs = std::filesystem;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Scanner status
 */
enum class ScannerStatus : uint8_t {
    Disconnected    = 0,
    Connecting      = 1,
    Connected       = 2,
    Monitoring      = 3,
    Scanning        = 4,
    Paused          = 5,
    Error           = 6
};

/**
 * @brief Mailbox format
 */
enum class MailboxFormat : uint8_t {
    Unknown     = 0,
    Mbox        = 1,    ///< Traditional mbox format
    Maildir     = 2,    ///< Maildir format (separate files)
    MboxRd      = 3,    ///< mboxrd variant
    MboxO       = 4     ///< mboxo variant
};

/**
 * @brief Account type
 */
enum class AccountType : uint8_t {
    Unknown     = 0,
    POP3        = 1,
    IMAP        = 2,
    Local       = 3,
    NNTP        = 4,
    RSS         = 5
};

/**
 * @brief Message event
 */
enum class MessageEvent : uint8_t {
    NewMessage      = 0,
    MessageChanged  = 1,
    MessageDeleted  = 2,
    MessageMoved    = 3,
    FolderScanned   = 4
};

/**
 * @brief Scan action
 */
enum class ThunderbirdScanAction : uint8_t {
    Allow           = 0,
    Block           = 1,
    Quarantine      = 2,
    Delete          = 3,
    MarkSpam        = 4,
    MarkRead        = 5,
    MoveTo          = 6,
    Tag             = 7,
    Notify          = 8
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Scanning        = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Thunderbird version info
 */
struct ThunderbirdVersionInfo {
    /// @brief Major version
    uint32_t majorVersion = 0;
    
    /// @brief Minor version
    uint32_t minorVersion = 0;
    
    /// @brief Patch version
    uint32_t patchVersion = 0;
    
    /// @brief Version string
    std::string versionString;
    
    /// @brief Is ESR (Extended Support Release)
    bool isESR = false;
    
    /// @brief Is beta
    bool isBeta = false;
    
    /// @brief Installation path
    fs::path installPath;
    
    [[nodiscard]] std::string ToString() const;
};

/**
 * @brief Thunderbird profile
 */
struct ThunderbirdProfile {
    /// @brief Profile name
    std::string name;
    
    /// @brief Profile path
    fs::path path;
    
    /// @brief Is default profile
    bool isDefault = false;
    
    /// @brief Is locked (in use)
    bool isLocked = false;
    
    /// @brief Account count
    size_t accountCount = 0;
    
    /// @brief Last used
    SystemTimePoint lastUsed;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Thunderbird account
 */
struct ThunderbirdAccount {
    /// @brief Account ID
    std::string accountId;
    
    /// @brief Account name
    std::string name;
    
    /// @brief Email address
    std::string email;
    
    /// @brief Server host
    std::string serverHost;
    
    /// @brief Account type
    AccountType type = AccountType::Unknown;
    
    /// @brief Root folder path
    fs::path rootFolderPath;
    
    /// @brief Is enabled
    bool isEnabled = true;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Mailbox folder
 */
struct MailboxFolder {
    /// @brief Folder name
    std::string name;
    
    /// @brief Full path
    fs::path path;
    
    /// @brief Parent account ID
    std::string accountId;
    
    /// @brief Format
    MailboxFormat format = MailboxFormat::Unknown;
    
    /// @brief Message count (estimated)
    size_t messageCount = 0;
    
    /// @brief Unread count
    size_t unreadCount = 0;
    
    /// @brief File size
    size_t fileSize = 0;
    
    /// @brief Last modified
    SystemTimePoint lastModified;
    
    /// @brief Is monitored
    bool isMonitored = false;
    
    /// @brief Is special folder (Inbox, Sent, etc.)
    bool isSpecial = false;
    
    /// @brief Special type name
    std::string specialType;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Parsed mbox message
 */
struct MboxMessage {
    /// @brief Message offset in file
    size_t fileOffset = 0;
    
    /// @brief Message size
    size_t messageSize = 0;
    
    /// @brief Message-ID header
    std::string messageId;
    
    /// @brief Subject
    std::string subject;
    
    /// @brief From
    std::string from;
    
    /// @brief To
    std::vector<std::string> to;
    
    /// @brief Date
    std::string date;
    
    /// @brief All headers
    std::map<std::string, std::string> headers;
    
    /// @brief Body text
    std::string bodyText;
    
    /// @brief Body HTML
    std::string bodyHtml;
    
    /// @brief Attachment count
    size_t attachmentCount = 0;
    
    /// @brief Is read
    bool isRead = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Native messaging request
 */
struct NativeMessageRequest {
    /// @brief Request ID
    std::string requestId;
    
    /// @brief Action
    std::string action;
    
    /// @brief Parameters
    std::map<std::string, std::string> params;
    
    /// @brief Message data (if any)
    std::optional<MboxMessage> message;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Native messaging response
 */
struct NativeMessageResponse {
    /// @brief Request ID
    std::string requestId;
    
    /// @brief Success
    bool success = true;
    
    /// @brief Error message
    std::string errorMessage;
    
    /// @brief Scan result (if scan request)
    std::optional<EmailScanResult> scanResult;
    
    /// @brief Action to take
    ThunderbirdScanAction action = ThunderbirdScanAction::Allow;
    
    /// @brief Additional data
    std::map<std::string, std::string> data;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Scan event
 */
struct ThunderbirdScanEvent {
    /// @brief Event ID
    std::string eventId;
    
    /// @brief Event type
    MessageEvent eventType = MessageEvent::NewMessage;
    
    /// @brief Folder
    MailboxFolder folder;
    
    /// @brief Message
    MboxMessage message;
    
    /// @brief Scan result
    std::optional<EmailScanResult> scanResult;
    
    /// @brief Action taken
    ThunderbirdScanAction actionTaken = ThunderbirdScanAction::Allow;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct ThunderbirdScannerStatistics {
    std::atomic<uint64_t> totalScanned{0};
    std::atomic<uint64_t> newMessagesScanned{0};
    std::atomic<uint64_t> foldersMonitored{0};
    std::atomic<uint64_t> threatsDetected{0};
    std::atomic<uint64_t> malwareBlocked{0};
    std::atomic<uint64_t> phishingBlocked{0};
    std::atomic<uint64_t> spamMarked{0};
    std::atomic<uint64_t> nativeMessagesReceived{0};
    std::atomic<uint64_t> nativeMessagesProcessed{0};
    std::atomic<uint64_t> fileChangesDetected{0};
    std::atomic<uint64_t> parseErrors{0};
    std::atomic<uint64_t> scanErrors{0};
    std::array<std::atomic<uint64_t>, 8> byEventType{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct ThunderbirdScannerConfiguration {
    /// @brief Enable scanner
    bool enabled = true;
    
    /// @brief Enable native messaging
    bool enableNativeMessaging = true;
    
    /// @brief Enable file monitoring
    bool enableFileMonitoring = true;
    
    /// @brief Scan new messages
    bool scanNewMessages = true;
    
    /// @brief Scan attachments
    bool scanAttachments = true;
    
    /// @brief Scan links
    bool scanLinks = true;
    
    /// @brief Detect phishing
    bool detectPhishing = true;
    
    /// @brief Detect spam
    bool detectSpam = true;
    
    /// @brief Auto-register native host
    bool autoRegisterNativeHost = true;
    
    /// @brief Profile paths to monitor
    std::vector<fs::path> profilePaths;
    
    /// @brief Excluded folders
    std::vector<std::string> excludedFolders;
    
    /// @brief Trusted senders
    std::vector<std::string> trustedSenders;
    
    /// @brief File change debounce
    uint32_t fileChangeDebounceMs = ThunderbirdConstants::FILE_CHANGE_DEBOUNCE_MS;
    
    /// @brief Maximum message size
    size_t maxMessageSize = ThunderbirdConstants::MAX_MESSAGE_SIZE;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using MessageEventCallback = std::function<void(const ThunderbirdScanEvent&)>;
using ScanResultCallback = std::function<void(const MboxMessage&, const EmailScanResult&)>;
using NativeMessageCallback = std::function<NativeMessageResponse(const NativeMessageRequest&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// THUNDERBIRD SCANNER CLASS
// ============================================================================

/**
 * @class ThunderbirdScanner
 * @brief Enterprise Thunderbird integration scanner
 */
class ThunderbirdScanner final {
public:
    [[nodiscard]] static ThunderbirdScanner& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    ThunderbirdScanner(const ThunderbirdScanner&) = delete;
    ThunderbirdScanner& operator=(const ThunderbirdScanner&) = delete;
    ThunderbirdScanner(ThunderbirdScanner&&) = delete;
    ThunderbirdScanner& operator=(ThunderbirdScanner&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const ThunderbirdScannerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    [[nodiscard]] ScannerStatus GetScannerStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const ThunderbirdScannerConfiguration& config);
    [[nodiscard]] ThunderbirdScannerConfiguration GetConfiguration() const;

    // ========================================================================
    // MONITORING
    // ========================================================================
    
    /// @brief Start monitoring profile
    [[nodiscard]] bool StartMonitoring(const fs::path& profilePath);
    
    /// @brief Stop monitoring
    void StopMonitoring();
    
    /// @brief Is monitoring active
    [[nodiscard]] bool IsMonitoring() const noexcept;
    
    /// @brief Add folder to monitor
    [[nodiscard]] bool AddMonitoredFolder(const fs::path& folderPath);
    
    /// @brief Remove folder from monitoring
    [[nodiscard]] bool RemoveMonitoredFolder(const fs::path& folderPath);
    
    /// @brief Get monitored folders
    [[nodiscard]] std::vector<MailboxFolder> GetMonitoredFolders() const;

    // ========================================================================
    // NATIVE MESSAGING
    // ========================================================================
    
    /// @brief Start native messaging host
    [[nodiscard]] bool StartNativeMessagingHost();
    
    /// @brief Stop native messaging host
    void StopNativeMessagingHost();
    
    /// @brief Is native host running
    [[nodiscard]] bool IsNativeHostRunning() const noexcept;
    
    /// @brief Register native messaging host in registry
    [[nodiscard]] bool RegisterNativeHost();
    
    /// @brief Unregister native messaging host
    [[nodiscard]] bool UnregisterNativeHost();
    
    /// @brief Process native message
    [[nodiscard]] NativeMessageResponse ProcessNativeMessage(
        const NativeMessageRequest& request);

    // ========================================================================
    // PROFILE/ACCOUNT DISCOVERY
    // ========================================================================
    
    /// @brief Discover Thunderbird installations
    [[nodiscard]] std::vector<ThunderbirdVersionInfo> DiscoverInstallations();
    
    /// @brief Discover profiles
    [[nodiscard]] std::vector<ThunderbirdProfile> DiscoverProfiles();
    
    /// @brief Get accounts from profile
    [[nodiscard]] std::vector<ThunderbirdAccount> GetAccounts(
        const fs::path& profilePath);
    
    /// @brief Get folders for account
    [[nodiscard]] std::vector<MailboxFolder> GetFolders(
        const fs::path& accountPath);

    // ========================================================================
    // SCANNING
    // ========================================================================
    
    /// @brief Scan mbox file
    [[nodiscard]] std::vector<EmailScanResult> ScanMboxFile(
        const fs::path& mboxPath,
        bool fullScan = false);
    
    /// @brief Scan single message
    [[nodiscard]] EmailScanResult ScanMessage(const MboxMessage& message);
    
    /// @brief Parse mbox file
    [[nodiscard]] std::vector<MboxMessage> ParseMboxFile(
        const fs::path& mboxPath,
        size_t maxMessages = 0);
    
    /// @brief Parse single message from mbox
    [[nodiscard]] std::optional<MboxMessage> ParseMboxMessage(
        const fs::path& mboxPath,
        size_t offset);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterMessageEventCallback(MessageEventCallback callback);
    void RegisterScanCallback(ScanResultCallback callback);
    void RegisterNativeMessageCallback(NativeMessageCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] ThunderbirdScannerStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    ThunderbirdScanner();
    ~ThunderbirdScanner();
    
    std::unique_ptr<ThunderbirdScannerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetScannerStatusName(ScannerStatus status) noexcept;
[[nodiscard]] std::string_view GetMailboxFormatName(MailboxFormat format) noexcept;
[[nodiscard]] std::string_view GetAccountTypeName(AccountType type) noexcept;
[[nodiscard]] std::string_view GetMessageEventName(MessageEvent event) noexcept;
[[nodiscard]] std::string_view GetThunderbirdScanActionName(ThunderbirdScanAction action) noexcept;

/// @brief Check if Thunderbird is running
[[nodiscard]] bool IsThunderbirdRunning();

/// @brief Get default profile path
[[nodiscard]] std::optional<fs::path> GetDefaultProfilePath();

/// @brief Parse profiles.ini
[[nodiscard]] std::vector<ThunderbirdProfile> ParseProfilesIni(const fs::path& iniPath);

/// @brief Detect mailbox format
[[nodiscard]] MailboxFormat DetectMailboxFormat(const fs::path& path);

}  // namespace Email
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_THUNDERBIRD_START_MONITORING(profilePath) \
    ::ShadowStrike::Email::ThunderbirdScanner::Instance().StartMonitoring(profilePath)

#define SS_THUNDERBIRD_IS_MONITORING() \
    ::ShadowStrike::Email::ThunderbirdScanner::Instance().IsMonitoring()

#define SS_THUNDERBIRD_SCAN_MBOX(path) \
    ::ShadowStrike::Email::ThunderbirdScanner::Instance().ScanMboxFile(path)