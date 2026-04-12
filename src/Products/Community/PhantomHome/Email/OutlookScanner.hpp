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
 * ShadowStrike NGAV - OUTLOOK SCANNER MODULE
 * ============================================================================
 *
 * @file OutlookScanner.hpp
 * @brief Enterprise-grade Microsoft Outlook integration for email security.
 *        Provides MAPI/COM add-in capabilities for real-time email scanning.
 *
 * Provides comprehensive Outlook integration including mail item interception,
 * folder monitoring, attachment scanning, and security policy enforcement.
 *
 * INTEGRATION METHODS:
 * ====================
 *
 * 1. COM ADD-IN
 *    - IDTExtensibility2 implementation
 *    - Office Ribbon customization
 *    - Custom task panes
 *    - Event sink connection
 *    - Application-level events
 *
 * 2. MAPI INTEGRATION
 *    - Extended MAPI access
 *    - Message store provider
 *    - Transport provider hook
 *    - Notification sink
 *    - Property access
 *
 * 3. OBJECT MODEL EVENTS
 *    - ItemSend event (outbound)
 *    - NewMailEx event (inbound)
 *    - ItemAdd (folder monitoring)
 *    - BeforeDelete
 *    - Reply/ReplyAll/Forward
 *
 * 4. SECURITY FEATURES
 *    - Attachment blocking
 *    - Link protection
 *    - Safe sender verification
 *    - Phishing detection
 *    - Malware scanning
 *    - DLP enforcement
 *
 * SUPPORTED VERSIONS:
 * ===================
 * - Microsoft Outlook 2016
 * - Microsoft Outlook 2019
 * - Microsoft Outlook 365
 * - Microsoft Outlook LTSC
 *
 * INTEGRATION:
 * ============
 * - EmailProtection orchestrator
 * - AttachmentScanner for files
 * - PhishingEmailDetector for content
 * - ThreatIntel for URL/domain IOCs
 *
 * @note Requires COM interop.
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
#  include <ObjBase.h>
#  include <OleAuto.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/COMUtils.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

struct IDispatch;
struct IUnknown;

namespace ShadowStrike::Email {
    class OutlookScannerImpl;
    struct EmailMessage;
    struct EmailScanResult;
}

namespace ShadowStrike {
namespace Email {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace OutlookConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Add-in GUID
    inline constexpr const char* ADDIN_GUID = "{F89A3E4B-7C1D-4A8E-B2F6-9D5C1E3A7B4F}";
    
    /// @brief Add-in ProgID
    inline constexpr const char* ADDIN_PROGID = "ShadowStrike.OutlookAddin";
    
    /// @brief Add-in friendly name
    inline constexpr const char* ADDIN_NAME = "ShadowStrike Email Security";
    
    /// @brief Minimum supported Outlook version
    inline constexpr uint32_t MIN_OUTLOOK_VERSION = 16;  // Outlook 2016
    
    /// @brief Maximum attachment size to scan
    inline constexpr size_t MAX_ATTACHMENT_SIZE = 100 * 1024 * 1024;  // 100MB
    
    /// @brief Scan timeout
    inline constexpr uint32_t SCAN_TIMEOUT_MS = 30000;

    /// @brief Outlook item types
    inline constexpr int OL_MAIL_ITEM = 0;
    inline constexpr int OL_MEETING_ITEM = 26;
    inline constexpr int OL_TASK_REQUEST = 49;

}  // namespace OutlookConstants

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
 * @brief Add-in connection status
 */
enum class AddinStatus : uint8_t {
    Disconnected    = 0,
    Connecting      = 1,
    Connected       = 2,
    Initializing    = 3,
    Ready           = 4,
    Scanning        = 5,
    Error           = 6,
    Disabled        = 7
};

/**
 * @brief Mail event type
 */
enum class MailEventType : uint8_t {
    NewMail         = 0,    ///< New mail received
    ItemSend        = 1,    ///< Mail being sent
    ItemAdd         = 2,    ///< Item added to folder
    ItemChange      = 3,    ///< Item modified
    BeforeDelete    = 4,    ///< Before item deletion
    Reply           = 5,    ///< Reply action
    ReplyAll        = 6,    ///< Reply All action
    Forward         = 7,    ///< Forward action
    AttachmentAdd   = 8,    ///< Attachment being added
    Open            = 9     ///< Item opened
};

/**
 * @brief Scan action
 */
enum class OutlookScanAction : uint8_t {
    Allow           = 0,    ///< Allow the action
    Block           = 1,    ///< Block the action
    Quarantine      = 2,    ///< Move to quarantine
    Delete          = 3,    ///< Delete the item
    StripAttachment = 4,    ///< Remove attachment
    TagSubject      = 5,    ///< Add tag to subject
    Prompt          = 6,    ///< Prompt user
    Log             = 7     ///< Log only
};

/**
 * @brief Folder type
 */
enum class OutlookFolderType : uint8_t {
    Inbox           = 0,
    SentItems       = 1,
    Drafts          = 2,
    Outbox          = 3,
    DeletedItems    = 4,
    JunkEmail       = 5,
    Calendar        = 6,
    Contacts        = 7,
    Tasks           = 8,
    Notes           = 9,
    Custom          = 10
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
 * @brief Outlook version info
 */
struct OutlookVersionInfo {
    /// @brief Major version
    uint32_t majorVersion = 0;
    
    /// @brief Minor version
    uint32_t minorVersion = 0;
    
    /// @brief Build number
    uint32_t buildNumber = 0;
    
    /// @brief Product name
    std::string productName;
    
    /// @brief Is 64-bit
    bool is64Bit = false;
    
    /// @brief Is Office 365
    bool isOffice365 = false;
    
    /// @brief Is retail/volume license
    std::string licenseType;
    
    [[nodiscard]] std::string ToString() const;
};

/**
 * @brief Mail item info
 */
struct MailItemInfo {
    /// @brief Entry ID
    std::string entryId;
    
    /// @brief Message class
    std::string messageClass;
    
    /// @brief Subject
    std::string subject;
    
    /// @brief Sender email
    std::string senderEmail;
    
    /// @brief Sender name
    std::string senderName;
    
    /// @brief Recipients
    std::vector<std::string> toRecipients;
    
    /// @brief CC recipients
    std::vector<std::string> ccRecipients;
    
    /// @brief BCC recipients
    std::vector<std::string> bccRecipients;
    
    /// @brief Body text
    std::string bodyText;
    
    /// @brief Body HTML
    std::string bodyHtml;
    
    /// @brief Attachment count
    size_t attachmentCount = 0;
    
    /// @brief Attachment names
    std::vector<std::string> attachmentNames;
    
    /// @brief Received time
    SystemTimePoint receivedTime;
    
    /// @brief Sent time
    SystemTimePoint sentTime;
    
    /// @brief Has attachments
    bool hasAttachments = false;
    
    /// @brief Is read
    bool isRead = false;
    
    /// @brief Importance (0=low, 1=normal, 2=high)
    int importance = 1;
    
    /// @brief Internet headers
    std::map<std::string, std::string> headers;
    
    /// @brief Parent folder path
    std::string folderPath;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Folder info
 */
struct FolderInfo {
    /// @brief Entry ID
    std::string entryId;
    
    /// @brief Folder name
    std::string name;
    
    /// @brief Folder path
    std::string path;
    
    /// @brief Folder type
    OutlookFolderType type = OutlookFolderType::Custom;
    
    /// @brief Item count
    size_t itemCount = 0;
    
    /// @brief Unread count
    size_t unreadCount = 0;
    
    /// @brief Is monitored
    bool isMonitored = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Scan event
 */
struct MailScanEvent {
    /// @brief Event ID
    std::string eventId;
    
    /// @brief Mail item info
    MailItemInfo mailItem;
    
    /// @brief Event type
    MailEventType eventType = MailEventType::NewMail;
    
    /// @brief Scan result
    std::optional<EmailScanResult> scanResult;
    
    /// @brief Action taken
    OutlookScanAction actionTaken = OutlookScanAction::Allow;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief Scan duration
    std::chrono::microseconds scanDuration{0};
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct OutlookScannerStatistics {
    std::atomic<uint64_t> totalScanned{0};
    std::atomic<uint64_t> newMailScanned{0};
    std::atomic<uint64_t> outboundScanned{0};
    std::atomic<uint64_t> threatsDetected{0};
    std::atomic<uint64_t> malwareBlocked{0};
    std::atomic<uint64_t> phishingBlocked{0};
    std::atomic<uint64_t> spamTagged{0};
    std::atomic<uint64_t> attachmentsStripped{0};
    std::atomic<uint64_t> sendBlocked{0};
    std::atomic<uint64_t> allowed{0};
    std::atomic<uint64_t> quarantined{0};
    std::atomic<uint64_t> scanErrors{0};
    std::array<std::atomic<uint64_t>, 16> byEventType{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct OutlookScannerConfiguration {
    /// @brief Enable scanner
    bool enabled = true;
    
    /// @brief Scan inbound mail
    bool scanInbound = true;
    
    /// @brief Scan outbound mail
    bool scanOutbound = true;
    
    /// @brief Scan attachments
    bool scanAttachments = true;
    
    /// @brief Scan links
    bool scanLinks = true;
    
    /// @brief Block dangerous attachments
    bool blockDangerousAttachments = true;
    
    /// @brief Block macros
    bool blockMacros = false;
    
    /// @brief Detect phishing
    bool detectPhishing = true;
    
    /// @brief Detect spam
    bool detectSpam = true;
    
    /// @brief Enforce DLP
    bool enforceDLP = false;
    
    /// @brief Show ribbon button
    bool showRibbonButton = true;
    
    /// @brief Show notification on block
    bool showNotificationOnBlock = true;
    
    /// @brief Allow user override
    bool allowUserOverride = false;
    
    /// @brief Monitored folders
    std::vector<OutlookFolderType> monitoredFolders = {
        OutlookFolderType::Inbox,
        OutlookFolderType::Outbox
    };
    
    /// @brief Trusted senders
    std::vector<std::string> trustedSenders;
    
    /// @brief Blocked extensions
    std::vector<std::string> blockedExtensions;
    
    /// @brief Scan timeout
    uint32_t scanTimeoutMs = OutlookConstants::SCAN_TIMEOUT_MS;
    
    /// @brief Maximum attachment size
    size_t maxAttachmentSize = OutlookConstants::MAX_ATTACHMENT_SIZE;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using MailEventCallback = std::function<void(const MailScanEvent&)>;
using ScanResultCallback = std::function<void(const MailItemInfo&, const EmailScanResult&)>;
using BlockCallback = std::function<void(const MailItemInfo&, OutlookScanAction)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

/// @brief Pre-send callback (return false to cancel send)
using PreSendCallback = std::function<bool(MailItemInfo&)>;

// ============================================================================
// OUTLOOK SCANNER CLASS
// ============================================================================

/**
 * @class OutlookScanner
 * @brief Enterprise Outlook integration scanner
 */
class OutlookScanner final {
public:
    [[nodiscard]] static OutlookScanner& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    OutlookScanner(const OutlookScanner&) = delete;
    OutlookScanner& operator=(const OutlookScanner&) = delete;
    OutlookScanner(OutlookScanner&&) = delete;
    OutlookScanner& operator=(OutlookScanner&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const OutlookScannerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    [[nodiscard]] AddinStatus GetAddinStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const OutlookScannerConfiguration& config);
    [[nodiscard]] OutlookScannerConfiguration GetConfiguration() const;

    // ========================================================================
    // ADD-IN OPERATIONS
    // ========================================================================
    
    /// @brief Initialize COM add-in
    [[nodiscard]] bool InitializeAddin();
    
    /// @brief Shutdown add-in
    [[nodiscard]] bool ShutdownAddin();
    
    /// @brief Connect to Outlook application
    [[nodiscard]] bool ConnectToOutlook();
    
    /// @brief Disconnect from Outlook
    void DisconnectFromOutlook();
    
    /// @brief Is connected to Outlook
    [[nodiscard]] bool IsConnected() const noexcept;
    
    /// @brief Get Outlook version
    [[nodiscard]] OutlookVersionInfo GetOutlookVersion() const;

    // ========================================================================
    // EVENT HANDLERS (called by COM entry points)
    // ========================================================================
    
    /// @brief Called on new mail
    void OnNewMail(void* pDispatchMailItem);
    
    /// @brief Called on new mail (multiple items)
    void OnNewMailEx(const std::string& entryIdCollection);
    
    /// @brief Called before item send (return false to cancel)
    [[nodiscard]] bool OnItemSend(void* pDispatchMailItem, bool& cancel);
    
    /// @brief Called on item add to folder
    void OnItemAdd(void* pDispatchItem);
    
    /// @brief Called on item change
    void OnItemChange(void* pDispatchItem);
    
    /// @brief Called before delete
    void OnBeforeDelete(void* pDispatchItem, bool& cancel);
    
    /// @brief Called on attachment add
    void OnAttachmentAdd(void* pDispatchAttachment, bool& cancel);

    // ========================================================================
    // SCANNING
    // ========================================================================
    
    /// @brief Scan mail item
    [[nodiscard]] EmailScanResult ScanMailItem(const MailItemInfo& mailInfo);
    
    /// @brief Scan mail item by entry ID
    [[nodiscard]] EmailScanResult ScanMailItemById(const std::string& entryId);
    
    /// @brief Get mail item info from IDispatch
    [[nodiscard]] std::optional<MailItemInfo> GetMailItemInfo(void* pDispatch);
    
    /// @brief Extract attachment to temp file
    [[nodiscard]] std::optional<fs::path> ExtractAttachment(
        void* pDispatch,
        size_t attachmentIndex);

    // ========================================================================
    // FOLDER OPERATIONS
    // ========================================================================
    
    /// @brief Get monitored folders
    [[nodiscard]] std::vector<FolderInfo> GetMonitoredFolders() const;
    
    /// @brief Add folder to monitor
    [[nodiscard]] bool AddMonitoredFolder(const std::string& folderPath);
    
    /// @brief Remove folder from monitoring
    [[nodiscard]] bool RemoveMonitoredFolder(const std::string& folderPath);
    
    /// @brief Scan entire folder
    [[nodiscard]] std::vector<EmailScanResult> ScanFolder(
        const std::string& folderPath,
        bool recursive = false);

    // ========================================================================
    // ACTIONS
    // ========================================================================
    
    /// @brief Move mail to junk
    [[nodiscard]] bool MoveToJunk(const std::string& entryId);
    
    /// @brief Delete mail
    [[nodiscard]] bool DeleteMail(const std::string& entryId);
    
    /// @brief Strip attachments from mail
    [[nodiscard]] bool StripAttachments(
        const std::string& entryId,
        const std::vector<std::string>& attachmentNames = {});
    
    /// @brief Add tag to subject
    [[nodiscard]] bool TagSubject(const std::string& entryId, const std::string& tag);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterMailEventCallback(MailEventCallback callback);
    void RegisterScanCallback(ScanResultCallback callback);
    void RegisterBlockCallback(BlockCallback callback);
    void RegisterPreSendCallback(PreSendCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] OutlookScannerStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    OutlookScanner();
    ~OutlookScanner();
    
    std::unique_ptr<OutlookScannerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetAddinStatusName(AddinStatus status) noexcept;
[[nodiscard]] std::string_view GetMailEventTypeName(MailEventType type) noexcept;
[[nodiscard]] std::string_view GetOutlookScanActionName(OutlookScanAction action) noexcept;
[[nodiscard]] std::string_view GetFolderTypeName(OutlookFolderType type) noexcept;

/// @brief Check if Outlook is running
[[nodiscard]] bool IsOutlookRunning();

/// @brief Get Outlook process ID
[[nodiscard]] std::optional<DWORD> GetOutlookProcessId();

/// @brief Parse entry ID collection string
[[nodiscard]] std::vector<std::string> ParseEntryIdCollection(const std::string& collection);

}  // namespace Email
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_OUTLOOK_IS_CONNECTED() \
    ::ShadowStrike::Email::OutlookScanner::Instance().IsConnected()

#define SS_OUTLOOK_SCAN_MAIL(entryId) \
    ::ShadowStrike::Email::OutlookScanner::Instance().ScanMailItemById(entryId)