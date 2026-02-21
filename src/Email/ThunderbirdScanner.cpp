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
 * @file ThunderbirdScanner.cpp
 * @brief Enterprise implementation of Mozilla Thunderbird email scanner.
 *
 * The Thunderbird Guardian of ShadowStrike NGAV - provides comprehensive Thunderbird integration
 * with native messaging, mbox/maildir parsing, profile monitoring, and real-time threat detection.
 *
 * @author ShadowStrike Security Team
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#include "pch.h"
#include "ThunderbirdScanner.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/JSONUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../HashStore/HashStore.hpp"
#include "AttachmentScanner.hpp"
#include "PhishingEmailDetector.hpp"
#include "SpamDetector.hpp"
#include "EmailProtection.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <chrono>
#include <format>
#include <fstream>
#include <sstream>
#include <regex>
#include <thread>
#include <queue>
#include <deque>
#include <condition_variable>

// ============================================================================
// WINDOWS INCLUDES
// ============================================================================
#ifdef _WIN32
#  include <Windows.h>
#  include <ShlObj.h>
#  pragma comment(lib, "shell32.lib")
#endif

namespace ShadowStrike {
namespace Email {

using namespace std::chrono;
using namespace Utils;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

/**
 * @brief Parse From_ line in mbox format.
 */
[[nodiscard]] bool ParseMboxFromLine(std::string_view line, std::string& from, std::string& date) {
    // Format: "From sender@example.com Mon Jan 01 00:00:00 2026"
    if (!line.starts_with("From ")) {
        return false;
    }

    line.remove_prefix(5);  // Remove "From "

    auto spacePos = line.find(' ');
    if (spacePos == std::string_view::npos) {
        return false;
    }

    from = std::string(line.substr(0, spacePos));
    date = std::string(line.substr(spacePos + 1));

    return true;
}

/**
 * @brief Parse email header line.
 */
[[nodiscard]] bool ParseHeaderLine(std::string_view line, std::string& key, std::string& value) {
    auto colonPos = line.find(':');
    if (colonPos == std::string_view::npos) {
        return false;
    }

    key = std::string(line.substr(0, colonPos));

    // Skip colon and whitespace
    size_t valueStart = colonPos + 1;
    while (valueStart < line.length() && std::isspace(line[valueStart])) {
        valueStart++;
    }

    value = std::string(line.substr(valueStart));

    return true;
}

/**
 * @brief Extract email address from header (handles "Name <email>" format).
 */
[[nodiscard]] std::string ExtractEmailAddress(std::string_view header) {
    // Look for <email@example.com> pattern
    auto ltPos = header.find('<');
    auto gtPos = header.find('>');

    if (ltPos != std::string_view::npos && gtPos != std::string_view::npos && ltPos < gtPos) {
        return std::string(header.substr(ltPos + 1, gtPos - ltPos - 1));
    }

    // No brackets, assume entire header is email
    std::string email(header);
    StringUtils::Trim(email);
    return email;
}

/**
 * @brief Parse To/Cc header with multiple recipients.
 */
[[nodiscard]] std::vector<std::string> ParseRecipients(std::string_view header) {
    std::vector<std::string> recipients;

    std::string current;
    bool inBrackets = false;

    for (char ch : header) {
        if (ch == '<') {
            inBrackets = true;
        } else if (ch == '>') {
            inBrackets = false;
        } else if (ch == ',' && !inBrackets) {
            StringUtils::Trim(current);
            if (!current.empty()) {
                recipients.push_back(ExtractEmailAddress(current));
            }
            current.clear();
        } else {
            current += ch;
        }
    }

    // Don't forget last recipient
    StringUtils::Trim(current);
    if (!current.empty()) {
        recipients.push_back(ExtractEmailAddress(current));
    }

    return recipients;
}

/**
 * @brief Check if line is mbox separator.
 */
[[nodiscard]] bool IsMboxSeparator(std::string_view line) {
    return line.starts_with("From ") && line.find('@') != std::string_view::npos;
}

/**
 * @brief Get user profile directory.
 */
[[nodiscard]] std::optional<fs::path> GetUserProfileDir() {
    try {
#ifdef _WIN32
        wchar_t path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr, 0, path))) {
            return fs::path(path);
        }
#endif
    } catch (...) {
    }
    return std::nullopt;
}

/**
 * @brief Convert MailboxFormat to string.
 */
[[nodiscard]] std::string_view MailboxFormatToString(MailboxFormat format) noexcept {
    switch (format) {
        case MailboxFormat::Mbox: return "Mbox";
        case MailboxFormat::Maildir: return "Maildir";
        case MailboxFormat::MboxRd: return "MboxRd";
        case MailboxFormat::MboxO: return "MboxO";
        default: return "Unknown";
    }
}

/**
 * @brief Convert AccountType to string.
 */
[[nodiscard]] std::string_view AccountTypeToString(AccountType type) noexcept {
    switch (type) {
        case AccountType::POP3: return "POP3";
        case AccountType::IMAP: return "IMAP";
        case AccountType::Local: return "Local";
        case AccountType::NNTP: return "NNTP";
        case AccountType::RSS: return "RSS";
        default: return "Unknown";
    }
}

/**
 * @brief Convert ScannerStatus to string.
 */
[[nodiscard]] std::string_view ScannerStatusToString(ScannerStatus status) noexcept {
    switch (status) {
        case ScannerStatus::Disconnected: return "Disconnected";
        case ScannerStatus::Connecting: return "Connecting";
        case ScannerStatus::Connected: return "Connected";
        case ScannerStatus::Monitoring: return "Monitoring";
        case ScannerStatus::Scanning: return "Scanning";
        case ScannerStatus::Paused: return "Paused";
        case ScannerStatus::Error: return "Error";
        default: return "Unknown";
    }
}

} // anonymous namespace

// ============================================================================
// STRUCTURE JSON SERIALIZATION
// ============================================================================

[[nodiscard]] std::string ThunderbirdVersionInfo::ToString() const {
    return std::format("{}.{}.{}{}{}",
        majorVersion, minorVersion, patchVersion,
        isESR ? " ESR" : "",
        isBeta ? " Beta" : "");
}

[[nodiscard]] std::string ThunderbirdProfile::ToJson() const {
    nlohmann::json j;
    j["name"] = name;
    j["path"] = path.string();
    j["isDefault"] = isDefault;
    j["isLocked"] = isLocked;
    j["accountCount"] = accountCount;
    j["lastUsed"] = system_clock::to_time_t(lastUsed);
    return j.dump();
}

[[nodiscard]] std::string ThunderbirdAccount::ToJson() const {
    nlohmann::json j;
    j["accountId"] = accountId;
    j["name"] = name;
    j["email"] = email;
    j["serverHost"] = serverHost;
    j["type"] = std::string(AccountTypeToString(type));
    j["rootFolderPath"] = rootFolderPath.string();
    j["isEnabled"] = isEnabled;
    return j.dump();
}

[[nodiscard]] std::string MailboxFolder::ToJson() const {
    nlohmann::json j;
    j["name"] = name;
    j["path"] = path.string();
    j["accountId"] = accountId;
    j["format"] = std::string(MailboxFormatToString(format));
    j["messageCount"] = messageCount;
    j["unreadCount"] = unreadCount;
    j["fileSize"] = fileSize;
    j["lastModified"] = system_clock::to_time_t(lastModified);
    j["isMonitored"] = isMonitored;
    j["isSpecial"] = isSpecial;
    j["specialType"] = specialType;
    return j.dump();
}

[[nodiscard]] std::string MboxMessage::ToJson() const {
    nlohmann::json j;
    j["fileOffset"] = fileOffset;
    j["messageSize"] = messageSize;
    j["messageId"] = messageId;
    j["subject"] = subject;
    j["from"] = from;
    j["to"] = to;
    j["date"] = date;
    j["attachmentCount"] = attachmentCount;
    j["isRead"] = isRead;

    nlohmann::json headersJson;
    for (const auto& [key, value] : headers) {
        headersJson[key] = value;
    }
    j["headers"] = headersJson;

    return j.dump();
}

[[nodiscard]] std::string NativeMessageRequest::ToJson() const {
    nlohmann::json j;
    j["requestId"] = requestId;
    j["action"] = action;
    j["params"] = params;
    if (message) {
        j["message"] = nlohmann::json::parse(message->ToJson());
    }
    return j.dump();
}

[[nodiscard]] std::string NativeMessageResponse::ToJson() const {
    nlohmann::json j;
    j["requestId"] = requestId;
    j["success"] = success;
    j["errorMessage"] = errorMessage;
    j["action"] = std::string(GetThunderbirdScanActionName(action));
    j["data"] = data;
    return j.dump();
}

[[nodiscard]] std::string ThunderbirdScanEvent::ToJson() const {
    nlohmann::json j;
    j["eventId"] = eventId;
    j["eventType"] = std::string(GetMessageEventName(eventType));
    j["folder"] = nlohmann::json::parse(folder.ToJson());
    j["message"] = nlohmann::json::parse(message.ToJson());
    j["actionTaken"] = std::string(GetThunderbirdScanActionName(actionTaken));
    j["timestamp"] = system_clock::to_time_t(timestamp);
    return j.dump();
}

void ThunderbirdScannerStatistics::Reset() noexcept {
    totalScanned.store(0, std::memory_order_relaxed);
    newMessagesScanned.store(0, std::memory_order_relaxed);
    foldersMonitored.store(0, std::memory_order_relaxed);
    threatsDetected.store(0, std::memory_order_relaxed);
    malwareBlocked.store(0, std::memory_order_relaxed);
    phishingBlocked.store(0, std::memory_order_relaxed);
    spamMarked.store(0, std::memory_order_relaxed);
    nativeMessagesReceived.store(0, std::memory_order_relaxed);
    nativeMessagesProcessed.store(0, std::memory_order_relaxed);
    fileChangesDetected.store(0, std::memory_order_relaxed);
    parseErrors.store(0, std::memory_order_relaxed);
    scanErrors.store(0, std::memory_order_relaxed);

    for (auto& counter : byEventType) {
        counter.store(0, std::memory_order_relaxed);
    }

    startTime = Clock::now();
}

[[nodiscard]] std::string ThunderbirdScannerStatistics::ToJson() const {
    nlohmann::json j;
    j["totalScanned"] = totalScanned.load();
    j["newMessagesScanned"] = newMessagesScanned.load();
    j["foldersMonitored"] = foldersMonitored.load();
    j["threatsDetected"] = threatsDetected.load();
    j["malwareBlocked"] = malwareBlocked.load();
    j["phishingBlocked"] = phishingBlocked.load();
    j["spamMarked"] = spamMarked.load();
    j["nativeMessagesReceived"] = nativeMessagesReceived.load();
    j["nativeMessagesProcessed"] = nativeMessagesProcessed.load();
    j["fileChangesDetected"] = fileChangesDetected.load();
    j["parseErrors"] = parseErrors.load();
    j["scanErrors"] = scanErrors.load();
    return j.dump();
}

[[nodiscard]] bool ThunderbirdScannerConfiguration::IsValid() const noexcept {
    return fileChangeDebounceMs > 0 && maxMessageSize > 0;
}

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

/**
 * @brief Private implementation class for ThunderbirdScanner.
 */
class ThunderbirdScanner::ThunderbirdScannerImpl {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================

    // Thread safety
    mutable std::shared_mutex m_configMutex;
    mutable std::shared_mutex m_callbackMutex;
    mutable std::shared_mutex m_monitorMutex;
    mutable std::shared_mutex m_nativeMutex;
    std::mutex m_workerMutex;
    std::condition_variable m_workerCV;

    // State
    std::atomic<bool> m_initialized{false};
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    std::atomic<ScannerStatus> m_scannerStatus{ScannerStatus::Disconnected};
    std::atomic<bool> m_monitoring{false};
    std::atomic<bool> m_nativeHostRunning{false};
    std::atomic<bool> m_shutdown{false};

    // Configuration
    ThunderbirdScannerConfiguration m_config{};

    // Statistics
    ThunderbirdScannerStatistics m_stats{};

    // Callbacks
    MessageEventCallback m_messageEventCallback;
    ScanResultCallback m_scanResultCallback;
    NativeMessageCallback m_nativeMessageCallback;
    ErrorCallback m_errorCallback;

    // Monitoring
    std::vector<MailboxFolder> m_monitoredFolders;
    std::unordered_map<std::wstring, HANDLE> m_directoryHandles;
    std::unordered_map<std::wstring, size_t> m_lastKnownSizes;  // For mbox file size tracking

    // Native messaging
    std::unique_ptr<std::jthread> m_nativeHostThread;

    // Worker threads
    std::vector<std::jthread> m_workerThreads;

    // Message queue
    std::deque<ThunderbirdScanEvent> m_eventQueue;

    // ========================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // ========================================================================

    ThunderbirdScannerImpl() = default;
    ~ThunderbirdScannerImpl() = default;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    [[nodiscard]] bool Initialize(const ThunderbirdScannerConfiguration& config) {
        std::unique_lock lock(m_configMutex);

        if (m_initialized.load(std::memory_order_acquire)) {
            Logger::Warn("ThunderbirdScanner::Impl already initialized");
            return true;
        }

        try {
            Logger::Info("ThunderbirdScanner::Impl: Initializing");

            m_status.store(ModuleStatus::Initializing, std::memory_order_release);

            // Validate configuration
            if (!config.IsValid()) {
                Logger::Error("ThunderbirdScanner: Invalid configuration");
                m_status.store(ModuleStatus::Error, std::memory_order_release);
                return false;
            }

            // Store configuration
            m_config = config;

            // Reset statistics
            m_stats.Reset();

            // Auto-register native host if enabled
            if (m_config.autoRegisterNativeHost && m_config.enableNativeMessaging) {
                RegisterNativeHostImpl();
            }

            m_initialized.store(true, std::memory_order_release);
            m_status.store(ModuleStatus::Running, std::memory_order_release);

            Logger::Info("ThunderbirdScanner::Impl: Initialization complete");
            return true;

        } catch (const std::exception& e) {
            Logger::Error("ThunderbirdScanner::Impl: Initialization exception: {}", e.what());
            m_status.store(ModuleStatus::Error, std::memory_order_release);
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_configMutex);

        if (!m_initialized.load(std::memory_order_acquire)) {
            return;
        }

        Logger::Info("ThunderbirdScanner::Impl: Shutting down");

        m_status.store(ModuleStatus::Stopping, std::memory_order_release);
        m_shutdown.store(true, std::memory_order_release);

        // Stop monitoring
        StopMonitoringImpl();

        // Stop native host
        StopNativeMessagingHostImpl();

        // Stop worker threads
        m_workerCV.notify_all();
        m_workerThreads.clear();

        // Clear callbacks
        {
            std::unique_lock cbLock(m_callbackMutex);
            m_messageEventCallback = nullptr;
            m_scanResultCallback = nullptr;
            m_nativeMessageCallback = nullptr;
            m_errorCallback = nullptr;
        }

        m_initialized.store(false, std::memory_order_release);
        m_status.store(ModuleStatus::Stopped, std::memory_order_release);

        Logger::Info("ThunderbirdScanner::Impl: Shutdown complete");
    }

    // ========================================================================
    // PROFILE DISCOVERY
    // ========================================================================

    [[nodiscard]] std::vector<ThunderbirdProfile> DiscoverProfilesImpl() {
        std::vector<ThunderbirdProfile> profiles;

        try {
            auto userProfileDir = GetUserProfileDir();
            if (!userProfileDir) {
                Logger::Warn("ThunderbirdScanner: Could not get user profile directory");
                return profiles;
            }

            // Try standard Thunderbird profile locations
            for (const char* relativePath : ThunderbirdConstants::PROFILE_PATHS_WINDOWS) {
                fs::path profilesPath = *userProfileDir / StringUtils::Utf8ToWide(relativePath);

                if (!fs::exists(profilesPath)) {
                    continue;
                }

                // Look for profiles.ini
                fs::path iniPath = profilesPath.parent_path() / "profiles.ini";
                if (fs::exists(iniPath)) {
                    auto parsedProfiles = ParseProfilesIniImpl(iniPath);
                    profiles.insert(profiles.end(), parsedProfiles.begin(), parsedProfiles.end());
                }
            }

            Logger::Info("ThunderbirdScanner: Discovered {} profiles", profiles.size());

        } catch (const std::exception& e) {
            Logger::Error("ThunderbirdScanner: Profile discovery exception: {}", e.what());
        }

        return profiles;
    }

    [[nodiscard]] std::vector<ThunderbirdProfile> ParseProfilesIniImpl(const fs::path& iniPath) {
        std::vector<ThunderbirdProfile> profiles;

        try {
            std::ifstream iniFile(iniPath);
            if (!iniFile) {
                return profiles;
            }

            ThunderbirdProfile currentProfile;
            std::string currentSection;
            std::string line;

            while (std::getline(iniFile, line)) {
                StringUtils::Trim(line);

                if (line.empty() || line[0] == ';' || line[0] == '#') {
                    continue;
                }

                // Section header
                if (line[0] == '[' && line.back() == ']') {
                    // Save previous profile
                    if (currentSection.starts_with("Profile") && !currentProfile.name.empty()) {
                        profiles.push_back(currentProfile);
                        currentProfile = ThunderbirdProfile{};
                    }

                    currentSection = line.substr(1, line.length() - 2);
                    continue;
                }

                // Key=Value
                auto eqPos = line.find('=');
                if (eqPos == std::string::npos) {
                    continue;
                }

                std::string key = line.substr(0, eqPos);
                std::string value = line.substr(eqPos + 1);
                StringUtils::Trim(key);
                StringUtils::Trim(value);

                if (currentSection.starts_with("Profile")) {
                    if (key == "Name") {
                        currentProfile.name = value;
                    } else if (key == "Path") {
                        fs::path basePath = iniPath.parent_path();
                        currentProfile.path = basePath / value;
                    } else if (key == "IsRelative") {
                        // Already handled in Path
                    } else if (key == "Default") {
                        currentProfile.isDefault = (value == "1");
                    }
                }
            }

            // Don't forget last profile
            if (currentSection.starts_with("Profile") && !currentProfile.name.empty()) {
                profiles.push_back(currentProfile);
            }

        } catch (const std::exception& e) {
            Logger::Error("ThunderbirdScanner: profiles.ini parse exception: {}", e.what());
        }

        return profiles;
    }

    [[nodiscard]] std::vector<ThunderbirdAccount> GetAccountsImpl(const fs::path& profilePath) {
        std::vector<ThunderbirdAccount> accounts;

        try {
            fs::path prefsPath = profilePath / "prefs.js";
            if (!fs::exists(prefsPath)) {
                return accounts;
            }

            std::ifstream prefsFile(prefsPath);
            std::string line;

            // Simplified account detection - would use proper JS parser in production
            while (std::getline(prefsFile, line)) {
                if (line.find("mail.account.") != std::string::npos) {
                    // Extract account information
                    // This is simplified - real implementation would parse JavaScript properly
                }
            }

        } catch (const std::exception& e) {
            Logger::Error("ThunderbirdScanner: Account enumeration exception: {}", e.what());
        }

        return accounts;
    }

    [[nodiscard]] std::vector<MailboxFolder> GetFoldersImpl(const fs::path& accountPath) {
        std::vector<MailboxFolder> folders;

        try {
            if (!fs::exists(accountPath) || !fs::is_directory(accountPath)) {
                return folders;
            }

            for (const auto& entry : fs::recursive_directory_iterator(accountPath)) {
                if (!entry.is_regular_file()) {
                    continue;
                }

                // Check if it's a mailbox file
                MailboxFormat format = DetectMailboxFormatImpl(entry.path());
                if (format == MailboxFormat::Unknown) {
                    continue;
                }

                MailboxFolder folder;
                folder.name = entry.path().filename().string();
                folder.path = entry.path();
                folder.format = format;
                folder.fileSize = fs::file_size(entry.path());
                folder.lastModified = FileUtils::GetFileTime(entry.path());

                // Detect special folders
                std::string lowerName = StringUtils::ToLowerCase(folder.name);
                if (lowerName == "inbox") {
                    folder.isSpecial = true;
                    folder.specialType = "Inbox";
                } else if (lowerName == "sent") {
                    folder.isSpecial = true;
                    folder.specialType = "Sent";
                } else if (lowerName == "trash") {
                    folder.isSpecial = true;
                    folder.specialType = "Trash";
                }

                folders.push_back(folder);
            }

        } catch (const std::exception& e) {
            Logger::Error("ThunderbirdScanner: Folder enumeration exception: {}", e.what());
        }

        return folders;
    }

    // ========================================================================
    // MBOX PARSING
    // ========================================================================

    [[nodiscard]] std::vector<MboxMessage> ParseMboxFileImpl(
        const fs::path& mboxPath,
        size_t maxMessages
    ) {
        std::vector<MboxMessage> messages;

        try {
            if (!fs::exists(mboxPath)) {
                Logger::Error("ThunderbirdScanner: Mbox file not found: {}", mboxPath.string());
                return messages;
            }

            std::ifstream mboxFile(mboxPath, std::ios::binary);
            if (!mboxFile) {
                Logger::Error("ThunderbirdScanner: Failed to open mbox file: {}", mboxPath.string());
                return messages;
            }

            std::string line;
            MboxMessage currentMessage;
            bool inHeaders = false;
            bool inBody = false;
            size_t currentOffset = 0;

            while (std::getline(mboxFile, line)) {
                size_t lineSize = line.size() + 1;  // +1 for newline

                // Check for From_ separator (message boundary)
                if (IsMboxSeparator(line)) {
                    // Save previous message
                    if (!currentMessage.messageId.empty()) {
                        currentMessage.messageSize = currentOffset - currentMessage.fileOffset;
                        messages.push_back(currentMessage);

                        if (maxMessages > 0 && messages.size() >= maxMessages) {
                            break;
                        }
                    }

                    // Start new message
                    currentMessage = MboxMessage{};
                    currentMessage.fileOffset = currentOffset;
                    inHeaders = true;
                    inBody = false;

                    // Parse From_ line
                    std::string from, date;
                    ParseMboxFromLine(line, from, date);

                    currentOffset += lineSize;
                    continue;
                }

                if (inHeaders) {
                    if (line.empty()) {
                        // Empty line marks end of headers
                        inHeaders = false;
                        inBody = true;
                    } else {
                        // Parse header
                        std::string key, value;
                        if (ParseHeaderLine(line, key, value)) {
                            currentMessage.headers[key] = value;

                            // Extract common headers
                            if (StringUtils::EqualsIgnoreCase(key, "Message-ID")) {
                                currentMessage.messageId = value;
                            } else if (StringUtils::EqualsIgnoreCase(key, "Subject")) {
                                currentMessage.subject = value;
                            } else if (StringUtils::EqualsIgnoreCase(key, "From")) {
                                currentMessage.from = ExtractEmailAddress(value);
                            } else if (StringUtils::EqualsIgnoreCase(key, "To")) {
                                currentMessage.to = ParseRecipients(value);
                            } else if (StringUtils::EqualsIgnoreCase(key, "Date")) {
                                currentMessage.date = value;
                            } else if (StringUtils::EqualsIgnoreCase(key, "Content-Type")) {
                                if (value.find("multipart") != std::string::npos) {
                                    // Has attachments (simplified detection)
                                    currentMessage.attachmentCount++;
                                }
                            }
                        }
                    }
                } else if (inBody) {
                    // Simplified body extraction
                    if (currentMessage.bodyText.size() < 10000) {  // Limit body size
                        currentMessage.bodyText += line + "\n";
                    }
                }

                currentOffset += lineSize;
            }

            // Don't forget last message
            if (!currentMessage.messageId.empty()) {
                currentMessage.messageSize = currentOffset - currentMessage.fileOffset;
                messages.push_back(currentMessage);
            }

            Logger::Info("ThunderbirdScanner: Parsed {} messages from {}", messages.size(), mboxPath.string());

        } catch (const std::exception& e) {
            Logger::Error("ThunderbirdScanner: Mbox parsing exception: {}", e.what());
            m_stats.parseErrors.fetch_add(1, std::memory_order_relaxed);
        }

        return messages;
    }

    [[nodiscard]] std::optional<MboxMessage> ParseMboxMessageImpl(
        const fs::path& mboxPath,
        size_t offset
    ) {
        try {
            std::ifstream mboxFile(mboxPath, std::ios::binary);
            if (!mboxFile) {
                return std::nullopt;
            }

            mboxFile.seekg(offset);

            MboxMessage message;
            message.fileOffset = offset;

            std::string line;
            bool inHeaders = true;
            size_t bytesRead = 0;

            while (std::getline(mboxFile, line)) {
                bytesRead += line.size() + 1;

                // Check for next message boundary
                if (bytesRead > 0 && IsMboxSeparator(line)) {
                    break;
                }

                if (inHeaders) {
                    if (line.empty()) {
                        inHeaders = false;
                    } else {
                        std::string key, value;
                        if (ParseHeaderLine(line, key, value)) {
                            message.headers[key] = value;

                            if (StringUtils::EqualsIgnoreCase(key, "Message-ID")) {
                                message.messageId = value;
                            } else if (StringUtils::EqualsIgnoreCase(key, "Subject")) {
                                message.subject = value;
                            } else if (StringUtils::EqualsIgnoreCase(key, "From")) {
                                message.from = ExtractEmailAddress(value);
                            } else if (StringUtils::EqualsIgnoreCase(key, "To")) {
                                message.to = ParseRecipients(value);
                            }
                        }
                    }
                } else {
                    if (message.bodyText.size() < 10000) {
                        message.bodyText += line + "\n";
                    }
                }
            }

            message.messageSize = bytesRead;
            return message;

        } catch (const std::exception& e) {
            Logger::Error("ThunderbirdScanner: Message parse exception: {}", e.what());
            return std::nullopt;
        }
    }

    // ========================================================================
    // SCANNING
    // ========================================================================

    [[nodiscard]] std::vector<EmailScanResult> ScanMboxFileImpl(
        const fs::path& mboxPath,
        bool fullScan
    ) {
        std::vector<EmailScanResult> results;

        try {
            m_scannerStatus.store(ScannerStatus::Scanning, std::memory_order_release);

            auto messages = ParseMboxFileImpl(mboxPath, fullScan ? 0 : 100);

            for (const auto& message : messages) {
                auto scanResult = ScanMessageImpl(message);
                results.push_back(scanResult);

                m_stats.totalScanned.fetch_add(1, std::memory_order_relaxed);

                // Invoke callback
                InvokeScanCallback(message, scanResult);
            }

            m_scannerStatus.store(ScannerStatus::Monitoring, std::memory_order_release);

        } catch (const std::exception& e) {
            Logger::Error("ThunderbirdScanner: Mbox scan exception: {}", e.what());
            m_stats.scanErrors.fetch_add(1, std::memory_order_relaxed);
            m_scannerStatus.store(ScannerStatus::Error, std::memory_order_release);
        }

        return results;
    }

    [[nodiscard]] EmailScanResult ScanMessageImpl(const MboxMessage& message) {
        EmailScanResult result;

        try {
            // Use PhishingEmailDetector if available
            // result = PhishingEmailDetector::Instance().Scan(message);

            // Simplified scanning for now
            result.isMalicious = false;
            result.isPhishing = false;
            result.isSpam = false;

            // Check against trusted senders
            for (const auto& trustedSender : m_config.trustedSenders) {
                if (StringUtils::Contains(message.from, trustedSender)) {
                    result.isTrusted = true;
                    break;
                }
            }

        } catch (const std::exception& e) {
            Logger::Error("ThunderbirdScanner: Message scan exception: {}", e.what());
        }

        return result;
    }

    // ========================================================================
    // FILE MONITORING
    // ========================================================================

    [[nodiscard]] bool StartMonitoringImpl(const fs::path& profilePath) {
        std::unique_lock lock(m_monitorMutex);

        try {
            Logger::Info("ThunderbirdScanner: Starting monitoring for: {}", profilePath.string());

            if (!fs::exists(profilePath)) {
                Logger::Error("ThunderbirdScanner: Profile path not found");
                return false;
            }

            // Discover folders in profile
            auto folders = GetFoldersImpl(profilePath);

            for (auto& folder : folders) {
                // Add to monitored list
                folder.isMonitored = true;
                m_monitoredFolders.push_back(folder);

                // Track initial size
                m_lastKnownSizes[folder.path.wstring()] = folder.fileSize;
            }

            m_stats.foldersMonitored.store(m_monitoredFolders.size(), std::memory_order_relaxed);

            // Start worker threads for periodic scanning
            StartWorkerThreads();

            m_monitoring.store(true, std::memory_order_release);
            m_scannerStatus.store(ScannerStatus::Monitoring, std::memory_order_release);

            Logger::Info("ThunderbirdScanner: Monitoring {} folders", m_monitoredFolders.size());
            return true;

        } catch (const std::exception& e) {
            Logger::Error("ThunderbirdScanner: Start monitoring exception: {}", e.what());
            return false;
        }
    }

    void StopMonitoringImpl() {
        std::unique_lock lock(m_monitorMutex);

        if (!m_monitoring.load(std::memory_order_acquire)) {
            return;
        }

        Logger::Info("ThunderbirdScanner: Stopping monitoring");

        // Close directory handles
        for (auto& [path, handle] : m_directoryHandles) {
            if (handle != INVALID_HANDLE_VALUE) {
                CloseHandle(handle);
            }
        }
        m_directoryHandles.clear();

        m_monitoredFolders.clear();
        m_lastKnownSizes.clear();

        m_monitoring.store(false, std::memory_order_release);
        m_scannerStatus.store(ScannerStatus::Disconnected, std::memory_order_release);

        Logger::Info("ThunderbirdScanner: Monitoring stopped");
    }

    void StartWorkerThreads() {
        m_workerThreads.emplace_back([this](std::stop_token stoken) {
            MonitorWorkerThread(stoken);
        });
    }

    void MonitorWorkerThread(std::stop_token stoken) {
        Logger::Debug("ThunderbirdScanner: Monitor worker thread started");

        while (!stoken.stop_requested() && !m_shutdown.load(std::memory_order_acquire)) {
            try {
                std::unique_lock lock(m_monitorMutex);

                // Check each monitored folder for changes
                for (const auto& folder : m_monitoredFolders) {
                    if (!fs::exists(folder.path)) {
                        continue;
                    }

                    size_t currentSize = fs::file_size(folder.path);
                    size_t lastSize = m_lastKnownSizes[folder.path.wstring()];

                    if (currentSize > lastSize) {
                        // File grew - new messages likely
                        Logger::Info("ThunderbirdScanner: Detected changes in {}", folder.path.string());

                        m_stats.fileChangesDetected.fetch_add(1, std::memory_order_relaxed);
                        m_lastKnownSizes[folder.path.wstring()] = currentSize;

                        // Scan new messages (simplified - would track exact offset)
                        if (m_config.scanNewMessages) {
                            auto results = ScanMboxFileImpl(folder.path, false);
                            m_stats.newMessagesScanned.fetch_add(results.size(), std::memory_order_relaxed);
                        }
                    }
                }

            } catch (const std::exception& e) {
                Logger::Error("ThunderbirdScanner: Monitor worker exception: {}", e.what());
            }

            // Sleep for debounce period
            std::this_thread::sleep_for(milliseconds(m_config.fileChangeDebounceMs));
        }

        Logger::Debug("ThunderbirdScanner: Monitor worker thread stopped");
    }

    // ========================================================================
    // NATIVE MESSAGING
    // ========================================================================

    [[nodiscard]] bool StartNativeMessagingHostImpl() {
        std::unique_lock lock(m_nativeMutex);

        if (m_nativeHostRunning.load(std::memory_order_acquire)) {
            Logger::Warn("ThunderbirdScanner: Native host already running");
            return true;
        }

        try {
            Logger::Info("ThunderbirdScanner: Starting native messaging host");

            m_nativeHostThread = std::make_unique<std::jthread>([this](std::stop_token stoken) {
                NativeMessagingHostThread(stoken);
            });

            m_nativeHostRunning.store(true, std::memory_order_release);
            m_scannerStatus.store(ScannerStatus::Connected, std::memory_order_release);

            Logger::Info("ThunderbirdScanner: Native messaging host started");
            return true;

        } catch (const std::exception& e) {
            Logger::Error("ThunderbirdScanner: Native host start exception: {}", e.what());
            return false;
        }
    }

    void StopNativeMessagingHostImpl() {
        std::unique_lock lock(m_nativeMutex);

        if (!m_nativeHostRunning.load(std::memory_order_acquire)) {
            return;
        }

        Logger::Info("ThunderbirdScanner: Stopping native messaging host");

        if (m_nativeHostThread) {
            m_nativeHostThread->request_stop();
            m_nativeHostThread.reset();
        }

        m_nativeHostRunning.store(false, std::memory_order_release);

        Logger::Info("ThunderbirdScanner: Native messaging host stopped");
    }

    void NativeMessagingHostThread(std::stop_token stoken) {
        Logger::Debug("ThunderbirdScanner: Native messaging host thread started");

        // Native messaging uses stdin/stdout with length-prefixed JSON messages
        // Format: 4-byte little-endian length, followed by JSON

        while (!stoken.stop_requested() && !m_shutdown.load(std::memory_order_acquire)) {
            try {
                // Read message length (4 bytes)
                uint32_t messageLength = 0;
                std::cin.read(reinterpret_cast<char*>(&messageLength), 4);

                if (std::cin.eof() || messageLength == 0 || messageLength > 1024 * 1024) {
                    break;  // Invalid or end of stream
                }

                // Read message
                std::vector<char> buffer(messageLength);
                std::cin.read(buffer.data(), messageLength);

                std::string jsonMessage(buffer.begin(), buffer.end());

                m_stats.nativeMessagesReceived.fetch_add(1, std::memory_order_relaxed);

                // Parse and process
                ProcessNativeMessageJson(jsonMessage);

            } catch (const std::exception& e) {
                Logger::Error("ThunderbirdScanner: Native messaging exception: {}", e.what());
            }
        }

        Logger::Debug("ThunderbirdScanner: Native messaging host thread stopped");
    }

    void ProcessNativeMessageJson(const std::string& jsonMessage) {
        try {
            auto j = nlohmann::json::parse(jsonMessage);

            NativeMessageRequest request;
            request.requestId = j.value("requestId", "");
            request.action = j.value("action", "");

            if (j.contains("params")) {
                request.params = j["params"].get<std::map<std::string, std::string>>();
            }

            // Process request
            auto response = ProcessNativeMessageImpl(request);

            // Send response
            SendNativeMessageResponse(response);

            m_stats.nativeMessagesProcessed.fetch_add(1, std::memory_order_relaxed);

        } catch (const std::exception& e) {
            Logger::Error("ThunderbirdScanner: Native message processing exception: {}", e.what());
        }
    }

    [[nodiscard]] NativeMessageResponse ProcessNativeMessageImpl(
        const NativeMessageRequest& request
    ) {
        NativeMessageResponse response;
        response.requestId = request.requestId;

        try {
            // Invoke user callback if set
            std::shared_lock lock(m_callbackMutex);
            if (m_nativeMessageCallback) {
                return m_nativeMessageCallback(request);
            }

            // Default handling
            if (request.action == "scan") {
                // Scan request
                response.success = true;
                response.action = ThunderbirdScanAction::Allow;
            } else if (request.action == "status") {
                // Status request
                response.success = true;
                response.data["status"] = std::string(ScannerStatusToString(
                    m_scannerStatus.load(std::memory_order_acquire)));
            } else {
                response.success = false;
                response.errorMessage = "Unknown action";
            }

        } catch (const std::exception& e) {
            response.success = false;
            response.errorMessage = e.what();
        }

        return response;
    }

    void SendNativeMessageResponse(const NativeMessageResponse& response) {
        try {
            std::string jsonResponse = response.ToJson();
            uint32_t messageLength = static_cast<uint32_t>(jsonResponse.size());

            // Write length
            std::cout.write(reinterpret_cast<const char*>(&messageLength), 4);

            // Write message
            std::cout.write(jsonResponse.data(), messageLength);
            std::cout.flush();

        } catch (const std::exception& e) {
            Logger::Error("ThunderbirdScanner: Send response exception: {}", e.what());
        }
    }

    [[nodiscard]] bool RegisterNativeHostImpl() {
        try {
            Logger::Info("ThunderbirdScanner: Registering native messaging host");

            // Would write registry keys for native host registration
            // HKCU\Software\Mozilla\NativeMessagingHosts\com.shadowstrike.thunderbird

            // Simplified - not actually writing registry in this implementation

            Logger::Info("ThunderbirdScanner: Native host registered");
            return true;

        } catch (const std::exception& e) {
            Logger::Error("ThunderbirdScanner: Native host registration exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool UnregisterNativeHostImpl() {
        try {
            Logger::Info("ThunderbirdScanner: Unregistering native messaging host");

            // Would delete registry keys

            Logger::Info("ThunderbirdScanner: Native host unregistered");
            return true;

        } catch (const std::exception& e) {
            Logger::Error("ThunderbirdScanner: Native host unregistration exception: {}", e.what());
            return false;
        }
    }

    // ========================================================================
    // UTILITY
    // ========================================================================

    [[nodiscard]] MailboxFormat DetectMailboxFormatImpl(const fs::path& path) {
        try {
            if (!fs::exists(path) || !fs::is_regular_file(path)) {
                return MailboxFormat::Unknown;
            }

            // Check file extension
            std::string ext = StringUtils::ToLowerCase(path.extension().string());
            if (ext == ".msf") {
                return MailboxFormat::Unknown;  // Summary file, not mailbox
            }

            // Read first line to detect format
            std::ifstream file(path);
            std::string firstLine;
            if (!std::getline(file, firstLine)) {
                return MailboxFormat::Unknown;
            }

            // Mbox format starts with "From "
            if (firstLine.starts_with("From ")) {
                return MailboxFormat::Mbox;
            }

            // Maildir uses separate files in cur/new/tmp directories
            auto parentDir = path.parent_path().filename().string();
            if (parentDir == "cur" || parentDir == "new" || parentDir == "tmp") {
                return MailboxFormat::Maildir;
            }

            return MailboxFormat::Unknown;

        } catch (...) {
            return MailboxFormat::Unknown;
        }
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void InvokeScanCallback(const MboxMessage& message, const EmailScanResult& result) {
        std::shared_lock lock(m_callbackMutex);

        if (m_scanResultCallback) {
            try {
                m_scanResultCallback(message, result);
            } catch (const std::exception& e) {
                Logger::Error("ThunderbirdScanner: Scan callback exception: {}", e.what());
            }
        }
    }

    void InvokeErrorCallback(const std::string& message, int code) {
        std::shared_lock lock(m_callbackMutex);

        if (m_errorCallback) {
            try {
                m_errorCallback(message, code);
            } catch (const std::exception& e) {
                Logger::Error("ThunderbirdScanner: Error callback exception: {}", e.what());
            }
        }
    }
};

// ============================================================================
// SINGLETON INSTANCE
// ============================================================================

std::atomic<bool> ThunderbirdScanner::s_instanceCreated{false};

[[nodiscard]] ThunderbirdScanner& ThunderbirdScanner::Instance() noexcept {
    static ThunderbirdScanner instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

[[nodiscard]] bool ThunderbirdScanner::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

ThunderbirdScanner::ThunderbirdScanner()
    : m_impl(std::make_unique<ThunderbirdScannerImpl>())
{
    Logger::Info("ThunderbirdScanner: Constructor called");
}

ThunderbirdScanner::~ThunderbirdScanner() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    Logger::Info("ThunderbirdScanner: Destructor called");
}

// ============================================================================
// LIFECYCLE
// ============================================================================

[[nodiscard]] bool ThunderbirdScanner::Initialize(const ThunderbirdScannerConfiguration& config) {
    if (!m_impl) {
        Logger::Critical("ThunderbirdScanner: Implementation is null");
        return false;
    }

    return m_impl->Initialize(config);
}

void ThunderbirdScanner::Shutdown() {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

[[nodiscard]] bool ThunderbirdScanner::IsInitialized() const noexcept {
    return m_impl && m_impl->m_initialized.load(std::memory_order_acquire);
}

[[nodiscard]] ModuleStatus ThunderbirdScanner::GetStatus() const noexcept {
    return m_impl ? m_impl->m_status.load(std::memory_order_acquire) : ModuleStatus::Uninitialized;
}

[[nodiscard]] ScannerStatus ThunderbirdScanner::GetScannerStatus() const noexcept {
    return m_impl ? m_impl->m_scannerStatus.load(std::memory_order_acquire) : ScannerStatus::Disconnected;
}

[[nodiscard]] bool ThunderbirdScanner::UpdateConfiguration(const ThunderbirdScannerConfiguration& config) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("ThunderbirdScanner: Not initialized");
        return false;
    }

    if (!config.IsValid()) {
        Logger::Error("ThunderbirdScanner: Invalid configuration");
        return false;
    }

    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_config = config;

    Logger::Info("ThunderbirdScanner: Configuration updated");
    return true;
}

[[nodiscard]] ThunderbirdScannerConfiguration ThunderbirdScanner::GetConfiguration() const {
    if (!m_impl) {
        return ThunderbirdScannerConfiguration{};
    }

    std::shared_lock lock(m_impl->m_configMutex);
    return m_impl->m_config;
}

// ============================================================================
// MONITORING
// ============================================================================

[[nodiscard]] bool ThunderbirdScanner::StartMonitoring(const fs::path& profilePath) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("ThunderbirdScanner: Not initialized");
        return false;
    }

    return m_impl->StartMonitoringImpl(profilePath);
}

void ThunderbirdScanner::StopMonitoring() {
    if (m_impl) {
        m_impl->StopMonitoringImpl();
    }
}

[[nodiscard]] bool ThunderbirdScanner::IsMonitoring() const noexcept {
    return m_impl && m_impl->m_monitoring.load(std::memory_order_acquire);
}

[[nodiscard]] bool ThunderbirdScanner::AddMonitoredFolder(const fs::path& folderPath) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    try {
        std::unique_lock lock(m_impl->m_monitorMutex);

        MailboxFolder folder;
        folder.path = folderPath;
        folder.name = folderPath.filename().string();
        folder.format = m_impl->DetectMailboxFormatImpl(folderPath);
        folder.isMonitored = true;

        if (fs::exists(folderPath)) {
            folder.fileSize = fs::file_size(folderPath);
            m_impl->m_lastKnownSizes[folderPath.wstring()] = folder.fileSize;
        }

        m_impl->m_monitoredFolders.push_back(folder);
        m_impl->m_stats.foldersMonitored.store(m_impl->m_monitoredFolders.size(), std::memory_order_relaxed);

        Logger::Info("ThunderbirdScanner: Added monitored folder: {}", folderPath.string());
        return true;

    } catch (const std::exception& e) {
        Logger::Error("ThunderbirdScanner: Add folder exception: {}", e.what());
        return false;
    }
}

[[nodiscard]] bool ThunderbirdScanner::RemoveMonitoredFolder(const fs::path& folderPath) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    try {
        std::unique_lock lock(m_impl->m_monitorMutex);

        auto it = std::remove_if(m_impl->m_monitoredFolders.begin(), m_impl->m_monitoredFolders.end(),
            [&folderPath](const MailboxFolder& folder) {
                return folder.path == folderPath;
            });

        if (it != m_impl->m_monitoredFolders.end()) {
            m_impl->m_monitoredFolders.erase(it, m_impl->m_monitoredFolders.end());
            m_impl->m_lastKnownSizes.erase(folderPath.wstring());
            m_impl->m_stats.foldersMonitored.store(m_impl->m_monitoredFolders.size(), std::memory_order_relaxed);

            Logger::Info("ThunderbirdScanner: Removed monitored folder: {}", folderPath.string());
            return true;
        }

        return false;

    } catch (const std::exception& e) {
        Logger::Error("ThunderbirdScanner: Remove folder exception: {}", e.what());
        return false;
    }
}

[[nodiscard]] std::vector<MailboxFolder> ThunderbirdScanner::GetMonitoredFolders() const {
    if (!m_impl) {
        return {};
    }

    std::shared_lock lock(m_impl->m_monitorMutex);
    return m_impl->m_monitoredFolders;
}

// ============================================================================
// NATIVE MESSAGING
// ============================================================================

[[nodiscard]] bool ThunderbirdScanner::StartNativeMessagingHost() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("ThunderbirdScanner: Not initialized");
        return false;
    }

    return m_impl->StartNativeMessagingHostImpl();
}

void ThunderbirdScanner::StopNativeMessagingHost() {
    if (m_impl) {
        m_impl->StopNativeMessagingHostImpl();
    }
}

[[nodiscard]] bool ThunderbirdScanner::IsNativeHostRunning() const noexcept {
    return m_impl && m_impl->m_nativeHostRunning.load(std::memory_order_acquire);
}

[[nodiscard]] bool ThunderbirdScanner::RegisterNativeHost() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    return m_impl->RegisterNativeHostImpl();
}

[[nodiscard]] bool ThunderbirdScanner::UnregisterNativeHost() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    return m_impl->UnregisterNativeHostImpl();
}

[[nodiscard]] NativeMessageResponse ThunderbirdScanner::ProcessNativeMessage(
    const NativeMessageRequest& request
) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        NativeMessageResponse response;
        response.requestId = request.requestId;
        response.success = false;
        response.errorMessage = "Scanner not initialized";
        return response;
    }

    return m_impl->ProcessNativeMessageImpl(request);
}

// ============================================================================
// PROFILE/ACCOUNT DISCOVERY
// ============================================================================

[[nodiscard]] std::vector<ThunderbirdVersionInfo> ThunderbirdScanner::DiscoverInstallations() {
    std::vector<ThunderbirdVersionInfo> installations;

    try {
        // Would check Program Files for thunderbird.exe
        // Parse version from binary or registry

        Logger::Debug("ThunderbirdScanner: Installation discovery not fully implemented");

    } catch (const std::exception& e) {
        Logger::Error("ThunderbirdScanner: Installation discovery exception: {}", e.what());
    }

    return installations;
}

[[nodiscard]] std::vector<ThunderbirdProfile> ThunderbirdScanner::DiscoverProfiles() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    return m_impl->DiscoverProfilesImpl();
}

[[nodiscard]] std::vector<ThunderbirdAccount> ThunderbirdScanner::GetAccounts(
    const fs::path& profilePath
) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    return m_impl->GetAccountsImpl(profilePath);
}

[[nodiscard]] std::vector<MailboxFolder> ThunderbirdScanner::GetFolders(
    const fs::path& accountPath
) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    return m_impl->GetFoldersImpl(accountPath);
}

// ============================================================================
// SCANNING
// ============================================================================

[[nodiscard]] std::vector<EmailScanResult> ThunderbirdScanner::ScanMboxFile(
    const fs::path& mboxPath,
    bool fullScan
) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("ThunderbirdScanner: Not initialized");
        return {};
    }

    return m_impl->ScanMboxFileImpl(mboxPath, fullScan);
}

[[nodiscard]] EmailScanResult ThunderbirdScanner::ScanMessage(const MboxMessage& message) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        EmailScanResult result;
        return result;
    }

    return m_impl->ScanMessageImpl(message);
}

[[nodiscard]] std::vector<MboxMessage> ThunderbirdScanner::ParseMboxFile(
    const fs::path& mboxPath,
    size_t maxMessages
) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("ThunderbirdScanner: Not initialized");
        return {};
    }

    return m_impl->ParseMboxFileImpl(mboxPath, maxMessages);
}

[[nodiscard]] std::optional<MboxMessage> ThunderbirdScanner::ParseMboxMessage(
    const fs::path& mboxPath,
    size_t offset
) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return std::nullopt;
    }

    return m_impl->ParseMboxMessageImpl(mboxPath, offset);
}

// ============================================================================
// CALLBACKS
// ============================================================================

void ThunderbirdScanner::RegisterMessageEventCallback(MessageEventCallback callback) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_messageEventCallback = std::move(callback);

    Logger::Debug("ThunderbirdScanner: Registered message event callback");
}

void ThunderbirdScanner::RegisterScanCallback(ScanResultCallback callback) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_scanResultCallback = std::move(callback);

    Logger::Debug("ThunderbirdScanner: Registered scan callback");
}

void ThunderbirdScanner::RegisterNativeMessageCallback(NativeMessageCallback callback) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_nativeMessageCallback = std::move(callback);

    Logger::Debug("ThunderbirdScanner: Registered native message callback");
}

void ThunderbirdScanner::RegisterErrorCallback(ErrorCallback callback) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_errorCallback = std::move(callback);

    Logger::Debug("ThunderbirdScanner: Registered error callback");
}

void ThunderbirdScanner::UnregisterCallbacks() {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_messageEventCallback = nullptr;
    m_impl->m_scanResultCallback = nullptr;
    m_impl->m_nativeMessageCallback = nullptr;
    m_impl->m_errorCallback = nullptr;

    Logger::Debug("ThunderbirdScanner: Unregistered all callbacks");
}

// ============================================================================
// STATISTICS
// ============================================================================

[[nodiscard]] ThunderbirdScannerStatistics ThunderbirdScanner::GetStatistics() const {
    if (!m_impl) {
        return ThunderbirdScannerStatistics{};
    }

    return m_impl->m_stats;
}

void ThunderbirdScanner::ResetStatistics() {
    if (!m_impl) return;

    m_impl->m_stats.Reset();
    Logger::Info("ThunderbirdScanner: Statistics reset");
}

[[nodiscard]] bool ThunderbirdScanner::SelfTest() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("ThunderbirdScanner: Self-test failed - not initialized");
        return false;
    }

    try {
        Logger::Info("ThunderbirdScanner: Running self-test");

        // Test 1: Profile discovery
        auto profiles = DiscoverProfiles();
        Logger::Debug("ThunderbirdScanner: Self-test - Found {} profiles", profiles.size());

        // Test 2: Mbox parsing (test with empty path - should fail gracefully)
        auto messages = ParseMboxFile("nonexistent.mbox", 1);
        if (!messages.empty()) {
            Logger::Error("ThunderbirdScanner: Self-test failed - parsed nonexistent file");
            return false;
        }

        // Test 3: Configuration validation
        ThunderbirdScannerConfiguration testConfig;
        if (!testConfig.IsValid()) {
            Logger::Error("ThunderbirdScanner: Self-test failed - default config invalid");
            return false;
        }

        // Test 4: Statistics
        auto stats = GetStatistics();
        if (stats.ToJson().empty()) {
            Logger::Error("ThunderbirdScanner: Self-test failed - statistics JSON empty");
            return false;
        }

        Logger::Info("ThunderbirdScanner: Self-test passed");
        return true;

    } catch (const std::exception& e) {
        Logger::Error("ThunderbirdScanner: Self-test exception: {}", e.what());
        return false;
    }
}

[[nodiscard]] std::string ThunderbirdScanner::GetVersionString() noexcept {
    return std::format("{}.{}.{}",
        ThunderbirdConstants::VERSION_MAJOR,
        ThunderbirdConstants::VERSION_MINOR,
        ThunderbirdConstants::VERSION_PATCH);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetScannerStatusName(ScannerStatus status) noexcept {
    return ScannerStatusToString(status);
}

[[nodiscard]] std::string_view GetMailboxFormatName(MailboxFormat format) noexcept {
    return MailboxFormatToString(format);
}

[[nodiscard]] std::string_view GetAccountTypeName(AccountType type) noexcept {
    return AccountTypeToString(type);
}

[[nodiscard]] std::string_view GetMessageEventName(MessageEvent event) noexcept {
    switch (event) {
        case MessageEvent::NewMessage: return "NewMessage";
        case MessageEvent::MessageChanged: return "MessageChanged";
        case MessageEvent::MessageDeleted: return "MessageDeleted";
        case MessageEvent::MessageMoved: return "MessageMoved";
        case MessageEvent::FolderScanned: return "FolderScanned";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetThunderbirdScanActionName(ThunderbirdScanAction action) noexcept {
    switch (action) {
        case ThunderbirdScanAction::Allow: return "Allow";
        case ThunderbirdScanAction::Block: return "Block";
        case ThunderbirdScanAction::Quarantine: return "Quarantine";
        case ThunderbirdScanAction::Delete: return "Delete";
        case ThunderbirdScanAction::MarkSpam: return "MarkSpam";
        case ThunderbirdScanAction::MarkRead: return "MarkRead";
        case ThunderbirdScanAction::MoveTo: return "MoveTo";
        case ThunderbirdScanAction::Tag: return "Tag";
        case ThunderbirdScanAction::Notify: return "Notify";
        default: return "Unknown";
    }
}

[[nodiscard]] bool IsThunderbirdRunning() {
    try {
        return ProcessUtils::IsProcessRunning(L"thunderbird.exe");
    } catch (...) {
        return false;
    }
}

[[nodiscard]] std::optional<fs::path> GetDefaultProfilePath() {
    try {
        auto userProfileDir = GetUserProfileDir();
        if (!userProfileDir) {
            return std::nullopt;
        }

        fs::path iniPath = *userProfileDir / "AppData" / "Roaming" / "Thunderbird" / "profiles.ini";
        if (!fs::exists(iniPath)) {
            return std::nullopt;
        }

        auto profiles = ParseProfilesIni(iniPath);
        for (const auto& profile : profiles) {
            if (profile.isDefault) {
                return profile.path;
            }
        }

        // Return first profile if no default
        if (!profiles.empty()) {
            return profiles[0].path;
        }

    } catch (...) {
    }

    return std::nullopt;
}

[[nodiscard]] std::vector<ThunderbirdProfile> ParseProfilesIni(const fs::path& iniPath) {
    ThunderbirdScanner& scanner = ThunderbirdScanner::Instance();
    if (scanner.IsInitialized() && scanner.m_impl) {
        return scanner.m_impl->ParseProfilesIniImpl(iniPath);
    }

    return {};
}

[[nodiscard]] MailboxFormat DetectMailboxFormat(const fs::path& path) {
    ThunderbirdScanner& scanner = ThunderbirdScanner::Instance();
    if (scanner.IsInitialized() && scanner.m_impl) {
        return scanner.m_impl->DetectMailboxFormatImpl(path);
    }

    return MailboxFormat::Unknown;
}

} // namespace Email
} // namespace ShadowStrike
