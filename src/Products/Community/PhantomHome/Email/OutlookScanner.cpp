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
 * ShadowStrike Email - OUTLOOK SCANNER IMPLEMENTATION
 * ============================================================================
 *
 * @file OutlookScanner.cpp
 * @brief Enterprise-grade Microsoft Outlook COM add-in integration for email security.
 *
 * This module implements comprehensive Outlook integration for real-time email
 * security scanning through COM add-in architecture, MAPI integration, and
 * event-driven malware detection.
 *
 * Architecture:
 * - COM add-in using IDTExtensibility2 interface
 * - MAPI (Messaging API) integration for deep mail access
 * - Event sink for mail events (NewMail, ItemSend, ItemAdd, etc.)
 * - Background scanning with EmailProtection integration
 * - Attachment extraction and analysis via AttachmentScanner
 * - Phishing detection via PhishingEmailDetector
 * - ThreatIntel integration for URL/domain IOCs
 * - DLP enforcement and policy-based blocking
 * - Callback architecture for real-time notifications
 *
 * Detection Capabilities:
 * - Inbound email scanning (NewMail, NewMailEx events)
 * - Outbound email scanning (ItemSend event with cancel capability)
 * - Attachment malware detection (file-based scanning)
 * - Link analysis and URL reputation checking
 * - Phishing email detection (content and sender analysis)
 * - Spam tagging and filtering
 * - Macro-enabled document detection
 * - DLP policy enforcement
 *
 * Actions:
 * - Block malicious emails (cancel send, delete)
 * - Move to Junk folder
 * - Strip dangerous attachments
 * - Tag subject line ([SPAM], [PHISHING], [BLOCKED])
 * - Quarantine threats
 * - User notification and prompts
 *
 * Supported Outlook Versions:
 * - Microsoft Outlook 2016 (minimum version 16)
 * - Microsoft Outlook 2019
 * - Microsoft Outlook 365
 * - Microsoft Outlook LTSC
 *
 * COM Event Handling:
 * - NewMail: Single mail notification (legacy)
 * - NewMailEx: Batch mail notification with EntryID collection
 * - ItemSend: Pre-send interception with cancel capability
 * - ItemAdd: Folder item addition notification
 * - ItemChange: Item modification notification
 * - BeforeDelete: Pre-delete interception
 * - AttachmentAdd: Attachment addition notification
 *
 * MITRE ATT&CK Coverage:
 * - T1566.001: Phishing: Spearphishing Attachment
 * - T1566.002: Phishing: Spearphishing Link
 * - T1204.001: User Execution: Malicious Link
 * - T1204.002: User Execution: Malicious File
 * - T1114: Email Collection
 * - T1048.003: Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "OutlookScanner.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "PhantomCore/Utils/FileUtils.hpp"
#include "PhantomCore/Utils/ProcessUtils.hpp"
#include "PhantomCore/Utils/SystemUtils.hpp"
#include "PhantomCore/Utils/CryptoUtils.hpp"
#include "PhantomCore/ThreatIntel/ThreatIntelLookup.hpp"
#include "PhantomCore/Whitelist/WhiteListStore.hpp"
#include "PhantomCore/HashStore/HashStore.hpp"
#include "EmailProtection.hpp"
#include "AttachmentScanner.hpp"
#include "PhishingEmailDetector.hpp"
#include "SpamDetector.hpp"

// ============================================================================
// SYSTEM INCLUDES
// ============================================================================
#include <Windows.h>
#include <comdef.h>
#include <comutil.h>
#include <objbase.h>
#include <ole2.h>
#include <oleauto.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <atlbase.h>       // For CComPtr, CComVariant, CComBSTR
#include <Sddl.h>          // For security descriptor creation
#include <random>

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <regex>
#include <unordered_set>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "psapi.lib")

namespace fs = std::filesystem;

namespace ShadowStrike {
namespace Email {

using namespace Utils;

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================
namespace {

    // Outlook dispatch IDs (DISPIDs) for common properties/methods
    constexpr DISPID DISPID_SUBJECT = 0x0037;
    constexpr DISPID DISPID_BODY = 0x9100;
    constexpr DISPID DISPID_HTMLBODY = 0x1013;
    constexpr DISPID DISPID_SENDEREMAIL = 0x0C1F;
    constexpr DISPID DISPID_SENDERNAME = 0x0042;
    constexpr DISPID DISPID_TO = 0x0E04;
    constexpr DISPID DISPID_CC = 0x0E03;
    constexpr DISPID DISPID_BCC = 0x0E02;
    constexpr DISPID DISPID_ATTACHMENTS = 0xF815;
    constexpr DISPID DISPID_ENTRYID = 0xF01E;
    constexpr DISPID DISPID_MESSAGECLASS = 0x001A;
    constexpr DISPID DISPID_RECEIVEDTIME = 0x0E06;
    constexpr DISPID DISPID_SENTTIME = 0x0039;
    constexpr DISPID DISPID_IMPORTANCE = 0x0017;
    constexpr DISPID DISPID_DELETE = 0xF04C;
    constexpr DISPID DISPID_MOVE = 0xF034;
    constexpr DISPID DISPID_SAVEAS = 0xF033;
    constexpr DISPID DISPID_SAVE = 0xF048;
    constexpr DISPID DISPID_COUNT = 0x50;
    constexpr DISPID DISPID_ITEM = 0x51;
    constexpr DISPID DISPID_FILENAME = 0x3704;
    constexpr DISPID DISPID_SAVEASFILE = 0xF035;
    constexpr DISPID DISPID_GETDEFAULTFOLDER = 0x109;
    constexpr DISPID DISPID_GETITEMFROMENTRYID = 0xF919;
    constexpr DISPID DISPID_SESSION = 0xF00B;

    // Outlook folder types
    constexpr int OL_FOLDER_JUNK_EMAIL = 23;

    // Dangerous file extensions
    const std::vector<std::wstring> DANGEROUS_EXTENSIONS = {
        L".exe", L".com", L".bat", L".cmd", L".scr", L".pif",
        L".vbs", L".js", L".jse", L".wsf", L".wsh",
        L".msi", L".msp", L".cpl", L".dll", L".sys",
        L".hta", L".reg", L".ps1", L".psm1",
        L".lnk", L".inf", L".ade", L".adp", L".app"
    };

    // Macro-enabled Office extensions
    const std::vector<std::wstring> MACRO_EXTENSIONS = {
        L".docm", L".dotm", L".xlsm", L".xltm", L".xlam",
        L".pptm", L".potm", L".ppam", L".ppsm", L".sldm"
    };

    // Generates a secure temp directory path with random component
    [[nodiscard]] fs::path GenerateSecureTempDir() {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> dist;
        
        std::wostringstream wss;
        wss << L"ShadowStrike_OutlookAttach_" << std::hex << dist(gen);
        
        return fs::temp_directory_path() / wss.str();
    }

    // RAII wrapper for Windows HANDLE
    class HandleGuard {
    public:
        explicit HandleGuard(HANDLE h = INVALID_HANDLE_VALUE) noexcept : m_handle(h) {}
        ~HandleGuard() noexcept { 
            if (m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr) {
                CloseHandle(m_handle);
            }
        }
        HandleGuard(const HandleGuard&) = delete;
        HandleGuard& operator=(const HandleGuard&) = delete;
        HandleGuard(HandleGuard&& other) noexcept : m_handle(other.m_handle) {
            other.m_handle = INVALID_HANDLE_VALUE;
        }
        HandleGuard& operator=(HandleGuard&& other) noexcept {
            if (this != &other) {
                if (m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr) {
                    CloseHandle(m_handle);
                }
                m_handle = other.m_handle;
                other.m_handle = INVALID_HANDLE_VALUE;
            }
            return *this;
        }
        [[nodiscard]] HANDLE get() const noexcept { return m_handle; }
        [[nodiscard]] bool valid() const noexcept { 
            return m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr;
        }
    private:
        HANDLE m_handle;
    };

    // Attachment staging directory (per-session, secured with restrictive ACL)
    const fs::path ATTACHMENT_TEMP_DIR = fs::temp_directory_path() / L"ShadowStrike_OutlookAttachments";

    // Maximum number of items to scan in a single folder pass
    constexpr size_t MAX_FOLDER_SCAN_ITEMS = 10000;

    // Maximum number of URLs to extract from a single email body
    constexpr size_t MAX_URL_EXTRACT_COUNT = 500;

    // DISPID for Outlook.Application.Version property
    constexpr DISPID DISPID_VERSION = 0xF057;

    // Outlook folder type IDs for GetDefaultFolder
    constexpr int OL_FOLDER_INBOX = 6;
    constexpr int OL_FOLDER_SENT_MAIL = 5;
    constexpr int OL_FOLDER_OUTBOX = 4;
    constexpr int OL_FOLDER_DELETED_ITEMS = 3;
    constexpr int OL_FOLDER_DRAFTS = 16;

    // Outlook property DISPIDs for folder Items collection
    constexpr DISPID DISPID_ITEMS = 0xF00E;
    constexpr DISPID DISPID_FOLDERS = 0xF00F;
    constexpr DISPID DISPID_FOLDERPATH = 0x66B5;
    constexpr DISPID DISPID_FOLDERNAME = 0x3001;

    // Extract URLs from text/HTML content using regex
    [[nodiscard]] static std::vector<std::string> ExtractUrlsFromText(const std::string& text) {
        std::vector<std::string> urls;
        if (text.empty()) return urls;

        try {
            // Match http/https URLs - deliberately broad to catch obfuscated variants
            static const std::regex urlPattern(
                R"(https?://[^\s"'<>\)\]\}]{4,2048})",
                std::regex::optimize | std::regex::icase);

            auto begin = std::sregex_iterator(text.begin(), text.end(), urlPattern);
            auto end = std::sregex_iterator();

            for (auto it = begin; it != end && urls.size() < MAX_URL_EXTRACT_COUNT; ++it) {
                std::string url = it->str();
                // Trim trailing punctuation that's likely not part of the URL
                while (!url.empty() && (url.back() == '.' || url.back() == ',' ||
                       url.back() == ';' || url.back() == ')')) {
                    url.pop_back();
                }
                if (!url.empty()) {
                    urls.push_back(std::move(url));
                }
            }
        } catch (const std::regex_error& e) {
            Logger::Error("ExtractUrlsFromText: regex error: {}", e.what());
        }

        return urls;
    }

    // Extract domain from email address (e.g., "user@example.com" → "example.com")
    [[nodiscard]] static std::string ExtractDomainFromEmail(const std::string& email) {
        auto atPos = email.rfind('@');
        if (atPos == std::string::npos || atPos + 1 >= email.size()) {
            return {};
        }
        return email.substr(atPos + 1);
    }

    // Map OutlookFolderType to Outlook OlDefaultFolders constant
    [[nodiscard]] static int FolderTypeToOlFolder(OutlookFolderType type) noexcept {
        switch (type) {
            case OutlookFolderType::Inbox:        return OL_FOLDER_INBOX;
            case OutlookFolderType::SentItems:    return OL_FOLDER_SENT_MAIL;
            case OutlookFolderType::Drafts:       return OL_FOLDER_DRAFTS;
            case OutlookFolderType::Outbox:       return OL_FOLDER_OUTBOX;
            case OutlookFolderType::DeletedItems:  return OL_FOLDER_DELETED_ITEMS;
            case OutlookFolderType::JunkEmail:    return OL_FOLDER_JUNK_EMAIL;
            default:                               return -1;
        }
    }

} // anonymous namespace

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

[[nodiscard]] static inline std::string ToLowerCopy(std::string_view s) noexcept {
    std::string r(s);
    for (auto& c : r) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return r;
}

[[nodiscard]] static inline std::string SanitizeForJson(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) { /* skip control chars */ }
                else out += static_cast<char>(c);
        }
    }
    return out;
}

[[nodiscard]] static bool IsDangerousExtension(const std::wstring& filename) noexcept {
    std::wstring lowerFilename = StringUtils::ToLowerCopy(filename);

    for (const auto& ext : DANGEROUS_EXTENSIONS) {
        if (lowerFilename.ends_with(ext)) {
            return true;
        }
    }

    return false;
}

[[nodiscard]] static bool IsMacroEnabled(const std::wstring& filename) noexcept {
    std::wstring lowerFilename = StringUtils::ToLowerCopy(filename);

    for (const auto& ext : MACRO_EXTENSIONS) {
        if (lowerFilename.ends_with(ext)) {
            return true;
        }
    }

    return false;
}

// Check if sender domain is in the trusted senders list
[[nodiscard]] static bool IsSafeSenderDomain(
    const std::string& senderEmail,
    const std::vector<std::string>& trustedSenders) noexcept {

    if (senderEmail.empty() || trustedSenders.empty()) return false;

    std::string domain = ExtractDomainFromEmail(senderEmail);
    if (domain.empty()) return false;

    std::string lowerDomain = ToLowerCopy(domain);
    std::string lowerEmail = ToLowerCopy(senderEmail);

    for (const auto& trusted : trustedSenders) {
        std::string lowerTrusted = ToLowerCopy(trusted);

        // Match full email address
        if (lowerTrusted == lowerEmail) return true;

        // Match domain (trusted entry might be "@domain.com" or just "domain.com")
        std::string trustedDomain = lowerTrusted;
        if (!trustedDomain.empty() && trustedDomain.front() == '@') {
            trustedDomain = trustedDomain.substr(1);
        }

        if (lowerDomain == trustedDomain) return true;

        // Match subdomain (e.g., "mail.example.com" matches "example.com")
        if (lowerDomain.size() > trustedDomain.size() + 1) {
            if (lowerDomain.ends_with("." + trustedDomain)) return true;
        }
    }

    return false;
}

[[nodiscard]] static std::string GenerateEventId() {
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dist;

    std::ostringstream oss;
    oss << "MAIL-" << std::hex << std::setfill('0') << std::setw(16) << timestamp
        << "-" << std::setw(8) << dist(gen);
    return oss.str();
}

// Escape a string for JSON output
[[nodiscard]] static std::string JsonEscape(const std::string& str) {
    std::ostringstream oss;
    for (char c : str) {
        switch (c) {
            case '"':  oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\b': oss << "\\b"; break;
            case '\f': oss << "\\f"; break;
            case '\n': oss << "\\n"; break;
            case '\r': oss << "\\r"; break;
            case '\t': oss << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    oss << "\\u" << std::hex << std::setfill('0') << std::setw(4)
                        << static_cast<int>(static_cast<unsigned char>(c));
                } else {
                    oss << c;
                }
        }
    }
    return oss.str();
}

// Helper to read a string property from IDispatch using DISPID
[[nodiscard]] static std::optional<std::string> GetDispatchStringProperty(
    IDispatch* pDispatch, DISPID dispId) {
    
    if (!pDispatch) return std::nullopt;

    DISPPARAMS dpNoArgs = {nullptr, nullptr, 0, 0};
    CComVariant varResult;
    EXCEPINFO excepInfo{};
    UINT argErr = 0;

    HRESULT hr = pDispatch->Invoke(
        dispId,
        IID_NULL,
        LOCALE_USER_DEFAULT,
        DISPATCH_PROPERTYGET,
        &dpNoArgs,
        &varResult,
        &excepInfo,
        &argErr);

    if (FAILED(hr)) {
        return std::nullopt;
    }

    if (varResult.vt == VT_BSTR && varResult.bstrVal != nullptr) {
        return StringUtils::ToNarrow(std::wstring(varResult.bstrVal, SysStringLen(varResult.bstrVal)));
    }

    return std::nullopt;
}

// Helper to read an int property from IDispatch using DISPID
[[nodiscard]] static std::optional<int> GetDispatchIntProperty(
    IDispatch* pDispatch, DISPID dispId) {
    
    if (!pDispatch) return std::nullopt;

    DISPPARAMS dpNoArgs = {nullptr, nullptr, 0, 0};
    CComVariant varResult;
    EXCEPINFO excepInfo{};
    UINT argErr = 0;

    HRESULT hr = pDispatch->Invoke(
        dispId,
        IID_NULL,
        LOCALE_USER_DEFAULT,
        DISPATCH_PROPERTYGET,
        &dpNoArgs,
        &varResult,
        &excepInfo,
        &argErr);

    if (FAILED(hr)) {
        return std::nullopt;
    }

    if (SUCCEEDED(varResult.ChangeType(VT_I4))) {
        return varResult.intVal;
    }

    return std::nullopt;
}

// Helper to get IDispatch property that returns an object
[[nodiscard]] static CComPtr<IDispatch> GetDispatchObjectProperty(
    IDispatch* pDispatch, DISPID dispId) {
    
    if (!pDispatch) return nullptr;

    DISPPARAMS dpNoArgs = {nullptr, nullptr, 0, 0};
    CComVariant varResult;
    EXCEPINFO excepInfo{};
    UINT argErr = 0;

    HRESULT hr = pDispatch->Invoke(
        dispId,
        IID_NULL,
        LOCALE_USER_DEFAULT,
        DISPATCH_PROPERTYGET,
        &dpNoArgs,
        &varResult,
        &excepInfo,
        &argErr);

    if (FAILED(hr) || varResult.vt != VT_DISPATCH || varResult.pdispVal == nullptr) {
        return nullptr;
    }

    CComPtr<IDispatch> pResult;
    pResult.Attach(varResult.pdispVal);
    varResult.vt = VT_EMPTY;  // Prevent VariantClear from releasing
    return pResult;
}

// Call a method with no arguments on IDispatch
[[nodiscard]] static bool InvokeDispatchMethod(IDispatch* pDispatch, DISPID dispId) {
    if (!pDispatch) return false;

    DISPPARAMS dpNoArgs = {nullptr, nullptr, 0, 0};
    CComVariant varResult;
    EXCEPINFO excepInfo{};
    UINT argErr = 0;

    HRESULT hr = pDispatch->Invoke(
        dispId,
        IID_NULL,
        LOCALE_USER_DEFAULT,
        DISPATCH_METHOD,
        &dpNoArgs,
        &varResult,
        &excepInfo,
        &argErr);

    return SUCCEEDED(hr);
}

// Set a string property on IDispatch
[[nodiscard]] static bool SetDispatchStringProperty(
    IDispatch* pDispatch, DISPID dispId, const std::wstring& value) {
    
    if (!pDispatch) return false;

    CComBSTR bstrValue(value.c_str());
    CComVariant varArg(bstrValue);
    DISPID dispIdNamed = DISPID_PROPERTYPUT;
    DISPPARAMS dp = {&varArg, &dispIdNamed, 1, 1};
    EXCEPINFO excepInfo{};
    UINT argErr = 0;

    HRESULT hr = pDispatch->Invoke(
        dispId,
        IID_NULL,
        LOCALE_USER_DEFAULT,
        DISPATCH_PROPERTYPUT,
        &dp,
        nullptr,
        &excepInfo,
        &argErr);

    return SUCCEEDED(hr);
}

// Get item from collection by 1-based index
[[nodiscard]] static CComPtr<IDispatch> GetCollectionItem(IDispatch* pCollection, int index) {
    if (!pCollection) return nullptr;

    CComVariant varIndex(index);
    DISPPARAMS dp = {&varIndex, nullptr, 1, 0};
    CComVariant varResult;
    EXCEPINFO excepInfo{};
    UINT argErr = 0;

    HRESULT hr = pCollection->Invoke(
        DISPID_ITEM,
        IID_NULL,
        LOCALE_USER_DEFAULT,
        DISPATCH_METHOD | DISPATCH_PROPERTYGET,
        &dp,
        &varResult,
        &excepInfo,
        &argErr);

    if (FAILED(hr) || varResult.vt != VT_DISPATCH || varResult.pdispVal == nullptr) {
        return nullptr;
    }

    CComPtr<IDispatch> pItem;
    pItem.Attach(varResult.pdispVal);
    varResult.vt = VT_EMPTY;
    return pItem;
}

// Get item from namespace by EntryID
[[nodiscard]] static CComPtr<IDispatch> GetItemFromEntryId(
    IDispatch* pNamespace, const std::string& entryId) {
    
    if (!pNamespace || entryId.empty()) return nullptr;

    std::wstring wEntryId = StringUtils::ToWide(entryId);
    CComBSTR bstrEntryId(wEntryId.c_str());
    CComVariant varEntryId(bstrEntryId);
    DISPPARAMS dp = {&varEntryId, nullptr, 1, 0};
    CComVariant varResult;
    EXCEPINFO excepInfo{};
    UINT argErr = 0;

    HRESULT hr = pNamespace->Invoke(
        DISPID_GETITEMFROMENTRYID,
        IID_NULL,
        LOCALE_USER_DEFAULT,
        DISPATCH_METHOD,
        &dp,
        &varResult,
        &excepInfo,
        &argErr);

    if (FAILED(hr) || varResult.vt != VT_DISPATCH || varResult.pdispVal == nullptr) {
        return nullptr;
    }

    CComPtr<IDispatch> pItem;
    pItem.Attach(varResult.pdispVal);
    varResult.vt = VT_EMPTY;
    return pItem;
}

// Get default folder by type
[[nodiscard]] static CComPtr<IDispatch> GetDefaultFolder(
    IDispatch* pNamespace, int folderType) {
    
    if (!pNamespace) return nullptr;

    CComVariant varFolderType(folderType);
    DISPPARAMS dp = {&varFolderType, nullptr, 1, 0};
    CComVariant varResult;
    EXCEPINFO excepInfo{};
    UINT argErr = 0;

    HRESULT hr = pNamespace->Invoke(
        DISPID_GETDEFAULTFOLDER,
        IID_NULL,
        LOCALE_USER_DEFAULT,
        DISPATCH_METHOD,
        &dp,
        &varResult,
        &excepInfo,
        &argErr);

    if (FAILED(hr) || varResult.vt != VT_DISPATCH || varResult.pdispVal == nullptr) {
        return nullptr;
    }

    CComPtr<IDispatch> pFolder;
    pFolder.Attach(varResult.pdispVal);
    varResult.vt = VT_EMPTY;
    return pFolder;
}

// Move mail item to folder
[[nodiscard]] static bool MoveMailItemToFolder(IDispatch* pMailItem, IDispatch* pFolder) {
    if (!pMailItem || !pFolder) return false;

    CComVariant varFolder(pFolder);
    DISPPARAMS dp = {&varFolder, nullptr, 1, 0};
    CComVariant varResult;
    EXCEPINFO excepInfo{};
    UINT argErr = 0;

    HRESULT hr = pMailItem->Invoke(
        DISPID_MOVE,
        IID_NULL,
        LOCALE_USER_DEFAULT,
        DISPATCH_METHOD,
        &dp,
        &varResult,
        &excepInfo,
        &argErr);

    return SUCCEEDED(hr);
}

// Save attachment to file
[[nodiscard]] static bool SaveAttachmentToFile(
    IDispatch* pAttachment, const std::wstring& filePath) {
    
    if (!pAttachment) return false;

    CComBSTR bstrPath(filePath.c_str());
    CComVariant varPath(bstrPath);
    DISPPARAMS dp = {&varPath, nullptr, 1, 0};
    EXCEPINFO excepInfo{};
    UINT argErr = 0;

    HRESULT hr = pAttachment->Invoke(
        DISPID_SAVEASFILE,
        IID_NULL,
        LOCALE_USER_DEFAULT,
        DISPATCH_METHOD,
        &dp,
        nullptr,
        &excepInfo,
        &argErr);

    return SUCCEEDED(hr);
}

// Create secure temp directory with restricted ACLs
[[nodiscard]] static std::optional<fs::path> CreateSecureTempDirectory() {
    try {
        fs::path tempDir = GenerateSecureTempDir();
        
        // Create the directory
        if (!fs::create_directories(tempDir)) {
            if (!fs::exists(tempDir)) {
                Logger::Error("OutlookScanner: Failed to create temp directory: {}", StringUtils::ToNarrow(tempDir.wstring()));
                return std::nullopt;
            }
        }

        // Set restrictive ACL (owner-only access)
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = FALSE;

        // SDDL: D:P(A;OICI;GA;;;BA)(A;OICI;GA;;;SY)(A;OICI;GA;;;CO)
        // Deny access to everyone except BUILTIN\Administrators, SYSTEM, and Creator Owner
        PSECURITY_DESCRIPTOR pSD = nullptr;
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;OICI;GA;;;BA)(A;OICI;GA;;;SY)(A;OICI;GA;;;CO)",
                SDDL_REVISION_1,
                &pSD,
                nullptr)) {
            
            SetFileSecurityW(tempDir.c_str(), DACL_SECURITY_INFORMATION, pSD);
            LocalFree(pSD);
        }

        return tempDir;

    } catch (const std::exception& e) {
        Logger::Error("OutlookScanner: CreateSecureTempDirectory failed: {}", e.what());
        return std::nullopt;
    }
}

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] std::string OutlookVersionInfo::ToString() const {
    std::ostringstream oss;
    oss << productName << " " << majorVersion << "." << minorVersion
        << " (Build " << buildNumber << ")";
    if (is64Bit) oss << " [64-bit]";
    if (isOffice365) oss << " [Office 365]";
    return oss.str();
}

[[nodiscard]] std::string MailItemInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"entryId\": \"" << entryId << "\",\n";
    oss << "  \"messageClass\": \"" << messageClass << "\",\n";
    oss << "  \"subject\": \"" << SanitizeForJson(subject) << "\",\n";
    oss << "  \"senderEmail\": \"" << senderEmail << "\",\n";
    oss << "  \"senderName\": \"" << SanitizeForJson(senderName) << "\",\n";
    oss << "  \"attachmentCount\": " << attachmentCount << ",\n";
    oss << "  \"hasAttachments\": " << (hasAttachments ? "true" : "false") << ",\n";
    oss << "  \"importance\": " << importance << ",\n";
    oss << "  \"isRead\": " << (isRead ? "true" : "false") << "\n";
    oss << "}";
    return oss.str();
}

[[nodiscard]] std::string FolderInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"entryId\": \"" << entryId << "\",\n";
    oss << "  \"name\": \"" << name << "\",\n";
    oss << "  \"path\": \"" << path << "\",\n";
    oss << "  \"type\": \"" << GetFolderTypeName(type) << "\",\n";
    oss << "  \"itemCount\": " << itemCount << ",\n";
    oss << "  \"unreadCount\": " << unreadCount << ",\n";
    oss << "  \"isMonitored\": " << (isMonitored ? "true" : "false") << "\n";
    oss << "}";
    return oss.str();
}

[[nodiscard]] std::string MailScanEvent::ToJson() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"eventId\": \"" << eventId << "\",\n";
    oss << "  \"mailItem\": " << mailItem.ToJson() << ",\n";
    oss << "  \"eventType\": \"" << GetMailEventTypeName(eventType) << "\",\n";
    oss << "  \"actionTaken\": \"" << GetOutlookScanActionName(actionTaken) << "\",\n";
    oss << "  \"scanDurationUs\": " << scanDuration.count() << "\n";
    oss << "}";
    return oss.str();
}

void OutlookScannerStatistics::Reset() noexcept {
    totalScanned = 0;
    newMailScanned = 0;
    outboundScanned = 0;
    threatsDetected = 0;
    malwareBlocked = 0;
    phishingBlocked = 0;
    spamTagged = 0;
    attachmentsStripped = 0;
    sendBlocked = 0;
    allowed = 0;
    quarantined = 0;
    scanErrors = 0;
    for (auto& counter : byEventType) {
        counter = 0;
    }
    startTime = Clock::now();
}

[[nodiscard]] std::string OutlookScannerStatistics::ToJson() const {
    auto now = Clock::now();
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - startTime);

    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"totalScanned\": " << totalScanned.load() << ",\n";
    oss << "  \"newMailScanned\": " << newMailScanned.load() << ",\n";
    oss << "  \"outboundScanned\": " << outboundScanned.load() << ",\n";
    oss << "  \"threatsDetected\": " << threatsDetected.load() << ",\n";
    oss << "  \"malwareBlocked\": " << malwareBlocked.load() << ",\n";
    oss << "  \"phishingBlocked\": " << phishingBlocked.load() << ",\n";
    oss << "  \"spamTagged\": " << spamTagged.load() << ",\n";
    oss << "  \"attachmentsStripped\": " << attachmentsStripped.load() << ",\n";
    oss << "  \"sendBlocked\": " << sendBlocked.load() << ",\n";
    oss << "  \"allowed\": " << allowed.load() << ",\n";
    oss << "  \"quarantined\": " << quarantined.load() << ",\n";
    oss << "  \"scanErrors\": " << scanErrors.load() << ",\n";
    oss << "  \"uptimeSeconds\": " << uptime.count() << "\n";
    oss << "}";
    return oss.str();
}

[[nodiscard]] OutlookScannerStatisticsSnapshot OutlookScannerStatistics::ToSnapshot() const noexcept {
    OutlookScannerStatisticsSnapshot snapshot;
    snapshot.totalScanned = totalScanned.load(std::memory_order_relaxed);
    snapshot.newMailScanned = newMailScanned.load(std::memory_order_relaxed);
    snapshot.outboundScanned = outboundScanned.load(std::memory_order_relaxed);
    snapshot.threatsDetected = threatsDetected.load(std::memory_order_relaxed);
    snapshot.malwareBlocked = malwareBlocked.load(std::memory_order_relaxed);
    snapshot.phishingBlocked = phishingBlocked.load(std::memory_order_relaxed);
    snapshot.spamTagged = spamTagged.load(std::memory_order_relaxed);
    snapshot.attachmentsStripped = attachmentsStripped.load(std::memory_order_relaxed);
    snapshot.sendBlocked = sendBlocked.load(std::memory_order_relaxed);
    snapshot.allowed = allowed.load(std::memory_order_relaxed);
    snapshot.quarantined = quarantined.load(std::memory_order_relaxed);
    snapshot.scanErrors = scanErrors.load(std::memory_order_relaxed);
    for (size_t i = 0; i < byEventType.size(); ++i) {
        snapshot.byEventType[i] = byEventType[i].load(std::memory_order_relaxed);
    }
    snapshot.startTime = startTime;
    return snapshot;
}

[[nodiscard]] std::string OutlookScannerStatisticsSnapshot::ToJson() const {
    auto now = Clock::now();
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - startTime);

    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"totalScanned\": " << totalScanned << ",\n";
    oss << "  \"newMailScanned\": " << newMailScanned << ",\n";
    oss << "  \"outboundScanned\": " << outboundScanned << ",\n";
    oss << "  \"threatsDetected\": " << threatsDetected << ",\n";
    oss << "  \"malwareBlocked\": " << malwareBlocked << ",\n";
    oss << "  \"phishingBlocked\": " << phishingBlocked << ",\n";
    oss << "  \"spamTagged\": " << spamTagged << ",\n";
    oss << "  \"attachmentsStripped\": " << attachmentsStripped << ",\n";
    oss << "  \"sendBlocked\": " << sendBlocked << ",\n";
    oss << "  \"allowed\": " << allowed << ",\n";
    oss << "  \"quarantined\": " << quarantined << ",\n";
    oss << "  \"scanErrors\": " << scanErrors << ",\n";
    oss << "  \"uptimeSeconds\": " << uptime.count() << "\n";
    oss << "}";
    return oss.str();
}

[[nodiscard]] bool OutlookScannerConfiguration::IsValid() const noexcept {
    if (scanTimeoutMs == 0 || scanTimeoutMs > 300000) return false;
    if (maxAttachmentSize == 0 || maxAttachmentSize > 1024ULL * 1024 * 1024) return false;
    return true;
}

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class OutlookScannerImpl final {
public:
    OutlookScannerImpl() = default;
    ~OutlookScannerImpl() = default;

    // Delete copy/move
    OutlookScannerImpl(const OutlookScannerImpl&) = delete;
    OutlookScannerImpl& operator=(const OutlookScannerImpl&) = delete;
    OutlookScannerImpl(OutlookScannerImpl&&) = delete;
    OutlookScannerImpl& operator=(OutlookScannerImpl&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const OutlookScannerConfiguration& config) {
        std::unique_lock lock(m_mutex);

        try {
            if (!config.IsValid()) {
                Logger::Error("OutlookScanner: Invalid configuration");
                return false;
            }

            m_config = config;
            m_status = ModuleStatus::Initializing;

            // Initialize COM
            HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
            if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
                Logger::Error("OutlookScanner: CoInitializeEx failed: 0x{:X}", hr);
                return false;
            }
            m_comInitialized = true;

            // Create temp directory for attachments
            if (!fs::exists(ATTACHMENT_TEMP_DIR)) {
                fs::create_directories(ATTACHMENT_TEMP_DIR);
            }

            m_initialized = true;
            m_status = ModuleStatus::Stopped;

            Logger::Info("OutlookScanner initialized (scanInbound={}, scanOutbound={}, scanAttachments={})",
                config.scanInbound, config.scanOutbound, config.scanAttachments);

            return true;

        } catch (const std::exception& e) {
            Logger::Error("OutlookScanner initialization failed: {}", e.what());
            m_status = ModuleStatus::Error;
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_mutex);

        try {
            if (m_addinStatus == AddinStatus::Connected) {
                DisconnectFromOutlookInternal();
            }

            m_mailEventCallbacks.clear();
            m_scanCallbacks.clear();
            m_blockCallbacks.clear();
            m_preSendCallbacks.clear();
            m_errorCallbacks.clear();

            m_monitoredFolders.clear();

            // Clean up temp directory
            if (fs::exists(ATTACHMENT_TEMP_DIR)) {
                try {
                    fs::remove_all(ATTACHMENT_TEMP_DIR);
                } catch (...) {}
            }

            if (m_comInitialized) {
                CoUninitialize();
                m_comInitialized = false;
            }

            m_initialized = false;
            m_status = ModuleStatus::Uninitialized;
            m_addinStatus = AddinStatus::Disconnected;

            Logger::Info("OutlookScanner shutdown complete");

        } catch (...) {
            // Suppress all exceptions
        }
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_initialized;
    }

    [[nodiscard]] ModuleStatus GetStatus() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_status;
    }

    [[nodiscard]] AddinStatus GetAddinStatus() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_addinStatus;
    }

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    [[nodiscard]] bool UpdateConfiguration(const OutlookScannerConfiguration& config) {
        std::unique_lock lock(m_mutex);

        if (!config.IsValid()) {
            Logger::Error("UpdateConfiguration: Invalid configuration");
            return false;
        }

        m_config = config;
        Logger::Info("OutlookScanner configuration updated");
        return true;
    }

    [[nodiscard]] OutlookScannerConfiguration GetConfiguration() const {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    // ========================================================================
    // ADD-IN OPERATIONS
    // ========================================================================

    [[nodiscard]] bool InitializeAddin() {
        std::unique_lock lock(m_mutex);

        try {
            if (!m_initialized) {
                Logger::Error("Cannot initialize add-in: not initialized");
                return false;
            }

            m_addinStatus = AddinStatus::Initializing;

            // Register ShadowStrike COM add-in ProgID in HKCU for the current user.
            // This allows Outlook to discover and load our security add-in on startup.
            HKEY hKey = nullptr;
            const std::wstring regPath =
                L"SOFTWARE\\Microsoft\\Office\\Outlook\\Addins\\"
                + StringUtils::ToWide(OutlookConstants::ADDIN_PROGID);

            LONG result = RegCreateKeyExW(
                HKEY_CURRENT_USER,
                regPath.c_str(),
                0, nullptr,
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                nullptr,
                &hKey,
                nullptr);

            if (result != ERROR_SUCCESS) {
                Logger::Error("OutlookScanner: Failed to create add-in registry key (error={})", result);
                m_addinStatus = AddinStatus::Error;
                return false;
            }

            // Set FriendlyName
            std::wstring friendlyName = StringUtils::ToWide(OutlookConstants::ADDIN_NAME);
            RegSetValueExW(hKey, L"FriendlyName", 0, REG_SZ,
                reinterpret_cast<const BYTE*>(friendlyName.c_str()),
                static_cast<DWORD>((friendlyName.size() + 1) * sizeof(wchar_t)));

            // Set LoadBehavior = 3 (load at startup)
            DWORD loadBehavior = 3;
            RegSetValueExW(hKey, L"LoadBehavior", 0, REG_DWORD,
                reinterpret_cast<const BYTE*>(&loadBehavior), sizeof(DWORD));

            // Set Description
            std::wstring description = L"ShadowStrike Email Security Scanner";
            RegSetValueExW(hKey, L"Description", 0, REG_SZ,
                reinterpret_cast<const BYTE*>(description.c_str()),
                static_cast<DWORD>((description.size() + 1) * sizeof(wchar_t)));

            RegCloseKey(hKey);

            m_addinStatus = AddinStatus::Ready;

            Logger::Info("OutlookScanner add-in initialized and registered (ProgID={})",
                OutlookConstants::ADDIN_PROGID);
            return true;

        } catch (const std::exception& e) {
            Logger::Error("Add-in initialization failed: {}", e.what());
            m_addinStatus = AddinStatus::Error;
            return false;
        }
    }

    [[nodiscard]] bool ShutdownAddin() {
        std::unique_lock lock(m_mutex);

        try {
            if (m_addinStatus == AddinStatus::Connected) {
                DisconnectFromOutlookInternal();
            }

            m_addinStatus = AddinStatus::Disconnected;

            Logger::Info("OutlookScanner add-in shutdown");
            return true;

        } catch (const std::exception& e) {
            Logger::Error("Add-in shutdown failed: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool ConnectToOutlook() {
        std::unique_lock lock(m_mutex);

        try {
            if (m_addinStatus == AddinStatus::Connected) {
                return true;
            }

            m_addinStatus = AddinStatus::Connecting;

            CLSID clsid;
            HRESULT hr = CLSIDFromProgID(L"Outlook.Application", &clsid);
            if (FAILED(hr)) {
                Logger::Error("OutlookScanner: Failed to get Outlook CLSID: 0x{:X}", hr);
                m_addinStatus = AddinStatus::Error;
                return false;
            }

            // Attempt to attach to a running Outlook instance first
            CComPtr<IUnknown> pUnknown;
            hr = GetActiveObject(clsid, nullptr, &pUnknown);

            if (SUCCEEDED(hr) && pUnknown) {
                hr = pUnknown->QueryInterface(IID_IDispatch,
                    reinterpret_cast<void**>(&m_pOutlookApp.p));
            } else {
                // No running instance — create one via COM local server
                hr = CoCreateInstance(clsid, nullptr, CLSCTX_LOCAL_SERVER,
                    IID_IDispatch, reinterpret_cast<void**>(&m_pOutlookApp.p));
            }

            if (FAILED(hr) || !m_pOutlookApp) {
                Logger::Warn("OutlookScanner: Could not connect to Outlook instance (0x{:X})", hr);
                m_pOutlookApp.Release();
                m_addinStatus = AddinStatus::Disconnected;
                return false;
            }

            // Obtain the MAPI Namespace (Session property on Application)
            m_pNamespace = GetDispatchObjectProperty(m_pOutlookApp, DISPID_SESSION);
            if (!m_pNamespace) {
                Logger::Error("OutlookScanner: Failed to obtain MAPI Namespace from Outlook.Application");
                m_pOutlookApp.Release();
                m_addinStatus = AddinStatus::Error;
                return false;
            }

            // Pre-cache the Junk Email folder for quarantine operations
            m_pJunkFolder = GetDefaultFolder(m_pNamespace, OL_FOLDER_JUNK_EMAIL);
            if (!m_pJunkFolder) {
                Logger::Warn("OutlookScanner: Could not obtain Junk Email folder — quarantine will be unavailable");
            }

            m_addinStatus = AddinStatus::Connected;
            m_status = ModuleStatus::Running;

            Logger::Info("Connected to Outlook Application instance via COM");
            return true;

        } catch (const std::exception& e) {
            Logger::Error("Connect to Outlook failed: {}", e.what());
            m_pOutlookApp.Release();
            m_pNamespace.Release();
            m_pJunkFolder.Release();
            m_addinStatus = AddinStatus::Error;
            return false;
        }
    }

    void DisconnectFromOutlook() {
        std::unique_lock lock(m_mutex);
        DisconnectFromOutlookInternal();
    }

    [[nodiscard]] bool IsConnected() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_addinStatus == AddinStatus::Connected;
    }

    [[nodiscard]] OutlookVersionInfo GetOutlookVersion() const {
        std::shared_lock lock(m_mutex);

        OutlookVersionInfo version;

        try {
            version.productName = "Microsoft Outlook";
            version.is64Bit = (sizeof(void*) == 8);
            {
                SystemUtils::OSVersion osVer{};
                if (SystemUtils::QueryOSVersion(osVer)) {
                    version.is64Bit = osVer.is64BitOS;
                }
            }
            version.isOffice365 = false;
            version.licenseType = "Unknown";

            if (!m_pOutlookApp) {
                Logger::Warn("GetOutlookVersion: Not connected to Outlook, returning defaults");
                return version;
            }

            // Query Outlook.Application.Version property (returns string like "16.0.17928.20114")
            auto versionStr = GetDispatchStringProperty(m_pOutlookApp, DISPID_VERSION);
            if (versionStr.has_value() && !versionStr->empty()) {
                // Parse "major.minor.build.revision"
                std::istringstream iss(versionStr.value());
                std::string token;

                if (std::getline(iss, token, '.')) {
                    version.majorVersion = static_cast<uint32_t>(std::stoul(token));
                }
                if (std::getline(iss, token, '.')) {
                    version.minorVersion = static_cast<uint32_t>(std::stoul(token));
                }
                if (std::getline(iss, token, '.')) {
                    version.buildNumber = static_cast<uint32_t>(std::stoul(token));
                }

                // Office 365 / Microsoft 365 builds have high build numbers (>10000)
                if (version.majorVersion == 16 && version.buildNumber >= 10000) {
                    version.isOffice365 = true;
                }

                Logger::Debug("OutlookScanner: Detected Outlook version: {}.{} (Build {})",
                    version.majorVersion, version.minorVersion, version.buildNumber);
            } else {
                Logger::Warn("GetOutlookVersion: Could not read Version property from Outlook.Application");
                version.majorVersion = 16;
            }

        } catch (const std::exception& e) {
            Logger::Error("GetOutlookVersion - Exception: {}", e.what());
        }

        return version;
    }

    // ========================================================================
    // EVENT HANDLERS
    // ========================================================================

    void OnNewMail(void* pDispatchMailItem) {
        try {
            if (!m_config.enabled || !m_config.scanInbound) return;

            m_stats.newMailScanned++;
            m_stats.totalScanned++;
            m_stats.byEventType[static_cast<size_t>(MailEventType::NewMail)]++;

            auto* pDisp = static_cast<IDispatch*>(pDispatchMailItem);
            auto mailInfo = ExtractMailItemInfo(pDisp);
            if (!mailInfo.has_value()) {
                Logger::Error("OnNewMail: Failed to extract mail item info");
                m_stats.scanErrors++;
                return;
            }

            ProcessMailEvent(mailInfo.value(), MailEventType::NewMail, pDisp);

        } catch (const std::exception& e) {
            Logger::Error("OnNewMail - Exception: {}", e.what());
            m_stats.scanErrors++;
        }
    }

    void OnNewMailEx(const std::string& entryIdCollection) {
        try {
            if (!m_config.enabled || !m_config.scanInbound) return;

            auto entryIds = ParseEntryIdCollection(entryIdCollection);

            for (const auto& entryId : entryIds) {
                m_stats.newMailScanned++;
                m_stats.totalScanned++;
                m_stats.byEventType[static_cast<size_t>(MailEventType::NewMail)]++;

                // Retrieve the MailItem by EntryID via MAPI Namespace
                CComPtr<IDispatch> pNamespace;
                CComPtr<IDispatch> pMailItem;
                {
                    std::shared_lock lock(m_mutex);
                    pNamespace = m_pNamespace;
                }

                if (!pNamespace) {
                    Logger::Error("OnNewMailEx: MAPI Namespace unavailable for EntryID: {}", entryId);
                    m_stats.scanErrors++;
                    continue;
                }

                pMailItem = GetItemFromEntryId(pNamespace, entryId);
                if (!pMailItem) {
                    Logger::Warn("OnNewMailEx: Could not resolve EntryID: {}", entryId);
                    m_stats.scanErrors++;
                    continue;
                }

                auto mailInfo = ExtractMailItemInfo(pMailItem);
                if (!mailInfo.has_value()) {
                    Logger::Error("OnNewMailEx: Failed to extract mail info for EntryID: {}", entryId);
                    m_stats.scanErrors++;
                    continue;
                }

                // Override entryId with the one from the event (authoritative)
                mailInfo->entryId = entryId;

                ProcessMailEvent(mailInfo.value(), MailEventType::NewMail, pMailItem);
            }

        } catch (const std::exception& e) {
            Logger::Error("OnNewMailEx - Exception: {}", e.what());
            m_stats.scanErrors++;
        }
    }

    [[nodiscard]] bool OnItemSend(void* pDispatchMailItem, bool& cancel) {
        try {
            if (!m_config.enabled || !m_config.scanOutbound) {
                return true;
            }

            m_stats.outboundScanned++;
            m_stats.totalScanned++;
            m_stats.byEventType[static_cast<size_t>(MailEventType::ItemSend)]++;

            auto* pDisp = static_cast<IDispatch*>(pDispatchMailItem);
            auto mailInfo = ExtractMailItemInfo(pDisp);
            if (!mailInfo.has_value()) {
                Logger::Error("OnItemSend: Failed to extract mail item info");
                m_stats.scanErrors++;
                return true;
            }

            // Invoke pre-send callbacks (snapshot to avoid holding lock during callback)
            std::vector<PreSendCallback> preSendCopy;
            {
                std::shared_lock lock(m_mutex);
                preSendCopy = m_preSendCallbacks;
            }

            for (const auto& callback : preSendCopy) {
                if (callback) {
                    try {
                        if (!callback(mailInfo.value())) {
                            cancel = true;
                            m_stats.sendBlocked++;
                            Logger::Warn("Send blocked by pre-send callback: {}", mailInfo->subject);
                            return false;
                        }
                    } catch (const std::exception& cbEx) {
                        Logger::Error("OnItemSend: Pre-send callback threw: {}", cbEx.what());
                    }
                }
            }

            // Scan for threats
            auto scanResult = ScanMailItemInternal(mailInfo.value());

            if (scanResult.hasMalware || scanResult.isPhishing) {
                cancel = true;
                m_stats.sendBlocked++;
                m_stats.threatsDetected++;

                if (scanResult.hasMalware) m_stats.malwareBlocked++;
                if (scanResult.isPhishing) m_stats.phishingBlocked++;

                Logger::Error("Outbound mail blocked: {} (threat={})",
                    mailInfo->subject,
                    scanResult.primaryThreatName);

                // Invoke block callbacks
                InvokeBlockCallbacks(mailInfo.value(), OutlookScanAction::Block);

                return false;
            }

            m_stats.allowed++;
            return true;

        } catch (const std::exception& e) {
            Logger::Error("OnItemSend - Exception: {}", e.what());
            m_stats.scanErrors++;
            return true;
        }
    }

    void OnItemAdd(void* pDispatchItem) {
        try {
            m_stats.byEventType[static_cast<size_t>(MailEventType::ItemAdd)]++;

            auto* pDisp = static_cast<IDispatch*>(pDispatchItem);
            auto mailInfo = ExtractMailItemInfo(pDisp);
            if (mailInfo.has_value()) {
                ProcessMailEvent(mailInfo.value(), MailEventType::ItemAdd, pDisp);
            }

        } catch (const std::exception& e) {
            Logger::Error("OnItemAdd - Exception: {}", e.what());
        }
    }

    void OnItemChange(void* pDispatchItem) {
        try {
            m_stats.byEventType[static_cast<size_t>(MailEventType::ItemChange)]++;

            if (!m_config.enabled) return;

            auto* pDisp = static_cast<IDispatch*>(pDispatchItem);
            if (!pDisp) return;

            // Re-extract mail info and rescan to detect modification-based evasion
            auto mailInfo = ExtractMailItemInfo(pDisp);
            if (!mailInfo.has_value()) {
                return; // Not a scannable item (calendar, task, etc.)
            }

            // Only rescan if item has attachments or is in a monitored folder
            if (mailInfo->hasAttachments || !mailInfo->folderPath.empty()) {
                EmailScanResult scanResult;
                {
                    std::shared_lock lock(m_mutex);
                    scanResult = ScanMailItemInternal(mailInfo.value());
                }
                if (scanResult.hasMalware || scanResult.isPhishing) {
                    Logger::Warn("OnItemChange: Modified item detected as threat: {} (entryId={})",
                        scanResult.primaryThreatName, mailInfo->entryId);

                    MailScanEvent event;
                    event.eventId = GenerateEventId();
                    event.mailItem = mailInfo.value();
                    event.eventType = MailEventType::ItemChange;
                    event.scanResult = scanResult;
                    event.timestamp = std::chrono::system_clock::now();
                    event.actionTaken = scanResult.hasMalware
                        ? OutlookScanAction::Delete
                        : OutlookScanAction::Block;
                    event.scanDuration = scanResult.scanDuration;

                    InvokeMailEventCallbacks(event);
                    InvokeBlockCallbacks(mailInfo.value(), event.actionTaken);
                }
            }

        } catch (const std::exception& e) {
            Logger::Error("OnItemChange - Exception: {}", e.what());
        }
    }

    void OnBeforeDelete(void* pDispatchItem, bool& cancel) {
        try {
            m_stats.byEventType[static_cast<size_t>(MailEventType::BeforeDelete)]++;

            auto* pDisp = static_cast<IDispatch*>(pDispatchItem);
            if (!pDisp) {
                cancel = false;
                return;
            }

            // Extract the EntryID to check if this item is quarantined
            auto entryIdOpt = GetDispatchStringProperty(pDisp, DISPID_ENTRYID);
            if (!entryIdOpt.has_value()) {
                cancel = false;
                return;
            }

            const std::string& entryId = entryIdOpt.value();

            // Protect quarantined items from accidental or malicious deletion
            {
                std::shared_lock lock(m_mutex);
                if (m_quarantinedEntryIds.count(entryId) > 0) {
                    Logger::Warn("OnBeforeDelete: Blocked deletion of quarantined item (entryId={})", entryId);
                    cancel = true;
                    return;
                }
            }

            // Log deletion audit trail for all monitored items
            auto subjectOpt = GetDispatchStringProperty(pDisp, DISPID_SUBJECT);
            auto senderOpt = GetDispatchStringProperty(pDisp, DISPID_SENDEREMAIL);

            Logger::Info("OnBeforeDelete: Item deletion allowed (entryId={}, subject={}, sender={})",
                entryId,
                subjectOpt.value_or("<unknown>"),
                senderOpt.value_or("<unknown>"));

            cancel = false;

        } catch (const std::exception& e) {
            Logger::Error("OnBeforeDelete - Exception: {}", e.what());
            cancel = false; // Fail-open for deletions to avoid trapping items
        }
    }

    void OnAttachmentAdd(void* pDispatchAttachment, bool& cancel) {
        try {
            m_stats.byEventType[static_cast<size_t>(MailEventType::AttachmentAdd)]++;

            if (!m_config.blockDangerousAttachments && !m_config.blockMacros) {
                return;
            }

            auto* pDisp = static_cast<IDispatch*>(pDispatchAttachment);
            if (!pDisp) return;

            // Extract filename from the attachment object (DISPID_FILENAME = PR_ATTACH_LONG_FILENAME)
            auto filenameOpt = GetDispatchStringProperty(pDisp, DISPID_FILENAME);
            if (!filenameOpt.has_value() || filenameOpt->empty()) {
                return; // Cannot determine filename — allow
            }

            const std::string& filename = filenameOpt.value();
            std::wstring wFilename = StringUtils::ToWide(filename);

            // Check dangerous file extensions
            if (m_config.blockDangerousAttachments && IsDangerousExtension(wFilename)) {
                cancel = true;
                m_stats.attachmentsStripped++;
                m_stats.threatsDetected++;

                Logger::Error("OnAttachmentAdd: Blocked dangerous attachment: {}", filename);
                return;
            }

            // Check macro-enabled Office document extensions
            if (m_config.blockMacros && IsMacroEnabled(wFilename)) {
                cancel = true;
                m_stats.attachmentsStripped++;

                Logger::Warn("OnAttachmentAdd: Blocked macro-enabled attachment: {}", filename);
                return;
            }

            // Check against user-configured blocked extensions
            std::string lowerFilename = ToLowerCopy(filename);
            for (const auto& ext : m_config.blockedExtensions) {
                std::string lowerExt = ToLowerCopy(ext);
                if (!lowerExt.empty() && lowerExt.front() != '.') {
                    lowerExt = "." + lowerExt;
                }
                if (lowerFilename.ends_with(lowerExt)) {
                    cancel = true;
                    m_stats.attachmentsStripped++;

                    Logger::Warn("OnAttachmentAdd: Blocked attachment by policy (ext={}): {}", ext, filename);
                    return;
                }
            }

        } catch (const std::exception& e) {
            Logger::Error("OnAttachmentAdd - Exception: {}", e.what());
        }
    }

    // ========================================================================
    // SCANNING
    // ========================================================================

    [[nodiscard]] EmailScanResult ScanMailItem(const MailItemInfo& mailInfo) {
        std::shared_lock lock(m_mutex);
        return ScanMailItemInternal(mailInfo);
    }

    [[nodiscard]] EmailScanResult ScanMailItemById(const std::string& entryId) {
        EmailScanResult result;

        try {
            if (entryId.empty()) {
                Logger::Error("ScanMailItemById: Empty EntryID provided");
                return result;
            }

            // Retrieve the MailItem by EntryID via MAPI Namespace
            CComPtr<IDispatch> pNamespace;
            {
                std::shared_lock lock(m_mutex);
                pNamespace = m_pNamespace;
            }

            if (!pNamespace) {
                Logger::Error("ScanMailItemById: MAPI Namespace unavailable");
                m_stats.scanErrors++;
                return result;
            }

            CComPtr<IDispatch> pMailItem = GetItemFromEntryId(pNamespace, entryId);
            if (!pMailItem) {
                Logger::Error("ScanMailItemById: Could not resolve EntryID: {}", entryId);
                m_stats.scanErrors++;
                return result;
            }

            auto mailInfo = ExtractMailItemInfo(pMailItem);
            if (!mailInfo.has_value()) {
                Logger::Error("ScanMailItemById: Failed to extract mail info for EntryID: {}", entryId);
                m_stats.scanErrors++;
                return result;
            }

            mailInfo->entryId = entryId;
            {
                std::shared_lock lock(m_mutex);
                result = ScanMailItemInternal(mailInfo.value());
            }
            result.messageId = entryId;

            m_stats.totalScanned++;

        } catch (const std::exception& e) {
            Logger::Error("ScanMailItemById - Exception: {}", e.what());
            m_stats.scanErrors++;
        }

        return result;
    }

    [[nodiscard]] std::optional<MailItemInfo> GetMailItemInfo(void* pDispatch) {
        return ExtractMailItemInfo(pDispatch);
    }

    [[nodiscard]] std::optional<fs::path> ExtractAttachment(void* pDispatch, size_t attachmentIndex) {
        try {
            auto* pMailItem = static_cast<IDispatch*>(pDispatch);
            if (!pMailItem) {
                Logger::Error("ExtractAttachment: Null mail item dispatch pointer");
                return std::nullopt;
            }

            // Get the Attachments collection from the mail item
            CComPtr<IDispatch> pAttachments = GetDispatchObjectProperty(pMailItem, DISPID_ATTACHMENTS);
            if (!pAttachments) {
                Logger::Error("ExtractAttachment: Could not obtain Attachments collection");
                return std::nullopt;
            }

            // Validate attachment count
            auto countOpt = GetDispatchIntProperty(pAttachments, DISPID_COUNT);
            if (!countOpt.has_value() || countOpt.value() <= 0) {
                Logger::Warn("ExtractAttachment: No attachments on mail item");
                return std::nullopt;
            }

            int count = countOpt.value();
            if (attachmentIndex == 0 || static_cast<int>(attachmentIndex) > count) {
                Logger::Error("ExtractAttachment: Index {} out of range (count={})", attachmentIndex, count);
                return std::nullopt;
            }

            // Get the specific attachment (1-based index)
            CComPtr<IDispatch> pAttachment = GetCollectionItem(pAttachments, static_cast<int>(attachmentIndex));
            if (!pAttachment) {
                Logger::Error("ExtractAttachment: Could not get attachment at index {}", attachmentIndex);
                return std::nullopt;
            }

            // Get filename for the temp path
            auto filenameOpt = GetDispatchStringProperty(pAttachment, DISPID_FILENAME);
            std::string filename = filenameOpt.value_or("attachment_" + std::to_string(attachmentIndex));

            // Validate filename — strip any path traversal attempts
            std::wstring wFilename = StringUtils::ToWide(filename);
            wFilename = fs::path(wFilename).filename().wstring();
            if (wFilename.empty()) {
                wFilename = L"attachment_" + std::to_wstring(attachmentIndex);
            }

            // Ensure the secure temp directory exists
            if (!fs::exists(ATTACHMENT_TEMP_DIR)) {
                auto secureDir = CreateSecureTempDirectory();
                if (!secureDir.has_value()) {
                    // Fallback to basic directory
                    fs::create_directories(ATTACHMENT_TEMP_DIR);
                }
            }

            // Save attachment to the secure temp path
            fs::path tempPath = ATTACHMENT_TEMP_DIR / wFilename;

            // Avoid overwriting — append index if file exists
            if (fs::exists(tempPath)) {
                tempPath = ATTACHMENT_TEMP_DIR /
                    (std::to_wstring(attachmentIndex) + L"_" + wFilename);
            }

            // Cap at MAX_ATTACHMENT_SIZE — check file after save
            if (!SaveAttachmentToFile(pAttachment, tempPath.wstring())) {
                Logger::Error("ExtractAttachment: SaveAsFile failed for '{}'", filename);
                return std::nullopt;
            }

            // Verify saved file size is within bounds
            std::error_code ec;
            auto fileSize = fs::file_size(tempPath, ec);
            if (ec || fileSize > m_config.maxAttachmentSize) {
                Logger::Warn("ExtractAttachment: Attachment '{}' exceeds max size ({} bytes)",
                    filename, fileSize);
                fs::remove(tempPath, ec);
                return std::nullopt;
            }

            Logger::Debug("ExtractAttachment: Saved '{}' to '{}'", filename,
                StringUtils::ToNarrow(tempPath.wstring()));
            return tempPath;

        } catch (const std::exception& e) {
            Logger::Error("ExtractAttachment - Exception: {}", e.what());
            return std::nullopt;
        }
    }

    // ========================================================================
    // FOLDER OPERATIONS
    // ========================================================================

    [[nodiscard]] std::vector<FolderInfo> GetMonitoredFolders() const {
        std::shared_lock lock(m_mutex);
        return std::vector<FolderInfo>(m_monitoredFolders.begin(), m_monitoredFolders.end());
    }

    [[nodiscard]] bool AddMonitoredFolder(const std::string& folderPath) {
        std::unique_lock lock(m_mutex);

        try {
            FolderInfo folder;
            folder.path = folderPath;
            folder.name = fs::path(folderPath).filename().string();
            folder.isMonitored = true;

            m_monitoredFolders.push_back(folder);

            Logger::Info("Added monitored folder: {}", folderPath);
            return true;

        } catch (const std::exception& e) {
            Logger::Error("AddMonitoredFolder - Exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool RemoveMonitoredFolder(const std::string& folderPath) {
        std::unique_lock lock(m_mutex);

        try {
            auto it = std::remove_if(m_monitoredFolders.begin(), m_monitoredFolders.end(),
                [&](const FolderInfo& folder) {
                    return folder.path == folderPath;
                });

            if (it != m_monitoredFolders.end()) {
                m_monitoredFolders.erase(it, m_monitoredFolders.end());
                Logger::Info("Removed monitored folder: {}", folderPath);
                return true;
            }

            return false;

        } catch (const std::exception& e) {
            Logger::Error("RemoveMonitoredFolder - Exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] std::vector<EmailScanResult> ScanFolder(const std::string& folderPath, bool recursive) {
        std::vector<EmailScanResult> results;

        try {
            CComPtr<IDispatch> pNamespace;
            {
                std::shared_lock lock(m_mutex);
                pNamespace = m_pNamespace;
            }

            if (!pNamespace) {
                Logger::Error("ScanFolder: MAPI Namespace unavailable");
                return results;
            }

            // Resolve folder by path — try default folders first
            CComPtr<IDispatch> pFolder;
            std::string lowerPath = ToLowerCopy(folderPath);

            if (lowerPath == "inbox")
                pFolder = GetDefaultFolder(pNamespace, OL_FOLDER_INBOX);
            else if (lowerPath == "sent" || lowerPath == "sentitems")
                pFolder = GetDefaultFolder(pNamespace, OL_FOLDER_SENT_MAIL);
            else if (lowerPath == "junk" || lowerPath == "junkemail")
                pFolder = GetDefaultFolder(pNamespace, OL_FOLDER_JUNK_EMAIL);
            else if (lowerPath == "drafts")
                pFolder = GetDefaultFolder(pNamespace, OL_FOLDER_DRAFTS);
            else if (lowerPath == "deleted" || lowerPath == "deleteditems")
                pFolder = GetDefaultFolder(pNamespace, OL_FOLDER_DELETED_ITEMS);

            if (!pFolder) {
                Logger::Error("ScanFolder: Could not resolve folder path: {}", folderPath);
                return results;
            }

            // Get Items collection from the folder
            CComPtr<IDispatch> pItems = GetDispatchObjectProperty(pFolder, DISPID_ITEMS);
            if (!pItems) {
                Logger::Error("ScanFolder: Could not obtain Items collection for folder: {}", folderPath);
                return results;
            }

            auto countOpt = GetDispatchIntProperty(pItems, DISPID_COUNT);
            if (!countOpt.has_value() || countOpt.value() <= 0) {
                Logger::Info("ScanFolder: Folder '{}' is empty", folderPath);
                return results;
            }

            int itemCount = std::min(countOpt.value(), static_cast<int>(MAX_FOLDER_SCAN_ITEMS));
            Logger::Info("ScanFolder: Scanning {} items in folder '{}'", itemCount, folderPath);

            results.reserve(static_cast<size_t>(itemCount));

            // Iterate items (Outlook collections are 1-based)
            for (int i = 1; i <= itemCount; ++i) {
                CComPtr<IDispatch> pItem = GetCollectionItem(pItems, i);
                if (!pItem) continue;

                // Verify this is a MailItem (MessageClass starts with "IPM.Note")
                auto msgClass = GetDispatchStringProperty(pItem, DISPID_MESSAGECLASS);
                if (!msgClass.has_value() || msgClass->find("IPM.Note") != 0) {
                    continue; // Skip non-mail items (calendar, task, etc.)
                }

                auto mailInfo = ExtractMailItemInfo(pItem);
                if (!mailInfo.has_value()) continue;

                EmailScanResult scanResult;
                {
                    std::shared_lock lock(m_mutex);
                    scanResult = ScanMailItemInternal(mailInfo.value());
                }
                m_stats.totalScanned++;
                results.push_back(std::move(scanResult));
            }

            Logger::Info("ScanFolder: Completed scan of folder '{}' — {}/{} items scanned",
                folderPath, results.size(), itemCount);

        } catch (const std::exception& e) {
            Logger::Error("ScanFolder - Exception: {}", e.what());
        }

        return results;
    }

    // ========================================================================
    // ACTIONS
    // ========================================================================

    [[nodiscard]] bool MoveToJunk(const std::string& entryId) {
        try {
            if (entryId.empty()) {
                Logger::Error("MoveToJunk: Empty EntryID");
                return false;
            }

            CComPtr<IDispatch> pNamespace;
            CComPtr<IDispatch> pJunkFolder;
            {
                std::shared_lock lock(m_mutex);
                pNamespace = m_pNamespace;
                pJunkFolder = m_pJunkFolder;
            }

            if (!pNamespace) {
                Logger::Error("MoveToJunk: MAPI Namespace unavailable");
                return false;
            }

            // Resolve the Junk folder if not cached
            if (!pJunkFolder) {
                pJunkFolder = GetDefaultFolder(pNamespace, OL_FOLDER_JUNK_EMAIL);
                if (!pJunkFolder) {
                    Logger::Error("MoveToJunk: Cannot obtain Junk Email folder");
                    return false;
                }
            }

            // Retrieve the mail item
            CComPtr<IDispatch> pMailItem = GetItemFromEntryId(pNamespace, entryId);
            if (!pMailItem) {
                Logger::Error("MoveToJunk: Could not resolve EntryID: {}", entryId);
                return false;
            }

            // Log audit trail before move
            auto subjectOpt = GetDispatchStringProperty(pMailItem, DISPID_SUBJECT);
            auto senderOpt = GetDispatchStringProperty(pMailItem, DISPID_SENDEREMAIL);

            if (!MoveMailItemToFolder(pMailItem, pJunkFolder)) {
                Logger::Error("MoveToJunk: Move operation failed for EntryID: {}", entryId);
                return false;
            }

            m_stats.quarantined++;

            // Track this item as quarantined to prevent accidental deletion
            {
                std::unique_lock lock(m_mutex);
                m_quarantinedEntryIds.insert(entryId);
            }

            Logger::Info("MoveToJunk: Moved item to Junk (entryId={}, subject={}, sender={})",
                entryId,
                subjectOpt.value_or("<unknown>"),
                senderOpt.value_or("<unknown>"));
            return true;

        } catch (const std::exception& e) {
            Logger::Error("MoveToJunk - Exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool DeleteMail(const std::string& entryId) {
        try {
            if (entryId.empty()) {
                Logger::Error("DeleteMail: Empty EntryID");
                return false;
            }

            CComPtr<IDispatch> pNamespace;
            {
                std::shared_lock lock(m_mutex);
                pNamespace = m_pNamespace;
            }

            if (!pNamespace) {
                Logger::Error("DeleteMail: MAPI Namespace unavailable");
                return false;
            }

            CComPtr<IDispatch> pMailItem = GetItemFromEntryId(pNamespace, entryId);
            if (!pMailItem) {
                Logger::Error("DeleteMail: Could not resolve EntryID: {}", entryId);
                return false;
            }

            // Log full audit trail before deletion (subject, sender, recipients)
            auto subjectOpt = GetDispatchStringProperty(pMailItem, DISPID_SUBJECT);
            auto senderOpt = GetDispatchStringProperty(pMailItem, DISPID_SENDEREMAIL);
            auto toOpt = GetDispatchStringProperty(pMailItem, DISPID_TO);

            Logger::Info("DeleteMail: Deleting item (entryId={}, subject={}, sender={}, to={})",
                entryId,
                subjectOpt.value_or("<unknown>"),
                senderOpt.value_or("<unknown>"),
                toOpt.value_or("<unknown>"));

            // Execute the deletion via COM
            if (!InvokeDispatchMethod(pMailItem, DISPID_DELETE)) {
                Logger::Error("DeleteMail: Delete method invocation failed for EntryID: {}", entryId);
                return false;
            }

            // Remove from quarantine tracking if it was there
            {
                std::unique_lock lock(m_mutex);
                m_quarantinedEntryIds.erase(entryId);
            }

            Logger::Info("DeleteMail: Successfully deleted item (entryId={})", entryId);
            return true;

        } catch (const std::exception& e) {
            Logger::Error("DeleteMail - Exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool StripAttachments(const std::string& entryId, const std::vector<std::string>& attachmentNames) {
        try {
            if (entryId.empty()) {
                Logger::Error("StripAttachments: Empty EntryID");
                return false;
            }

            CComPtr<IDispatch> pNamespace;
            {
                std::shared_lock lock(m_mutex);
                pNamespace = m_pNamespace;
            }

            if (!pNamespace) {
                Logger::Error("StripAttachments: MAPI Namespace unavailable");
                return false;
            }

            CComPtr<IDispatch> pMailItem = GetItemFromEntryId(pNamespace, entryId);
            if (!pMailItem) {
                Logger::Error("StripAttachments: Could not resolve EntryID: {}", entryId);
                return false;
            }

            CComPtr<IDispatch> pAttachments = GetDispatchObjectProperty(pMailItem, DISPID_ATTACHMENTS);
            if (!pAttachments) {
                Logger::Warn("StripAttachments: No attachments collection on item (entryId={})", entryId);
                return false;
            }

            auto countOpt = GetDispatchIntProperty(pAttachments, DISPID_COUNT);
            if (!countOpt.has_value() || countOpt.value() <= 0) {
                Logger::Info("StripAttachments: Item has no attachments (entryId={})", entryId);
                return true;
            }

            int count = countOpt.value();
            uint32_t removedCount = 0;

            // Iterate in reverse order to avoid index shifting during deletion
            for (int i = count; i >= 1; --i) {
                CComPtr<IDispatch> pAttachment = GetCollectionItem(pAttachments, i);
                if (!pAttachment) continue;

                auto filenameOpt = GetDispatchStringProperty(pAttachment, DISPID_FILENAME);
                if (!filenameOpt.has_value()) continue;

                bool shouldRemove = false;
                if (attachmentNames.empty()) {
                    // Empty list means strip ALL attachments
                    shouldRemove = true;
                } else {
                    std::string lowerFilename = ToLowerCopy(filenameOpt.value());
                    for (const auto& name : attachmentNames) {
                        if (ToLowerCopy(name) == lowerFilename) {
                            shouldRemove = true;
                            break;
                        }
                    }
                }

                if (shouldRemove) {
                    // Attachment.Delete() removes the attachment
                    if (InvokeDispatchMethod(pAttachment, DISPID_DELETE)) {
                        ++removedCount;
                        Logger::Info("StripAttachments: Removed attachment '{}' from entryId={}",
                            filenameOpt.value(), entryId);
                    } else {
                        Logger::Error("StripAttachments: Failed to remove attachment '{}' from entryId={}",
                            filenameOpt.value(), entryId);
                    }
                }
            }

            // Save the modified mail item
            if (removedCount > 0) {
                InvokeDispatchMethod(pMailItem, DISPID_SAVE);
                m_stats.attachmentsStripped += removedCount;
            }

            Logger::Info("StripAttachments: Removed {}/{} attachments from entryId={}",
                removedCount, count, entryId);
            return true;

        } catch (const std::exception& e) {
            Logger::Error("StripAttachments - Exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool TagSubject(const std::string& entryId, const std::string& tag) {
        try {
            if (entryId.empty() || tag.empty()) {
                Logger::Error("TagSubject: Empty EntryID or tag");
                return false;
            }

            CComPtr<IDispatch> pNamespace;
            {
                std::shared_lock lock(m_mutex);
                pNamespace = m_pNamespace;
            }

            if (!pNamespace) {
                Logger::Error("TagSubject: MAPI Namespace unavailable");
                return false;
            }

            CComPtr<IDispatch> pMailItem = GetItemFromEntryId(pNamespace, entryId);
            if (!pMailItem) {
                Logger::Error("TagSubject: Could not resolve EntryID: {}", entryId);
                return false;
            }

            // Get current subject
            auto subjectOpt = GetDispatchStringProperty(pMailItem, DISPID_SUBJECT);
            std::string currentSubject = subjectOpt.value_or("");

            // Construct the tag prefix (e.g., "[SPAM] ")
            std::string tagPrefix = "[" + tag + "] ";

            // Avoid double-tagging
            if (currentSubject.find(tagPrefix) != std::string::npos) {
                Logger::Debug("TagSubject: Item already tagged with [{}] (entryId={})", tag, entryId);
                return true;
            }

            // Prepend tag to subject
            std::string newSubject = tagPrefix + currentSubject;
            std::wstring wNewSubject = StringUtils::ToWide(newSubject);

            if (!SetDispatchStringProperty(pMailItem, DISPID_SUBJECT, wNewSubject)) {
                Logger::Error("TagSubject: Failed to set Subject property (entryId={})", entryId);
                return false;
            }

            // Save the modified mail item
            if (!InvokeDispatchMethod(pMailItem, DISPID_SAVE)) {
                Logger::Error("TagSubject: Failed to save item after tagging (entryId={})", entryId);
                return false;
            }

            Logger::Info("TagSubject: Tagged item with [{}] (entryId={}, subject={})",
                tag, entryId, newSubject);
            return true;

        } catch (const std::exception& e) {
            Logger::Error("TagSubject - Exception: {}", e.what());
            return false;
        }
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void RegisterMailEventCallback(MailEventCallback callback) {
        std::unique_lock lock(m_mutex);
        m_mailEventCallbacks.push_back(std::move(callback));
    }

    void RegisterScanCallback(OutlookScanResultCallback callback) {
        std::unique_lock lock(m_mutex);
        m_scanCallbacks.push_back(std::move(callback));
    }

    void RegisterBlockCallback(BlockCallback callback) {
        std::unique_lock lock(m_mutex);
        m_blockCallbacks.push_back(std::move(callback));
    }

    void RegisterPreSendCallback(PreSendCallback callback) {
        std::unique_lock lock(m_mutex);
        m_preSendCallbacks.push_back(std::move(callback));
    }

    void RegisterErrorCallback(ErrorCallback callback) {
        std::unique_lock lock(m_mutex);
        m_errorCallbacks.push_back(std::move(callback));
    }

    void UnregisterCallbacks() {
        std::unique_lock lock(m_mutex);
        m_mailEventCallbacks.clear();
        m_scanCallbacks.clear();
        m_blockCallbacks.clear();
        m_preSendCallbacks.clear();
        m_errorCallbacks.clear();
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] OutlookScannerStatisticsSnapshot GetStatistics() const {
        std::shared_lock lock(m_mutex);
        return m_stats.ToSnapshot();
    }

    void ResetStatistics() {
        std::unique_lock lock(m_mutex);
        m_stats.Reset();
    }

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    [[nodiscard]] bool SelfTest() {
        try {
            Logger::Info("=== OutlookScanner Self-Test ===");

            // Test 1: Configuration validation
            OutlookScannerConfiguration testConfig;
            testConfig.scanInbound = true;
            testConfig.scanOutbound = true;
            if (!testConfig.IsValid()) {
                Logger::Error("Self-test failed: Configuration validation");
                return false;
            }

            // Test 2: Check Outlook running
            bool outlookRunning = IsOutlookRunning();
            Logger::Info("Self-test: Outlook running = {}", outlookRunning);

            // Test 3: Temp directory creation
            if (!fs::exists(ATTACHMENT_TEMP_DIR)) {
                Logger::Error("Self-test failed: Temp directory missing");
                return false;
            }

            Logger::Info("Self-test: PASSED");
            return true;

        } catch (const std::exception& e) {
            Logger::Error("Self-test failed with exception: {}", e.what());
            return false;
        }
    }

private:
    // ========================================================================
    // INTERNAL METHODS
    // ========================================================================

    void DisconnectFromOutlookInternal() {
        try {
            // Release COM interface pointers in reverse acquisition order
            m_pJunkFolder.Release();
            m_pNamespace.Release();
            m_pOutlookApp.Release();
            m_quarantinedEntryIds.clear();

            m_addinStatus = AddinStatus::Disconnected;
            m_status = ModuleStatus::Stopped;

            Logger::Info("Disconnected from Outlook — all COM references released");

        } catch (const std::exception& e) {
            Logger::Error("Disconnect failed: {}", e.what());
        }
    }

    [[nodiscard]] std::optional<MailItemInfo> ExtractMailItemInfo(void* pDispatch) {
        try {
            auto* pDisp = static_cast<IDispatch*>(pDispatch);
            if (!pDisp) return std::nullopt;

            MailItemInfo info;

            // Verify message class — only process mail items (IPM.Note*)
            auto msgClassOpt = GetDispatchStringProperty(pDisp, DISPID_MESSAGECLASS);
            info.messageClass = msgClassOpt.value_or("IPM.Note");
            if (info.messageClass.find("IPM.Note") != 0 &&
                info.messageClass != "IPM.Schedule.Meeting.Request") {
                // Not a mail item or meeting request — skip
                return std::nullopt;
            }

            // Extract EntryID
            auto entryIdOpt = GetDispatchStringProperty(pDisp, DISPID_ENTRYID);
            info.entryId = entryIdOpt.value_or(GenerateEventId());

            // Extract Subject
            auto subjectOpt = GetDispatchStringProperty(pDisp, DISPID_SUBJECT);
            info.subject = subjectOpt.value_or("");

            // Extract Sender information
            auto senderEmailOpt = GetDispatchStringProperty(pDisp, DISPID_SENDEREMAIL);
            info.senderEmail = senderEmailOpt.value_or("");

            auto senderNameOpt = GetDispatchStringProperty(pDisp, DISPID_SENDERNAME);
            info.senderName = senderNameOpt.value_or("");

            // Extract Recipients
            auto toOpt = GetDispatchStringProperty(pDisp, DISPID_TO);
            if (toOpt.has_value() && !toOpt->empty()) {
                std::istringstream iss(toOpt.value());
                std::string recipient;
                while (std::getline(iss, recipient, ';')) {
                    recipient.erase(0, recipient.find_first_not_of(" \t"));
                    recipient.erase(recipient.find_last_not_of(" \t") + 1);
                    if (!recipient.empty()) info.toRecipients.push_back(recipient);
                }
            }

            auto ccOpt = GetDispatchStringProperty(pDisp, DISPID_CC);
            if (ccOpt.has_value() && !ccOpt->empty()) {
                std::istringstream iss(ccOpt.value());
                std::string recipient;
                while (std::getline(iss, recipient, ';')) {
                    recipient.erase(0, recipient.find_first_not_of(" \t"));
                    recipient.erase(recipient.find_last_not_of(" \t") + 1);
                    if (!recipient.empty()) info.ccRecipients.push_back(recipient);
                }
            }

            // Extract Body (plain text and HTML)
            auto bodyOpt = GetDispatchStringProperty(pDisp, DISPID_BODY);
            info.bodyText = bodyOpt.value_or("");

            auto htmlBodyOpt = GetDispatchStringProperty(pDisp, DISPID_HTMLBODY);
            info.bodyHtml = htmlBodyOpt.value_or("");

            // Extract Importance
            auto importanceOpt = GetDispatchIntProperty(pDisp, DISPID_IMPORTANCE);
            info.importance = importanceOpt.value_or(1);

            // Extract Attachments metadata
            CComPtr<IDispatch> pAttachments = GetDispatchObjectProperty(pDisp, DISPID_ATTACHMENTS);
            if (pAttachments) {
                auto countOpt = GetDispatchIntProperty(pAttachments, DISPID_COUNT);
                info.attachmentCount = countOpt.has_value() && countOpt.value() > 0
                    ? static_cast<size_t>(countOpt.value()) : 0;
                info.hasAttachments = info.attachmentCount > 0;

                // Extract attachment filenames (for extension/name checking)
                for (size_t i = 1; i <= info.attachmentCount && i <= 100; ++i) {
                    CComPtr<IDispatch> pAttachment = GetCollectionItem(pAttachments, static_cast<int>(i));
                    if (pAttachment) {
                        auto filenameOpt = GetDispatchStringProperty(pAttachment, DISPID_FILENAME);
                        if (filenameOpt.has_value() && !filenameOpt->empty()) {
                            info.attachmentNames.push_back(filenameOpt.value());
                        }
                    }
                }
            }

            info.receivedTime = std::chrono::system_clock::now();

            return info;

        } catch (const std::exception& e) {
            Logger::Error("ExtractMailItemInfo - Exception: {}", e.what());
            return std::nullopt;
        }
    }

    [[nodiscard]] EmailScanResult ScanMailItemInternal(const MailItemInfo& mailInfo) {
        auto startTime = std::chrono::steady_clock::now();

        EmailScanResult result;
        result.messageId = mailInfo.entryId;
        result.isClean = true;
        result.scanTimestamp = std::chrono::system_clock::now();

        try {
            // Check whitelist (sender email or domain)
            // Whitelist check: use per-scan whitelist from configuration (trusted senders)
            // Check safe sender domains from configuration
            if (IsSafeSenderDomain(mailInfo.senderEmail, m_config.trustedSenders)) {
                result.riskScore = 5;
                m_stats.allowed++;
                return result;
            }

            // ================================================================
            // Attachment scanning — check extensions and file content
            // ================================================================
            if (m_config.scanAttachments && mailInfo.hasAttachments) {
                for (const auto& attachmentName : mailInfo.attachmentNames) {
                    std::wstring wAttachmentName = StringUtils::ToWide(attachmentName);

                    // Check dangerous extensions
                    if (m_config.blockDangerousAttachments && IsDangerousExtension(wAttachmentName)) {
                        result.hasMalware = true;
                        result.isClean = false;
                        result.primaryThreatName = "Dangerous file extension: " + attachmentName;
                        result.riskScore = 90;
                        result.scanLog = "Extension blocking";
                        result.detectedThreats = static_cast<EmailThreatType>(
                            static_cast<uint32_t>(result.detectedThreats) |
                            static_cast<uint32_t>(EmailThreatType::MaliciousAttachment));
                        result.blockedAttachments.push_back(attachmentName);
                        result.recommendedAction = ScanAction::Block;
                        break;
                    }

                    // Check macro-enabled files
                    if (m_config.blockMacros && IsMacroEnabled(wAttachmentName)) {
                        result.hasMalware = true;
                        result.isClean = false;
                        result.primaryThreatName = "Macro-enabled document: " + attachmentName;
                        result.riskScore = 80;
                        result.scanLog = "Macro detection";
                        result.detectedThreats = static_cast<EmailThreatType>(
                            static_cast<uint32_t>(result.detectedThreats) |
                            static_cast<uint32_t>(EmailThreatType::SuspiciousMacro));
                        result.blockedAttachments.push_back(attachmentName);
                        result.recommendedAction = ScanAction::StripAttachments;
                        break;
                    }
                }
            }

            // ================================================================
            // Phishing detection — use PhishingEmailDetector if available
            // ================================================================
            if (m_config.detectPhishing && !result.hasMalware) {
                if (PhishingEmailDetector::HasInstance()) {
                    auto& phishDetector = PhishingEmailDetector::Instance();

                    auto phishResult = phishDetector.AnalyzeEmail(
                        mailInfo.subject,
                        mailInfo.bodyText,
                        mailInfo.bodyHtml,
                        mailInfo.senderEmail,
                        "",  // replyTo — not available from basic MailItem
                        mailInfo.headers);

                    if (phishResult.isPhishing) {
                        result.isPhishing = true;
                        result.isClean = false;
                        result.phishingConfidence = phishResult.confidenceScore;
                        result.riskScore = std::max(result.riskScore, phishResult.riskScore);
                        result.primaryThreatName = "Phishing: " + phishResult.analysisSummary;
                        result.scanLog = "PhishingEmailDetector";
                        result.detectedThreats = static_cast<EmailThreatType>(
                            static_cast<uint32_t>(result.detectedThreats) |
                            static_cast<uint32_t>(EmailThreatType::Phishing));
                        result.recommendedAction = ScanAction::Block;

                        // Append matched patterns to threat details
                        for (const auto& pattern : phishResult.matchedPatterns) {
                            ThreatDetail detail;
                            detail.type = EmailThreatType::Phishing;
                            detail.threatName = pattern;
                            detail.description = phishResult.analysisSummary;
                            result.threatDetails.push_back(std::move(detail));
                        }
                    }
                } else {
                    Logger::Debug("ScanMailItemInternal: PhishingEmailDetector not initialized, skipping");
                }
            }

            // ================================================================
            // Spam detection — use SpamDetector if available
            // ================================================================
            if (m_config.detectSpam && !result.hasMalware && !result.isPhishing) {
                if (SpamDetector::HasInstance()) {
                    auto& spamDetector = SpamDetector::Instance();

                    auto spamResult = spamDetector.AnalyzeEmail(
                        mailInfo.subject,
                        mailInfo.bodyText,
                        mailInfo.bodyHtml,
                        mailInfo.senderEmail,
                        mailInfo.toRecipients,
                        mailInfo.headers);

                    result.spamScore = spamResult.spamScore;
                    result.isSpam = spamResult.isSpam;

                    if (result.isSpam) {
                        result.isClean = false;
                        result.riskScore = std::max(result.riskScore, spamResult.spamScore);
                        result.primaryThreatName = "Spam detected (score=" + std::to_string(spamResult.spamScore) + ")";
                        result.scanLog = "SpamDetector";
                        result.detectedThreats = static_cast<EmailThreatType>(
                            static_cast<uint32_t>(result.detectedThreats) |
                            static_cast<uint32_t>(EmailThreatType::Spam));
                        result.recommendedAction = ScanAction::TagSubject;
                    }
                } else {
                    Logger::Debug("ScanMailItemInternal: SpamDetector not initialized, skipping");
                }
            }

            // ================================================================
            // Link / URL scanning — extract URLs from body and check reputation
            // ================================================================
            if (m_config.scanLinks) {
                // Extract URLs from both plain text and HTML body
                std::vector<std::string> urls = ExtractUrlsFromText(mailInfo.bodyText);
                auto htmlUrls = ExtractUrlsFromText(mailInfo.bodyHtml);
                urls.insert(urls.end(), htmlUrls.begin(), htmlUrls.end());

                // De-duplicate
                std::sort(urls.begin(), urls.end());
                urls.erase(std::unique(urls.begin(), urls.end()), urls.end());

                if (!urls.empty() && PhishingEmailDetector::HasInstance()) {
                    auto& phishDetector = PhishingEmailDetector::Instance();

                    for (const auto& url : urls) {
                        if (phishDetector.IsMaliciousLink(url)) {
                            result.maliciousUrls.push_back(url);
                            result.isClean = false;
                            result.riskScore = std::max(result.riskScore, 85);
                            result.detectedThreats = static_cast<EmailThreatType>(
                                static_cast<uint32_t>(result.detectedThreats) |
                                static_cast<uint32_t>(EmailThreatType::MaliciousURL));

                            if (result.primaryThreatName.empty()) {
                                result.primaryThreatName = "Malicious URL detected: " + url;
                                result.recommendedAction = ScanAction::Block;
                            }
                        }
                    }
                }
            }

        } catch (const std::exception& e) {
            Logger::Error("ScanMailItemInternal - Exception: {}", e.what());
            m_stats.scanErrors++;
        }

        auto endTime = std::chrono::steady_clock::now();
        result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);

        return result;
    }

    void ProcessMailEvent(const MailItemInfo& mailInfo, MailEventType eventType,
                         IDispatch* pMailItem = nullptr) {
        try {
            // Take shared lock for config-dependent scanning, release before callbacks
            EmailScanResult scanResult;
            {
                std::shared_lock lock(m_mutex);
                scanResult = ScanMailItemInternal(mailInfo);
            }

            // Create event
            MailScanEvent event;
            event.eventId = GenerateEventId();
            event.mailItem = mailInfo;
            event.eventType = eventType;
            event.scanResult = scanResult;
            event.timestamp = std::chrono::system_clock::now();
            event.scanDuration = scanResult.scanDuration;

            // Determine action based on scan result severity
            if (scanResult.hasMalware) {
                event.actionTaken = OutlookScanAction::Delete;
                m_stats.malwareBlocked++;
                m_stats.threatsDetected++;
            } else if (scanResult.isPhishing) {
                event.actionTaken = OutlookScanAction::Quarantine;
                m_stats.phishingBlocked++;
                m_stats.threatsDetected++;
            } else if (!scanResult.maliciousUrls.empty()) {
                event.actionTaken = OutlookScanAction::Block;
                m_stats.threatsDetected++;
            } else if (scanResult.isSpam) {
                event.actionTaken = OutlookScanAction::TagSubject;
                m_stats.spamTagged++;
            } else {
                event.actionTaken = OutlookScanAction::Allow;
                m_stats.allowed++;
            }

            // Execute the determined action if we have a live COM pointer
            if (pMailItem && event.actionTaken != OutlookScanAction::Allow) {
                ExecuteAction(pMailItem, mailInfo, event.actionTaken);
            }

            // Invoke callbacks (snapshot lists to avoid lock during invocation)
            InvokeMailEventCallbacks(event);
            InvokeScanCallbacks(mailInfo, scanResult);

            if (event.actionTaken != OutlookScanAction::Allow) {
                InvokeBlockCallbacks(mailInfo, event.actionTaken);
            }

        } catch (const std::exception& e) {
            Logger::Error("ProcessMailEvent - Exception: {}", e.what());
        }
    }

    // Execute an enforcement action on a live COM mail item
    void ExecuteAction(IDispatch* pMailItem, const MailItemInfo& mailInfo,
                       OutlookScanAction action) {
        try {
            switch (action) {
                case OutlookScanAction::Delete:
                    if (InvokeDispatchMethod(pMailItem, DISPID_DELETE)) {
                        Logger::Info("ProcessMailEvent: Deleted malicious item (subject={}, sender={})",
                            mailInfo.subject, mailInfo.senderEmail);
                    }
                    break;

                case OutlookScanAction::Quarantine: {
                    CComPtr<IDispatch> pJunkFolder;
                    {
                        std::shared_lock lock(m_mutex);
                        pJunkFolder = m_pJunkFolder;
                    }
                    if (pJunkFolder && MoveMailItemToFolder(pMailItem, pJunkFolder)) {
                        {
                            std::unique_lock lock(m_mutex);
                            m_quarantinedEntryIds.insert(mailInfo.entryId);
                        }
                        m_stats.quarantined++;
                        Logger::Info("ProcessMailEvent: Quarantined item (subject={}, sender={})",
                            mailInfo.subject, mailInfo.senderEmail);
                    } else {
                        Logger::Warn("ProcessMailEvent: Quarantine failed — Junk folder unavailable");
                    }
                    break;
                }

                case OutlookScanAction::TagSubject: {
                    std::wstring wTag;
                    // Determine tag based on context
                    wTag = L"[SPAM] ";

                    auto subjectOpt = GetDispatchStringProperty(pMailItem, DISPID_SUBJECT);
                    std::string currentSubject = subjectOpt.value_or("");
                    std::string tagged = StringUtils::ToNarrow(wTag) + currentSubject;
                    SetDispatchStringProperty(pMailItem, DISPID_SUBJECT,
                        StringUtils::ToWide(tagged));
                    InvokeDispatchMethod(pMailItem, DISPID_SAVE);

                    Logger::Info("ProcessMailEvent: Tagged item subject (subject={}, sender={})",
                        mailInfo.subject, mailInfo.senderEmail);
                    break;
                }

                case OutlookScanAction::Block:
                    // For blocked items, move to Junk as a fallback
                    {
                        CComPtr<IDispatch> pJunkFolder;
                        {
                            std::shared_lock lock(m_mutex);
                            pJunkFolder = m_pJunkFolder;
                        }
                        if (pJunkFolder) {
                            MoveMailItemToFolder(pMailItem, pJunkFolder);
                        }
                    }
                    Logger::Info("ProcessMailEvent: Blocked item (subject={}, sender={})",
                        mailInfo.subject, mailInfo.senderEmail);
                    break;

                default:
                    break;
            }
        } catch (const std::exception& e) {
            Logger::Error("ExecuteAction - Exception: {}", e.what());
        }
    }

    void InvokeMailEventCallbacks(const MailScanEvent& event) {
        // Snapshot callbacks under lock, then invoke outside lock to prevent deadlock
        std::vector<MailEventCallback> callbacksCopy;
        {
            std::shared_lock lock(m_mutex);
            callbacksCopy = m_mailEventCallbacks;
        }

        for (const auto& callback : callbacksCopy) {
            try {
                if (callback) {
                    callback(event);
                }
            } catch (const std::exception& e) {
                Logger::Error("InvokeMailEventCallbacks: Callback threw: {}", e.what());
            }
        }
    }

    void InvokeScanCallbacks(const MailItemInfo& mailInfo, const EmailScanResult& result) {
        std::vector<OutlookScanResultCallback> callbacksCopy;
        {
            std::shared_lock lock(m_mutex);
            callbacksCopy = m_scanCallbacks;
        }

        for (const auto& callback : callbacksCopy) {
            try {
                if (callback) {
                    callback(mailInfo, result);
                }
            } catch (const std::exception& e) {
                Logger::Error("InvokeScanCallbacks: Callback threw: {}", e.what());
            }
        }
    }

    void InvokeBlockCallbacks(const MailItemInfo& mailInfo, OutlookScanAction action) {
        std::vector<BlockCallback> callbacksCopy;
        {
            std::shared_lock lock(m_mutex);
            callbacksCopy = m_blockCallbacks;
        }

        for (const auto& callback : callbacksCopy) {
            try {
                if (callback) {
                    callback(mailInfo, action);
                }
            } catch (const std::exception& e) {
                Logger::Error("InvokeBlockCallbacks: Callback threw: {}", e.what());
            }
        }
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };
    bool m_comInitialized{ false };
    ModuleStatus m_status{ ModuleStatus::Uninitialized };
    AddinStatus m_addinStatus{ AddinStatus::Disconnected };

    OutlookScannerConfiguration m_config;
    OutlookScannerStatistics m_stats;

    // COM interface pointers (RAII via CComPtr)
    CComPtr<IDispatch> m_pOutlookApp;
    CComPtr<IDispatch> m_pNamespace;
    CComPtr<IDispatch> m_pJunkFolder;

    // Callbacks
    std::vector<MailEventCallback> m_mailEventCallbacks;
    std::vector<OutlookScanResultCallback> m_scanCallbacks;
    std::vector<BlockCallback> m_blockCallbacks;
    std::vector<PreSendCallback> m_preSendCallbacks;
    std::vector<ErrorCallback> m_errorCallbacks;

    // Folders
    std::vector<FolderInfo> m_monitoredFolders;

    // Set of EntryIDs currently in quarantine (protected from deletion)
    std::unordered_set<std::string> m_quarantinedEntryIds;
};

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

std::atomic<bool> OutlookScanner::s_instanceCreated{ false };

OutlookScanner& OutlookScanner::Instance() noexcept {
    static OutlookScanner instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

[[nodiscard]] bool OutlookScanner::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

OutlookScanner::OutlookScanner()
    : m_impl(std::make_unique<OutlookScannerImpl>()) {
    Logger::Info("OutlookScanner instance created");
}

OutlookScanner::~OutlookScanner() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    Logger::Info("OutlookScanner instance destroyed");
}

// ============================================================================
// PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

bool OutlookScanner::Initialize(const OutlookScannerConfiguration& config) {
    return m_impl->Initialize(config);
}

void OutlookScanner::Shutdown() {
    m_impl->Shutdown();
}

bool OutlookScanner::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus OutlookScanner::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

AddinStatus OutlookScanner::GetAddinStatus() const noexcept {
    return m_impl->GetAddinStatus();
}

bool OutlookScanner::UpdateConfiguration(const OutlookScannerConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

OutlookScannerConfiguration OutlookScanner::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

// ========================================================================
// ADD-IN OPERATIONS
// ========================================================================

bool OutlookScanner::InitializeAddin() {
    return m_impl->InitializeAddin();
}

bool OutlookScanner::ShutdownAddin() {
    return m_impl->ShutdownAddin();
}

bool OutlookScanner::ConnectToOutlook() {
    return m_impl->ConnectToOutlook();
}

void OutlookScanner::DisconnectFromOutlook() {
    m_impl->DisconnectFromOutlook();
}

bool OutlookScanner::IsConnected() const noexcept {
    return m_impl->IsConnected();
}

OutlookVersionInfo OutlookScanner::GetOutlookVersion() const {
    return m_impl->GetOutlookVersion();
}

// ========================================================================
// EVENT HANDLERS
// ========================================================================

void OutlookScanner::OnNewMail(IDispatch* pDispatchMailItem) {
    m_impl->OnNewMail(static_cast<void*>(pDispatchMailItem));
}

void OutlookScanner::OnNewMailEx(const std::string& entryIdCollection) {
    m_impl->OnNewMailEx(entryIdCollection);
}

bool OutlookScanner::OnItemSend(IDispatch* pDispatchMailItem, bool& cancel) {
    return m_impl->OnItemSend(static_cast<void*>(pDispatchMailItem), cancel);
}

void OutlookScanner::OnItemAdd(IDispatch* pDispatchItem) {
    m_impl->OnItemAdd(static_cast<void*>(pDispatchItem));
}

void OutlookScanner::OnItemChange(IDispatch* pDispatchItem) {
    m_impl->OnItemChange(static_cast<void*>(pDispatchItem));
}

void OutlookScanner::OnBeforeDelete(IDispatch* pDispatchItem, bool& cancel) {
    m_impl->OnBeforeDelete(static_cast<void*>(pDispatchItem), cancel);
}

void OutlookScanner::OnAttachmentAdd(IDispatch* pDispatchAttachment, bool& cancel) {
    m_impl->OnAttachmentAdd(static_cast<void*>(pDispatchAttachment), cancel);
}

// ========================================================================
// SCANNING
// ========================================================================

EmailScanResult OutlookScanner::ScanMailItem(const MailItemInfo& mailInfo) {
    return m_impl->ScanMailItem(mailInfo);
}

EmailScanResult OutlookScanner::ScanMailItemById(const std::string& entryId) {
    return m_impl->ScanMailItemById(entryId);
}

std::optional<MailItemInfo> OutlookScanner::GetMailItemInfo(IDispatch* pDispatch) {
    return m_impl->GetMailItemInfo(static_cast<void*>(pDispatch));
}

std::optional<fs::path> OutlookScanner::ExtractAttachment(IDispatch* pDispatch, size_t attachmentIndex) {
    return m_impl->ExtractAttachment(static_cast<void*>(pDispatch), attachmentIndex);
}

// ========================================================================
// FOLDER OPERATIONS
// ========================================================================

std::vector<FolderInfo> OutlookScanner::GetMonitoredFolders() const {
    return m_impl->GetMonitoredFolders();
}

bool OutlookScanner::AddMonitoredFolder(const std::string& folderPath) {
    return m_impl->AddMonitoredFolder(folderPath);
}

bool OutlookScanner::RemoveMonitoredFolder(const std::string& folderPath) {
    return m_impl->RemoveMonitoredFolder(folderPath);
}

std::vector<EmailScanResult> OutlookScanner::ScanFolder(const std::string& folderPath, bool recursive) {
    return m_impl->ScanFolder(folderPath, recursive);
}

// ========================================================================
// ACTIONS
// ========================================================================

bool OutlookScanner::MoveToJunk(const std::string& entryId) {
    return m_impl->MoveToJunk(entryId);
}

bool OutlookScanner::DeleteMail(const std::string& entryId) {
    return m_impl->DeleteMail(entryId);
}

bool OutlookScanner::StripAttachments(const std::string& entryId, const std::vector<std::string>& attachmentNames) {
    return m_impl->StripAttachments(entryId, attachmentNames);
}

bool OutlookScanner::TagSubject(const std::string& entryId, const std::string& tag) {
    return m_impl->TagSubject(entryId, tag);
}

// ========================================================================
// CALLBACKS
// ========================================================================

void OutlookScanner::RegisterMailEventCallback(MailEventCallback callback) {
    m_impl->RegisterMailEventCallback(std::move(callback));
}

void OutlookScanner::RegisterScanCallback(OutlookScanResultCallback callback) {
    m_impl->RegisterScanCallback(std::move(callback));
}

void OutlookScanner::RegisterBlockCallback(BlockCallback callback) {
    m_impl->RegisterBlockCallback(std::move(callback));
}

void OutlookScanner::RegisterPreSendCallback(PreSendCallback callback) {
    m_impl->RegisterPreSendCallback(std::move(callback));
}

void OutlookScanner::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void OutlookScanner::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

// ========================================================================
// STATISTICS
// ========================================================================

OutlookScannerStatisticsSnapshot OutlookScanner::GetStatistics() const {
    return m_impl->GetStatistics();
}

void OutlookScanner::ResetStatistics() {
    m_impl->ResetStatistics();
}

// ========================================================================
// DIAGNOSTICS
// ========================================================================

bool OutlookScanner::SelfTest() {
    return m_impl->SelfTest();
}

[[nodiscard]] std::string OutlookScanner::GetVersionString() noexcept {
    std::ostringstream oss;
    oss << OutlookConstants::VERSION_MAJOR << "."
        << OutlookConstants::VERSION_MINOR << "."
        << OutlookConstants::VERSION_PATCH;
    return oss.str();
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetAddinStatusName(AddinStatus status) noexcept {
    switch (status) {
        case AddinStatus::Disconnected: return "Disconnected";
        case AddinStatus::Connecting: return "Connecting";
        case AddinStatus::Connected: return "Connected";
        case AddinStatus::Initializing: return "Initializing";
        case AddinStatus::Ready: return "Ready";
        case AddinStatus::Scanning: return "Scanning";
        case AddinStatus::Error: return "Error";
        case AddinStatus::Disabled: return "Disabled";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetMailEventTypeName(MailEventType type) noexcept {
    switch (type) {
        case MailEventType::NewMail: return "NewMail";
        case MailEventType::ItemSend: return "ItemSend";
        case MailEventType::ItemAdd: return "ItemAdd";
        case MailEventType::ItemChange: return "ItemChange";
        case MailEventType::BeforeDelete: return "BeforeDelete";
        case MailEventType::Reply: return "Reply";
        case MailEventType::ReplyAll: return "ReplyAll";
        case MailEventType::Forward: return "Forward";
        case MailEventType::AttachmentAdd: return "AttachmentAdd";
        case MailEventType::Open: return "Open";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetOutlookScanActionName(OutlookScanAction action) noexcept {
    switch (action) {
        case OutlookScanAction::Allow: return "Allow";
        case OutlookScanAction::Block: return "Block";
        case OutlookScanAction::Quarantine: return "Quarantine";
        case OutlookScanAction::Delete: return "Delete";
        case OutlookScanAction::StripAttachment: return "StripAttachment";
        case OutlookScanAction::TagSubject: return "TagSubject";
        case OutlookScanAction::Prompt: return "Prompt";
        case OutlookScanAction::Log: return "Log";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetFolderTypeName(OutlookFolderType type) noexcept {
    switch (type) {
        case OutlookFolderType::Inbox: return "Inbox";
        case OutlookFolderType::SentItems: return "SentItems";
        case OutlookFolderType::Drafts: return "Drafts";
        case OutlookFolderType::Outbox: return "Outbox";
        case OutlookFolderType::DeletedItems: return "DeletedItems";
        case OutlookFolderType::JunkEmail: return "JunkEmail";
        case OutlookFolderType::Calendar: return "Calendar";
        case OutlookFolderType::Contacts: return "Contacts";
        case OutlookFolderType::Tasks: return "Tasks";
        case OutlookFolderType::Notes: return "Notes";
        case OutlookFolderType::Custom: return "Custom";
        default: return "Unknown";
    }
}

[[nodiscard]] bool IsOutlookRunning() {
    try {
        HandleGuard hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!hSnapshot.valid()) {
            return false;
        }

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (!Process32FirstW(hSnapshot.get(), &pe32)) {
            return false;
        }

        do {
            std::wstring processName = pe32.szExeFile;
            std::wstring lowerName = StringUtils::ToLowerCopy(processName);

            if (lowerName == L"outlook.exe") {
                return true;
            }
        } while (Process32NextW(hSnapshot.get(), &pe32));

        return false;

    } catch (...) {
        return false;
    }
}

[[nodiscard]] std::optional<DWORD> GetOutlookProcessId() {
    try {
        HandleGuard hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!hSnapshot.valid()) {
            return std::nullopt;
        }

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (!Process32FirstW(hSnapshot.get(), &pe32)) {
            return std::nullopt;
        }

        do {
            std::wstring processName = pe32.szExeFile;
            std::wstring lowerName = StringUtils::ToLowerCopy(processName);

            if (lowerName == L"outlook.exe") {
                return pe32.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot.get(), &pe32));

        return std::nullopt;

    } catch (...) {
        return std::nullopt;
    }
}

[[nodiscard]] std::vector<std::string> ParseEntryIdCollection(const std::string& collection) {
    std::vector<std::string> entryIds;

    try {
        // EntryID collection format: comma-separated list of EntryIDs
        std::istringstream iss(collection);
        std::string entryId;

        while (std::getline(iss, entryId, ',')) {
            // Trim whitespace
            entryId.erase(0, entryId.find_first_not_of(" \t\r\n"));
            entryId.erase(entryId.find_last_not_of(" \t\r\n") + 1);

            if (!entryId.empty()) {
                entryIds.push_back(entryId);
            }
        }

    } catch (const std::exception& e) {
        Logger::Error("ParseEntryIdCollection - Exception: {}", e.what());
    }

    return entryIds;
}

}  // namespace Email
}  // namespace ShadowStrike
