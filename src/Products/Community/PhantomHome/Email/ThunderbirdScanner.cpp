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
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "PhantomCore/Utils/FileUtils.hpp"
#include "PhantomCore/Utils/HashUtils.hpp"
#include "PhantomCore/Utils/SystemUtils.hpp"
#include "PhantomCore/Utils/JSONUtils.hpp"
#include "PhantomCore/Utils/ProcessUtils.hpp"
#include "PhantomCore/Utils/Base64Utils.hpp"
#include "PhantomCore/HashStore/HashStore.hpp"
#include "AttachmentScanner.hpp"
#include "PhishingEmailDetector.hpp"
#include "SpamDetector.hpp"
#include "EmailProtection.hpp"

// ============================================================================
// JSON LIBRARY (L1 fix)
// ============================================================================
#include <nlohmann/json.hpp>

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

inline void TrimNarrow(std::string& s) {
    auto notspace = [](unsigned char c) { return !std::isspace(c); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), notspace));
    s.erase(std::find_if(s.rbegin(), s.rend(), notspace).base(), s.end());
}

[[nodiscard]] inline std::string ToLowerCopy(std::string_view s) noexcept {
    std::string r(s);
    for (auto& c : r) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return r;
}

inline bool IEquals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) return false;
    }
    return true;
}

inline constexpr uint32_t kMaxNativeMessageSize = 1024 * 1024;

[[nodiscard]] bool ReadExactFromStdIn(void* buffer, std::streamsize bytes) {
    std::cin.read(static_cast<char*>(buffer), bytes);
    return std::cin.good() && std::cin.gcount() == bytes;
}

[[nodiscard]] bool IsValidNativeHostName(std::string_view hostName) noexcept {
    if (hostName.empty() || hostName.size() > 128) {
        return false;
    }

    for (unsigned char ch : hostName) {
        if (std::isalnum(ch) || ch == '.' || ch == '_' || ch == '-') {
            continue;
        }
        return false;
    }

    return true;
}

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
 * @brief Parse email header line (M7 fix - safe isspace).
 */
[[nodiscard]] bool ParseHeaderLine(std::string_view line, std::string& key, std::string& value) {
    auto colonPos = line.find(':');
    if (colonPos == std::string_view::npos) {
        return false;
    }

    key = std::string(line.substr(0, colonPos));

    // Skip colon and whitespace (M7 fix - cast to unsigned char)
    size_t valueStart = colonPos + 1;
    while (valueStart < line.length() && std::isspace(static_cast<unsigned char>(line[valueStart]))) {
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
    TrimNarrow(email);
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
            TrimNarrow(current);
            if (!current.empty()) {
                recipients.push_back(ExtractEmailAddress(current));
            }
            current.clear();
        } else {
            current += ch;
        }
    }

    // Don't forget last recipient
    TrimNarrow(current);
    if (!current.empty()) {
        recipients.push_back(ExtractEmailAddress(current));
    }

    return recipients;
}

/**
 * @brief Check if line is mbox separator (H2 fix - more lenient matching).
 * Standard mbox From line: "From <sender> <date>" (not all have @)
 * Also handles >From quoting for body lines.
 */
[[nodiscard]] bool IsMboxSeparator(std::string_view line) {
    // Must start with "From " (not ">From ")
    if (!line.starts_with("From ") || line.starts_with(">From ")) {
        return false;
    }
    
    // Remove "From " prefix and check rest
    auto rest = line.substr(5);
    
    // Must have at least one space (between sender and date)
    auto spacePos = rest.find(' ');
    if (spacePos == std::string_view::npos || spacePos == 0) {
        return false;
    }
    
    // Validate the date portion - RFC 5322 mbox envelope line date
    // typically starts with a day-of-week abbreviation (Mon Tue Wed...) or
    // month abbreviation (Jan Feb Mar...). We accept both formats.
    auto datePart = rest.substr(spacePos + 1);
    if (datePart.empty()) {
        return false;
    }

    // Trim leading whitespace from date
    size_t dateStart = 0;
    while (dateStart < datePart.size() &&
           std::isspace(static_cast<unsigned char>(datePart[dateStart]))) {
        ++dateStart;
    }
    if (dateStart >= datePart.size()) {
        return false;
    }
    datePart.remove_prefix(dateStart);

    // Extract the first token of the date
    auto tokenEnd = datePart.find(' ');
    auto firstToken = datePart.substr(0, tokenEnd);

    // RFC 5322 day-of-week abbreviations
    static constexpr std::string_view kDays[] = {
        "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"
    };
    // RFC 5322 month abbreviations
    static constexpr std::string_view kMonths[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };

    for (auto d : kDays) {
        if (firstToken == d) return true;
    }
    for (auto m : kMonths) {
        if (firstToken == m) return true;
    }

    // Also accept numeric day (1-31) as first token for non-standard generators
    if (firstToken.size() <= 2 && firstToken.size() >= 1) {
        bool allDigits = true;
        for (char c : firstToken) {
            if (!std::isdigit(static_cast<unsigned char>(c))) {
                allDigits = false;
                break;
            }
        }
        if (allDigits) {
            int day = 0;
            for (char c : firstToken) day = day * 10 + (c - '0');
            if (day >= 1 && day <= 31) return true;
        }
    }

    return false;
}

/**
 * @brief Check if line is quoted From in body (H2 fix).
 */
[[nodiscard]] bool IsQuotedFromLine(std::string_view line) {
    return line.starts_with(">From ");
}

/**
 * @brief Get user profile directory (L5 fix - log on error).
 */
[[nodiscard]] std::optional<fs::path> GetUserProfileDir() {
    try {
#ifdef _WIN32
        wchar_t path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr, 0, path))) {
            return fs::path(path);
        }
#endif
    } catch (const std::exception& e) {
        Logger::Warn("ThunderbirdScanner: GetUserProfileDir exception: {}", e.what());
    } catch (...) {
        Logger::Warn("ThunderbirdScanner: GetUserProfileDir unknown exception");
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

// ============================================================================
// MIME & ENCODING HELPER FUNCTIONS
// ============================================================================

namespace {

/// @brief Maximum MIME nesting depth to prevent pathological multipart bombs.
inline constexpr size_t kMaxMimeNestingDepth = 10;

/**
 * @brief Decode a quoted-printable encoded string per RFC 2045.
 */
[[nodiscard]] std::string DecodeQuotedPrintable(std::string_view input) {
    std::string output;
    output.reserve(input.size());

    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '=') {
            // Soft line break: =\r\n or =\n
            if (i + 1 < input.size() && input[i + 1] == '\n') {
                ++i; // skip \n
                continue;
            }
            if (i + 2 < input.size() && input[i + 1] == '\r' && input[i + 2] == '\n') {
                i += 2; // skip \r\n
                continue;
            }
            // Hex pair
            if (i + 2 < input.size()) {
                auto hexVal = [](char c) -> int {
                    if (c >= '0' && c <= '9') return c - '0';
                    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                    return -1;
                };
                int hi = hexVal(input[i + 1]);
                int lo = hexVal(input[i + 2]);
                if (hi >= 0 && lo >= 0) {
                    output += static_cast<char>((hi << 4) | lo);
                    i += 2;
                    continue;
                }
            }
            // Malformed =, pass through
            output += '=';
        } else {
            output += input[i];
        }
    }
    return output;
}

/**
 * @brief Decode a base64 encoded string using the infrastructure Base64Utils.
 */
[[nodiscard]] std::string DecodeBase64String(std::string_view input) {
    // Strip whitespace from base64 input (line breaks are common in MIME)
    std::string cleaned;
    cleaned.reserve(input.size());
    for (char c : input) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            cleaned += c;
        }
    }

    std::vector<uint8_t> decoded;
    Utils::Base64DecodeError err = Utils::Base64DecodeError::None;
    Utils::Base64DecodeOptions opts;
    opts.ignoreWhitespace = true;

    if (Utils::Base64Decode(cleaned, decoded, err, opts)) {
        return std::string(decoded.begin(), decoded.end());
    }

    Logger::Debug("ThunderbirdScanner: Base64 decode failed: {}",
                  Utils::Base64DecodeErrorToString(err));
    return {};
}

/**
 * @brief Decode message body based on Content-Transfer-Encoding.
 */
[[nodiscard]] std::string DecodeTransferEncoding(
    std::string_view body,
    std::string_view encoding
) {
    if (encoding.empty() || encoding == "7bit" || encoding == "8bit" || encoding == "binary") {
        return std::string(body);
    }
    if (encoding == "quoted-printable") {
        return DecodeQuotedPrintable(body);
    }
    if (encoding == "base64") {
        return DecodeBase64String(body);
    }
    // Unknown encoding - return raw
    return std::string(body);
}

/**
 * @brief Extract a parameter value from a MIME header (e.g., boundary from Content-Type).
 * Handles both quoted and unquoted parameter values.
 */
[[nodiscard]] std::string ExtractMimeParam(std::string_view header, std::string_view paramName) {
    // Search case-insensitively for paramName=
    std::string lowerHeader(header);
    std::string lowerParam(paramName);
    for (auto& c : lowerHeader) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    for (auto& c : lowerParam) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    std::string searchKey = lowerParam + "=";
    auto pos = lowerHeader.find(searchKey);
    if (pos == std::string::npos) {
        return {};
    }

    size_t valueStart = pos + searchKey.size();
    if (valueStart >= header.size()) {
        return {};
    }

    // Handle quoted value
    if (header[valueStart] == '"') {
        ++valueStart;
        auto endQuote = header.find('"', valueStart);
        if (endQuote == std::string_view::npos) {
            return std::string(header.substr(valueStart));
        }
        return std::string(header.substr(valueStart, endQuote - valueStart));
    }

    // Unquoted value - ends at ; or whitespace or end of string
    size_t valueEnd = valueStart;
    while (valueEnd < header.size() && header[valueEnd] != ';' &&
           !std::isspace(static_cast<unsigned char>(header[valueEnd]))) {
        ++valueEnd;
    }
    return std::string(header.substr(valueStart, valueEnd - valueStart));
}

/**
 * @brief Check if a Content-Type indicates multipart.
 */
[[nodiscard]] bool IsMultipartContentType(std::string_view contentType) {
    std::string lower(contentType.substr(0, 20));
    for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return lower.starts_with("multipart/");
}

/**
 * @brief Check if Content-Disposition indicates an attachment.
 */
[[nodiscard]] bool IsAttachmentDisposition(std::string_view disposition) {
    if (disposition.empty()) return false;
    std::string lower(disposition);
    for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    // "attachment" or "attachment; filename=..."
    return lower.starts_with("attachment");
}

/**
 * @brief Extract filename from Content-Disposition header.
 */
[[nodiscard]] std::string ExtractAttachmentFilename(std::string_view disposition) {
    return ExtractMimeParam(disposition, "filename");
}

/**
 * @brief Represents a single MIME part.
 */
struct MimePart {
    std::map<std::string, std::string> headers;
    std::string body;
    std::string contentType;
    std::string contentDisposition;
    std::string transferEncoding;
    bool isAttachment = false;
    std::string filename;
};

/**
 * @brief Parse MIME multipart body into parts.
 * @param body       Raw body content after headers.
 * @param boundary   The multipart boundary (without -- prefix).
 * @param depth      Current nesting depth for recursion protection.
 * @return Vector of parsed MIME parts.
 */
[[nodiscard]] std::vector<MimePart> ParseMultipartBody(
    std::string_view body,
    std::string_view boundary,
    size_t depth = 0
) {
    std::vector<MimePart> parts;

    if (depth > kMaxMimeNestingDepth || boundary.empty()) {
        return parts;
    }

    std::string delimiter = "--" + std::string(boundary);
    std::string closeDelimiter = delimiter + "--";

    // Find the first boundary
    auto pos = body.find(delimiter);
    if (pos == std::string_view::npos) {
        return parts;
    }

    // Skip past first delimiter line
    pos += delimiter.size();
    if (pos < body.size() && body[pos] == '\r') ++pos;
    if (pos < body.size() && body[pos] == '\n') ++pos;

    while (pos < body.size()) {
        // Find next boundary
        auto nextBoundary = body.find(delimiter, pos);
        if (nextBoundary == std::string_view::npos) {
            break;
        }

        // Extract this part's content (between current pos and next boundary)
        auto partContent = body.substr(pos, nextBoundary - pos);

        // Remove trailing \r\n before boundary
        if (partContent.size() >= 2 && partContent.ends_with("\r\n")) {
            partContent.remove_suffix(2);
        } else if (partContent.size() >= 1 && partContent.ends_with("\n")) {
            partContent.remove_suffix(1);
        }

        // Parse part headers and body
        MimePart part;
        auto headerEnd = partContent.find("\r\n\r\n");
        size_t bodyStart = 0;
        if (headerEnd != std::string_view::npos) {
            bodyStart = headerEnd + 4;
        } else {
            headerEnd = partContent.find("\n\n");
            if (headerEnd != std::string_view::npos) {
                bodyStart = headerEnd + 2;
            }
        }

        if (headerEnd != std::string_view::npos) {
            // Parse part headers (with folding support)
            auto headersStr = partContent.substr(0, headerEnd);
            std::string currentKey, currentValue;

            auto commitHeader = [&]() {
                if (!currentKey.empty()) {
                    part.headers[currentKey] = currentValue;
                    if (IEquals(currentKey, "Content-Type")) {
                        part.contentType = currentValue;
                    } else if (IEquals(currentKey, "Content-Disposition")) {
                        part.contentDisposition = currentValue;
                    } else if (IEquals(currentKey, "Content-Transfer-Encoding")) {
                        part.transferEncoding = currentValue;
                        // Normalize to lowercase
                        for (auto& c : part.transferEncoding)
                            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                    }
                }
            };

            std::istringstream headerStream{std::string(headersStr)};
            std::string hLine;
            while (std::getline(headerStream, hLine)) {
                // Remove trailing \r
                if (!hLine.empty() && hLine.back() == '\r') hLine.pop_back();

                // Folded continuation line (starts with whitespace)
                if (!hLine.empty() &&
                    (hLine[0] == ' ' || hLine[0] == '\t') &&
                    !currentKey.empty()) {
                    currentValue += " ";
                    size_t ws = 0;
                    while (ws < hLine.size() &&
                           std::isspace(static_cast<unsigned char>(hLine[ws]))) ++ws;
                    currentValue += hLine.substr(ws);
                    continue;
                }

                // Commit previous header
                commitHeader();

                // Parse new header
                auto colon = hLine.find(':');
                if (colon != std::string::npos) {
                    currentKey = hLine.substr(0, colon);
                    size_t valStart = colon + 1;
                    while (valStart < hLine.size() &&
                           std::isspace(static_cast<unsigned char>(hLine[valStart]))) ++valStart;
                    currentValue = hLine.substr(valStart);
                } else {
                    currentKey.clear();
                    currentValue.clear();
                }
            }
            commitHeader();

            part.body = std::string(partContent.substr(bodyStart));
        } else {
            // No headers - entire content is body
            part.body = std::string(partContent);
        }

        // Determine if this is an attachment
        if (IsAttachmentDisposition(part.contentDisposition)) {
            part.isAttachment = true;
            part.filename = ExtractAttachmentFilename(part.contentDisposition);
        } else if (!part.contentType.empty()) {
            // Also check Content-Type name= for inline attachments
            auto name = ExtractMimeParam(part.contentType, "name");
            if (!name.empty() && !part.contentType.starts_with("text/") &&
                !IsMultipartContentType(part.contentType)) {
                part.isAttachment = true;
                part.filename = name;
            }
        }

        parts.push_back(std::move(part));

        // Advance past boundary
        pos = nextBoundary + delimiter.size();

        // Check for closing boundary
        if (pos + 2 <= body.size() && body[pos] == '-' && body[pos + 1] == '-') {
            break; // End of multipart
        }

        // Skip line ending after boundary
        if (pos < body.size() && body[pos] == '\r') ++pos;
        if (pos < body.size() && body[pos] == '\n') ++pos;
    }

    return parts;
}

/**
 * @brief Recursively extract text bodies and count attachments from MIME parts.
 */
void ExtractMimeContent(
    const std::vector<MimePart>& parts,
    std::string& bodyText,
    std::string& bodyHtml,
    size_t& attachmentCount,
    size_t maxBodySize,
    size_t depth = 0
) {
    if (depth > kMaxMimeNestingDepth) return;

    for (const auto& part : parts) {
        if (part.isAttachment) {
            ++attachmentCount;
            continue;
        }

        // Check if this part is itself multipart
        if (IsMultipartContentType(part.contentType)) {
            auto innerBoundary = ExtractMimeParam(part.contentType, "boundary");
            if (!innerBoundary.empty()) {
                auto innerParts = ParseMultipartBody(part.body, innerBoundary, depth + 1);
                ExtractMimeContent(innerParts, bodyText, bodyHtml,
                                   attachmentCount, maxBodySize, depth + 1);
            }
            continue;
        }

        // Decode the body
        std::string decodedBody = DecodeTransferEncoding(part.body, part.transferEncoding);

        // Determine content type
        std::string lowerCT(part.contentType);
        for (auto& c : lowerCT) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

        if (lowerCT.starts_with("text/plain") && bodyText.size() < maxBodySize) {
            size_t remaining = maxBodySize - bodyText.size();
            bodyText += decodedBody.substr(0, remaining);
        } else if (lowerCT.starts_with("text/html") && bodyHtml.size() < maxBodySize) {
            size_t remaining = maxBodySize - bodyHtml.size();
            bodyHtml += decodedBody.substr(0, remaining);
        }
    }
}

/**
 * @brief Unescape a JavaScript string literal value from prefs.js.
 * Handles standard escape sequences: \\, \", \n, \r, \t, \uXXXX.
 */
[[nodiscard]] std::string UnescapeJsString(std::string_view value) {
    std::string result;
    result.reserve(value.size());

    for (size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '\\' && i + 1 < value.size()) {
            char next = value[i + 1];
            switch (next) {
                case '\\': result += '\\'; ++i; break;
                case '"':  result += '"';  ++i; break;
                case '\'': result += '\''; ++i; break;
                case 'n':  result += '\n'; ++i; break;
                case 'r':  result += '\r'; ++i; break;
                case 't':  result += '\t'; ++i; break;
                case 'u': {
                    // \uXXXX - Unicode escape
                    if (i + 5 < value.size()) {
                        auto hexToInt = [](char c) -> int {
                            if (c >= '0' && c <= '9') return c - '0';
                            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                            return -1;
                        };
                        int h3 = hexToInt(value[i + 2]);
                        int h2 = hexToInt(value[i + 3]);
                        int h1 = hexToInt(value[i + 4]);
                        int h0 = hexToInt(value[i + 5]);
                        if (h3 >= 0 && h2 >= 0 && h1 >= 0 && h0 >= 0) {
                            uint32_t codepoint = (h3 << 12) | (h2 << 8) | (h1 << 4) | h0;
                            // Encode as UTF-8
                            if (codepoint < 0x80) {
                                result += static_cast<char>(codepoint);
                            } else if (codepoint < 0x800) {
                                result += static_cast<char>(0xC0 | (codepoint >> 6));
                                result += static_cast<char>(0x80 | (codepoint & 0x3F));
                            } else {
                                result += static_cast<char>(0xE0 | (codepoint >> 12));
                                result += static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F));
                                result += static_cast<char>(0x80 | (codepoint & 0x3F));
                            }
                            i += 5;
                            break;
                        }
                    }
                    // Malformed \u - pass through
                    result += '\\';
                    break;
                }
                default:
                    // Unknown escape - pass through
                    result += '\\';
                    break;
            }
        } else {
            result += value[i];
        }
    }
    return result;
}

/**
 * @brief Parse a single user_pref() line from Thunderbird's prefs.js.
 * @return pair of (key, value) or empty strings on failure.
 */
[[nodiscard]] std::pair<std::string, std::string> ParsePrefsJsLine(std::string_view line) {
    // Format: user_pref("key", "value");  or  user_pref("key", value);
    static constexpr std::string_view kPrefix = "user_pref(\"";

    // Trim whitespace
    while (!line.empty() && std::isspace(static_cast<unsigned char>(line.front()))) {
        line.remove_prefix(1);
    }

    if (!line.starts_with(kPrefix)) {
        return {};
    }
    line.remove_prefix(kPrefix.size());

    // Find the closing quote for the key (handling escaped quotes)
    std::string key;
    size_t i = 0;
    while (i < line.size()) {
        if (line[i] == '\\' && i + 1 < line.size()) {
            key += line[i];
            key += line[i + 1];
            i += 2;
        } else if (line[i] == '"') {
            break;
        } else {
            key += line[i];
            ++i;
        }
    }
    if (i >= line.size()) return {};

    // Unescape the key
    key = UnescapeJsString(key);
    line.remove_prefix(i + 1); // skip closing "

    // Expect ", " or ","
    while (!line.empty() && (line.front() == ',' || line.front() == ' ')) {
        line.remove_prefix(1);
    }

    // Parse value - may be quoted string, number, or boolean
    std::string value;
    if (!line.empty() && line.front() == '"') {
        // Quoted string value
        line.remove_prefix(1);
        size_t j = 0;
        while (j < line.size()) {
            if (line[j] == '\\' && j + 1 < line.size()) {
                value += line[j];
                value += line[j + 1];
                j += 2;
            } else if (line[j] == '"') {
                break;
            } else {
                value += line[j];
                ++j;
            }
        }
        value = UnescapeJsString(value);
    } else {
        // Unquoted value (number or boolean)
        while (!line.empty() && line.front() != ')' && line.front() != ';') {
            value += line.front();
            line.remove_prefix(1);
        }
        // Trim
        while (!value.empty() &&
               std::isspace(static_cast<unsigned char>(value.back()))) {
            value.pop_back();
        }
    }

    return {key, value};
}

/**
 * @brief Validate that a file path is safe (no directory traversal relative to base).
 */
[[nodiscard]] bool IsPathSafe(const fs::path& candidate, const fs::path& base) {
    try {
        auto canonicalCandidate = fs::weakly_canonical(candidate);
        auto canonicalBase = fs::weakly_canonical(base);
        auto candidateStr = canonicalCandidate.string();
        auto baseStr = canonicalBase.string();
        return candidateStr.starts_with(baseStr);
    } catch (...) {
        return false;
    }
}

} // anonymous namespace (MIME helpers)

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

[[nodiscard]] std::string ThunderbirdScannerStatisticsSnapshot::ToJson() const {
    nlohmann::json j;
    j["totalScanned"] = totalScanned;
    j["newMessagesScanned"] = newMessagesScanned;
    j["foldersMonitored"] = foldersMonitored;
    j["threatsDetected"] = threatsDetected;
    j["malwareBlocked"] = malwareBlocked;
    j["phishingBlocked"] = phishingBlocked;
    j["spamMarked"] = spamMarked;
    j["nativeMessagesReceived"] = nativeMessagesReceived;
    j["nativeMessagesProcessed"] = nativeMessagesProcessed;
    j["fileChangesDetected"] = fileChangesDetected;
    j["parseErrors"] = parseErrors;
    j["scanErrors"] = scanErrors;
    
    nlohmann::json eventTypes = nlohmann::json::array();
    for (const auto& count : byEventType) {
        eventTypes.push_back(count);
    }
    j["byEventType"] = eventTypes;
    
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

[[nodiscard]] ThunderbirdScannerStatisticsSnapshot ThunderbirdScannerStatistics::ToSnapshot() const noexcept {
    ThunderbirdScannerStatisticsSnapshot snapshot;
    snapshot.totalScanned = totalScanned.load(std::memory_order_relaxed);
    snapshot.newMessagesScanned = newMessagesScanned.load(std::memory_order_relaxed);
    snapshot.foldersMonitored = foldersMonitored.load(std::memory_order_relaxed);
    snapshot.threatsDetected = threatsDetected.load(std::memory_order_relaxed);
    snapshot.malwareBlocked = malwareBlocked.load(std::memory_order_relaxed);
    snapshot.phishingBlocked = phishingBlocked.load(std::memory_order_relaxed);
    snapshot.spamMarked = spamMarked.load(std::memory_order_relaxed);
    snapshot.nativeMessagesReceived = nativeMessagesReceived.load(std::memory_order_relaxed);
    snapshot.nativeMessagesProcessed = nativeMessagesProcessed.load(std::memory_order_relaxed);
    snapshot.fileChangesDetected = fileChangesDetected.load(std::memory_order_relaxed);
    snapshot.parseErrors = parseErrors.load(std::memory_order_relaxed);
    snapshot.scanErrors = scanErrors.load(std::memory_order_relaxed);
    
    for (size_t i = 0; i < byEventType.size(); ++i) {
        snapshot.byEventType[i] = byEventType[i].load(std::memory_order_relaxed);
    }
    
    snapshot.startTime = startTime;
    return snapshot;
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
class ThunderbirdScannerImpl final {
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
    ThunderbirdScanResultCallback m_scanResultCallback;
    NativeMessageCallback m_nativeMessageCallback;
    ErrorCallback m_errorCallback;

    // Monitoring
    std::vector<MailboxFolder> m_monitoredFolders;
    std::unordered_map<std::wstring, HANDLE> m_directoryHandles;
    std::unordered_map<std::wstring, size_t> m_lastKnownSizes;  // For mbox file size tracking
    std::unordered_map<std::wstring, size_t> m_lastScannedOffsets; // Byte offset of last-scanned position

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
                fs::path profilesPath = *userProfileDir / StringUtils::ToWide(relativePath);

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
            std::string currentPath;
            bool isRelative = true;  // M3 fix: track IsRelative flag
            fs::path basePath = iniPath.parent_path();

            while (std::getline(iniFile, line)) {
                TrimNarrow(line);

                if (line.empty() || line[0] == ';' || line[0] == '#') {
                    continue;
                }

                // Section header
                if (line[0] == '[' && line.back() == ']') {
                    // Save previous profile
                    if (currentSection.starts_with("Profile") && !currentProfile.name.empty()) {
                        // M3 fix: Apply IsRelative logic
                        if (isRelative) {
                            currentProfile.path = basePath / currentPath;
                        } else {
                            currentProfile.path = fs::path(currentPath);
                        }
                        
                        // M2 fix: Canonicalize and validate path
                        try {
                            currentProfile.path = fs::weakly_canonical(currentProfile.path);
                            
                            // Verify it's under the Thunderbird profiles directory
                            auto canonicalBase = fs::weakly_canonical(basePath);
                            auto profileStr = currentProfile.path.string();
                            auto baseStr = canonicalBase.string();
                            
                            // Path traversal check: profile path must start with base or be absolute outside
                            if (isRelative && profileStr.find(baseStr) != 0) {
                                Logger::Warn("ThunderbirdScanner: Potential path traversal detected in profile path: {}", 
                                             currentPath);
                                // Skip this profile
                            } else {
                                profiles.push_back(currentProfile);
                            }
                        } catch (const std::exception& e) {
                            Logger::Warn("ThunderbirdScanner: Failed to canonicalize profile path {}: {}", 
                                         currentPath, e.what());
                        }
                        
                        currentProfile = ThunderbirdProfile{};
                        currentPath.clear();
                        isRelative = true;
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
                TrimNarrow(key);
                TrimNarrow(value);

                if (currentSection.starts_with("Profile")) {
                    if (key == "Name") {
                        currentProfile.name = value;
                    } else if (key == "Path") {
                        currentPath = value;
                    } else if (key == "IsRelative") {
                        isRelative = (value == "1");  // M3 fix: properly handle IsRelative flag
                    } else if (key == "Default") {
                        currentProfile.isDefault = (value == "1");
                    }
                }
            }

            // Don't forget last profile
            if (currentSection.starts_with("Profile") && !currentProfile.name.empty()) {
                // M3 fix: Apply IsRelative logic
                if (isRelative) {
                    currentProfile.path = basePath / currentPath;
                } else {
                    currentProfile.path = fs::path(currentPath);
                }
                
                // M2 fix: Canonicalize and validate
                try {
                    currentProfile.path = fs::weakly_canonical(currentProfile.path);
                    
                    auto canonicalBase = fs::weakly_canonical(basePath);
                    auto profileStr = currentProfile.path.string();
                    auto baseStr = canonicalBase.string();
                    
                    if (isRelative && profileStr.find(baseStr) != 0) {
                        Logger::Warn("ThunderbirdScanner: Potential path traversal detected in profile path: {}", 
                                     currentPath);
                    } else {
                        profiles.push_back(currentProfile);
                    }
                } catch (const std::exception& e) {
                    Logger::Warn("ThunderbirdScanner: Failed to canonicalize profile path {}: {}", 
                                 currentPath, e.what());
                }
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
                Logger::Debug("ThunderbirdScanner: prefs.js not found at: {}", prefsPath.string());
                return accounts;
            }

            // Validate prefs.js path is under the profile directory
            if (!IsPathSafe(prefsPath, profilePath)) {
                Logger::Warn("ThunderbirdScanner: prefs.js path traversal detected: {}",
                             prefsPath.string());
                return accounts;
            }

            // Check file size to prevent DoS on pathological files
            auto fileSize = fs::file_size(prefsPath);
            if (fileSize > 10 * 1024 * 1024) { // 10MB cap for prefs.js
                Logger::Warn("ThunderbirdScanner: prefs.js exceeds size limit ({} bytes)", fileSize);
                return accounts;
            }

            std::ifstream prefsFile(prefsPath);
            if (!prefsFile) {
                Logger::Error("ThunderbirdScanner: Failed to open prefs.js: {}", prefsPath.string());
                return accounts;
            }

            // Parse all user_pref() lines into a key-value map
            std::unordered_map<std::string, std::string> prefs;
            std::string line;
            size_t lineCount = 0;
            constexpr size_t kMaxLines = 500000;

            while (std::getline(prefsFile, line) && lineCount < kMaxLines) {
                ++lineCount;
                auto [key, value] = ParsePrefsJsLine(line);
                if (!key.empty()) {
                    prefs[key] = value;
                }
            }

            Logger::Debug("ThunderbirdScanner: Parsed {} preferences from prefs.js", prefs.size());

            // Get account list: mail.accountmanager.accounts = "account1,account2,..."
            auto accountListIt = prefs.find("mail.accountmanager.accounts");
            if (accountListIt == prefs.end()) {
                Logger::Debug("ThunderbirdScanner: No mail.accountmanager.accounts found");
                return accounts;
            }

            // Split comma-separated account IDs
            std::vector<std::string> accountIds;
            {
                std::istringstream stream(accountListIt->second);
                std::string accountId;
                while (std::getline(stream, accountId, ',')) {
                    TrimNarrow(accountId);
                    if (!accountId.empty()) {
                        accountIds.push_back(accountId);
                    }
                }
            }

            // Cap account count to prevent pathological inputs
            constexpr size_t kMaxAccounts = 200;
            if (accountIds.size() > kMaxAccounts) {
                Logger::Warn("ThunderbirdScanner: Account count {} exceeds limit, truncating",
                             accountIds.size());
                accountIds.resize(kMaxAccounts);
            }

            for (const auto& acctId : accountIds) {
                ThunderbirdAccount account;
                account.accountId = acctId;

                // Get server key: mail.account.<id>.server = "server1"
                std::string serverKeyPref = "mail.account." + acctId + ".server";
                auto serverKeyIt = prefs.find(serverKeyPref);
                if (serverKeyIt == prefs.end()) continue;

                std::string serverKey = serverKeyIt->second;

                // Get server properties
                auto getServerPref = [&](const std::string& prop) -> std::string {
                    auto it = prefs.find("mail.server." + serverKey + "." + prop);
                    return (it != prefs.end()) ? it->second : std::string{};
                };

                // Server type determines account type
                std::string serverType = getServerPref("type");
                if (serverType == "imap") {
                    account.type = AccountType::IMAP;
                } else if (serverType == "pop3") {
                    account.type = AccountType::POP3;
                } else if (serverType == "none" || serverType == "movemail") {
                    account.type = AccountType::Local;
                } else if (serverType == "nntp") {
                    account.type = AccountType::NNTP;
                } else if (serverType == "rss") {
                    account.type = AccountType::RSS;
                }

                account.serverHost = getServerPref("hostname");
                account.name = getServerPref("name");
                if (account.name.empty()) {
                    account.name = account.serverHost;
                }

                // Get root folder path (directory on disk)
                std::string directory = getServerPref("directory");
                if (!directory.empty()) {
                    account.rootFolderPath = fs::path(directory);
                } else {
                    // Fallback: construct from server key
                    std::string dirRel = getServerPref("directory-rel");
                    if (dirRel.starts_with("[ProfD]")) {
                        account.rootFolderPath = profilePath / dirRel.substr(7);
                    }
                }

                // Validate root folder path against traversal
                if (!account.rootFolderPath.empty()) {
                    try {
                        account.rootFolderPath = fs::weakly_canonical(account.rootFolderPath);
                    } catch (...) {
                        Logger::Warn("ThunderbirdScanner: Failed to canonicalize account path for {}",
                                     acctId);
                    }
                }

                // Get identity (email address)
                std::string identitiesPref = "mail.account." + acctId + ".identities";
                auto identitiesIt = prefs.find(identitiesPref);
                if (identitiesIt != prefs.end() && !identitiesIt->second.empty()) {
                    // Take the first identity
                    std::string firstIdentity = identitiesIt->second;
                    auto commaPos = firstIdentity.find(',');
                    if (commaPos != std::string::npos) {
                        firstIdentity = firstIdentity.substr(0, commaPos);
                    }
                    TrimNarrow(firstIdentity);

                    auto emailIt = prefs.find("mail.identity." + firstIdentity + ".useremail");
                    if (emailIt != prefs.end()) {
                        account.email = emailIt->second;
                    }

                    // Get user-friendly name from identity if server name is empty
                    if (account.name.empty()) {
                        auto fullNameIt = prefs.find("mail.identity." + firstIdentity + ".fullName");
                        if (fullNameIt != prefs.end()) {
                            account.name = fullNameIt->second;
                        }
                    }
                }

                // Check if account is enabled (default: true)
                std::string enabledStr = getServerPref("hidden");
                account.isEnabled = (enabledStr != "true");

                accounts.push_back(std::move(account));
            }

            Logger::Info("ThunderbirdScanner: Enumerated {} accounts from profile: {}",
                         accounts.size(), profilePath.string());

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
                folder.lastModified = std::chrono::clock_cast<std::chrono::system_clock>(
                    fs::last_write_time(entry.path()));

                // Detect special folders
                std::string lowerName = ToLowerCopy(folder.name);
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

            // Validate file size against cap
            auto mboxFileSize = fs::file_size(mboxPath);
            if (mboxFileSize > ThunderbirdConstants::MAX_MBOX_FILE_SIZE) {
                Logger::Error("ThunderbirdScanner: Mbox file exceeds size limit ({} bytes): {}",
                              mboxFileSize, mboxPath.string());
                return messages;
            }

            std::ifstream mboxFile(mboxPath, std::ios::binary);
            if (!mboxFile) {
                Logger::Error("ThunderbirdScanner: Failed to open mbox file: {}", mboxPath.string());
                return messages;
            }

            const size_t bodyLimit = m_config.maxBodyTextSize > 0
                ? m_config.maxBodyTextSize
                : ThunderbirdConstants::DEFAULT_BODY_TEXT_LIMIT;
            const size_t msgLimit = (maxMessages > 0)
                ? std::min(maxMessages, ThunderbirdConstants::MAX_MESSAGES_PER_MBOX)
                : ThunderbirdConstants::MAX_MESSAGES_PER_MBOX;

            std::string line;
            MboxMessage currentMessage;
            bool inHeaders = false;
            bool inBody = false;
            size_t currentOffset = 0;
            std::string rawBody;                   // Accumulate raw body for MIME parsing
            std::string topContentType;            // Top-level Content-Type
            std::string topTransferEncoding;       // Top-level Content-Transfer-Encoding
            std::string currentHeaderKey;          // For header folding
            std::string currentHeaderValue;

            auto finalizeHeaders = [&]() {
                // Commit last folded header
                if (!currentHeaderKey.empty()) {
                    currentMessage.headers[currentHeaderKey] = currentHeaderValue;
                    if (IEquals(currentHeaderKey, "Message-ID")) {
                        currentMessage.messageId = currentHeaderValue;
                    } else if (IEquals(currentHeaderKey, "Subject")) {
                        currentMessage.subject = currentHeaderValue;
                    } else if (IEquals(currentHeaderKey, "From")) {
                        currentMessage.from = ExtractEmailAddress(currentHeaderValue);
                    } else if (IEquals(currentHeaderKey, "To")) {
                        currentMessage.to = ParseRecipients(currentHeaderValue);
                    } else if (IEquals(currentHeaderKey, "Date")) {
                        currentMessage.date = currentHeaderValue;
                    } else if (IEquals(currentHeaderKey, "Content-Type")) {
                        topContentType = currentHeaderValue;
                    } else if (IEquals(currentHeaderKey, "Content-Transfer-Encoding")) {
                        topTransferEncoding = currentHeaderValue;
                        for (auto& c : topTransferEncoding)
                            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                    }
                }
                currentHeaderKey.clear();
                currentHeaderValue.clear();
            };

            auto finalizeMessage = [&]() {
                finalizeHeaders();

                // Parse body using MIME structure
                if (IsMultipartContentType(topContentType)) {
                    auto boundary = ExtractMimeParam(topContentType, "boundary");
                    if (!boundary.empty()) {
                        auto mimeParts = ParseMultipartBody(rawBody, boundary);
                        currentMessage.attachmentCount = 0;
                        ExtractMimeContent(mimeParts,
                                           currentMessage.bodyText,
                                           currentMessage.bodyHtml,
                                           currentMessage.attachmentCount,
                                           bodyLimit);
                    } else {
                        // Multipart with no boundary - treat as plain text
                        currentMessage.bodyText = rawBody.substr(0, bodyLimit);
                    }
                } else {
                    // Single-part message
                    std::string decoded = DecodeTransferEncoding(rawBody, topTransferEncoding);

                    std::string lowerCT(topContentType);
                    for (auto& c : lowerCT)
                        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

                    if (lowerCT.starts_with("text/html")) {
                        currentMessage.bodyHtml = decoded.substr(0, bodyLimit);
                    } else {
                        // Default to text/plain
                        currentMessage.bodyText = decoded.substr(0, bodyLimit);
                    }
                    currentMessage.attachmentCount = 0;
                }
            };

            while (std::getline(mboxFile, line)) {
                // Handle \r\n line endings
                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }
                size_t lineSize = line.size() + 1;  // +1 for newline

                // Check for From_ separator (message boundary)
                if (IsMboxSeparator(line)) {
                    // Save previous message
                    if (inHeaders || inBody) {
                        if (!currentMessage.messageId.empty() || !currentMessage.subject.empty()) {
                            // Finalize MIME body parsing
                            finalizeMessage();
                            currentMessage.messageSize = currentOffset - currentMessage.fileOffset;
                            messages.push_back(currentMessage);

                            if (messages.size() >= msgLimit) {
                                break;
                            }
                        }
                    }

                    // Start new message
                    currentMessage = MboxMessage{};
                    currentMessage.fileOffset = currentOffset;
                    inHeaders = true;
                    inBody = false;
                    rawBody.clear();
                    topContentType.clear();
                    topTransferEncoding.clear();
                    currentHeaderKey.clear();
                    currentHeaderValue.clear();

                    // Parse From_ line
                    std::string from, date;
                    ParseMboxFromLine(line, from, date);

                    currentOffset += lineSize;
                    continue;
                }

                if (inHeaders) {
                    if (line.empty()) {
                        // Empty line marks end of headers - commit last header
                        finalizeHeaders();
                        inHeaders = false;
                        inBody = true;
                    } else if (!line.empty() &&
                               (line[0] == ' ' || line[0] == '\t') &&
                               !currentHeaderKey.empty()) {
                        // Header folding (continuation line per RFC 5322)
                        size_t ws = 0;
                        while (ws < line.size() &&
                               std::isspace(static_cast<unsigned char>(line[ws]))) ++ws;
                        currentHeaderValue += " " + line.substr(ws);
                    } else {
                        // Commit previous header
                        if (!currentHeaderKey.empty()) {
                            currentMessage.headers[currentHeaderKey] = currentHeaderValue;
                            if (IEquals(currentHeaderKey, "Message-ID")) {
                                currentMessage.messageId = currentHeaderValue;
                            } else if (IEquals(currentHeaderKey, "Subject")) {
                                currentMessage.subject = currentHeaderValue;
                            } else if (IEquals(currentHeaderKey, "From")) {
                                currentMessage.from = ExtractEmailAddress(currentHeaderValue);
                            } else if (IEquals(currentHeaderKey, "To")) {
                                currentMessage.to = ParseRecipients(currentHeaderValue);
                            } else if (IEquals(currentHeaderKey, "Date")) {
                                currentMessage.date = currentHeaderValue;
                            } else if (IEquals(currentHeaderKey, "Content-Type")) {
                                topContentType = currentHeaderValue;
                            } else if (IEquals(currentHeaderKey, "Content-Transfer-Encoding")) {
                                topTransferEncoding = currentHeaderValue;
                                for (auto& c : topTransferEncoding)
                                    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                            }
                        }

                        // Parse new header
                        std::string key, value;
                        if (ParseHeaderLine(line, key, value)) {
                            currentHeaderKey = key;
                            currentHeaderValue = value;
                        } else {
                            currentHeaderKey.clear();
                            currentHeaderValue.clear();
                        }
                    }
                } else if (inBody) {
                    // Unquote mboxrd ">From " lines in body
                    if (line.starts_with(">From ")) {
                        rawBody += line.substr(1) + "\n";
                    } else {
                        rawBody += line + "\n";
                    }

                    // Safety cap on raw body accumulation
                    if (rawBody.size() > m_config.maxMessageSize) {
                        rawBody.resize(m_config.maxMessageSize);
                    }
                }

                currentOffset += lineSize;
            }

            // Don't forget last message
            if ((inHeaders || inBody) &&
                (!currentMessage.messageId.empty() || !currentMessage.subject.empty())) {
                finalizeMessage();
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

            mboxFile.seekg(static_cast<std::streamoff>(offset));
            if (!mboxFile.good()) {
                Logger::Error("ThunderbirdScanner: Failed to seek to offset {} in {}",
                              offset, mboxPath.string());
                return std::nullopt;
            }

            const size_t bodyLimit = m_config.maxBodyTextSize > 0
                ? m_config.maxBodyTextSize
                : ThunderbirdConstants::DEFAULT_BODY_TEXT_LIMIT;

            MboxMessage message;
            message.fileOffset = offset;

            std::string line;
            bool inHeaders = true;
            bool firstLine = true;
            size_t bytesRead = 0;
            std::string rawBody;
            std::string topContentType;
            std::string topTransferEncoding;
            std::string currentHeaderKey, currentHeaderValue;

            auto commitHeader = [&]() {
                if (currentHeaderKey.empty()) return;
                message.headers[currentHeaderKey] = currentHeaderValue;
                if (IEquals(currentHeaderKey, "Message-ID")) {
                    message.messageId = currentHeaderValue;
                } else if (IEquals(currentHeaderKey, "Subject")) {
                    message.subject = currentHeaderValue;
                } else if (IEquals(currentHeaderKey, "From")) {
                    message.from = ExtractEmailAddress(currentHeaderValue);
                } else if (IEquals(currentHeaderKey, "To")) {
                    message.to = ParseRecipients(currentHeaderValue);
                } else if (IEquals(currentHeaderKey, "Date")) {
                    message.date = currentHeaderValue;
                } else if (IEquals(currentHeaderKey, "Content-Type")) {
                    topContentType = currentHeaderValue;
                } else if (IEquals(currentHeaderKey, "Content-Transfer-Encoding")) {
                    topTransferEncoding = currentHeaderValue;
                    for (auto& c : topTransferEncoding)
                        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                }
                currentHeaderKey.clear();
                currentHeaderValue.clear();
            };

            while (std::getline(mboxFile, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                bytesRead += line.size() + 1;

                // Skip the From_ line at the start if we seeked to it
                if (firstLine) {
                    firstLine = false;
                    if (IsMboxSeparator(line)) {
                        continue; // Skip the envelope From_ line
                    }
                }

                // Check for next message boundary (end of this message)
                if (!firstLine && IsMboxSeparator(line)) {
                    break;
                }

                if (inHeaders) {
                    if (line.empty()) {
                        commitHeader();
                        inHeaders = false;
                    } else if ((line[0] == ' ' || line[0] == '\t') && !currentHeaderKey.empty()) {
                        // Header folding
                        size_t ws = 0;
                        while (ws < line.size() &&
                               std::isspace(static_cast<unsigned char>(line[ws]))) ++ws;
                        currentHeaderValue += " " + line.substr(ws);
                    } else {
                        commitHeader();
                        std::string key, value;
                        if (ParseHeaderLine(line, key, value)) {
                            currentHeaderKey = key;
                            currentHeaderValue = value;
                        }
                    }
                } else {
                    // Body
                    if (line.starts_with(">From ")) {
                        rawBody += line.substr(1) + "\n";
                    } else {
                        rawBody += line + "\n";
                    }
                    if (rawBody.size() > m_config.maxMessageSize) {
                        rawBody.resize(m_config.maxMessageSize);
                    }
                }
            }

            // Finalize MIME body
            commitHeader();
            if (IsMultipartContentType(topContentType)) {
                auto boundary = ExtractMimeParam(topContentType, "boundary");
                if (!boundary.empty()) {
                    auto mimeParts = ParseMultipartBody(rawBody, boundary);
                    message.attachmentCount = 0;
                    ExtractMimeContent(mimeParts, message.bodyText, message.bodyHtml,
                                       message.attachmentCount, bodyLimit);
                } else {
                    message.bodyText = rawBody.substr(0, bodyLimit);
                }
            } else {
                std::string decoded = DecodeTransferEncoding(rawBody, topTransferEncoding);
                std::string lowerCT(topContentType);
                for (auto& c : lowerCT)
                    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

                if (lowerCT.starts_with("text/html")) {
                    message.bodyHtml = decoded.substr(0, bodyLimit);
                } else {
                    message.bodyText = decoded.substr(0, bodyLimit);
                }
            }

            message.messageSize = bytesRead;
            return message;

        } catch (const std::exception& e) {
            Logger::Error("ThunderbirdScanner: Message parse exception at offset {}: {}",
                          offset, e.what());
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
        auto scanStart = std::chrono::steady_clock::now();

        try {
            result.messageId = message.messageId;
            result.scanTimestamp = std::chrono::system_clock::now();

            // Check trusted senders first for early-out
            for (const auto& trustedSender : m_config.trustedSenders) {
                if (message.from.find(trustedSender) != std::string::npos) {
                    result.isClean = true;
                    result.recommendedAction = ScanAction::Allow;
                    result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::steady_clock::now() - scanStart);
                    return result;
                }
            }

            // Phishing detection via PhishingEmailDetector
            if (m_config.detectPhishing) {
                try {
                    auto& phishingDetector = PhishingEmailDetector::Instance();
                    if (phishingDetector.IsInitialized()) {
                        // Extract URLs from body for analysis
                        auto phishingResult = phishingDetector.AnalyzeEmail(
                            message.subject,
                            message.bodyText,
                            message.bodyHtml,
                            message.from,
                            /*replyTo=*/"",  // Would come from Reply-To header
                            message.headers);

                        if (phishingResult.isPhishing) {
                            result.isPhishing = true;
                            result.phishingConfidence = phishingResult.confidenceScore;
                            result.isClean = false;
                            result.riskScore = std::max(result.riskScore, phishingResult.riskScore);
                            result.primaryThreatName = "Phishing: " + phishingResult.analysisSummary;
                            result.recommendedAction = ScanAction::Block;

                            m_stats.phishingBlocked.fetch_add(1, std::memory_order_relaxed);
                            m_stats.threatsDetected.fetch_add(1, std::memory_order_relaxed);
                        }

                        // Collect malicious URLs from phishing analysis
                        for (const auto& urlResult : phishingResult.urlAnalyses) {
                            if (urlResult.verdict == URLVerdict::Malicious ||
                                urlResult.verdict == URLVerdict::Phishing) {
                                result.maliciousUrls.push_back(urlResult.originalUrl);
                            }
                        }
                    }
                } catch (const std::exception& e) {
                    Logger::Warn("ThunderbirdScanner: Phishing detection failed for message {}: {}",
                                 message.messageId, e.what());
                }
            }

            // Spam detection via SpamDetector
            if (m_config.detectSpam && !result.isPhishing) {
                try {
                    auto& spamDetector = SpamDetector::Instance();
                    if (spamDetector.IsInitialized()) {
                        auto spamResult = spamDetector.AnalyzeEmail(
                            message.subject,
                            message.bodyText,
                            message.bodyHtml,
                            message.from,
                            message.to,
                            message.headers);

                        if (spamResult.isSpam) {
                            result.isSpam = true;
                            result.spamScore = spamResult.spamScore;
                            result.isClean = false;
                            result.riskScore = std::max(result.riskScore, spamResult.spamScore);
                            if (result.primaryThreatName.empty()) {
                                result.primaryThreatName = "Spam detected (score=" +
                                    std::to_string(spamResult.spamScore) + ")";
                            }
                            result.recommendedAction = ScanAction::TagSubject;

                            m_stats.spamMarked.fetch_add(1, std::memory_order_relaxed);
                        }
                    }
                } catch (const std::exception& e) {
                    Logger::Warn("ThunderbirdScanner: Spam detection failed for message {}: {}",
                                 message.messageId, e.what());
                }
            }

            // Attachment scanning - check if message has attachment metadata
            if (m_config.scanAttachments && message.attachmentCount > 0) {
                try {
                    auto& attachmentScanner = AttachmentScanner::Instance();
                    if (attachmentScanner.IsInitialized()) {
                        // Check for high-risk attachment types from Content-Type headers
                        for (const auto& [hdrKey, hdrVal] : message.headers) {
                            if (IEquals(hdrKey, "Content-Disposition") &&
                                IsAttachmentDisposition(hdrVal)) {
                                auto filename = ExtractAttachmentFilename(hdrVal);
                                if (!filename.empty()) {
                                    fs::path attachPath(filename);
                                    if (attachmentScanner.IsHighRiskExtension(
                                            attachPath.extension().string())) {
                                        result.hasMalware = true;
                                        result.isClean = false;
                                        result.maliciousAttachments.push_back(filename);
                                        result.primaryThreatName = "High-risk attachment: " + filename;
                                        result.recommendedAction = ScanAction::Block;
                                        m_stats.malwareBlocked.fetch_add(1, std::memory_order_relaxed);
                                        m_stats.threatsDetected.fetch_add(1, std::memory_order_relaxed);
                                    }
                                }
                            }
                        }
                    }
                } catch (const std::exception& e) {
                    Logger::Warn("ThunderbirdScanner: Attachment scan failed for message {}: {}",
                                 message.messageId, e.what());
                }
            }

            // If nothing was detected, mark as clean
            if (result.isClean && !result.isPhishing && !result.isSpam && !result.hasMalware) {
                result.recommendedAction = ScanAction::Allow;
            }

        } catch (const std::exception& e) {
            Logger::Error("ThunderbirdScanner: Message scan exception for {}: {}",
                          message.messageId, e.what());
        }

        result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - scanStart);
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

                // Track initial size and scanned offset
                m_lastKnownSizes[folder.path.wstring()] = folder.fileSize;
                m_lastScannedOffsets[folder.path.wstring()] = folder.fileSize;
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
        m_lastScannedOffsets.clear();

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
                    auto folderKey = folder.path.wstring();
                    size_t lastSize = m_lastKnownSizes[folderKey];

                    if (currentSize > lastSize) {
                        // File grew - new messages likely
                        Logger::Info("ThunderbirdScanner: Detected {} bytes of new data in {}",
                                     currentSize - lastSize, folder.path.string());

                        m_stats.fileChangesDetected.fetch_add(1, std::memory_order_relaxed);
                        m_lastKnownSizes[folderKey] = currentSize;

                        // Incremental scanning: seek to the last scanned offset
                        // and parse only new messages from that point forward
                        if (m_config.scanNewMessages) {
                            size_t scanOffset = m_lastScannedOffsets[folderKey];

                            try {
                                std::ifstream mboxFile(folder.path, std::ios::binary);
                                if (!mboxFile) continue;

                                mboxFile.seekg(static_cast<std::streamoff>(scanOffset));
                                if (!mboxFile.good()) continue;

                                // Scan forward from the last known offset to find new messages
                                std::string scanLine;
                                size_t localOffset = scanOffset;
                                size_t newMsgCount = 0;

                                // Find the next From_ separator at or after scanOffset
                                while (std::getline(mboxFile, scanLine)) {
                                    if (!scanLine.empty() && scanLine.back() == '\r')
                                        scanLine.pop_back();
                                    size_t lineLen = scanLine.size() + 1;

                                    if (IsMboxSeparator(scanLine) && localOffset >= scanOffset) {
                                        // Parse the message starting at this offset
                                        auto msg = ParseMboxMessageImpl(folder.path, localOffset);
                                        if (msg.has_value()) {
                                            auto scanResult = ScanMessageImpl(msg.value());
                                            InvokeScanCallback(msg.value(), scanResult);
                                            ++newMsgCount;

                                            m_stats.totalScanned.fetch_add(1, std::memory_order_relaxed);
                                        }
                                    }
                                    localOffset += lineLen;
                                }

                                // Update the scanned offset to current end of file
                                m_lastScannedOffsets[folderKey] = currentSize;
                                m_stats.newMessagesScanned.fetch_add(newMsgCount, std::memory_order_relaxed);

                                if (newMsgCount > 0) {
                                    Logger::Info("ThunderbirdScanner: Scanned {} new messages from {}",
                                                 newMsgCount, folder.path.string());
                                }

                            } catch (const std::exception& e) {
                                Logger::Error("ThunderbirdScanner: Incremental scan exception for {}: {}",
                                              folder.path.string(), e.what());
                                m_stats.scanErrors.fetch_add(1, std::memory_order_relaxed);
                            }
                        }
                    } else if (currentSize < lastSize) {
                        // File shrank - possibly compacted; reset offset tracking
                        Logger::Info("ThunderbirdScanner: File shrank (compaction?) in {}",
                                     folder.path.string());
                        m_lastKnownSizes[folderKey] = currentSize;
                        m_lastScannedOffsets[folderKey] = 0;
                    }
                }

            } catch (const std::exception& e) {
                Logger::Error("ThunderbirdScanner: Monitor worker exception: {}", e.what());
            }

            // Release lock before sleeping
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
                if (!ReadExactFromStdIn(&messageLength, sizeof(messageLength))) {
                    if (!std::cin.eof()) {
                        Logger::Warn("ThunderbirdScanner: Native messaging stream terminated mid-frame");
                    }
                    break;
                }

                if (messageLength == 0 || messageLength > kMaxNativeMessageSize) {
                    Logger::Warn("ThunderbirdScanner: Rejected native message with invalid length {}", messageLength);
                    break;
                }

                std::string jsonMessage(messageLength, '\0');
                if (!ReadExactFromStdIn(jsonMessage.data(), static_cast<std::streamsize>(messageLength))) {
                    Logger::Warn("ThunderbirdScanner: Truncated native message payload (expected {} bytes)",
                                 messageLength);
                    break;
                }

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

#ifdef _WIN32
            // Write registry key:
            // HKCU\Software\Mozilla\NativeMessagingHosts\com.shadowstrike.thunderbird
            // Default value = path to the native messaging manifest JSON file

            // Build the manifest path: alongside our executable
            wchar_t exePath[MAX_PATH] = {};
            if (GetModuleFileNameW(nullptr, exePath, MAX_PATH) == 0) {
                Logger::Error("ThunderbirdScanner: GetModuleFileName failed (error={})",
                              GetLastError());
                return false;
            }

            fs::path exeDir = fs::path(exePath).parent_path();
            fs::path manifestPath = exeDir / "com.shadowstrike.thunderbird.json";

            // Create the manifest JSON file
            nlohmann::json manifest;
            manifest["name"] = ThunderbirdConstants::NATIVE_HOST_NAME;
            manifest["description"] = "ShadowStrike Email Security for Thunderbird";
            manifest["path"] = fs::path(exePath).string();
            manifest["type"] = "stdio";
            manifest["allowed_extensions"] = nlohmann::json::array({
                ThunderbirdConstants::EXTENSION_ID
            });

            {
                std::ofstream manifestFile(manifestPath);
                if (!manifestFile) {
                    Logger::Error("ThunderbirdScanner: Failed to create manifest file at: {}",
                                  manifestPath.string());
                    return false;
                }
                manifestFile << manifest.dump(2);
                if (!manifestFile.good()) {
                    Logger::Error("ThunderbirdScanner: Failed to write manifest file");
                    return false;
                }
            }

            if (!IsValidNativeHostName(ThunderbirdConstants::NATIVE_HOST_NAME)) {
                Logger::Error("ThunderbirdScanner: Invalid native host name '{}'", ThunderbirdConstants::NATIVE_HOST_NAME);
                return false;
            }

            // Write registry key pointing to the manifest
            std::wstring regKeyPath =
                L"Software\\Mozilla\\NativeMessagingHosts\\" +
                StringUtils::ToWide(ThunderbirdConstants::NATIVE_HOST_NAME);

            HKEY hKey = nullptr;
            LONG result = RegCreateKeyExW(
                HKEY_CURRENT_USER,
                regKeyPath.c_str(),
                0,
                nullptr,
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                nullptr,
                &hKey,
                nullptr);

            if (result != ERROR_SUCCESS) {
                Logger::Error("ThunderbirdScanner: RegCreateKeyEx failed (error={})", result);
                return false;
            }

            // RAII guard for the registry key
            auto keyGuard = std::unique_ptr<std::remove_pointer_t<HKEY>, decltype(&RegCloseKey)>(
                hKey, RegCloseKey);

            std::wstring manifestPathW = manifestPath.wstring();
            result = RegSetValueExW(
                hKey,
                nullptr,  // Default value
                0,
                REG_SZ,
                reinterpret_cast<const BYTE*>(manifestPathW.c_str()),
                static_cast<DWORD>((manifestPathW.size() + 1) * sizeof(wchar_t)));

            if (result != ERROR_SUCCESS) {
                Logger::Error("ThunderbirdScanner: RegSetValueEx failed (error={})", result);
                return false;
            }

            Logger::Info("ThunderbirdScanner: Native host registered at: {}", manifestPath.string());
            return true;
#else
            Logger::Warn("ThunderbirdScanner: Registry registration not supported on this platform");
            return false;
#endif

        } catch (const std::exception& e) {
            Logger::Error("ThunderbirdScanner: Native host registration exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool UnregisterNativeHostImpl() {
        try {
            Logger::Info("ThunderbirdScanner: Unregistering native messaging host");

#ifdef _WIN32
            // Delete registry key
            std::wstring regKeyPath =
                L"Software\\Mozilla\\NativeMessagingHosts\\" +
                StringUtils::ToWide(ThunderbirdConstants::NATIVE_HOST_NAME);

            LONG result = RegDeleteKeyW(HKEY_CURRENT_USER, regKeyPath.c_str());
            if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND) {
                Logger::Error("ThunderbirdScanner: RegDeleteKey failed (error={})", result);
                return false;
            }

            // Also remove the manifest file
            wchar_t exePath[MAX_PATH] = {};
            if (GetModuleFileNameW(nullptr, exePath, MAX_PATH) != 0) {
                fs::path manifestPath = fs::path(exePath).parent_path() /
                    "com.shadowstrike.thunderbird.json";
                std::error_code ec;
                fs::remove(manifestPath, ec);
                if (ec) {
                    Logger::Warn("ThunderbirdScanner: Failed to remove manifest file: {}",
                                 ec.message());
                }
            }

            Logger::Info("ThunderbirdScanner: Native host unregistered");
            return true;
#else
            Logger::Warn("ThunderbirdScanner: Registry unregistration not supported on this platform");
            return false;
#endif

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
            std::string ext = ToLowerCopy(path.extension().string());
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
        Logger::Error("ThunderbirdScanner: Implementation is null");
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
            m_impl->m_lastScannedOffsets[folderPath.wstring()] = folder.fileSize;
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
            m_impl->m_lastScannedOffsets.erase(folderPath.wstring());
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
#ifdef _WIN32
        // Check standard installation paths for thunderbird.exe
        static constexpr std::wstring_view kSearchPaths[] = {
            L"C:\\Program Files\\Mozilla Thunderbird",
            L"C:\\Program Files (x86)\\Mozilla Thunderbird",
        };

        for (auto searchPath : kSearchPaths) {
            fs::path tbDir(searchPath);
            fs::path tbExe = tbDir / "thunderbird.exe";

            if (!fs::exists(tbExe)) continue;

            ThunderbirdVersionInfo info;
            info.installPath = tbDir;

            // Try to read version from application.ini
            fs::path appIni = tbDir / "application.ini";
            if (fs::exists(appIni)) {
                std::ifstream iniFile(appIni);
                std::string line;
                std::string versionStr;
                while (std::getline(iniFile, line)) {
                    if (line.starts_with("Version=")) {
                        versionStr = line.substr(8);
                        while (!versionStr.empty() &&
                               std::isspace(static_cast<unsigned char>(versionStr.back()))) {
                            versionStr.pop_back();
                        }
                    }
                }

                // Parse major.minor.patch from version string
                if (!versionStr.empty()) {
                    info.versionString = versionStr;

                    // Check for ESR suffix
                    if (versionStr.find("esr") != std::string::npos) {
                        info.isESR = true;
                    }
                    if (versionStr.find("beta") != std::string::npos ||
                        versionStr.find("b") != std::string::npos) {
                        info.isBeta = true;
                    }

                    // Parse numeric version components
                    auto dotPos1 = versionStr.find('.');
                    if (dotPos1 != std::string::npos) {
                        try {
                            info.majorVersion = static_cast<uint32_t>(
                                std::stoul(versionStr.substr(0, dotPos1)));
                        } catch (...) {}

                        auto dotPos2 = versionStr.find('.', dotPos1 + 1);
                        if (dotPos2 != std::string::npos) {
                            try {
                                info.minorVersion = static_cast<uint32_t>(
                                    std::stoul(versionStr.substr(dotPos1 + 1, dotPos2 - dotPos1 - 1)));
                                // Patch may have non-numeric suffixes (e.g. "1esr")
                                std::string patchStr = versionStr.substr(dotPos2 + 1);
                                size_t patchEnd = 0;
                                while (patchEnd < patchStr.size() &&
                                       std::isdigit(static_cast<unsigned char>(patchStr[patchEnd]))) {
                                    ++patchEnd;
                                }
                                if (patchEnd > 0) {
                                    info.patchVersion = static_cast<uint32_t>(
                                        std::stoul(patchStr.substr(0, patchEnd)));
                                }
                            } catch (...) {}
                        } else {
                            try {
                                // Only major.minor, no patch
                                std::string minorStr = versionStr.substr(dotPos1 + 1);
                                size_t end = 0;
                                while (end < minorStr.size() &&
                                       std::isdigit(static_cast<unsigned char>(minorStr[end]))) ++end;
                                if (end > 0) {
                                    info.minorVersion = static_cast<uint32_t>(
                                        std::stoul(minorStr.substr(0, end)));
                                }
                            } catch (...) {}
                        }
                    }
                }
            }

            // Fallback: query registry for installed version
            if (info.versionString.empty()) {
                HKEY hKey = nullptr;
                LONG result = RegOpenKeyExW(
                    HKEY_LOCAL_MACHINE,
                    L"SOFTWARE\\Mozilla\\Mozilla Thunderbird",
                    0, KEY_READ | KEY_WOW64_64KEY, &hKey);
                if (result == ERROR_SUCCESS) {
                    auto keyGuard = std::unique_ptr<
                        std::remove_pointer_t<HKEY>, decltype(&RegCloseKey)>(hKey, RegCloseKey);
                    wchar_t versionBuf[256] = {};
                    DWORD bufSize = sizeof(versionBuf);
                    result = RegQueryValueExW(hKey, L"CurrentVersion", nullptr, nullptr,
                                              reinterpret_cast<LPBYTE>(versionBuf), &bufSize);
                    if (result == ERROR_SUCCESS) {
                        info.versionString = StringUtils::ToNarrow(versionBuf);
                    }
                }
            }

            installations.push_back(std::move(info));
        }

        Logger::Debug("ThunderbirdScanner: Discovered {} Thunderbird installations",
                       installations.size());
#endif

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

void ThunderbirdScanner::RegisterScanCallback(ThunderbirdScanResultCallback callback) {
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

[[nodiscard]] ThunderbirdScannerStatisticsSnapshot ThunderbirdScanner::GetStatistics() const {
    if (!m_impl) {
        return ThunderbirdScannerStatisticsSnapshot{};
    }

    return m_impl->m_stats.ToSnapshot();
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
    // Route through the singleton's public DiscoverProfiles which internally
    // calls ParseProfilesIniImpl. For standalone parsing without full scanner
    // init, use a lightweight local parser.
    try {
        if (!fs::exists(iniPath)) {
            return {};
        }

        // Cap file size to prevent DoS
        auto fileSize = fs::file_size(iniPath);
        if (fileSize > 1 * 1024 * 1024) { // 1MB cap for profiles.ini
            Logger::Warn("ParseProfilesIni: File exceeds size limit ({} bytes): {}",
                         fileSize, iniPath.string());
            return {};
        }

        std::vector<ThunderbirdProfile> profiles;
        std::ifstream iniFile(iniPath);
        if (!iniFile) {
            return profiles;
        }

        fs::path basePath = iniPath.parent_path();
        ThunderbirdProfile currentProfile;
        std::string currentSection;
        bool currentIsRelative = true; // Default: paths are relative
        std::string currentRawPath;
        std::string line;

        auto commitProfile = [&]() {
            if (!currentSection.starts_with("Profile") || currentProfile.name.empty()) {
                return;
            }

            // Resolve path based on IsRelative flag
            if (!currentRawPath.empty()) {
                if (currentIsRelative) {
                    currentProfile.path = basePath / currentRawPath;
                } else {
                    currentProfile.path = fs::path(currentRawPath);
                }

                // Canonicalize and validate against directory traversal
                try {
                    currentProfile.path = fs::weakly_canonical(currentProfile.path);
                } catch (...) {
                    Logger::Warn("ParseProfilesIni: Failed to canonicalize path for profile: {}",
                                 currentProfile.name);
                }

                // Verify the profile path is under the Thunderbird data directory
                // (relative paths must stay under basePath)
                if (currentIsRelative && !IsPathSafe(currentProfile.path, basePath)) {
                    Logger::Warn("ParseProfilesIni: Directory traversal detected in profile {}: {}",
                                 currentProfile.name, currentRawPath);
                    return; // Skip this profile
                }
            }

            profiles.push_back(currentProfile);
        };

        while (std::getline(iniFile, line)) {
            TrimNarrow(line);

            if (line.empty() || line[0] == ';' || line[0] == '#') {
                continue;
            }

            if (line[0] == '[' && line.back() == ']') {
                // Commit previous profile section
                commitProfile();

                currentSection = line.substr(1, line.length() - 2);
                currentProfile = ThunderbirdProfile{};
                currentIsRelative = true;
                currentRawPath.clear();
                continue;
            }

            auto eqPos = line.find('=');
            if (eqPos == std::string::npos) {
                continue;
            }

            std::string key = line.substr(0, eqPos);
            std::string value = line.substr(eqPos + 1);
            TrimNarrow(key);
            TrimNarrow(value);

            if (currentSection.starts_with("Profile")) {
                if (key == "Name") {
                    currentProfile.name = value;
                } else if (key == "IsRelative") {
                    currentIsRelative = (value == "1");
                } else if (key == "Path") {
                    currentRawPath = value;
                } else if (key == "Default") {
                    currentProfile.isDefault = (value == "1");
                }
            }
        }

        // Commit final section
        commitProfile();

        return profiles;

    } catch (const std::exception& e) {
        Logger::Error("ParseProfilesIni: Exception - {}", e.what());
        return {};
    }
}

[[nodiscard]] MailboxFormat DetectMailboxFormat(const fs::path& path) {
    try {
        if (!fs::exists(path) || !fs::is_regular_file(path)) {
            return MailboxFormat::Unknown;
        }

        std::string ext = ToLowerCopy(path.extension().string());
        if (ext == ".msf") {
            return MailboxFormat::Unknown;
        }

        std::ifstream file(path);
        std::string firstLine;
        if (!std::getline(file, firstLine)) {
            return MailboxFormat::Unknown;
        }

        if (firstLine.starts_with("From ")) {
            return MailboxFormat::Mbox;
        }

        auto parentDir = path.parent_path().filename().string();
        if (parentDir == "cur" || parentDir == "new" || parentDir == "tmp") {
            return MailboxFormat::Maildir;
        }

        return MailboxFormat::Unknown;

    } catch (...) {
        return MailboxFormat::Unknown;
    }
}

} // namespace Email
} // namespace ShadowStrike
