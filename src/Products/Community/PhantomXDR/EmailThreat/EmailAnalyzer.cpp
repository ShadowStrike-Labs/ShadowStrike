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
#include "EmailAnalyzer.hpp"

#include <format>
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "PhantomCore/Utils/HashUtils.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <limits>
#include <optional>
#include <regex>
#include <set>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::EmailThreat {

namespace SU = ShadowStrike::Utils::StringUtils;
using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Database::QueryResult;
using ShadowStrike::Utils::HashUtils::Algorithm;
using ShadowStrike::Utils::HashUtils::Error;
using ShadowStrike::Utils::HashUtils::Hasher;
using ShadowStrike::Utils::Logger;
namespace fs = std::filesystem;

namespace {

constexpr std::string_view kSchemaSql = R"(
    CREATE TABLE IF NOT EXISTS xdr_email_scan_results (
        message_id          TEXT PRIMARY KEY,
        file_path           TEXT NOT NULL,
        file_sha256         TEXT NOT NULL,
        header_from         TEXT,
        header_to           TEXT,
        header_cc           TEXT,
        header_subject      TEXT,
        header_date         TEXT,
        in_reply_to         TEXT,
        received_chain      TEXT,
        return_path         TEXT,
        spf_result          TEXT,
        dkim_result         TEXT,
        dmarc_result        TEXT,
        verdict             INTEGER NOT NULL,
        indicators          INTEGER NOT NULL,
        confidence          REAL NOT NULL,
        links_extracted     TEXT,
        suspicious_links    TEXT,
        header_anomalies    TEXT,
        mitre_technique     TEXT,
        attachments_data    TEXT,
        summary             TEXT,
        analyzed_at         INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_xdr_email_scans_time ON xdr_email_scan_results(analyzed_at DESC);
    CREATE INDEX IF NOT EXISTS idx_xdr_email_scans_sender ON xdr_email_scan_results(header_from);
    CREATE INDEX IF NOT EXISTS idx_xdr_email_scans_verdict ON xdr_email_scan_results(verdict);
)";

constexpr std::size_t kMaxEmailFileSize = 64ULL * 1024ULL * 1024ULL;
constexpr std::size_t kMaxMimePartDepth = 12;
constexpr std::size_t kMaxMimePartCount = 256;
constexpr std::size_t kMaxAttachmentCount = 128;
constexpr std::size_t kMaxLinkCount = 512;
constexpr std::size_t kMaxCacheEntries = 512;
constexpr std::size_t kHashReadChunkSize = 1ULL * 1024ULL * 1024ULL;
constexpr std::size_t kMaxStorageFieldLength = 64ULL * 1024ULL;
constexpr int64_t kSleepSliceMs = 500;

constexpr uint32_t kEndOfChain = 0xFFFFFFFEu;
constexpr uint32_t kFreeSector = 0xFFFFFFFFu;
constexpr uint32_t kNoStream = 0xFFFFFFFFu;

struct HeaderCollection {
    std::unordered_map<std::string, std::string> values;
    std::vector<std::string> received;
};

struct ParsedEmail {
    EmailHeader header;
    std::string plainBody;
    std::string htmlBody;
    std::vector<EmailAttachment> attachments;
};

struct MimeSection {
    HeaderCollection headers;
    std::string body;
};

[[nodiscard]] std::string ToLowerAscii(std::string_view value) {
    std::string lowered;
    lowered.reserve(value.size());
    for (const unsigned char ch : value) {
        lowered.push_back(static_cast<char>(std::tolower(ch)));
    }
    return lowered;
}

[[nodiscard]] std::string TrimAscii(std::string_view value) {
    std::size_t start = 0;
    std::size_t end = value.size();
    while (start < end && std::isspace(static_cast<unsigned char>(value[start])) != 0) {
        ++start;
    }
    while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1])) != 0) {
        --end;
    }
    return std::string(value.substr(start, end - start));
}

[[nodiscard]] bool IContains(std::string_view haystack, std::string_view needle) {
    if (needle.empty()) {
        return true;
    }
    const std::string haystackLower = ToLowerAscii(haystack);
    const std::string needleLower = ToLowerAscii(needle);
    return haystackLower.find(needleLower) != std::string::npos;
}

[[nodiscard]] std::string LimitForStorage(std::string value) {
    if (value.size() > kMaxStorageFieldLength) {
        value.resize(kMaxStorageFieldLength);
    }
    return value;
}

[[nodiscard]] int64_t ToUnixSeconds(const std::chrono::system_clock::time_point timePoint) {
    return std::chrono::duration_cast<std::chrono::seconds>(timePoint.time_since_epoch()).count();
}

[[nodiscard]] std::chrono::system_clock::time_point FromUnixSeconds(const int64_t seconds) {
    return std::chrono::system_clock::time_point{std::chrono::seconds(seconds)};
}

[[nodiscard]] uint16_t ReadUInt16LE(const std::vector<uint8_t>& buffer, const std::size_t offset) {
    if (offset + sizeof(uint16_t) > buffer.size()) {
        return 0;
    }
    return static_cast<uint16_t>(buffer[offset]) |
           static_cast<uint16_t>(buffer[offset + 1] << 8);
}

[[nodiscard]] uint32_t ReadUInt32LE(const std::vector<uint8_t>& buffer, const std::size_t offset) {
    if (offset + sizeof(uint32_t) > buffer.size()) {
        return 0;
    }
    return static_cast<uint32_t>(buffer[offset]) |
           (static_cast<uint32_t>(buffer[offset + 1]) << 8) |
           (static_cast<uint32_t>(buffer[offset + 2]) << 16) |
           (static_cast<uint32_t>(buffer[offset + 3]) << 24);
}

[[nodiscard]] uint64_t ReadUInt64LE(const std::vector<uint8_t>& buffer, const std::size_t offset) {
    if (offset + sizeof(uint64_t) > buffer.size()) {
        return 0;
    }

    uint64_t value = 0;
    for (std::size_t index = 0; index < sizeof(uint64_t); ++index) {
        value |= static_cast<uint64_t>(buffer[offset + index]) << (index * 8);
    }
    return value;
}

[[nodiscard]] std::string EscapeStorageString(std::string_view input) {
    std::string escaped;
    escaped.reserve(input.size() + 8);
    for (const char ch : input) {
        switch (ch) {
        case '\\': escaped += "\\\\"; break;
        case '\n': escaped += "\\n"; break;
        case '\r': escaped += "\\r"; break;
        case '\t': escaped += "\\t"; break;
        case '|': escaped += "\\p"; break;
        default: escaped.push_back(ch); break;
        }
    }
    return escaped;
}

[[nodiscard]] std::string UnescapeStorageString(std::string_view input) {
    std::string value;
    value.reserve(input.size());
    for (std::size_t index = 0; index < input.size(); ++index) {
        if (input[index] == '\\' && index + 1 < input.size()) {
            ++index;
            switch (input[index]) {
            case 'n': value.push_back('\n'); break;
            case 'r': value.push_back('\r'); break;
            case 't': value.push_back('\t'); break;
            case 'p': value.push_back('|'); break;
            case '\\': value.push_back('\\'); break;
            default:
                value.push_back(input[index]);
                break;
            }
            continue;
        }
        value.push_back(input[index]);
    }
    return value;
}

[[nodiscard]] std::string SerializeStringList(const std::vector<std::string>& values) {
    std::ostringstream stream;
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index != 0) {
            stream << '\n';
        }
        stream << EscapeStorageString(values[index]);
    }
    return stream.str();
}

[[nodiscard]] std::vector<std::string> DeserializeStringList(std::string_view serialized) {
    std::vector<std::string> values;
    std::string current;
    for (std::size_t index = 0; index < serialized.size(); ++index) {
        if (serialized[index] == '\n') {
            values.push_back(UnescapeStorageString(current));
            current.clear();
            continue;
        }
        current.push_back(serialized[index]);
    }
    if (!current.empty() || !serialized.empty()) {
        values.push_back(UnescapeStorageString(current));
    }
    return values;
}

[[nodiscard]] std::string SerializeAttachments(const std::vector<EmailAttachment>& attachments) {
    std::vector<std::string> rows;
    rows.reserve(attachments.size());
    for (const auto& attachment : attachments) {
        rows.push_back(std::format("{}|{}|{}|{}|{}|{}|{}|{}",
            EscapeStorageString(attachment.filename),
            EscapeStorageString(attachment.contentType),
            attachment.size,
            EscapeStorageString(attachment.sha256),
            attachment.isExecutable ? 1 : 0,
            attachment.hasMacro ? 1 : 0,
            attachment.isPasswordProtected ? 1 : 0,
            attachment.isDoubleExtension ? 1 : 0));
    }
    return SerializeStringList(rows);
}

[[nodiscard]] std::vector<EmailAttachment> DeserializeAttachments(std::string_view serialized) {
    std::vector<EmailAttachment> attachments;
    for (const auto& row : DeserializeStringList(serialized)) {
        std::vector<std::string> parts;
        std::string current;
        bool escaped = false;
        for (const char ch : row) {
            if (escaped) {
                current.push_back('\\');
                current.push_back(ch);
                escaped = false;
                continue;
            }
            if (ch == '\\') {
                escaped = true;
                continue;
            }
            if (ch == '|') {
                parts.push_back(UnescapeStorageString(current));
                current.clear();
                continue;
            }
            current.push_back(ch);
        }
        parts.push_back(UnescapeStorageString(current));
        if (parts.size() != 8) {
            continue;
        }

        EmailAttachment attachment;
        attachment.filename = parts[0];
        attachment.contentType = parts[1];
        attachment.size = static_cast<uint64_t>(std::strtoull(parts[2].c_str(), nullptr, 10));
        attachment.sha256 = parts[3];
        attachment.isExecutable = parts[4] == "1";
        attachment.hasMacro = parts[5] == "1";
        attachment.isPasswordProtected = parts[6] == "1";
        attachment.isDoubleExtension = parts[7] == "1";
        attachments.push_back(std::move(attachment));
    }
    return attachments;
}

[[nodiscard]] bool DecodeHexNibble(const char ch, uint8_t& value) {
    if (ch >= '0' && ch <= '9') {
        value = static_cast<uint8_t>(ch - '0');
        return true;
    }
    if (ch >= 'a' && ch <= 'f') {
        value = static_cast<uint8_t>(10 + ch - 'a');
        return true;
    }
    if (ch >= 'A' && ch <= 'F') {
        value = static_cast<uint8_t>(10 + ch - 'A');
        return true;
    }
    return false;
}

[[nodiscard]] std::string QuotedPrintableDecode(std::string_view input) {
    std::string decoded;
    decoded.reserve(input.size());
    for (std::size_t index = 0; index < input.size(); ++index) {
        if (input[index] == '=' && index + 2 < input.size()) {
            if (input[index + 1] == '\r' && input[index + 2] == '\n') {
                index += 2;
                continue;
            }
            uint8_t hi = 0;
            uint8_t lo = 0;
            if (DecodeHexNibble(input[index + 1], hi) && DecodeHexNibble(input[index + 2], lo)) {
                decoded.push_back(static_cast<char>((hi << 4) | lo));
                index += 2;
                continue;
            }
        }
        decoded.push_back(input[index] == '_' ? ' ' : input[index]);
    }
    return decoded;
}

[[nodiscard]] int Base64Value(const char ch) {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return 26 + ch - 'a';
    if (ch >= '0' && ch <= '9') return 52 + ch - '0';
    if (ch == '+') return 62;
    if (ch == '/') return 63;
    return -1;
}

[[nodiscard]] std::vector<uint8_t> Base64Decode(std::string_view input) {
    std::vector<uint8_t> output;
    output.reserve((input.size() * 3) / 4);

    int buffer = 0;
    int bitsCollected = 0;
    for (const char ch : input) {
        if (std::isspace(static_cast<unsigned char>(ch)) != 0) {
            continue;
        }
        if (ch == '=') {
            break;
        }
        const int value = Base64Value(ch);
        if (value < 0) {
            continue;
        }
        buffer = (buffer << 6) | value;
        bitsCollected += 6;
        if (bitsCollected >= 8) {
            bitsCollected -= 8;
            output.push_back(static_cast<uint8_t>((buffer >> bitsCollected) & 0xFF));
        }
    }
    return output;
}

[[nodiscard]] std::string DecodeRfc2047Words(const std::string& input) {
    std::string result;
    result.reserve(input.size());

    std::size_t cursor = 0;
    while (cursor < input.size()) {
        const std::size_t start = input.find("=?", cursor);
        if (start == std::string::npos) {
            result.append(input.substr(cursor));
            break;
        }
        result.append(input.substr(cursor, start - cursor));

        const std::size_t charsetEnd = input.find('?', start + 2);
        const std::size_t encodingEnd = charsetEnd == std::string::npos ? std::string::npos : input.find('?', charsetEnd + 1);
        const std::size_t textEnd = encodingEnd == std::string::npos ? std::string::npos : input.find("?=", encodingEnd + 1);
        if (charsetEnd == std::string::npos || encodingEnd == std::string::npos || textEnd == std::string::npos) {
            result.append(input.substr(start, 2));
            cursor = start + 2;
            continue;
        }

        const std::string encodedText = input.substr(encodingEnd + 1, textEnd - encodingEnd - 1);
        const char encoding = input[charsetEnd + 1];
        if (encoding == 'B' || encoding == 'b') {
            const auto decoded = Base64Decode(encodedText);
            result.append(reinterpret_cast<const char*>(decoded.data()), decoded.size());
        } else if (encoding == 'Q' || encoding == 'q') {
            result.append(QuotedPrintableDecode(encodedText));
        } else {
            result.append(input.substr(start, textEnd + 2 - start));
        }
        cursor = textEnd + 2;
    }

    return result;
}

[[nodiscard]] std::string UnfoldHeaders(std::string_view rawHeaders) {
    std::string unfolded;
    unfolded.reserve(rawHeaders.size());
    for (std::size_t index = 0; index < rawHeaders.size(); ++index) {
        if (rawHeaders[index] == '\r' && index + 2 < rawHeaders.size() &&
            rawHeaders[index + 1] == '\n' &&
            (rawHeaders[index + 2] == ' ' || rawHeaders[index + 2] == '\t')) {
            unfolded.push_back(' ');
            index += 2;
            while (index + 1 < rawHeaders.size() &&
                   (rawHeaders[index + 1] == ' ' || rawHeaders[index + 1] == '\t')) {
                ++index;
            }
            continue;
        }
        if (rawHeaders[index] == '\n' && index + 1 < rawHeaders.size() &&
            (rawHeaders[index + 1] == ' ' || rawHeaders[index + 1] == '\t')) {
            unfolded.push_back(' ');
            ++index;
            while (index + 1 < rawHeaders.size() &&
                   (rawHeaders[index + 1] == ' ' || rawHeaders[index + 1] == '\t')) {
                ++index;
            }
            continue;
        }
        unfolded.push_back(rawHeaders[index]);
    }
    return unfolded;
}

[[nodiscard]] HeaderCollection ParseHeaders(std::string_view rawHeaders) {
    HeaderCollection headers;
    std::istringstream stream(UnfoldHeaders(rawHeaders));
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.empty()) {
            continue;
        }
        const std::size_t colon = line.find(':');
        if (colon == std::string::npos) {
            continue;
        }
        const std::string key = ToLowerAscii(TrimAscii(line.substr(0, colon)));
        const std::string value = DecodeRfc2047Words(TrimAscii(line.substr(colon + 1)));
        if (key == "received") {
            headers.received.push_back(value);
        }
        headers.values[key] = value;
    }
    return headers;
}

[[nodiscard]] std::string GetHeaderValue(const HeaderCollection& headers, std::string_view name) {
    const auto it = headers.values.find(ToLowerAscii(name));
    if (it == headers.values.end()) {
        return {};
    }
    return it->second;
}

[[nodiscard]] std::optional<MimeSection> SplitHeadersAndBody(std::string_view rawSection) {
    const std::size_t headerEnd = rawSection.find("\r\n\r\n");
    if (headerEnd != std::string::npos) {
        MimeSection section;
        section.headers = ParseHeaders(rawSection.substr(0, headerEnd));
        section.body = std::string(rawSection.substr(headerEnd + 4));
        return section;
    }

    const std::size_t altHeaderEnd = rawSection.find("\n\n");
    if (altHeaderEnd != std::string::npos) {
        MimeSection section;
        section.headers = ParseHeaders(rawSection.substr(0, altHeaderEnd));
        section.body = std::string(rawSection.substr(altHeaderEnd + 2));
        return section;
    }
    return std::nullopt;
}

[[nodiscard]] std::string GetHeaderParameter(std::string_view headerValue, std::string_view parameterName) {
    const std::string lowerValue = ToLowerAscii(headerValue);
    const std::string parameter = std::format("{}=", ToLowerAscii(parameterName));
    const std::size_t position = lowerValue.find(parameter);
    if (position == std::string::npos) {
        return {};
    }

    std::size_t valueStart = position + parameter.size();
    while (valueStart < headerValue.size() && std::isspace(static_cast<unsigned char>(headerValue[valueStart])) != 0) {
        ++valueStart;
    }
    if (valueStart >= headerValue.size()) {
        return {};
    }

    if (headerValue[valueStart] == '"') {
        const std::size_t endQuote = headerValue.find('"', valueStart + 1);
        if (endQuote == std::string::npos) {
            return TrimAscii(headerValue.substr(valueStart + 1));
        }
        return std::string(headerValue.substr(valueStart + 1, endQuote - valueStart - 1));
    }

    std::size_t valueEnd = valueStart;
    while (valueEnd < headerValue.size() && headerValue[valueEnd] != ';' && headerValue[valueEnd] != '\r' && headerValue[valueEnd] != '\n') {
        ++valueEnd;
    }
    return TrimAscii(headerValue.substr(valueStart, valueEnd - valueStart));
}

[[nodiscard]] std::string DecodeTransferEncodedBody(std::string_view body,
                                                    std::string_view transferEncoding) {
    const std::string normalized = ToLowerAscii(TrimAscii(transferEncoding));
    if (normalized == "base64") {
        const auto decoded = Base64Decode(body);
        return std::string(reinterpret_cast<const char*>(decoded.data()), decoded.size());
    }
    if (normalized == "quoted-printable") {
        return QuotedPrintableDecode(body);
    }
    return std::string(body);
}

[[nodiscard]] bool IsExecutableExtension(std::string_view fileName) {
    static constexpr std::array<std::string_view, 14> kExtensions = {
        ".exe", ".dll", ".scr", ".bat", ".cmd", ".com", ".msi",
        ".ps1", ".js", ".vbs", ".wsf", ".hta", ".cpl", ".jar"
    };
    const std::string lower = ToLowerAscii(fileName);
    for (const auto extension : kExtensions) {
        if (lower.size() >= extension.size() && lower.ends_with(extension)) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool IsArchiveExtension(std::string_view fileName) {
    static constexpr std::array<std::string_view, 6> kExtensions = {
        ".zip", ".rar", ".7z", ".ace", ".jar", ".iso"
    };
    const std::string lower = ToLowerAscii(fileName);
    for (const auto extension : kExtensions) {
        if (lower.size() >= extension.size() && lower.ends_with(extension)) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool HasMacroExtension(std::string_view fileName) {
    static constexpr std::array<std::string_view, 7> kExtensions = {
        ".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".ppam", ".vba"
    };
    const std::string lower = ToLowerAscii(fileName);
    for (const auto extension : kExtensions) {
        if (lower.size() >= extension.size() && lower.ends_with(extension)) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool HasDoubleExtension(std::string_view fileName) {
    const std::string lower = ToLowerAscii(fileName);
    const std::size_t lastDot = lower.rfind('.');
    if (lastDot == std::string::npos || lastDot == 0) {
        return false;
    }
    const std::size_t secondDot = lower.rfind('.', lastDot - 1);
    if (secondDot == std::string::npos) {
        return false;
    }

    static constexpr std::array<std::string_view, 8> kLureExtensions = {
        ".txt", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png"
    };
    for (const auto extension : kLureExtensions) {
        if (lower.substr(secondDot).starts_with(extension)) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool IsExecutableMagic(const std::vector<uint8_t>& bytes) {
    if (bytes.size() >= 2 && bytes[0] == 'M' && bytes[1] == 'Z') {
        return true;
    }
    if (bytes.size() >= 4 && bytes[0] == 0x7F && bytes[1] == 'E' && bytes[2] == 'L' && bytes[3] == 'F') {
        return true;
    }
    if (bytes.size() >= 4 && bytes[0] == 0xCA && bytes[1] == 0xFE && bytes[2] == 0xBA && bytes[3] == 0xBE) {
        return true;
    }
    return false;
}

[[nodiscard]] bool ContainsOleMacroMarkers(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) {
        return false;
    }
    const std::string body(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    return IContains(body, "vba") || IContains(body, "project") || IContains(body, "worddocument") || IContains(body, "macros");
}

[[nodiscard]] bool IsPasswordProtectedArchive(const std::vector<uint8_t>& bytes, std::string_view fileName) {
    if (bytes.size() >= 8 && bytes[0] == 'P' && bytes[1] == 'K') {
        for (std::size_t index = 0; index + 8 < bytes.size() && index < 4096; ++index) {
            if (bytes[index] == 'P' && bytes[index + 1] == 'K' && bytes[index + 2] == 0x03 && bytes[index + 3] == 0x04) {
                const uint16_t flags = static_cast<uint16_t>(bytes[index + 6]) |
                                       static_cast<uint16_t>(bytes[index + 7] << 8);
                if ((flags & 0x0001u) != 0) {
                    return true;
                }
            }
        }
    }
    return ToLowerAscii(fileName).ends_with(".aes.zip") || ToLowerAscii(fileName).ends_with(".enc.zip");
}

[[nodiscard]] std::string ComputeSha256(const std::vector<uint8_t>& bytes) {
    Error hashError{};
    Hasher hasher(Algorithm::SHA256);
    if (!hasher.Init(&hashError)) {
        Logger::Error("EmailAnalyzer: SHA-256 initialization failed win32={} ntstatus={}",
            hashError.win32,
            hashError.ntstatus);
        return {};
    }
    if (!bytes.empty() && !hasher.Update(bytes.data(), bytes.size(), &hashError)) {
        Logger::Error("EmailAnalyzer: SHA-256 update failed win32={} ntstatus={}",
            hashError.win32,
            hashError.ntstatus);
        return {};
    }
    std::string digest;
    if (!hasher.FinalHex(digest, false, &hashError)) {
        Logger::Error("EmailAnalyzer: SHA-256 finalize failed win32={} ntstatus={}",
            hashError.win32,
            hashError.ntstatus);
        return {};
    }
    return digest;
}

[[nodiscard]] std::string ComputeFileSha256(const fs::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        return {};
    }

    Error hashError{};
    Hasher hasher(Algorithm::SHA256);
    if (!hasher.Init(&hashError)) {
        Logger::Error("EmailAnalyzer: file SHA-256 initialization failed win32={} ntstatus={}",
            hashError.win32,
            hashError.ntstatus);
        return {};
    }

    std::vector<char> buffer(kHashReadChunkSize);
    while (stream) {
        stream.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize bytesRead = stream.gcount();
        if (bytesRead > 0 && !hasher.Update(buffer.data(), static_cast<std::size_t>(bytesRead), &hashError)) {
            Logger::Error("EmailAnalyzer: file SHA-256 update failed win32={} ntstatus={}",
                hashError.win32,
                hashError.ntstatus);
            return {};
        }
    }

    std::string digest;
    if (!hasher.FinalHex(digest, false, &hashError)) {
        Logger::Error("EmailAnalyzer: file SHA-256 finalize failed win32={} ntstatus={}",
            hashError.win32,
            hashError.ntstatus);
        return {};
    }
    return digest;
}

[[nodiscard]] std::vector<uint8_t> ReadFileBounded(const fs::path& path, std::size_t maxSize) {
    std::error_code errorCode;
    const auto fileSize = fs::file_size(path, errorCode);
    if (errorCode || fileSize > maxSize) {
        return {};
    }

    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        return {};
    }

    std::vector<uint8_t> bytes(static_cast<std::size_t>(fileSize));
    if (!bytes.empty()) {
        stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (stream.gcount() != static_cast<std::streamsize>(bytes.size())) {
            return {};
        }
    }
    return bytes;
}

[[nodiscard]] std::string HtmlEntityDecode(std::string text) {
    const std::array<std::pair<std::string_view, std::string_view>, 5> replacements = {{
        {"&amp;", "&"},
        {"&lt;", "<"},
        {"&gt;", ">"},
        {"&quot;", "\""},
        {"&#39;", "'"}
    }};

    for (const auto& [needle, replacement] : replacements) {
        std::size_t position = 0;
        while ((position = text.find(needle, position)) != std::string::npos) {
            text.replace(position, needle.size(), replacement);
            position += replacement.size();
        }
    }
    return text;
}

[[nodiscard]] std::string StripHtmlTags(std::string_view html) {
    std::string output;
    output.reserve(html.size());
    bool inTag = false;
    for (const char ch : html) {
        if (ch == '<') {
            inTag = true;
            continue;
        }
        if (ch == '>') {
            inTag = false;
            output.push_back(' ');
            continue;
        }
        if (!inTag) {
            output.push_back(ch);
        }
    }
    return HtmlEntityDecode(output);
}

[[nodiscard]] std::vector<std::string> ExtractUrls(std::string_view text) {
    static const std::regex kUrlRegex(R"(((?:https?|ftp)://[^\s<>\"]+|data:[^\s<>\"]+))",
        std::regex::icase | std::regex::optimize);

    std::unordered_set<std::string> unique;
    std::vector<std::string> urls;
    urls.reserve(32);

    const std::string input(text);
    for (std::sregex_iterator it(input.begin(), input.end(), kUrlRegex), end; it != end; ++it) {
        const std::string match = TrimAscii((*it).str());
        if (match.empty()) {
            continue;
        }
        if (unique.insert(match).second) {
            urls.push_back(match);
            if (urls.size() >= kMaxLinkCount) {
                break;
            }
        }
    }
    return urls;
}

[[nodiscard]] std::vector<std::pair<std::string, std::string>> ExtractAnchorPairs(const std::string& html) {
    static const std::regex kAnchorRegex(R"(<a[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>)",
        std::regex::icase | std::regex::optimize);

    std::vector<std::pair<std::string, std::string>> anchors;
    for (std::sregex_iterator it(html.begin(), html.end(), kAnchorRegex), end; it != end; ++it) {
        anchors.emplace_back((*it)[1].str(), StripHtmlTags((*it)[2].str()));
        if (anchors.size() >= 128) {
            break;
        }
    }
    return anchors;
}

[[nodiscard]] std::string ExtractHostFromUrl(std::string_view url) {
    std::string normalized = TrimAscii(url);
    if (normalized.empty()) {
        return {};
    }
    const std::string lower = ToLowerAscii(normalized);
    if (lower.starts_with("data:")) {
        return "data:";
    }

    std::size_t schemePos = normalized.find("://");
    std::size_t hostStart = schemePos == std::string::npos ? 0 : schemePos + 3;
    if (hostStart >= normalized.size()) {
        return {};
    }

    if (normalized[hostStart] == '[') {
        const std::size_t end = normalized.find(']', hostStart + 1);
        if (end == std::string::npos) {
            return {};
        }
        return ToLowerAscii(normalized.substr(hostStart + 1, end - hostStart - 1));
    }

    std::size_t hostEnd = hostStart;
    while (hostEnd < normalized.size()) {
        const char ch = normalized[hostEnd];
        if (ch == '/' || ch == ':' || ch == '?' || ch == '#') {
            break;
        }
        ++hostEnd;
    }
    return ToLowerAscii(normalized.substr(hostStart, hostEnd - hostStart));
}

[[nodiscard]] bool IsIpLiteral(std::string_view host) {
    if (host.empty()) {
        return false;
    }
    if (host.find(':') != std::string::npos) {
        return true;
    }
    int dots = 0;
    for (const char ch : host) {
        if (ch == '.') {
            ++dots;
            continue;
        }
        if (!std::isdigit(static_cast<unsigned char>(ch))) {
            return false;
        }
    }
    return dots == 3;
}

[[nodiscard]] bool LooksHomoglyphDomain(std::string_view host) {
    if (host.find("xn--") != std::string::npos) {
        return true;
    }
    for (const unsigned char ch : host) {
        if (ch >= 0x80U) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool LooksRecentlyRegisteredDomain(std::string_view host) {
    static constexpr std::array<std::string_view, 12> kSuspiciousTlds = {
        ".top", ".xyz", ".click", ".shop", ".cfd", ".monster",
        ".sbs", ".help", ".live", ".online", ".site", ".zip"
    };

    const std::string lower = ToLowerAscii(host);
    const std::size_t dot = lower.find('.');
    const std::string label = dot == std::string::npos ? lower : lower.substr(0, dot);
    const auto digitCount = static_cast<int>(std::count_if(label.begin(), label.end(), [](const char ch) {
        return std::isdigit(static_cast<unsigned char>(ch)) != 0;
    }));
    const auto hyphenCount = static_cast<int>(std::count(label.begin(), label.end(), '-'));

    bool suspiciousTld = false;
    for (const auto tld : kSuspiciousTlds) {
        if (lower.ends_with(tld)) {
            suspiciousTld = true;
            break;
        }
    }

    return suspiciousTld && (digitCount >= 3 || hyphenCount >= 2 || label.size() >= 18);
}

[[nodiscard]] bool IsUrlShortener(std::string_view host) {
    static const std::unordered_set<std::string> kShorteners = {
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "rebrand.ly", "cutt.ly",
        "is.gd", "shorturl.at", "buff.ly", "lnkd.in"
    };
    return kShorteners.contains(ToLowerAscii(host));
}

[[nodiscard]] std::pair<std::string, std::string> ExtractDisplayNameAndAddress(std::string_view fromField) {
    const std::string trimmed = TrimAscii(fromField);
    const std::size_t lt = trimmed.find('<');
    const std::size_t gt = trimmed.find('>');
    if (lt != std::string::npos && gt != std::string::npos && gt > lt) {
        return {TrimAscii(trimmed.substr(0, lt)), ToLowerAscii(TrimAscii(trimmed.substr(lt + 1, gt - lt - 1)))};
    }
    const std::size_t at = trimmed.find('@');
    if (at != std::string::npos) {
        return {{}, ToLowerAscii(trimmed)};
    }
    return {trimmed, {}};
}

[[nodiscard]] std::string ExtractDomainFromEmail(std::string_view address) {
    const std::string normalized = ToLowerAscii(TrimAscii(address));
    const std::size_t at = normalized.find('@');
    if (at == std::string::npos || at + 1 >= normalized.size()) {
        return {};
    }
    return normalized.substr(at + 1);
}

[[nodiscard]] std::string ExtractDateToken(std::string_view receivedLine) {
    const std::size_t semicolon = receivedLine.rfind(';');
    if (semicolon == std::string::npos || semicolon + 1 >= receivedLine.size()) {
        return {};
    }
    return TrimAscii(receivedLine.substr(semicolon + 1));
}

void AddIndicator(EmailAnalysisResult& result,
                  const PhishingIndicator indicator,
                  const double weight,
                  const std::string& detail,
                  std::vector<std::string>* details = nullptr) {
    if (!HasIndicator(result.indicators, indicator)) {
        result.indicators |= indicator;
        result.confidence += weight;
    }
    if (details != nullptr && !detail.empty()) {
        details->push_back(detail);
    }
}

void AppendUnique(std::vector<std::string>& values, const std::string& item) {
    if (item.empty()) {
        return;
    }
    if (std::find(values.begin(), values.end(), item) == values.end()) {
        values.push_back(item);
    }
}

void FinalizeVerdict(EmailAnalysisResult& result) {
    result.confidence = std::clamp(result.confidence, 0.0, 100.0);

    const bool hasExecAttachment = HasIndicator(result.indicators, PhishingIndicator::ExecutableAttachment);
    const bool hasMacro = HasIndicator(result.indicators, PhishingIndicator::MacroAttachment);
    const bool hasMaliciousLinkProfile = HasIndicator(result.indicators, PhishingIndicator::SuspiciousLink) &&
                                         HasIndicator(result.indicators, PhishingIndicator::MismatchedURL);

    if (result.confidence >= 90.0 || (hasExecAttachment && hasMaliciousLinkProfile) || (hasExecAttachment && hasMacro)) {
        result.verdict = EmailVerdict::Malicious;
    } else if (result.confidence >= 75.0) {
        result.verdict = HasIndicator(result.indicators, PhishingIndicator::SuspiciousSender)
            ? EmailVerdict::Spear_Phishing
            : EmailVerdict::Phishing;
    } else if (result.confidence >= 45.0) {
        result.verdict = EmailVerdict::Suspicious;
    } else {
        result.verdict = EmailVerdict::Clean;
    }

    if (result.mitreTechnique.empty()) {
        if (hasExecAttachment || hasMacro) {
            result.mitreTechnique = "T1566.001";
        } else if (!result.suspiciousLinks.empty()) {
            result.mitreTechnique = "T1566.002";
        } else if (HasIndicator(result.indicators, PhishingIndicator::SuspiciousSender)) {
            result.mitreTechnique = "T1534";
        } else {
            result.mitreTechnique = "T1566";
        }
    }

    if (result.summary.empty()) {
        result.summary = std::format(
            "verdict={} confidence={:.1f} attachments={} suspicious_links={} anomalies={}",
            static_cast<int>(result.verdict),
            result.confidence,
            result.attachmentsAnalyzed.size(),
            result.suspiciousLinks.size(),
            result.headerAnomalies.size());
    }
}

void AnalyzeAuthenticationHeaders(const EmailHeader& header, EmailAnalysisResult& result) {
    const std::string authLine = ToLowerAscii(header.spfResult + " " + header.dkimResult + " " + header.dmarcResult);
    if (IContains(authLine, "spf=fail") || IContains(header.spfResult, "fail") || IContains(header.spfResult, "softfail")) {
        AddIndicator(result, PhishingIndicator::SPFFailure, 16.0, "SPF authentication failed", &result.headerAnomalies);
    }
    if (IContains(authLine, "dkim=fail") || IContains(header.dkimResult, "fail")) {
        AddIndicator(result, PhishingIndicator::DKIMFailure, 14.0, "DKIM authentication failed", &result.headerAnomalies);
    }
    if (IContains(authLine, "dmarc=fail") || IContains(header.dmarcResult, "fail")) {
        AddIndicator(result, PhishingIndicator::DMARCFailure, 18.0, "DMARC authentication failed", &result.headerAnomalies);
    }
}

void AnalyzeReceivedChain(const EmailHeader& header, EmailAnalysisResult& result) {
    if (header.receivedChain.empty()) {
        AddIndicator(result, PhishingIndicator::HeaderAnomaly, 8.0, "No Received chain present", &result.headerAnomalies);
        return;
    }
    if (header.receivedChain.size() > 20) {
        AddIndicator(result, PhishingIndicator::HeaderAnomaly, 12.0, "Excessive Received hop count", &result.headerAnomalies);
    }

    std::unordered_set<std::string> uniqueLines;
    std::vector<std::string> dateTokens;
    for (const auto& line : header.receivedChain) {
        if (!uniqueLines.insert(ToLowerAscii(line)).second) {
            AddIndicator(result, PhishingIndicator::HeaderAnomaly, 10.0, "Duplicate Received header entry", &result.headerAnomalies);
            break;
        }
        if (!IContains(line, "from") || !IContains(line, "by")) {
            AddIndicator(result, PhishingIndicator::HeaderAnomaly, 6.0, "Malformed Received header entry", &result.headerAnomalies);
        }
        const std::string dateToken = ExtractDateToken(line);
        if (!dateToken.empty()) {
            dateTokens.push_back(dateToken);
        }
    }
    if (dateTokens.size() >= 2 && dateTokens.front() == dateTokens.back()) {
        AddIndicator(result, PhishingIndicator::HeaderAnomaly, 6.0, "Repeated Received timestamp observed", &result.headerAnomalies);
    }
}

void AnalyzeSender(const EmailHeader& header, EmailAnalysisResult& result) {
    static const std::unordered_set<std::string> kFreemailDomains = {
        "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "proton.me", "protonmail.com", "icloud.com"
    };
    static constexpr std::array<std::string_view, 12> kImpersonationTerms = {
        "security", "support", "helpdesk", "finance", "payroll", "admin",
        "microsoft", "office365", "vpn", "invoice", "bank", "hr"
    };

    const auto [displayName, address] = ExtractDisplayNameAndAddress(header.from);
    const std::string senderDomain = ExtractDomainFromEmail(address);
    const std::string replyToDomain = ExtractDomainFromEmail(header.returnPath);

    if (address.empty()) {
        AddIndicator(result, PhishingIndicator::SuspiciousSender, 10.0, "Sender address missing", &result.headerAnomalies);
    }
    if (!replyToDomain.empty() && !senderDomain.empty() && replyToDomain != senderDomain) {
        AddIndicator(result, PhishingIndicator::SuspiciousSender, 15.0, "Return-Path domain differs from From domain", &result.headerAnomalies);
    }

    if (!displayName.empty() && displayName.find('@') != std::string::npos) {
        const std::string displayedDomain = ExtractDomainFromEmail(displayName);
        if (!displayedDomain.empty() && displayedDomain != senderDomain) {
            AddIndicator(result, PhishingIndicator::SpoofedDomain, 18.0, "Display name embeds a different sender domain", &result.headerAnomalies);
        }
    }

    if (kFreemailDomains.contains(senderDomain)) {
        for (const auto keyword : kImpersonationTerms) {
            if (IContains(displayName, keyword) || IContains(header.subject, keyword)) {
                AddIndicator(result, PhishingIndicator::SuspiciousSender, 14.0,
                    std::format("Freemail sender impersonation pattern observed ({})", keyword),
                    &result.headerAnomalies);
                break;
            }
        }
    }

    if (LooksHomoglyphDomain(senderDomain)) {
        AddIndicator(result, PhishingIndicator::HomoglyphDomain, 16.0, "Sender domain contains punycode or non-ASCII characters", &result.headerAnomalies);
    }
    if (LooksRecentlyRegisteredDomain(senderDomain)) {
        AddIndicator(result, PhishingIndicator::RecentlyRegisteredDomain, 12.0, "Sender domain exhibits newly-registered domain heuristics", &result.headerAnomalies);
    }
}

void AnalyzeLanguage(const ParsedEmail& parsedEmail, EmailAnalysisResult& result) {
    static constexpr std::array<std::string_view, 18> kUrgencyTerms = {
        "urgent", "immediately", "asap", "right now", "final notice", "deadline",
        "act now", "verify now", "suspend", "account closure", "password expires",
        "wire transfer", "payment today", "action required", "attention", "security alert",
        "confidential request", "within 24 hours"
    };
    static constexpr std::array<std::string_view, 8> kThreatTerms = {
        "disciplinary", "termination", "penalty", "locked out", "breach", "non-compliance", "escalation", "law enforcement"
    };

    const std::string body = ToLowerAscii(parsedEmail.plainBody + "\n" + StripHtmlTags(parsedEmail.htmlBody));
    const std::string subject = ToLowerAscii(parsedEmail.header.subject);

    int urgencyHits = 0;
    for (const auto term : kUrgencyTerms) {
        if (body.find(term) != std::string::npos || subject.find(term) != std::string::npos) {
            ++urgencyHits;
        }
    }
    if (urgencyHits >= 2) {
        AddIndicator(result, PhishingIndicator::UrgentLanguage, static_cast<double>(std::min(urgencyHits * 6, 22)),
            "Urgency-heavy language detected");
    }

    for (const auto term : kThreatTerms) {
        if (body.find(term) != std::string::npos) {
            AddIndicator(result, PhishingIndicator::UrgentLanguage, 8.0,
                std::format("Threat-pressure language detected ({})", term));
        }
    }
}

void AnalyzeAttachments(const ParsedEmail& parsedEmail, EmailAnalysisResult& result) {
    for (const auto& attachment : parsedEmail.attachments) {
        result.attachmentsAnalyzed.push_back(attachment);
        if (attachment.isExecutable) {
            AddIndicator(result, PhishingIndicator::ExecutableAttachment, 30.0,
                std::format("Executable attachment detected ({})", attachment.filename));
        }
        if (attachment.hasMacro) {
            AddIndicator(result, PhishingIndicator::MacroAttachment, 20.0,
                std::format("Macro-enabled attachment detected ({})", attachment.filename));
        }
        if (attachment.isPasswordProtected) {
            AddIndicator(result, PhishingIndicator::PasswordProtectedAttachment, 18.0,
                std::format("Password-protected archive detected ({})", attachment.filename));
        }
        if (attachment.isDoubleExtension) {
            AddIndicator(result, PhishingIndicator::DoubleExtension, 16.0,
                std::format("Double-extension attachment detected ({})", attachment.filename));
        }
        if (attachment.isExecutable || attachment.hasMacro || attachment.isPasswordProtected || attachment.isDoubleExtension) {
            AddIndicator(result, PhishingIndicator::SuspiciousAttachment, 10.0,
                std::format("Attachment {} contributed to the phishing score", attachment.filename));
        }
    }
}

void AnalyzeUrls(const ParsedEmail& parsedEmail, EmailAnalysisResult& result) {
    std::unordered_set<std::string> uniqueLinks;
    const auto extractedTextUrls = ExtractUrls(parsedEmail.plainBody);
    const auto extractedHtmlUrls = ExtractUrls(parsedEmail.htmlBody);
    const auto anchors = ExtractAnchorPairs(parsedEmail.htmlBody);

    auto collectUrl = [&](const std::string& url) {
        if (url.empty()) {
            return;
        }
        if (uniqueLinks.insert(url).second && result.linksExtracted.size() < kMaxLinkCount) {
            result.linksExtracted.push_back(url);
        }
    };

    for (const auto& url : extractedTextUrls) {
        collectUrl(url);
    }
    for (const auto& url : extractedHtmlUrls) {
        collectUrl(url);
    }
    for (const auto& [href, text] : anchors) {
        collectUrl(href);
        const auto textUrls = ExtractUrls(text);
        for (const auto& visibleUrl : textUrls) {
            if (ExtractHostFromUrl(visibleUrl) != ExtractHostFromUrl(href)) {
                AddIndicator(result, PhishingIndicator::MismatchedURL, 20.0,
                    std::format("Anchor text mismatch observed: {} -> {}", visibleUrl, href));
                AppendUnique(result.suspiciousLinks, href);
            }
        }
    }

    for (const auto& url : result.linksExtracted) {
        const std::string host = ExtractHostFromUrl(url);
        if (host.empty()) {
            continue;
        }
        if (host == "data:") {
            AddIndicator(result, PhishingIndicator::SuspiciousLink, 22.0, "data: URI observed in message content");
            AppendUnique(result.suspiciousLinks, url);
        }
        if (IsUrlShortener(host)) {
            AddIndicator(result, PhishingIndicator::SuspiciousLink, 12.0,
                std::format("URL shortener observed ({})", host));
            AppendUnique(result.suspiciousLinks, url);
        }
        if (IsIpLiteral(host)) {
            AddIndicator(result, PhishingIndicator::SuspiciousLink, 18.0,
                std::format("IP-literal URL observed ({})", host));
            AppendUnique(result.suspiciousLinks, url);
        }
        if (LooksHomoglyphDomain(host)) {
            AddIndicator(result, PhishingIndicator::HomoglyphDomain, 18.0,
                std::format("Homoglyph or punycode URL host observed ({})", host));
            AppendUnique(result.suspiciousLinks, url);
        }
        if (LooksRecentlyRegisteredDomain(host)) {
            AddIndicator(result, PhishingIndicator::RecentlyRegisteredDomain, 10.0,
                std::format("URL host exhibits newly-registered-domain heuristics ({})", host));
            AppendUnique(result.suspiciousLinks, url);
        }
    }
}

[[nodiscard]] EmailAttachment BuildAttachment(std::string fileName,
                                              std::string contentType,
                                              const std::vector<uint8_t>& bytes) {
    EmailAttachment attachment;
    attachment.filename = fileName.empty() ? "unnamed_attachment" : std::move(fileName);
    attachment.contentType = contentType.empty() ? "application/octet-stream" : std::move(contentType);
    attachment.size = bytes.size();
    attachment.sha256 = ComputeSha256(bytes);
    attachment.isExecutable = IsExecutableExtension(attachment.filename) || IsExecutableMagic(bytes);
    attachment.hasMacro = HasMacroExtension(attachment.filename) || ContainsOleMacroMarkers(bytes);
    attachment.isPasswordProtected = IsArchiveExtension(attachment.filename) && IsPasswordProtectedArchive(bytes, attachment.filename);
    attachment.isDoubleExtension = HasDoubleExtension(attachment.filename);
    return attachment;
}

void ParseMimeEntity(const HeaderCollection& headers,
                     const std::string& body,
                     ParsedEmail& parsedEmail,
                     const std::size_t depth,
                     std::size_t& partCount) {
    if (depth > kMaxMimePartDepth || partCount > kMaxMimePartCount) {
        return;
    }
    ++partCount;

    const std::string contentTypeHeader = GetHeaderValue(headers, "content-type");
    const std::string dispositionHeader = GetHeaderValue(headers, "content-disposition");
    const std::string transferEncoding = GetHeaderValue(headers, "content-transfer-encoding");
    const std::string lowerContentType = ToLowerAscii(contentTypeHeader);

    if (lowerContentType.starts_with("multipart/")) {
        const std::string boundary = GetHeaderParameter(contentTypeHeader, "boundary");
        if (boundary.empty()) {
            return;
        }
        const std::string delimiter = "--" + boundary;
        std::size_t searchFrom = 0;
        while (true) {
            const std::size_t partStart = body.find(delimiter, searchFrom);
            if (partStart == std::string::npos) {
                break;
            }
            const std::size_t dataStart = body.find_first_of("\r\n", partStart + delimiter.size());
            if (dataStart == std::string::npos) {
                break;
            }
            const std::size_t nextStart = body.find(delimiter, dataStart);
            if (nextStart == std::string::npos) {
                break;
            }
            std::string rawPart = body.substr(dataStart, nextStart - dataStart);
            rawPart = TrimAscii(rawPart);
            if (const auto section = SplitHeadersAndBody(rawPart)) {
                ParseMimeEntity(section->headers, section->body, parsedEmail, depth + 1, partCount);
            }
            searchFrom = nextStart;
            if (body.compare(nextStart, delimiter.size() + 2, delimiter + "--") == 0) {
                break;
            }
        }
        return;
    }

    const std::string decodedBody = DecodeTransferEncodedBody(body, transferEncoding);
    std::vector<uint8_t> bytes(decodedBody.begin(), decodedBody.end());

    const std::string fileName = [&]() {
        std::string name = GetHeaderParameter(dispositionHeader, "filename");
        if (name.empty()) {
            name = GetHeaderParameter(contentTypeHeader, "name");
        }
        return DecodeRfc2047Words(name);
    }();

    const bool isAttachment = IContains(dispositionHeader, "attachment") || !fileName.empty();
    if (isAttachment && parsedEmail.attachments.size() < kMaxAttachmentCount) {
        parsedEmail.attachments.push_back(BuildAttachment(fileName, contentTypeHeader, bytes));
        return;
    }

    if (IContains(lowerContentType, "text/plain")) {
        parsedEmail.plainBody.append(decodedBody);
        parsedEmail.plainBody.push_back('\n');
    } else if (IContains(lowerContentType, "text/html")) {
        parsedEmail.htmlBody.append(decodedBody);
        parsedEmail.htmlBody.push_back('\n');
    }
}

[[nodiscard]] ParsedEmail ParseEml(const std::vector<uint8_t>& bytes) {
    ParsedEmail parsedEmail;
    const std::string raw(bytes.begin(), bytes.end());
    if (const auto section = SplitHeadersAndBody(raw)) {
        parsedEmail.header.from = GetHeaderValue(section->headers, "from");
        parsedEmail.header.to = GetHeaderValue(section->headers, "to");
        parsedEmail.header.cc = GetHeaderValue(section->headers, "cc");
        parsedEmail.header.subject = GetHeaderValue(section->headers, "subject");
        parsedEmail.header.date = GetHeaderValue(section->headers, "date");
        parsedEmail.header.messageId = GetHeaderValue(section->headers, "message-id");
        parsedEmail.header.inReplyTo = GetHeaderValue(section->headers, "in-reply-to");
        parsedEmail.header.returnPath = GetHeaderValue(section->headers, "return-path");
        parsedEmail.header.receivedChain = section->headers.received;

        const std::string authResults = GetHeaderValue(section->headers, "authentication-results");
        parsedEmail.header.spfResult = authResults;
        parsedEmail.header.dkimResult = authResults;
        parsedEmail.header.dmarcResult = authResults;

        const std::string receivedSpf = GetHeaderValue(section->headers, "received-spf");
        if (!receivedSpf.empty()) {
            parsedEmail.header.spfResult = receivedSpf;
        }

        std::size_t partCount = 0;
        ParseMimeEntity(section->headers, section->body, parsedEmail, 0, partCount);

        if (parsedEmail.plainBody.empty() && parsedEmail.htmlBody.empty()) {
            parsedEmail.plainBody = section->body;
        }
    }
    return parsedEmail;
}

class CompoundFileReader final {
public:
    [[nodiscard]] bool Load(std::vector<uint8_t> bytes, std::string& error) {
        bytes_ = std::move(bytes);
        error.clear();
        if (bytes_.size() < 512) {
            error = "MSG/CFBF file smaller than compound header";
            return false;
        }

        static constexpr std::array<uint8_t, 8> kSignature = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
        if (!std::equal(kSignature.begin(), kSignature.end(), bytes_.begin())) {
            error = "Compound file signature mismatch";
            return false;
        }

        sectorSize_ = static_cast<std::size_t>(1ULL << ReadUInt16LE(bytes_, 30));
        miniSectorSize_ = static_cast<std::size_t>(1ULL << ReadUInt16LE(bytes_, 32));
        firstDirectorySector_ = ReadUInt32LE(bytes_, 48);
        miniStreamCutoff_ = ReadUInt32LE(bytes_, 56);
        firstMiniFatSector_ = ReadUInt32LE(bytes_, 60);
        miniFatSectorCount_ = ReadUInt32LE(bytes_, 64);
        firstDifatSector_ = ReadUInt32LE(bytes_, 68);
        difatSectorCount_ = ReadUInt32LE(bytes_, 72);
        fatSectorCount_ = ReadUInt32LE(bytes_, 44);

        if (sectorSize_ == 0 || miniSectorSize_ == 0) {
            error = "Invalid sector sizing in compound file";
            return false;
        }

        if (!LoadFat(error) || !LoadDirectory(error) || !LoadMiniFat(error) || !BuildPathMap(error)) {
            return false;
        }

        return true;
    }

    [[nodiscard]] bool HasPath(std::string_view path) const {
        return pathIndex_.contains(std::string(path));
    }

    [[nodiscard]] std::vector<std::string> EnumeratePaths() const {
        std::vector<std::string> paths;
        paths.reserve(pathIndex_.size());
        for (const auto& [path, _] : pathIndex_) {
            paths.push_back(path);
        }
        std::sort(paths.begin(), paths.end());
        return paths;
    }

    [[nodiscard]] std::vector<uint8_t> ReadStream(std::string_view path) const {
        const auto it = pathIndex_.find(std::string(path));
        if (it == pathIndex_.end()) {
            return {};
        }
        const auto& entry = directoryEntries_[it->second];
        if (entry.streamSize == 0) {
            return {};
        }
        if (entry.streamSize < miniStreamCutoff_ && entry.objectType != 5) {
            return ReadMiniStream(entry.startSector, entry.streamSize);
        }
        return ReadRegularStream(entry.startSector, entry.streamSize);
    }

private:
    struct DirectoryEntry {
        std::string name;
        uint8_t objectType = 0;
        uint32_t leftSibling = kNoStream;
        uint32_t rightSibling = kNoStream;
        uint32_t child = kNoStream;
        uint32_t startSector = kEndOfChain;
        uint64_t streamSize = 0;
    };

    [[nodiscard]] std::size_t SectorOffset(const uint32_t sector) const {
        return 512ULL + static_cast<std::size_t>(sector) * sectorSize_;
    }

    [[nodiscard]] bool LoadFat(std::string& error) {
        std::vector<uint32_t> difat;
        difat.reserve(fatSectorCount_ + 8);
        for (std::size_t offset = 76; offset < 76 + 109 * sizeof(uint32_t); offset += sizeof(uint32_t)) {
            const uint32_t sector = ReadUInt32LE(bytes_, offset);
            if (sector != kFreeSector) {
                difat.push_back(sector);
            }
        }

        uint32_t currentDifatSector = firstDifatSector_;
        for (uint32_t iteration = 0; iteration < difatSectorCount_ && currentDifatSector != kEndOfChain; ++iteration) {
            const std::size_t offset = SectorOffset(currentDifatSector);
            if (offset + sectorSize_ > bytes_.size()) {
                error = "DIFAT sector out of bounds";
                return false;
            }
            const std::size_t entriesPerSector = (sectorSize_ / sizeof(uint32_t)) - 1;
            for (std::size_t entryIndex = 0; entryIndex < entriesPerSector; ++entryIndex) {
                const uint32_t sector = ReadUInt32LE(bytes_, offset + entryIndex * sizeof(uint32_t));
                if (sector != kFreeSector) {
                    difat.push_back(sector);
                }
            }
            currentDifatSector = ReadUInt32LE(bytes_, offset + sectorSize_ - sizeof(uint32_t));
        }

        if (difat.empty()) {
            error = "Compound file FAT is empty";
            return false;
        }

        fat_.clear();
        for (const uint32_t fatSector : difat) {
            const std::size_t offset = SectorOffset(fatSector);
            if (offset + sectorSize_ > bytes_.size()) {
                error = "FAT sector out of bounds";
                return false;
            }
            for (std::size_t entryOffset = 0; entryOffset < sectorSize_; entryOffset += sizeof(uint32_t)) {
                fat_.push_back(ReadUInt32LE(bytes_, offset + entryOffset));
            }
        }
        return true;
    }

    [[nodiscard]] std::vector<uint8_t> ReadRegularStream(const uint32_t startSector, const uint64_t expectedSize) const {
        std::vector<uint8_t> data;
        if (startSector == kEndOfChain || startSector == kFreeSector) {
            return data;
        }

        uint32_t sector = startSector;
        std::unordered_set<uint32_t> seen;
        while (sector != kEndOfChain && sector != kFreeSector && seen.insert(sector).second) {
            const std::size_t offset = SectorOffset(sector);
            if (offset + sectorSize_ > bytes_.size()) {
                break;
            }
            data.insert(data.end(), bytes_.begin() + static_cast<std::ptrdiff_t>(offset),
                bytes_.begin() + static_cast<std::ptrdiff_t>(offset + sectorSize_));
            if (sector >= fat_.size()) {
                break;
            }
            sector = fat_[sector];
        }
        if (expectedSize != 0 && data.size() > expectedSize) {
            data.resize(static_cast<std::size_t>(expectedSize));
        }
        return data;
    }

    [[nodiscard]] bool LoadDirectory(std::string& error) {
        const std::vector<uint8_t> directoryStream = ReadRegularStream(firstDirectorySector_, 0);
        if (directoryStream.empty()) {
            error = "Directory stream could not be read";
            return false;
        }

        directoryEntries_.clear();
        for (std::size_t offset = 0; offset + 128 <= directoryStream.size(); offset += 128) {
            const uint16_t nameLength = ReadUInt16LE(directoryStream, offset + 64);
            DirectoryEntry entry;
            if (nameLength >= 2) {
                std::wstring wideName;
                for (std::size_t nameOffset = 0; nameOffset + 1 < nameLength - 1 && offset + nameOffset + 1 < directoryStream.size(); nameOffset += 2) {
                    const wchar_t character = static_cast<wchar_t>(ReadUInt16LE(directoryStream, offset + nameOffset));
                    if (character == L'\0') {
                        break;
                    }
                    wideName.push_back(character);
                }
                entry.name = SU::ToNarrow(wideName);
            }
            entry.objectType = offset + 66 < directoryStream.size() ? directoryStream[offset + 66] : 0;
            entry.leftSibling = ReadUInt32LE(directoryStream, offset + 68);
            entry.rightSibling = ReadUInt32LE(directoryStream, offset + 72);
            entry.child = ReadUInt32LE(directoryStream, offset + 76);
            entry.startSector = ReadUInt32LE(directoryStream, offset + 116);
            entry.streamSize = ReadUInt64LE(directoryStream, offset + 120);
            directoryEntries_.push_back(std::move(entry));
        }

        if (directoryEntries_.empty()) {
            error = "No directory entries parsed from compound file";
            return false;
        }

        if (!directoryEntries_.empty()) {
            rootMiniStream_ = ReadRegularStream(directoryEntries_.front().startSector, directoryEntries_.front().streamSize);
        }
        return true;
    }

    [[nodiscard]] bool LoadMiniFat(std::string& error) {
        if (firstMiniFatSector_ == kEndOfChain || miniFatSectorCount_ == 0) {
            return true;
        }
        const std::vector<uint8_t> miniFatBytes = ReadRegularStream(firstMiniFatSector_, static_cast<uint64_t>(miniFatSectorCount_) * sectorSize_);
        if (miniFatBytes.empty()) {
            error = "MiniFAT could not be read";
            return false;
        }
        miniFat_.clear();
        for (std::size_t offset = 0; offset + sizeof(uint32_t) <= miniFatBytes.size(); offset += sizeof(uint32_t)) {
            miniFat_.push_back(ReadUInt32LE(miniFatBytes, offset));
        }
        return true;
    }

    [[nodiscard]] std::vector<uint8_t> ReadMiniStream(const uint32_t startSector, const uint64_t size) const {
        std::vector<uint8_t> data;
        if (startSector == kEndOfChain || startSector == kFreeSector || miniFat_.empty() || rootMiniStream_.empty()) {
            return data;
        }

        uint32_t sector = startSector;
        std::unordered_set<uint32_t> seen;
        while (sector != kEndOfChain && sector != kFreeSector && seen.insert(sector).second) {
            const std::size_t offset = static_cast<std::size_t>(sector) * miniSectorSize_;
            if (offset + miniSectorSize_ > rootMiniStream_.size()) {
                break;
            }
            data.insert(data.end(), rootMiniStream_.begin() + static_cast<std::ptrdiff_t>(offset),
                rootMiniStream_.begin() + static_cast<std::ptrdiff_t>(offset + miniSectorSize_));
            if (sector >= miniFat_.size()) {
                break;
            }
            sector = miniFat_[sector];
        }
        if (data.size() > size) {
            data.resize(static_cast<std::size_t>(size));
        }
        return data;
    }

    void TraverseTree(const uint32_t entryIndex,
                      const std::string& parentPath,
                      std::unordered_set<uint32_t>& visited) {
        if (entryIndex == kNoStream || entryIndex >= directoryEntries_.size() || visited.contains(entryIndex)) {
            return;
        }
        visited.insert(entryIndex);
        const auto& entry = directoryEntries_[entryIndex];

        TraverseTree(entry.leftSibling, parentPath, visited);

        std::string currentPath = parentPath;
        if (entry.objectType != 5 && !entry.name.empty()) {
            currentPath = parentPath.empty() ? entry.name : parentPath + "/" + entry.name;
            pathIndex_[currentPath] = entryIndex;
        }
        if (entry.child != kNoStream) {
            TraverseTree(entry.child, currentPath, visited);
        }
        TraverseTree(entry.rightSibling, parentPath, visited);
    }

    [[nodiscard]] bool BuildPathMap(std::string& error) {
        if (directoryEntries_.empty()) {
            error = "Cannot build path map without directory entries";
            return false;
        }
        pathIndex_.clear();
        std::unordered_set<uint32_t> visited;
        TraverseTree(directoryEntries_.front().child, {}, visited);
        return true;
    }

    std::vector<uint8_t> bytes_;
    std::size_t sectorSize_ = 0;
    std::size_t miniSectorSize_ = 0;
    uint32_t firstDirectorySector_ = kEndOfChain;
    uint32_t firstMiniFatSector_ = kEndOfChain;
    uint32_t miniFatSectorCount_ = 0;
    uint32_t firstDifatSector_ = kEndOfChain;
    uint32_t difatSectorCount_ = 0;
    uint32_t fatSectorCount_ = 0;
    uint32_t miniStreamCutoff_ = 4096;
    std::vector<uint32_t> fat_;
    std::vector<uint32_t> miniFat_;
    std::vector<DirectoryEntry> directoryEntries_;
    std::vector<uint8_t> rootMiniStream_;
    std::unordered_map<std::string, std::size_t> pathIndex_;
};

[[nodiscard]] std::string ReadMsgStringProperty(CompoundFileReader& reader,
                                                std::string_view prefix,
                                                std::string_view propertyIdHex) {
    const std::array<std::string, 3> suffixes = {"001F", "001E", "0102"};
    for (const auto& suffix : suffixes) {
        const std::string path = prefix.empty()
            ? std::format("__substg1.0_{}{}", propertyIdHex, suffix)
            : std::format("{}/__substg1.0_{}{}", prefix, propertyIdHex, suffix);
        if (!reader.HasPath(path)) {
            continue;
        }
        auto data = reader.ReadStream(path);
        if (data.empty()) {
            continue;
        }
        if (suffix == "001F") {
            std::wstring wide;
            for (std::size_t offset = 0; offset + 1 < data.size(); offset += 2) {
                const wchar_t ch = static_cast<wchar_t>(static_cast<uint16_t>(data[offset]) |
                    static_cast<uint16_t>(data[offset + 1] << 8));
                if (ch == L'\0') {
                    break;
                }
                wide.push_back(ch);
            }
            return SU::ToNarrow(wide);
        }
        std::string value(reinterpret_cast<const char*>(data.data()), data.size());
        while (!value.empty() && value.back() == '\0') {
            value.pop_back();
        }
        return value;
    }
    return {};
}

[[nodiscard]] ParsedEmail ParseMsg(const std::vector<uint8_t>& bytes) {
    ParsedEmail parsedEmail;
    CompoundFileReader reader;
    std::string error;
    if (!reader.Load(bytes, error)) {
        Logger::Warn("EmailAnalyzer: MSG parser rejected compound file: {}", error);
        return parsedEmail;
    }

    parsedEmail.header.subject = ReadMsgStringProperty(reader, {}, "0037");
    const std::string senderName = ReadMsgStringProperty(reader, {}, "0C1A");
    const std::string senderEmail = ReadMsgStringProperty(reader, {}, "0C1F");
    parsedEmail.header.from = senderName.empty() || senderEmail.empty()
        ? (!senderEmail.empty() ? senderEmail : senderName)
        : std::format("{} <{}>", senderName, senderEmail);
    parsedEmail.header.to = ReadMsgStringProperty(reader, {}, "0E04");
    parsedEmail.header.cc = ReadMsgStringProperty(reader, {}, "0E03");
    parsedEmail.header.messageId = ReadMsgStringProperty(reader, {}, "1035");
    parsedEmail.header.date = ReadMsgStringProperty(reader, {}, "3008");
    parsedEmail.header.returnPath = senderEmail;
    parsedEmail.plainBody = ReadMsgStringProperty(reader, {}, "1000");
    parsedEmail.htmlBody = ReadMsgStringProperty(reader, {}, "1013");

    const std::string transportHeaders = ReadMsgStringProperty(reader, {}, "007D");
    if (!transportHeaders.empty()) {
        const HeaderCollection headers = ParseHeaders(transportHeaders);
        if (parsedEmail.header.messageId.empty()) {
            parsedEmail.header.messageId = GetHeaderValue(headers, "message-id");
        }
        parsedEmail.header.inReplyTo = GetHeaderValue(headers, "in-reply-to");
        parsedEmail.header.date = parsedEmail.header.date.empty() ? GetHeaderValue(headers, "date") : parsedEmail.header.date;
        parsedEmail.header.receivedChain = headers.received;
        const std::string authResults = GetHeaderValue(headers, "authentication-results");
        parsedEmail.header.spfResult = authResults;
        parsedEmail.header.dkimResult = authResults;
        parsedEmail.header.dmarcResult = authResults;
        const std::string receivedSpf = GetHeaderValue(headers, "received-spf");
        if (!receivedSpf.empty()) {
            parsedEmail.header.spfResult = receivedSpf;
        }
    }

    std::set<std::string> attachmentRoots;
    for (const auto& path : reader.EnumeratePaths()) {
        if (path.starts_with("__attach_version1.0_#")) {
            const std::size_t separator = path.find('/');
            attachmentRoots.insert(separator == std::string::npos ? path : path.substr(0, separator));
        }
    }

    for (const auto& root : attachmentRoots) {
        if (parsedEmail.attachments.size() >= kMaxAttachmentCount) {
            break;
        }
        std::string fileName = ReadMsgStringProperty(reader, root, "3707");
        if (fileName.empty()) {
            fileName = ReadMsgStringProperty(reader, root, "3704");
        }
        std::string mimeType = ReadMsgStringProperty(reader, root, "370E");
        const std::vector<uint8_t> data = reader.ReadStream(std::format("{}/__substg1.0_37010102", root));
        if (data.empty()) {
            continue;
        }
        parsedEmail.attachments.push_back(BuildAttachment(fileName, mimeType, data));
    }

    if (parsedEmail.plainBody.empty() && !parsedEmail.htmlBody.empty()) {
        parsedEmail.plainBody = StripHtmlTags(parsedEmail.htmlBody);
    }

    return parsedEmail;
}

[[nodiscard]] bool IsSupportedEmailFile(const fs::path& emailPath) {
    const std::string extension = ToLowerAscii(emailPath.extension().string());
    return extension == ".eml" || extension == ".msg";
}

[[nodiscard]] EmailAnalysisResult LoadResultFromRow(QueryResult& result) {
    EmailAnalysisResult analysis;
    analysis.header.messageId = result.IsNull("message_id") ? std::string{} : result.GetString("message_id");
    analysis.filePath = result.IsNull("file_path") ? std::string{} : result.GetString("file_path");
    analysis.fileSha256 = result.IsNull("file_sha256") ? std::string{} : result.GetString("file_sha256");
    analysis.header.from = result.IsNull("header_from") ? std::string{} : result.GetString("header_from");
    analysis.header.to = result.IsNull("header_to") ? std::string{} : result.GetString("header_to");
    analysis.header.cc = result.IsNull("header_cc") ? std::string{} : result.GetString("header_cc");
    analysis.header.subject = result.IsNull("header_subject") ? std::string{} : result.GetString("header_subject");
    analysis.header.date = result.IsNull("header_date") ? std::string{} : result.GetString("header_date");
    analysis.header.inReplyTo = result.IsNull("in_reply_to") ? std::string{} : result.GetString("in_reply_to");
    analysis.header.receivedChain = result.IsNull("received_chain") ? std::vector<std::string>{} : DeserializeStringList(result.GetString("received_chain"));
    analysis.header.returnPath = result.IsNull("return_path") ? std::string{} : result.GetString("return_path");
    analysis.header.spfResult = result.IsNull("spf_result") ? std::string{} : result.GetString("spf_result");
    analysis.header.dkimResult = result.IsNull("dkim_result") ? std::string{} : result.GetString("dkim_result");
    analysis.header.dmarcResult = result.IsNull("dmarc_result") ? std::string{} : result.GetString("dmarc_result");
    analysis.verdict = static_cast<EmailVerdict>(result.IsNull("verdict") ? 0 : result.GetInt("verdict"));
    analysis.indicators = static_cast<PhishingIndicator>(result.IsNull("indicators") ? 0 : static_cast<uint32_t>(result.GetInt64("indicators")));
    analysis.confidence = result.IsNull("confidence") ? 0.0 : result.GetDouble("confidence");
    analysis.linksExtracted = result.IsNull("links_extracted") ? std::vector<std::string>{} : DeserializeStringList(result.GetString("links_extracted"));
    analysis.suspiciousLinks = result.IsNull("suspicious_links") ? std::vector<std::string>{} : DeserializeStringList(result.GetString("suspicious_links"));
    analysis.headerAnomalies = result.IsNull("header_anomalies") ? std::vector<std::string>{} : DeserializeStringList(result.GetString("header_anomalies"));
    analysis.mitreTechnique = result.IsNull("mitre_technique") ? std::string{} : result.GetString("mitre_technique");
    analysis.attachmentsAnalyzed = result.IsNull("attachments_data") ? std::vector<EmailAttachment>{} : DeserializeAttachments(result.GetString("attachments_data"));
    analysis.summary = result.IsNull("summary") ? std::string{} : result.GetString("summary");
    analysis.analyzedAt = result.IsNull("analyzed_at") ? std::chrono::system_clock::time_point{} : FromUnixSeconds(result.GetInt64("analyzed_at"));
    return analysis;
}

} // namespace

class EmailAnalyzerImpl final {
public:
    std::atomic<bool> initialized{false};
    std::atomic<uint64_t> totalScans{0};
    std::atomic<uint64_t> suspiciousScans{0};
    std::atomic<uint64_t> phishingScans{0};
    std::atomic<uint64_t> maliciousScans{0};
    std::atomic<uint64_t> totalAttachments{0};
    std::atomic<uint64_t> totalLinks{0};
    std::atomic<uint64_t> emlFilesParsed{0};
    std::atomic<uint64_t> msgFilesParsed{0};
    std::atomic<uint64_t> persistedResults{0};
    std::atomic<uint64_t> databaseFailures{0};
    mutable std::shared_mutex mutex;
    std::unordered_map<std::string, EmailAnalysisResult> cache;
    std::deque<std::string> cacheOrder;
    std::jthread maintenanceThread;

    void StartMaintenanceThread() {
        maintenanceThread = std::jthread([this](const std::stop_token stopToken) {
            MaintenanceLoop(stopToken);
        });
    }

    void MaintenanceLoop(const std::stop_token stopToken) {
        while (!stopToken.stop_requested()) {
            {
                std::unique_lock lock(mutex);
                while (cacheOrder.size() > kMaxCacheEntries) {
                    const std::string oldest = cacheOrder.front();
                    cacheOrder.pop_front();
                    cache.erase(oldest);
                }
            }
            for (int64_t slept = 0; slept < 10 && !stopToken.stop_requested(); ++slept) {
                std::this_thread::sleep_for(std::chrono::milliseconds(kSleepSliceMs));
            }
        }
    }

    void UpdateCache(const EmailAnalysisResult& result) {
        if (result.header.messageId.empty()) {
            return;
        }
        std::unique_lock lock(mutex);
        cache[result.header.messageId] = result;
        cacheOrder.push_back(result.header.messageId);
        while (cacheOrder.size() > kMaxCacheEntries) {
            const std::string oldest = cacheOrder.front();
            cacheOrder.pop_front();
            cache.erase(oldest);
        }
    }
};

EmailAnalyzer::EmailAnalyzer()
    : m_impl(std::make_unique<EmailAnalyzerImpl>()) {
}

EmailAnalyzer::~EmailAnalyzer() = default;

bool EmailAnalyzer::Initialize() {
    auto& db = DatabaseManager::Instance();
    if (!db.IsInitialized()) {
        Logger::Error("EmailAnalyzer: DatabaseManager is not initialized");
        return false;
    }

    DatabaseError dbError{};
    if (!db.Execute(kSchemaSql, &dbError)) {
        Logger::Error("EmailAnalyzer: schema initialization failed code={} msg={}",
            dbError.sqliteCode,
            SU::ToNarrow(dbError.message));
        m_impl->databaseFailures.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    m_impl->initialized.store(true, std::memory_order_release);
    m_impl->StartMaintenanceThread();
    Logger::Info("EmailAnalyzer: initialized successfully");
    return true;
}

void EmailAnalyzer::Shutdown() {
    m_impl->initialized.store(false, std::memory_order_release);
    if (m_impl->maintenanceThread.joinable()) {
        m_impl->maintenanceThread.request_stop();
        m_impl->maintenanceThread.join();
    }
    std::unique_lock lock(m_impl->mutex);
    m_impl->cache.clear();
    m_impl->cacheOrder.clear();
}

bool EmailAnalyzer::IsInitialized() const noexcept {
    return m_impl->initialized.load(std::memory_order_acquire);
}

EmailAnalysisResult EmailAnalyzer::ScanEmailFile(const fs::path& emailPath) {
    EmailAnalysisResult result;
    result.filePath = emailPath.string();
    result.analyzedAt = std::chrono::system_clock::now();

    if (!IsInitialized()) {
        Logger::Warn("EmailAnalyzer: ScanEmailFile called before Initialize");
        return result;
    }

    std::error_code errorCode;
    if (!fs::exists(emailPath, errorCode) || errorCode || !fs::is_regular_file(emailPath, errorCode)) {
        Logger::Warn("EmailAnalyzer: path does not reference a regular file: {}", emailPath.string());
        return result;
    }
    if (!IsSupportedEmailFile(emailPath)) {
        Logger::Warn("EmailAnalyzer: unsupported email file extension: {}", emailPath.string());
        return result;
    }

    result.fileSha256 = ComputeFileSha256(emailPath);
    const auto bytes = ReadFileBounded(emailPath, kMaxEmailFileSize);
    if (bytes.empty()) {
        Logger::Warn("EmailAnalyzer: failed to read email file or file exceeded size guard: {}", emailPath.string());
        return result;
    }

    ParsedEmail parsedEmail;
    const std::string extension = ToLowerAscii(emailPath.extension().string());
    if (extension == ".eml") {
        parsedEmail = ParseEml(bytes);
        m_impl->emlFilesParsed.fetch_add(1, std::memory_order_relaxed);
    } else {
        parsedEmail = ParseMsg(bytes);
        m_impl->msgFilesParsed.fetch_add(1, std::memory_order_relaxed);
    }

    result.header = parsedEmail.header;
    if (result.header.messageId.empty()) {
        const std::string seed = !result.fileSha256.empty() ? result.fileSha256 : ComputeSha256(bytes);
        result.header.messageId = std::format("<{}@local.emailthreat>", seed.substr(0, std::min<std::size_t>(seed.size(), 32)));
    }

    AnalyzeAuthenticationHeaders(result.header, result);
    AnalyzeReceivedChain(result.header, result);
    AnalyzeSender(result.header, result);
    AnalyzeLanguage(parsedEmail, result);
    AnalyzeAttachments(parsedEmail, result);
    AnalyzeUrls(parsedEmail, result);

    if (result.header.subject.empty()) {
        AddIndicator(result, PhishingIndicator::HeaderAnomaly, 5.0, "Subject header missing", &result.headerAnomalies);
    }
    if (result.header.messageId.empty()) {
        AddIndicator(result, PhishingIndicator::HeaderAnomaly, 8.0, "Message-ID missing", &result.headerAnomalies);
    }

    FinalizeVerdict(result);

    m_impl->totalScans.fetch_add(1, std::memory_order_relaxed);
    m_impl->totalAttachments.fetch_add(result.attachmentsAnalyzed.size(), std::memory_order_relaxed);
    m_impl->totalLinks.fetch_add(result.linksExtracted.size(), std::memory_order_relaxed);
    switch (result.verdict) {
    case EmailVerdict::Suspicious:
        m_impl->suspiciousScans.fetch_add(1, std::memory_order_relaxed);
        break;
    case EmailVerdict::Phishing:
    case EmailVerdict::Spear_Phishing:
        m_impl->phishingScans.fetch_add(1, std::memory_order_relaxed);
        break;
    case EmailVerdict::Malicious:
        m_impl->maliciousScans.fetch_add(1, std::memory_order_relaxed);
        break;
    case EmailVerdict::Clean:
    default:
        break;
    }

    DatabaseError dbError{};
    const bool stored = DatabaseManager::Instance().ExecuteWithParams(
        "INSERT OR REPLACE INTO xdr_email_scan_results (message_id, file_path, file_sha256, header_from, header_to, header_cc, header_subject, header_date, in_reply_to, received_chain, return_path, spf_result, dkim_result, dmarc_result, verdict, indicators, confidence, links_extracted, suspicious_links, header_anomalies, mitre_technique, attachments_data, summary, analyzed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &dbError,
        LimitForStorage(result.header.messageId),
        LimitForStorage(result.filePath),
        LimitForStorage(result.fileSha256),
        LimitForStorage(result.header.from),
        LimitForStorage(result.header.to),
        LimitForStorage(result.header.cc),
        LimitForStorage(result.header.subject),
        LimitForStorage(result.header.date),
        LimitForStorage(result.header.inReplyTo),
        SerializeStringList(result.header.receivedChain),
        LimitForStorage(result.header.returnPath),
        LimitForStorage(result.header.spfResult),
        LimitForStorage(result.header.dkimResult),
        LimitForStorage(result.header.dmarcResult),
        static_cast<int>(result.verdict),
        static_cast<int64_t>(static_cast<uint32_t>(result.indicators)),
        result.confidence,
        SerializeStringList(result.linksExtracted),
        SerializeStringList(result.suspiciousLinks),
        SerializeStringList(result.headerAnomalies),
        LimitForStorage(result.mitreTechnique),
        SerializeAttachments(result.attachmentsAnalyzed),
        LimitForStorage(result.summary),
        ToUnixSeconds(result.analyzedAt));

    if (!stored) {
        Logger::Error("EmailAnalyzer: failed to persist result code={} msg={}",
            dbError.sqliteCode,
            SU::ToNarrow(dbError.message));
        m_impl->databaseFailures.fetch_add(1, std::memory_order_relaxed);
    } else {
        m_impl->persistedResults.fetch_add(1, std::memory_order_relaxed);
    }

    m_impl->UpdateCache(result);
    Logger::Info("EmailAnalyzer: scanned {} verdict={} confidence={:.1f} attachments={} suspicious_links={}",
        emailPath.string(),
        static_cast<int>(result.verdict),
        result.confidence,
        result.attachmentsAnalyzed.size(),
        result.suspiciousLinks.size());
    return result;
}

std::vector<EmailAnalysisResult> EmailAnalyzer::ScanDirectory(const fs::path& directoryPath, const bool recursive) {
    std::vector<EmailAnalysisResult> results;
    if (!IsInitialized()) {
        Logger::Warn("EmailAnalyzer: ScanDirectory called before Initialize");
        return results;
    }

    std::error_code errorCode;
    if (!fs::exists(directoryPath, errorCode) || errorCode || !fs::is_directory(directoryPath, errorCode)) {
        Logger::Warn("EmailAnalyzer: ScanDirectory target is not a directory: {}", directoryPath.string());
        return results;
    }

    auto processPath = [&](const fs::path& entryPath) {
        if (IsSupportedEmailFile(entryPath)) {
            results.push_back(ScanEmailFile(entryPath));
        }
    };

    if (recursive) {
        for (fs::recursive_directory_iterator it(directoryPath, fs::directory_options::skip_permission_denied, errorCode), end;
             it != end; it.increment(errorCode)) {
            if (errorCode) {
                Logger::Warn("EmailAnalyzer: recursive directory scan error at {}", directoryPath.string());
                errorCode.clear();
                continue;
            }
            if (it->is_regular_file(errorCode) && !errorCode) {
                processPath(it->path());
            } else {
                errorCode.clear();
            }
        }
    } else {
        for (fs::directory_iterator it(directoryPath, fs::directory_options::skip_permission_denied, errorCode), end;
             it != end; it.increment(errorCode)) {
            if (errorCode) {
                Logger::Warn("EmailAnalyzer: directory scan error at {}", directoryPath.string());
                errorCode.clear();
                continue;
            }
            if (it->is_regular_file(errorCode) && !errorCode) {
                processPath(it->path());
            } else {
                errorCode.clear();
            }
        }
    }

    return results;
}

std::optional<EmailAnalysisResult> EmailAnalyzer::GetScanResult(std::string_view messageId) const {
    if (messageId.empty()) {
        return std::nullopt;
    }

    {
        std::shared_lock lock(m_impl->mutex);
        const auto it = m_impl->cache.find(std::string(messageId));
        if (it != m_impl->cache.end()) {
            return it->second;
        }
    }

    DatabaseError dbError{};
    auto query = DatabaseManager::Instance().QueryWithParams(
        "SELECT message_id, file_path, file_sha256, header_from, header_to, header_cc, header_subject, header_date, in_reply_to, received_chain, return_path, spf_result, dkim_result, dmarc_result, verdict, indicators, confidence, links_extracted, suspicious_links, header_anomalies, mitre_technique, attachments_data, summary, analyzed_at FROM xdr_email_scan_results WHERE message_id = ? LIMIT 1",
        &dbError,
        std::string(messageId));

    if (dbError.HasError()) {
        Logger::Error("EmailAnalyzer: GetScanResult query failed code={} msg={}",
            dbError.sqliteCode,
            SU::ToNarrow(dbError.message));
        m_impl->databaseFailures.fetch_add(1, std::memory_order_relaxed);
        return std::nullopt;
    }
    if (!query.Next()) {
        return std::nullopt;
    }

    EmailAnalysisResult result = LoadResultFromRow(query);
    m_impl->UpdateCache(result);
    return result;
}

std::vector<EmailAnalysisResult> EmailAnalyzer::GetScanHistory(const std::size_t limit) const {
    std::vector<EmailAnalysisResult> history;
    DatabaseError dbError{};
    auto query = DatabaseManager::Instance().QueryWithParams(
        "SELECT message_id, file_path, file_sha256, header_from, header_to, header_cc, header_subject, header_date, in_reply_to, received_chain, return_path, spf_result, dkim_result, dmarc_result, verdict, indicators, confidence, links_extracted, suspicious_links, header_anomalies, mitre_technique, attachments_data, summary, analyzed_at FROM xdr_email_scan_results ORDER BY analyzed_at DESC LIMIT ?",
        &dbError,
        static_cast<int64_t>(limit));

    if (dbError.HasError()) {
        Logger::Error("EmailAnalyzer: GetScanHistory query failed code={} msg={}",
            dbError.sqliteCode,
            SU::ToNarrow(dbError.message));
        m_impl->databaseFailures.fetch_add(1, std::memory_order_relaxed);
        return history;
    }

    while (query.Next()) {
        history.push_back(LoadResultFromRow(query));
    }
    return history;
}

EmailAnalyzerStatistics EmailAnalyzer::GetStatistics() const noexcept {
    EmailAnalyzerStatistics statistics;
    statistics.totalScans = m_impl->totalScans.load(std::memory_order_relaxed);
    statistics.suspiciousScans = m_impl->suspiciousScans.load(std::memory_order_relaxed);
    statistics.phishingScans = m_impl->phishingScans.load(std::memory_order_relaxed);
    statistics.maliciousScans = m_impl->maliciousScans.load(std::memory_order_relaxed);
    statistics.totalAttachments = m_impl->totalAttachments.load(std::memory_order_relaxed);
    statistics.totalLinks = m_impl->totalLinks.load(std::memory_order_relaxed);
    statistics.emlFilesParsed = m_impl->emlFilesParsed.load(std::memory_order_relaxed);
    statistics.msgFilesParsed = m_impl->msgFilesParsed.load(std::memory_order_relaxed);
    statistics.persistedResults = m_impl->persistedResults.load(std::memory_order_relaxed);
    statistics.databaseFailures = m_impl->databaseFailures.load(std::memory_order_relaxed);
    return statistics;
}

} // namespace ShadowStrike::Products::PhantomXDR::EmailThreat
