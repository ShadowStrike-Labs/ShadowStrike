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
 * ShadowStrike Core Network - EMAIL SCANNER IMPLEMENTATION
 * ============================================================================
 *
 * @file EmailScanner.cpp
 * @brief Enterprise-grade email security scanning and threat detection.
 *
 * This module provides comprehensive email security through:
 * - MIME parsing with Base64/Quoted-Printable decoding
 * - Malware scanning of attachments (executables, macros, scripts)
 * - Phishing detection (URL analysis, sender spoofing, brand impersonation)
 * - Spam filtering with Bayesian-style scoring
 * - Business Email Compromise (BEC) detection
 * - Data Loss Prevention (DLP) for PII/financial data
 * - SPF/DKIM/DMARC authentication validation
 * - Protocol parsing for SMTP, IMAP, POP3
 *
 * Integration:
 * - FileTypeAnalyzer: File type verification and spoofing detection
 * - ExecutableAnalyzer: PE/ELF binary analysis
 * - PatternStore: Phishing/malware pattern matching
 * - ThreatIntel: Domain/IP reputation lookups
 * - Whitelist: Trusted sender verification
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "EmailScanner.hpp"

// Infrastructure includes
#include "../../Utils/Logger.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../Utils/Base64Utils.hpp"
#include "../FileSystem/FileTypeAnalyzer.hpp"
#include "../FileSystem/ExecutableAnalyzer.hpp"
#include "../FileSystem/ArchiveExtractor.hpp"

// Standard library
#include <algorithm>
#include <cctype>
#include <regex>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <condition_variable>
#include <thread>
#include <mutex>
#include <random>

#include <Windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

namespace ShadowStrike {
namespace Core {
namespace Network {

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

/**
 * @brief Base64 decoding — delegates to enterprise Base64Utils.
 */
std::vector<uint8_t> Base64Decode(std::string_view input) {
    std::vector<uint8_t> result;
    ShadowStrike::Utils::Base64DecodeError err{};
    ShadowStrike::Utils::Base64DecodeOptions opts;
    opts.ignoreWhitespace = true;
    opts.acceptMissingPadding = true;
    if (!ShadowStrike::Utils::Base64Decode(input, result, err, opts)) {
        return {};
    }
    return result;
}

/**
 * @brief Quoted-Printable decoding (RFC 2045 §6.7) — bounded, locale-independent.
 *
 * Decodes "=XX" hex escapes only when both characters are hex digits, so an
 * attacker cannot smuggle arbitrary bytes via locale-dependent strtol parsing
 * of high-bit input. Soft line breaks (=CRLF, =LF) are silently dropped.
 */
std::string QuotedPrintableDecode(std::string_view input) {
    static constexpr auto hexVal = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };

    std::string result;
    result.reserve(input.size());

    const size_t n = input.size();
    for (size_t i = 0; i < n; ++i) {
        if (input[i] == '=' && i + 2 < n) {
            // Soft line break: "=\r\n" or "=\n"
            if (input[i + 1] == '\r' && input[i + 2] == '\n') {
                i += 2;
                continue;
            }
            if (input[i + 1] == '\n') {
                i += 1;
                continue;
            }

            const int hi = hexVal(input[i + 1]);
            const int lo = hexVal(input[i + 2]);
            if (hi >= 0 && lo >= 0) {
                result.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
            // Malformed escape — emit '=' literally as RFC permits.
        } else if (input[i] == '=' && i + 1 == n - 1 && input[i + 1] == '\n') {
            // Trailing soft break with bare LF at very end
            ++i;
            continue;
        }
        result.push_back(input[i]);
    }

    return result;
}

// ============================================================================
// MIME PARSING CONSTANTS & HELPERS
// ============================================================================

// Security limits for MIME parsing
constexpr size_t kMaxMultipartNestingDepth = 10;
constexpr size_t kMaxMIMEPartCount         = 256;
constexpr size_t kMaxArchiveEntryCount     = 1024;
constexpr size_t kMaxArchiveExtractionSize = 64 * 1024 * 1024;  // 64 MB
constexpr size_t kMaxSingleAttachmentSize  = 128 * 1024 * 1024; // 128 MB
constexpr size_t kMaxHeaderLineLength      = 8192;
constexpr size_t kMaxEncodedWordLength     = 2048;

// Hard caps to prevent header parsing DoS
constexpr size_t kMaxHeaderTotalSize       = 256 * 1024;        // 256 KB total headers
constexpr size_t kMaxHeaderCount           = 1000;              // Max distinct header lines
constexpr size_t kMaxHeaderValueLength     = 16 * 1024;         // 16 KB per header value
constexpr size_t kMaxReceivedHeaders       = 64;                // Cap traceroute headers
constexpr size_t kMaxRecipientsPerField    = 1000;              // Cap To/Cc/Bcc lists

// Session DoS protection
constexpr size_t kSessionBufferHardCap     = 100ULL * 1024 * 1024; // 100 MB / session buffer
constexpr size_t kAddressParseInputLimit   = 4096;                  // Per-address parse cap

// Body parsing caps
constexpr size_t kMaxBodyTextRetained      = 4ULL * 1024 * 1024;   // 4 MB plain/html retained

/**
 * @brief Sanitize attacker-controlled strings before logging or alert routing.
 *
 * Strips ASCII control characters (CR, LF, NUL, TAB, ESC, etc.) that would
 * otherwise enable log-line injection (CWE-117) and forensic-trail forgery
 * when an attacker controls Message-ID, Subject, From, or filename fields.
 * Replaces dangerous characters with '?', truncates the result to a hard
 * cap so a malicious 4 GB header cannot cause logger pressure, and is
 * always-noexcept so it is safe inside catch blocks and shutdown paths.
 */
[[nodiscard]] std::string SanitizeForLog(std::string_view input, size_t maxLen = 256) noexcept {
    std::string out;
    const size_t n = (input.size() < maxLen) ? input.size() : maxLen;
    out.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        const unsigned char c = static_cast<unsigned char>(input[i]);
        if (c < 0x20 || c == 0x7F) {
            out.push_back('?');
        } else {
            out.push_back(static_cast<char>(c));
        }
    }
    if (input.size() > maxLen) {
        out.append("...");
    }
    return out;
}

/**
 * @brief Generate a cryptographically random hex token for unique temp file names.
 *
 * Backed by BCryptGenRandom (CNG); avoids predictable-name symlink races
 * (CWE-377) and process-address leakage in temp paths.
 */
[[nodiscard]] std::wstring GenerateRandomToken(size_t bytes = 16) noexcept {
    std::vector<uint8_t> raw(bytes, 0u);
    NTSTATUS st = ::BCryptGenRandom(nullptr, raw.data(), static_cast<ULONG>(raw.size()),
                                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st != 0 /* STATUS_SUCCESS */) {
        // Fallback: time-mixed counter (not cryptographic, but namespaces collisions).
        static std::atomic<uint64_t> counter{ 0 };
        const uint64_t t = static_cast<uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count());
        const uint64_t mix = t ^ counter.fetch_add(1u, std::memory_order_relaxed);
        for (size_t i = 0; i < raw.size(); ++i) {
            raw[i] = static_cast<uint8_t>((mix >> ((i * 8u) % 64u)) & 0xFFu);
        }
    }
    static const wchar_t kHex[] = L"0123456789abcdef";
    std::wstring out(raw.size() * 2u, L'0');
    for (size_t i = 0; i < raw.size(); ++i) {
        out[i * 2u]     = kHex[(raw[i] >> 4) & 0x0Fu];
        out[i * 2u + 1] = kHex[raw[i]        & 0x0Fu];
    }
    return out;
}

// Dangerous archive extensions for risk elevation
static const std::array<std::string_view, 14> kDangerousArchiveExtensions = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1",
    ".vbs", ".js",  ".hta", ".wsf", ".msi", ".com",
    ".pif", ".cpl"
};

/**
 * @brief RFC 2047 encoded-word decoder.
 * Handles =?charset?encoding?text?= tokens in MIME headers.
 * Supports B (base64) and Q (quoted-printable variant) encodings.
 */
std::string DecodeRFC2047EncodedWord(const std::string& input) {
    std::string result;
    result.reserve(input.size());

    size_t pos = 0;
    while (pos < input.size()) {
        size_t startToken = input.find("=?", pos);
        if (startToken == std::string::npos) {
            result.append(input, pos, std::string::npos);
            break;
        }

        // Append text before the encoded-word
        result.append(input, pos, startToken - pos);

        // Parse =?charset?encoding?text?=
        size_t charsetEnd = input.find('?', startToken + 2);
        if (charsetEnd == std::string::npos || charsetEnd - startToken > kMaxEncodedWordLength) {
            result.append("=?");
            pos = startToken + 2;
            continue;
        }

        size_t encodingEnd = input.find('?', charsetEnd + 1);
        if (encodingEnd == std::string::npos || encodingEnd - charsetEnd > 3) {
            result.append("=?");
            pos = startToken + 2;
            continue;
        }

        size_t textEnd = input.find("?=", encodingEnd + 1);
        if (textEnd == std::string::npos || textEnd - startToken > kMaxEncodedWordLength) {
            result.append("=?");
            pos = startToken + 2;
            continue;
        }

        const char encoding = input[charsetEnd + 1];
        std::string encodedText = input.substr(encodingEnd + 1, textEnd - (encodingEnd + 1));

        if (encoding == 'B' || encoding == 'b') {
            // Base64 encoding
            auto decoded = Base64Decode(encodedText);
            result.append(reinterpret_cast<const char*>(decoded.data()), decoded.size());
        } else if (encoding == 'Q' || encoding == 'q') {
            // Q-encoding: like quoted-printable but underscore = space
            static constexpr auto qHexVal = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            std::string qDecoded;
            qDecoded.reserve(encodedText.size());
            for (size_t i = 0; i < encodedText.size(); ++i) {
                if (encodedText[i] == '_') {
                    qDecoded += ' ';
                } else if (encodedText[i] == '=' && i + 2 < encodedText.size()) {
                    const int hi = qHexVal(encodedText[i + 1]);
                    const int lo = qHexVal(encodedText[i + 2]);
                    if (hi >= 0 && lo >= 0) {
                        qDecoded += static_cast<char>((hi << 4) | lo);
                        i += 2;
                    } else {
                        qDecoded += encodedText[i];
                    }
                } else {
                    qDecoded += encodedText[i];
                }
            }
            result.append(qDecoded);
        } else {
            // Unknown encoding — preserve raw
            result.append(input, startToken, textEnd + 2 - startToken);
        }

        pos = textEnd + 2;
    }

    return result;
}

/**
 * @brief Unfold RFC 5322 header continuation lines.
 * Lines starting with SP/HTAB are continuations of the previous header.
 */
std::string UnfoldHeaders(std::string_view raw) {
    std::string result;
    result.reserve(raw.size());

    for (size_t i = 0; i < raw.size(); ++i) {
        if (raw[i] == '\r' && i + 1 < raw.size() && raw[i + 1] == '\n') {
            // Check if next line is a continuation (starts with SP or HTAB)
            if (i + 2 < raw.size() && (raw[i + 2] == ' ' || raw[i + 2] == '\t')) {
                result += ' ';
                i += 2; // skip \r\n and the leading whitespace
                // Skip additional whitespace
                while (i + 1 < raw.size() && (raw[i + 1] == ' ' || raw[i + 1] == '\t')) {
                    ++i;
                }
                continue;
            }
        } else if (raw[i] == '\n') {
            // Bare LF (non-standard but encountered in wild)
            if (i + 1 < raw.size() && (raw[i + 1] == ' ' || raw[i + 1] == '\t')) {
                result += ' ';
                i += 1;
                while (i + 1 < raw.size() && (raw[i + 1] == ' ' || raw[i + 1] == '\t')) {
                    ++i;
                }
                continue;
            }
        }
        result += raw[i];
    }

    return result;
}

/**
 * @brief Extract a parameter value from a MIME header value string.
 * e.g., from 'multipart/mixed; boundary="abc"' extracts "abc" for param "boundary".
 * Supports RFC 5987 extended parameters (e.g., filename*=UTF-8''encoded%20name).
 */
std::string ExtractMIMEParameter(const std::string& headerValue, const std::string& paramName) {
    // First try RFC 5987 extended parameter (paramName*)
    std::string extName = paramName + "*=";
    size_t extPos = headerValue.find(extName);
    if (extPos != std::string::npos) {
        std::string extVal = headerValue.substr(extPos + extName.size());
        size_t end = extVal.find_first_of(";\r\n");
        if (end != std::string::npos) extVal = extVal.substr(0, end);

        // Format: charset'language'encoded_value
        size_t firstQuote = extVal.find('\'');
        size_t secondQuote = (firstQuote != std::string::npos) ?
            extVal.find('\'', firstQuote + 1) : std::string::npos;

        if (secondQuote != std::string::npos) {
            std::string percentEncoded = extVal.substr(secondQuote + 1);
            // Percent-decode (RFC 5987) — locale-independent hex parsing.
            static constexpr auto pctHex = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            std::string decoded;
            decoded.reserve(percentEncoded.size());
            for (size_t i = 0; i < percentEncoded.size(); ++i) {
                if (percentEncoded[i] == '%' && i + 2 < percentEncoded.size()) {
                    const int hi = pctHex(percentEncoded[i + 1]);
                    const int lo = pctHex(percentEncoded[i + 2]);
                    if (hi >= 0 && lo >= 0) {
                        decoded += static_cast<char>((hi << 4) | lo);
                        i += 2;
                        continue;
                    }
                }
                decoded += percentEncoded[i];
            }
            return decoded;
        }
    }

    // Standard parameter
    std::string stdName = paramName + "=";
    size_t pos = headerValue.find(stdName);
    if (pos == std::string::npos) return {};

    std::string val = headerValue.substr(pos + stdName.size());

    // Trim leading whitespace
    size_t startTrim = val.find_first_not_of(" \t");
    if (startTrim != std::string::npos && startTrim > 0) {
        val = val.substr(startTrim);
    }

    if (!val.empty() && val.front() == '"') {
        // Quoted string
        size_t closeQuote = val.find('"', 1);
        if (closeQuote != std::string::npos) {
            return val.substr(1, closeQuote - 1);
        }
        return val.substr(1);
    }

    // Unquoted — terminated by semicolon or whitespace
    size_t end = val.find_first_of("; \t\r\n");
    if (end != std::string::npos) {
        return val.substr(0, end);
    }
    return val;
}

/**
 * @brief Check if a filename extension is dangerous (executable content).
 */
bool IsDangerousExtension(const std::string& filename) {
    size_t dotPos = filename.rfind('.');
    if (dotPos == std::string::npos) return false;

    std::string ext = filename.substr(dotPos);
    // Case-insensitive comparison
    for (auto& c : ext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    for (const auto& dangerous : kDangerousArchiveExtensions) {
        if (ext == dangerous) return true;
    }
    return false;
}

/**
 * @brief Extract email address from RFC 5322 format.
 *
 * Hardened against ReDoS via input length cap and locale-stable normalization.
 * Treats inputs above kAddressParseInputLimit as invalid (would otherwise
 * trigger catastrophic backtracking in the regex engine on a malicious
 * 1 MB Display-Name).
 */
EmailAddress ParseEmailAddress(const std::string& input) {
    EmailAddress addr;

    if (input.empty() || input.size() > kAddressParseInputLimit) {
        return addr;
    }

    // Pattern: "Display Name" <local@domain> or local@domain
    static const std::regex emailRegex(
        R"((?:([^<]*?)\s*<)?([a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+)@([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*)>?)"
    );

    std::smatch match;
    try {
        if (std::regex_search(input, match, emailRegex)) {
            addr.displayName = match[1].str();
            addr.localPart = match[2].str();
            addr.domain = match[3].str();
            addr.fullAddress = addr.localPart + "@" + addr.domain;
            addr.isValid = true;

            // Trim display name
            if (!addr.displayName.empty()) {
                addr.displayName.erase(0, addr.displayName.find_first_not_of(" \t\""));
                const auto endPos = addr.displayName.find_last_not_of(" \t\"");
                if (endPos != std::string::npos) {
                    addr.displayName.erase(endPos + 1);
                } else {
                    addr.displayName.clear();
                }
            }

            // Check domain validity
            addr.isDomainValid = !addr.domain.empty() && addr.domain.find('.') != std::string::npos;

            // Check display name mismatch (phishing indicator) using ASCII-safe lowering.
            if (!addr.displayName.empty()) {
                std::string lowerDisplay = addr.displayName;
                std::string lowerDomain  = addr.domain;
                std::transform(lowerDisplay.begin(), lowerDisplay.end(), lowerDisplay.begin(),
                    [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
                std::transform(lowerDomain.begin(), lowerDomain.end(), lowerDomain.begin(),
                    [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });

                if (lowerDisplay.find('@') != std::string::npos &&
                    lowerDisplay.find(lowerDomain) == std::string::npos) {
                    addr.hasDisplayNameMismatch = true;
                }
            }
        }
    } catch (const std::regex_error&) {
        // Defensive: regex implementations may throw on pathological input.
        addr = EmailAddress{};
    }

    return addr;
}

[[nodiscard]] std::string ToLowerASCII(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

std::string NormalizeEmail(std::string_view input) {
    auto parsed = ParseEmailAddress(std::string(input));
    std::string normalized = parsed.localPart;
    if (!parsed.domain.empty()) {
        if (!normalized.empty()) {
            normalized.push_back('@');
        }
        normalized += parsed.domain;
    }
    if (normalized.empty()) {
        normalized.assign(input.begin(), input.end());
    }

    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return normalized;
}

[[nodiscard]] std::vector<std::string> DetectHTMLExploits(std::string_view html) {
    std::vector<std::string> findings;
    if (html.empty()) {
        return findings;
    }

    const auto lowerHtml = ToLowerASCII(std::string(html));
    const auto addFinding = [&findings](const char* finding) {
        const std::string value(finding);
        if (std::find(findings.begin(), findings.end(), value) == findings.end()) {
            findings.emplace_back(value);
        }
    };

    if (lowerHtml.find("<script") != std::string::npos) {
        addFinding("HTML body contains script tag");
    }
    if (lowerHtml.find("javascript:") != std::string::npos) {
        addFinding("HTML body contains javascript URI");
    }
    if (lowerHtml.find("data:text/html") != std::string::npos ||
        lowerHtml.find("data:application") != std::string::npos) {
        addFinding("HTML body contains inline data URI payload");
    }
    if (lowerHtml.find("onload=") != std::string::npos ||
        lowerHtml.find("onerror=") != std::string::npos ||
        lowerHtml.find("onclick=") != std::string::npos) {
        addFinding("HTML body contains inline event handler");
    }
    if (lowerHtml.find("<iframe") != std::string::npos ||
        lowerHtml.find("<object") != std::string::npos ||
        lowerHtml.find("<embed") != std::string::npos) {
        addFinding("HTML body contains active embedded content");
    }

    return findings;
}

[[nodiscard]] bool ContainsEicar(std::span<const uint8_t> data) {
    if (data.empty()) {
        return false;
    }

    constexpr std::string_view kEicar =
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    const std::string content(reinterpret_cast<const char*>(data.data()), data.size());
    return content.find(kEicar) != std::string::npos;
}

[[nodiscard]] bool ContainsOLEObject(std::span<const uint8_t> data) {
    static constexpr uint8_t kOleHeader[] = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
    return data.size() >= std::size(kOleHeader) &&
        std::equal(std::begin(kOleHeader), std::end(kOleHeader), data.begin());
}

[[nodiscard]] bool HasRTLOCharacter(std::string_view fileName) {
    return fileName.find("\xE2\x80\xAE") != std::string_view::npos;
}

[[nodiscard]] bool HasDoubleExtension(std::string_view fileName) {
    const auto firstDot = fileName.find('.');
    if (firstDot == std::string_view::npos) {
        return false;
    }

    const auto lastDot = fileName.rfind('.');
    if (lastDot == std::string_view::npos || firstDot == lastDot || lastDot + 1 >= fileName.size()) {
        return false;
    }

    const auto secondExt = ToLowerASCII(std::string(fileName.substr(lastDot + 1)));
    static const std::array<std::string_view, 12> kExecutableExts = {
        "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "ps1", "hta"
    };
    for (const auto candidate : kExecutableExts) {
        if (secondExt == candidate) {
            return true;
        }
    }
    return false;
}

/**
 * @brief Extract URLs from text content.
 */
std::vector<std::string> ExtractURLs(const std::string& content) {
    std::vector<std::string> urls;

    // Pattern for URLs
    static const std::regex urlRegex(
        R"((https?|ftp)://[^\s<>"{}|\\^`\[\]]+)",
        std::regex::icase
    );

    auto wordsBegin = std::sregex_iterator(content.begin(), content.end(), urlRegex);
    auto wordsEnd = std::sregex_iterator();

    for (std::sregex_iterator i = wordsBegin; i != wordsEnd; ++i) {
        std::smatch match = *i;
        urls.push_back(match.str());
        if (urls.size() >= EmailScannerConstants::MAX_URLS_PER_EMAIL) {
            break;
        }
    }

    return urls;
}

/**
 * @brief Calculate Levenshtein distance for brand impersonation detection.
 */
size_t LevenshteinDistance(std::string_view s1, std::string_view s2) {
    const size_t len1 = s1.size();
    const size_t len2 = s2.size();

    std::vector<std::vector<size_t>> d(len1 + 1, std::vector<size_t>(len2 + 1));

    for (size_t i = 0; i <= len1; ++i) d[i][0] = i;
    for (size_t j = 0; j <= len2; ++j) d[0][j] = j;

    for (size_t i = 1; i <= len1; ++i) {
        for (size_t j = 1; j <= len2; ++j) {
            const size_t cost = (s1[i - 1] == s2[j - 1]) ? 0 : 1;
            d[i][j] = std::min({
                d[i - 1][j] + 1,      // deletion
                d[i][j - 1] + 1,      // insertion
                d[i - 1][j - 1] + cost // substitution
            });
        }
    }

    return d[len1][len2];
}

/**
 * @brief Known brands for impersonation detection.
 */
const std::vector<std::string> g_knownBrands = {
    "paypal", "amazon", "microsoft", "google", "apple", "facebook",
    "linkedin", "twitter", "instagram", "netflix", "ebay", "dropbox",
    "adobe", "salesforce", "office365", "outlook", "gmail", "yahoo",
    "bank", "chase", "wellsfargo", "bankofamerica", "citibank"
};

/**
 * @brief Urgency keywords for phishing detection.
 */
const std::vector<std::string> g_urgencyKeywords = {
    "urgent", "immediate", "action required", "verify", "suspended",
    "locked", "expired", "confirm", "alert", "warning", "security",
    "unauthorized", "unusual activity", "click here", "act now",
    "limited time", "within 24 hours", "account will be closed"
};

/**
 * @brief Credential request keywords.
 */
const std::vector<std::string> g_credentialKeywords = {
    "password", "username", "login", "credential", "social security",
    "ssn", "credit card", "account number", "pin", "security code",
    "cvv", "routing number", "bank account", "verify identity"
};

/**
 * @brief Spam indicator keywords.
 */
const std::vector<std::string> g_spamKeywords = {
    "free", "winner", "congratulations", "claim", "prize", "lottery",
    "million dollars", "nigerian prince", "inheritance", "forex",
    "weight loss", "viagra", "cialis", "pharmacy", "casino",
    "click here now", "limited offer", "act fast", "bonus"
};

/**
 * @brief PII regex patterns for DLP.
 */
struct DLPPattern {
    std::regex pattern;
    std::string dataType;
    uint8_t severity;
};

const std::vector<DLPPattern> g_dlpPatterns = {
    // Credit card (basic pattern)
    {std::regex(R"(\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b)"), "Credit Card", 9},

    // SSN
    {std::regex(R"(\b\d{3}-\d{2}-\d{4}\b)"), "SSN", 10},

    // Email addresses (for data exfiltration)
    {std::regex(R"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)"), "Email Address", 3},

    // Phone numbers
    {std::regex(R"(\b\d{3}[-.]?\d{3}[-.]?\d{4}\b)"), "Phone Number", 4},
};

} // anonymous namespace

// ============================================================================
// CONFIGURATION STATIC METHODS
// ============================================================================

EmailScannerConfig EmailScannerConfig::CreateDefault() noexcept {
    EmailScannerConfig config;
    // Defaults already set in struct
    return config;
}

EmailScannerConfig EmailScannerConfig::CreateHighSecurity() noexcept {
    EmailScannerConfig config;
    config.enableMalwareScanning = true;
    config.enablePhishingDetection = true;
    config.enableSpamFiltering = true;
    config.enableDLP = true;
    config.enableBECDetection = true;
    config.enableAuthValidation = true;

    config.scanAttachments = true;
    config.extractArchives = true;
    config.sandboxExecutables = true;
    config.maxArchiveDepth = 5;

    config.scanURLs = true;

    config.spamThreshold = 0.6;
    config.phishingThreshold = 0.5;
    config.becThreshold = 0.4;

    config.malwareAction = EmailAction::BLOCK;
    config.phishingAction = EmailAction::BLOCK;
    config.spamAction = EmailAction::QUARANTINE;

    config.logThreatsOnly = true;
    config.retainEmailContent = false;

    return config;
}

EmailScannerConfig EmailScannerConfig::CreatePerformance() noexcept {
    EmailScannerConfig config;
    config.enableMalwareScanning = true;
    config.enablePhishingDetection = true;
    config.enableSpamFiltering = false;
    config.enableDLP = false;
    config.enableBECDetection = false;
    config.enableAuthValidation = false;

    config.scanAttachments = true;
    config.extractArchives = false;
    config.sandboxExecutables = false;

    config.scanURLs = true;
    config.maxURLsToScan = 50;

    config.workerThreads = 8;
    config.logThreatsOnly = true;

    return config;
}

EmailScannerConfig EmailScannerConfig::CreateForensic() noexcept {
    EmailScannerConfig config = CreateHighSecurity();

    config.logAllEmails = true;
    config.logThreatsOnly = false;
    config.retainEmailContent = true;

    return config;
}

// ============================================================================
// STATISTICS IMPLEMENTATION
// ============================================================================

void EmailScannerStatistics::Reset() noexcept {
    totalPacketsProcessed.store(0, std::memory_order_relaxed);
    totalBytesProcessed.store(0, std::memory_order_relaxed);
    totalEmailsScanned.store(0, std::memory_order_relaxed);

    activeSessions.store(0, std::memory_order_relaxed);
    totalSessions.store(0, std::memory_order_relaxed);
    sessionsTimedOut.store(0, std::memory_order_relaxed);

    smtpEmails.store(0, std::memory_order_relaxed);
    imapEmails.store(0, std::memory_order_relaxed);
    pop3Emails.store(0, std::memory_order_relaxed);

    malwareDetected.store(0, std::memory_order_relaxed);
    phishingDetected.store(0, std::memory_order_relaxed);
    spamDetected.store(0, std::memory_order_relaxed);
    becDetected.store(0, std::memory_order_relaxed);
    dlpViolations.store(0, std::memory_order_relaxed);

    attachmentsScanned.store(0, std::memory_order_relaxed);
    maliciousAttachments.store(0, std::memory_order_relaxed);
    archivesExtracted.store(0, std::memory_order_relaxed);

    urlsScanned.store(0, std::memory_order_relaxed);
    maliciousUrls.store(0, std::memory_order_relaxed);
    phishingUrls.store(0, std::memory_order_relaxed);

    emailsBlocked.store(0, std::memory_order_relaxed);
    emailsQuarantined.store(0, std::memory_order_relaxed);
    attachmentsStripped.store(0, std::memory_order_relaxed);

    avgScanTimeUs.store(0, std::memory_order_relaxed);
    maxScanTimeUs.store(0, std::memory_order_relaxed);
}

// ============================================================================
// CALLBACK MANAGER
// ============================================================================

class CallbackManager {
public:
    uint64_t RegisterAnalysis(EmailAnalysisCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_analysisCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterAlert(EmailAlertCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_alertCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterAttachment(AttachmentCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_attachmentCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterPhishing(PhishingCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_phishingCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterMalware(MalwareCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_malwareCallbacks[id] = std::move(callback);
        return id;
    }

    bool Unregister(uint64_t id) {
        std::unique_lock lock(m_mutex);

        if (m_analysisCallbacks.erase(id)) return true;
        if (m_alertCallbacks.erase(id)) return true;
        if (m_attachmentCallbacks.erase(id)) return true;
        if (m_phishingCallbacks.erase(id)) return true;
        if (m_malwareCallbacks.erase(id)) return true;

        return false;
    }

    void InvokeAnalysis(const EmailAnalysis& analysis) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_analysisCallbacks) {
            try {
                callback(analysis);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"EmailScanner: Analysis callback exception: %hs", e.what());
            }
        }
    }

    void InvokeAlert(const EmailAlert& alert) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_alertCallbacks) {
            try {
                callback(alert);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"EmailScanner: Alert callback exception: %hs", e.what());
            }
        }
    }

    void InvokeAttachment(uint64_t emailId, const AttachmentInfo& attachment) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_attachmentCallbacks) {
            try {
                callback(emailId, attachment);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"EmailScanner: Attachment callback exception: %hs", e.what());
            }
        }
    }

    void InvokePhishing(uint64_t emailId, const PhishingAnalysis& analysis) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_phishingCallbacks) {
            try {
                callback(emailId, analysis);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"EmailScanner: Phishing callback exception: %hs", e.what());
            }
        }
    }

    void InvokeMalware(uint64_t emailId, ThreatType threat, const std::string& signature) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_malwareCallbacks) {
            try {
                callback(emailId, threat, signature);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"EmailScanner: Malware callback exception: %hs", e.what());
            }
        }
    }

private:
    mutable std::shared_mutex m_mutex;
    uint64_t m_nextId{ 1 };
    std::unordered_map<uint64_t, EmailAnalysisCallback> m_analysisCallbacks;
    std::unordered_map<uint64_t, EmailAlertCallback> m_alertCallbacks;
    std::unordered_map<uint64_t, AttachmentCallback> m_attachmentCallbacks;
    std::unordered_map<uint64_t, PhishingCallback> m_phishingCallbacks;
    std::unordered_map<uint64_t, MalwareCallback> m_malwareCallbacks;
};

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class EmailScannerImpl {
public:
    EmailScannerImpl() = default;
    ~EmailScannerImpl() {
        Stop();
    }

    // Prevent copying
    EmailScannerImpl(const EmailScannerImpl&) = delete;
    EmailScannerImpl& operator=(const EmailScannerImpl&) = delete;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    bool Initialize(const EmailScannerConfig& config) {
        std::unique_lock lock(m_mutex);

        try {
            SS_LOG_INFO(L"Network", L"EmailScanner: Initializing...");

            m_config = config;

            // Validate configuration bounds — defensive against caller error.
            if (m_config.workerThreads == 0) {
                m_config.workerThreads = 1;
            }
            if (m_config.workerThreads > 64) {
                m_config.workerThreads = 64;
            }
            if (m_config.maxActiveSessionsCount == 0) {
                m_config.maxActiveSessionsCount = 1;
            }
            if (m_config.maxActiveSessionsCount > EmailScannerConstants::MAX_ACTIVE_SESSIONS) {
                m_config.maxActiveSessionsCount = EmailScannerConstants::MAX_ACTIVE_SESSIONS;
            }
            if (m_config.sessionTimeoutMs == 0) {
                m_config.sessionTimeoutMs = EmailScannerConstants::SESSION_TIMEOUT_MS;
            }
            if (m_config.maxAttachmentSize == 0 ||
                m_config.maxAttachmentSize > kMaxSingleAttachmentSize) {
                m_config.maxAttachmentSize = kMaxSingleAttachmentSize;
            }
            if (m_config.maxArchiveDepth > 32) {
                m_config.maxArchiveDepth = 32;
            }
            if (m_config.maxURLsToScan == 0 ||
                m_config.maxURLsToScan > EmailScannerConstants::MAX_URLS_PER_EMAIL) {
                m_config.maxURLsToScan = EmailScannerConstants::MAX_URLS_PER_EMAIL;
            }

            // Initialize callback manager
            m_callbackManager = std::make_unique<CallbackManager>();

            // Verify infrastructure
            if (!FileSystem::FileTypeAnalyzer::Instance().Initialize(
                FileSystem::FileTypeAnalyzerConfig::CreateDefault())) {
                SS_LOG_WARN(L"Network", L"EmailScanner: FileTypeAnalyzer initialization warning");
            }

            if (!FileSystem::ExecutableAnalyzer::Instance().Initialize()) {
                SS_LOG_WARN(L"Network", L"EmailScanner: ExecutableAnalyzer initialization warning");
            }

            // Seed whitelist sets from configuration. Senders are normalized to
            // lowercase local@domain; standalone domains are kept in a dedicated
            // set so IsWhitelisted() can match by domain without colliding with
            // user@domain entries.
            {
                std::unique_lock wlock(m_whitelistMutex);
                m_whitelist.clear();
                m_whitelistDomains.clear();
                for (const auto& entry : m_config.whitelistedSenders) {
                    if (entry.empty()) continue;
                    m_whitelist.insert(NormalizeEmail(entry));
                }
                for (const auto& dom : m_config.whitelistedDomains) {
                    if (dom.empty()) continue;
                    std::string d = dom;
                    std::transform(d.begin(), d.end(), d.begin(),
                        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
                    m_whitelistDomains.insert(std::move(d));
                }
            }

            m_initialized = true;
            SS_LOG_INFO(L"Network", L"EmailScanner: Initialized successfully");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"EmailScanner: Initialization failed: %hs", e.what());
            return false;
        }
    }

    bool Start() {
        std::unique_lock lock(m_mutex);

        if (!m_initialized) {
            SS_LOG_ERROR(L"Network", L"EmailScanner: Not initialized");
            return false;
        }

        if (m_running) {
            SS_LOG_WARN(L"Network", L"EmailScanner: Already running");
            return true;
        }

        try {
            m_running = true;

            // Start worker threads
            for (uint32_t i = 0; i < m_config.workerThreads; ++i) {
                m_workers.emplace_back([this]() { WorkerThread(); });
            }

            SS_LOG_INFO(L"Network", L"EmailScanner: Started with %u worker threads", m_config.workerThreads);
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"EmailScanner: Start failed: %hs", e.what());
            m_running = false;
            return false;
        }
    }

    void Stop() {
        {
            std::unique_lock lock(m_mutex);
            if (!m_running) return;

            SS_LOG_INFO(L"Network", L"EmailScanner: Stopping...");
            m_running = false;
        }

        m_cv.notify_all();

        // Wait for workers
        for (auto& worker : m_workers) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        m_workers.clear();

        SS_LOG_INFO(L"Network", L"EmailScanner: Stopped");
    }

    void Shutdown() noexcept {
        Stop();
        std::unique_lock lock(m_mutex);
        m_initialized = false;
        m_sessions.clear();
        SS_LOG_INFO(L"Network", L"EmailScanner: Shutdown complete");
    }

    bool IsRunning() const noexcept {
        return m_running.load(std::memory_order_acquire);
    }

    // ========================================================================
    // PACKET PROCESSING
    // ========================================================================

    void FeedPacket(std::span<const uint8_t> data, const std::string& srcIP,
                   uint16_t srcPort, const std::string& dstIP, uint16_t dstPort) {
        if (!m_running.load(std::memory_order_acquire) || data.empty()) {
            return;
        }

        try {
            m_stats.totalPacketsProcessed.fetch_add(1, std::memory_order_relaxed);
            m_stats.totalBytesProcessed.fetch_add(data.size(), std::memory_order_relaxed);

            // Determine protocol from port
            EmailProtocol protocol = EmailProtocol::UNKNOWN;
            if (dstPort == EmailScannerConstants::PORT_SMTP || srcPort == EmailScannerConstants::PORT_SMTP) {
                protocol = EmailProtocol::SMTP;
            } else if (dstPort == EmailScannerConstants::PORT_SMTPS || srcPort == EmailScannerConstants::PORT_SMTPS) {
                protocol = EmailProtocol::SMTPS;
            } else if (dstPort == EmailScannerConstants::PORT_IMAP || srcPort == EmailScannerConstants::PORT_IMAP) {
                protocol = EmailProtocol::IMAP;
            } else if (dstPort == EmailScannerConstants::PORT_IMAPS || srcPort == EmailScannerConstants::PORT_IMAPS) {
                protocol = EmailProtocol::IMAPS;
            } else if (dstPort == EmailScannerConstants::PORT_POP3 || srcPort == EmailScannerConstants::PORT_POP3) {
                protocol = EmailProtocol::POP3;
            } else if (dstPort == EmailScannerConstants::PORT_POP3S || srcPort == EmailScannerConstants::PORT_POP3S) {
                protocol = EmailProtocol::POP3S;
            }

            if (protocol == EmailProtocol::UNKNOWN) {
                return;
            }

            // Build a stable canonical session key.
            const std::string sessionKey = srcIP + ":" + std::to_string(srcPort) + "-" +
                                          dstIP + ":" + std::to_string(dstPort);

            // ----- Critical section #1: append to session buffer -----
            // We do NOT call ScanEmail under m_sessionMutex because email
            // scanning is CPU- and I/O-heavy (regex, hashing, archive
            // extraction) and would otherwise serialize the entire session
            // table. Instead we extract framed messages here, drop the lock,
            // then scan the framed payload.
            std::vector<std::vector<uint8_t>> framedMessages;
            EmailProtocol framedProto = protocol;

            {
                std::unique_lock lock(m_sessionMutex);

                auto it = m_sessionMap.find(sessionKey);
                if (it == m_sessionMap.end()) {
                    // Reject new sessions if the active table is at capacity.
                    if (m_sessions.size() >= m_config.maxActiveSessionsCount) {
                        SS_LOG_WARN(L"Network",
                            L"EmailScanner::FeedPacket: active session cap reached (%zu); dropping new flow",
                            m_sessions.size());
                        return;
                    }

                    const uint64_t sessionId = m_nextSessionId.fetch_add(1u, std::memory_order_relaxed);
                    EmailSession session;
                    session.sessionId   = sessionId;
                    session.protocol    = protocol;
                    session.clientIP    = srcIP;
                    session.clientPort  = srcPort;
                    session.serverIP    = dstIP;
                    session.serverPort  = dstPort;
                    session.startTime   = std::chrono::system_clock::now();
                    session.lastActivity = session.startTime;

                    m_sessions.emplace(sessionId, std::move(session));
                    auto inserted = m_sessionMap.emplace(sessionKey, sessionId);
                    it = inserted.first;
                    m_stats.totalSessions.fetch_add(1, std::memory_order_relaxed);
                    m_stats.activeSessions.fetch_add(1, std::memory_order_relaxed);
                }

                const uint64_t sessionId = it->second;
                auto sessIt = m_sessions.find(sessionId);
                if (sessIt == m_sessions.end()) {
                    // Stale map entry — drop and bail.
                    m_sessionMap.erase(it);
                    return;
                }
                EmailSession& session = sessIt->second;

                // DoS guard: cap per-session reassembly buffer.
                const size_t hardCap = (std::min)(kSessionBufferHardCap,
                    static_cast<size_t>(EmailScannerConstants::MAX_EMAIL_SIZE) * 4u);
                if (session.buffer.size() + data.size() > hardCap) {
                    SS_LOG_WARN(L"Network",
                        L"EmailScanner::FeedPacket: session %llu buffer cap exceeded; resetting",
                        static_cast<unsigned long long>(session.sessionId));
                    session.buffer.clear();
                    session.buffer.shrink_to_fit();
                    if (data.size() > hardCap) {
                        return;
                    }
                }

                session.buffer.insert(session.buffer.end(), data.begin(), data.end());
                session.lastActivity = std::chrono::system_clock::now();
                session.bytesTransferred += data.size();

                // Frame any complete messages out of the session buffer; the
                // returned blobs are owned and can be scanned without the lock.
                framedProto = session.protocol;
                framedMessages = ExtractFramedMessages(session);
            }

            // ----- Outside the lock: scan each framed message. -----
            for (auto& blob : framedMessages) {
                std::span<const uint8_t> view(blob.data(), blob.size());
                auto analysis    = ScanEmail(view);
                analysis.protocol = framedProto;
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"EmailScanner::FeedPacket: %hs", e.what());
        }
    }

    // ========================================================================
    // EMAIL ANALYSIS
    // ========================================================================

    EmailAnalysis ScanEmail(std::span<const uint8_t> emailData) {
        const auto startTime = std::chrono::high_resolution_clock::now();

        EmailAnalysis analysis;
        analysis.analysisId = m_nextAnalysisId.fetch_add(1, std::memory_order_relaxed);
        analysis.scannedAt = std::chrono::system_clock::now();
        analysis.emailSize = emailData.size();

        try {
            // Parse headers
            auto [headerEnd, headerData] = ExtractHeaders(emailData);
            analysis.header = ParseHeadersImpl(headerData);
            analysis.messageId = analysis.header.messageId;

            // Determine direction
            analysis.direction = DetermineDirection(analysis.header);

            // Check whitelist
            if (IsWhitelisted(analysis.header.from.fullAddress)) {
                analysis.result = ScanResult::CLEAN;
                analysis.action = EmailAction::ALLOW;

                const auto endTime = std::chrono::high_resolution_clock::now();
                analysis.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);

                m_stats.totalEmailsScanned.fetch_add(1, std::memory_order_relaxed);
                return analysis;
            }

            // Parse body
            if (headerEnd < emailData.size()) {
                auto bodyData = emailData.subspan(headerEnd);
                ParseBody(bodyData, analysis);
            }

            // Scan attachments
            if (m_config.scanAttachments) {
                for (auto& attachment : analysis.attachments) {
                    ScanAttachmentImpl(attachment);
                    m_callbackManager->InvokeAttachment(analysis.analysisId, attachment);

                    if (attachment.riskLevel == AttachmentRisk::CRITICAL ||
                        attachment.riskLevel == AttachmentRisk::BLOCKED) {
                        analysis.threats.push_back(ThreatType::MALWARE_ATTACHMENT);
                        m_stats.maliciousAttachments.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            }

            // Scan URLs
            if (m_config.scanURLs) {
                std::string combinedContent = analysis.bodyText + " " + analysis.bodyHtml;
                analysis.urls = AnalyzeURLsImpl(combinedContent);
            }

            // Phishing detection
            if (m_config.enablePhishingDetection) {
                analysis.phishingAnalysis = AnalyzePhishingImpl(analysis);
                if (analysis.phishingAnalysis.isPhishing) {
                    analysis.threats.push_back(ThreatType::PHISHING_URL);
                    m_stats.phishingDetected.fetch_add(1, std::memory_order_relaxed);
                    m_callbackManager->InvokePhishing(analysis.analysisId, analysis.phishingAnalysis);
                }
            }

            // Spam detection
            if (m_config.enableSpamFiltering) {
                AnalyzeSpam(analysis);
            }

            // BEC detection
            if (m_config.enableBECDetection) {
                AnalyzeBEC(analysis);
            }

            // DLP scanning
            if (m_config.enableDLP) {
                AnalyzeDLP(analysis);
            }

            // Authentication validation
            if (m_config.enableAuthValidation) {
                analysis.authResults = ParseAuthenticationResults(analysis.header);
            }

            // Calculate threat score and determine action
            CalculateThreatScore(analysis);
            DetermineAction(analysis);

            // Create alerts
            if (analysis.result != ScanResult::CLEAN) {
                CreateAlerts(analysis);
            }

            // Update statistics
            const auto endTime = std::chrono::high_resolution_clock::now();
            analysis.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);

            m_stats.totalEmailsScanned.fetch_add(1, std::memory_order_relaxed);
            UpdateScanTimeStats(analysis.scanDuration.count());

            // Invoke callbacks
            m_callbackManager->InvokeAnalysis(analysis);

            SS_LOG_INFO(L"Network", L"EmailScanner: Scanned email %hs - Score: %u, Result: %d, Action: %d", SanitizeForLog(analysis.messageId).c_str(), static_cast<unsigned>(analysis.threatScore), static_cast<int>(analysis.result), static_cast<int>(analysis.action));

            return analysis;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"EmailScanner::ScanEmail: %hs", e.what());
            analysis.result = ScanResult::ERROR;
            return analysis;
        }
    }

    EmailAnalysis ScanEmailFile(const std::wstring& emlPath) {
        try {
            std::vector<std::byte> rawFileData;
            if (!Utils::FileUtils::ReadAllBytes(emlPath, rawFileData) || rawFileData.empty()) {
                SS_LOG_ERROR(L"Network", L"EmailScanner: Failed to read email file");
                return EmailAnalysis{};
            }

            auto* fileDataPtr = reinterpret_cast<const uint8_t*>(rawFileData.data());
            return ScanEmail(std::span<const uint8_t>(fileDataPtr, rawFileData.size()));

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"EmailScanner::ScanEmailFile: %hs", e.what());
            return EmailAnalysis{};
        }
    }

    EmailHeader ParseHeaders(std::span<const uint8_t> headerData) {
        return ParseHeadersImpl(headerData);
    }

    // ========================================================================
    // ATTACHMENT ANALYSIS
    // ========================================================================

    AttachmentInfo ScanAttachment(std::span<const uint8_t> data,
                                 const std::string& filename,
                                 const std::string& contentType) {
        AttachmentInfo info;
        info.attachmentId = m_nextAttachmentId.fetch_add(1, std::memory_order_relaxed);
        info.filename = filename;
        info.contentType = contentType;
        info.size = data.size();

        if (data.size() > m_config.maxAttachmentSize) {
            info.riskLevel = AttachmentRisk::BLOCKED;
            info.threats.push_back(ThreatType::MALWARE_ATTACHMENT);
            return info;
        }

        // Store data if requested
        if (m_config.retainEmailContent && data.size() < 10 * 1024 * 1024) {
            info.data.assign(data.begin(), data.end());
        }

        ScanAttachmentImpl(info);
        m_stats.attachmentsScanned.fetch_add(1, std::memory_order_relaxed);

        return info;
    }

    std::vector<AttachmentInfo> ScanArchive(std::span<const uint8_t> archiveData,
                                           const std::string& filename) {
        std::vector<AttachmentInfo> results;

        if (archiveData.empty()) {
            return results;
        }

        // Cap input size to prevent decompression bombs
        if (archiveData.size() > kMaxSingleAttachmentSize) {
            SS_LOG_WARN(L"Network",
                L"EmailScanner::ScanArchive: archive exceeds size limit (%zu bytes), skipping deep inspection",
                archiveData.size());
            AttachmentInfo info;
            info.filename  = filename;
            info.isArchive = true;
            info.size      = archiveData.size();
            info.riskLevel = AttachmentRisk::HIGH;
            results.push_back(std::move(info));
            m_stats.archivesExtracted.fetch_add(1, std::memory_order_relaxed);
            return results;
        }

        // Detect archive format from magic bytes
        using ShadowStrike::Core::FileSystem::ArchiveExtractor;
        using ShadowStrike::Core::FileSystem::ArchiveFormat;

        const auto& extractor = ArchiveExtractor::Instance();
        const ArchiveFormat detectedFormat = extractor.DetectFormat(archiveData);

        if (detectedFormat == ArchiveFormat::Unknown) {
            // Not a recognized archive — return as opaque attachment
            AttachmentInfo info;
            info.filename  = filename;
            info.isArchive = true;
            info.size      = archiveData.size();
            info.riskLevel = AttachmentRisk::MEDIUM;
            results.push_back(std::move(info));
            m_stats.archivesExtracted.fetch_add(1, std::memory_order_relaxed);
            return results;
        }

        // Write to secure temp file for ArchiveExtractor (it requires file path)
        std::error_code ec;
        auto tempDir = std::filesystem::temp_directory_path(ec);
        if (ec) {
            SS_LOG_ERROR(L"Network",
                L"EmailScanner::ScanArchive: cannot resolve temp directory: %hs", ec.message().c_str());
            AttachmentInfo info;
            info.filename  = filename;
            info.isArchive = true;
            info.size      = archiveData.size();
            info.riskLevel = AttachmentRisk::MEDIUM;
            results.push_back(std::move(info));
            return results;
        }

        // Build a unique, unpredictable temp path. Using a CNG-random token
        // (rather than addresses or hashes of attacker-controlled data)
        // defeats symlink/junction TOCTOU on shared temp directories.
        std::filesystem::path tempPath;
        HANDLE tempHandle = INVALID_HANDLE_VALUE;
        for (int attempt = 0; attempt < 8; ++attempt) {
            const std::wstring token = GenerateRandomToken(16);
            tempPath = tempDir / (L"ss_email_arch_" + token + L".tmp");

            // CREATE_NEW: fail if file exists (no overwrite of attacker-placed file).
            // FILE_FLAG_OPEN_REPARSE_POINT: do not follow symlinks/junctions.
            tempHandle = ::CreateFileW(
                tempPath.c_str(),
                GENERIC_WRITE,
                0, // no sharing — exclusive
                nullptr,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                nullptr);
            if (tempHandle != INVALID_HANDLE_VALUE) {
                break;
            }
            const DWORD err = ::GetLastError();
            if (err != ERROR_FILE_EXISTS && err != ERROR_ALREADY_EXISTS) {
                SS_LOG_ERROR(L"Network",
                    L"EmailScanner::ScanArchive: CreateFileW failed (Win32=%lu)",
                    static_cast<unsigned long>(err));
                AttachmentInfo info;
                info.filename  = filename;
                info.isArchive = true;
                info.size      = archiveData.size();
                info.riskLevel = AttachmentRisk::MEDIUM;
                results.push_back(std::move(info));
                return results;
            }
        }
        if (tempHandle == INVALID_HANDLE_VALUE) {
            SS_LOG_ERROR(L"Network",
                L"EmailScanner::ScanArchive: exhausted unique temp path attempts");
            AttachmentInfo info;
            info.filename  = filename;
            info.isArchive = true;
            info.size      = archiveData.size();
            info.riskLevel = AttachmentRisk::MEDIUM;
            results.push_back(std::move(info));
            return results;
        }

        // RAII cleanup: close handle, then delete the file.
        struct TempFileGuard {
            HANDLE handle;
            std::filesystem::path path;
            ~TempFileGuard() {
                if (handle != INVALID_HANDLE_VALUE) {
                    ::CloseHandle(handle);
                }
                std::error_code ignored;
                std::filesystem::remove(path, ignored);
            }
        } tempGuard{ tempHandle, tempPath };

        {
            const uint8_t* p = archiveData.data();
            size_t remaining = archiveData.size();
            while (remaining > 0) {
                const DWORD chunk = static_cast<DWORD>(
                    (std::min<size_t>)(remaining, static_cast<size_t>(1u << 20)));
                DWORD written = 0;
                if (!::WriteFile(tempHandle, p, chunk, &written, nullptr) ||
                    written != chunk) {
                    SS_LOG_ERROR(L"Network",
                        L"EmailScanner::ScanArchive: WriteFile failed (Win32=%lu)",
                        static_cast<unsigned long>(::GetLastError()));
                    AttachmentInfo info;
                    info.filename  = filename;
                    info.isArchive = true;
                    info.size      = archiveData.size();
                    info.riskLevel = AttachmentRisk::MEDIUM;
                    results.push_back(std::move(info));
                    return results;
                }
                p         += chunk;
                remaining -= chunk;
            }
            // Flush so ArchiveExtractor (which opens by path) sees the bytes.
            ::FlushFileBuffers(tempHandle);
            // Close write handle now; keep RAII guard for delete on scope exit.
            ::CloseHandle(tempHandle);
            tempGuard.handle = INVALID_HANDLE_VALUE;
        }

        // List contents with security limits
        try {
            ShadowStrike::Core::FileSystem::ExtractionOptions extractOpts =
                ShadowStrike::Core::FileSystem::ExtractionOptions::CreateDefault();
            extractOpts.maxEntries  = kMaxArchiveEntryCount;
            extractOpts.maxTotalSize = kMaxArchiveExtractionSize;
            extractOpts.maxNestingDepth = 3; // Limit nested-archive depth inside email

            auto entries = extractor.ListContents(tempPath.wstring(), extractOpts);

            // Parent archive entry
            AttachmentInfo archiveInfo;
            archiveInfo.filename  = filename;
            archiveInfo.isArchive = true;
            archiveInfo.size      = archiveData.size();
            archiveInfo.riskLevel = AttachmentRisk::MEDIUM;

            bool hasDangerousContent = false;
            size_t executableCount   = 0;
            size_t scriptCount       = 0;

            for (const auto& entry : entries) {
                // Convert entry path to narrow string for analysis. Use the
                // shared UTF-8 narrowing helper rather than a byte copy so
                // non-ASCII filenames survive intact for downstream checks.
                std::string entryName = Utils::StringUtils::ToNarrow(entry.path);

                if (entry.isPE) {
                    ++executableCount;
                    hasDangerousContent = true;
                }
                if (entry.isScript) {
                    ++scriptCount;
                    hasDangerousContent = true;
                }
                if (entry.isNestedArchive) {
                    hasDangerousContent = true;
                }

                // Check for dangerous extensions
                if (IsDangerousExtension(entryName)) {
                    hasDangerousContent = true;
                }

                // High compression ratio may indicate zip bomb
                if (entry.compressionRatio > 100.0) {
                    archiveInfo.riskLevel = AttachmentRisk::HIGH;
                    SS_LOG_WARN(L"Network",
                        L"EmailScanner::ScanArchive: suspicious compression ratio %.1f in %hs",
                        entry.compressionRatio, SanitizeForLog(entryName).c_str());
                }

                // Check security flags
                if (entry.isSuspicious) {
                    hasDangerousContent = true;
                }
            }

            if (hasDangerousContent) {
                archiveInfo.riskLevel = AttachmentRisk::HIGH;
            }
            if (executableCount > 0) {
                archiveInfo.riskLevel = AttachmentRisk::CRITICAL;
            }

            SS_LOG_INFO(L"Network",
                L"EmailScanner::ScanArchive: %hs contains %zu entries (%zu executables, %zu scripts)",
                SanitizeForLog(filename).c_str(), entries.size(), executableCount, scriptCount);

            results.push_back(std::move(archiveInfo));
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network",
                L"EmailScanner::ScanArchive: extraction failed for %hs: %hs",
                filename.c_str(), e.what());
            AttachmentInfo info;
            info.filename  = filename;
            info.isArchive = true;
            info.size      = archiveData.size();
            info.riskLevel = AttachmentRisk::HIGH;  // Suspicious: couldn't analyze
            results.push_back(std::move(info));
        }

        m_stats.archivesExtracted.fetch_add(1, std::memory_order_relaxed);
        return results;
    }

    // ========================================================================
    // URL ANALYSIS
    // ========================================================================

    std::vector<URLInfo> AnalyzeURLs(const std::string& content) {
        return AnalyzeURLsImpl(content);
    }

    // ========================================================================
    // PHISHING ANALYSIS
    // ========================================================================

    PhishingAnalysis AnalyzePhishing(const EmailAnalysis& analysis) {
        return AnalyzePhishingImpl(analysis);
    }

    // ========================================================================
    // SESSION MANAGEMENT
    // ========================================================================

    std::vector<EmailSession> GetActiveSessions() const {
        std::shared_lock lock(m_sessionMutex);
        std::vector<EmailSession> sessions;
        sessions.reserve(m_sessions.size());

        for (const auto& [id, session] : m_sessions) {
            sessions.push_back(session);
        }

        return sessions;
    }

    std::optional<EmailSession> GetSession(uint64_t sessionId) const {
        std::shared_lock lock(m_sessionMutex);
        auto it = m_sessions.find(sessionId);
        if (it != m_sessions.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    void TerminateSession(uint64_t sessionId) {
        std::unique_lock lock(m_sessionMutex);
        auto it = m_sessions.find(sessionId);
        if (it != m_sessions.end()) {
            // Remove from session map
            const std::string key = it->second.clientIP + ":" +
                                   std::to_string(it->second.clientPort) + "-" +
                                   it->second.serverIP + ":" +
                                   std::to_string(it->second.serverPort);
            m_sessionMap.erase(key);
            m_sessions.erase(it);
            m_stats.activeSessions.fetch_sub(1, std::memory_order_relaxed);
        }
    }

    // ========================================================================
    // WHITELIST MANAGEMENT
    // ========================================================================

    bool AddToWhitelist(const std::string& sender) {
        if (sender.empty() || sender.size() > kAddressParseInputLimit) {
            return false;
        }
        std::unique_lock lock(m_whitelistMutex);
        // If the input is a bare domain (no '@'), record it as a domain whitelist entry.
        if (sender.find('@') == std::string::npos) {
            std::string d = sender;
            std::transform(d.begin(), d.end(), d.begin(),
                [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
            auto [it, inserted] = m_whitelistDomains.insert(std::move(d));
            (void)it;
            return inserted;
        }
        auto [it, inserted] = m_whitelist.insert(NormalizeEmail(sender));
        (void)it;
        return inserted;
    }

    bool RemoveFromWhitelist(const std::string& sender) {
        if (sender.empty() || sender.size() > kAddressParseInputLimit) {
            return false;
        }
        std::unique_lock lock(m_whitelistMutex);
        if (sender.find('@') == std::string::npos) {
            std::string d = sender;
            std::transform(d.begin(), d.end(), d.begin(),
                [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
            return m_whitelistDomains.erase(d) > 0;
        }
        return m_whitelist.erase(NormalizeEmail(sender)) > 0;
    }

    bool IsWhitelisted(const std::string& sender) const {
        if (sender.empty() || sender.size() > kAddressParseInputLimit) {
            return false;
        }
        std::shared_lock lock(m_whitelistMutex);
        if (m_whitelist.contains(NormalizeEmail(sender))) {
            return true;
        }
        // Also accept whitelisted domains so org-wide trust lists work.
        const auto atPos = sender.find('@');
        if (atPos != std::string::npos && atPos + 1 < sender.size()) {
            std::string domain = sender.substr(atPos + 1);
            // Strip trailing '>' if input is "<a@b>".
            while (!domain.empty() && (domain.back() == '>' || domain.back() == ' ' ||
                                       domain.back() == '\t' || domain.back() == '\r')) {
                domain.pop_back();
            }
            std::transform(domain.begin(), domain.end(), domain.begin(),
                [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
            if (m_whitelistDomains.contains(domain)) {
                return true;
            }
        }
        return false;
    }

    // ========================================================================
    // CALLBACK MANAGEMENT
    // ========================================================================

    uint64_t RegisterAnalysisCallback(EmailAnalysisCallback callback) {
        return m_callbackManager->RegisterAnalysis(std::move(callback));
    }

    uint64_t RegisterAlertCallback(EmailAlertCallback callback) {
        return m_callbackManager->RegisterAlert(std::move(callback));
    }

    uint64_t RegisterAttachmentCallback(AttachmentCallback callback) {
        return m_callbackManager->RegisterAttachment(std::move(callback));
    }

    uint64_t RegisterPhishingCallback(PhishingCallback callback) {
        return m_callbackManager->RegisterPhishing(std::move(callback));
    }

    uint64_t RegisterMalwareCallback(MalwareCallback callback) {
        return m_callbackManager->RegisterMalware(std::move(callback));
    }

    bool UnregisterCallback(uint64_t callbackId) {
        return m_callbackManager->Unregister(callbackId);
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    const EmailScannerStatistics& GetStatistics() const noexcept {
        return m_stats;
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
    }

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    bool PerformDiagnostics() const {
        SS_LOG_INFO(L"Network", L"EmailScanner Diagnostics:");
        SS_LOG_INFO(L"Network", L"  Initialized: %d", static_cast<int>(m_initialized));
        SS_LOG_INFO(L"Network", L"  Running: %d", static_cast<int>(m_running.load()));
        SS_LOG_INFO(L"Network", L"  Active Sessions: %u", m_stats.activeSessions.load());
        SS_LOG_INFO(L"Network", L"  Emails Scanned: %llu", static_cast<unsigned long long>(m_stats.totalEmailsScanned.load()));
        SS_LOG_INFO(L"Network", L"  Threats Detected: %llu", static_cast<unsigned long long>(m_stats.malwareDetected.load() + m_stats.phishingDetected.load()));
        return true;
    }

    bool ExportDiagnostics(const std::wstring& outputPath) const {
        try {
            std::wstring report;
            report += L"EmailScanner Diagnostics Report\r\n";
            report += L"================================\r\n";
            report += L"Initialized: " + std::to_wstring(static_cast<int>(m_initialized)) + L"\r\n";
            report += L"Running: " + std::to_wstring(static_cast<int>(m_running.load())) + L"\r\n";
            report += L"Active Sessions: " + std::to_wstring(m_stats.activeSessions.load()) + L"\r\n";
            report += L"Emails Scanned: " + std::to_wstring(m_stats.totalEmailsScanned.load()) + L"\r\n";
            report += L"Malware Detected: " + std::to_wstring(m_stats.malwareDetected.load()) + L"\r\n";
            report += L"Phishing Detected: " + std::to_wstring(m_stats.phishingDetected.load()) + L"\r\n";
            report += L"Spam Detected: " + std::to_wstring(m_stats.spamDetected.load()) + L"\r\n";
            report += L"BEC Detected: " + std::to_wstring(m_stats.becDetected.load()) + L"\r\n";
            report += L"DLP Violations: " + std::to_wstring(m_stats.dlpViolations.load()) + L"\r\n";
            report += L"Blocked: " + std::to_wstring(m_stats.emailsBlocked.load()) + L"\r\n";
            report += L"Quarantined: " + std::to_wstring(m_stats.emailsQuarantined.load()) + L"\r\n";
            report += L"Avg Scan (us): " + std::to_wstring(m_stats.avgScanTimeUs.load()) + L"\r\n";
            report += L"Max Scan (us): " + std::to_wstring(m_stats.maxScanTimeUs.load()) + L"\r\n";

            std::string narrow = ShadowStrike::Utils::StringUtils::ToNarrow(report);
            Utils::FileUtils::Error err{};
            return Utils::FileUtils::WriteAllBytesAtomic(
                outputPath,
                reinterpret_cast<const std::byte*>(narrow.data()), narrow.size(),
                &err);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"EmailScanner::ExportDiagnostics: %hs", e.what());
            return false;
        }
    }

private:
    // ========================================================================
    // INTERNAL IMPLEMENTATION
    // ========================================================================

    void WorkerThread() {
        SS_LOG_INFO(L"Network", L"EmailScanner: Worker thread started");

        while (m_running.load(std::memory_order_acquire)) {
            std::unique_lock lock(m_mutex);
            m_cv.wait_for(lock, std::chrono::seconds(1));

            // Session timeout cleanup
            CleanupTimedOutSessions();
        }

        SS_LOG_INFO(L"Network", L"EmailScanner: Worker thread exited");
    }

    void CleanupTimedOutSessions() {
        std::unique_lock lock(m_sessionMutex);
        const auto now = std::chrono::system_clock::now();
        const auto timeout = std::chrono::milliseconds(m_config.sessionTimeoutMs);

        for (auto it = m_sessions.begin(); it != m_sessions.end();) {
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - it->second.lastActivity
            );

            if (elapsed > timeout) {
                const std::string key = it->second.clientIP + ":" +
                                       std::to_string(it->second.clientPort) + "-" +
                                       it->second.serverIP + ":" +
                                       std::to_string(it->second.serverPort);
                m_sessionMap.erase(key);
                it = m_sessions.erase(it);
                m_stats.activeSessions.fetch_sub(1, std::memory_order_relaxed);
                m_stats.sessionsTimedOut.fetch_add(1, std::memory_order_relaxed);
            } else {
                ++it;
            }
        }
    }

    /**
     * @brief Frame complete RFC 5321/3501 messages out of a session reassembly buffer.
     *
     * Returns owned byte vectors so the caller can drop the session lock
     * before invoking the (heavy) scanner. The caller-owned buffer is
     * advanced past every framed message that is returned. The function is
     * bounded: it never returns more than kMaxMIMEPartCount messages per call,
     * caps individual literal sizes, and refuses to allocate copies larger
     * than EmailScannerConstants::MAX_EMAIL_SIZE.
     */
    std::vector<std::vector<uint8_t>> ExtractFramedMessages(EmailSession& session) {
        std::vector<std::vector<uint8_t>> framed;
        if (session.buffer.empty()) {
            return framed;
        }

        const auto* base = session.buffer.data();
        const size_t bufSize = session.buffer.size();

        auto consume = [&](size_t consumeBytes) {
            if (consumeBytes >= session.buffer.size()) {
                session.buffer.clear();
                session.buffer.shrink_to_fit();
            } else {
                session.buffer.erase(session.buffer.begin(),
                                     session.buffer.begin() + static_cast<ptrdiff_t>(consumeBytes));
            }
        };

        auto findCRLFDotCRLF = [](const uint8_t* data, size_t len, size_t startOffset) -> size_t {
            if (len < 5 || startOffset + 5 > len) return SIZE_MAX;
            for (size_t i = startOffset; i + 5 <= len; ++i) {
                if (data[i]   == '\r' && data[i+1] == '\n' &&
                    data[i+2] == '.'  && data[i+3] == '\r' && data[i+4] == '\n') {
                    return i;
                }
            }
            return SIZE_MAX;
        };

        auto enqueueIfBounded = [&](const uint8_t* p, size_t len) -> bool {
            if (len == 0 || len > EmailScannerConstants::MAX_EMAIL_SIZE) {
                if (len > EmailScannerConstants::MAX_EMAIL_SIZE) {
                    SS_LOG_WARN(L"Network",
                        L"EmailScanner: framed message exceeds MAX_EMAIL_SIZE (%zu); dropping",
                        len);
                }
                return false;
            }
            framed.emplace_back(p, p + len);
            return true;
        };

        if (session.protocol == EmailProtocol::SMTP ||
            session.protocol == EmailProtocol::SMTPS ||
            session.protocol == EmailProtocol::UNKNOWN) {
            // SMTP DATA framing: message ends at "\r\n.\r\n".
            const size_t dataPos = findCRLFDotCRLF(base, bufSize, 0u);
            if (dataPos != SIZE_MAX) {
                if (enqueueIfBounded(base, dataPos)) {
                    session.emailsProcessed++;
                }
                consume(dataPos + 5u);
            }
        } else if (session.protocol == EmailProtocol::POP3 ||
                   session.protocol == EmailProtocol::POP3S) {
            size_t msgStart = 0;
            // Skip leading "+OK ...\r\n" status if present.
            if (bufSize >= 3 && std::memcmp(base, "+OK", 3u) == 0) {
                size_t lineEnd = SIZE_MAX;
                for (size_t i = 0; i + 1 < bufSize; ++i) {
                    if (base[i] == '\r' && base[i+1] == '\n') {
                        lineEnd = i;
                        break;
                    }
                }
                if (lineEnd == SIZE_MAX) {
                    return framed; // wait for more
                }
                msgStart = lineEnd + 2u;
            }
            const size_t dataPos = findCRLFDotCRLF(base, bufSize, msgStart);
            if (dataPos != SIZE_MAX) {
                if (enqueueIfBounded(base + msgStart, dataPos - msgStart)) {
                    session.emailsProcessed++;
                }
                consume(dataPos + 5u);
            }
        } else if (session.protocol == EmailProtocol::IMAP ||
                   session.protocol == EmailProtocol::IMAPS) {
            // IMAP literals: "{<size>}\r\n<size bytes>".
            size_t scan = 0;
            while (scan < bufSize) {
                // Locate '{' candidate.
                const uint8_t* lbrace = static_cast<const uint8_t*>(
                    std::memchr(base + scan, '{', bufSize - scan));
                if (!lbrace) break;
                size_t lpos = static_cast<size_t>(lbrace - base);

                // Find matching '}'.
                const uint8_t* rbrace = static_cast<const uint8_t*>(
                    std::memchr(base + lpos + 1, '}', bufSize - (lpos + 1)));
                if (!rbrace) break;
                size_t rpos = static_cast<size_t>(rbrace - base);

                // Validate size token is purely digits and bounded.
                if (rpos - lpos - 1 == 0 || rpos - lpos - 1 > 16) {
                    scan = rpos + 1;
                    continue;
                }
                bool numeric = true;
                size_t literalSize = 0;
                for (size_t i = lpos + 1; i < rpos; ++i) {
                    const uint8_t d = base[i];
                    if (d < '0' || d > '9') { numeric = false; break; }
                    // Build with overflow guard.
                    if (literalSize > (SIZE_MAX - (d - '0')) / 10u) {
                        numeric = false;
                        break;
                    }
                    literalSize = literalSize * 10u + static_cast<size_t>(d - '0');
                }
                if (!numeric) {
                    scan = rpos + 1;
                    continue;
                }
                if (literalSize > EmailScannerConstants::MAX_EMAIL_SIZE) {
                    SS_LOG_WARN(L"Network",
                        L"EmailScanner: IMAP literal too large (%zu); skipping",
                        literalSize);
                    scan = rpos + 1;
                    continue;
                }

                // Require CRLF after '}'.
                if (rpos + 2u >= bufSize) break; // need more bytes
                if (base[rpos + 1] != '\r' || base[rpos + 2] != '\n') {
                    scan = rpos + 1;
                    continue;
                }
                const size_t dataStart = rpos + 3u;
                if (dataStart + literalSize > bufSize) {
                    return framed; // wait for more
                }

                if (enqueueIfBounded(base + dataStart, literalSize)) {
                    session.emailsProcessed++;
                }
                consume(dataStart + literalSize);
                break; // one message per call to avoid CPU starvation
            }
        }

        return framed;
    }

    std::pair<size_t, std::span<const uint8_t>> ExtractHeaders(std::span<const uint8_t> emailData) {
        // Find header/body separator (blank line)
        for (size_t i = 0; i + 3 < emailData.size(); ++i) {
            if (emailData[i] == '\r' && emailData[i + 1] == '\n' &&
                emailData[i + 2] == '\r' && emailData[i + 3] == '\n') {
                return {i + 4, emailData.subspan(0, i)};
            }
            if (emailData[i] == '\n' && emailData[i + 1] == '\n') {
                return {i + 2, emailData.subspan(0, i)};
            }
        }

        return {emailData.size(), emailData};
    }

    EmailHeader ParseHeadersImpl(std::span<const uint8_t> headerData) {
        EmailHeader header;

        try {
            // Hard cap: refuse to parse pathologically large header sections.
            // RFC 5322 implementations universally allow rejecting these.
            const size_t headerSize = (std::min<size_t>)(headerData.size(), kMaxHeaderTotalSize);
            std::string headerText(reinterpret_cast<const char*>(headerData.data()), headerSize);
            std::istringstream stream(headerText);
            std::string line;
            std::string currentHeader;
            std::string currentValue;
            size_t headerCount = 0;

            auto processHeader = [&]() {
                if (currentHeader.empty()) return;

                // Cap the value size — arbitrarily long values are a DoS vector.
                if (currentValue.size() > kMaxHeaderValueLength) {
                    currentValue.resize(kMaxHeaderValueLength);
                }

                std::string lowerHeader = currentHeader;
                std::transform(lowerHeader.begin(), lowerHeader.end(), lowerHeader.begin(),
                    [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });

                ++headerCount;
                if (headerCount > kMaxHeaderCount) {
                    return;
                }

                if (lowerHeader == "from") {
                    header.from = ParseEmailAddress(currentValue);
                } else if (lowerHeader == "to") {
                    if (header.to.size() < kMaxRecipientsPerField) {
                        header.to.push_back(ParseEmailAddress(currentValue));
                    }
                } else if (lowerHeader == "cc") {
                    if (header.cc.size() < kMaxRecipientsPerField) {
                        header.cc.push_back(ParseEmailAddress(currentValue));
                    }
                } else if (lowerHeader == "subject") {
                    header.subject = currentValue;
                    header.decodedSubject = currentValue; // Simplified
                } else if (lowerHeader == "message-id") {
                    header.messageId = currentValue;
                } else if (lowerHeader == "date") {
                    header.dateString = currentValue;
                } else if (lowerHeader == "reply-to") {
                    header.replyTo = ParseEmailAddress(currentValue);
                } else if (lowerHeader == "return-path") {
                    header.returnPath = currentValue;
                } else if (lowerHeader == "received") {
                    if (header.receivedHeaders.size() < kMaxReceivedHeaders) {
                        header.receivedHeaders.push_back(currentValue);
                    }
                } else if (lowerHeader == "authentication-results") {
                    header.authenticationResults = currentValue;
                } else if (lowerHeader == "dkim-signature") {
                    header.dkimSignature = currentValue;
                } else if (lowerHeader == "x-mailer") {
                    header.xMailer = currentValue;
                } else if (lowerHeader == "user-agent") {
                    header.userAgent = currentValue;
                } else if (lowerHeader == "content-type") {
                    header.contentType = currentValue;
                } else {
                    if (header.customHeaders.size() < kMaxHeaderCount) {
                        header.customHeaders[currentHeader] = currentValue;
                    }
                }
            };

            while (std::getline(stream, line)) {
                if (line.empty() || line == "\r") break;

                // Per-line length cap — RFC 5322 §2.1.1 recommends 998 octets;
                // we accept up to kMaxHeaderLineLength then truncate.
                if (line.size() > kMaxHeaderLineLength) {
                    line.resize(kMaxHeaderLineLength);
                }

                // Remove CR if present
                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }

                // Check for header continuation (starts with space or tab)
                if (!line.empty() && (line[0] == ' ' || line[0] == '\t')) {
                    if (currentValue.size() < kMaxHeaderValueLength) {
                        currentValue += " ";
                        currentValue.append(line, 1,
                            (std::min<size_t>)(line.size() - 1,
                                kMaxHeaderValueLength - currentValue.size()));
                    }
                } else {
                    // Process previous header
                    processHeader();

                    if (headerCount >= kMaxHeaderCount) {
                        SS_LOG_WARN(L"Network",
                            L"EmailScanner::ParseHeadersImpl: header count cap reached (%zu); truncating",
                            headerCount);
                        break;
                    }

                    // Parse new header
                    size_t colonPos = line.find(':');
                    if (colonPos != std::string::npos && colonPos > 0) {
                        currentHeader = line.substr(0, colonPos);
                        currentValue = line.substr(colonPos + 1);

                        // Trim leading whitespace from value
                        currentValue.erase(0, currentValue.find_first_not_of(" \t"));
                    } else {
                        currentHeader.clear();
                        currentValue.clear();
                    }
                }
            }

            // Process last header
            processHeader();

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"EmailScanner::ParseHeadersImpl: %hs", e.what());
        }

        return header;
    }

    void ParseBody(std::span<const uint8_t> bodyData, EmailAnalysis& analysis) {
        try {
            const std::string contentType = analysis.header.contentType;

            if (contentType.find("multipart") != std::string::npos) {
                ParseMultipartBody(bodyData, contentType, analysis, 0);
            } else if (contentType.find("text/plain") != std::string::npos) {
                analysis.bodyText = std::string(
                    reinterpret_cast<const char*>(bodyData.data()),
                    bodyData.size()
                );
            } else if (contentType.find("text/html") != std::string::npos) {
                analysis.bodyHtml = std::string(
                    reinterpret_cast<const char*>(bodyData.data()),
                    bodyData.size()
                );
                auto htmlThreats = DetectHTMLExploits(analysis.bodyHtml);
                for (auto& threat : htmlThreats) {
                    analysis.header.anomalies.push_back(std::move(threat));
                }
            } else if (contentType.find("application/") != std::string::npos ||
                       contentType.find("image/") != std::string::npos) {
                // Non-text single-part body — treat as implicit attachment
                AttachmentInfo attachment;
                attachment.contentType = contentType;
                attachment.size        = bodyData.size();
                attachment.data.assign(bodyData.begin(), bodyData.end());
                attachment.disposition = ContentDisposition::ATTACHMENT;
                analysis.attachments.push_back(std::move(attachment));
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"EmailScanner::ParseBody: %hs", e.what());
        }
    }

    void ParseMultipartBody(std::span<const uint8_t> bodyData,
                           const std::string& contentType,
                           EmailAnalysis& analysis,
                           size_t recursionDepth) {
        if (recursionDepth >= kMaxMultipartNestingDepth) {
            SS_LOG_WARN(L"Network",
                L"EmailScanner::ParseMultipartBody: max nesting depth %zu reached, aborting",
                kMaxMultipartNestingDepth);
            analysis.header.anomalies.push_back(
                "Excessive MIME nesting depth (possible evasion)");
            return;
        }

        // Extract boundary using robust parameter extraction
        std::string boundary = ExtractMIMEParameter(contentType, "boundary");
        if (boundary.empty()) {
            SS_LOG_WARN(L"Network",
                L"EmailScanner::ParseMultipartBody: missing boundary parameter");
            return;
        }

        // Sanitize boundary — RFC 2046 says max 70 chars, no trailing spaces
        if (boundary.size() > 70) {
            boundary.resize(70);
        }

        const std::string boundaryDelim = "--" + boundary;
        std::string bodyStr(reinterpret_cast<const char*>(bodyData.data()), bodyData.size());

        size_t partCount = 0;
        size_t pos = 0;
        while ((pos = bodyStr.find(boundaryDelim, pos)) != std::string::npos) {
            pos += boundaryDelim.length();

            // Check for end boundary (--boundary--)
            if (pos + 2 <= bodyStr.length() && bodyStr[pos] == '-' && bodyStr[pos + 1] == '-') {
                break;
            }

            // Skip past CRLF after boundary
            if (pos < bodyStr.length() && bodyStr[pos] == '\r') ++pos;
            if (pos < bodyStr.length() && bodyStr[pos] == '\n') ++pos;

            // Find next boundary
            size_t nextBoundary = bodyStr.find(boundaryDelim, pos);
            if (nextBoundary == std::string::npos) break;

            // Guard against excessive part count
            if (++partCount > kMaxMIMEPartCount) {
                SS_LOG_WARN(L"Network",
                    L"EmailScanner::ParseMultipartBody: exceeded max part count %zu",
                    kMaxMIMEPartCount);
                analysis.header.anomalies.push_back(
                    "Excessive MIME part count (possible evasion or abuse)");
                break;
            }

            std::string part = bodyStr.substr(pos, nextBoundary - pos);
            ParseMIMEPart(part, analysis, recursionDepth);

            pos = nextBoundary;
        }
    }

    void ParseMIMEPart(const std::string& part, EmailAnalysis& analysis,
                       size_t recursionDepth) {
        // Find headers/body separator
        size_t bodyPos = part.find("\r\n\r\n");
        if (bodyPos == std::string::npos) {
            bodyPos = part.find("\n\n");
            if (bodyPos == std::string::npos) return;
            bodyPos += 2;
        } else {
            bodyPos += 4;
        }

        std::string rawHeaders = part.substr(0, bodyPos);
        std::string body = part.substr(bodyPos);

        // Unfold continuation lines (RFC 5322 §2.2.3)
        std::string headers = UnfoldHeaders(rawHeaders);

        // Parse headers with proper field extraction
        std::string contentType;
        std::string contentDisposition;
        std::string contentEncoding;
        std::string contentId;
        std::string filename;

        std::istringstream stream(headers);
        std::string line;
        while (std::getline(stream, line)) {
            // Strip trailing CR
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }

            if (line.empty()) continue;

            // Case-insensitive header name matching
            std::string lowerLine = line;
            for (auto& c : lowerLine) {
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            }

            if (lowerLine.starts_with("content-type:")) {
                contentType = line.substr(13);
                // Trim leading whitespace
                size_t start = contentType.find_first_not_of(" \t");
                if (start != std::string::npos && start > 0) {
                    contentType = contentType.substr(start);
                }
            } else if (lowerLine.starts_with("content-disposition:")) {
                contentDisposition = line.substr(20);
                size_t start = contentDisposition.find_first_not_of(" \t");
                if (start != std::string::npos && start > 0) {
                    contentDisposition = contentDisposition.substr(start);
                }
            } else if (lowerLine.starts_with("content-transfer-encoding:")) {
                contentEncoding = line.substr(26);
                contentEncoding.erase(0, contentEncoding.find_first_not_of(" \t"));
                // Strip trailing whitespace/semicolons
                while (!contentEncoding.empty() &&
                       (contentEncoding.back() == ' ' || contentEncoding.back() == '\t' ||
                        contentEncoding.back() == ';' || contentEncoding.back() == '\r')) {
                    contentEncoding.pop_back();
                }
            } else if (lowerLine.starts_with("content-id:")) {
                contentId = line.substr(11);
                size_t start = contentId.find_first_not_of(" \t");
                if (start != std::string::npos && start > 0) {
                    contentId = contentId.substr(start);
                }
                // Strip angle brackets: <id> -> id
                if (!contentId.empty() && contentId.front() == '<') {
                    contentId = contentId.substr(1);
                    size_t close = contentId.find('>');
                    if (close != std::string::npos) {
                        contentId = contentId.substr(0, close);
                    }
                }
            }
        }

        // Extract filename from Content-Disposition and Content-Type
        // Priority: Content-Disposition filename* > filename > Content-Type name* > name
        filename = ExtractMIMEParameter(contentDisposition, "filename");
        if (filename.empty()) {
            filename = ExtractMIMEParameter(contentType, "name");
        }

        // Decode RFC 2047 encoded-words in filename
        if (filename.find("=?") != std::string::npos) {
            filename = DecodeRFC2047EncodedWord(filename);
        }

        // Detect nested multipart — recurse
        std::string lowerCT = contentType;
        for (auto& c : lowerCT) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }

        if (lowerCT.find("multipart/") != std::string::npos) {
            auto bodySpan = std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(body.data()), body.size());
            ParseMultipartBody(bodySpan, contentType, analysis, recursionDepth + 1);
            return;
        }

        // Decode body based on encoding
        std::vector<uint8_t> decodedBody;
        std::string lowerEncoding = contentEncoding;
        for (auto& c : lowerEncoding) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }

        if (lowerEncoding.find("base64") != std::string::npos) {
            decodedBody = Base64Decode(body);
        } else if (lowerEncoding.find("quoted-printable") != std::string::npos) {
            std::string decoded = QuotedPrintableDecode(body);
            decodedBody.assign(decoded.begin(), decoded.end());
        } else {
            // 7bit, 8bit, or binary — pass through
            decodedBody.assign(body.begin(), body.end());
        }

        // Cap decoded size to prevent memory exhaustion
        if (decodedBody.size() > kMaxSingleAttachmentSize) {
            SS_LOG_WARN(L"Network",
                L"EmailScanner::ParseMIMEPart: decoded body exceeds %zu bytes, truncating",
                kMaxSingleAttachmentSize);
            decodedBody.resize(kMaxSingleAttachmentSize);
        }

        // Determine disposition: attachment, inline, or body text
        bool isAttachment = !filename.empty() ||
                            contentDisposition.find("attachment") != std::string::npos;
        bool isInline = contentDisposition.find("inline") != std::string::npos;

        // Content-Type mismatch detection: filename says .exe but Content-Type says image/jpeg
        if (!filename.empty() && IsDangerousExtension(filename)) {
            if (lowerCT.find("image/") != std::string::npos ||
                lowerCT.find("text/") != std::string::npos ||
                lowerCT.find("audio/") != std::string::npos) {
                analysis.header.anomalies.push_back(
                    "Content-Type/extension mismatch: " + filename +
                    " declared as " + contentType);
            }
        }

        if (isAttachment || (!contentId.empty() && isInline)) {
            AttachmentInfo attachment;
            attachment.filename    = filename;
            attachment.contentType = contentType;
            attachment.size        = decodedBody.size();
            attachment.data        = std::move(decodedBody);

            if (isInline) {
                attachment.disposition = ContentDisposition::INLINE;
            } else {
                attachment.disposition = ContentDisposition::ATTACHMENT;
            }

            // Store Content-ID for inline reference tracking
            if (!contentId.empty()) {
                attachment.contentId = contentId;
            }

            analysis.attachments.push_back(std::move(attachment));
        } else {
            // Body content
            if (lowerCT.find("text/plain") != std::string::npos) {
                analysis.bodyText = std::string(decodedBody.begin(), decodedBody.end());
            } else if (lowerCT.find("text/html") != std::string::npos) {
                analysis.bodyHtml = std::string(decodedBody.begin(), decodedBody.end());
                auto htmlThreats = DetectHTMLExploits(analysis.bodyHtml);
                for (auto& threat : htmlThreats) {
                    analysis.header.anomalies.push_back(std::move(threat));
                }
            } else if (!lowerCT.empty() && lowerCT.find("text/") == std::string::npos) {
                // Non-text part without disposition — treat as inline attachment
                AttachmentInfo attachment;
                attachment.filename    = filename;
                attachment.contentType = contentType;
                attachment.size        = decodedBody.size();
                attachment.data        = std::move(decodedBody);
                attachment.disposition = ContentDisposition::INLINE;
                analysis.attachments.push_back(std::move(attachment));
            }
        }
    }

    void ScanAttachmentImpl(AttachmentInfo& attachment) {
        try {
            // Calculate hashes using the correct HashUtils::Compute API
            if (!attachment.data.empty()) {
                std::vector<uint8_t> sha256Digest;
                if (Utils::HashUtils::Compute(
                        Utils::HashUtils::Algorithm::SHA256,
                        attachment.data.data(), attachment.data.size(),
                        sha256Digest)) {
                    const size_t copyLen = std::min(sha256Digest.size(), attachment.sha256.size());
                    std::copy_n(sha256Digest.begin(), copyLen, attachment.sha256.begin());

                    std::string hexStr;
                    if (Utils::HashUtils::ComputeHex(
                            Utils::HashUtils::Algorithm::SHA256,
                            attachment.data.data(), attachment.data.size(),
                            hexStr, false)) {
                        attachment.sha256Hex = std::move(hexStr);
                    }
                }

                std::vector<uint8_t> md5Digest;
                if (Utils::HashUtils::Compute(
                        Utils::HashUtils::Algorithm::MD5,
                        attachment.data.data(), attachment.data.size(),
                        md5Digest)) {
                    const size_t copyLen = std::min(md5Digest.size(), attachment.md5.size());
                    std::copy_n(md5Digest.begin(), copyLen, attachment.md5.begin());
                }
            }

            // EICAR test pattern detection
            if (!attachment.data.empty() && ContainsEicar(
                    std::span<const uint8_t>(attachment.data.data(), attachment.data.size()))) {
                attachment.riskLevel = AttachmentRisk::CRITICAL;
                attachment.scanResult = ScanResult::MALICIOUS;
                attachment.matchedSignatures.push_back("EICAR-Test-File");
                attachment.threats.push_back(ThreatType::MALWARE_ATTACHMENT);
                m_stats.attachmentsScanned.fetch_add(1, std::memory_order_relaxed);
                return;
            }

            // OLE compound document detection (embedded objects)
            if (!attachment.data.empty() && ContainsOLEObject(
                    std::span<const uint8_t>(attachment.data.data(), attachment.data.size()))) {
                attachment.hasActiveContent = true;
                attachment.riskLevel = std::max(attachment.riskLevel, AttachmentRisk::MEDIUM);
            }

            // RTLO / double-extension detection on filename
            if (!attachment.filename.empty()) {
                if (HasRTLOCharacter(attachment.filename)) {
                    attachment.riskLevel = AttachmentRisk::CRITICAL;
                    attachment.threats.push_back(ThreatType::MALWARE_ATTACHMENT);
                }
                if (HasDoubleExtension(attachment.filename)) {
                    attachment.riskLevel = std::max(attachment.riskLevel, AttachmentRisk::HIGH);
                    attachment.threats.push_back(ThreatType::MALWARE_ATTACHMENT);
                }
            }

            // Detect actual file type via FileTypeAnalyzer
            if (!attachment.data.empty()) {
                auto typeInfo = FileSystem::FileTypeAnalyzer::Instance().AnalyzeBuffer(
                    std::span<const uint8_t>(attachment.data.data(), attachment.data.size()),
                    ShadowStrike::Utils::StringUtils::ToWide(attachment.filename)
                );

                attachment.detectedType = static_cast<int>(typeInfo.category) >= 0 ?
                    std::to_string(static_cast<int>(typeInfo.format)) : "Unknown";

                if (typeInfo.isSpoofed) {
                    attachment.typeMismatch = true;
                    attachment.riskLevel = std::max(attachment.riskLevel, AttachmentRisk::HIGH);
                    attachment.threats.push_back(ThreatType::MALWARE_ATTACHMENT);
                }

                if (typeInfo.isExecutable) {
                    attachment.type = AttachmentType::EXECUTABLE;
                    attachment.riskLevel = AttachmentRisk::CRITICAL;
                    attachment.threats.push_back(ThreatType::MALWARE_ATTACHMENT);
                } else if (typeInfo.isScript) {
                    attachment.type = AttachmentType::SCRIPT;
                    attachment.riskLevel = std::max(attachment.riskLevel, AttachmentRisk::HIGH);
                    attachment.threats.push_back(ThreatType::MALWARE_SCRIPT);
                } else if (typeInfo.isArchive) {
                    attachment.type = AttachmentType::ARCHIVE;
                    attachment.isArchive = true;
                    attachment.riskLevel = std::max(attachment.riskLevel, AttachmentRisk::MEDIUM);
                } else if (typeInfo.canContainMacros) {
                    attachment.hasMacros = true;
                    attachment.riskLevel = std::max(attachment.riskLevel, AttachmentRisk::MEDIUM);
                }
            }

            // Update scan result
            if (attachment.riskLevel >= AttachmentRisk::HIGH) {
                attachment.scanResult = ScanResult::MALICIOUS;
            } else if (attachment.riskLevel == AttachmentRisk::MEDIUM) {
                attachment.scanResult = ScanResult::SUSPICIOUS;
            } else {
                attachment.scanResult = ScanResult::CLEAN;
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"EmailScanner::ScanAttachmentImpl: %hs", e.what());
            attachment.scanResult = ScanResult::ERROR;
        }
    }

    std::vector<URLInfo> AnalyzeURLsImpl(const std::string& content) {
        std::vector<URLInfo> urls;

        try {
            auto extractedUrls = ExtractURLs(content);
            m_stats.urlsScanned.fetch_add(extractedUrls.size(), std::memory_order_relaxed);

            for (const auto& url : extractedUrls) {
                URLInfo info;
                info.url = url;

                // Extract domain
                size_t domainStart = url.find("://");
                if (domainStart != std::string::npos) {
                    domainStart += 3;
                    size_t domainEnd = url.find('/', domainStart);
                    if (domainEnd == std::string::npos) {
                        domainEnd = url.length();
                    }
                    info.domain = url.substr(domainStart, domainEnd - domainStart);
                }

                // Check for phishing indicators
                AnalyzeURLForPhishing(info);

                if (info.isPhishing) {
                    m_stats.phishingUrls.fetch_add(1, std::memory_order_relaxed);
                }

                urls.push_back(std::move(info));
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"EmailScanner::AnalyzeURLsImpl: %hs", e.what());
        }

        return urls;
    }

    void AnalyzeURLForPhishing(URLInfo& info) {
        // Check for homograph attacks (IDN homographs)
        if (info.domain.find("xn--") != std::string::npos) {
            info.isHomograph = true;
            info.phishingScore += 0.3;
        }

        // Check for IP addresses in domain
        static const std::regex ipRegex(R"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})");
        if (std::regex_search(info.domain, ipRegex)) {
            info.phishingScore += 0.2;
        }

        // Check for suspicious TLDs
        static const std::vector<std::string> suspiciousTLDs = {
            ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw"
        };
        for (const auto& tld : suspiciousTLDs) {
            if (info.domain.ends_with(tld)) {
                info.phishingScore += 0.15;
                break;
            }
        }

        // Check for brand impersonation in domain
        for (const auto& brand : g_knownBrands) {
            if (info.domain.find(brand) != std::string::npos &&
                info.domain.find(brand + ".com") == std::string::npos) {
                // Brand name in domain but not official domain
                info.phishingScore += 0.25;
            }
        }

        // Check for excessive subdomains
        size_t dotCount = std::count(info.domain.begin(), info.domain.end(), '.');
        if (dotCount > 3) {
            info.phishingScore += 0.1;
        }

        if (info.phishingScore >= 0.5) {
            info.isPhishing = true;
        }
    }

    PhishingAnalysis AnalyzePhishingImpl(const EmailAnalysis& analysis) {
        PhishingAnalysis phishing;

        try {
            double score = 0.0;

            // Check sender spoofing
            if (analysis.header.from.hasDisplayNameMismatch) {
                phishing.displayNameMismatch = true;
                phishing.indicators.push_back("Display name mismatch");
                score += 0.3;
            }

            // Check authentication failures
            if (!analysis.authResults.spfPass) {
                phishing.senderSpoofed = true;
                phishing.indicators.push_back("SPF failure");
                score += 0.2;
            }
            if (!analysis.authResults.dkimPass) {
                phishing.indicators.push_back("DKIM failure");
                score += 0.15;
            }
            if (!analysis.authResults.dmarcPass) {
                phishing.indicators.push_back("DMARC failure");
                score += 0.15;
            }

            // Check for urgency language
            std::string combinedContent = analysis.header.decodedSubject + " " +
                                         analysis.bodyText + " " + analysis.bodyHtml;
            std::string lowerContent = combinedContent;
            std::transform(lowerContent.begin(), lowerContent.end(), lowerContent.begin(), ::tolower);

            for (const auto& keyword : g_urgencyKeywords) {
                if (lowerContent.find(keyword) != std::string::npos) {
                    phishing.hasUrgencyLanguage = true;
                    phishing.indicators.push_back("Urgency: " + keyword);
                    score += 0.05;
                }
            }

            // Check for credential requests
            for (const auto& keyword : g_credentialKeywords) {
                if (lowerContent.find(keyword) != std::string::npos) {
                    phishing.hasCredentialRequest = true;
                    phishing.indicators.push_back("Credential request: " + keyword);
                    score += 0.1;
                }
            }

            // Check URLs
            for (const auto& url : analysis.urls) {
                if (url.isPhishing) {
                    phishing.hasSuspiciousLinks = true;
                    phishing.suspiciousUrlCount++;
                    phishing.indicators.push_back("Phishing URL: " + url.url);
                    score += 0.15;
                }
            }

            // Check for brand impersonation
            for (const auto& brand : g_knownBrands) {
                if (lowerContent.find(brand) != std::string::npos) {
                    const std::string senderDomain = analysis.header.from.domain;
                    std::string lowerDomain = senderDomain;
                    std::transform(lowerDomain.begin(), lowerDomain.end(), lowerDomain.begin(), ::tolower);

                    if (lowerDomain.find(brand) == std::string::npos) {
                        // Mentions brand but sender is not from brand domain
                        phishing.brandImpersonation = true;
                        phishing.impersonatedBrand = brand;
                        phishing.indicators.push_back("Brand impersonation: " + brand);
                        score += 0.25;
                        break;
                    }
                }
            }

            phishing.confidence = std::min(score, 1.0);
            phishing.indicatorCount = static_cast<uint32_t>(phishing.indicators.size());
            phishing.isPhishing = (phishing.confidence >= m_config.phishingThreshold);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"EmailScanner::AnalyzePhishingImpl: %hs", e.what());
        }

        return phishing;
    }

    void AnalyzeSpam(EmailAnalysis& analysis) {
        try {
            double score = 0.0;

            std::string combinedContent = analysis.header.decodedSubject + " " +
                                         analysis.bodyText + " " + analysis.bodyHtml;
            std::string lowerContent = combinedContent;
            std::transform(lowerContent.begin(), lowerContent.end(), lowerContent.begin(), ::tolower);

            // Check spam keywords
            for (const auto& keyword : g_spamKeywords) {
                if (lowerContent.find(keyword) != std::string::npos) {
                    analysis.spamIndicators.push_back(keyword);
                    score += 0.1;
                }
            }

            // Excessive caps
            size_t capsCount = std::count_if(combinedContent.begin(), combinedContent.end(),
                [](char c) { return std::isupper(static_cast<unsigned char>(c)) != 0; });
            if (combinedContent.length() > 0) {
                double capsRatio = static_cast<double>(capsCount) / combinedContent.length();
                if (capsRatio > 0.5) {
                    analysis.spamIndicators.push_back("Excessive capitals");
                    score += 0.15;
                }
            }

            // Excessive exclamation marks
            size_t exclCount = std::count(combinedContent.begin(), combinedContent.end(), '!');
            if (exclCount > 5) {
                analysis.spamIndicators.push_back("Excessive exclamation marks");
                score += 0.1;
            }

            // Missing or suspicious from address
            if (analysis.header.from.fullAddress.empty() || !analysis.header.from.isValid) {
                analysis.spamIndicators.push_back("Invalid sender");
                score += 0.2;
            }

            analysis.spamScore = std::min(score, 1.0);
            analysis.isSpam = (analysis.spamScore >= m_config.spamThreshold);

            if (analysis.isSpam) {
                m_stats.spamDetected.fetch_add(1, std::memory_order_relaxed);
                analysis.threats.push_back(ThreatType::SPAM);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"EmailScanner::AnalyzeSpam: %hs", e.what());
        }
    }

    void AnalyzeBEC(EmailAnalysis& analysis) {
        try {
            double score = 0.0;

            std::string lowerSubject = analysis.header.decodedSubject;
            std::transform(lowerSubject.begin(), lowerSubject.end(), lowerSubject.begin(), ::tolower);

            // Check for payment/financial keywords
            static const std::vector<std::string> becKeywords = {
                "wire transfer", "payment", "invoice", "urgent payment", "bank details",
                "account details", "transfer funds", "payroll", "ceo", "president",
                "executive", "confidential", "discreet", "wire immediately"
            };

            for (const auto& keyword : becKeywords) {
                if (lowerSubject.find(keyword) != std::string::npos) {
                    analysis.becIndicators.push_back(keyword);
                    score += 0.15;
                }
            }

            // Check for executive impersonation
            static const std::vector<std::string> execTitles = {
                "ceo", "cfo", "cto", "president", "vp", "vice president", "director", "executive"
            };

            std::string senderName = analysis.header.from.displayName;
            std::transform(senderName.begin(), senderName.end(), senderName.begin(), ::tolower);

            for (const auto& title : execTitles) {
                if (senderName.find(title) != std::string::npos) {
                    analysis.becIndicators.push_back("Executive title in sender");
                    score += 0.2;
                    break;
                }
            }

            // Check for domain spoofing
            if (analysis.phishingAnalysis.domainSpoofed) {
                analysis.becIndicators.push_back("Domain spoofing");
                score += 0.25;
            }

            // Internal direction with external sender
            if (analysis.direction == EmailDirection::INTERNAL &&
                !analysis.header.from.domain.empty()) {
                // Simplified check - would need organization domain list
                analysis.becIndicators.push_back("External sender, internal mail");
                score += 0.15;
            }

            analysis.becScore = std::min(score, 1.0);
            analysis.isBEC = (analysis.becScore >= m_config.becThreshold);

            if (analysis.isBEC) {
                m_stats.becDetected.fetch_add(1, std::memory_order_relaxed);
                analysis.threats.push_back(ThreatType::BEC_IMPERSONATION);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"EmailScanner::AnalyzeBEC: %hs", e.what());
        }
    }

    void AnalyzeDLP(EmailAnalysis& analysis) {
        try {
            std::string combinedContent = analysis.bodyText + " " + analysis.bodyHtml;

            for (const auto& pattern : g_dlpPatterns) {
                auto begin = std::sregex_iterator(combinedContent.begin(), combinedContent.end(), pattern.pattern);
                auto end = std::sregex_iterator();

                for (std::sregex_iterator i = begin; i != end; ++i) {
                    std::smatch match = *i;

                    DLPResult::Violation violation;
                    violation.dataType = pattern.dataType;
                    violation.match = match.str();
                    violation.location = "Body";
                    violation.severity = pattern.severity;

                    analysis.dlpResult.violations.push_back(violation);
                    analysis.dlpResult.violationCount++;

                    // Set flags
                    if (pattern.dataType == "Credit Card") {
                        analysis.dlpResult.hasCreditCard = true;
                        analysis.dlpResult.hasFinancialData = true;
                    } else if (pattern.dataType == "SSN") {
                        analysis.dlpResult.hasSSN = true;
                        analysis.dlpResult.hasPII = true;
                    }
                }
            }

            if (analysis.dlpResult.violationCount > 0) {
                analysis.dlpResult.hasViolation = true;
                m_stats.dlpViolations.fetch_add(analysis.dlpResult.violationCount, std::memory_order_relaxed);
                analysis.threats.push_back(ThreatType::DLP_VIOLATION);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"EmailScanner::AnalyzeDLP: %hs", e.what());
        }
    }

    AuthenticationResults ParseAuthenticationResults(const EmailHeader& header) {
        AuthenticationResults results;

        try {
            // Parse Authentication-Results header
            const std::string& authHeader = header.authenticationResults;
            if (!authHeader.empty()) {
                std::string lower = authHeader;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

                // SPF
                if (lower.find("spf=pass") != std::string::npos) {
                    results.spfPass = true;
                    results.spfResult = "pass";
                } else if (lower.find("spf=fail") != std::string::npos) {
                    results.spfResult = "fail";
                    results.failures.push_back("SPF");
                } else if (lower.find("spf=") != std::string::npos) {
                    results.spfResult = "softfail/neutral/none";
                }

                // DKIM
                if (lower.find("dkim=pass") != std::string::npos) {
                    results.dkimPass = true;
                    results.dkimResult = "pass";
                } else if (lower.find("dkim=fail") != std::string::npos) {
                    results.dkimResult = "fail";
                    results.failures.push_back("DKIM");
                }

                // DMARC
                if (lower.find("dmarc=pass") != std::string::npos) {
                    results.dmarcPass = true;
                    results.dmarcResult = "pass";
                } else if (lower.find("dmarc=fail") != std::string::npos) {
                    results.dmarcResult = "fail";
                    results.failures.push_back("DMARC");
                }
            }

            results.allPass = results.spfPass && results.dkimPass && results.dmarcPass;
            results.anyFail = !results.failures.empty();

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"EmailScanner::ParseAuthenticationResults: %hs", e.what());
        }

        return results;
    }

    EmailDirection DetermineDirection(const EmailHeader& header) {
        // Simplified - would need organization domain configuration
        // Check if sender and recipient are from same domain
        if (!header.from.domain.empty() && !header.to.empty()) {
            if (header.from.domain == header.to[0].domain) {
                return EmailDirection::INTERNAL;
            }
        }

        // Default to inbound for now
        return EmailDirection::INBOUND;
    }

    void CalculateThreatScore(EmailAnalysis& analysis) {
        uint32_t score = 0;

        // Malware attachments (+40)
        for (const auto& attachment : analysis.attachments) {
            if (attachment.riskLevel == AttachmentRisk::CRITICAL) {
                score += 40;
            } else if (attachment.riskLevel == AttachmentRisk::HIGH) {
                score += 25;
            } else if (attachment.riskLevel == AttachmentRisk::MEDIUM) {
                score += 10;
            }
        }

        // Phishing (+30)
        if (analysis.phishingAnalysis.isPhishing) {
            score += static_cast<uint32_t>(analysis.phishingAnalysis.confidence * 30);
        }

        // BEC (+25)
        if (analysis.isBEC) {
            score += static_cast<uint32_t>(analysis.becScore * 25);
        }

        // Spam (+15)
        if (analysis.isSpam) {
            score += static_cast<uint32_t>(analysis.spamScore * 15);
        }

        // DLP (+20)
        if (analysis.dlpResult.hasViolation) {
            score += std::min(analysis.dlpResult.violationCount * 5, 20u);
        }

        // Authentication failures (+10)
        if (analysis.authResults.anyFail) {
            score += static_cast<uint32_t>(analysis.authResults.failures.size() * 3);
        }

        analysis.threatScore = std::min(score, 100u);
    }

    void DetermineAction(EmailAnalysis& analysis) {
        // Determine result
        if (analysis.threatScore >= 70) {
            analysis.result = ScanResult::MALICIOUS;
        } else if (analysis.threatScore >= 40) {
            analysis.result = ScanResult::SUSPICIOUS;
        } else {
            analysis.result = ScanResult::CLEAN;
        }

        // Determine action based on threat types
        bool hasMalware = false;
        bool hasPhishing = false;
        bool hasSpam = false;

        for (const auto& threat : analysis.threats) {
            if (static_cast<int>(threat) >= 100 && static_cast<int>(threat) < 200) {
                hasMalware = true;
            } else if (static_cast<int>(threat) >= 200 && static_cast<int>(threat) < 300) {
                hasPhishing = true;
            } else if (static_cast<int>(threat) == 400) {
                hasSpam = true;
            }
        }

        // Apply configured actions
        if (hasMalware) {
            analysis.action = m_config.malwareAction;
            m_stats.malwareDetected.fetch_add(1, std::memory_order_relaxed);
        } else if (hasPhishing) {
            analysis.action = m_config.phishingAction;
        } else if (hasSpam) {
            analysis.action = m_config.spamAction;
        } else if (analysis.result == ScanResult::SUSPICIOUS) {
            analysis.action = EmailAction::TAG_SUSPICIOUS;
        } else {
            analysis.action = EmailAction::ALLOW;
        }

        // Update action statistics
        if (analysis.action == EmailAction::BLOCK) {
            m_stats.emailsBlocked.fetch_add(1, std::memory_order_relaxed);
        } else if (analysis.action == EmailAction::QUARANTINE) {
            m_stats.emailsQuarantined.fetch_add(1, std::memory_order_relaxed);
        } else if (analysis.action == EmailAction::STRIP_ATTACHMENTS) {
            m_stats.attachmentsStripped.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void CreateAlerts(const EmailAnalysis& analysis) {
        try {
            for (const auto& threat : analysis.threats) {
                EmailAlert alert;
                alert.alertId = m_nextAlertId.fetch_add(1, std::memory_order_relaxed);
                alert.analysisId = analysis.analysisId;
                alert.timestamp = std::chrono::system_clock::now();
                alert.threatType = threat;
                alert.messageId = analysis.messageId;
                alert.subject = analysis.header.decodedSubject;
                alert.sender = analysis.header.from.fullAddress;
                alert.direction = analysis.direction;
                alert.actionTaken = analysis.action;

                // Set severity
                if (static_cast<int>(threat) >= 100 && static_cast<int>(threat) < 200) {
                    alert.severity = 9;  // Malware
                    alert.threatDescription = "Malware detected in email";
                } else if (static_cast<int>(threat) >= 200 && static_cast<int>(threat) < 300) {
                    alert.severity = 8;  // Phishing
                    alert.threatDescription = "Phishing attempt detected";
                } else if (static_cast<int>(threat) >= 300 && static_cast<int>(threat) < 400) {
                    alert.severity = 7;  // BEC
                    alert.threatDescription = "Business Email Compromise detected";
                }

                // Add recipients
                for (const auto& to : analysis.header.to) {
                    alert.recipients.push_back(to.fullAddress);
                }

                // Invoke callback
                m_callbackManager->InvokeAlert(alert);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"EmailScanner::CreateAlerts: %hs", e.what());
        }
    }

    void UpdateScanTimeStats(uint64_t timeUs) {
        // Atomic CAS loop for thread-safe running average
        uint64_t currentAvg = m_stats.avgScanTimeUs.load(std::memory_order_relaxed);
        uint64_t newAvg;
        do {
            newAvg = (currentAvg == 0) ? timeUs : (currentAvg + timeUs) / 2;
        } while (!m_stats.avgScanTimeUs.compare_exchange_weak(
            currentAvg, newAvg, std::memory_order_relaxed));

        // Atomic CAS for max
        uint64_t currentMax = m_stats.maxScanTimeUs.load(std::memory_order_relaxed);
        while (timeUs > currentMax) {
            if (m_stats.maxScanTimeUs.compare_exchange_weak(
                    currentMax, timeUs, std::memory_order_relaxed)) {
                break;
            }
        }
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    mutable std::shared_mutex m_sessionMutex;
    mutable std::shared_mutex m_whitelistMutex;

    bool m_initialized{ false };
    std::atomic<bool> m_running{ false };
    EmailScannerConfig m_config;

    // Threading
    std::vector<std::thread> m_workers;
    std::condition_variable_any m_cv;

    // Sessions
    std::unordered_map<uint64_t, EmailSession> m_sessions;
    std::unordered_map<std::string, uint64_t> m_sessionMap;  // key -> sessionId
    std::atomic<uint64_t> m_nextSessionId{ 1 };

    // Analysis
    std::atomic<uint64_t> m_nextAnalysisId{ 1 };
    std::atomic<uint64_t> m_nextAttachmentId{ 1 };
    std::atomic<uint64_t> m_nextAlertId{ 1 };

    // Whitelist
    std::unordered_set<std::string> m_whitelist;
    std::unordered_set<std::string> m_whitelistDomains;

    // Callbacks
    std::unique_ptr<CallbackManager> m_callbackManager;

    // Statistics
    EmailScannerStatistics m_stats;
};

// ============================================================================
// MAIN CLASS IMPLEMENTATION (SINGLETON + FORWARDING)
// ============================================================================

EmailScanner::EmailScanner()
    : m_impl(std::make_unique<EmailScannerImpl>()) {
}

EmailScanner::~EmailScanner() = default;

EmailScanner& EmailScanner::Instance() {
    static EmailScanner instance;
    return instance;
}

bool EmailScanner::Initialize(const EmailScannerConfig& config) {
    return m_impl->Initialize(config);
}

bool EmailScanner::Start() {
    return m_impl->Start();
}

void EmailScanner::Stop() {
    m_impl->Stop();
}

void EmailScanner::Shutdown() noexcept {
    m_impl->Shutdown();
}

bool EmailScanner::IsRunning() const noexcept {
    return m_impl->IsRunning();
}

void EmailScanner::FeedPacket(const std::vector<uint8_t>& data) {
    m_impl->FeedPacket(std::span<const uint8_t>(data.data(), data.size()),
                      "", 0, "", 0);
}

void EmailScanner::FeedPacket(std::span<const uint8_t> data,
                             const std::string& srcIP, uint16_t srcPort,
                             const std::string& dstIP, uint16_t dstPort) {
    m_impl->FeedPacket(data, srcIP, srcPort, dstIP, dstPort);
}

EmailAnalysis EmailScanner::ScanEmail(const std::vector<uint8_t>& emailData) {
    return m_impl->ScanEmail(std::span<const uint8_t>(emailData.data(), emailData.size()));
}

EmailAnalysis EmailScanner::ScanEmailFile(const std::wstring& emlPath) {
    return m_impl->ScanEmailFile(emlPath);
}

EmailHeader EmailScanner::ParseHeaders(std::span<const uint8_t> headerData) {
    return m_impl->ParseHeaders(headerData);
}

AttachmentInfo EmailScanner::ScanAttachment(std::span<const uint8_t> data,
                                           const std::string& filename,
                                           const std::string& contentType) {
    return m_impl->ScanAttachment(data, filename, contentType);
}

std::vector<AttachmentInfo> EmailScanner::ScanArchive(std::span<const uint8_t> archiveData,
                                                      const std::string& filename) {
    return m_impl->ScanArchive(archiveData, filename);
}

std::vector<URLInfo> EmailScanner::AnalyzeURLs(const std::string& content) {
    return m_impl->AnalyzeURLs(content);
}

PhishingAnalysis EmailScanner::AnalyzePhishing(const EmailAnalysis& analysis) {
    return m_impl->AnalyzePhishing(analysis);
}

std::vector<EmailSession> EmailScanner::GetActiveSessions() const {
    return m_impl->GetActiveSessions();
}

std::optional<EmailSession> EmailScanner::GetSession(uint64_t sessionId) const {
    return m_impl->GetSession(sessionId);
}

void EmailScanner::TerminateSession(uint64_t sessionId) {
    m_impl->TerminateSession(sessionId);
}

bool EmailScanner::AddToWhitelist(const std::string& sender) {
    return m_impl->AddToWhitelist(sender);
}

bool EmailScanner::RemoveFromWhitelist(const std::string& sender) {
    return m_impl->RemoveFromWhitelist(sender);
}

bool EmailScanner::IsWhitelisted(const std::string& sender) const {
    return m_impl->IsWhitelisted(sender);
}

uint64_t EmailScanner::RegisterAnalysisCallback(EmailAnalysisCallback callback) {
    return m_impl->RegisterAnalysisCallback(std::move(callback));
}

uint64_t EmailScanner::RegisterAlertCallback(EmailAlertCallback callback) {
    return m_impl->RegisterAlertCallback(std::move(callback));
}

uint64_t EmailScanner::RegisterAttachmentCallback(AttachmentCallback callback) {
    return m_impl->RegisterAttachmentCallback(std::move(callback));
}

uint64_t EmailScanner::RegisterPhishingCallback(PhishingCallback callback) {
    return m_impl->RegisterPhishingCallback(std::move(callback));
}

uint64_t EmailScanner::RegisterMalwareCallback(MalwareCallback callback) {
    return m_impl->RegisterMalwareCallback(std::move(callback));
}

bool EmailScanner::UnregisterCallback(uint64_t callbackId) {
    return m_impl->UnregisterCallback(callbackId);
}

const EmailScannerStatistics& EmailScanner::GetStatistics() const noexcept {
    return m_impl->GetStatistics();
}

void EmailScanner::ResetStatistics() noexcept {
    m_impl->ResetStatistics();
}

bool EmailScanner::PerformDiagnostics() const {
    return m_impl->PerformDiagnostics();
}

bool EmailScanner::ExportDiagnostics(const std::wstring& outputPath) const {
    return m_impl->ExportDiagnostics(outputPath);
}

}  // namespace Network
}  // namespace Core
}  // namespace ShadowStrike
