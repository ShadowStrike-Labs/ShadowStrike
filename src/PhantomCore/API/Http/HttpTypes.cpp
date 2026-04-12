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
#include "PhantomCore/API/Http/HttpTypes.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstring>
#include <sstream>

namespace ShadowStrike {
namespace Http {

// ============================================================================
// CaseInsensitiveHash / CaseInsensitiveEqual
// ============================================================================

size_t CaseInsensitiveHash::operator()(std::string_view key) const noexcept {
    size_t hash = 0x811c9dc5ULL; // FNV-1a offset basis
    for (char c : key) {
        auto lower = static_cast<unsigned char>(
            (c >= 'A' && c <= 'Z') ? (c + ('a' - 'A')) : c);
        hash ^= lower;
        hash *= 0x01000193ULL; // FNV-1a prime
    }
    return hash;
}

bool CaseInsensitiveEqual::operator()(std::string_view a, std::string_view b) const noexcept {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca += ('a' - 'A');
        if (cb >= 'A' && cb <= 'Z') cb += ('a' - 'A');
        if (ca != cb) return false;
    }
    return true;
}

// ============================================================================
// HttpRequest
// ============================================================================

std::optional<std::string_view> HttpRequest::GetHeader(std::string_view name) const noexcept {
    auto it = headers.find(std::string(name));
    if (it != headers.end()) {
        return std::string_view(it->second);
    }
    return std::nullopt;
}

std::optional<std::string_view> HttpRequest::GetContentType() const noexcept {
    return GetHeader("Content-Type");
}

std::optional<size_t> HttpRequest::GetContentLength() const noexcept {
    auto val = GetHeader("Content-Length");
    if (!val) return std::nullopt;

    size_t result = 0;
    auto [ptr, ec] = std::from_chars(val->data(), val->data() + val->size(), result);
    if (ec != std::errc{} || ptr != val->data() + val->size()) {
        return std::nullopt;
    }
    return result;
}

bool HttpRequest::IsKeepAlive() const noexcept {
    auto conn = GetHeader("Connection");
    if (!conn) {
        // HTTP/1.1 defaults to keep-alive
        return httpVersion.find("1.1") != std::string::npos;
    }
    // Case-insensitive check for "close"
    std::string lower(conn->size(), '\0');
    std::transform(conn->begin(), conn->end(), lower.begin(),
        [](char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); });
    return lower.find("close") == std::string::npos;
}

std::string_view HttpRequest::GetBodyString() const noexcept {
    if (body.empty()) return {};
    return std::string_view(reinterpret_cast<const char*>(body.data()), body.size());
}

std::unordered_map<std::string, std::string> HttpRequest::ParseQueryParams() const {
    std::unordered_map<std::string, std::string> params;
    if (queryString.empty()) return params;

    std::string_view qs = queryString;
    while (!qs.empty()) {
        auto ampPos = qs.find('&');
        auto pair = qs.substr(0, ampPos);
        qs = (ampPos != std::string_view::npos) ? qs.substr(ampPos + 1) : std::string_view{};

        if (pair.empty()) continue;

        auto eqPos = pair.find('=');
        if (eqPos != std::string_view::npos) {
            auto key = UrlDecode(pair.substr(0, eqPos));
            auto value = UrlDecode(pair.substr(eqPos + 1));
            if (!key.empty()) {
                params[std::move(key)] = std::move(value);
            }
        } else {
            auto key = UrlDecode(pair);
            if (!key.empty()) {
                params[std::move(key)] = "";
            }
        }
    }
    return params;
}

std::optional<std::string> HttpRequest::GetQueryParam(std::string_view name) const {
    auto params = ParseQueryParams();
    auto it = params.find(std::string(name));
    if (it != params.end()) return it->second;
    return std::nullopt;
}

// ============================================================================
// HttpResponse
// ============================================================================

void HttpResponse::SetHeader(std::string name, std::string value) {
    headers[std::move(name)] = std::move(value);
}

void HttpResponse::SetContentType(std::string_view contentType) {
    headers["Content-Type"] = std::string(contentType);
}

void HttpResponse::SetBody(std::string_view text) {
    body.assign(text.begin(), text.end());
}

void HttpResponse::SetBody(const uint8_t* data, size_t length) {
    body.assign(data, data + length);
}

void HttpResponse::SetBody(std::vector<uint8_t> data) {
    body = std::move(data);
}

void HttpResponse::SetJsonBody(std::string_view json) {
    SetContentType("application/json; charset=utf-8");
    SetBody(json);
}

HttpResponse HttpResponse::MakeError(HttpStatus httpStatus, std::string_view message,
                                     std::string_view requestId) {
    HttpResponse resp;
    resp.status = httpStatus;

    std::string json = "{\"error\":{\"code\":";
    json += std::to_string(static_cast<uint16_t>(httpStatus));
    json += ",\"status\":\"";
    json += HttpStatusReasonPhrase(httpStatus);
    json += "\",\"message\":\"";
    // Escape JSON special characters in message
    for (char c : message) {
        switch (c) {
            case '"':  json += "\\\""; break;
            case '\\': json += "\\\\"; break;
            case '\n': json += "\\n";  break;
            case '\r': json += "\\r";  break;
            case '\t': json += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
                    json += buf;
                } else {
                    json += c;
                }
                break;
        }
    }
    json += "\"";
    if (!requestId.empty()) {
        json += ",\"request_id\":\"";
        json += requestId;
        json += "\"";
    }
    json += "}}";

    resp.SetJsonBody(json);
    return resp;
}

HttpResponse HttpResponse::MakeJson(HttpStatus httpStatus, std::string_view json) {
    HttpResponse resp;
    resp.status = httpStatus;
    resp.SetJsonBody(json);
    return resp;
}

std::vector<uint8_t> HttpResponse::Serialize() const {
    std::string statusLine = HTTP_VERSION_11;
    statusLine += ' ';
    statusLine += std::to_string(static_cast<uint16_t>(status));
    statusLine += ' ';
    statusLine += HttpStatusReasonPhrase(status);
    statusLine += CRLF;

    // Build header block
    std::string headerBlock;
    headerBlock.reserve(512);

    bool hasContentLength = false;
    bool hasContentType = false;
    for (const auto& [key, val] : headers) {
        headerBlock += key;
        headerBlock += ": ";
        headerBlock += val;
        headerBlock += CRLF;

        // Track which standard headers are present
        if (CaseInsensitiveEqual{}(key, "Content-Length")) hasContentLength = true;
        if (CaseInsensitiveEqual{}(key, "Content-Type"))   hasContentType = true;
    }

    // Auto-add Content-Length if not set
    if (!hasContentLength) {
        headerBlock += "Content-Length: ";
        headerBlock += std::to_string(body.size());
        headerBlock += CRLF;
    }

    // Terminate headers
    headerBlock += CRLF;

    // Assemble final output
    size_t totalSize = statusLine.size() + headerBlock.size() + body.size();
    std::vector<uint8_t> result;
    result.reserve(totalSize);
    result.insert(result.end(), statusLine.begin(), statusLine.end());
    result.insert(result.end(), headerBlock.begin(), headerBlock.end());
    result.insert(result.end(), body.begin(), body.end());
    return result;
}

// ============================================================================
// URL Decode / Encode
// ============================================================================

static int HexDigitValue(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::string UrlDecode(std::string_view encoded) {
    std::string result;
    result.reserve(encoded.size());

    for (size_t i = 0; i < encoded.size(); ++i) {
        if (encoded[i] == '%' && i + 2 < encoded.size()) {
            int hi = HexDigitValue(encoded[i + 1]);
            int lo = HexDigitValue(encoded[i + 2]);
            if (hi >= 0 && lo >= 0) {
                result += static_cast<char>((hi << 4) | lo);
                i += 2;
                continue;
            }
        } else if (encoded[i] == '+') {
            result += ' ';
            continue;
        }
        result += encoded[i];
    }
    return result;
}

std::string UrlEncode(std::string_view raw) {
    static constexpr const char* kHex = "0123456789ABCDEF";
    std::string result;
    result.reserve(raw.size() * 3);

    for (unsigned char c : raw) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            result += static_cast<char>(c);
        } else {
            result += '%';
            result += kHex[c >> 4];
            result += kHex[c & 0x0F];
        }
    }
    return result;
}

bool ContainsPathTraversal(std::string_view path) noexcept {
    // Check for ".." segments
    size_t pos = 0;
    while (pos < path.size()) {
        if (path[pos] == '.') {
            if (pos + 1 < path.size() && path[pos + 1] == '.') {
                // Found ".." — check if it's a complete segment
                bool leftBoundary  = (pos == 0 || path[pos - 1] == '/' || path[pos - 1] == '\\');
                bool rightBoundary = (pos + 2 >= path.size() || path[pos + 2] == '/' || path[pos + 2] == '\\');
                if (leftBoundary && rightBoundary) return true;
            }
        }
        ++pos;
    }

    // Check for null bytes (poisoning)
    if (path.find('\0') != std::string_view::npos) return true;

    // Check for backslash (Windows path traversal via HTTP)
    if (path.find('\\') != std::string_view::npos) return true;

    return false;
}

// ============================================================================
// StringToHttpMethod
// ============================================================================

HttpMethod StringToHttpMethod(std::string_view method) noexcept {
    if (method.size() < 3 || method.size() > 7) return HttpMethod::Unknown;

    // Fast path: compare first char then full string
    switch (method[0]) {
        case 'G':
            if (method == "GET") return HttpMethod::GET;
            break;
        case 'P':
            if (method == "POST")  return HttpMethod::POST;
            if (method == "PUT")   return HttpMethod::PUT;
            if (method == "PATCH") return HttpMethod::PATCH;
            break;
        case 'D':
            if (method == "DELETE") return HttpMethod::DELETE_;
            break;
        case 'H':
            if (method == "HEAD") return HttpMethod::HEAD;
            break;
        case 'O':
            if (method == "OPTIONS") return HttpMethod::OPTIONS;
            break;
    }
    return HttpMethod::Unknown;
}

} // namespace Http
} // namespace ShadowStrike
