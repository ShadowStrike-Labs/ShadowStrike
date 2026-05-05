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
    // FNV-1a. Use the 64-bit constants when size_t is 64-bit so the
    // hash actually mixes the upper bits; the 32-bit constants leave
    // the upper 32 bits of size_t identically zero, which collapses
    // the unordered_map's bucket distribution on 64-bit Windows.
    if constexpr (sizeof(size_t) >= 8) {
        size_t hash = static_cast<size_t>(0xcbf29ce484222325ULL); // FNV-1a 64 offset
        for (char c : key) {
            const auto lower = static_cast<unsigned char>(
                (c >= 'A' && c <= 'Z') ? (c + ('a' - 'A')) : c);
            hash ^= lower;
            hash *= static_cast<size_t>(0x100000001b3ULL); // FNV-1a 64 prime
        }
        return hash;
    } else {
        size_t hash = 0x811c9dc5u; // FNV-1a 32 offset
        for (char c : key) {
            const auto lower = static_cast<unsigned char>(
                (c >= 'A' && c <= 'Z') ? (c + ('a' - 'A')) : c);
            hash ^= lower;
            hash *= 0x01000193u; // FNV-1a 32 prime
        }
        return hash;
    }
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
        // HTTP/1.1 defaults to keep-alive; HTTP/1.0 defaults to close.
        return httpVersion.find("1.1") != std::string::npos;
    }

    // RFC 7230 §6.1: Connection is a comma-separated list of tokens.
    // A substring match for "close" matches "close-foo" or "x-close" — not
    // RFC compliant and a smuggling/keep-alive desync hazard. Tokenize.
    std::string_view sv(*conn);
    size_t pos = 0;
    while (pos < sv.size()) {
        // Skip leading OWS / commas.
        while (pos < sv.size() && (sv[pos] == ' ' || sv[pos] == '\t' || sv[pos] == ',')) {
            ++pos;
        }
        const size_t start = pos;
        while (pos < sv.size() && sv[pos] != ',') ++pos;
        size_t end = pos;
        // Trim trailing OWS.
        while (end > start && (sv[end - 1] == ' ' || sv[end - 1] == '\t')) --end;

        const auto token = sv.substr(start, end - start);
        if (token.size() == 5) {
            // Case-insensitive compare to "close".
            char buf[5];
            for (size_t i = 0; i < 5; ++i) {
                char c = token[i];
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
                buf[i] = c;
            }
            if (std::memcmp(buf, "close", 5) == 0) return false;
        }
    }
    return true;
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

namespace {

// Internal: append a JSON-escaped UTF-8 string to `out`.
// Escapes per RFC 8259: ", \, control bytes (< 0x20). High-bit bytes are
// passed through; the producer is responsible for valid UTF-8.
void AppendJsonEscaped(std::string& out, std::string_view in) {
    out.reserve(out.size() + in.size() + 2);
    for (char c : in) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x",
                                  static_cast<unsigned>(static_cast<unsigned char>(c)));
                    out += buf;
                } else {
                    out += c;
                }
                break;
        }
    }
}

// Strict response-side header gate. Skips any header that fails name/value
// validation. Centralized so SetHeader, SetContentType and Serialize all
// agree on what is wire-emittable.
[[nodiscard]] bool IsWireSafeHeader(std::string_view name, std::string_view value) noexcept {
    return IsValidHeaderName(name) && IsValidHeaderValue(value);
}

} // namespace

void HttpResponse::SetHeader(std::string name, std::string value) {
    // Defense in depth against response-header injection / response splitting
    // (CWE-113). Reject on construction so a bad value never reaches Serialize.
    if (!IsWireSafeHeader(name, value)) {
        return;
    }
    headers[std::move(name)] = std::move(value);
}

void HttpResponse::SetContentType(std::string_view contentType) {
    if (!IsValidHeaderValue(contentType)) {
        // Fall back to a hardcoded safe default rather than emit a poisoned
        // Content-Type that could enable MIME-confusion or response splitting.
        headers["Content-Type"] = "application/octet-stream";
        return;
    }
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
    AppendJsonEscaped(json, message);
    json += "\"";
    if (!requestId.empty()) {
        // Bug previously: requestId was concatenated raw, allowing JSON
        // injection (and reflected XSS for clients that render the field
        // un-encoded). Always escape.
        json += ",\"request_id\":\"";
        AppendJsonEscaped(json, requestId);
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
    // Build status line
    std::string statusLine = HTTP_VERSION_11;
    statusLine += ' ';
    statusLine += std::to_string(static_cast<uint16_t>(status));
    statusLine += ' ';
    statusLine += HttpStatusReasonPhrase(status);
    statusLine += CRLF;

    // Build header block.
    //
    // Security: we MUST emit a single, truthful Content-Length matching the
    // exact body byte count and we MUST never emit Transfer-Encoding. A
    // caller-supplied Content-Length that disagrees with body.size() is the
    // textbook HTTP request-smuggling primitive (CWE-444); a caller-supplied
    // Transfer-Encoding combined with our Content-Length triggers TE.CL
    // smuggling. Strip both unconditionally, then re-add Content-Length below.
    //
    // Each header is also re-validated here as a defence-in-depth gate against
    // CWE-113 response splitting; SetHeader already rejects bad values, but
    // the headers map is publicly mutable so we must not trust its current
    // contents at the wire boundary.
    std::string headerBlock;
    headerBlock.reserve(512);

    for (const auto& [key, val] : headers) {
        if (CaseInsensitiveEqual{}(key, "Content-Length")) continue;
        if (CaseInsensitiveEqual{}(key, "Transfer-Encoding")) continue;
        if (!IsWireSafeHeader(key, val)) continue;

        headerBlock += key;
        headerBlock += ": ";
        headerBlock += val;
        headerBlock += CRLF;
    }

    headerBlock += "Content-Length: ";
    headerBlock += std::to_string(body.size());
    headerBlock += CRLF;

    // Terminate header block.
    headerBlock += CRLF;

    // Cap final size sanity-check: status line + headers + body must not
    // exceed SIZE_MAX. Practically impossible at this scale but cheap to
    // guard against a future caller pushing a huge body and headers map.
    const size_t headerBytes = statusLine.size() + headerBlock.size();
    if (body.size() > SIZE_MAX - headerBytes) {
        return {};
    }
    const size_t totalSize = headerBytes + body.size();

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
// Header Name / Value Validation (RFC 7230)
// ============================================================================

bool IsValidHeaderName(std::string_view name) noexcept {
    if (name.empty() || name.size() > MAX_HEADER_LINE_LENGTH) return false;
    // RFC 7230 token: 1*tchar
    //   tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "."
    //         / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
    for (unsigned char c : name) {
        const bool isAlpha = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
        const bool isDigit = (c >= '0' && c <= '9');
        const bool isOther =
            c == '!' || c == '#' || c == '$' || c == '%' || c == '&' ||
            c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' ||
            c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
        if (!isAlpha && !isDigit && !isOther) return false;
    }
    return true;
}

bool IsValidHeaderValue(std::string_view value) noexcept {
    if (value.size() > MAX_HEADER_LINE_LENGTH) return false;
    // RFC 7230 §3.2: field-value contains VCHAR / SP / HTAB / obs-text.
    // Reject CR, LF, NUL and other C0 controls (except HTAB) — these enable
    // header injection / response splitting (CWE-113).
    for (unsigned char c : value) {
        if (c == '\r' || c == '\n' || c == '\0') return false;
        if (c < 0x20 && c != '\t') return false;
        if (c == 0x7F) return false; // DEL
    }
    return true;
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
