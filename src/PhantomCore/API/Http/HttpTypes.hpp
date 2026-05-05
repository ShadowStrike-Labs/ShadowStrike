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
 * ShadowStrike NGAV - HTTP TYPES
 * ============================================================================
 *
 * @file HttpTypes.hpp
 * @brief Shared types for the ShadowStrike embedded HTTP server.
 *
 * Defines HTTP methods, status codes, headers, request/response structures
 * used by HttpServer and RESTServer.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. Licensed under AGPL-3.0-or-later.
 * ============================================================================
 */

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <optional>
#include <chrono>
#include <functional>

namespace ShadowStrike {
namespace Http {

// ============================================================================
// CONSTANTS
// ============================================================================

/// Maximum HTTP header line length (8 KB — prevents DoS via huge headers)
inline constexpr size_t MAX_HEADER_LINE_LENGTH = 8192;

/// Maximum total headers size (64 KB)
inline constexpr size_t MAX_HEADERS_TOTAL_SIZE = 65536;

/// Maximum number of HTTP headers per request
inline constexpr size_t MAX_HEADER_COUNT = 100;

/// Maximum URL length (8 KB)
inline constexpr size_t MAX_URL_LENGTH = 8192;

/// Maximum HTTP method length
inline constexpr size_t MAX_METHOD_LENGTH = 16;

/// Default read buffer size per connection (4 KB)
inline constexpr size_t DEFAULT_READ_BUFFER_SIZE = 4096;

/// Maximum request body size (default, overridable)
inline constexpr size_t DEFAULT_MAX_BODY_SIZE = 1ULL * 1024 * 1024;

/// HTTP/1.1 version string
inline constexpr const char* HTTP_VERSION_11 = "HTTP/1.1";

/// CRLF line terminator
inline constexpr const char* CRLF = "\r\n";

/// Header/body separator
inline constexpr const char* HEADER_BODY_SEPARATOR = "\r\n\r\n";

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief HTTP request methods
 */
enum class HttpMethod : uint8_t {
    Unknown = 0,
    GET     = 1,
    POST    = 2,
    PUT     = 3,
    DELETE_ = 4,    // DELETE is a Windows macro
    PATCH   = 5,
    HEAD    = 6,
    OPTIONS = 7
};

/**
 * @brief HTTP response status codes
 */
enum class HttpStatus : uint16_t {
    // 2xx Success
    OK                  = 200,
    Created             = 201,
    Accepted            = 202,
    NoContent           = 204,

    // 3xx Redirection
    MovedPermanently    = 301,
    Found               = 302,
    NotModified         = 304,

    // 4xx Client errors
    BadRequest          = 400,
    Unauthorized        = 401,
    Forbidden           = 403,
    NotFound            = 404,
    MethodNotAllowed    = 405,
    RequestTimeout      = 408,
    Conflict            = 409,
    PayloadTooLarge     = 413,
    URITooLong          = 414,
    UnsupportedMedia    = 415,
    TooManyRequests     = 429,

    // 5xx Server errors
    InternalError       = 500,
    NotImplemented      = 501,
    ServiceUnavailable  = 503
};

/**
 * @brief Connection state for keep-alive tracking
 */
enum class ConnectionState : uint8_t {
    Reading     = 0,    ///< Waiting for / receiving request data
    Processing  = 1,    ///< Request dispatched to handler
    Writing     = 2,    ///< Sending response
    KeepAlive   = 3,    ///< Awaiting next request on same connection
    Closing     = 4     ///< Draining and closing
};

// ============================================================================
// HEADER MAP
// ============================================================================

/**
 * @brief Case-insensitive header map.
 *
 * HTTP headers are case-insensitive per RFC 7230 §3.2.
 * We store the original casing but compare case-insensitively.
 */
struct CaseInsensitiveHash {
    [[nodiscard]] size_t operator()(std::string_view key) const noexcept;
};

struct CaseInsensitiveEqual {
    [[nodiscard]] bool operator()(std::string_view a, std::string_view b) const noexcept;
};

using HeaderMap = std::unordered_map<
    std::string, std::string,
    CaseInsensitiveHash, CaseInsensitiveEqual>;

// ============================================================================
// REQUEST / RESPONSE
// ============================================================================

/**
 * @brief Parsed HTTP request
 */
struct HttpRequest {
    HttpMethod method = HttpMethod::Unknown;
    std::string path;                   ///< URL path (decoded, no query)
    std::string queryString;            ///< Raw query string after '?'
    std::string httpVersion;            ///< e.g. "HTTP/1.1"
    HeaderMap headers;
    std::vector<uint8_t> body;
    std::string remoteAddress;          ///< Peer IP (always 127.0.0.1 for us)
    uint16_t remotePort = 0;
    std::chrono::steady_clock::time_point receivedAt;

    /// @brief Get a header value (case-insensitive)
    [[nodiscard]] std::optional<std::string_view> GetHeader(std::string_view name) const noexcept;

    /// @brief Get the Content-Type header
    [[nodiscard]] std::optional<std::string_view> GetContentType() const noexcept;

    /// @brief Get Content-Length (parsed, validated)
    [[nodiscard]] std::optional<size_t> GetContentLength() const noexcept;

    /// @brief Check if connection should be kept alive
    [[nodiscard]] bool IsKeepAlive() const noexcept;

    /// @brief Get the body as a string_view
    [[nodiscard]] std::string_view GetBodyString() const noexcept;

    /// @brief Parse query string parameters
    [[nodiscard]] std::unordered_map<std::string, std::string> ParseQueryParams() const;

    /// @brief Get a specific query parameter
    [[nodiscard]] std::optional<std::string> GetQueryParam(std::string_view name) const;

    /// @brief Get a path parameter extracted by route matching
    std::unordered_map<std::string, std::string> pathParams;
};

/**
 * @brief HTTP response to send
 */
struct HttpResponse {
    HttpStatus status = HttpStatus::OK;
    HeaderMap headers;
    std::vector<uint8_t> body;

    /// @brief Set a header
    void SetHeader(std::string name, std::string value);

    /// @brief Set Content-Type
    void SetContentType(std::string_view contentType);

    /// @brief Set the body from a string
    void SetBody(std::string_view text);

    /// @brief Set the body from raw bytes
    void SetBody(const uint8_t* data, size_t length);

    /// @brief Set the body from a vector
    void SetBody(std::vector<uint8_t> data);

    /// @brief Set JSON body (sets Content-Type automatically)
    void SetJsonBody(std::string_view json);

    /// @brief Build a complete error JSON response
    static HttpResponse MakeError(HttpStatus status, std::string_view message,
                                  std::string_view requestId = {});

    /// @brief Build a JSON success response
    static HttpResponse MakeJson(HttpStatus status, std::string_view json);

    /// @brief Serialize to wire format (status line + headers + body)
    [[nodiscard]] std::vector<uint8_t> Serialize() const;
};

// ============================================================================
// ROUTE HANDLER
// ============================================================================

/**
 * @brief Route handler function signature.
 *
 * The handler receives a parsed request and must fill the response.
 * Return value is ignored — set response.status for HTTP status.
 */
using RequestHandler = std::function<void(const HttpRequest& request, HttpResponse& response)>;

/**
 * @brief Middleware function signature.
 *
 * Middlewares can inspect/modify the request, and optionally short-circuit
 * by returning false (which means "do not call the next handler").
 */
using Middleware = std::function<bool(const HttpRequest& request, HttpResponse& response)>;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// @brief Convert HttpMethod to string
[[nodiscard]] constexpr const char* HttpMethodToString(HttpMethod method) noexcept;

/// @brief Parse method string to enum
[[nodiscard]] HttpMethod StringToHttpMethod(std::string_view method) noexcept;

/// @brief Get the standard reason phrase for a status code
[[nodiscard]] constexpr const char* HttpStatusReasonPhrase(HttpStatus status) noexcept;

/// @brief URL-decode a percent-encoded string
[[nodiscard]] std::string UrlDecode(std::string_view encoded);

/// @brief URL-encode a string
[[nodiscard]] std::string UrlEncode(std::string_view raw);

/// @brief Check if a path contains traversal attempts (e.g., "..")
[[nodiscard]] bool ContainsPathTraversal(std::string_view path) noexcept;

/**
 * @brief Validate an HTTP header field name per RFC 7230 §3.2.6 (token).
 *
 * Rejects empty names and any byte not in the RFC token set. Used as the
 * primary defense against response-header injection / response splitting.
 */
[[nodiscard]] bool IsValidHeaderName(std::string_view name) noexcept;

/**
 * @brief Validate an HTTP header field value (RFC 7230 §3.2 field-content).
 *
 * Rejects CR, LF, NUL and other control bytes that would allow CRLF injection
 * or smuggling on the response wire. Tabs are permitted (RFC field-vchar).
 */
[[nodiscard]] bool IsValidHeaderValue(std::string_view value) noexcept;

// ============================================================================
// INLINE IMPLEMENTATIONS
// ============================================================================

constexpr const char* HttpMethodToString(HttpMethod method) noexcept {
    switch (method) {
        case HttpMethod::GET:       return "GET";
        case HttpMethod::POST:      return "POST";
        case HttpMethod::PUT:       return "PUT";
        case HttpMethod::DELETE_:   return "DELETE";
        case HttpMethod::PATCH:     return "PATCH";
        case HttpMethod::HEAD:      return "HEAD";
        case HttpMethod::OPTIONS:   return "OPTIONS";
        default:                    return "UNKNOWN";
    }
}

constexpr const char* HttpStatusReasonPhrase(HttpStatus status) noexcept {
    switch (status) {
        case HttpStatus::OK:                    return "OK";
        case HttpStatus::Created:               return "Created";
        case HttpStatus::Accepted:              return "Accepted";
        case HttpStatus::NoContent:             return "No Content";
        case HttpStatus::MovedPermanently:      return "Moved Permanently";
        case HttpStatus::Found:                 return "Found";
        case HttpStatus::NotModified:           return "Not Modified";
        case HttpStatus::BadRequest:            return "Bad Request";
        case HttpStatus::Unauthorized:          return "Unauthorized";
        case HttpStatus::Forbidden:             return "Forbidden";
        case HttpStatus::NotFound:              return "Not Found";
        case HttpStatus::MethodNotAllowed:      return "Method Not Allowed";
        case HttpStatus::RequestTimeout:        return "Request Timeout";
        case HttpStatus::Conflict:              return "Conflict";
        case HttpStatus::PayloadTooLarge:       return "Payload Too Large";
        case HttpStatus::URITooLong:            return "URI Too Long";
        case HttpStatus::UnsupportedMedia:      return "Unsupported Media Type";
        case HttpStatus::TooManyRequests:       return "Too Many Requests";
        case HttpStatus::InternalError:         return "Internal Server Error";
        case HttpStatus::NotImplemented:        return "Not Implemented";
        case HttpStatus::ServiceUnavailable:    return "Service Unavailable";
        default:                                return "Unknown";
    }
}

} // namespace Http
} // namespace ShadowStrike
