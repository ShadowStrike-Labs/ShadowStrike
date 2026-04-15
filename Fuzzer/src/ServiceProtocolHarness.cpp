// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
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
 * @file ServiceProtocolHarness.cpp
 * @brief Implementation of the embedded HTTP service protocol fuzz harness.
 */

#include "ShadowStrike/Fuzzer/Harnesses/ServiceProtocolHarness.hpp"

#include "ShadowStrike/Fuzzer/Core/FuzzLoop.hpp"
#include "PhantomCore/API/Http/HttpServer.hpp"
#include "PhantomCore/API/Http/HttpTypes.hpp"

#include <nlohmann/json.hpp>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
#include <exception>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ShadowStrike::Fuzzer {
namespace {

namespace SSHttp = ShadowStrike::Http;
using Json = nlohmann::json;

constexpr uint16_t kMinHarnessPort = 20000;
constexpr uint16_t kMaxHarnessPort = 52000;
constexpr size_t kPortRange = static_cast<size_t>(kMaxHarnessPort - kMinHarnessPort);
constexpr DWORD kSocketTimeoutMs = 200;
constexpr auto kServerReadyTimeout = std::chrono::milliseconds(2000);
constexpr auto kStatsWaitTimeout = std::chrono::milliseconds(250);
constexpr auto kInterFragmentDelayBase = std::chrono::milliseconds(2);
constexpr size_t kMaxWireBytes = 64ULL * 1024;
constexpr size_t kMaxResponseBytes = 256ULL * 1024;
constexpr size_t kMaxJsonDepth = 8;
constexpr size_t kMaxRouteTokenSize = 48;
constexpr size_t kMaxHeaderValueSize = 96;
constexpr size_t kMaxPathEntries = 8;

enum class Scenario : uint8_t {
    RawMutation = 0,
    Health = 1,
    Preflight = 2,
    Login = 3,
    Config = 4,
    Scan = 5,
    ThreatLookup = 6,
    KeepAlive = 7,
    Sse = 8,
    TruncatedBody = 9
};

struct ProtocolInput {
    Scenario scenario = Scenario::Health;
    uint8_t fragmentMode = 0;
    uint8_t optionFlags = 0;
    uint8_t interFragmentDelayMs = 0;
    std::span<const uint8_t> payload{};
};

struct SocketHandle {
    SOCKET value = INVALID_SOCKET;

    SocketHandle() noexcept = default;
    explicit SocketHandle(const SOCKET socket) noexcept : value(socket) {}

    SocketHandle(const SocketHandle&) = delete;
    SocketHandle& operator=(const SocketHandle&) = delete;

    SocketHandle(SocketHandle&& other) noexcept : value(other.value) {
        other.value = INVALID_SOCKET;
    }

    SocketHandle& operator=(SocketHandle&& other) noexcept {
        if (this != &other) {
            Reset();
            value = other.value;
            other.value = INVALID_SOCKET;
        }
        return *this;
    }

    ~SocketHandle() {
        Reset();
    }

    [[nodiscard]] bool IsValid() const noexcept {
        return value != INVALID_SOCKET;
    }

    void Reset() noexcept {
        if (value != INVALID_SOCKET) {
            ::closesocket(value);
            value = INVALID_SOCKET;
        }
    }
};

struct HarnessState {
    std::shared_mutex rateLimitLock;
    std::unordered_map<std::string, std::deque<std::chrono::steady_clock::time_point>> rateWindows;
    std::atomic<uint64_t> requestSequence{0};
    const std::string authToken = "fuzz-token";
    const std::string csrfToken = "fuzz-csrf";
};

struct ServerFixture {
    SSHttp::HttpServer server;
    std::shared_ptr<HarnessState> state;
    bool started = false;

    ~ServerFixture() {
        if (started) {
            server.Stop();
        }
        if (server.IsInitialized()) {
            server.Shutdown();
        }
    }
};

[[nodiscard]] std::mutex& HarnessMutex() {
    static std::mutex mutex;
    return mutex;
}

[[nodiscard]] std::unique_ptr<ServerFixture>& HarnessServer() {
    static std::unique_ptr<ServerFixture> fixture;
    return fixture;
}

std::string ExceptionCodeToStringInternal(const DWORD code) {
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:         return "EXCEPTION_ACCESS_VIOLATION";
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
    case EXCEPTION_BREAKPOINT:               return "EXCEPTION_BREAKPOINT";
    case EXCEPTION_DATATYPE_MISALIGNMENT:    return "EXCEPTION_DATATYPE_MISALIGNMENT";
    case EXCEPTION_FLT_DENORMAL_OPERAND:     return "EXCEPTION_FLT_DENORMAL_OPERAND";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:       return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
    case EXCEPTION_FLT_INEXACT_RESULT:       return "EXCEPTION_FLT_INEXACT_RESULT";
    case EXCEPTION_FLT_INVALID_OPERATION:    return "EXCEPTION_FLT_INVALID_OPERATION";
    case EXCEPTION_FLT_OVERFLOW:             return "EXCEPTION_FLT_OVERFLOW";
    case EXCEPTION_FLT_STACK_CHECK:          return "EXCEPTION_FLT_STACK_CHECK";
    case EXCEPTION_FLT_UNDERFLOW:            return "EXCEPTION_FLT_UNDERFLOW";
    case EXCEPTION_GUARD_PAGE:               return "EXCEPTION_GUARD_PAGE";
    case EXCEPTION_ILLEGAL_INSTRUCTION:      return "EXCEPTION_ILLEGAL_INSTRUCTION";
    case EXCEPTION_IN_PAGE_ERROR:            return "EXCEPTION_IN_PAGE_ERROR";
    case EXCEPTION_INT_DIVIDE_BY_ZERO:       return "EXCEPTION_INT_DIVIDE_BY_ZERO";
    case EXCEPTION_INT_OVERFLOW:             return "EXCEPTION_INT_OVERFLOW";
    case EXCEPTION_INVALID_DISPOSITION:      return "EXCEPTION_INVALID_DISPOSITION";
    case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "EXCEPTION_NONCONTINUABLE_EXCEPTION";
    case EXCEPTION_PRIV_INSTRUCTION:         return "EXCEPTION_PRIV_INSTRUCTION";
    case EXCEPTION_SINGLE_STEP:              return "EXCEPTION_SINGLE_STEP";
    case EXCEPTION_STACK_OVERFLOW:           return "EXCEPTION_STACK_OVERFLOW";
    case STATUS_HEAP_CORRUPTION:             return "STATUS_HEAP_CORRUPTION";
    default: {
        char buffer[32]{};
        std::snprintf(buffer, sizeof(buffer), "EXCEPTION_0x%08lX", code);
        return buffer;
    }
    }
}

void CaptureFirstIssue(HarnessResult& result, std::string_view message) {
    if (result.errorMessage.empty()) {
        result.errorMessage.assign(message.data(), message.size());
    }
}

void RecordValidationIssue(HarnessResult& result, std::string_view message) {
    ++result.validationIssueCount;
    CaptureFirstIssue(result, message);
}

void RecordAnomaly(HarnessResult& result, std::string_view message) {
    ++result.anomalyCount;
    CaptureFirstIssue(result, message);
}

[[nodiscard]] std::span<const uint8_t> Slice(
    const std::span<const uint8_t> input,
    const size_t offset,
    const size_t count = std::dynamic_extent) noexcept
{
    if (offset >= input.size()) {
        return {};
    }

    const size_t remaining = input.size() - offset;
    return input.subspan(offset, std::min(remaining, count));
}

[[nodiscard]] std::string MakeToken(
    const std::span<const uint8_t> input,
    const std::string_view fallback,
    const size_t maxLength)
{
    static constexpr std::string_view alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-_";
    if (input.empty()) {
        return std::string(fallback);
    }

    std::string token;
    token.reserve(std::min(maxLength, input.size()));
    for (const uint8_t byte : input) {
        if (token.size() >= maxLength) {
            break;
        }
        token.push_back(alphabet[byte % alphabet.size()]);
    }

    if (token.empty()) {
        token.assign(fallback);
    }
    return token;
}

[[nodiscard]] std::string MakeHeaderValue(
    const std::span<const uint8_t> input,
    const std::string_view fallback,
    const size_t maxLength)
{
    if (input.empty()) {
        return std::string(fallback);
    }

    std::string value;
    value.reserve(std::min(maxLength, input.size()));
    for (const uint8_t byte : input) {
        if (value.size() >= maxLength) {
            break;
        }

        const char ch = static_cast<char>(0x20 + (byte % 95));
        if (ch == '\r' || ch == '\n') {
            value.push_back(' ');
        } else {
            value.push_back(ch);
        }
    }

    if (value.empty()) {
        value.assign(fallback);
    }
    return value;
}

[[nodiscard]] uint32_t Fnv1a32(const std::span<const uint8_t> input) noexcept {
    uint32_t hash = 2166136261u;
    for (const uint8_t byte : input) {
        hash ^= byte;
        hash *= 16777619u;
    }
    return hash;
}

[[nodiscard]] ProtocolInput DecodeInput(const std::span<const uint8_t> input) noexcept {
    ProtocolInput decoded{};
    if (input.empty()) {
        return decoded;
    }

    decoded.scenario = static_cast<Scenario>(input[0] % 10);
    decoded.fragmentMode = (input.size() > 1) ? static_cast<uint8_t>(input[1] % 5) : 0;
    decoded.optionFlags = (input.size() > 2) ? input[2] : 0;
    decoded.interFragmentDelayMs = (input.size() > 3) ? static_cast<uint8_t>(input[3] % 4) : 0;
    decoded.payload = Slice(input, 4);
    return decoded;
}

[[nodiscard]] uint16_t DeriveBasePort(const std::span<const uint8_t> input) noexcept {
    const uint32_t hash = input.empty() ? 0xC0FFEE11u : Fnv1a32(input);
    return static_cast<uint16_t>(kMinHarnessPort + (hash % kPortRange));
}

[[nodiscard]] bool SetSocketTimeouts(const SOCKET socket) noexcept {
    const DWORD timeout = kSocketTimeoutMs;
    return ::setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0 &&
           ::setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == 0;
}

[[nodiscard]] std::optional<SocketHandle> ConnectLocalhost(const uint16_t port) {
    const SOCKET socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket == INVALID_SOCKET) {
        return std::nullopt;
    }

    SocketHandle handle(socket);
    if (!SetSocketTimeouts(handle.value)) {
        return std::nullopt;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (::connect(handle.value, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        return std::nullopt;
    }

    return handle;
}

[[nodiscard]] bool WaitForServerReady(const uint16_t port) {
    const auto deadline = std::chrono::steady_clock::now() + kServerReadyTimeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (auto probe = ConnectLocalhost(port); probe.has_value()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
}

void AppendHeader(std::string& request, std::string_view name, std::string_view value) {
    request.append(name);
    request.append(": ");
    request.append(value);
    request.append(SSHttp::CRLF);
}

[[nodiscard]] std::string BuildRequest(
    std::string_view method,
    std::string_view target,
    const std::vector<std::pair<std::string, std::string>>& headers,
    std::string_view body)
{
    std::string request;
    request.reserve(target.size() + body.size() + 256);
    request.append(method);
    request.push_back(' ');
    request.append(target);
    request.append(" HTTP/1.1");
    request.append(SSHttp::CRLF);
    AppendHeader(request, "Host", "127.0.0.1");
    for (const auto& [name, value] : headers) {
        AppendHeader(request, name, value);
    }
    if (!body.empty()) {
        AppendHeader(request, "Content-Length", std::to_string(body.size()));
    }
    request.append(SSHttp::CRLF);
    request.append(body);
    return request;
}

[[nodiscard]] std::vector<std::vector<uint8_t>> FragmentRequest(
    const std::vector<uint8_t>& request,
    const ProtocolInput& input)
{
    if (request.empty()) {
        return {};
    }

    std::vector<std::vector<uint8_t>> fragments;
    switch (input.fragmentMode) {
    case 0:
        fragments.push_back(request);
        break;
    case 1: {
        const size_t pivot = request.size() / 2;
        fragments.emplace_back(request.begin(), request.begin() + static_cast<std::ptrdiff_t>(pivot));
        fragments.emplace_back(request.begin() + static_cast<std::ptrdiff_t>(pivot), request.end());
        break;
    }
    case 2: {
        size_t offset = 0;
        while (offset < request.size()) {
            const size_t chunk = std::min<size_t>(1 + (offset % 7), request.size() - offset);
            fragments.emplace_back(
                request.begin() + static_cast<std::ptrdiff_t>(offset),
                request.begin() + static_cast<std::ptrdiff_t>(offset + chunk));
            offset += chunk;
        }
        break;
    }
    case 3: {
        const std::string_view wire(
            reinterpret_cast<const char*>(request.data()),
            request.size());
        const size_t split = wire.find(SSHttp::HEADER_BODY_SEPARATOR);
        if (split != std::string_view::npos) {
            const size_t bodyOffset = split + std::strlen(SSHttp::HEADER_BODY_SEPARATOR);
            fragments.emplace_back(request.begin(), request.begin() + static_cast<std::ptrdiff_t>(bodyOffset));
            if (bodyOffset < request.size()) {
                fragments.emplace_back(request.begin() + static_cast<std::ptrdiff_t>(bodyOffset), request.end());
            }
        } else {
            fragments.push_back(request);
        }
        break;
    }
    default: {
        const std::span<const uint8_t> plan = input.payload;
        size_t offset = 0;
        size_t planIndex = 0;
        while (offset < request.size()) {
            const size_t chunk = plan.empty()
                ? std::min<size_t>(8, request.size() - offset)
                : std::min<size_t>(1 + (plan[planIndex % plan.size()] % 11), request.size() - offset);
            fragments.emplace_back(
                request.begin() + static_cast<std::ptrdiff_t>(offset),
                request.begin() + static_cast<std::ptrdiff_t>(offset + chunk));
            offset += chunk;
            ++planIndex;
        }
        break;
    }
    }

    fragments.erase(
        std::remove_if(
            fragments.begin(),
            fragments.end(),
            [](const auto& fragment) { return fragment.empty(); }),
        fragments.end());

    if (fragments.empty()) {
        fragments.push_back(request);
    }
    return fragments;
}

[[nodiscard]] bool SendAll(const SOCKET socket, std::span<const uint8_t> bytes) {
    size_t offset = 0;
    while (offset < bytes.size()) {
        const int sent = ::send(
            socket,
            reinterpret_cast<const char*>(bytes.data() + offset),
            static_cast<int>(std::min<size_t>(INT_MAX, bytes.size() - offset)),
            0);
        if (sent <= 0) {
            return false;
        }
        offset += static_cast<size_t>(sent);
    }
    return true;
}

[[nodiscard]] bool SendFragments(
    const SOCKET socket,
    const std::vector<std::vector<uint8_t>>& fragments,
    const uint8_t interFragmentDelayMs)
{
    for (const auto& fragment : fragments) {
        if (!SendAll(socket, fragment)) {
            return false;
        }
        if (interFragmentDelayMs != 0) {
            std::this_thread::sleep_for(kInterFragmentDelayBase * interFragmentDelayMs);
        }
    }
    return true;
}

[[nodiscard]] std::vector<uint8_t> ReadResponse(const SOCKET socket) {
    std::vector<uint8_t> response;
    response.reserve(4096);
    std::array<uint8_t, 4096> buffer{};

    while (response.size() < kMaxResponseBytes) {
        const int received = ::recv(
            socket,
            reinterpret_cast<char*>(buffer.data()),
            static_cast<int>(buffer.size()),
            0);
        if (received > 0) {
            response.insert(response.end(), buffer.begin(), buffer.begin() + received);
            continue;
        }

        if (received == 0) {
            break;
        }

        const int error = ::WSAGetLastError();
        if (error == WSAETIMEDOUT || error == WSAEWOULDBLOCK) {
            break;
        }
        break;
    }

    return response;
}

[[nodiscard]] std::optional<unsigned> ParseStatusCode(const std::vector<uint8_t>& response) {
    const std::string_view view(reinterpret_cast<const char*>(response.data()), response.size());
    const size_t lineEnd = view.find(SSHttp::CRLF);
    if (lineEnd == std::string_view::npos) {
        return std::nullopt;
    }

    const std::string_view line = view.substr(0, lineEnd);
    const size_t firstSpace = line.find(' ');
    if (firstSpace == std::string_view::npos || firstSpace + 1 >= line.size()) {
        return std::nullopt;
    }

    unsigned statusCode = 0;
    const auto statusView = line.substr(firstSpace + 1, 3);
    const auto [ptr, ec] = std::from_chars(statusView.data(), statusView.data() + statusView.size(), statusCode);
    if (ec != std::errc{} || ptr != statusView.data() + statusView.size()) {
        return std::nullopt;
    }
    return statusCode;
}

[[nodiscard]] size_t CountStatusLines(const std::vector<uint8_t>& response) noexcept {
    const std::string_view view(reinterpret_cast<const char*>(response.data()), response.size());
    size_t count = 0;
    size_t position = 0;
    while ((position = view.find("HTTP/1.1 ", position)) != std::string_view::npos) {
        ++count;
        position += 9;
    }
    return count;
}

[[nodiscard]] bool ResponseContains(std::span<const uint8_t> response, std::string_view token) noexcept {
    if (response.empty() || token.empty()) {
        return false;
    }
    const std::string_view view(reinterpret_cast<const char*>(response.data()), response.size());
    return view.find(token) != std::string_view::npos;
}

[[nodiscard]] bool StatsAdvanced(
    const SSHttp::HttpServerStats::Snapshot& before,
    const SSHttp::HttpServerStats::Snapshot& after) noexcept
{
    return after.totalConnections > before.totalConnections ||
           after.totalRequests > before.totalRequests ||
           after.totalResponses > before.totalResponses ||
           after.parseErrors > before.parseErrors ||
           after.bytesReceived > before.bytesReceived ||
           after.bytesSent > before.bytesSent;
}

[[nodiscard]] SSHttp::HttpServerStats::Snapshot WaitForStats(
    SSHttp::HttpServer& server,
    const SSHttp::HttpServerStats::Snapshot& before)
{
    const auto deadline = std::chrono::steady_clock::now() + kStatsWaitTimeout;
    SSHttp::HttpServerStats::Snapshot after = server.GetStats();
    while (!StatsAdvanced(before, after) && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        after = server.GetStats();
    }
    return after;
}

[[nodiscard]] size_t MeasureJsonDepth(const Json& value, const size_t depth = 1) {
    if (!value.is_array() && !value.is_object()) {
        return depth;
    }

    size_t maxDepth = depth;
    if (value.is_array()) {
        for (const auto& element : value) {
            maxDepth = std::max(maxDepth, MeasureJsonDepth(element, depth + 1));
        }
        return maxDepth;
    }

    for (const auto& [key, element] : value.items()) {
        (void)key;
        maxDepth = std::max(maxDepth, MeasureJsonDepth(element, depth + 1));
    }
    return maxDepth;
}

[[nodiscard]] bool IsLocalOrigin(std::string_view origin) noexcept {
    return origin == "http://localhost" ||
           origin == "http://127.0.0.1" ||
           origin == "http://127.0.0.1:9443";
}

[[nodiscard]] bool IsPublicEndpoint(std::string_view path) noexcept {
    return path == "/api/v1/health" ||
           path == "/api/v1/auth/login" ||
           path == "/api/v1/events/stream";
}

[[nodiscard]] bool TryParseJsonRequest(
    const SSHttp::HttpRequest& request,
    const size_t maxBodyBytes,
    const size_t maxDepth,
    Json& parsed,
    SSHttp::HttpResponse& response)
{
    const auto contentType = request.GetContentType();
    if (!contentType || contentType->find("application/json") == std::string_view::npos) {
        response = SSHttp::HttpResponse::MakeError(
            SSHttp::HttpStatus::UnsupportedMedia,
            "application/json request body required");
        return false;
    }

    if (request.body.empty()) {
        response = SSHttp::HttpResponse::MakeError(
            SSHttp::HttpStatus::BadRequest,
            "request body must not be empty");
        return false;
    }

    if (request.body.size() > maxBodyBytes) {
        response = SSHttp::HttpResponse::MakeError(
            SSHttp::HttpStatus::PayloadTooLarge,
            "request body exceeds harness limit");
        return false;
    }

    parsed = Json::parse(request.GetBodyString(), nullptr, false);
    if (parsed.is_discarded()) {
        response = SSHttp::HttpResponse::MakeError(
            SSHttp::HttpStatus::BadRequest,
            "malformed JSON body");
        return false;
    }

    if (MeasureJsonDepth(parsed) > maxDepth) {
        response = SSHttp::HttpResponse::MakeError(
            SSHttp::HttpStatus::BadRequest,
            "JSON nesting depth exceeds harness limit");
        return false;
    }

    return true;
}

void RegisterRoutes(SSHttp::HttpServer& server, const std::shared_ptr<HarnessState>& state) {
    server.Use([state](const SSHttp::HttpRequest& request, SSHttp::HttpResponse& response) -> bool {
        response.SetHeader("X-Content-Type-Options", "nosniff");
        response.SetHeader("X-Frame-Options", "DENY");
        response.SetHeader("Cache-Control", "no-store");
        response.SetHeader(
            "X-Request-Id",
            "svc-" + std::to_string(state->requestSequence.fetch_add(1, std::memory_order_relaxed) + 1));
        return true;
    });

    server.Use([](const SSHttp::HttpRequest& request, SSHttp::HttpResponse& response) -> bool {
        const auto origin = request.GetHeader("Origin");
        if (origin.has_value()) {
            response.SetHeader("Vary", "Origin");
            response.SetHeader(
                "Access-Control-Allow-Origin",
                IsLocalOrigin(*origin) ? std::string(*origin) : "null");
        }

        if (request.method == SSHttp::HttpMethod::OPTIONS) {
            response.status = SSHttp::HttpStatus::NoContent;
            response.SetHeader("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS");
            response.SetHeader("Access-Control-Allow-Headers", "Authorization, Content-Type, X-CSRF-Token");
            response.SetHeader("Access-Control-Max-Age", "60");
            return false;
        }
        return true;
    });

    server.Use([state](const SSHttp::HttpRequest& request, SSHttp::HttpResponse& response) -> bool {
        const auto now = std::chrono::steady_clock::now();
        std::unique_lock lock(state->rateLimitLock);
        auto& window = state->rateWindows[request.remoteAddress.empty() ? "127.0.0.1" : request.remoteAddress];
        while (!window.empty() && (now - window.front()) > std::chrono::seconds(1)) {
            window.pop_front();
        }
        if (window.size() >= 8) {
            response = SSHttp::HttpResponse::MakeError(
                SSHttp::HttpStatus::TooManyRequests,
                "rate limit exceeded");
            return false;
        }
        window.push_back(now);
        return true;
    });

    server.Use([state](const SSHttp::HttpRequest& request, SSHttp::HttpResponse& response) -> bool {
        if (IsPublicEndpoint(request.path)) {
            return true;
        }

        const auto authHeader = request.GetHeader("Authorization");
        const std::string expectedAuth = "Bearer " + state->authToken;
        if (!authHeader || *authHeader != std::string_view(expectedAuth)) {
            response = SSHttp::HttpResponse::MakeError(
                SSHttp::HttpStatus::Unauthorized,
                "missing or invalid bearer token");
            response.SetHeader("WWW-Authenticate", "Bearer");
            return false;
        }

        if (request.method == SSHttp::HttpMethod::POST ||
            request.method == SSHttp::HttpMethod::PUT ||
            request.method == SSHttp::HttpMethod::PATCH ||
            request.method == SSHttp::HttpMethod::DELETE_) {
            const auto csrf = request.GetHeader("X-CSRF-Token");
            if (!csrf || *csrf != std::string_view(state->csrfToken)) {
                response = SSHttp::HttpResponse::MakeError(
                    SSHttp::HttpStatus::Forbidden,
                    "missing or invalid CSRF token");
                return false;
            }
        }

        return true;
    });

    server.Get("/api/v1/health", [](const SSHttp::HttpRequest& request, SSHttp::HttpResponse& response) {
        Json payload{
            {"status", "ok"},
            {"keep_alive", request.IsKeepAlive()},
            {"path_traversal", SSHttp::ContainsPathTraversal(request.path)},
            {"query_count", request.ParseQueryParams().size()}
        };
        if (const auto echo = request.GetQueryParam("echo"); echo.has_value()) {
            payload["echo"] = echo->substr(0, 32);
        }
        response = SSHttp::HttpResponse::MakeJson(SSHttp::HttpStatus::OK, payload.dump());
    });

    server.Post("/api/v1/auth/login", [state](const SSHttp::HttpRequest& request, SSHttp::HttpResponse& response) {
        Json body;
        if (!TryParseJsonRequest(request, 32 * 1024, kMaxJsonDepth, body, response)) {
            return;
        }

        if (!body.is_object()) {
            response = SSHttp::HttpResponse::MakeError(
                SSHttp::HttpStatus::BadRequest,
                "login body must be a JSON object");
            return;
        }

        const auto username = body.find("username");
        const auto password = body.find("password");
        if (username == body.end() || password == body.end() ||
            !username->is_string() || !password->is_string()) {
            response = SSHttp::HttpResponse::MakeError(
                SSHttp::HttpStatus::BadRequest,
                "username and password must be present");
            return;
        }

        const std::string user = username->get<std::string>();
        const std::string pass = password->get<std::string>();
        if (user.empty() || pass.empty() || user.size() > 128 || pass.size() > 128) {
            response = SSHttp::HttpResponse::MakeError(
                SSHttp::HttpStatus::Unauthorized,
                "invalid credentials");
            return;
        }

        Json payload{
            {"token", state->authToken},
            {"csrf_token", state->csrfToken},
            {"user", user.substr(0, 64)}
        };
        response = SSHttp::HttpResponse::MakeJson(SSHttp::HttpStatus::OK, payload.dump());
    });

    server.Put("/api/v1/config", [](const SSHttp::HttpRequest& request, SSHttp::HttpResponse& response) {
        Json body;
        if (!TryParseJsonRequest(request, 64 * 1024, kMaxJsonDepth, body, response)) {
            return;
        }

        if (!body.is_object()) {
            response = SSHttp::HttpResponse::MakeError(
                SSHttp::HttpStatus::BadRequest,
                "config body must be an object");
            return;
        }

        const size_t settingCount = body.size();
        if (settingCount > 32) {
            response = SSHttp::HttpResponse::MakeError(
                SSHttp::HttpStatus::BadRequest,
                "too many config entries");
            return;
        }

        Json payload{
            {"updated", settingCount},
            {"status", "accepted"}
        };
        response = SSHttp::HttpResponse::MakeJson(SSHttp::HttpStatus::Accepted, payload.dump());
    });

    server.Post("/api/v1/scan/custom", [](const SSHttp::HttpRequest& request, SSHttp::HttpResponse& response) {
        Json body;
        if (!TryParseJsonRequest(request, 64 * 1024, kMaxJsonDepth, body, response)) {
            return;
        }

        if (!body.is_object() || !body.contains("paths") || !body["paths"].is_array()) {
            response = SSHttp::HttpResponse::MakeError(
                SSHttp::HttpStatus::BadRequest,
                "paths array is required");
            return;
        }

        const Json& paths = body["paths"];
        if (paths.size() > kMaxPathEntries) {
            response = SSHttp::HttpResponse::MakeError(
                SSHttp::HttpStatus::BadRequest,
                "too many path entries");
            return;
        }

        for (const auto& pathValue : paths) {
            if (!pathValue.is_string()) {
                response = SSHttp::HttpResponse::MakeError(
                    SSHttp::HttpStatus::BadRequest,
                    "all paths must be strings");
                return;
            }

            const std::string path = pathValue.get<std::string>();
            if (path.size() > 1024 || SSHttp::ContainsPathTraversal(path)) {
                response = SSHttp::HttpResponse::MakeError(
                    SSHttp::HttpStatus::Forbidden,
                    "path traversal rejected");
                return;
            }
        }

        Json payload{
            {"queued_paths", paths.size()},
            {"status", "queued"}
        };
        response = SSHttp::HttpResponse::MakeJson(SSHttp::HttpStatus::Accepted, payload.dump());
    });

    server.Get("/api/v1/threats/:id", [](const SSHttp::HttpRequest& request, SSHttp::HttpResponse& response) {
        const auto it = request.pathParams.find("id");
        if (it == request.pathParams.end() || it->second.empty() || it->second.size() > kMaxRouteTokenSize) {
            response = SSHttp::HttpResponse::MakeError(
                SSHttp::HttpStatus::BadRequest,
                "invalid threat identifier");
            return;
        }

        if (!std::all_of(it->second.begin(), it->second.end(), [](const char ch) {
                return std::isalnum(static_cast<unsigned char>(ch)) || ch == '-' || ch == '_';
            })) {
            response = SSHttp::HttpResponse::MakeError(
                SSHttp::HttpStatus::BadRequest,
                "threat identifier contains invalid characters");
            return;
        }

        Json payload{
            {"id", it->second},
            {"verbose", request.GetQueryParam("verbose").value_or("false")}
        };
        response = SSHttp::HttpResponse::MakeJson(SSHttp::HttpStatus::OK, payload.dump());
    });

    server.SetSSEEndpoint("/api/v1/events/stream");
}

[[nodiscard]] bool StartServer(
    ServerFixture& fixture,
    const std::span<const uint8_t> input,
    HarnessResult& result)
{
    fixture.state = std::make_shared<HarnessState>();
    const uint16_t preferredPort = DeriveBasePort(input);

    for (size_t attempt = 0; attempt < 32; ++attempt) {
        SSHttp::HttpServer candidate;
        SSHttp::HttpServerConfig config{};
        config.bindAddress = SSHttp::DEFAULT_HTTP_BIND;
        config.port = static_cast<uint16_t>(
            kMinHarnessPort + ((preferredPort - kMinHarnessPort + attempt) % kPortRange));
        config.workerThreads = 2;
        config.maxConnections = 16;
        config.maxBodySize = 128 * 1024;
        config.maxHeaderLineSize = 4096;
        config.maxHeadersTotalSize = 16 * 1024;
        config.maxHeaderCount = 64;
        config.maxUrlLength = 2048;
        config.keepAliveTimeoutSec = 1;
        config.incompleteRequestTimeoutSec = 1;
        config.maxKeepAliveRequests = 8;
        config.serverIdentity.clear();
        config.enableRequestLogging = false;
        config.enableKeepAlive = true;

        if (!candidate.Initialize(config)) {
            continue;
        }

        RegisterRoutes(candidate, fixture.state);
        if (!candidate.Start()) {
            candidate.Shutdown();
            continue;
        }

        if (!WaitForServerReady(config.port)) {
            candidate.Stop();
            candidate.Shutdown();
            continue;
        }

        candidate.ResetStats();
        fixture.server = std::move(candidate);
        fixture.started = true;
        return true;
    }

    RecordValidationIssue(result, "Failed to start embedded HTTP service harness server.");
    return false;
}

[[nodiscard]] bool PrepareServerForIteration(ServerFixture& fixture) {
    {
        std::unique_lock lock(fixture.state->rateLimitLock);
        fixture.state->rateWindows.clear();
    }
    fixture.state->requestSequence.store(0, std::memory_order_relaxed);

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(300);
    while (fixture.server.GetStats().activeConnections != 0 && std::chrono::steady_clock::now() < deadline) {
        if (fixture.server.GetSSEClientCount() != 0) {
            fixture.server.BroadcastSSE("cleanup", R"({"phase":"iteration-reset"})");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    if (fixture.server.GetStats().activeConnections != 0) {
        return false;
    }

    fixture.server.ResetStats();
    return true;
}

[[nodiscard]] bool ObserveScenario(
    SSHttp::HttpServer& server,
    const SSHttp::HttpServerStats::Snapshot& before,
    const std::vector<uint8_t>& response,
    HarnessResult& result,
    std::string_view scenarioName)
{
    const auto after = WaitForStats(server, before);
    const bool observed = StatsAdvanced(before, after) || !response.empty();
    if (!observed) {
        std::string message(scenarioName);
        message += " produced no observable parser or response activity.";
        RecordAnomaly(result, message);
        return false;
    }

    if (after.totalRequests > before.totalRequests ||
        after.parseErrors > before.parseErrors ||
        after.totalResponses > before.totalResponses) {
        result.parsedOk = true;
    }
    return true;
}

[[nodiscard]] bool ExpectStatus(
    const std::vector<uint8_t>& response,
    const std::initializer_list<unsigned> acceptedStatuses,
    HarnessResult& result,
    std::string_view scenarioName)
{
    const auto status = ParseStatusCode(response);
    if (!status.has_value()) {
        std::string message(scenarioName);
        message += " did not return a parseable HTTP status line.";
        RecordValidationIssue(result, message);
        return false;
    }

    if (std::find(acceptedStatuses.begin(), acceptedStatuses.end(), *status) == acceptedStatuses.end()) {
        std::string message(scenarioName);
        message += " returned unexpected status ";
        message += std::to_string(*status);
        message += '.';
        RecordAnomaly(result, message);
        return false;
    }
    return true;
}

[[nodiscard]] bool ExerciseRequest(
    SSHttp::HttpServer& server,
    const ProtocolInput& input,
    const std::vector<uint8_t>& request,
    HarnessResult& result,
    std::string_view scenarioName)
{
    auto client = ConnectLocalhost(server.GetPort());
    if (!client.has_value()) {
        std::string message(scenarioName);
        message += " failed to connect to harness server.";
        RecordValidationIssue(result, message);
        return false;
    }

    const auto before = server.GetStats();
    if (!SendFragments(client->value, FragmentRequest(request, input), input.interFragmentDelayMs)) {
        std::string message(scenarioName);
        message += " failed while sending request fragments.";
        RecordValidationIssue(result, message);
        return false;
    }

    ::shutdown(client->value, SD_SEND);
    const std::vector<uint8_t> response = ReadResponse(client->value);
    return ObserveScenario(server, before, response, result, scenarioName);
}

[[nodiscard]] bool ExerciseRawMutation(
    SSHttp::HttpServer& server,
    const ProtocolInput& input,
    HarnessResult& result)
{
    std::vector<uint8_t> request;
    if (input.payload.empty()) {
        static constexpr std::string_view fallback = "BROKEN / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        request.assign(fallback.begin(), fallback.end());
    } else {
        request.assign(input.payload.begin(), input.payload.begin() + static_cast<std::ptrdiff_t>(
            std::min(input.payload.size(), kMaxWireBytes)));
    }

    return ExerciseRequest(server, input, request, result, "raw-http-mutation");
}

[[nodiscard]] bool ExerciseHealth(
    SSHttp::HttpServer& server,
    const ProtocolInput& input,
    HarnessResult& result)
{
    const std::string echo = SSHttp::UrlEncode(MakeToken(Slice(input.payload, 0, 24), "health", 24));
    const std::string requestText = BuildRequest(
        "GET",
        "/api/v1/health?echo=" + echo,
        {
            {"Connection", "close"},
            {"X-Fuzz-Marker", MakeHeaderValue(Slice(input.payload, 24, 20), "svc-health", kMaxHeaderValueSize)}
        },
        {});
    const std::vector<uint8_t> request(requestText.begin(), requestText.end());

    auto client = ConnectLocalhost(server.GetPort());
    if (!client.has_value()) {
        RecordValidationIssue(result, "health request failed to connect to harness server.");
        return false;
    }

    const auto before = server.GetStats();
    if (!SendFragments(client->value, FragmentRequest(request, input), input.interFragmentDelayMs)) {
        RecordValidationIssue(result, "health request failed while sending request fragments.");
        return false;
    }

    ::shutdown(client->value, SD_SEND);
    const std::vector<uint8_t> response = ReadResponse(client->value);
    const bool observed = ObserveScenario(server, before, response, result, "health-request");
    if (!observed) {
        return false;
    }

    if (!ExpectStatus(response, {200}, result, "health-request")) {
        return false;
    }
    if (!ResponseContains(response, "\"status\":\"ok\"")) {
        RecordValidationIssue(result, "health request response did not include the expected status payload.");
    }
    return true;
}

[[nodiscard]] bool ExercisePreflight(
    SSHttp::HttpServer& server,
    const ProtocolInput& input,
    HarnessResult& result)
{
    const std::string origin = (input.optionFlags & 0x01u) != 0 ? "http://evil.invalid" : "http://localhost";
    const std::string requestText = BuildRequest(
        "OPTIONS",
        "/api/v1/config",
        {
            {"Origin", origin},
            {"Access-Control-Request-Method", "PUT"},
            {"Connection", "close"}
        },
        {});
    const std::vector<uint8_t> request(requestText.begin(), requestText.end());

    auto client = ConnectLocalhost(server.GetPort());
    if (!client.has_value()) {
        RecordValidationIssue(result, "preflight request failed to connect to harness server.");
        return false;
    }

    const auto before = server.GetStats();
    if (!SendFragments(client->value, FragmentRequest(request, input), input.interFragmentDelayMs)) {
        RecordValidationIssue(result, "preflight request failed while sending request fragments.");
        return false;
    }

    ::shutdown(client->value, SD_SEND);
    const std::vector<uint8_t> response = ReadResponse(client->value);
    const bool observed = ObserveScenario(server, before, response, result, "preflight-request");
    if (!observed) {
        return false;
    }

    if (!ExpectStatus(response, {204}, result, "preflight-request")) {
        return false;
    }
    if (!ResponseContains(response, "Access-Control-Allow-Methods")) {
        RecordValidationIssue(result, "preflight response did not advertise allowed methods.");
    }
    return true;
}

[[nodiscard]] std::string BuildLoginBody(const ProtocolInput& input) {
    Json body{
        {"username", MakeToken(Slice(input.payload, 0, 16), "analyst", 16)},
        {"password", MakeToken(Slice(input.payload, 16, 24), "hunter2", 24)},
        {"remember_me", (input.optionFlags & 0x10u) != 0}
    };
    return body.dump();
}

[[nodiscard]] bool ExerciseLogin(
    SSHttp::HttpServer& server,
    const ProtocolInput& input,
    HarnessResult& result)
{
    std::string body = BuildLoginBody(input);
    if ((input.optionFlags & 0x02u) != 0 && !body.empty()) {
        body.resize(body.size() / 2);
    }

    const std::string contentType =
        ((input.optionFlags & 0x04u) != 0) ? "text/plain" : "application/json";
    const std::string requestText = BuildRequest(
        "POST",
        "/api/v1/auth/login",
        {
            {"Connection", "close"},
            {"Content-Type", contentType}
        },
        body);
    const std::vector<uint8_t> request(requestText.begin(), requestText.end());

    auto client = ConnectLocalhost(server.GetPort());
    if (!client.has_value()) {
        RecordValidationIssue(result, "login request failed to connect to harness server.");
        return false;
    }

    const auto before = server.GetStats();
    if (!SendFragments(client->value, FragmentRequest(request, input), input.interFragmentDelayMs)) {
        RecordValidationIssue(result, "login request failed while sending request fragments.");
        return false;
    }

    ::shutdown(client->value, SD_SEND);
    const std::vector<uint8_t> response = ReadResponse(client->value);
    const bool observed = ObserveScenario(server, before, response, result, "login-request");
    if (!observed) {
        return false;
    }

    if (!ExpectStatus(response, {200, 400, 401, 415}, result, "login-request")) {
        return false;
    }
    return true;
}

[[nodiscard]] bool ExerciseConfigUpdate(
    SSHttp::HttpServer& server,
    const ProtocolInput& input,
    const std::shared_ptr<HarnessState>& state,
    HarnessResult& result)
{
    Json body{
        {"scan_threads", 1 + (Fnv1a32(Slice(input.payload, 0, 8)) % 8)},
        {"telemetry_level", MakeToken(Slice(input.payload, 8, 12), "standard", 12)},
        {"tamper_protection", (input.optionFlags & 0x20u) == 0}
    };
    std::string bodyText = body.dump();

    std::vector<std::pair<std::string, std::string>> headers{
        {"Connection", "close"},
        {"Content-Type", ((input.optionFlags & 0x04u) != 0) ? "application/octet-stream" : "application/json"}
    };
    if ((input.optionFlags & 0x01u) == 0) {
        headers.emplace_back("Authorization", "Bearer " + state->authToken);
    }
    if ((input.optionFlags & 0x02u) == 0) {
        headers.emplace_back("X-CSRF-Token", state->csrfToken);
    }

    const std::string requestText = BuildRequest("PUT", "/api/v1/config", headers, bodyText);
    const std::vector<uint8_t> request(requestText.begin(), requestText.end());

    auto client = ConnectLocalhost(server.GetPort());
    if (!client.has_value()) {
        RecordValidationIssue(result, "config update request failed to connect to harness server.");
        return false;
    }

    const auto before = server.GetStats();
    if (!SendFragments(client->value, FragmentRequest(request, input), input.interFragmentDelayMs)) {
        RecordValidationIssue(result, "config update request failed while sending request fragments.");
        return false;
    }

    ::shutdown(client->value, SD_SEND);
    const std::vector<uint8_t> response = ReadResponse(client->value);
    const bool observed = ObserveScenario(server, before, response, result, "config-update");
    if (!observed) {
        return false;
    }

    if (!ExpectStatus(response, {202, 401, 403, 400, 415}, result, "config-update")) {
        return false;
    }
    return true;
}

[[nodiscard]] bool ExerciseCustomScan(
    SSHttp::HttpServer& server,
    const ProtocolInput& input,
    const std::shared_ptr<HarnessState>& state,
    HarnessResult& result)
{
    Json body;
    body["paths"] = Json::array();

    const bool insertTraversal = (input.optionFlags & 0x08u) != 0;
    body["paths"].push_back(insertTraversal
        ? "..\\..\\Windows\\System32\\" + MakeToken(Slice(input.payload, 0, 12), "calc", 12) + ".exe"
        : "C:\\Samples\\" + MakeToken(Slice(input.payload, 0, 12), "sample", 12) + ".bin");
    body["paths"].push_back("C:\\Users\\Public\\" + MakeToken(Slice(input.payload, 12, 12), "notes", 12) + ".dat");

    std::vector<std::pair<std::string, std::string>> headers{
        {"Connection", "close"},
        {"Content-Type", "application/json"},
        {"Authorization", "Bearer " + state->authToken},
        {"X-CSRF-Token", state->csrfToken}
    };

    const std::string bodyText = body.dump();
    const std::string requestText = BuildRequest("POST", "/api/v1/scan/custom", headers, bodyText);
    const std::vector<uint8_t> request(requestText.begin(), requestText.end());

    auto client = ConnectLocalhost(server.GetPort());
    if (!client.has_value()) {
        RecordValidationIssue(result, "custom scan request failed to connect to harness server.");
        return false;
    }

    const auto before = server.GetStats();
    if (!SendFragments(client->value, FragmentRequest(request, input), input.interFragmentDelayMs)) {
        RecordValidationIssue(result, "custom scan request failed while sending request fragments.");
        return false;
    }

    ::shutdown(client->value, SD_SEND);
    const std::vector<uint8_t> response = ReadResponse(client->value);
    const bool observed = ObserveScenario(server, before, response, result, "custom-scan");
    if (!observed) {
        return false;
    }

    if (!ExpectStatus(response, {202, 403, 400}, result, "custom-scan")) {
        return false;
    }
    return true;
}

[[nodiscard]] bool ExerciseThreatLookup(
    SSHttp::HttpServer& server,
    const ProtocolInput& input,
    const std::shared_ptr<HarnessState>& state,
    HarnessResult& result)
{
    const std::string threatId = MakeToken(Slice(input.payload, 0, 24), "ioc-42", 24);
    const std::string requestText = BuildRequest(
        "GET",
        "/api/v1/threats/" + threatId + "?verbose=" + ((input.optionFlags & 0x01u) != 0 ? "true" : "false"),
        {
            {"Connection", "close"},
            {"Authorization", "Bearer " + state->authToken}
        },
        {});
    const std::vector<uint8_t> request(requestText.begin(), requestText.end());

    auto client = ConnectLocalhost(server.GetPort());
    if (!client.has_value()) {
        RecordValidationIssue(result, "threat lookup request failed to connect to harness server.");
        return false;
    }

    const auto before = server.GetStats();
    if (!SendFragments(client->value, FragmentRequest(request, input), input.interFragmentDelayMs)) {
        RecordValidationIssue(result, "threat lookup request failed while sending request fragments.");
        return false;
    }

    ::shutdown(client->value, SD_SEND);
    const std::vector<uint8_t> response = ReadResponse(client->value);
    const bool observed = ObserveScenario(server, before, response, result, "threat-lookup");
    if (!observed) {
        return false;
    }

    if (!ExpectStatus(response, {200, 400}, result, "threat-lookup")) {
        return false;
    }
    return true;
}

[[nodiscard]] bool ExerciseKeepAlive(
    SSHttp::HttpServer& server,
    const ProtocolInput& input,
    const std::shared_ptr<HarnessState>& state,
    HarnessResult& result)
{
    auto client = ConnectLocalhost(server.GetPort());
    if (!client.has_value()) {
        RecordValidationIssue(result, "keep-alive scenario failed to connect to harness server.");
        return false;
    }

    const std::string threatId = MakeToken(Slice(input.payload, 0, 18), "case42", 18);
    const std::string requestOne = BuildRequest(
        "GET",
        "/api/v1/health?echo=keepalive",
        {
            {"Connection", "keep-alive"}
        },
        {});
    const std::string requestTwo = BuildRequest(
        "GET",
        "/api/v1/threats/" + threatId,
        {
            {"Connection", "close"},
            {"Authorization", "Bearer " + state->authToken}
        },
        {});

    std::vector<uint8_t> wire;
    wire.reserve(requestOne.size() + requestTwo.size());
    wire.insert(wire.end(), requestOne.begin(), requestOne.end());
    wire.insert(wire.end(), requestTwo.begin(), requestTwo.end());

    const auto before = server.GetStats();
    if (!SendFragments(client->value, FragmentRequest(wire, input), input.interFragmentDelayMs)) {
        RecordValidationIssue(result, "keep-alive scenario failed while sending request fragments.");
        return false;
    }

    ::shutdown(client->value, SD_SEND);
    const std::vector<uint8_t> response = ReadResponse(client->value);
    const bool observed = ObserveScenario(server, before, response, result, "keep-alive");
    if (!observed) {
        return false;
    }

    const auto after = server.GetStats();
    if ((after.totalRequests - before.totalRequests) < 2 && CountStatusLines(response) < 2) {
        RecordAnomaly(result, "keep-alive scenario did not observe both pipelined requests.");
    }
    return true;
}

[[nodiscard]] bool ExerciseSse(
    SSHttp::HttpServer& server,
    const ProtocolInput& input,
    HarnessResult& result)
{
    auto client = ConnectLocalhost(server.GetPort());
    if (!client.has_value()) {
        RecordValidationIssue(result, "SSE scenario failed to connect to harness server.");
        return false;
    }

    const std::string requestText = BuildRequest(
        "GET",
        "/api/v1/events/stream",
        {
            {"Accept", "text/event-stream"},
            {"Cache-Control", "no-cache"},
            {"Connection", "keep-alive"}
        },
        {});
    const std::vector<uint8_t> request(requestText.begin(), requestText.end());

    const auto before = server.GetStats();
    if (!SendFragments(client->value, FragmentRequest(request, input), input.interFragmentDelayMs)) {
        RecordValidationIssue(result, "SSE scenario failed while sending request fragments.");
        return false;
    }

    ::shutdown(client->value, SD_SEND);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    server.BroadcastSSE("fuzz", R"({"channel":"service-proto"})");
    const std::vector<uint8_t> response = ReadResponse(client->value);
    client->Reset();
    const auto cleanupDeadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(120);
    while (server.GetSSEClientCount() != 0 && std::chrono::steady_clock::now() < cleanupDeadline) {
        server.BroadcastSSE("cleanup", R"({"phase":"sse-drain"})");
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    const bool observed = ObserveScenario(server, before, response, result, "sse-stream");
    if (!observed) {
        return false;
    }

    if (!ResponseContains(response, "text/event-stream")) {
        RecordValidationIssue(result, "SSE scenario did not observe an event-stream response.");
    }
    if (server.GetSSEClientCount() != 0) {
        RecordAnomaly(result, "SSE scenario left a persistent server-side event-stream client behind.");
    }
    return true;
}

[[nodiscard]] bool ExerciseTruncatedBody(
    SSHttp::HttpServer& server,
    const ProtocolInput& input,
    HarnessResult& result)
{
    auto client = ConnectLocalhost(server.GetPort());
    if (!client.has_value()) {
        RecordValidationIssue(result, "truncated-body scenario failed to connect to harness server.");
        return false;
    }

    const std::string partialBody = BuildLoginBody(input).substr(0, 8);
    std::string request;
    request.reserve(256);
    request.append("POST /api/v1/auth/login HTTP/1.1\r\n");
    AppendHeader(request, "Host", "127.0.0.1");
    AppendHeader(request, "Content-Type", "application/json");
    AppendHeader(request, "Content-Length", std::to_string(partialBody.size() + 128));
    AppendHeader(request, "Connection", "close");
    request.append(SSHttp::CRLF);
    request.append(partialBody);

    const std::vector<uint8_t> wire(request.begin(), request.end());
    const auto before = server.GetStats();
    if (!SendFragments(client->value, FragmentRequest(wire, input), input.interFragmentDelayMs)) {
        RecordValidationIssue(result, "truncated-body scenario failed while sending request fragments.");
        return false;
    }

    ::shutdown(client->value, SD_SEND);
    const std::vector<uint8_t> response = ReadResponse(client->value);
    return ObserveScenario(server, before, response, result, "truncated-body");
}

[[nodiscard]] bool DispatchScenario(
    ServerFixture& fixture,
    const ProtocolInput& input,
    HarnessResult& result)
{
    switch (input.scenario) {
    case Scenario::RawMutation:
        return ExerciseRawMutation(fixture.server, input, result);
    case Scenario::Health:
        return ExerciseHealth(fixture.server, input, result);
    case Scenario::Preflight:
        return ExercisePreflight(fixture.server, input, result);
    case Scenario::Login:
        return ExerciseLogin(fixture.server, input, result);
    case Scenario::Config:
        return ExerciseConfigUpdate(fixture.server, input, fixture.state, result);
    case Scenario::Scan:
        return ExerciseCustomScan(fixture.server, input, fixture.state, result);
    case Scenario::ThreatLookup:
        return ExerciseThreatLookup(fixture.server, input, fixture.state, result);
    case Scenario::KeepAlive:
        return ExerciseKeepAlive(fixture.server, input, fixture.state, result);
    case Scenario::Sse:
        return ExerciseSse(fixture.server, input, result);
    case Scenario::TruncatedBody:
        return ExerciseTruncatedBody(fixture.server, input, result);
    }

    RecordValidationIssue(result, "Service protocol harness selected an unknown scenario.");
    return false;
}

[[nodiscard]] bool WriteBinaryFile(
    const std::filesystem::path& path,
    const std::vector<uint8_t>& bytes)
{
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) {
        return false;
    }

    stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return stream.good();
}

[[nodiscard]] std::optional<std::vector<uint8_t>> ReadFileBytes(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        return std::nullopt;
    }

    stream.seekg(0, std::ios::end);
    const auto size = stream.tellg();
    if (size < 0) {
        return std::nullopt;
    }

    stream.seekg(0, std::ios::beg);
    std::vector<uint8_t> bytes(static_cast<size_t>(size));
    if (!bytes.empty()) {
        stream.read(reinterpret_cast<char*>(bytes.data()), size);
        if (!stream.good() && !stream.eof()) {
            return std::nullopt;
        }
    }
    return bytes;
}

void WriteSeedIfAbsent(
    const std::filesystem::path& corpusDir,
    const std::string_view fileName,
    std::initializer_list<uint8_t> bytes)
{
    const auto path = corpusDir / std::string(fileName);
    if (std::filesystem::exists(path)) {
        return;
    }

    const std::vector<uint8_t> seed(bytes);
    (void)WriteBinaryFile(path, seed);
}

void EnsureSeedCorpus(const std::filesystem::path& corpusDir) {
    WriteSeedIfAbsent(corpusDir, "seed-health.bin", {1, 0, 0, 0, 'o', 'k'});
    WriteSeedIfAbsent(corpusDir, "seed-preflight.bin", {2, 1, 0, 0, 'c', 'o', 'r', 's'});
    WriteSeedIfAbsent(corpusDir, "seed-login.bin", {3, 0, 0, 0, 'a', 'n', 'a', 'l', 'y', 's', 't'});
    WriteSeedIfAbsent(corpusDir, "seed-config.bin", {4, 0, 0, 0, 'c', 'f', 'g'});
    WriteSeedIfAbsent(corpusDir, "seed-scan.bin", {5, 3, 0, 0, 'p', 'a', 't', 'h'});
    WriteSeedIfAbsent(corpusDir, "seed-threat.bin", {6, 0, 0, 0, 't', 'h', 'r', 'e', 'a', 't'});
    WriteSeedIfAbsent(corpusDir, "seed-keepalive.bin", {7, 4, 0, 1, 'k', 'a'});
    WriteSeedIfAbsent(corpusDir, "seed-sse.bin", {8, 1, 0, 0, 's', 's', 'e'});
    WriteSeedIfAbsent(corpusDir, "seed-truncated-body.bin", {9, 2, 0, 0, 't', 'r', 'u', 'n', 'c'});
}

}  // namespace

bool ServiceProtocolHarness::ExerciseServiceProtocolImpl(
    const uint8_t* data,
    const size_t size,
    HarnessResult& result)
{
    const std::span<const uint8_t> input(data, size);
    std::unique_lock guard(HarnessMutex());
    auto& fixtureHolder = HarnessServer();

    if (!fixtureHolder || !fixtureHolder->started || !fixtureHolder->server.IsRunning()) {
        fixtureHolder = std::make_unique<ServerFixture>();
        if (!StartServer(*fixtureHolder, input, result)) {
            fixtureHolder.reset();
            return false;
        }
    }

    if (!PrepareServerForIteration(*fixtureHolder)) {
        fixtureHolder.reset();
        fixtureHolder = std::make_unique<ServerFixture>();
        if (!StartServer(*fixtureHolder, input, result) || !PrepareServerForIteration(*fixtureHolder)) {
            RecordValidationIssue(result, "Failed to prepare persistent HTTP service harness server for a new iteration.");
            fixtureHolder.reset();
            return false;
        }
    }

    if (!fixtureHolder || !fixtureHolder->started) {
        return false;
    }

    const ProtocolInput decoded = DecodeInput(input);
    return DispatchScenario(*fixtureHolder, decoded, result);
}

unsigned long ServiceProtocolHarness::SEHCallServiceProtocol(
    const uint8_t* data,
    const size_t size,
    HarnessResult* pResult) noexcept
{
    DWORD exceptionCode = 0;
    __try {
        (void)ExerciseServiceProtocolImpl(data, size, *pResult);
    } __except (exceptionCode = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
    }
    return exceptionCode;
}

HarnessResult ServiceProtocolHarness::Run(std::span<const uint8_t> input) noexcept {
    HarnessResult result{};

    try {
        const DWORD exceptionCode = SEHCallServiceProtocol(
            input.empty() ? nullptr : input.data(),
            input.size(),
            &result);
        if (exceptionCode != 0) {
            result.crashed = true;
            result.crashSignal = ExceptionCodeToString(exceptionCode);
            if (result.errorMessage.empty()) {
                result.errorMessage = "Structured exception while exercising the embedded HTTP service boundary.";
            }
        }
    } catch (const std::exception& ex) {
        result.crashed = true;
        result.crashSignal = "CXX_EXCEPTION";
        result.errorMessage = ex.what();
    } catch (...) {
        result.crashed = true;
        result.crashSignal = "UNKNOWN_EXCEPTION";
        result.errorMessage = "Unknown C++ exception while exercising the embedded HTTP service boundary.";
    }

    return result;
}

HarnessFunction ServiceProtocolHarness::GetHarnessFunction() noexcept {
    return [](std::span<const uint8_t> input) -> HarnessResult {
        return Run(input);
    };
}

std::string_view ServiceProtocolHarness::GetName() noexcept {
    return "fuzz-service-proto";
}

std::string_view ServiceProtocolHarness::GetDescription() noexcept {
    return "Embedded localhost HTTP service protocol harness for hostile request framing, routing, auth, CORS, keep-alive, and SSE flows";
}

std::string ServiceProtocolHarness::ExceptionCodeToString(const unsigned long code) noexcept {
    return ExceptionCodeToStringInternal(code);
}

int RunServiceProtocolFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config) noexcept
{
    if (!InstallCtrlCHandler()) {
        std::cerr << "[ServiceProtoFuzzer] Warning: Failed to install Ctrl+C handler\n";
    }

    const auto corpusDir = workspaceDir / "corpora" / "service-proto";
    const auto crashDir = workspaceDir / "crashes" / "service-proto";

    std::error_code ec;
    std::filesystem::create_directories(corpusDir, ec);
    if (ec) {
        std::cerr << "[ServiceProtoFuzzer] Failed to create corpus directory: " << corpusDir << '\n';
        return 1;
    }

    ec.clear();
    std::filesystem::create_directories(crashDir, ec);
    if (ec) {
        std::cerr << "[ServiceProtoFuzzer] Failed to create crash directory: " << crashDir << '\n';
        return 1;
    }

    EnsureSeedCorpus(corpusDir);
    const auto sanitySeed = ReadFileBytes(corpusDir / "seed-health.bin");
    if (!sanitySeed.has_value()) {
        std::cerr << "[ServiceProtoFuzzer] Failed to read service protocol sanity seed\n";
        return 1;
    }

    const HarnessResult sanityResult = ServiceProtocolHarness::Run(*sanitySeed);
    if (sanityResult.crashed || !sanityResult.parsedOk) {
        std::cerr << "[ServiceProtoFuzzer] Sanity check failed";
        if (!sanityResult.errorMessage.empty()) {
            std::cerr << ": " << sanityResult.errorMessage;
        }
        if (!sanityResult.crashSignal.empty()) {
            std::cerr << " (" << sanityResult.crashSignal << ')';
        }
        std::cerr << '\n';
        return 1;
    }

    FuzzLoopConfig loopConfig = config;
    loopConfig.targetName = std::string(ServiceProtocolHarness::GetName());

    std::cout << "[ServiceProtoFuzzer] Starting embedded HTTP service protocol fuzzing...\n";
    std::cout << "[ServiceProtoFuzzer] Corpus: " << corpusDir << '\n';
    std::cout << "[ServiceProtoFuzzer] Crashes: " << crashDir << '\n';

    FuzzLoop loop(corpusDir, crashDir, ServiceProtocolHarness::GetHarnessFunction(), loopConfig);
    const bool success = loop.Run();
    const auto& stats = loop.GetStatistics();

    std::cout << "\n[ServiceProtoFuzzer] Final Results:\n";
    std::cout << "  Total iterations: " << stats.totalIterations << '\n';
    std::cout << "  Unique crashes:   " << stats.uniqueCrashes << '\n';
    std::cout << "  Total crashes:    " << stats.crashesFound << '\n';
    std::cout << "  Final corpus:     " << stats.corpusSize << '\n';
    std::cout << "  Parse success:    " << stats.parseSuccesses << '\n';
    std::cout << "  Parse failure:    " << stats.parseFailures << '\n';
    std::cout << "  Duration:         " << (stats.durationMs / 1000) << "s\n";
    std::cout << "  Speed:            " << std::fixed << std::setprecision(1)
              << stats.iterationsPerSecond << " iter/s\n";

    return success ? 0 : 1;
}

}  // namespace ShadowStrike::Fuzzer
