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
 * @file TrafficHarness.cpp
 * @brief Implementation of the traffic-analysis fuzz harness.
 */

#include "ShadowStrike/Fuzzer/Harnesses/TrafficHarness.hpp"

#include "ShadowStrike/Fuzzer/Core/FuzzLoop.hpp"

#include "Core/Network/TrafficAnalyzer.hpp"
#include "RealTime/NetworkTrafficFilter.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ShadowStrike::Fuzzer {
namespace {

namespace SSCoreNet = ShadowStrike::Core::Network;
namespace SSRealTime = ShadowStrike::RealTime;

constexpr size_t kMaxInputBytes = 4096;
constexpr size_t kMaxPacketPayloadBytes = 1400;
constexpr size_t kMaxPayloadBytes = 2048;
constexpr uint64_t kFuzzConnectionId = 0x5452414646494301ULL;
constexpr uint32_t kFuzzProcessId = 4242;
constexpr unsigned long kSehSuccess = 0UL;
constexpr unsigned long kSehInvalidParameter = 0xC000000DUL;

std::mutex& HarnessMutex() {
    static std::mutex mutex;
    return mutex;
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

[[nodiscard]] std::span<const uint8_t> TailBytes(
    std::span<const uint8_t> input,
    const size_t offset) noexcept
{
    if (offset >= input.size()) {
        return {};
    }

    return input.subspan(offset);
}

[[nodiscard]] std::vector<uint8_t> CopyInput(
    std::span<const uint8_t> input,
    const size_t maxBytes)
{
    const size_t copyLength = std::min(input.size(), maxBytes);
    return std::vector<uint8_t>(input.begin(), input.begin() + static_cast<std::ptrdiff_t>(copyLength));
}

[[nodiscard]] uint16_t ReadU16(std::span<const uint8_t> input, const size_t offset, const uint16_t fallback) noexcept {
    if (offset + sizeof(uint16_t) > input.size()) {
        return fallback;
    }

    return static_cast<uint16_t>(
        (static_cast<uint16_t>(input[offset]) << 8) |
        static_cast<uint16_t>(input[offset + 1]));
}

[[nodiscard]] uint32_t ReadU32(std::span<const uint8_t> input, const size_t offset, const uint32_t fallback) noexcept {
    if (offset + sizeof(uint32_t) > input.size()) {
        return fallback;
    }

    return (static_cast<uint32_t>(input[offset]) << 24) |
           (static_cast<uint32_t>(input[offset + 1]) << 16) |
           (static_cast<uint32_t>(input[offset + 2]) << 8) |
           static_cast<uint32_t>(input[offset + 3]);
}

void AppendU16BE(std::vector<uint8_t>& bytes, const uint16_t value) {
    bytes.push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
    bytes.push_back(static_cast<uint8_t>(value & 0xFFu));
}

void AppendU24BE(std::vector<uint8_t>& bytes, const size_t value) {
    bytes.push_back(static_cast<uint8_t>((value >> 16) & 0xFFu));
    bytes.push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
    bytes.push_back(static_cast<uint8_t>(value & 0xFFu));
}

void AppendU32BE(std::vector<uint8_t>& bytes, const uint32_t value) {
    bytes.push_back(static_cast<uint8_t>((value >> 24) & 0xFFu));
    bytes.push_back(static_cast<uint8_t>((value >> 16) & 0xFFu));
    bytes.push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
    bytes.push_back(static_cast<uint8_t>(value & 0xFFu));
}

void AppendBytes(std::vector<uint8_t>& bytes, std::span<const uint8_t> extra) {
    bytes.insert(bytes.end(), extra.begin(), extra.end());
}

[[nodiscard]] uint16_t ComputeInternetChecksum(std::span<const uint8_t> buffer) noexcept {
    uint32_t sum = 0;
    size_t index = 0;

    while (index + 1 < buffer.size()) {
        sum += static_cast<uint32_t>(
            (static_cast<uint16_t>(buffer[index]) << 8) |
            static_cast<uint16_t>(buffer[index + 1]));
        index += 2;
    }

    if (index < buffer.size()) {
        sum += static_cast<uint32_t>(static_cast<uint16_t>(buffer[index]) << 8);
    }

    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum & 0xFFFFu);
}

[[nodiscard]] std::string SanitizedLabel(std::span<const uint8_t> input, const std::string_view fallback) {
    std::string label;
    label.reserve(std::min<size_t>(input.size(), 24));

    for (const uint8_t byte : input) {
        const char candidate = static_cast<char>(byte & 0x7F);
        if ((candidate >= 'a' && candidate <= 'z') ||
            (candidate >= 'A' && candidate <= 'Z') ||
            (candidate >= '0' && candidate <= '9')) {
            label.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(candidate))));
        } else if (candidate == '-' || candidate == '_') {
            label.push_back('-');
        }

        if (label.size() == 24) {
            break;
        }
    }

    if (label.empty()) {
        label.assign(fallback.begin(), fallback.end());
    }

    if (label.front() == '-') {
        label.front() = 'a';
    }
    if (label.back() == '-') {
        label.back() = 'z';
    }

    return label;
}

[[nodiscard]] std::string BuildDomainFromInput(std::span<const uint8_t> input) {
    const auto left = SanitizedLabel(input.first(std::min<size_t>(input.size(), 12)), "shadow");
    const auto right = SanitizedLabel(TailBytes(input, std::min<size_t>(input.size(), 12)).first(
                                          std::min<size_t>(TailBytes(input, std::min<size_t>(input.size(), 12)).size(), 10)),
                                      "telemetry");
    return left + "." + right + ".example";
}

[[nodiscard]] std::string BuildDgaDomain(std::span<const uint8_t> input) {
    static constexpr std::string_view alphabet = "bcdfghjklmnpqrstvwxyz0123456789";

    std::string label;
    label.reserve(18);
    for (size_t i = 0; i < 18; ++i) {
        const uint8_t source = input.empty() ? static_cast<uint8_t>(i * 13u + 7u) : input[i % input.size()];
        label.push_back(alphabet[source % alphabet.size()]);
    }

    return label + ".com";
}

[[nodiscard]] std::vector<uint8_t> BuildHttpPayload(std::span<const uint8_t> input, const bool post) {
    const std::string host = BuildDomainFromInput(input);
    const std::string path = "/" + SanitizedLabel(TailBytes(input, 8), "index");
    const std::string body = std::string("{\"sample\":\"") + SanitizedLabel(TailBytes(input, 4), "alpha") + "\"}";

    std::ostringstream request;
    request << (post ? "POST " : "GET ") << path << " HTTP/1.1\r\n"
            << "Host: " << host << "\r\n"
            << "User-Agent: ShadowStrikeFuzzer/traffic\r\n"
            << "Accept: */*\r\n";

    if (post) {
        request << "Content-Type: application/json\r\n"
                << "Content-Length: " << body.size() << "\r\n";
    }

    request << "\r\n";
    if (post) {
        request << body;
    }

    const std::string text = request.str();
    return std::vector<uint8_t>(text.begin(), text.end());
}

[[nodiscard]] std::vector<uint8_t> BuildTlsClientHello(std::span<const uint8_t> input) {
    std::vector<uint8_t> body;
    body.reserve(256);

    body.push_back(0x03);
    body.push_back(0x03);

    for (size_t i = 0; i < 32; ++i) {
        const uint8_t byte = input.empty() ? static_cast<uint8_t>(0xA0u + i) : input[i % input.size()];
        body.push_back(byte);
    }

    const uint8_t sessionLength = static_cast<uint8_t>(std::min<size_t>(4, input.size() % 5));
    body.push_back(sessionLength);
    for (uint8_t i = 0; i < sessionLength; ++i) {
        body.push_back(static_cast<uint8_t>(0x10u + i));
    }

    std::vector<uint16_t> cipherSuites{
        0x1301u,
        0x1302u,
        0x1303u,
        static_cast<uint16_t>(0xC02Fu + (input.empty() ? 0u : input[0] % 4u)),
    };

    AppendU16BE(body, static_cast<uint16_t>(cipherSuites.size() * sizeof(uint16_t)));
    for (const uint16_t suite : cipherSuites) {
        AppendU16BE(body, suite);
    }

    body.push_back(1u);
    body.push_back(0u);

    std::vector<uint8_t> extensions;

    const std::string host = BuildDomainFromInput(input);
    std::vector<uint8_t> sni;
    AppendU16BE(sni, static_cast<uint16_t>(host.size() + 3u));
    sni.push_back(0u);
    AppendU16BE(sni, static_cast<uint16_t>(host.size()));
    sni.insert(sni.end(), host.begin(), host.end());
    AppendU16BE(extensions, 0x0000u);
    AppendU16BE(extensions, static_cast<uint16_t>(sni.size()));
    AppendBytes(extensions, sni);

    std::vector<uint8_t> groups;
    AppendU16BE(groups, 4u);
    AppendU16BE(groups, 0x001Du);
    AppendU16BE(groups, 0x0017u);
    AppendU16BE(extensions, 0x000Au);
    AppendU16BE(extensions, static_cast<uint16_t>(groups.size()));
    AppendBytes(extensions, groups);

    const std::array<uint8_t, 2> pointFormats{1u, 0u};
    AppendU16BE(extensions, 0x000Bu);
    AppendU16BE(extensions, static_cast<uint16_t>(pointFormats.size()));
    AppendBytes(extensions, pointFormats);

    AppendU16BE(body, static_cast<uint16_t>(extensions.size()));
    AppendBytes(body, extensions);

    std::vector<uint8_t> handshake;
    handshake.push_back(0x01u);
    AppendU24BE(handshake, body.size());
    AppendBytes(handshake, body);

    std::vector<uint8_t> record;
    record.push_back(0x16u);
    record.push_back(0x03u);
    record.push_back(0x03u);
    AppendU16BE(record, static_cast<uint16_t>(handshake.size()));
    AppendBytes(record, handshake);
    return record;
}

[[nodiscard]] std::vector<uint8_t> BuildDnsQuery(std::string domain) {
    if (domain.empty()) {
        domain = "shadowstrike.example";
    }

    std::vector<uint8_t> query;
    query.reserve(128);

    AppendU16BE(query, 0x1337u);
    AppendU16BE(query, 0x0100u);
    AppendU16BE(query, 1u);
    AppendU16BE(query, 0u);
    AppendU16BE(query, 0u);
    AppendU16BE(query, 0u);

    size_t offset = 0;
    while (offset < domain.size()) {
        const size_t dot = domain.find('.', offset);
        const size_t end = (dot == std::string::npos) ? domain.size() : dot;
        const size_t labelLength = end - offset;
        query.push_back(static_cast<uint8_t>(std::min<size_t>(labelLength, 63)));
        query.insert(query.end(), domain.begin() + static_cast<std::ptrdiff_t>(offset),
                     domain.begin() + static_cast<std::ptrdiff_t>(offset + std::min<size_t>(labelLength, 63)));
        offset = (dot == std::string::npos) ? domain.size() : dot + 1;
    }

    query.push_back(0u);
    AppendU16BE(query, 1u);
    AppendU16BE(query, 1u);
    return query;
}

[[nodiscard]] std::vector<uint8_t> BuildBase64ishPayload(std::span<const uint8_t> input) {
    static constexpr std::string_view alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string encoded;
    const size_t targetLength = std::max<size_t>(8, std::min<size_t>(64, input.empty() ? 24 : input.size() * 2));
    encoded.reserve(targetLength + 4);

    for (size_t i = 0; i < targetLength; ++i) {
        const uint8_t source = input.empty() ? static_cast<uint8_t>(i * 11u + 3u) : input[i % input.size()];
        encoded.push_back(alphabet[source % alphabet.size()]);
    }

    while ((encoded.size() % 4u) != 0u) {
        encoded.push_back('=');
    }

    return std::vector<uint8_t>(encoded.begin(), encoded.end());
}

[[nodiscard]] std::vector<uint8_t> BuildEthernetFrame(const uint16_t etherType, std::span<const uint8_t> payload) {
    std::vector<uint8_t> frame;
    frame.reserve(14 + payload.size());

    const std::array<uint8_t, 6> dstMac{0x00u, 0x15u, 0x5Du, 0x01u, 0x02u, 0x03u};
    const std::array<uint8_t, 6> srcMac{0x00u, 0x15u, 0x5Du, 0x04u, 0x05u, 0x06u};
    AppendBytes(frame, dstMac);
    AppendBytes(frame, srcMac);
    AppendU16BE(frame, etherType);
    AppendBytes(frame, payload);
    return frame;
}

[[nodiscard]] std::vector<uint8_t> BuildIpv4Packet(
    const uint8_t protocol,
    const uint16_t srcPort,
    const uint16_t dstPort,
    std::span<const uint8_t> payload,
    const bool useTcp)
{
    std::vector<uint8_t> l4;
    if (useTcp) {
        l4.reserve(20 + payload.size());
        AppendU16BE(l4, srcPort);
        AppendU16BE(l4, dstPort);
        AppendU32BE(l4, 0x01020304u);
        AppendU32BE(l4, 0x05060708u);
        l4.push_back(0x50u);
        l4.push_back(0x18u);
        AppendU16BE(l4, 0x4000u);
        AppendU16BE(l4, 0u);
        AppendU16BE(l4, 0u);
        AppendBytes(l4, payload);
    } else {
        l4.reserve(8 + payload.size());
        AppendU16BE(l4, srcPort);
        AppendU16BE(l4, dstPort);
        AppendU16BE(l4, static_cast<uint16_t>(8 + payload.size()));
        AppendU16BE(l4, 0u);
        AppendBytes(l4, payload);
    }

    std::vector<uint8_t> ipHeader(20u, 0u);
    ipHeader[0] = 0x45u;
    ipHeader[1] = 0u;
    const uint16_t totalLength = static_cast<uint16_t>(ipHeader.size() + l4.size());
    ipHeader[2] = static_cast<uint8_t>((totalLength >> 8) & 0xFFu);
    ipHeader[3] = static_cast<uint8_t>(totalLength & 0xFFu);
    ipHeader[4] = 0x12u;
    ipHeader[5] = 0x34u;
    ipHeader[6] = 0x40u;
    ipHeader[7] = 0u;
    ipHeader[8] = 64u;
    ipHeader[9] = protocol;
    ipHeader[12] = 10u;
    ipHeader[13] = 0u;
    ipHeader[14] = 0u;
    ipHeader[15] = 5u;
    ipHeader[16] = 203u;
    ipHeader[17] = 0u;
    ipHeader[18] = 113u;
    ipHeader[19] = 25u;

    const uint16_t checksum = ComputeInternetChecksum(ipHeader);
    ipHeader[10] = static_cast<uint8_t>((checksum >> 8) & 0xFFu);
    ipHeader[11] = static_cast<uint8_t>(checksum & 0xFFu);

    std::vector<uint8_t> packet = BuildEthernetFrame(0x0800u, ipHeader);
    packet.insert(packet.end(), l4.begin(), l4.end());
    return packet;
}

struct AnalyzerPacketCase {
    std::vector<uint8_t> packet;
    SSCoreNet::Protocol expectedProtocol{SSCoreNet::Protocol::UNKNOWN};
    bool intentionallyMalformed{false};
};

[[nodiscard]] AnalyzerPacketCase BuildAnalyzerPacketCase(std::span<const uint8_t> input) {
    const uint8_t selector = input.empty() ? 0u : input[0];
    const bool malformed = (selector & 0x80u) != 0u;
    const auto body = TailBytes(input, 2);

    AnalyzerPacketCase packetCase;
    switch (selector % 4u) {
    case 0u: {
        const auto payload = BuildHttpPayload(body, false);
        packetCase.packet = BuildIpv4Packet(6u, ReadU16(input, 2, 49152u), 80u, payload, true);
        packetCase.expectedProtocol = SSCoreNet::Protocol::HTTP;
        break;
    }
    case 1u: {
        const auto payload = BuildTlsClientHello(body);
        packetCase.packet = BuildIpv4Packet(6u, ReadU16(input, 2, 52345u), 443u, payload, true);
        packetCase.expectedProtocol = SSCoreNet::Protocol::HTTPS;
        break;
    }
    case 2u: {
        const auto payload = BuildDnsQuery(BuildDomainFromInput(body));
        packetCase.packet = BuildIpv4Packet(17u, ReadU16(input, 2, 53000u), 53u, payload, false);
        packetCase.expectedProtocol = SSCoreNet::Protocol::DNS;
        break;
    }
    default: {
        packetCase.packet = CopyInput(body, kMaxInputBytes);
        if (packetCase.packet.empty()) {
            packetCase.packet = {0u};
        }
        packetCase.expectedProtocol = SSCoreNet::Protocol::UNKNOWN;
        break;
    }
    }

    if (malformed && packetCase.packet.size() > 24u) {
        const size_t trim = 1u + (body.empty() ? 0u : static_cast<size_t>(body[0] % 12u));
        packetCase.packet.resize(packetCase.packet.size() - std::min(trim, packetCase.packet.size() - 1u));
        packetCase.intentionallyMalformed = true;
    }

    return packetCase;
}

struct FilterTransferCase {
    std::vector<uint8_t> data;
    SSRealTime::AppProtocol expectedProtocol{SSRealTime::AppProtocol::Unknown};
    bool outbound{true};
    size_t reportedSize{0};
};

[[nodiscard]] FilterTransferCase BuildFilterTransferCase(std::span<const uint8_t> input) {
    const uint8_t selector = input.empty() ? 0u : input[0];
    const auto body = TailBytes(input, 2);

    FilterTransferCase transfer;
    switch (selector % 3u) {
    case 0u:
        transfer.data = BuildHttpPayload(body, (selector & 0x08u) != 0u);
        transfer.expectedProtocol = SSRealTime::AppProtocol::HTTP;
        break;
    case 1u:
        transfer.data = BuildTlsClientHello(body);
        transfer.expectedProtocol = SSRealTime::AppProtocol::TLS;
        break;
    default:
        transfer.data = CopyInput(body, kMaxPayloadBytes);
        if (transfer.data.size() < 4u) {
            transfer.data.insert(transfer.data.end(), {0x90u, 0x90u, 0x90u, 0xCCu});
        }
        transfer.expectedProtocol = SSRealTime::AppProtocol::Unknown;
        break;
    }

    transfer.outbound = (selector & 0x20u) == 0u;
    transfer.reportedSize = transfer.data.size();
    if ((selector & 0x40u) != 0u && !transfer.data.empty()) {
        transfer.reportedSize += 1u + static_cast<size_t>(transfer.data[0] % 32u);
    }

    return transfer;
}

[[nodiscard]] SSRealTime::NetworkFilterConfig BuildFilterConfig() {
    SSRealTime::NetworkFilterConfig config = SSRealTime::NetworkFilterConfig::CreateMonitorOnly();
    config.deepInspection = true;
    config.detectC2 = true;
    config.detectDGA = true;
    config.detectExfiltration = false;
    config.largeTransferThreshold = std::numeric_limits<size_t>::max() / 2u;
    return config;
}

[[nodiscard]] SSRealTime::NetworkConnection BuildConnection(
    const SSRealTime::AppProtocol appProtocol,
    const bool outbound)
{
    SSRealTime::NetworkConnection connection;
    connection.connectionId = kFuzzConnectionId;
    connection.processId = kFuzzProcessId;
    connection.processName = L"traffic-harness.exe";
    connection.direction = outbound ? SSRealTime::ConnectionDirection::Outbound
                                    : SSRealTime::ConnectionDirection::Inbound;
    connection.state = SSRealTime::ConnectionState::Connecting;
    connection.appProtocol = appProtocol;
    connection.creationTime = std::chrono::system_clock::now();
    connection.lastActivity = connection.creationTime;
    connection.tuple.protocol = SSRealTime::NetworkProtocol::TCP;
    connection.tuple.local = {SSRealTime::IPAddress::FromString("10.0.0.5"), 51515u};
    connection.tuple.remote = {SSRealTime::IPAddress::FromString("203.0.113.25"), 443u};
    connection.domainName = "traffic.shadowstrike.example";
    connection.sni = connection.domainName;
    return connection;
}

[[nodiscard]] SSRealTime::NetworkEndpoint BuildBeaconEndpoint() {
    return {SSRealTime::IPAddress::FromString("203.0.113.99"), 8443u};
}

[[nodiscard]] SSCoreNet::TrafficAnalyzerConfig BuildAnalyzerConfig() {
    SSCoreNet::TrafficAnalyzerConfig config = SSCoreNet::TrafficAnalyzerConfig::CreateDefault();
    config.enableProtocolDetection = true;
    config.enableTLSInspection = true;
    config.enablePayloadAnalysis = true;
    config.enableAnomalyDetection = true;
    config.enableStreamReassembly = true;
    config.enableShellcodeDetection = true;
    config.enableSignatureScanning = false;
    config.checkJA3Reputation = false;
    config.extractCertificates = false;
    config.validateCertChain = false;
    config.useThreadPool = false;
    config.enableCaching = false;
    config.workerThreads = 1;
    config.maxActiveStreams = 32;
    config.maxPayloadScan = std::min<size_t>(config.maxPayloadScan, 4096u);
    return config;
}

bool EnsureAnalyzerReady(HarnessResult& result) {
    auto& analyzer = SSCoreNet::TrafficAnalyzer::Instance();
    if (!analyzer.IsRunning()) {
        analyzer.Shutdown();
        if (!analyzer.Initialize(BuildAnalyzerConfig())) {
            RecordValidationIssue(result, "TrafficAnalyzer initialization failed.");
            return false;
        }

        if (!analyzer.Start()) {
            RecordValidationIssue(result, "TrafficAnalyzer start failed.");
            return false;
        }
    }

    analyzer.ResetStatistics();
    analyzer.ClearAllStreams();
    return true;
}

void PrepareFilterForIteration() {
    auto& filter = SSRealTime::NetworkTrafficFilter::Instance();
    static bool initialized = false;

    if (!initialized) {
        (void)filter.Initialize(nullptr, BuildFilterConfig());
        initialized = true;
    }

    filter.UpdateConfig(BuildFilterConfig());
    filter.ResetFuzzingState();
}

bool ExerciseAnalyzePacket(std::span<const uint8_t> input, HarnessResult& result) {
    if (!EnsureAnalyzerReady(result)) {
        return false;
    }

    auto& analyzer = SSCoreNet::TrafficAnalyzer::Instance();
    AnalyzerPacketCase packetCase = BuildAnalyzerPacketCase(input);

    analyzer.AnalyzePacket(packetCase.packet);
    const auto analysis = analyzer.AnalyzePacket(packetCase.packet, std::chrono::system_clock::now());
    const auto& stats = analyzer.GetStatistics();
    const uint64_t totalPackets = stats.totalPackets.load(std::memory_order_relaxed);

    result.parsedOk = analysis.analysisComplete || analysis.packet.isValid || (totalPackets > 0u);

    if (totalPackets == 0u) {
        RecordValidationIssue(result, "TrafficAnalyzer did not account for the packet.");
    }

    if (analysis.packet.captureLength > packetCase.packet.size()) {
        RecordValidationIssue(result, "Packet capture length exceeded supplied packet size.");
    }

    if (analysis.packet.payloadOffset > analysis.packet.captureLength) {
        RecordValidationIssue(result, "Payload offset exceeded capture length.");
    }

    if (analysis.packet.payloadLength > analysis.packet.captureLength) {
        RecordValidationIssue(result, "Payload length exceeded capture length.");
    }

    if (analysis.packet.isValid && !analysis.packet.parseError.empty()) {
        RecordAnomaly(result, "Valid packet unexpectedly reported a parse error.");
    }

    if (!packetCase.intentionallyMalformed &&
        packetCase.expectedProtocol != SSCoreNet::Protocol::UNKNOWN &&
        analysis.packet.isValid &&
        analysis.protocol == SSCoreNet::Protocol::UNKNOWN) {
        RecordValidationIssue(result, "Structured packet was not classified by TrafficAnalyzer.");
    }

    analyzer.ClearAllStreams();
    return true;
}

bool ExerciseAnalyzePayload(std::span<const uint8_t> input, HarnessResult& result) {
    if (!EnsureAnalyzerReady(result)) {
        return false;
    }

    auto& analyzer = SSCoreNet::TrafficAnalyzer::Instance();
    std::vector<uint8_t> payload;

    switch ((input.empty() ? 0u : input[0]) % 4u) {
    case 0u:
        payload = CopyInput(TailBytes(input, 1), kMaxPayloadBytes);
        break;
    case 1u:
        payload = BuildBase64ishPayload(TailBytes(input, 1));
        break;
    case 2u:
        payload = BuildHttpPayload(TailBytes(input, 1), false);
        break;
    default:
        payload = BuildTlsClientHello(TailBytes(input, 1));
        break;
    }

    const auto analysis = analyzer.AnalyzePayload(payload);
    result.parsedOk = true;

    if (analysis.size != payload.size()) {
        RecordValidationIssue(result, "AnalyzePayload reported the wrong payload size.");
    }

    if (payload.empty() && analysis.type != SSCoreNet::PayloadType::UNKNOWN) {
        RecordValidationIssue(result, "Empty payload was not classified as UNKNOWN.");
    }

    if (analysis.isBase64 && analysis.type != SSCoreNet::PayloadType::ENCODED_BASE64) {
        RecordValidationIssue(result, "Base64 flag diverged from payload classification.");
    }

    return true;
}

bool ExerciseCalculateJa3(std::span<const uint8_t> input, HarnessResult& result) {
    if (!EnsureAnalyzerReady(result)) {
        return false;
    }

    auto hello = BuildTlsClientHello(TailBytes(input, 1));
    if (!input.empty() && (input[0] & 0x80u) != 0u && hello.size() > 6u) {
        hello.resize(hello.size() - 3u);
    }

    const auto& analyzer = SSCoreNet::TrafficAnalyzer::Instance();
    const auto ja3 = analyzer.CalculateJA3(hello);
    result.parsedOk = true;

    if (!ja3.hash.empty() && ja3.rawString.empty()) {
        RecordValidationIssue(result, "JA3 hash was emitted without a raw fingerprint string.");
    }

    if (!ja3.rawString.empty() && ja3.version == SSCoreNet::TrafficAnalyzerTLSVersion::UNKNOWN) {
        RecordValidationIssue(result, "Parsed JA3 fingerprint kept an UNKNOWN TLS version.");
    }

    return true;
}

bool ExerciseFilterFlow(std::span<const uint8_t> input, HarnessResult& result) {
    PrepareFilterForIteration();

    auto& filter = SSRealTime::NetworkTrafficFilter::Instance();
    const auto transfer = BuildFilterTransferCase(input);
    const auto connection = BuildConnection(transfer.expectedProtocol, transfer.outbound);

    const auto action = filter.OnConnectionAttempt(connection);
    if (action == SSRealTime::FilterAction::Block || action == SSRealTime::FilterAction::Terminate) {
        RecordAnomaly(result, "Monitor-only filter unexpectedly blocked the fuzz connection.");
    }

    filter.OnConnectionEstablished(connection);
    filter.OnDataTransfer(connection.connectionId, transfer.outbound, transfer.reportedSize, transfer.data);

    const auto liveConnection = filter.GetConnection(connection.connectionId);
    const auto stats = filter.GetStats();
    result.parsedOk = true;

    if (!liveConnection.has_value()) {
        RecordValidationIssue(result, "Connection disappeared before inspection completed.");
    } else {
        if (transfer.expectedProtocol != SSRealTime::AppProtocol::Unknown &&
            liveConnection->appProtocol != transfer.expectedProtocol) {
            RecordValidationIssue(result, "OnDataTransfer failed to identify the expected application protocol.");
        }

        if (transfer.expectedProtocol == SSRealTime::AppProtocol::TLS && !liveConnection->isTLS) {
            RecordValidationIssue(result, "TLS transfer was not marked as encrypted.");
        }
    }

    if (stats.totalConnections == 0u) {
        RecordValidationIssue(result, "Filter connection statistics were not updated.");
    }

    if (transfer.data.size() >= 4u && stats.deepInspections == 0u) {
        RecordValidationIssue(result, "Deep inspection statistics were not updated.");
    }

    filter.OnConnectionClosed(connection.connectionId);
    if (filter.GetConnection(connection.connectionId).has_value()) {
        RecordAnomaly(result, "Connection close did not release the tracked connection.");
    }

    return true;
}

bool ExerciseDnsAndDga(std::span<const uint8_t> input, HarnessResult& result) {
    PrepareFilterForIteration();

    auto& filter = SSRealTime::NetworkTrafficFilter::Instance();
    SSRealTime::DNSQueryEvent query;
    query.queryId = ReadU16(input, 1, 0x3137u);
    query.timestamp = std::chrono::system_clock::now();
    query.processId = kFuzzProcessId;
    query.domain = ((input.empty() ? 0u : input[0]) & 0x10u) != 0u
        ? BuildDgaDomain(TailBytes(input, 1))
        : BuildDomainFromInput(TailBytes(input, 1));
    query.queryType = ((input.empty() ? 0u : input[0]) & 0x20u) != 0u ? 16u : 1u;
    query.resolvedIPs.push_back(SSRealTime::IPAddress::FromString("203.0.113.88"));
    query.responseTimeMs = ReadU32(input, 4, 23u) % 5000u;

    const bool dga = filter.IsDGADomain(query.domain);
    (void)filter.OnDNSQuery(query);
    const auto stats = filter.GetStats();
    result.parsedOk = true;

    if (stats.dnsQueries == 0u) {
        RecordValidationIssue(result, "DNS query statistics were not updated.");
    }

    if (dga && stats.dgaDetected == 0u) {
        RecordValidationIssue(result, "DGA detection failed to account for a flagged query.");
    }

    return true;
}

bool ExerciseBeaconAnalysis(std::span<const uint8_t> input, HarnessResult& result) {
    PrepareFilterForIteration();

    auto& filter = SSRealTime::NetworkTrafficFilter::Instance();
    const auto remote = BuildBeaconEndpoint();
    SSRealTime::BeaconAnalysis analysis;

    const size_t iterations = SSRealTime::NetworkFilterConstants::MIN_BEACON_SAMPLES +
                              2u +
                              static_cast<size_t>((input.empty() ? 0u : input[0]) % 4u);
    for (size_t i = 0; i < iterations; ++i) {
        analysis = filter.AnalyzeBeaconPattern(kFuzzProcessId, remote);
    }

    result.parsedOk = true;

    if (analysis.sampleCount < SSRealTime::NetworkFilterConstants::MIN_BEACON_SAMPLES) {
        RecordValidationIssue(result, "Beacon tracker failed to retain the bounded minimum sample window.");
    }

    return true;
}

bool WriteSeed(
    const std::filesystem::path& path,
    std::span<const uint8_t> bytes)
{
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) {
        return false;
    }

    stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return stream.good();
}

void EnsureSeedCorpus(const std::filesystem::path& corpusDir) {
    const std::vector<std::pair<std::string, std::vector<uint8_t>>> seeds{
        {"seed-http-packet.bin", {0x00u, 0x00u, 'G', 'E', 'T', ' ', '/', 'i', 'n', 'd', 'e', 'x'}},
        {"seed-tls-ja3.bin", {0x02u, 0x00u, 0x16u, 0x03u, 0x03u, 0x01u, 0x23u, 0x45u, 0x67u}},
        {"seed-payload-base64.bin", {0x01u, 'Q', 'U', 'J', 'D', 'R', 'E', 'V', 'G', 'R', 'w', '='}},
        {"seed-filter-http.bin", {0x03u, 0x00u, 'P', 'O', 'S', 'T', ' ', '/', 'a', 'p', 'i'}},
        {"seed-dns-dga.bin", {0x04u, 0x10u, 'x', 'j', '9', 'q', 'v', '3', 'n', '6'}},
        {"seed-beacon.bin", {0x05u, 0x00u, 0xAAu, 0xBBu, 0xCCu, 0xDDu}},
    };

    for (const auto& [fileName, bytes] : seeds) {
        const auto path = corpusDir / fileName;
        if (std::filesystem::exists(path)) {
            continue;
        }

        (void)WriteSeed(path, bytes);
    }
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

    std::vector<uint8_t> bytes(static_cast<size_t>(size));
    stream.seekg(0, std::ios::beg);
    if (!bytes.empty() &&
        !stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()))) {
        return std::nullopt;
    }

    return bytes;
}

}  // namespace

unsigned long TrafficHarness::SEHCallTraffic(
    const uint8_t* data,
    const size_t size,
    HarnessResult* result) noexcept
{
    __try {
        if (result == nullptr) {
            return kSehInvalidParameter;
        }

        if (!ExerciseTrafficImpl(data, size, *result)) {
            if (!result->crashed && result->errorMessage.empty()) {
                result->errorMessage = "Traffic harness reported failure.";
            }
        }
        return kSehSuccess;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return static_cast<unsigned long>(GetExceptionCode());
    }
}

bool TrafficHarness::ExerciseTrafficImpl(
    const uint8_t* data,
    const size_t size,
    HarnessResult& result)
{
    const std::span<const uint8_t> input(
        (data == nullptr || size == 0u) ? nullptr : data,
        (data == nullptr) ? 0u : size);

    const std::lock_guard<std::mutex> lock(HarnessMutex());
    const uint8_t selector = input.empty() ? 0u : input[0];

    switch (selector % 6u) {
    case 0u:
        return ExerciseAnalyzePacket(input, result);
    case 1u:
        return ExerciseAnalyzePayload(input, result);
    case 2u:
        return ExerciseCalculateJa3(input, result);
    case 3u:
        return ExerciseFilterFlow(input, result);
    case 4u:
        return ExerciseDnsAndDga(input, result);
    default:
        return ExerciseBeaconAnalysis(input, result);
    }
}

HarnessResult TrafficHarness::Run(std::span<const uint8_t> input) noexcept {
    HarnessResult result;

    try {
        const unsigned long sehCode = SEHCallTraffic(
            input.empty() ? nullptr : input.data(),
            input.size(),
            &result);
        if (sehCode != kSehSuccess) {
            result.crashed = true;
            result.crashSignal = ExceptionCodeToStringInternal(sehCode);
            if (result.errorMessage.empty()) {
                result.errorMessage = "Traffic harness terminated with a structured exception.";
            }
        }
    }
    catch (const std::exception& ex) {
        result.crashed = true;
        result.crashSignal = "CPP_EXCEPTION";
        result.errorMessage = ex.what();
    }
    catch (...) {
        result.crashed = true;
        result.crashSignal = "CPP_UNKNOWN_EXCEPTION";
    }

    return result;
}

HarnessFunction TrafficHarness::GetHarnessFunction() noexcept {
    return [](std::span<const uint8_t> input) -> HarnessResult {
        return Run(input);
    };
}

std::string_view TrafficHarness::GetName() noexcept {
    return "traffic";
}

std::string_view TrafficHarness::GetDescription() noexcept {
    return "TrafficAnalyzer and NetworkTrafficFilter fuzz harness";
}

std::string TrafficHarness::ExceptionCodeToString(const unsigned long code) {
    return ExceptionCodeToStringInternal(code);
}

int RunTrafficFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config) noexcept
{
    if (!InstallCtrlCHandler()) {
        std::cerr << "[TrafficFuzzer] Warning: Failed to install Ctrl+C handler\n";
    }

    const auto corpusDir = workspaceDir / "corpora" / "traffic";
    const auto crashDir = workspaceDir / "crashes" / "traffic";

    std::error_code ec;
    std::filesystem::create_directories(corpusDir, ec);
    if (ec) {
        std::cerr << "[TrafficFuzzer] Failed to create corpus directory: " << corpusDir << '\n';
        return 1;
    }

    ec.clear();
    std::filesystem::create_directories(crashDir, ec);
    if (ec) {
        std::cerr << "[TrafficFuzzer] Failed to create crash directory: " << crashDir << '\n';
        return 1;
    }

    EnsureSeedCorpus(corpusDir);

    static constexpr std::array<std::string_view, 6> kSanitySeeds{
        "seed-http-packet.bin",
        "seed-tls-ja3.bin",
        "seed-payload-base64.bin",
        "seed-filter-http.bin",
        "seed-dns-dga.bin",
        "seed-beacon.bin",
    };

    for (const auto seedName : kSanitySeeds) {
        const auto seedBytes = ReadFileBytes(corpusDir / seedName);
        if (!seedBytes.has_value()) {
            std::cerr << "[TrafficFuzzer] Failed to read sanity seed: " << seedName << '\n';
            return 1;
        }

        const HarnessResult sanity = TrafficHarness::Run(*seedBytes);
        if (sanity.crashed || !sanity.parsedOk) {
            std::cerr << "[TrafficFuzzer] Sanity check failed for " << seedName;
            if (!sanity.errorMessage.empty()) {
                std::cerr << ": " << sanity.errorMessage;
            }
            if (!sanity.crashSignal.empty()) {
                std::cerr << " (" << sanity.crashSignal << ')';
            }
            std::cerr << '\n';
            return 1;
        }
    }

    FuzzLoopConfig loopConfig = config;
    loopConfig.targetName = std::string(TrafficHarness::GetName());

    std::cout << "[TrafficFuzzer] Starting traffic analysis fuzzing...\n";
    std::cout << "[TrafficFuzzer] Corpus: " << corpusDir << '\n';
    std::cout << "[TrafficFuzzer] Crashes: " << crashDir << '\n';

    FuzzLoop loop(corpusDir, crashDir, TrafficHarness::GetHarnessFunction(), loopConfig);
    const bool success = loop.Run();
    const auto& stats = loop.GetStatistics();

    std::cout << "\n[TrafficFuzzer] Final Results:\n";
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
