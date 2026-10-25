/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file IpClassification.cpp
 * @brief Parse-then-mask address classification; see IpClassification.hpp.
 */
#include "pch.h"
#include "IpClassification.hpp"

#include <WinSock2.h>
#include <WS2tcpip.h>

#include <cstdint>
#include <cstring>
#include <string>

#pragma comment(lib, "Ws2_32.lib")

namespace ShadowStrike::Utils::Ip {
namespace {

// The longest textual IPv6 address is 45 characters (INET6_ADDRSTRLEN - 1); anything longer is not
// an address and is refused before it is copied.
constexpr size_t kMaxLiteral = 64;

[[nodiscard]] bool ParseV4(std::string_view text, in_addr& out) noexcept {
    if (text.empty() || text.size() > kMaxLiteral) return false;
    const std::string copy(text);
    return ::inet_pton(AF_INET, copy.c_str(), &out) == 1;
}

[[nodiscard]] bool ParseV6(std::string_view text, in6_addr& out) noexcept {
    if (const size_t zone = text.find('%'); zone != std::string_view::npos) {
        if (zone + 1 == text.size()) return false;   // "fe80::1%" names no zone
        text = text.substr(0, zone);
    }
    if (text.empty() || text.size() > kMaxLiteral) return false;
    const std::string copy(text);
    return ::inet_pton(AF_INET6, copy.c_str(), &out) == 1;
}

[[nodiscard]] bool IsPrivateOrLocalV4(uint32_t hostOrder) noexcept {
    return (hostOrder & 0xFF000000u) == 0x0A000000u ||   // 10.0.0.0/8
           (hostOrder & 0xFFF00000u) == 0xAC100000u ||   // 172.16.0.0/12
           (hostOrder & 0xFFFF0000u) == 0xC0A80000u ||   // 192.168.0.0/16
           (hostOrder & 0xFF000000u) == 0x7F000000u ||   // 127.0.0.0/8
           (hostOrder & 0xFFFF0000u) == 0xA9FE0000u;     // 169.254.0.0/16
}

}  // namespace

bool IsIPv4Literal(std::string_view text) noexcept {
    try {
        in_addr addr{};
        return ParseV4(text, addr);
    } catch (...) {
        return false;
    }
}

bool IsIPv6Literal(std::string_view text) noexcept {
    try {
        in6_addr addr{};
        return ParseV6(text, addr);
    } catch (...) {
        return false;
    }
}

bool IsPrivateOrLocalAddress(std::string_view text) noexcept {
    try {
        if (in_addr v4{}; ParseV4(text, v4)) {
            return IsPrivateOrLocalV4(ntohl(v4.s_addr));
        }
        in6_addr v6{};
        if (!ParseV6(text, v6)) return false;
        const uint8_t* b = v6.s6_bytes;

        static constexpr uint8_t kLoopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        if (std::memcmp(b, kLoopback, sizeof(kLoopback)) == 0) return true;   // ::1
        if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return true;                // fe80::/10
        if ((b[0] & 0xFE) == 0xFC) return true;                                // fc00::/7

        // ::ffff:a.b.c.d carries an IPv4 address and is exactly as private as that address.
        static constexpr uint8_t kMappedPrefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
        if (std::memcmp(b, kMappedPrefix, sizeof(kMappedPrefix)) == 0) {
            const uint32_t mapped = (static_cast<uint32_t>(b[12]) << 24) | (static_cast<uint32_t>(b[13]) << 16) |
                                    (static_cast<uint32_t>(b[14]) << 8) | static_cast<uint32_t>(b[15]);
            return IsPrivateOrLocalV4(mapped);
        }
        return false;
    } catch (...) {
        return false;
    }
}

}  // namespace ShadowStrike::Utils::Ip
