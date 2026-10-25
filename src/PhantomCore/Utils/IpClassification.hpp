/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file IpClassification.hpp
 * @brief Is a textual address IPv6, and is it reachable only from the local network?
 *
 * WHY THIS EXISTS (task 295). Two IPLeakProtection modules (Privacy and IoT) each exported their
 * own IsPrivateIP and IsIPv6Address, and they disagreed: the Privacy copy compared text, so it
 * classified 10.999.999.999 as private and covered a sixteenth of fe80::/10, and both IPv6 tests
 * were a single find(':'), so "example.com:8080" was "IPv6". Every answer here comes from parsing
 * the literal first and then testing bit masks, which cannot drift from a prefix length the way a
 * text comparison can.
 *
 * WHAT "PRIVATE OR LOCAL" COVERS:
 *   IPv4  10/8, 172.16/12, 192.168/16 (RFC 1918), 127/8 loopback, 169.254/16 link-local
 *   IPv6  ::1 loopback, fe80::/10 link-local, fc00::/7 unique-local, and an IPv4-mapped
 *         address (::ffff:a.b.c.d) classified by the IPv4 address it carries
 *
 * DELIBERATELY NOT COVERED: 100.64/10 carrier-grade NAT. Whether a CGNAT address seen as the
 * machine's public address is a leak is a product decision (register 340), not arithmetic.
 *
 * An IPv6 zone suffix ("fe80::1%12", as Windows reports adapter addresses) is accepted and
 * ignored. Brackets, ports and host names are not addresses and answer false.
 */
#pragma once

#include <string_view>

namespace ShadowStrike::Utils::Ip {

/// True when `text` parses as a dotted-quad IPv4 address.
[[nodiscard]] bool IsIPv4Literal(std::string_view text) noexcept;

/// True when `text` parses as an IPv6 address (an optional %zone suffix is ignored).
[[nodiscard]] bool IsIPv6Literal(std::string_view text) noexcept;

/// True when `text` is an IPv4 or IPv6 address in a range listed in the file comment.
/// Anything that does not parse as an address is not private.
[[nodiscard]] bool IsPrivateOrLocalAddress(std::string_view text) noexcept;

}  // namespace ShadowStrike::Utils::Ip
