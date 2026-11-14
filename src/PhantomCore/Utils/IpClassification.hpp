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
 *   IPv4  10/8, 172.16/12, 192.168/16 (RFC 1918), 127/8 loopback, 169.254/16 link-local,
 *         100.64/10 carrier-grade NAT (RFC 6598)
 *   IPv6  ::1 loopback, fe80::/10 link-local, fc00::/7 unique-local, and an IPv4-mapped
 *         address (::ffff:a.b.c.d) classified by the IPv4 address it carries
 *
 * 100.64/10 carrier-grade NAT: covered as private per register 340 item 9 - it is not
 * internet-routable, so a CGNAT address seen as the machine's "public" address is not a
 * disclosure of public identity. This only sets the informational isPrivate flag; it does
 * NOT suppress a VPN leak, because CheckForLeaks decides a leak by comparing the observed
 * public address against the VPN adapter's address (a mismatch is a leak regardless of
 * whether the observed address is private), so a CGNAT address seen while the VPN is up
 * still mismatches and still fires.
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
