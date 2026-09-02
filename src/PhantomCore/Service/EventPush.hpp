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
 * ShadowStrike NGAV - SERVICE-SIDE PUSH-EVENT BUILDER
 * ============================================================================
 *
 * @file EventPush.hpp
 * @brief Pure service-tier functions that construct pre-serialised push-event
 *        envelopes ready to pass to ServiceCommunicator::BroadcastEvent().
 *
 * Wire format (little-endian, 24-byte header + JSON body):
 *   [magic:       4 bytes]  0x53534156 ("SSAV")
 *   [version:     2 bytes]  1
 *   [reserved:    2 bytes]  0x0000
 *   [type:        4 bytes]  CommandType raw uint32
 *   [requestId:   8 bytes]  0  (push events are unsolicited)
 *   [payloadSize: 4 bytes]  JSON byte count
 *   [json:   payloadSize]   UTF-8 JSON payload
 *
 * Cross-reference: ShadowStrike::PhantomHome::IPC::Envelope::Serialize()
 *                  (src/Products/Community/PhantomHome/UI/IPC/Messages.hpp)
 *
 * This header deliberately does NOT include Messages.hpp: that file lives in
 * the UI tier and pulls in Qt; service-tier code must remain Qt-free.
 * The serialisation is inlined in EventPush.cpp with a reference comment.
 *
 * @note Do NOT call these builders from detection hot paths.  Build the
 *       envelope on a low-priority thread and pass it to BroadcastEvent().
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * ============================================================================
 */

#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

namespace ShadowStrike::Service::Events {

/**
 * @brief Serialise a ProtectionStateChanged push-event envelope.
 *
 * JSON payload: { "newState": "<newState>", "reason": "<reason>" }
 * CommandType:  ProtectionStateChanged (102)
 * requestId:    0 (unsolicited)
 *
 * @param newState  Machine-readable protection state string (e.g. "active",
 *                  "paused", "error").  Not logged or user-visible by this layer.
 * @param reason    Short English description of why the state changed.
 * @return Serialised wire buffer, or empty on internal failure.
 */
[[nodiscard]] std::vector<std::uint8_t>
BuildProtectionStateChanged(std::string_view newState, std::string_view reason);

/**
 * @brief Serialise a HeadlineStateChanged push-event envelope.
 *
 * JSON payload: { "state": "<state>" }
 * CommandType:  HeadlineStateChanged (104)
 * requestId:    0
 *
 * @param state  Headline protection indicator string (e.g. "protected",
 *               "at_risk", "critical").
 * @return Serialised wire buffer, or empty on internal failure.
 */
[[nodiscard]] std::vector<std::uint8_t>
BuildHeadlineStateChanged(std::string_view state);

/**
 * @brief Serialise a ScanProgressEvent push-event envelope.
 *
 * JSON payload:
 *   { "scanId": "<scanId>", "percent": <int>,
 *     "itemsScanned": <uint64>, "threatsFound": <uint64> }
 * CommandType: ScanProgressEvent (103)
 * requestId:   0
 *
 * @param scanId        Unique identifier of the in-progress scan, as issued by
 *                      StartScan. A STRING, not a number: ids are minted as
 *                      "scan-<n>", so a numeric parameter could not carry one and
 *                      the only caller passed a literal 0 instead. The UI keys
 *                      its progress polling on this value.
 * @param percent       Completion percentage [0, 100].  Clamped if out-of-range.
 * @param itemsScanned  Number of items inspected so far.
 * @param threatsFound  Number of threats detected so far.
 * @return Serialised wire buffer, or empty on internal failure.
 */
[[nodiscard]] std::vector<std::uint8_t>
BuildScanProgressEvent(std::string_view scanId,
                       int              percent,
                       std::uint64_t    itemsScanned,
                       std::uint64_t    threatsFound);

/**
 * @brief Serialise a PgtiFeedUpdated push-event envelope.
 *
 * JSON payload: { "feedId": "<feedId>", "health": "<health>" }
 * CommandType:  PgtiFeedUpdated (106)
 * requestId:    0
 *
 * @param feedId   Canonical PGTI feed identifier (e.g. "malware_ip").
 * @param health   Health state string: "healthy" | "degraded" | "failed" | "disabled".
 * @return Serialised wire buffer, or empty on internal failure.
 */
[[nodiscard]] std::vector<std::uint8_t>
BuildPgtiFeedUpdated(std::string_view feedId, std::string_view health);

/**
 * @brief Serialise a RecommendationsChanged push-event envelope.
 *
 * JSON payload: { "activeCount": <uint32> }
 * CommandType:  RecommendationsChanged (107)
 * requestId:    0
 *
 * @param activeCount  Number of currently active (non-dismissed) recommendations.
 * @return Serialised wire buffer, or empty on internal failure.
 */
[[nodiscard]] std::vector<std::uint8_t>
BuildRecommendationsChanged(std::uint32_t activeCount);

} // namespace ShadowStrike::Service::Events
