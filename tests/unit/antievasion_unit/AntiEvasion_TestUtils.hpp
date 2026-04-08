#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <initializer_list>
#include <stdexcept>
#include <vector>

#include "../../../src/Shared_modules/Utils/NetworkUtils.hpp"

namespace ShadowStrike::AntiEvasion::Tests {

inline std::chrono::system_clock::time_point SecondsAfter(
    const std::chrono::system_clock::time_point base,
    const int64_t seconds) noexcept {
    return base + std::chrono::seconds(seconds);
}

inline std::vector<std::chrono::system_clock::time_point> BuildSystemClockSeries(
    std::initializer_list<int64_t> offsetsSeconds) {
    const auto base = std::chrono::system_clock::time_point{};

    std::vector<std::chrono::system_clock::time_point> timestamps;
    timestamps.reserve(offsetsSeconds.size());

    for (const int64_t offset : offsetsSeconds) {
        timestamps.push_back(SecondsAfter(base, offset));
    }

    return timestamps;
}

inline ShadowStrike::Utils::NetworkUtils::MacAddress MakeMac(
    std::initializer_list<uint8_t> bytes) {
    std::array<uint8_t, 6> macBytes{};
    size_t index = 0;

    for (const uint8_t byte : bytes) {
        if (index >= macBytes.size()) {
            throw std::invalid_argument("MAC address must contain exactly six bytes");
        }

        macBytes[index++] = byte;
    }

    if (index != macBytes.size()) {
        throw std::invalid_argument("MAC address must contain exactly six bytes");
    }

    return ShadowStrike::Utils::NetworkUtils::MacAddress{ macBytes };
}

} // namespace ShadowStrike::AntiEvasion::Tests
