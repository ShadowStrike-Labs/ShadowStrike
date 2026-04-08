/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Shared helpers for deterministic Core\Registry unit tests.
 */

#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Core::Registry::Test {

[[nodiscard]] inline std::vector<uint8_t> WideStringToRegistryBytes(
    std::wstring_view value,
    bool includeNull = true) {
    const size_t charCount = value.size() + (includeNull ? 1u : 0u);
    std::vector<uint8_t> bytes(charCount * sizeof(wchar_t), 0);

    if (!value.empty()) {
        std::memcpy(bytes.data(), value.data(), value.size() * sizeof(wchar_t));
    }

    return bytes;
}

[[nodiscard]] inline std::vector<uint8_t> NarrowBytes(std::string_view value) {
    return std::vector<uint8_t>(value.begin(), value.end());
}

[[nodiscard]] inline std::vector<uint8_t> HighEntropyBytes(size_t size) {
    std::vector<uint8_t> bytes(size);
    for (size_t i = 0; i < size; ++i) {
        bytes[i] = static_cast<uint8_t>(i & 0xFF);
    }
    return bytes;
}

[[nodiscard]] inline bool ContainsString(
    std::span<const std::string> values,
    std::string_view expected) {
    return std::find_if(
        values.begin(),
        values.end(),
        [expected](const std::string& value) { return value == expected; }) != values.end();
}

[[nodiscard]] inline bool ContainsWideString(
    std::span<const std::wstring> values,
    std::wstring_view expected) {
    return std::find_if(
        values.begin(),
        values.end(),
        [expected](const std::wstring& value) { return value == expected; }) != values.end();
}

}  // namespace ShadowStrike::Core::Registry::Test
