/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Shared helpers for deterministic RealTime unit tests.
 */

#pragma once

#include <algorithm>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::RealTime::Tests {

template <typename T>
[[nodiscard]] inline bool ContainsValue(std::span<const T> values, const T& expected) {
    return std::find(values.begin(), values.end(), expected) != values.end();
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

[[nodiscard]] inline bool ContainsSubstring(
    std::string_view haystack,
    std::string_view needle) {
    return haystack.find(needle) != std::string_view::npos;
}

}  // namespace ShadowStrike::RealTime::Tests
