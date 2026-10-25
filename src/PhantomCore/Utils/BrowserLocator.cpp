/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "pch.h"
#include "BrowserLocator.hpp"

#include <system_error>
#include <vector>

#ifdef _WIN32
#  include <Windows.h>
#endif

namespace ShadowStrike::Utils::Browser {

namespace {

/// Expands %VAR% references; empty when a variable is undefined (the result would
/// otherwise still contain the literal %VAR% and could name a relative path).
[[nodiscard]] std::wstring ExpandPattern(std::wstring_view pattern) {
#ifdef _WIN32
    const std::wstring in(pattern);
    const DWORD required = ::ExpandEnvironmentStringsW(in.c_str(), nullptr, 0);
    if (required == 0 || required > 32768) {
        return {};
    }
    std::vector<wchar_t> buffer(required);
    const DWORD written = ::ExpandEnvironmentStringsW(in.c_str(), buffer.data(), required);
    if (written == 0 || written > required) {
        return {};
    }
    std::wstring out(buffer.data());
    if (out.find(L'%') != std::wstring::npos) {
        return {};
    }
    return out;
#else
    (void)pattern;
    return {};
#endif
}

}  // namespace

std::filesystem::path FindBrowserExecutable(InstalledBrowser b) noexcept {
    try {
        for (const auto pattern : ExecutablePathPatterns(b)) {
            const std::wstring expanded = ExpandPattern(pattern);
            if (expanded.empty()) {
                continue;
            }
            const std::filesystem::path candidate(expanded);
            std::error_code ec;
            if (candidate.is_absolute() && std::filesystem::is_regular_file(candidate, ec)) {
                return candidate;
            }
        }
    } catch (...) {
        // allocation failure: report not found rather than a wrong path
    }
    return {};
}

}  // namespace ShadowStrike::Utils::Browser
