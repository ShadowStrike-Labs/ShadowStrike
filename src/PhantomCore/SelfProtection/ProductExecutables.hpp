// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * ShadowStrike Phantom - The executables this product installs
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 */

/**
 * @file ProductExecutables.hpp
 * @brief One list of the product's own process images, and the test that tells one from an impostor.
 *
 * Self-protection modules each kept their own list of "our executables", and each list drifted from
 * the installer on its own: SelfDefense and ProcessProtection were corrected separately, and
 * RegistryProtection still guarded ShadowStrikeUI.exe and ShadowStrikeUpdater.exe, names this product
 * has never installed, while the shipped UI, tray and driver-resume helper had no guard. A list that
 * names files that do not exist reports success and protects nothing, so the lists now read one array.
 *
 * The MSI File table is the authority. A process image added to the installer is added here once.
 *
 * A NAME IS NOT AN IDENTITY. Any binary can be renamed to one of these, so a caller that grants trust
 * must also require IsInsideInstallDirectory (the directory the running product was started from).
 */

#pragma once

#include <Windows.h>

#include <array>
#include <string>
#include <string_view>

namespace ShadowStrike::Security::ProductExecutables {

/// The process images the installer ships, as named in the MSI File table.
inline constexpr std::array<std::wstring_view, 4> kNames = {
    L"ShadowStrikePhantomService.exe",
    L"ShadowStrikePhantomTray.exe",
    L"ShadowStrikePhantomUI.exe",
    L"ShadowStrikeDriverResume.exe",
};

namespace detail {
[[nodiscard]] inline bool OrdinalEqualsIgnoreCase(std::wstring_view a, std::wstring_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    if (a.empty()) {
        return true;
    }
    return ::CompareStringOrdinal(a.data(), static_cast<int>(a.size()),
                                  b.data(), static_cast<int>(b.size()), TRUE) == CSTR_EQUAL;
}
}  // namespace detail

/// True when fileName (a bare file name, no directory) is one of kNames, compared case-insensitively.
[[nodiscard]] inline bool IsProductName(std::wstring_view fileName) noexcept {
    for (const auto name : kNames) {
        if (detail::OrdinalEqualsIgnoreCase(name, fileName)) {
            return true;
        }
    }
    return false;
}

/// True when imagePath names a file below directory. The directory must end in a separator, which is
/// what stops a sibling sharing its prefix (C:\Program Files\ShadowStrike2\) from matching. An empty or
/// unterminated directory matches nothing, so an unresolvable install directory fails closed.
[[nodiscard]] inline bool IsInsideDirectory(std::wstring_view imagePath, std::wstring_view directory) noexcept {
    if (directory.empty() || directory.back() != L'\\' || imagePath.size() <= directory.size()) {
        return false;
    }
    return detail::OrdinalEqualsIgnoreCase(imagePath.substr(0, directory.size()), directory);
}

/// The directory the running executable was started from, with a trailing separator. Resolved once:
/// it cannot change while the process runs. Empty when the module path cannot be read.
[[nodiscard]] inline const std::wstring& InstallDirectory() {
    static const std::wstring directory = []() -> std::wstring {
        std::wstring buffer(32768, L'\0');
        const DWORD length = ::GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0 || length >= buffer.size()) {
            return {};
        }
        buffer.resize(length);
        const auto slash = buffer.find_last_of(L'\\');
        return slash == std::wstring::npos ? std::wstring{} : buffer.substr(0, slash + 1);
    }();
    return directory;
}

/// True when imagePath lies below the directory the running product was started from.
[[nodiscard]] inline bool IsInsideInstallDirectory(std::wstring_view imagePath) {
    return IsInsideDirectory(imagePath, InstallDirectory());
}

}  // namespace ShadowStrike::Security::ProductExecutables
