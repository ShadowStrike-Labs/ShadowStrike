/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file FileExtensionRisk.hpp
 * @brief The one list of file extensions that carry executable content.
 *
 * WHY THIS EXISTS (task 309). Five copies of this list decided whether an
 * attachment or download is dangerous - EmailProtection (20 entries),
 * AttachmentScanner (22), MaliciousDownloadBlocker (21), OutlookScanner (25) and
 * PhantomCore's EmailScanner (14) - and no copy was a superset of another. The
 * email attachment scanner did not know .cpl (a Control Panel applet is a DLL that
 * runs on double-click); EmailProtection and the download blocker covered .vbs but
 * not .vbe, its encoded form. Copying entries between the copies fixes today and
 * guarantees the next divergence, so every consumer now asks this header.
 *
 * WHAT IS AND IS NOT DECIDED HERE. This answers one question - can a file of this
 * extension execute code when opened - and each consumer keeps its own policy for
 * what to do about it, and its own way of extracting the extension (the download
 * blocker deliberately treats "evil.exe." as extension "."; see
 * DownloadExtensionPolicy_Tests). Macro-enabled Office formats, archives and
 * document types are separate questions with their own lists.
 *
 * Matching is ASCII case-insensitive and WHOLE-STRING, leading dot included:
 * ".EXE" matches, ".exe.txt", "exe" and ".ex" do not.
 */

#pragma once

#include <array>
#include <cstddef>
#include <string_view>

namespace ShadowStrike::Utils::FileExtensionRisk {

/// The union of the five former lists, lower case, sorted. Adding an entry here
/// changes every consumer at once, which is the point.
inline constexpr std::array<std::string_view, 28> kExecutableContentExtensions = {
    ".ade",  ".adp",  ".app",  ".bat",  ".cmd",  ".com",  ".cpl",
    ".dll",  ".exe",  ".hta",  ".inf",  ".jar",  ".js",   ".jse",
    ".lnk",  ".msi",  ".msp",  ".pif",  ".ps1",  ".psd1", ".psm1",
    ".reg",  ".scr",  ".sys",  ".vbe",  ".vbs",  ".wsf",  ".wsh",
};

// The list must stay lower case, dot-led, sorted and free of duplicates: the
// matcher folds only the candidate, and a duplicate would hide a missing entry
// from anyone counting.
static_assert([] {
    for (std::size_t i = 0; i < kExecutableContentExtensions.size(); ++i) {
        const auto e = kExecutableContentExtensions[i];
        if (e.size() < 2 || e[0] != '.') return false;
        for (const char c : e) {
            if (c >= 'A' && c <= 'Z') return false;
        }
        if (i > 0 && !(kExecutableContentExtensions[i - 1] < e)) return false;
    }
    return true;
}(), "kExecutableContentExtensions must be lower case, dot-led, sorted and unique");

namespace detail {

template <typename CharT>
[[nodiscard]] constexpr bool EqualsAsciiLower(std::basic_string_view<CharT> candidate,
                                              std::string_view lowerEntry) noexcept {
    if (candidate.size() != lowerEntry.size()) {
        return false;
    }
    for (std::size_t i = 0; i < candidate.size(); ++i) {
        const auto c = candidate[i];
        // Only ASCII letters fold. A non-ASCII code unit can never equal an entry,
        // which is all ASCII, so it is compared unfolded and simply fails.
        const auto folded = (c >= CharT('A') && c <= CharT('Z')) ? static_cast<CharT>(c - CharT('A') + CharT('a')) : c;
        if (folded != static_cast<CharT>(static_cast<unsigned char>(lowerEntry[i]))) {
            return false;
        }
    }
    return true;
}

template <typename CharT>
[[nodiscard]] constexpr bool IsExecutableContentImpl(std::basic_string_view<CharT> extension) noexcept {
    for (const auto entry : kExecutableContentExtensions) {
        if (EqualsAsciiLower(extension, entry)) {
            return true;
        }
    }
    return false;
}

} // namespace detail

/// True when a file with this extension (leading dot included) can execute code
/// when opened.
[[nodiscard]] constexpr bool IsExecutableContentExtension(std::string_view extension) noexcept {
    return detail::IsExecutableContentImpl(extension);
}

/// Wide overload for callers holding std::wstring / std::filesystem paths.
[[nodiscard]] constexpr bool IsExecutableContentExtension(std::wstring_view extension) noexcept {
    return detail::IsExecutableContentImpl(extension);
}

/// The final extension of a file NAME, leading dot included, or empty when the
/// name has none. "invoice.pdf.exe" gives ".exe"; "README" and "dir\\" give "".
template <typename CharT>
[[nodiscard]] constexpr std::basic_string_view<CharT> LastExtension(std::basic_string_view<CharT> fileName) noexcept {
    // The extension must lie inside the final path component.
    std::size_t start = 0;
    for (std::size_t i = fileName.size(); i > 0; --i) {
        const auto c = fileName[i - 1];
        if (c == CharT('\\') || c == CharT('/')) {
            start = i;
            break;
        }
    }
    const auto dot = fileName.rfind(CharT('.'));
    if (dot == std::basic_string_view<CharT>::npos || dot < start) {
        return {};
    }
    return fileName.substr(dot);
}

} // namespace ShadowStrike::Utils::FileExtensionRisk
