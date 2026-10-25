/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file BrowserLocator.hpp
 * @brief The ONE answer to "where is this browser's executable installed" (task 316).
 *
 * PrivacyCleaner returned hard-coded literals it never checked (Chrome under Program Files
 * only, so neither the x86 nor the per-user install was found; Chromium had none at all),
 * while SecureBrowser expanded a pattern list and tested each candidate but knew only
 * Chrome, Edge and Firefox. Both now ask this header.
 *
 * Candidates are environment-variable patterns, tried in order; the first that expands and
 * exists wins. %LocalAppData% resolves for the calling process's user, so a SYSTEM caller
 * finds machine-wide installs only; that is the honest limit of a path lookup.
 *
 * Chromium's official builds are named chrome.exe. ProcessImageName therefore returns
 * chrome.exe for it, and callers that act on processes must also match the IMAGE PATH
 * (ImagePathMatchRequired) or they would act on Google Chrome.
 */
#pragma once

#include <array>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>

namespace ShadowStrike::Utils::Browser {

enum class InstalledBrowser : unsigned char {
    Chrome, Edge, Firefox, Opera, Brave, Vivaldi, Chromium
};

/// Install-location patterns, most common first.
[[nodiscard]] constexpr std::span<const std::wstring_view> ExecutablePathPatterns(InstalledBrowser b) noexcept {
    using namespace std::string_view_literals;
    static constexpr std::array chrome = {
        L"%ProgramFiles%\\Google\\Chrome\\Application\\chrome.exe"sv,
        L"%ProgramFiles(x86)%\\Google\\Chrome\\Application\\chrome.exe"sv,
        L"%LocalAppData%\\Google\\Chrome\\Application\\chrome.exe"sv};
    static constexpr std::array edge = {
        L"%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe"sv,
        L"%ProgramFiles%\\Microsoft\\Edge\\Application\\msedge.exe"sv};
    static constexpr std::array firefox = {
        L"%ProgramFiles%\\Mozilla Firefox\\firefox.exe"sv,
        L"%ProgramFiles(x86)%\\Mozilla Firefox\\firefox.exe"sv,
        L"%LocalAppData%\\Mozilla Firefox\\firefox.exe"sv};
    static constexpr std::array opera = {
        L"%LocalAppData%\\Programs\\Opera\\launcher.exe"sv,
        L"%ProgramFiles%\\Opera\\launcher.exe"sv};
    static constexpr std::array brave = {
        L"%ProgramFiles%\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"sv,
        L"%ProgramFiles(x86)%\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"sv,
        L"%LocalAppData%\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"sv};
    static constexpr std::array vivaldi = {
        L"%LocalAppData%\\Vivaldi\\Application\\vivaldi.exe"sv,
        L"%ProgramFiles%\\Vivaldi\\Application\\vivaldi.exe"sv};
    static constexpr std::array chromium = {
        L"%LocalAppData%\\Chromium\\Application\\chrome.exe"sv,
        L"%ProgramFiles%\\Chromium\\Application\\chrome.exe"sv};
    switch (b) {
        case InstalledBrowser::Chrome:   return chrome;
        case InstalledBrowser::Edge:     return edge;
        case InstalledBrowser::Firefox:  return firefox;
        case InstalledBrowser::Opera:    return opera;
        case InstalledBrowser::Brave:    return brave;
        case InstalledBrowser::Vivaldi:  return vivaldi;
        case InstalledBrowser::Chromium: return chromium;
    }
    return {};
}

/// The image name its processes run under. Opera's launcher.exe starts opera.exe.
[[nodiscard]] constexpr std::wstring_view ProcessImageName(InstalledBrowser b) noexcept {
    switch (b) {
        case InstalledBrowser::Chrome:   return L"chrome.exe";
        case InstalledBrowser::Edge:     return L"msedge.exe";
        case InstalledBrowser::Firefox:  return L"firefox.exe";
        case InstalledBrowser::Opera:    return L"opera.exe";
        case InstalledBrowser::Brave:    return L"brave.exe";
        case InstalledBrowser::Vivaldi:  return L"vivaldi.exe";
        case InstalledBrowser::Chromium: return L"chrome.exe";
    }
    return {};
}

/// True when the image name is shared with another browser, so a process must also be
/// matched by its image path. Only Chromium (chrome.exe, as Google Chrome).
[[nodiscard]] constexpr bool ImagePathMatchRequired(InstalledBrowser b) noexcept {
    return b == InstalledBrowser::Chromium;
}

/// The first candidate that exists, or empty when the browser is not installed where it
/// is looked for.
[[nodiscard]] std::filesystem::path FindBrowserExecutable(InstalledBrowser b) noexcept;

}  // namespace ShadowStrike::Utils::Browser
