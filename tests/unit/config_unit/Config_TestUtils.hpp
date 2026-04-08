/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Shared helpers for deterministic Config module unit tests.
 */

#pragma once

#include <Windows.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>

#include "../../../include/nlohmann/json.hpp"

namespace ShadowStrike::Config::Test {

namespace fs = std::filesystem;
using Json = nlohmann::json;

class ScopedTempDir final {
public:
    explicit ScopedTempDir(std::wstring_view prefix) {
        wchar_t buffer[MAX_PATH]{};
        const DWORD length = ::GetTempPathW(MAX_PATH, buffer);
        if (length == 0 || length >= MAX_PATH) {
            throw std::runtime_error("GetTempPathW failed");
        }

        m_path = fs::path(buffer) / UniqueWide(prefix);
        std::error_code ec;
        if (!fs::create_directories(m_path, ec) && ec) {
            throw std::runtime_error("Failed to create temporary directory");
        }
    }

    ~ScopedTempDir() {
        std::error_code ec;
        fs::remove_all(m_path, ec);
    }

    ScopedTempDir(const ScopedTempDir&) = delete;
    ScopedTempDir& operator=(const ScopedTempDir&) = delete;

    [[nodiscard]] const fs::path& Path() const noexcept {
        return m_path;
    }

    [[nodiscard]] fs::path File(std::wstring_view fileName) const {
        return m_path / fs::path(fileName);
    }

private:
    fs::path m_path;

    [[nodiscard]] static std::wstring UniqueWide(std::wstring_view prefix) {
        static std::atomic_uint64_t counter{0};
        return std::wstring(prefix) +
               std::to_wstring(::GetCurrentProcessId()) + L"_" +
               std::to_wstring(counter.fetch_add(1, std::memory_order_relaxed));
    }
};

[[nodiscard]] inline std::string UniqueUtf8(std::string_view prefix) {
    static std::atomic_uint64_t counter{0};
    return std::string(prefix) + "_" +
           std::to_string(::GetCurrentProcessId()) + "_" +
           std::to_string(counter.fetch_add(1, std::memory_order_relaxed));
}

inline void WriteUtf8File(const fs::path& path, const std::string& content) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) {
        throw std::runtime_error("Failed to open file for writing");
    }
    stream.write(content.data(), static_cast<std::streamsize>(content.size()));
    if (!stream.good()) {
        throw std::runtime_error("Failed to write file content");
    }
}

[[nodiscard]] inline Json ReadJsonFile(const fs::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        throw std::runtime_error("Failed to open JSON file");
    }
    return Json::parse(stream);
}

[[nodiscard]] inline Json ParseJson(const std::string& text) {
    return Json::parse(text);
}

}  // namespace ShadowStrike::Config::Test
