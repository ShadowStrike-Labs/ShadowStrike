/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Shared helpers for deterministic Core\Network unit tests.
 */

#pragma once

#include <Windows.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

namespace ShadowStrike::Core::Network::Test {

namespace fs = std::filesystem;

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

    [[nodiscard]] fs::path File(std::wstring_view name) const {
        return m_path / fs::path(name);
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

[[nodiscard]] inline std::string ReadTextFile(const fs::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        throw std::runtime_error("Failed to open text file");
    }

    return std::string(std::istreambuf_iterator<char>(stream),
                       std::istreambuf_iterator<char>());
}

}  // namespace ShadowStrike::Core::Network::Test
