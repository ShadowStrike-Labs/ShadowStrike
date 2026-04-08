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
#include <filesystem>
#include <fstream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Core::Registry::Test {

namespace fs = std::filesystem;

[[nodiscard]] inline std::wstring MakeUniqueWideName(std::wstring_view prefix) {
    GUID guid{};
    if (FAILED(::CoCreateGuid(&guid))) {
        return std::wstring(prefix) + L"_fallback";
    }

    wchar_t buffer[96]{};
    swprintf_s(
        buffer,
        L"%ls_%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
        std::wstring(prefix).c_str(),
        guid.Data1,
        guid.Data2,
        guid.Data3,
        guid.Data4[0],
        guid.Data4[1],
        guid.Data4[2],
        guid.Data4[3],
        guid.Data4[4],
        guid.Data4[5],
        guid.Data4[6],
        guid.Data4[7]);
    return buffer;
}

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

class TempDirectoryGuard {
public:
    explicit TempDirectoryGuard(std::wstring_view prefix = L"ShadowStrike_CoreRegistry_UT") {
        root_ = fs::temp_directory_path() / fs::path(MakeUniqueWideName(prefix));
        std::error_code ec;
        fs::create_directories(root_, ec);
        if (ec) {
            throw std::runtime_error("Failed to create Core\\Registry test temp directory");
        }
    }

    ~TempDirectoryGuard() {
        std::error_code ec;
        fs::remove_all(root_, ec);
    }

    [[nodiscard]] const fs::path& Root() const noexcept {
        return root_;
    }

    [[nodiscard]] fs::path Path(std::wstring_view relative) const {
        return root_ / fs::path(std::wstring(relative));
    }

    [[nodiscard]] fs::path WriteBytes(std::wstring_view relative, std::span<const uint8_t> bytes) const {
        const fs::path fullPath = Path(relative);
        std::error_code ec;
        fs::create_directories(fullPath.parent_path(), ec);
        if (ec) {
            throw std::runtime_error("Failed to create parent directory for Core\\Registry test file");
        }

        std::ofstream stream(fullPath, std::ios::binary | std::ios::trunc);
        if (!stream.is_open()) {
            throw std::runtime_error("Failed to open Core\\Registry test file for binary write");
        }

        if (!bytes.empty()) {
            stream.write(
                reinterpret_cast<const char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
        }

        if (!stream.good()) {
            throw std::runtime_error("Failed to write Core\\Registry test binary file");
        }

        return fullPath;
    }

    [[nodiscard]] fs::path WriteText(std::wstring_view relative, std::string_view text) const {
        const auto bytes = NarrowBytes(text);
        return WriteBytes(relative, bytes);
    }

    [[nodiscard]] std::string ReadText(const fs::path& path) const {
        std::ifstream stream(path, std::ios::binary);
        if (!stream.is_open()) {
            throw std::runtime_error("Failed to open Core\\Registry test file for read");
        }

        return std::string(
            std::istreambuf_iterator<char>(stream),
            std::istreambuf_iterator<char>());
    }

private:
    fs::path root_;
};

}  // namespace ShadowStrike::Core::Registry::Test
