/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::LiveResponse {

struct ProcessSnapshot {
    uint32_t pid = 0;
    uint32_t parentPid = 0;
    std::wstring name;
    std::wstring path;
    std::wstring commandLine;
    std::wstring userName;
    std::wstring integrityLevel;
    bool isElevated = false;
    uint64_t workingSetSize = 0;
    uint64_t privateBytes = 0;
    std::chrono::system_clock::time_point startTime{};

    struct ModuleInfo {
        std::wstring name;
        std::wstring path;
        uintptr_t baseAddress = 0;
        size_t size = 0;
        bool isSigned = false;
    };
    std::vector<ModuleInfo> modules;

    struct ThreadInfo {
        uint32_t tid = 0;
        int basePriority = 0;
        bool isSuspended = false;
        uintptr_t startAddress = 0;
    };
    std::vector<ThreadInfo> threads;

    struct HandleInfo {
        std::wstring typeName;
        std::wstring objectName;
        uint32_t handleValue = 0;
    };
    std::vector<HandleInfo> handles;

    struct ConnectionInfo {
        std::string localAddress;
        uint16_t localPort = 0;
        std::string remoteAddress;
        uint16_t remotePort = 0;
        std::string protocol;
        std::string state;
    };
    std::vector<ConnectionInfo> connections;
};

struct RegistryKeySnapshot {
    std::wstring fullPath;
    std::wstring name;
    uint32_t subKeyCount = 0;
    uint32_t valueCount = 0;
    std::chrono::system_clock::time_point lastWriteTime{};

    struct ValueInfo {
        std::wstring name;
        uint32_t type = 0;
        std::string dataPreview;
        uint32_t dataSize = 0;
    };
    std::vector<ValueInfo> values;
    std::vector<std::wstring> subKeys;
};

struct RegistryDiffEntry {
    enum class ChangeType : uint8_t { Added, Removed, Modified };
    ChangeType changeType{};
    std::wstring keyPath;
    std::wstring valueName;
    std::string oldValue;
    std::string newValue;
};

struct FileEntry {
    std::wstring path;
    std::wstring name;
    bool isDirectory = false;
    uint64_t size = 0;
    std::chrono::system_clock::time_point createdAt{};
    std::chrono::system_clock::time_point modifiedAt{};
    std::chrono::system_clock::time_point accessedAt{};
    uint32_t attributes = 0;
    std::string sha256;
    bool isSigned = false;
    bool isHidden = false;
    bool isSystem = false;
};

struct FileTimelineEntry {
    std::wstring path;
    std::chrono::system_clock::time_point timestamp;
    enum class Action : uint8_t { Created, Modified, Accessed, Renamed, Deleted };
    Action action{};
    std::string details;
};

} // namespace ShadowStrike::Products::PhantomEDR::LiveResponse
