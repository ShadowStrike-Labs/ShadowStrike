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
#include "pch.h"
#include "Products/Community/PhantomEDR/LiveResponse/RegistryInspector.hpp"

#include "PhantomCore/Utils/HashUtils.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/RegistryUtils.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

#include <algorithm>
#include <functional>
#include <unordered_map>

namespace ShadowStrike::Products::PhantomEDR::LiveResponse {

class RegistryInspectorImpl final {
public:
    std::atomic<bool> initialized{ false };
    mutable std::shared_mutex mutex;
};

namespace {

using ShadowStrike::Utils::Logger;
namespace HashUtils = ShadowStrike::Utils::HashUtils;
namespace RegistryUtils = ShadowStrike::Utils::RegistryUtils;
namespace StringUtils = ShadowStrike::Utils::StringUtils;

constexpr uint64_t kWindowsEpochOffset = 116444736000000000ULL;
constexpr uint32_t kMaxSnapshotKeys = 4096;
constexpr size_t kPreviewByteLimit = 256;

[[nodiscard]] std::chrono::system_clock::time_point FileTimeToSystemTime(const FILETIME& fileTime) noexcept {
    ULARGE_INTEGER value{};
    value.LowPart = fileTime.dwLowDateTime;
    value.HighPart = fileTime.dwHighDateTime;

    if (value.QuadPart <= kWindowsEpochOffset) {
        return {};
    }

    using HundredNanoseconds = std::chrono::duration<int64_t, std::ratio<1, 10000000>>;
    const auto unixTicks = static_cast<int64_t>(value.QuadPart - kWindowsEpochOffset);
    return std::chrono::system_clock::time_point{
        std::chrono::duration_cast<std::chrono::system_clock::duration>(HundredNanoseconds{ unixTicks }) };
}

[[nodiscard]] std::wstring ExtractKeyName(std::wstring_view fullPath) {
    const size_t separator = fullPath.find_last_of(L'\\');
    if (separator == std::wstring_view::npos) {
        return std::wstring(fullPath);
    }
    return std::wstring(fullPath.substr(separator + 1));
}

[[nodiscard]] std::wstring CombineKeyPath(std::wstring_view parent, std::wstring_view child) {
    if (parent.empty()) {
        return std::wstring(child);
    }
    if (child.empty()) {
        return std::wstring(parent);
    }

    std::wstring result(parent);
    if (!result.empty() && result.back() != L'\\') {
        result.push_back(L'\\');
    }
    result.append(child);
    return result;
}

[[nodiscard]] std::string MakeHexPreview(const std::vector<uint8_t>& bytes) {
    const size_t previewSize = std::min(bytes.size(), kPreviewByteLimit);
    std::vector<uint8_t> preview(bytes.begin(), bytes.begin() + static_cast<ptrdiff_t>(previewSize));
    std::string value = HashUtils::ToHexLower(preview);
    if (bytes.size() > previewSize) {
        value += "...";
    }
    return value;
}

[[nodiscard]] std::string JoinMultiStringPreview(const std::vector<std::wstring>& values) {
    std::wstring joined;
    for (size_t index = 0; index < values.size(); ++index) {
        if (index != 0) {
            joined += L"; ";
        }
        joined += values[index];
    }
    return StringUtils::ToNarrow(joined);
}

[[nodiscard]] std::string ReadValuePreview(
    const RegistryUtils::RegistryKey& key,
    const RegistryUtils::ValueInfo& valueInfo) {
    RegistryUtils::Error error{};

    switch (valueInfo.type) {
    case RegistryUtils::ValueType::String: {
        std::wstring value;
        return key.ReadString(valueInfo.name, value, &error) ? StringUtils::ToNarrow(value) : std::string{};
    }
    case RegistryUtils::ValueType::ExpandString: {
        std::wstring value;
        return key.ReadExpandString(valueInfo.name, value, false, &error) ? StringUtils::ToNarrow(value) : std::string{};
    }
    case RegistryUtils::ValueType::MultiString: {
        std::vector<std::wstring> values;
        return key.ReadMultiString(valueInfo.name, values, &error) ? JoinMultiStringPreview(values) : std::string{};
    }
    case RegistryUtils::ValueType::DWord: {
        DWORD value = 0;
        if (!key.ReadDWord(valueInfo.name, value, &error)) {
            return {};
        }
        return std::format("0x{:08x} ({})", value, value);
    }
    case RegistryUtils::ValueType::QWord: {
        uint64_t value = 0;
        if (!key.ReadQWord(valueInfo.name, value, &error)) {
            return {};
        }
        return std::format("0x{:016x} ({})", value, value);
    }
    case RegistryUtils::ValueType::Binary: {
        std::vector<uint8_t> data;
        return key.ReadBinary(valueInfo.name, data, &error) ? MakeHexPreview(data) : std::string{};
    }
    default:
        return std::format("<type:{} size:{}>", static_cast<uint32_t>(valueInfo.type), valueInfo.dataSize);
    }
}

[[nodiscard]] std::optional<RegistryKeySnapshot> BrowseKeyInternal(std::wstring_view fullPath) {
    HKEY rootKey = nullptr;
    std::wstring subKey;
    if (!RegistryUtils::SplitPath(fullPath, rootKey, subKey) || rootKey == nullptr) {
        Logger::Warn("RegistryInspector: invalid registry path");
        return std::nullopt;
    }

    RegistryUtils::RegistryKey key;
    RegistryUtils::Error error{};
    if (!key.Open(rootKey, subKey, {}, &error)) {
        Logger::Debug("RegistryInspector: failed to open key");
        return std::nullopt;
    }

    RegistryUtils::KeyInfo info{};
    if (!key.QueryInfo(info, &error)) {
        Logger::Warn("RegistryInspector: QueryInfo failed");
        return std::nullopt;
    }

    RegistryKeySnapshot snapshot{};
    snapshot.fullPath = std::wstring(fullPath);
    snapshot.name = ExtractKeyName(fullPath);
    snapshot.subKeyCount = info.subKeyCount;
    snapshot.valueCount = info.valueCount;
    snapshot.lastWriteTime = FileTimeToSystemTime(info.lastWriteTime);

    std::vector<std::wstring> subKeys;
    if (key.EnumKeys(subKeys, &error)) {
        snapshot.subKeys = std::move(subKeys);
        std::ranges::sort(snapshot.subKeys);
    }

    std::vector<RegistryUtils::ValueInfo> values;
    if (key.EnumValues(values, &error)) {
        snapshot.values.reserve(values.size());
        for (const auto& value : values) {
            snapshot.values.push_back(RegistryKeySnapshot::ValueInfo{
                .name = value.name,
                .type = static_cast<uint32_t>(value.type),
                .dataPreview = ReadValuePreview(key, value),
                .dataSize = value.dataSize
            });
        }

        std::ranges::sort(snapshot.values, [](const auto& left, const auto& right) {
            return left.name < right.name;
        });
    }

    return snapshot;
}

[[nodiscard]] bool MatchesPattern(std::wstring_view pattern, const RegistryInspector::SearchResult& result) {
    if (StringUtils::IContains(result.valueName, pattern)) {
        return true;
    }

    const std::wstring previewWide = StringUtils::ToWide(result.dataPreview);
    return !previewWide.empty() && StringUtils::IContains(previewWide, pattern);
}

void AddStringValueEntries(
    std::wstring_view keyPath,
    std::wstring_view type,
    std::vector<RegistryInspector::AutoRunEntry>& entries) {
    const auto snapshot = BrowseKeyInternal(keyPath);
    if (!snapshot.has_value()) {
        return;
    }

    for (const auto& value : snapshot->values) {
        if (value.dataPreview.empty()) {
            continue;
        }

        entries.push_back(RegistryInspector::AutoRunEntry{
            .location = std::wstring(keyPath),
            .name = value.name,
            .value = StringUtils::ToWide(value.dataPreview),
            .type = std::wstring(type)
        });
    }
}

void AddSelectedValueEntries(
    std::wstring_view keyPath,
    std::wstring_view type,
    std::initializer_list<std::wstring_view> valueNames,
    std::vector<RegistryInspector::AutoRunEntry>& entries) {
    const auto snapshot = BrowseKeyInternal(keyPath);
    if (!snapshot.has_value()) {
        return;
    }

    for (const auto& value : snapshot->values) {
        if (value.dataPreview.empty()) {
            continue;
        }

        const bool selected = std::ranges::any_of(valueNames, [&](const auto candidate) {
            return StringUtils::IEquals(value.name, candidate);
        });
        if (!selected) {
            continue;
        }

        entries.push_back(RegistryInspector::AutoRunEntry{
            .location = std::wstring(keyPath),
            .name = value.name,
            .value = StringUtils::ToWide(value.dataPreview),
            .type = std::wstring(type)
        });
    }
}

void AddServiceEntries(std::vector<RegistryInspector::AutoRunEntry>& entries) {
    constexpr std::wstring_view servicesKey = L"HKLM\\SYSTEM\\CurrentControlSet\\Services";
    const auto snapshot = BrowseKeyInternal(servicesKey);
    if (!snapshot.has_value()) {
        return;
    }

    for (const auto& serviceName : snapshot->subKeys) {
        const std::wstring fullServicePath = CombineKeyPath(servicesKey, serviceName);

        HKEY rootKey = nullptr;
        std::wstring subKey;
        if (!RegistryUtils::SplitPath(fullServicePath, rootKey, subKey)) {
            continue;
        }

        RegistryUtils::RegistryKey key;
        RegistryUtils::Error error{};
        if (!key.Open(rootKey, subKey, {}, &error)) {
            continue;
        }

        DWORD start = 0;
        if (!key.ReadDWord(L"Start", start, &error) || (start != 2 && start != 3)) {
            continue;
        }

        std::wstring imagePath;
        if (!key.ReadString(L"ImagePath", imagePath, &error)) {
            (void)key.ReadExpandString(L"ImagePath", imagePath, false, &error);
        }

        entries.push_back(RegistryInspector::AutoRunEntry{
            .location = fullServicePath,
            .name = serviceName,
            .value = imagePath,
            .type = L"Service"
        });
    }
}

void EnumerateTaskTree(std::wstring_view rootPath, std::vector<RegistryInspector::AutoRunEntry>& entries, const uint32_t depth = 0) {
    if (depth > 8) {
        return;
    }

    const auto snapshot = BrowseKeyInternal(rootPath);
    if (!snapshot.has_value()) {
        return;
    }

    for (const auto& taskName : snapshot->subKeys) {
        const std::wstring fullPath = CombineKeyPath(rootPath, taskName);
        entries.push_back(RegistryInspector::AutoRunEntry{
            .location = fullPath,
            .name = taskName,
            .value = fullPath,
            .type = L"ScheduledTask"
        });
        EnumerateTaskTree(fullPath, entries, depth + 1);
    }
}

} // namespace

RegistryInspector::RegistryInspector()
    : m_impl(std::make_unique<RegistryInspectorImpl>()) {
}

RegistryInspector::~RegistryInspector() = default;

RegistryInspector& RegistryInspector::Instance() {
    static RegistryInspector instance;
    return instance;
}

bool RegistryInspector::Initialize() {
    std::unique_lock lock(m_impl->mutex);
    if (m_impl->initialized.load(std::memory_order_acquire)) {
        return true;
    }

    m_impl->initialized.store(true, std::memory_order_release);
    Logger::Info("RegistryInspector: initialized");
    return true;
}

void RegistryInspector::Shutdown() {
    std::unique_lock lock(m_impl->mutex);
    m_impl->initialized.store(false, std::memory_order_release);
    Logger::Info("RegistryInspector: shutdown complete");
}

bool RegistryInspector::IsInitialized() const noexcept {
    return m_impl->initialized.load(std::memory_order_acquire);
}

std::optional<RegistryKeySnapshot> RegistryInspector::BrowseKey(std::wstring_view fullPath) {
    std::shared_lock lock(m_impl->mutex);
    if (!m_impl->initialized.load(std::memory_order_acquire)) {
        Logger::Warn("RegistryInspector: BrowseKey requested before initialization");
        return std::nullopt;
    }

    return BrowseKeyInternal(fullPath);
}

std::vector<RegistryInspector::SearchResult> RegistryInspector::SearchValues(
    std::wstring_view rootPath,
    std::wstring_view pattern,
    const uint32_t maxDepth,
    const uint32_t maxResults) {
    std::shared_lock lock(m_impl->mutex);
    if (!m_impl->initialized.load(std::memory_order_acquire) || rootPath.empty() || pattern.empty() || maxResults == 0) {
        return {};
    }

    const uint32_t effectiveMaxResults = std::min<uint32_t>(maxResults, 1000U);
    std::vector<SearchResult> results;
    results.reserve(effectiveMaxResults);

    std::function<void(std::wstring_view, uint32_t)> search = [&](const std::wstring_view keyPath, const uint32_t depth) {
        if (depth > maxDepth || results.size() >= effectiveMaxResults) {
            return;
        }

        const auto snapshot = BrowseKeyInternal(keyPath);
        if (!snapshot.has_value()) {
            return;
        }

        for (const auto& value : snapshot->values) {
            SearchResult result{
                .keyPath = snapshot->fullPath,
                .valueName = value.name,
                .dataPreview = value.dataPreview,
                .valueType = value.type
            };

            if (MatchesPattern(pattern, result)) {
                results.push_back(std::move(result));
                if (results.size() >= effectiveMaxResults) {
                    return;
                }
            }
        }

        for (const auto& subKey : snapshot->subKeys) {
            search(CombineKeyPath(snapshot->fullPath, subKey), depth + 1);
            if (results.size() >= effectiveMaxResults) {
                return;
            }
        }
    };

    search(rootPath, 0);
    Logger::Info("RegistryInspector: search returned {} result(s)", results.size());
    return results;
}

std::vector<RegistryInspector::AutoRunEntry> RegistryInspector::GetAutoRunEntries() {
    std::shared_lock lock(m_impl->mutex);
    if (!m_impl->initialized.load(std::memory_order_acquire)) {
        Logger::Warn("RegistryInspector: GetAutoRunEntries requested before initialization");
        return {};
    }

    std::vector<AutoRunEntry> entries;
    entries.reserve(256);

    AddStringValueEntries(L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", L"Run", entries);
    AddStringValueEntries(L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"RunOnce", entries);
    AddStringValueEntries(L"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", L"Run", entries);
    AddSelectedValueEntries(L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        L"Winlogon", { L"Shell", L"Userinit" }, entries);
    AddStringValueEntries(L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", L"ShellFolder", entries);
    AddServiceEntries(entries);
    EnumerateTaskTree(L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree", entries);

    std::ranges::sort(entries, [](const auto& left, const auto& right) {
        if (left.location != right.location) {
            return left.location < right.location;
        }
        return left.name < right.name;
    });

    Logger::Info("RegistryInspector: enumerated {} auto-run entries", entries.size());
    return entries;
}

std::vector<RegistryKeySnapshot> RegistryInspector::TakeSnapshot(
    std::wstring_view rootPath,
    const uint32_t maxDepth) {
    std::shared_lock lock(m_impl->mutex);
    if (!m_impl->initialized.load(std::memory_order_acquire) || rootPath.empty()) {
        return {};
    }

    std::vector<RegistryKeySnapshot> snapshots;
    snapshots.reserve(std::min<uint32_t>(kMaxSnapshotKeys, 512U));

    std::function<void(std::wstring_view, uint32_t)> capture = [&](const std::wstring_view keyPath, const uint32_t depth) {
        if (depth > maxDepth || snapshots.size() >= kMaxSnapshotKeys) {
            return;
        }

        const auto snapshot = BrowseKeyInternal(keyPath);
        if (!snapshot.has_value()) {
            return;
        }

        snapshots.push_back(*snapshot);
        for (const auto& subKey : snapshot->subKeys) {
            capture(CombineKeyPath(snapshot->fullPath, subKey), depth + 1);
            if (snapshots.size() >= kMaxSnapshotKeys) {
                return;
            }
        }
    };

    capture(rootPath, 0);

    std::ranges::sort(snapshots, [](const auto& left, const auto& right) {
        return left.fullPath < right.fullPath;
    });

    Logger::Debug("RegistryInspector: captured {} registry key snapshots", snapshots.size());
    return snapshots;
}

std::vector<RegistryDiffEntry> RegistryInspector::CompareSnapshots(
    const std::vector<RegistryKeySnapshot>& before,
    const std::vector<RegistryKeySnapshot>& after) {
    std::vector<RegistryDiffEntry> diffs;

    std::unordered_map<std::wstring, const RegistryKeySnapshot*> beforeByPath;
    std::unordered_map<std::wstring, const RegistryKeySnapshot*> afterByPath;
    beforeByPath.reserve(before.size());
    afterByPath.reserve(after.size());

    for (const auto& snapshot : before) {
        beforeByPath.emplace(snapshot.fullPath, &snapshot);
    }
    for (const auto& snapshot : after) {
        afterByPath.emplace(snapshot.fullPath, &snapshot);
    }

    for (const auto& [path, afterSnapshot] : afterByPath) {
        if (!beforeByPath.contains(path)) {
            diffs.push_back(RegistryDiffEntry{
                .changeType = RegistryDiffEntry::ChangeType::Added,
                .keyPath = path,
                .valueName = {},
                .oldValue = {},
                .newValue = "<key added>"
            });
            continue;
        }

        std::unordered_map<std::wstring, const RegistryKeySnapshot::ValueInfo*> beforeValues;
        std::unordered_map<std::wstring, const RegistryKeySnapshot::ValueInfo*> afterValues;
        for (const auto& value : beforeByPath[path]->values) {
            beforeValues.emplace(value.name, &value);
        }
        for (const auto& value : afterSnapshot->values) {
            afterValues.emplace(value.name, &value);
        }

        for (const auto& [valueName, afterValue] : afterValues) {
            if (!beforeValues.contains(valueName)) {
                diffs.push_back(RegistryDiffEntry{
                    .changeType = RegistryDiffEntry::ChangeType::Added,
                    .keyPath = path,
                    .valueName = valueName,
                    .oldValue = {},
                    .newValue = afterValue->dataPreview
                });
                continue;
            }

            const auto* beforeValue = beforeValues[valueName];
            if (beforeValue->type != afterValue->type
                || beforeValue->dataSize != afterValue->dataSize
                || beforeValue->dataPreview != afterValue->dataPreview) {
                diffs.push_back(RegistryDiffEntry{
                    .changeType = RegistryDiffEntry::ChangeType::Modified,
                    .keyPath = path,
                    .valueName = valueName,
                    .oldValue = beforeValue->dataPreview,
                    .newValue = afterValue->dataPreview
                });
            }
        }

        for (const auto& [valueName, beforeValue] : beforeValues) {
            if (!afterValues.contains(valueName)) {
                diffs.push_back(RegistryDiffEntry{
                    .changeType = RegistryDiffEntry::ChangeType::Removed,
                    .keyPath = path,
                    .valueName = valueName,
                    .oldValue = beforeValue->dataPreview,
                    .newValue = {}
                });
            }
        }
    }

    for (const auto& [path, beforeSnapshot] : beforeByPath) {
        if (!afterByPath.contains(path)) {
            diffs.push_back(RegistryDiffEntry{
                .changeType = RegistryDiffEntry::ChangeType::Removed,
                .keyPath = path,
                .valueName = {},
                .oldValue = "<key removed>",
                .newValue = {}
            });
        }
    }

    std::ranges::sort(diffs, [](const auto& left, const auto& right) {
        if (left.keyPath != right.keyPath) {
            return left.keyPath < right.keyPath;
        }
        if (left.valueName != right.valueName) {
            return left.valueName < right.valueName;
        }
        return static_cast<uint8_t>(left.changeType) < static_cast<uint8_t>(right.changeType);
    });

    Logger::Debug("RegistryInspector: computed {} registry differences", diffs.size());
    return diffs;
}

} // namespace ShadowStrike::Products::PhantomEDR::LiveResponse
