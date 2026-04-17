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
#include "Products/Community/PhantomEDR/LiveResponse/ProcessInspector.hpp"

#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/ProcessUtils.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

#include <algorithm>
#include <array>
#include <cwctype>
#include <functional>
#include <limits>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace ShadowStrike::Products::PhantomEDR::LiveResponse {

class ProcessInspectorImpl final {
public:
    std::atomic<bool> initialized{ false };
    mutable std::shared_mutex mutex;
};

namespace {

using ShadowStrike::Utils::Logger;
namespace ProcessUtils = ShadowStrike::Utils::ProcessUtils;
namespace StringUtils = ShadowStrike::Utils::StringUtils;

constexpr uint64_t kWindowsEpochOffset = 116444736000000000ULL;

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

[[nodiscard]] std::wstring ToLower(std::wstring_view value) {
    return StringUtils::ToLowerCopy(value);
}

[[nodiscard]] bool IsLikelySystemProcess(const ProcessUtils::ProcessInfo& process) {
    if (process.basic.isSystemProcess || process.security.isRunningAsSystem) {
        return true;
    }

    const std::wstring lowerPath = ToLower(process.basic.executablePath);
    return lowerPath.starts_with(L"c:\\windows\\system32\\")
        || lowerPath.starts_with(L"c:\\windows\\syswow64\\")
        || lowerPath == L"system";
}

[[nodiscard]] bool IsUserWritableExecutionPath(std::wstring_view path) {
    const std::wstring lowerPath = ToLower(path);
    static constexpr std::array<std::wstring_view, 9> kSuspiciousRoots{
        L"\\users\\",
        L"\\programdata\\",
        L"\\windows\\temp\\",
        L"\\temp\\",
        L"\\appdata\\local\\temp\\",
        L"\\appdata\\roaming\\",
        L"\\downloads\\",
        L"\\desktop\\",
        L"\\public\\"
    };

    return std::ranges::any_of(kSuspiciousRoots, [&](const auto candidate) {
        return lowerPath.find(candidate) != std::wstring::npos;
    });
}

[[nodiscard]] std::optional<uint16_t> TryParsePort(std::wstring_view value) {
    if (value.empty()) {
        return std::nullopt;
    }

    size_t portStart = value.find_last_of(L':');
    if (portStart == std::wstring_view::npos) {
        portStart = value.find_last_of(L" /");
    }
    if (portStart == std::wstring_view::npos || portStart + 1 >= value.size()) {
        return std::nullopt;
    }

    while (portStart < value.size() && !std::iswdigit(value[portStart])) {
        ++portStart;
    }

    if (portStart >= value.size()) {
        return std::nullopt;
    }

    uint32_t port = 0;
    for (size_t index = portStart; index < value.size() && std::iswdigit(value[index]); ++index) {
        port = (port * 10U) + static_cast<uint32_t>(value[index] - L'0');
        if (port > std::numeric_limits<uint16_t>::max()) {
            return std::nullopt;
        }
    }

    return static_cast<uint16_t>(port);
}

[[nodiscard]] bool IsStandardPort(const uint16_t port) {
    static const std::unordered_set<uint16_t> kStandardPorts{
        20, 21, 22, 25, 53, 67, 68, 69, 80, 88, 110, 123, 135, 137, 138, 139, 143,
        161, 162, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 1434, 1521, 3306,
        3389, 5432, 5900, 5985, 5986, 8080, 8443
    };
    return kStandardPorts.contains(port);
}

[[nodiscard]] void ParseEndpoint(std::wstring_view endpoint, std::string& address, uint16_t& port) {
    const std::wstring trimmed = StringUtils::TrimCopy(endpoint);
    endpoint = trimmed;
    port = 0;

    if (endpoint.empty()) {
        address.clear();
        return;
    }

    const size_t colon = endpoint.find_last_of(L':');
    if (colon != std::wstring_view::npos && colon + 1 < endpoint.size()) {
        address = StringUtils::ToNarrow(endpoint.substr(0, colon));
        const auto parsedPort = TryParsePort(endpoint.substr(colon + 1));
        if (parsedPort.has_value()) {
            port = *parsedPort;
            return;
        }
    }

    address = StringUtils::ToNarrow(endpoint);
}

[[nodiscard]] ProcessSnapshot::ConnectionInfo ParseActiveConnection(std::wstring_view entry) {
    ProcessSnapshot::ConnectionInfo connection{};

    std::vector<std::wstring> tokens;
    std::wstring current;
    for (const wchar_t ch : entry) {
        if (std::iswspace(ch)) {
            if (!current.empty()) {
                tokens.push_back(std::move(current));
                current.clear();
            }
            continue;
        }
        current.push_back(ch);
    }
    if (!current.empty()) {
        tokens.push_back(std::move(current));
    }

    if (tokens.size() >= 4 && std::all_of(tokens[0].begin(), tokens[0].end(), [](const wchar_t ch) { return std::iswalpha(ch) != 0; })) {
        connection.protocol = StringUtils::ToNarrow(tokens[0]);
        ParseEndpoint(tokens[1], connection.localAddress, connection.localPort);
        ParseEndpoint(tokens[2], connection.remoteAddress, connection.remotePort);
        connection.state = StringUtils::ToNarrow(tokens[3]);
    } else if (tokens.size() >= 3) {
        ParseEndpoint(tokens[0], connection.localAddress, connection.localPort);
        ParseEndpoint(tokens[1], connection.remoteAddress, connection.remotePort);
        connection.state = StringUtils::ToNarrow(tokens[2]);
    } else {
        connection.localAddress = StringUtils::ToNarrow(entry);
    }

    if (connection.protocol.empty()) {
        connection.protocol = "TCP";
    }

    return connection;
}

[[nodiscard]] ProcessSnapshot::ConnectionInfo ParseOpenPort(std::wstring_view entry) {
    ProcessSnapshot::ConnectionInfo connection{};
    connection.state = "LISTENING";
    connection.remoteAddress = "*";
    connection.protocol = "TCP";

    const std::wstring lower = ToLower(entry);
    if (lower.find(L"udp") != std::wstring::npos) {
        connection.protocol = "UDP";
    }

    if (const auto port = TryParsePort(entry); port.has_value()) {
        connection.localPort = *port;
    }

    connection.localAddress = StringUtils::ToNarrow(entry);
    return connection;
}

[[nodiscard]] ProcessSnapshot MakeProcessSnapshotFromInfo(const ProcessUtils::ProcessInfo& info) {
    ProcessSnapshot snapshot{};
    snapshot.pid = info.basic.pid;
    snapshot.parentPid = info.basic.parentPid;
    snapshot.name = info.basic.name;
    snapshot.path = info.basic.executablePath;
    snapshot.commandLine = info.basic.commandLine;
    snapshot.userName = info.security.userName;
    snapshot.integrityLevel = info.security.integrityLevel;
    snapshot.isElevated = info.security.isElevated;
    snapshot.workingSetSize = static_cast<uint64_t>(info.memory.workingSetSize);
    snapshot.privateBytes = static_cast<uint64_t>(info.memory.privateMemorySize);
    snapshot.startTime = FileTimeToSystemTime(info.basic.creationTime);

    snapshot.modules.reserve(info.modules.size());
    for (const auto& module : info.modules) {
        snapshot.modules.push_back(ProcessSnapshot::ModuleInfo{
            .name = module.name,
            .path = module.path,
            .baseAddress = reinterpret_cast<uintptr_t>(module.baseAddress),
            .size = static_cast<size_t>(module.size),
            .isSigned = module.isSigned
        });
    }

    snapshot.threads.reserve(info.threads.size());
    for (const auto& thread : info.threads) {
        snapshot.threads.push_back(ProcessSnapshot::ThreadInfo{
            .tid = thread.tid,
            .basePriority = thread.basePriority,
            .isSuspended = thread.isSuspended,
            .startAddress = reinterpret_cast<uintptr_t>(thread.startAddress)
        });
    }

    snapshot.handles.reserve(info.handles.size());
    for (const auto& handle : info.handles) {
        snapshot.handles.push_back(ProcessSnapshot::HandleInfo{
            .typeName = handle.typeName,
            .objectName = handle.name,
            .handleValue = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(handle.handle) & 0xFFFFFFFFu)
        });
    }

    snapshot.connections.reserve(info.network.activeConnections.size() + info.network.openPorts.size());
    for (const auto& connection : info.network.activeConnections) {
        snapshot.connections.push_back(ParseActiveConnection(connection));
    }
    for (const auto& openPort : info.network.openPorts) {
        snapshot.connections.push_back(ParseOpenPort(openPort));
    }

    return snapshot;
}

[[nodiscard]] bool AreSnapshotsEquivalent(const ProcessSnapshot& left, const ProcessSnapshot& right) {
    auto moduleKey = [](const ProcessSnapshot::ModuleInfo& module) {
        return std::tuple{ module.name, module.path, module.baseAddress, module.size, module.isSigned };
    };
    auto threadKey = [](const ProcessSnapshot::ThreadInfo& thread) {
        return std::tuple{ thread.tid, thread.basePriority, thread.isSuspended, thread.startAddress };
    };
    auto handleKey = [](const ProcessSnapshot::HandleInfo& handle) {
        return std::tuple{ handle.typeName, handle.objectName, handle.handleValue };
    };
    auto connectionKey = [](const ProcessSnapshot::ConnectionInfo& connection) {
        return std::tuple{ connection.localAddress, connection.localPort, connection.remoteAddress,
            connection.remotePort, connection.protocol, connection.state };
    };

    return left.parentPid == right.parentPid
        && left.name == right.name
        && left.path == right.path
        && left.commandLine == right.commandLine
        && left.userName == right.userName
        && left.integrityLevel == right.integrityLevel
        && left.isElevated == right.isElevated
        && left.startTime == right.startTime
        && left.workingSetSize == right.workingSetSize
        && left.privateBytes == right.privateBytes
        && std::ranges::equal(left.modules, right.modules, {}, moduleKey, moduleKey)
        && std::ranges::equal(left.threads, right.threads, {}, threadKey, threadKey)
        && std::ranges::equal(left.handles, right.handles, {}, handleKey, handleKey)
        && std::ranges::equal(left.connections, right.connections, {}, connectionKey, connectionKey);
}

} // namespace

ProcessInspector::ProcessInspector()
    : m_impl(std::make_unique<ProcessInspectorImpl>()) {
}

ProcessInspector::~ProcessInspector() = default;

ProcessInspector& ProcessInspector::Instance() {
    static ProcessInspector instance;
    return instance;
}

bool ProcessInspector::Initialize() {
    std::unique_lock lock(m_impl->mutex);
    if (m_impl->initialized.load(std::memory_order_acquire)) {
        return true;
    }

    m_impl->initialized.store(true, std::memory_order_release);
    Logger::Info("ProcessInspector: initialized");
    return true;
}

void ProcessInspector::Shutdown() {
    std::unique_lock lock(m_impl->mutex);
    m_impl->initialized.store(false, std::memory_order_release);
    Logger::Info("ProcessInspector: shutdown complete");
}

bool ProcessInspector::IsInitialized() const noexcept {
    return m_impl->initialized.load(std::memory_order_acquire);
}

std::vector<ProcessInspector::ProcessTreeNode> ProcessInspector::GetProcessTree() {
    std::shared_lock lock(m_impl->mutex);
    if (!m_impl->initialized.load(std::memory_order_acquire)) {
        Logger::Warn("ProcessInspector: GetProcessTree requested before initialization");
        return {};
    }

    std::vector<ProcessUtils::ProcessInfo> processInfos;
    ProcessUtils::Error error{};
    if (!ProcessUtils::CreateProcessSnapshot(processInfos, &error)) {
        Logger::Error("ProcessInspector: CreateProcessSnapshot failed for tree build");
        return {};
    }

    std::unordered_map<uint32_t, ProcessTreeNode> nodes;
    nodes.reserve(processInfos.size());

    for (const auto& info : processInfos) {
        nodes.emplace(info.basic.pid, ProcessTreeNode{
            .process = MakeProcessSnapshotFromInfo(info),
            .depth = 0,
            .childPids = {}
        });
    }

    for (const auto& info : processInfos) {
        const uint32_t pid = info.basic.pid;
        const uint32_t parentPid = info.basic.parentPid;
        if (parentPid != 0 && parentPid != pid) {
            if (auto parentIt = nodes.find(parentPid); parentIt != nodes.end()) {
                parentIt->second.childPids.push_back(pid);
            }
        }
    }

    for (auto& [_, node] : nodes) {
        std::ranges::sort(node.childPids);
    }

    std::vector<uint32_t> roots;
    roots.reserve(nodes.size());
    for (const auto& [pid, node] : nodes) {
        if (node.process.parentPid == 0 || node.process.parentPid == pid || !nodes.contains(node.process.parentPid)) {
            roots.push_back(pid);
        }
    }
    std::ranges::sort(roots);

    std::vector<ProcessTreeNode> ordered;
    ordered.reserve(nodes.size());
    std::unordered_set<uint32_t> visited;
    visited.reserve(nodes.size());

    const std::function<void(uint32_t, uint32_t)> walk = [&](const uint32_t pid, const uint32_t depth) {
        auto it = nodes.find(pid);
        if (it == nodes.end() || !visited.insert(pid).second) {
            return;
        }

        auto node = it->second;
        node.depth = depth;
        ordered.push_back(std::move(node));

        for (const uint32_t childPid : it->second.childPids) {
            walk(childPid, depth + 1);
        }
    };

    for (const uint32_t rootPid : roots) {
        walk(rootPid, 0);
    }

    for (const auto& [pid, _] : nodes) {
        if (!visited.contains(pid)) {
            walk(pid, 0);
        }
    }

    Logger::Debug("ProcessInspector: built process tree with {} nodes", ordered.size());
    return ordered;
}

std::optional<ProcessSnapshot> ProcessInspector::InspectProcess(const uint32_t pid) {
    std::shared_lock lock(m_impl->mutex);
    if (!m_impl->initialized.load(std::memory_order_acquire)) {
        Logger::Warn("ProcessInspector: InspectProcess requested before initialization");
        return std::nullopt;
    }

    ProcessUtils::ProcessInfo info{};
    ProcessUtils::Error error{};
    if (!ProcessUtils::GetProcessInfo(pid, info, &error)) {
        Logger::Warn("ProcessInspector: GetProcessInfo failed for pid {}", pid);
        return std::nullopt;
    }

    std::vector<ProcessUtils::ProcessModuleInfo> modules;
    if (ProcessUtils::EnumerateProcessModules(pid, modules, &error)) {
        info.modules = std::move(modules);
    } else {
        Logger::Debug("ProcessInspector: module enumeration failed for pid {}", pid);
    }

    std::vector<ProcessUtils::ProcessThreadInfo> threads;
    if (ProcessUtils::EnumerateProcessThreads(pid, threads, &error)) {
        info.threads = std::move(threads);
    } else {
        Logger::Debug("ProcessInspector: thread enumeration failed for pid {}", pid);
    }

    auto snapshot = MakeProcessSnapshotFromInfo(info);
    Logger::Debug("ProcessInspector: inspected pid {}", pid);
    return snapshot;
}

std::vector<ProcessInspector::SuspiciousProcessInfo> ProcessInspector::GetSuspiciousProcesses() {
    std::shared_lock lock(m_impl->mutex);
    if (!m_impl->initialized.load(std::memory_order_acquire)) {
        Logger::Warn("ProcessInspector: GetSuspiciousProcesses requested before initialization");
        return {};
    }

    std::vector<ProcessUtils::ProcessInfo> processInfos;
    ProcessUtils::Error error{};
    if (!ProcessUtils::CreateProcessSnapshot(processInfos, &error)) {
        Logger::Error("ProcessInspector: CreateProcessSnapshot failed for suspicious scan");
        return {};
    }

    std::unordered_map<uint32_t, const ProcessUtils::ProcessInfo*> byPid;
    byPid.reserve(processInfos.size());
    for (const auto& process : processInfos) {
        byPid.emplace(process.basic.pid, &process);
    }

    std::vector<SuspiciousProcessInfo> suspiciousProcesses;
    suspiciousProcesses.reserve(processInfos.size() / 8U + 1U);

    for (const auto& process : processInfos) {
        SuspiciousProcessInfo suspicious{};
        suspicious.process = MakeProcessSnapshotFromInfo(process);

        if (IsLikelySystemProcess(process)) {
            const bool unsignedModulePresent = std::ranges::any_of(process.modules, [](const auto& module) {
                return !module.isSigned;
            });
            if (unsignedModulePresent) {
                suspicious.reasons.emplace_back("unsigned module loaded by system process");
                suspicious.riskScore += 35;
            }
        }

        if (IsUserWritableExecutionPath(process.basic.executablePath)) {
            suspicious.reasons.emplace_back("process executing from user-writable location");
            suspicious.riskScore += 30;
        }

        if (process.security.hasDebugPrivilege || process.security.hasSeDebugPrivilege) {
            suspicious.reasons.emplace_back("debug privilege enabled");
            suspicious.riskScore += 25;
        }

        const bool unusualPort = std::ranges::any_of(suspicious.process.connections, [](const auto& connection) {
            return (connection.localPort != 0 && !IsStandardPort(connection.localPort))
                || (connection.remotePort != 0 && !IsStandardPort(connection.remotePort));
        });
        if (unusualPort) {
            suspicious.reasons.emplace_back("network activity on non-standard port");
            suspicious.riskScore += 20;
        }

        const auto parentIt = byPid.find(process.basic.parentPid);
        if (parentIt != byPid.end()) {
            const std::wstring parentName = ToLower(parentIt->second->basic.name);
            const bool scriptedParent = parentName == L"cmd.exe" || parentName == L"powershell.exe" || parentName == L"pwsh.exe";
            if (scriptedParent && !suspicious.process.connections.empty()) {
                suspicious.reasons.emplace_back("network-capable child spawned by shell");
                suspicious.riskScore += 20;
            }
        }

        if (!suspicious.reasons.empty()) {
            suspicious.riskScore = std::min<uint32_t>(suspicious.riskScore, 100U);
            suspiciousProcesses.push_back(std::move(suspicious));
        }
    }

    std::ranges::sort(suspiciousProcesses, [](const auto& left, const auto& right) {
        if (left.riskScore != right.riskScore) {
            return left.riskScore > right.riskScore;
        }
        return left.process.pid < right.process.pid;
    });

    Logger::Info("ProcessInspector: identified {} suspicious processes", suspiciousProcesses.size());
    return suspiciousProcesses;
}

std::vector<ProcessSnapshot> ProcessInspector::TakeSnapshot() {
    std::shared_lock lock(m_impl->mutex);
    if (!m_impl->initialized.load(std::memory_order_acquire)) {
        Logger::Warn("ProcessInspector: TakeSnapshot requested before initialization");
        return {};
    }

    std::vector<ProcessUtils::ProcessInfo> processInfos;
    ProcessUtils::Error error{};
    if (!ProcessUtils::CreateProcessSnapshot(processInfos, &error)) {
        Logger::Error("ProcessInspector: CreateProcessSnapshot failed");
        return {};
    }

    std::vector<ProcessSnapshot> snapshots;
    snapshots.reserve(processInfos.size());
    for (const auto& process : processInfos) {
        snapshots.push_back(MakeProcessSnapshotFromInfo(process));
    }

    std::ranges::sort(snapshots, [](const auto& left, const auto& right) {
        return left.pid < right.pid;
    });

    Logger::Debug("ProcessInspector: captured snapshot of {} processes", snapshots.size());
    return snapshots;
}

ProcessInspector::ProcessDiff ProcessInspector::CompareSnapshots(
    const std::vector<ProcessSnapshot>& before,
    const std::vector<ProcessSnapshot>& after) {
    ProcessDiff diff{};

    std::unordered_map<uint32_t, const ProcessSnapshot*> beforeByPid;
    std::unordered_map<uint32_t, const ProcessSnapshot*> afterByPid;
    beforeByPid.reserve(before.size());
    afterByPid.reserve(after.size());

    for (const auto& process : before) {
        beforeByPid.emplace(process.pid, &process);
    }
    for (const auto& process : after) {
        afterByPid.emplace(process.pid, &process);
    }

    for (const auto& [pid, process] : afterByPid) {
        if (!beforeByPid.contains(pid)) {
            diff.newProcesses.push_back(pid);
            continue;
        }

        if (!AreSnapshotsEquivalent(*beforeByPid[pid], *process)) {
            diff.modifiedProcesses.push_back(pid);
        }
    }

    for (const auto& [pid, _] : beforeByPid) {
        if (!afterByPid.contains(pid)) {
            diff.terminatedProcesses.push_back(pid);
        }
    }

    std::ranges::sort(diff.newProcesses);
    std::ranges::sort(diff.terminatedProcesses);
    std::ranges::sort(diff.modifiedProcesses);

    Logger::Debug("ProcessInspector: diff new={} terminated={} modified={}",
        diff.newProcesses.size(), diff.terminatedProcesses.size(), diff.modifiedProcesses.size());
    return diff;
}

} // namespace ShadowStrike::Products::PhantomEDR::LiveResponse
