#include "ShadowStrike/Fuzzer/Core/WorkerBackendRuntime.hpp"

#include "ShadowStrike/Fuzzer/Core/CampaignPlanner.hpp"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string_view>
#include <vector>

namespace ShadowStrike::Fuzzer {

namespace {

[[nodiscard]] std::string EscapeJson(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size() + 8);

    for (const char ch : value) {
        switch (ch) {
        case '\\': escaped += "\\\\"; break;
        case '"': escaped += "\\\""; break;
        case '\b': escaped += "\\b"; break;
        case '\f': escaped += "\\f"; break;
        case '\n': escaped += "\\n"; break;
        case '\r': escaped += "\\r"; break;
        case '\t': escaped += "\\t"; break;
        default:
            escaped.push_back(ch);
            break;
        }
    }

    return escaped;
}

[[nodiscard]] bool WriteTextFile(const std::filesystem::path& path, const std::string& text) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) {
        return false;
    }

    stream.write(text.data(), static_cast<std::streamsize>(text.size()));
    return stream.good();
}

[[nodiscard]] std::wstring ToWide(std::string_view value) {
    return std::wstring(value.begin(), value.end());
}

class ScopedHandle final {
public:
    ScopedHandle() = default;
    explicit ScopedHandle(const HANDLE handle) noexcept
        : handle_(handle) {}

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    ScopedHandle(ScopedHandle&& other) noexcept
        : handle_(other.release()) {}

    ScopedHandle& operator=(ScopedHandle&& other) noexcept {
        if (this != &other) {
            reset(other.release());
        }

        return *this;
    }

    ~ScopedHandle() {
        reset();
    }

    [[nodiscard]] HANDLE get() const noexcept {
        return handle_;
    }

    [[nodiscard]] bool valid() const noexcept {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

    [[nodiscard]] HANDLE release() noexcept {
        const HANDLE released = handle_;
        handle_ = INVALID_HANDLE_VALUE;
        return released;
    }

    void reset(const HANDLE handle = INVALID_HANDLE_VALUE) noexcept {
        if (valid()) {
            ::CloseHandle(handle_);
        }
        handle_ = handle;
    }

private:
    HANDLE handle_{ INVALID_HANDLE_VALUE };
};

[[nodiscard]] std::string BuildWin32ErrorMessage(std::string_view prefix, const DWORD errorCode) {
    std::ostringstream stream;
    stream << prefix << " (Win32=" << errorCode << ").";
    return stream.str();
}

[[nodiscard]] std::wstring EscapeCommandLineArgument(const std::wstring& value) {
    std::wstring escaped;
    escaped.reserve((value.size() * 2) + 2);
    escaped.push_back(L'"');

    std::size_t trailingBackslashes = 0;
    for (const wchar_t ch : value) {
        if (ch == L'\\') {
            ++trailingBackslashes;
            continue;
        }

        if (ch == L'"') {
            escaped.append(trailingBackslashes * 2 + 1, L'\\');
            escaped.push_back(ch);
            trailingBackslashes = 0;
            continue;
        }

        if (trailingBackslashes != 0) {
            escaped.append(trailingBackslashes, L'\\');
            trailingBackslashes = 0;
        }

        escaped.push_back(ch);
    }

    if (trailingBackslashes != 0) {
        escaped.append(trailingBackslashes * 2, L'\\');
    }

    escaped.push_back(L'"');
    return escaped;
}

[[nodiscard]] std::wstring BuildWorkerCommandLine(
    const std::wstring& executablePath,
    const std::wstring& commandName,
    const std::filesystem::path& workspaceRoot,
    std::string_view planId)
{
    return EscapeCommandLineArgument(executablePath) + L' ' +
        commandName + L' ' +
        EscapeCommandLineArgument(workspaceRoot.wstring()) + L' ' +
        EscapeCommandLineArgument(ToWide(planId));
}

[[nodiscard]] std::filesystem::path GetResultPath(std::string_view planId) {
    return std::filesystem::path("state\\worker-results") / (std::string(planId) + ".json");
}

[[nodiscard]] std::filesystem::path GetLogPath(std::string_view planId) {
    return std::filesystem::path("state\\worker-logs") / (std::string(planId) + ".log");
}

[[nodiscard]] std::filesystem::path GetExecutionManifestPath(std::string_view planId) {
    return std::filesystem::path("state\\executions") / (std::string(planId) + ".json");
}

[[nodiscard]] bool ReadTextFile(const std::filesystem::path& path, std::string& text) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        return false;
    }

    std::ostringstream buffer;
    buffer << stream.rdbuf();
    if (!stream.good() && !stream.eof()) {
        return false;
    }

    text = buffer.str();
    return true;
}

[[nodiscard]] bool TryExtractJsonStringField(
    std::string_view document,
    std::string_view fieldName,
    std::string& value)
{
    const std::string marker = "\"" + std::string(fieldName) + "\"";
    const std::size_t keyOffset = document.find(marker);
    if (keyOffset == std::string_view::npos) {
        return false;
    }

    const std::size_t colonOffset = document.find(':', keyOffset + marker.size());
    if (colonOffset == std::string_view::npos) {
        return false;
    }

    const std::size_t quoteOffset = document.find('"', colonOffset + 1);
    if (quoteOffset == std::string_view::npos) {
        return false;
    }

    const std::size_t valueOffset = quoteOffset + 1;
    const std::size_t valueEndOffset = document.find('"', valueOffset);
    if (valueEndOffset == std::string_view::npos) {
        return false;
    }

    value.assign(document.substr(valueOffset, valueEndOffset - valueOffset));
    return true;
}

[[nodiscard]] std::vector<std::string> CollectRequiredInputs(const CampaignExecutionPlan& plan) {
    std::vector<std::string> inputs;

    for (const auto& seedSource : plan.seedSources) {
        if (std::find(inputs.begin(), inputs.end(), seedSource.relativePath) == inputs.end()) {
            inputs.push_back(seedSource.relativePath);
        }
    }

    for (const auto& step : plan.steps) {
        if (std::find(inputs.begin(), inputs.end(), step.input.relativePath) == inputs.end()) {
            inputs.push_back(step.input.relativePath);
        }
    }

    return inputs;
}

[[nodiscard]] std::uint64_t ComputeTotalInputBytes(
    const std::filesystem::path& workspaceRoot,
    const std::vector<std::string>& inputs)
{
    std::uint64_t totalBytes = 0;
    for (const auto& input : inputs) {
        std::error_code ec;
        const auto size = std::filesystem::file_size(workspaceRoot / input, ec);
        if (!ec) {
            totalBytes += size;
        }
    }

    return totalBytes;
}

[[nodiscard]] std::string BuildWorkerResultJson(
    const WorkerCommandKind kind,
    const CampaignExecutionPlan& plan,
    const HarnessAdapterDescriptor& adapter,
    const std::vector<std::string>& inputs,
    const std::uint64_t totalInputBytes,
    const std::uint64_t durationMs)
{
    std::ostringstream stream;
    stream << "{\n"
           << "  \"planId\": \"" << EscapeJson(plan.id) << "\",\n"
           << "  \"targetId\": \"" << EscapeJson(plan.targetId) << "\",\n"
           << "  \"adapterId\": \"" << EscapeJson(adapter.id) << "\",\n"
           << "  \"workerImage\": \"" << EscapeJson(adapter.workerImage) << "\",\n"
           << "  \"workerKind\": \"" << ToString(kind) << "\",\n"
           << "  \"executionManifestRelativePath\": \"" << EscapeJson(GetExecutionManifestPath(plan.id).string()) << "\",\n"
           << "  \"status\": \"completed\",\n"
           << "  \"statusReason\": \"Worker executed launch contract successfully.\",\n"
           << "  \"snapshotProfile\": \"" << EscapeJson(plan.snapshotProfile) << "\",\n"
           << "  \"requiredInputCount\": " << inputs.size() << ",\n"
           << "  \"totalInputBytes\": " << totalInputBytes << ",\n"
           << "  \"kernelStepCount\": " << plan.steps.size() << ",\n"
           << "  \"userModeSeedSourceCount\": " << plan.seedSources.size() << ",\n"
           << "  \"durationMs\": " << durationMs << "\n"
           << "}\n";
    return stream.str();
}

[[nodiscard]] std::wstring GetCurrentExecutablePath() {
    std::wstring buffer(MAX_PATH, L'\0');
    DWORD length = 0;

    for (;;) {
        length = ::GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0) {
            return {};
        }

        if (length < buffer.size() - 1) {
            buffer.resize(length);
            return buffer;
        }

        buffer.resize(buffer.size() * 2);
    }
}

[[nodiscard]] WorkerCommandKind ResolveWorkerKind(const HarnessAdapterKind kind) {
    switch (kind) {
    case HarnessAdapterKind::KernelVmCampaign:
        return WorkerCommandKind::KernelVm;
    case HarnessAdapterKind::BrokerSession:
        return WorkerCommandKind::Broker;
    case HarnessAdapterKind::ParserFrontDoor:
    case HarnessAdapterKind::DifferentialParser:
        return WorkerCommandKind::Parser;
    }

    return WorkerCommandKind::Parser;
}

[[nodiscard]] DWORD GetWorkerTimeoutMs(const HarnessAdapterKind kind) {
    switch (kind) {
    case HarnessAdapterKind::KernelVmCampaign:
        return 300000;
    case HarnessAdapterKind::BrokerSession:
        return 120000;
    case HarnessAdapterKind::ParserFrontDoor:
    case HarnessAdapterKind::DifferentialParser:
        return 90000;
    }

    return 120000;
}

[[nodiscard]] bool RemoveStaleArtifact(
    const std::filesystem::path& path,
    std::string& errorMessage)
{
    std::error_code ec;
    const bool exists = std::filesystem::exists(path, ec);
    if (ec) {
        errorMessage = "Failed to inspect stale artifact path: " + path.string();
        return false;
    }

    if (exists) {
        std::filesystem::remove(path, ec);
        if (ec) {
            errorMessage = "Failed to remove stale artifact path: " + path.string();
            return false;
        }
    }

    return true;
}

[[nodiscard]] bool ValidateWorkerInputs(
    const std::filesystem::path& workspaceRoot,
    const CampaignExecutionPlan& plan,
    std::string& failureReason)
{
    const auto inputs = CollectRequiredInputs(plan);
    for (const auto& input : inputs) {
        if (!std::filesystem::exists(workspaceRoot / input)) {
            failureReason = "Missing required worker input: " + input;
            return false;
        }
    }

    if (!plan.snapshotProfile.empty() &&
        !std::filesystem::exists(workspaceRoot / ("vm\\profiles\\" + plan.snapshotProfile + ".json"))) {
        failureReason = "Missing worker snapshot profile manifest.";
        return false;
    }

    return true;
}

[[nodiscard]] bool ValidateExecutionManifest(
    const std::filesystem::path& workspaceRoot,
    const CampaignExecutionPlan& plan,
    const HarnessAdapterDescriptor& adapter,
    std::string& failureReason)
{
    const auto manifestRelativePath = GetExecutionManifestPath(plan.id);
    std::string manifestText;
    if (!ReadTextFile(workspaceRoot / manifestRelativePath, manifestText)) {
        failureReason = "Missing worker execution manifest: " + manifestRelativePath.string();
        return false;
    }

    std::string manifestPlanId;
    if (!TryExtractJsonStringField(manifestText, "planId", manifestPlanId) || manifestPlanId != plan.id) {
        failureReason = "Worker execution manifest plan id does not match the scheduled plan.";
        return false;
    }

    std::string manifestAdapterId;
    if (!TryExtractJsonStringField(manifestText, "adapterId", manifestAdapterId) || manifestAdapterId != adapter.id) {
        failureReason = "Worker execution manifest adapter id does not match the scheduled adapter.";
        return false;
    }

    return true;
}

[[nodiscard]] int RunWorker(
    const WorkerCommandKind kind,
    const std::filesystem::path& workspaceRoot,
    const CampaignExecutionPlan& plan,
    const HarnessAdapterDescriptor& adapter)
{
    const auto resultPath = workspaceRoot / GetResultPath(plan.id);
    std::error_code ec;
    std::filesystem::create_directories(resultPath.parent_path(), ec);
    if (ec) {
        std::cerr << "Failed to create worker-result directory\n";
        return 3;
    }

    std::string failureReason;
    if (!ValidateExecutionManifest(workspaceRoot, plan, adapter, failureReason) ||
        !ValidateWorkerInputs(workspaceRoot, plan, failureReason)) {
        if (!WriteTextFile(resultPath,
                "{\n  \"status\": \"quarantined\",\n  \"reason\": \"" + EscapeJson(failureReason) + "\"\n}\n")) {
            std::cerr << "Failed to write quarantined worker result\n";
        }
        std::cout << failureReason << '\n';
        return 2;
    }

    const auto inputs = CollectRequiredInputs(plan);
    const auto start = std::chrono::steady_clock::now();
    const auto totalBytes = ComputeTotalInputBytes(workspaceRoot, inputs);

    std::cout << "Worker kind: " << ToString(kind) << '\n';
    std::cout << "Plan: " << plan.id << '\n';
    std::cout << "Adapter: " << adapter.id << '\n';
    std::cout << "Required inputs: " << inputs.size() << '\n';
    if (!plan.snapshotProfile.empty()) {
        std::cout << "Snapshot profile: " << plan.snapshotProfile << '\n';
    }

    const auto end = std::chrono::steady_clock::now();
    const auto durationMs = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());

    if (!WriteTextFile(resultPath, BuildWorkerResultJson(kind, plan, adapter, inputs, totalBytes, durationMs))) {
        std::cerr << "Failed to write worker result file\n";
        return 3;
    }

    return 0;
}

}  // namespace

std::string_view ToString(const WorkerCommandKind kind) {
    switch (kind) {
    case WorkerCommandKind::KernelVm:
        return "kernel-vm-worker";
    case WorkerCommandKind::Broker:
        return "broker-worker";
    case WorkerCommandKind::Parser:
        return "parser-worker";
    }

    return "unknown";
}

bool WorkerBackendRuntime::LaunchWorkerProcess(
    const std::filesystem::path& workspaceRoot,
    const CampaignExecutionPlan& plan,
    const HarnessAdapterDescriptor& adapter,
    std::string& errorMessage,
    WorkerProcessResult& result)
{
    const auto executablePath = GetCurrentExecutablePath();
    if (executablePath.empty()) {
        errorMessage = "Failed to resolve current executable path for worker launch.";
        return false;
    }

    const auto logPath = workspaceRoot / GetLogPath(plan.id);
    const auto resultPath = workspaceRoot / GetResultPath(plan.id);

    std::error_code ec;
    std::filesystem::create_directories(logPath.parent_path(), ec);
    if (ec) {
        errorMessage = "Failed to create worker log directory.";
        return false;
    }
    std::filesystem::create_directories(resultPath.parent_path(), ec);
    if (ec) {
        errorMessage = "Failed to create worker result directory.";
        return false;
    }

    const auto workerKind = ResolveWorkerKind(adapter.kind);
    const std::wstring commandName =
        workerKind == WorkerCommandKind::KernelVm ? L"--worker-kernel-vm" :
        workerKind == WorkerCommandKind::Broker ? L"--worker-broker" :
        L"--worker-parser";
    const std::wstring commandLine = BuildWorkerCommandLine(executablePath, commandName, workspaceRoot, plan.id);
    const DWORD timeoutMs = GetWorkerTimeoutMs(adapter.kind);

    if (!RemoveStaleArtifact(resultPath, errorMessage)) {
        return false;
    }

    SECURITY_ATTRIBUTES securityAttributes{};
    securityAttributes.nLength = sizeof(securityAttributes);
    securityAttributes.bInheritHandle = TRUE;

    ScopedHandle logHandle(::CreateFileW(
        logPath.wstring().c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ,
        &securityAttributes,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
    if (!logHandle.valid()) {
        errorMessage = "Failed to open worker log file.";
        return false;
    }

    ScopedHandle nullInputHandle(::CreateFileW(
        L"NUL",
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        &securityAttributes,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
    if (!nullInputHandle.valid()) {
        errorMessage = "Failed to open NUL input handle for worker launch.";
        return false;
    }

    std::array<HANDLE, 2> inheritedHandles{
        nullInputHandle.get(),
        logHandle.get()
    };

    SIZE_T attributeListBytes = 0;
    ::InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeListBytes);
    std::vector<std::byte> attributeBuffer(attributeListBytes);
    auto* attributeList = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(attributeBuffer.data());
    if (::InitializeProcThreadAttributeList(attributeList, 1, 0, &attributeListBytes) == FALSE) {
        errorMessage = BuildWin32ErrorMessage(
            "Failed to initialize worker handle inheritance list",
            ::GetLastError());
        return false;
    }

    const BOOL updatedAttributes = ::UpdateProcThreadAttribute(
        attributeList,
        0,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        inheritedHandles.data(),
        static_cast<SIZE_T>(inheritedHandles.size() * sizeof(HANDLE)),
        nullptr,
        nullptr);
    if (updatedAttributes == FALSE) {
        const DWORD lastError = ::GetLastError();
        ::DeleteProcThreadAttributeList(attributeList);
        errorMessage = BuildWin32ErrorMessage(
            "Failed to update worker handle inheritance list",
            lastError);
        return false;
    }

    STARTUPINFOEXW startupInfo{};
    startupInfo.StartupInfo.cb = sizeof(startupInfo);
    startupInfo.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startupInfo.StartupInfo.hStdOutput = logHandle.get();
    startupInfo.StartupInfo.hStdError = logHandle.get();
    startupInfo.StartupInfo.hStdInput = nullInputHandle.get();
    startupInfo.lpAttributeList = attributeList;

    PROCESS_INFORMATION processInfo{};
    std::wstring mutableCommandLine = commandLine;
    const BOOL created = ::CreateProcessW(
        executablePath.c_str(),
        mutableCommandLine.data(),
        nullptr,
        nullptr,
        TRUE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &startupInfo.StartupInfo,
        &processInfo);
    const DWORD createProcessError = created == FALSE ? ::GetLastError() : ERROR_SUCCESS;
    ::DeleteProcThreadAttributeList(attributeList);

    if (created == FALSE) {
        errorMessage = BuildWin32ErrorMessage("CreateProcessW failed for worker launch", createProcessError);
        return false;
    }

    ScopedHandle processHandle(processInfo.hProcess);
    ScopedHandle threadHandle(processInfo.hThread);

    result.planId = plan.id;
    result.laneId = adapter.laneId;
    result.adapterId = adapter.id;
    result.workerImage = adapter.workerImage;
    result.resultRelativePath = GetResultPath(plan.id).string();
    result.logRelativePath = GetLogPath(plan.id).string();

    const DWORD waitResult = ::WaitForSingleObject(processHandle.get(), timeoutMs);
    if (waitResult == WAIT_TIMEOUT) {
        result.status = RunnerExecutionStatus::Crashed;
        result.failureSignal = "worker-timeout";
        result.exitCode = ERROR_TIMEOUT;
        result.statusReason = "Worker exceeded the execution timeout and was terminated.";
        ::TerminateProcess(processHandle.get(), ERROR_TIMEOUT);
        ::WaitForSingleObject(processHandle.get(), 30000);
        errorMessage.clear();
        return true;
    }

    if (waitResult == WAIT_FAILED) {
        errorMessage = BuildWin32ErrorMessage("WaitForSingleObject failed for worker launch", ::GetLastError());
        return false;
    }

    DWORD exitCode = 0;
    if (::GetExitCodeProcess(processHandle.get(), &exitCode) == FALSE) {
        errorMessage = BuildWin32ErrorMessage("Failed to collect worker exit code", ::GetLastError());
        return false;
    }

    result.exitCode = static_cast<std::uint32_t>(exitCode);

    switch (exitCode) {
    case 0:
        result.status = std::filesystem::exists(resultPath)
            ? RunnerExecutionStatus::Completed
            : RunnerExecutionStatus::Crashed;
        result.statusReason = result.status == RunnerExecutionStatus::Completed
            ? "Worker process completed successfully."
            : "Worker exited successfully but did not emit a result file.";
        result.failureSignal = result.status == RunnerExecutionStatus::Completed
            ? ""
            : "worker-missing-result";
        break;
    case 2:
        result.status = RunnerExecutionStatus::Quarantined;
        result.statusReason = "Worker quarantined the plan during live execution.";
        result.failureSignal.clear();
        break;
    default:
        result.status = RunnerExecutionStatus::Crashed;
        result.failureSignal = "worker-exit-code-" + std::to_string(exitCode);
        result.statusReason = "Worker process exited abnormally.";
        break;
    }

    errorMessage.clear();
    return true;
}

int WorkerBackendRuntime::RunWorkerCommand(
    const WorkerCommandKind kind,
    const std::filesystem::path& workspaceRoot,
    const std::string_view planId)
{
    const auto* plan = CampaignPlanner::FindById(planId);
    if (plan == nullptr) {
        std::cerr << "Unknown worker plan id: " << planId << '\n';
        return 3;
    }

    const auto* adapter = HarnessAdapterCatalog::FindForPlan(*plan);
    if (adapter == nullptr) {
        std::cerr << "Unable to resolve worker adapter for plan: " << planId << '\n';
        return 3;
    }

    return RunWorker(kind, workspaceRoot, *plan, *adapter);
}

}  // namespace ShadowStrike::Fuzzer
