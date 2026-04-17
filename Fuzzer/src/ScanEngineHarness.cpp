// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
#include "ShadowStrike/Fuzzer/Harnesses/ScanEngineHarness.hpp"

#include "PhantomCore/Core/Engine/ScanEngine.hpp"
#include "PhantomCore/Utils/FileUtils.hpp"

#include <Windows.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace SSF = ShadowStrike::Fuzzer;
namespace SSE = ShadowStrike::Core::Engine;

namespace {

constexpr uint8_t kLaneMask = 0x03;
constexpr uint8_t kLaneMemory = 0;
constexpr uint8_t kLaneFile = 1;
constexpr uint8_t kLaneArchive = 2;
constexpr uint8_t kLaneOrchestration = 3;

constexpr std::string_view kMarkerInfected = "FUZZ_SIG_INFECTED";
constexpr std::string_view kMarkerSuspicious = "FUZZ_SIG_SUSPICIOUS";
constexpr std::string_view kMarkerArchiveBomb = "FUZZ_ARCHIVE_BOMB";

thread_local std::filesystem::path g_activeTempRoot;
SRWLOCK g_scanEngineLock = SRWLOCK_INIT;
std::atomic<uint64_t> g_tempSequence{ 0 };

void FinalizeHarnessResult(SSF::HarnessResult& result) noexcept {
    if (result.validationIssueCount != 0) {
        result.parsedOk = false;
    }
}

void ResetScanEngineNoexcept() noexcept {
    try {
        SSE::ScanEngine::Instance().Shutdown();
    } catch (...) {
    }
}

void CleanupTempRootNoexcept() noexcept {
    if (g_activeTempRoot.empty()) {
        return;
    }

    std::error_code ec;
    std::filesystem::remove_all(g_activeTempRoot, ec);
    g_activeTempRoot.clear();
}

[[nodiscard]] std::filesystem::path MakeTempRoot() {
    const uint64_t sequence = g_tempSequence.fetch_add(1, std::memory_order_relaxed);
    const std::wstring name = L"scan-engine-fuzz-" +
        std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(sequence);
    return std::filesystem::temp_directory_path() / name;
}

[[nodiscard]] std::vector<uint8_t> MakePayload(std::span<const uint8_t> input) {
    if (input.size() <= 2) {
        return std::vector<uint8_t>{ 'M', 'Z', 0x90, 0x00 };
    }

    return std::vector<uint8_t>(input.begin() + 2, input.end());
}

[[nodiscard]] bool WriteBytes(
    const std::filesystem::path& path,
    std::span<const uint8_t> bytes)
{
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) {
        return false;
    }

    stream.write(
        reinterpret_cast<const char*>(bytes.data()),
        static_cast<std::streamsize>(bytes.size()));
    return stream.good();
}

[[nodiscard]] bool ValidateDetectionExpectation(
    std::span<const uint8_t> payload,
    const SSE::EngineResult& result)
{
    const std::string_view payloadView(
        reinterpret_cast<const char*>(payload.data()),
        payload.size());

    if (payloadView.find(kMarkerInfected) != std::string_view::npos) {
        return result.verdict == SSE::ScanVerdict::Infected ||
               result.verdict == SSE::ScanVerdict::Suspicious;
    }

    if (payloadView.find(kMarkerSuspicious) != std::string_view::npos) {
        return result.verdict == SSE::ScanVerdict::Suspicious ||
               result.verdict == SSE::ScanVerdict::Infected;
    }

    return true;
}

[[nodiscard]] SSE::EngineConfig BuildConfig(const std::filesystem::path& tempRoot) {
    SSE::EngineConfig config = SSE::EngineConfig::CreateDefault();
    config.enableBehaviorAnalysis = false;
    config.enableMachineLearning = false;
    config.enableCloudLookup = false;
    config.enableAMSI = false;
    config.enableScriptAnalysis = false;
    config.enableHeuristics = false;
    config.enableCompressedScanning = true;
    config.enableResultCache = true;
    config.scanThreads = 1;
    config.maxConcurrentScans = 1;
    config.maxFileSizeRealTime = 4 * 1024 * 1024;
    config.maxFileSizeOnDemand = 4 * 1024 * 1024;
    config.signatureDbPath = (tempRoot / "signature.db").wstring();
    config.whitelistDbPath = (tempRoot / "whitelist.db").wstring();
    config.threatIntelDbPath = (tempRoot / "threatintel.db").wstring();
    config.reportPath = (tempRoot / "reports").wstring();
    config.archiveOptions.maxArchiveSize = 4 * 1024 * 1024;
    config.archiveOptions.maxExtractedSize = 4 * 1024 * 1024;
    config.archiveOptions.maxFilesInArchive = 16;
    config.archiveOptions.maxNestingDepth = 4;
    return config;
}

[[nodiscard]] SSE::ScanContext BuildContext(
    const std::wstring& filePath,
    bool deepScan,
    bool stopOnFirstMatch)
{
    SSE::ScanContext context{};
    context.type = SSE::ScanType::OnDemand;
    context.priority = SSE::ScanPriority::Normal;
    context.filePath = filePath;
    context.processId = 31337;
    context.deepScan = deepScan;
    context.scanArchives = true;
    context.scanPacked = true;
    context.stopOnFirstMatch = stopOnFirstMatch;
    context.useCache = false;
    context.timeout = std::chrono::milliseconds(5000);
    return context;
}

void NoteValidationFailure(
    SSF::HarnessResult& result,
    std::string_view message)
{
    ++result.validationIssueCount;
    if (result.errorMessage.empty()) {
        result.errorMessage.assign(message.begin(), message.end());
    }
}

void ExerciseMemoryLane(
    SSE::ScanEngine& engine,
    std::span<const uint8_t> payload,
    uint8_t flags,
    SSF::HarnessResult& result)
{
    const SSE::ScanContext context = BuildContext(L"memory://scan-engine", (flags & 0x04u) != 0, true);
    const SSE::EngineResult scanResult = engine.ScanMemory(payload, context);
    result.parsedOk = true;

    if (!ValidateDetectionExpectation(payload, scanResult)) {
        NoteValidationFailure(result, "memory lane verdict mismatch");
    }
}

void ExerciseFileLane(
    SSE::ScanEngine& engine,
    const std::filesystem::path& tempRoot,
    std::span<const uint8_t> payload,
    uint8_t flags,
    SSF::HarnessResult& result)
{
    const bool useExcludedPath = (flags & 0x08u) != 0;
    const std::filesystem::path samplePath = tempRoot /
        (useExcludedPath ? "excluded-sample.exe" : "sample.exe");
    if (!WriteBytes(samplePath, payload)) {
        NoteValidationFailure(result, "file lane failed to materialize sample");
        return;
    }

    uint64_t detectionCallbacks = 0;
    const uint64_t callbackId = engine.RegisterDetectionCallback(
        [&detectionCallbacks](const SSE::EngineResult&) {
            ++detectionCallbacks;
        });

    if (useExcludedPath) {
        SSE::ExclusionRule exclusion{};
        exclusion.type = SSE::ExclusionRule::Type::Path;
        exclusion.pattern = samplePath.wstring();
        exclusion.enabled = true;
        exclusion.description = "scan-engine fuzz exact-path exclusion";
        engine.AddExclusion(exclusion);
    }

    const SSE::ScanContext context = BuildContext(samplePath.wstring(), (flags & 0x04u) != 0, true);
    const SSE::EngineResult fileResult = engine.ScanFile(samplePath.wstring(), context);
    const SSE::EngineResult quickResult = engine.QuickScanFile(samplePath.wstring());
    result.parsedOk = true;

    if (!useExcludedPath && !ValidateDetectionExpectation(payload, fileResult)) {
        NoteValidationFailure(result, "file lane verdict mismatch");
    }

    if (useExcludedPath && fileResult.verdict != SSE::ScanVerdict::Whitelisted) {
        NoteValidationFailure(result, "excluded file was not skipped cleanly");
    }

    if (useExcludedPath && quickResult.verdict != SSE::ScanVerdict::Whitelisted) {
        NoteValidationFailure(result, "quick excluded file was not skipped cleanly");
    }

    if (!useExcludedPath && !ValidateDetectionExpectation(payload, quickResult)) {
        NoteValidationFailure(result, "quick file lane verdict mismatch");
    }

    if (callbackId != 0 && !engine.UnregisterDetectionCallback(callbackId)) {
        NoteValidationFailure(result, "failed to unregister detection callback");
    }

    if (!engine.GetExclusions().empty()) {
        engine.ClearExclusions();
    }

    if (!useExcludedPath &&
        detectionCallbacks == 0 &&
        std::string_view(reinterpret_cast<const char*>(payload.data()), payload.size()).find(kMarkerInfected) !=
            std::string_view::npos) {
        NoteValidationFailure(result, "file lane detection callback did not fire");
    }
}

void ExerciseArchiveLane(
    SSE::ScanEngine& engine,
    const std::filesystem::path& tempRoot,
    std::span<const uint8_t> payload,
    uint8_t flags,
    SSF::HarnessResult& result)
{
    const std::filesystem::path archivePath = tempRoot / "sample.zip";
    if (!WriteBytes(archivePath, payload)) {
        NoteValidationFailure(result, "archive lane failed to materialize archive");
        return;
    }

    SSE::ArchiveScanOptions options{};
    options.action = SSE::ArchiveAction::Scan;
    options.maxArchiveSize = 4 * 1024 * 1024;
    options.maxExtractedSize = 4 * 1024 * 1024;
    options.maxFilesInArchive = 8;
    options.maxNestingDepth = ((flags & 0x10u) != 0) ? 1u : 3u;

    const SSE::ScanContext context = BuildContext(archivePath.wstring(), false, true);
    const SSE::BatchScanResult archiveResult = engine.ScanArchive(archivePath.wstring(), options, context);
    result.parsedOk = true;

    if (!archiveResult.results.empty()) {
        for (const auto& entryResult : archiveResult.results) {
            if (!ValidateDetectionExpectation(payload, entryResult)) {
                NoteValidationFailure(result, "archive child result mismatch");
                break;
            }
        }
    }
}

void ExerciseOrchestrationLane(
    SSE::ScanEngine& engine,
    const std::filesystem::path& tempRoot,
    std::span<const uint8_t> payload,
    uint8_t flags,
    SSF::HarnessResult& result)
{
    const std::filesystem::path root = tempRoot / "tree";
    const std::filesystem::path cleanPath = root / "clean.exe";
    const std::filesystem::path infectedPath = root / "infected.exe";
    std::error_code ec;
    std::filesystem::create_directories(root, ec);
    if (ec) {
        NoteValidationFailure(result, "orchestration lane failed to create directory");
        return;
    }

    const std::vector<uint8_t> cleanBytes{ 'M', 'Z', 0x90, 0x00, 'C', 'L', 'N' };
    if (!WriteBytes(cleanPath, cleanBytes) || !WriteBytes(infectedPath, payload)) {
        NoteValidationFailure(result, "orchestration lane failed to write samples");
        return;
    }

    std::atomic<uint64_t> detectionCallbacks{0};
    std::atomic<uint64_t> completeCallbacks{0};
    const uint64_t detectionId = engine.RegisterDetectionCallback(
        [&detectionCallbacks](const SSE::EngineResult&) {
            detectionCallbacks.fetch_add(1, std::memory_order_relaxed);
        });
    const uint64_t completeId = engine.RegisterCompleteCallback(
        [&completeCallbacks](const SSE::ScanStatistics&) {
            completeCallbacks.fetch_add(1, std::memory_order_relaxed);
        });

    SSE::BatchScanRequest batchRequest{};
    batchRequest.context = BuildContext(root.wstring(), (flags & 0x04u) != 0, false);
    batchRequest.filePaths = { cleanPath.wstring(), infectedPath.wstring() };
    batchRequest.maxConcurrency = 2;
    const SSE::BatchScanResult batchResult = engine.ScanBatch(batchRequest);

    SSE::DirectoryScanRequest directoryRequest{};
    directoryRequest.rootPath = root.wstring();
    directoryRequest.context = BuildContext(root.wstring(), false, false);
    directoryRequest.maxConcurrency = 2;
    directoryRequest.recursive = true;
    const SSE::DirectoryScanResult directoryResult = engine.ScanDirectory(directoryRequest);

    const bool selfTestOk = engine.SelfTest();
    const SSE::ScanEngine::Stats stats = engine.GetStatistics();
    result.parsedOk = true;

    if (batchResult.results.size() != batchRequest.filePaths.size()) {
        NoteValidationFailure(result, "batch scan result count mismatch");
    }

    if (directoryResult.results.empty()) {
        NoteValidationFailure(result, "directory scan produced no results");
    }

    if (!selfTestOk) {
        NoteValidationFailure(result, "scan engine self-test failed");
    }

    if (stats.totalScans == 0) {
        NoteValidationFailure(result, "statistics were not updated");
    }

    if (detectionId != 0 && !engine.UnregisterDetectionCallback(detectionId)) {
        NoteValidationFailure(result, "failed to unregister orchestration detection callback");
    }

    if (completeId != 0 && !engine.UnregisterCompleteCallback(completeId)) {
        NoteValidationFailure(result, "failed to unregister orchestration complete callback");
    }

    const std::string_view payloadView(
        reinterpret_cast<const char*>(payload.data()),
        payload.size());
    if (payloadView.find(kMarkerInfected) != std::string_view::npos &&
        detectionCallbacks.load(std::memory_order_relaxed) == 0) {
        NoteValidationFailure(result, "orchestration detection callback did not fire");
    }
}

void EnsureSeedCorpus(const std::filesystem::path& corpusDir) {
    const std::array<std::pair<std::string_view, std::vector<uint8_t>>, 4> seeds{{
        { "seed-memory.bin", { kLaneMemory, 0x00, 'M', 'Z', 0x90, 0x00, 'm', 'e', 'm' } },
        { "seed-file.bin", { kLaneFile, 0x00, 'M', 'Z', 0x90, 0x00,
            'F','U','Z','Z','_','S','I','G','_','I','N','F','E','C','T','E','D' } },
        { "seed-archive.bin", { kLaneArchive, 0x10, 'P', 'K', 0x03, 0x04,
            'F','U','Z','Z','_','A','R','C','H','I','V','E','_','B','O','M','B' } },
        { "seed-orchestration.bin", { kLaneOrchestration, 0x00, 'M', 'Z', 0x90, 0x00,
            'F','U','Z','Z','_','S','I','G','_','I','N','F','E','C','T','E','D' } },
    }};

    for (const auto& [name, bytes] : seeds) {
        const auto seedPath = corpusDir / name;
        if (std::filesystem::exists(seedPath)) {
            continue;
        }

        WriteBytes(seedPath, bytes);
    }
}

[[nodiscard]] std::optional<std::vector<uint8_t>> ReadFileBytes(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        return std::nullopt;
    }

    stream.seekg(0, std::ios::end);
    const std::streamoff size = stream.tellg();
    if (size < 0) {
        return std::nullopt;
    }

    stream.seekg(0, std::ios::beg);
    std::vector<uint8_t> bytes(static_cast<size_t>(size));
    if (!bytes.empty()) {
        stream.read(reinterpret_cast<char*>(bytes.data()), size);
        if (!stream) {
            return std::nullopt;
        }
    }

    return bytes;
}

}  // namespace

namespace ShadowStrike::Fuzzer {

HarnessResult ScanEngineHarness::Run(std::span<const uint8_t> input) noexcept {
    HarnessResult result{};
    result.parsedOk = false;

    const auto start = std::chrono::steady_clock::now();
    const unsigned long sehCode = SEHCallScanEngine(input.data(), input.size(), &result);
    result.parseTimeNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - start).count());

    if (sehCode != 0) {
        result.crashed = true;
        result.crashSignal = ExceptionCodeToString(sehCode);
        result.parsedOk = false;
    }

    FinalizeHarnessResult(result);
    return result;
}

HarnessFunction ScanEngineHarness::GetHarnessFunction() noexcept {
    return [](std::span<const uint8_t> input) noexcept {
        return Run(input);
    };
}

std::string_view ScanEngineHarness::GetName() noexcept {
    return "scan-engine";
}

std::string_view ScanEngineHarness::GetDescription() noexcept {
    return "Real ScanEngine orchestration fuzzing harness";
}

std::string ScanEngineHarness::ExceptionCodeToString(unsigned long code) {
    std::ostringstream stream;
    stream << "0x" << std::hex << std::uppercase << code;
    return stream.str();
}

unsigned long ScanEngineHarness::SEHCallScanEngine(
    const uint8_t* data,
    size_t size,
    HarnessResult* result) noexcept
{
    unsigned long sehCode = 0;
    AcquireSRWLockExclusive(&g_scanEngineLock);
    __try {
        __try {
            if (result != nullptr) {
                result->parsedOk = ExerciseScanEngineImpl(data, size, *result);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            sehCode = GetExceptionCode();
        }
    } __finally {
        ResetScanEngineNoexcept();
        CleanupTempRootNoexcept();
        ReleaseSRWLockExclusive(&g_scanEngineLock);
    }

    return sehCode;
}

bool ScanEngineHarness::ExerciseScanEngineImpl(
    const uint8_t* data,
    size_t size,
    HarnessResult& result)
{
    if (data == nullptr || size < 2) {
        result.errorMessage = "scan-engine input too small";
        return false;
    }

    const uint8_t lane = data[0] & kLaneMask;
    const uint8_t flags = data[1];
    const std::span<const uint8_t> input(data, size);
    const std::vector<uint8_t> payload = MakePayload(input);

    const std::filesystem::path tempRoot = MakeTempRoot();
    g_activeTempRoot = tempRoot;

    std::error_code ec;
    std::filesystem::create_directories(tempRoot, ec);
    if (ec) {
        result.errorMessage = "failed to create scan-engine temp root";
        return false;
    }

    auto& engine = SSE::ScanEngine::Instance();
    if (!engine.Initialize(BuildConfig(tempRoot))) {
        result.errorMessage = "scan engine initialization failed";
        return false;
    }

    switch (lane) {
        case kLaneMemory:
            ExerciseMemoryLane(engine, payload, flags, result);
            break;
        case kLaneFile:
            ExerciseFileLane(engine, tempRoot, payload, flags, result);
            break;
        case kLaneArchive:
            ExerciseArchiveLane(engine, tempRoot, payload, flags, result);
            break;
        case kLaneOrchestration:
            ExerciseOrchestrationLane(engine, tempRoot, payload, flags, result);
            break;
        default:
            result.errorMessage = "invalid scan-engine lane";
            return false;
    }

    return result.validationIssueCount == 0;
}

int RunScanEngineFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config) noexcept
{
    if (!InstallCtrlCHandler()) {
        std::cerr << "[ScanEngineFuzzer] Warning: Failed to install Ctrl+C handler\n";
    }

    const auto corpusDir = workspaceDir / "corpora" / "scan-engine";
    const auto crashDir = workspaceDir / "crashes" / "scan-engine";

    std::error_code ec;
    std::filesystem::create_directories(corpusDir, ec);
    if (ec) {
        std::cerr << "[ScanEngineFuzzer] Failed to create corpus directory: " << corpusDir << '\n';
        return 1;
    }

    ec.clear();
    std::filesystem::create_directories(crashDir, ec);
    if (ec) {
        std::cerr << "[ScanEngineFuzzer] Failed to create crash directory: " << crashDir << '\n';
        return 1;
    }

    EnsureSeedCorpus(corpusDir);

    static constexpr std::array<std::string_view, 4> kSanitySeeds{
        "seed-memory.bin",
        "seed-file.bin",
        "seed-archive.bin",
        "seed-orchestration.bin",
    };

    for (const auto seedName : kSanitySeeds) {
        const auto seedBytes = ReadFileBytes(corpusDir / seedName);
        if (!seedBytes.has_value()) {
            std::cerr << "[ScanEngineFuzzer] Failed to read sanity seed: " << seedName << '\n';
            return 1;
        }

        const HarnessResult sanity = ScanEngineHarness::Run(*seedBytes);
        if (sanity.crashed || !sanity.parsedOk) {
            std::cerr << "[ScanEngineFuzzer] Sanity check failed for " << seedName;
            if (!sanity.errorMessage.empty()) {
                std::cerr << ": " << sanity.errorMessage;
            }
            if (!sanity.crashSignal.empty()) {
                std::cerr << " (" << sanity.crashSignal << ')';
            }
            std::cerr << '\n';
            return 1;
        }
    }

    FuzzLoopConfig loopConfig = config;
    loopConfig.targetName = std::string(ScanEngineHarness::GetName());

    std::cout << "[ScanEngineFuzzer] Starting scan-engine fuzzing...\n";
    std::cout << "[ScanEngineFuzzer] Corpus: " << corpusDir << '\n';
    std::cout << "[ScanEngineFuzzer] Crashes: " << crashDir << '\n';

    FuzzLoop loop(corpusDir, crashDir, ScanEngineHarness::GetHarnessFunction(), loopConfig);
    const bool success = loop.Run();
    const auto& stats = loop.GetStatistics();

    std::cout << "\n[ScanEngineFuzzer] Final Results:\n";
    std::cout << "  Total iterations: " << stats.totalIterations << '\n';
    std::cout << "  Unique crashes:   " << stats.uniqueCrashes << '\n';
    std::cout << "  Total crashes:    " << stats.crashesFound << '\n';
    std::cout << "  Final corpus:     " << stats.corpusSize << '\n';
    std::cout << "  Parse success:    " << stats.parseSuccesses << '\n';
    std::cout << "  Parse failure:    " << stats.parseFailures << '\n';
    std::cout << "  Duration:         " << (stats.durationMs / 1000) << "s\n";
    std::cout << "  Speed:            " << std::fixed << std::setprecision(1)
              << stats.iterationsPerSecond << " iter/s\n";

    return success ? 0 : 1;
}

}  // namespace ShadowStrike::Fuzzer
