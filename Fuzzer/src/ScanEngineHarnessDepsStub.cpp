#include "PhantomCore/Core/Engine/EmulationEngine.hpp"
#include "PhantomCore/Core/Engine/HeuristicAnalyzer.hpp"
#include "PhantomCore/Core/Engine/MachineLearningDetector.hpp"
#include "PhantomCore/Core/Engine/PackerUnpacker.hpp"
#include "PhantomCore/Core/Engine/PolymorphicDetector.hpp"
#include "PhantomCore/Core/Engine/SandboxAnalyzer.hpp"
#include "PhantomCore/Core/Engine/ZeroDayDetector.hpp"
#include "PhantomCore/Core/FileSystem/ArchiveExtractor.hpp"
#include "PhantomCore/Core/FileSystem/DocumentScanner.hpp"
#include "PhantomCore/Core/FileSystem/ExecutableAnalyzer.hpp"
#include "PhantomCore/AI/CortexConfig.hpp"
#include "PhantomCore/AI/CortexTypes.hpp"
#include "PhantomCore/AI/PhantomCortex.hpp"
#include "PhantomCore/Database/LogDB.hpp"
#include "PhantomCore/FuzzyHasher/FuzzyHasher.hpp"
#include "PhantomCore/HashStore/HashStore.hpp"
#include "PhantomCore/SignatureStore/SignatureStore.hpp"
#include "PhantomCore/SignatureStore/SignatureFormat.hpp"
#include "PhantomCore/SignatureStore/YaraRuleStore.hpp"
#include "PhantomCore/Scripts/AMSIIntegration.hpp"
#include "PhantomCore/Scripts/JavaScriptScanner.hpp"
#include "PhantomCore/Scripts/MacroDetector.hpp"
#include "PhantomCore/Scripts/PowerShellScanner.hpp"
#include "PhantomCore/Scripts/PythonScriptScanner.hpp"
#include "PhantomCore/Scripts/VBScriptScanner.hpp"
#include "PhantomCore/ThreatIntel/ThreatIntelDatabase.hpp"
#include "PhantomCore/ThreatIntel/ThreatIntelStore.hpp"
#include "PhantomCore/Utils/ProcessUtils.hpp"
#include "PhantomCore/Whitelist/WhiteListStore.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr std::string_view kMarkerInfected = "FUZZ_SIG_INFECTED";
constexpr std::string_view kMarkerSuspicious = "FUZZ_SIG_SUSPICIOUS";
constexpr std::string_view kMarkerArchiveBomb = "FUZZ_ARCHIVE_BOMB";

[[nodiscard]] std::vector<uint8_t> ReadAllBytes(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        return {};
    }

    stream.seekg(0, std::ios::end);
    const std::streamoff size = stream.tellg();
    if (size <= 0) {
        return {};
    }

    stream.seekg(0, std::ios::beg);
    std::vector<uint8_t> data(static_cast<size_t>(size));
    stream.read(reinterpret_cast<char*>(data.data()), size);
    if (!stream) {
        return {};
    }

    return data;
}

[[nodiscard]] bool ContainsMarker(std::span<const uint8_t> bytes, std::string_view marker) {
    if (bytes.empty() || marker.empty() || bytes.size() < marker.size()) {
        return false;
    }

    const std::string_view haystack(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    return haystack.find(marker) != std::string_view::npos;
}

[[nodiscard]] ShadowStrike::SignatureStore::DetectionResult MakeDetection(
    std::string_view name,
    ShadowStrike::SignatureStore::ThreatLevel level,
    std::string_view description)
{
    ShadowStrike::SignatureStore::DetectionResult detection{};
    detection.signatureId = 0x5353414E454E4755ull;
    detection.signatureName.assign(name.begin(), name.end());
    detection.threatLevel = level;
    detection.description.assign(description.begin(), description.end());
    detection.tags.emplace_back("fuzz");
    detection.matchTimestamp = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    return detection;
}

}  // namespace

namespace ShadowStrike::HashStore {

HashStore::HashStore() = default;
HashStore::~HashStore() = default;
HashBucket::~HashBucket() = default;

}  // namespace ShadowStrike::HashStore

namespace ShadowStrike::SignatureStore {

YaraRuleStore::YaraRuleStore() = default;
YaraRuleStore::~YaraRuleStore() = default;
SignatureIndex::~SignatureIndex() = default;

SignatureStore::SignatureStore() = default;
SignatureStore::~SignatureStore() = default;

StoreError SignatureStore::Initialize(const std::wstring&, bool) noexcept {
    m_initialized.store(true, std::memory_order_release);
    return StoreError::Success();
}

void SignatureStore::Close() noexcept {
    m_initialized.store(false, std::memory_order_release);
}

ScanResult SignatureStore::ScanFile(const std::wstring& filePath, const ScanOptions&) const noexcept {
    ScanResult result{};
    const std::vector<uint8_t> data = ReadAllBytes(filePath);
    result.totalBytesScanned = data.size();

    if (ContainsMarker(data, kMarkerInfected)) {
        result.detections.push_back(MakeDetection(
            "Fuzz.ScanEngine.Infected",
            ThreatLevel::Critical,
            "Deterministic infected file marker"));
    } else if (ContainsMarker(data, kMarkerSuspicious)) {
        result.detections.push_back(MakeDetection(
            "Fuzz.ScanEngine.Suspicious",
            ThreatLevel::Medium,
            "Deterministic suspicious file marker"));
    }

    return result;
}

}  // namespace ShadowStrike::SignatureStore

namespace ShadowStrike::Whitelist {

StoreError WhitelistStore::Load(const std::wstring&, bool readOnly) noexcept {
    m_initialized.store(true, std::memory_order_release);
    m_readOnly.store(readOnly, std::memory_order_release);
    return {};
}

void WhitelistStore::Close() noexcept {
    m_initialized.store(false, std::memory_order_release);
}

uint64_t WhitelistStore::GetEntryCount() const noexcept {
    return 2;
}

LookupResult WhitelistStore::IsHashWhitelisted(
    const std::string& hashString,
    HashAlgorithm,
    const QueryOptions&) const noexcept
{
    LookupResult result{};
    result.found = hashString.starts_with("00");
    return result;
}

}  // namespace ShadowStrike::Whitelist

namespace ShadowStrike::ThreatIntel {

class ThreatIntelStore::Impl {};

ThreatIntelDatabase::ThreatIntelDatabase() = default;
ThreatIntelDatabase::~ThreatIntelDatabase() = default;
MappedRegion::~MappedRegion() = default;

bool ThreatIntelDatabase::Open(const DatabaseConfig&) noexcept {
    return true;
}

void ThreatIntelDatabase::Close() noexcept {
}

size_t ThreatIntelDatabase::GetEntryCount() const noexcept {
    return 1;
}

size_t ThreatIntelDatabase::FindEntry(std::string_view value, IOCType type) const noexcept {
    return (type == IOCType::FileHash && value.find("deadbeef") != std::string_view::npos) ? 0 : SIZE_MAX;
}

ThreatIntelStore::ThreatIntelStore() = default;
ThreatIntelStore::~ThreatIntelStore() = default;

bool ThreatIntelStore::Initialize(const StoreConfig&) {
    return true;
}

void ThreatIntelStore::Shutdown() {
}

StoreLookupResult ThreatIntelStore::LookupHash(
    std::string_view,
    std::string_view hashValue,
    const StoreLookupOptions&) noexcept
{
    StoreLookupResult result{};
    if (hashValue.find("deadbeef") != std::string_view::npos) {
        result.found = true;
        result.score = 95;
        result.reputation = ReputationLevel::Malicious;
        result.confidence = ConfidenceLevel::High;
        result.category = ThreatCategory::Malware;
    }
    return result;
}

}  // namespace ShadowStrike::ThreatIntel

namespace ShadowStrike::Core::Engine {

struct HeuristicAnalyzer::Impl {};
struct MachineLearningDetector::Impl {};
struct PackerUnpacker::Impl {};
class PolymorphicDetectorImpl {};
class SandboxAnalyzer::Impl {};
class EmulationEngine::Impl {};
class ZeroDayDetector::Impl {};

HeuristicAnalyzer& HeuristicAnalyzer::Instance() {
    static HeuristicAnalyzer instance;
    return instance;
}

HeuristicAnalyzer::HeuristicAnalyzer() = default;
HeuristicAnalyzer::~HeuristicAnalyzer() = default;

bool HeuristicAnalyzer::Initialize(
    std::shared_ptr<Utils::ThreadPool>,
    const HeuristicAnalyzerConfig&)
{
    return true;
}

void HeuristicAnalyzer::Shutdown() {
}

HeuristicResult HeuristicAnalyzer::AnalyzeFile(const std::wstring& filePath) {
    HeuristicResult result{};
    result.filePath = filePath;
    return result;
}

MachineLearningDetector::MachineLearningDetector() = default;
MachineLearningDetector::~MachineLearningDetector() = default;

void MachineLearningDetector::Shutdown() {
}

PackerUnpacker& PackerUnpacker::Instance() noexcept {
    static PackerUnpacker instance;
    return instance;
}

PackerUnpacker::PackerUnpacker() noexcept = default;
PackerUnpacker::~PackerUnpacker() = default;

bool PackerUnpacker::Initialize(UnpackError*) noexcept {
    return true;
}

void PackerUnpacker::Shutdown() noexcept {
}

PolymorphicDetector& PolymorphicDetector::Instance() noexcept {
    static PolymorphicDetector instance;
    return instance;
}

PolymorphicDetector::PolymorphicDetector() = default;
PolymorphicDetector::~PolymorphicDetector() = default;

bool PolymorphicDetector::Initialize(const PolymorphicConfiguration&) {
    return true;
}

void PolymorphicDetector::Shutdown() {
}

bool PolymorphicDetector::IsInitialized() const noexcept {
    return true;
}

PolyResult PolymorphicDetector::AnalyzeFile(const fs::path& filePath, const PolyAnalysisOptions&) {
    PolyResult result{};
    result.engineName = filePath.filename().string();
    return result;
}

SandboxAnalyzer& SandboxAnalyzer::Instance() noexcept {
    static SandboxAnalyzer instance;
    return instance;
}

SandboxAnalyzer::SandboxAnalyzer() noexcept = default;
SandboxAnalyzer::~SandboxAnalyzer() = default;

bool SandboxAnalyzer::Initialize(const SandboxAnalyzerConfiguration&, SandboxError*) noexcept {
    return true;
}

void SandboxAnalyzer::Shutdown() noexcept {
}

bool SandboxAnalyzer::IsInitialized() const noexcept {
    return true;
}

SandboxVerdict SandboxAnalyzer::Analyze(
    const fs::path&,
    const SandboxAnalysisOptions&,
    SandboxError*) noexcept
{
    SandboxVerdict result{};
    return result;
}

EmulationEngine& EmulationEngine::Instance() {
    static EmulationEngine instance;
    return instance;
}

EmulationEngine::EmulationEngine() = default;
EmulationEngine::~EmulationEngine() = default;

bool EmulationEngine::Initialize(std::shared_ptr<Utils::ThreadPool>) {
    return true;
}

void EmulationEngine::Shutdown() {
}

bool EmulationEngine::IsInitialized() const noexcept {
    return true;
}

EmulationResult EmulationEngine::EmulatePE(
    const std::vector<uint8_t>& data,
    const EmulationConfig&)
{
    EmulationResult result{};
    if (ContainsMarker(data, kMarkerInfected)) {
        result.isMalicious = true;
        result.threatName = "Fuzz.Emulation.Detected";
        result.threatScore = 90.0f;
    }
    return result;
}

ZeroDayDetector& ZeroDayDetector::Instance() noexcept {
    static ZeroDayDetector instance;
    return instance;
}

ZeroDayDetector::ZeroDayDetector() = default;
ZeroDayDetector::~ZeroDayDetector() = default;

bool ZeroDayDetector::Initialize(const ZeroDayConfiguration&) {
    return true;
}

void ZeroDayDetector::Shutdown() {
}

bool ZeroDayDetector::IsInitialized() const noexcept {
    return true;
}

ZeroDayResult ZeroDayDetector::AnalyzeFile(
    const fs::path& filePath,
    const ZeroDayAnalysisOptions&)
{
    ZeroDayResult result{};
    result.description = filePath.filename().string();
    return result;
}

}  // namespace ShadowStrike::Core::Engine

namespace ShadowStrike::Core::FileSystem {

class ExecutableAnalyzerImpl {};
class DocumentScannerImpl {};
class ArchiveExtractorImpl {};

ExecutableAnalyzer& ExecutableAnalyzer::Instance() {
    static ExecutableAnalyzer instance;
    return instance;
}

ExecutableAnalyzer::ExecutableAnalyzer() = default;
ExecutableAnalyzer::~ExecutableAnalyzer() = default;

bool ExecutableAnalyzer::Initialize() {
    return true;
}

void ExecutableAnalyzer::Shutdown() noexcept {
}

bool ExecutableAnalyzer::IsPE(const std::wstring& filePath) const {
    const std::filesystem::path path(filePath);
    const std::wstring ext = path.extension().wstring();
    return ext == L".exe" || ext == L".dll" || ext == L".sys";
}

ExecutableInfo ExecutableAnalyzer::Analyze(
    const std::wstring& filePath,
    const AnalysisOptions&)
{
    ExecutableInfo result{};
    result.isValid = true;
    const std::vector<uint8_t> data = ReadAllBytes(filePath);
    if (ContainsMarker(data, kMarkerSuspicious)) {
        result.riskScore = 85;
    }
    return result;
}

std::optional<std::vector<float>> ExecutableAnalyzer::ExtractMLFeatures(
    const ExecutableInfo&) const
{
    return std::vector<float>{ 0.1f, 0.2f, 0.3f };
}

DocumentScanner& DocumentScanner::Instance() {
    static DocumentScanner instance;
    return instance;
}

DocumentScanner::DocumentScanner() = default;
DocumentScanner::~DocumentScanner() = default;

bool DocumentScanner::Initialize(const DocumentScannerConfig&) {
    return true;
}

void DocumentScanner::Shutdown() noexcept {
}

bool DocumentScanner::IsInitialized() const noexcept {
    return true;
}

DocumentScanResult DocumentScanner::Scan(
    const std::wstring& filePath,
    const DocumentScannerConfig&) {
    DocumentScanResult result{};
    const std::vector<uint8_t> data = ReadAllBytes(filePath);
    if (ContainsMarker(data, kMarkerInfected)) {
        result.verdict = ScanVerdict::Malicious;
        result.riskScore = 90;
        DocumentThreat finding{};
        finding.description = "Fuzz document marker";
        finding.mitreId = "T1204";
        result.threats.push_back(std::move(finding));
        result.aiClassification = "Doc.Malware.Fuzz";
        result.aiMaliciousConfidence = 0.95f;
    }
    return result;
}

ArchiveExtractor& ArchiveExtractor::Instance() {
    static ArchiveExtractor instance;
    return instance;
}

ArchiveExtractor::ArchiveExtractor() = default;
ArchiveExtractor::~ArchiveExtractor() = default;

bool ArchiveExtractor::Initialize(const ArchiveExtractorConfig&) {
    return true;
}

void ArchiveExtractor::Shutdown() noexcept {
}

bool ArchiveExtractor::IsArchive(const std::wstring& filePath) const {
    return std::filesystem::path(filePath).extension() == L".zip";
}

ExtractionSummary ArchiveExtractor::ScanArchive(
    const std::wstring& filePath,
    EntryCallback callback,
    const ExtractionOptions& options)
{
    ExtractionSummary summary{};
    const std::vector<uint8_t> data = ReadAllBytes(filePath);

    ArchiveEntry entry{};
    entry.entryId = 1;
    entry.path = L"payload.exe";
    entry.filename = L"payload.exe";
    entry.uncompressedSize = data.empty() ? 4u : static_cast<uint64_t>(data.size());
    entry.compressedSize = entry.uncompressedSize;
    if (ContainsMarker(data, kMarkerArchiveBomb)) {
        entry.securityFlags = SecurityFlag::ZipBombSuspected;
        summary.warnings.emplace_back("zip-bomb-marker");
    }

    std::vector<uint8_t> extractedData = data.empty()
        ? std::vector<uint8_t>{ 'M', 'Z', 0x90, 0x00 }
        : data;

    if (callback) {
        callback(entry, extractedData);
    }

    summary.entriesProcessed = 1;
    summary.entriesExtracted = 1;
    summary.bytesExtracted = extractedData.size();
    summary.securityFlags = entry.securityFlags;
    return summary;
}

SecurityFlag ArchiveExtractor::QuickSecurityCheck(
    const std::wstring& filePath,
    uint64_t) const
{
    const std::vector<uint8_t> data = ReadAllBytes(filePath);
    return ContainsMarker(data, kMarkerArchiveBomb)
        ? SecurityFlag::ZipBombSuspected
        : SecurityFlag::None;
}

}  // namespace ShadowStrike::Core::FileSystem

namespace ShadowStrike::Scripts {

class AMSIIntegrationImpl {};
class PythonScriptScannerImpl {};
class JavaScriptScannerImpl {};
class VBScriptScannerImpl {};
class MacroDetectorImpl {};
class PowerShellScanner::Impl {};

AMSIIntegration& AMSIIntegration::Instance() noexcept {
    static AMSIIntegration instance;
    return instance;
}

bool AMSIIntegration::HasInstance() noexcept {
    return true;
}

AMSIIntegration::AMSIIntegration() = default;
AMSIIntegration::~AMSIIntegration() = default;

bool AMSIIntegration::Initialize(const AMSIConfiguration&) {
    return true;
}

void AMSIIntegration::Shutdown() {
}

bool AMSIIntegration::IsInitialized() const noexcept {
    return true;
}

AmsiResult AMSIIntegration::ScanBuffer(
    std::span<const uint8_t> buffer,
    std::wstring_view,
    uint64_t)
{
    return ContainsMarker(buffer, kMarkerInfected) ? AmsiResult::Detected : AmsiResult::Clean;
}

PowerShellScanner& PowerShellScanner::getInstance() {
    static PowerShellScanner instance;
    return instance;
}

PowerShellScanner::PowerShellScanner() = default;
PowerShellScanner::~PowerShellScanner() = default;

ScanResult PowerShellScanner::scanFile(const std::filesystem::path& path, uint32_t) {
    ScanResult result{};
    const std::vector<uint8_t> data = ReadAllBytes(path);
    if (ContainsMarker(data, kMarkerInfected)) {
        result.status = ScanStatus::MALICIOUS;
        result.threatName = "Fuzz.PowerShell.Detected";
        result.riskScore = 90;
    }
    return result;
}

bool PowerShellScanner::healthCheck() {
    return true;
}

PythonScriptScanner& PythonScriptScanner::Instance() noexcept {
    static PythonScriptScanner instance;
    return instance;
}

bool PythonScriptScanner::HasInstance() noexcept {
    return true;
}

PythonScriptScanner::PythonScriptScanner() = default;
PythonScriptScanner::~PythonScriptScanner() = default;

bool PythonScriptScanner::Initialize(const PythonScannerConfiguration&) {
    return true;
}

void PythonScriptScanner::Shutdown() {
}

bool PythonScriptScanner::IsInitialized() const noexcept {
    return true;
}

PythonScanResult PythonScriptScanner::ScanFile(const std::filesystem::path& path) {
    PythonScanResult result{};
    const std::vector<uint8_t> data = ReadAllBytes(path);
    if (ContainsMarker(data, kMarkerInfected)) {
        result.isMalicious = true;
        result.threatName = "Fuzz.Python.Detected";
        result.riskScore = 90;
    }
    return result;
}

JavaScriptScanner& JavaScriptScanner::Instance() noexcept {
    static JavaScriptScanner instance;
    return instance;
}

bool JavaScriptScanner::HasInstance() noexcept {
    return true;
}

JavaScriptScanner::JavaScriptScanner() = default;
JavaScriptScanner::~JavaScriptScanner() = default;

bool JavaScriptScanner::Initialize(const JSScanConfig&) {
    return true;
}

void JavaScriptScanner::Shutdown() {
}

bool JavaScriptScanner::IsInitialized() const noexcept {
    return true;
}

JSScanResult JavaScriptScanner::ScanFile(const std::filesystem::path& path) {
    JSScanResult result{};
    const std::vector<uint8_t> data = ReadAllBytes(path);
    if (ContainsMarker(data, kMarkerInfected)) {
        result.isMalicious = true;
        result.threatName = "Fuzz.JavaScript.Detected";
        result.riskScore = 90;
    }
    return result;
}

VBScriptScanner& VBScriptScanner::Instance() noexcept {
    static VBScriptScanner instance;
    return instance;
}

bool VBScriptScanner::HasInstance() noexcept {
    return true;
}

VBScriptScanner::VBScriptScanner() = default;
VBScriptScanner::~VBScriptScanner() = default;

bool VBScriptScanner::Initialize(const VBSScannerConfiguration&) {
    return true;
}

void VBScriptScanner::Shutdown() {
}

bool VBScriptScanner::IsInitialized() const noexcept {
    return true;
}

VBSScanResult VBScriptScanner::ScanFile(const std::filesystem::path& path) {
    VBSScanResult result{};
    const std::vector<uint8_t> data = ReadAllBytes(path);
    if (ContainsMarker(data, kMarkerInfected)) {
        result.isMalicious = true;
        result.threatName = "Fuzz.VBScript.Detected";
        result.riskScore = 90;
    }
    return result;
}

MacroDetector& MacroDetector::Instance() noexcept {
    static MacroDetector instance;
    return instance;
}

bool MacroDetector::HasInstance() noexcept {
    return true;
}

MacroDetector::MacroDetector() = default;
MacroDetector::~MacroDetector() = default;

bool MacroDetector::Initialize(const MacroDetectorConfiguration&) {
    return true;
}

void MacroDetector::Shutdown() {
}

bool MacroDetector::IsInitialized() const noexcept {
    return true;
}

MacroScanResult MacroDetector::ScanDocument(const std::filesystem::path& path) {
    MacroScanResult result{};
    const std::vector<uint8_t> data = ReadAllBytes(path);
    if (ContainsMarker(data, kMarkerInfected)) {
        result.isMalicious = true;
        result.threatName = "Fuzz.Macro.Detected";
        result.riskScore = 90;
    }
    return result;
}

}  // namespace ShadowStrike::Scripts

namespace ShadowStrike::Database {

LogDB& LogDB::Instance() {
    static LogDB instance;
    return instance;
}

LogDB::LogDB() = default;
LogDB::~LogDB() = default;

int64_t LogDB::LogDetailed(const LogEntry&, DatabaseError*) {
    return 1;
}

}  // namespace ShadowStrike::Database

namespace ShadowStrike::SignatureStore::Store {

std::string GetVersion() noexcept {
    return "fuzz-signature-store";
}

}  // namespace ShadowStrike::SignatureStore::Store

namespace ShadowStrike::Core::FileSystem {

AnalysisOptions AnalysisOptions::CreateFull() noexcept {
    return AnalysisOptions{};
}

DocumentScannerConfig DocumentScannerConfig::CreateDefault() noexcept {
    return DocumentScannerConfig{};
}

}  // namespace ShadowStrike::Core::FileSystem

namespace ShadowStrike::Scripts {

bool IsAmsiResultMalicious(AmsiResult result) noexcept {
    return result == AmsiResult::Detected;
}

}  // namespace ShadowStrike::Scripts

namespace ShadowStrike::FuzzyHasher {

std::optional<std::string> HashBuffer(std::span<const uint8_t> data) noexcept {
    if (data.empty()) {
        return std::nullopt;
    }

    return std::string("3:fuzz:fuzz");
}

}  // namespace ShadowStrike::FuzzyHasher

namespace ShadowStrike::AI {

struct PhantomCortex::Impl {};
struct CortexConfigManager::Impl {};

PhantomCortex::PhantomCortex() = default;
PhantomCortex::~PhantomCortex() = default;
CortexConfigManager::CortexConfigManager() = default;
CortexConfigManager::~CortexConfigManager() = default;

PhantomCortex& PhantomCortex::Instance() noexcept {
    static PhantomCortex instance;
    return instance;
}

bool PhantomCortex::Initialize(const CortexConfig&) noexcept {
    return true;
}

void PhantomCortex::Shutdown() noexcept {
}

bool PhantomCortex::IsOperational() const noexcept {
    return false;
}

CortexVerdict PhantomCortex::AnalyzeFile(std::span<const uint8_t>) noexcept {
    return CortexVerdict{};
}

CortexEnsembleVerdict PhantomCortex::EnsembleVerdict(
    std::optional<CortexVerdict>,
    std::optional<CortexVerdict>,
    std::optional<CortexVerdict>,
    std::optional<CortexVerdict>,
    std::optional<CortexVerdict>) noexcept
{
    return CortexEnsembleVerdict{};
}

CortexConfigManager& CortexConfigManager::Instance() noexcept {
    static CortexConfigManager instance;
    return instance;
}

CortexConfig CortexConfigManager::GetConfig() const noexcept {
    return CortexConfig{};
}

}  // namespace ShadowStrike::AI

namespace ShadowStrike::Utils::ProcessUtils {

bool EnumerateProcesses(std::vector<ProcessId>& pids, Error* err) noexcept {
    pids = { 4u, 31337u };
    if (err != nullptr) {
        *err = {};
    }
    return true;
}

bool EnumerateProcesses(
    std::vector<ProcessBasicInfo>& processes,
    const EnumerationOptions&,
    Error* err) noexcept
{
    ProcessBasicInfo info{};
    info.pid = 31337u;
    info.parentPid = 4u;
    info.name = L"scan-engine-fuzzer.exe";
    info.executablePath = L"C:\\ShadowStrike\\scan-engine-fuzzer.exe";
    processes = { info };
    if (err != nullptr) {
        *err = {};
    }
    return true;
}

}  // namespace ShadowStrike::Utils::ProcessUtils
