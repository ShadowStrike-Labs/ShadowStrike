#include "pch.h"

#include <new>

#include "../../../src/PhantomCore/AI/PhantomCortex.hpp"
#include "../../../src/PhantomCore/Core/Engine/BehaviorAnalyzer.hpp"
#include "../../../src/PhantomCore/Core/Engine/ScanEngine.hpp"
#include "../../../src/PhantomCore/HashStore/HashStore.hpp"
#include "../../../src/PhantomCore/SelfProtection/DigitalSignatureValidator.hpp"
#include "../../../src/PhantomCore/Whitelist/WhiteListStore.hpp"

namespace ShadowStrike::HashStore {

std::optional<SignatureStore::DetectionResult> HashStore::LookupHashString(
    const std::string& /*hashStr*/,
    SignatureStore::HashType /*type*/) const noexcept
{
    return std::nullopt;
}

}  // namespace ShadowStrike::HashStore

namespace ShadowStrike::Whitelist {

LookupResult WhitelistStore::IsWhitelisted(
    std::wstring_view /*filePath*/,
    const HashValue* /*fileHash*/,
    const std::array<uint8_t, 32>* /*certThumbprint*/,
    std::wstring_view /*publisher*/,
    const QueryOptions& /*options*/) const noexcept
{
    return LookupResult{};
}

}  // namespace ShadowStrike::Whitelist

namespace ShadowStrike::Core::Engine {

EngineResult ScanEngine::QuickScanFile(const std::wstring& /*filePath*/) {
    return EngineResult{};
}

const char* BehaviorPatternTypeToString(BehaviorPatternType /*pattern*/) noexcept {
    return "Unknown";
}

bool BehaviorAnalyzer::IsInitialized() const noexcept {
    return false;
}

std::optional<BehaviorVerdict> BehaviorAnalyzer::ProcessEvent(const BehaviorEvent& /*event*/) {
    return std::nullopt;
}

BehaviorEvent CreateProcessEvent(
    BehaviorEventType type,
    uint32_t sourceProcessId,
    uint32_t targetProcessId) noexcept
{
    BehaviorEvent event{};
    event.eventType = type;
    event.processId = sourceProcessId;
    event.targetProcessId = targetProcessId;
    return event;
}

}  // namespace ShadowStrike::Core::Engine

namespace ShadowStrike::Security {

DigitalSignatureValidator& DigitalSignatureValidator::Instance() noexcept {
    alignas(DigitalSignatureValidator) static unsigned char storage[sizeof(DigitalSignatureValidator)]{};
    return *std::launder(reinterpret_cast<DigitalSignatureValidator*>(storage));
}

SignatureAnalysisResult DigitalSignatureValidator::ValidateProcessImage(
    uint32_t /*processId*/,
    uint32_t /*parentProcessId*/,
    std::wstring_view /*imagePath*/)
{
    return SignatureAnalysisResult{};
}

}  // namespace ShadowStrike::Security

namespace ShadowStrike::AI {

PhantomCortex& PhantomCortex::Instance() noexcept {
    alignas(PhantomCortex) static unsigned char storage[sizeof(PhantomCortex)]{};
    return *std::launder(reinterpret_cast<PhantomCortex*>(storage));
}

bool PhantomCortex::IsOperational() const noexcept {
    return false;
}

CortexVerdict PhantomCortex::AnalyzeFile(std::span<const uint8_t> /*fileBytes*/) noexcept {
    return CortexVerdict{};
}

}  // namespace ShadowStrike::AI
