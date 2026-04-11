#include "../../../src/pch.h"

#include "../../../src/Shared_modules/Communication/AlertSystem.hpp"
#include "../../../src/Shared_modules/Communication/TelemetryCollector.hpp"
#include "../../../src/Shared_modules/Communication/IPCManager.hpp"
#include "../../../src/Shared_modules/Core/Process/ProcessKiller.hpp"
#include "../../../src/Shared_modules/Utils/ProcessUtils.hpp"

namespace ShadowStrike::Communication {

class AlertSystemImpl {};
class TelemetryCollectorImpl {};
class IPCManagerImpl {};
class FilterConnection {};
class ThreatIntelPusher {};

AlertSystem::AlertSystem() = default;
AlertSystem::~AlertSystem() = default;

AlertSystem& AlertSystem::Instance() noexcept {
    static AlertSystem instance;
    return instance;
}

bool AlertSystem::HasInstance() noexcept {
    return true;
}

bool AlertSystem::IsInitialized() const noexcept {
    return true;
}

std::string AlertSystem::RaiseAlert(const Alert&) {
    return "ransomware-test-alert";
}

std::string AlertSystem::RaiseAlert(
    AlertSeverity,
    AlertType,
    const std::string&,
    const std::string&,
    const std::string&) {
    return "ransomware-test-alert";
}

TelemetryCollector::TelemetryCollector() = default;
TelemetryCollector::~TelemetryCollector() = default;

TelemetryCollector& TelemetryCollector::Instance() noexcept {
    static TelemetryCollector instance;
    return instance;
}

bool TelemetryCollector::HasInstance() noexcept {
    return true;
}

void TelemetryCollector::RecordCustom(
    const std::string&,
    const std::map<std::string, std::string>&) {
}

IPCManager::IPCManager() = default;
IPCManager::~IPCManager() = default;

IPCManager& IPCManager::Instance() noexcept {
    static IPCManager instance;
    return instance;
}

bool IPCManager::HasInstance() noexcept {
    return true;
}

bool IPCManager::IsFilterPortConnected() const noexcept {
    return false;
}

bool IPCManager::SendToKernel(
    const void*,
    size_t,
    void*,
    size_t* replySize,
    uint32_t) {
    if (replySize != nullptr) {
        *replySize = 0;
    }
    return false;
}

}  // namespace ShadowStrike::Communication

namespace ShadowStrike::Core::Process {

class ProcessKillerImpl {};

ProcessKiller::ProcessKiller() = default;
ProcessKiller::~ProcessKiller() = default;

KillResult ProcessKiller::TerminateTree(uint32_t) {
    return KillResult::AlreadyDead;
}

}  // namespace ShadowStrike::Core::Process

namespace ShadowStrike::Utils::ProcessUtils {

std::optional<std::wstring> GetProcessName(ProcessId, Error*) noexcept {
    return L"ransomware-test-process.exe";
}

}  // namespace ShadowStrike::Utils::ProcessUtils
