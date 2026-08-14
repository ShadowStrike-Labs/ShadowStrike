#include "../../../src/pch.h"
#include <gtest/gtest.h>

#ifdef SHADOWSTRIKE_SELFPROTECTION_TEST_SHIMS

#include "../../../src/PhantomCore/Communication/AlertSystem.hpp"
#include "../../../src/PhantomCore/Communication/TelemetryCollector.hpp"
#include "../../../src/PhantomCore/Communication/IPCManager.hpp"

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

std::string AlertSystem::RaiseAlert(
    AlertSeverity,
    AlertType,
    const std::string&,
    const std::string&,
    const std::string&) {
    return "selfprotection-test-alert";
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

void IPCManager::RegisterRegistryHandler(RegistryOpCallback) {
}

void IPCManager::RegisterGenericHandler(GenericMessageCallback) {
}

}  // namespace ShadowStrike::Communication

#endif
