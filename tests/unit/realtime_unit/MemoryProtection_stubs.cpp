/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Test-harness shims for MemoryProtection unit tests.
 *
 * These definitions isolate deterministic MemoryProtection contracts from
 * communication, behavior-analysis, and process-monitor integrations that are
 * not exercised by the unit tests in this folder.
 */

#include "pch.h"

#include <new>

#include "../../../src/Shared_modules/Communication/AlertSystem.hpp"
#include "../../../src/Shared_modules/Communication/TelemetryCollector.hpp"
#include "../../../src/Shared_modules/Communication/IPCManager.hpp"
#include "../../../src/Shared_modules/Core/Engine/BehaviorAnalyzer.hpp"
#include "../../../src/Shared_modules/RealTime/ProcessCreationMonitor.hpp"

namespace ShadowStrike {

namespace Communication {

AlertSystem& AlertSystem::Instance() noexcept {
    alignas(AlertSystem) static unsigned char storage[sizeof(AlertSystem)]{};
    return *std::launder(reinterpret_cast<AlertSystem*>(storage));
}

std::string AlertSystem::RaiseAlert(
    AlertSeverity /*severity*/,
    AlertType /*type*/,
    const std::string& /*subject*/,
    const std::string& /*details*/,
    const std::string& /*source*/)
{
    return {};
}

TelemetryCollector& TelemetryCollector::Instance() noexcept {
    alignas(TelemetryCollector) static unsigned char storage[sizeof(TelemetryCollector)]{};
    return *std::launder(reinterpret_cast<TelemetryCollector*>(storage));
}

void TelemetryCollector::RecordDetection(const DetectionEventData& /*detection*/) {
}

IPCManager& IPCManager::Instance() noexcept {
    alignas(IPCManager) static unsigned char storage[sizeof(IPCManager)]{};
    return *std::launder(reinterpret_cast<IPCManager*>(storage));
}

}  // namespace Communication

namespace Core::Engine {

BehaviorAnalyzer& BehaviorAnalyzer::Instance() {
    alignas(BehaviorAnalyzer) static unsigned char storage[sizeof(BehaviorAnalyzer)]{};
    return *std::launder(reinterpret_cast<BehaviorAnalyzer*>(storage));
}

bool BehaviorAnalyzer::ProcessEventAsync(BehaviorEvent /*event*/) {
    return true;
}

}  // namespace Core::Engine

namespace RealTime {

ProcessCreationMonitor& ProcessCreationMonitor::Instance() {
    alignas(ProcessCreationMonitor) static unsigned char storage[sizeof(ProcessCreationMonitor)]{};
    return *std::launder(reinterpret_cast<ProcessCreationMonitor*>(storage));
}

uint64_t ProcessCreationMonitor::RegisterTerminateCallback(ProcessTerminateCallback /*callback*/) {
    return 1;
}

bool ProcessCreationMonitor::UnregisterTerminateCallback(uint64_t callbackId) {
    return callbackId != 0;
}

}  // namespace RealTime

}  // namespace ShadowStrike
