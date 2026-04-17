/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
#pragma once

#include "Products/Community/PhantomEDR/DeviceControl/DeviceControlTypes.hpp"

#include <memory>
#include <optional>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::DeviceControl {

class DevicePolicyEngineImpl;

class DevicePolicyEngine final {
public:
    [[nodiscard]] static DevicePolicyEngine& Instance();
    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const;

    [[nodiscard]] bool ReloadPolicies();
    [[nodiscard]] bool UpsertPolicy(const DevicePolicy& policy);
    [[nodiscard]] bool RemovePolicy(std::string_view policyId);
    [[nodiscard]] std::vector<DevicePolicy> ListPolicies() const;

    [[nodiscard]] DevicePolicyDecision EvaluateDevice(
        const DeviceInfo& device,
        std::string_view userName = {}) const;

    [[nodiscard]] bool HandleDeviceEvent(const DeviceEvent& event);
    [[nodiscard]] bool RefreshConnectedDevices();
    [[nodiscard]] std::vector<DeviceInfo> GetConnectedDevices() const;
    [[nodiscard]] std::optional<DeviceInfo> GetConnectedDevice(std::string_view instanceId) const;

private:
    DevicePolicyEngine();
    ~DevicePolicyEngine();
    DevicePolicyEngine(const DevicePolicyEngine&) = delete;
    DevicePolicyEngine& operator=(const DevicePolicyEngine&) = delete;
    DevicePolicyEngine(DevicePolicyEngine&&) = delete;
    DevicePolicyEngine& operator=(DevicePolicyEngine&&) = delete;

    std::unique_ptr<DevicePolicyEngineImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::DeviceControl
