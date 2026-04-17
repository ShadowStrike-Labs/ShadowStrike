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

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::DeviceControl {

using DeviceTimestamp = std::chrono::system_clock::time_point;

enum class DeviceType : uint8_t {
    Unknown = 0,
    UsbMassStorage = 1,
    UsbHid = 2,
    Bluetooth = 3,
    Thunderbolt = 4,
    UsbNetwork = 5,
    UsbPrinter = 6,
    UsbHub = 7,
    UsbComposite = 8,
    Imaging = 9,
    SmartCard = 10,
    AudioVideo = 11,
    WirelessAdapter = 12,
    VendorSpecific = 13
};

enum class DevicePolicyAction : uint8_t {
    Allow = 0,
    Block = 1,
    ReadOnly = 2,
    AuditOnly = 3
};

enum class DeviceEventKind : uint8_t {
    Connected = 0,
    Disconnected = 1,
    PolicyEvaluated = 2,
    PolicyBlocked = 3,
    PolicyReadOnly = 4,
    Audited = 5
};

enum class DeviceExceptionType : uint8_t {
    DeviceSerial = 0,
    User = 1,
    TimeWindow = 2
};

struct DeviceInfo final {
    DeviceType type = DeviceType::Unknown;
    std::wstring instanceId;
    std::wstring interfacePath;
    std::string vendorId;
    std::string productId;
    std::string serialNumber;
    std::string description;
    std::string manufacturer;
    std::string className;
    std::string hardwareId;
    bool present = true;
    bool removable = false;
    bool usbBus = false;
    bool bluetoothBus = false;
    bool thunderboltBus = false;
};

struct DevicePolicy final {
    std::string policyId;
    std::string name;
    std::string description;
    DeviceType deviceType = DeviceType::Unknown;
    DevicePolicyAction action = DevicePolicyAction::Allow;
    bool enabled = true;
    int32_t priority = 100;
    std::optional<std::string> vendorId;
    std::optional<std::string> productId;
    std::optional<std::string> serialNumber;
    std::optional<std::string> descriptionPattern;
    std::optional<std::string> manufacturerPattern;
    std::optional<std::string> userName;
};

struct DevicePolicyDecision final {
    DevicePolicyAction action = DevicePolicyAction::Allow;
    std::string matchedPolicyId;
    std::string matchedExceptionId;
    std::string reason;
    bool exceptionApplied = false;
    bool enforcementApplied = false;
};

struct DeviceEvent final {
    int64_t eventId = 0;
    DeviceTimestamp timestamp{};
    DeviceEventKind eventKind = DeviceEventKind::Connected;
    DeviceInfo device;
    DevicePolicyAction actionTaken = DevicePolicyAction::Allow;
    std::string userName;
    std::string hostName;
    std::string reason;
};

struct DeviceEventQuery final {
    std::optional<DeviceTimestamp> startTime;
    std::optional<DeviceTimestamp> endTime;
    std::optional<DeviceType> deviceType;
    std::optional<DevicePolicyAction> actionTaken;
    uint32_t limit = 1000;
};

struct DeviceExceptionEntry final {
    std::string exceptionId;
    std::string name;
    DeviceExceptionType type = DeviceExceptionType::DeviceSerial;
    DeviceType deviceType = DeviceType::Unknown;
    bool enabled = true;
    std::optional<std::string> serialNumber;
    std::optional<std::string> userName;
    std::optional<uint16_t> startMinuteOfDay;
    std::optional<uint16_t> endMinuteOfDay;
    uint8_t daysOfWeekMask = 0x7F;
    std::optional<DeviceTimestamp> validFrom;
    std::optional<DeviceTimestamp> validUntil;
    DevicePolicyAction overrideAction = DevicePolicyAction::Allow;
    std::string notes;
};

struct DeviceExceptionMatch final {
    DeviceExceptionEntry exception;
    DevicePolicyAction effectiveAction = DevicePolicyAction::Allow;
    std::string reason;
};

[[nodiscard]] constexpr bool IsRestrictiveAction(const DevicePolicyAction action) noexcept
{
    return action == DevicePolicyAction::Block || action == DevicePolicyAction::ReadOnly;
}

} // namespace ShadowStrike::Products::PhantomEDR::DeviceControl
