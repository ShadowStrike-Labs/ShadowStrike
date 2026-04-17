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

class DeviceExceptionsImpl;

class DeviceExceptions final {
public:
    [[nodiscard]] static DeviceExceptions& Instance();

    [[nodiscard]] bool Initialize(const std::wstring& databasePath = L"");
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const;

    [[nodiscard]] bool UpsertException(const DeviceExceptionEntry& entry);
    [[nodiscard]] bool RemoveException(std::string_view exceptionId);
    [[nodiscard]] std::optional<DeviceExceptionEntry> GetException(std::string_view exceptionId) const;
    [[nodiscard]] std::vector<DeviceExceptionEntry> ListExceptions() const;
    [[nodiscard]] std::optional<DeviceExceptionMatch> MatchException(
        const DeviceInfo& device,
        std::string_view userName,
        DeviceTimestamp when) const;

private:
    DeviceExceptions();
    ~DeviceExceptions();

    DeviceExceptions(const DeviceExceptions&) = delete;
    DeviceExceptions& operator=(const DeviceExceptions&) = delete;
    DeviceExceptions(DeviceExceptions&&) = delete;
    DeviceExceptions& operator=(DeviceExceptions&&) = delete;

    std::unique_ptr<DeviceExceptionsImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::DeviceControl
