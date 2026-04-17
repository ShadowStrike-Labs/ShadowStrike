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
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::DeviceControl {

class DeviceAuditLogImpl;

class DeviceAuditLog final {
public:
    [[nodiscard]] static DeviceAuditLog& Instance();

    [[nodiscard]] bool Initialize(const std::wstring& databasePath = L"", uint32_t retentionDays = 90);
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const;

    [[nodiscard]] bool RecordEvent(const DeviceEvent& event);
    [[nodiscard]] std::vector<DeviceEvent> QueryEvents(const DeviceEventQuery& query) const;
    [[nodiscard]] uint64_t PurgeExpiredEvents();
    [[nodiscard]] bool SetRetentionDays(uint32_t retentionDays);
    [[nodiscard]] uint32_t GetRetentionDays() const;

private:
    DeviceAuditLog();
    ~DeviceAuditLog();

    DeviceAuditLog(const DeviceAuditLog&) = delete;
    DeviceAuditLog& operator=(const DeviceAuditLog&) = delete;
    DeviceAuditLog(DeviceAuditLog&&) = delete;
    DeviceAuditLog& operator=(DeviceAuditLog&&) = delete;

    std::unique_ptr<DeviceAuditLogImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::DeviceControl
