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

#include <cstdint>

namespace ShadowStrike::IoT {

enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Scanning        = 3,
    Monitoring      = 4,
    Assessing       = 5,
    Protected       = 6,
    Vulnerable      = 7,
    Paused          = 8,
    Stopping        = 9,
    Stopped         = 10,
    Error           = 11
};

}  // namespace ShadowStrike::IoT
