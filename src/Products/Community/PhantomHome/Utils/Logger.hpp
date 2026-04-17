/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
// Redirect: PhantomHome modules use "../Utils/Logger.hpp" relative to their
// subdirectories. This header satisfies that include path and forwards to the
// canonical PhantomCore logger, found via /I src.
#pragma once
#include "PhantomCore/Utils/Logger.hpp"
