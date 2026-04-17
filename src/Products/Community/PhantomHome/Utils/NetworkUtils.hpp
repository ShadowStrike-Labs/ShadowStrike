/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
// Redirect header: PhantomHome submodules use "../Utils/NetworkUtils.hpp"
// relative to their subdirectory. Forwards to the canonical PhantomCore
// implementation, resolved via the /I src include root.
#pragma once
#include "PhantomCore/Utils/NetworkUtils.hpp"
