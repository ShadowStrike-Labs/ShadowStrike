/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
// Redirect header: PhantomHome submodules use "../SignatureStore/SignatureStore.hpp" relative to their
// subdirectory. Forwards to the canonical PhantomCore implementation.
#pragma once
#include "PhantomCore/SignatureStore/SignatureStore.hpp"
