/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file NabWiring.hpp
 * @brief Forward-declaration of the keep-alive symbol emitted by NabWiring.cpp.
 *
 * WiringAnchor.cpp references PhantomHome_KeepAlive_NetworkAttackBlocker to
 * prevent MSVC /OPT:REF + LTCG from eliding the NabWiring translation unit.
 */

#pragma once

extern "C" void PhantomHome_KeepAlive_NetworkAttackBlocker() noexcept;
