/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file AmsiWiring.hpp
 * @brief Forward-declaration of the keep-alive symbol emitted by AmsiWiring.cpp.
 *
 * WiringAnchor.cpp takes the address of PhantomHome_KeepAlive_AmsiProvider to
 * prevent MSVC /OPT:REF + LTCG from eliding the AmsiWiring translation unit
 * (and its static registrar) in Release builds.
 */

#pragma once

extern "C" void PhantomHome_KeepAlive_AmsiProvider() noexcept;
