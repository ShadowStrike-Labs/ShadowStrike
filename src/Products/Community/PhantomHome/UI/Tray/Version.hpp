/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Version.hpp — Compile-time version string for the Phantom tray process.
 *
 * TODO(packaging): replace kVersion with a value injected by the build
 * pipeline (CMake configure_file / MSBuild property) so it matches the
 * installer version.  Cross-reference: packaging\version.props.
 */
#pragma once

namespace ShadowStrike::PhantomHome::Tray::Version {

inline constexpr wchar_t kVersion[] = L"1.0.0-dev";

} // namespace ShadowStrike::PhantomHome::Tray::Version
