/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * main.cpp — Phantom tray-process entry point.
 *
 * Sole responsibility: wWinMain → TrayApp::Instance().Run().
 * All logic lives in TrayApp.cpp; this file is intentionally minimal.
 */
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>

#include "TrayApp.hpp"

int APIENTRY wWinMain(
    HINSTANCE hInstance,
    HINSTANCE /*hPrev*/,
    LPWSTR    /*cmdLine*/,
    int       /*nShow*/)
{
    return ShadowStrike::PhantomHome::Tray::TrayApp::Instance().Run(hInstance);
}
