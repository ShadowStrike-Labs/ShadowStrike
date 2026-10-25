/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file PasswordFieldIdentity_Tests.cpp
 * @brief What counts as a password field for secure-input and screenshot protection (task 308).
 *
 * ES_PASSWORD is 0x20, a class-specific style bit. On a Button the same bit is BS_LEFTTEXT, so a
 * checkbox with its text on the left was reported as a password field and given secure-input
 * protection, spending protected-window slots that real password fields then could not get. These
 * cases create real windows in the test process, so the answer comes from the window manager.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/Banking/KeyloggerProtection.hpp"

namespace {

using ShadowStrike::Banking::IsPasswordCapableEditClass;
using ShadowStrike::Banking::IsPasswordField;

/// A hidden control destroyed at scope exit.
class ScopedControl {
public:
    ScopedControl(const wchar_t* cls, DWORD style)
        : m_hwnd(::CreateWindowExW(0, cls, L"", WS_POPUP | style, 0, 0, 10, 10, nullptr, nullptr,
                                   ::GetModuleHandleW(nullptr), nullptr)) {}
    ~ScopedControl() {
        if (m_hwnd) ::DestroyWindow(m_hwnd);
    }
    ScopedControl(const ScopedControl&) = delete;
    ScopedControl& operator=(const ScopedControl&) = delete;
    [[nodiscard]] uint64_t Handle() const noexcept { return reinterpret_cast<uint64_t>(m_hwnd); }
    [[nodiscard]] bool Created() const noexcept { return m_hwnd != nullptr; }

private:
    HWND m_hwnd;
};

TEST(PasswordFieldIdentity, OnlyAnEditWithThePasswordStyleIsAPasswordField) {
    ScopedControl password(L"Edit", ES_PASSWORD);
    ScopedControl plain(L"Edit", 0);
    ScopedControl leftTextCheckbox(L"Button", BS_AUTOCHECKBOX | BS_LEFTTEXT);
    ASSERT_TRUE(password.Created() && plain.Created() && leftTextCheckbox.Created());
    ASSERT_EQ(static_cast<LONG_PTR>(ES_PASSWORD), static_cast<LONG_PTR>(BS_LEFTTEXT))
        << "the premise: the two styles share a bit";

    EXPECT_TRUE(IsPasswordField(password.Handle()));
    EXPECT_FALSE(IsPasswordField(plain.Handle()));
    EXPECT_FALSE(IsPasswordField(leftTextCheckbox.Handle()))
        << "BS_LEFTTEXT is the same bit as ES_PASSWORD and was read as one";
    EXPECT_FALSE(IsPasswordField(0));
}

TEST(PasswordFieldIdentity, TheEditFamilyIsMatchedByWholeClassName) {
    EXPECT_TRUE(IsPasswordCapableEditClass(L"Edit"));
    EXPECT_TRUE(IsPasswordCapableEditClass(L"EDIT"));
    EXPECT_TRUE(IsPasswordCapableEditClass(L"RichEdit20W"));
    EXPECT_TRUE(IsPasswordCapableEditClass(L"RICHEDIT50W"));
    EXPECT_FALSE(IsPasswordCapableEditClass(L"Button"));
    EXPECT_FALSE(IsPasswordCapableEditClass(L"Edit2"));
    EXPECT_FALSE(IsPasswordCapableEditClass(L"MyEdit"));
    EXPECT_FALSE(IsPasswordCapableEditClass(L"RichEdit"));
    EXPECT_FALSE(IsPasswordCapableEditClass(L""));
}

}  // namespace
