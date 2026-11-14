// ============================================================================
// EmulatorBuiltinPatterns_Tests.cpp
//
// The emulator's built-in pattern for a reflective-DLL loader is stored encoded
// so the shipped binary carries no plain copy of the export name (task 385: with
// the WS2_32.dll import, a plain copy makes the service executable match the
// shipped YARA rule SIGNATURE_BASE_HKTL_Meterpreter_Inmemory). These tests pin
// that the decoded pattern still finds the bytes it always looked for.
// ============================================================================
#include "pch.h"
#include <gtest/gtest.h>
#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>
#include "../../../PhantomEmulator/Integration/YaraScanner.hpp"

namespace {

bool HasRule(const std::vector<Phantom::YaraMatch>& matches, const std::string& rule) {
    return std::any_of(matches.begin(), matches.end(),
                       [&rule](const Phantom::YaraMatch& m) { return m.ruleName == rule; });
}

std::vector<std::uint8_t> Bytes(const std::string& s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

}  // namespace

TEST(EmulatorBuiltinPatternTest, TheReflectiveLoaderExportNameStillMatches) {
    Phantom::YaraScanner scanner;
    (void)scanner.Initialize();  // built-in patterns load whether or not libyara does
    const auto buffer = Bytes(std::string("junk ") + "Reflective" + "Loader" + " tail");
    EXPECT_TRUE(HasRule(scanner.ScanWithBuiltinRules(buffer), "ReflectiveDLL_Loader"));
}

TEST(EmulatorBuiltinPatternTest, ANearMissDoesNotMatch) {
    Phantom::YaraScanner scanner;
    (void)scanner.Initialize();
    const auto buffer = Bytes(std::string("Reflective") + "Loadex and reflectiveloader");
    EXPECT_FALSE(HasRule(scanner.ScanWithBuiltinRules(buffer), "ReflectiveDLL_Loader"));
}
