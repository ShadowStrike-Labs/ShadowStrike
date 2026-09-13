/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file ModuleCatalog_Tests.cpp
 * @brief The catalog that tells the UI which modules exist, and the invariants it must hold.
 *
 * ModuleCatalog is the single list the Home UI renders from and the IPC layer resolves module ids
 * against. It is static data, which is exactly why it drifts: an entry added by hand can duplicate
 * an id, omit a translation key, or claim a supported-modes mask that contradicts what
 * GetSupportedModesForId reports for the same id, and nothing would notice until a user opened the
 * page.
 *
 * Every case here is relational or structural rather than a count of entries, so adding a genuine
 * new module does not fail the suite. The one exception is asserted as a lower bound, because a
 * catalog that had collapsed to a handful of entries would still satisfy every other property.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "Products/Community/PhantomHome/UI/Shared/ModuleCatalog.hpp"

#include <set>
#include <string>

namespace ShadowStrike::Products::Home::UI::Test {
namespace {

class ModuleCatalogTest : public ::testing::Test {
protected:
    const ModuleCatalog& catalog = ModuleCatalog::Instance();
};

TEST_F(ModuleCatalogTest, TheCatalogIsNotEmpty) {
    // A lower bound, not an exact count: adding a module must not fail this.
    EXPECT_GE(catalog.All().size(), 20u)
        << "the module catalog has collapsed; the Home UI renders from this list";
}

TEST_F(ModuleCatalogTest, EveryIdIsUnique) {
    // A duplicate id makes FindById return whichever entry happens to come first, so one module
    // would silently shadow another in the UI and in every IPC call that resolves by id.
    std::set<std::string> seen;
    for (const auto& entry : catalog.All()) {
        EXPECT_TRUE(seen.insert(entry.id).second)
            << "duplicate catalog id: " << entry.id;
    }
}

TEST_F(ModuleCatalogTest, EveryEntryIsFindableById) {
    // The two access paths must agree. If All() lists an entry FindById cannot resolve, the UI can
    // render a row whose detail page cannot be opened.
    for (const auto& entry : catalog.All()) {
        const auto* found = catalog.FindById(entry.id);
        ASSERT_NE(nullptr, found) << "All() lists an id FindById cannot resolve: " << entry.id;
        EXPECT_EQ(entry.id, found->id);
    }
}

TEST_F(ModuleCatalogTest, AnUnknownIdResolvesToNothing) {
    // Anti-vacuity for the case above: if FindById returned an entry for anything, that test would
    // pass without proving a resolution actually happened.
    EXPECT_EQ(nullptr, catalog.FindById("this-module-id-does-not-exist"));
    EXPECT_EQ(nullptr, catalog.FindById(""));
}

TEST_F(ModuleCatalogTest, EveryEntryCarriesTheStringsTheUiNeeds) {
    // An empty translation key renders as a blank row rather than failing loudly.
    for (const auto& entry : catalog.All()) {
        EXPECT_FALSE(entry.id.empty()) << "an entry has no id";
        EXPECT_FALSE(entry.displayNameKey.empty()) << "no display name key for " << entry.id;
        EXPECT_FALSE(entry.descriptionKey.empty()) << "no description key for " << entry.id;
        EXPECT_FALSE(entry.iconId.empty()) << "no icon id for " << entry.id;
    }
}

TEST_F(ModuleCatalogTest, EveryEntrySupportsAtLeastOneMode) {
    // A mask of zero means the module can be configured into no mode at all, so the UI would offer
    // a control that cannot produce a valid value.
    for (const auto& entry : catalog.All()) {
        EXPECT_NE(0u, entry.supportedModesMask)
            << entry.id << " supports no protection mode";
    }
}

TEST_F(ModuleCatalogTest, TheModesAccessorAgreesWithTheEntry) {
    // GetSupportedModesForId is a free function that, per its own documentation, consults
    // ModuleCatalog FIRST and only falls back to the orchestrator's descriptor for modules the
    // catalog does not list - so for a catalog entry the two must agree.
    // Two APIs report the same fact. If they disagree, the UI enables a mode the orchestrator will
    // refuse, or hides one it would accept.
    for (const auto& entry : catalog.All()) {
        EXPECT_EQ(entry.supportedModesMask, GetSupportedModesForId(entry.id))
            << "supported-modes mask disagrees between All() and GetSupportedModesForId for "
            << entry.id;
    }
}

TEST_F(ModuleCatalogTest, TheCategoriesPartitionTheCatalog) {
    // Every entry must appear under exactly one category, or a module is either invisible in the UI
    // or listed twice.
    std::size_t summed = 0;
    for (std::uint8_t c = 0; c <= static_cast<std::uint8_t>(ModuleCategory::SpecializedProtection);
         ++c) {
        summed += catalog.ByCategory(static_cast<ModuleCategory>(c)).size();
    }
    EXPECT_EQ(catalog.All().size(), summed)
        << "the per-category views do not partition the catalog, so a module is missing from the "
           "UI or appears in two categories";
}

TEST_F(ModuleCatalogTest, EveryCategoryViewReturnsOnlyThatCategory) {
    for (std::uint8_t c = 0; c <= static_cast<std::uint8_t>(ModuleCategory::SpecializedProtection);
         ++c) {
        const auto cat = static_cast<ModuleCategory>(c);
        for (const auto* entry : catalog.ByCategory(cat)) {
            ASSERT_NE(nullptr, entry);
            EXPECT_EQ(cat, entry->category)
                << entry->id << " is returned by the wrong category view";
        }
    }
}

// A uniqueness test for detailPage was written here and REMOVED after it failed: several modules
// legitimately share one detail page, because a category page such as Privacy hosts the webcam,
// microphone, location and cookie modules together. Asserting uniqueness would have been asserting
// an invariant the design does not hold, so it is recorded here rather than left as a broken test.

}  // namespace
}  // namespace ShadowStrike::Products::Home::UI::Test
