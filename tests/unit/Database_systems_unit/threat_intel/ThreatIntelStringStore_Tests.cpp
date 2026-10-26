// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * ShadowStrike Phantom - Threat-intel string store and string-valued indicator tests
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 */

/**
 * @file ThreatIntelStringStore_Tests.cpp
 * @brief Pins the text store behind Domain, URL and Email indicators, and what the store answers with it.
 *
 * Before the string store (task 345) a domain indicator was stored as (offset 0, length) and matched by
 * that pair, so a looked-up domain matched ANY stored domain of the same length and took its reputation;
 * a second same-length domain was refused as a duplicate of the first. The store cases below use
 * same-length texts on purpose: they are the inputs the old comparison could not tell apart.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "PhantomCore/ThreatIntel/ThreatIntelDatabase.hpp"
#include "PhantomCore/ThreatIntel/ThreatIntelIOCManager.hpp"
#include "PhantomCore/ThreatIntel/ThreatIntelIndex.hpp"
#include "PhantomCore/ThreatIntel/ThreatIntelStore.hpp"
#include "PhantomCore/ThreatIntel/ThreatIntelStringStore.hpp"

#include <atomic>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

using namespace ShadowStrike::ThreatIntel;

class ScratchFolder {
public:
    ScratchFolder() {
        static std::atomic<uint32_t> s_seq{0};
        path = std::filesystem::temp_directory_path() /
               ("ss_tistr_" + std::to_string(::GetCurrentProcessId()) + "_" + std::to_string(s_seq.fetch_add(1)));
        std::filesystem::create_directories(path);
    }
    ~ScratchFolder() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
    std::filesystem::path path;
};

uintmax_t FileSize(const std::filesystem::path& p) {
    std::error_code ec;
    const auto size = std::filesystem::file_size(p, ec);
    return ec ? 0 : size;
}

// ============================================================================
// ThreatIntelStringStore
// ============================================================================

TEST(ThreatIntelStringStore, InterningGivesEachTextExactlyOneReference) {
    ScratchFolder dir;
    ThreatIntelStringStore store;
    ASSERT_TRUE(store.Open((dir.path / "s.strings").wstring(), false));

    const auto evil = store.Intern("evil-one.example");
    const auto again = store.Intern("evil-one.example");
    const auto other = store.Intern("good-two.example");  // same length
    ASSERT_TRUE(evil && again && other);
    EXPECT_EQ(evil->offset, again->offset);
    EXPECT_EQ(evil->length, again->length);
    EXPECT_NE(evil->offset, other->offset) << "two texts of one length share a reference";
    EXPECT_GE(evil->offset, ThreatIntelStringStore::kFirstOffset) << "offset 0 must keep meaning 'no text'";
    EXPECT_EQ(store.Get(evil->offset, evil->length), "evil-one.example");
    EXPECT_EQ(store.Get(other->offset, other->length), "good-two.example");
    EXPECT_EQ(store.StringCount(), 2u);
    EXPECT_FALSE(store.Find("safe-one.example").has_value());
}

TEST(ThreatIntelStringStore, OnlyAnExactRecordIsAValidReference) {
    ScratchFolder dir;
    ThreatIntelStringStore store;
    ASSERT_TRUE(store.Open((dir.path / "s.strings").wstring(), false));
    const auto ref = store.Intern("malware.example");
    ASSERT_TRUE(ref);
    EXPECT_TRUE(store.IsValidRef(ref->offset, ref->length));
    EXPECT_FALSE(store.IsValidRef(0, ref->length));
    EXPECT_FALSE(store.IsValidRef(ref->offset + 1, ref->length - 1)) << "a reference inside a text is not a text";
    EXPECT_FALSE(store.IsValidRef(ref->offset, ref->length - 1));
    EXPECT_TRUE(store.Get(ref->offset + 1, ref->length - 1).empty());
    EXPECT_TRUE(store.Get(0, 8).empty());
}

TEST(ThreatIntelStringStore, TextsSurviveReopenWithTheSameReferences) {
    ScratchFolder dir;
    const auto file = (dir.path / "s.strings").wstring();
    InternedString first{}, second{};
    {
        ThreatIntelStringStore store;
        ASSERT_TRUE(store.Open(file, false));
        first = *store.Intern("https://evil.example/payload");
        second = *store.Intern("phish@evil.example");
    }
    ThreatIntelStringStore store;
    ASSERT_TRUE(store.Open(file, false));
    EXPECT_EQ(store.StringCount(), 2u);
    const auto found = store.Find("https://evil.example/payload");
    ASSERT_TRUE(found);
    EXPECT_EQ(found->offset, first.offset);
    EXPECT_EQ(store.Get(second.offset, second.length), "phish@evil.example");
}

TEST(ThreatIntelStringStore, AnIncompleteLastRecordIsDroppedAndAppendingResumesOnABoundary) {
    ScratchFolder dir;
    const auto file = dir.path / "s.strings";
    {
        ThreatIntelStringStore store;
        ASSERT_TRUE(store.Open(file.wstring(), false));
        ASSERT_TRUE(store.Intern("one.example"));
        ASSERT_TRUE(store.Intern("two.example"));
    }
    const auto complete = FileSize(file);
    {
        std::ofstream tail(file, std::ios::binary | std::ios::app);
        const char partial[] = {'\x20', '\x00', 'x'};  // length 32, then one byte of text: a crash mid-write
        tail.write(partial, sizeof(partial));
    }
    {
        ThreatIntelStringStore store;
        ASSERT_TRUE(store.Open(file.wstring(), false));
        EXPECT_EQ(store.StringCount(), 2u);
        EXPECT_EQ(store.TruncatedTailBytes(), 3u);
        EXPECT_EQ(FileSize(file), complete) << "the partial record was not cut off";
        ASSERT_TRUE(store.Intern("three.example"));
    }
    ThreatIntelStringStore store;
    ASSERT_TRUE(store.Open(file.wstring(), false));
    EXPECT_EQ(store.StringCount(), 3u);
    EXPECT_TRUE(store.Find("three.example").has_value());
    EXPECT_EQ(store.TruncatedTailBytes(), 0u);
}

TEST(ThreatIntelStringStore, AnUnreadableFileIsMovedAsideNotOverwritten) {
    ScratchFolder dir;
    const auto file = dir.path / "s.strings";
    {
        std::ofstream junk(file, std::ios::binary);
        junk << "not a string store at all";
    }
    ThreatIntelStringStore store;
    ASSERT_TRUE(store.Open(file.wstring(), false));
    EXPECT_TRUE(store.ReplacedUnreadableFile());
    EXPECT_EQ(store.StringCount(), 0u);
    EXPECT_TRUE(store.Intern("fresh.example"));
    size_t aside = 0;
    for (const auto& item : std::filesystem::directory_iterator(dir.path)) {
        aside += item.path().filename().wstring().find(L".unreadable-") != std::wstring::npos ? 1 : 0;
    }
    EXPECT_EQ(aside, 1u) << "the unreadable bytes were not kept for diagnosis";
}

TEST(ThreatIntelStringStore, AReadOnlyStoreNeverWrites) {
    ScratchFolder dir;
    const auto file = dir.path / "s.strings";
    {
        ThreatIntelStringStore missing;
        ASSERT_TRUE(missing.Open(file.wstring(), true));
        EXPECT_FALSE(missing.Intern("x.example").has_value());
    }
    EXPECT_FALSE(std::filesystem::exists(file)) << "a read-only open created the file";
    {
        ThreatIntelStringStore writer;
        ASSERT_TRUE(writer.Open(file.wstring(), false));
        ASSERT_TRUE(writer.Intern("known.example"));
    }
    const auto size = FileSize(file);
    ThreatIntelStringStore reader;
    ASSERT_TRUE(reader.Open(file.wstring(), true));
    EXPECT_TRUE(reader.Find("known.example").has_value());
    EXPECT_TRUE(reader.Intern("known.example").has_value()) << "an existing text is still found";
    EXPECT_FALSE(reader.Intern("new.example").has_value());
    EXPECT_EQ(FileSize(file), size);
}

TEST(ThreatIntelStringStore, EmptyAndOversizedTextsAreRefused) {
    ScratchFolder dir;
    ThreatIntelStringStore store;
    ASSERT_TRUE(store.Open((dir.path / "s.strings").wstring(), false));
    EXPECT_FALSE(store.Intern("").has_value());
    EXPECT_FALSE(store.Intern(std::string(ThreatIntelStringStore::kMaxStringLength + 1, 'a')).has_value());
    EXPECT_TRUE(store.Intern(std::string(ThreatIntelStringStore::kMaxStringLength, 'a')).has_value());
}

TEST(ThreatIntelStringStore, AReturnedTextStaysValidWhileTheStoreGrows) {
    ScratchFolder dir;
    ThreatIntelStringStore store;
    ASSERT_TRUE(store.Open((dir.path / "s.strings").wstring(), false));
    const auto ref = store.Intern("first.example");
    ASSERT_TRUE(ref);
    const std::string_view view = store.Get(ref->offset, ref->length);
    for (int i = 0; i < 3000; ++i) {  // about 3 MB: several chunks
        ASSERT_TRUE(store.Intern("filler-" + std::to_string(i) + std::string(1000, 'z')));
    }
    EXPECT_EQ(view, "first.example") << "text moved while a reader held it";
}

// ============================================================================
// ThreatIntelDatabase: entries written before the store existed
// ============================================================================

TEST(ThreatIntelDatabaseStrings, AStringEntryWithoutTextIsRevokedAtOpen) {
    ScratchFolder dir;
    const auto path = (dir.path / "legacy.tidb").wstring();
    {
        ThreatIntelDatabase db;
        ASSERT_TRUE(db.Open(path));
        const size_t index = db.AllocateEntry();
        ASSERT_NE(index, SIZE_MAX);
        IOCEntry* entry = db.GetMutableEntry(index);
        ASSERT_NE(entry, nullptr);
        entry->type = IOCType::Domain;
        entry->value.stringRef.stringOffset = 0;  // the shape every pre-store domain had
        entry->value.stringRef.stringLength = 11;
        entry->flags = IOCFlags::Enabled;
        const size_t hashIndex = db.AllocateEntry();
        ASSERT_NE(hashIndex, SIZE_MAX);
        db.GetMutableEntry(hashIndex)->type = IOCType::FileHash;
        db.GetMutableEntry(hashIndex)->flags = IOCFlags::Enabled;
        db.Close();
    }
    std::filesystem::remove(ThreatIntelDatabase::StringStorePathFor(path));

    ThreatIntelDatabase db;
    ASSERT_TRUE(db.Open(path));
    EXPECT_EQ(db.GetRevokedUnresolvableStringEntries(), 1u);
    EXPECT_TRUE(HasFlag(db.GetEntry(0)->flags, IOCFlags::Revoked));
    EXPECT_FALSE(HasFlag(db.GetEntry(1)->flags, IOCFlags::Revoked)) << "a non-string entry was revoked";
}

TEST(ThreatIntelDatabaseStrings, DeletingADatabaseDeletesItsTexts) {
    ScratchFolder dir;
    const auto path = (dir.path / "gone.tidb").wstring();
    {
        ThreatIntelDatabase db;
        ASSERT_TRUE(db.Open(path));
        ASSERT_TRUE(db.InternString("left-behind.example"));
        db.Close();
    }
    ASSERT_TRUE(std::filesystem::exists(ThreatIntelDatabase::StringStorePathFor(path)));
    ASSERT_TRUE(DeleteDatabaseFile(path));
    EXPECT_FALSE(std::filesystem::exists(ThreatIntelDatabase::StringStorePathFor(path)));
}

// ============================================================================
// ThreatIntelStore: what a lookup of a string-valued indicator answers
// ============================================================================

class StringIndicatorTest : public ::testing::Test {
protected:
    ScratchFolder dir;
    std::wstring path = (dir.path / "ti.tidb").wstring();

    std::unique_ptr<ThreatIntelStore> Open() {
        auto store = CreateThreatIntelStore();
        StoreConfig cfg;
        cfg.databasePath = path;
        cfg.enableAutoFeedUpdate = false;
        cfg.enableCache = true;
        EXPECT_TRUE(store->Initialize(cfg));
        return store;
    }
};

TEST_F(StringIndicatorTest, SameLengthDomainsAreDifferentIndicators) {
    auto store = Open();
    ASSERT_TRUE(store->AddIOC(IOCType::Domain, "evil-one.example", ReputationLevel::Malicious,
                              ThreatIntelSource::InternalAnalysis));
    ASSERT_TRUE(store->AddIOC(IOCType::Domain, "good-two.example", ReputationLevel::Safe,
                              ThreatIntelSource::InternalAnalysis))
        << "a second domain of the same length was refused as a duplicate";

    const auto evil = store->LookupDomain("evil-one.example");
    EXPECT_TRUE(evil.found);
    EXPECT_EQ(evil.reputation, ReputationLevel::Malicious);
    const auto good = store->LookupDomain("good-two.example");
    EXPECT_TRUE(good.found);
    EXPECT_EQ(good.reputation, ReputationLevel::Safe);
    EXPECT_FALSE(store->LookupDomain("safe-one.example").found)
        << "an unknown domain matched a stored one of the same length";
    store->Shutdown();
}

TEST_F(StringIndicatorTest, ADomainMatchesInEveryCanonicalSpelling) {
    auto store = Open();
    ASSERT_TRUE(store->AddIOC(IOCType::Domain, "evil-one.example", ReputationLevel::Malicious,
                              ThreatIntelSource::InternalAnalysis));
    EXPECT_TRUE(store->LookupDomain("EVIL-ONE.Example").found);
    EXPECT_TRUE(store->LookupDomain("www.evil-one.example").found);
    EXPECT_FALSE(store->LookupDomain("evil-one.example.org").found);
    store->Shutdown();
}

// Task 352: valid spellings of a stored indicator are found, not refused by validation.
TEST_F(StringIndicatorTest, AnAbsoluteDomainNameAndAnUpperCaseSchemeAreFound) {
    auto store = Open();
    ASSERT_TRUE(store->AddIOC(IOCType::Domain, "evil-one.example", ReputationLevel::Malicious,
                              ThreatIntelSource::InternalAnalysis));
    ASSERT_TRUE(store->AddIOC(IOCType::URL, "http://evil-one.example/a.exe", ReputationLevel::Malicious,
                              ThreatIntelSource::InternalAnalysis));
    EXPECT_TRUE(store->LookupDomain("evil-one.example.").found) << "the root dot of an absolute name was refused";
    EXPECT_FALSE(store->LookupDomain("evil-one.example..").found);
    EXPECT_TRUE(store->LookupURL("HTTP://evil-one.example/a.exe").found) << "an upper-case scheme was refused";
    EXPECT_TRUE(store->LookupURL("Http://EVIL-ONE.example/a.exe").found);
    EXPECT_FALSE(store->LookupURL("HTTP://evil-one.example/A.exe").found) << "the path is case-sensitive";
    store->Shutdown();
}

TEST_F(StringIndicatorTest, AUrlHostIsCaseInsensitiveAndItsPathIsNot) {
    auto store = Open();
    ASSERT_TRUE(store->AddIOC(IOCType::URL, "http://EVIL.example/Payload.exe", ReputationLevel::Malicious,
                              ThreatIntelSource::InternalAnalysis));
    EXPECT_TRUE(store->LookupURL("http://evil.example/Payload.exe").found);
    EXPECT_TRUE(store->LookupURL("http://Evil.Example/Payload.exe").found);
    EXPECT_FALSE(store->LookupURL("http://evil.example/payload.exe").found)
        << "URL paths are case-sensitive; folding them would merge distinct indicators";
    EXPECT_FALSE(store->LookupURL("http://good.example/Payload.exe").found);
    store->Shutdown();
}

TEST_F(StringIndicatorTest, StringIndicatorsSurviveARestart) {
    {
        auto store = Open();
        ASSERT_TRUE(store->AddIOC(IOCType::Domain, "evil-one.example", ReputationLevel::Malicious,
                                  ThreatIntelSource::InternalAnalysis));
        ASSERT_TRUE(store->AddIOC(IOCType::Email, "boss@evil-one.example", ReputationLevel::Malicious,
                                  ThreatIntelSource::InternalAnalysis));
        store->Shutdown();
    }
    auto store = Open();
    EXPECT_TRUE(store->LookupDomain("evil-one.example").found);
    EXPECT_TRUE(store->LookupEmail("boss@evil-one.example").found);
    EXPECT_FALSE(store->LookupDomain("safe-one.example").found);
    store->Shutdown();
}

TEST_F(StringIndicatorTest, AStringEntryWithoutStoredTextIsRefused) {
    auto store = Open();
    IOCEntry entry{};
    entry.type = IOCType::Domain;
    entry.reputation = ReputationLevel::Malicious;
    entry.confidence = ConfidenceLevel::High;
    entry.value.stringRef.stringOffset = 0;
    entry.value.stringRef.stringLength = 16;
    EXPECT_FALSE(store->AddIOC(entry)) << "a domain with no text would match every domain of its length";
    entry.value.stringRef.stringOffset = 4096;  // inside no record
    EXPECT_FALSE(store->AddIOC(entry));
    EXPECT_FALSE(store->LookupDomain("evil-one.example").found);
    store->Shutdown();
}

// Task 357: the per-thread lookup cache answered from before a change. Each case looks the
// indicator up once, changes it, and looks again on the same thread.
TEST_F(StringIndicatorTest, ALookupAfterRemovalDoesNotFindTheIndicator) {
    auto store = Open();
    ASSERT_TRUE(store->AddIOC(IOCType::IPv4, "203.0.113.9", ReputationLevel::Malicious,
                              ThreatIntelSource::InternalAnalysis));
    ASSERT_TRUE(store->LookupIPv4("203.0.113.9").found);
    ASSERT_TRUE(store->RemoveIOC(IOCType::IPv4, "203.0.113.9"));
    EXPECT_FALSE(store->LookupIPv4("203.0.113.9").found) << "a removed indicator is still answered";
    store->Shutdown();
}

TEST_F(StringIndicatorTest, ALookupAfterAnUpdateSeesTheNewReputation) {
    auto store = Open();
    ASSERT_TRUE(store->AddIOC(IOCType::Domain, "evil-one.example", ReputationLevel::Suspicious,
                              ThreatIntelSource::InternalAnalysis));
    ASSERT_EQ(store->LookupDomain("evil-one.example").reputation, ReputationLevel::Suspicious);
    // Adding it again with the default options updates the entry (task 356).
    ASSERT_TRUE(store->AddIOC(IOCType::Domain, "evil-one.example", ReputationLevel::Malicious,
                              ThreatIntelSource::InternalAnalysis));
    EXPECT_EQ(store->LookupDomain("evil-one.example").reputation, ReputationLevel::Malicious)
        << "the lookup answered with the reputation from before the update";
    store->Shutdown();
}

TEST_F(StringIndicatorTest, AStringIndicatorCanBeRemovedByItsText) {
    auto store = Open();
    ASSERT_TRUE(store->AddIOC(IOCType::Domain, "evil-one.example", ReputationLevel::Malicious,
                              ThreatIntelSource::InternalAnalysis));
    ASSERT_TRUE(store->AddIOC(IOCType::Domain, "good-two.example", ReputationLevel::Safe,
                              ThreatIntelSource::InternalAnalysis));
    EXPECT_TRUE(store->RemoveIOC(IOCType::Domain, "evil-one.example"));
    EXPECT_FALSE(store->LookupDomain("evil-one.example").found);
    EXPECT_TRUE(store->LookupDomain("good-two.example").found) << "removing one domain removed another";
    store->Shutdown();
}

// ============================================================================
// Deduplication index across restarts and Optimize (task 354)
// ============================================================================

class DedupIndexTest : public ::testing::Test {
protected:
    ScratchFolder dir;
    std::wstring path = (dir.path / "dedup.tidb").wstring();

    static IOCOperationResult Add(ThreatIntelIOCManager& manager, IOCType type, std::string_view value) {
        IOCEntry entry{};
        EXPECT_TRUE(manager.ParseAndStoreIOC(type, value, entry)) << std::string(value);
        entry.reputation = ReputationLevel::Malicious;
        // The defaults update an existing entry; ask for the duplicate to be reported instead.
        IOCAddOptions options;
        options.overwriteIfExists = false;
        options.updateIfExists = false;
        return manager.AddIOC(entry, options);
    }
};

TEST_F(DedupIndexTest, AnIndicatorAddedAgainAfterARestartIsADuplicate) {
    {
        ThreatIntelDatabase db;
        ASSERT_TRUE(db.Open(path));
        ThreatIntelIOCManager manager;
        ASSERT_EQ(manager.Initialize(&db).code, ThreatIntelError::Success);
        ASSERT_TRUE(Add(manager, IOCType::IPv4, "203.0.113.7").success);
        ASSERT_TRUE(Add(manager, IOCType::Domain, "evil-one.example").success);
        manager.Shutdown();
        db.Close();
    }
    ThreatIntelDatabase db;
    ASSERT_TRUE(db.Open(path));
    ThreatIntelIOCManager manager;
    ASSERT_EQ(manager.Initialize(&db).code, ThreatIntelError::Success);
    const auto ip = Add(manager, IOCType::IPv4, "203.0.113.7");
    const auto domain = Add(manager, IOCType::Domain, "evil-one.example");
    EXPECT_TRUE(ip.wasDuplicate) << "the dedup index started empty after the restart";
    EXPECT_TRUE(domain.wasDuplicate);
    EXPECT_EQ(db.GetEntryCount(), 2u) << "a restart turned a re-add into a second copy";
    EXPECT_TRUE(manager.ExistsIOC(IOCType::Domain, "evil-one.example"));
    manager.Shutdown();
}

TEST_F(DedupIndexTest, OptimizeKeepsEveryLiveIndicatorRecognised) {
    ThreatIntelDatabase db;
    ASSERT_TRUE(db.Open(path));
    ThreatIntelIOCManager manager;
    ASSERT_EQ(manager.Initialize(&db).code, ThreatIntelError::Success);
    ASSERT_TRUE(Add(manager, IOCType::IPv4, "203.0.113.7").success);
    ASSERT_TRUE(Add(manager, IOCType::IPv6, "2001:db8::7").success);
    ASSERT_TRUE(Add(manager, IOCType::Domain, "evil-one.example").success);
    ASSERT_TRUE(manager.Optimize());
    EXPECT_TRUE(Add(manager, IOCType::IPv4, "203.0.113.7").wasDuplicate)
        << "Optimize rebuilt IPv4 keys as a.b.c.d/32, which AddIOC never uses";
    EXPECT_TRUE(Add(manager, IOCType::IPv6, "2001:db8::7").wasDuplicate) << "Optimize dropped IPv6 keys";
    EXPECT_TRUE(Add(manager, IOCType::Domain, "evil-one.example").wasDuplicate) << "Optimize dropped string keys";
    EXPECT_EQ(db.GetEntryCount(), 3u);
    manager.Shutdown();
}

// ============================================================================
// ThreatIntelIndex reads indicator text from the string store (task 353)
// ============================================================================

// The view passed to Initialize goes out of scope at once, as ThreatIntelStore's local did. The
// index used to keep a pointer to it; it now keeps a copy, and reads texts from the string store.
TEST(ThreatIntelIndexStrings, ADomainIsIndexedFromTheStringStoreAfterTheCallersViewIsGone) {
    ScratchFolder dir;
    ThreatIntelDatabase db;
    ASSERT_TRUE(db.Open((dir.path / "index.tidb").wstring()));
    ThreatIntelIndex index;
    {
        const MemoryMappedView view = db.GetMemoryMappedView();
        ASSERT_EQ(index.Initialize(view, db.GetHeader()).code, ThreatIntelError::Success);
    }
    index.SetStringSource(&db.Strings());

    const auto text = db.InternString("evil-one.example");
    ASSERT_TRUE(text);
    IOCEntry entry{};
    entry.entryId = 1;
    entry.type = IOCType::Domain;
    entry.flags = IOCFlags::Enabled;
    entry.value.stringRef.stringOffset = text->offset;
    entry.value.stringRef.stringLength = text->length;
    ASSERT_EQ(index.Insert(entry, 0).code, ThreatIntelError::Success);

    EXPECT_TRUE(index.LookupDomain("evil-one.example").found);
    EXPECT_FALSE(index.LookupDomain("good-two.example").found);
    index.SetStringSource(nullptr);
    index.Shutdown();
}

}  // namespace
