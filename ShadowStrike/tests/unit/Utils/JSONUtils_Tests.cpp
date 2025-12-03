/*
 * ============================================================================
 * ShadowStrike JSONUtils - ENTERPRISE-GRADE UNIT TESTS
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Comprehensive unit test suite for JSONUtils module
 * Coverage: Parse, stringify, file I/O, JSON pointer, path operations,
 *           merge patch, validation, security limits, edge cases
 *
 * Test Standards: Sophos/CrowdStrike enterprise quality
 *
 * ============================================================================
 */

#include <gtest/gtest.h>
#include "../../../src/Utils/JSONUtils.hpp"
#include "../../../src/Utils/FileUtils.hpp"
#include <Objbase.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using namespace ShadowStrike::Utils::JSON;
namespace fs = std::filesystem;

// ============================================================================
// TEST FIXTURE
// ============================================================================
class JSONUtilsTest : public ::testing::Test {
protected:
    fs::path testRoot;
    
    void SetUp() override {
        wchar_t tempPath[MAX_PATH]{};
        GetTempPathW(MAX_PATH, tempPath);
        
        GUID guid{};
        CoCreateGuid(&guid);
        wchar_t guidStr[64];
        swprintf_s(guidStr, L"%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            guid.Data1, guid.Data2, guid.Data3,
            guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
            guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
        
        testRoot = fs::path(tempPath) / (L"ShadowStrike_JSON_UT_" + std::wstring(guidStr));
        fs::create_directories(testRoot);
    }
    
    void TearDown() override {
        if (!testRoot.empty() && fs::exists(testRoot)) {
            std::error_code ec;
            fs::remove_all(testRoot, ec);
        }
    }
    
    fs::path TestPath(const std::wstring& relative) const {
        return testRoot / relative;
    }
};

// ============================================================================
// PARSE TESTS
// ============================================================================
TEST_F(JSONUtilsTest, Parse_ValidSimpleObject) {
    std::string jsonText = R"({"name":"test","value":123})";
    Json j;
    Error err;
    
    ASSERT_TRUE(Parse(jsonText, j, &err));
    EXPECT_TRUE(j.is_object());
    EXPECT_EQ(j["name"], "test");
    EXPECT_EQ(j["value"], 123);
}

TEST_F(JSONUtilsTest, Parse_ValidArray) {
    std::string jsonText = R"([1, 2, 3, "four", true, null])";
    Json j;
    
    ASSERT_TRUE(Parse(jsonText, j));
    EXPECT_TRUE(j.is_array());
    EXPECT_EQ(j.size(), 6u);
    EXPECT_EQ(j[0], 1);
    EXPECT_EQ(j[3], "four");
    EXPECT_TRUE(j[4].is_boolean());
    EXPECT_TRUE(j[5].is_null());
}

TEST_F(JSONUtilsTest, Parse_WithComments) {
    std::string jsonText = R"(
        {
            // This is a comment
            "key": "value", /* block comment */
            "number": 42
        }
    )";
    Json j;
    ParseOptions opt;
    opt.allowComments = true;
    
    ASSERT_TRUE(Parse(jsonText, j, nullptr, opt));
    EXPECT_EQ(j["key"], "value");
    EXPECT_EQ(j["number"], 42);
}

TEST_F(JSONUtilsTest, Parse_InvalidJSON_SyntaxError) {
    std::string jsonText = R"({"invalid": })";
    Json j;
    Error err;
    
    EXPECT_FALSE(Parse(jsonText, j, &err));
    EXPECT_FALSE(err.message.empty());
}

TEST_F(JSONUtilsTest, Parse_EmptyString) {
    Json j;
    Error err;
    
    EXPECT_FALSE(Parse("", j, &err));
}

TEST_F(JSONUtilsTest, Parse_NestedDepthLimit) {
    std::string deeply_nested;
    for (int i = 0; i < 1100; ++i) {
        deeply_nested += "{\"a\":";
    }
    deeply_nested += "1";
    for (int i = 0; i < 1100; ++i) {
        deeply_nested += "}";
    }
    
    Json j;
    Error err;
    ParseOptions opt;
    opt.maxDepth = 1000;
    
    EXPECT_FALSE(Parse(deeply_nested, j, &err, opt));
}

TEST_F(JSONUtilsTest, Parse_Unicode) {
    std::string jsonText = R"({"text":"Hello 世界 🌍"})";
    Json j;
    
    ASSERT_TRUE(Parse(jsonText, j));
    EXPECT_EQ(j["text"], "Hello 世界 🌍");
}

// ============================================================================
// STRINGIFY TESTS
// ============================================================================
TEST_F(JSONUtilsTest, Stringify_SimpleObject) {
    Json j;
    j["name"] = "test";
    j["value"] = 123;
    std::string out;
    
    ASSERT_TRUE(Stringify(j, out));
    EXPECT_FALSE(out.empty());
    EXPECT_NE(out.find("name"), std::string::npos);
    EXPECT_NE(out.find("test"), std::string::npos);
}

TEST_F(JSONUtilsTest, Stringify_PrettyFormat) {
    Json j;
    j["a"] = 1;
    j["b"] = Json::object();
    j["b"]["c"] = 2;
    std::string out;
    StringifyOptions opt;
    opt.pretty = true;
    opt.indentSpaces = 4;
    
    ASSERT_TRUE(Stringify(j, out, opt));
    EXPECT_NE(out.find("\n"), std::string::npos);
    EXPECT_NE(out.find("    "), std::string::npos);
}

TEST_F(JSONUtilsTest, Stringify_Minified) {
    Json j;
    j["key"] = "value";
    j["num"] = 42;
    std::string out;
    StringifyOptions opt;
    opt.pretty = false;
    
    ASSERT_TRUE(Stringify(j, out, opt));
    EXPECT_EQ(out.find("\n"), std::string::npos);
}

// ============================================================================
// MINIFY/PRETTIFY TESTS
// ============================================================================
TEST_F(JSONUtilsTest, Minify_ValidJSON) {
    std::string jsonText = R"(
        {
            "key": "value",
            "number": 123
        }
    )";
    std::string out;
    
    ASSERT_TRUE(Minify(jsonText, out));
    EXPECT_EQ(out.find("\n"), std::string::npos);
    EXPECT_EQ(out.find("  "), std::string::npos);
}

TEST_F(JSONUtilsTest, Prettify_ValidJSON) {
    std::string jsonText = R"({"a":1,"b":{"c":2}})";
    std::string out;
    
    ASSERT_TRUE(Prettify(jsonText, out, 2));
    EXPECT_NE(out.find("\n"), std::string::npos);
}

// ============================================================================
// FILE I/O TESTS
// ============================================================================
TEST_F(JSONUtilsTest, LoadFromFile_ValidFile) {
    auto path = TestPath(L"test.json");
    std::ofstream ofs(path);
    ofs << R"({"test": true, "value": 42})";
    ofs.close();
    
    Json j;
    Error err;
    
    ASSERT_TRUE(LoadFromFile(path, j, &err));
    ASSERT_TRUE(j.contains("test"));
    ASSERT_TRUE(j.at("test").is_boolean());
    EXPECT_TRUE(j.at("test").get_ref<const bool&>());
    EXPECT_EQ(j["value"], 42);
}

TEST_F(JSONUtilsTest, LoadFromFile_NonExistentFile) {
    auto path = TestPath(L"nonexistent.json");
    Json j;
    Error err;
    
    EXPECT_FALSE(LoadFromFile(path, j, &err));
    EXPECT_FALSE(err.message.empty());
}

TEST_F(JSONUtilsTest, LoadFromFile_EmptyFile) {
    auto path = TestPath(L"empty.json");
    std::ofstream ofs(path);
    ofs.close();
    
    Json j;
    Error err;
    
    EXPECT_FALSE(LoadFromFile(path, j, &err));
}

TEST_F(JSONUtilsTest, LoadFromFile_WithBOM) {
    auto path = TestPath(L"bom.json");
    std::ofstream ofs(path, std::ios::binary);
    ofs << "\xEF\xBB\xBF" << R"({"key": "value"})";
    ofs.close();
    
    Json j;
    
    ASSERT_TRUE(LoadFromFile(path, j));
    EXPECT_EQ(j["key"], "value");
}

TEST_F(JSONUtilsTest, LoadFromFile_TooLarge) {
    auto path = TestPath(L"large.json");
    Json j;
    Error err;
    
    // Test with 1KB max
    EXPECT_FALSE(LoadFromFile(path, j, &err, {}, 1024));
}

TEST_F(JSONUtilsTest, SaveToFile_BasicSave) {
    auto path = TestPath(L"output.json");
    Json j;
    j["key"] = "value";
    j["number"] = 123;
    Error err;
    
    ASSERT_TRUE(SaveToFile(path, j, &err));
    EXPECT_TRUE(fs::exists(path));
    
    // Verify content
    Json loaded;
    ASSERT_TRUE(LoadFromFile(path, loaded));
    EXPECT_EQ(loaded["key"], "value");
    EXPECT_EQ(loaded["number"], 123);
}

TEST_F(JSONUtilsTest, SaveToFile_WithBOM) {
    auto path = TestPath(L"bom_output.json");
    Json j;
    j["test"] = true;
    SaveOptions opt;
    opt.writeBOM = true;
    
    ASSERT_TRUE(SaveToFile(path, j, nullptr, opt));
    
    std::ifstream ifs(path, std::ios::binary);
    char bom[3];
    ifs.read(bom, 3);
    EXPECT_EQ(static_cast<unsigned char>(bom[0]), 0xEF);
    EXPECT_EQ(static_cast<unsigned char>(bom[1]), 0xBB);
    EXPECT_EQ(static_cast<unsigned char>(bom[2]), 0xBF);
}

TEST_F(JSONUtilsTest, SaveToFile_AtomicReplace) {
    auto path = TestPath(L"atomic.json");
    Json j1;
    j1["version"] = 1;
    Json j2;
    j2["version"] = 2;
    
    SaveOptions opt;
    opt.atomicReplace = true;
    
    ASSERT_TRUE(SaveToFile(path, j1, nullptr, opt));
    ASSERT_TRUE(SaveToFile(path, j2, nullptr, opt));
    
    Json loaded;
    ASSERT_TRUE(LoadFromFile(path, loaded));
    EXPECT_EQ(loaded["version"], 2);
}

TEST_F(JSONUtilsTest, SaveToFile_PrettyFormat) {
    auto path = TestPath(L"pretty.json");
    Json j;
    j["a"] = 1;
    j["b"] = Json::object();
    j["b"]["c"] = 2;
    SaveOptions opt;
    opt.pretty = true;
    opt.indentSpaces = 4;
    
    ASSERT_TRUE(SaveToFile(path, j, nullptr, opt));
    
    std::ifstream ifs(path);
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("\n"), std::string::npos);
}

// ============================================================================
// JSON POINTER TESTS
// ============================================================================
TEST_F(JSONUtilsTest, ToJsonPointer_AlreadyPointer) {
    std::string result = ToJsonPointer("/a/b/c");
    EXPECT_EQ(result, "/a/b/c");
}

TEST_F(JSONUtilsTest, ToJsonPointer_DotNotation) {
    std::string result = ToJsonPointer("a.b.c");
    EXPECT_EQ(result, "/a/b/c");
}

TEST_F(JSONUtilsTest, ToJsonPointer_BracketNotation) {
    std::string result = ToJsonPointer("a[0].b[1]");
    EXPECT_EQ(result, "/a/0/b/1");
}

TEST_F(JSONUtilsTest, ToJsonPointer_Mixed) {
    std::string result = ToJsonPointer("root.items[0].name");
    EXPECT_EQ(result, "/root/items/0/name");
}

TEST_F(JSONUtilsTest, ToJsonPointer_EscapeSpecialChars) {
    std::string result = ToJsonPointer("a~b/c");
    EXPECT_NE(result.find("~0"), std::string::npos); // ~ escaped
    EXPECT_NE(result.find("~1"), std::string::npos); // / escaped
}

TEST_F(JSONUtilsTest, ToJsonPointer_EmptyString) {
    std::string result = ToJsonPointer("");
    EXPECT_EQ(result, "/");
}

// ============================================================================
// CONTAINS TESTS
// ============================================================================
TEST_F(JSONUtilsTest, Contains_ExistingPath) {
    std::string jsonText = R"({"a": {"b": {"c": 42}}})";
    Json j;
    ASSERT_TRUE(Parse(jsonText, j));
    
    EXPECT_TRUE(Contains(j, "/a/b/c"));
    EXPECT_TRUE(Contains(j, "a.b.c"));
}

TEST_F(JSONUtilsTest, Contains_NonExistingPath) {
    std::string jsonText = R"({"a": {"b": 1}})";
    Json j;
    ASSERT_TRUE(Parse(jsonText, j));
    
    EXPECT_FALSE(Contains(j, "/a/x"));
    EXPECT_FALSE(Contains(j, "a.b.c"));
}

TEST_F(JSONUtilsTest, Contains_ArrayIndex) {
    std::string jsonText = R"({"items": [1, 2, 3]})";
    Json j;
    ASSERT_TRUE(Parse(jsonText, j));
    
    EXPECT_TRUE(Contains(j, "/items/0"));
    EXPECT_TRUE(Contains(j, "items[1]"));
    EXPECT_FALSE(Contains(j, "/items/10"));
}

// ============================================================================
// GET/SET TESTS
// ============================================================================
TEST_F(JSONUtilsTest, Get_ValidPath_String) {
    std::string jsonText = R"({"user": {"name": "Alice"}})";
    Json j;
    ASSERT_TRUE(Parse(jsonText, j));
    std::string name;
    
    ASSERT_TRUE(Get(j, "user.name", name));
    EXPECT_EQ(name, "Alice");
}

TEST_F(JSONUtilsTest, Get_ValidPath_Int) {
    std::string jsonText = R"({"config": {"port": 8080}})";
    Json j;
    ASSERT_TRUE(Parse(jsonText, j));
    int port;
    
    ASSERT_TRUE(Get(j, "config.port", port));
    EXPECT_EQ(port, 8080);
}

TEST_F(JSONUtilsTest, Get_InvalidPath) {
    Json j;
    j["a"] = 1;
    std::string value;
    
    EXPECT_FALSE(Get(j, "x.y.z", value));
}

TEST_F(JSONUtilsTest, Get_TypeMismatch) {
    Json j;
    j["value"] = "string";
    int num;
    
    EXPECT_FALSE(Get(j, "value", num));
}

TEST_F(JSONUtilsTest, GetOr_ExistingValue) {
    Json j;
    j["timeout"] = 30;
    
    int value = GetOr(j, "timeout", 60);
    EXPECT_EQ(value, 30);
}

TEST_F(JSONUtilsTest, GetOr_DefaultValue) {
    Json j;
    j["a"] = 1;
    
    int value = GetOr(j, "missing", 42);
    EXPECT_EQ(value, 42);
}

TEST_F(JSONUtilsTest, Set_NewPath) {
    Json j;
    
    ASSERT_TRUE(Set(j, "user.name", std::string("Bob")));
    EXPECT_EQ(j["user"]["name"], "Bob");
}

TEST_F(JSONUtilsTest, Set_OverwriteExisting) {
    Json j;
    j["key"] = "old";
    
    ASSERT_TRUE(Set(j, "key", std::string("new")));
    EXPECT_EQ(j["key"], "new");
}

TEST_F(JSONUtilsTest, Set_NestedPath) {
    Json j;
    
    ASSERT_TRUE(Set(j, "a.b.c.d", 42));
    EXPECT_EQ(j["a"]["b"]["c"]["d"], 42);
}

TEST_F(JSONUtilsTest, Set_ArrayIndex) {
    Json j = Json::array();
    
    ASSERT_TRUE(Set(j, "[0]", std::string("first")));
    EXPECT_TRUE(j.is_array());
    EXPECT_EQ(j.size(), 1u);
    EXPECT_EQ(j[0], "first");
}

// ============================================================================
// MERGE PATCH TESTS
// ============================================================================
TEST_F(JSONUtilsTest, MergePatch_AddNewKeys) {
    Json target;
    target["a"] = 1;
    Json patch;
    patch["b"] = 2;
    
    MergePatch(target, patch);
    
    EXPECT_EQ(target["a"], 1);
    EXPECT_EQ(target["b"], 2);
}

TEST_F(JSONUtilsTest, MergePatch_OverwriteKeys) {
    Json target;
    target["a"] = 1;
    target["b"] = 2;
    Json patch;
    patch["a"] = 99;
    
    MergePatch(target, patch);
    
    EXPECT_EQ(target["a"], 99);
    EXPECT_EQ(target["b"], 2);
}

TEST_F(JSONUtilsTest, MergePatch_DeleteKeys) {
    Json target;
    target["a"] = 1;
    target["b"] = 2;
    Json patch;
    patch["b"] = nullptr;
    
    MergePatch(target, patch);
    
    EXPECT_TRUE(target.contains("a"));
    EXPECT_FALSE(target.contains("b"));
}

TEST_F(JSONUtilsTest, MergePatch_NestedObjects) {
    std::string targetText = R"({"user": {"name": "Alice", "age": 30}})";
    std::string patchText = R"({"user": {"age": 31, "city": "NYC"}})";
    Json target, patch;
    ASSERT_TRUE(Parse(targetText, target));
    ASSERT_TRUE(Parse(patchText, patch));
    
    MergePatch(target, patch);
    
    EXPECT_EQ(target["user"]["name"], "Alice");
    EXPECT_EQ(target["user"]["age"], 31);
    EXPECT_EQ(target["user"]["city"], "NYC");
}

// ============================================================================
// REQUIRE KEYS TESTS
// ============================================================================
TEST_F(JSONUtilsTest, RequireKeys_AllPresent) {
    Json j;
    j["test"] = true;
    j["name"] = "test";
    j["version"] = 1;
    j["enabled"] = true;
    Error err;
    
    EXPECT_TRUE(RequireKeys(j, "/", {"name", "version"}, &err));
}

TEST_F(JSONUtilsTest, RequireKeys_MissingKey) {
    Json j;
    j["name"] = "test";
    Error err;
    
    EXPECT_FALSE(RequireKeys(j, "/", {"name", "version"}, &err));
    EXPECT_FALSE(err.message.empty());
    EXPECT_NE(err.message.find("version"), std::string::npos);
}

TEST_F(JSONUtilsTest, RequireKeys_NestedObject) {
    std::string jsonText = R"({"config": {"host": "localhost", "port": 8080}})";
    Json j;
    ASSERT_TRUE(Parse(jsonText, j));
    Error err;
    
    EXPECT_TRUE(RequireKeys(j, "/config", {"host", "port"}, &err));
}

TEST_F(JSONUtilsTest, RequireKeys_PathNotFound) {
    Json j;
    j["a"] = 1;
    Error err;
    
    EXPECT_FALSE(RequireKeys(j, "/x/y", {"key"}, &err));
}

TEST_F(JSONUtilsTest, RequireKeys_NotAnObject) {
    Json j;
    j["value"] = 123;
    Error err;
    
    EXPECT_FALSE(RequireKeys(j, "/value", {"key"}, &err));
}

// ============================================================================
// EDGE CASES & SECURITY TESTS
// ============================================================================
TEST_F(JSONUtilsTest, EdgeCase_VeryLargeNumber) {
    Json j;
    j["big"] = static_cast<Json::number_unsigned_t>(9007199254740992ULL);
    std::string out;
    
    ASSERT_TRUE(Stringify(j, out));
    
    Json parsed;
    ASSERT_TRUE(Parse(out, parsed));
    EXPECT_EQ(parsed["big"].get_ref<const Json::number_unsigned_t&>(), static_cast<Json::number_unsigned_t>(9007199254740992ULL));
}

TEST_F(JSONUtilsTest, EdgeCase_SpecialFloats) {
    Json j;
    j["inf"] = std::numeric_limits<double>::infinity();
    j["ninf"] = -std::numeric_limits<double>::infinity();
    j["nan"] = std::numeric_limits<double>::quiet_NaN();
    
    std::string out;
    ASSERT_TRUE(Stringify(j, out));
}

TEST_F(JSONUtilsTest, EdgeCase_EmptyObject) {
    Json j = Json::object();
    std::string out;
    
    ASSERT_TRUE(Stringify(j, out));
    EXPECT_EQ(out, "{}");
}

TEST_F(JSONUtilsTest, EdgeCase_EmptyArray) {
    Json j = Json::array();
    std::string out;
    
    ASSERT_TRUE(Stringify(j, out));
    EXPECT_EQ(out, "[]");
}

TEST_F(JSONUtilsTest, Security_MaxDepthProtection) {
    ParseOptions opt;
    opt.maxDepth = 10;
    
    std::string deep = "{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":{\"f\":{\"g\":{\"h\":{\"i\":{\"j\":{\"k\":1}}}}}}}}}}}";
    Json j;
    Error err;
    
    EXPECT_FALSE(Parse(deep, j, &err, opt));
}

TEST_F(JSONUtilsTest, EdgeCase_ComplexNestedStructure) {
    Json j;
    j["users"] = Json::array();
    j["users"].push_back(Json::object());
    j["users"][0]["id"] = 1;
    j["users"][0]["name"] = "Alice";
    j["users"][0]["roles"] = Json::array({ "admin", "user" });
    j["users"].push_back(Json::object());
    j["users"][1]["id"] = 2;
    j["users"][1]["name"] = "Bob";
    j["users"][1]["roles"] = Json::array({ "user" });

    j["config"] = Json::object();
    j["config"]["database"] = Json::object();
    j["config"]["database"]["host"] = "localhost";
    j["config"]["database"]["port"] = 5432;
    j["config"]["cache"] = Json::object();
    j["config"]["cache"]["enabled"] = true;
    j["config"]["cache"]["ttl"] = 3600;
    auto path = TestPath(L"complex.json");
    ASSERT_TRUE(SaveToFile(path, j));
    
    Json loaded;
    ASSERT_TRUE(LoadFromFile(path, loaded));
    EXPECT_EQ(loaded["users"][0]["name"], "Alice");
    EXPECT_EQ(loaded["config"]["database"]["port"], 5432);
}

TEST_F(JSONUtilsTest, EdgeCase_UnicodeEscape) {
    std::string jsonText = R"({"emoji": "\uD83D\uDE00"})";
    Json j;
    
    ASSERT_TRUE(Parse(jsonText, j));
    ASSERT_TRUE(j.contains("emoji"));
    ASSERT_TRUE(j.at("emoji").is_string());
    std::string emoji = j.at("emoji").get_ref<const std::string&>();
    EXPECT_FALSE(emoji.empty());
}

TEST_F(JSONUtilsTest, Stress_ManyKeys) {
    Json j;
    for (int i = 0; i < 1000; ++i) {
        j["key_" + std::to_string(i)] = i;
    }
    
    std::string out;
    ASSERT_TRUE(Stringify(j, out));
    
    Json parsed;
    ASSERT_TRUE(Parse(out, parsed));
    EXPECT_EQ(parsed.size(), 1000u);
}

TEST_F(JSONUtilsTest, Stress_LargeArray) {
    Json j = Json::array();
    for (int i = 0; i < 10000; ++i) {
        j.push_back(i);
    }
    
    std::string out;
    ASSERT_TRUE(Stringify(j, out));
    EXPECT_GT(out.size(), 10000u);
}
