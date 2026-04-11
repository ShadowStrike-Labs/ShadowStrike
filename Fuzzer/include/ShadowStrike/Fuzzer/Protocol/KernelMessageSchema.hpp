#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Fuzzer {

enum class KernelFieldEncoding {
    UnsignedInteger,
    BitFlags,
    Boolean,
    EnumValue,
    FixedBytes,
    FixedAnsiString,
    WideCharCount,
    ByteCount
};

[[nodiscard]] std::string_view ToString(KernelFieldEncoding encoding);

struct KernelFieldSchema {
    std::string name;
    std::size_t offset;
    std::size_t width;
    KernelFieldEncoding encoding;
    std::string description;
    std::vector<std::string> invariants;
};

struct KernelVariableSegmentSchema {
    std::string name;
    std::string lengthField;
    std::size_t elementWidth;
    std::string encoding;
    std::string description;
};

struct KernelMessageSchema {
    std::string id;
    std::string surfaceId;
    std::string seedId;
    std::uint16_t messageType;
    std::string messageName;
    std::string direction;
    std::size_t minimumSize;
    std::string description;
    std::vector<std::string> invariants;
    std::vector<std::string> mutationAxes;
    std::vector<KernelFieldSchema> fields;
    std::vector<KernelVariableSegmentSchema> variableSegments;
};

class KernelMessageSchemaCatalog final {
public:
    [[nodiscard]] static const std::vector<KernelMessageSchema>& GetSchemas();
    [[nodiscard]] static const KernelMessageSchema* FindById(std::string_view id);
    [[nodiscard]] static std::string RenderJson(const std::vector<KernelMessageSchema>& schemas);
};

}  // namespace ShadowStrike::Fuzzer
