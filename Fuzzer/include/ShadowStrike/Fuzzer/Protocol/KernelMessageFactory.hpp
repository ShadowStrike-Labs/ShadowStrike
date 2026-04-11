#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Fuzzer {

enum class BinarySeedKind {
    Baseline,
    StructuredVariant
};

[[nodiscard]] std::string_view ToString(BinarySeedKind kind);

struct BinarySeedArtifact {
    std::string id;
    std::string surfaceId;
    std::string fileName;
    std::string description;
    std::vector<std::uint8_t> bytes;
    BinarySeedKind kind{ BinarySeedKind::Baseline };
    std::string schemaId;
    std::string parentId;
};

class KernelMessageFactory final {
public:
    [[nodiscard]] static std::vector<BinarySeedArtifact> BuildBaselineSeedSet();
    [[nodiscard]] static std::vector<BinarySeedArtifact> BuildStructuredVariantSeedSet();
    [[nodiscard]] static std::vector<BinarySeedArtifact> BuildFullSeedSet();
    [[nodiscard]] static std::optional<BinarySeedArtifact> BuildById(std::string_view id);
};

}  // namespace ShadowStrike::Fuzzer
