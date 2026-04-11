#include "ShadowStrike/Fuzzer/Core/AttackSurface.hpp"
#include "ShadowStrike/Fuzzer/Protocol/KernelMessageFactory.hpp"
#include "ShadowStrike/Fuzzer/Protocol/KernelMessageSchema.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>

namespace SSF = ShadowStrike::Fuzzer;

namespace {

[[nodiscard]] std::string EscapeJson(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size() + 8);

    for (const char ch : value) {
        switch (ch) {
        case '\\': escaped += "\\\\"; break;
        case '"': escaped += "\\\""; break;
        case '\b': escaped += "\\b"; break;
        case '\f': escaped += "\\f"; break;
        case '\n': escaped += "\\n"; break;
        case '\r': escaped += "\\r"; break;
        case '\t': escaped += "\\t"; break;
        default:
            escaped.push_back(ch);
            break;
        }
    }

    return escaped;
}

void PrintUsage() {
    std::cout
        << "ShadowStrikeFuzzer\n"
        << "Usage:\n"
        << "  ShadowStrikeFuzzer --list-targets\n"
        << "  ShadowStrikeFuzzer --describe-target <id>\n"
        << "  ShadowStrikeFuzzer --export-surface-map <json-path>\n"
        << "  ShadowStrikeFuzzer --export-kernel-schemas <json-path>\n"
        << "  ShadowStrikeFuzzer --export-kernel-seeds <directory>\n"
        << "  ShadowStrikeFuzzer --export-kernel-variants <directory>\n"
        << "  ShadowStrikeFuzzer --bootstrap <directory>\n";
}

[[nodiscard]] bool WriteBinaryFile(
    const std::filesystem::path& path,
    const std::vector<std::uint8_t>& bytes)
{
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) {
        return false;
    }

    stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return stream.good();
}

[[nodiscard]] bool WriteTextFile(const std::filesystem::path& path, const std::string& text) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) {
        return false;
    }

    stream.write(text.data(), static_cast<std::streamsize>(text.size()));
    return stream.good();
}

[[nodiscard]] std::string NarrowAscii(std::wstring_view value) {
    std::string narrow;
    narrow.reserve(value.size());

    for (const wchar_t ch : value) {
        if (ch > 0x7F) {
            return {};
        }

        narrow.push_back(static_cast<char>(ch));
    }

    return narrow;
}

[[nodiscard]] std::string BuildSeedManifestJson(const std::vector<SSF::BinarySeedArtifact>& seeds) {
    std::ostringstream stream;
    stream << "{\n  \"seeds\": [\n";

    for (std::size_t index = 0; index < seeds.size(); ++index) {
        const auto& seed = seeds[index];
        stream << "    {\n"
               << "      \"id\": \"" << EscapeJson(seed.id) << "\",\n"
               << "      \"surfaceId\": \"" << EscapeJson(seed.surfaceId) << "\",\n"
               << "      \"kind\": \"" << SSF::ToString(seed.kind) << "\",\n"
               << "      \"schemaId\": \"" << EscapeJson(seed.schemaId) << "\",\n"
               << "      \"parentId\": \"" << EscapeJson(seed.parentId) << "\",\n"
               << "      \"fileName\": \"" << EscapeJson(seed.fileName) << "\",\n"
               << "      \"description\": \"" << EscapeJson(seed.description) << "\",\n"
               << "      \"size\": " << seed.bytes.size() << "\n"
               << "    }";

        if (index + 1 != seeds.size()) {
            stream << ',';
        }

        stream << '\n';
    }

    stream << "  ]\n}\n";
    return stream.str();
}

[[nodiscard]] int ExportBinaryArtifacts(
    const std::filesystem::path& outputDirectory,
    const std::vector<SSF::BinarySeedArtifact>& artifacts,
    const std::string_view description)
{
    std::error_code ec;
    std::filesystem::create_directories(outputDirectory, ec);
    if (ec) {
        std::cerr << "Failed to create seed output directory: " << outputDirectory << '\n';
        return 1;
    }

    for (const auto& artifact : artifacts) {
        const auto path = outputDirectory / artifact.fileName;
        if (!WriteBinaryFile(path, artifact.bytes)) {
            std::cerr << "Failed to write seed: " << path << '\n';
            return 1;
        }
    }

    const auto manifestPath = outputDirectory / "manifest.json";
    if (!WriteTextFile(manifestPath, BuildSeedManifestJson(artifacts))) {
        std::cerr << "Failed to write seed manifest: " << manifestPath << '\n';
        return 1;
    }

    std::cout << "Exported " << artifacts.size() << ' ' << description << " to "
              << outputDirectory.string() << '\n';
    return 0;
}

[[nodiscard]] int ExportKernelSeeds(const std::filesystem::path& outputDirectory) {
    return ExportBinaryArtifacts(
        outputDirectory,
        SSF::KernelMessageFactory::BuildBaselineSeedSet(),
        "kernel-protocol baseline seeds");
}

[[nodiscard]] int ExportKernelVariants(const std::filesystem::path& outputDirectory) {
    return ExportBinaryArtifacts(
        outputDirectory,
        SSF::KernelMessageFactory::BuildStructuredVariantSeedSet(),
        "kernel-protocol structured variants");
}

[[nodiscard]] int ExportSurfaceMap(const std::filesystem::path& outputPath) {
    std::error_code ec;
    if (outputPath.has_parent_path()) {
        std::filesystem::create_directories(outputPath.parent_path(), ec);
        if (ec) {
            std::cerr << "Failed to create surface-map directory: " << outputPath.parent_path() << '\n';
            return 1;
        }
    }

    const auto json = SSF::AttackSurfaceRegistry::RenderJson(SSF::AttackSurfaceRegistry::GetDefaultRegistry());
    if (!WriteTextFile(outputPath, json)) {
        std::cerr << "Failed to write surface map: " << outputPath << '\n';
        return 1;
    }

    std::cout << "Exported attack-surface map to " << outputPath.string() << '\n';
    return 0;
}

[[nodiscard]] int ExportKernelSchemas(const std::filesystem::path& outputPath) {
    std::error_code ec;
    if (outputPath.has_parent_path()) {
        std::filesystem::create_directories(outputPath.parent_path(), ec);
        if (ec) {
            std::cerr << "Failed to create schema directory: " << outputPath.parent_path() << '\n';
            return 1;
        }
    }

    const auto json = SSF::KernelMessageSchemaCatalog::RenderJson(SSF::KernelMessageSchemaCatalog::GetSchemas());
    if (!WriteTextFile(outputPath, json)) {
        std::cerr << "Failed to write kernel schema catalog: " << outputPath << '\n';
        return 1;
    }

    std::cout << "Exported kernel message schema catalog to " << outputPath.string() << '\n';
    return 0;
}

[[nodiscard]] int Bootstrap(const std::filesystem::path& outputDirectory) {
    std::error_code ec;
    std::filesystem::create_directories(outputDirectory, ec);
    if (ec) {
        std::cerr << "Failed to create bootstrap directory: " << outputDirectory << '\n';
        return 1;
    }

    if (const int surfaceStatus = ExportSurfaceMap(outputDirectory / "attack-surface-map.json");
        surfaceStatus != 0) {
        return surfaceStatus;
    }

    if (const int schemaStatus = ExportKernelSchemas(outputDirectory / "kernel-message-schemas.json");
        schemaStatus != 0) {
        return schemaStatus;
    }

    if (const int seedStatus = ExportKernelSeeds(outputDirectory / "kernel-seeds");
        seedStatus != 0) {
        return seedStatus;
    }

    return ExportKernelVariants(outputDirectory / "kernel-variants");
}

}  // namespace

int wmain(int argc, wchar_t* argv[]) {
    if (argc <= 1) {
        PrintUsage();
        return 0;
    }

    const std::wstring_view command = argv[1];

    if (command == L"--list-targets") {
        for (const auto& surface : SSF::AttackSurfaceRegistry::GetDefaultRegistry()) {
            std::cout << surface.id << " | " << surface.component << " | "
                      << surface.protocolOrFormat << '\n';
        }
        return 0;
    }

    if (command == L"--describe-target") {
        if (argc < 3) {
            std::cerr << "--describe-target requires an id\n";
            return 1;
        }

        const std::string id = NarrowAscii(argv[2]);
        if (id.empty()) {
            std::cerr << "Target ids must be ASCII\n";
            return 1;
        }

        const auto* surface = SSF::AttackSurfaceRegistry::FindById(id);
        if (surface == nullptr) {
            std::cerr << "Unknown target id: " << id << '\n';
            return 1;
        }

        std::cout << SSF::AttackSurfaceRegistry::DescribeText(*surface);
        return 0;
    }

    if (command == L"--export-surface-map") {
        if (argc < 3) {
            std::cerr << "--export-surface-map requires an output path\n";
            return 1;
        }

        return ExportSurfaceMap(argv[2]);
    }

    if (command == L"--export-kernel-schemas") {
        if (argc < 3) {
            std::cerr << "--export-kernel-schemas requires an output path\n";
            return 1;
        }

        return ExportKernelSchemas(argv[2]);
    }

    if (command == L"--export-kernel-seeds") {
        if (argc < 3) {
            std::cerr << "--export-kernel-seeds requires an output directory\n";
            return 1;
        }

        return ExportKernelSeeds(argv[2]);
    }

    if (command == L"--export-kernel-variants") {
        if (argc < 3) {
            std::cerr << "--export-kernel-variants requires an output directory\n";
            return 1;
        }

        return ExportKernelVariants(argv[2]);
    }

    if (command == L"--bootstrap") {
        if (argc < 3) {
            std::cerr << "--bootstrap requires an output directory\n";
            return 1;
        }

        return Bootstrap(argv[2]);
    }

    std::cerr << "Unknown command\n";
    PrintUsage();
    return 1;
}
