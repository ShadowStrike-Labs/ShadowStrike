#include <filesystem>
#include <iostream>

int main() {
    std::filesystem::file_time_type default_time{};
    std::cout << "Default constructed: " << default_time.time_since_epoch().count() << std::endl;
    return 0;
}
