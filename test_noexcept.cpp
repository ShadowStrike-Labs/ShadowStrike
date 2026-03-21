#include <string>
#include <vector>
#include <iostream>
#include <type_traits>

int main() {
    std::cout << "std::string(string&&) noexcept: " 
              << std::is_nothrow_move_constructible<std::string>::value << std::endl;
    std::cout << "std::vector<uint8_t>(vector&&) noexcept: " 
              << std::is_nothrow_move_constructible<std::vector<uint8_t>>::value << std::endl;
    return 0;
}
