// Test if volatile prevents optimization
#include <iostream>
#include <cstdint>

bool ConstantTimeEqual_Volatile(const char* a, const char* b, size_t len) {
    volatile unsigned char acc = 0;
    for (size_t i = 0; i < len; ++i) {
        acc |= a[i] ^ b[i];
    }
    return acc == 0;
}

bool ConstantTimeEqual_NonVolatile(const char* a, const char* b, size_t len) {
    unsigned char acc = 0;
    for (size_t i = 0; i < len; ++i) {
        acc |= a[i] ^ b[i];
    }
    return acc == 0;
}

int main() {
    const char* s1 = "test_token_44_chars_exactly_for_base64_check";
    const char* s2 = "test_token_44_chars_exactly_for_base64_check";
    std::cout << "Volatile version: " << ConstantTimeEqual_Volatile(s1, s2, 44) << std::endl;
    std::cout << "Non-volatile version: " << ConstantTimeEqual_NonVolatile(s1, s2, 44) << std::endl;
    return 0;
}
