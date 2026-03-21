#include <iostream>
#include <cstdint>

int main() {
    size_t blockSize = 16;
    uint8_t padLen = 5;
    
    std::cout << "Testing mask computation for blockSize=" << blockSize << ", padLen=" << static_cast<int>(padLen) << "\n\n";
    
    for (size_t i = 0; i < blockSize; ++i) {
        bool shouldBePadding = i >= (blockSize - static_cast<size_t>(padLen));
        
        // The actual code's mask computation
        int condition = i >= (blockSize - static_cast<size_t>(padLen));
        int negated = -condition;  // 0 becomes 0x00000000, 1 becomes 0xFFFFFFFF
        uint8_t mask = static_cast<uint8_t>(negated);  // Truncate to 0x00 or 0xFF
        
        std::cout << "i=" << i << ": condition=" << condition 
                  << ", -condition=" << negated 
                  << ", mask=0x" << std::hex << static_cast<int>(mask) << std::dec
                  << ", expected=" << (shouldBePadding ? "0xFF" : "0x00") << "\n";
    }
    
    return 0;
}
