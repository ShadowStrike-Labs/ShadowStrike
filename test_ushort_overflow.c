// Test USHORT wraparound in C
#include <stdio.h>
#include <windows.h>

int main() {
    USHORT starSi;
    
    // Test 1: Increment at max boundary
    starSi = 65535;
    printf("starSi = 65535 (0xFFFF)\n");
    starSi++;
    printf("After starSi++: %u (0x%04X)\n", starSi, starSi);
    
    // Test 2: Increment near UNICODE_STRING max
    starSi = 32766;
    printf("\nstarSi = 32766\n");
    starSi++;
    printf("After starSi++: %u\n", starSi);
    starSi++;
    printf("After starSi++: %u\n", starSi);
    
    // Test 3: What's the actual max from UNICODE_STRING?
    printf("\nMax UNICODE_STRING.Length = 65535 bytes\n");
    printf("Max chars = 65535 / 2 = %u\n", 65535/2);
    printf("But wait, Length must be even (WCHAR-aligned)\n");
    printf("So max Length = 65534 bytes\n");
    printf("Max chars = 65534 / 2 = %u\n", 65534/2);
    
    return 0;
}
