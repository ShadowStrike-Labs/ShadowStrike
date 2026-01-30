
#ifndef NT_UNDOCUMENTED_H
#define NT_UNDOCUMENTED_H


#include <Windows.h>


typedef struct _KSYSTEM_TIME {
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} KSYSTEM_TIME, * PKSYSTEM_TIME;


typedef struct _KUSER_SHARED_DATA {
    ULONG                         TickCountLowDeprecated;
    ULONG                         TickCountMultiplier;
    volatile KSYSTEM_TIME         InterruptTime;
    volatile KSYSTEM_TIME         SystemTime;
    volatile KSYSTEM_TIME         TimeZoneOffset;

}KUSER_SHARED_DATA, *KUSER_SHARED_DATA;



#endif // NT_UNDOCUMENTED_H