#pragma once

#ifdef _KERNEL_MODE
    #include <fltKernel.h>
#else
    #include <windows.h>
#endif

#define SHADOWSTRIKE_DRIVER_NAME     L"ShadowStrikeFlt"
#define SHADOWSTRIKE_DRIVER_VERSION  L"3.0.0"

// Buffer sizes
#define MAX_FILE_PATH_LENGTH 1024
#define MAX_PROCESS_NAME_LENGTH 260
