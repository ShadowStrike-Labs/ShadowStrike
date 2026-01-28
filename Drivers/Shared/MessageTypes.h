#pragma once

typedef enum _SHADOWSTRIKE_MESSAGE_TYPE {
    FilterMessageType_None = 0,
    FilterMessageType_Register,           // User-mode service registering
    FilterMessageType_Unregister,         // User-mode service disconnecting
    FilterMessageType_Heartbeat,          // Keep-alive
    FilterMessageType_ConfigUpdate,       // Configuration update

    // Scans
    FilterMessageType_ScanRequest,        // File scan request (Pre-Create/Write)
    FilterMessageType_ScanVerdict,        // Verdict reply

    // Behavioral Notifications
    FilterMessageType_ProcessNotify,      // Process creation/termination
    FilterMessageType_ThreadNotify,       // Remote thread creation
    FilterMessageType_ImageLoad,          // Image load (DLL/Driver)
    FilterMessageType_RegistryNotify,     // Registry operation

    FilterMessageType_Max
} SHADOWSTRIKE_MESSAGE_TYPE;
