#pragma once

#include <evntprov.h>

typedef unsigned short USHORT;
typedef unsigned char UCHAR;

// ETW Event descriptor creation macro
// Creates an EVENT_DESCRIPTOR structure with proper initialization
#define MAKE_EVT_DESCRIPTOR(EventId, Level) \
    { \
        static_cast<USHORT>(ThreadPoolEventId::EventId), \
        0, \
        0, \
        static_cast<UCHAR>(Level), \
        0, \
        0, \
        0 \
    }

enum class ThreadPoolEventId : USHORT {
    ThreadPoolCreated,
    ThreadPoolDestroyed,
    ThreadPoolTaskSubmitted,
    ThreadPoolTaskStarted,
    ThreadPoolTaskCompleted,
    ThreadPoolThreadCreated,
    ThreadPoolThreadDestroyed,
    ThreadPoolPaused,
    ThreadPoolResumed,
    ThreadPoolResized,
    ThreadPoolGroupCreated,
    ThreadPoolGroupWaitComplete,
    ThreadPoolGroupCancelled,
	MaxEventId //always at the end
};
