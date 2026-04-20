// tlsh.h i�indeki __attribute__ sorununu ��zmek i�in
// tlsh.h dosyas�n�n EN BA�INA (ilk include'dan �NCE) bunu ekle:

#ifndef TLSH_COMPAT_H
#define TLSH_COMPAT_H

// Windows MSVC uyumlulu�u
#ifdef _MSC_VER
#define __attribute__(x)
#define __extension__
// Uyar�lar� bast�r - TLSH kodu POSIX fonklar� kullan�yor
#pragma warning(disable: 4996)  // deprecated function warnings
#pragma warning(disable: 4267)  // conversion warnings
#define _CRT_SECURE_NO_WARNINGS
#endif

// dirent.h uyumlulu�u
#ifdef _WIN32
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// Windows i�in dirent.h replacement
typedef struct {
    HANDLE handle;
    WIN32_FIND_DATAA data;
    int first;
} DIR;

struct dirent {
    char d_name[260];
};

inline DIR* opendir(const char* name) {
    DIR* dir = (DIR*)malloc(sizeof(DIR));
    char path[MAX_PATH];
    snprintf(path, MAX_PATH, "%s\\*", name);
    dir->handle = FindFirstFileA(path, &dir->data);
    dir->first = 1;
    if (dir->handle == INVALID_HANDLE_VALUE) {
        free(dir);
        return NULL;
    }
    return dir;
}

inline struct dirent* readdir(DIR* dir) {
    if (!dir) return NULL;
    static struct dirent entry;
    if (dir->first) {
        dir->first = 0;
    }
    else {
        if (!FindNextFileA(dir->handle, &dir->data))
            return NULL;
    }
    strcpy_s(entry.d_name, sizeof(entry.d_name), dir->data.cFileName);
    return &entry;
}

inline int closedir(DIR* dir) {
    if (dir) {
        FindClose(dir->handle);
        free(dir);
    }
    return 0;
}

// POSIX string fonksiyonlar� replacement
#ifndef strdup
#define strdup _strdup
#endif

#ifndef snprintf
#define snprintf _snprintf
#endif

#else
#include <dirent.h>
#endif

#endif // TLSH_COMPAT_H