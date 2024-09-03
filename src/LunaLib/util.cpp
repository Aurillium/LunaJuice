#include "pch.h"
#include <malloc.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <windows.h>
#include <winternl.h>

#include "debug.h"

#include "Config.h"

char* ConvertUnicodeStringToAnsi(const UNICODE_STRING& unicodeString) {
    // Determine the required buffer size
    int bufferSize = WideCharToMultiByte(
        CP_ACP,               // Code page: ANSI code page
        0,                    // No special flags
        unicodeString.Buffer, // Source wide-char string
        unicodeString.Length / sizeof(WCHAR), // Number of characters
        NULL,                 // No conversion yet, just calculating size
        0,                    // No buffer yet
        NULL,                 // No default char replacement
        NULL                  // Don't care about default char usage
    );

    // Return NULL on fail
    if (bufferSize == 0) {
        return NULL;
    }

    // Allocate the buffer
    char* ansiString = (char*)malloc(bufferSize + 1); // +1 for null-terminator
    // Return NULL on fail
    if (ansiString == NULL) {
        return NULL;
    }

    // Perform the actual conversion
    WideCharToMultiByte(
        CP_ACP,               // Code page: ANSI code page
        0,                    // No special flags
        unicodeString.Buffer, // Source wide-char string
        unicodeString.Length / sizeof(WCHAR), // Number of characters
        ansiString,           // Destination buffer
        bufferSize,           // Buffer size
        NULL,                 // No default char replacement
        NULL                  // Don't care about default char usage
    );

    // Null-terminate the string
    ansiString[bufferSize] = '\0';

    return ansiString;
}

// https://gist.github.com/mattn/253013/d47b90159cf8ffa4d92448614b748aa1d235ebe4
DWORD GetParentProcessId(DWORD pid) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD ppid = 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    __try {
        if (hSnapshot == INVALID_HANDLE_VALUE) __leave;

        ZeroMemory(&pe32, sizeof(pe32));
        pe32.dwSize = sizeof(pe32);
        if (!Process32First(hSnapshot, &pe32)) __leave;

        do {
            if (pe32.th32ProcessID == pid) {
                ppid = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));

    }
    __finally {
        if (hSnapshot != INVALID_HANDLE_VALUE && hSnapshot != NULL) CloseHandle(hSnapshot);
    }
    return ppid;
}

LPSTR OptimalSprintf(LPCSTR fmt, ...) {
    va_list args, argsCopy;
    va_start(args, fmt);
    va_copy(argsCopy, args);

    size_t bufferSize = vsnprintf(NULL, 0, fmt, args);
    LPSTR buffer = (LPSTR)calloc(bufferSize + 1, sizeof(CHAR));
    if (buffer == NULL) {
        WRITELINE_DEBUG("Could not allocate space for buffer.");
        return NULL;
    }

    vsprintf_s(buffer, bufferSize + 1, fmt, argsCopy);

    va_end(argsCopy);
    va_end(args);

    return buffer;
}

char FlagIndex(LunaAPI::HookFlags flag) {
    char index = 0;
    size_t value = flag;
    while (!(value & 1) || index == sizeof(LunaAPI::HookFlags) * 8) {
        value >>= 1;
    }
    return index;
}