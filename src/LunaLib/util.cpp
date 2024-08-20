#include "pch.h"
#include <malloc.h>
#include <tlhelp32.h>
#include <windows.h>
#include <winternl.h>

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