#include "pch.h"
#include <malloc.h>
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