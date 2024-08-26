#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>

#include "output.h"

DWORD FindPidByName(LPCSTR name) {
    // Take a snapshot of all processes in the system
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot." << std::endl;
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process
    // Only supports wide strings
    if (!Process32First(hProcessSnap, &pe32)) {
        std::cerr << "Failed to retrieve the first process." << std::endl;
        CloseHandle(hProcessSnap);
        return 0;
    }

    // Iterate over the processes
    do {
        // Compare the process name
        if (!strcmp(pe32.szExeFile, name)) {
            // Process found, return the process ID
            CloseHandle(hProcessSnap);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    // Process not found
    CloseHandle(hProcessSnap);
    DISP_WARN("Could not find process ID from '" << name << "'");
    return 0;
}

bool NoCapCmp(const char* string, const char* other, size_t length) {
    for (size_t i = 0; i < length; i++) {
        // Correct capitals
        char c1, c2;

        if (string[i] >= 'A' && string[i] <= 'Z')
            c1 = string[i] + 32;
        else c1 = string[i];

        if (other[i] >= 'A' && other[i] <= 'Z')
            c2 = other[i] + 32;
        else c2 = other[i];

        if (c1 != c2) {
            return false;
        }
    }
}
bool NoCapCmp(const char* string, const char* other) {
    size_t i = 0;
    while (true) {
        if (string[i] == 0) {
            return other[i] == 0;
        } else if (other[i] == 0) {
            return string[i] == 0;
        }

        // Correct capitals
        char c1, c2;

        if (string[i] >= 'A' && string[i] <= 'Z')
            c1 = string[i] + 32;
        else c1 = string[i];

        if (other[i] >= 'A' && other[i] <= 'Z')
            c2 = other[i] + 32;
        else c2 = other[i];

        if (c1 != c2) {
            return false;
        }

        i++;
    }
}

// Perhaps make this secure?
void RandomString(char* buffer, const char* options, size_t length) {
    size_t numOptions = strlen(options);
    for (size_t i = 0; i < length; i++) {
        buffer[i] = options[rand() % numOptions];
    }
}