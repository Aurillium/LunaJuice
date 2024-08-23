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