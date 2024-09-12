// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
// Kernel and advapi32
#include <Windows.h>
#include <securitybaseapi.h>
// Others
#include <iostream>

#include "debug.h"
#include "events.h"
#include "hooks.h"
#include "mitigations.h"
#include "pyhooking.h"
#include "server.h"

#include "shared_util.h"

#include "Config.h"

#include <polyhook2/IHook.hpp>
#include <polyhook2/Detour/NatDetour.hpp>

#include "include/python/Python.h"

static HANDLE hMapFile;
static LPVOID lpMemFile;

void PyHook() {
    // This works
    //Py_Initialize();
    WRITELINE_DEBUG("About to init");
    BOOL success = PySetupHook(R"(
def hookfunc(a, b, c):
    print("Hooked:", a, b, c)
    original_function(a, b, c)
)", "hookfunc", "test_function", NULL, NULL);
}

// Install the hooks
void PrepareHooks() {
    PREPARE_HOOK("ole32.dll", CoCreateInstance);
    PREPARE_HOOK("ntdll.dll", NtReadFile);
    PREPARE_HOOK("ntdll.dll", NtWriteFile);
    PREPARE_HOOK("ntdll.dll", RtlAdjustPrivilege);
    PREPARE_HOOK("ntdll.dll", NtCreateUserProcess);
    PREPARE_HOOK("kernel32.dll", OpenProcess);
    PREPARE_HOOK("kernel32.dll", CreateRemoteThread);
    PREPARE_HOOK("kernel32.dll", CreateRemoteThreadEx);
    PREPARE_HOOK("kernel32.dll", WriteProcessMemory);
    PREPARE_HOOK("kernel32.dll", ReadProcessMemory);
    PREPARE_HOOK("kernel32.dll", CreateProcessA);
    PREPARE_HOOK("kernel32.dll", CreateProcessW);
    PREPARE_HOOK("kernel32.dll", ReadConsoleA);
    PREPARE_HOOK("kernel32.dll", ReadConsoleW);
}

BOOL CloseShare() {
    if (hMapFile != NULL) {
        UnmapViewOfFile(lpMemFile);
        CloseHandle(hMapFile);
        return TRUE;
    }
    return FALSE;
}

// This is called by the host
BOOL LoadConfig(LunaAPI::LunaStart config) {
    // Connect to named mutex for further communication

    WRITELINE_DEBUG("Hello, my name is " << config.id << "!");

    // Initialise hooks
    SetDefaultMitigations(config.mitigations);
    SetDefaultLogs(config.logs);
    //InstallInitialHooks(config.hooks, config.mitigations, config.logs);
    WRITELINE_DEBUG("Installed hooks!");

    CloseShare();
    
    // Start the RPC server
    HANDLE hThread = CreateThread(
        NULL,                               // Default security attributes
        0,                                  // Default stack size
        (LPTHREAD_START_ROUTINE)BeginServer,// Thread function
        &config.id,                         // Thread function arguments
        0,                                  // Default creation flags
        NULL);                              // No thread identifier needed

    if (hThread == NULL) {
        WRITELINE_DEBUG("Could not create thread.");
        return FALSE;
    }

    CloseHandle(hThread);

    return TRUE;
}


// Set up and populate shared memory for init
BOOL InitShare(HMODULE hModule) {
    LunaAPI::LunaShared shared;

    // Get a handle to our file map
    hMapFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, SHARED_GLOBAL_NAME);
    if (hMapFile == NULL) {
        WRITELINE_DEBUG("Could not open global file mapping.");

        // Try open session mapping if there's no global one
        hMapFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, SHARED_SESSION_NAME);
        if (hMapFile == NULL) {
            // Fail if neither work
            WRITELINE_DEBUG("Could not open session file mapping.");
            return FALSE;
        }
    }

    // Get our shared memory pointer
    lpMemFile = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (lpMemFile == NULL) {
        WRITELINE_DEBUG("Could not map shared memory.");
        return FALSE;
    }

    // Set shared memory to hold what our remote process needs
    memset(lpMemFile, 0, sizeof(LunaAPI::LunaShared));
    shared.hModule = hModule;
    shared.lpInit = (LPDWORD)LoadConfig;
    shared.dwOffset = (DWORD)shared.lpInit - (DWORD)shared.hModule;
    memcpy(lpMemFile, &shared, sizeof(LunaAPI::LunaShared));

    return TRUE;
}

// This code is run on injection
__declspec(dllexport) BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {    
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        WRITELINE_DEBUG("Attached to process...");
        PrepareHooks();
        WRITELINE_DEBUG("Prepared hooks!");
        if (!InitialiseCPython()) {
            WRITELINE_DEBUG("Failed to initialise Python runtime.");
        }
        else {
            WRITELINE_DEBUG("Initialised Python runtime!");
            PyHook();
        }

        if (!InitShare(hModule)) {
            WRITELINE_DEBUG("Could not set up shared memory.");
        }
        else {
            WRITELINE_DEBUG("Initialised share memory!");
        }

        if (!OpenLogger()) {
            WRITELINE_DEBUG("Could not open logger.");
        }
        else {
            WRITELINE_DEBUG("Started logger!");
        }

        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        WRITELINE_DEBUG("Detaching from process");
        if (CloseShare()) {
            WRITELINE_DEBUG("Closed shared memory, was it used?");
        } else {
            WRITELINE_DEBUG("Shared memory was already closed!");
        }
        CloseLogger();
        WRITELINE_DEBUG("Closed logger and we are out!");
        break;
    }

    return TRUE;
}
