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
#include "server.h"

#include "shared_util.h"

#include "Config.h"

#include <polyhook2/IHook.hpp>
#include <polyhook2/Detour/NatDetour.hpp>

static HANDLE hMapFile;
static LPVOID lpMemFile;

EXTERN_HOOK(NtReadFile);
EXTERN_HOOK(NtWriteFile);
EXTERN_HOOK(ReadConsoleA);
EXTERN_HOOK(ReadConsoleW);
EXTERN_HOOK(RtlAdjustPrivilege);
EXTERN_HOOK(OpenProcess);
EXTERN_HOOK(CreateRemoteThread);
EXTERN_HOOK(CreateRemoteThreadEx);
EXTERN_HOOK(WriteProcessMemory);
EXTERN_HOOK(ReadProcessMemory);
EXTERN_HOOK(CreateProcessW);
EXTERN_HOOK(CreateProcessA);
EXTERN_HOOK(NtCreateUserProcess);
EXTERN_HOOK(CoCreateInstance);

// Install the hooks
void InstallInitialHooks(LunaAPI::HookFlags flags, LunaAPI::MitigationFlags mitigations, LunaAPI::LogFlags logs) {
    CONDITIONAL_REGISTER_HOOK(flags, "ole32.dll", CoCreateInstance, mitigations, logs);
    CONDITIONAL_REGISTER_HOOK(flags, "ntdll.dll", NtReadFile, mitigations, logs);
    CONDITIONAL_REGISTER_HOOK(flags, "ntdll.dll", NtWriteFile, mitigations, logs);
    CONDITIONAL_REGISTER_HOOK(flags, "ntdll.dll", RtlAdjustPrivilege, mitigations, logs);
    CONDITIONAL_REGISTER_HOOK(flags, "ntdll.dll", NtCreateUserProcess, mitigations, logs);
    CONDITIONAL_REGISTER_HOOK(flags, "kernel32.dll", OpenProcess, mitigations, logs);
    CONDITIONAL_REGISTER_HOOK(flags, "kernel32.dll", CreateRemoteThread, mitigations, logs);
    CONDITIONAL_REGISTER_HOOK(flags, "kernel32.dll", CreateRemoteThreadEx, mitigations, logs);
    CONDITIONAL_REGISTER_HOOK(flags, "kernel32.dll", WriteProcessMemory, mitigations, logs);
    CONDITIONAL_REGISTER_HOOK(flags, "kernel32.dll", ReadProcessMemory, mitigations, logs);
    CONDITIONAL_REGISTER_AW_HOOK(flags, "kernel32.dll", CreateProcess, mitigations, logs);
    CONDITIONAL_REGISTER_AW_HOOK(flags, "kernel32.dll", ReadConsole, mitigations, logs);
}

BOOL CloseShare() {
    if (hMapFile != NULL) {
        UnmapViewOfFile(lpMemFile);
        CloseHandle(hMapFile);
        return TRUE;
    }
    return FALSE;
}

BOOL LoadConfig(LunaAPI::LunaStart config) {
    // Connect to named mutex for further communication

    WRITELINE_DEBUG("Hello, my name is " << config.id << "!");

    // Initialise hooks
    SetDefaultMitigations(config.mitigations);
    SetDefaultLogs(config.logs);
    InstallInitialHooks(config.hooks, config.mitigations, config.logs);
    WRITELINE_DEBUG("Installed hooks!");

    CloseShare();
    
    // Start the RPC server
    HANDLE hThread = CreateThread(
        NULL,                               // Default security attributes
        0,                                  // Default stack size
        (LPTHREAD_START_ROUTINE)BeginPipe,  // Thread function
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
        if (!InitShare(hModule)) {
            WRITELINE_DEBUG("Could not set up shared memory.");
        }
        WRITELINE_DEBUG("Initialised share memory...");

        if (!OpenLogger()) {
            WRITELINE_DEBUG("Could not open logger.");
        }
        WRITELINE_DEBUG("Started logger!");

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
