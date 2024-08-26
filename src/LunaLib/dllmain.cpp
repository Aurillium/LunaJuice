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

#include "shared.h"

#include "include/capstone/capstone.h"

static HANDLE hMapFile;
static LPVOID lpMemFile;

// Install the hooks
void InstallHooks(HookFlags flags) {
#if _DEBUG
    EXTERN_HOOK(MessageBoxA);
    QUICK_HOOK("user32.dll", MessageBoxA);
#endif

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

    // File read/write
    if (flags & Enable_NtReadFile) {
        QUICK_HOOK_V3("ntdll.dll", NtReadFile);
    }
    if (flags & Enable_NtWriteFile) {
        QUICK_HOOK_V3("ntdll.dll", NtWriteFile);
    }
    // Console read
    if (flags & Enable_ReadConsole) {
        QUICK_HOOK_V4("kernel32.dll", ReadConsoleA);
        QUICK_HOOK_V4("kernel32.dll", ReadConsoleW);
    }
    
    if (flags & Enable_RtlAdjustPrivilege) {
        QUICK_HOOK_V4("ntdll.dll", RtlAdjustPrivilege);
    }

    // Remote processes
    if (flags & Enable_OpenProcess) {
        QUICK_HOOK_V4("kernel32.dll", OpenProcess);
    }
    if (flags & Enable_CreateRemoteThread) {
        QUICK_HOOK_V4("kernel32.dll", CreateRemoteThread);
        QUICK_HOOK_V4("kernel32.dll", CreateRemoteThreadEx);
    }
    if (flags & Enable_WriteProcessMemory) {
        QUICK_HOOK_V4("kernel32.dll", WriteProcessMemory);
    }
    if (flags & Enable_ReadProcessMemory) {
        QUICK_HOOK_V4("kernel32.dll", ReadProcessMemory);
    }
    
    // Process start
    if (flags & Enable_CreateProcess) {
        QUICK_HOOK_V4("kernel32.dll", CreateProcessW);
        QUICK_HOOK_V4("kernel32.dll", CreateProcessA);
    }
    if (flags & Enable_NtCreateUserProcess) {
        QUICK_HOOK_V3("ntdll.dll", NtCreateUserProcess);
    }
}

BOOL CloseShare() {
    if (hMapFile != NULL) {
        UnmapViewOfFile(lpMemFile);
        CloseHandle(hMapFile);
        return TRUE;
    }
    return FALSE;
}

BOOL LoadConfig(LunaStart config) {
    // Connect to named mutex for further communication

    WRITELINE_DEBUG("Hello, my name is " << config.id << "!");

    // Initialise hooks
    InstallHooks(config.hooks);
    WRITELINE_DEBUG("Installed hooks!");

    CloseShare();

    return TRUE;
}


// Set up and populate shared memory for init
BOOL InitShare(HMODULE hModule) {
    LunaShared shared;

    // Get a handle to our file map
    hMapFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, SHARED_GLOBAL_NAME);
    if (hMapFile == NULL) {
        WRITELINE_DEBUG("Could not open global file mapping.");

        // Try open session mapping if there's no global one
        hMapFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, SHARED_GLOBAL_NAME);
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
    memset(lpMemFile, 0, sizeof(LunaShared));
    shared.hModule = hModule;
    shared.lpInit = (LPDWORD)LoadConfig;
    shared.dwOffset = (DWORD)shared.lpInit - (DWORD)shared.hModule;
    memcpy(lpMemFile, &shared, sizeof(LunaShared));

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
