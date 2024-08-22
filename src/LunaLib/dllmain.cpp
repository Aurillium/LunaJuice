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

#include "include/capstone/capstone.h"

// Install the hooks
void InstallHooks() {
#if _DEBUG
    EXTERN_HOOK(MessageBoxA);
    QUICK_HOOK_V4("user32.dll", MessageBoxA);
#endif
    EXTERN_HOOK(NtReadFile);
    EXTERN_HOOK(NtWriteFile);
    QUICK_HOOK_V3("ntdll.dll", NtReadFile);
    //QUICK_HOOK_V3("ntdll.dll", NtWriteFile); // Odd outputs, unreliable
    EXTERN_HOOK(ReadConsoleA);
    EXTERN_HOOK(ReadConsoleW);
    QUICK_HOOK_V4("kernel32.dll", ReadConsoleA);
    QUICK_HOOK_V4("kernel32.dll", ReadConsoleW);

    // Privilege adjust
    EXTERN_HOOK(RtlAdjustPrivilege);
    EXTERN_HOOK(ZwAdjustPrivilegesToken);
    EXTERN_HOOK(NtAdjustPrivilegesToken);
    QUICK_HOOK_V4("ntdll.dll", RtlAdjustPrivilege);
    //QUICK_HOOK_V3("ntdll.dll", ZwAdjustPrivilegesToken); // Broken
    //QUICK_HOOK_V3("ntdll.dll", NtAdjustPrivilegesToken); // Broken

    // Remote processes
    EXTERN_HOOK(OpenProcess);
    EXTERN_HOOK(CreateRemoteThread);
    EXTERN_HOOK(CreateRemoteThreadEx);
    EXTERN_HOOK(WriteProcessMemory);
    EXTERN_HOOK(ReadProcessMemory);
    QUICK_HOOK_V4("kernel32.dll", OpenProcess);
    QUICK_HOOK_V4("kernel32.dll", CreateRemoteThread);
    QUICK_HOOK_V4("kernel32.dll", CreateRemoteThreadEx);
    QUICK_HOOK_V4("kernel32.dll", WriteProcessMemory);
    QUICK_HOOK_V4("kernel32.dll", ReadProcessMemory);

    // Process start
    EXTERN_HOOK(CreateProcessW);
    EXTERN_HOOK(CreateProcessA);
    QUICK_HOOK_V4("kernel32.dll", CreateProcessW);
    QUICK_HOOK_V4("kernel32.dll", CreateProcessA);
    EXTERN_HOOK(NtCreateUserProcess);
    QUICK_HOOK_V3("ntdll.dll", NtCreateUserProcess);

    //QUICK_HOOK("msvcrt.dll", fgets);
    //QUICK_HOOK("msvcrt.dll", fgetws);
    //QUICK_HOOK("msvcrt.dll", _read);

    WRITELINE_DEBUG((void*)Real_NtReadFile);
}

// This code is run on injection
__declspec(dllexport) BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        WRITELINE_DEBUG("Attached to process");
        OpenLogger();
        WRITELINE_DEBUG("Started logger!");
        InstallHooks();
        WRITELINE_DEBUG("Installed hooks!");
        break;
    case DLL_THREAD_ATTACH:
        // These logs are quite verbose, so commented out even for testing by default
        //WRITELINE_DEBUG("Attached to thread");
        break;
    case DLL_THREAD_DETACH:
        //WRITELINE_DEBUG("Detached from thread");
        break;
    case DLL_PROCESS_DETACH:
        WRITELINE_DEBUG("Detaching from process");
        CloseLogger();
        WRITELINE_DEBUG("Closed logger!");
        break;
    }
    return TRUE;
}
