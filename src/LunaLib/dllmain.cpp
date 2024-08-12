// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
// Kernel and advapi32
#include <Windows.h>
#include <securitybaseapi.h>
// Others
#include <ntstatus.h>
#include <iostream>

#include <userenv.h>

#include <psapi.h>
#include <dbghelp.h>

#include <wincred.h>

#include "hooks.h"

// Debug logs
void LogLine(const char* message) {
#if _DEBUG
    std::cerr << message << std::endl;
#endif
}
void Log(const char* message) {
#if _DEBUG
    std::cerr << message;
#endif
}

// This may need improvement, unsure on stability
bool InstallHookV2(IN LPCSTR moduleName, IN LPCSTR functionName, IN void* hookFunction, OUT void* originalFunction) {
    HMODULE hModule = GetModuleHandle(NULL);
    if (hModule == NULL) {
        LogLine("Failed to get module handle");
        return false;
    }

    // Get a handle on program imports
    ULONG size;
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);
    // We need this to access DLL info
    if (importDesc == NULL) {
        LogLine("Failed to get import descriptor");
        return false;
    }

    // Loop through each import
    while (importDesc->Name) {
        // Construct the module name
        const char* modName = (const char*)((BYTE*)hModule + importDesc->Name);
        // Check if we have the library we want to hook into
        // This is case insensitive
        if (_stricmp(modName, moduleName) == 0) {
            // ?????????
            // https://stackoverflow.com/questions/2641489/what-is-a-thunk
            // This is where the magic happens
            // Unfortunately, I do not fully understand the magic yet
            // Here is where we find our function though
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);
            while (thunk->u1.Function) {
                FARPROC* pfn = (FARPROC*)&thunk->u1.Function;
                FARPROC fn = (FARPROC)GetProcAddress(GetModuleHandleA(moduleName), functionName);

                // Is this our function?
                if (fn == (FARPROC)*pfn) {
                    // Now we hook

                    // Unprotect the memory containing the function address and save the old protection
                    DWORD oldProtect;
                    VirtualProtect(pfn, sizeof(FARPROC), PAGE_EXECUTE_READWRITE, &oldProtect);

                    // Save original
                    originalFunction = *pfn;
                    // Set function address to our function
                    *pfn = (FARPROC)hookFunction;
                    // Reapply page protection
                    VirtualProtect(pfn, sizeof(FARPROC), oldProtect, &oldProtect);

                    // Let the user know we succeeded
                    Log("Successfully hooked ");
                    LogLine(functionName);
                    return true;
                }
                thunk++;
            }
        }
        importDesc++;
    }

    // :(
    Log("Failed to hook ");
    LogLine(functionName);
    return false;
}

// Install the hooks
void InstallHooksV2() {
#if _DEBUG
    QUICK_HOOK("user32.dll", MessageBoxA);
#endif
    // Testing for now
    QUICK_HOOK("ntdll.dll", RtlAdjustPrivilege);
    QUICK_HOOK("kernel32.dll", WriteFile);
    QUICK_HOOK("kernel32.dll", ReadFile);
    QUICK_HOOK("ntdll.dll", NtReadFile);

    // Privilege adjust
    QUICK_HOOK("kernel32.dll", AdjustTokenPrivileges);
    QUICK_HOOK("ntdll.dll", ZwAdjustPrivilegesToken);
    QUICK_HOOK("ntdll.dll", NtAdjustPrivilegesToken);

    // Remote processes
    QUICK_HOOK("kernel32.dll", OpenProcess);
    QUICK_HOOK("kernel32.dll", CreateRemoteThread);
    QUICK_HOOK("kernel32.dll", CreateRemoteThreadEx);
    QUICK_HOOK("kernel32.dll", WriteProcessMemory);
    QUICK_HOOK("kernel32.dll", ReadProcessMemory);

    // Process start
    QUICK_HOOK("kernel32.dll", CreateProcessW);
    QUICK_HOOK("kernel32.dll", CreateProcessA);

    //QUICK_HOOK("msvcrt.dll", fgets);
    //QUICK_HOOK("msvcrt.dll", fgetws);
    //QUICK_HOOK("msvcrt.dll", _read);
}

// This code is run on injection
__declspec(dllexport) BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        LogLine("Attached to process");
        InstallHooksV2();
        break;
    case DLL_THREAD_ATTACH:
        // These logs are quite verbose, so commented out even for testing by default
        //LogLine("Attached to thread");
        break;
    case DLL_THREAD_DETACH:
        //LogLine("Detached from thread");
        break;
    case DLL_PROCESS_DETACH:
        LogLine("Detached from process");
        break;
    }
    return TRUE;
}
