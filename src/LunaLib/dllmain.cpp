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

// Macro to make hooking easier
// Make sure you follow the naming format though!
// Hooked_{name}, Real_{name}
#define QUICK_HOOK(dll, name) (InstallHookV2(dll, #name, (void*)Hooked_##name, (void*)Real_##name))

// Based on Mimikatz usage (signature is from source)
extern "C" NTSTATUS WINAPI RtlAdjustPrivilege(IN ULONG Privilege, IN BOOL Enable, IN BOOL CurrentThread, OUT PULONG pPreviousState);

// Good code
typedef BOOL(__stdcall* WriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
// Priv adjust
typedef BOOL(__stdcall* AdjustTokenPrivileges_t)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
typedef NTSTATUS(__stdcall* RtlAdjustPrivilege_t)(IN ULONG, IN BOOL, IN BOOL, OUT PULONG);
//typedef DWORD(__stdcall* ZwAdjustPrivilegeToken_t)();

static WriteFile_t Real_WriteFile = WriteFile;
static AdjustTokenPrivileges_t Real_AdjustTokenPrivileges = AdjustTokenPrivileges;
static RtlAdjustPrivilege_t Real_RtlAdjustPrivilege = RtlAdjustPrivilege;
//static ZwAdjustPrivilegeToken_t Real_ZwAdjustPrivilegeToken = ZwAdjustPrivilegeToken;
// Need to work out params ^^^

// Does not get called
static BOOL __stdcall Hooked_WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    // Redirect file writes or modify behavior here
    std::cout << "File Write Hooked!" << std::endl;
    return Real_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}
static BOOL __stdcall Hooked_AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength) {
    // Redirect file writes or modify behavior here
    std::cout << "Token adjust hooked!" << std::endl;
    return Real_AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);
}
static NTSTATUS WINAPI Hooked_RtlAdjustPrivilege(IN ULONG Privilege, IN BOOL Enable, IN BOOL CurrentThread, OUT PULONG pPreviousState) {
    std::cout << "Faked sucessful escalation!" << std::endl;
    return 0xC0000061; // Permission denied
    // Success
    return 0;
}

typedef BOOL(__stdcall* ReadFile_t)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
static ReadFile_t Real_ReadFile = ReadFile;
BOOL WINAPI Hooked_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    BOOL result = Real_ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    if (/*hFile == GetStdHandle(STD_INPUT_HANDLE)*/true) {
        Log("Read ");
#if _DEBUG
        std::cout << lpNumberOfBytesRead;
#endif
        LogLine(" from stdin");
    }
    return result;
}

// For testing purposes only
#if _DEBUG
typedef BOOL(WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
static MessageBoxA_t Real_MessageBoxA = MessageBoxA;
BOOL WINAPI Hooked_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    std::cout << "Intercepted MessageBoxA called!" << std::endl;
    std::cout << "Text: " << lpText << std::endl;
    std::cout << "Caption: " << lpCaption << std::endl;
    BOOL result = Real_MessageBoxA(hWnd, "Hooked Function", lpCaption, uType);
    return result;
}
#endif


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
    QUICK_HOOK("ntdll.dll", RtlAdjustPrivilege);
    QUICK_HOOK("kernel32.dll", WriteFile);
    QUICK_HOOK("kernel32.dll", ReadFile);
    QUICK_HOOK("advapi32.dll", AdjustTokenPrivileges);
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
