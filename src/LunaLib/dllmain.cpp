// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
// Kernel and advapi32
#include <Windows.h>
//#include <aclapi.h>
#include <securitybaseapi.h>
// Others
#include <ntstatus.h>
#include <detours.h>
#include <iostream>

#include <userenv.h>

#include <psapi.h>
#include <dbghelp.h>

// Mimikatz globals
//#include <ntstatus.h>
//#define WIN32_NO_STATUS
//#define SECURITY_WIN32
//#define CINTERFACE
//#define COBJMACROS
//#include <windows.h>
//#include <sspi.h>
//#include <sddl.h>
#include <wincred.h>
//#include <ntsecapi.h>
//#include <ntsecpkg.h>
//#include <stdio.h>
//#include <wchar.h>

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

#define QUICK_HOOK(dll, name) (InstallHookV2(dll, #name, (void*)Hooked_##name, (void*)Real_##name))

// Based on Mimikatz usage
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
    // No permissions
    return 0xC0000061; // https://joyasystems.com/list-of-ntstatus-codes
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

// REMOVE LATER
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



// This may need improvement, unsure on stability
bool InstallHookV2(LPCSTR moduleName, LPCSTR functionName, void* hookFunction, void* originalFunction) {
    // Get module handle
    HMODULE hModule = GetModuleHandle(NULL);
    if (hModule == NULL) {
        LogLine("Failed to get module handle");
        return false;
    }

    // ?????
    // I think we're getting a handle on the module's exports
    ULONG size;
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);
    if (importDesc == NULL) {
        LogLine("Failed to get import descriptor");
        return false;
    }

    // Loop through all exports of the selected DLL?
    while (importDesc->Name) {
        // Construct the module name
        const char* modName = (const char*)((BYTE*)hModule + importDesc->Name);
        // Check if we have the export we want to hook
        if (_stricmp(modName, moduleName) == 0) {
            // ?????????
            // https://stackoverflow.com/questions/2641489/what-is-a-thunk
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);
            while (thunk->u1.Function) {
                FARPROC* pfn = (FARPROC*)&thunk->u1.Function;
                FARPROC fn = (FARPROC)GetProcAddress(GetModuleHandleA(moduleName), functionName);
                if (fn == (FARPROC)*pfn) {
                    DWORD oldProtect;
                    VirtualProtect(pfn, sizeof(FARPROC), PAGE_EXECUTE_READWRITE, &oldProtect);

                    // ORIGINAL
                    originalFunction = *pfn;

                    *pfn = (FARPROC)hookFunction;
                    VirtualProtect(pfn, sizeof(FARPROC), oldProtect, &oldProtect);
                    Log("Successfully hooked ");
                    LogLine(functionName);
                    return true;
                }
                thunk++;
            }
        }
        importDesc++;
    }

    Log("Failed to hook ");
    LogLine(functionName);
    return false;
}

void InstallHooksV2() {
    QUICK_HOOK("user32.dll", MessageBoxA);
    QUICK_HOOK("ntdll.dll", RtlAdjustPrivilege);
    QUICK_HOOK("kernel32.dll", WriteFile);
    QUICK_HOOK("kernel32.dll", ReadFile);
    QUICK_HOOK("advapi32.dll", AdjustTokenPrivileges);
}

__declspec(dllexport) BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        LogLine("Attached to process");
        InstallHooksV2();
        break;
    case DLL_THREAD_ATTACH:
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
