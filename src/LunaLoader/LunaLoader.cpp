// LunaLoader.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <errhandlingapi.h>
#include <iostream>
#include <string>
#include <stdexcept>
#include <TlHelp32.h>


#include "resource.h"

#define DISP_WINERROR(message) std::cerr << message << ": " << GetLastError() << std::endl
#define DISP_ERROR(message) std::cerr << message << "." << std::endl;
#define DISP_LOG(message) std::cout << message << std::endl;

const char* privilegesToRemove[] = {
        "SeDebugPrivilege",
        "SeImpersonatePrivilege",
        "SeDelegateSessionUserImpersonatePrivilege",
        "SeCreateTokenPrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeChangeNotifyPrivilege",
        "SeCreateGlobalPrivilege",
        "SeCreatePagefilePrivilege",
        "SeCreatePermanentPrivilege",
        "SeEnableDelegationPrivilege",
        "SeLoadDriverPrivilege",
        "SeLockMemoryPrivilege",
        "SeMachineAccountPrivilege",
        "SeManageVolumePrivilege",
        "SeProfileSingleProcessPrivilege",
        "SeRelabelPrivilege",
        "SeRemoteShutdownPrivilege",
        "SeRestorePrivilege",
        "SeSecurityPrivilege",
        "SeShutdownPrivilege",
        "SeSystemEnvironmentPrivilege",
        "SeTakeOwnershipPrivilege",
        "SeTcbPrivilege",
        "SeTrustedCredManAccessPrivilege"
        // Unsolicited input?
};
const DWORD SE_PRIVILEGE_DISABLED = 0x00000000;

// TODO: Can probably do all privileges at once now
static BOOL DropAllPrivileges(int targetProcessId)
{
    for (short i = 0; i < sizeof(privilegesToRemove) / sizeof(char*); i++)
    {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, targetProcessId);
        if (hProcess == NULL)
        {
            DISP_WINERROR("Could not get handle to process");
            return FALSE;
        }

        HANDLE hToken;
        if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        {
            DISP_WINERROR("Could not open process token");
            return FALSE;
        }

        TOKEN_PRIVILEGES* tp = (TOKEN_PRIVILEGES*)malloc(sizeof(TOKEN_PRIVILEGES));
        if (tp == NULL) {
            DISP_WINERROR("Could not allocate memory for token privileges");
            return FALSE;
        }
        tp->PrivilegeCount = 1;

        // Add privileges to be removed (example: SE_DEBUG_NAME)
        LUID luid;
        if (!LookupPrivilegeValueA(NULL, privilegesToRemove[i], &luid))
        {
            DISP_WINERROR("Could not find privilege value for " << privilegesToRemove[i]);
            free(tp);
            return FALSE;
        }

        tp->Privileges->Luid = luid;
        tp->Privileges->Attributes = SE_PRIVILEGE_DISABLED;

        // Adjust token privileges
        if (!AdjustTokenPrivileges(hToken, false, tp, 0, NULL, NULL))
        {
            DISP_WINERROR("Could not adjust privilege");
            free(tp);
            return FALSE;
        }

        free(tp);

        std::cout << "Dropped " << privilegesToRemove[i] << "." << std::endl;

        CloseHandle(hToken);
        CloseHandle(hProcess);
        return TRUE;
    }
}

static BOOL EnableDebugPrivilege()
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        DISP_WINERROR("Could not get process token");
        return FALSE;
    }

    LUID luid;
    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid))
    {
        DISP_WINERROR("Could not find value of debug privilege");
        return FALSE;
    }

    TOKEN_PRIVILEGES* tp = (TOKEN_PRIVILEGES*)malloc(sizeof(TOKEN_PRIVILEGES));
    if (tp == NULL) {
        DISP_WINERROR("Could not allocate memory for token privileges");
        return FALSE;
    }
    tp->PrivilegeCount = 1;
    tp->Privileges->Luid = luid;
    tp->Privileges->Attributes = 0x00000002;

    if (!AdjustTokenPrivileges(hToken, false, tp, 0, NULL, NULL))
    {
        DISP_WINERROR("Could not add debug privilege");
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

static BOOL InjectDLL(int targetProcessId)
{
    // First save the DLL to the disk

    HINSTANCE hInstance = GetModuleHandleA(NULL);

    // Prepare to take the DLL out
    CHAR dllPath[MAX_PATH];
    GetTempPathA(MAX_PATH, dllPath);
    GetTempFileNameA(dllPath, "", 0, dllPath);

    HRSRC hResource = FindResource(hInstance, MAKEINTRESOURCE(IDR_DLL1), RT_RCDATA);
    if (!hResource) {
        DISP_WINERROR("Could not find library");
        return FALSE;
    }

    DWORD size = SizeofResource(hInstance, hResource);
    if (size == 0) {
        DISP_WINERROR("Could not get library size");
        return FALSE;
    }

    HGLOBAL hLoadedResource = LoadResource(hInstance, hResource);
    if (!hLoadedResource) {
        DISP_WINERROR("Could not load library into memory");
        return FALSE;
    }

    const char* data = (const char*)LockResource(hLoadedResource);

    HANDLE hFile = CreateFileA(dllPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DISP_WINERROR("Could not create file '" << dllPath << "'");
        return FALSE;
    }

    DWORD bytesWritten = 0;
    if (!WriteFile(hFile, data, size, &bytesWritten, NULL) || bytesWritten != size)
    {
        DISP_WINERROR("Could not write to temporary file '" << dllPath << "'");
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);

    // Now we inject that

    // Open the remote process to write
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, targetProcessId);
    if (hProcess == NULL)
    {
        DISP_WINERROR("Could not open " << targetProcessId);
        return FALSE;
    }

    DWORD byteLength = (DWORD)((MAX_PATH) * sizeof(CHAR));
    HANDLE allocMemAddress = VirtualAllocEx(hProcess, NULL, byteLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (allocMemAddress == NULL)
    {
        DISP_WINERROR("Failed to allocate memory in target process");
        CloseHandle(hProcess);
        return FALSE;
    }
    SIZE_T written = 0;
    WriteProcessMemory(hProcess, allocMemAddress, dllPath, byteLength, &written);

    // This block creates a remote thread to load the DLL
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    // Could improve this bt using LoadLibraryEx and passing a handle?
    FARPROC hLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)hLoadLibrary, allocMemAddress, 0, NULL);

    if (hThread == NULL)
    {
        DISP_WINERROR("Failed to create remote thread");
        CloseHandle(hProcess);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, allocMemAddress, 0, MEM_RELEASE);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    std::cout << "DLL injected successfully.";

    return TRUE;
}

DWORD FindPidByName(LPCWSTR name) {
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
        if (!_wcsicmp(pe32.szExeFile, name)) {
            // Process found, return the process ID
            CloseHandle(hProcessSnap);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    // Process not found
    CloseHandle(hProcessSnap);
    return 0;
}

int main(int argc, char* argv[])
{
    DWORD targetProcessId = 0;
    if (argc < 2)
    {
        std::cerr << "Usage: DropPrivileges <ProcessId>" << std::endl;
#if _DEBUG
        // Mimikatz for now
        std::cout << "No arguments, attempting to inject to Mimikatz for debug." << std::endl;
        targetProcessId = FindPidByName(L"mimikatz.exe");
        if (!targetProcessId) {
            DISP_ERROR("Mimikatz not found.");
            return 1;
        } else {
            std::cout << "Injecting into Mimikatz." << std::endl;
        }
#else
        return 1;
#endif
    }
    else {
        try {
            targetProcessId = std::stoi(argv[1]);
        }
        catch (const std::invalid_argument& e) {
            DISP_ERROR("The input '" << argv[1] << "' is not a valid integer." << std::endl);
            return 1;  // Return an error code
        }
        catch (const std::out_of_range& e) {
            DISP_ERROR("The input '" << argv[1] << "' must be above 0 and be a valid PID." << std::endl);
            return 1;  // Return an error code
        }
    }

    DISP_LOG("Obtaining debug privilege...");
    EnableDebugPrivilege();

    // This interferes with legitimate processes, don't do it for now
    //Console.WriteLine("Dropping all privileges...");
    //DropAllPrivileges(targetProcessId);
    DISP_LOG("Injecting monitor DLL...");
    InjectDLL(targetProcessId);
    DISP_LOG("Dropped privileges for process ID " << targetProcessId << ".");

    return 0;
}
