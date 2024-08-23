﻿// LunaLoader.cpp : This file contains the 'main' function. Program execution begins and ends there.
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

const LPCWSTR juiceIcon[] = {
    L"\n\x1b[49m       \x1b[49;38;2;134;134;213m▄\x1b[48;2;124;124;213m▀\x1b[49;38;2;124;124;213m▀              \x1b[0m",
    L"\x1b[49m       \x1b[48;2;134;134;213;38;2;124;124;213m▀\x1b[49m                \x1b[0m",
    L"\x1b[49m     \x1b[48;2;124;124;213;38;2;137;137;225m▀█▄█████████\x1b[49m▄ \x1b[49m     \x1b[0m",
    L"\x1b[49m     \x1b[48;2;124;124;213m  \x1b[48;2;158;158;249m       \x1b[38;2;174;174;250m▄    \x1b[49m     \x1b[0m",
    L"\x1b[49m     \x1b[48;2;124;124;213m  \x1b[48;2;158;158;249m \x1b[38;2;174;174;250m▀\x1b[38;2;140;140;232m▄██▀▀█▄ \x1b[38;2;174;174;250m▀ \x1b[49m     \x1b[0m",
    L"\x1b[49m     \x1b[48;2;124;124;213m  \x1b[48;2;158;158;249m  \x1b[48;2;140;140;232m  \x1b[48;2;158;158;249m \x1b[38;2;174;174;250m▀  \x1b[38; 2; 140; 140; 232m▀   \x1b[49m     \x1b[0m",
    L"\x1b[49m     \x1b[48;2;124;124;213m  \x1b[48;2;158;158;249;38;2;174;174;250m▀ \x1b[48;2;140;140;232m  \x1b[48;2;158;158;249m    \x1b[38;2;140;140;232m▄ \x1b[38;2;174;174;250m▄ \x1b[49m     \x1b[0m",
    L"\x1b[49m     \x1b[48;2;124;124;213m  \x1b[48;2;158;158;249m  \x1b[38;2;140;140;232m▀██▄▄█▀   \x1b[49m     \x1b[0m",
    L"\x1b[49m     \x1b[48;2;124;124;213m  \x1b[48;2;158;158;249m \x1b[38;2;174;174;250m▀ \x1b[38;2;140;140;232m▄   ▄ \x1b[38;2;174;174;250m▀  \x1b[49m     \x1b[0m",
    L"\x1b[49m    \x1b[49;38;2;174;174;250m▄\x1b[48;2;124;124;213m  \x1b[48;2;158;158;249m   \x1b[48;2;140;140;232m \x1b[38;2;158;158;249m▀█▀▄██\x1b[48;2;174;174;250m▀█\x1b[49;38;2;174;174;250m▄\x1b[49m▄\x1b[49;38;2;223;113;38m  \x1b[0m",
    L"\x1b[49m \x1b[49;38;2;174;174;250m▄\x1b[48;2;188;188;251m▄█▀\x1b[48;2;124;124;213m  \x1b[48;2;158;158;249m            █\x1b[48;2;188;188;251m▄█\x1b[49m  \x1b[0m",
    L"\x1b[49m  \x1b[38;2;174;174;250m▀▀███\x1b[48;2;188;188;251m▀█▄████▀███\x1b[49m▀\x1b[49;38;2;188;188;251m▀\x1b[38;2;174;174;250m▀\x1b[0m\x1b[0m"
};
const LPCWSTR textArt[] = {
    LR"(,--.                                ,--.        ,--.             )",
    LR"(|  |   ,--.,--.,--, --, ,--,--.     |  |,--.,--.`--' ,---. ,---. )",
    LR"(|  |   |  ||  ||      \' ,-.  |,--. |  ||  ||  |,--.| .--'| .-. :)",
    LR"(|  '--.'  ''  '|  ||  |\ '-'  ||  '-'  /'  ''  '|  |\ `--.\   --.)",
    LR"(`-----' `----' `--''--' `--`--' `-----'  `----' `--' `---' `----')"
};
// The printed lengths of both graphics
// Do not use juiceLength for buffer sizes
const size_t juiceLength = 24;
const size_t textLength = 66;
// The index of the icon that the text starts
const size_t textStart = 4;

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
    if (hKernel32 == NULL) {
        DISP_WINERROR("Could not find kernel32 DLL");
        VirtualFreeEx(hProcess, allocMemAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    // Could improve this by using LoadLibraryEx and passing a handle? -- No, it's reserved for future use
    FARPROC hLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    if (hKernel32 == NULL) {
        DISP_WINERROR("Could not find kernel32 DLL");
        VirtualFreeEx(hProcess, allocMemAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)hLoadLibrary, allocMemAddress, 0, NULL);

    if (hThread == NULL)
    {
        DISP_WINERROR("Failed to create remote thread");
        VirtualFreeEx(hProcess, allocMemAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, allocMemAddress, 0, MEM_RELEASE);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    DISP_LOG("DLL injected successfully.");

    return TRUE;
}

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
    return 0;
}

BOOL PrintBanner() {

    // Get the handle to the standard output
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hStdout == NULL)
    {
        DISP_WINERROR("Error getting standard output handle.");
        return FALSE;
    }

    DWORD mode;
    // Get the current console mode
    if (!GetConsoleMode(hStdout, &mode))
    {
        DISP_WINERROR("Error getting console mode.");
        return FALSE;
    }

    // Enable virtual terminal processing
    mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    if (!SetConsoleMode(hStdout, mode))
    {
        DISP_WINERROR("Error setting console mode.");
        return FALSE;
    }

    CONSOLE_SCREEN_BUFFER_INFO csbi;
    size_t columns, rows;
    GetConsoleScreenBufferInfo(hStdout, &csbi);
    columns = csbi.srWindow.Right - csbi.srWindow.Left + 1;
    rows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;

    // If there's room, print icon
    if (columns > juiceLength) {
        if (columns > juiceLength + 4 + textLength) {
            // Centre the text to juice
            for (size_t i = 0; i < sizeof(juiceIcon) / sizeof(LPCWSTR); i++)
            {
                bool textPrinting = i >= textStart && i < textStart + sizeof(textArt) / sizeof(LPCWSTR);
                size_t textIndex = i - textStart;
                size_t juiceRowLength = lstrlenW(juiceIcon[i]);
                // Cap padding at 24
                size_t padding = min(
                    // Use the render length for the spacing, but real length for the buffer
                    (columns - juiceLength - textLength) / 2 - 2,
                    24
                );
                // +2 for line endings
                size_t totalLength = juiceRowLength + (textPrinting ? textLength + padding : 0) + 2;
                // +1 for null byte
                LPWSTR buffer = (LPWSTR)calloc(totalLength + 1, sizeof(WCHAR));
                // Fall back to default if we can't get the icon to work
                if (buffer == NULL) {
                    DISP_ERROR("Icon/title render failed.");
                    goto default_message;
                }
                lstrcatW(buffer, juiceIcon[i]);
                if (textPrinting) {
                    for (size_t i = juiceRowLength; i < padding + juiceRowLength; i++) {
                        buffer[i] = L' ';
                    }
                    lstrcatW(buffer, textArt[textIndex]);
                }
                buffer[totalLength - 2] = L'\r';
                buffer[totalLength - 1] = L'\n';
                WriteConsoleW(hStdout, buffer, totalLength, NULL, NULL);
                free(buffer);
            }
            std::cout << std::endl;
        } else {
            // Print just the juice icon
            for (size_t i = 0; i < sizeof(juiceIcon) / sizeof(LPCWSTR); i++)
            {
                size_t juiceRowLength = lstrlenW(juiceIcon[i]);
                // +2 for line endings, +1 for null byte
                LPWSTR buffer = (LPWSTR)calloc(juiceRowLength + 3, sizeof(WCHAR));
                if (buffer == NULL) {
                    DISP_ERROR("Icon render failed.");
                    goto default_message;
                }
                lstrcatW(buffer, juiceIcon[i]);
                buffer[juiceRowLength] = L'\r';
                buffer[juiceRowLength + 1] = L'\n';
                WriteConsoleW(hStdout, buffer, juiceRowLength + 2, NULL, NULL);
                free(buffer);
            }
            std::cout << std::endl << "   =*= LunaJuice =*=" << std::endl << std::endl;
        }
    } else {
        default_message:
        std::cout << "=*= Welcome to LunaJuice! =*=" << std::endl;
    }

    return TRUE;
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
        targetProcessId = FindPidByName("mimikatz.exe");
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
        catch (const std::invalid_argument&) {
            DISP_ERROR("The input '" << argv[1] << "' is not a valid integer." << std::endl);
            return 1;  // Return an error code
        }
        catch (const std::out_of_range&) {
            DISP_ERROR("The input '" << argv[1] << "' must be above 0 and be a valid PID." << std::endl);
            return 1;  // Return an error code
        }
    }

    PrintBanner();

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
