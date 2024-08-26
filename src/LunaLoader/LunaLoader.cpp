// LunaLoader.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <errhandlingapi.h>
#include <iostream>
#include <tlhelp32.h>

#include "arguments.h"
#include "output.h"
#include "resource.h"
#include "util.h"

#include "shared.h"

bool verboseEnabled = false;
LunaShared initData;
LunaStart config;

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
const DWORD juiceLength = 24;
const DWORD textLength = 66;
// The index of the icon that the text starts
const DWORD textStart = 4;

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

static BOOL SaveDLL(LPSTR buffer) {
    HINSTANCE hInstance = GetModuleHandleA(NULL);

    // Prepare to take the DLL out
    GetTempPathA(MAX_PATH, buffer);
    GetTempFileNameA(buffer, "", 0, buffer);

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

    HANDLE hFile = CreateFileA(buffer, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DISP_WINERROR("Could not create file '" << buffer << "'");
        return FALSE;
    }

    DWORD bytesWritten = 0;
    if (!WriteFile(hFile, data, size, &bytesWritten, NULL) || bytesWritten != size)
    {
        DISP_WINERROR("Could not write to temporary file '" << buffer << "'");
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);

    return TRUE;
}

#define ADD_FLAG_CMP(name, expr, update) if (NoCapCmp(expr, #name)) {\
    update = update | Enable_##name;\
}

// Consumes mitigations and hooks
BOOL PopulateStartData(LUNA_ARGUMENTS *arguments) {
    // Set up hooks

    // Loop over and OR with hook flags in config
    size_t startIndex = 0, i = 0;
    BOOL inText = FALSE;

    DISP_VERBOSE("Starting to add hooks...");

    if (arguments->hooks[0] == 0) {
        config.hooks = DEFAULT_HOOKS;
        UPDATE_VERBOSE("No data, added default hooks.");
    } else {
        while (true) {
            CHAR current = arguments->hooks[i];

            // When we get to the end of a hook, add it to config
            if (IS_WHITESPACE(current) || current == ',' || current == 0) {
                // We've hit whitespace or a comma after being in text, time to drop
                if (inText) {

                    // This is technically constant/static because it comes directly from argv
                    // We can modify it though
                    ((char*)arguments->hooks)[i] = 0;

                    // Get hook name to compare
                    LPCSTR hookName = &arguments->hooks[startIndex];

                    // Compare and add hooks
                    if (NoCapCmp("DEFAULT", hookName)) {
                        config.hooks = config.hooks | DEFAULT_HOOKS;
                    }
                    else ADD_FLAG_CMP(NtReadFile, hookName, config.hooks)
                    else ADD_FLAG_CMP(NtWriteFile, hookName, config.hooks)
                    else ADD_FLAG_CMP(ReadConsole, hookName, config.hooks)
                    else ADD_FLAG_CMP(RtlAdjustPrivilege, hookName, config.hooks)
                    else ADD_FLAG_CMP(OpenProcess, hookName, config.hooks)
                    else ADD_FLAG_CMP(CreateRemoteThread, hookName, config.hooks)
                    else ADD_FLAG_CMP(WriteProcessMemory, hookName, config.hooks)
                    else ADD_FLAG_CMP(ReadProcessMemory, hookName, config.hooks)
                    else ADD_FLAG_CMP(CreateProcess, hookName, config.hooks)
                    else ADD_FLAG_CMP(NtCreateUserProcess, hookName, config.hooks)
                    else {
                        DISP_WARN("Could not find hook '" << hookName << "'");
                    }

                    UPDATE_VERBOSE("Added " << hookName);
                    inText = FALSE;
                }

                // Process from after whitespace/comma
                startIndex = i + 1;
            }
            else {
                // If not whitespace/comma, we're in a privilege.
                inText = TRUE;
            }

            // We've reached the end
            if (current == 0) {
                break;
            }

            i++;
        }
    }

    // Add mitigations

    startIndex = 0, i = 0;
    inText = FALSE;

    DISP_VERBOSE("Starting to add mitigations...");

    if (arguments->mitigations[0] == 0) {
        UPDATE_VERBOSE("No data, no mitigations active.");
    }
    else {
        while (true) {
            CHAR current = arguments->mitigations[i];

            // When we get to the end of a hook, add it to config
            if (IS_WHITESPACE(current) || current == ',' || current == 0) {
                // We've hit whitespace or a comma after being in text, time to drop
                if (inText) {

                    // This is technically constant/static because it comes directly from argv
                    // We can modify it though
                    ((char*)arguments->mitigations)[i] = 0;

                    // Get hook name to compare
                    LPCSTR mitigationName = &arguments->mitigations[startIndex];

                    // Compare and add mitigations
                    ADD_FLAG_CMP(BlockEsc, mitigationName, config.mitigations)
                    else ADD_FLAG_CMP(BlanketFakeSuccess, mitigationName, config.mitigations)
                    else ADD_FLAG_CMP(BlanketNoPerms, mitigationName, config.mitigations)
                    else {
                        DISP_WARN("Could not find mitigation '" << mitigationName << "'");
                    }

                    UPDATE_VERBOSE("Added " << mitigationName);
                    inText = FALSE;
                }

                // Process from after whitespace/comma
                startIndex = i + 1;
            }
            else {
                // If not whitespace/comma, we're in a privilege.
                inText = TRUE;
            }

            // We've reached the end
            if (current == 0) {
                break;
            }

            i++;
        }
    }

    return TRUE;
}

// This consumes arguments.dropPrivileges
BOOL DropPrivileges(HANDLE hProcess, LUNA_ARGUMENTS *arguments) {
    // We could create an array of privileges theoretically, but this would probably
    // mean looping over arguments twice or creating another array so we could optimise
    // the size. This is just simpler
    TOKEN_PRIVILEGES tp;
    LUID luid;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        DISP_WINERROR("Could not open process token");
        return FALSE;
    }

    size_t startIndex = 0, i = 0;
    BOOL shownLink = FALSE;
    BOOL inText = FALSE;

    DISP_VERBOSE("Starting drop loop...");

    while (true) {

        CHAR current = arguments->dropPrivileges[i];

        // When we get to the end of one privilege, drop it
        if (IS_WHITESPACE(current) || current == ',' || current == 0) {
            // We've hit whitespace or a comma after being in text, time to drop
            if (inText) {

                // This is technically constant/static because it comes directly from argv
                // We can modify it though
                ((char*)arguments->dropPrivileges)[i] = 0;

                // Lookup privilege name starting at our current position
                LPCSTR privilegeName = &arguments->dropPrivileges[startIndex];
                if (!LookupPrivilegeValueA(NULL, privilegeName, &luid)) {
                    DISP_WARN("Could not find privilege value for '" << privilegeName << "'. Remember these are case-sensitive");
                    if (!shownLink) {
                        UPDATE_WARN("A list can be found here: https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants");
                        shownLink = TRUE;
                    }
                    // Move to next index then continue
                    startIndex = i + 1;
                    i++;
                    continue;
                }
                tp.Privileges->Luid = luid;
                tp.Privileges->Attributes = SE_PRIVILEGE_DISABLED;

                if (!AdjustTokenPrivileges(hToken, false, &tp, 0, NULL, NULL)) {
                    DISP_WINERROR("Could not adjust privilege");
                    return FALSE;
                }

                UPDATE_VERBOSE("Dropped " << privilegeName);
                inText = FALSE;
            }

            // Process from after whitespace/comma
            startIndex = i + 1;
        } else {
            // If not whitespace/comma, we're in a privilege.
            inText = TRUE;
        }

        // We've reached the end
        if (current == 0) {
            break;
        }

        i++;
    }

    CloseHandle(hToken);

    return TRUE;
}

static BOOL InjectDLL(HANDLE hProcess, LPCSTR dllPath)
{
    // Prepare shared object

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;

    // Define a security descriptor with access for all users
    PSECURITY_DESCRIPTOR psd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
    if (psd == NULL) {
        DISP_WINERROR("Could not allocate memory for security descriptor");
        return FALSE;
    }
    InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION);
    if (psd == NULL) {
        DISP_WINERROR("Could not initialise security descriptor for mapped file");
        return FALSE;
    }
    SetSecurityDescriptorDacl(psd, TRUE, (PACL)NULL, FALSE);

    sa.lpSecurityDescriptor = psd;

    HANDLE hFileMapping = CreateFileMappingA(
        INVALID_HANDLE_VALUE,       // Use paging file
        &sa,                        // Security attributes
        PAGE_READWRITE,             // Read/write access
        0,                          // Maximum object size (high-order DWORD)
        1024,                       // Maximum object size (low-order DWORD)
        SHARED_GLOBAL_NAME);        // Name of the file mapping object
    if (hFileMapping == NULL) {
        DISP_WINERROR("Could not create file mapping");
        return FALSE;
    }

    // Get our shared memory pointer
    LPVOID lpMemFile;
    lpMemFile = MapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (lpMemFile == NULL) {
        DISP_WINERROR("Could not map shared memory");
        return FALSE;
    }

    // Inject saved DLL

    DWORD byteLength = (DWORD)((MAX_PATH) * sizeof(CHAR));
    HANDLE allocMemAddress = VirtualAllocEx(hProcess, NULL, byteLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (allocMemAddress == NULL)
    {
        DISP_WINERROR("Failed to allocate memory for injection in target");
        return FALSE;
    }
    SIZE_T written = 0;
    WriteProcessMemory(hProcess, allocMemAddress, dllPath, byteLength, &written);

    // This block creates a remote thread to load the DLL
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 == NULL) {
        DISP_WINERROR("Could not find kernel32 DLL");
        VirtualFreeEx(hProcess, allocMemAddress, 0, MEM_RELEASE);
        return FALSE;
    }
    // Could improve this by using LoadLibraryEx and passing a handle? -- No, it's reserved for future use
    FARPROC hLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    if (hKernel32 == NULL) {
        DISP_WINERROR("Could not find LoadLibraryA function");
        VirtualFreeEx(hProcess, allocMemAddress, 0, MEM_RELEASE);
        return FALSE;
    }
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)hLoadLibrary, allocMemAddress, 0, NULL);

    if (hThread == NULL) {
        DISP_WINERROR("Failed to create remote thread");
        VirtualFreeEx(hProcess, allocMemAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    // Wait for thread to exit
    WaitForSingleObject(hThread, INFINITE);
    // Clean up
    VirtualFreeEx(hProcess, allocMemAddress, 0, MEM_RELEASE);
    CloseHandle(hThread);

    // Now save the data we receive so we can init

    memcpy(&initData, lpMemFile, sizeof(LunaShared));

    LocalFree(psd);
    UnmapViewOfFile(lpMemFile);
    CloseHandle(hFileMapping);

    return TRUE;
}

BOOL InitialiseLunaJuice(HANDLE hProcess) {
    // TODO: secure random value
    config.id[0] = 'h';
    config.id[1] = 'i';
    config.id[2] = '!';

    // Allocate room for the config
    HANDLE allocMemAddress = VirtualAllocEx(hProcess, NULL, sizeof(LunaStart), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (allocMemAddress == NULL) {
        DISP_WINERROR("Failed to allocate memory for configuration in target");
        return FALSE;
    }

    DISP_VERBOSE("yett");

    // Copy configuration into target
    size_t written = 0;
    WriteProcessMemory(hProcess, allocMemAddress, &config, sizeof(LunaStart), &written);

    // Process configuration and load hooks
    HANDLE hConfigThread = CreateRemoteThread(hProcess, NULL, 0, LPTHREAD_START_ROUTINE(initData.lpInit), allocMemAddress, 0, NULL);
    if (hConfigThread == NULL) {
        DISP_WINERROR("Failed to create config thread");
        return FALSE;
    }
    WaitForSingleObject(hConfigThread, INFINITE);

    return TRUE;
}


BOOL PrintBanner(HANDLE hStdout) {

    CONSOLE_SCREEN_BUFFER_INFO csbi;
    SHORT columns, rows;
    if (hStdout != NULL) {
        GetConsoleScreenBufferInfo(hStdout, &csbi);
        columns = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        rows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
    } else {
        columns = 0;
        rows = 0;
        // Don't rely on the handle
        goto default_message;
    }

    // If there's room, print icon
    // Sizes here are DWORD because any more seems unnecessary,
    // and WriteConsole uses it
    if (columns > juiceLength) {
        // Print the banner or icon
        if (columns > juiceLength + 4 + textLength) {
            // Centre the text to juice
            for (DWORD i = 0; i < sizeof(juiceIcon) / sizeof(LPCWSTR); i++)
            {
                bool textPrinting = i >= textStart && i < textStart + sizeof(textArt) / sizeof(LPCWSTR);
                DWORD textIndex = i - textStart;
                DWORD juiceRowLength = lstrlenW(juiceIcon[i]);
                // Cap padding at 24
                DWORD padding = min(
                    // Use the render length for the spacing, but real length for the buffer
                    (columns - juiceLength - textLength) / 2 - 2,
                    24
                );
                // +2 for line endings
                DWORD totalLength = juiceRowLength + (textPrinting ? textLength + padding : 0) + 2;
                // +1 for null byte
                LPWSTR buffer = (LPWSTR)calloc(totalLength + 1, sizeof(WCHAR));
                // Fall back to default if we can't get the icon to work
                if (buffer == NULL) {
                    DISP_ERROR("Icon/title render failed");
                    goto default_message;
                }
                lstrcatW(buffer, juiceIcon[i]);
                if (textPrinting) {
                    for (DWORD i = juiceRowLength; i < padding + juiceRowLength; i++) {
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
            for (DWORD i = 0; i < sizeof(juiceIcon) / sizeof(LPCWSTR); i++)
            {
                DWORD juiceRowLength = lstrlenW(juiceIcon[i]);
                // +2 for line endings, +1 for null byte
                LPWSTR buffer = (LPWSTR)calloc(juiceRowLength + 3, sizeof(WCHAR));
                if (buffer == NULL) {
                    DISP_ERROR("Icon render failed");
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
    int ret = 0;

    // Get the handle to the standard output
    // We're going to try enable nice ANSI formatting
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hStdout == NULL)
        DISP_WINERROR("Error getting standard output handle, some formatting may not work");
    else {
        DWORD mode;
        // Get the current console mode
        if (!GetConsoleMode(hStdout, &mode))
            DISP_WINERROR("Error getting console mode, some formatting may not work");
        // Enable virtual terminal processing
        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        if (!SetConsoleMode(hStdout, mode))
            DISP_WINERROR("Error setting console mode, some formatting may not work");
    }

    // Process arguments
    LUNA_ARGUMENTS arguments = GetArguments(argc, argv);
    verboseEnabled = arguments.verbose;

    if (arguments.help) {
        DisplayUsage();
        return 0;
    }

    if (arguments.pid == 0)
    {
#if _DEBUG
        // Mimikatz for testing
        std::cout << "No PID found, attempting to inject to Mimikatz for debug." << std::endl;
        arguments.pid = FindPidByName("mimikatz.exe");
        if (!arguments.pid) {
            DISP_ERROR("Mimikatz not found");
            return 1;
        } else {
            std::cout << "Injecting into Mimikatz." << std::endl;
        }
#else
        DisplayUsage();
        return 1;
#endif
    }

    // Main flow
    HANDLE hProcess;

    if (!PrintBanner(hStdout))
        DISP_WARN("Could not display banner");

    DISP_LOG("Targetting " << arguments.pid);

    if (!PopulateStartData(&arguments)) {
        DISP_ERROR("Could not process arguments");
        ret = 1;
        goto cleanup_nohandle;
    }

    DISP_LOG("Obtaining debug privilege...");
    if (!EnableDebugPrivilege()) {
        DISP_ERROR("Could not obtain debug privilege (cannot modify process)");
        ret = 1;
        goto cleanup_nohandle;
    }
    UPDATE_LOG("Got debug!");

    // Save DLL to disk
    DISP_VERBOSE("Extracting DLL...");
    CHAR dllPath[MAX_PATH];
    if (!SaveDLL(dllPath)) {
        DISP_WINERROR("Could save DLL to disk");
        ret = 1;
        goto cleanup_nohandle;
    }
    UPDATE_VERBOSE("DLL saved to '" << dllPath << "'.");

    // Open the remote process to write
    DISP_LOG("Opening process...");
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, arguments.pid);
    if (hProcess == NULL) {
        DISP_WINERROR("Could not open " << arguments.pid);
        ret = 1;
        goto cleanup_nohandle;
    }
    UPDATE_LOG("Opened successfully!");

    DISP_LOG("Dropping selected privileges...");
    if (!DropPrivileges(hProcess, &arguments)) {
        DISP_ERROR("Failed to drop privileges");
        ret = 1;
        goto cleanup;
    }
    UPDATE_LOG("Dropped privileges successfully!");

    DISP_LOG("Injecting monitor DLL...");
    if (!InjectDLL(hProcess, dllPath)) {
        DISP_ERROR("Could not inject DLL into target");
        ret = 1;
        goto cleanup;
    }
    UPDATE_LOG("DLL injected successfully!");

    DISP_LOG("Initialising LunaJuice...");
    if (!InitialiseLunaJuice(hProcess)) {
        DISP_ERROR("Could not initialise LunaJuice");
        return 1;
    }
    UPDATE_LOG("Initialised!");

    DISP_SUCCESS("LunaJuice is ready to go!");

    cleanup:
    CloseHandle(hProcess);

    cleanup_nohandle:
    RESET_FORMAT;

    return ret;
}
