#include <iostream>
#include <Windows.h>

#include "arguments.h"
#include "comms.h"
#include "output.h"
#include "util.h"

#include "shared.h"

extern bool verboseEnabled;

LunaStart config;
HANDLE hPipeRPC;

void LoadRandomID() {
    RandomString(config.id, ID_CHARACTERS, MAX_ID_LENGTH);
}
void LoadCustomID(const char* id) {
    size_t idLength = strlen(id);
    if (idLength > MAX_ID_LENGTH) {
        DISP_WARN("Implant ID cannot be above " << MAX_ID_LENGTH << "Characters. '" << id << "' will be truncated");
    }
    memcpy_s(config.id, 24, id, idLength);
}

// Create config data
// Consumes mitigations and hooks
BOOL PopulateStartData(LUNA_ARGUMENTS* arguments) {
    // Set ID
    if (arguments->name[0] == 0) {
        // Create ID for instance
        LoadRandomID();
    } else {
        LoadCustomID(arguments->name);
    }

    // Set up hooks

    // Loop over and OR with hook flags in config
    size_t startIndex = 0, i = 0;
    BOOL inText = FALSE;

    DISP_VERBOSE("Starting to add hooks...");

    if (arguments->hooks[0] == 0) {
        config.hooks = DEFAULT_HOOKS;
        UPDATE_VERBOSE("No data, added default hooks.");
    }
    else {
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

BOOL InitialiseLunaJuice(HANDLE hProcess, LPTHREAD_START_ROUTINE initLocation) {

    // Allocate room for the config
    HANDLE allocMemAddress = VirtualAllocEx(hProcess, NULL, sizeof(LunaStart), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (allocMemAddress == NULL) {
        DISP_WINERROR("Failed to allocate memory for configuration in target");
        return FALSE;
    }

    // Copy configuration into target
    size_t written = 0;
    WriteProcessMemory(hProcess, allocMemAddress, &config, sizeof(LunaStart), &written);

    // Process configuration and load hooks
    HANDLE hConfigThread = CreateRemoteThread(hProcess, NULL, 0, initLocation, allocMemAddress, 0, NULL);
    if (hConfigThread == NULL) {
        DISP_WINERROR("Failed to create config thread");
        return FALSE;
    }
    WaitForSingleObject(hConfigThread, INFINITE);

    UPDATE_LOG("Hi, my name is '" << config.id << "'!");

    return TRUE;
}

BOOL LJHandshakeClient() {
    DISP_VERBOSE("Attempting handshake...");

    // Send handshake message to ensure connection is working
    DWORD bytesWritten = 0, bytesRead = 0;
    const char initialMessage[] = "marco";
    BOOL success = WriteFile(hPipeRPC, initialMessage, sizeof(initialMessage), &bytesWritten, NULL);
    if (!success || sizeof(initialMessage) != bytesWritten) {
        DISP_WINERROR("Could not write to LunaJuice pipe");
        CloseHandle(hPipeRPC);
        return FALSE;
    }
    UPDATE_VERBOSE("marco");

    // Read server's response
    char buffer[8];
    success = ReadFile(hPipeRPC, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
    if (!success || bytesRead == 0) {
        DISP_WINERROR("Could not read LunaJuice pipe");
        CloseHandle(hPipeRPC);
        return FALSE;
    }
    if (buffer[0] == 'p' && buffer[1] == 'o' && buffer[2] == 'l' && buffer[3] == 'o') {
        UPDATE_VERBOSE_REMOTE("polo");
        return TRUE;
    }
    CloseHandle(hPipeRPC);
    return FALSE;
}

BOOL ConnectLunaJuice() {
    // The stub is 10 chars long (incl null byte), then ID is 24 (excl null byte)
    char pipeName[MAX_ID_LENGTH + 10] = "\\\\.\\pipe\\";
    for (size_t i = 0; i < MAX_ID_LENGTH + 1; i++) {
        pipeName[i + 9] = config.id[i];
    }

    // Attempt to connect to the named pipe
    hPipeRPC = CreateFileA(
        pipeName,              // Pipe name
        GENERIC_READ |         // Read and write access
        GENERIC_WRITE,
        0,                     // No sharing
        NULL,                  // Default security attributes
        OPEN_EXISTING,         // Opens existing pipe
        0,                     // Default attributes
        NULL);                 // No template file

    if (hPipeRPC == INVALID_HANDLE_VALUE) {
        DISP_WINERROR("Could not connect to LunaJuice pipe");
        return FALSE;
    }

    BOOL connected = LJHandshakeClient();

    if (connected) {
        DISP_REMOTE("Completed handshake with LunaJuice.");
    } else {
        DISP_ERROR("Could not complete handshake with LunaJuice");
    }

    // Close the pipe
    CloseHandle(hPipeRPC);

    return 0;
}