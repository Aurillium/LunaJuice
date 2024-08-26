#include "pch.h"
#include <Windows.h>
#include <sddl.h> 

#include "debug.h"

#include "shared.h"

HANDLE hPipeRPC;

BOOL LJHandshakeServer() {
    DWORD bytesWritten = 0, bytesRead = 0;

    // Read client's handshake message
    char buffer[8];
    BOOL success = ReadFile(hPipeRPC, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
    if (!success || bytesRead == 0) {
        WRITELINE_DEBUG("Could not read LunaJuice pipe: " << GetLastError());
        DisconnectNamedPipe(hPipeRPC);
        return FALSE;
    }
    if (buffer[0] != 'm' || buffer[1] != 'a' || buffer[2] != 'r' || buffer[3] != 'c' || buffer[4] != 'o') {
        WRITELINE_DEBUG("Buffer: " << buffer);
        WRITELINE_DEBUG("Failed check.");
        return FALSE;
    }

    // Send response
    const char response[] = "polo";
    success = WriteFile(hPipeRPC, response, sizeof(response), &bytesWritten, NULL);
    if (!success || sizeof(response) != bytesWritten) {
        WRITELINE_DEBUG("Could not write to LunaJuice pipe: " << GetLastError());
        DisconnectNamedPipe(hPipeRPC);
        return FALSE;
    }

    // Success!    
    return TRUE;
}

BOOL BeginPipe(LPVOID lpParam) {
    char* id = (char*)lpParam;
    // The stub is 10 chars long (incl null byte), then ID is 24 (excl null byte)
    char pipeName[MAX_ID_LENGTH + 10] = "\\\\.\\pipe\\";
    for (size_t i = 0; i < MAX_ID_LENGTH + 1; i++) {
        pipeName[i + 9] = id[i];
    }

    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR psd = NULL;

    // Security descriptor string to allow access to Authenticated Users
    const char* sddl = "D:(A;OICI;GA;;;AU)"; // AU: Authenticated Users, GA: Generic All Access

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl, SDDL_REVISION_1, &psd, NULL)) {
        WRITELINE_DEBUG("Could not create security descriptor: " << GetLastError());
        return FALSE;
    }

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = psd;
    sa.bInheritHandle = FALSE;

    hPipeRPC = CreateNamedPipeA(
        pipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,      // One instance at a time
        1024,
        1024,
        0,
        &sa);

    if (hPipeRPC == INVALID_HANDLE_VALUE) {
        WRITELINE_DEBUG("Could not create pipe server: " << GetLastError());
        LocalFree(psd);
        return FALSE;
    }

    WRITELINE_DEBUG("Pipe waiting for connections...");

    while (true) {
        BOOL connectSuccess = ConnectNamedPipe(hPipeRPC, NULL);
        BOOL alreadyHaveClient = GetLastError() == ERROR_PIPE_CONNECTED;

        if (connectSuccess) {
            WRITELINE_DEBUG("Connected!");
            if (LJHandshakeServer()) {
                WRITELINE_DEBUG("Handshake success!");
                // Give the client some time to recieve
                Sleep(500);
                DisconnectNamedPipe(hPipeRPC);
            } else {
                WRITELINE_DEBUG("Handshake failed!");
            }
        }
    }

    WRITELINE_DEBUG("Server thread exitting now...");
    CloseHandle(hPipeRPC);
}