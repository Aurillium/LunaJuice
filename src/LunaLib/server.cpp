#include "pch.h"
#include <map>
#include <Windows.h>
#include <sddl.h> 

#include "commands.h"
#include "debug.h"
#include "server.h"

#include "Config.h"
#include "Protocol.h"

#include "shared_util.h"

std::map<HANDLE, LunaConnection*> CONNECTED_CLIENTS = std::map<HANDLE, LunaConnection*>();

// DO NOT CALL FROM WITHIN THREAD
BOOL CleanupConnection(HANDLE hPipe) {
    BOOL ret = FALSE;
    LunaConnection* connection = CONNECTED_CLIENTS[hPipe];
    if (connection->locked) {
        WRITELINE_DEBUG("WARNING: Cleanup was called from a locked connection.");
    }
    connection->locked = TRUE;
    WaitForSingleObject(connection->hThread, INFINITE);
    GetExitCodeThread(connection->hThread, (LPDWORD)&ret);
    CONNECTED_CLIENTS.erase(hPipe);
    free(connection);
    return ret;
}

BOOL LJHandshakeServer(HANDLE hPipe) {
    DWORD bytesWritten = 0, bytesRead = 0;

    // Read client's handshake message
    char buffer[8];
    BOOL success = ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
    if (!success || bytesRead == 0) {
        WRITELINE_DEBUG("Could not read LunaJuice pipe: " << GetLastError());
        return FALSE;
    }
    if (buffer[0] != 'm' || buffer[1] != 'a' || buffer[2] != 'r' || buffer[3] != 'c' || buffer[4] != 'o') {
        WRITELINE_DEBUG("Buffer: " << buffer);
        WRITELINE_DEBUG("Failed check.");
        return FALSE;
    }

    // Send response
    const char response[] = "polo";
    success = WriteFile(hPipe, response, sizeof(response), &bytesWritten, NULL);
    if (!success || sizeof(response) != bytesWritten) {
        WRITELINE_DEBUG("Could not write to LunaJuice pipe: " << GetLastError());
        return FALSE;
    }

    // Success!    
    return TRUE;
}

BOOL SendError(HANDLE hPipe, LunaAPI::ResponseCode code) {
    DWORD bytesWritten = 0;

    LunaAPI::PacketHeader header;
    header.length = 0;
    header.code.response = code;
    BOOL success = WriteFile(hPipe, (LPCVOID)&header, sizeof(header), &bytesWritten, NULL);
    if (!success || sizeof(header) != bytesWritten) {
        WRITELINE_DEBUG("Could not write to LunaJuice pipe: " << GetLastError());
        // True here means close the connection
        return TRUE;
    }
    return FALSE;
}

BOOL SendData(HANDLE hPipe, LunaAPI::ResponseCode code, LPCVOID buffer, size_t length) {
    DWORD bytesWritten = 0;

    LunaAPI::PacketHeader header;
    header.length = length;
    header.code.response = code;
    BOOL success = WriteFile(hPipe, (LPCVOID)&header, sizeof(header), &bytesWritten, NULL);
    if (!success || sizeof(header) != bytesWritten) {
        WRITELINE_DEBUG("Could not write response code to LunaJuice pipe: " << GetLastError());
        // True here means close the connection
        return TRUE;
    }
    success = WriteFile(hPipe, buffer, length, &bytesWritten, NULL);
    if (!success || length != bytesWritten) {
        WRITELINE_DEBUG("Could not write data to LunaJuice pipe: " << GetLastError());
        return TRUE;
    }
    return FALSE;
}

BOOL WaitForCommand(HANDLE hPipe) {
    DWORD bytesRead = 0;

    LunaAPI::PacketHeader header;
    BOOL success = ReadFile(hPipe, &header, sizeof(header), &bytesRead, NULL);
    if (!success || bytesRead == 0) {
        WRITELINE_DEBUG("Could not read opcode from LunaJuice pipe: " << GetLastError());
        return TRUE;
    }

    void* buffer = NULL;
    if (header.length) {
        buffer = (void*)malloc(header.length);
        if (buffer == NULL) {
            // Return error
            WRITELINE_DEBUG("Could not allocate memory for RPC data buffer.");
            return SendError(hPipe, LunaAPI::Resp_OutOfMemory);
        }

        success = ReadFile(hPipe, buffer, header.length, &bytesRead, NULL);
        if (!success || bytesRead == 0) {
            free(buffer);
            WRITELINE_DEBUG("Could not read additional data from LunaJuice pipe: " << GetLastError());
            return TRUE;
        }
    }
    // Pass in handle and buffer to handler functions
    LunaAPI::OpCode opcode = header.code.opcode;
    bool foundCommand = true;
    bool ret = false;
    if (opcode == LunaAPI::Op_Disconnect) {
        // Terminate connection, send no data back
        ret = true;
    }

    // Set config
    else if (opcode == LunaAPI::Op_RegisterHook) {
        ret = Handle_RegisterHook(hPipe, buffer, header.length);
    }
    else if (opcode == LunaAPI::Op_SetDefaultMitigations) {
        ret = Handle_SetDefaultMitigations(hPipe, buffer, header.length);
    }
    else if (opcode == LunaAPI::Op_SetDefaultLogging) {
        ret = Handle_SetDefaultLogging(hPipe, buffer, header.length);
    }
    else if (opcode == LunaAPI::Op_SetFunctionConfig) {
        ret = Handle_SetFunctionConfig(hPipe, buffer, header.length);
    }
    else if (opcode == LunaAPI::Op_AddFunctionConfig) {
        ret = Handle_AddFunctionConfig(hPipe, buffer, header.length);
    }
    else if (opcode == LunaAPI::Op_DelFunctionConfig) {
        ret = Handle_DelFunctionConfig(hPipe, buffer, header.length);
    }
    else if (opcode == LunaAPI::Op_SetFunctionState) {
        ret = Handle_SetFunctionState(hPipe, buffer, header.length);
    }
    else if (opcode == LunaAPI::Op_SetSecuritySettings) {
        ret = Handle_SetSecuritySettings(hPipe, buffer, header.length);
    }

    // Get config
    else if (opcode == LunaAPI::Op_GetDefaultPolicy) {
        ret = Handle_GetDefaultPolicy(hPipe, buffer, header.length);
    }
    else if (opcode == LunaAPI::Op_GetFunctionInfo) {
        ret = Handle_GetFunctionInfo(hPipe, buffer, header.length);
    }
    else if (opcode == LunaAPI::Op_GetFunctionIdentifier) {
        ret = Handle_GetFunctionIdentifier(hPipe, buffer, header.length);
    }
    else if (opcode == LunaAPI::Op_GetRegistrySize) {
        ret = Handle_GetRegistrySize(hPipe, buffer, header.length);
    }
    else if (opcode == LunaAPI::Op_QueryByIdentifier) {
        ret = Handle_QueryByIdentifier(hPipe, buffer, header.length);
    }

    else {
        foundCommand = false;
    }

    free(buffer);

    // If we found the command, return the result
    if (foundCommand) {
        return ret;
    }
    // If not, it was an invalid command
    return SendError(hPipe, LunaAPI::Resp_InvalidCommand);
}

// Client connection flow
BOOL HandleClient(LPVOID lpParam) {
    HANDLE hPipe = (HANDLE)lpParam;
    BOOL ret = TRUE;
    BOOL close = FALSE;

    WRITELINE_DEBUG("Connected!");
    // Handshake first
    if (LJHandshakeServer(hPipe)) {
        WRITELINE_DEBUG("Handshake success!");
    }
    else {
        WRITELINE_DEBUG("Handshake failed!");
        ret = FALSE;
        goto cleanup;
    }

    // Wait for commands until the connection is set to close
    while (!close) {
        close = WaitForCommand(hPipe);
    }
    WRITELINE_DEBUG("Closing connection...");

cleanup:
    // Create another thread to clean this connection up if we naturally reach the end
    // TODO: This needs refinement
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CleanupConnection, (LPVOID)hPipe, 0, NULL);
    return ret;
}

BOOL BeginServer(LPVOID lpParam) {
    char* id = (char*)lpParam;
    // The stub is 10 chars long (incl null byte), then ID is 24 (excl null byte)
    char pipeName[LUNA_MAX_ID_LENGTH + 10] = "\\\\.\\pipe\\";
    for (size_t i = 0; i < LUNA_MAX_ID_LENGTH + 1; i++) {
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

    while (true) {
        HANDLE hPipeRPC = CreateNamedPipeA(
            pipeName,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            32,      // Max instances
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

        BOOL connectSuccess = ConnectNamedPipe(hPipeRPC, NULL);
        //BOOL alreadyHaveClient = GetLastError() == ERROR_PIPE_CONNECTED;

        if (connectSuccess) {
            WRITELINE_DEBUG("Handling client...");
            LunaConnection* connection = (LunaConnection*)malloc(sizeof(LunaConnection));
            if (connection == NULL) {
                WRITELINE_DEBUG("Could not allocate memory for new RPC connection.");
                continue;
            }
            connection->locked = FALSE;
            HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)HandleClient, (LPVOID)hPipeRPC, 0, NULL);
            connection->hThread = hThread;
            CONNECTED_CLIENTS[hPipeRPC] = connection;
            if (hThread == NULL) {
                WRITELINE_DEBUG("Could not create thread for RPC.");
                continue;
            }
        }
        else {
            WRITELINE_DEBUG("Connection failed.");
            CloseHandle(hPipeRPC);
        }
    }

    // Clean up all leftover threads here
    // No threads left behind

    LocalFree(psd);
    WRITELINE_DEBUG("Server thread exitting now...");
    return TRUE;
}