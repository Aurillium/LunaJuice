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

std::map<HANDLE, LunaServer*> CONNECTED_CLIENTS = std::map<HANDLE, LunaServer*>();

template<> RPCArguments* GetArgumentNode(LunaConnection* connection, char** _) {
    RPCArguments* node = (RPCArguments*)malloc(sizeof(RPCArguments));

    if (node == NULL) {
        WRITELINE_DEBUG("No room to store RPC call arguments (argument structure).");
        return NULL;
    }
    node->next = NULL;

    // Get the length of the string
    DWORD length = 0;
    if (!connection->GetTyped(&length)) {
        WRITELINE_DEBUG("Could not get argument string length.");
        free(node);
        return FALSE;
    }
    char* item = (char*)malloc(sizeof(length));
    if (item == NULL) {
        WRITELINE_DEBUG("No room to store RPC call arguments (argument value).");
        free(node);
        return FALSE;
    }
    if (!connection->GetRaw(item, length)) {
        WRITELINE_DEBUG("Could not get item from RPC arguents.");
        free(item);
        free(node);
        return FALSE;
    }
    node->value = item;
}

BOOL LunaServer::ServerHandshake() {
    std::lock_guard<std::recursive_mutex> lock(*mtx);
    DWORD bytesWritten = 0, bytesRead = 0;

    // Read client's handshake message
    char buffer[8];
    BOOL success = ReadFile(this->hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
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
    success = WriteFile(this->hPipe, response, sizeof(response), &bytesWritten, NULL);
    if (!success || sizeof(response) != bytesWritten) {
        WRITELINE_DEBUG("Could not write to LunaJuice pipe: " << GetLastError());
        return FALSE;
    }

    // Success!    
    return TRUE;
}

BOOL LunaServer::RunCommand() {
    LunaAPI::PacketHeader header = this->WaitForPacket();

    // Pass in handle and buffer to handler functions
    LunaAPI::OpCode opcode = header.code.opcode;
    bool foundCommand = true;
    bool ret = false;
    if (opcode == LunaAPI::Op_Disconnect) {
        // Terminate connection, send no data back
        ret = true;
    }
#ifdef _DEBUG
    // THIS IS ONLY FOR TESTING
    else if (opcode == LunaAPI::Op_AddTest) {
        RunRPC<int, bool, int, int>(this, Handle_TestFunc);
    }
#endif

    // Set config
    /*else if (opcode == LunaAPI::Op_RegisterHook) {
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
    }*/

    else {
        foundCommand = false;
    }

    // If we found the command, return the result
    if (foundCommand) {
        return ret;
    }
    // If not, it was an invalid command
    return this->SendHeader(LunaAPI::Resp_InvalidCommand);
}

// Client connection flow
BOOL LunaServer::ServeConnection(LunaServer* connection) {
    // Don't lock here
    BOOL ret = TRUE;
    BOOL close = FALSE;

    WRITELINE_DEBUG("Connected!");
    // Handshake first
    if (connection->ServerHandshake()) {
        WRITELINE_DEBUG("Handshake success!");
    }
    else {
        WRITELINE_DEBUG("Handshake failed!");
        ret = FALSE;
        goto cleanup;
    }

    // Wait for commands until the connection is set to close
    while (!close) {
        close = connection->RunCommand();
    }
    WRITELINE_DEBUG("Closing connection...");

cleanup:
    // Clean the connection up when we're done with it
    CONNECTED_CLIENTS.erase(connection->hPipe);
    free(connection);
    return ret;
}

BOOL BeginServer(LPVOID lpParam) {
    if (lpParam == NULL) {
        // We don't have an ID to set up the server
        return FALSE;
    }
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
            LunaServer* connection = new LunaServer(hPipeRPC);
            if (connection == NULL) {
                WRITELINE_DEBUG("Could not allocate memory for new RPC connection.");
                continue;
            }
            HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LunaServer::ServeConnection, connection, 0, NULL);
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

    // TODO: Clean up all leftover threads here
    // No threads left behind

    LocalFree(psd);
    WRITELINE_DEBUG("Server thread exitting now...");
    return TRUE;
}