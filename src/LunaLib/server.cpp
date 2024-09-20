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

LunaConnection::LunaConnection(HANDLE hPipe) {
    this->hPipe = hPipe;
    this->lastResponse = LunaAPI::Resp_None;
    // Buffer info
    this->currentBuffer = NULL;
    this->currentLength = 0;
    this->bufferPosition = 0;
    this->bufferLength = 0;
    this->bufferBase = 0;
}

LunaAPI::ResponseCode LunaConnection::GetLastError() {
    std::lock_guard<std::recursive_mutex> lock(mtx);
    return this->lastResponse;
}

LunaAPI::PacketHeader LunaConnection::WaitForPacket() {
    DWORD bytesRead = 0;

    LunaAPI::PacketHeader header;
    BOOL success = ReadFile(this->hPipe, &header, sizeof(header), &bytesRead, NULL);
    if (!success || bytesRead != sizeof(header)) {
        WRITELINE_DEBUG("Could not read header from LunaJuice pipe: " << GetLastError());
        return LunaAPI::PacketHeader{LunaAPI::CommCode{LunaAPI::Resp_Disconnect}, 0};
    }
    this->currentLength = header.length;
    this->bufferBase = 0;
    this->bufferLength = 0;
    this->bufferPosition = 0;
    free(this->currentBuffer);
    this->currentBuffer = NULL;
    return header;
}

BOOL LunaConnection::LoadNextBuffer() {
    std::lock_guard<std::recursive_mutex> lock(mtx);

    if (this->bufferPosition < this->bufferLength) {
        WRITELINE_DEBUG("Buffer has not reached its end, are we reloading too early?");
    }
    else if (this->bufferPosition > this->bufferLength) {
        WRITELINE_DEBUG("Buffer position is past length, possible overrun?");
    }
    if (this->bufferBase + this->bufferLength == this->currentLength) {
        this->lastResponse = LunaAPI::Resp_OutOfData;
        WRITELINE_DEBUG("Out of data from RPC");
        return FALSE;
    }
    free(this->currentBuffer);
    this->bufferBase += this->bufferLength;
    this->bufferLength = min(MAX_PACKET_BUFFER, this->currentLength - this->bufferBase);
    this->bufferPosition = 0;
    this->currentBuffer = malloc(this->bufferLength);
    if (this->currentBuffer == NULL) {
        this->lastResponse = LunaAPI::Resp_OutOfMemory;
        WRITELINE_DEBUG("Could not allocate space for RPC data buffer.");
        return FALSE;
    }

    DWORD bytesRead = 0;
    DWORD totalRead = 0;
    while (totalRead < this->bufferLength) {
        BOOL success = ReadFile(this->hPipe, (void*)((uint64_t)this->currentBuffer + totalRead), this->bufferLength - totalRead, &bytesRead, NULL);
        if (!success) {
            free(this->currentBuffer);
            this->currentBuffer = NULL;
            this->currentLength = 0;
            this->bufferBase = 0;
            this->bufferLength = 0;
            this->bufferPosition = 0;
            WRITELINE_DEBUG("Could not read data from LunaJuice pipe: " << GetLastError());
            return FALSE;
        }
        if (bytesRead == 0) {
            break; // End of file
            // This will probably be an error
        }
        totalRead += bytesRead;
    }

    return TRUE;
}

BOOL LunaConnection::ServerHandshake() {
    std::lock_guard<std::recursive_mutex> lock(mtx);
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


BOOL LunaConnection::SendHeader(LunaAPI::ResponseCode code, DWORD length) {
    DWORD bytesWritten = 0;

    LunaAPI::PacketHeader header;
    header.length = length;
    header.code.response = code;
    BOOL success = WriteFile(this->hPipe, (LPCVOID)&header, sizeof(header), &bytesWritten, NULL);
    if (!success || sizeof(header) != bytesWritten) {
        WRITELINE_DEBUG("Could not write to LunaJuice pipe: " << GetLastError());
        // True here means close the connection
        return TRUE;
    }
    return FALSE;
}

BOOL LunaConnection::SendPacket(LunaAPI::ResponseCode code, LPCVOID buffer, DWORD length) {
    DWORD bytesWritten = 0;

    LunaAPI::PacketHeader header;
    header.length = length;
    header.code.response = code;
    BOOL success = WriteFile(this->hPipe, (LPCVOID)&header, sizeof(header), &bytesWritten, NULL);
    if (!success || sizeof(header) != bytesWritten) {
        WRITELINE_DEBUG("Could not write response code to LunaJuice pipe: " << GetLastError());
        // True here means close the connection
        return TRUE;
    }
    success = WriteFile(this->hPipe, buffer, length, &bytesWritten, NULL);
    if (!success || length != bytesWritten) {
        WRITELINE_DEBUG("Could not write data to LunaJuice pipe: " << GetLastError());
        return TRUE;
    }
    return FALSE;
}

BOOL LunaConnection::SendData(LPCVOID buffer, DWORD length) {
    DWORD bytesWritten = 0;

    BOOL success = WriteFile(this->hPipe, buffer, length, &bytesWritten, NULL);
    if (!success || length != bytesWritten) {
        WRITELINE_DEBUG("Could not write data to LunaJuice pipe: " << GetLastError());
        return TRUE;
    }
    return FALSE;
}

BOOL LunaConnection::RunCommand() {
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
BOOL LunaConnection::ServeConnection(LunaConnection* connection) {
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
            LunaConnection* connection = new LunaConnection(hPipeRPC);
            if (connection == NULL) {
                WRITELINE_DEBUG("Could not allocate memory for new RPC connection.");
                continue;
            }
            HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LunaConnection::ServeConnection, connection, 0, NULL);
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