#include "pch.h"
#include <iostream>

#include "Config.h"
#include "Implant.h"

#include "connection.h"
#include "output.h"

using namespace LunaAPI;

LunaImplant::LunaImplant(LPCSTR implantID) {
    registry = HookRegistry();
    size_t idLength = strlen(implantID);
    if (idLength > LUNA_MAX_ID_LENGTH) {
        DISP_WARN("Implant ID cannot be above " << LUNA_MAX_ID_LENGTH << "Characters. '" << implantID << "' will be truncated");
    }
    memcpy_s(id, LUNA_MAX_ID_LENGTH, implantID, idLength);
    
    // Set this up on connect
    connected = FALSE;
    hPipeRPC = NULL;
}

BOOL LunaImplant::Connect() {
    // The stub is 10 chars long (incl null byte), then ID is 24 (excl null byte)
    char pipeName[LUNA_MAX_ID_LENGTH + 10] = "\\\\.\\pipe\\";
    for (size_t i = 0; i < LUNA_MAX_ID_LENGTH + 1; i++) {
        pipeName[i + 9] = id[i];
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

    BOOL connected = Handshake();

    if (connected) {
        DISP_REMOTE("Completed handshake with LunaJuice.");
    }
    else {
        DISP_ERROR("Could not complete handshake with LunaJuice");
    }

    // Close the pipe
    CloseHandle(hPipeRPC);

    return TRUE;
}

void LunaImplant::Disconnect() {
    // It doesn't really matter if it goes through or not
    // the connection is about to close anyway
    SendPacket(this->hPipeRPC, Op_Disconnect, NULL, 0);
    connected = FALSE;
}

BOOL LunaImplant::Handshake() {
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

BOOL LunaImplant::RegisterHook(LPCSTR identifier) {
    BOOL result = SendPacket(this->hPipeRPC, Op_RegisterHook, (LPCVOID)identifier, strlen(identifier));
    if (!result) {
        UPDATE_ERROR("Could not send data to LunaJuice to register hook");
        return FALSE;
    }
    PacketHeader header;
    result = RecvHeader(this->hPipeRPC, &header);
    if (!result) {
        UPDATE_ERROR("Could not get packet header from LunaJuice");
        return FALSE;
    }
    if (header.code.response == Resp_UnknownError) {
        DISP_ERROR("Could not register hook with LunaJuice");
    }

    HookID id = 0;
    result = RecvFixedData(this->hPipeRPC, &id, sizeof(id));
    if (!result) {
        UPDATE_ERROR("Could not get hook ID from LunaJuice");
        return FALSE;
    }
    this->registry[identifier] = id;
    DISP_VERBOSE_REMOTE("Registered '" << identifier << "' as " << id << ".");
    return TRUE;
}