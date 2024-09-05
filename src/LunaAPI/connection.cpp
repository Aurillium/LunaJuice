#include "pch.h"
#include <iostream>

#include "Protocol.h"

#include "output.h"

using namespace LunaAPI;

BOOL SendPacket(HANDLE hPipe, OpCode code, LPCVOID buffer, size_t length) {
    DWORD bytesWritten = 0;

    PacketHeader header;
    header.length = length;
    header.code.opcode = code;
    BOOL success = WriteFile(hPipe, (LPCVOID)&header, sizeof(header), &bytesWritten, NULL);
    if (!success || bytesWritten != sizeof(header)) {
        
        DISP_WINERROR("Could not write response code to LunaJuice implant server");
        return FALSE;
    }
    if (length) {
        success = WriteFile(hPipe, buffer, length, &bytesWritten, NULL);
        if (!success || bytesWritten != length) {
            DISP_WINERROR("Could not write data to LunaJuice implant server");
            return FALSE;
        }
    }
    return TRUE;
}

BOOL RecvPacket(HANDLE hPipe, PacketHeader* header, LPVOID* buffer) {
    DWORD bytesRead = 0;

    BOOL success = ReadFile(hPipe, header, sizeof(LunaAPI::PacketHeader), &bytesRead, NULL);
    if (!success || bytesRead != sizeof(*header)) {
        DISP_WINERROR("Could not read response code from LunaJuice implant server");
        return FALSE;
    }

    // By default, there is no data
    *buffer = NULL;
    if (header->length) {
        *buffer = malloc(header->length);
        if (*buffer == NULL) {
            // Return error
            DISP_ERROR("Could not allocate memory for RPC data buffer");
            return FALSE;
        }

        success = ReadFile(hPipe, *buffer, header->length, &bytesRead, NULL);
        if (!success || bytesRead != header->length) {
            free(*buffer);
            *buffer = NULL;
            DISP_WINERROR("Could not read response data from LunaJuice implant server");
            return FALSE;
        }
    }
    return TRUE;
}

BOOL RecvFixedPacket(HANDLE hPipe, PacketHeader* header, LPVOID buffer, size_t length) {
    DWORD bytesRead = 0;

    BOOL success = ReadFile(hPipe, header, sizeof(LunaAPI::PacketHeader), &bytesRead, NULL);
    if (!success || bytesRead != sizeof(*header)) {
        DISP_WINERROR("Could not read response code from LunaJuice implant server");
        return FALSE;
    }

    if (header->length != length) {
        DISP_WINERROR("Expected packet length (" << length << ") and real packet length (" << header->length << ") do not match");
        return FALSE;
    }
    if (header->length) {
        success = ReadFile(hPipe, buffer, header->length, &bytesRead, NULL);
        if (!success || bytesRead != header->length) {
            DISP_WINERROR("Could not read response data from LunaJuice implant server");
            return FALSE;
        }
    }
    return TRUE;
}

BOOL RecvHeader(HANDLE hPipe, PacketHeader* header) {
    DWORD bytesRead = 0;

    BOOL success = ReadFile(hPipe, header, sizeof(LunaAPI::PacketHeader), &bytesRead, NULL);
    if (!success || bytesRead != sizeof(*header)) {
        DISP_WINERROR("Could not read response code from LunaJuice implant server");
        return FALSE;
    }
    return TRUE;
}
BOOL RecvFixedData(HANDLE hPipe, LPVOID buffer, size_t length) {
    DWORD bytesRead = 0;

    BOOL success = ReadFile(hPipe, buffer, length, &bytesRead, NULL);
    if (!success || bytesRead != length) {
        DISP_WINERROR("Could not read data from LunaJuice implant server");
        return FALSE;
    }
    return TRUE;
}