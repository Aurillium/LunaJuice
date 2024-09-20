#include "pch.h"
#include <iostream>

#include "Protocol.h"

#include "output.h"

using namespace LunaAPI;

BOOL ReadLengthIntoBuffer(HANDLE hPipe, LPVOID buffer, size_t length) {
    // Loop until all data receieved
    DWORD totalRead = 0;
    while (totalRead < length) {
        DWORD bytesRead = 0;
        BOOL success = ReadFile(hPipe, (void*)((uint64_t)buffer + totalRead), length, &bytesRead, NULL);
        if (!success) {
            DISP_ERROR("Could not read additional data from LunaJuice pipe: " << GetLastError());
            return FALSE;
        }
        if (bytesRead == 0) {
            DISP_WARN("Unexpected end of file");
            break; // End of file
            // This will probably be an error
        }
        totalRead += bytesRead;
    }
    return totalRead == length;
}

BOOL SendPacket(HANDLE hPipe, OpCode code, LPCVOID buffer, size_t length) {
    DWORD bytesWritten = 0;

    PacketHeader header;
    header.length = length;
    header.code.opcode = code;
    BOOL success = WriteFile(hPipe, &header, sizeof(header), &bytesWritten, NULL);
    if (!success || bytesWritten != sizeof(header)) {
        DISP_WINERROR("Could not write opcode to LunaJuice implant server");
        return FALSE;
    }
    if (length) {
        success = WriteFile(hPipe, buffer, length, &bytesWritten, NULL);
        if (!success || bytesWritten != length) {
            DISP_WINERROR("Could not write data to LunaJuice implant server");
            return FALSE;
        }
    }
    //DISP_VERBOSE("Send packet! Bytes: " << bytesWritten);
    return TRUE;
}

BOOL RecvPacket(HANDLE hPipe, PacketHeader* header, LPVOID* buffer) {
    BOOL success = ReadLengthIntoBuffer(hPipe, header, sizeof(*header));
    if (!success) {
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

        success = ReadLengthIntoBuffer(hPipe, *buffer, header->length);
        if (!success) {
            free(*buffer);
            *buffer = NULL;
            DISP_WINERROR("Could not read response data from LunaJuice implant server");
            return FALSE;
        }
    }
    return TRUE;
}

BOOL RecvFixedPacket(HANDLE hPipe, PacketHeader* header, LPVOID buffer, size_t length) {
    BOOL success = ReadLengthIntoBuffer(hPipe, header, sizeof(*header));
    if (!success) {
        DISP_WINERROR("Could not read response code from LunaJuice implant server");
        return FALSE;
    }

    if (header->length != length) {
        DISP_WINERROR("Expected packet length (" << length << ") and real packet length (" << header->length << ") do not match");
        return FALSE;
    }
    if (header->length) {
        success = ReadLengthIntoBuffer(hPipe, buffer, header->length);
        if (!success) {
            DISP_WINERROR("Could not read response data from LunaJuice implant server");
            return FALSE;
        }
    }
    return TRUE;
}

BOOL RecvHeader(HANDLE hPipe, PacketHeader* header) {
    BOOL success = ReadLengthIntoBuffer(hPipe, header, sizeof(*header));
    if (!success) {
        DISP_WINERROR("Could not read response code from LunaJuice implant server");
        return FALSE;
    }
    return TRUE;
}
BOOL RecvFixedData(HANDLE hPipe, LPVOID buffer, size_t length) {
    BOOL success = ReadLengthIntoBuffer(hPipe, buffer, length);
    if (!success) {
        DISP_WINERROR("Could not read data from LunaJuice implant server");
        return FALSE;
    }
    return TRUE;
}