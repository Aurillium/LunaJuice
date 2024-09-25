#include "pch.h"
#include <iostream>

#include "Config.h"
#include "LunaConnection.h"
#include "Protocol.h"

#include "output.h"

using namespace LunaAPI;

BOOL LunaConnection::GetRaw(void* buffer, DWORD length) {
    std::lock_guard<std::recursive_mutex> lock(*mtx);

    size_t loaded = 0;

    // Keep reading from the buffer until we have the whole object
    while (loaded < length) {
        size_t bufferAvailable = this->bufferLength - this->bufferPosition;
        if (!bufferAvailable) {
            if (!this->LoadNextBuffer()) {
                DISP_ERROR("Could not load data buffer.");
                return FALSE;
            }
            // Go back to the start and recalculate available length
            continue;
        }

        // How much data we can load
        size_t toLoad = min(length, bufferAvailable);
        // Not sure why we need this min when this is supposed to be a safe function, but it doesn't work without it :)
        memcpy_s(
            (void*)((uint64_t)buffer + loaded),
            toLoad,
            (void*)((uint64_t)this->currentBuffer + this->bufferPosition),
            toLoad
        );
        this->bufferPosition += toLoad;
        loaded += toLoad;
    }
    return TRUE;
}

LunaConnection::LunaConnection(HANDLE hPipe) {
    this->hPipe = hPipe;
    this->lastResponse = LunaAPI::Resp_None;
    this->mtx = new std::recursive_mutex();
    // Buffer info
    this->currentBuffer = NULL;
    this->currentLength = 0;
    this->bufferPosition = 0;
    this->bufferLength = 0;
    this->bufferBase = 0;
}
LunaConnection::~LunaConnection() {
    CloseHandle(this->hPipe);
    delete this->mtx;
    free(this->currentBuffer);
}

LunaAPI::ResponseCode LunaConnection::GetLastError() {
    std::lock_guard<std::recursive_mutex> lock(*mtx);
    return this->lastResponse;
}

LunaAPI::PacketHeader LunaConnection::WaitForPacket() {
    DWORD bytesRead = 0;

    LunaAPI::PacketHeader header;
    BOOL success = ReadFile(this->hPipe, &header, sizeof(header), &bytesRead, NULL);
    if (!success || bytesRead != sizeof(header)) {
        DISP_ERROR("Could not read header from LunaJuice pipe: " << GetLastError());
        return LunaAPI::PacketHeader{ LunaAPI::CommCode{LunaAPI::Resp_Disconnect}, 0 };
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
    std::lock_guard<std::recursive_mutex> lock(*mtx);

    if (this->bufferPosition < this->bufferLength) {
        DISP_ERROR("Buffer has not reached its end, are we reloading too early?");
    }
    else if (this->bufferPosition > this->bufferLength) {
        DISP_ERROR("Buffer position is past length, possible overrun?");
    }
    if (this->bufferBase + this->bufferLength == this->currentLength) {
        this->lastResponse = LunaAPI::Resp_OutOfData;
        DISP_ERROR("Out of data from RPC");
        return FALSE;
    }
    free(this->currentBuffer);
    this->bufferBase += this->bufferLength;
    this->bufferLength = min(MAX_PACKET_BUFFER, this->currentLength - this->bufferBase);
    this->bufferPosition = 0;
    this->currentBuffer = malloc(this->bufferLength);
    if (this->currentBuffer == NULL) {
        this->lastResponse = LunaAPI::Resp_OutOfMemory;
        DISP_ERROR("Could not allocate space for RPC data buffer.");
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
            DISP_ERROR("Could not read data from LunaJuice pipe: " << GetLastError());
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


BOOL LunaConnection::SendHeader(LunaAPI::ResponseCode code, DWORD length) {
    DWORD bytesWritten = 0;

    LunaAPI::PacketHeader header;
    header.length = length;
    header.code.response = code;
    BOOL success = WriteFile(this->hPipe, (LPCVOID)&header, sizeof(header), &bytesWritten, NULL);
    if (!success || sizeof(header) != bytesWritten) {
        DISP_ERROR("Could not write to LunaJuice pipe: " << GetLastError());
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
        DISP_ERROR("Could not write response code to LunaJuice pipe: " << GetLastError());
        // True here means close the connection
        return TRUE;
    }
    success = WriteFile(this->hPipe, buffer, length, &bytesWritten, NULL);
    if (!success || length != bytesWritten) {
        DISP_ERROR("Could not write data to LunaJuice pipe: " << GetLastError());
        return TRUE;
    }
    return FALSE;
}



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