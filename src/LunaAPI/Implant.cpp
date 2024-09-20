#include "pch.h"
#include <iostream>

#include "Config.h"
#include "Implant.h"
#include "Protocol.h"

#include "connection.h"
#include "output.h"

using namespace LunaAPI;

LunaImplant::LunaImplant(LPCSTR implantID) {
    registry = HookRegistry();
    size_t idLength = strlen(implantID);
    if (idLength > LUNA_MAX_ID_LENGTH) {
        DISP_WARN("Implant ID cannot be above " << LUNA_MAX_ID_LENGTH << " characters. '" << implantID << "' will be truncated");
        idLength = LUNA_MAX_ID_LENGTH;
    }
    memcpy_s(id, LUNA_MAX_ID_LENGTH, implantID, idLength);
    // Null terminate
    id[idLength] = 0;
    
    // Set this up on connect
    connected = FALSE;
    hPipeRPC = NULL;
}

ResponseCode LunaImplant::Connect() {
    // The stub is 10 chars long (incl null byte), then ID is 24 (excl null byte)
    char pipeName[LUNA_MAX_ID_LENGTH + 10] = "\\\\.\\pipe\\";
    for (size_t i = 0; i < LUNA_MAX_ID_LENGTH; i++) {
        pipeName[i + 9] = this->id[i];
    }
    // Null terminate if not done already
    pipeName[LUNA_MAX_ID_LENGTH + 9] = 0;

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

    DISP_VERBOSE("Connecting to '" << pipeName << "'...");
    if (hPipeRPC == INVALID_HANDLE_VALUE) {
        DISP_WINERROR("Could not connect to LunaJuice pipe");
        return Resp_Disconnect;
    }

    this->connected = Handshake() == Resp_Success;

    if (connected) {
        DISP_REMOTE("Completed handshake with LunaJuice.");
    }
    else {
        DISP_ERROR("Could not complete handshake with LunaJuice");
    }

    return Resp_Success;
}
void LunaImplant::Disconnect() {
    // It doesn't really matter if it goes through or not
    // the connection is about to close anyway
    SendPacket(this->hPipeRPC, Op_Disconnect, NULL, 0);
    this->connected = FALSE;
    CloseHandle(this->hPipeRPC);
}
BOOL LunaImplant::IsConnected() {
    if (this->connected) {
        if (this->hPipeRPC == NULL || this->hPipeRPC == INVALID_HANDLE_VALUE) {
            this->connected = FALSE;
        }
        else {
            return TRUE;
        }
    }
    DISP_VERBOSE("IsConnected(): pipe is null = " << (this->hPipeRPC == NULL) << ", handle invalid = " << (this->hPipeRPC == INVALID_HANDLE_VALUE) << ", connected false = " << (this->connected == FALSE));
    return FALSE;
}

ResponseCode LunaImplant::Handshake() {
    DISP_VERBOSE("Attempting handshake...");

    // Send handshake message to ensure connection is working
    DWORD bytesWritten = 0, bytesRead = 0;
    const char initialMessage[] = "marco";
    BOOL success = WriteFile(hPipeRPC, initialMessage, sizeof(initialMessage), &bytesWritten, NULL);
    if (!success || sizeof(initialMessage) != bytesWritten) {
        DISP_WINERROR("Could not write to LunaJuice pipe");
        CloseHandle(hPipeRPC);
        return Resp_Disconnect;
    }
    UPDATE_VERBOSE("marco");

    // Read server's response
    char buffer[8];
    success = ReadFile(hPipeRPC, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
    if (!success || bytesRead == 0) {
        DISP_WINERROR("Could not read LunaJuice pipe");
        CloseHandle(hPipeRPC);
        return Resp_Disconnect;
    }
    if (buffer[0] == 'p' && buffer[1] == 'o' && buffer[2] == 'l' && buffer[3] == 'o') {
        UPDATE_VERBOSE_REMOTE("polo");
        return Resp_Success;
    }
    CloseHandle(hPipeRPC);
    DISP_ERROR("Handshake with RPC failed");
    return Resp_Disconnect;
}

ResponseCode LunaImplant::RegisterHook(LPCSTR identifier) {
    BOOL result = SendPacket(this->hPipeRPC, Op_NativeRegisterHook, (LPCVOID)identifier, strlen(identifier));
    if (!result) {
        UPDATE_ERROR("Could not send data to LunaJuice to register hook");
        return Resp_Disconnect;
    }
    PacketHeader header;
    result = RecvHeader(this->hPipeRPC, &header);
    if (!result) {
        UPDATE_ERROR("Could not get packet header from LunaJuice");
        return Resp_Disconnect;
    }
    if (header.code.response != Resp_Success) {
        DISP_ERROR("Could not register hook with LunaJuice");
        return header.code.response;
    }

    HookID id = 0;
    result = RecvFixedData(this->hPipeRPC, &id, sizeof(id));
    if (!result) {
        UPDATE_ERROR("Could not get hook ID from LunaJuice");
        return Resp_Disconnect;
    }
    this->registry[identifier] = id;
    DISP_VERBOSE_REMOTE("Registered '" << identifier << "' as " << id << ".");
    return Resp_Success;
}

ResponseCode LunaImplant::SetDefaultMitigations(LunaAPI::MitigationFlags mitigations) {
    BOOL result = SendPacket(this->hPipeRPC, Op_NativeSetDefaultMiti, &mitigations, sizeof(mitigations));
    if (!result) {
        UPDATE_ERROR("Could not send data to LunaJuice to set default mitigations");
        return Resp_Disconnect;
    }

    PacketHeader header;
    result = RecvHeader(this->hPipeRPC, &header);
    if (!result) {
        UPDATE_ERROR("Could not get packet header from LunaJuice");
        return Resp_Disconnect;
    }
    return header.code.response;
}
ResponseCode LunaImplant::SetDefaultLogs(LunaAPI::LogFlags logs) {
    BOOL result = SendPacket(this->hPipeRPC, Op_NativeSetDefaultLogs, &logs, sizeof(logs));
    if (!result) {
        UPDATE_ERROR("Could not send data to LunaJuice to set default logs");
        return Resp_Disconnect;
    }

    PacketHeader header;
    result = RecvHeader(this->hPipeRPC, &header);
    if (!result) {
        UPDATE_ERROR("Could not get packet header from LunaJuice");
        return Resp_Disconnect;
    }
    return header.code.response;
}
ResponseCode LunaImplant::SetSecuritySettings(LunaAPI::SecuritySettings security) {
    BOOL result = SendPacket(this->hPipeRPC, Op_SetSecuritySettings, &security, sizeof(security));
    if (!result) {
        UPDATE_ERROR("Could not send data to LunaJuice to set security policy");
        return Resp_Disconnect;
    }
    PacketHeader header;
    result = RecvHeader(this->hPipeRPC, &header);
    if (!result) {
        UPDATE_ERROR("Could not get packet header from LunaJuice");
        return Resp_Disconnect;
    }
    return header.code.response;
}
ResponseCode LunaImplant::SetFunctionConfig(HookConfig config) {
    BOOL result = SendPacket(this->hPipeRPC, Op_NativeSetFunctionConfig, &config, sizeof(config));
    if (!result) {
        UPDATE_ERROR("Could not send data to LunaJuice to set function config");
        return Resp_Disconnect;
    }
    PacketHeader header;
    result = RecvHeader(this->hPipeRPC, &header);
    if (!result) {
        UPDATE_ERROR("Could not get packet header from LunaJuice");
        return Resp_Disconnect;
    }
    return header.code.response;
}
ResponseCode LunaImplant::AddFunctionConfig(HookConfig config) {
    BOOL result = SendPacket(this->hPipeRPC, Op_NativeAddFunctionConfig, &config, sizeof(config));
    if (!result) {
        UPDATE_ERROR("Could not send data to LunaJuice to add function config");
        return Resp_Disconnect;
    }
    PacketHeader header;
    result = RecvHeader(this->hPipeRPC, &header);
    if (!result) {
        UPDATE_ERROR("Could not get packet header from LunaJuice");
        return Resp_Disconnect;
    }
    return header.code.response;
}
ResponseCode LunaImplant::DelFunctionConfig(HookConfig config) {
    BOOL result = SendPacket(this->hPipeRPC, Op_NativeDelFunctionConfig, &config, sizeof(config));
    if (!result) {
        UPDATE_ERROR("Could not send data to LunaJuice to remove function config");
        return Resp_Disconnect;
    }
    PacketHeader header;
    result = RecvHeader(this->hPipeRPC, &header);
    if (!result) {
        UPDATE_ERROR("Could not get packet header from LunaJuice");
        return Resp_Disconnect;
    }
    return header.code.response;
}
ResponseCode LunaImplant::SetFunctionState(HookID id, BOOL enabled) {
    DWORD bufferSize = sizeof(id) + sizeof(enabled);
    void* buffer = malloc(bufferSize);
    // Copy hook ID, followed by status
    memcpy_s(buffer, sizeof(id), &id, sizeof(id));
    memcpy_s((void*)((uint64_t)buffer + sizeof(id)), sizeof(enabled), &enabled, sizeof(enabled));

    // Send the buffer
    BOOL result = SendPacket(this->hPipeRPC, Op_NativeSetFunctionState, buffer, bufferSize);
    if (!result) {
        UPDATE_ERROR("Could not send header to LunaJuice to set function state");
        return Resp_Disconnect;
    }
    
    PacketHeader header;
    result = RecvHeader(this->hPipeRPC, &header);
    if (!result) {
        UPDATE_ERROR("Could not get packet header from LunaJuice");
        return Resp_Disconnect;
    }
    return header.code.response;
}

ResponseCode LunaImplant::SetFunctionConfig(LPCSTR id, MitigationFlags mitigations, LogFlags logs) {
    auto entry = this->registry.find(id);
    if (entry == this->registry.end()) {
        return Resp_NotFound;
    }
    HookConfig config = HookConfig();
    config.hook = entry->second;
    config.mitigations = mitigations;
    config.logs = logs;
    return this->SetFunctionConfig(config);
}
ResponseCode LunaImplant::AddFunctionConfig(LPCSTR id, MitigationFlags mitigations, LogFlags logs) {
    auto entry = this->registry.find(id);
    if (entry == this->registry.end()) {
        return Resp_NotFound;
    }
    HookConfig config = HookConfig();
    config.hook = entry->second;
    config.mitigations = mitigations;
    config.logs = logs;
    return this->AddFunctionConfig(config);
}
ResponseCode LunaImplant::DelFunctionConfig(LPCSTR id, MitigationFlags mitigations, LogFlags logs) {
    auto entry = this->registry.find(id);
    if (entry == this->registry.end()) {
        return Resp_NotFound;
    }
    HookConfig config = HookConfig();
    config.hook = entry->second;
    config.mitigations = mitigations;
    config.logs = logs;
    return this->DelFunctionConfig(config);
}
ResponseCode LunaImplant::SetFunctionState(LPCSTR id, BOOL enabled) {
    auto entry = this->registry.find(id);
    if (entry == this->registry.end()) {
        return Resp_NotFound;
    }
    return this->SetFunctionState(entry->second, enabled);
}


// Get config
/*ResponseCode LunaImplant::GetDefaultPolicy(Policy* policy) {
    BOOL result = SendPacket(this->hPipeRPC, Op_NativeGetDefaultLogs, NULL, 0);
    if (!result) {
        UPDATE_ERROR("Could not send data to LunaJuice to get default policy");
        return Resp_Disconnect;
    }
    PacketHeader header;
    result = RecvHeader(this->hPipeRPC, &header);
    if (!result) {
        UPDATE_ERROR("Could not get packet header from LunaJuice");
        return Resp_Disconnect;
    }
    if (header.code.response != Resp_Success) {
        DISP_ERROR("Could not get default policy");
        return header.code.response;
    }

    result = RecvFixedData(this->hPipeRPC, policy., sizeof(*policy));
    if (!result) {
        UPDATE_ERROR("Could not receive default policy from LunaJuice");
        return Resp_Disconnect;
    }
    return Resp_Success;
}*/
ResponseCode LunaImplant::GetRegistrySize(HookID* size) {
    BOOL result = SendPacket(this->hPipeRPC, Op_GetRegistrySize, NULL, 0);
    if (!result) {
        UPDATE_ERROR("Could not send data to LunaJuice to get registry size");
        return Resp_Disconnect;
    }
    PacketHeader header;
    result = RecvHeader(this->hPipeRPC, &header);
    if (!result) {
        UPDATE_ERROR("Could not get packet header from LunaJuice");
        return Resp_Disconnect;
    }
    if (header.code.response != Resp_Success) {
        DISP_ERROR("Could not get registry size");
        return header.code.response;
    }

    result = RecvFixedData(this->hPipeRPC, size, sizeof(*size));
    if (!result) {
        UPDATE_ERROR("Could not receive registry size from LunaJuice");
        return Resp_Disconnect;
    }
    return Resp_Success;
}
//ResponseCode LunaImplant::GetFunctionIdentifier(HookID id, LPCSTR* answer, size_t* length);
ResponseCode LunaImplant::QueryByIdentifier(LPCSTR id, HookID* answer) {
    BOOL result = SendPacket(this->hPipeRPC, Op_QueryByIdentifier, id, strlen(id));
    if (!result) {
        UPDATE_ERROR("Could not send data to LunaJuice to get function identifier");
        return Resp_Disconnect;
    }
    PacketHeader header;
    result = RecvHeader(this->hPipeRPC, &header);
    if (!result) {
        UPDATE_ERROR("Could not get packet header from LunaJuice");
        return Resp_Disconnect;
    }
    if (header.code.response != Resp_Success) {
        DISP_ERROR("Could not get function identifier");
        return header.code.response;
    }

    result = RecvFixedData(this->hPipeRPC, answer, sizeof(*answer));
    if (!result) {
        UPDATE_ERROR("Could not receive function identifier from LunaJuice");
        return Resp_Disconnect;
    }
    return Resp_Success;
}

// TODO: may be broken
ResponseCode LunaImplant::GetFunctionInfo(HookID id, HookConfig* config, BOOL* enabled) {
    BOOL result = SendPacket(this->hPipeRPC, Op_NativeGetFunctionConfig, &id, sizeof(id));
    if (!result) {
        UPDATE_ERROR("Could not send data to LunaJuice to get function info");
        return Resp_Disconnect;
    }
    PacketHeader header;
    result = RecvHeader(this->hPipeRPC, &header);
    if (!result) {
        UPDATE_ERROR("Could not get packet header from LunaJuice");
        return Resp_Disconnect;
    }
    if (header.code.response != Resp_Success) {
        DISP_ERROR("Could not get function data");
        return header.code.response;
    }
    if (header.length != sizeof(*config) + sizeof(*enabled)) {
        DISP_ERROR("Packet was wrong length for function info");
        return Resp_Disconnect;
    }

    // Receive config then state
    result = RecvFixedData(this->hPipeRPC, config, sizeof(*config));
    if (!result) {
        UPDATE_ERROR("Could not receieve function data from LunaJuice");
        return Resp_Disconnect;
    }
    result = RecvFixedData(this->hPipeRPC, enabled, sizeof(*enabled));
    if (!result) {
        UPDATE_ERROR("Could not receieve function state from LunaJuice");
        return Resp_Disconnect;
    }
    return Resp_Success;
}
ResponseCode LunaImplant::GetFunctionInfo(LPCSTR id, HookConfig* config, BOOL* enabled) {
    auto entry = this->registry.find(id);
    if (entry == this->registry.end()) {
        return Resp_NotFound;
    }
    return this->GetFunctionInfo(entry->second, config, enabled);
}


// Debug only area
#ifdef _DEBUG
ResponseCode LunaImplant::AdditionTest(int a, int b, int* c) {
    void* buf = malloc(sizeof(bool) + sizeof(int) * 2);
    char test = 'h';
    memcpy_s(buf, sizeof(bool) + sizeof(int) * 2, &test, sizeof(bool));
    memcpy_s((void*)((uint64_t)buf + sizeof(bool)), sizeof(int) * 2, &a, sizeof(int));
    memcpy_s((void*)((uint64_t)buf + sizeof(bool) + sizeof(int)), sizeof(int), &b, sizeof(int));
    BOOL result = SendPacket(this->hPipeRPC, Op_AddTest, buf, sizeof(bool) + sizeof(int) * 2);
    if (!result) {
        DISP_ERROR("Could not send addition packet");
        return Resp_Disconnect;
    }
    PacketHeader header;
    result = RecvHeader(this->hPipeRPC, &header);
    if (!result) {
        DISP_ERROR("Could not receive addition result header");
        return Resp_Disconnect;
    }
    if (header.code.response != Resp_Success) {
        DISP_ERROR("Failed to add numbers");
        return header.code.response;
    }
    result = RecvFixedData(this->hPipeRPC, c, sizeof(*c));
    if (!result) {
        DISP_ERROR("Could not receive addition result data");
        return Resp_Disconnect;
    }
    return Resp_Success;
}
#endif