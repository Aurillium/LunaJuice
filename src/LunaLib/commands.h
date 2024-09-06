#pragma once
#include <Windows.h>

#include "debug.h"
#include "server.h"

#define REQUIRE_DATA(hPipe, buffer, length) if (buffer == NULL) { \
	WRITELINE_DEBUG("Data was required for RPC call but none provided."); \
	return SendError(hPipe, LunaAPI::Resp_InvalidRequest); \
}
#define REQUIRE_LENGTH(hPipe, buffer, length, required) if (length < required) { \
	WRITELINE_DEBUG("Data provided to RPC call must be at least " << required << " bytes. Was only " << length << "."); \
	return SendError(hPipe, LunaAPI::Resp_InvalidRequest); \
}

BOOL Handle_RegisterHook(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_SetDefaultMitigations(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_SetDefaultLogging(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_SetFunctionConfig(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_AddFunctionConfig(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_DelFunctionConfig(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_SetFunctionState(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_SetSecuritySettings(HANDLE hPipe, LPVOID buffer, DWORD length);

BOOL Handle_GetDefaultPolicy(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_GetFunctionInfo(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_GetFunctionIdentifier(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_GetRegistrySize(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_QueryByIdentifier(HANDLE hPipe, LPVOID buffer, DWORD length);