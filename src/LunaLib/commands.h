#pragma once
#include <Windows.h>

#include "debug.h"
#include "server.h"

#define REQUIRE_DATA(hPipe, buffer, length) if (buffer == NULL) { \
	WRITELINE_DEBUG("Data was required for RPC call but none provided."); \
	return SendHeader(hPipe, LunaAPI::Resp_InvalidRequest); \
}
#define REQUIRE_LENGTH(hPipe, buffer, length, required) if (length < required) { \
	WRITELINE_DEBUG("Data provided to RPC call must be at least " << required << " bytes. Was only " << length << "."); \
	return SendHeader(hPipe, LunaAPI::Resp_InvalidRequest); \
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


// NEW

BOOL Handle_GetRegistrySize(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_QueryByIdentifier(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_GetFunctionIdentifier(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_GetEntryInfo(HANDLE hPipe, LPVOID buffer, DWORD length);

BOOL Handle_SetSecuritySettings(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_GetSecuritySettings(HANDLE hPipe, LPVOID buffer, DWORD length);

BOOL Handle_NativeRegisterHook(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_NativeSetDefaultMiti(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_NativeGetDefaultMiti(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_NativeSetDefaultLogs(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_NativeGetDefaultLogs(HANDLE hPipe, LPVOID buffer, DWORD length);

BOOL Handle_NativeSetFunctionConfig(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_NativeAddFunctionConfig(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_NativeDelFunctionConfig(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_NativeGetFunctionConfig(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_NativeSetFunctionState(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_NativeGetFunctionState(HANDLE hPipe, LPVOID buffer, DWORD length);

BOOL Handle_PythonRegisterHook(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_PythonSetDefaultLogs(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_PythonGetDefaultLogs(HANDLE hPipe, LPVOID buffer, DWORD length);

BOOL Handle_PythonSetFunctionConfig(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_PythonAddFunctionConfig(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_PythonDelFunctionConfig(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_PythonGetFunctionConfig(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_PythonSetFunctionState(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_PythonGetFunctionState(HANDLE hPipe, LPVOID buffer, DWORD length);

BOOL Handle_PythonEval(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_PythonExec(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_PythonVersion(HANDLE hPipe, LPVOID buffer, DWORD length);
BOOL Handle_PythonInitialise(HANDLE hPipe, LPVOID buffer, DWORD length);

#ifdef _DEBUG
LunaAPI::ResponseCode Handle_TestFunc(LunaConnection* connection, int* out, RPCArguments* head);
#endif