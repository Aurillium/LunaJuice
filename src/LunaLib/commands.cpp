#include "pch.h"
#include <any>

#include "commands.h"
#include "hooking.h"

#include "Config.h"

BOOL Handle_RegisterHook(HANDLE hPipe, LPVOID buffer, DWORD length) {
	REQUIRE_DATA(hPipe, buffer, length);

	LPSTR target = (LPSTR)malloc(length + sizeof(CHAR));
	if (target == NULL) {
		WRITELINE_DEBUG("Could not allocate memory to store target function name.");
		return SendError(hPipe, LunaAPI::Resp_OutOfMemory);
	}
	memcpy_s(target, length, buffer, length);
	// Null terminate
	target[length] = 0;
	DWORD i = 0;
	while (target[i] != 0) {
		if (target[i] == '!') {
			break;
		}
		i++;
	}
	if (i == 0) {
		WRITELINE_DEBUG("'!' either not in target or invalid position.");
		free(target);
		return SendError(hPipe, LunaAPI::Resp_BadParameter);
	}
	void* hookAddress = GetHookFunction((LPCSTR)target);
	if (hookAddress == NULL) {
		free(target);
		return SendError(hPipe, LunaAPI::Resp_UnsupportedHook);
	}
	LunaAPI::HookID id = LunaHook<std::any(*)(std::any)>::Register(target, hookAddress, GetDefaultMitigations(), GetDefaultLogs());
	free(target);

	if (id == MAXDWORD32) {
		return SendError(hPipe, LunaAPI::Resp_UnknownError);
	}

	return SendData(hPipe, LunaAPI::Resp_Success, &id, sizeof(id));
}
BOOL Handle_SetDefaultMitigations(HANDLE hPipe, LPVOID buffer, DWORD length) {
	REQUIRE_DATA(hPipe, buffer, length);
	REQUIRE_LENGTH(hPipe, buffer, length, sizeof(LunaAPI::MitigationFlags));

	LunaAPI::MitigationFlags* mitigations = (LunaAPI::MitigationFlags*)buffer;
	SetDefaultMitigations(*mitigations);

	return SendError(hPipe, LunaAPI::Resp_Success);
}
BOOL Handle_SetDefaultLogging(HANDLE hPipe, LPVOID buffer, DWORD length) {
	REQUIRE_DATA(hPipe, buffer, length);
	REQUIRE_LENGTH(hPipe, buffer, length, sizeof(LunaAPI::LogFlags));

	LunaAPI::LogFlags* logs = (LunaAPI::LogFlags*)buffer;
	SetDefaultLogs(*logs);

	return SendError(hPipe, LunaAPI::Resp_Success);
}
BOOL Handle_SetFunctionConfig(HANDLE hPipe, LPVOID buffer, DWORD length) {
	REQUIRE_DATA(hPipe, buffer, length);
	REQUIRE_LENGTH(hPipe, buffer, length, sizeof(LunaAPI::HookConfig));

	return SendError(hPipe, LunaAPI::Resp_Success);
}
BOOL Handle_AddFunctionConfig(HANDLE hPipe, LPVOID buffer, DWORD length) {
	REQUIRE_DATA(hPipe, buffer, length);
	REQUIRE_LENGTH(hPipe, buffer, length, sizeof(LunaAPI::HookConfig));

	return SendError(hPipe, LunaAPI::Resp_Success);
}
BOOL Handle_DelFunctionConfig(HANDLE hPipe, LPVOID buffer, DWORD length) {
	REQUIRE_DATA(hPipe, buffer, length);
	REQUIRE_LENGTH(hPipe, buffer, length, sizeof(LunaAPI::HookConfig));

	return SendError(hPipe, LunaAPI::Resp_Success);
}
BOOL Handle_SetFunctionState(HANDLE hPipe, LPVOID buffer, DWORD length) {
	REQUIRE_DATA(hPipe, buffer, length);
	//REQUIRE_LENGTH(hPipe, buffer, length, sizeof(LunaAPI::HooksEnabled));

	return SendError(hPipe, LunaAPI::Resp_Success);
}
BOOL Handle_SetSecuritySettings(HANDLE hPipe, LPVOID buffer, DWORD length) {
	REQUIRE_DATA(hPipe, buffer, length);
	REQUIRE_LENGTH(hPipe, buffer, length, sizeof(LunaAPI::SecuritySettings));

	return SendError(hPipe, LunaAPI::Resp_Success);
}

BOOL Handle_GetDefaultPolicy(HANDLE hPipe, LPVOID buffer, DWORD length) {
	return FALSE;
}
BOOL Handle_GetFunctionInfo(HANDLE hPipe, LPVOID buffer, DWORD length) {
	return FALSE;
}
BOOL Handle_GetSecuritySettings(HANDLE hPipe, LPVOID buffer, DWORD length) {
	return FALSE;
}