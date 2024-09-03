#include "pch.h"

#include "commands.h"
#include "hooking.h"

#include "Config.h"

BOOL Handle_SetDefaultMitigations(HANDLE hPipe, LPVOID buffer, DWORD length) {
	REQUIRE_DATA(hPipe, buffer, length);
	REQUIRE_LENGTH(hPipe, buffer, length, sizeof(LunaAPI::MitigationFlags));

	LunaAPI::MitigationFlags* mitigations = (LunaAPI::MitigationFlags*)buffer;
	SetDefaultMitigations(*mitigations);

	SendError(hPipe, LunaAPI::Resp_Success);
}
BOOL Handle_SetDefaultLogging(HANDLE hPipe, LPVOID buffer, DWORD length) {
	REQUIRE_DATA(hPipe, buffer, length);
	REQUIRE_LENGTH(hPipe, buffer, length, sizeof(LunaAPI::LogFlags));

	LunaAPI::LogFlags* logs = (LunaAPI::LogFlags*)buffer;
	SetDefaultLogs(*logs);

	SendError(hPipe, LunaAPI::Resp_Success);
}
BOOL Handle_SetFunctionConfig(HANDLE hPipe, LPVOID buffer, DWORD length) {
	REQUIRE_DATA(hPipe, buffer, length);
	REQUIRE_LENGTH(hPipe, buffer, length, sizeof(LunaAPI::HooksConfig));

	SendError(hPipe, LunaAPI::Resp_Success);
}
BOOL Handle_SetFunctionState(HANDLE hPipe, LPVOID buffer, DWORD length) {
	REQUIRE_DATA(hPipe, buffer, length);
	REQUIRE_LENGTH(hPipe, buffer, length, sizeof(LunaAPI::HooksEnabled));

	SendError(hPipe, LunaAPI::Resp_Success);
}
BOOL Handle_SetSecuritySettings(HANDLE hPipe, LPVOID buffer, DWORD length) {
	REQUIRE_DATA(hPipe, buffer, length);
	REQUIRE_LENGTH(hPipe, buffer, length, sizeof(LunaAPI::SecuritySettings));

	SendError(hPipe, LunaAPI::Resp_Success);
}

BOOL Handle_GetDefaultPolicy(HANDLE hPipe, LPVOID buffer, DWORD length) {
	
}
BOOL Handle_GetFunctionInfo(HANDLE hPipe, LPVOID buffer, DWORD length) {
	
}
BOOL Handle_GetSecuritySettings(HANDLE hPipe, LPVOID buffer, DWORD length) {

}