#include "pch.h"
#include <any>

#include "commands.h"
#include "hooking.h"
#include "secure.h"

#include "Config.h"

// Does not contain handling for hook existing already
BOOL Handle_RegisterHook(HANDLE hPipe, LPVOID buffer, DWORD length) {
	REQUIRE_DATA(hPipe, buffer, length);

	LPSTR target = (LPSTR)malloc(length + sizeof(CHAR));
	if (target == NULL) {
		WRITELINE_DEBUG("Could not allocate memory to store target function name.");
		return SendHeader(hPipe, LunaAPI::Resp_OutOfMemory);
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
		return SendHeader(hPipe, LunaAPI::Resp_BadParameter);
	}
	void* hookAddress = GetHookFunction((LPCSTR)target);
	if (hookAddress == NULL) {
		free(target);
		return SendHeader(hPipe, LunaAPI::Resp_UnsupportedHook);
	}
	LunaAPI::HookID id = LunaHook<AnyFunction>::Register(target, hookAddress, GetDefaultMitigations(), GetDefaultLogs());
	free(target);

	if (id == MAXDWORD32) {
		return SendHeader(hPipe, LunaAPI::Resp_UnknownError);
	}

	return SendPacket(hPipe, LunaAPI::Resp_Success, &id, sizeof(id));
}

BOOL Handle_SetDefaultMitigations(HANDLE hPipe, LPVOID buffer, DWORD length) {
	REQUIRE_DATA(hPipe, buffer, length);
	REQUIRE_LENGTH(hPipe, buffer, length, sizeof(LunaAPI::MitigationFlags));

	LunaAPI::MitigationFlags mitigations = *(LunaAPI::MitigationFlags*)buffer;
	SetDefaultMitigations(mitigations);

	return SendHeader(hPipe, LunaAPI::Resp_Success);
}

BOOL Handle_SetDefaultLogging(HANDLE hPipe, LPVOID buffer, DWORD length) {
	REQUIRE_DATA(hPipe, buffer, length);
	REQUIRE_LENGTH(hPipe, buffer, length, sizeof(LunaAPI::LogFlags));

	LunaAPI::LogFlags logs = *(LunaAPI::LogFlags*)buffer;
	SetDefaultLogs(logs);

	return SendHeader(hPipe, LunaAPI::Resp_Success);
}

BOOL Handle_SetFunctionConfig(HANDLE hPipe, LPVOID buffer, DWORD length) {
	REQUIRE_DATA(hPipe, buffer, length);
	REQUIRE_LENGTH(hPipe, buffer, length, sizeof(LunaAPI::HookConfig));

	LunaAPI::HookConfig config = *(LunaAPI::HookConfig*)buffer;
	if (config.hook >= HOOK_STORAGE.size()) {
		return SendHeader(hPipe, LunaAPI::Resp_NotFound);
	}

	// = new
	LunaHook<AnyFunction>* hook = HOOK_STORAGE[config.hook];
	hook->mitigations = config.mitigations;
	hook->logEvents = config.logs;

	return SendHeader(hPipe, LunaAPI::Resp_Success);
}

BOOL Handle_AddFunctionConfig(HANDLE hPipe, LPVOID buffer, DWORD length) {
	REQUIRE_DATA(hPipe, buffer, length);
	REQUIRE_LENGTH(hPipe, buffer, length, sizeof(LunaAPI::HookConfig));

	LunaAPI::HookConfig config = *(LunaAPI::HookConfig*)buffer;
	if (config.hook >= HOOK_STORAGE.size()) {
		return SendHeader(hPipe, LunaAPI::Resp_NotFound);
	}

	// = new | current
	LunaHook<AnyFunction>* hook = HOOK_STORAGE[config.hook];
	hook->mitigations |= config.mitigations;
	hook->logEvents |= config.logs;

	return SendHeader(hPipe, LunaAPI::Resp_Success);
}

BOOL Handle_DelFunctionConfig(HANDLE hPipe, LPVOID buffer, DWORD length) {
	REQUIRE_DATA(hPipe, buffer, length);
	REQUIRE_LENGTH(hPipe, buffer, length, sizeof(LunaAPI::HookConfig));

	LunaAPI::HookConfig config = *(LunaAPI::HookConfig*)buffer;
	if (config.hook >= HOOK_STORAGE.size()) {
		return SendHeader(hPipe, LunaAPI::Resp_NotFound);
	}

	// = current & !new
	LunaHook<AnyFunction>* hook = HOOK_STORAGE[config.hook];
	hook->mitigations &= ~config.mitigations;
	hook->logEvents &= ~config.logs;

	return SendHeader(hPipe, LunaAPI::Resp_Success);
}

BOOL Handle_SetFunctionState(HANDLE hPipe, LPVOID buffer, DWORD length) {
	REQUIRE_DATA(hPipe, buffer, length);
	REQUIRE_LENGTH(hPipe, buffer, length, sizeof(LunaAPI::HookID) + sizeof(BOOL));

	LunaAPI::HookID id = *(LunaAPI::HookID*)buffer;
	if (id >= HOOK_STORAGE.size()) {
		return SendHeader(hPipe, LunaAPI::Resp_NotFound);
	}
	// Should be the memory directly after hook ID
	BOOL enabled = *(BOOL*)( (uint64_t)buffer + sizeof(LunaAPI::HookID) );

	LunaHook<AnyFunction>* hook = HOOK_STORAGE[id];
	// Enable if that's the choice, or disable
	BOOL success = enabled ? hook->Enable() : hook->Disable();
	// Return whether it succeeded or failed
	return SendHeader(hPipe, success ? LunaAPI::Resp_Success : LunaAPI::Resp_OperationFailed);
}

BOOL Handle_SetSecuritySettings(HANDLE hPipe, LPVOID buffer, DWORD length) {
	REQUIRE_DATA(hPipe, buffer, length);
	REQUIRE_LENGTH(hPipe, buffer, length, sizeof(LunaAPI::SecuritySettings));

	LunaAPI::SecuritySettings security = *(LunaAPI::SecuritySettings*)buffer;
	SetSecuritySettings(security);

	return SendHeader(hPipe, LunaAPI::Resp_Success);
}




BOOL Handle_GetDefaultPolicy(HANDLE hPipe, LPVOID buffer, DWORD length) {
	LunaAPI::Policy policy = LunaAPI::Policy();
	policy.mitigations = GetDefaultMitigations();
	policy.logs = GetDefaultLogs();
	policy.security = GetSecuritySettings();
	return SendPacket(hPipe, LunaAPI::Resp_Success, &policy, sizeof(policy));
}

BOOL Handle_GetFunctionInfo(HANDLE hPipe, LPVOID buffer, DWORD length) {
	REQUIRE_DATA(hPipe, buffer, length);
	REQUIRE_LENGTH(hPipe, buffer, length, sizeof(LunaAPI::HookID));

	LunaAPI::HookID id = *(LunaAPI::HookID*)buffer;
	if (id >= HOOK_STORAGE.size()) {
		return SendHeader(hPipe, LunaAPI::Resp_NotFound);
	}

	LunaAPI::HookConfig config = LunaAPI::HookConfig();
	config.hook = id;
	config.mitigations = HOOK_STORAGE[id]->mitigations;
	config.logs = HOOK_STORAGE[id]->logEvents;
	BOOL status = HOOK_STORAGE[id]->GetStatus();
	BOOL failed = SendHeader(hPipe, LunaAPI::Resp_Success, sizeof(config) + sizeof(BOOL));
	if (failed) return TRUE;
	failed = SendData(hPipe, &config, sizeof(config));
	if (failed) return TRUE;
	return SendData(hPipe, &status, sizeof(status));
}

BOOL Handle_GetFunctionIdentifier(HANDLE hPipe, LPVOID buffer, DWORD length) {
	REQUIRE_DATA(hPipe, buffer, length);
	REQUIRE_LENGTH(hPipe, buffer, length, sizeof(LunaAPI::HookID));

	LunaAPI::HookID id = *(LunaAPI::HookID*)buffer;
	if (id >= HOOK_STORAGE.size()) {
		return SendHeader(hPipe, LunaAPI::Resp_NotFound);
	}

	// Save identifier in LunaHook, then retrieve here
}

BOOL Handle_GetRegistrySize(HANDLE hPipe, LPVOID buffer, DWORD length) {
	LunaAPI::HookID size = HOOK_STORAGE.size();
	return SendPacket(hPipe, LunaAPI::Resp_Success, &size, sizeof(size));
}

BOOL Handle_QueryByIdentifier(HANDLE hPipe, LPVOID buffer, DWORD length) {
	REQUIRE_DATA(hPipe, buffer, length);

	LPSTR target = (LPSTR)malloc(length + sizeof(CHAR));
	if (target == NULL) {
		WRITELINE_DEBUG("Could not allocate memory to store target function name.");
		return SendHeader(hPipe, LunaAPI::Resp_OutOfMemory);
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
		return SendHeader(hPipe, LunaAPI::Resp_BadParameter);
	}

	auto entry = REGISTRY.find(target);
	free(target);
	if (entry == REGISTRY.end()) {
		return SendHeader(hPipe, LunaAPI::Resp_NotFound);
	}

	return SendPacket(hPipe, LunaAPI::Resp_Success, &entry->second, sizeof(entry->second));
}