#pragma once
#include "framework.h"

#include "Config.h"
#include "Loader.h"
#include "Protocol.h"

namespace LunaAPI {
	class LUNA_API LunaImplant {
	private:
		// Private variables
		HANDLE hPipeRPC;
		CHAR id[LUNA_MAX_ID_LENGTH + 1];
		BOOL connected;
		HookRegistry registry;

		// Internal functions
		ResponseCode Handshake();
	public:
		LunaImplant(LPCSTR id);
		ResponseCode Connect();
		void Disconnect();

		// Set config
		ResponseCode RegisterHook(LPCSTR identifier);
		ResponseCode SetDefaultMitigations(LunaAPI::MitigationFlags mitigations);
		ResponseCode SetDefaultLogs(LunaAPI::LogFlags logs);
		ResponseCode SetFunctionConfig(HookConfig config);
		ResponseCode SetFunctionConfig(LPCSTR id, MitigationFlags mitigations, LogFlags logs);
		ResponseCode AddFunctionConfig(HookConfig config);
		ResponseCode AddFunctionConfig(LPCSTR id, MitigationFlags mitigations, LogFlags logs);
		ResponseCode DelFunctionConfig(HookConfig config);
		ResponseCode DelFunctionConfig(LPCSTR id, MitigationFlags mitigations, LogFlags logs);
		ResponseCode SetFunctionState(HookID id, BOOL enabled);
		ResponseCode SetFunctionState(LPCSTR id, BOOL enabled);
		ResponseCode SetSecuritySettings(LunaAPI::SecuritySettings security);

		// Get config
		ResponseCode GetDefaultPolicy(Policy* policy);
		ResponseCode GetFunctionInfo(HookID id, HookConfig* config);
		ResponseCode GetFunctionInfo(LPCSTR id, HookConfig* config);
		//ResponseCode GetFunctionIdentifier(HookID id, LPCSTR* answer, size_t* length);
		ResponseCode GetRegistrySize(HookID* size);
		ResponseCode QueryByIdentifier(LPCSTR id, HookID* answer);
	};
}