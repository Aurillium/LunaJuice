#pragma once
#include "framework.h"

#include "Config.h"
#include "Loader.h"

namespace LunaAPI {
	class LUNA_API LunaImplant {
	private:
		// Private variables
		HANDLE hPipeRPC;
		CHAR id[LUNA_MAX_ID_LENGTH + 1];
		BOOL connected;
		HookRegistry registry;

		// Internal functions
		BOOL Handshake();
	public:
		LunaImplant(LPCSTR id);
		BOOL Connect();
		void Disconnect();
		BOOL RegisterHook(LPCSTR identifier);
	};
}