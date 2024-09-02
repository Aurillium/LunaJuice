#pragma once
#include "framework.h"

#include "Loader.h"

namespace LunaAPI {
	class LUNA_API LunaImplant {
	private:
		// Private variables
		HANDLE hPipeRPC;
		CHAR id[LUNA_MAX_ID_LENGTH + 1];
		BOOL connected;

		// Internal functions
		BOOL Handshake();
	public:
		LunaImplant(LPCSTR id);
		BOOL Connect();
	};
}