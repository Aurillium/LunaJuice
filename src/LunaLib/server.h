
#pragma once
#include <Windows.h>

#include "Protocol.h"

typedef struct _LunaConnection {
	HANDLE hThread;
	BOOL locked;
} LunaConnection;

BOOL SendError(HANDLE hPipe, LunaAPI::ResponseCode code);
BOOL SendData(HANDLE hPipe, LunaAPI::ResponseCode code, LPCVOID buffer, size_t length);
BOOL BeginServer(LPVOID lpParam);