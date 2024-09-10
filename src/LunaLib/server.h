
#pragma once
#include <Windows.h>

#include "Protocol.h"

typedef struct _LunaConnection {
	HANDLE hThread;
	BOOL locked;
} LunaConnection;

BOOL SendHeader(HANDLE hPipe, LunaAPI::ResponseCode code, size_t length = 0);
BOOL SendPacket(HANDLE hPipe, LunaAPI::ResponseCode code, LPCVOID buffer, size_t length);
BOOL SendData(HANDLE hPipe, LPCVOID buffer, size_t length);
BOOL BeginServer(LPVOID lpParam);