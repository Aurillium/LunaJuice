#pragma once
#include <Windows.h>

#include "Protocol.h"

using namespace LunaAPI;

BOOL SendPacket(HANDLE hPipe, OpCode code, LPCVOID buffer, size_t length);
BOOL RecvPacket(HANDLE hPipe, PacketHeader* header, LPVOID* buffer);
BOOL RecvFixedPacket(HANDLE hPipe, PacketHeader* header, LPVOID buffer, size_t length);
BOOL RecvHeader(HANDLE hPipe, PacketHeader* header);
BOOL RecvFixedData(HANDLE hPipe, LPVOID buffer, size_t length);
