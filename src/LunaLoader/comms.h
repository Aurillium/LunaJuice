
#pragma once
#include <Windows.h>

#include "arguments.h"

#define ID_CHARACTERS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"

void LoadCustomID(const char* id);
BOOL PopulateStartData(LUNA_ARGUMENTS* arguments);
BOOL InitialiseLunaJuice(HANDLE hProcess, LPTHREAD_START_ROUTINE initLocation);
BOOL ConnectLunaJuice();