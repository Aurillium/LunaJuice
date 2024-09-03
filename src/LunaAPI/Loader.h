#pragma once
#include "framework.h"

#include <Windows.h>
#include "Config.h"

#ifdef _DEBUG
#define VERBOSE_DEFAULT TRUE
#else
#define VERBOSE_DEFAULT FALSE
#endif

namespace LunaAPI {
	BOOL LUNA_API InjectDLL(HANDLE IN hProcess, LPCSTR IN dllPath, LunaShared OUT *sharedMemory);
	BOOL LUNA_API InitialiseLunaJuice(HANDLE IN hProcess, LPTHREAD_START_ROUTINE IN initLocation, LunaStart IN config);
	void LUNA_API InitialiseLuna(BOOL verbose = VERBOSE_DEFAULT);
}