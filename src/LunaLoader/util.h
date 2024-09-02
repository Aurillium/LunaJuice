
#pragma once
#include <Windows.h>

DWORD FindPidByName(LPCSTR name);

bool NoCapCmp(const char* string, const char* other, size_t length);
bool NoCapCmp(const char* string, const char* other);

#define ADD_FLAG_CMP(name, expr, update) if (NoCapCmp(expr, #name)) {\
    update = update | LunaAPI::Enable_##name;\
}