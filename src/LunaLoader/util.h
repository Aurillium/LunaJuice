
#pragma once
#include <Windows.h>

DWORD FindPidByName(LPCSTR name);

bool NoCapCmp(const char* string, const char* other, size_t length);
bool NoCapCmp(const char* string, const char* other);

void RandomString(char* buffer, const char* options, size_t length);

#define ADD_FLAG_CMP(name, expr, update) if (NoCapCmp(expr, #name)) {\
    update = update | Enable_##name;\
}