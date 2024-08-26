#pragma once
#include <Windows.h>

// Default values
// This is a C++ feature
typedef struct _LUNA_ARGUMENTS {
	LPCSTR dropPrivileges = "";
	LPCSTR mitigations = "";
	LPCSTR hooks = "default";
#if _DEBUG
	BOOL verbose = TRUE;
#else
	BOOL verbose = FALSE;
#endif
	BOOL help = FALSE;
	DWORD pid = 0;
} LUNA_ARGUMENTS;

LUNA_ARGUMENTS GetArguments(int argc, char* argv[]);
void DisplayUsage();

// Useful for positioning in arguments.cpp, not really useful outside
void ParseArg(int* index, int argc, char* argv[], char eq, LUNA_ARGUMENTS* args);