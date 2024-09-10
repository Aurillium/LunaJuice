#pragma once
#include <Windows.h>

// Default values
// This is a C++ feature
typedef struct _LUNA_ARGUMENTS {
	LPCSTR dropPrivileges = "";
	LPCSTR mitigations = "";
	LPCSTR events = "";
	LPCSTR hooks = "";
	LPCSTR name = "";
#if _DEBUG
	BOOL verbose = TRUE;
#else
	BOOL verbose = FALSE;
#endif
	BOOL help = FALSE;
	BOOL rpc = FALSE;
	DWORD pid = 0;

	BOOL testMode = FALSE;
} LUNA_ARGUMENTS;

LUNA_ARGUMENTS GetArguments(int argc, char* argv[]);
void DisplayUsage();

// Useful for positioning in arguments.cpp, not really useful outside
void ParseArg(int* index, int argc, char* argv[], char eq, LUNA_ARGUMENTS* args);