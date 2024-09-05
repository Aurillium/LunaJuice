#include "pch.h"

#include "events.h"
#include "messages.h"
#include <iostream>

#include "debug.h"
#include "functionlogs.h"
#include "hooks.h"
#include "util.h"

// One instance for the whole process ensures efficiency
HANDLE LOG_HANDLE;

LPCSTR PID;
LPCSTR PPID;
LPCSTR PATH;
LPCSTR PARENT_PATH;
DWORD PPID_INT;

CONST LPCSTR GetOwnPath() { return PATH; }
CONST LPCSTR GetOwnPid() { return PID; }
CONST LPCSTR GetParentPath() { return PARENT_PATH; }
CONST LPCSTR GetParentPid() { return PPID; }
CONST DWORD GetParentPidInt() { return PPID_INT; }

#define DEFAULT_ARGS 5

static BOOL PopulateDetailFields() {
	char* pidBuffer = (char*)calloc(11 /* Max PID size is 10 */, sizeof(char));
	char* pathBuffer = (char*)calloc(MAX_PATH + 1, sizeof(char));
	char* ppidBuffer = (char*)calloc(11 /* Max PID size is 10 */, sizeof(char));
	char* parentPathBuffer = (char*)calloc(MAX_PATH + 1, sizeof(char));

	if (pidBuffer == NULL || pathBuffer == NULL || ppidBuffer == NULL || parentPathBuffer == NULL) {
		WRITELINE_DEBUG("Could not allocate memory for detail fields.");
		return FALSE;
	}

	// TODO: More error handling
	DWORD pid = GetCurrentProcessId();
	sprintf_s(pidBuffer, 11, "%d", pid);

	GetModuleFileNameA(NULL, pathBuffer, MAX_PATH);

	DWORD ppid = GetParentProcessId(pid);
	sprintf_s(ppidBuffer, 11, "%d", ppid);
	PPID_INT = ppid;

	// This should always run before hooking
#if _DEBUG
	static OpenProcess_t RealOpenProcess = (OpenProcess_t)GetRealFunction("kernel32.dll!OpenProcess");
	if (RealOpenProcess == NULL) {
		WRITELINE_DEBUG("OpenProcess function could not be found. This indicates a bug in LunaJuice.");
		return FALSE;
	}
#endif
	HANDLE parentHandle = RealOpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ppid);
	unsigned long bufferLen = MAX_PATH;
	QueryFullProcessImageNameA(parentHandle, 0, parentPathBuffer, &bufferLen);

	PID = pidBuffer;
	PPID = ppidBuffer;
	PATH = pathBuffer;
	PARENT_PATH = parentPathBuffer;

	return TRUE;
}

BOOL OpenLogger() {
	if (LOG_HANDLE != NULL) {
		WRITELINE_DEBUG("Log handle already registered.");
		return FALSE;
	}

	// If this succeeds we definitely have all fields populated
	if (!PopulateDetailFields()) {
		WRITELINE_DEBUG("Could not populate details fields.");
		return FALSE;
	}

	LOG_HANDLE = RegisterEventSourceA(NULL, LOG_NAME);
	if (LOG_HANDLE == NULL) {
		WRITELINE_DEBUG("Log registration failed. Error: " << GetLastError());
		return FALSE;
	}
	return TRUE;
}

BOOL CloseLogger() {
	if (LOG_HANDLE == NULL) {
		WRITELINE_DEBUG("Log handle already closed.");
		return FALSE;
	}

	if (!DeregisterEventSource(LOG_HANDLE)) {
		WRITELINE_DEBUG("Failed to close log. Error: " << GetLastError());
		return FALSE;
	}
	LOG_HANDLE = NULL;
	return TRUE;
}
// Call after freeing your own arguments to avoid memory leaks
static BOOL FreeEventBaseArguments(LPCSTR* arguments, size_t extra = 0) {
	for (size_t i = 0; i < DEFAULT_ARGS + extra; i++)
	{
		// It's up to the user to ensure no constant strings
		// are actually stored.
		free((LPSTR)arguments[i]);
	}
	free(arguments);
	return TRUE;
}

static LPCSTR GetThreadUsername() {
	char usernameBuffer[SECURITY_MAX_SID_SIZE + 1];
	char domainBuffer[SECURITY_MAX_SID_SIZE + 1];

	// Gets thread token or process token if no thread token
	HANDLE token = GetCurrentThreadEffectiveToken();
	if (token == NULL) {
		WRITELINE_DEBUG("Could not get current token.");
		return NULL;
	}
	DWORD tokenUserSize = 0;
	PTOKEN_USER tokenUser;

	// There will be an error saying there isn't enough space because we're giving it a null pointer
	if (!GetTokenInformation(token, TokenUser, nullptr, 0, &tokenUserSize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		WRITELINE_DEBUG("Failed to get token user size: " << GetLastError());
		return NULL;
	}

	tokenUser = (PTOKEN_USER)malloc(tokenUserSize);
	if (tokenUser == NULL) {
		WRITELINE_DEBUG("Failed to allocate space for token user.");
		return NULL;
	}

	if (!GetTokenInformation(token, TokenUser, tokenUser, tokenUserSize, &tokenUserSize)) {
		WRITELINE_DEBUG("Failed to get token user: " << GetLastError());
		free(tokenUser);
		return NULL;
	}

	DWORD usernameSize = SECURITY_MAX_SID_SIZE;
	DWORD domainSize = SECURITY_MAX_SID_SIZE;
	SID_NAME_USE SidType;
	if (!LookupAccountSidA(nullptr, tokenUser->User.Sid, usernameBuffer, &usernameSize, domainBuffer, &domainSize, &SidType)) {
		WRITELINE_DEBUG("Failed to lookup SID.");
		free(tokenUser);
		return NULL;
	}

	DWORD usernameLength = lstrlenA(usernameBuffer);
	DWORD domainLength = lstrlenA(domainBuffer);
	// One extra for null byte, one extra for backslash
	DWORD totalSize = usernameLength + domainLength + 2;
	char* joinedName = (char*)calloc(totalSize, sizeof(char));
	if (joinedName == NULL) {
		WRITELINE_DEBUG("Failed to allocate memory to store username.");
		return NULL;
	}
	memcpy_s(joinedName, domainLength, domainBuffer, domainLength);
	joinedName[domainLength] = '\\';
	memcpy_s(joinedName + domainLength + 1, usernameLength - domainLength - 1, usernameBuffer, usernameLength);

	// This must be freed
	return joinedName;
}

static LPCSTR* EventBaseArguments(size_t extra) {
	HANDLE_CHECK;

	LPCSTR* strings = (LPCSTR*)calloc(DEFAULT_ARGS + extra, sizeof(LPCSTR*));
	if (strings == NULL) {
		return NULL;
	}

	char* pidBuffer = (char*)calloc(11 /* Max PID size is 10 */, sizeof(char));
	char* pathBuffer = (char*)calloc(MAX_PATH + 1, sizeof(char));
	char* ppidBuffer = (char*)calloc(11 /* Max PID size is 10 */, sizeof(char));
	char* parentPathBuffer = (char*)calloc(MAX_PATH + 1, sizeof(char));
	

	if (pidBuffer == NULL || pathBuffer == NULL || ppidBuffer == NULL || parentPathBuffer == NULL) {
		WRITELINE_DEBUG("Could not allocate memory to copy details.");
		return NULL;
	}

	memcpy_s(pidBuffer, 11, PID, 11);
	memcpy_s(pathBuffer, MAX_PATH, PATH, MAX_PATH);
	memcpy_s(ppidBuffer, 11, PPID, 11);
	memcpy_s(parentPathBuffer, MAX_PATH, PARENT_PATH, MAX_PATH);

	// This must be freed later
	LPCSTR joinedName = GetThreadUsername();
	if (joinedName == NULL) {
		WRITELINE_DEBUG("Could not get thread username");
		return NULL;
	}

	// These will all get freed by FreeEventBaseArguments
	strings[0] = pidBuffer;
	strings[1] = pathBuffer;
	strings[2] = ppidBuffer;
	strings[3] = joinedName;
	strings[4] = parentPathBuffer;

	return strings;
}

BOOL LogStdin(LPCSTR content) {
	HANDLE_CHECK;

	LPCSTR* arguments = EventBaseArguments(1);
	if (arguments == NULL) {
		WRITELINE_DEBUG("An error occurred while collecting base arguments.");
		return FALSE;
	}
	// Find carriage return; this denotes end of input
	const char* position = strchr(content, '\r');
	size_t length = position - content;
	LPSTR buffer = (LPSTR)calloc(position - content + 1, sizeof(CHAR));
	if (buffer == NULL) {
		WRITELINE_DEBUG("Could not allocate space for pretty stdin text, falling back to default buffer.");
		arguments[5] = content;
	} else {
		memcpy_s(buffer, length, content, length);
		arguments[5] = buffer;
	}

	if (!ReportEventA(LOG_HANDLE, EVENTLOG_INFORMATION_TYPE, CAT_STANDARD_FILE, MSG_STDIN_READ, NULL, 6, 0, arguments, NULL)) {
		WRITELINE_DEBUG("Could not send event: " << GetLastError());
		FreeEventBaseArguments(arguments);
		free(buffer);
		return FALSE;
	}
	FreeEventBaseArguments(arguments);
	// Freeing NULL has no effect
	free(buffer);
	return TRUE;
}

BOOL LogStdout(LPCSTR content) {
	HANDLE_CHECK;

	LPCSTR* arguments = EventBaseArguments(1);
	if (arguments == NULL) {
		WRITELINE_DEBUG("An error occurred while collecting base arguments.");
		return FALSE;
	}
	arguments[5] = content;
	if (!ReportEventA(LOG_HANDLE, EVENTLOG_INFORMATION_TYPE, CAT_STANDARD_FILE, MSG_STDOUT_WRITE, NULL, 6, 0, arguments, NULL)) {
		WRITELINE_DEBUG("Could not send event: " << GetLastError());
		FreeEventBaseArguments(arguments);
		return FALSE;
	}
	FreeEventBaseArguments(arguments);
	return TRUE;
}

BOOL LogStderr(LPCSTR content) {
	HANDLE_CHECK;

	LPCSTR* arguments = EventBaseArguments(1);
	if (arguments == NULL) {
		WRITELINE_DEBUG("An error occurred while collecting base arguments.");
		return FALSE;
	}
	arguments[5] = content;
	if (!ReportEventA(LOG_HANDLE, EVENTLOG_INFORMATION_TYPE, CAT_STANDARD_FILE, MSG_STDERR_WRITE, NULL, 6, 0, arguments, NULL)) {
		WRITELINE_DEBUG("Could not send event: " << GetLastError());
		FreeEventBaseArguments(arguments);
		return FALSE;
	}
	FreeEventBaseArguments(arguments);
	return TRUE;
}

BOOL LogParentSpoof(DWORD fakeParent, LPCSTR image, LPCSTR parameters, DWORD pid) {
	HANDLE_CHECK;

	LPCSTR* arguments = EventBaseArguments(4);
	arguments[5] = image;
	arguments[6] = (LPCSTR)calloc(11, sizeof(char));
	if (arguments[6] == NULL) {
		WRITELINE_DEBUG("Could not send event: could not allocate buffer for new PID.");
		return FALSE;
	}
	sprintf_s((char*)arguments[6], 11, "%d", pid);
	arguments[7] = parameters;
	arguments[8] = (LPCSTR)calloc(11, sizeof(char));
	if (arguments[8] == NULL) {
		WRITELINE_DEBUG("Could not send event: could not allocate buffer for fake parent PID.");
		return FALSE;
	}
	sprintf_s((char*)arguments[8], 11, "%d", fakeParent);

	if (!ReportEventA(LOG_HANDLE, EVENTLOG_INFORMATION_TYPE, CAT_PROCESS, MSG_SPOOFED_PROCESS, NULL, 9, 0, arguments, NULL)) {
		WRITELINE_DEBUG("Could not send event: " << GetLastError());
		FreeEventBaseArguments(arguments);
		return FALSE;
	}

	// 4 frees the extra 4 arguments
	FreeEventBaseArguments(arguments, 4);
	return TRUE;
}
BOOL LogProcessCreate(LPCSTR image, LPCSTR parameters, DWORD pid) {
	HANDLE_CHECK;

	LPCSTR* arguments = EventBaseArguments(4);
	arguments[5] = image;
	arguments[6] = (LPCSTR)calloc(11, sizeof(char));
	if (arguments[6] == NULL) {
		WRITELINE_DEBUG("Could not send event: could not allocate buffer for new PID.");
		return FALSE;
	}
	sprintf_s((char*)arguments[6], 11, "%d", pid);
	arguments[7] = parameters;

	if (!ReportEventA(LOG_HANDLE, EVENTLOG_INFORMATION_TYPE, CAT_PROCESS, MSG_SPAWN_PROCESS, NULL, 8, 0, arguments, NULL)) {
		WRITELINE_DEBUG("Could not send event: " << GetLastError());
		FreeEventBaseArguments(arguments);
		return FALSE;
	}

	// 3 frees the extra 3 arguments
	FreeEventBaseArguments(arguments, 3);
	return TRUE;
}
BOOL LogPrivilegeAdjust(BOOL added, ULONG privilege) {
	LPCSTR* arguments = EventBaseArguments(2);

	LUID luid;
	luid.LowPart = privilege;
	luid.HighPart = 0;

	DWORD nameLength = 255;
	char* name = (char*)calloc(nameLength + 1, sizeof(char));

	if (name == NULL) {
		WRITELINE_DEBUG("Could not allocate memory for privilege name");
		FreeEventBaseArguments(arguments);
		return FALSE;
	}

	if (!LookupPrivilegeNameA(NULL, &luid, name, &nameLength)) {
		sprintf_s(name, nameLength, "UNKNOWN PRIVILEGE (%lu)", privilege);
	}

	if (added) {
		arguments[5] = "added";
	} else {
		arguments[5] = "removed";
	}
	arguments[6] = name;

	if (!ReportEventA(LOG_HANDLE, EVENTLOG_INFORMATION_TYPE, CAT_PRIVILEGE, MSG_PRIVILEGE_ADJUST, NULL, 7, 0, arguments, NULL)) {
		WRITELINE_DEBUG("Could not send event: " << GetLastError());
		free(name);
		FreeEventBaseArguments(arguments);
		return FALSE;
	}

	WRITELINE_DEBUG("Logged");

	free(name);
	FreeEventBaseArguments(arguments);

	return TRUE;
}

// Take the already-formatted signature
// This just reduces the weight of the library 
// because we don't need to define it in the header
BOOL LogFunctionCall(LPCSTR signature) {
	if (signature == NULL) {
		// Error handling here makes the macro a bit more useable
		WRITELINE_DEBUG("Signature was NULL, could not send event.");
		return FALSE;
	}

	LPCSTR* arguments = EventBaseArguments(1);
	arguments[5] = signature;

	if (!ReportEventA(LOG_HANDLE, EVENTLOG_INFORMATION_TYPE, CAT_FUNCTION_CALL, MSG_FUNCTION_CALL, NULL, 6, 0, arguments, NULL)) {
		WRITELINE_DEBUG("Could not send event: " << GetLastError());
		FreeEventBaseArguments(arguments);
		return FALSE;
	}

	FreeEventBaseArguments(arguments);
	return TRUE;
}