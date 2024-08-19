#include "pch.h"

#include "events.h"
#include "messages.h"
#include <iostream>

#include "debug.h"
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

EXTERN_HOOK(OpenProcess);

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
	if (Real_OpenProcess != NULL) {
		WRITELINE_DEBUG("ASSERTION FAILED: Real_OpenProcess == NULL. Unexpected behaviour will occur (probably a crash on the next line).");
		WRITELINE_DEBUG("Make sure to hook AFTER this code, or use Real_OpenProcess below.");
	}
#endif
	HANDLE parentHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ppid);
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
static void FreeEventBaseArguments(LPCSTR* arguments, size_t extra = 0) {
	for (size_t i = 0; i < DEFAULT_ARGS + extra; i++)
	{
		free((void*)arguments[i]);
	}
	free(arguments);
}

static LPCSTR GetThreadUsername() {
	char* usernameBuffer = (char*)calloc(SECURITY_MAX_SID_SIZE + 1, sizeof(char));
	char* domainBuffer = (char*)calloc(SECURITY_MAX_SID_SIZE + 1, sizeof(char));

	if (usernameBuffer == NULL || domainBuffer == NULL) {
		WRITELINE_DEBUG("Could not allocate memory to store username and domain.");
		return NULL;
	}

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
	memcpy_s(joinedName + domainLength + 1, usernameLength, usernameBuffer, usernameLength);

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
	memcpy_s(pathBuffer, MAX_PATH + 1, PATH, MAX_PATH + 1);
	memcpy_s(ppidBuffer, 11, PPID, 11);
	memcpy_s(parentPathBuffer, MAX_PATH + 1, PARENT_PATH, MAX_PATH + 1);

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
	arguments[5] = content;
	if (!ReportEventA(LOG_HANDLE, EVENTLOG_INFORMATION_TYPE, CAT_STANDARD_FILE, MSG_STDIN_READ, NULL, 6, 0, arguments, NULL)) {
		WRITELINE_DEBUG("Could not send event: " << GetLastError());
		FreeEventBaseArguments(arguments);
		return FALSE;
	}
	FreeEventBaseArguments(arguments);
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
	LPCSTR* arguments = EventBaseArguments(1);

	LUID luid;
	luid.LowPart = privilege;
	luid.HighPart = 0;

	DWORD nameLength = 255;
	char* name = (char*)calloc(nameLength + 1, sizeof(char));
	if (name == NULL) {
		WRITELINE_DEBUG("Could not allocate memory for privilege name");
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
		FreeEventBaseArguments(arguments);
		return FALSE;
	}

	free(name);
	FreeEventBaseArguments(arguments);
}