#include <iostream>
#include <string>

#include "arguments.h"
#include "output.h"
#include "util.h"

#include "shared.h"

// A simple (mostly) C argument parser
// (Anything not C is trivial to implement in C)

size_t NameEnds(const char* string, char character) {
	size_t length = strlen(string);
	for (int i = 0; i < length; i++) {
		if (string[i] == character) {
			return i;
		}
	}
	return length;
}

char* GetValueBuffer(int* index, char* current, char* next, size_t nameEnd) {
	if (strlen(current) == nameEnd) {
		// If the next argument is a flag, there's no next buffer
		if (next != NULL && (next[0] == '-' || next[0] == '/')) {
			return NULL;
		}
		// I'm impressed VS caught incorrect order of operations
		++*index;
		return next;
	} else {
		return &current[nameEnd + 1];
	}
}

BOOL ParseBool(char* buffer) {
	// Don't need extra values for a bool
	if (buffer == NULL) {
		return TRUE;
	}

	size_t length = strlen(buffer);
	if (
		NoCapCmp(buffer, "true", length) ||
		NoCapCmp(buffer, "t", length) ||
		NoCapCmp(buffer, "yes", length) ||
		NoCapCmp(buffer, "y", length)
		) return true;
	else if (
		NoCapCmp(buffer, "false", length) ||
		NoCapCmp(buffer, "f", length) ||
		NoCapCmp(buffer, "no", length) ||
		NoCapCmp(buffer, "n", length)
		) return false;

	DISP_WARN("Invalid boolean '" << buffer << "', defaulting to true");
	return true;
}
LPCSTR ParseString(char* buffer) {
	if (buffer == NULL) {
		return "";
	}
	return buffer;
}

#define INVALID_BASE16(expr) ((buffer[i] < '0' || buffer[i] > '9') && (buffer[i] < 'a' || buffer[i] > 'f') && (buffer[i] < 'A' || buffer[i] > 'F'))
#define INVALID_BASE10(expr) (buffer[i] < '0' || buffer[i] > '9')
#define INVALID_BASE8(expr) (buffer[i] < '0' || buffer[i] > '7')
#define INVALID_BASE2(expr) (buffer[i] != '0' && buffer[i] != '1')
DWORD ParseDword(char* buffer) {
	if (buffer == NULL) {
		return 0;
	}

	// This logic is mostly here for other types
	bool negative = false;
	switch (buffer[0]) {
	case '-':
		negative = true;
	case '+':
		// Negative is already false
		buffer = &buffer[1];
	}

	// Short circuit evaluation benefits
	int base = 10;
	if (buffer[0] != 0 && (buffer[1] == 'x' || buffer[1] == 'X' || buffer[1] == 'h' || buffer[1] == 'H')) {
		base = 16;
		buffer = &buffer[2];
	} else if (buffer[0] != 0 && (buffer[1] == 'o' || buffer[1] == 'O')) {
		base = 8;
		buffer = &buffer[2];
	} else if (buffer[0] != 0 && (buffer[1] == 'b' || buffer[1] == 'B')) {
		base = 2;
		buffer = &buffer[2];
	} else if (buffer[0] != 0 && (buffer[1] == 'd' || buffer[1] == 'D')) {
		base = 10;
		buffer = &buffer[2];
	}

	DWORD number = 0;
	DWORD updated = 0;
	for (size_t i = 0; buffer[i] != 0; i++) {
		if (
			(base == 16 && INVALID_BASE16(buffer[i])) ||
			(base == 10 && INVALID_BASE10(buffer[i])) ||
			(base == 8 && INVALID_BASE8(buffer[i])) ||
			(base == 2 && INVALID_BASE2(buffer[i]))
		) {
			DISP_WARN("Invalid base-" << base << " digit: " << buffer[i] << ", returning 0");
			return 0;
		}

		int digit = 0;
		if (buffer[i] >= '0' || buffer[i] <= '9') {
			digit = buffer[i] - 48;
		}
		else if (buffer[i] >= 'a' || buffer[i] <= 'z') {
			digit = buffer[i] - 87;
		}
		else if (buffer[i] >= 'A' || buffer[i] <= 'z') {
			digit = buffer[i] - 55;
		}
		updated = updated * base + digit;
		if (updated < number) {
			DISP_WARN("Integer overflow while parsing argument, returning 0");
			return 0;
		}
		number = updated;
	}

	if (negative) {
		DISP_WARN("Negative numbers are not supported here. Sign will be ignored");
	}

	return number;
}

LUNA_ARGUMENTS GetArguments(int argc, char* argv[]) {
	LUNA_ARGUMENTS result;

	// No point parsing if there are no arguments
	if (argc < 2) {
		return result;
	}
	// Start parsing from after executable name
	argv = &argv[1];
	argc--;

	int index = 0;
	for (int i = 0; i < argc; i++) {
		// If the parser put us ahead, catch up
		if (index > i) continue;

		LPCSTR parsed;
		if (argv[i][0] == '/') {
			// Windows parsing
			ParseArg(&index, argc, argv, ':', &result);
		}
		else if (argv[i][0] == '-') {
			// Linux parsing
			ParseArg(&index, argc, argv, '=', &result);
		}
		else {
			if (result.pid != 0) {
				DISP_WARN("Only one PID is supported, '" << argv[i] << "' will be ignored");
				continue;
			}
			result.pid = ParseDword(argv[i]);
		}
		index++;
	}
	return result;
}

void ParseArg(int* index, int argc, char* argv[], char eq, LUNA_ARGUMENTS* args) {
	char* current;
	// One after the first character
	// Unless that's a dash and we're using the Linux format
	if (argv[*index][1] == '-' && eq == '=')
		current = &argv[*index][2];
	else current = &argv[*index][1];
	int nameLength = NameEnds(current, eq);

	// If there is a next argument, get it in this variable
	// Otherwise null
	char* next = (*index < argc - 1 ? argv[*index + 1] : NULL);
	char* valueBuffer = GetValueBuffer(index, current, next, nameLength);
	if (
		// Debugging
		NoCapCmp(current, "h", nameLength) ||
		NoCapCmp(current, "help", nameLength) ||
		NoCapCmp(current, "?", nameLength)
	) {
		args->help = ParseBool(valueBuffer);
	}
	else if (
		NoCapCmp(current, "v", nameLength) ||
		NoCapCmp(current, "verbose", nameLength)
	) {
		args->verbose = ParseBool(valueBuffer);
	}
	else if (
		// Mitigations
		NoCapCmp(current, "d", nameLength) ||
		NoCapCmp(current, "drop", nameLength)
	) {
		args->dropPrivileges = ParseString(valueBuffer);
	}
	else if (
		NoCapCmp(current, "m", nameLength) ||
		NoCapCmp(current, "mitigation", nameLength) ||
		NoCapCmp(current, "mitigations", nameLength) ||
		NoCapCmp(current, "mitigate", nameLength)
		) {
		args->mitigations = ParseString(valueBuffer);
	}
	else if (
		// Controls
		NoCapCmp(current, "l", nameLength) ||
		NoCapCmp(current, "hook", nameLength) ||
		NoCapCmp(current, "hooks", nameLength)
	) {
		args->hooks = ParseString(valueBuffer);
	}
	else if (
		NoCapCmp(current, "c", nameLength) ||
		NoCapCmp(current, "rpc", nameLength)
		) {
		args->rpc = ParseBool(valueBuffer);
	}
	else if (
		// Miscellaneous
		NoCapCmp(current, "p", nameLength) ||
		NoCapCmp(current, "pid", nameLength)
		) {
		if (args->pid != 0) {
			DISP_WARN("Only one process is supported, '" << valueBuffer << "' will be ignored");
			return;
		}
		args->pid = ParseDword(valueBuffer);
	}
	else if (
		NoCapCmp(current, "i", nameLength) ||
		NoCapCmp(current, "implant", nameLength)
		) {
		args->name = ParseString(valueBuffer);
	}
	else if (
		NoCapCmp(current, "n", nameLength) ||
		NoCapCmp(current, "name", nameLength)
		) {
		if (args->pid != 0) {
			DISP_WARN("Only one process is supported, '" << valueBuffer << "' will be ignored");
			return;
		}
		LPCSTR processName = ParseString(valueBuffer);
		args->pid = FindPidByName(processName);
	}
	else {
		// Quick hack to display only the name
		// This is safe because we don't use it later; no info lost
		current[nameLength] = 0;
		DISP_WARN("Unrecognised argument '" << current << "'");
	}
}

void DisplayUsage() {
	std::cerr << 
		"Usage: LunaLoader [OPTIONS] PID" << std::endl <<
		"Inject LunaLib into PID" << std::endl <<
		"" << std::endl <<
		"Example: LunaLoader /d:SeDebugPrivilege,SeImpersonatePrivilege /v 2832" << std::endl <<
		"Example: LunaLoader /hooks:NtReadFile:ntdll.dll:V4 /p:2832" << std::endl <<
		"Example: LunaLoader --name=mspaint.exe -l=NtReadFile:ntdll.dll -v=true" << std::endl <<
		"Example: LunaLoader /rpc /i WELSH_BATTLE" << std::endl <<
		"                                 " << std::endl <<
		"Debugging:                       " << std::endl <<
		"/h, /help, /?                    Display this menu and exit" << std::endl <<
		"/v, /verbose                     Enable verbose logging" << std::endl <<
		"                                 " << std::endl <<
		"Mitigation:                      " << std::endl <<
		"/d, /drop:privilege,...          Privileges to drop before injection. Useful in" << std::endl <<
		"                                 combination with /m:BlockEsc to observe behaviour" << std::endl <<
		"                                 with lower risk of escalation." << std::endl <<
		"/m, /mitigations:mitigations,... Mitigations to prevent escalation/movement. A" << std::endl <<
		"                                 list may be found in the GitHub wiki." << std::endl <<
		"                                 " << std::endl <<
		"Controls:                        " << std::endl <<
		"/c, /rpc                         Connect to RPC. Currently requires implant name" << std::endl <<
		"/l, /load, /hook                 A list of functions to hook. 'default' can be" << std::endl <<
		"/hooks=function:dll:version,...  specified to keep the default functions and add" << std::endl <<
		"                                 more. The DLL name containing the function must" << std::endl <<
		"                                 be provided. The version (2-4) is 2 by default." << std::endl <<
		"Miscellaneous:                   " << std::endl <<
		"/p, /pid:pid                     Process ID of target." << std::endl <<
		"/n, /name:process_name           Find target by process name (less accurate)." << std::endl <<
		"/i, /implant:implant_name        Implant name to connect with (<=" << MAX_ID_LENGTH << " chars)." << std::endl <<
		"" << std::endl <<
		"If one argument fails to parse, the next equivalent argument with the same name will be taken instead." << std::endl <<
		"More information available on the GitHub wiki: https://github.com/Aurillium/LunaJuice/wiki" << std::endl <<
	std::endl;
}