#pragma once
#define DISP_WINERROR(message) std::cerr << message << ": " << GetLastError() << "\x1b[0m" << std::endl
#define DISP_ERROR(message) std::cerr << "\x1b[91;1m[E]\x1b[0;31m >> \x1b[0;91m" << message << ".\x1b[0m" << std::endl
#define DISP_WARN(message) std::cerr << "\x1b[93;1m[W]\x1b[0;33m >> \x1b[0;93m" << message << ".\x1b[0m" << std::endl
#define DISP_LOG(message) std::cout << "\x1b[96;1m[I]\x1b[0;36m >> \x1b[0m" << message << std::endl
#define DISP_VERBOSE(message) if (verboseEnabled) std::cout << "\x1b[95;1m[V]\x1b[0;35m >> \x1b[0m" << message << std::endl
#define RESET_FORMAT std::cout << "\x1b[0m"