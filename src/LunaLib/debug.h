#pragma once

#if _DEBUG
// Required to use the debug functions
#include <iostream>
#define WRITE_DEBUG(expression) std::cerr << expression
#define WRITELINE_DEBUG(expression) std::cerr << expression << std::endl
#else
#define WRITE_DEBUG(expression)
#define WRITELINE_DEBUG(expression)
#endif