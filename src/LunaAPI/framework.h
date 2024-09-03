#pragma once

#ifdef LUNA_API_EXPORTS
	#ifndef LUNA_API_STATIC
		#define LUNA_API __declspec(dllexport)
	#else
		#define LUNA_API 
	#endif
#else
	#define LUNA_API __declspec(dllimport)
#endif

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>
