#pragma once

BOOL InstallHookV4(IN LPCSTR moduleName, IN LPCSTR functionName, IN void* hookFunction, OUT void** originalFunction);

#define QUICK_HOOK_V4(dll, name) (InstallHookV4(dll, #name, (void*)Hooked_##name, (void**)&Real_##name))