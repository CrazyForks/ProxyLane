#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifndef PROBE_VALUE
#error PROBE_VALUE must be defined by the build.
#endif

extern "C" __declspec(dllexport) DWORD WINAPI ProbeValue()
{
	return PROBE_VALUE;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID)
{
	return TRUE;
}
