#pragma once
#include <Windows.h>


typedef bool(WINAPI* fnDllMain)(HINSTANCE, DWORD, LPVOID);

typedef HMODULE(WINAPI* fnLoadLibraryA)(
	
	LPCSTR lpLibFileName
);

typedef FARPROC(WINAPI* fnGetProcAddress)(
	HMODULE hModule,
	LPCSTR  lpProcName
);

typedef LPVOID(WINAPI* fnVirtualAlloc)(

	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
);

typedef BOOL(WINAPI* fnVirtualProtect)(

	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
);

typedef NTSTATUS(NTAPI* fnNtFlushInstructionCache)(

	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_In_ SIZE_T Length
);