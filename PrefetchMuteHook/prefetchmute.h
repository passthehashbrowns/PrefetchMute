#pragma once
#include <tdh.h>
#include <winternl.h>

VOID DoOriginalPfSvWriteBufferEx(
	LPCWSTR param_1, LPCVOID param_2, DWORD param_3, unsigned int param_4
);

int WINAPI PfSvWriteBufferExHook(
	LPCWSTR param_1, LPCVOID param_2, DWORD param_3, unsigned int param_4
);

VOID HookPfSvWriteBufferEx();

typedef int(WINAPI* PfSvWriteBufferEx_) (LPCWSTR param_1, LPCVOID param_2, DWORD param_3, unsigned int param_4);

BOOL PlaceHook();

extern "C" {
	BOOL WINAPI EnumProcessModules(
		HANDLE hProcess,
		HMODULE* lphModule,
		DWORD cb,
		LPDWORD lpcbNeeded
	);
}

extern "C"
{
	DWORD
		WINAPI
		GetModuleBaseNameA(
			_In_ HANDLE hProcess,
			_In_opt_ HMODULE hModule,
			_Out_writes_(nSize) LPSTR lpBaseName,
			_In_ DWORD nSize
		); }